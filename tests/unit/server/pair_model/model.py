#!/usr/bin/env python3
"""Executable model of (a) census v4 key regime and (b) the UP-14 server delivery plan's regime machine.
Oracle: among ARRIVED events for a rule, the one with the greatest true emission time is the truth.
A row that is not flagged must hold the truth verdict. Pending/seen-event machinery is out of scope
(first deliveries only)."""
import random, sys, collections

STALE = 3600
SLACK = 300
CAP = 300


class Row:
    __slots__ = "state key iseq ts_hwm seq_hwm hwm_recv flag pair upd".split()

    def __init__(s):
        s.state = None; s.key = 0; s.iseq = 0; s.ts_hwm = None; s.seq_hwm = None
        s.hwm_recv = None; s.flag = False; s.pair = None; s.upd = None


class Ev:
    def __init__(s, **k):
        s.__dict__.update(k)


def derive_key(ts, recv):
    if ts <= 0:
        return 0, False
    b = recv + CAP
    return (b, True) if ts > b else (ts, False)


# ---------- v4 key regime (first-delivery, no pending) ----------
def v4_apply(row, st, key, capped, iseq, now, state):
    """mutates row (existing). returns nothing."""
    P = key > (row.key or 0) or (key == (row.key or 0) and iseq > (row.iseq or 0))
    R = (key > 0 and key < (row.ts_hwm or 0) and iseq > (row.iseq or 0) and row.hwm_recv is not None
         and (row.hwm_recv > now + SLACK or now - row.hwm_recv > STALE))
    APPLY = P or R
    TIE = key != 0 and key == (row.key or 0) and state != row.state
    where = APPLY or iseq > (row.iseq or 0) or TIE or key > (row.ts_hwm or 0)
    if not where:
        return
    old_hwm = row.ts_hwm or 0
    old_seqhwm = row.seq_hwm if row.seq_hwm is not None else (row.iseq or 0)
    if APPLY:
        flag = (key == 0 or capped or (row.key == 0) or key < old_hwm or (row.flag and key <= old_hwm)
                or iseq < old_seqhwm or TIE)
        row.state = state; row.key = key; row.iseq = iseq
    else:
        flag = row.flag or iseq > (row.iseq or 0) or TIE
    if key > old_hwm:
        row.hwm_recv = now
    row.ts_hwm = max(old_hwm, key) or None
    row.seq_hwm = max(old_seqhwm, iseq)
    row.flag = flag


def v4_insert(key, capped, iseq, now, state):
    r = Row()
    r.state = state; r.key = key; r.iseq = iseq
    r.ts_hwm = key or None; r.seq_hwm = iseq
    r.hwm_recv = now if key > 0 else None
    r.flag = (key == 0 or capped)
    return r


class V4:
    name = "v4"

    def __init__(s):
        s.rows = {}

    def ingest(s, ev, now):
        key, capped = derive_key(ev.ts, now)
        r = s.rows.get(ev.rule)
        if r is None:
            s.rows[ev.rule] = v4_insert(key, capped, ev.iseq, now, ev.state)
        else:
            v4_apply(r, None, key, capped, ev.iseq, now, ev.state)


# ---------- plan: regime machine ----------
class AgentOrder:
    def __init__(s):
        s.epoch = None; s.hwm = None; s.recv = None; s.retired = None
        s.ctr = collections.Counter()


class Plan:
    name = "plan"

    def __init__(s, opts=()):
        s.rows = {}
        s.ag = AgentOrder()
        s.opts = set(opts)
        s.variant = None
        s.ctr = collections.Counter()

    def fresh(s, now):
        a = s.ag
        return a.recv is not None and not (now - a.recv > STALE or a.recv > now + SLACK)

    def agent_step(s, ev, now):
        a = s.ag
        if ev.pair is None:
            a.ctr["unpaired"] += 1
            if a.epoch is not None and s.fresh(now):
                a.ctr["unpaired_held"] += 1
                return "unpaired_held"
            return "unpaired"
        e, sq = ev.pair
        if a.retired is not None and e == a.retired:
            return "refused_retired"
        if a.epoch is None or e > a.epoch:
            a.epoch, a.hwm, a.recv = e, sq, now
            return "current"
        if e == a.epoch and sq > a.hwm:
            a.hwm, a.recv = sq, now
            return "current"
        if e == a.epoch:
            if s.fresh(now):
                return "straggler"
            a.hwm, a.recv = sq, now
            return "rebase"
        # e < a.epoch
        if s.fresh(now):
            a.ctr["regress"] += 1
            return "refused_regression"
        a.retired = a.epoch
        a.epoch, a.hwm, a.recv = e, sq, now
        return "rebase"

    def ingest(s, ev, now):
        mode = s.agent_step(ev, now)
        key, capped = derive_key(ev.ts, now)
        r = s.rows.get(ev.rule)
        s.ctr[mode] += 1
        def raise_hwm(r):
            if "refusal_hwm" in s.opts and key > (r.ts_hwm or 0):
                r.hwm_recv = now
                r.ts_hwm = key
        if mode == "refused_retired":
            if r is not None:
                r.flag = True; raise_hwm(r)
            return
        if mode == "refused_regression":
            if r is None:
                nr = Row(); nr.state = ev.state; nr.key = key; nr.iseq = ev.iseq; nr.pair = ev.pair
                nr.flag = True; s.rows[ev.rule] = nr
            else:
                r.flag = True; raise_hwm(r)
            return
        if mode == "unpaired_held":
            if r is None:
                nr = v4_insert(key, capped, ev.iseq, now, ev.state)
                nr.flag = True; s.rows[ev.rule] = nr
            elif r.pair is not None and "held_apply_if_newer_key" in s.opts and key > r.key:
                old = r.ts_hwm or 0
                r.state = ev.state; r.key = key; r.iseq = ev.iseq
                r.flag = True; r.pair = None
                if key > old:
                    r.hwm_recv = now
                r.ts_hwm = max(old, key) or None
                r.seq_hwm = max(r.seq_hwm or 0, ev.iseq)
            elif r.pair is not None:
                # REFUSE, flag, ts_hwm raised
                r.flag = True
                if key > (r.ts_hwm or 0):
                    r.hwm_recv = now
                r.ts_hwm = max(r.ts_hwm or 0, key) or None
                if s.variant == "apply_held_if_newer_key" and key > r.key:
                    pass
            else:
                v4_apply(r, None, key, capped, ev.iseq, now, ev.state)
            return
        if mode == "unpaired":
            if r is None:
                s.rows[ev.rule] = v4_insert(key, capped, ev.iseq, now, ev.state)
            elif r.pair is not None:
                # hold expired: apply by arrival, flag, pair cleared, ts_hwm raised
                old = r.ts_hwm or 0
                prev_key = r.key
                r.state = ev.state; r.key = key; r.iseq = ev.iseq
                r.flag = True; r.pair = None
                nk = max(key, prev_key) if "trans_hwm_rowkey" in s.opts else key
                if nk > old:
                    r.hwm_recv = now
                r.ts_hwm = max(old, nk) or None
                r.seq_hwm = max(r.seq_hwm or 0, ev.iseq)
            else:
                v4_apply(r, None, key, capped, ev.iseq, now, ev.state)
            return
        # current / straggler / rebase
        e, sq = ev.pair
        if r is None:
            nr = Row(); nr.state = ev.state; nr.key = key; nr.iseq = ev.iseq; nr.pair = ev.pair
            nr.flag = (mode == "rebase"); nr.seq_hwm = ev.iseq
            s.rows[ev.rule] = nr
            return

        def clean_rule():
            return key > (r.ts_hwm or 0)

        def do_apply(flag):
            r.state = ev.state; r.key = key; r.iseq = ev.iseq; r.pair = ev.pair
            r.flag = flag
            r.seq_hwm = max(r.seq_hwm or 0, ev.iseq)

        if r.pair is None:
            do_apply(True); return
        ce, cs = r.pair
        if ce != e:
            if mode == "rebase":
                do_apply(True)
            elif ce > e:
                do_apply(True)
            else:
                do_apply(not clean_rule())
            return
        if sq > cs:
            do_apply(True if mode == "rebase" else (not clean_rule()))
            return
        if sq == cs:
            r.flag = True; s.ctr["dup"] += 1; raise_hwm(r)
            return
        # sq < cs
        if mode == "straggler":
            r.flag = True; raise_hwm(r)
            return
        do_apply(True)


# ---------- schedule generator ----------
def gen_schedule(rng, nrules=2, lags=(10,46,600,5000), with_restart=True, p_lost=0.15, p_reorder=0.1, p_step=0.1,
                 p_claim_fail=0.1, p_lower_epoch=0.1, p_quiet_gap=0.15):
    """Single stamping sender (per boot), shared emit_seq counter across rules.
    Returns list of arrivals (arrival_time, Ev). Ev has rule, state, ts, pair, t_emit, id."""
    t = 1_000_000  # real time
    off = 0
    events = []   # (t_emit, ev)
    boots = rng.randint(1, 4) if with_restart else 1
    epoch = rng.randint(1000, 5000)
    eid = 0
    pending_replays = []  # (earliest_arrival, ev_clone)
    arrivals = []
    for b in range(boots):
        if b > 0:
            t += rng.choice([60, 600, 4000, 12000])
            r = rng.random()
            if r < p_lower_epoch:
                epoch = max(1, epoch - rng.randint(1, 3000))
            else:
                epoch += rng.randint(1, 5000)
        claim_fail = rng.random() < p_claim_fail
        seq = 0
        n = rng.randint(2, 10)
        for _ in range(n):
            if rng.random() < p_quiet_gap:
                t += rng.choice([4000, 8000])
            else:
                t += rng.randint(1, 60)
            if rng.random() < p_step:
                off -= rng.randint(1, 20)
            elif rng.random() < 0.03:
                off += rng.randint(1, 20)
            seq += 1
            eid += 1
            rule = rng.randrange(nrules)
            ev = Ev(id=eid, rule=rule, state=rng.choice("CE"), ts=t + off, t_emit=t,
                    pair=None if claim_fail else (epoch, seq), lost=False)
            delay = rng.randint(0, 3)
            if rng.random() < p_lost:
                ev.lost = True
                # replay as 0/0 later, with original timestamp
                rep = Ev(id=ev.id, rule=rule, state=ev.state, ts=ev.ts, t_emit=ev.t_emit, pair=None,
                         lost=False)
                arrivals.append((t + rng.choice(list(lags)), rep))
            else:
                arrivals.append((t + delay + (rng.randint(0, 2) if rng.random() < p_reorder else 0), ev))
    arrivals.sort(key=lambda x: x[0])
    return arrivals


def run(cls, arrivals, **kw):
    m = cls(**kw) if kw else cls()
    truth = {}  # rule -> (t_emit, state)
    viol = []
    iseq = 0
    for i, (at, ev) in enumerate(arrivals):
        iseq += 1
        ev.iseq = iseq
        m.ingest(ev, at)
        cur = truth.get(ev.rule)
        if cur is None or ev.t_emit > cur[0]:
            truth[ev.rule] = (ev.t_emit, ev.state)
        for rule, (te, st) in truth.items():
            row = m.rows.get(rule)
            if row is None:
                viol.append((i, rule, "missing"))
            elif (not row.flag) and row.state != st:
                viol.append((i, rule, "wrong_unflagged"))
    # final: wrong-and-flagged count
    wf = sum(1 for rule, (te, st) in truth.items() if rule in m.rows and m.rows[rule].state != st
             and m.rows[rule].flag)
    return viol, wf, m


if __name__ == "__main__":
    N = int(sys.argv[1]) if len(sys.argv) > 1 else 20000
    stats = {"v4": collections.Counter(), "plan": collections.Counter()}
    examples = {"v4": [], "plan": []}
    better = collections.Counter()
    for seed in range(N):
        rng = random.Random(seed)
        arr = gen_schedule(rng)
        for cls in (V4, Plan):
            viol, wf, m = run(cls, arr)
            k = cls.name
            if viol:
                stats[k]["sched_with_violation"] += 1
                kinds = {v[2] for v in viol}
                for kk in kinds:
                    stats[k][kk] += 1
                if len(examples[k]) < 3:
                    examples[k].append(seed)
            if wf:
                stats[k]["final_wrong_flagged"] += 1
        # compare
        v4v, v4wf, _ = run(V4, arr)
        pv, pwf, _ = run(Plan, arr)
        if not v4v and v4wf == 0 and (pv or pwf):
            better["v4_ok_plan_not"] += 1
            if len([1 for _ in range(1)]) and better["v4_ok_plan_not"] <= 3:
                examples.setdefault("v4_ok_plan_not", []).append(seed)
        if (v4v or v4wf) and not (pv or pwf):
            better["plan_ok_v4_not"] += 1
    print("schedules", N)
    for k, v in stats.items():
        print(k, dict(v))
    print(dict(better))
    print(examples)
