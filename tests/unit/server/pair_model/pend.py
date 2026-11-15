"""Pending-evidence extension of the model.

Semantics follow origin/dev's project_rule_status (agent step [plan only] -> fold -> upsert -> fold again -> clear),
with the plan's rev-2 regime-aware rules of section 2.5 for the seen-event tests and the clear rule:

  D(p, row)  "the seen event p disagrees with the row" (flag + fold):
     both unpaired (or v4):  (p.key, p.iseq) > (row.key, row.iseq) OR p.iseq > row.iseq OR (p.key<>0 AND p.key = row.key AND p.iseq <> row.iseq)
     both paired:            (p.pair >= row.pair lexicographically) OR p.epoch = retired_epoch
     p unpaired, row paired: True        p paired, row unpaired: True
  FOLD_MAX_KEY: max key over disagreeing seen events that are UNPAIRED (v4: all).
  CLEAR (retire p): both paired: p.pair <= row.pair OR p.epoch = retired; p unpaired & row paired: True;
     p paired & row unpaired: False (stays pending); both unpaired / v4: (p.key,p.iseq) <= (row.key,row.iseq).

Oracle: among ALL arrived events of a rule (pending or not) the greatest emission time is the truth. Contract: a row that is
unflagged and has NO pending event of the rule must hold it."""
import os, sys, random, copy, collections
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from model import Row, Ev, AgentOrder, derive_key, STALE, SLACK, CAP
from ext import gen2


def v4_apply_s(row, key, capped, iseq, now, state, seen_max, seen=(), upd=None):
    P = key > (row.key or 0) or (key == (row.key or 0) and iseq > (row.iseq or 0))
    R = (key > 0 and key < (row.ts_hwm or 0) and iseq > (row.iseq or 0) and row.hwm_recv is not None
         and (row.hwm_recv > now + SLACK or now - row.hwm_recv > STALE))
    APPLY = P or R
    TIE = key != 0 and key == (row.key or 0) and state != row.state
    base_seq = row.seq_hwm if row.seq_hwm is not None else (row.iseq or 0)
    where = APPLY or iseq > (row.iseq or 0) or TIE or key > (row.ts_hwm or 0) or seen_max > base_seq
    if not where:
        return 'refused_noop'
    old_hwm = row.ts_hwm or 0
    if APPLY:
        flag = (key == 0 or capped or (row.key == 0) or key < old_hwm or (row.flag and key <= old_hwm)
                or iseq < base_seq or TIE
                or any(p.iseq > iseq or (p.key != 0 and p.key == key and p.iseq != iseq) for p in seen))
        row.state = state; row.key = key; row.iseq = iseq; row.upd = upd
    else:
        flag = row.flag or iseq > (row.iseq or 0) or TIE
    if key > old_hwm:
        row.hwm_recv = now
    row.ts_hwm = max(old_hwm, key) or None
    row.seq_hwm = max(base_seq, iseq, seen_max)
    row.flag = flag
    return 'applied' if row.iseq == iseq else 'refused_flagged'


class Ev2:
    def __init__(s, **k): s.__dict__.update(k)


class Store:
    """mode 'v4' (pair ignored) or 'plan' (rev-2 regime machine)."""
    def __init__(s, mode, variant=()):
        s.mode = mode; s.var = set(variant)
        s.rows = {}; s.events = {}; s.ag = AgentOrder(); s.iseq = 0
        s.stats = collections.Counter()
        s.cnt = collections.Counter(); s.last = ''

    # ---- agent step (plan only), identical to model.Plan.agent_step ----
    def fresh(s, now):
        a = s.ag
        return a.recv is not None and not (now - a.recv > STALE or a.recv > now + SLACK)

    def agent_step(s, pair, now):
        a = s.ag
        if pair is None:
            s.cnt["unpaired_events"] += 1
            if a.epoch is not None and s.fresh(now):
                s.cnt["unpaired_held"] += 1; return "unpaired_held"
            return "unpaired"
        e, sq = pair
        if a.retired is not None and e == a.retired:
            s.cnt["retired_events"] += 1; return "refused_retired"
        if a.epoch is None or e > a.epoch:
            a.epoch, a.hwm, a.recv = e, sq, now; return "current"
        if e == a.epoch and sq > a.hwm:
            a.hwm, a.recv = sq, now; return "current"
        if e == a.epoch:
            if s.fresh(now):
                s.cnt["pair_stragglers"] += 1; return "straggler"
            a.hwm, a.recv = sq, now; s.cnt["pair_recoveries"] += 1; return "rebase"
        if s.fresh(now):
            s.cnt["pair_regressions"] += 1; return "refused_regression"
        a.retired = a.epoch; a.epoch, a.hwm, a.recv = e, sq, now
        s.cnt["pair_recoveries"] += 1
        return "rebase"

    def agent_mode_readonly(s, pair, now):
        """Repair (variant repair_ro): decide the mode against the pair clock WITHOUT mutating it and WITHOUT recovery."""
        a = s.ag
        if pair is None:
            return "unpaired_held" if (a.epoch is not None and s.fresh(now)) else "unpaired"
        e, sq = pair
        if a.retired is not None and e == a.retired: return "refused_retired"
        if a.epoch is None or e > a.epoch or (e == a.epoch and sq > a.hwm): return "current"
        if e == a.epoch: return "straggler"
        return "refused_regression"

    # ---- seen tests ----
    def paired(s, x):
        return s.mode == "plan" and x.pair is not None

    def D(s, p, row):
        if s.mode == "plan":
            pp = p.pair is not None; rp = row.pair is not None
            if pp and rp:
                return (p.pair >= row.pair or (s.ag.retired is not None and p.pair[0] == s.ag.retired)
                        or ("seen_arrival" in s.var and p.iseq > row.iseq)
                        or ("seen_epoch" in s.var and p.pair[0] != row.pair[0]))
            if pp != rp:
                return True
        return ((p.key, p.iseq) > (row.key, row.iseq) or p.iseq > row.iseq
                or (p.key != 0 and p.key == row.key and p.iseq != row.iseq))

    def Dinc(s, p, e):
        pp = p.pair is not None; ep = e.pair is not None
        if pp and ep:
            return (p.pair >= e.pair or (s.ag.retired is not None and p.pair[0] == s.ag.retired)
                    or ("seen_arrival" in s.var and p.iseq > e.iseq)
                    or ("seen_epoch" in s.var and p.pair[0] != e.pair[0]))
        if pp != ep:
            return True
        return ((p.key, p.iseq) > (e.key, e.iseq) or p.iseq > e.iseq
                or (p.key != 0 and p.key == e.key and p.iseq != e.iseq))

    def dominated(s, p, row):
        if s.mode == "plan":
            pp = p.pair is not None; rp = row.pair is not None
            # rev 2.3 (Astra O5): the retired-epoch retire holds against ANY row regime, as the plan text says
            if pp and s.ag.retired is not None and p.pair[0] == s.ag.retired: return True
            if pp and rp:
                return p.pair <= row.pair or (s.ag.retired is not None and p.pair[0] == s.ag.retired)
            if (not pp) and rp:
                return True
            if pp and not rp:
                return False
        return (p.key, p.iseq) <= (row.key, row.iseq)

    def fold(s, rule, seen, now):
        row = s.rows.get(rule)
        if row is None: return
        dis = [p for p in seen if s.D(p, row)]
        if not dis: return
        row.flag = True
        keys = [p.key for p in dis if (s.mode == "v4" or p.pair is None or "fold_seen_all" in s.var)]
        mk = max(keys) if keys else 0
        if mk > (row.ts_hwm or 0):
            row.hwm_recv = now
            row.ts_hwm = max(row.ts_hwm or 0, mk) or None

    # ---- upsert ----
    def upsert(s, e, mode, seen, now):
        rule = e.rule; key, capped, iseq, state, pair = e.key, e.capped, e.iseq, e.state, e.pair
        seen_max = max([p.iseq for p in seen], default=0)
        r = s.rows.get(rule)
        if s.mode == "v4":
            if r is None:
                dis = [p for p in seen if (p.key, p.iseq) > (key, iseq) or p.iseq > iseq
                       or (p.key != 0 and p.key == key and p.iseq != iseq)]
                mk = max([p.key for p in dis], default=None)
                nr = Row(); nr.state = state; nr.key = key; nr.iseq = iseq
                nr.ts_hwm = max(key, mk or 0) or None; nr.seq_hwm = max(iseq, seen_max)
                nr.hwm_recv = now if (key > 0 or mk is not None) else None
                nr.flag = (key == 0 or capped or mk is not None); nr.upd = e.id
                s.rows[rule] = nr; s.v4out = 'applied'
            else:
                s.v4out = v4_apply_s(r, key, capped, iseq, now, state, seen_max, seen, e.id)
            return
        # plan: cells of PlanY (see gen_sql.py), with key/capped given
        def fold_row(rr, prev_key):
            if rr.flag:
                v = max(key, prev_key)
                if v > (rr.ts_hwm or 0):
                    rr.ts_hwm = v; rr.hwm_recv = now
        prev_key = r.key if r is not None else 0
        base_seq = (r.seq_hwm if r.seq_hwm is not None else (r.iseq or 0)) if r is not None else 0
        def bump():
            rr = s.rows.get(rule)
            if rr is not None and r is not None and rr is r: rr.seq_hwm = max(base_seq, iseq, seen_max)
        a = s.ag
        dis = [p for p in seen if s.Dinc(p, e)]
        mk = max([p.key for p in dis], default=None)
        def ins_row(flag_force):
            nr = Row(); nr.state = state; nr.upd = e.id; nr.key = key; nr.iseq = iseq; nr.seq_hwm = max(iseq, seen_max)
            keymode = mode in ("unpaired", "unpaired_held")
            nr.pair = None if keymode else pair
            if keymode:
                nr.ts_hwm = max(key, mk or 0) or None
                nr.hwm_recv = now if (key > 0 or mk is not None) else None
                nr.flag = (mode == "unpaired_held") or (key == 0 or capped or mk is not None)
            else:
                nr.flag = bool(flag_force) or mk is not None
                nr.ts_hwm = (max(key, mk or 0) or None) if nr.flag else None
                nr.hwm_recv = now if (nr.flag and nr.ts_hwm is not None) else None
            s.rows[rule] = nr
        if mode == "refused_retired":
            if r is None:
                ins_row(True)
            else:
                r.flag = True; fold_row(r, prev_key); bump()
            return
        if mode == "refused_regression":
            if r is None:
                ins_row(True)
            else:
                r.flag = True; fold_row(r, prev_key); bump()
            return
        if mode == "unpaired_held":
            if r is None:
                ins_row(True)
            elif r.pair is not None:
                r.flag = True
                old = r.ts_hwm or 0
                if key > old: r.hwm_recv = now
                r.ts_hwm = max(old, key) or None
                fold_row(r, prev_key); bump()
            else:
                s.v4out = v4_apply_s(r, key, capped, iseq, now, state, seen_max, seen, e.id)
            return
        if mode == "unpaired":
            if r is None:
                ins_row(False)
            elif r.pair is not None and "no_f6_guard" not in s.var and not (iseq > (r.iseq or 0)):
                # rev 2.3 F6: an unpaired event older by arrival than the paired verdict does not apply
                r.flag = True; fold_row(r, prev_key); bump()
            elif r.pair is not None:
                old = r.ts_hwm or 0
                r.state = state; r.upd = e.id; r.key = key; r.iseq = iseq; r.flag = True; r.pair = None
                nk = max(key, prev_key)
                if nk > old: r.hwm_recv = now
                r.ts_hwm = max(old, nk) or None
                bump()
            else:
                s.v4out = v4_apply_s(r, key, capped, iseq, now, state, seen_max, seen, e.id)
            return
        # current / straggler / rebase (paired event)
        ev_e, ev_s = pair
        if r is None:
            ins_row(mode == "rebase")
            return
        def clean(): return key > (r.ts_hwm or 0) and not dis
        def do_apply(flag):
            r.state = state; r.upd = e.id; r.key = key; r.iseq = iseq; r.pair = pair; r.flag = flag
        def refuse():
            r.flag = True
        if r.pair is None:
            do_apply(True)
        else:
            ce, cs = r.pair
            if ce != ev_e:
                if mode == "rebase": do_apply(True)
                elif ce > ev_e: do_apply(True)
                else: do_apply(not clean())
            elif ev_s > cs:
                do_apply(True if mode == "rebase" else (not clean()))
            elif ev_s == cs:
                refuse()
            else:
                if mode == "straggler": refuse()
                else: do_apply(True)
        fold_row(r, prev_key); bump()

    # ---- decision label (plan 2.6); '' = no label (key-regime event that changed nothing) ----
    @staticmethod
    def label(mode, old, applied, pair):
        """old: None (no row) or the row's pair before the statement (None = unpaired verdict)."""
        if mode == "refused_regression": return "refused_regression"
        if mode == "refused_retired": return "refused_retired"
        if mode in ("unpaired", "unpaired_held"):
            if old is not None and old[0]:
                return "transition_to_key" if (mode == "unpaired" and applied) else "held_unpaired"
            return "applied_key" if applied else ""
        if old is None: return "rebase" if mode == "rebase" else "applied_pair"
        if not old[0]: return "rebase" if mode == "rebase" else "transition_to_pair"
        if old[1] == pair: return "refused_duplicate"
        if applied: return "rebase" if mode == "rebase" else "applied_pair"
        return "refused_straggler"

    # ---- clear ----
    def clear(s, e, seen, repair, now):
        row = s.rows.get(e.rule)
        if row is None: return
        cand = ([e] if repair else []) + seen
        for p in cand:
            if p.pending and s.dominated(p, row):
                p.pending = False

    # ---- project ----
    def project(s, e, source, now):
        seen = sorted([p for p in s.events.values() if p.pending and p.rule == e.rule and p.id != e.id],
                      key=lambda p: p.iseq)
        if s.mode == "plan" and source == "repair" and getattr(s, "force_mode", None):
            mode = s.force_mode; s.force_mode = None
        elif s.mode == "plan" and source == "repair" and "repair_ro" in s.var:
            mode = s.agent_mode_readonly(e.pair, now)
        else:
            mode = s.agent_step(e.pair, now) if s.mode == "plan" else None
        s.fold(e.rule, seen, now)
        r0 = s.rows.get(e.rule)
        old = None if r0 is None else (r0.pair is not None, r0.pair)
        s.upsert(e, mode, seen, now)
        r1 = s.rows.get(e.rule)
        applied = r1 is not None and r1.iseq == e.iseq
        lab = s.label(mode, old, applied, e.pair) if s.mode == "plan" else ""
        if lab == "refused_duplicate" and source == "first":
            s.cnt["pair_duplicates"] += 1
        sqlmode = {"straggler": "current_straggler", "rebase": "current_rebase"}.get(mode, mode)
        s.last = f"{sqlmode}|{lab}"
        s.fold(e.rule, seen, now)
        s.clear(e, seen, source == "repair", now)

    def first(s, ev, now, fail):
        s.iseq += 1
        key, capped = derive_key(ev.ts, now)
        e = Ev2(id=ev.id, rule=ev.rule, state=ev.state, key=key, capped=capped, iseq=s.iseq,
                pair=ev.pair if s.mode == "plan" else ev.pair, pending=False, t_emit=ev.t_emit)
        s.events[e.id] = e
        if fail:
            s.v4out = 'failed'
            e.pending = True; s.stats["pending_created"] += 1
            if s.mode == "plan" and "observe_failed" in s.var:
                m0 = s.agent_step(e.pair, now)
                s.last = {"straggler": "current_straggler", "rebase": "current_rebase"}.get(m0, m0) + ":pending"
            return
        s.project(e, "first", now)

    def repair(s, eid, now, fail):
        e = s.events[eid]
        s.last = "noop"; s.v4out = "noop"
        if not e.pending: return
        if fail:
            s.stats["repair_failed"] += 1; s.v4out = 'failed'
            if s.mode == "plan" and "repair_ro" in s.var:
                m0 = s.agent_mode_readonly(e.pair, now)
                s.last = {"straggler": "current_straggler"}.get(m0, m0) + ":pending"
            return
        s.project(e, "repair", now)
        s.stats["repaired"] += 1


def gen_actions(rng, p_fail=0.1, p_redeliver=0.7, **gk):
    arr = gen2(rng, **gk)
    acts = []
    for at, ev in arr:
        fail = rng.random() < p_fail
        acts.append((at, "first", ev, fail))
        if fail and rng.random() < p_redeliver:
            t = at
            for _ in range(2):
                t += rng.choice([30, 600, 4000, 8000])
                f2 = rng.random() < p_fail
                acts.append((t, "repair", ev.id, f2))
                if not f2: break
    acts.sort(key=lambda x: x[0])
    return acts


def run(mode, acts, variant=()):
    m = Store(mode, variant); truth = {}; viol = []; ev_by_id = {}
    for i, (at, kind, x, fail) in enumerate(acts):
        if kind == "first":
            ev_by_id[x.id] = x
            m.first(copy.copy(x), at, fail)
            c = truth.get(x.rule)
            if c is None or x.t_emit > c[0]: truth[x.rule] = (x.t_emit, x.state)
        else:
            m.repair(x, at, fail)
        for rule, (te, st) in truth.items():
            row = m.rows.get(rule)
            pend = any(p.pending and p.rule == rule for p in m.events.values())
            if row is None:
                if not pend: viol.append((i, rule, "missing"))
            elif (not row.flag) and (not pend) and row.state != st:
                viol.append((i, rule, "wrong_unflagged"))
    wf = sum(1 for rule, (te, st) in truth.items() if rule in m.rows and m.rows[rule].state != st)
    strand = sum(1 for p in m.events.values() if p.pending)
    # liveness: is the agent's LIVE epoch (the epoch of the latest-emitted paired event) fenced as retired at the end?
    paired = [(x[2].t_emit, x[2].pair[0]) for x in acts if x[1] == "first" and x[2].pair is not None]
    live = max(paired)[1] if paired else None
    m.fenced_live = (mode == "plan" and live is not None and m.ag.retired == live)
    return viol, wf, strand, m


VARIANTS = [("v4", "v4", ()), ("plan (rev 2.1 as written)", "plan", ()), ("+seen_arrival", "plan", ("seen_arrival",)),
            ("+observe_failed", "plan", ("observe_failed",)), ("+repair_ro", "plan", ("repair_ro",)),
            ("+arrival+observe+ro", "plan", ("seen_arrival", "observe_failed", "repair_ro")),
            ("+arr+epoch+foldall", "plan", ("seen_arrival", "seen_epoch", "fold_seen_all")),
            ("+arr+epoch+foldall+obs", "plan", ("seen_arrival", "seen_epoch", "fold_seen_all", "observe_failed")),
            ("+ALL (arr,epoch,fold,obs,ro)", "plan", ("seen_arrival", "seen_epoch", "fold_seen_all", "observe_failed", "repair_ro"))]

def camp(N, label, **gk):
    print(f"\n## {label}  {gk}")
    print(f"{'variant':30s} {'wu_sched':>8s} {'missing':>8s} {'wrong_final':>11s} {'stranded':>9s} {'live_fenced':>11s}")
    for name, mode, var in VARIANTS:
        wu = mi = wf = st = fl = 0
        for seed in range(N):
            acts = gen_actions(random.Random(seed), **gk)
            viol, w, s_, m = run(mode, acts, var)
            fl += 1 if m.fenced_live else 0
            kinds = {v[2] for v in viol}
            wu += "wrong_unflagged" in kinds; mi += "missing" in kinds; wf += 1 if w else 0; st += 1 if s_ else 0
        print(f"{name:30s} {wu:8d} {mi:8d} {wf:11d} {st:9d} {fl:11d}")


if __name__ == "__main__":
    N = int(sys.argv[1])
    camp(N, "A: fails 10%, loss 3%, steps 5%", p_fail=0.1, p_lost=0.03)
    camp(N, "B: fails 30% (stress), no faults", p_fail=0.3)
    camp(N, "C: fails 10% + claim fail/lower epoch", p_fail=0.1, p_claim_fail=0.1, p_lower_epoch=0.1)
    camp(N, "D: all faults + late + eq-epoch", p_fail=0.2, p_late=0.05, p_lower_epoch=0.1, p_eqwipe=0.1, p_lost=0.03, p_claim_fail=0.05)
    camp(N, "E: clock steps only + fails 10%", p_fail=0.1, p_step=0.15)
