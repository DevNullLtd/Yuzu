"""Step 2: generator with delayed old-boot deliveries + equal-epoch restarts, and plan variants testing the
candidate invariant fix for O1/F2/F3 (pair-mode applies feed ts_hwm)."""
import os, sys, random, collections
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from model import *

BASE_FIX = ("trans_hwm_rowkey", "refusal_hwm")   # F2 + F3 fixes

class PlanX(Plan):
    """variant hooks applied AFTER Plan.ingest (mode captured from agent_step)."""
    def __init__(s, opts=(), hook=None):
        Plan.__init__(s, opts); s.hook = hook; s.name = "planx"
    def ingest(s, ev, now):
        box = {}
        orig = s.agent_step
        def wrapped(e, n):
            m = orig(e, n); box["m"] = m; return m
        s.agent_step = wrapped
        prev = s.rows.get(ev.rule); prev_key = prev.key if prev is not None else 0
        Plan.ingest(s, ev, now)
        s.agent_step = orig
        mode = box.get("m"); r = s.rows.get(ev.rule)
        if r is None or s.hook is None: return
        key, _ = derive_key(ev.ts, now)
        def raise_to(v):
            if v > (r.ts_hwm or 0):
                r.ts_hwm = v; r.hwm_recv = now
        pairmodes = ("current", "straggler", "rebase", "refused_regression", "refused_retired")
        if s.hook in ("rebase_hwm", "flagged_apply_hwm"):
            if mode in ("current", "straggler", "rebase") and r.pair == ev.pair and r.iseq == ev.iseq:
                if (s.hook == "rebase_hwm" and mode == "rebase") or (s.hook == "flagged_apply_hwm" and r.flag):
                    raise_to(key)
        elif s.hook == "fold_prev":      # while flagged by a pair-mode event, ts_hwm >= event key and superseded row key
            if mode in pairmodes and r.flag:
                raise_to(max(key, prev_key))
        elif s.hook == "fold_all":       # same for every mode
            if r.flag:
                raise_to(max(key, prev_key))

VARIANTS = {
    "v4":                    lambda: V4(),
    "plan(as written)":      lambda: PlanX(()),
    "plan+F2F3":             lambda: PlanX(BASE_FIX),
    "+rebase_hwm":           lambda: PlanX(BASE_FIX, "rebase_hwm"),
    "+flagged_apply_hwm":    lambda: PlanX(BASE_FIX, "flagged_apply_hwm"),
    "+fold_prev":            lambda: PlanX(BASE_FIX, "fold_prev"),
    "+fold_all":             lambda: PlanX(BASE_FIX, "fold_all"),
    "+fold_prev+held":       lambda: PlanX(BASE_FIX + ("held_apply_if_newer_key",), "fold_prev"),
}

def gen2(rng, nrules=2, lags=(10, 46, 600), p_lost=0.0, p_reorder=0.1, p_step=0.05, p_claim_fail=0.0,
         p_lower_epoch=0.0, p_eqwipe=0.0, p_late=0.0, p_quiet_gap=0.15):
    """like model.gen_schedule, plus: p_late = a paired event is delivered 4000-8000 s late (old boot's event
    arriving after a restart); p_eqwipe = a restart reuses the same epoch (KV-wipe residual), seq resets."""
    t = 1_000_000; off = 0; boots = rng.randint(1, 4)
    epoch = rng.randint(1000, 5000); eid = 0; arrivals = []
    for b in range(boots):
        if b > 0:
            t += rng.choice([60, 600, 4000, 12000])
            r = rng.random()
            if r < p_lower_epoch: epoch = max(1, epoch - rng.randint(1, 3000))
            elif r < p_lower_epoch + p_eqwipe: pass
            else: epoch += rng.randint(1, 5000)
        claim_fail = rng.random() < p_claim_fail
        seq = 0
        for _ in range(rng.randint(2, 10)):
            t += rng.choice([4000, 8000]) if rng.random() < p_quiet_gap else rng.randint(1, 60)
            if rng.random() < p_step: off -= rng.randint(1, 20)
            elif rng.random() < 0.03: off += rng.randint(1, 20)
            seq += 1; eid += 1
            rule = rng.randrange(nrules)
            ev = Ev(id=eid, rule=rule, state=rng.choice("CE"), ts=t + off, t_emit=t,
                    pair=None if claim_fail else (epoch, seq), lost=False)
            if rng.random() < p_lost:
                rep = Ev(id=ev.id, rule=rule, state=ev.state, ts=ev.ts, t_emit=ev.t_emit, pair=None, lost=False)
                arrivals.append((t + rng.choice(list(lags)), rep))
            else:
                d = rng.randint(0, 3) + (rng.randint(0, 2) if rng.random() < p_reorder else 0)
                if rng.random() < p_late: d += rng.choice([4000, 8000])
                arrivals.append((t + d, ev))
    arrivals.sort(key=lambda x: x[0])
    return arrivals

def camp(N, label, **gk):
    print(f"\n## {label}  {gk}")
    print(f"{'variant':24s} {'wu_sched':>8s} {'wf_final':>8s} {'rightflag_final':>15s}")
    for name, mk in VARIANTS.items():
        wu = wf = rf = 0
        for seed in range(N):
            arr = gen2(random.Random(seed), **gk)
            viol, w, m = run(mk, arr)   # run() calls cls(**kw) only if kw; mk is a factory
            wu += 1 if viol else 0; wf += 1 if w else 0
            # right-but-flagged at end (cost of the fix)
            truth = {}
            for at, ev in arr:
                c = truth.get(ev.rule)
                if c is None or ev.t_emit > c[0]: truth[ev.rule] = (ev.t_emit, ev.state)
            rf += 1 if any(r in m.rows and m.rows[r].flag and m.rows[r].state == st for r, (te, st) in truth.items()) else 0
        print(f"{name:24s} {wu:8d} {wf:8d} {rf:15d}")

if __name__ == "__main__":
    N = int(sys.argv[1])
    camp(N, "A lost 3%, no faults (regression check)", p_lost=0.03)
    camp(N, "B claim-fail 2% only", p_claim_fail=0.02)
    camp(N, "C lower-epoch 2% only", p_lower_epoch=0.02)
    camp(N, "D clock steps only", p_step=0.15)
    camp(N, "E late old-boot only", p_late=0.05, p_lower_epoch=0.1, p_eqwipe=0.1)
    camp(N, "F late + lower/eq epoch + lost 3%", p_late=0.05, p_lower_epoch=0.1, p_eqwipe=0.1, p_lost=0.03, p_claim_fail=0.02)
