"""Digests of the plan model (pend.Store plan REC2 + pend.gen_actions) for the C++ harness cross-check.
Canonical forms are those of test_census_pair_harness.cpp (snap_text, schedule_text)."""
import os, sys, random, copy
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from pend import Store, gen_actions
REC2 = ("seen_arrival", "seen_epoch", "fold_seen_all", "repair_ro", "observe_failed")
CAMPS = [dict(p_fail=0.2, p_lost=0.03, p_step=0.05, p_claim_fail=0.05, p_lower_epoch=0.1, p_eqwipe=0.1, p_late=0.05),
         dict(p_fail=0.1, p_lost=0.03),
         dict(p_fail=0.4, p_step=0.2),
         dict(p_fail=0.2, p_lost=0.03, p_eqwipe=0.4),
         dict(p_fail=0.2, p_claim_fail=0.05, p_lower_epoch=0.15, p_eqwipe=0.1, p_late=0.2)]
f = lambda x: "" if x is None else str(x)
# An FNV-style 64-bit hash with a NON-standard offset basis (1469598103934665603; real FNV-1a is
# 14695981039346656037). Identical to fnv1a() in test_census_pair_harness.cpp; changing it requires
# regenerating the digest table.
def fnv(s):
    h = 1469598103934665603
    for c in s.encode():
        h ^= c; h = (h * 1099511628211) & 0xFFFFFFFFFFFFFFFF
    return h
def schedule_text(acts):
    o = ""
    for at, kind, x, fail in acts:
        if kind == "first":
            e, s = x.pair if x.pair else (0, 0)
            o += "F,%d,%d,%d,%s,%d,%d,%d,%d\n" % (at, x.id, x.rule, x.state, x.ts, e, s, 1 if fail else 0)
        else:
            o += "R,%d,%d,%d\n" % (at, x, 1 if fail else 0)
    return o
def trace_text(seed, acts, nrules):
    m = Store("plan", REC2); o = ""
    for i, (at, kind, x, fail) in enumerate(acts):
        if kind == "first": m.first(copy.copy(x), at, fail)
        else: m.repair(x, at, fail)
        tag = "%d|%d|" % (seed, i)
        o += "D|" + tag + m.last + "\n"
        for rule in range(nrules):
            r = m.rows.get(rule)
            if r is None: continue
            o += "R|%sr%d|%s|%s|%s|%s|%s|%s|%s|%s|%s|t%s\n" % (tag, rule, r.state, "t" if r.flag else "f",
                f(r.pair[0] if r.pair else None), f(r.pair[1] if r.pair else None), r.key, f(r.ts_hwm), f(r.seq_hwm), r.iseq, f(r.hwm_recv), r.upd)
        ids = ",".join(str(e.id) for e in sorted(m.events.values(), key=lambda e: e.iseq) if e.pending)
        o += "P|%s%s\n" % (tag, ids)
        a = m.ag; c = m.cnt
        o += "A|%s%s|%s|%s|%d|%d|%d|%d|%d|%d|%d|%s\n" % (tag, f(a.epoch), f(a.hwm), f(a.retired), c["unpaired_events"], c["unpaired_held"],
            c["pair_regressions"], c["pair_stragglers"], c["pair_recoveries"], c["pair_duplicates"], c["retired_events"], f(a.recv))
    return o
def seed_acts(seed):
    gk = dict(CAMPS[seed % 5]); nrules = 2 + (seed // 5) % 2
    pf = gk.pop("p_fail")
    return gen_actions(random.Random(seed), p_fail=pf, nrules=nrules, **gk), nrules
if __name__ == "__main__":
    n = int(sys.argv[1]) if len(sys.argv) > 1 else 64
    for seed in range(n):
        acts, nr = seed_acts(seed)
        print("%d %016x %016x" % (seed, fnv(schedule_text(acts)), fnv(trace_text(seed, acts, nr))))
