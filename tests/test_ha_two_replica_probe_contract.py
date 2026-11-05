#!/usr/bin/env python3
"""Offline contract test for scripts/ha/ha-two-replica-probe-client.py (HA WS-13 slice 13.6, #7082).

No rig, no network: synthetic run directories only. It pins the rules whose failure would let a run that proves
nothing read as valid evidence (positive-evidence validity, scoring of non-dispatch errors, an export that must not
replace committed CSVs with empty files). Run with `python3 -I tests/test_ha_two_replica_probe_contract.py`.
It is not wired into CI; the rig it supports is a lab measurement tool, not a deployment.
"""
import csv
import importlib.util
import json
import os
import shutil
import sys
import tempfile
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
CLIENT = os.path.join(HERE, "..", "scripts", "ha", "ha-two-replica-probe-client.py")
spec = importlib.util.spec_from_file_location("probe_client", CLIENT)
pc = importlib.util.module_from_spec(spec)
sys.dont_write_bytecode = True
spec.loader.exec_module(pc)

AGENTS = ["agent-a", "agent-b"]


def row(label, replica, surface, agent, outcome="delivered", http=202, arm="ids", cohort="clean", holder="1"):
    return {"label": label, "replica": replica, "surface": surface, "agent_id": agent, "arm": arm, "cohort": cohort,
            "holder": holder, "role": "holder" if str(replica) == holder else "non-holder", "http": http,
            "outcome": outcome, "final_outcome": outcome, "command_id": "c", "reason": "", "t_send_ms": 1,
            "agents_reached": 1, "body": ""}


def good_rows(labels=("control", "+60s", "+120s", "+300s", "+420s")):
    return [row(l, r, s, a) for l in labels for r in (1, 2) for s in ("v1", "legacy") for a in AGENTS]


class RunDir:
    def __init__(self, rows, scenario="NOFAULT", window=480, complete=True, sample=True, meta=True, name="run-x"):
        self.root = tempfile.mkdtemp(prefix="yuzu_test_probe_")
        self.dir = os.path.join(self.root, name)
        os.makedirs(self.dir)
        with open(os.path.join(self.dir, "probes.jsonl"), "w") as f:
            for r in rows:
                f.write(json.dumps(r) + "\n")
        if meta:
            open(os.path.join(self.dir, "meta.txt"), "w").write("id=%s victim=gateway-1 total=20 window=%s sample=2\n" % (scenario, window))
        if sample:
            open(os.path.join(self.dir, "sample.txt"), "w").write("".join("%s,clean,1\n" % a for a in AGENTS))
        if complete:
            open(os.path.join(self.dir, "COMPLETE"), "w").close()

    def rows(self):
        return pc.load_rows(os.path.join(self.dir, "probes.jsonl"))

    def close(self):
        shutil.rmtree(self.root, ignore_errors=True)


class ValidityTests(unittest.TestCase):
    def check(self, rd, **kw):
        return pc.run_validity(rd.dir, rd.rows(), **kw)

    def test_complete_good_run_is_valid(self):
        rd = RunDir(good_rows()); self.addCleanup(rd.close)
        self.assertEqual(self.check(rd, require_complete=True), [])

    def test_empty_probes_not_valid(self):
        rd = RunDir([]); self.addCleanup(rd.close)
        self.assertTrue(self.check(rd))

    def test_no_control_rows_not_valid(self):
        rd = RunDir(good_rows(("+60s", "+120s", "+300s", "+420s"))); self.addCleanup(rd.close)
        self.assertTrue(any("control" in w for w in self.check(rd)))

    def test_missing_replica_not_valid(self):
        rd = RunDir([r for r in good_rows() if not (r["replica"] == 2 and r["label"] == "+300s")]); self.addCleanup(rd.close)
        self.assertTrue(self.check(rd))

    def test_all_http_500_not_valid(self):
        rows = [row(l, r, s, a, outcome="rig_error", http=500) for l in ("control", "+60s", "+120s", "+300s", "+420s")
                for r in (1, 2) for s in ("v1", "legacy") for a in AGENTS]
        rd = RunDir(rows); self.addCleanup(rd.close)
        self.assertTrue(any("rig-error" in w or "control failed" in w for w in self.check(rd)))

    def test_control_only_window_not_valid(self):
        rd = RunDir(good_rows(("control",)), window=60); self.addCleanup(rd.close)
        self.assertTrue(self.check(rd))

    def test_no_meta_not_valid(self):
        rd = RunDir(good_rows(), meta=False); self.addCleanup(rd.close)
        self.assertTrue(self.check(rd))

    def test_duplicate_rows_not_valid(self):
        rd = RunDir(good_rows() + [good_rows()[0]]); self.addCleanup(rd.close)
        self.assertTrue(any("duplicate" in w for w in self.check(rd)))

    def test_incomplete_needs_marker_or_attestation(self):
        rd = RunDir(good_rows(), complete=False); self.addCleanup(rd.close)
        self.assertTrue(self.check(rd, require_complete=True))
        self.assertEqual(self.check(rd, require_complete=True, legacy_unmarked=True), [])
        self.assertEqual(self.check(rd), [])

    def test_fault_run_needs_capture_showing_the_drop(self):
        rd = RunDir(good_rows(), scenario="F3-2r"); self.addCleanup(rd.close)
        open(os.path.join(rd.dir, "fault_ms"), "w").write("1000000")
        open(os.path.join(rd.dir, "undo_ms"), "w").write("1480000")
        self.assertTrue(any("no packet-capture" in w for w in self.check(rd)))
        cap = "---COUNTS---\nin10s 1010 3\nout10s 1020 0\nout10s 1030 0\n"
        open(os.path.join(rd.dir, "cap-victim-50055.txt"), "w").write(cap)
        self.assertEqual(self.check(rd), [])
        open(os.path.join(rd.dir, "cap-victim-50055.txt"), "w").write(cap + "out10s 1040 7\n")
        self.assertTrue(any("drop did not hold" in w for w in self.check(rd)))


class ScoreTests(unittest.TestCase):
    def test_only_503_or_zero_reached_is_a_refusal(self):
        for http, want in ((503, "refused"), (0, "rig_error"), (401, "rig_error"), (429, "rig_error"), (500, "rig_error")):
            self.assertEqual(pc.score({"http": http, "agents_reached": "", "body": ""}, [])[0], want, http)
        self.assertEqual(pc.score({"http": 202, "agents_reached": 0, "body": ""}, [])[0], "refused")
        self.assertEqual(pc.score({"http": 400, "agents_reached": "", "body": "x could not be parsed"}, [])[0], "probe_invalid")

    def test_server_synthesised_is_not_delivered(self):
        rec = {"http": 202, "agents_reached": 1, "body": ""}
        self.assertEqual(pc.score(rec, [{"status": 2, "error_detail": "[gateway_unavailable] x"}])[0], "server_synthesised")
        self.assertEqual(pc.score(rec, [{"status": 1, "output": "Linux"}])[0], "delivered")
        self.assertEqual(pc.score(rec, [])[0], "accepted_no_result")

    def test_untagged_rows_are_never_clean(self):
        rows = [{"label": "control", "arm": "ids", "agent_id": "a", "final_outcome": "delivered"}]
        pc.classify_cohorts(rows)
        self.assertEqual(rows[0]["cohort_eff"], "unknown")

    def test_failed_control_makes_the_agent_inconclusive(self):
        rows = good_rows(("control",))
        for r in rows:
            if r["agent_id"] == "agent-a" and r["replica"] == 2:
                r["final_outcome"] = "refused"
        bad = pc.classify_cohorts(rows)
        self.assertEqual(bad, ["agent-a"])
        self.assertTrue(all(r["cohort_eff"] == "inconclusive" for r in rows if r["agent_id"] == "agent-a"))

    def test_load_rows_skips_non_objects(self):
        rd = RunDir(good_rows()); self.addCleanup(rd.close)
        with open(os.path.join(rd.dir, "probes.jsonl"), "a") as f:
            f.write("[1, 2]\nnot json\n")
        self.assertEqual(len(rd.rows()), len(good_rows()))


class ExportTests(unittest.TestCase):
    def run_export(self, state, out, runs="", legacy=""):
        import argparse
        a = argparse.Namespace(state=state, out=out, runs=runs, legacy_unmarked=legacy)
        pc.cmd_export(a)

    def test_zero_runs_never_replaces_the_committed_csvs(self):
        out = tempfile.mkdtemp(prefix="yuzu_test_probe_"); self.addCleanup(shutil.rmtree, out, True)
        committed = os.path.join(out, "probe-summary.csv")
        open(committed, "w").write("committed\n")
        empty = tempfile.mkdtemp(prefix="yuzu_test_probe_"); self.addCleanup(shutil.rmtree, empty, True)
        with self.assertRaises(SystemExit):
            self.run_export(empty, out)
        self.assertEqual(open(committed).read(), "committed\n")

    def test_good_run_exports_valid_and_bad_run_exports_not_valid(self):
        state = tempfile.mkdtemp(prefix="yuzu_test_probe_"); self.addCleanup(shutil.rmtree, state, True)
        out = tempfile.mkdtemp(prefix="yuzu_test_probe_"); self.addCleanup(shutil.rmtree, out, True)
        good = RunDir(good_rows(), name="run-good"); bad = RunDir(good_rows(("+60s",)), name="run-bad")
        for rd in (good, bad):
            shutil.move(rd.dir, os.path.join(state, os.path.basename(rd.dir))); self.addCleanup(rd.close)
        self.run_export(state, out)
        got = {r["run"]: r["valid"] for r in csv.DictReader(open(os.path.join(out, "run-timeline.csv")))}
        self.assertEqual(got, {"run-good": "yes", "run-bad": "no"})


if __name__ == "__main__":
    unittest.main(verbosity=1)
