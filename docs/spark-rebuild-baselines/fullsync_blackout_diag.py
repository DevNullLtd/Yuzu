#!/usr/bin/env python3
"""#3990 full_sync blackout diagnostic driver (ruling-13 on #3850).

One-time rig-scoped instrument, not production tooling (see the plan's
"Sol feedback declined" section for why this stays simple rather than
production-hardened). Measures B = T1 - T0 (log interval, continuity only)
and C = T2_last - T0 (primary measurand, R5.7) on a single Windows agent
under two detection backends (legacy IGuard vs spark), triggered two ways:
a baseline (re)deploy, and a bare rule-create in no baseline (the
heartbeat-reconcile trigger that is #3990's own literal shape).

See docs/spark-rebuild-baselines/3990-fullsync-blackout-run.md for the
measurand definitions, void rules, and decision criterion this implements -
this file is the mechanism, that doc is the record of what it measured.

Environment: YUZU_BASE (default http://localhost:8080, inherited from
generate_resgate_load.py's own G.BASE), YUZU_ADMIN_USER,
YUZU_ADMIN_PASS (defaults match generate_resgate_load.py's UAT defaults -
override for a non-default rig). YUZU_DGRHP_SSH (ssh destination for the
agent-log reads, e.g. "-S /tmp/sock -i ~/.ssh/key user@host" as a single
pre-built arg string), YUZU_AGENT_LOG (default C:\\rigA\\logs\\agent.log).

PARTIALLY FIXED 2026-09-07 (see docs/spark-rebuild-baselines/3990-fullsync-blackout-run.md,
"T1 detection: the real root cause"): much of the t0_not_found/t1_not_found false-void rate
from the 2026-09-06/07 run is explained by a flush-lag gap, not this script's window/timestamp
matching logic. `agents/core/src/main.cpp` never calls `logger->flush_on(...)` on the
--log-file sink, and spdlog's own default `flush_level_` is `level::off` - confirmed against
the vendored header, not assumed - so a log line's embedded timestamp is accurate at write
time, but the underlying bytes can sit unflushed for an unpredictable period (measured live:
from ~2s up to ~108s) before becoming visible to ANY external reader, this script included.
Widened ROOT_CAUSED_T0_TIMEOUT/ROOT_CAUSED_T1_TIMEOUT to compensate - a bounded workaround for
this one-time measurement, NOT a proven-reliable fix.

FIXED 2026-09-07: `run_repeat()` folds `functional_valid` into `void_reason` itself for the
clean-verdict phases (B/B2). Cohort service-watch targets use `BLACKOUT_SVC_OVERRIDE` (5
services confirmed live, replacing 5 confirmed Stopped on DGRHP).

R5.7 T2 RE-MEASUREMENT (2026-09-19, rung 9c PR-6 item 2 - see
docs/spark-stage2-guardian-consumer-design.md "R5.7 - Re-measurement methodology"):
Window B alone is no longer a valid proxy for spark's real arm-completion latency on current
`origin/dev` - rung 9c PR-2 added `pending=` to the `apply_rules ok` line and moved
`reconcile_rule_locked()` to a NonWaiting attach model, so T1 no longer waits for every rule's
arm to commit. This round adds:
  - dev-shape T1_RE (six groups, `pending=` included).
  - T0D_RE: a new runtime log line, `Guardian spark: detach_all complete (epoch=,
    incarnation_floor=, detached_rules=, withdrawn_claims=)`, emitted as the LAST statement of
    `GuardianSparkRuntime::detach_all()`'s locked block. `epoch` is a monotonic per-application
    counter (`detach_epoch_`), `incarnation_floor` is `gen_counter_` at teardown time.
  - T2_RE: a new runtime log line, `Guardian spark: arm committed for rule '<id>' (epoch=,
    incarnation=, type=, via=, attach_to_commit_ms=)`, the LAST statement of
    `GuardianSparkRuntime::commit_new_generation_locked()` - the only valid log-side proxy for
    "this rule is armed" under spark. `epoch` names which application (full_sync teardown) the
    commit belongs to; membership is decided by EPOCH IDENTITY, never by timestamp order (a
    previous application's stale in-flight callback can otherwise land between the new
    `full_sync cleared` line and `detach_all()` and get miscounted - found by an Astra
    adversarial review of this round's design, independently confirmed against source before
    being folded in).
  - C = T2_last - T0 is now the HEADLINE measurand; B is reported for continuity only and no
    longer brackets synchronous arm completion under the NonWaiting model - a drop in B versus
    the historical clean-v2 numbers is a MODEL CHANGE, not an improvement, and must not be
    reported as one.
  - Two-class void taxonomy (instrument-invalid vs genuine failure), `run_id`-scoped Phase B2
    trigger ids (closes a real trigger-ID-reuse trap the existing run doc already documented),
    bounded functional-validity polling, and an offline `selftest` subcommand (run BEFORE any
    server login) covering the fence logic end to end.

KNOWN BUG, FIXED THIS ROUND: `cmd_report`'s grouping previously could not distinguish rows from
two different `run` invocations sharing the same label. Every row now carries `run_id` and
`comparison_id`; grouping and the printed report key on both.

The flush-lag gap above is a real property of the agent's --log-file output worth flagging as
its own product finding (live-tailing --log-file for near-real-time diagnostics is unreliable
without a flush policy) - filed as https://github.com/Tr3kkR/Yuzu/issues/4608 (2026-09-19,
after a later re-measurement round on this same diagnostic's methodology hit the identical
gap a second time).
"""

import argparse
import hashlib
import json
import os
import re
import shlex
import statistics
import subprocess
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime, timedelta, timezone

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import generate_resgate_load as G  # noqa: E402

BASE = G.BASE
SCRATCH_DIR = os.environ.get("YUZU_BLACKOUT_SCRATCH", "/tmp/blackout-diag")
os.makedirs(SCRATCH_DIR, exist_ok=True)

DGRHP_SSH = os.environ.get("YUZU_DGRHP_SSH", "")
AGENT_LOG = os.environ.get("YUZU_AGENT_LOG", r"C:\rigA\logs\agent.log")

COHORT_PREFIX = "blackout-"
COHORT_N = 20  # 20 file + 20 registry + 20 service = 60
COHORT_BASELINE = "blackout-cohort"
TRIGGER_RULE_ID = "blackout-trigger-rule"
TRIGGER_BASELINE = "blackout-trigger"
SCRATCH_DIR_WIN = r"C:\rigA\blackout-scratch"

# 1-indexed override of G.SERVICE_NAMES for THIS script's cohort only - see the "FIXED
# 2026-09-07" docstring note above for why (Spooler/Themes/BITS/wuauserv/W32Time confirmed
# Stopped on DGRHP, live-checked before picking these replacements).
BLACKOUT_SVC_OVERRIDE = {1: "LSM", 2: "DcomLaunch", 4: "RpcEptMapper", 5: "nsi", 15: "SamSs"}

RIGA_ALLOWLIST_RE = re.compile(r"^riga-")
PROTECTED_RULE_IDS = {"dgrhp-drift-test-file"}
PROTECTED_BASELINE_NAMES = {"DGRHP File Drift Test"}

LOG_TS_RE = re.compile(
    r"^\[(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}\.\d{3})\] \[(\w+)\] \[(\d+)\] (.*)$"
)
T0_RE = re.compile(r"Guardian: full_sync cleared (\d+) prior rule\(s\)")
T0_FALLBACK_RE = re.compile(r"Received command: plugin=__guard__, action=push_rules")
PUSH_CMD_RE = T0_FALLBACK_RE  # same line; R5.7 role: an OBSERVED push command, not a T0
T1_RE = re.compile(
    r"Guardian: apply_rules ok \(applied=(\d+), failed=(\d+), pending=(\d+), "
    r"full_sync=(true|false), generation=(\d+), total=(\d+)\)"
)
T0D_RE = re.compile(
    r"Guardian spark: detach_all complete \(epoch=(\d+), incarnation_floor=(\d+), "
    r"detached_rules=(\d+), withdrawn_claims=(\d+)\)"
)
T2_RE = re.compile(
    r"Guardian spark: arm committed for rule '([^']+)' \(epoch=(\d+), "
    r"incarnation=(\d+), type=([\w-]+), via=([\w-]+), attach_to_commit_ms=(\d+)\)"
)
# #4665: the "Guardian: " prefix is REQUIRED in the pattern text itself, unlike the other
# five anchored regexes below - the real emitter (guardian_engine.cpp's file/service/registry
# guard-armed spdlog::info calls) writes `msg` as "Guardian: file guard armed for rule '...'
# (...)", so the defining phrase does NOT start at msg's position 0 without it. Every call
# site now uses `.match()` (position-0-anchored); dropping this prefix would silently break
# every genuine legacy-arm match, not just close the forgery this anchoring exists to close.
ARM_LEGACY_RE = re.compile(r"Guardian: (?:file|service|registry) guard armed for rule '([^']+)'")
ARM_SPARK_RE = re.compile(r"SparkEngine: armed '([^']+)'")
BACKEND_RE = re.compile(r"detection backend = (\w+)")
NETWORK_CONNECTED_RE = re.compile(r"Guardian engine network-connected")

# Void taxonomy (R5.7 round 2, §2.2 item 3). Instrument-invalid: the instrument, not the
# system, failed - reported, never counted, never held against reliability. Genuine failure:
# the system did not do what the push asked - counts against the phase's reliability gate AND
# is a product finding. `void_class_for` has no prefix matching for most dynamic reasons:
# `trigger_failed:<msg>` (like any other reason not listed in GENUINE_FAILURE_REASONS or
# matched below) classifies instrument by default. ONE deliberate exception:
# `not_full_sync(<v>)` (D1, driver-merge follow-on review) - see void_class_for's own
# docstring for why this one dynamic-prefix reason classifies genuine.
INSTRUMENT_INVALID_REASONS = frozenset({
    "t0_not_found", "t0d_not_found", "t1_not_found", "t2_incomplete", "t2_late",
    "log_rotated_mid_window", "trigger_not_created", "repush_confound",
    "applied_ne_total", "double_full_sync", "cohort_composition", "teardown_size_mismatch",
})
GENUINE_FAILURE_REASONS = frozenset({
    "failed_gt_0", "arm_never_confirmed", "functional_invalid", "fence_violation",
})


def void_class_for(reason):
    """`not_full_sync(<v>)` is a deliberate exception to the no-prefix-matching rule
    (D1, driver-merge follow-on review, 2026-09-19): T0 only logs inside
    `if (push.full_sync())` (guardian_engine.cpp), and apply_rules is mtx_-serialised,
    so a T1 line matched for this application with full_sync=false almost always means
    a real mid-reconcile failure (guardian_engine.cpp's per-rule persist-failure path
    latches after teardown, before re-arming) rather than an instrument problem -
    exactly the blackout this diagnostic exists to detect. Classified genuine on
    asymmetric cost: a false genuine costs one unnecessary look, a false instrument
    silently discards real evidence. Known false-genuine risk, accepted: an ordinary
    agent restart between T0d and the ok line produces the same log signature; the
    detector that would disambiguate (BACKEND_RE/NETWORK_CONNECTED_RE) is dead code
    (#4610). The row retains its own `full_sync` field independent of void_reason, so
    this classification can be reversed without re-deriving anything from the string."""
    if reason is None:
        return None
    if reason in GENUINE_FAILURE_REASONS or (reason and reason.startswith("not_full_sync(")):
        return "genuine"
    return "instrument"


def genuine_t1_failure(phase, failed):
    """Pure: does this attempt's own T1-reported `failed` count override any
    LATER collection-stage void reason? R5.7 adversarial-review fix (both
    reviewers independently probed this live) - `run_repeat` must check this
    before `collect_t2`'s own void `reason`, never after, or a genuine
    backend-reported arm failure can be laundered into an instrument-invalid
    void just because the same window also saw an unrelated collection-stage
    confound (found live: R5.7 T2 re-run, Phase B2 spark repeat 3)."""
    return "failed_gt_0" if phase in ("B", "B2") and failed > 0 else None


def resolve_post_t2_void(t1_genuine_reason, collection_reason):
    """Pure: the WHOLE precedence decision `run_repeat` needs once both
    signals are available - a T1-genuine failure reason (from
    genuine_t1_failure(), known before T2 collection even starts) and
    collect_t2()'s own collection-stage void `reason` (known only after).
    Genuine ALWAYS wins, unconditionally.

    This function exists (rather than leaving the two sequential `if`s inline
    in `run_repeat`) because `run_repeat` does live SSH/network I/O and has no
    offline selftest coverage - a first version of this fix's own regression
    test (selftest F15) handed a pre-labeled `void_class="genuine"` row
    straight to `compute_verdict()`, which never exercises this precedence
    decision at all and would have passed unchanged had the fix never
    shipped (found by quality-engineer during /governance, confirmed by
    reverting the fix and re-running selftest - it still passed 17/17).
    Extracting the decision itself into a pure function lets a fixture
    supply BOTH signals at once and assert genuine wins, which is what
    actually regression-tests the bug. Returns (void_class, void_reason)."""
    if t1_genuine_reason:
        return "genuine", t1_genuine_reason
    if collection_reason:
        return void_class_for(collection_reason), collection_reason
    return None, None


# --------------------------------------------------------------------------
# ssh / agent-log helpers
# --------------------------------------------------------------------------


def _ssh_argv():
    if not DGRHP_SSH:
        raise RuntimeError("YUZU_DGRHP_SSH not set")
    return ["ssh"] + shlex.split(DGRHP_SSH)


def ssh_ps(cmd_ps1, timeout=30):
    """Run a PowerShell command on DGRHP over the (assumed already-open,
    control-mastered) ssh connection. -EncodedCommand (base64 UTF-16LE) is
    used deliberately - a plain -Command string gets re-quoted by the hop
    through ssh's own argv-join + the remote shell, mangling pipes/parens
    (confirmed empirically: 'Measure-Object' is not recognized' from a
    perfectly valid PS pipeline). Encoding sidesteps that layer entirely."""
    import base64
    encoded = base64.b64encode(cmd_ps1.encode("utf-16-le")).decode("ascii")
    argv = _ssh_argv() + ["powershell.exe", "-NoProfile", "-EncodedCommand", encoded]
    try:
        r = subprocess.run(argv, capture_output=True, timeout=timeout)
    except subprocess.TimeoutExpired:
        # Governance (this round, security-guardian): subprocess.TimeoutExpired's own
        # str() embeds the full argv - the ssh destination/user and any -i key path from
        # YUZU_DGRHP_SSH - at the START of the message. Every caller that truncates a
        # caught exception's str() to a bounded length (str(e)[:200], to keep committed
        # JSONL evidence rows bounded) truncates from the END, which does NOT remove that
        # prefix - several call sites' own comments claimed it did, which was false as
        # written (that reasoning was about payload SIZE, not argv POSITION). Sanitize
        # once, here, at the source, rather than trying to fix every caller's truncation.
        raise TimeoutError(f"ssh_ps timed out after {timeout}s") from None
    stdout = r.stdout.decode("utf-8", errors="replace")
    stderr = r.stderr.decode("utf-8", errors="replace")
    if r.returncode != 0 and not stdout:
        # Governance (Gate 8 re-review, security-guardian): this raise has the identical
        # leak shape the TimeoutExpired fix above closed - OpenSSH's own connection/auth
        # failure text (destination host, "Load key '<path>': ...") lands in `stderr` on
        # exactly the failures this branch exists to report, and that text used to flow
        # straight into the same str(e)[:200] call sites the TimeoutExpired fix was
        # supposed to make uniformly safe. Print the raw stderr locally (console only,
        # never committed) for whoever is actually debugging the rig; raise a sanitized
        # message - just the return code - so every downstream void_reason site stays
        # safe without needing its own fix.
        print(f"[ssh_ps] rc={r.returncode} stderr: {stderr[:500]}", file=sys.stderr)
        raise RuntimeError(f"ssh_ps failed rc={r.returncode}")
    return stdout


_DGRHP_UTC_OFFSET = None  # timedelta, lazily computed once - see dgrhp_utc_offset()


def dgrhp_utc_offset():
    """DGRHP's local-clock UTC offset (a timedelta), e.g. +1h under BST. See the
    original docstring history in git blame for why this is computed live rather
    than hardcoded - unchanged this round."""
    global _DGRHP_UTC_OFFSET
    if _DGRHP_UTC_OFFSET is None:
        out = ssh_ps(
            "[System.TimeZoneInfo]::Local.GetUtcOffset([DateTime]::Now).TotalSeconds"
        ).strip()
        _DGRHP_UTC_OFFSET = timedelta(seconds=float(out))
    return _DGRHP_UTC_OFFSET


def dgrhp_now():
    """'Now', expressed in the SAME local-labeled-as-UTC convention
    parse_log_line() uses - read DGRHP's own clock directly (one ssh round
    trip) rather than doing cross-host arithmetic, which drifts. A small
    backward safety margin absorbs the round-trip time between reading the
    clock and actually issuing the trigger. Unchanged this round."""
    out = ssh_ps("Get-Date -Format 'yyyy-MM-dd HH:mm:ss.fff'").strip()
    ts = datetime.strptime(out, "%Y-%m-%d %H:%M:%S.%f").replace(tzinfo=timezone.utc)
    return ts - timedelta(seconds=2)


TAIL_LINES = 20000  # generous: observed peak ~115 lines/sec from the leftover riga-* outbox
                     # storm, so this covers several minutes even in the noisy pre-purge phase.
                     # R5.7: also ample for the clean-cohort B/B2 burst (~62 SparkEngine armed
                     # + 62 T2 + T0/T0d/T1 + evals); NOT ample at the Phase-A storm rate - see
                     # tail_saturated tracking in observe_t0().

ROOT_CAUSED_T0_TIMEOUT = 240
ROOT_CAUSED_T1_TIMEOUT = 240
ROOT_CAUSED_T0D_TIMEOUT = 240
ROOT_CAUSED_T2_VISIBILITY_TIMEOUT = 240


def agent_log_size():
    """Cheap O(1) file-length probe, used only to detect rotation."""
    out = ssh_ps(f"(Get-Item -LiteralPath '{AGENT_LOG}').Length")
    out = out.strip()
    return int(out) if out else 0


def agent_log_tail():
    """Fixed-size tail read. Callers filter to their own window by comparing
    each line's OWN embedded timestamp against a Python-side start marker."""
    out = ssh_ps(f"Get-Content -Path '{AGENT_LOG}' -Tail {TAIL_LINES}")
    return out.splitlines()


def parse_log_line(raw):
    m = LOG_TS_RE.match(raw)
    if not m:
        return None
    ts_str, level, thread, msg = m.groups()
    ts = datetime.strptime(ts_str, "%Y-%m-%d %H:%M:%S.%f").replace(tzinfo=timezone.utc)
    return {"ts": ts, "level": level, "thread": thread, "msg": msg, "raw": raw}


def _ev(ts_str, msg, raw=None):
    """Construct a parsed-event-shaped dict directly, for selftest fixtures -
    bypasses parse_log_line/LOG_TS_RE so fixtures don't need a fully-formed
    `[ts] [level] [thread] msg` line, just the two fields the classification
    logic actually reads (ts, msg), plus an optional distinct `raw` for
    identity-based tests (F9's same-ms-tie case)."""
    ts = datetime.strptime(ts_str, "%Y-%m-%d %H:%M:%S.%f").replace(tzinfo=timezone.utc)
    return {"ts": ts, "level": "info", "thread": "1", "msg": msg, "raw": raw if raw is not None else msg}


# --------------------------------------------------------------------------
# HTTP helpers (beyond generate_resgate_load's)
# --------------------------------------------------------------------------


def get_json(op, path):
    req = urllib.request.Request(BASE + path, method="GET")
    return json.loads(op.open(req, timeout=20).read().decode("utf-8"))


def get_metrics(op):
    req = urllib.request.Request(BASE + "/metrics", method="GET")
    text = op.open(req, timeout=20).read().decode("utf-8", "replace")
    out = {}
    for line in text.splitlines():
        if line.startswith("#") or not line.strip():
            continue
        m = re.match(r"^([a-zA-Z_:][a-zA-Z0-9_:]*)(\{[^}]*\})?\s+([0-9eE+\-.]+)$", line)
        if m:
            name, labels, val = m.groups()
            out[name + (labels or "")] = float(val)
    return out


def metric_sum(metrics, prefix):
    return sum(v for k, v in metrics.items() if k.startswith(prefix))


# --------------------------------------------------------------------------
# cohort / rule builders
# --------------------------------------------------------------------------


def cohort_rule(kind, i):
    rid = f"{COHORT_PREFIX}{kind}-{i:02d}"
    if kind == "file":
        path = f"{SCRATCH_DIR_WIN}\\watch-{i:02d}.txt"
        return {
            "rule_id": rid, "name": rid, "enabled": True, "enforcement_mode": "audit",
            "severity": "low", "os_target": "windows", "scope": "",
            "spark": {"type": "file-change", "params": {"path": path}},
            "assertion": {"type": "file-exists", "params": {"path": path, "expected": "present"}},
            "remediation": {"type": "alert-only", "params": {}},
        }
    if kind == "reg":
        return {
            "rule_id": rid, "name": rid, "enabled": True, "enforcement_mode": "audit",
            "severity": "low", "os_target": "windows", "scope": "",
            "spark": {"type": "registry-change",
                      "params": {"hive": "HKCU", "key": f"SOFTWARE\\YuzuBlackout\\Key{i:02d}"}},
            "assertion": {"type": "registry-value-equals",
                          "params": {"hive": "HKCU", "key": f"SOFTWARE\\YuzuBlackout\\Key{i:02d}",
                                     "value_name": "Flag", "value_type": "REG_DWORD",
                                     "expected": "1"}},
            "remediation": {"type": "alert-only", "params": {}},
        }
    if kind == "svc":
        name = BLACKOUT_SVC_OVERRIDE.get(i, G.SERVICE_NAMES[i - 1])
        return {
            "rule_id": rid, "name": rid, "enabled": True, "enforcement_mode": "audit",
            "severity": "low", "os_target": "windows", "scope": "",
            "spark": {"type": "service-status-change", "params": {"service_name": name}},
            "assertion": {"type": "service-running", "params": {"service_name": name}},
            "remediation": {"type": "alert-only", "params": {}},
        }
    raise ValueError(kind)


def cohort_rules():
    rules = []
    for i in range(1, COHORT_N + 1):
        rules.append(cohort_rule("reg", i))
    for i in range(1, COHORT_N + 1):
        rules.append(cohort_rule("file", i))
    for i in range(1, COHORT_N + 1):
        rules.append(cohort_rule("svc", i))
    return rules


def expected_rule_ids():
    """R5.7: the closed 62-member set every full_sync in this diagnostic's
    cohort should re-arm (60 cohort + trigger + the pre-existing protected
    rule, which rides along on every full_sync regardless of what this
    diagnostic itself created)."""
    return set(r["rule_id"] for r in cohort_rules()) | {TRIGGER_RULE_ID} | set(PROTECTED_RULE_IDS)


def trigger_rule():
    path = f"{SCRATCH_DIR_WIN}\\trigger.txt"
    return {
        "rule_id": TRIGGER_RULE_ID, "name": TRIGGER_RULE_ID, "enabled": True,
        "enforcement_mode": "audit", "severity": "low", "os_target": "windows", "scope": "",
        "spark": {"type": "file-change", "params": {"path": path}},
        "assertion": {"type": "file-exists", "params": {"path": path, "expected": "present"}},
        "remediation": {"type": "alert-only", "params": {}},
    }


# --------------------------------------------------------------------------
# inventory / purge
# --------------------------------------------------------------------------


def cmd_inventory(op, out_path=None):
    rules = get_json(op, "/api/v1/guaranteed-state/rules?limit=1000")["data"]
    baselines_html = G.list_baselines_html(op)
    baseline_ids = re.findall(
        r'href="/guardian/baseline/([A-Za-z0-9._\-]+)"[^>]*>([^<]+)</a>', baselines_html
    )
    riga_rules = sorted(r["rule_id"] for r in rules if RIGA_ALLOWLIST_RE.match(r["rule_id"]))
    riga_baselines = sorted(
        (bid, name) for bid, name in baseline_ids if RIGA_ALLOWLIST_RE.match(name)
    )
    protected_present = {
        rid: any(r["rule_id"] == rid for r in rules) for rid in PROTECTED_RULE_IDS
    }
    protected_baselines_present = {
        name: any(n == name for _, n in baseline_ids) for name in PROTECTED_BASELINE_NAMES
    }
    manifest = {
        "total_rules": len(rules),
        "riga_rule_ids": riga_rules,
        "riga_baseline_ids": [b for b, _ in riga_baselines],
        "riga_baseline_names": {b: n for b, n in riga_baselines},
        "protected_rules_present": protected_present,
        "protected_baselines_present": protected_baselines_present,
    }
    if out_path:
        with open(out_path, "w") as f:
            json.dump(manifest, f, indent=2)
    print(
        f"[inventory] total_rules={manifest['total_rules']} riga_rules={len(riga_rules)} "
        f"riga_baselines={len(riga_baselines)} protected_rules_present={protected_present} "
        f"protected_baselines_present={protected_baselines_present}"
    )
    return manifest


def cmd_purge(op, apply=False):
    manifest_path = os.path.join(SCRATCH_DIR, "purge_manifest.json")
    fresh = cmd_inventory(op, out_path=None)
    for rid, present in fresh["protected_rules_present"].items():
        if not present:
            print(f"[purge] ABORT: protected rule '{rid}' not found - refusing to proceed",
                  file=sys.stderr)
            return 1
    for name, present in fresh["protected_baselines_present"].items():
        if not present:
            print(f"[purge] ABORT: protected baseline '{name}' not found - refusing to proceed",
                  file=sys.stderr)
            return 1
    for rid in fresh["riga_rule_ids"]:
        if not RIGA_ALLOWLIST_RE.match(rid):
            print(f"[purge] ABORT: non-allowlisted id in purge set: {rid}", file=sys.stderr)
            return 1

    if not apply:
        with open(manifest_path, "w") as f:
            json.dump(fresh, f, indent=2)
        print(f"[purge] DRY RUN: would delete {len(fresh['riga_baseline_ids'])} baselines, "
              f"{len(fresh['riga_rule_ids'])} rules. Manifest written to {manifest_path}.")
        return 0

    if not os.path.exists(manifest_path):
        print("[purge] ABORT: no dry-run manifest found - run --dry-run first", file=sys.stderr)
        return 1
    with open(manifest_path) as f:
        dry = json.load(f)
    if set(dry["riga_rule_ids"]) != set(fresh["riga_rule_ids"]) or \
            set(dry["riga_baseline_ids"]) != set(fresh["riga_baseline_ids"]):
        print("[purge] ABORT: live catalogue has drifted from the --dry-run manifest - "
              "re-run --dry-run and re-verify before --apply", file=sys.stderr)
        return 1

    failed_baselines, failed_rules = [], []
    # Governance (unhappy-path UP-9): `except Exception` deliberately does NOT catch
    # KeyboardInterrupt (a Ctrl-C should interrupt, not be swallowed as a delete failure) -
    # but a mid-loop interrupt used to lose the "what got deleted this run" tally entirely,
    # only printed at the end. try/finally prints the partial tally on any exit path,
    # interrupted or not; a subsequent --apply re-verifies against a fresh dry-run regardless.
    try:
        for i, bid in enumerate(fresh["riga_baseline_ids"], 1):
            try:
                G.delete_baseline_form(op, bid)
            except Exception as e:  # noqa: BLE001
                print(f"[purge] baseline delete FAILED {bid}: {e}", file=sys.stderr)
                failed_baselines.append(bid)
            if i % 10 == 0 or i == len(fresh["riga_baseline_ids"]):
                print(f"[purge] baselines {i}/{len(fresh['riga_baseline_ids'])}")
        for i, rid in enumerate(fresh["riga_rule_ids"], 1):
            if not G.delete_rule(op, rid):
                failed_rules.append(rid)
            if i % 500 == 0 or i == len(fresh["riga_rule_ids"]):
                print(f"[purge] rules {i}/{len(fresh['riga_rule_ids'])}")
    finally:
        print(f"[purge] tally so far: failed_baselines={len(failed_baselines)} "
              f"failed_rules={len(failed_rules)}")

    post = cmd_inventory(op, out_path=None)
    ok = (
        len(post["riga_rule_ids"]) == 0
        and len(post["riga_baseline_ids"]) == 0
        and all(post["protected_rules_present"].values())
        and all(post["protected_baselines_present"].values())
    )
    print(f"[purge] DONE. failed_baselines={len(failed_baselines)} "
          f"failed_rules={len(failed_rules)} post_riga_rules={len(post['riga_rule_ids'])} "
          f"post_riga_baselines={len(post['riga_baseline_ids'])} clean={ok}")
    return 0 if ok else 1


def prepare_cohort_targets():
    """Pre-create every watched target in its EXPECTED-compliant state before
    arming. R5.7: no longer statically pre-creates hbr-NN.txt files here -
    hbr rule ids/paths are now run_id-scoped (hbr_rule()), unknown until
    cmd_run() mints a run_id, so their watch files are touched per-repeat in
    run_repeat() instead (_touch_win_file())."""
    ps = f"""
New-Item -ItemType Directory -Force -Path '{SCRATCH_DIR_WIN}' | Out-Null
for ($i=1; $i -le {COHORT_N}; $i++) {{
    $n = $i.ToString('00')
    New-Item -ItemType File -Force -Path "{SCRATCH_DIR_WIN}\\watch-$n.txt" | Out-Null
    $key = "HKCU:\\SOFTWARE\\YuzuBlackout\\Key$n"
    New-Item -Path $key -Force | Out-Null
    New-ItemProperty -Path $key -Name 'Flag' -Value 1 -PropertyType DWord -Force | Out-Null
}}
New-Item -ItemType File -Force -Path "{SCRATCH_DIR_WIN}\\trigger.txt" | Out-Null
Write-Output "prepared"
"""
    out = ssh_ps(ps, timeout=30)
    if "prepared" not in out:
        raise RuntimeError(f"prepare_cohort_targets failed: {out[:500]}")


def _touch_win_file(path):
    out = ssh_ps(f"New-Item -ItemType File -Force -Path '{path}' | Out-Null; Write-Output done",
                 timeout=15)
    if "done" not in out:
        raise RuntimeError(f"_touch_win_file failed for {path}: {out[:300]}")


def cmd_ensure(op):
    os.makedirs(SCRATCH_DIR, exist_ok=True)
    prepare_cohort_targets()
    rules = cohort_rules()
    failed, reused = G._post_all(op, rules)
    cohort_baseline_id = G.ensure_deployed_baseline(
        op, COHORT_BASELINE, [r["name"] for r in rules]
    )
    trig = trigger_rule()
    G.post_rule(op, trig)
    trigger_baseline_id = G.ensure_deployed_baseline(op, TRIGGER_BASELINE, [trig["name"]])
    print(f"[ensure] armed {len(rules) - failed}/{len(rules)} cohort rules ({reused} reused), "
          f"cohort baseline {COHORT_BASELINE} ({cohort_baseline_id}), "
          f"trigger baseline {TRIGGER_BASELINE} ({trigger_baseline_id})")
    return 1 if failed else 0


def cmd_teardown_cohort(op):
    # Governance (unhappy-path UP-8): per-item try/except + tally, same pattern cmd_purge's
    # own delete loops already use - a bare call here only caught HTTPError (via delete_rule's
    # own internals) not URLError, so a REST connectivity blip mid-sequence used to abort with
    # no record of what was actually removed; safety on re-run was incidental (404-idempotent
    # deletes), not by design.
    failed = []
    for label, fn in (
        (f"baseline {TRIGGER_BASELINE}", lambda: G.teardown_deployed_baseline(op, TRIGGER_BASELINE)),
        (f"baseline {COHORT_BASELINE}", lambda: G.teardown_deployed_baseline(op, COHORT_BASELINE)),
    ):
        try:
            fn()
        except Exception as e:  # noqa: BLE001
            print(f"[teardown] {label} delete FAILED: {e}", file=sys.stderr)
            failed.append(label)
    for r in cohort_rules():
        try:
            if not G.delete_rule(op, r["rule_id"]):
                failed.append(r["rule_id"])
        except Exception as e:  # noqa: BLE001
            print(f"[teardown] rule {r['rule_id']} delete FAILED: {e}", file=sys.stderr)
            failed.append(r["rule_id"])
    try:
        if not G.delete_rule(op, TRIGGER_RULE_ID):
            failed.append(TRIGGER_RULE_ID)
    except Exception as e:  # noqa: BLE001
        print(f"[teardown] trigger rule delete FAILED: {e}", file=sys.stderr)
        failed.append(TRIGGER_RULE_ID)
    # R5.7: sweep EVERY blackout-hbr-* rule by catalogue query, not a fixed id range -
    # run_id-scoped ids from possibly several invocations (including void attempts) can
    # otherwise be left behind (the exact class of leftover the existing run doc's
    # "hbr-01..03 -> hbr-04..06" teardown miss already documented).
    # Governance Gate 8 (quality-engineer, second pass, ported from v1's own #3990 driver
    # fix round): guard this scan itself - an unguarded call here would abort AFTER
    # baselines/cohort-rules/trigger-rule are already deleted but skip the failed-tally
    # print and the SSH scratch cleanup below, self-inconsistent with the per-rule guards
    # just above.
    try:
        rules = get_json(op, "/api/v1/guaranteed-state/rules?limit=1000")["data"]
        hbr_ids = sorted(r["rule_id"] for r in rules if r["rule_id"].startswith(f"{COHORT_PREFIX}hbr-"))
    except Exception as e:  # noqa: BLE001
        print(f"[teardown] hbr rule scan FAILED, skipping hbr cleanup this run: {e}",
              file=sys.stderr)
        hbr_ids = []
        failed.append("hbr-scan")
    for rid in hbr_ids:
        try:
            if not G.delete_rule(op, rid):
                failed.append(rid)
        except Exception as e:  # noqa: BLE001
            print(f"[teardown] hbr rule {rid} delete FAILED: {e}", file=sys.stderr)
            failed.append(rid)
    if hbr_ids:
        print(f"[teardown] deleted {len(hbr_ids)} blackout-hbr-* rule(s): {', '.join(hbr_ids)}")
    if failed:
        print(f"[teardown] {len(failed)} item(s) failed to delete, safe to re-run: "
              f"{', '.join(failed)}", file=sys.stderr)
    try:
        ssh_ps(
            f"Remove-Item -Recurse -Force -Path '{SCRATCH_DIR_WIN}' -ErrorAction SilentlyContinue; "
            f"Remove-Item -Recurse -Force -Path 'HKCU:\\SOFTWARE\\YuzuBlackout' -ErrorAction SilentlyContinue; "
            f"Write-Output done",
            timeout=30,
        )
    except Exception as e:  # noqa: BLE001
        print(f"[teardown] filesystem/registry cleanup failed (non-fatal): {e}", file=sys.stderr)
    print("[teardown] cohort/trigger baselines, rules, scratch files/registry removed")
    return 0


def hbr_rule(run_id, n):
    """R5.7 fix: rule_id (and watched path) are now run_id-scoped
    (`blackout-hbr-<run_id>-NN`), closing a real trigger-ID-reuse trap the
    existing run doc already documented (hbr_counter resets to 1 every
    cmd_run invocation, so two invocations used to collide on the same
    rule_id and a 409 silently meant "no new rule created")."""
    rid = f"{COHORT_PREFIX}hbr-{run_id}-{n:02d}"
    path = f"{SCRATCH_DIR_WIN}\\hbr-{run_id}-{n:02d}.txt"
    return {
        "rule_id": rid, "name": rid, "enabled": True, "enforcement_mode": "audit",
        "severity": "low", "os_target": "windows", "scope": "",
        "spark": {"type": "file-change", "params": {"path": path}},
        "assertion": {"type": "file-exists", "params": {"path": path, "expected": "present"}},
        "remediation": {"type": "alert-only", "params": {}},
    }


# --------------------------------------------------------------------------
# measurement - pure functions (no SSH/HTTP; directly selftest-able)
# --------------------------------------------------------------------------


def _fetch_window(window_start_ts):
    """Fetch the current fixed tail, parse it, and return only lines whose OWN
    embedded timestamp is >= window_start_ts, sorted by that timestamp. Also
    returns the current file size, for the caller's rotation check."""
    size = agent_log_size()
    raw_lines = agent_log_tail()
    parsed = []
    for raw in raw_lines:
        p = parse_log_line(raw)
        if p and p["ts"] >= window_start_ts:
            parsed.append(p)
    parsed.sort(key=lambda p: p["ts"])
    return parsed, size


def _find_first(events, regex, at_or_after=None, strictly_after=None):
    # #4665: anchored (`.match()`, not `.search()`) for the identical reason the direct
    # T0_RE/T0D_RE/T1_RE call sites are anchored below - this helper is the indirect path
    # those three regexes (plus PUSH_CMD_RE, whose own literal prefix also sits at msg's
    # start) reach _fetch_window()'s events through, and an unanchored search here would
    # leave every live-measurement caller (observe_t0/observe_t0d/observe_t1) exploitable
    # even after the direct sites were fixed.
    for p in events:
        if at_or_after is not None and p["ts"] < at_or_after:
            continue
        if strictly_after is not None and p["ts"] <= strictly_after:
            continue
        m = regex.match(p["msg"])
        if m:
            return p, m
    return None, None


def find_own_push_cmd_raw(events, t0_ts):
    """The trigger's own `Received command: ... push_rules` line, identified
    as the LAST such line at/before T0 - excluded from repush_confound
    accounting by RAW LINE CONTENT (not timestamp value), so a genuinely
    distinct second push command landing at the identical millisecond (F9)
    is still counted."""
    candidates = [p for p in events if p["ts"] <= t0_ts and PUSH_CMD_RE.match(p["msg"])]
    return candidates[-1]["raw"] if candidates else None


def classify_t2(events, epoch, floor, expected_rule_ids, own_push_raw, backend, t0_ts, t0d_ts):
    """Pure classification over an already-fetched event list (any order -
    does not assume sorted input). Membership is decided by EPOCH IDENTITY
    for spark (never by timestamp order - the R5.7 round-2 fence, closing
    the stale-prior-application gap Astra's adversarial review found in
    round 1's timestamp-only design) and by the T0d BOUNDARY for legacy
    (which has no epoch field of its own).

    Returns: selected{rid: {...}}, rejected[{line,reason}], adopt_lines[...],
    push_lines[event,...] (excluding the trigger's own line), missing[rid,...],
    legacy_before_t0d[raw,...], next_t0d_ts (the next application's T0d
    timestamp if one appears, else None - `double_full_sync` by EVENT, never
    by a bare timestamp comparison)."""
    remaining = set(expected_rule_ids)
    selected, rejected, adopt_lines, push_lines, legacy_before_t0d = {}, [], [], [], []
    next_t0d_ts = None
    own_excluded = False
    for p in sorted(events, key=lambda p: p["ts"]):
        if p["ts"] < t0_ts:
            continue
        m0d = T0D_RE.match(p["msg"])
        if m0d:
            epoch2 = int(m0d.group(1))
            if epoch2 != epoch and p["ts"] > t0d_ts:
                if next_t0d_ts is None or p["ts"] < next_t0d_ts:
                    next_t0d_ts = p["ts"]
                continue
        if next_t0d_ts is not None and p["ts"] >= next_t0d_ts:
            continue
        mpush = PUSH_CMD_RE.match(p["msg"])
        if mpush:
            if not own_excluded and own_push_raw is not None and p["raw"] == own_push_raw:
                own_excluded = True
                continue
            push_lines.append(p)
            continue
        if backend == "spark":
            m2 = T2_RE.match(p["msg"])
            if not m2:
                continue
            rid, epoch_s, inc_s, typ, via, ms_s = m2.groups()
            epoch_v, inc_v, ms_v = int(epoch_s), int(inc_s), int(ms_s)
            if epoch_v != epoch:
                rejected.append({"line": p["raw"], "reason": "wrong_epoch"})
                continue
            if rid not in expected_rule_ids:
                rejected.append({"line": p["raw"], "reason": "unexpected_rule"})
                continue
            if via == "callback-adopt":
                adopt_lines.append({"rule_id": rid, "ts": p["ts"], "incarnation": inc_v,
                                     "type": typ, "attach_to_commit_ms": ms_v})
            if inc_v <= floor and via != "callback-adopt":
                rejected.append({"line": p["raw"], "reason": "fence_violation_below_floor"})
                continue
            if rid in selected:
                rejected.append({"line": p["raw"], "reason": "duplicate_rule"})
                continue
            selected[rid] = {"ts": p["ts"], "incarnation": inc_v, "type": typ, "via": via,
                              "attach_to_commit_ms": ms_v,
                              "reobserved_adopt": inc_v <= floor and via == "callback-adopt"}
            remaining.discard(rid)
        else:
            mL = ARM_LEGACY_RE.match(p["msg"])
            if not mL:
                continue
            rid = mL.group(1)
            if p["ts"] < t0d_ts:
                legacy_before_t0d.append(p["raw"])
                continue
            if rid not in expected_rule_ids or rid in selected:
                continue
            selected[rid] = {"ts": p["ts"]}
            remaining.discard(rid)
    return {
        "selected": selected, "rejected": rejected, "adopt_lines": adopt_lines,
        "push_lines": push_lines, "legacy_before_t0d": legacy_before_t0d,
        "missing": sorted(remaining), "next_t0d_ts": next_t0d_ts,
    }


def check_teardown_size(t0d, backend, expected_n):
    expected_detached = expected_n if backend == "spark" else 0
    return "teardown_size_mismatch" if t0d["detached_rules"] != expected_detached else None


def sweep_row_pure(events, epoch, floor, missing_rule_ids, backend, t0_ts, t0d_ts, own_push_raw):
    """Post-invocation sweep core: a second, patient look at a fuller log
    span for rule_ids a repeat's own bounded T2 collection never found.

    R5.7 adversarial-review fix (both reviewers independently probed this,
    two directions): the original hand-rolled scan diverged from
    classify_t2's membership predicate in both directions - no
    next-application upper bound on the legacy branch (so a LATER
    application's arm for the same fixed cohort rule_id could be attributed
    to this, earlier, repeat), and no floor/adopt handling on the spark
    branch (so it accepted a below-floor non-adopt line classify_t2 would
    reject as fence_violation_below_floor, and rejected a legal below-floor
    callback-adopt line classify_t2 accepts). Reusing classify_t2 itself,
    scoped to just the missing rule_ids, makes the sweep's membership rule
    identical to the primary classifier's by construction - not merely
    documented as identical, which is what the docstring claimed before this
    fix and was not true.

    Also returns whether the fuller scan turned up a genuine fence violation
    for one of the missing rule_ids (R5.7 adversarial-review-class fix, UP-2,
    /governance unhappy-path): the caller must treat that as taking
    precedence over BOTH "found on the second look" and "still missing" -
    same fence-violation-first precedence as resolve_collect_t2_reason() -
    or a genuine epoch-fence correctness defect gets silently declared
    instrument-invalid (t2_late) just because a DIFFERENT valid line for the
    same rule_id also happened to show up in the fuller window.

    Returns (found{rid:{...}}, still_missing[rid,...], fence_violated: bool)."""
    result = classify_t2(events, epoch, floor, missing_rule_ids, own_push_raw, backend, t0_ts, t0d_ts)
    fence_violated = bool(result["legacy_before_t0d"]) or any(
        r["reason"] == "fence_violation_below_floor" for r in result["rejected"])
    return result["selected"], result["missing"], fence_violated


def compute_window_math(t0_ts, t0d_ts, t1_ts, selected):
    """C/B window arithmetic from an already-classified `selected` dict.
    Pure - directly selftest-able (F6)."""
    items = sorted(selected.items(), key=lambda kv: kv[1]["ts"])
    ts_list = [v["ts"] for _, v in items]
    t2_first, t2_last = ts_list[0], ts_list[-1]
    c_ms = (t2_last - t0_ts).total_seconds() * 1000
    c_first_ms = (t2_first - t0_ts).total_seconds() * 1000
    c_from_t0d_ms = (t2_last - t0d_ts).total_seconds() * 1000
    t2_spread_ms = (t2_last - t2_first).total_seconds() * 1000
    t1_to_t2_last_ms = (t2_last - t1_ts).total_seconds() * 1000
    n_before = sum(1 for ts in ts_list if ts < t1_ts)
    n_tie = sum(1 for ts in ts_list if ts == t1_ts)
    n_after = sum(1 for ts in ts_list if ts > t1_ts)
    n_adopt = sum(1 for _, v in items if v.get("via") == "callback-adopt")
    n_shared = sum(1 for _, v in items if v.get("via") in ("inline-shared", "callback-shared"))
    attach_vals = [v["attach_to_commit_ms"] for _, v in items if "attach_to_commit_ms" in v]
    by_type = {}
    for _, v in items:
        if "type" in v:
            by_type.setdefault(v["type"], []).append((v["ts"] - t0_ts).total_seconds() * 1000)
    return {
        "c_ms": c_ms, "c_first_ms": c_first_ms, "c_from_t0d_ms": c_from_t0d_ms,
        "t2_spread_ms": t2_spread_ms, "t1_to_t2_last_ms": t1_to_t2_last_ms,
        "n_t2": len(items), "n_t2_before_t1": n_before, "n_t2_tie_t1": n_tie,
        "n_t2_after_t1": n_after, "n_adopt": n_adopt, "n_shared": n_shared,
        "attach_to_commit_ms_max": max(attach_vals) if attach_vals else None,
        "t2_by_type_max_ms": {k: max(vs) for k, vs in by_type.items()},
    }


def _instrument_void_ceiling_breached(rows):
    """R5.7 adversarial-review fix (both reviewers independently probed this
    live: 3 valid + 4 instrument-invalid rows returned PASS): compute_verdict
    previously had no code path implementing the pre-registered rule
    (3990-fullsync-blackout-run.md §"Verdict per phase" item 2) that a cell
    whose instrument-invalid voids exceed 50% of its own attempts is
    INCONCLUSIVE, never PASS, regardless of whether the valid count also
    happens to reach the floor. Empty cell -> no ceiling to breach."""
    if not rows:
        return False
    instrument = sum(1 for r in rows if r.get("void_class") == "instrument")
    return instrument * 2 > len(rows)


def compute_verdict(legacy_rows, spark_rows, floor):
    """§7 two-gate verdict: reliability (ALL attempts, both cells) then
    latency (counted repeats only), margin = max(1000ms, legacy median).

    /governance happy-path finding: fullsync-blackout-results.jsonl is a
    single accumulated file spanning multiple, incompatible historical
    schemas (label="clean"/"clean-v2" rows from an earlier diagnostic round
    predate the c_ms/C-measurand convention entirely and have no "c_ms" key
    at all) - a bare r["c_ms"] below would KeyError on such a row if it were
    ever counted "valid". Requiring "c_ms" in r here means a schema-
    incompatible row simply never counts as measurable under THIS verdict
    definition (worst case that cell reads INCONCLUSIVE - floor not reached
    - rather than crashing cmd_report); every real label="t2-v1" row already
    carries c_ms whenever it is not void, so this changes nothing for the
    data this fix round is actually about."""
    legacy_valid = [r for r in legacy_rows if not r.get("void_reason") and "c_ms" in r]
    spark_valid = [r for r in spark_rows if not r.get("void_reason") and "c_ms" in r]
    genuine = any(r.get("void_class") == "genuine" for r in legacy_rows + spark_rows)
    if genuine:
        return "FAIL-RELIABILITY"
    if _instrument_void_ceiling_breached(legacy_rows) or _instrument_void_ceiling_breached(spark_rows):
        return "INCONCLUSIVE"
    if len(legacy_valid) < floor or len(spark_valid) < floor:
        return "INCONCLUSIVE"
    legacy_c = statistics.median(r["c_ms"] for r in legacy_valid)
    spark_c = statistics.median(r["c_ms"] for r in spark_valid)
    margin = max(1000.0, legacy_c)
    return "PASS" if spark_c <= legacy_c + margin else "FAIL-LATENCY"


# --------------------------------------------------------------------------
# measurement - live (SSH-polling) stage wrappers around the pure functions
# --------------------------------------------------------------------------


def observe_t0(window_start_ts, allow_fallback_t0, t0_timeout_s, poll=2.0):
    size0 = agent_log_size()
    deadline = time.time() + t0_timeout_s
    while time.time() < deadline:
        events, size = _fetch_window(window_start_ts)
        if size < size0:
            return None, None, "log_rotated_mid_window", False
        tail_saturated = bool(events) and events[0]["ts"] > window_start_ts
        p, m = _find_first(events, T0_RE, at_or_after=window_start_ts)
        if p:
            return p, "cleared", None, tail_saturated
        if allow_fallback_t0:
            p, m = _find_first(events, PUSH_CMD_RE, at_or_after=window_start_ts)
            if p:
                return p, "fallback", None, tail_saturated
        time.sleep(poll)
    return None, None, "t0_not_found", False


def observe_t0d(window_start_ts, t0_ts, t0d_timeout_s, poll=2.0):
    size0 = agent_log_size()
    deadline = time.time() + t0d_timeout_s
    while time.time() < deadline:
        events, size = _fetch_window(window_start_ts)
        if size < size0:
            return None, "log_rotated_mid_window"
        p, m = _find_first(events, T0D_RE, at_or_after=t0_ts)
        if p:
            epoch, floor, detached, withdrawn = (int(x) for x in m.groups())
            return {"ts": p["ts"], "epoch": epoch, "floor": floor,
                    "detached_rules": detached, "withdrawn_claims": withdrawn}, None
        time.sleep(poll)
    return None, "t0d_not_found"


def observe_t1(window_start_ts, t0d_ts, t1_timeout_s, poll=2.0):
    size0 = agent_log_size()
    deadline = time.time() + t1_timeout_s
    while time.time() < deadline:
        events, size = _fetch_window(window_start_ts)
        if size < size0:
            return None, "log_rotated_mid_window"
        p, m = _find_first(events, T1_RE, at_or_after=t0d_ts)
        if p:
            return {"ts": p["ts"], "groups": m.groups()}, None
        time.sleep(poll)
    return None, "t1_not_found"


def resolve_collect_t2_reason(result):
    """Pure: given one classify_t2() result, decide collect_t2's void reason
    with FENCE-VIOLATION-FIRST precedence. R5.7 adversarial-review-class fix
    (found during /governance's unhappy-path review, UP-1): the original
    collect_t2() checked `next_t0d_ts` (-> "double_full_sync") INSIDE the
    polling loop and returned immediately, so a genuine fence violation
    (`legacy_before_t0d`, or a rejected `fence_violation_below_floor` line)
    already sitting in `result["rejected"]` at that exact moment was never
    consulted - the same laundering shape resolve_post_t2_void() fixes for
    failed_gt_0 vs a collection-stage reason, one level further in. Did not
    manifest in this branch's own committed data (verified: none of the
    double_full_sync rows carry a fence_violation_below_floor rejection) but
    is a real, reachable bug in the classifier this tool is documented as
    reusable for."""
    if result["legacy_before_t0d"] or any(
            r["reason"] == "fence_violation_below_floor" for r in result["rejected"]):
        return "fence_violation"
    if result["next_t0d_ts"] is not None:
        return "double_full_sync"
    if result["missing"]:
        return "t2_incomplete"
    if result["push_lines"]:
        return "repush_confound"
    return None


def collect_t2(t0_ts, t0d, window_start_ts, own_push_raw, expected_rule_ids, backend,
               visibility_timeout_s=ROOT_CAUSED_T2_VISIBILITY_TIMEOUT, poll=2.0):
    """Live S4: poll until classify_t2() reports nothing missing, a next-
    application T0d appears, or the visibility deadline expires. Returns
    (classify_t2 result dict, void_reason or None, last fetched events -
    the latter reused by the caller for the n_arm_lines continuity field).
    t2_incomplete/repush_confound are decided only after the polling deadline
    is exhausted (see resolve_collect_t2_reason() for the reason precedence
    itself, checked every iteration so fence_violation/double_full_sync can
    never be masked by continuing to poll).

    Accepted residual limitation (/governance quality-engineer, Gate 8 round
    2, same class already accepted for run_repeat()'s own call to
    resolve_post_t2_void()): this function does live SSH/network I/O
    (_fetch_window, time.sleep) and has no offline selftest coverage, so a
    future edit that reorders THIS loop's own two-line early-return check
    relative to resolve_collect_t2_reason() would go undetected by selftest
    even though resolve_collect_t2_reason() itself is directly, thoroughly
    fixture-tested (F18). Kept minimal deliberately (one function call, one
    membership check) specifically to keep that residual risk as small as
    it can be made without a live-rig integration test."""
    deadline = time.time() + visibility_timeout_s
    result, last_events = None, []
    while time.time() < deadline:
        events, size = _fetch_window(window_start_ts)
        last_events = events
        result = classify_t2(events, t0d["epoch"], t0d["floor"], expected_rule_ids,
                              own_push_raw, backend, t0_ts, t0d["ts"])
        early_reason = resolve_collect_t2_reason(result)
        if early_reason in ("fence_violation", "double_full_sync"):
            return result, early_reason, last_events
        if not result["missing"]:
            break
        time.sleep(poll)
    if result is None:
        result = classify_t2([], t0d["epoch"], t0d["floor"], expected_rule_ids,
                              own_push_raw, backend, t0_ts, t0d["ts"])
    return result, resolve_collect_t2_reason(result), last_events


def resolve_sweep_reclassification(fence_violated, still_missing):
    """Pure: given sweep_row_pure()'s three-way result for one previously-
    t2_incomplete row, decide its reclassification. Fence-violation-first,
    same precedence family as resolve_collect_t2_reason()/
    resolve_post_t2_void() (/governance quality-engineer, Gate 8 round 2:
    the branch ORDER itself - not just sweep_row_pure()'s fence_violated
    computation - is what UP-2's fix actually depends on, and nothing
    exercised that order directly until this extraction; sweep_incomplete()
    is a live-I/O wrapper like run_repeat()/collect_t2(), so this mirrors
    the same "extract the decision into a pure function" fix already applied
    to both). Returns (void_class, void_reason)."""
    if fence_violated:
        return "genuine", "fence_violation"
    if not still_missing:
        return "instrument", "t2_late"
    return "genuine", "arm_never_confirmed"


def sweep_incomplete(rows, window_start_ts):
    """R5.7 §2.2 item 8: one final, patient read of the whole log span at the
    end of a cmd_run() invocation, reclassifying every t2_incomplete row per
    resolve_sweep_reclassification()."""
    incomplete = [r for r in rows if r.get("void_reason") == "t2_incomplete"]
    if not incomplete:
        return rows
    # Governance (this round, b-lite): worst-positioned unguarded SSH call in this file -
    # this fetch runs ONCE, after every attempt in the cell has already completed. On
    # failure, skip the reclassification pass entirely rather than crash: every
    # t2_incomplete row simply stays t2_incomplete (already instrument-invalid, never
    # counted toward PASS, can only push a cell toward INCONCLUSIVE via the existing
    # >50%-void ceiling) - the same honest outcome as if the run had been killed here.
    try:
        events, _ = _fetch_window(window_start_ts)
    except Exception as e:  # noqa: BLE001
        print(f"[sweep] log fetch failed, skipping reclassification for {len(incomplete)} "
              f"t2_incomplete row(s): {type(e).__name__}:{str(e)[:200]}", file=sys.stderr)
        return rows
    # Governance (this round, unhappy-path UP-2/UP-3): unlike observe_t0(), this was the
    # only _fetch_window() caller with no saturation check at all - a many-repeat or
    # noisy run can roll TAIL_LINES past an EARLY attempt's own T0d/T2 lines by the time
    # this single post-loop sweep runs, well before a LATER attempt's own lines are at
    # any risk. The check is therefore PER-ROW, against THAT row's own t0d_ts, not one
    # blanket check against the whole sweep's window_start_ts - a blanket check would
    # misfire on every row whose own events legitimately start some time after
    # window_start_ts, which in a multi-repeat run is nearly every later repeat, even
    # when nothing was actually truncated (window_start_ts is captured once, before the
    # very first repeat). A truncated re-scan can fabricate a false GENUINE
    # arm_never_confirmed from an instrument gap (no void-ceiling escape applies to a
    # genuine classification, unlike an instrument one) - a row this affects skips
    # reclassification, not the whole sweep.
    earliest_fetched_ts = events[0]["ts"] if events else None
    for r in incomplete:
        t0_ts = datetime.fromisoformat(r["t0"])
        t0d_ts = datetime.fromisoformat(r["t0d"]["ts"])
        if earliest_fetched_ts is not None and earliest_fetched_ts > t0d_ts:
            print(f"[sweep] fetched tail's earliest event ({earliest_fetched_ts.isoformat()}) "
                  f"is already after this row's own T0d ({t0d_ts.isoformat()}) - the window "
                  f"between them was truncated. Skipping reclassification for this row rather "
                  f"than reclassify from data known incomplete.", file=sys.stderr)
            continue
        own_push_raw = find_own_push_cmd_raw(events, t0_ts)
        found, still_missing, fence_violated = sweep_row_pure(
            events, r["t0d"]["epoch"], r["t0d"]["floor"], set(r["missing_rule_ids"]),
            r["backend"], t0_ts, t0d_ts, own_push_raw)
        # Governance (this round, quality-engineer + consistency-auditor, independently):
        # resolve_sweep_reclassification() already returns the authoritative
        # (void_class, void_reason) tuple - a prior version of this loop re-dispatched on
        # the resulting string with only "t2_late"/"arm_never_confirmed" named branches
        # and a catch-all `else` that unconditionally overwrote ANY other outcome -
        # including "fence_violation" - back to ("genuine", "arm_never_confirmed"),
        # silently discarding the exact cross-application fence-violation signal this
        # whole epoch-fence redesign exists to catch. Assign once, from the function's
        # own return; never re-derive or overwrite it from the resulting string.
        r["void_class"], r["void_reason"] = resolve_sweep_reclassification(
            fence_violated, still_missing)
        r["missing_rule_ids"] = still_missing
        if r["void_reason"] == "t2_late":
            for rid, v in found.items():
                r["t2_selected"][rid] = {**v, "ts": v["ts"].isoformat()}
            r["missing_rule_ids"] = []
    return rows


def replace_run_rows(lines, run_id, swept_rows):
    """Pure: rewrites a results-file's lines (each a raw string WITH its
    trailing newline, as returned by readlines()) so every row belonging to
    `run_id` is replaced by its corresponding entry in `swept_rows` (matched
    by `repeat`, each row's per-attempt index within a run - unique within
    one run_id, stable across the write-through/sweep boundary), and every
    OTHER line - a different run's already-committed evidence, possibly
    from a prior invocation entirely - passes through completely unchanged,
    as the original raw string, never a json.loads()/dumps() round-trip
    (which can reorder keys or reformat a float and produce a spurious diff
    in committed evidence this function has no business touching). A line
    that fails to parse as JSON, or has no matching `repeat` in this run,
    also passes through unchanged.

    Exists because cmd_run() writes each row through to disk as soon as
    it's produced (governance, R5.7 driver-merge follow-on round: a mid-run
    SSH/rig hiccup must not discard an already-completed repeat), but
    sweep_incomplete() can only correctly reclassify t2_incomplete rows
    once every attempt in the cell is in hand - so the file's pre-sweep
    (conservative) rows for THIS run need a targeted, in-place correction
    afterward, not a full-file rewrite. `swept_rows` are dicts built as
    `{**r, "label": label}` from the SAME row objects the write-through
    pass already dumped, so a row sweep_incomplete() left untouched
    re-serializes byte-identical to what's already on disk (sweep only
    reassigns existing keys' values, never adds a new top-level key, so key
    insertion order - and therefore json.dumps output - is unaffected) -
    replacing every row of this run unconditionally is therefore safe and
    correct even when zero rows actually changed, not just when some did.

    Returns the new full line list; the caller does the actual atomic file
    swap (temp file + os.replace(), so a kill mid-rewrite can't corrupt
    already-committed evidence from other runs sharing this file)."""
    by_repeat = {r["repeat"]: json.dumps(r) + "\n" for r in swept_rows}
    out = []
    for line in lines:
        try:
            parsed = json.loads(line)
        except (json.JSONDecodeError, ValueError):
            out.append(line)
            continue
        # Governance (this round, security-guardian): a line that parses as valid JSON
        # but isn't an object (e.g. a bare `123`/`[]`/`null`) previously raised
        # AttributeError on `.get(...)`, uncaught - contradicting this function's own
        # docstring claim that such a line "passes through unchanged". Guard explicitly.
        if (isinstance(parsed, dict) and parsed.get("run_id") == run_id
                and parsed.get("repeat") in by_repeat):
            out.append(by_repeat[parsed["repeat"]])
        else:
            out.append(line)
    return out


def _foreign_fingerprint(lines, run_id):
    """Count + content hash of every line NOT belonging to `run_id`, order-preserved -
    used by cmd_run() to detect a concurrent writer between its initial read and its
    atomic swap (governance, this round, unhappy-path UP-1). A bare line count (the
    prior check) cannot catch a same-length concurrent write - e.g. two invocations
    racing with an equal number of counted repeats - since it only notices the file
    getting longer or shorter, never merely DIFFERENT. Hashing only the foreign lines
    (never our own run's rows, which this process is legitimately about to rewrite)
    means the check fires on any change to evidence this process has no business
    touching, without false-positiving on this process's own in-place correction.
    A non-dict-JSON or unparseable line counts as foreign, matching
    replace_run_rows()'s own pass-through rule."""
    foreign = []
    for line in lines:
        try:
            parsed = json.loads(line)
        except (json.JSONDecodeError, ValueError):
            foreign.append(line)
            continue
        if not (isinstance(parsed, dict) and parsed.get("run_id") == run_id):
            foreign.append(line)
    digest = hashlib.sha256("".join(foreign).encode()).hexdigest()
    return len(foreign), digest


def resolve_cohort_void(d_by_rule, never_fetched):
    """Row-level void classification for a cohort whose functional-validity poll
    (`cohort_events_d()`) left at least one rule "not_observed". Genuine ALWAYS
    wins, unconditionally (governance Gate-4 unhappy-path, PR #4614 review round)
    - the same asymmetric-cost doctrine `void_class_for()`'s own docstring states
    and `resolve_post_t2_void()` already applies elsewhere in this file: a false
    instrument silently discards real evidence, a false genuine costs one
    unnecessary look. A single never-fetched rule out of a whole cohort must NOT
    void every OTHER rule's reliable, genuinely-never-restored evidence - only
    when EVERY still-not-observed rule's last look was fetch-tainted is there
    zero reliable genuine signal at all."""
    reliably_not_observed = {rid for rid, v in d_by_rule.items() if v == "not_observed"} \
        - never_fetched
    if reliably_not_observed:
        return "genuine", "functional_invalid"
    return "instrument", "cohort_fetch_unreliable_at_end:" + ",".join(sorted(never_fetched))


def cohort_events_d(op, rule_ids, t0_dt, deadline_ms, poll=5.0):
    """Bounded functional-validity polling (R5.7 §2.2 item 6, replacing the
    prior one-shot lookup): poll every `poll` seconds until every rule has a
    `guard.compliant` event whose embedded ms falls in [t0_ms, t0_ms +
    deadline_ms], or until that event-time deadline plus a 60s ingestion
    grace has elapsed on the driver clock. t0_dt is log-native
    (local-labeled-as-UTC); event_id's embedded ms is real UTC - the offset
    is subtracted back out before comparing, same correction as before.

    Returns (by_rule, never_fetched): a rule left "not_observed" whose MOST
    RECENT poll attempt raised (never_fetched) is an instrument failure (our
    last look at it, right before giving up, was unreliable), not a genuine
    "the guard never fired" - the caller must not fold the two together
    (Doomgoose review, PR #4614: a bare `except Exception:
    continue` here used to launder a REST-fetch failure for the whole
    polling window into the same "not_observed" state a genuinely-never-
    fired guard produces). Deliberately LATEST-attempt, not EVER-succeeded:
    `deadline_ms` is sized (`max(2 * c_ms, 30000)`, the caller's own
    comment) so the FIRST sweep is expected to find nothing for nearly
    every rule - an ever-succeeded flag would credit that always-empty
    first sweep and stay permanently true even if every later attempt (the
    ones actually covering the window the real event would land in) then
    failed for the rest of the grace period, silently reproducing the same
    laundering this fix exists to close via a different mechanism
    (unhappy-path Gate-4 finding, this same review round)."""
    t0_ms = int(t0_dt.timestamp() * 1000) - int(dgrhp_utc_offset().total_seconds() * 1000)
    grace_deadline = time.time() + (deadline_ms / 1000.0) + 60.0
    by_rule = {rid: "not_observed" for rid in rule_ids}
    last_fetch_ok = {rid: False for rid in rule_ids}
    while time.time() < grace_deadline:
        pending = [rid for rid, v in by_rule.items() if v == "not_observed"]
        if not pending:
            break
        for rid in pending:
            try:
                data = get_json(op, f"/api/v1/guaranteed-state/events?rule_id={rid}&limit=100")["data"]
            except Exception as e:  # noqa: BLE001
                print(f"[cohort_events_d] fetch failed for rule '{rid}': "
                      f"{type(e).__name__}: {e}", file=sys.stderr)
                last_fetch_ok[rid] = False
                continue
            last_fetch_ok[rid] = True
            found = None
            for ev in data:
                if ev.get("event_type") != "guard.compliant":
                    continue
                m = re.search(r"-(\d{13})-\d+$", ev.get("event_id", ""))
                if not m:
                    continue
                ms = int(m.group(1))
                if t0_ms <= ms <= t0_ms + deadline_ms:
                    if found is None or ms < found:
                        found = ms
            if found is not None:
                by_rule[rid] = found - t0_ms
        if any(v == "not_observed" for v in by_rule.values()):
            time.sleep(poll)
    never_fetched = {rid for rid in rule_ids
                     if by_rule[rid] == "not_observed" and not last_fetch_ok[rid]}
    return by_rule, never_fetched


# --------------------------------------------------------------------------
# measurement - per-repeat orchestration
# --------------------------------------------------------------------------


def run_repeat(op, phase, backend, trigger_kind, cohort_ids, exp_rule_ids, repeat_idx,
                trigger_id_cache, run_id, comparison_id):
    """One trigger-and-observe cycle. Always returns a row dict, built up
    incrementally from S0 onward, with as much evidence populated as was
    actually observed before any void - R5.7 §2.2 item 7 (evidence retained
    on every row, void or not)."""
    row = {
        "phase": phase, "backend": backend, "repeat": repeat_idx,
        "run_id": run_id, "comparison_id": comparison_id,
        "void_class": None, "void_reason": None,
    }
    # Governance (unhappy-path UP-3, chaos CH-2, ported from v1's own #3990 driver fix
    # round): guarded like the trigger call just below - an unguarded REST blip here used
    # to crash the whole cmd_run loop instead of voiding one attempt, asymmetric with every
    # other REST call in this function.
    try:
        m0 = get_metrics(op)
    except Exception as e:  # noqa: BLE001
        row.update(void_class="instrument",
                   void_reason=f"metrics_unavailable:{type(e).__name__}:{str(e)[:200]}")
        return row
    # Governance Gate 8 (unhappy-path, second pass, ported): dgrhp_now() is its own unguarded
    # ssh_ps() round trip, and the single most frequent SSH call site in this function (once
    # per attempt) - a bare call here still crashes the whole cmd_run loop on an SSH blip.
    try:
        window_start_ts = dgrhp_now()  # NOT datetime.now(timezone.utc) - see dgrhp_utc_offset()
    except Exception as e:  # noqa: BLE001
        row.update(void_class="instrument",
                    void_reason=f"dgrhp_clock_unavailable:{type(e).__name__}:{str(e)[:200]}")
        return row
    http_status = None
    if trigger_kind == "deploy":
        try:
            G.deploy_baseline_form(op, trigger_id_cache["trigger_baseline_id"])
            http_status = 200
        except Exception as e:  # noqa: BLE001
            row.update(trigger_http_status=None, void_class="instrument",
                       void_reason=f"trigger_failed:{type(e).__name__}:{str(e)[:200]}")
            return row
    else:
        n = trigger_id_cache["hbr_counter"]
        trigger_id_cache["hbr_counter"] += 1
        rule = hbr_rule(run_id, n)
        try:
            _touch_win_file(rule["spark"]["params"]["path"])
            _, existed = G.post_rule(op, rule)
        except Exception as e:  # noqa: BLE001
            row.update(trigger_http_status=None, void_class="instrument",
                       void_reason=f"trigger_failed:{type(e).__name__}:{str(e)[:200]}")
            return row
        http_status = 409 if existed else 201
        if existed:
            row.update(trigger_http_status=http_status, void_class="instrument",
                       void_reason="trigger_not_created")
            return row
    row["trigger_http_status"] = http_status

    allow_fallback_t0 = False  # R5.7: B/B2 never accept the fallback T0 (round-2 correction)
    # Governance (unhappy-path UP-2, ported): observe_t0 polls over SSH for up to
    # ROOT_CAUSED_T0_TIMEOUT seconds; an uncaught subprocess.TimeoutExpired or SSH
    # control-socket failure from ssh_ps() (via _fetch_window/agent_log_size) used to
    # propagate all the way out and crash the whole cmd_run loop instead of voiding this
    # one attempt the way trigger_failed/metrics_unavailable already do.
    try:
        t0, t0_source, reason, tail_saturated = observe_t0(
            window_start_ts, allow_fallback_t0, ROOT_CAUSED_T0_TIMEOUT)
    except Exception as e:  # noqa: BLE001
        # Governance Gate 8 (quality-engineer, second pass, ported; corrected this round,
        # security-guardian): ssh_ps() itself now sanitizes a raw subprocess.TimeoutExpired
        # before it can escape (its str() embedded the full argv - SSH destination/user/key
        # path - at the message's START, which str(e)[:200]'s END-truncation did NOT
        # remove, contrary to this comment's own earlier claim). Name and truncate here
        # too, defensively, for any other exception type reaching this point.
        row.update(void_class="instrument",
                    void_reason=f"observe_t0_failed:{type(e).__name__}:{str(e)[:200]}")
        return row
    row["tail_saturated"] = tail_saturated
    if reason:
        row.update(void_class=void_class_for(reason), void_reason=reason)
        return row
    row["t0"], row["t0_source"] = t0["ts"].isoformat(), t0_source

    # Governance (unhappy-path UP-2 class, ported/extended): a direct _fetch_window() call,
    # same failure mode as every other SSH-polling call in this function.
    try:
        own_events, _ = _fetch_window(window_start_ts)
    except Exception as e:  # noqa: BLE001
        row.update(void_class="instrument",
                    void_reason=f"own_events_fetch_failed:{type(e).__name__}:{str(e)[:200]}")
        return row
    own_push_raw = find_own_push_cmd_raw(own_events, t0["ts"])

    if backend == "spark":
        # Governance (unhappy-path UP-2, ported): observe_t0d is the same class of
        # SSH-polling call as observe_t0 just above.
        try:
            t0d, reason = observe_t0d(window_start_ts, t0["ts"], ROOT_CAUSED_T0D_TIMEOUT)
        except Exception as e:  # noqa: BLE001
            row.update(void_class="instrument",
                        void_reason=f"observe_t0d_failed:{type(e).__name__}:{str(e)[:200]}")
            return row
        if reason:
            row.update(void_class=void_class_for(reason), void_reason=reason)
            return row
        size_reason = check_teardown_size(t0d, backend, len(exp_rule_ids))
        if size_reason:
            row.update(void_class=void_class_for(size_reason), void_reason=size_reason)
            return row
    else:
        # R5.7 wrinkle, found live on the rig (2026-09-19): GuardianEngine::
        # wire_spark_engine() returns BEFORE constructing spark_runtime_ when
        # spark_disabled_by_config is true (the --spark-disable branch, checked
        # before the "!engine" branch) - so under legacy, spark_runtime_ stays
        # null for the agent's whole lifetime and detach_all()'s `if
        # (spark_runtime_)` guard makes it a permanent no-op: the T0d line NEVER
        # fires for a --spark-disable agent, contradicting this plan's original
        # assumption that detach_all() runs regardless of backend. Legacy never
        # needed the epoch fence in the first place - its arms are SYNCHRONOUS
        # under apply_rules()'s own mtx_, same thread as T0/T1, so there is no
        # stale-prior-application race to guard against. Synthesize t0d = t0
        # (epoch/floor/detached_rules/withdrawn_claims are meaningless for
        # legacy and recorded as 0) so collect_t2's shared membership logic
        # (legacy branch: "after t0d_ts" == "after t0_ts", a no-op restriction)
        # needs no separate code path.
        t0d = {"ts": t0["ts"], "epoch": 0, "floor": 0, "detached_rules": 0, "withdrawn_claims": 0}
    row["t0d"] = {"ts": t0d["ts"].isoformat(), "epoch": t0d["epoch"], "floor": t0d["floor"],
                  "detached_rules": t0d["detached_rules"], "withdrawn_claims": t0d["withdrawn_claims"]}

    # Governance (unhappy-path UP-2, ported): observe_t1 is the same class of SSH-polling
    # call as observe_t0/observe_t0d above.
    try:
        t1, reason = observe_t1(window_start_ts, t0d["ts"], ROOT_CAUSED_T1_TIMEOUT)
    except Exception as e:  # noqa: BLE001
        row.update(void_class="instrument",
                    void_reason=f"observe_t1_failed:{type(e).__name__}:{str(e)[:200]}")
        return row
    if reason:
        row.update(void_class=void_class_for(reason), void_reason=reason)
        return row
    applied, failed, pending, full_sync, generation, total = (
        int(t1["groups"][0]), int(t1["groups"][1]), int(t1["groups"][2]),
        t1["groups"][3], int(t1["groups"][4]), int(t1["groups"][5]),
    )
    row.update(t1=t1["ts"].isoformat(), applied=applied, failed=failed, pending=pending,
               total=total, generation=generation, full_sync=full_sync)
    # Governance (unhappy-path UP-5, ported): full_sync is captured by T1_RE but was never
    # asserted - an apply_rules ok line with full_sync=false still matched and was silently
    # accepted as this measurement's T1. Void on it instead of silently accepting it.
    if full_sync != "true":
        row.update(void_class=void_class_for(f"not_full_sync({full_sync})"),
                    void_reason=f"not_full_sync({full_sync})")
        return row
    b_ms = (t1["ts"] - t0["ts"]).total_seconds() * 1000
    row["b_ms"] = b_ms

    # m1: sampled on DGRHP's own clock (never local time.time() - see dgrhp_now()'s own
    # docstring for the cross-host drift this avoids), immediately after T1 becomes visible.
    # Governance (unhappy-path UP-3, ported and extended to this m1 site to match the
    # guarding already applied to every other SSH/REST call in this function - m0's
    # get_metrics() call above has the identical failure mode): an unguarded blip here
    # would otherwise crash the whole cmd_run loop for the sake of a metrics snapshot.
    try:
        m1_observed_dgrhp = dgrhp_now()
        m1 = get_metrics(op)
    except Exception as e:  # noqa: BLE001
        row.update(void_class="instrument",
                   void_reason=f"m1_unavailable:{type(e).__name__}:{str(e)[:200]}")
        return row
    row["m1_observed_wall"] = m1_observed_dgrhp.isoformat()
    row["m1_lag_ms"] = (m1_observed_dgrhp - t1["ts"]).total_seconds() * 1000

    if total != len(exp_rule_ids):
        row.update(void_class=void_class_for("cohort_composition"), void_reason="cohort_composition")
        return row

    # Governance (this round, b-lite): collect_t2()'s own _fetch_window() polls every 2s
    # for up to ROOT_CAUSED_T2_VISIBILITY_TIMEOUT (240s), doing repeated SSH round trips -
    # the longest single SSH-exposure window per attempt in this file. An unguarded blip
    # anywhere in that span used to crash the whole cmd_run loop instead of voiding just
    # this one attempt, same UP-2 symptom class as every other guard in this function.
    try:
        result, reason, last_events = collect_t2(t0["ts"], t0d, window_start_ts, own_push_raw,
                                                  exp_rule_ids, backend)
    except Exception as e:  # noqa: BLE001
        row.update(void_class="instrument",
                   void_reason=f"t2_collect_failed:{type(e).__name__}:{str(e)[:200]}")
        return row
    row["t2_selected"] = {rid: {**v, "ts": v["ts"].isoformat()} for rid, v in result["selected"].items()}
    row["t2_rejected"] = result["rejected"]
    row["missing_rule_ids"] = result["missing"]
    row["push_cmd_lines_in_window"] = [p["raw"] for p in result["push_lines"]]
    row["legacy_lines_before_t0d"] = result["legacy_before_t0d"]
    row["n_reobserved_adopt"] = sum(1 for v in result["selected"].values() if v.get("reobserved_adopt"))
    row["n_arm_lines"] = (
        sum(1 for p in last_events if p["ts"] >= t0["ts"] and ARM_SPARK_RE.match(p["msg"]))
        if backend == "spark" else len(result["selected"])
    )
    # A collection-stage instrument-invalid `reason` (e.g. double_full_sync,
    # t2_incomplete) must never suppress an ALREADY-known genuine failure -
    # resolve_post_t2_void()'s own docstring has the full rationale, including
    # why the precedence decision itself, not just genuine_t1_failure()'s
    # value, needs to be a separately fixture-testable pure function.
    void_class, void_reason = resolve_post_t2_void(genuine_t1_failure(phase, failed), reason)
    if void_reason:
        row.update(void_class=void_class, void_reason=void_reason)
        return row

    wm = compute_window_math(t0["ts"], t0d["ts"], t1["ts"], result["selected"])
    row.update(wm)

    reconcile_sent_delta = metric_sum(m1, 'yuzu_server_guardian_reconciles_total{result="sent"}') \
        - metric_sum(m0, 'yuzu_server_guardian_reconciles_total{result="sent"}')
    pushes_policy_change_delta = (
        metric_sum(m1, 'yuzu_server_guardian_pushes_dispatched_total{reason="policy_change"}')
        - metric_sum(m0, 'yuzu_server_guardian_pushes_dispatched_total{reason="policy_change"}')
    )
    row["reconcile_sent_delta"] = reconcile_sent_delta
    row["pushes_policy_change_delta"] = pushes_policy_change_delta

    phase_is_clean_verdict = phase in ("B", "B2")
    if phase_is_clean_verdict:
        # failed>0 is handled above for B/B2 (hoisted ahead of collect_t2's reason
        # check via genuine_t1_failure()) - by this point every remaining B/B2 row
        # has failed==0. Phase A rows never go through that check and are not
        # phase_is_clean_verdict, so this guard is what scopes the invariant.
        if applied != total:
            row.update(void_class="instrument", void_reason="applied_ne_total")
            return row
        if phase == "B" and (reconcile_sent_delta != 0 or pushes_policy_change_delta != 1):
            row.update(void_class="instrument",
                       void_reason=f"push_counter_mismatch(reconcile_sent_delta="
                                   f"{reconcile_sent_delta},pushes_delta={pushes_policy_change_delta})")
            return row
        if phase == "B2" and (reconcile_sent_delta != 1 or pushes_policy_change_delta != 0):
            row.update(void_class="instrument",
                       void_reason=f"push_counter_mismatch(reconcile_sent_delta="
                                   f"{reconcile_sent_delta},pushes_delta={pushes_policy_change_delta})")
            return row

    c_ms = row["c_ms"]
    deadline_ms = max(2 * c_ms, 30000)
    # Governance Gate 8 (self-review, third pass, ported - same UP-2 class already applied
    # to observe_t0/observe_t0d/observe_t1 above): cohort_events_d() calls
    # dgrhp_utc_offset() which, on a cache miss (the common case - it's lazily computed once
    # per process, and this is the FIRST call site reached on the B/B2 path), makes its own
    # unguarded ssh_ps() round trip - a failure here used to crash the whole cmd_run loop
    # after T0/T0d/T1 had already been successfully observed, discarding real data. No
    # pre-existing void_reason to preserve at this point in this branch's flow (every earlier
    # void condition above already returns immediately), unlike v1's flatter structure.
    try:
        d_by_rule, cohort_never_fetched = cohort_events_d(op, cohort_ids, t0["ts"], deadline_ms)
    except Exception as e:  # noqa: BLE001
        row.update(void_class="instrument",
                    void_reason=f"cohort_events_failed:{type(e).__name__}:{str(e)[:200]}")
        return row
    functional_valid = all(v != "not_observed" for v in d_by_rule.values())
    row["compliant_restored_ms_by_rule"] = d_by_rule
    row["functional_valid"] = functional_valid
    if phase_is_clean_verdict and not functional_valid:
        void_class, void_reason = resolve_cohort_void(d_by_rule, cohort_never_fetched)
        row.update(void_class=void_class, void_reason=void_reason)
        return row

    row.update(void_class=None, void_reason=None)
    return row


def cmd_run(op, phase, backend, trigger_kind, repeats, gap, label, out_path, comparison_id):
    if phase in ("B", "B2") and not comparison_id:
        print("[run] --comparison is required for phase B/B2", file=sys.stderr)
        return 1
    # Governance (this round, unhappy-path UP-1b): a bare timestamp is only
    # second-granular - two cmd_run() invocations started within the same second
    # (a real operator pattern: legacy+spark or Phase B+B2 launched as separate
    # background processes moments apart) would share run_id, and
    # replace_run_rows() matches purely on (run_id, repeat) - both loops number
    # attempts 1, 2, 3..., so one invocation's finalizer would silently overwrite
    # the OTHER's rows by matching repeat index. Each invocation is a distinct OS
    # process (cmd_run() is called exactly once per process, from main()'s CLI
    # dispatch), so the pid makes run_id unique across any concurrent invocation
    # regardless of phase/backend, with no downstream parser expecting a bare
    # timestamp shape (grepped every run_id use site).
    run_id = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ") + f"-{os.getpid()}"
    trigger_id_cache = {"hbr_counter": 1}
    if trigger_kind == "deploy":
        tb = find_baseline_id(op, TRIGGER_BASELINE)
        if not tb:
            raise RuntimeError(f"trigger baseline '{TRIGGER_BASELINE}' not found - run 'ensure' first")
        trigger_id_cache["trigger_baseline_id"] = tb
    cohort_ids = [r["rule_id"] for r in cohort_rules()]
    exp_rule_ids = expected_rule_ids()
    window_start_for_sweep = dgrhp_now()

    results = []
    valid = 0
    attempts = 0
    max_attempts = repeats * 2
    while valid < repeats and attempts < max(max_attempts, 10):
        attempts += 1
        r = run_repeat(op, phase, backend, trigger_kind, cohort_ids, exp_rule_ids, attempts,
                       trigger_id_cache, run_id, comparison_id)
        results.append(r)
        # Governance (R5.7 driver-merge follow-on, b-lite): write through per attempt, same
        # reasoning cmd_run_phase_a already has - a mid-run SSH/rig hiccup must not discard
        # every already-completed repeat (this happened for real on this branch's own DGRHP
        # run). This row is PRE-SWEEP (conservative); sweep_incomplete() below still needs
        # the full in-memory `results` list to reclassify t2_incomplete rows by re-scanning
        # the whole log span, so any row it changes gets corrected in place afterward via
        # replace_run_rows() rather than losing the write-through property by batching again.
        with open(out_path, "a") as f:
            f.write(json.dumps({**r, "label": label}) + "\n")
        status = "VOID:" + r["void_reason"] if r.get("void_reason") else f"c_ms={r.get('c_ms', '?')}"
        print(f"[run] {label} {backend} {phase} attempt={attempts} {status}")
        if not r.get("void_reason"):
            valid += 1
        if valid < repeats:
            time.sleep(gap)

    results = sweep_incomplete(results, window_start_for_sweep)
    inconclusive = valid < repeats
    swept_rows = [{**r, "label": label} for r in results]
    # Governance (this round): out_path may not exist yet - repeats=0 (a degenerate but
    # reachable CLI invocation) or a --out path that's never been written to leaves the
    # write-through loop above never entered, so nothing created the file. The pre-write-
    # through code tolerated this (its single unconditional "a"-mode open created the file
    # regardless of whether anything was written); a bare "r"-mode open here would crash
    # with FileNotFoundError where the old code silently produced an empty file - not a
    # behavior change worth having, for a two-line guard.
    lines = []
    if os.path.exists(out_path):
        with open(out_path, "r") as f:
            lines = f.readlines()
    # Governance (this round, unhappy-path UP-1): fingerprint the FOREIGN lines (not
    # this run's own, which we are legitimately about to rewrite) before touching
    # anything, and re-check the fingerprint - not a bare line count - immediately
    # before the swap. Before this round, cmd_run's final write was a pure append,
    # safe under a concurrent writer; this round's read-modify-write finalization is
    # NOT - a second process's own equal-length in-place rewrite (e.g. two invocations
    # racing with the same repeat count) changed the file's CONTENT without changing
    # its LINE COUNT, so a bare-count check passed while silently reverting the other
    # process's sweep corrections. A content hash catches that; a count cannot. This
    # run's own per-attempt rows are already durably on disk via write-through above
    # regardless of what happens next, so refusing here costs only THIS run's own
    # sweep-reclassification correction, never data - and relies on run_id (now
    # pid-suffixed, see above) actually being unique per invocation, or two racing
    # invocations of the SAME run_id would exclude each other's rows from "foreign"
    # on both sides and this check would not see them either.
    before_count, before_digest = _foreign_fingerprint(lines, run_id)
    lines = replace_run_rows(lines, run_id, swept_rows)
    live_lines = []
    if os.path.exists(out_path):
        with open(out_path) as f:
            live_lines = f.readlines()
    live_count, live_digest = _foreign_fingerprint(live_lines, run_id)
    if live_count != before_count or live_digest != before_digest:
        print(f"[run] {label} {backend} {phase} ABORT: {out_path}'s other-run evidence "
              f"changed ({before_count} foreign lines before this finalization, "
              f"{live_count} now, digest {'unchanged' if live_digest == before_digest else 'CHANGED'}) "
              f"- a concurrent writer is the likely cause. Refusing to overwrite. This "
              f"run's own {len(results)} attempt row(s) are already durable on disk via "
              f"write-through; only THIS run's sweep-reclassification correction is lost "
              f"- 'report' re-reads the file as-is and does NOT re-run the sweep, so it "
              f"will not recover it. Re-run the measurement if the correction matters.",
              file=sys.stderr)
        return 1
    # Governance (Gate 8 re-review, unhappy-path): explicitly restating the residual this
    # check does NOT close, since the prior code's own comment naming it was dropped when
    # this check replaced the bare line count - this fingerprint check narrows the
    # concurrent-writer race to the gap between THIS check and the os.replace() swap two
    # lines below; it is not a full lock. A third writer landing in that specific
    # (small, unlocked) window still escapes detection. Acceptable under this tool's
    # documented single-operator usage model; real locking would be needed if concurrent
    # invocation becomes a real, expected usage pattern rather than an operator mistake.
    tmp_path = f"{out_path}.tmp-{os.getpid()}"
    with open(tmp_path, "w") as f:
        f.writelines(lines)
    os.replace(tmp_path, out_path)
    void_final = sum(1 for r in results if r.get("void_reason"))
    print(f"[run] {label} {backend} {phase} DONE valid={valid}/{repeats} "
          f"attempts={attempts} void={void_final} inconclusive={inconclusive} "
          f"run_id={run_id} comparison_id={comparison_id}")
    return 0


def find_baseline_id(op, name):
    return G.find_baseline_id(G.list_baselines_html(op), name)


def observe_phase_a_window(window_start_ts):
    """Phase A: no trigger, no clean-cohort void rules, no fence machinery -
    context-only, NOT verdict-bearing (unchanged this round except the
    dev-shape T1_RE unpack, which now needs a `pending` slot)."""
    size0 = agent_log_size()
    deadline_t0 = time.time() + 1200
    t0 = t0_source = None
    while time.time() < deadline_t0 and t0 is None:
        events, size = _fetch_window(window_start_ts)
        if size < size0:
            return {"void_reason": "log_rotated_mid_window"}
        for p in events:
            if T0_RE.match(p["msg"]):
                t0, t0_source = p, "cleared"
                break
        if t0 is None:
            for p in events:
                if PUSH_CMD_RE.match(p["msg"]):
                    t0, t0_source = p, "fallback"
                    break
        if t0 is not None:
            break
        time.sleep(2)
    if t0 is None:
        return {"void_reason": "t0_not_found_in_cap"}

    deadline_t1 = time.time() + 120
    t1 = t1_groups = None
    arm_events = []
    while time.time() < deadline_t1 and t1 is None:
        events, size = _fetch_window(window_start_ts)
        if size < size0:
            return {"void_reason": "log_rotated_mid_window"}
        after_t0 = [p for p in events if p["ts"] >= t0["ts"]]
        arm_events = [p for p in after_t0
                      if ARM_LEGACY_RE.match(p["msg"]) or ARM_SPARK_RE.match(p["msg"])]
        for p in after_t0:
            m = T1_RE.match(p["msg"])
            if m:
                t1, t1_groups = p, m.groups()
                break
        if t1 is not None:
            break
        time.sleep(2)
    if t1 is None:
        return {"void_reason": "t1_not_found_within_120s_of_t0"}
    arm_events = [p for p in arm_events if p["ts"] <= t1["ts"]]

    applied, failed, pending, full_sync, generation, total = t1_groups
    b_ms = (t1["ts"] - t0["ts"]).total_seconds() * 1000
    return {
        "void_reason": None, "t0_source": t0_source, "t0": t0["ts"].isoformat(),
        "t1": t1["ts"].isoformat(), "generation": int(generation), "applied": int(applied),
        "failed": int(failed), "total": int(total), "pending": int(pending), "b_ms": b_ms,
        "n_arm_lines": len(arm_events), "next_window_start": t1["ts"],
    }


def cmd_run_phase_a(op, backend, label, out_path, cap_seconds=1200, target_windows=3):
    start = time.time()
    n_windows = 0
    # Governance Gate 8 (unhappy-path, second pass): Phase A never got UP-2's SSH-exception
    # guarding at all - only Phase B/B2's observe_window() was wrapped. Phase A is context-only
    # (never verdict-bearing, see the run doc), but an unguarded SSH blip here still crashed
    # the whole cmd_run_phase_a invocation rather than ending the observation early or voiding
    # one window, same UP-2 symptom class.
    try:
        window_start_ts = dgrhp_now()  # NOT datetime.now(timezone.utc) - see dgrhp_utc_offset()
    except Exception as e:  # noqa: BLE001
        print(f"[run-a] {label} {backend} ABORT: dgrhp clock unavailable before first window: "
              f"{type(e).__name__}:{str(e)[:200]}", file=sys.stderr)
        return 1
    while n_windows < target_windows and (time.time() - start) < cap_seconds:
        try:
            obs = observe_phase_a_window(window_start_ts)
        except Exception as e:  # noqa: BLE001
            obs = {"void_reason": f"observe_failed:{type(e).__name__}:{str(e)[:200]}"}
        try:
            window_start_ts = obs.get("next_window_start") or dgrhp_now()
        except Exception as e:  # noqa: BLE001
            n_windows += 1
            obs.pop("next_window_start", None)
            obs.update({"phase": "A", "backend": backend, "label": label, "repeat": n_windows})
            with open(out_path, "a") as f:
                f.write(json.dumps(obs) + "\n")
            print(f"[run-a] {label} {backend} window={n_windows} dgrhp clock unavailable for "
                  f"next window, ending observation early: {type(e).__name__}:{str(e)[:200]}",
                  file=sys.stderr)
            break
        obs.pop("next_window_start", None)
        n_windows += 1
        obs.update({"phase": "A", "backend": backend, "label": label, "repeat": n_windows})
        # Governance (unhappy-path UP-1): write through per window, same reasoning as cmd_run.
        with open(out_path, "a") as f:
            f.write(json.dumps(obs) + "\n")
        status = "VOID:" + obs["void_reason"] if obs.get("void_reason") else \
            f"b_ms={obs['b_ms']:.1f} applied={obs['applied']} failed={obs['failed']} total={obs['total']}"
        print(f"[run-a] {label} {backend} window={n_windows} {status}")
        if obs.get("void_reason") in ("log_rotated_mid_window",):
            break
    elapsed = time.time() - start
    print(f"[run-a] {label} {backend} DONE windows={n_windows} elapsed_s={elapsed:.0f} "
          f"cap_hit={elapsed >= cap_seconds}")
    return 0


# --------------------------------------------------------------------------
# reporting
# --------------------------------------------------------------------------


def build_report_lines(rows):
    groups = {}
    for r in rows:
        key = (r.get("comparison_id"), r.get("run_id"), r["label"], r["backend"], r["phase"])
        groups.setdefault(key, []).append(r)
    lines = ["| Comparison | Run | Label | Backend | Phase | Attempted | Valid | Floor reached | "
             "B median (ms) | C median (ms) | Void breakdown |",
             "|---|---|---|---|---|---|---|---|---|---|---|"]
    for key in sorted(groups, key=lambda k: tuple(str(x) for x in k)):
        comparison_id, run_id, label, backend, phase = key
        rs = groups[key]
        valid = [r for r in rs if not r.get("void_reason")]
        floor = 5 if phase == "B" else 3
        reached = "Y" if len(valid) >= floor else "N"
        void_counts = {}
        for r in rs:
            if r.get("void_reason"):
                void_counts[r["void_reason"]] = void_counts.get(r["void_reason"], 0) + 1
        void_str = ", ".join(f"{k}={v}" for k, v in sorted(void_counts.items())) or "-"
        b_vals = [r["b_ms"] for r in valid if "b_ms" in r]
        c_vals = [r["c_ms"] for r in valid if "c_ms" in r]
        b_med = f"{statistics.median(b_vals):.1f}" if b_vals else "-"
        c_med = f"{statistics.median(c_vals):.1f}" if c_vals else "-"
        lines.append(f"| {comparison_id} | {run_id} | {label} | {backend} | {phase} | "
                      f"{len(rs)} | {len(valid)} | {reached} | {b_med} | {c_med} | {void_str} |")
    return lines


def build_verdict_lines(rows):
    # R5.7 bug fix (found live, 2026-09-19): legacy and spark are separate
    # cmd_run() invocations and therefore carry DIFFERENT run_id values by
    # construction - grouping on run_id (as an earlier version of this
    # function did) can never pair them for the SAME comparison, and every
    # verdict silently read INCONCLUSIVE (each backend saw 0 rows for the
    # other side). The pairing key is (comparison_id, label, phase) only;
    # run_id is per-backend provenance, reported per cell in
    # build_report_lines, not part of how cells are paired for a verdict.
    groups = {}
    for r in rows:
        if r["phase"] not in ("B", "B2"):
            continue
        key = (r.get("comparison_id"), r["label"], r["phase"])
        groups.setdefault(key, {}).setdefault(r["backend"], []).append(r)
    lines = ["| Comparison | Label | Phase | Verdict |", "|---|---|---|---|"]
    for key in sorted(groups, key=lambda k: tuple(str(x) for x in k)):
        comparison_id, label, phase = key
        cells = groups[key]
        floor = 5 if phase == "B" else 3
        verdict = compute_verdict(cells.get("legacy", []), cells.get("spark", []), floor)
        lines.append(f"| {comparison_id} | {label} | {phase} | {verdict} |")
    return lines


def cmd_report(in_path, out_md_path):
    rows = []
    with open(in_path) as f:
        for line in f:
            rows.append(json.loads(line))
    lines = build_report_lines(rows) + [""] + build_verdict_lines(rows)
    with open(out_md_path, "w") as f:
        f.write("\n".join(lines) + "\n")
    print("\n".join(lines))
    return 0


# --------------------------------------------------------------------------
# selftest - offline, no rig, no server. Run BEFORE any login (see main()).
# Fixtures F1-F14 per the R5.7 round-2 plan §2.2 item 11 - this is the check
# that would have caught the dev-shape T1_RE drift before a rig round, and
# the actual correctness test for the epoch-fence design Astra's adversarial
# review found round 1's timestamp-only version unsound against.
# --------------------------------------------------------------------------


def _f1():
    dev_line = "Guardian: apply_rules ok (applied=62, failed=0, pending=3, full_sync=true, generation=5, total=62)"
    old_line = "Guardian: apply_rules ok (applied=62, failed=0, full_sync=true, generation=5, total=62)"
    ok1 = bool(T1_RE.match(dev_line))
    ok2 = not bool(T1_RE.match(old_line))
    return ok1 and ok2, f"dev_match={ok1} old_rejected={ok2}"


def _f2():
    lines = {
        "t0": "Guardian: full_sync cleared 62 prior rule(s)",
        "t0d": "Guardian spark: detach_all complete (epoch=3, incarnation_floor=100, "
               "detached_rules=62, withdrawn_claims=0)",
        "t1": "Guardian: apply_rules ok (applied=62, failed=0, pending=0, full_sync=true, "
              "generation=5, total=62)",
        "t2": "Guardian spark: arm committed for rule 'blackout-reg-01' (epoch=3, "
              "incarnation=101, type=registry, via=inline-arm, attach_to_commit_ms=12)",
        "legacy": "Guardian: file guard armed for rule 'blackout-file-01'",
        "sparkengine": r"SparkEngine: armed 'reg:HKCU\SOFTWARE\YuzuBlackout\Key01'",
    }
    regexes = {"t0": T0_RE, "t0d": T0D_RE, "t1": T1_RE, "t2": T2_RE,
               "legacy": ARM_LEGACY_RE, "sparkengine": ARM_SPARK_RE}
    ok, detail = True, []
    for name, line in lines.items():
        matched = {r for r, rx in regexes.items() if rx.match(line)}
        if matched != {name}:
            ok = False
            detail.append(f"{name}: matched={matched}")
    m = T0D_RE.match(lines["t0d"])
    if not m or [int(x) for x in m.groups()] != [3, 100, 62, 0]:
        ok = False
        detail.append("t0d field mismatch")
    m = T2_RE.match(lines["t2"])
    if not m or m.groups() != ("blackout-reg-01", "3", "101", "registry", "inline-arm", "12"):
        ok = False
        detail.append("t2 field mismatch")
    return ok, "; ".join(detail) or "all regexes pairwise-exclusive, fields parsed correctly"


def _f3():
    events = [
        _ev("2026-09-19 10:00:00.000", "Guardian: full_sync cleared 1 prior rule(s)"),
        _ev("2026-09-19 10:00:00.020",
            "Guardian spark: arm committed for rule 'blackout-reg-01' (epoch=2, incarnation=50, "
            "type=registry, via=callback-arm, attach_to_commit_ms=5)"),  # STALE, epoch E-1
        _ev("2026-09-19 10:00:00.050", "Guardian spark: detach_all complete (epoch=3, "
            "incarnation_floor=100, detached_rules=1, withdrawn_claims=0)"),
        _ev("2026-09-19 10:00:00.100", "Guardian: apply_rules ok (applied=1, failed=0, "
            "pending=0, full_sync=true, generation=5, total=1)"),
        _ev("2026-09-19 10:00:00.150",
            "Guardian spark: arm committed for rule 'blackout-reg-01' (epoch=3, incarnation=101, "
            "type=registry, via=inline-arm, attach_to_commit_ms=8)"),
    ]
    result = classify_t2(events, epoch=3, floor=100, expected_rule_ids={"blackout-reg-01"},
                          own_push_raw=None, backend="spark",
                          t0_ts=events[0]["ts"], t0d_ts=events[2]["ts"])
    stale_rejected = any(r["reason"] == "wrong_epoch" for r in result["rejected"])
    completed = not result["missing"] and "blackout-reg-01" in result["selected"]
    return stale_rejected and completed, f"stale_rejected={stale_rejected} completed={completed}"


def _f4():
    events = [
        _ev("2026-09-19 10:00:00.000", "Guardian: full_sync cleared 1 prior rule(s)"),
        _ev("2026-09-19 10:00:00.010", "Guardian spark: detach_all complete (epoch=3, "
            "incarnation_floor=100, detached_rules=1, withdrawn_claims=0)"),
        _ev("2026-09-19 10:00:00.030",
            "Guardian spark: arm committed for rule 'blackout-reg-01' (epoch=3, incarnation=42, "
            "type=registry, via=callback-adopt, attach_to_commit_ms=3)"),  # incarnation <= floor
    ]
    result = classify_t2(events, epoch=3, floor=100, expected_rule_ids={"blackout-reg-01"},
                          own_push_raw=None, backend="spark",
                          t0_ts=events[0]["ts"], t0d_ts=events[1]["ts"])
    v = result["selected"].get("blackout-reg-01")
    ok = v is not None and v["reobserved_adopt"] is True and not result["missing"]
    no_fv = not any(r["reason"] == "fence_violation_below_floor" for r in result["rejected"])
    return ok and no_fv, f"selected_reobserved={ok} no_fence_violation={no_fv}"


def _f5():
    events = [
        _ev("2026-09-19 10:00:00.000", "Guardian: full_sync cleared 1 prior rule(s)"),
        _ev("2026-09-19 10:00:00.010", "Guardian spark: detach_all complete (epoch=3, "
            "incarnation_floor=100, detached_rules=1, withdrawn_claims=0)"),
        _ev("2026-09-19 10:00:00.030",
            "Guardian spark: arm committed for rule 'blackout-reg-01' (epoch=3, incarnation=42, "
            "type=registry, via=inline-arm, attach_to_commit_ms=3)"),  # NOT adopt, below floor
    ]
    result = classify_t2(events, epoch=3, floor=100, expected_rule_ids={"blackout-reg-01"},
                          own_push_raw=None, backend="spark",
                          t0_ts=events[0]["ts"], t0d_ts=events[1]["ts"])
    flagged = any(r["reason"] == "fence_violation_below_floor" for r in result["rejected"])
    not_selected = "blackout-reg-01" not in result["selected"]
    return flagged and not_selected, f"flagged={flagged} not_selected={not_selected}"


def _f6():
    t0 = _ev("2026-09-19 10:00:00.000", "x")["ts"]
    t1 = _ev("2026-09-19 10:00:00.100", "x")["ts"]
    selected = {
        "r1": {"ts": _ev("2026-09-19 10:00:00.050", "x")["ts"], "via": "inline-arm"},
        "r2": {"ts": t1, "via": "inline-arm"},
        "r3": {"ts": _ev("2026-09-19 10:00:00.150", "x")["ts"], "via": "inline-arm"},
    }
    wm = compute_window_math(t0, t0, t1, selected)
    ok = (wm["n_t2_before_t1"] == 1 and wm["n_t2_tie_t1"] == 1 and wm["n_t2_after_t1"] == 1
          and abs(wm["c_ms"] - 150.0) < 1e-6)
    return ok, (f"before={wm['n_t2_before_t1']} tie={wm['n_t2_tie_t1']} "
                f"after={wm['n_t2_after_t1']} c_ms={wm['c_ms']}")


def _f7():
    events = [
        _ev("2026-09-19 10:00:00.030",
            "Guardian spark: arm committed for rule 'blackout-reg-02' (epoch=1, incarnation=11, "
            "type=registry, via=inline-arm, attach_to_commit_ms=3)"),
        _ev("2026-09-19 10:00:00.000", "Guardian: full_sync cleared 2 prior rule(s)"),
        _ev("2026-09-19 10:00:00.010", "Guardian spark: detach_all complete (epoch=1, "
            "incarnation_floor=5, detached_rules=2, withdrawn_claims=0)"),
        _ev("2026-09-19 10:00:00.020",
            "Guardian spark: arm committed for rule 'blackout-reg-01' (epoch=1, incarnation=10, "
            "type=registry, via=inline-arm, attach_to_commit_ms=3)"),
    ]
    t0_ts = min(e["ts"] for e in events if T0_RE.match(e["msg"]))
    t0d_ev = [e for e in events if T0D_RE.match(e["msg"])][0]
    result = classify_t2(events, epoch=1, floor=5,
                          expected_rule_ids={"blackout-reg-01", "blackout-reg-02"},
                          own_push_raw=None, backend="spark", t0_ts=t0_ts, t0d_ts=t0d_ev["ts"])
    ok = not result["missing"] and len(result["selected"]) == 2
    return ok, f"missing={result['missing']} selected={sorted(result['selected'])}"


def _f8():
    events = [
        _ev("2026-09-19 10:00:00.000", "Guardian: full_sync cleared 1 prior rule(s)"),
        _ev("2026-09-19 10:00:00.010", "Guardian spark: detach_all complete (epoch=1, "
            "incarnation_floor=5, detached_rules=1, withdrawn_claims=0)"),
        _ev("2026-09-19 10:00:00.500", "Guardian: full_sync cleared 1 prior rule(s)"),
        _ev("2026-09-19 10:00:00.510", "Guardian spark: detach_all complete (epoch=2, "
            "incarnation_floor=10, detached_rules=1, withdrawn_claims=0)"),
    ]
    result = classify_t2(events, epoch=1, floor=5, expected_rule_ids={"blackout-reg-01"},
                          own_push_raw=None, backend="spark",
                          t0_ts=events[0]["ts"], t0d_ts=events[1]["ts"])
    ok = result["next_t0d_ts"] is not None
    return ok, f"next_t0d_ts={result['next_t0d_ts']}"


def _f9():
    # "Same-ms tie" case: the trigger's OWN push-command line and a genuinely
    # DIFFERENT extra push both land at the identical millisecond, at-or-after
    # t0_ts (a line strictly before t0_ts is out of classify_t2's window
    # entirely, by construction - not what this fixture is testing). Identity
    # (raw line content), not timestamp value, is what must tell them apart.
    own_line = "Received command: plugin=__guard__, action=push_rules"
    own_raw = "OWN:" + own_line
    extra_raw = "EXTRA:" + own_line
    events = [
        _ev("2026-09-19 10:00:00.000", "Guardian: full_sync cleared 1 prior rule(s)"),
        _ev("2026-09-19 10:00:00.000", own_line, raw=own_raw),      # tie with T0
        _ev("2026-09-19 10:00:00.000", own_line, raw=extra_raw),    # same ms, DIFFERENT raw
        _ev("2026-09-19 10:00:00.010", "Guardian spark: detach_all complete (epoch=1, "
            "incarnation_floor=5, detached_rules=1, withdrawn_claims=0)"),
        _ev("2026-09-19 10:00:00.030",
            "Guardian spark: arm committed for rule 'blackout-reg-01' (epoch=1, incarnation=10, "
            "type=registry, via=inline-arm, attach_to_commit_ms=3)"),
    ]
    result = classify_t2(events, epoch=1, floor=5, expected_rule_ids={"blackout-reg-01"},
                          own_push_raw=own_raw, backend="spark",
                          t0_ts=events[0]["ts"], t0d_ts=events[3]["ts"])
    ok = len(result["push_lines"]) == 1 and result["push_lines"][0]["raw"] == extra_raw
    return ok, f"push_lines={[p['raw'] for p in result['push_lines']]}"


def _f10():
    t0 = _ev("2026-09-19 10:00:00.000", "x")["ts"]
    t0d = _ev("2026-09-19 10:00:00.010", "x")["ts"]
    base = [
        _ev("2026-09-19 10:00:00.000", "Guardian: full_sync cleared 1 prior rule(s)"),
        _ev("2026-09-19 10:00:00.010", "Guardian spark: detach_all complete (epoch=1, "
            "incarnation_floor=5, detached_rules=1, withdrawn_claims=0)"),
    ]
    late = base + [
        _ev("2026-09-19 10:00:00.090",
            "Guardian spark: arm committed for rule 'blackout-reg-01' (epoch=1, incarnation=10, "
            "type=registry, via=inline-arm, attach_to_commit_ms=3)"),
    ]
    r1 = classify_t2(base, epoch=1, floor=5, expected_rule_ids={"blackout-reg-01"},
                      own_push_raw=None, backend="spark", t0_ts=t0, t0d_ts=t0d)
    r2 = classify_t2(late, epoch=1, floor=5, expected_rule_ids={"blackout-reg-01"},
                      own_push_raw=None, backend="spark", t0_ts=t0, t0d_ts=t0d)
    ok = bool(r1["missing"]) and not r2["missing"]
    return ok, f"early_missing={r1['missing']} late_missing={r2['missing']}"


def _f11():
    t0_ts = _ev("2026-09-19 10:00:00.000", "x")["ts"]
    t0d_ts = _ev("2026-09-19 10:00:00.010", "x")["ts"]
    events_found = [
        _ev("2026-09-19 10:00:05.000",
            "Guardian spark: arm committed for rule 'blackout-reg-01' (epoch=1, incarnation=10, "
            "type=registry, via=inline-arm, attach_to_commit_ms=3)"),
    ]
    found, still_missing, fence_violated = sweep_row_pure(
        events_found, epoch=1, floor=5, missing_rule_ids={"blackout-reg-01"},
        backend="spark", t0_ts=t0_ts, t0d_ts=t0d_ts, own_push_raw=None)
    ok1 = "blackout-reg-01" in found and not still_missing and not fence_violated
    found2, still_missing2, fence_violated2 = sweep_row_pure(
        [], epoch=1, floor=5, missing_rule_ids={"blackout-reg-01"},
        backend="spark", t0_ts=t0_ts, t0d_ts=t0d_ts, own_push_raw=None)
    ok2 = not found2 and still_missing2 == ["blackout-reg-01"] and not fence_violated2
    return ok1 and ok2, f"found_case={ok1} never_found_case={ok2}"


def _f12():
    # All-void cell (both backends, one void row each) - must still print and
    # must read INCONCLUSIVE (floor not reached).
    void_rows = [
        {"comparison_id": "cmp1", "run_id": "run1", "label": "t2-v1", "backend": "legacy",
         "phase": "B", "repeat": 1, "void_class": "instrument", "void_reason": "t0_not_found"},
        {"comparison_id": "cmp1", "run_id": "run1", "label": "t2-v1", "backend": "spark",
         "phase": "B", "repeat": 1, "void_class": "instrument", "void_reason": "t1_not_found"},
    ]
    lines = build_report_lines(void_rows)
    printed = any("cmp1" in ln and "t2-v1" in ln for ln in lines)
    verdicts = build_verdict_lines(void_rows)
    inconclusive = any("INCONCLUSIVE" in ln for ln in verdicts)

    # R5.7 bug (found live, 2026-09-19): legacy and spark are SEPARATE cmd_run()
    # invocations and therefore carry DIFFERENT run_id values in real data - an
    # earlier build_verdict_lines() grouped on run_id and could never pair them,
    # so every verdict silently read INCONCLUSIVE regardless of how much valid
    # data existed. This fixture uses realistic DIFFERENT run_ids per backend
    # and enough valid repeats to clear the floor - the verdict must NOT be
    # INCONCLUSIVE (it should resolve the actual latency/reliability gates).
    def _valid(backend, run_id, n, c_ms):
        return [{"comparison_id": "cmp2", "run_id": run_id, "label": "t2-v1", "backend": backend,
                 "phase": "B", "repeat": i, "void_class": None, "void_reason": None,
                 "c_ms": c_ms, "b_ms": c_ms} for i in range(1, n + 1)]
    paired_rows = (_valid("legacy", "legacy-run-1", 5, 70.0) +
                   _valid("spark", "spark-run-1", 5, 80.0))
    paired_verdicts = build_verdict_lines(paired_rows)
    paired_not_inconclusive = (
        len(paired_verdicts) > 2 and "INCONCLUSIVE" not in paired_verdicts[2]
    )
    return (printed and inconclusive and paired_not_inconclusive,
            f"cell_printed={printed} all_void_inconclusive={inconclusive} "
            f"cross_run_id_paired={paired_not_inconclusive} "
            f"paired_verdict_line={paired_verdicts[2] if len(paired_verdicts) > 2 else None}")


def _f13():
    events_ok = [
        _ev("2026-09-19 10:00:00.000", "Guardian: full_sync cleared 1 prior rule(s)"),
        _ev("2026-09-19 10:00:00.010", "Guardian spark: detach_all complete (epoch=1, "
            "incarnation_floor=5, detached_rules=0, withdrawn_claims=0)"),
        _ev("2026-09-19 10:00:00.050", "Guardian: file guard armed for rule 'blackout-file-01'"),
    ]
    r_ok = classify_t2(events_ok, epoch=1, floor=5, expected_rule_ids={"blackout-file-01"},
                        own_push_raw=None, backend="legacy",
                        t0_ts=events_ok[0]["ts"], t0d_ts=events_ok[1]["ts"])
    ok1 = not r_ok["missing"] and not r_ok["legacy_before_t0d"]

    events_bad = [
        _ev("2026-09-19 10:00:00.000", "Guardian: full_sync cleared 1 prior rule(s)"),
        _ev("2026-09-19 10:00:00.005", "Guardian: file guard armed for rule 'blackout-file-01'"),
        _ev("2026-09-19 10:00:00.010", "Guardian spark: detach_all complete (epoch=1, "
            "incarnation_floor=5, detached_rules=0, withdrawn_claims=0)"),
    ]
    r_bad = classify_t2(events_bad, epoch=1, floor=5, expected_rule_ids={"blackout-file-01"},
                         own_push_raw=None, backend="legacy",
                         t0_ts=events_bad[0]["ts"], t0d_ts=events_bad[2]["ts"])
    ok2 = bool(r_bad["legacy_before_t0d"])
    return ok1 and ok2, f"ok_case={ok1} before_t0d_case={ok2}"


def _f14():
    t0d = {"epoch": 1, "floor": 5, "detached_rules": 60, "withdrawn_claims": 0}
    ok1 = check_teardown_size(t0d, "spark", 62) == "teardown_size_mismatch"
    t0d_ok = {"epoch": 1, "floor": 5, "detached_rules": 62, "withdrawn_claims": 0}
    ok2 = check_teardown_size(t0d_ok, "spark", 62) is None
    t0d_legacy = {"epoch": 1, "floor": 5, "detached_rules": 0, "withdrawn_claims": 0}
    ok3 = check_teardown_size(t0d_legacy, "legacy", 62) is None
    return ok1 and ok2 and ok3, f"mismatch_detected={ok1} ok_spark={ok2} ok_legacy={ok3}"


def _f15():
    # genuine_t1_failure() itself: only B/B2 with failed>0 yields failed_gt_0.
    ok1 = genuine_t1_failure("B2", 1) == "failed_gt_0"
    ok2 = genuine_t1_failure("B", 1) == "failed_gt_0"
    ok3 = genuine_t1_failure("B2", 0) is None
    ok4 = genuine_t1_failure("A", 1) is None

    # resolve_post_t2_void() with BOTH signals present at once - the actual
    # shape of the bug found live (R5.7 T2 re-run, Phase B2 spark repeat 3):
    # a T1-genuine failure reason AND a collection-stage instrument reason on
    # the SAME attempt. Genuine must win regardless of argument order or
    # which signal is falsy.
    #
    # quality-engineer found, during /governance, that an earlier version of
    # this fixture handed a PRE-LABELED void_class="genuine" row straight to
    # compute_verdict() - which never calls resolve_post_t2_void() (or
    # run_repeat) at all, so it passed unchanged even with the actual fix
    # reverted (confirmed empirically: reverting the run_repeat precedence
    # fix and re-running selftest still passed 17/17). This version calls
    # resolve_post_t2_void() directly with both raw signals, which DOES fail
    # if the precedence is wrong - confirmed the other way too: swapping the
    # two `if` bodies (collection-reason-first) makes this fixture fail.
    both_signals = resolve_post_t2_void("failed_gt_0", "double_full_sync")
    ok5 = both_signals == ("genuine", "failed_gt_0")
    only_collection = resolve_post_t2_void(None, "t1_not_found")
    ok6 = only_collection == ("instrument", "t1_not_found")
    only_genuine = resolve_post_t2_void("failed_gt_0", None)
    ok7 = only_genuine == ("genuine", "failed_gt_0")
    neither = resolve_post_t2_void(None, None)
    ok8 = neither == (None, None)
    return (ok1 and ok2 and ok3 and ok4 and ok5 and ok6 and ok7 and ok8,
            f"phase_gate={ok1 and ok2 and ok3 and ok4} genuine_wins_over_collection={ok5} "
            f"collection_only={ok6} genuine_only={ok7} neither={ok8} "
            f"both_signals_result={both_signals}")


def _f16():
    # Sweep membership parity with classify_t2 (both directions, both reviewers'
    # probes): (a) legacy - a LATER application's arm for the same fixed cohort
    # rule_id must NOT be attributed to an earlier, still-open repeat once the
    # next application's own T0d has appeared; (b) spark - a below-floor
    # non-adopt line must be rejected (fence_violation_below_floor, same as
    # classify_t2), and a below-floor callback-adopt line must be ACCEPTED
    # (classify_t2's documented adoption exception), not the reverse.
    t0_ts = _ev("2026-09-19 10:00:00.000", "x")["ts"]
    t0d_ts = _ev("2026-09-19 10:00:00.010", "x")["ts"]

    # (a) legacy cross-application attribution
    events_cross_app = [
        _ev("2026-09-19 10:00:00.010", "Guardian spark: detach_all complete (epoch=1, "
            "incarnation_floor=0, detached_rules=1, withdrawn_claims=0)"),
        # the NEXT application's own T0d (a different epoch) appears before any
        # arm line for the missing rule from THIS application ever does
        _ev("2026-09-19 10:00:05.000", "Guardian spark: detach_all complete (epoch=2, "
            "incarnation_floor=1, detached_rules=1, withdrawn_claims=0)"),
        # this arm line belongs to epoch 2's application, not epoch 1's
        _ev("2026-09-19 10:00:05.050", "Guardian: file guard armed for rule 'blackout-file-01'"),
    ]
    found_a, still_missing_a, fence_violated_a = sweep_row_pure(
        events_cross_app, epoch=1, floor=0, missing_rule_ids={"blackout-file-01"},
        backend="legacy", t0_ts=t0_ts, t0d_ts=t0d_ts, own_push_raw=None)
    ok_a = ("blackout-file-01" not in found_a and still_missing_a == ["blackout-file-01"]
            and not fence_violated_a)

    # (b) spark below-floor non-adopt rejected, below-floor adopt accepted
    events_floor = [
        _ev("2026-09-19 10:00:05.000",
            "Guardian spark: arm committed for rule 'blackout-reg-01' (epoch=1, incarnation=3, "
            "type=registry, via=inline-arm, attach_to_commit_ms=1)"),
        _ev("2026-09-19 10:00:05.010",
            "Guardian spark: arm committed for rule 'blackout-reg-02' (epoch=1, incarnation=3, "
            "type=registry, via=callback-adopt, attach_to_commit_ms=1)"),
    ]
    found_b, still_missing_b, fence_violated_b = sweep_row_pure(
        events_floor, epoch=1, floor=5,
        missing_rule_ids={"blackout-reg-01", "blackout-reg-02"},
        backend="spark", t0_ts=t0_ts, t0d_ts=t0d_ts, own_push_raw=None)
    ok_b_reject_below_floor_non_adopt = "blackout-reg-01" not in found_b
    ok_b_accept_below_floor_adopt = "blackout-reg-02" in found_b
    # blackout-reg-01's rejected line IS a genuine fence_violation_below_floor
    # (R5.7 adversarial-review-class fix, UP-2) - sweep_row_pure must surface
    # it via fence_violated, not silently swallow it now that reg-02 is found.
    ok_b_fence_violated_surfaced = fence_violated_b is True
    return (ok_a and ok_b_reject_below_floor_non_adopt and ok_b_accept_below_floor_adopt
            and ok_b_fence_violated_surfaced,
            f"legacy_no_cross_app_attribution={ok_a} "
            f"spark_below_floor_non_adopt_rejected={ok_b_reject_below_floor_non_adopt} "
            f"spark_below_floor_adopt_accepted={ok_b_accept_below_floor_adopt} "
            f"fence_violated_surfaced={ok_b_fence_violated_surfaced} "
            f"still_missing_a={still_missing_a}")


def _f17():
    # >50% instrument-invalid ceiling (both reviewers independently probed
    # this live): a cell with a majority of instrument-invalid voids must
    # read INCONCLUSIVE even when its valid count also happens to reach floor.
    def _rows(n_valid, n_instrument, backend, phase="B2"):
        valid = [{"phase": phase, "backend": backend, "void_class": None, "void_reason": None,
                  "c_ms": 90.0} for _ in range(n_valid)]
        instrument = [{"phase": phase, "backend": backend, "void_class": "instrument",
                        "void_reason": "t1_not_found"} for _ in range(n_instrument)]
        return valid + instrument

    legacy_clean = _rows(3, 0, "legacy")
    spark_majority_void_at_floor = _rows(3, 4, "spark")  # 3/7 valid = floor met, 4/7 = 57% instrument
    v1 = compute_verdict(legacy_clean, spark_majority_void_at_floor, floor=3)
    ok1 = v1 == "INCONCLUSIVE"

    spark_exactly_half = _rows(3, 3, "spark")  # 3/6 = exactly 50%, NOT over half - ceiling must not fire
    v2 = compute_verdict(legacy_clean, spark_exactly_half, floor=3)
    ok2 = v2 != "INCONCLUSIVE" or len([r for r in spark_exactly_half if not r.get("void_reason")]) < 3

    spark_clean = _rows(5, 0, "spark")
    v3 = compute_verdict(legacy_clean, spark_clean, floor=3)
    ok3 = v3 == "PASS"
    return (ok1 and ok2 and ok3,
            f"majority_void_at_floor_inconclusive={ok1} (verdict={v1}) "
            f"exactly_50pct_not_over_ceiling={ok2} (verdict={v2}) clean_pass={ok3} (verdict={v3})")


def _f18():
    # resolve_collect_t2_reason()'s precedence rule (/governance unhappy-path
    # UP-1): fence_violation must win over EVERY other reason, exactly like
    # resolve_post_t2_void()'s genuine-wins rule one level up. Construct
    # classify_t2()-shaped result dicts directly (pure function of a dict, no
    # need to go through classify_t2 itself) covering every reason and every
    # combination where fence_violation co-occurs with a later-checked one.
    def _result(legacy_before_t0d=None, rejected=None, next_t0d_ts=None,
                missing=None, push_lines=None):
        return {"legacy_before_t0d": legacy_before_t0d or [],
                "rejected": rejected or [], "next_t0d_ts": next_t0d_ts,
                "missing": missing or [], "push_lines": push_lines or []}

    fence_via_legacy = _result(legacy_before_t0d=["raw line"], next_t0d_ts="t")
    ok1 = resolve_collect_t2_reason(fence_via_legacy) == "fence_violation"

    fence_via_rejected = _result(rejected=[{"line": "x", "reason": "fence_violation_below_floor"}],
                                  next_t0d_ts="t", missing=["r1"], push_lines=["p"])
    ok2 = resolve_collect_t2_reason(fence_via_rejected) == "fence_violation"

    double_full_sync_only = _result(next_t0d_ts="t")
    ok3 = resolve_collect_t2_reason(double_full_sync_only) == "double_full_sync"

    t2_incomplete_only = _result(missing=["r1"])
    ok4 = resolve_collect_t2_reason(t2_incomplete_only) == "t2_incomplete"

    repush_confound_only = _result(push_lines=["p"])
    ok5 = resolve_collect_t2_reason(repush_confound_only) == "repush_confound"

    clean = _result()
    ok6 = resolve_collect_t2_reason(clean) is None

    return (ok1 and ok2 and ok3 and ok4 and ok5 and ok6,
            f"fence_via_legacy_wins={ok1} fence_via_rejected_wins_over_double_full_sync={ok2} "
            f"double_full_sync_only={ok3} t2_incomplete_only={ok4} repush_confound_only={ok5} "
            f"clean={ok6}")


def _f19():
    # /governance consistency-auditor finding: void_class_for()'s
    # GENUINE_FAILURE_REASONS / INSTRUMENT_INVALID_REASONS partition is
    # enforced only by a default branch (any string not in the genuine set
    # classifies instrument) - nothing pins today's actual membership, so a
    # future new void_reason literal added at a call site without also being
    # added to GENUINE_FAILURE_REASONS would silently become instrument, the
    # exact laundering direction 2dbb9c7d1 fixed for a different code path.
    # This fixture locks today's CLOSED, hand-verified list of every
    # row-level void_reason literal actually produced by a call site in this
    # file (excludes observe_phase_a_window()'s own ad-hoc "..._in_cap"/
    # "..._within_120s_of_t0" dict keys, which are Phase-A-only, never passed
    # through void_class_for, and not verdict-bearing per the run doc's own
    # "context only" framing; also excludes "fence_violation_below_floor",
    # which is a REJECTED-LINE-level reason inside result["rejected"], never
    # itself a row-level void_reason).
    genuine_literals = {"failed_gt_0", "arm_never_confirmed", "functional_invalid",
                         "fence_violation"}
    instrument_literals = {"t0_not_found", "t0d_not_found", "t1_not_found", "t2_incomplete",
                            "t2_late", "log_rotated_mid_window", "trigger_not_created",
                            "repush_confound", "applied_ne_total", "double_full_sync",
                            "cohort_composition", "teardown_size_mismatch"}
    ok1 = genuine_literals == GENUINE_FAILURE_REASONS
    ok2 = instrument_literals == INSTRUMENT_INVALID_REASONS
    ok3 = not (GENUINE_FAILURE_REASONS & INSTRUMENT_INVALID_REASONS)
    ok4 = all(void_class_for(r) == "genuine" for r in genuine_literals)
    ok5 = all(void_class_for(r) == "instrument" for r in instrument_literals)
    # The documented dynamic-prefix reasons classify instrument by default (the
    # comment above INSTRUMENT_INVALID_REASONS's own definition describes this;
    # not a set-membership case). Grown from 2 to 12 across the R5.7-driver-merge
    # governance round and its hardening follow-on (2026-09-19): the ported per-site
    # SSH/REST guards each mint their own dynamic-prefix reason (metrics_unavailable/
    # dgrhp_clock_unavailable/observe_t0_failed/own_events_fetch_failed/
    # observe_t0d_failed/observe_t1_failed/m1_unavailable/cohort_events_failed/
    # t2_collect_failed - the last one found missing from this list by
    # quality-engineer, a fixture-completeness gap only: void_class_for's default-
    # instrument fallback already classified it correctly, this list just didn't
    # pin it), plus cohort_fetch_unreliable_at_end (Doomgoose review, PR #4614:
    # cohort_events_d()'s bare `except Exception: continue` used to
    # launder a REST-fetch failure for the whole polling window into the same
    # "not_observed" a genuinely-never-fired guard produces, folding it into
    # functional_invalid's genuine bucket - see cohort_events_d()'s own docstring.
    # Named "unreliable_at_end", not "never_succeeded" - security-guardian Gate 2
    # (this review round) found the earlier name literally false for a rule whose
    # FIRST poll succeeded and only its later attempts failed, exactly the case
    # this fix's own last-attempt semantics are about).
    dynamic_prefix_reasons = [
        "trigger_failed:some error",
        "push_counter_mismatch(reconcile_sent_delta=1,pushes_delta=0)",
        "metrics_unavailable:some error",
        "dgrhp_clock_unavailable:TimeoutExpired:cmd timed out",
        "observe_t0_failed:TimeoutExpired:cmd timed out",
        "own_events_fetch_failed:TimeoutExpired:cmd timed out",
        "observe_t0d_failed:TimeoutExpired:cmd timed out",
        "observe_t1_failed:TimeoutExpired:cmd timed out",
        "m1_unavailable:TimeoutExpired:cmd timed out",
        "cohort_events_failed:TimeoutExpired:cmd timed out",
        "t2_collect_failed:TimeoutExpired:cmd timed out",
        "cohort_fetch_unreliable_at_end:r1,r2",
    ]
    ok6 = all(void_class_for(r) == "instrument" for r in dynamic_prefix_reasons)
    # not_full_sync(...) is the ONE deliberate exception (D1, driver-merge follow-on
    # review, applied 2026-09-19) - see void_class_for's own docstring for the full
    # reasoning. Pinned both ways: it must NOT be in the plain-instrument set above,
    # and it must classify genuine regardless of the embedded value.
    ok7 = (void_class_for("not_full_sync(false)") == "genuine"
           and void_class_for("not_full_sync(true)") == "genuine"
           and "not_full_sync(false)" not in dynamic_prefix_reasons)
    return (ok1 and ok2 and ok3 and ok4 and ok5 and ok6 and ok7,
            f"genuine_set_matches={ok1} instrument_set_matches={ok2} "
            f"zero_overlap={ok3} genuine_classify_correct={ok4} "
            f"instrument_classify_correct={ok5} dynamic_prefix_default_instrument={ok6} "
            f"not_full_sync_is_genuine_exception={ok7}")


def _f20():
    # resolve_sweep_reclassification()'s branch order (/governance
    # quality-engineer, Gate 8 round 2): fence_violation must win over BOTH
    # t2_late and arm_never_confirmed, exactly like the two sibling
    # precedence functions. Direct pure-function test, all three outcomes
    # plus the one that matters most - fence_violated=True even when
    # still_missing is ALSO empty (the exact UP-2 masking shape: a rule_id
    # both rejected for a fence violation AND found via a different valid
    # line must not read t2_late just because still_missing ended up empty).
    ok1 = resolve_sweep_reclassification(True, []) == ("genuine", "fence_violation")
    ok2 = resolve_sweep_reclassification(True, ["r1"]) == ("genuine", "fence_violation")
    ok3 = resolve_sweep_reclassification(False, []) == ("instrument", "t2_late")
    ok4 = resolve_sweep_reclassification(False, ["r1"]) == ("genuine", "arm_never_confirmed")
    return (ok1 and ok2 and ok3 and ok4,
            f"fence_violated_wins_even_when_found={ok1} fence_violated_wins_when_still_missing={ok2} "
            f"t2_late_when_clean={ok3} arm_never_confirmed_when_missing={ok4}")


def _f21():
    # replace_run_rows() (R5.7 driver-merge follow-on, b-lite persistence fix): the
    # per-attempt write-through means cmd_run() must correct only the rows
    # sweep_incomplete() actually changed, in place, without disturbing any other run's
    # already-committed evidence sharing the same file - a foreign line must survive
    # completely byte-identical (no json.loads/dumps round-trip), a matching line must be
    # replaced, and a matching line sweep_incomplete left UNCHANGED must still round-trip
    # byte-identical too (the "zero rows changed" case is not a special case skipped
    # entirely, it's the same code path producing the same bytes).
    foreign_line = '{"run_id": "OTHER_RUN", "repeat": 1, "weird_float": 1.10, "extra": "kept"}\n'
    this_run_r1_before = {"run_id": "THIS_RUN", "repeat": 1, "label": "t2-v1",
                           "void_reason": "t2_incomplete"}
    this_run_r2_before = {"run_id": "THIS_RUN", "repeat": 2, "label": "t2-v1",
                           "void_reason": None, "c_ms": 92.0}
    lines = [
        foreign_line,
        json.dumps(this_run_r1_before) + "\n",
        json.dumps(this_run_r2_before) + "\n",
    ]
    # r1 was reclassified by sweep_incomplete (t2_incomplete -> t2_late); r2 was left
    # untouched (same dict content - the "zero rows changed" case, for THIS row).
    r1_after = {**this_run_r1_before, "void_reason": "t2_late", "void_class": "instrument"}
    swept_rows = [r1_after, dict(this_run_r2_before)]

    out = replace_run_rows(lines, "THIS_RUN", swept_rows)

    ok_count = len(out) == len(lines)
    ok_foreign_untouched = out[0] == foreign_line
    ok_r1_replaced = json.loads(out[1])["void_reason"] == "t2_late"
    ok_r2_noop_byte_identical = out[2] == lines[2]

    empty_out = replace_run_rows([foreign_line], "THIS_RUN", [])
    ok_no_matching_run_is_noop = empty_out == [foreign_line]

    ok = (ok_count and ok_foreign_untouched and ok_r1_replaced and ok_r2_noop_byte_identical
          and ok_no_matching_run_is_noop)
    return (ok,
            f"line_count_preserved={ok_count} foreign_line_byte_identical={ok_foreign_untouched} "
            f"matching_row_replaced={ok_r1_replaced} unchanged_row_byte_identical={ok_r2_noop_byte_identical} "
            f"no_matching_run_is_noop={ok_no_matching_run_is_noop}")


def _f22():
    # sweep_incomplete() INTEGRATION test (R5.7 driver-merge follow-on hardening round;
    # quality-engineer + consistency-auditor, independently: F20 only exercises
    # resolve_sweep_reclassification() in isolation, never sweep_incomplete() itself -
    # the function's only real caller, and the one that actually shipped the
    # fence_violation-clobbering bug this round fixes). Monkeypatches the module-level
    # _fetch_window() (this function's only live-I/O dependency) to return synthetic
    # events, then calls sweep_incomplete() directly - the real code path cmd_run()
    # exercises, not a hand-derivation of what it should do.
    global _fetch_window
    orig_fetch_window = _fetch_window
    t0_ts = _ev("2026-09-19 10:00:00.000", "x")["ts"]
    t0d_ts = _ev("2026-09-19 10:00:00.010", "x")["ts"]
    window_start = t0_ts - timedelta(seconds=1)

    def base_row(missing_rule_id):
        return {
            "void_reason": "t2_incomplete", "t0": t0_ts.isoformat(),
            "t0d": {"ts": t0d_ts.isoformat(), "epoch": 1, "floor": 5},
            "missing_rule_ids": [missing_rule_id], "backend": "spark",
            "t2_selected": {},
        }

    try:
        # Case A: a below-floor NON-adopt commit for the still-missing rule (F16's own
        # events_floor scenario, proven to produce fence_violated=True via
        # sweep_row_pure) - sweep_incomplete's end-to-end result must be
        # ("genuine", "fence_violation"), not silently overwritten to
        # ("genuine", "arm_never_confirmed") by its own dispatch. Includes a realistic
        # T0d line AT this row's own t0d_ts as the earliest fetched event (a real sweep
        # fetch spans the whole run and would include it) so the new per-row
        # not-truncated check correctly does not fire here - a fetch containing only the
        # later arm-commit line would not represent a real, non-truncated re-scan.
        fence_events = [
            _ev("2026-09-19 10:00:00.010", "Guardian spark: detach_all complete "
                "(epoch=1, incarnation_floor=0, detached_rules=1, withdrawn_claims=0)"),
            _ev("2026-09-19 10:00:05.000",
                "Guardian spark: arm committed for rule 'blackout-reg-01' (epoch=1, "
                "incarnation=3, type=registry, via=inline-arm, attach_to_commit_ms=1)"),
        ]
        _fetch_window = lambda _ws: (fence_events, 1000)  # noqa: E731
        out_fence = sweep_incomplete([base_row("blackout-reg-01")], window_start)
        fence_ok = (out_fence[0]["void_reason"] == "fence_violation"
                    and out_fence[0]["void_class"] == "genuine")

        # Case B: genuinely never confirmed, no fence violation - must still classify
        # arm_never_confirmed (the fix must not swing the other way and start
        # mislabeling a real non-fence outcome as something else).
        _fetch_window = lambda _ws: ([], 1000)  # noqa: E731
        out_missing = sweep_incomplete([base_row("blackout-reg-02")], window_start)
        missing_ok = (out_missing[0]["void_reason"] == "arm_never_confirmed"
                      and out_missing[0]["void_class"] == "genuine")

        # Case C: a saturated tail (earliest fetched event already after THIS row's own
        # t0d_ts - nothing at or before t0d_ts survived in the fetch) must skip
        # reclassification for this row, leaving it exactly t2_incomplete - not
        # fabricate a genuine finding from data known truncated (UP-2/UP-3). Per-row,
        # not blanket: window_start_ts itself is irrelevant to the check now.
        saturated_events = [_ev("2026-09-19 10:00:04.000", "unrelated line")]
        _fetch_window = lambda _ws: (saturated_events, 1000)  # noqa: E731
        row_c = base_row("blackout-reg-03")
        out_saturated = sweep_incomplete([row_c], window_start)
        saturated_ok = out_saturated[0]["void_reason"] == "t2_incomplete"

        # Case D (Gate 8 re-review, quality-engineer + unhappy-path, independently: cases
        # A-C each call sweep_incomplete() with a single-row list, so a regression to a
        # BLANKET per-call check - "any row truncated -> skip the whole sweep", the exact
        # shape the original broken attempt at this fix had - would still pass all three.
        # This case puts an EARLY row (truncated: its own t0d_ts precedes the fetch's
        # earliest event) and a LATER row (not truncated) in ONE sweep_incomplete() call
        # and asserts they resolve independently - only a genuinely PER-ROW check can
        # pass this.
        row_early = base_row("blackout-reg-04")
        row_early["t0d"] = {"ts": "2026-09-19T10:00:00.010+00:00", "epoch": 1, "floor": 5}
        row_late = base_row("blackout-reg-05")
        row_late["t0d"] = {"ts": "2026-09-19T10:00:20.000+00:00", "epoch": 1, "floor": 5}
        mixed_events = [_ev("2026-09-19 10:00:15.000", "unrelated line")]
        _fetch_window = lambda _ws: (mixed_events, 1000)  # noqa: E731
        out_mixed = sweep_incomplete([row_early, row_late], window_start)
        mixed_early_still_incomplete = out_mixed[0]["void_reason"] == "t2_incomplete"
        mixed_late_reclassified = out_mixed[1]["void_reason"] == "arm_never_confirmed"
        mixed_ok = mixed_early_still_incomplete and mixed_late_reclassified
    finally:
        _fetch_window = orig_fetch_window

    ok = fence_ok and missing_ok and saturated_ok and mixed_ok
    return (ok, f"fence_violation_survives_sweep_incomplete={fence_ok} "
                f"arm_never_confirmed_still_correct={missing_ok} "
                f"saturated_tail_skips_reclassification={saturated_ok} "
                f"per_row_not_blanket_in_mixed_batch={mixed_ok}")


def _f23():
    # _foreign_fingerprint() (R5.7 driver-merge follow-on hardening round, unhappy-path
    # UP-1): the concurrent-writer guard it replaces used a bare line count, which
    # cannot catch two invocations racing to an EQUAL final line count - the exact
    # shape of the bug this fixture locks. Two "foreign" (different run_id) lines with
    # the SAME COUNT but DIFFERENT CONTENT must fingerprint differently; the current
    # run's own rows must be excluded entirely (their presence/absence/edits must never
    # change the fingerprint, since this process is legitimately about to rewrite them).
    foreign_v1 = ['{"run_id": "OTHER", "repeat": 1, "c_ms": 74.0}\n']
    foreign_v2 = ['{"run_id": "OTHER", "repeat": 1, "c_ms": 999.0}\n']  # same count, different content
    ok_count_equal = _foreign_fingerprint(foreign_v1, "THIS_RUN")[0] == \
        _foreign_fingerprint(foreign_v2, "THIS_RUN")[0]
    ok_digest_differs = _foreign_fingerprint(foreign_v1, "THIS_RUN")[1] != \
        _foreign_fingerprint(foreign_v2, "THIS_RUN")[1]

    this_run_line = '{"run_id": "THIS_RUN", "repeat": 1, "c_ms": 1.0}\n'
    fp_without_ours = _foreign_fingerprint(foreign_v1, "THIS_RUN")
    fp_with_ours = _foreign_fingerprint(foreign_v1 + [this_run_line], "THIS_RUN")
    ok_own_run_excluded = fp_without_ours == fp_with_ours

    ok = ok_count_equal and ok_digest_differs and ok_own_run_excluded
    return (ok, f"equal_length_same_count={ok_count_equal} "
                f"different_content_different_digest={ok_digest_differs} "
                f"own_run_rows_excluded={ok_own_run_excluded}")


def _f24():
    # cohort_events_d() (Doomgoose review, PR #4614, corrected in a follow-up
    # round after unhappy-path found the first version credited a rule's
    # ALWAYS-EMPTY first sweep - guaranteed by deadline_ms's own sizing - and
    # stayed permanently "ok" even if every later attempt then failed for the
    # rest of the grace window): a rule whose MOST RECENT poll attempt raised must
    # come back in `never_fetched` - not "ever raised", not "ever succeeded".
    # Three rules pin the three cases: always fails (never_fetched); succeeds
    # once early then fails for good (now ALSO never_fetched - the corrected
    # case, previously wrongly excluded); fails early then recovers and
    # succeeds on its last attempt (excluded - the LAST look is what counts).
    # Mutation: reverting the fix (dropping `last_fetch_ok`/`never_fetched` and
    # returning bare `by_rule`) makes this fixture fail with a ValueError
    # unpacking the return value - three rule_ids into a two-variable unpack,
    # not the ambiguous "succeeds silently, fails two lines later" shape a
    # 2-rule cohort would produce (verified empirically both ways).
    global get_json, time, _DGRHP_UTC_OFFSET
    orig_get_json = get_json
    orig_sleep = time.sleep
    orig_time = time.time
    orig_offset = _DGRHP_UTC_OFFSET
    fake_now = [1_800_000_000.0]
    attempts = {"ok_then_always_fails": 0, "fails_then_ok_at_end": 0}
    try:
        time.time = lambda: fake_now[0]  # noqa: E731
        time.sleep = lambda s: fake_now.__setitem__(0, fake_now[0] + s)  # noqa: E731
        _DGRHP_UTC_OFFSET = timedelta(0)  # avoid dgrhp_utc_offset()'s real ssh_ps() round trip

        def fake_get_json(_op, path):
            if "rule_id=always_fails" in path:
                raise RuntimeError("simulated REST failure")
            if "rule_id=ok_then_always_fails" in path:
                attempts["ok_then_always_fails"] += 1
                if attempts["ok_then_always_fails"] == 1:
                    return {"data": []}  # one real, empty fetch, then breaks for good
                raise RuntimeError("simulated REST failure")
            if "rule_id=fails_then_ok_at_end" in path:
                attempts["fails_then_ok_at_end"] += 1
                if attempts["fails_then_ok_at_end"] < 3:
                    raise RuntimeError("simulated REST failure")
                return {"data": []}  # recovers - the LAST attempt succeeds
            return {"data": []}

        get_json = fake_get_json
        t0_dt = datetime(2026, 9, 19, 10, 0, 0, tzinfo=timezone.utc)
        by_rule, never_fetched = cohort_events_d(
            "op", ["always_fails", "ok_then_always_fails", "fails_then_ok_at_end"],
            t0_dt, deadline_ms=1000, poll=1.0)
    finally:
        get_json = orig_get_json
        time.sleep = orig_sleep
        time.time = orig_time
        _DGRHP_UTC_OFFSET = orig_offset

    always_fails_never_fetched = "always_fails" in never_fetched
    ok_then_fails_now_never_fetched = "ok_then_always_fails" in never_fetched
    recovered_excluded = "fails_then_ok_at_end" not in never_fetched
    all_not_observed = all(by_rule[r] == "not_observed" for r in by_rule)
    ok = (always_fails_never_fetched and ok_then_fails_now_never_fetched
          and recovered_excluded and all_not_observed)
    return (ok, f"always_fails_never_fetched={always_fails_never_fetched} "
                f"ok_then_fails_now_never_fetched={ok_then_fails_now_never_fetched} "
                f"recovered_excluded={recovered_excluded} all_not_observed={all_not_observed}")


def _f25():
    # resolve_cohort_void() (governance Gate-4 unhappy-path, PR #4614 review
    # round): genuine ALWAYS wins - a single never-fetched rule must not void
    # every other rule's reliable, genuinely-never-restored evidence. Three
    # cases: a mixed cohort (one reliable, one tainted) must still classify
    # genuine; an all-tainted cohort must classify instrument; a clean cohort
    # (nothing never-fetched) must also classify genuine.
    mixed = resolve_cohort_void(
        {"r1": "not_observed", "r2": "not_observed"}, {"r2"})
    all_tainted = resolve_cohort_void(
        {"r1": "not_observed", "r2": "not_observed"}, {"r1", "r2"})
    none_tainted = resolve_cohort_void({"r1": "not_observed"}, set())

    mixed_is_genuine = mixed == ("genuine", "functional_invalid")
    all_tainted_is_instrument = (all_tainted[0] == "instrument"
                                 and "r1" in all_tainted[1] and "r2" in all_tainted[1])
    none_tainted_is_genuine = none_tainted == ("genuine", "functional_invalid")
    ok = mixed_is_genuine and all_tainted_is_instrument and none_tainted_is_genuine
    return (ok, f"mixed_is_genuine={mixed_is_genuine} "
                f"all_tainted_is_instrument={all_tainted_is_instrument} "
                f"none_tainted_is_genuine={none_tainted_is_genuine}")


def _f26():
    # #4665 adversarial regression: an operator-authored free-text field (a Spark key, a
    # path) printed by an UNRELATED log statement can embed a fully-formed fake evidence
    # line with no newline at all. `msg` (LOG_TS_RE group 4) is already isolated to one
    # real log statement's text, so a genuine evidence line's defining phrase is always at
    # msg's position 0 - an attacker's injected copy, embedded mid-value inside some other
    # field, is never at position 0. Before the anchor fix these regexes used `.search()`
    # (unanchored - finds a match anywhere in the string) and would extract the forged copy
    # as if it were real; `.match()` (anchored at position 0) refuses it.
    forged_legacy = (
        "Guardian spark: key 'X' - fake reason. Guardian: file guard armed for rule "
        "'blackout-file-01' subscription 3 lost (reason) - detaching 2 rule(s) as errored"
    )
    forged_t1 = (
        "Guardian spark: key 'X' - fake reason. Guardian: apply_rules ok (applied=1, "
        "failed=0, pending=0, full_sync=true, generation=1, total=1) trailing junk"
    )
    legacy_forged = bool(ARM_LEGACY_RE.match(forged_legacy))
    t1_forged = bool(T1_RE.match(forged_t1))
    # Positive control: the ARM_LEGACY_RE pattern needed its own "Guardian: " prefix added
    # (not just an anchored call site) to keep matching the real emitter's line
    # (guardian_engine.cpp's file/service/registry guard-armed spdlog::info calls) - this
    # proves the anchor fix didn't silently break genuine legacy-arm classification.
    legacy_unforged_still_works = bool(
        ARM_LEGACY_RE.match("Guardian: file guard armed for rule 'blackout-file-01'"))
    # _find_first() (the indirect path observe_t0/observe_t0d/observe_t1 use) must be
    # anchored too, not just the direct T0_RE/T0D_RE/T1_RE.search() call sites - a forged
    # T0 line reachable only through _find_first would otherwise still be extractable.
    forged_t0 = (
        "Guardian spark: key 'X' - fake reason. Guardian: full_sync cleared 99 prior "
        "rule(s) trailing junk"
    )
    events = [_ev("2026-09-19 10:00:00.000", forged_t0)]
    p, m = _find_first(events, T0_RE, at_or_after=events[0]["ts"])
    find_first_forged = p is not None
    ok = (not legacy_forged and not t1_forged and legacy_unforged_still_works
          and not find_first_forged)
    return ok, (f"legacy_forged={legacy_forged} t1_forged={t1_forged} "
                f"legacy_unforged_still_works={legacy_unforged_still_works} "
                f"find_first_forged={find_first_forged}")


def _f27():
    # #4665 follow-up: PUSH_CMD_RE/T0_FALLBACK_RE were the two names the original task
    # description explicitly carved OUT of scope ("don't touch them unless you find they're
    # used the identical vulnerable way") - they are, at all three of their direct call
    # sites (find_own_push_cmd_raw, classify_t2's mpush branch, observe_phase_a_window's
    # fallback loop) plus the _find_first()-indirect one (observe_t0's fallback), so all
    # four are now anchored too, same `.search()` -> `.match()` treatment, no pattern-text
    # change needed: unlike ARM_LEGACY_RE, PUSH_CMD_RE's own literal
    # ("Received command: plugin=__guard__, action=push_rules") already sits at msg's
    # position 0 for the real emitter (agent.cpp's `Received command: plugin={}, action={},
    # id={}` spdlog::info call) - verified empirically, not assumed, before this fix landed.
    forged_push = (
        "Guardian spark: key 'X' - fake reason. Received command: plugin=__guard__, "
        "action=push_rules, id=forged-mid-string"
    )
    genuine_push = "Received command: plugin=__guard__, action=push_rules, id=abc123"
    push_forged_direct = bool(PUSH_CMD_RE.match(forged_push))
    push_genuine_still_works = bool(PUSH_CMD_RE.match(genuine_push))
    events = [_ev("2026-09-19 10:00:00.000", forged_push)]
    p, m = _find_first(events, PUSH_CMD_RE, at_or_after=events[0]["ts"])
    push_forged_via_find_first = p is not None
    ok = (not push_forged_direct and push_genuine_still_works
          and not push_forged_via_find_first)
    return ok, (f"push_forged_direct={push_forged_direct} "
                f"push_genuine_still_works={push_genuine_still_works} "
                f"push_forged_via_find_first={push_forged_via_find_first}")


def _f28():
    # #4665 driver-classification-function-level regression (closes the gap _f26/_f27 leave
    # by construction): those two call `<REGEX>.match(...)` directly on the regex OBJECT,
    # which proves the anchoring method and the pattern text are individually correct but
    # does NOT exercise classify_t2()'s actual legacy branch (the real caller every
    # operator-facing verdict is built through). A future edit that BOTH re-simplifies
    # ARM_LEGACY_RE's pattern (drops the "Guardian: " prefix) AND regresses its call site
    # back to `.search()` would slip past every other #4665 fixture but must not slip past
    # this one. The forged line reproduces the task's own construction: a Spark-key/path
    # free-text field on an UNRELATED log statement embeds a fully-formed fake
    # "file guard armed for rule '...'" phrase with no newline, for a rule id
    # ("blackout-file-99") that is never genuinely armed in this event list - only a
    # DIFFERENT, genuinely-armed rule id ("blackout-file-01") should end up selected.
    t0_ts = _ev("2026-09-19 10:00:00.000", "x")["ts"]
    t0d_ts = _ev("2026-09-19 10:00:00.010", "x")["ts"]
    forged_line = (
        "Guardian spark: key 'X' - fake reason. Guardian: file guard armed for rule "
        "'blackout-file-99' subscription 3 lost (reason) - detaching 2 rule(s) as errored"
    )
    events = [
        _ev("2026-09-19 10:00:00.000", "Guardian: full_sync cleared 2 prior rule(s)"),
        _ev("2026-09-19 10:00:00.020", forged_line),
        _ev("2026-09-19 10:00:00.030",
            "Guardian: file guard armed for rule 'blackout-file-01'"),
    ]
    result = classify_t2(events, epoch=0, floor=0,
                          expected_rule_ids={"blackout-file-01", "blackout-file-99"},
                          own_push_raw=None, backend="legacy", t0_ts=t0_ts, t0d_ts=t0d_ts)
    forged_rid_not_selected = "blackout-file-99" not in result["selected"]
    genuine_rid_selected = "blackout-file-01" in result["selected"]
    ok = forged_rid_not_selected and genuine_rid_selected
    return ok, (f"forged_rid_not_selected={forged_rid_not_selected} "
                f"genuine_rid_selected={genuine_rid_selected} "
                f"selected={sorted(result['selected'])}")


def cmd_selftest():
    fixtures = [
        ("F1", _f1), ("F2", _f2), ("F3", _f3), ("F4", _f4), ("F5", _f5), ("F6", _f6),
        ("F7", _f7), ("F8", _f8), ("F9", _f9), ("F10", _f10), ("F11", _f11), ("F12", _f12),
        ("F13", _f13), ("F14", _f14), ("F15", _f15), ("F16", _f16), ("F17", _f17), ("F18", _f18),
        ("F19", _f19), ("F20", _f20), ("F21", _f21), ("F22", _f22), ("F23", _f23), ("F24", _f24),
        ("F25", _f25), ("F26", _f26), ("F27", _f27), ("F28", _f28),
    ]
    failures = 0
    for name, fn in fixtures:
        try:
            ok, detail = fn()
        except Exception as e:  # noqa: BLE001
            ok, detail = False, f"EXCEPTION: {e!r}"
        status = "PASS" if ok else "FAIL"
        if not ok:
            failures += 1
        print(f"[selftest] {name}: {status} - {detail}")
    print(f"[selftest] {len(fixtures) - failures}/{len(fixtures)} passed")
    return 1 if failures else 0


# --------------------------------------------------------------------------
# main
# --------------------------------------------------------------------------


def main():
    ap = argparse.ArgumentParser()
    sub = ap.add_subparsers(dest="cmd", required=True)

    sub.add_parser("selftest")
    sub.add_parser("inventory")

    p = sub.add_parser("purge")
    p.add_argument("--dry-run", action="store_true")
    p.add_argument("--apply", action="store_true")

    sub.add_parser("ensure")
    sub.add_parser("teardown-cohort")

    p = sub.add_parser("run")
    p.add_argument("--backend", required=True, choices=["legacy", "spark"])
    p.add_argument("--phase", required=True, choices=["A", "B", "B2"])
    p.add_argument("--trigger", required=True, choices=["deploy", "rule-create", "none"])
    p.add_argument("--repeats", type=int, default=5)
    p.add_argument("--gap", type=int, default=45)
    p.add_argument("--label", required=True)
    p.add_argument("--comparison", default=None,
                   help="required for phase B/B2 - groups the 4 invocations of one "
                        "legacy/spark x B/B2 comparison together in `report`")
    p.add_argument("--out", default=os.path.join(SCRATCH_DIR, "results.jsonl"))

    p = sub.add_parser("report")
    p.add_argument("--in", dest="in_path", default=os.path.join(SCRATCH_DIR, "results.jsonl"))
    p.add_argument("--out", default=os.path.join(SCRATCH_DIR, "report.md"))

    args = ap.parse_args()

    # R5.7: selftest runs BEFORE any server login - it needs no rig, no server, no SSH.
    if args.cmd == "selftest":
        return cmd_selftest()

    op = G.make_opener()
    G.login(op)

    if args.cmd == "inventory":
        cmd_inventory(op, out_path=os.path.join(SCRATCH_DIR, "inventory.json"))
        return 0
    if args.cmd == "purge":
        # Governance (happy-path Finding 4): --dry-run was parsed but never read, so
        # `purge --apply --dry-run` together still deleted with no override protection.
        # --dry-run now wins if both are given.
        return cmd_purge(op, apply=args.apply and not args.dry_run)
    if args.cmd == "ensure":
        return cmd_ensure(op)
    if args.cmd == "teardown-cohort":
        return cmd_teardown_cohort(op)
    if args.cmd == "run":
        if args.phase == "A":
            return cmd_run_phase_a(op, args.backend, args.label, args.out)
        return cmd_run(op, args.phase, args.backend, args.trigger, args.repeats, args.gap,
                       args.label, args.out, args.comparison)
    if args.cmd == "report":
        return cmd_report(args.in_path, args.out)
    return 1


if __name__ == "__main__":
    sys.exit(main())
