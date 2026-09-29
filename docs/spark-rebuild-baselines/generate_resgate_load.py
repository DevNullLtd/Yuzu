#!/usr/bin/env python3
"""Arm fixed Guardian loads against a running rig via the real REST surface.

Committed 2026-08-18 (F11, #2298; D1 ruling 2026-08-05: port-lite) - previously a
local-only spike, same posture as .uat-seed/guardian/seed-baselines.py. Companion to
resource_sampler.cpp and stage11-resource-gate-runbook.md.

Two independent load profiles, each with its own rule-id prefix so `arm`/`teardown` and
`arm-errored`/`teardown-errored` never collide and can run standalone or together:

  arm / teardown (prefix "resgate-"):
    20 registry + 20 file + 20 service guards, all Known/compliant targets - the
    ORIGINAL resource-gate load (rung-2 legacy-vs-spark A/B, still blocked on the
    flip's --spark-disable; this script is ready, the gate itself is not run here).

  arm-errored / teardown-errored (prefix "resgate-err-"):
    20 registry + 20 file guards (no service profile - see below) whose watched
    targets exist but are unreadable by the agent's service account, so every
    evaluation reads Unknown. This is the flood-measurement load for F11: it drives
    the errored-refresh (F5 6b) and priority-lane-demotion (F5 6c) paths this script's
    original profile never touches (a Known/compliant target never goes Unknown).
    No service variant: per agents/core/src/guardian_state_reader.cpp,
    ERROR_SERVICE_DOES_NOT_EXIST resolves to Known(Stopped), not Unknown - a
    nonexistent service cannot produce the errored path this profile needs, and the
    service lane shares the registry lane's 60s cadence so no coverage is lost by
    omitting it.

    This script does NOT create the deny-ACL state the errored targets need - that is
    an OS-level admin action, deliberately kept out of a script that talks to the REST
    API, not the filesystem/registry. Run the icacls/PowerShell one-liners in
    stage11-resource-gate-runbook.md FIRST, then arm-errored.

    BOTH profiles create + deploy a Baseline containing their own rules (and
    teardown deletes it). This is not optional decoration: every push -- including
    this script's own full_sync -- funnels through guardian_push_fn_'s
    filter_deployed_members() gate (server.cpp:~17601-17640), which keeps only
    rules that are members of a *deployed* Baseline (docs/guardian-baseline-model.md).
    A rule that exists in the Guard store but belongs to no deployed Baseline is
    silently dropped from every push, no error either side -- the 2026-08-18 F11
    live run hit exactly this for arm-errored (40 rules created and confirmed
    stored via REST, zero ever reached the agent's reconcile; see "Live DGRHP
    window" / forward action item 4 in f11-flood-measurement-run.md). The original
    arm/teardown profile has the identical exposure (governance Gate 4,
    consistency-auditor + happy-path, 2026-08-18) and gets the same treatment here.

    A SECOND, separate, genuinely production-scope bug (NOT fixed by this harness
    and NOT F11-scoped) shares the exact same dispatch chokepoint as this Baseline
    fix: finalize_classified_command's kill-switch gate rejects any command whose
    first classified segment isn't a lowercase-starting identifier, which "__guard__"
    never is -- so every __guard__:push_rules dispatch (including this script's own
    push_full_sync, AND any Baseline deploy's fleet-wide full_sync) is unconditionally
    kill-switched and silently dropped on an affected rig, no error surfaced. Confirmed
    from code (server.cpp's finalize_classified_command / is_valid_identifier), not
    just from the live run's symptom -- see f11-flood-measurement-run.md's "Live
    DGRHP window" section. Getting the Baseline-membership half right (this file)
    was necessary but was proven, by the shared code path, to never have been
    SUFFICIENT on its own for actual delivery until that separate bug is fixed.

All guards in both profiles are enforcement_mode="audit" + remediation.type="alert-only"
- Observe only, matching the .uat-seed/guardian/README-cis-observe.md convention
(CLAUDE.md flags dangerous-enforce paths as a single chokepoint; a resource/flood
measurement has no business anywhere near it). Resource/flood cost comes from ARMING
the watch and evaluating it, not from remediation, so audit mode is the correct posture
for this measurement, not just the safe one.

Registry guards in the original profile watch synthetic HKCU test keys (no real system
state). File guards watch synthetic files under a scratch directory this script
creates. Service guards watch real, already-present Windows services in Observe mode -
read-only status watches, nothing is started/stopped/changed.

Errored-profile registry guards watch HKLM keys (NOT HKCU - the agent runs as a service
account, and an admin-created HKCU key would be missing from the agent's own hive,
which reads as Known-absent, not Unknown; see guardian_state_reader.cpp). Errored-
profile file guards watch files under a deny-ACL directory.

Usage:
    python generate_resgate_load.py arm              # original: create+deploy 60 rules
    python generate_resgate_load.py teardown          # original: delete Baseline + 60 rules
    python generate_resgate_load.py arm-errored       # errored: create+deploy 40 rules
    python generate_resgate_load.py teardown-errored  # errored: delete Baseline + 40 rules

Config via env (matches seed-baselines.py):
    YUZU_BASE, YUZU_ADMIN_USER, YUZU_ADMIN_PASS
"""
import html
import http.cookiejar
import json
import os
import re
import sys
import urllib.error
import urllib.parse
import urllib.request

BASE = os.environ.get("YUZU_BASE", "http://localhost:8080").rstrip("/")
USER = os.environ.get("YUZU_ADMIN_USER", "admin")
PASS = os.environ.get("YUZU_ADMIN_PASS", "YuzuUatAdmin1!")

RULE_PREFIX = "resgate-"
ERR_RULE_PREFIX = "resgate-err-"
N = 20

# Fixed names so arm/arm-errored and teardown/teardown-errored can find the SAME
# Baseline across separate script invocations without persisting its id anywhere
# (BaselineStore enforces unique names, so re-running arm[-errored] without a
# teardown in between is detected as "already exists" and reused, not duplicated).
BASELINE_NAME = "resgate-baseline"
ERR_BASELINE_NAME = "resgate-err-baseline"

# Real, near-universally-present Windows services. Observe-only - never
# started/stopped/reconfigured, just watched.
SERVICE_NAMES = [
    "Spooler", "Themes", "AudioSrv", "BITS", "wuauserv", "Schedule",
    "EventLog", "PlugPlay", "Power", "ProfSvc", "Dnscache", "Dhcp",
    "LanmanServer", "LanmanWorkstation", "W32Time", "WinDefend", "wscsvc",
    "CryptSvc", "Winmgmt", "RpcSs",
][:N]


def registry_rule(i):
    rid = f"{RULE_PREFIX}reg-{i:02d}"
    return {
        "rule_id": rid,
        "name": rid,
        "enabled": True,
        "enforcement_mode": "audit",
        "severity": "low",
        "os_target": "windows",
        "scope": "",
        "spark": {
            "type": "registry-change",
            "params": {"hive": "HKCU", "key": f"SOFTWARE\\YuzuResGate\\Key{i:02d}"},
        },
        "assertion": {
            "type": "registry-value-equals",
            "params": {
                "hive": "HKCU",
                "key": f"SOFTWARE\\YuzuResGate\\Key{i:02d}",
                "value_name": "Flag",
                "value_type": "REG_DWORD",
                "expected": "1",
            },
        },
        "remediation": {"type": "alert-only", "params": {}},
    }


def file_rule(i, scratch_dir):
    rid = f"{RULE_PREFIX}file-{i:02d}"
    path = f"{scratch_dir}\\watch-{i:02d}.txt"
    return {
        "rule_id": rid,
        "name": rid,
        "enabled": True,
        "enforcement_mode": "audit",
        "severity": "low",
        "os_target": "windows",
        "scope": "",
        "spark": {"type": "file-change", "params": {"path": path}},
        "assertion": {"type": "file-exists", "params": {"path": path, "expected": "present"}},
        "remediation": {"type": "alert-only", "params": {}},
    }


def service_rule(i):
    rid = f"{RULE_PREFIX}svc-{i:02d}"
    name = SERVICE_NAMES[i - 1]
    return {
        "rule_id": rid,
        "name": rid,
        "enabled": True,
        "enforcement_mode": "audit",
        "severity": "low",
        "os_target": "windows",
        "scope": "",
        "spark": {"type": "service-status-change", "params": {"service_name": name}},
        "assertion": {"type": "service-running", "params": {"service_name": name}},
        "remediation": {"type": "alert-only", "params": {}},
    }


def registry_rule_errored(i, denied_hive_key):
    """Watches an HKLM key that EXISTS but denies read to the agent's account - reads
    Unknown (ERROR_ACCESS_DENIED), never Known-absent. Caller must have already created
    the key + deny ACE per the runbook before arming."""
    rid = f"{ERR_RULE_PREFIX}reg-{i:02d}"
    key = f"{denied_hive_key}\\Key{i:02d}"
    return {
        "rule_id": rid,
        "name": rid,
        "enabled": True,
        "enforcement_mode": "audit",
        "severity": "low",
        "os_target": "windows",
        "scope": "",
        "spark": {"type": "registry-change", "params": {"hive": "HKLM", "key": key}},
        "assertion": {
            "type": "registry-value-equals",
            "params": {
                "hive": "HKLM",
                "key": key,
                "value_name": "Flag",
                "value_type": "REG_DWORD",
                "expected": "1",
            },
        },
        "remediation": {"type": "alert-only", "params": {}},
    }


def file_rule_errored(i, denied_dir):
    """Watches a file that EXISTS but denies read to the agent's account - reads
    Unknown (EACCES/ERROR_ACCESS_DENIED), never Known-absent. Caller must have already
    created the file + deny ACE per the runbook before arming."""
    rid = f"{ERR_RULE_PREFIX}file-{i:02d}"
    path = f"{denied_dir}\\watch-{i:02d}.txt"
    return {
        "rule_id": rid,
        "name": rid,
        "enabled": True,
        "enforcement_mode": "audit",
        "severity": "low",
        "os_target": "windows",
        "scope": "",
        "spark": {"type": "file-change", "params": {"path": path}},
        "assertion": {"type": "file-exists", "params": {"path": path, "expected": "present"}},
        "remediation": {"type": "alert-only", "params": {}},
    }


def make_opener():
    cj = http.cookiejar.CookieJar()
    return urllib.request.build_opener(urllib.request.HTTPCookieProcessor(cj))


def login(op):
    data = urllib.parse.urlencode({"username": USER, "password": PASS}).encode()
    op.open(BASE + "/login", data=data, timeout=15)


def post_rule(op, rule):
    """Returns (ok, already_existed). A 409 (rest_api_v1.cpp's create_rule handler:
    duplicate rule_id/name) means a prior arm[-errored] already created this exact
    rule and this is an idempotent re-run - NOT a failure (governance Gate 4, UP-7:
    re-running arm-errored on an already-armed rig previously reported "0/40
    armed" because every 409 counted as FAIL)."""
    body = json.dumps(rule).encode("utf-8")
    req = urllib.request.Request(
        BASE + "/api/v1/guaranteed-state/rules",
        data=body,
        headers={"Content-Type": "application/json"},
    )
    try:
        op.open(req, timeout=15).read()
        return True, False
    except urllib.error.HTTPError as e:
        if e.code == 409:
            return True, True
        raise


def delete_rule(op, rule_id):
    req = urllib.request.Request(
        BASE + f"/api/v1/guaranteed-state/rules/{rule_id}",
        method="DELETE",
    )
    try:
        op.open(req, timeout=15)
        return True
    except urllib.error.HTTPError as e:
        print(f"[resgate-load] DELETE {rule_id}: HTTP {e.code}", file=sys.stderr)
        return False


def push_full_sync(op):
    req = urllib.request.Request(
        BASE + "/api/v1/guaranteed-state/push",
        data=json.dumps({"full_sync": True}).encode(),
        headers={"Content-Type": "application/json"},
    )
    op.open(req, timeout=15)


# -- Baseline plumbing (shared by both load profiles) ------------------------
#
# No JSON REST route exists for Baseline create/deploy/delete yet (dashboard
# fragment-only, form-urlencoded HTML responses) - these helpers drive the same
# form-fragment surface .uat-seed/guardian/seed-baselines.py uses for the create
# call, plus deploy/delete/lookup, which that script doesn't need.


def create_baseline_form(op, name, member_names):
    fields = [("name", name), ("description", "F11 resource-gate/flood-measurement harness baseline")]
    fields += [("guards", n) for n in member_names]
    body = urllib.parse.urlencode(fields, encoding="utf-8").encode("utf-8")
    req = urllib.request.Request(
        BASE + "/fragments/guardian/baselines",
        data=body,
        headers={"Content-Type": "application/x-www-form-urlencoded; charset=utf-8"},
    )
    return op.open(req, timeout=15).read().decode("utf-8", "replace")


def list_baselines_html(op):
    req = urllib.request.Request(BASE + "/fragments/guardian/baselines", method="GET")
    return op.open(req, timeout=15).read().decode("utf-8", "replace")


def find_baseline_id(html_text, name):
    # Matches render_baselines_fragment()'s per-card anchor:
    # <a class="baseline-name" href="/guardian/baseline/{ID}" ...>{ESCAPED NAME}</a>
    pattern = re.compile(
        r'href="/guardian/baseline/([A-Za-z0-9._\-]+)"[^>]*>' + re.escape(html.escape(name)) + r"</a>"
    )
    m = pattern.search(html_text)
    return m.group(1) if m else None


def _raise_if_baseline_action_failed(resp, action):
    """deploy_baseline and delete_baseline_action (guardian_routes.cpp) both render
    a failure ("Deploy failed: ...", "Delete failed: ...", "Baseline not found.",
    "Baseline store unavailable.") as a <div class="empty-state"> panel inside a
    gs-modal-card; success re-renders the baselines/guards fragments instead and
    never contains that marker. Governance Gate 4 (unhappy-path UP-5): this
    response was previously fetched and discarded, so a real deploy/delete failure
    printed as unconditional "success" - raise loudly instead."""
    if 'class="empty-state"' in resp:
        raise RuntimeError(f"baseline {action} failed: {resp[:300]}")


def deploy_baseline_form(op, baseline_id):
    req = urllib.request.Request(
        BASE + f"/fragments/guardian/baseline/{baseline_id}/deploy",
        data=b"",
        headers={"Content-Type": "application/x-www-form-urlencoded"},
    )
    resp = op.open(req, timeout=15).read().decode("utf-8", "replace")
    _raise_if_baseline_action_failed(resp, "deploy")
    return resp


def delete_baseline_form(op, baseline_id):
    req = urllib.request.Request(
        BASE + f"/fragments/guardian/baseline/{baseline_id}/delete",
        data=b"",
        headers={"Content-Type": "application/x-www-form-urlencoded"},
    )
    resp = op.open(req, timeout=15).read().decode("utf-8", "replace")
    _raise_if_baseline_action_failed(resp, "delete")
    return resp


def ensure_deployed_baseline(op, name, member_names):
    """Creates (or reuses, if arm[-errored] ran before without a teardown) the
    fixed-name Baseline covering the given rules, and deploys it. Without this,
    the rules exist in the Guard store but reach no agent - see the module
    docstring's guardian_push_fn_ note. Shared by both load profiles (governance
    Gate 4, consistency-auditor + happy-path, 2026-08-18: the original arm/teardown
    profile had the identical exposure the errored profile was fixed for)."""
    resp = create_baseline_form(op, name, member_names)
    if "gs-error-banner" in resp and "already exists" not in resp.lower():
        raise RuntimeError(f"baseline create failed: {resp[:300]}")
    baseline_id = find_baseline_id(resp, name)
    if not baseline_id:
        baseline_id = find_baseline_id(list_baselines_html(op), name)
    if not baseline_id:
        raise RuntimeError(f"could not find baseline id for '{name}' after create")
    deploy_baseline_form(op, baseline_id)  # deploy itself fires a fleet-wide full_sync
    return baseline_id


def teardown_deployed_baseline(op, name):
    """Deletes the named Baseline if present. delete_baseline_action fires its own
    fleet-wide full_sync when the deleted Baseline was deployed, so this is the
    actual agent-side disarm step - do it BEFORE deleting the rule definitions
    themselves."""
    baseline_id = find_baseline_id(list_baselines_html(op), name)
    if not baseline_id:
        print(f"[resgate-load] no '{name}' baseline found, nothing to remove")
        return
    delete_baseline_form(op, baseline_id)
    print(f"[resgate-load] deleted baseline '{name}' ({baseline_id}), fleet reconciled")


def all_rules(scratch_dir):
    rules = [registry_rule(i) for i in range(1, N + 1)]
    rules += [file_rule(i, scratch_dir) for i in range(1, N + 1)]
    rules += [service_rule(i) for i in range(1, N + 1)]
    return rules


def all_rules_errored(denied_dir, denied_hive_key):
    rules = [registry_rule_errored(i, denied_hive_key) for i in range(1, N + 1)]
    rules += [file_rule_errored(i, denied_dir) for i in range(1, N + 1)]
    return rules


def _post_all(op, rules):
    """Posts every rule, tolerating a 409 (already armed by a prior run) as
    success-not-failure. Returns (failed_count, reused_count)."""
    failed = 0
    reused = 0
    for rule in rules:
        try:
            _, already_existed = post_rule(op, rule)
            if already_existed:
                reused += 1
        except Exception as e:  # noqa: BLE001
            print(f"[resgate-load] FAIL {rule['rule_id']}: {e}", file=sys.stderr)
            failed += 1
    return failed, reused


def cmd_arm(op, scratch_dir):
    # Pre-create the scratch dir + the 20 watched files so the initial
    # assertion state is "present" (compliant) - quieter dashboard, and
    # ReadDirectoryChangesW needs the parent dir to exist regardless.
    os.makedirs(scratch_dir, exist_ok=True)
    for i in range(1, N + 1):
        open(os.path.join(scratch_dir, f"watch-{i:02d}.txt"), "a", encoding="utf-8").close()

    rules = all_rules(scratch_dir)
    failed, reused = _post_all(op, rules)
    push_full_sync(op)
    try:
        baseline_id = ensure_deployed_baseline(op, BASELINE_NAME, [r["name"] for r in rules])
    except Exception as e:  # noqa: BLE001
        print(f"[resgate-load] armed {3*N - failed}/{3*N} guards ({reused} reused), pushed "
              f"full_sync, but BASELINE DEPLOY FAILED: {e} - rules exist but reach NO agent "
              f"until a Baseline covering them is deployed (see the module docstring)",
              file=sys.stderr)
        return 1
    print(f"[resgate-load] armed {3*N - failed}/{3*N} guards ({reused} reused), deployed "
          f"baseline '{BASELINE_NAME}' ({baseline_id}), pushed full_sync")
    return 1 if failed else 0


def cmd_teardown(op):
    try:
        teardown_deployed_baseline(op, BASELINE_NAME)
    except Exception as e:  # noqa: BLE001
        print(f"[resgate-load] BASELINE TEARDOWN FAILED: {e} - the fleet-side disarm this "
              f"performs did not happen; rule definitions below are still being deleted",
              file=sys.stderr)
    failed = 0
    for rule in all_rules("C:\\YuzuResGate"):
        if not delete_rule(op, rule["rule_id"]):
            failed += 1
    push_full_sync(op)
    print(f"[resgate-load] deleted {3*N - failed}/{3*N} guards, pushed full_sync "
          f"(scratch dir + registry keys NOT auto-removed - clean up by hand if desired)")
    return 1 if failed else 0


def cmd_arm_errored(op, denied_dir, denied_hive_key):
    # Deliberately does NOT create denied_dir, its files, the HKLM key, or any ACE -
    # that is the runbook's job (an OS-level admin action, not a REST-surface one).
    # Arming against targets the runbook hasn't yet prepared will just read Unknown
    # for the wrong reason (missing, not denied) - verify the deny-ACL setup is done
    # (a manual read as the agent's own account should fail) before arming.
    rules = all_rules_errored(denied_dir, denied_hive_key)
    failed, reused = _post_all(op, rules)
    push_full_sync(op)
    try:
        baseline_id = ensure_deployed_baseline(op, ERR_BASELINE_NAME, [r["name"] for r in rules])
    except Exception as e:  # noqa: BLE001
        print(f"[resgate-load] armed-errored {2*N - failed}/{2*N} guards ({reused} reused), "
              f"pushed full_sync, but BASELINE DEPLOY FAILED: {e} - rules exist but reach NO "
              f"agent until a Baseline covering them is deployed (see the module docstring)",
              file=sys.stderr)
        return 1
    print(f"[resgate-load] armed-errored {2*N - failed}/{2*N} guards ({reused} reused), "
          f"deployed baseline '{ERR_BASELINE_NAME}' ({baseline_id}), pushed full_sync")
    return 1 if failed else 0


def cmd_teardown_errored(op, denied_dir, denied_hive_key):
    try:
        teardown_deployed_baseline(op, ERR_BASELINE_NAME)
    except Exception as e:  # noqa: BLE001
        print(f"[resgate-load] BASELINE TEARDOWN FAILED: {e} - the fleet-side disarm this "
              f"performs did not happen; rule definitions below are still being deleted",
              file=sys.stderr)
    failed = 0
    for rule in all_rules_errored(denied_dir, denied_hive_key):
        if not delete_rule(op, rule["rule_id"]):
            failed += 1
    push_full_sync(op)
    print(f"[resgate-load] deleted-errored {2*N - failed}/{2*N} guards, pushed full_sync "
          f"(deny-ACL dir/key NOT auto-removed - clean up by hand)")
    return 1 if failed else 0


def main():
    valid = ("arm", "teardown", "arm-errored", "teardown-errored")
    if len(sys.argv) != 2 or sys.argv[1] not in valid:
        print(__doc__)
        return 1
    scratch_dir = os.environ.get("YUZU_RESGATE_SCRATCH_DIR", "C:\\YuzuResGate")
    denied_dir = os.environ.get("YUZU_RESGATE_DENIED_DIR", "C:\\YuzuResGateDenied")
    denied_hive_key = os.environ.get(
        "YUZU_RESGATE_DENIED_HIVE_KEY", "SOFTWARE\\YuzuResGateDenied")
    op = make_opener()
    try:
        login(op)
    except Exception as e:  # noqa: BLE001
        print(f"[resgate-load] ERROR: cannot reach rig at {BASE}: {e}", file=sys.stderr)
        return 1
    if sys.argv[1] == "arm":
        return cmd_arm(op, scratch_dir)
    if sys.argv[1] == "teardown":
        return cmd_teardown(op)
    if sys.argv[1] == "arm-errored":
        return cmd_arm_errored(op, denied_dir, denied_hive_key)
    return cmd_teardown_errored(op, denied_dir, denied_hive_key)


if __name__ == "__main__":
    sys.exit(main())
