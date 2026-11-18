#!/usr/bin/env bash
# test_cla_environment.sh — lexical pin on where CLA_REPO_ACCESS_TOKEN is read.
#
# WHY THIS EXISTS. CLA_REPO_ACCESS_TOKEN is stored in the `cla` environment,
# which only the default branch may use, so a workflow on another branch
# cannot read it (docs/dependency-updates.md, "The cla environment"). This
# keeps the token's readers to the one job that needs it, cla.yml's
# cla-check, in that environment: a reader without the environment gets no
# token and the CLA check breaks, and every other job placed in the
# environment would receive the token too.
#
# WHAT IT PINS.
#   cla.yml: job cla-check declares `environment` with name `cla` and
#   `deployment: false`, and reads secrets.CLA_REPO_ACCESS_TOKEN; no other
#   part of cla.yml (another job, the workflow-level env) reads it.
#   Every other workflow or action file under .github: does not read
#   secrets.CLA_REPO_ACCESS_TOKEN (dot or bracket form), declares no job in
#   the `cla` environment, and passes no whole `secrets` context
#   (toJSON(secrets), `secrets: inherit`), which would carry the token too
#   from a job in that environment.
#
# Lexical only: the environment's settings (its branch rule, where the secret
# is stored) are owner settings the API reports; this cannot see them.
#
# Run: bash tests/shell/test_cla_environment.sh
# YUZU_CLA_ENV_TEST_ROOT points it at another tree (mutation testing).
set -uo pipefail

ROOT="${YUZU_CLA_ENV_TEST_ROOT:-$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)}"

python3 - "$ROOT" <<'PY'
import re, sys
from pathlib import Path
import yaml

root = Path(sys.argv[1])
fails = []
passes = 0
def need(cond, msg):
    global passes
    print(("  [pass] " if cond else "  [FAIL] ") + msg)
    if cond:
        passes += 1
    else:
        fails.append(msg)

SECRET = "CLA_REPO_ACCESS_TOKEN"
ENV = "cla"
JOB = "cla-check"
SECRET_READ = re.compile(r"secrets\s*(?:\.\s*" + SECRET + r"\b|\[\s*['\"]" + SECRET + r"['\"])")
WHOLE_SECRETS = re.compile(r"toJSON\s*\(\s*secrets\s*\)|secrets\s*:\s*inherit", re.I)

def dump(x):
    return yaml.safe_dump(x, width=10**6)

def env_name(job):
    e = job.get("environment") if isinstance(job, dict) else None
    return e.get("name") if isinstance(e, dict) else e

cla_path = root / ".github/workflows/cla.yml"
try:
    cla = yaml.safe_load(cla_path.read_text(encoding="utf-8")) or {}
except (OSError, yaml.YAMLError) as e:
    cla = {}
    need(False, f"cla.yml loads ({e})")
jobs = cla.get("jobs") or {}
job = jobs.get(JOB)
need(isinstance(job, dict), f"cla.yml has the job {JOB}")
job = job if isinstance(job, dict) else {}
need(env_name(job) == ENV, f"{JOB} declares environment `{ENV}`")
e = job.get("environment")
need(isinstance(e, dict) and e.get("deployment") is False,
     f"{JOB}'s environment sets `deployment: false`")
need(bool(SECRET_READ.search(dump(job))), f"{JOB} reads secrets.{SECRET}")
for jname, other in jobs.items():
    if jname == JOB:
        continue
    need(not SECRET_READ.search(dump(other)), f"cla.yml job {jname} does not read {SECRET}")
    need(env_name(other) != ENV, f"cla.yml job {jname} does not declare the {ENV} environment")
rest = {k: v for k, v in cla.items() if k != "jobs"}
need(not SECRET_READ.search(dump(rest)), f"cla.yml outside its jobs (e.g. workflow env) does not read {SECRET}")
need(not WHOLE_SECRETS.search(cla_path.read_text(encoding="utf-8", errors="ignore")),
     "cla.yml passes no whole secrets context")

others = sorted(p for p in (root / ".github").rglob("*")
                if p.is_file() and p.suffix in (".yml", ".yaml") and p != cla_path)
need(len(others) >= 20, f"the scan sees the other workflow and action files ({len(others)})")
for p in others:
    text = p.read_text(encoding="utf-8", errors="ignore")
    rel = p.relative_to(root)
    need(not SECRET_READ.search(text), f"{rel} does not read {SECRET}")
    try:
        doc = yaml.safe_load(text) or {}
    except yaml.YAMLError:
        doc = {}
    declares = [j for j, v in ((doc.get("jobs") or {}) if isinstance(doc, dict) else {}).items()
                if env_name(v) == ENV]
    need(not declares, f"{rel} declares no job in the {ENV} environment" +
         (f" (found {declares})" if declares else ""))
    m = WHOLE_SECRETS.search(text)
    need(not m, f"{rel} passes no whole secrets context" + (f" ({m.group(0)!r})" if m else ""))

print(f"test_cla_environment: {passes} passed, {len(fails)} failed")
sys.exit(1 if fails else 0)
PY
