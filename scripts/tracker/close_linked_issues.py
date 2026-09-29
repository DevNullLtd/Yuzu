#!/usr/bin/env python3
"""close_linked_issues.py -- close issues that merged dev PRs claim (ADR-3001 A1 par.3-5).

The one driver behind every mode of the close automation. All modes share
closing_refs.py (the single parser) and ONE planning path (build_plan), so the
leak scan can never disagree with the close path it audits.

Modes (default is ALWAYS --dry-run; nothing mutates without --execute):

  --push BEFORE AFTER     workflow mode: close what the PRs merged by this
                          push range claim. Used by close-linked-issues.yml.
  --backfill              one-time #2139 backfill: sweep ALL merged dev PRs,
                          list still-open claimed issues. The dry run writes a
                          plan snapshot (--plan FILE); --execute additionally
                          requires --yes-i-reviewed, the SAME --plan FILE (the
                          run aborts, exit 4, if the live plan drifted from the
                          reviewed snapshot -- PR bodies are editable
                          post-merge, so the diff the maintainer approved is
                          the diff that executes), and --approval-url (the
                          #2139 comment recording per-issue approval; verified
                          to exist with a trusted author, and embedded in
                          every backfill evidence comment). In backfill mode,
                          `security`-labelled candidates are EXCLUDED
                          (printed, never mutated -- not even an advisory):
                          the maintainer reviews them in the diff instead.
  --undo-push BEFORE AFTER  recompute the closure set for an exact prior push
                          range and reopen what THIS automation closed there
                          (verified by its own idempotency marker).
  --leak-scan             completeness backstop: refs in recently-merged PR
                          bodies that would be CLOSED by the ladder right now
                          -- i.e. an earlier run failed. Non-empty => exit 1
                          (the workflow's alert job fires). Shares build_plan,
                          so protected/advisory items are never "leaks".

Decision ladder, order load-bearing (issue-standard.md 5.1; A1 par.4-5):
  cap (>6 refs on one PR => close NOTHING for that PR, plan a cap-skip issue)
  -> 404 -> self-ref -> not-an-issue(PR) -> not-open -> already-marked
  (idempotent, TRUSTED comments only) -> `security` label => ADVISORY (push) /
  EXCLUDED (backfill) -> `do-not-close` label or scripts/tracker/
  do-not-close.txt => ADVISORY -> assigned => ADVISORY -> open linked PR (full
  timeline, no truncation) => ADVISORY -> CLOSE as completed (the state change
  lands FIRST, then the evidence comment, then `fixed-on-dev`, label tolerated
  missing -- comment-first would plant the idempotency marker on a still-open
  issue if the close PATCH failed, blinding every liveness mechanism at once).

Marker idempotency trusts only comments whose author is github-actions[bot]
or whose author_association is OWNER/MEMBER/COLLABORATOR -- a drive-by
commenter cannot suppress the automation by pasting a marker (anyone who CAN
plant a trusted marker already has write access and could close directly).

FAIL-CLOSED invariants:
  - scripts/tracker/do-not-close.txt missing or unparseable => the run refuses
    to close ANYTHING (exit 3). A deleted never-close list must never mean
    "nothing is protected". (Also makes this PR safe to merge before/after the
    PR that introduces the file.)
  - planning NEVER mutates: build_plan is read-only; every mutation (closes,
    advisories, cap-skip issues) happens in apply_plan, strictly AFTER the
    security assertions below have passed.
  - backfill hard-stop (A1 par.4): if any `security`-labelled issue holds a
    mutating action in the backfill plan, exit 4 with zero mutations.
  - defense-in-depth (all modes): a CLOSE action still carrying the
    `security` label after the ladder aborts the run, zero mutations, exit 4.
  - compare API truncation (250-commit cap): an over-long push range aborts
    loudly (the alert job fires) instead of silently skipping merged PRs.

GitHub access goes through the `gh` CLI (repo convention -- never raw curl),
authenticated by GH_TOKEN in CI or ambient `gh auth` locally. Mutations are
throttled (MUTATION_SLEEP_S) to stay clear of secondary rate limits.

Stdlib only. Run as `python` on Windows dev boxes (python3 is the Store stub).
"""

from __future__ import annotations

import argparse
import json
import os
import pathlib
import subprocess
import sys
import time

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
import closing_refs  # noqa: E402  (the single parser -- see module docstring)

REPO = "DevNullLtd/Yuzu"
TARGET_BRANCH = "dev"
PER_PR_CAP = 6  # A1 par.5: observed max on 360 merged dev PRs is 6; >6 is anomalous
MUTATION_SLEEP_S = 2
LEAK_SCAN_WINDOW = 50
COMPARE_COMMIT_CAP = 250  # GitHub compare API hard cap; beyond it commits are silently dropped
DNC_PATH = pathlib.Path(__file__).resolve().parent / "do-not-close.txt"

CLOSE_MARKER = "yuzu-close-linked: pr={pr} issue={issue}"
ADVISORY_MARKER = "yuzu-close-linked-advisory: pr={pr} issue={issue}"
CAPSKIP_MARKER = "yuzu-close-linked-capskip: pr={pr}"
UNDO_MARKER = "yuzu-close-linked-undo: pr={pr} issue={issue}"

# CONTRIBUTOR is deliberately excluded (any merged-commit author gets it).
# Note: on a user-owned repo COLLABORATOR implies explicit write access; if
# the repo ever moves to an org with read/triage collaborator roles, revisit.
TRUSTED_ASSOCIATIONS = {"OWNER", "MEMBER", "COLLABORATOR"}
TRUSTED_BOT = "github-actions[bot]"

# Plan actions
CLOSE, ADVISORY, SKIP, EXCLUDED, CAPSKIP = "CLOSE", "ADVISORY", "SKIP", "EXCLUDED", "CAPSKIP"
MUTATING_ACTIONS = {CLOSE, ADVISORY, CAPSKIP}


class GhError(RuntimeError):
    pass


def gh_api(path: str, *args: str, method: str = "GET", paginate: bool = False):
    """Call `gh api` and return parsed JSON (None for 404 on GET)."""
    cmd = ["gh", "api", path, "--method", method]
    if paginate:
        cmd += ["--paginate", "--slurp"]
    cmd += list(args)
    proc = subprocess.run(cmd, capture_output=True, text=True, encoding="utf-8")
    if proc.returncode != 0:
        if method == "GET" and ("HTTP 404" in proc.stderr or "Not Found" in proc.stderr):
            return None
        raise GhError(f"gh api {path} failed (exit {proc.returncode}): {proc.stderr.strip()[:400]}")
    if not proc.stdout.strip():
        return {}
    data = json.loads(proc.stdout)
    if paginate and isinstance(data, list) and data and isinstance(data[0], list):
        data = [item for page in data for item in page]  # --slurp wraps pages
    return data


def load_do_not_close() -> set:
    """Parse the committed never-close list. Any problem => GhError (fail closed)."""
    if not DNC_PATH.exists():
        raise GhError(
            f"{DNC_PATH} is MISSING -- refusing to close anything (fail-closed; "
            f"the never-close list is a load-bearing input, see issue-standard.md 5.1)"
        )
    numbers = set()
    for lineno, line in enumerate(DNC_PATH.read_text(encoding="utf-8").splitlines(), 1):
        body = line.split("#", 1)[0].strip()
        if not body:
            continue
        if not (body.isascii() and body.isdigit() and not (len(body) > 1 and body[0] == "0")):
            raise GhError(f"do-not-close.txt:{lineno}: unparseable entry {body!r} -- fail-closed")
        numbers.add(int(body))
    if not numbers:
        raise GhError("do-not-close.txt parsed EMPTY -- fail-closed")
    return numbers


# ---------------------------------------------------------------------------
# Pure classification (unit-tested without network)

def trusted_comment_blob(comments: list) -> str:
    """Concatenate only comments whose author can be trusted for marker
    idempotency: the Actions bot, or an OWNER/MEMBER/COLLABORATOR. Anyone able
    to plant a trusted marker has write access and could close issues
    directly -- so spoofing buys an attacker nothing."""
    trusted = []
    for c in comments:
        login = ((c.get("user") or {}).get("login")) or ""
        assoc = c.get("author_association") or ""
        if login == TRUSTED_BOT or assoc in TRUSTED_ASSOCIATIONS:
            trusted.append(c.get("body") or "")
    return "\n".join(trusted)


def classify(issue: dict, pr_number: int, dnc: set, comments_blob: str) -> tuple:
    """Return (action, reason) for one referenced issue -- the network-free
    part of the ladder. The open-linked-PR signal needs the timeline API, so
    build_plan layers it on top of a CLOSE result."""
    n = None if issue is None else issue.get("number")
    if issue is None:
        return SKIP, "not found (404)"
    if n == pr_number:
        return SKIP, "self-reference"
    if "pull_request" in issue:
        return SKIP, "reference is a PR, not an issue"
    if issue.get("state") != "open":
        return SKIP, "already closed"
    if CLOSE_MARKER.format(pr=pr_number, issue=n) in comments_blob:
        return SKIP, "already closed by this automation for this PR (marker)"
    labels = {l["name"] for l in issue.get("labels", [])}
    advisory_done = ADVISORY_MARKER.format(pr=pr_number, issue=n) in comments_blob
    if "security" in labels:
        return (SKIP if advisory_done else ADVISORY), "`security` label -- never closed by automation"
    if "do-not-close" in labels:
        return (SKIP if advisory_done else ADVISORY), "`do-not-close` label -- never closed by automation"
    if n in dnc:
        return (SKIP if advisory_done else ADVISORY), "listed in scripts/tracker/do-not-close.txt"
    if issue.get("assignees"):
        return (SKIP if advisory_done else ADVISORY), "assigned -- a human owns this issue"
    return CLOSE, "claimed by merged PR"


def has_security_label(issue: dict) -> bool:
    return any(l["name"] == "security" for l in (issue or {}).get("labels", []))


# ---------------------------------------------------------------------------
# GitHub plumbing

def has_open_linked_pr(issue_number: int) -> bool:
    """Timeline check: any OPEN PR cross-references this issue. Scans EVERY
    paginated event -- no truncation: the events are chronological, so any
    prefix cap would discard exactly the newest cross-references."""
    events = gh_api(
        f"repos/{REPO}/issues/{issue_number}/timeline",
        "-f", "per_page=100",
        paginate=True,
    ) or []
    for ev in events:
        src = (ev.get("source") or {}).get("issue") or {}
        if "pull_request" in src and src.get("state") == "open":
            return True
    return False


def run_context() -> str:
    server = os.environ.get("GITHUB_SERVER_URL")
    repo = os.environ.get("GITHUB_REPOSITORY")
    run_id = os.environ.get("GITHUB_RUN_ID")
    if server and repo and run_id:
        return f"[workflow run]({server}/{repo}/actions/runs/{run_id})"
    who = os.environ.get("USERNAME") or os.environ.get("USER") or "operator"
    return f"local run by `{who}`"


def merged_prs_for_range(before: str, after: str) -> list:
    """PRs merged into TARGET_BRANCH whose merge/squash commit is inside the
    pushed range, resolved via the compare API + commit-PR association.
    Fails loudly on compare truncation rather than silently skipping PRs."""
    if set(before) == {"0"}:  # branch-creation push: no meaningful range
        return []
    cmp_data = gh_api(f"repos/{REPO}/compare/{before}...{after}")
    if cmp_data is None:
        raise GhError(f"compare {before}...{after} not found")
    commits = cmp_data.get("commits", [])
    if len(commits) >= COMPARE_COMMIT_CAP:
        raise GhError(
            f"push range {before[:10]}..{after[:10]} returned {len(commits)} commits -- at the "
            f"compare API's {COMPARE_COMMIT_CAP}-commit cap, so merged PRs may be missing. "
            f"Refusing to run a possibly-partial close pass; split the range at intermediate "
            f"SHAs and re-run --push per sub-range."
        )
    shas = [c["sha"] for c in commits]
    prs, seen = [], set()
    for sha in shas:
        assoc = gh_api(f"repos/{REPO}/commits/{sha}/pulls") or []
        for pr in assoc:
            num = pr["number"]
            if num in seen:
                continue
            seen.add(num)
            if not pr.get("merged_at"):
                continue
            if pr.get("base", {}).get("ref") != TARGET_BRANCH:
                continue
            if pr.get("merge_commit_sha") not in shas:
                continue  # associated but merged by an earlier push
            prs.append(pr)
    return prs


def all_merged_dev_prs(max_pages: int = 0) -> list:
    """Every merged dev-base PR, most recently MERGED first (the pulls API
    sorts by creation; a long-lived PR merged yesterday must not escape a
    recency window). max_pages > 0 bounds the fetch for windowed callers
    (the per-push leak scan must not paginate the repo's whole PR history);
    0 = unbounded (the backfill needs everything)."""
    if max_pages > 0:
        prs = []
        for page in range(1, max_pages + 1):
            batch = gh_api(
                f"repos/{REPO}/pulls",
                "-f", "state=closed", "-f", f"base={TARGET_BRANCH}",
                "-f", "per_page=100", "-f", f"page={page}",
            ) or []
            prs.extend(batch)
            if len(batch) < 100:
                break
    else:
        prs = gh_api(
            f"repos/{REPO}/pulls",
            "-f", "state=closed", "-f", f"base={TARGET_BRANCH}", "-f", "per_page=100",
            paginate=True,
        ) or []
    merged = [p for p in prs if p.get("merged_at")]
    merged.sort(key=lambda p: p["merged_at"], reverse=True)
    return merged


def issue_with_comments(n: int) -> tuple:
    """Returns (issue_json_or_None, trusted_comment_blob)."""
    issue = gh_api(f"repos/{REPO}/issues/{n}")
    if issue is None:
        return None, ""
    comments = gh_api(f"repos/{REPO}/issues/{n}/comments", "-f", "per_page=100", paginate=True) or []
    return issue, trusted_comment_blob(comments)


def post_comment(n: int, body: str, execute: bool):
    if not execute:
        return
    gh_api(f"repos/{REPO}/issues/{n}/comments", "-f", f"body={body}", method="POST")
    time.sleep(MUTATION_SLEEP_S)


def close_issue(n: int, execute: bool):
    if not execute:
        return
    gh_api(f"repos/{REPO}/issues/{n}", "-f", "state=closed", "-f", "state_reason=completed", method="PATCH")
    time.sleep(MUTATION_SLEEP_S)


def add_label(n: int, label: str, execute: bool):
    """Tolerates a missing label (A1: an early merge cannot fail a close)."""
    if not execute:
        return
    try:
        gh_api(f"repos/{REPO}/issues/{n}/labels", "-f", f"labels[]={label}", method="POST")
        time.sleep(MUTATION_SLEEP_S)
    except GhError as e:
        print(f"  note: could not add label {label!r} to #{n} ({e}); continuing", file=sys.stderr)


_full_pr_cache: dict = {}


def merged_by_login(pr: dict) -> str:
    """The list endpoints (compare-associated PRs, pulls?state=closed) return
    pull-request-simple objects that OMIT merged_by entirely -- naming the
    authorizing human requires one lazy GET of the full PR per CLOSE-carrying
    PR (verified live: both list sources lack the field)."""
    if pr.get("merged_by"):
        return pr["merged_by"].get("login") or "unknown"
    num = pr["number"]
    if num not in _full_pr_cache:
        _full_pr_cache[num] = gh_api(f"repos/{REPO}/pulls/{num}") or {}
    return ((_full_pr_cache[num].get("merged_by") or {}).get("login")) or "unknown"


def evidence_comment(pr: dict, issue_n: int, approval_url: str = "") -> str:
    merger = merged_by_login(pr)
    sha = (pr.get("merge_commit_sha") or "")[:10]
    approval = (
        f"Backfill authorized per-issue by the maintainer: {approval_url}\n\n" if approval_url else ""
    )
    return (
        f"Closed automatically by `close-linked-issues` ({run_context()}): "
        f"PR #{pr['number']} (merge `{sha}`, merged into `{TARGET_BRANCH}` by @{merger}) "
        f"declares it closes this issue.\n\n"
        f"Performed by automation; the authorizing human is the PR's merger. "
        f"{approval}"
        f"Wrong close? Reopen and add the `do-not-close` label -- automation "
        f"never touches it again (docs/agents/issue-standard.md 5.1).\n\n"
        f"<!-- {CLOSE_MARKER.format(pr=pr['number'], issue=issue_n)} -->"
    )


def advisory_comment(pr: dict, issue_n: int, reason: str) -> str:
    return (
        f"Merged PR #{pr['number']} claims to close this issue, but it is "
        f"protected from automated closure ({reason}). A human must verify the "
        f"fix against current `origin/{TARGET_BRANCH}` before closing "
        f"(docs/agents/issue-standard.md 5.1).\n\n"
        f"<!-- {ADVISORY_MARKER.format(pr=pr['number'], issue=issue_n)} -->"
    )


CAPSKIP_TITLE_KEY = "cap-skip on PR #{pr}"  # search phrase MUST be a substring of the title


def capskip_title(pr_number: int, ref_count: int) -> str:
    return f"close-linked-issues: {CAPSKIP_TITLE_KEY.format(pr=pr_number)} ({ref_count} closing refs)"


def create_capskip_issue(pr: dict, refs: list):
    key = CAPSKIP_TITLE_KEY.format(pr=pr["number"])
    existing = gh_api(
        "search/issues",
        "-f", f"q=repo:{REPO} is:issue is:open in:title \"{key}\"",
    ) or {}
    if existing.get("total_count", 0) > 0:
        print(f"  cap-skip issue already open for PR #{pr['number']}")
        return
    body = (
        f"PR #{pr['number']} resolves {len(refs)} issues ({', '.join(f'#{n}' for n in refs)}), "
        f"over the per-PR sanity cap of {PER_PR_CAP} (ADR-3001 A1 par.5). The automation closed "
        f"NOTHING for this PR; a human should review and close the genuine ones by hand.\n\n"
        f"Run: {run_context()}\n\n<!-- {CAPSKIP_MARKER.format(pr=pr['number'])} -->"
    )
    # The POST returns the created issue -- label it directly rather than
    # re-searching (the search index lags by seconds-to-minutes, which
    # silently dropped the labels).
    created = gh_api(
        f"repos/{REPO}/issues",
        "-f", f"title={capskip_title(pr['number'], len(refs))}", "-f", f"body={body}",
        method="POST",
    ) or {}
    time.sleep(MUTATION_SLEEP_S)
    if created.get("number"):
        for lbl in ("needs-triage", "P2"):
            add_label(created["number"], lbl, True)


# ---------------------------------------------------------------------------
# Planning (READ-ONLY) and applying (the only mutating phase)

def build_plan(prs: list, dnc: set, backfill: bool = False) -> list:
    """The ONE planning path shared by push, backfill, and leak-scan modes.
    Read-only by contract: no mutation happens here, so the security
    assertions in assert_plan_safe() always run before anything changes.
    Returns a list of (pr, issue_n_or_None, action, reason, issue_json)."""
    plan = []
    for pr in prs:
        refs = closing_refs.closing_numbers(pr.get("body") or "")
        if not refs:
            continue
        if len(refs) > PER_PR_CAP:
            plan.append((pr, None, CAPSKIP, f"{len(refs)} refs > cap {PER_PR_CAP}", {"refs": refs}))
            continue
        for n in refs:
            issue, blob = issue_with_comments(n)
            action, reason = classify(issue, pr["number"], dnc, blob)
            if action == CLOSE and has_open_linked_pr(n):
                if ADVISORY_MARKER.format(pr=pr["number"], issue=n) in blob:
                    action, reason = SKIP, "an open PR still references this issue (advisory already posted)"
                else:
                    action, reason = ADVISORY, "an open PR still references this issue"
            if backfill and action in (CLOSE, ADVISORY) and has_security_label(issue):
                # Backfill never mutates a security-labelled issue, not even an
                # advisory: the maintainer reviews these in the dry-run diff.
                action = EXCLUDED
            plan.append((pr, n, action, reason, issue))
    return plan


def assert_plan_safe(plan: list, backfill: bool):
    """Runs BEFORE any mutation, every mode. Exit 4 = zero mutations happened."""
    for pr, n, action, reason, issue in plan:
        if action == CLOSE and has_security_label(issue):
            print(f"FATAL: ladder bug -- CLOSE action for security-labelled #{n}. "
                  f"Aborting with zero mutations.", file=sys.stderr)
            sys.exit(4)
        if backfill and action in MUTATING_ACTIONS and n is not None and has_security_label(issue):
            print(f"FATAL: backfill hard-stop (A1 par.4) -- security-labelled #{n} holds a "
                  f"mutating action ({action}). Aborting with zero mutations.", file=sys.stderr)
            sys.exit(4)


def print_plan(plan: list):
    def sort_key(item):
        pr, n, action, reason, issue = item
        labels = {l["name"] for l in (issue or {}).get("labels", [])} if n else set()
        danger = ("security" in labels, "P0" in labels, "P1" in labels,
                  bool((issue or {}).get("assignees")) if n else False)
        return (-sum(danger), action not in (EXCLUDED, ADVISORY), n or 0)

    for pr, n, action, reason, issue in sorted(plan, key=sort_key):
        if action == CAPSKIP:
            print(f"  {action:8} PR #{pr['number']} -- {reason}: closes nothing, files a cap-skip issue")
            continue
        labels = ",".join(l["name"] for l in (issue or {}).get("labels", [])) if issue else "-"
        title = (issue or {}).get("title", "?")[:60]
        print(f"  {action:8} #{n:<5} (PR #{pr['number']}) [{labels}] {title!r} -- {reason}")


def apply_plan(plan: list, execute: bool, approval_url: str = ""):
    """The ONLY mutating phase. Callers must have run assert_plan_safe first.

    Order within a CLOSE is load-bearing: the STATE CHANGE lands first, the
    evidence comment (which carries the idempotency marker) second. The
    reverse would plant the marker on a still-open issue whenever the close
    PATCH failed mid-batch -- and a marked-but-open issue is invisible to the
    re-run, the leak scan, AND the alert's green follow-up simultaneously.
    A closed-but-uncommented issue (comment failed after close) is the benign
    orphan: the per-mutation progress lines below tell the operator exactly
    which comment to post by hand."""
    closed = advised = capskips = 0
    for pr, n, action, reason, issue in plan:
        if action == CLOSE:
            close_issue(n, execute)
            if execute:
                print(f"  closed #{n} (PR #{pr['number']})", flush=True)
            post_comment(n, evidence_comment(pr, n, approval_url), execute)
            if execute:
                print(f"  evidence comment posted on #{n}", flush=True)
            add_label(n, "fixed-on-dev", execute)
            closed += 1
        elif action == ADVISORY:
            post_comment(n, advisory_comment(pr, n, reason), execute)
            if execute:
                print(f"  advisory posted on #{n} (PR #{pr['number']})", flush=True)
            advised += 1
        elif action == CAPSKIP:
            if execute:
                create_capskip_issue(pr, issue["refs"])
                print(f"  cap-skip issue filed for PR #{pr['number']}", flush=True)
            else:
                print(f"  [dry-run] would open cap-skip issue for PR #{pr['number']}")
            capskips += 1
    mode = "EXECUTED" if execute else "DRY-RUN (nothing mutated)"
    skips = sum(1 for p in plan if p[2] == SKIP)
    excluded = sum(1 for p in plan if p[2] == EXCLUDED)
    print(f"{mode}: {closed} close(s), {advised} advisory comment(s), {capskips} cap-skip(s), "
          f"{skips} skip(s), {excluded} excluded (security, backfill)")


def plan_snapshot(plan: list) -> list:
    """The reviewable identity of a plan: sorted (pr, issue, action) triples.
    PR bodies are editable post-merge, so --backfill --execute refuses to run
    against anything but the exact snapshot the maintainer reviewed."""
    return sorted(
        [pr["number"], n if n is not None else 0, action]
        for pr, n, action, _r, _i in plan
        if action != SKIP
    )


def verify_approval_url(url: str) -> bool:
    """The --approval-url must be a comment on the tracking issue (#2139) by a
    trusted author -- converting --yes-i-reviewed from attestation into a
    reference to a durable record (A1 par.4)."""
    if "#issuecomment-" not in url:
        return False
    comment_id = url.rsplit("#issuecomment-", 1)[1].strip("/")
    if not comment_id.isdigit():
        return False
    c = gh_api(f"repos/{REPO}/issues/comments/{comment_id}")
    if not c:
        return False
    login = ((c.get("user") or {}).get("login")) or ""
    assoc = c.get("author_association") or ""
    on_2139 = (c.get("issue_url") or "").endswith("/issues/2139")
    return on_2139 and (login == TRUSTED_BOT or assoc in TRUSTED_ASSOCIATIONS)


# ---------------------------------------------------------------------------
# Modes

def mode_push(before: str, after: str, execute: bool) -> int:
    dnc = load_do_not_close()
    prs = merged_prs_for_range(before, after)
    if not prs:
        print(f"no merged {TARGET_BRANCH}-base PRs in {before[:10]}..{after[:10]}")
        return 0
    print(f"{len(prs)} merged PR(s) in range: {', '.join('#' + str(p['number']) for p in prs)}")
    plan = build_plan(prs, dnc)
    assert_plan_safe(plan, backfill=False)
    print_plan(plan)
    apply_plan(plan, execute)
    return 0


def mode_backfill(execute: bool, reviewed: bool, plan_file: str, approval_url: str) -> int:
    dnc = load_do_not_close()
    if execute:
        if not reviewed:
            print("--backfill --execute requires --yes-i-reviewed: the dry-run diff is "
                  "reviewed per-issue by the maintainer on #2139 first (A1 par.4).")
            return 2
        if not plan_file or not pathlib.Path(plan_file).exists():
            print("--backfill --execute requires --plan FILE (the snapshot the dry run wrote "
                  "and the maintainer reviewed) -- PR bodies are editable post-merge, so "
                  "execution is pinned to the reviewed diff, not to a live re-parse.")
            return 2
        if not approval_url or not verify_approval_url(approval_url):
            print("--backfill --execute requires --approval-url pointing at the maintainer's "
                  "per-issue approval comment on #2139 (a trusted-author comment; verified "
                  "via the API). This converts the flag into a reference to a durable record.")
            return 2
    prs = all_merged_dev_prs()
    print(f"scanning {len(prs)} merged {TARGET_BRANCH}-base PRs...")
    plan = build_plan(prs, dnc, backfill=True)
    assert_plan_safe(plan, backfill=True)
    live = [p for p in plan if p[2] != SKIP]
    print(f"\nbackfill plan ({len(live)} item(s)), most dangerous first "
          f"(EXCLUDED = security-labelled, reviewed here, never mutated):")
    print_plan(live)
    snapshot = plan_snapshot(plan)
    if execute:
        reviewed_snapshot = json.loads(pathlib.Path(plan_file).read_text(encoding="utf-8"))
        if reviewed_snapshot != snapshot:
            print("FATAL: the live plan DIFFERS from the reviewed snapshot -- a PR body or "
                  "issue state changed since the dry run (post-merge body edits are the "
                  "known attack shape). Zero mutations. Re-run the dry run, re-review, "
                  "re-execute.", file=sys.stderr)
            sys.exit(4)
    elif plan_file:
        pathlib.Path(plan_file).write_text(json.dumps(snapshot, indent=1), encoding="utf-8")
        print(f"plan snapshot written to {plan_file} (pass the same file to --execute)")
    apply_plan(plan, execute, approval_url=approval_url or "")
    return 0


def mode_undo_push(before: str, after: str, execute: bool) -> int:
    load_do_not_close()  # fail-closed applies to undo too
    prs = merged_prs_for_range(before, after)
    undone = 0
    for pr in prs:
        for n in closing_refs.closing_numbers(pr.get("body") or ""):
            issue, blob = issue_with_comments(n)
            if issue is None:
                continue
            marker = CLOSE_MARKER.format(pr=pr["number"], issue=n)
            if marker not in blob:
                print(f"  #{n}: no trusted close marker for PR #{pr['number']} -- not ours, skipping")
                continue
            if issue.get("state") == "open":
                print(f"  #{n}: already open -- skipping")
                continue
            if execute:
                gh_api(f"repos/{REPO}/issues/{n}", "-f", "state=open", method="PATCH")
                time.sleep(MUTATION_SLEEP_S)
                post_comment(n, f"Reopened by `close-linked-issues --undo-push` for PR #{pr['number']} "
                                f"({run_context()}).\n\n"
                                f"<!-- {UNDO_MARKER.format(pr=pr['number'], issue=n)} -->", execute)
                add_label(n, "needs-triage", execute)
                try:
                    gh_api(f"repos/{REPO}/issues/{n}/labels/fixed-on-dev", method="DELETE")
                except GhError:
                    pass
            print(f"  {'reopened' if execute else '[dry-run] would reopen'} #{n} (PR #{pr['number']})")
            undone += 1
    print(f"undo: {undone} issue(s) {'reopened' if execute else 'would reopen'}")
    return 0


def mode_leak_scan(window: int) -> int:
    """Exit 1 if the ladder would CLOSE anything right now over the recent
    window -- i.e. an earlier run failed. Uses build_plan, the same path as
    the close job, so a protected/advisory item can never be a false leak."""
    dnc = load_do_not_close()
    # 3 pages of 100 comfortably covers any 50-PR merge window without
    # paginating the repo's entire PR history on every push.
    prs = all_merged_dev_prs(max_pages=max(3, (window * 2) // 100 + 1))[:window]
    plan = build_plan(prs, dnc)
    leaks = [(pr, n) for pr, n, action, _r, _i in plan if action == CLOSE]
    if leaks:
        print(f"LEAK: {len(leaks)} claimed-but-open issue(s) the ladder would close now:")
        for pr, n in leaks:
            edited = ""
            if (pr.get("updated_at") or "") > (pr.get("merged_at") or ""):
                edited = (" [PR updated after merge -- bodies are editable post-merge; "
                          "check the edit history before closing #%d by hand]" % n)
            print(f"  #{n} (claimed by merged PR #{pr['number']}){edited}")
        return 1
    print(f"leak scan clean over the {len(prs)} most recently merged PRs")
    return 0


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    mode = ap.add_mutually_exclusive_group(required=True)
    mode.add_argument("--push", nargs=2, metavar=("BEFORE", "AFTER"))
    mode.add_argument("--backfill", action="store_true")
    mode.add_argument("--undo-push", nargs=2, metavar=("BEFORE", "AFTER"))
    mode.add_argument("--leak-scan", action="store_true")
    ap.add_argument("--execute", action="store_true", help="mutate (default: dry-run)")
    ap.add_argument("--yes-i-reviewed", action="store_true",
                    help="backfill only: confirm the dry-run diff was reviewed per-issue")
    ap.add_argument("--plan", default="",
                    help="backfill: dry-run writes the plan snapshot here; --execute requires "
                         "the same file and aborts on drift")
    ap.add_argument("--approval-url", default="",
                    help="backfill --execute: URL of the maintainer's approval comment on #2139")
    ap.add_argument("--window", type=int, default=LEAK_SCAN_WINDOW)
    args = ap.parse_args(argv)

    try:
        if args.push:
            return mode_push(args.push[0], args.push[1], args.execute)
        if args.backfill:
            return mode_backfill(args.execute, args.yes_i_reviewed, args.plan, args.approval_url)
        if args.undo_push:
            return mode_undo_push(args.undo_push[0], args.undo_push[1], args.execute)
        if args.leak_scan:
            return mode_leak_scan(args.window)
    except GhError as e:
        print(f"ERROR: {e}", file=sys.stderr)
        return 3
    return 0


if __name__ == "__main__":
    sys.exit(main())
