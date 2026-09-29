#!/usr/bin/env python3
"""Frozen regression corpus for the tracker close automation (ADR-3001 A1 §11-§12).

Two surfaces, no network:

1. The parser (scripts/tracker/closing_refs.py) against a fixture corpus of
   REAL merged-PR body fragments -- including PR #1711, the canonical negated
   case ("does **not** close #1634"): the single most load-bearing line in
   this file. The grammar was acceptance-tested once against GitHub's own
   oracle (closingIssuesReferences on all 72 merged main-base PRs: zero false
   negatives; supersets limited to one chain + one already-closed ref); this
   corpus keeps it from regressing without the network.

2. The decision ladder (close_linked_issues.classify + load_do_not_close):
   never-close signals, idempotency markers, the fail-closed contract on a
   missing/broken do-not-close.txt, and the per-PR cap boundary.

Wired into tests/meson.build (suite: docs). Meson coverage is structurally
sufficient here: everything this test guards lives under scripts/, which is
code-side for the CI docs-only gate, so any PR that can break the parser also
runs the heavy platform jobs. Run locally as
`python tests/test_close_automation.py`.
"""

import pathlib
import sys
import tempfile

ROOT = pathlib.Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "scripts" / "tracker"))

import closing_refs  # noqa: E402
import close_linked_issues as cli  # noqa: E402

# --------------------------------------------------------------------------
# 1. Parser corpus: (name, body fragment, expected same-repo closing numbers)

PARSER_CORPUS = [
    # -- real bodies (verbatim fragments from merged DevNullLtd/Yuzu PRs) --------
    ("PR #1711 negated (MANDATORY negative)",
     "Hardening for the response/execution read surface (#1634, **partial** — does **not** close #1634).",
     []),
    ("PR #1711 second negation",
     "**So this does NOT bound a normal operator's responses to their management groups and does NOT close the cross-operator read #1634 describes.**",
     []),
    ("PR #795 two-ref chain", "Closes #520, #630.", [520, 630]),
    ("PR #736 keyword chain (GitHub honoured only #618)",
     "- **Auth persistence** — SQLite-backed AuthDB (fixes #618, #388, #527)",
     [618, 388, 527]),
    ("PR #373 parenthetical", "erlang ci-gateway 27 → 28 (closes #334)", [334]),
    ("PR #2074 explicit-partial (ladder protects, parser matches)",
     "Closes #2011 (lock half).", [2011]),
    ("PR #2051 resolves-by-policy (ladder protects, parser matches)",
     "Guardian Stage-2 enforce on the **queued** tier (resolves #2014 by policy)", [2014]),
    ("keyword without adjacent ref does not fire",
     "closes roadmap 8.1; #253, #587, #589", []),
    # -- grammar edges -------------------------------------------------------
    ("chain with and", "fixes #1, #2 and #3", [1, 2, 3]),
    ("colon form", "Resolves: #41", [41]),
    ("GH- form", "closed GH-77", [77]),
    ("URL form", "Fixes https://github.com/DevNullLtd/Yuzu/issues/612", [612]),
    ("same-repo qualified", "Closes DevNullLtd/Yuzu#99", [99]),
    ("pre-transfer slug still same-repo", "Closes Tr3kkR/Yuzu#98", [98]),
    ("cross-repo excluded", "Closes octo/kit#5 and fixes other/repo#6", []),
    ("newline between keyword and ref", "Closes\n#61", [61]),
    ("negation stops at contrast", "This does not fix #12, but closes #13", [13]),
    ("negation stops at sentence", "Won't fix #31. Closes #32", [32]),
    ("fenced code suppressed", "```\nCloses #55\n```", []),
    ("inline code suppressed", "run `git commit -m 'closes #56'`", []),
    ("blockquote suppressed", "> the old PR said closes #57", []),
    ("html comment suppressed", "<!-- closes #58 -->", []),
    ("relates-to never fires", "Relates to #99. Part of #98.", []),
    ("no leading zeros / no #0", "Fixed #0 and #012", []),
    ("dedupe preserves order", "Closes #5, #4, #5", [5, 4]),
    ("mismatched fence chars stay fenced", "~~~\ntext\n```\ncloses #2\n~~~", []),
    ("whitespace/& chain separators", "Closes #1 #2 & #3", [1, 2, 3]),
]


def run_parser_corpus(failures):
    for name, body, want in PARSER_CORPUS:
        got = closing_refs.closing_numbers(body)
        if got != want:
            failures.append(f"parser: {name}: want {want}, got {got}")


# --------------------------------------------------------------------------
# 2. Decision-ladder unit tests (pure, no network)

def _issue(n, state="open", labels=(), assignees=(), is_pr=False):
    d = {
        "number": n,
        "state": state,
        "title": f"issue {n}",
        "labels": [{"name": l} for l in labels],
        "assignees": [{"login": a} for a in assignees],
    }
    if is_pr:
        d["pull_request"] = {}
    return d


def run_ladder_tests(failures):
    dnc = {318, 1634}
    cases = [
        # (name, issue, pr, comments_blob, expected action)
        ("404", None, 100, "", cli.SKIP),
        ("self-ref", _issue(100), 100, "", cli.SKIP),
        ("is a PR", _issue(7, is_pr=True), 100, "", cli.SKIP),
        ("already closed", _issue(7, state="closed"), 100, "", cli.SKIP),
        ("close marker idempotent", _issue(7), 100,
         "<!-- yuzu-close-linked: pr=100 issue=7 -->", cli.SKIP),
        ("security label -> advisory", _issue(7, labels=["bug", "security"]), 100, "", cli.ADVISORY),
        ("do-not-close label -> advisory", _issue(7, labels=["do-not-close"]), 100, "", cli.ADVISORY),
        ("in dnc file -> advisory", _issue(1634), 100, "", cli.ADVISORY),
        ("advisory marker idempotent", _issue(1634), 100,
         "<!-- yuzu-close-linked-advisory: pr=100 issue=1634 -->", cli.SKIP),
        ("assigned -> advisory", _issue(7, assignees=["alice"]), 100, "", cli.ADVISORY),
        ("plain open issue -> close", _issue(7, labels=["bug", "P2"]), 100, "", cli.CLOSE),
    ]
    for name, issue, pr, blob, want in cases:
        got, _reason = cli.classify(issue, pr, dnc, blob)
        if got != want:
            failures.append(f"ladder: {name}: want {want}, got {got}")


def run_dnc_failclosed_tests(failures):
    real = cli.DNC_PATH
    try:
        with tempfile.TemporaryDirectory() as td:
            # missing file
            cli.DNC_PATH = pathlib.Path(td) / "do-not-close.txt"
            for content, label in [
                (None, "missing file"),
                ("garbage-line\n", "unparseable line"),
                ("# comments only\n", "empty set"),
                ("0318\n", "leading zero"),
            ]:
                if content is not None:
                    cli.DNC_PATH.write_text(content, encoding="utf-8")
                try:
                    cli.load_do_not_close()
                    failures.append(f"fail-closed: {label}: expected GhError, got success")
                except cli.GhError:
                    pass
                if content is None:
                    cli.DNC_PATH = pathlib.Path(td) / "do-not-close.txt"  # still missing
            # happy path
            cli.DNC_PATH.write_text("318  # live vuln\n1634 # partial\n", encoding="utf-8")
            got = cli.load_do_not_close()
            if got != {318, 1634}:
                failures.append(f"fail-closed: happy path parsed {got}")
    finally:
        cli.DNC_PATH = real


def run_cap_tests(failures):
    six = " ".join(f"closes #{n}" for n in range(1, 7))
    seven = " ".join(f"closes #{n}" for n in range(1, 8))
    if len(closing_refs.closing_numbers(six)) > cli.PER_PR_CAP:
        failures.append("cap: 6 refs must be within the cap")
    if not len(closing_refs.closing_numbers(seven)) > cli.PER_PR_CAP:
        failures.append("cap: 7 refs must exceed the cap")


# --------------------------------------------------------------------------
# 3. build_plan / assert_plan_safe / leak-scan consistency (adversarial-review
# findings K1/K2/K5, CDEX-P1-01/02/03/04 -- monkeypatched world, no network)

class _FakeWorld:
    """Monkeypatch harness: a fake tracker the driver's plumbing reads."""

    def __init__(self, issues, timelines=None, comments=None):
        self.issues = issues              # n -> issue json
        self.timelines = timelines or {}  # n -> list of timeline events
        self.comments = comments or {}    # n -> list of comment jsons
        self._saved = {}

    def __enter__(self):
        self._saved = {
            "issue_with_comments": cli.issue_with_comments,
            "has_open_linked_pr": cli.has_open_linked_pr,
            "gh_api": cli.gh_api,
            "has_write_access": cli.has_write_access,
        }
        # Marker trust is a real collaborators-API lookup in production; these
        # are network-free tests, so resolve it from the fixture's own
        # author_association instead. The fixtures still express intent as
        # OWNER/MEMBER/COLLABORATOR; only the PRODUCTION resolver changed.
        cli.has_write_access = lambda login: any(
            ((c.get("user") or {}).get("login")) == login
            and (c.get("author_association") or "") in {"OWNER", "MEMBER", "COLLABORATOR"}
            for cs in self.comments.values() for c in cs
        )
        cli.issue_with_comments = lambda n: (
            self.issues.get(n),
            cli.trusted_comment_blob(self.comments.get(n, [])),
        )
        cli.has_open_linked_pr = lambda n: any(
            "pull_request" in ((ev.get("source") or {}).get("issue") or {})
            and ((ev.get("source") or {}).get("issue") or {}).get("state") == "open"
            for ev in self.timelines.get(n, [])
        )
        cli.gh_api = self._no_network
        return self

    def __exit__(self, *exc):
        for k, v in self._saved.items():
            setattr(cli, k, v)

    @staticmethod
    def _no_network(*a, **k):
        raise AssertionError(f"unexpected network call during pure test: {a}")


def _pr(number, body):
    return {"number": number, "body": body, "merged_at": "2026-01-01T00:00:00Z",
            "merge_commit_sha": "f" * 40, "merged_by": {"login": "tester"},
            "base": {"ref": "dev"}}


def _linked_open_pr_event():
    return {"source": {"issue": {"state": "open", "pull_request": {}}}}


def _linked_closed_pr_event():
    return {"source": {"issue": {"state": "closed", "pull_request": {}}}}


def run_plan_tests(failures):
    dnc = {1634}

    # K1 regression: open-linked-PR event AFTER 300 closed events must still protect.
    world = _FakeWorld(
        issues={77: _issue(77, labels=["bug"])},
        timelines={77: [_linked_closed_pr_event()] * 300 + [_linked_open_pr_event()]},
    )
    with world:
        plan = cli.build_plan([_pr(500, "Closes #77")], dnc)
    actions = {(n, a) for _p, n, a, _r, _i in plan}
    if (77, cli.ADVISORY) not in actions:
        failures.append(f"K1: open linked PR beyond event 300 must yield ADVISORY, got {actions}")

    # CDEX-P1-01 regression: backfill mode EXCLUDES security-labelled issues
    # (no mutating action), and assert_plan_safe exits 4 if one slips through.
    world = _FakeWorld(issues={520: _issue(520, labels=["bug", "security", "P1"])})
    with world:
        plan = cli.build_plan([_pr(501, "Closes #520")], dnc, backfill=True)
    if [(a) for _p, n, a, _r, _i in plan if n == 520] != [cli.EXCLUDED]:
        failures.append(f"backfill: security-labelled issue must be EXCLUDED, got {plan}")
    forged = [( _pr(501, ""), 520, cli.ADVISORY, "forged", _issue(520, labels=["security"]))]
    try:
        cli.assert_plan_safe(forged, backfill=True)
        failures.append("backfill hard-stop: mutating action on security issue must exit 4")
    except SystemExit as e:
        if e.code != 4:
            failures.append(f"backfill hard-stop: want exit 4, got {e.code}")

    # Defense-in-depth (all modes): CLOSE on a security issue exits 4.
    forged_close = [(_pr(502, ""), 9, cli.CLOSE, "bug", _issue(9, labels=["security"]))]
    try:
        cli.assert_plan_safe(forged_close, backfill=False)
        failures.append("defense-in-depth: CLOSE on security issue must exit 4")
    except SystemExit as e:
        if e.code != 4:
            failures.append(f"defense-in-depth: want exit 4, got {e.code}")

    # K2 regression: the leak scan and the close path share build_plan, so an
    # issue protected only by an open linked PR is ADVISORY -- never a leak.
    world = _FakeWorld(
        issues={88: _issue(88, labels=["bug"])},
        timelines={88: [_linked_open_pr_event()]},
    )
    with world:
        plan = cli.build_plan([_pr(503, "Fixes #88")], dnc)
    leak_class = [n for _p, n, a, _r, _i in plan if a == cli.CLOSE]
    if leak_class:
        failures.append(f"K2: linked-PR-protected issue must not be leak/CLOSE class: {leak_class}")

    # CDEX-P1-04 regression: an untrusted commenter cannot spoof the marker...
    spoof = [{"user": {"login": "driveby"}, "author_association": "NONE",
              "body": "<!-- yuzu-close-linked: pr=504 issue=55 -->"}]
    world = _FakeWorld(issues={55: _issue(55, labels=["bug"])}, comments={55: spoof})
    with world:
        plan = cli.build_plan([_pr(504, "Closes #55")], dnc)
    if [(a) for _p, n, a, _r, _i in plan if n == 55] != [cli.CLOSE]:
        failures.append(f"marker spoof: untrusted marker must not suppress the close, got {plan}")
    # ...but the same marker from a collaborator (who could close directly) does.
    trusted = [{"user": {"login": "maintainer"}, "author_association": "COLLABORATOR",
                "body": "<!-- yuzu-close-linked: pr=504 issue=55 -->"}]
    world = _FakeWorld(issues={55: _issue(55, labels=["bug"])}, comments={55: trusted})
    with world:
        plan = cli.build_plan([_pr(504, "Closes #55")], dnc)
    if [(a) for _p, n, a, _r, _i in plan if n == 55] != [cli.SKIP]:
        failures.append(f"marker trust: collaborator marker must suppress (idempotency), got {plan}")

    # Org-transfer regression (2026-09-28, Tr3kkR/Yuzu -> DevNullLtd/Yuzu).
    # author_association reports MEMBER for ANY org member, and DevNullLtd's
    # default_repository_permission is `read`, so association is no longer a
    # proxy for push access. Trust must follow the collaborators API instead:
    # a MEMBER who cannot push must NOT be able to suppress a close.
    saved_hwa = cli.has_write_access
    member_ro = [{"user": {"login": "readonly-org-member"},
                  "author_association": "MEMBER",
                  "body": "<!-- yuzu-close-linked: pr=505 issue=56 -->"}]
    world = _FakeWorld(issues={56: _issue(56, labels=["bug"])}, comments={56: member_ro})
    with world:
        cli.has_write_access = lambda login: False   # the API says: no push
        try:
            plan = cli.build_plan([_pr(505, "Closes #56")], dnc)
        finally:
            cli.has_write_access = saved_hwa
    if [(a) for _p, n, a, _r, _i in plan if n == 56] != [cli.CLOSE]:
        failures.append(
            f"marker trust: a read-only org MEMBER must not suppress the close, got {plan}")

    # ...and the same login DOES suppress once the API grants push.
    world = _FakeWorld(issues={56: _issue(56, labels=["bug"])}, comments={56: member_ro})
    with world:
        cli.has_write_access = lambda login: login == "readonly-org-member"
        try:
            plan = cli.build_plan([_pr(505, "Closes #56")], dnc)
        finally:
            cli.has_write_access = saved_hwa
    if [(a) for _p, n, a, _r, _i in plan if n == 56] != [cli.SKIP]:
        failures.append(
            f"marker trust: push-capable author must suppress (idempotency), got {plan}")

    # Cap goes through the plan (CAPSKIP) and never reaches per-issue actions.
    world = _FakeWorld(issues={})
    with world:
        plan = cli.build_plan([_pr(505, " ".join(f"closes #{n}" for n in range(1, 8)))], dnc)
    if [a for _p, _n, a, _r, _i in plan] != [cli.CAPSKIP]:
        failures.append(f"cap: 7-ref PR must plan exactly one CAPSKIP, got {plan}")


def run_range_tests(failures):
    """merged_prs_for_range: truncation abort, zero-SHA short-circuit,
    base-branch filter, earlier-push merge-sha dedupe (quality S1)."""
    def fake_gh(path, *args, **kw):
        if path.startswith(f"repos/{cli.REPO}/compare/"):
            return fake_gh.compare
        if "/commits/" in path and path.endswith("/pulls"):
            sha = path.split("/commits/")[1].rsplit("/", 1)[0]
            return fake_gh.assoc.get(sha, [])
        raise AssertionError(f"unexpected gh path {path}")

    saved = cli.gh_api
    cli.gh_api = fake_gh
    try:
        # zero-SHA before (branch-creation push) -> no PRs, no API calls
        if cli.merged_prs_for_range("0" * 40, "b" * 40) != []:
            failures.append("range: all-zero BEFORE must return []")
        # truncation: >= 250 commits aborts
        fake_gh.compare = {"commits": [{"sha": f"{i:040x}"} for i in range(250)]}
        fake_gh.assoc = {}
        try:
            cli.merged_prs_for_range("a" * 40, "b" * 40)
            failures.append("range: 250-commit compare must raise GhError")
        except cli.GhError:
            pass
        # filtering: wrong base / unmerged / merge-sha outside range all drop
        s1, s2 = "1" * 40, "2" * 40
        fake_gh.compare = {"commits": [{"sha": s1}, {"sha": s2}]}
        fake_gh.assoc = {
            s1: [
                {"number": 1, "merged_at": "x", "base": {"ref": "dev"}, "merge_commit_sha": s1},
                {"number": 2, "merged_at": "x", "base": {"ref": "main"}, "merge_commit_sha": s1},
                {"number": 3, "merged_at": None, "base": {"ref": "dev"}, "merge_commit_sha": s1},
            ],
            s2: [
                {"number": 4, "merged_at": "x", "base": {"ref": "dev"}, "merge_commit_sha": "9" * 40},
            ],
        }
        got = [p["number"] for p in cli.merged_prs_for_range("a" * 40, "b" * 40)]
        if got != [1]:
            failures.append(f"range: filters must keep only PR 1, got {got}")
    finally:
        cli.gh_api = saved


def run_undo_tests(failures):
    """mode_undo_push reopens ONLY automation-closed (trusted-marker) issues
    (quality S2). Dry-run path, no mutations."""
    import contextlib
    import io

    marker = "<!-- yuzu-close-linked: pr=600 issue=70 -->"
    trusted = [{"user": {"login": "github-actions[bot]"}, "author_association": "NONE",
                "body": marker}]
    spoofed = [{"user": {"login": "driveby"}, "author_association": "NONE",
                "body": "<!-- yuzu-close-linked: pr=600 issue=71 -->"}]
    world = _FakeWorld(
        issues={70: _issue(70, state="closed"), 71: _issue(71, state="closed"),
                72: _issue(72, state="open")},
        comments={70: trusted, 71: spoofed,
                  72: [{"user": {"login": "github-actions[bot]"}, "author_association": "NONE",
                        "body": "<!-- yuzu-close-linked: pr=600 issue=72 -->"}]},
    )
    saved = cli.merged_prs_for_range
    cli.merged_prs_for_range = lambda b, a: [_pr(600, "Closes #70, #71, #72")]
    try:
        with world:
            out = io.StringIO()
            with contextlib.redirect_stdout(out):
                # bypass load_do_not_close (network-free): point at a temp file
                real_dnc = cli.DNC_PATH
                with tempfile.TemporaryDirectory() as td:
                    cli.DNC_PATH = pathlib.Path(td) / "do-not-close.txt"
                    cli.DNC_PATH.write_text("1\n", encoding="utf-8")
                    try:
                        cli.mode_undo_push("a" * 40, "b" * 40, execute=False)
                    finally:
                        cli.DNC_PATH = real_dnc
            text = out.getvalue()
        if "would reopen #70" not in text:
            failures.append(f"undo: trusted-marker closed issue must reopen; got: {text!r}")
        if "would reopen #71" in text:
            failures.append("undo: spoofed marker must NOT reopen")
        if "would reopen #72" in text:
            failures.append("undo: open issue must not reopen")
    finally:
        cli.merged_prs_for_range = saved


def run_snapshot_and_misc_tests(failures):
    """Backfill plan-snapshot identity (UP-6a), capskip title/search coupling,
    approval-url shape rejection (no network for bad shapes)."""
    plan_a = [(_pr(1, ""), 5, cli.CLOSE, "r", _issue(5)),
              (_pr(1, ""), 6, cli.SKIP, "r", _issue(6))]
    plan_b = [(_pr(1, ""), 5, cli.ADVISORY, "r", _issue(5))]
    snap_a, snap_b = cli.plan_snapshot(plan_a), cli.plan_snapshot(plan_b)
    if snap_a == snap_b:
        failures.append("snapshot: differing plans must differ")
    if snap_a != cli.plan_snapshot(list(plan_a)):
        failures.append("snapshot: identical plans must match")
    if any(row[2] == cli.SKIP for row in snap_a):
        failures.append("snapshot: SKIP rows must not be part of the reviewed identity")

    key = cli.CAPSKIP_TITLE_KEY.format(pr=123)
    if key not in cli.capskip_title(123, 7):
        failures.append("capskip: search key must be a substring of the generated title")

    for bad in ("", "https://github.com/DevNullLtd/Yuzu/issues/2139",
                "https://github.com/DevNullLtd/Yuzu/issues/2139#issuecomment-notanumber"):
        if cli.verify_approval_url(bad):
            failures.append(f"approval-url: {bad!r} must be rejected")


def main() -> int:
    failures = []
    run_parser_corpus(failures)
    run_ladder_tests(failures)
    run_dnc_failclosed_tests(failures)
    run_cap_tests(failures)
    run_plan_tests(failures)
    run_range_tests(failures)
    run_undo_tests(failures)
    run_snapshot_and_misc_tests(failures)
    if failures:
        print(f"close-automation checks FAILED ({len(failures)}):")
        for f in failures:
            print(f"  - {f}")
        return 1
    print(
        f"close-automation checks OK "
        f"({len(PARSER_CORPUS)} parser cases, 11 ladder cases, fail-closed + cap, "
        f"plan/hard-stop/leak-consistency/marker-trust)"
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
