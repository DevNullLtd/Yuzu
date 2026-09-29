#!/usr/bin/env python3
"""Repo-hygiene checks for the issue-lifecycle standard (ADR-3001, Amendment A1)
and the instruction-file standard (docs/instruction-file-standard.md).

Invariants that must hold on every platform:

1. The six ALWAYS-LOADED instruction files -- CLAUDE.md, AGENTS.md, and the
   four routed-concern tables CLAUDE.md @-imports -- each stay under a 40,000
   character budget, behind the 48,000 hard cap. Counted UTF-8-decoded in
   Python deliberately: these files are dense with multi-byte punctuation, so
   byte counts (`wc -c`, and `wc -m` on Windows Git Bash, which degrades to
   bytes) read ~300 higher than the character count -- the exact confusion
   Amendment A1 par.8 corrects.

   The budget sits below the cap so the next approach is caught with runway.
   Previously only CLAUDE.md was measured, and the ceiling was hit three times;
   the second breach was found at 39,996 of 40,000 bytes, and the unmeasured
   routed-concern tables had independently reached 38,545 and 37,808 while
   AGENTS.md sat 25% over a cap nothing applied to it.

   Also enforced on those six files:
     - EXPIRES: markers -- a temporary section whose date has passed fails the
       build. A workstreams block outlived its stated window by four weeks,
       with its own teardown procedure already written, because nothing checked.
     - Dead pointers -- a backticked repo path that resolves nowhere fails.
       Three citations pointed into a private memory directory and resolved
       nowhere, not even on the author's own machine. Deliberate absences go in
       ABSENT_BY_DESIGN with a reason.

2. scripts/tracker/do-not-close.txt parses -- integers only (one per line,
   '#' comments allowed), no duplicates, never empty. Every automated close
   path reads this file; a malformed line silently shrinking the never-close
   set is exactly the failure a green build must catch.

3. docs/agents/issue-standard.md exists and still contains its never-close
   section (5.1), which do-not-close.txt and the automation cite as their
   authority.

Wired into tests/meson.build (suite: docs), mirroring test_changelog_order.py.
"""

import pathlib
import re
import subprocess
import sys

ROOT = pathlib.Path(__file__).resolve().parent.parent

CLAUDE_MD_CHAR_CAP = 48_000

# Budget sits below the hard cap so the next approach is caught with runway to
# plan an extraction, not at the wall. Both prior breaches were discovered with
# nothing left to give -- the second at 39,996 of 40,000 bytes -- and both were
# resolved by splitting, which is now exhausted. See
# docs/instruction-file-standard.md.
#
# 2026-09-14: raised 32,000 -> 40,000 (Alex: "we keep needing to do this") --
# .claude/routed-concerns.md was already at 31,929/32,000 chars with new rows
# owed from Wave 7b and Wave 8 plugin work, each breach costing a scramble PR.
# The hard cap moved 40,000 -> 48,000 in the same change specifically so this
# budget keeps the same 8,000-char runway it always had, rather than becoming
# the wall itself.
INSTRUCTION_FILE_BUDGET = 40_000

# Every file here loads into an agent session before any work starts: CLAUDE.md
# and AGENTS.md directly, the four routed-concern tables via CLAUDE.md's
# @-imports. Only CLAUDE.md was measured before; the routed-concern tables had
# reached 38,545 and 37,808 unmeasured, and AGENTS.md 49,859 -- already 25% over
# the cap nothing was applying to it.
# The four routed-concern tables, checked for column structure as well as size.
# A cell containing an unescaped "|" silently shifts every column to its right,
# which is how a CATASTROPHIC row's "Loaded by" agent list was once overwritten
# by a copy of its own "Doc" column -- leaving a credential-revocation surface
# with no review trigger, while the table still looked well-formed.
ROUTED_CONCERN_FILES = (
    ".claude/routed-concerns.md",
    ".claude/routed-concerns-access-control.md",
    ".claude/routed-concerns-security-posture.md",
    ".claude/routed-concerns-software-estate.md",
)

INSTRUCTION_FILES = (
    "CLAUDE.md",
    "AGENTS.md",
    ".claude/routed-concerns.md",
    ".claude/routed-concerns-access-control.md",
    ".claude/routed-concerns-security-posture.md",
    ".claude/routed-concerns-software-estate.md",
)

# <!-- EXPIRES: YYYY-MM-DD owner:@who -->
EXPIRES_RE = re.compile(r"EXPIRES:\s*(\d{4})-(\d{2})-(\d{2})")

# Backticked paths that look like repo paths: contain a '/' or a known suffix,
# no spaces, no glob/placeholder metacharacters.
BACKTICK_PATH_RE = re.compile(r"`([A-Za-z0-9_./-]+\.(?:md|hpp|cpp|py|sh|json|yml|yaml|ini|h|txt))`")

# Paths that are deliberately absent from the repo. Each needs a reason: an
# entry here is an assertion that the citation is correct and the file's
# absence is intended, not that the check is inconvenient.
ABSENT_BY_DESIGN = {
    # Commercially sensitive; kept local-only and untracked on purpose. The
    # routed-concern row citing it already tells the reader to ask the operator.
    "docs/dex-brd-coverage.md",
}

# ASCII digits only, no leading zero: `isdigit()` alone accepts Arabic-Indic
# numerals a grep/bash consumer would miss, and `0318` would int() to 318 while
# a string-comparing consumer looks for "318" — both are silent-shrink bugs.
ISSUE_NUMBER_RE = re.compile(r"0|[1-9][0-9]*")


_BASENAMES: set[str] = set()


def _tracked_basenames() -> set[str]:
    """Basenames of every tracked file, for resolving bare-filename citations."""
    if not _BASENAMES:
        out = subprocess.run(
            ["git", "-C", str(ROOT), "ls-files"],
            capture_output=True, text=True, check=True,
        ).stdout
        _BASENAMES.update(pathlib.PurePosixPath(p).name for p in out.splitlines())
    return _BASENAMES


def main() -> int:
    failures = []

    # 1. Always-loaded instruction files: budget, expiry, dead pointers
    import datetime

    today = datetime.date.today()
    sizes = {}
    for rel in INSTRUCTION_FILES:
        path = ROOT / rel
        if not path.exists():
            failures.append(f"{rel} is missing")
            continue
        text = path.read_text(encoding="utf-8")
        n = len(text)
        sizes[rel] = n

        if n >= CLAUDE_MD_CHAR_CAP:
            failures.append(
                f"{rel} is {n} characters -- at/over the {CLAUDE_MD_CHAR_CAP} "
                f"hard cap. Route detail to docs/ and keep only invariants + "
                f"pointers (docs/instruction-file-standard.md). If this PR did "
                f"not touch {rel}, dev is already over cap -- land a trim PR "
                f"first; this failure is not your change's fault."
            )
        elif n >= INSTRUCTION_FILE_BUDGET:
            failures.append(
                f"{rel} is {n} characters -- over the {INSTRUCTION_FILE_BUDGET} "
                f"budget (hard cap {CLAUDE_MD_CHAR_CAP}). This file loads into "
                f"every agent session. Extract to a docs/ file and leave a "
                f"pointer; see docs/instruction-file-standard.md for the "
                f"placement ladder."
            )

        # Expiry markers. A temporary section must say when it dies, and the
        # date must be enforced -- a workstreams block outlived its own stated
        # window by four weeks, with its teardown procedure already written,
        # because nothing checked.
        for match in EXPIRES_RE.finditer(text):
            y, m, d = (int(g) for g in match.groups())
            try:
                expiry = datetime.date(y, m, d)
            except ValueError:
                failures.append(f"{rel}: unparseable EXPIRES date {y}-{m:02d}-{d:02d}")
                continue
            if expiry < today:
                failures.append(
                    f"{rel}: a section expired on {expiry} and is still present. "
                    f"Remove it, or move its expiry out deliberately."
                )

        # Dead pointers. A committed instruction file must not cite a path no
        # collaborator can open -- three citations pointed at a private memory
        # directory and resolved nowhere, not even on the author's machine.
        for match in BACKTICK_PATH_RE.finditer(text):
            cited = match.group(1)
            if cited.startswith(("http", "//")) or cited in ABSENT_BY_DESIGN:
                continue
            if "/" in cited:
                # Path-shaped: must resolve exactly.
                if not (ROOT / cited).exists():
                    failures.append(
                        f"{rel} cites `{cited}`, which does not exist in the repo."
                    )
            else:
                # A bare filename is still a pointer -- `STREAM.md` named a file
                # that existed nowhere, and read as authoritative for months. It
                # cannot be resolved to one location, so require only that some
                # tracked file carries that name; a citation matching nothing is
                # dead by any reading.
                if cited not in _tracked_basenames():
                    failures.append(
                        f"{rel} cites `{cited}`, and no file with that name "
                        f"exists in the repo."
                    )

    # 1b. Routed-concern tables: column structure
    #
    # test_issue_docs.py cannot judge whether a row routes to the RIGHT agents,
    # but it can prove every row still has three distinct, populated columns.
    for rel in ROUTED_CONCERN_FILES:
        path = ROOT / rel
        if not path.exists():
            continue
        for lineno, line in enumerate(
            path.read_text(encoding="utf-8").splitlines(), start=1
        ):
            if not line.startswith("|"):
                continue
            if set(line.strip()) <= {"|", "-", " ", ":"}:
                continue  # header separator
            cells = line.split("|")
            if len(cells) != 5:
                failures.append(
                    f"{rel}:{lineno}: routed-concern row has {len(cells) - 2} "
                    f"columns, expected 3. A literal '|' inside a cell must be "
                    f"escaped as '\\|' -- an unescaped one shifts every column "
                    f"to its right and silently corrupts the row."
                )
                continue
            concern, doc, loaded_by = (c.strip() for c in cells[1:4])
            if concern.lower().startswith("concern"):
                continue  # header row
            for name, value in (
                ("Concern", concern), ("Doc", doc), ("Loaded by", loaded_by)
            ):
                if not value:
                    failures.append(
                        f"{rel}:{lineno}: routed-concern row has an empty "
                        f"'{name}' column."
                    )
            if doc and doc == loaded_by:
                failures.append(
                    f"{rel}:{lineno}: routed-concern row's 'Loaded by' column is "
                    f"a verbatim copy of its 'Doc' column -- the row names no "
                    f"review trigger. Standing rule 1: the matrix decides WHICH "
                    f"agents, never WHETHER."
                )

    # 1c. Every routed-concern table is @-imported by CLAUDE.md (so it loads into every session) and
    # named in AGENTS.md (the only loader on the Codex/Kimi leg). A dropped or mistyped line would
    # silently unload a table while every other gate stayed green.
    claude_lines = (ROOT / "CLAUDE.md").read_text(encoding="utf-8").splitlines()
    agents_text = (ROOT / "AGENTS.md").read_text(encoding="utf-8")
    for rel in ROUTED_CONCERN_FILES:
        if f"@{rel}" not in claude_lines:
            failures.append(f"CLAUDE.md does not @-import {rel}: that table would not load into any session.")
        if f"`{rel}`" not in agents_text:
            failures.append(f"AGENTS.md does not name {rel}: the Codex/Kimi leg would never open it.")

    # 2. do-not-close.txt parses clean
    dnc_path = ROOT / "scripts" / "tracker" / "do-not-close.txt"
    if not dnc_path.exists():
        failures.append(f"{dnc_path.relative_to(ROOT)} is missing")
    else:
        numbers = []
        for lineno, line in enumerate(
            dnc_path.read_text(encoding="utf-8").splitlines(), start=1
        ):
            body, _, comment = line.partition("#")
            body = body.strip()
            if not body:
                # A comment-only line whose text is purely a number is the
                # `#318` typo class: the entry the author meant to protect
                # silently became a comment. Prose comments never trip this.
                if comment.strip().isdigit():
                    failures.append(
                        f"do-not-close.txt:{lineno}: comment-only line is a bare "
                        f"number ({comment.strip()!r}) -- probably a '#'-prefixed "
                        f"entry typo; the issue is NOT protected as written"
                    )
                continue
            if not ISSUE_NUMBER_RE.fullmatch(body):
                failures.append(
                    f"do-not-close.txt:{lineno}: not a bare ASCII issue number "
                    f"(no leading zeros): {body!r}"
                )
            else:
                numbers.append(int(body))
        if not numbers:
            failures.append(
                "do-not-close.txt parses to an EMPTY set -- the never-close "
                "guard would be inert. Restore the entries from git history "
                "(git show origin/dev:scripts/tracker/do-not-close.txt)."
            )
        dupes = {n for n in numbers if numbers.count(n) > 1}
        if dupes:
            failures.append(f"do-not-close.txt: duplicate numbers: {sorted(dupes)}")

    # 3. the standard exists and keeps its never-close section
    std_path = ROOT / "docs" / "agents" / "issue-standard.md"
    if not std_path.exists():
        failures.append("docs/agents/issue-standard.md is missing")
    else:
        std = std_path.read_text(encoding="utf-8")
        if "What automation must never close" not in std:
            failures.append(
                "issue-standard.md no longer contains the 'What automation must "
                "never close' section that do-not-close.txt and the close "
                "automation cite as their authority"
            )

    if failures:
        print("issue-docs checks FAILED:")
        for f in failures:
            print(f"  - {f}")
        return 1

    summary = ", ".join(
        f"{rel} {n}/{INSTRUCTION_FILE_BUDGET}" for rel, n in sizes.items()
    )
    print(f"issue-docs checks OK ({summary})")
    return 0


if __name__ == "__main__":
    sys.exit(main())
