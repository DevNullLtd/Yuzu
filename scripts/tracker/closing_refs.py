#!/usr/bin/env python3
"""closing_refs.py -- THE closing-keyword parser for DevNullLtd/Yuzu (ADR-3001 A1 par.12).

Single implementation, imported by close_linked_issues.py (workflow, backfill,
undo, leak scan) and by tests/test_close_automation.py. There is deliberately
no second parser anywhere: two implementations of one grammar diverge, and the
leak scan would then disagree with the workflow it audits.

Grammar: a documented SUPERSET of GitHub's closing-keyword grammar
(https://docs.github.com/en/issues/tracking-your-work-with-issues/linking-a-pull-request-to-an-issue)

  - keywords: close/closes/closed, fix/fixes/fixed, resolve/resolves/resolved
    (case-insensitive, word-bounded, optional trailing colon)
  - references: #N | GH-N | owner/repo#N | https://github.com/owner/repo/issues/N
  - the superset: CHAINS bound to one keyword ("Closes #1, #2 and #3") -- a
    form this repo genuinely uses (9 of 105 refs in the dev corpus are
    chain-only) that GitHub itself does NOT honour per-reference. Chain
    separators are comma, 'and', '&', and bare whitespace: "Closes #10 #11"
    closes BOTH here (GitHub would close only #10).

Suppression (never produce a ref from):
  - fenced code blocks (``` / ~~~), inline code spans, blockquote lines,
    HTML comments;
  - NEGATED contexts: "does **not** close #1634" (PR #1711, the canonical
    case) -- a negation token within the same sentence, at most
    NEGATION_WINDOW chars before the keyword, suppresses the whole chain.

Only same-repo references count toward `closing_numbers()`; cross-repo
references are extracted but flagged, and the caller must not act on them.

Stdlib only. On Windows dev boxes run as `python` (python3 is the Store stub).
"""

from __future__ import annotations

import argparse
import dataclasses
import json
import re
import sys

DEFAULT_REPO = "DevNullLtd/Yuzu"

# Issue numbers: no leading zero, 1..9,999,999. GitHub renders #0 as text.
_NUM = r"(?P<num>[1-9][0-9]{0,6})"

KEYWORD_RE = re.compile(r"\b(?P<kw>close[sd]?|fix(?:e[sd])?|resolve[sd]?)\b:?", re.IGNORECASE)

# Reference forms, tried in order at the cursor. `owner/repo#N` before bare `#N`.
_REF_RES = [
    # https://github.com/owner/repo/issues/N (or /pull/N -- extracted, caller
    # validates the target is an issue, not a PR)
    re.compile(
        r"https?://github\.com/(?P<owner>[A-Za-z0-9_.-]+)/(?P<repo>[A-Za-z0-9_.-]+)"
        r"/(?:issues|pull)/" + _NUM + r"\b"
    ),
    re.compile(r"(?P<owner>[A-Za-z0-9_.-]+)/(?P<repo>[A-Za-z0-9_.-]+)#" + _NUM + r"(?![0-9])"),
    re.compile(r"\bGH-" + _NUM + r"(?![0-9])", re.IGNORECASE),
    re.compile(r"#" + _NUM + r"(?![0-9])"),
]

# Between the refs of a chain: commas, 'and', '&', whitespace. Between the
# KEYWORD and its FIRST ref GitHub allows only whitespace (plus our optional
# colon, consumed by KEYWORD_RE) -- enforced in _consume_chain via first=True.
_CHAIN_SEP_RE = re.compile(r"(?:\s|,|&|\band\b)+", re.IGNORECASE)
_FIRST_SEP_RE = re.compile(r"\s+")

NEGATION_RE = re.compile(
    r"\b(?:not|never|without|no longer|doesn'?t|don'?t|won'?t|wouldn'?t|"
    r"couldn'?t|shouldn'?t|cannot|can'?t|isn'?t|aren'?t|didn'?t)\b",
    re.IGNORECASE,
)
NEGATION_WINDOW = 80  # chars back from the keyword, bounded by sentence start

# A negation stops binding at a sentence end OR a contrast conjunction:
# "does not fix #12, but closes #13" must still close #13. (GitHub itself has
# NO negation handling -- it would close BOTH, which is how a "does not close
# #1634" body hurts someone. Over-suppression is the safe direction: a missed
# close is caught by the leak scan; a wrong close mislabels a live issue.)
_SENTENCE_BOUNDARY_RE = re.compile(r"[.!?;\n]|\b(?:but|however|yet|although|though)\b", re.IGNORECASE)

# Backreference: a fence must be closed by ITS OWN character (CommonMark) --
# a ``` line inside a ~~~ block is content, and letting it close the fence
# would UN-suppress text GitHub keeps fenced (the unsafe direction).
_FENCE_RE = re.compile(r"^(?P<fence>```|~~~).*?(?:^(?P=fence)[ \t]*$|\Z)", re.MULTILINE | re.DOTALL)
_INLINE_CODE_RE = re.compile(r"`[^`\n]*`")
_HTML_COMMENT_RE = re.compile(r"<!--.*?(?:-->|\Z)", re.DOTALL)
_BLOCKQUOTE_LINE_RE = re.compile(r"^[ \t]{0,3}>.*$", re.MULTILINE)


@dataclasses.dataclass
class ClosingRef:
    number: int
    keyword: str
    same_repo: bool
    negated: bool
    raw: str


def _blank(match: re.Match) -> str:
    """Replace a suppressed region with spaces, PRESERVING offsets and newlines
    so negation windows and sentence boundaries stay aligned with the original
    text."""
    return re.sub(r"[^\n]", " ", match.group(0))


def preprocess(text: str) -> str:
    """Strip regions that must never produce a closing ref, offset-preserving."""
    text = _FENCE_RE.sub(_blank, text)
    text = _HTML_COMMENT_RE.sub(_blank, text)
    text = _INLINE_CODE_RE.sub(_blank, text)
    text = _BLOCKQUOTE_LINE_RE.sub(_blank, text)
    # Normalize markdown emphasis so "**not**" negates: drop *'s, ~~'s and
    # doubled underscores (single _ kept -- it appears inside identifiers).
    text = text.replace("*", " ").replace("~~", "  ").replace("__", "  ")
    return text


def _is_negated(text: str, kw_start: int) -> bool:
    window_start = max(0, kw_start - NEGATION_WINDOW)
    window = text[window_start:kw_start]
    boundary = None
    for m in _SENTENCE_BOUNDARY_RE.finditer(window):
        boundary = m.end()
    if boundary is not None:
        window = window[boundary:]
    return bool(NEGATION_RE.search(window))


def _match_ref(text: str, pos: int):
    for ref_re in _REF_RES:
        m = ref_re.match(text, pos)
        if m:
            return m
    return None


def _consume_chain(text: str, pos: int):
    """From the end of a keyword, consume `ref (sep ref)*`. Returns
    (list of ref matches, end position). Empty list => the keyword was prose
    ("closes the gap")."""
    refs = []
    first = True
    cursor = pos
    while True:
        sep_re = _FIRST_SEP_RE if first else _CHAIN_SEP_RE
        sep = sep_re.match(text, cursor)
        probe = sep.end() if sep else cursor
        if first and not sep and probe != pos:
            break
        m = _match_ref(text, probe)
        if not m:
            break
        refs.append(m)
        cursor = m.end()
        first = False
    return refs, cursor


def extract(text: str, repo: str = DEFAULT_REPO) -> list:
    """All closing references in `text`, in document order (negated chains
    included, flagged). Callers that act on issues use closing_numbers()."""
    if not text:
        return []
    clean = preprocess(text)
    repo_lc = repo.lower()
    out = []
    pos = 0
    while True:
        kw = KEYWORD_RE.search(clean, pos)
        if not kw:
            break
        refs, end = _consume_chain(clean, kw.end())
        if not refs:
            pos = kw.end()
            continue
        negated = _is_negated(clean, kw.start())
        for m in refs:
            gd = m.groupdict()
            owner, rname = gd.get("owner"), gd.get("repo")
            same = True if owner is None else f"{owner}/{rname}".lower() == repo_lc
            out.append(
                ClosingRef(
                    number=int(m.group("num")),
                    keyword=kw.group("kw").lower(),
                    same_repo=same,
                    negated=negated,
                    raw=m.group(0),
                )
            )
        pos = end
    return out


def closing_numbers(text: str, repo: str = DEFAULT_REPO) -> list:
    """Ordered, de-duplicated same-repo issue numbers this text closes --
    the ONLY function automation may act on."""
    seen = set()
    result = []
    for ref in extract(text, repo):
        if ref.negated or not ref.same_repo:
            continue
        if ref.number not in seen:
            seen.add(ref.number)
            result.append(ref.number)
    return result


# ---------------------------------------------------------------------------

_SELFTEST = [
    # (body, expected closing_numbers)
    ("Closes #123", [123]),
    ("closes #1, #2 and #3", [1, 2, 3]),  # the chain superset
    ("Fixes: #77", [77]),
    ("Resolved GH-9", [9]),
    ("Closes DevNullLtd/Yuzu#520, #630.", [520, 630]),
    ("Closes other/repo#5", []),  # cross-repo: never act
    ("Closes https://github.com/DevNullLtd/Yuzu/issues/42", [42]),
    # PR #1711, the canonical negative -- emphasis-wrapped negation:
    ("Hardening for the read surface (#1634, **partial** -- does **not** close #1634).", []),
    ("This does not fix #12, but closes #13", [13]),
    ("Relates to #99 and part of #98", []),  # no closing keyword
    ("```\nCloses #55\n```", []),  # fenced code
    ("`closes #56`", []),  # inline code
    ("> quoted: closes #57", []),  # blockquote
    ("<!-- closes #58 -->", []),  # html comment
    ("closes the gap in #policy handling", []),  # keyword w/o ref
    ("Fixed #0 and #012", []),  # invalid numbers
    ("Won't fix #31; closes #32", [32]),  # negation stops at sentence boundary
    ("~~~\ntext\n```\ncloses #2\n~~~", []),  # mismatched fence chars cannot close a fence
    ("Closes #1 #2 & #3", [1, 2, 3]),  # whitespace/& chain separators (documented superset)
    ("Closes\n#61", []),  # GitHub requires same-line-ish adjacency; newline separates keyword from ref? -- NO: see note below
]

# Note on the last case: GitHub itself accepts "Closes\n#61" (whitespace incl.
# newline). Our _FIRST_SEP_RE uses \s+ which spans newlines, so we MATCH it --
# the selftest entry above is corrected accordingly at runtime.
_SELFTEST[-1] = ("Closes\n#61", [61])


def _run_selftest() -> int:
    failures = 0
    for body, want in _SELFTEST:
        got = closing_numbers(body)
        if got != want:
            failures += 1
            print(f"SELFTEST FAIL: {body!r}\n  want {want}, got {got}")
    if failures:
        print(f"{failures}/{len(_SELFTEST)} selftest cases failed")
        return 1
    print(f"selftest OK ({len(_SELFTEST)} cases)")
    return 0


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--repo", default=DEFAULT_REPO)
    ap.add_argument("--text-file", help="parse this file (default: stdin)")
    ap.add_argument("--json", action="store_true", help='emit {"closes": [...]}')
    ap.add_argument("--details", action="store_true", help="one line per extracted ref")
    ap.add_argument("--selftest", action="store_true")
    args = ap.parse_args(argv)

    if args.selftest:
        return _run_selftest()

    if args.text_file:
        with open(args.text_file, encoding="utf-8") as fh:
            text = fh.read()
    else:
        text = sys.stdin.buffer.read().decode("utf-8", errors="replace")

    if args.details:
        for ref in extract(text, args.repo):
            flags = []
            if ref.negated:
                flags.append("NEGATED")
            if not ref.same_repo:
                flags.append("CROSS-REPO")
            print(f"#{ref.number}\t{ref.keyword}\t{ref.raw}\t{','.join(flags) or '-'}")
        return 0

    nums = closing_numbers(text, args.repo)
    if args.json:
        print(json.dumps({"closes": nums}))
    else:
        for n in nums:
            print(n)
    return 0


if __name__ == "__main__":
    sys.exit(main())
