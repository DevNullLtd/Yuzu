#!/usr/bin/env python3
"""Anchor `docs/user-manual/rbac.md`'s tables to their C++ seed arrays (#480).

`rbac.md` enumerates the RBAC model four times over — system roles, securable
types, operations, and the authorization-topology floor — and every one of those
tables is a hand-maintained copy of an array in C++ source. Nothing checked that
the copy still matched, so it stopped matching: by the time PR #4776 audited it,
the doc claimed 6 roles against 7 seeded, 23 securable types against 38, and a
five-row topology floor against ten, with the word "five" repeated in three
places of surrounding prose. Each drift arrived one PR at a time, and every one
of those PRs was reviewed.

This test makes that class of drift a red CI leg instead of an archaeology
exercise. It asserts SET EQUALITY, not just counts, so the failure message names
the securable that was added without a doc row rather than reporting `38 != 39`.

## Sources of truth

    server/core/src/rbac_store.cpp          seed_defaults(): types[], ops[], roles[]
    server/core/src/authz_topology_floor.hpp kTopologyFloor[]

## What this does NOT cover

The **per-role permission totals** — `Administrator` 193, `ITServiceOwner` 93,
`Viewer` 24 — are not checked. They are products of `seed_defaults()`'s grant
loops, and reproducing those loops in Python would mean maintaining a second
implementation of the seed whose own drift nothing would catch. That is a worse
trade than the gap. The totals remain hand-verified; see #480 for the discussion.

This is stated here rather than left implicit because a partial gate that reads
as a total one is how the next stale number ships: a reader who sees this file
pass must not conclude that every figure in `rbac.md` is anchored.

## Vacuity

Every extraction below fails LOUD when it finds nothing. A regex that silently
matches zero rows after someone reformats a table would turn this file into a
test that passes by asserting nothing — the exact false-green shape
`docs/testing/unit-test-conventions.md` warns about. Both the C++ parsers and
the Markdown parsers therefore assert a non-empty result before comparing, and
the C++ parsers additionally cross-check the element count they extracted
against the array's own declared size.

Run: python3 -m pytest tests/test_rbac_doc_counts.py
     or plain `python3 tests/test_rbac_doc_counts.py` with no pytest installed.
"""

import pathlib
import re
import sys

ROOT = pathlib.Path(__file__).resolve().parents[1]
RBAC_MD = ROOT / "docs" / "user-manual" / "rbac.md"
RBAC_STORE = ROOT / "server" / "core" / "src" / "rbac_store.cpp"
FLOOR_HPP = ROOT / "server" / "core" / "src" / "authz_topology_floor.hpp"


def _read(path):
    assert path.is_file(), f"source of truth missing: {path.relative_to(ROOT)}"
    return path.read_text(encoding="utf-8")


# --------------------------------------------------------------------------
# C++ side
# --------------------------------------------------------------------------

def _string_array(src, decl_re, label):
    """Extract a `std::array<std::string_view, N> name = {...}` initialiser.

    Returns the list of string literals. The declared N is cross-checked against
    the number of literals recovered, so a parser that silently drops elements
    (a comment shape it does not handle, a line continuation) fails here rather
    than producing a short list that then disagrees with the doc for the wrong
    reason — which would send the reader to the doc instead of to this parser.
    """
    m = re.search(decl_re, src)
    assert m, (
        f"could not find the {label} declaration in rbac_store.cpp. The "
        f"declaration was reshaped and this parser was not updated: fix the "
        f"pattern, do not delete the assertion."
    )
    declared = int(m.group("n"))
    body = _balanced_braces(src, src.index("{", m.end() - 1))
    items = re.findall(r'"([^"]+)"', _strip_comments(body))
    assert items, f"{label}: initialiser parsed but yielded no entries"
    assert len(items) == declared, (
        f"{label}: declared std::array size {declared} but this parser recovered "
        f"{len(items)} entries ({items}). The parser is wrong, not the doc."
    )
    return items


def _balanced_braces(src, open_idx):
    """Return the text between `src[open_idx]` == '{' and its matching '}'."""
    assert src[open_idx] == "{", "internal: _balanced_braces given a non-brace"
    depth = 0
    for i in range(open_idx, len(src)):
        if src[i] == "{":
            depth += 1
        elif src[i] == "}":
            depth -= 1
            if depth == 0:
                return src[open_idx + 1:i]
    raise AssertionError("unbalanced braces while parsing an initialiser")


def _strip_comments(text):
    text = re.sub(r"/\*.*?\*/", "", text, flags=re.S)
    return re.sub(r"//[^\n]*", "", text)


def seeded_securables():
    return _string_array(
        _read(RBAC_STORE),
        r"std::array<std::string_view,\s*(?P<n>\d+)>\s+types\s*=",
        "types[]",
    )


def seeded_operations():
    return _string_array(
        _read(RBAC_STORE),
        r"std::array<std::string_view,\s*(?P<n>\d+)>\s+ops\s*=",
        "ops[]",
    )


def seeded_roles():
    """Extract `std::array<RoleSeed, N> roles` — names only, not descriptions.

    `RoleSeed` rows are `{"Name", "Description"}` pairs, so unlike the two
    string_view arrays the literal count is 2N. That difference is why this does
    not reuse `_string_array`.
    """
    src = _read(RBAC_STORE)
    m = re.search(r"std::array<RoleSeed,\s*(?P<n>\d+)>\s+roles\s*=", src)
    assert m, (
        "could not find the roles[] declaration in rbac_store.cpp. The "
        "declaration was reshaped and this parser was not updated."
    )
    declared = int(m.group("n"))
    body = _strip_comments(_balanced_braces(src, src.index("{", m.end() - 1)))
    # First literal of each `{"Name", "Desc"}` pair. `RoleSeed{...}` on the
    # first element is the aggregate's explicit type, not an extra entry.
    names = re.findall(r'\{\s*"([^"]+)"\s*,', body)
    assert names, "roles[]: initialiser parsed but yielded no role names"
    assert len(names) == declared, (
        f"roles[]: declared std::array size {declared} but this parser "
        f"recovered {len(names)} names ({names}). The parser is wrong."
    )
    return names


def topology_floor():
    src = _read(FLOOR_HPP)
    m = re.search(r"kTopologyFloor\[\]\s*=", src)
    assert m, "could not find kTopologyFloor[] in authz_topology_floor.hpp"
    body = _strip_comments(_balanced_braces(src, src.index("{", m.end() - 1)))
    pairs = re.findall(r'\{\s*"([^"]+)"\s*,\s*"([^"]+)"\s*\}', body)
    assert pairs, "kTopologyFloor[]: initialiser parsed but yielded no entries"
    return [f"{s}:{o}" for s, o in pairs]


# --------------------------------------------------------------------------
# Markdown side
# --------------------------------------------------------------------------

def _section(md, heading):
    """Return the lines of the `## heading` section, up to the next `## `."""
    lines = md.splitlines()
    try:
        start = next(i for i, l in enumerate(lines) if l.strip() == heading)
    except StopIteration:
        raise AssertionError(
            f"rbac.md no longer has a `{heading}` section. If it was renamed, "
            f"update this constant; do not drop the check."
        )
    for i in range(start + 1, len(lines)):
        if lines[i].startswith("## "):
            return lines[start + 1:i]
    return lines[start + 1:]


def _first_cell_tokens(section_lines, pattern, label):
    """Collect the first capture of `pattern` from each table row in a section."""
    found = []
    for line in section_lines:
        if not line.startswith("|"):
            continue
        m = re.match(pattern, line)
        if m:
            found.append(m.group(1))
    assert found, (
        f"{label}: matched no table rows in rbac.md. The table was reformatted "
        f"and this pattern no longer fits — fix the pattern. A silent zero here "
        f"would make every comparison below vacuously true."
    )
    return found


def documented_securables():
    return _first_cell_tokens(
        _section(_read(RBAC_MD), "## Securable Types"),
        r"\|\s*`([A-Za-z]+)`\s*\|",
        "Securable Types table",
    )


def documented_operations():
    return _first_cell_tokens(
        _section(_read(RBAC_MD), "## Operations"),
        r"\|\s*`([A-Za-z]+)`",
        "Operations table",
    )


def documented_roles():
    return _first_cell_tokens(
        _section(_read(RBAC_MD), "## System Roles"),
        r"\|\s*\*\*([A-Za-z]+)\*\*\s*\|",
        "System Roles table",
    )


def documented_floor():
    md = _read(RBAC_MD)
    lines = md.splitlines()
    start = next(
        (i for i, l in enumerate(lines)
         if l.startswith("## ") and "authorization topology floor" in l.lower()),
        None,
    )
    assert start is not None, (
        "rbac.md no longer has an authorization-topology-floor section heading."
    )
    end = next((i for i in range(start + 1, len(lines))
                if lines[i].startswith("## ")), len(lines))
    return _first_cell_tokens(
        lines[start + 1:end],
        r"\|\s*`([A-Za-z]+:[A-Za-z]+)`",
        "topology floor table",
    )


# --------------------------------------------------------------------------
# Prose counts
# --------------------------------------------------------------------------

WORD_NUMBERS = {
    "one": 1, "two": 2, "three": 3, "four": 4, "five": 5, "six": 6,
    "seven": 7, "eight": 8, "nine": 9, "ten": 10, "eleven": 11, "twelve": 12,
}


def _as_int(tok):
    t = tok.lower()
    return WORD_NUMBERS.get(t, int(t) if t.isdigit() else None)


NUM = r"(\d+|[A-Za-z]+)"


def _scoped(md, scope):
    """Return (text, line_offset) for a heading fragment, or the whole document.

    Fails loud on a scope that matches no heading: a silently-empty haystack
    would make every pattern inside it match nothing, which the min_matches
    floor would then report as a phrasing change rather than a missing section.
    """
    if scope is None:
        return md, 0
    lines = md.splitlines()
    start = next((i for i, l in enumerate(lines)
                  if l.startswith("## ") and scope in l.lower()), None)
    assert start is not None, (
        f"rbac.md has no `## ` heading containing {scope!r} — the section was "
        f"renamed. Update the scope constant; do not widen it to None, which "
        f"would silently re-admit unrelated sections."
    )
    end = next((i for i in range(start + 1, len(lines))
                if lines[i].startswith("## ")), len(lines))
    return chr(10).join(lines[start:end]), start


# The floor patterns are scoped to the floor SECTION, not the whole document.
# A document-wide `these N` also matches rbac.md:75's "these three" (three
# ADR-0017 list-read routes, nothing to do with the floor) — an unscoped
# pattern reds the build on correct prose in an unrelated section.
FLOOR_SECTION = "authorization topology floor"

# Each entry is (pattern, scope, count_source, min_matches, label). `scope` is
# None for the whole document, or a lowercase fragment of the `## ` heading
# whose section the pattern is confined to.
#
# The patterns are deliberately narrow, anchored on a TOTALITY marker ("all N",
# "of the N", "these N"). A bare `N securable types` also matches the perfectly
# correct SUBSET counts in the role table — "ITServiceOwner ... 18 securable
# types", "Viewer ... Read on 24 securable types" — and an over-broad pattern
# that reds the build on correct prose is a check people switch off. Every
# pattern here was validated against the real document: it matches the totals
# and none of the subsets.
#
# `min_matches` is the anti-vacuity floor. If a reword drops a pattern's hit
# count below it, this file fails and names the pattern, rather than quietly
# asserting nothing.
#
# There is deliberately NO prose pattern for the ROLE count. `rbac.md` states no
# role total in running text today (only subset phrases like "the same two roles
# that already hold ApiToken:Write"), and inventing a pattern that matches
# nothing is worse than not having one. Roles are covered by
# `test_system_roles_match_seed`, which is strictly stronger than a count: it
# names the role that drifted.
PROSE_CHECKS = [
    (rf"all\s+{NUM}\s+securable\s+types", None, "securables", 1,
     "'all N securable types'"),
    (rf"of\s+the\s+{NUM}\s+securable\s+types", None, "securables", 1,
     "'of the N securable types'"),
    (rf"{NUM}\s+reads\s+are\s+treated", FLOOR_SECTION, "floor", 1, "floor intro"),
    (rf"these\s+{NUM}\b", FLOOR_SECTION, "floor", 3, "floor: these N"),
]


def prose_counts():
    """Every place `rbac.md` states a TOTAL in running text, with its expected value.

    Digits and spelled-out words both, because the three stale "five"s PR #4776
    removed were all spelled out — a digits-only sweep would have passed over the
    exact defect that motivated this file.
    """
    md = _read(RBAC_MD)
    expected_by_source = {
        "securables": len(seeded_securables()),
        "floor": len(topology_floor()),
    }

    results = []
    for pattern, scope, source, min_matches, label in PROSE_CHECKS:
        haystack, line_offset = _scoped(md, scope)
        hits = 0
        for m in re.finditer(pattern, haystack, flags=re.I):
            value = _as_int(m.group(1))
            if value is None:
                # Neither a digit nor a number word — prose this check has no
                # business policing.
                continue
            hits += 1
            line_no = line_offset + haystack[:m.start()].count(chr(10)) + 1
            results.append(
                (label, line_no, m.group(0).strip(), value, expected_by_source[source])
            )
        assert hits >= min_matches, (
            f"{label}: matched {hits} counted occurrence(s) in rbac.md, expected "
            f"at least {min_matches}. Either the phrasing moved (update the "
            f"pattern) or the statement was deliberately removed (lower "
            f"min_matches in the same change, with a reason). Leaving it "
            f"matching nothing turns this into a test that asserts nothing."
        )
    return results


# --------------------------------------------------------------------------
# Tests
# --------------------------------------------------------------------------

def _compare(doc, seed, what):
    missing = [x for x in seed if x not in doc]
    extra = [x for x in doc if x not in seed]
    msg = []
    if missing:
        msg.append(f"seeded in C++ but ABSENT from rbac.md: {missing}")
    if extra:
        msg.append(f"documented in rbac.md but NOT seeded: {extra}")
    assert not msg, (
        f"{what} drift between rbac.md and its seed array "
        f"({len(doc)} documented, {len(seed)} seeded):\n  " + "\n  ".join(msg)
    )


def test_securable_types_match_seed():
    _compare(documented_securables(), seeded_securables(), "Securable type")


def test_operations_match_seed():
    _compare(documented_operations(), seeded_operations(), "Operation")


def test_system_roles_match_seed():
    _compare(documented_roles(), seeded_roles(), "System role")


def test_topology_floor_matches_source():
    _compare(documented_floor(), topology_floor(), "Topology floor entry")


def test_prose_counts_match_seed():
    wrong = [
        f"rbac.md:{line} says {text!r} ({label}) — should be {expected}"
        for label, line, text, value, expected in prose_counts()
        if value != expected
    ]
    assert not wrong, "stale count in rbac.md prose:\n  " + "\n  ".join(wrong)


def main():
    failures = []
    for name, fn in sorted(globals().items()):
        if name.startswith("test_") and callable(fn):
            try:
                fn()
            except AssertionError as exc:
                failures.append(f"FAIL {name}:\n{exc}")
            else:
                print(f"ok   {name}")
    if failures:
        print("\n" + "\n\n".join(failures), file=sys.stderr)
        return 1
    print("\ncheck-rbac-doc-counts: OK (rbac.md matches its seed arrays)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
