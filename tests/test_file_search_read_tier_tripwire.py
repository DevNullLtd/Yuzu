#!/usr/bin/env python3
"""Tripwire: the stored rows of the file_search plugin stay in the EXISTING Forensics read tier.

file_search is dispatched under FileRetrieval with AdminOrApproval (a Forensics row is single-target; a
search must stay launchable at a group or the fleet), yet what it stores is withheld from every reader
without a global Forensics:Read. ONE catalogue flag on its row (`StoredRowTier::ForensicsRead`) makes
`derive_forensics_plugin_set` put it in the set every read surface already holds, so the live bus, the
failure-text sanitiser, the SQL exclusion, the tracker scrub, the result-set refusal, the hardware notice
and the `response.forensics.read` audit row all apply with no edit: no second tier, no second permission
check, no new audit verb. A unit test cannot see most of these rows go missing; this gate pins them.

Pinned over server/core/src (comments stripped): the enum and its ordinary default, the one derivation, the
two catalogue defect rules and the four properties of the file_search row; the tier flag named only in the
enum, the derivation and the fragment; the plugin named by a string literal only in its fragment, the
enablement table, the action descriptions and the kill-switch seed (a name-keyed special case is a second
path around the set); no second-tier or new-audit-verb spelling. The four
`unrestricted_internal_consumer()` sites stay pinned, per site, by tests/test_response_store_read_tripwire.py.

GREP LIMIT: lexical; it cannot see a branch that never runs, a plugin name built at run time or one split
across adjacent string literals (the unit tests assert the behaviour). `--selftest` deletes each required
statement and appends each forbidden spelling in memory and requires the gate to name it.

Usage: python3 -I tests/test_file_search_read_tier_tripwire.py [--selftest]
"""
from __future__ import annotations

import importlib.util
import os
import re
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
REPO_ROOT = os.path.dirname(HERE)
SRC = os.path.join("server", "core", "src")
CAP_HPP = os.path.join(SRC, "command_capability.hpp")
SET_HPP = os.path.join(SRC, "forensics_plugin_set.hpp")
FRAGMENT = os.path.join(SRC, "capability_decls", "plugin_action_catalogue_file_search.hpp")
FILTER_HPP = os.path.join(SRC, "response_tier_filter.hpp")
SERVER_CPP = os.path.join(SRC, "server.cpp")
ENABLEMENT = os.path.join(SRC, "enablement_units.hpp")
DESCRIPTIONS = os.path.join(SRC, "agent_registry.cpp")
HINT = (" (this gate pins where the file_search stored rows are read; if the rule was legitimately "
        "changed, update docs/authz-model.md section 4 and the routed-concerns Forensics-tier row first, "
        "then tests/test_file_search_read_tier_tripwire.py)")

# The comment-free, whitespace-collapsed text the sibling #4990 gate already uses: one scanner, so a
# comment that mentions a token can neither satisfy nor break a check here either.
_spec = importlib.util.spec_from_file_location(
    "forensics_tier_wiring_lexical", os.path.join(HERE, "test_forensics_tier_wiring_lexical.py"))
_sib = importlib.util.module_from_spec(_spec)
sys.modules[_spec.name] = _sib
_spec.loader.exec_module(_sib)
canonical = _sib.canonical

# Each row: (id, file, a C++ snippet, why). The snippet is canonicalised like the text it is looked for
# in, so line wrapping and indentation do not matter.
REQUIRED: list[tuple[str, str, str, str]] = [
    ("tier-enum", CAP_HPP,
     "enum class StoredRowTier : uint8_t { Ordinary, ForensicsRead, };",
     "the catalogue flag that puts a plugin's stored rows in the Forensics read tier"),
    ("tier-default", CAP_HPP, "StoredRowTier stored_rows{StoredRowTier::Ordinary};",
     "a row's stored rows are ordinary unless it says otherwise: a changed default would withhold every plugin"),
    ("derive-adds-flagged", SET_HPP,
     "if (cap.stored_rows == StoredRowTier::ForensicsRead) names.push_back(ascii_lower(cap.plugin));",
     "the ONE place a flagged plugin joins the set every read surface holds"),
    ("defect-flagged-dash", SET_HPP,
     "for (const auto& plugin : flagged) { if (plugin.find('-') != std::string::npos)",
     "a flagged plugin whose name holds '-' cannot be told apart by the hardware poll's command-id split"),
    ("defect-flagged-mixed", SET_HPP, "if (ordinary_elsewhere.contains(plugin))",
     "the tier is per plugin: a flagged plugin with an ordinary row would withhold that row's output too"),
    ("row-plugin", FRAGMENT, '.plugin = "file_search",', "the flagged row is the file_search row"),
    ("row-stored-rows", FRAGMENT, ".stored_rows = StoredRowTier::ForensicsRead,",
     "without the flag the search results are readable at Response:Read"),
    ("row-dispatch-securable", FRAGMENT, '.securable = "FileRetrieval",',
     "the dispatch securable stays FileRetrieval, so fleet and group targeting stay possible"),
    ("row-gate", FRAGMENT, ".execute_gate = ExecuteGate::AdminOrApproval,",
     "launching a search by a non-administrator needs an approval"),
]

# Spellings that must NOT occur anywhere under server/core/src (a second tier, a new audit verb).
FORBIDDEN: list[tuple[str, str, str]] = [
    ("second-tier", r"\bTierVisibility\b|\brestricted_names\b|\bsame_securable\w*|StoredRowTier::SameSecurable",
     "stored file_search rows have no second read tier: they use the Forensics tier"),
    ("new-audit-verb", r"response\.restricted",
     "reads of stored file_search rows audit as response.forensics.read, never a verb of their own"),
]

# The files that may name the tier flag, and the files that may name the plugin by a string literal.
TIER_FLAG_FILES = frozenset({CAP_HPP, SET_HPP, FRAGMENT})
PLUGIN_NAME_FILES = frozenset({FRAGMENT, ENABLEMENT, DESCRIPTIONS, SERVER_CPP})
TIER_FLAG = re.compile(r"\bStoredRowTier\b|\bstored_rows\b")
# A quote, or the raw-string opener `"(`, then the name, in any case: a SQL literal ('file_search' inside a
# string), a case variant and R"(file_search)" are all names. A bare identifier is not (f(file_search)).
PLUGIN_NAME = re.compile(r'(?:["\']|"\()file_search\b', re.IGNORECASE)

# A cheap raw-text prefilter: only a file that mentions one of these is canonicalised.
_PREFILTER = re.compile(
    r'file_search|StoredRowTier|stored_rows|response\.restricted|'
    r"TierVisibility|restricted_names|same_securable", re.IGNORECASE)
_SRC_EXTS = (".cpp", ".hpp", ".h", ".cc")


def load(root: str = REPO_ROOT) -> dict[str, str]:
    """{path relative to the repo: canonical text} for every file that matters to a check."""
    wanted = {CAP_HPP, SET_HPP, FRAGMENT}
    out: dict[str, str] = {}
    for dirpath, _dirs, files in os.walk(os.path.join(root, SRC)):
        for name in files:
            if not name.endswith(_SRC_EXTS):
                continue
            full = os.path.join(dirpath, name)
            rel = os.path.relpath(full, root)
            with open(full, encoding="utf-8", errors="replace") as fh:
                raw = fh.read()
            if rel in wanted or _PREFILTER.search(raw):
                out[rel] = canonical(raw)
    return out


def problems(texts: dict[str, str]) -> list[tuple[str, str]]:
    """Every violated rule as (id, message); empty when the gate holds."""
    found: list[tuple[str, str]] = []
    for rid, path, snippet, why in REQUIRED:
        text = texts.get(path)
        if text is None:
            found.append((rid, f"{path} is missing: {why}{HINT}"))
        elif canonical(snippet).strip() not in text:
            found.append((rid, f"{path} no longer holds `{snippet}`: {why}{HINT}"))
    for rid, pattern, why in FORBIDDEN:
        for path, text in sorted(texts.items()):
            if re.search(pattern, text):
                found.append((rid, f"{path} spells a forbidden form: {why}{HINT}"))
    for path, text in sorted(texts.items()):
        if path not in TIER_FLAG_FILES and TIER_FLAG.search(text):
            found.append(("tier-flag-outside", f"{path} names the stored-row tier flag; only the enum, the "
                          f"derivation and the file_search fragment may{HINT}"))
        if path not in PLUGIN_NAME_FILES and PLUGIN_NAME.search(text):
            found.append(("plugin-name-outside", f"{path} names the file_search plugin by a string literal; "
                          f"a name-keyed special case is a second path around the Forensics set{HINT}"))
    return found


def selftest() -> int:
    """Mutate the real sources in memory (nothing on disk is touched) and require each mutation named."""
    failures: list[str] = []

    def expect(cond: bool, what: str) -> None:
        if not cond:
            failures.append(what)
            print(f"FAIL: {what}", file=sys.stderr)

    def ids(texts: dict[str, str]) -> set[str]:
        return {rid for rid, _ in problems(texts)}

    base = load()
    expect(problems(base) == [], "the real tree must pass the gate: " + "; ".join(m for _, m in problems(base)))
    expect(len(REQUIRED) >= 9, "the required-statement list must not shrink silently")

    for rid, path, snippet, _why in REQUIRED:
        text = base.get(path, "")
        needle = canonical(snippet).strip()
        if needle not in text:
            expect(False, f"{rid}: the statement no longer matches the real source (stale snippet)")
            continue
        deleted = dict(base, **{path: text.replace(needle, "", 1)})
        expect(rid in ids(deleted), f"{rid}: deleting its statement was NOT detected")
        # A comment that merely mentions the statement must not satisfy it.
        commented = dict(base, **{path: canonical("// " + snippet + "\n")})
        expect(rid in ids(commented), f"{rid}: a comment mentioning its statement satisfied it")

    for rid, pattern, _why in FORBIDDEN:
        spelling = {"second-tier": "TierVisibility x;", "new-audit-verb": '"response.restricted.read"'}[rid]
        expect(rid in ids(dict(base, **{FILTER_HPP: base.get(FILTER_HPP, "") + canonical(spelling)})),
               f"{rid}: appending its spelling was NOT detected")
        expect(re.search(pattern, canonical("// " + spelling)) is None,
               f"{rid}: a comment spelling must not count")
    for spelling in ("restricted_names()", "StoredRowTier::SameSecurable", "same_securable_granted"):
        expect("second-tier" in ids(dict(base, **{FILTER_HPP: base.get(FILTER_HPP, "") + canonical(spelling + ";")})),
               f"second-tier: `{spelling}` was NOT detected")

    # Naming the flag, or the plugin, in a file outside the pinned lists.
    outside = os.path.join(SRC, "forensics_read_audit.hpp")
    expect("tier-flag-outside" in ids(dict(base, **{outside: canonical("auto t = StoredRowTier::Ordinary;")})),
           "tier-flag-outside: the flag named in another file was NOT detected")
    expect("tier-flag-outside" in ids(dict(base, **{outside: canonical("if (cap.stored_rows == x) {}")})),
           "tier-flag-outside: .stored_rows read in another file was NOT detected")
    expect("plugin-name-outside" in ids(dict(base, **{outside: canonical('if (p == "file_search") {}')})),
           "plugin-name-outside: the plugin named in another file was NOT detected")
    expect("plugin-name-outside" not in ids(dict(base, **{outside: canonical('// "file_search" in a comment')})),
           "plugin-name-outside: a comment mention must not count")
    for what, spelling in (("a SQL literal", 'auto q = "WHERE plugin = \'file_search\'";'),
                           ("a case variant", 'if (p == "File_Search") {}'),
                           ("a raw string", 'auto r = R"(file_search)";')):
        expect("plugin-name-outside" in ids(dict(base, **{outside: canonical(spelling)})),
               f"plugin-name-outside: {what} in another file was NOT detected")
    expect("plugin-name-outside" not in ids(dict(base, **{outside: canonical("use(file_search);")})),
           "plugin-name-outside: a bare identifier must not count")

    print(f"selftest: {len(failures)} failure(s)")
    return 1 if failures else 0


def main() -> int:
    if "--selftest" in sys.argv[1:]:
        return selftest()
    found = problems(load())
    for rid, msg in found:
        print(f"FAIL [{rid}]: {msg}", file=sys.stderr)
    if found:
        return 1
    print("test_file_search_read_tier_tripwire: ok")
    return 0


if __name__ == "__main__":
    sys.exit(main())
