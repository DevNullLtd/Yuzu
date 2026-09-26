#!/usr/bin/env python3
"""test_capability_gate_consistency.py — #1398's content<->catalogue drift gate.

Issue #1398: an `InstructionDefinition`'s `approval.mode` was enforced only
on the governed `POST /api/instructions/:id/execute` path, never on raw
dispatch (`POST /api/command`, MCP `execute_instruction`). The fix adds an
`ExecuteGate` dimension to `CommandCapability` (`command_capability.hpp`),
authored per `plugin.action` row across the eight `capability_decls/*.hpp`
fragments, derived STRICTEST-WINS from every shipped definition targeting
that pair (`auto` -> `None`, `role-gated` -> `AdminOrApproval`, `always` ->
`AlwaysApproval`). This script is the mechanical guarantee that the
authored catalogue value and the derived content value never drift apart —
a content author tightening a definition's `approval.mode` without a
matching catalogue change is exactly the shape of gap #1398 was filed for,
just at the pair level instead of the platform level.

Three things checked against the real, integrated tree:

  1. GATE CONSISTENCY: for every `plugin.action` pair that both (a) has a
     shipped `InstructionDefinition` and (b) has a catalogue row, the
     catalogue's authored `.execute_gate` must equal the strictest
     `approval.mode` among every definition targeting that pair. Mismatches
     are named exactly (`plugin.action`: catalogue says X, content demands
     Y).
  2. NON-CATALOGUE EXEMPTION RULE (Decision 1, #1398 design doc): a content
     pair with NO catalogue row is exempt from gating BY CONSTRUCTION only
     when it is server-side (`server`/`server_internal`/`_server`-prefixed)
     — such a pair can never reach `CommandCapabilityRegistry::classify`
     because nothing dispatches it to an agent. A future catalogue-eligible
     plugin action that ships content but never gets a catalogue row would
     otherwise silently inherit this exemption; this check makes that a
     named failure instead.
  3. PARSE INTEGRITY: the number of fragment rows this script's regex finds
     an `.execute_gate` for must equal the number of rows it finds a
     `.plugin`/`.action` pair for, and both must equal EXPECTED_TOTAL_ROWS
     (see the itemized sum next to that constant's own definition below,
     not repeated here — this second copy is what drifted stale first)
     — architect review requirement: a regex that silently fails to
     associate a gate with its row must read as a hard failure, never as
     an absent gate.

Mode-defaulting semantics are replicated EXACTLY from
`server/core/scripts/embed_content.py`'s `def_envelope`
(`approval.get("mode") or "auto"`) so a definition with no `approval:`
block, or an empty one, derives `auto` identically in both places —
otherwise this gate and the build-time embed step could disagree about
what a defaulted definition means.

Runnable standalone: `python3 tests/test_capability_gate_consistency.py`.
Hermetic — reads only source files already on disk under this repository
(content/definitions/*.yaml, the seven capability_decls fragments); no
subprocess, no network, no clock. Requires PyYAML, an existing hard build
dependency (see embed_content.py) — not a new one for this repo.

Demonstrating the failure modes is done on fabricated data only, per this
package's boundary against editing real fragment/content files —
`TestFailureModesOnSyntheticData` feeds synthetic pair/mode/gate maps
straight into the same `diff_gates` analysis function the real-tree check
uses.
"""

from __future__ import annotations

import re
import sys
import unittest
from pathlib import Path

try:
    import yaml  # type: ignore[import-not-found]
except ImportError:
    print(
        "ERROR: test_capability_gate_consistency.py requires PyYAML "
        "(already a hard build dependency — see embed_content.py). "
        "Install with `pip install pyyaml`.",
        file=sys.stderr,
    )
    sys.exit(1)

REPO_ROOT = Path(__file__).resolve().parent.parent
CONTENT_GLOB = "content/definitions/*.yaml"

FRAGMENT_FILES = [
    "server/core/src/capability_decls/core_dispatch_capabilities.hpp",
    "server/core/src/capability_decls/plugin_action_catalogue_content_dist.hpp",
    "server/core/src/capability_decls/plugin_action_catalogue_a.hpp",
    "server/core/src/capability_decls/plugin_action_catalogue_b.hpp",
    "server/core/src/capability_decls/plugin_action_catalogue_c.hpp",
    "server/core/src/capability_decls/plugin_action_catalogue_d.hpp",
    "server/core/src/capability_decls/plugin_action_catalogue_disk_actions.hpp",
    "server/core/src/capability_decls/plugin_action_catalogue_filesystem_posture.hpp",
    "server/core/src/capability_decls/plugin_action_catalogue_power_health.hpp",
    "server/core/src/capability_decls/plugin_action_catalogue_autoruns.hpp",
    "server/core/src/capability_decls/plugin_action_catalogue_app_usage.hpp",
    "server/core/src/capability_decls/plugin_action_catalogue_execution_artifacts.hpp",
    "server/core/src/capability_decls/plugin_action_catalogue_windows_optional_features.hpp",
    "server/core/src/capability_decls/plugin_action_catalogue_peripherals.hpp",
    "server/core/src/capability_decls/plugin_action_catalogue_printing.hpp",
    "server/core/src/capability_decls/plugin_action_catalogue_app_control.hpp",
    "server/core/src/capability_decls/plugin_action_catalogue_firmware_posture.hpp",
    "server/core/src/capability_decls/plugin_action_catalogue_runtimes.hpp",
    "server/core/src/capability_decls/plugin_action_catalogue_platform_security.hpp",
    "server/core/src/capability_decls/plugin_action_catalogue_browser_inventory.hpp",
    "server/core/src/capability_decls/plugin_action_catalogue_system_hardening.hpp",
    "server/core/src/capability_decls/plugin_action_catalogue_pkg_inventory.hpp",
]
# 4 + 5 + 45 + 55 + 34 + 42 + 2 + 3 + 4 — see command_capability.hpp's fragment
# doc comments and the #1398 design doc's verified row-count audit. The 2 is
# disk_actions and the trailing 4 is power_health
# (battery/thermal/power_plan/set_power_plan), both Wave 6. The leading 4
# (core_dispatch_capabilities.hpp) already includes the hardware CI
# sync-on-demand row (`__sync__.now`) — it is NOT a separate increment on
# top of this base sum; an earlier revision of this comment listed it as
# one anyway ("+1 core") and a reader naively adding every bullet below
# got 204, one over the true total, which is exactly the trap this note
# now exists to flag. (The stale EXPECTED_TOTAL_ROWS=206 this replaces was
# off by a further 2 rows for reasons lost to history — 203 is the value
# re-derived from the fragments themselves, not from reconciling 206.)
# Wave 7 PR7.1: +2 autoruns (list/catalog).
# Wave 7b PR7b.3: +3 app_usage (summary/last_used/foreground).
# Wave 7b PR7b.1: +3 execution_artifacts (shimcache/amcache/prefetch).
# Wave 9 PR9.2b: +2 windows_optional_features (list/info).
# Wave 9 PR9.1a: +3 peripherals (usb/pci/thunderbolt).
# Wave 9 PR9.1b: +2 printing (printers/jobs).
# Wave 9 PR9.1b (follow-up): +1 printing.clear_queue (merged to dev as PR #4616).
# Wave 8 PR8.4: +1 firmware_posture (firmware).
# Wave 10 P2a-3: +2 browser_inventory (browsers/profiles); its extensions action follows as its own PR (+1 then).
# Wave 8 PR8.6: +2 app_control (wdac_policy/applocker_policy) — read-only
# posture; add_rule/remove_rule (#282) follow as separate Destructive-class rows.
# Wave 8 PR8.1-a1: +2 platform_security (secure_boot/code_integrity).
# Wave 10 PR10.1-b: +2 runtimes (dotnet/jvm).
# Wave 8 PR8.1-b: +1 system_hardening (posture).
# Wave 10 PR10.1-c: +2 pkg_inventory (managers/packages).
# Running total: 194 (base, already includes __sync__.now — see above) +
# 2 (autoruns) + 3 (app_usage) + 3 (execution_artifacts) +
# 2 (windows_optional_features) + 3 (peripherals) + 2 (printing) +
# 1 (printing.clear_queue) + 2 (app_control) + 2 (platform_security) +
# 2 (browser_inventory) + 1 (firmware_posture) + 2 (runtimes, dotnet/jvm) +
# 1 (system_hardening) + 2 (pkg_inventory, managers/packages) = 222.
# This constant has been bumped independently on several sides of several merges
# (PR #4719 and PR #4964 CI are the trail; #4721 tracks deriving it per fragment).
# The rule is always the same: find the shared baseline all sides agree on and add
# EVERY side's new plugin on top of it, never pick one side's total -- and re-derive
# by RUNNING parse_fragment_gate_rows over FRAGMENT_FILES rather than trusting hand
# arithmetic, which has drifted before (206, then 203, then repeatedly since).
EXPECTED_TOTAL_ROWS = 222

# Decision 1 (#1398 design doc): the ONLY prefixes a content-declared pair
# with no catalogue row may carry — server-side handlers with no
# agent-dispatch surface, so ExecuteGate is meaningless for them.
NON_CATALOGUE_EXEMPT_PREFIXES = ("server", "server_internal", "_server")

RANK = {"auto": 0, "role-gated": 1, "always": 2}
MODE_TO_GATE = {"auto": "None", "role-gated": "AdminOrApproval", "always": "AlwaysApproval"}

_ROW_RE = re.compile(
    r'\.plugin\s*=\s*"([^"]+)"\s*,\s*'
    r'\.action\s*=\s*"([^"]+)"'
    r'(?:.*?)'
    r'\.execute_gate\s*=\s*ExecuteGate::(\w+)\s*,',
    re.DOTALL,
)
_PAIR_ONLY_RE = re.compile(r'\.plugin\s*=\s*"([^"]+)"\s*,\s*\.action\s*=\s*"([^"]+)"')


def parse_content_pair_modes(content_root: Path) -> dict[tuple[str, str], list[str]]:
    """Every `(plugin, action) -> [approval.mode, ...]` across every
    definition in every multi-document `content/definitions/*.yaml` file.
    Mode-defaulting matches `embed_content.py`'s `def_envelope` exactly:
    `approval.get("mode") or "auto"`.
    """
    pair_modes: dict[tuple[str, str], list[str]] = {}
    for path in sorted(content_root.glob(CONTENT_GLOB)):
        with path.open(encoding="utf-8") as f:
            docs = list(yaml.safe_load_all(f))
        for doc in docs:
            if not isinstance(doc, dict):
                continue
            spec = doc.get("spec")
            if not isinstance(spec, dict):
                continue
            exec_ = spec.get("execution") or {}
            plugin = exec_.get("plugin") or spec.get("plugin") or ""
            action = exec_.get("action") or spec.get("action") or ""
            if not plugin or not action:
                continue
            approval = spec.get("approval") or {}
            mode = approval.get("mode") or "auto"
            pair_modes.setdefault((plugin, str(action).lower()), []).append(mode)
    return pair_modes


def non_string_column_values(doc: object, fallback_id: str) -> list[str]:
    """`<definition id>.<column>: <repr>` for every non-string entry of the
    `values` list of one definition document's result columns."""
    if not isinstance(doc, dict):
        return []
    def_id = (doc.get("metadata") or {}).get("id", fallback_id)
    result = (doc.get("spec") or {}).get("result")
    columns = result.get("columns") if isinstance(result, dict) else None
    return [
        f"{def_id}.{col.get('name')}: {v!r}"
        for col in columns or []
        for v in col.get("values") or []
        if not isinstance(v, str)
    ]


def find_non_string_column_values(content_root: Path) -> list[str]:
    """Every `<definition id>.<column>: <repr>` whose `values` list holds a
    non-string. YAML 1.1 reads an unquoted on/off/yes/no as a boolean, so such
    a vocabulary token renders as True/False in every generated doc unless quoted.
    """
    bad: list[str] = []
    for path in sorted(content_root.glob(CONTENT_GLOB)):
        with path.open(encoding="utf-8") as f:
            docs = list(yaml.safe_load_all(f))
        for doc in docs:
            bad.extend(non_string_column_values(doc, path.name))
    return bad


def parse_fragment_gate_rows(path: Path) -> list[tuple[str, str, str]]:
    """Every `(plugin, action, execute_gate)` triple a fragment declares, in
    file order. Pairs on `.plugin =` immediately followed by `.action =`
    (same adjacency `test_capability_catalogue_complete.py` relies on),
    extended to also capture the `.execute_gate = ExecuteGate::<Value>`
    that must follow somewhere later in the same row.
    """
    text = path.read_text(encoding="utf-8")
    return [(p, a, g) for p, a, g in _ROW_RE.findall(text)]


def parse_fragment_pair_count(path: Path) -> int:
    """Count of `.plugin =`/`.action =` adjacent pairs only, independent of
    whether a gate was found for them — the parse-integrity comparison
    baseline (check 3 in the module docstring).
    """
    text = path.read_text(encoding="utf-8")
    return len(_PAIR_ONLY_RE.findall(text))


def diff_gates(
    pair_modes: dict[tuple[str, str], list[str]],
    fragment_rows: list[tuple[str, str, str]],
) -> tuple[dict[tuple[str, str], tuple[str, str]], set[tuple[str, str]]]:
    """The pure analysis this gate's checks 1 and 2 run — no file I/O, so
    the synthetic failure-mode tests below can drive it directly.

    Returns `(mismatches, unexempt_missing)`:
      - `mismatches`: pair -> (catalogue_gate, derived_gate) for every
        catalogue-backed pair where the authored gate disagrees with the
        strictest mode any shipped definition declares for it.
      - `unexempt_missing`: content pairs with NO catalogue row whose
        plugin is NOT one of the exempt server-side prefixes — a
        catalogue-eligible action that content declares but the catalogue
        never classifies.
    """
    catalogue_gate_by_pair = {(p, a): g for p, a, g in fragment_rows}

    mismatches: dict[tuple[str, str], tuple[str, str]] = {}
    unexempt_missing: set[tuple[str, str]] = set()

    for pair, modes in pair_modes.items():
        strictest_mode = max(modes, key=lambda m: RANK.get(m, -1))
        if strictest_mode not in RANK:
            # An unvalidated mode is a separate gate's problem (rung 1's
            # embed_content.py / instruction_store.cpp vocabulary check) —
            # this script only compares gates for validly-moded pairs so
            # the two checks stay independent and don't double-report the
            # same underlying defect.
            continue
        derived_gate = MODE_TO_GATE[strictest_mode]

        plugin = pair[0]
        catalogue_gate = catalogue_gate_by_pair.get(pair)
        if catalogue_gate is None:
            if not plugin.startswith(NON_CATALOGUE_EXEMPT_PREFIXES):
                unexempt_missing.add(pair)
            continue

        if catalogue_gate != derived_gate:
            mismatches[pair] = (catalogue_gate, derived_gate)

    return mismatches, unexempt_missing


def format_gaps(
    mismatches: dict[tuple[str, str], tuple[str, str]],
    unexempt_missing: set[tuple[str, str]],
) -> str:
    lines: list[str] = []
    for (plugin, action), (catalogue_gate, derived_gate) in sorted(mismatches.items()):
        lines.append(
            f"GATE MISMATCH for {plugin}.{action}: catalogue authors "
            f"ExecuteGate::{catalogue_gate}, but shipped content demands "
            f"ExecuteGate::{derived_gate} — update the catalogue row (or "
            "the content, if the catalogue is the intended source of truth "
            "for this change)"
        )
    for plugin, action in sorted(unexempt_missing):
        lines.append(
            f"UNCLASSIFIED GATE-ELIGIBLE PAIR {plugin}.{action}: content declares "
            "this pair but no capability_decls/*.hpp row exists for it, and its "
            f"plugin prefix is not in the exempt server-side set "
            f"{NON_CATALOGUE_EXEMPT_PREFIXES} — this pair CAN reach "
            "CommandCapabilityRegistry::classify, so it needs an authored "
            ".execute_gate row"
        )
    return "\n".join(lines)


class TestGateConsistencyOnRealTree(unittest.TestCase):
    """The actual drift gate: parses the live repository and fails, naming
    every gap, if content's approval.mode and the seven capability-catalogue
    fragments' execute_gate have drifted apart.
    """

    def test_no_gate_gaps_between_content_and_catalogue(self) -> None:
        pair_modes = parse_content_pair_modes(REPO_ROOT)
        self.assertTrue(pair_modes, "parsed zero content definitions — the glob is broken")

        fragment_rows: list[tuple[str, str, str]] = []
        pair_only_count = 0
        for rel in FRAGMENT_FILES:
            path = REPO_ROOT / rel
            fragment_rows.extend(parse_fragment_gate_rows(path))
            pair_only_count += parse_fragment_pair_count(path)

        # Check 3: parse-integrity. A regex that finds the plugin/action
        # pair but silently fails to associate an execute_gate with it
        # (e.g. a future field reordering this script's regex doesn't
        # anticipate) must fail loud here, not read as "no gate = fine".
        self.assertEqual(
            len(fragment_rows), pair_only_count,
            f"parsed {pair_only_count} plugin/action pairs across the {len(FRAGMENT_FILES)} fragments but "
            f"only {len(fragment_rows)} had an associated .execute_gate — the row/gate "
            "regex has drifted apart from the fragment file format (or a row is missing "
            "its .execute_gate field, which should be a COMPILE failure via each "
            "fragment's static_assert(all_gates_specified(...)) — if it isn't, that "
            "sweep itself has a bug)",
        )
        self.assertEqual(
            len(fragment_rows), EXPECTED_TOTAL_ROWS,
            f"expected exactly {EXPECTED_TOTAL_ROWS} total capability rows across the {len(FRAGMENT_FILES)} "
            f"fragments, found {len(fragment_rows)} — update EXPECTED_TOTAL_ROWS if a row "
            f"was deliberately added or removed, after confirming the {len(FRAGMENT_FILES)} per-file counts "
            "in the #1398 design doc's row-count audit are updated too",
        )
        self.assertNotIn(
            "Unspecified", {g for _, _, g in fragment_rows},
            "a fragment row's execute_gate parsed as ExecuteGate::Unspecified — this "
            "should be IMPOSSIBLE (every fragment's static_assert(all_gates_specified(...)) "
            "makes an omitted .execute_gate a compile failure), so either that sweep is "
            "broken or a row was authored with the sentinel value explicitly",
        )

        mismatches, unexempt_missing = diff_gates(pair_modes, fragment_rows)

        if mismatches or unexempt_missing:
            self.fail("\n" + format_gaps(mismatches, unexempt_missing))


class TestDefinitionValueVocabularies(unittest.TestCase):
    """Every `values:` entry of every shipped definition column is a string."""

    def test_every_values_entry_is_a_string(self) -> None:
        bad = find_non_string_column_values(REPO_ROOT)
        self.assertFalse(
            bad,
            "non-string `values:` entries (quote on/off/yes/no so YAML keeps them strings):\n"
            + "\n".join(bad),
        )


class TestFailureModesOnSyntheticData(unittest.TestCase):
    """Proves `diff_gates` and the `values:` vocabulary scan actually catch
    the drift shapes they guard, using fabricated data only — never a real
    fragment or content file.
    """

    def test_an_unquoted_on_off_values_entry_is_named(self) -> None:
        # `yaml.safe_load` turns an unquoted on/off into a boolean: exactly the
        # silent coercion the real-tree guard exists to catch.
        doc = yaml.safe_load(
            "metadata: {id: x}\n"
            "spec: {result: {columns: [{name: state, values: [enabled, on, off]}]}}\n"
        )
        self.assertEqual(non_string_column_values(doc, "fallback"), ["x.state: True", "x.state: False"])

    def test_quoted_on_off_values_entries_pass(self) -> None:
        doc = yaml.safe_load(
            "metadata: {id: x}\n"
            "spec: {result: {columns: [{name: state, values: [enabled, 'on', 'off']}]}}\n"
        )
        self.assertEqual(non_string_column_values(doc, "fallback"), [])

    def test_stricter_content_than_catalogue_is_named(self) -> None:
        pair_modes = {("widget", "explode"): ["role-gated"]}
        fragment_rows = [("widget", "explode", "None")]
        mismatches, unexempt_missing = diff_gates(pair_modes, fragment_rows)
        self.assertEqual(mismatches, {("widget", "explode"): ("None", "AdminOrApproval")})
        self.assertFalse(unexempt_missing)

    def test_looser_content_than_catalogue_is_also_named(self) -> None:
        # A catalogue gate stricter than content demands is still a drift —
        # #1398's fix ships an accurate reflection of content, not a
        # ratchet that only tightens.
        pair_modes = {("widget", "spin"): ["auto"]}
        fragment_rows = [("widget", "spin", "AlwaysApproval")]
        mismatches, unexempt_missing = diff_gates(pair_modes, fragment_rows)
        self.assertEqual(mismatches, {("widget", "spin"): ("AlwaysApproval", "None")})
        self.assertFalse(unexempt_missing)

    def test_strictest_wins_across_multiple_definitions(self) -> None:
        pair_modes = {("tar", "sql"): ["auto", "auto", "role-gated", "auto"]}
        fragment_rows = [("tar", "sql", "None")]
        mismatches, unexempt_missing = diff_gates(pair_modes, fragment_rows)
        self.assertEqual(mismatches, {("tar", "sql"): ("None", "AdminOrApproval")})

    def test_matching_gate_is_not_reported(self) -> None:
        pair_modes = {("rdp_control", "set_state"): ["role-gated"]}
        fragment_rows = [("rdp_control", "set_state", "AdminOrApproval")]
        mismatches, unexempt_missing = diff_gates(pair_modes, fragment_rows)
        self.assertFalse(mismatches)
        self.assertFalse(unexempt_missing)

    def test_exempt_server_prefix_missing_row_is_not_reported(self) -> None:
        pair_modes = {("server", "policy.delete"): ["always"]}
        mismatches, unexempt_missing = diff_gates(pair_modes, [])
        self.assertFalse(mismatches)
        self.assertFalse(unexempt_missing)

    def test_unexempt_missing_catalogue_row_is_named(self) -> None:
        pair_modes = {("widget", "ghost"): ["role-gated"]}
        mismatches, unexempt_missing = diff_gates(pair_modes, [])
        self.assertFalse(mismatches)
        self.assertEqual(unexempt_missing, {("widget", "ghost")})

    def test_invalid_mode_is_skipped_not_crashed_on(self) -> None:
        # An invalid approval.mode is rung 1's vocabulary check's problem
        # (embed_content.py / instruction_store.cpp), not this script's —
        # it must not crash comparing an unranked mode.
        pair_modes = {("widget", "spin"): ["manual"]}
        fragment_rows = [("widget", "spin", "None")]
        mismatches, unexempt_missing = diff_gates(pair_modes, fragment_rows)
        self.assertFalse(mismatches)
        self.assertFalse(unexempt_missing)

    def test_invalid_mode_ignored_but_a_sibling_valid_mode_still_drives_strictest_wins(
        self,
    ) -> None:
        # #1398 (quality-engineer, Gate 3, NICE): the case above proves an
        # invalid mode alone doesn't crash the comparison; this proves it
        # doesn't get silently counted toward strictest-wins either — a pair
        # with one invalid def ("manual") and one valid role-gated def must
        # still derive AdminOrApproval from the VALID sibling, not fall back
        # to None because the invalid entry short-circuited the whole pair.
        pair_modes = {("widget", "spin"): ["manual", "role-gated"]}
        fragment_rows = [("widget", "spin", "None")]
        mismatches, unexempt_missing = diff_gates(pair_modes, fragment_rows)
        self.assertEqual(mismatches, {("widget", "spin"): ("None", "AdminOrApproval")})
        self.assertFalse(unexempt_missing)


if __name__ == "__main__":
    unittest.main()
