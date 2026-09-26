#!/usr/bin/env python3
"""test_capability_catalogue_complete.py — PR1.9's cross-fragment drift gate.

The capability catalogue (`server/core/src/command_capability.hpp`'s
`CommandCapability` rows) is authored as independent, hand-written
sources: the per-plugin-group fragment headers listed in
FRAGMENT_FILES below (each owned by a different package) plus the
core-owned `capability_decls/core_dispatch_capabilities.hpp` (the four
system-initiated dispatches a plugin never receives from a caller —
`tar.fleet_snapshot`, `__guard__.push_rules`, `asset_tags.sync`, `__sync__.now`). Nobody
mechanically checks that these sources, taken together, actually
match what the plugins declare via their `actions()` override. This script
is that check.

It parses every `actions()` override under `agents/plugins/*/src/*.cpp`
(each plugin's `name()` override gives the plugin half of the pair; the
literal strings inside the `static const char* acts[] = {...}` array give
the action half) and cross-references the result against every
`.plugin = "..."` / `.action = "..."` pair declared across every
capability-catalogue header. It fails, naming the exact offending
`plugin.action`, when:

  1. A plugin declares an action that has no catalogue row anywhere across
     the sources (a MISSING row) — a plugin ships a capability the
     dispatch-classification layer would report `Unclassified` for.
  2. One of the per-group fragments declares a `plugin.action` no
     plugin's `actions()` override names (a BOGUS row) — dead, unreachable
     catalogue data, or a typo that silently shadows the real action. (The
     core-owned fragment is exempt from this direction only:
     `__guard__.push_rules` is a real, intentional row with no backing
     plugin — Guardian's rule-push is a server-internal dispatch, not
     something any plugin's `actions()` ever lists.)
  3. The same `plugin.action` is declared by more than one
     source (a DUPLICATE row) — two independently-authored fragments
     racing to classify the same dispatch, which `CommandCapabilityRegistry
     ::classify` resolves as `Ambiguous`, never first-wins (see
     `command_capability.hpp`).

Runnable standalone: `python3 tests/test_capability_catalogue_complete.py`.
Hermetic — reads only source files already on disk under this repository;
no subprocess, no network, no clock. Exits non-zero (via `unittest`'s
default runner) if any check against the real, integrated tree fails.

Demonstrating the three failure modes (required by this test's own
acceptance criteria) is done WITHOUT touching a single real fragment or
plugin file, per this package's boundaries — `TestFailureModesOnSyntheticData`
below feeds fabricated `(plugin, action)` sets straight into the same
`diff_catalogue` analysis function the real-tree check uses, and asserts it
reports the precise gap:

  - `test_missing_row_is_named`      → a synthetic action with no fragment
    row comes back in `missing`, named exactly `("widget", "explode")`.
  - `test_bogus_row_is_named`        → a synthetic fragment row with no
    backing plugin action comes back in `bogus`, named exactly
    `("widget", "ghost_action")`.
  - `test_duplicate_row_is_named`    → the same `plugin.action` declared in
    two synthetic fragment files comes back in `duplicates`, naming both
    source files (`frag_x.hpp`, `frag_y.hpp`).
"""

from __future__ import annotations

import re
import sys
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
PLUGINS_GLOB = "agents/plugins/*/src/*.cpp"

FRAGMENT_FILES = [
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
CORE_FILE = "server/core/src/capability_decls/core_dispatch_capabilities.hpp"

_NAME_RE = re.compile(
    r'std::string_view\s+name\(\)\s*const\s*noexcept\s*override\s*\{\s*'
    r'return\s+(?:"([^"]+)"|(\w+))\s*;',
)
_ACTIONS_BODY_RE = re.compile(
    r'actions\(\)\s*const\s*noexcept\s*override\s*\{(.*?)return\s+acts;',
    re.DOTALL,
)
_STRING_LITERAL_RE = re.compile(r'"([^"]*)"')
_FRAGMENT_ROW_RE = re.compile(
    r'\.plugin\s*=\s*"([^"]+)".*?\.action\s*=\s*"([^"]+)"',
    re.DOTALL,
)


def parse_plugin_actions(plugins_root: Path) -> dict[str, set[str]]:
    """Every (plugin -> {actions}) declared by an `actions()` override under
    `agents/plugins/*/src/*.cpp`. A plugin's name comes from its `name()`
    override, either a direct string literal or (for the two plugins that
    factor it into a `kName` constant) that constant's own literal
    definition — never inferred from the directory name, since that is not
    what the dispatcher actually sees.
    """
    actions_by_plugin: dict[str, set[str]] = {}
    for path in sorted(plugins_root.glob(PLUGINS_GLOB)):
        text = path.read_text(encoding="utf-8")
        actions_match = _ACTIONS_BODY_RE.search(text)
        if not actions_match:
            continue  # not the plugin's main file (e.g. a collector helper)

        name_match = _NAME_RE.search(text)
        if not name_match:
            raise AssertionError(
                f"{path}: has an actions() override but no name() override "
                "this parser recognises — update the parser, this is a real "
                "plugin file"
            )
        literal, ident = name_match.group(1), name_match.group(2)
        if literal is not None:
            plugin = literal
        else:
            const_match = re.search(
                r'\bconst\s+char\*\s+' + re.escape(ident) + r'\s*=\s*"([^"]+)"', text
            )
            if not const_match:
                raise AssertionError(
                    f"{path}: name() returns identifier {ident!r} but no "
                    f"`const char* {ident} = \"...\";` definition was found"
                )
            plugin = const_match.group(1)

        acts = set(_STRING_LITERAL_RE.findall(actions_match.group(1)))
        actions_by_plugin.setdefault(plugin, set()).update(acts)
    return actions_by_plugin


def parse_fragment_rows(path: Path) -> list[tuple[str, str]]:
    """Every `(plugin, action)` pair declared by one `capability_decls/*.hpp`
    fragment header, in file order. Pairs on the adjacency of `.plugin = ` and
    the `.action = ` that immediately follows it — the format every fragment
    in this catalogue uses for every row.
    """
    text = path.read_text(encoding="utf-8")
    return _FRAGMENT_ROW_RE.findall(text)


def diff_catalogue(
    actions_by_plugin: dict[str, set[str]],
    fragment_rows_by_file: dict[str, list[tuple[str, str]]],
    core_rows: list[tuple[str, str]],
) -> tuple[set[tuple[str, str]], set[tuple[str, str]], dict[tuple[str, str], list[str]]]:
    """The pure analysis at this gate's core — no file I/O, so the synthetic
    failure-mode tests below can drive it directly.

    Returns `(missing, bogus, duplicates)`:
      - `missing`: plugin.action pairs a plugin declares that no source
        (any of the seven per-group headers, or core) covers.
      - `bogus`: plugin.action pairs one of the seven FRAGMENT files declares
        that no plugin actually has (core is exempt — see module docstring).
      - `duplicates`: plugin.action -> list of >=2 source labels that each
        declared it independently (across all eight sources, fragments and
        core alike — a fragment/core collision is exactly as ambiguous to
        `CommandCapabilityRegistry::classify` as a fragment/fragment one).
    """
    real_pairs = {
        (plugin, action) for plugin, acts in actions_by_plugin.items() for action in acts
    }

    all_fragment_pairs: set[tuple[str, str]] = set()
    sources_by_pair: dict[tuple[str, str], list[str]] = {}
    for label, rows in fragment_rows_by_file.items():
        for pair in rows:
            all_fragment_pairs.add(pair)
            sources_by_pair.setdefault(pair, []).append(label)
    for pair in core_rows:
        sources_by_pair.setdefault(pair, []).append("core")

    catalogue_pairs = all_fragment_pairs | set(core_rows)

    missing = real_pairs - catalogue_pairs
    bogus = all_fragment_pairs - real_pairs
    duplicates = {pair: srcs for pair, srcs in sources_by_pair.items() if len(srcs) > 1}

    return missing, bogus, duplicates


def format_gaps(
    missing: set[tuple[str, str]],
    bogus: set[tuple[str, str]],
    duplicates: dict[tuple[str, str], list[str]],
) -> str:
    lines: list[str] = []
    for plugin, action in sorted(missing):
        lines.append(f"MISSING catalogue row for {plugin}.{action} (declared by the plugin, "
                      "classified nowhere)")
    for plugin, action in sorted(bogus):
        lines.append(f"BOGUS catalogue row for {plugin}.{action} (no plugin declares this "
                      "action)")
    for (plugin, action), srcs in sorted(duplicates.items()):
        lines.append(f"DUPLICATE catalogue row for {plugin}.{action} declared in: "
                      f"{', '.join(srcs)}")
    return "\n".join(lines)


SERVER_CPP = "server/core/src/server.cpp"


def _fragment_accessor(rel: str) -> str:
    """`.../plugin_action_catalogue_disk_actions.hpp` -> the accessor name the
    production composition site must call."""
    stem = rel.rsplit("/", 1)[-1].removesuffix(".hpp")
    return stem + "()"


class TestProductionCompositionWiring(unittest.TestCase):
    """K3 (external functional review): every catalogue test — C++ and Python —
    composes its OWN list of fragment spans, and the Python gates read the
    fragment HEADERS. Nothing read `server.cpp`, so deleting the two lines that
    wire a fragment into the live `CommandCapabilityRegistry` left the entire
    server suite and both gates green while the plugin's actions classified as
    Unclassified in production.

    This is a source tripwire, following the precedent at
    `tests/unit/server/test_agent_properties_scope_authz.cpp`. It is deliberately
    textual: the point is to guard the one file no compiled test observes.
    """

    def test_every_fragment_is_included_and_composed_in_server_cpp(self) -> None:
        server = (REPO_ROOT / SERVER_CPP).read_text(encoding="utf-8")
        missing_include: list[str] = []
        missing_compose: list[str] = []
        for rel in FRAGMENT_FILES:
            header = rel.rsplit("/", 1)[-1]
            if f'#include "capability_decls/{header}"' not in server:
                missing_include.append(header)
            if _fragment_accessor(rel) not in server:
                missing_compose.append(_fragment_accessor(rel))
        self.assertEqual(
            [], missing_include,
            f"{SERVER_CPP} does not #include these catalogue fragments, so their rows "
            f"cannot reach the production registry: {missing_include}",
        )
        self.assertEqual(
            [], missing_compose,
            f"{SERVER_CPP} includes but never COMPOSES these fragments into the "
            f"CommandCapabilityRegistry, so every action they declare classifies as "
            f"Unclassified in production while every test stays green: {missing_compose}",
        )


class TestCatalogueCompleteOnRealTree(unittest.TestCase):
    """The actual drift gate: parses the live repository and fails, naming
    every gap, if the plugins' actions() tables and the eight capability
    sources have drifted apart.
    """

    def test_no_gaps_between_plugins_and_catalogue(self) -> None:
        actions_by_plugin = parse_plugin_actions(REPO_ROOT)
        self.assertTrue(actions_by_plugin, "parsed zero plugins — the glob or parser is broken")

        fragment_rows_by_file = {
            rel: parse_fragment_rows(REPO_ROOT / rel) for rel in FRAGMENT_FILES
        }
        core_rows = parse_fragment_rows(REPO_ROOT / CORE_FILE)

        missing, bogus, duplicates = diff_catalogue(
            actions_by_plugin, fragment_rows_by_file, core_rows
        )

        if missing or bogus or duplicates:
            self.fail("\n" + format_gaps(missing, bogus, duplicates))


class TestFailureModesOnSyntheticData(unittest.TestCase):
    """Proves `diff_catalogue` actually catches all three drift shapes, using
    fabricated data only — never a real fragment or plugin file (this
    package may not edit either).
    """

    def test_missing_row_is_named(self) -> None:
        actions_by_plugin = {"widget": {"spin", "explode"}}
        fragment_rows_by_file = {"frag_x.hpp": [("widget", "spin")]}
        missing, bogus, duplicates = diff_catalogue(actions_by_plugin, fragment_rows_by_file, [])
        self.assertEqual(missing, {("widget", "explode")})
        self.assertFalse(bogus)
        self.assertFalse(duplicates)

    def test_bogus_row_is_named(self) -> None:
        actions_by_plugin = {"widget": {"spin"}}
        fragment_rows_by_file = {
            "frag_x.hpp": [("widget", "spin"), ("widget", "ghost_action")],
        }
        missing, bogus, duplicates = diff_catalogue(actions_by_plugin, fragment_rows_by_file, [])
        self.assertFalse(missing)
        self.assertEqual(bogus, {("widget", "ghost_action")})
        self.assertFalse(duplicates)

    def test_duplicate_row_is_named(self) -> None:
        actions_by_plugin = {"widget": {"spin"}}
        fragment_rows_by_file = {
            "frag_x.hpp": [("widget", "spin")],
            "frag_y.hpp": [("widget", "spin")],
        }
        missing, bogus, duplicates = diff_catalogue(actions_by_plugin, fragment_rows_by_file, [])
        self.assertFalse(missing)
        self.assertFalse(bogus)
        self.assertEqual(duplicates, {("widget", "spin"): ["frag_x.hpp", "frag_y.hpp"]})

    def test_core_row_with_no_backing_plugin_is_not_bogus(self) -> None:
        # __guard__.push_rules is real production data: a core-owned,
        # system-issued dispatch no plugin's actions() ever names. The core
        # source is exempt from the bogus-row direction of the check for
        # exactly this reason.
        actions_by_plugin = {"widget": {"spin"}}
        fragment_rows_by_file = {"frag_x.hpp": [("widget", "spin")]}
        core_rows = [("__guard__", "push_rules")]
        missing, bogus, duplicates = diff_catalogue(
            actions_by_plugin, fragment_rows_by_file, core_rows
        )
        self.assertFalse(missing)
        self.assertFalse(bogus)
        self.assertFalse(duplicates)

    def test_core_row_duplicated_by_a_fragment_is_a_duplicate(self) -> None:
        actions_by_plugin = {"tar": {"fleet_snapshot"}}
        fragment_rows_by_file = {"frag_x.hpp": [("tar", "fleet_snapshot")]}
        core_rows = [("tar", "fleet_snapshot")]
        missing, bogus, duplicates = diff_catalogue(
            actions_by_plugin, fragment_rows_by_file, core_rows
        )
        self.assertFalse(missing)
        self.assertFalse(bogus)
        self.assertEqual(duplicates, {("tar", "fleet_snapshot"): ["frag_x.hpp", "core"]})


if __name__ == "__main__":
    unittest.main()
