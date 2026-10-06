#!/usr/bin/env python3
"""test_capability_gate_consistency.py — #1398's content<->catalogue drift gate.

Issue #1398: an `InstructionDefinition`'s `approval.mode` was enforced only
on the governed `POST /api/instructions/:id/execute` path, never on raw
dispatch (`POST /api/command`, MCP `execute_instruction`). The fix adds an
`ExecuteGate` dimension to `CommandCapability` (`command_capability.hpp`),
authored per `plugin.action` row across the `capability_decls/*.hpp`
fragments (FRAGMENT_FILES below), derived STRICTEST-WINS from every shipped definition targeting
that pair (`auto` -> `None`, `role-gated` -> `AdminOrApproval`, `always` ->
`AlwaysApproval`). This script is the mechanical guarantee that the
authored catalogue value and the derived content value never drift apart —
a content author tightening a definition's `approval.mode` without a
matching catalogue change is exactly the shape of gap #1398 was filed for,
just at the pair level instead of the platform level.

Five checks run against the real, integrated tree: checks 1-3 are the original
gate-consistency set, checks 4 and 5 (after check 3) are the question
classification set. Checks 1-5 all read the shipped definitions through one
shared walk (`parse_content_definitions` / `walk_definition_docs`, see below):
`content/definitions` and `content/packs`, recursively, `kind:
InstructionDefinition` documents only.

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
     not repeated here — this second copy is what drifted stale first).
     Architect review requirement: a regex that silently fails to
     associate a gate with its row must read as a hard failure, never as
     an absent gate.

Two more checks (question/catalogue classification, ADR-0033 section 1: a
definition must not self-certify read-vs-effect):

  4. QUESTION CLASS: every question definition (`spec.type` missing, empty or
     `question`, as `embed_content.py` defaults it) whose pair HAS a catalogue
     row must map to a `DispatchClass::ReadOnly` row. Plugin and action are
     case-folded on both sides, as the runtime `classify()` is
     case-insensitive. A (plugin, action) pair declared twice in the catalogue
     is a hard failure, as is a fragment whose counts disagree: its
     `.dispatch_class` row count, its `.plugin`/`.action` pair count and its
     bare `.plugin =` count must be equal (the third, looser count catches a
     row written in a shape neither regex matches). The set of
     `capability_decls/*.hpp` files on disk must also equal FRAGMENT_FILES: a
     fragment that is not listed is invisible to every check.
  5. ROWLESS QUESTIONS: every question definition whose pair has NO catalogue
     row must be named in the pinned `ROWLESS_QUESTION_IDS` (plugin exactly one
     of SERVER_SIDE_PSEUDO_PLUGINS, lowercased but not stripped) or
     `ROWLESS_QUESTION_IDS_UNEXPLAINED` (anything else); an unpinned id, or a
     stale pin, fails and says to update the pin deliberately. The pin sizes
     must sum to `EXPECTED_ROWLESS_QUESTION_COUNT`.

The shared walk mirrors `embed_content.py` (the only source of shipped
definitions). `TestDefinitionWalkParityWithEmbed` runs that script's `main()`
in-process and compares, per definition id, the `(type, plugin, action)` its
generated bundle carries with the walk's (first occurrence of a repeated id),
on the real tree and on the fabricated trees of
`TestDefinitionParsingOnSyntheticTrees`. It compares nothing else (not names,
approval modes or YAML sources).

Mode-defaulting semantics are replicated EXACTLY from
`server/core/scripts/embed_content.py`'s `def_envelope`
(`approval.get("mode") or "auto"`) so a definition with no `approval:`
block, or an empty one, derives `auto` identically in both places —
otherwise this gate and the build-time embed step could disagree about
what a defaulted definition means.

Runnable standalone: `python3 tests/test_capability_gate_consistency.py`.
Reads source files already on disk under this repository (content/definitions
and content/packs YAML, the capability_decls fragments). The one exception to
"read only" is `TestDefinitionWalkParityWithEmbed`, which loads
`server/core/scripts/embed_content.py` by path (bytecode writing disabled
around the load, so no `__pycache__` is written) and runs its `main()` in this
process, writing only inside a `TemporaryDirectory`. No subprocess, no network,
no clock. Requires PyYAML, an existing hard build dependency (see
embed_content.py), not a new one for this repo.

Demonstrating the failure modes is done on fabricated data only, per this
package's boundary against editing real fragment/content files —
`TestFailureModesOnSyntheticData` feeds synthetic pair/mode/gate maps
straight into the same `diff_gates` analysis function the real-tree check
uses.
"""

from __future__ import annotations

import contextlib
import importlib.util
import io
import json
import re
import sys
import tempfile
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
    "server/core/src/capability_decls/plugin_action_catalogue_browser_policy.hpp",
    "server/core/src/capability_decls/plugin_action_catalogue_update_source_trust.hpp",
    "server/core/src/capability_decls/plugin_action_catalogue_app_control.hpp",
    "server/core/src/capability_decls/plugin_action_catalogue_firmware_posture.hpp",
    "server/core/src/capability_decls/plugin_action_catalogue_runtimes.hpp",
    "server/core/src/capability_decls/plugin_action_catalogue_platform_security.hpp",
    "server/core/src/capability_decls/plugin_action_catalogue_browser_inventory.hpp",
    "server/core/src/capability_decls/plugin_action_catalogue_local_security_policy.hpp",
    "server/core/src/capability_decls/plugin_action_catalogue_privacy_permissions.hpp",
    "server/core/src/capability_decls/plugin_action_catalogue_system_hardening.hpp",
    "server/core/src/capability_decls/plugin_action_catalogue_pkg_inventory.hpp",
    "server/core/src/capability_decls/plugin_action_catalogue_mgmt_posture.hpp",
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
# Wave 10 PR10.2-b: +1 browser_policy (policies).
# Running total: 194 (base, already includes __sync__.now — see above) +
# 2 (autoruns) + 3 (app_usage) + 3 (execution_artifacts) +
# 2 (windows_optional_features) + 3 (peripherals) + 2 (printing) +
# 1 (printing.clear_queue) + 2 (app_control) + 2 (platform_security) +
# 2 (browser_inventory) + 1 (firmware_posture) + 2 (runtimes, dotnet/jvm) +
# 1 (system_hardening) + 2 (pkg_inventory, managers/packages) + 1 (browser_policy) = 223.
# This constant has been bumped independently on several sides of several merges
# (PR #4719 and PR #4964 CI are the trail; #4721 tracks deriving it per fragment).
# The rule is always the same: find the shared baseline all sides agree on and add
# EVERY side's new plugin on top of it, never pick one side's total -- and re-derive
# by RUNNING parse_fragment_gate_rows over FRAGMENT_FILES rather than trusting hand
# arithmetic, which has drifted before (206, then 203, then repeatedly since). Dev
# landed at 222 here (219 baseline + system_hardening 1 + pkg_inventory 2); dev's own
# browser_policy (+1) landed on top of that: 222 + 1 = 223. This branch's own
# dev merged privacy_permissions (+1) on top of the 223 baseline: dev is now at 224.
# This branch's own local_security_policy (+3: password_policy/lockout_policy/
# audit_policy -- sudoers is PLANNED, follows as its own PR, not counted here) lands on
# top of dev's CURRENT 224 (not the pre-merge 223): 224 + 3 = 227. Verified directly by
# running parse_fragment_gate_rows over FRAGMENT_FILES with both plugins' fragments
# present, not by hand arithmetic -- see the merge-arithmetic trap this comment exists
# to name (adding this branch's own delta to a stale baseline undercounts by the other
# side's own delta).
# Wave 10 PR10.1-d: +1 update_source_trust (sources) on top of dev's 227 = 228, verified by
# running parse_fragment_gate_rows over FRAGMENT_FILES and by a `grep -c` sum
# (both 228), not by adding to a possibly-stale baseline.
# local_security_policy's `sudoers` action (+1, Medium risk tier) on top of that 228: the total is
# 229, re-derived by running parse_fragment_gate_rows over FRAGMENT_FILES, not by adding to a
# baseline.
# Wave 11 PR11.2-a: +1 network_config.routes (ReadOnly, Infrastructure:Read, gate None) on top of
# 229 = 230, re-derived by running parse_fragment_gate_rows over FRAGMENT_FILES (the test's own
# count), not by adding to a baseline. Fragment C is now 35 rows.
# mgmt_posture (posture, +1) lands on top of dev's 230 (merge-arithmetic: this branch's own delta
# added to dev's CURRENT total, re-derived by running parse_fragment_gate_rows over
# FRAGMENT_FILES with both fragments present, not by hand): 231.
EXPECTED_TOTAL_ROWS = 231

# Decision 1 (#1398 design doc): the ONLY prefixes a content-declared pair
# with no catalogue row may carry — server-side handlers with no
# agent-dispatch surface, so ExecuteGate is meaningless for them.
NON_CATALOGUE_EXEMPT_PREFIXES = ("server", "server_internal", "_server")

# `question` definitions with NO catalogue row, split by plugin name. Every
# id below was derived by running `parse_content_questions` against
# content/definitions/*.yaml and checking the pair against the
# capability_decls/*.hpp rows (`parse_fragment_dispatch_classes`).
#
# ROWLESS_QUESTION_IDS: the plugin is exactly one of SERVER_SIDE_PSEUDO_PLUGINS.
# These pairs have no catalogue row, so `classify_and_authorize_dispatch`
# (agent_registry.hpp, the `!classified` return) denies them as Unclassified.
# A new rowless question, or a pinned id that gained a row, changed type or was
# removed, fails the check: update this pin deliberately, in the same change.
ROWLESS_QUESTION_IDS = (
    "server.compliance.policy_detail",
    "server.compliance.summary",
    "server.deployment.list_jobs",
    "server.directory.list_users",
    "server.directory.sync_status",
    "server.inventory.agent",
    "server.inventory.query",
    "server.inventory.tables",
    "server.notifications.list",
    "server.patches.deployment_status",
    "server.patches.fleet_summary",
    "server.patches.list_missing",
    "server.policy.list",
    "server.policy_fragment.list",
    "server.product_pack.get",
    "server.product_pack.list",
    "server.webhooks.deliveries",
    "server.webhooks.list",
    "server.workflow.execution_status",
    "server.workflow.get",
    "server.workflow.list",
)
EXPECTED_ROWLESS_QUESTION_COUNT = 21

# The plugin names check 5 treats as server-side, matched EXACTLY after
# lowercasing (NOT stripped: `"Server "` is not server-side and lands in the
# UNEXPLAINED bucket). The pre-existing check 2 (`diff_gates`) keeps its looser
# `startswith(NON_CATALOGUE_EXEMPT_PREFIXES)` match on purpose: it is Decision 1
# of the #1398 design doc (docs/security-reviews/1398-dispatch-approval-gate-design.md,
# which words it as "-prefixed") and changing it was outside this change's
# scope. Consequence: a plugin such as `serverless` is exempt from check 2 but
# lands in the UNEXPLAINED bucket here, so it still fails check 5 unless pinned.
SERVER_SIDE_PSEUDO_PLUGINS = ("server", "server_internal", "_server")

# ROWLESS_QUESTION_IDS_UNEXPLAINED: rowless questions whose plugin is NOT a
# server-side pseudo-plugin, i.e. a suspected catalogue gap (a real agent
# plugin action with a question but no capability row). Empty today. A
# non-empty entry here is a TODO for the catalogue author, not an approval;
# pinning it only keeps the check fail-closed for a NEW such id.
ROWLESS_QUESTION_IDS_UNEXPLAINED: tuple[str, ...] = ()

RANK = {"auto": 0, "role-gated": 1, "always": 2}
MODE_TO_GATE = {"auto": "None", "role-gated": "AdminOrApproval", "always": "AlwaysApproval"}

_ROW_RE = re.compile(
    r'\.plugin\s*=\s*"([^"]+)"\s*,\s*'
    r'\.action\s*=\s*"([^"]+)"'
    r'(?:.*?)'
    r'\.execute_gate\s*=\s*ExecuteGate::(\w+)\s*,',
    re.DOTALL,
)
# `.dispatch_class` follows `.action` in every row, possibly after `//`
# comment lines (plugin_action_catalogue_c.hpp's flush_dns row has one).
_CLASS_RE = re.compile(
    r'\.plugin\s*=\s*"([^"]+)"\s*,\s*'
    r'\.action\s*=\s*"([^"]+)"\s*,'
    r'(?:\s|//[^\n]*)*'
    r'\.dispatch_class\s*=\s*DispatchClass::(\w+)\s*,'
)
_PAIR_ONLY_RE = re.compile(r'\.plugin\s*=\s*"([^"]+)"\s*,\s*\.action\s*=\s*"([^"]+)"')
# Deliberately looser than both regexes above: every `.plugin =` assignment, whatever
# follows it. A row written `.plugin = kConst` or with a comment between `.plugin` and
# `.action` is matched by neither row regex, but is still counted here.
_PLUGIN_ASSIGN_RE = re.compile(r'\.plugin\s*=')
DECLS_DIR = "server/core/src/capability_decls"


_EMBED_MODULE = None


def _embed_content():
    """`server/core/scripts/embed_content.py`, loaded by path so the definition
    walk reuses its `split_docs` instead of copying it. The module is registered
    in `sys.modules` while it executes (a dataclass in a future refactor needs
    that) and removed again afterwards, and bytecode writing is off so the load
    leaves no `__pycache__` in the source tree."""
    global _EMBED_MODULE
    if _EMBED_MODULE is None:
        name = "embed_content_for_gate_test"
        spec = importlib.util.spec_from_file_location(name, REPO_ROOT / "server/core/scripts/embed_content.py")
        assert spec is not None and spec.loader is not None
        module = importlib.util.module_from_spec(spec)
        saved_dont_write = sys.dont_write_bytecode
        sys.dont_write_bytecode = True
        sys.modules[name] = module
        try:
            spec.loader.exec_module(module)
        finally:
            sys.dont_write_bytecode = saved_dont_write
            sys.modules.pop(name, None)
        _EMBED_MODULE = module
    return _EMBED_MODULE


def _as_dict(value: object) -> dict:
    return value if isinstance(value, dict) else {}


def walk_definition_docs(repo_root: Path) -> list[tuple[str, dict]]:
    """`(definition id, document)` for every `kind: InstructionDefinition`
    document, in `embed_content.py`'s walk order.

    Mirrors `embed_content.py` (the only source of shipped definitions): the
    walk is `sorted(definitions rglob *.yaml + packs rglob *.yaml)` (its
    `yaml_files`), documents come from its `split_docs`, a document that fails
    to parse is skipped (it warns and continues) and only `kind ==
    "InstructionDefinition"` is taken. A definition with no usable id gets the
    fallback id `<path relative to the repo root>#<document index>`.
    """
    embed = _embed_content()
    content_root = repo_root / "content"
    files = sorted(
        list((content_root / "definitions").rglob("*.yaml"))
        + list((content_root / "packs").rglob("*.yaml"))
    )
    found: list[tuple[str, dict]] = []
    for path in files:
        rel = path.relative_to(repo_root).as_posix()
        for index, doc_text in enumerate(embed.split_docs(path.read_text(encoding="utf-8"))):
            try:
                doc = yaml.safe_load(doc_text)
            except yaml.YAMLError:
                continue
            if not isinstance(doc, dict) or doc.get("kind") != "InstructionDefinition":
                continue
            def_id = _as_dict(doc.get("metadata")).get("id")
            if not def_id or not isinstance(def_id, str):
                def_id = f"{rel}#{index}"
            found.append((def_id, doc))
    return found


def definition_fields(doc: dict) -> tuple[str, str, str]:
    """`(type, plugin, action)` of one definition document, by `def_envelope`'s
    rules in `embed_content.py`: `type` is `spec.get("type") or "question"`,
    plugin/action come from `spec.execution.*` falling back to `spec.*`, and the
    action is lowercased. The plugin is returned exactly as written (the
    consumers fold it where they need to). Unlike `embed_content.py` this never
    raises on malformed content (a non-dict `spec`/`execution`, a non-string
    plugin/action): the field becomes empty and the definition surfaces by id in
    check 5.
    """
    spec = _as_dict(doc.get("spec"))
    exec_ = _as_dict(spec.get("execution"))
    plugin = exec_.get("plugin") or spec.get("plugin") or ""
    action = exec_.get("action") or spec.get("action") or ""
    return (
        str(spec.get("type") or "question"),
        plugin if isinstance(plugin, str) else "",
        action.lower() if isinstance(action, str) else "",
    )


def parse_content_definitions(repo_root: Path) -> list[tuple[str, str, str, str]]:
    """`(definition id, type, plugin, action)` for every shipped definition,
    via `walk_definition_docs` and `definition_fields`."""
    return [(def_id, *definition_fields(doc)) for def_id, doc in walk_definition_docs(repo_root)]


def parse_content_questions(repo_root: Path) -> list[tuple[str, str, str]]:
    """`(definition id, plugin, action)` for every question definition (see
    `parse_content_definitions`). The plugin is as written and the action is
    lowercased; a question naming no usable plugin/action yields empty strings,
    never a skip.
    """
    return [(i, p, a) for i, t, p, a in parse_content_definitions(repo_root) if t == "question"]


def parse_content_pair_modes(repo_root: Path) -> dict[tuple[str, str], list[str]]:
    """Every `(plugin, action) -> [approval.mode, ...]` across every definition
    `walk_definition_docs` returns. Mode-defaulting matches `embed_content.py`'s
    `def_envelope` exactly: `approval.get("mode") or "auto"`. A definition with
    no plugin or no action is left out (checks 1-2 compare pairs).
    """
    pair_modes: dict[tuple[str, str], list[str]] = {}
    for _def_id, doc in walk_definition_docs(repo_root):
        _type, plugin, action = definition_fields(doc)
        if not plugin or not action:
            continue
        mode = _as_dict(_as_dict(doc.get("spec")).get("approval")).get("mode") or "auto"
        pair_modes.setdefault((plugin, action), []).append(str(mode))
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


def find_non_string_column_values(repo_root: Path) -> list[str]:
    """Every `<definition id>.<column>: <repr>` whose `values` list holds a
    non-string, across every definition `walk_definition_docs` returns. YAML 1.1
    reads an unquoted on/off/yes/no as a boolean, so such a vocabulary token
    renders as True/False in every generated doc unless quoted.
    """
    bad: list[str] = []
    for def_id, doc in walk_definition_docs(repo_root):
        bad.extend(non_string_column_values(doc, def_id))
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


def parse_fragment_plugin_assign_count(path: Path) -> int:
    """Count of every `.plugin =` in a fragment, the loosest row count: it does
    not care what follows, so a row neither `_CLASS_RE` nor `_PAIR_ONLY_RE`
    matches is still counted (see `check_fragment_class_parity`)."""
    return len(_PLUGIN_ASSIGN_RE.findall(path.read_text(encoding="utf-8")))


def parse_fragment_dispatch_classes(path: Path) -> list[tuple[str, str, str]]:
    """Every `(plugin, action, DispatchClass)` triple a fragment declares."""
    return _CLASS_RE.findall(path.read_text(encoding="utf-8"))


def fold(value: object) -> str:
    """Case-fold and strip a plugin/action name for the check 4/5 lookups.
    The runtime `classify()` (command_capability.hpp) compares plugin AND
    action case-insensitively; a non-string (malformed content) folds to "",
    which matches no catalogue row and so surfaces as an unpinned rowless
    question naming the definition.
    """
    return value.strip().lower() if isinstance(value, str) else ""


def build_class_by_pair(
    class_rows: list[tuple[str, str, str]],
) -> tuple[dict[tuple[str, str], str], list[str]]:
    """`(folded plugin, folded action) -> DispatchClass`, plus one message per
    pair declared more than once. The runtime `classify()` returns `Ambiguous`
    for such a pair, so it is a defect whether or not the classes agree. For a
    conflicting pair the map keeps the first non-ReadOnly class, so check 4
    still sees the stricter reading.
    """
    seen: dict[tuple[str, str], list[str]] = {}
    for plugin, action, cls in class_rows:
        seen.setdefault((fold(plugin), fold(action)), []).append(cls)
    problems: list[str] = []
    by_pair: dict[tuple[str, str], str] = {}
    for (plugin, action), classes in seen.items():
        by_pair[(plugin, action)] = next((c for c in classes if c != "ReadOnly"), classes[0])
        if len(classes) > 1:
            problems.append(
                f"DUPLICATE CATALOGUE ROW: {plugin}.{action} is declared {len(classes)} times "
                f"with DispatchClass::{' and DispatchClass::'.join(classes)} -- the runtime "
                "classify() returns Ambiguous for a pair matched twice (case-insensitively)"
            )
    return by_pair, problems


def check_fragment_class_parity(name: str, class_count: int, pair_count: int, assign_count: int) -> str | None:
    """Per-fragment parse integrity for check 4: the `.dispatch_class` rows, the
    `.plugin`/`.action` pairs and the bare `.plugin =` occurrences the regexes
    found must be the same number. None when they agree."""
    if class_count == pair_count == assign_count:
        return None
    return (
        f"{name}: {pair_count} plugin/action pairs, {class_count} matched `.dispatch_class`, "
        f"{assign_count} `.plugin =` occurrences -- these must be equal. A row whose "
        "`.dispatch_class` the regex missed (a comment in an unexpected place, a macro-built row) "
        "or one written in a shape the pair regex misses (`.plugin = kConst`, a comment between "
        "`.plugin` and `.action`) would read as rowless and escape check 4; a `.plugin =` in a "
        "comment or helper struct also lands here and needs a deliberate decision"
    )


def check_fragment_listing(repo_root: Path, listed: list[str]) -> str | None:
    """The `capability_decls/*.hpp` files on disk must be exactly `listed`
    (FRAGMENT_FILES): an unlisted fragment is invisible to every check. None
    when they agree."""
    on_disk = {p.relative_to(repo_root).as_posix() for p in (repo_root / DECLS_DIR).glob("*.hpp")}
    extra = sorted(on_disk - set(listed))
    missing = sorted(set(listed) - on_disk)
    repeated = sorted({f for f in listed if listed.count(f) > 1})
    if not (extra or missing or repeated):
        return None
    parts = []
    if extra:
        parts.append(f"on disk but not in FRAGMENT_FILES: {extra}")
    if missing:
        parts.append(f"in FRAGMENT_FILES but not on disk: {missing}")
    if repeated:
        parts.append(f"listed more than once in FRAGMENT_FILES: {repeated}")
    return f"FRAGMENT_FILES does not match {DECLS_DIR}/*.hpp -- " + "; ".join(parts)


def check_questions(
    questions: list[tuple[str, str, str]],
    class_by_pair: dict[tuple[str, str], str],
    pinned: tuple[str, ...],
    pinned_unexplained: tuple[str, ...],
    expected_count: int,
) -> list[str]:
    """Checks 4 and 5 (module docstring); pure, so the synthetic tests drive
    it directly. Returns one message per problem, empty when clean.
    """
    problems: list[str] = []
    rowless_server: dict[str, tuple[str, str]] = {}
    rowless_other: dict[str, tuple[str, str]] = {}

    seen_ids: set[str] = set()
    for def_id, raw_plugin, raw_action in questions:
        if def_id in seen_ids:
            problems.append(f"DUPLICATE QUESTION ID: {def_id} is defined by more than one question definition")
        seen_ids.add(def_id)
        plugin, action = fold(raw_plugin), fold(raw_action)
        cls = class_by_pair.get((plugin, action))
        if cls is None:
            # The catalogue lookup above folds (strip + lowercase) like classify(); the
            # server-side bucket lowercases only, so a plugin "Server " is NOT server-side.
            plugin_key = raw_plugin.lower() if isinstance(raw_plugin, str) else ""
            bucket = rowless_server if plugin_key in SERVER_SIDE_PSEUDO_PLUGINS else rowless_other
            bucket[def_id] = (plugin_key, action)
        elif cls != "ReadOnly":
            problems.append(
                f"QUESTION IS NOT READ-ONLY: definition {def_id} (spec.type: question) "
                f"targets {plugin}.{action}, whose catalogue row is DispatchClass::{cls} "
                "-- reclassify the definition as `action` (a definition must not self-certify "
                "read-vs-effect, ADR-0033 section 1); changing a catalogue row's "
                "dispatch_class is a security decision that needs its own review"
            )

    for label, found, pin in (
        ("ROWLESS_QUESTION_IDS", rowless_server, pinned),
        ("ROWLESS_QUESTION_IDS_UNEXPLAINED", rowless_other, pinned_unexplained),
    ):
        for def_id in sorted(set(found) - set(pin)):
            plugin, action = found[def_id]
            problems.append(
                f"UNPINNED ROWLESS QUESTION: definition {def_id} (plugin {plugin!r}, action "
                f"{action!r}) is a question with no capability_decls row and is not in {label} "
                "-- a question that cannot be classified cannot run as an agent dispatch; add a "
                f"catalogue row or update {label} (and its count) deliberately in this file. "
                "A question whose pair lives in a fragment missing from FRAGMENT_FILES also "
                "looks rowless: check that list first"
            )
        for def_id in sorted(set(pin) - set(found)):
            problems.append(
                f"STALE ROWLESS PIN: {def_id} is in {label} but is no longer a rowless "
                "question of that kind (it gained a catalogue row, changed type, changed "
                f"plugin or was removed) -- remove it from {label} deliberately"
            )

    for label, pin in (("ROWLESS_QUESTION_IDS", pinned), ("ROWLESS_QUESTION_IDS_UNEXPLAINED", pinned_unexplained)):
        if list(pin) != sorted(set(pin)):
            problems.append(f"{label} must be sorted and free of duplicates")
    total = len(pinned) + len(pinned_unexplained)
    if total != expected_count:
        problems.append(
            f"rowless-question pin count is {total}, expected {expected_count} -- update "
            "EXPECTED_ROWLESS_QUESTION_COUNT together with the pin"
        )
    return problems


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
    every gap, if content's approval.mode and the capability-catalogue
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


def collect_question_problems(
    repo_root: Path,
    fragment_files: list[str],
    pinned: tuple[str, ...] = ROWLESS_QUESTION_IDS,
    pinned_unexplained: tuple[str, ...] = ROWLESS_QUESTION_IDS_UNEXPLAINED,
    expected_count: int = EXPECTED_ROWLESS_QUESTION_COUNT,
) -> list[str]:
    """Everything checks 4 and 5 report for `repo_root`'s fragments and content,
    one message per problem (empty when clean). The real-tree test and the
    synthetic wiring test both call this, so the per-fragment parity and the
    duplicate-row wiring is exercised on fabricated input too."""
    problems: list[str] = []
    class_rows: list[tuple[str, str, str]] = []
    for rel in fragment_files:
        path = repo_root / rel
        rows = parse_fragment_dispatch_classes(path)
        class_rows.extend(rows)
        # Parse integrity, per fragment: a row the regexes missed would read as "no row"
        # and wrongly land in the rowless set.
        msg = check_fragment_class_parity(
            rel, len(rows), parse_fragment_pair_count(path), parse_fragment_plugin_assign_count(path)
        )
        if msg:
            problems.append(msg)
    class_by_pair, duplicate_problems = build_class_by_pair(class_rows)
    problems.extend(duplicate_problems)
    questions = parse_content_questions(repo_root)
    if not questions:
        problems.append("parsed zero question definitions -- the glob or spec.type read is broken")
    problems.extend(check_questions(questions, class_by_pair, pinned, pinned_unexplained, expected_count))
    return problems


class TestQuestionClassificationOnRealTree(unittest.TestCase):
    """Checks 4 and 5: `spec.type: question` against the catalogue's
    DispatchClass, and the pinned set of rowless questions.
    """

    def test_questions_are_read_only_and_rowless_ones_are_pinned(self) -> None:
        problems = collect_question_problems(REPO_ROOT, FRAGMENT_FILES)
        if problems:
            self.fail("\n" + "\n".join(problems))

    def test_every_fragment_on_disk_is_listed(self) -> None:
        msg = check_fragment_listing(REPO_ROOT, FRAGMENT_FILES)
        if msg:
            self.fail(msg)


_JSON_STR = r'"(?:[^"\\]|\\.)*"'
_BUNDLE_ENVELOPE_RE = re.compile(
    r'R"BCT\(\{"id": (' + _JSON_STR + r'), "name": ' + _JSON_STR + r', "version": ' + _JSON_STR
    + r', "type": (' + _JSON_STR + r'), "plugin": (' + _JSON_STR + r'), "action": (' + _JSON_STR + r')'
)


def embedded_definitions(content_root: Path) -> dict[str, tuple[str, str, str]]:
    """`id -> (type, plugin, action)` of every definition `embed_content.py`
    ingests from `content_root`, as its generated bundle carries them (its
    `main()` run in-process into a temp dir). Each envelope literal starts
    `{"id": ..., "name": ..., "version": ..., "type": ..., "plugin": ...,
    "action": ...`, which is all this reads. A non-zero exit raises with the
    exit code and everything embed wrote to stderr (it can fail on content
    unrelated to definitions, e.g. a bad plugin-docs manifest)."""
    embed = _embed_content()
    with tempfile.TemporaryDirectory(prefix="yuzu_test_gate_parity_") as td:
        out = Path(td) / "bundled_content.cpp"
        saved_argv = sys.argv
        sys.argv = ["embed_content.py", str(content_root), str(out)]
        stdout, stderr = io.StringIO(), io.StringIO()
        try:
            with contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
                rc = embed.main()
        finally:
            sys.argv = saved_argv
        if rc != 0:
            raise AssertionError(
                f"embed_content.py exited {rc} on {content_root}; its stderr:\n{stderr.getvalue()}"
            )
        text = out.read_text(encoding="utf-8")
    section = text[text.index("kBundledDefinitions"):text.index("kBundledSets")]
    return {
        json.loads(i): (json.loads(t), json.loads(p), json.loads(a))
        for i, t, p, a in _BUNDLE_ENVELOPE_RE.findall(section)
    }


def assert_walk_matches_embed(case: unittest.TestCase, repo_root: Path) -> None:
    """The gate's definition walk and `embed_content.py` must agree, for every
    definition id, on `(type, plugin, action)` as written (no folding), and on
    which ids exist. Nothing else is compared."""
    embedded = embedded_definitions(repo_root / "content")
    case.assertTrue(embedded, "embed_content.py ingested zero definitions -- the bundle read is broken")
    walked: dict[str, tuple[str, str, str]] = {}
    for def_id, def_type, plugin, action in parse_content_definitions(repo_root):
        walked.setdefault(def_id, (def_type, plugin, action))  # embed_content.py keeps the first of a repeated id
    differing = [
        f"  {i}: walk={walked.get(i)} embed={embedded.get(i)}"
        for i in sorted(set(walked) | set(embedded))
        if walked.get(i) != embedded.get(i)
    ]
    case.assertFalse(
        differing,
        f"the gate's definition walk and embed_content.py disagree on {len(differing)} definition "
        "id(s), about which definitions ship or about their (type, plugin, action) -- a question "
        "the gate cannot see is a question it does not classify; update parse_content_definitions / "
        "definition_fields. First differences:\n" + "\n".join(differing[:10]),
    )


class TestDefinitionWalkParityWithEmbed(unittest.TestCase):
    """Checks 1-5 must see the definitions the server actually ships."""

    def test_gate_walk_sees_exactly_what_embed_content_ingests(self) -> None:
        assert_walk_matches_embed(self, REPO_ROOT)


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

    def test_question_on_a_destructive_row_is_named(self) -> None:
        problems = check_questions(
            [("widget.wipe", "widget", "wipe")], {("widget", "wipe"): "Destructive"}, (), (), 0
        )
        self.assertEqual(len(problems), 1)
        for needle in ("widget.wipe", "DispatchClass::Destructive", "reclassify"):
            self.assertIn(needle, problems[0])

    def test_question_on_a_mutating_row_is_named(self) -> None:
        problems = check_questions([("w.set", "widget", "set")], {("widget", "set"): "Mutating"}, (), (), 0)
        self.assertIn("DispatchClass::Mutating", problems[0])

    def test_readonly_question_with_a_row_is_clean(self) -> None:
        self.assertEqual(
            check_questions([("w.get", "widget", "get")], {("widget", "get"): "ReadOnly"}, (), (), 0), []
        )

    def test_extra_rowless_server_question_is_named(self) -> None:
        questions = [("server.a", "server", "a"), ("server.b", "server", "b")]
        problems = check_questions(questions, {}, ("server.a",), (), 1)
        self.assertEqual(len(problems), 1)
        self.assertIn("UNPINNED ROWLESS QUESTION", problems[0])
        self.assertIn("server.b", problems[0])

    def test_rowless_question_on_a_real_plugin_needs_the_unexplained_pin(self) -> None:
        questions = [("w.ghost", "widget", "ghost")]
        problems = check_questions(questions, {}, ("w.ghost",), (), 1)
        self.assertTrue(any("UNPINNED" in p and "ROWLESS_QUESTION_IDS_UNEXPLAINED" in p for p in problems))
        self.assertTrue(any("STALE ROWLESS PIN" in p for p in problems))
        self.assertEqual(check_questions(questions, {}, (), ("w.ghost",), 1), [])

    def test_pinned_id_that_gained_a_row_or_vanished_is_named(self) -> None:
        gained = check_questions(
            [("server.a", "server", "a")], {("server", "a"): "ReadOnly"}, ("server.a",), (), 1
        )
        self.assertEqual(len(gained), 1)
        self.assertIn("STALE ROWLESS PIN", gained[0])
        vanished = check_questions([], {}, ("server.a",), (), 1)
        self.assertIn("STALE ROWLESS PIN", vanished[0])

    def test_pin_count_and_ordering_are_enforced(self) -> None:
        questions = [("server.a", "server", "a"), ("server.b", "server", "b")]
        self.assertTrue(any("count" in p for p in check_questions(questions, {}, ("server.a", "server.b"), (), 3)))
        self.assertTrue(any("sorted" in p for p in check_questions(questions, {}, ("server.b", "server.a"), (), 2)))


    def test_unexplained_pin_sorting_and_duplicates_are_enforced(self) -> None:
        questions = [("w.a", "widget", "a"), ("w.b", "widget", "b")]
        unsorted = check_questions(questions, {}, (), ("w.b", "w.a"), 2)
        self.assertTrue(any("ROWLESS_QUESTION_IDS_UNEXPLAINED must be sorted" in p for p in unsorted))
        duplicated = check_questions(questions, {}, (), ("w.a", "w.a"), 2)
        self.assertTrue(any("ROWLESS_QUESTION_IDS_UNEXPLAINED must be sorted" in p for p in duplicated))

    def test_unpinned_message_mentions_a_missing_fragment(self) -> None:
        problems = check_questions([("w.a", "widget", "a")], {}, (), (), 0)
        self.assertIn("FRAGMENT_FILES", problems[0])

    def test_not_read_only_message_points_at_the_definition_not_the_row(self) -> None:
        problems = check_questions([("w.x", "widget", "x")], {("widget", "x"): "Mutating"}, (), (), 0)
        self.assertIn("reclassify the definition as `action`", problems[0])
        self.assertIn("security decision", problems[0])

    def test_exact_server_match_rejects_server_prefixed_lookalikes(self) -> None:
        questions = [("s.a", "serverless", "a"), ("s.b", "serverfoo", "b")]
        problems = check_questions(questions, {}, ("s.a", "s.b"), (), 2)
        self.assertEqual(sum("UNPINNED ROWLESS QUESTION" in p for p in problems), 2)
        self.assertTrue(all("ROWLESS_QUESTION_IDS_UNEXPLAINED" in p for p in problems if "UNPINNED" in p))
        self.assertEqual(check_questions(questions, {}, (), ("s.a", "s.b"), 2), [])
        for plugin in SERVER_SIDE_PSEUDO_PLUGINS:
            self.assertEqual(check_questions([("x", plugin, "a")], {}, ("x",), (), 1), [])

    def test_catalogue_and_definition_plugin_case_is_folded(self) -> None:
        rows = [("Widget", "Wipe", "Destructive")]
        by_pair, problems = build_class_by_pair(rows)
        self.assertEqual((by_pair, problems), ({("widget", "wipe"): "Destructive"}, []))
        found = check_questions([("w.wipe", " WIDGET ", "WIPE")], by_pair, (), (), 0)
        self.assertEqual(len(found), 1)
        self.assertIn("DispatchClass::Destructive", found[0])
        # Server-side detection is folded too.
        self.assertEqual(check_questions([("s.a", "Server", "a")], {}, ("s.a",), (), 1), [])

    def test_conflicting_duplicate_catalogue_rows_name_both_classes(self) -> None:
        by_pair, problems = build_class_by_pair(
            [("widget", "wipe", "Destructive"), ("Widget", "WIPE", "ReadOnly")]
        )
        self.assertEqual(len(problems), 1)
        for needle in ("DUPLICATE CATALOGUE ROW", "widget.wipe", "DispatchClass::Destructive", "DispatchClass::ReadOnly"):
            self.assertIn(needle, problems[0])
        # The stricter class survives, so a question on the pair still fails check 4.
        self.assertEqual(by_pair[("widget", "wipe")], "Destructive")

    def test_same_class_duplicate_catalogue_row_is_reported_too(self) -> None:
        _, problems = build_class_by_pair([("w", "a", "ReadOnly"), ("w", "a", "ReadOnly")])
        self.assertEqual(len(problems), 1)
        self.assertIn("DUPLICATE CATALOGUE ROW", problems[0])

    def test_fragment_class_parity_names_file_and_all_counts(self) -> None:
        self.assertIsNone(check_fragment_class_parity("f.hpp", 3, 3, 3))
        for counts, needles in (
            ((2, 3, 3), ("f.hpp", "3 plugin/action pairs", "2 matched", "3 `.plugin =`")),
            ((3, 3, 4), ("f.hpp", "3 plugin/action pairs", "3 matched", "4 `.plugin =`")),
        ):
            msg = check_fragment_class_parity("f.hpp", *counts)
            assert msg is not None
            for needle in needles:
                self.assertIn(needle, msg)

    def test_plugin_server_with_whitespace_is_not_server_side(self) -> None:
        # The catalogue lookup strips; the server-side bucket must not.
        questions = [("s.a", "Server ", "a")]
        problems = check_questions(questions, {}, ("s.a",), (), 1)
        self.assertTrue(any("UNPINNED ROWLESS QUESTION" in p and "ROWLESS_QUESTION_IDS_UNEXPLAINED" in p for p in problems))
        self.assertTrue(any("STALE ROWLESS PIN" in p for p in problems))
        self.assertEqual(check_questions(questions, {}, (), ("s.a",), 1), [])
        # ...but the same padded plugin still finds its catalogue row.
        self.assertEqual(check_questions(questions, {("server", "a"): "ReadOnly"}, (), (), 0), [])

    def test_duplicate_question_ids_are_reported(self) -> None:
        questions = [("w.a", "widget", "a"), ("w.a", "widget", "b")]
        problems = check_questions(questions, {("widget", "a"): "ReadOnly", ("widget", "b"): "ReadOnly"}, (), (), 0)
        self.assertEqual(len(problems), 1)
        self.assertIn("DUPLICATE QUESTION ID: w.a", problems[0])


def _definition_yaml(def_id: str | None, *, kind: str = "InstructionDefinition", type_line: str | None = None,
                     plugin: str = "widget", action: str = "wipe") -> str:
    lines = [f"kind: {kind}", "metadata:"]
    lines.append(f"  id: {def_id}" if def_id else "  displayName: nameless")
    lines.append("spec:")
    if type_line is not None:
        lines.append(f"  {type_line}")
    lines += ["  execution:", f"    plugin: {plugin}", f"    action: {action}"]
    return "\n".join(lines) + "\n"


def _write_tree(root: Path, files: dict[str, str]) -> None:
    for rel, text in files.items():
        path = root / rel
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text, encoding="utf-8")


class TestDefinitionParsingOnSyntheticTrees(unittest.TestCase):
    """The definition walk against fabricated content trees in a temp dir. A tree
    `embed_content.py` accepts is also checked for parity with it (`parity=True`),
    so rglob, typeless and kind behaviour is compared with embed's, not only
    asserted here; malformed trees embed rejects pass `parity=False`.
    """

    def _parse(self, files: dict[str, str], *, parity: bool = True) -> list[tuple[str, str, str]]:
        with tempfile.TemporaryDirectory(prefix="yuzu_test_gate_content_") as td:
            root = Path(td)
            _write_tree(root, {f"content/{rel}": text for rel, text in files.items()})
            if parity:
                assert_walk_matches_embed(self, root)
            return parse_content_questions(root)

    def test_missing_none_and_empty_type_count_as_question(self) -> None:
        docs = "---\n".join([
            _definition_yaml("a.missing"),
            _definition_yaml("a.none", type_line="type: null"),
            _definition_yaml("a.empty", type_line='type: ""'),
            _definition_yaml("a.question", type_line="type: question"),
            _definition_yaml("a.action", type_line="type: action"),
        ])
        got = self._parse({"definitions/x.yaml": docs})
        self.assertEqual(
            sorted(i for i, _, _ in got), ["a.empty", "a.missing", "a.none", "a.question"]
        )

    def test_nested_definitions_and_packs_are_walked(self) -> None:
        got = self._parse({
            "definitions/top.yaml": _definition_yaml("d.top"),
            "definitions/sub/deeper/nested.yaml": _definition_yaml("d.nested"),
            "packs/pack.yaml": _definition_yaml("p.pack"),
            "packs/sub/inner.yaml": _definition_yaml("p.inner"),
            "elsewhere/ignored.yaml": _definition_yaml("z.ignored"),
        })
        self.assertEqual(sorted(i for i, _, _ in got), ["d.nested", "d.top", "p.inner", "p.pack"])

    def test_only_instruction_definitions_are_taken(self) -> None:
        docs = "---\n".join([
            _definition_yaml("k.def"),
            _definition_yaml("k.set", kind="InstructionSet"),
            _definition_yaml("k.pack", kind="ProductPack"),
        ])
        self.assertEqual([i for i, _, _ in self._parse({"packs/mixed.yaml": docs})], ["k.def"])

    def test_plugin_is_kept_as_written_and_action_is_lowercased(self) -> None:
        got = self._parse({"definitions/c.yaml": _definition_yaml("c.one", plugin="Server", action="List")})
        self.assertEqual(got, [("c.one", "Server", "list")])

    def test_malformed_definitions_do_not_crash_and_are_named(self) -> None:
        docs = "---\n".join([
            "kind: InstructionDefinition\nmetadata: {id: m.list}\nspec:\n  execution: [1, 2]\n",
            "kind: InstructionDefinition\nmetadata: {id: m.scalar}\nspec: oops\n",
            "kind: InstructionDefinition\nmetadata: {id: m.nonstr}\n"
            "spec:\n  execution: {plugin: [a, b], action: {x: 1}}\n",
            "kind: InstructionDefinition\nmetadata: oops\nspec: {plugin: p, action: a}\n",
        ])
        got = self._parse({"definitions/bad.yaml": docs}, parity=False)
        self.assertEqual(
            got,
            [
                ("m.list", "", ""),
                ("m.scalar", "", ""),
                ("m.nonstr", "", ""),
                ("content/definitions/bad.yaml#3", "p", "a"),
            ],
        )
        problems = check_questions(got[:3], {}, (), (), 0)
        self.assertEqual(sum("UNPINNED ROWLESS QUESTION" in p for p in problems), 3)
        for def_id in ("m.list", "m.scalar", "m.nonstr"):
            self.assertTrue(any(def_id in p for p in problems))

    def test_idless_definitions_do_not_collapse(self) -> None:
        docs = "---\n".join([_definition_yaml(None), _definition_yaml(None)])
        got = self._parse({"definitions/idless.yaml": docs}, parity=False)
        self.assertEqual([i for i, _, _ in got], ["content/definitions/idless.yaml#0", "content/definitions/idless.yaml#1"])
        self.assertFalse(any("DUPLICATE QUESTION ID" in p for p in check_questions(got, {}, (), (), 0)))

    def test_a_typeless_destructive_question_under_packs_and_nested_definitions_fails(self) -> None:
        got = self._parse({
            "definitions/sub/x.yaml": _definition_yaml("n.wipe"),
            "packs/y.yaml": _definition_yaml("p.wipe"),
        })
        problems = check_questions(got, {("widget", "wipe"): "Destructive"}, (), (), 0)
        self.assertEqual(len(problems), 2)
        self.assertTrue(all("QUESTION IS NOT READ-ONLY" in p for p in problems))

    def test_checks_1_to_3_see_packs_and_nested_definitions(self) -> None:
        def with_mode(def_id: str, mode: str) -> str:
            return _definition_yaml(def_id, plugin="widget", action="wipe") + f"  approval:\n    mode: {mode}\n"

        with tempfile.TemporaryDirectory(prefix="yuzu_test_gate_content_") as td:
            root = Path(td)
            _write_tree(root, {
                "content/definitions/top.yaml": with_mode("d.top", "auto"),
                "content/definitions/sub/nested.yaml": with_mode("d.nested", "role-gated"),
                "content/packs/pack.yaml": with_mode("p.pack", "always"),
            })
            assert_walk_matches_embed(self, root)
            pair_modes = parse_content_pair_modes(root)
            self.assertEqual(sorted(pair_modes), [("widget", "wipe")])
            self.assertEqual(sorted(pair_modes[("widget", "wipe")]), ["always", "auto", "role-gated"])
            mismatches, _ = diff_gates(pair_modes, [("widget", "wipe", "None")])
            self.assertEqual(mismatches, {("widget", "wipe"): ("None", "AlwaysApproval")})

    def test_non_string_column_values_are_found_under_packs(self) -> None:
        doc = _definition_yaml("p.cols") + "  result:\n    columns:\n      - {name: state, values: [enabled, on]}\n"
        with tempfile.TemporaryDirectory(prefix="yuzu_test_gate_content_") as td:
            root = Path(td)
            _write_tree(root, {"content/packs/p.yaml": doc})
            self.assertEqual(find_non_string_column_values(root), ["p.cols.state: True"])


_ROW = '    {{ .plugin = "{plugin}", .action = "{action}", .dispatch_class = DispatchClass::{cls}, }},\n'


class TestQuestionProblemCollectionOnSyntheticTree(unittest.TestCase):
    """`collect_question_problems`, the helper the real-tree test calls, run on a
    fabricated repo: a duplicate catalogue row, a fragment whose counts disagree,
    and a question on a non-ReadOnly row must all come back. This is what makes
    the wiring (not only the pure functions) fail if it is removed."""

    def test_duplicate_row_count_mismatch_and_non_read_only_question_are_all_reported(self) -> None:
        a_rel = f"{DECLS_DIR}/a.hpp"
        b_rel = f"{DECLS_DIR}/b.hpp"
        with tempfile.TemporaryDirectory(prefix="yuzu_test_gate_repo_") as td:
            root = Path(td)
            _write_tree(root, {
                a_rel: _ROW.format(plugin="widget", action="wipe", cls="Destructive")
                + _ROW.format(plugin="Widget", action="WIPE", cls="ReadOnly"),
                # `.plugin = kConst` is matched by neither row regex: 1 `.plugin =`, 0 pairs, 0 classes.
                # A second, ordinary row keeps the pair and class counts at 1 each.
                b_rel: '    { .plugin = kPlugin, .action = "x", .dispatch_class = DispatchClass::ReadOnly, },\n'
                + _ROW.format(plugin="gadget", action="get", cls="ReadOnly"),
                "content/definitions/q.yaml": _definition_yaml("w.wipe", plugin="widget", action="wipe"),
            })
            problems = collect_question_problems(root, [a_rel, b_rel], (), (), 0)
        self.assertTrue(any("DUPLICATE CATALOGUE ROW: widget.wipe" in p for p in problems), problems)
        self.assertTrue(
            any(b_rel in p and "1 plugin/action pairs" in p and "2 `.plugin =`" in p for p in problems), problems
        )
        self.assertFalse(any(a_rel in p and "plugin/action pairs" in p for p in problems), problems)
        self.assertTrue(any("QUESTION IS NOT READ-ONLY" in p and "w.wipe" in p for p in problems), problems)

    def test_clean_tree_reports_nothing_and_an_empty_walk_is_a_problem(self) -> None:
        rel = f"{DECLS_DIR}/a.hpp"
        with tempfile.TemporaryDirectory(prefix="yuzu_test_gate_repo_") as td:
            root = Path(td)
            _write_tree(root, {
                rel: _ROW.format(plugin="widget", action="get", cls="ReadOnly"),
                "content/definitions/q.yaml": _definition_yaml("w.get", plugin="widget", action="get"),
            })
            self.assertEqual(collect_question_problems(root, [rel], (), (), 0), [])
            (root / "content/definitions/q.yaml").unlink()
            self.assertTrue(any("zero question definitions" in p for p in collect_question_problems(root, [rel], (), (), 0)))


class TestFragmentListing(unittest.TestCase):
    def test_extra_missing_and_repeated_fragments_are_named(self) -> None:
        with tempfile.TemporaryDirectory(prefix="yuzu_test_gate_repo_") as td:
            root = Path(td)
            _write_tree(root, {f"{DECLS_DIR}/a.hpp": "", f"{DECLS_DIR}/zz.hpp": ""})
            listed = [f"{DECLS_DIR}/a.hpp", f"{DECLS_DIR}/gone.hpp", f"{DECLS_DIR}/a.hpp"]
            msg = check_fragment_listing(root, listed)
            assert msg is not None
            for needle in (f"{DECLS_DIR}/zz.hpp", f"{DECLS_DIR}/gone.hpp", "listed more than once"):
                self.assertIn(needle, msg)
            self.assertIsNone(check_fragment_listing(root, [f"{DECLS_DIR}/a.hpp", f"{DECLS_DIR}/zz.hpp"]))


if __name__ == "__main__":
    unittest.main()
