#!/usr/bin/env python3
"""Unit tests for tools/plugin-doc-gen/plugin_doc_gen.py's pure functions.

Inline fixtures only — no repository state, no build. The tree-level gate
(every README's fences byte-match the sources, hash freshness, the ratchet)
is tests/test_plugin_readmes.py.
"""
from __future__ import annotations

import sys
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT / "tools" / "plugin-doc-gen"))

import plugin_doc_gen as g  # noqa: E402

MATRIX = """intro text
<!-- BEGIN GENERATED: capmatrix-gen (#2204) — do not hand-edit; regenerate with
     tools/capmatrix-gen, verified by scripts/ci/check-capability-matrix.sh -->
| Plugin | Action | OS | Support | Rung | Mechanism | Fallback |
|---|---|---|---|---|---|---|
| alpha | probe | linux | unsupported | - | - | not bound on any reachable host |
| alpha | probe | macos | constrained | 1 | IOKit thing | identity only |
| alpha | probe | windows | supported | 1 | IOCTL thing | - |
| beta | list | linux | supported | 2 | argv runner | - |
| beta | list | macos | supported | 2 | argv runner | - |
| beta | list | windows | supported | 1 | COM | - |
<!-- END GENERATED -->
| not | a | row | after | the | block | x |
"""

FRAGMENT = """
inline constexpr std::array<CommandCapability, 2> kRows{{
    {
        .plugin = "alpha",
        .action = "probe",
        .dispatch_class = DispatchClass::ReadOnly,
        .mutability = Mutability::None,
        .securable = "Inventory",
        .operation = authz::Operation::Read,
        .risk_tier = authz::RiskTier::Low,
        .system_reserved = false,
        .execute_gate = ExecuteGate::None,
    },
    {
        .plugin = "beta", .action = "list",
        .dispatch_class = DispatchClass::Mutating, .mutability = Mutability::Reversible,
        .securable = "Security", .operation = authz::Operation::Write,
        .risk_tier = authz::RiskTier::High, .execute_gate = ExecuteGate::AdminOrApproval,
    },
}};
"""

PLUGIN_TU = '''
class AlphaPlugin final : public yuzu::Plugin {
public:
    std::string_view name() const noexcept override { return "alpha"; }
    std::string_view version() const noexcept override { return "1.2.3"; }
    std::string_view description() const noexcept override {
        return "Probes things "
               "and reports them";
    }
};
'''

PLUGIN_TU_CONST = '''
namespace { constexpr const char* kName = "gamma"; constexpr const char* kVersion = "0.9.0"; }
class GammaPlugin final : public yuzu::Plugin {
    std::string_view name() const noexcept override { return kName; }
    std::string_view version() const noexcept override { return kVersion; }
};
'''

SAMPLE = """captured: macos 26.5.1 · bare-metal · 2026-09-06 · euid 501 · leg-hash pending
== action=probe
row|one
row|two
[result_status] CONSTRAINED / PARTIAL / macos:iokit:health_unread

== action=danger key=value path="/Applications/Some App"
[not captured] Destructive/Irreversible: not executed on a live host

== action=big
row|x
[truncated] capture hit the LocalDispatcher byte cap
[result_status] OK / FULL / 
[rc] 1
"""

README = r"""# alpha

<!-- BEGIN GENERATED: plugin-doc-gen header -->
old
<!-- END GENERATED -->

## How it works

Reads things.

```mermaid
flowchart LR
  A --> B
```

## OS capability

<!-- BEGIN GENERATED: plugin-doc-gen capability -->
<!-- END GENERATED -->

## Privileges and prerequisites

| OS | Runs as | Extra grant needed | Measured | If the read is refused |
|---|---|---|---|---|
| Windows | svc | none | 2026-09-01 | `error\|com_init` row |

## Data contract

### Outputs

Rows are `kind|a|b`; field 0 is the discriminator.

<!-- BEGIN GENERATED: plugin-doc-gen outputs -->
<!-- END GENERATED -->

### Result status

| Status | Completeness | Provenance | When |
|---|---|---|---|
| `OK` | — | — | clean |

### Where the data goes

- **Instruction result.** store
- **Siblings:** none

## Caveats and known gaps

1. **One.** first
2. **Two.** second
"""


def _defs(columns):
    return [g.Definition(id="x.alpha.probe", display_name="Probe", description="d", plugin="alpha",
                         action="probe", platforms=["windows"], approval_mode="auto",
                         execute_roles=["r"], author_roles=["a"], gather={}, parameters={},
                         columns=columns, path="content/definitions/alpha.yaml")]


class MatrixParsing(unittest.TestCase):
    def test_rows_grouped_and_dashes_blanked(self):
        m = g.parse_matrix_block(MATRIX)
        self.assertEqual(set(m), {"alpha", "beta"})
        leg = m["alpha"]["probe"]["linux"]
        self.assertEqual((leg.support, leg.rung, leg.mechanism), ("unsupported", "", ""))
        self.assertEqual(leg.fallback, "not bound on any reachable host")
        self.assertEqual(m["beta"]["list"]["windows"].mechanism, "COM")

    def test_rows_after_end_marker_are_ignored(self):
        self.assertNotIn("not", g.parse_matrix_block(MATRIX))

    def test_missing_block_raises(self):
        with self.assertRaises(ValueError):
            g.parse_matrix_block("no block here")

    def test_best_support_order(self):
        m = g.parse_matrix_block(MATRIX)
        self.assertEqual(g.best_support(m["alpha"], "windows"), "supported")
        self.assertEqual(g.best_support(m["alpha"], "macos"), "constrained")
        self.assertEqual(g.best_support(m["alpha"], "linux"), "unsupported")
        self.assertEqual(g.best_support({}, "linux"), "undeclared")


class CapabilityParsing(unittest.TestCase):
    def test_rows_and_enum_tails(self):
        rows = g.parse_capability_fragment(FRAGMENT, "frag.hpp")
        self.assertEqual([(r.plugin, r.action) for r in rows], [("alpha", "probe"), ("beta", "list")])
        self.assertEqual(rows[0].securable, "Inventory")
        self.assertEqual(rows[0].operation, "Read")
        self.assertEqual(rows[0].execute_gate, "None")
        self.assertEqual(rows[1].dispatch_class, "Mutating")
        self.assertEqual(rows[1].risk_tier, "High")
        self.assertEqual(rows[1].execute_gate, "AdminOrApproval")


class IdentityParsing(unittest.TestCase):
    def test_literal_identity_with_adjacent_strings(self):
        ident = g.parse_plugin_identity(PLUGIN_TU)
        self.assertEqual(ident, {"name": "alpha", "version": "1.2.3",
                                 "description": "Probes things and reports them"})

    def test_constant_identity_resolved(self):
        ident = g.parse_plugin_identity(PLUGIN_TU_CONST)
        self.assertEqual(ident["name"], "gamma")
        self.assertEqual(ident["version"], "0.9.0")
        self.assertIsNone(ident["description"])


class DefinitionParsing(unittest.TestCase):
    def test_only_definitions_with_plugin_and_action(self):
        docs = [
            {"kind": "InstructionSet", "metadata": {"id": "s"}},
            {"kind": "InstructionDefinition", "metadata": {"id": "x.a", "displayName": "A",
                                                            "description": "multi\n  line"},
             "spec": {"execution": {"plugin": "alpha", "action": "probe"},
                      "platforms": ["windows", "darwin"],
                      "approval": {"mode": "auto"},
                      "permissions": {"executeRoles": ["r1"], "authorRoles": ["a1"]},
                      "gather": {"ttlSeconds": 120},
                      "parameters": {"type": "object", "properties": {"p": {"type": "string"}},
                                     "required": ["p"]},
                      "result": {"columns": [{"name": "c", "type": "string", "values": ["x", "y"],
                                              "example": "x", "platforms": ["windows"]}]}}},
            {"kind": "InstructionDefinition", "metadata": {"id": "bad"}, "spec": {}},
        ]
        defs = g.parse_definition_docs(docs, "content/definitions/alpha.yaml")
        self.assertEqual(len(defs), 1)
        d = defs[0]
        self.assertEqual(d.description, "multi line")
        self.assertEqual(d.columns[0]["values"], ["x", "y"])
        self.assertEqual(d.columns[0]["platforms"], ["windows"])
        self.assertEqual(d.gather, {"ttlSeconds": 120})


class SampleParsing(unittest.TestCase):
    def test_stamp_actions_status_and_not_captured(self):
        s = g.parse_sample(SAMPLE, "macos")
        self.assertEqual(s.stamp["os_version"], "26.5.1")
        self.assertEqual(s.stamp["host_class"], "bare-metal")
        self.assertEqual(s.stamp["privilege"], "euid 501")
        self.assertEqual(s.stamp["leg_hash"], "pending")
        self.assertEqual([a["action"] for a in s.actions], ["probe", "danger", "big"])
        big = s.actions[2]
        self.assertEqual(big["rows"], ["row|x"])
        self.assertTrue(big["truncated"])
        self.assertEqual(big["rc"], 1)
        self.assertEqual(s.actions[0]["rows"], ["row|one", "row|two"])
        self.assertEqual(s.actions[0]["result_status"]["provenance"], "macos:iokit:health_unread")
        self.assertEqual(s.actions[1]["params"], 'key=value path="/Applications/Some App"')
        self.assertEqual(s.actions[1]["not_captured"], "Destructive/Irreversible: not executed on a live host")
        self.assertIsNone(s.actions[1]["result_status"])

    def test_bad_stamp_rejected(self):
        with self.assertRaises(ValueError):
            g.parse_sample("== action=x\nrow\n", "linux")

    def test_trim(self):
        rows = [f"r{i}" for i in range(15)]
        out = g.trim_rows(rows, 12)
        self.assertEqual(len(out), 13)
        self.assertEqual(out[-1], "… 12 of 15 rows shown")
        self.assertEqual(g.trim_rows(rows[:3], 12), rows[:3])


class Splitting(unittest.TestCase):
    def test_escaped_pipe_is_a_literal_cell_character(self):
        self.assertEqual(g.split_md_row("| a | `x\\|y` | c |"), ["a", "`x|y`", "c"])
        self.assertEqual(g.split_md_row("| a | b |"), ["a", "b"])

    def test_matrix_block_honours_capmatrix_escapes(self):
        block = MATRIX.replace("| IOCTL thing | - |", "| IOCTL \\| thing | - |")
        m = g.parse_matrix_block(block)
        self.assertEqual(m["alpha"]["probe"]["windows"].mechanism, "IOCTL | thing")

    def test_capability_row_trailing_comment_and_missing_comma(self):
        frag = """{ .plugin = "z", .action = "q",
            .execute_gate = ExecuteGate::AlwaysApproval, // note
            .securable = "Security" // last field, no comma
        }"""
        rows = g.parse_capability_fragment(frag, "f")
        self.assertEqual(rows[0].execute_gate, "AlwaysApproval")
        self.assertEqual(rows[0].securable, "Security")

    def test_cpp_unescape_keeps_utf8(self):
        self.assertEqual(g._unescape_cpp('Gr\u00f6\u00dfen \\"x\\" a\\\\b'), 'Größen "x" a\\b')


    def test_capability_row_field_value_containing_a_closing_brace(self):
        # PR #4112 review, minor: a `}` inside a quoted field value must not
        # terminate the row early -- the naive first-`}` regex this replaced
        # silently truncated there, defaulting every field after the
        # truncation point (execute_gate included) to '-' with no warning.
        frag = ('{ .plugin = "z", .action = "q", .securable = "Config}Store", '
               '.execute_gate = ExecuteGate::AlwaysApproval }')
        rows = g.parse_capability_fragment(frag, "f")
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0].securable, "Config}Store")
        self.assertEqual(rows[0].execute_gate, "AlwaysApproval")


class LegHash(unittest.TestCase):
    def test_stable_and_sensitive_to_mechanism_not_fallback(self):
        m = g.parse_matrix_block(MATRIX)
        cols = [{"name": "c", "type": "string"}]
        h1 = g.leg_hash(m["alpha"], _defs(cols))
        self.assertEqual(len(h1), 12)
        self.assertEqual(h1, g.leg_hash(m["alpha"], _defs(cols)))
        m["alpha"]["probe"]["windows"].fallback = "reworded"
        self.assertEqual(h1, g.leg_hash(m["alpha"], _defs(cols)))
        m["alpha"]["probe"]["windows"].mechanism = "different"
        self.assertNotEqual(h1, g.leg_hash(m["alpha"], _defs(cols)))

    def test_sensitive_to_column_shape_only(self):
        m = g.parse_matrix_block(MATRIX)
        h1 = g.leg_hash(m["alpha"], _defs([{"name": "c", "type": "string", "example": "1"}]))
        h2 = g.leg_hash(m["alpha"], _defs([{"name": "c", "type": "string", "example": "2"}]))
        h3 = g.leg_hash(m["alpha"], _defs([{"name": "c", "type": "int64"}]))
        self.assertEqual(h1, h2)
        self.assertNotEqual(h1, h3)


class Splicing(unittest.TestCase):
    def test_replace_and_report_missing(self):
        out, missing = g.splice(README, {"header": "NEW", "capability": "CAP"}, g.README_BLOCKS)
        self.assertIn("<!-- BEGIN GENERATED: plugin-doc-gen header -->\nNEW\n<!-- END GENERATED -->", out)
        self.assertIn("<!-- BEGIN GENERATED: plugin-doc-gen capability -->\nCAP\n<!-- END GENERATED -->", out)
        self.assertNotIn("old", out)
        self.assertEqual(missing, ["inputs", "samples", "source"])

    def test_idempotent(self):
        once, _ = g.splice(README, {"header": "NEW"})
        twice, _ = g.splice(once, {"header": "NEW"})
        self.assertEqual(once, twice)


class HandSections(unittest.TestCase):
    def test_sections_split_and_manifest_shape(self):
        sec = g.split_sections(README)
        self.assertIn("## How it works", sec)
        self.assertIn("### Result status", sec)
        m = g.hand_sections_to_manifest(README)
        self.assertEqual(m["how_it_works"], "Reads things.")
        self.assertEqual(m["privileges"], [{"os": "Windows", "runs_as": "svc", "grant": "none",
                                            "measured": "2026-09-01", "if_refused": "`error|com_init` row"}])
        self.assertEqual(m["outputs_note"], "Rows are `kind|a|b`; field 0 is the discriminator.")
        self.assertEqual(m["result_status"][0]["status"], "`OK`")
        self.assertEqual(m["where_the_data_goes"], ["**Instruction result.** store", "**Siblings:** none"])
        self.assertEqual(m["caveats"], ["**One.** first", "**Two.** second"])

    def test_fenced_headings_are_not_sections(self):
        text = "## Real\n\n```\n## not a heading\n```\n\n## Other\nx"
        self.assertEqual(set(g.split_sections(text)), {"## Real", "## Other"})


class Rendering(unittest.TestCase):
    def _doc(self):
        m = g.parse_matrix_block(MATRIX)
        rows = g.parse_capability_fragment(FRAGMENT, "frag.hpp")
        return g.PluginDoc(name="alpha", version="1.2.3", description="Probes",
                           legs=m["alpha"], cap_rows=[r for r in rows if r.plugin == "alpha"],
                           definitions=_defs([{"name": "c", "type": "string", "values": ["x"],
                                               "example": "x", "platforms": ["darwin"],
                                               "description": "col"}]),
                           samples={"macos": g.parse_sample(SAMPLE, "macos")},
                           source={"plugin": ["agents/plugins/alpha/src/a.cpp"], "definitions": [],
                                   "capability_rows": ["frag.hpp"], "tests": [], "privilege_row": False,
                                   "changelog": []},
                           readme_path="agents/plugins/alpha/README.md")

    def test_header_platforms_and_security(self):
        h = g.render_header(self._doc())
        self.assertIn("Windows ✅ · macOS 🟡 constrained · Linux ⛔ unsupported", h)
        self.assertIn("securable `Inventory` · operation Read · risk Low · dispatch ReadOnly · approval gate None", h)
        self.assertIn("Collector · read-only · on-demand", h)
        self.assertIn("`probe` (definition `x.alpha.probe`)", h)

    def test_capability_matrix_and_limits(self):
        c = g.render_capability(self._doc())
        self.assertIn("| `probe` | ✅ supported · rung 1 · IOCTL thing | 🟡 constrained · rung 1 · IOKit thing | ⛔ unsupported |", c)
        self.assertIn("- **`probe` / Linux** — not bound on any reachable host", c)

    def test_outputs_table_uses_optional_keys(self):
        o = g.render_outputs(self._doc())
        self.assertIn("**`x.alpha.probe` — `c`**", o)
        self.assertIn("| `c` | string | `x` | macOS | `x` | col |", o)

    def test_inputs_none(self):
        self.assertEqual(g.render_inputs(self._doc()), "The action takes no parameters.")

    def test_samples_block_and_not_captured(self):
        s = g.render_samples(self._doc())
        self.assertIn("**macOS** — captured: macos 26.5.1 · bare-metal · 2026-09-06 · euid 501 · leg-hash pending", s)
        self.assertIn("== action=probe\nrow|one\nrow|two\n[result_status] CONSTRAINED / PARTIAL / macos:iokit:health_unread", s)
        self.assertIn('== action=danger key=value path="/Applications/Some App"\n[not captured] Destructive/Irreversible', s)

    def test_manifest_round_trip(self):
        doc = self._doc()
        m = g.build_manifest(doc, README)
        self.assertEqual(m["manifest_version"], g.MANIFEST_VERSION)
        self.assertEqual(m["platforms"], {"windows": "supported", "macos": "constrained", "linux": "unsupported"})
        self.assertEqual(m["security"][0]["securable"], "Inventory")
        self.assertEqual(m["actions"][0]["legs"]["macos"]["mechanism"], "IOKit thing")
        self.assertEqual(m["how_it_works"], "Reads things.")
        self.assertEqual(m["samples"]["macos"]["actions"][1]["not_captured"],
                         "Destructive/Irreversible: not executed on a live host")
        self.assertEqual(m["leg_hash"], g.leg_hash(doc.legs, doc.definitions))

    def test_index_and_nav(self):
        idx = g.render_index([self._doc()])
        self.assertIn("| `alpha` | ✅ 🟡 ⛔ | Probes | [README](../../agents/plugins/alpha/README.md) |", idx)
        nav = g.render_nav([self._doc()])
        self.assertIn("{ file: 'agents/plugins/alpha/README', slug: 'plugins/alpha', title: 'alpha' }", nav)


class CommentLedRows(unittest.TestCase):
    def test_comment_between_brace_and_plugin_is_not_a_row_boundary(self):
        # 14 of the 193 shipped rows open with a rationale comment on the line
        # after `{`; the parser used to skip every one of them silently.
        frag = """
inline constexpr std::array<CommandCapability, 2> kRows{{
    {
        // Overwrites the file in place — Irreversible, not Reversible.
        .plugin = "gamma", .action = "write",
        .dispatch_class = DispatchClass::Destructive, .mutability = Mutability::Irreversible,
        .securable = "Filesystem", // the fs securable
        .operation = authz::Operation::Write, .risk_tier = authz::RiskTier::High,
        .execute_gate = ExecuteGate::AlwaysApproval,
    },
    {
        .plugin = "gamma", .action = "read",
        .dispatch_class = DispatchClass::ReadOnly, .mutability = Mutability::None,
        .securable = "Filesystem", .operation = authz::Operation::Read,
        .risk_tier = authz::RiskTier::Low, .execute_gate = ExecuteGate::None,
    },
}};
"""
        rows = g.parse_capability_fragment(frag, "frag.hpp")
        self.assertEqual([(r.action, r.dispatch_class, r.securable) for r in rows],
                         [("write", "Destructive", "Filesystem"), ("read", "ReadOnly", "Filesystem")])


class TruncatedSamples(unittest.TestCase):
    def test_action_without_status_line_is_rejected(self):
        # A short write (disk full) leaves the last action without its
        # [result_status] line; the file must not parse as a whole capture.
        cut = SAMPLE.split("[result_status] CONSTRAINED")[0]
        with self.assertRaisesRegex(ValueError, "probe.*no \\[result_status\\] line"):
            g.parse_sample(cut, "macos")

    def test_not_captured_marker_needs_no_status_line(self):
        s = g.parse_sample(SAMPLE, "macos")
        self.assertIsNone(s.actions[1]["result_status"])
        self.assertTrue(s.actions[1]["not_captured"])

    def test_stamp_only_file_is_rejected(self):
        with self.assertRaisesRegex(ValueError, "no `== action=` block"):
            g.parse_sample(SAMPLE.splitlines()[0] + "\n", "macos")


class ColumnDocKeys(unittest.TestCase):
    def _doc(self, column):
        return [{"kind": "InstructionDefinition", "metadata": {"id": "x.a"},
                 "spec": {"execution": {"plugin": "alpha", "action": "probe"},
                          "result": {"columns": [column]}}}]

    def test_scalar_platforms_rejected(self):
        with self.assertRaisesRegex(ValueError, "x.a.c: `platforms` must be a list"):
            g.parse_definition_docs(self._doc({"name": "c", "type": "string", "platforms": "windows"}), "p.yaml")

    def test_unknown_platform_rejected(self):
        with self.assertRaisesRegex(ValueError, "not \\['macos'\\]"):
            g.parse_definition_docs(self._doc({"name": "c", "type": "string", "platforms": ["macos"]}), "p.yaml")

    def test_values_only_on_string_columns(self):
        with self.assertRaisesRegex(ValueError, "only meaningful on a string column"):
            g.parse_definition_docs(self._doc({"name": "n", "type": "int64", "values": [1, 2]}), "p.yaml")

    def test_well_formed_keys_pass(self):
        defs = g.parse_definition_docs(self._doc({"name": "c", "type": "string", "values": ["a", "b"],
                                                  "example": "a", "platforms": ["windows", "darwin"],
                                                  "description": "d"}), "p.yaml")
        self.assertEqual(defs[0].columns[0]["platforms"], ["windows", "darwin"])


class InputsRendering(unittest.TestCase):
    def _doc(self):
        d = _defs([])[0]
        d.parameters = {"type": "object", "required": ["mode"], "properties": {
            "mode": {"type": "string", "description": "Startup mode",
                     "validation": {"enum": ["automatic", "manual"]}},
            "name": {"type": "string", "description": "Unit name",
                     "validation": {"minLength": 1, "maxLength": 256, "pattern": "^[a-z.]+$"}},
            "dry_run": {"type": "boolean", "default": False, "description": "Plan only"},
        }}
        m = g.parse_matrix_block(MATRIX)
        return g.PluginDoc(name="alpha", version="1", description="P", legs=m["alpha"], cap_rows=[],
                           definitions=[d], samples={}, source={}, readme_path="agents/plugins/alpha/README.md")

    def test_constraints_column_and_yaml_scalars(self):
        table = g.render_inputs(self._doc())
        self.assertIn("| Definition | Parameter | Type | Required | Default | Constraints | Description |", table)
        self.assertIn("| `x.alpha.probe` | `mode` | string | yes | - | enum: automatic, manual | Startup mode |", table)
        self.assertIn("| pattern: ^[a-z.]+$ · minLength 1 · maxLength 256 |", table)
        self.assertIn("| `dry_run` | boolean | no | false | - | Plan only |", table)

    def test_manifest_carries_constraints(self):
        m = g.build_manifest(self._doc(), README)
        by_name = {i["name"]: i for i in m["inputs"]}
        self.assertEqual(by_name["mode"]["constraints"], {"enum": ["automatic", "manual"]})
        self.assertIsNone(by_name["dry_run"]["constraints"])
        self.assertIs(by_name["dry_run"]["default"], False)


class ManifestKeySet(unittest.TestCase):
    def test_build_manifest_emits_exactly_the_declared_keys(self):
        doc = Rendering()._doc()
        self.assertEqual(set(g.build_manifest(doc, README)), set(g.MANIFEST_KEYS))


class DefinitionShapes(unittest.TestCase):
    def _doc(self, **spec):
        base = {"execution": {"plugin": "alpha", "action": "probe"}}
        base.update(spec)
        return [{"kind": "InstructionDefinition", "metadata": {"id": "x.a"}, "spec": base}]

    def test_scalar_platforms_and_roles_rejected(self):
        with self.assertRaisesRegex(ValueError, "x.a: spec.platforms must be a list, not str"):
            g.parse_definition_docs(self._doc(platforms="windows"), "p.yaml")
        with self.assertRaisesRegex(ValueError, "spec.permissions.executeRoles must be a list"):
            g.parse_definition_docs(self._doc(permissions={"executeRoles": "endpoint-admin"}), "p.yaml")

    def test_scalar_columns_and_list_parameters_rejected(self):
        with self.assertRaisesRegex(ValueError, "spec.result.columns must be a list"):
            g.parse_definition_docs(self._doc(result={"columns": "kind"}), "p.yaml")
        with self.assertRaisesRegex(ValueError, "spec.parameters must be an object"):
            g.parse_definition_docs(self._doc(parameters=["a", "b"]), "p.yaml")
        with self.assertRaisesRegex(ValueError, "every spec.result.columns entry must be an object"):
            g.parse_definition_docs(self._doc(result={"columns": [7]}), "p.yaml")


class SampleSanity(unittest.TestCase):
    def test_stamp_os_must_match_the_file(self):
        with self.assertRaisesRegex(ValueError, "stamp says os 'macos' but the file is windows.txt"):
            g.parse_sample(SAMPLE, "windows")

    def test_host_class_is_closed(self):
        with self.assertRaisesRegex(ValueError, "host class 'laptop' is not one of"):
            g.parse_sample(SAMPLE.replace("bare-metal", "laptop", 1), "macos")

    def test_not_captured_class_is_closed(self):
        bad = SAMPLE.replace("[not captured] Destructive/Irreversible: not executed on a live host",
                             "[not captured] whatever")
        with self.assertRaisesRegex(ValueError, "must read .*agent-context.*hardware-absent"):
            g.parse_sample(bad, "macos")
        ok = SAMPLE.replace("Destructive/Irreversible: not executed on a live host",
                            "agent-context: init needs the KV store")
        self.assertEqual(g.parse_sample(ok, "macos").actions[1]["not_captured"],
                         "agent-context: init needs the KV store")

    def test_not_captured_block_with_row_or_status_data_is_rejected(self):
        # PR #4112 review, minor: [not captured] (never executed) and
        # row/status/rc data (only producible by an executed run) are
        # mutually exclusive -- a block claiming both is self-contradictory.
        with_row = SAMPLE.replace(
            "[not captured] Destructive/Irreversible: not executed on a live host",
            "[not captured] Destructive/Irreversible: not executed on a live host\nrow|unexpected")
        with self.assertRaisesRegex(ValueError, "has `\\[not captured\\]` but also carries"):
            g.parse_sample(with_row, "macos")

        with_status = SAMPLE.replace(
            "[not captured] Destructive/Irreversible: not executed on a live host",
            "[not captured] Destructive/Irreversible: not executed on a live host\n"
            "[result_status] OK / FULL / ")
        with self.assertRaisesRegex(ValueError, "has `\\[not captured\\]` but also carries"):
            g.parse_sample(with_status, "macos")

        with_rc = SAMPLE.replace(
            "[not captured] Destructive/Irreversible: not executed on a live host",
            "[not captured] Destructive/Irreversible: not executed on a live host\n[rc] 1")
        with self.assertRaisesRegex(ValueError, "has `\\[not captured\\]` but also carries"):
            g.parse_sample(with_rc, "macos")

    def test_marker_before_any_action_and_duplicate_action_rejected(self):
        lines = SAMPLE.splitlines()
        with self.assertRaisesRegex(ValueError, "before any `== action=`"):
            g.parse_sample(lines[0] + "\n[not captured] agent-context: x\n" + "\n".join(lines[1:]) + "\n", "macos")
        dup = SAMPLE + "== action=probe\nrow|again\n[result_status] OK / FULL / \n"
        with self.assertRaisesRegex(ValueError, "action 'probe' appears twice"):
            g.parse_sample(dup, "macos")


class ShapeChecks(unittest.TestCase):
    def test_structural_lints(self):
        problems = g.readme_shape_problems(README, "alpha", "agents/plugins/alpha/README.md", ["windows:x:denied"])
        joined = "\n".join(problems)
        # The fixture README has one privileges row, two caveats, two bullets, no
        # inputs/samples/source fences, and no `windows:x:denied` in Result status.
        self.assertIn("has no macOS row", joined)
        self.assertIn("has no Linux row", joined)
        self.assertIn("does not name it", joined)
        self.assertNotIn("Caveats and known gaps' has", joined)
        self.assertNotIn("Where the data goes' needs", joined)

    def test_index_total_caption(self):
        idx = g.render_index([Rendering()._doc()], 51)
        self.assertTrue(idx.startswith("1 of 51 plugins document themselves this way"))


class ValidationShapes(unittest.TestCase):
    def _doc(self, validation):
        return [{"kind": "InstructionDefinition", "metadata": {"id": "x.a"},
                 "spec": {"execution": {"plugin": "alpha", "action": "probe"},
                          "parameters": {"type": "object", "properties": {"mode": {"type": "string", "validation": validation}}}}}]

    def test_validation_block_shape(self):
        with self.assertRaisesRegex(ValueError, "'mode': validation must be an object"):
            g.parse_definition_docs(self._doc("x"), "p.yaml")
        with self.assertRaisesRegex(ValueError, "validation.enum must be a list"):
            g.parse_definition_docs(self._doc({"enum": "x"}), "p.yaml")
        self.assertEqual(len(g.parse_definition_docs(self._doc({"enum": ["a"], "minLength": 1}), "p.yaml")), 1)


class DuplicateIds(unittest.TestCase):
    def test_duplicate_definition_id_across_files_is_an_error(self):
        import tempfile, shutil
        tmp = Path(tempfile.mkdtemp(prefix="yuzu_test_dupids_"))
        self.addCleanup(shutil.rmtree, tmp, ignore_errors=True)
        (tmp / "content" / "definitions").mkdir(parents=True)
        body = "---\nkind: InstructionDefinition\nmetadata: {id: x.dup}\nspec:\n  execution: {plugin: alpha, action: probe}\n"
        (tmp / "content" / "definitions" / "a.yaml").write_text(body, encoding="utf-8")
        (tmp / "content" / "definitions" / "b.yaml").write_text(body, encoding="utf-8")
        with self.assertRaisesRegex(ValueError, "b.yaml: definition id 'x.dup' is already defined in content/definitions/a.yaml"):
            g.load_definitions(tmp)


class StructuralLintsPositive(unittest.TestCase):
    def test_caveat_count_lead_and_bullets(self):
        many = README.replace("1. **One.** first\n2. **Two.** second",
                              "\n".join(f"{i}. **C{i}.** x" for i in range(1, 7)))
        self.assertTrue(any("has 6 items; the contract is 1–5" in p
                            for p in g.readme_shape_problems(many, "alpha", "r.md")))
        plain = README.replace("1. **One.** first", "1. One. first")
        self.assertTrue(any("does not open with a bold lead" in p
                            for p in g.readme_shape_problems(plain, "alpha", "r.md")))
        one_bullet = README.replace("- **Siblings:** none\n", "")
        self.assertTrue(any("needs at least the instruction-result bullet" in p
                            for p in g.readme_shape_problems(one_bullet, "alpha", "r.md")))
        self.assertTrue(any("no '**Sensitivity.**' bullet" in p
                            for p in g.readme_shape_problems(README, "alpha", "r.md")))


class MarkerBinding(unittest.TestCase):
    def test_marker_class_must_match_the_capability_row(self):
        doc = Rendering()._doc()  # alpha: probe is ReadOnly/None; sample marks `danger` Destructive/Irreversible
        problems = g.sample_coverage_problems(doc)
        self.assertTrue(any("`[not captured] Destructive/Irreversible:` on action 'danger' — the capability row says no row"
                            in p for p in problems), problems)
        s = g.parse_sample(SAMPLE.replace("== action=danger key=value path=\"/Applications/Some App\"", "== action=probe2"), "macos")
        doc.samples = {"macos": s}
        doc.cap_rows = list(doc.cap_rows) + [g.CapRow(plugin="alpha", action="probe2", dispatch_class="Destructive",
                                                       mutability="Irreversible", securable="S", operation="Write",
                                                       risk_tier="High", execute_gate="AlwaysApproval", fragment="f")]
        self.assertFalse([p for p in g.sample_coverage_problems(doc) if "probe2" in p and "[not captured]" in p])


if __name__ == "__main__":
    unittest.main()
