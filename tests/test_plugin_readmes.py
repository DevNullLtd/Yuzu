#!/usr/bin/env python3
"""Plugin README gate (docs/plugin-readme-standard.md) — meson `docs` suite.

Hermetic: parses the checked-in tree, builds nothing. Enforces:

1. README-existence ratchet — the number of agents/plugins/<x>/ directories
   WITHOUT a README.md may equal or fall below RATCHET_BASELINE_MISSING, never
   rise. Lower the baseline in the same PR that adds READMEs (PR D.2 takes it
   to 0); raising it means a plugin directory landed undocumented, which is
   exactly the regression this gate exists to block.
2. For every README present: the seven `##` section headings in order (the
   title block is the standard's eighth section), the Data-contract
   subsections in order, hand-written sections non-empty, all six generated
   fences present, hand tables at their contracted width.
3. Generated artefacts byte-match the sources (README fences, the catalog
   index, the site nav fragment, the content/plugin-docs manifests) — the same
   contract scripts/ci/check-capability-matrix.sh enforces for the capability
   matrix, delegated to plugin_doc_gen.check_repo.
4. Samples: every (action, OS) leg the descriptor declares supported or
   constrained is captured — or explicitly `[not captured]` — in a parseable
   docs/samples/<os>.txt whose leg-hash is current or `pending`.
5. The manifest's key set equals the schema table in the standard.

The checks are functions over a repository root so the GateSelfTest at the
bottom can drive every failure branch on a synthetic tree — the committed
tree only ever exercises the passing path.
"""
from __future__ import annotations

import re
import shutil
import sys
import tempfile
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT / "tools" / "plugin-doc-gen"))

import plugin_doc_gen as g  # noqa: E402

# Every plugin directory minus the pilots (disk_actions, firewall). DECREASE
# this as READMEs land; it cannot be increased without a reviewed decision.
RATCHET_BASELINE_MISSING = 0

def missing_readmes(repo: Path) -> list[str]:
    return [n for n in g.plugin_dirs(repo) if not (repo / "agents" / "plugins" / n / "README.md").exists()]


def readme_problems(repo: Path, name: str) -> list[str]:
    """Rule 2 / rule 10 shape checks for one README (plugin_doc_gen owns them
    so `--check` is the same gate); empty when it conforms."""
    path = repo / "agents" / "plugins" / name / "README.md"
    return g.readme_shape_problems(path.read_text(encoding="utf-8"), name,
                                   path.relative_to(repo).as_posix(), g.provenance_literals(repo, name))


def sample_problems(repo: Path, matrix: dict, name: str) -> list[str]:
    """Rule 5, per leg, on the parsed samples of one plugin."""
    doc = g.load_plugin(repo, name, matrix, g.load_definitions(repo), g.load_capability_rows(repo))
    return [w for w in doc.warnings if w.startswith("error:")] + g.sample_coverage_problems(doc)


def standard_manifest_keys(repo: Path) -> set[str]:
    """The keys the standard's "Manifest schema" table documents."""
    text = (repo / "docs" / "plugin-readme-standard.md").read_text(encoding="utf-8")
    start = text.find("## Manifest schema")
    if start < 0:
        return set()
    end = text.find("\n## ", start + 1)
    keys: set[str] = set()
    for row in g.parse_md_table(text[start:end if end > 0 else len(text)]):
        keys.update(re.findall(r"`([a-z_]+)`", row[0]))
    return keys


class Ratchet(unittest.TestCase):
    def test_missing_readme_count_never_grows(self):
        missing = missing_readmes(REPO_ROOT)
        self.assertLessEqual(
            len(missing), RATCHET_BASELINE_MISSING,
            f"{len(missing)} plugin directories have no README.md (baseline "
            f"{RATCHET_BASELINE_MISSING}): {sorted(missing)}. A new plugin ships with "
            "agents/plugins/<name>/README.md per docs/plugin-readme-standard.md.")
        if len(missing) < RATCHET_BASELINE_MISSING:
            self.fail(
                f"only {len(missing)} plugin directories lack a README — lower "
                f"RATCHET_BASELINE_MISSING in tests/test_plugin_readmes.py to {len(missing)} "
                "in this PR so the gate keeps ratcheting down.")


class ReadmeShape(unittest.TestCase):
    def test_every_readme_follows_the_section_contract(self):
        problems = [p for name in g.documented_plugins(REPO_ROOT) for p in readme_problems(REPO_ROOT, name)]
        self.assertFalse(problems, "\n".join(problems))


class GeneratedArtefacts(unittest.TestCase):
    def test_fences_index_nav_and_manifests_are_current(self):
        errors, warnings = g.check_repo(REPO_ROOT)
        for w in warnings:
            print(f"warning: {w}", file=sys.stderr)
        self.assertFalse(errors, "\n\n".join(errors))

    def test_manifest_keys_match_the_standard(self):
        documented = standard_manifest_keys(REPO_ROOT)
        self.assertTrue(documented, "docs/plugin-readme-standard.md has no Manifest schema table")
        self.assertEqual(documented, set(g.MANIFEST_KEYS),
                         "docs/plugin-readme-standard.md's Manifest schema table and "
                         "plugin_doc_gen.MANIFEST_KEYS disagree — update both in the same change")


class Samples(unittest.TestCase):
    def test_every_supported_leg_has_a_capture(self):
        matrix = g.parse_matrix_block((REPO_ROOT / "docs" / "os-capability-matrix.md").read_text(encoding="utf-8"))
        problems = [p for name in g.documented_plugins(REPO_ROOT) for p in sample_problems(REPO_ROOT, matrix, name)]
        self.assertFalse(problems, "\n".join(problems))


# ── self-test on a synthetic tree ─────────────────────────────────────────────

_SYNTH_MATRIX = """# OS capability matrix
<!-- BEGIN GENERATED: capmatrix-gen (#2204) — do not hand-edit -->
| Plugin | Action | OS | Support | Rung | Mechanism | Fallback |
|---|---|---|---|---|---|---|
| alpha | probe | linux | unsupported | - | - | not bound |
| alpha | probe | macos | constrained | 1 | IOKit thing | identity only |
| alpha | probe | windows | supported | 1 | IOCTL thing | - |
| alpha | wipe | linux | unsupported | - | - | - |
| alpha | wipe | macos | unsupported | - | - | - |
| alpha | wipe | windows | supported | 1 | DeviceIoControl | - |
<!-- END GENERATED -->
"""

_SYNTH_FRAGMENT = """
inline constexpr std::array<CommandCapability, 2> kRows{{
    {
        .plugin = "alpha", .action = "probe",
        .dispatch_class = DispatchClass::ReadOnly, .mutability = Mutability::None,
        .securable = "Inventory", .operation = authz::Operation::Read,
        .risk_tier = authz::RiskTier::Low, .execute_gate = ExecuteGate::None,
    },
    {
        // Destroys data — never captured on a live host.
        .plugin = "alpha", .action = "wipe",
        .dispatch_class = DispatchClass::Destructive, .mutability = Mutability::Irreversible,
        .securable = "Filesystem", .operation = authz::Operation::Write,
        .risk_tier = authz::RiskTier::High, .execute_gate = ExecuteGate::AlwaysApproval,
    },
}};
"""

_SYNTH_TU = """
class AlphaPlugin final : public yuzu::Plugin {
public:
    std::string_view name() const noexcept override { return "alpha"; }
    std::string_view version() const noexcept override { return "1.2.3"; }
    std::string_view description() const noexcept override { return "Probes things"; }
};
"""

_SYNTH_YAML = """---
apiVersion: yuzu.io/v1alpha1
kind: InstructionDefinition
metadata:
  id: x.alpha.probe
  displayName: Probe
  description: Probes a thing.
spec:
  execution: {plugin: alpha, action: probe}
  platforms: [windows, darwin]
  approval: {mode: auto}
  permissions: {executeRoles: [endpoint-admin], authorRoles: [endpoint-admin]}
  parameters:
    type: object
    properties:
      mode: {type: string, description: Mode, validation: {enum: [fast, full]}}
  result:
    columns:
      - {name: kind, type: string, values: [probe], example: probe, description: Row kind}
      - {name: value, type: string, description: The value}
"""

_SYNTH_README = """# alpha

<!-- BEGIN GENERATED: plugin-doc-gen header -->
<!-- END GENERATED -->

## How it works

Reads things.

## OS capability

<!-- BEGIN GENERATED: plugin-doc-gen capability -->
<!-- END GENERATED -->

## Privileges and prerequisites

| OS | Runs as | Extra grant needed | Measured | If the read is refused |
|---|---|---|---|---|
| Windows | svc | none | 2026-09-01 | `error\\|com_init` row |
| macOS | daemon | none | 2026-09-01 | `error\\|iokit` row |
| Linux | n/a | n/a | — | always `UNAVAILABLE` |

## Data contract

### Inputs

<!-- BEGIN GENERATED: plugin-doc-gen inputs -->
<!-- END GENERATED -->

### Outputs

Rows are `kind|value`.

<!-- BEGIN GENERATED: plugin-doc-gen outputs -->
<!-- END GENERATED -->

### Result status

| Status | Completeness | Provenance | When |
|---|---|---|---|
| `OK` | — | — | clean |

### Where the data goes

- **Instruction result.** store
- **Not consumed by** anything else.
- **Sensitivity.** nothing beyond the device id.

## Sample output

<!-- BEGIN GENERATED: plugin-doc-gen samples -->
<!-- END GENERATED -->

## Caveats and known gaps

1. **One.** first

## Source and tests

<!-- BEGIN GENERATED: plugin-doc-gen source -->
<!-- END GENERATED -->
"""

_SYNTH_SAMPLE = """captured: {os} 1.0 · vm · 2026-09-06 · euid 0 · leg-hash pending
== action=probe
probe|one
[result_status] OK / FULL / 

== action=wipe
[not captured] Destructive/Irreversible: not executed on a live host

"""

_SYNTH_CATALOG = """# Agent plugins

<!-- BEGIN GENERATED: plugin-doc-gen index -->
<!-- END GENERATED -->
"""


def _write(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8", newline="\n")


def make_synthetic_repo(root: Path) -> None:
    _write(root / "docs" / "os-capability-matrix.md", _SYNTH_MATRIX)
    _write(root / "docs" / "plugin-readme-standard.md", "## Manifest schema\n\n| Key | From | Shape |\n|---|---|---|\n"
           + "".join(f"| `{k}` | x | y |\n" for k in sorted(g.MANIFEST_KEYS)))
    _write(root / "server" / "core" / "src" / "capability_decls" / "plugin_action_catalogue_x.hpp", _SYNTH_FRAGMENT)
    _write(root / "agents" / "plugins" / "alpha" / "src" / "alpha_plugin.cpp", _SYNTH_TU)
    _write(root / "agents" / "plugins" / "alpha" / "README.md", _SYNTH_README)
    for os_name in ("windows", "macos"):
        _write(root / "agents" / "plugins" / "alpha" / "docs" / "samples" / f"{os_name}.txt",
               _SYNTH_SAMPLE.format(os=os_name))
    _write(root / "content" / "definitions" / "alpha.yaml", _SYNTH_YAML)
    _write(root / "docs" / "user-manual" / "agent-plugins.md", _SYNTH_CATALOG)
    (root / "tests").mkdir()
    (root / "changelog.d").mkdir()
    (root / "site" / "src").mkdir(parents=True)


class GateSelfTest(unittest.TestCase):
    """Every failure branch of the gate, driven on a synthetic tree (the
    committed tree only exercises the passing path)."""

    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp(prefix="yuzu_test_readme_gate_"))
        self.addCleanup(shutil.rmtree, self.tmp, ignore_errors=True)
        make_synthetic_repo(self.tmp)
        self.readme = self.tmp / "agents" / "plugins" / "alpha" / "README.md"
        self.macos = self.tmp / "agents" / "plugins" / "alpha" / "docs" / "samples" / "macos.txt"
        self.matrix_path = self.tmp / "docs" / "os-capability-matrix.md"

    def _matrix(self):
        return g.parse_matrix_block(self.matrix_path.read_text(encoding="utf-8"))

    def _edit(self, path: Path, old: str, new: str, count: int = 1):
        text = path.read_text(encoding="utf-8")
        self.assertIn(old, text)
        _write(path, text.replace(old, new, count))

    def test_generate_apply_check_and_stamp(self):
        # Fresh tree: everything generated is stale, so check reports a diff
        # for every artefact, and generate/apply then makes it current.
        errors, _ = g.check_repo(self.tmp)
        self.assertTrue(any("agents/plugins/alpha/README.md: generated content differs" in e for e in errors))
        self.assertTrue(any("content/plugin-docs/alpha.json" in e for e in errors))
        self.assertTrue(any("site/src/nav.plugins.mjs" in e for e in errors))
        outcome = g.generate(self.tmp)
        self.assertFalse(outcome.errors, outcome.errors)
        g.apply(self.tmp, outcome)
        errors, warnings = g.check_repo(self.tmp)
        self.assertFalse(errors, errors)
        self.assertEqual(sorted(w for w in warnings if "pending" in w),
                         ["alpha/macos: capture stamp leg-hash pending (run --stamp after capture)",
                          "alpha/windows: capture stamp leg-hash pending (run --stamp after capture)"])
        self.assertEqual(g.generate(self.tmp).changed, {}, "second run is not idempotent")
        # Generated content spot-checks on the real renderers.
        readme = self.readme.read_text(encoding="utf-8")
        self.assertIn("| `probe` | ✅ supported · rung 1 · IOCTL thing |", readme)
        self.assertIn("| `x.alpha.probe` | `mode` | string | no | - | enum: fast, full | Mode |", readme)
        self.assertIn("**macOS** — captured: macos 1.0 · vm · 2026-09-06 · euid 0 · leg-hash pending", readme)
        # Stamp: the hash lands; the README's samples block and the manifest
        # carry the stamp, so one more --all makes the tree current again
        # (the documented order: capture, --stamp, --all, --check).
        h = g.stamp(self.tmp, "alpha", "macos")
        self.assertRegex(h, r"^[0-9a-f]{12}$")
        self.assertIn(f"leg-hash {h}\n", self.macos.read_text(encoding="utf-8"))
        errors, _ = g.check_repo(self.tmp)
        self.assertTrue(any(f"+**macOS** — captured: macos 1.0 · vm · 2026-09-06 · euid 0 · leg-hash {h}" in e
                            for e in errors), errors)
        g.apply(self.tmp, g.generate(self.tmp))
        errors, warnings = g.check_repo(self.tmp)
        self.assertFalse(errors, errors)
        self.assertFalse(any("alpha/macos" in w for w in warnings))
        self.assertTrue(any("alpha/windows" in w and "pending" in w for w in warnings))
        with self.assertRaisesRegex(ValueError, "no such plugin directory"):
            g.stamp(self.tmp, "../etc", "macos")
        with self.assertRaisesRegex(ValueError, "OS must be one of"):
            g.stamp(self.tmp, "alpha", "solaris")
        # The gate's own checks pass on the generated tree, and the manifest
        # keys are the standard's.
        self.assertEqual(readme_problems(self.tmp, "alpha"), [])
        self.assertEqual(sample_problems(self.tmp, self._matrix(), "alpha"), [])
        self.assertEqual(standard_manifest_keys(self.tmp), set(g.MANIFEST_KEYS))

    def _generated(self):
        outcome = g.generate(self.tmp)
        self.assertFalse(outcome.errors, outcome.errors)
        g.apply(self.tmp, outcome)
        g.stamp(self.tmp, "alpha", "macos")
        g.stamp(self.tmp, "alpha", "windows")
        g.apply(self.tmp, g.generate(self.tmp))
        self.assertEqual(g.check_repo(self.tmp)[0], [])

    def test_hand_edit_inside_a_fence_is_a_diff(self):
        self._generated()
        self._edit(self.readme, "IOCTL thing", "hand-typed mechanism")
        errors, _ = g.check_repo(self.tmp)
        self.assertEqual(len(errors), 1)
        self.assertIn("agents/plugins/alpha/README.md: generated content differs — run plugin_doc_gen.py --all", errors[0])
        self.assertIn("-| `probe` | ✅ supported · rung 1 · hand-typed mechanism |", errors[0])

    def test_mechanism_change_stales_the_capture(self):
        self._generated()
        self._edit(self.matrix_path, "IOCTL thing", "IOCTL other thing")
        errors, _ = g.check_repo(self.tmp)
        self.assertTrue(any("alpha/windows: capture leg-hash" in e and "is stale" in e for e in errors), errors)
        self.assertTrue(any("alpha/macos: capture leg-hash" in e for e in errors), errors)

    def test_missing_fence_and_missing_readme_manifest(self):
        self._generated()
        self._edit(self.readme, "<!-- BEGIN GENERATED: plugin-doc-gen source -->\n", "")
        errors, _ = g.check_repo(self.tmp)
        self.assertTrue(any("missing fence `plugin-doc-gen source`" in e for e in errors), errors)
        self.readme.unlink()
        errors, _ = g.check_repo(self.tmp)
        self.assertTrue(any("content/plugin-docs/alpha.json: no README for this plugin" in e for e in errors), errors)
        self.assertEqual(missing_readmes(self.tmp), ["alpha"])

    def test_unknown_plugin_name_is_an_error(self):
        outcome = g.generate(self.tmp, only="omega")
        self.assertEqual(outcome.errors, ["omega: no agents/plugins/omega/README.md — the generator never creates one"])

    def test_shape_checks_name_every_defect(self):
        self._generated()
        self._edit(self.readme, "## Privileges and prerequisites", "## Privileges")
        self._edit(self.readme, "1. **One.** first", "")
        self._edit(self.readme, "| Windows | svc | none | 2026-09-01 | `error\\|com_init` row |",
                   "| Windows | svc | none | 2026-09-01 | `error|com_init` row |")
        problems = "\n".join(readme_problems(self.tmp, "alpha"))
        self.assertIn("section headings must appear in order", problems)
        self.assertIn("hand-written section '## Caveats and known gaps' is empty", problems)
        # The renamed heading is no longer the contracted section, so it reads
        # as empty — the table under it is checked by test_pipe_width_check.
        self.assertIn("hand-written section '## Privileges and prerequisites' is empty", problems)

    def test_pipe_width_check(self):
        self._generated()
        self._edit(self.readme, "`error\\|com_init` row", "`error|com_init` row")
        problems = readme_problems(self.tmp, "alpha")
        self.assertEqual(len(problems), 1)
        self.assertIn("'## Privileges and prerequisites' row has 6 cells, contract is 5", problems[0])

    def test_samples_are_checked_per_leg(self):
        self._generated()
        matrix = self._matrix()
        # An action captured on one OS only: the other supported leg is named.
        self._edit(self.macos, "== action=probe", "== action=other")
        problems = sample_problems(self.tmp, matrix, "alpha")
        self.assertEqual(len(problems), 2, problems)
        self.assertIn("alpha/macos: action 'probe' is constrained on macos but docs/samples/macos.txt has no "
                      "`== action=probe` block", problems[0])
        self.assertIn("captures action 'other', which the descriptor does not declare", problems[1])
        # A missing sample file on a supported OS.
        self.macos.unlink()
        problems = sample_problems(self.tmp, matrix, "alpha")
        self.assertIn("docs/samples/macos.txt is missing or unparseable (rule 5)", problems[0])
        # A truncated capture (no status line) is reported through the parser.
        _write(self.macos, _SYNTH_SAMPLE.format(os="macos").split("[result_status]")[0])
        problems = sample_problems(self.tmp, matrix, "alpha")
        self.assertTrue(any("action 'probe' has no [result_status] line" in p for p in problems), problems)
        # Linux declares nothing supported, so no Linux sample is required.
        self.assertFalse(any("linux" in p for p in problems))

    def test_malformed_column_keys_fail_generation(self):
        self._edit(self.tmp / "content" / "definitions" / "alpha.yaml",
                   "values: [probe], example: probe", "values: [probe], example: probe, platforms: windows")
        with self.assertRaisesRegex(ValueError, "x.alpha.probe.kind: `platforms` must be a list"):
            g.generate(self.tmp)

    def test_matrix_action_without_capability_row_is_an_error(self):
        self._edit(self.tmp / "server" / "core" / "src" / "capability_decls" / "plugin_action_catalogue_x.hpp",
                   '.plugin = "alpha", .action = "wipe"', '.plugin = "alpha", .action = "wipe_renamed"')
        outcome = g.generate(self.tmp)
        self.assertTrue(any("action 'wipe' is in the capability-matrix block but no CommandCapability row" in e
                            for e in outcome.errors), outcome.errors)


if __name__ == "__main__":
    unittest.main()
