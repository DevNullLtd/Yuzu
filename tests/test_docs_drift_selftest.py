#!/usr/bin/env python3
"""Self-test for scripts/ci/check-docs-drift.py (docs/docs-drift-gate.md).

The committed tree only ever exercises the passing path, and a checker that
always returned 0 would pass it too. This drives every failure branch on
synthetic input - new and fixed drift, baseline growth, dead/duplicate/plugin-
reaching manifest rules, touch violations, and exemption lines hidden in code
fences or HTML comments - each paired with a passing control so a "fires"
result shows the gate discriminates rather than failing everything.

It also pins the policy constants (FLAG_SOURCES, CATEGORIES, the exemption
keyword) so narrowing what the gate checks means editing this file in the
same reviewed change. Imports the hyphenated script via importlib, the
pattern tests/test_seam_closure_selftest.py uses. Stdlib only.
"""
from __future__ import annotations

import importlib.util
import json
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
_spec = importlib.util.spec_from_file_location("check_docs_drift", ROOT / "scripts" / "ci" / "check-docs-drift.py")
d = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(d)
canon = d.load_parity().canonicalize


def rules(*specs):
    return [{"id": i, "code": c, "docs": ds, "_rx": [d.glob_to_regex(g) for g in c]} for i, c, ds in specs]


class PinnedPolicy(unittest.TestCase):
    def test_flag_sources(self):
        self.assertEqual(d.FLAG_SOURCES, (
            "server/core/src/main.cpp",
            "server/core/src/server_ota_options.hpp",
            "server/core/src/server_gateway_peer_options.hpp",
            "agents/core/src/main.cpp",
        ))

    def test_categories_and_keyword(self):
        self.assertEqual(d.CATEGORIES, ("rest_undocumented", "rest_stale", "mcp_undocumented", "flag_undocumented"))
        # Must never be the plugin rule's global-override keyword.
        self.assertEqual(d.EXEMPT_KEYWORD, "doc-coupling-exempt")


class Extraction(unittest.TestCase):
    def test_doc_path_param_styles_key_alike(self):
        want = canon("/api/v1/devices/([^/]+)/tags")
        for p in ("/api/v1/devices/{id}/tags", "/api/v1/devices/<agent_id>/tags",
                  "/api/v1/devices/:id/tags", "/api/v1/devices/{id}/tags?limit=5", "/api/v1/devices/{id}/tags."):
            self.assertEqual(d.normalize_doc_path(p, canon), want, p)

    def test_heading_routes(self):
        text = ("#### `GET /api/v1/a`\n"
                "#### `GET`/`DELETE /api/v1/b/{id}`\n"
                "Prose GET /api/v1/not-a-heading\n"
                "```\n#### `GET /api/v1/in-fence`\n```\n"
                "#### `GET /api/legacy`\n")
        got = set(d.doc_heading_routes(text, canon))
        self.assertEqual(got, {("GET", "/api/v1/a"), ("GET", "/api/v1/b/{param}"), ("DELETE", "/api/v1/b/{param}")})

    def test_flags(self):
        src = {"m.cpp": 'app.add_option("--a,-a", x);\napp.add_flag("-b,--bee", y);\n'
                        'app.add_flag("--on,!--no-on", z);\napp.add_flag("--d{true}", w);\napp.add_option(name, v);\n'}
        self.assertEqual(set(d.extract_flags(src)), {"--a", "--bee", "--on", "--no-on", "--d"})

    def test_flag_documented_is_token_exact(self):
        self.assertTrue(d.documented("--tls", "use `--tls` here"))
        self.assertFalse(d.documented("--tls", "use --tls-system-roots"))


class Ratchet(unittest.TestCase):
    def drift(self, routes=(), docs=(), tools=(), mcp="", flags=(), manual=""):
        return d.compute_drift(set(routes), set(docs), set(tools), mcp, dict.fromkeys(flags, "x"), manual)

    def base(self, **kw):
        return {c: set(kw.get(c, ())) for c in d.CATEGORIES}

    def test_equal_passes(self):
        dr = self.drift(routes=[("GET", "/api/v1/x")], tools=["t"], flags=["--f"])
        self.assertEqual(d.ratchet_errors(dr, self.base(rest_undocumented=["GET /api/v1/x"],
                                                        mcp_undocumented=["t"], flag_undocumented=["--f"])), [])

    def test_new_gap_in_each_category_fires(self):
        dr = self.drift(routes=[("GET", "/api/v1/x")], docs=[("GET", "/api/v1/gone")], tools=["t"], flags=["--f"])
        errs = d.ratchet_errors(dr, self.base())
        self.assertEqual(len(errs), 4)
        self.assertTrue(all(e.startswith("new ") for e in errs))

    def test_fixed_gap_still_in_baseline_fires(self):
        errs = d.ratchet_errors(self.drift(), self.base(mcp_undocumented=["t"]))
        self.assertEqual(len(errs), 1)
        self.assertIn("fixed mcp_undocumented: t", errs[0])

    def test_swap_cannot_hide_behind_count(self):
        # one gap fixed, a different one added: counts equal, still two errors
        dr = self.drift(tools=["new_tool"])
        self.assertEqual(len(d.ratchet_errors(dr, self.base(mcp_undocumented=["old_tool"]))), 2)

    def test_documented_backticked_tool_passes(self):
        self.assertEqual(self.drift(tools=["t"], mcp="| `t` | does it |")["mcp_undocumented"], [])

    def test_write_baseline_refuses_growth(self):
        with tempfile.TemporaryDirectory(prefix="yuzu_test_") as tmp:
            p = Path(tmp) / "b.json"
            p.write_text(json.dumps({c: [] for c in d.CATEGORIES}))
            dr = self.drift(tools=["t"])
            self.assertEqual(d.write_baseline(p, dr, allow_growth=False), 1)
            self.assertEqual(json.loads(p.read_text())["mcp_undocumented"], [])
            self.assertEqual(d.write_baseline(p, dr, allow_growth=True), 0)
            self.assertEqual(json.loads(p.read_text())["mcp_undocumented"], ["t"])
            self.assertEqual(d.write_baseline(p, self.drift(), allow_growth=False), 0)  # shrinking is free


class Manifest(unittest.TestCase):
    def test_glob(self):
        rx = d.glob_to_regex("server/core/src/mcp_*.{hpp,cpp}")
        self.assertTrue(rx.match("server/core/src/mcp_server.cpp"))
        self.assertFalse(rx.match("server/core/src/mcp_server.cc"))
        self.assertFalse(rx.match("server/core/src/sub/mcp_x.cpp"))
        self.assertTrue(d.glob_to_regex("gateway/**/*.erl").match("gateway/a/b/c.erl"))
        self.assertTrue(d.glob_to_regex("gateway/**/*.erl").match("gateway/c.erl"))

    def test_clean_manifest_passes(self):
        r = rules(("a", ["src/a_*.cpp"], ["docs/a.md"]))
        self.assertEqual(d.manifest_errors(r, ["src/a_x.cpp"], lambda p: True), [])

    def test_each_defect_fires(self):
        r = rules(("a", ["src/a_*.cpp"], ["docs/a.md"]), ("a", ["src/none_*.cpp"], ["docs/missing.md"]),
                  ("Bad_Id", ["agents/plugins/*/src/*.cpp"], []))
        errs = d.manifest_errors(r, ["src/a_x.cpp", "agents/plugins/p/src/x.cpp"], lambda p: p == "docs/a.md")
        text = "\n".join(errs)
        for needle in ("duplicate rule id", "matches no file", "missing doc", "kebab-case",
                       "names no docs", "plugin README touch rule"):
            self.assertIn(needle, text)

    def test_real_manifest_loads_and_is_clean(self):
        r = d.load_manifest(d.MANIFEST)
        self.assertGreater(len(r), 0)
        self.assertEqual(d.manifest_errors(r, d.repo_files(), lambda p: (ROOT / p).is_file()), [])


class Exemptions(unittest.TestCase):
    def test_parsing(self):
        cases = {
            "doc-coupling-exempt: mcp — comment-only change": {"mcp"},
            "- doc-coupling-exempt: mcp - comment-only change": {"mcp"},
            "Summary\r\ndoc-coupling-exempt: mcp — comment-only\r\n": {"mcp"},
            "doc-coupling-exempt: mcp — x": set(),                    # content-free reason
            "doc-coupling-exempt: mcp": set(),                        # no reason
            "docs-unchanged: mcp — the plugin keyword": set(),       # wrong keyword
            "```\ndoc-coupling-exempt: mcp — hidden\n```": set(),
            "````\n```\ndoc-coupling-exempt: mcp — hidden\n````": set(),  # decoy inner fence
            "<!--\ndoc-coupling-exempt: mcp — hidden\n-->": set(),
            "<!-- a --> doc-coupling-exempt: mcp — renders visibly": {"mcp"},
            "```\nx\n```\ndoc-coupling-exempt: mcp — after a closed fence": {"mcp"},
        }
        for body, want in cases.items():
            self.assertEqual(set(d.exemptions(body)), want, repr(body))


class Touch(unittest.TestCase):
    R = rules(("mcp", ["server/mcp_*.cpp"], ["docs/mcp.md", "docs/rest.md"]))

    def test_no_coupled_change(self):
        self.assertEqual(d.touch_check(["server/other.cpp"], self.R, ""), ([], []))

    def test_doc_touched_passes(self):
        errs, notes = d.touch_check(["server/mcp_a.cpp", "docs/rest.md"], self.R, "")
        self.assertEqual(errs, [])
        self.assertIn("ok", notes[0])

    def test_violation_fires_and_names_fix(self):
        errs, _ = d.touch_check(["server/mcp_a.cpp"], self.R, "")
        self.assertEqual(len(errs), 1)
        self.assertIn("doc-coupling-exempt: mcp —", errs[0])

    def test_exemption_passes_only_its_rule(self):
        r = self.R + rules(("dex", ["server/dex_*.cpp"], ["docs/dex.md"]))
        errs, _ = d.touch_check(["server/mcp_a.cpp", "server/dex_a.cpp"], r,
                                "doc-coupling-exempt: mcp — refactor only")
        self.assertEqual(len(errs), 1)
        self.assertTrue(errs[0].startswith("dex:"))

    def test_unknown_exemption_is_noted(self):
        _, notes = d.touch_check([], self.R, "doc-coupling-exempt: nope — whatever reason")
        self.assertIn("unknown rule", notes[0])


class LiveTree(unittest.TestCase):
    def test_gate_passes_on_committed_tree(self):
        self.assertEqual(d.run_facts(), 0)


if __name__ == "__main__":
    unittest.main()
