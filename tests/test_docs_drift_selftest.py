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
import os
import re
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
_spec = importlib.util.spec_from_file_location("check_docs_drift", ROOT / "scripts" / "ci" / "check-docs-drift.py")
d = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(d)
canon = d.load_parity().canonicalize
HOOK = ROOT / "scripts" / "hooks" / "docs-drift-pr-guard.py"
_hspec = importlib.util.spec_from_file_location("docs_drift_pr_guard", HOOK)
hook = importlib.util.module_from_spec(_hspec)
_hspec.loader.exec_module(hook)

# A planted script that, if ever executed, leaves a marker file next to itself.
PLANT = "import pathlib; pathlib.Path(__file__).with_name('EXECUTED').write_text('x')\n"


def hermetic_env(**extra):
    """The environment for every git / hook subprocess here: no inherited GIT_*
    (a git-hook context sets GIT_DIR / GIT_INDEX_FILE), and no global or
    system config, so a developer's commit.gpgsign or core.hooksPath cannot
    break or leak into a test commit."""
    env = {k: v for k, v in os.environ.items() if not k.startswith("GIT_")}
    env.update(GIT_CONFIG_GLOBAL=os.devnull, GIT_CONFIG_NOSYSTEM="1", **extra)
    return env


def git(repo, *args):
    return subprocess.run(["git", "-C", str(repo), "-c", "user.name=t", "-c", "user.email=t@example.invalid",
                           "-c", "commit.gpgsign=false", *args],
                          check=True, capture_output=True, text=True, env=hermetic_env()).stdout.strip()


def write(root, rel, text):
    path = Path(root) / rel
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")


def synthetic_tree(root, routes=130, tools=100, flags=70, documented=True):
    """A minimal repo shape the gate can read: generated routes, kTools[] and
    CLI flags (above MIN_EXTRACTED by default), each documented, an empty
    baseline, and one coupling rule `coupled`: server/core/src/coupled_*.cpp
    -> docs/user-manual/coupled.md."""
    src = "server/core/src/"
    write(root, src + "routes_gen.cpp", "".join(f'    sink.Get("/api/v1/r{i}", h);\n' for i in range(routes)))
    write(root, src + "mcp_server.cpp", "static const ToolDef kTools[] = {\n" +
          "".join(f'    {{"tool_{i}", "d"}},\n' for i in range(tools)) + "};\n")
    # A tool served from the registry seam (mcp_tools_*.cpp) is not in kTools[]; the gate's tool
    # set includes it, and the parity script's registry-file floor needs one file under --root.
    write(root, src + "mcp_tools_fixture.cpp", "constexpr ToolRecord kToolRecords[] = {\n"
          '    {"tool_registry", "d"},\n' "};\n")
    write(root, src + "main.cpp", "".join(f'app.add_option("--flag-{i}", x);\n' for i in range(flags)))
    for j, rel in enumerate(d.FLAG_SOURCES[1:]):
        write(root, rel, f'app.add_flag("--src{j}-flag", y);\n')
    write(root, src + "coupled_a.cpp", "int a;\n")
    n = 1 if documented else 0
    write(root, "docs/user-manual/rest-api.md", "".join(f"#### `GET /api/v1/r{i}`\n" for i in range(routes * n)))
    write(root, "docs/user-manual/mcp.md", "".join(f"`tool_{i}`\n" for i in range(tools * n)) +
          "`tool_registry`\n" * n)
    write(root, "docs/user-manual/server-admin.md", "".join(f"`--flag-{i}`\n" for i in range(flags * n)) +
          "".join(f"`--src{j}-flag`\n" for j in range(len(d.FLAG_SOURCES) - 1)))
    write(root, "docs/user-manual/coupled.md", "coupled\n")
    write(root, d.BASELINE_REL, json.dumps({c: [] for c in d.CATEGORIES}))
    write(root, d.MANIFEST_REL, json.dumps({"rules": [{"id": "coupled", "why": "t",
                                                      "code": [src + "coupled_*.cpp"],
                                                      "docs": ["docs/user-manual/coupled.md"]}]}))


def rules(*specs):
    return [{"id": i, "code": c, "docs": ds, "_rx": [d.glob_to_regex(g) for g in c]} for i, c, ds in specs]


class PinnedPolicy(unittest.TestCase):
    def test_flag_sources(self):
        self.assertEqual(d.FLAG_SOURCES, (
            "server/core/src/main.cpp",
            "server/core/src/server_ota_options.hpp",
            "server/core/src/server_gateway_peer_options.hpp",
            "server/core/src/server_guardian_reconcile_options.hpp",
            "agents/core/src/main.cpp",
        ))

    def test_categories_and_keyword(self):
        self.assertEqual(d.CATEGORIES, ("rest_undocumented", "rest_stale", "mcp_undocumented", "flag_undocumented"))
        # Must never be the plugin rule's global-override keyword.
        self.assertEqual(d.EXEMPT_KEYWORD, "doc-coupling-exempt")

    def test_extraction_floors(self):
        self.assertEqual(d.MIN_EXTRACTED, {"routes": 120, "tools": 90, "flags": 60})
        self.assertEqual(d.extraction_floor_errors({"routes": 120, "tools": 90, "flags": 60}), [])
        errs = d.extraction_floor_errors({"routes": 0, "tools": 200, "flags": 59})
        self.assertEqual(len(errs), 2)
        self.assertTrue(errs[0].startswith("only 0 routes"))


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

    def test_flag_constants_resolve(self):
        consts = d.flag_constants(['inline constexpr std::string_view kPinFlag = "--pin";\n'
                                   'constexpr const char* kOther = "--other";\n'])
        self.assertEqual(consts, {"kPinFlag": "--pin", "kOther": "--other"})
        src = {"o.hpp": "app.add_option(std::string{kPinFlag}, v);\napp.add_flag(kOther, w);\napp.add_flag(kUnknown, z);\n"}
        self.assertEqual(set(d.extract_flags(src, consts)), {"--pin", "--other"})

    def test_real_gateway_peer_flags_are_extracted(self):
        # The UP-4 case: these three are defined through constants.
        consts = d.flag_constants(d.read_tree_file(ROOT, f) for g in d.FLAG_CONSTANT_GLOBS for f in ROOT.glob(g))
        flags = d.extract_flags({rel: (ROOT / rel).read_text(encoding="utf-8", errors="replace")
                                 for rel in d.FLAG_SOURCES}, consts)
        for f in ("--gateway-peer-pin", "--gateway-peer-pin-file", "--insecure-gateway-peer"):
            self.assertIn(f, flags)

    def test_every_cli11_caller_is_a_flag_source(self):
        callers = set()
        for top in ("server/core/src", "agents/core/src"):
            for f in (ROOT / top).rglob("*"):
                if f.suffix in (".cpp", ".hpp", ".h") and re.search(r"\badd_(?:option|flag)\s*\(",
                                                                    f.read_text(encoding="utf-8", errors="replace")):
                    callers.add(f.relative_to(ROOT).as_posix())
        self.assertLessEqual(callers, set(d.FLAG_SOURCES), "add the file to FLAG_SOURCES")

    def test_heading_parser_respects_commonmark_fences(self):
        text = ("````md\n```\n#### `GET /api/v1/in-example`\n```\n````\n"
                "#### `GET /api/v1/after`\n")
        self.assertEqual(set(d.doc_heading_routes(text, canon)), {("GET", "/api/v1/after")})

    def test_parity_extractors_read_only_the_repointed_globals(self):
        """--root works by repointing SERVER_SRC and MCP_SERVER_CPP; an
        extractor reading any other path global would silently check the
        trusted tree instead."""
        mod = d.load_parity()
        path_globals = {k for k, v in vars(mod).items() if isinstance(v, Path)}
        used = set()
        for fn in (mod.extract_all_routes, mod.extract_mcp_tools, mod._read_mcp_server_cpp,
                   mod._extract_registry_tools, mod._registry_dir):
            used |= set(fn.__code__.co_names) & path_globals
        self.assertEqual(used, {"SERVER_SRC", "MCP_SERVER_CPP"})

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
        self.assertIn("stale mcp_undocumented: t", errs[0])

    def test_swap_cannot_hide_behind_count(self):
        # one gap fixed, a different one added: counts equal, still two errors
        dr = self.drift(tools=["new_tool"])
        self.assertEqual(len(d.ratchet_errors(dr, self.base(mcp_undocumented=["old_tool"]))), 2)

    def test_documented_backticked_tool_passes(self):
        self.assertEqual(self.drift(tools=["t"], mcp="| `t` | does it |")["mcp_undocumented"], [])

    def test_write_baseline_refuses_growth(self):
        with tempfile.TemporaryDirectory(prefix="yuzu_test_") as tmp:
            p = Path(tmp) / "b.json"
            p.write_text(json.dumps({c: [] for c in d.CATEGORIES}), encoding="utf-8")
            dr = self.drift(tools=["t"])
            self.assertEqual(d.write_baseline(p, dr, allow_growth=False), 1)
            self.assertEqual(json.loads(p.read_text(encoding="utf-8"))["mcp_undocumented"], [])
            self.assertEqual(d.write_baseline(p, dr, allow_growth=True), 0)
            self.assertEqual(json.loads(p.read_text(encoding="utf-8"))["mcp_undocumented"], ["t"])
            self.assertEqual(d.write_baseline(p, self.drift(), allow_growth=False), 0)  # shrinking is free


class Manifest(unittest.TestCase):
    def test_glob(self):
        rx = d.glob_to_regex("server/core/src/mcp_*.{hpp,cpp}")
        self.assertTrue(rx.match("server/core/src/mcp_server.cpp"))
        self.assertFalse(rx.match("server/core/src/mcp_server.cc"))
        self.assertFalse(rx.match("server/core/src/sub/mcp_x.cpp"))
        self.assertTrue(d.glob_to_regex("gateway/**/*.erl").match("gateway/a/b/c.erl"))
        self.assertTrue(d.glob_to_regex("gateway/**/*.erl").match("gateway/c.erl"))
        self.assertTrue(d.glob_to_regex("a/b?.cpp").match("a/b1.cpp"))
        self.assertFalse(d.glob_to_regex("a/b?.cpp").match("a/b/.cpp"))

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
            "doc-coupling-exempt: mcp — ab": set(),                   # 2 chars: below the minimum
            "doc-coupling-exempt: mcp — abc": {"mcp"},                # 3 chars: the minimum
            "doc-coupling-exempt: mcp": set(),                        # no reason
            "docs-unchanged: mcp — the plugin keyword": set(),       # wrong keyword
            "```\ndoc-coupling-exempt: mcp — hidden\n```": set(),
            "````\n```\ndoc-coupling-exempt: mcp — hidden\n````": set(),  # decoy inner fence
            "<!--\ndoc-coupling-exempt: mcp — hidden\n-->": set(),
            "<!-- a --> doc-coupling-exempt: mcp — renders visibly": {"mcp"},
            "```\nx\n```\ndoc-coupling-exempt: mcp — after a closed fence": {"mcp"},
            '<img alt="\ndoc-coupling-exempt: mcp — hidden in an attribute\n">': set(),
            'text <img alt="\ndoc-coupling-exempt: mcp — inline attribute\n"> more': set(),
            "<script>\ndoc-coupling-exempt: mcp — hidden\n\nstill\n</script>": set(),
            "<details>\ndoc-coupling-exempt: mcp — in an html block\n": set(),
            "<details>\nx\n\ndoc-coupling-exempt: mcp — after the block's blank line": {"mcp"},
            "<br>\n\ndoc-coupling-exempt: mcp — after a one-line tag": {"mcp"},
            # CommonMark: these blocks end at their marker, not at a blank line
            "<!DOCTYPE html>\ndoc-coupling-exempt: mcp — after a one-line doctype": {"mcp"},
            "<?xml version='1.0'?>\ndoc-coupling-exempt: mcp — after a one-line pi": {"mcp"},
            "<!DOCTYPE html\n\ndoc-coupling-exempt: mcp — inside an open doctype\n>": set(),
            "<?\n\ndoc-coupling-exempt: mcp — inside a processing instruction\n?>": set(),
            "<![CDATA[\n\ndoc-coupling-exempt: mcp — inside cdata\n]]>": set(),
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


class Floors(unittest.TestCase):
    """The floor must be WIRED into current_drift, not merely computable."""
    def test_below_floor_fails_closed_and_above_passes(self):
        with tempfile.TemporaryDirectory(prefix="yuzu_test_") as tmp:
            synthetic_tree(tmp)
            self.assertEqual(d.current_drift(tmp)["mcp_undocumented"], [])  # control: above the floor
        with tempfile.TemporaryDirectory(prefix="yuzu_test_") as tmp:
            synthetic_tree(tmp)
            write(tmp, d.FLAG_SOURCES[1], "// no flags here\n")
            with self.assertRaisesRegex(RuntimeError, "yields no flags"):
                d.current_drift(tmp)
        for short in ({"routes": 5}, {"tools": 5}, {"flags": 5}):
            with tempfile.TemporaryDirectory(prefix="yuzu_test_") as tmp:
                synthetic_tree(tmp, **short)
                with self.assertRaisesRegex(RuntimeError, "extracted \\(floor"):
                    d.current_drift(tmp)


class SyntheticRepo(unittest.TestCase):
    """--root, --write-baseline and --touch end to end against a real git repo."""
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory(prefix="yuzu_test_")
        self.repo = Path(self._tmp.name) / "repo"
        synthetic_tree(self.repo)
        subprocess.run(["git", "init", "-q", str(self.repo)], check=True, env=hermetic_env())
        git(self.repo, "add", "-A")
        git(self.repo, "commit", "-qm", "base")
        self.base = git(self.repo, "rev-parse", "HEAD")
        git(self.repo, "update-ref", "refs/remotes/origin/dev", "HEAD")

    def tearDown(self):
        self._tmp.cleanup()

    def commit(self, msg="c"):
        git(self.repo, "add", "-A")
        git(self.repo, "commit", "-qm", msg)
        return git(self.repo, "rev-parse", "HEAD")

    def add_undocumented_tool(self):
        path = self.repo / "server/core/src/mcp_server.cpp"
        path.write_text(path.read_text(encoding="utf-8").replace("};", '    {"zz_new", "d"},\n};'), encoding="utf-8")

    def test_root_is_forwarded(self):
        self.assertEqual(d.main(["--root", str(self.repo)]), 0)
        self.add_undocumented_tool()
        self.assertEqual(d.main(["--root", str(self.repo)]), 1)
        self.assertEqual(d.main([]), 0)  # the default tree is unaffected

    def test_write_baseline_via_main(self):
        self.add_undocumented_tool()
        baseline = self.repo / d.BASELINE_REL
        self.assertEqual(d.main(["--root", str(self.repo), "--update-baseline"]), 1)
        self.assertEqual(json.loads(baseline.read_text(encoding="utf-8"))["mcp_undocumented"], [])
        self.assertEqual(d.main(["--root", str(self.repo), "--write-baseline", "--allow-growth"]), 0)
        self.assertEqual(json.loads(baseline.read_text(encoding="utf-8"))["mcp_undocumented"], ["zz_new"])

    def touch(self, head, body=None):
        args = ["--root", str(self.repo), "--touch", self.base, head]
        if body is not None:
            bf = self.repo.parent / "touch-body.md"
            bf.write_text(body, encoding="utf-8")
            args.append(str(bf))
        return d.main(args)

    def test_touch_end_to_end(self):
        write(self.repo, "server/core/src/coupled_a.cpp", "int a = 1;\n")
        head = self.commit()
        self.assertEqual(self.touch(head), 1)
        self.assertEqual(self.touch(head, "doc-coupling-exempt: coupled — comment-only change"), 0)
        self.assertEqual(self.touch(head, "doc-coupling-exempt: other — wrong rule named"), 1)
        write(self.repo, "docs/user-manual/coupled.md", "coupled, updated\n")
        self.assertEqual(self.touch(self.commit()), 0)

    def test_rename_out_of_a_coupled_path_counts(self):
        git(self.repo, "mv", "server/core/src/coupled_a.cpp", "server/core/src/renamed.cpp")
        self.assertEqual(self.touch(self.commit()), 1)  # needs --no-renames to see the old path

    def test_untrusted_tree_reads_are_bounded(self):
        """A symlink out of the tree, or to a device, fails the run closed
        instead of reading it. (A FIFO is refused by the same is_file check.)"""
        if not hasattr(os, "symlink"):
            self.skipTest("no symlinks")
        doc = self.repo / d.REST_DOC
        doc.unlink()
        try:
            os.symlink("/dev/zero" if os.path.exists("/dev/zero") else str(ROOT / d.REST_DOC), doc)
        except OSError:
            self.skipTest("cannot create symlinks here")
        with self.assertRaisesRegex(ValueError, "outside the tree|not a regular file"):
            d.current_drift(self.repo)
        self.assertEqual(d.main(["--root", str(self.repo)]), 1)

    def test_tree_git_config_cannot_run_commands(self):
        marker = self.repo.parent / "FSMONITOR"
        hook = self.repo.parent / "fsmon-gate.sh"
        hook.write_text(f"#!/bin/sh\ntouch '{marker}'\n", encoding="utf-8")
        hook.chmod(0o755)
        git(self.repo, "config", "core.fsmonitor", str(hook))
        # Control: an unguarded ls-files in this tree DOES run it ...
        subprocess.run(["git", "-C", str(self.repo), "ls-files"], capture_output=True, env=hermetic_env())
        if not marker.exists():
            self.skipTest("this git does not run core.fsmonitor for ls-files")
        marker.unlink()
        # ... and the gate's own git calls do not.
        d.main(["--root", str(self.repo)])
        d.main(["--root", str(self.repo), "--touch", self.base, "HEAD"])
        self.assertFalse(marker.exists())

    def test_update_baseline_rejects_unknown_arguments(self):
        baseline = self.repo / d.BASELINE_REL
        before = baseline.read_bytes()
        self.assertEqual(d.main(["--root", str(self.repo), "--update-baseline", "--help"]), 2)
        self.assertEqual(baseline.read_bytes(), before)

    def test_a_flag_shared_by_two_sources_does_not_trip_the_floor(self):
        src = self.repo / d.FLAG_SOURCES[1]
        src.write_text(src.read_text(encoding="utf-8") + 'app.add_option("--flag-0", x);\n', encoding="utf-8")  # also in main.cpp
        write(self.repo, d.FLAG_SOURCES[2], 'app.add_option("--flag-0", x);\n')  # ONLY a duplicate
        self.assertEqual(d.current_drift(self.repo)["flag_undocumented"], [])

    def outside_copy(self, name, text):
        """A regular file OUTSIDE the repo (next to it in the same tempdir)."""
        path = self.repo.parent / name
        path.write_text(text, encoding="utf-8")
        return path

    def symlink_or_skip(self, target, link):
        if not hasattr(os, "symlink"):
            self.skipTest("no symlinks")
        link.unlink(missing_ok=True)
        try:
            os.symlink(target, link)
        except OSError:
            self.skipTest("cannot create symlinks here")

    def test_guard_outside_tree_alone(self):
        """A symlink to an ordinary, small, regular file outside the tree:
        only the outside-the-tree check can refuse it."""
        doc = self.repo / d.REST_DOC
        target = self.outside_copy("outside-rest-api.md", doc.read_text(encoding="utf-8"))
        self.symlink_or_skip(target, doc)
        with self.assertRaisesRegex(ValueError, "outside the tree"):
            d.current_drift(self.repo)

    def test_guard_regular_file_alone(self):
        """A FIFO inside the tree: only the regular-file check refuses it
        (and O_NONBLOCK keeps the open from hanging)."""
        if not hasattr(os, "mkfifo"):
            self.skipTest("no FIFOs")
        doc = self.repo / d.REST_DOC
        doc.unlink()
        os.mkfifo(doc)
        with self.assertRaisesRegex(ValueError, "not a regular file"):
            d.read_tree_file(self.repo, doc)

    def test_guard_size_cap_alone(self):
        doc = self.repo / d.REST_DOC
        old = d.MAX_READ_BYTES
        d.MAX_READ_BYTES = 8
        try:
            write(self.repo, d.REST_DOC, "123456789")  # 9 bytes
            with self.assertRaisesRegex(ValueError, "larger than 8 bytes"):
                d.read_tree_file(self.repo, doc)
            write(self.repo, d.REST_DOC, "12345678")   # control: exactly the cap
            self.assertEqual(d.read_tree_file(self.repo, doc), "12345678")
        finally:
            d.MAX_READ_BYTES = old

    def test_parity_inputs_are_vetted_before_extraction(self):
        """check-api-parity reads server/core/src/*.cpp itself, unbounded; the
        gate must vet those files first."""
        target = self.outside_copy("outside.cpp", 'sink.Get("/api/v1/outside", h);\n')
        self.symlink_or_skip(target, self.repo / "server/core/src/zz_link.cpp")
        with self.assertRaisesRegex(ValueError, "outside the tree"):
            d.current_drift(self.repo)

    def test_symlinked_parent_directory_is_refused(self):
        if not hasattr(os, "symlink"):
            self.skipTest("no symlinks")
        with tempfile.TemporaryDirectory(prefix="yuzu_test_") as outside:
            manual = self.repo / d.USER_MANUAL
            for f in manual.iterdir():
                (Path(outside) / f.name).write_bytes(f.read_bytes())
                f.unlink()
            manual.rmdir()
            try:
                os.symlink(outside, manual)
            except OSError:
                self.skipTest("cannot create symlinks here")
            with self.assertRaisesRegex(ValueError, "outside the tree"):
                d.current_drift(self.repo)

    def test_refused_reads_do_not_leak_descriptors(self):
        fd_dir = "/dev/fd" if os.path.isdir("/dev/fd") else "/proc/self/fd"
        if not os.path.isdir(fd_dir) or not hasattr(os, "mkfifo"):
            self.skipTest("cannot count descriptors or make FIFOs here")
        doc = self.repo / d.REST_DOC
        doc.unlink()
        os.mkfifo(doc)
        before = len(os.listdir(fd_dir))
        for _ in range(50):
            with self.assertRaises(ValueError):
                d.read_tree_file(self.repo, doc)
        self.assertEqual(len(os.listdir(fd_dir)), before)

    def test_a_directory_where_a_file_is_expected_fails_closed_without_leaking(self):
        doc = self.repo / d.REST_DOC
        doc.unlink()
        doc.mkdir()
        with self.assertRaisesRegex(ValueError, "not a regular file|cannot be opened"):
            d.read_tree_file(self.repo, doc)

    def test_newer_schema_keys_are_ignored_by_an_older_gate(self):
        """The hook runs the PROJECT's gate on a possibly newer tree: unknown
        manifest/baseline keys must be ignored, not crash or flip the result."""
        man = self.repo / d.MANIFEST_REL
        data = json.loads(man.read_text(encoding="utf-8"))
        data["schema_version"] = 99
        data["rules"][0]["future_field"] = ["x"]
        man.write_text(json.dumps(data), encoding="utf-8")
        base = self.repo / d.BASELINE_REL
        b = json.loads(base.read_text(encoding="utf-8"))
        b["some_future_category"] = ["anything"]
        base.write_text(json.dumps(b), encoding="utf-8")
        self.assertEqual(d.main(["--root", str(self.repo)]), 0)

    def test_touch_fails_closed(self):
        self.assertEqual(self.touch("0" * 40), 1)  # unknown commit
        self.assertEqual(d.main(["--root", str(self.repo), "--touch", self.base, "HEAD",
                                 str(self.repo / "no-such-body.md")]), 1)

    def run_hook(self, command):
        env = hermetic_env(CLAUDE_PROJECT_DIR=str(ROOT))
        payload = json.dumps({"tool_name": "Bash", "cwd": str(self.repo), "tool_input": {"command": command}})
        r = subprocess.run([sys.executable, "-I", str(HOOK)], input=payload, capture_output=True,
                           text=True, env=env, timeout=120)
        self.assertEqual(r.returncode, 0)
        return json.loads(r.stdout)["hookSpecificOutput"]["permissionDecisionReason"] if r.stdout else ""

    def run_hook_from(self, cwd, command):
        env = hermetic_env(CLAUDE_PROJECT_DIR=str(ROOT))
        payload = json.dumps({"tool_name": "Bash", "cwd": str(cwd), "tool_input": {"command": command}})
        r = subprocess.run([sys.executable, "-I", str(HOOK)], input=payload, capture_output=True,
                           text=True, env=env, timeout=120)
        return json.loads(r.stdout)["hookSpecificOutput"]["permissionDecisionReason"] if r.stdout else ""

    def test_hook_does_not_run_the_trees_fsmonitor(self):
        marker = self.repo.parent / "FSMONITOR-HOOK"
        script = self.repo.parent / "fsmon.sh"
        script.write_text(f"#!/bin/sh\ntouch '{marker}'\n", encoding="utf-8")
        script.chmod(0o755)
        git(self.repo, "config", "core.fsmonitor", str(script))
        subprocess.run(["git", "-C", str(self.repo), "ls-files"], capture_output=True, env=hermetic_env())
        if not marker.exists():
            self.skipTest("this git does not run core.fsmonitor for ls-files")
        write(self.repo, "server/core/src/coupled_a.cpp", "int a = 1;\n")
        self.commit()  # this test's own git add/commit runs the fsmonitor too
        marker.unlink(missing_ok=True)
        self.assertIn("coupled:", self.run_hook("gh pr create --title t"))
        self.assertFalse(marker.exists())

    def test_hook_fails_open_without_a_base_ref(self):
        git(self.repo, "update-ref", "-d", "refs/remotes/origin/dev")
        write(self.repo, "server/core/src/coupled_a.cpp", "int a = 1;\n")
        self.commit()
        self.assertEqual(self.run_hook("gh pr create --title t"), "")

    def test_hook_follows_a_leading_cd(self):
        write(self.repo, "server/core/src/coupled_a.cpp", "int a = 1;\n")
        self.commit()
        reason = self.run_hook_from(self.repo.parent, f"cd {self.repo.name} && gh pr create --title t")
        self.assertIn("coupled:", reason)

    def test_hook_allows_a_branch_that_predates_the_gate(self):
        (self.repo / d.MANIFEST_REL).unlink()
        (self.repo / d.BASELINE_REL).unlink()
        write(self.repo, "server/core/src/coupled_a.cpp", "int a = 1;\n")
        self.commit()
        self.assertEqual(self.run_hook("gh pr create --title t"), "")

    def test_hook_plumbing(self):
        """Touch-only failure, then allowed by --body, by -F (relative to the
        command's cwd), and via a doc change; then a facts-only failure. The
        allow cases also prove --root is forwarded: without it the project's
        gate would look for this repo's commits in the project tree and fail
        closed."""
        write(self.repo, "server/core/src/coupled_a.cpp", "int a = 1;\n")
        self.commit()
        reason = self.run_hook("gh pr create --title t")
        self.assertIn("coupled:", reason)
        self.assertNotIn("new mcp_undocumented", reason)
        self.assertEqual(self.run_hook('gh pr create -b "doc-coupling-exempt: coupled — refactor only"'), "")
        write(self.repo, "body.md", "doc-coupling-exempt: coupled — refactor only\n")
        self.assertEqual(self.run_hook("gh pr create -F body.md"), "")
        write(self.repo, "body.md", "no exemption here\n")  # control: the file IS read
        self.assertIn("coupled:", self.run_hook("gh pr create -F body.md"))
        (self.repo / "body.md").unlink()
        self.add_undocumented_tool()
        self.commit()
        reason = self.run_hook('gh pr create --body "doc-coupling-exempt: coupled — refactor only"')
        self.assertIn("new mcp_undocumented: zz_new", reason)
        self.assertNotIn("coupled:", reason)


class RootIsData(unittest.TestCase):
    def test_parity_extractor_is_never_loaded_from_root(self):
        with tempfile.TemporaryDirectory(prefix="yuzu_test_") as tmp:
            planted = Path(tmp) / "scripts" / "ci"
            planted.mkdir(parents=True)
            for name in ("check-api-parity.py", "check-docs-drift.py"):
                (planted / name).write_text(PLANT, encoding="utf-8")
            mod = d.load_parity(tmp)
            self.assertEqual(mod.SERVER_SRC, Path(tmp) / "server" / "core" / "src")
            self.assertEqual(d.run_facts(Path(tmp)), 1)  # empty tree: fails closed
            self.assertFalse((planted / "EXECUTED").exists())

    def test_bad_invocations_are_usage_errors(self):
        for argv in (["--bogus"], ["--touch"], ["--touch", "a"], ["--list", "--nope"]):
            self.assertEqual(d.main(argv), 2, argv)

    def test_root_flag_checks_the_named_tree(self):
        self.assertEqual(d.main(["--root", str(ROOT)]), 0)
        with tempfile.TemporaryDirectory(prefix="yuzu_test_") as tmp:
            self.assertEqual(d.main(["--root", tmp]), 1)


class Hook(unittest.TestCase):
    def test_command_position_matching(self):
        cases = {
            'gh pr create --base main -b "x"': ["--base", "main", "-b", "x"],
            "cd w && gh pr create -F b.md": ["-F", "b.md"],
            "git push\ngh pr create --title t": ["--title", "t"],
            "git push; gh pr create": [],
            "(cd a && true); gh pr create --title t": ["--title", "t"],
            'gh pr create \\\n  --base main \\\n  --body "b"': ["--base", "main", "--body", "b"],
            "gh pr create\\\n --title t": ["--title", "t"],
            'gh pr create --body "a\nb" && echo done': ["--body", "a\nb"],
            'git commit -m "then gh pr create"': None,
            "echo gh pr create": None,
            "gh pr view 3": None,
        }
        for cmd, want in cases.items():
            self.assertEqual(hook.pr_create_args(cmd), want, repr(cmd))

    def test_cd_target(self):
        self.assertEqual(hook.cd_target("cd wt && gh pr create"), "wt")
        self.assertEqual(hook.cd_target("cd a; cd b && gh pr create"), os.path.join("a", "b"))
        self.assertEqual(hook.cd_target("cd /abs && gh pr create"), "/abs")
        self.assertEqual(hook.cd_target("cd ~/wt && gh pr create"), os.path.expanduser("~/wt"))
        self.assertEqual(hook.cd_target("cd wt && BR=$(git branch --show-current) && gh pr create"), "wt")
        self.assertEqual(hook.cd_target('cd wt && gh pr create --body "$(cat b.md)"'), "wt")
        self.assertIsNone(hook.cd_target("BR=$(cd x && git rev-parse HEAD) && gh pr create"))
        self.assertEqual(hook.cd_target("N=$((1+2)) && cd wt && gh pr create"), "wt")
        self.assertEqual(hook.cd_target("A=$(a $(b)) && cd wt && gh pr create"), "wt")
        for unresolvable in ('cd "$WT" && gh pr create', "cd - && gh pr create",
                             "cd -P x && gh pr create", "cd `pwd` && gh pr create",
                             "(cd x) && gh pr create", "(cd x && true); gh pr create",
                             "cd a || gh pr create", "cd a || cd b && gh pr create"):
            self.assertIsNone(hook.cd_target(unresolvable), unresolvable)
        self.assertIsNone(hook.cd_target("gh pr create && cd x"))
        self.assertIsNone(hook.cd_target("echo cd x && gh pr create"))

    def test_deny_text_is_cleaned(self):
        self.assertEqual(hook._clean("a\u202eb\x1bc\u200bd\U0001F600e\u061cf"), "a?b?c?d?e?f")
        self.assertEqual(hook._clean("ok — fine\n\tindent"), "ok — fine\n\tindent")

    def test_body_file_read_is_capped(self):
        with tempfile.TemporaryDirectory(prefix="yuzu_test_") as tmp:
            (Path(tmp) / "b.md").write_text("x" * 20, encoding="utf-8")
            old = hook._MAX_BODY
            hook._MAX_BODY = 5
            try:
                self.assertEqual(hook.pr_args(["-F", "b.md"], tmp), ("dev", "xxxxx"))
            finally:
                hook._MAX_BODY = old

    def test_unexpected_error_is_reported_not_silent(self):
        payload = json.dumps({"tool_name": "Bash", "tool_input": ["not", "an", "object"]})
        r = subprocess.run([sys.executable, "-I", str(HOOK)], input=payload, capture_output=True,
                           text=True, env=hermetic_env(CLAUDE_PROJECT_DIR=str(ROOT)), timeout=60)
        self.assertEqual(r.returncode, 0)
        msg = json.loads(r.stdout)
        self.assertIn("docs-drift-pr-guard skipped (AttributeError)", msg["systemMessage"])
        self.assertNotIn("hookSpecificOutput", msg)  # still allows

    def test_pr_args(self):
        self.assertEqual(hook.pr_args(["--base=main", "--body", "b"], "/"), ("main", "b"))
        self.assertEqual(hook.pr_args([], "/"), ("dev", ""))

    def run_hook(self, cwd, command, project=ROOT):
        env = hermetic_env(CLAUDE_PROJECT_DIR=str(project))
        payload = json.dumps({"tool_name": "Bash", "cwd": str(cwd), "tool_input": {"command": command}})
        r = subprocess.run([sys.executable, "-I", str(HOOK)], input=payload, capture_output=True,
                           text=True, env=env, timeout=120)
        self.assertEqual(r.returncode, 0)  # always 0; the decision is in the JSON
        return r.stdout

    def test_never_executes_the_cwd_trees_gate(self):
        """The cwd is a repo whose own gate is planted. The hook must run the
        PROJECT's gate against it as data: it denies naming the tree's drift
        and the plant never runs. The specific deny is what makes this
        non-vacuous - an early fail-open return would also leave no marker."""
        with tempfile.TemporaryDirectory(prefix="yuzu_test_") as tmp:
            repo = Path(tmp)
            synthetic_tree(repo)
            mcp = repo / "server/core/src/mcp_server.cpp"
            mcp.write_text(mcp.read_text(encoding="utf-8").replace("};", '    {"zz_planted_drift", "d"},\n};'), encoding="utf-8")
            for name in ("check-docs-drift.py", "check-api-parity.py"):
                (repo / "scripts" / "ci" / name).write_text(PLANT, encoding="utf-8")
            subprocess.run(["git", "init", "-q", tmp], check=True, env=hermetic_env())
            git(repo, "add", "-A")
            git(repo, "commit", "-qm", "plant")
            git(repo, "update-ref", "refs/remotes/origin/dev", "HEAD")
            out = self.run_hook(repo, "gh pr create --title x")
            self.assertFalse((repo / "scripts" / "ci" / "EXECUTED").exists())
            decision = json.loads(out)["hookSpecificOutput"]
            self.assertEqual(decision["permissionDecision"], "deny")
            self.assertIn("new mcp_undocumented: zz_planted_drift", decision["permissionDecisionReason"])
            self.assertEqual(self.run_hook(repo, 'git commit -m "gh pr create"'), "")

    def test_project_without_gate_does_nothing(self):
        with tempfile.TemporaryDirectory(prefix="yuzu_test_") as tmp:
            self.assertEqual(self.run_hook(ROOT, "gh pr create", project=tmp), "")


class LiveTree(unittest.TestCase):
    def test_gate_passes_on_committed_tree(self):
        self.assertEqual(d.run_facts(), 0)


if __name__ == "__main__":
    unittest.main()
