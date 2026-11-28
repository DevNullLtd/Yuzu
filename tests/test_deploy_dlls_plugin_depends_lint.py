#!/usr/bin/env python3
r"""The Windows deploy_dlls target waits for every plugin to link (#8926).

The root meson.build's `deploy_dlls` custom_target runs
scripts/deploy_build_dlls.py, which copies every
`agents/plugins/<dir>/*.dll` in the build tree into `plugins/`. It is
`build_always_stale` and built by default, so without a `depends:` on the
plugin libraries ninja could run it while the linker still held a plugin DLL
open. The copy then failed with WinError 32 and, since a failed copy is fatal
(#8317), so did the Windows build: `Windows MSVC release` on main at
2eb355611e failed that way twice, on 3 and then 7 plugin DLLs.

The fix is a list: the root meson.build sets `yuzu_plugin_libs = []` before
the first plugin subdir, every plugin meson.build appends its library, and
`deploy_dlls` has `depends: yuzu_plugin_libs`. A plugin that forgets to append
brings the race back for that one DLL, and nothing else would notice, so these
checks read the source text (stdlib only, no Windows):

- The plugin set is DERIVED from every `subdir('agents/plugins/<dir>')` in the
  root meson.build, never hand-kept.
- Each such meson.build has exactly one `shared_library(` (or
  `shared_module(`), assigned to a variable, and a top-level (unindented)
  `yuzu_plugin_libs += <that variable>` after it. It never assigns
  `yuzu_plugin_libs =`, which would drop the plugins appended before it.
- The root meson.build assigns `yuzu_plugin_libs = []` exactly once, before
  the first plugin subdir, and the `deploy_dlls` custom_target has
  `depends: yuzu_plugin_libs`.

Each check also runs against a mutated copy of the sources and must fail
there, so a check that has stopped matching anything cannot pass silently.
"""

import re
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
MESON = ROOT / "meson.build"
PLUGINS = ROOT / "agents" / "plugins"

# The root meson.build builds 75 plugins today; far fewer means the subdir
# regex stopped matching, not that plugins were removed.
MIN_PLUGINS = 50

SUBDIR_RE = re.compile(r"\bsubdir\(\s*'agents/plugins/([^'/]+)'\s*\)")
LIB_CALL_RE = re.compile(r"\bshared_(?:library|module)\(")
LIB_ASSIGN_RE = re.compile(r"^(\w+)\s*=\s*shared_(?:library|module)\(", re.M)
ROOT_INIT_RE = re.compile(r"^\s*yuzu_plugin_libs\s*=\s*\[\s*\]\s*$", re.M)
ANY_ASSIGN_RE = re.compile(r"^\s*yuzu_plugin_libs\s*=(?!=)", re.M)


def strip_meson_comments(text: str) -> str:
    """Drop `#` comments from meson source (no `#` occurs inside the strings
    these checks read)."""
    return "\n".join(l.split("#", 1)[0] for l in text.splitlines())


def deploy_target_block(code: str):
    """The text of the `custom_target('deploy_dlls', ...)` call, or None."""
    m = re.search(r"custom_target\(\s*'deploy_dlls'", code)
    if not m:
        return None
    depth = 0
    for i in range(m.end() - 1, len(code)):
        if code[i] == "(":
            depth += 1
        elif code[i] == ")":
            depth -= 1
            if depth == 0:
                return code[m.start():i + 1]
    return None


def plugin_problems(d: str, text) -> list:
    if text is None:
        return [f"agents/plugins/{d}/meson.build: missing"]
    code = strip_meson_comments(text)
    where = f"agents/plugins/{d}/meson.build"
    calls = LIB_CALL_RE.findall(code)
    if len(calls) != 1:
        return [f"{where}: expected one shared_library, found {len(calls)}"]
    assigned = LIB_ASSIGN_RE.search(code)
    if not assigned:
        return [f"{where}: the shared_library is not assigned to a variable, so it cannot be appended to yuzu_plugin_libs"]
    var = assigned.group(1)
    found = []
    append = re.search(rf"^yuzu_plugin_libs\s*\+=\s*(?:\[\s*{var}\s*\]|{var})\s*$", code, re.M)
    if not append:
        found.append(f"{where}: no top-level `yuzu_plugin_libs += {var}`; deploy_dlls would not wait for this plugin (#8926)")
    elif append.start() < assigned.start():
        found.append(f"{where}: `yuzu_plugin_libs += {var}` comes before {var} is assigned")
    if ANY_ASSIGN_RE.search(code):
        found.append(f"{where}: assigns `yuzu_plugin_libs =`, which drops every plugin appended before it")
    return found


def problems(meson_text: str, read_plugin_meson) -> list:
    code = strip_meson_comments(meson_text)
    found = []
    dirs = SUBDIR_RE.findall(code)
    if len(dirs) < MIN_PLUGINS:
        found.append(f"meson.build: found only {len(dirs)} agents/plugins subdirs; the discovery stopped matching")
    if len(dirs) != len(set(dirs)):
        found.append("meson.build: an agents/plugins subdir is listed twice")

    inits = list(ROOT_INIT_RE.finditer(code))
    if len(inits) != 1 or len(ANY_ASSIGN_RE.findall(code)) != 1:
        found.append("meson.build: expected exactly one `yuzu_plugin_libs = []`")
    else:
        first_subdir = SUBDIR_RE.search(code)
        if first_subdir and inits[0].start() > first_subdir.start():
            found.append("meson.build: `yuzu_plugin_libs = []` comes after the first plugin subdir, so it drops their appends")

    block = deploy_target_block(code)
    if block is None:
        found.append("meson.build: no custom_target('deploy_dlls', ...) found")
    elif not re.search(r"\bdepends\s*:\s*yuzu_plugin_libs\b", block):
        found.append("meson.build: deploy_dlls has no `depends: yuzu_plugin_libs`; it can run while plugins still link (#8926)")

    for d in dirs:
        found += plugin_problems(d, read_plugin_meson(d))
    return found


def read_plugin_meson_from_tree(d: str):
    p = PLUGINS / d / "meson.build"
    return p.read_text(encoding="utf-8") if p.is_file() else None


class DeployDllsPluginDepends(unittest.TestCase):
    def setUp(self):
        self.meson = MESON.read_text(encoding="utf-8")

    def test_source_is_clean(self):
        self.assertEqual(problems(self.meson, read_plugin_meson_from_tree), [])

    def test_root_mutations_are_caught(self):
        mutations = {
            "depends dropped": ("    depends: yuzu_plugin_libs,\n", ""),
            "depends names another list": ("    depends: yuzu_plugin_libs,\n", "    depends: [],\n"),
            "init dropped": ("yuzu_plugin_libs = []\n", ""),
            "init moved after the plugin subdirs": (
                "yuzu_plugin_libs = []\nif build_agent", "if build_agent"),
            "init duplicated": ("yuzu_plugin_libs = []\n", "yuzu_plugin_libs = []\nyuzu_plugin_libs = []\n"),
            "deploy target renamed": ("custom_target('deploy_dlls',", "custom_target('deploy_plugin_dlls',"),
            "a new plugin without an append": (
                "  subdir('agents/plugins/pkg_inventory')",
                "  subdir('agents/plugins/pkg_inventory')\n  subdir('agents/plugins/zz_new_plugin')"),
        }

        def reader(d):
            if d == "zz_new_plugin":
                return "zz_new_plugin_lib = shared_library(\n  'zz_new_plugin',\n  name_prefix: '',\n)\n"
            return read_plugin_meson_from_tree(d)

        for name, (old, new) in mutations.items():
            with self.subTest(mutation=name):
                self.assertIn(old, self.meson, f"mutation anchor for {name!r} not found")
                mutated = self.meson.replace(old, new, 1)
                if name == "init moved after the plugin subdirs":
                    mutated = mutated.replace("# ── Server", "yuzu_plugin_libs = []\n# ── Server", 1)
                self.assertNotEqual(problems(mutated, reader), [], f"{name!r} was not caught")

    def test_plugin_mutations_are_caught(self):
        def reader_with(target, transform):
            def reader(d):
                text = read_plugin_meson_from_tree(d)
                return transform(text) if d == target and text is not None else text
            return reader

        append = "yuzu_plugin_libs += wol_plugin_lib\n"
        cases = {
            "append dropped": lambda t: t.replace(append, ""),
            "append commented out": lambda t: t.replace(append, "# " + append),
            "append indented under a condition": lambda t: t.replace(append, "if false\n  " + append + "endif\n"),
            "append names another variable": lambda t: t.replace(append, "yuzu_plugin_libs += wol_deps\n"),
            "library not assigned": lambda t: t.replace("wol_plugin_lib = shared_library(", "shared_library("),
            "list reset": lambda t: t.replace(append, "yuzu_plugin_libs = [wol_plugin_lib]\n"),
            "a second library": lambda t: t + "shared_library('wol2', name_prefix: '')\n",
            "meson.build missing": lambda t: None,
        }
        for name, transform in cases.items():
            with self.subTest(mutation=name):
                self.assertIn(append, read_plugin_meson_from_tree("wol"), "mutation anchor not found")
                self.assertNotEqual(problems(self.meson, reader_with("wol", transform)), [], f"{name!r} was not caught")

    def test_list_form_append_is_accepted(self):
        def reader(d):
            text = read_plugin_meson_from_tree(d)
            if d == "wol":
                text = text.replace("yuzu_plugin_libs += wol_plugin_lib\n", "yuzu_plugin_libs += [wol_plugin_lib]\n")
            return text
        self.assertEqual(problems(self.meson, reader), [])


if __name__ == "__main__":
    sys.exit(0 if unittest.main(exit=False).result.wasSuccessful() else 1)
