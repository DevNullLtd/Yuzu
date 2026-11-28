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
  root meson.build, never hand-kept, and it must equal the set of
  `agents/plugins/*/meson.build` files on disk, so a plugin registered some
  other way (a `foreach`, a computed path) fails here instead of going
  unchecked. Every plugin subdir comes before the `deploy_dlls` target, which
  only sees the list as it stands at that point.
- Each such meson.build has exactly one library call (`shared_library`,
  `shared_module`, `both_libraries` or `library`), assigned to a variable
  outside any `if`/`foreach` block, and a `yuzu_plugin_libs += <that
  variable>` after it, also outside any block. Block depth is tracked from
  `if`/`foreach` ... `endif`/`endforeach`, not from indentation, which meson
  ignores. The file never calls `subdir_done()` (it would skip the append)
  and never assigns `yuzu_plugin_libs =`, which would drop the plugins
  appended before it. A plugin built only on some OSes puts the condition on
  its root `subdir()` call.
- The root meson.build assigns `yuzu_plugin_libs = []` exactly once, outside
  any block and before the first plugin subdir, and the `deploy_dlls`
  custom_target has `depends: yuzu_plugin_libs`.

Limits, by design.

Fails red (a correct or fixable file is rejected):
- One library per plugin directory: a second one fails here, so the rule is
  widened deliberately rather than missed.
- The append must name the library variable directly, not an alias.
- The on-disk set is a filesystem glob, so an untracked plugin directory in a
  local tree fails here until it is registered or removed.

Not caught (green):
- A `.dll` produced by a `custom_target` in a plugin directory.
- A literal `subdir('agents/plugins/...')` inside a root string.
- A second `custom_target('deploy_dlls', ...)` (meson rejects that).

Either way: block depth is read line by line, so a multi-line string with a
line that starts with `if`, `foreach`, `endif` or `endforeach` skews it. That
can fail a correct file, or pass an append that is really inside a block.
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
_LIB_FN = r"(?:shared_library|shared_module|both_libraries|library)\s*\("
LIB_CALL_RE = re.compile(r"\b" + _LIB_FN)
LIB_ASSIGN_RE = re.compile(r"^[ \t]*(\w+)\s*=\s*" + _LIB_FN, re.M)
ROOT_INIT_RE = re.compile(r"^\s*yuzu_plugin_libs\s*=\s*\[\s*\]\s*$", re.M)
ANY_ASSIGN_RE = re.compile(r"^\s*yuzu_plugin_libs\s*=(?!=)", re.M)
SUBDIR_DONE_RE = re.compile(r"\bsubdir_done\s*\(")
BLOCK_OPEN_RE = re.compile(r"^\s*(?:if|foreach)\b")
BLOCK_CLOSE_RE = re.compile(r"^\s*(?:endif|endforeach)\b")


def strip_meson_comments(text: str) -> str:
    """Drop a leading BOM and `#` comments from meson source (no `#` occurs
    inside the strings these checks read)."""
    return "\n".join(l.split("#", 1)[0] for l in text.lstrip("\ufeff").splitlines())


def block_depth_at(code: str, offset: int) -> int:
    """How many `if`/`foreach` blocks enclose the line holding `offset`.

    Meson ignores indentation, so a condition is found by counting block
    keywords, never by looking at leading whitespace."""
    depth = 0
    pos = 0
    for line in code.splitlines(keepends=True):
        end = pos + len(line)
        if BLOCK_CLOSE_RE.match(line):
            depth -= 1
        if pos <= offset < end:
            return depth
        if BLOCK_OPEN_RE.match(line):
            depth += 1
        pos = end
    return depth


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
        return [f"{where}: expected one library call (shared_library, shared_module, both_libraries or library), found {len(calls)}; this lint allows one library per plugin directory, because deploy_dlls copies every DLL in it, so a second library needs this lint widened to check it too"]
    assigned = LIB_ASSIGN_RE.search(code)
    if not assigned:
        return [f"{where}: the library call is not assigned to a variable, so it cannot be appended to yuzu_plugin_libs"]
    var = assigned.group(1)
    found = []
    if block_depth_at(code, assigned.start()) != 0:
        found.append(f"{where}: {var} is assigned inside an if/foreach block; put the condition on the plugin's subdir() in the root meson.build instead")
    appends = list(re.finditer(rf"^[ \t]*yuzu_plugin_libs\s*\+=\s*(?:\[\s*{var}\s*(?:,\s*)?\]|{var})\s*$", code, re.M))
    top = [a for a in appends if block_depth_at(code, a.start()) == 0]
    if not top:
        if appends:
            found.append(f"{where}: `yuzu_plugin_libs += {var}` is inside an if/foreach block; it must run whenever the plugin is built (#8926)")
        else:
            found.append(f"{where}: no `yuzu_plugin_libs += {var}`; deploy_dlls would not wait for this plugin (#8926)")
    elif top[0].start() < assigned.start():
        found.append(f"{where}: `yuzu_plugin_libs += {var}` comes before {var} is assigned")
    if SUBDIR_DONE_RE.search(code):
        found.append(f"{where}: calls subdir_done(), which can skip the `yuzu_plugin_libs += {var}` append; put the condition on the root subdir() instead")
    if ANY_ASSIGN_RE.search(code):
        found.append(f"{where}: assigns `yuzu_plugin_libs =`, which drops every plugin appended before it")
    return found


def plugin_dirs_on_disk() -> list:
    return sorted(p.parent.name for p in PLUGINS.glob("*/meson.build"))


def problems(meson_text: str, read_plugin_meson, on_disk_dirs=None) -> list:
    if on_disk_dirs is None:
        on_disk_dirs = plugin_dirs_on_disk()
    code = strip_meson_comments(meson_text)
    found = []
    matches = list(SUBDIR_RE.finditer(code))
    dirs = [m.group(1) for m in matches]
    if len(dirs) < MIN_PLUGINS:
        found.append(f"meson.build: found only {len(dirs)} agents/plugins subdirs; the discovery stopped matching")
    if len(dirs) != len(set(dirs)):
        found.append("meson.build: an agents/plugins subdir is listed twice")
    for d in sorted(set(on_disk_dirs) - set(dirs)):
        found.append(f"meson.build: agents/plugins/{d}/meson.build exists but has no literal `subdir('agents/plugins/{d}')`, so this lint cannot check it appends to yuzu_plugin_libs")

    inits = list(ROOT_INIT_RE.finditer(code))
    if len(inits) != 1 or len(ANY_ASSIGN_RE.findall(code)) != 1:
        found.append("meson.build: expected exactly one `yuzu_plugin_libs = []`")
    else:
        if block_depth_at(code, inits[0].start()) != 0:
            found.append("meson.build: `yuzu_plugin_libs = []` is inside an if/foreach block")
        if matches and inits[0].start() > matches[0].start():
            found.append("meson.build: `yuzu_plugin_libs = []` comes after the first plugin subdir, so it drops their appends")

    block = deploy_target_block(code)
    if block is None:
        found.append("meson.build: no custom_target('deploy_dlls', ...) found")
    else:
        if not re.search(r"\bdepends\s*:\s*yuzu_plugin_libs\b", block):
            found.append("meson.build: deploy_dlls has no `depends: yuzu_plugin_libs`; it can run while plugins still link (#8926)")
        deploy_at = code.index(block)
        for m in matches:
            if m.start() > deploy_at:
                found.append(f"meson.build: subdir('agents/plugins/{m.group(1)}') comes after custom_target('deploy_dlls'), which only sees the plugins appended before it")

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
            "a plugin registered by a foreach": (
                "  subdir('agents/plugins/wol')\n",
                "  foreach _p : ['wol']\n    subdir('agents/plugins/' + _p)\n  endforeach\n"),
            "a plugin subdir after deploy_dlls": (
                "# ── Summary", "subdir('agents/plugins/zz_new_plugin')\n# ── Summary"),
            "init inside a block": (
                "yuzu_plugin_libs = []\nif build_agent", "if true\nyuzu_plugin_libs = []\nendif\nif build_agent"),
        }

        def reader(d):
            if d == "zz_new_plugin":
                if "a new plugin without an append" in current:
                    return "zz_new_plugin_lib = shared_library(\n  'zz_new_plugin',\n  name_prefix: '',\n)\n"
                return ("zz_new_plugin_lib = shared_library(\n  'zz_new_plugin',\n  name_prefix: '',\n)\n"
                        "yuzu_plugin_libs += zz_new_plugin_lib\n")
            return read_plugin_meson_from_tree(d)

        current = set()
        for name, (old, new) in mutations.items():
            current.clear()
            current.add(name)
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
            "unindented append inside if/endif": lambda t: t.replace(append, "if false\n" + append + "endif\n"),
            "append only in an else branch": lambda t: t.replace(append, "if false\nelse\n" + append + "endif\n"),
            "subdir_done before the append": lambda t: t.replace(append, "subdir_done()\n" + append),
            "a helper library()": lambda t: t + "wol_helper = library('wol_helper', 'x.cpp')\n",
            "library assigned inside an OS if": lambda t: t.replace(
                "wol_plugin_lib = shared_library(", "if true\nwol_plugin_lib = shared_library(").replace(
                append, "endif\n" + append),
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

    def test_formatting_variants_are_accepted(self):
        append = "yuzu_plugin_libs += wol_plugin_lib\n"
        variants = {
            "BOM": lambda t: "\ufeff" + t,
            "tab-indented append": lambda t: t.replace(append, "\t" + append),
            "multi-line list append": lambda t: t.replace(append, "yuzu_plugin_libs += [\n  wol_plugin_lib,\n]\n"),
            "trailing comma": lambda t: t.replace(append, "yuzu_plugin_libs += [wol_plugin_lib,]\n"),
            "space before the paren": lambda t: t.replace("= shared_library(", "= shared_library ("),
        }
        for name, transform in variants.items():
            with self.subTest(variant=name):
                original = read_plugin_meson_from_tree("wol")
                self.assertNotEqual(transform(original), original, f"variant {name!r} no longer changes the file")

                def reader(d, transform=transform):
                    text = read_plugin_meson_from_tree(d)
                    return transform(text) if d == "wol" else text
                self.assertEqual(problems(self.meson, reader), [], f"{name!r} was wrongly rejected")


if __name__ == "__main__":
    sys.exit(0 if unittest.main(exit=False).result.wasSuccessful() else 1)
