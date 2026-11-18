#!/usr/bin/env python3
r"""Every agent plugin the build produces is in the Windows installer (#4867).

deploy/packaging/windows/yuzu-agent.iss names each plugin DLL on its own
`Source:` line, while every other packaging path (the release zip, the deb and
rpm, the macOS pkg, the agent images) takes the plugins by glob. The .iss is
compiled only by release.yml, so a plugin added to the build without an .iss
line ships in the zip and silently not in the installer; six had drifted out
that way (browser_inventory, license_scan, netprobe, printing,
privacy_permissions, rdp_control). Five are now installed; license_scan is a
recorded `plugin-not-installed` exclusion (ADR-3006 D10: installing it would
start the daily software_licensing collection with no operator action;
follow-up #8309), and the release zip still carries it. These checks read the
source text; stdlib only, no Windows, no Inno Setup.

What they pin:

- The set of plugins the build produces is DERIVED, never hand-kept: every
  `subdir('agents/plugins/<dir>')` in the root meson.build, and each such
  directory's one `shared_library('<name>', ...)` (the DLL is `<name>.dll`,
  `name_prefix: ''`). Every plugin `subdir` is counted, including the four demo
  plugins behind `build_examples`: that option defaults to true and the
  release's Windows configure does not set it, which is also pinned here (a
  release that stopped building them would fail ISCC on their lines).
- Each such plugin has exactly one `Source:` line
  `{#BuildDir}\agents\plugins\<dir>\<name>.dll`, installed to
  `{app}\plugins`, under a component declared in [Components] (never `core`
  unless it is already one of the core plugins below), OR one recorded
  exclusion comment in [Files]:
      ; plugin-not-installed: <dir>: <reason, at least 20 characters>
  Leaving a plugin out of the installer is then a reviewed line in the .iss,
  not an omission.
- No `Source:` line names a plugin the build does not produce (ISCC would
  fail on it at release time), no plugin is both listed and excluded, and an
  exclusion names a plugin the build produces.
- [UninstallDelete] deletes, by exact name, every excluded plugin's DLL
  (`{app}\plugins\<name>.dll`: the zip carries it, so an operator may have
  copied it in, and the uninstaller removes only what [Files] installed) and
  the two files agent self-update leaves in `{app}\bin`
  (`yuzu-agent.old.exe`, `.yuzu-update-verified`). No `files` entry there
  uses a wildcard.

Each check also runs against a mutated copy of the sources and must fail
there, so a check that has stopped matching anything cannot pass silently.
"""

import re
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
ISS = ROOT / "deploy" / "packaging" / "windows" / "yuzu-agent.iss"
MESON = ROOT / "meson.build"
OPTIONS = ROOT / "meson.options"
RELEASE = ROOT / ".github" / "workflows" / "release.yml"
PLUGINS = ROOT / "agents" / "plugins"

# The plugins installed with the fixed `core` component (no plugin component
# can deselect them). Any other plugin must use a `plugins\...` component, so a
# new plugin cannot quietly become impossible to leave out.
CORE_PLUGINS = frozenset({
    "status", "agent_actions", "agent_logging", "tags", "diagnostics",
    "content_dist", "device_identity",
})

# Files agent self-update writes beside yuzu-agent.exe (agents/core/src/updater.cpp):
# the previous executable, kept for rollback, and the update-verified marker.
OTA_LEFTOVERS = (
    'Type: files; Name: "{app}\\bin\\yuzu-agent.old.exe"',
    'Type: files; Name: "{app}\\bin\\.yuzu-update-verified"',
)

EXCLUDE_RE = re.compile(r"^\s*;\s*plugin-not-installed:\s*([a-z0-9_]+)\s*:\s*(.*?)\s*$")
SOURCE_RE = re.compile(r'^\s*Source:\s*"([^"]*)"(.*)$')
PLUGIN_SRC_RE = re.compile(r"^\{#BuildDir\}\\agents\\plugins\\([^\\]+)\\([^\\]+)$")


def strip_meson_comments(text: str) -> str:
    """Drop `#` comments from meson source (no `#` occurs inside the strings
    these checks read)."""
    return "\n".join(l.split("#", 1)[0] for l in text.splitlines())


def built_plugin_dirs(meson_text: str) -> list:
    return re.findall(r"\bsubdir\(\s*'agents/plugins/([^'/]+)'\s*\)", strip_meson_comments(meson_text))


def plugin_dll(plugin_meson_text: str):
    """(<name>.dll, problem) from a plugin's meson.build."""
    code = strip_meson_comments(plugin_meson_text)
    names = re.findall(r"\bshared_(?:library|module)\(\s*'([^']+)'", code)
    if len(names) != 1:
        return None, f"expected one shared_library, found {len(names)}"
    if not re.search(r"\bname_prefix:\s*''", code):
        return None, "shared_library has no `name_prefix: ''`, so its DLL name is not derivable here"
    return names[0] + ".dll", None


def section(iss: str, name: str) -> str:
    m = re.search(rf"^\[{re.escape(name)}\]\s*$(.*?)(?=^\[[A-Za-z]+\]\s*$|\Z)", iss, re.S | re.M)
    return m.group(1) if m else ""


def field(rest: str, key: str):
    m = re.search(rf";\s*{key}:\s*(\"[^\"]*\"|[^;]+)", rest)
    if not m:
        return None
    return m.group(1).strip().strip('"').strip()


def problems(iss: str, meson_text: str, read_plugin_meson, options: str, release: str) -> list:
    found = []

    dirs = built_plugin_dirs(meson_text)
    if len(dirs) < 10:
        found.append(f"meson.build: found only {len(dirs)} agents/plugins subdirs; the discovery stopped matching")
    if len(set(dirs)) != len(dirs):
        found.append("meson.build: an agents/plugins subdir is listed twice")
    expected = {}
    for d in dirs:
        text = read_plugin_meson(d)
        if text is None:
            found.append(f"agents/plugins/{d}/meson.build: missing")
            continue
        dll, why = plugin_dll(text)
        if why:
            found.append(f"agents/plugins/{d}/meson.build: {why}")
            continue
        expected[d] = dll

    # build_examples: on by default, and the release's Windows build leaves it.
    if not re.search(r"option\('build_examples',\s*type:\s*'boolean',\s*value:\s*true\b", options):
        found.append("meson.options: build_examples no longer defaults to true; the demo plugins' "
                     "installer lines would name DLLs the release does not build")
    m = re.search(r"^  build-windows:\n(.*?)(?=^  [a-z0-9-]+:\n|\Z)", release, re.S | re.M)
    if not m:
        found.append("release.yml: build-windows job not found")
    elif "build_examples" in m.group(1):
        found.append("release.yml: build-windows sets build_examples; revisit the demo plugins' installer lines")

    components = set(re.findall(r'^\s*Name:\s*"([^"]+)"', section(iss, "Components"), re.M))
    if "core" not in components:
        found.append("[Components]: no `core` component found; the section parse stopped matching")

    files = section(iss, "Files")
    if not files.strip():
        found.append("[Files] section not found")
    listed, excluded = {}, {}
    for line in files.splitlines():
        ex = EXCLUDE_RE.match(line)
        if ex:
            name, reason = ex.group(1), ex.group(2)
            if name in excluded:
                found.append(f"plugin-not-installed: {name} is recorded twice")
            if len(reason) < 20:
                found.append(f"plugin-not-installed: {name} has no recorded reason (need a sentence, got {reason!r})")
            excluded[name] = reason
            continue
        if re.match(r"^\s*;", line):
            continue
        src = SOURCE_RE.match(line)
        if not src:
            continue
        pm = PLUGIN_SRC_RE.match(src.group(1))
        if not pm:
            if "agents\\plugins\\" in src.group(1):
                found.append(f"[Files]: plugin Source line not in the one-DLL form: {line.strip()}")
            continue
        d, dll = pm.group(1), pm.group(2)
        rest = src.group(2)
        if d in listed:
            found.append(f"[Files]: plugin {d} has more than one Source line")
        listed[d] = rest
        if d not in expected:
            found.append(f"[Files]: {d} is not a plugin the build produces (no subdir in meson.build); ISCC would fail on it")
            continue
        if dll != expected[d]:
            found.append(f"[Files]: {d} names {dll}, but its meson.build builds {expected[d]}")
        dest = field(rest, "DestDir")
        if dest != "{app}\\plugins":
            found.append(f"[Files]: {d} is installed to {dest!r}, not {{app}}\\plugins")
        comp = field(rest, "Components")
        if comp is None:
            found.append(f"[Files]: {d} has no Components:")
        else:
            for c in comp.split():
                if c not in components:
                    found.append(f"[Files]: {d} uses component {c!r}, which [Components] does not declare")
            if comp == "core" and d not in CORE_PLUGINS:
                found.append(f"[Files]: {d} is installed with the fixed core component; give it a plugins\\... component")
            if comp != "core" and d in CORE_PLUGINS:
                found.append(f"[Files]: core plugin {d} is no longer installed with the core component")

    for d in sorted(expected):
        if d in listed and d in excluded:
            found.append(f"{d}: both installed and recorded as plugin-not-installed")
        elif d not in listed and d not in excluded:
            found.append(f"{d}: built by meson.build but has no installer Source line and no "
                         f"`; plugin-not-installed: {d}: <reason>` record in yuzu-agent.iss")
    for d in sorted(set(excluded) - set(expected)):
        found.append(f"plugin-not-installed: {d} is not a plugin the build produces (stale record)")

    # [UninstallDelete]: an excluded plugin's DLL and the self-update leftovers.
    ud = [l.strip() for l in section(iss, "UninstallDelete").splitlines()
          if l.strip() and not l.strip().startswith(";")]
    if not ud:
        found.append("[UninstallDelete] section not found or empty")
    for d in sorted(set(excluded) & set(expected)):
        entry = f'Type: files; Name: "{{app}}\\plugins\\{expected[d]}"'
        if ud.count(entry) != 1:
            found.append(f"[UninstallDelete]: excluded plugin {d} needs exactly one `{entry}` "
                         f"(the zip carries it; uninstall must not leave it to be loaded)")
    for entry in OTA_LEFTOVERS:
        if ud.count(entry) != 1:
            found.append(f"[UninstallDelete]: needs exactly one `{entry}` (left by agent self-update)")
    for l in ud:
        if l.startswith("Type: files;") and re.search(r"[*?]", l):
            found.append(f"[UninstallDelete]: a files entry uses a wildcard: {l}")
    return found


def read_plugin_meson_from_tree(d: str):
    p = PLUGINS / d / "meson.build"
    return p.read_text(encoding="utf-8") if p.is_file() else None


class InstallerPluginCoverage(unittest.TestCase):
    def setUp(self):
        self.iss = ISS.read_text(encoding="utf-8")
        self.meson = MESON.read_text(encoding="utf-8")
        self.options = OPTIONS.read_text(encoding="utf-8")
        self.release = RELEASE.read_text(encoding="utf-8")

    def run_problems(self, iss=None, meson=None, options=None, release=None, reader=None):
        return problems(iss if iss is not None else self.iss,
                        meson if meson is not None else self.meson,
                        reader or read_plugin_meson_from_tree,
                        options if options is not None else self.options,
                        release if release is not None else self.release)

    def test_source_is_clean(self):
        self.assertEqual(self.run_problems(), [])

    def test_mutations_are_caught(self):
        netprobe = ('Source: "{#BuildDir}\\agents\\plugins\\netprobe\\netprobe.dll"; DestDir: "{app}\\plugins"; '
                    'Components: plugins\\network; Flags: ignoreversion\n')
        mutations = {
            "a plugin line dropped": ("iss", netprobe, ""),
            "the license_scan exclusion dropped": ("iss", "; plugin-not-installed: license_scan:", "; license_scan:"),
            "a plugin line dropped, excluded without a reason": ("iss", netprobe, "; plugin-not-installed: netprobe: no\n"),
            "a plugin both listed and excluded": ("iss", netprobe, netprobe + "; plugin-not-installed: netprobe: kept out of the installer on purpose\n"),
            "a plugin line commented out": ("iss", netprobe, "; " + netprobe),
            "a stale exclusion": ("iss", netprobe, netprobe + "; plugin-not-installed: no_such_plugin: kept out of the installer on purpose\n"),
            "a line for a plugin that is not built": ("iss", netprobe, netprobe.replace("netprobe", "no_such_plugin")),
            "a duplicate plugin line": ("iss", netprobe, netprobe + netprobe),
            "wrong DLL name": ("iss", "plugins\\netprobe\\netprobe.dll", "plugins\\netprobe\\net_probe.dll"),
            "wrong destination": ("iss", netprobe, netprobe.replace('DestDir: "{app}\\plugins"', 'DestDir: "{app}\\bin"')),
            "undeclared component": ("iss", netprobe, netprobe.replace("plugins\\network", "plugins\\networking")),
            "no component": ("iss", netprobe, netprobe.replace("Components: plugins\\network; ", "")),
            "a plugin made unselectable (core)": ("iss", netprobe, netprobe.replace("plugins\\network", "core")),
            "a core plugin moved off core": ("iss", 'plugins\\status\\status.dll"; DestDir: "{app}\\plugins"; Components: core;', 'plugins\\status\\status.dll"; DestDir: "{app}\\plugins"; Components: plugins\\system;'),
            "a new plugin added to the build": ("meson", "  subdir('agents/plugins/pkg_inventory')", "  subdir('agents/plugins/pkg_inventory')\n  subdir('agents/plugins/zz_new_plugin')"),
            "build_examples default flipped": ("options", "option('build_examples', type: 'boolean', value: true", "option('build_examples', type: 'boolean', value: false"),
            "license_scan uninstall entry dropped": ("iss", 'Type: files; Name: "{app}\\plugins\\license_scan.dll"\n', ""),
            "license_scan uninstall entry misnamed": ("iss", '{app}\\plugins\\license_scan.dll"\n', '{app}\\plugins\\licence_scan.dll"\n'),
            "license_scan uninstall entry commented out": ("iss", 'Type: files; Name: "{app}\\plugins\\license_scan.dll"\n', '; Type: files; Name: "{app}\\plugins\\license_scan.dll"\n'),
            "a new exclusion without an uninstall entry": ("iss", netprobe, "; plugin-not-installed: netprobe: kept out of the installer on purpose\n"),
            "old exe uninstall entry dropped": ("iss", 'Type: files; Name: "{app}\\bin\\yuzu-agent.old.exe"\n', ""),
            "update marker uninstall entry dropped": ("iss", 'Type: files; Name: "{app}\\bin\\.yuzu-update-verified"\n', ""),
            "a wildcard uninstall entry added": ("iss", 'Type: files; Name: "{app}\\bin\\yuzu-agent.old.exe"\n', 'Type: files; Name: "{app}\\bin\\yuzu-agent.old.exe"\nType: files; Name: "{app}\\plugins\\*.dll"\n'),
            "uninstall section renamed": ("iss", "[UninstallDelete]\n", "[UninstallDeleted]\n"),
            "release turns build_examples off": ("release", "            -Dbuild_tests=false `\n", "            -Dbuild_tests=false `\n            -Dbuild_examples=false `\n"),
        }
        for name, (which, old, new) in mutations.items():
            with self.subTest(mutation=name):
                srcs = {"iss": self.iss, "meson": self.meson, "options": self.options, "release": self.release}
                self.assertTrue(old in srcs[which], f"mutation anchor for {name!r} not found")
                srcs[which] = srcs[which].replace(old, new, 1)

                def reader(d):
                    if d == "zz_new_plugin":
                        return "shared_library(\n  'zz_new_plugin',\n  name_prefix: '',\n)\n"
                    return read_plugin_meson_from_tree(d)

                self.assertNotEqual(self.run_problems(srcs["iss"], srcs["meson"], srcs["options"], srcs["release"], reader),
                                    [], f"{name!r} was not caught")

    def test_plugin_meson_mutations_are_caught(self):
        def reader_with(d_target, transform):
            def reader(d):
                text = read_plugin_meson_from_tree(d)
                return transform(text) if d == d_target and text is not None else text
            return reader
        cases = {
            "target renamed": reader_with("printing", lambda t: t.replace("'printing'", "'printing2'", 1)),
            "name_prefix dropped": reader_with("printing", lambda t: re.sub(r"\n\s*name_prefix:\s*'',", "\n", t, count=1)),
            "plugin meson.build missing": reader_with("printing", lambda t: None),
        }
        for name, reader in cases.items():
            with self.subTest(mutation=name):
                self.assertNotEqual(self.run_problems(reader=reader), [], f"{name!r} was not caught")


if __name__ == "__main__":
    sys.exit(0 if unittest.main(exit=False).result.wasSuccessful() else 1)
