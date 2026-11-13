#!/usr/bin/env python3
"""Tests for `scripts/whats-new.py` (what changed since the last pull).

Builds a throwaway git repository, makes an "old" commit and a "new" one, and runs the
real script against it. Stdlib only.
"""

import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
SCRIPT = ROOT / "scripts" / "whats-new.py"

MESON_OLD = "project('yuzu', 'cpp',\n  version: '0.15.0',\n  meson_version: '>=1.3.0')\n"
MESON_NEW = MESON_OLD.replace("0.15.0", "0.16.0")
PLUGIN_H = "#define YUZU_PLUGIN_ABI_VERSION {}\n#define YUZU_PLUGIN_ABI_VERSION_MIN 1\n"
LOCK = '{"1.2.0",\n[{<<"cowboy">>,{pkg,<<"cowboy">>,<<"{}">>},0}]}.\n'


def vcpkg(baseline, abseil):
    return json.dumps({
        "builtin-baseline": baseline,
        "dependencies": ["zlib", {"name": "abseil", "version>=": abseil}],
    })


class WhatsNew(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix="yuzu_test_whatsnew_")
        self.repo = Path(self.tmp.name)
        self.git("init", "-q", "-b", "dev")
        self.git("config", "user.email", "t@example.invalid")
        self.git("config", "user.name", "t")

    def tearDown(self):
        self.tmp.cleanup()

    def git(self, *args):
        return subprocess.run(["git", *args], cwd=self.repo, check=True,
                              capture_output=True, text=True).stdout.strip()

    def put(self, rel, text):
        p = self.repo / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(text, encoding="utf-8")

    def commit(self, msg):
        self.git("add", "-A")
        self.git("commit", "-q", "-m", msg)
        return self.git("rev-parse", "HEAD")

    def run_script(self, *args):
        return subprocess.run([sys.executable, str(SCRIPT), "--repo", str(self.repo), *args],
                              capture_output=True, text=True)

    def seed_old(self):
        self.put("meson.build", MESON_OLD)
        self.put("vcpkg.json", vcpkg("a" * 40, "20240116.1"))
        self.put("sdk/include/yuzu/plugin.h", PLUGIN_H.format(4))
        self.put("gateway/rebar.lock", LOCK.replace("{}", "2.18.0"))
        self.put("changelog.d/README.md", "readme\n")
        self.put("changelog.d/1-old.added.md", "- **Already there.**\n")
        return self.commit("old")

    def test_reports_bumps_and_fragments(self):
        old = self.seed_old()
        self.put("meson.build", MESON_NEW)
        self.put("vcpkg.json", vcpkg("b" * 40, "20250127.0"))
        self.put("sdk/include/yuzu/plugin.h", PLUGIN_H.format(5))
        self.put("gateway/rebar.lock", LOCK.replace("{}", "2.19.0"))
        self.put("changelog.d/2-new.fixed.md", "- **Fixed a thing.** More detail.\n  Second line.\n")
        self.put("changelog.d/3-sec.security.md", "- **Closed a hole.**\n")
        self.commit("new")
        res = self.run_script("--since", old)
        self.assertEqual(res.returncode, 0, res.stderr)
        out = res.stdout
        self.assertIn("project version (meson.build): 0.15.0 -> 0.16.0", out)
        self.assertIn("plugin ABI (YUZU_PLUGIN_ABI_VERSION): 4 -> 5", out)
        self.assertIn("vcpkg dependency abseil: >=20240116.1 -> >=20250127.0", out)
        self.assertIn("vcpkg builtin-baseline: aaaaaaaaaa -> bbbbbbbbbb", out)
        self.assertIn("gateway package cowboy: 2.18.0 -> 2.19.0", out)
        self.assertIn("**Fixed a thing.** More detail.", out)
        self.assertNotIn("Second line.", out)  # brief mode: first line only
        self.assertNotIn("Already there", out)  # added before the range
        self.assertLess(out.index("Security"), out.index("Fixed"))  # breaking-first order
        self.assertIn("Second line.", self.run_script("--since", old, "--full").stdout)

    def test_dependabot_bumps_split_runtime_and_tooling(self):
        old = self.seed_old()
        self.put("deploy/docker/Dockerfile.x", "FROM busybox\n")
        self.commit("build(deps): bump busybox from `fd7dc98` to `a46257e` in /deploy/docker")
        self.put(".github/workflows/ci.yml", "a\n")
        self.commit("build(deps): bump docker/login-action")
        self.put("requirements-ci.txt", "gcovr==8.8\n")
        self.commit("chore(deps): bump gcovr from 8.7 to 8.8")
        self.put("server/unrelated.cpp", "x\n")
        self.commit("fix: a subject that merely mentions build(deps): bump")
        out = self.run_script("--since", old).stdout
        self.assertIn("1 runtime image, 2 CI/tooling", out)
        self.assertIn("bump busybox", out)
        self.assertNotIn("docker/login-action", out)  # collapsed to a count
        self.assertIn("+ 2 CI/tooling bumps", out)
        self.assertNotIn("merely mentions", out)
        full = self.run_script("--since", old, "--full").stdout
        self.assertIn("docker/login-action", full)
        self.assertIn("bump gcovr", full)

    def test_no_dependabot_section_when_none(self):
        old = self.seed_old()
        self.put("x.txt", "x\n")
        self.commit("feat: ordinary change")
        self.assertNotIn("Dependabot", self.run_script("--since", old).stdout)

    def test_default_since_is_orig_head(self):
        old = self.seed_old()
        self.put("changelog.d/2-new.added.md", "- **New feature.**\n")
        self.commit("new")
        self.git("update-ref", "ORIG_HEAD", old)
        res = self.run_script()
        self.assertEqual(res.returncode, 0, res.stderr)
        self.assertIn("New feature", res.stdout)

    def test_no_orig_head_is_a_clear_error(self):
        self.seed_old()
        res = self.run_script()
        self.assertEqual(res.returncode, 2)
        self.assertIn("--since", res.stderr)

    def test_fragment_removed_by_a_release_is_still_listed(self):
        old = self.seed_old()
        self.put("changelog.d/2-gone.added.md", "- **Added then released.**\n")
        self.commit("add fragment")
        (self.repo / "changelog.d/2-gone.added.md").unlink()
        self.commit("release promote")
        self.assertIn("Added then released", self.run_script("--since", old).stdout)

    def test_renamed_fragment_listed_once(self):
        old = self.seed_old()
        self.put("changelog.d/0000-x.added.md", "- **Renamed one.**\n")
        self.commit("placeholder id")
        self.git("mv", "changelog.d/0000-x.added.md", "changelog.d/77-x.added.md")
        self.commit("rename to PR number")
        self.assertEqual(self.run_script("--since", old).stdout.count("Renamed one"), 1)

    def test_since_must_be_ancestor(self):
        self.seed_old()
        self.git("checkout", "-q", "-b", "other")
        self.put("x.txt", "x")
        other = self.commit("other")
        self.git("checkout", "-q", "dev")
        self.put("y.txt", "y")
        self.commit("dev side")
        res = self.run_script("--since", other)
        self.assertEqual(res.returncode, 2)
        self.assertIn("not an ancestor", res.stderr)


if __name__ == "__main__":
    unittest.main()
