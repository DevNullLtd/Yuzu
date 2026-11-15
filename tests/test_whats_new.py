#!/usr/bin/env python3
"""Tests for `scripts/whats-new.py` (what changed since the last pull).

Builds throwaway git repositories (a real upstream and clone for the `git pull` flows, the
real `assemble-changelog.py promote` for the release flow), runs the real script against
them and asserts on what it prints. Hermetic: no global or system git config, no hooks, no
signing, and nothing depends on the clock (commit dates are pinned). Stdlib only.
"""

import importlib.util
import json
import os
import shutil
import subprocess
import sys
import tempfile
import threading
import unittest
from unittest import mock
from datetime import datetime, timedelta, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
SCRIPT = ROOT / "scripts" / "whats-new.py"
ASSEMBLE = ROOT / "scripts" / "assemble-changelog.py"

MESON_OLD = "project('yuzu', 'cpp',\n  version: '0.15.0',\n  meson_version: '>=1.3.0')\n"
MESON_NEW = MESON_OLD.replace("0.15.0", "0.16.0")
PLUGIN_H = "#define YUZU_PLUGIN_ABI_VERSION {}\n#define YUZU_PLUGIN_ABI_VERSION_MIN {}\n"
LOCK = '{"1.2.0",\n[{<<"cowboy">>,{pkg,<<"cowboy">>,<<"%s">>},0}]}.\n'
CHANGELOG = "# Changelog\n\n## [Unreleased]\n\nNotes.\n\n## [1.2.0] - 2026-09-01\n\n### Fixed\n\n- **Older.**\n"


def load(path, name):
    spec = importlib.util.spec_from_file_location(name, path)
    mod = importlib.util.module_from_spec(spec)
    sys.modules[name] = mod
    spec.loader.exec_module(mod)
    return mod


WN = load(SCRIPT, "whats_new_under_test")


def vcpkg(baseline, deps, features=None, overrides=None):
    data = {"builtin-baseline": baseline, "dependencies": deps}
    if features:
        data["features"] = features
    if overrides:
        data["overrides"] = overrides
    return json.dumps(data)


class GitCase(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix="yuzu_test_whatsnew_")
        self.dir = Path(self.tmp.name)
        self.env = {
            # No inherited GIT_* variable (a hook exports GIT_DIR and GIT_INDEX_FILE) may point git elsewhere.
            **{k: v for k, v in os.environ.items() if not k.startswith("GIT_")},
            "GIT_CONFIG_GLOBAL": os.devnull, "GIT_CONFIG_SYSTEM": os.devnull, "GIT_CONFIG_NOSYSTEM": "1",
            "TZ": "UTC",
            # No user-level git files (a global ignore or attributes file) change what a commit holds.
            "HOME": str(self.dir / "home"), "XDG_CONFIG_HOME": str(self.dir / "home"), "USERPROFILE": str(self.dir / "home"),
            # Never discover a repository above the temp directory (TMPDIR may sit inside one).
            "GIT_CEILING_DIRECTORIES": str(Path(self.tmp.name).parent),
            "GIT_AUTHOR_NAME": "t", "GIT_AUTHOR_EMAIL": "t@example.invalid",
            "GIT_COMMITTER_NAME": "t", "GIT_COMMITTER_EMAIL": "t@example.invalid",
        }
        (self.dir / "home").mkdir()
        self.clock = 0

    def tearDown(self):
        self.tmp.cleanup()

    def git(self, repo, *args):
        done = subprocess.run(
            ["git", "-c", "commit.gpgsign=false", "-c", "core.hooksPath=" + os.devnull,
             "-c", "pull.rebase=false", "-c", "init.defaultBranch=dev", *args],
            cwd=repo, env=self.env, check=True, capture_output=True, text=True)
        return done.stdout.strip()

    def init(self, name="repo"):
        repo = self.dir / name
        repo.mkdir()
        self.git(repo, "init", "-q", "-b", "dev")
        return repo

    def put(self, repo, rel, text):
        p = Path(repo) / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(text, encoding="utf-8", newline="")

    def commit(self, repo, msg, date=None):
        self.clock += 1
        stamp = date or f"2026-10-{self.clock:02d}T12:00:00+0000"
        self.env["GIT_AUTHOR_DATE"] = self.env["GIT_COMMITTER_DATE"] = stamp
        self.git(repo, "add", "-A")
        self.git(repo, "commit", "-q", "-m", msg)
        return self.git(repo, "rev-parse", "HEAD")

    def run_script(self, repo, *args, env=None):
        return subprocess.run([sys.executable, str(SCRIPT), "--repo", str(repo), *args],
                              env=env or self.env, capture_output=True, text=True, timeout=60)

    def ok(self, repo, *args):
        res = self.run_script(repo, *args)
        self.assertEqual(res.returncode, 0, res.stderr)
        return res.stdout

    def make_clone(self):
        upstream = self.init("upstream")
        self.seed(upstream)
        local = self.dir / "local"
        self.git(self.dir, "clone", "-q", str(upstream), str(local))
        return upstream, local

    def push_upstream(self, upstream, name, text):
        self.put(upstream, f"changelog.d/{name}", text)
        self.commit(upstream, f"upstream {name}")

    def try_git(self, repo, *args):
        return subprocess.run(
            ["git", "-c", "commit.gpgsign=false", "-c", "core.hooksPath=" + os.devnull, *args],
            cwd=repo, env=self.env, capture_output=True, text=True)

    def short(self, repo, rev):
        return self.git(repo, "rev-parse", rev)

    def seed(self, repo):
        self.put(repo, "meson.build", MESON_OLD)
        self.put(repo, "vcpkg.json", vcpkg("a" * 40, ["zlib", {"name": "abseil", "version>=": "20240116.1"}]))
        self.put(repo, "sdk/include/yuzu/plugin.h", PLUGIN_H.format(4, 1))
        self.put(repo, "gateway/rebar.lock", LOCK % "2.18.0")
        self.put(repo, "CHANGELOG.md", CHANGELOG)
        self.put(repo, "changelog.d/README.md", "readme\n")
        self.put(repo, "changelog.d/1-old.added.md", "- **Already there.**\n")
        return self.commit(repo, "old")


class Versions(GitCase):
    def test_every_tracked_bump_and_the_new_and_removed_labels(self):
        repo = self.init()
        old = self.seed(repo)
        self.put(repo, "meson.build", MESON_NEW)
        self.put(repo, "vcpkg.json", vcpkg("b" * 40, [{"name": "abseil", "version>=": "20250127.0"}, "fmt"],
                                           overrides=[{"name": "zlib", "version": "1.3"}]))
        self.put(repo, "sdk/include/yuzu/plugin.h", PLUGIN_H.format(5, 2))
        self.put(repo, "gateway/rebar.lock", LOCK % "2.19.0")
        self.put(repo, "CHANGELOG.md", CHANGELOG.replace("## [1.2.0]", "## [1.3.0] - 2026-10-30\n\n- **x**\n\n## [1.2.0]"))
        self.commit(repo, "new")
        out = self.ok(repo, "--since", old)
        for line in (
            "project version (meson.build): 0.15.0 -> 0.16.0",
            "plugin ABI (YUZU_PLUGIN_ABI_VERSION): 4 -> 5",
            "plugin ABI (YUZU_PLUGIN_ABI_VERSION_MIN): 1 -> 2",
            "vcpkg builtin-baseline: aaaaaaaaaa -> bbbbbbbbbb",
            "vcpkg dependency abseil: >=20240116.1 -> >=20250127.0",
            "vcpkg dependency fmt: (unconstrained)  (new)",
            "vcpkg dependency zlib: (unconstrained)  (removed)",
            "vcpkg override zlib: 1.3  (new)",
            "gateway package cowboy: 2.18.0 -> 2.19.0",
            "latest released CHANGELOG section: 1.2.0 -> 1.3.0",
        ):
            self.assertIn(line, out)
        self.assertNotIn("Unreleased", out)

    def test_a_dependency_moved_into_a_feature_is_not_reported_removed(self):
        repo = self.init()
        old = self.seed(repo)
        self.put(repo, "vcpkg.json", vcpkg("a" * 40, [{"name": "abseil", "version>=": "20240116.1"}],
                                           features={"server": {"dependencies": ["zlib"]}}))
        self.commit(repo, "move zlib")
        out = self.ok(repo, "--since", old)
        self.assertNotIn("(removed)", out)
        self.assertIn("vcpkg dependency zlib: (unconstrained) -> (unconstrained) [feature server]", out)

    def test_unreadable_files_are_reported_not_diffed(self):
        repo = self.init()
        old = self.seed(repo)
        self.put(repo, "vcpkg.json", "{not json")
        self.put(repo, "gateway/rebar.lock", '{"1.3.0", [{<<"cowboy">>, {hex, <<"cowboy">>, <<"2.19.0">>}, 0}]}.\n')
        self.commit(repo, "break formats")
        out = self.ok(repo, "--since", old)
        self.assertIn("! vcpkg.json not compared: vcpkg.json is not valid JSON", out)
        self.assertIn("! gateway/rebar.lock not compared", out)
        self.assertNotIn("(removed)", out)

    def test_surface_notes(self):
        repo = self.init()
        old = self.seed(repo)
        for rel in ("proto/x.proto", "gateway/apps/a.erl", "sdk/include/yuzu/x.h", "deploy/docker/Dockerfile.x"):
            self.put(repo, rel, "x\n")
        self.put(repo, "vcpkg.json", vcpkg("c" * 40, ["zlib"]))
        self.commit(repo, "touch surfaces")
        out = self.ok(repo, "--since", old)
        for text in ("vcpkg manifest or triplets changed", "`proto/` changed (server, agent and gateway consume it)",
                     "`gateway/` changed: rebuild the Erlang gateway", "`sdk/` changed",
                     "deploy/compose files changed (1 file)", "with --wipe"):
            self.assertIn(text, out)

    def test_nothing_tracked_changed(self):
        repo = self.init()
        old = self.seed(repo)
        self.put(repo, "x.txt", "x\n")
        self.commit(repo, "unrelated")
        self.assertIn("none of the tracked versions changed", self.ok(repo, "--since", old))


class Fragments(GitCase):
    def test_grouping_order_truncation_and_counts(self):
        repo = self.init()
        old = self.seed(repo)
        long_added = "- **Long.** " + "x" * 300
        self.put(repo, "changelog.d/2-new.added.md", long_added + "\n- **Second bullet.**\n  continuation\n")
        self.put(repo, "changelog.d/3-sec.security.md", "- **Sec.** " + "y" * 300 + "\n")
        self.put(repo, "changelog.d/4-rm.removed.md", "- **Gone.**\n")
        self.put(repo, "changelog.d/5-fx.fixed.md", "- **Fixed.**\n")
        self.put(repo, "changelog.d/6-ch.changed.md", "- **Breaking, changed.**\n")
        self.put(repo, "changelog.d/README.md", "readme changed\n")
        self.put(repo, "changelog.d/7-bad.bogus.md", "- **Bad section.**\n")
        self.put(repo, "changelog.d/sub/8-nested.added.md", "- **Nested.**\n")
        self.commit(repo, "fragments")
        out = self.ok(repo, "--since", old)
        self.assertRegex(out, r"Changelog entries added \(6[,)]")
        positions = [out.index(s) for s in ("Security (1)", "Removed (1)", "Changed (1)", "Added (2)", "Fixed (1)")]
        self.assertEqual(positions, sorted(positions))
        long_line = next(line for line in out.splitlines() if line.startswith("- **Long.**"))
        self.assertEqual(len(long_line), 200)  # cut to 200 characters, marked
        self.assertTrue(long_line.endswith("..."))
        self.assertIn("- **Sec.** " + "y" * 300, out)  # security is never cut
        self.assertNotIn("continuation", out)  # first line only
        for absent in ("readme", "Bad section", "Nested", "Already there"):
            self.assertNotIn(absent, out)
        full = self.ok(repo, "--since", old, "--full")
        self.assertIn("continuation", full)
        self.assertIn("x" * 300, full)

    def test_a_breaking_entry_is_never_cut(self):
        repo = self.init()
        old = self.seed(repo)
        self.put(repo, "changelog.d/2-b.changed.md", "- **Breaking: do this.** " + "z" * 300 + "\n")
        self.commit(repo, "breaking")
        self.assertIn("z" * 300, self.ok(repo, "--since", old))

    def test_a_fragment_without_a_bullet_is_named(self):
        repo = self.init()
        old = self.seed(repo)
        self.put(repo, "changelog.d/2-prose.added.md", "no bullet here\n")
        self.put(repo, "changelog.d/3-ok.added.md", "- **Fine.**\n")
        self.commit(repo, "fragments")
        out = self.ok(repo, "--since", old)
        self.assertIn("! 1 fragment with no '- ' bullet, not summarised: 2-prose.added.md", out)
        self.assertRegex(out, r"Changelog entries added \(1[,)]")

    def test_rename_with_rewording_is_listed_once_with_the_final_text(self):
        repo = self.init()
        old = self.seed(repo)
        self.put(repo, "changelog.d/0000-x.fixed.md", "- **Old wording.**\n")
        self.commit(repo, "placeholder")
        self.git(repo, "mv", "changelog.d/0000-x.fixed.md", "changelog.d/77-x.changed.md")
        self.put(repo, "changelog.d/77-x.changed.md", "- **New wording.**\n")
        self.commit(repo, "rename, reword, move section")
        out = self.ok(repo, "--since", old)
        self.assertIn("New wording", out)
        self.assertNotIn("Old wording", out)
        self.assertEqual(out.count("wording"), 1)

    def test_a_reverted_fragment_is_not_listed(self):
        repo = self.init()
        old = self.seed(repo)
        self.put(repo, "changelog.d/2-r.added.md", "- **Reverted feature.**\n")
        self.commit(repo, "add")
        (repo / "changelog.d/2-r.added.md").unlink()
        self.commit(repo, "revert")
        self.assertNotIn("Reverted feature", self.ok(repo, "--since", old))

    def test_same_text_in_two_sections_is_listed_in_both(self):
        repo = self.init()
        old = self.seed(repo)
        self.put(repo, "changelog.d/2-a.added.md", "- **Same text.**\n")
        self.put(repo, "changelog.d/2-a.fixed.md", "- **Same text.**\n")
        self.commit(repo, "two sections")
        self.assertEqual(self.ok(repo, "--since", old).count("Same text"), 2)

    def test_a_fragment_added_through_a_merge_commit_is_found(self):
        repo = self.init()
        old = self.seed(repo)
        self.git(repo, "checkout", "-q", "-b", "feat")
        self.put(repo, "changelog.d/2-feat.added.md", "- **Via merge.**\n")
        self.commit(repo, "feature")
        self.git(repo, "checkout", "-q", "dev")
        self.put(repo, "x.txt", "x\n")
        self.commit(repo, "other work")
        self.git(repo, "merge", "-q", "--no-ff", "-m", "Merge feat", "feat")
        self.assertIn("Via merge", self.ok(repo, "--since", old))

    def test_a_promoted_fragment_is_listed_once_next_to_the_new_release(self):
        repo = self.init()
        old = self.seed(repo)
        self.put(repo, "changelog.d/2-rel.added.md", "- **Added then released.**\n")
        self.put(repo, "changelog.d/3-gone.fixed.md", "- **Withdrawn, never released.**\n")
        self.commit(repo, "add fragments")
        (repo / "changelog.d/3-gone.fixed.md").unlink()
        self.commit(repo, "withdraw one")
        subprocess.run(
            [sys.executable, str(ASSEMBLE), "promote", "1.3.0", "--date", "2026-10-30",
             "--changelog", str(repo / "CHANGELOG.md"), "--fragments-dir", str(repo / "changelog.d")],
            check=True, capture_output=True, text=True)
        self.put(repo, "meson.build", MESON_NEW)
        self.commit(repo, "release 1.3.0")
        self.assertFalse((repo / "changelog.d/2-rel.added.md").exists(), "promote should delete the fragment")
        out = self.ok(repo, "--since", old)
        self.assertEqual(out.count("Added then released"), 1)
        self.assertNotIn("Withdrawn", out)
        self.assertIn("latest released CHANGELOG section: 1.2.0 -> 1.3.0", out)

    def test_grammar_matches_assemble_changelog(self):
        assemble = load(ASSEMBLE, "assemble_changelog_for_parity")
        self.assertEqual(set(WN.SECTION_ORDER), set(assemble.SECTION_KEYS))
        names = ["1-a.added.md", "a.b-c_d.fixed.md", "A9.security.md", ".x.added.md", "a b.added.md",
                 "README.md", "x.bogus.md", "-a.added.md", "a.added.txt", "_a.added.md", "a.Added.md", "a.added.MD",
                 "a.added.md.md", "a..added.md", "a.added.md ", " a.added.md"]
        # Every ASCII character in the first, a middle and the last place of the stem, and in each section.
        for c in map(chr, range(32, 127)):
            names += [f"{c}a.added.md", f"a{c}b.fixed.md", f"ab{c}.changed.md", f"a.{c}added.md", f"a.added{c}md"]
        for name in names:
            self.assertEqual(bool(WN.FRAGMENT_RE.fullmatch(name)), bool(assemble.FRAGMENT_NAME_RE.fullmatch(name)), repr(name))


class Base(GitCase):
    def test_default_is_the_last_pull_and_survives_later_actions(self):
        upstream, local = self.make_clone()
        self.assertEqual(self.run_script(local).returncode, 2)  # a fresh clone has no pull yet
        self.push_upstream(upstream, "2-a.added.md", "- **First pulled.**\n")
        self.push_upstream(upstream, "3-b.fixed.md", "- **Second pulled.**\n")
        self.git(local, "pull", "-q")
        out = self.ok(local)
        self.assertIn("since your last pull: 2 commits", out)
        self.assertIn("First pulled", out)
        self.assertIn("Second pulled", out)
        # None of these writes a pull entry, so none may move the base or hide the pull.
        self.git(local, "checkout", "-q", "-b", "feat")
        self.put(local, "changelog.d/9-own.added.md", "- **Own work.**\n")
        self.commit(local, "own")
        self.git(local, "checkout", "-q", "dev")
        self.git(local, "merge", "-q", "--no-ff", "-m", "local merge", "feat")
        out = self.ok(local)
        self.assertIn("First pulled", out)
        self.assertIn("Second pulled", out)
        self.git(local, "reset", "-q", "--hard", "HEAD~1")
        self.git(local, "reset", "-q", "--hard", "origin/dev")
        self.assertIn("First pulled", self.ok(local))

    def test_a_second_pull_moves_the_base(self):
        upstream, local = self.make_clone()
        self.push_upstream(upstream, "2-a.added.md", "- **First pulled.**\n")
        self.git(local, "pull", "-q")
        self.push_upstream(upstream, "3-b.fixed.md", "- **Second pulled.**\n")
        self.git(local, "pull", "-q")
        out = self.ok(local)
        self.assertIn("Second pulled", out)
        self.assertNotIn("First pulled", out)

    def test_fetch_then_manual_merge_counts_as_a_pull(self):
        upstream, local = self.make_clone()
        self.push_upstream(upstream, "2-a.added.md", "- **Via fetch and merge.**\n")
        self.git(local, "fetch", "-q")
        self.git(local, "merge", "-q", "origin/dev")
        self.assertIn("Via fetch and merge", self.ok(local))

    def test_a_local_merge_of_a_branch_is_not_a_pull(self):
        upstream, local = self.make_clone()
        self.push_upstream(upstream, "2-a.added.md", "- **Pulled.**\n")
        self.git(local, "pull", "-q")
        self.git(local, "checkout", "-q", "-b", "feat")
        self.put(local, "changelog.d/9-own.added.md", "- **Own work.**\n")
        self.commit(local, "own")
        self.git(local, "checkout", "-q", "dev")
        self.git(local, "merge", "-q", "--no-ff", "-m", "local merge", "feat")
        out = self.ok(local)
        self.assertIn("since your last pull: 3 commits", out)  # the pulled commit, the local commit, the local merge
        self.assertIn("Pulled", out)

    def test_pull_with_rebase_starts_at_the_common_ancestor(self):
        upstream, local = self.make_clone()
        self.put(local, "x.txt", "local\n")
        self.commit(local, "local commit")
        self.push_upstream(upstream, "2-a.added.md", "- **Rebased pull.**\n")
        self.git(local, "pull", "-q", "--rebase")
        out = self.ok(local)
        self.assertIn("Rebased pull", out)
        self.assertIn("range starts at the common ancestor", out)

    def test_since_a_date_uses_commit_dates(self):
        repo = self.init()
        self.seed(repo)
        self.put(repo, "changelog.d/2-mid.added.md", "- **Before the cut.**\n")
        self.commit(repo, "mid", date="2026-03-10T12:00:00+0000")
        self.put(repo, "changelog.d/3-late.added.md", "- **After the cut.**\n")
        self.commit(repo, "late", date="2026-06-10T12:00:00+0000")
        out = self.ok(repo, "--since", "2026-04-01")
        self.assertIn("After the cut", out)
        self.assertNotIn("Before the cut", out)
        self.assertIn("Base ", out)

    def test_bad_since_values_are_refused(self):
        repo = self.init()
        old = self.seed(repo)
        self.put(repo, "x.txt", "x\n")
        self.commit(repo, "next")
        for value, text in (
            ("yesterdy", "is not a ref"), ("2 wekks ago", "is not a ref"), ("garbage", "is not a ref"),
            ("2000-01-01", "no commit is older"), ("HEAD", "nothing to compare"),
        ):
            res = self.run_script(repo, "--since", value)
            self.assertEqual(res.returncode, 2, value)
            self.assertIn(text, res.stderr, value)
        res = self.run_script(repo, "--since=--output=pwned")
        self.assertEqual(res.returncode, 2)
        self.assertEqual([p.name for p in repo.iterdir() if "pwned" in p.name], [])
        self.assertEqual(self.run_script(repo, "--since", old).returncode, 0)

    def test_a_commit_that_is_not_an_ancestor_is_refused(self):
        repo = self.init()
        self.seed(repo)
        self.git(repo, "checkout", "-q", "-b", "other")
        self.put(repo, "x.txt", "x\n")
        other = self.commit(repo, "other")
        self.git(repo, "checkout", "-q", "dev")
        self.put(repo, "y.txt", "y\n")
        self.commit(repo, "dev side")
        res = self.run_script(repo, "--since", other)
        self.assertEqual(res.returncode, 2)
        self.assertIn("not an ancestor", res.stderr)

    def test_shallow_clone_is_named(self):
        upstream = self.init("upstream")
        self.seed(upstream)
        self.put(upstream, "x.txt", "x\n")
        self.commit(upstream, "second")
        shallow = self.dir / "shallow"
        self.git(self.dir, "clone", "-q", "--depth", "1", "file://" + str(upstream), str(shallow))
        res = self.run_script(shallow, "--since", "2026-01-01")
        self.assertEqual(res.returncode, 2)
        self.assertIn("shallow clone", res.stderr)

    def test_environment_failures_are_clean_errors(self):
        plain = self.dir / "plain"
        plain.mkdir()
        res = self.run_script(plain)
        self.assertEqual(res.returncode, 2)
        self.assertNotIn("Traceback", res.stderr)
        res = self.run_script(plain, env={**self.env, "PATH": ""})
        self.assertEqual(res.returncode, 2)
        self.assertIn("git was not found on PATH", res.stderr)
        self.assertNotIn("Traceback", res.stderr)

    def test_a_failed_read_is_an_error_not_an_absence(self):
        repo = WN.Repo(self.dir)
        for stderr, absent in (("fatal: path 'x' does not exist in 'abc'", True),
                               ("fatal: path 'x' exists on disk, but not in 'abc'", True),
                               ("fatal: unable to read abc123 (promisor remote unreachable)", False)):
            repo._run = lambda *a, s=stderr: subprocess.CompletedProcess(a, 128, "", s)
            if absent:
                self.assertIsNone(repo.show("abc", "x"))
            else:
                with self.assertRaises(WN.GitError):
                    repo.show("abc", "x")


class DependencyBumps(GitCase):
    def test_images_are_listed_and_other_bumps_counted(self):
        repo = self.init()
        old = self.seed(repo)
        self.put(repo, "deploy/docker/Dockerfile.x", "FROM busybox\n")
        self.commit(repo, "build(deps): bump busybox from `fd7dc98` to `a46257e` in /deploy/docker")
        self.put(repo, "deploy/docker/requirements-meson.txt", "meson==1\n")
        self.commit(repo, "build(deps): bump meson in /deploy/docker")
        self.put(repo, ".github/workflows/ci.yml", "a\n")
        self.commit(repo, "build(deps): bump docker/login-action")
        self.put(repo, "requirements-ci.txt", "gcovr==8.8\n")
        self.commit(repo, "chore(deps-dev): bump gcovr from 8.7 to 8.8")
        self.put(repo, "server/unrelated.cpp", "x\n")
        self.commit(repo, "fix: a subject that merely mentions build(deps): bump")
        out = self.ok(repo, "--since", old)
        self.assertIn("1 Docker image, 3 other", out)
        self.assertIn("bump busybox", out)
        section = out.split("Dependency bumps")[1].split("\n\n")[0]
        self.assertNotIn("docker/login-action", section)
        self.assertIn("+ 3 other bumps", section)
        self.assertNotIn("merely mentions", section)
        full = self.ok(repo, "--since", old, "--full")
        for text in ("docker/login-action", "bump gcovr", "bump meson in /deploy/docker"):
            self.assertIn(text, full)

    def test_no_section_when_there_are_none(self):
        repo = self.init()
        old = self.seed(repo)
        self.put(repo, "x.txt", "x\n")
        self.commit(repo, "feat: ordinary change")
        self.assertNotIn("Dependency bumps", self.ok(repo, "--since", old))


class Output(GitCase):
    def test_terminal_control_characters_are_replaced(self):
        repo = self.init()
        old = self.seed(repo)
        evil = "\x1b]0;PWNED\x07\x1b[2J\x9b31m"
        self.put(repo, "changelog.d/2-evil.added.md", f"- **Entry{evil}.**\r\n")
        self.put(repo, "deploy/docker/Dockerfile.x", "FROM x\n")
        self.commit(repo, f"build(deps): bump {evil}x")
        out = self.ok(repo, "--since", old)
        for ch in ("\x1b", "\x07", "\x9b", "\r"):
            self.assertNotIn(ch, out)
        self.assertIn("Entry", out)
        self.assertIn("bump ?]0;PWNED", out)

    def test_clean_keeps_newline_and_tab(self):
        self.assertEqual(WN.clean("a\tb\nc\x1bd"), "a\tb\nc?d")

    def test_date_grammar(self):
        for good in ("2026-11-01", "2026-11-01 12:30", "2026-11-01T12:30:15", "yesterday", "2 weeks ago", "1 day ago"):
            self.assertTrue(WN.DATE_RE.match(good), good)
        for bad in ("yesterdy", "2 wekks ago", "last tuesday", "--output=x", "", "2 weeks"):
            self.assertFalse(WN.DATE_RE.match(bad), bad)


def within(seconds, fn, *args):
    """fn(*args) run on a daemon thread; (finished, result). A regression that loops forever fails
    one test instead of stalling the whole suite until the CI timeout."""
    done: list[object] = []
    worker = threading.Thread(target=lambda: done.append(fn(*args)), daemon=True)
    worker.start()
    worker.join(seconds)
    return (not worker.is_alive()), (done[0] if done else None)


class FakeRepo(WN.Repo):
    """A Repo whose git answers are canned: for the reflog parser and the extractors."""

    def __init__(self, runs=None, files=None):
        super().__init__(Path("."))
        self.runs = runs or {}
        self.files = files or {}

    def _run(self, *args, **kw):
        return subprocess.CompletedProcess(args, 0, self.runs.get(args[0], ""), "")

    def show(self, ref, path):
        return self.files.get((ref, path))


class BaseSelection(GitCase):
    def base_token(self, out):
        return next(line for line in out.splitlines() if line.startswith("Base ")).split()[1]

    def test_a_pull_on_another_branch_does_not_replace_this_branchs_pull(self):
        upstream, local = self.make_clone()
        self.push_upstream(upstream, "2-a.added.md", "- **Pull A.**\n")
        self.git(local, "pull", "-q")
        self.git(local, "checkout", "-q", "-b", "feat")
        self.push_upstream(upstream, "3-b.added.md", "- **Pull B on feat.**\n")
        self.git(local, "pull", "-q", "origin", "dev")
        self.git(local, "checkout", "-q", "dev")
        self.put(local, "x.txt", "local\n")
        self.commit(local, "local commit on dev")
        out = self.ok(local)
        self.assertIn("Pull A", out)
        self.assertNotIn("Pull B", out)  # feat's pull is not dev's

    def test_merging_another_remote_branch_is_not_a_pull_of_this_one(self):
        upstream, local = self.make_clone()
        self.push_upstream(upstream, "2-a.added.md", "- **Pull A.**\n")
        self.git(local, "pull", "-q")
        self.git(upstream, "checkout", "-q", "-b", "other")
        self.push_upstream(upstream, "3-o.added.md", "- **Other branch.**\n")
        self.git(upstream, "checkout", "-q", "dev")
        self.git(local, "fetch", "-q")
        self.git(local, "merge", "-q", "--no-edit", "origin/other")
        out = self.ok(local)
        self.assertIn("Pull A", out)
        self.assertIn("Other branch", out)

    def test_a_detached_head_is_refused(self):
        upstream, local = self.make_clone()
        self.git(local, "checkout", "-q", "--detach")
        res = self.run_script(local)
        self.assertEqual(res.returncode, 2)
        self.assertIn("detached", res.stderr)

    def test_two_pull_rebases_in_a_row_start_at_the_second(self):
        upstream, local = self.make_clone()
        self.put(local, "x.txt", "l1\n")
        self.commit(local, "local 1")
        self.push_upstream(upstream, "2-a.added.md", "- **Pull A.**\n")
        self.git(local, "pull", "-q", "--rebase")
        # No commit between the two pulls: their reflog step entries are adjacent.
        self.push_upstream(upstream, "3-b.added.md", "- **Pull B.**\n")
        self.git(local, "pull", "-q", "--rebase")
        out = self.ok(local)
        self.assertIn("Pull B", out)
        self.assertNotIn("Pull A", out)

    def test_rebase_pull_reports_its_base_and_counts(self):
        upstream, local = self.make_clone()
        before = self.short(upstream, "HEAD")
        self.put(local, "x.txt", "local\n")
        self.commit(local, "local commit")
        self.push_upstream(upstream, "2-a.added.md", "- **Rebased pull.**\n")
        self.git(local, "pull", "-q", "--rebase")
        out = self.ok(local)
        self.assertIn("2 commits", out)  # the pulled one and the rebased local one
        self.assertTrue(before.startswith(self.base_token(out)), out)

    def test_pull_rebase_with_a_conflict_then_continue(self):
        upstream, local = self.make_clone()
        self.put(upstream, "x.txt", "base\n")
        self.commit(upstream, "shared file")
        self.git(local, "pull", "-q")
        self.put(local, "x.txt", "local\n")
        self.commit(local, "local edit")
        self.put(upstream, "x.txt", "upstream\n")
        self.put(upstream, "changelog.d/2-a.added.md", "- **Pulled through a conflict.**\n")
        self.commit(upstream, "upstream edit")
        self.assertNotEqual(self.try_git(local, "pull", "--rebase").returncode, 0)
        self.put(local, "x.txt", "resolved\n")
        self.git(local, "add", "x.txt")
        self.env["GIT_EDITOR"] = "true"
        self.git(local, "rebase", "--continue")
        self.assertIn("Pulled through a conflict", self.ok(local))

    def test_no_pull_message_names_the_remedy(self):
        upstream, local = self.make_clone()
        res = self.run_script(local)
        self.assertEqual(res.returncode, 2)
        self.assertIn("no pull is recorded for this branch", res.stderr)
        self.assertIn('--since "2 weeks ago"', res.stderr)

    def test_the_forged_reflog_line_is_not_a_record(self):
        # A replayed commit subject can carry \v, which str.splitlines() treats as a line break.
        a, b, c, d = ("1" * 40, "2" * 40, "3" * 40, "4" * 40)
        reflog = f"{a}\tcommit: mine\x0b{c}\tpull: forged\n{b}\tpull: Fast-forward\n{d}\tclone: from x\n"
        repo = FakeRepo(runs={"symbolic-ref": "refs/heads/dev\n", "rev-parse": "origin/dev\n", "reflog": reflog})
        self.assertEqual(WN.last_pull_base(repo)[0], d)
        junk = f"not-a-sha\tpull: x\n{b}\tpull: Fast-forward\n{d}\tclone: from x\n"
        repo.runs["reflog"] = junk
        self.assertEqual(WN.last_pull_base(repo)[0], d)

    def test_merge_entries_match_only_this_branchs_upstream(self):
        a, b, c = ("1" * 40, "2" * 40, "3" * 40)
        repo = FakeRepo(runs={"symbolic-ref": "refs/heads/dev\n", "rev-parse": "origin/dev\n",
                              "reflog": f"{a}\tmerge origin/other: Fast-forward\n{b}\tmerge origin/dev: Fast-forward\n{c}\tclone: x\n"})
        self.assertEqual(WN.last_pull_base(repo)[0], c)
        repo.runs["rev-parse"] = ""  # no upstream configured: a bare merge is not a pull
        with self.assertRaises(WN.GitError):
            WN.last_pull_base(repo)


class UtcClock:
    """Run a test with the process clock in UTC, so date arithmetic does not depend on the machine."""

    def setUp(self):
        super().setUp()
        import time
        self._tz = os.environ.get("TZ")
        os.environ["TZ"] = "UTC"
        if hasattr(time, "tzset"):
            time.tzset()

    def tearDown(self):
        import time
        if self._tz is None:
            os.environ.pop("TZ", None)
        else:
            os.environ["TZ"] = self._tz
        if hasattr(time, "tzset"):
            time.tzset()
        super().tearDown()


class DateValidation(UtcClock, GitCase):
    def test_a_bare_date_means_the_start_of_that_day(self):
        self.assertEqual(WN.date_cutoff("2026-11-01"), "2026-11-01 00:00:00")
        self.assertEqual(WN.date_cutoff("2026-11-01 12:30"), "2026-11-01 12:30")
        self.assertEqual(WN.date_cutoff("2026-11-01T12:30:15"), "2026-11-01T12:30:15")
        now = datetime(2026, 11, 13, 16, 0, 0)
        self.assertEqual(WN.date_cutoff("yesterday", now), "2026-11-12 16:00:00")
        self.assertEqual(WN.date_cutoff("3 days ago", now), "2026-11-10 16:00:00")
        self.assertEqual(WN.date_cutoff("2 hours ago", now), "2026-11-13 14:00:00")
        self.assertEqual(WN.date_cutoff("90 minutes ago", now), "2026-11-13 14:30:00")
        self.assertEqual(WN.date_cutoff("30 seconds ago", now), "2026-11-13 15:59:30")
        self.assertEqual(WN.date_cutoff("2 weeks ago", now), "2026-10-30 16:00:00")
        self.assertEqual(WN.date_cutoff("1 month ago", datetime(2026, 3, 31, 9, 0, 0)), "2026-02-28 09:00:00")
        self.assertEqual(WN.date_cutoff("13 months ago", now), "2025-10-13 16:00:00")
        self.assertEqual(WN.date_cutoff("1 year ago", datetime(2024, 2, 29, 9, 0, 0)), "2023-02-28 09:00:00")
        for far in ("9999 years ago", "1000 years ago", "9999 months ago", "57 years ago"):
            with self.assertRaises(WN.GitError, msg=far):
                WN.date_cutoff(far, now)

    def test_a_bare_date_does_not_depend_on_the_time_of_day(self):
        repo = self.init()
        self.seed(repo)
        self.put(repo, "x.txt", "x\n")
        self.commit(repo, "before", date="2026-10-31T12:00:00+0000")
        self.put(repo, "changelog.d/2-early.added.md", "- **Early on the day.**\n")
        self.commit(repo, "early", date="2026-11-01T01:00:00+0000")
        self.put(repo, "changelog.d/3-late.added.md", "- **Late on the day.**\n")
        self.commit(repo, "late", date="2026-11-01T23:00:00+0000")
        out = self.ok(repo, "--since", "2026-11-01")
        self.assertIn("Early on the day", out)
        self.assertIn("Late on the day", out)

    def test_calendar_impossible_and_junk_dates_are_refused(self):
        for bad in ("2026-02-30", "2026-00-10", "2026-11-00", "2026-04-31", "2026-11-01 25:99", "2026-13-45",
                    "2026-11-01 junk", "junk 2026-11-01", "2026-11-01\n", "yesterday\n", "99999 years ago", "2 wekks ago",
                    "\u0665 days ago", "2 Days ago", "2  days ago", "-1 days ago"):
            with self.assertRaises(WN.GitError, msg=repr(bad)):
                WN.date_cutoff(bad)

    def test_cli_refuses_an_impossible_date(self):
        repo = self.init()
        self.seed(repo)
        res = self.run_script(repo, "--since", "2026-02-30")
        self.assertEqual(res.returncode, 2)
        self.assertIn("not a real calendar date", res.stderr)


class FragmentSelection(GitCase):
    def test_a_pending_fragment_is_not_listed_when_a_release_lands_in_the_range(self):
        repo = self.init()
        self.seed(repo)
        self.git(repo, "checkout", "-q", "-b", "side")
        self.put(repo, "changelog.d/3-g.added.md", "- **Added on the side branch.**\n")
        self.commit(repo, "side")
        self.git(repo, "checkout", "-q", "dev")
        self.put(repo, "changelog.d/2-f.added.md", "- **Already pulled, pending.**\n")
        old = self.commit(repo, "pending fragment, already pulled")
        self.git(repo, "merge", "-q", "--no-ff", "-m", "Merge side", "side")
        subprocess.run(
            [sys.executable, str(ASSEMBLE), "promote", "1.3.0", "--date", "2026-10-30",
             "--changelog", str(repo / "CHANGELOG.md"), "--fragments-dir", str(repo / "changelog.d")],
            check=True, capture_output=True, text=True)
        self.commit(repo, "release 1.3.0")
        out = self.ok(repo, "--since", old)
        self.assertEqual(out.count("Added on the side branch"), 1)
        self.assertNotIn("Already pulled, pending", out)

    def test_a_withdrawn_fragment_is_not_matched_by_older_changelog_text(self):
        repo = self.init()
        self.seed(repo)
        self.put(repo, "CHANGELOG.md", CHANGELOG.replace("- **Older.**", "- **Fix.** an older, unrelated entry"))
        old = self.commit(repo, "changelog mentions Fix.")
        self.put(repo, "changelog.d/2-fix.fixed.md", "- **Fix.**\n")
        self.commit(repo, "add")
        (repo / "changelog.d/2-fix.fixed.md").unlink()
        self.commit(repo, "withdraw")
        out = self.ok(repo, "--since", old)
        self.assertNotIn("Fixed (", out)
        self.assertIn("No changelog fragments were added", out)

    def test_a_fragment_renamed_from_a_path_that_existed_is_not_new(self):
        repo = self.init()
        old = self.seed(repo)
        self.git(repo, "mv", "changelog.d/1-old.added.md", "changelog.d/2-renamed.changed.md")
        self.commit(repo, "rename an already-pulled fragment")
        self.assertNotIn("Already there", self.ok(repo, "--since", old))

    def test_an_edited_existing_fragment_is_not_listed(self):
        repo = self.init()
        old = self.seed(repo)
        self.put(repo, "changelog.d/1-old.added.md", "- **Already there, edited.**\n")
        self.commit(repo, "edit")
        self.assertNotIn("edited", self.ok(repo, "--since", old))

    def test_identical_bullets_in_one_section_count_once(self):
        repo = self.init()
        old = self.seed(repo)
        self.put(repo, "changelog.d/2-a.added.md", "- **Twice.**\n")
        self.put(repo, "changelog.d/3-b.added.md", "- **Twice.**\n")
        self.commit(repo, "same text")
        out = self.ok(repo, "--since", old)
        self.assertEqual(out.count("**Twice.**"), 1)
        self.assertRegex(out, r"Changelog entries added \(1[,)]")

    def test_removed_deprecated_and_breaking_entries_are_shown_whole(self):
        repo = self.init()
        old = self.seed(repo)
        self.put(repo, "changelog.d/2-r.removed.md", "- **Removed.** " + "r" * 300 + "\n  second line of removal\n")
        self.put(repo, "changelog.d/3-d.deprecated.md", "- **Deprecated.** " + "d" * 300 + "\n")
        self.put(repo, "changelog.d/4-b.changed.md", "- **Breaking: change.** first\n  migration step\n")
        self.put(repo, "changelog.d/5-s.security.md", "- **Sec.**\n  continuation of the security entry\n")
        self.commit(repo, "entries")
        out = self.ok(repo, "--since", old)
        for text in ("r" * 300, "second line of removal", "d" * 300, "migration step", "continuation of the security entry"):
            self.assertIn(text, out)

    def test_the_brief_cut_is_exactly_at_the_limit(self):
        repo = self.init()
        old = self.seed(repo)
        at = "- **A.** " + "a" * (200 - len("- **A.** "))
        over = "- **B.** " + "b" * (201 - len("- **B.** "))
        self.put(repo, "changelog.d/2-at.added.md", at + "\n")
        self.put(repo, "changelog.d/3-over.added.md", over + "\n")
        self.commit(repo, "two lengths")
        out = self.ok(repo, "--since", old)
        self.assertIn(at + "\n", out + "\n")
        self.assertNotIn(at + "...", out)
        line = next(line for line in out.splitlines() if line.startswith("- **B.**"))
        self.assertEqual((len(line), line.endswith("...")), (200, True))

    def test_vertical_tab_does_not_split_a_bullet_or_a_subject(self):
        repo = self.init()
        old = self.seed(repo)
        self.put(repo, "changelog.d/2-v.added.md", "- **First half.**\x0b- **looks like a second bullet**\n")
        self.put(repo, "server/q.txt", "x\n")
        self.commit(repo, "build(deps): bump x\x0bdeploy/docker/Dockerfile")
        out = self.ok(repo, "--since", old)
        self.assertRegex(out, r"Changelog entries added \(1[,)]")
        self.assertIn("0 Docker images, 1 other", out)


class Extractors(GitCase):
    def test_vcpkg_shapes(self):
        def read(text):
            return WN.vcpkg(FakeRepo(files={("r", "vcpkg.json"): text}), "r")
        for bad in ('{"dependencies": 3}', '{"dependencies": [3]}', '{"dependencies": [{"x": 1}]}',
                    '{"features": [1]}', '{"overrides": [3]}', "[]", "{bad"):
            with self.assertRaises(ValueError, msg=bad):
                read(bad)
        out = read(json.dumps({
            "builtin-baseline": "a" * 40, "dependencies": ["zlib", {"name": "abseil", "version>=": "1"}],
            "features": {"server": {"dependencies": ["zlib"]}, "agent": {"description": "no deps key"}},
            "overrides": [{"name": "a", "version-semver": "1.2.3"}, {"name": "b", "version-date": "2026-01-01"}],
        }))
        self.assertEqual(out["vcpkg dependency zlib"], "(unconstrained), (unconstrained) [feature server]")
        self.assertEqual(out["vcpkg override a"], "1.2.3")
        self.assertEqual(out["vcpkg override b"], "2026-01-01")
        self.assertEqual(out["vcpkg builtin-baseline"], "a" * 10)
        self.assertNotIn("vcpkg dependency agent", out)

    def test_rebar_lock_absent_at_one_end_reads_as_new(self):
        repo = FakeRepo(files={("n", "gateway/rebar.lock"): LOCK % "2.19.0"})
        lines = WN.version_changes(repo, "o", "n")
        self.assertIn("  + gateway package cowboy: 2.19.0  (new)", lines)

    def test_a_pathologically_nested_manifest_is_reported_not_a_traceback(self):
        repo = FakeRepo(files={("n", "vcpkg.json"): "[" * 100000, ("o", "vcpkg.json"): "{}"})
        lines = WN.version_changes(repo, "o", "n")
        self.assertIn("  ! vcpkg.json not compared: nested too deeply", lines)

    def test_image_file_variants(self):
        for path, image in (("deploy/docker/Dockerfile", True), ("deploy/docker/Dockerfile.runner", True),
                            ("deploy/docker/x.Dockerfile", True), ("deploy/docker/docker-compose.yml", True),
                            ("deploy/docker/requirements.txt", False), ("other/Dockerfile", False)):
            self.assertEqual(WN._is_image_file(path), image, path)

    def test_a_commit_touching_an_image_and_another_file_is_an_image_bump(self):
        repo = self.init()
        old = self.seed(repo)
        self.put(repo, "deploy/docker/Dockerfile.y", "FROM y\n")
        self.put(repo, "server/z.txt", "z\n")
        self.commit(repo, "build(deps): bump y")
        self.assertIn("1 Docker image, 0 other", self.ok(repo, "--since", old))

    def test_a_deps_looking_line_in_a_message_body_is_not_a_bump(self):
        repo = self.init()
        old = self.seed(repo)
        self.put(repo, "x.txt", "x\n")
        self.git(repo, "add", "-A")
        self.git(repo, "commit", "-q", "-m", "feat: ordinary", "-m", "build(deps): not a subject")
        self.assertNotIn("Dependency bumps", self.ok(repo, "--since", old))


class Surfaces(GitCase):
    def test_a_file_moved_out_of_a_watched_directory_is_still_noted(self):
        repo = self.init()
        self.seed(repo)
        self.put(repo, "proto/a.proto", "syntax = \"proto3\";\n")
        old = self.commit(repo, "add proto")
        (repo / "other").mkdir()
        self.git(repo, "mv", "proto/a.proto", "other/a.proto")
        self.commit(repo, "move it out")
        self.assertIn("`proto/` changed", self.ok(repo, "--since", old))

    def test_header_lines_and_root_files(self):
        repo = self.init()
        old = self.seed(repo)
        self.put(repo, "x.txt", "x\n")
        head = self.commit(repo, "the head subject")
        out = self.ok(repo, "--since", old).splitlines()
        self.assertTrue(out[0].startswith("Changes since "), out[0])
        self.assertIn("1 commit, 1 file ((root) 1)", out[0])
        self.assertTrue(out[1].startswith("Base ") and out[1].endswith(" old"), out[1])
        self.assertTrue(out[2].startswith("Head ") and out[2].endswith(" the head subject"), out[2])
        self.assertTrue(head.startswith(out[2].split()[1]))

    def test_an_annotated_tag_and_a_subdirectory(self):
        repo = self.init()
        old = self.seed(repo)
        self.git(repo, "tag", "-a", "v1", "-m", "release", old)
        self.put(repo, "sub/x.txt", "x\n")
        self.commit(repo, "next")
        self.assertIn("Changes since v1", self.ok(repo, "--since", "v1"))
        self.assertIn("Changes since v1", self.ok(repo / "sub", "--since", "v1"))

    def test_no_fragments_line_names_the_real_range(self):
        repo = self.init()
        old = self.seed(repo)
        self.put(repo, "x.txt", "x\n")
        self.commit(repo, "no fragment")
        out = self.ok(repo, "--since", old)
        self.assertIn(f"`git log --first-parent --oneline {old[:10]}..HEAD`", out)


class Hostile(GitCase):
    def test_clean_table(self):
        for ch in ("\x00", "\x07", "\x0d", "\x1b", "\x7f", "\x9b", "\u202e", "\u200b", "\u2028", "\ufeff"):
            self.assertEqual(WN.clean("a" + ch + "b"), "a?b", repr(ch))
        self.assertEqual(WN.clean("a\tb\nc"), "a\tb\nc")
        self.assertEqual(WN.clean("plain é text"), "plain é text")

    def test_a_carriage_return_in_a_fragment_and_a_subject_reaches_clean(self):
        repo = self.init()
        old = self.seed(repo)
        self.put(repo, "changelog.d/2-cr.added.md", "- **Entry\x08EVIL.**\n")
        self.put(repo, "deploy/docker/Dockerfile.x", "FROM x\n")
        self.commit(repo, "build(deps): bump a\rb")
        out = self.ok(repo, "--since", old)
        self.assertNotIn("\r", out)
        self.assertIn("Entry?EVIL", out)
        self.assertIn("bump a?b", out)

    def test_control_characters_in_an_argument_do_not_reach_stderr(self):
        repo = self.init()
        self.seed(repo)
        res = self.run_script(repo, "--since", "\x1b[2Jzz")
        self.assertEqual(res.returncode, 2)
        self.assertNotIn("\x1b", res.stderr)

    def test_non_ascii_text_survives_a_narrow_output_encoding(self):
        repo = self.init()
        old = self.seed(repo)
        self.put(repo, "changelog.d/2-u.added.md", "- **Caf\u00e9 \u2192 th\u00e9.**\n")
        self.commit(repo, "unicode")
        res = self.run_script(repo, "--since", old, env={**self.env, "PYTHONIOENCODING": "ascii"})
        self.assertEqual(res.returncode, 0, res.stderr)
        self.assertNotIn("Traceback", res.stderr)
        self.assertIn("Caf? ? th?", res.stdout)

    def test_bad_repo_arguments_are_clean_errors(self):
        for target in ("/nonexistent/dir", "/etc/passwd"):
            res = subprocess.run([sys.executable, str(SCRIPT), "--repo", target], env=self.env,
                                 capture_output=True, text=True)
            self.assertEqual(res.returncode, 2, target)
            self.assertNotIn("Traceback", res.stderr)
        res = subprocess.run([sys.executable, str(SCRIPT), "--repo", "/nonexistent/dir"], env=self.env,
                             capture_output=True, text=True)
        self.assertNotIn("not found on PATH", res.stderr)


def promote(repo, version="1.3.0"):
    subprocess.run(
        [sys.executable, str(ASSEMBLE), "promote", version, "--date", "2026-10-30",
         "--changelog", str(repo / "CHANGELOG.md"), "--fragments-dir", str(repo / "changelog.d")],
        check=True, capture_output=True, text=True)


class PullHelpers(GitCase):
    def reflog_repo(self, *lines, remote="origin", merge="refs/heads/dev", upstream="origin/dev", branch="dev"):
        shas = ["%040x" % (i + 1) for i in range(len(lines))]
        reflog = "".join(f"{sha}\t{subject}\n" for sha, subject in zip(shas, lines))

        class R(FakeRepo):
            def _run(self, *args, **kw):
                out = {"symbolic-ref": f"refs/heads/{branch}\n", "rev-parse": upstream + "\n", "reflog": reflog}.get(args[0], "")
                if args[0] == "config":
                    out = {f"branch.{branch}.remote": remote, f"branch.{branch}.merge": merge}.get(args[1], "") + "\n"
                return subprocess.CompletedProcess(args, 0, out, "")
        return R(), shas

    def base_for(self, subject, **kw):
        repo, shas = self.reflog_repo(subject, "clone: from x", **kw)
        try:
            return WN.last_pull_base(repo)[0] == shas[1]
        except WN.GitError:
            return None


class PullArguments(PullHelpers):
    def test_which_pull_subjects_count(self):
        counts = ["pull: Fast-forward", "pull -q: Fast-forward", "pull --rebase (finish): returning to refs/heads/dev",
                  "pull -q origin dev: Fast-forward", "pull origin dev: Merge made", "pull --ff-only origin: Fast-forward",
                  "pull -q --rebase origin dev (finish): x", "pull origin refs/heads/dev: Fast-forward",
                  "merge origin/dev: Fast-forward"]
        refuses = ["pull -q origin fix/foo: Fast-forward", "pull fork dev: Fast-forward", "pull origin dev extra: x",
                   "pull --rebase origin fix/foo (finish): x", "merge origin/dev-hotfix: Fast-forward",
                   "merge origin/dev2: Fast-forward", "merge origin/devtools: Fast-forward", "merge origin/dev~1: x",
                   "merge origin/other: x", "merge feature: x", "pullover: x", "commit (merge): resolve"]
        for subject in counts:
            self.assertTrue(self.base_for(subject), subject)
        for subject in refuses:
            self.assertIsNone(self.base_for(subject), subject)

    def test_without_an_upstream_a_pull_must_name_the_branch_itself(self):
        kw = dict(remote="", merge="", upstream="")
        self.assertTrue(self.base_for("pull origin dev: Fast-forward", **kw))
        self.assertTrue(self.base_for("pull: Fast-forward", **kw))
        self.assertIsNone(self.base_for("pull origin fix/foo: Fast-forward", **kw))
        self.assertIsNone(self.base_for("merge origin/dev: Fast-forward", **kw))  # no upstream: not a pull

    def test_a_pull_of_another_branch_does_not_replace_the_pull_of_this_one(self):
        upstream, local = self.make_clone()
        self.push_upstream(upstream, "2-a.added.md", "- **Pull A.**\n")
        self.git(local, "pull", "-q")
        self.git(upstream, "checkout", "-q", "-b", "fix/foo")
        self.push_upstream(upstream, "3-foo.added.md", "- **Foo branch.**\n")
        self.git(upstream, "checkout", "-q", "dev")
        self.git(local, "pull", "-q", "origin", "fix/foo")
        out = self.ok(local)
        self.assertIn("Pull A", out)
        self.assertIn("Foo branch", out)

    def test_merging_a_branch_that_extends_the_upstream_name_is_not_a_pull(self):
        upstream, local = self.make_clone()
        self.push_upstream(upstream, "2-a.added.md", "- **Pull A.**\n")
        self.git(local, "pull", "-q")
        self.git(upstream, "checkout", "-q", "-b", "dev2")
        self.push_upstream(upstream, "3-d.added.md", "- **On dev2.**\n")
        self.git(upstream, "checkout", "-q", "dev")
        self.git(local, "fetch", "-q")
        self.git(local, "merge", "-q", "--no-edit", "origin/dev2")
        out = self.ok(local)
        self.assertIn("Pull A", out)
        self.assertIn("On dev2", out)

    def test_the_default_run_says_which_reflog_entry_it_used(self):
        upstream, local = self.make_clone()
        self.push_upstream(upstream, "2-a.added.md", "- **Pull A.**\n")
        self.git(local, "pull", "-q")
        self.assertIn("Via  reflog entry: pull -q: Fast-forward", self.ok(local))
        self.assertNotIn("Via ", self.ok(local, "--since", "HEAD~1"))

    def test_resetting_below_the_pull_is_an_error_not_an_empty_report(self):
        upstream, local = self.make_clone()
        self.push_upstream(upstream, "2-a.added.md", "- **Pull A.**\n")
        self.git(local, "pull", "-q")
        self.git(local, "reset", "-q", "--hard", "HEAD~1")
        res = self.run_script(local)
        self.assertEqual(res.returncode, 2)
        self.assertIn("nothing to compare", res.stderr)

    def test_a_pull_stopped_by_a_conflict_starts_at_the_pull_before_it(self):
        upstream, local = self.make_clone()
        self.push_upstream(upstream, "2-first.added.md", "- **Clean pull.**\n")
        self.git(local, "pull", "-q")
        self.put(upstream, "x.txt", "base\n")
        self.commit(upstream, "shared")
        self.git(local, "pull", "-q")
        self.put(local, "x.txt", "local\n")
        self.commit(local, "local edit")
        self.put(upstream, "x.txt", "upstream\n")
        self.put(upstream, "changelog.d/3-c.added.md", "- **Through the conflict.**\n")
        self.commit(upstream, "upstream edit")
        self.assertNotEqual(self.try_git(local, "pull", "--rebase").returncode, 0)
        self.put(local, "x.txt", "resolved\n")
        self.git(local, "add", "x.txt")
        self.env["GIT_EDITOR"] = "true"
        self.git(local, "rebase", "--continue")
        out = self.ok(local)
        self.assertIn("Through the conflict", out)  # never lost
        # The pull that stopped on a conflict is not recognised, so the base is the pull before it.
        self.assertIn("Via  reflog entry: pull -q: Fast-forward", out)
        self.assertIn("3 commits", out)  # upstream "shared" is in the range: it started earlier, not later


class PromotedFragments(GitCase):
    def promoted(self, name, body, **kw):
        repo = self.init()
        self.seed(repo)
        old = self.git(repo, "rev-parse", "HEAD")
        self.put(repo, f"changelog.d/{name}", body)
        self.commit(repo, "add")
        promote(repo)
        self.commit(repo, "release")
        return repo, old

    def test_a_pinned_exact_line_must_be_added_by_the_range(self):
        repo = self.init()
        self.seed(repo)
        self.put(repo, "CHANGELOG.md", CHANGELOG.replace("- **Older.**", "- **Fix.**"))
        old = self.commit(repo, "changelog already has the exact line")
        self.put(repo, "changelog.d/2-fix.fixed.md", "- **Fix.**\n")
        self.commit(repo, "add")
        (repo / "changelog.d/2-fix.fixed.md").unlink()
        self.commit(repo, "withdraw")
        self.assertIn("No changelog fragments were added", self.ok(repo, "--since", old))

    def test_a_multi_line_security_entry_is_shown_whole_after_promotion(self):
        repo, old = self.promoted("2-s.security.md", "- **Sec fix.** first line\n  second line of the step\n")
        out = self.ok(repo, "--since", old)
        self.assertIn("second line of the step", out)
        self.assertEqual(out.count("Sec fix"), 1)

    def test_an_indented_crlf_and_lone_cr_fragments_survive_promotion(self):
        repo = self.init()
        self.seed(repo)
        old = self.git(repo, "rev-parse", "HEAD")
        self.put(repo, "changelog.d/2-i.added.md", "  - **Indented first line.**\n")
        self.put(repo, "changelog.d/3-c.fixed.md", "- **Crlf entry.**\r\n  continued\r\n")
        self.put(repo, "changelog.d/4-r.changed.md", "- **Cr one.**\r- **Cr two.**\r")
        self.commit(repo, "odd line endings")
        pending = self.ok(repo, "--since", old)
        promote(repo)
        self.commit(repo, "release")
        out = self.ok(repo, "--since", old)
        for text in ("Indented first line", "Crlf entry", "Cr one", "Cr two"):
            self.assertIn(text, pending, text)
            self.assertIn(text, out, text)
        self.assertNotIn("\r", out)
        self.assertNotIn("?", out.split("Changelog entries added")[1])  # no stray control marks
        self.assertRegex(out, r"Changelog entries added \(4[,)]")

    def test_promotion_listing_survives_hostile_git_config(self):
        repo, old = self.promoted("2-p.added.md", "- **Promoted under config.**\n")
        cfg = self.dir / "hostile.gitconfig"
        cfg.write_text("[color]\n\tui = always\n[diff]\n\texternal = /bin/false\n\trenames = false\n"
                       "[log]\n\tshowSignature = true\n[core]\n\tpager = false\n", encoding="utf-8")
        res = self.run_script(repo, "--since", old, env={**self.env, "GIT_CONFIG_GLOBAL": str(cfg)})
        self.assertEqual(res.returncode, 0, res.stderr)
        self.assertIn("Promoted under config", res.stdout)

    def test_works_from_a_subdirectory(self):
        repo, old = self.promoted("2-p.added.md", "- **Promoted, from a subdirectory.**\n")
        (repo / "sub").mkdir()
        self.assertIn("Promoted, from a subdirectory", self.ok(repo / "sub", "--since", old))

    def test_a_fragment_renamed_in_the_range_and_then_promoted_is_not_new(self):
        repo = self.init()
        self.seed(repo)
        old = self.git(repo, "rev-parse", "HEAD")
        self.git(repo, "mv", "changelog.d/1-old.added.md", "changelog.d/9-renamed.added.md")
        self.commit(repo, "rename")
        promote(repo)
        self.commit(repo, "release")
        self.assertNotIn("Already there", self.ok(repo, "--since", old))


class Robustness(GitCase):
    def test_blobs_handles_missing_entries_in_the_middle(self):
        repo = self.init()
        self.seed(repo)
        sha = self.git(repo, "rev-parse", "HEAD")
        r = WN.Repo(repo)
        got = r.blobs([f"{sha}:meson.build", f"{sha}:nope.txt", f"{sha}:changelog.d/README.md"], required=False)
        self.assertEqual(got[f"{sha}:nope.txt"], None)
        self.assertEqual(got[f"{sha}:changelog.d/README.md"], "readme\n")
        self.assertIn("project('yuzu'", got[f"{sha}:meson.build"])
        self.assertIsNone(r.show(sha, "nope.txt"))
        self.assertEqual(r.blobs([]), {})
        with self.assertRaises(WN.GitError) as cm:  # by default a missing object is an error, never "nothing there"
            r.blobs([f"{sha}:meson.build", f"{sha}:nope.txt"])
        self.assertIn("nope.txt", str(cm.exception))

    def test_an_unexpected_cat_file_reply_is_an_error(self):
        class R(FakeRepo):
            def _run(self, *args, **kw):
                return subprocess.CompletedProcess(args, 0, b"abc ambiguous\n", b"")
        with self.assertRaises(WN.GitError):
            R().blobs(["abc:x"])

    def test_show_reports_a_real_read_failure(self):
        # Not a repository: git fails for a reason other than an absent path. The ceiling keeps git
        # from finding a repository above the temp directory (this runs in-process, not through self.env).
        with mock.patch.dict(os.environ, {"GIT_CEILING_DIRECTORIES": str(self.dir.parent)}):
            with self.assertRaises(WN.GitError):
                WN.Repo(self.dir).show("HEAD", "meson.build")

    def test_sha_grammar(self):
        for good in ("a" * 40, "0" * 64):
            self.assertTrue(WN.SHA_RE.fullmatch(good), good)
        for bad in ("A" * 40, "a" * 39, "a" * 41, "a" * 63, "a" * 65, "g" * 40, "a" * 40 + "\n", ""):
            self.assertFalse(WN.SHA_RE.fullmatch(bad), repr(bad))

    def test_the_error_text_on_stderr_is_cleaned(self):
        repo = self.init()
        self.seed(repo)
        saved = WN.build_report

        def boom(*a, **k):
            raise WN.GitError("bad \x1b[2J \x9b \u202e text")
        WN.build_report = boom
        import contextlib
        import io
        err = io.StringIO()
        try:
            with contextlib.redirect_stderr(err):
                rc = WN.main(["--repo", str(repo)])
        finally:
            WN.build_report = saved
        self.assertEqual(rc, 2)
        self.assertEqual(err.getvalue(), "whats-new: bad ?[2J ? ? text\n")

    @unittest.skipUnless(os.name == "posix", "needs a shell redirect")
    def test_a_closed_stdout_is_not_a_traceback(self):
        repo = self.init()
        old = self.seed(repo)
        self.put(repo, "x.txt", "x\n")
        self.commit(repo, "next")
        res = subprocess.run(f'"{sys.executable}" "{SCRIPT}" --repo "{repo}" --since {old} >&-', shell=True,
                             env=self.env, capture_output=True, text=True)
        self.assertEqual(res.returncode, 0, res.stderr)
        self.assertNotIn("Traceback", res.stderr)

    def test_clean_every_boundary(self):
        inside = [0x00, 0x08, 0x0b, 0x0c, 0x0e, 0x1f, 0x7f, 0x80, 0x9f, 0xad, 0x34f, 0x61c, 0x115f, 0x1160, 0x17b4,
                  0x17b5, 0x180b, 0x180d, 0x180e, 0x180f, 0x200b, 0x200f, 0x2028, 0x2029, 0x202a, 0x202e, 0x2060, 0x2064,
                  0x2065, 0xfff0, 0xfff8, 0xe0080, 0xe00ff, 0xe01f0, 0xe0fff, 0x2066, 0x2069, 0x206a, 0x2800, 0x3164, 0xd800, 0xfe00, 0xfe0f, 0xfeff, 0xffa0,
                  0xfff9, 0xfffb, 0xfffc, 0xe0000, 0xe0001, 0xe007f, 0xe0100, 0xe01ef]
        outside = [0x09, 0x0a, 0x20, 0x7e, 0xa0, 0xa1, 0x34e, 0x350, 0x61b, 0x61d, 0x1810, 0x200a, 0x2010, 0x2027,
                   0x202f, 0x205f, 0x27ff, 0x2801, 0x3163, 0x3165, 0xfdff, 0xfe10, 0xfefe, 0xff00, 0xff9f,
                   0xffef, 0xfffd, 0xdffff, 0xe1000, 0x41, 0xe9, 0x4e2d]
        for cp in inside:
            self.assertEqual(WN.clean(f"a{chr(cp)}b"), "a?b", hex(cp))
        for cp in outside:
            self.assertEqual(WN.clean(f"a{chr(cp)}b"), f"a{chr(cp)}b", hex(cp))

    def test_vertical_tab_style_separators_do_not_split_text(self):
        self.assertEqual(WN.lines_of("a\x0bb\x0cc\u2028d\x85e"), ["a\x0bb\x0cc\u2028d\x85e"])
        self.assertEqual(WN.bullets("- one\x0b- two\n- three"), ["- one\x0b- two", "- three"])

    def test_long_changed_and_fixed_entries_are_still_cut(self):
        repo = self.init()
        old = self.seed(repo)
        self.put(repo, "changelog.d/2-c.changed.md", "- **Changed.** " + "c" * 300 + "\n")
        self.put(repo, "changelog.d/3-f.fixed.md", "- **Fixed.** " + "f" * 300 + "\n")
        self.put(repo, "changelog.d/4-b.fixed.md", "- **BREAKING:** " + "k" * 300 + "\n")
        self.commit(repo, "long entries")
        out = self.ok(repo, "--since", old)
        self.assertNotIn("c" * 300, out)
        self.assertNotIn("f" * 300, out)
        self.assertIn("k" * 300, out)  # the breaking marker is matched in any case


class RelativeDatesEndToEnd(GitCase):
    def test_relative_dates_resolve_against_commit_dates(self):
        repo = self.init()
        self.seed(repo)
        now = datetime.now(timezone.utc)
        self.put(repo, "changelog.d/2-old.added.md", "- **Long ago.**\n")
        self.commit(repo, "old", date=(now - timedelta(days=800)).strftime("%Y-%m-%dT%H:%M:%S+0000"))
        self.put(repo, "changelog.d/3-new.added.md", "- **Recent.**\n")
        self.commit(repo, "recent", date=now.strftime("%Y-%m-%dT%H:%M:%S+0000"))
        out = self.ok(repo, "--since", "1 year ago")
        self.assertIn("Recent", out)
        self.assertNotIn("Long ago", out)


class PullRules(PullHelpers):
    def test_pull_subjects_that_must_not_count_and_must(self):
        refuses = ["pull origin :zz: Fast-forward", "pull origin 'fix(finish)': x", "pull origin fix(start): x",
                   "merge origin/dev: Merge made by the 'ours' strategy.", "merge dev: x", "merge origin: x",
                   "merge /dev: x", "pull -s ours origin fix/foo: x", "pull -X theirs origin fix/foo: x",
                   "pull --depth 5 origin fix/foo: x", "pull -- origin fix/foo: x"]
        counts = ["pull -X theirs: Fast-forward", "pull -s ort: Fast-forward", "pull --depth 5: x", "pull -j 2: x",
                  "pull -o x: x", "pull --upload-pack x: x", "pull --cleanup m: x", "pull -X theirs origin dev: x",
                  "pull --rebase -X theirs (finish): x", "pull origin dev:dev: Fast-forward",
                  "pull origin dev:other: Fast-forward", "pull -- origin dev: x", "pull --strategy ours origin dev: x"]
        for subject in counts:
            self.assertTrue(self.base_for(subject), subject)
        for subject in refuses:
            self.assertIsNone(self.base_for(subject), subject)

    def test_every_option_that_takes_a_value_has_its_value_skipped(self):
        # Written out here, not read from the script: a set that loses an entry must fail this test.
        for opt in ("-s", "--strategy", "-X", "--strategy-option", "-o", "--server-option", "-j", "--jobs", "--depth",
                    "--deepen", "--cleanup", "--upload-pack", "--shallow-since", "--shallow-exclude",
                    "--negotiation-tip", "--refmap"):
            self.assertTrue(self.base_for(f"pull {opt} v origin dev: x"), opt)  # `v` is not a repository
            self.assertIsNone(self.base_for(f"pull {opt} v origin fix/foo: x"), opt)

    def test_a_pull_that_kept_none_of_the_upstream_is_not_a_pull(self):
        self.assertIsNone(self.base_for("pull -s ours origin dev: Merge made by the 'ours' strategy."))
        self.assertTrue(self.base_for("pull -s ours origin dev: Fast-forward"))

    def test_a_step_marker_needs_whitespace_before_it(self):
        # A branch that is literally named `dev(finish)` is not a step marker on `dev`.
        kw = dict(branch="dev(finish)", merge="refs/heads/dev(finish)", upstream="origin/dev(finish)")
        self.assertTrue(self.base_for("pull origin dev(finish): Fast-forward", **kw))
        self.assertTrue(self.base_for("pull origin dev(finish) (finish): x", **kw))

    def test_a_local_branch_with_a_different_name_than_its_upstream(self):
        upstream, local = self.make_clone()
        self.git(local, "checkout", "-q", "-b", "work", "origin/dev")
        self.push_upstream(upstream, "2-a.added.md", "- **Pulled into work.**\n")
        self.git(local, "pull", "-q")
        self.push_upstream(upstream, "3-b.added.md", "- **Second, by name.**\n")
        self.git(local, "pull", "-q", "origin", "dev")
        out = self.ok(local)
        self.assertIn("Second, by name", out)
        self.assertNotIn("Pulled into work", out)

    def test_an_annotated_tag_at_head_is_nothing_to_compare(self):
        repo = self.init()
        self.seed(repo)
        self.git(repo, "tag", "-a", "v9", "-m", "tag at head")
        res = self.run_script(repo, "--since", "v9")
        self.assertEqual(res.returncode, 2)
        self.assertIn("nothing to compare", res.stderr)

    def test_the_fallback_base_equal_to_head_is_an_error(self):
        class R(WN.Repo):
            def ok(self, *a):
                return False  # not an ancestor

            def git(self, *a):
                return "HEADSHA\n"  # the merge-base is HEAD

        saved = WN.last_pull_base
        WN.last_pull_base = lambda repo: ("OLDSHA", "pull: x")
        try:
            with self.assertRaises(WN.GitError) as ctx:
                WN.resolve_base(R(Path(".")), None, "HEADSHA")
        finally:
            WN.last_pull_base = saved
        self.assertIn("nothing to compare", str(ctx.exception))


class RenamedFragments(GitCase):
    def test_a_new_fragment_that_resembles_a_deleted_one_is_still_new(self):
        repo = self.init()
        self.seed(repo)
        body = "- **Templated entry.** line one\n  line two of the template\n  line three of the template\n"
        self.put(repo, "changelog.d/2-old.fixed.md", body)
        old = self.commit(repo, "a fragment")
        (repo / "changelog.d/2-old.fixed.md").unlink()
        self.put(repo, "changelog.d/3-new.fixed.md", body.replace("Templated entry.", "A different entry."))
        self.commit(repo, "delete one, add a close relative")
        self.assertIn("A different entry", self.ok(repo, "--since", old))

    def test_a_promoted_new_fragment_may_share_a_first_line_with_an_old_one(self):
        repo = self.init()
        self.seed(repo)
        self.put(repo, "changelog.d/2-gen.fixed.md", "- **Fixed.**\n")
        old = self.commit(repo, "generic fragment, pending")
        self.put(repo, "changelog.d/3-gen.fixed.md", "- **Fixed.**\n  but this one is new and longer\n")
        self.commit(repo, "another with the same first line")
        promote(repo)
        self.commit(repo, "release")
        out = self.ok(repo, "--since", old, "--full")
        self.assertRegex(out, r"Changelog entries added \(1[,)]")
        self.assertIn("but this one is new and longer", out)

    def test_an_unchanged_rename_is_not_new_but_an_edited_one_is(self):
        repo = self.init()
        old = self.seed(repo)
        self.git(repo, "mv", "changelog.d/1-old.added.md", "changelog.d/2-moved.added.md")
        self.commit(repo, "move unchanged")
        self.assertNotIn("Already there", self.ok(repo, "--since", old))
        self.put(repo, "changelog.d/2-moved.added.md", "- **Already there, reworded.**\n")
        self.commit(repo, "then reword it")
        self.assertIn("Already there, reworded", self.ok(repo, "--since", old))

    def test_a_nul_in_a_promoted_fragment_does_not_hide_it(self):
        repo = self.init()
        old = self.seed(repo)
        self.put(repo, "changelog.d/2-nul.added.md", "- **Has a NUL.** x\x00y\n")
        self.commit(repo, "fragment with a NUL")
        promote(repo)
        self.commit(repo, "release")
        self.assertIn("Has a NUL", self.ok(repo, "--since", old))

    def test_a_deleted_fragment_with_no_bullet_makes_no_warning(self):
        repo = self.init()
        old = self.seed(repo)
        self.put(repo, "changelog.d/2-junk.fixed.md", "no bullet here\n")
        self.commit(repo, "junk")
        (repo / "changelog.d/2-junk.fixed.md").unlink()
        self.commit(repo, "removed by hand")
        promote(repo)
        self.commit(repo, "release")
        self.assertNotIn("no '- ' bullet", self.ok(repo, "--since", old))

    def test_a_non_ascii_dockerfile_path_is_still_an_image_bump(self):
        repo = self.init()
        old = self.seed(repo)
        self.put(repo, "deploy/docker/Dockerfile.caf\u00e9", "FROM x\n")
        self.commit(repo, "build(deps): bump x")
        self.assertIn("1 Docker image, 0 other", self.ok(repo, "--since", old))

    def test_a_non_utf8_commit_subject_is_replaced_not_a_traceback(self):
        repo = self.init()
        old = self.seed(repo)
        self.git(repo, "config", "i18n.commitEncoding", "ISO-8859-1")  # the repo stores latin-1 subjects
        self.put(repo, "x.txt", "x\n")
        self.git(repo, "add", "-A")
        subprocess.run(["git", "-c", "commit.gpgsign=false", "commit", "-q", "-F", "-"], cwd=repo, env=self.env,
                       input="build(deps): bump caf\xe9\n".encode("latin-1"), check=True, capture_output=True)
        res = self.run_script(repo, "--since", old)
        self.assertEqual(res.returncode, 0, res.stderr)
        self.assertNotIn("Traceback", res.stderr)
        # Without the pinned i18n.logOutputEncoding git would hand back the stored latin-1 bytes.
        self.assertIn("bump caf\u00e9", res.stdout)

    def test_a_broken_pipe_is_quiet(self):
        repo = self.init()
        old = self.seed(repo)
        self.put(repo, "x.txt", "x\n")
        self.commit(repo, "next")
        r, w = os.pipe()
        os.close(r)
        try:
            res = subprocess.run([sys.executable, str(SCRIPT), "--repo", str(repo), "--since", old], env=self.env,
                                 stdout=w, stderr=subprocess.PIPE, text=True)
        finally:
            os.close(w)
        self.assertEqual(res.returncode, 0, res.stderr)
        self.assertNotIn("Traceback", res.stderr)

    def test_a_failed_cat_file_is_an_error(self):
        class R(FakeRepo):
            def _run(self, *args, **kw):
                return subprocess.CompletedProcess(args, 1, b"", b"fatal: broken")
        with self.assertRaises(WN.GitError):
            R().blobs(["abc:x"])


class PromotedFragmentLives(GitCase):
    """Fragment lifecycles a net diff cannot tell apart: rename vs delete-and-add, rename then edit."""

    def delete(self, repo, rel):
        (repo / rel).unlink()

    def test_a_new_fragment_identical_to_one_a_release_promoted_is_listed(self):
        repo = self.init()
        self.put(repo, "changelog.d/2-a.fixed.md", "- **Bump flaky timeout.**\n")
        old = self.seed(repo)
        promote(repo)
        self.commit(repo, "release")
        self.put(repo, "changelog.d/9-b.fixed.md", "- **Bump flaky timeout.**\n")
        self.commit(repo, "the same words, a new change")
        out = self.ok(repo, "--since", old)
        self.assertRegex(out, r"Changelog entries added \(1[,)]")
        self.assertIn("Bump flaky timeout", out)

    def test_a_deletion_and_an_identical_addition_in_separate_commits_is_not_a_rename(self):
        repo = self.init()
        self.put(repo, "changelog.d/2-a.fixed.md", "- **Same text.**\n")
        old = self.seed(repo)
        self.delete(repo, "changelog.d/2-a.fixed.md")
        self.commit(repo, "withdraw")
        self.put(repo, "changelog.d/3-b.fixed.md", "- **Same text.**\n")
        self.commit(repo, "re-land under another name")
        self.assertIn("Same text", self.ok(repo, "--since", old))

    def test_a_path_promoted_and_added_back_with_new_text_is_listed(self):
        repo = self.init()
        self.put(repo, "changelog.d/2-a.fixed.md", "- **First text.**\n")
        old = self.seed(repo)
        promote(repo)
        self.commit(repo, "release")
        self.put(repo, "changelog.d/2-a.fixed.md", "- **Second text.**\n")
        self.commit(repo, "same name, new change")
        out = self.ok(repo, "--since", old)
        self.assertIn("Second text", out)
        self.assertNotIn("First text", out)

    def test_added_renamed_edited_then_promoted_is_listed_once(self):
        repo = self.init()
        old = self.seed(repo)
        self.put(repo, "changelog.d/2-a.added.md", "- **Early title.** details\n")
        self.commit(repo, "add")
        self.git(repo, "mv", "changelog.d/2-a.added.md", "changelog.d/7-b.added.md")
        self.commit(repo, "rename to the PR number")
        self.put(repo, "changelog.d/7-b.added.md", "- **Final title.** details\n")
        self.commit(repo, "reword")
        promote(repo)
        self.commit(repo, "release")
        out = self.ok(repo, "--since", old)
        self.assertIn("Final title", out)
        self.assertNotIn("Early title", out)
        self.assertRegex(out, r"Changelog entries added \(1[,)]")

    def test_a_rename_that_changes_the_section_then_promoted_shows_the_final_section(self):
        repo = self.init()
        old = self.seed(repo)
        self.put(repo, "changelog.d/2-y.added.md", "- **Moved section.**\n")
        self.commit(repo, "add")
        self.git(repo, "mv", "changelog.d/2-y.added.md", "changelog.d/2-y.fixed.md")
        self.commit(repo, "it was a fix")
        promote(repo)
        self.commit(repo, "release")
        out = self.ok(repo, "--since", old)
        self.assertIn("Fixed (1)", out)
        self.assertNotIn("Added (", out)
        self.assertEqual(out.count("Moved section"), 1)

    def test_an_old_fragment_renamed_twice_unchanged_is_not_new_even_when_promoted(self):
        repo = self.init()
        old = self.seed(repo)
        self.git(repo, "mv", "changelog.d/1-old.added.md", "changelog.d/5-mid.added.md")
        self.commit(repo, "first rename")
        self.git(repo, "mv", "changelog.d/5-mid.added.md", "changelog.d/8-last.added.md")
        self.commit(repo, "second rename")
        self.assertNotIn("Already there", self.ok(repo, "--since", old))
        promote(repo)
        self.commit(repo, "release")
        self.assertNotIn("Already there", self.ok(repo, "--since", old))

    def test_a_rename_chain_cycle_does_not_hang(self):
        class R(FakeRepo):
            def git(self, *args):
                return ""

            def names(self, *args):
                return {"diff": ["changelog.d/2-b.added.md"], "ls-tree": ["changelog.d/1-a.added.md"]}.get(args[0], [])

            def blobs(self, specs, required=True):
                return {s: "- **x.**\n" for s in specs}

        saved = WN._rename_pairs
        WN._rename_pairs = lambda *a: ({"changelog.d/2-b.added.md": ("changelog.d/3-c.added.md", 100),
                                        "changelog.d/3-c.added.md": ("changelog.d/2-b.added.md", 100)}, {})
        try:
            finished, result = within(10, WN.added_fragments, R(), "o", "n")
        finally:
            WN._rename_pairs = saved
        self.assertTrue(finished, "old_root looped")
        self.assertEqual(list(result), ["changelog.d/2-b.added.md"])

    def test_an_inherited_git_dir_does_not_redirect_the_script(self):
        repo = self.init()
        old = self.seed(repo)
        self.put(repo, "changelog.d/2-a.added.md", "- **Right repo.**\n")
        self.commit(repo, "add")
        other = self.init("other")
        self.seed(other)
        env = {**self.env, "GIT_DIR": str(other / ".git")}
        res = self.run_script(repo, "--since", old, env=env)
        self.assertEqual(res.returncode, 0, res.stderr)
        self.assertIn("Right repo", res.stdout)

    def test_the_suite_environment_carries_no_git_variable_but_its_own(self):
        own = {"GIT_CONFIG_GLOBAL", "GIT_CONFIG_SYSTEM", "GIT_CONFIG_NOSYSTEM", "GIT_CEILING_DIRECTORIES",
               "GIT_AUTHOR_NAME", "GIT_AUTHOR_EMAIL", "GIT_COMMITTER_NAME", "GIT_COMMITTER_EMAIL"}
        with mock.patch.dict(os.environ, {"GIT_DIR": "/nonexistent"}):
            case = GitCase("setUp")
            case.setUp()
            try:
                self.assertEqual({k for k in case.env if k.startswith("GIT_")}, own)
            finally:
                case.tearDown()

    def test_a_meson_version_cannot_span_lines(self):
        repo = self.init()
        self.put(repo, "meson.build", "project('yuzu', version: '1.0\nINJECTED')\n")
        self.commit(repo, "odd")
        self.assertEqual(WN.meson_version(WN.Repo(repo), "HEAD"), {})


class FragmentLivesAndHostileText(GitCase):
    """Fragment lives, promoted lines edited later, hidden names, forged lines."""

    def promoted_twice(self, first_at_base):
        repo = self.init()
        if first_at_base:
            self.put(repo, "changelog.d/2-a.fixed.md", "- **First text.**\n")
        old = self.seed(repo)
        if not first_at_base:
            self.put(repo, "changelog.d/2-a.fixed.md", "- **First text.**\n")
            self.commit(repo, "add")
        promote(repo)
        self.commit(repo, "release 1")
        self.put(repo, "changelog.d/2-a.fixed.md", "- **Second text.**\n")
        self.commit(repo, "same name, new change")
        promote(repo, "1.4.0")
        self.commit(repo, "release 2")
        return repo, old

    def test_a_path_promoted_twice_lists_the_second_life_when_the_first_was_the_readers(self):
        repo, old = self.promoted_twice(True)
        out = self.ok(repo, "--since", old)
        self.assertIn("Second text", out)
        self.assertNotIn("First text", out)
        self.assertRegex(out, r"Changelog entries added \(1[,)]")

    def test_a_path_promoted_twice_lists_both_lives_when_neither_was_the_readers(self):
        repo, old = self.promoted_twice(False)
        out = self.ok(repo, "--since", old)
        self.assertIn("First text", out)
        self.assertIn("Second text", out)
        self.assertNotIn("Already there", out)
        self.assertRegex(out, r"Changelog entries added \(2[,)]")

    def test_a_name_reused_after_a_rename_and_promoted_lists_both_entries(self):
        repo = self.init()
        old = self.seed(repo)
        self.put(repo, "changelog.d/0000-x.fixed.md", "- **X entry.**\n")
        self.commit(repo, "add")
        self.git(repo, "mv", "changelog.d/0000-x.fixed.md", "changelog.d/7-x.fixed.md")
        self.commit(repo, "rename to the PR number")
        self.put(repo, "changelog.d/0000-x.fixed.md", "- **Y entry other.**\n")
        self.commit(repo, "the placeholder name again")
        promote(repo)
        self.commit(repo, "release")
        out = self.ok(repo, "--since", old)
        self.assertIn("X entry", out)
        self.assertIn("Y entry other", out)

    def test_a_rename_cycle_then_a_release_still_lists_the_entry_once(self):
        repo = self.init()
        old = self.seed(repo)
        self.put(repo, "changelog.d/2-a.fixed.md", "- **Cycle entry.**\n")
        self.commit(repo, "add")
        for src, dst in (("2-a", "3-b"), ("3-b", "2-a"), ("2-a", "3-b")):
            self.git(repo, "mv", f"changelog.d/{src}.fixed.md", f"changelog.d/{dst}.fixed.md")
            self.commit(repo, f"{src} to {dst}")
        promote(repo)
        self.commit(repo, "release")
        out = self.ok(repo, "--since", old)
        self.assertRegex(out, r"Changelog entries added \(1[,)]")
        self.assertIn("Cycle entry", out)

    def test_a_promoted_line_polished_after_the_release_is_still_listed(self):
        repo = self.init()
        old = self.seed(repo)
        self.put(repo, "changelog.d/7000-x.changed.md", "- **Breaking** change X needs action. Details here.\n")
        self.put(repo, "changelog.d/7001-y.fixed.md", "- Plain Y.\n")
        self.commit(repo, "add")
        promote(repo)
        self.commit(repo, "release")
        text = (repo / "CHANGELOG.md").read_text(encoding="utf-8")
        self.put(repo, "CHANGELOG.md", text.replace("Plain Y.", "Plain Y (see docs).").replace(
            "Details here.", "Details in the upgrade guide."))
        self.commit(repo, "polish the release notes")
        out = self.ok(repo, "--since", old)
        self.assertIn("Breaking", out)
        self.assertIn("Plain Y", out)
        self.assertRegex(out, r"Changelog entries added \(2[,)]")

    def test_a_rename_into_security_or_removed_is_a_reclassification_and_is_listed(self):
        repo = self.init()
        self.put(repo, "changelog.d/3-s.fixed.md", "- **Sec text.**\n")
        self.put(repo, "changelog.d/4-r.changed.md", "- **Gone text.**\n")
        old = self.seed(repo)
        self.git(repo, "mv", "changelog.d/3-s.fixed.md", "changelog.d/3-s.security.md")
        self.git(repo, "mv", "changelog.d/4-r.changed.md", "changelog.d/4-r.removed.md")
        self.commit(repo, "reclassify")
        out = self.ok(repo, "--since", old)
        self.assertIn("Security (1)", out)
        self.assertIn("Removed (1)", out)
        self.assertNotIn("Already there", out)

    def test_a_renamed_edited_then_promoted_old_fragment_is_listed_in_its_new_words(self):
        repo = self.init()
        old = self.seed(repo)
        self.git(repo, "mv", "changelog.d/1-old.added.md", "changelog.d/5-mid.added.md")
        self.commit(repo, "rename")
        self.put(repo, "changelog.d/5-mid.added.md", "- **Already there, now reworded.**\n")
        self.commit(repo, "reword")
        promote(repo)
        self.commit(repo, "release")
        self.assertIn("now reworded", self.ok(repo, "--since", old))

    def test_an_existing_fragment_reworded_and_then_promoted_is_not_listed(self):
        repo = self.init()
        old = self.seed(repo)
        self.put(repo, "changelog.d/1-old.added.md", "- **Already there, reworded.**\n")
        self.commit(repo, "reword")
        promote(repo)
        self.commit(repo, "release")
        self.assertNotIn("Already there", self.ok(repo, "--since", old))

    def test_a_rename_made_inside_a_merge_commit_is_still_a_rename(self):
        repo = self.init()
        old = self.seed(repo)
        self.git(repo, "checkout", "-q", "-b", "side")
        self.put(repo, "side.txt", "s\n")
        self.commit(repo, "side")
        self.git(repo, "checkout", "-q", "dev")
        self.put(repo, "dev.txt", "d\n")
        self.commit(repo, "dev")
        self.git(repo, "merge", "--no-ff", "--no-commit", "side")
        self.git(repo, "mv", "changelog.d/1-old.added.md", "changelog.d/2-new.added.md")
        self.commit(repo, "merge with a rename")
        self.assertNotIn("Already there", self.ok(repo, "--since", old))

    def test_a_rename_is_found_when_the_user_config_turns_rename_detection_off(self):
        repo = self.init()
        old = self.seed(repo)
        self.git(repo, "config", "diff.renames", "false")
        self.git(repo, "config", "merge.renames", "false")
        self.git(repo, "mv", "changelog.d/1-old.added.md", "changelog.d/2-new.added.md")
        self.commit(repo, "rename")
        self.assertNotIn("Already there", self.ok(repo, "--since", old))

    def test_an_edited_existing_fragment_is_not_listed_after_a_stale_merge(self):
        repo = self.init()
        self.put(repo, "x.txt", "x\n")
        self.commit(repo, "base")
        self.git(repo, "checkout", "-q", "-b", "side")
        self.put(repo, "side.txt", "s\n")
        self.commit(repo, "side forked before the fragment existed")
        self.git(repo, "checkout", "-q", "dev")
        self.put(repo, "changelog.d/1-old.added.md", "- **Already there.**\n")
        old = self.commit(repo, "the fragment the reader has")
        self.put(repo, "changelog.d/1-old.added.md", "- **Already there, reworded.**\n")
        self.commit(repo, "reword it")
        self.git(repo, "merge", "--no-ff", "-q", "-m", "merge side", "side")
        out = self.ok(repo, "--since", old)
        self.assertNotIn("Already there", out)
        self.assertIn("No changelog fragments were added", out)

    def test_a_name_ending_in_a_newline_is_reported_not_silently_dropped(self):
        repo = self.init()
        old = self.seed(repo)
        self.put(repo, "changelog.d/hide.security.md\n", "- **Security**: hidden fix.\n")
        self.put(repo, "changelog.d/3-ok.fixed.md", "- **Visible.**\n")
        self.commit(repo, "add")
        out = self.ok(repo, "--since", old)
        self.assertIn("Visible", out)
        self.assertIn("! 1 file added under changelog.d/ not named like fragments", out)
        self.assertIn("hide.security.md?", out)

    def test_a_missing_object_is_an_error_not_no_fragments(self):
        repo = self.init()
        old = self.seed(repo)
        self.put(repo, "changelog.d/2-n.fixed.md", "- **New entry.**\n")
        self.commit(repo, "add")
        oid = self.git(repo, "rev-parse", "HEAD:changelog.d/2-n.fixed.md")
        (repo / ".git" / "objects" / oid[:2] / oid[2:]).unlink()
        res = self.run_script(repo, "--since", old)
        self.assertEqual(res.returncode, 2, res.stdout)
        self.assertIn("2-n.fixed.md", res.stderr)
        self.assertNotIn("No changelog fragments", res.stdout)

    def test_repository_text_cannot_start_a_line_of_its_own(self):
        repo = self.init()
        old = self.seed(repo)
        self.put(repo, "vcpkg.json", vcpkg("a" * 40, ["zlib", {"name": "abseil", "version>=": "20240116.1"},
                                                      "evil\nSecurity (0)\n  none of the tracked versions changed"]))
        self.put(repo, "gateway/rebar.lock", LOCK % "2.18.0" + '{pkg,<<"cow\nChanges since your last pull: 0 commits">>,<<"1">>}.\n')
        self.put(repo, "top\nVersion bumps\n  none of the tracked versions changed/x.txt", "x\n")
        self.put(repo, "changelog.d/9-s.security.md",
                 "- **Security**: real one\nChangelog entries added (0)\n\nNo changelog fragments were added in this range\n")
        self.commit(repo, "hostile text")
        out = self.ok(repo, "--since", old)
        lines = out.splitlines()
        for forged in ("Security (0)", "  none of the tracked versions changed", "Changelog entries added (0)",
                       "No changelog fragments were added in this range"):
            self.assertNotIn(forged, lines, forged)
        self.assertEqual(sum(1 for line in lines if line.startswith("Changes since")), 1)
        self.assertEqual(lines.count("Version bumps"), 1)
        self.assertEqual(sum(1 for line in lines if line.startswith("Changelog entries added")), 1)
        self.assertIn("    Changelog entries added (0)", lines)  # shown, but indented under the real entry

    def test_the_relative_date_floor_matches_the_absolute_one(self):
        with self.assertRaises(WN.GitError):
            WN.date_cutoff("56 years ago", now=datetime(2026, 1, 1, 5))
        with self.assertRaises(WN.GitError):
            WN.date_cutoff("1 year ago", now=datetime(1971, 1, 1))
        self.assertTrue(WN.date_cutoff("1 day ago", now=datetime(2026, 1, 5)))

    def test_the_environment_git_runs_in_is_pinned(self):
        if os.name == "nt":
            self.skipTest("a shell shim")
        shim = self.dir / "bin"
        shim.mkdir()
        dump = self.dir / "env.dump"
        (shim / "git").write_text(f'#!/bin/sh\nenv > "{dump}"\nexec "{shutil.which("git")}" "$@"\n')
        (shim / "git").chmod(0o755)
        repo = self.init()
        old = self.seed(repo)
        self.put(repo, "x.txt", "x\n")
        self.commit(repo, "next")
        env = {**self.env, "PATH": f"{shim}{os.pathsep}{os.environ.get('PATH', '')}", "LANGUAGE": "de",
               **{k: str(self.dir / "elsewhere") for k in sorted(WN.REPO_LOCATING_ENV)}}
        self.assertEqual(self.run_script(repo, "--since", old, env=env).returncode, 0)
        seen = dict(line.split("=", 1) for line in dump.read_text().splitlines() if "=" in line)
        # Written out here, not read from the script, so an entry the script loses fails this test.
        for name in ("GIT_DIR", "GIT_WORK_TREE", "GIT_INDEX_FILE", "GIT_COMMON_DIR", "GIT_OBJECT_DIRECTORY",
                     "GIT_ALTERNATE_OBJECT_DIRECTORIES", "GIT_NAMESPACE", "GIT_PREFIX"):
            self.assertIn(name, env)
            self.assertNotIn(name, seen)
        self.assertEqual((seen.get("LC_ALL"), seen.get("LANGUAGE")), ("C", "C"))

    def test_a_rename_lasso_that_does_not_include_the_start_does_not_hang(self):
        class R(FakeRepo):
            def git(self, *args):
                return ""

            def names(self, *args):
                return ["changelog.d/1-x.added.md"] if args[0] == "diff" and "--diff-filter=AT" in args else []

            def blobs(self, specs, required=True):
                return {s: "- **x.**\n" for s in specs}

        saved = WN._rename_pairs
        pairs = {"changelog.d/1-x.added.md": ("changelog.d/2-y.added.md", 100),
                 "changelog.d/2-y.added.md": ("changelog.d/3-z.added.md", 100),
                 "changelog.d/3-z.added.md": ("changelog.d/2-y.added.md", 100)}
        WN._rename_pairs = lambda *a: (pairs, {})
        try:
            finished, result = within(10, WN.added_fragments, R(), "o", "n")
        finally:
            WN._rename_pairs = saved
        self.assertTrue(finished, "old_root looped")
        self.assertEqual(list(result), ["changelog.d/1-x.added.md"])


class FragmentEdgeCases(GitCase):
    """Names that are not fragments, release shapes that hide a promotion, files that are not files."""

    def test_a_misnamed_file_renamed_into_a_fragment_name_is_a_new_entry_not_a_crash(self):
        repo = self.init()
        old = self.seed(repo)
        self.put(repo, "changelog.d/9-x.fix.md", "- **Typo section.**\n")
        self.put(repo, "changelog.d/draft.md", "- **Draft notes.**\n")
        self.commit(repo, "first try")
        self.git(repo, "mv", "changelog.d/9-x.fix.md", "changelog.d/9-x.fixed.md")
        self.git(repo, "mv", "changelog.d/draft.md", "changelog.d/10-draft.added.md")
        self.commit(repo, "name them properly")
        res = self.run_script(repo, "--since", old)
        self.assertEqual(res.returncode, 0, res.stderr)
        self.assertNotIn("Traceback", res.stderr)
        self.assertIn("Typo section", res.stdout)
        self.assertIn("Draft notes", res.stdout)

    def test_a_rename_through_a_non_fragment_name_is_a_new_entry(self):
        repo = self.init()
        old = self.seed(repo)
        self.git(repo, "mv", "changelog.d/1-old.added.md", "changelog.d/tmp.md")
        self.commit(repo, "park")
        self.git(repo, "mv", "changelog.d/tmp.md", "changelog.d/5-new.added.md")
        self.commit(repo, "unpark")
        out = self.ok(repo, "--since", old)
        # Not recognised as the entry the reader had (the rename went through a name that is not a
        # fragment name), so it is listed, once: an extra line, never a missing one.
        self.assertEqual(out.count("Already there"), 1)
        self.assertRegex(out, r"Changelog entries added \(1[,)]")

    def test_a_misnamed_file_renamed_then_promoted_is_listed_once(self):
        repo = self.init()
        old = self.seed(repo)
        self.put(repo, "changelog.d/9-x.fix.md", "- **Typo section.**\n")
        self.commit(repo, "first try")
        self.git(repo, "mv", "changelog.d/9-x.fix.md", "changelog.d/9-x.fixed.md")
        self.commit(repo, "fix the name")
        promote(repo)
        self.commit(repo, "release")
        out = self.ok(repo, "--since", old)
        self.assertEqual(out.count("Typo section"), 1)

    def test_a_release_reachable_only_through_a_pruned_merge_parent_is_still_seen(self):
        repo = self.init()
        self.put(repo, "CHANGELOG.md", CHANGELOG)
        self.put(repo, "changelog.d/README.md", "readme\n")
        old = self.commit(repo, "base, no fragments")
        self.git(repo, "checkout", "-q", "-b", "topic")
        self.put(repo, "changelog.d/20-topic.added.md", "- **Topic feature.**\n")
        self.commit(repo, "topic")
        self.git(repo, "checkout", "-q", "dev")
        self.put(repo, "changelog.d/10-a.fixed.md", "- **Dev fix A.**\n")
        self.commit(repo, "dev a")
        self.put(repo, "changelog.d/11-b.added.md", "- **Dev feature B.**\n")
        self.commit(repo, "dev b")
        promote(repo)
        self.commit(repo, "release")
        self.git(repo, "merge", "-q", "--no-ff", "-m", "merge topic", "topic")
        out = self.ok(repo, "--since", old)
        for entry in ("Topic feature", "Dev fix A", "Dev feature B"):
            self.assertIn(entry, out)
        self.assertRegex(out, r"Changelog entries added \(3[,)]")

    def test_a_release_that_also_adds_a_similar_fragment_still_promotes_the_deleted_one(self):
        repo = self.init()
        old = self.seed(repo)
        self.put(repo, "changelog.d/2-a.fixed.md", "- **Alpha fix**\n  one\n  two\n  three\n  four\n")
        self.commit(repo, "add")
        promote(repo)
        self.put(repo, "changelog.d/3-next.fixed.md", "- **Beta fix**\n  one\n  two\n  three\n  four\n")
        self.commit(repo, "release, and the next change in the same commit")
        out = self.ok(repo, "--since", old)
        self.assertIn("Alpha fix", out)
        self.assertIn("Beta fix", out)

    def test_a_rename_with_an_edit_that_keeps_the_first_bullet_is_listed_once(self):
        repo = self.init()
        old = self.seed(repo)
        self.put(repo, "changelog.d/2-a.fixed.md", "- **Alpha fix**\n  one\n  two\n  three\n  four\n")
        self.commit(repo, "add")
        self.git(repo, "mv", "changelog.d/2-a.fixed.md", "changelog.d/7-a.fixed.md")
        self.put(repo, "changelog.d/7-a.fixed.md", "- **Alpha fix**\n  one\n  two\n  three\n  five\n")
        self.commit(repo, "rename and edit the tail")
        promote(repo)
        self.commit(repo, "release")
        self.assertEqual(self.ok(repo, "--since", old).count("Alpha fix"), 1)

    def test_a_submodule_named_like_a_fragment_is_reported_not_fatal(self):
        repo = self.init()
        old = self.seed(repo)
        self.put(repo, "changelog.d/3-ok.fixed.md", "- **Visible.**\n")
        self.git(repo, "add", "-A")
        self.git(repo, "update-index", "--add", "--cacheinfo", f"160000,{'a' * 40},changelog.d/9-sub.fixed.md")
        # A gitlink whose commit this repository does have is a commit where a file was expected.
        self.git(repo, "update-index", "--add", "--cacheinfo", f"160000,{old},changelog.d/8-sub.added.md")
        self.clock += 1
        self.env["GIT_AUTHOR_DATE"] = self.env["GIT_COMMITTER_DATE"] = f"2026-10-{self.clock:02d}T12:00:00+0000"
        self.git(repo, "commit", "-q", "-m", "a gitlink among the fragments")
        res = self.run_script(repo, "--since", old)
        self.assertEqual(res.returncode, 0, res.stderr)
        self.assertIn("Visible", res.stdout)
        self.assertIn("! 2 paths named like fragments but not regular files", res.stdout)
        self.assertIn("9-sub.fixed.md", res.stdout)
        self.assertIn("8-sub.added.md", res.stdout)

    def test_readme_and_gitkeep_are_not_reported_but_a_nested_fragment_is(self):
        repo = self.init()
        old = self.seed(repo)
        self.put(repo, "changelog.d/.gitkeep", "")
        self.put(repo, "changelog.d/sub/4-n.fixed.md", "- **Nested.**\n")
        self.commit(repo, "files")
        out = self.ok(repo, "--since", old)
        self.assertIn("! 1 file added under changelog.d/", out)
        self.assertIn("sub/4-n.fixed.md", out)
        self.assertNotIn(".gitkeep", out)

    def test_only_unlistable_files_say_so_instead_of_claiming_nothing_was_added(self):
        repo = self.init()
        old = self.seed(repo)
        self.put(repo, "changelog.d/5-nobullet.fixed.md", "no bullet here\n")
        self.commit(repo, "a fragment with no bullet")
        out = self.ok(repo, "--since", old)
        self.assertIn("No changelog entries could be listed", out)
        self.assertNotIn("No changelog fragments were added", out)
        self.assertIn("! 1 fragment with no '- ' bullet", out)

    def test_a_promoted_entry_carries_a_note_that_it_is_as_promoted(self):
        repo = self.init()
        old = self.seed(repo)
        self.put(repo, "changelog.d/2-a.fixed.md", "- **Released.**\n")
        self.commit(repo, "add")
        promote(repo)
        self.commit(repo, "release")
        self.assertIn("wording as it was", self.ok(repo, "--since", old))
        repo2 = self.init("other")
        old2 = self.seed(repo2)
        self.put(repo2, "changelog.d/2-a.fixed.md", "- **Pending.**\n")
        self.commit(repo2, "add")
        self.assertNotIn("wording as it was", self.ok(repo2, "--since", old2))

    def test_a_gitattributes_that_marks_the_changelog_binary_does_not_hide_a_promotion(self):
        repo = self.init()
        self.put(repo, ".gitattributes", "CHANGELOG.md -diff\n")
        old = self.seed(repo)
        self.put(repo, "changelog.d/2-a.fixed.md", "- **Released anyway.**\n")
        self.commit(repo, "add")
        promote(repo)
        self.commit(repo, "release")
        self.assertIn("Released anyway", self.ok(repo, "--since", old))

    @unittest.skipUnless(os.name == "posix", "needs /dev/zero")
    def test_a_mailmap_file_in_the_repository_config_cannot_hang_the_script(self):
        repo = self.init()
        old = self.seed(repo)
        self.git(repo, "config", "mailmap.file", "/dev/zero")
        self.put(repo, "changelog.d/2-a.fixed.md", "- **Mailmapped.**\n")
        self.commit(repo, "add")
        self.assertIn("Mailmapped", self.ok(repo, "--since", old))

    def test_a_changelog_heading_without_a_closing_bracket_cannot_swallow_the_next_line(self):
        repo = FakeRepo(files={("HEAD", "CHANGELOG.md"): "## [1\n## [2.0.0] - 2026-11-01\n"})
        self.assertEqual(WN.released_version(repo, "HEAD"), {"latest released CHANGELOG section": "2.0.0"})

    def test_repository_text_in_every_version_field_cannot_start_a_line_of_its_own(self):
        forged = "2\nVersion bumps\n  none of the tracked versions changed\nChangelog entries added (0)"

        def check(out):
            lines = out.splitlines()
            self.assertEqual(lines.count("Version bumps"), 1, out)
            self.assertNotIn("Changelog entries added (0)", lines)
            self.assertNotIn("  none of the tracked versions changed", lines)

        base = ["zlib", {"name": "abseil", "version>=": "20240116.1"}]
        variants = {
            "changed": (base, {"abseil": forged}),
            "added": (base + [{"name": "newdep", "version>=": forged}], {}),
            "override": (base, {"overrides": [{"name": "zlib", "version": forged}]}),
            "feature name": (base, {"features": {"f\nVersion bumps": {"description": "x", "dependencies": ["zlib"]}}}),
        }
        for label, (deps, extra) in variants.items():
            with self.subTest(label):
                repo = self.init(f"r-{label.replace(' ', '-')}")
                old = self.seed(repo)
                if label == "changed":
                    deps = ["zlib", {"name": "abseil", "version>=": forged}]
                    extra = {}
                data = json.loads(vcpkg("a" * 40, deps))
                data.update(extra)
                self.put(repo, "vcpkg.json", json.dumps(data))
                self.commit(repo, "hostile")
                check(self.ok(repo, "--since", old))
        # The forged value on the old side: dropped, and changed to a real one.
        for label, newer in (("removed", ["zlib"]), ("changed back", ["zlib", {"name": "abseil", "version>=": "20240116.1"}])):
            with self.subTest(label):
                repo = self.init(f"r-{label.replace(' ', '-')}")
                self.seed(repo)
                self.put(repo, "vcpkg.json", vcpkg("a" * 40, ["zlib", {"name": "abseil", "version>=": forged}]))
                old = self.commit(repo, "hostile")
                self.put(repo, "vcpkg.json", vcpkg("a" * 40, newer))
                self.commit(repo, "fix it")
                check(self.ok(repo, "--since", old))


class VersionsFlagAndMarkers(GitCase):
    """--versions, the **Breaking count in the header, and the [released X] marker."""

    def released_repo(self):
        """A fragment added then promoted into 1.3.0, then a second fragment still pending."""
        repo = self.init()
        self.seed(repo)
        old = self.git(repo, "rev-parse", "HEAD")
        self.put(repo, "changelog.d/2-rel.added.md", "- **Shipped thing.**\n")
        self.commit(repo, "add")
        promote(repo)
        self.commit(repo, "release")
        self.put(repo, "changelog.d/3-pend.fixed.md", "- **Pending thing.**\n")
        self.commit(repo, "pending")
        return repo, old

    def test_a_promoted_entry_names_its_release_and_a_pending_one_is_unmarked(self):
        repo, old = self.released_repo()
        out = self.ok(repo, "--since", old)
        self.assertRegex(out, r"Changelog entries added \(2, 1 already released\)")
        self.assertIn("- **Shipped thing.**  [released 1.3.0]", out)
        self.assertIn("- **Pending thing.**\n", out)
        self.assertEqual(out.count("[released"), 1)

    def test_nothing_is_marked_when_no_release_is_in_the_range(self):
        repo = self.init()
        old = self.seed(repo)
        self.put(repo, "changelog.d/2-a.added.md", "- **Only pending.**\n")
        self.commit(repo, "add")
        out = self.ok(repo, "--since", old)
        self.assertIn("Changelog entries added (1)", out)
        self.assertNotIn("released", out.split("Changelog entries added")[1].split("Added (1)")[1])

    def test_an_entry_polished_after_its_release_is_marked_without_a_version(self):
        repo, old = self.released_repo()
        text = (repo / "CHANGELOG.md").read_text(encoding="utf-8")
        self.put(repo, "CHANGELOG.md", text.replace("- **Shipped thing.**", "- **Shipped thing, polished.**"))
        self.commit(repo, "polish the release notes")
        out = self.ok(repo, "--since", old)
        self.assertIn("- **Shipped thing.**  [released]", out)
        self.assertNotIn("[released 1.3.0]", out)

    def test_an_entry_whose_line_sits_under_unreleased_is_not_marked(self):
        repo, old = self.released_repo()
        text = (repo / "CHANGELOG.md").read_text(encoding="utf-8")
        self.put(repo, "CHANGELOG.md", text.replace("## [1.3.0] - 2026-10-30", "## [Unreleased]"))
        self.commit(repo, "the release was backed out")
        out = self.ok(repo, "--since", old)
        self.assertIn("Shipped thing", out)
        self.assertNotIn("[released", out)
        self.assertRegex(out, r"Changelog entries added \(2\)")

    def test_the_marker_survives_truncation_and_whole_entry_display(self):
        repo = self.init()
        old = self.seed(repo)
        self.put(repo, "changelog.d/2-long.added.md", "- **Long.** " + "x" * 400 + "\n")
        self.put(repo, "changelog.d/3-sec.security.md", "- **Sec.** first\n  second line\n")
        self.commit(repo, "add")
        promote(repo)
        self.commit(repo, "release")
        out = self.ok(repo, "--since", old)
        self.assertRegex(out, r"- \*\*Long\.\*\* x+\.\.\.  \[released 1\.3\.0\]\n")
        self.assertIn("- **Sec.** first  [released 1.3.0]\n      second line", out)  # the fragment's own 2 spaces, plus 4

    def test_the_header_counts_breaking_entries_with_the_right_plural(self):
        repo = self.init()
        old = self.seed(repo)
        self.put(repo, "changelog.d/2-a.added.md", "- **Plain.**\n")
        self.commit(repo, "plain")
        self.assertNotIn("Breaking  ", self.ok(repo, "--since", old))
        self.put(repo, "changelog.d/3-b.changed.md", "- **Breaking: one.**\n")
        self.commit(repo, "one")
        out = self.ok(repo, "--since", old)
        self.assertIn("Breaking  1 changelog entry marked **Breaking (listed below)", out)
        self.assertRegex(out, r"Changelog entries added \(2, 1 breaking\)")
        self.put(repo, "changelog.d/4-c.removed.md", "- **breaking, removed.**\n")
        self.commit(repo, "two")
        out = self.ok(repo, "--since", old)
        self.assertIn("Breaking  2 changelog entries marked **Breaking (listed below)", out)
        # The header line comes before the first section, with the other header lines.
        self.assertLess(out.index("Breaking  2"), out.index("Version bumps"))

    def test_versions_prints_bumps_and_image_bumps_but_no_entries(self):
        repo = self.init()
        old = self.seed(repo)
        self.put(repo, "meson.build", MESON_NEW)
        self.put(repo, "deploy/docker/Dockerfile.x", "FROM busybox\n")
        self.commit(repo, "build(deps): bump busybox from `fd7dc98` to `a46257e` in /deploy/docker")
        self.put(repo, ".github/workflows/ci.yml", "a\n")
        self.commit(repo, "build(deps): bump docker/login-action")
        self.put(repo, "changelog.d/2-a.added.md", "- **A pending entry.**\n")
        self.put(repo, "changelog.d/3-b.changed.md", "- **Breaking: pending.**\n")
        self.commit(repo, "fragments")
        out = self.ok(repo, "--since", old, "--versions")
        self.assertIn("Version bumps", out)
        self.assertIn("~ project version (meson.build)", out)
        self.assertIn("Docker image bumps (1)", out)
        self.assertIn("busybox", out)
        self.assertIn("+ 1 other dependency bump (workflows, pip, npm); --full lists them", out)
        self.assertNotIn("Changelog entries added", out)
        self.assertNotIn("A pending entry", out)
        # The count stays in the header, and says where the entries went.
        self.assertIn("Breaking  1 changelog entry marked **Breaking (run without --versions to read them)", out)
        full = self.ok(repo, "--since", old, "--versions", "--full")
        self.assertIn("docker/login-action", full)

    def test_versions_with_nothing_to_show_still_says_so(self):
        repo = self.init()
        old = self.seed(repo)
        self.put(repo, "server/x.cpp", "x\n")
        self.commit(repo, "fix: x")
        out = self.ok(repo, "--since", old, "--versions")
        self.assertIn("none of the tracked versions changed", out)
        self.assertNotIn("Changelog", out)

    def test_release_sections_maps_lines_to_the_heading_above_them(self):
        sections = WN.release_sections(
            "# Changelog\n\n## [Unreleased]\n\n- **Pending.**\n\n## [1.3.0] - 2026-10-30\n\n### Added\n- **New.**\n"
            "- **Twice.**\n\n## [1.2.0] - 2026-09-01\n\n- **Old.**\n- **Twice.**\n")
        self.assertIsNone(sections["- **Pending.**"])
        self.assertEqual(sections["- **New.**"], "1.3.0")
        self.assertEqual(sections["- **Old.**"], "1.2.0")
        self.assertEqual(sections["- **Twice.**"], "")  # under two headings: no version is named
        self.assertEqual(WN.release_sections(None), {})

    def test_versions_is_in_the_help(self):
        res = self.run_script(self.dir, "--help")
        self.assertIn("--versions", res.stdout)

    def test_an_abbreviation_of_a_flag_is_refused(self):
        repo = self.init()
        self.seed(repo)
        for flag in ("--version", "--v", "--ful"):
            res = self.run_script(repo, flag)
            self.assertEqual(res.returncode, 2, flag)
            self.assertIn("unrecognized arguments", res.stderr)


class MarkerAmbiguity(GitCase):
    """A marker never names a version the CHANGELOG cannot support, and a released entry is never read as pending
    for a reason this script can see. Governance round 1 (SG-F1, UP-1, UP-2, UP-3 and their scenarios)."""

    def release_into(self, repo, changelog, old, first_line="- **Shipped thing.**"):
        """Add a fragment, then a release commit that writes `changelog` and removes the fragment."""
        self.put(repo, "changelog.d/2-rel.added.md", first_line + "\n")
        self.commit(repo, "add")
        self.put(repo, "CHANGELOG.md", changelog)
        self.git(repo, "rm", "-qf", "changelog.d/2-rel.added.md")
        self.commit(repo, "release")

    def base(self, name="repo"):
        repo = self.init(name)
        return repo, self.seed(repo)

    def test_a_line_under_two_releases_is_not_given_either_version(self):
        repo, old = self.base()
        log = ("# Changelog\n\n## [Unreleased]\n\n## [1.1.0] - 2026-10-30\n\n- **Shipped thing.**\n\n"
               "## [1.0.0] - 2026-09-01\n\n- **Shipped thing.**\n")
        self.release_into(repo, log, old)
        out = self.ok(repo, "--since", old)
        self.assertIn("- **Shipped thing.**  [released]\n", out)
        self.assertNotIn("[released 1.", out)

    def test_a_line_under_unreleased_and_a_release_is_released_without_a_version(self):
        repo, old = self.base()
        log = "# Changelog\n\n## [Unreleased]\n\n- **Shipped thing.**\n\n## [1.0.0] - 2026-09-01\n\n- **Shipped thing.**\n"
        self.release_into(repo, log, old)
        out = self.ok(repo, "--since", old)
        self.assertIn("- **Shipped thing.**  [released]\n", out)

    def test_a_heading_that_is_not_bracketed_names_no_version(self):
        repo, old = self.base()
        log = "# Changelog\n\n## [1.1.0] - 2026-10-30\n\n- **Other.**\n\n## 1.0.0\n\n- **Shipped thing.**\n"
        self.release_into(repo, log, old)
        out = self.ok(repo, "--since", old)
        self.assertIn("- **Shipped thing.**  [released]\n", out)
        self.assertNotIn("[released 1.1.0]", out)

    def test_a_byte_order_mark_before_the_first_heading_is_ignored(self):
        repo, old = self.base()
        log = "\ufeff## [1.0.0] - 2026-09-01\n\n- **Shipped thing.**\n"
        self.release_into(repo, log, old)
        out = self.ok(repo, "--since", old)
        self.assertIn("- **Shipped thing.**  [released 1.0.0]\n", out)
        self.assertNotIn("\ufeff", out)

    def test_unreleased_in_any_case_or_spacing_is_not_released(self):
        for n, heading in enumerate(("## [UNRELEASED]", "## [ unreleased ]", "## [Unreleased] - TBD")):
            with self.subTest(heading=heading):
                repo, old = self.base(f"repo{n}")
                self.release_into(repo, f"# Changelog\n\n{heading}\n\n- **Shipped thing.**\n", old)
                out = self.ok(repo, "--since", old)
                self.assertIn("Shipped thing", out)
                self.assertNotIn("[released", out)

    def test_a_fragment_still_present_at_head_is_listed_without_a_marker(self):
        repo, old = self.base()
        self.put(repo, "changelog.d/2-rel.added.md", "- **Shipped thing.**\n")
        self.commit(repo, "add")
        self.put(repo, "CHANGELOG.md", "# Changelog\n\n## [1.0.0] - 2026-09-01\n\n- **Shipped thing.**\n")
        self.commit(repo, "release that kept the fragment")
        out = self.ok(repo, "--since", old)
        self.assertIn("- **Shipped thing.**\n", out)
        self.assertNotIn("[released", out)

    def test_changelog_missing_at_head_marks_promoted_entries_without_a_version(self):
        repo, old = self.base()
        self.put(repo, "changelog.d/2-rel.added.md", "- **Shipped thing.**\n")
        self.commit(repo, "add")
        self.put(repo, "CHANGELOG.md", CHANGELOG + "\n## [1.3.0] - 2026-10-30\n\n- **Shipped thing.**\n")
        self.git(repo, "rm", "-qf", "changelog.d/2-rel.added.md")
        self.commit(repo, "release")
        self.git(repo, "rm", "-qf", "CHANGELOG.md")
        self.commit(repo, "delete the changelog")
        res = self.run_script(repo, "--since", old)
        self.assertEqual(res.returncode, 0, res.stderr)
        self.assertIn("- **Shipped thing.**  [released]\n", res.stdout)

    def test_a_hostile_version_heading_is_cut_and_cannot_forge_a_line(self):
        repo, old = self.base()
        name = "1.0.0\x1b[2J\u202e" + "A" * 300_000
        log = f"# Changelog\n\n## [{name}]\n\n" + "- **Shipped thing.**\n"
        self.release_into(repo, log, old)
        out = self.ok(repo, "--since", old)
        tag = [ln for ln in out.splitlines() if "Shipped thing" in ln]
        self.assertEqual(len(tag), 1)
        self.assertLess(len(tag[0]), 120)
        self.assertTrue(tag[0].endswith("...]"), tag[0])
        self.assertNotIn("\x1b", out)
        self.assertNotIn("\u202e", out)

    def test_a_heading_in_any_other_level_one_or_two_form_names_no_version(self):
        for n, heading in enumerate(("##\t[1.0.0]", "  ## [1.0.0]", "# [1.0.0]", "##")):
            with self.subTest(heading=heading):
                repo, old = self.base(f"repo{n}")
                log = f"# Changelog\n\n## [0.9.0] - 2026-08-01\n\n- **Other.**\n\n{heading}\n\n- **Shipped thing.**\n"
                self.release_into(repo, log, old)
                out = self.ok(repo, "--since", old)
                self.assertIn("- **Shipped thing.**  [released]\n", out)
                self.assertNotIn("[released 0.9.0]", out)

    def test_a_comment_line_is_not_a_heading(self):
        """An indented or fenced `# comment` (a shell snippet in the notes) must not end the section above it."""
        for n, body in enumerate(("  # restart the agent\n", "```\n# restart the agent\n```\n", "~~~sh\n## x\n~~~\n")):
            with self.subTest(body=body):
                repo, old = self.base(f"repo{n}")
                log = f"# Changelog\n\n## [Unreleased]\n\n{body}\n- **Pending thing.**\n"
                self.release_into(repo, log, old, first_line="- **Pending thing.**")
                out = self.ok(repo, "--since", old)
                self.assertIn("- **Pending thing.**\n", out)
                self.assertNotIn("[released", out)

    def test_a_bare_heading_in_a_crlf_changelog_names_no_version(self):
        repo, old = self.base()
        log = "# Changelog\r\n\r\n## [0.9.0] - 2026-08-01\r\n\r\n- **Other.**\r\n\r\n##\r\n\r\n- **Shipped thing.**\r\n"
        self.release_into(repo, log, old)
        out = self.ok(repo, "--since", old)
        self.assertIn("- **Shipped thing.**  [released]\n", out)
        self.assertNotIn("[released 0.9.0]", out)

    def test_an_indented_version_heading_is_a_heading_only_up_to_three_spaces(self):
        """Three spaces is still a Markdown heading (the version is unknown); four or a tab is a code block."""
        head = "## [0.9.0]\n- a\n"
        for indent, want in (("  ", ""), ("   ", ""), ("    ", "0.9.0"), ("\t", "0.9.0")):
            with self.subTest(indent=repr(indent)):
                self.assertEqual(WN.release_sections(f"{head}{indent}## [1.0.0]\n- b\n")["- b"], want)

    def test_an_unclosed_or_mismatched_fence_never_names_a_version(self):
        for name, body in (("unclosed", "```\n- fenced\n"),
                           ("inline span", "```code``` text\n- fenced\n"),
                           ("mixed", "```\n~~~\n- fenced\n")):
            with self.subTest(name):
                sections = WN.release_sections(
                    f"## [Unreleased]\n- u\n\n## [2.0]\n{body}\n## [1.0]\n- old\n\n## [Unreleased]\n- later\n")
                self.assertEqual(sections["- old"], "")
                self.assertEqual(sections["- later"], "")

    def test_a_balanced_fence_showing_headings_changes_nothing(self):
        log = ("## [1.0]\n```\n## [9.9]\n## [Unreleased]\n```\n- real1\n\n"
               "## [Unreleased]\n~~~md\n## [1.0]\n~~~\n- pending\n")
        sections = WN.release_sections(log)
        self.assertEqual(sections["- real1"], "1.0")
        self.assertIsNone(sections["- pending"])

    def test_a_tilde_line_does_not_close_a_backtick_fence(self):
        sections = WN.release_sections("## [1.0]\n```\n~~~\n# not a heading\n```\n- after\n")
        self.assertEqual(sections["- after"], "1.0")
        self.assertEqual(sections["# not a heading"], "1.0")

    def test_a_sub_heading_does_not_end_the_section(self):
        repo, old = self.base()
        log = "# Changelog\n\n## [1.0.0] - 2026-09-01\n\n### Added\n\n- **Shipped thing.**\n"
        self.release_into(repo, log, old)
        self.assertIn("- **Shipped thing.**  [released 1.0.0]\n", self.ok(repo, "--since", old))

    def test_a_line_before_any_heading_names_no_version(self):
        repo, old = self.base()
        self.release_into(repo, "- **Shipped thing.**\n\n## [1.0.0] - 2026-09-01\n\n- **Other.**\n", old)
        self.assertIn("- **Shipped thing.**  [released]\n", self.ok(repo, "--since", old))

    def test_the_tag_cut_is_at_forty_characters(self):
        self.assertEqual(WN.tag_for("x" * 40), "  [released " + "x" * 40 + "]")
        self.assertEqual(WN.tag_for("x" * 41), "  [released " + "x" * 37 + "...]")
        self.assertEqual(WN.tag_for(""), "  [released]")

    def test_every_mode_agrees_on_a_compound_changelog(self):
        repo, old = self.base()
        log = ("\ufeff# Changelog\n\n## [Unreleased]\n\n- **Dup.**\n\n## [1.1.0] - 2026-10-30\n\n- **Dup.**\n- **Plain.**\n\n"
               "## 1.0.0\n\n- **Dup.**\n")
        self.put(repo, "changelog.d/2-a.added.md", "- **Dup.**\n")
        self.put(repo, "changelog.d/3-b.added.md", "- **Plain.**\n")
        self.commit(repo, "add")
        self.put(repo, "CHANGELOG.md", log)
        self.git(repo, "rm", "-qf", "changelog.d/2-a.added.md", "changelog.d/3-b.added.md")
        self.commit(repo, "release")
        for flags in ((), ("--full",), ("--versions",), ("--versions", "--full")):
            with self.subTest(flags=flags):
                res = self.run_script(repo, "--since", old, *flags)
                self.assertEqual(res.returncode, 0, res.stderr)
                self.assertNotIn("Traceback", res.stderr)
                if "--versions" not in flags:
                    self.assertIn("- **Dup.**  [released]\n", res.stdout)
                    self.assertIn("- **Plain.**  [released 1.1.0]\n", res.stdout)
                    self.assertNotIn("[released 1.0.0]", res.stdout)


class VersionsModeNotices(GitCase):
    """--versions prints the same `!` notices as the full report, so the Breaking count is never presented as
    complete when a fragment was not read (SG-F1)."""

    def breaking_repo(self):
        repo = self.init()
        old = self.seed(repo)
        self.put(repo, "changelog.d/2-b.changed.md", "- **Breaking: readable.**\n")
        return repo, old

    def check(self, repo, old, needle, commit=True):
        if commit:
            self.commit(repo, "fragments")
        for flags in (("--versions",), ("--versions", "--full"), ()):
            with self.subTest(flags=flags):
                out = self.ok(repo, "--since", old, *flags)
                self.assertIn(needle, out)
                if "--versions" in flags:
                    self.assertIn("Fragments the report could not use, which the Breaking count leaves out", out)
                    self.assertIn("Breaking  1 changelog entry", out)
                    self.assertNotIn("Changelog entries added", out)

    def test_an_oversized_fragment(self):
        repo, old = self.breaking_repo()
        self.put(repo, "changelog.d/3-big.changed.md", "- **Breaking: big.** " + "x" * (2 * 1024 * 1024) + "\n")
        self.check(repo, old, "over 1024 KiB, not read")

    def test_a_misnamed_file(self):
        repo, old = self.breaking_repo()
        self.put(repo, "changelog.d/notes.txt", "x\n")
        self.check(repo, old, "not named like fragments")

    def test_a_fragment_with_no_bullet(self):
        repo, old = self.breaking_repo()
        self.put(repo, "changelog.d/3-none.added.md", "no bullet here\n")
        self.check(repo, old, "with no '- ' bullet")

    def test_a_gitlink_named_like_a_fragment(self):
        repo, old = self.breaking_repo()
        self.git(repo, "add", "-A")
        self.git(repo, "update-index", "--add", "--cacheinfo", f"160000,{'a' * 40},changelog.d/9-sub.fixed.md")
        self.git(repo, "commit", "-q", "-m", "fragments")
        self.check(repo, old, "not regular files (a submodule)", commit=False)

    def test_a_fragment_a_merge_commit_removed_and_reworded(self):
        repo = self.init()
        self.put(repo, "CHANGELOG.md", CHANGELOG)
        self.put(repo, "changelog.d/README.md", "readme\n")
        old = self.commit(repo, "base")
        self.git(repo, "checkout", "-q", "-b", "rel")
        self.put(repo, "x.txt", "x\n")
        self.commit(repo, "rel work")
        self.git(repo, "checkout", "-q", "-b", "next", old)
        self.put(repo, "changelog.d/3-c.fixed.md", "- **Original text.**\n")
        self.put(repo, "changelog.d/4-b.changed.md", "- **Breaking: readable.**\n")
        self.commit(repo, "c")
        self.git(repo, "checkout", "-q", "rel")
        self.git(repo, "merge", "--no-commit", "--no-ff", "next")
        self.put(repo, "CHANGELOG.md", (repo / "CHANGELOG.md").read_text().replace("### Fixed", "### Fixed\n- **Reworded in the merge.**", 1))
        self.git(repo, "rm", "-qf", "changelog.d/3-c.fixed.md")
        self.commit(repo, "merge and reword")
        out = self.ok(repo, "--since", old, "--versions")
        self.assertIn("! 1 fragment removed by a merge commit matched no line added to CHANGELOG.md", out)
        self.assertIn("3-c.fixed.md", out)

    def test_two_kinds_of_notice_keep_their_order_and_follow_a_blank_line(self):
        repo, old = self.breaking_repo()
        self.put(repo, "changelog.d/3-none.added.md", "no bullet here\n")
        self.put(repo, "changelog.d/notes.txt", "x\n")
        self.put(repo, "changelog.d/4-big.changed.md", "- **Breaking: big.** " + "x" * (2 * 1024 * 1024) + "\n")
        self.commit(repo, "fragments")
        self.put(repo, ".github/workflows/ci.yml", "a\n")
        self.commit(repo, "build(deps): bump docker/login-action")
        out = self.ok(repo, "--since", old, "--versions")
        self.assertIn("+ 1 other dependency bump (workflows, pip, npm); --full lists them\n\nFragments the report", out)
        self.assertLess(out.index("with no '- ' bullet"), out.index("not named like fragments"))
        self.assertLess(out.index("not named like fragments"), out.index("over 1024 KiB"))
        self.assertIn("\n\nFragments the report could not use", out)

    def test_no_notice_line_when_everything_was_read(self):
        repo, old = self.breaking_repo()
        self.commit(repo, "fragments")
        out = self.ok(repo, "--since", old, "--versions")
        self.assertNotIn("Fragments the report could not use", out)
        self.assertNotIn("\n! ", out)

    def test_versions_full_names_the_other_dependency_bumps(self):
        repo = self.init()
        old = self.seed(repo)
        self.put(repo, ".github/workflows/ci.yml", "a\n")
        self.commit(repo, "build(deps): bump docker/login-action")
        out = self.ok(repo, "--since", old, "--versions", "--full")
        self.assertIn("Other dependency bumps (1)", out)
        self.assertIn("docker/login-action", out)
        self.assertNotIn("Other dependency bumps", self.ok(repo, "--since", old, "--versions"))
        none = self.init("none")
        old2 = self.seed(none)
        self.put(none, "server/x.cpp", "x\n")
        self.commit(none, "fix: x")
        self.assertNotIn("Other dependency bumps", self.ok(none, "--since", old2, "--versions", "--full"))

    def test_versions_with_a_breaking_entry_and_no_bump_says_both(self):
        repo = self.init()
        old = self.seed(repo)
        self.put(repo, "changelog.d/2-b.changed.md", "- **Breaking: x.**\n")
        self.commit(repo, "fragment")
        out = self.ok(repo, "--since", old, "--versions")
        self.assertIn("(run without --versions to read them)", out)
        self.assertIn("none of the tracked versions changed", out)

    def test_both_heading_suffixes_come_in_the_documented_order(self):
        repo = self.init()
        old = self.seed(repo)
        self.put(repo, "changelog.d/2-rel.changed.md", "- **Breaking: shipped.**\n")
        self.commit(repo, "add")
        promote(repo)
        self.commit(repo, "release")
        self.put(repo, "changelog.d/3-p.added.md", "- **Pending.**\n")
        self.commit(repo, "pending")
        out = self.ok(repo, "--since", old)
        self.assertIn("Changelog entries added (2, 1 already released, 1 breaking)", out)


class RoundEight(GitCase):
    """Merge commits that finish a release, bounded reads, odd repository paths, wording."""

    def three_way(self, repo):
        """base -> `side` (one unrelated commit) and dev (the caller's commits), returning the base."""
        old = self.seed(repo)
        self.git(repo, "checkout", "-q", "-b", "side")
        self.put(repo, "side.txt", "s\n")
        self.commit(repo, "side")
        self.git(repo, "checkout", "-q", "dev")
        return old

    def test_a_fragment_removed_only_by_a_merge_commit_is_still_listed(self):
        repo = self.init()
        self.put(repo, "CHANGELOG.md", CHANGELOG)
        self.put(repo, "changelog.d/README.md", "readme\n")
        old = self.commit(repo, "base")
        self.git(repo, "checkout", "-q", "-b", "rel")
        self.put(repo, "changelog.d/10-a.fixed.md", "- **Release fix A.**\n")
        self.commit(repo, "a")
        promote(repo)
        self.commit(repo, "release prep")
        self.git(repo, "checkout", "-q", "-b", "next", old)
        self.put(repo, "changelog.d/11-b.fixed.md", "- **Merge-only fix B.**\n")
        self.commit(repo, "b")
        self.git(repo, "checkout", "-q", "rel")
        # The release branch takes dev in, adds the entry to its section by hand and removes the fragment.
        self.git(repo, "merge", "--no-ff", "--no-commit", "next")
        text = (repo / "CHANGELOG.md").read_text()
        self.put(repo, "CHANGELOG.md", text.replace("- **Release fix A.**", "- **Release fix A.**\n- **Merge-only fix B.**"))
        self.git(repo, "rm", "-qf", "changelog.d/11-b.fixed.md")
        self.commit(repo, "merge next into the release branch and re-promote")
        out = self.ok(repo, "--since", old)
        self.assertIn("Release fix A", out)
        self.assertIn("Merge-only fix B", out)
        self.assertRegex(out, r"Changelog entries added \(2[,)]")

    def test_a_fragment_reworded_before_a_merge_commit_release_is_listed_with_the_promoted_wording(self):
        repo = self.init()
        self.put(repo, "CHANGELOG.md", CHANGELOG)
        self.put(repo, "changelog.d/README.md", "readme\n")
        old = self.commit(repo, "base")
        self.put(repo, "changelog.d/1-a.changed.md", "- **Breaking: rename.** first wording\n")
        self.put(repo, "changelog.d/2-b.fixed.md", "- **Sibling fix.**\n")
        self.commit(repo, "add")
        self.git(repo, "checkout", "-q", "-b", "rel", old)
        self.put(repo, "x.txt", "x\n")
        self.commit(repo, "rel work")
        self.git(repo, "checkout", "-q", "dev")
        self.put(repo, "changelog.d/1-a.changed.md", "- **Breaking: rename.** corrected wording\n")
        self.commit(repo, "reword")
        self.git(repo, "checkout", "-q", "rel")
        self.git(repo, "merge", "--no-commit", "--no-ff", "dev")
        promote(repo)
        self.commit(repo, "merge dev and promote")
        out = self.ok(repo, "--since", old)
        self.assertIn("corrected wording", out)
        self.assertNotIn("first wording", out)
        self.assertIn("Sibling fix", out)

    def test_a_fragment_a_merge_commit_removed_and_reworded_in_the_merge_is_named(self):
        repo = self.init()
        self.put(repo, "CHANGELOG.md", CHANGELOG)
        self.put(repo, "changelog.d/README.md", "readme\n")
        old = self.commit(repo, "base")
        self.git(repo, "checkout", "-q", "-b", "rel")
        self.put(repo, "x.txt", "x\n")
        self.commit(repo, "rel work")
        self.git(repo, "checkout", "-q", "-b", "next", old)
        self.put(repo, "changelog.d/3-c.fixed.md", "- **Original text.**\n")
        self.commit(repo, "c")
        self.git(repo, "checkout", "-q", "rel")
        self.git(repo, "merge", "--no-commit", "--no-ff", "next")
        self.put(repo, "CHANGELOG.md", (repo / "CHANGELOG.md").read_text().replace("### Fixed", "### Fixed\n- **Reworded in the merge.**", 1))
        self.git(repo, "rm", "-qf", "changelog.d/3-c.fixed.md")
        self.commit(repo, "merge and reword")
        out = self.ok(repo, "--since", old)
        self.assertIn("! 1 fragment removed by a merge commit matched no line added to CHANGELOG.md", out)
        self.assertIn("3-c.fixed.md", out)

    def test_a_merge_that_pairs_a_deletion_with_an_identical_new_file_does_not_hide_the_new_file(self):
        repo = self.init()
        old = self.three_way(repo)
        self.git(repo, "rm", "-q", "changelog.d/1-old.added.md")
        self.commit(repo, "drop it")
        self.put(repo, "changelog.d/2-q.added.md", "- **Already there.**\n")
        self.commit(repo, "the same text under a new name")
        self.git(repo, "merge", "-q", "--no-ff", "-m", "merge side", "side")
        out = self.ok(repo, "--since", old)
        self.assertRegex(out, r"Changelog entries added \(1[,)]")
        self.assertIn("Already there", out)

    def test_a_file_replacing_a_gitlink_under_a_fragment_name_is_listed(self):
        repo = self.init()
        self.seed(repo)
        self.git(repo, "update-index", "--add", "--cacheinfo", f"160000,{'a' * 40},changelog.d/9-sub.fixed.md")
        self.clock += 1
        self.env["GIT_AUTHOR_DATE"] = self.env["GIT_COMMITTER_DATE"] = f"2026-10-{self.clock:02d}T12:00:00+0000"
        self.git(repo, "commit", "-q", "-m", "a gitlink")
        old = self.git(repo, "rev-parse", "HEAD")
        self.put(repo, "changelog.d/9-sub.fixed.md", "- **Now a file.**\n")
        self.commit(repo, "a file instead")
        self.assertIn("Now a file", self.ok(repo, "--since", old))

    @unittest.skipUnless(os.name == "posix", "a trailing space in a directory name")
    def test_a_repository_whose_directory_name_ends_in_a_space_is_not_confused_with_its_sibling(self):
        mine, other = self.init("proj"), self.init("proj ")
        for repo, text in ((mine, "- **Sibling entry.**\n"), (other, "- **Spacey entry.**\n")):
            old = self.seed(repo)
            self.put(repo, "changelog.d/2-n.added.md", text)
            self.commit(repo, "add")
            if repo is other:
                out = self.ok(repo, "--since", old)
        self.assertIn("Spacey entry", out)
        self.assertNotIn("Sibling entry", out)

    @unittest.skipUnless(os.name == "posix", "a directory name that is not UTF-8")
    def test_a_repository_path_that_is_not_utf8_still_works(self):
        try:
            repo = self.init(os.fsdecode(b"p\xff"))
        except (OSError, UnicodeError):
            self.skipTest("this file system does not take a non-UTF-8 name")
        old = self.seed(repo)
        self.put(repo, "changelog.d/2-n.added.md", "- **In an odd place.**\n")
        self.commit(repo, "add")
        self.assertIn("In an odd place", self.ok(repo, "--since", old))

    def test_a_huge_fragment_is_named_not_read_and_the_others_are_listed(self):
        repo = self.init()
        old = self.seed(repo)
        self.put(repo, "changelog.d/2-big.added.md", "- **Big.**\n" + "x" * (WN.MAX_FRAGMENT_BYTES + 1))
        self.put(repo, "changelog.d/3-ok.fixed.md", "- **Fine.**\n")
        self.commit(repo, "add")
        out = self.ok(repo, "--since", old)
        self.assertIn("Fine", out)
        self.assertNotIn("Big.", out)
        self.assertIn("! 1 fragment file over 1024 KiB, not read: changelog.d/2-big.added.md", out.replace("changelog.d/2-big", "changelog.d/2-big"))

    def test_the_same_object_under_many_specs_is_read_once(self):
        repo = self.init()
        self.seed(repo)
        self.put(repo, "changelog.d/2-a.fixed.md", "- **Same.**\n")
        self.put(repo, "changelog.d/3-b.fixed.md", "- **Same.**\n")
        self.commit(repo, "two copies")
        calls = []
        real = WN.Repo._run

        def spy(self_, *args, **kw):
            calls.append(args[:2])
            return real(self_, *args, **kw)

        WN.Repo._run = spy
        try:
            got = WN.Repo(repo).blobs(["HEAD:changelog.d/2-a.fixed.md", "HEAD:changelog.d/3-b.fixed.md"])
        finally:
            WN.Repo._run = real
        self.assertEqual(list(got.values()), ["- **Same.**\n"] * 2)
        batch = [c for c in calls if c == ("cat-file", "--batch")]
        self.assertEqual(len(batch), 1)

    def test_a_flood_of_odd_names_is_cut_on_the_line(self):
        repo = self.init()
        old = self.seed(repo)
        for i in range(25):
            self.put(repo, f"changelog.d/sub/f{i:02d}.md", "x\n")
        self.commit(repo, "many")
        out = self.ok(repo, "--since", old)
        self.assertIn("! 25 files added under changelog.d/", out)
        self.assertIn(", and 5 more", out)
        self.assertNotIn("f24.md", out)

    def test_only_odd_names_or_only_gitlinks_say_so_instead_of_claiming_nothing_was_added(self):
        repo = self.init()
        old = self.seed(repo)
        self.put(repo, "changelog.d/sub/x.md", "x\n")
        self.commit(repo, "odd")
        out = self.ok(repo, "--since", old)
        self.assertIn("No changelog entries could be listed", out)
        self.assertNotIn("No changelog fragments were added", out)
        repo2 = self.init("r2")
        old2 = self.seed(repo2)
        self.git(repo2, "update-index", "--add", "--cacheinfo", f"160000,{'a' * 40},changelog.d/9-sub.fixed.md")
        self.git(repo2, "commit", "-q", "-m", "gitlink")
        out2 = self.ok(repo2, "--since", old2)
        self.assertIn("No changelog entries could be listed", out2)
        self.assertIn("! 1 path named like fragments but not regular files", out2)

    def test_singular_forms(self):
        repo = self.init()
        old = self.seed(repo)
        self.put(repo, "proto/a.proto", "x\n")
        self.put(repo, "sdk/a.h", "x\n")
        self.put(repo, "gateway/a.erl", "x\n")
        self.put(repo, ".github/workflows/ci.yml", "x\n")
        self.commit(repo, "chore(deps): bump actions/foo from 1 to 2")
        out = self.ok(repo, "--since", old)
        self.assertIn("(1 file)", out)
        self.assertIn("+ 1 other bump (", out)
        self.assertNotIn("1 other bumps", out)
        self.assertNotIn("1 files", out)

    def test_a_range_of_only_empty_commits_has_no_empty_parentheses(self):
        repo = self.init()
        old = self.seed(repo)
        self.git(repo, "commit", "-q", "--allow-empty", "-m", "nothing")
        out = self.ok(repo, "--since", old)
        self.assertIn("1 commit, 0 files\n", out)
        self.assertNotIn("()", out)

    def test_an_empty_repository_says_so(self):
        repo = self.init()
        res = self.run_script(repo, "--since", "HEAD")
        self.assertEqual(res.returncode, 2)
        self.assertIn("no commits", res.stderr)
        self.assertNotIn("fatal", res.stderr)

    def test_since_head_names_the_real_reason(self):
        repo = self.init()
        self.seed(repo)
        res = self.run_script(repo, "--since", "HEAD")
        self.assertEqual(res.returncode, 2)
        self.assertIn("HEAD is HEAD itself, so there is nothing to compare", res.stderr)
        self.assertNotIn("HEAD: HEAD", res.stderr)

    def test_the_date_error_says_the_unit_is_lowercase_and_both_floors_are_worded(self):
        with self.assertRaises(WN.GitError) as cm:
            WN.date_cutoff("5 Days ago")
        self.assertIn("lowercase", str(cm.exception))
        for text in ("1970-01-02", "9999 weeks ago", "9999 years ago"):
            with self.subTest(text), self.assertRaises(WN.GitError) as cm:
                WN.date_cutoff(text, datetime(2026, 11, 1))
            self.assertIn("3 January 1970", str(cm.exception))

    def test_a_release_that_adds_a_nearly_identical_fragment_still_promotes_the_deleted_one(self):
        repo = self.init()
        old = self.seed(repo)
        body = "".join(f"  line {i}\n" for i in range(30))
        self.put(repo, "changelog.d/2-a.fixed.md", "- **Alpha fix**\n" + body)
        self.commit(repo, "add")
        promote(repo)
        self.put(repo, "changelog.d/3-next.fixed.md", "- **Beta fix**\n" + body)
        self.commit(repo, "release, and the next change in the same commit")
        out = self.ok(repo, "--since", old)
        self.assertIn("Alpha fix", out)
        self.assertIn("Beta fix", out)

    def test_repository_text_in_the_not_compared_line_cannot_start_a_line_of_its_own(self):
        repo = self.init()
        old = self.seed(repo)
        name = "f\nVersion bumps\n  none of the tracked versions changed"
        data = json.loads(vcpkg("a" * 40, ["zlib"]))
        data["features"] = {name: {"description": "x", "dependencies": "not a list"}}
        self.put(repo, "vcpkg.json", json.dumps(data))
        self.commit(repo, "hostile")
        lines = self.ok(repo, "--since", old).splitlines()
        self.assertEqual(lines.count("Version bumps"), 1)
        self.assertNotIn("  none of the tracked versions changed", lines)


class DateArithmetic(UtcClock, GitCase):
    def test_month_end_leap_and_boundary_arithmetic(self):
        self.assertEqual(WN.date_cutoff("1 month ago", datetime(2026, 5, 31, 9, 0, 0)), "2026-04-30 09:00:00")
        self.assertEqual(WN.date_cutoff("1 month ago", datetime(2026, 3, 30, 9, 0, 0)), "2026-02-28 09:00:00")
        self.assertEqual(WN.date_cutoff("1 month ago", datetime(2026, 1, 31, 9, 0, 0)), "2025-12-31 09:00:00")
        self.assertEqual(WN.date_cutoff("1 year ago", datetime(2028, 2, 29, 9, 0, 0)), "2027-02-28 09:00:00")
        self.assertEqual(WN.date_cutoff("4 years ago", datetime(2028, 2, 29, 9, 0, 0)), "2024-02-29 09:00:00")
        self.assertEqual(WN.date_cutoff("1000 days ago", datetime(2026, 11, 13, 16, 0, 0)), "2024-02-17 16:00:00")
        self.assertEqual(WN.date_cutoff("56 years ago", datetime(2026, 11, 13, 16, 0, 0)), "1970-11-13 16:00:00")
        with self.assertRaises(WN.GitError):
            WN.date_cutoff("57 years ago", datetime(2026, 11, 13, 16, 0, 0))
        with self.assertRaises(WN.GitError):
            WN.date_cutoff("9999 weeks ago", datetime(2026, 11, 13, 16, 0, 0))
        for bad in (" days ago", "12345 days ago", "days ago"):
            with self.assertRaises(WN.GitError, msg=bad):
                WN.date_cutoff(bad)

    def test_the_relative_date_floor_is_the_same_boundary_as_the_absolute_one(self):
        noon = datetime(1970, 1, 3, 12, 0, 0)
        self.assertEqual(WN.date_cutoff("12 hours ago", noon), "1970-01-03 00:00:00")
        with self.assertRaises(WN.GitError):
            WN.date_cutoff("13 hours ago", noon)

    def test_absolute_years_outside_1970_to_2099_are_refused(self):
        for bad in ("2100-01-01", "9999-12-31", "1969-12-31", "0001-01-01"):
            with self.assertRaises(WN.GitError, msg=bad):
                WN.date_cutoff(bad)
        self.assertEqual(WN.date_cutoff("2099-12-31"), "2099-12-31 00:00:00")
        self.assertEqual(WN.date_cutoff("1970-01-03"), "1970-01-03 00:00:00")
        # East of UTC git can read a moment on 1 January 1970 (a negative timestamp) as "now"; the floor is two days later.
        for early in ("1970-01-01", "1970-01-02 23:59", "1970-01-01T00:00:00"):
            with self.assertRaises(WN.GitError, msg=early):
                WN.date_cutoff(early)

    def test_a_relative_date_before_the_epoch_is_a_clean_error_even_if_the_os_cannot_convert_it(self):
        class Boom(datetime):
            def astimezone(self, *a):
                raise OSError("Invalid argument")  # what Windows raises for a pre-1970 local time
        with self.assertRaises(WN.GitError):
            WN.date_cutoff("3000 weeks ago", Boom(2026, 11, 13, 16, 0, 0))


class DateDaylightSaving(GitCase):
    @unittest.skipUnless(hasattr(__import__("time"), "tzset"), "needs time.tzset")
    def test_a_duration_across_a_daylight_saving_change_is_absolute(self):
        import time
        old_tz = os.environ.get("TZ")
        os.environ["TZ"] = "America/New_York"
        time.tzset()
        try:
            if time.strftime("%Z", time.localtime(1780000000)) not in ("EDT", "EST"):
                self.skipTest("no time zone database for America/New_York")
            # 2026-03-08 10:00 EDT is 8 elapsed hours after 2026-03-08 01:00 EST (the clocks jumped 02:00 -> 03:00),
            # so ten hours before it is 23:00 EST on the 7th.
            self.assertEqual(WN.date_cutoff("10 hours ago", datetime(2026, 3, 8, 10, 0, 0)), "2026-03-07 23:00:00")
            # A day is 24 hours, as git counts it: 10:00 EDT on the 8th is 09:00 EST on the 7th.
            self.assertEqual(WN.date_cutoff("1 day ago", datetime(2026, 3, 8, 10, 0, 0)), "2026-03-07 09:00:00")
        finally:
            if old_tz is None:
                os.environ.pop("TZ", None)
            else:
                os.environ["TZ"] = old_tz
            time.tzset()


if __name__ == "__main__":
    unittest.main()
