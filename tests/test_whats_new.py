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
import subprocess
import sys
import tempfile
import unittest
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
            **os.environ,
            "GIT_CONFIG_GLOBAL": os.devnull, "GIT_CONFIG_SYSTEM": os.devnull, "GIT_CONFIG_NOSYSTEM": "1",
            "TZ": "UTC",
            # Never discover a repository above the temp directory (TMPDIR may sit inside one).
            "GIT_CEILING_DIRECTORIES": str(Path(self.tmp.name).parent),
            "GIT_AUTHOR_NAME": "t", "GIT_AUTHOR_EMAIL": "t@example.invalid",
            "GIT_COMMITTER_NAME": "t", "GIT_COMMITTER_EMAIL": "t@example.invalid",
        }
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
                              env=env or self.env, capture_output=True, text=True)

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
        self.assertIn("! vcpkg not compared: vcpkg.json is not valid JSON", out)
        self.assertIn("! rebar_lock not compared", out)
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
                     "deploy/compose files changed (1 files)", "with --wipe"):
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
        self.assertIn("Changelog entries added (6)", out)
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
        self.assertIn("! 1 fragment(s) had no '- ' bullet and are not summarised: 2-prose.added.md", out)
        self.assertIn("Changelog entries added (1)", out)

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
        for name in ("1-a.added.md", "a.b-c_d.fixed.md", "A9.security.md", ".x.added.md", "a b.added.md",
                     "README.md", "x.bogus.md", "-a.added.md", "a.added.txt", "_a.added.md"):
            self.assertEqual(bool(WN.FRAGMENT_RE.match(name)), bool(assemble.FRAGMENT_NAME_RE.match(name)), name)


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
        self.assertIn("Changelog entries added (1)", out)

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
        self.assertIn("Changelog entries added (1)", out)
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
        self.assertIn("  ! vcpkg not compared: nested too deeply", lines)

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
        self.assertIn("1 commits, 1 files ((root) 1)", out[0])
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


class PullArguments(GitCase):
    def reflog_repo(self, *lines, remote="origin", merge="refs/heads/dev", upstream="origin/dev"):
        shas = ["%040x" % (i + 1) for i in range(len(lines))]
        reflog = "".join(f"{sha}\t{subject}\n" for sha, subject in zip(shas, lines))

        class R(FakeRepo):
            def _run(self, *args, **kw):
                out = {"symbolic-ref": "refs/heads/dev\n", "rev-parse": upstream + "\n", "reflog": reflog}.get(args[0], "")
                if args[0] == "config":
                    out = {"branch.dev.remote": remote, "branch.dev.merge": merge}.get(args[1], "") + "\n"
                return subprocess.CompletedProcess(args, 0, out, "")
        return R(), shas

    def base_for(self, subject, **kw):
        repo, shas = self.reflog_repo(subject, "clone: from x", **kw)
        try:
            return WN.last_pull_base(repo)[0] == shas[1]
        except WN.GitError:
            return None

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
        old = self.commit(repo, "base", date="2026-10-20T12:00:00+0000") if False else self.git(repo, "rev-parse", "HEAD")
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
        self.assertIn("Changelog entries added (4)", out)

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
        got = r.blobs([f"{sha}:meson.build", f"{sha}:nope.txt", f"{sha}:changelog.d/README.md"])
        self.assertEqual(got[f"{sha}:nope.txt"], None)
        self.assertEqual(got[f"{sha}:changelog.d/README.md"], "readme\n")
        self.assertIn("project('yuzu'", got[f"{sha}:meson.build"])
        self.assertIsNone(r.show(sha, "nope.txt"))
        self.assertEqual(r.blobs([]), {})

    def test_an_unexpected_cat_file_reply_is_an_error(self):
        class R(FakeRepo):
            def _run(self, *args, **kw):
                return subprocess.CompletedProcess(args, 0, b"abc ambiguous\n", b"")
        with self.assertRaises(WN.GitError):
            R().blobs(["abc:x"])

    def test_show_reports_a_real_read_failure(self):
        with self.assertRaises(WN.GitError):  # not a repository: git fails for a reason other than an absent path
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
                  0x17b5, 0x180b, 0x180d, 0x180e, 0x200b, 0x200f, 0x2028, 0x2029, 0x202a, 0x202e, 0x2060, 0x2064,
                  0x2066, 0x2069, 0x206a, 0x2800, 0x3164, 0xd800, 0xfe00, 0xfe0f, 0xfeff, 0xffa0,
                  0xfff9, 0xfffb, 0xfffc, 0xe0000, 0xe0001, 0xe007f, 0xe0100, 0xe01ef]
        outside = [0x09, 0x0a, 0x20, 0x7e, 0xa0, 0xa1, 0x34e, 0x350, 0x61b, 0x61d, 0x180f, 0x200a, 0x2010, 0x2027,
                   0x202f, 0x205f, 0x2065, 0x27ff, 0x2801, 0x3163, 0x3165, 0xfdff, 0xfe10, 0xfefe, 0xff00, 0xff9f,
                   0xfff8, 0xfffd, 0xdffff, 0xe0080, 0xe00ff, 0xe01f0, 0x41, 0xe9, 0x4e2d]
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


class RoundFourPulls(PullArguments):
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


class RoundFourFragments(GitCase):
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
        self.assertIn("Changelog entries added (1)", out)
        self.assertIn("but this one is new and longer", out)

    def test_an_unchanged_rename_is_not_new_but_an_edited_one_is(self):
        repo = self.init()
        old = self.seed(repo)
        self.git(repo, "mv", "changelog.d/1-old.added.md", "changelog.d/2-moved.added.md")
        self.commit(repo, "move unchanged")
        self.assertNotIn("Already there", self.ok(repo, "--since", old))

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
        self.put(repo, "x.txt", "x\n")
        self.git(repo, "add", "-A")
        subprocess.run(["git", "-c", "commit.gpgsign=false", "-c", "i18n.commitEncoding=ISO-8859-1", "commit", "-q",
                        "-F", "-"], cwd=repo, env=self.env, input="build(deps): bump caf\xe9\n".encode("latin-1"),
                       check=True, capture_output=True)
        res = self.run_script(repo, "--since", old)
        self.assertEqual(res.returncode, 0, res.stderr)
        self.assertNotIn("Traceback", res.stderr)

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


class RoundFourDates(UtcClock, GitCase):
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

    def test_absolute_years_outside_1970_to_2099_are_refused(self):
        for bad in ("2100-01-01", "9999-12-31", "1969-12-31", "0001-01-01"):
            with self.assertRaises(WN.GitError, msg=bad):
                WN.date_cutoff(bad)
        self.assertEqual(WN.date_cutoff("2099-12-31"), "2099-12-31 00:00:00")
        self.assertEqual(WN.date_cutoff("1970-01-01"), "1970-01-01 00:00:00")


class RoundFourDst(GitCase):
    @unittest.skipUnless(hasattr(__import__("time"), "tzset"), "needs time.tzset")
    def test_a_duration_across_a_daylight_saving_change_is_absolute(self):
        import time
        old_tz = os.environ.get("TZ")
        os.environ["TZ"] = "America/New_York"
        time.tzset()
        try:
            # 2026-03-08 10:00 EDT is 9 real hours after 2026-03-08 01:00 EST... clocks jumped 02:00 -> 03:00.
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
