#!/usr/bin/env python3
"""The legacy `quarantine` agent plugin is gone, and no trace of it returns.

Device containment is the firewall plugin's four actions (quarantine, release,
quarantine_status, quarantine_allow). The old plugin's sources, its build and
packaging wiring, its tests and scripts, its definition ids, its sink-manifest
rows and every doc that described it were removed together. This gate pins that
removal lexically: no tracked file outside the history allowlist may name the
old plugin's files, actions, rule or chain prefixes, definition ids or the
plugin itself.

It is a source-text check (no build, no network). Files are enumerated with
`git ls-files`, falling back to a directory walk that skips build and vendored
trees when git is unavailable (precedent: test_docker_context_embeds_lexical.py).

The PATTERNS list is the one source of truth: the `git grep` in the PRQ.2 plan's
verification step is a copy of it, and the self-test below proves each pattern
fires on a mutated sample and that the two anchored patterns stay quiet on the
firewall plugin's own names.
"""
import os
import re
import subprocess
import unittest

REPO = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..")
THIS = "tests/test_legacy_quarantine_plugin_removed_lexical.py"

# A name character: a pattern anchored with this must not fire inside a longer identifier
# (firewall_quarantine_parsers.hpp, rig.quarantine.quarantine_device).
NC = r"[A-Za-z0-9_]"

PATTERNS = [
    r"agents/plugins/quarantine",
    r"(?<!" + NC + r")quarantine_(?:plugin|parsers)\.(?:cpp|hpp)",
    r"quarantine_serialization",
    r"test_quarantine_(?:parsers|argv)",
    r"unquarantine",
    r"whitelist_ips",
    # The two refusal tokens the plugin's guard used; narrower than the bare prefix so this test's
    # own registered file name (test_legacy_quarantine_plugin_removed_lexical.py) is not a hit.
    r"legacy_quarantine_(?:active|rules_present)",
    r"YuzuQuarantine_",
    r"yuzu-quarantine",
    r"security\.quarantine\.",
    r"(?<!" + NC + r")quarantine\.(?:quarantine|status|whitelist)(?!" + NC + r")",
    r"quarantine`? (?:agent )?plugin",
    r"\"quarantine\", *\"(?:quarantine|status|whitelist)\"",
    r"plugin *= *\"quarantine\"",
    r"plugin=quarantine",
]
COMPILED = [re.compile(p) for p in PATTERNS]

# History: records of what shipped, which keep naming the removed plugin.
ALLOW_PREFIXES = (
    "changelog.d/",
    "governance.d/",
    "docs/adr/",
    "docs/reviews/",
    "docs/security-reviews/",
    "docs/plans/",
)
ALLOW_FILES = {
    "CHANGELOG.md",
    "docs/roadmap.md",
    # The whole file: its new section names what was removed, and its older sections are history.
    "docs/user-manual/upgrading.md",
    # Records the v0.14.1 release's plugin list (its `source` field).
    "deploy/packaging/linux-floor-baseline.json",
    THIS,
}

SKIP_DIRS = {".git", "build", "vcpkg_installed", "node_modules", "_build", ".claude/worktrees"}


def allowlisted(rel):
    return rel in ALLOW_FILES or rel.startswith(ALLOW_PREFIXES)


def hits_in(text):
    """Pattern strings that fire anywhere in `text` (line by line, as `git grep` does)."""
    found = []
    for line in text.splitlines():
        for pat, rx in zip(PATTERNS, COMPILED):
            if rx.search(line):
                found.append(pat)
    return found


def tracked_files():
    try:
        out = subprocess.run(
            # --others so a file not yet added is scanned too (in CI every file is tracked).
            ["git", "-C", REPO, "ls-files", "-z", "--cached", "--others", "--exclude-standard"],
            capture_output=True, check=True, timeout=120,
        ).stdout
        return [p for p in out.decode("utf-8", "replace").split("\0") if p]
    except (OSError, subprocess.SubprocessError):
        pass
    # No git: walk the tree, skipping build and vendored directories.
    files = []
    for root, dirs, names in os.walk(REPO):
        rel_root = os.path.relpath(root, REPO).replace(os.sep, "/")
        dirs[:] = [d for d in dirs
                   if d not in SKIP_DIRS and not d.startswith("build-")
                   and (rel_root + "/" + d).lstrip("./") not in SKIP_DIRS]
        for n in names:
            files.append(os.path.normpath(os.path.join(rel_root, n)).replace(os.sep, "/"))
    return files


def read_text(rel):
    path = os.path.join(REPO, rel)
    try:
        with open(path, "rb") as f:
            raw = f.read()
    except OSError:
        return None  # listed but gone (a deleted file still in the index), or unreadable
    if b"\0" in raw[:8192]:
        return None  # binary
    return raw.decode("utf-8", "replace")


class LegacyQuarantinePluginRemoved(unittest.TestCase):
    def test_the_plugin_and_its_definition_file_do_not_exist(self):
        for rel in ("agents/plugins/quarantine", "content/definitions/quarantine.yaml",
                    "content/plugin-docs/quarantine.json"):
            self.assertFalse(os.path.exists(os.path.join(REPO, rel)), rel + " must not exist")

    def test_no_tracked_file_outside_history_names_the_removed_plugin(self):
        offenders = {}
        for rel in tracked_files():
            if allowlisted(rel):
                continue
            text = read_text(rel)
            if text is None:
                continue
            fired = sorted(set(hits_in(text)))
            if fired:
                offenders[rel] = fired
        self.assertEqual(
            offenders, {},
            "the legacy quarantine plugin is removed; these files still name it (remove the "
            "reference, or name the firewall plugin's action instead):\n"
            + "\n".join("  %s: %s" % (k, ", ".join(v)) for k, v in sorted(offenders.items())))

    def test_the_agent_sudoers_grants_no_bare_pfctl_and_no_iptables_save_or_restore(self):
        text = read_text("scripts/install-agent-user.sh")
        self.assertIsNotNone(text)
        grants = [l.strip() for l in text.splitlines() if "NOPASSWD:" in l and not l.lstrip().startswith("#")]
        bare_pfctl = [g for g in grants if re.search(r"NOPASSWD:\s*/sbin/pfctl\s*$", g)]
        self.assertEqual(bare_pfctl, [], "a bare /sbin/pfctl grant would make the narrowed pf lines cosmetic")
        helpers = [g for g in grants if re.search(r"(?:ip6?tables)-(?:save|restore)", g)]
        self.assertEqual(helpers, [], "no caller of iptables-save/-restore remains; do not grant them")
        # The firewall plugin's iptables fallback still needs the two bare tools.
        self.assertTrue(any(re.search(r"NOPASSWD:\s*/usr/sbin/iptables\s*$", g) for g in grants))
        self.assertTrue(any(re.search(r"NOPASSWD:\s*/usr/sbin/ip6tables\s*$", g) for g in grants))


class PatternSelfTest(unittest.TestCase):
    """Each pattern fires on a mutated sample; the anchored ones stay quiet on firewall names."""

    SAMPLES = {
        r"agents/plugins/quarantine": "include_directories('../agents/plugins/quarantine/src')",
        r"(?<!" + NC + r")quarantine_(?:plugin|parsers)\.(?:cpp|hpp)": "see quarantine_plugin.cpp:58",
        r"quarantine_serialization": "#include \"quarantine_serialization.hpp\"",
        r"test_quarantine_(?:parsers|argv)": "tests/unit/test_quarantine_parsers.cpp",
        r"unquarantine": "run the unquarantine action",
        r"whitelist_ips": "params[\"whitelist_ips\"]",
        r"legacy_quarantine_(?:active|rules_present)": "refused|legacy_quarantine_active",
        r"YuzuQuarantine_": "netsh name YuzuQuarantine_allow_1",
        r"yuzu-quarantine": "-N yuzu-quarantine",
        r"security\.quarantine\.": "security.quarantine.isolate",
        r"(?<!" + NC + r")quarantine\.(?:quarantine|status|whitelist)(?!" + NC + r")":
            "dispatch quarantine.status now",
        r"quarantine`? (?:agent )?plugin": "the `quarantine` plugin",
        r"\"quarantine\", *\"(?:quarantine|status|whitelist)\"": "{\"quarantine\", \"status\"}",
        r"plugin *= *\"quarantine\"": ".plugin = \"quarantine\",",
        r"plugin=quarantine": "?plugin=quarantine",
    }

    def test_every_pattern_has_a_sample_and_fires_on_it(self):
        self.assertEqual(set(self.SAMPLES), set(PATTERNS), "a pattern without a self-test sample")
        for pat, sample in self.SAMPLES.items():
            self.assertIn(pat, hits_in(sample), "pattern does not fire on its own sample: " + pat)

    def test_anchored_patterns_stay_quiet_on_the_firewall_plugins_names(self):
        for quiet in ("agents/plugins/firewall/src/firewall_quarantine_parsers.hpp",
                      "tests/unit/test_firewall_quarantine_parsers.cpp",
                      "rig.quarantine.quarantine_device",
                      "firewall.quarantine and firewall.quarantine_status",
                      "{\"firewall\", \"quarantine_status\"}",
                      "security.firewall.quarantine"):
            self.assertEqual(hits_in(quiet), [], "false positive on: " + quiet)
        # ...and the test's own registered file name is not a hit either.
        self.assertEqual(hits_in("files('test_legacy_quarantine_plugin_removed_lexical.py')"), [])

    def test_the_allowlist_suppresses_a_history_path_and_nothing_else(self):
        for rel in ("changelog.d/2026-11-11-firewall-only-containment.removed.md",
                    "docs/adr/0047-quarantine-store-postgres-migration.md",
                    "docs/user-manual/upgrading.md", "CHANGELOG.md", THIS,
                    "deploy/packaging/linux-floor-baseline.json"):
            self.assertTrue(allowlisted(rel), rel)
        for rel in ("docs/user-manual/security-hardening.md", "server/core/src/rest_api_v1.cpp",
                    "docs/capability-map.md", "docs/roadmap-extra.md"):
            self.assertFalse(allowlisted(rel), rel)


if __name__ == "__main__":
    unittest.main()
