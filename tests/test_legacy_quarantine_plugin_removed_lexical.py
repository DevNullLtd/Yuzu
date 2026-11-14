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
    # Records the v0.14.1 release's plugin list (its `source` field).
    "deploy/packaging/linux-floor-baseline.json",
    THIS,
}

# Files where only NAMED sections are history (#7588d). upgrading.md used to be exempt as a whole
# file, which let any new text in it name the removed plugin. Now its nine sections that do name it
# today are exempt (the new section naming what was removed, and the older sections that are
# history); a line under any other `## ` heading, or before the first one, is scanned like any
# other file. A heading is matched by its leading text, so an edit to the end of a title does not
# silently drop the exemption.
ALLOW_SECTIONS = {
    "docs/user-manual/upgrading.md": (
        "## \u26a0\ufe0f Breaking: device containment is the firewall plugin's four actions",
        "## \u26a0\ufe0f Breaking: `POST` and `DELETE /api/v1/quarantine` now apply the dispatch approval check",
        "## Behaviour change: web UI wording and layout",
        "## Behaviour change: protective actions exempt from plugin enablement",
        "## Behaviour change: Destructive-class dispatch now requires explicit `agent_ids`",
        "## \u26a0\ufe0f Behaviour change: quarantine containment now covers IPv6, and reports honestly",
        "## \u26a0\ufe0f Behaviour change: quarantine is now enforced at instruction dispatch",
        "## \u26a0\ufe0f Behaviour change: raw dispatch now enforces InstructionDefinition approval governance",
        "## Upgrade notes by release",
    ),
}

SKIP_DIRS = {".git", "build", "vcpkg_installed", "node_modules", "_build", ".claude/worktrees"}


def allowlisted(rel):
    return rel in ALLOW_FILES or rel.startswith(ALLOW_PREFIXES)


def outside_allowed_sections(text, prefixes):
    """`text` with every line under an allowed `## ` heading blanked, so the scan sees only the
    rest. The heading line itself belongs to its section. A `## ` inside a fenced code block is not
    a heading. Line numbers are kept."""
    out = []
    allowed = False
    fenced = False
    for line in text.splitlines():
        if line.lstrip().startswith("```"):
            fenced = not fenced
        elif not fenced and line.startswith("## "):
            allowed = line.startswith(prefixes)
        out.append("" if allowed else line)
    return "\n".join(out)


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


# The nine argv shapes the agent's sudoers grants for each iptables tool (#7634); the single
# statement of them in C++ is iptables_argv_in_sudo_shape.
IPT_TOOLS = ("/usr/sbin/iptables", "/usr/sbin/ip6tables")
IPT_SHAPES = (
    "-S",
    "-N yuzu-fwq-*",
    "-A yuzu-fwq-*",
    "-I INPUT 1 -j yuzu-fwq-*",
    "-I OUTPUT 1 -j yuzu-fwq-*",
    "-I FORWARD 1 -j yuzu-fwq-*",
    "-D * -j yuzu-fwq-*",
    "-F yuzu-fwq-*",
    "-X yuzu-fwq-*",
)


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
            if rel in ALLOW_SECTIONS:
                text = outside_allowed_sections(text, ALLOW_SECTIONS[rel])
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
        # #7634: iptables and ip6tables are no longer granted bare either; each has the nine shapes.
        bare_ipt = [g for g in grants if re.search(r"NOPASSWD:\s*/usr/sbin/ip6?tables\s*$", g)]
        self.assertEqual(bare_ipt, [], "a bare iptables or ip6tables grant would make the shape lines cosmetic")
        ipt_grants = [g for g in grants if re.search(r"NOPASSWD:\s*/usr/sbin/ip6?tables\b", g)]
        want = ["$ACCOUNT_NAME ALL=(root) NOPASSWD: %s %s" % (tool, shape)
                for tool in IPT_TOOLS for shape in IPT_SHAPES]
        self.assertEqual(sorted(ipt_grants), sorted(want),
                         "the iptables / ip6tables grants must be exactly the eighteen shape lines")

    def test_the_iptables_grants_and_the_agents_shape_predicate_name_the_same_tokens(self):
        """Lockstep (#7634): scripts/install-agent-user.sh is written from the shapes that
        iptables_argv_in_sudo_shape accepts. Every fixed token of the grants is spelled in the
        predicate, and every token the predicate spells is in the grants, so neither can move
        alone."""
        header = read_text("agents/plugins/firewall/src/firewall_quarantine_parsers.hpp")
        self.assertIsNotNone(header)
        start = header.find("inline bool iptables_argv_in_sudo_shape(")
        self.assertGreater(start, 0, "iptables_argv_in_sudo_shape is gone from the parsers header")
        end = header.find("\n}\n", start)
        body = header[start:end]
        spelled = set(re.findall(r'"([^"]*)"', body))
        granted = {t for shape in IPT_SHAPES for t in shape.split()
                   if t != "*" and not t.startswith("yuzu-fwq-")}
        self.assertEqual(spelled, granted)
        # The tool paths and the chain prefix are named through their constants.
        self.assertIn("kIptablesPath", body)
        self.assertIn("kIp6tablesPath", body)
        self.assertIn("ipt_chain_gen(", body)
        self.assertIn('kIptablesPath = "/usr/sbin/iptables"', header)
        self.assertIn('kIp6tablesPath = "/usr/sbin/ip6tables"', header)
        self.assertRegex(header, r'kIptablesChainPrefix\s*=\s*"yuzu-fwq-"')


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
                    "CHANGELOG.md", THIS,
                    "deploy/packaging/linux-floor-baseline.json"):
            self.assertTrue(allowlisted(rel), rel)
        # upgrading.md is exempt by section only (#7588d), never as a whole file.
        for rel in ("docs/user-manual/upgrading.md", "docs/user-manual/security-hardening.md",
                    "server/core/src/rest_api_v1.cpp", "docs/capability-map.md",
                    "docs/roadmap-extra.md"):
            self.assertFalse(allowlisted(rel), rel)
        self.assertEqual(len(ALLOW_SECTIONS["docs/user-manual/upgrading.md"]), 9)


class SectionAllowlistSelfTest(unittest.TestCase):
    """The per-section exemption is quiet under an allowed heading and loud everywhere else."""

    PREFIXES = ALLOW_SECTIONS["docs/user-manual/upgrading.md"]
    HIT = "The `quarantine` plugin was removed."
    ALLOWED = "## Behaviour change: protective actions exempt from plugin enablement (a suffix)"

    def scan(self, text):
        return hits_in(outside_allowed_sections(text, self.PREFIXES))

    def test_a_hit_under_an_allowed_heading_is_quiet(self):
        self.assertEqual(self.scan(self.ALLOWED + "\n\n" + self.HIT + "\n"), [])

    def test_the_same_hit_under_another_heading_is_reported(self):
        self.assertNotEqual(self.scan("## Behaviour change: something new\n\n" + self.HIT + "\n"), [])

    def test_a_hit_before_the_first_heading_is_reported(self):
        self.assertNotEqual(self.scan(self.HIT + "\n" + self.ALLOWED + "\n"), [])

    def test_the_exemption_ends_at_the_next_heading(self):
        text = self.ALLOWED + "\n" + self.HIT + "\n## Another section\n" + self.HIT + "\n"
        self.assertEqual(len(self.scan(text)), len(hits_in(self.HIT)))

    def test_a_heading_inside_a_code_fence_does_not_open_or_close_a_section(self):
        text = "## Another section\n```\n" + self.ALLOWED + "\n```\n" + self.HIT + "\n"
        self.assertNotEqual(self.scan(text), [])

    def test_the_nine_sections_exist_in_the_file_today(self):
        text = read_text("docs/user-manual/upgrading.md")
        self.assertIsNotNone(text)
        headings = [l for l in text.splitlines() if l.startswith("## ")]
        for prefix in self.PREFIXES:
            self.assertTrue(any(h.startswith(prefix) for h in headings),
                            "no upgrading.md heading starts with: " + prefix)


if __name__ == "__main__":
    unittest.main()
