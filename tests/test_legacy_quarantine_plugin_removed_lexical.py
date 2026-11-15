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
import shutil
import subprocess
import sys
import tempfile
import unittest
from concurrent.futures import ThreadPoolExecutor

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
# silently drop the exemption. An entry is a `## ` heading, which covers everything up to the next
# `## ` heading (its `### ` subsections included), or a `### ` heading, which covers that
# subsection only: "## Upgrade notes by release" is where every release's notes land, so it is
# exempt by the one subsection that names the plugin, never as a whole.
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
        "### `quarantine` plugin: reporting is now more conservative",
    ),
}

SKIP_DIRS = {".git", "build", "vcpkg_installed", "node_modules", "_build", ".claude/worktrees"}


def allowlisted(rel):
    return rel in ALLOW_FILES or rel.startswith(ALLOW_PREFIXES)


def heading_level(line):
    """2 for a `## ` heading, 3 for a `### ` heading, else 0."""
    m = re.match(r"(##|###) ", line)
    return len(m.group(1)) if m else 0


def outside_allowed_sections(text, prefixes):
    """`text` with every line under an allowed heading blanked, so the scan sees only the rest. An
    allowed `## ` heading covers its `### ` subsections too; an allowed `### ` heading covers that
    subsection only, ending at the next `## ` or `### ` heading. The heading line itself belongs to
    its section. A heading inside a fenced code block is not a heading. Line numbers are kept."""
    out = []
    allowed = False
    allowed_level = 0
    fenced = False
    for line in text.splitlines():
        if line.lstrip().startswith("```"):
            fenced = not fenced
        elif not fenced:
            level = heading_level(line)
            if level == 2:
                allowed, allowed_level = line.startswith(prefixes), 2
            elif level == 3 and not (allowed and allowed_level == 2):
                allowed, allowed_level = line.startswith(prefixes), 3
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


HELPER_RE = re.compile(r"cat <<'YUZU_FW_HELPER'\n(.*?)\nYUZU_FW_HELPER\n", re.S)
HEADER = "agents/plugins/firewall/src/firewall_quarantine_parsers.hpp"
INSTALLER = "scripts/install-agent-user.sh"


def helper_text():
    """The firewall helper exactly as the installer writes it (a quoted heredoc: nothing in it is
    expanded by the installer)."""
    text = read_text(INSTALLER)
    m = HELPER_RE.search(text or "")
    if not m:
        raise AssertionError("the installer no longer carries the firewall helper heredoc")
    return m.group(1) + "\n"


def installer_helper_path():
    m = re.search(r'^FW_HELPER_PATH="([^"]+)"$', read_text(INSTALLER) or "", re.M)
    return m.group(1) if m else None


def header_helper_path():
    m = re.search(r'kFwHelperPath\s*=\s*"([^"]+)"', read_text(HEADER) or "")
    return m.group(1) if m else None


class IptablesHelperGrant(unittest.TestCase):
    """The agent account has no iptables grant at all: one root-owned helper, named with no
    argument and no wildcard, takes the iptables / ip6tables work (#7634) and the nftables ruleset
    load. The only nft lines left are the two fixed ones that delete and list the table. The C++
    twins of the helper's grammar are iptables_helper_argv and nft_ruleset_text in the parsers
    header."""

    def grant_lines(self):
        text = read_text(INSTALLER)
        self.assertIsNotNone(text)
        return [l.strip() for l in text.splitlines() if "NOPASSWD:" in l and not l.lstrip().startswith("#")]

    def test_the_sudoers_text_grants_no_iptables_binary_of_any_kind(self):
        bad = [g for g in self.grant_lines() if re.search(r"ip6?tables", g)]
        self.assertEqual(bad, [], "no grant may name iptables, ip6tables, -save or -restore; the helper is the grant")

    def test_the_helper_line_has_no_argument_and_no_wildcard(self):
        lines = [g for g in self.grant_lines() if "FW_HELPER_PATH" in g]
        self.assertEqual(lines, ["$ACCOUNT_NAME ALL=(root) NOPASSWD: $FW_HELPER_PATH"])
        self.assertNotIn("*", lines[0])

    def test_no_nft_line_has_a_wildcard_there_is_no_bare_nft_and_the_two_fixed_lines_remain(self):
        nft = [g for g in self.grant_lines() if re.search(r"\bnft\b", g)]
        for g in nft:
            self.assertNotIn("*", g)
        self.assertEqual([g for g in nft if re.search(r"NOPASSWD:\s*/usr/sbin/nft\s*$", g)], [])
        self.assertEqual(nft, [
            "$ACCOUNT_NAME ALL=(root) NOPASSWD: /usr/sbin/nft delete table inet yuzu_quarantine",
            "$ACCOUNT_NAME ALL=(root) NOPASSWD: /usr/sbin/nft list table inet yuzu_quarantine",
        ])

    def test_the_helper_accepts_the_staging_name_the_plugin_creates(self):
        header = read_text(HEADER)
        plugin = read_text("agents/plugins/firewall/src/firewall_plugin.cpp")
        self.assertIn('stage_("yuzu-fwq-", ".nft", text)', header)
        self.assertIn('data_dir + "/firewall-staging"', plugin)
        text = helper_text()
        self.assertIn("*/firewall-staging)", text)
        self.assertIn("yuzu-fwq-*.nft)", text)

    def test_the_helper_path_is_the_same_string_in_the_installer_and_the_header(self):
        path = installer_helper_path()
        self.assertEqual(path, "/usr/local/sbin/yuzu-fw-helper")
        self.assertEqual(header_helper_path(), path)

    def test_no_sudoers_line_other_than_the_helper_follows_the_helper_path_with_text(self):
        for g in self.grant_lines():
            self.assertNotRegex(g, r"yuzu-fw-helper\S*\s+\S", g)

    def test_the_helper_is_installed_before_the_sudoers_file_and_removed_and_checked(self):
        text = read_text(INSTALLER)
        dispatch = text[text.index('case "$ACTION" in'):]
        self.assertLess(dispatch.index("install_fw_helper ||"), dispatch.index("install_sudoers"))
        self.assertIn("remove_fw_helper", dispatch)
        check = text[text.index("check_install() {"):text.index("# ── action dispatch")]
        self.assertIn("check_fw_helper ||", check)
        body = text[text.index("install_fw_helper() {"):text.index("remove_fw_helper() {")]
        self.assertIn("SKIP_SUDOERS", body)               # --no-sudoers skips it
        self.assertIn('"$PLATFORM" != "linux"', body)      # Linux only
        for step in ("mktemp", "chown root:root", "chmod 0755", "sh -n", "mv -f"):
            self.assertIn(step, body)                      # temp file beside it, rename into place

    def test_the_helper_text_has_no_eval_no_shell_no_command_substitution(self):
        code = "\n".join(l for l in helper_text().splitlines() if not l.lstrip().startswith("#"))
        for needle in ("eval", "sh -c", "bash -c", "$(", "`", "$((", "source ", ". /"):
            self.assertNotIn(needle, code)
        self.assertTrue(helper_text().startswith("#!/bin/sh\n"))
        self.assertIn("\nset -u\n", helper_text())


def available_shells():
    found = []
    for name in ("sh", "dash", "bash"):
        path = shutil.which(name)
        if path and os.path.realpath(path) not in [os.path.realpath(f) for f in found]:
            found.append(path)
    return found


def run_all(argvs):
    """Run each argv, a few at a time (a process per case is what costs here): the results, in order."""
    def one(argv):
        return subprocess.run(argv, capture_output=True, text=True, timeout=30)
    with ThreadPoolExecutor(max_workers=8) as pool:
        return list(pool.map(one, argvs))


# The helper's accepted argument lists, each with the family it is run for. The C++ twin of this
# list, and of the adversarial one below, is the iptables_helper_argv group in
# tests/unit/test_firewall_quarantine_parsers.cpp; the two grammars move together.
HELPER_ACCEPTED = [
    ("iptables", ["-S"]),
    ("ip6tables", ["-S"]),
    ("iptables", ["-N", "yuzu-fwq-1"]),
    ("ip6tables", ["-N", "yuzu-fwq-12-f"]),
    ("iptables", ["-N", "yuzu-fwq-2147483647"]),
    ("iptables", ["-N", "yuzu-fwq-0000000001"]),
    ("iptables", ["-F", "yuzu-fwq-7"]),
    ("ip6tables", ["-X", "yuzu-fwq-7-f"]),
    ("iptables", ["-A", "yuzu-fwq-4", "-j", "DROP"]),
    ("ip6tables", ["-A", "yuzu-fwq-4-f", "-j", "DROP"]),
    ("iptables", ["-A", "yuzu-fwq-4", "-i", "lo", "-j", "ACCEPT"]),
    ("iptables", ["-A", "yuzu-fwq-4", "-o", "lo", "-j", "ACCEPT"]),
    ("ip6tables", ["-A", "yuzu-fwq-4", "-p", "icmpv6", "--icmpv6-type", "133", "-j", "ACCEPT"]),
    ("ip6tables", ["-A", "yuzu-fwq-4", "-p", "icmpv6", "--icmpv6-type", "136", "-j", "ACCEPT"]),
    ("iptables", ["-A", "yuzu-fwq-4", "-p", "udp", "--sport", "68", "--dport", "67", "-j", "ACCEPT"]),
    ("iptables", ["-A", "yuzu-fwq-4", "-d", "203.0.113.53", "-p", "udp", "--dport", "53", "-j", "ACCEPT"]),
    ("iptables", ["-A", "yuzu-fwq-4", "-s", "198.51.100.7", "-p", "tcp", "--sport", "50051",
                  "--tcp-flags", "ACK", "ACK", "-j", "ACCEPT"]),
    ("iptables", ["-A", "yuzu-fwq-4", "-s", "198.51.100.7", "-p", "tcp", "--sport", "50051",
                  "--tcp-flags", "RST", "RST", "-j", "ACCEPT"]),
    ("iptables", ["-A", "yuzu-fwq-4", "-s", "10.0.0.5", "-p", "tcp", "--dport", "22", "-j", "ACCEPT"]),
    ("iptables", ["-A", "yuzu-fwq-4", "-d", "10.0.0.7", "-p", "tcp", "-j", "ACCEPT"]),
    ("iptables", ["-A", "yuzu-fwq-4", "-d", "10.1.0.0/16", "-p", "udp", "--dport", "53", "-j", "ACCEPT"]),
    ("iptables", ["-A", "yuzu-fwq-4", "-s", "10.0.0.0/32", "-p", "tcp", "--dport", "65535", "-j", "ACCEPT"]),
    ("iptables", ["-A", "yuzu-fwq-4", "-s", "255.255.255.255/32", "-p", "udp", "-j", "ACCEPT"]),
    ("iptables", ["-A", "yuzu-fwq-4", "-d", "0.0.0.0/0", "-p", "tcp", "-j", "ACCEPT"]),
    ("iptables", ["-A", "yuzu-fwq-4", "-d", "10.0.200.9", "-p", "tcp", "-j", "ACCEPT"]),
    ("ip6tables", ["-A", "yuzu-fwq-4", "-d", "2001:db8::/32", "-p", "tcp", "--dport", "443", "-j", "ACCEPT"]),
    ("ip6tables", ["-A", "yuzu-fwq-4", "-s", "2001:4860:4860::8888", "-p", "udp", "--sport", "53", "-j", "ACCEPT"]),
    ("ip6tables", ["-A", "yuzu-fwq-4", "-s", "::", "-p", "tcp", "--sport", "1", "--dport", "2",
                   "--tcp-flags", "RST", "RST", "-j", "ACCEPT"]),
    ("ip6tables", ["-A", "yuzu-fwq-4", "-d", "2001:db8::/128", "-p", "udp", "-j", "ACCEPT"]),
    ("iptables", ["-I", "INPUT", "1", "-j", "yuzu-fwq-3"]),
    ("ip6tables", ["-I", "OUTPUT", "1", "-j", "yuzu-fwq-3"]),
    ("iptables", ["-I", "FORWARD", "1", "-j", "yuzu-fwq-3-f"]),
    ("iptables", ["-D", "INPUT", "-j", "yuzu-fwq-2"]),
    ("ip6tables", ["-D", "DOCKER-USER", "-j", "yuzu-fwq-2-f"]),
    ("iptables", ["-D", "a" * 28, "-j", "yuzu-fwq-2"]),
]

_ADV = [
    # a tail after a complete rule: split into tokens and glued onto one
    ["-A", "yuzu-fwq-1", "-j", "DROP", "-t", "raw"],
    ["-A", "yuzu-fwq-1", "-j", "DROP", "--modprobe=/x"],
    ["-A", "yuzu-fwq-1", "-j", "DROP", "-m", "comment", "--comment", "x"],
    ["-A", "yuzu-fwq-1", "-j", "DROP", "-w"],
    # the same in front of the shape or between its tokens
    ["-t", "raw", "-A", "yuzu-fwq-1", "-j", "DROP"],
    ["--modprobe=/x", "-A", "yuzu-fwq-1", "-j", "DROP"],
    ["-A", "yuzu-fwq-1", "--modprobe", "/x", "-j", "DROP"],
    ["-A", "yuzu-fwq-1", "-m", "comment", "--comment", "x", "-j", "ACCEPT"],
    ["-A", "yuzu-fwq-1", "-p", "tcp", "--dport", "22", "--modprobe=/x", "-j", "ACCEPT"],
    ["-A", "yuzu-fwq-1", "-p", "tcp", "--dport", "22", "-j", "ACCEPT", "-t", "raw"],
    ["-A", "yuzu-fwq-1", "-p", "tcp", "-j", "ACCEPT", "--dport", "22"],
    ["-A", "yuzu-fwq-1", "-p", "tcp", "--dport", "22", "--sport", "22", "-j", "ACCEPT"],
    # a rule that is not one of the plan's
    ["-A", "yuzu-fwq-1", "-j", "ACCEPT"],
    ["-A", "yuzu-fwq-1", "-j", "REJECT"],
    ["-A", "yuzu-fwq-1", "-j", "DROP", "-j", "DROP"],
    ["-A", "yuzu-fwq-1", "-j"],
    ["-A", "yuzu-fwq-1"],
    ["-A", "yuzu-fwq-1", "-i", "eth0", "-j", "ACCEPT"],
    ["-A", "yuzu-fwq-1", "-i", "lo", "-o", "lo", "-j", "ACCEPT"],
    ["-A", "yuzu-fwq-1", "-p", "icmp", "-j", "ACCEPT"],
    ["-A", "yuzu-fwq-1", "-p", "all", "-j", "ACCEPT"],
    ["-A", "yuzu-fwq-1", "-p", "6", "-j", "ACCEPT"],
    # a chain that is not ours
    ["-A", "INPUT", "-j", "DROP"],
    ["-A", "yuzu-fwq-1x", "-j", "DROP"],
    ["-A", "yuzu-fwq-", "-j", "DROP"],
    ["-A", "xyuzu-fwq-1", "-j", "DROP"],
    ["-N", "DOCKER"],
    ["-N", "yuzu-fwq-"],
    ["-N", "yuzu-fwq--f"],
    ["-N", "yuzu-fwq-1-f-f"],
    ["-N", "yuzu-fwq-1x"],
    ["-N", "yuzu-fwq-2147483648"],
    ["-N", "yuzu-fwq-12345678901"],
    ["-N", "yuzu-fwq- 1"],
    ["-N", "yuzu-fwq-+1"],
    ["-N", "yuzu-fwq-1", "extra"],
    ["-F"],
    ["-F", "INPUT"],
    ["-X", "DOCKER"],
    ["-X"],
    # ports
    *[["-A", "yuzu-fwq-1", "-p", "tcp", "--dport", port, "-j", "ACCEPT"]
      for port in ("0", "65536", "-1", "+22", "022", "", "22 ", " 22", "2e1", "0x16", "99999", "123456")],
    *[["-A", "yuzu-fwq-1", "-p", "udp", "--sport", port, "-j", "ACCEPT"] for port in ("0", "65536", "-1")],
    # addresses
    *[["-A", "yuzu-fwq-1", "-s", addr, "-p", "tcp", "-j", "ACCEPT"]
      for addr in ("evil.example.com", "localhost", "-1.2.3.4", "--modprobe=/x", "10.0.0", "10.0.0.0.0",
                   "10..0.1", ".10.0.1", "10.0.0.", "10.0.0.1/33", "10.0.0.1/", "/24", "10.0.0.1/-1",
                   "10.0.0.1/24/1", "10.0.0.1/0024", "2001:db8::1/129", "2001:db8:::1", "2001:DB8::1",
                   "fe80:1", "g::1", "10.0.0.1 ", "0x0a.0.0.1", "10.0.0.1,10.0.0.2", "::ffff:1.2.3.4",
                   "!10.0.0.1", "10.0.0.1/ 8", "", "1" * 44,
                   # out of range or zero-padded quads (F8): a name to the tool, not an address
                   "999.1.1.1", "256.0.0.1", "1.2.3.256", "01.2.3.4")],
    ["-A", "yuzu-fwq-1", "-s", "10.0.0.1", "-d", "10.0.0.2", "-p", "tcp", "-j", "ACCEPT"],
    # neighbour discovery
    *[["-A", "yuzu-fwq-1", "-p", "icmpv6", "--icmpv6-type", t, "-j", "ACCEPT"]
      for t in ("132", "137", "0", "13", "1333", "13x", "", "-133", "+133")],
    ["-A", "yuzu-fwq-1", "-s", "fe80::1", "-p", "icmpv6", "--icmpv6-type", "135", "-j", "ACCEPT"],
    ["-A", "yuzu-fwq-1", "-p", "icmpv6", "--icmpv6-type", "135", "--dport", "1", "-j", "ACCEPT"],
    ["-A", "yuzu-fwq-1", "-p", "icmpv6", "-j", "ACCEPT"],
    # tcp flags
    ["-A", "yuzu-fwq-1", "-p", "tcp", "--tcp-flags", "SYN", "SYN", "-j", "ACCEPT"],
    ["-A", "yuzu-fwq-1", "-p", "tcp", "--tcp-flags", "ACK", "RST", "-j", "ACCEPT"],
    ["-A", "yuzu-fwq-1", "-p", "tcp", "--tcp-flags", "ACK,RST", "ACK", "-j", "ACCEPT"],
    ["-A", "yuzu-fwq-1", "-p", "tcp", "--tcp-flags", "ACK", "-j", "ACCEPT"],
    ["-A", "yuzu-fwq-1", "-p", "udp", "--tcp-flags", "ACK", "ACK", "-j", "ACCEPT"],
    # the jump insert
    ["-I", "INPUT", "2", "-j", "yuzu-fwq-1"],
    ["-I", "INPUT", "0", "-j", "yuzu-fwq-1"],
    ["-I", "INPUT", "1", "-j", "ACCEPT"],
    ["-I", "INPUT", "1", "-j", "DOCKER"],
    ["-I", "yuzu-fwq-1", "1", "-j", "yuzu-fwq-1"],
    ["-I", "PREROUTING", "1", "-j", "yuzu-fwq-1"],
    ["-I", "input", "1", "-j", "yuzu-fwq-1"],
    ["-I", "INPUT", "1", "-j", "yuzu-fwq-1", "-m", "comment"],
    ["-I", "INPUT", "-j", "yuzu-fwq-1"],
    # the jump delete
    ["-D", "--modprobe=/x", "-j", "yuzu-fwq-1"],
    ["-D", "-t", "-j", "yuzu-fwq-1"],
    ["-D", "a" * 29, "-j", "yuzu-fwq-1"],
    ["-D", "IN PUT", "-j", "yuzu-fwq-1"],
    ["-D", "INPUT;", "-j", "yuzu-fwq-1"],
    ["-D", "IN\nPUT", "-j", "yuzu-fwq-1"],
    ["-D", "", "-j", "yuzu-fwq-1"],
    ["-D", "INPUT", "-j", "ACCEPT"],
    ["-D", "INPUT", "1"],
    ["-D", "INPUT", "-j", "yuzu-fwq-1", "extra"],
    # other operations and extra tokens on a one-token shape
    *[[op] for op in ("-P", "-L", "-R", "-C", "-E", "-Z", "-V", "-h", "--help", "--list", "-S1", "-s")],
    ["-P", "INPUT", "ACCEPT"],
    ["-S", "INPUT"],
    ["-S", "-t", "raw"],
]


@unittest.skipIf(sys.platform == "win32", "runs the helper under a POSIX shell")
class IptablesHelperRuns(unittest.TestCase):
    """The helper text, run with its two exec targets replaced by a stub that prints the argument
    list it was handed. Every accepted shape reproduces its exact argument list on both tools;
    every adversarial one exits non-zero having run nothing. Run under each POSIX shell found
    (sh, dash, bash): the helper must not depend on a bash extension."""

    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.TemporaryDirectory(prefix="yuzu_test_fwhelper_")
        d = cls.tmp.name
        text = helper_text()
        for tool in ("/usr/sbin/iptables", "/usr/sbin/ip6tables"):
            assert text.count(tool) == 1, "the helper must name %s exactly once, as its exec target" % tool
        cls.stubs = {}
        for fam, target in (("iptables", "/usr/sbin/iptables"), ("ip6tables", "/usr/sbin/ip6tables")):
            stub = os.path.join(d, "stub-" + fam)
            with open(stub, "w") as f:
                # One argument per line, behind the tool's own name.
                f.write("#!/bin/sh\nprintf 'RAN %s\\n' \"${0##*/}\"\nfor a; do printf '%s\\n' \"$a\"; done\n")
            os.chmod(stub, 0o755)
            cls.stubs[fam] = stub
            text = text.replace(target, stub)
        cls.path = os.path.join(d, "yuzu-fw-helper")
        with open(cls.path, "w") as f:
            f.write(text)

    @classmethod
    def tearDownClass(cls):
        cls.tmp.cleanup()

    def test_the_helper_passes_a_syntax_check_under_every_shell(self):
        for shell in available_shells():
            r = subprocess.run([shell, "-n", self.path], capture_output=True, text=True, timeout=30)
            self.assertEqual((r.returncode, r.stderr), (0, ""), shell)

    def test_every_accepted_shape_runs_the_tool_with_exactly_its_own_argument_list(self):
        self.assertEqual({family for family, _ in HELPER_ACCEPTED}, {"iptables", "ip6tables"})
        for shell in available_shells():
            results = run_all([[shell, self.path, family] + tokens for family, tokens in HELPER_ACCEPTED])
            for (family, tokens), r in zip(HELPER_ACCEPTED, results):
                want = "RAN stub-%s\n" % family + "".join(t + "\n" for t in tokens)
                self.assertEqual((r.returncode, r.stdout, r.stderr), (0, want, ""), (shell, family, tokens))

    def test_every_adversarial_argument_list_exits_non_zero_having_run_nothing(self):
        self.assertGreater(len(_ADV), 100)
        for shell in available_shells():
            for fam in ("iptables", "ip6tables"):
                results = run_all([[shell, self.path, fam] + tokens for tokens in _ADV])
                for tokens, r in zip(_ADV, results):
                    self.assertNotEqual(r.returncode, 0, (shell, fam, tokens))
                    self.assertEqual(r.stdout, "", (shell, fam, tokens, "the tool ran"))

    def test_other_tools_and_families_and_a_bare_call_are_refused(self):
        bad = ([], ["iptables"], ["ip6tables"], ["iptables-save", "-S"], ["/usr/sbin/iptables", "-S"],
               ["nft", "-S"], ["IPTABLES", "-S"], ["", "-S"], ["iptables", ""], ["iptables", "-S", ""])
        for shell in available_shells():
            for argv, r in zip(bad, run_all([[shell, self.path] + list(a) for a in bad])):
                self.assertNotEqual(r.returncode, 0, (shell, argv))
                self.assertEqual(r.stdout, "", (shell, argv))

    def test_the_environment_cannot_change_what_runs(self):
        env = dict(os.environ, PATH="/nonexistent", IFS="-", ENV="/nonexistent", BASH_ENV="/nonexistent")
        for shell in available_shells():
            r = subprocess.run([shell, self.path, "iptables", "-N", "yuzu-fwq-1"], capture_output=True,
                               text=True, timeout=30, env=env)
            self.assertEqual((r.returncode, r.stdout), (0, "RAN stub-iptables\n-N\nyuzu-fwq-1\n"), shell)


GOLDEN_RE = re.compile(r'kGoldenNftRuleset = R"NFTGOLDEN\((.*?)\)NFTGOLDEN";', re.S)
PARSERS_TEST = "tests/unit/test_firewall_quarantine_parsers.cpp"


def golden_ruleset():
    """The ruleset the C++ unit test pins as nft_ruleset_text's output for a set that uses every rule
    form, read out of that test so the helper is run against the plugin's own text."""
    m = GOLDEN_RE.search(read_text(PARSERS_TEST) or "")
    if not m:
        raise AssertionError("the golden nft ruleset is gone from " + PARSERS_TEST)
    return m.group(1)


@unittest.skipIf(sys.platform == "win32", "runs the helper under a POSIX shell")
class NftLoadRuns(unittest.TestCase):
    """`yuzu-fw-helper nft load <path>`, run with nft replaced by a stub that prints its arguments
    and its standard input. The plugin's golden text comes out of the stub byte for byte on
    `-f /dev/stdin`; a file that is anything else, or a path that is not the staged shape, runs
    nothing. Run under each POSIX shell found (sh, dash, bash)."""

    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.TemporaryDirectory(prefix="yuzu_test_fwhelper_")
        d = cls.tmp.name
        text = helper_text()
        assert text.count("/usr/sbin/nft") == 1, "the helper must name /usr/sbin/nft exactly once"
        cls.helpers = {}
        for name, code in (("ok", 0), ("fail", 3)):
            stub = os.path.join(d, "stub-nft-" + name)
            with open(stub, "w") as f:
                f.write("#!/bin/sh\nprintf 'RAN %s\\n' \"${0##*/}\"\nfor a; do printf '%s\\n' \"$a\"; done\n"
                        "cat\nexit " + str(code) + "\n")
            os.chmod(stub, 0o755)
            path = os.path.join(d, "yuzu-fw-helper-" + name)
            with open(path, "w") as f:
                f.write(text.replace("/usr/sbin/nft", stub))
            cls.helpers[name] = path
        cls.stage = os.path.join(d, "var", "lib", "yuzu-agent", "firewall-staging")
        os.makedirs(cls.stage)
        cls.golden = golden_ruleset()
        cls.n = 0

    @classmethod
    def tearDownClass(cls):
        cls.tmp.cleanup()

    @classmethod
    def staged(cls, content):
        """A staged file holding `content` (str or bytes); its path."""
        cls.n += 1
        path = os.path.join(cls.stage, "yuzu-fwq-t%d.nft" % cls.n)
        with open(path, "wb") as f:
            f.write(content if isinstance(content, bytes) else content.encode())
        return path

    def want(self, ruleset=None):
        return ("RAN stub-nft-ok\n-f\n/dev/stdin\n" + (self.golden if ruleset is None else ruleset)).encode()

    def run_load(self, shell, path, helper="ok", extra=(), env=None):
        return subprocess.run([shell, self.helpers[helper], "nft", "load", path, *extra], capture_output=True,
                              timeout=30, env=env)

    def run_each(self, jobs):
        """jobs: [(shell, argv-after-the-helper)] run a few at a time; the results in order."""
        def one(job):
            shell, args = job
            return subprocess.run([shell, self.helpers["ok"], *args], capture_output=True, timeout=30)
        with ThreadPoolExecutor(max_workers=8) as pool:
            return list(pool.map(one, jobs))

    def refused(self, content, label):
        """The helper runs nothing for `content` under every shell, and says only the fixed line."""
        path = self.staged(content)
        results = self.run_each([(sh, ["nft", "load", path]) for sh in available_shells()])
        for sh, r in zip(available_shells(), results):
            self.assertNotEqual(r.returncode, 0, (sh, label))
            self.assertEqual(r.stdout, b"", (sh, label, "nft ran"))
            self.assertEqual(r.stderr, b"yuzu-fw-helper: refused\n", (sh, label))

    def test_the_golden_text_reaches_nft_byte_for_byte_on_stdin_under_every_shell(self):
        self.assertTrue(self.golden.startswith("table inet yuzu_quarantine {}\n") and self.golden.endswith("\n}\n"))
        path = self.staged(self.golden)
        for sh in available_shells():
            r = self.run_load(sh, path)
            self.assertEqual((r.returncode, r.stdout, r.stderr), (0, self.want(), b""), sh)

    def test_the_helper_exits_with_nfts_status(self):
        path = self.staged(self.golden)
        for sh in available_shells():
            r = self.run_load(sh, path, helper="fail")
            self.assertEqual((r.returncode, r.stdout), (3, self.want().replace(b"stub-nft-ok", b"stub-nft-fail")), sh)

    def test_the_environment_cannot_change_what_runs(self):
        env = dict(os.environ, PATH="/nonexistent", IFS="-", ENV="/nonexistent", BASH_ENV="/nonexistent")
        path = self.staged(self.golden)
        for sh in available_shells():
            r = self.run_load(sh, path, env=env)
            self.assertEqual((r.returncode, r.stdout), (0, self.want()), sh)

    def test_a_nul_byte_in_the_file_never_reaches_nft(self):
        lines = self.golden.split("\n")
        for at in (0, 5, 6, 7, 20):
            lines2 = list(lines)
            lines2[at] = lines2[at][:4] + "\0" + lines2[at][4:]
            path = self.staged("\n".join(lines2))
            for sh in available_shells():
                r = self.run_load(sh, path)
                self.assertNotIn(b"\0", r.stdout, (sh, at))
                # either refused having run nothing, or nft got the plugin's own text
                self.assertIn((r.returncode, r.stdout), ((64, b""), (0, self.want())), (sh, at))

    def test_a_file_that_is_not_the_plugins_ruleset_runs_nothing(self):
        g = self.golden
        lines = g.split("\n")[:-1]
        FORWARD = lines.index("  chain forward {")
        INPUT = lines.index("    type filter hook input priority -100; policy drop;") + 1
        OUTPUT = lines.index("    type filter hook output priority -100; policy drop;") + 1
        cases = {
            "empty": "",
            "only the first line": lines[0] + "\n",
            "the flush line is the last": "\n".join(lines[:2]) + "\n",
            "cut after the flush": "\n".join(lines[:3]) + "\n",
            "no final newline": g[:-1],
            "include at the top": 'include "/etc/passwd"\n' + g,
            "include inside the table": g.replace("  chain input {", '  include "/etc/x"\n  chain input {', 1),
            "include as a rule": g.replace("    iif lo accept\n", '    include "/etc/x"\n', 1),
            "define": g.replace("table inet yuzu_quarantine {}\n", "define x = 1\ntable inet yuzu_quarantine {}\n", 1),
            "another table first": "table ip evil {}\n" + g,
            "another table named in the flush": g.replace("flush table inet yuzu_quarantine", "flush table inet filter", 1),
            "flush ruleset": g.replace("flush table inet yuzu_quarantine", "flush ruleset", 1),
            "another family": g.replace("table inet yuzu_quarantine {}", "table ip yuzu_quarantine {}", 1),
            "a fourth chain": g[:-2] + "  chain extra {\n    type filter hook output priority -100; policy drop;\n  }\n}\n",
            "another hook": g.replace("hook input", "hook prerouting", 1),
            "another priority": g.replace("hook input priority -100", "hook input priority 0", 1),
            "policy accept": g.replace("policy drop;", "policy accept;", 1),
            "a second property": g.replace("policy drop;", "policy drop; counter;", 1),
            "a rule in the forward chain": g.replace("hook forward priority -100; policy drop;\n",
                                                     "hook forward priority -100; policy drop;\n    iif lo accept\n", 1),
            "an accept in the forward chain": g.replace("hook forward priority -100; policy drop;\n",
                                                        "hook forward priority -100; policy drop;\n    accept\n", 1),
            "counter": g.replace("    iif lo accept\n", "    counter accept\n", 1),
            "counter in a rule": g.replace("ip saddr 10.0.0.5 tcp dport 22 accept", "ip saddr 10.0.0.5 tcp dport 22 counter accept", 1),
            "log": g.replace("    iif lo accept\n", "    log\n", 1),
            "log with a prefix": g.replace("    iif lo accept\n", '    log prefix "x" accept\n', 1),
            "jump": g.replace("    iif lo accept\n", "    jump other\n", 1),
            "goto": g.replace("    iif lo accept\n", "    goto other\n", 1),
            "dnat": g.replace("    iif lo accept\n", "    dnat to 10.0.0.1\n", 1),
            "ct state": g.replace("    iif lo accept\n", "    ct state established accept\n", 1),
            "drop target": g.replace("    iif lo accept\n", "    drop\n", 1),
            "accept everything": g.replace("    iif lo accept\n", "    accept\n", 1),
            "queue": g.replace("    iif lo accept\n", "    queue\n", 1),
            "a second statement after a semicolon": g.replace("    iif lo accept\n", "    iif lo accept; flush ruleset\n", 1),
            "a comment line": g.replace("flush table inet yuzu_quarantine\n", "# note\nflush table inet yuzu_quarantine\n", 1),
            "a trailing comment": g.replace("    iif lo accept\n", "    iif lo accept # note\n", 1),
            "a blank line": g.replace("flush table inet yuzu_quarantine\n", "\nflush table inet yuzu_quarantine\n", 1),
            "a blank line inside a chain": g.replace("    iif lo accept\n", "\n    iif lo accept\n", 1),
            "a tab for the indent": g.replace("    iif lo accept\n", "\tiif lo accept\n", 1),
            "a tab between words": g.replace("ip saddr 10.0.0.5 tcp dport 22 accept", "ip saddr 10.0.0.5\ttcp dport 22 accept", 1),
            "a doubled space": g.replace("ip saddr 10.0.0.5 tcp dport 22 accept", "ip saddr 10.0.0.5  tcp dport 22 accept", 1),
            "a trailing space": g.replace("    iif lo accept\n", "    iif lo accept \n", 1),
            "three-space indent": g.replace("    iif lo accept\n", "   iif lo accept\n", 1),
            "five-space indent": g.replace("    iif lo accept\n", "     iif lo accept\n", 1),
            "CRLF line ends": g.replace("\n", "\r\n"),
            "one CR": g.replace("    iif lo accept\n", "    iif lo accept\r\n", 1),
            "a backslash continuation": g.replace("    iif lo accept\n", "    iif lo \\\n    accept\n", 1),
            "a host name": g.replace("ip saddr 10.0.0.5 tcp dport 22 accept", "ip saddr example.com tcp dport 22 accept", 1),
            "a host name for ip6": g.replace("ip6 saddr 2001:db8::/32", "ip6 saddr example.com", 1),
            "a set of addresses": g.replace("ip saddr 10.0.0.5 tcp dport 22", "ip saddr { 10.0.0.5, 10.0.0.6 } tcp dport 22", 1),
            "a negated address": g.replace("ip saddr 10.0.0.5 tcp dport 22", "ip saddr != 10.0.0.5 tcp dport 22", 1),
            "an octet past 255": g.replace("ip saddr 10.0.0.5 tcp dport 22", "ip saddr 999.1.1.1 tcp dport 22", 1),
            "256 in an octet": g.replace("ip saddr 10.0.0.5 tcp dport 22", "ip saddr 256.0.0.1 tcp dport 22", 1),
            "a zero-padded octet": g.replace("ip saddr 10.0.0.5 tcp dport 22", "ip saddr 01.2.3.4 tcp dport 22", 1),
            "a short quad": g.replace("ip saddr 10.0.0.5 tcp dport 22", "ip saddr 10.0.5 tcp dport 22", 1),
            "ip with an IPv6 address": g.replace("ip saddr 10.0.0.5 tcp dport 22", "ip saddr 2001:db8::1 tcp dport 22", 1),
            "ip6 with an IPv4 address": g.replace("ip6 saddr 2001:db8::/32", "ip6 saddr 10.0.0.5", 1),
            "a prefix past 32": g.replace("ip saddr 10.1.0.0/16", "ip saddr 10.1.0.0/33", 1),
            "an upper-case IPv6": g.replace("ip6 saddr 2001:db8::/32", "ip6 saddr 2001:DB8::/32", 1),
            "port 0": g.replace("tcp dport 22 accept", "tcp dport 0 accept", 1),
            "port 65536": g.replace("tcp dport 22 accept", "tcp dport 65536 accept", 1),
            "a port range": g.replace("tcp dport 22 accept", "tcp dport 22-80 accept", 1),
            "a leading-zero port": g.replace("tcp dport 22 accept", "tcp dport 022 accept", 1),
            "two protocols": g.replace("tcp dport 22 accept", "udp dport 22 tcp sport 1 accept", 1),
            "tcp flags on udp": g.replace("ip saddr 10.1.0.0/16 udp sport 53 accept",
                                         "ip saddr 10.1.0.0/16 udp sport 53 tcp flags & (syn|ack) != syn accept", 1),
            "other tcp flags": g.replace("tcp flags & (syn|ack) != syn", "tcp flags & syn == syn", 1),
            "iif in the output chain": g[:g.index("    oif lo accept")] + "    iif lo accept\n" +
                                       g[g.index("    oif lo accept") + len("    oif lo accept\n"):],
            "oif in the input chain": g.replace("    iif lo accept\n", "    oif lo accept\n", 1),
            "another interface": g.replace("    iif lo accept\n", "    iif eth0 accept\n", 1),
            "an ICMP type": g.replace("nd-neighbor-advert }", "nd-neighbor-advert, echo-request }", 1),
            "text after the closing brace": g + "flush ruleset\n",
            "a blank line after the closing brace": g + "\n",
            "the whole table twice": g + g,
            "a root-only line marker": g.replace("    iif lo accept\n", "    ROOT-ONLY-SECRET-LINE\n", 1),
        }
        for label, content in cases.items():
            with self.subTest(label):
                self.refused(content, label)
        # the same positions, one input-chain and one output-chain rule line each
        for chain_at, name in ((INPUT, "input"), (OUTPUT, "output")):
            with self.subTest("junk rule in " + name):
                junk = lines[:chain_at] + ["    nonsense"] + lines[chain_at:]
                self.refused("\n".join(junk) + "\n", "junk rule in " + name)

    def test_nothing_from_a_refused_file_is_printed(self):
        path = self.staged(self.golden.replace("    iif lo accept\n", "    ROOT-ONLY-SECRET-LINE\n", 1))
        for sh in available_shells():
            r = self.run_load(sh, path)
            self.assertNotIn(b"SECRET", r.stdout + r.stderr, sh)

    def test_the_line_caps_are_512_lines_of_512_characters(self):
        g = self.golden.split("\n")[:-1]
        at = g.index("    type filter hook input priority -100; policy drop;") + 1
        def padded(rules):
            return "\n".join(g[:at] + ["    iif lo accept"] * rules + g[at:]) + "\n"
        edge = 512 - len(g)
        # 512 lines is accepted, 513 is not (every line in both is otherwise valid)
        text512 = padded(edge)
        self.assertEqual(text512.count("\n"), 512)
        path = self.staged(text512)
        for sh in available_shells():
            r = self.run_load(sh, path)
            self.assertEqual((r.returncode, r.stdout), (0, self.want(text512)), sh)
        self.refused(padded(edge + 1), "513 lines")
        # a 513-character line, and a 512-character one that is not a rule
        self.refused(self.golden.replace("    iif lo accept\n", "    iif lo accept" + " " * 496 + "\n", 1), "a 513-character line")
        self.refused(self.golden.replace("    iif lo accept\n", "    " + "a" * 507 + "\n", 1), "a 512-character line")
        self.refused("x" * 300000, "a file past the byte cap, one line")

    def test_a_link_a_fifo_a_directory_and_a_missing_file_run_nothing(self):
        good = self.staged(self.golden)
        link = os.path.join(self.stage, "yuzu-fwq-link.nft")
        os.symlink(good, link)
        fifo = os.path.join(self.stage, "yuzu-fwq-fifo.nft")
        os.mkfifo(fifo)
        directory = os.path.join(self.stage, "yuzu-fwq-dir.nft")
        os.mkdir(directory)
        missing = os.path.join(self.stage, "yuzu-fwq-missing.nft")
        for label, path in (("symlink", link), ("fifo", fifo), ("directory", directory), ("missing", missing)):
            for sh in available_shells():
                r = self.run_load(sh, path)   # a FIFO that was opened would block until the 30 s timeout
                self.assertNotEqual(r.returncode, 0, (sh, label))
                self.assertEqual(r.stdout, b"", (sh, label))
                self.assertEqual(r.stderr, b"yuzu-fw-helper: refused\n", (sh, label))

    def test_a_path_outside_the_staged_shape_runs_nothing(self):
        good = self.staged(self.golden)
        name = os.path.basename(good)
        other = os.path.join(self.tmp.name, "other")
        os.makedirs(other)
        elsewhere = os.path.join(other, name)
        with open(good, "rb") as f, open(elsewhere, "wb") as g:
            g.write(f.read())
        bad = [
            ("relative", os.path.relpath(good)),
            ("relative from the staging dir", "firewall-staging/" + name),
            ("a directory not named firewall-staging", elsewhere),
            ("the staging name only as a prefix", os.path.join(self.tmp.name, "x-firewall-staging", name)),
            ("the staging name one level up", os.path.join(self.stage, "sub", name)),
            ("a leaf without the stem", os.path.join(self.stage, "t1.nft")),
            ("a leaf with another suffix", os.path.join(self.stage, "yuzu-fwq-t1.txt")),
            ("a leaf with nothing between", os.path.join(self.stage, "yuzu-fwq-.nft")),
            ("a leaf with a space", os.path.join(self.stage, "yuzu-fwq-a b.nft")),
            ("a leaf with a semicolon", os.path.join(self.stage, "yuzu-fwq-a;b.nft")),
            ("a leaf with a glob", os.path.join(self.stage, "yuzu-fwq-*.nft")),
            ("a leaf with a dollar", os.path.join(self.stage, "yuzu-fwq-$x.nft")),
            ("a leaf with a newline", os.path.join(self.stage, "yuzu-fwq-a\nb.nft")),
            ("a newline in the directory", os.path.join(self.tmp.name, "a\nb", "firewall-staging", name)),
            ("a control character", os.path.join(self.stage, "yuzu-fwq-a\x01b.nft")),
            ("a DEL", os.path.join(self.stage, "yuzu-fwq-a\x7fb.nft")),
            ("past 512 characters", "/" + "a" * 300 + "/firewall-staging/yuzu-fwq-" + "b" * 200 + ".nft"),
            ("the root", "/"),
            ("an empty path", ""),
            ("a bare dash", "-"),
            ("an option", "-f"),
            ("a trailing slash", self.stage + "/"),
        ]
        for label, path in bad:
            for sh in available_shells():
                r = self.run_load(sh, path)
                self.assertNotEqual(r.returncode, 0, (sh, label))
                self.assertEqual(r.stdout, b"", (sh, label))

    def test_the_action_takes_exactly_three_arguments(self):
        good = self.staged(self.golden)
        calls = [["nft"], ["nft", "load"], ["nft", good], ["nft", "load", good, "extra"], ["nft", "load", good, ""],
                 ["nft", "-f", good], ["nft", "list", "table", "inet", "yuzu_quarantine"], ["nft", "delete", "table"],
                 ["nft", "LOAD", good], ["nft", "load ", good], ["nft", "", good], ["NFT", "load", good],
                 ["nft", "save", good], ["nft", "load", "-f", good]]
        jobs = [(sh, c) for sh in available_shells() for c in calls]
        for (sh, c), r in zip(jobs, self.run_each(jobs)):
            self.assertNotEqual(r.returncode, 0, (sh, c))
            self.assertEqual(r.stdout, b"", (sh, c))

    def test_every_rule_form_is_accepted_in_the_chain_the_plugin_emits_it_in(self):
        g = self.golden.split("\n")[:-1]
        at = g.index("    type filter hook input priority -100; policy drop;") + 1
        forms = [
            "ip saddr 255.255.255.255 tcp dport 65535 accept",
            "ip daddr 0.0.0.0/0 meta l4proto udp accept",
            "ip saddr 10.0.0.0/32 tcp sport 1 tcp dport 2 tcp flags & (syn|ack) != syn accept",
            "ip6 daddr ::/0 udp sport 53 accept",
            "ip6 saddr ::1 tcp sport 22 tcp flags & (syn|ack) != syn accept",
            "tcp dport 22 accept",
            "udp sport 53 accept",
            "meta l4proto tcp accept",
            "meta l4proto tcp tcp flags & (syn|ack) != syn accept",
        ]
        for form in forms:
            text = "\n".join(g[:at] + ["    " + form] + g[at:]) + "\n"
            path = self.staged(text)
            for sh in available_shells():
                r = self.run_load(sh, path)
                self.assertEqual((r.returncode, r.stdout), (0, self.want(text)), (sh, form))


@unittest.skipIf(sys.platform == "win32", "runs the installer's function under bash")
class HelperDirectoryVerdict(unittest.TestCase):
    """The installer stops before writing the helper, and --check fails, when the helper's directory
    is not owned by root or other users can write to it; a group-writable one (Debian's
    root:staff 2775 /usr/local) is a warning, not a refusal. The decision is one pure function."""

    FN_RE = re.compile(r"^fw_dir_verdict\(\) \{\n.*?\n\}\n", re.S | re.M)

    @classmethod
    def setUpClass(cls):
        m = cls.FN_RE.search(read_text(INSTALLER) or "")
        assert m, "the installer no longer carries fw_dir_verdict"
        cls.fn = m.group(0)

    def verdicts(self, cases):
        script = self.fn + "".join("fw_dir_verdict '%s' '%s'\n" % c for c in cases)
        r = subprocess.run(["bash", "-c", script], capture_output=True, text=True, timeout=30)
        self.assertEqual((r.returncode, r.stderr), (0, ""))
        return r.stdout.split()

    def test_root_owned_and_not_group_or_other_writable_is_ok(self):
        self.assertEqual(self.verdicts([("0", "755"), ("0", "555"), ("0", "700"), ("0", "0"), ("0", "644")]),
                         ["ok"] * 5)

    def test_a_group_writable_root_owned_directory_warns(self):
        self.assertEqual(self.verdicts([("0", "2775"), ("0", "775"), ("0", "770"), ("0", "720"), ("0", "760")]),
                         ["warn"] * 5)

    def test_other_write_or_a_non_root_owner_refuses(self):
        self.assertEqual(self.verdicts([("0", "777"), ("0", "757"), ("0", "1777"), ("0", "702"), ("0", "773"),
                                        ("1000", "755"), ("1", "755"), ("1000", "777")]),
                         ["refuse"] * 8)

    def test_anything_that_is_not_a_uid_and_an_octal_mode_refuses(self):
        self.assertEqual(self.verdicts([("", "755"), ("0", ""), ("0", "75x"), ("0", "855"), ("root", "755"),
                                        ("-1", "755"), ("0", "-755"), ("0", "7 5")]),
                         ["refuse"] * 8)

    def test_the_installer_and_the_check_apply_it_and_clean_up_a_stale_temp(self):
        text = read_text(INSTALLER)
        install = text[text.index("install_fw_helper() {"):text.index("remove_fw_helper() {")]
        self.assertLess(install.index("check_fw_dir"), install.index("mktemp"))      # stop before writing
        self.assertLess(install.index(".yuzu-fw-helper.??????"), install.index("mktemp"))
        check = text[text.index("check_fw_helper() {"):text.index("# ── linux capabilities")]
        self.assertIn("check_fw_dir", check)
        self.assertIn("stat -L -c '%u %a %G'", text)


@unittest.skipIf(sys.platform == "win32", "runs the installer under bash")
class InstallerDryRunOnLinux(unittest.TestCase):
    """The installer's Linux branch, under `--dry-run` with a `uname` that says Linux (a dry run
    only prints): the helper is written BEFORE the sudoers file, is the text the heredoc holds,
    and `--no-sudoers` skips both."""

    def dry_run(self, *extra):
        with tempfile.TemporaryDirectory(prefix="yuzu_test_fwhelper_") as d:
            shim = os.path.join(d, "uname")
            with open(shim, "w") as f:
                f.write('#!/bin/sh\ncase "$1" in -s) echo Linux ;; *) /usr/bin/uname "$@" ;; esac\n')
            os.chmod(shim, 0o755)
            env = dict(os.environ, PATH=d + os.pathsep + os.environ.get("PATH", ""))
            r = subprocess.run(["bash", os.path.join(REPO, INSTALLER), "--dry-run", *extra],
                               capture_output=True, text=True, timeout=60, env=env)
        self.assertEqual(r.returncode, 0, r.stderr)
        return r.stdout

    def test_the_helper_is_printed_before_the_sudoers_file_and_is_the_heredoc_text(self):
        out = self.dry_run()
        helper_marker = "[dry-run] would write the following to /usr/local/sbin/yuzu-fw-helper (root:root 0755):"
        sudoers_marker = "[dry-run] would write the following to /etc/sudoers.d/yuzu-agent:"
        self.assertIn(helper_marker, out)
        self.assertIn(sudoers_marker, out)
        self.assertLess(out.index(helper_marker), out.index(sudoers_marker))
        printed = out[out.index(helper_marker) + len(helper_marker) + 1:out.index(sudoers_marker)]
        lines = [l[len("[dry-run]   "):] for l in printed.splitlines() if l.startswith("[dry-run]   ")]
        self.assertEqual("\n".join(lines) + "\n", helper_text())
        self.assertIn("[dry-run]   yuzu ALL=(root) NOPASSWD: /usr/local/sbin/yuzu-fw-helper\n", out)
        self.assertNotRegex(out, r"NOPASSWD: /usr/sbin/ip6?tables")

    def test_no_sudoers_skips_the_helper_too(self):
        out = self.dry_run("--no-sudoers")
        self.assertNotIn("yuzu-fw-helper", out)
        self.assertNotIn("/etc/sudoers.d/yuzu-agent:", out)


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

    # QE-4: "## Upgrade notes by release" is where every release's notes land, so it is exempt by
    # the one `### ` subsection that names the plugin, never as a whole.
    PARENT = "## Upgrade notes by release"
    SUB = "### `quarantine` plugin: reporting is now more conservative (Wave-2 argv migration)"

    def test_a_hit_under_the_one_allowed_subsection_is_quiet(self):
        text = self.PARENT + "\n\n### Another release\n\nintro\n\n" + self.SUB + "\n" + self.HIT + "\n"
        self.assertEqual(self.scan(text), [])

    def test_the_same_hit_under_another_subsection_of_that_section_is_reported(self):
        self.assertNotEqual(self.scan(self.PARENT + "\n### vNEXT: something new\n" + self.HIT + "\n"), [])

    def test_a_hit_directly_under_the_parent_heading_is_reported(self):
        self.assertNotEqual(self.scan(self.PARENT + "\n" + self.HIT + "\n"), [])

    def test_a_subsection_exemption_ends_at_the_next_subsection(self):
        text = self.PARENT + "\n" + self.SUB + "\n" + self.HIT + "\n### The next release\n" + self.HIT + "\n"
        self.assertEqual(len(self.scan(text)), len(hits_in(self.HIT)))

    def test_a_subsection_exemption_ends_at_the_next_section(self):
        text = self.PARENT + "\n" + self.SUB + "\n" + self.HIT + "\n## Another section\n" + self.HIT + "\n"
        self.assertEqual(len(self.scan(text)), len(hits_in(self.HIT)))

    def test_a_subsection_of_an_allowed_section_stays_exempt(self):
        self.assertEqual(self.scan(self.ALLOWED + "\n### A child\n" + self.HIT + "\n"), [])

    def test_a_subsection_heading_inside_a_code_fence_does_not_open_a_section(self):
        text = self.PARENT + "\n```\n" + self.SUB + "\n```\n" + self.HIT + "\n"
        self.assertNotEqual(self.scan(text), [])

    def test_the_nine_sections_exist_in_the_file_today(self):
        text = read_text("docs/user-manual/upgrading.md")
        self.assertIsNotNone(text)
        headings = [l for l in text.splitlines() if heading_level(l)]
        for prefix in self.PREFIXES:
            self.assertTrue(any(h.startswith(prefix) for h in headings),
                            "no upgrading.md heading starts with: " + prefix)


if __name__ == "__main__":
    unittest.main()
