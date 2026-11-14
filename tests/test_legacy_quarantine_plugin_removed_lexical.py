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
    argument and no wildcard, takes the iptables / ip6tables work (#7634). The C++ twin of the
    helper's grammar is iptables_helper_argv in the parsers header."""

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
                   "!10.0.0.1", "10.0.0.1/ 8", "", "1" * 44)],
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
        self.assertIn("[dry-run]   $ACCOUNT_NAME" .replace("$ACCOUNT_NAME", "yuzu") +
                      " ALL=(root) NOPASSWD: /usr/local/sbin/yuzu-fw-helper\n", out)
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
