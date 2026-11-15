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
SVC_HELPER_RE = re.compile(r"cat <<'YUZU_SVC_HELPER'\n(.*?)\nYUZU_SVC_HELPER\n", re.S)
HEADER = "agents/plugins/firewall/src/firewall_quarantine_parsers.hpp"
SVC_HEADER = "agents/plugins/services/src/services_parsers.hpp"
INSTALLER = "scripts/install-agent-user.sh"


def helper_text():
    """The firewall helper exactly as the installer writes it (a quoted heredoc: nothing in it is
    expanded by the installer)."""
    text = read_text(INSTALLER)
    m = HELPER_RE.search(text or "")
    if not m:
        raise AssertionError("the installer no longer carries the firewall helper heredoc")
    return m.group(1) + "\n"


def svc_helper_text():
    """The services helper exactly as the installer writes it."""
    text = read_text(INSTALLER)
    m = SVC_HELPER_RE.search(text or "")
    if not m:
        raise AssertionError("the installer no longer carries the services helper heredoc")
    return m.group(1) + "\n"


def code_lines(text):
    """The lines of a script that are not comments."""
    return "\n".join(l for l in text.splitlines() if not l.lstrip().startswith("#"))


def installer_platform_values():
    """The per-platform values the installer's platform block sets: {platform: {NAME: value}}."""
    text = read_text(INSTALLER) or ""
    m = re.search(r'case "\$OS" in\n(.*?)\n    \*\)\n', text, re.S)
    if not m:
        raise AssertionError("the installer's platform block is gone")
    arms = m.group(1)
    mac, _, lin = arms.partition("    Linux)")
    out = {}
    for platform, block in (("macos", mac), ("linux", lin)):
        out[platform] = dict(re.findall(r'^\s+(ROOT_GROUP|FW_HELPER_PATH|SVC_HELPER_PATH)="([^"]+)"$', block, re.M))
    return out


def installer_helper_path():
    return installer_platform_values()["linux"].get("FW_HELPER_PATH")


def header_helper_path():
    m = re.search(r'kFwHelperPath\s*=\s*"([^"]+)"', read_text(HEADER) or "")
    return m.group(1) if m else None


def header_constant(rel, name):
    m = re.search(r"\b%s\s*=\s*\n?\s*\"([^\"]+)\"" % re.escape(name), read_text(rel) or "")
    return m.group(1) if m else None


def render_installer(platform, *extra, visudo=None):
    """`install-agent-user.sh --dry-run` with a `uname` that says `platform` ("linux" or "macos"): a
    dry run only prints, so this is the helpers and the sudoers text the installer would write."""
    with tempfile.TemporaryDirectory(prefix="yuzu_test_fwhelper_") as d:
        shim = os.path.join(d, "uname")
        os_name = "Linux" if platform == "linux" else "Darwin"
        with open(shim, "w") as f:
            f.write('#!/bin/sh\ncase "$1" in -s) echo %s ;; *) /usr/bin/uname "$@" ;; esac\n' % os_name)
        os.chmod(shim, 0o755)
        if visudo is not None:   # a `visudo` that is a shell body: the sudoers writer asks it about `requiretty`
            with open(os.path.join(d, "visudo"), "w") as f:
                f.write("#!/bin/sh\n" + visudo + "\n")
            os.chmod(os.path.join(d, "visudo"), 0o755)
        env = dict(os.environ, PATH=d + os.pathsep + os.environ.get("PATH", ""))
        r = subprocess.run(["bash", os.path.join(REPO, INSTALLER), "--dry-run", *extra],
                           capture_output=True, text=True, timeout=60, env=env)
    if r.returncode != 0:
        raise AssertionError(r.stderr)
    return r.stdout


def rendered_section(out, marker, end_marker=None):
    """The text a dry run prints after `marker` (one `[dry-run]   `-prefixed line each), up to the
    next dry-run `would write` line or the end of the prefixed block."""
    start = out.index(marker) + len(marker) + 1
    lines = []
    for l in out[start:].splitlines():
        if not l.startswith("[dry-run]   "):
            break
        lines.append(l[len("[dry-run]   "):])
    return "\n".join(lines) + "\n"


def rendered_sudoers(platform):
    out = render_installer(platform)
    return rendered_section(out, "[dry-run] would write the following to /etc/sudoers.d/yuzu-agent:")


def rendered_grants(platform):
    """Every non-comment NOPASSWD line of the sudoers text the installer renders for `platform`."""
    return [l.strip() for l in rendered_sudoers(platform).splitlines()
            if "NOPASSWD:" in l and not l.lstrip().startswith("#")]


class IptablesHelperGrant(unittest.TestCase):
    """The agent account has no iptables grant at all: one root-owned helper, named with no
    argument and no wildcard, takes the iptables / ip6tables work (#7634) and the nftables ruleset
    load. The only nft lines left are the two fixed ones that delete and list the table. The C++
    twins of the helper's grammar are iptables_helper_argv and nft_ruleset_text in the parsers
    header. (This class reads the installer's text, so it runs on every host; RenderedSudoers
    below reads what the installer renders for each platform.)"""

    def grant_lines(self):
        text = read_text(INSTALLER)
        self.assertIsNotNone(text)
        # the macOS pfctl -X lines come from a printf loop; RenderedSudoers checks all 24 of them
        return [l.strip() for l in text.splitlines()
                if "NOPASSWD:" in l and not l.lstrip().startswith(("#", "printf"))]

    def test_the_sudoers_text_grants_no_iptables_binary_of_any_kind(self):
        bad = [g for g in self.grant_lines() if re.search(r"ip6?tables", g)]
        self.assertEqual(bad, [], "no grant may name iptables, ip6tables, -save or -restore; the helper is the grant")

    def test_the_helper_line_has_no_argument_and_no_wildcard(self):
        # one line in the macOS block and one in the Linux block, each the same
        lines = [g for g in self.grant_lines() if "FW_HELPER_PATH" in g]
        self.assertEqual(lines, ["$ACCOUNT_NAME ALL=(root) NOPASSWD: $FW_HELPER_PATH"] * 2)
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

    def test_the_helper_accepts_the_staging_names_the_plugin_creates(self):
        header = read_text(HEADER)
        plugin = read_text("agents/plugins/firewall/src/firewall_plugin.cpp")
        self.assertIn('stage_("yuzu-fwq-", ".nft", text)', header)
        self.assertIn('stage_("yuzu-fwq-", ".pf", text)', header)
        self.assertIn('data_dir + "/firewall-staging"', plugin)
        text = helper_text()
        self.assertIn("*/firewall-staging)", text)
        # one shape check for both, which takes the suffix
        self.assertEqual(text.count('staged_file "$1" .nft'), 1)
        self.assertEqual(text.count('staged_file "$1" .pf'), 1)
        self.assertIn('yuzu-fwq-*"$sfx")', text)

    def test_the_helper_paths_are_the_same_strings_in_the_installer_and_the_headers(self):
        values = installer_platform_values()
        self.assertEqual(values["linux"], {"ROOT_GROUP": "root", "FW_HELPER_PATH": "/usr/local/sbin/yuzu-fw-helper",
                                           "SVC_HELPER_PATH": "/usr/local/sbin/yuzu-svc-helper"})
        self.assertEqual(values["macos"], {"ROOT_GROUP": "wheel",
                                           "FW_HELPER_PATH": "/Library/PrivilegedHelperTools/yuzu-fw-helper",
                                           "SVC_HELPER_PATH": "/Library/PrivilegedHelperTools/yuzu-svc-helper"})
        self.assertEqual(header_constant(HEADER, "kFwHelperPath"), values["linux"]["FW_HELPER_PATH"])
        self.assertEqual(header_constant(HEADER, "kFwHelperPathMacos"), values["macos"]["FW_HELPER_PATH"])
        self.assertEqual(header_constant(SVC_HEADER, "kSvcHelperPathLinux"), values["linux"]["SVC_HELPER_PATH"])
        self.assertEqual(header_constant(SVC_HEADER, "kSvcHelperPathMacos"), values["macos"]["SVC_HELPER_PATH"])
        self.assertEqual(installer_helper_path(), header_helper_path())

    def test_no_sudoers_line_other_than_the_helpers_follows_a_helper_path_with_text(self):
        for g in self.grant_lines():
            self.assertNotRegex(g, r"yuzu-(?:fw|svc)-helper\S*\s+\S", g)
            self.assertNotRegex(g, r"HELPER_PATH\s+\S", g)

    def test_the_helpers_are_installed_before_the_sudoers_file_and_removed_and_checked(self):
        text = read_text(INSTALLER)
        dispatch = text[text.index('case "$ACTION" in'):]
        self.assertLess(dispatch.index("if install_helpers; then"), dispatch.index("install_sudoers"))
        self.assertIn("remove_helpers", dispatch)
        check = text[text.index("check_install() {"):text.index("# ── action dispatch")]
        self.assertIn("check_helpers ||", check)
        body = text[text.index("install_helper() {"):text.index("install_helpers() {")]
        self.assertIn("SKIP_SUDOERS", body)               # --no-sudoers skips it
        self.assertNotIn('"$PLATFORM"', body)              # both platforms
        for step in ("mktemp", 'chown "root:$ROOT_GROUP"', "chmod 0755", "sh -n", "mv -f"):
            self.assertIn(step, body)                      # temp file beside it, rename into place
        both = text[text.index("install_helpers() {"):text.index("remove_helpers() {")]
        self.assertIn('install_helper "$FW_HELPER_PATH" generate_fw_helper_content', both)
        self.assertIn('install_helper "$SVC_HELPER_PATH" generate_svc_helper_content', both)
        checks = text[text.index("check_helpers() {"):text.index("# ── linux capabilities")]
        self.assertIn('check_helper "$FW_HELPER_PATH" generate_fw_helper_content', checks)
        self.assertIn('check_helper "$SVC_HELPER_PATH" generate_svc_helper_content', checks)

    def test_the_helper_texts_have_no_eval_no_shell_no_command_substitution(self):
        for name, text in (("yuzu-fw-helper", helper_text()), ("yuzu-svc-helper", svc_helper_text())):
            code = code_lines(text)
            for needle in ("eval", "sh -c", "bash -c", "$(", "`", "$((", "source ", ". /"):
                self.assertNotIn(needle, code, name)
            self.assertTrue(text.startswith("#!/bin/sh\n"), name)
            self.assertIn("\nset -u\n", text, name)
            for prelude in ("\nPATH=/usr/sbin:/usr/bin:/sbin:/bin\n", "\nLC_ALL=C\n", "\nset -f\n", "\nIFS=' '\n"):
                self.assertIn(prelude, text, name)


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
                   "10.0.0.1/24/1", "10.0.0.1/0024", "10.0.0.1/08", "10.0.0.1/024", "10.0.0.1/000",
                   "10.0.0.1/032", "2001:db8::/032", "2001:db8::1/129", "2001:db8:::1", "2001:DB8::1",
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


GOLDEN_PF_RE = re.compile(r'kGoldenPfRuleset = R"PFGOLDEN\((.*?)\)PFGOLDEN";', re.S)


def golden_pf_ruleset():
    """The anchor ruleset the C++ unit test pins as pf_anchor_ruleset's output for a set that uses
    every rule form, read out of that test so the helper is run against the plugin's own text."""
    m = GOLDEN_PF_RE.search(read_text(PARSERS_TEST) or "")
    if not m:
        raise AssertionError("the golden pf ruleset is gone from " + PARSERS_TEST)
    return m.group(1)


class StagedLoadCase:
    """Shared harness (a mixin: the concrete cases below are the TestCases) for the helper's two
    file-taking actions, `nft load <path>` and `pf load <path>`, run with the tool replaced by a stub
    that prints its arguments and its standard input. The plugin's golden text comes out of the stub
    byte for byte; a file that is anything else, or a path that is not the staged shape, runs
    nothing. Run under each POSIX shell found (sh, dash, bash). The subclasses name the action, the
    suffix and the tool."""

    ACTION = None       # "nft" | "pf"
    SUFFIX = None       # ".nft" | ".pf"
    TOOL = None         # the exec target the helper names exactly once, replaced by a stub
    STUB_STEM = None    # "stub-nft" | "stub-pfctl"
    TOOL_ARGV = ()      # what the helper hands the tool, before its standard input

    @classmethod
    def golden_text(cls):
        raise NotImplementedError

    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.TemporaryDirectory(prefix="yuzu_test_fwhelper_")
        d = cls.tmp.name
        text = helper_text()
        assert text.count(cls.TOOL) == 1, "the helper must name %s exactly once" % cls.TOOL
        cls.helpers = {}
        for name, code in (("ok", 0), ("fail", 3)):
            stub = os.path.join(d, "%s-%s" % (cls.STUB_STEM, name))
            with open(stub, "w") as f:
                f.write("#!/bin/sh\nprintf 'RAN %s\\n' \"${0##*/}\"\nfor a; do printf '%s\\n' \"$a\"; done\n"
                        "cat\nexit " + str(code) + "\n")
            os.chmod(stub, 0o755)
            path = os.path.join(d, "yuzu-fw-helper-" + name)
            with open(path, "w") as f:
                f.write(text.replace(cls.TOOL, stub))
            cls.helpers[name] = path
        cls.stage = os.path.join(d, "var", "lib", "yuzu-agent", "firewall-staging")
        os.makedirs(cls.stage)
        cls.golden = cls.golden_text()
        cls.n = 0

    @classmethod
    def tearDownClass(cls):
        cls.tmp.cleanup()

    @classmethod
    def staged(cls, content):
        """A staged file holding `content` (str or bytes); its path."""
        cls.n += 1
        path = os.path.join(cls.stage, "yuzu-fwq-t%d%s" % (cls.n, cls.SUFFIX))
        with open(path, "wb") as f:
            f.write(content if isinstance(content, bytes) else content.encode())
        return path

    def want(self, ruleset=None, helper="ok"):
        head = "RAN %s-%s\n" % (self.STUB_STEM, helper) + "".join(a + "\n" for a in self.TOOL_ARGV)
        return (head + (self.golden if ruleset is None else ruleset)).encode()

    def run_load(self, shell, path, helper="ok", extra=(), env=None):
        return subprocess.run([shell, self.helpers[helper], self.ACTION, "load", path, *extra], capture_output=True,
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
        results = self.run_each([(sh, [self.ACTION, "load", path]) for sh in available_shells()])
        for sh, r in zip(available_shells(), results):
            self.assertNotEqual(r.returncode, 0, (sh, label))
            self.assertEqual(r.stdout, b"", (sh, label, "the tool ran"))
            self.assertEqual(r.stderr, b"yuzu-fw-helper: refused\n", (sh, label))

    def test_the_golden_text_reaches_the_tool_byte_for_byte_on_stdin_under_every_shell(self):
        self.assertTrue(self.golden.endswith("\n"))
        path = self.staged(self.golden)
        for sh in available_shells():
            r = self.run_load(sh, path)
            self.assertEqual((r.returncode, r.stdout, r.stderr), (0, self.want(), b""), sh)

    def test_the_helper_exits_with_the_tools_status(self):
        path = self.staged(self.golden)
        for sh in available_shells():
            r = self.run_load(sh, path, helper="fail")
            self.assertEqual((r.returncode, r.stdout), (3, self.want(helper="fail")), sh)

    def test_the_environment_cannot_change_what_runs(self):
        env = dict(os.environ, PATH="/nonexistent", IFS="-", ENV="/nonexistent", BASH_ENV="/nonexistent")
        path = self.staged(self.golden)
        for sh in available_shells():
            r = self.run_load(sh, path, env=env)
            self.assertEqual((r.returncode, r.stdout), (0, self.want()), sh)

    def test_a_nul_byte_in_the_file_never_reaches_the_tool(self):
        lines = self.golden.split("\n")
        for at in (0, 5, 6, 7, 20):
            lines2 = list(lines)
            lines2[at] = lines2[at][:4] + "\0" + lines2[at][4:]
            path = self.staged("\n".join(lines2))
            for sh in available_shells():
                r = self.run_load(sh, path)
                self.assertNotIn(b"\0", r.stdout, (sh, at))
                # either refused having run nothing, or the tool got the plugin's own text
                self.assertIn((r.returncode, r.stdout), ((64, b""), (0, self.want())), (sh, at))
        # a tail of NUL bytes and no newline: the shell drops it or reads it as an empty line
        path = self.staged(self.golden.encode() + b"\0" * 8)
        for sh in available_shells():
            r = self.run_load(sh, path)
            self.assertNotIn(b"\0", r.stdout, (sh, "nul tail"))
            self.assertIn((r.returncode, r.stdout), ((64, b""), (0, self.want())), (sh, "nul tail"))

    def test_a_link_a_fifo_a_directory_and_a_missing_file_run_nothing(self):
        good = self.staged(self.golden)
        link = os.path.join(self.stage, "yuzu-fwq-link" + self.SUFFIX)
        os.symlink(good, link)
        fifo = os.path.join(self.stage, "yuzu-fwq-fifo" + self.SUFFIX)
        os.mkfifo(fifo)
        directory = os.path.join(self.stage, "yuzu-fwq-dir" + self.SUFFIX)
        os.mkdir(directory)
        missing = os.path.join(self.stage, "yuzu-fwq-missing" + self.SUFFIX)
        for label, path in (("symlink", link), ("fifo", fifo), ("directory", directory), ("missing", missing)):
            for sh in available_shells():
                r = self.run_load(sh, path)   # a FIFO that was opened would block until the 30 s timeout
                self.assertNotEqual(r.returncode, 0, (sh, label))
                self.assertEqual(r.stdout, b"", (sh, label))
                self.assertEqual(r.stderr, b"yuzu-fw-helper: refused\n", (sh, label))

    def test_the_action_takes_exactly_three_arguments(self):
        good = self.staged(self.golden)
        a = self.ACTION
        calls = [[a], [a, "load"], [a, good], [a, "load", good, "extra"], [a, "load", good, ""],
                 [a, "-f", good], [a, "list", "table", "inet", "yuzu_quarantine"], [a, "delete", "table"],
                 [a, "LOAD", good], [a, "load ", good], [a, "", good], [a.upper(), "load", good],
                 [a, "save", good], [a, "load", "-f", good]]
        jobs = [(sh, c) for sh in available_shells() for c in calls]
        for (sh, c), r in zip(jobs, self.run_each(jobs)):
            self.assertNotEqual(r.returncode, 0, (sh, c))
            self.assertEqual(r.stdout, b"", (sh, c))

    def test_the_other_actions_staged_file_is_refused(self):
        """A file staged for the other tool, whatever it holds, is not this action's: the suffix is
        the action's own."""
        other = ".pf" if self.SUFFIX == ".nft" else ".nft"
        path = os.path.join(self.stage, "yuzu-fwq-other-%d%s" % (self.n + 1000, other))
        with open(path, "w") as f:
            f.write(self.golden)
        for sh in available_shells():
            r = self.run_load(sh, path)
            self.assertEqual((r.returncode, r.stdout, r.stderr), (64, b"", b"yuzu-fw-helper: refused\n"), sh)

    def test_a_path_outside_the_staged_shape_runs_nothing(self):
        good = self.staged(self.golden)
        name = os.path.basename(good)
        other_sfx = ".pf" if self.SUFFIX == ".nft" else ".nft"
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
            ("a leaf without the stem", os.path.join(self.stage, "t1" + self.SUFFIX)),
            ("a leaf with another suffix", os.path.join(self.stage, "yuzu-fwq-t1.txt")),
            ("a leaf with the other tool's suffix", os.path.join(self.stage, "yuzu-fwq-t1" + other_sfx)),
            ("a leaf with a cut-short suffix", os.path.join(self.stage, "yuzu-fwq-t1" + other_sfx + self.SUFFIX[:-1])),
            ("a leaf with nothing between", os.path.join(self.stage, "yuzu-fwq-" + self.SUFFIX)),
            ("a leaf with a space", os.path.join(self.stage, "yuzu-fwq-a b" + self.SUFFIX)),
            ("a leaf with a semicolon", os.path.join(self.stage, "yuzu-fwq-a;b" + self.SUFFIX)),
            ("a leaf with a glob", os.path.join(self.stage, "yuzu-fwq-*" + self.SUFFIX)),
            ("a leaf with a dollar", os.path.join(self.stage, "yuzu-fwq-$x" + self.SUFFIX)),
            ("a leaf with a newline", os.path.join(self.stage, "yuzu-fwq-a\nb" + self.SUFFIX)),
            ("a newline in the directory", os.path.join(self.tmp.name, "a\nb", "firewall-staging", name)),
            ("a control character", os.path.join(self.stage, "yuzu-fwq-a\x01b" + self.SUFFIX)),
            ("a DEL", os.path.join(self.stage, "yuzu-fwq-a\x7fb" + self.SUFFIX)),
            ("past 512 characters", "/" + "a" * 300 + "/firewall-staging/yuzu-fwq-" + "b" * 200 + self.SUFFIX),
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



@unittest.skipIf(sys.platform == "win32", "runs the helper under a POSIX shell")
class NftLoadRuns(StagedLoadCase, unittest.TestCase):
    """`yuzu-fw-helper nft load <path>`, run with nft replaced by a stub. The plugin's golden
    ruleset comes out of the stub byte for byte on `-f /dev/stdin`."""

    ACTION = "nft"
    SUFFIX = ".nft"
    TOOL = "/usr/sbin/nft"
    STUB_STEM = "stub-nft"
    TOOL_ARGV = ("-f", "/dev/stdin")

    @classmethod
    def golden_text(cls):
        return golden_ruleset()

    def test_the_golden_text_is_the_plugins_ruleset(self):
        self.assertTrue(self.golden.startswith("table inet yuzu_quarantine {}\n") and self.golden.endswith("\n}\n"))

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
            "a leading-zero prefix": g.replace("ip saddr 10.1.0.0/16", "ip saddr 10.1.0.0/016", 1),
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
            "an unterminated flush ruleset after the closing brace": g + "flush ruleset",
            "an unterminated tail past the byte cap": g + "x" * 300000,
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




@unittest.skipIf(sys.platform == "win32", "runs the helper under a POSIX shell")
class PfLoadRuns(StagedLoadCase, unittest.TestCase):
    """`yuzu-fw-helper pf load <path>` (macOS), run with pfctl replaced by a stub. The plugin's
    golden anchor ruleset comes out of the stub byte for byte after `-a
    com.apple/000.yuzu_quarantine -f /dev/stdin`; a file that is anything else, or a path that is
    not the staged shape, runs nothing."""

    ACTION = "pf"
    SUFFIX = ".pf"
    TOOL = "/sbin/pfctl"
    STUB_STEM = "stub-pfctl"
    TOOL_ARGV = ("-a", "com.apple/000.yuzu_quarantine", "-f", "/dev/stdin")

    @classmethod
    def golden_text(cls):
        return golden_pf_ruleset()

    CLOSING = "block drop quick all\n"

    def with_rule(self, rule):
        """The golden text with one more line in front of the closing line."""
        self.assertTrue(self.golden.endswith(self.CLOSING))
        return self.golden[:-len(self.CLOSING)] + rule + "\n" + self.CLOSING

    def mod(self, old, new):
        """The golden text with the first `old` replaced by `new` (which must change it)."""
        self.assertIn(old, self.golden)
        out = self.golden.replace(old, new, 1)
        self.assertNotEqual(out, self.golden)
        return out

    def test_the_golden_text_is_the_plugins_anchor_ruleset(self):
        self.assertTrue(self.golden.startswith("no nat all\nno rdr all\npass quick on lo0 all no state\n"))
        self.assertTrue(self.golden.endswith(self.CLOSING))
        self.assertEqual(self.golden.count(self.CLOSING), 1)

    def test_a_file_that_is_not_the_plugins_anchor_ruleset_runs_nothing(self):
        g = self.golden
        lines = g.split("\n")[:-1]
        RULE = "pass out quick inet proto udp from any to 203.0.113.53 port 53 keep state"
        CTRL_OUT = "pass out quick inet proto tcp from any to 198.51.100.7 port 50051 no state"
        CTRL_IN = "pass in quick inet proto tcp from 198.51.100.7 port 50051 to any no state"
        EX_IN = "pass in quick inet proto tcp from 10.0.0.5 to any port 22 keep state"
        cases = {
            "empty": "",
            "only the first line": lines[0] + "\n",
            "cut before the closing line": "\n".join(lines[:-1]) + "\n",
            "no final newline": g[:-1],
            "the closing line missing, a rule last": "\n".join(lines[:-1] + [RULE]) + "\n",
            "the closing line twice": g + self.CLOSING,
            "text after the closing line": g + "pass all\n",
            "an unterminated tail after the closing line": g + "pass all",
            "a blank line after the closing line": g + "\n",
            "a blank line inside": self.mod("no rdr all\n", "no rdr all\n\n"),
            "include at the top": 'include "/etc/passwd"\n' + g,
            "include as a rule": self.with_rule('include "/etc/x"'),
            "load anchor": self.with_rule('load anchor "x" from "/etc/pf.conf"'),
            "anchor": self.with_rule('anchor "x"'),
            "anchor with a rule": self.with_rule('anchor "x" all'),
            "a table": self.with_rule("table <t> { 10.0.0.1 }"),
            "a macro": self.with_rule('x = "1"'),
            "set skip": self.with_rule("set skip on lo0"),
            "set limit": self.with_rule("set limit states 10"),
            "a nat rule": self.with_rule("nat on en0 inet from any to any -> 10.0.0.1"),
            "an rdr rule": self.with_rule("rdr pass on lo0 proto tcp from any to any port 80 -> 127.0.0.1 port 8080"),
            "a scoped no nat": self.mod("no nat all\n", "no nat on en0 all\n"),
            "no nat repeated": self.mod("no nat all\n", "no nat all\nno nat all\n"),
            "no rdr before no nat": self.mod("no nat all\nno rdr all\n", "no rdr all\nno nat all\n"),
            "pass all": self.with_rule("pass all"),
            "pass quick all": self.with_rule("pass quick all"),
            "block all": self.with_rule("block all"),
            "a log pass": self.with_rule("pass log quick inet proto tcp from any to 10.0.0.1 port 22 keep state"),
            "another interface for the loopback line": self.mod("pass quick on lo0 all no state",
                                                                "pass quick on en0 all no state"),
            "a stateful loopback line": self.mod("pass quick on lo0 all no state", "pass quick on lo0 all keep state"),
            "the loopback line moved down": self.mod("pass quick on lo0 all no state\n", "")
                                            .replace(self.CLOSING, "pass quick on lo0 all no state\n" + self.CLOSING),
            "a host name": self.mod("to 203.0.113.53 port 53 keep state", "to example.com port 53 keep state"),
            "a list as the address": self.mod("to 203.0.113.53 port 53 keep state",
                                              "to { 10.0.0.1, 10.0.0.2 } port 53 keep state"),
            "a table as the address": self.mod("to 203.0.113.53 port 53 keep state", "to <t> port 53 keep state"),
            "any as the destination": self.mod("to 203.0.113.53 port 53 keep state", "to any port 53 keep state"),
            "a negated address": self.mod("to 203.0.113.53 port 53 keep state", "to ! 203.0.113.53 port 53 keep state"),
            "an interface as the address": self.mod("to 203.0.113.53 port 53 keep state", "to (en0) port 53 keep state"),
            "inet with an IPv6 address": self.mod("inet6 proto udp from any to 2001:4860:4860::8888",
                                                  "inet proto udp from any to 2001:4860:4860::8888"),
            "inet6 with an IPv4 address": self.mod("inet proto udp from any to 203.0.113.53",
                                                   "inet6 proto udp from any to 203.0.113.53"),
            "no family": self.mod("pass out quick inet proto udp from any to 203.0.113.53",
                                  "pass out quick proto udp from any to 203.0.113.53"),
            "proto icmp": self.mod("inet proto udp from any to 203.0.113.53", "inet proto icmp from any to 203.0.113.53"),
            "proto all": self.mod("inet proto udp from any to 203.0.113.53", "inet from any to 203.0.113.53"),
            "a numeric proto": self.mod("inet proto udp from any to 203.0.113.53", "inet proto 17 from any to 203.0.113.53"),
            "port 0": self.mod("to 203.0.113.53 port 53 keep state", "to 203.0.113.53 port 0 keep state"),
            "port 65536": self.mod("to 203.0.113.53 port 53 keep state", "to 203.0.113.53 port 65536 keep state"),
            "a leading-zero port": self.mod("to 203.0.113.53 port 53 keep state", "to 203.0.113.53 port 053 keep state"),
            "a port range": self.mod("to 203.0.113.53 port 53 keep state", "to 203.0.113.53 port 53:80 keep state"),
            "a named port": self.mod("to 203.0.113.53 port 53 keep state", "to 203.0.113.53 port domain keep state"),
            "a port list": self.mod("to 203.0.113.53 port 53 keep state", "to 203.0.113.53 port { 53, 80 } keep state"),
            "a port operator": self.mod("to 203.0.113.53 port 53 keep state", "to 203.0.113.53 port > 53 keep state"),
            "an octet past 255": self.mod("to 203.0.113.53 port 53 keep state", "to 999.1.1.1 port 53 keep state"),
            "a zero-padded octet": self.mod("to 203.0.113.53 port 53 keep state", "to 203.0.113.053 port 53 keep state"),
            "a short quad": self.mod("to 203.0.113.53 port 53 keep state", "to 203.0.53 port 53 keep state"),
            "a prefix past 32": self.mod("to 10.1.0.0/16 port 53", "to 10.1.0.0/33 port 53"),
            "a leading-zero prefix": self.mod("to 10.1.0.0/16 port 53", "to 10.1.0.0/016 port 53"),
            "an upper-case IPv6": self.mod("to 2001:4860:4860::8888", "to 2001:4860:4860::888A"),
            "an IPv6 prefix past 128": self.mod("from 2001:db8::/32 to any", "from 2001:db8::/129 to any"),
            "an interface-scoped address": self.mod("to 2001:db8::9 keep", "to fe80::1%en0 keep"),
            "a comment line": self.with_rule("# note"),
            "a trailing comment": self.mod(RULE, RULE + " # note"),
            "a tab": self.mod(RULE, RULE.replace("udp from", "udp\tfrom")),
            "a doubled space": self.mod(RULE, RULE.replace("udp from", "udp  from")),
            "a trailing space": self.mod(RULE, RULE + " "),
            "a leading space": self.mod(RULE, " " + RULE),
            "CRLF line ends": g.replace("\n", "\r\n"),
            "one CR": self.mod(RULE + "\n", RULE + "\r\n"),
            "a backslash continuation": self.mod(RULE + "\n", RULE.replace("udp from", "udp \\\nfrom") + "\n"),
            "modulate state": self.mod(RULE, RULE.replace("keep state", "modulate state")),
            "synproxy state": self.mod(CTRL_OUT, CTRL_OUT.replace("no state", "synproxy state")),
            "flags": self.mod(RULE, RULE.replace("keep state", "flags S/SA keep state")),
            "a label": self.mod(RULE, RULE + " label x"),
            "a tag": self.mod(RULE, RULE + " tag x"),
            "a user": self.mod(RULE, RULE.replace("keep state", "user root keep state")),
            "a queue": self.mod(RULE, RULE + " queue q"),
            "an extra word": self.mod(RULE, RULE + " all"),
            "keep state spelled with one word": self.mod(RULE, RULE.replace("keep state", "keepstate")),
            "no state on a udp rule": self.mod(RULE, RULE.replace("keep state", "no state")),
            "no state without a port": self.mod(CTRL_OUT, CTRL_OUT.replace(" port 50051", "")),
            "the in control line with the exception layout":
                self.mod(CTRL_IN, "pass in quick inet proto tcp from 198.51.100.7 to any port 50051 no state"),
            "the in exception line with the control layout":
                self.mod(EX_IN, "pass in quick inet proto tcp from 10.0.0.5 port 22 to any keep state"),
            "an out line with the in layout": self.mod(RULE, "pass out quick inet proto udp from 203.0.113.53 to any "
                                                             "port 53 keep state"),
            "an in line with the out layout": self.mod(EX_IN, "pass in quick inet proto tcp from any to 10.0.0.5 "
                                                              "port 22 keep state"),
            "a direction other than in and out": self.mod(RULE, RULE.replace("pass out", "pass on")),
            "no direction": self.mod(RULE, RULE.replace("pass out ", "pass ")),
            "not quick": self.mod(RULE, RULE.replace(" quick", "")),
            "block instead of pass": self.mod(RULE, RULE.replace("pass out", "block out")),
            "a source port on an out line": self.mod(RULE, RULE.replace("from any to", "from any port 1024 to")),
            "the nd line with a sixth type": self.mod("{ 133, 134, 135, 136 }", "{ 133, 134, 135, 136, 137 }"),
            "the nd line with a missing type": self.mod("{ 133, 134, 135, 136 }", "{ 133, 134, 135 }"),
            "the nd line for inet": self.mod("pass quick inet6 proto icmp6", "pass quick inet proto icmp6"),
            "the dhcp line toward any": self.mod("to 255.255.255.255 port 67", "to any port 67"),
            "the dhcp reply from another port": self.mod("from any port 67 to any port 68", "from any port 68 to any port 68"),
            "the closing line with a log": self.mod(self.CLOSING, "block drop quick all log\n"),
            "block drop all as the closing line": self.mod(self.CLOSING, "block drop all\n"),
            "block return as the closing line": self.mod(self.CLOSING, "block return quick all\n"),
            "an indented closing line": self.mod(self.CLOSING, " block drop quick all\n"),
            "text after the closing line on its own line": g + "anchor \"x\"\n",
            "an unterminated flush after the closing brace": g + "flush",
            "the whole ruleset twice": g + g,
            "an unterminated tail past the byte cap": g + "x" * 300000,
            "a root-only line marker": self.with_rule("ROOT-ONLY-SECRET-LINE"),
        }
        for label, content in cases.items():
            with self.subTest(label):
                self.refused(content, label)

    def test_nothing_from_a_refused_file_is_printed(self):
        path = self.staged(self.with_rule("ROOT-ONLY-SECRET-LINE"))
        for sh in available_shells():
            r = self.run_load(sh, path)
            self.assertNotIn(b"SECRET", r.stdout + r.stderr, sh)

    def test_the_line_caps_are_512_lines_of_512_characters(self):
        g = self.golden.split("\n")[:-1]
        rule = "pass out quick inet proto tcp from any to 10.0.0.1 port 22 keep state"
        def padded(n):
            return "\n".join(g[:-1] + [rule] * n + g[-1:]) + "\n"
        edge = 512 - len(g)
        # 512 lines is accepted, 513 is not (every line in both is otherwise valid)
        text512 = padded(edge)
        self.assertEqual(text512.count("\n"), 512)
        path = self.staged(text512)
        for sh in available_shells():
            r = self.run_load(sh, path)
            self.assertEqual((r.returncode, r.stdout), (0, self.want(text512)), sh)
        self.refused(padded(edge + 1), "513 lines")
        # a 513-character line, and a 512-character one that is not a rule (a valid line is far shorter)
        line = self.golden.split("\n")[3]
        self.refused(self.mod(line, line + " " * (513 - len(line))), "a 513-character line")
        self.refused(self.mod(line, line + " " * (512 - len(line))), "a 512-character line that is not a rule")
        self.refused(self.with_rule("a" * 512), "a 512-character junk line")
        self.refused("x" * 300000, "a file past the byte cap, one line")

    def test_every_rule_form_is_accepted_wherever_the_plugin_puts_it(self):
        forms = [
            "pass out quick inet proto tcp from any to 255.255.255.255 port 65535 keep state",
            "pass out quick inet proto udp from any to 0.0.0.0/0 keep state",
            "pass in quick inet6 proto tcp from ::/0 to any port 1 keep state",
            "pass out quick inet6 proto udp from any to ::1 port 53 keep state",
            "pass out quick inet proto tcp from any to 10.0.0.0/32 port 1 no state",
            "pass in quick inet6 proto tcp from 2001:db8::1 port 443 to any no state",
            "pass in quick inet proto udp from 10.1.0.0/16 to any keep state",
            "pass in quick inet proto udp from 10.1.0.0/16 to any port 65535 keep state",
            "pass out quick inet6 proto tcp from any to 2001:db8::/128 port 8443 no state",
        ]
        for form in forms:
            text = self.with_rule(form)
            path = self.staged(text)
            for sh in available_shells():
                r = self.run_load(sh, path)
                self.assertEqual((r.returncode, r.stdout), (0, self.want(text)), (sh, form))

    def test_a_staging_directory_with_a_space_works(self):
        """The packaged macOS data directory contains a space (/Library/Application Support/Yuzu):
        the staged path travels as one argument and the shape check does not split it."""
        spaced = os.path.join(self.tmp.name, "Library", "Application Support", "Yuzu", "firewall-staging")
        os.makedirs(spaced)
        path = os.path.join(spaced, "yuzu-fwq-AbC123.pf")
        with open(path, "w") as f:
            f.write(self.golden)
        for sh in available_shells():
            r = self.run_load(sh, path)
            self.assertEqual((r.returncode, r.stdout, r.stderr), (0, self.want(), b""), sh)

    @unittest.skipUnless(sys.platform == "darwin" and os.path.exists("/sbin/pfctl"),
                         "parses the text with the real pfctl, which only a Mac has")
    def test_the_golden_text_and_every_accepted_form_parse_under_the_real_pfctl(self):
        """`pfctl -n` parses and loads nothing. The helper hands pfctl a ruleset it rebuilt itself,
        and what it rebuilt is what the plugin generates, so the plugin's own text must be text the
        real tool accepts."""
        texts = [("the golden text", self.golden)]
        for form in ("pass out quick inet proto tcp from any to 10.0.0.0/32 port 1 no state",
                     "pass in quick inet6 proto tcp from 2001:db8::1 port 443 to any no state",
                     "pass in quick inet proto udp from 10.1.0.0/16 to any keep state"):
            texts.append((form, self.with_rule(form)))
        for label, text in texts:
            r = subprocess.run(["/sbin/pfctl", "-n", "-a", "com.apple/000.yuzu_quarantine", "-f", "/dev/stdin"],
                               input=text.encode(), capture_output=True, timeout=30)
            self.assertEqual(r.returncode, 0, (label, r.stdout, r.stderr))


@unittest.skipIf(sys.platform == "win32", "runs the helper under a POSIX shell")
class SvcHelperRuns(unittest.TestCase):
    """`yuzu-svc-helper`, run with systemctl and launchctl replaced by stubs that print their
    arguments. Every accepted shape reproduces its exact argument list; everything else exits
    non-zero having run nothing. Run under each POSIX shell found (sh, dash, bash): the helper must
    not depend on a bash extension."""

    VERBS = ("enable", "disable", "mask", "unmask")
    NAMES = ("cron.service", "getty@tty1.service", "-foo", "a", "a" * 256, "A.b_c-d@e", "0", "--now",
             "com.apple.something", "-")
    REFUSED_LINE = b"yuzu-svc-helper: refused\n"

    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.TemporaryDirectory(prefix="yuzu_test_svchelper_")
        d = cls.tmp.name
        text = svc_helper_text()
        code = code_lines(text)
        assert code.count("/usr/bin/systemctl") == 2 and code.count("/bin/launchctl") == 2, \
            "the helper names each tool path only as its exec target"

        def stub(name):
            path = os.path.join(d, name)
            with open(path, "w") as f:
                f.write("#!/bin/sh\nprintf 'RAN %s\\n' \"${0##*/}\"\nfor a; do printf '%s\\n' \"$a\"; done\n")
            os.chmod(path, 0o755)
            return path

        primary, fallback, launchctl = stub("stub-systemctl-usr"), stub("stub-systemctl-bin"), stub("stub-launchctl")
        missing = os.path.join(d, "no-such-systemctl")

        def build(name, usr_bin, bin_):
            # /usr/bin/systemctl first: /bin/systemctl is a substring of it
            t = text.replace("/usr/bin/systemctl", usr_bin).replace("/bin/systemctl", bin_)
            t = t.replace("/bin/launchctl", launchctl)
            path = os.path.join(d, name)
            with open(path, "w") as f:
                f.write(t)
            return path

        cls.path = build("yuzu-svc-helper", primary, fallback)
        cls.path_no_primary = build("yuzu-svc-helper-fallback", missing, fallback)

    @classmethod
    def tearDownClass(cls):
        cls.tmp.cleanup()

    def run_helper(self, shell, args, path=None, env=None):
        return subprocess.run([shell, path or self.path, *args], capture_output=True, timeout=30, env=env)

    def run_each(self, jobs, path=None):
        def one(job):
            return self.run_helper(job[0], job[1], path)
        with ThreadPoolExecutor(max_workers=8) as pool:
            return list(pool.map(one, jobs))

    def test_the_helper_passes_a_syntax_check_under_every_shell(self):
        for shell in available_shells():
            r = subprocess.run([shell, "-n", self.path], capture_output=True, text=True, timeout=30)
            self.assertEqual((r.returncode, r.stderr), (0, ""), shell)

    def test_systemctl_runs_with_the_verb_then_double_dash_then_the_name(self):
        jobs = [(sh, ["systemctl", v, n]) for sh in available_shells() for v in self.VERBS for n in self.NAMES]
        for (sh, args), r in zip(jobs, self.run_each(jobs)):
            want = ("RAN stub-systemctl-usr\n%s\n--\n%s\n" % (args[1], args[2])).encode()
            self.assertEqual((r.returncode, r.stdout, r.stderr), (0, want, b""), (sh, args))

    def test_systemctl_falls_back_to_the_other_path_only_when_the_first_is_not_executable(self):
        jobs = [(sh, ["systemctl", v, "cron.service"]) for sh in available_shells() for v in self.VERBS]
        for (sh, args), r in zip(jobs, self.run_each(jobs, self.path_no_primary)):
            want = ("RAN stub-systemctl-bin\n%s\n--\ncron.service\n" % args[1]).encode()
            self.assertEqual((r.returncode, r.stdout, r.stderr), (0, want, b""), (sh, args))

    def test_launchctl_runs_with_the_verb_and_the_system_target(self):
        jobs = [(sh, ["launchctl", v, n]) for sh in available_shells() for v in ("enable", "disable")
                for n in self.NAMES]
        for (sh, args), r in zip(jobs, self.run_each(jobs)):
            want = ("RAN stub-launchctl\n%s\nsystem/%s\n" % (args[1], args[2])).encode()
            self.assertEqual((r.returncode, r.stdout, r.stderr), (0, want, b""), (sh, args))

    def test_a_name_that_is_option_shaped_is_one_argument_after_the_double_dash(self):
        for sh in available_shells():
            r = self.run_helper(sh, ["systemctl", "enable", "--now"])
            self.assertEqual(r.stdout, b"RAN stub-systemctl-usr\nenable\n--\n--now\n", sh)

    def refused(self, args, label=None, path=None):
        jobs = [(sh, list(args)) for sh in available_shells()]
        for (sh, a), r in zip(jobs, self.run_each(jobs, path)):
            self.assertNotEqual(r.returncode, 0, (sh, label or a))
            self.assertEqual(r.stdout, b"", (sh, label or a, "a tool ran"))
            self.assertEqual(r.stderr, self.REFUSED_LINE, (sh, label or a))

    def test_a_name_outside_the_class_or_the_length_runs_nothing(self):
        bad = ["a" * 257, "a" * 300, "", "/", "a/b", "system/foo", "a b", " a", "a ", "--root=/x", "a=b", "a;b",
               "a|b", "a&b", "a$b", "$x", "`x`", "$(x)", "a\nb", "\nfoo", "foo\n", "a\tb", "a*", "*", "?", "[a]", "{a}",
               "a\\b", "a'b", 'a"b', "a,b", "a:b", "é", "!", "~", "#", "%", "+",
               "/Library/LaunchDaemons/x.plist", "../x", "x/../y", "a\r"]
        for tool, verb in (("systemctl", "enable"), ("systemctl", "mask"), ("launchctl", "enable"),
                           ("launchctl", "disable")):
            for name in bad:
                self.refused([tool, verb, name], (tool, verb, name))

    def test_a_verb_outside_the_granted_ones_runs_nothing(self):
        for verb in ("start", "stop", "restart", "reload", "edit", "link", "daemon-reload", "set-default", "kill",
                     "preset", "revoke", "is-enabled", "status", "cat", "show", "list-units", "poweroff", "reboot",
                     "isolate", "import-environment", "ENABLE", "Enable", "enable ", " enable", "--help", "-h", "",
                     "--root=/x", "--now", "--system", "-t", "enable;", "disable|", "mask\n"):
            self.refused(["systemctl", verb, "cron.service"], ("systemctl", verb))
        for verb in ("bootstrap", "bootout", "kickstart", "kill", "load", "unload", "print", "print-disabled",
                     "list", "submit", "remove", "start", "stop", "blame", "reboot", "ENABLE", "mask", "unmask",
                     "enable ", "", "--help"):
            self.refused(["launchctl", verb, "com.example.agent"], ("launchctl", verb))

    def test_a_verb_of_the_other_family_runs_nothing(self):
        # mask and unmask are systemctl's; launchd has no such state
        self.refused(["launchctl", "mask", "com.example.agent"])
        self.refused(["launchctl", "unmask", "com.example.agent"])

    def test_the_argument_count_is_exactly_three(self):
        calls = [[], ["systemctl"], ["systemctl", "enable"], ["launchctl", "enable"],
                 ["systemctl", "enable", "cron.service", "extra"], ["systemctl", "enable", "cron.service", "--now"],
                 ["systemctl", "enable", "--now", "cron.service"], ["systemctl", "--now", "enable", "cron.service"],
                 ["systemctl", "enable", "cron.service", ""], ["launchctl", "enable", "x", "y"],
                 ["launchctl", "enable", "x", "system/y"], ["systemctl", "enable", "-- ", "cron.service"],
                 ["systemctl", "enable", "a", "b", "c", "d"], ["", "", ""], ["systemctl", "", ""]]
        for c in calls:
            self.refused(c)

    def test_another_tool_family_runs_nothing(self):
        for family in ("service", "sc", "rc-service", "init", "sudo", "sh", "bash", "rm", "systemctl ", " systemctl",
                       "SYSTEMCTL", "Systemctl", "launchctl ", "/usr/bin/systemctl", "/bin/launchctl", "systemd",
                       "journalctl", "loginctl", "iptables", "nft", "pfctl", ""):
            self.refused([family, "enable", "cron.service"], family)

    def test_the_environment_cannot_change_what_runs(self):
        env = dict(os.environ, PATH="/nonexistent", IFS="-", ENV="/nonexistent", BASH_ENV="/nonexistent",
                   LC_ALL="en_US.UTF-8")
        for sh in available_shells():
            r = self.run_helper(sh, ["systemctl", "disable", "cron.service"], env=env)
            self.assertEqual((r.returncode, r.stdout), (0, b"RAN stub-systemctl-usr\ndisable\n--\ncron.service\n"), sh)
            r = self.run_helper(sh, ["launchctl", "disable", "com.example.agent"], env=env)
            self.assertEqual((r.returncode, r.stdout), (0, b"RAN stub-launchctl\ndisable\nsystem/com.example.agent\n"), sh)

    def test_a_glob_in_the_working_directory_is_never_expanded(self):
        with tempfile.TemporaryDirectory(prefix="yuzu_test_svchelper_") as d:
            for n in ("a", "b"):
                open(os.path.join(d, n), "w").close()
            for sh in available_shells():
                r = subprocess.run([sh, self.path, "systemctl", "enable", "*"], capture_output=True, timeout=30, cwd=d)
                self.assertNotEqual(r.returncode, 0, sh)
                self.assertEqual(r.stdout, b"", sh)

    def test_the_name_is_checked_before_the_tool_or_the_verb(self):
        """A bad name is refused whatever the other arguments are: nothing about the tool is read first."""
        for args in (["systemctl", "start", "a b"], ["launchctl", "bootout", "a/b"], ["nonsense", "x", "a;b"]):
            self.refused(args)


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

    def test_the_installer_and_the_check_apply_it(self):
        text = read_text(INSTALLER)
        install = text[text.index("install_helper() {"):text.index("install_helpers() {")]
        self.assertLess(install.index("check_helper_dir"), install.index("mktemp"))      # stop before writing
        check = text[text.index("check_helper() {"):text.index("check_helpers() {")]
        self.assertIn("check_helper_dir", check)

    def test_the_stat_form_is_chosen_by_platform_never_by_trying_one_after_the_other(self):
        """On GNU stat `-f` means file-system status, so a `stat -f ... || stat -c ...` chain would
        take the first answer on Linux and it would be the wrong one."""
        text = read_text(INSTALLER)
        for fn in ("dir_info() {", "file_owner_mode() {"):
            body = text[text.index(fn):]
            body = body[:body.index("\n}\n")]
            self.assertIn('[[ "$PLATFORM" == "macos" ]]', body, fn)
            self.assertNotRegex(body, r"stat[^\n]*\|\|", fn)
        # And nowhere else in the installer (`check_install` once chained `stat -f ... || stat -c ...`).
        self.assertNotRegex(text, r"\bstat +-[^\n]*\|\|")
        self.assertIn("stat -L -f '%u %Lp %Sg'", text)
        self.assertIn("stat -L -c '%u %a %G'", text)
        self.assertIn("stat -f '%Su:%Sg %Lp'", text)
        self.assertIn("stat -c '%U:%G %a'", text)


@unittest.skipIf(sys.platform == "win32", "runs the installer under bash")
class RenderedSudoers(unittest.TestCase):
    """The sudoers text the installer renders for each platform (`--dry-run` with a `uname` that says
    so). No grant line takes a wildcard: a helper named with no argument, or a fixed command, or on
    macOS the 24 `pfctl -X` lines that pin the release token's length one bracket class per digit."""

    HELPERS = {
        "linux": ("/usr/local/sbin/yuzu-fw-helper", "/usr/local/sbin/yuzu-svc-helper", "yuzu"),
        "macos": ("/Library/PrivilegedHelperTools/yuzu-fw-helper", "/Library/PrivilegedHelperTools/yuzu-svc-helper",
                  "_yuzu"),
    }

    @classmethod
    def setUpClass(cls):
        cls.grants = {p: rendered_grants(p) for p in cls.HELPERS}
        cls.text = {p: rendered_sudoers(p) for p in cls.HELPERS}

    def test_the_helper_lines_are_exactly_the_helper_with_no_argument_and_no_wildcard(self):
        for platform, (fw, svc, acct) in self.HELPERS.items():
            lines = self.grants[platform]
            self.assertEqual([l for l in lines if "yuzu-fw-helper" in l],
                             ["%s ALL=(root) NOPASSWD: %s" % (acct, fw)], platform)
            self.assertEqual([l for l in lines if "yuzu-svc-helper" in l],
                             ["%s ALL=(root) NOPASSWD: %s" % (acct, svc)], platform)

    def test_no_grant_line_has_a_star_or_a_question_mark(self):
        for platform, lines in self.grants.items():
            self.assertGreater(len(lines), 5, platform)
            for g in lines:
                self.assertNotIn("*", g, (platform, g))
                self.assertNotIn("?", g, (platform, g))

    def test_no_grant_line_names_systemctl_launchctl_or_security(self):
        for platform, lines in self.grants.items():
            for g in lines:
                self.assertNotRegex(g, r"\b(?:systemctl|launchctl|security)\b", (platform, g))
            # the sudoers text does not grant them in a comment either
            for l in self.text[platform].splitlines():
                if not l.lstrip().startswith("#"):
                    self.assertNotRegex(l, r"\b(?:systemctl|launchctl|security)\b", (platform, l))

    def test_a_bracket_class_appears_only_on_the_pfctl_release_lines_and_there_are_24(self):
        self.assertEqual([g for g in self.grants["linux"] if "[" in g], [])
        mac = self.grants["macos"]
        self.assertEqual([g for g in mac if "[" in g and "/sbin/pfctl -X " not in g], [])
        cls = "[0123456789]"
        want = ["_yuzu ALL=(root) NOPASSWD: /sbin/pfctl -X " + cls * n for n in range(1, 25)]
        self.assertEqual([g for g in mac if "/sbin/pfctl -X" in g], want)
        # the n-th line ends after its n classes, and no line has a character class of anything else
        for g in mac:
            if "[" in g:
                self.assertRegex(g, r"^_yuzu ALL=\(root\) NOPASSWD: /sbin/pfctl -X (?:\[0123456789\]){1,24}$")

    def test_no_pfctl_line_has_a_wildcard_and_there_is_no_bare_pfctl(self):
        for g in self.grants["macos"]:
            if "pfctl" in g:
                self.assertNotIn("*", g)
                self.assertNotIn("?", g)
        self.assertEqual([g for g in self.grants["macos"] if re.search(r"NOPASSWD:\s*/sbin/pfctl\s*$", g)], [])
        self.assertEqual([g for g in self.grants["macos"] if re.search(r"pfctl.* -f\b", g)], [],
                         "no pfctl grant takes a file name; the helper loads the anchor")
        self.assertEqual([g for g in self.grants["linux"] if "pfctl" in g], [])

    def test_the_whole_grant_list_per_platform(self):
        cls = "[0123456789]"
        lin = ["yuzu ALL=(root) NOPASSWD: /usr/local/sbin/yuzu-fw-helper",
               "yuzu ALL=(root) NOPASSWD: /usr/sbin/nft delete table inet yuzu_quarantine",
               "yuzu ALL=(root) NOPASSWD: /usr/sbin/nft list table inet yuzu_quarantine",
               "yuzu ALL=(root) NOPASSWD: /usr/local/sbin/yuzu-svc-helper",
               "yuzu ALL=(root) NOPASSWD: /usr/bin/systemd-resolve --flush-caches",
               "yuzu ALL=(root) NOPASSWD: /usr/bin/resolvectl flush-caches"]
        self.assertEqual(self.grants["linux"], lin)
        p = "_yuzu ALL=(root) NOPASSWD: "
        mac = ([p + "/Library/PrivilegedHelperTools/yuzu-fw-helper", p + "/sbin/pfctl -E"]
               + [p + "/sbin/pfctl -X " + cls * n for n in range(1, 25)]
               + [p + "/sbin/pfctl -a com.apple/000.yuzu_quarantine -F rules",
                  p + "/sbin/pfctl -a com.apple/000.yuzu_quarantine -F nat",
                  p + "/sbin/pfctl -a com.apple/000.yuzu_quarantine -s rules",
                  p + "/sbin/pfctl -a com.apple -s Anchors",
                  p + "/sbin/pfctl -F states",
                  p + "/sbin/pfctl -s info",
                  p + "/sbin/pfctl -s rules",
                  p + "/sbin/pfctl -s References",
                  p + "/Library/PrivilegedHelperTools/yuzu-svc-helper",
                  p + "/usr/bin/dscacheutil -flushcache",
                  p + "/usr/bin/killall -HUP mDNSResponder"])
        self.assertEqual(self.grants["macos"], mac)

    @unittest.skipUnless(shutil.which("visudo"), "visudo is not installed")
    def test_visudo_accepts_the_rendered_text_of_each_platform(self):
        for platform, text in self.text.items():
            with tempfile.TemporaryDirectory(prefix="yuzu_test_sudoers_") as d:
                path = os.path.join(d, "yuzu-agent")
                with open(path, "w") as f:
                    f.write(text)
                r = subprocess.run(["visudo", "-cf", path], capture_output=True, text=True, timeout=30)
                self.assertEqual(r.returncode, 0, (platform, r.stdout, r.stderr))

    def test_requiretty_is_written_only_when_this_hosts_visudo_accepts_it(self):
        # sudo-rs rejects the whole file over `!requiretty`; sudo and the classic visudo accept it.
        for platform in self.text:
            accepted = render_installer(platform, visudo="exit 0")
            refused = render_installer(platform, visudo='grep -q requiretty "$2" && exit 1; exit 0')
            self.assertIn("!requiretty", accepted, platform)
            self.assertNotIn("requiretty", refused, platform)
            self.assertIn('env_keep += "YUZU_*"', refused, platform)

    def test_the_comments_say_what_the_grants_are_and_that_the_installer_is_rerun(self):
        for platform, text in self.text.items():
            self.assertIn("installer is re-run", text, platform)
            self.assertNotRegex(text, r"(?i)exploit|root-equivalent|vulnerab", platform)


@unittest.skipIf(sys.platform == "win32", "runs the installer under bash")
class InstallerDryRun(unittest.TestCase):
    """The installer under `--dry-run` with a `uname` that says each platform (a dry run only
    prints): both helpers are written BEFORE the sudoers file, each is the text its heredoc holds,
    and `--no-sudoers` skips all three."""

    PLATFORMS = {
        "linux": ("root", "/usr/local/sbin/yuzu-fw-helper", "/usr/local/sbin/yuzu-svc-helper"),
        "macos": ("wheel", "/Library/PrivilegedHelperTools/yuzu-fw-helper",
                  "/Library/PrivilegedHelperTools/yuzu-svc-helper"),
    }

    def markers(self, platform):
        group, fw, svc = self.PLATFORMS[platform]
        return ("[dry-run] would write the following to %s (root:%s 0755):" % (fw, group),
                "[dry-run] would write the following to %s (root:%s 0755):" % (svc, group),
                "[dry-run] would write the following to /etc/sudoers.d/yuzu-agent:")

    def test_both_helpers_are_printed_before_the_sudoers_file_and_are_the_heredoc_texts(self):
        for platform in self.PLATFORMS:
            out = render_installer(platform)
            fw_marker, svc_marker, sudoers_marker = self.markers(platform)
            for m in (fw_marker, svc_marker, sudoers_marker):
                self.assertEqual(out.count(m), 1, (platform, m))
            self.assertLess(out.index(fw_marker), out.index(sudoers_marker), platform)
            self.assertLess(out.index(svc_marker), out.index(sudoers_marker), platform)
            self.assertEqual(rendered_section(out, fw_marker), helper_text(), platform)
            self.assertEqual(rendered_section(out, svc_marker), svc_helper_text(), platform)

    def test_no_sudoers_skips_both_helpers_and_the_sudoers_file(self):
        for platform in self.PLATFORMS:
            out = render_installer(platform, "--no-sudoers")
            self.assertNotIn("yuzu-fw-helper", out, platform)
            self.assertNotIn("yuzu-svc-helper", out, platform)
            self.assertNotIn("/etc/sudoers.d/yuzu-agent:", out, platform)

    def test_the_sudoers_file_names_the_helpers_it_was_rendered_with(self):
        for platform, (group, fw, svc) in self.PLATFORMS.items():
            out = render_installer(platform)
            acct = "yuzu" if platform == "linux" else "_yuzu"
            self.assertIn("[dry-run]   %s ALL=(root) NOPASSWD: %s\n" % (acct, fw), out, platform)
            self.assertIn("[dry-run]   %s ALL=(root) NOPASSWD: %s\n" % (acct, svc), out, platform)
            self.assertNotRegex(out, r"NOPASSWD: /usr/sbin/ip6?tables", platform)


@unittest.skipIf(sys.platform == "win32", "runs the installer under bash")
class InstallerFailedHelper(unittest.TestCase):
    """The installer's real install dispatch, run from a copy with the account, state-directory and
    setcap steps stubbed and every path pointed into a temporary directory: the sudoers file is
    written only when both helpers were installed in the run. When one was not, the file is removed
    (an earlier file's lines included), `install_sudoers` is never reached and the run exits 1; a
    sudoers file that fails to install removes any earlier file too and ends the run with its own
    status and no "install complete"."""

    BASH = "/bin/bash" if os.path.exists("/bin/bash") else "bash"   # macOS: 3.2, the oldest the installer meets
    ANCHOR = 'case "$ACTION" in\n    install)\n'
    MARK = "# yuzu-test-splice"
    EARLIER = "yuzu ALL=(root) NOPASSWD: /usr/sbin/iptables *\n"

    @classmethod
    def setUpClass(cls):
        cls.text = read_text(INSTALLER)
        assert cls.text is not None and cls.text.count(cls.ANCHOR) == 1, "the install dispatch moved"

    def run_install(self, d, helper_dir_mode=None, sudoers_rc=0, stubs=""):
        """Runs the install dispatch. helper_dir_mode None: a directory the verdict accepts (its
        owner and mode are stubbed), else the directory is created with that mode and judged as it
        is. Returns (returncode, stdout, stderr, install_sudoers_was_reached, helper_dir)."""
        helper_dir = os.path.join(d, "helpers")
        os.mkdir(helper_dir)
        if helper_dir_mode is not None:
            os.chmod(helper_dir, helper_dir_mode)
        calls = os.path.join(d, "calls")
        sudoers = os.path.join(d, "yuzu-agent")
        stub = "\n".join([
            self.MARK,
            "require_root() { :; }",
            "macos_create_user() { :; }",
            "linux_user_exists() { return 0; }",
            "create_state_dirs() { :; }",
            "apply_setcap() { :; }",
            "chown() { :; }",
            "SUDOERS_FILE='%s'" % sudoers,
            "FW_HELPER_PATH='%s'" % os.path.join(helper_dir, "yuzu-fw-helper"),
            "SVC_HELPER_PATH='%s'" % os.path.join(helper_dir, "yuzu-svc-helper"),
            "install_sudoers() { echo install_sudoers >> '%s'; return %d; }" % (calls, sudoers_rc),
            "" if helper_dir_mode is not None else "dir_info() { echo '0 755 root'; }",
            stubs,
            "",
        ])
        spliced = self.text.replace(self.ANCHOR, stub + self.ANCHOR, 1)
        # An unspliced copy is the real installer, and CI may run as root: never run one.
        self.assertEqual(spliced.count(self.MARK), 1)
        script = os.path.join(d, "install.sh")
        with open(script, "w") as f:
            f.write(spliced)
        r = subprocess.run([self.BASH, script], capture_output=True, text=True, timeout=120)
        reached = os.path.exists(calls)
        return r.returncode, r.stdout, r.stderr, reached, helper_dir

    def seed_sudoers(self, d):
        path = os.path.join(d, "yuzu-agent")
        with open(path, "w") as f:
            f.write(self.EARLIER)
        return path

    def test_a_refused_helper_directory_removes_the_sudoers_file_and_fails_the_run(self):
        with tempfile.TemporaryDirectory(prefix="yuzu_test_installer_") as d:
            sudoers = self.seed_sudoers(d)
            rc, out, err, reached, helper_dir = self.run_install(d, helper_dir_mode=0o777)
            self.assertEqual(rc, 1, (out, err))
            self.assertFalse(os.path.exists(sudoers), "the earlier file's lines must not stay")
            self.assertFalse(reached, "install_sudoers must not be reached")
            self.assertEqual(os.listdir(helper_dir), [], "no helper, and no temporary file")
            self.assertIn("was removed", err)
            self.assertNotIn("install complete", out)

    def test_one_failed_helper_removes_the_sudoers_file_and_the_other_stays(self):
        with tempfile.TemporaryDirectory(prefix="yuzu_test_installer_") as d:
            sudoers = self.seed_sudoers(d)
            rc, out, err, reached, helper_dir = self.run_install(
                d, stubs="generate_svc_helper_content() { return 1; }")
            self.assertEqual(rc, 1, (out, err))
            self.assertFalse(os.path.exists(sudoers))
            self.assertFalse(reached)
            self.assertEqual(os.listdir(helper_dir), ["yuzu-fw-helper"])
            self.assertIn("was removed", err)
            self.assertNotIn("install complete", out)

    def test_a_file_that_cannot_be_removed_is_reported_as_such(self):
        with tempfile.TemporaryDirectory(prefix="yuzu_test_installer_") as d:
            os.mkdir(os.path.join(d, "yuzu-agent"))   # not a file: remove_sudoers leaves it
            rc, out, err, reached, _ = self.run_install(d, helper_dir_mode=0o777)
            self.assertEqual(rc, 1, (out, err))
            self.assertFalse(reached)
            self.assertIn("could not be removed", err)
            self.assertNotIn("was removed", err)

    def test_both_helpers_installed_reaches_install_sudoers_and_completes(self):
        with tempfile.TemporaryDirectory(prefix="yuzu_test_installer_") as d:
            sudoers = self.seed_sudoers(d)
            rc, out, err, reached, helper_dir = self.run_install(d)
            self.assertEqual(rc, 0, (out, err))
            self.assertTrue(reached)
            self.assertTrue(os.path.exists(sudoers), "only a failed helper removes the file")
            self.assertEqual(sorted(os.listdir(helper_dir)), ["yuzu-fw-helper", "yuzu-svc-helper"])
            self.assertIn("install complete", out)

    def test_a_sudoers_file_that_fails_to_install_ends_the_run_with_its_status(self):
        with tempfile.TemporaryDirectory(prefix="yuzu_test_installer_") as d:
            sudoers = self.seed_sudoers(d)
            rc, out, err, reached, _ = self.run_install(d, sudoers_rc=3)
            self.assertEqual(rc, 3, (out, err))
            self.assertTrue(reached)
            self.assertFalse(os.path.exists(sudoers), "no earlier grant may stay after a failed install")
            self.assertIn("was not installed (status 3)", err)
            self.assertNotIn("install complete", out)

    def test_the_file_path_is_one_plain_assignment_never_read_from_the_environment(self):
        lines = [l for l in self.text.splitlines() if l.startswith("SUDOERS_FILE=")]
        self.assertEqual(len(lines), 1)
        self.assertRegex(lines[0], r'^SUDOERS_FILE="/etc/sudoers\.d/yuzu-agent"(?:\s+#.*)?$')
        self.assertNotIn("${SUDOERS_FILE", self.text)


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
