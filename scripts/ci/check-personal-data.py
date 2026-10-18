#!/usr/bin/env python3
"""Guard: no real personal, device or private-network data in this PUBLIC repo.

Scans every tracked file (`git ls-files`) for the leak classes PR #6010 and its
redaction follow-up cleaned up. Stdlib only. See docs/plugin-readme-standard.md
rule 5 ("Personal-data guard") for the contributor-facing summary.

Detectors (stable ids):
  home-path                 /Users/<u>/, /home/<u>/, C:\\Users\\<u>\\ (\\, \\\\ or /)
  windows-sid               S-1-5-21-a-b-c[-rid] of a real-looking domain/machine
  tailnet-ip                Tailscale CGNAT 100.64.0.0/10 and fd7a:115c:a1e0::/48
  mac-address               real-looking MAC, in samples/fixtures scope only
  private-key               PEM "PRIVATE KEY" block with a base64-plausible body
  personal-email            consumer-mailbox address (gmail, outlook, icloud, ...)
  tracked-session-artifact  tracked file under .claude/plans/, .serena/,
                            .claude/projects/

Binary files are also decoded as UTF-16LE and UTF-16BE at both byte alignments
(Windows registry exports, captures, hive-ish blobs).

Escape hatches (both explicit, both reviewed in the PR diff):
  (a) same-line marker  `personal-data-ok: <reason>` (reason >= 10 chars)
  (b) scripts/ci/personal-data-baseline.json: PRE-EXISTING hits as allowed
      COUNTS per (path, detector): {"path", "detector", "max_hits"}. No value
      or hash of a value is stored (the file is public; a hash of an IP, MAC
      or short username is brute-forceable). A file fails when its hit count
      for a detector exceeds max_hits or it has hits and no entry. Known,
      accepted limit: a baselined file can swap one value for another of the
      same detector without failing, until the baseline is emptied. Fewer hits
      than max_hits = "stale": reported always, fatal only with
      --strict-baseline. `--update-baseline` regenerates the file.

Allowlists (all in this file so a change is a reviewable diff):
  PLACEHOLDER_USERS     home-path names that are synthetic, CI/service
                        accounts or OS-default profile names.
  SID rule              placeholder S-1-5-21-1111111111-2222222222-3333333333;
                        synthetic when every sub-authority < 1000 or is a
                        repeated-digit run (e.g. 1111111111, 999999999).
  Tailnet rule          100.64.0.0/24 and 100.100.100.100 are placeholders;
                        fd7a:115c:a1e0:: suffix of the form ::N / ::NN is.
  MAC rule              documentation 00:00:5e:00:53:xx, locally administered
                        (first-octet bit 0x02), multicast (bit 0x01), all-zero,
                        broadcast, and MAC_ALLOWLIST_PREFIXES are synthetic.

Output never prints a full matched value: `path:line: [detector] abcdef...`.
Exit: 0 clean, 1 new hits (or stale under --strict-baseline), 2 usage/error.
"""
from __future__ import annotations

import argparse
import hashlib
import ipaddress
import json
import os
import re
import subprocess
import sys

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
BASELINE_REL = "scripts/ci/personal-data-baseline.json"

MARKER_RE = re.compile(r"personal-data-ok:\s*(\S.*)")
MARKER_MIN_REASON = 10
MAX_FILE_BYTES = 20 * 1024 * 1024

# Paths never scanned: append-only / assembled / vendored / generated.
EXCLUDE_PREFIXES = ("governance.d/", "vcpkg_installed/", "gateway/_checkouts/", ".git/")
EXCLUDE_EXACT = ("CHANGELOG.md", BASELINE_REL)
EXCLUDE_GLOBS = (re.compile(r"\.pb\.[^/]*$"),)

# mac-address is scoped to places that hold captures / fixtures.
MAC_SCOPE = (
    re.compile(r"^agents/plugins/[^/]+/docs/samples/"),
    re.compile(r"^tests/unit/fixtures/"),
    re.compile(r"^tests/unit/.*\.(cpp|hpp)$"),
    re.compile(r"^content/plugin-docs/"),
    re.compile(r"^agents/plugins/[^/]+/README\.md$"),
)

ARTIFACT_PREFIXES = (".claude/plans/", ".serena/", ".claude/projects/")

# Names that are placeholders, synthetic test personas, CI/service accounts or
# OS-default profile names. Compared case-insensitively. Derived from what the
# tests, docs and CI configs legitimately use.
PLACEHOLDER_USERS = {
    # generic placeholders
    "user", "users", "username", "usr", "name", "me", "you", "u", "x", "foo",
    "bar", "baz", "example", "someone", "somebody", "person", "operator",
    "yourname", "your_name", "your-name", "youruser", "currentuser", "current",
    "target", "victim", "attacker", "owner", "other", "otheruser", "unknown",
    "jsmith", "jdoe", "jane", "john", "johndoe", "janedoe", "smith", "doe",
    # synthetic personas used in tests/docs
    "alice", "bob", "carol", "dave", "eve", "mallory", "frank", "grace",
    "heidi", "ivan", "judy", "oscar", "peggy", "trent", "walter", "charlie",
    "test", "tester", "testuser", "test_user", "test-user", "demo", "sample",
    "fake", "dummy", "nobody", "guest", "root", "admin", "administrator",
    "alex", "sam", "pat", "kim", "dev", "developer", "build", "builder",
    # service / CI accounts
    "runner", "runneradmin", "yuzuci", "yuzu", "_yuzu", "yuzu-agent",
    "yuzuagent", "yuzu_agent", "yuzu-server", "yuzu-gateway", "github",
    "jenkins", "ubuntu", "vagrant", "ec2-user", "azureuser", "buildkite",
    "gitlab-runner", "actions", "docker", "postgres", "www-data", "daemon",
    "systemd", "svc", "service", "agent", "server", "gateway", "ci",
    "github-runner", "linuxbrew", "samba", "claude", "node", "app", "vcpkg", "opt", "tmp", "nonexistent", "missing",
    # OS-default profile folders
    "public", "default", "default user", "all users", "shared", "deleted",
    "defaultuser0", "localservice", "networkservice", "system", "system32",
}

PUBLIC_PLACEHOLDER_SID = "s-1-5-21-1111111111-2222222222-3333333333"

# Documentation / synthetic MAC prefixes (lowercase, colon form).
MAC_ALLOWLIST_PREFIXES = ("00:00:5e:00:53:", "de:ad:be:ef:", "11:22:33:", "aa:bb:cc:",
                          "00:11:22:33:", "12:34:56:", "ab:cd:ef:", "01:23:45:", "01:02:03:")

CONSUMER_DOMAINS = (r"gmail\.com|googlemail\.com|outlook\.com|hotmail\.com|live\.com|"
                    r"icloud\.com|me\.com|yahoo\.[a-z.]{2,}|proton\.me|protonmail\.com")

HOME_UNIX_RE = re.compile(r"""(?i)(?<![A-Za-z0-9_])/(?:Users|home)/([A-Za-z0-9_.\-]+)(?=[/\\"'`)\s]|$)""")
HOME_WIN_RE = re.compile(
    r"""(?i)[A-Za-z]:(?:\\\\|\\|/)Users(?:\\\\|\\|/)([A-Za-z0-9_.\-]+)(?=[/\\"'`)\s]|$)""")
SID_RE = re.compile(r"(?i)\bS-1-5-21-(\d{1,10})-(\d{1,10})-(\d{1,10})(-\d{1,10})?\b")
IPV4_RE = re.compile(r"(?<![\d.])(100\.(?:6[4-9]|[7-9]\d|1[01]\d|12[0-7])\.\d{1,3}\.\d{1,3})(?![\d])")
IPV6_RE = re.compile(r"(?i)(?<![0-9a-f:])(fd7a:115c:a1e0(?::[0-9a-f]{0,4}){1,6}[0-9a-f]{0,4})(?![0-9a-f:])")
MAC_RE = re.compile(r"(?i)(?<![0-9a-f:\-])((?:[0-9a-f]{2}[:\-]){5}[0-9a-f]{2})(?![0-9a-f]|[:\-][0-9a-f])")
KEY_RE = re.compile(
    r"-----BEGIN ((?:[A-Z0-9]+ )*PRIVATE KEY)-----([^-]{0,20000}?)-----END \1-----", re.S)
EMAIL_RE = re.compile(
    r"(?i)(?<![A-Za-z0-9._%+\-])([A-Za-z0-9._%+\-]+@(?:" + CONSUMER_DOMAINS + r"))(?![A-Za-z0-9\-])")
B64_RE = re.compile(r"^[A-Za-z0-9+/=]+$")

HINTS = {
    "home-path": "use a placeholder account such as /home/jsmith/ or C:\\Users\\jsmith\\",
    "windows-sid": "use the placeholder S-1-5-21-1111111111-2222222222-3333333333",
    "tailnet-ip": "use a 100.64.0.x placeholder (100.64.0.0/24) or 100.100.100.100",
    "mac-address": "use a documentation MAC 00:00:5e:00:53:xx or a locally administered 02:xx:..",
    "private-key": "never commit a private key; generate it at test time",
    "personal-email": "use user@example.com or an example.org / .test address",
    "tracked-session-artifact": "git rm --cached the file; keep session files out of the tree",
}


def sha(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8", "replace")).hexdigest()


class Hit:
    __slots__ = ("path", "line", "detector", "value", "digest")

    def __init__(self, path, line, detector, value):
        self.path, self.line, self.detector, self.value = path, line, detector, value
        self.digest = sha(value)

    def key(self):
        return (self.path, self.detector, self.digest)

    def render(self):
        v = self.value
        shown = (v[:6] + "...") if len(v) > 6 else (v[: max(1, len(v) // 2)] + "...")
        return f"{self.path}:{self.line}: [{self.detector}] {shown}"


def excluded(path: str) -> bool:
    return (path in EXCLUDE_EXACT or path.startswith(EXCLUDE_PREFIXES)
            or any(g.search(path) for g in EXCLUDE_GLOBS))


def sid_synthetic(m) -> bool:
    subs = [m.group(1), m.group(2), m.group(3)]
    if "S-1-5-21-%s-%s-%s" % tuple(subs) == PUBLIC_PLACEHOLDER_SID.upper():
        return True
    for s in subs:
        if int(s) >= 1000 and len(set(s)) > 1:
            return False
    return True


def mac_synthetic(mac: str) -> bool:
    norm = mac.lower().replace("-", ":")
    octets = [int(o, 16) for o in norm.split(":")]
    if octets[0] & 0x03:           # multicast (01) or locally administered (02)
        return True
    if all(o == 0 for o in octets) or all(o == 0xFF for o in octets):
        return True
    return norm.startswith(MAC_ALLOWLIST_PREFIXES)


def tailnet_v4_synthetic(ip: str) -> bool:
    try:
        a = ipaddress.IPv4Address(ip)
    except ValueError:
        return True
    return a in ipaddress.IPv4Network("100.64.0.0/24") or ip == "100.100.100.100"


def tailnet_v6_synthetic(ip: str) -> bool:
    try:
        a = ipaddress.IPv6Address(ip)
    except ValueError:
        return True
    if a not in ipaddress.IPv6Network("fd7a:115c:a1e0::/48"):
        return True
    return (int(a) & ((1 << 80) - 1)) < 0x100   # suffix ::N / ::NN style (<=0xff)


def key_body_plausible(body: str) -> bool:
    lines = [ln.strip() for ln in body.strip().splitlines()]
    lines = [ln for ln in lines if ln and ":" not in ln]   # drop Proc-Type/DEK-Info
    joined = "".join(lines)
    return len(joined) >= 64 and bool(B64_RE.match(joined))


def line_of(text: str, pos: int) -> int:
    return text.count("\n", 0, pos) + 1


def scan_text(path: str, text: str, hits: list, mac_scope: bool, seen: set):
    lines = text.split("\n")

    def add(pos, det, value):
        ln = line_of(text, pos)
        mk = MARKER_RE.search(lines[ln - 1]) if ln - 1 < len(lines) else None
        if mk and len(mk.group(1).strip()) >= MARKER_MIN_REASON:
            return
        k = (ln, det, value)
        if k in seen:
            return
        seen.add(k)
        hits.append(Hit(path, ln, det, value))

    for rx in (HOME_UNIX_RE, HOME_WIN_RE):
        for m in rx.finditer(text):
            u = m.group(1).lower()
            if u in PLACEHOLDER_USERS or not u.strip("."):
                continue
            add(m.start(1), "home-path", u)
    for m in SID_RE.finditer(text):
        if not sid_synthetic(m):
            add(m.start(), "windows-sid", m.group(0).upper())
    for m in IPV4_RE.finditer(text):
        ip = m.group(1)
        if all(int(p) <= 255 for p in ip.split(".")) and not tailnet_v4_synthetic(ip):
            add(m.start(1), "tailnet-ip", ip)
    for m in IPV6_RE.finditer(text):
        ip = m.group(1)
        try:
            ipaddress.IPv6Address(ip)
        except ValueError:
            continue
        if not tailnet_v6_synthetic(ip):
            add(m.start(1), "tailnet-ip", ip.lower())
    if mac_scope:
        for m in MAC_RE.finditer(text):
            if not mac_synthetic(m.group(1)):
                add(m.start(1), "mac-address", m.group(1).lower().replace("-", ":"))
    if "PRIVATE KEY-----" in text:
        for m in KEY_RE.finditer(text):
            if key_body_plausible(m.group(2)):
                add(m.start(), "private-key", re.sub(r"\s+", "", m.group(2)))
    for m in EMAIL_RE.finditer(text):
        add(m.start(1), "personal-email", m.group(1).lower())


def decodings(data: bytes):
    """Yield text views of a file. Text: utf-8. Binary: also UTF-16 LE/BE at
    both byte alignments (a UTF-16 string can start at an odd offset)."""
    yield data.decode("utf-8", "replace")
    if b"\x00" in data[:8192] or b"\x00" in data:
        for off in (0, 1):
            chunk = data[off:]
            chunk = chunk[: len(chunk) & ~1]
            for enc in ("utf-16-le", "utf-16-be"):
                yield chunk.decode(enc, "replace")


def scan_file(path: str, data: bytes, hits: list):
    mac_scope = any(r.search(path) for r in MAC_SCOPE)
    seen: set = set()
    for text in decodings(data):
        scan_text(path, text, hits, mac_scope, seen)


def tracked_files(root: str):
    out = subprocess.run(["git", "-C", root, "ls-files", "-z"], check=True,
                         capture_output=True).stdout
    return [p for p in out.decode("utf-8", "surrogateescape").split("\0") if p]


def scan_repo(root: str):
    hits: list = []
    for rel in tracked_files(root):
        if excluded(rel):
            continue
        if rel.startswith(ARTIFACT_PREFIXES):
            hits.append(Hit(rel, 1, "tracked-session-artifact", rel))
            continue
        full = os.path.join(root, rel)
        try:
            if os.path.islink(full) or not os.path.isfile(full):
                continue
            if os.path.getsize(full) > MAX_FILE_BYTES:
                continue
            with open(full, "rb") as f:
                data = f.read()
        except OSError:
            continue
        scan_file(rel, data, hits)
    return hits


def load_baseline(root: str):
    p = os.path.join(root, BASELINE_REL)
    if not os.path.exists(p):
        return {}
    with open(p, encoding="utf-8") as f:
        doc = json.load(f)
    return {(e["path"], e["detector"]): int(e["max_hits"]) for e in doc.get("entries", [])}


def count_hits(hits):
    counts: dict = {}
    for h in hits:
        counts[(h.path, h.detector)] = counts.get((h.path, h.detector), 0) + 1
    return counts


def write_baseline(root: str, hits):
    counts = count_hits(hits)
    doc = {
        "_comment": ("Pre-existing personal-data hits as allowed counts per path+detector "
                     "(no values, no hashes). Meant to shrink to empty; see "
                     "docs/plugin-readme-standard.md rule 5."),
        "entries": [{"path": p, "detector": d, "max_hits": n}
                    for (p, d), n in sorted(counts.items())],
    }
    os.makedirs(os.path.dirname(os.path.join(root, BASELINE_REL)), exist_ok=True)
    with open(os.path.join(root, BASELINE_REL), "w", encoding="utf-8") as f:
        json.dump(doc, f, indent=1, sort_keys=True)
        f.write("\n")
    return len(counts)


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("--root", default=REPO_ROOT)
    ap.add_argument("--strict-baseline", action="store_true",
                    help="fail on stale baseline entries (default: report only)")
    ap.add_argument("--update-baseline", action="store_true",
                    help="rewrite the baseline from the current tree and exit 0")
    args = ap.parse_args(argv)
    root = os.path.abspath(args.root)
    try:
        hits = scan_repo(root)
    except (subprocess.CalledProcessError, OSError) as e:
        print(f"check-personal-data: cannot list tracked files: {e}", file=sys.stderr)
        return 2
    if args.update_baseline:
        n = write_baseline(root, hits)
        print(f"check-personal-data: baseline rewritten ({n} entries)")
        return 0
    baseline = load_baseline(root)
    counts = count_hits(hits)
    over = {k for k, n in counts.items() if n > baseline.get(k, 0)}
    new = [h for h in hits if (h.path, h.detector) in over]
    stale = sorted((k, n, counts.get(k, 0)) for k, n in baseline.items()
                   if counts.get(k, 0) < n)
    for h in sorted(new, key=lambda h: (h.path, h.line, h.detector)):
        print(h.render())
    if new:
        print()
        for d in sorted({h.detector for h in new}):
            print(f"hint [{d}]: {HINTS[d]}")
        print("Or, if genuinely intended: append `personal-data-ok: <reason, >=10 chars>` on "
              "that line. See docs/plugin-readme-standard.md rule 5.")
    for (p, d), allowed, now in stale:
        print(f"stale baseline entry: {p} [{d}] max_hits {allowed} but {now} found (lower it)")
    if new:
        print(f"check-personal-data: FAIL - {len(new)} new hit(s)")
        return 1
    if stale and args.strict_baseline:
        print(f"check-personal-data: FAIL - {len(stale)} stale baseline entr(ies) (--strict-baseline)")
        return 1
    print(f"check-personal-data: OK ({len(hits)} baselined, {len(stale)} stale)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
