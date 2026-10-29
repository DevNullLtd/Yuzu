#!/usr/bin/env python3
"""Guard: no real personal, device or private-network data in this PUBLIC repo.

Scans the tracked files' committed content (`git ls-files -s` + `git cat-file`,
so a symlink's target string is scanned too) for the leak classes PR #6010 and
its redaction follow-up cleaned up. Stdlib only. Not scanned, and counted in a
one-line summary printed on every run: governance.d/ (append-only), CHANGELOG.md
(never edited), generated *.pb.*, vendored trees (`excluded`), blobs over
20 MiB (`oversize`), blobs git cannot return (`unreadable`), submodules. See docs/plugin-readme-standard.md
rule 5 ("Personal-data guard") for the contributor-facing summary.

Detectors (stable ids):
  home-path                 /Users/<u>/, /home/<u>/, C:\\Users\\<u>\\ (\\, \\\\ or /)
  windows-sid               S-1-5-21-a-b-c[-rid] of a real-looking domain/machine
  tailnet-ip                Tailscale CGNAT 100.64.0.0/10 and fd7a:115c:a1e0::/48
  mac-address               real-looking MAC, in samples/fixtures scope only
  private-key               PEM "PRIVATE KEY" block (incl. encrypted traditional PEM
                            and OpenPGP "PGP PRIVATE KEY BLOCK" armour) with a
                            base64-plausible body
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

Output never prints any part of a matched value: `path:line: [detector]`, with
control characters in the path escaped.

Shrink-only ratchet: `--ratchet` (CI) compares the baseline against its
merge-base version (`--base`, default origin/dev; the same shape as
check-governance-ledger.py); any (path, detector) whose max_hits rose, or any
new entry, fails. A file git detects as RENAMED between the merge-base and HEAD
keeps its allowance under its new path, so moving a baselined file is not growth.
A baseline absent at the base (the PR introducing it) is skipped with a notice.

Exit: 0 clean, 1 new hits (or stale under --strict-baseline), 2 usage/error.
"""
from __future__ import annotations

import argparse
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

# Names that can never be a real person's account: placeholders, CI/service
# accounts and OS-default profile names. Compared case-insensitively. Human
# given names / personas are deliberately NOT here (a real account with that
# name would pass silently); see PERSONA_USERS for the one scope they are
# accepted in.
PLACEHOLDER_USERS = {
    # generic placeholders (never a plausible real account)
    "user", "users", "username", "usr", "name", "me", "you", "u", "x", "foo",
    "bar", "baz", "example", "someone", "somebody", "person", "operator",
    "yourname", "your_name", "your-name", "youruser", "currentuser", "current",
    "target", "victim", "attacker", "owner", "other", "otheruser", "unknown",
    "jsmith", "johndoe", "janedoe",
    "test", "tester", "testuser", "test_user", "test-user", "demo", "sample",
    "fake", "dummy", "nobody", "guest", "root", "admin", "administrator",
    "dev", "developer", "build", "builder",
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

# Synthetic test personas. Human given names, so a real account could share one:
# accepted ONLY in unit-test source (tests/unit/**), where they are the cast of
# the test cases, and NOT under a `fixtures` or `samples` directory, because real
# contributor data has reached captured fixtures and samples before. Anywhere
# else (docs, product source, ...) they are flagged like any other name.
PERSONA_USERS = {
    "alice", "bob", "carol", "dave", "eve", "mallory", "frank", "grace",
    "heidi", "ivan", "judy", "oscar", "peggy", "trent", "walter", "charlie",
    "alex", "sam", "pat", "kim", "jane", "john", "smith", "doe", "jdoe",
}


def persona_scope(path: str) -> bool:
    parts = path.split("/")
    return (path.startswith("tests/unit/")
            and not ({"fixtures", "samples"} & set(parts[:-1])))


PUBLIC_PLACEHOLDER_SID = "s-1-5-21-1111111111-2222222222-3333333333"

# Documentation / synthetic MAC prefixes (lowercase, colon form).
MAC_ALLOWLIST_PREFIXES = ("00:00:5e:00:53:", "de:ad:be:ef:", "11:22:33:", "aa:bb:cc:",
                          "00:11:22:33:", "12:34:56:", "ab:cd:ef:", "01:23:45:", "01:02:03:")

CONSUMER_DOMAINS = (r"gmail\.com|googlemail\.com|outlook\.com|hotmail\.com|live\.com|"
                    r"icloud\.com|me\.com|yahoo\.[a-z.]{2,}|proton\.me|protonmail\.com")

HOME_UNIX_RE = re.compile(r"""(?i)(?<![A-Za-z0-9_])/(?:Users|home)/([A-Za-z0-9_.\-]+)(?![A-Za-z0-9_.\-])""")
HOME_WIN_RE = re.compile(
    r"""(?i)[A-Za-z]:(?:\\\\|\\|/)Users(?:\\\\|\\|/)([A-Za-z0-9_.\-]+)(?![A-Za-z0-9_.\-])""")
SID_RE = re.compile(r"(?i)\bS-1-5-21-(\d{1,10})-(\d{1,10})-(\d{1,10})(-\d{1,10})?\b")
IPV4_RE = re.compile(r"(?<![\d.])(100\.(?:6[4-9]|[7-9]\d|1[01]\d|12[0-7])\.\d{1,3}\.\d{1,3})(?![\d])")
IPV6_RE = re.compile(r"(?i)(?<![0-9a-f:])(fd7a:115c:a1e0(?::[0-9a-f]{0,4}){1,6}[0-9a-f]{0,4})(?![0-9a-f:])")
MAC_RE = re.compile(r"(?i)(?<![0-9a-f:\-])((?:[0-9a-f]{2}[:\-]){5}[0-9a-f]{2})(?![0-9a-f]|[:\-][0-9a-f])")
KEY_BEGIN_RE = re.compile(r"-----BEGIN ((?:[A-Z0-9]+ )*PRIVATE KEY(?: BLOCK)?)-----\s*$")
KEY_HEADER_RE = re.compile(r"^[A-Za-z][A-Za-z0-9\-]*:(?:\s|$)")   # RFC 1421 / OpenPGP armour header
KEY_MAX_BODY_CHARS = 20000
# A trailing "." is sentence punctuation; ".<alnum>" means the domain goes on
# (user@outlook.com.example is not an outlook address).
EMAIL_RE = re.compile(
    r"(?i)(?<![A-Za-z0-9._%+\-])([A-Za-z0-9._%+\-]+@(?:" + CONSUMER_DOMAINS
    + r"))(?![A-Za-z0-9_\-]|\.[A-Za-z0-9_\-])")
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


def safe_text(text: str) -> str:
    """Printable form of an attacker-controlled string (a tracked path): control
    characters escaped so a newline cannot start a forged log line, and a leading
    `::` (a GitHub Actions workflow command) neutralised."""
    out = "".join(c if c.isprintable() else
                  {"\n": "\\n", "\r": "\\r", "\t": "\\t"}.get(c, "\\x%02x" % ord(c) if ord(c) < 256 else "\\u%04x" % ord(c))
                  for c in text)
    return "\\:\\:" + out[2:] if out.startswith("::") else out


class Hit:
    __slots__ = ("path", "line", "detector")

    def __init__(self, path, line, detector):
        self.path, self.line, self.detector = path, line, detector

    def render(self):
        return f"{safe_text(self.path)}:{self.line}: [{self.detector}]"


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


def key_body_plausible(body_lines) -> bool:
    joined = "".join(ln.strip() for ln in body_lines)
    return len(joined) >= 64 and bool(B64_RE.match(joined))


def find_private_keys(lines):
    """Yield (1-based BEGIN line, base64 body) for each armoured private key.

    Line-by-line armour parser: BEGIN line, optional `Key: value` armour headers
    (Proc-Type/DEK-Info, OpenPGP Version/Comment), a blank separator, then a
    base64 body ending at the matching END line. A body that is not plausible
    base64 (`...` placeholders in docs) is not a key."""
    i, n = 0, len(lines)
    while i < n:
        m = KEY_BEGIN_RE.search(lines[i])
        if not m:
            i += 1
            continue
        label, start, j = m.group(1), i, i + 1
        while j < n and (KEY_HEADER_RE.match(lines[j].strip()) or not lines[j].strip()):
            j += 1
        body, size = [], 0
        while j < n and lines[j].strip() != "-----END " + label + "-----":
            body.append(lines[j])
            size += len(lines[j])
            if size > KEY_MAX_BODY_CHARS or "-----BEGIN " in lines[j]:
                body = None
                break
            j += 1
        if body is not None and j < n and key_body_plausible(body):
            yield start + 1, "".join(ln.strip() for ln in body)
        i = max(j, start + 1)


def line_of(text: str, pos: int) -> int:
    return text.count("\n", 0, pos) + 1


def scan_text(path: str, text: str, hits: list, mac_scope: bool, seen: set):
    lines = text.split("\n")

    def add(pos, det, value):
        add_line(line_of(text, pos), det, value)

    def add_line(ln, det, value):
        mk = MARKER_RE.search(lines[ln - 1]) if ln - 1 < len(lines) else None
        if mk and len(mk.group(1).strip()) >= MARKER_MIN_REASON:
            return
        k = (ln, det, value)
        if k in seen:
            return
        seen.add(k)
        hits.append(Hit(path, ln, det))

    for rx in (HOME_UNIX_RE, HOME_WIN_RE):
        for m in rx.finditer(text):
            u = m.group(1).lower().rstrip(".")
            if u in PLACEHOLDER_USERS or not u.strip("."):
                continue
            if u in PERSONA_USERS and persona_scope(path):
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
    if "PRIVATE KEY" in text:
        for ln, body in find_private_keys(lines):
            add_line(ln, "private-key", body)
    for m in EMAIL_RE.finditer(text):
        add(m.start(1), "personal-email", m.group(1).lower())


def decodings(data: bytes):
    """Yield text views of a file. Text: utf-8. Binary: also UTF-16 LE/BE at
    both byte alignments (a UTF-16 string can start at an odd offset)."""
    yield data.decode("utf-8", "replace")
    if b"\x00" in data:
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


def tracked_entries(root: str):
    """[(mode, object id, path)] from the index (`git ls-files -s`)."""
    out = subprocess.run(["git", "-C", root, "ls-files", "-s", "-z"], check=True,
                         capture_output=True).stdout
    entries = []
    for rec in out.decode("utf-8", "surrogateescape").split("\0"):
        if rec:
            meta, _, path = rec.partition("\t")
            mode, oid, _stage = meta.split(" ")
            entries.append((mode, oid, path))
    return entries


def blob_sizes(root: str, oids):
    """{oid: size or None (missing)} via one `git cat-file --batch-check`."""
    res = subprocess.run(["git", "-C", root, "cat-file", "--batch-check"], check=True,
                         capture_output=True, input="".join(o + "\n" for o in oids).encode())
    sizes = {}
    for ln in res.stdout.decode().splitlines():
        parts = ln.split(" ")
        sizes[parts[0]] = int(parts[2]) if len(parts) == 3 and parts[1] != "missing" else None
    return sizes


def read_blobs(root: str, oids):
    """Yield (oid, bytes) in bounded batches (<= ~64 MiB per `cat-file --batch`)."""
    def batch(group, sizes):
        res = subprocess.run(["git", "-C", root, "cat-file", "--batch"], check=True,
                             capture_output=True, input="".join(o + "\n" for o in group).encode())
        buf, pos = res.stdout, 0
        for oid in group:
            nl = buf.index(b"\n", pos)
            size = int(buf[pos:nl].split(b" ")[2])
            yield oid, buf[nl + 1:nl + 1 + size]
            pos = nl + 1 + size + 1

    group, total = [], 0
    sizes = blob_sizes(root, oids)
    for oid in oids:
        group.append(oid)
        total += sizes[oid]
        if total >= 64 * 1024 * 1024:
            yield from batch(group, sizes)
            group, total = [], 0
    if group:
        yield from batch(group, sizes)


def scan_repo(root: str):
    """-> (hits, skipped) where skipped = {reason: count}."""
    hits: list = []
    skipped = {"excluded": 0, "oversize": 0, "unreadable": 0, "submodule": 0}
    todo = []
    for mode, oid, rel in tracked_entries(root):
        if excluded(rel):
            skipped["excluded"] += 1
        elif rel.startswith(ARTIFACT_PREFIXES):
            hits.append(Hit(rel, 1, "tracked-session-artifact"))
        elif mode == "160000":
            skipped["submodule"] += 1
        else:
            todo.append((oid, rel))
    sizes = blob_sizes(root, [o for o, _ in todo])
    paths: dict = {}
    for oid, rel in todo:
        if sizes.get(oid) is None:
            skipped["unreadable"] += 1
        elif sizes[oid] > MAX_FILE_BYTES:
            skipped["oversize"] += 1
        else:
            paths.setdefault(oid, []).append(rel)
    for oid, data in read_blobs(root, list(paths)):
        for rel in paths[oid]:
            scan_file(rel, data, hits)
    return hits, skipped


def renamed_paths(root: str, mb: str):
    """{old path: new path} for files git detects as renamed between mb and HEAD."""
    out = subprocess.run(["git", "-C", root, "diff", "-z", "-M", "-l5000", "--name-status",
                          "--diff-filter=R", mb, "HEAD"], check=True,
                         capture_output=True).stdout.decode("utf-8", "surrogateescape").split("\0")
    # -z name-status renames are three fields: "R<score>", old, new.
    return {out[i + 1]: out[i + 2] for i in range(0, len(out) - 2, 3) if out[i].startswith("R")}


def ratchet(root: str, base: str, counts_now):
    """Shrink-only check of the baseline vs its merge-base version.
    -> (problem lines, notice or None). Raises CalledProcessError if the base
    ref cannot be resolved (fail closed in CI)."""
    mb = subprocess.run(["git", "-C", root, "merge-base", base, "HEAD"], check=True,
                        capture_output=True, text=True).stdout.strip()
    show = subprocess.run(["git", "-C", root, "show", f"{mb}:{BASELINE_REL}"],
                          capture_output=True)
    if show.returncode != 0:
        return [], f"ratchet skipped: {BASELINE_REL} does not exist at the merge-base"
    renamed = renamed_paths(root, mb)
    old = {(renamed.get(e["path"], e["path"]), e["detector"]): int(e["max_hits"])
           for e in json.loads(show.stdout.decode("utf-8")).get("entries", [])}
    problems = []
    for (p, d), n in sorted(load_baseline(root).items()):
        if n > old.get((p, d), 0):
            problems.append(f"baseline grew: {safe_text(p)} [{d}] max_hits "
                            f"{old.get((p, d), 0)} -> {n} (the baseline may only shrink)")
    return problems, None


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
    ap.add_argument("--ratchet", action="store_true",
                    help="also fail if the baseline grew vs its merge-base version (CI)")
    ap.add_argument("--base", default=os.environ.get("PDG_BASE", "origin/dev"),
                    help="base ref for --ratchet (default: $PDG_BASE, else origin/dev; CI sets "
                         "PDG_BASE to the PR's target branch)")
    ap.add_argument("--update-baseline", action="store_true",
                    help="rewrite the baseline from the current tree and exit 0")
    args = ap.parse_args(argv)
    root = os.path.abspath(args.root)
    try:
        hits, skipped = scan_repo(root)
    except (subprocess.CalledProcessError, OSError) as e:
        print(f"check-personal-data: cannot list tracked files: {e}", file=sys.stderr)
        return 2
    print("check-personal-data: scanned content of tracked files; skipped: "
          + " ".join(f"{k}={v}" for k, v in skipped.items()))
    if args.update_baseline:
        n = write_baseline(root, hits)
        print(f"check-personal-data: baseline rewritten ({n} entries)")
        return 0
    try:
        baseline = load_baseline(root)
    except (OSError, ValueError, KeyError, TypeError, AttributeError) as e:
        print(f"check-personal-data: cannot read {BASELINE_REL}: {e!r}", file=sys.stderr)
        return 2
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
        print(f"stale baseline entry: {safe_text(p)} [{d}] max_hits {allowed} but {now} found (lower it)")
    if new:
        print(f"check-personal-data: FAIL - {len(new)} new hit(s)")
        return 1
    if args.ratchet:
        try:
            problems, notice = ratchet(root, args.base, counts)
        except (subprocess.CalledProcessError, OSError, ValueError, KeyError, TypeError,
                AttributeError) as e:
            print(f"check-personal-data: cannot evaluate the baseline ratchet vs {args.base}: {e}",
                  file=sys.stderr)
            print("hint: fetch the base branch (git fetch origin dev) or set PDG_BASE / --base "
                  "to a ref your clone has", file=sys.stderr)
            return 2
        if notice:
            print(f"check-personal-data: {notice}")
        for ln in problems:
            print(ln)
        if problems:
            print(f"check-personal-data: FAIL - baseline grew ({len(problems)} entr(ies))")
            return 1
    if stale and args.strict_baseline:
        print(f"check-personal-data: FAIL - {len(stale)} stale baseline entr(ies) (--strict-baseline)")
        return 1
    print(f"check-personal-data: OK ({len(hits)} baselined, {len(stale)} stale)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
