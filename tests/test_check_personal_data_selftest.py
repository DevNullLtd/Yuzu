#!/usr/bin/env python3
"""Self-test for scripts/ci/check-personal-data.py.

Builds throwaway git repos at runtime (prefix yuzu_test_) and checks every
detector with positive and negative cases, the UTF-16 decode, both escape
hatches, baseline stale/strict behaviour, and that output never carries a full
value. Leak-shaped values are assembled by concatenation so this file does not
trip the guard it tests. Stdlib only.
"""
from __future__ import annotations

import base64
import contextlib
import io
import os
import subprocess
import sys
import tempfile
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
SCRIPT = os.path.join(os.path.dirname(HERE), "scripts", "ci", "check-personal-data.py")

import importlib.util
_spec = importlib.util.spec_from_file_location("check_personal_data", SCRIPT)
cpd = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(cpd)

# Leak-shaped values, split so the source text never matches a detector.
U = "/Us" + "ers/"
H = "/ho" + "me/"
REAL_USER = "zed" + "mund"
SID = "S-1-5-" + "21-3623811015-3361044348-30300820"
SID_RID = SID + "-1001"
TN4 = "100." + "101.55.7"
TN6 = "fd7a:" + "115c:a1e0:ab12:4321:0:0:9f3e"
MAC = "3c:" + "22:fb:4a:91:0d"
EMAIL = "zedmund" + "@" + "gmail" + ".com"
KEYHDR = "-----BEGIN " + "RSA PRIVATE KEY-----"
KEYEND = "-----END " + "RSA PRIVATE KEY-----"


def rand_b64_lines(n=3, width=64):
    """Key-shaped body built at runtime from random bytes: no key literal is committed."""
    raw = base64.b64encode(os.urandom(n * width * 3 // 4)).decode()
    return [raw[i:i + width] for i in range(0, len(raw), width)]


BODY = "\n".join(rand_b64_lines())
PGPHDR = "-----BEGIN " + "PGP PRIVATE KEY BLOCK-----"
PGPEND = "-----END " + "PGP PRIVATE KEY BLOCK-----"


class Repo:
    def __init__(self):
        self._td = tempfile.TemporaryDirectory(prefix="yuzu_test_pdg_")
        self.root = self._td.name
        subprocess.run(["git", "init", "-q", self.root], check=True)

    def write(self, rel, content, binary=False):
        p = os.path.join(self.root, rel)
        os.makedirs(os.path.dirname(p), exist_ok=True)
        with open(p, "wb") as f:
            f.write(content if binary else content.encode())

    def run(self, *args):
        subprocess.run(["git", "-C", self.root, "add", "-A", "-f"], check=True)
        out, err = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            rc = cpd.main(["--root", self.root, *args])
        return rc, out.getvalue()

    def close(self):
        self._td.cleanup()


class T(unittest.TestCase):
    def setUp(self):
        self.r = Repo()
        self.addCleanup(self.r.close)

    def hit(self, rel, content, det, **kw):
        self.r.write(rel, content, **kw)
        rc, out = self.r.run()
        self.assertEqual(rc, 1, out)
        self.assertIn("[" + det + "]", out)
        return out

    def clean(self, rel, content):
        self.r.write(rel, content)
        rc, out = self.r.run()
        self.assertEqual(rc, 0, out)

    # home-path
    def test_home_path(self):
        self.hit("a.md", f"see {U}{REAL_USER}/x\n", "home-path")
    def test_home_path_linux_and_windows(self):
        self.hit("a.md", f"{H}{REAL_USER}/x\n", "home-path")
        self.r.write("b.md", "C:\\Us" + "ers\\" + REAL_USER + "\\x\n")
        self.r.write("c.md", "c:\\\\Us" + "ers\\\\" + REAL_USER + "\\\\x\n")
        self.r.write("d.md", "D:/Us" + "ers/" + REAL_USER + "/x\n")
        rc, out = self.r.run()
        for f in "abcd":
            self.assertIn(f + ".md:", out)
    def test_home_path_punctuation_tail(self):
        for i, tail in enumerate([",", ";", ":", "]", "}", ">", "."]):
            self.r.write(f"p{i}.md", f"see {H}{REAL_USER}{tail} next\n")
            self.r.write(f"w{i}.md", "see C:\\Us" + "ers\\" + REAL_USER + tail + " next\n")
        rc, out = self.r.run()
        self.assertEqual(rc, 1)
        for i in range(7):
            self.assertIn(f"p{i}.md:", out)
            self.assertIn(f"w{i}.md:", out)
    def test_home_path_placeholders(self):
        self.clean("a.md", f"{U}jsmith/x {H}runner/y {U}Public/z {U}<user>/ {H}$USER/ {H}jsmith, {H}root;\n")
    def test_persona_names_only_in_unit_tests(self):
        # personas are accepted in tests/unit/** only, never under fixtures/samples or elsewhere
        persona = f"{H}ali" + "ce/x\n"
        self.clean("tests/unit/foo.cpp", persona)
        self.clean("tests/unit/server/bar.cpp", persona)
        for rel in ("tests/unit/fixtures/x.txt", "tests/unit/a/samples/x.txt", "docs/x.md",
                    "agents/core/src/x.hpp"):
            self.r.write(rel, persona)
        rc, out = self.r.run()
        self.assertEqual(rc, 1, out)
        for rel in ("tests/unit/fixtures/x.txt:1:", "tests/unit/a/samples/x.txt:1:", "docs/x.md:1:",
                    "agents/core/src/x.hpp:1:"):
            self.assertIn(rel, out)
        self.assertNotIn("tests/unit/foo.cpp", out)
        self.assertNotIn("bar.cpp", out)
    def test_non_persona_name_in_unit_tests_flagged(self):
        self.hit("tests/unit/foo.cpp", f"{H}{REAL_USER}/x\n", "home-path")

    # windows-sid
    def test_sid(self):
        self.hit("a.txt", SID + "\n", "windows-sid")
        self.hit("b.txt", SID_RID + "\n", "windows-sid")
    def test_sid_synthetic(self):
        self.clean("a.txt", "S-1-5-21-1111111111-2222222222-3333333333 S-1-5-21-1-2-3-500 S-1-5-18\n")

    # tailnet-ip
    def test_tailnet(self):
        self.hit("a.txt", TN4 + "\n", "tailnet-ip")
        self.hit("b.txt", TN6 + "\n", "tailnet-ip")
    def test_tailnet_placeholders(self):
        self.clean("a.txt", "100.64.0.7 100.100.100.100 100.128.0.1 100.63.1.1 fd7a:115c:a1e0::5 fd7a:115c:a1e0::2a\n")

    # mac-address
    def test_mac_in_scope_only(self):
        self.r.write("tests/unit/fixtures/f.txt", MAC + "\n")
        self.r.write("docs/other.md", MAC.replace("3c", "4c") + "\n")
        rc, out = self.r.run()
        self.assertEqual(rc, 1)
        self.assertIn("tests/unit/fixtures/f.txt:1: [mac-address]", out)
        self.assertNotIn("docs/other.md", out)
    def test_mac_synthetic(self):
        self.clean("agents/plugins/x/docs/samples/linux.txt",
                   "00:00:5e:00:53:01 02:42:ac:11:00:02 00:00:00:00:00:00 ff:ff:ff:ff:ff:ff "
                   "01:00:5e:00:00:fb de:ad:be:ef:00:01 11:22:33:44:55:66 aa:bb:cc:dd:ee:ff\n")

    # private-key
    def test_private_key(self):
        self.hit("a.pem", f"{KEYHDR}\n{BODY}\n{KEYEND}\n", "private-key")
    def test_private_key_encrypted_pem(self):
        enc = "Proc-Type: 4,ENCRYPTED\nDEK-Info: AES-128-CBC,0123456789ABCDEF0123456789ABCDEF\n\n"
        self.hit("a.pem", f"{KEYHDR}\n{enc}{BODY}\n{KEYEND}\n", "private-key")
    def test_private_key_pgp_block(self):
        body = "\n".join(rand_b64_lines()) + "\n=ab12"
        self.hit("a.asc", f"{PGPHDR}\nVersion: Example 1.0\nComment: x\n\n{body}\n{PGPEND}\n", "private-key")
    def test_private_key_indented_and_unterminated(self):
        self.hit("a.yml", "k: |\n" + "\n".join("  " + ln for ln in [KEYHDR] + BODY.split("\n") + [KEYEND]) + "\n", "private-key")
    def test_private_key_unterminated_not_key(self):
        self.clean("b.md", f"{KEYHDR}\n{BODY}\n")        # no END line: not a key block
    def test_private_key_header_only_body_not_key(self):
        self.clean("a.md", f"{KEYHDR}\nProc-Type: 4,ENCRYPTED\nDEK-Info: AES-128-CBC,00\n{KEYEND}\n")
    def test_selftest_file_is_clean(self):
        with open(os.path.join(HERE, os.path.basename(__file__))) as f:
            self.r.write("t.py", f.read())
        rc, out = self.r.run()
        self.assertEqual(rc, 0, out)
    def test_private_key_non_key(self):
        self.clean("a.md", f"grep '{KEYHDR}' file  and {KEYHDR}\n...\n{KEYEND}\n")

    # personal-email
    def test_email(self):
        self.hit("a.md", f"mail {EMAIL}\n", "personal-email")
    def test_email_ok(self):
        self.clean("a.md", "user@example.com a@corp.test bob@gmail.example "
                   "user@outlook.com.example user@gmail.com.evil.test\n")
    def test_email_sentence_end(self):
        self.hit("a.md", f"mail {EMAIL}. Thanks\n", "personal-email")

    # tracked-session-artifact
    def test_artifact(self):
        for p in (".claude/plans/x.md", ".serena/memories/m.md", ".claude/projects/p/t.jsonl"):
            self.r.write(p, "harmless\n")
        rc, out = self.r.run()
        self.assertEqual(rc, 1)
        self.assertEqual(sum(1 for ln in out.splitlines() if ": [tracked-session-artifact]" in ln), 3)

    # scope exclusions
    def test_excluded(self):
        for p in ("governance.d/x.md", "CHANGELOG.md", "vcpkg_installed/a.h", "x/api.pb.cc"):
            self.r.write(p, f"{U}{REAL_USER}/x {EMAIL}\n")
        rc, out = self.r.run()
        self.assertEqual(rc, 0, out)

    # UTF-16
    def test_utf16_all_alignments(self):
        txt = f"x {U}{REAL_USER}/q\n"
        for i, (enc, pad) in enumerate([("utf-16-le", b""), ("utf-16-be", b""),
                                         ("utf-16-le", b"\x01"), ("utf-16-be", b"\x01")]):
            self.r.write(f"b{i}.bin", pad + txt.encode(enc), binary=True)
        rc, out = self.r.run()
        self.assertEqual(rc, 1)
        for i in range(4):
            self.assertIn(f"b{i}.bin:", out)

    # escape hatches
    def test_inline_marker(self):
        self.clean("a.md", f"{U}{REAL_USER}/x  personal-data-ok: synthetic fixture value\n")
    def test_inline_marker_short_reason_rejected(self):
        self.hit("a.md", f"{U}{REAL_USER}/x  personal-data-ok: ok\n", "home-path")
    def test_marker_other_line_does_not_cover(self):
        self.hit("a.md", f"personal-data-ok: synthetic fixture value\n{U}{REAL_USER}/x\n", "home-path")

    def test_baseline_counts(self):
        self.r.write("a.md", f"{U}{REAL_USER}/x\n{H}{REAL_USER}two/y\n")
        rc, _ = self.r.run("--update-baseline")
        self.assertEqual(rc, 0)
        rc, out = self.r.run()          # equal count passes
        self.assertEqual(rc, 0, out)
        self.assertNotIn("stale baseline", out)
        # exceeding the count fails (every hit of that file+detector listed)
        self.r.write("a.md", f"{U}{REAL_USER}/x\n{H}{REAL_USER}two/y\n{H}{REAL_USER}3/z\n")
        rc, out = self.r.run()
        self.assertEqual(rc, 1)
        # a new file with hits and no entry fails
        self.r.write("a.md", f"{U}{REAL_USER}/x\n{H}{REAL_USER}two/y\n")
        self.r.write("b.md", f"{U}{REAL_USER}/x\n")
        rc, out = self.r.run()
        self.assertEqual(rc, 1)
        self.assertIn("b.md:", out)

    def test_baseline_stale(self):
        self.r.write("a.md", f"{U}{REAL_USER}/x\n{H}{REAL_USER}two/y\n")
        self.r.run("--update-baseline")
        self.r.write("a.md", f"{U}{REAL_USER}/x\n")      # fewer than max_hits
        rc, out = self.r.run()
        self.assertEqual(rc, 0)
        self.assertIn("stale baseline entry", out)
        rc, out = self.r.run("--strict-baseline")
        self.assertEqual(rc, 1)

    def test_baseline_file_has_no_values_or_hashes(self):
        self.r.write("a.md", f"{U}{REAL_USER}/x {EMAIL}\n")
        self.r.run("--update-baseline")
        with open(os.path.join(self.r.root, cpd.BASELINE_REL)) as f:
            raw = f.read()
        self.assertNotIn(REAL_USER, raw)
        self.assertNotIn(EMAIL, raw)
        self.assertNotIn("sha256", raw)
        self.assertNotRegex(raw, r"[0-9a-f]{40,}")

    def test_home_path_bare(self):
        for i, tail in enumerate(["", '"', "'", " x", ")", "`"]):
            self.r.write(f"b{i}.md", f"p {U}{REAL_USER}{tail}\n".rstrip("\n") + ("" if tail else ""))
        rc, out = self.r.run()
        self.assertEqual(rc, 1)
        for i in range(6):
            self.assertIn(f"b{i}.md:", out)
        self.r.write("w.md", "C:\\Us" + "ers\\" + REAL_USER)
        rc, out = self.r.run()
        self.assertIn("w.md:", out)

    # output hygiene
    def test_output_never_any_value(self):
        content = "\n".join([f"{U}{REAL_USER}/x", SID_RID, TN4, TN6, EMAIL])
        self.r.write("a.md", content + "\n")
        self.r.write("tests/unit/fixtures/m.txt", MAC + "\n")
        self.r.write("k.pem", f"{KEYHDR}\n{BODY}\n{KEYEND}\n")
        self.r.write(".serena/memories/m.md", "x\n")
        self.r.write(".claude/plans/" + REAL_USER + ".md", "x\n")
        rc, out = self.r.run()
        self.assertEqual(rc, 1)
        self.assertIn("[home-path]", out)
        # no value, no value prefix (a 7-char name used to print 6 chars)
        for v in (REAL_USER, REAL_USER[:3], SID, SID[:12], SID_RID, TN4, TN6, MAC, EMAIL, "zedm",
                  BODY.splitlines()[0][:8]):
            self.assertNotIn(v, out.replace(".claude/plans/" + REAL_USER + ".md", ""))
        self.assertEqual(out.count("a.md:1: [home-path]"), 1)

    def test_output_escapes_hostile_filename(self):
        name = "x\n::warning::forged " + REAL_USER + ".md"
        self.r.write(".serena/" + name, "x\n")
        self.r.write("::error::" + "lead" + ".md", f"{U}{REAL_USER}/x\n")
        self.r.write("t\tab\rcr.md", f"{U}{REAL_USER}/x\n")
        rc, out = self.r.run()
        self.assertEqual(rc, 1)
        for ln in out.splitlines():
            self.assertFalse(ln.startswith("::"), ln)
        self.assertNotIn("\n::warning::", out)
        self.assertIn("\\n::warning::forged", out)
        self.assertNotIn("\r", out)
        self.assertNotIn("\t", out)

    # what is scanned
    def test_symlink_target_scanned(self):
        os.symlink(f"{U}{REAL_USER}/target", os.path.join(self.r.root, "lnk"))
        rc, out = self.r.run()
        self.assertEqual(rc, 1, out)
        self.assertIn("lnk:1: [home-path]", out)
    def test_skip_summary_printed(self):
        self.r.write("CHANGELOG.md", "x\n")
        self.r.write("a.md", "fine\n")
        rc, out = self.r.run()
        self.assertEqual(rc, 0, out)
        self.assertIn("skipped: excluded=1 oversize=0 unreadable=0 submodule=0", out)
    def test_oversize_counted(self):
        old = cpd.MAX_FILE_BYTES
        cpd.MAX_FILE_BYTES = 10
        try:
            self.r.write("big.txt", "x" * 100)
            rc, out = self.r.run()
        finally:
            cpd.MAX_FILE_BYTES = old
        self.assertEqual(rc, 0, out)
        self.assertIn("oversize=1", out)

    # shrink-only ratchet
    def _ratchet_repo(self, base_count, now_count):
        def lines(n):
            return "".join(f"{U}{REAL_USER}{i}/x\n" for i in range(n))
        self.r.write("a.md", lines(base_count))
        self.r.run("--update-baseline")
        subprocess.run(["git", "-C", self.r.root, "add", "-A", "-f"], check=True)
        subprocess.run(["git", "-C", self.r.root, "-c", "user.name=t", "-c", "user.email=t@example.com",
                        "commit", "-q", "-m", "base"], check=True)
        subprocess.run(["git", "-C", self.r.root, "branch", "-f", "basebr"], check=True)
        self.r.write("a.md", lines(now_count))
        self.r.run("--update-baseline")
        subprocess.run(["git", "-C", self.r.root, "add", "-A", "-f"], check=True)
        subprocess.run(["git", "-C", self.r.root, "-c", "user.name=t", "-c", "user.email=t@example.com",
                        "commit", "-q", "--allow-empty", "-m", "head"], check=True)
    def test_ratchet_grow_fails(self):
        self._ratchet_repo(1, 2)
        rc, out = self.r.run("--ratchet", "--base", "basebr")
        self.assertEqual(rc, 1, out)
        self.assertIn("baseline grew", out)
    def test_ratchet_new_entry_fails(self):
        self._ratchet_repo(1, 1)
        self.r.write("b.md", f"{U}{REAL_USER}/x\n")
        self.r.run("--update-baseline")
        rc, out = self.r.run("--ratchet", "--base", "basebr")
        self.assertEqual(rc, 1, out)
        self.assertIn("baseline grew", out)
    def test_ratchet_shrink_and_equal_pass(self):
        self._ratchet_repo(2, 1)
        rc, out = self.r.run("--ratchet", "--base", "basebr")
        self.assertEqual(rc, 0, out)
        rc, out = self.r.run("--ratchet", "--base", "basebr")
        self.assertEqual(rc, 0, out)
    def test_ratchet_skipped_when_baseline_absent_at_base(self):
        self.r.write("a.md", "x\n")
        subprocess.run(["git", "-C", self.r.root, "add", "-A", "-f"], check=True)
        subprocess.run(["git", "-C", self.r.root, "-c", "user.name=t", "-c", "user.email=t@example.com",
                        "commit", "-q", "-m", "base"], check=True)
        subprocess.run(["git", "-C", self.r.root, "branch", "-f", "basebr"], check=True)
        self.r.write("b.md", f"{U}{REAL_USER}/x\n")
        self.r.run("--update-baseline")
        rc, out = self.r.run("--ratchet", "--base", "basebr")
        self.assertEqual(rc, 0, out)
        self.assertIn("ratchet skipped", out)
    def test_ratchet_unresolvable_base_is_error(self):
        self._ratchet_repo(1, 1)
        rc, _ = self.r.run("--ratchet", "--base", "no-such-ref")
        self.assertEqual(rc, 2)


if __name__ == "__main__":
    unittest.main()
