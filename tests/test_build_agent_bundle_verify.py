#!/usr/bin/env python3
"""Offline test of scripts/build-agent-bundle.sh's release-verification path (#7529).

The script used to treat the release SHA256SUMS as signed without checking its
cosign bundle, and accepted a file whose hash appeared on ANY line. These tests
run the real script with `--verify-only` against stub `gh` and `cosign` programs
and fixture release assets, never touching the network or docker:

  * the cosign stub RECORDS its argv, and the tests assert the exact certificate
    identity per signing era, the issuer, the bundle path, and that no
    `-regexp` flag is ever passed;
  * a file whose hash appears only on ANOTHER file's line must fail (the old
    false pass), as must a tampered file, an ambiguous or missing name, a bad
    signature (cosign's stderr must be shown), a missing .sigstore, a legacy
    .bundle-only release, an absent cosign, and a malformed version.

MutationSelfTest then applies a mutant of the script (always to a scratch COPY,
never the tracked file) for each guarded behaviour and requires the matching
case to fail, so a case that cannot catch its bug is itself a failure.
Stdlib only; needs a POSIX bash, so it skips on Windows.
"""

import hashlib
import os
import shutil
import stat
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
REAL_SCRIPT = ROOT / "scripts" / "build-agent-bundle.sh"
SCRIPT = Path(os.environ.get("YUZU_BUNDLE_SCRIPT", str(REAL_SCRIPT)))
BASH = shutil.which("bash") or "bash"
IN_MUTATION_RUN = "YUZU_BUNDLE_SCRIPT" in os.environ

ISSUER = "https://token.actions.githubusercontent.com"
OLD, NEW = "Tr3kkR/Yuzu", "DevNullLtd/Yuzu"
FORK = "Example/Fork"          # the checkout's origin; must never decide the signer

# Tools the script needs, linked into a private PATH dir so "cosign absent" is
# testable without the host's cosign (or anything else) leaking in.
TOOLS = ["git", "sed", "awk", "tr", "cut", "mktemp", "sha256sum", "ls", "head", "cat",
         "rm", "wc", "mkdir", "cp", "dirname", "basename", "grep", "sort", "env",
         "tail", "uname", "find", "xargs", "id", "chmod", "du", "date", "printf"]

GH_STUB = r"""#!/bin/bash
printf '%s\n' "$@" > "$STUB_LOG_DIR/gh.argv"
[ "$1 $2" = "release download" ] || exit 9
dest=""; pats=()
shift 2
while [ $# -gt 0 ]; do
  case "$1" in
    -D) dest="$2"; shift ;;
    -p) pats+=("$2"); shift ;;
  esac
  shift
done
for f in "$STUB_FIXTURE"/*; do
  b="$(basename "$f")"
  for p in "${pats[@]}"; do
    case "$b" in $p) cp "$f" "$dest/$b" ;; esac
  done
done
exit "${STUB_GH_RC:-0}"
"""

COSIGN_STUB = r"""#!/bin/bash
printf '%s\n' "$@" > "$STUB_LOG_DIR/cosign.argv"
[ -n "${STUB_COSIGN_STDERR:-}" ] && printf '%s\n' "$STUB_COSIGN_STDERR" >&2
exit "${STUB_COSIGN_RC:-0}"
"""


def sha(b: bytes) -> str:
    return hashlib.sha256(b).hexdigest()


def artifacts(version: str) -> dict:
    return {
        "yuzu-linux-x64.tar.gz": b"linux",
        "yuzu-agent-windows-x64.zip": b"win",
        "yuzu-agent-macos-arm64.tar.gz": b"mac",
        f"yuzu-agent_{version}_amd64.deb": b"deb",
        f"yuzu-agent-{version}-1.x86_64.rpm": b"rpm",
        f"YuzuAgent-{version}-macos-arm64.pkg": b"pkg",
        f"YuzuAgentSetup-{version}.exe": b"exe",
    }


@unittest.skipIf(os.name == "nt" or shutil.which("bash") is None, "needs a POSIX bash")
class VerifyTests(unittest.TestCase):
    def setUp(self):
        self._td = tempfile.TemporaryDirectory(prefix="yuzu_test_bundle_verify_")
        self.addCleanup(self._td.cleanup)
        self.tmp = Path(self._td.name)
        self.fixture = self.tmp / "fixture"
        self.logs = self.tmp / "logs"
        self.toolbin = self.tmp / "toolbin"
        self.stubs = self.tmp / "stubs"
        self.scratch = self.tmp / "scratch"          # the script's TMPDIR
        for d in (self.fixture, self.logs, self.toolbin, self.stubs, self.scratch):
            d.mkdir()
        for t in TOOLS:
            real = shutil.which(t)
            if real:
                (self.toolbin / t).symlink_to(real)
        self._stub("gh", GH_STUB)

    def _stub(self, name, body):
        p = self.stubs / name
        p.write_text(body)
        p.chmod(p.stat().st_mode | stat.S_IXUSR)

    def release(self, version="0.15.0", sums_lines=None, sigstore=True, legacy_bundle=False,
                overrides=None, drop=()):
        """Write a fixture release; sums_lines defaults to a correct manifest."""
        files = artifacts(version)
        for k, v in (overrides or {}).items():
            files[k] = v
        for name, body in files.items():
            if name not in drop:
                (self.fixture / name).write_bytes(body)
        if sums_lines is None:
            sums_lines = [f"{sha(b)}  {n}" for n, b in artifacts(version).items()]
        (self.fixture / "SHA256SUMS").write_text("\n".join(sums_lines) + "\n")
        if sigstore:
            (self.fixture / "SHA256SUMS.sigstore").write_text("{}")
        if legacy_bundle:
            (self.fixture / "SHA256SUMS.bundle").write_text("{}")
        return files

    def run_script(self, *args, cosign=True, cosign_rc=0, cosign_stderr="", extra_env=None,
                   cosign_body=COSIGN_STUB):
        if cosign:
            self._stub("cosign", cosign_body)
        env = {
            "PATH": f"{self.stubs}:{self.toolbin}",
            "HOME": str(self.tmp),
            "TMPDIR": str(self.scratch),
            "YUZU_REPO_SLUG": FORK,
            "STUB_FIXTURE": str(self.fixture),
            "STUB_LOG_DIR": str(self.logs),
            "STUB_COSIGN_RC": str(cosign_rc),
            "STUB_COSIGN_STDERR": cosign_stderr,
        }
        env.update(extra_env or {})
        if not cosign and (self.stubs / "cosign").exists():
            (self.stubs / "cosign").unlink()
        return subprocess.run([BASH, str(SCRIPT), "--verify-only", *args], cwd=ROOT,
                              env=env, capture_output=True, text=True)

    def cosign_argv(self):
        return (self.logs / "cosign.argv").read_text().splitlines()

    def assertFailed(self, r, *needles):
        out = r.stdout + r.stderr
        self.assertNotEqual(r.returncode, 0, out)
        for n in needles:
            self.assertIn(n, out)
        self.assertNotIn("match their own SHA256SUMS line", out)

    def assertCleanedUp(self):
        self.assertEqual(list(self.scratch.iterdir()), [], "script left its mktemp dir behind")

    # ---- the good path and the exact cosign argv ------------------------------------
    def test_good_release_passes_with_exact_identity(self):
        self.release("0.15.0")
        r = self.run_script("--version", "0.15.0")
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        self.assertIn("match their own SHA256SUMS line", r.stdout)
        argv = self.cosign_argv()
        self.assertEqual(argv[0], "verify-blob")
        self.assertEqual(argv[argv.index("--certificate-identity") + 1],
                         f"https://github.com/{NEW}/.github/workflows/release.yml@refs/tags/v0.15.0")
        self.assertEqual(argv[argv.index("--certificate-oidc-issuer") + 1], ISSUER)
        bundle = argv[argv.index("--bundle") + 1]
        self.assertTrue(bundle.startswith(str(self.scratch) + "/yuzu-agent-bundle."), bundle)
        self.assertTrue(bundle.endswith("/SHA256SUMS.sigstore"), bundle)
        self.assertTrue(argv[-1].endswith("/SHA256SUMS"), argv)
        self.assertEqual(len(argv), 8, argv)
        self.assertFalse([a for a in argv if "regexp" in a], argv)
        gh = (self.logs / "gh.argv").read_text().splitlines()
        self.assertIn("v0.15.0", gh)
        self.assertEqual(gh[gh.index("--repo") + 1], FORK)   # download follows origin, signer does not
        self.assertCleanedUp()

    def test_signer_table_by_era(self):
        cases = [("0.9.0", OLD), ("0.11.0", OLD), ("0.13.0", OLD), ("0.13.9", OLD),
                 ("0.13.0-rc1", OLD), ("0.14.0-rc2", NEW), ("0.14.0", NEW),
                 ("0.15.0", NEW), ("1.0.0", NEW), ("v0.14.0-rc2", NEW)]
        for ver, signer in cases:
            with self.subTest(version=ver):
                for p in self.fixture.glob("*"):
                    p.unlink()
                bare = ver.lstrip("v")
                self.release(bare)
                r = self.run_script("--version", ver)
                self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
                argv = self.cosign_argv()
                self.assertEqual(
                    argv[argv.index("--certificate-identity") + 1],
                    f"https://github.com/{signer}/.github/workflows/release.yml@refs/tags/v{bare}")
                self.assertFalse([a for a in argv if "regexp" in a])

    def test_signer_never_comes_from_the_checkout_origin(self):
        # FORK is the origin in every run; neither era's identity may mention it.
        self.release("0.13.0")
        r = self.run_script("--version", "0.13.0")
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        self.assertNotIn("Example", " ".join(self.cosign_argv()))

    def test_signer_repo_override(self):
        self.release("0.15.0")
        r = self.run_script("--version", "0.15.0", "--signer-repo", OLD)
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        argv = self.cosign_argv()
        self.assertEqual(argv[argv.index("--certificate-identity") + 1],
                         f"https://github.com/{OLD}/.github/workflows/release.yml@refs/tags/v0.15.0")
        r = self.run_script("--version", "0.15.0", f"--signer-repo={NEW}")
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        self.assertIn(NEW, " ".join(self.cosign_argv()))

    def test_malformed_signer_repo_refused(self):
        self.release("0.15.0")
        r = self.run_script("--version", "0.15.0", "--signer-repo", "no-slash")
        self.assertFailed(r, "malformed --signer-repo")

    def test_malformed_versions_refused_before_any_download(self):
        for bad in ["0.14", "abc", "0.14.0-rc", "1.2.3.4", "0.99999.0", "0.14.0;ls",
                    "0.14.0-rc1x", "00000.1.0", "0.14.0-gamma1", "-1.0.0", "0.14.0 ",
                    "0.13.0/../1", ""]:
            with self.subTest(version=bad):
                (self.logs / "gh.argv").unlink(missing_ok=True)
                self.release("0.15.0")
                r = self.run_script("--version", bad)
                self.assertFailed(r, "malformed --version")
                self.assertFalse((self.logs / "gh.argv").exists(), "downloaded before validating")

    # ---- signature failures ---------------------------------------------------------
    def test_bad_signature_fails_and_shows_cosign_stderr(self):
        self.release("0.15.0")
        r = self.run_script("--version", "0.15.0", cosign_rc=1,
                            cosign_stderr="Error: none of the expected identities matched")
        self.assertFailed(r, "cosign verify-blob FAILED", "none of the expected identities matched")
        self.assertCleanedUp()

    def test_wrong_era_signer_fails(self):
        # The stub cannot judge identities, so model the real behaviour: it fails
        # whenever the identity is not the one the fixture was "signed" with.
        self.release("0.13.0")
        stub = COSIGN_STUB.replace(
            "exit \"${STUB_COSIGN_RC:-0}\"",
            'case "$*" in *"/Tr3kkR/Yuzu/"*) exit 0 ;; esac\n'
            'echo "Error: certificate identity mismatch" >&2; exit 1')
        r = self.run_script("--version", "0.13.0", "--signer-repo", NEW, cosign_body=stub)
        self.assertFailed(r, "certificate identity mismatch")

    def test_missing_sigstore_fails_closed(self):
        self.release("0.15.0", sigstore=False)
        r = self.run_script("--version", "0.15.0")
        self.assertFailed(r, "no SHA256SUMS.sigstore")
        self.assertFalse((self.logs / "cosign.argv").exists())

    def test_legacy_bundle_only_release_fails_closed_naming_it(self):
        self.release("0.11.0", sigstore=False, legacy_bundle=True)
        r = self.run_script("--version", "0.11.0")
        self.assertFailed(r, "legacy SHA256SUMS.bundle")
        self.assertFalse((self.logs / "cosign.argv").exists())

    def test_cosign_absent_fails_closed(self):
        self.release("0.15.0")
        r = self.run_script("--version", "0.15.0", cosign=False)
        self.assertFailed(r, "need cosign on PATH")
        self.assertFalse((self.logs / "gh.argv").exists(), "must stop before downloading")

    # ---- per-file hash lookup -------------------------------------------------------
    def test_tampered_file_fails(self):
        self.release("0.15.0", overrides={"yuzu-linux-x64.tar.gz": b"evil"})
        r = self.run_script("--version", "0.15.0")
        self.assertFailed(r, "hash MISMATCH", "yuzu-linux-x64.tar.gz")

    def test_hash_only_on_another_files_line_fails(self):
        # The old false pass: the hash of the tampered .exe is present in the
        # manifest, but only on a line named for a different file.
        ver = "0.15.0"
        evil = b"evil-exe"
        good = artifacts(ver)
        lines = [f"{sha(b)}  {n}" for n, b in good.items() if not n.endswith(".exe")]
        lines.append(f"{sha(b'some other exe')}  YuzuAgentSetup-{ver}.exe")
        lines.append(f"{sha(evil)}  decoy-unrelated-file.txt")
        self.release(ver, sums_lines=lines, overrides={f"YuzuAgentSetup-{ver}.exe": evil})
        r = self.run_script("--version", ver)
        self.assertFailed(r, "hash MISMATCH", f"YuzuAgentSetup-{ver}.exe")

    def test_file_with_no_line_of_its_own_fails_even_if_hash_listed_elsewhere(self):
        ver = "0.15.0"
        lines = [f"{sha(b)}  {n}" for n, b in artifacts(ver).items() if not n.endswith(".exe")]
        lines.append(f"{sha(b'exe')}  decoy-unrelated-file.txt")      # right hash, wrong name
        self.release(ver, sums_lines=lines)
        r = self.run_script("--version", ver)
        self.assertFailed(r, "no line for", f"YuzuAgentSetup-{ver}.exe")

    def test_substring_and_prefix_names_do_not_match(self):
        ver = "0.15.0"
        lines = [f"{sha(b)}  {n}" for n, b in artifacts(ver).items() if n != "yuzu-linux-x64.tar.gz"]
        lines.append(f"{sha(b'linux')}  other-yuzu-linux-x64.tar.gz")
        lines.append(f"{sha(b'linux')}  yuzu-linux-x64.tar.gz.sig")
        self.release(ver, sums_lines=lines)
        r = self.run_script("--version", ver)
        self.assertFailed(r, "no line for", "yuzu-linux-x64.tar.gz")

    def test_ambiguous_duplicate_name_fails(self):
        ver = "0.15.0"
        lines = [f"{sha(b)}  {n}" for n, b in artifacts(ver).items()]
        lines.append(f"{sha(b'linux')}  yuzu-linux-x64.tar.gz")
        self.release(ver, sums_lines=lines)
        r = self.run_script("--version", ver)
        self.assertFailed(r, "ambiguous", "yuzu-linux-x64.tar.gz")

    def test_ambiguous_sanitised_name_fails(self):
        ver = "0.12.0.rc0"                       # as GitHub serves 0.12.0~rc0
        art = artifacts(ver)
        tilde = f"yuzu-agent_0.12.0~rc0_amd64.deb"
        lines = [f"{sha(b)}  {n}" for n, b in art.items() if not n.endswith(".deb")]
        lines += [f"{sha(b'deb')}  {tilde}", f"{sha(b'deb')}  {tilde}"]
        self.release(ver, sums_lines=lines)
        r = self.run_script("--version", "0.13.0")
        self.assertFailed(r, "ambiguous")

    def test_tilde_sanitised_name_matches_when_unique(self):
        ver = "0.12.0.rc0"
        art = artifacts(ver)
        lines = [f"{sha(b)}  {n}" for n, b in art.items() if not n.endswith(".deb")]
        lines.append(f"{sha(b'deb')}  yuzu-agent_0.12.0~rc0_amd64.deb")
        self.release(ver, sums_lines=lines)
        r = self.run_script("--version", "0.13.0")
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)

    def test_exact_name_wins_over_tilde_fallback(self):
        # An exact line with the wrong hash must fail even if a ~ line would match.
        ver = "0.15.0"
        art = artifacts(ver)
        lines = [f"{sha(b)}  {n}" for n, b in art.items() if n != "yuzu-linux-x64.tar.gz"]
        lines.append(f"{sha(b'nope')}  yuzu-linux-x64.tar.gz")
        lines.append(f"{sha(b'linux')}  yuzu-linux-x64~tar.gz")      # would match if ~ were read as .
        self.release(ver, sums_lines=lines)
        r = self.run_script("--version", ver)
        self.assertFailed(r, "hash MISMATCH")

    def test_binary_marker_tolerated(self):
        ver = "0.15.0"
        lines = [f"{sha(b)} *{n}" for n, b in artifacts(ver).items()]
        self.release(ver, sums_lines=lines)
        r = self.run_script("--version", ver)
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)

    def test_uppercase_hash_refused(self):
        ver = "0.15.0"
        lines = [f"{sha(b)}  {n}" for n, b in artifacts(ver).items() if n != "yuzu-linux-x64.tar.gz"]
        lines.append(f"{sha(b'linux').upper()}  yuzu-linux-x64.tar.gz")
        self.release(ver, sums_lines=lines)
        r = self.run_script("--version", ver)
        self.assertFailed(r, "malformed hash")

    def test_old_archive_names_are_used_when_new_ones_are_absent(self):
        # Releases before ADR-0035 step 2 name the archives yuzu-windows-x64.zip /
        # yuzu-macos-arm64.tar.gz; the fallback must work, not exit silently.
        ver = "0.13.0"
        art = {n: b for n, b in artifacts(ver).items()
               if n not in ("yuzu-agent-windows-x64.zip", "yuzu-agent-macos-arm64.tar.gz")}
        art["yuzu-windows-x64.zip"] = b"oldwin"
        art["yuzu-macos-arm64.tar.gz"] = b"oldmac"
        for n, b in art.items():
            (self.fixture / n).write_bytes(b)
        (self.fixture / "SHA256SUMS").write_text(
            "".join(f"{sha(b)}  {n}\n" for n, b in art.items()))
        (self.fixture / "SHA256SUMS.sigstore").write_text("{}")
        r = self.run_script("--version", ver)
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)

    def test_missing_installer_names_the_asset(self):
        self.release("0.15.0", drop=("YuzuAgentSetup-0.15.0.exe",))
        r = self.run_script("--version", "0.15.0")
        self.assertFailed(r, "no Windows installer asset")

    def test_verify_only_stops_and_leaves_no_build_state(self):
        self.release("0.15.0")
        staging = ROOT / "deploy" / "docker" / ".agent-bundle-build"
        existed = staging.exists()
        r = self.run_script("--version", "0.15.0")
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        self.assertIn("--verify-only", r.stdout)
        self.assertNotIn("Laying out", r.stdout)
        self.assertEqual(staging.exists(), existed)


@unittest.skipIf(os.name == "nt" or shutil.which("bash") is None or IN_MUTATION_RUN,
                 "needs a POSIX bash; not recursive")
class MutationSelfTest(unittest.TestCase):
    """Each mutant breaks one guarded behaviour in a scratch copy of the script;
    the named VerifyTests case must then FAIL (else it cannot catch its bug)."""

    V = "VerifyTests."
    MUTANTS = [
        ("skip-cosign",
         "if ! cosign verify-blob", "if ! true",
         ["test_bad_signature_fails_and_shows_cosign_stderr", "test_good_release_passes_with_exact_identity"]),
        ("identity-as-regexp",
         '--certificate-identity "$SIGNER_IDENTITY"', '--certificate-identity-regexp "$SIGNER_IDENTITY"',
         ["test_good_release_passes_with_exact_identity", "test_signer_table_by_era"]),
        ("wrong-issuer",
         '--certificate-oidc-issuer "$SIGNER_ISSUER"', '--certificate-oidc-issuer "https://example.invalid"',
         ["test_good_release_passes_with_exact_identity"]),
        ("stderr-hidden",
         "sed 's/^/     cosign: /' \"$DL/cosign.err\" >&2", "true",
         ["test_bad_signature_fails_and_shows_cosign_stderr"]),
        ("signer-from-origin",
         'SIGNER_REPO="$(parse_signer_repo "$VERSION")"', 'SIGNER_REPO="$REPO_SLUG"',
         ["test_signer_never_comes_from_the_checkout_origin", "test_signer_table_by_era"]),
        ("era-boundary-moved",
         '[ "$minor" -le 13 ]', '[ "$minor" -le 14 ]',
         ["test_signer_table_by_era"]),
        ("override-ignored",
         'SIGNER_REPO="$2"; shift', "shift",
         ["test_signer_repo_override"]),
        ("version-unchecked",
         '|| die "malformed --version', '|| true # "malformed --version',
         ["test_malformed_versions_refused_before_any_download"]),
        ("cosign-optional",
         'command -v cosign >/dev/null 2>&1 || die', 'command -v cosign >/dev/null 2>&1 || true #',
         ["test_cosign_absent_fails_closed"]),
        ("missing-sigstore-tolerated",
         'if [ ! -s "$DL/SHA256SUMS.sigstore" ]; then', 'if [ -e /nonexistent/yuzu_mutant ]; then',
         ["test_missing_sigstore_fails_closed"]),
        ("legacy-bundle-not-named",
         '[ -s "$DL/SHA256SUMS.bundle" ]', '[ -s "$DL/nonexistent.bundle" ]',
         ["test_legacy_bundle_only_release_fails_closed_naming_it"]),
        ("hash-compare-dropped",
         '[ "$h" = "$want" ] || die', 'true || die',
         ["test_tampered_file_fails", "test_hash_only_on_another_files_line_fails", "test_exact_name_wins_over_tilde_fallback"]),
        ("own-line-not-required",
         '[ -n "$matches" ] || die "no line for', '[ -n "$matches" ] || matches="$h" # no line for',
         ["test_file_with_no_line_of_its_own_fails_even_if_hash_listed_elsewhere", "test_substring_and_prefix_names_do_not_match"]),
        ("ambiguity-tolerated",
         '[ "$n" = 1 ] || die', '[ "$n" = 1 ] || matches="$(printf \'%s\\n\' "$matches" | head -1)" #',
         ["test_ambiguous_duplicate_name_fails", "test_ambiguous_sanitised_name_fails"]),
        ("name-match-loosened",
         "if (name == want)", "if (index(name, want))",
         ["test_substring_and_prefix_names_do_not_match"]),
        ("hash-shape-unchecked",
         '[[ "$want" =~ ^[0-9a-f]{64}$ ]] || die', 'true || die',
         ["test_uppercase_hash_refused"]),
        ("tilde-fallback-removed",
         'matches="$(sums_hashes "$f" sanitised)"', 'matches=""',
         ["test_tilde_sanitised_name_matches_when_unique"]),
        ("tilde-fallback-always",
         'if [ -z "$matches" ]; then', 'if true; then',
         ["test_exact_name_wins_over_tilde_fallback"]),
        ("binary-marker-refused",
         '|| substr($0, 66, 1) == "*"', '|| 0',
         ["test_binary_marker_tolerated"]),
        ("pick-dies-silently-on-no-match",
         '2>/dev/null | head -1 ) || true; }', '2>/dev/null | head -1 ); }',
         ["test_old_archive_names_are_used_when_new_ones_are_absent", "test_missing_installer_names_the_asset"]),
        ("verify-only-continues",
         'ok "--verify-only: $TAG verified (signer $SIGNER_REPO); stopping before any build"\n  exit 0',
         'ok "--verify-only: $TAG verified (signer $SIGNER_REPO); stopping before any build"',
         ["test_verify_only_stops_and_leaves_no_build_state"]),
    ]

    def test_every_guard_has_a_case_that_catches_its_mutant(self):
        text = REAL_SCRIPT.read_text()
        with tempfile.TemporaryDirectory(prefix="yuzu_test_bundle_mutant_") as d:
            clean = self._run(REAL_SCRIPT, [])
            self.assertEqual(clean.returncode, 0, "unmutated script must pass:\n" + clean.stderr)
            for name, old, new, tests in self.MUTANTS:
                with self.subTest(mutant=name):
                    self.assertEqual(text.count(old), 1, f"mutant {name}: anchor not unique in script")
                    mutant = Path(d) / f"{name}.sh"
                    mutant.write_text(text.replace(old, new))
                    r = self._run(mutant, [self.V + t for t in tests])
                    self.assertNotEqual(r.returncode, 0, f"mutant {name} survived all of {tests}")
                    for t in tests:
                        self.assertRegex(r.stderr, rf"(FAIL|ERROR): {t} ",
                                         f"mutant {name} not caught by {t}")

    @staticmethod
    def _run(script, tests):
        env = dict(os.environ, YUZU_BUNDLE_SCRIPT=str(script))
        cmd = [sys.executable, "-I", str(Path(__file__).resolve()), *(tests or ["VerifyTests"])]
        return subprocess.run(cmd, env=env, capture_output=True, text=True)


if __name__ == "__main__":
    unittest.main()
