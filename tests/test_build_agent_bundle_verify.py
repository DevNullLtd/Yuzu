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
import io
import os
import shutil
import stat
import subprocess
import sys
import tarfile
import tempfile
import unittest
import zipfile
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
         "tail", "uname", "find", "xargs", "id", "chmod", "du", "date", "printf",
         # shasum is a perl script: the macOS fallback needs both (and a case hides sha256sum).
         "shasum", "perl",
         # only the (docker-stubbed) build cases need these
         "tar", "gzip", "unzip"]

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


def installers(version: str, deb_sep: str = ".") -> dict:
    """Installer file names as published (real spellings, checked against the
    DevNullLtd/Yuzu releases): stable 0.15.0 -> _0.15.0_ / -0.15.0-1. / -0.15.0-macos /
    -0.15.0.exe; prerelease 0.13.0-rc6 -> deb _0.13.0.rc6_ (or -rc6 from 0.14.0-rc3 on;
    deb_sep picks '.', '-' or '~'), rpm -0.13.0-0.1.rc6., pkg/exe 0.13.0_rc6."""
    base, _, pre = version.partition("-")
    if pre:
        return {
            f"yuzu-agent_{base}{deb_sep}{pre}_amd64.deb": b"deb",
            f"yuzu-agent-{base}-0.1.{pre}.x86_64.rpm": b"rpm",
            f"YuzuAgent-{base}_{pre}-macos-arm64.pkg": b"pkg",
            f"YuzuAgentSetup-{base}_{pre}.exe": b"exe",
        }
    return {
        f"yuzu-agent_{version}_amd64.deb": b"deb",
        f"yuzu-agent-{version}-1.x86_64.rpm": b"rpm",
        f"YuzuAgent-{version}-macos-arm64.pkg": b"pkg",
        f"YuzuAgentSetup-{version}.exe": b"exe",
    }


def artifacts(version: str, deb_sep: str = ".") -> dict:
    return {
        "yuzu-linux-x64.tar.gz": b"linux",
        "yuzu-agent-windows-x64.zip": b"win",
        "yuzu-agent-macos-arm64.tar.gz": b"mac",
        **installers(version, deb_sep),
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
        self.repo = self.tmp / "repo"                # the script's REPO_ROOT: NEVER the real checkout
        for d in (self.fixture, self.logs, self.toolbin, self.stubs, self.scratch, self.repo):
            d.mkdir()
        # The script `cd`s to `git rev-parse --show-toplevel` and creates/removes a
        # staging dir under deploy/docker, so it only ever runs from a scratch
        # `git init` copy (the test_ensure_install_helpers.py pattern), never from
        # the checkout this test lives in (#7529 governance UP-1).
        subprocess.run(["git", "init", "-q", str(self.repo)], check=True,
                       env={"PATH": os.environ["PATH"], "HOME": str(self.tmp)})
        (self.repo / "scripts").mkdir()
        shutil.copy(SCRIPT, self.repo / "scripts" / "build-agent-bundle.sh")
        (self.repo / "deploy" / "docker").mkdir(parents=True)
        for f in ("Dockerfile.agent-bundle.chisel", "agent-bundle-extract.sh"):
            shutil.copy(ROOT / "deploy" / "docker" / f, self.repo / "deploy" / "docker" / f)
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
                   cosign_body=COSIGN_STUB, verify_only=True, hide=()):
        for t in hide:
            (self.toolbin / t).unlink(missing_ok=True)
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
        script = self.repo / "scripts" / "build-agent-bundle.sh"
        pre = ["--verify-only"] if verify_only else []
        return subprocess.run([BASH, str(script), *pre, *args], cwd=self.repo,
                              env=env, capture_output=True, text=True)

    def staging_dirs(self):
        return sorted(p.name for p in (self.repo / "deploy" / "docker").glob(".agent-bundle-build*"))

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

    def test_override_differing_from_the_era_table_warns_loudly(self):
        self.release("0.15.0")
        r = self.run_script("--version", "0.15.0", "--signer-repo", OLD)
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        self.assertIn("[!!] --signer-repo Tr3kkR/Yuzu differs from the era table's DevNullLtd/Yuzu", r.stdout)
        # the era default and an override equal to it stay silent
        for extra in ([], ["--signer-repo", NEW]):
            r = self.run_script("--version", "0.15.0", *extra)
            self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
            self.assertNotIn("differs from the era table", r.stdout)

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

    def test_failure_text_names_only_the_two_signers_and_forbids_copying_the_subject(self):
        # SEC-1/SRE-1: the die text must not invite --signer-repo <what cosign reported>.
        self.release("0.15.0")
        r = self.run_script("--version", "0.15.0", cosign_rc=1,
                            cosign_stderr="Error: expected SAN github.com/Attacker/Yuzu")
        self.assertFailed(r, "Tr3kkR/Yuzu", "DevNullLtd/Yuzu", "tampered release or the wrong download source",
                          "NEVER set --signer-repo", "cosign older than v2.6.2",
                          "There is no offline mode", "treat it as permanent")
        self.assertNotIn("wrong --signer-repo", r.stdout + r.stderr)

    def test_bad_signature_wins_over_a_tampered_file(self):
        # QE-1 / ordering: with BOTH a bad signature and a tampered file the run
        # must stop at the signature, never reach (or report) the hash.
        self.release("0.15.0", overrides={"yuzu-linux-x64.tar.gz": b"evil"})
        r = self.run_script("--version", "0.15.0", cosign_rc=1, cosign_stderr="Error: bad sig")
        self.assertFailed(r, "cosign verify-blob FAILED")
        self.assertNotIn("hash MISMATCH", r.stdout + r.stderr)

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
        # needle is the NON-legacy text: the legacy branch says "(no SHA256SUMS.sigstore)"
        self.assertFailed(r, "no SHA256SUMS.sigstore on v0.15.0")
        self.assertNotIn("legacy", r.stdout + r.stderr)
        self.assertIn("v0.8.0-rc0 to v0.10.0 carry neither", r.stdout + r.stderr)   # C8-1: cause on THIS branch
        self.assertFalse((self.logs / "cosign.argv").exists())

    def test_legacy_bundle_only_release_fails_closed_naming_it(self):
        self.release("0.7.1-rc1", sigstore=False, legacy_bundle=True)   # the only .bundle-only era (v0.7.x)
        r = self.run_script("--version", "0.7.1-rc1")
        self.assertFailed(r, "legacy SHA256SUMS.bundle")
        # UP-2: the by-hand command is inline, exact and tag-bound (no doc pointer, no regexp).
        self.assertIn("cosign verify-blob --bundle SHA256SUMS.bundle --certificate-identity "
                      f"https://github.com/{OLD}/.github/workflows/release.yml@refs/tags/v0.7.1-rc1 "
                      f"--certificate-oidc-issuer {ISSUER} SHA256SUMS", r.stdout + r.stderr)
        self.assertNotIn("regexp", r.stdout + r.stderr)
        self.assertNotIn("v0.8.0-rc0", r.stdout + r.stderr)
        self.assertFalse((self.logs / "cosign.argv").exists())

    def test_cosign_absent_fails_closed(self):
        self.release("0.15.0")
        r = self.run_script("--version", "0.15.0", cosign=False)
        self.assertFailed(r, "need cosign on PATH", "install cosign from the Sigstore releases", "cosign version")
        self.assertNotIn("have no cosign package", r.stdout + r.stderr)
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
        ver = "0.13.0-rc6"                       # GitHub serves the manifest's 0.13.0~rc6 as 0.13.0.rc6
        art = artifacts(ver)
        tilde = "yuzu-agent_0.13.0~rc6_amd64.deb"
        lines = [f"{sha(b)}  {n}" for n, b in art.items() if not n.endswith(".deb")]
        lines += [f"{sha(b'deb')}  {tilde}", f"{sha(b'deb')}  {tilde}"]
        self.release(ver, sums_lines=lines)
        r = self.run_script("--version", ver)
        self.assertFailed(r, "ambiguous")

    def test_tilde_sanitised_name_matches_when_unique(self):
        ver = "0.13.0-rc6"
        art = artifacts(ver)
        lines = [f"{sha(b)}  {n}" for n, b in art.items() if not n.endswith(".deb")]
        lines.append(f"{sha(b'deb')}  yuzu-agent_0.13.0~rc6_amd64.deb")
        self.release(ver, sums_lines=lines)
        r = self.run_script("--version", ver)
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

    # ---- installer selection is by the REQUESTED version (C8-2) -------------------------
    def _release_with_extra(self, ver, extra, sums_extra=True):
        files = self.release(ver)
        for n, b in extra.items():
            (self.fixture / n).write_bytes(b)
        if sums_extra:
            with (self.fixture / "SHA256SUMS").open("a") as f:
                for n, b in extra.items():
                    f.write(f"{sha(b)}  {n}\n")
        return files

    def test_installers_of_an_older_prerelease_on_the_same_release_are_not_picked(self):
        # v0.13.0-rc6 really carries the rc4 AND rc6 .deb/.rpm; `ls | head -1` bundled rc4.
        stale = {n: b"stale-" + b for n, b in installers("0.13.0-rc4").items()}
        self._release_with_extra("0.13.0-rc6", stale)
        r = self.run_script("--version", "0.13.0-rc6")
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        sel = [l for l in r.stdout.splitlines() if "Installers selected" in l]
        self.assertEqual(len(sel), 1, r.stdout)
        for n in installers("0.13.0-rc6"):
            self.assertIn(n, sel[0])
        self.assertNotIn("rc4", sel[0])

    def test_every_published_spelling_is_selected(self):
        for ver, sep in [("0.13.0-rc6", "."), ("0.14.0-rc2", "."), ("0.14.0-rc3", "-"),
                         ("0.14.0-rc7", "~"), ("0.15.0", "."), ("0.8.1-alpha1", "."), ("0.9.0-beta2", "-")]:
            with self.subTest(version=ver, deb_sep=sep):
                for p in self.fixture.glob("*"):
                    p.unlink()
                art = artifacts(ver, sep)
                for n, b in art.items():
                    (self.fixture / n).write_bytes(b)
                (self.fixture / "SHA256SUMS").write_text("".join(f"{sha(b)}  {n}\n" for n, b in art.items()))
                (self.fixture / "SHA256SUMS.sigstore").write_text("{}")
                r = self.run_script("--version", ver)
                self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
                for n in installers(ver, sep):
                    self.assertIn(n, r.stdout)

    def test_two_installers_for_the_same_version_are_ambiguous(self):
        both = {"yuzu-agent_0.13.0-rc6_amd64.deb": b"deb2"}      # '.' and '-' spellings together
        self._release_with_extra("0.13.0-rc6", both)
        r = self.run_script("--version", "0.13.0-rc6")
        self.assertFailed(r, "ambiguous: 2 .deb installer assets", "yuzu-agent_0.13.0.rc6_amd64.deb",
                          "yuzu-agent_0.13.0-rc6_amd64.deb")

    def test_installers_only_for_another_version_are_refused_naming_them(self):
        ver = "0.13.0-rc6"
        wrong = installers("0.13.0-rc4")
        self.release(ver, drop=tuple(installers(ver)))
        for n, b in wrong.items():
            (self.fixture / n).write_bytes(b)
        r = self.run_script("--version", ver)
        self.assertFailed(r, "no .deb installer asset for 0.13.0-rc6", "yuzu-agent_0.13.0.rc4_amd64.deb")

    def test_missing_installer_names_the_asset(self):
        self.release("0.15.0", drop=("YuzuAgentSetup-0.15.0.exe",))
        r = self.run_script("--version", "0.15.0")
        self.assertFailed(r, "no Windows installer asset")

    def test_verify_only_stops_and_leaves_no_build_state(self):
        # A marker in the scratch checkout's staging area must survive (UP-1).
        marker = self.repo / "deploy" / "docker" / ".agent-bundle-build" / "marker"
        marker.parent.mkdir()
        marker.write_text("keep")
        self.release("0.15.0")
        r = self.run_script("--version", "0.15.0")
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        self.assertIn("--verify-only", r.stdout)
        self.assertNotIn("Laying out", r.stdout)
        self.assertTrue(marker.exists(), "a run deleted a staging tree it did not create")
        self.assertEqual(self.staging_dirs(), [".agent-bundle-build"])

    def test_verify_only_refuses_push_and_multiarch(self):
        # HP-1: --verify-only builds and pushes nothing, so the combination is an error, not a silent exit 0.
        self.release("0.15.0")
        for flag in ("--push", "--multiarch"):
            with self.subTest(flag=flag):
                (self.logs / "gh.argv").unlink(missing_ok=True)
                r = self.run_script("--version", "0.15.0", flag)
                self.assertFailed(r, "--verify-only downloads and verifies only")
                self.assertFalse((self.logs / "gh.argv").exists())

    def test_help_prints_the_whole_header_block(self):
        # DOC8-1: the range is derived from the header, not hard-coded.
        out = subprocess.run([BASH, str(self.repo / "scripts" / "build-agent-bundle.sh"), "-h"],
                             cwd=self.repo, capture_output=True, text=True,
                             env={"PATH": f"{self.toolbin}", "HOME": str(self.tmp), "YUZU_REPO_SLUG": FORK}).stdout
        lines = out.splitlines()
        self.assertEqual(lines[-1], "Windows/macOS agent artifacts). Override with --version for another release.")
        self.assertIn("--verify-only", out)
        self.assertFalse([l for l in lines if l.startswith("#")], out)   # the comment marker is stripped

    @unittest.skipIf(hasattr(os, "geteuid") and os.geteuid() == 0, "root reads a 000 file")
    def test_unreadable_manifest_after_cosign_dies_with_a_message(self):
        # UP-9: used to exit 2 with no [xx] line (a bare set -e abort).
        self.release("0.15.0")
        body = COSIGN_STUB.replace('exit "${STUB_COSIGN_RC:-0}"', 'chmod 000 "${@: -1}"; exit 0')
        r = self.run_script("--version", "0.15.0", cosign_body=body)
        self.assertFailed(r, "cannot read SHA256SUMS while looking up")

    def test_sha256sum_absent_falls_back_to_shasum(self):
        # XP-1: the macOS toolchain has shasum (perl) but no sha256sum.
        if shutil.which("shasum") is None or shutil.which("perl") is None:
            self.skipTest("needs shasum + perl")
        self.release("0.15.0")
        r = self.run_script("--version", "0.15.0", hide=("sha256sum",))
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        self.assertIn("match their own SHA256SUMS line", r.stdout)

    # ---- the build path (docker stubbed): per-run staging dir (UP-12) -----------------
    def _build_release(self, version="0.15.0"):
        def tgz(binname):
            b = io.BytesIO()
            with tarfile.open(fileobj=b, mode="w:gz") as t:
                for name, data, mode in (("top/bin/" + binname, b"#!/bin/sh\n", 0o755),
                                         ("top/plugins/p.so", b"so", 0o644)):
                    ti = tarfile.TarInfo(name)
                    ti.size, ti.mode = len(data), mode
                    t.addfile(ti, io.BytesIO(data))
            return b.getvalue()
        zb = io.BytesIO()
        with zipfile.ZipFile(zb, "w") as z:
            z.writestr("top/bin/yuzu-agent.exe", b"MZ")
            z.writestr("top/plugins/p.dll", b"dll")
        files = artifacts(version)
        files["yuzu-linux-x64.tar.gz"] = tgz("yuzu-agent")
        files["yuzu-agent-macos-arm64.tar.gz"] = tgz("yuzu-agent")
        files["yuzu-agent-windows-x64.zip"] = zb.getvalue()
        for n, b in files.items():
            (self.fixture / n).write_bytes(b)
        (self.fixture / "SHA256SUMS").write_text("".join(f"{sha(b)}  {n}\n" for n, b in files.items()))
        (self.fixture / "SHA256SUMS.sigstore").write_text("{}")
        self._stub("docker", '#!/bin/bash\nprintf "%s\\n" "$*" >> "$STUB_LOG_DIR/docker.argv"\n'
                             '[ "$1" = build ] && ls "${@: -1}" > "$STUB_LOG_DIR/docker.context"\nexit 0\n')

    def _build(self, *extra):
        if shutil.which("unzip") is None:
            self.skipTest("needs unzip")
        return self.run_script("--version", "0.15.0", "--no-test", *extra, verify_only=False)

    def test_build_uses_and_removes_only_its_own_staging_dir(self):
        self._build_release()
        old = self.repo / "deploy" / "docker" / ".agent-bundle-build" / "marker"
        other = self.repo / "deploy" / "docker" / ".agent-bundle-build.ZZZZZZ" / "marker"
        for m in (old, other):
            m.parent.mkdir()
            m.write_text("keep")
        r = self._build()
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        self.assertTrue(old.exists() and other.exists(), "a build deleted a tree it did not create")
        self.assertEqual(self.staging_dirs(), [".agent-bundle-build", ".agent-bundle-build.ZZZZZZ"])
        ctx = (self.logs / "docker.context").read_text()
        self.assertIn("yuzu-agents", ctx)          # docker built from the run's own tree
        self.assertIn("extract.sh", ctx)

    def test_keep_staging_prints_the_path_and_runs_get_distinct_dirs(self):
        self._build_release()
        r1 = self._build("--keep-staging")
        r2 = self._build("--keep-staging")
        for r in (r1, r2):
            self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        dirs = self.staging_dirs()
        self.assertEqual(len(dirs), 2, dirs)
        for d in dirs:
            self.assertRegex(d, r"^\.agent-bundle-build\.[A-Za-z0-9]{6}$")
            self.assertIn(f"staging kept at deploy/docker/{d}", r1.stdout + r2.stdout)

    def test_readmes_do_not_overclaim_signing_and_name_the_image_verification(self):
        # SEC8-2 / REL8-3: neither the Windows nor the macOS binaries are code-signed, and
        # the sha256 files cannot authenticate payload/ -- only the image signature does.
        self._build_release()
        r = self._build("--keep-staging")
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        (root,) = self.staging_dirs()
        tree = self.repo / "deploy" / "docker" / root / "yuzu-agents"
        top = (tree / "README.txt").read_text()
        win = (tree / "windows-x64" / "README.txt").read_text()
        mac = (tree / "macos-arm64" / "README.txt").read_text()
        ident = f"https://github.com/{NEW}/.github/workflows/release.yml@refs/tags/v0.15.0"
        image = "ghcr.io/example/yuzu-agent-bundle-chisel:0.15.0"
        for name, text in (("top", top), ("mac", mac)):
            with self.subTest(readme=name):
                self.assertIn(f"cosign verify {image}", text)
                self.assertIn(f"--certificate-identity {ident}", text)
                self.assertIn(f"--certificate-oidc-issuer {ISSUER}", text)
        self.assertLess(mac.index("cosign verify"), mac.index("xattr -dr com.apple.quarantine"))
        self.assertIn("NOT Authenticode-signed today, #239", win)
        self.assertIn("NOT Authenticode-signed today, #239", top)
        for text in (top, win, mac):
            self.assertNotRegex(text, r"(?<!NOT )(?<!not )Authenticode-signed")
            self.assertNotIn("via signed installer", text)

    def test_failed_build_cleans_its_staging_dir_and_keep_staging_preserves_it(self):
        self._build_release()
        (self.fixture / "yuzu-agent-windows-x64.zip").write_bytes(b"not a zip")
        # keep the manifest consistent so the failure is in the build, not the hash
        lines = [l for l in (self.fixture / "SHA256SUMS").read_text().splitlines()
                 if not l.endswith("yuzu-agent-windows-x64.zip")]
        lines.append(f"{sha(b'not a zip')}  yuzu-agent-windows-x64.zip")
        (self.fixture / "SHA256SUMS").write_text("\n".join(lines) + "\n")
        r = self._build()
        self.assertNotEqual(r.returncode, 0)
        self.assertEqual(self.staging_dirs(), [])
        r = self._build("--keep-staging")
        self.assertNotEqual(r.returncode, 0)
        self.assertEqual(len(self.staging_dirs()), 1)


class WorkflowArgvTests(unittest.TestCase):
    """release.yml's signing-time verify must use the same cosign flag set as the
    script (SEC8-5): a signature the script would reject must fail the signing job."""

    @staticmethod
    def _statement(text, anchor):
        """The shell statement starting at anchor, continuation lines joined."""
        i = text.index(anchor)
        out = []
        for line in text[i:].splitlines():
            out.append(line.rstrip("\\").strip())
            if not line.rstrip().endswith("\\"):
                break
        return " ".join(out)

    def test_signing_time_verify_matches_the_scripts_flag_set(self):
        wf = (ROOT / ".github" / "workflows" / "release.yml").read_text()
        sig = self._statement(wf, "cosign verify-blob --bundle SHA256SUMS.sigstore")
        scr = self._statement(REAL_SCRIPT.read_text(), "if ! cosign verify-blob")
        flags = lambda st: sorted(t for t in st.split() if t.startswith("--"))
        self.assertEqual(flags(sig), flags(scr), (sig, scr))
        self.assertEqual(flags(sig), ["--bundle", "--certificate-identity", "--certificate-oidc-issuer"])
        self.assertIn("release.yml@${SIGN_REF}", sig)
        self.assertNotIn("regexp", wf)


@unittest.skipIf(os.name == "nt" or shutil.which("bash") is None or IN_MUTATION_RUN,
                 "needs a POSIX bash; not recursive")
class MutationSelfTest(unittest.TestCase):
    """Each mutant breaks one guarded behaviour in a scratch copy of the script;
    the named VerifyTests case must then FAIL (else it cannot catch its bug)."""

    V = "VerifyTests."
    MUTANTS = [
        ("skip-cosign",
         "if ! cosign verify-blob", "if ! true",
         ["test_bad_signature_fails_and_shows_cosign_stderr", "test_good_release_passes_with_exact_identity",
          "test_bad_signature_wins_over_a_tampered_file"]),
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
         ["test_old_archive_names_are_used_when_new_ones_are_absent"]),
        ("verify-only-continues",
         'ok "--verify-only: $TAG verified (signer $SIGNER_REPO); stopping before any build"\n  exit 0',
         'ok "--verify-only: $TAG verified (signer $SIGNER_REPO); stopping before any build"',
         ["test_verify_only_stops_and_leaves_no_build_state"]),
        ("signer-warning-removed",
         'if [ "$SIGNER_REPO" != "$ERA_SIGNER_REPO" ]; then', 'if false; then',
         ["test_override_differing_from_the_era_table_warns_loudly"]),
        ("die-text-invites-override",
         'fail "NEVER set --signer-repo to the subject cosign reports above."',
         'fail "wrong --signer-repo for this era? pass the subject above."',
         ["test_failure_text_names_only_the_two_signers_and_forbids_copying_the_subject"]),
        ("legacy-bundle-doc-pointer",
         'verify that release by hand: cosign verify-blob --bundle SHA256SUMS.bundle --certificate-identity https://github.com/${SIGNER_REPO}/.github/workflows/release.yml@refs/tags/${TAG} --certificate-oidc-issuer ${SIGNER_ISSUER} SHA256SUMS',
         'verify that release by hand per release-verification.md',
         ["test_legacy_bundle_only_release_fails_closed_naming_it"]),
        ("shasum-wrong-algorithm",
         'SHACHK="shasum -a 256"', 'SHACHK="shasum -a 1"',
         ["test_sha256sum_absent_falls_back_to_shasum"]),
        ("fixed-staging-dir",
         'STAGING="$(mktemp -d "$REPO_ROOT/$STAGING_PREFIX.XXXXXX")" || die "cannot create a staging dir under $REPO_ROOT/deploy/docker"',
         'STAGING="$REPO_ROOT/$STAGING_PREFIX"; rm -rf "$STAGING"; mkdir -p "$STAGING"',
         ["test_build_uses_and_removes_only_its_own_staging_dir"]),
        ("keep-staging-silent",
         'info "staging kept at $STAGING"', 'true',
         ["test_keep_staging_prints_the_path_and_runs_get_distinct_dirs"]),
        ("staging-never-cleaned",
         'case "$STAGING" in "$STAGING_PREFIX".??????) rm -rf "$STAGING" 2>/dev/null || warn "could not remove the staging dir $STAGING" ;; esac', 'true',
         ["test_failed_build_cleans_its_staging_dir_and_keep_staging_preserves_it"]),
        ("installer-first-match",
         'for c in "$@"; do [ -e "$DL/$c" ] && hits+=("$c"); done',
         'hits=($(cd "$DL" && ls $glob 2>/dev/null | head -1))',
         ["test_installers_of_an_older_prerelease_on_the_same_release_are_not_picked",
          "test_installers_only_for_another_version_are_refused_naming_them"]),
        ("installer-ambiguity-tolerated",
         '*) die "ambiguous: ${#hits[@]} $label',
         '*) printf -v "$var" \'%s\' "${hits[0]}" ;;\n    99) die "ambiguous: ${#hits[@]} $label',
         ["test_two_installers_for_the_same_version_are_ambiguous"]),
        ("installer-absence-tolerated",
         '0) present="$(',
         '0) printf -v "$var" \'%s\' "" ;;\n    99) present="$(',
         ["test_installers_only_for_another_version_are_refused_naming_them", "test_missing_installer_names_the_asset"]),
        ("verify-only-push-tolerated",
         '[ "$VERIFY_ONLY" = 0 ] || [ "$PUSH" = 0 ]', 'true',
         ["test_verify_only_refuses_push_and_multiarch"]),
        ("help-range-hardcoded",
         "awk 'NR == 1 { next } /^#/ { sub(/^# ?/, \"\"); print; next } { exit }' \"$0\"",
         "sed -n '2,39p' \"$0\" | sed 's/^# \\?//'",
         ["test_help_prints_the_whole_header_block"]),
        ("manifest-read-failure-silent",
         'matches="$(sums_hashes "$f" sanitised)" || die "cannot read SHA256SUMS while looking up $f"',
         'matches="$(sums_hashes "$f" sanitised)" || true',
         ["test_unreadable_manifest_after_cosign_dies_with_a_message"]),
        ("mac-readme-image-verify-removed",
         "  #   cosign verify ${IMAGE_REF} \\\\", "  #   true ${IMAGE_REF} \\\\",
         ["test_readmes_do_not_overclaim_signing_and_name_the_image_verification"]),
        ("windows-readme-claims-authenticode",
         "Yuzu Agent — windows-x64 — ${VERSION}  (NOT Authenticode-signed today, #239)",
         "Yuzu Agent — windows-x64 — ${VERSION}  (Authenticode-signed)",
         ["test_readmes_do_not_overclaim_signing_and_name_the_image_verification"]),
        ("legacy-branch-always",
         'if [ -s "$DL/SHA256SUMS.bundle" ]; then', 'if true; then',
         ["test_missing_sigstore_fails_closed"]),
    ]

    # A mutant's only catching case SKIPS on a host lacking the tool it drives; the
    # matching mutant must then skip too, else the suite goes red on that host
    # (BCI8-1 / XP8-1). Names map to the host requirements of the cases above.
    NEEDS = {
        "shasum-wrong-algorithm": ("shasum", "perl"),
        "fixed-staging-dir": ("unzip",),
        "keep-staging-silent": ("unzip",),
        "mac-readme-image-verify-removed": ("unzip",),
        "windows-readme-claims-authenticode": ("unzip",),
        "staging-never-cleaned": ("unzip",),
        "manifest-read-failure-silent": ("!root",),
    }

    @classmethod
    def _skip_reason(cls, name):
        for need in cls.NEEDS.get(name, ()):
            if need == "!root":
                if hasattr(os, "geteuid") and os.geteuid() == 0:
                    return "running as root (a 000 file stays readable)"
            elif shutil.which(need) is None:
                return f"needs {need}"
        return None

    def test_every_guard_has_a_case_that_catches_its_mutant(self):
        text = REAL_SCRIPT.read_text()
        with tempfile.TemporaryDirectory(prefix="yuzu_test_bundle_mutant_") as d:
            clean = self._run(REAL_SCRIPT, [])
            self.assertEqual(clean.returncode, 0, "unmutated script must pass:\n" + clean.stderr)
            for name, old, new, tests in self.MUTANTS:
                with self.subTest(mutant=name):
                    why = self._skip_reason(name)
                    if why:
                        self.skipTest(f"mutant {name}: its case skips here ({why})")
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
