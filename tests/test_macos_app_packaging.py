#!/usr/bin/env python3
"""Portable contracts for the macOS Endpoint Security development package lane."""

from __future__ import annotations

import datetime as dt
import importlib.util
import json
import os
import plistlib
import re
import shlex
import shutil
import subprocess
import sys
import tempfile
import unittest
from unittest import mock
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
HELPER = ROOT / "deploy/packaging/macos/build-app.py"
PLIST_HELPER = ROOT / "deploy/packaging/macos/generate-launchd-plist.py"
MERGE_PLIST_HELPER = ROOT / "deploy/packaging/macos/merge-launchd-plist.js"
BUILD_PKG = ROOT / "deploy/packaging/macos/build-pkg.sh"
# Run the package builder under the shell a stock Mac actually has. /bin/bash is
# GNU bash 3.2 on macOS; a newer bash first on PATH (Homebrew) hides 3.2-only
# defects such as an empty "${array[@]}" tripping `set -u` (PR #4482 review).
PKG_SHELL = "/bin/bash" if Path("/bin/bash").is_file() else "bash"


def script_function(source: str, name: str) -> str:
    """One shell function, verbatim, from an installer script."""
    start = source.index("\n" + name + "() {") + 1
    return source[start:source.index("\n}\n", start) + 3]
MACOS_TRIPLET = ROOT / "triplets/arm64-osx.cmake"
spec = importlib.util.spec_from_file_location("macos_bundle", HELPER)
assert spec and spec.loader
bundle = importlib.util.module_from_spec(spec)
spec.loader.exec_module(bundle)


# The installer scripts only ever run on macOS. Cases that reach BSD stat
# (`stat -f`), `shasum` or `ditto` need that userland; GNU coreutils parses
# `stat -f` as --file-system. Pure-Bash cases with stubbed platform commands
# stay portable to Linux, but native Windows cannot host the Bash fixtures.
macos_userland = unittest.skipUnless(sys.platform == "darwin", "needs macOS userland (BSD stat, shasum, ditto)")
posix_shell = unittest.skipIf(os.name == "nt", "POSIX Bash fixture; native Windows never runs these installers")

# Production preamble of every installer script (governance qe-2): a harness
# that drops pipefail or calls the function under test as `fn && echo X`
# suspends errexit inside it and hides a mid-function failure.
PREAMBLE = "set -euo pipefail\n"


def _shell_case(table: dict, default: str) -> str:
    arms = " ".join(f"{shlex.quote(str(path))}) echo {value} ;;" for path, value in table.items())
    return f'case "$3" in {arms} *) {default} ;; esac'


def stat_stub(owners: dict | None = None, modes: dict | None = None, real_modes: bool = False) -> str:
    """`stat -f FMT PATH` stub: the installer runs as root, a test does not.

    Owners and groups come from `owners` (default 0, root). Modes come from
    `modes`, else the real BSD stat (`real_modes`, macOS only) or 755.
    """
    mode_default = 'command stat "$@"' if real_modes else "echo 755"
    return ('stat() { case "$2" in '
            f'%u|%g) {_shell_case(owners or {}, "echo 0")} ;; '
            f'%Lp) {_shell_case(modes or {}, mode_default)} ;; '
            '*) command stat "$@" ;; esac; }\n')


def launchctl_stub(root: Path) -> str:
    """launchd as a state fixture: `print` answers from launchctl.state (absent:
    service not loaded), `print-disabled` from launchctl.disabled; every call
    is logged. `bootout` unloads (print then answers 113) until the next
    `bootstrap`, as launchd does once the job has gone; a test that needs a
    slow unload drives `print` itself. `sleep` is a no-op so the real
    require_started and stop_service run instantly."""
    return f'''launchctl() {{
    echo "$*" >> "{root}/launchctl.log"
    case "$1" in
        print) [[ ! -e "{root}/launchctl.unloaded" && -f "{root}/launchctl.state" ]] || return 113
               cat "{root}/launchctl.state" ;;
        print-disabled) cat "{root}/launchctl.disabled" 2>/dev/null || true ;;
        bootout) : > "{root}/launchctl.unloaded" ;;
        bootstrap) rm -f "{root}/launchctl.unloaded" ;;
    esac
}}
sleep() {{ :; }}
'''


RUNNING = "state = running\npid = 4242\n"


def profile(**changes: object) -> dict:
    now = dt.datetime.now(dt.timezone.utc)
    result: dict = {
        "Platform": ["macOS"],
        "CreationDate": now - dt.timedelta(days=1),
        "ExpirationDate": now + dt.timedelta(days=1),
        "TeamIdentifier": ["TEAM123"],
        "ProvisionedDevices": ["device-1"],
        "DeveloperCertificates": [b"test certificate"],
        "Entitlements": {
            "application-identifier": "PREFIX123.com.example.yuzu",
            "com.apple.developer.team-identifier": "TEAM123",
            "com.apple.developer.endpoint-security.client": True,
        },
    }
    result.update(changes)
    return result


class ProfileValidationTests(unittest.TestCase):
    @unittest.skipIf(os.name == "nt", "POSIX Bash fixture; native Windows does not use these installers")
    def test_legacy_classifier_rejects_bad_signature_in_conditional(self) -> None:
        # Run the real function bodies in the conditional context that disables
        # Bash errexit. Stub only platform commands, never the classifier logic.
        with tempfile.TemporaryDirectory(prefix="yuzu_test_legacy_app_") as temporary:
            candidate = Path(temporary) / "YuzuAgent.app"
            contents = candidate / "Contents"
            contents.mkdir(parents=True)
            embedded = contents / "embedded.provisionprofile"
            embedded.touch()
            # preinstall no longer classifies legacy apps: its snapshot copy was
            # dead (governance sec-8).
            self.assertNotIn("legacy_app_is_managed", (BUILD_PKG.parent / "preinstall").read_text())
            for script in ("postinstall", "uninstall.sh"):
                source = (BUILD_PKG.parent / script).read_text()
                start = source.index("legacy_app_is_managed() {")
                end = source.index("\n}", start) + 2
                function = source[start:end].replace("/usr/libexec/PlistBuddy", "plist_buddy")
                harness = r'''
set -euo pipefail
LEGACY_APP_ID=TEAM.com.example.yuzu
LEGACY_TEAM_ID=TEAM
LEGACY_SIGNING_AUTHORITY='Test Authority'
LEGACY_PROFILE_SHA256=testdigest
plist_buddy() { echo com.example.yuzu; }
codesign() {
    if [[ "$1" == --verify ]]; then return "$VERIFY_STATUS"; fi
    printf 'TeamIdentifier=TEAM\nAuthority=Test Authority\n'
}
shasum() { echo 'testdigest fixture'; }
'''
                harness += function + '\nif legacy_app_is_managed "$1"; then echo MANAGED; else echo REJECTED; fi\n'
                for status, expected in ((0, "MANAGED"), (1, "REJECTED")):
                    with self.subTest(script=script, signature_status=status):
                        result = subprocess.run(
                            ["bash", "-c", harness, "legacy-contract", str(candidate)],
                            env={**os.environ, "VERIFY_STATUS": str(status)},
                            capture_output=True, text=True, check=True,
                        )
                        self.assertEqual(result.stdout.strip(), expected)

    def test_full_xcode_sdk_layout_requires_es_header_and_linker_stub(self) -> None:
        with tempfile.TemporaryDirectory(prefix="yuzu_test_macos_sdk_") as temporary:
            sdk = Path(temporary)
            header = sdk / "usr/include/EndpointSecurity/EndpointSecurity.h"
            stub = sdk / "usr/lib/libEndpointSecurity.tbd"
            header.parent.mkdir(parents=True)
            stub.parent.mkdir(parents=True)
            header.touch()
            stub.touch()
            with mock.patch.object(bundle, "run", return_value=str(sdk)):
                bundle.require_es_sdk()
            stub.unlink()
            with mock.patch.object(bundle, "run", return_value=str(sdk)):
                with self.assertRaisesRegex(bundle.BundleError, "linker stub"):
                    bundle.require_es_sdk()

    @unittest.skipIf(os.name == "nt", "POSIX packaging fixture")
    def test_loose_builder_supports_nested_flat_and_empty_plugin_layouts(self) -> None:
        for layout in ("nested", "flat", "empty", "duplicate"):
            with self.subTest(layout=layout), tempfile.TemporaryDirectory(prefix="yuzu_test_loose_pkg_") as temporary:
                root = Path(temporary)
                binaries = root / "build"
                (binaries / "agents/core").mkdir(parents=True)
                (binaries / "agents/core/yuzu-agent").write_bytes(b"agent fixture")
                if layout != "empty":
                    plugins = binaries / ("plugins" if layout == "flat" else "agents/plugins/tar")
                    plugins.mkdir(parents=True)
                    (plugins / "tar.dylib").write_bytes(b"plugin fixture")
                if layout == "duplicate":
                    other = binaries / "agents/plugins/other"
                    other.mkdir()
                    (other / "tar.dylib").write_bytes(b"collision")
                tools = root / "tools"
                tools.mkdir()
                captured = root / "manifest"
                # The builder now fails when a plugin cannot be hashed (governance
                # uh-2), so a host without macOS's shasum gets a sha256sum shim.
                shim = {} if shutil.which("shasum") else {
                    "shasum": '#!/bin/sh\n[ "$1" = -a ] && shift 2\nexec sha256sum "$@"\n'}
                for name, body in {
                    **shim,
                    "lipo": "#!/bin/sh\necho arm64\n",
                    "pkgbuild": "#!/bin/sh\nset -eu\nroot=; last=\nwhile [ \"$#\" -gt 0 ]; do case \"$1\" in --root) root=\"$2\"; shift 2 ;; *) last=\"$1\"; shift ;; esac; done\ncp \"$root/usr/local/lib/yuzu/.package-files.incoming\" \"$CAPTURED_MANIFEST\"\n: > \"$last\"\n",
                    "productbuild": "#!/bin/sh\nfor last; do :; done\n: > \"$last\"\n",
                }.items():
                    tool = tools / name
                    tool.write_text(body)
                    tool.chmod(0o755)
                result = subprocess.run(
                    [PKG_SHELL, str(BUILD_PKG), "--bin-dir", str(binaries), "--version", "1.0", "--output", str(root / "dist")],
                    env={**os.environ, "PATH": f"{tools}:{os.environ['PATH']}", "CAPTURED_MANIFEST": str(captured)},
                    text=True, capture_output=True,
                )
                if layout == "duplicate":
                    self.assertNotEqual(result.returncode, 0)
                    self.assertIn("duplicate", result.stderr)
                    self.assertFalse(captured.exists())
                else:
                    self.assertEqual(result.returncode, 0, result.stderr)
                    # The first line names the package version (governance rd-2).
                    self.assertEqual(captured.read_text(), "# package-version 1.0\n" +
                                     ("" if layout == "empty" else "plugins/tar.dylib\n"))

    def _build_loose(self, root: Path, plugin_name: str,
                     extra_tools: dict[str, str] | None = None, version: str = "1.0") -> subprocess.CompletedProcess:
        """build-pkg.sh's loose lane with stub packaging tools. The pkgbuild stub
        captures the hash sidecar, the Scripts directory and a payload listing."""
        binaries = root / "build"
        (binaries / "agents/core").mkdir(parents=True)
        (binaries / "agents/core/yuzu-agent").write_bytes(b"agent fixture")
        (binaries / "plugins").mkdir()
        (binaries / "plugins" / plugin_name).write_bytes(b"plugin fixture")
        tools = root / "tools"
        tools.mkdir()
        # The builder hashes the loose binary and every plugin; a host without
        # macOS's shasum gets a sha256sum shim.
        shim = {} if shutil.which("shasum") else {
            "shasum": '#!/bin/sh\n[ "$1" = -a ] && shift 2\nexec sha256sum "$@"\n'}
        pkgbuild = ('#!/bin/sh\nset -eu\nroot=; scripts=; last=\nwhile [ "$#" -gt 0 ]; do case "$1" in '
                    '--root) root="$2"; shift 2 ;; --scripts) scripts="$2"; shift 2 ;; *) last="$1"; shift ;; esac; done\n'
                    'cp "$root/usr/local/lib/yuzu/.package-files.sha256.incoming" "$CAPTURED_HASHES"\n'
                    'cp -R "$scripts" "$CAPTURED_SCRIPTS"\n(cd "$root" && find . -print) > "$CAPTURED_PAYLOAD"\n'
                    ': > "$last"\n')
        for name, body in {
            **shim,
            "lipo": "#!/bin/sh\necho arm64\n",
            "pkgbuild": pkgbuild,
            "productbuild": "#!/bin/sh\nfor last; do :; done\n: > \"$last\"\n",
            **(extra_tools or {}),
        }.items():
            (tools / name).write_text(body)
            (tools / name).chmod(0o755)
        return subprocess.run(
            [PKG_SHELL, str(BUILD_PKG), "--bin-dir", str(binaries), "--version", version, "--output", str(root / "dist")],
            env={**os.environ, "PATH": f"{tools}:{os.environ['PATH']}", "CAPTURED_HASHES": str(root / "hashes"),
                 "CAPTURED_SCRIPTS": str(root / "scripts"), "CAPTURED_PAYLOAD": str(root / "payload.txt")},
            text=True, capture_output=True)

    @posix_shell
    def test_builder_accepts_release_candidate_versions(self) -> None:
        # Governance rd-n1: release.yml turns a tag's "-" into "_" (0.15.0_rc1).
        for version, accepted in (("0.15.0_rc1", True), ("0.15.0", True), ("0.15.0+build.7", True),
                                  ("1.0;rm", False), ("1.0 x", False), ("_1.0", False), ("1.0/..", False)):
            with self.subTest(version=version), tempfile.TemporaryDirectory(prefix="yuzu_test_pkg_version_") as temporary:
                root = Path(temporary)
                result = self._build_loose(root, "tar.dylib", version=version)
                self.assertEqual(result.returncode == 0, accepted, result.stderr)
                if accepted:
                    self.assertEqual((root / "scripts/package-files.list").read_text().splitlines()[0],
                                     f"# package-version {version}")
                else:
                    self.assertIn("--version must be a plain version string", result.stderr)
        with tempfile.TemporaryDirectory(prefix="yuzu_test_pkg_version_") as temporary:
            result = self._build_loose(Path(temporary), "tar.dylib", version="")
            self.assertNotEqual(result.returncode, 0)

    @posix_shell
    def test_builder_ships_preinstall_facts_and_the_merge_helper_in_scripts(self) -> None:
        # Governance rd-n2/G8-S3: preinstall reads the lane, the unsigned-plugin flag
        # and the plugin list from the package's Scripts directory; the root-run
        # merge helper ships there too, never in the payload below /usr/local.
        with tempfile.TemporaryDirectory(prefix="yuzu_test_pkg_scripts_") as temporary:
            root = Path(temporary)
            result = self._build_loose(root, "tar.dylib")
            self.assertEqual(result.returncode, 0, result.stderr)
            scripts = root / "scripts"
            self.assertEqual(sorted(path.name for path in scripts.iterdir()),
                             ["merge-launchd-plist.js", "package-files.list", "package-info", "postinstall", "preinstall"])
            self.assertEqual((scripts / "package-info").read_text(), "mode=loose\nunsigned_plugins=1\n")
            self.assertEqual((scripts / "package-files.list").read_text(), "# package-version 1.0\nplugins/tar.dylib\n")
            self.assertEqual((scripts / "merge-launchd-plist.js").read_bytes(), MERGE_PLIST_HELPER.read_bytes())
            payload = (root / "payload.txt").read_text()
            self.assertNotIn("merge-launchd-plist", payload)
            self.assertIn("./usr/local/bin/.yuzu-agent.incoming", payload)

    @macos_userland
    def test_builder_records_each_plugin_hash(self) -> None:
        import hashlib
        with tempfile.TemporaryDirectory(prefix="yuzu_test_plugin_hashes_") as temporary:
            root = Path(temporary)
            result = self._build_loose(root, "tar.dylib")
            self.assertEqual(result.returncode, 0, result.stderr)
            agent = hashlib.sha256(b"agent fixture").hexdigest()
            expected = hashlib.sha256(b"plugin fixture").hexdigest()
            # The loose binary is recorded too, so postinstall can verify the
            # delivered bytes before promoting them (governance ch-5).
            self.assertEqual((root / "hashes").read_text(),
                             f"{agent}  bin/yuzu-agent\n{expected}  plugins/tar.dylib\n")

    @posix_shell
    def test_builder_rejects_a_plugin_name_with_whitespace(self) -> None:
        with tempfile.TemporaryDirectory(prefix="yuzu_test_plugin_space_") as temporary:
            result = self._build_loose(Path(temporary), "bad name.dylib")
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("contains whitespace", result.stderr)

    @posix_shell
    def test_builder_fails_when_a_plugin_cannot_be_hashed(self) -> None:
        # Governance uh-2: the hash was computed inside a printf argument, so a
        # failing shasum recorded an empty hash and the build still succeeded.
        # A shasum that misbehaves only for one target and hashes anything else
        # (with sha256sum where macOS's shasum is absent).
        real = ('[ -x /usr/bin/shasum ] && exec /usr/bin/shasum "$@"\n'
                '[ "$1" = -a ] && shift 2\nexec sha256sum "$@"\n')
        for target, name, message in (
                ("*.dylib", "tar.dylib", "cannot hash plugin|invalid SHA-256 for plugin"),
                ("*/.yuzu-agent.incoming", "yuzu-agent", "cannot hash yuzu-agent|invalid SHA-256 for yuzu-agent")):
            for label, bad in (("fails", "exit 1"), ("prints garbage", "echo 'not-a-digest  x'; exit 0")):
                shasum = f'#!/bin/sh\ncase "$3" in {target}) {bad} ;; esac\n' + real
                with self.subTest(target=name, shasum=label), \
                        tempfile.TemporaryDirectory(prefix="yuzu_test_plugin_nohash_") as temporary:
                    root = Path(temporary)
                    result = self._build_loose(root, "tar.dylib", {"shasum": shasum})
                    self.assertNotEqual(result.returncode, 0)
                    self.assertIn(name, result.stderr)
                    self.assertRegex(result.stderr, message)
                    self.assertFalse((root / "hashes").exists())
                    self.assertFalse((root / "dist").exists() and any((root / "dist").iterdir()))

    # PR #4482 review: package ownership of a plugin is its recorded bytes, not its name.
    def _ownership_harness(self, root: Path, body: str) -> subprocess.CompletedProcess:
        source = (BUILD_PKG.parent / "postinstall").read_text()
        program = "\n".join(script_function(source, name)
                            for name in ("plugin_hash_matches", "was_managed_plugin", "harden_managed_plugins"))
        stubs = PREAMBLE + f"""chown() {{ echo "CHOWN $*" >> "{root}/chown.log"; }}
PLUGIN_DIR="{root}/plugins"; MANIFEST="{root}/package-files.list"; HASHES="{root}/package-files.sha256"
"""
        return subprocess.run([PKG_SHELL, "-c", stubs + program + "\n" + body], text=True, capture_output=True)

    @macos_userland
    def test_plugin_ownership_requires_the_recorded_hash(self) -> None:
        import hashlib
        with tempfile.TemporaryDirectory(prefix="yuzu_test_plugin_owner_") as temporary:
            root = Path(temporary)
            (root / "plugins").mkdir()
            (root / "plugins/tar.dylib").write_bytes(b"package bytes")
            (root / "package-files.list").write_text("plugins/tar.dylib\n")
            (root / "package-files.sha256").write_text(
                f"{hashlib.sha256(b'package bytes').hexdigest()}  plugins/tar.dylib\n")
            ok = self._ownership_harness(
                root, 'if was_managed_plugin tar.dylib; then echo MANAGED; fi\nharden_managed_plugins "$MANIFEST"\necho OWNED')
            self.assertEqual(ok.returncode, 0, ok.stderr)
            self.assertEqual(ok.stdout.split(), ["MANAGED", "OWNED"])
            self.assertIn("CHOWN root:wheel", (root / "chown.log").read_text())
            (root / "chown.log").unlink()
            (root / "plugins/tar.dylib").write_bytes(b"replaced by someone else")
            managed = self._ownership_harness(root, 'if was_managed_plugin tar.dylib; then echo MANAGED; else echo NOT-MANAGED; fi')
            self.assertIn("NOT-MANAGED", managed.stdout)
            harden = self._ownership_harness(root, 'harden_managed_plugins "$MANIFEST"')
            self.assertNotEqual(harden.returncode, 0)
            self.assertIn("does not match the package's recorded hash", harden.stderr)
            self.assertNotIn("tar.dylib", (root / "chown.log").read_text() if (root / "chown.log").exists() else "")
            (root / "package-files.sha256").unlink()   # an older, name-only package
            legacy = self._ownership_harness(root, 'if was_managed_plugin tar.dylib; then echo MANAGED; fi')
            self.assertIn("MANAGED", legacy.stdout)

    @unittest.skipIf(os.name == "nt", "POSIX receipt fixture")
    def test_legacy_plugin_ownership_comes_only_from_exact_receipt_paths(self) -> None:
        source = (BUILD_PKG.parent / "preinstall").read_text()
        # uh8-4 split the receipt reader out of adopt_receipted_plugins.
        function = "\n".join(script_function(source, name) for name in
                             ("receipt_plugin_entries", "adopt_receipted_plugins")).replace("/usr/sbin/pkgutil", "pkgutil")
        for receipt, status, expected in (
            ("usr/local/lib/yuzu/plugins/tar.dylib\nusr/local/lib/other.dylib\n", 0, "plugins/tar.dylib\n"),
            ("usr/local/lib/yuzu/plugins/sub/evil.dylib\n", 0, None),
            ("usr/local/lib/yuzu/plugins/../evil.dylib\n", 0, None),
            ("usr/local/lib/yuzu/plugins/a\tb.dylib\n", 0, None),
            ("usr/local/lib/yuzu/plugins/.hidden.dylib\n", 0, None),
            # AppleDouble metadata a build host leaves in the receipt is skipped (xp-15).
            ("usr/local/lib/yuzu/plugins/._tar.dylib\nusr/local/lib/yuzu/plugins/tar.dylib\n", 0, "plugins/tar.dylib\n"),
            ("usr/local/lib/yuzu/plugins/tar.dylib\n", 1, None),
        ):
            with self.subTest(receipt=receipt, status=status), tempfile.TemporaryDirectory(prefix="yuzu_test_receipt_") as temporary:
                root = Path(temporary)
                (root / "plugins").mkdir()
                (root / "plugins/third-party.dylib").write_bytes(b"unmanaged")
                harness = PREAMBLE + '''pkgutil() { [[ "$1" == --files && "$2" == com.yuzu.agent ]] || exit 99; printf '%s' "$RECEIPT"; return "$RECEIPT_STATUS"; }
''' + function + "\nadopt_receipted_plugins\n"
                result = subprocess.run(["bash", "-c", harness], text=True, capture_output=True,
                                        env={**os.environ, "YUZU_LIB": temporary, "RECEIPT": receipt,
                                             "RECEIPT_STATUS": str(status)})
                manifest = root / "package-files.list"
                self.assertEqual(manifest.read_text() if manifest.exists() else None, expected)
                self.assertEqual(result.returncode == 0, expected is not None or status == 1)
                self.assertEqual((root / "plugins/third-party.dylib").read_bytes(), b"unmanaged")

    @macos_userland
    def test_data_directory_created_when_missing_and_preserved_when_present(self) -> None:
        for script in ("postinstall", "preinstall"):
            with self.subTest(script=script):
                self._data_directory_contract(script)

    def _data_directory_contract(self, script: str) -> None:
        source = (BUILD_PKG.parent / script).read_text()
        functions = "\n".join(script_function(source, name)
                              for name in ("data_directory_owner_trusted", "require_trusted_data_directory"))
        if script == "postinstall":
            functions += "\n" + script_function(source, "ensure_data_directory")
            call = "ensure_data_directory\n"
        else:
            call = "require_trusted_data_directory\n"
        functions = functions.replace("/usr/bin/id", "id")
        with tempfile.TemporaryDirectory(prefix="yuzu_test_data_dir_") as temporary:
            data = Path(temporary) / "data"
            # The installer runs as root; the fixture reports the data directory's owner as
            # FAKE_UID (default root) and the _yuzu account's uid as YUZU_UID (unset: no
            # such account), so ownership can be exercised without privileges.
            fake_stat = 'stat() { if [[ "$2" == "%u" ]]; then echo "${FAKE_UID:-0}"; else command stat "$@"; fi; }\n'
            fake_id = 'id() { [[ "$1 $2" == "-u _yuzu" && -n "${YUZU_UID:-}" ]] || return 1; echo "$YUZU_UID"; }\n'
            harness = (PREAMBLE + fake_stat + fake_id + "require_trusted_directory() { return 0; }\nchown() { echo CHOWN; }\n"
                       + functions + "\n" + call + "echo DONE\n")
            def invoke(**extra):
                return subprocess.run([PKG_SHELL, "-c", harness], text=True, capture_output=True,
                                      env={**os.environ, "DATA_DIR": str(data), **extra})
            if script == "postinstall":
                result = invoke()
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertEqual(data.stat().st_mode & 0o777, 0o750)
                self.assertEqual(result.stdout.split(), ["CHOWN", "DONE"])
            else:
                data.mkdir(mode=0o750)
                data.chmod(0o750)
            data.chmod(0o710)
            sentinel = data / "keep"
            sentinel.write_bytes(b"existing data")
            for uid, yuzu_uid in (("0", ""), ("0", "299"), ("299", "299")):
                # Root-owned, or owned by the _yuzu service account that
                # install-agent-user.sh provisions (governance rd-1): accepted, untouched.
                before = data.stat()
                result = invoke(FAKE_UID=uid, YUZU_UID=yuzu_uid)
                self.assertEqual(result.returncode, 0, f"uid {uid} (_yuzu={yuzu_uid}): {result.stderr}")
                self.assertEqual(result.stdout.strip(), "DONE")
                self.assertEqual(data.stat().st_uid, before.st_uid)
                self.assertEqual(data.stat().st_mode, before.st_mode)
                self.assertEqual(sentinel.read_bytes(), b"existing data")
            if script == "postinstall":
                link = Path(temporary) / "link"
                link.symlink_to(data, target_is_directory=True)
                result = subprocess.run([PKG_SHELL, "-c", harness], text=True, capture_output=True,
                                        env={**os.environ, "DATA_DIR": str(link)})
                self.assertNotEqual(result.returncode, 0)
            # Group/world writable, another account, or a _yuzu-owned directory on a
            # host with no _yuzu account: refused and left exactly as it was.
            for mode, uid, yuzu_uid in ((0o777, "0", ""), (0o770, "0", ""), (0o770, "299", "299"),
                                        (0o750, "501", "299"), (0o750, "299", "")):
                data.chmod(mode)
                before = data.stat()
                result = invoke(FAKE_UID=uid, YUZU_UID=yuzu_uid)
                self.assertNotEqual(result.returncode, 0, f"mode {oct(mode)} uid {uid} was accepted")
                self.assertNotIn("DONE", result.stdout)
                self.assertIn("must be owned by root or _yuzu and not group/world writable", result.stderr)
                # The data root holds the agent's identity: never advise removing it.
                self.assertNotIn("remove it", result.stderr)
                self.assertIn("do not delete it", result.stderr)
                self.assertEqual(data.stat().st_mode, before.st_mode)
                self.assertEqual(sentinel.read_bytes(), b"existing data")
            data.chmod(0o710)

    def test_preinstall_refuses_an_untrusted_data_directory_before_staging(self) -> None:
        preinstall = (BUILD_PKG.parent / "preinstall").read_text()
        check = preinstall.index('require_trusted_data_directory || exit 1')
        self.assertLess(check, preinstall.index('secure_payload_parent "$APP_ROOT" 755'))
        self.assertLess(check, preinstall.index('write_recovery_phase "$RECOVERY" prepared'))
        self.assertLess(preinstall.index('require_trusted_data_directory() {'), check)

    def test_provisioning_udid_is_not_substituted_with_hardware_uuid(self) -> None:
        hardware_uuid = "AAAAAAAA-AAAA-AAAA-AAAA-AAAAAAAAAAAA"
        provisioning_udid = "BBBBBBBB-BBBB-BBBB-BBBB-BBBBBBBBBBBB"
        system_profiler = (
            "Hardware:\n"
            f"    Hardware UUID: {hardware_uuid}\n"
            f"    Provisioning UDID: {provisioning_udid}\n"
        )
        self.assertEqual(bundle.provisioning_udid_from_system_profiler(system_profiler),
                         provisioning_udid)

    def test_valid_profile_returns_profile_prefix_and_team(self) -> None:
        self.assertEqual(bundle.validate_profile(profile(), "com.example.yuzu", device_id="device-1"),
                         ("PREFIX123", "TEAM123"))

    def test_documented_macos_application_identifier_key_is_required(self) -> None:
        candidate = profile()
        entitlements = candidate["Entitlements"].copy()
        entitlements.pop("application-identifier")
        entitlements["com.apple.application-identifier"] = "PREFIX123.com.example.yuzu"
        candidate["Entitlements"] = entitlements
        self.assertEqual(bundle.validate_profile(candidate, "com.example.yuzu", device_id="device-1"),
                         ("PREFIX123", "TEAM123"))

    def test_apple_legacy_osx_platform_tag_is_recognized_as_macos(self) -> None:
        self.assertEqual(bundle.validate_profile(profile(Platform=["OSX"]), "com.example.yuzu",
                                                 device_id="device-1"), ("PREFIX123", "TEAM123"))

    def test_f01_rejects_missing_false_or_non_boolean_es_grant(self) -> None:
        for value in (None, False, "true"):
            with self.subTest(value=value):
                candidate = profile()
                entitlements = candidate["Entitlements"].copy()
                if value is None:
                    entitlements.pop("com.apple.developer.endpoint-security.client")
                else:
                    entitlements["com.apple.developer.endpoint-security.client"] = value
                candidate["Entitlements"] = entitlements
                with self.assertRaisesRegex(bundle.BundleError, "Endpoint Security"):
                    bundle.validate_profile(candidate, "com.example.yuzu", device_id="device-1")

    def test_f01_rejects_expired_wrong_platform_and_ineligible_device(self) -> None:
        expired = profile(ExpirationDate=dt.datetime.now(dt.timezone.utc) - dt.timedelta(seconds=1))
        with self.assertRaisesRegex(bundle.BundleError, "expired"):
            bundle.validate_profile(expired, "com.example.yuzu", device_id="device-1")
        with self.assertRaisesRegex(bundle.BundleError, "macOS"):
            bundle.validate_profile(profile(Platform=["iOS"]), "com.example.yuzu", device_id="device-1")
        with self.assertRaisesRegex(bundle.BundleError, "not eligible"):
            bundle.validate_profile(profile(), "com.example.yuzu", device_id="other-device")

    def test_f02_rejects_signer_not_authorized_by_profile(self) -> None:
        with self.assertRaisesRegex(bundle.BundleError, "not authorized"):
            bundle.validate_profile(profile(), "com.example.yuzu", device_id="device-1",
                                    signer_fingerprint="0" * 40)

    def test_f03_rejects_wrong_bundle_or_team(self) -> None:
        with self.assertRaisesRegex(bundle.BundleError, "bundle ID"):
            bundle.validate_profile(profile(), "com.other.yuzu", device_id="device-1")
        candidate = profile(TeamIdentifier=["OTHERTEAM"])
        with self.assertRaisesRegex(bundle.BundleError, "TeamIdentifier"):
            bundle.validate_profile(candidate, "com.example.yuzu", device_id="device-1")


class PackagingStructureTests(unittest.TestCase):
    # ── Shared installer harness ────────────────────────────────────────────────
    # Real installer functions, extracted verbatim, run under the production
    # preamble against a fixture tree. Only platform commands are stubbed:
    # launchctl (a state fixture), sleep, stat (the installer runs as root),
    # chown, ditto and, where noted, PlistBuddy/id/pkgutil. require_started is
    # always the real one. /usr/local is rewritten to the fixture's "ul".
    RECOVERY_NAMES = {
        "preinstall": ("plugin_hash_matches", "remove_managed_plugins", "quarantine_legacy_app",
                       "acl_grants_write", "code_directory_chain_trusted", "require_started", "stop_service",
                       "restart_restored_service", "recover_interrupted_promotion", "copy_back",
                       "restore_missing_live_files"),
        "postinstall": ("recovery_path", "plugin_hash_matches", "remove_managed_plugins", "quarantine_legacy_app",
                        "acl_grants_write", "code_directory_chain_trusted", "require_started", "stop_service",
                        "restart_restored_service", "finish_recovery", "restore_previous"),
    }

    def _installer_harness(self, root: Path, script: str, names: tuple[str, ...], body: str, *,
                           plist: str = "agent", owners: dict | None = None, modes: dict | None = None,
                           real_modes: bool = False, stubs: str = "") -> subprocess.CompletedProcess:
        source = (BUILD_PKG.parent / script).read_text()
        program = "\n".join(script_function(source, name) for name in names)
        program = (program.replace("/usr/local", str(root / "ul")).replace("/usr/bin/id", "id")
                   .replace("/usr/sbin/pkgutil", "pkgutil"))
        if plist != "real":
            program = program.replace("/usr/libexec/PlistBuddy", "plist_buddy")
        plist_buddy = {
            "agent": 'printf \'Array {\\n    %s\\n}\\n\' "$LOOSE_BIN/yuzu-agent"',
            "legacy": 'printf \'Array {\\n    %s\\n}\\n\' "$LEGACY_APP/Contents/MacOS/yuzu-agent"',
            "fail": "return 1",
            "real": ":",
        }[plist]
        ul = root / "ul"
        variables = f"""
STATE_DIR="{root}/state"; RECOVERY_FILE="$STATE_DIR/current-recovery"
DATA_DIR="{root}/data"; LEGACY_APP="$DATA_DIR/YuzuAgent.app"; LOG_DIR="{root}/logs"
LOOSE_BIN="{ul}/bin"; YUZU_LIB="{ul}/lib/yuzu"; PLUGIN_DIR="$YUZU_LIB/plugins"
INCOMING_PLUGIN_DIR="$YUZU_LIB/.plugins.incoming"; MODE_FILE="$YUZU_LIB/package-mode"
MANIFEST="$YUZU_LIB/package-files.list"; INCOMING_MANIFEST="$YUZU_LIB/.package-files.incoming"
HASHES="$YUZU_LIB/package-files.sha256"; INCOMING_HASHES="$YUZU_LIB/.package-files.sha256.incoming"
INCOMING_BUNDLE_ARCHIVE="$YUZU_LIB/.bundle-contents.incoming.zip"
APP_ROOT="{root}/app"; APP="$APP_ROOT/YuzuAgent.app"; INCOMING_APP="$APP_ROOT/.YuzuAgent.incoming.app"
PLIST="{root}/LaunchDaemons/com.yuzu.agent.plist"; INCOMING_PLIST="{root}/LaunchDaemons/.com.yuzu.agent.incoming.plist"
DEFAULT_CA="{root}/etc/default-ca.pem"
"""
        # The installer only runs on macOS. Off macOS, GNU ls has no -e, so the real
        # acl_grants_write would read every path as an ACL write grant; report none
        # there. ACL handling itself is tested natively (test_acl_write_grants_...).
        no_acls = ("acl_grants_write() { return 1; }\n"
                   if sys.platform != "darwin" and "acl_grants_write" in names else "")
        harness = (PREAMBLE + stat_stub(owners, modes, real_modes) + launchctl_stub(root)
                   + "chown() { :; }\n"
                   + 'ditto() { if [[ -d "$1" ]]; then mkdir -p "$2"; cp -R "$1/." "$2/"; '
                     'else mkdir -p "$(dirname "$2")"; cp "$1" "$2"; fi; }\n'
                   + f"plist_buddy() {{ {plist_buddy}; }}\n" + variables + stubs + program + "\n"
                   + no_acls + body)
        return subprocess.run([PKG_SHELL, "-c", harness], text=True, capture_output=True)

    def _recovery_layout(self, root: Path, *, phase: str = "promoting", was_running: bool = True,
                         loose: bool = False) -> Path:
        for folder in ("LaunchDaemons", "app", "data", "logs", "etc", "ul/bin", "ul/lib/yuzu/plugins"):
            (root / folder).mkdir(parents=True, exist_ok=True)
        recovery = root / "state/install-recovery.TEST"
        (recovery / "LaunchDaemons").mkdir(parents=True)
        (recovery / "LaunchDaemons/com.yuzu.agent.plist").write_text("previous definition")
        (recovery / "phase").write_text(phase + "\n")
        if was_running:
            (recovery / "service-was-running").touch()
        if loose:
            (recovery / "loose").mkdir()
            (recovery / "loose/yuzu-agent").write_text("previous loose agent")
        (root / "state/current-recovery").write_text(f"{recovery}\n")
        return recovery

    def _recovery_modes(self, root: Path, **extra: int) -> dict:
        """recovery_path/require_recovery_directory demand pointer 600, snapshot 700."""
        modes = {root / "state/current-recovery": 600, root / "state/install-recovery.TEST": 700}
        modes.update({root / path: mode for path, mode in extra.items()})
        return modes

    def _restore(self, root: Path, script: str, recovery: Path, **options) -> subprocess.CompletedProcess:
        # Plain statement, then a marker: production errexit applies inside (qe-2).
        body = ("restore_previous\necho RESTORED\n" if script == "postinstall"
                else f'recover_interrupted_promotion "{recovery}"\necho RESTORED\n')
        options.setdefault("modes", self._recovery_modes(root))
        return self._installer_harness(root, script, self.RECOVERY_NAMES[script], body, **options)

    def _launchctl_log(self, root: Path) -> str:
        log = root / "launchctl.log"
        return log.read_text() if log.exists() else ""

    @posix_shell
    def test_interrupted_plugin_promotion_restores_old_generation_and_allows_retry(self) -> None:
        post = (BUILD_PKG.parent / "postinstall").read_text()
        with tempfile.TemporaryDirectory(prefix="yuzu_test_retry_manifest_") as temporary:
            root = Path(temporary)
            recovery = self._recovery_layout(root)
            lib = root / "ul/lib/yuzu"
            (lib / ".plugins.incoming").mkdir()
            (lib / "package-files.list").write_text("plugins/old.dylib\n")
            (lib / ".package-files.incoming").write_text("plugins/old.dylib\nplugins/new.dylib\n")
            (recovery / "package-files.list").write_text("plugins/old.dylib\n")
            (recovery / "yuzu/plugins").mkdir(parents=True)
            (recovery / "yuzu/plugins/old.dylib").write_bytes(b"old generation")
            (lib / "plugins/old.dylib").write_bytes(b"replacement")
            (lib / "plugins/new.dylib").write_bytes(b"new before crash")
            (lib / "plugins/third-party.dylib").write_bytes(b"unmanaged")
            (lib / ".plugins.incoming/new.dylib").write_bytes(b"retry")
            collisions = "\n".join(script_function(post, name)
                                   for name in ("was_managed_plugin", "reject_unmanaged_plugin_collisions"))
            result = self._installer_harness(
                root, "preinstall", self.RECOVERY_NAMES["preinstall"],
                f'recover_interrupted_promotion "{recovery}"\nreject_unmanaged_plugin_collisions\necho DONE\n',
                stubs=collisions + "\n")
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertIn("DONE", result.stdout)
            self.assertFalse((lib / "plugins/new.dylib").exists())
            self.assertEqual((lib / "plugins/old.dylib").read_bytes(), b"old generation")
            self.assertEqual((lib / "plugins/third-party.dylib").read_bytes(), b"unmanaged")

    # ── PR #4482 review (Doomgoose blocker 1): an unrecognized legacy app must never
    # deadlock recovery. Governance qe-1: BOTH recovery paths are exercised — the
    # preinstall recover_interrupted_promotion and the postinstall restore_previous.
    @posix_shell
    def test_unrecognized_legacy_app_is_quarantined_without_rolling_back_a_healthy_install(self) -> None:
        with tempfile.TemporaryDirectory(prefix="yuzu_test_legacy_retire_") as temporary:
            root = Path(temporary)
            recovery = self._recovery_layout(root)
            (root / "data/YuzuAgent.app/Contents").mkdir(parents=True)
            result = self._installer_harness(
                root, "postinstall", ("quarantine_legacy_app", "retire_legacy_app"),
                f'recovery="{recovery}"\nretire_legacy_app\necho RETIRED\n',
                stubs="legacy_app_is_managed() { return 1; }\n")
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertIn("RETIRED", result.stdout)
            self.assertIn("quarantined an unrecognized legacy", result.stderr)
            self.assertFalse((root / "data/YuzuAgent.app").exists())
            self.assertFalse((recovery / "legacy-retired.app").exists())
            self.assertEqual(len(list((root / "state/quarantine").glob("legacy-YuzuAgent.*/YuzuAgent.app"))), 1)

    @posix_shell
    def test_recovery_with_a_retained_legacy_app_restarts_the_previous_service(self) -> None:
        for script in ("preinstall", "postinstall"):
            with self.subTest(script=script), tempfile.TemporaryDirectory(prefix="yuzu_test_legacy_recover_") as temporary:
                root = Path(temporary)
                recovery = self._recovery_layout(root)
                (recovery / "legacy-retired.app/Contents").mkdir(parents=True)
                (root / "launchctl.state").write_text(RUNNING)
                # preinstall's recovery must also be repeatable, never a dead end;
                # postinstall's ends by discarding the pointer and snapshot.
                for _attempt in ((1, 2) if script == "preinstall" else (1,)):
                    result = self._restore(root, script, recovery)
                    self.assertEqual(result.returncode, 0, result.stderr)
                    self.assertIn("RESTORED", result.stdout)
                self.assertFalse((recovery / "legacy-retired.app").exists())
                self.assertEqual(len(list((root / "state/quarantine").glob("legacy-YuzuAgent.*/YuzuAgent.app"))), 1)
                self.assertEqual((root / "LaunchDaemons/com.yuzu.agent.plist").read_text(), "previous definition")
                log = self._launchctl_log(root)
                self.assertIn("enable system/com.yuzu.agent", log)
                self.assertIn("bootstrap system", log)
                if script == "postinstall":
                    self.assertFalse((root / "state/current-recovery").exists())
                    self.assertFalse(recovery.exists())

    @posix_shell
    def test_recovery_never_starts_a_legacy_data_root_service_but_does_not_block(self) -> None:
        for script in ("preinstall", "postinstall"):
            with self.subTest(script=script), tempfile.TemporaryDirectory(prefix="yuzu_test_legacy_plist_") as temporary:
                root = Path(temporary)
                recovery = self._recovery_layout(root)
                (root / "launchctl.state").write_text(RUNNING)
                result = self._restore(root, script, recovery, plist="legacy")
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertIn("RESTORED", result.stdout)
                self.assertIn("did not start it from non-package-owned data", result.stderr)
                self.assertNotIn("bootstrap", self._launchctl_log(root))

    @posix_shell
    def test_recovery_does_not_start_a_service_whose_definition_cannot_be_read(self) -> None:
        # A failed read used to flow through `| grep -q` and look like "not the legacy
        # program", so the service was started anyway (PR #4482 review, pipefail item).
        for script in ("preinstall", "postinstall"):
            with self.subTest(script=script), tempfile.TemporaryDirectory(prefix="yuzu_test_plist_unreadable_") as temporary:
                root = Path(temporary)
                recovery = self._recovery_layout(root)
                (root / "launchctl.state").write_text(RUNNING)
                result = self._restore(root, script, recovery, plist="fail")
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertIn("RESTORED", result.stdout)
                self.assertIn("could not read the restored service definition", result.stderr)
                self.assertNotIn("bootstrap", self._launchctl_log(root))

    @posix_shell
    def test_recovery_does_not_start_a_loose_agent_from_an_untrusted_directory(self) -> None:
        for script in ("preinstall", "postinstall"):
            with self.subTest(script=script), tempfile.TemporaryDirectory(prefix="yuzu_test_loose_recover_") as temporary:
                root = Path(temporary)
                recovery = self._recovery_layout(root, loose=True)
                (root / "launchctl.state").write_text(RUNNING)
                result = self._restore(root, script, recovery,
                                       modes=self._recovery_modes(root, **{"ul/bin": 775}))
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertIn("RESTORED", result.stdout)
                self.assertIn("did not start it", result.stderr)
                self.assertEqual((root / "ul/bin/yuzu-agent").read_text(), "previous loose agent")
                self.assertNotIn("bootstrap", self._launchctl_log(root))

    @posix_shell
    def test_recovery_starts_only_a_service_that_was_running(self) -> None:
        # Governance sec-1/hp-1: a service that was stopped (or never configured)
        # when the snapshot was taken is restored, not started.
        for script in ("preinstall", "postinstall"):
            with self.subTest(script=script), tempfile.TemporaryDirectory(prefix="yuzu_test_not_running_") as temporary:
                root = Path(temporary)
                recovery = self._recovery_layout(root, was_running=False)
                (root / "launchctl.state").write_text(RUNNING)
                result = self._restore(root, script, recovery)
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertIn("RESTORED", result.stdout)
                self.assertIn("it was not running before, so it was not started", result.stderr)
                self.assertEqual((root / "LaunchDaemons/com.yuzu.agent.plist").read_text(), "previous definition")
                self.assertNotIn("bootstrap", self._launchctl_log(root))

    @posix_shell
    def test_recovery_restores_an_administrators_disable_override(self) -> None:
        # Governance sre8-3: a running agent that was also disabled is restarted by
        # recovery (enable, bootstrap) and then disabled again for the next boot.
        for script in ("preinstall", "postinstall"):
            for disabled in (True, False):
                with self.subTest(script=script, disabled=disabled), \
                        tempfile.TemporaryDirectory(prefix="yuzu_test_restore_disabled_") as temporary:
                    root = Path(temporary)
                    recovery = self._recovery_layout(root)
                    if disabled:
                        (recovery / "service-was-disabled").touch()
                    (root / "launchctl.state").write_text(RUNNING)
                    result = self._restore(root, script, recovery)
                    self.assertEqual(result.returncode, 0, result.stderr)
                    self.assertIn("RESTORED", result.stdout)
                    log = self._launchctl_log(root)
                    self.assertIn("bootstrap system", log)
                    if disabled:
                        self.assertIn("\ndisable system/com.yuzu.agent", log)
                        self.assertLess(log.index("bootstrap system"), log.index("\ndisable system/com.yuzu.agent"))
                    else:
                        self.assertNotIn("\ndisable system/com.yuzu.agent", log)

    @posix_shell
    def test_postinstall_records_a_disable_override_before_promoting(self) -> None:
        post = (BUILD_PKG.parent / "postinstall").read_text()
        record = post.index('if service_disabled; then : > "$recovery/service-was-disabled"')
        self.assertLess(record, post.index("PROMOTION_ARMED=1\n"))

    @posix_shell
    def test_recovery_completes_when_the_restored_service_will_not_stay_running(self) -> None:
        # Governance sec-1: the restored agent never reaches `state = running`. The
        # real require_started gives up; recovery reports it and completes instead
        # of failing (which left the pointer at "promoting" and wedged every install).
        for script in ("preinstall", "postinstall"):
            with self.subTest(script=script), tempfile.TemporaryDirectory(prefix="yuzu_test_restore_unhealthy_") as temporary:
                root = Path(temporary)
                recovery = self._recovery_layout(root)
                (root / "launchctl.state").write_text("state = spawn scheduled\n")
                result = self._restore(root, script, recovery)
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertIn("RESTORED", result.stdout)
                self.assertIn("did not stay running", result.stderr)
                log = self._launchctl_log(root)
                self.assertIn("bootstrap system", log)
                # The real require_started: six polls after the bootstrap. stop_service's
                # own polls (before the restore) are not health observations.
                self.assertEqual(log.split("bootstrap system", 1)[1].count("print system/com.yuzu.agent"), 6)
                if script == "postinstall":
                    self.assertFalse((root / "state/current-recovery").exists())
                    self.assertFalse(recovery.exists())

    @posix_shell
    def test_restore_previous_is_a_no_op_before_promotion(self) -> None:
        # Governance uh-3/ch-2: a failure before "promoting" has changed nothing
        # active, so the restore must not bounce the service or touch any file.
        with tempfile.TemporaryDirectory(prefix="yuzu_test_restore_prepared_") as temporary:
            root = Path(temporary)
            recovery = self._recovery_layout(root, phase="prepared")
            (root / "ul/bin/yuzu-agent").write_text("active agent")
            (root / "ul/lib/yuzu/plugins/third-party.dylib").write_text("operator plugin")
            (root / "LaunchDaemons/com.yuzu.agent.plist").write_text("active definition")
            result = self._restore(root, "postinstall", recovery)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertIn("RESTORED", result.stdout)
            self.assertEqual(self._launchctl_log(root), "")
            self.assertEqual((root / "ul/bin/yuzu-agent").read_text(), "active agent")
            self.assertEqual((root / "ul/lib/yuzu/plugins/third-party.dylib").read_text(), "operator plugin")
            self.assertEqual((root / "LaunchDaemons/com.yuzu.agent.plist").read_text(), "active definition")
            self.assertTrue((root / "state/current-recovery").exists())
            self.assertTrue(recovery.exists())

    @posix_shell
    def test_recovery_removes_the_pointer_before_the_snapshot(self) -> None:
        # Governance uh-1: an orphaned snapshot is harmless; a pointer to a deleted
        # snapshot wedged every later install. `sync` records what exists when called.
        sync = ('sync() { local p=absent s=absent; [[ -e "$RECOVERY_FILE" ]] && p=present; '
                '[[ -d "$STATE_DIR/install-recovery.TEST" ]] && s=present; '
                'echo "pointer=$p snapshot=$s" >> "$STATE_DIR/../sync.log"; }\n')
        with tempfile.TemporaryDirectory(prefix="yuzu_test_restore_order_") as temporary:
            root = Path(temporary)
            recovery = self._recovery_layout(root)
            (root / "launchctl.state").write_text(RUNNING)
            result = self._restore(root, "postinstall", recovery, stubs=sync)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual((root / "sync.log").read_text().splitlines()[-1], "pointer=absent snapshot=present")
            self.assertFalse(recovery.exists())
        pre = (BUILD_PKG.parent / "preinstall").read_text()
        with tempfile.TemporaryDirectory(prefix="yuzu_test_discard_order_") as temporary:
            root = Path(temporary)
            recovery = self._recovery_layout(root, phase="prepared")
            result = self._installer_harness(root, "preinstall", ("discard_recovery",),
                                             f'discard_recovery "{recovery}"\necho DONE\n', stubs=sync)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual((root / "sync.log").read_text().splitlines(), ["pointer=absent snapshot=present"])
            self.assertFalse(recovery.exists())
        self.assertNotIn('rm -rf "$pending"\n            rm -f "$RECOVERY_FILE"', pre)

    # ── Governance uh-1: the preinstall recovery block never wedges ─────────────
    def _preinstall_recovery_block(self) -> str:
        pre = (BUILD_PKG.parent / "preinstall").read_text()
        start = pre.index('if [[ -e "$RECOVERY_FILE" || -L "$RECOVERY_FILE" ]]; then\n    pending=')
        # uh8-7: the pending recovery and the orphan sweep end where the refusing
        # checks begin.
        return pre[start:pre.index('\nPACKAGE_MODE="$(awk', start)] + "\n"

    def _run_recovery_block(self, root: Path, *, stub_recovery: bool, **options) -> subprocess.CompletedProcess:
        names = ("require_recovery_directory", "read_recovery_path", "discard_recovery")
        if not stub_recovery:
            names += self.RECOVERY_NAMES["preinstall"]
        stubs = options.pop("stubs", "")
        if stub_recovery:
            stubs += ('recover_interrupted_promotion() { echo "RECOVER $1" >> "$STATE_DIR/../recover.log"; }\n'
                      'restore_missing_live_files() { echo "MISSING $1" >> "$STATE_DIR/../recover.log"; }\n')
        options.setdefault("modes", self._recovery_modes(root))
        return self._installer_harness(root, "preinstall", names,
                                       self._preinstall_recovery_block() + "echo PROCEEDED\n",
                                       stubs=stubs, **options)

    @posix_shell
    def test_preinstall_recovery_block_resolves_every_phase(self) -> None:
        for phase, recovers in (("prepared", False), ("promoting", True), ("", True), ("garbage", True),
                                ("prepared  ", True)):
            with self.subTest(phase=phase), tempfile.TemporaryDirectory(prefix="yuzu_test_phase_") as temporary:
                root = Path(temporary)
                recovery = self._recovery_layout(root, phase=phase)
                result = self._run_recovery_block(root, stub_recovery=True)
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertIn("PROCEEDED", result.stdout)
                log = root / "recover.log"
                self.assertEqual(log.read_text() if log.exists() else "",
                                 f"RECOVER {recovery}\n" if recovers else f"MISSING {recovery}\n")
                self.assertFalse((root / "state/current-recovery").exists())
                self.assertFalse(recovery.exists())

    @posix_shell
    def test_preinstall_recovery_with_an_unhealthy_service_is_not_repeated(self) -> None:
        # Governance sec-1, end to end through the real block: the restored agent will
        # not stay up, recovery still completes, and the next install finds nothing.
        with tempfile.TemporaryDirectory(prefix="yuzu_test_recover_unhealthy_") as temporary:
            root = Path(temporary)
            recovery = self._recovery_layout(root)
            (root / "launchctl.state").write_text("state = not running\n")
            first = self._run_recovery_block(root, stub_recovery=False)
            self.assertEqual(first.returncode, 0, first.stderr)
            self.assertIn("PROCEEDED", first.stdout)
            self.assertIn("did not stay running", first.stderr)
            self.assertFalse((root / "state/current-recovery").exists())
            self.assertFalse(recovery.exists())
            calls = self._launchctl_log(root)
            second = self._run_recovery_block(root, stub_recovery=False)
            self.assertEqual(second.returncode, 0, second.stderr)
            self.assertIn("PROCEEDED", second.stdout)
            self.assertEqual(self._launchctl_log(root), calls)

    @posix_shell
    def test_an_unusable_recovery_pointer_is_dropped_not_fatal(self) -> None:
        for case in ("missing snapshot", "empty", "symlink", "outside state root", "valid"):
            with self.subTest(case=case), tempfile.TemporaryDirectory(prefix="yuzu_test_pointer_") as temporary:
                root = Path(temporary)
                recovery = self._recovery_layout(root)
                pointer = root / "state/current-recovery"
                elsewhere = root / "state/install-recovery.TEST"
                if case == "missing snapshot":
                    pointer.write_text(f"{root}/state/install-recovery.GONE\n")
                elif case == "empty":
                    pointer.write_text("")
                elif case == "symlink":
                    target = root / "pointer-target"
                    target.write_text(f"{recovery}\n")
                    pointer.unlink()
                    pointer.symlink_to(target)
                elif case == "outside state root":
                    elsewhere = root / "app"
                    pointer.write_text(f"{elsewhere}\n")
                result = self._installer_harness(
                    root, "preinstall", ("require_recovery_directory", "read_recovery_path"),
                    'out="$(read_recovery_path)"\necho "OUT=[$out]"\n', modes=self._recovery_modes(root))
                self.assertEqual(result.returncode, 0, result.stderr)
                if case == "valid":
                    self.assertIn(f"OUT=[{recovery}]", result.stdout)
                    self.assertTrue(pointer.exists())
                    continue
                self.assertIn("OUT=[]", result.stdout)
                self.assertIn("discarding an unusable installation recovery pointer", result.stderr)
                self.assertFalse(pointer.exists() or pointer.is_symlink())
                # The pointer's target is never deleted on the pointer's say-so.
                self.assertTrue(recovery.exists())
                self.assertTrue(elsewhere.exists())
                if case == "symlink":
                    self.assertTrue((root / "pointer-target").exists())

    # ── Governance sec-5/uh-3/ch-2/rd-n2: postinstall's flag-guarded EXIT trap ─
    def _promotion_exit(self, body: str) -> subprocess.CompletedProcess:
        """The real on_exit, armed as postinstall arms it (both flags 0, then the
        trap), with the two restores replaced by loggers."""
        post = (BUILD_PKG.parent / "postinstall").read_text()
        harness = (PREAMBLE + script_function(post, "on_exit")
                   + 'restore_previous() { echo RESTORE >> "$RESTORE_LOG"; }\n'
                   + 'restore_missing_live_files() { echo MISSING >> "$RESTORE_LOG"; }\n'
                   + "INSTALL_COMPLETED=0\nPROMOTION_ARMED=0\ntrap on_exit EXIT\n" + body)
        with tempfile.TemporaryDirectory(prefix="yuzu_test_on_exit_") as temporary:
            log = Path(temporary) / "restore.log"
            result = subprocess.run([PKG_SHELL, "-c", harness], text=True, capture_output=True,
                                    env={**os.environ, "RESTORE_LOG": str(log)})
            text = log.read_text() if log.exists() else ""
            result.restores = text.count("RESTORE")  # type: ignore[attr-defined]
            result.missing = text.count("MISSING")  # type: ignore[attr-defined]
        return result

    @posix_shell
    def test_promotion_failures_restore_exactly_when_armed(self) -> None:
        done = "PROMOTION_ARMED=0\nINSTALL_COMPLETED=1\n"
        cases = {
            # Before promotion an exit is a refusal: only missing live files are
            # put back (rd-n2), never the snapshot.
            "failure before arming": ("false\nPROMOTION_ARMED=1\n", 0, 1, False),
            "refusal exit before arming": ("exit 1\n", 0, 1, False),
            # errexit inside a function skipped the non-inherited ERR trap (sec-5).
            "failure inside a function": ("PROMOTION_ARMED=1\nstep() { false; echo unreachable; }\nstep\n", 1, 0, False),
            "failure at top level": ("PROMOTION_ARMED=1\nfalse\n", 1, 0, False),
            # bash 3.2 reports $?=0 to an EXIT trap after a `set -u` abort.
            "set -u abort": ('PROMOTION_ARMED=1\necho "$NEVER_DEFINED_ANYWHERE"\n' + done, 1, 0, False),
            "explicit exit": ("PROMOTION_ARMED=1\nexit 3\n", 1, 0, False),
            # A handled failure inside a command substitution must never restore
            # (with `set -E` bash 3.2 fired the ERR trap inside the subshell).
            "handled substitution": ('PROMOTION_ARMED=1\nx="$(false)" || true\n'
                                     'probe() { local o; o="$(false)" || return 0; }\nprobe\n' + done, 0, 0, True),
            "completed": ("PROMOTION_ARMED=1\ntrue\n" + done, 0, 0, True),
            # Disarmed but not completed (a failure after the disarm): a refusal-style
            # exit, never a restore of the snapshot over the new install.
            "failure after disarm": ("PROMOTION_ARMED=1\nPROMOTION_ARMED=0\nfalse\n", 0, 1, False),
        }
        for name, (body, restores, missing, succeeds) in cases.items():
            with self.subTest(case=name):
                result = self._promotion_exit(body)
                self.assertEqual(result.restores, restores, result.stderr)  # type: ignore[attr-defined]
                self.assertEqual(result.missing, missing, result.stderr)  # type: ignore[attr-defined]
                self.assertEqual(result.returncode == 0, succeeds, result.stderr)
                self.assertNotIn("unreachable", result.stdout)

    @posix_shell
    def test_successful_postinstall_tail_restores_nothing(self) -> None:
        # Quality g8q-1: the real tail, from the legacy retirement to the completion
        # flag, run behaviourally. A good install must neither restore the snapshot
        # nor run the refusal restore; a failure after the disarm must not restore
        # the snapshot over the new install.
        post = (BUILD_PKG.parent / "postinstall").read_text()
        # Anchored on markers the guarded lines are not part of, so deleting the
        # disarm or the completion flag fails behaviourally, not by slicing.
        start = post.index("\nretire_legacy_app\n", post.index("# The previous development bundle lived below")) + 1
        tail = post[start:post.index('echo "$outcome"\n', start)]
        for name, finish, restores, missing, succeeds in (
                ("clean", ":", 0, 0, True),
                ("finish_recovery fails", "false", 0, 1, False)):
            with self.subTest(case=name):
                body = ('retire_legacy_app() { :; }\n'
                        f'finish_recovery() {{ {finish}; }}\nrecovery=/nonexistent\n'
                        'PROMOTION_ARMED=1\n' + tail + 'echo TAIL-DONE\n')
                result = self._promotion_exit(body)
                self.assertEqual(result.restores, restores, result.stderr)  # type: ignore[attr-defined]
                self.assertEqual(result.missing, missing, result.stderr)  # type: ignore[attr-defined]
                self.assertEqual(result.returncode == 0, succeeds, result.stderr)
                self.assertEqual("TAIL-DONE" in result.stdout, succeeds)

    def test_installer_scripts_run_with_pipefail(self) -> None:
        for name in ("preinstall", "postinstall", "uninstall.sh"):
            source = (BUILD_PKG.parent / name).read_text()
            self.assertIn("\nset -euo pipefail\n", source, name)
            self.assertNotRegex(source, r"(?m)^\s*set -[a-zA-Z]*E", name)
            self.assertNotIn("trap 'restore_previous' ERR", source, name)
        post = (BUILD_PKG.parent / "postinstall").read_text()
        # The trap is armed before the first main-flow statement, so every early
        # refusal also runs it (rd-n2); the snapshot restore is armed only after
        # the promoting phase is durable and just before the service is stopped.
        trap = post.index("trap on_exit EXIT\n\nensure_state_dir\n")
        self.assertLess(post.index("INSTALL_COMPLETED=0\nPROMOTION_ARMED=0\non_exit() {"), trap)
        phase = post.index("mv -f \"$recovery/.phase.new\" \"$recovery/phase\"")
        armed = post.index("PROMOTION_ARMED=1\nrequire_stopped\n")
        self.assertLess(trap, phase)
        self.assertLess(phase, armed)
        disarmed = post.index("PROMOTION_ARMED=0\nfinish_recovery \"$recovery\"\nINSTALL_COMPLETED=1\n")
        self.assertLess(post.index("\nretire_legacy_app\n", armed), disarmed)

    # ── Governance sec-2: the whole /usr/local chain, both lanes ───────────────
    @macos_userland
    def test_code_directory_chain_must_be_root_owned_and_not_writable(self) -> None:
        for script in ("preinstall", "postinstall"):
            with self.subTest(script=script), tempfile.TemporaryDirectory(prefix="yuzu_test_chain_") as temporary:
                root = Path(temporary)
                ul = root / "ul"
                levels = [ul, ul / "lib", ul / "lib/yuzu", ul / "bin"]
                for level in levels:
                    level.mkdir(parents=True, exist_ok=True)
                    level.chmod(0o755)

                def verdicts(owners: dict | None = None) -> tuple[str, str]:
                    out = []
                    for lane in ("bundle", "loose"):
                        result = self._installer_harness(
                            root, script, ("acl_grants_write", "code_directory_chain_trusted"),
                            f'if code_directory_chain_trusted {lane}; then echo TRUSTED; else echo REFUSED; fi\n',
                            owners=owners, real_modes=True)
                        self.assertEqual(result.returncode, 0, result.stderr)
                        out.append(result.stdout.strip())
                    return out[0], out[1]

                self.assertEqual(verdicts(), ("TRUSTED", "TRUSTED"))
                for level in levels:
                    lane_bin = level == ul / "bin"
                    expected = ("TRUSTED", "REFUSED") if lane_bin else ("REFUSED", "REFUSED")
                    level.chmod(0o775)
                    self.assertEqual(verdicts(), expected, f"group-writable {level}")
                    level.chmod(0o757)
                    self.assertEqual(verdicts(), expected, f"world-writable {level}")
                    level.chmod(0o755)
                    self.assertEqual(verdicts({level: 501}), expected, f"user-owned {level}")
                self.assertEqual(verdicts(), ("TRUSTED", "TRUSTED"))
                # A symlinked level is refused; an absent one has nothing to swap.
                (ul / "lib/yuzu").rmdir()
                self.assertEqual(verdicts(), ("TRUSTED", "TRUSTED"))
                (root / "elsewhere").mkdir()
                (ul / "lib/yuzu").symlink_to(root / "elsewhere")
                self.assertEqual(verdicts(), ("REFUSED", "REFUSED"))

    def test_loose_promotion_is_refused_before_the_active_service_is_touched(self) -> None:
        post = (BUILD_PKG.parent / "postinstall").read_text()
        pre = (BUILD_PKG.parent / "preinstall").read_text()
        stop = post.index("require_stopped\nremove_managed_plugins")
        promoting = post.index("printf 'promoting\\n'")
        for check in ('require_trusted_log_directory || exit 1', 'require_trusted_code_tree "$MODE" || exit 1',
                      "reject_unmanaged_plugin_collisions || exit 1",
                      "verify_incoming_loose_code || exit 1",
                      'recovery="$(recovery_path)" || {',
                      '/usr/bin/osascript -l JavaScript "$SCRIPT_SRC/merge-launchd-plist.js"',
                      "reject_unsigned_plugins_under_enforcement || exit 1"):
            at = post.index(check)
            self.assertLess(at, stop, check)
            self.assertLess(at, promoting, check)
        self.assertLess(post.index("require_trusted_code_tree() {"), post.index('require_trusted_code_tree "$MODE" || exit 1'))
        # The merge helper runs from the package's Scripts directory, never from
        # below /usr/local (sec-2, G8-S3).
        self.assertIn('SCRIPT_SRC="$(cd "$(dirname "$0")" && pwd)"', post)
        self.assertNotIn("$YUZU_LIB/merge-launchd-plist.js", post)
        self.assertNotIn("$recovery/merge-launchd-plist.js", post)
        self.assertNotIn("osascript -l JavaScript /usr/local/lib/yuzu/merge-launchd-plist.js", post)
        # preinstall runs every payload-independent check before Installer writes
        # anything (rd-n2): package-info, data and log directories, and the lane's
        # code tree before any payload parent; collisions and signature enforcement
        # before the snapshot copies and the pointer.
        payload = pre.index('secure_payload_parent "$APP_ROOT" 755')
        for check in ('"$SCRIPT_SRC/package-info"', "require_trusted_data_directory || exit 1",
                      "require_trusted_log_directory || exit 1", 'require_trusted_code_tree "$PACKAGE_MODE" || exit 1'):
            self.assertLess(pre.index(check), payload, check)
        snapshot = pre.index('copy_if_present "$PLIST" "$RECOVERY/LaunchDaemons/com.yuzu.agent.plist"')
        for check in ("reject_unmanaged_plugin_collisions || exit 1", "reject_unsigned_plugins_under_enforcement || exit 1"):
            self.assertLess(pre.index("adopt_receipted_plugins\n" + "reject_unmanaged"), pre.index(check))
            self.assertLess(pre.index(check), snapshot, check)
            self.assertLess(pre.index(check), pre.index('> "$RECOVERY_FILE.new"'), check)
        # The recovery pointer is written through a temporary name (uh-1).
        self.assertLess(pre.index('> "$RECOVERY_FILE.new"'), pre.index('mv -f "$RECOVERY_FILE.new" "$RECOVERY_FILE"'))

    # ── Governance ch-4: content a non-root account could have written ─────────
    @macos_userland
    def test_untrusted_code_entries_are_listed_and_refused(self) -> None:
        for script in ("preinstall", "postinstall"):
            with self.subTest(script=script), tempfile.TemporaryDirectory(prefix="yuzu_test_entries_") as temporary:
                root = Path(temporary)
                bin_dir, plugins = root / "ul/bin", root / "ul/lib/yuzu/plugins"
                bin_dir.mkdir(parents=True)
                plugins.mkdir(parents=True)

                def run(owners: dict | None = None) -> subprocess.CompletedProcess:
                    return self._installer_harness(root, script, ("acl_grants_write", "reject_untrusted_code_entries"),
                                                   "reject_untrusted_code_entries\necho ACCEPTED\n",
                                                   owners=owners, real_modes=True)

                clean = run()
                self.assertEqual(clean.returncode, 0, clean.stderr)
                self.assertIn("ACCEPTED", clean.stdout)
                # /usr/local/bin entries go through the (stubbed-owner) stat check;
                # everything below plugins/ through find, whose -user 0 cannot be
                # stubbed: every file a test creates is non-root, so all of them
                # must be listed, at any depth and under any name (G8-S1).
                (plugins / "sub").mkdir()
                files = {bin_dir / "yuzu-agent": 0o644, bin_dir / "yuzu-agent.old": 0o664,
                         bin_dir / "libyuzu_agent_core.dylib": 0o644, bin_dir / ".yuzu-update-verified": 0o666,
                         bin_dir / ".yuzu-agent.incoming": 0o775,
                         bin_dir / ".libyuzu_agent_core.incoming.dylib": 0o755,
                         bin_dir / "other-tool": 0o666, plugins / "good.dylib": 0o644,
                         plugins / ".hidden": 0o664, plugins / "..evil.dylib": 0o644,
                         plugins / "sub/nested.dylib": 0o644}
                for path, mode in files.items():
                    path.write_text("fixture")
                    path.chmod(mode)
                (plugins / "evil.dylib").symlink_to(plugins / "good.dylib")
                result = run({bin_dir / "libyuzu_agent_core.dylib": 501})
                self.assertNotEqual(result.returncode, 0)
                self.assertNotIn("ACCEPTED", result.stdout)
                listed = {line.strip() for line in result.stderr.splitlines() if line.startswith("         /")}
                self.assertEqual(listed, {str(bin_dir / "yuzu-agent.old"), str(bin_dir / "libyuzu_agent_core.dylib"),
                                          str(bin_dir / ".yuzu-update-verified"), str(bin_dir / ".yuzu-agent.incoming"),
                                          str(plugins / "good.dylib"), str(plugins / ".hidden"),
                                          str(plugins / "..evil.dylib"), str(plugins / "sub"),
                                          str(plugins / "sub/nested.dylib"), str(plugins / "evil.dylib")})
                self.assertIn("remove anything you did not install as root", result.stderr)
                self.assertIn("Do not chown -R", result.stderr)

    @macos_userland
    def test_code_tree_check_reports_entries_even_when_a_directory_is_refused(self) -> None:
        # G8-S1: a directory refusal must not hide the file listing, or a
        # recursive chown "fix" makes planted files look root-installed.
        for script in ("preinstall", "postinstall"):
            with self.subTest(script=script), tempfile.TemporaryDirectory(prefix="yuzu_test_tree_") as temporary:
                root = Path(temporary)
                ul = root / "ul"
                for level in (ul, ul / "lib", ul / "lib/yuzu", ul / "lib/yuzu/plugins", ul / "bin"):
                    level.mkdir(parents=True, exist_ok=True)
                    level.chmod(0o755)
                (ul / "lib/yuzu/plugins/..evil.dylib").write_text("planted")
                names = ("acl_grants_write", "code_directory_chain_trusted", "reject_untrusted_code_entries",
                         "require_trusted_code_tree")
                for lane, loosened, chain_refused in (("bundle", ul / "lib", True), ("bundle", ul / "bin", False),
                                                      ("loose", ul / "bin", True)):
                    loosened.chmod(0o775)
                    result = self._installer_harness(root, script, names,
                                                     f"require_trusted_code_tree {lane}\necho ACCEPTED\n",
                                                     real_modes=True)
                    loosened.chmod(0o755)
                    self.assertNotEqual(result.returncode, 0)
                    self.assertNotIn("ACCEPTED", result.stdout)
                    self.assertEqual("must be root-owned and not group/world writable" in result.stderr, chain_refused,
                                     (lane, loosened, result.stderr))
                    # The harness rewrites /usr/local to the fixture's "ul" in messages too.
                    self.assertEqual(f"{ul}/bin must be" in result.stderr, chain_refused and lane == "loose")
                    self.assertIn(str(ul / "lib/yuzu/plugins/..evil.dylib"), result.stderr)

    @unittest.skipUnless(sys.platform == "darwin", "native macOS archive/plist integration")
    def test_two_stage_final_output_cms_policy_is_verified_before_publication(self) -> None:
        # Orchestration fixture, not a cryptographic claim: the verifier double
        # checks exact final bytes and argv. Real CMS verification is covered by
        # the agent CMS suite; never bypass it in the builder.
        with tempfile.TemporaryDirectory(prefix="yuzu_test_final_cms_") as temporary:
            root = Path(temporary)
            app = root / "bundle/YuzuAgent.app/Contents/MacOS"
            app.mkdir(parents=True)
            verifier = app / "yuzu-agent"
            verifier.write_text('#!/bin/sh\nset -eu\n[ "$1" = --verify-plugin-signature ]\n[ "$3" = --plugin-trust-bundle ]\ncmp "$2" "$2.sig"\n')
            verifier.chmod(0o755)
            (app.parent / "Info.plist").write_bytes(plistlib.dumps({"CFBundleShortVersionString": "1.0"}))
            plugins = root / "bundle/plugins"
            plugins.mkdir()
            plugin = plugins / "tar.dylib"
            plugin.write_bytes(b"final Apple-signed byte fixture")
            (plugins / "tar.dylib.sig").write_bytes(plugin.read_bytes())
            (plugins / "plugin-signing-policy.json").write_text(json.dumps(
                {"runtime_plugin_trust_bundle": "/etc/yuzu-agent/certs/plugins.pem"}))
            trust = root / "trust.pem"
            trust.write_text("fixture trust")
            tools = root / "tools"
            tools.mkdir()
            captured = root / "captured.plist"
            for name, body in {
                "codesign": "#!/bin/sh\nexit 0\n",
                "lipo": "#!/bin/sh\necho arm64\n",
                "pkgbuild": "#!/bin/sh\nset -eu\nroot=; last=\nwhile [ \"$#\" -gt 0 ]; do case \"$1\" in --root) root=\"$2\"; shift 2 ;; *) last=\"$1\"; shift ;; esac; done\ncp \"$root/Library/LaunchDaemons/.com.yuzu.agent.incoming.plist\" \"$CAPTURED_PLIST\"\n: > \"$last\"\n",
                "productbuild": "#!/bin/sh\nfor last; do :; done\n: > \"$last\"\n",
            }.items():
                tool = tools / name
                tool.write_text(body)
                tool.chmod(0o755)
            for tampered in (False, True):
                if tampered:
                    plugin.write_bytes(b"changed after CMS signing")
                output = root / ("tampered" if tampered else "valid")
                result = subprocess.run([PKG_SHELL, str(BUILD_PKG), "--bundle-dir", str(root / "bundle"),
                                         "--version", "1.0", "--output", str(output),
                                         "--plugin-trust-bundle", str(trust)], text=True, capture_output=True,
                                        env={**os.environ, "PATH": f"{tools}:{os.environ['PATH']}",
                                             "CAPTURED_PLIST": str(captured)})
                if tampered:
                    self.assertNotEqual(result.returncode, 0)
                    self.assertFalse(output.exists())
                else:
                    self.assertEqual(result.returncode, 0, result.stderr)
                    args = plistlib.loads(captured.read_bytes())["ProgramArguments"]
                    self.assertIn("--plugin-require-signature", args)
                    self.assertEqual(args[args.index("--plugin-trust-bundle") + 1],
                                     "/etc/yuzu-agent/certs/plugins.pem")

    @unittest.skipUnless(sys.platform == "darwin", "native macOS plist integration")
    def test_native_plist_merge_falls_back_on_an_unreadable_previous_definition(self) -> None:
        # Governance ch-1: an unparseable or malformed live definition (a hand-edit
        # typo, a torn write) installs the package default with a warning instead of
        # wedging every upgrade. A malformed GENERATED definition is a package bug
        # and still fails without touching the destination.
        with tempfile.TemporaryDirectory(prefix="yuzu_test_plist_native_") as temporary:
            root = Path(temporary)
            previous, destination = root / "previous.plist", root / "new.plist"
            generated = plistlib.dumps({"ProgramArguments": ["/new/agent"]})
            for prior in (b"not a plist at all", b"", plistlib.dumps({"ProgramArguments": []}),
                          plistlib.dumps({"ProgramArguments": [42]}),
                          plistlib.dumps({"ProgramArguments": ["/old/agent"], "EnvironmentVariables": []}),
                          plistlib.dumps({"ProgramArguments": ["/old/agent"], "EnvironmentVariables": {"A": 1}})):
                with self.subTest(prior=prior[:40]):
                    previous.write_bytes(prior)
                    destination.write_bytes(generated)
                    result = subprocess.run(["/usr/bin/osascript", "-l", "JavaScript", str(MERGE_PLIST_HELPER),
                                             "--previous", str(previous), "--destination", str(destination)],
                                            text=True, capture_output=True)
                    self.assertEqual(result.returncode, 0, result.stderr)
                    self.assertEqual(destination.read_bytes(), generated)
                    self.assertIn("cannot be read", result.stderr)
            previous.write_bytes(plistlib.dumps({"ProgramArguments": ["/old/agent"]}))
            broken = plistlib.dumps({"ProgramArguments": []})
            destination.write_bytes(broken)
            result = subprocess.run(["/usr/bin/osascript", "-l", "JavaScript", str(MERGE_PLIST_HELPER),
                                     "--previous", str(previous), "--destination", str(destination)],
                                    text=True, capture_output=True)
            self.assertNotEqual(result.returncode, 0)
            self.assertEqual(destination.read_bytes(), broken)

    def test_vcpkg_macos_target_triplet_pins_the_documented_runtime_floor(self) -> None:
        triplet = MACOS_TRIPLET.read_text()
        self.assertIn("set(VCPKG_TARGET_ARCHITECTURE arm64)", triplet)
        self.assertIn("set(VCPKG_CMAKE_SYSTEM_NAME Darwin)", triplet)
        self.assertIn('set(VCPKG_OSX_DEPLOYMENT_TARGET "13.3")', triplet)

    def test_builder_requires_the_documented_macos_deployment_target(self) -> None:
        output = (
            "binary:\n"
            "Load command 4\n"
            "      cmd LC_BUILD_VERSION\n"
            "    minos 13.3\n"
            "      sdk 26.5\n"
        )
        with mock.patch.object(bundle, "run", return_value=output):
            self.assertEqual(bundle.macho_deployment_targets(Path("binary")), ["13.3"])
            bundle.require_macos_deployment_target([Path("binary")])
        wrong_target = output.replace("minos 13.3", "minos 26.0")
        with mock.patch.object(bundle, "run", return_value=wrong_target):
            with self.assertRaisesRegex(bundle.BundleError, "rebuild with meson/native"):
                bundle.require_macos_deployment_target([Path("binary")])

    def test_builder_requires_all_machos_to_match_agent_architectures(self) -> None:
        def lipo(argv: list[str]) -> str:
            return "arm64\n" if argv[-1] == "agent" else "x86_64\n"

        with mock.patch.object(bundle, "run", side_effect=lipo):
            with self.assertRaisesRegex(bundle.BundleError, "architectures x86_64, expected arm64"):
                bundle.require_matching_architectures(Path("agent"), [Path("plugin")])

    def test_builder_requires_the_exact_tar_plugin_basename(self) -> None:
        with tempfile.TemporaryDirectory(prefix="yuzu_test_macos_bundle_") as temporary:
            plugin_dir = Path(temporary) / "plugins"
            plugin_dir.mkdir()
            (plugin_dir / "not_tar.dylib").touch()
            with self.assertRaisesRegex(bundle.BundleError, "TAR plugin"):
                bundle.find_plugins(Path(temporary))
            (plugin_dir / "tar.dylib").touch()
            self.assertEqual({plugin.name for plugin in bundle.find_plugins(Path(temporary))},
                             {"not_tar.dylib", "tar.dylib"})

    def test_payload_is_staged_before_postinstall_promotes_it(self) -> None:
        preinstall = (ROOT / "deploy/packaging/macos/preinstall").read_text()
        postinstall = (ROOT / "deploy/packaging/macos/postinstall").read_text()
        package_builder = BUILD_PKG.read_text()
        self.assertIn('.bundle-contents.incoming.zip', package_builder)
        self.assertIn('ditto -c -k --keepParent "$APP/Contents"', package_builder)
        self.assertIn('.plugins.incoming', package_builder)
        self.assertNotIn('rm -rf "/Library/Application Support/Yuzu/YuzuAgent.app"', preinstall)
        self.assertIn('recover_interrupted_promotion', preinstall)
        self.assertNotIn('launchctl bootout',
                         preinstall[:preinstall.index('recover_interrupted_promotion')])
        self.assertIn('secure_payload_parent "$APP_ROOT" 755', preinstall)
        self.assertIn('non-package owner', preinstall)
        self.assertNotIn('secure_payload_parent "$DATA_DIR"', preinstall)
        self.assertIn('ensure_data_directory', postinstall)
        self.assertIn('secure_payload_parent "$YUZU_LIB" 755', preinstall)
        self.assertIn('root-owned and not group/world writable', preinstall)
        self.assertIn('ensure_state_dir()', preinstall)
        self.assertIn('recovery state root must be root:wheel mode 700', preinstall)
        self.assertIn('recovery pointer must be root:wheel mode 600', postinstall)
        self.assertIn('discarding an unusable installation recovery pointer', preinstall)
        self.assertIn('refusing recovery path outside the trusted state root', preinstall)
        self.assertIn('secure_payload_parent "$parent" 755', preinstall)
        self.assertIn('write_recovery_phase "$RECOVERY" prepared', preinstall)
        self.assertIn('promoting)', preinstall)
        self.assertIn('recover_interrupted_promotion "$pending"', preinstall)
        self.assertIn('mv "$INCOMING_APP" "$APP"', postinstall)
        self.assertIn('incoming bundle archive is missing or symlinked', postinstall)
        self.assertIn('set -euo pipefail', postinstall)
        self.assertIn('/usr/bin/unzip -Z1 "$INCOMING_BUNDLE_ARCHIVE"', postinstall)
        self.assertIn('incoming bundle archive has an unsafe entry', postinstall)
        self.assertIn('incoming bundle contains a symlink', postinstall)
        self.assertIn('require_stopped', postinstall)
        self.assertIn('require_started', postinstall)
        self.assertIn('stable=0', postinstall)
        self.assertIn('require_started', preinstall)
        self.assertNotIn('launchctl bootstrap system "$PLIST" >/dev/null 2>&1 || true', postinstall)
        self.assertNotIn('chown root:wheel "$APP_ROOT" "$LOG_DIR" "$CONFIG_DIR" "$CERT_DIR" "$YUZU_LIB"', postinstall)
        self.assertIn('preserve_or_create_directory "$CONFIG_DIR" 755', postinstall)
        self.assertIn('operational directory must be root-owned and not group/world writable', postinstall)
        self.assertIn('preserve_or_create_directory "$CERT_DIR" 755', postinstall)
        self.assertIn('"$parent" == "/etc" && -L "$parent"', postinstall)
        self.assertIn('"$(readlink "$parent")" == "private/etc"', postinstall)
        self.assertIn('require_trusted_directory "/private/etc"', postinstall)
        self.assertIn('remove_managed_plugins "$MANIFEST"', postinstall)
        self.assertIn('rm -rf "$recovery"', postinstall)
        self.assertIn('finish_recovery "$recovery"', postinstall)

    def test_recovery_clears_both_lanes_and_uninstall_removes_transition_paths(self) -> None:
        preinstall = (ROOT / "deploy/packaging/macos/preinstall").read_text()
        postinstall = (ROOT / "deploy/packaging/macos/postinstall").read_text()
        uninstall = (ROOT / "deploy/packaging/macos/uninstall.sh").read_text()
        clear_lanes = ('rm -f "$LOOSE_BIN/yuzu-agent" "$LOOSE_BIN/libyuzu_agent_core.dylib" '
                       '/usr/local/lib/libyuzu_agent_core.dylib \\\n'
                       '          "$LOOSE_BIN/yuzu-agent.old" "$LOOSE_BIN/.yuzu-update-verified"')
        # Promotion and restore (postinstall) and recovery (preinstall) also drop the
        # updater's rollback file and marker (governance ch-4, rd-5).
        pattern = re.escape(clear_lanes).replace(re.escape("\\\n          "), r"\\\n\s+")
        self.assertEqual(len(re.findall(pattern, postinstall)), 2)
        self.assertEqual(len(re.findall(pattern, preinstall)), 1)
        self.assertIn('"$LOOSE_BIN/yuzu-agent.old" "$LOOSE_BIN/.yuzu-update-verified"', uninstall)
        self.assertIn('remove_managed_plugins "$MANIFEST"', postinstall)
        self.assertIn('harden_managed_plugins "$MANIFEST"', postinstall)
        collision = "collides with one not installed by a Yuzu package, or changed since"
        self.assertIn(collision, postinstall)
        self.assertIn(collision, preinstall)
        self.assertNotIn("unmanaged third-party plugin", preinstall + postinstall)
        self.assertIn('reject_unmanaged_plugin_collisions()', postinstall)
        self.assertLess(postinstall.index('reject_unmanaged_plugin_collisions || exit 1'),
                        postinstall.index('require_stopped\nremove_managed_plugins'))
        self.assertEqual(postinstall.count(collision), 1)
        self.assertIn('remove_managed_plugins "$INCOMING_MANIFEST"', postinstall)
        self.assertIn('LEGACY_APP="$DATA_DIR/YuzuAgent.app"', preinstall)
        # The snapshot's legacy copy was never restored from (sec-8): preinstall
        # neither copies nor classifies a legacy app, and carries no identity pins.
        self.assertNotIn('legacy_app_is_managed', preinstall)
        self.assertNotIn('$RECOVERY/legacy', preinstall)
        for pin in ("LEGACY_TEAM_ID", "LEGACY_APP_ID", "LEGACY_SIGNING_AUTHORITY", "LEGACY_PROFILE_SHA256"):
            self.assertNotIn(pin, preinstall)
            self.assertIn(pin + "=", postinstall)
            self.assertIn(pin + "=", uninstall)
        self.assertIn('codesign -dvv "$candidate"', postinstall)
        self.assertIn('legacy-retired.app', postinstall)
        self.assertIn('retire_legacy_app', postinstall)
        self.assertIn('did not start it from non-package-owned data', preinstall)
        self.assertIn('did not start it from non-package-owned data', postinstall)
        self.assertIn('quarantine_legacy_app "$recovery/legacy-retired.app"', preinstall)
        self.assertIn('quarantine_legacy_app "$recovery/legacy-retired.app"', postinstall)
        self.assertNotIn('retained legacy app in root-owned recovery', preinstall + postinstall)
        self.assertIn('retire_legacy_app', postinstall)
        self.assertNotIn('recovery/legacy/YuzuAgent.app', postinstall)
        self.assertIn('retire_legacy_app', uninstall)
        self.assertIn('"/Library/Application Support/Yuzu/YuzuAgent.app"', uninstall)
        self.assertIn('YUZU_LIB="/usr/local/lib/yuzu"', uninstall)
        self.assertIn('"$YUZU_LIB/merge-launchd-plist.py"', uninstall)
        self.assertIn('"$YUZU_LIB/plugin-signing-policy.json"', uninstall)
        self.assertIn('sync', postinstall)
        self.assertNotIn('rm -rf "$APP" "$PLUGIN_DIR"', postinstall)
        self.assertIn('.YuzuAgent.incoming.app', uninstall)
        self.assertIn('.bundle-contents.incoming.zip', uninstall)
        self.assertIn('.plugins.incoming', uninstall)
        self.assertIn('invalid package plugin manifest entry', uninstall)
        self.assertNotIn('rm -rf "/Library/Application Support/Yuzu/YuzuAgent.app" \\\n+       "/Library/Application Support/Yuzu/.YuzuAgent.incoming.app" \\\n+       /usr/local/lib/yuzu/plugins', uninstall)

    def test_cms_enforcement_refuses_mixed_plugin_sidecars(self) -> None:
        source = HELPER.read_text()
        self.assertIn('all external plugins must have CMS sidecars', source)
        package_builder = (ROOT / "deploy/packaging/macos/build-pkg.sh").read_text()
        self.assertIn('all external plugins must have CMS sidecars when signing policy is present', package_builder)
        self.assertIn('CMS_ENFORCEMENT=1', package_builder)
        self.assertIn('intentionally never read again, closing validation-to-publication races', package_builder)
        self.assertIn('codesign --verify --deep --strict --verbose=2 "$STAGED_APP"', package_builder)
        self.assertIn('for plugin in "$STAGED_PLUGINS"/*.dylib; do', package_builder)
        self.assertIn('AGENT_BIN="$STAGED_APP/Contents/MacOS/yuzu-agent"', package_builder)
        self.assertIn('staged bundle version does not match --version', package_builder)
        package_readme = (ROOT / "deploy/packaging/macos/README.md").read_text()
        self.assertIn('--plugin-trust-bundle <build-trust.pem>', package_readme)
        self.assertIn('unrecognized', package_readme)
        # The README states what the scripts now do: an unrecognized app is
        # quarantined and never blocks (uninstall included), and one lock
        # serialises installs and uninstalls (governance ch-3).
        self.assertIn('/var/db/yuzu-agent/quarantine/legacy-YuzuAgent.*/', package_readme)
        self.assertIn('/var/db/.yuzu-agent-transition.lock', package_readme)
        self.assertNotIn('uninstall-legacy.*', package_readme)
        self.assertNotIn('uninstall stopped before deleting package code',
                         (ROOT / "deploy/packaging/macos/uninstall.sh").read_text())

    @unittest.skipUnless(sys.platform == "darwin", "native macOS archive/plist integration")
    def test_package_builder_rejects_a_mixed_cms_plugin_set_before_publishing(self) -> None:
        with tempfile.TemporaryDirectory(prefix="yuzu_test_macos_mixed_cms_") as temporary:
            root = Path(temporary)
            app = root / "bundle/YuzuAgent.app/Contents/MacOS"
            app.mkdir(parents=True)
            executable = app / "yuzu-agent"
            executable.write_text("#!/bin/sh\nexit 42\n")
            executable.chmod(0o755)
            with (app.parent / "Info.plist").open("wb") as output:
                plistlib.dump({"CFBundleShortVersionString": "1.0"}, output)
            plugins = root / "bundle/plugins"
            plugins.mkdir()
            (plugins / "tar.dylib").write_bytes(b"tar")
            (plugins / "tar.dylib.sig").write_bytes(b"tar sidecar")
            (plugins / "other.dylib").write_bytes(b"missing sidecar")
            (plugins / "plugin-signing-policy.json").write_text(
                json.dumps({"runtime_plugin_trust_bundle": "/etc/yuzu-agent/certs/plugins.pem"}) + "\n")
            trust = root / "plugins.pem"
            trust.write_text("test trust material\n")
            tools = root / "tools"
            tools.mkdir()
            codesign = tools / "codesign"
            codesign.write_text("#!/bin/sh\nexit 0\n")
            codesign.chmod(0o755)
            output = root / "dist"
            result = subprocess.run([PKG_SHELL, str(BUILD_PKG), "--bundle-dir", str(root / "bundle"),
                                     "--version", "1.0", "--output", str(output),
                                     "--plugin-trust-bundle", str(trust)],
                                    capture_output=True, text=True,
                                    env=os.environ | {"PATH": f"{tools}:{os.environ['PATH']}"})
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("all external plugins must have CMS sidecars", result.stderr)
            self.assertFalse(output.exists())

    @unittest.skipUnless(sys.platform == "darwin", "native macOS stat/permissions integration")
    def test_operational_directory_guard_rejects_untrusted_owner_and_symlink(self) -> None:
        postinstall = (ROOT / "deploy/packaging/macos/postinstall").read_text()
        start = postinstall.index("preserve_or_create_directory()")
        end = postinstall.index("\n\nlegacy_app_is_managed()", start)
        guard = postinstall[start:end]
        with tempfile.TemporaryDirectory(prefix="yuzu_test_macos_operational_dir_") as temporary:
            root = Path(temporary)
            unsafe = root / "unsafe"
            unsafe.mkdir()
            for path in (unsafe, root / "linked"):
                if path.name == "linked":
                    path.symlink_to(unsafe, target_is_directory=True)
                result = subprocess.run(["bash", "-ceu", guard + "\npreserve_or_create_directory \"$TARGET\" 755"],
                                        env=os.environ | {"TARGET": str(path)},
                                        capture_output=True, text=True)
                self.assertNotEqual(result.returncode, 0)
                self.assertIn("operational path", result.stderr) if path.is_symlink() else \
                    self.assertIn("operational directory must be root-owned", result.stderr)

    @unittest.skipUnless(sys.platform == "darwin", "native macOS archive/plist integration")
    def test_package_builder_validates_the_private_plugin_snapshot_after_source_mutation(self) -> None:
        with tempfile.TemporaryDirectory(prefix="yuzu_test_macos_package_race_") as temporary:
            root = Path(temporary)
            app = root / "bundle/YuzuAgent.app/Contents/MacOS"
            app.mkdir(parents=True)
            executable = app / "yuzu-agent"
            executable.write_text("#!/bin/sh\nexit 0\n")
            executable.chmod(0o755)
            with (app.parent / "Info.plist").open("wb") as output:
                plistlib.dump({"CFBundleShortVersionString": "1.0"}, output)
            plugins = root / "bundle/plugins"
            plugins.mkdir()
            source_plugin = plugins / "tar.dylib"
            source_plugin.write_bytes(b"original staged bytes")
            tools = root / "tools"
            tools.mkdir()
            captured = root / "captured-plugin"
            for name, body in {
                "codesign": "#!/bin/sh\ncase \"$*\" in */YuzuAgent.app*) printf 'mutated source bytes' > \"$RACE_SOURCE\"; printf 'mutated source plist' > \"$RACE_INFO\" ;; esac\nexit 0\n",
                "lipo": "#!/bin/sh\necho arm64\n",
                "pkgbuild": "#!/bin/sh\nroot=; last=\nwhile [ \"$#\" -gt 0 ]; do case \"$1\" in --root) root=\"$2\"; shift 2 ;; *) last=\"$1\"; shift ;; esac; done\ncp \"$root/usr/local/lib/yuzu/.plugins.incoming/tar.dylib\" \"$CAPTURED_PLUGIN\"\n: > \"$last\"\n",
                "productbuild": "#!/bin/sh\nfor last; do :; done\n: > \"$last\"\n",
            }.items():
                tool = tools / name
                tool.write_text(body)
                tool.chmod(0o755)
            output = root / "dist"
            result = subprocess.run([PKG_SHELL, str(BUILD_PKG), "--bundle-dir", str(root / "bundle"),
                                     "--version", "1.0", "--output", str(output)],
                                    capture_output=True, text=True,
                                    env=os.environ | {"PATH": f"{tools}:{os.environ['PATH']}",
                                                      "RACE_SOURCE": str(source_plugin),
                                                      "RACE_INFO": str(app.parent / "Info.plist"),
                                                      "CAPTURED_PLUGIN": str(captured)})
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual(source_plugin.read_bytes(), b"mutated source bytes")
            self.assertEqual((app.parent / "Info.plist").read_bytes(), b"mutated source plist")
            self.assertEqual(captured.read_bytes(), b"original staged bytes")

    def _bundle_fixture(self, root: Path, productbuild: str) -> tuple[Path, dict[str, str]]:
        app = root / "bundle/YuzuAgent.app/Contents/MacOS"
        app.mkdir(parents=True)
        (app / "yuzu-agent").write_text("#!/bin/sh\nexit 0\n")
        (app / "yuzu-agent").chmod(0o755)
        with (app.parent / "Info.plist").open("wb") as output:
            plistlib.dump({"CFBundleShortVersionString": "1.0"}, output)
        (root / "bundle/plugins").mkdir()
        (root / "bundle/plugins/tar.dylib").write_bytes(b"plugin")   # no plugin-signing-policy.json
        tools = root / "tools"
        tools.mkdir()
        for name, body in {
            "codesign": "#!/bin/sh\nexit 0\n",
            "lipo": "#!/bin/sh\necho arm64\n",
            "pkgbuild": "#!/bin/sh\nfor last; do :; done\n: > \"$last\"\n",
            "productbuild": productbuild,
        }.items():
            (tools / name).write_text(body)
            (tools / name).chmod(0o755)
        return root / "dist", os.environ | {"PATH": f"{tools}:{os.environ['PATH']}"}

    @macos_userland
    def test_policy_free_bundle_package_is_built_under_the_stock_shell(self) -> None:
        # PR #4482 review: an empty POLICY_ARGS tripped `set -u` on bash 3.2 and the
        # EXIT trap turned the abort into exit 0 with no package written.
        with tempfile.TemporaryDirectory(prefix="yuzu_test_macos_nopolicy_") as temporary:
            output, env = self._bundle_fixture(Path(temporary), "#!/bin/sh\nfor last; do :; done\n: > \"$last\"\n")
            result = subprocess.run([PKG_SHELL, str(BUILD_PKG), "--bundle-dir", str(Path(temporary) / "bundle"),
                                     "--version", "1.0", "--output", str(output)],
                                    capture_output=True, text=True, env=env)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertNotIn("unbound variable", result.stderr)
            self.assertTrue((output / "YuzuAgent-1.0-macos-arm64.pkg").is_file())

    @macos_userland
    def test_builder_fails_when_no_package_was_written(self) -> None:
        # A tool that exits 0 without producing the artifact, or a stale artifact from an
        # earlier run, must never be reported as a successful build.
        with tempfile.TemporaryDirectory(prefix="yuzu_test_macos_nopkg_") as temporary:
            output, env = self._bundle_fixture(Path(temporary), "#!/bin/sh\nexit 0\n")
            output.mkdir()
            (output / "YuzuAgent-1.0-macos-arm64.pkg").write_text("stale from an earlier run")
            result = subprocess.run([PKG_SHELL, str(BUILD_PKG), "--bundle-dir", str(Path(temporary) / "bundle"),
                                     "--version", "1.0", "--output", str(output)],
                                    capture_output=True, text=True, env=env)
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("did not write", result.stderr)

    def test_builder_refuses_a_populated_output_before_touching_inputs(self) -> None:
        with tempfile.TemporaryDirectory(prefix="yuzu_test_macos_bundle_") as temporary:
            output = Path(temporary) / "published"
            output.mkdir()
            sentinel = output / "keep"
            sentinel.write_text("unchanged")
            args = type("Args", (), {
                "bin_dir": str(Path(temporary) / "missing-bin"),
                "profile": str(Path(temporary) / "missing-profile"),
                "output_dir": str(output),
                "bundle_id": "com.example.yuzu",
                "sign_identity": "unused",
                "version": "1.0",
                "final_plugin_sig_dir": None,
            })()
            with self.assertRaisesRegex(bundle.BundleError, "already exists and is populated"):
                bundle.build(args)
            self.assertEqual(sentinel.read_text(), "unchanged")

    def test_otool_dependency_parser_excludes_an_id_by_load_command_type(self) -> None:
        output = (
            "libyuzu_agent_core.dylib:\n"
            "Load command 4\n"
            "          cmd LC_ID_DYLIB\n"
            "         name @rpath/libyuzu_agent_core.dylib (offset 24)\n"
            "Load command 12\n"
            "          cmd LC_LOAD_DYLIB\n"
            "         name /usr/lib/libSystem.B.dylib (offset 24)\n"
        )
        with mock.patch.object(bundle, "run", return_value=output):
            self.assertEqual(bundle.otool_dependencies(Path("libyuzu_agent_core.dylib")),
                             ["/usr/lib/libSystem.B.dylib"])

    def test_otool_dependency_parser_retains_all_real_dependency_kinds(self) -> None:
        output = (
            "yuzu-agent:\n"
            "Load command 14\n"
            "          cmd LC_LOAD_DYLIB\n"
            "         name @rpath/libyuzu_agent_core.dylib (offset 24)\n"
            "Load command 15\n"
            "          cmd LC_LOAD_WEAK_DYLIB\n"
            "         name @rpath/liboptional.dylib (offset 24)\n"
            "Load command 16\n"
            "          cmd LC_REEXPORT_DYLIB\n"
            "         name @rpath/libreexport.dylib (offset 24)\n"
            "Load command 17\n"
            "          cmd LC_LOAD_UPWARD_DYLIB\n"
            "         name @rpath/libupward.dylib (offset 24)\n"
            "Load command 18\n"
            "          cmd LC_LAZY_LOAD_DYLIB\n"
            "         name @rpath/liblazy.dylib (offset 24)\n"
        )
        with mock.patch.object(bundle, "run", return_value=output):
            self.assertEqual(bundle.otool_dependencies(Path("yuzu-agent")),
                             ["@rpath/libyuzu_agent_core.dylib", "@rpath/liboptional.dylib",
                              "@rpath/libreexport.dylib", "@rpath/libupward.dylib",
                              "@rpath/liblazy.dylib"])

    def test_bundle_plist_preserves_external_plugins_and_disables_ota(self) -> None:
        with tempfile.TemporaryDirectory(prefix="yuzu_test_macos_bundle_") as temporary:
            root = Path(temporary)
            destination = root / "output with spaces.plist"
            result = subprocess.run([sys.executable, str(PLIST_HELPER), "--source",
                                     str(ROOT / "deploy/packaging/macos/com.yuzu.agent.plist"), "--output",
                                     str(destination), "--bundle-executable", "/example/YuzuAgent.app/Contents/MacOS/yuzu-agent"],
                                    check=True, capture_output=True, text=True)
            self.assertEqual(result.returncode, 0)
            with destination.open("rb") as output:
                plist = plistlib.load(output)
            arguments = plist["ProgramArguments"]
            self.assertEqual(arguments[0], "/example/YuzuAgent.app/Contents/MacOS/yuzu-agent")
            self.assertIn("--plugin-dir", arguments)
            self.assertEqual(arguments[arguments.index("--plugin-dir") + 1], "/usr/local/lib/yuzu/plugins")
            self.assertIn("--no-auto-update", arguments)

    @unittest.skipUnless(sys.platform == "darwin", "native macOS plist integration")
    def test_bundle_upgrade_preserves_hardened_plugin_policy_and_server_settings(self) -> None:
        with tempfile.TemporaryDirectory(prefix="yuzu_test_macos_bundle_") as temporary:
            root = Path(temporary)
            previous, destination = root / "previous.plist", root / "new.plist"
            with previous.open("wb") as output:
                plistlib.dump({"ProgramArguments": ["/usr/local/bin/yuzu-agent", "--server",
                                                       "server.example:50051", "--plugin-trust-bundle",
                                                       "/etc/yuzu-agent/certs/plugins.pem",
                                                       "--plugin-require-signature", "--plugin-dir",
                                                       "/old/plugins"],
                                "EnvironmentVariables": {
                                    "YUZU_SERVER": "env-server.example:50051",
                                    "YUZU_TLS_SYSTEM_ROOTS": "1",
                                    "YUZU_PLUGIN_ALLOWLIST": "/etc/yuzu-agent/plugins.sha256",
                                    "YUZU_PLUGIN_TRUST_BUNDLE": "/etc/yuzu-agent/certs/env-plugins.pem",
                                    "YUZU_PLUGIN_REQUIRE_SIGNATURE": "1",
                                }}, output)
            subprocess.run([sys.executable, str(PLIST_HELPER), "--source",
                            str(ROOT / "deploy/packaging/macos/com.yuzu.agent.plist"), "--output",
                            str(destination), "--bundle-executable", "/bundle/yuzu-agent"], check=True)
            subprocess.run(["/usr/bin/osascript", "-l", "JavaScript", str(MERGE_PLIST_HELPER), "--previous", str(previous),
                            "--destination", str(destination)], check=True)
            with destination.open("rb") as output:
                merged = plistlib.load(output)["ProgramArguments"]
            self.assertEqual(merged[0], "/bundle/yuzu-agent")
            self.assertIn("--no-auto-update", merged)
            self.assertIn("--plugin-require-signature", merged)
            self.assertEqual(merged[merged.index("--plugin-trust-bundle") + 1],
                             "/etc/yuzu-agent/certs/plugins.pem")
            self.assertEqual(merged[merged.index("--server") + 1], "server.example:50051")
            self.assertEqual(merged[merged.index("--plugin-dir") + 1],
                             "/usr/local/lib/yuzu/plugins")
            with destination.open("rb") as output:
                environment = plistlib.load(output)["EnvironmentVariables"]
            self.assertEqual(environment, {
                "YUZU_SERVER": "env-server.example:50051", "YUZU_TLS_SYSTEM_ROOTS": "1",
                "YUZU_PLUGIN_ALLOWLIST": "/etc/yuzu-agent/plugins.sha256",
                "YUZU_PLUGIN_TRUST_BUNDLE": "/etc/yuzu-agent/certs/env-plugins.pem",
                "YUZU_PLUGIN_REQUIRE_SIGNATURE": "1",
            })

            policy = root / "plugin-policy.json"
            policy.write_text(json.dumps({"runtime_plugin_trust_bundle": "/etc/yuzu-agent/certs/new.pem"}))
            policy_destination = root / "policy.plist"
            subprocess.run([sys.executable, str(PLIST_HELPER), "--source",
                            str(ROOT / "deploy/packaging/macos/com.yuzu.agent.plist"), "--output",
                            str(policy_destination), "--bundle-executable", "/bundle/yuzu-agent",
                            "--plugin-signing-policy", str(policy)], check=True)
            subprocess.run(["/usr/bin/osascript", "-l", "JavaScript", str(MERGE_PLIST_HELPER), "--previous", str(previous),
                            "--destination", str(policy_destination)], check=True)
            with policy_destination.open("rb") as output:
                policy_plist = plistlib.load(output)
            self.assertEqual(policy_plist["EnvironmentVariables"], {
                "YUZU_SERVER": "env-server.example:50051", "YUZU_TLS_SYSTEM_ROOTS": "1",
                "YUZU_PLUGIN_ALLOWLIST": "/etc/yuzu-agent/plugins.sha256",
            })
            policy_arguments = policy_plist["ProgramArguments"]
            self.assertEqual(policy_arguments[policy_arguments.index("--plugin-trust-bundle") + 1],
                             "/etc/yuzu-agent/certs/new.pem")
            self.assertIn("--plugin-require-signature", policy_arguments)

    @unittest.skipUnless(sys.platform == "darwin", "native macOS plist integration")
    def test_legacy_upgrade_retains_operator_disabled_ota(self) -> None:
        with tempfile.TemporaryDirectory(prefix="yuzu_test_macos_bundle_") as temporary:
            root = Path(temporary)
            previous, destination = root / "previous.plist", root / "new.plist"
            with previous.open("wb") as output:
                plistlib.dump({"ProgramArguments": ["/usr/local/bin/yuzu-agent", "--no-auto-update"]}, output)
            with destination.open("wb") as output:
                plistlib.dump({"ProgramArguments": ["/usr/local/bin/yuzu-agent"]}, output)
            subprocess.run(["/usr/bin/osascript", "-l", "JavaScript", str(MERGE_PLIST_HELPER), "--previous", str(previous),
                            "--destination", str(destination)], check=True)
            with destination.open("rb") as output:
                self.assertIn("--no-auto-update", plistlib.load(output)["ProgramArguments"])
            with destination.open("wb") as output:
                plistlib.dump({"ProgramArguments": ["/usr/local/bin/yuzu-agent"]}, output)
            subprocess.run(["/usr/bin/osascript", "-l", "JavaScript", str(MERGE_PLIST_HELPER), "--previous", str(previous),
                            "--destination", str(destination), "--force-no-auto-update"], check=True)
            with destination.open("rb") as output:
                self.assertEqual(plistlib.load(output)["ProgramArguments"], ["/usr/local/bin/yuzu-agent"])

    def test_final_plugin_sidecars_use_the_shared_agent_verifier(self) -> None:
        with mock.patch.object(bundle, "run", return_value="") as run:
            bundle.verify_final_plugin_sidecar(Path("/bundle/yuzu-agent"), Path("/plugins/tar.dylib"),
                                               Path("/trust/plugins.pem"))
        run.assert_called_once_with([str(Path("/bundle/yuzu-agent")), "--verify-plugin-signature",
                                     str(Path("/plugins/tar.dylib")), "--plugin-trust-bundle",
                                     str(Path("/trust/plugins.pem"))])

    @unittest.skipUnless(sys.platform == "darwin", "native macOS archive/plist integration")
    def test_packaging_refuses_a_stale_cms_sidecar_before_publishing(self) -> None:
        with tempfile.TemporaryDirectory(prefix="yuzu_test_macos_bundle_") as temporary:
            root = Path(temporary)
            app = root / "bundle/YuzuAgent.app"
            executable = app / "Contents/MacOS/yuzu-agent"
            executable.parent.mkdir(parents=True)
            executable.write_text("#!/bin/sh\nexit 42\n")
            executable.chmod(0o755)
            with (app / "Contents/Info.plist").open("wb") as output:
                plistlib.dump({"CFBundleShortVersionString": "1.0"}, output)
            plugins = root / "bundle/plugins"
            plugins.mkdir()
            (plugins / "tar.dylib").write_bytes(b"stale-final-plugin-bytes")
            (plugins / "tar.dylib.sig").write_bytes(b"stale-sidecar")
            (plugins / "plugin-signing-policy.json").write_text(
                json.dumps({"runtime_plugin_trust_bundle": "/etc/yuzu-agent/certs/plugins.pem"}) + "\n")
            trust = root / "plugins.pem"
            trust.write_text("test trust material\n")
            tools = root / "tools"
            tools.mkdir()
            for name, body in {
                "codesign": "#!/bin/sh\nexit 0\n",
                "lipo": "#!/bin/sh\necho arm64\n",
                "pkgbuild": "#!/bin/sh\nexit 99\n",
                "productbuild": "#!/bin/sh\nexit 99\n",
            }.items():
                tool = tools / name
                tool.write_text(body)
                tool.chmod(0o755)
            environment = os.environ | {"PATH": f"{tools}:{os.environ['PATH']}"}
            output = root / "dist"
            result = subprocess.run([PKG_SHELL, str(BUILD_PKG), "--bundle-dir", str(root / "bundle"),
                                     "--version", "1.0", "--output", str(output),
                                     "--plugin-trust-bundle", str(trust)],
                                    capture_output=True, text=True, env=environment)
            self.assertEqual(result.returncode, 42, result.stderr)
            self.assertFalse((output / "YuzuAgent-1.0-macos-arm64.pkg").exists())

    @unittest.skipIf(os.name == "nt", "POSIX Bash fixture")
    def test_builder_rejects_ambiguous_lanes_before_invoking_macos_tools(self) -> None:
        result = subprocess.run([PKG_SHELL, str(BUILD_PKG), "--bin-dir", "x", "--bundle-dir", "y",
                                 "--version", "1.0"], capture_output=True, text=True)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("exactly one", result.stderr)

    # ── Governance uh-5: orphaned snapshots are collected, nothing else ────────
    @posix_shell
    def test_preinstall_collects_only_well_formed_orphan_snapshots(self) -> None:
        pre = (BUILD_PKG.parent / "preinstall").read_text()
        start = pre.index('for orphan in "$STATE_DIR"/install-recovery.*; do')
        loop = pre[start:pre.index("\ndone\n", start) + 6]
        self.assertLess(pre.index('if [[ -e "$RECOVERY_FILE" || -L "$RECOVERY_FILE" ]]; then'), start)
        self.assertLess(start, pre.index('RECOVERY="$(mktemp -d'))
        with tempfile.TemporaryDirectory(prefix="yuzu_test_orphans_") as temporary:
            root = Path(temporary)
            state = root / "state"
            for name in ("install-recovery.OLD/LaunchDaemons", "install-recovery.LOOSE_MODE", "quarantine/legacy-YuzuAgent.X"):
                (state / name).mkdir(parents=True)
            (state / "install-recovery.FILE").write_text("not a snapshot")
            (root / "elsewhere").mkdir()
            (root / "elsewhere/keep").write_text("kept")
            (state / "install-recovery.LINK").symlink_to(root / "elsewhere")
            result = self._installer_harness(root, "preinstall", ("require_recovery_directory",),
                                             loop + "echo DONE\n",
                                             modes={state / "install-recovery.OLD": 700,
                                                    state / "install-recovery.LINK": 700})
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertIn("DONE", result.stdout)
            self.assertFalse((state / "install-recovery.OLD").exists())
            for kept in ("install-recovery.LOOSE_MODE", "install-recovery.FILE", "quarantine/legacy-YuzuAgent.X"):
                self.assertTrue((state / kept).exists(), kept)
            self.assertTrue((state / "install-recovery.LINK").is_symlink())
            self.assertEqual((root / "elsewhere/keep").read_text(), "kept")

    # ── Governance sec-3: removal honours the recorded hash in every script ────
    @macos_userland
    def test_plugin_removal_keeps_an_operator_modified_listed_plugin(self) -> None:
        import hashlib
        for script in ("preinstall", "postinstall", "uninstall.sh"):
            with self.subTest(script=script), tempfile.TemporaryDirectory(prefix="yuzu_test_plugin_remove_") as temporary:
                root = Path(temporary)
                lib = root / "ul/lib/yuzu"
                plugins = lib / "plugins"
                plugins.mkdir(parents=True)
                manifest, hashes = lib / "package-files.list", lib / "package-files.sha256"

                def populate() -> None:
                    (plugins / "ours.dylib").write_bytes(b"package bytes")
                    (plugins / "ours.dylib.sig").write_bytes(b"sidecar")
                    (plugins / "theirs.dylib").write_bytes(b"operator rebuild")
                    (plugins / "third-party.dylib").write_bytes(b"never listed")

                populate()
                manifest.write_text("# package-version 1.0\nplugins/ours.dylib\nplugins/theirs.dylib\n")
                hashes.write_text(f"{hashlib.sha256(b'package bytes').hexdigest()}  plugins/ours.dylib\n"
                                  f"{hashlib.sha256(b'original package bytes').hexdigest()}  plugins/theirs.dylib\n")
                body = 'remove_managed_plugins "$MANIFEST" "$HASHES"\necho DONE\n'
                result = self._installer_harness(root, script, ("plugin_hash_matches", "remove_managed_plugins"), body)
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertIn("DONE", result.stdout)
                self.assertFalse((plugins / "ours.dylib").exists())
                self.assertFalse((plugins / "ours.dylib.sig").exists())
                self.assertEqual((plugins / "theirs.dylib").read_bytes(), b"operator rebuild")
                self.assertIn("kept", result.stderr)
                self.assertIn("theirs.dylib", result.stderr)
                self.assertEqual((plugins / "third-party.dylib").read_bytes(), b"never listed")
                # A package that recorded no hashes owned its files by name.
                hashes.unlink()
                populate()
                result = self._installer_harness(root, script, ("plugin_hash_matches", "remove_managed_plugins"), body)
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertFalse((plugins / "ours.dylib").exists())
                self.assertFalse((plugins / "theirs.dylib").exists())
                self.assertEqual((plugins / "third-party.dylib").read_bytes(), b"never listed")

    # ── Governance uh8-1: ownership is any package's record, not just the paired one ─
    @macos_userland
    def test_plugin_removal_accepts_any_package_hash_record(self) -> None:
        import hashlib
        def line(data: bytes, name: str) -> str:
            return f"{hashlib.sha256(data).hexdigest()}  plugins/{name}\n"
        for script in ("preinstall", "postinstall", "uninstall.sh"):
            with self.subTest(script=script), tempfile.TemporaryDirectory(prefix="yuzu_test_any_record_") as temporary:
                root = Path(temporary)
                lib = root / "ul/lib/yuzu"
                plugins = lib / "plugins"
                plugins.mkdir(parents=True)
                (plugins / "new.dylib").write_bytes(b"new package bytes")
                (plugins / "theirs.dylib").write_bytes(b"operator rebuild")
                (lib / "manifest").write_text("# package-version 2.0\nplugins/new.dylib\nplugins/theirs.dylib\n")
                (lib / "old.sha256").write_text(line(b"original", "theirs.dylib"))
                (lib / "new.sha256").write_text(line(b"new package bytes", "new.dylib") + line(b"new", "theirs.dylib"))
                body = ('remove_managed_plugins "$YUZU_LIB/manifest" "$YUZU_LIB/old.sha256" '
                        '"$YUZU_LIB/absent.sha256" "$YUZU_LIB/new.sha256"\necho DONE\n')
                result = self._installer_harness(root, script, ("plugin_hash_matches", "remove_managed_plugins"), body)
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertIn("DONE", result.stdout)
                # Matched only by the second record: removed.
                self.assertFalse((plugins / "new.dylib").exists())
                # Matched by none: kept, with the warning.
                self.assertEqual((plugins / "theirs.dylib").read_bytes(), b"operator rebuild")
                self.assertIn("kept", result.stderr)
                # No record exists at all: removed by name.
                (plugins / "new.dylib").write_bytes(b"anything")
                body = ('remove_managed_plugins "$YUZU_LIB/manifest" "$YUZU_LIB/absent.sha256"\necho DONE\n')
                result = self._installer_harness(root, script, ("plugin_hash_matches", "remove_managed_plugins"), body)
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertFalse((plugins / "new.dylib").exists())
                self.assertFalse((plugins / "theirs.dylib").exists())

    @macos_userland
    def test_recovery_in_the_manifest_hashes_window_removes_the_new_package_plugins(self) -> None:
        # uh8-1: promotion moved the new manifest but the new hashes had not yet
        # replaced the old ones. Recovery must still recognise the new package's
        # plugin, from the incoming record or from the snapshot's copy of it.
        import hashlib
        def line(data: bytes, name: str) -> str:
            return f"{hashlib.sha256(data).hexdigest()}  plugins/{name}\n"
        for script in ("postinstall", "preinstall"):
            for record in ("incoming", "snapshot copy"):
                with self.subTest(script=script, record=record), \
                        tempfile.TemporaryDirectory(prefix="yuzu_test_hash_window_") as temporary:
                    root = Path(temporary)
                    recovery = self._recovery_layout(root, was_running=False)
                    lib = root / "ul/lib/yuzu"
                    (lib / "plugins/new.dylib").write_bytes(b"new package bytes")
                    (lib / "package-files.list").write_text("# package-version 2.0\nplugins/new.dylib\n")
                    (lib / "package-files.sha256").write_text(line(b"old", "old.dylib"))
                    new_record = line(b"new package bytes", "new.dylib")
                    if record == "incoming":
                        (lib / ".package-files.sha256.incoming").write_text(new_record)
                    else:
                        (recovery / "incoming-package-files.sha256").write_text(new_record)
                    result = self._restore(root, script, recovery)
                    self.assertEqual(result.returncode, 0, result.stderr)
                    self.assertIn("RESTORED", result.stdout)
                    self.assertFalse((lib / "plugins/new.dylib").exists(), result.stderr)
                    self.assertNotIn("kept", result.stderr)

    @posix_shell
    def test_postinstall_keeps_the_new_hash_record_in_the_snapshot_before_promoting(self) -> None:
        post = (BUILD_PKG.parent / "postinstall").read_text()
        copy = 'ditto "$INCOMING_HASHES" "$recovery/incoming-package-files.sha256"'
        self.assertIn(copy, post)
        self.assertLess(post.index(copy), post.index("printf 'promoting\\n' > \"$recovery/.phase.new\""))
        self.assertLess(post.index(copy), post.index('mv "$INCOMING_MANIFEST" "$MANIFEST"'))

    # ── Governance rd-2: a manifest left behind by a rollback is re-derived ────
    @macos_userland
    def test_stale_manifest_after_a_rollback_is_re_derived(self) -> None:
        import hashlib
        pkgutil = '''pkgutil() {
    case "$1" in
        --pkg-info) [[ -n "${RECEIPT_VERSION:-}" ]] || return 1
                    printf 'package-id: com.yuzu.agent\\nversion: %s\\nvolume: /\\n' "$RECEIPT_VERSION" ;;
        --files) printf '%s\\n' usr/local/lib/yuzu/plugins/a.dylib usr/local/lib/yuzu/plugins/c.dylib usr/local/bin/yuzu-agent ;;
    esac
}
'''
        stale = "# package-version 2.0\nplugins/a.dylib\nplugins/b.dylib\nplugins/n.dylib\n"
        for receipt, rederived in (("1.0", True), ("2.0", False), ("", False), ("header-less", False)):
            with self.subTest(receipt=receipt), tempfile.TemporaryDirectory(prefix="yuzu_test_stale_manifest_") as temporary:
                root = Path(temporary)
                lib = root / "ul/lib/yuzu"
                (lib / "plugins").mkdir(parents=True)
                manifest, hashes = lib / "package-files.list", lib / "package-files.sha256"
                written = stale.split("\n", 1)[1] if receipt == "header-less" else stale
                manifest.write_text(written)
                # The rollback overwrote a.dylib with the older release's bytes and left
                # N-only n.dylib as N shipped it; b.dylib is gone.
                (lib / "plugins/a.dylib").write_bytes(b"release O")
                (lib / "plugins/n.dylib").write_bytes(b"release N only")
                hash_text = "".join(f"{hashlib.sha256(data).hexdigest()}  plugins/{name}\n" for name, data in
                                    (("a.dylib", b"release N"), ("b.dylib", b"b"), ("n.dylib", b"release N only")))
                hashes.write_text(hash_text)
                version = "1.0" if receipt == "header-less" else receipt
                result = self._installer_harness(
                    root, "preinstall", ("receipt_plugin_entries", "discard_stale_manifest"),
                    "discard_stale_manifest\necho DONE\n", stubs=f"RECEIPT_VERSION={version}\n" + pkgutil)
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertIn("DONE", result.stdout)
                if rederived:
                    self.assertEqual(manifest.read_text(), "plugins/a.dylib\nplugins/c.dylib\nplugins/n.dylib\n")
                    # uh8-4: the re-derived manifest and its hashes agree. Each listed,
                    # present plugin is recorded with the bytes now on disk; c.dylib is absent.
                    self.assertEqual(hashes.read_text(),
                                     f"{hashlib.sha256(b'release O').hexdigest()}  plugins/a.dylib\n"
                                     f"{hashlib.sha256(b'release N only').hexdigest()}  plugins/n.dylib\n")
                    self.assertIn("re-deriving plugin ownership", result.stderr)
                else:
                    self.assertEqual(manifest.read_text(), written)
                    self.assertEqual(hashes.read_text(), hash_text)
                for pattern in (".still-owned.*", ".rederived-manifest.*", ".rederived-hashes.*"):
                    self.assertEqual(list(lib.glob(pattern)), [], pattern)

    @macos_userland
    def test_stale_manifest_rederivation_interrupted_between_moves_converges(self) -> None:
        # uh8-4: the re-derived hashes move first. A stop before the manifest moves
        # leaves the stale, version-stamped manifest beside hashes that already
        # describe the bytes on disk; the next run re-derives again and ends in
        # the same agreeing pair.
        import hashlib
        pkgutil = ('pkgutil() { case "$1" in --pkg-info) printf \'version: 1.0\\n\' ;; '
                   '--files) printf \'%s\\n\' usr/local/lib/yuzu/plugins/a.dylib ;; esac; }\n')
        failing_second_mv = ('mv() { local n; n=$(cat "$YUZU_LIB/../mv.count" 2>/dev/null || echo 0); '
                             'echo $((n + 1)) > "$YUZU_LIB/../mv.count"; [[ "$n" != 1 ]] || return 1; command mv "$@"; }\n')
        with tempfile.TemporaryDirectory(prefix="yuzu_test_stale_interrupted_") as temporary:
            root = Path(temporary)
            lib = root / "ul/lib/yuzu"
            (lib / "plugins").mkdir(parents=True)
            manifest, hashes = lib / "package-files.list", lib / "package-files.sha256"
            manifest.write_text("# package-version 2.0\nplugins/a.dylib\nplugins/n.dylib\n")
            (lib / "plugins/a.dylib").write_bytes(b"release O")
            (lib / "plugins/n.dylib").write_bytes(b"release N only")
            hashes.write_text(f"{hashlib.sha256(b'release N').hexdigest()}  plugins/a.dylib\n"
                              f"{hashlib.sha256(b'release N only').hexdigest()}  plugins/n.dylib\n")
            names = ("receipt_plugin_entries", "discard_stale_manifest")
            first = self._installer_harness(root, "preinstall", names, "discard_stale_manifest\necho DONE\n",
                                            stubs=pkgutil + failing_second_mv)
            self.assertNotEqual(first.returncode, 0)
            self.assertNotIn("DONE", first.stdout)
            self.assertTrue(manifest.read_text().startswith("# package-version 2.0\n"))
            second = self._installer_harness(root, "preinstall", names, "discard_stale_manifest\necho DONE\n",
                                             stubs=pkgutil)
            self.assertEqual(second.returncode, 0, second.stderr)
            self.assertIn("re-deriving plugin ownership", second.stderr)
            self.assertEqual(manifest.read_text(), "plugins/a.dylib\nplugins/n.dylib\n")
            self.assertEqual(hashes.read_text(), f"{hashlib.sha256(b'release O').hexdigest()}  plugins/a.dylib\n"
                                                 f"{hashlib.sha256(b'release N only').hexdigest()}  plugins/n.dylib\n")

    @macos_userland
    def test_stale_manifest_rederivation_failure_leaves_no_temporary_file(self) -> None:
        # If the Installer receipt cannot be adopted, the refusal must not leak
        # its .still-owned temp file into /usr/local/lib/yuzu (g8ch, S11).
        pkgutil = ('pkgutil() { [[ "$1" == --pkg-info ]] || return 1; '
                   "printf 'package-id: com.yuzu.agent\\nversion: 1.0\\n'; }\n")
        with tempfile.TemporaryDirectory(prefix="yuzu_test_stale_leak_") as temporary:
            root = Path(temporary)
            lib = root / "ul/lib/yuzu"
            (lib / "plugins").mkdir(parents=True)
            (lib / "package-files.list").write_text("# package-version 2.0\nplugins/a.dylib\n")
            (lib / "package-files.sha256").write_text("stale hashes\n")
            result = self._installer_harness(
                root, "preinstall", ("discard_stale_manifest",), "discard_stale_manifest\necho DONE\n",
                stubs=pkgutil + 'receipt_plugin_entries() { echo "ERROR: unsafe receipt" >&2; return 1; }\n')
            self.assertNotEqual(result.returncode, 0)
            self.assertNotIn("DONE", result.stdout)
            self.assertIn("unsafe receipt", result.stderr)
            for pattern in (".still-owned.*", ".rederived-manifest.*", ".rederived-hashes.*"):
                self.assertEqual(list(lib.glob(pattern)), [], pattern)
            # Nothing was replaced: the stale pair stays for the next run to re-derive.
            self.assertEqual((lib / "package-files.list").read_text(), "# package-version 2.0\nplugins/a.dylib\n")
            self.assertEqual((lib / "package-files.sha256").read_text(), "stale hashes\n")

    # ── Governance g8ch-B1 / g8ch-L2: bootout returns before the job is gone ────
    @posix_shell
    def test_stop_service_waits_for_launchd_to_unload_the_job(self) -> None:
        # Measured on macOS 15: bootout returns in ~8 ms, the job leaves ~1.3 s later.
        # A counter-driven launchd answers `print` for the first `loaded` calls.
        def launchd(root: Path, loaded: int) -> str:
            return f"""launchctl() {{
    echo "$*" >> "{root}/launchctl.log"
    [[ "$1" == print ]] || return 0
    local n; n=$(cat "{root}/prints" 2>/dev/null || echo 0); echo $((n + 1)) > "{root}/prints"
    [[ "$n" -lt {loaded} ]] || return 113
}}
"""
        for script in ("preinstall", "postinstall", "uninstall.sh"):
            for loaded, stops in ((0, True), (1, True), (4, True), (61, True), (1000, False)):
                with self.subTest(script=script, loaded=loaded), \
                        tempfile.TemporaryDirectory(prefix="yuzu_test_stop_") as temporary:
                    root = Path(temporary)
                    result = self._installer_harness(
                        root, script, ("stop_service",),
                        "if stop_service; then echo STOPPED; else echo STILL_LOADED; fi\n",
                        stubs=launchd(root, loaded))
                    self.assertEqual(result.returncode, 0, result.stderr)
                    self.assertEqual(result.stdout.strip(), "STOPPED" if stops else "STILL_LOADED")
                    log = self._launchctl_log(root)
                    self.assertEqual(log.count("bootout system/com.yuzu.agent"), 1 if loaded else 0)
                    prints = int((root / "prints").read_text())
                    # One probe, then one poll per 0.5 s for at most 60 polls (30 s).
                    self.assertEqual(prints, min(loaded, 61) + 1 if stops else 62)
        with tempfile.TemporaryDirectory(prefix="yuzu_test_stop_refuse_") as temporary:
            root = Path(temporary)
            result = self._installer_harness(root, "postinstall", ("stop_service", "require_stopped"),
                                             "require_stopped\necho PROCEEDED\n", stubs=launchd(root, 1000))
            self.assertNotEqual(result.returncode, 0)
            self.assertNotIn("PROCEEDED", result.stdout)
            self.assertIn("did not unload within 30 seconds", result.stderr)

    # ── Governance G8-S7: an access-control list is a write grant mode bits miss ─
    @macos_userland
    def test_acl_write_grants_are_refused_and_stripped(self) -> None:
        for script in ("preinstall", "postinstall"):
            with self.subTest(script=script), tempfile.TemporaryDirectory(prefix="yuzu_test_acl_") as temporary:
                root = Path(temporary)
                ul = root / "ul"
                levels = [ul, ul / "lib", ul / "lib/yuzu", ul / "bin"]
                for level in levels:
                    level.mkdir(parents=True, exist_ok=True)
                    level.chmod(0o755)
                try:
                    self._acl_cases(root, script, ul, levels)
                finally:
                    # A failed assertion must not leave a deny ACL that stops the
                    # temporary directory from being removed.
                    subprocess.run(["chmod", "-RN", str(ul)], capture_output=True)
        # Hardening strips an ACL from promoted code (chmod go-w alone leaves it).
        with tempfile.TemporaryDirectory(prefix="yuzu_test_acl_harden_") as temporary:
            root = Path(temporary)
            plugins = root / "ul/lib/yuzu/plugins"
            plugins.mkdir(parents=True)
            (plugins / "x.dylib").write_text("plugin")
            (plugins / "x.dylib.sig").write_text("sidecar")
            for name in ("x.dylib", "x.dylib.sig"):
                subprocess.run(["chmod", "+a", "everyone allow write,append", str(plugins / name)], check=True)
            (root / "ul/lib/yuzu/package-files.list").write_text("plugins/x.dylib\n")
            result = self._installer_harness(root, "postinstall",
                                             ("plugin_hash_matches", "harden_managed_plugins"),
                                             'harden_managed_plugins "$MANIFEST"\necho HARDENED\n')
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertIn("HARDENED", result.stdout)
            for name in ("x.dylib", "x.dylib.sig"):
                listing = subprocess.run(["/bin/ls", "-le", str(plugins / name)], capture_output=True, text=True).stdout
                self.assertNotRegex(listing, r"(?m)^ *\d+: ", name)


    def _acl_cases(self, root: Path, script: str, ul: Path, levels: list) -> None:
        def chain(lane: str) -> str:
            result = self._installer_harness(
                root, script, ("acl_grants_write", "code_directory_chain_trusted"),
                f"if code_directory_chain_trusted {lane}; then echo TRUSTED; else echo REFUSED; fi\n",
                real_modes=True)
            self.assertEqual(result.returncode, 0, result.stderr)
            return result.stdout.strip()

        self.assertEqual((chain("bundle"), chain("loose")), ("TRUSTED", "TRUSTED"))
        for level in levels:
            in_both = level != ul / "bin"
            subprocess.run(["chmod", "+a", "everyone allow add_file,add_subdirectory", str(level)], check=True)
            self.assertEqual((chain("bundle"), chain("loose")),
                             ("REFUSED" if in_both else "TRUSTED", "REFUSED"), f"allow ACL on {level}")
            subprocess.run(["chmod", "-N", str(level)], check=True)
            # Deny entries name write permissions too; only an allow is a grant.
            subprocess.run(["chmod", "+a", "everyone deny add_file,add_subdirectory,delete_child,writeattr",
                            str(level)], check=True)
            self.assertEqual((chain("bundle"), chain("loose")), ("TRUSTED", "TRUSTED"),
                             f"deny-only ACL on {level}")
            subprocess.run(["chmod", "-N", str(level)], check=True)

        # Entries: a /usr/local/bin entry the (stubbed) owner and mode checks
        # pass, the plugin directory itself (find's -mindepth 1 never lists it)
        # and a plugin file, each flagged only by its ACL.
        plugins = ul / "lib/yuzu/plugins"
        plugins.mkdir()
        agent = ul / "bin/yuzu-agent"
        agent.write_text("agent")
        agent.chmod(0o755)
        plugin = plugins / "acl.dylib"
        plugin.write_text("plugin")
        plugin.chmod(0o644)
        subprocess.run(["chmod", "+a", "everyone allow write,append", str(agent)], check=True)
        subprocess.run(["chmod", "+a", "everyone allow write", str(plugin)], check=True)
        subprocess.run(["chmod", "+a", "everyone allow add_file", str(plugins)], check=True)
        result = self._installer_harness(root, script, ("acl_grants_write", "reject_untrusted_code_entries"),
                                         "reject_untrusted_code_entries\necho ACCEPTED\n", real_modes=True)
        self.assertNotEqual(result.returncode, 0)
        self.assertNotIn("ACCEPTED", result.stdout)
        listed = {line.strip() for line in result.stderr.splitlines() if line.startswith("         /")}
        acl = " (access control list grants write)"
        self.assertIn(str(agent), listed)
        self.assertIn(str(plugins) + acl, listed)
        self.assertIn(str(plugin) + acl, listed)
        self.assertNotIn(str(plugins / "missing") + acl, listed)

    # ── Governance rd-r2-1: an interrupted O→N install leaves a prepared snapshot ──
    @posix_shell
    def test_prepared_snapshot_restores_missing_live_files_before_it_is_discarded(self) -> None:
        with tempfile.TemporaryDirectory(prefix="yuzu_test_prepared_restore_") as temporary:
            root = Path(temporary)
            recovery = self._recovery_layout(root, phase="prepared", loose=True)
            (recovery / "yuzu/plugins").mkdir(parents=True)
            (recovery / "yuzu/plugins/a.dylib").write_text("snapshot a")
            (recovery / "yuzu/plugins/b.dylib").write_text("snapshot b")
            (recovery / "package-files.list").write_text("plugins/a.dylib\nplugins/b.dylib\n")
            # Installer removed the old receipt's live files; only b.dylib and a newer
            # plist remain. Nothing may be overwritten.
            (root / "LaunchDaemons/com.yuzu.agent.plist").write_text("live definition")
            (root / "ul/lib/yuzu/plugins/b.dylib").write_text("live b")
            result = self._run_recovery_block(root, stub_recovery=False)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertIn("PROCEEDED", result.stdout)
            self.assertEqual((root / "ul/bin/yuzu-agent").read_text(), "previous loose agent")
            self.assertEqual((root / "ul/lib/yuzu/plugins/a.dylib").read_text(), "snapshot a")
            self.assertEqual((root / "ul/lib/yuzu/plugins/b.dylib").read_text(), "live b")
            self.assertEqual((root / "LaunchDaemons/com.yuzu.agent.plist").read_text(), "live definition")
            self.assertEqual((root / "ul/lib/yuzu/package-files.list").read_text(), "plugins/a.dylib\nplugins/b.dylib\n")
            self.assertFalse((root / "state/current-recovery").exists())
            self.assertFalse(recovery.exists())
            # A prepared snapshot is never a reason to touch launchd.
            self.assertEqual(self._launchctl_log(root), "")

    # ── Governance rd-r2-3: configuration directories are checked before the payload ──
    def _configuration_check(self) -> str:
        pre = (BUILD_PKG.parent / "preinstall").read_text()
        start = pre.index("for configuration_dir in /private/etc/yuzu-agent")
        return pre[start:pre.index("done\n", start) + len("done\n")]

    @macos_userland
    def test_preinstall_refuses_untrusted_configuration_directories_before_the_payload(self) -> None:
        pre = (BUILD_PKG.parent / "preinstall").read_text()
        check = self._configuration_check()
        self.assertLess(pre.index(check), pre.index('secure_payload_parent "$APP_ROOT" 755\n'))
        self.assertLess(pre.index(check), pre.index('\nRECOVERY="$(mktemp'))
        for case, mode, owner, accepted in (("absent", None, 0, True), ("root 755", 0o755, 0, True),
                                            ("group-writable", 0o775, 0, False),
                                            ("another owner", 0o755, 501, False)):
            with self.subTest(case=case), tempfile.TemporaryDirectory(prefix="yuzu_test_config_dir_") as temporary:
                root = Path(temporary)
                etc = root / "etc"
                etc.mkdir()
                etc.chmod(0o755)
                config = etc / "yuzu-agent"
                owners = {}
                if mode is not None:
                    (config / "certs").mkdir(parents=True)
                    for path in (config, config / "certs"):
                        path.chmod(0o755)
                    (config / "certs").chmod(mode)
                    owners = {config / "certs": owner}
                body = check.replace("/private/etc", str(etc)) + "echo ACCEPTED\n"
                result = self._installer_harness(root, "preinstall", ("require_trusted_directory",), body,
                                                 owners=owners, real_modes=True)
                self.assertEqual("ACCEPTED" in result.stdout, accepted, result.stderr)
                self.assertEqual(result.returncode == 0, accepted, result.stderr)
                if not accepted:
                    self.assertIn(str(config / "certs"), result.stderr)

    # ── Governance hp-1 / sre-2 / hp-2: the postinstall start decision ─────────
    def _write_plist(self, path: Path, arguments: list[str] | None = None, environment: dict | None = None) -> None:
        plist = plistlib.loads((BUILD_PKG.parent / "com.yuzu.agent.plist").read_bytes())
        plist["ProgramArguments"] = plist["ProgramArguments"] + (arguments or [])
        if environment:
            plist["EnvironmentVariables"] = environment
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(plistlib.dumps(plist))

    @macos_userland
    def test_service_definition_configured_requires_a_trust_anchor(self) -> None:
        cases = (([], None, False, False), (["--server", "s:50051"], {"YUZU_SERVER": "s:50051"}, False, False),
                 (["--ca-cert", "/etc/ca.pem"], None, False, True), (["--ca-cert=/etc/ca.pem"], None, False, True),
                 (["--tls-system-roots"], None, False, True), (["--no-tls"], None, False, True),
                 ([], {"YUZU_CA_CERT": "/etc/ca.pem"}, False, True), ([], {"YUZU_TLS_SYSTEM_ROOTS": "1"}, False, True),
                 # As the agent reads them (xp-18): env_truthy, and a non-empty CA path.
                 ([], {"YUZU_TLS_SYSTEM_ROOTS": "TRUE"}, False, True), ([], {"YUZU_TLS_SYSTEM_ROOTS": "on"}, False, True),
                 ([], {"YUZU_TLS_SYSTEM_ROOTS": "0"}, False, False), ([], {"YUZU_TLS_SYSTEM_ROOTS": "false"}, False, False),
                 ([], {"YUZU_CA_CERT": ""}, False, False), ([], {"YUZU_CA_CERT": "  "}, False, False),
                 ([], None, True, True))
        for arguments, environment, default_ca, configured in cases:
            with self.subTest(arguments=arguments, environment=environment, default_ca=default_ca), \
                    tempfile.TemporaryDirectory(prefix="yuzu_test_configured_") as temporary:
                root = Path(temporary)
                self._write_plist(root / "LaunchDaemons/com.yuzu.agent.plist", arguments, environment)
                if default_ca:
                    (root / "etc").mkdir()
                    (root / "etc/default-ca.pem").write_text("ca")
                result = self._installer_harness(
                    root, "postinstall", ("service_definition_configured",),
                    'if service_definition_configured "$PLIST"; then echo CONFIGURED; else echo UNCONFIGURED; fi\n',
                    plist="real")
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertEqual(result.stdout.strip(), "CONFIGURED" if configured else "UNCONFIGURED")

    @posix_shell
    def test_service_state_probes_read_launchd_exactly(self) -> None:
        # "Was running" = the same pid across two observations (xp-17): an agent
        # launchd keeps restarting is momentarily running with a new pid each time.
        for states, running in (((RUNNING, RUNNING), True),
                                (("state = running\n\tpid = 7\n", "state = running\n\tpid = 7\n"), True),
                                ((RUNNING, "state = running\npid = 4343\n"), False),
                                ((RUNNING, "state = spawn scheduled\n"), False),
                                (("state = running\n", "state = running\n"), False),
                                (("state = not running\n",), False), (("state = waiting\n",), False), ((None,), False)):
            with self.subTest(states=states), tempfile.TemporaryDirectory(prefix="yuzu_test_running_") as temporary:
                root = Path(temporary)
                for index, state in enumerate(states):
                    if state is not None:
                        (root / f"launchctl.state.{index}").write_text(state)
                sequence = f'''launchctl() {{
    local n; n=$(cat "{root}/launchctl.calls" 2>/dev/null || echo 0); echo $((n + 1)) > "{root}/launchctl.calls"
    [[ -f "{root}/launchctl.state.$n" ]] || return 113; cat "{root}/launchctl.state.$n"
}}
'''
                result = self._installer_harness(root, "postinstall", ("service_pid", "service_running_stably"),
                                                 sequence + "if service_running_stably; then echo RUNNING; else echo STOPPED; fi\n")
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertEqual(result.stdout.strip(), "RUNNING" if running else "STOPPED")
        for overrides, disabled in (('\t"com.yuzu.agent" => disabled\n', True), ('\t"com.yuzu.agent" => true\n', True),
                                    ('\t"com.yuzu.agent" => enabled\n', False), ('\t"com.yuzu.agent" => false\n', False),
                                    ('\t"com.yuzu.agentx" => disabled\n', False), ("", False)):
            with self.subTest(overrides=overrides), tempfile.TemporaryDirectory(prefix="yuzu_test_disabled_") as temporary:
                root = Path(temporary)
                (root / "launchctl.disabled").write_text("disabled services = {\n" + overrides + "}\n")
                result = self._installer_harness(root, "postinstall", ("service_disabled",),
                                                 "if service_disabled; then echo DISABLED; else echo ENABLED; fi\n")
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertEqual(result.stdout.strip(), "DISABLED" if disabled else "ENABLED")

    @macos_userland
    def test_install_starts_only_what_it_should(self) -> None:
        # The real start-decision block. A fresh install of the stock package must not
        # be rolled back for an agent that exits until it is configured (hp-1); an
        # administrator-disabled service is respected (sre-2); a previously running
        # service is health-gated (a failure exits, and the EXIT trap restores).
        post = (BUILD_PKG.parent / "postinstall").read_text()
        block = post[post.index("# Start decision."):post.index("# The previous development bundle lived below")]
        cases = {
            "running before, healthy": (True, RUNNING, "", ["--no-tls"], True, "installed and started", True),
            "running before, unhealthy": (True, "state = not running\n", "", ["--no-tls"], True, None, False),
            # g8ch-M1: the merge fell back to the unconfigured default; never health-gated.
            "running before, settings lost": (True, RUNNING, "", [], False,
                                              "NOT started: the previous service definition could not be read", True),
            # g8ch-i5: enabled to restart, then the administrator's override is put back.
            "running and disabled": (True, RUNNING, '"com.yuzu.agent" => disabled', ["--no-tls"], True,
                                     "installed and started", True),
            "disabled by administrator": (False, RUNNING, '"com.yuzu.agent" => disabled', ["--ca-cert", "/c"], False,
                                          "disabled by an administrator", True),
            "configured, healthy": (False, RUNNING, "", ["--ca-cert", "/c"], True, "installed and started", True),
            "configured, unhealthy": (False, "state = not running\n", "", ["--no-tls"], True,
                                      "did not stay running", True),
            "fresh, unconfigured": (False, "state = not running\n", "", [], False,
                                    "not started: no server trust anchor", True),
            # con8-2: the merge reported an unreadable definition; even a trust anchor
            # the default definition finds (here --no-tls stands in for default-ca.pem)
            # must not health-gate and start it against the default server.
            "running before, definition lost but configured": (True, RUNNING, "", ["--no-tls"], False,
                                                              "NOT started: the previous service definition could not be read",
                                                              True),
        }
        for name, (was_running, state, disabled, arguments, bootstraps, outcome, succeeds) in cases.items():
            lost = 1 if "definition lost" in name else 0
            with self.subTest(case=name), tempfile.TemporaryDirectory(prefix="yuzu_test_start_") as temporary:
                root = Path(temporary)
                recovery = self._recovery_layout(root, was_running=was_running)
                self._write_plist(root / "LaunchDaemons/com.yuzu.agent.plist", arguments)
                (root / "launchctl.state").write_text(state)
                (root / "launchctl.disabled").write_text("disabled services = {\n\t" + disabled + "\n}\n")
                result = self._installer_harness(
                    root, "postinstall", ("require_started", "service_disabled", "service_definition_configured"),
                    f'recovery="{recovery}"\nprior_definition_lost={lost}\n' + block + 'echo "OUTCOME=$outcome"\n',
                    plist="real")
                self.assertEqual(result.returncode == 0, succeeds, result.stderr)
                log = self._launchctl_log(root)
                self.assertEqual("bootstrap system" in log, bootstraps, log)
                self.assertEqual("enable system/com.yuzu.agent" in log, was_running and bootstraps, log)
                if was_running and bootstraps:
                    self.assertLess(log.index("enable system/com.yuzu.agent"), log.index("bootstrap system"))
                if was_running and disabled and succeeds:
                    self.assertIn("\ndisable system/com.yuzu.agent", log)
                    self.assertLess(log.index("bootstrap system"), log.index("\ndisable system/com.yuzu.agent"))
                else:
                    self.assertNotIn("\ndisable system/com.yuzu.agent", log)
                if outcome is None:
                    self.assertNotIn("OUTCOME=", result.stdout)
                else:
                    self.assertIn(outcome, result.stdout)

    # ── Governance pd-1: retained signature enforcement vs unsigned plugins ────
    @macos_userland
    def test_unsigned_plugins_are_refused_when_signatures_will_be_required(self) -> None:
        # CLI11's reading (g8b-3): a bare flag is on; =VALUE and the env var are off
        # for 0/false/off/no/empty, on otherwise; the command line overrides the env.
        cases = (([], None, False, True), (["--plugin-require-signature"], None, False, False),
                 (["--plugin-require-signature"], None, True, True),
                 ([], {"YUZU_PLUGIN_REQUIRE_SIGNATURE": "1"}, False, False),
                 ([], {"YUZU_PLUGIN_REQUIRE_SIGNATURE": "TRUE"}, False, False),
                 ([], {"YUZU_PLUGIN_REQUIRE_SIGNATURE": "0"}, False, True),
                 ([], {"YUZU_PLUGIN_REQUIRE_SIGNATURE": "Off"}, False, True),
                 ([], {"YUZU_PLUGIN_REQUIRE_SIGNATURE": ""}, False, True),
                 (["--plugin-require-signature=false"], None, False, True),
                 (["--plugin-require-signature=yes"], None, False, False),
                 (["--plugin-require-signature=false"], {"YUZU_PLUGIN_REQUIRE_SIGNATURE": "1"}, False, True),
                 (["--plugin-require-signature=false", "--plugin-require-signature"], None, False, False),
                 ([], {"YUZU_PLUGIN_TRUST_BUNDLE": "/t.pem"}, False, True))
        for arguments, environment, signed, accepted in cases:
            with self.subTest(arguments=arguments, environment=environment, signed=signed), \
                    tempfile.TemporaryDirectory(prefix="yuzu_test_unsigned_") as temporary:
                root = Path(temporary)
                self._write_plist(root / "LaunchDaemons/.com.yuzu.agent.incoming.plist", arguments, environment)
                incoming = root / "ul/lib/yuzu/.plugins.incoming"
                incoming.mkdir(parents=True)
                (incoming / "tar.dylib").write_bytes(b"plugin")
                if signed:
                    (incoming / "tar.dylib.sig").write_bytes(b"sidecar")
                result = self._installer_harness(
                    root, "postinstall",
                    ("cli11_flag_value_enabled", "plugin_signatures_required_by",
                     "service_definition_requires_plugin_signatures", "reject_unsigned_plugins_under_enforcement"),
                    "reject_unsigned_plugins_under_enforcement\necho ACCEPTED\n", plist="real")
                self.assertEqual(result.returncode == 0, accepted, result.stderr)
                self.assertEqual("ACCEPTED" in result.stdout, accepted)
                if not accepted:
                    self.assertIn("tar.dylib has no signature", result.stderr)

    # ── Governance er-2: every operator YUZU_* setting survives an upgrade ─────
    @unittest.skipUnless(sys.platform == "darwin", "native macOS plist integration")
    def test_plist_merge_retains_every_operator_yuzu_setting(self) -> None:
        with tempfile.TemporaryDirectory(prefix="yuzu_test_plist_env_") as temporary:
            root = Path(temporary)
            previous, destination = root / "previous.plist", root / "new.plist"
            operator = {
                "YUZU_UPDATE_TRUST_BUNDLE": "/etc/yuzu-agent/certs/update.pem",
                "YUZU_UPDATE_REQUIRE_SIGNATURE": "1",
                "YUZU_AGENT_INVENTORY_DISABLE": "1",
                "YUZU_AGENT_LICENSE_SCAN_USER_REF": "omit",
                "HTTPS_PROXY": "http://proxy.example:3128",
            }
            previous.write_bytes(plistlib.dumps({
                "ProgramArguments": ["/usr/local/bin/yuzu-agent", "--server", "s:50051"],
                "EnvironmentVariables": {**operator, "DYLD_INSERT_LIBRARIES": "/tmp/inject.dylib",
                                         "YUZU_DATA_DIR": "/tmp/elsewhere"}}))
            self._write_plist(destination)
            result = subprocess.run(["/usr/bin/osascript", "-l", "JavaScript", str(MERGE_PLIST_HELPER),
                                     "--previous", str(previous), "--destination", str(destination)],
                                    text=True, capture_output=True)
            self.assertEqual(result.returncode, 0, result.stderr)
            merged = plistlib.loads(destination.read_bytes())
            self.assertEqual(merged["EnvironmentVariables"], operator)
            self.assertIn("not retaining DYLD_INSERT_LIBRARIES", result.stderr)
            self.assertIn("not retaining YUZU_DATA_DIR", result.stderr)
            self.assertEqual(merged["ProgramArguments"][-2:], ["--server", "s:50051"])

    # ── Governance ch-3: one transition at a time; uninstall clears recovery ───
    def test_installer_scripts_take_the_transition_lock_first(self) -> None:
        guard = ('if [[ "${YUZU_PKG_TRANSITION_LOCKED:-}" != 1 ]]; then\n')
        # uh8-6: the lock is held on this shell's own descriptor; the wrapper form
        # is only the fallback for a lockf without the descriptor form.
        descriptor = '    exec 9>>"$TRANSITION_LOCK"\n    lock_status=0\n    /usr/bin/lockf -s -t 120 9 2>/dev/null || lock_status=$?\n'
        execute = ('        exec /usr/bin/lockf -k -t 120 "$TRANSITION_LOCK" \\\n'
                   '            /usr/bin/env YUZU_PKG_TRANSITION_LOCKED=1 /bin/bash "$0" "$@"\n    fi\nfi\n')
        for name in ("preinstall", "postinstall", "uninstall.sh"):
            source = (BUILD_PKG.parent / name).read_text()
            self.assertIn(guard, source, name)
            self.assertIn(descriptor, source, name)
            self.assertIn(execute, source, name)
            first_work = min(source.index(marker) for marker in ("PLIST=", "DATA_DIR=") if marker in source)
            self.assertLess(source.index(descriptor), source.index(execute), name)
            self.assertLess(source.index(execute), first_work, name)
            # PATH is pinned before anything runs (G8-S4).
            self.assertLess(source.index("PATH=/usr/bin:/bin:/usr/sbin:/sbin\nexport PATH\n"), source.index(guard), name)
            self.assertIn("TRANSITION_LOCK=/var/db/.yuzu-agent-transition.lock\n", source, name)
        uninstall = (BUILD_PKG.parent / "uninstall.sh").read_text()
        self.assertIn("ensure_state_dir\nclear_recovery_state\nstop_service ||", uninstall)

    @posix_shell
    def test_uninstall_clears_recovery_state_pointer_first_and_keeps_the_quarantine(self) -> None:
        sync = ('sync() { local p=absent s=absent; [[ -e "$RECOVERY_FILE" ]] && p=present; '
                'compgen -G "$STATE_DIR/install-recovery.*" >/dev/null && s=present; '
                'echo "pointer=$p snapshot=$s" >> "$STATE_DIR/../sync.log"; }\n')
        with tempfile.TemporaryDirectory(prefix="yuzu_test_uninstall_state_") as temporary:
            root = Path(temporary)
            state = root / "state"
            for name in ("install-recovery.A/LaunchDaemons", "install-recovery.B", "uninstall-legacy.C",
                         "quarantine/legacy-YuzuAgent.Q/YuzuAgent.app"):
                (state / name).mkdir(parents=True)
            (state / "current-recovery").write_text(f"{state}/install-recovery.A\n")
            (state / "current-recovery.new").write_text("torn")
            result = self._installer_harness(root, "uninstall.sh", ("clear_recovery_state",),
                                             "clear_recovery_state\necho DONE\n", stubs=sync)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertIn("DONE", result.stdout)
            self.assertEqual((root / "sync.log").read_text().splitlines(), ["pointer=absent snapshot=present"])
            self.assertEqual(sorted(path.name for path in state.iterdir()), ["quarantine"])
            self.assertTrue((state / "quarantine/legacy-YuzuAgent.Q/YuzuAgent.app").is_dir())

    # ── Governance G8-S2 / uh8-6: the transition lock ──────────────────────────
    _WRAPPER = ('        exec /usr/bin/lockf -k -t 120 "$TRANSITION_LOCK" \\\n'
                '            /usr/bin/env YUZU_PKG_TRANSITION_LOCKED=1 /bin/bash "$0" "$@"\n')

    def _lock_preamble(self, name: str, lock: Path) -> str:
        """The script's real lock preamble against a fixture lock path; lockf is
        resolved through PATH (a test may define a function), the wrapper re-exec
        reports WRAPPER instead of re-running the script, and LOCKED marks falling
        through with the lock held on fd 9."""
        source = (BUILD_PKG.parent / name).read_text()
        start = source.index("TRANSITION_LOCK=/var/db/.yuzu-agent-transition.lock\n")
        tail = '/bin/bash "$0" "$@"\n    fi\nfi\n'
        preamble = source[start:source.index(tail, start) + len(tail)]
        self.assertIn(self._WRAPPER, preamble, name)
        preamble = (preamble.replace(self._WRAPPER, '        echo WRAPPER; exit 0\n')
                    .replace("/usr/bin/lockf -s -t 120 9", "lockf -s -t 120 9")
                    .replace("TRANSITION_LOCK=/var/db/.yuzu-agent-transition.lock",
                             f"TRANSITION_LOCK={shlex.quote(str(lock))}"))
        return preamble + "echo LOCKED\n"

    def _run_lock(self, script: str) -> subprocess.CompletedProcess:
        env = {key: value for key, value in os.environ.items() if key != "YUZU_PKG_TRANSITION_LOCKED"}
        return subprocess.run([PKG_SHELL, "-c", PREAMBLE + "umask 022\n" + script],
                              text=True, capture_output=True, env=env)

    @posix_shell
    def test_transition_lock_is_created_owner_only_and_never_followed(self) -> None:
        # Off macOS there is no lockf; the descriptor form is stubbed as granted.
        lockf = "" if sys.platform == "darwin" else "lockf() { return 0; }\n"
        for name in ("preinstall", "postinstall", "uninstall.sh"):
            for case in ("absent", "world-readable", "symlink"):
                with self.subTest(script=name, case=case), \
                        tempfile.TemporaryDirectory(prefix="yuzu_test_lock_") as temporary:
                    root = Path(temporary)
                    lock, target = root / "transition.lock", root / "elsewhere"
                    if case == "world-readable":
                        lock.write_text("")
                        lock.chmod(0o644)
                    elif case == "symlink":
                        target.write_text("not a lock")
                        target.chmod(0o644)
                        lock.symlink_to(target)
                    result = self._run_lock(lockf + self._lock_preamble(name, lock))
                    if case == "symlink":
                        self.assertNotEqual(result.returncode, 0)
                        self.assertNotIn("LOCKED", result.stdout)
                        self.assertIn("refusing a symlinked transition lock", result.stderr)
                        self.assertEqual(target.stat().st_mode & 0o777, 0o644)
                        self.assertEqual(target.read_text(), "not a lock")
                    else:
                        self.assertEqual(result.returncode, 0, result.stderr)
                        self.assertIn("LOCKED", result.stdout)
                        self.assertNotIn("WRAPPER", result.stdout)
                        self.assertEqual(lock.stat().st_mode & 0o777, 0o600)

    @macos_userland
    def test_transition_lock_is_held_by_the_script_itself(self) -> None:
        # uh8-6: the real lockf locks the script's own fd 9, so the lock is held
        # for exactly as long as the script runs, with no wrapper process whose
        # death would release it.
        for name in ("preinstall", "postinstall", "uninstall.sh"):
            with self.subTest(script=name), tempfile.TemporaryDirectory(prefix="yuzu_test_lock_held_") as temporary:
                lock = Path(temporary) / "transition.lock"
                # Under the production errexit preamble the probe's status is captured.
                probe = (f'second=0; /usr/bin/lockf -s -t 1 {shlex.quote(str(lock))} true || second=$?\n'
                         'echo "SECOND=$second"\n')
                result = self._run_lock(self._lock_preamble(name, lock) + probe)
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertIn("LOCKED", result.stdout)
                self.assertNotIn("WRAPPER", result.stdout)
                self.assertIn("SECOND=75", result.stdout)
                after = subprocess.run(["/usr/bin/lockf", "-s", "-t", "1", str(lock), "true"])
                self.assertEqual(after.returncode, 0)

    @posix_shell
    def test_transition_lock_falls_back_or_refuses_on_lockf_status(self) -> None:
        for name in ("preinstall", "postinstall", "uninstall.sh"):
            for status, outcome in ((64, "WRAPPER"), (2, "WRAPPER"), (75, "REFUSED")):
                with self.subTest(script=name, status=status), \
                        tempfile.TemporaryDirectory(prefix="yuzu_test_lock_status_") as temporary:
                    lock = Path(temporary) / "transition.lock"
                    lockf = f"lockf() {{ return {status}; }}\n"
                    # A descriptor still open at the wrapper means the fallback leaked it.
                    probe_fd = 'echo "FD9=$( { true >&9; } 2>/dev/null && echo open || echo closed)"\n'
                    script = self._lock_preamble(name, lock).replace(
                        '        echo WRAPPER; exit 0\n', '        ' + probe_fd + '        echo WRAPPER; exit 0\n')
                    result = self._run_lock(lockf + script)
                    self.assertNotIn("LOCKED", result.stdout)
                    if outcome == "WRAPPER":
                        self.assertEqual(result.returncode, 0, result.stderr)
                        self.assertIn("WRAPPER", result.stdout)
                        self.assertIn("FD9=closed", result.stdout)
                    else:
                        self.assertNotEqual(result.returncode, 0)
                        self.assertNotIn("WRAPPER", result.stdout)
                        self.assertIn("did not finish within 2 minutes", result.stderr)

    # ── Governance rd-n2: a pre-promotion refusal puts back missing live files ─
    @posix_shell
    def test_refusal_restores_only_missing_live_files_from_a_prepared_snapshot(self) -> None:
        names = ("recovery_path", "copy_back", "restore_missing_live_files")
        for phase, pointer, restores in (("prepared", True, True), ("promoting", True, False), ("prepared", False, False)):
            with self.subTest(phase=phase, pointer=pointer), \
                    tempfile.TemporaryDirectory(prefix="yuzu_test_missing_live_") as temporary:
                root = Path(temporary)
                recovery = self._recovery_layout(root, phase=phase, loose=True)
                (recovery / "loose/libyuzu_agent_core.dylib").write_text("previous core")
                (recovery / "package-files.list").write_text("plugins/a.dylib\nplugins/b.dylib\n")
                (recovery / "yuzu/plugins").mkdir(parents=True)
                (recovery / "yuzu/plugins/a.dylib").write_text("previous a")
                (recovery / "yuzu/plugins/b.dylib").write_text("previous b")
                lib = root / "ul/lib/yuzu"
                # Installer removed the old receipt's plist, binary and a.dylib; b.dylib
                # and the manifest survived with other bytes and must not be touched.
                (lib / "plugins/b.dylib").write_text("live b")
                (lib / "package-files.list").write_text("live manifest\n")
                if not pointer:
                    (root / "state/current-recovery").unlink()
                result = self._installer_harness(root, "postinstall", names,
                                                 "restore_missing_live_files\necho DONE\n",
                                                 modes=self._recovery_modes(root))
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertIn("DONE", result.stdout)
                live = {root / "LaunchDaemons/com.yuzu.agent.plist": "previous definition",
                        root / "ul/bin/yuzu-agent": "previous loose agent",
                        root / "ul/bin/libyuzu_agent_core.dylib": "previous core",
                        lib / "plugins/a.dylib": "previous a"}
                for path, content in live.items():
                    if restores:
                        self.assertEqual(path.read_text(), content, path)
                    else:
                        self.assertFalse(path.exists(), path)
                self.assertEqual((lib / "plugins/b.dylib").read_text(), "live b")
                self.assertEqual((lib / "package-files.list").read_text(), "live manifest\n")
                self.assertEqual(self._launchctl_log(root), "")
                self.assertTrue(recovery.exists())

    # ── Governance rd-n2: preinstall refuses before the payload exists ─────────
    @posix_shell
    def test_preinstall_requires_its_package_facts(self) -> None:
        pre = (BUILD_PKG.parent / "preinstall").read_text()
        start = pre.index('PACKAGE_MODE="$(awk')
        block = pre[start:pre.index("\n", pre.index('echo "ERROR: the package is missing its package-info', start)) + 1]
        for info, listing, accepted in (("mode=loose\nunsigned_plugins=1\n", True, True),
                                        ("mode=bundle\nunsigned_plugins=0\n", True, True),
                                        (None, True, False), ("mode=loose\n", False, False),
                                        ("mode=other\nunsigned_plugins=0\n", True, False), ("", True, False)):
            with self.subTest(info=info, listing=listing), \
                    tempfile.TemporaryDirectory(prefix="yuzu_test_package_info_") as temporary:
                scripts = Path(temporary)
                if info is not None:
                    (scripts / "package-info").write_text(info)
                if listing:
                    (scripts / "package-files.list").write_text("# package-version 1.0\n")
                result = subprocess.run([PKG_SHELL, "-c", PREAMBLE + f"SCRIPT_SRC={shlex.quote(str(scripts))}\n" + block
                                         + 'echo "MODE=$PACKAGE_MODE UNSIGNED=$UNSIGNED_PLUGINS"\n'],
                                        text=True, capture_output=True)
                self.assertEqual(result.returncode == 0, accepted, result.stderr)
                if accepted:
                    mode = "loose" if "loose" in info else "bundle"
                    self.assertIn(f"MODE={mode} UNSIGNED={'1' if 'plugins=1' in info else '0'}", result.stdout)
                else:
                    self.assertIn("missing its package-info or plugin list", result.stderr)

    # ── Governance uh8-7: a pending recovery runs before any refusal ───────────
    def test_preinstall_recovers_before_its_refusing_checks(self) -> None:
        pre = (BUILD_PKG.parent / "preinstall").read_text()
        recovery = pre.index('ensure_state_dir\nif [[ -e "$RECOVERY_FILE" || -L "$RECOVERY_FILE" ]]; then')
        for check in ('PACKAGE_MODE="$(awk', "require_trusted_data_directory || exit 1",
                      "require_trusted_log_directory || exit 1", "require_trusted_directory \"$configuration_dir\"",
                      'require_trusted_code_tree "$PACKAGE_MODE" || exit 1', 'secure_payload_parent "$APP_ROOT" 755',
                      "reject_unmanaged_plugin_collisions || exit 1"):
            self.assertLess(recovery, pre.index(check), check)

    @posix_shell
    def test_preinstall_refusal_follows_the_pending_recovery(self) -> None:
        pre = (BUILD_PKG.parent / "preinstall").read_text()
        start = pre.index('ensure_state_dir\nif [[ -e "$RECOVERY_FILE" || -L "$RECOVERY_FILE" ]]; then')
        end = pre.index("require_trusted_log_directory || exit 1\n", start) + len("require_trusted_log_directory || exit 1\n")
        block = pre[start:end]
        names = ("require_trusted_directory", "ensure_state_dir", "require_recovery_directory", "read_recovery_path",
                 "discard_recovery", "data_directory_owner_trusted", "require_trusted_data_directory",
                 "require_trusted_log_directory")
        with tempfile.TemporaryDirectory(prefix="yuzu_test_recover_first_") as temporary:
            root = Path(temporary)
            recovery = self._recovery_layout(root, phase="promoting")
            scripts = root / "scripts"
            scripts.mkdir()
            (scripts / "package-info").write_text("mode=loose\nunsigned_plugins=1\n")
            (scripts / "package-files.list").write_text("# package-version 1.0\n")
            stubs = (f"SCRIPT_SRC={shlex.quote(str(scripts))}\n"
                     'recover_interrupted_promotion() { echo "RECOVER $1" >> "$STATE_DIR/../recover.log"; }\n'
                     'restore_missing_live_files() { echo "MISSING $1" >> "$STATE_DIR/../recover.log"; }\n')
            modes = self._recovery_modes(root, state=700, data=775)
            result = self._installer_harness(root, "preinstall", names, block + "echo PROCEEDED\n",
                                             stubs=stubs, modes=modes)
            self.assertNotEqual(result.returncode, 0)
            self.assertNotIn("PROCEEDED", result.stdout)
            self.assertIn("existing data directory must be owned by root or _yuzu", result.stderr)
            # The interrupted promotion was recovered first, and its state cleared.
            self.assertEqual((root / "recover.log").read_text(), f"RECOVER {recovery}\n")
            self.assertFalse((root / "state/current-recovery").exists())
            self.assertFalse(recovery.exists())

    @macos_userland
    def test_preinstall_refuses_a_plugin_collision_before_the_payload(self) -> None:
        import hashlib
        names = ("plugin_hash_matches", "was_managed_plugin", "reject_unmanaged_plugin_collisions")
        for case, accepted in (("absent", True), ("managed", True), ("managed, no hash sidecar", True),
                               ("unlisted", False), ("operator-modified", False)):
            with self.subTest(case=case), tempfile.TemporaryDirectory(prefix="yuzu_test_pre_collision_") as temporary:
                root = Path(temporary)
                lib = root / "ul/lib/yuzu"
                (lib / "plugins").mkdir(parents=True)
                (root / "scripts").mkdir()
                (root / "scripts/package-files.list").write_text("# package-version 2.0\nplugins/a.dylib\n")
                if case != "absent":
                    (lib / "plugins/a.dylib").write_bytes(b"modified" if case == "operator-modified" else b"shipped")
                if case != "unlisted":
                    (lib / "package-files.list").write_text("# package-version 1.0\nplugins/a.dylib\n")
                if case != "managed, no hash sidecar":
                    (lib / "package-files.sha256").write_text(f"{hashlib.sha256(b'shipped').hexdigest()}  plugins/a.dylib\n")
                result = self._installer_harness(root, "preinstall", names,
                                                 "reject_unmanaged_plugin_collisions\necho ACCEPTED\n",
                                                 stubs=f'SCRIPT_SRC="{root}/scripts"\n')
                self.assertEqual(result.returncode == 0, accepted, result.stderr)
                self.assertEqual("ACCEPTED" in result.stdout, accepted)
                if not accepted:
                    self.assertIn("plugin a.dylib collides with one not installed by a Yuzu package", result.stderr)

    @macos_userland
    def test_preinstall_refuses_unsigned_plugins_under_retained_enforcement(self) -> None:
        cases = (("1", ["--plugin-require-signature"], None, "plist", False),
                 ("1", [], {"YUZU_PLUGIN_REQUIRE_SIGNATURE": "1"}, "plist", False),
                 ("1", [], {"YUZU_PLUGIN_REQUIRE_SIGNATURE": "0"}, "plist", True),
                 ("1", ["--plugin-require-signature=no"], {"YUZU_PLUGIN_REQUIRE_SIGNATURE": "1"}, "plist", True),
                 ("1", [], None, "plist", True),
                 ("1", ["--plugin-require-signature"], None, "unreadable", True),
                 ("1", [], None, "absent", True),
                 ("0", ["--plugin-require-signature"], None, "plist", True))
        for unsigned, arguments, environment, kind, accepted in cases:
            with self.subTest(unsigned=unsigned, arguments=arguments, environment=environment, kind=kind), \
                    tempfile.TemporaryDirectory(prefix="yuzu_test_pre_unsigned_") as temporary:
                root = Path(temporary)
                plist = root / "LaunchDaemons/com.yuzu.agent.plist"
                if kind == "plist":
                    self._write_plist(plist, arguments, environment)
                elif kind == "unreadable":
                    plist.parent.mkdir(parents=True)
                    plist.write_text("<plist><dict><key>ProgramArguments</key><array><string>--plugin-require-sig")
                result = self._installer_harness(root, "preinstall", ("cli11_flag_value_enabled", "plugin_signatures_required_by",
                                                                      "reject_unsigned_plugins_under_enforcement"),
                                                 "reject_unsigned_plugins_under_enforcement\necho ACCEPTED\n",
                                                 plist="real", stubs=f"UNSIGNED_PLUGINS={unsigned}\n")
                self.assertEqual(result.returncode == 0, accepted, result.stderr)
                self.assertEqual("ACCEPTED" in result.stdout, accepted)
                if not accepted:
                    self.assertIn("this package has unsigned plugins", result.stderr)

    # ── Governance rd-n3: the log directory follows the data directory's rule ──
    @macos_userland
    def test_log_directory_owner_is_root_or_yuzu(self) -> None:
        fake_id = 'id() { [[ "$1 $2" == "-u _yuzu" && -n "${YUZU_UID:-}" ]] || return 1; echo "$YUZU_UID"; }\n'
        for script in ("preinstall", "postinstall"):
            names = ("data_directory_owner_trusted", "require_trusted_log_directory")
            for case, owner, yuzu_uid, mode, accepted in (("root", 0, "", 0o755, True),
                                                           ("_yuzu", 299, "299", 0o750, True),
                                                           ("_yuzu on a host without _yuzu", 299, "", 0o750, False),
                                                           ("group-writable", 0, "", 0o775, False),
                                                           ("another account", 501, "299", 0o755, False),
                                                           ("missing", None, "", None, True)):
                with self.subTest(script=script, case=case), \
                        tempfile.TemporaryDirectory(prefix="yuzu_test_log_dir_") as temporary:
                    root = Path(temporary)
                    logs = root / "logs"
                    owners = {}
                    if owner is not None:
                        logs.mkdir()
                        logs.chmod(mode)
                        (logs / "yuzu-agent.log").write_text("history")
                        owners = {logs: owner}
                    result = self._installer_harness(
                        root, script, names, "require_trusted_log_directory\necho ACCEPTED\n",
                        owners=owners, real_modes=True,
                        stubs=fake_id + f"YUZU_UID={yuzu_uid}\nrequire_trusted_directory() {{ :; }}\n")
                    self.assertEqual(result.returncode == 0, accepted, result.stderr)
                    self.assertEqual("ACCEPTED" in result.stdout, accepted)
                    if owner is None:
                        # postinstall creates a missing one root:wheel 755; preinstall leaves it.
                        self.assertEqual(logs.is_dir(), script == "postinstall")
                        if script == "postinstall":
                            self.assertEqual(logs.stat().st_mode & 0o777, 0o755)
                    else:
                        self.assertEqual(logs.stat().st_mode & 0o777, mode)
                        self.assertEqual((logs / "yuzu-agent.log").read_text(), "history")
                    if not accepted:
                        self.assertIn("log directory must be owned by root or _yuzu", result.stderr)

    # ── Governance ch-5: the delivered loose code must be the package's bytes ──
    @macos_userland
    def test_incoming_loose_code_must_match_the_recorded_hashes(self) -> None:
        import hashlib
        agent, core = b"agent bytes", b"core bytes"
        record = {"agent": f"{hashlib.sha256(agent).hexdigest()}  bin/yuzu-agent\n",
                  "core": f"{hashlib.sha256(core).hexdigest()}  bin/libyuzu_agent_core.dylib\n"}
        cases = {
            "agent and core match": (agent, core, "agent core", True, None),
            "agent only, no core delivered or recorded": (agent, None, "agent", True, None),
            "swapped agent": (b"evil", core, "agent core", False, "incoming yuzu-agent does not match"),
            "swapped core": (agent, b"evil", "agent core", False, "incoming libyuzu_agent_core.dylib does not match"),
            "agent unrecorded": (agent, None, "", False, "recorded no hash for the delivered yuzu-agent"),
            "core delivered but unrecorded": (agent, core, "agent", False,
                                              "recorded no hash for the delivered libyuzu_agent_core.dylib"),
            "agent symlinked": ("symlink", None, "agent", False, "incoming yuzu-agent is missing or not a regular file"),
            "agent missing": (None, None, "agent", False, "incoming yuzu-agent is missing or not a regular file"),
        }
        for name, (agent_bytes, core_bytes, recorded, accepted, message) in cases.items():
            with self.subTest(case=name), tempfile.TemporaryDirectory(prefix="yuzu_test_loose_hash_") as temporary:
                root = Path(temporary)
                bin_dir, lib = root / "ul/bin", root / "ul/lib/yuzu"
                bin_dir.mkdir(parents=True)
                lib.mkdir(parents=True)
                incoming = bin_dir / ".yuzu-agent.incoming"
                if agent_bytes == "symlink":
                    (root / "real-agent").write_bytes(agent)
                    incoming.symlink_to(root / "real-agent")
                elif agent_bytes is not None:
                    incoming.write_bytes(agent_bytes)
                if core_bytes is not None:
                    (bin_dir / ".libyuzu_agent_core.incoming.dylib").write_bytes(core_bytes)
                (lib / ".package-files.sha256.incoming").write_text(
                    "".join(record[key] for key in recorded.split()) + "0" * 64 + "  plugins/tar.dylib\n")
                result = self._installer_harness(root, "postinstall", ("verify_incoming_loose_code",),
                                                 "verify_incoming_loose_code\necho VERIFIED\n")
                self.assertEqual(result.returncode == 0, accepted, result.stderr)
                self.assertEqual("VERIFIED" in result.stdout, accepted)
                if message:
                    self.assertIn(message, result.stderr)

    # ── Governance G8-S5: bash 3.2 ignores a failing bare [[ ]] under errexit ──
    @macos_userland
    def test_bundle_definition_without_no_auto_update_is_refused(self) -> None:
        post = (BUILD_PKG.parent / "postinstall").read_text()
        start = post.index('if [[ "$MODE" == "bundle" ]]; then\n    chown -R root:wheel "$APP"')
        block = post[start:post.index("fi\nsync\n", start) + 3].replace("/usr/libexec/PlistBuddy", "plist_buddy")
        for arguments, accepted in (("--plugin-dir x --no-auto-update", True), ("--plugin-dir x", False)):
            with self.subTest(arguments=arguments), tempfile.TemporaryDirectory(prefix="yuzu_test_bundle_tail_") as temporary:
                root = Path(temporary)
                (root / "app/YuzuAgent.app").mkdir(parents=True)
                stubs = ('chmod() { :; }\nharden_managed_plugins() { :; }\n'
                         f'plist_buddy() {{ printf "Array {{\\n    %s\\n}}\\n" {arguments}; }}\nMODE=bundle\n')
                result = self._installer_harness(root, "postinstall", (), block + "echo PAST\n", stubs=stubs)
                self.assertEqual(result.returncode == 0, accepted, result.stderr)
                self.assertEqual("PAST" in result.stdout, accepted)
                if not accepted:
                    self.assertIn("lacks --no-auto-update", result.stderr)

    # ── Governance con8-1: the signature setting read as CLI11 2.6 reads it ────
    CLI11_ON = ("1", "9", "t", "y", "+", "true", "TRUE", "True", "on", "yes", "enable", "42", "+3",
                " yes", "\ton\t", "maybe", "2x")
    CLI11_OFF = ("0", "f", "n", "-", "false", "FALSE", "off", "no", "disable", "-1", "00", "+0", " 0 ", "No")

    @posix_shell
    def test_cli11_flag_values_match_cli11(self) -> None:
        # to_flag_value: 1-9/t/y/+ and true/on/yes/enable on; 0/f/n/- and
        # false/off/no/disable off; other integers on when positive; anything
        # CLI11 would reject counts as on (refuse rather than guess). An empty
        # inline value is the bare flag (on); an empty environment value is off.
        cases = ([(value, source, True) for value in self.CLI11_ON for source in ("argument", "environment")]
                 + [(value, source, False) for value in self.CLI11_OFF for source in ("argument", "environment")]
                 + [("", "argument", True), ("", "environment", False),
                    ("  ", "argument", True), ("  ", "environment", False)])
        body = "".join(
            f"if cli11_flag_value_enabled '{value}' {source}; then echo 'ON|{value}|{source}'; "
            f"else echo 'OFF|{value}|{source}'; fi\n" for value, source, _ in cases) + "echo DONE\n"
        for script in ("preinstall", "postinstall"):
            with self.subTest(script=script), tempfile.TemporaryDirectory(prefix="yuzu_test_cli11_") as temporary:
                result = self._installer_harness(Path(temporary), script, ("cli11_flag_value_enabled",), body)
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertIn("DONE", result.stdout)
                lines = [line for line in result.stdout.splitlines() if line != "DONE"]
                self.assertEqual(len(lines), len(cases))
                for line, (value, source, enabled) in zip(lines, cases):
                    self.assertEqual(line, f"{'ON' if enabled else 'OFF'}|{value}|{source}",
                                     f"{script}: {value!r} from the {source}")

    @macos_userland
    def test_empty_inline_signature_flag_requires_signatures_but_empty_env_does_not(self) -> None:
        # con8-1: `--plugin-require-signature=` is the bare flag to CLI11, so the
        # upgraded agent would reject unsigned plugins; an empty environment value
        # leaves enforcement off.
        cases = ((["--plugin-require-signature="], None, 0),
                 ([], {"YUZU_PLUGIN_REQUIRE_SIGNATURE": ""}, 1),
                 (["--plugin-require-signature=f"], None, 1),
                 ([], {"YUZU_PLUGIN_REQUIRE_SIGNATURE": "enable"}, 0))
        for script in ("preinstall", "postinstall"):
            for arguments, environment, expected in cases:
                with self.subTest(script=script, arguments=arguments, environment=environment), \
                        tempfile.TemporaryDirectory(prefix="yuzu_test_cli11_plist_") as temporary:
                    root = Path(temporary)
                    self._write_plist(root / "LaunchDaemons/com.yuzu.agent.plist", arguments, environment)
                    result = self._installer_harness(
                        root, script, ("cli11_flag_value_enabled", "plugin_signatures_required_by"),
                        'status=0\nplugin_signatures_required_by "$PLIST" || status=$?\necho "STATUS=$status"\n',
                        plist="real")
                    self.assertEqual(result.returncode, 0, result.stderr)
                    self.assertIn(f"STATUS={expected}", result.stdout)

    # ── Governance con8-3: ACLs on every trusted directory, stripped from owned roots ──
    @macos_userland
    def test_trusted_directories_refuse_write_acls_and_secured_roots_lose_them(self) -> None:
        for script in ("preinstall", "postinstall"):
            with self.subTest(script=script), tempfile.TemporaryDirectory(prefix="yuzu_test_acl_dir_") as temporary:
                root = Path(temporary)
                target = root / "parent"
                target.mkdir(mode=0o755)
                target.chmod(0o755)

                def check() -> subprocess.CompletedProcess:
                    return self._installer_harness(
                        root, script, ("acl_grants_write", "require_trusted_directory"),
                        f'require_trusted_directory "{target}"\necho TRUSTED\n', real_modes=True)

                try:
                    result = check()
                    self.assertEqual(result.returncode, 0, result.stderr)
                    self.assertIn("TRUSTED", result.stdout)
                    subprocess.run(["chmod", "+a", "everyone allow add_file,add_subdirectory", str(target)],
                                   check=True)
                    result = check()
                    self.assertNotEqual(result.returncode, 0)
                    self.assertNotIn("TRUSTED", result.stdout)
                    self.assertIn("access control list lets another account modify", result.stderr)
                    subprocess.run(["chmod", "-N", str(target)], check=True)
                    subprocess.run(["chmod", "+a", "everyone deny add_file,delete_child", str(target)], check=True)
                    result = check()
                    self.assertEqual(result.returncode, 0, result.stderr)
                    self.assertIn("TRUSTED", result.stdout)
                finally:
                    subprocess.run(["chmod", "-RN", str(root)], capture_output=True)
        # preinstall secures the package-owned roots it creates or adopts: an ACL
        # someone added to APP_ROOT (or YUZU_LIB) is stripped, not carried along.
        with tempfile.TemporaryDirectory(prefix="yuzu_test_acl_secure_") as temporary:
            root = Path(temporary)
            root.chmod(0o755)
            app_root = root / "app"
            app_root.mkdir(mode=0o755)
            try:
                subprocess.run(["chmod", "+a", "everyone allow add_file,add_subdirectory", str(app_root)],
                               check=True)
                result = self._installer_harness(
                    root, "preinstall", ("acl_grants_write", "require_trusted_directory", "secure_payload_parent"),
                    'secure_payload_parent "$APP_ROOT" 755\necho SECURED\n', real_modes=True)
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertIn("SECURED", result.stdout)
                listing = subprocess.run(["/bin/ls", "-lde", str(app_root)], capture_output=True, text=True).stdout
                self.assertNotRegex(listing, r"(?m)^ *\d+: ", listing)
            finally:
                subprocess.run(["chmod", "-RN", str(root)], capture_output=True)

    # ── Governance con8-2: the merge reports a lost definition to postinstall ──
    @unittest.skipUnless(sys.platform == "darwin", "native macOS plist integration")
    def test_plist_merge_reports_an_unreadable_previous_definition_on_stdout(self) -> None:
        with tempfile.TemporaryDirectory(prefix="yuzu_test_merge_report_") as temporary:
            root = Path(temporary)
            good, bad = root / "good.plist", root / "bad.plist"
            self._write_plist(good, ["--server", "s:50051", "--no-tls"])
            bad.write_text("<plist><dict><key>ProgramArguments</key><array><string>--server")
            for previous, expected in ((good, ""), (bad, "prior-unreadable")):
                with self.subTest(previous=previous.name):
                    destination = root / f"new-{previous.name}"
                    destination.write_bytes((BUILD_PKG.parent / "com.yuzu.agent.plist").read_bytes())
                    result = subprocess.run(
                        ["/usr/bin/osascript", "-l", "JavaScript", str(MERGE_PLIST_HELPER),
                         "--previous", str(previous), "--destination", str(destination)],
                        capture_output=True, text=True)
                    self.assertEqual(result.returncode, 0, result.stderr)
                    self.assertEqual(result.stdout.strip(), expected)

    @posix_shell
    def test_postinstall_reads_the_lost_definition_report(self) -> None:
        post = (BUILD_PKG.parent / "postinstall").read_text()
        # The merge's stdout is captured, and the report sets the flag the start
        # decision reads.
        self.assertIn('merge_result="$(/usr/bin/osascript -l JavaScript "$SCRIPT_SRC/merge-launchd-plist.js"', post)
        start = post.index("prior_definition_lost=0\n")
        # Anchored on the next statement, so mutating the report check itself
        # fails behaviourally rather than by slicing.
        block = post[start:post.index("reject_unsigned_plugins_under_enforcement || exit 1\n", start)]
        self.assertLess(start, post.index("# Start decision."))
        for name, setup, lost in (("no previous definition", "", 0),
                                  ("normal merge", "merge_result=\n", 0),
                                  ("unreadable previous definition", "merge_result=prior-unreadable\n", 1)):
            with self.subTest(case=name):
                result = subprocess.run([PKG_SHELL, "-c", PREAMBLE + setup + block +
                                         'echo "LOST=$prior_definition_lost"\n'],
                                        capture_output=True, text=True)
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertIn(f"LOST={lost}", result.stdout)

    # ── Governance con8-4: uninstall after a rollback removes plugins by name ──
    def _uninstall_plugin_block(self) -> str:
        source = (BUILD_PKG.parent / "uninstall.sh").read_text()
        start = source.index('if [[ ! -f "$MANIFEST" ]]; then\n')
        return source[start:source.index("\nfi\n", start) + 4]

    @macos_userland
    def test_uninstall_removes_plugins_by_name_when_the_manifest_is_stale(self) -> None:
        import hashlib
        receipt = ("usr/local/lib/yuzu/plugins/old.dylib\nusr/local/lib/yuzu/plugins/._old.dylib\n"
                   "usr/local/bin/yuzu-agent\n")
        # (manifest written, installed version, survivors)
        cases = {
            # Stale: the hashes are N's, the bytes O's; removed by name anyway, and
            # the receipt's own plugin with them. The AppleDouble entry names nothing.
            "stale manifest": ("2.0", "1.0", {"third.dylib", "._old.dylib"}),
            # No manifest at all: only the receipt names package plugins.
            "no manifest": (None, "1.0", {"shared.dylib", "modified.dylib", "third.dylib", "._old.dylib"}),
            # A current manifest keeps the hash rule: the operator's modified copy stays.
            "current manifest": ("1.0", "1.0", {"modified.dylib", "old.dylib", "third.dylib", "._old.dylib"}),
        }
        for name, (written, installed, survivors) in cases.items():
            with self.subTest(case=name), tempfile.TemporaryDirectory(prefix="yuzu_test_uninstall_stale_") as temporary:
                root = Path(temporary)
                plugins = root / "ul/lib/yuzu/plugins"
                plugins.mkdir(parents=True)
                for plugin in ("shared.dylib", "modified.dylib", "old.dylib", "third.dylib", "._old.dylib"):
                    (plugins / plugin).write_bytes(f"bytes of {plugin}".encode())
                lib = root / "ul/lib/yuzu"
                if written is not None:
                    (lib / "package-files.list").write_text(
                        f"# package-version {written}\nplugins/shared.dylib\nplugins/modified.dylib\n")
                    recorded = {"shared.dylib": hashlib.sha256(b"bytes of shared.dylib").hexdigest(),
                                "modified.dylib": hashlib.sha256(b"what the package shipped").hexdigest()}
                    (lib / "package-files.sha256").write_text(
                        "".join(f"{digest}  plugins/{plugin}\n" for plugin, digest in recorded.items()))
                stubs = (f'pkgutil() {{ case "$1" in --pkg-info) printf "package-id: com.yuzu.agent\\n'
                         f'version: {installed}\\n" ;; --files) printf "%s" "$RECEIPT" ;; *) return 99 ;; esac; }}\n'
                         f"RECEIPT='{receipt}'\n")
                result = self._installer_harness(
                    root, "uninstall.sh",
                    ("plugin_hash_matches", "remove_managed_plugins", "manifest_is_stale", "remove_receipted_plugins"),
                    self._uninstall_plugin_block() + "echo REMOVED\n", stubs=stubs)
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertIn("REMOVED", result.stdout)
                self.assertEqual({path.name for path in plugins.iterdir()}, survivors)
                self.assertEqual("predates the installed package" in result.stderr, name == "stale manifest")

    @posix_shell
    def test_uninstall_manifest_staleness_is_read_from_its_version_header(self) -> None:
        for first_line, installed, pkg_status, stale in (
                ("# package-version 2.0", "1.0", 0, True),
                ("# package-version 1.0", "1.0", 0, False),
                ("plugins/x.dylib", "1.0", 0, False),          # older manifest: no header
                ("# package-version 2.0", "", 0, False),        # receipt without a version
                ("# package-version 2.0", "1.0", 1, False)):    # no receipt at all
            with self.subTest(first_line=first_line, installed=installed, pkg_status=pkg_status), \
                    tempfile.TemporaryDirectory(prefix="yuzu_test_stale_check_") as temporary:
                root = Path(temporary)
                lib = root / "ul/lib/yuzu"
                lib.mkdir(parents=True)
                (lib / "package-files.list").write_text(first_line + "\n")
                stubs = (f'pkgutil() {{ [[ "$1" == --pkg-info ]] || return 99; '
                         f'printf "version: {installed}\\n"; return {pkg_status}; }}\n')
                result = self._installer_harness(
                    root, "uninstall.sh", ("manifest_is_stale",),
                    "if manifest_is_stale; then echo STALE; else echo CURRENT; fi\n", stubs=stubs)
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertEqual(result.stdout.strip(), "STALE" if stale else "CURRENT")

    # ── Governance con8-10: the "preserved" line survives the snapshot's removal ──
    @posix_shell
    def test_preserved_line_prints_after_an_upgrade_only(self) -> None:
        post = (BUILD_PKG.parent / "postinstall").read_text()
        start = post.index("\nretire_legacy_app\n", post.index("# The previous development bundle lived below")) + 1
        tail = post[start:]
        for name, upgrade in (("upgrade", True), ("fresh install", False)):
            with self.subTest(case=name), tempfile.TemporaryDirectory(prefix="yuzu_test_preserved_") as temporary:
                root = Path(temporary)
                recovery = self._recovery_layout(root, phase="promoting")
                if not upgrade:
                    (recovery / "LaunchDaemons/com.yuzu.agent.plist").unlink()
                body = ('retire_legacy_app() { :; }\n'
                        f'recovery="{recovery}"\noutcome="OUTCOME-LINE"\nPROMOTION_ARMED=1\n' + tail)
                result = self._installer_harness(root, "postinstall", ("finish_recovery",), body)
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertIn("OUTCOME-LINE", result.stdout)
                # finish_recovery really ran: the snapshot and the pointer are gone.
                self.assertFalse(recovery.exists())
                self.assertFalse((root / "state/current-recovery").exists())
                self.assertEqual("service settings were preserved" in result.stdout, upgrade)

    # ── Governance uh8-4 residue: leftover re-derivation temporaries are swept ──
    @posix_shell
    def test_preinstall_sweeps_leftover_rederivation_files(self) -> None:
        pre = (BUILD_PKG.parent / "preinstall").read_text()
        secured = pre.index('secure_payload_parent "$YUZU_LIB" 755\n')
        start = pre.index("rm -f ", secured)
        sweep = pre[start:pre.index("\n", pre.index(".legacy-manifest.*", start)) + 1]
        # Right after YUZU_LIB is secured, and before anything reads the manifest.
        self.assertEqual(pre[secured:start].count("\n"), 2, pre[secured:start])
        self.assertLess(start, pre.index("\ndiscard_stale_manifest\n"))
        with tempfile.TemporaryDirectory(prefix="yuzu_test_sweep_") as temporary:
            lib = Path(temporary) / "lib/yuzu"
            (lib / "plugins").mkdir(parents=True)
            leftovers = (".rederived-manifest.AbC123", ".rederived-hashes.x9", ".still-owned.QQ", ".legacy-manifest.z")
            kept = ("package-files.list", "package-files.sha256", ".package-files.incoming",
                    ".package-files.sha256.incoming", "rederived-manifest.visible")
            for name in leftovers + kept:
                (lib / name).write_text(name)
            result = subprocess.run([PKG_SHELL, "-c", PREAMBLE + f'YUZU_LIB="{lib}"\n' + sweep + "echo SWEPT\n"],
                                    capture_output=True, text=True)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertIn("SWEPT", result.stdout)
            self.assertEqual({path.name for path in lib.iterdir()}, set(kept) | {"plugins"})
            # With nothing to sweep the line is still a no-op, never an error.
            result = subprocess.run([PKG_SHELL, "-c", PREAMBLE + f'YUZU_LIB="{lib}"\n' + sweep + "echo SWEPT\n"],
                                    capture_output=True, text=True)
            self.assertEqual(result.returncode, 0, result.stderr)

if __name__ == "__main__":
    unittest.main()
