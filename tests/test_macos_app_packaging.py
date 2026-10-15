#!/usr/bin/env python3
"""Portable contracts for the macOS Endpoint Security development package lane."""

from __future__ import annotations

import datetime as dt
import importlib.util
import json
import os
import plistlib
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
MACOS_TRIPLET = ROOT / "triplets/arm64-osx.cmake"
spec = importlib.util.spec_from_file_location("macos_bundle", HELPER)
assert spec and spec.loader
bundle = importlib.util.module_from_spec(spec)
spec.loader.exec_module(bundle)


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
            for script in ("preinstall", "postinstall", "uninstall.sh"):
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
                for name, body in {
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
                    self.assertEqual(captured.read_text(), "" if layout == "empty" else "plugins/tar.dylib\n")

    @unittest.skipIf(os.name == "nt", "POSIX receipt fixture")
    def test_legacy_plugin_ownership_comes_only_from_exact_receipt_paths(self) -> None:
        source = (BUILD_PKG.parent / "preinstall").read_text()
        start = source.index("adopt_receipted_plugins() {")
        function = source[start:source.index("\n}", start) + 2].replace("/usr/sbin/pkgutil", "pkgutil")
        for receipt, status, expected in (
            ("usr/local/lib/yuzu/plugins/tar.dylib\nusr/local/lib/other.dylib\n", 0, "plugins/tar.dylib\n"),
            ("usr/local/lib/yuzu/plugins/sub/evil.dylib\n", 0, None),
            ("usr/local/lib/yuzu/plugins/../evil.dylib\n", 0, None),
            ("usr/local/lib/yuzu/plugins/a\tb.dylib\n", 0, None),
            ("usr/local/lib/yuzu/plugins/.hidden.dylib\n", 0, None),
            ("usr/local/lib/yuzu/plugins/tar.dylib\n", 1, None),
        ):
            with self.subTest(receipt=receipt, status=status), tempfile.TemporaryDirectory(prefix="yuzu_test_receipt_") as temporary:
                root = Path(temporary)
                (root / "plugins").mkdir()
                (root / "plugins/third-party.dylib").write_bytes(b"unmanaged")
                harness = '''set -eu
pkgutil() { [[ "$1" == --files && "$2" == com.yuzu.agent ]] || exit 99; printf '%s' "$RECEIPT"; return "$RECEIPT_STATUS"; }
''' + function + "\nadopt_receipted_plugins\n"
                result = subprocess.run(["bash", "-c", harness], text=True, capture_output=True,
                                        env={**os.environ, "YUZU_LIB": temporary, "RECEIPT": receipt,
                                             "RECEIPT_STATUS": str(status)})
                manifest = root / "package-files.list"
                self.assertEqual(manifest.read_text() if manifest.exists() else None, expected)
                self.assertEqual(result.returncode == 0, expected is not None or status == 1)
                self.assertEqual((root / "plugins/third-party.dylib").read_bytes(), b"unmanaged")

    @unittest.skipIf(os.name == "nt", "POSIX permissions fixture")
    def test_data_directory_created_when_missing_and_preserved_when_present(self) -> None:
        source = (BUILD_PKG.parent / "postinstall").read_text()
        start = source.index("ensure_data_directory() {")
        function = source[start:source.index("\n}", start) + 2]
        with tempfile.TemporaryDirectory(prefix="yuzu_test_data_dir_") as temporary:
            data = Path(temporary) / "data"
            check_start = source.index("require_trusted_data_directory() {")
            function = source[check_start:source.index("\n}", check_start) + 2] + "\n" + function
            # The installer runs as root; the fixture reports the data directory's owner as
            # FAKE_UID (default root) so ownership can be exercised without privileges.
            fake_stat = 'stat() { if [[ "$2" == "%u" ]]; then echo "${FAKE_UID:-0}"; else command stat "$@"; fi; }\n'
            harness = "set -eu\n" + fake_stat + "require_trusted_directory() { return 0; }\nchown() { echo CHOWN; }\n" + function + "\nensure_data_directory\n"
            def invoke(**extra):
                return subprocess.run([PKG_SHELL, "-c", harness], text=True, capture_output=True,
                                      env={**os.environ, "DATA_DIR": str(data), **extra})
            result = invoke()
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual(data.stat().st_mode & 0o777, 0o750)
            self.assertEqual(result.stdout.strip(), "CHOWN")
            data.chmod(0o710)
            sentinel = data / "keep"
            sentinel.write_bytes(b"existing data")
            before = data.stat()
            result = invoke()
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual(result.stdout, "")
            self.assertEqual(data.stat().st_uid, before.st_uid)
            self.assertEqual(data.stat().st_mode, before.st_mode)
            self.assertEqual(sentinel.read_bytes(), b"existing data")
            link = Path(temporary) / "link"
            link.symlink_to(data, target_is_directory=True)
            result = subprocess.run([PKG_SHELL, "-c", harness], text=True, capture_output=True,
                                    env={**os.environ, "DATA_DIR": str(link)})
            self.assertNotEqual(result.returncode, 0)
            # PR #4482 review: an existing data root that is not root-owned, or is
            # group/world writable, is refused and left exactly as it was.
            for mode, uid in ((0o777, "0"), (0o770, "0"), (0o750, "501")):
                data.chmod(mode)
                before = data.stat()
                result = invoke(FAKE_UID=uid)
                self.assertNotEqual(result.returncode, 0, f"mode {oct(mode)} uid {uid} was accepted")
                self.assertIn("must be root-owned and not group/world writable", result.stderr)
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
    @unittest.skipIf(os.name == "nt", "POSIX recovery fixture")
    def test_interrupted_plugin_promotion_restores_old_generation_and_allows_retry(self) -> None:
        pre = (BUILD_PKG.parent / "preinstall").read_text()
        post = (BUILD_PKG.parent / "postinstall").read_text()
        def function(source, name):
            start = source.index(name + "() {")
            return source[start:source.index("\n}", start) + 2]
        with tempfile.TemporaryDirectory(prefix="yuzu_test_retry_manifest_") as temporary:
            root = Path(temporary)
            for folder in ("lib/plugins", "app", "recovery/yuzu/plugins", "bin", "next-incoming"):
                (root / folder).mkdir(parents=True)
            (root / "lib/package-files.list").write_text("plugins/old.dylib\n")
            (root / "lib/.package-files.incoming").write_text("plugins/old.dylib\nplugins/new.dylib\n")
            (root / "recovery/package-files.list").write_text("plugins/old.dylib\n")
            (root / "recovery/yuzu/plugins/old.dylib").write_bytes(b"old generation")
            (root / "lib/plugins/old.dylib").write_bytes(b"replacement")
            (root / "lib/plugins/new.dylib").write_bytes(b"new before crash")
            (root / "lib/plugins/third-party.dylib").write_bytes(b"unmanaged")
            (root / "next-incoming/new.dylib").write_bytes(b"retry")
            harness = '''set -eu
launchctl() { :; }
require_started() { :; }
ditto() { if [[ -d "$1" ]]; then cp -R "$1/." "$2/"; else cp "$1" "$2"; fi; }
'''
            harness += "\n".join(function(pre, name) for name in ("quarantine_legacy_app", "remove_managed_plugins", "recover_interrupted_promotion"))
            harness += "\n" + "\n".join(function(post, name) for name in ("was_managed_plugin", "reject_unmanaged_plugin_collisions"))
            harness = harness.replace("/usr/local/bin", str(root / "bin")).replace("/usr/local/lib", str(root / "lib"))
            harness += '''
ROOT="$1"
YUZU_LIB="$ROOT/lib"
APP_ROOT="$ROOT/app"
PLIST="$ROOT/absent.plist"
LEGACY_APP="$ROOT/absent-legacy.app"
MANIFEST="$YUZU_LIB/package-files.list"
PLUGIN_DIR="$YUZU_LIB/plugins"
INCOMING_PLUGIN_DIR="$ROOT/next-incoming"
recover_interrupted_promotion "$ROOT/recovery"
reject_unmanaged_plugin_collisions
'''
            result = subprocess.run(["bash", "-c", harness, "recovery-fixture", temporary],
                                    text=True, capture_output=True)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertFalse((root / "lib/plugins/new.dylib").exists())
            self.assertEqual((root / "lib/plugins/old.dylib").read_bytes(), b"old generation")
            self.assertEqual((root / "lib/plugins/third-party.dylib").read_bytes(), b"unmanaged")

    # ── PR #4482 review (Doomgoose blocker 1): an unrecognized legacy app must never
    # deadlock recovery. Before the fix it stayed in the recovery snapshot, both
    # recovery paths returned 1 before restarting the service, and every later
    # install failed the same way.
    @staticmethod
    def _script_function(source: str, name: str) -> str:
        start = source.index("\n" + name + "() {") + 1
        return source[start:source.index("\n}\n", start) + 3]

    def _legacy_harness(self, root: Path, script: str, names: tuple[str, ...], body: str,
                        plist_points_to_legacy: bool = False,
                        plist_read_fails: bool = False) -> subprocess.CompletedProcess:
        source = (BUILD_PKG.parent / script).read_text()
        program = "\n".join(self._script_function(source, name) for name in names)
        program = (program.replace("/usr/local/bin", str(root / "bin")).replace("/usr/local/lib", str(root / "lib"))
                   .replace("/usr/libexec/PlistBuddy", "plist_buddy"))
        legacy = root / "data/YuzuAgent.app"
        stubs = f"""set -eu
launchctl() {{ echo "$*" >> "{root}/launchctl.log"; }}
require_started() {{ :; }}
chown() {{ :; }}
legacy_app_is_managed() {{ return 1; }}
plist_buddy() {{ {"return 1" if plist_read_fails else ("echo " + str(legacy) + "/Contents/MacOS/yuzu-agent" if plist_points_to_legacy else "echo /usr/local/bin/yuzu-agent")}; }}
ditto() {{ if [[ -d "$1" ]]; then mkdir -p "$2"; cp -R "$1/." "$2/"; else cp "$1" "$2"; fi; }}
STATE_DIR="{root}/state"; LEGACY_APP="{legacy}"; YUZU_LIB="{root}/lib"; APP_ROOT="{root}/app"; APP="{root}/app/YuzuAgent.app"
PLIST="{root}/LaunchDaemons/com.yuzu.agent.plist"; PLUGIN_DIR="{root}/lib/plugins"; MANIFEST="{root}/lib/package-files.list"
MODE_FILE="{root}/lib/package-mode"; recovery="{root}/state/install-recovery.TEST"
"""
        return subprocess.run([PKG_SHELL, "-c", stubs + program + "\n" + body], text=True, capture_output=True)

    def _legacy_layout(self, root: Path) -> Path:
        for folder in ("state/install-recovery.TEST/LaunchDaemons", "data/YuzuAgent.app/Contents",
                       "LaunchDaemons", "app", "lib/plugins", "bin"):
            (root / folder).mkdir(parents=True, exist_ok=True)
        (root / "state/install-recovery.TEST/LaunchDaemons/com.yuzu.agent.plist").write_text("previous")
        return root / "state/install-recovery.TEST"

    def test_unrecognized_legacy_app_is_quarantined_without_rolling_back_a_healthy_install(self) -> None:
        with tempfile.TemporaryDirectory(prefix="yuzu_test_legacy_retire_") as temporary:
            root = Path(temporary)
            recovery = self._legacy_layout(root)
            result = self._legacy_harness(root, "postinstall", ("quarantine_legacy_app", "retire_legacy_app"),
                                          "retire_legacy_app && echo RETIRED")
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertIn("RETIRED", result.stdout)
            self.assertIn("quarantined an unrecognized legacy", result.stderr)
            self.assertFalse((root / "data/YuzuAgent.app").exists())
            self.assertFalse((recovery / "legacy-retired.app").exists())
            self.assertEqual(len(list((root / "state/quarantine").glob("legacy-YuzuAgent.*/YuzuAgent.app"))), 1)

    def test_recovery_with_a_retained_legacy_app_restarts_the_previous_service(self) -> None:
        with tempfile.TemporaryDirectory(prefix="yuzu_test_legacy_recover_") as temporary:
            root = Path(temporary)
            recovery = self._legacy_layout(root)
            (recovery / "legacy-retired.app/Contents").mkdir(parents=True)
            for _attempt in (1, 2):    # recovery must also be repeatable, never a dead end
                result = self._legacy_harness(root, "preinstall",
                                              ("quarantine_legacy_app", "remove_managed_plugins", "recover_interrupted_promotion"),
                                              f'recover_interrupted_promotion "{recovery}" && echo RECOVERED')
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertIn("RECOVERED", result.stdout)
            self.assertFalse((recovery / "legacy-retired.app").exists())
            self.assertIn("bootstrap system", (root / "launchctl.log").read_text())

    def test_recovery_never_starts_a_legacy_data_root_service_but_does_not_block(self) -> None:
        with tempfile.TemporaryDirectory(prefix="yuzu_test_legacy_plist_") as temporary:
            root = Path(temporary)
            recovery = self._legacy_layout(root)
            result = self._legacy_harness(root, "preinstall",
                                          ("quarantine_legacy_app", "remove_managed_plugins", "recover_interrupted_promotion"),
                                          f'recover_interrupted_promotion "{recovery}" && echo RECOVERED',
                                          plist_points_to_legacy=True)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertIn("did not start it from non-package-owned data", result.stderr)
            log = root / "launchctl.log"
            self.assertNotIn("bootstrap", log.read_text() if log.exists() else "")

    def test_recovery_does_not_start_a_service_whose_definition_cannot_be_read(self) -> None:
        # A failed read used to flow through `| grep -q` and look like "not the legacy
        # program", so the service was started anyway (PR #4482 review, pipefail item).
        with tempfile.TemporaryDirectory(prefix="yuzu_test_plist_unreadable_") as temporary:
            root = Path(temporary)
            recovery = self._legacy_layout(root)
            result = self._legacy_harness(root, "preinstall",
                                          ("quarantine_legacy_app", "remove_managed_plugins", "recover_interrupted_promotion"),
                                          f'recover_interrupted_promotion "{recovery}" && echo RECOVERED',
                                          plist_read_fails=True)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertIn("could not read the restored service definition", result.stderr)
            log = root / "launchctl.log"
            self.assertNotIn("bootstrap", log.read_text() if log.exists() else "")

    def test_installer_scripts_run_with_pipefail(self) -> None:
        for name in ("preinstall", "postinstall", "uninstall.sh"):
            self.assertIn("\nset -euo pipefail\n", (BUILD_PKG.parent / name).read_text(), name)

    # ── PR #4482 review (Doomgoose blocker 3): the loose lane's code directory.
    def _loose_dir_harness(self, root: Path, body: str, owners: dict[str, str], script: str = "postinstall",
                           names: tuple[str, ...] = ("loose_code_directory_trusted",)) -> subprocess.CompletedProcess:
        source = (BUILD_PKG.parent / script).read_text()
        program = "\n".join(self._script_function(source, name) for name in names)
        local, local_bin = root / "ul", root / "ul/bin"
        program = (program.replace("for path in /usr/local /usr/local/bin", f'for path in "{local}" "{local_bin}"')
                   .replace("/usr/local/bin", str(local_bin)).replace("/usr/local/lib", str(root / "ul/lib"))
                   .replace("/usr/libexec/PlistBuddy", "plist_buddy"))
        cases = " ".join(f'"{path}") echo {uid} ;;' for path, uid in owners.items())
        stubs = f"""set -eu
stat() {{ if [[ "$2" == "%u" ]]; then case "$3" in {cases} *) echo 0 ;; esac; else command stat "$@"; fi; }}
launchctl() {{ echo "$*" >> "{root}/launchctl.log"; }}
require_started() {{ :; }}
plist_buddy() {{ echo {local_bin}/yuzu-agent; }}
ditto() {{ if [[ -d "$1" ]]; then mkdir -p "$2"; cp -R "$1/." "$2/"; else cp "$1" "$2"; fi; }}
STATE_DIR="{root}/state"; LEGACY_APP="{root}/data/YuzuAgent.app"; YUZU_LIB="{root}/ul/lib/yuzu"; APP_ROOT="{root}/app"
PLIST="{root}/LaunchDaemons/com.yuzu.agent.plist"; PLUGIN_DIR="{root}/ul/lib/yuzu/plugins"
"""
        return subprocess.run([PKG_SHELL, "-c", stubs + program + "\n" + body], text=True, capture_output=True)

    def test_loose_code_directory_must_be_root_owned_and_not_writable(self) -> None:
        with tempfile.TemporaryDirectory(prefix="yuzu_test_loose_dir_") as temporary:
            root = Path(temporary)
            local, local_bin = root / "ul", root / "ul/bin"
            local_bin.mkdir(parents=True)
            def trusted(owners: dict[str, str] | None = None) -> bool:
                result = self._loose_dir_harness(root, "loose_code_directory_trusted && echo TRUSTED", owners or {})
                return "TRUSTED" in result.stdout
            local.chmod(0o755); local_bin.chmod(0o755)
            self.assertTrue(trusted())
            local_bin.chmod(0o775)                            # Intel-Homebrew-style group-writable bin
            self.assertFalse(trusted())
            local_bin.chmod(0o755); local.chmod(0o777)        # writable parent: bin itself can be renamed
            self.assertFalse(trusted())
            local.chmod(0o755)
            self.assertFalse(trusted({str(local_bin): "501"}))  # user-owned bin
            local_bin.rmdir(); (root / "elsewhere").mkdir(); local_bin.symlink_to(root / "elsewhere")
            self.assertFalse(trusted())

    def test_loose_promotion_is_refused_before_the_active_service_is_touched(self) -> None:
        postinstall = (BUILD_PKG.parent / "postinstall").read_text()
        check = postinstall.index('if [[ "$MODE" == "loose" ]] && ! loose_code_directory_trusted; then')
        self.assertLess(postinstall.index("loose_code_directory_trusted() {"), check)
        self.assertLess(check, postinstall.index("require_stopped\nremove_managed_plugins"))
        self.assertLess(check, postinstall.index("printf 'promoting\\n'"))

    def test_recovery_does_not_start_a_loose_agent_from_an_untrusted_directory(self) -> None:
        with tempfile.TemporaryDirectory(prefix="yuzu_test_loose_recover_") as temporary:
            root = Path(temporary)
            recovery = root / "state/install-recovery.TEST"
            for folder in ("loose", "LaunchDaemons"):
                (recovery / folder).mkdir(parents=True)
            (recovery / "loose/yuzu-agent").write_text("previous loose agent")
            (recovery / "LaunchDaemons/com.yuzu.agent.plist").write_text("previous")
            for folder in ("ul/bin", "ul/lib/yuzu/plugins", "LaunchDaemons", "app", "data"):
                (root / folder).mkdir(parents=True, exist_ok=True)
            (root / "ul").chmod(0o755); (root / "ul/bin").chmod(0o775)
            result = self._loose_dir_harness(
                root, f'recover_interrupted_promotion "{recovery}" && echo RECOVERED', {}, script="preinstall",
                names=("loose_code_directory_trusted", "quarantine_legacy_app", "remove_managed_plugins",
                       "recover_interrupted_promotion"))
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertIn("RECOVERED", result.stdout)
            self.assertIn("did not start it", result.stderr)
            self.assertEqual((root / "ul/bin/yuzu-agent").read_text(), "previous loose agent")
            log = root / "launchctl.log"
            self.assertNotIn("bootstrap", log.read_text() if log.exists() else "")

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
    def test_native_plist_merge_fails_without_replacing_destination(self) -> None:
        with tempfile.TemporaryDirectory(prefix="yuzu_test_plist_native_") as temporary:
            root = Path(temporary)
            previous, destination = root / "previous.plist", root / "new.plist"
            sentinel = plistlib.dumps({"ProgramArguments": ["/new/agent"]})
            for prior in ({"ProgramArguments": []}, {"ProgramArguments": [42]},
                          {"ProgramArguments": ["/old/agent"], "EnvironmentVariables": []}):
                previous.write_bytes(plistlib.dumps(prior))
                destination.write_bytes(sentinel)
                result = subprocess.run(["/usr/bin/osascript", "-l", "JavaScript", str(MERGE_PLIST_HELPER),
                                         "--previous", str(previous), "--destination", str(destination)],
                                        text=True, capture_output=True)
                self.assertNotEqual(result.returncode, 0)
                self.assertEqual(destination.read_bytes(), sentinel)

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
        self.assertIn('recovery pointer must be root:wheel mode 600', preinstall)
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

    def test_recovery_clears_both_lanes_and_uninstall_removes_transition_paths(self) -> None:
        preinstall = (ROOT / "deploy/packaging/macos/preinstall").read_text()
        postinstall = (ROOT / "deploy/packaging/macos/postinstall").read_text()
        uninstall = (ROOT / "deploy/packaging/macos/uninstall.sh").read_text()
        self.assertIn('rm -f /usr/local/bin/yuzu-agent /usr/local/bin/libyuzu_agent_core.dylib /usr/local/lib/libyuzu_agent_core.dylib', postinstall)
        self.assertIn('remove_managed_plugins "$MANIFEST"', postinstall)
        self.assertIn('harden_managed_plugins "$MANIFEST"', postinstall)
        self.assertIn('collides with an unmanaged third-party plugin', postinstall)
        self.assertIn('reject_unmanaged_plugin_collisions()', postinstall)
        self.assertLess(postinstall.index('reject_unmanaged_plugin_collisions || exit 1'),
                        postinstall.index('require_stopped\nremove_managed_plugins'))
        self.assertEqual(postinstall.count('collides with an unmanaged third-party plugin'), 1)
        self.assertIn('remove_managed_plugins "$INCOMING_MANIFEST"', postinstall)
        self.assertIn('LEGACY_APP="$DATA_DIR/YuzuAgent.app"', preinstall)
        self.assertIn('legacy_app_is_managed()', preinstall)
        # Copy, then verify the copy (never the live path between check and copy).
        copy_at = preinstall.index('copy_if_present "$LEGACY_APP" "$RECOVERY/legacy/YuzuAgent.app"')
        verify_at = preinstall.index('legacy_app_is_managed "$RECOVERY/legacy/YuzuAgent.app" || rm -rf "$RECOVERY/legacy"')
        self.assertLess(copy_at, verify_at)
        self.assertNotIn('if legacy_app_is_managed; then', preinstall)
        self.assertIn('LEGACY_TEAM_ID="7RLSYL2JM7"', preinstall)
        self.assertIn('LEGACY_PROFILE_SHA256="3e764aafaa5cd29398ef6646b98c7b00332404c5ea57f79b92663695acdd70e1"', preinstall)
        self.assertIn('LEGACY_SIGNING_AUTHORITY="Mac Developer: Nathan Dornbrook (YA95685L8R)"', preinstall)
        self.assertIn('codesign -dvv "$candidate"', preinstall)
        self.assertIn('legacy-retired.app', postinstall)
        self.assertIn('retire_legacy_app', postinstall)
        self.assertIn('did not start it from non-package-owned data', preinstall)
        self.assertIn('did not start it from non-package-owned data', postinstall)
        self.assertIn('quarantine_legacy_app "$recovery/legacy-retired.app"', preinstall)
        self.assertIn('quarantine_legacy_app "$recovery/legacy-retired.app"', postinstall)
        self.assertNotIn('retained legacy app in root-owned recovery', preinstall + postinstall)
        self.assertIn('copy_if_present "$LEGACY_APP" "$RECOVERY/legacy/YuzuAgent.app"', preinstall)
        self.assertIn('retire_legacy_app', postinstall)
        self.assertNotIn('recovery/legacy/YuzuAgent.app', postinstall)
        self.assertIn('retire_legacy_app', uninstall)
        self.assertIn('"/Library/Application Support/Yuzu/YuzuAgent.app"', uninstall)
        self.assertIn('/usr/local/lib/yuzu/merge-launchd-plist.py', uninstall)
        self.assertIn('/usr/local/lib/yuzu/plugin-signing-policy.json', uninstall)
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
        self.assertIn('uninstall-legacy.*', package_readme)
        self.assertIn('exits nonzero', package_readme)
        self.assertIn('daemon remains unloaded until a later successful package', package_readme)
        self.assertIn('transition, so do not restart it before that inspection', package_readme)

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


if __name__ == "__main__":
    unittest.main()
