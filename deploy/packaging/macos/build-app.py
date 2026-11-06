#!/usr/bin/env python3
"""Stage and sign the opt-in Yuzu macOS Endpoint Security development bundle.

The script intentionally accepts an original provisioning-profile CMS blob, not
decoded profile XML. It is a development packaging tool; it neither installs a
LaunchDaemon nor changes keychain, TCC, SIP, or release-signing state.
"""

from __future__ import annotations

import argparse
import base64
import datetime as dt
import hashlib
import json
import os
import plistlib
import re
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import Iterable


class BundleError(RuntimeError):
    pass


def run(argv: list[str], *, text: bool = True) -> str:
    try:
        completed = subprocess.run(argv, check=True, text=text, stdout=subprocess.PIPE,
                                   stderr=subprocess.PIPE)
    except FileNotFoundError as error:
        raise BundleError(f"required macOS tool is unavailable: {argv[0]}") from error
    except subprocess.CalledProcessError as error:
        detail = error.stderr.strip() if text else ""
        raise BundleError(f"command failed ({' '.join(argv[:2])}): {detail}") from error
    return completed.stdout if text else ""


def profile_fingerprint(der: bytes) -> str:
    return hashlib.sha1(der).hexdigest().upper()


def parse_profile(profile_path: Path) -> dict:
    decoded = run(["security", "cms", "-D", "-i", str(profile_path)])
    try:
        result = plistlib.loads(decoded.encode())
    except plistlib.InvalidFileException as error:
        raise BundleError("security cms produced an invalid provisioning-profile plist") from error
    if not isinstance(result, dict):
        raise BundleError("decoded provisioning profile is not a dictionary")
    return result


def profile_certificate_fingerprints(profile: dict) -> set[str]:
    certificates = profile.get("DeveloperCertificates")
    if not isinstance(certificates, list) or not certificates:
        raise BundleError("profile has no DeveloperCertificates")
    result: set[str] = set()
    for certificate in certificates:
        if not isinstance(certificate, bytes):
            raise BundleError("profile DeveloperCertificates contains a non-DER value")
        result.add(profile_fingerprint(certificate))
    return result


def parse_profile_date(value: object, name: str) -> dt.datetime:
    if not isinstance(value, dt.datetime):
        raise BundleError(f"profile {name} is missing or malformed")
    return value.replace(tzinfo=value.tzinfo or dt.timezone.utc).astimezone(dt.timezone.utc)


def profile_app_identity(profile: dict) -> tuple[str, str, str]:
    entitlements = profile.get("Entitlements")
    if not isinstance(entitlements, dict):
        raise BundleError("profile has no Entitlements dictionary")
    # macOS provisioning profiles use the documented com.apple key. Retain the
    # legacy spelling for older profile encoders, but never let two disagree.
    macos_app_id = entitlements.get("com.apple.application-identifier")
    legacy_app_id = entitlements.get("application-identifier")
    if macos_app_id is not None and legacy_app_id is not None and macos_app_id != legacy_app_id:
        raise BundleError("profile application-identifier keys disagree")
    app_id = macos_app_id if macos_app_id is not None else legacy_app_id
    team_id = entitlements.get("com.apple.developer.team-identifier")
    if not isinstance(app_id, str) or "." not in app_id:
        raise BundleError("profile application-identifier is missing or malformed")
    if not isinstance(team_id, str) or not team_id:
        raise BundleError("profile team identifier is missing or malformed")
    prefix, bundle_id = app_id.split(".", 1)
    if not prefix or not bundle_id:
        raise BundleError("profile application-identifier is missing its prefix or bundle ID")
    return prefix, bundle_id, team_id


def validate_profile(profile: dict, bundle_id: str, *, now: dt.datetime | None = None,
                     device_id: str | None = None, signer_fingerprint: str | None = None) -> tuple[str, str]:
    """Validate decoded profile fields without claiming its CMS is authentic."""
    now = (now or dt.datetime.now(dt.timezone.utc)).astimezone(dt.timezone.utc)
    # Apple's provisioning-profile schema still serialises the macOS platform
    # as "OSX" on current developer profiles. Accept that spelling as macOS;
    # it is not an iOS profile fallback.
    platforms = profile.get("Platform")
    if not isinstance(platforms, list) or not {"macOS", "OSX"}.intersection(platforms):
        raise BundleError("profile is not authorized for the macOS platform")
    if parse_profile_date(profile.get("ExpirationDate"), "ExpirationDate") <= now:
        raise BundleError("profile is expired")
    if parse_profile_date(profile.get("CreationDate"), "CreationDate") > now:
        raise BundleError("profile is not yet valid")
    entitlements = profile.get("Entitlements")
    assert isinstance(entitlements, dict)
    if entitlements.get("com.apple.developer.endpoint-security.client") is not True:
        raise BundleError("profile Endpoint Security entitlement must be Boolean true")
    prefix, authorized_bundle_id, team_id = profile_app_identity(profile)
    if authorized_bundle_id != bundle_id:
        raise BundleError("requested bundle ID does not match profile application-identifier")
    team_ids = profile.get("TeamIdentifier")
    if not isinstance(team_ids, list) or team_id not in team_ids:
        raise BundleError("profile TeamIdentifier does not match entitlement team identifier")
    if device_id is not None and not profile.get("ProvisionsAllDevices", False):
        devices = profile.get("ProvisionedDevices")
        if not isinstance(devices, list) or device_id not in devices:
            raise BundleError("this Mac is not eligible under the development provisioning profile")
    if signer_fingerprint is not None and signer_fingerprint.upper() not in profile_certificate_fingerprints(profile):
        raise BundleError("selected signing certificate is not authorized by the provisioning profile")
    return prefix, team_id


_IDENTITY = re.compile(r"^\s*\d+\)\s+([0-9A-F]{40})\s+\"(.+)\"$")


def signing_identities() -> list[tuple[str, str]]:
    output = run(["security", "find-identity", "-v", "-p", "codesigning"])
    identities: list[tuple[str, str]] = []
    for line in output.splitlines():
        match = _IDENTITY.match(line)
        if match and ("Apple Development" in match.group(2) or "Mac Developer" in match.group(2)):
            identities.append((match.group(1), match.group(2)))
    return identities


def select_identity(requested: str, profile: dict) -> tuple[str, str]:
    matches = [(fingerprint, name) for fingerprint, name in signing_identities()
               if requested == fingerprint or requested == name]
    if not matches:
        raise BundleError("no matching Apple Development or Mac Developer signing identity is available")
    if len(matches) != 1:
        raise BundleError("signing identity is ambiguous; use its SHA-1 fingerprint")
    fingerprint, name = matches[0]
    if fingerprint not in profile_certificate_fingerprints(profile):
        raise BundleError("selected signing certificate is not authorized by the provisioning profile")
    return fingerprint, name


_PROVISIONING_UDID = re.compile(
    r"^\s*Provisioning UDID:\s*([0-9A-Fa-f]+(?:-[0-9A-Fa-f]+)+)\s*$", re.MULTILINE)


def provisioning_udid_from_system_profiler(output: str) -> str:
    """Extract the Apple Developer registration ID without substituting Hardware UUID."""
    matches = _PROVISIONING_UDID.findall(output)
    if len(matches) != 1:
        raise BundleError("could not determine a unique Provisioning UDID for this Mac")
    return matches[0]


def local_device_id() -> str:
    output = run(["/usr/sbin/system_profiler", "SPHardwareDataType"])
    return provisioning_udid_from_system_profiler(output)


def require_es_sdk() -> None:
    sdk = Path(run(["xcrun", "--sdk", "macosx", "--show-sdk-path"]).strip())
    header = sdk / "usr/include/EndpointSecurity/EndpointSecurity.h"
    linker_stub = sdk / "usr/lib/libEndpointSecurity.tbd"
    if not header.is_file() or not linker_stub.is_file():
        raise BundleError("the active SDK must ship the EndpointSecurity header and linker stub for this bundle lane")


def find_first(paths: Iterable[Path]) -> Path:
    for path in paths:
        if path.is_file():
            return path
    raise BundleError("required agent executable or core library was not found in --bin-dir")


def find_plugins(bin_dir: Path) -> list[Path]:
    roots = [bin_dir / "plugins", bin_dir / "agents/plugins"]
    found: dict[str, Path] = {}
    for root in roots:
        if not root.is_dir():
            continue
        for plugin in root.rglob("*.dylib"):
            prior = found.setdefault(plugin.name, plugin)
            if prior != plugin:
                raise BundleError(f"duplicate plugin output basename: {plugin.name}")
    plugins = list(found.values())
    if not any(plugin.name == "echo.dylib" for plugin in plugins):
        raise BundleError("Echo plugin is required in the development bundle")
    return plugins


_DYLIB_DEPENDENCY_COMMANDS = frozenset({
    "LC_LOAD_DYLIB",
    "LC_LOAD_WEAK_DYLIB",
    "LC_REEXPORT_DYLIB",
    "LC_LOAD_UPWARD_DYLIB",
    "LC_LAZY_LOAD_DYLIB",
})
_MACOS_DEPLOYMENT_TARGET = "13.3"


def macho_architectures(path: Path) -> frozenset[str]:
    """Return the complete Mach-O slice set, without inferring it from a host."""
    architectures = frozenset(run(["lipo", "-archs", str(path)]).split())
    if not architectures:
        raise BundleError(f"Mach-O {path.name} has no architectures")
    return architectures


def require_matching_architectures(reference: Path, paths: Iterable[Path]) -> None:
    """Require every distributable Mach-O to have the agent's exact slice set."""
    expected = macho_architectures(reference)
    for path in paths:
        actual = macho_architectures(path)
        if actual != expected:
            raise BundleError(
                f"{path.name} architectures {', '.join(sorted(actual))}, expected "
                f"{', '.join(sorted(expected))} to match {reference.name}")


def macho_deployment_targets(path: Path) -> list[str]:
    """Read every architecture's minimum macOS version from load commands."""
    lines = run(["otool", "-l", str(path)]).splitlines()
    targets: list[str] = []
    for index, line in enumerate(lines):
        if line.strip() != "cmd LC_BUILD_VERSION":
            continue
        for detail in lines[index + 1:]:
            if detail.startswith("Load command "):
                break
            minimum = re.match(r"\s*minos\s+(\d+(?:\.\d+)*)\s*$", detail)
            if minimum is not None:
                targets.append(minimum.group(1))
                break
    if not targets:
        raise BundleError(f"Mach-O {path.name} has no LC_BUILD_VERSION deployment target")
    return targets


def require_macos_deployment_target(paths: Iterable[Path]) -> None:
    for path in paths:
        actual = macho_deployment_targets(path)
        if any(target != _MACOS_DEPLOYMENT_TARGET for target in actual):
            raise BundleError(
                f"{path.name} targets macOS {', '.join(actual)}, expected {_MACOS_DEPLOYMENT_TARGET}; "
                "rebuild with meson/native/macos-appleclang.ini")


def otool_dependencies(path: Path) -> list[str]:
    """Return every dylib dependency recorded in Mach-O load commands.

    ``otool -L`` is useful for human inspection but intentionally prints a
    dylib's ``LC_ID_DYLIB`` together with its imported libraries.  Its first
    entry happens to be the install name for a normal dylib, but that is a
    presentation convention, not an eligibility rule for relocation.  Read
    ``otool -l`` instead so executables, dylibs, weak links, re-exports, and
    upward/lazy links are classified by their actual load-command type.
    """
    lines = run(["otool", "-l", str(path)]).splitlines()
    dependencies: list[str] = []
    for index, line in enumerate(lines):
        command = re.match(r"\s*cmd\s+(LC_[A-Z_]+)\s*$", line)
        if command is None or command.group(1) not in _DYLIB_DEPENDENCY_COMMANDS:
            continue
        for detail in lines[index + 1:]:
            if detail.startswith("Load command "):
                raise BundleError(f"Mach-O dependency command in {path.name} has no install name")
            name = re.match(r"\s*name\s+(.+?)\s+\(offset\s+\d+\)\s*$", detail)
            if name is not None:
                dependencies.append(name.group(1))
                break
        else:
            raise BundleError(f"Mach-O dependency command in {path.name} has no install name")
    return dependencies


def otool_rpaths(path: Path) -> list[str]:
    lines = run(["otool", "-l", str(path)]).splitlines()
    result: list[str] = []
    for index, line in enumerate(lines):
        if line.strip() == "cmd LC_RPATH":
            for candidate in lines[index + 1:index + 6]:
                match = re.match(r"\s*path\s+([^ ]+)", candidate)
                if match:
                    result.append(match.group(1))
                    break
    return result


def is_system_dependency(name: str) -> bool:
    return name.startswith("/System/Library/") or name.startswith("/usr/lib/")


def resolve_dependency(name: str, source: Path) -> Path | None:
    if is_system_dependency(name):
        return None
    candidates: list[Path] = []
    if name.startswith("@loader_path/"):
        candidates.append(source.parent / name.removeprefix("@loader_path/"))
    elif name.startswith("@executable_path/"):
        candidates.append(source.parent / name.removeprefix("@executable_path/"))
    elif name.startswith("@rpath/"):
        suffix = name.removeprefix("@rpath/")
        for rpath in otool_rpaths(source):
            rpath = rpath.replace("@loader_path", str(source.parent))
            candidates.append(Path(rpath) / suffix)
    elif name.startswith("/"):
        candidates.append(Path(name))
    else:
        raise BundleError(f"unsupported Mach-O dependency reference: {name}")
    for candidate in candidates:
        if candidate.is_file():
            return candidate.resolve()
    raise BundleError(f"unresolved Mach-O dependency {name} referenced by {source.name}")


def copy_dependency_closure(initial: list[Path], frameworks: Path) -> dict[Path, Path]:
    copied: dict[Path, Path] = {}
    pending = list(initial)
    while pending:
        source = pending.pop()
        if source in copied:
            continue
        destination = frameworks / source.name
        if destination.exists():
            raise BundleError(f"conflicting dependency basename: {source.name}")
        shutil.copy2(source, destination, follow_symlinks=True)
        copied[source.resolve()] = destination
        for dependency in otool_dependencies(source):
            resolved = resolve_dependency(dependency, source)
            if resolved is not None and resolved.resolve() not in copied:
                pending.append(resolved.resolve())
    return copied


def replace_rpaths(path: Path, rpaths: list[str]) -> None:
    for rpath in otool_rpaths(path):
        run(["install_name_tool", "-delete_rpath", rpath, str(path)])
    for rpath in rpaths:
        run(["install_name_tool", "-add_rpath", rpath, str(path)])


def relocate(path: Path, copied: dict[Path, Path], *, executable: bool, source: Path | None = None) -> None:
    source = source or path
    for dependency in otool_dependencies(path):
        resolved = resolve_dependency(dependency, source) if not is_system_dependency(dependency) else None
        if resolved is not None and resolved.resolve() in copied:
            run(["install_name_tool", "-change", dependency, f"@rpath/{copied[resolved.resolve()].name}", str(path)])
        elif resolved is not None:
            raise BundleError(f"unpackaged non-system dependency {dependency} in {path.name}")
    if not executable:
        run(["install_name_tool", "-id", f"@rpath/{path.name}", str(path)])
    replace_rpaths(path, ["@executable_path/../Frameworks"] if executable else ["@loader_path"])


def sign(path: Path, identity: str, *, entitlements: Path | None = None) -> None:
    command = ["codesign", "--force", "--sign", identity, "--options", "runtime", "--timestamp=none"]
    if entitlements is not None:
        command += ["--entitlements", str(entitlements)]
    run(command + [str(path)])


def verify_code(path: Path) -> None:
    run(["codesign", "--verify", "--deep", "--strict", "--verbose=2", str(path)])


def ensure_no_build_paths(paths: Iterable[Path]) -> None:
    prohibited = ("vcpkg_installed", "build-macos", "/opt/homebrew", "/usr/local/Cellar")
    for path in paths:
        report = run(["otool", "-L", str(path)]) + run(["otool", "-l", str(path)])
        if any(value in report for value in prohibited):
            raise BundleError(f"build-machine dependency or rpath remains in {path.name}")


def verify_final_plugin_sidecar(verifier: Path, plugin: Path, trust_bundle: Path) -> None:
    """Use the agent's shared CMS verifier on the post-signing plugin bytes."""
    run([str(verifier), "--verify-plugin-signature", str(plugin),
         "--plugin-trust-bundle", str(trust_bundle)])


def build(args: argparse.Namespace) -> Path:
    bin_dir, profile_path, output = Path(args.bin_dir), Path(args.profile), Path(args.output_dir)
    if output.exists() and any(output.iterdir()):
        raise BundleError("--output-dir already exists and is populated")
    if not profile_path.is_file():
        raise BundleError("provisioning profile does not exist")
    profile = parse_profile(profile_path)
    validate_profile(profile, args.bundle_id, device_id=local_device_id())
    _fingerprint, identity = select_identity(args.sign_identity, profile)
    require_es_sdk()
    agent = find_first([bin_dir / "yuzu-agent", bin_dir / "agents/core/yuzu-agent"])
    core = find_first([bin_dir / "libyuzu_agent_core.dylib", bin_dir / "agents/core/libyuzu_agent_core.dylib"])
    plugins = find_plugins(bin_dir)
    require_matching_architectures(agent, [core, *plugins])
    require_macos_deployment_target([agent, core, *plugins])
    signed_sources = [plugin for plugin in plugins if Path(str(plugin) + ".sig").is_file()]
    trust_bundle = Path(args.plugin_trust_bundle) if args.plugin_trust_bundle else None
    if signed_sources and len(signed_sources) != len(plugins):
        raise BundleError("all external plugins must have CMS sidecars when CMS signature enforcement is enabled")
    if signed_sources and (trust_bundle is None or not trust_bundle.is_file() or
                           not args.runtime_plugin_trust_bundle or not args.final_plugin_sig_dir):
        raise BundleError("plugins with CMS sidecars require --plugin-trust-bundle and "
                          "--runtime-plugin-trust-bundle")

    prefix, _profile_bundle_id, team_id = profile_app_identity(profile)
    parent = output.parent.resolve()
    parent.mkdir(parents=True, exist_ok=True)
    staging = Path(tempfile.mkdtemp(prefix="yuzu_bundle_", dir=parent))
    try:
        app = staging / "YuzuAgent.app"
        contents, macos, frameworks = app / "Contents", app / "Contents/MacOS", app / "Contents/Frameworks"
        macos.mkdir(parents=True)
        frameworks.mkdir()
        shutil.copy2(agent, macos / "yuzu-agent")
        shutil.copy2(profile_path, contents / "embedded.provisionprofile")
        plistlib.dump({"CFBundleIdentifier": args.bundle_id, "CFBundleExecutable": "yuzu-agent",
                       "CFBundlePackageType": "APPL", "CFBundleName": "Yuzu Agent",
                       "CFBundleShortVersionString": args.version, "CFBundleVersion": args.version,
                       "LSMinimumSystemVersion": "13.3"}, (contents / "Info.plist").open("wb"))
        entitlements = staging / "agent-entitlements.plist"
        plistlib.dump({"com.apple.developer.endpoint-security.client": True,
                       "com.apple.application-identifier": f"{prefix}.{args.bundle_id}",
                       "com.apple.developer.team-identifier": team_id}, entitlements.open("wb"))
        copied = copy_dependency_closure([core], frameworks)
        copied[core.resolve()] = frameworks / core.name
        for source, destination in copied.items():
            relocate(destination, copied, executable=False, source=source)
        relocate(macos / "yuzu-agent", copied, executable=True, source=agent)

        plugin_dir = staging / "plugins"
        plugin_dir.mkdir()
        for plugin in plugins:
            destination = plugin_dir / plugin.name
            shutil.copy2(plugin, destination)
            relocate(destination, copied, executable=False, source=plugin)
            sign(destination, identity)
            sidecar = Path(str(plugin) + ".sig")
            if sidecar.exists():
                final_sidecar = Path(args.final_plugin_sig_dir) / sidecar.name
                if not final_sidecar.is_file():
                    raise BundleError(f"{sidecar.name} covers pre-signing bytes; provide a final-byte sidecar")
                shutil.copy2(final_sidecar, plugin_dir / sidecar.name)
        staged_machos = [*frameworks.iterdir(), *plugin_dir.glob("*.dylib")]
        require_matching_architectures(macos / "yuzu-agent", staged_machos)
        require_macos_deployment_target([macos / "yuzu-agent", *staged_machos])
        for library in frameworks.iterdir():
            sign(library, identity)
        sign(app, identity, entitlements=entitlements)
        verify_code(app)
        if signed_sources:
            assert trust_bundle is not None
            for plugin in plugin_dir.glob("*.dylib"):
                if (plugin_dir / f"{plugin.name}.sig").is_file():
                    verify_final_plugin_sidecar(macos / "yuzu-agent", plugin, trust_bundle)
            (plugin_dir / "plugin-signing-policy.json").write_text(json.dumps({
                "runtime_plugin_trust_bundle": args.runtime_plugin_trust_bundle,
            }, sort_keys=True) + "\n")
        for plugin in plugin_dir.glob("*.dylib"):
            verify_code(plugin)
        ensure_no_build_paths([macos / "yuzu-agent", *frameworks.iterdir(), *plugin_dir.glob("*.dylib")])
        if output.exists():
            output.rmdir()
        output.mkdir()
        shutil.move(str(app), output / "YuzuAgent.app")
        shutil.move(str(plugin_dir), output / "plugins")
        return output
    except Exception:
        shutil.rmtree(staging, ignore_errors=True)
        raise
    finally:
        if staging.exists():
            shutil.rmtree(staging, ignore_errors=True)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--bin-dir", required=True)
    parser.add_argument("--version", required=True)
    parser.add_argument("--bundle-id", required=True)
    parser.add_argument("--profile", required=True)
    parser.add_argument("--sign-identity", required=True)
    parser.add_argument("--output-dir", required=True)
    parser.add_argument("--final-plugin-sig-dir", help="directory containing final-byte CMS sidecars")
    parser.add_argument("--plugin-trust-bundle", help="PEM trust bundle for final-byte CMS verification")
    parser.add_argument("--runtime-plugin-trust-bundle",
                        help="installed PEM trust-bundle path to enforce when sidecars exist")
    args = parser.parse_args(argv)
    try:
        result = build(args)
    except BundleError as error:
        print(f"ERROR: {error}", file=sys.stderr)
        return 1
    print(result)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
