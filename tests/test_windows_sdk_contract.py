#!/usr/bin/env python3
"""Fail when Yuzu's reviewed Windows SDK contract drifts between boundaries."""

from __future__ import annotations

import pathlib
import re
import os
import shutil
import subprocess
import sys
import tempfile


ROOT = pathlib.Path(__file__).resolve().parent.parent
SDK = "10.0.26100.0"
ACTION = "ilammy/msvc-dev-cmd"
EXPECTED_WORKFLOWS = {
    "ci.yml",
    "codeql.yml",
    "instructions-windows-validate.yml",
    "nightly.yml",
    "release.yml",
}
USES_LINE = re.compile(
    rf"^(?P<indent>\s*)(?:-\s+)?uses:\s*(?P<quote>['\"]?)"
    rf"{re.escape(ACTION)}@(?P<ref>[^\s'\"#]+)(?P=quote)\s*(?:#.*)?$"
)


def workflow_files(root: pathlib.Path) -> list[pathlib.Path]:
    """Return both GitHub-supported workflow filename extensions."""
    return sorted((*root.glob("*.yml"), *root.glob("*.yaml")))


def action_steps(path: pathlib.Path) -> list[tuple[int, list[str]]]:
    """Return each named action step from ``path`` without a YAML dependency."""
    lines = path.read_text(encoding="utf-8").splitlines()
    steps: list[tuple[int, list[str]]] = []
    for index, line in enumerate(lines):
        match = USES_LINE.fullmatch(line)
        if not match:
            continue
        uses_indent = len(match.group("indent")) + (2 if line.lstrip().startswith("-") else 0)
        block = [line]
        for following in lines[index + 1 :]:
            if following.strip():
                indent = len(following) - len(following.lstrip())
                if indent < uses_indent:
                    break
            block.append(following)
        steps.append((index + 1, block))
    return steps


def sdk_inputs(block: list[str]) -> tuple[int, list[str]]:
    """Return (with-block count, direct ``with.sdk`` values) for one action step."""
    match = USES_LINE.fullmatch(block[0])
    if not match:
        return 0, []
    uses_indent = len(match.group("indent")) + (
        2 if block[0].lstrip().startswith("-") else 0
    )
    with_indexes = [
        offset
        for offset, line in enumerate(block[1:], start=1)
        if line.strip() == "with:"
        and len(line) - len(line.lstrip()) == uses_indent
    ]
    values: list[str] = []
    if len(with_indexes) == 1:
        for line in block[with_indexes[0] + 1 :]:
            if not line.strip():
                continue
            indent = len(line) - len(line.lstrip())
            if indent <= uses_indent:
                break
            if indent == uses_indent + 2 and line.strip().startswith("sdk:"):
                values.append(line.strip())
    return len(with_indexes), values


def mandatory_manifest_step(body: str) -> bool:
    """Return whether a workflow step unconditionally runs the assertion."""
    if re.search(
        r"(?im)^\s*(?:if|continue-on-error)\s*:|optional|skipping manifest|"
        r"if\s*\(\s*Test-Path|\|\|\s*true\b",
        body,
    ):
        return False
    run_lines = re.findall(r"(?m)^\s*run:\s*(.*?)\s*$", body)
    return len(run_lines) == 1 and bool(
        re.fullmatch(
            r"\./deploy/windows/Assert-Toolchain\.ps1\s+-ManifestPath\s+"
            r"'C:\\actions-runner\\toolchain-manifest\.json'",
            run_lines[0],
        )
    )


def msys_path(path: pathlib.Path) -> str:
    """Return a path that an MSYS2 bash process can open."""
    resolved = path.resolve()
    if sys.platform == "win32":
        drive, tail = resolved.drive, str(resolved)[len(resolved.drive) :]
        return f"/{drive[0].lower()}{tail.replace(chr(92), '/')}"
    return str(resolved)


def exercise_setup_sdk_preflight(setup: str, failures: list[str]) -> None:
    """Prove setup fails closed when any pinned SDK artifact is absent."""
    # Windows' PATH commonly resolves `bash` to System32\bash.exe (the WSL
    # launcher), which cannot source an MSYS2 /c/... fixture.  Exercise the
    # exact shell this setup contract supports instead.
    if sys.platform == "win32":
        msys_bash = pathlib.Path(r"C:\msys64\usr\bin\bash.exe")
        bash = str(msys_bash) if msys_bash.is_file() else None
    else:
        bash = shutil.which("bash")
    if not bash:
        failures.append("setup_msvc_env.sh regression requires bash on PATH")
        return

    with tempfile.TemporaryDirectory() as fixture_dir:
        fixture_root = pathlib.Path(fixture_dir)
        sdk_root = fixture_root / "Windows Kits" / "10"
        fixture_setup = fixture_root / "setup_msvc_env.sh"
        fixture_text = setup.replace(
            '_WIN_SDK="/c/Program Files (x86)/Windows Kits/10"',
            f'_WIN_SDK="{msys_path(sdk_root)}"',
        )
        if fixture_text == setup:
            failures.append("setup SDK-root fixture could not replace the canonical path")
            return
        fixture_setup.write_text(fixture_text, encoding="utf-8")

        artifacts = {
            "Windows.h": sdk_root / "Include" / SDK / "um" / "Windows.h",
            "kernel32.lib": sdk_root / "Lib" / SDK / "um" / "x64" / "kernel32.lib",
            "rc.exe": sdk_root / "bin" / SDK / "x64" / "rc.exe",
        }
        for artifact in artifacts.values():
            artifact.parent.mkdir(parents=True, exist_ok=True)
            artifact.touch()

        protected_exports = (
            "CC",
            "CXX",
            "VSCMD_VER",
            "TMP",
            "TEMP",
            "CMAKE_GENERATOR",
            "CMAKE_BUILD_TYPE",
            "VCPKG_ROOT",
            "CMAKE_TOOLCHAIN_FILE",
            "VCPKG_DEFAULT_TRIPLET",
            "INCLUDE",
            "LIB",
            "PATH",
        )
        internal_names = (
            "_MSVC_VER",
            "_SDK_VER",
            "_VS_ROOT",
            "_VS_INSTALLER",
            "_VC_TOOLS",
            "_WIN_SDK",
            "_VCPKG",
            "_PROJECT_ROOT",
            "_CMAKE_DIR",
            "_PYTHON_DIR",
            "_MESON_DIR",
            "_SDK_HEADER",
            "_SDK_LIB",
            "_SDK_RC",
            "_SDK_MISSING",
        )
        sentinel = "yuzu-sdk-preflight-sentinel"
        base_env = os.environ.copy()
        expected_exports = {
            name: (base_env.get(name, "") if name == "PATH" else sentinel)
            for name in protected_exports
        }

        def run_setup(mode: str) -> subprocess.CompletedProcess[str]:
            if mode == "source":
                command = (
                    'for name in ${PROTECTED_EXPORTS}; do '
                    'printf "BEFORE:%s=%s\\n" "$name" "${!name-__UNSET__}"; done; '
                    'source "$1"; rc=$?; '
                    'for name in ${PROTECTED_EXPORTS}; do '
                    'printf "STATE:%s=%s\\n" "$name" "${!name-__UNSET__}"; done; '
                    'for name in ${INTERNAL_NAMES}; do '
                    'printf "LOCAL:%s=%s\\n" "$name" "${!name-__UNSET__}"; done; '
                    'if declare -F _require_sdk_artifact >/dev/null; then '
                    'printf "FUNCTION:_require_sdk_artifact=SET\\n"; else '
                    'printf "FUNCTION:_require_sdk_artifact=__UNSET__\\n"; fi; '
                    'exit "$rc"'
                )
            else:
                command = ""
            env = base_env.copy()
            env.update(expected_exports)
            env["PROTECTED_EXPORTS"] = " ".join(protected_exports)
            env["INTERNAL_NAMES"] = " ".join(internal_names)
            argv = (
                [bash, "-c", command, "setup-sdk-regression", msys_path(fixture_setup)]
                if mode == "source"
                else [bash, msys_path(fixture_setup)]
            )
            return subprocess.run(
                argv,
                check=False,
                capture_output=True,
                text=True,
                env=env,
            )

        for mode in ("source", "execute"):
            complete = run_setup(mode)
            if complete.returncode != 0:
                failures.append(
                    f"setup ({mode}) rejected a complete pinned SDK fixture: "
                    f"{complete.stdout}{complete.stderr}".strip()
                )

        for name, artifact in artifacts.items():
            artifact.unlink()
            for mode in ("source", "execute"):
                missing = run_setup(mode)
                output = f"{missing.stdout}\n{missing.stderr}"
                if missing.returncode == 0:
                    failures.append(
                        f"setup ({mode}) accepted a pinned SDK fixture missing {name}"
                    )
                elif name not in output or SDK not in output:
                    failures.append(
                        f"setup ({mode}) failure for missing {name} did not identify "
                        f"the {SDK} artifact"
                    )
                if mode == "source":
                    before = {
                        line.removeprefix("BEFORE:").partition("=")[0]:
                        line.partition("=")[2]
                        for line in output.splitlines()
                        if line.startswith("BEFORE:")
                    }
                    after = {
                        line.removeprefix("STATE:").partition("=")[0]:
                        line.partition("=")[2]
                        for line in output.splitlines()
                        if line.startswith("STATE:")
                    }
                    for export_name in expected_exports:
                        if before.get(export_name) != after.get(export_name):
                            failures.append(
                                f"setup failure for missing {name} mutated {export_name}"
                            )
                    for internal_name in internal_names:
                        if f"LOCAL:{internal_name}=__UNSET__" not in output:
                            failures.append(
                                f"setup failure for missing {name} leaked {internal_name}"
                            )
                    if "FUNCTION:_require_sdk_artifact=__UNSET__" not in output:
                        failures.append(
                            f"setup failure for missing {name} leaked _require_sdk_artifact"
                        )
            artifact.touch()


def main() -> int:
    failures: list[str] = []

    with tempfile.TemporaryDirectory() as fixture_dir:
        fixture_root = pathlib.Path(fixture_dir)
        for name in ("first.yml", "second.yaml", "ignored.txt"):
            (fixture_root / name).touch()
        if [path.name for path in workflow_files(fixture_root)] != [
            "first.yml",
            "second.yaml",
        ]:
            failures.append("workflow inventory must scan both .yml and .yaml files")
        quoted_action = fixture_root / "quoted.yaml"
        quoted_action.write_text(
            "      - name: Quoted action fixture\n"
            f'        uses: "{ACTION}@{"a" * 40}" # v1.13.0\n'
            "        env:\n"
            f"          sdk: {SDK}\n",
            encoding="utf-8",
        )
        quoted_steps = action_steps(quoted_action)
        if len(quoted_steps) != 1 or sdk_inputs(quoted_steps[0][1]) != (0, []):
            failures.append(
                "action parser must discover a quoted uses scalar without "
                "false-greening sdk under env"
            )

    valid_fixture = [
        f"        uses: {ACTION}@{'a' * 40}",
        "        with:",
        f"          sdk: {SDK}",
    ]
    env_false_green_fixture = [
        f"        uses: {ACTION}@{'a' * 40}",
        "        env:",
        f"          sdk: {SDK}",
    ]
    if sdk_inputs(valid_fixture) != (1, [f"sdk: {SDK}"]):
        failures.append("action parser rejected a valid direct with.sdk input")
    if sdk_inputs(env_false_green_fixture) != (0, []):
        failures.append("action parser false-greened sdk under env instead of with")

    setup = (ROOT / "setup_msvc_env.sh").read_text(encoding="utf-8")
    setup_pins = re.findall(r'^_SDK_VER="([^"]+)"$', setup, re.MULTILINE)
    if setup_pins != [SDK]:
        failures.append(f"setup_msvc_env.sh _SDK_VER is {setup_pins!r}, expected [{SDK!r}]")
    exercise_setup_sdk_preflight(setup, failures)

    provision = (ROOT / "deploy/windows/Provision-Windows-Runner.ps1").read_text(
        encoding="utf-8"
    )
    required_provision_fragments = (
        f"[ValidateSet('{SDK}')][string]$WindowsSdkVersion = '{SDK}'",
        "Microsoft.VisualStudio.Component.Windows11SDK.26100",
        "windows_sdk=$WindowsSdkVersion",
        "name='windows_sdk_header'",
        "name='windows_sdk_lib'",
        "name='windows_sdk_rc'",
        "REBOOT REQUIRED ($context): keep every runner drained",
        "exit 3",
    )
    for fragment in required_provision_fragments:
        if fragment not in provision:
            failures.append(f"provisioning contract is missing {fragment!r}")

    nightly = (ROOT / ".github/workflows/nightly.yml").read_text(encoding="utf-8")
    nightly_manifest = re.search(
        r"(?ms)^\s*- name: Assert toolchain manifest \(self-hosted\)\s*$"
        r"(?P<body>.*?)(?=^\s*- name:|\Z)",
        nightly,
    )
    if not nightly_manifest or not mandatory_manifest_step(nightly_manifest.group("body")):
        failures.append("nightly Windows job does not require Assert-Toolchain.ps1")
    disabled_manifest_fixture = (
        "        if: false\n"
        "        run: ./deploy/windows/Assert-Toolchain.ps1 -ManifestPath fixture\n"
    )
    if mandatory_manifest_step(disabled_manifest_fixture):
        failures.append("nightly manifest checker accepted a workflow-level if: false")
    for suppression in (
        "        continue-on-error: true\n"
        "        run: ./deploy/windows/Assert-Toolchain.ps1 -ManifestPath "
        "'C:\\actions-runner\\toolchain-manifest.json'\n",
        "        run: ./deploy/windows/Assert-Toolchain.ps1 -ManifestPath "
        "'C:\\actions-runner\\toolchain-manifest.json' || true\n",
    ):
        if mandatory_manifest_step(suppression):
            failures.append("nightly manifest checker accepted failure suppression")

    contract = (ROOT / "deploy/windows/toolchain-contract.json").read_text(
        encoding="utf-8"
    )
    required_contract_fragments = (
        f'"windows_sdk": "{SDK}"',
        '"windows_sdk_header"',
        '"windows_sdk_lib"',
        '"windows_sdk_rc"',
        '"artifact_probes"',
    )
    for fragment in required_contract_fragments:
        if fragment not in contract:
            failures.append(f"reviewed toolchain contract is missing {fragment!r}")

    contract_tests = (ROOT / "deploy/windows/Test-ToolchainContract.ps1").read_text(
        encoding="utf-8"
    )
    for fragment in (
        "an omitted Windows SDK library fails",
        "a stale Windows SDK artifact version fails",
        "a Windows SDK artifact from another target directory fails",
    ):
        if fragment not in contract_tests:
            failures.append(f"toolchain contract tests are missing {fragment!r}")

    for relative in (
        "docs/windows-build.md",
        "deploy/windows/README.md",
        "docs/dependency-updates.md",
    ):
        text = (ROOT / relative).read_text(encoding="utf-8")
        if SDK not in text:
            failures.append(f"{relative} does not name the reviewed SDK target {SDK}")
    maintenance_docs = (ROOT / "deploy/windows/README.md").read_text(encoding="utf-8")
    for evidence in (
        "reviewed PR and exact commit",
        "manifest hash",
        "native validation `/test` run ID",
        "reboot or rollback outcome",
    ):
        if evidence not in maintenance_docs:
            failures.append(f"maintenance evidence checklist is missing {evidence!r}")

    workflows = ROOT / ".github/workflows"
    found_workflows: set[str] = set()
    for path in workflow_files(workflows):
        for line_number, block in action_steps(path):
            found_workflows.add(path.name)
            uses_line = block[0].strip()
            if not re.fullmatch(
                rf"(?:-\s+)?uses:\s*(?P<quote>['\"]?){re.escape(ACTION)}@"
                rf"[0-9a-f]{{40}}(?P=quote)\s+#\s+v\d+\.\d+\.\d+",
                uses_line,
            ):
                failures.append(
                    f"{path.relative_to(ROOT)}:{line_number}: action must remain "
                    "SHA-pinned with a version comment so Dependabot can update it"
                )
            with_count, sdk_lines = sdk_inputs(block)
            if with_count != 1:
                failures.append(
                    f"{path.relative_to(ROOT)}:{line_number}: action step has "
                    f"{with_count} with blocks, expected exactly 1"
                )
            if sdk_lines != [f"sdk: {SDK}"]:
                failures.append(
                    f"{path.relative_to(ROOT)}:{line_number}: sdk input is "
                    f"{sdk_lines!r}, expected ['sdk: {SDK}']"
                )

    if found_workflows != EXPECTED_WORKFLOWS:
        failures.append(
            "msvc-dev-cmd workflow inventory drifted: "
            f"found {sorted(found_workflows)}, expected {sorted(EXPECTED_WORKFLOWS)}"
        )

    dependabot = (ROOT / ".github/dependabot.yml").read_text(encoding="utf-8")
    gha_entry = re.search(
        r'(?ms)^\s*- package-ecosystem: ["\']github-actions["\']\s*$'
        r'(?P<body>.*?)(?=^\s*- package-ecosystem:|\Z)',
        dependabot,
    )
    if not gha_entry:
        failures.append(".github/dependabot.yml has no github-actions entry")
    else:
        body = gha_entry.group("body")
        for expected in ('directory: "/"', 'target-branch: "dev"'):
            if expected not in body:
                failures.append(f"github-actions Dependabot entry is missing {expected!r}")

    if failures:
        print("Windows SDK contract FAILED:")
        for failure in failures:
            print(f"  - {failure}")
        return 1

    print(
        f"Windows SDK contract OK ({SDK}; {len(EXPECTED_WORKFLOWS)} workflows; "
        "GHA action Dependabot-tracked)"
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
