#!/usr/bin/env python3
"""Compile and run exactly one named gateway EUnit contract in a fresh VM.

REBAR_BASE_DIR must name a caller-owned build directory, separate from _build.
Compilation and execution share a 300-second deadline; killing/reaping a timed
out child gets at most 10 more seconds. Meson's outer timeout should be 330s.
This wrapper is for local process contracts: it starts no distribution/epmd.
"""

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import signal
import subprocess
import sys
import time

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from erlang_toolchain import (  # noqa: E402
    base_env, kill_tree, otp_version, rebar3_prefix, windows_stdio_isolation,
    uninterrupted_cleanup, termination_interrupt,
)
from gateway_test_summary import executed_count, strict_verdict  # noqa: E402

DEADLINE_SECONDS = 300


def run(command, gateway, env, deadline, log=None):
    """Capture native output; communicate bounds both pipe reads and exit wait."""
    remaining = deadline - time.monotonic()
    if remaining <= 0:
        raise RuntimeError("contract deadline exhausted before child startup")
    options = windows_stdio_isolation()
    options.setdefault("stdin", subprocess.DEVNULL)
    if os.name == "nt":
        options["creationflags"] |= subprocess.CREATE_NEW_PROCESS_GROUP
    else:
        options["start_new_session"] = True
    if log is not None:
        log.write_text("", encoding="utf-8")
    print("[gateway-contract] " + " ".join(command), flush=True)
    proc = subprocess.Popen(command, cwd=gateway, env=env,
                            stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                            text=True, encoding="utf-8", errors="replace", **options)
    try:
        output, _ = proc.communicate(timeout=remaining)
    except (subprocess.TimeoutExpired, KeyboardInterrupt) as exc:
        with uninterrupted_cleanup():
            killed = kill_tree(proc, timeout=5)
            try:
                output, _ = proc.communicate(timeout=5)
            except subprocess.TimeoutExpired:
                output = ""
                proc.stdout.close()
        if log is not None:
            log.write_text(output, encoding="utf-8")
        print(output, end="", flush=True)
        raise RuntimeError(
            f"contract interrupted or deadline exceeded ({type(exc).__name__}); "
            f"process-tree kill reported {'success' if killed else 'failure'}") from exc
    if log is not None:
        log.write_text(output, encoding="utf-8")
    print(output, end="", flush=True)
    return proc.returncode, output


def contract_verdict(output, code):
    verdict, _, message = strict_verdict(output, code)
    if not verdict and executed_count(output) != 1:
        return 1, "named contract must execute exactly one test"
    return (1 if verdict else 0), message


def beam_hashes(paths):
    # Hash code available to this VM, including dependency/test helpers. This
    # is not a claim that every listed module executed or a coverage report.
    return {str(beam): hashlib.sha256(beam.read_bytes()).hexdigest()
            for directory in paths for beam in sorted(Path(directory).glob("*.beam"))}


def evidence_directory(parent, identity):
    if not re.fullmatch(r"[A-Za-z0-9_.-]+", identity) or identity in (".", ".."):
        raise ValueError("invalid contract evidence ID")
    if parent is None:
        return None
    output = Path(parent) / identity
    output.mkdir(parents=True, exist_ok=False)
    return output


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("gateway_dir", type=Path)
    parser.add_argument("module")
    parser.add_argument("generator")
    parser.add_argument("--id", dest="contract_id")
    args = parser.parse_args()
    for atom in (args.module, args.generator):
        if not re.fullmatch(r"[a-z][A-Za-z0-9_]*", atom):
            parser.error("module and generator must be unquoted Erlang identifiers")
    gateway = args.gateway_dir.resolve()
    selected_base = os.environ.get("REBAR_BASE_DIR")
    if not selected_base:
        parser.error("REBAR_BASE_DIR must select an isolated build directory")
    base = (gateway / selected_base).resolve()
    if base == (gateway / "_build").resolve():
        parser.error("REBAR_BASE_DIR must be separate from gateway/_build")
    env = base_env()
    if not env.get("YUZU_OTP_BIN"):
        parser.error("no pinned Erlang/OTP toolchain found")
    env["REBAR_BASE_DIR"] = str(base)
    env.setdefault("ERL_CRASH_DUMP", str(base / "contract-erl-crash.dump"))
    identity = args.contract_id or f"{args.module}.{args.generator}"
    output_dir = evidence_directory(os.environ.get("YUZU_CONTRACT_EVIDENCE_DIR"), identity)
    metadata = {"schema_version": 1, "contract_id": identity,
                "module": args.module, "generator": args.generator,
                "status": "FAIL", "cases": 0, "build_directory": str(base),
                "otp_version": otp_version(env["YUZU_OTP_BIN"]),
                "otp_bin": env["YUZU_OTP_BIN"]}
    deadline = time.monotonic() + DEADLINE_SECONDS

    def capture(command, label):
        return run(command, gateway, env, deadline,
                   output_dir / (label + ".log") if output_dir else None)

    try:
        code, version = capture(rebar3_prefix() + ["--version"], "rebar-version")
        if code:
            raise RuntimeError("cannot identify rebar3 version")
        metadata["rebar_version"] = version.strip()
        code, _ = capture(rebar3_prefix() + ["as", "test", "compile"], "compile")
        if code:
            raise RuntimeError(f"test-profile compilation exited {code}")

        lib = base / "test" / "lib"
        tests = lib / "yuzu_gw" / "test"
        test_beam = tests / (args.module + ".beam")
        if not test_beam.is_file():
            raise RuntimeError(f"compiled test module missing: {args.module}")
        paths = [str(p) for p in sorted(lib.glob("*/ebin"))] + [str(tests)]
        metadata["beam_sha256"] = beam_hashes(paths)
        erl = str(Path(env["YUZU_OTP_BIN"]) / ("erl.exe" if os.name == "nt" else "erl"))
        # Runtime identity comes from the very VM executing the contract. The
        # fixed JSON marker is separate from EUnit's native completion summary.
        evaluation = (
            f"{{module,{args.module}}}=code:ensure_loaded({args.module}), "
            'io:format("GATEWAY_CONTRACT_RUNTIME=~s~n",[json:encode(#{'
            'otp_release=>list_to_binary(erlang:system_info(otp_release)),'
            'erts_version=>list_to_binary(erlang:system_info(version)),'
            'system_version=>list_to_binary(erlang:system_info(system_version)),'
            f'test_module_path=>unicode:characters_to_binary(code:which({args.module}))'
            '})]), '
            f"true=erlang:function_exported({args.module},{args.generator},0), "
            f"case eunit:test({args.module}:{args.generator}(),[verbose]) of "
            "ok -> halt(0); _ -> halt(1) end."
        )
        code, output = capture([erl, "-noshell", "-pa", *paths, "-eval", evaluation], "test")
        metadata["native_exit_code"] = code
        metadata["cases"] = executed_count(output) or 0
        verdict, message = contract_verdict(output, code)
        metadata["verdict"] = message
        markers = [line.removeprefix("GATEWAY_CONTRACT_RUNTIME=")
                   for line in output.splitlines() if line.startswith("GATEWAY_CONTRACT_RUNTIME=")]
        if len(markers) == 1:
            metadata["runtime"] = json.loads(markers[0])
        if verdict:
            return 1
        if len(markers) != 1:
            raise RuntimeError("missing or ambiguous native runtime identity")
        if Path(metadata["runtime"]["test_module_path"]).resolve() != test_beam.resolve():
            raise RuntimeError("VM loaded a different test module than the hashed artifact")
        if beam_hashes(paths) != metadata["beam_sha256"]:
            raise RuntimeError("compiled BEAM artifacts changed during contract execution")
        metadata["status"] = "PASS"
        return 0
    except Exception as exc:
        metadata["error"] = f"{type(exc).__name__}: {exc}"
        raise
    finally:
        serialized = json.dumps(metadata, sort_keys=True, indent=2) + "\n"
        if output_dir:
            (output_dir / "result.json").write_text(serialized, encoding="utf-8")
            print(f"[gateway-contract] {metadata['status']}: {output_dir / 'result.json'}", flush=True)
        else:
            print("GATEWAY_CONTRACT_EVIDENCE=" + json.dumps(metadata, sort_keys=True), flush=True)


if __name__ == "__main__":
    if os.name != "nt":
        signal.signal(signal.SIGTERM, termination_interrupt)
    try:
        sys.exit(main())
    except (OSError, RuntimeError, ValueError) as exc:
        print(f"gateway-contract: {exc}", file=sys.stderr)
        sys.exit(1)
