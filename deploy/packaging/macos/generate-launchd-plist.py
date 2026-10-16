#!/usr/bin/env python3
"""Create the bundle-mode LaunchDaemon plist without textual plist editing."""

from __future__ import annotations

import argparse
import json
import plistlib
from pathlib import Path


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--source", required=True)
    parser.add_argument("--output", required=True)
    parser.add_argument("--bundle-executable", required=True)
    parser.add_argument("--plugin-signing-policy")
    args = parser.parse_args()
    with Path(args.source).open("rb") as source:
        plist = plistlib.load(source)
    arguments = plist.get("ProgramArguments")
    if not isinstance(arguments, list) or not arguments:
        raise SystemExit("source plist has no ProgramArguments")
    plist["ProgramArguments"] = [args.bundle_executable, *arguments[1:]]
    if "--no-auto-update" not in plist["ProgramArguments"]:
        plist["ProgramArguments"].append("--no-auto-update")
    if args.plugin_signing_policy:
        policy = json.loads(Path(args.plugin_signing_policy).read_text())
        trust_bundle = policy.get("runtime_plugin_trust_bundle")
        if not isinstance(trust_bundle, str) or not trust_bundle:
            raise SystemExit("plugin signing policy has no runtime trust bundle")
        plist["ProgramArguments"].extend(
            ["--plugin-trust-bundle", trust_bundle, "--plugin-require-signature"])
    with Path(args.output).open("wb") as output:
        plistlib.dump(plist, output, sort_keys=False)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
