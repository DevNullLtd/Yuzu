#!/usr/bin/env python3
"""Extract one workflow step's `run: |` body, de-indented, for a hermetic shell test.

The tests under tests/shell/ execute the REAL step bodies out of the workflow
files rather than a copy, so they cannot drift into asserting a duplicate of the
logic instead of the logic. Select the step with `--id <step id>` or
`--name <step name>`. PyYAML (already a CI dependency) selects only actual
`jobs.*.steps` entries and decodes the selected literal scalar; step-shaped
text inside a shell heredoc cannot become a workflow step.

`--subst 'github.expr=VAR'` rewrites `${{ github.expr }}` to `$VAR` so the
harness can drive it; any other `${{` left in the body is an error, because the
shell cannot evaluate it and a silent leftover would make the test vacuous.

Usage: extract_run_block.py <workflow.yml> <out.sh> (--id ID | --name NAME) [--subst EXPR=VAR ...]
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

import yaml
from yaml.nodes import MappingNode, ScalarNode, SequenceNode


def field(node, key):
    if not isinstance(node, MappingNode):
        raise ValueError("expected a workflow mapping")
    matches = [value for name, value in node.value
               if isinstance(name, ScalarNode) and name.value == key]
    if len(matches) > 1:
        raise ValueError(f"duplicate workflow field {key!r}")
    return matches[0] if matches else None


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("workflow")
    ap.add_argument("out")
    sel = ap.add_mutually_exclusive_group(required=True)
    sel.add_argument("--id")
    sel.add_argument("--name")
    ap.add_argument("--subst", action="append", default=[])
    args = ap.parse_args()

    selector, wanted = ("id", args.id) if args.id else ("name", args.name)
    try:
        document = yaml.compose(Path(args.workflow).read_text(encoding="utf-8"),
                                Loader=yaml.SafeLoader)
        jobs = field(document, "jobs")
        if not isinstance(jobs, MappingNode):
            raise ValueError("workflow has no jobs mapping")
        matches = []
        for _, job in jobs.value:
            steps = field(job, "steps")
            if steps is None:  # reusable-workflow jobs have no local steps
                continue
            if not isinstance(steps, SequenceNode):
                raise ValueError("job steps must be a sequence")
            for step in steps.value:
                selected = field(step, selector)
                if isinstance(selected, ScalarNode) and selected.value == wanted:
                    matches.append(step)
        if len(matches) != 1:
            raise ValueError(f"expected exactly one step {selector}={wanted!r}, found {len(matches)}")
        run = field(matches[0], "run")
        if not isinstance(run, ScalarNode) or run.style != "|":
            raise ValueError("selected step has no literal run: | block")
        text = run.value
    except (OSError, ValueError, yaml.YAMLError) as exc:
        print(f"cannot extract workflow step from {args.workflow}: {exc}", file=sys.stderr)
        return 2
    for subst in args.subst:
        expr, var = subst.split("=", 1)
        text = text.replace("${{ " + expr + " }}", "$" + var)
    leftover = [line for line in text.split("\n") if "${{" in line]
    if leftover:
        print("unsubstituted GitHub expression in the extracted body:\n" + "\n".join(leftover), file=sys.stderr)
        return 2
    if not text.strip():
        print("extracted body is empty", file=sys.stderr)
        return 2
    Path(args.out).write_text(text if text.endswith("\n") else text + "\n", encoding="utf-8")
    return 0


if __name__ == "__main__":
    sys.exit(main())
