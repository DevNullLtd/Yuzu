#!/usr/bin/env python3
"""check-definition-descriptions.py - description-quality ratchet over content/definitions/*.yaml.

The description text of a shipped InstructionDefinition is what an agentic worker reads through
`discover_instructions` / `get_definition` to decide whether and how to run it. Nothing used to
check it, so this lints the objectively checkable part, per definition:

  definition-description        metadata.description is present, at least 40 characters after
                                whitespace collapse, and not just the definition's displayName
                                or id (compared case-insensitively)
  parameter-description         every parameter under spec.parameters.properties has a
                                description of at least 10 characters (after collapse)
  result-column-description      every column under spec.result.columns has a non-blank description
  tags                           metadata.tags is a non-empty list

It is a RATCHET over scripts/ci/definition-descriptions-baseline.json, which lists the failures
that already existed when the rule landed:

  (a) a failure that is NOT in the baseline fails the run (a new or edited definition must pass);
  (b) a baselined failure that no longer fails ALSO fails the run (the baseline may only shrink:
      delete the entry in the same change that fixed it).

`--update-baseline` rewrites the baseline from the current tree. Run it deliberately, after
reviewing a change that legitimately alters the tree or the rules, never to hide a new failure; it
never runs in CI.

Entry keys: `<definition id>` for definition-level rules, `<definition id>:<parameter>` and
`<definition id>:<column>` for the per-item rules.

Needs PyYAML (the same dependency server/core/scripts/embed_content.py has at build time).
Exit 0 = clean, 1 = ratchet violation, 2 = usage or parse error.
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

try:
    import yaml  # type: ignore[import-not-found]
except ImportError:  # pragma: no cover - exercised only on a host without PyYAML
    sys.stderr.write("check-definition-descriptions: PyYAML is required (pip install pyyaml)\n")
    sys.exit(2)

REPO_ROOT = Path(__file__).resolve().parents[2]
DEFAULT_DEFINITIONS = REPO_ROOT / "content" / "definitions"
DEFAULT_BASELINE = Path(__file__).resolve().parent / "definition-descriptions-baseline.json"

MIN_DEFINITION_DESCRIPTION = 40
MIN_PARAMETER_DESCRIPTION = 10

RULES = (
    "definition-description",
    "parameter-description",
    "result-column-description",
    "tags",
)

# What a failing entry has to satisfy, printed with every NEW violation so a failing author need
# not open this script.
REQUIREMENTS = {
    "definition-description": (
        f"metadata.description must be at least {MIN_DEFINITION_DESCRIPTION} characters and not "
        "just the definition's displayName or id"
    ),
    "parameter-description": (
        f"the parameter needs a description of at least {MIN_PARAMETER_DESCRIPTION} characters"
    ),
    "result-column-description": "the result column needs a non-blank description",
    "tags": "metadata.tags must list at least one non-blank tag",
}


def collapse(value: object) -> str:
    """Whitespace-collapsed text of a YAML scalar; non-scalars count as empty."""
    if value is None or isinstance(value, (dict, list)):
        return ""
    return " ".join(str(value).split())


def lint_definition(doc: dict, fallback_id: str) -> tuple[str, dict[str, set[str]]]:
    """(definition id, {rule: {entry key, ...}}) for one InstructionDefinition document."""
    metadata = doc.get("metadata") if isinstance(doc.get("metadata"), dict) else {}
    spec = doc.get("spec") if isinstance(doc.get("spec"), dict) else {}
    def_id = collapse(metadata.get("id")) or fallback_id
    failures: dict[str, set[str]] = {rule: set() for rule in RULES}

    description = collapse(metadata.get("description"))
    names = {collapse(metadata.get("displayName")).lower(), def_id.lower()} - {""}
    if len(description) < MIN_DEFINITION_DESCRIPTION or description.lower() in names:
        failures["definition-description"].add(def_id)

    tags = metadata.get("tags")
    if not (isinstance(tags, list) and any(collapse(t) for t in tags)):
        failures["tags"].add(def_id)

    parameters = spec.get("parameters")
    properties = parameters.get("properties") if isinstance(parameters, dict) else None
    if isinstance(properties, dict):
        for name, descriptor in properties.items():
            text = collapse(descriptor.get("description")) if isinstance(descriptor, dict) else ""
            if len(text) < MIN_PARAMETER_DESCRIPTION:
                failures["parameter-description"].add(f"{def_id}:{name}")

    result = spec.get("result")
    columns = result.get("columns") if isinstance(result, dict) else None
    if isinstance(columns, list):
        for index, column in enumerate(columns):
            if isinstance(column, dict):
                name = collapse(column.get("name")) or f"#{index}"
                text = collapse(column.get("description"))
            else:
                name, text = f"#{index}", ""
            if not text:
                failures["result-column-description"].add(f"{def_id}:{name}")
    return def_id, failures


def lint_tree(definitions_dir: Path) -> tuple[dict[str, set[str]], int]:
    """(all failures by rule, number of definitions scanned). Raises ValueError on bad YAML."""
    failures: dict[str, set[str]] = {rule: set() for rule in RULES}
    scanned = 0
    for path in sorted(definitions_dir.glob("*.yaml")):
        try:
            docs = list(yaml.safe_load_all(path.read_text(encoding="utf-8")))
        except yaml.YAMLError as exc:
            raise ValueError(f"{path.name}: not parseable as YAML ({type(exc).__name__})") from exc
        for index, doc in enumerate(docs):
            if not isinstance(doc, dict) or doc.get("kind") != "InstructionDefinition":
                continue
            scanned += 1
            _, found = lint_definition(doc, f"{path.name}#{index}")
            for rule, keys in found.items():
                failures[rule] |= keys
    return failures, scanned


def load_baseline(path: Path) -> dict[str, set[str]]:
    data = json.loads(path.read_text(encoding="utf-8"))
    raw = data.get("baseline")
    if not isinstance(raw, dict) or set(raw) != set(RULES):
        raise ValueError(f"{path.name}: 'baseline' must have exactly the rules {list(RULES)}")
    out: dict[str, set[str]] = {}
    for rule in RULES:
        if not isinstance(raw[rule], list) or not all(isinstance(e, str) for e in raw[rule]):
            raise ValueError(f"{path.name}: baseline['{rule}'] must be a list of strings")
        out[rule] = set(raw[rule])
    return out


def write_baseline(path: Path, failures: dict[str, set[str]]) -> None:
    doc = {
        "_comment": (
            "Ratchet baseline for scripts/ci/check-definition-descriptions.py: the definition "
            "description failures that existed when the rule landed. It may only shrink: delete an "
            "entry in the same change that fixes it. Regenerate with --update-baseline, run deliberately, never to hide a new failure."
        ),
        "baseline": {rule: sorted(failures[rule]) for rule in RULES},
    }
    path.write_text(json.dumps(doc, indent=2) + "\n", encoding="utf-8")


def compare(failures: dict[str, set[str]], baseline: dict[str, set[str]]) -> list[str]:
    """Ratchet violations as printable lines; empty when the tree matches the baseline."""
    problems: list[str] = []
    for rule in RULES:
        for key in sorted(failures[rule] - baseline[rule]):
            problems.append(f"NEW      {rule}: {key} ({REQUIREMENTS[rule]})")
        for key in sorted(baseline[rule] - failures[rule]):
            problems.append(
                f"STALE    {rule}: {key} no longer fails (or no longer exists): "
                "remove it from the baseline"
            )
    return problems


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--definitions", type=Path, default=DEFAULT_DEFINITIONS)
    parser.add_argument("--baseline", type=Path, default=DEFAULT_BASELINE)
    parser.add_argument("--update-baseline", action="store_true",
                        help="rewrite the baseline from the current tree (run deliberately, never "
                             "to hide a new failure)")
    args = parser.parse_args(argv)

    try:
        failures, scanned = lint_tree(args.definitions)
    except (OSError, ValueError) as exc:
        sys.stderr.write(f"check-definition-descriptions: {exc}\n")
        return 2
    if scanned == 0:
        sys.stderr.write(f"check-definition-descriptions: no InstructionDefinition under "
                         f"{args.definitions}\n")
        return 2

    if args.update_baseline:
        write_baseline(args.baseline, failures)
        print("baseline rewritten: " + ", ".join(f"{r}={len(failures[r])}" for r in RULES))
        return 0

    try:
        baseline = load_baseline(args.baseline)
    except (OSError, ValueError) as exc:
        sys.stderr.write(f"check-definition-descriptions: {exc}\n")
        return 2

    problems = compare(failures, baseline)
    summary = ", ".join(f"{r}={len(failures[r])}" for r in RULES)
    if problems:
        for line in problems:
            print(line)
        print(f"check-definition-descriptions: FAIL ({len(problems)} ratchet violation(s); "
              f"{scanned} definitions; failing now: {summary})")
        return 1
    print(f"check-definition-descriptions: OK ({scanned} definitions; baselined failures: {summary})")
    return 0


if __name__ == "__main__":
    sys.exit(main())
