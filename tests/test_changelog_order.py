#!/usr/bin/env python3
"""CHANGELOG.md ordering check.

Validates that the project CHANGELOG follows the Keep a Changelog convention
of reverse chronological order: every released version section
(`## [X.Y.Z] - YYYY-MM-DD`) must appear before any older release in the file.
The `## [Unreleased]` section, if present, must be the very first version
header.

Run directly via `python3 tests/test_changelog_order.py`, or via meson test:
    meson test changelog_order

Exits non-zero (and prints the offending header pair) on any drift, so this
catches the common mistake of editing one section in place without keeping
the rest of the file in order — which is how `[0.1.0]` ended up wedged between
`[Unreleased]` and `[0.9.0]` in the v0.9.0 era.
"""

from __future__ import annotations

import re
import sys
from datetime import date
from pathlib import Path

# Match `## [Unreleased]` and `## [1.2.3] - YYYY-MM-DD` (with optional rc/beta tags).
HEADER_RE = re.compile(
    r"^## \[(?P<version>[^\]]+)\](?:\s*-\s*(?P<date>\d{4}-\d{2}-\d{2}))?\s*$"
)
SEMVER_RE = re.compile(r"^(\d+)\.(\d+)\.(\d+)(?:[-+].*)?$")


def parse_changelog(path: Path) -> list[tuple[int, str, date | None]]:
    """Return [(line_no, raw_version, date_or_None), ...] in file order."""
    sections: list[tuple[int, str, date | None]] = []
    for lineno, raw in enumerate(path.read_text(encoding="utf-8").splitlines(), start=1):
        m = HEADER_RE.match(raw)
        if not m:
            continue
        version = m.group("version")
        date_str = m.group("date")
        parsed_date: date | None = None
        if date_str:
            try:
                parsed_date = date.fromisoformat(date_str)
            except ValueError as exc:
                print(
                    f"CHANGELOG.md:{lineno}: invalid date '{date_str}' in"
                    f" header: {exc}",
                    file=sys.stderr,
                )
                sys.exit(2)
        sections.append((lineno, version, parsed_date))
    return sections


def semver_key(version: str) -> tuple[int, int, int] | None:
    m = SEMVER_RE.match(version)
    if not m:
        return None
    return (int(m.group(1)), int(m.group(2)), int(m.group(3)))


def check_order(sections: list[tuple[int, str, date | None]]) -> list[str]:
    """Return a list of error messages (empty list = pass)."""
    errors: list[str] = []
    if not sections:
        return ["CHANGELOG.md: no `## [version]` headers found"]

    # If [Unreleased] is present it must be first.
    unreleased_indices = [
        i for i, (_, v, _) in enumerate(sections) if v.lower() == "unreleased"
    ]
    if len(unreleased_indices) > 1:
        for idx in unreleased_indices[1:]:
            lineno = sections[idx][0]
            errors.append(
                f"CHANGELOG.md:{lineno}: duplicate `[Unreleased]` section"
            )
    if unreleased_indices and unreleased_indices[0] != 0:
        lineno = sections[unreleased_indices[0]][0]
        errors.append(
            f"CHANGELOG.md:{lineno}: `[Unreleased]` must be the first version"
            " header"
        )

    # Released versions must be reverse-chronological by date, with semver as
    # a tiebreaker for same-day releases.
    released = [(ln, v, d) for (ln, v, d) in sections if v.lower() != "unreleased"]
    for prev, curr in zip(released, released[1:]):
        prev_lineno, prev_version, prev_date = prev
        curr_lineno, curr_version, curr_date = curr

        if prev_date is None or curr_date is None:
            errors.append(
                f"CHANGELOG.md:{curr_lineno}: release `[{curr_version}]` has"
                " no date — every released section needs `- YYYY-MM-DD`"
            )
            continue

        if curr_date > prev_date:
            errors.append(
                f"CHANGELOG.md:{curr_lineno}: `[{curr_version}]` ({curr_date})"
                f" is newer than the preceding `[{prev_version}]`"
                f" ({prev_date}) at line {prev_lineno} — order must be reverse"
                " chronological"
            )
            continue

        if curr_date == prev_date:
            # Same-day releases: fall back to semver. Newer semver must come
            # first; equal versions are a duplicate.
            prev_key = semver_key(prev_version)
            curr_key = semver_key(curr_version)
            if prev_key is None or curr_key is None:
                continue  # Non-semver tag; we don't try to order it.
            if curr_key > prev_key:
                errors.append(
                    f"CHANGELOG.md:{curr_lineno}: `[{curr_version}]` is newer"
                    f" than the preceding `[{prev_version}]` at line"
                    f" {prev_lineno} on the same day ({prev_date}) — order"
                    " must be reverse chronological"
                )
            elif curr_key == prev_key:
                errors.append(
                    f"CHANGELOG.md:{curr_lineno}: duplicate version"
                    f" `[{curr_version}]` (also at line {prev_lineno})"
                )

    return errors


def main(argv: list[str]) -> int:
    if len(argv) > 1:
        path = Path(argv[1])
    else:
        path = Path(__file__).resolve().parent.parent / "CHANGELOG.md"

    if not path.is_file():
        print(f"{path}: file not found", file=sys.stderr)
        return 2

    sections = parse_changelog(path)
    errors = check_order(sections)

    if errors:
        for err in errors:
            print(err, file=sys.stderr)
        print(
            f"\nCHANGELOG order check FAILED ({len(errors)} issue(s)).",
            file=sys.stderr,
        )
        return 1

    print(f"CHANGELOG order check OK — {len(sections)} sections in order")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
