#!/usr/bin/env python3
"""The upgrade note for the Windows package sources states the fresh-deployment contract.

docs/user-manual/upgrading.md "Deployment contract (hard cutover)" (routed Forensics clause 8) forbids
a document from describing an in-place upgrade of an enrolled fleet. The sibling behaviour-change
sections each open with a fixed sentence saying so; this section must too, and must not tell an
operator that rows appear "on the next daily sync" with "no re-enrolment" (which reads as an upgrade
path). Pure text check, no build.
"""
import pathlib
import re
import sys

DOC = pathlib.Path(__file__).resolve().parent.parent / "docs" / "user-manual" / "upgrading.md"
HEADING = "## Behaviour change: Windows software counts include Store apps, Chocolatey packages and winget presence"
PREAMBLE = ('This describes the build in a fresh deployment (see "Deployment contract (hard cutover)" '
            "in the Forensics section of this page); it is not a procedure for carrying a fleet forward.")
FORBIDDEN = (re.compile(r"next daily sync", re.I), re.compile(r"no re-?enrol", re.I))


def section(text: str) -> str:
    start = text.index(HEADING)
    nxt = text.find("\n## ", start + len(HEADING))
    return text[start:nxt if nxt != -1 else len(text)]


def main() -> int:
    body = section(DOC.read_text(encoding="utf-8"))
    lines = [l for l in body.splitlines()[1:] if l.strip()]
    errors = []
    if not lines or lines[0] != PREAMBLE:
        errors.append("the section must open with the fresh-deployment sentence used by its neighbours")
    for pat in FORBIDDEN:
        if pat.search(body):
            errors.append(f"the section must not say {pat.pattern!r}: it reads as an in-place upgrade path")
    for e in errors:
        print(f"test_upgrade_notes_contract: {e}", file=sys.stderr)
    return 1 if errors else 0


if __name__ == "__main__":
    sys.exit(main())
