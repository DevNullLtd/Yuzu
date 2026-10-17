#!/usr/bin/env python3
"""check-sample-privacy.py -- refuses plugin sample captures that would publish data tying a
device to a person or an organisation (docs/plugin-readme-standard.md rule 5).

Samples (`agents/plugins/<name>/docs/samples/<os>.txt`) are published in a public repository, so a
problem has to be caught BEFORE the push: CI runs too late. Run it as a git pre-push hook
(`scripts/hooks/pre-push`, which checks only the samples a push changes) or by hand:

    python3 scripts/check-sample-privacy.py agents/plugins/certificates/docs/samples/windows.txt

It flags three things, each chosen because it is unambiguous and absent from every legitimate
existing capture of its kind:

  * a certificate row issued by a device-enrolment CA (Intune, MS-Organization-Access) whose subject
    carries a GUID -- that GUID is the device's Entra or Intune identity;
  * a user-profile path (`C:\\Users\\<name>`, `/Users/<name>`, `/home/<name>`) whose name is not a
    placeholder or a built-in profile;
  * a Windows account SID (`S-1-5-21-...`), which identifies a machine and its accounts.

E-mail addresses are deliberately NOT flagged: public package metadata (Debian maintainers in the
installed_apps capture) is full of them, and a check that cries wolf gets bypassed. A redaction is
written as `(redacted)` and noted in the stamp line, as rule 5 requires.

Exit status: 0 clean, 1 findings, 2 usage or read error.
"""
import re
import sys
from pathlib import Path

REDACTED = "(redacted)"

# Issuers of device-enrolment certificates. Their subject is the device's identity in a tenant.
_ENROLMENT_ISSUER = re.compile(r"MS-Organization-(?:P2P-)?Access|Microsoft Intune|Intune MDM", re.IGNORECASE)
# A device certificate's subject is the bare device GUID (an Entra device ID or Intune device ID).
# The same issuers also sign public CA certificates with ordinary names, which are not flagged.
_DEVICE_ID = re.compile(r"\b[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\b", re.IGNORECASE)

# Profile names that identify nobody: the README standard's placeholder and OS built-ins.
_SAFE_PROFILE_NAMES = {"jsmith", "public", "default", "default user", "all users", "shared", "runner",
                       REDACTED}
_PROFILE_PATH = re.compile(r"(?:\b[A-Za-z]:[\\/]+Users[\\/]+|/Users/|/home/)([^/\\|\s:;,'\"]+)")

_ACCOUNT_SID = re.compile(r"\bS-1-5-21-\d+-\d+-\d+(?:-\d+)?\b")
# The documented placeholder a redaction uses (see #6010); it identifies nothing.
_PLACEHOLDER_SID_DOMAIN = "S-1-5-21-1111111111-2222222222-3333333333"

# Certificate rows: subject|issuer|thumbprint|... (the certificates plugin's row layout).
_CERT_SUBJECT, _CERT_ISSUER = 0, 1


def problems(text: str) -> list[str]:
    """Every finding in one sample's text, as `line N: reason` strings."""
    found = []
    for n, line in enumerate(text.splitlines(), start=1):
        fields = line.split("|")
        if (len(fields) > _CERT_ISSUER and _ENROLMENT_ISSUER.search(fields[_CERT_ISSUER])
                and _DEVICE_ID.search(fields[_CERT_SUBJECT])):
            found.append(f"line {n}: device-enrolment certificate (issuer "
                         f"'{fields[_CERT_ISSUER].strip()}') with an unredacted subject")
        for m in _PROFILE_PATH.finditer(line):
            if m.group(1).lower() not in _SAFE_PROFILE_NAMES:
                found.append(f"line {n}: user-profile path names '{m.group(1)}' "
                             f"(use the placeholder 'jsmith' or '{REDACTED}')")
        if any(not m.group(0).startswith(_PLACEHOLDER_SID_DOMAIN) for m in _ACCOUNT_SID.finditer(line)):
            found.append(f"line {n}: Windows account SID")
    return found


def main(argv: list[str]) -> int:
    if not argv:
        print(__doc__.strip().splitlines()[0], file=sys.stderr)
        print("usage: check-sample-privacy.py SAMPLE.txt [...]", file=sys.stderr)
        return 2
    status = 0
    for arg in argv:
        try:
            text = Path(arg).read_text(encoding="utf-8", errors="replace")
        except OSError as e:
            print(f"{arg}: cannot read: {e}", file=sys.stderr)
            return 2
        for p in problems(text):
            print(f"{arg}: {p}")
            status = 1
    if status:
        print("\nSample privacy check FAILED: redact the fields above with '(redacted)', note the "
              "redaction in the stamp line's privilege field, and see docs/plugin-readme-standard.md "
              "rule 5.", file=sys.stderr)
    return status


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
