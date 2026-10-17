#!/usr/bin/env python3
"""test_sample_privacy.py -- every committed plugin sample capture passes
scripts/check-sample-privacy.py, except the findings already recorded in KNOWN_FINDINGS.

The pre-push hook (scripts/hooks/pre-push) is the real guard, because the repository is public and
CI runs after the push. This test is the backstop for a checkout without the hook: a NEW finding in
any sample fails here. KNOWN_FINDINGS is a ratchet over samples captured before the check existed:
it may only shrink. Fixing a sample means removing (or lowering) its entry in the same change.

Runnable standalone: `python3 tests/test_sample_privacy.py` (how meson runs it).
"""
import importlib.util
import unittest
from collections import Counter
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
_spec = importlib.util.spec_from_file_location(
    "check_sample_privacy", REPO_ROOT / "scripts" / "check-sample-privacy.py")
checker = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(checker)

# Findings present when the check was introduced (2026-10-17): a local profile name and a local
# account SID in Windows captures. Each entry is the exact number of findings in that file.
KNOWN_FINDINGS = {
    "agents/plugins/autoruns/docs/samples/windows.txt": 51,
    "agents/plugins/netstat/docs/samples/windows.txt": 4,
    "agents/plugins/processes/docs/samples/windows.txt": 10,
    "agents/plugins/procfetch/docs/samples/windows.txt": 5,
    "agents/plugins/registry/docs/samples/windows.txt": 2,
}


def _findings() -> Counter:
    counts = Counter()
    for path in sorted(REPO_ROOT.glob("agents/plugins/*/docs/samples/*.txt")):
        found = checker.problems(path.read_text(encoding="utf-8", errors="replace"))
        if found:
            counts[path.relative_to(REPO_ROOT).as_posix()] = len(found)
    return counts


class CommittedSamples(unittest.TestCase):
    def test_no_new_privacy_findings(self):
        current = _findings()
        for path, count in current.items():
            with self.subTest(sample=path):
                allowed = KNOWN_FINDINGS.get(path, 0)
                self.assertLessEqual(
                    count, allowed,
                    f"{path}: {count} privacy finding(s), {allowed} known. Run "
                    f"`python3 scripts/check-sample-privacy.py {path}` and redact them.")

    def test_known_findings_shrink_when_fixed(self):
        current = _findings()
        for path, allowed in KNOWN_FINDINGS.items():
            with self.subTest(sample=path):
                self.assertEqual(
                    current.get(path, 0), allowed,
                    f"{path}: the known count is stale; lower KNOWN_FINDINGS to "
                    f"{current.get(path, 0)} (it may only shrink).")


class CheckerCatches(unittest.TestCase):
    """Each rule still fires on the shape it exists for, and stays quiet on its look-alikes."""

    def test_device_enrolment_certificate_subject(self):
        row = ("23a40c37-941d-4546-8ff0-6a62d30a2e0c|Microsoft Intune Device Management Device CA|"
               "AB12|2026-09-16|2027-09-14|01|MY|Digital Signature|RSA|2048|sha256WithRSAEncryption")
        self.assertEqual(len(checker.problems(row)), 1)
        self.assertEqual(checker.problems(row.replace(row.split("|")[0], "(redacted)", 1)), [])

    def test_public_ca_signed_by_an_enrolment_issuer_is_not_flagged(self):
        row = ("CN=Microsoft Intune MDM Device CA|CN=Microsoft Intune Root Certification Authority|"
               "AB12|2020-01-01|2030-01-01|01|CA|Certificate Sign|RSA|4096|sha256WithRSAEncryption")
        self.assertEqual(checker.problems(row), [])

    def test_profile_paths(self):
        self.assertEqual(len(checker.problems(r"C:\Users\Alex\AppData\x.exe")), 1)
        self.assertEqual(len(checker.problems("/home/alice/.config")), 1)
        self.assertEqual(checker.problems("/Users/jsmith/Library"), [])
        self.assertEqual(checker.problems(r"C:\Users\Public\Desktop"), [])

    def test_account_sid(self):
        self.assertEqual(len(checker.problems("owner|S-1-5-21-1-2-3-1001")), 1)
        self.assertEqual(checker.problems("owner|S-1-5-18"), [])
        self.assertEqual(checker.problems("HKU\\S-1-5-21-1111111111-2222222222-3333333333-1001\\Run"), [])


if __name__ == "__main__":
    unittest.main()
