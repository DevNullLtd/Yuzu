#!/usr/bin/env python3
"""test_remote_access_audit_definition.py -- pins the definition YAML's result columns (the
row_kind-first, field_1..field_7 name sequence and the row_kind enum) to the row layout
remote_access_audit_legs.hpp and the two parsers headers emit, so a reordered or renamed result
column fails here rather than only in a dashboard, and that the description keeps its
configured-not-effective and never-emitted wording. It compares the YAML with the literals
below; it does not read the C++.

Runnable standalone: `python3 tests/test_remote_access_audit_definition.py` (how meson runs it;
a bare pytest-style file with no runner would execute zero assertions and always exit 0).
"""
import unittest
from pathlib import Path

import yaml

REPO_ROOT = Path(__file__).resolve().parent.parent
DEFINITION = REPO_ROOT / "content" / "definitions" / "remote_access_audit.yaml"

# One stream, rows discriminated by field 0 (row_kind); the YAML names the shared tail fields
# generically (field_1..field_7) and documents each row kind's meaning in the column
# descriptions, so this pins the literal column-name sequence and the row_kind enum.
EXPECTED_COLUMNS = ["row_kind"] + [f"field_{i}" for i in range(1, 8)]
ROW_KINDS = ["status", "source", "config", "service", "file", "key"]


def _definition() -> dict:
    docs = [d for d in yaml.safe_load_all(DEFINITION.read_text(encoding="utf-8")) if d]
    assert len(docs) == 1, "remote_access_audit.yaml defines exactly one action (list)"
    return docs[0]


class RemoteAccessAuditDefinitionColumns(unittest.TestCase):
    def test_row_kind_leads_and_the_columns_match_the_wire_row(self):
        names = [c["name"] for c in _definition()["spec"]["result"]["columns"]]
        self.assertEqual(names, EXPECTED_COLUMNS)

    def test_row_kind_values_are_the_shapes_the_plugin_emits_today(self):
        row_kind = _definition()["spec"]["result"]["columns"][0]
        self.assertEqual(row_kind["values"], ROW_KINDS)

    def test_description_states_fingerprints_only_and_configured_not_effective(self):
        text = _definition()["metadata"]["description"].lower()
        self.assertIn("fingerprint", text)
        self.assertIn("configured", text)
        self.assertIn("not sshd's effective policy", text)
        self.assertIn("comments", text)
        self.assertIn("option values", text)
        self.assertIn("key-file paths", text)
        self.assertIn("off until enabled", text)
        # what the audit does not cover is stated in the description, not only in the README
        self.assertIn("does not read every way to log in", text)
        self.assertIn("certificate authority", text)
        self.assertIn("host-based authentication", text)
        self.assertIn("access list", text)
        self.assertIn("uid 500", text)
        # the flagged set is the six closed-set keywords, AuthenticationMethods included, and the two
        # undetectable gaps are stated as documented-only (no token), never as flagged
        self.assertIn("authenticationmethods", text)
        self.assertIn("one of these six", text)
        self.assertIn("raise no token and are documented only", text)

    def test_header_separates_flagged_sources_from_undetectable_gaps(self):
        header = DEFINITION.read_text(encoding="utf-8").split("\n---\n", 1)[0]
        flat = " ".join(line.lstrip("# ").strip() for line in header.splitlines())
        self.assertIn("When sshd_config sets one of these six", flat)
        self.assertIn("AuthenticationMethods", flat)
        self.assertIn("NOT read, and NOT detectable", flat)
        self.assertIn("documented, not flagged", flat)

    def test_columns_state_the_listed_count_and_the_row_cap_signal(self):
        cols = {c["name"]: c["description"] for c in _definition()["spec"]["result"]["columns"]}
        self.assertIn("number of key lines listed", cols["field_4"])
        self.assertIn("keys:row_cap", cols["field_4"])
        self.assertNotIn("lines accepted", cols["field_4"])


class RemoteAccessAuditDefinitionContract(unittest.TestCase):
    def test_identity_platforms_gather_approval_and_compatibility_are_pinned(self):
        doc = _definition()
        spec = doc["spec"]
        self.assertEqual(doc["metadata"]["id"], "crossplatform.security.remote_access_audit")
        self.assertEqual(spec["execution"]["plugin"], "remote_access_audit")
        self.assertEqual(spec["execution"]["action"], "list")
        self.assertEqual(spec["platforms"], ["windows", "linux", "darwin"])
        self.assertEqual(spec["execution"]["concurrency"], "per-device")
        self.assertEqual(spec["gather"]["ttlSeconds"], 3600)
        # role-gated <-> ExecuteGate::AdminOrApproval (test_capability_gate_consistency.py maps it)
        self.assertEqual(spec["approval"]["mode"], "role-gated")
        self.assertEqual(spec["permissions"]["executeRoles"], ["admin"])
        self.assertEqual(spec["compatibility"]["requiredPlugins"], ["remote_access_audit"])
        self.assertEqual(spec["parameters"]["properties"], {})
        self.assertEqual(spec["type"], "question")  # read-only: the catalogue gate relies on it
        self.assertEqual(doc["status"]["phase"], "active")


if __name__ == "__main__":
    unittest.main()
