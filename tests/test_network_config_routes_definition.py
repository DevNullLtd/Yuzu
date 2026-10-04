#!/usr/bin/env python3
"""The `routes` instruction definition exists and matches what the plugin emits.

Nothing else requires it: the capability tests compare the plugin's actions() with the
catalogue, and the gate-consistency test checks definitions that EXIST, so deleting or
reshaping this document would leave them green. This pins the id, the plugin/action pair, the
approval mode, the platforms and the ordered result columns against the ten-field row
`route|family|destination|prefix_len|gateway|interface|metric|table|type|origin` (the leading
`route` is the row discriminator, not a column).
"""
import unittest
from pathlib import Path

import yaml

REPO = Path(__file__).resolve().parent.parent
DEFINITIONS = REPO / "content" / "definitions" / "network_config.yaml"

COLUMNS = [
    ("family", "string"),
    ("destination", "string"),
    ("prefix_len", "int32"),
    ("gateway", "string"),
    ("interface", "string"),
    ("metric", "string"),
    ("table", "string"),
    ("route_type", "string"),
    ("origin", "string"),
]


def load_routes():
    docs = [d for d in yaml.safe_load_all(DEFINITIONS.read_text(encoding="utf-8")) if d]
    found = [d for d in docs if d.get("metadata", {}).get("id") == "device.network_config.routes"]
    return found


class RoutesDefinition(unittest.TestCase):
    def test_exactly_one_definition(self):
        self.assertEqual(len(load_routes()), 1)

    def test_dispatch_pair_and_posture(self):
        spec = load_routes()[0]["spec"]
        self.assertEqual(spec["execution"]["plugin"], "network_config")
        self.assertEqual(spec["execution"]["action"], "routes")
        self.assertEqual(spec["parameters"]["properties"], {})
        self.assertEqual(spec["approval"]["mode"], "auto")
        self.assertEqual(sorted(spec["platforms"]), ["darwin", "linux", "windows"])
        self.assertEqual(spec["compatibility"]["requiredPlugins"], ["network_config"])

    def test_ordered_result_columns(self):
        cols = load_routes()[0]["spec"]["result"]["columns"]
        self.assertEqual([(c["name"], c["type"]) for c in cols], COLUMNS)
        for c in cols:
            self.assertEqual(sorted(c["platforms"]), ["darwin", "linux", "windows"], c["name"])
            self.assertTrue(c["description"].strip(), c["name"])

    def test_every_other_action_still_has_its_definition(self):
        docs = [d for d in yaml.safe_load_all(DEFINITIONS.read_text(encoding="utf-8")) if d]
        actions = {d["spec"]["execution"]["action"] for d in docs}
        self.assertEqual(actions, {"adapters", "ip_addresses", "dns_servers", "proxy", "dns_cache", "arp", "routes"})


if __name__ == "__main__":
    unittest.main()
