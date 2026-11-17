#!/usr/bin/env python3
"""F39: the disk_space `path` parameter refuses a UNC / device spelling server-side (a RE2 pattern in
content/definitions/disk_space.yaml). The pattern is RE2 (no lookahead) and uses only constructs
Python's `re` reads the same way, so it is exercised here against the shipped YAML.
Runnable standalone: `python3 tests/test_disk_space_definition_pattern.py`."""
import re
import unittest
from pathlib import Path

import yaml

DEFINITION = Path(__file__).resolve().parent.parent / "content" / "definitions" / "disk_space.yaml"


def path_validation():
    for doc in yaml.safe_load_all(DEFINITION.read_text()):
        if doc and doc.get("spec", {}).get("execution", {}).get("plugin") == "disk_space":
            return doc["spec"]["parameters"]["properties"]["path"]["validation"]
    raise AssertionError("disk_space definition not found")


class DiskSpacePathPattern(unittest.TestCase):
    def setUp(self):
        self.v = path_validation()
        self.rx = re.compile(self.v["pattern"])
        self.assertEqual(self.v["maxLength"], 4096)

    def test_local_shapes_pass(self):
        for p in ["", "/", "/var/lib", "C:\\", "D:\\data", "C:", "relative/dir", "\\Windows"]:
            self.assertTrue(self.rx.fullmatch(p), p)

    def test_unc_and_device_spellings_are_refused(self):
        for p in ["\\\\host\\share", "//host/share", "\\\\?\\UNC\\h\\s", "\\\\.\\PhysicalDrive0",
                  "\\//host", "/\\host", "/var\nx"]:
            self.assertFalse(self.rx.fullmatch(p), repr(p))


if __name__ == "__main__":
    unittest.main()
