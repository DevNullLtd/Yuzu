#!/usr/bin/env python3
"""Validate the /crypto CBOM export against the official CycloneDX 1.7 JSON schema.

The documents under tests/fixtures/cyclonedx/golden/ are REAL `crypto_cbom::cbom_json` output for
fixed synthetic inputs (tests/unit/server/test_crypto_cbom.cpp asserts the exporter still
produces those exact bytes, so they cannot rot). This test validates each against the vendored
bom-1.7.schema.json (+ its three sibling schemas, registered locally so nothing is fetched), and
asserts the Yuzu invariants the schema cannot express: type `library` only, no cryptoProperties.

Needs the `jsonschema` package (>= 4.18, for `referencing`). If it is absent the test exits 77
(meson SKIP, printed loudly) unless YUZU_REQUIRE_JSONSCHEMA=1, which makes it a FAILURE - set that
on any CI leg that is meant to enforce the schema.
"""
import json
import os
import sys
from pathlib import Path

FIXTURES = Path(__file__).resolve().parent / "fixtures" / "cyclonedx"
SCHEMAS = ["bom-1.7.schema.json", "cryptography-defs.schema.json", "jsf-0.82.schema.json",
           "spdx.schema.json"]


def main() -> int:
    try:
        import jsonschema
        from referencing import Registry, Resource
        from referencing.jsonschema import DRAFT7
    except ImportError as exc:
        msg = f"test_cbom_schema: jsonschema/referencing not importable ({exc})"
        if os.environ.get("YUZU_REQUIRE_JSONSCHEMA") == "1":
            print(msg + " and YUZU_REQUIRE_JSONSCHEMA=1: FAIL", file=sys.stderr)
            return 1
        print(msg + ": SKIPPING (pip install 'jsonschema>=4.18')", file=sys.stderr)
        return 77

    loaded = {n: json.loads((FIXTURES / n).read_text(encoding="utf-8")) for n in SCHEMAS}
    registry = Registry()
    for name, doc in loaded.items():
        res = Resource.from_contents(doc, default_specification=DRAFT7)
        registry = registry.with_resource(f"http://cyclonedx.org/schema/{name}", res)
        registry = registry.with_resource(name, res)
    validator = jsonschema.Draft7Validator(loaded["bom-1.7.schema.json"], registry=registry)

    goldens = sorted((FIXTURES / "golden").glob("*.cdx.json"))
    if len(goldens) < 3:
        print(f"expected at least 3 golden BOMs, found {len(goldens)}", file=sys.stderr)
        return 1

    failures = 0
    for path in goldens:
        doc = json.loads(path.read_text(encoding="utf-8"))
        errors = sorted(validator.iter_errors(doc), key=lambda e: list(e.absolute_path))
        for e in errors:
            failures += 1
            print(f"{path.name}: {'/'.join(map(str, e.absolute_path))}: {e.message}", file=sys.stderr)

        def check(cond: bool, what: str) -> None:
            nonlocal failures
            if not cond:
                failures += 1
                print(f"{path.name}: {what}", file=sys.stderr)

        check(doc.get("specVersion") == "1.7", "specVersion must be 1.7")
        check(all(c.get("type") == "library" for c in doc.get("components", [])),
              "every component must be type library")
        check("cryptoProperties" not in json.dumps(doc), "cryptoProperties must never be emitted")
        refs = [c["bom-ref"] for c in doc.get("components", [])]
        check(len(refs) == len(set(refs)), "bom-ref values must be unique")
        print(f"{path.name}: {'OK' if not errors else 'INVALID'} ({len(refs)} components)")
    # The bundled schema must actually reject a bad document (guards a no-op validator).
    bad = {"bomFormat": "CycloneDX", "specVersion": "1.7", "serialNumber": "not-a-urn"}
    if not list(validator.iter_errors(bad)):
        failures += 1
        print("validator accepted a document with a malformed serialNumber", file=sys.stderr)
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
