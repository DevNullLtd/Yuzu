# CycloneDX 1.7 JSON schemas (vendored)

Used by `tests/test_cbom_schema.py` to validate the `/crypto` CBOM export
(`server/core/src/crypto_cbom.*`) against the official schema.

Source: https://github.com/CycloneDX/specification, `schema/` directory, `master` branch,
downloaded 2026-10-18 (unmodified):

- https://raw.githubusercontent.com/CycloneDX/specification/master/schema/bom-1.7.schema.json
- https://raw.githubusercontent.com/CycloneDX/specification/master/schema/cryptography-defs.schema.json
- https://raw.githubusercontent.com/CycloneDX/specification/master/schema/jsf-0.82.schema.json
- https://raw.githubusercontent.com/CycloneDX/specification/master/schema/spdx.schema.json

`bom-1.7.schema.json` references the other three by relative `$ref`; the test registers all
four so no network fetch happens. Licence: Apache-2.0 (CycloneDX specification).

`golden/` holds real `cbom_json` output for fixed synthetic inputs; `test_crypto_cbom.cpp`
asserts the exporter still produces those exact bytes, and the Python test validates them.
