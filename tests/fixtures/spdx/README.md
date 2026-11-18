# SPDX 2.3 JSON schema (vendored)

Used by `tests/test_artifact_sbom.py` to validate every SPDX SBOM its tests
generate with `scripts/ci/artifact-sbom.py` (with the CycloneDX 1.7 schemas in
`../cyclonedx/` for the CycloneDX half). The test validates whenever the
`jsonschema` package (>= 4.18) is importable; with `YUZU_REQUIRE_JSONSCHEMA=1`
(set on the `CBOM schema` job of `.github/workflows/docs-lint.yml`) a missing
`jsonschema` is a failure, not a skip.

Source: https://github.com/spdx/spdx-spec, `schemas/spdx-schema.json`, pinned
to the **`v2.3` tag**, unmodified (byte-identical to that tag; verified
2026-11-18), renamed with its version:

| File | sha256 |
|---|---|
| `spdx-schema-2.3.json` | `239208b7ac287b3cf5d9a9af23f9d69863971102a5e1587a27a398b43490b89b` |

Fetched from
`https://raw.githubusercontent.com/spdx/spdx-spec/v2.3/schemas/spdx-schema.json`.
It holds no external `$ref`, so nothing is fetched at test time. Licence: the
SPDX specification is published under the Creative Commons Attribution 3.0
Unported licence (CC-BY-3.0); the upstream `LICENSE` from the same tag is
copied alongside as `LICENSE`, and the repo `NOTICE` lists the schema.
Attribution, as the specification states it (`chapters/index.md` at the same
tag): "Copyright © 2010-2022 Linux Foundation and its Contributors. This work
is licensed under the Creative Commons Attribution License 3.0 Unported
(CC-BY-3.0)". https://spdx.github.io/spdx-spec/v2.3/
