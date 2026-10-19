# CycloneDX 1.7 JSON schemas (vendored)

Used by `tests/test_cbom_schema.py` to validate the `/crypto` CBOM export
(`server/core/src/crypto_cbom.*`) against the official schema.

Source: https://github.com/CycloneDX/specification, `schema/` directory, pinned to the
**`1.7.2` tag** (the files below are byte-identical to that tag; verified 2026-10-19), unmodified:

| File | sha256 |
|---|---|
| `bom-1.7.schema.json` | `73308edec3ab2d38bfffd993e96a042b594314143b6971a6e9ed98bbb6bd76ce` |
| `cryptography-defs.schema.json` | `027b059a729a06d591bac79a584ef04f83fc32d91a826fdba6ad3c98a10e5b44` |
| `jsf-0.82.schema.json` | `8bae002c25e723db7ee1f26afde680ae1a2b1a8f6b4b4b0fd65dc3becb090aae` |
| `spdx.schema.json` | `4b345e2329f209f34e960ae2a8e7cb46a166907e6a45e94978565925dc47b359` |

Each is fetched from `https://raw.githubusercontent.com/CycloneDX/specification/1.7.2/schema/<file>`.
`bom-1.7.schema.json` references three relative `$ref`s; the test registers all four so no
network fetch happens. Licence: Apache-2.0 (CycloneDX specification); the upstream `LICENSE`
from the same tag is copied alongside as `LICENSE`, and the repo `NOTICE` lists the schemas.

`golden/` holds real `cbom_json` output for fixed synthetic inputs; `test_crypto_cbom.cpp`
asserts the exporter still produces those exact bytes, and the Python test validates them.
After an intended shape change, regenerate with:

    YUZU_UPDATE_GOLDEN=1 <build>/tests/yuzu_server_tests "[golden]"

(the run fails once by design so the update is never silent); re-run without the variable
and it must pass.
