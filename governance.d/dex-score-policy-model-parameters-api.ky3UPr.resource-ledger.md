# Resource Ledger: dex-score-policy-model-parameters-api (range ac486af32..e3d6c3605)

Every owning boundary and every borrow the diff adds or changes in C++ (server/core/src/rest_api_v1.cpp, dex_score_policy_json.hpp, dex_score_policy_writer.hpp and the three test files). The diff adds no new owning resource: one string literal, one string constant, one comment, and test value types only. No new fd, HANDLE, SOCKET, `FILE*`, sqlite3, libpq, OpenSSL or BCrypt object, thread, subprocess, callback context, mapped library or temp path. No manual cleanup in new C++.

| ID | Resource / construct | Owner type | Acquired | Released | Transfer | Failure cleanup |
|---|---|---|---|---|---|---|
| R1 | the `DexScorePolicyDocument` component and the `/dex/score-policy` path entry in `openapi_spec()` | raw-string literals (static storage), concatenated at compile time | program load | program exit | read through `openapi_spec()`'s existing `const std::string&`; no new reference escapes | none (each literal stays under the MSVC 16,380-byte cap; the largest is 15,097 bytes) |
| R2 | the remediation text in `dex_score_policy_projection_remediation` (dex_score_policy_json.hpp) | `std::string_view` over a string literal | call | return | the view points at static storage, so it outlives every caller | none (non-owning, `noexcept`) |
| R3 | the doc comments in dex_score_policy_json.hpp and dex_score_policy_writer.hpp | comment text | n/a | n/a | n/a | n/a |
| R4 | `kModelBody` and `check_model_document` (test_dex_score_policy_routes.cpp) | `constexpr const char*` literal; a free function taking `const json&` | test run | test run | the function only reads its argument; nothing is retained | none |
| R5 | the `doc` lambda in the OpenAPI completeness test | lambda capturing `&schemas` by reference | in the test body | end of the test case | `schemas` is a `const json&` into the local `spec`, which outlives the lambda; the lambda is not stored | none |
| R6 | `emitted`, `eov`, `em`, `eo`, `data` and the other `const json&` bindings in that test | const references into the local `emitted`, `spec` values | in the test body | end of the test case | every reference is guarded by a `contains` or `REQUIRE` before it is taken; none outlives its owner | none |
| R7 | `schema_at`, `array_contains`, `object_keys` (file-scope helpers) | free functions returning values (`json`, `bool`, `std::set<std::string>`) | call | return | return by value; no reference into the argument escapes | none |
