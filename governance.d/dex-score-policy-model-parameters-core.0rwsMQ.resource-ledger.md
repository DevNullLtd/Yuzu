# Resource Ledger: dex-score-policy-model-parameters-core (range d460f7618..feat/dex-score-policy-model-parameters-core)

Every owning boundary and every borrow the diff adds or changes in C++ (server/core/src/dex_stability_score.hpp, dex_stats.hpp, dex_score_policy.hpp, dex_score_policy_json.hpp, dex_read_model.cpp, guaranteed_state_store.{hpp,cpp} and the test files). Each row was checked by `cpp-safety` in governance round 1 (lifetime proof of every string_view and temporary) and by Kimi's ASan probe in the adversarial round. The diff adds no new owning raw resource.

| ID | Resource / construct | Owner type | Acquired | Released | Transfer | Failure cleanup |
|---|---|---|---|---|---|---|
| R1 | `cap_values` (stringified per-subject caps) in `dex_app_stability_checked` | local `std::vector<std::string>`, `reserve()`d to the input size before any `emplace_back` | the loop over `per_subject_caps` | end of the function | `string_view`s into it are taken immediately from the `emplace_back` reference and consumed by `pg::to_text_array`; the reserve guarantees no reallocation invalidates an earlier view | exception unwinds the vector; nothing else owned |
| R2 | `cap_subject_views` / `cap_value_views` | local `std::vector<std::string_view>` | same loop | end of the function | views into the const-ref parameter's strings (outlive the call) and into `cap_values`; not stored past the two `to_text_array` calls | none (non-owning) |
| R3 | `cap_subject_array`, `cap_value_array`, `sql`, `params` | local `std::string` / `std::vector<std::string>` values | built before the lambda | end of the function | passed to `exec_params` by const reference inside the synchronous `dex_read_checked` body (no thread or async escape) | none |
| R4 | `subject_caps` in `build_dex_apps_model` | local `std::vector<std::pair<std::string,int64_t>>` | copies of `o.image` / `o.per_device_event_cap` from the policy | end of the function | passed by const reference to the store call; the policy (const reference held for the function) is not retained | none |
| R5 | `StabilityModel` / `DexEffectivePolicy` copies | plain value types (three scalars; strings copied as before) | `apply_override` / `resolve_dex_score_policy` return by value | end of use | no reference into the policy escapes | none |
| R6 | `dex_proportion` / `dex_rate` / `z_for_confidence` locals | stack scalars | call | return | none | none (bisection bounded at 200 iterations) |

No new fd, HANDLE, SOCKET, `FILE*`, sqlite3 or libpq object (the PGconn use is unchanged inside `dex_read_checked`), OpenSSL or BCrypt object, thread, subprocess, callback context, mapped library or temp path. No manual cleanup in new C++.
