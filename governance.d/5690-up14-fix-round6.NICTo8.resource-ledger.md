# Resource Ledger: UP-14 agent fix round (b6de288a2, bb195a0e1, b7f311955, be5347b7b, round-7 fix commit)

C++ diff scope: `agents/core/src/{agent.cpp, guardian_drift_event.{hpp,cpp}, guardian_journal_format.{hpp,cpp}, guardian_spark_runtime.{hpp,cpp}}`; b7f311955 is comments only (code tokens proven identical to bb195a0e1 with a comment stripper). be5347b7b adds code but no resource: one `#include <yuzu/log_token.hpp>`, one `::yuzu::log_id_token(...)` argument (by-value temporary, consumed inside the existing `try/catch(...)`), and one `bool` expression in the legacy drift-sink lambda (`sent = (outcome == Sent) && !guardian_event_refused_by_server(ev)`, a pure const-ref read); no owner, capture, thread or lock change. The round-7 fix commit is comments, docs and a Python test only.

| Resource | Owner type | Acquired | Released | Transfer | Failure cleanup |
|---|---|---|---|---|---|
| `AgentImpl::guardian_unsendable_events_` (`std::atomic<std::uint64_t>`) | plain member of `AgentImpl`, trivially destructible | zero-initialised at construction | destroyed with `AgentImpl` | none | none needed; `fetch_add` is noexcept |
| `refuse_unsendable_guardian_event(ev, path)` | private member function; no owned state | n/a | n/a | `path` is a `std::string_view` over the literals `"legacy"` and `"spark"`, never stored | the `spdlog::warn` is wrapped in `try/catch(...)`; both early `return Sent` precede any lock, so no lock can leak |
| `wire_ev` in `send_guardian_outbox_entry` | local `const` `GuaranteedStateEvent`, scope-owned | built before the lock | end of function | none (was a temporary before) | exception-safe by scope |
| threads / callbacks | none added | n/a | n/a | the Spark refusal runs on `GuardianOutboxSendExecutor`'s existing DETACHED worker and the legacy refusal on the legacy executor worker or the DEX observer callback; it touches only the atomic and spdlog | safety rests on the existing orphan-exit contract (`hard_exit.hpp`), unchanged |
| fd / HANDLE / SOCKET / `FILE*` / sqlite / OpenSSL / BCrypt / temp path / subprocess | none added | n/a | n/a | n/a | n/a |

No manual cleanup in new code; no policy floor hit.
