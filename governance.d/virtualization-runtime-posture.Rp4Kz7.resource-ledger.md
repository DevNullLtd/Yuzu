# Resource Ledger — virtualization runtime_posture

Range: `origin/dev..HEAD` (branch `feat/virtualization-runtime-posture`)

## Summary

This diff adds one **socket** (an `httplib::Client` over a unix domain socket, call-scoped, opened per
request) and one **file descriptor** (the `O_PATH` endpoint descriptor), both RAII-owned and both
opened only when the operator sets `agent.runtime_endpoint`. It adds no thread, subprocess, `FILE*`,
`sqlite3*`, OpenSSL object, mapped library or temp path. The nlohmann values are value types.

## Table 1 — new owned state

| ID | Resource / construct | Owner type | Acquired | Released | Transfer | Failure cleanup |
|---|---|---|---|---|---|---|
| R1 | Endpoint descriptor (`O_PATH\|O_NOFOLLOW\|O_CLOEXEC`, `fstat`-checked, held so the transport connects through `/proc/self/fd/<N>`) | `yuzu::agent::ScopedFd` inside the function-local `EndpointHandle` in `run_linux_runtime_posture` | `open_endpoint_checked`, only after the lexical endpoint decision passed | the end of `run_linux_runtime_posture` (the single-flight body returns), including an exception | none: the Transport lambda borrows it by reference for the run | RAII; an `open` failure leaves it invalid and the endpoint reads `unreachable` or `endpoint_refused` |
| R2 | Unix socket of one request | `httplib::Client` local to `one_request` (its destructor closes the socket) | per request, after the verb table built the `Request` and the remaining budget was at least 1 ms | return from `one_request` | none | RAII; `Connection: close`, keep-alive off, so no connection outlives a request |
| R3 | Response body accumulator (`std::string`) | `TransportResult::body` | grown by the content receiver, which stops at the 1 MiB cap and cancels the transfer | moved into the parsed JSON step, then dropped | moved to the caller | value type; an oversized body is cleared and reported `response_oversized` |
| R4 | Parsed JSON (`nlohmann::json`) | `ParsedJson` locals | `parse_limited` (non-throwing, callback discards nesting past 32) | scope exit | readers take const references | value type; nothing deeper than 32 levels is ever built |
| R5 | Rows (`std::vector<ContainerRow>`, `ConfigRow`, formatted strings) | locals of `runtime_posture_linux` | from the list reply, capped at 256 rows; inspections at 64 | moved into the `Posture` | to `report` | value types; fields are truncated to 256 bytes (64 for network mode and versions) before escaping |
| R6 | `std::atomic<bool>` single-flight flag (`runtime_posture_flight`) | function-local static, process lifetime | `compare_exchange_strong` at the top of the leg | the `Release` guard's destructor on every exit path, an exception included | none | RAII guard; a concurrent dispatch returns `busy` without touching the filesystem or the socket |
| R7 | Operator endpoint string (`runtime_endpoint_slot`) | function-local static `std::string` behind a `std::mutex` | `init()` copies `agent.runtime_endpoint` | process lifetime | read by copy | none; written once in `init()`, read under the mutex |
| R8 | `static constexpr Legs kLegs` (now three leg pointers) | static storage, constant-initialised | none | none | none | none |

## Deadlines

The HTTP transport is bounded: one 20 s monotonic action deadline whose remaining time is passed as the
per-request total timeout (`set_max_timeout`, never zero: the seam stops issuing requests below 1 ms),
connect `min(2 s, remaining)`, read `min(5 s, remaining)`, a 1 MiB body cap, redirects and decompression
off. The deadline logic is unit-tested over an injected clock. The `stat` calls are not covered by it:
`stat` of a data root on a network mount is skipped through the shared `network_fstype.hpp` guard
(`<runtime>:network_fs_skipped`); sockets and config files live under `/run` and `/etc` and are not guarded.

## Table 2 — pre-existing resources this diff touches without changing ownership

| Resource | Owner | This diff's interaction |
|---|---|---|
| plugin `execute()` | `VirtualizationPlugin` | `execute_action` gains a third arm; still one `try { ... } catch (...) { ... }` around the whole body, the catch writing a fixed-token status row named for the action in its own nested `try`/`catch (...)`. The leg itself adds no `catch`. |
| `AgentConfig` / `plugin_ctx_.config` | agent core | one string field and one config key (`agent.runtime_endpoint`) beside `agent.data_dir`; copied at agent construction, no lifetime change. |

## Tests

`tests/unit/test_virtualization_runtime_parsers.cpp` (pure) and `tests/unit/test_virtualization_runtime_legs.cpp`
(fakes for stat, read, the endpoint open, the transport and the clock; no real socket or file, no sleeps)
cover the verb table, the endpoint refusals, the deadline and the recovery rules. The real socket
behaviour (the `/proc/self/fd` connect, a trickling peer, the proxy request matrix) is measured on a Linux
host after the gates settle and recorded in the PR body; no probe source is committed.
