# Resource Ledger: sam36-export-size-limits

Every owning boundary the C++ in `origin/dev..HEAD` (feat/inventory-export-size-limits) acquires. The change adds size limits to the streamed installed-software export (`software_export_stream.hpp`, `software_export_routes.{hpp,cpp}`, the two flags in `main.cpp`, the config fields in `server.hpp`, the wiring in `server.cpp`). It acquires no new owning resource: no thread, file descriptor, lock, lease, allocation with its own lifetime, or temporary path. The streamed export's own resources (the `StreamBudget::Lease`, the engine quota slot, the shared `Stream`, the `Ctx`) are recorded in `governance.d/sam36-software-export.dKEERG.resource-ledger.md` and are unchanged.

| ID | Resource / construct | Owner type | Acquired | Released | Transfer | Failure cleanup |
|---|---|---|---|---|---|---|
| R1 | `software_export::Limits` (two `std::int64_t`) | value member of `Ctx` (copied from `Deps::limits` and clamped at registration) | `register_routes`, at server bring-up | with the `Ctx`, at server destruction | none; read-only after registration | none needed: a trivially copyable value |
| R2 | `Stream::rows_written`, `Stream::bytes_written` (two `std::int64_t`) | members of the existing per-request `Stream` | with the `Stream`, at request time | with the `Stream`, on the same teardown paths as the lease | none | none needed: plain counters |

## Decision lines

- **Cut, never a clean end.** A stream that would pass either limit returns false from the provider without calling `sink.done()`, so the chunked response ends without its terminating chunk, exactly like the 900 s deadline. The outcome is `limit`, counted once in `yuzu_server_software_export_total` by the existing releaser, which still frees the lease and the engine quota slot first.
- **True maximum.** The page that would pass a limit is not written (the check runs before `sink.write`); a result exactly at a limit completes. The comparison is made against the remaining allowance, never as a sum, so no counter state overflows.
- **No path to unlimited.** The flags are range-checked at the command line (1000 to 1000000000 rows, 1 MiB to 1 TiB), and `clamp_limits` raises a 0 or negative value from any other caller to the floor at registration.
- **No new label values beyond `limit`.** The closed `result` label set grows from four to five values and stays pre-seeded for both formats; which of the two limits fired is in the log line only, not a label.
- **Access-control table (routed concern: security-guardian).** No new route, no new permission, no change to the gate, scope handling or audit. The limits only shorten what an already-authorized stream may write.
