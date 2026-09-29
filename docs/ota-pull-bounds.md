# Agent OTA pull bounds

Routed doc for the **agent OTA pull bounds** concern in `.claude/routed-concerns.md` (#913/#911).
Loaded by `cpp-safety` + `architect` on the paths that row names.

Operator-facing behaviour is in `docs/user-manual/server-admin.md` "Agent OTA pull bounds"; the
lifetime contract is restated at the source in `server/core/src/ota_transfer_watchdog.hpp`. This
document holds the invariants, which are silently regressible and live nowhere else.

The subject is the per-peer admission gate on `DownloadUpdate` and the `OtaTransferWatchdog` that
enforces its transfer deadline.

## CATASTROPHIC — four parts, all silently regressible

### 1. The cancel/erase lock pairing

The watchdog's sweeper invokes its `CancelFn` **while holding `mu_`**, and the handler's RAII
`Registration` erases its entry under that **same** `mu_`. Removing either half is a use-after-free
on a borrowed `grpc::ServerContext*`: the sweeper would then be free to `TryCancel` a handler frame
that has already returned.

### 2. `ServerImpl` member order

`agent_service_` MUST stay declared **before** `agent_server_`. That ordering is what guarantees the
gRPC server — and every handler frame holding a `Registration` — is destroyed first. There is no
`static_assert` and no test, so a reorder in a 22k-line file is a shutdown use-after-free that no
other gate can see.

### 3. `PrincipalQuota` is held by value

It lives by value in `AgentServiceImpl` and is reconfigured in place via `set_config`. **Never
reintroduce a `unique_ptr` reseat** — every live `QuotaSlot` holds a raw `owner_` back-pointer into
it.

### 4. The certificate reserve

The server-wide ceiling's certificate reserve (`OtaTotalAdmission::effective_cap`) is the only bound
an IP-keyed caller cannot escape by commanding more addresses. Collapsing the two ceilings back into
one, or letting the reserve arithmetic round an IP-keyed share to zero on a non-zero cap, re-opens
either a fleet-wide lockout of enrolled agents or a total OTA outage for a certless fleet.

Its OCCUPANCY is tested in `test_ota_total_admission.cpp`, **not over the wire**: a live-wire case
reaches the gate one call at a time, so `prev` is always 0 and the counter can be deleted without
reddening anything.

## Load-bearing, but not catastrophic

- `refund()` is find-not-insert — a late refund must never resurrect an evicted key at full burst.
- `enforce_cap_locked` / `purge_stale` never evict an entry with `in_flight != 0`.
- The admission key falls back to peer IP, so `max_tracked` must stay above the live key count, or
  eviction re-mints full buckets and silently disables the rate dimension.
