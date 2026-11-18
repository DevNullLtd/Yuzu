# Bulk device-CI read: concurrency cap and page byte bound, residuals

**Date:** 2026-11-18
**Change:** `GET /api/v1/hardware-ci` and the MCP tool `list_hardware_ci_records`: a per-replica cap on
concurrent bulk reads (#7949), a byte bound on one response page (#7950) and the audit-outage read
amplification note (#7951). Three commits on `fix/hardware-ci-bulk-read-bounds`: `915454b74b` (the cap),
`28e94b3b9a` (the byte bound) and `547d449e1b` (audit rows, coverage and changelog).
**Status:** implemented and governed once; not merged. The residuals below are recorded, not accepted.

## What the cap does and does not do

`BulkReadSlots` (`server/core/src/bulk_read_slots.hpp`) is one counting semaphore per replica, shared by the
REST route and the MCP tool, with a fixed 500 ms wait and a hard maximum of 8. Unset, the cap is
`min(2, max(1, pool/4))`; an explicit value must be 1 to 8 (argument parsing) and at most `max(1, pool/2)`
(boot refusal). It limits how many pool connections bulk reads can hold, so a burst of bulk pages cannot
take the whole pool from authorization and the audit write. It is not a reserve: at pool size 1 the cap is
the whole pool, and other traffic can still exhaust the pool. A fleet read over the cap is a retryable `503`
(REST: no audit row; MCP: one generic best-effort row); point reads (`agent_id`) take no slot.

## What the byte bound does and does not do

A page ends once its device rows reach 4 MiB (REST) or 1 MiB (MCP, which emits the payload twice), keeping at
least one row; `page_bytes_capped: true` and the audit token ` byte_capped=1` appear only when it ended the
page. It bounds the response, not the work: all `limit`+1 rows (up to 1001, about 30 MB raw) are read and held
before the page is cut.

## Residuals recorded by this change (pending owner acceptance)

Recorded 2026-11-18. Each is a fact about the code as committed.

1. One caller can hold every slot, and the semaphore wait is not first-in-first-out, so a low-privilege
   `Inventory:Read` caller can starve the CMDB sync's bulk read. A per-principal limit is a follow-up.
2. Point reads (`agent_id`) are uncapped.
3. There is no audit-liveness breaker. #7951 is bounded for the read phase only: the slot is released before
   the audit write and audit writers are not capped, so an audit-table lock held by migration DDL or
   `VACUUM FULL` can still saturate the pool (a mechanism that predates this change).
4. A slot is held for the whole store call: a pool acquire of up to 3 s (500 ms when the pool is saturated),
   up to 10 s to open a connection and the 5 s statement limit. Against a database that stops answering
   rather than running slowly those limits may not fire, so a hold can exceed that sum. Recovery is passive.
5. A read waiting for a slot occupies an HTTP worker for up to 500 ms; the cap bounds connections, not workers.
6. The byte bound does not bound memory: a cap of 8 can transiently hold several hundred MB on one replica.
7. REST busy refusals are counter-only (`yuzu_hardware_ci_read_busy_total{surface="rest"}`): no principal is
   attributed to a refusal flood.
8. No alert rule and no in-use gauge ship for the cap yet.
9. Retries are not rate limited, and the server adds no jitter to its `retry_after_ms` hint.
10. The cap is per replica; fleet capacity is replicas times the cap, and a balancer retry can land on a
    replica with free slots.
11. The chaos scenarios for an audit outage and a hung database were designed, not run.
12. ThreadSanitizer was not run on the new concurrency tests; the timing-based tests give lower bounds only.

## Frozen by this change

The keyset SQL (`COLLATE "C"`), migration v4's index, the `h1` cursor prefix and the collation gate's single
read mapping (`device_ci_read_gate.hpp`) are unchanged; see
`docs/security-reviews/hardware-ci-bulk-read-collation-drift-2026-11-15.md`.

## Where to read more

Operator view and triage: `docs/user-manual/server-admin.md` "Bulk device-CI read concurrency". Client retry
rule: `docs/user-manual/rest-api.md` (`GET /api/v1/hardware-ci`). Counter: `docs/user-manual/metrics.md`.
