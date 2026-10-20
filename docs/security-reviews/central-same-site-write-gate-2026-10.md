# Design record: central same-site gate for cookie-session writes

**Date:** 2026-10-20
**Subject:** cookie-session writes require a same-site `Origin` or `Referer`, decided once in the
server's pre-routing handler.
**Code:** `server/core/src/same_site_write_policy.hpp` (the pure decision and its invariants
banner), `server/core/src/same_site_write_gate.hpp` (counter, audit row, 403 body), the one call in
`server/core/src/server.cpp`.
**Tripwires:** `tests/test_same_site_wiring_lexical.py`,
`tests/unit/server/test_same_site_exempt_inventory.cpp`.
**Operator documentation:** [REST API](../user-manual/rest-api.md) (cookie-session writes),
[Upgrading](../user-manual/upgrading.md), [Server Administration](../user-manual/server-admin.md)
(`--csrf-trusted-origin`). Architecture summary: [auth-architecture.md](../auth-architecture.md)
"Same-site gate for cookie-session writes".

## Decision

Any request other than `GET`, `HEAD` or `OPTIONS` that is authorised by a cookie session is
refused `403` `cross-site request refused` unless it carries an `Origin` or `Referer` naming this
site or an entry from `--csrf-trusted-origin`. The check is one function with one caller. A
per-route copy of the same test is defence in depth and serves unit tests that bypass pre-routing.

## Why a pre-routing chokepoint

| Property | Pre-routing predicate (chosen) | Guard wrapped around route registration |
|---|---|---|
| Sees the resolved `auth_source` | Yes, the session is already resolved | Needs a second session lookup per request, or a resolver captured at every construction site |
| A new route cannot escape | Yes: coverage is by placement, registered route or not | Only while every registration goes through the wrapper |
| Runs before the body is read | Yes | No: the body is already buffered |
| Exemptions | By placement, no second list | Needs its own path list, a second copy of the pre-session set |
| Fits the existing chokepoint pattern | Yes (body cap, on-behalf-of, rate limiter) | A new pattern |

The wrapper's one advantage, route-level unit tests without a server, is already served by the
per-route copies, which stay.

## Rules

- **Placement.** After authentication and its `401` block; before step-up evaluation, step-up
  challenge emission, the engine-principal stash and every route handler. The gate uses the session
  the caller already resolved and never resolves a second one. The guarantee is exactly: for a
  request the gate refuses, the refusal happens after authentication and before step-up
  evaluation, before any challenge is emitted and before route-handler effects. Authentication
  itself is not free of side effects (durable session lookup, activity refresh), so no stronger
  claim is made.
- **Keying.** The decision keys on the resolved session's `auth_source`, never on whether a
  `Cookie` or `Authorization` header is present. Token sources are not gated; a request that
  resolves to a cookie source is gated even if it also carries a token.
- **Methods.** Everything except exactly `GET`, `HEAD` and `OPTIONS` is a write (fail closed). No
  carve-out for read-only `POST`s.
- **Exemptions** are by placement only: `is_login_exempt_path`'s pre-session set, the health probes
  and the metrics endpoint return before session resolution and never reach the gate. There is no
  second list.
- **Predicate.** `Origin` and `Referer` only. It calls `browser_write_is_cross_site` and does not
  re-implement it. The refusal reason is derived from header presence and cannot change the
  decision.
- **Trusted origins.** Normalised once at boot (`normalise_trusted_origins`); the gate receives the
  post-normalise set.

## Observable shapes

- `403` in the A4 envelope with a `remediation` and no `permission` field: the refusal does not name
  a grant that would not, by itself, admit the caller.
- One `csrf.denied` audit row stamped from the held session. If the row cannot be persisted the
  refusal stands and `Sec-Audit-Failed` is set.
- `yuzu_server_csrf_denied_total{path_class,reason}`: bounded labels (`path_class` from the body-cap
  table, never the raw path), pre-seeded to 0. Operational, not a security-event label.
- Exceptions: the gate never throws. The status is assigned first, each later step sits in its own
  `try`, and every refusal is counted exactly once (`gate_error` only if nothing was counted).
- Boot logs one `info` line stating the rule and the trusted-origin count; the first refusal logs a
  throttled `warn` that names the flag.

## Tripwires and their limits

1. `tests/test_same_site_wiring_lexical.py` pins the single call site in `server.cpp`: its position
   after authentication, the pinned set of early returns before it with their conditions, no
   early return between authentication and the gate, the call before the engine stash, and the
   absence of step-up entry points from the pre-routing handler. Lexical only: a relocation that
   keeps every token in order, or a textually identical but semantically different condition,
   is not detected.
2. `tests/unit/server/test_same_site_exempt_inventory.cpp` evaluates the real pre-session
   predicates over every mutating registration it can see and requires the bypassed set to equal a
   recorded ledger. Source-text scan: a computed path or a new receiver spelling is invisible.

## Proxy deployments

A reverse proxy that rewrites `Host` makes a browser's own `Origin` look foreign. The operator
declares the public origin with `--csrf-trusted-origin`; the boot line and the first refusal name
the flag. A proxy must not inject or rewrite `Origin` or `Referer`, which would turn the control off.
There is no kill switch and no observe-only mode.

## Decisions recorded

- MCP transport: the endpoint is gated like any other. A cookie caller sends `Referer`, or an
  `Origin` that both the gate and the endpoint's own allowlist accept. The endpoint's own `Origin`
  check keeps applying independently when streaming is on.
- Per-route copies stay in place in this change.
- No ADR: no new store and no architectural choice beyond the existing chokepoint pattern.

## Follow-ups

- Consolidating the per-route copies onto the gate (#5876).
- An alert rule for the metric, tuned against real traffic.
- Moving the MCP adapter's cookie mode to tokens.
