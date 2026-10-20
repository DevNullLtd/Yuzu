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
  re-implement it. The refusal reason is derived from which of the two headers are non-empty and
  cannot change the decision.
- **Trusted origins.** Normalised once at boot (`normalise_trusted_origins`); the gate receives the
  post-normalise set.

## Observable shapes

- `403` in the A4 envelope with a `remediation` and no `permission` field: the refusal does not name
  a grant that would not, by itself, admit the caller.
- One `csrf.denied` audit row stamped from the held session: `result=denied`, `target_id` the
  sanitised `METHOD path` (the request path truncated at 200 bytes), `detail` fixed text plus `reason=<token>` from the
  closed refusal-reason set (no header bytes). If the row cannot be persisted the refusal stands and
  `Sec-Audit-Failed` is set. With no audit store configured nothing fails to persist, so there is no
  row, no header, and the counter is the only record. The `gate_error` path writes no row of its own.
- `yuzu_server_csrf_denied_total{path_class,reason}`: bounded labels (`path_class` from the body-cap
  table, never the raw path), pre-seeded to 0. Operational, not a security-event label (see
  "Decisions recorded"). Alert rules in the `yuzu-web-writes` group: a Host-rewriting-proxy rule on
  `origin_mismatch` plus `referer_mismatch` (3 or more in 15 minutes) and a rule on any `gate_error`
  in 15 minutes; `no_origin_no_referer` is deliberately not alerted. The window and threshold are
  tentative, not tuned against fleet data.
- Exceptions: the gate never throws. The status is assigned first, each later step sits in its own
  `try`, and every refusal is counted exactly once (`gate_error` only if nothing was counted).
- Boot prints one line to standard error, before the log level and `--log-file` are configured (so
  neither hides it nor receives it): the accepted trusted-origin set when any is declared, otherwise the rule
  and that no `--csrf-trusted-origin` value was accepted. The refusal warning names the flag and is
  time-throttled: at most one per 60 seconds per reason (one slot per refusal reason and one for
  `gate_error`), the first of each reason since start always logs, and the counter records every
  refusal.
- Ordering, an accepted guarantee: after authentication; before step-up evaluation, challenge
  emission and route-handler effects. A cookie wins over a token credential on the same request.

## Tripwires and their limits

1. `tests/test_same_site_wiring_lexical.py` pins the single call site in `server.cpp`: its position
   after authentication, the pinned set of early returns before it with their conditions, no
   early return between authentication and the gate, the call before the engine stash, and the
   absence of step-up entry points from the pre-routing handler. Lexical only: a relocation that
   keeps every token in order, or a textually identical but semantically different condition,
   is not detected.
2. `tests/unit/server/test_same_site_exempt_inventory.cpp` evaluates the real pre-session
   predicates over every mutating registration it can see and requires the bypassed set to equal a
   recorded ledger. Source-text scan with documented blind spots: a computed path, a new receiver
   spelling, a registration made in a `.hpp`, and a mutating `GET` handler are invisible to it (and
   a mutating `GET` is outside the gate by definition).

The wiring tripwire is a source-text check, so it can establish that the call is present, live and
in position, not what the surrounding code does at run time. It first applies line splicing, then
counts the gate, session-resolve, engine-stash and audit-sink tokens on text with comments removed
and string and raw-string literals blanked. It rejects a preprocessor directive inside the handler
body, a digraph spelling of a brace, bracket or hash, and any additional pre-routing handler
registration however it is spelled; it requires that the call is not nested in any `if` chain and
sits at a statement boundary, and that the text between session resolution and the call is exactly
the pinned authentication block, so an added statement (including a call that never returns) is
rejected. Each rejected class has a mutation case in its self-test. Its stated limits: it does not
detect reassignment of the session, configuration or metrics objects before the call, shadowing of
those names, a change to `req.method` made before the call, or a semantic change made through a
helper function or a cast (for example a `const_cast` on the session). Those rest on review, and on
the integration tests that drive the real handler.

## Proxy deployments

A reverse proxy that rewrites `Host` makes a browser's own `Origin` look foreign. The operator
declares the public origin with `--csrf-trusted-origin`; the boot line and the first refusal name
the flag. A proxy must not inject or rewrite `Origin` or `Referer`, which would turn the control off.
There is no kill switch and no observe-only mode. Known consequence, accepted: a deployment whose
proxy rewrites `Host` and that has no declared origin and no pre-existing API token loses every
dashboard write, including creating a token, until it restarts with the flag or reaches the server
directly; sign-in, reads and the health probes keep working, so no probe detects it. The upgrade
section opens with a pre-upgrade checklist for this reason.

## Decisions recorded

- MCP transport: the endpoint is gated like any other. A cookie caller sends `Referer`, or an
  `Origin` that both the gate and the endpoint's own allowlist accept. The endpoint's own `Origin`
  check keeps applying independently when streaming is on. The refusal is the REST error envelope.
- Per-route copies stay in place in this change. They fall into two predicate variants: copies of the
  token-exempt predicate (`browser_write_is_cross_site`), which are unreachable in production, and
  copies of the plain `origin_is_same_site` test, which are not token-exempt and so still answer a
  token caller of those dashboard-panel routes. "Defence in depth" and "token callers are not
  affected" are therefore stated with that exception.
- Operational, not security-event, metric. The counter carries no `event="security"` label: a
  refusal is as often a script or proxy misconfiguration as a deliberate cross-site request, and the rules alert on the
  proxy signature and on internal failure rather than on volume. Hard to change later: adding an
  `event` label changes the series identity and breaks continuity for every rule and dashboard
  already built on it.
- Refusal surface in the dashboard: the gate keeps answering with the A4 JSON body. Most dashboard
  pages (htmx) do not swap a non-2xx response, so a refused write is silent in the UI; the operator
  documentation says so and points at the audit row and the counter. Making the UI render the
  refusal is a separate change.
- Authority for the absence of an ADR and for the choices above: the owner rulings recorded by Dave
  on 2026-10-20 (no ADR: no new store and no architectural choice beyond the existing chokepoint
  pattern; no kill switch; no configuration gauge; the lockout case is documented, not redesigned;
  the audit-row coalescing question is deferred).
- Evidence mapping for the SOC 2 first-customer scope is in
  [enterprise-readiness-soc2-first-customer.md](../enterprise-readiness-soc2-first-customer.md).

## Follow-ups

- Consolidating the per-route copies onto the gate (#5876).
- Tuning the alert window and threshold against real traffic.
- Coalescing `csrf.denied` rows per session or principal (each refusal is one synchronous audit
  write; the per-IP rate limiter is the only flood bound today). Deferred by owner ruling; it trades
  audit evidence for load, so it is the owner's decision.
- Moving the MCP adapter's cookie mode to tokens.
