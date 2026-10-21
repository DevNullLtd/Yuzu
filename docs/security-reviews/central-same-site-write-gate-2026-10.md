# Design record: central same-site gate for cookie-session writes

**Date:** 2026-10-20
**Subject:** cookie-session writes (and cookie-session requests that dispatch work) require a same-site `Origin` or `Referer` (or same-origin fetch metadata), decided once in the
server's pre-routing handler.
**Code:** `server/core/src/same_site_write_policy.hpp` (the pure decision and its invariants
banner), `server/core/src/same_site_write_gate.hpp` (counter, audit row, 403 body), the one call in
`server/core/src/server.cpp`.
**Tripwires and closure evidence:** `scripts/e2e-security-test.sh` (live stack),
`tests/test_same_site_wiring_lexical.py`, `tests/unit/server/test_same_site_exempt_inventory.cpp`.
**Operator documentation:** [REST API](../user-manual/rest-api.md) (cookie-session writes),
[Upgrading](../user-manual/upgrading.md), [Server Administration](../user-manual/server-admin.md)
(`--csrf-trusted-origin`). Architecture summary: [auth-architecture.md](../auth-architecture.md)
"Same-site gate for cookie-session writes".

## Decision

Any request other than `GET`, `HEAD` or `OPTIONS` that is authorised by a cookie session is
refused `403` `cross-site request refused` unless it carries an `Origin` or `Referer` naming this
site or an entry from `--csrf-trusted-origin`. The check is one function with one caller. A
per-route copy of the same test is defence in depth and serves unit tests that bypass pre-routing.
Cookie-session requests that dispatch work are held to the same rule by a reviewed list (see
"Guarded reads"); the sentence above describes the write-method rule.

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
  carve-out for read-only `POST`s. The one addition is the guarded-read table below.
- **Exemptions** are by placement only: `is_login_exempt_path`'s pre-session set, the health probes
  and the metrics endpoint return before session resolution and never reach the gate. There is no
  second list.
- **Predicate.** `Origin` and `Referer` only. It calls `browser_write_is_cross_site` and does not
  re-implement it. The refusal reason is derived from which of the two headers are non-empty and
  cannot change the decision. The decision also takes the web listener's TLS state
  (`Config::https_enabled`), passed explicitly with no default. On a listener that terminates TLS
  itself the same-host comparison requires an `https://` source and treats only `:443` as a default
  port, on both sides. On a plain listener the comparison stays loose (the `Host` header carries no
  scheme), except that a scheme-qualified `https://` trusted origin pins that host: an `http://`
  source for the same host and port is then not same-host. A literal `null` is refused whatever the
  allowlist holds.
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
- Boot prints one line to standard output, before the log level and `--log-file` are configured (so
  neither hides it nor receives it): the accepted trusted-origin set when any is declared, otherwise the rule
  and that no `--csrf-trusted-origin` value was accepted. The refusal warning names the flag and is
  time-throttled: at most one per 60 seconds per reason (one slot per refusal reason and one for
  `gate_error`), the first of each reason since start always logs, and the counter records every
  refusal.
- Ordering, an accepted guarantee: after authentication; before step-up evaluation, challenge
  emission and route-handler effects. A cookie wins over a token credential on the same request.

## Closure evidence, tripwires and their limits

1. **Closure evidence for the production wiring:** the cookie-session category of
   `scripts/e2e-security-test.sh`. It drives a real server over a real socket with a logged-in
   cookie session and asserts both the HTTP status and the refusal text: a write with neither
   header, with a foreign `Origin` and with `Origin: null` is refused; a write with a same-site
   `Origin` or `Referer` reaches the handler; a bearer-token write with neither header is not
   refused by the central check (the refusal is recognised by its own remediation text, which the
   per-route checks do not emit); a write using a method with no registered handler is refused
   alike and an admitted one is not; the session still works afterwards. It then reads the audit
   REST API back and requires at least one new `csrf.denied` row per refusal, each `denied`, with a
   `<METHOD> <path>` target, a closed-set `reason=` token and the logged-in admin as principal. A
   transport failure fails the case. The `/test` default and `--full` pipelines run it after the Phase 5 fan-out; `--quick`
   has no live stack and skips it, and no CI workflow runs it.
2. The unit pipeline fixture (`test_same_site_write_gate.cpp`) models production: it applies the
   gate through a real pre-routing pipeline over a real socket, but it is a copy of the call shape,
   not the production handler.
3. `tests/test_same_site_wiring_lexical.py` is a best-effort source-text tripwire, not proof. It
   pins the single call site in `server.cpp`: its position after authentication, the pinned set of
   early returns before it with their conditions, no early return between authentication and the
   gate, the call before the engine stash, and the absence of step-up entry points from the
   pre-routing handler. A relocation that keeps every token in order, or a textually identical but
   semantically different condition, is not detected.
4. `tests/unit/server/test_same_site_exempt_inventory.cpp` evaluates the real pre-session
   predicates over every mutating registration it can see and requires the bypassed set to equal a
   recorded ledger. Source-text scan with documented blind spots: a computed path, a new receiver
   spelling and a registration made in a `.hpp` are invisible to it. A read-method handler that
   dispatches work is covered by the guarded-read table instead (see "Guarded reads" below), and
   its own scan has the limits stated there.

The wiring tripwire first applies line splicing, then counts the gate, session-resolve,
engine-stash and audit-sink tokens on text with comments removed and string and raw-string literals
blanked. It rejects line splices, digraph and trigraph spellings, a preprocessor directive inside
the handler body, calls that never return, rebinding of the pinned names, and any additional
pre-routing handler registration however it is spelled; it requires that the call is not nested in
any `if` chain and sits at a statement boundary, and that the text between session resolution and
the call is exactly the pinned authentication block. Each rejected class has a mutation case in its
self-test. Its stated limits: it cannot see macro, helper or alias tricks (for example a
`const_cast` on the session, a change to `req.method` made through a helper, or reassignment of the
configuration or metrics objects before the call), it reads only `server/core/src` so a registrar
elsewhere is invisible to it, and it relies on one reading of the preprocessor where compilers
differ in detail. It also does not see a later assignment or nulling of the audit-sink member after
its initialiser, a new `httplib::Server` object that serves routes without the handler, or an
unlisted pre-resolve block that returns before authentication (such a block is unconstrained apart
from the pinned returns). It pins the registration's receiver and that the registration is an
unconditional statement, and the call's argument list, including the web listener's TLS-state
member (a literal there fails it). The live-stack category reads the `csrf.denied` rows back
through the audit API, which also covers an unwired audit sink in the production build. The
tripwire's blind spots rest on review, on the integration tests that drive the real handler, and
on the live-stack category above.

## Guarded reads

**Decision (owner, 2026-10-21).** Cookie-session requests that dispatch work are held to the same
rule as writes even when their method is `GET` or `HEAD`. The owner chose a central, reviewed list
guarded by the same gate over converting those requests to `POST`.

**Options considered.**

| Option | Outcome |
|---|---|
| Central reviewed list guarded by the existing gate (chosen) | One decision, one caller, one counter, audit row and alert set. No route, client or test changes for the dashboard. The list is data, so adding an entry is a one-line reviewed change. |
| Convert each request to `POST` | Puts the work behind the existing write rule with no new mechanism, but changes the request contract of every dashboard caller and test, and leaves the next such request to be noticed by review alone. Not chosen. |
| Per-handler checks | Reopens the drift the central gate exists to remove. Not chosen. |

**Mechanism.** `is_guarded_read(method, path)` is true for `GET` or `HEAD` with a path that exactly
equals an entry of `kFetchMetadataGuardedPaths` (`same_site_write_policy.hpp`); no prefix match, no
query. `HEAD` is included because the HTTP library routes it to the `GET` handler. `OPTIONS` is never
guarded. The gate's first statement returns for a request that is neither a write method nor a
guarded read, so an ordinary read costs one method test and one path-prefix compare. For a guarded
request the decision is: token sources admitted; otherwise, if `Sec-Fetch-Site` is present, `same-origin`
or `none` admitted (case-insensitive) and any other value refused with `origin_mismatch`; a repeated
`Sec-Fetch-Site` header is treated as a non-matching value and refused with `origin_mismatch` (the HTTP
library reads the last value, so a first value could otherwise disagree with the one decided on); if the
header is absent, the `Origin`/`Referer` rule applies exactly as for a write (neither header refused as
`no_origin_no_referer`; otherwise the same-site comparison with trusted origins and the listener's TLS
state). `Sec-Fetch-Site` is a forbidden header name: page script cannot set it. A browser sends it only
to a potentially trustworthy origin (HTTPS or loopback), so a plain-HTTP listener on a non-loopback
address, and Safari before 16.4, send no fetch metadata and fall to the `Origin`/`Referer` rule. A
same-origin `GET` carries no `Origin`, so on such a deployment the guarded requests depend on `Referer`;
the server's own default `Referrer-Policy` (`strict-origin-when-cross-origin`) supplies it, and a proxy
or page policy of `no-referrer` would break them. A TLS-terminating proxy is unaffected, because the
browser talks to the proxy over HTTPS. `none` is a navigation the user started (typed address,
bookmark). `same-site` is refused because a sibling origin is not this origin. There is no new refusal
reason, metric, label or alert; the audit `target_id` is `GET <path>` or `HEAD <path>`. The audit
`detail` text is the fixed write wording ("browser write refused") for a guarded request too.

**Evidence.** The policy truth table covers every table entry for both methods; the pipeline fixture
registers one guarded canary and asserts refusal shape, counter, audit row, handler not run, admission
and the fallback cases; `tests/unit/server/test_same_site_exempt_inventory.cpp` fails on a table entry
that is not a registered `GET` route and on a read-method registration whose handler contains a
dispatch or state-change marker but is on neither the table nor a reviewed ledger (best-effort, lexical: a computed
path or a dispatch reached through more than one helper hop is invisible to it); the live-stack
category in `scripts/e2e-security-test.sh` drives one covered request through a real server with a
cookie session for each fetch-metadata value, the header-less case, the `Referer` fallback, a token
caller, `HEAD`, and the token-reachable v1 read in the table. The policy suite also spells out the
table content literally, so replacing an entry fails it, and the pipeline fixture checks a repeated
`Sec-Fetch-Site` header and the path spellings that the router and the gate must decide alike.

**Round-6 additions.** The table gained further requests that persist state or force a refresh when
read. One of them is a v1 REST route that is both cookie-reachable and token-reachable; token callers
stay exempt there as everywhere. The cheap prefilter in `is_guarded_read` therefore accepts two path
prefixes instead of one. The compile-time checks on the table carry messages that explain this coupling. The
refusal remediation text now mentions fetch metadata.

**Options not taken.** Requiring `Sec-Fetch-Mode: navigate` for the `none` value, so that only a real
navigation is admitted without an `Origin` or `Referer`, is optional hardening and is not done: it
would not change the prefetch residual below, and it adds a second header to reason about. Converting
the guarded requests to `POST` stays the option not chosen above.

**Residuals, accepted and stated.** Header checks do not distinguish a user action from a prefetch,
prerender or link preview that the same user's own browser issues on its own initiative: such a
request carries `same-origin` or `none` and is admitted. A client that sends neither fetch metadata
nor `Origin`/`Referer` is refused. A request whose path is not on the table is not checked, so
completeness rests on the tripwire above plus review. Deliberately outside the list, by decision: a
small number of cookie-reachable `GET`s that read secrets-adjacent material or hold a stream lease.
The list covers the requests that dispatch work and the reads known to persist or refresh server
state; it is not a claim that every state-changing `GET` is guarded. Fetch metadata is only as trustworthy as the
client that sends it; a non-browser client can set any value, which is why this narrows browser-driven
cross-site requests and is not an authorisation control.

## Proxy deployments

A reverse proxy that rewrites `Host` makes a browser's own `Origin` look foreign. The operator
declares the public origin with `--csrf-trusted-origin`; the boot line and the first refusal name
the flag. A proxy must not inject or rewrite `Origin` or `Referer`, which would turn the control off.
There is no kill switch and no observe-only mode. Known consequence, accepted: a deployment whose
proxy rewrites `Host` and that has no declared origin and no pre-existing API token loses every
dashboard write, including creating a token, until it restarts with the flag or reaches the server
directly; sign-in, ordinary reads and the health probes keep working, so no probe detects it. The upgrade
section opens with a pre-upgrade checklist for this reason.

The server behind a TLS-terminating proxy listens in plain HTTP and cannot see the public scheme, so
the operator declares the public origin WITH its `https://` scheme, which pins the scheme for that
host (a plain-`http://` source for it is refused) whether or not the proxy forwards `Host`. Residual,
documented: a proxied deployment WITHOUT a declared `https://` origin still treats an `http://`
`Origin` for the same host and port as same-site; the remedy is the declaration.

## Decisions recorded

- MCP transport: the endpoint is gated like any other. A cookie caller sends `Referer`, or an
  `Origin` that both the gate and the endpoint's own allowlist accept. The endpoint's own `Origin`
  check keeps applying independently when streaming is on. The refusal is the REST error envelope.
- Per-route copies stay in place in this change. They fall into two predicate variants: copies of the
  token-exempt predicate (`browser_write_is_cross_site`), which are unreachable in production, and
  copies of the plain `origin_is_same_site` test, which are not token-exempt and so still answer a
  token caller of those dashboard-panel routes. "Defence in depth" and "token callers are not
  affected" are therefore stated with that exception.
- Scheme-aware same-host comparison: added in the governance fix round per owner instruction. The
  listener's TLS state is a required argument of the decision and the gate (no default), read from
  `Config::https_enabled` at the one production call site; the per-route copies keep the loose
  default. Residual for proxied deployments without a declared `https://` origin, stated above.
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
- A reviewed ledger for read-method handlers that contain a dispatch marker but only read starts
  empty; entries need a one-line reason.
- Tuning the alert window and threshold against real traffic.
- Coalescing `csrf.denied` rows per session or principal (each refusal is one synchronous audit
  write; the per-IP rate limiter is the only flood bound today). Deferred by owner ruling; it trades
  audit evidence for load, so it is the owner's decision.
- Moving the MCP adapter's cookie mode to tokens.
