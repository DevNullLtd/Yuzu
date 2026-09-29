# The REST + MCP Twin Recipe

**Status:** recipe (F3 of the API-parity programme, issue #3993). Read this before starting any
of the ~36 twin PRs enumerated by #2146.

## Why this document exists

ADR-1005 Decision 4 and `docs/adr/0031-presentation-core-engine-decomposition.md` migration step
3 require every dashboard capability to be reachable over versioned REST **and** MCP, discoverable
(A2), A4-enveloped, with a securable/operation pair and an audit verb. #2146 measured the gap at
roughly 40-60 missing capabilities — a programme, not a handful of one-off PRs. Without one written
recipe, each of those ~36 PRs re-derives the pattern independently, and the programme's two most
likely failure modes become near-certain instead of avoidable:

1. **JSON-shape drift.** The REST handler and the MCP handler each grow their own row-building
   lambda, and the two quietly diverge over time as one gets a bugfix the other doesn't.
2. **Fail-mode unification.** REST, the HTML dashboard fragment, and MCP have **deliberately
   different** audit-failure postures (below). A twin PR that "cleans this up" by picking one
   posture and applying it everywhere passes every test it writes and breaks a SOC 2 control.

This recipe is written once, from the two best-parity exemplars already in the tree
(`engine-principals`, `access-reviews`, and the `discover_routes.{hpp,cpp}` shared-builder family),
plus the real anti-pattern already on record (`network_routes.cpp`'s duplicated stat-row builders).
Every citation below was checked against `origin/dev` in the course of writing this doc; where a
line number in an earlier research note had drifted, the correction is noted inline.

Related reading: `docs/agentic-first-principle.md` (A1 dashboard parity, A2 discovery, A4 error
envelope), `docs/adr-1005-execution-plan.md`, `docs/mcp-server.md` (the pre-existing, narrower
tool-registration checklist this document supersets), issue #2146 (the sizing/enumeration issue
this recipe programme answers), issue #3991 (F1 — the per-domain conformance ledger a twin PR
updates; see checklist step 10).

---

## Table of contents

1. [The one rule: a shared builder, projected three ways](#1-the-one-rule-a-shared-builder-projected-three-ways)
2. [REST route recipe](#2-rest-route-recipe)
3. [MCP tool recipe](#3-mcp-tool-recipe)
4. [The per-surface audit fail-mode table](#4-the-per-surface-audit-fail-mode-table)
5. [Chokepoints to route through when relevant](#5-chokepoints-to-route-through-when-relevant)
6. [Test recipe](#6-test-recipe)
7. [The full checklist](#7-the-full-checklist)
8. [Worked example: `SoftwareDeployment` MCP twins](#8-worked-example-softwaredeployment-mcp-twins)

---

## 1. The one rule: a shared builder, projected three ways

**REST, MCP, and the HTML dashboard fragment must call the same function to build the response
body's data.** Not "call similar functions." Not "keep them in sync by convention." The *same*
function, in one translation unit, that each surface calls and then serializes/wraps differently.
This is the single highest-leverage rule in this recipe: it turns "did the JSON shapes drift" from
a review question into a compile-time impossibility.

### The exemplar: `discover_routes.{hpp,cpp}`

`server/core/src/discover_routes.hpp` (158 lines) declares five pure builder functions —
`build_permissions_catalog`, `build_instructions_catalog`, `build_routes_catalog`,
`scope_kinds_catalog`, `build_plugins_catalog` — each taking only the store/registry it needs and
returning a `DiscoveryDoc { std::string json; std::string etag; }`. The file header states the
intent explicitly:

> "The five builder functions (`build_*_catalog`) are pure — no I/O beyond reading the
> store/registry pointer passed in — and are declared here specifically so `mcp_server.cpp` can
> call the SAME functions for the mirrored `discover_*` MCP tools... REST and MCP therefore cannot
> drift from each other by construction."

`docs/agentic-first-principle.md` §A2 makes the same claim in the platform-invariant document:
"Each is mirrored as a **read-only MCP tool**... sharing the SAME builder functions as their REST
siblings — REST and MCP cannot drift from each other by construction."

`DiscoverRoutes` (same header) also demonstrates the REST registration half of this pattern: two
`register_routes` overloads, one taking `httplib::Server&` (production) and one taking
`HttpRouteSink&` (unit-testable, no socket) — see §2 below.

### The anti-pattern: `network_routes.cpp` / `mcp_server.cpp`'s duplicated stat builders

Contrast this with the network-quality surface. `rest_api_v1.cpp:11467` defines a local lambda:

```cpp
auto net_stat_json = [](const std::optional<NetPerfStat>& s) -> std::string { ... };
```

and `mcp_server.cpp:8093` defines **the same lambda body**, under the local name `stat_json`, for
the MCP `get_network_fleet` tool. (The DEX perf family repeats the pattern too:
`rest_api_v1.cpp:10698`'s `perf_stat_json` vs `mcp_server.cpp:7444`'s `stat_json`.) These are not
malicious — they're the natural result of writing the REST handler first, then copy-pasting into
the MCP handler because the two files don't share an obvious common home for a three-line
formatter. But it means a future bugfix to one (say, a NaN-handling fix) has to be remembered and
reapplied to the other by a human, forever. This is the failure mode Rule 1 exists to make
structurally impossible — **a twin PR must not add a second copy of a row-builder lambda.**

*(Correction to prior research: an earlier note cited these as `rest_api_v1.cpp:11468` /
`mcp_server.cpp:8091`; the verified lines against `origin/dev` are `11467` and `8093`. The DEX
`perf_stat_json`/`stat_json` pair is a second, independently-verified instance of the same
anti-pattern, not previously called out.)*

### The rule, stated for a twin PR

- Put the shared builder in a `*_model.cpp`/`*_model.hpp` pair (or, if the capability already has a
  dedicated `*_routes.{hpp,cpp}` module, colocate it there — see `discover_routes.hpp`'s own
  precedent of living beside its route class). It must not `#include` anything REST- or
  MCP-specific (no `httplib.h`, no `mcp_jsonrpc.hpp`) — the whole point is that both call it.
- The builder returns a value type (a `struct`, or a raw JSON string plus whatever
  ETag/pagination metadata the caller needs) — never an `httplib::Response&` or JSON-RPC response
  object. Each surface's thin wrapper does its own enveloping (A4 for REST/MCP errors, `ok_json`/
  `list_json` for REST success, `tool_result(...)` for MCP success).
- If the dashboard fragment renders HTML, its renderer should call the *same* builder for the
  underlying data and then format it as HTML — not re-derive the data. `network_routes.hpp`'s
  `render_network_overview_fragment(const NetPerfSnapshot& snap)` is that shape: it takes the
  already-built snapshot type, not a store handle it re-queries.

---

## 2. REST route recipe

### Where routes register

Two patterns coexist in the tree; either is acceptable for a new twin, but match the existing
convention for the domain you're extending:

- **Centralized**, inline in `server/core/src/rest_api_v1.cpp`'s big `register_routes` function —
  the majority of routes, including all four `software-deployments` handlers used as this
  document's worked example (§8).
- **Self-registering module**, a dedicated `<domain>_routes.{hpp,cpp}` pair with its own
  `RoutesClass` exposing `register_routes(...)`. `network_routes.hpp`/`.cpp`, `dex_routes.cpp`, and
  `discover_routes.hpp`/`.cpp` are this shape.

**Whichever you pick, ship the two-overload pattern** — a production overload taking
`httplib::Server&` and a testable overload taking `HttpRouteSink&`. `network_routes.hpp:74-84`:

```cpp
/// Register the /network routes. The page shell is auth-only static chrome;
/// the data-bearing fragments gate on GuaranteedState:Read.
void register_routes(httplib::Server& svr, AuthFn auth_fn, PermFn perm_fn, AuditFn audit_fn,
                     PerfFn perf_fn = {});

/// HttpRouteSink overload — same registration against the polymorphic seam
/// so the handlers are unit-testable in-process via TestRouteSink (no
/// httplib acceptor; the #438 TSan trap). The httplib::Server& overload
/// wraps + delegates.
void register_routes(HttpRouteSink& sink, AuthFn auth_fn, PermFn perm_fn, AuditFn audit_fn,
                     PerfFn perf_fn = {});
```

The `httplib::Server&` overload is a thin wrapper that constructs an `HttplibRouteSink` and
delegates — never register directly against raw `httplib::Server` in a way that bypasses the sink,
or the route becomes untestable via `TestRouteSink` (§6).

### The A4 envelope helpers

Two headers, split on whether they touch `httplib`:

- `server/core/src/rest_a4_envelope.hpp` — pure builders, no `httplib.h` include, so they're
  testable in isolation: `make_correlation_id()`, `error_json_a4(code, message, cid, ...)` (three
  overloads, the third taking the full `A4ErrorOpts` for `retry_after_ms`/`remediation`/
  `permission`/`approval_id`+`status_url`), and `make_event_envelope(...)` for SSE.
- `server/core/src/rest_a4_envelope_http.hpp` — the `httplib::Response&`-coupled wrappers:
  `ensure_correlation_id(res)` (mints or reuses `X-Correlation-Id`), `a4_denial(res, code, message,
  opts)` (caller sets `res.status`), and `a4_error(res, message, opts)` (derives `code` from the
  already-set `res.status`).

Every new REST error path goes through `detail::a4_error(res, "...")` or `detail::a4_denial(...)`
— never a hand-rolled `{"error": "..."}` body. The legacy bare `error_json()` helper is retired
(#1470; see the comment at `rest_api_v1.cpp:215-218`).

### Success envelopes

`rest_api_v1.cpp:211` (`ok_json`) and `:220` (`list_json`), both near the top of the file:

```cpp
std::string ok_json(std::string_view data_json) {
    return JObj().raw("data", data_json).raw("meta", R"({"api_version":"v1"})").str();
}

std::string list_json(std::string_view data_json, int64_t total, int64_t start = 0,
                      int64_t page_size = 50) {
    auto pag = JObj().add("total", total).add("start", start).add("page_size", page_size).str();
    return JObj().raw("data", data_json).raw("pagination", pag)
        .raw("meta", R"({"api_version":"v1"})").str();
}
```

Use `ok_json` for a single object/scalar result, `list_json` for anything returning an array with a
total count. Both wrap the shared builder's output (§1) — they never build the `data` payload
themselves.

### OpenAPI entry

`openapi_spec()` (`rest_api_v1.cpp:516`) is a hand-maintained raw-string literal (split into
several `R"json(...)"` segments to stay under MSVC's ~16 KB per-literal cap — see the comment at
`:1109-1111`), **not** generated from the live route table. `docs/agentic-first-principle.md` §A2
flags this explicitly: `GET /api/v1/discover/routes` subsets this same document and inherits its
"can under-report" caveat. Add one `"/<path>": { "get"/"post": {...} }` entry per route, following
the density of an existing entry in the same tag family — e.g. `/network/fleet`
(`rest_api_v1.cpp:1107`) for a short read, or `/dex/devices/{id}/app-perf`
(`rest_api_v1.cpp:1076`) for one that documents its audit/fail-closed posture inline. Match that
density: summary, tag, a description paragraph naming the required permission and any audit verb,
full `parameters`, and every realistic `responses` status (200/400/403/503, plus the
`Sec-Audit-Failed` header block on any audited route — see `/network/devices`'s entry at
`rest_api_v1.cpp:1113` for the header-documentation shape).

### `docs/user-manual/rest-api.md` entry

Follow the existing per-route entry shape (e.g. `GET /api/v1/management-groups` at
`docs/user-manual/rest-api.md:334`): an `####` heading with the method+path, one-line summary,
**Permission:** line, and a fenced `json` **Response:** example built from realistic sample data —
not a schema dump. Add the route to the `## Table of Contents` (line 55) in its domain's existing
group, or start a new `###` group if the twin is the first route in a new domain.

---

## 3. MCP tool recipe

### Four tables plus a dispatch branch

Every MCP tool touches five things in `server/core/src/mcp_server.cpp`, and all five must agree or
the server refuses to boot. (A destructive action-twin also has a sixth thing to decide, in
`mcp_policy.hpp` rather than `mcp_server.cpp` — `requires_approval()`, not boot-enforced; see
below.)

| Table | Line (verified `origin/dev`) | What it holds |
|---|---|---|
| `kTools[]` | 365 | `{name, description, input_schema_json, output_schema_json}` — the served tool |
| `kToolSecurityRows[]` | 1850 | `{name, {securable_type, operation, service_scope}}` — RBAC pair + confinement class |
| `kWriteToolsRaw[]` / `kWriteTools` | 1750 / 1783 | raw array + derived set of every non-Read tool name (the `--mcp-read-only` guard keys on this) |
| `kToolAnnotation` | 2332 | `{effect (ReadOnly/Additive/Destructive), idempotent, title}` — served `annotations` |
| dispatch branch | wherever the tool's domain cluster lives | `if (tool_name == "...") { ... }` |

*(Correction to prior research: `kToolAnnotation` was cited at "~2338"; the verified line is
`2332`. `kToolSecurityRows[]` and `kTools[]` matched their cited lines, `1850` and `365`, exactly.)*

A served tool with no `kToolSecurityRows` row, a row naming no served tool, a non-Read tool missing
from `kWriteTools`, a Read tool wrongly present in it, an operation/securable outside the RBAC
catalogue, or a `global_safe` service-scope claim with no backing `kServiceScopeGlobalSafe` entry —
all of these are **boot failures**, not lint warnings. `validate_tool_security_registration`
(`mcp_server.cpp:2153`) collects every such offence into one deterministic, sorted message and
`throw`s `std::runtime_error` (`mcp_server.cpp:2286-2289`) from inside `McpServer::McpServer()`
(the ctor calls it at `mcp_server.cpp:2895`). There is no partial-boot fallback — get any one of the
four tables wrong and the server does not start. Treat that as the safety net it is, not an
obstacle: run the server locally after adding a tool and let it tell you what's missing.

### Tier vs RBAC — and the lesson already paid for once

`server/core/src/mcp_policy.hpp`'s `tier_allows(mcp_tier, securable_type, operation)` runs
**before** RBAC (readonly / operator / supervised — see the file header comment,
`mcp_policy.hpp:7-14`). The critical property for a twin PR: **`tier_allows` is keyed on the
`(securable_type, operation)` pair, not on the tool or the route.** `auth_routes.cpp`'s
`require_permission`/`require_scoped_permission` consult this exact same function for **every**
transport (REST and MCP alike). That means widening a tool's tier requirement widens every other
route/tool sharing that same securable/operation pair too — REST included.

The file's own "ROUND-3 FINDING" comment (`mcp_policy.hpp:30-73`) is the fully-worked cautionary
tale, worth reading before touching this function: an early attempt admitted
`rotate_api_token`/`confirm_api_token_rotation` at the `operator` tier by adding `if
(securable_type == "ApiToken" && operation == "Write") return true;`. That silently widened
**every** `ApiToken:Write` surface — including `POST /api/v1/tokens` (plain token creation) — to
operator-tier tokens, on both REST and MCP, because the check has no notion of which *tool* is
calling. A second attempt tried a tool-scoped exception at the two call sites instead; that turned
out to be structurally unreachable, because `mcp_server.cpp`'s generic tier gate resolves admission
from the `(securable, operation)` pair for every tool **before** any per-tool handler code runs — a
call-site-local exception never executes.

**The actual fix, and the rule for a twin PR:** mint a **distinct operation string**,
`ApiToken:Rotate`, used only by the two rotation tools' `kToolSecurityRows` entries and the REST
rotate/confirm routes' `perm_fn` calls — never by the plain-create route, which keeps
`ApiToken:Write`. Two different strings cannot be conflated by a shared string-keyed lookup, so the
operator-tier allowance on `Rotate` cannot touch `Write` on any transport, by construction. **If a
twin PR finds that a securable/operation pair it wants to expose at a narrower tier is already used
by something broader, the fix is always a new operation string — never a tool-specific `if` inside
`tier_allows`.**

### A fifth registration point: `requires_approval()`

`tier_allows()` decides *whether* a supervised-tier token may call a tool at all; a separate
function, `requires_approval(mcp_tier, securable_type, operation)` (`mcp_policy.hpp:97`), decides
*whether that call must go through the maker-checker approval workflow first* — checked, per its
own doc comment, "AFTER `tier_allows()` returns true." **It is not derived from anything else — it
is its own hard-coded, exact-match `(securable_type, operation)` list** (supervised tier:
`Execution:Execute`, any `Delete`, `Policy:Write`, `Security:Write`, `Security:Execute`,
`UserManagement:Write`, `ManagementGroup:Write`; operator tier: `Tag:Delete` only —
`mcp_policy.hpp:105-158`). A pair that is destructive in the everyday sense but **absent** from this
list runs un-approved at supervised tier, full stop — there is no fallback heuristic ("Write implies
approval" is not the rule; `ApiToken:Write` itself is not in the list, deliberately, per the comment
at `mcp_policy.hpp:124-151`).

**This means a twin PR for a destructive action-twin must explicitly decide, and state in the tool
description, whether its `(securable_type, operation)` pair belongs in `requires_approval()`** — not
assume it inherits the REST route's own gate. A REST route's MFA step-up (`step_up_fn`) and MCP's
approval workflow are two different mechanisms answering the same "is this consequential enough to
need extra friction" question for two different callers (an interactive human vs. a non-interactive
token); one does not imply the other is wired. If the twin PR adds the pair to `requires_approval()`,
say so explicitly and reference the existing entries' rationale style (most entries carry a short
"why" comment, and the deliberately-absent `ApiToken:Rotate` case is documented at length as the
worked precedent for reasoning through the decision either way). Treat this as a genuine fifth thing
to register alongside the four tables in §3's checklist — `docs/mcp-server.md:38`'s checklist does
not name it, and neither did the four-table framing this document opened with, which is itself a
correction worth carrying forward from writing this recipe.

### Superseding, not duplicating, `docs/mcp-server.md`

`docs/mcp-server.md:38` already carries an "Adding a tool (checklist)" bullet covering the four
tables, the boot-failure behavior, and the `output_schema_json` CI-fatal (non-boot) completeness
gate (`kOutputSchemaExempt`, `test_mcp_server.cpp`'s `tools/list` contract test). That checklist is
correct and should stay — this document does not replace it, it wraps it in the REST + audit +
RBAC + test + docs steps a *twin* additionally needs (§7's full checklist folds it in as steps
5-6).

---

## 4. The per-surface audit fail-mode table

**This is the section most likely to be gotten wrong, and getting it wrong breaks a SOC 2 control
rather than failing a test.** `server/core/src/rest_audit.hpp:28-40` states the three postures
explicitly:

> "HTTP routes wrap it with `emit_behavioral_audit`, which sets the `Sec-Audit-Failed: true`
> response header on failure. The caller then picks its posture from the returned bool — HTML
> dashboard fragments PROCEED and render (a transient audit hiccup must not blank the operator's
> lens; the header carries the signal), REST JSON integrations FAIL CLOSED (503) so a downstream
> CMDB never records evidence-less PII as audited. MCP wraps the kernel itself (JSON-RPC has no
> response-header channel) and surfaces the gap through its own body field."

| Surface | On audit-persist failure | Mechanism |
|---|---|---|
| **REST JSON** | Fails closed: `503` + `Sec-Audit-Failed: true` header, body never sent | `emit_behavioral_audit` return value checked; caller returns before reading the store |
| **HTML dashboard fragment** | Proceeds anyway, renders the data | `emit_behavioral_audit` return value explicitly discarded with `(void)` |
| **MCP** | Proceeds anyway, flags the gap in the body | `try_persist_audit` (the lower-level, header-free kernel) return value captured and surfaced as `"audit_persisted": false` in the JSON-RPC result payload |

**A twin PR must implement all three postures on its own surface — never pick one and apply it to
the others.** Concretely: a REST route must check the bool and fail closed; the same data's MCP
twin must check the bool and add `audit_persisted:false` on failure, never fail the whole call; and
if a dashboard fragment already exists for the same data, its `(void)`-discard must not be
"fixed" to also fail closed.

### The two functions involved

`server/core/src/rest_audit.hpp` layers two functions:

- **`try_persist_audit`** (line 64) — the channel-agnostic kernel. Calls `audit_fn`, catches any
  throw (a `bad_alloc`-class failure is otherwise silent), logs the catch arm, returns the persist
  outcome. Templated on the specific route class's `AuditFn` alias so it binds without depending on
  any one of `RestApiV1::AuditFn` / `DexRoutes::AuditFn` / `mcp::McpServer::AuditFn`. This is what
  MCP calls directly, since it has no response-header channel to layer on top.
- **`emit_behavioral_audit`** (line 138) — the HTTP-specific wrapper: calls `try_persist_audit`,
  then sets `Sec-Audit-Failed: true` on `res` if it failed (idempotently — see the header-multimap
  comment at lines 144-149, since `httplib::Response::set_header` **appends**, not replaces). Marked
  `[[nodiscard]]` specifically so a REST route can't silently drop the bool and serve PII after a
  known audit-persist failure (line 133-136) — a fragment's legitimate `(void)`-discard is the one
  place that's meant to ignore it, and it does so explicitly.

A null/empty `audit_fn` (audit-off deployments) is **not** a persistence failure — both functions
return `true` and set no header in that case (line 38-41). Don't conflate "audit disabled" with
"audit failed."

### Worked example (real code, both halves you can copy)

**REST fail-closed**, `server/core/src/rest_api_v1.cpp:10253-10265` (`GET
/api/v1/dex/devices/{id}/app-perf`, verb `dex.device.app_perf.view`):

```cpp
if (!detail::emit_behavioral_audit(audit_fn, req, res, "dex.device.app_perf.view",
                                   "success", "Agent", agent_id,
                                   "REST per-device app-perf drill cid=" + cid)) {
    res.status = 503;
    res.set_content(
        detail::error_json_a4(503, "audit subsystem unavailable; refusing to serve "
                                   "device data without durable evidence",
                              cid, 5000, "retry the request"),
        "application/json");
    return;
}
```

**Fragment set-and-proceed**, `server/core/src/dex_routes.cpp:3462-3465` (`GET
/fragments/dex/device/app-perf`, same verb, same underlying data):

```cpp
(void)detail::emit_behavioral_audit(
    audit_fn_, req, res, "dex.device.app_perf.view", "success", "Agent", id,
    "device app-perf-over-time drill (B1 retained)");
const auto rows = app_perf_providers_.device(id);
// ... renders `rows` regardless of the audit outcome; the header alone carries the signal.
```

**MCP `audit_persisted:false`**, `server/core/src/mcp_server.cpp:8026-8051`
(`compare_app_perf_versions`, verb `dex.app_perf.compare`):

```cpp
// Set-and-proceed: capture the persist bool and surface `audit_persisted:false` in
// the body (MCP has no Sec-Audit-Failed header channel — the documented MCP posture).
const bool audit_ok = mcp_audit("success", "group=" + audit_token(group) + " app=" + ...);
JObj payload_obj;
payload_obj.add("app", app) /* ... */;
if (!audit_ok)
    payload_obj.add("audit_persisted", false);
```

**Honesty note on this example** — these three snippets are real, current code and correctly
demonstrate each posture. *(Correction, #4035:* the per-device drill's MCP gap this paragraph
originally described is now closed — `get_dex_device_app_perf` (`mcp_server.cpp`) is the MCP twin,
calling the shared `dex_device_app_perf_json` builder (`dex_read_model.hpp`) the REST route also
calls, per Rule 1. `dex.device.app_perf.view` is now a genuine REST+fragment+MCP triplet, one of the
first in the tree — but `compare_app_perf_versions` is still a *different*, fleet/cohort-scoped route
in the same DEX app-perf family, not a fourth surface of the same capability; see the correction
below about which posture it actually demonstrates.) A codebase-wide search for one *single* route
with a genuine REST+fragment+MCP triplet otherwise turned up none as clean as this recipe would
like; the `network`/`fleet`/`devices` and `engine-principals`/`access-reviews` families come closest
to full REST+MCP parity but predate the fragment layer or don't have one.

Also worth knowing: for MCP, the generic per-tool audit wrapper `mcp_audit` (`mcp_server.cpp:3959`)
stamps the audit action as `"mcp." + tool_name` by default; several tools call `try_persist_audit`
directly with the REST-side domain verb instead, so the audit trail reads the same regardless of
transport — `get_dex_signal_detail` and #4035's `get_dex_device_score`/`get_dex_device_app_perf` are
real examples of this. **Prefer the domain verb over the generic `mcp.<tool_name>` action** when a
REST twin with an established verb already exists — that keeps the audit log queryable by capability
rather than by transport. *(Correction, #4035: `compare_app_perf_versions` — cited above as an
example of this — does NOT actually do it. Re-reading its handler in full: the only audit call is
the generic `mcp_audit("success", ...)`, which persists `action="mcp.compare_app_perf_versions"`, not
the domain verb `dex.app_perf.compare` this paragraph claimed. Its DENIAL path
(`deny_fleet_wide_service_scoped`) does correctly use the domain verb, and
`docs/user-manual/rest-api.md`'s own MCP tool table already documents the success-path discrepancy
correctly — this recipe doc was the one that had it wrong. Treat `get_dex_signal_detail` as this
rule's verified worked example instead.)*

### One more asymmetry: read vs. mutate

The three-posture table above is written for **reads**. A **mutating** route (§8's action-twin) has
already committed its side effect by the time the audit call runs — you cannot "fail closed" after
the fact without either double-executing or leaving the system in an inconsistent state. The
`software_deployment.start`/`.rollback`/`.cancel` sites (`rest_api_v1.cpp:9041-9130`, and see the
comment at `:8965-8969`) show the resulting pattern: the store call runs first, `try_persist_audit`
runs second, and a failure only sets `Sec-Audit-Failed: true` — the mutation's success response
still ships. **Don't try to make a mutating twin "fail closed" on audit failure** the way a read
can; set the header (REST), surface `audit_persisted:false` (MCP), and ship the result either way.

---

## 5. Chokepoints to route through when relevant

Not every twin needs all five. Route through the ones that apply to your capability's shape.

**`authorize_list_read`** (`server/core/src/rbac_store.hpp:340`, impl `rbac_store.cpp:2531`) — the
ADR-0017 admit-then-filter chokepoint for any per-agent **list** read. A bare `require_permission`
is inert against management-group confinement: a global-permission holder sees the whole fleet
regardless of scope. Don't call `authorize_list_read` directly in a new route, though —
`AuthRoutes::require_fleet_read` (`server/core/src/authz_gates.hpp`/`.cpp:14`) is the composed,
self-sufficient gate a route should call instead; it decides the management-group axis on top of
`authorize_list_read` and must **replace** a `require_permission` call on the route it migrates
onto, never be paired with one (see the "SELF-SUFFICIENT" doc comment in `authz_gates.hpp`). The
real, already-migrated example: `GET /api/v1/inventory/software` and its MCP twin
`query_installed_software` both moved onto `require_fleet_read` together (`authz_gates.hpp:35-38`)
— a genuine same-capability, same-gate REST+MCP pair to model a new list-twin's authorization on.

**`deny_fleet_wide_service_scoped`** — a lambda, not a shared function (each transport defines its
own copy: `rest_api_v1.cpp:1541`, `mcp_server.cpp:4222`), because `require_permission`'s
service-scoped-token branch checks only the `ITServiceOwner` **role**, never the token's own
service-tag scope. For any fleet-wide read that names an `agent_id` with no single agent to confine
a service-scoped token's own tag against, call this **before** the permission check (it audits the
denial and writes the 403 itself, returning `true` when the caller must return immediately). Both
implementations carry the same rationale comment inline — read whichever transport you're touching
before wiring a new fleet-wide list route.

**`check_targeting_shape` + `classify_dispatch_arm`** (`server/core/src/dispatch_target_shape.hpp`)
— for any **dispatch** route (something that sends a command to agents), not every list/read route.
`check_targeting_shape` (line 237) validates the parsed request body's targeting shape before
`classify_dispatch_arm` (line 308) decides which of `agent_ids` vs. `scope` wins (an explicit
`agent_ids` list always beats a broadcast request) — omitted targeting means the whole fleet
(`kBroadcastScope`, `"__all__"`, line 82), and a targeting expression that resolves to nothing is an
error, never silently inferred as "everyone" or "no one." A twin PR adding a new dispatch surface
must call `check_targeting_shape` on the **parsed JSON body**, never on the output of a helper that
collapses "omitted," "empty," and "malformed" into the same `{}` — that collapse is exactly the
#2500/#2492 defect class this header exists to prevent.

**`on_behalf_guard.hpp`** — reserved on-behalf-of header/field names, rejected outright (not
ignored) at the pre-routing chokepoint shared by REST and MCP (same httplib instance) and by the
gRPC interceptor. This is background context for a twin PR, not usually something it touches
directly: no delegation mechanism exists yet (ADR-1005 Phase 5), so there is nothing for a new
route to opt into. Just don't invent a header that happens to collide with a reserved name.

**`StreamBudget`** (`server/core/src/stream_budget.hpp`) — the one shared admission budget for
every held-open SSE response on the httplib worker pool (MCP's `GET /mcp/v1/`, `/api/v1/events`,
the dashboard SSE drawer, legacy `/events`). Only relevant if your twin involves SSE or any other
held-open streaming response. If it does: lease from the existing `StreamBudget` instance, never a
parallel counter — httplib is thread-per-connection, so an unleased stream silently pins a worker
nobody is counting against the shared cap.

---

## 6. Test recipe

### REST: `TestRouteSink`

`tests/unit/server/test_route_sink.hpp` is an in-process `HttpRouteSink` implementation that
exercises a route owner's `register_routes(HttpRouteSink&, ...)` overload with no socket, no
acceptor thread (the #438 TSan trap a live `httplib::Server` hit). Its header comment names what it
does and does **not** model (no percent-decoding, no multipart/chunked, none of the pre/post-routing
pipeline — so a gate that moves into pre-routing leaves every sink test green while the actual
protection is gone). Two invariants specific to fixture authors, both load-bearing:

1. **Declare the sink after the route owner it registers.** Handlers capture the owner's `this`;
   declaring the sink first and the owner second means the owner is destroyed while the captured
   handlers are still notionally reachable.
2. **Pass the content-type explicitly on a form-body POST.** `Post(path, body)` defaults to
   `application/json`, which does **not** populate `req.params` — a handler reading
   `req.has_param(...)` is then exercised through whatever fallback it has, not its production
   branch (the #1786 false-green, re-armable by omitting the content-type argument again).

### MCP: `mcp_server_testonly.hpp` + `test_operator_surface_twins.cpp`

`server/core/src/mcp_server_testonly.hpp` exposes copies of the TU-private tables so a separate test
TU can assert against them without duplicating the maps: `tool_security_rows_for_test()`,
`tool_annotation_names_for_test()`, `write_tool_names_for_test()`, `tool_names_for_test()`, plus
wrappers running the real C8 dispatch classifier/validator over synthetic tables.

`tests/unit/server/test_operator_surface_twins.cpp`'s `kExpectedTwins[]` array (line 417) is the
pattern to extend:

```cpp
constexpr TwinRow kExpectedTwins[] = {
    {"get_plugin_config", "PluginConfig", "Read", true},
    {"list_plugin_config", "PluginConfig", "Read", true},
    {"set_plugin_config", "PluginConfig", "Write", false},
    // ...
};
```

Each row is checked against the served `kToolSecurityRows`/`kWriteTools`/annotation/schema tables
by three `TEST_CASE`s beneath it (lines 433, 447, 462) — securable/operation parity, write-tool
classification, and the full A5 annotation+schema contract. **Add one row per new tool your twin PR
ships.**

### MCP round-trip test

Beyond the `kExpectedTwins` table-parity check (which proves registration is internally
consistent), add or extend a `test_mcp_server.cpp`-style test that actually dispatches the new tool
through the JSON-RPC surface (a synthetic `tools/call` request) and asserts on the response shape —
the table check proves the tool is *registered* correctly, not that its *handler* does the right
thing.

---

## 7. The full checklist

Work through these in order. Steps marked "(if applicable)" depend on your capability's shape —
see §5 for which chokepoints apply.

1. **Shared builder function.** Write the pure `to_json`-shaped builder (§1) that both REST and MCP
   will call. No `httplib.h`, no MCP-specific includes.
2. **REST handler + A4 envelope.** Register via the two-overload `HttpRouteSink`/`httplib::Server`
   pattern (§2). Success via `ok_json`/`list_json`; every error via `detail::a4_error`/`a4_denial`.
3. **Chokepoints** (if applicable): `authorize_list_read`/`require_fleet_read` for a per-agent list,
   `deny_fleet_wide_service_scoped` before the permission check on a fleet-wide identity-linked
   list, `check_targeting_shape`+`classify_dispatch_arm` for a dispatch route (§5).
4. **RBAC securable/operation.** Check whether the pair already exists in the seed arrays
   (`server/core/src/rbac_store.cpp`'s `seed_defaults()`, the `types` array starting at line 559 and
   the `ops`/`roles`/`grant(...)` calls following it from line 532 onward — *correction: an earlier
   note cited "roughly lines 291-369," which is actually the Postgres migration DDL; the live seed
   function is `seed_defaults()`, starting at line 532*). If new, add the securable to `types[]`,
   grant it to the roles that need it via the `grant(role, securable, operation)` calls further
   down, and add a line to `docs/auth-architecture.md`'s RBAC section (the routed-concern doc for
   this area) — `docs/authz-model.md` (ADR-0033 §2's dispatch-visibility model) is a narrower,
   separate document and not the general permission reference.
5. **OpenAPI entry.** One `"/<path>"` object per route in `openapi_spec()` (`rest_api_v1.cpp:516`),
   matching an existing entry's density in the same tag family (§2).
6. **MCP registration.** `kTools[]`, `kToolSecurityRows[]`, `kWriteTools` (if non-Read),
   `kToolAnnotation`, plus the `if (tool_name == "...")` dispatch branch (§3) — all boot-enforced.
   For a destructive action-twin, also decide `requires_approval()` (§3's "fifth registration
   point") explicitly — it is **not** boot-enforced, so a missed decision here fails silently, not
   loudly. Run the server locally after wiring the four tables — `validate_tool_security_registration`
   will refuse to boot on any mismatch, which is the fastest way to find a missed table.
7. **Audit verb.** Pick (or reuse, if a REST/fragment twin already has one) a `noun.verb` action
   string per `docs/observability-conventions.md`'s audit envelope shape. Apply the correct posture
   per surface (§4) — fail-closed REST, set-and-proceed fragment, `audit_persisted:false` MCP, with
   the read-vs-mutate distinction from §4's closing note.
8. **`kExpectedTwins[]` test row.** Add one row per new tool to
   `tests/unit/server/test_operator_surface_twins.cpp:417` (§6).
9. **Tests.** A `TestRouteSink` fixture for the REST handler (mind the two gotchas, §6) and an MCP
   round-trip test dispatching the new tool through the JSON-RPC surface.
10. **Docs.** `docs/user-manual/rest-api.md` entry (§2) + `docs/mcp-server.md` entry (following its
    own "Adding a tool" checklist, §3).
11. **Changelog fragment.** One file, `changelog.d/<PR#>-<slug>.added.md`, per
    `changelog.d/README.md`'s format — never a direct `CHANGELOG.md` edit.
12. **F1 ledger row flip.** Issue #3991 (open at the time of writing; this recipe does not depend on
    its files existing yet) will add `docs/api-parity-ledger.md` plus per-domain machine files at
    `scripts/ci/api-parity/<domain>.json`, one row per capability with a `status` of `twinned` /
    `planned:#N` / `composed-of:<ids>` / `exception:<...>` / `retire`. Once that ledger lands, a
    twin PR's last step is flipping its domain's row from `planned:#N` to `twinned` — described here
    in prose only, since the ledger itself is a separate, not-yet-landed deliverable.

---

## 8. Worked example: `SoftwareDeployment` MCP twins

### Why this domain

The recipe asks for a real, small, self-contained gap — not a hypothetical. `SoftwareDeployment` is
a clean fit: it already has a complete, small REST surface (5 routes, all inline in
`rest_api_v1.cpp`) with a fully-seeded RBAC pair (`SoftwareDeployment:Read`/`:Execute`, already
granted to `Operator` — `rbac_store.cpp:711-712`), but **zero** MCP presence — verified by grepping
`mcp_server.cpp` for `SoftwareDeployment`/`sw_deploy`; the only hit is the securable's own
name appearing in an unrelated RBAC-catalogue validation array (`mcp_server.cpp:2127`), not a tool.

This also happens to demonstrate both halves the acceptance criteria ask for from one small domain:
`GET /api/v1/software-deployments` (a **read-twin**) and `POST
/api/v1/software-deployments/{id}/start` (an **action-twin**, complete with an MFA step-up gate
that the MCP twin has to reason about explicitly — a live, non-hypothetical instance of the "MCP
has no interactive step-up" question raised in §3).

*(This section is a worked walkthrough for this recipe document, not a claim that the PR below has
been implemented — no source files change as part of #3993, which is docs-only.)*

### The existing REST surface (read for context)

```cpp
// rest_api_v1.cpp:8972 — list, gated SoftwareDeployment:Read
sink.Get("/api/v1/software-deployments", [perm_fn, sw_deploy_store](...) {
    if (!perm_fn(req, res, "SoftwareDeployment", "Read")) return;
    auto status = req.has_param("status") ? req.get_param_value("status") : std::string{};
    auto deps = sw_deploy_store->list_deployments(status);
    if (!deps) { /* a4_error, sw_deploy_error_status(deps.error()) */ }
    JArr arr;
    for (const auto& d : *deps)
        arr.add(JObj().add("id", d.id).add("package_id", d.package_id).add("status", d.status)
                    .add("created_by", d.created_by).add("created_at", d.created_at)
                    /* started_at, completed_at, agents_targeted/success/failure */);
    res.set_content(list_json(arr.str(), static_cast<int64_t>(deps->size())), "application/json");
});

// rest_api_v1.cpp:9042 — start, gated SoftwareDeployment:Execute + MFA step-up
sink.Post(R"(/api/v1/software-deployments/([a-f0-9]+)/start)", [...](...) {
    auto session = auth_fn(req, res); if (!session) return;
    if (!perm_fn(req, res, "SoftwareDeployment", "Execute")) return;
    if (step_up_fn && !step_up_fn(req, res, *session, "POST .../start")) return;
    auto result = sw_deploy_store->start_deployment(req.matches[1].str());
    if (result) {
        if (!detail::try_persist_audit(audit_fn, req, "software_deployment.start", "success",
                                       "SoftwareDeployment", id, ""))
            res.set_header("Sec-Audit-Failed", "true");
        res.set_content(ok_json(JObj().add("started", true).str()), "application/json");
    } else { /* a4_error */ }
});
```

Note the row-building loop in the list handler is inline, not factored into a named function yet
(this predates the twin PR) — step 1 below fixes that as part of adding the twin, per Rule 1.

### Step-by-step against the checklist

**1. Shared builder.** Factor the list handler's row-building loop into a pure function, e.g. in a
new `software_deployment_model.{hpp,cpp}` (or colocated in `software_deployment_store.hpp` beside
the `SoftwareDeployment` struct, whichever the reviewer prefers for this domain's size):

```cpp
// software_deployment_model.hpp
std::string software_deployment_row_json(const SoftwareDeployment& d) {
    return JObj().add("id", d.id).add("package_id", d.package_id).add("status", d.status)
        .add("created_by", d.created_by).add("created_at", d.created_at)
        .add("started_at", d.started_at).add("completed_at", d.completed_at)
        .add("agents_targeted", static_cast<int64_t>(d.agents_targeted))
        .add("agents_success", static_cast<int64_t>(d.agents_success))
        .add("agents_failure", static_cast<int64_t>(d.agents_failure)).str();
}
```

Update the existing REST handler to call it (a small, low-risk refactor bundled into the twin PR —
this is exactly the kind of pre-existing duplication-in-waiting Rule 1 exists to close off before a
second caller appears).

**2. REST handler.** Already exists (`list_deployments`/`start_deployment`); no new REST route
needed for this example. (A from-scratch twin PR would write this step against §2.)

**3. Chokepoints.** Not a per-agent list (it's per-deployment, not per-agent) and not a dispatch
route in the `dispatch_target_shape.hpp` sense (deployments target a `scope_expression`, resolved
inside `SoftwareDeploymentStore`, not through the shared dispatch chokepoint) — no chokepoint
applies here beyond the plain `perm_fn` check already in place.

**4. RBAC.** Already seeded — `SoftwareDeployment` is in `rbac_store.cpp`'s securable-types array
(line 565) with `Read`/`Execute` granted to `Operator` (lines 711-712) and to `Administrator`
generally. Nothing to add.

**5. OpenAPI.** Already documented for REST (not shown above; follows the same pattern as
`/network/fleet`). No change needed for the MCP twin itself — MCP tools are documented via
`kTools[]`'s description field and `docs/mcp-server.md`, not OpenAPI.

**6. MCP registration — the actual twin work.** Before any of the tables below: the dispatch
handler needs a `SoftwareDeploymentStore*` to call, which means threading one into `McpServer` the
same way every other store-backed tool family does — either a constructor parameter (see
`app_perf_providers` at `mcp_server.cpp:3092`, passed in alongside the other store pointers) or a
private member set at construction (see `upload_grant_store_`, referenced in the
`revoke_upload_grant` handler this example's dispatch branch is modeled on). REST already captures
`sw_deploy_store` by value in its route lambdas (`rest_api_v1.cpp:8972`); MCP needs the equivalent
plumbing on its own construction path — this is usually the first thing a twin author has to find,
before any of the table edits below.

Next, the decision §3's "fifth registration point"
calls out explicitly: `SoftwareDeployment:Execute` is **not** in `requires_approval()`'s hard-coded
supervised-tier list today (verified — the full list is `Execution:Execute`, any `Delete`,
`Policy:Write`, `Security:Write`, `Security:Execute`, `UserManagement:Write`,
`ManagementGroup:Write`; `mcp_policy.hpp:105-121`). Starting a deployment pushes a package to live
endpoints — REST gates the equivalent action behind an MFA step-up (`step_up_fn`,
`rest_api_v1.cpp:9053`) precisely because it is consequential. The twin PR's job is to make that
call explicitly rather than silently ship an unapproved supervised-tier action: add
`if (securable_type == "SoftwareDeployment" && operation == "Execute") return true;` to the
supervised-tier block in `requires_approval()` (`mcp_policy.hpp:105`), with a short comment
recording the REST-parity rationale (matching the style of the existing entries there) — this is
the MCP-native answer to a step-up gate MCP tokens cannot satisfy interactively (they're
non-interactive; see the engine-principal tools' "platform-wide MCP step-up exemption" note,
`mcp_server.cpp:970-975`, for the precedent of stating this reasoning explicitly rather than
leaving it implicit).

```cpp
// mcp_policy.hpp:105 -- add to the supervised-tier block in requires_approval():
if (securable_type == "SoftwareDeployment" && operation == "Execute") return true;
// Deployment start pushes a package to live endpoints -- REST parity with its
// step_up_fn MFA gate (rest_api_v1.cpp POST .../start); MCP tokens are non-interactive,
// so maker-checker approval is the equivalent friction for this transport.

// kTools[] (mcp_server.cpp, near the other list-style read tools):
{"list_software_deployments",
 "List software deployments, optionally filtered by status. Requires SoftwareDeployment:Read.",
 R"({"type":"object","properties":{"status":{"type":"string","description":"Optional status filter"}}})",
 R"j({"type":"object","properties":{"deployments":{"type":"array","items":{"type":"object",
   "properties":{"id":{"type":"string"},"package_id":{"type":"string"},"status":{"type":"string"},
   "created_by":{"type":"string"},"created_at":{"type":"integer"},"started_at":{"type":"integer"},
   "completed_at":{"type":"integer"},"agents_targeted":{"type":"integer"},
   "agents_success":{"type":"integer"},"agents_failure":{"type":"integer"}},
   "required":["id","package_id","status","created_by","created_at"]}}},
   "required":["deployments"]})j"},

{"start_software_deployment",
 "Start a pending software deployment, pushing its package to the target scope. Requires "
 "SoftwareDeployment:Execute. Destructive/irreversible against live endpoints -- gated at the "
 "supervised MCP tier through maker-checker approval (added to requires_approval() by this PR "
 "as the MCP-native equivalent of REST's MFA step-up gate, which MCP tokens cannot satisfy "
 "interactively).",
 R"({"type":"object","properties":{"deployment_id":{"type":"string","minLength":1}},
     "required":["deployment_id"]})",
 R"j({"type":"object","properties":{"started":{"type":"boolean"}},"required":["started"]})j"},

// kToolSecurityRows[]:
{"list_software_deployments", {"SoftwareDeployment", "Read"}},
{"start_software_deployment", {"SoftwareDeployment", "Execute"}},

// kWriteToolsRaw[] (start_software_deployment only -- list_ stays out, it's Read):
"start_software_deployment",

// kToolAnnotation:
{"list_software_deployments", {ToolEffect::ReadOnly, true, "List software deployments"}},
{"start_software_deployment", {ToolEffect::Destructive, false, "Start software deployment"}},

// dispatch branch, modeled on revoke_upload_grant's shape (mcp_server.cpp:11958):
if (tool_name == "list_software_deployments") {
    if (!tier_allows(tier, "SoftwareDeployment", "Read")) { /* a4_error kTierDenied */ }
    if (!perm_fn(req, res, "SoftwareDeployment", "Read")) return;
    if (!sw_deploy_store_) { /* a4_error kInternalError, "store unavailable" */ }
    auto status = param_str(args, "status");
    auto deps = sw_deploy_store_->list_deployments(status);
    if (!deps) { /* a4_error kInternalError, sw_deploy_client_message(...) */ }
    JArr arr;
    for (const auto& d : *deps) arr.add_raw(software_deployment_row_json(d));  // SHARED builder
    res.set_content(success_response(id, tool_result(
        JObj().raw("deployments", arr.str()).str(), kObjectOutputSchema)), "application/json");
}
if (tool_name == "start_software_deployment") {
    if (!tier_allows(tier, "SoftwareDeployment", "Execute")) { /* a4_error kTierDenied */ }
    // requires_approval("supervised", "SoftwareDeployment", "Execute") now gates this in the
    // approval workflow at the supervised tier, per the requires_approval() edit above -- the
    // MCP-native equivalent of REST's step_up_fn gate, added by this PR, not inherited for free.
    if (!perm_fn(req, res, "SoftwareDeployment", "Execute")) return;
    auto dep_id = param_str(args, "deployment_id");
    if (dep_id.empty()) { /* a4_error kInvalidParams */ }
    auto result = sw_deploy_store_->start_deployment(dep_id);
    if (!result) { /* a4_error kInternalError, sw_deploy_client_message(...) */ }
    const bool audit_ok = try_persist_audit(audit_fn, req, "software_deployment.start", "success",
                                            "SoftwareDeployment", dep_id, "");
    JObj payload; payload.add("started", true);
    if (!audit_ok) payload.add("audit_persisted", false);   // MCP posture, per §4 -- NOT a 503
    res.set_content(success_response(id, tool_result(payload.str(), kObjectOutputSchema)),
                    "application/json");
}
```

This is the point where the shared-builder rule (§1) actually pays for itself:
`list_software_deployments`'s handler calls the exact same `software_deployment_row_json` the REST
handler was refactored to call in step 1 — a future field addition to one is a field addition to
both, not a two-file remember-to-update.

**7. Audit verb.** `start_software_deployment` reuses REST's existing `software_deployment.start`
verb (not a new `mcp.start_software_deployment` — see §4's note on preferring the domain verb).
Posture: MCP set-and-proceed with `audit_persisted:false`, matching §4's table — **not** a 503,
even though the analogous REST route can't fail closed either (the mutation already committed by
the time the audit call runs; see §4's read-vs-mutate closing note). `list_software_deployments` is
metadata about deployments, not per-agent behavioural PII, so it does not need
`emit_behavioral_audit`'s stricter posture at all — a plain success/failure log via `try_persist_audit`
(or no audit call, matching the REST list route's own unaudited posture) is proportionate.

**8. `kExpectedTwins[]` rows:**

```cpp
{"list_software_deployments", "SoftwareDeployment", "Read", true},
{"start_software_deployment", "SoftwareDeployment", "Execute", false},
```

**9. Tests.** A `TestRouteSink` fixture already likely exists for the REST list/start routes (or
should, if not) — the MCP twin needs its own dispatch-through-JSON-RPC test asserting the shared
builder's output appears verbatim in both surfaces' responses for the same store state, which is
the actual regression test for Rule 1 holding.

**10. Docs.** `docs/user-manual/rest-api.md` likely already documents the REST routes; add a
`docs/mcp-server.md` entry for the two new tools following its own tool-documentation convention.

**11. Changelog.** `changelog.d/<PR#>-software-deployment-mcp-twins.added.md`:
```markdown
- **MCP twins for software deployments.** `list_software_deployments` and
  `start_software_deployment` bring the `/api/v1/software-deployments` REST surface to REST+MCP
  parity (api-parity programme, #2146).
```

**12. Ledger.** Flip `software-deployments`' row from `planned:#<this-PR>` to `twinned` in the F1
ledger once #3991 lands.

</br>

This walkthrough deliberately used an existing, small, real REST surface rather than inventing a
capability — every line number and function signature above (aside from the new tool names
themselves) is real, current code, so the shape of a from-scratch twin PR should look identical to
this one with steps 1-2 done in full rather than "already existed."
