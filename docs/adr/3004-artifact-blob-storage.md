---
status: accepted
date: 2026-08-04
owner: "@Doomgoose (Alex Young)"
deciders: "@Doomgoose (author), dev-team Architect (design frozen 2026-08-04, protocol text carried
  verbatim into upload_grant_parsers.hpp and implemented identically by the paired agent-side
  package)."
scope: server-side artifact receive path (CC-06), UploadGrantStore, file_retrieval_routes
depends-on: ["0006-server-postgresql-substrate", "0008-postgres-substrate-architecture",
  "0010-secrets-at-rest-envelope-encryption", "0012-server-postgres-store-contract"]
related: ["0030-api-token-rotation-and-lifecycle"]
context-refs: ["CC-06", "PR1.6a", "PR1.6b (agent half, identical protocol text)"]
---

# 3004: One-time upload grant + chunked artifact receive (CC-06 server-side fix)

## Context

CC-06 flagged the pre-existing `POST /api/v1/file-retrieval` handler
(`rest_api_v1.cpp`, capability 10.13, deleted by PR1.6c): it trusted a
client-supplied `agent_id` and `original_path` in the JSON body, gated only
on a bare `FileRetrieval:Write` permission check, and did not actually
write the uploaded bytes anywhere durable — a stub that logged and returned
200. Any caller (or anything that could forge the identity check) could
claim to be any agent and assert any originating path, and the "upload"
went nowhere.

The natural fix — "derive the agent identity from the authenticated
transport, the way every other agent RPC does" — is not implementable
against the code as it stands. Agent mTLS terminates at the gRPC listener
(`agents/core/src/agent.cpp:1274-1347`); there is no authenticated agent
REST transport anywhere in the server. The plugin ABI's context object
(`sdk/include/yuzu/plugin.h` ~:285-320) exposes config/secret/storage
accessors to a plugin, but nothing that lets a plugin assert its own
identity over a channel the server can verify. Building that transport (a
second mTLS listener terminating at the REST layer, or threading the gRPC
peer identity through to an HTTP handler) is a materially larger change
than this PR's scope and was explicitly rejected by the Architect during
planning (peer findings PLAN-004/PLAN-005, both independently verified
against the code before this design was frozen).

A one-shot bearer credential (a single "upload grant" token) does not
resolve this on its own either: the frozen protocol below needs to
authenticate potentially many chunk PUTs over the lifetime of one upload
(resumable, bounded-size chunks), and a credential that is consumed on
first use cannot also authenticate request 2 through N.

## Decision

**Two credentials, two lifetimes.** A grant is minted by an operator (who
already carries `UploadGrant:Write`) and names the agent, source, and
size/hash bounds — agent identity is therefore a **server-side fact
recorded at mint time**, asserted by the trusted operator, never by the
client presenting the credential later. The grant is redeemed **exactly
once**, atomically, into a session. The session's own bearer credential —
freshly minted at redemption, unrelated to the grant secret — authenticates
every subsequent chunk/status/commit/cancel call for that one upload. A
grant that never got redeemed carries no chunk-authenticating power; a
session that has run out its grant's redemption cannot itself be re-minted
into a second, sibling session. See `upload_grant_parsers.hpp`'s file
header for the wire protocol verbatim (paths, headers, states, the closed
ten-value error `reason` set) — that text is Architect-frozen and the
paired agent-side package (PR1.6b) implements it identically; this ADR
does not restate it, only the design rationale behind it.

**Credential shape and verification.** Both credentials are
`<id>.<secret>`: a 16-byte random id (32 hex chars, `AuthManager::random_bytes`
+ `bytes_to_hex`) and a 32-byte random secret (64 hex chars), never
uppercase, generated the same way `ApiTokenStore`/`AuthDB` generate their
own bearer tokens. Only `sha256(secret)` is ever persisted — the raw
secret is returned to the caller exactly once (at mint, and again at
session-open) and never appears in a log line, an audit `detail` field, or
a second database column. Verification is: look the row up **by id**, then
compare the presented secret's digest against the stored digest with a
constant-time byte comparison (`upload_grant::constant_time_equals`) — a
plain SQL `WHERE secret_hash = $1` lookup was deliberately NOT used for the
credential check, so the atomic redemption UPDATE (below) can condition
purely on `grant_id`/`state`/`expiry`, matching the frozen protocol's text.
An unknown id, a wrong secret, and a revoked grant all collapse onto the
**same** wire outcome (`grant_unknown` / `session_unknown`) — the
`device_token_rejection.hpp` precedent: never let a caller discriminate
"this credential once existed" from "it never did" by response shape.

**Single redemption is a Postgres guarantee, not an application lock.** The
actual state transition is one `UPDATE upload_grant_store.grants SET
state='redeemed' WHERE grant_id=$1 AND state='minted' AND expires_at >=
$2::bigint RETURNING grant_id`. Under READ COMMITTED, a second concurrent
caller's identical UPDATE blocks on the row lock, then re-evaluates its
WHERE clause against the just-committed row (EvalPlanQual) and matches
zero rows — deterministically, not probabilistically. This is what the
acceptance test drives with two real threads issuing the statement through
two real connections, not a mock of "the first caller wins."

**Destination key is server-facts-only, structurally.** The
`file_retrieval_routes.cpp` write path never receives a client-suppliable
path anywhere in its call graph: `upload_grant::derive_destination_key`
takes only a pre-validated `retention_class` (closed three-value allowlist)
and the grant_id the store itself generated — there is no parameter through
which a caller-controlled string could reach it. The blob lands at
`blob_root / retention_class / grant_id` (`blob_root` is a Deps field
server.cpp wires from its own config, not from any request). The mint
request's `source_path` field is persisted as **operator-informational
metadata only** (what the operator declares the file to be) — it is never
read back by anything that opens a file.

**Write-once-per-chunk, not per-upload.** "Opens the destination once…
streams through that same RAII handle" (frozen protocol, acceptance
criteria) is scoped to ONE chunk request, not the whole multi-request
upload — an upload's chunks arrive as separate HTTP requests (over time,
potentially to a restarted process), so there is no single file handle
that could span them. Within one chunk handler: the path is computed
exactly once from `UploadSessionInfo::destination_key` (itself resolved
once, at session authentication, from server-side facts) and is never
re-derived before the `std::fstream` open a few lines later — the
comment at that call site is the audit anchor. The first chunk
(`start == 0`) opens `trunc`; every later chunk opens the existing file
`in|out` and seeks to `start`, which — because `start` is checked equal to
`recorded_offset` before this point — is always exactly at the file's
current end. No gap-filling, no re-ordering.

**Commit verification is computed fresh, not carried across requests.**
Rather than maintain an incremental SHA-256 state in memory across the many
separate chunk requests (fragile across a process restart mid-upload, and
the "digest so far" would need its own persisted-or-lost story), `commit`
re-opens the fully-written blob and streams it through one `EVP_MD_CTX` in
64 KiB reads (`compute_file_sha256_hex`) — memory-bounded regardless of
file size, and correct even if the server process restarted between the
first chunk and the last (the partial bytes already durable on disk are
the only truth that matters; a resumed chunk after a restart still checks
`start == recorded_offset` against the database row, not against anything
cached in RAM). The three verification legs (declared size, client-
supplied hash, grant's optional expected hash) collapse to the single
`hash_mismatch` (422) outcome — acceptance-criteria-mandated, and a
defense-in-depth choice: telling a caller precisely *which* leg failed
hands an attacker a size/hash oracle for free.

## Blob layout

```
<blob_root>/<retention_class>/<grant_id>
```

`retention_class` is one of `standard` | `extended` | `transient` (closed
allowlist, `upload_grant::is_valid_retention_class`) — a *hint* for a
future retention sweep (not built in this PR; `completed_uploads.retention_class`
is durably recorded so that sweep has something to key on when it ships).
`grant_id` is the 32-hex-char id the store minted — collision-free by
construction (CSPRNG, `UNIQUE` on the id's owning row) and never re-used
across grants (a revoked/expired/redeemed grant is a dead row, never
recycled).

## Encryption at rest

**Deferred, recorded as an open item — NOT built in this PR.**
`SecretCodec` (ADR-0010) envelope-encrypts individual *database columns*
(a bounded-size secret value, transformed on write and read back through
one `EVP_CIPHER_CTX` call). It has no story for an arbitrary-size,
streamed-to-disk **file** — wrapping every chunk write through a per-file
AEAD context (nonce management across resumed/restarted uploads, where the
plaintext boundary between chunk N and N+1 must stay stable even if a
chunk is retried) is a materially different engineering problem than
column encryption, and building it was out of this PR's scope per the
Architect's frozen boundaries. Today, blob-at-rest confidentiality is
whatever the deployment's disk-level encryption provides (the same
implicit posture Yuzu's cert/key material on disk already has outside
`SecretCodec`'s reach) — **not** an application-level guarantee this store
makes. `completed_uploads` (the durable metadata row: destination key,
actual size, verified hash, retention class, received-at) carries no
secret material itself and needs no `SecretCodec` registration; only the
grant/session **credentials** are hashed (never encrypted-and-recoverable
— they are bearer secrets, verify-only is the correct primitive, matching
`ApiTokenStore`'s `token_hash` precedent, not `SecretCodec`'s
encrypt-and-decrypt one). A follow-up PR that wants blob-content
encryption at rest should treat it as a new design, not an extension of
this credential-hashing story.

## Retention / expiry

- **Grant TTL** defaults to, and is capped at, 15 minutes
  (`upload_grant::resolve_grant_ttl_secs`, default and ceiling both 900s
  unless a mint request asks for something shorter). An operator-requested
  TTL above the ceiling is silently clamped down, never rejected — a
  non-positive request is treated as "use the default," never floored to a
  near-instant expiry that would read as a confusing failure moments
  later.
- **Session TTL inherits the grant's `expires_at`** — a session never
  outlives the redemption window that created it, and there is no separate
  session-TTL knob to keep in sync.
- **Exact boundary**: `now == expires_at` is still valid; only
  `now > expires_at` is expired (`upload_grant::is_expired`) — pinned by a
  boundary test in both the pure-layer and store-behaviour suites.
- **Blob retention** (how long a *committed* upload's bytes and
  `completed_uploads` row survive) is intentionally **not** decided by this
  PR — `retention_class` is recorded so a future sweep has the field to key
  on, but no sweep exists yet. This mirrors `AccessReviewStore`'s posture
  (no prune method, evidence persists until a follow-up policy says
  otherwise) more than the `/auto` run stores' 14-day prune — an uploaded
  artifact is closer to compliance evidence than to operational scratch
  state, and inventing a default retention window without a concrete
  consumer was judged worse than leaving the field inert for now.
- **Any touch after expiry discards the partial and reports 410** — this
  applies even to the read-only status/resume poll, per the frozen
  protocol's literal text ("any request after it"), not just the mutating
  chunk/commit/cancel routes.

## Why the metadata is born-Postgres

Per ADR-0006 (every server store migrates, none stays SQLite) and the
playbook's greenfield recipe: `UploadGrantStore` is new, so there is no
legacy SQLite data to backfill — schema `upload_grant_store`, three tables
(`grants`, `sessions`, `completed_uploads`), unqualified migration DDL,
schema-qualified runtime statements, `RETURNING` for every mutate-and-return,
bounded `try_acquire_for` leases everywhere at runtime. **Posture (ADR-0012
§1): construction fail-closed; every mutator that decides an authentication
outcome (mint, `open_session`, `authenticate_session`, `advance_offset`,
`commit_session`, `cancel_session`, `revoke`) is AUTHORITATIVE** — a lease
timeout or query error is `std::unexpected`/a dedicated `kUnavailable`
outcome, never confusable with a legitimate negative result, because this
store backs an authentication decision and a silently-swallowed write here
is either a silently-granted or a silently-denied upload. The one
exception is `expire_stale_sessions`, an optional best-effort maintenance
sweep (durability-on-top, mirrors `OfflineEndpointStore::upsert`) — every
per-request path already evaluates expiry itself against the injected
clock, so the sweep is pure hygiene (an abandoned session doesn't sit
`open` forever in operator list views), never load-bearing for the expiry
guarantee itself.

`docs/postgres-migration-ladder.md` gains rows for both `UploadGrantStore`
(this store) and `PluginConfigStore` (PR1.5b, the sibling package that
owns `plugin_config_store.{hpp,cpp}` but — per that package's own
boundaries — does not edit the ladder itself, to avoid two packages racing
an edit to the same file in one wave).

## Consequences

- p7 (PR1.6b, the agent-side transport) implements this identical
  protocol text — a status code, header name, or reason string drifting
  between the two packages would only surface as an integration failure,
  not a compile error, so the frozen text in `upload_grant_parsers.hpp`'s
  file header is the single source of truth both packages were built
  against.
- The legacy `POST /api/v1/file-retrieval` handler (`rest_api_v1.cpp:7572`)
  is deleted by PR1.6c, not by this package (`rest_api_v1.cpp` is outside
  this package's `owned_files`) — until that lands, the vulnerable stub
  and this fix coexist on different paths (`/api/v1/file-retrieval` vs.
  `/api/v1/upload-grants` + `/api/v1/uploads`).
- Blob-content encryption at rest and a retention sweep are both explicitly
  open follow-ups, not silently-closed gaps — see the two sections above.
