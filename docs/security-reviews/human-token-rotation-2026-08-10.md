# Security review — Human API-token rotation (SOC 2 CC6.3)

| Field | Value |
|---|---|
| Date | 2026-08-10 |
| Scope | Self-service overlap-pair rotation for human-owned API tokens — `ApiTokenStore::rotate_token`/`confirm_token_rotation` (store core), kind-discriminated telemetry, `POST /api/v1/tokens/{id}/rotate`/`.../confirm` (REST), and a 33-case adversarial regression suite |
| Control | SOC 2 **CC6.3** (authentication/credential lifecycle) — closes the human-token half of `/auth-and-authz` gap-matrix **P2 #11** (the engine-credential half shipped earlier as part of the `engine` principal ladder) |
| Driver | `/auth-and-authz` gap matrix P2 #11 |
| Branch | `feat/auth-human-token-rotation`, integration commit `e1bf2d86` |
| Reviewer | Multiple review rounds across store-core, REST, and telemetry sub-branches (round numbers below), including plan-review before implementation, two ownership/architecture specialists, and an independent architect adjudication on the confirm-error taxonomy. A fifth piece — MCP tool twins — is **still in review, not in this branch**, and is covered separately below. |
| Status | Store core + REST + telemetry: implemented, adversarial-regression-suite green (33 `[human]` cases). MCP twins: in review, not merged. |

## Purpose

Records the evidence chain for adding self-service credential rotation to
human-owned API tokens — mint a successor while the existing (predecessor)
token stays valid for a bounded overlap window, then an explicit
maker-checker confirm that revokes the predecessor and closes the rotation.
Engine-credential rotation shipped earlier (`rotate_engine_credential`/
`confirm_rotation`, `docs/auth-architecture.md` "Overlap-pair credential
rotation") on a **principal-keyed** state machine. This is the human twin, on
a deliberately different, **token-keyed** state machine — see the design
decision below for why the two cannot share one invariant.

## Control surface

| Element | Location |
|---|---|
| Store core (`rotate_token`/`confirm_token_rotation`) | `server/core/src/api_token_store.{hpp,cpp}` |
| Group-scoped confirm-state classifier | `server/core/src/rotation_confirm_state.hpp` (`classify_confirm_state_in_group`) |
| Shared REST/MCP error classifier | `server/core/src/engine_store_error_class.hpp` |
| Shared successor-lookup seam | `server/core/src/token_rotation_lookup.hpp` (`derive_rotation_successor`) |
| Kind-discriminated telemetry naming | `server/core/src/rotation_sweep_naming.hpp` |
| REST routes | `server/core/src/rest_api_v1.cpp` (`POST /api/v1/tokens/{id}/rotate`, `.../confirm`) |
| T12 maintenance sweep (shared engine+human) | `server/core/src/server.cpp` (`engine_rotation_sweep_thread_`) |
| Tests | `tests/unit/server/test_api_token_store.cpp` (33 `[human]`-tagged cases) |
| Docs | `docs/auth-architecture.md` "Human API-token rotation" (this feature's design record), `docs/user-manual/rest-api.md` "API Tokens" (REST reference), `docs/user-manual/authentication.md` "Rotating a Token" (user-manual walkthrough), `docs/user-manual/metrics.md`, `docs/observability-conventions.md`, `docs/user-manual/audit-log.md` |

## Design decisions with security rationale

- **Token-keyed, not principal-keyed (caught at plan review, before code
  existed).** The engine arm's ≤2-active-credential ceiling is enforced
  **per principal** — correct because an engine principal has exactly one
  credential. A human routinely holds several unrelated concurrent tokens, so
  a principal-keyed ceiling on the human arm would block rotating any one
  token the moment its owner held a third, unrelated one. `rotate_token`/
  `confirm_token_rotation` key on the token being rotated and enforce the
  ≤2 ceiling **per `rotation_group`** instead — a human's other tokens never
  count against it. The advisory lock stays `hashtext(principal_id)` (same
  key as the engine arm and the T12 sweep), so activity for a shared
  principal still serializes across both arms.
- **The identical invariant gap recurred one layer up, in the REST route,
  and was caught a second time (round 3).** The route's successor lookup —
  needed to return the freshly-minted token's `token_id`/`expires_at` — was
  copied from the engine rotate route's inline loop ("the active row whose
  `supersedes_token_id` is set"), sound there only because that route's own
  store arm enforces the per-principal ≤2 ceiling and so at most one linked
  row can exist. On the human arm, with several independent in-flight
  rotations possible per principal, the copied loop matched the *first*
  linked row, not necessarily the one belonging to the predecessor actually
  rotated. **Two independent reproductions against live Postgres, plus an
  architectural ruling that the fix belonged at a shared seam rather than
  inline.** The reproduction: rotating token A then token B (same owner)
  inside A's overlap window returned B's raw secret paired with A's
  successor `token_id` — confirming that id would have revoked A while B,
  the token whose secret the caller actually held, stayed live and
  unconfirmed. Fixed (`c1325015`) by extracting the derivation into one
  shared, DB-free, unit-testable seam — `derive_rotation_successor`
  (`token_rotation_lookup.hpp`) — so the REST route today and the MCP twin
  landing separately both call the same function. A second inline copy of
  this loop is exactly the drift that produced the bug the first time; see
  the header's own doc comment for the full reproduction writeup. The seam
  extraction is itself the evidence the architectural ruling was acted on —
  an inline fix on the REST route would have been the cheaper change and was
  explicitly rejected in favour of the shared seam.
  **Attribution note:** `c1325015`'s own commit message is the only
  artifact this record can cite for "two specialists" plus "per the
  coordinator's correction" — no `governance.d/` ledger fragment exists for
  this work, and an independence claim in a compliance record should not
  rest on a recollection routed through the party being reviewed (the
  coordinator, here). If per-round/per-reviewer attribution is needed for
  audit purposes, cite it from a governance ledger fragment once one is
  produced for this work, not from this paragraph or from memory.
- **Ownership is enforced at the store seam, not merely at the route.**
  `rotate_token`/`confirm_token_rotation` reject unless `requesting_user`
  equals the resolved token row's own `principal_id` — checked in a
  pre-transaction lookup and again, authoritatively, on the fresh re-read
  taken under the advisory lock. The route-level ownership check that runs
  first is defense-in-depth on top of this, never a substitute for it. This
  is a deliberate asymmetry with the engine arm (whose caller is a
  third-party admin by design): a human token's raw successor secret
  authenticates *as that user*, so an admin re-serving or confirming
  another user's rotation would be handed (or would complete the cutover
  of) a credential impersonating someone else — identity takeover, not a
  permission gap an admin override could legitimately cross. There is no
  rotate-as-admin path; an admin acting on another user's token has
  `revoke_token`/`revoke_for_principal` instead.
- **"Self-service" is qualified, not absolute — under RBAC-on this composes
  to effectively admin-only, and that is true of the shipped surface, not a
  future caveat.** REST rotate/confirm gate on `ApiToken:Write`. Verified
  against this branch's RBAC seed data (`rbac_store.cpp`): `ApiToken:Write`
  is granted only to `Administrator` (full-CRUD loop) and `ApiTokenManager`
  (explicit grant); `Operator`, `PlatformEngineer`, `Viewer` (read-only), and
  `ITServiceOwner` (explicitly excluded, per its own seeding comment) do not
  hold it. Composed with the store-seam ownership requirement above (no
  admin override, ever): an `Operator`- or `Viewer`-role user who **owns** a
  token has no RBAC-on path to rotate it themselves, and no admin can do it
  for them either — the token cannot be rotated by anyone until its owner is
  separately granted `ApiToken:Write`. This is **pre-existing and unchanged
  by this work** — `POST /api/v1/tokens` is already gated the same way;
  `DELETE /api/v1/tokens/{id}` is gated on the sibling `ApiToken:Delete`
  operation (`rest_api_v1.cpp:2624`), not `Write` — but the RBAC seed data
  grants both operations to the same two roles (`Administrator`,
  `ApiTokenManager`) and to no others, so the admin-only conclusion holds
  identically for delete. Recorded here because every "self-service" claim
  elsewhere in this record means *self-service subject to holding the
  relevant `ApiToken:*` grant*, not *available to any authenticated owner*.
- **A wrong-owner rejection is indistinguishable from a nonexistent token —
  the surface is not an enumeration oracle.** Both the store-level rejection
  and the REST route's own 404 use identical wording/status for "this token
  doesn't exist" and "this token exists but isn't yours"
  (`"no such token to rotate"` / `"no such token to confirm"` at the store;
  `404 token not found` at REST, mirroring the existing `DELETE
  /api/v1/tokens/{id}` route's posture). A denied attempt is still fully
  audited server-side (`result=denied`, `detail=owner=<real owner>`) —
  the ambiguity is client-facing only.
- **Lifetime-neutral by deliberate choice.** The successor's absolute
  `expires_at` always inherits the predecessor's verbatim — never
  recomputed as `now + 90d`, which would silently extend authorization
  lifetime through what should be a lateral credential swap. The store-level
  function retains an internal `successor_expires_at` override parameter
  (shared plumbing with the engine arm's own successor-TTL logic), but the
  REST route deliberately does not expose it as a request field — a
  senior-architecture ruling that rotation must read as lifetime-neutral in
  CC6.3 evidence, with no caller-controlled path to extend a grant through
  what should be a lateral swap. A caller needing a longer-lived replacement
  mints a fresh token via `POST /api/v1/tokens`, a distinct,
  separately-audited action.
- **Confirm error taxonomy was explicitly adjudicated, and an earlier
  reading was wrong in the dangerous direction (round 5).** The group-scoped
  classifier (`classify_confirm_state_in_group`) distinguishes a POSITIVE
  fact — `kGroupEmpty`: the principal-wide active read succeeded and
  returned rows, but none carry the pinned `rotation_group`, i.e. the
  rotation has already resolved — from a genuinely AMBIGUOUS one —
  `kAmbiguousEmpty`: the principal-wide read came back empty, indistinguishable
  from a swallowed `SELECT` failure. Round 4 shipped `kGroupEmpty` as
  `Transient` (REST `503`, retryable). Independent architect adjudication,
  escalated after that classification was flagged as doubtful, corrected it
  to `Conflict` (REST `409` / MCP `kInvalidParams`, terminal) before merge,
  on three independent grounds: (1) `#2404` precedent — the engine arm was
  once `503`-retryable for the same shape of state and made an
  idempotent-hint-honouring agentic client retry a permanently-failing call
  forever; `Transient` on `kGroupEmpty` reintroduces that exact defect on
  the human arm; (2) arm parity — the engine arm's `kSoleOtherToken` state
  carries the identical "rotate again if needed" guidance and classifies
  `Conflict`, and telling a client to take a *different* action (call
  rotate, not retry confirm) is the definition of `409`, not `503`; (3) the
  classifier's own file-level contract ("every terminal state → Conflict or
  ClientValidation") — `kGroupEmpty` is documented as a positive fact, not
  ambiguous. `kAmbiguousEmpty` stays `Transient`, unchanged, for the
  symmetric reason: it genuinely cannot be told apart from a swallowed read
  failure, so retry is the correct client behaviour.

## Review-round chronology (what each round found, briefly)

Skimmable index into the branch's own commit history — full detail is in
each commit message, not repeated here:

- **Round 2** (`a5e0f8fa`) — non-ASCII hyphen in new `describe()` help
  strings; cosmetic, fixed.
- **Round 3** (`c1325015`) — the successor-lookup scoping defect above;
  BLOCKING, fixed, extracted to `token_rotation_lookup.hpp`.
- **Round 4** (`6899aae8`) — two defects: a grace-cache entry could leak
  (never evictable) if a Postgres `COMMIT` failed *after* the transaction
  callback itself returned success (a narrow but real TOCTOU in
  `PgPool::run_in_txn`'s contract), fixed with an RAII `ScopeExit`-style
  guard covering every exit path; and two new confirm-error strings had
  silently inherited the engine arm's `kSoleOtherToken` classification via
  substring collision in `engine_store_error_class.hpp`, giving a
  never-rotated token's confirm attempt a `409` whose own text said "retry"
  — given distinct wording and an explicit classifier entry.
- **Round 5** (`7332ae52`) — the `kGroupEmpty` Transient→Conflict
  correction above.
- **Round 6** (`a960e8b1`) — ownership-specialist review of rounds 4–5
  found the fix shape sound but flagged one BLOCKING gap (a new regression
  test armed its test hook by bare assignment instead of the RAII pattern
  this repo requires for test hooks, generalised into a reusable
  `ScopedPgConnHook`) and three follow-ups (an unconditional-on-all-paths
  secret scrub that had excluded the commit-failure path; a `std::function`
  closure exceeding libstdc++'s small-object buffer, replaced with an
  allocation-free template `ScopeExit`; a defensive `try_acquire_for` +
  `REQUIRE` in place of a bare pool re-entry that was safe only by
  configuration accident). A second, independent pass in the same round
  found the round-5 doc comment had overclaimed ("every terminal state →
  Conflict, no ClientValidation exists here" — false; `kOverfullGroup` is
  ClientValidation, and the file's own tests assert it) and corrected it.
- **Post-merge integration** (`035099e8`, `c1325015` continuation,
  `1fca6352`, `7caa1134`) — two of the 33 `[human]` test cases had their
  asserted contract corrected against the merged shape; `token_rotation_lookup.hpp`
  was made fully DB-free (the derivation takes a plain `std::vector<ApiToken>`,
  not a store handle, so it is unit-testable without live Postgres) and its
  post-confirm contract stated explicitly (see "Design decisions" above and
  the header's own extensive doc comment).

## Privilege-escalation finding — caught in review, not shipped

During review of the (separate, still-in-review) MCP tool twins, a proposed
`operator`-tier MCP allowance on the `ApiToken:Write` securable was found to
be directly exploitable — not via a downstream hop through rotate/confirm.
`ApiToken:Write` is the gate on `POST /api/v1/tokens` (mint, `rest_api_v1.cpp`)
**and** its settings twin `POST /api/settings/api-tokens`
(`settings_routes.cpp`), and **both accept a caller-chosen `mcp_tier`**
(including empty/untiered). An `operator`-tier token minting a token with no
`mcp_tier` set produces a credential that then skips `tier_allows` entirely
on every later call (an empty `mcp_tier` is the untiered/interactive case).
So the proposed allowance would have let an `operator`-tier token directly
mint itself an untiered, unconfined credential — a **first-order**
consequence of the one-line change, present the moment the allowance
existed, with no rotate/confirm call required. `#2945` below is the
**pre-existing** instance of this identical escape at the `supervised` tier;
the proposed allowance would have extended it to `operator`.

A first attempted fix scoped the allowance narrowly to the rotate/confirm
MCP *tools themselves* and was found structurally unreachable — RBAC
evaluates on the shared REST/MCP `(securable, operation)` pair, not
per-tool, so a tool-scoped carve-out cannot exist without duplicating the
permission model. The adjudicated remedy is a **new, narrower RBAC
operation — `ApiToken:Rotate`** — separate from `ApiToken:Write`, so the
MCP allowance (once it lands) can be granted without also widening
`POST /api/v1/tokens`(-equivalent) mint access to every `ApiToken:Write`
holder. **The remedy is not REST-scope-neutral: it also re-gates this
branch's own `POST /api/v1/tokens/{id}/rotate`/`.../confirm` routes from
`ApiToken:Write` onto the new `ApiToken:Rotate`, for parity across
transports.** **UPDATE (2026-08-10, MCP-twins merge):** the operator-tier
MCP allowance, the `ApiToken:Rotate` operation (`rbac_store.cpp:397`, seeded
to `Administrator`+`ApiTokenManager` at `rbac_store.cpp:480,662`), and the
REST re-gating (`rest_api_v1.cpp`'s rotate + confirm route `perm_fn(req, res,
"ApiToken", "Rotate")` gates) are now **all present in this
branch** — the MCP-twins piece merged (`98b0b084`) and this record was
stale until this pass corrected it; the whole decision recorded above,
including the REST-side re-gating, shipped as adjudicated, not
re-litigated or silently dropped.

**Detection mechanism — corrected. The 920-cell sweep verified the remedy;
it did not detect the defect.** 920 = 5 tiers × 23 securables × **8**
operations — but this branch's own RBAC operation set
(`rbac_store.cpp`'s `ops[]`) has **7** (`Read`, `Write`, `Execute`,
`Delete`, `Approve`, `Push`, `Attest`); the eighth, `Rotate`, exists only on
the remedy commit. The sweep therefore necessarily ran against the
**post-fix** operation vocabulary. A before/after sweep of the *vulnerable
proposal* (the one-line `operator`-tier allowance on `ApiToken:Write`,
against the 7-operation pre-fix vocabulary) changes exactly **one** cell —
which is evidence the change *was* narrow, not evidence it was safe: the
defect's severity comes from what else is gated on that one cell
(`ApiToken:Write`), not from the cell count changing. The defect was
instead found by **enumerating the call sites that consult the
`(ApiToken, Write)` pair** — exactly **four**: `POST /api/v1/tokens`, `POST
/api/settings/api-tokens`, and the REST rotate/confirm routes — and
recognising that the proposed allowance widened all four at once, not just
the two rotate/confirm MCP tools it was written for.

The suite claim is narrower than first stated: `tests/unit/server/test_auth_routes.cpp`
does exercise the REST-path tier predicate (`require_permission`/
`require_scoped_permission`) — ten call sites across its `[mcp]`-tagged
cases, against the `Execution`, `Infrastructure`, `Security`, and `Tag`
securables (verified by grep; none against `ApiToken`). The defensible
statement: **no test exercised the tier predicate for the `ApiToken`
securable specifically on the REST transport, and there is no
per-`(securable, operation)` REST tier coverage matrix** — so this class of
defect had a real, specific blind spot, not a suite that never tests
tiering at all.

The durable lesson: **a one-cell change to a shared permission predicate
inherits the union of every route consulting that `(securable, operation)`
pair — enumerate the call graph behind the chokepoint, not the grid of
possible values the predicate can take.** The vulnerable proposal itself
moved exactly **one** cell (the `operator`-tier allowance on
`ApiToken:Write`); the remedy's own delta is **two** (splitting the gate
into `ApiToken:Write` and the new `ApiToken:Rotate`). A one-cell delta is
precisely why a grid sweep could not have found this: the grid a sweep
compares before/after is a snapshot of the predicate's OUTPUT (which values
it returns per input), and a single narrow cell changing looks identical
whether that cell is inert or, as here, the single most consequential grant
in the table — severity lives in what else consults that cell, information
the grid does not encode at all. A grid sweep is the right tool for
verifying a remedy's blast radius *after* the operation vocabulary is
final (it correctly proved the two-cell remedy's narrowness above); it is
the wrong tool for finding a defect in a proposal that hasn't shipped its
own new operation yet, because the grid it would sweep doesn't exist yet
either.

## Open risks (pre-existing, surfaced by this work)

Ten issues were opened while building this feature, in two groups, and the
distinction matters when reading this record.

**Seven are pre-existing or deferred behaviour** — the entries listed below.
None of those is a defect *in* this feature's own new rotate/confirm code,
but `#2945` shares this record's central chokepoint (`ApiToken:Write`) and
the shipped-default (RBAC-off) configuration, so it is recorded as a live
open risk, not a footnote.

**Three more (`#2969`, `#2970`, `#2971`) were filed from the eight-gate
governance pass on this same range**, after this section was last revised,
and they break the premise above: `#2970` A and B *are* defects in this
feature's own new surface (the embedded OpenAPI under-declares `400` on both
rotation routes; the MCP twin silently coerces a wrongly-typed
`overlap_days` to the 7-day default). `#2969` covers the sweep's
silent-failure path and the absence of an alertable stuck-pair signal;
`#2971` covers two engine-arm principal-keyed premises surviving in a
token-keyed arm. They are listed after the seven, under their own heading,
rather than folded in.

Owner: **unassigned** for all ten — filed, not yet triaged to an owner.

This count has now been wrong twice, in opposite directions, which is worth
stating rather than quietly fixing: it read "Three" while four more were
open, was corrected to "Seven", and three further issues were filed from the
same governance run hours later. A count is a claim about a moving set; when
revising this section, re-derive it (`gh issue list --search "rotation"`)
rather than incrementing.

- **`#2943`** (Owner: unassigned) — `confirm_rotation` (engine arm) **and**
  `confirm_token_rotation` (human arm, this feature) share a structural
  fallthrough after their respective "exactly one pair matched" case:
  when the matched rows' linkage doesn't resolve to a clean
  predecessor/successor pair, both reuse the ambiguous-empty
  `"no in-flight rotation to confirm"` string — classified `Transient` for a
  state reached only after a *positive*, non-empty read. Same defect class
  as `#2404` and the round-5 `kGroupEmpty` correction above, in the same
  direction; not fixed by this branch — the human arm inherits it because
  both arms share the fallthrough shape, and the fix (a dedicated terminal
  string classified `Conflict`) is scoped to touch both arms together.
- **`#2944`** (Owner: unassigned) — the **engine** rotate response's
  `overlap_expires_at` is read off the successor row at both the engine
  REST and MCP call sites; the store never stamps that column on a
  successor (only the predecessor UPDATE sets it), so it reports a
  structural `0`. Surfaced while building this feature's
  `token_rotation_lookup.hpp`, whose `RotationSuccessorInfo::
  predecessor_overlap_expires_at` sources the field from the predecessor row
  precisely to avoid this — the human REST route (this feature) does
  **not** have this defect. The engine call sites are unmigrated and
  tracked separately.
- **`#2945`** (Owner: unassigned; **security-labelled, open**) — a
  `supervised`-tier API/MCP token can mint itself a tier-less, perpetual
  token via `POST /api/v1/tokens` (and its settings twin `POST
  /api/settings/api-tokens`), escaping its own tier confinement — the same
  chokepoint (`ApiToken:Write`) and the same first-order minting mechanism
  the "Privilege-escalation finding" above traces in detail for the
  `operator`-tier proposal that was caught before shipping. **Compensating
  control: none identified.** Traced `auth_routes.cpp`'s tiered-token
  fall-through: after `tier_allows` passes, the request still needs to
  clear either the RBAC-on `check_permission(username, ApiToken, Write)`
  check or the RBAC-off legacy-floor `effective_role == admin` check — but
  in every reachable path, the principal who can exploit this already holds
  `ApiToken:Write` outright (`Administrator`/`ApiTokenManager` under
  RBAC-on, or a legacy `admin`-role account under RBAC-off — legacy `Role`
  is binary `{user, admin}`, `auth.hpp:29`), which is the SAME grant needed
  to mint the narrowed token in the first place. So enabling RBAC changes
  *which* mechanism gates the fall-through but does not remove the
  exploit's precondition — a Write-privileged principal can de-confine
  their own deliberately-narrowed token under either configuration. This is
  a confinement-escape (an already-privileged principal defeating their own
  blast-radius reduction), not a vertical low-to-high privilege escalation
  — but it is real, open, and shares this feature's chokepoint. Surfaced
  while reviewing the proposed `operator`-tier MCP allowance above, whose
  extension of the same class of gap to `operator` tokens was caught and
  not shipped.
- **`#2961`** (Owner: unassigned; **P1, security**) — the rotation
  **consent record** (the maker-checker attestation that `confirm`
  produces) is stored durably for its *state* (Postgres: `rotation_group`,
  `supersedes_token_id`, `overlap_expires_at`, `confirmed_at`) but the
  operator's *consent to cut over* lives only in a process-local RAM map
  (`rotation_grace_cache_`). A single server restart inside the overlap
  window (default 7 days — no unusual configuration required) silently
  destroys that attestation: `confirm_token_rotation` can never succeed for
  the pair afterward, `confirmed_at` is never written, and the sweep cuts
  over on the timer instead with no error surfaced at cutover time — the
  advertised operator-confirmed-cutover control silently degrades to
  timer-based cutover, and the compliance record shows nothing amiss.
  Affects both arms (engine + this feature's human arm); the human arm's
  consequence is sharper (operator lockout, not just an engine restart). A
  second-order consequence is that confirm cannot succeed on a replica that
  did not itself serve the rotate, and that grace entries leak across
  replicas (never evicted cross-process, including by `revoke_for_principal`
  deactivation/sign-out-everywhere). Filed by the `unhappy-path` reviewer
  (UP-1, UP-2, UP-3, UP-13); durability requires new persistent state, which
  is why it is a separate re-cut rather than a fold into this branch.

  **RESOLVED 2026-08-11** (`feat/auth-rotation-confirm-durability`, migration
  v3). `api_tokens.rotation_initiator` durably stamps the confirming
  operator onto the successor row, inside the same advisory-locked mint
  transaction, on **both** arms. `ApiTokenStore::resolve_rotation_initiator`
  is the single chokepoint `confirm_rotation`/`confirm_token_rotation` now
  read through: RAM (`rotation_grace_cache_`) first, the durable column as
  the RAM-absent recovery path, fail closed if the two disagree, empty never
  treated as a wildcard. This closes the plain-restart failure mode
  described above, and — because the durable column is a Postgres row, not
  process-local — also closes the "confirm cannot succeed on a replica that
  did not itself serve the rotate" sub-case for the identity check
  specifically.

  **WARNING — do NOT recover a successor id out-of-band in order to confirm.**
  An earlier revision of this section framed that as a bonus of the durable
  column. It is not; it is the one dangerous way to use this change, and the
  `unhappy-path` gate caught the text recommending it (UP-2, I4 harmful
  operator guidance).

  If the rotate response or the raw successor secret was not received, do NOT
  look the successor id up (via `list_active_for_principal` or a support
  query) and call confirm. **Confirm attests that the successor secret was
  received and retained, and it immediately revokes the predecessor.** Doing
  it without the secret leaves an active credential nobody holds — zero usable
  credentials for that principal. Instead, explicitly **revoke the unknown
  successor**, which preserves the known predecessor, then start a new
  rotation.

  The durable initiator binding restores confirmation after a restart ONLY for
  an operator who retained the original rotate response — its raw secret and
  its successor id. It does not, and cannot, establish that the secret was
  ever delivered.

  Adjudicated (architect, `gpt-5.6-sol`, not the change author): the
  pre-#2961 behaviour here was an ACCIDENTAL and incomplete guard, not a
  control. The RAM entry proved the server had MINTED the secret, never that
  the client received it — it is populated before the HTTP response is
  written, so even pre-#2961 a lost-response caller who recovered the id could
  already confirm on the same process. A restart merely happened to erase the
  identity evidence as well. Losing that coupling is therefore not a
  security-control regression, and the proposed `last_used_at != 0` guard was
  REJECTED: it cannot distinguish "secret received but not yet deployed" from
  "secret never received" (both are 0), and would break confirm-before-rollout
  across a restart, which is precisely what #2961 exists to enable. The honest
  mechanical fix is proof of possession at confirm — presenting the successor
  secret, verifiable against the stored hash without persisting the raw — and
  that is a separate API/MCP/UI and threat-model change, tracked separately.
  Residual until then: an operator who obtains a successor id out-of-band and
  falsely attests receipt can revoke the only credential they actually hold. **Not closed by this fix, and deliberately so:** the
  raw successor secret's grace-window re-serve (F4) stays RAM-only — a
  one-time reveal must not become durable, so that capability is still
  forfeited on restart. **Not closed, still tracked separately, and this fix
  adds a NEW trigger for it:** the "grace entries leak across replicas"
  (memory never evicted cross-process) sub-case above is a RAM-cache
  lifecycle question, orthogonal to the identity check now having a durable
  source, and remains open — but it used to be a narrow, largely theoretical
  exposure (pre-fix, a confirm attempted on a replica that did not serve the
  mint always failed closed at the identity check, so a successful
  cross-replica confirm — the case that leaves the OTHER replica's cache
  entry stranded — essentially never happened in practice). Post-fix,
  cross-replica confirm is the durable fallback's whole reason to exist and
  now succeeds routinely: when replica B confirms a rotation minted on
  replica A, B's own (empty) cache has nothing to evict and A's entry is
  never touched — `evict_rotation_raw` is process-local, so only the replica
  that actually runs the confirm call clears its own copy. This converts the
  leak from an occasional, largely-unreachable edge case into a systematic
  one on any multi-replica deployment where mint and confirm land on
  different instances. No secret is retained in the stranded entry (the raw
  value is already scrubbed past the 120s reveal window by the time most
  confirms happen) — the leaked residue is ~100 bytes of
  `rotation_group`/`requesting_user`/`minted` per stranded entry — but the
  eventual cross-replica cache-invalidation work (tracked separately, not
  filed as its own issue by this pass) needs to know the trigger is now
  routine, not rare. Confirm still has no time bound (#2962) and the
  rotation sweep still lacks the full clock-guard shape (#2964) — neither is
  touched by this fix. A rotation already in flight when v3 is applied has
  an empty `rotation_initiator` and stays unconfirmable after a restart — it
  fails closed rather than matching any caller; an operator mid-upgrade with
  an in-flight rotation should confirm it before restarting if possible.
  If not, the sweep resolves the pair on its own timer only if the
  successor was presented at least once (UP-5) — if it was never
  presented, the sweep never resolves this pair, and the operator must
  revoke the specific credential no longer trusted via
  `DELETE /api/v1/tokens/{token_id}`, never the terminal principal-level
  `DELETE /api/v1/engine-principals/{id}` route.
- **`#2962`** (Owner: unassigned) — two unrecoverable terminals in the
  rotation state machine, both reachable single-instance. (A) `confirm` has
  no time bound on the grace *entry* itself (only the raw-secret re-serve
  window is bounded, 120s) and does not consult the successor's
  `last_used_at`, so an operator whose rotate response was lost in transit
  can still call confirm on the never-received successor — revoking the
  predecessor they actually hold and leaving themselves with a token whose
  secret nobody has. (B) a failed `resolve_rotation_pair_after_revoke`
  (after an out-of-band revoke/delete of one half of a pair) is logged and
  dropped with no counter or alert; the survivor keeps its stale
  `rotation_group` forever, rotate/confirm on it error permanently, and
  nothing heals it short of a manual DB edit. `unhappy-path` findings UP-4,
  UP-7; related to `#2961` (the durability root cause) and `#2943`.
- **`#2963`** (Owner: unassigned; **decision, not a defect**) — the
  shipped default configuration composes two independently-correct controls
  (RBAC-off legacy fallback requires `effective_role == admin` for any
  non-`Read` operation; the store enforces self-service-only rotation with
  no admin override) into a narrower population than either control
  describes on its own: only an admin, and only their own tokens, can
  rotate — a non-admin token owner cannot rotate their own token, and no
  admin can do it on their behalf. Separately, the Gate 8
  authority-inheritance guard's tier/scope equality requirement means an
  interactive (untiered) session cannot rotate its own MCP-tiered or
  service-scoped token — backwards precisely when rotation matters most
  (suspected compromise), since the guard requires holding the secret you
  are trying to replace. And the 24h overlap floor plus verbatim
  expiry-inheritance mean a token within 24h of expiry cannot be rotated at
  all. This issue asks Fraser to decide the intended reachable population
  and end-of-life path, not to implement a fix — `unhappy-path` findings
  UP-8, UP-9, UP-10, corroborated by the Gate 8 `security-guardian`
  re-review.
- **`#2964`** (Owner: unassigned) — the rotation sweep is a bulk
  wall-clock-driven mutation with none of the seven-part clock-guard shape
  the routed clock-guarded-retention concern mandates for that class of
  pass (only the per-tick cap ships in this branch, the "half that always
  applies"); a forward NTP step would cut over every in-flight rotation
  fleet-wide in one tick. Separately, the new rotation failure modes are
  unalertable today: there is no rotate-side metric at all (only confirm
  has one), `resolve_rotation_pair_after_revoke` failure is uncounted (see
  `#2962`), `docs/prometheus/yuzu-alerts.yml` was not touched so the four
  pre-seeded human rotation metric families and `yuzu_api_token_confirm_
  total` sit at zero with no rule referencing them, and under a future
  multi-replica deployment the process-local `successor_unused` dedup state
  would duplicate audit rows and counters N-way. `unhappy-path` findings
  UP-6, UP-14, UP-16.

### Filed by the eight-gate governance pass (defects in this feature's own surface)

These three postdate the section above and are listed separately because two
of them break its "no defect in this feature's own new code" premise.

- **`#2969`** (Owner: unassigned) — the sweep's successor-unused scan
  (`list_rotations_nearing_expiry_unused`) has no failure-signalling path at
  all: on a pool-lease timeout or a failed `SELECT` it logs and returns an
  empty vector, indistinguishable from "nothing nearing expiry", and the
  enclosing `try/catch` cannot catch what is never thrown. Second-order, a
  failed scan then feeds `warn_dedup.prune({})` and wipes every tracked
  pair's de-dup state, so previously-audited stuck pairs re-fire once the
  fault clears. Also carries the alertable-signal gap: `sre` ratified
  holding the counter to once-per-state but recommended publishing
  `RotationWarnDedup::tracked_elapsed()` as a **gauge**, which the dedup
  already computes. Two further sections bear directly on this record's own
  telemetry claims: the engine-side `describe()` calls are string literals
  not bound to `kEngineRotationSweepNames`, and the engine `auto_revoked` /
  `events` families are **not** pre-seeded while their human twins now are —
  so two families this document repeatedly calls "twins" behave
  asymmetrically under `absent()` / `increase()`. The fourth records the
  deliberate naming asymmetry: `yuzu_rotation_sweep_capped_total` was
  renamed kind-neutral because it had never shipped, while
  `yuzu_engine_principal_rotation_sweep_failures_total` keeps its engine
  name because renaming a shipped series breaks existing alerts.
  `sre` F1 (pre-seeding half fixed), F2 and the cadence adjudication;
  `consistency-auditor` F6; `architect` A-1.

- **`#2970`** (Owner: unassigned) — **two of these are in this feature's own
  new surface.** (A) the embedded OpenAPI declares no `400` at all on
  `/tokens/{id}/confirm` and enumerates three of at least eight `400` causes
  on `/rotate`, so the machine-readable contract served via
  `/api/v1/discover/routes` disagrees with `rest-api.md`, which is correct.
  (B) MCP `rotate_api_token` silently coerces a wrongly-typed `overlap_days`
  (a JSON float, or a string) to the 7-day default while the REST twin 400s
  on the same shape. (C) `api_token.reveal` and `.confirm` share no
  correlation key. (D) no operator runbook for the stuck-pair state.
  `consistency-auditor` F3/F4, `compliance-officer` F4/F5, `sre` F3.

- **`#2971`** (Owner: unassigned) — two engine-arm premises survive in the
  token-keyed human arm: both new arms abort on a **principal-wide**
  property (any active `principal_kind='engine'` row under the principal),
  and `read_active_for_principal_on_conn` is an unbounded principal-wide
  read inside the advisory-locked write transaction, on a cost model
  inherited from a set that was bounded at 2 by construction. The two differ
  in reachability and the issue is explicit about it: **A** is `E6` — engine
  credentials are only minted against `engine:`-prefixed principal ids, so
  the wrong outcome is proven unable to occur. **B is live today**, on every
  rotate and confirm; what is bounded is the blast radius (the advisory lock
  is per-principal, `statement_timeout` bounds the query), and the point of
  recording it is that a cost premise changed silently when the arm went
  token-keyed. `architect` A-2, A-3.

## Threats considered

- **Ownership bypass / cross-user rotation.** No path: enforced at the store
  seam on both the pre-lock lookup and the authoritative locked re-read;
  no admin override exists.
- **Enumeration of another user's token via the rotate/confirm 404.**
  Closed — identical wording/status for absent and not-owned.
- **Grant-lifetime extension disguised as rotation.** Closed —
  `expires_at` inheritance is unconditional at the REST surface; no request
  field can override it.
- **Retry-forever on a permanently-failing confirm.** Closed for
  `kGroupEmpty` (round 5); the sibling `#2943` fallthrough is a known,
  filed, not-yet-fixed instance of the same class — see above.
- **Raw-secret/`token_id` mismatch across concurrent rotations for one
  user.** Closed (round 3) via `derive_rotation_successor`'s exact-predecessor
  scoping.
- **Grace-cache leak on a Postgres commit failure.** Closed (round 4) via
  the RAII `ScopeExit` guard.
- **Cross-transport privilege widening via a shared securable.** Caught
  before any code shipped (MCP-twins review); remedy decided (including a
  REST-side re-gate) and **implemented and merged** — see
  "Privilege-escalation finding" above (updated 2026-08-10).
- **Tiered-token self-de-confinement via `ApiToken:Write` minting (`#2945`).**
  OPEN, no compensating control identified, pre-existing (not introduced or
  fixed by this feature) — see "Open risks" above.
- **Rotation authority inheritance (governance Gate 7, CRITICAL — caught
  before merge, not shipped).** `rotate_token` copied a caller-chosen
  predecessor's `mcp_tier`/`scope_service`/`expires_at` verbatim into the
  successor with no check that the CALLER's own current authority matched
  the predecessor's — so an operator-tier caller could pick their own
  untiered sibling token as the predecessor and receive an untiered,
  perpetual, full-authority successor: rotation as a self-service
  privilege-escalation lever, distinct from `#2945`'s minting-side escape
  (that one needs `ApiToken:Write`/admin already; this one needed only
  `ApiToken:Rotate` on the caller's OWN, lesser-tiered token). Closed in the
  same governance pass that surfaced it (never shipped to a merged branch):
  `rotate_token`/`confirm_token_rotation` now take `caller_mcp_tier`/
  `caller_scope_service` and refuse — inside the advisory-locked
  transaction, against a fresh predecessor re-read, folded into the same
  "no such token to rotate" wording as the ownership/absence cases — unless
  they are EQUAL (not "no broader than") to the predecessor's own values.
  Both REST and MCP thread the caller's server-synthesized
  `session->mcp_tier`/`token_scope_service` (`synthesize_token_session`,
  never client-controllable) through to the store. Pinned by store-level
  tests (refusal + row-count non-insertion; matching-tier success with an
  explicit inheritance assertion; scope mismatch) tagged `[pg][token]
  [rotation]` in `test_api_token_store.cpp`, plus route-level tests
  asserting the threading for both REST and MCP.
- **UPDATE (governance Gate 8 fix round, same day):** two corrections to
  how the equality guard above is characterized. (1) Equality closes the
  privilege-**escalation** direction only — it does not make `rotate`/
  `confirm` approval-equivalent to `revoke`/`delete`. `mcp_policy.hpp`'s
  `requires_approval()` carries no `ApiToken` rule, so at `supervised` tier
  `Delete` requires approval and `Rotate` does not; a caller can rotate and
  confirm a same-principal sibling token of equal tier/scope — destroying
  its predecessor and revealing a fresh successor secret to themselves —
  with neither `ApiToken:Delete` nor an approval. No privilege gain, but a
  real residual (availability + cross-consumer credential capture within
  one principal). (2) The guard also blocks the **de-escalating**
  direction, undocumented until this pass: a cookie/JIT-elevated session's
  empty tier/scope does not match a predecessor that itself carries a tier
  or scope, so the owner of an MCP-tiered or service-scoped token cannot
  rotate/confirm it from the dashboard at all — only that token's own
  secret (or an equally-tiered session) can, which is backwards precisely
  when the secret is under suspicion. Both points, plus the fact that the
  `"no such token to rotate"`/`"...to confirm"` wording is misleading (not
  wrong) for this case, are now recorded in
  `docs/auth-architecture.md` "Human API-token rotation",
  `docs/user-manual/authentication.md` "Rotating a Token", and the error
  matrices in `docs/user-manual/rest-api.md`. **Addendum (2026-09-17, #2963):**
  the de-escalating-direction gap this paragraph flags as an undocumented
  capability loss was subsequently DECIDED and FIXED — a caller holding no
  standing tier/scope may now act on any of its own tokens; see
  `docs/auth-architecture.md` "Human API-token rotation" for the current
  state. This review's own text below is left as the point-in-time record
  of what the pass found, not updated in place. Pinned by a new REST-level
  test: an untiered (cookie-shaped) caller refused rotating its own tiered
  token (`test_rest_api_tokens_rotation.cpp`, `[pg][rest][token][rotation]
  [security]`) — the REST harness's session tier/scope default to
  untiered, so nothing exercised this direction before this pass.
  Widening the guard to admit a strictly-higher-authority caller is an
  explicitly OPEN product decision, not made here.

## Validation

- Unit: `tests/unit/server/test_api_token_store.cpp` `[human]` — 33 cases
  added by the adversarial regression suite (`67c585c9`, written against
  the pinned `rotate_token`/`confirm_token_rotation` signatures **before**
  the implementation landed, so the suite judges the implementation
  independently). Coverage: group- vs principal-scoped ceiling (the core
  regression this feature exists to prevent), Hermes F1/F2 concurrency and
  atomic pair-commit twins, `sweep_expired_rotations` +
  `list_rotations_nearing_expiry_unused` kind-discrimination, successor TTL
  inheritance, `#2384`-style pin-mismatch (same- and cross-lineage), confirm
  terminal-vs-retryable state discrimination, store-level self-service
  ownership binding, absence of a token-enumeration oracle, the
  group-scoped >2-active defensive reject, and a
  `classify_engine_store_error` round-trip. Two cases had their asserted
  contract corrected post-merge (`035099e8`) against the final shape.
- **Directly verified, 2026-08-10** (not sourced from
  `~/.local/share/yuzu/test-runs.db` — this was an ad hoc binary invocation,
  not a `/test`-skill run, so it has no ledger entry there): built
  `tests-build-server-linux_x64/yuzu_server_tests` from this branch (`e1bf2d86`
  plus this record's own doc-only commits on top) and ran against live
  Postgres (`localhost:5433`, `YUZU_TEST_ENABLE_PG=1`). `"[human]"` →
  **33 test cases, 404 assertions, all passed**. `"[token]"` (broader
  API-token sanity check) → **161 test cases, 1804 assertions, all passed**.
  Reproducible via `./tests-build-server-linux_x64/yuzu_server_tests
  "[human]"` with `YUZU_TEST_POSTGRES_DSN` set.

## Reviewer

Multi-round review across the store-core, telemetry, and REST sub-branches
(rounds 2–6 above), plan-review before implementation (token-keyed vs
principal-keyed), two ownership/architecture specialists (round 6), and an
independent architect adjudication (round 5, confirm-error taxonomy). MCP
tool twins are reviewed separately and remain in progress.

## Addendum — 2026-08-23 (#3015, proof of possession)

This review's "Rotating a Token" interim guidance (added `5edbbc06`, in
response to UP-2 above: if the rotate response was lost, revoke the unknown
successor rather than looking its `token_id` up and confirming it) covered a
real gap — `confirm` took only the session identity + `token_id`, so a
caller who recovered an unknown successor's id out-of-band could confirm a
rotation whose secret they never received, revoking the predecessor they
still held. That gap is now closed at the mechanism, not just the operator
runbook: **#3015 adds proof-of-possession to both confirm arms** —
`confirm_rotation` (engine) and `confirm_token_rotation` (human) now require
the caller to present the raw successor secret itself, verified via a
constant-time hash comparison against the successor's stored hash, checked
last, strictly after every other admission check (ownership, pair-state,
the successor `token_id` pin, and the initiator binding) has passed. A
caller who never received the secret cannot manufacture it from a recovered
`token_id` alone, so the interim revoke-don't-confirm guidance is no longer
a workaround for a missing check — it is now what the mechanism itself
enforces (`docs/user-manual/authentication.md` "Rotating a Token", updated
in the same round as this addendum). This is a **breaking** change on both
REST confirm routes and both MCP confirm tools: a caller confirming with
`token_id` alone now gets `400` where it previously succeeded.

Shipped alongside it: the **#2961 residual A** gap this review's UP-2
discussion did not cover — `revoke_for_principal` ("sign out everywhere" /
principal deactivation) previously left any RAM-only grace-cache successor
secret from a recent rotate re-servable via a grace-window replay for up to
the grace window's duration *after* every credential for that principal had
just been revoked. `revoke_for_principal` now scrubs (`yuzu::secure_zero`,
never a bare erase) every affected rotation group's cached raw secret after
the per-principal advisory-locked revoke transaction commits (keyed by the
rotation groups that transaction returned) — safe because no active
predecessor remains to re-serve one, so a deactivated/signed-out principal
cannot leave a re-servable secret behind. (Residual B — a genuinely concurrent in-flight mint's own
post-commit cache write racing a revoke — remains bounded by the existing
`successor_rotation_still_pending` guard and is unchanged by this round;
see `api_token_store.hpp`'s `revoke_for_principal` doc comment.)

Full detail: the #3015 commit itself, `docs/user-manual/rest-api.md`'s
confirm-route error matrices, and `docs/user-manual/authentication.md`
"Rotating a Token".

## Governance Gate 7 follow-up — 2026-08-24

Two doc-fix findings against the addendum above, both verified against the
shipped `#3015` code before writing this down (not asserted from the design
intent alone):

- **Ordering invariant.** PoP is verified STRICTLY LAST in both confirm
  arms — after ownership/pair-state, the `token_id` pin, tier, scope, and
  the initiator binding, in that order (`api_token_store.hpp`'s
  `confirm_rotation`/`confirm_token_rotation` doc comments, "ORDERING IS
  LOAD-BEARING"). A future reorder that moved PoP ahead of the initiator
  binding would reintroduce the cross-admin oracle this addendum's engine-arm
  design closed (a non-initiator who also knows — or guesses — the correct
  secret could distinguish "wrong secret" from "valid secret, not your
  rotation"). `test_api_token_store.cpp`'s `[pop][oracle]` case already pins
  this specific relative order (a non-initiator presenting the *correct*
  secret must get the SAME non-disclosing "different operator" outcome as
  one presenting a *wrong* secret) — flagged here so a later change to
  either confirm arm's check order re-verifies against that test explicitly,
  since a reorder of PoP relative to the *other*, earlier checks (ownership,
  pair-state, tier, scope) is a distinct hazard the oracle test does not by
  itself cover.
- **Deliberate REST/MCP audit asymmetry.** The missing-secret early-out
  (`400` REST / `kInvalidParams` MCP) IS audited on the REST confirm routes
  (`audit_fn(..., "failure", ..., "secret required")` in `rest_api_v1.cpp`)
  but is NOT audited on the MCP confirm tools — verified in
  `mcp_server.cpp`: both `confirm_engine_rotation` and
  `confirm_api_token_rotation` return on a missing/empty `secret` before any
  `mcp_audit`/`audit_fn` call. This is not new drift — it matches the
  pre-existing, in-code-documented MCP convention that input-validation
  early-outs (a missing `principal_id`/`token_id`, same functions) are
  likewise unaudited on that transport ("family scope contract" — the
  `#2404` confirm-outcome-counter comment immediately above
  `confirm_engine_rotation`'s body states it applies "NOT on the tier / perm
  / input-validation early-outs"). The security-relevant outcome — a
  *wrong* secret, `403`/`kPermissionDenied` — IS audited on both
  transports. Recorded so a later auditor reading only the MCP side does
  not mistake the missing-secret gap for an omission specific to #3015.

