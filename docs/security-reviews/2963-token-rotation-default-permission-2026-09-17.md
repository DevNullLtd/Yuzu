# #2963 — human API-token rotation: default-permission reachability + tier-guard exception

**Date:** 2026-09-17
**Issue:** [#2963](https://github.com/Tr3kkR/Yuzu/issues/2963) (`decision` label — "the outcome is a recorded decision, not code") — [decision-trail comment](https://github.com/Tr3kkR/Yuzu/issues/2963#issuecomment-5717905783) posted on the issue itself, independently of this document, after PR #4470 review flagged the issue had no recorded approval trail
**PR:** [#4470](https://github.com/Tr3kkR/Yuzu/pull/4470)
**Commits (as reviewed):** `daad9f7d1` (fix), `6aedf9ec1` (governance hardening
round), `0cfa147db` (Gate 4/6 follow-through), `972a250a3` (ledger commit).
**Commits (as pushed — see note below):** `aafadd85d`, `531816ecb`,
`5f679211f`, `dbbb01620` respectively.

> **Note on commit hashes (added after PR #4470 review flagged this):** the
> four commits above were rewritten via `git commit-tree` (non-interactive,
> preserving tree/parent/author/message content byte-for-byte except one
> deleted `Claude-Session:` trailer line per line-item feedback in
> [[feedback-no-claude-footer-or-session-link]]) AFTER every governance gate
> in this document had already run and recorded its findings against the
> ORIGINAL hashes. The rewrite changed commit identity (SHA) but not content
> — every finding, fix, and test result recorded against the original SHAs
> below is unchanged and still accurate against the pushed tree; only the
> citation needs the mapping above to resolve. Governance ledger rows
> recorded against the original SHAs are NOT edited in place (the ledger's
> append/supersede-only contract) — see the superseding row in
> `governance.d/2963-token-rotation-default-permission.bj3HoJ.jsonl` with
> `finding_id: "2963-META-sha-rebase"`. Lesson for future runs: rewrite
> commit history (if needed for any reason) BEFORE running governance, or
> re-run governance against the final hashes, never after recording findings
> against hashes about to be discarded.
**Follows:** `docs/security-reviews/human-token-rotation-2026-08-10.md` (the original design review this decision resolves an open item from)

## Origin

`unhappy-path` findings UP-8/UP-9/UP-10 from the original human-token-rotation
governance run, corroborated independently by the Gate 8 `security-guardian`
re-review, flagged that the shipped self-service rotation surface
(`ApiTokenStore::rotate_token`/`confirm_token_rotation`, `POST
/api/v1/tokens/{id}/rotate`/`.../confirm`, MCP twins) composed two independently
correct controls into something narrower than either intended:

1. RBAC ships OFF by default, and the legacy fallback in
   `AuthRoutes::require_permission`/`require_scoped_permission` denied every
   non-`Read` operation — including `ApiToken:Rotate` — to a non-admin caller.
2. The store's self-service-only ownership check has no admin override.

Composed: only an admin could rotate, and only their own token — the feature
was reachable by nobody but an admin in the shipped default configuration.
A second, related gap: the authority-inheritance guard required bare equality
between the caller's own `mcp_tier`/`scope_service` and the token's, so an
untiered dashboard/cookie session could never rotate its own MCP-tiered or
service-scoped token — backwards precisely when the token's secret is the
thing under suspicion.

## Questions framed, and the decisions made

Three questions, each presented to the operator (Fraser) with a recommended
option and its rationale; all three recommendations were approved as-is
before any code was written.

**Q1 — Should `ApiToken:Rotate` be reachable by a non-admin token owner in the
default RBAC-off configuration?**
**Decided: yes.** Precedent: `DELETE /api/v1/sessions/me` already has NO
admin gate at all for the identical reason (self-service, ownership-enforced
downstream, recoverable) — this gate decides "may attempt", never "may act on
resource X", so admitting a non-admin caller grants nothing beyond their own
resource. Implemented as a new, single-purpose allowlist
(`server/core/src/legacy_self_service_allow.hpp`), consulted in both legacy
branches strictly below the existing `authz_topology_floor.hpp` check, mirror-
image of that file's mechanism (widens instead of floors).

**Q2 — Should a full-authority interactive session be permitted to rotate its
own narrower (tiered/scoped) tokens?**
**Decided: yes, as a single named exception, never a tier lattice.** A caller
holding no standing `mcp_tier`/`scope_service` already holds a strict superset
of what any tiered/scoped token can do, and the successor still inherits the
TOKEN's own narrower tier/scope verbatim — nothing is escalated. A general
"no broader than" ordering was explicitly rejected (it needs a tier-lattice
assumption the original guard deliberately avoided). Implemented as
`caller_may_act_on_tiered_token` (`server/core/src/api_token_store.cpp`),
replacing the bare equality check at all three call sites that had it
(`rotate_token`'s pre-txn + authoritative checks, `confirm_token_rotation`'s
defense-in-depth check).

**Q3 — What is the intended path for a token nearing expiry?**
**Decided: document only — mint a new token instead.** Rotation is
deliberately lifetime-neutral (CC6.3 property: the successor always inherits
the predecessor's `expires_at` verbatim) and the overlap window has a 24h
floor, so a token expiring within 24h cannot fit a lifetime-neutral overlap
without either extending its life or shrinking the floor past the point where
both secrets are reliably live for a cutover — neither is acceptable. The
store's existing, specific rejection
(`"overlap window would exceed the predecessor credential's expiry"`, 400) is
the intended terminal answer, not a bug. No code changed for this decision.

## What changed

| File | Change |
|---|---|
| `server/core/src/legacy_self_service_allow.hpp` | New. Single-entry allowlist (`{"ApiToken","Rotate"}`), consulted in `auth_routes.cpp`'s two legacy branches. |
| `server/core/src/auth_routes.cpp` | `require_permission`/`require_scoped_permission`: `self_service_exempt = !floored && legacy_self_service_allow(...)`, ANDed into the existing admin-role-required condition. RBAC-on path and the topology floor are untouched and evaluated first. |
| `server/core/src/api_token_store.{cpp,hpp}` | New `caller_may_act_on_tiered_token` helper; 3 call sites updated; doc comments corrected (they previously stated the old behavior as permanent/undecided). |
| `server/core/src/rest_api_v1.cpp`, `mcp_server.cpp` | OpenAPI + MCP tool description text updated (prose only, no schema/route/status-code change). |
| `docs/auth-architecture.md`, `docs/user-manual/{authentication,rest-api,mcp}.md`, `docs/mcp-server.md` | Design record + operator docs corrected to describe the new behavior (two passages previously stated the old behavior as a deliberate, permanent limitation). |
| `tests/unit/server/{test_auth_routes,test_api_token_store,test_rest_api_tokens_rotation}.cpp` | +6 new tests, 1 test rewritten (it had pinned the pre-fix refusal as intended behavior). |

## Safety argument (why widening these two admissions doesn't escalate authority)

- Both decisions widen **who may attempt** an operation; neither weakens the
  operation's own effect. `ApiTokenStore::rotate_token`/`confirm_token_rotation`
  independently and unconditionally refuse any `requesting_user` other than the
  resolved token row's own `principal_id` — no admin override, unchanged by
  this diff.
- The successor of a rotation always inherits the **predecessor's** own
  `mcp_tier`/`scope_service`/`expires_at` verbatim (pre-existing, unchanged
  logic) — never the caller's. A full-authority caller exercising the Q2
  exception can never mint a token broader than the one it replaced.
- The topology floor (`authz_topology_floor.hpp`) is checked first and cannot
  be bypassed by the new allowlist — `self_service_exempt` is computed as
  `!floored && legacy_self_service_allow(...)`, so a floored pair can never
  also be exempted.
- The exemption is a closed, single-entry list (`ApiToken:Rotate` only) with a
  four-part admission test in its own header comment for any future addition:
  self-targeted, unconditional downstream ownership enforcement, no new
  authority granted, and no separate non-authority impact (irreversibility,
  third-party availability loss, audit-evidence requirement) that would
  justify gating it regardless.

## Governance

Full `/governance origin/dev..HEAD` run: Gate 2 (security-guardian PASS,
docs-writer — 1 real MEDIUM finding, fixed same round: an OpenAPI description
had put the tier-mismatch clause under `404` instead of `400`), Gate 3
(architect — 2 non-blocking SHOULD doc-quality suggestions, both folded;
cpp-expert clean; cpp-safety clean, no resource/lifetime findings), Gate 4
(happy-path PASS; unhappy-path — see risk register in the run ledger), Gate 6
(compliance-officer — PASS with 2 SHOULD: this doc, and reclassifying the
changelog fragment from `.security.md` to `.changed.md`, both addressed; sre
PASS; enterprise-readiness — see run ledger), Gate 8 re-review of the
hardening round (security-guardian PASS, consistency-auditor PASS — confirmed
OpenAPI/hand-written docs/code/MCP description all agree post-fix, and no
sibling route has the same 404-vs-400 defect). Zero BLOCKING/HIGH findings at
any gate. Ledger: `governance.d/2963-token-rotation-default-permission.*.jsonl`.

## Residual, tracked, not fixed by this change

- No runtime kill-switch for the `legacy_self_service_allow` exemption (it is
  a compile-time `constexpr` list) — judged acceptable per sre's Gate 6 review
  since the store-enforced ownership check backstops any regression here, and
  this is a reachability fix, not an active-exploit mitigation requiring a
  runtime toggle.
- No proactive UI warning for a token approaching the 24h near-expiry dead
  zone — surfaced only via the store's own error message and this decision's
  documentation. Not filed as a follow-up issue; noted here as a known,
  accepted rough edge.
