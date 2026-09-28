# Draft issue comments — #5047 Phase 2 (DO NOT POST — operator review first)

These are drafted comment bodies for the orchestrating session / operator to review and post
manually via `gh issue comment`. Nothing in this file has been posted. Branch:
`fix/5047-result-set-tier-policy-cross-transport`.

---

## (a) Comment for #5047

AC1 (deciding whether `ResultSet` gets a real RBAC securable) is being closed as a duplicate
of #1207, which already tracks that work and its constraints (see the comment being added
there now). This PR does not attempt AC1.

What this PR does fix is the narrower, independently-real bug AC2 asks for: the 4 result-set
*write* routes/tools (`create`/`pin`/`unpin`/`delete_result_set`) had no RBAC/`perm_fn` gate at
all — ownership was the sole check — and MCP's C8 tier/approval belt (`tier_allows`/
`requires_approval`) only ran on the MCP transport. A supervised-tier MCP bearer token could
therefore reach the identical mutation, unrestricted, by calling REST or the dashboard fragment
instead of `/mcp/v1/` — the exact class of bypass #520 was supposed to have closed everywhere.

The fix: `AuthRoutes::require_permission`'s `mcp_tier` branch is extracted verbatim into a new
`AuthRoutes::require_tier_policy(req, res, session, securable_type, operation)`, which is now
also called from the 4 REST write routes (`server/core/src/rest_api_v1.cpp`) and their 4
dashboard-fragment twins (`server/core/src/result_set_routes.cpp`), right after session
resolution and before the ownership check. `require_permission` itself is unchanged in
observable behaviour (regression-tested).

The already-accepted empty-tier gap (a plain RBAC session or a non-MCP-tiered API token skips
this belt on every transport, not just these four routes) is untouched by this PR — that's
#4309's open design question, not this one's.

Tests: `tests/unit/server/test_auth_routes.cpp` (the extracted `require_tier_policy` directly),
`tests/unit/server/test_result_set_routes.cpp` (the 4 fragment write sites), and a new
`tests/unit/server/test_rest_result_sets_tier_policy.cpp` (the 4 REST write routes, including a
real end-to-end supervised-tier `DELETE` → 403 w/ ticket-then-recall remediation, and confirming
an engine-principal session — hard-locked to `mcp_tier=readonly` — is now denied a write it was
previously admitted to on ownership alone).

`docs/user-manual/rbac.md` gained a "Not RBAC-gated: per-operator result sets" section recording
the ownership-only design, the no-admin-override fact, which producer routes/tools ARE RBAC-gated
(and on what securable), and pointers to #1207/#4309.

---

## (b) Comment for #1207

Recording binding constraints for whoever implements the real `ResultSet` securable, gathered
while fixing the narrower #5047 cross-transport bug (which does NOT attempt this issue):

1. **AND-compose with ownership, never replace it.** An operator's own result sets must stay
   reachable by ownership alone regardless of any securable grant they hold or lack — the
   securable is for *additional* (cross-operator) reach, not a gate that could lock an owner out
   of their own resource or admit a non-owner outright without an explicit share.
2. **Sharing must be a distinct, separately-gated operation** — not a side effect of a broader
   `ResultSet:Write`/`:Read` grant. A grant that happens to cover `ResultSet` must not silently
   widen access to every other operator's result sets; do not conflate "I can create result sets"
   with "I can read/mutate someone else's."
3. **Cover all three surfaces, not just REST+MCP.** There are 8 REST routes, 8 MCP tool twins,
   AND 6 dashboard fragments (`/fragments/result-sets/*`) on the ownership-only family today —
   whatever securable/grant model lands must reach the fragments too, or the dashboard becomes a
   silent bypass of a REST/MCP-only fix (the exact shape of bug #5047 just closed on a different
   axis).
4. **Decide engine-principal admission explicitly.** Engine principals (ADR-1005 class) are
   default-deny and hard-locked to `mcp_tier=readonly`; #5047 makes an engine session's REST
   *write* explicitly denied by the tier belt (previously admitted on ownership alone if the
   engine session happened to own the row). Once a real securable exists, decide on purpose
   whether/how an engine principal can ever hold a `ResultSet` grant — don't let it fall out
   accidentally from the general RBAC engine-principal rules.

Also note for scoping: the 4 *producer* routes/tools (`create_result_set_from_tar_query`,
`create_result_set_from_instruction_result`, `reevaluate_result_set` — all `Execution:Execute`,
confined dispatch visibility; `create_result_set_from_inventory_query` — `Inventory:Read` via the
ADR-0017 fleet-read chokepoint) are NOT part of the ownership-only family and already have real
securables — this issue is about the other 8 read/write routes.

---

## (c) Comment for #4309

Flagging 4 additional tool instances of this issue's empty-tier gap, found while fixing the
independently-real cross-transport bug in #5047 (unaffected by that fix — recording here for your
own tracking, not asking you to act):

`create_result_set`, `pin_result_set`, `unpin_result_set`, `delete_result_set` (and their REST/
dashboard-fragment twins) all skip C8's tier/approval belt entirely for a caller with an empty
`mcp_tier` (a plain RBAC session, or an API token minted without one) — same root cause as every
other tool already on this issue's list: `mcp::tier_allows`/`requires_approval` both return `true`
unconditionally on an empty tier, and this whole family also happens to have no RBAC/`perm_fn`
gate to fall back on, so an empty-tier caller who owns the resource gets no additional protection
at all beyond ownership on a Destructive op (`delete_result_set`'s `Infrastructure:Delete`).

#5047 does not attempt to fix this — it only closes the *cross-transport* half (a TIERED bearer
switching to REST to dodge the belt). The empty-tier design question stays entirely open here.
