- **Fixed — result-set write routes could no longer bypass the MCP tier/approval belt by
  switching transports (#5047).** `create`/`pin`/`unpin`/`delete_result_set` have no RBAC
  securable of their own (ownership-scoped by design, unchanged — see
  `docs/user-manual/rbac.md`'s new "Not RBAC-gated: per-operator result sets" section), but an
  MCP-tiered bearer token could previously reach the identical mutation its own MCP tool already
  tier/approval-gates by calling `POST/DELETE /api/v1/result-sets/*` or the equivalent dashboard
  fragment instead of `/mcp/v1/`. `AuthRoutes::require_tier_policy` (extracted from
  `require_permission`, same tier/approval logic, no behavior change there) now also runs on all
  8 of those write sites, closing the cross-transport gap for tiered callers — an untiered
  caller (plain RBAC session, or an API token minted with no `mcp_tier`) is unaffected, which
  stays the separate, already-tracked #4309 design question.
