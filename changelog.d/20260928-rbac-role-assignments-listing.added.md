- **Fleet-wide RBAC role-assignment listing.** `GET /api/v1/rbac/roles/assignments` and its
  MCP twin `list_rbac_role_assignments` return every `(principal_type, principal_id, role_name)`
  grant row on record, across all three principal types, in one bulk read — the complete grant
  table, not a management-group-confined slice. Gated on the same dedicated `AccessReview:Read`
  securable the SOC 2 access-review export uses, admitting the seeded `Reviewer` role as well as
  `Administrator`.
