- **Legacy `GET /api/approvals` now validates `status` (#2146 A2-R4).** The
  legacy unversioned route previously passed an unrecognized `status` query
  value (a typo, a case mismatch, or an explicit empty string) straight into
  the SQL filter, silently returning a false-empty or false-ALL-statuses
  result instead of rejecting the request. It now 400s on any value outside
  `pending`/`approved`/`rejected`/`expired`, matching the new
  `GET /api/v1/approvals` twin and MCP `list_pending_approvals`.
