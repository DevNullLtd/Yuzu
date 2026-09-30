- **Breaking — `POST /api/v1/result-sets`, MCP `create_result_set`, and the dashboard CSV-paste
  import (`POST /fragments/result-sets/create`) now require `Infrastructure:Read` and validate
  that every `device_ids` entry exists and is visible to the caller** (#4983). Previously all
  three surfaces accepted an arbitrary caller-supplied `device_ids` array with only a type check
  (`is_string()`) and an array-size cap and no RBAC check at all — a nonexistent id, or a real id
  outside the caller's own management-group/service-scope confinement, was silently accepted as a
  member, so `device_count`/lineage on the created result set were unverified. A `device_ids`
  entry that does not exist, or that exists but is outside the caller's own scope, now rejects the
  WHOLE request with `400 RESULT_SET_UNKNOWN_DEVICE_ID` (REST) / the JSON-RPC equivalent (MCP) /
  an error toast (the dashboard fragment) — never a silent drop and never a partial create — with
  the offending id(s) named in the error (the caller's own submitted list, so this is not a
  disclosure of someone else's device existence). Each `device_ids` entry is also now capped at
  256 bytes (`400 RESULT_SET_DEVICE_ID_TOO_LONG` / the JSON-RPC equivalent / an error toast) — a
  separate, additional new rejection path on all three surfaces. **Breaking change:** the new gate
  is a mandatory admit-then-filter `Infrastructure:Read` chokepoint (`fleet_read_fn`, ADR-0017),
  checked whenever `device_ids` is non-empty. Under an RBAC-**enabled** deployment, of the six
  built-in roles only `Administrator` and `ITServiceOwner` hold `Infrastructure:Read` — `Viewer`, `Operator`,
  `PlatformEngineer`, `ApiTokenManager`, and `Reviewer` do **not** — so a principal holding one of
  those five roles who could previously create a result set with `device_ids` now receives a new
  `403`. This only bites RBAC-**enabled** deployments; the default RBAC-**off** configuration is
  unaffected. See `docs/user-manual/server-admin.md`'s new vNEXT entry for the full upgrade note
  and remediation. A request that omits `device_ids`, or supplies an empty array, is completely
  unaffected on all three surfaces — no new gate, no new cost.

  The existence check is presence-merged (the same fleet-wide domain a real dispatch uses, not
  just this replica's local connections), so a device known only via cross-replica presence is
  correctly recognized as existing under normal operation. During a cross-replica presence-store
  degradation, however, `AgentRegistry::all_ids()` narrows to local-only ids (the same documented
  residual its other two existing callers already carry, tracked under #5007) — this can cause a
  transient, non-retryable false-reject of a presence-only device in that window; it is not the
  "never wrongly rejected" guarantee an earlier draft of this note claimed.

  Correction to an earlier draft of this note: the per-owner result-set quota is **not** paddable
  by a junk `device_ids` entry — `ResultSetStore`'s quota check counts result *sets*
  (`SELECT COUNT(*) ... WHERE owner_principal = $1`), not member rows, so one set with junk
  members only ever consumes exactly one quota unit regardless of member count. The gap this fix
  closes is the unverified `device_count`/lineage and the missing authorization check, not quota
  padding.
