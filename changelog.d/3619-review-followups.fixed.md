- **Create Group from results checks `ManagementGroup:Write` again after its audit row (#3619
  follow-up to #7081).** `POST /api/dashboard/group-from-results` checked the permission once,
  before its `attempted` audit row, and that write can wait on the audit store. A grant withdrawn
  during the wait no longer creates the group: the request is answered `403`, nothing is created,
  and `group.create_from_results` records `failure` with `detail=permission_revoked`. The session
  and the visible agent set were already decided again at that point (`session_revoked`,
  `scope_revoked`), and the group's `created_by` now comes from the re-authenticated session.
