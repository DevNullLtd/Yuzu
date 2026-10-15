- **Compliance dashboard fragments now enforce the same permissions as their REST twins.**
  `/fragments/compliance/summary` requires `Policy:Read`, and `/fragments/compliance/{id}`
  uses the fleet-read gate as its only gate, lists only the devices in the caller's scope
  and writes a `compliance.agent_statuses.view` audit row on every open (a failed audit
  write still renders the page and sets `Sec-Audit-Failed`). Previously both fragments
  needed only a signed-in session. Roles without `Policy:Read`, and operators whose grant
  arrives only through a management group, no longer see compliance data on the
  dashboard that they could already not read through the API.
