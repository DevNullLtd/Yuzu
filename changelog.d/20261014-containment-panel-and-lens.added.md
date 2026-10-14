- **Device containment on the Hardware page.** A Quarantined devices panel, a Quarantined pill on
  list rows, a record-header banner and a Containment tab show which devices have an active
  quarantine record and how far containment has been shown to reach them (recorded, applied, or
  confirmed), and let an operator with `Security:Execute` quarantine or release a device from a
  dialog. Release ends the server record only and says so. The list and panel use the same
  `Security:Read` list-gate decision as `GET /api/v1/quarantine` (one decision per view, its scope
  applied in the store query, so a confined account sees only its own records and an out-of-scope
  record costs no probe or audit row), extracted into one shared function; quarantining or releasing
  a device now writes an `attempt` audit row before the change and refuses it (503,
  `Sec-Audit-Failed: true`) if that row cannot be written; the page route now forwards a validated `lens` so a link can open a specific tab.
