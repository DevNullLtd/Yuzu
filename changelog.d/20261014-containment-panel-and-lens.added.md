- **Device containment on the Hardware page.** A Quarantined devices panel, a Quarantined pill on
  list rows, a record-header banner and a Containment tab show which devices have an active
  quarantine record and how far containment has been shown to reach them (recorded, applied, or
  confirmed), and let an operator with `Security:Execute` quarantine or release a device from a
  dialog. Release ends the server record only and says so. The panel and list pills make one `Security:Read` list-gate decision per view and apply its
  scope in the store query, the same rule as `GET /api/v1/quarantine`, so a confined account sees
  only its own records and an out-of-scope record costs no per-record permission check or audit
  row. The page route now forwards a validated `lens` so a link can open a specific tab.
