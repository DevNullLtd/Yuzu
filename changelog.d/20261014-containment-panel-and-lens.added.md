- **Device containment on the Hardware page.** A Quarantined devices panel, a Quarantined pill on
  list rows, a record-header banner and a Containment tab show which devices have an active
  quarantine record and how far containment has been shown to reach them (recorded, applied, or
  confirmed), and let an operator with `Security:Execute` quarantine or release a device from a
  dialog. Release ends the server record only and says so. The list and panel use the same
  per-record admit-then-filter read as `GET /api/v1/quarantine`, extracted into one shared
  function; the page route now forwards a validated `lens` so a link can open a specific tab.
