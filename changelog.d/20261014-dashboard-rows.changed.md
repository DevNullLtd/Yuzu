- **Dashboard laid out as rows.** The console page (`/`) now stacks, top to bottom: a full-width
  scope bar (the device picker plus a reference line of the scope kinds from
  `/api/v1/discover/scope-kinds`), the console with its results beside the command history, the
  readout, Needs attention beside Server health, Recent events, and Estate state beside Compliance by
  policy. Rows share one grid with a 22px gutter and stack to one column under 1140px. The page
  scrolls as a whole instead of pinning the results table to the viewport. The panels that were on
  the Home page moved here, and their fragment routes moved from `/fragments/home/*` to
  `/fragments/dashboard/*` (their audit action is `dashboard.fragment.access_denied`). Rows the design draws without a data source on the server
  (a ranked device list, events by severity, command throughput, activity by hour) are not shown.
