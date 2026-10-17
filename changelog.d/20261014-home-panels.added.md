- **Dashboard: Compliance by policy, Recent events and Server health panels.** Three dashboard
  fragments (`/fragments/dashboard/policies`, `/fragments/dashboard/activity`,
  `/fragments/dashboard/health`) fill the Dashboard's lower rows. Compliance by policy lists the five
  enabled policies with the lowest pass rate and shows "No results yet" for a policy that has not
  reported, never 0 percent. Recent events is a five-column table (time, who, action, target,
  severity, the last being the audit row's own result) of the eight newest audit rows, shown to
  administrators who hold `AuditLog:Read`; `detail`, source address, user agent and session id are
  never shown. Server health reuses the `/api/health` document, so the panel and the probe agree on
  what "healthy" means. Every panel answers 200 with a distinct note for a refused, limited or
  unreadable read, and a service scoped token is refused first. No new REST route or MCP tool.
