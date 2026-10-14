- **Home page: Compliance by policy, Recent activity and Server health panels.** Three new dashboard
  fragments (`/fragments/home/policies`, `/fragments/home/activity`, `/fragments/home/health`) back
  the Home page. Compliance by policy lists the five enabled policies with the lowest pass rate and
  shows "No results yet" for a policy that has not reported, never 0 percent. Recent activity shows
  the eight newest audit rows (time, who, action, target, result) to administrators who hold
  `AuditLog:Read`; `detail`, source address, user agent and session id are never shown. Server health
  reuses the `/api/health` document, so Home and the probe agree on what "healthy" means. Every
  panel answers 200 with a distinct note for a refused, limited or unreadable read, and a service
  scoped token is refused first. No new REST route or MCP tool.
