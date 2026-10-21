- **Settings gains a General page.** `/settings/general` groups the Appearance preference (table
  density, saved in this browser), the agent heartbeat timeout and log level (the two runtime
  settings that already had a `PUT /api/config/{key}` route and no UI), the existing
  server-configuration and analytics read-outs, and a recent-events table with Pending and Emitted
  counts. Changing the heartbeat timeout, or lowering the log level to `warn` or `error`, asks for
  confirmation first. The page is admin-only and additive: every panel stays on `/settings`, and no
  REST route or MCP tool is added. The server-configuration table now labels the old "Session
  Timeout" row "Agent heartbeat timeout" (it is the agent liveness window, not the dashboard
  sign-in expiry) and gains read-only "Dashboard idle timeout" and "Dashboard session lifetime"
  rows; `GET /api/v1/settings/server-config` gains `session_inactivity_seconds` and
  `session_absolute_lifetime_seconds`.
