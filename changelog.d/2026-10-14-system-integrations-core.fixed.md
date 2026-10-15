- **BREAKING for scripted callers of `POST /api/settings/mcp`: both fields are now required.**
  Before, the handler read the first `enabled` and `read_only` it found and treated a missing or
  unrecognised value as `false`, so a body carrying only one field silently switched MCP off or
  flipped Read-only. Now the body (`application/x-www-form-urlencoded`, fields split on `&`)
  must contain exactly one `enabled` and exactly one `read_only`, each with the literal value
  `true` or `false`. Request shapes and the answer:
  - both fields, once each, `true` or `false`: applied, as before (status 200);
  - either field missing, empty body, or a JSON body: `400`, nothing changed, body
    `{"error":{"code":400,"message":"enabled is required"}}` (or `read_only is required`);
  - either field repeated (for example the old hidden `false` plus a checked `true`): `400`,
    `... must be supplied exactly once`;
  - a value other than `true` or `false` (`on`, `1`, empty, `True`): `400`,
    `... must be true or false`;
  - not an admin session: unchanged (the existing admin check answers first).
  Update scripts to send `enabled=<true|false>&read_only=<true|false>` on every call.
- **The MCP settings form could not turn MCP on.** The old panel posted a hidden `false` field
  before each checkbox and the handler read the first match, so any change made while MCP was
  enabled left it disabled and Read-only unset. The panel is now one form with a radio group per
  field and one Save, with a confirmation that matches the state being saved.
