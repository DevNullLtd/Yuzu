- **The MCP settings form could not turn MCP on, and a partial request changed MCP state.** The
  old panel posted a hidden `false` field before each checkbox and the handler read the first
  match, so any change made while MCP was enabled left it disabled and Read-only unset; an absent
  `enabled` or `read_only` field was also read as `false`. `POST /api/settings/mcp` now requires
  exactly one `enabled` and one `read_only`, each `true` or `false`, and answers `400` with
  nothing changed otherwise. The panel is one form with a radio group per field and one Save,
  with a confirmation that matches the state being saved.
