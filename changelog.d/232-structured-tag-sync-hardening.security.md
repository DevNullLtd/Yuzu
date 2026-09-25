- **Breaking — structured-tag sync hardened: bounded change log, escaped and capped values, atomic persistence** (#232).
  The agent's change log is now bounded at the newest 50 entries in memory as well as on disk, so a
  long-running agent no longer grows it without limit. Synced tag values are capped at 448 bytes (the
  server's own limit, cut on a UTF-8 codepoint boundary) and every field the plugin emits — values, keys,
  and the echoed text of its two error rows — is now escaped with the shared `safe_output_field`, so a
  value containing `|` (for example `Rack A|3`) can no longer shift or forge columns, and a value
  containing a backslash or an embedded CR/LF is normalized (`\` → `/`, CR/LF → space) for the same
  reason; stored values are never rejected or stripped. State is now persisted under the same lock as
  the change that produced it, through a temp file renamed into place (owner-only `0600` on POSIX;
  Windows keeps the inherited ACL), and write failures are logged and reported on `sync` as a
  `CONSTRAINED` / `PARTIAL` result status with provenance `asset_tags:persist_failed` (`sync` previously
  declared no status). A corrupt or wrong-typed state file is now rejected whole with a logged reason,
  and the agent starts from defaults until the next `sync` rewrites it; a malformed
  `asset_tags.check_interval` is logged instead of silently ignored. **Operator action on upgrade:** an
  existing state file holding more than 50 change entries is trimmed to the newest 50 on load — older
  entries in the `changes` action's diagnostic trail are lost, not archived; this is local diagnostic
  history, not the authoritative tag state, which remains intact on the server. Stored values longer than
  448 bytes are capped on load, and a value containing `\`/CR/LF renders differently after upgrade per
  the escaping above. A stored value that is not valid UTF-8 is persisted with U+FFFD in place of each
  bad byte, so it changes after a restart; a value the server accepted is valid UTF-8 and is unaffected.
