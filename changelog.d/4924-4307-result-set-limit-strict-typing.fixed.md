- **MCP `list_result_sets`/`get_result_set_members` now reject a wrong-typed `limit`, instead of silently substituting the default (#4307).**
  Both handlers parsed `limit` with the loose `param_int` helper, which
  silently falls back to its default on a present-but-wrong-typed value (a
  JSON string or bool) — a caller-side type mistake went entirely
  unreported, and any subsequent range check passed because the default is
  always in range. Both now use `param_int_strict` (`#2970B` convention,
  already adopted elsewhere in this file), returning `kInvalidParams` on a
  malformed `limit` rather than a default-limited success.
