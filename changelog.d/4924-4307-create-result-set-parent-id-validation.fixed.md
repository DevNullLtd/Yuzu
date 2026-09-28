- **`create_result_set` (REST `POST /api/v1/result-sets` and its MCP twin) now rejects a malformed or empty `parent_id`, instead of silently creating a parentless set (#4307).**
  Both the REST route and the MCP tool accepted `parent_id` only when it was
  a non-empty JSON string; a caller-supplied `{"parent_id": 123}` or
  `{"parent_id": ""}` fell straight through that guard and was silently
  treated as "no parent_id" — the caller believed the new set was parented
  onto an existing one, and it silently wasn't. Both now 400 /
  `kInvalidParams` with `RESULT_SET_BAD_PARENT` on that shape, matching the
  existing guard the three dispatching result-set producers already apply
  to the same field (this route is synchronous and never dispatches, so the
  fix carries no new metric — that family is reserved for the
  dispatch-targeting routes).
