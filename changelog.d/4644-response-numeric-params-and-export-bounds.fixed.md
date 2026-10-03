- **Response query/aggregate/export routes parse numeric parameters strictly and bound export size (#4644, #4703).**
  `status`, `since`, `until`, `limit` (and `offset` on the legacy catch-all route) on `GET /api/responses/{id}[/aggregate|/export]`,
  `GET /api/v1/responses/{id}[/aggregate|/export]` and `GET /api/v1/executions/{id}/responses` are read with `std::stoi`/`std::stoll`
  before this change, which stopped at the first non-digit: `?since=1e9` silently meant "since epoch second 1" and `?status=0x1`
  meant status `0`. A malformed value (trailing characters, hex/exponent form, whitespace, a leading `+`, an empty value or an
  out-of-range number) now returns `400`, and `status` below the documented `-1` "any" sentinel (for example `status=-5`, which the
  store treated as no filter) is rejected too. MCP `query_responses` rejects a non-integer or `< -1` `status` and a non-integer `limit` as
  invalid params instead of reading them as the default. The legacy `GET /api/responses/{id}/export` now clamps a caller-supplied
  `limit` to `[1,10000]` like its v1 twin (an explicit `?limit=999999999` previously requested an unbounded fetch), and both export
  routes stop appending rows at approximately 50 MiB of row payload (each response output is capped at only 2 MiB at ingest, so a row
  cap alone allowed a multi-GB serialized body). That cap bounds the serialized response, not worker memory: the full result is still
  loaded before it applies. A body cut by the byte cap or the row cap carries the same truncation signal:
  `pagination.result_truncated_by_cap` / `X-Result-Truncated-By-Cap: true` on v1, and `X-Result-Truncated-By-Cap: true` (CSV) or a
  top-level `result_truncated_by_cap` field (JSON envelope, new) on the legacy route. Clients that relied on a malformed value being
  silently ignored will now see `400`.
