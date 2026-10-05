- **Breaking: response routes parse numeric parameters strictly and exports are bounded (#4644, #4703).**
  `status`, `since`, `until`, `limit` (and `offset` on the legacy catch-all route) on `GET /api/responses/{id}[/aggregate|/export]`,
  `GET /api/v1/responses/{id}[/aggregate|/export]` and `GET /api/v1/executions/{id}/responses` were read with `std::stoi`/`std::stoll`,
  which stop at the first non-digit and accept a leading `+` or whitespace: `?since=1e9` silently meant "since epoch second 1",
  `?status=0x1` meant status `0`, `?limit=100abc` meant `100` and `?since=1.5` meant `1`. The whole value must now be one base-10
  integer, so those forms return `400` (an empty value and a value too large for its type already did). `status` below the
  documented `-1` "any" sentinel, such as `status=-5` (which the store treated as no filter), is now `400` as well. A script that
  passes a fractional epoch (`date +%s.%N`) must send integer seconds. A **negative** `since` or `until`, and `until=0`, are `400` too (each was read as "unbounded", so a window that underflowed or collapsed to `0` returned the whole result): omit the parameter for no bound on that side. `since=0` stays accepted and matches the same rows as omitting it. MCP `query_responses` returns `-32602` for a `status` or `limit`
  that is not a JSON integer (a float, a string, a boolean and `null`, which was previously read as the default: omit the key
  instead), for `status` below `-1` or above `2147483647`, and for an unsigned value above `9223372036854775807` (which wrapped to
  `-1`, the "any" sentinel). `param_int_strict` now refuses that unsigned range for its 16 other MCP callers too.
  The legacy `GET /api/responses/{id}/export` now clamps a caller-supplied `limit` to `1` through `10000` like its v1 twin (an explicit
  `?limit=999999999` was an unbounded fetch; `limit=0` or a negative value now serves one row), its `count` is the number of rows served,
  and the legacy `GET /api/responses/{id}` clamps an explicit `limit` to `1000` like v1 and MCP; when the caller asked for more than 1000
  and got a full page, its body now carries `result_truncated_by_cap: true`. Both export routes also stop at 50 MiB of
  row payload (`output` plus `error_detail`; each output is cut to only 2 MiB of raw bytes at ingest, apart from a terminal frame's `error_detail`, so a row cap alone allowed a multi-GB body).
  The cut is made inside the store query, so the fetch holds about that much payload plus one final row (the last row kept can run
  past the cap by up to its own size, about 4 MiB for text output and up to about 12 MiB for output dense in invalid bytes or NULs, and more where a terminal frame's `error_detail`, which is not cut at ingest, is large)
  instead of materialising up to `limit` full rows first; a result under 50 MiB of raw
  payload can still be cut when its escaped serialized form crosses the cap. The plain list routes (`GET .../responses/{id}`, MCP
  `query_responses`, `GET /api/v1/executions/{id}/responses`) are still bounded by row count only, and so is the dashboard results fragment's filtered branch;
  the execution visualization route, the dashboard results fragment's unfiltered read and the TAR retention-paused scan page now share the byte-aware fetch and report a cut (see the next entry); other internal reads, for example the pre-flight and deployment polls (50,000 rows), are also unbounded by bytes. A cut export, whether by the row cap
  or the byte cap, is marked: `pagination.result_truncated_by_cap` (v1 JSON) or a top-level `result_truncated_by_cap` field (legacy JSON,
  new), and a cut CSV ends with one extra trailer record `# result_truncated_by_cap cause=<row_cap|byte_cap>` padded to the header width
  (a CSV parser that expects a number in the `id` column fails on it, only on a cut file, on purpose; an uncut CSV is unchanged). A cut
  export also carries an `X-Result-Truncated-By-Cap: true` header (CSV, both routes) and a `responses-<id>-truncated.<json|csv>`
  download name, which `curl -OJ` keeps and a plain `curl -o` does not; any character of the id outside `[A-Za-z0-9._-]` is
  written as `_` in that name (only the legacy route accepts such ids). Read a CSV export as CSV and take the final record: a
  quoted cell can contain text that looks like the trailer. The cap is not operator-tunable. Two counters,
  `yuzu_server_response_param_rejected_total{surface}` and `yuzu_server_response_export_truncated_total{surface,cause}`, report the
  rejections and the cuts. During a rolling upgrade, replicas on the old and new build answer a malformed value differently (`200`
  versus `400`).
