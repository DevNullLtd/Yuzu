# Response Store and Data Export

The response store persists every instruction result returned by agents. It
provides filtering, aggregation, and export capabilities so operators can
analyze fleet-wide data without an external database.

## Storage

Responses are stored in the server's PostgreSQL substrate (schema
`response_store`, ADR-0039 — see the "Storage substrate (PostgreSQL)" section
below for the migration and retention details). Each response is recorded as a
`StoredResponse` containing the agent identity, instruction metadata, execution
status, result payload, and timing information.

| Setting | Default | Description |
|---|---|---|
| Retention period | 90 days | Responses older than this are deleted by the clock-guarded retention reap (`response_retention_days`) |
| Reap cadence | ~1 hour | How often the shared maintenance thread runs the expired-response reap |

## Response structure

Every stored response contains:

| Field | Type | Description |
|---|---|---|
| `id` | integer | Unique identifier for the response |
| `instruction_id` | string | Identifier of the instruction that was executed |
| `agent_id` | string | Agent that produced the response |
| `timestamp` | integer | Unix timestamp when the server recorded the response |
| `status` | integer | CommandResponse::Status enum value (0 = success, etc.) |
| `output` | string | Command output text |
| `error_detail` | string | Error message if the execution failed |

## Typed result schemas

Every instruction definition declares a result schema specifying column names
and types. This enables structured querying and ensures clean export to
downstream analytics platforms.

| Type | Description | Example value |
|---|---|---|
| `bool` | Boolean | `true` |
| `int32` | 32-bit signed integer | `42` |
| `int64` | 64-bit signed integer | `1099511627776` |
| `string` | UTF-8 text | `"Windows 11 Pro"` |
| `datetime` | ISO 8601 timestamp | `"2024-03-19T14:30:00Z"` |
| `guid` | UUID | `"550e8400-e29b-41d4-a716-446655440000"` |
| `clob` | Large text (configurable truncation) | Full file contents, log output |

Typed schemas make it straightforward to create ClickHouse tables, Splunk
sourcetypes, or Excel pivot tables from exported data.

## REST API

### GET /api/responses/{instruction_id}

Retrieve responses for a specific instruction execution with optional
filtering and pagination.

**Path parameters:**

| Parameter | Type | Description |
|---|---|---|
| `instruction_id` | string | The instruction execution to query |

**Query parameters:**

| Parameter | Type | Description |
|---|---|---|
| `agent_id` | string | Filter by agent |
| `status` | integer | Filter by status (integer enum value) |
| `since` | integer | Only responses at or after this Unix timestamp (inclusive); omit for no lower bound, `0` is accepted and matches the same rows |
| `until` | integer | Only responses at or before this Unix timestamp (inclusive); omit for no upper bound, must be `1` or more (`0` is `400`) |
| `limit` | integer | Number of responses to return (default 100, at most 1000; zero or below means the default). Asking for more than 1000 and getting a full page sets `result_truncated_by_cap` in the envelope |
| `offset` | integer | Offset for pagination (default 0) |

**Response envelope:**

```json
{
  "responses": [ ... ],
  "count": 42
}
```

When the caller asked for more than 1000 rows and the page came back full (exactly 1000 rows), the
envelope also carries `"result_truncated_by_cap": true`: more rows may exist past the ceiling. The
field is absent otherwise.

**Example --- fetch all responses for an instruction:**

```bash
curl -s -b cookies.txt \
  'http://localhost:8080/api/responses/instr-20240319-001' | jq .
```

**Example --- filter by agent and status:**

```bash
curl -s -b cookies.txt \
  'http://localhost:8080/api/responses/instr-20240319-001?agent_id=agent-007&status=0' | jq .
```

**Example --- paginate through large result sets:**

```bash
# Page 1 (first 100)
curl -s -b cookies.txt \
  'http://localhost:8080/api/responses/instr-20240319-001?limit=100&offset=0' | jq .

# Page 2 (next 100)
curl -s -b cookies.txt \
  'http://localhost:8080/api/responses/instr-20240319-001?limit=100&offset=100' | jq .
```

**Example --- find all failures:**

```bash
curl -s -b cookies.txt \
  'http://localhost:8080/api/responses/instr-20240319-001?status=1' | jq '.responses[] | {agent_id, error_detail}'
```

## Aggregation

### GET /api/responses/{instruction_id}/aggregate

The response store supports server-side aggregation so operators can compute
fleet-wide statistics without downloading every row.

**Query parameters:**

| Parameter | Type | Description |
|---|---|---|
| `group_by` | string | Column to group by (default: `status`). Common values: `status`, `agent_id` |
| `op` | string | Aggregation function: `count` (default), `sum`, `avg`, `min`, `max` |
| `op_column` | string | Column for sum/avg/min/max operations |
| `agent_id` | string | Filter by agent |
| `status` | integer | Filter by status |
| `since` | integer | Only responses at or after this Unix timestamp (inclusive); omit for no lower bound, `0` is accepted and matches the same rows |
| `until` | integer | Only responses at or before this Unix timestamp (inclusive); omit for no upper bound, must be `1` or more (`0` is `400`) |

**Response:**

```json
{
  "instruction_id": "instr-20240319-001",
  "groups": [
    { "group_value": "0", "count": 35, "aggregate_value": 0.0 },
    { "group_value": "1", "count": 7, "aggregate_value": 0.0 }
  ],
  "total_groups": 2,
  "total_rows": 42
}
```

### Supported functions

| Function | `op` value | Description |
|---|---|---|
| Count | `count` | Number of matching responses (default) |
| Sum | `sum` | Sum of a numeric column |
| Average | `avg` | Average of a numeric column |
| Minimum | `min` | Minimum value of a column |
| Maximum | `max` | Maximum value of a column |

### Drill-down

Operators can click an aggregate row in the dashboard to drill down into the
individual responses that compose it. The dashboard passes the group key as
filter parameters to the response query endpoint.

## Data export

### GET /api/responses/{instruction_id}/export

The dedicated export endpoint supports both CSV and JSON formats with the same
filter parameters as the query endpoint. It defaults to a higher limit
(10,000 rows) for bulk exports. Numeric parameters must be one whole base-10 integer
(`since=1e9`, `limit=100abc`, `status=0x1` and `since=1.5` are `400`, not a different
filter); omitting `since` or `until` means no bound on that side, `since=0` is accepted and matches the same rows as omitting it, and `until=0` or a negative
value is `400`.

**Query parameters:**

| Parameter | Type | Description |
|---|---|---|
| `format` | string | Export format: `csv` or `json` (default: `json`) |
| `agent_id` | string | Filter by agent |
| `status` | integer | Filter by status |
| `since` | integer | Only responses at or after this Unix timestamp (inclusive); omit for no lower bound, `0` is accepted and matches the same rows |
| `until` | integer | Only responses at or before this Unix timestamp (inclusive); omit for no upper bound, must be `1` or more (`0` is `400`) |
| `limit` | integer | Number of responses to export (default and maximum 10,000; zero or below serves one row) |

**Example --- export instruction responses as CSV:**

```bash
curl -s -b cookies.txt \
  'http://localhost:8080/api/responses/instr-20240319-001/export?format=csv' \
  -o responses.csv
```

**Example --- export as JSON:**

```bash
curl -s -b cookies.txt \
  'http://localhost:8080/api/responses/instr-20240319-001/export?format=json' \
  -o responses.json
```

The CSV format includes the columns:
`id`, `instruction_id`, `agent_id`, `timestamp`, `status`, `output`, `error_detail`.

**A bounded export can be cut.** Besides the row limit, an export stops once the rows served
carry 50 MiB of `output` plus `error_detail` (always on whole rows, and at least one row is
served; the last row kept can run past the cap by up to its own size: about 4 MiB for text output,
up to about 12 MiB for output dense in invalid bytes or NULs, because each field is cut to 2 MiB at
ingest before invalid bytes and NULs are replaced by the 3-byte U+FFFD; this includes the `error_detail` written when a terminal frame closes a running row). The cap is not
configurable. A cut export, whether by the row limit with more matching rows left, or by the byte
cap, is marked, so check for it before trusting a bulk pull: the JSON envelope has a top-level
`"result_truncated_by_cap": true`, and a CSV file ends with one extra trailer record,
`# result_truncated_by_cap cause=row_cap` (or `byte_cap`) padded with empty fields to the header's
width. The trailer is the signal that reaches every consumer. Agent output is arbitrary, so a
quoted cell can contain text that looks like the trailer: parse the file as CSV and read the final
record, do not regex-match lines. Two out-of-body signals accompany
it: a CSV response carries an `X-Result-Truncated-By-Cap: true` header, and the download is named
`responses-<instruction_id>-truncated.<json|csv>` instead of `responses-<instruction_id>.<json|csv>`.
A plain `curl -o responses.csv ...` keeps neither (curl picks the file name and drops the headers);
`curl -OJ` keeps the name, and `curl -sS -D - -o responses.csv ...` prints the headers. An uncut
export carries none of these. To read past a cap there is no cursor: pull once per `agent_id`, or
set `until` to the oldest `timestamp` received (inclusive, so rows tied at that second return
again: de-duplicate on `id`). In the JSON envelope, `count` is the number of rows served. The
REST v1 twin (`GET /api/v1/responses/{id}/export`) marks a cut the same way, with the JSON flag
under `pagination` and a 10-field CSV trailer.

### Generic JSON-to-CSV export

**POST /api/export/json-to-csv**

A generic endpoint that accepts any JSON array in the request body and returns
a CSV file. This can be used with data from any Yuzu API.

```bash
curl -s -b cookies.txt \
  'http://localhost:8080/api/v1/audit?limit=1000' \
  | jq -c '.data' \
  | curl -s -b cookies.txt \
      -X POST \
      -H 'Content-Type: application/json' \
      -d @- \
      'http://localhost:8080/api/export/json-to-csv' -o audit.csv
```

### Exportable data sources

The JSON-to-CSV endpoint accepts data from any Yuzu API. Common sources:

| Source | How to fetch |
|---|---|
| Instruction responses | `GET /api/responses/{instruction_id}` |
| Audit events | `GET /api/v1/audit` (use `.data` from the envelope) |
| Inventory data | Per-plugin structured blobs via the REST API |

## Analytics integration

### ClickHouse

Create a ClickHouse table matching the instruction's typed result schema, then
periodically load exported CSV or JSON files:

```sql
CREATE TABLE yuzu_disk_usage (
    agent_id    String,
    drive       String,
    total_gb    Int64,
    free_gb     Int64,
    collected   DateTime
) ENGINE = MergeTree()
ORDER BY (agent_id, collected);
```

```bash
# Export and load
curl -s -b cookies.txt \
  'http://localhost:8080/api/responses/disk-usage-001' \
  | curl -s -b cookies.txt \
      -X POST -H 'Content-Type: application/json' -d @- \
      'http://localhost:8080/api/export/json-to-csv' \
  | clickhouse-client --query "INSERT INTO yuzu_disk_usage FORMAT CSV"
```

### Splunk

Forward response data to Splunk via HEC:

```bash
curl -s -b cookies.txt \
  'http://localhost:8080/api/responses/instr-20240319-001' \
  | jq -c '.responses[]' \
  | while read -r row; do
      curl -s -X POST \
        -H "Authorization: Splunk YOUR-HEC-TOKEN" \
        -d "{\"sourcetype\": \"yuzu:response\", \"event\": ${row}}" \
        https://splunk.example.com:8088/services/collector/event
    done
```

## Storage substrate (PostgreSQL, ADR-0039)

Since the Postgres migration (ADR-0006/0039), responses live in the server's
PostgreSQL database (schema `response_store`), not a local `responses.db`. Three
operator-visible notes:

- **History reset on cutover.** The legacy SQLite `responses.db` is **not**
  migrated — response history is operational, TTL'd telemetry (skippable
  backfill, ADR-0009), so on the upgrade to the Postgres substrate the
  response history starts empty and refills as new commands run. The server
  logs a one-time `response history reset on Postgres cutover` warning at
  first boot. Executions-drawer and TAR views for commands issued before the
  cutover will be empty; commands issued after are unaffected.
- **Non-UTF-8 plugin output is sanitised.** A plugin can emit non-UTF-8 bytes
  in its output/error; PostgreSQL `TEXT` requires valid UTF-8, so such bytes
  are replaced with the Unicode replacement character (U+FFFD) at ingest. The
  response row is still stored and still renders (defanged) — it is not
  dropped or turned into a 500.
- **Facets are bounded.** Each response keeps the distinct (column, value) pairs of its output as
  facets, which drive the facet filter, group-from-results and the agent-count preview.
  - **Long values.** A value over 2048 bytes (measured on the value as stored, after invalid UTF-8
    and NUL bytes are rewritten) is left out of the response's facets. It is excluded, never
    truncated, because a prefix would be a different value than the one the agent reported. The
    response row, its output and every other facet still persist. Before this limit, one such value
    made the whole facet insert fail and the response lost ALL of its facets. The limit exists
    because the value is part of two database indexes, which refuse an entry over about 2.7 KB.
  - **Older rows.** Older servers indexed values that fit the database index limit (about 2.7 KB
    for an incompressible value, minus the instruction id length; a compressible value could be
    larger). Rows already stored by an older server stay readable until retention removes them.
    Values over 2048 bytes in newly ingested responses are not indexed, so the facet filter, the
    dropdowns and the group-from-results count show nothing or "0 agents" for such a value; this
    includes values between 2049 bytes and about 2.6 KB that older servers indexed. The results
    page shows a hint when a filter value is over 2048 bytes, the REST and MCP agent-count previews
    name such a filter in `unindexed_filter_keys`, and the create-group form and the group-from-results
    `422` say the count may be wrong.
  - **Cap.** At most 5,000 facets are kept per response, chosen by most lines first, then column
    index ascending, then value ascending, so the same output always keeps the same facets. A rare
    value (one line, such as a single package on one host) sorts late and is the first to be cut.
    The symptom is an agent missing from a facet filter or preview while its response still shows in
    the results. Before, which 5,000 survived was whichever the server held first, so a rare value
    could be cut and the choice was not repeatable.
  - **Lost facets are not recoverable.** A response whose facets were lost (`batch_failed`, or cut
    by `cap`) has no facets re-derived afterwards, and nothing marks such a response as affected
    (#5630). For `batch_failed` (a refused facet insert) run the command again and recreate any static
    group built from the affected response from the NEW run, because running the command again does
    not repair a group that already exists. For `cap` a re-run of the same output cuts the same
    facets, so use a command or filter that returns fewer distinct values. For `value_too_long`
    there is nothing to re-run. A `cap` or `batch_failed` response logs a warning naming its
    `response_id` ("facet count (N) exceeds the per-response cap" and "facet batch insert failed");
    a `value_too_long` exclusion logs only at debug level, so at the default level only the counter
    shows it.
  - **Counting.** Every facet that did not persist is counted in
    `yuzu_server_response_facets_dropped_total{reason}` (`value_too_long`, `cap`, `batch_failed`);
    see [metrics.md](metrics.md).
  - **Retention.** Facet rows are removed with their response by the existing reaper
    (`--response-retention-days`, default 90); there is no separate facet retention.

## Retention and cleanup

Responses are retained for 90 days by default. The server reaps responses
whose TTL has expired on a periodic guarded sweep (clock-guarded and capped,
so a skewed clock or a large backlog cannot mass-delete or stall — the same
retention-guard shape the audit log uses). Deletion is permanent.

To preserve data beyond the retention window, set up periodic exports using
cron or a scheduled task:

```bash
#!/bin/bash
# /etc/cron.daily/yuzu-response-export
DATE=$(date +%Y-%m-%d)
for INSTR_ID in $(curl -s -b /opt/yuzu/cookies.txt \
  'http://localhost:8080/api/v1/instructions' | jq -r '.[].id'); do
    curl -s -b /opt/yuzu/cookies.txt \
      "http://localhost:8080/api/responses/${INSTR_ID}" \
      > "/var/log/yuzu/responses-${INSTR_ID}-${DATE}.json"
done
```

## Planned features

| Feature | Roadmap | Description |
|---|---|---|
| Response templates | Planned | Pre-defined views with saved filters and column selections |
| Response offloading | Planned | Forward response data to external HTTP endpoints automatically |
