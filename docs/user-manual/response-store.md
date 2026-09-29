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
| `since` | integer | Only responses after this Unix timestamp |
| `until` | integer | Only responses before this Unix timestamp |
| `limit` | integer | Number of responses to return (default 100) |
| `offset` | integer | Offset for pagination (default 0) |

**Response envelope:**

```json
{
  "responses": [ ... ],
  "count": 42
}
```

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
| `since` | integer | Only responses after this Unix timestamp |
| `until` | integer | Only responses before this Unix timestamp |

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
(10,000 rows) for bulk exports.

**Query parameters:**

| Parameter | Type | Description |
|---|---|---|
| `format` | string | Export format: `csv` or `json` (default: `json`) |
| `agent_id` | string | Filter by agent |
| `status` | integer | Filter by status |
| `since` | integer | Only responses after this Unix timestamp |
| `until` | integer | Only responses before this Unix timestamp |
| `limit` | integer | Number of responses to export (default 10,000) |

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
PostgreSQL database (schema `response_store`), not a local `responses.db`. Two
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
