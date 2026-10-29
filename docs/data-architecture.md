# Data Architecture for Analytics Integration

The `architect` and `sre` agents load this document when designing schemas for new features. CLAUDE.md keeps a one-line pointer.

When building new features, design data schemas with downstream analytics in mind. The four data classes below are the integration surface; all other persistence is internal.

## Response data

- Every instruction definition declares a typed schema (column name + type).
- Permitted types: `bool`, `int32`, `int64`, `string`, `datetime`, `guid`, `clob`.
- Typed schemas make it trivial to materialize ClickHouse tables or Splunk sourcetypes from a `ProductPack`.
- Large text fields use `clob` with configurable truncation — never embed unbounded blobs in `string` columns.

## Audit events

- Envelope: `{timestamp, principal, action, target_type, target_id, result, detail}` — see `docs/observability-conventions.md` for the full schema.
- Forwardable to Splunk HEC or generic webhook sinks.
- Indexed by `timestamp` and `principal` for efficient queries.
- Denied operations MUST emit an audit event (SOC 2 CC7.2 evidence chain).

## Metrics

- Prometheus exposition format on `/metrics`.
- Labels: `agent_id`, `plugin`, `method`, `status`, `os`, `arch`.
- Grafana dashboard templates: `docs/grafana/`.
- ClickHouse ingest path: `prometheus_remote_write`, or scrape `/metrics` directly.

## Inventory data

- Per-plugin structured blobs stored server-side.
- Queryable via REST API with filter expressions.
- **Schema is self-describing** — the plugin reports its own schema at registration. Downstream tooling consumes the schema to materialize tables, not by hard-coding column lists.
- **Standard-format exports** (for example the CycloneDX CBOM at `GET /api/v1/crypto/cbom`) carry Yuzu-specific facts as document properties named `yuzu:<domain>:<snake_key>` (such as `yuzu:crypto:scope`), with string values, so a standard consumer ignores them safely and Yuzu-aware tooling can read them.
- **Fleet certificate inventory classification.** The certificate inventory store (`certificate_inventory_store`, ADR-0070 D12, slice-2 PR 2a-2a) holds machine-scope X.509 facts, but its subject DN and SAN fields (`cert_fact`, `cert_san`) are **potential personal data**: a machine certificate can carry a person's name, e-mail address or UPN. It is a typed source, never stored in the generic inventory store (`server/core/src/typed_inventory_sources.hpp`); never export these fields to analytics or metric labels. Access tier: nothing reads the store in 2a-2a; its read surface arrives in 2a-2b behind the dedicated, admin-floored `CertificateInventory` securable, never `Inventory:Read`. Retention: an agent's rows are erased by the agent-decommission cascade; from 2a-2d, stores unread for 30 days are pruned at store and location grain. The full classification is the SOC 2 data-inventory row "Fleet certificate inventory" in `docs/enterprise-readiness-soc2-first-customer.md`.

## Storage substrate

Server-side stores live on **PostgreSQL** as of 2026-06-09 (ADR-0006); the agent stays on
SQLite. New server stores default to Postgres, existing ones migrate incrementally behind
per-store ADRs. ClickHouse (below) remains the **analytics** sink, fed separately — it is not
the OLTP substrate. Schema designers: read `docs/adr/0006-server-postgresql-substrate.md`
(and ADR-0004, its first instance) before adding a server store.

## Cross-references

- `docs/adr/0006-server-postgresql-substrate.md` — server storage substrate (PostgreSQL)
- `docs/observability-conventions.md` — metric/label/audit envelope rules
- `docs/clickhouse-setup.md` — ClickHouse ingest pipeline
- `docs/analytics-events.md` — event taxonomy and downstream contracts
