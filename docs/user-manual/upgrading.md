# Upgrading Yuzu

This guide covers upgrading Yuzu components (server, agent, gateway) between versions.

## Version Compatibility

| Server Version | Min Agent Version | Min Gateway Version | Notes |
|---|---|---|---|
| 0.1.x | 0.1.0 | 0.1.0 | Initial release family |
| 0.5.x | 0.5.0 | 0.5.0 | Compiler hardening flags (`-fstack-protector-strong`, `_FORTIFY_SOURCE=2`, full RELRO), config file permission enforcement (`0600` on Unix), SRI integrity attributes on CDN scripts, configurable trigger limit (default 2000), git-derived version strings, chargen instruction definitions. |
| 0.6.x – 0.9.x | same as 0.5.x | same as 0.5.x | No on-disk format changes from 0.5.x; upgrade directly to 0.10.x. |
| 0.10.x | 0.10.0 | 0.10.0 | Server-side schema migration runner wired into every SQLite store. Upgrading from 0.9.x or earlier is data-preserving: the first 0.10.x startup stamps each database at schema v1 and runs a one-time legacy compatibility shim for stores that historically added columns via silent `ALTER TABLE` (`api_token_store`, `instruction_store`, `patch_manager`, `policy_store`, `product_pack_store`, `response_store`). Failed migrations close the affected store's DB handle and are reported via `/readyz` with the failed store name — **check `/readyz`, not `/livez`, to confirm upgrade success**. |
| 0.15.x (next) | 0.12.0 | 0.12.0 | **Fleet visualization three-tier layout + talking sockets + curved tube wires (PR 12).** `/viz/fleet` no longer renders machines on a single flat grid. Cubes now stack into three architectural tiers: frontend on the top Y plane, applications in the middle, databases on the bottom. Classification is heuristic — `classifyTier` reads listener-port hints (DB/web port sets) and process category, priority `db > web > app`. **Behavioural break for automation consumers:** if you scripted SIEM rules or dashboards that filter by "where a cube falls in the canvas", expect tier reassignments after upgrade. The wire change is *additive* — `schema_minor` bumps `3 → 4` with a new optional `local_addr` field on `ListenerSocket` carrying the kernel-reported bind address (server-side bounded at 64 bytes per field). Strict-validating consumers pinned to `schema_minor == 3` should relax their validator to `minimum: 3`. **Loopback-only listeners (`127.x`, `::1`, `[::1]`, `::ffff:127.x`) no longer appear on cube surfaces** — they're not reachable from other instances. **New talking-socket primitive:** each cube grows a ring of cool-blue dots on its BOTTOM face, one per unique outbound `(proto, dst_ip, dst_port)`; hover surfaces `talking: tcp → ip:port`. **Wire geometry changed:** cross-machine connections render as `THREE.TubeGeometry` along a `CubicBezierCurve3` with vertical end-tangents instead of 1px `THREE.Line` — wires drop straight down out of the source cube floor, run mostly-straight through space, and dock straight up into the destination's listener sphere. Screen-scrapers that parsed wire colour or geometry need updating. **Origin RGB `AxesHelper` removed** from the empty-scene scaffold — the three tier planes replace it as the orientation cue. **Default camera reframed** to `(45, 60, 45)` looking at the middle tier (was `(35, 30, 35)` looking at origin); bookmarked URLs will land on the new framing. Bundle size ~70 → ~84 KB. **Known limitation:** databases on non-standard ports (Postgres on 5431, etc.) misclassify as `app` tier unless their process is identified as `database` by the agent's process classifier. **Rolling-upgrade behaviour:** during a staged agent rollout, agents on a build older than the `tar.fleet_snapshot` action have no topology to push and appear in `/viz/fleet` as dimmed `stale` cubes until their agent is upgraded — this is expected, not a regression (previously such agents vanished from the visualization entirely once any agent pushed). **Kill-switch change:** `--viz-disable` now also `503`s the `/viz/fleet` and `/viz/host/<id>` page shells, not just the REST endpoints — an operator who sets the flag no longer sees a half-working page; it also writes a `server.viz_disabled` audit event at boot. **Governance Gate 7 hardening (no operator action required):** parser field caps on all agent-controlled strings, an IP-claim reclaim window so a crashed agent no longer strands its IPs forever, CAP-1 eviction keyed on the server clock, per-entry isolation in gateway `BatchHeartbeat` ingest, and a fix for a registration-replay storm under upstream flapping. **Scope-walking YAML `fromResultSet:` DSL (PR-E).** Policies whose `spec.scope:` used a `selector:` mapping block previously stored an empty scope (matched all devices — the selector was silently ignored). Existing rows are not migrated, but **re-creating or re-importing** such a policy after upgrade applies the selector as a real predicate and may narrow targeting — review the intended scope before re-import. Inline flow-mapping scope (`scope: {fromResultSet: x}`) is now rejected; use the block form. Result-set aliases referenced from `fromResultSet:` must be drawn from the `[A-Za-z0-9_.:*-]` charset (no spaces/quotes). **Inventory freshness gauge now server-clock-stamped (#1685).** `yuzu_inventory_stale_agents` keys on the server's receipt time, not the agent-supplied `collected_at`. A one-time migration (v3) at first 0.15.x startup clamps any `inventory_state` row whose `last_seen`/`first_seen` was stamped from a future-skewed agent clock back down to now. **Operator-visible:** if any agents had future-skewed clocks, the gauge may show a one-time *increase* post-upgrade as previously-hidden endpoints re-enter the staleness window with a fresh ~48h grace — genuinely active agents fall back out within two daily sync cycles; this is the intended security correction, not an incident. No operator action required (the `YuzuInventoryStaleAgents` alert ships disabled). **Rollback note:** downgrading the server below 0.15.x after v3 has run is data-safe (schema unchanged) but new inventory syncs revert to stamping `last_seen` from agent time, silently re-opening the clock-skew gap for those rows. **DEX application performance over time (opt-in).** New per-app, per-version CPU/working-set trend views (DEX → Performance → "Application performance over time"; REST `/api/v1/dex/perf/{apps,app,group}` + the `list_dex_perf_apps`/`get_dex_app_perf`/`get_dex_group_app_perf` MCP tools; per-device drill `GET /api/v1/dex/devices/{id}/app-perf`). **No action is required to upgrade, but the views are EMPTY until you opt in:** per-application sampling ships **off by default** (`procperf_enabled=false`) because it is usage-class telemetry (works-council-relevant). Enable `procperf_enabled=true` on the target devices via `tar.configure` (and leave the daily-sync master switch `--inventory-disable` unset). Data appears **after the first completed UTC midnight** on each opted-in device (the agent ships a daily summary, not immediately), and the trends lengthen as days accumulate (fleet ≤180 days, group ≤31 days). A freshly-enrolled or non-opted-in device shows an honest empty state ("no application performance history yet"), not a bug. The per-device drill is also reachable from a dashboard panel on the `/device` DEX lens ("Application performance over time" — same retained data, no live query, no `Execute` permission; no upgrade action needed). The per-device drill is behavioural PII — scoped + audited (`dex.device.app_perf.view`, fail-closed); the fleet and group aggregates suppress any app/version on fewer than 10 devices to a count only (no singling-out). **Response/execution reads fail closed on a corrupt RBAC store (#1634, partial).** The response readers (`query_responses` + `aggregate_responses` MCP tools, `GET /api/v1/executions/{id}/visualization`, `GET /api/responses/{id}` / `/aggregate` / `/export`) route through a per-agent management-group filter. **The only operator-visible change in this release** is fail-closed behavior under a **corrupt/load-failed `rbac.db`**: these surfaces now return zero rows (the legacy `/api/responses/{id}/aggregate` returns `503`) instead of exposing the whole fleet via the legacy read fallback. **Not yet changed:** under normal RBAC operation these reads are **not** management-group-scoped — a holder of global `Response:Read` still sees all agents' responses (the filter is inert under the current global gate; the gate change that makes scoping effective is tracked under #1634). RBAC explicitly disabled is unchanged. No operator action required. **MCP agentic write surface + A2 discovery + A4 error-shape (R2, #289 / #1794).** Five MCP write tools (`set_tag`/`delete_tag`/`approve_request`/`reject_request`/`quarantine_device`) ship with a ticket-then-recall approval flow, plus the `/api/v1/discover/*` discovery family. The approvals store gains additive `consumed_at` + `consumed_by` columns (auto-migrated at first startup; no operator action). **Breaking wire-shape change:** many `/api/v1` error bodies that were previously `{"error":"<string>"}` are now the nested A4 object `{"error":{"code","message","correlation_id",…}}` — a REST client that read `error` as a *string* must migrate to `error.code` / `error.message` (see `rest-api.md` §Error envelope). The MCP write surface is gated behind the existing tier model + a maker-checker approval workflow; audit `mcp.<tool>` covers every write. **NVD CVE-store schema migration (v1→v2) + full CPE version-range matching.** The server-side NVD store is reshaped on first startup (flat `cve` → normalized `cve` + `cve_match`); `/api/nvd/match` now evaluates real CPE version ranges. **Operator-visible on upgrade:** (a) the migration **drops and rebuilds the local CVE mirror** — vulnerability-matching coverage is reduced until the next NVD sync completes (rate-limited; up to a few hours without an API key), self-healing and logged with a warning at migration time; (b) `GET /api/nvd/status` `total_cves` now counts **distinct CVEs** (was one row per affected product) so it reads **lower** after upgrade even once fully synced, and near-zero during the rebuild window — **expected, not data loss**. Any SIEM/dashboard alerting on the `total_cves` magnitude should be re-baselined. No config change or action required. **NVD CVE sync now actually runs (was dormant).** A `rate_limit()` integer overflow meant the server-side NVD sync slept ~292 years before its first request, so it never populated on any prior deployment (`/api/nvd/status` `total_cves` stayed at the built-in seed). It now runs on startup. **Operator-visible:** (a) the server makes **new outbound HTTPS requests to `services.nvd.nist.gov`** — restricted-egress / air-gapped deployments that silently never reached it before may now log connection failures (set `--no-nvd-sync` to disable, or `--nvd-proxy`); (b) `total_cves` grows from the seed as the (keyword-scoped) sync populates. No config change required to benefit. **OIDC JWT signature verification now enforced on the Windows server (#1856/#1782, CRITICAL).** A Windows *server* build previously **skipped OIDC `id_token` signature verification entirely** — accepting forged RS256/384/512 tokens (session minting / account takeover). It now verifies on every platform via the same OpenSSL path. **Operator-visible only if you run a Windows server with OIDC SSO:** verification now genuinely depends on the IdP's JWKS being reachable, so a misconfigured or unreachable `jwks_uri` that the old Windows build *silently tolerated* (by accepting everything) will now cause **all OIDC logins to fail closed**. **Before upgrading a Windows + OIDC deployment**, confirm the server can reach the IdP `jwks_uri` and that system clock skew is within tolerance; if OIDC logins start failing fleet-wide post-upgrade, check JWKS reachability first. Local-password and API-token auth are unaffected; Linux/macOS servers already verified and are unchanged. **MCP `execute_instruction`'s zero-agents-reached response schema gained three new fields and a widened `status` enum (#3424/#3511).** The published `outputSchema`'s `oneOf` grew from 2 branches to 5: the success branch is unchanged, but the single `{status:"no_agents_reached", ...}` zero-reach branch is now four mutually-exclusive branches — `no_agents_reached` (same trigger condition, but now REQUIRES `retry_after_ms` where it was previously absent/unspecified), plus new `quarantined`, `containment_unreadable`, and `plugin_not_found` — each REQUIRING three new fields that were not previously present: `retry_after_ms` (a per-branch `const` — `5000` for the two retryable branches `containment_unreadable` and `no_agents_reached`, `null` for the two permanent branches `quarantined` and `plugin_not_found`), `agents_quarantined`, and `agents_unknown_plugin` (integer counts, present on every zero-reach branch regardless of which status matched). **Strict-validating consumers pinned to the old 2-branch `oneOf` or the old `no_agents_reached`-only zero-reach shape will reject a response using one of the three new statuses, or reject the new required fields on the shape they already recognized.** Relax any pinned `oneOf`/`const` validation to accept the widened schema (`GET /mcp/v1/` `tools/list` always reflects the current, authoritative shape) before upgrading an agentic client with strict response validation. A client that only branches on `status == "no_agents_reached"` string-equality (rather than treating an unrecognized status as "some non-retryable or retryable failure, check `message`") should add explicit handling for the three new values — see `docs/user-manual/mcp.md`'s `execute_instruction` row for the full semantics and retry guidance. **Alert-rule change (action may be required if you maintain a fork).** `YuzuDispatchTargetRejected`'s exclusion widens from `reason!="quarantined"` alone to `reason!~"quarantined\|unknown_plugin"` — same reasoning as the #881 exclusion above: a misconfigured automation retrying against an absent plugin is a caller mistake, not a fleet outage, and without the exclusion it clears the alert's `>3/15m` threshold on its own. If you maintain a fork of `docs/prometheus/yuzu-alerts.yml`, apply the same widened exclusion (`!~`, not `=~` — the fork's rule excludes both reasons, it does not match only them). |
| 0.15.x (next) | 0.12.0 | 0.12.0 | **Fleet visualization three-tier layout + talking sockets + curved tube wires (PR 12).** `/viz/fleet` no longer renders machines on a single flat grid. Cubes now stack into three architectural tiers: frontend on the top Y plane, applications in the middle, databases on the bottom. Classification is heuristic — `classifyTier` reads listener-port hints (DB/web port sets) and process category, priority `db > web > app`. **Behavioural break for automation consumers:** if you scripted SIEM rules or dashboards that filter by "where a cube falls in the canvas", expect tier reassignments after upgrade. The wire change is *additive* — `schema_minor` bumps `3 → 4` with a new optional `local_addr` field on `ListenerSocket` carrying the kernel-reported bind address (server-side bounded at 64 bytes per field). Strict-validating consumers pinned to `schema_minor == 3` should relax their validator to `minimum: 3`. **Loopback-only listeners (`127.x`, `::1`, `[::1]`, `::ffff:127.x`) no longer appear on cube surfaces** — they're not reachable from other instances. **New talking-socket primitive:** each cube grows a ring of cool-blue dots on its BOTTOM face, one per unique outbound `(proto, dst_ip, dst_port)`; hover surfaces `talking: tcp → ip:port`. **Wire geometry changed:** cross-machine connections render as `THREE.TubeGeometry` along a `CubicBezierCurve3` with vertical end-tangents instead of 1px `THREE.Line` — wires drop straight down out of the source cube floor, run mostly-straight through space, and dock straight up into the destination's listener sphere. Screen-scrapers that parsed wire colour or geometry need updating. **Origin RGB `AxesHelper` removed** from the empty-scene scaffold — the three tier planes replace it as the orientation cue. **Default camera reframed** to `(45, 60, 45)` looking at the middle tier (was `(35, 30, 35)` looking at origin); bookmarked URLs will land on the new framing. Bundle size ~70 → ~84 KB. **Known limitation:** databases on non-standard ports (Postgres on 5431, etc.) misclassify as `app` tier unless their process is identified as `database` by the agent's process classifier. **Rolling-upgrade behaviour:** during a staged agent rollout, agents on a build older than the `tar.fleet_snapshot` action have no topology to push and appear in `/viz/fleet` as dimmed `stale` cubes until their agent is upgraded — this is expected, not a regression (previously such agents vanished from the visualization entirely once any agent pushed). **Kill-switch change:** `--viz-disable` now also `503`s the `/viz/fleet` and `/viz/host/<id>` page shells, not just the REST endpoints — an operator who sets the flag no longer sees a half-working page; it also writes a `server.viz_disabled` audit event at boot. **Governance Gate 7 hardening (no operator action required):** parser field caps on all agent-controlled strings, an IP-claim reclaim window so a crashed agent no longer strands its IPs forever, CAP-1 eviction keyed on the server clock, per-entry isolation in gateway `BatchHeartbeat` ingest, and a fix for a registration-replay storm under upstream flapping. **Scope-walking YAML `fromResultSet:` DSL (PR-E).** Policies whose `spec.scope:` used a `selector:` mapping block previously stored an empty scope (matched all devices — the selector was silently ignored). Existing rows are not migrated, but **re-creating or re-importing** such a policy after upgrade applies the selector as a real predicate and may narrow targeting — review the intended scope before re-import. Inline flow-mapping scope (`scope: {fromResultSet: x}`) is now rejected; use the block form. Result-set aliases referenced from `fromResultSet:` must be drawn from the `[A-Za-z0-9_.:*-]` charset (no spaces/quotes). **Inventory freshness gauge now server-clock-stamped (#1685).** `yuzu_inventory_stale_agents` keys on the server's receipt time, not the agent-supplied `collected_at`. A one-time migration (v3) at first 0.15.x startup clamps any `inventory_state` row whose `last_seen`/`first_seen` was stamped from a future-skewed agent clock back down to now. **Operator-visible:** if any agents had future-skewed clocks, the gauge may show a one-time *increase* post-upgrade as previously-hidden endpoints re-enter the staleness window with a fresh ~48h grace — genuinely active agents fall back out within two daily sync cycles; this is the intended security correction, not an incident. No operator action required (the `YuzuInventoryStaleAgents` alert ships disabled). **Rollback note:** downgrading the server below 0.15.x after v3 has run is data-safe (schema unchanged) but new inventory syncs revert to stamping `last_seen` from agent time, silently re-opening the clock-skew gap for those rows. **DEX application performance over time (opt-in).** New per-app, per-version CPU/working-set trend views (DEX → Performance → "Application performance over time"; REST `/api/v1/dex/perf/{apps,app,group}` + the `list_dex_perf_apps`/`get_dex_app_perf`/`get_dex_group_app_perf` MCP tools; per-device drill `GET /api/v1/dex/devices/{id}/app-perf`). **No action is required to upgrade, but the views are EMPTY until you opt in:** per-application sampling ships **off by default** (`procperf_enabled=false`) because it is usage-class telemetry (works-council-relevant). Enable `procperf_enabled=true` on the target devices via `tar.configure` (and leave the daily-sync master switch `--inventory-disable` unset). Data appears **after the first completed UTC midnight** on each opted-in device (the agent ships a daily summary, not immediately), and the trends lengthen as days accumulate (fleet ≤180 days, group ≤31 days). A freshly-enrolled or non-opted-in device shows an honest empty state ("no application performance history yet"), not a bug. The per-device drill is also reachable from a dashboard panel on the `/device` DEX lens ("Application performance over time" — same retained data, no live query, no `Execute` permission; no upgrade action needed). The per-device drill is behavioural PII — scoped + audited (`dex.device.app_perf.view`, fail-closed); the fleet and group aggregates suppress any app/version on fewer than 10 devices to a count only (no singling-out). **Response/execution reads fail closed on a corrupt RBAC store (#1634, partial).** The response readers (`query_responses` + `aggregate_responses` MCP tools, `GET /api/v1/executions/{id}/visualization`, `GET /api/responses/{id}` / `/aggregate` / `/export`) route through a per-agent management-group filter. **The only operator-visible change in this release** is fail-closed behavior under a **corrupt/load-failed `rbac.db`**: these surfaces now return zero rows (the legacy `/api/responses/{id}/aggregate` returns `503`) instead of exposing the whole fleet via the legacy read fallback. **Not yet changed:** under normal RBAC operation these reads are **not** management-group-scoped — a holder of global `Response:Read` still sees all agents' responses (the filter is inert under the current global gate; the gate change that makes scoping effective is tracked under #1634). RBAC explicitly disabled is unchanged. No operator action required. **MCP agentic write surface + A2 discovery + A4 error-shape (R2, #289 / #1794).** Five MCP write tools (`set_tag`/`delete_tag`/`approve_request`/`reject_request`/`quarantine_device`) ship with a ticket-then-recall approval flow, plus the `/api/v1/discover/*` discovery family. The approvals store gains additive `consumed_at` + `consumed_by` columns (auto-migrated at first startup; no operator action). **Breaking wire-shape change:** many `/api/v1` error bodies that were previously `{"error":"<string>"}` are now the nested A4 object `{"error":{"code","message","correlation_id",…}}` — a REST client that read `error` as a *string* must migrate to `error.code` / `error.message` (see `rest-api.md` §Error envelope). The MCP write surface is gated behind the existing tier model + a maker-checker approval workflow; audit `mcp.<tool>` covers every write. **NVD CVE-store schema migration (v1→v2) + full CPE version-range matching.** The server-side NVD store is reshaped on first startup (flat `cve` → normalized `cve` + `cve_match`); `/api/nvd/match` now evaluates real CPE version ranges. **Operator-visible on upgrade:** (a) the migration **drops and rebuilds the local CVE mirror** — vulnerability-matching coverage is reduced until the next NVD sync completes (rate-limited; up to a few hours without an API key), self-healing and logged with a warning at migration time; (b) `GET /api/nvd/status` `total_cves` now counts **distinct CVEs** (was one row per affected product) so it reads **lower** after upgrade even once fully synced, and near-zero during the rebuild window — **expected, not data loss**. Any SIEM/dashboard alerting on the `total_cves` magnitude should be re-baselined. No config change or action required. **NVD CVE sync now actually runs (was dormant).** A `rate_limit()` integer overflow meant the server-side NVD sync slept ~292 years before its first request, so it never populated on any prior deployment (`/api/nvd/status` `total_cves` stayed at the built-in seed). It now runs on startup. **Operator-visible:** (a) the server makes **new outbound HTTPS requests to `services.nvd.nist.gov`** — restricted-egress / air-gapped deployments that silently never reached it before may now log connection failures (set `--no-nvd-sync` to disable, or `--nvd-proxy`); (b) `total_cves` grows from the seed as the sync populates. No config change required to benefit. **NVD sync now builds the FULL CVE catalog (newest-first), not ~20 keywords.** The sync backfills every CVE published within a configurable window — `--nvd-backfill-years` / `YUZU_NVD_BACKFILL_YEARS` (default **8 years**; `0` = full history) — newest-first and **resumable across restarts**, then settles into a periodic last-modified freshness re-check. **Operator-visible:** the server makes sustained HTTPS requests to `services.nvd.nist.gov`, the local NVD DB grows into the hundreds of MB, and `/api/nvd/status` `total_cves` climbs continuously while `backfill_complete` stays `false` until the backfill floor is first reached — `last_sync_time` advances after every successful fetch window and is **not** a completion signal (use the new `backfill_complete` + `backfill_oldest_published` fields, and the `yuzu_nvd_total_cves` / `yuzu_nvd_backfill_complete` metrics, for progress). **`/api/nvd/status` `enabled` semantics corrected:** it now reflects whether sync is configured on, so under `--no-nvd-sync` it reports `enabled:false` (was `true`); a monitor keying on `enabled` to mean "mirror usable" should check `total_cves` instead. The initial backfill is NVD-rate-limited (hours without an `--nvd-api-key`, minutes with one) and resumes where it left off if interrupted. Set `--no-nvd-sync` to disable, `--nvd-proxy` for restricted egress. Product matching stays name-based (vendor-precise CPE identity pending ADR-0018). **Certificate inventory now reads System/SystemRoot keychains and Linux `/etc/ssl/certs` natively (no more `openssl`/`security` CLI shell-out for those stores).** The `certificates` plugin's `list`/`details`/`delete` actions are unchanged in output shape (same pipe-delimited columns, same field values) — this is a collection-mechanism change only, verified byte-parity against the prior CLI-based output. The macOS login keychain read has ALSO moved off its governed-shell path in this same release (#3406): it now runs as a pre-split argv through the bounded runner, with the console user's home directory resolved in-process instead of by the shell. Output shape is unchanged. **One operator-visible correction:** when the console user cannot be determined — most often a slow or unreachable directory service on a domain-joined Mac — `certificates.list`/`details` with `store=login` or `all` now return an explicit `not_available|<reason>` row and mark the result PARTIAL. Previously that case silently dropped the login keychain and the list read as complete, and `details` could answer a confident `not_found` for a certificate it had never looked for. Expect to SEE partial results where output previously looked clean on such hosts; that is the bug being fixed, not a regression. No operator action required; mixed old/new-agent fleets and rollback are safe (no server-side or schema change). |
| 0.15.x (next) | 0.12.0 | 0.12.0 | **Fleet visualization three-tier layout + talking sockets + curved tube wires (PR 12).** `/viz/fleet` no longer renders machines on a single flat grid. Cubes now stack into three architectural tiers: frontend on the top Y plane, applications in the middle, databases on the bottom. Classification is heuristic — `classifyTier` reads listener-port hints (DB/web port sets) and process category, priority `db > web > app`. **Behavioural break for automation consumers:** if you scripted SIEM rules or dashboards that filter by "where a cube falls in the canvas", expect tier reassignments after upgrade. The wire change is *additive* — `schema_minor` bumps `3 → 4` with a new optional `local_addr` field on `ListenerSocket` carrying the kernel-reported bind address (server-side bounded at 64 bytes per field). Strict-validating consumers pinned to `schema_minor == 3` should relax their validator to `minimum: 3`. **Loopback-only listeners (`127.x`, `::1`, `[::1]`, `::ffff:127.x`) no longer appear on cube surfaces** — they're not reachable from other instances. **New talking-socket primitive:** each cube grows a ring of cool-blue dots on its BOTTOM face, one per unique outbound `(proto, dst_ip, dst_port)`; hover surfaces `talking: tcp → ip:port`. **Wire geometry changed:** cross-machine connections render as `THREE.TubeGeometry` along a `CubicBezierCurve3` with vertical end-tangents instead of 1px `THREE.Line` — wires drop straight down out of the source cube floor, run mostly-straight through space, and dock straight up into the destination's listener sphere. Screen-scrapers that parsed wire colour or geometry need updating. **Origin RGB `AxesHelper` removed** from the empty-scene scaffold — the three tier planes replace it as the orientation cue. **Default camera reframed** to `(45, 60, 45)` looking at the middle tier (was `(35, 30, 35)` looking at origin); bookmarked URLs will land on the new framing. Bundle size ~70 → ~84 KB. **Known limitation:** databases on non-standard ports (Postgres on 5431, etc.) misclassify as `app` tier unless their process is identified as `database` by the agent's process classifier. **Rolling-upgrade behaviour:** during a staged agent rollout, agents on a build older than the `tar.fleet_snapshot` action have no topology to push and appear in `/viz/fleet` as dimmed `stale` cubes until their agent is upgraded — this is expected, not a regression (previously such agents vanished from the visualization entirely once any agent pushed). **Kill-switch change:** `--viz-disable` now also `503`s the `/viz/fleet` and `/viz/host/<id>` page shells, not just the REST endpoints — an operator who sets the flag no longer sees a half-working page; it also writes a `server.viz_disabled` audit event at boot. **Governance Gate 7 hardening (no operator action required):** parser field caps on all agent-controlled strings, an IP-claim reclaim window so a crashed agent no longer strands its IPs forever, CAP-1 eviction keyed on the server clock, per-entry isolation in gateway `BatchHeartbeat` ingest, and a fix for a registration-replay storm under upstream flapping. **Scope-walking YAML `fromResultSet:` DSL (PR-E).** Policies whose `spec.scope:` used a `selector:` mapping block previously stored an empty scope (matched all devices — the selector was silently ignored). Existing rows are not migrated, but **re-creating or re-importing** such a policy after upgrade applies the selector as a real predicate and may narrow targeting — review the intended scope before re-import. Inline flow-mapping scope (`scope: {fromResultSet: x}`) is now rejected; use the block form. Result-set aliases referenced from `fromResultSet:` must be drawn from the `[A-Za-z0-9_.:*-]` charset (no spaces/quotes). **Inventory freshness gauge now server-clock-stamped (#1685).** `yuzu_inventory_stale_agents` keys on the server's receipt time, not the agent-supplied `collected_at`. A one-time migration (v3) at first 0.15.x startup clamps any `inventory_state` row whose `last_seen`/`first_seen` was stamped from a future-skewed agent clock back down to now. **Operator-visible:** if any agents had future-skewed clocks, the gauge may show a one-time *increase* post-upgrade as previously-hidden endpoints re-enter the staleness window with a fresh ~48h grace — genuinely active agents fall back out within two daily sync cycles; this is the intended security correction, not an incident. No operator action required (the `YuzuInventoryStaleAgents` alert ships disabled). **Rollback note:** downgrading the server below 0.15.x after v3 has run is data-safe (schema unchanged) but new inventory syncs revert to stamping `last_seen` from agent time, silently re-opening the clock-skew gap for those rows. **DEX application performance over time (opt-in).** New per-app, per-version CPU/working-set trend views (DEX → Performance → "Application performance over time"; REST `/api/v1/dex/perf/{apps,app,group}` + the `list_dex_perf_apps`/`get_dex_app_perf`/`get_dex_group_app_perf` MCP tools; per-device drill `GET /api/v1/dex/devices/{id}/app-perf`). **No action is required to upgrade, but the views are EMPTY until you opt in:** per-application sampling ships **off by default** (`procperf_enabled=false`) because it is usage-class telemetry (works-council-relevant). Enable `procperf_enabled=true` on the target devices via `tar.configure` (and leave the daily-sync master switch `--inventory-disable` unset). Data appears **after the first completed UTC midnight** on each opted-in device (the agent ships a daily summary, not immediately), and the trends lengthen as days accumulate (fleet ≤180 days, group ≤31 days). A freshly-enrolled or non-opted-in device shows an honest empty state ("no application performance history yet"), not a bug. The per-device drill is also reachable from a dashboard panel on the `/device` DEX lens ("Application performance over time" — same retained data, no live query, no `Execute` permission; no upgrade action needed). The per-device drill is behavioural PII — scoped + audited (`dex.device.app_perf.view`, fail-closed); the fleet and group aggregates suppress any app/version on fewer than 10 devices to a count only (no singling-out). **Response/execution reads fail closed on a corrupt RBAC store (#1634, partial).** The response readers (`query_responses` + `aggregate_responses` MCP tools, `GET /api/v1/executions/{id}/visualization`, `GET /api/responses/{id}` / `/aggregate` / `/export`) route through a per-agent management-group filter. **The only operator-visible change in this release** is fail-closed behavior under a **corrupt/load-failed `rbac.db`**: these surfaces now return zero rows (the legacy `/api/responses/{id}/aggregate` returns `503`) instead of exposing the whole fleet via the legacy read fallback. **Not yet changed:** under normal RBAC operation these reads are **not** management-group-scoped — a holder of global `Response:Read` still sees all agents' responses (the filter is inert under the current global gate; the gate change that makes scoping effective is tracked under #1634). RBAC explicitly disabled is unchanged. No operator action required. **MCP agentic write surface + A2 discovery + A4 error-shape (R2, #289 / #1794).** Five MCP write tools (`set_tag`/`delete_tag`/`approve_request`/`reject_request`/`quarantine_device`) ship with a ticket-then-recall approval flow, plus the `/api/v1/discover/*` discovery family. The approvals store gains additive `consumed_at` + `consumed_by` columns (auto-migrated at first startup; no operator action). **Breaking wire-shape change:** many `/api/v1` error bodies that were previously `{"error":"<string>"}` are now the nested A4 object `{"error":{"code","message","correlation_id",…}}` — a REST client that read `error` as a *string* must migrate to `error.code` / `error.message` (see `rest-api.md` §Error envelope). The MCP write surface is gated behind the existing tier model + a maker-checker approval workflow; audit `mcp.<tool>` covers every write. **NVD CVE-store schema migration (v1→v2) + full CPE version-range matching.** The server-side NVD store is reshaped on first startup (flat `cve` → normalized `cve` + `cve_match`); `/api/nvd/match` now evaluates real CPE version ranges. **Operator-visible on upgrade:** (a) the migration **drops and rebuilds the local CVE mirror** — vulnerability-matching coverage is reduced until the next NVD sync completes (rate-limited; up to a few hours without an API key), self-healing and logged with a warning at migration time; (b) `GET /api/nvd/status` `total_cves` now counts **distinct CVEs** (was one row per affected product) so it reads **lower** after upgrade even once fully synced, and near-zero during the rebuild window — **expected, not data loss**. Any SIEM/dashboard alerting on the `total_cves` magnitude should be re-baselined. No config change or action required. **NVD CVE sync now actually runs (was dormant).** A `rate_limit()` integer overflow meant the server-side NVD sync slept ~292 years before its first request, so it never populated on any prior deployment (`/api/nvd/status` `total_cves` stayed at the built-in seed). It now runs on startup. **Operator-visible:** (a) the server makes **new outbound HTTPS requests to `services.nvd.nist.gov`** — restricted-egress / air-gapped deployments that silently never reached it before may now log connection failures (set `--no-nvd-sync` to disable, or `--nvd-proxy`); (b) `total_cves` grows from the seed as the sync populates. No config change required to benefit. **NVD sync now builds the FULL CVE catalog (newest-first), not ~20 keywords.** The sync backfills every CVE published within a configurable window — `--nvd-backfill-years` / `YUZU_NVD_BACKFILL_YEARS` (default **8 years**; `0` = full history) — newest-first and **resumable across restarts**, then settles into a periodic last-modified freshness re-check. **Operator-visible:** the server makes sustained HTTPS requests to `services.nvd.nist.gov`, the local NVD DB grows into the hundreds of MB, and `/api/nvd/status` `total_cves` climbs continuously while `backfill_complete` stays `false` until the backfill floor is first reached — `last_sync_time` advances after every successful fetch window and is **not** a completion signal (use the new `backfill_complete` + `backfill_oldest_published` fields, and the `yuzu_nvd_total_cves` / `yuzu_nvd_backfill_complete` metrics, for progress). **`/api/nvd/status` `enabled` semantics corrected:** it now reflects whether sync is configured on, so under `--no-nvd-sync` it reports `enabled:false` (was `true`); a monitor keying on `enabled` to mean "mirror usable" should check `total_cves` instead. The initial backfill is NVD-rate-limited (hours without an `--nvd-api-key`, minutes with one) and resumes where it left off if interrupted. Set `--no-nvd-sync` to disable, `--nvd-proxy` for restricted egress. Product matching stays name-based (vendor-precise CPE identity pending ADR-0018). **Certificate inventory now reads System/SystemRoot keychains and Linux `/etc/ssl/certs` natively (no more `openssl`/`security` CLI shell-out for those stores).** The `certificates` plugin's `list`/`details`/`delete` actions are unchanged in output shape (same pipe-delimited columns, same field values) — this is a collection-mechanism change only, verified byte-parity against the prior CLI-based output. The macOS login keychain is unchanged (still reads via the existing governed-shell path, a deliberate exception — see `docs/agent-spawn-sink-manifest.md`). No operator action required; mixed old/new-agent fleets and rollback are safe (no server-side or schema change). |
| 0.15.x (next) | 0.12.0 | 0.12.0 | **`PatchManager` now runs on PostgreSQL (ADR-0062).** `/api/patches/*` (patch inventory + deployment tracking) moved off its own `patches.db` SQLite file onto the shared Postgres substrate (schema `patch_manager`). **No data carries over from a pre-Postgres install** (fresh-start-by-default, ADR-0009) — any deployment record that existed before upgrade is gone and must be re-created via `POST /api/patches/deploy`. Server startup now fails closed if the `patch_manager` schema can't be created/opened — a posture upgrade from the SQLite era, where construction was unconditional/best-effort and no caller ever checked whether the store had actually opened; confirm success via `/readyz` (`patch_manager` is now reported by both `/readyz` and `/healthz`, absent from both before this release). **Removed: automatic patch-deployment orchestration.** `PatchManager::execute_deployment()` (the scan → install → verify → reboot workflow) had zero production callers on any released build — nothing ever wired a dispatch/OS-lookup callback to it — and is deleted, not ported; `POST /api/patches/deploy` still creates a deployment + per-target rows, but nothing in the server drives them through that workflow automatically (see #3669, filed alongside this change, and `docs/capability-map.md` §8.3/§8.4/§8.6). **Patch inventory (`GET /api/patches`) is separately unwired**: `record_patches()`, the only method that writes it, also has no production caller — this predates the migration and is not something upgrading changes — so `GET /api/patches` returns empty in every real deployment today; see `docs/capability-map.md` §8.5/§8.7 and #3676. No operator action required beyond re-creating any in-flight deployment after upgrade. |
| 0.15.x (next) | 0.12.0 | 0.12.0 | **`WorkflowEngine` now runs on PostgreSQL (ADR-0064).** `/api/workflows*` and `/api/workflow-executions/*` moved off `workflows.db` SQLite onto the shared Postgres substrate (schema `workflow_engine`). **No data carries over from a pre-Postgres install** (fresh-start-by-default, ADR-0009) — any workflow definition and its execution history that existed before upgrade is gone; re-create workflows via `POST /api/workflows` (or product-pack re-install). Server startup now fails closed if the `workflow_engine` schema can't be created/opened — a posture upgrade from the SQLite era, where construction was unconditional/best-effort and no caller ever checked whether the store had actually opened; confirm success via `/readyz` (already reported before this release) and `/healthz` (newly reported — was absent before this release). **Delete semantics changed: `DELETE /api/workflows/:id` now soft-deletes.** The response shape is unchanged (`{"deleted": true|false}`), but a deleted workflow's row and its execution history are now retained internally rather than orphaned — this is not operator-visible today (no "show deleted workflows" surface exists), but a deleted workflow's `id` can never be reused. No operator action required. |
| 0.15.x (next) | 0.12.0 | 0.12.0 | **Guardian file-hash `max_bytes` now has a hard ceiling (#2233).** An authored `file-hash-equals` rule's `max_bytes` (the hashing-DoS cap) was previously accepted unbounded from the authoring API. It is now clamped to 1 GiB (`kMaxFileHashBytes`) on the agent, and the server rejects a new/edited rule authoring a value above that ceiling in either JSON wire form (400). **Operator-visible only if you have a PRE-EXISTING `file-hash-equals` rule authored (before this release) with `max_bytes` above 1 GiB, watching a file at or above that size:** after upgrade, that file reports `<oversize>` instead of being hashed — a compliance-verdict change with no authoring-time signal (the rule already exists, so the new server-side reject cannot retroactively catch it). List your rules via `GET /api/v1/guaranteed-state/rules` (the route returns every rule; there is no server-side filter), check any `file-hash-equals` rule for `max_bytes` over 1073741824, and re-author within the ceiling if the larger cap was intentional. No operator action required otherwise. **DEX and management-group reads now fail closed on a degraded read instead of answering a healthy/empty result (#4855, #1762)** — see "Behaviour change: DEX device score and management-group member reads now fail closed on a degraded read (#4855, #1762)" below. |
| 0.14.x | 0.12.0 | 0.12.0 | **Fleet visualization intra-cube edges (PR 8).** `/viz/fleet` now draws faint white lines (opacity `0.3`) inside each machine cube connecting process dots that are reciprocal ends of a loopback TCP socket (127.0.0.1 / ::1). Two operator-visible changes: (a) **wire shape** — `/api/v1/viz/fleet/topology` `schema_minor` bumps `1 → 2` and a new optional `dst_pid` field appears on `scope: local` connection edges. Renderers that ignore unknown keys per the contract see no break; strict-validating consumers pinned to `schema_minor == 1` should relax their validator to `minimum: 1`. (b) **dropped unmatched halves** — unpaired Local-scope edges (kernel snapshot race during teardown, agent's 4096-connection cap cutting a partner) are now dropped server-side before serialisation. Integrations counting `connections` array length per machine as a proxy for active IPC pairs should re-baseline after upgrade; the count trends marginally lower. Lines appear only when the host has active loopback flows (e.g. Prometheus scraping node_exporter, a client talking to local Redis / Postgres); a fresh agent with no inter-process loopback shows process dots but no lines — expected, not a regression. |
| 0.13.x | 0.12.0 | 0.12.0 | **Fleet visualization process layer.** `/viz/fleet` now renders interior process dots inside each machine cube, coloured by category (system/browser/database/web/runtime/other) — no operator action required, but operators upgrading from a 0.12.x build will see the dashboard suddenly populated with thousands of small spheres on next page load. Process data was already collected via `tar.fleet_snapshot` since 0.12.x; PR 7 only renders it. To suppress process visibility for specific agents (privacy-sensitive hosts, regulated workloads), set `process_enabled=false` on those agents via `tar.configure` — this also suppresses their dots on the visualization. Hover a dot to see pid/name/user/category; agent-controlled string fields are HTML-escaped and length-clamped before render. Per-cube dot count is soft-capped at 1000 for graceful degradation on heavily-threaded hosts; the cube tooltip still shows the true reported count. |
| 0.12.x | 0.12.0 | 0.12.0 | **Build-time content auto-import.** All YAML files in `content/definitions/` (217 InstructionDefinitions) and `content/packs/` (10 InstructionSets at this version) are now embedded in the server binary and auto-imported on every startup. Existing operator-customised definitions with matching IDs are NEVER overwritten — conflicts are silently skipped. **Behaviour change for upgrades:** definitions that an operator previously DELETED via the REST API or dashboard will reappear after upgrade because the auto-import treats a missing row as "needs creation". To permanently suppress a shipped definition, set `enabled: false` via the dashboard or `PATCH /api/v1/definitions/{id}` rather than DELETE-ing the row. Each auto-import write emits an `audit_events.action="content.bundled_import"` row with `principal=system` so operators can audit which definitions were inserted at boot. **Yuzu dark navy palette + Inter webfont** (visual change every operator sees) and **Apache ECharts chart renderer** (replaces bespoke SVG; same payload contract — no operator migration required) ship in the same release. |

**Rule of thumb:** agents and gateway should be the same minor version as the server, or one minor version behind. The server is always upgraded first.

## Behaviour change: DEX device score and management-group member reads now fail closed on a degraded read (#4855, #1762)

**Not a Breaking lead for the DEX routes and the management-group MEMBER-read path** — those already documented a `503` response before this release; what changes for them is when it fires, not the documented contract. **This does NOT hold for `GET /api/v1/management-groups/{id}`'s own GROUP-ROW read or its MCP twin `get_management_group`** (governance round-2, #1762): before this release, a degraded group-row read answered the SAME flat, undocumented `404 "group not found"` a genuinely nonexistent group id gets — there was no `503` contract for that case at all. This release adds a NEWLY DOCUMENTED, additive `503`/retryable error path for a degraded group-row read specifically; the `404` contract for a genuine not-found is unchanged. A client that already treats any `503` from these routes as retryable per the A4 contract needs no code change; a client that inferred "management group not found" purely from a `404` status code should note that `404` now unambiguously means "no such group" (never "could not tell") — narrower, not wider, than before.

**Operator-visible behaviour change (fail-closed reads).** Two previously fail-soft read paths now surface a degraded Postgres read as a retryable error instead of a healthy-looking or empty result:

- **Per-device DEX experience score (#4855).** `GET /api/v1/dex/devices/{id}` and MCP `get_dex_device_score` now answer `503`/a retryable MCP error when the per-device signal-summary read degrades, instead of the previous fabricated healthy score of 100 with no signals. The device-page DEX lens shows a "DEX store degraded." placeholder in the same case. `GET /api/v1/dex/overview` (and its dashboard/MCP twins) gains a new `unscored` field counting connected devices whose per-device score could not be computed — a non-zero `unscored` means `great`/`fair`/`poor`/`overall_experience` cover fewer devices than are actually connected, not a healthier fleet than reported.
- **Management-group reads (#1762).** The `/dex/perf/app` group-trend read (`GET /api/v1/dex/perf/group` and its dashboard/MCP twins), `/auto` VERIFY's before/after compare, and `GET /api/v1/management-groups/{id}` (+ MCP `get_management_group`) now report a member-lookup degrade as `503`/a retryable error, instead of rendering it as "0 members" or "no member reported". As of governance round-2, `GET /api/v1/management-groups/{id}` and `get_management_group` ALSO report a degrade in the GROUP ROW's own read the same way (`503`/retryable), instead of the flat `404` that previously made a store outage indistinguishable from a genuinely nonexistent group.

**Counters/alerts to watch during and after upgrade:** `yuzu_server_guardian_read_degrade_total` (alert `YuzuGuardianReadDegraded`; this release adds a new `source="guardian_rules"` value alongside the pre-existing `source="guardian_state"`, both now pre-seeded to 0 at boot across all three `reason` values) and `yuzu_server_mgmt_group_read_degrade_total` (alert `YuzuMgmtGroupReadDegraded`, now also counting the `get_members_checked` member-read degrade). A sustained non-zero rate on either during the upgrade window means the affected reads are answering retryable errors, not that devices or groups actually shrank.

No config or data migration is required.

## ⚠️ Breaking: `GET /api/v1/openapi.json` now requires authentication (#2057)

The OpenAPI spec endpoint used to be public — any unauthenticated client could
fetch it to learn the REST surface. It now gates `Infrastructure:Read`, the
same permission the MCP `yuzu://openapi` resource twin already required, so
the two surfaces agree.

**Breaking for pre-auth tooling.** A script, health-checker, or API-client
codegen step that fetched the spec before logging in now gets `401` instead
of the document:

```json
{"error":{"code":401,"message":"unauthorized"},"meta":{"api_version":"v1"}}
```

**What to do.** Fetch the spec with a session cookie or an API token, same as
any other `/api/v1/*` route:

```bash
# Session cookie (dashboard-style login)
curl -c cookies.txt -X POST http://localhost:8080/login \
    -d "username=admin&password=<password>"
curl -b cookies.txt http://localhost:8080/api/v1/openapi.json

# API token
curl -H "Authorization: Bearer <api-token>" \
    http://localhost:8080/api/v1/openapi.json
```

## Agent OTA pulls are now bounded per peer (#913, #911) — behaviour change

`DownloadUpdate` is now admitted through a per-peer gate. A refused pull returns
gRPC `RESOURCE_EXHAUSTED`; a transfer exceeding `--ota-transfer-deadline-secs`
(default 900) or `--ota-chunk-write-deadline-secs` (default 30) returns
`DEADLINE_EXCEEDED`. Agents retry on their normal update interval, so no update is
lost — but the first fleet-wide update after upgrading can take substantially
longer than before, and on one deployment shape it can take days.

**Check this before your first post-upgrade fleet update.** Admission keys on the
peer's certificate identity, falling back to **source IP** where no client
certificate is presented. Every certless agent behind one NAT egress therefore
shares **one** bucket: 2 concurrent transfers and a sustained 1 admission per
minute for the entire site, after an initial burst of 20.

| Certless devices behind one egress | Time for a fleet-wide update |
|---|---|
| 20 | minutes (absorbed by the burst) |
| 500 | ~8 hours |
| 5,000 | ~3.5 days |

**What to do.** Run `yuzu_ota_admission_key_mode_total` and look at the
`mode="peer_ip"` share. If it is material:

- **Preferred:** enrol those agents with client certificates. Each then gets its
  own bucket and the problem disappears.
- **Otherwise:** raise `--ota-rate-refill-per-min` and `--ota-max-concurrent-per-peer`
  for the rollout window, and raise `--ota-max-concurrent-total` (default 64) if you
  raise the per-peer values across a large fleet.

Watch `yuzu_ota_download_admission_total{decision="rejected_rate"}` during the
rollout, and see the "Agent OTA pull bounds" runbook in `server-admin.md`.

Also new, and **check this one before you upgrade a large fleet**:
`--grpc-max-threads` (default 8192) now caps the gRPC sync server's thread pool.
Previously nothing did. It is a fleet-size ceiling rather than a tuning dial —
`AgentService` is synchronous and `Subscribe` holds one thread for the life of
each connected agent's command stream, so the value must exceed your
concurrently-connected agent count. Below it, gRPC answers `RESOURCE_EXHAUSTED`
to every RPC on every service sharing the quota, which is a fleet-wide outage
rather than back-pressure. 8192 covers the fleets this release targets; if you
run more than ~5,000 concurrent agents, raise it (`expected_agents x 1.5`)
in the same change as the upgrade.

`--ota-cert-reserve-pct` (default 50) reserves half of `--ota-max-concurrent-total`
for peers admitted on a certificate identity. If your fleet is largely
unenrolled — no client certificates, so admission keys on source IP — the
remaining half is the whole capacity those agents can use, and you may want to
lower the reserve or raise the total for the rollout window.

## ⚠️ Security: rotate `oidc_client_secret` if it was ever set on this install

**Every release up to and including v0.13.0** emitted the OIDC client secret in the clear to three
places, and this upgrade closes all three:

- the **server log**, written verbatim by the startup override pass on **every boot**;
- `GET /api/config`, a route gated only on `Infrastructure:Read`;
- the `config.update` **audit detail** written by `PUT /api/config/:key`, which is durably retained and
  readable by every role seeded `AuditLog:Read` - the seeded `Operator` role among them.

**Breaking for automation:** closing the second path changed a response shape.
`GET /api/config` now reports `"is_set": true|false` for a secret-valued key instead of `value`, so a
client reading `value` for `oidc_client_secret` gets nothing where it previously got the credential.
Full shape and the reason it is not a placeholder:
[`rest-api.md`](rest-api.md#get-apiconfig).

Because the log path fired on every boot, **historical logs** — and anything that ingested them, such
as journald, a Docker log driver, or a SIEM — may still hold the secret in plaintext. Purge or restrict
those as your retention policy allows.

Audit rows written before the upgrade are now redacted when read, so the value stops being disclosed
through that path too. The rows themselves are deliberately left intact: an audit row is compliance
evidence, and rewriting history to conceal a mistake is a worse posture than declining to disclose it.
**So the plaintext remains at rest** in those rows, and a direct database read or a restored backup
still shows it. Do not assume a fixed expiry: `audit_retention_days` defaults to 365, but each prune
pass is capped, and the retention guard deliberately declines a pass after a clock anomaly or a long
outage, so rows can outlive the nominal figure. The secret also remains stored in plaintext
in runtime-config; this fix closes disclosure paths and does not encrypt it at rest (see
`security-hardening.md`, "Current encryption posture").

**Who this affects:** any install where `oidc_client_secret` was ever set through **Settings -> OIDC**
or `PUT /api/config/oidc_client_secret` on an affected release. All three paths above read from
runtime-config, so a secret supplied **only** via `--oidc-client-secret` or `YUZU_OIDC_CLIENT_SECRET`,
and never written through Settings or the API, was not disclosed by *those three paths*.

**That is not the same as "not disclosed".** A secret passed as `--oidc-client-secret` sits in the
process command line, world-readable through `ps` or `/proc/<pid>/cmdline`, and it is typically also in
a systemd unit, a Compose file, or shell history. If you cannot rule those out, rotate anyway.
`YUZU_OIDC_CLIENT_SECRET` is better against other local users — `/proc/<pid>/environ` is owner-only,
unlike `cmdline` — but it is *not* better if the value is written into a Compose file or unit, since
`docker inspect` exposes it to anyone in the `docker` group. Prefer a secrets manager that injects the
environment variable at runtime.

**Before you begin, check you have a local account you can sign in with** — and on
`--auth-mode=sso-only`, that it is the configured break-glass account, MFA-enrolled and armable.
Rotating breaks SSO until Yuzu is re-pointed, and the way back in needs an account that already exists:
break-glass *names* one rather than creating it. On an install with none, the only fallback
[`auth-db-recovery.md`](../ops-runbooks/auth-db-recovery.md) documents is destructive.

**What to do: rotate the client secret at your IdP, and delete the old one.** The upgrade closes the
disclosure paths but **does not change the stored value** — anything that already read it still holds a
working credential, and only the IdP can invalidate it. Most IdPs let you *add* a second client secret
without removing the first; adding one is not a rotation, because the disclosed secret keeps working
until it is deleted.

Deletion does not reach what the secret already bought: access tokens minted with it are signed JWTs
that stay valid until they expire, and IdP sessions can outlast them. Treat revoking those as part of
the same job. Yuzu's own sessions are separate — the IdP cannot reach them — and are held in memory for
at most 8 hours; they end on a restart, or per operator via
`DELETE /api/v1/sessions?username=<name>` (admin, `UserManagement:Write`). **Neither reaches API
tokens**: one minted under a session that used the disclosed secret survives every step above. List
them with `GET /api/v1/tokens` and revoke with `DELETE /api/v1/tokens/{id}`.

Re-pointing Yuzu at the new secret is a configuration task rather than a remediation one: once
everything above is dealt with, SSO failing until you update it is an outage, not a continuing
disclosure. It is also configuration-specific and easy to get subtly wrong, so it is being written up as
a reviewed runbook rather than summarised here. Until that lands, see
[`authentication.md`](authentication.md) ("OIDC Single Sign-On") for the durable and non-durable ways to
configure OIDC.

## ⚠️ Breaking: a multi-host `--postgres-dsn` now needs `target_session_attrs=read-write`, and `load_balance_hosts` is refused (HA WS-8)

Affects you only if the server's Postgres connection names **more than one host** — `host=n1,n2,n3`,
`postgresql://n1,n2/yuzu`, a `PGHOST`/`PGHOSTADDR` list in the server's environment, or a host list in
the `pg_service.conf` entry a `service=` DSN or `PGSERVICE` names — or sets `load_balance_hosts` (in
the DSN, `PGLOADBALANCEHOSTS` or that service entry). A single host without `load_balance_hosts`,
including a proxy or managed endpoint (RDS, Azure Flexible Server, Cloud SQL, the shipped HAProxy
compose), is unaffected.

Check before upgrading — look for a host list or load balancing in the DSN and the server's environment:

```bash
grep -rnE 'YUZU_POSTGRES_DSN|postgres-dsn|PGHOST|PGHOSTADDR|PGLOADBALANCEHOSTS|PGSERVICE' \
  /etc/yuzu/ /etc/systemd/system/yuzu-server.service* <your compose/env files> 2>/dev/null
```

If that shows `service=` or `PGSERVICE`, also read the named entry in the service file libpq uses
(`PGSERVICEFILE`, else `~/.pg_service.conf` of the server's user, else `pg_service.conf` in
`PGSYSCONFDIR`) for `host`, `hostaddr`, `load_balance_hosts` and `target_session_attrs`.

- **No `target_session_attrs` set:** the server adds `target_session_attrs=read-write` and logs a
  warning at startup (`... using target_session_attrs=read-write ...`). It will no longer connect to a
  standby, which it previously could do silently whenever a standby was listed first. The DSN is
  rebuilt from libpq's own parse — the same settings in keyword form — and checked option by option
  before use. Set the attribute yourself to silence the warning.
- **`read-write` or `primary`:** unchanged.
- **Any other value** (`any`, `read-only`, `standby`, `prefer-standby`, or an unrecognised one): **the
  server refuses to start** with `Invalid --postgres-dsn: ...`. Change it to `read-write` (or remove it)
  before upgrading.
- **`load_balance_hosts` set to anything but `disable`** (in the DSN or `PGLOADBALANCEHOSTS`), with any
  number of hosts: **the server refuses to start**. Remove it (or set `disable`) before upgrading. The
  server writes to one primary, so with read-write the shuffle balances nothing — and `/readyz` holds
  one connection, so it cannot see a host that fails only some of the pool's shuffled connections.
- **A `service=` entry or `PGSERVICE`:** libpq applies the service file only when it connects, so
  the server checks what libpq resolved on its first Postgres connection at startup, and refuses to
  start (`Invalid Postgres connection settings: ...`) if the resolved settings set
  `load_balance_hosts`, or list several hosts without `target_session_attrs=read-write` (or
  `primary`) — it cannot add the attribute to a service file, so set it there yourself. The readiness
  probe repeats the check each time it opens a connection, but it keeps a healthy one open, so a
  later edit that breaks these rules shows on `/readyz` only at its next reconnect — **restart the
  server after editing the service file**.
- **Not checked — set `target_session_attrs=read-write` yourself:** one host *name* that resolves to
  several servers (DNS round-robin, a Kubernetes headless service).

## Behaviour change: `/readyz` now goes red when Postgres is unreachable, and shutdown can hold for a drain grace (HA WS-8, ADR-2002 §12)

`/readyz` gains a gating `pg_reachable` row, fed by a small probe on its own Postgres connection. Before
this change, `/readyz` stayed **200** through a Postgres outage whenever the server had idle pooled
connections or no traffic (the pool's connect breaker only notices a failed *new* connection, and every
store's row only reports whether it opened at startup). A load balancer health-checking `/readyz` kept
sending traffic to a server that could not serve it.

What you may observe after upgrading:

- **`/readyz` answers 503 during a database outage or failover**, with `"failed_stores":["pg_reachable"]`
  and a `"pg"` reason (`unreachable`, `stale`, `read_only`, `not_yet_probed`). During a Postgres failover
  every replica goes red at once, for roughly the failover time. If an orchestrator's **liveness** probe
  points at `/readyz`, move it to `/livez` before upgrading — otherwise a database blip restarts every
  server.
- **One more Postgres connection per server** (the probe). Budget `N_servers × 2` connections beyond the
  pool against `max_connections` (the other extra one is the leader-election connection).
- **A new alert, `YuzuServerPostgresUnreachable`**, and three `yuzu_server_pg_reachab*` metrics — see
  `docs/user-manual/metrics.md`.
- **New flag `--shutdown-drain-seconds`** (`YUZU_SHUTDOWN_DRAIN_SECONDS`, default **0**, max 60). On
  `SIGTERM` the server keeps serving for at least that long after `/readyz` turns `503 draining`, so a load
  balancer stops routing to it before the listener closes. The default 0 keeps today's shutdown timing;
  set it for any deployment behind a load balancer, **and raise your orchestrator's stop timeout by the
  same amount** (guidance in `docs/user-manual/server-admin.md`, "Load balancers and shutdown drain"). The
  execution-drain wait it sits alongside is now timed in wall-clock seconds (at most 30 s) rather than
  counted as 30 polls.
- **`/readyz` also goes red on a primary that refuses writes** (`default_transaction_read_only` on — some
  managed Postgres services do this when storage fills), reported as `"pg":"read_only"`.
- **Multi-host `--postgres-dsn` now requires `target_session_attrs=read-write`** — a breaking change
  with its own section above.
- **Docker healthchecks.** The demo and viz-UAT composes healthcheck `/readyz`; that is right for
  readiness, but under Docker Swarm or an auto-heal sidecar an outage longer than the healthcheck's
  retry window marks the container unhealthy and restarts it. Point restart-driving checks at `/livez`.

**What to do:** point liveness probes at `/livez`, readiness at `/readyz`; check your Postgres
`max_connections` headroom; set `--shutdown-drain-seconds` if a load balancer fronts the server.

## Behaviour change: legacy `/api/executions*` routes are now management-group confined (#3789)

The legacy pre-v1 `GET /api/executions` (list), `/{id}` (detail), `/{id}/summary`, `/{id}/agents`,
`/{id}/children`, `POST /{id}/rerun`, and `POST /{id}/cancel` routes previously carried NO
management-group confinement at all — a bare `Execution:Read`/`Execute` grant, global or
group-scoped, saw and could act on the entire fleet's executions. They now gate on
`require_fleet_read`, the same admit-then-filter mechanism `GET /api/v1/executions/{id}` already
used.

**Who this affects:** operators holding `Execution:Read`/`Execute` ONLY through a management group
(not a global grant) — these callers are newly ADMITTED to the five GET routes (previously flat
`403`'d outright) but see a narrowed, redacted view. A global grant holder sees no behavior change
on read shape. Everyone sees the following response-shape changes regardless of scope:

- `GET /{id}/summary`, `/{id}/agents`, and `/{id}/children` now return `404` for an unknown
  execution id, instead of a zero-filled/empty `200`.
- `POST /{id}/cancel` now returns `404` for a nonexistent execution id, instead of a false
  `200 {"status":"cancelled"}` (the underlying `UPDATE` always reported success even when it
  matched zero rows).
- A caller holding `Execution:Execute` but **not** `Execution:Read` can no longer rerun or cancel
  an execution — both mutating routes now also require `Read` admission through the fleet gate,
  since `require_fleet_read` is the only place the mutation's target-visibility check happens.
- `GET /api/executions` (list) now caps `limit` at 500 (previously unbounded).
- A gate failure caused by a degraded RBAC/management-group store now returns `503` with
  `retry_after_ms` instead of a flat `403`.
- **`rerun`'s unknown-id response differs by grant scope, deliberately.** A confined caller
  attempting a rerun always gets the uniform `404` above. An UNCONFINED (global-grant) caller
  hitting a genuinely unknown execution id instead keeps the pre-existing
  `400 {"error":"original execution not found"}` from `create_rerun` — unchanged from before
  #3789, and intentionally not unified with the new `404`, to minimize behavior change for
  existing global-grant automation. `cancel` has no equivalent asymmetry: it returns `404` for an
  unknown id under every grant scope.
- An execution whose targeted cohort never fully reports (an agent that went permanently offline
  mid-run, for example) can permanently fail `rerun`/`cancel`'s complete-cohort check for a
  confined caller. The escape hatch is a **global** `Execution:Execute`+`Execution:Read` grant,
  which is never subject to this confinement rule.

**What to do:** if you have automation with a group-scoped (not global) `Execution:Read`/`Execute`
grant, re-verify it still sees the executions it depends on — a confined caller now sees only
executions it dispatched itself or that involve at least one agent it can see, rather than being
denied outright or (previously) seeing everything. If you scripted around the old `/cancel`
false-success or the old zero-filled `/summary` response for an unknown id, update to expect `404`.

**Verify:** `GET /api/executions/{id}` for an execution outside your management-group scope should
return `404`, not the previously-unfiltered full record. `docs/auth-architecture.md`'s "Fourth
migration (#3789)" section has the full design; `docs/user-manual/rest-api.md`'s "Executions"
section has the per-route reference including the `503` shape and the `rerun` escape hatch above.

## Behaviour change: Destructive-class dispatch now requires explicit `agent_ids` on REST and MCP (#3685)

17 `plugin.action` pairs are classified `Destructive` in the command catalogue: `tar.purge_source`,
`tar.rollup`, `filesystem.delete_lines`, `registry.delete_value`, `registry.delete_key`,
`storage.clear`, `content_dist.stage`, `content_dist.execute_staged`, `content_dist.cleanup`,
`content_dist.upload_file`, `tags.clear`, `script_exec.exec`, `script_exec.powershell`,
`script_exec.bash`, `http_client.download`, `certificates.delete`, and `quarantine.quarantine`
(19 as of this writing — `power_health.set_power_plan` and `printing.clear_queue` have since joined
them, under the same rule).
Dispatching any of them without explicit, non-empty `agent_ids` — an omitted/empty target, or a
`scope` (including `"__all__"`, even alongside `agent_ids`) — is now refused with `400`
(`"destructive action requires explicit in-scope agent_ids; broadcast and scope fan-out are
refused"`) on REST `POST /api/command`, and `-32602` with the same message on MCP
`execute_instruction` (refused before an approval ticket is minted or consumed, at both the
supervised-tier pre-mint gate and the operator-tier handler).

**MCP `execute_instruction` had no Destructive-targeting gate at all before this release** — a
scope-targeted or broadcast call to one of the 17 rows above dispatched normally and succeeded.

**REST `/api/command`'s outcome for these 17 rows is unchanged** — the prior guard already denied
a scope-targeted or broadcast dispatch to any of them, both before and after this release. What
changed on REST is the guard's shape, not its outcome: the prior code was an `if` that collapsed
"classified and not Destructive" and "failed to classify at all" (a classify-miss) into the same
skipped branch, relying on a classify-miss being denied unconditionally further downstream
(`build_classified_command`) rather than proving that locally. This release replaces it with an
exhaustive switch with no default arm, so a future change to the verdict enum forces a
compile-time decision here too, instead of silently falling through to a guard shape that was
correct only because of a downstream backstop.

**Who this affects:** two surfaces change outcome in this release. **MCP `execute_instruction`**,
for any operator or automation dispatching one of the 17 rows above with `scope` or an
omitted/empty target. And the **dashboard execute surface** (`POST /api/dashboard/execute`), which
gains the gate for the first time here — including the case most likely to bite, an **omitted**
scope: that surface treated "no target named" as the whole fleet, so console automation that
posted neither `agent_ids` nor `scope` for one of these rows previously dispatched fleet-wide and
is now refused. A REST `/api/command` caller was already refused before this release and sees no
behavior change. Dispatches to a row NOT on this list are unaffected on all three surfaces.

**A second dashboard change, distinct from the targeting gate:** an explicitly-targeted Destructive
dispatch from the console is now confined to the agents visible to the calling operator, matching
REST. With RBAC off this is a no-op — every enrolled agent belongs to the auto-created root "All
Devices" group, so the visible set is the whole fleet. It bites only with **RBAC enforcement on**
where an operator holds `Execution:Execute` as a global grant rather than through a
management-group role: that operator has no management-group rows to be visible through, so the
confined list is empty and the dispatch is refused with `no reachable in-scope agent` (audited
`reason=scope_violation`). The fix is to grant the operator a management-group role covering the
agents they administer. Note the message names in-scope reachability, not connectivity — an agent
shown as online in the console can still produce it.

**What to do — the field to send differs by surface, so do not apply one remediation to both:**

- **MCP `execute_instruction`** (and REST `/api/command`): send an explicit, non-empty
  `agent_ids` array.
- **Dashboard `POST /api/dashboard/execute`**: this endpoint has **no `agent_ids` field** and
  ignores one if sent. It takes a single `scope` form field, and one explicit agent is expressed
  as `scope=<agent-id>` (a management group is `scope=group:<id>`, the fleet is `scope=__all__` —
  the latter two are what the gate now refuses for Destructive rows). Console automation must
  therefore send `scope=<agent-id>`. The browser UI already does this and needs no change.

In both cases, if RBAC is enforced, also confirm the calling operator's management-group roles
cover the agents named — see the confinement note above.
`POST /api/instructions/{id}/execute` and MCP `execute_bundle` do not yet enforce the gate — a
tracked follow-up, not a gap this release closes.

**Verify:** re-run the affected dispatch with an explicit single target — `agent_ids` on
MCP/REST, `scope=<agent-id>` on the dashboard — and confirm it succeeds as before; a group-scope,
broadcast, or untargeted call to one of the 17 rows should now return the refusal above rather
than dispatching. To confirm the gate is exercising in your environment:

```promql
yuzu_server_dispatch_target_rejected_total{route=~"command|mcp|dashboard",reason="destructive_untargeted"}
```

Note the regex matcher (`=~`): a label matcher cannot take an alternation of quoted strings. The visible-agent confinement refusal is deliberately **not** on that counter —
look for the `command.dispatch|denied` audit row carrying `reason=scope_violation` instead.

## Behaviour change: SAML login gains a new availability coupling to `rbac_store` (#1832)

SAML SSO now reaches parity with OIDC's group-to-role RBAC reconciliation (see
[`authentication.md`](authentication.md) "SAML Fine-Grained RBAC"). This introduces a
coupling that did not exist before: on a deployment that already has **RBAC enabled**
**and** `--saml-group-attribute` configured, a SAML login now depends on `rbac_store`
being reachable — a transient reconcile-store error denies the login outright
(fail-closed), rather than granting a session under stale or unreconciled roles.
Previously, a `--saml-group-attribute`-configured deployment's SAML logins did not
touch the RBAC store at all (only the coarse `--saml-admin-group` admin/user mapping
ran), so this is a genuinely new dependency for that combination of flags, not a
tightening of an existing one.

**What to do:** if you run SAML with both RBAC enabled and `--saml-group-attribute`
set, ensure `rbac_store` (PostgreSQL) health and availability are covered by whatever
you already monitor for RBAC-gated REST/MCP calls — a `rbac_store` outage now also
takes down SAML login for that deployment, not just RBAC-gated reads. Deployments that
leave `--saml-group-attribute` unset, or that run with RBAC disabled, are unaffected —
this section is a no-op for them.

**Also note:** the `--saml-group-attribute` group-value cap (`saml::kMaxGroupValues`)
is raised from 64 to 200 in this release, to align with
`RbacStore::kMaxIdpGroupsPerLogin`. A SAML assertion carrying 65–200 group values,
which previously had its excess values silently truncated (and the login still
succeeded), now has all of them considered. An assertion carrying more than 200 group
values, which previously also truncated-and-logged-in, now instead **denies the
login** (mirrors OIDC's `group_count_exceeded` behaviour) — see "SAML Fine-Grained
RBAC" in `authentication.md` for the full detail, including the practical httplib
form-body-size caveat on how large an assertion can realistically reach `/saml/acs`.

## Behaviour change: InstructionStore moves to PostgreSQL — deleted content no longer resurrects (ADR-0058)

`InstructionStore` (InstructionDefinitions and InstructionSets — the operator- and
build-time-shipped instruction/question catalog) moves from per-replica SQLite to the shared
PostgreSQL substrate (ADR-0006/0007), like every other migrated store. **No legacy-SQLite
backfill** (ADR-0009's fresh-start-by-default class, following `ResponseStore`'s precedent): no
production fleet has ever run a pre-Postgres build of any Yuzu store, so the pre-migration
`instructions.db` is never read. On upgrade, the bundled catalog reseeds fresh on first boot the
same way it always does, and any operator-authored content must be re-created via the normal
API (`POST /api/instructions`, `POST /api/instruction-sets`) — there is no automatic carry-over.

**Breaking, deliberate: an operator-deleted bundled definition/set no longer reappears.**
Since 0.12.x (see that row above), deleting a build-time-shipped definition and rebooting made
it silently reappear — the old per-replica SQLite reseed logic couldn't distinguish "never
seeded" from "deliberately deleted", so `enabled: false` was the documented workaround for
permanent suppression. **That workaround is no longer necessary but still works.** Post-upgrade,
a deleted bundled id stays deleted — across every reboot, every replica, and every future
release — via a tombstone the reseed loop consults. **Recovery path:** the tombstone only
gates the build-time-trusted reseed path; an operator can still freely bring the id back at any
time via a normal `POST /api/instructions` create or `POST /api/instructions/import`.

**A side effect worth knowing:** delete-and-reboot was also, incidentally, the only existing
way to force an existing bundled definition to pick up *newer* bundled content shipped in a
later release (delete it, then the next boot's reseed re-inserts the current version). That
side channel is now closed along with the resurrection bug it depended on — an existing bundled
row, edited or not, never automatically picks up newer shipped content. There is currently no
other refresh mechanism; tracked in [#2555](https://github.com/Tr3kkR/Yuzu/issues/2555).

**REST contract change** on the direct `/api/instructions*` / `/api/instruction-sets*` routes:
`DELETE` on a missing id now returns `404` (was `200 {"deleted": false}`); `create`/`update`/
`import`/`create-set` now return `503` on a genuine database failure instead of a misleading
`400`. See [`rest-api.md`](rest-api.md#instructions) for the full per-route response-code
reference. Any automation that specifically parsed the old `200 {"deleted": false}` shape or
treated every non-2xx response as a validation error should be updated.

No operator action is required to upgrade; the reseed loop runs automatically at boot. See
`docs/adr/0058-instruction-store-postgres-migration.md` for the full design record.

**Caveat (rollback direction):** the above covers forward migration only. `instructions.db`
still exists after the upgrade (it keeps backing the still-SQLite
`ExecutionTracker`/`ApprovalManager`/`ScheduleEngine` siblings), but this binary never writes
InstructionDefinition/InstructionSet rows to it. If you roll the server *binary* back to a
pre-migration release, the outcome depends on your deployment's history and is never an empty
catalog either way — the pre-migration binary's own boot sequence unconditionally
`CREATE TABLE IF NOT EXISTS`-es the catalog tables and runs its own every-boot bundled-content
reseed loop, the same way this store always has:
- **A deployment that upgraded from a pre-migration install** still has its old
  `instructions.db` catalog tables, untouched by the new binary. The rolled-back binary reads
  them and serves that pre-cutover snapshot — including re-resurrecting any bundled definition
  or set an operator deliberately deleted in Postgres after cutover, since the old binary has
  no concept of the tombstone table.
- **A deployment that was Postgres-first from its first boot** has no catalog tables in
  `instructions.db` yet. The rolled-back binary creates them fresh and reseeds that old
  release's full bundled catalog — a stale but non-empty catalog, not an empty one.
- **Either way, anything created or edited via the API while running the new (Postgres)
  binary is invisible during the rollback** — it lives only in Postgres, which the old binary
  never reads — and, because there is no backfill, is not recovered automatically when you
  roll forward again either; content authored while rolled back must be re-entered.

## Behaviour change: token-rotation confirm now requires proof of possession (#3015)

`confirm` on a rotation — REST `POST /api/v1/tokens/{id}/confirm` and `POST /api/v1/engine-principals/{id}/credentials/confirm`, plus the MCP twins `confirm_api_token_rotation`/`confirm_engine_rotation` — previously admitted on caller identity plus the successor's `token_id` alone. A caller who recovered an unknown successor's `token_id` out-of-band (a support ticket, a log line) could confirm — and thereby revoke the predecessor for — a rotation whose secret they never actually received. All four confirm surfaces now additionally require the raw successor secret itself in the request body/args, verified with a constant-time hash comparison against the successor's stored hash, checked LAST — strictly after ownership, pair-state, the `token_id` pin, tier, scope, and the initiator binding have all already passed — before the predecessor is touched.

**Who this affects:** any caller (human or automation) confirming a rotation with only the `token_id`, and any caller confirming with the wrong secret.

- **REST:** a confirm body carrying no `secret` field (or an empty one) now gets `400` instead of succeeding; a wrong `secret` gets `403`.
- **MCP:** `confirm_api_token_rotation`/`confirm_engine_rotation` called without a `secret` arg now get `kInvalidParams`; a wrong one gets `kPermissionDenied`.

Correctly-implemented automation already holds the secret — it's the same raw value the `rotate` response returns exactly once (REST `data.token`) — so a caller that installs the successor from that response and passes it straight through to `confirm` sees no change in behavior.

**What to do if you lose the rotate response before confirming:** you can no longer confirm — there's no way to manufacture the secret from the `token_id` alone. Two recovery paths, and neither is new — this change makes the mechanism enforce guidance already documented in [`authentication.md`](authentication.md#rotating-a-token) "Rotating a Token" (don't look the successor up and confirm blind):

1. **Wait for the automatic overlap-window sweep.** Proof of possession gates this immediate, explicit `confirm` call only — the 60-second background sweep is unaffected by this change and still auto-revokes the predecessor on its own schedule with no secret required, provided the successor secret was actually installed and presented (used) at least once.
2. **Revoke the unknown successor and start a new rotation.** This keeps the predecessor working immediately, at the cost of restarting the rotation.

See [`authentication.md`](authentication.md#rotating-a-token) and [`engine-principals.md`](engine-principals.md) for the full detail, and [`rest-api.md`](rest-api.md) for the exact REST error bodies.

## Behaviour change: MCP approval-store permanent failures now say don't retry (#2786)

An MCP approval-ticket recall that hits a store fault has always returned `-32603` with a `retry_after_ms` hint. Previously that hint was `5000` (retry after 5 seconds) for every store fault except a never-opened store, including one that was open but failing in a way no amount of retrying clears — SQLite corruption, not-a-database, a read-only filesystem, or a full disk. Those four cases now correctly get `retry_after_ms: null` (the same "escalate to an operator" response a never-opened store gets) instead of the transient retry hint.

**What to do:** if you have automation that blindly retries on `-32603` without checking `retry_after_ms`, it now stops retrying sooner in this specific case — which is the correct behavior (the old retries were futile). If your automation already honors `retry_after_ms` per [invariant A5](../agentic-first-principle.md), no change is needed. See [`mcp.md`](mcp.md) "`-32603`: Approval store unavailable" for the full response-body reference.

## Behaviour change: four MCP tool input schemas got stricter (#2444)

`revoke_certificate.serial_hex`, `confirm_engine_rotation.token_id`, `quarantine_device.reason`/`whitelist`, and the eight *approval-gated* engine-principal tools' `principal_id` (`create`/`revoke_engine_principal`, `mint`/`rotate_engine_credential`, `transfer_engine_principal_owner`, `assign`/`unassign_engine_role`) now carry `pattern`/`maxLength` bounds mirroring their handlers' own checks (previously enforced only at the handler, after an approval ticket was already consumed). `get_engine_principal` and `list_engine_roles` also gained the same `principal_id` pattern, but per this codebase's standing rule that input-schema validation runs only on the approval-gated path (`mcp-server.md`'s "Pre-approval input-schema validation"), those two are Read-tier and never approval-gated — the pattern is advertised metadata on `tools/list` only, not server-enforced; a malformed `principal_id` still reaches the handler and is rejected there exactly as before.

**Who this affects:** any operator or automation with an outstanding (pending or
approved-but-unconsumed) approval ticket for one of these ten tools —
`revoke_certificate`, `confirm_engine_rotation`, `quarantine_device`,
`create_engine_principal`, `revoke_engine_principal`, `mint_engine_credential`,
`rotate_engine_credential`, `transfer_engine_principal_owner`,
`assign_engine_role`, `unassign_engine_role` — whose arguments don't match the
new bound: `serial_hex` must be `^[0-9A-Fa-f]{1,64}$`; `token_id` must be
`^[0-9a-f]{24}$`; `quarantine_device.reason`/`whitelist` must be ≤1024/≤512
bytes (whitelist additionally charset-restricted); `principal_id` must match
`^engine:[a-z0-9._-]+$` (or the bare-slug form on `assign`/`unassign_engine_role`).
Full patterns: `mcp-server.md`'s "Pre-approval input-schema validation" section.

**What to do:** such a ticket becomes unrecallable fail-closed once the new
server is running — the recall fails pre-consume just like any other
schema-invalid call, and the ticket is never burned, but it also can't be
redeemed as originally minted. It stays valid until its normal 7-day expiry
(pending or approved-unconsumed), then ages out and must be re-requested. To
check exposure before upgrading, list your outstanding tickets for these ten
tools (`list_pending_approvals` MCP tool or `GET /api/v1/approvals`) and
compare each one's arguments against the patterns above; no action is needed
for a ticket that already matches, or if you have none outstanding.

**Verify:** re-request any ticket the check above flagged, confirm the new
recall succeeds under the same tier, and confirm a deliberately malformed
value (e.g. a non-hex `serial_hex`) is now rejected at mint time — `-32602`,
no approval created — rather than being accepted and only failing later at
the handler.

## Behaviour change: `discover_instructions`/`GET /api/v1/discover/instructions` null out a non-object stored `parameter_schema` (#2986)

Both surfaces share one builder (`build_instructions_catalog`) that parses each `InstructionDefinition`'s stored `parameter_schema` text. It previously forwarded any value that parsed as JSON, even a non-object (an array, string, number, or boolean). It now forwards it only when the parsed value is itself a JSON object — a non-object value is reported as `null` instead, matching `GET /api/v1/discover/plugins`' existing behavior for the same field.

**Who this affects:** an operator or integration that authored an `InstructionDefinition` with a non-object `parameter_schema` — reachable via the ordinary `create`/`update`/`import` paths, which don't validate the field's shape on write. No shipped content sets `parameter_schema` to anything but an object or leaves it unset (defaults to `{}`), so this affects only a deliberately or accidentally malformed definition.

**What to do:** if you have such a definition and relied on the old raw-forwarding behavior, re-author `parameter_schema` as a JSON Schema object. No action is required otherwise.

## Behaviour change: webhook and offload-target deliveries, and enrollment/execution-failure notifications, now actually fire (#3261)

A boot-ordering bug wired `NotificationStore`/`WebhookStore`/`OffloadTargetStore` into
the agent-service RPC path (`Register`, `Subscribe`, `process_gateway_response`) before
those three stores were constructed, so the wiring silently never took effect. Dashboard
notifications for agent enrollment and execution failures, and configured webhook/offload
deliveries for `agent.registered` and `execution.completed` events, have been dead for
the life of the process **since the stores were introduced** — for `NotificationStore`/
`WebhookStore`, every tagged release from v0.10.0 through v0.13.0 (roughly four months);
`OffloadTargetStore` didn't exist until v0.12.0, so its affected window is v0.12.0 through
v0.13.0 (roughly three months). Every use site double-guards `ptr && ptr->is_open()` with a
silent skip, so nothing logged or alerted; the bug produced zero signal. They now fire on
every boot.

**What to do:** if you configured a webhook (`POST /api/webhooks`) since v0.10.0, or an
offload target (`POST /api/v1/offload-targets`) since v0.12.0, expecting live traffic and
saw none, that integration has been silently non-functional the entire time, not merely quiet
— there is no queued backlog to replay, because the events were never generated in the
first place. If you use one of these integrations as part of your own monitoring or
compliance evidence chain (a SIEM feed, an alerting pipeline), treat the gap as a
documented monitoring-coverage lapse for that period, not just a product bug, when
recording it in your own change or incident log. After upgrading, confirm your receiving
endpoint still exists and can handle real traffic before you rely on it — deliveries
start immediately, with no flag or opt-in involved. If your webhook fires to Slack or a
similar noisy channel for enrollment alerts, note that `agent.registered` fires on every
gRPC reconnect, not only first enrollment (this is unchanged, documented behaviour — see
"Webhooks" / "Offload Targets" in [`rest-api.md`](rest-api.md) — but was invisible
until now); the "Agent Enrolled" **dashboard notification** specifically does not repeat
on reconnect, so a server restart with N connected agents does not flood that feed.

## Behaviour change: `mcp.bridge.*` audit rows can now carry `result=failure` (#2487 / #2506)

Audit rows for the MCP progress bridge (`mcp.bridge.done_reap`, `session_dead`, `arming_reaped`, `pin_acked`, `forced_expire`) were previously stamped `result=success` unconditionally, regardless of what actually happened. They now report the real outcome: `result=failure` when a background teardown could not release one of the resources it owns, or when the terminal-frame publish ladder poisoned the session, threw, or was never reached. The `detail` field names which, and no longer asserts a delivery or a poisoning that did not occur.

**What to do:** if you have a SIEM rule, dashboard or evidence query that treats `result` on this verb family as a constant `success` - for example "alert if any `mcp.bridge.*` row is not `success`" - update it before upgrading, or it will fire on legitimate rows. Note also that `failure` here is *self-audited*: a rule that surfaces failure branches by filtering on `denied` will not see these. Filter on `result != "success"` where you need both. `mcp.bridge.cancel` is unaffected and remains `success`.

These rows are background-actor events (`principal=system`), not operator actions, and a `failure` row does **not** mean a client lost a result - executions stay durably fetchable by `execution_id`. See [`audit-log.md`](audit-log.md) for the verb family and [`../ops-runbooks/mcp-bridge-teardown-recovery.md`](../ops-runbooks/mcp-bridge-teardown-recovery.md) for what to do when the paired alert fires.

## Behaviour change: MCP unknown-tool calls now audit `result=denied`, not `failure` (#2445)

An MCP `tools/call` request naming a tool that doesn't exist has always returned `-32601` (`kMethodNotFound`) with the same error message. The audit row for that rejection previously carried `result=failure` - the token this codebase reserves for server-side faults - while every sibling denial on the surface (tier, read-only, schema, input-bounds, per-submitter-cap) uses `result=denied`. It now audits `result=denied` too, matching those siblings. Nothing about the JSON-RPC response changed.

**What to do:** if you have a SIEM rule, dashboard or evidence query that classifies `mcp.<tool_name>` rows by filtering on `result=failure` to catch unknown-tool probes, re-point it at `result=denied` before upgrading, or it will stop matching. A rule that already filters on `result != "success"` sees both and needs no change. Note `result=failure` was never a clean isolator for unknown-tool probes specifically - it is also emitted for genuine server-side faults on *known* tools (store degraded, dispatch exception, etc.) and for several other client-caused-but-mislabeled rejections on the same surface (still open, tracked in #3176), so a rule that wants unknown-tool rows specifically should filter on `detail="unknown tool"`, which this change does not touch. See [`audit-log.md`](audit-log.md) "Result vocabulary" for the surface's current token usage.

## Behaviour change: a failed MCP progress-bridge teardown is now retried instead of being permanently retained (#2513)

A `mcp.bridge.*` teardown step (unsubscribe, releasing the streamed admission charge, or erasing the correlation record) that failed used to strand the record - and the bus channel, replay buffer, and per-session admission slot it held - for the rest of the process's life. It now gets up to `Config::teardown_retry_max` retries beyond the first attempt (4 total attempts by default), one per later sweep tick, before falling back to the old permanent-retention behavior. New `yuzu_mcp_bridge_teardown_retry_total{outcome="recovered"|"exhausted"}` metric and `mcp.bridge.teardown_retry` audit action evidence which happened; see [`audit-log.md`](audit-log.md) and [`../ops-runbooks/mcp-bridge-teardown-recovery.md`](../ops-runbooks/mcp-bridge-teardown-recovery.md).

**What to do:** the shipped `YuzuMcpBridgeTeardownIncomplete` alert changed from a raw counter test (fires and never clears, since the underlying series is monotonic) to a windowed `increase(...[15m]) > 0` test, because most of its movement now self-heals via retry within a few sweep ticks. If you copied the old rule into your own alerting config instead of re-importing `docs/prometheus/yuzu-alerts.yml`, update it the same way or it will stay permanently firing on transient, already-recovered blips. The new `YuzuMcpBridgeTeardownRetryExhausted` alert is now the actual permanent-retention signal - add it if you track these alerts individually rather than loading the bundled rules file wholesale.

If you have dashboard or SIEM logic reading the pre-existing `yuzu_mcp_bridge_teardown_incomplete_total` counter directly rather than through the bundled alert - it is unchanged in name and label shape, but its increment semantics changed: previously one increment per stranded record (ever), now up to `Config::teardown_retry_max` + 1 increments for the SAME record (once per failed step, per attempt) before it either recovers or exhausts. Arithmetic that read the counter as "count of stranded records" will now overcount under retry; read `yuzu_mcp_bridge_teardown_retry_total{outcome="exhausted"}` for that instead. `Config::teardown_retry_max` is a code-constant default, not an operator-configurable flag or env var - there is nothing to tune here.

## Behaviour change: agent command replay protection is now durable, and a redelivered command replays its real result (HA WS-0, ADR-2002)

The agent's command deduplication moved from an in-memory set (cleared on every reconnect) to a durable SQLite store (`command_dedup.db` in the agent data directory). Two consequences an operator or automation may observe:

**Breaking for automation/SIEM.** A redelivered/duplicate command no longer receives a `REJECTED` response with the fixed reason `"command replay rejected: duplicate command_id"`. That string **is retired.** A duplicate now either replays the command's **original terminal frame** (its real `SUCCESS`/`FAILURE`/`REJECTED` status, exit code, and structured error — the terminal frame carries the outcome, not the streamed stdout, which is not re-sent) or, while the first attempt is still running, returns a non-terminal `RUNNING` frame with output `"duplicate command still in flight"`. Any detection rule, dashboard, or evidence query that matched the old rejection string on a redelivered command will silently stop matching — re-point it before upgrading (there is no longer a single "this was a replay" signal on the wire; the server correlates by `command_id`).

**What to do:** update or remove any rule keyed on `"command replay rejected: duplicate command_id"`. If you tracked replays for security evidence, note the agent now emits `yuzu.dedup_*` heartbeat tags (`dedup_degraded` for an unopenable store; `dedup_claim_errors`/`dedup_record_errors`/`dedup_release_errors` for post-open write failures; `dedup_replays`) instead; fleet-wide `yuzu_fleet_*` aggregation + an alert land with the HA observability workstream (WS-11).

**New on-disk artifact.** `command_dedup.db` (plus `-wal`/`-shm`) appears in the agent's `--data-dir`, bounded to the most recent commands. It is a regenerable safety net, **not** a backup target. **Upgrade is fresh-start** — no migration from the old in-memory scheme (there was no persistent state to carry); worst case on upgrade is that one already-delivered command could re-execute if redelivered during the restart, exactly as it could before this change. Downgrade is safe: an older agent simply ignores the file.

**Degraded mode is fail-open.** If the store cannot be opened or written (e.g. a full disk), the agent keeps executing commands **undeduplicated** rather than refusing them, and surfaces the condition on the heartbeat: `yuzu.dedup_degraded=1` for a store that never **opened**, and the `dedup_claim_errors`/`dedup_record_errors`/`dedup_release_errors` counters for **post-open** write failures. A per-destructive-instruction-class fail-closed option is planned but not in this release.

## Behaviour change: an MCP maintenance failure degrades instead of aborting the server (#2487)

A transient failure in the MCP progress-bridge sweep or the MCP session collector, which runs on the server's maintenance thread, previously escaped that thread and terminated the whole process. It is now contained: the tick is skipped and retried on the next cycle.

**What to do:** be aware this is a genuine trade, not a pure win. The old failure was self-announcing - the process died, your supervisor restarted it, and uptime monitoring saw it. The new one is silent unless you are scraping metrics: a sustained failure means bridge teardown or session collection stops running, live MCP progress can degrade for the remaining life of the process, and `/readyz` will continue to report healthy throughout (MCP session state deliberately does not gate readiness). If you run Prometheus, scrape `yuzu_mcp_bridge_teardown_incomplete_total`, `yuzu_mcp_maintenance_tick_failures_total` and `yuzu_mcp_bridge_records_active`, and load the bundled rules in `docs/prometheus/yuzu-alerts.yml` - they are not applied automatically. If you do not, you will not see this condition at all.

Note this narrows the crash surface rather than closing it: other work on the same maintenance thread remains unguarded, so a sufficiently severe resource exhaustion can still terminate the process from a different call site.

## Behaviour change: `yuzu-agent` no longer restart-loops forever (ADR-0021 rung 7.7a)

The `yuzu-agent` systemd unit now sets `StartLimitIntervalSec=300` + `StartLimitBurst=5` in its `[Unit]` section. Previously the unit was `Restart=always` with no start limit, so an agent that could not stay up restarted every 10 seconds indefinitely. With this change, if the agent exits 5 times within 300 seconds systemd stops retrying and the unit enters `failed`.

This matters because the agent's Guardian engine can now `hard_exit()` when an I/O worker is wedged past a grace period (a permanently wedged watched target, e.g. a dead NFS mount or a hung service query); without the start limit that would be a silent 10-second crash loop.

**What to do:** if you alert on systemd unit state, add `yuzu-agent` entering `failed` to your alerts - it means the agent gave up after a crash loop and the device is now dark, which the old restart-forever behaviour hid. Recover with `systemctl reset-failed yuzu-agent` once the underlying cause (e.g. the wedged mount) is resolved, then `systemctl start yuzu-agent`. The Guardian spark detection path this rung wires is dormant (`--spark-disable` unchanged, legacy detection unaffected), so there is no detection-behaviour change to account for. See also [`server-admin.md`](server-admin.md) "Stopping a wedged agent".

## Behaviour change: a Guardian rule that fails to arm no longer crashes the agent (ADR-0021 rung 7.7b PR-1a)

Independent of the dormant spark path above, the Guardian engine's `apply_rules` (which runs on the **live legacy detection path** regardless of `--spark-disable`) now firewalls a per-rule reconcile failure. Previously, if arming a rule threw - e.g. a `std::thread` creation failure under resource exhaustion, or a `bad_alloc` - the exception escaped onto the agent's dispatch thread and aborted the whole daemon. It now degrades: the failure is caught and counted, the rule stays persisted, and the agent keeps running. The `full_sync` teardown and the dispatch boundary carry the same firewall.

One behaviour to be aware of: when a rule fails to arm, the agent **holds its policy generation** (does not report "caught up") so the server's heartbeat reconcile keeps re-pushing and retrying - a transient resource failure self-heals within a reconcile cycle. A rule that fails **persistently** (rare - it requires a durable resource condition, not bad rule content) keeps the agent behind-generation and drives a re-push each reconcile interval; this is visible in the server's `guaranteed_state.reconcile` audit rows for that agent. No operator action is required.

## Behaviour change: Guardian event-drop metric narrows to genuine collisions (ADR-0021 rung 7.7b PR-Sv)

Guardian event ingest now distinguishes an idempotent **redelivery** (a matching-fields `event_id` PK conflict — the durable agent lifecycle journal's expected crash-durable, duplicate-tolerant, bounded-retry redelivery, not a guarantee of eventual delivery - an un-acked record that ages out of the 7-day retention window is a rare, counted loss, not silent) from a genuine **collision** (a mismatched-payload conflict — a forged-id pre-claim or an `event_seq_` reset carrying a different event). The eviction-loss counter (`yuzu.guardian_journal_evicted_no_send_evidence`) is in-memory only and resets on agent restart, and today has no dashboard, REST, or MCP surface at all, per-agent or fleet-wide - see [Reconnect replay traffic](guaranteed-state.md#reconnect-replay-traffic-durable-lifecycle-journal) for the full picture (tracked under #2298). **A high redelivery count after an agent outage or reconnect storm is expected and is NOT a loss signal** - genuine loss shows up only as a mismatched collision (`..._events_dropped_total`) or the rare journal-eviction case above. Three operator-visible consequences:

- **`yuzu_server_guardian_events_dropped_total` narrows.** It now counts only mismatched collisions; benign redeliveries move to the new `yuzu_server_guardian_events_redelivered_total`. **If you deployed the bundled `YuzuGuardianEventsDropped` rule from `docs/prometheus/yuzu-alerts.yml`** (a copy, not something the server auto-upgrades) **with your own or a wider threshold tuned to reconnect churn, re-apply the updated rule (now `> 5/1h`)** — otherwise your old threshold's baseline drops post-upgrade and the alert goes **silently dead**, not loud, on a CC7.3 signal.
- **A metric series steps down, and a new one appears.** Any Grafana panel/PromQL against `..._events_dropped_total` shows a step-change *drop* at upgrade with no incident — **expected, not data loss**; watch total PK-conflict volume via the new `..._events_redelivered_total` series. A third new series, `..._events_ingest_errors_total` (with a bundled `YuzuGuardianIngestErrors` alert), counts operational ingest faults so a persistent fault can't silently hide collisions.
- **DEX de-duplication on reconnect.** Before this change, a redelivered event re-ran the DEX blast-radius + alert observers on every agent reconnect. If you saw duplicate/false blast-radius sightings or duplicate routed alerts during reconnect storms, those stop now — an intentional fix, not a regression.

**Verify:** post-upgrade, confirm the new series are present and re-tune any custom copy of the drop alert:

```promql
yuzu_server_guardian_events_redelivered_total   # should appear and climb on reconnects
yuzu_server_guardian_events_ingest_errors_total # should stay at 0 in a healthy fleet
```

No config or data migration is required.

## Behaviour change: a degraded file-change rule now reports itself unhealthy instead of staying silently green (#4748)

A `file-change` Guardian rule watches its target's parent directory to detect the target being renamed or moved. If that watch's own teardown repeatedly fails to confirm (normally only a wedged filesystem driver, or sustained packet loss on a network share), rename detection for that rule permanently disables until the rule is re-armed. Previously the only signal was a single agent log line — the rule kept reporting `guard.compliant` (the device page's compliance census showed it green) for as long as the agent ran, even though it could no longer detect a rename of its watched directory.

After this upgrade, a rule that reaches this state reports itself `errored` on the device page (the same red state as an unresolved drift) instead, with an operator-facing detail explaining the cause and how to recover, and re-asserts every 5 minutes for as long as it stays disabled. The rule's own file presence/content detection is unaffected either way — only rename detection is lost, and only its *reporting* changes here.

**This is not a retroactive flip.** The disabled state is in-memory only (never persisted), so it resets on the very restart that ships this fix — no rule that was showing compliant before upgrading suddenly shows errored at upgrade time. What changes is *future* behavior: if a rule reaches this degraded state after upgrading (e.g. from another bout of network-share packet loss), it now shows red where a pre-upgrade agent would have stayed silently green. If you see a previously-quiet `file-change` rule turn red after upgrading, that is very likely this fix correctly surfacing a pre-existing condition on your network share, not a new regression — see [the degraded-mode section](guaranteed-state.md#file-guards--detect-a-file-changed-or-deleted-in-realtime) for the recovery steps (re-push the rule's policy, re-deploy its Baseline, or restart the agent).

No config or data migration is required.

## Behaviour change: dashboard YAML Save is schema-aware and stricter (#1993)

`POST /api/instructions/yaml` (the New Definition panel's Save endpoint) and
`POST /api/instructions/validate-yaml` now share one schema-aware parser that
accepts the canonical nested InstructionDefinition schema (`metadata.id`,
`spec.execution.plugin/action` — the documented format every shipped
definition uses), which the old substring scanner rejected. In exchange, the
endpoint is stricter about malformed input:

**Who this affects:** automation POSTing YAML to `/api/instructions/yaml`
that (a) omits `apiVersion:`/`kind:` lines, (b) relied on a stray `name:`
substring anywhere in the document being picked up as the definition name,
(c) re-creates a definition whose `metadata.id` already exists (now **409**
with a denied audit row instead of a silent second copy under a generated
id), (d) supplies an explicit id outside `[A-Za-z0-9._-]{1,128}`, or
(e) pastes multi-document (`---`-separated) files (now rejected; save one
definition at a time). Interactive panel users are unaffected — the
structured form's output stays accepted.

**Verify:** re-run your automation against a test server; failures surface as
specific per-field messages (e.g. `Missing metadata.id (or metadata.name)
field`), and successful saves now emit `instruction.create` /
`instruction.update` audit rows.

## ⚠️ Reserved on-behalf-of headers rejected + `principal_class` metric label (ADR-1005 Phase 1)

Two operator-visible changes ship together:

**1. Reserved headers now 403.** Five header names are reserved and rejected
on every HTTP endpoint before authentication (`On-Behalf-Of`,
`X-On-Behalf-Of`, `X-Yuzu-On-Behalf-Of`, `X-Yuzu-Delegated-Operator`,
`X-Yuzu-Delegation-Artifact`, case-insensitive; the equivalent gRPC metadata
keys cause the call to be cancelled). Nothing previously consumed these
headers, so a correctly-built integration is unaffected — but **pre-flight
check any proxy, service mesh, or SSO gateway in front of Yuzu**: some
API-gateway products stamp an on-behalf-of/OBO convention header on every
upstream request (the name is Microsoft's Entra OBO term), which would 403
**all** REST/MCP/dashboard traffic after upgrade. Health probes (`/livez`,
`/readyz`, `/health`, `/api/health`) are exempt, so the pod stays in rotation
— a green probe with a 100% 403 rate is the signature (see
`docs/operations/troubleshooting.md`). Rejections are visible in
`yuzu_onbehalf_rejected_total` and throttled `[ADR-1005]` warn lines.

**2. `yuzu_http_requests_total` gains a `principal_class` label**
(`human`/`agent`/`none`; `engine` reserved). This is a Prometheus
series-identity change on a long-shipped metric: old `{method,status}` series
freeze at upgrade and new `{method,status,principal_class}` series start at
zero. Plain selector queries and `sum by (method, status)` keep working;
re-baseline any dashboard or alert that matches the exact label set or joins
on series identity.

## ⚠️ Breaking: account lockout is ON by default

This release adds account lockout for failed **local-password** logins (SOC 2
CC6.3) and it is **active by default** (`--auth-lockout-threshold=5`,
`--auth-lockout-window-secs=900`) **on any deployment that runs with a
persistent auth database** — i.e. one started with `--data-dir`.

> **⚠️ `--data-dir` is required.** Lockout state lives in the persistent
> `auth.db`, which only exists when the server is started with `--data-dir`.
> The shipped **container images and compose files** pass `--data-dir
> /var/lib/yuzu`, so lockout genuinely is on by default there. The
> **systemd/.deb** unit now also passes `--data-dir /var/lib/yuzu` (added in
> this release) — but if you run a **custom invocation** without `--data-dir`,
> the server falls back to in-memory auth and lockout (and session persistence)
> is silently **off**. The server logs a loud startup `WARN` in that state.
> Set `--data-dir` to make the control active.
>
> **Superseded by the AuthDB→Postgres migration (see below).** Lockout state
> now lives in **Postgres** (`users.failed_login_count` / `locked_until`), not
> `auth.db`. It is active whenever `--postgres-dsn` (or `YUZU_POSTGRES_DSN`) is
> set — which the server now **requires to boot at all** (no SQLite fallback) —
> and `--data-dir` no longer gates it. Read the `--data-dir` requirement above
> as historical, for pre-migration builds only.

No further config change is required to opt in — a deployment that already runs
with `--postgres-dsn` gains the behavior the instant you start the new build.

What changes on upgrade:

- After **5 consecutive failed `POST /login` attempts** a local-password account
  is locked for **15 minutes**. While locked, every login attempt — *including
  one with the correct password* — returns the **same generic 401 as a bad
  password** (no `Retry-After`, no "you are locked" message; this is deliberate,
  to avoid a username-enumeration / lock-state oracle).
- The lock **auto-expires** after the window — it is never permanent — and a
  user who waits it out regains a full attempt budget.
- Scope is **local-password only**. SSO/OIDC logins (throttled by your IdP) and
  API/automation tokens are **unaffected** — no automation breakage.

**Highest-risk targets** on upgrade: shared or service accounts that log in with
a password, and any password-rotation / monitoring automation that may submit a
stale password in a loop — these can now lock themselves out where previously
nothing happened.

**Before upgrading, do ONE of:**

1. Accept the default (recommended for most) — it closes a real
   credential-stuffing surface. Make sure operators know the recovery path
   below.
2. Raise the threshold if you also rate-limit at the network layer
   (NIST 800-63B §5.2.2 suggests ≥10): `--auth-lockout-threshold=10`.
3. Disable it (not recommended; constitutes a deviation from the CC6.3 hardened
   baseline): `--auth-lockout-threshold=0` (the server logs a startup `WARN`).

**Recovery if an account is locked out:**

- Another admin can clear it immediately:
  `POST /api/v1/users/{username}/unlock` (`UserManagement:Write`, MFA step-up).
- Or wait out the window (default 15 min).
- **Single-admin deployments:** there is no self-service unlock for the *only*
  admin (the unlock endpoint requires a second privileged principal), so either
  wait out the window or use the offline recovery procedure in
  `docs/ops-runbooks/auth-db-recovery.md` § Account lockout recovery. That
  runbook is now Postgres-native throughout: its fallback clears
  `failed_login_count` / `locked_until` with `psql "$YUZU_POSTGRES_DSN"`
  against `auth.users`, which is exactly the sole-admin case. It writes no
  audit row, so record it in your change-management system.

## Behaviour change: operator/API tags now beat agent self-report (#1411)

An agent's self-reported tags (`scopable_tags`, synced on every Register) can no
longer overwrite an operator- or API-set tag for the same `(agent_id, key)` — the
operator/API value is now authoritative. This closes a path where a rogue or
misconfigured agent could self-assign into an operator-declared benchmark cohort.

**Who this affects:** only an operator who *deliberately* relied on agent-reported
values winning over an operator/API-set tag for the same key. After upgrade those
agent values stop overriding — silently (no error, no log line); an affected device
simply drops out of the cohort the operator-set value defines.

**Verify:** audit the `source` field via MCP `get_tags` — `GET /api/v1/tags` does not
expose `source`, only `key`/`value` pairs (see the read-side note below) — to see whether
each key is `api`/`mcp`-sourced (operator/API) or `agent`-sourced.

**Read-side completion (#3295):** #1411 closed the write-time overwrite; scope-DSL
`tag:<key>` evaluation (dispatch targeting, management-group membership) had its own,
separate precedence — a currently-connected agent's live self-report answered before the
store was even consulted. That is now also store-first: an operator/API-set row always
wins for scope-DSL purposes too, and an agent-claimed `service` value never answers from
the live self-report at all (it is dropped at registration, not just at store sync).
**Who this affects:** an operator who deliberately relied on a live agent's tag value
overriding an operator/API-set tag specifically for dispatch targeting or cohort
membership while that agent stayed connected. See `docs/asset-tagging-guide.md` "Tag
source precedence (read time, scope-DSL, #3295)".

**Caution:** the `/devices` tag-chip display is unaffected by this change and can now
visibly disagree with what actually governs targeting: it renders only the agent's live
self-report, never the TagStore row, so a store value that now wins for dispatch
purposes — of any source, including a previously-synced agent value that's now stale
relative to the agent's live report, not only an operator-set one — may not be what the
dashboard chip shows. When a store row exists for the key, MCP `get_tags` (its `source`
field) is the source of truth for what governs a device's scope-DSL matching, not the
dashboard; `GET /api/v1/tags?agent_id=<id>` does not expose `source`. For a
gateway-proxied or not-yet-synced agent with no store row at all, the live self-report
(what the dashboard shows) is what actually governs — an empty `get_tags`/`GET
/api/v1/tags` result for a key means the live claim decides, not that nothing does.

**Remediate:** if an agent-reported value was the *intended* one, re-set it explicitly
via the REST API (writes `source=api`) or MCP `set_tag` (writes `source=mcp`) — either is
authoritative over an agent-sourced row. Keys the agent reports that the operator never
set are unaffected.

## Behaviour change: MCP approval-gated calls use ticket-then-recall (-32006) (#289)

Supervised-tier MCP tokens that attempt an approval-gated operation (e.g. `delete_tag`,
`quarantine_device`) now run through a **ticket-then-recall** approval flow. The first
call returns JSON-RPC error `-32006` (`ApprovalRequired`) whose `error.data` carries an
`approval_id` and a `status_url` (`GET /api/v1/approvals/{id}`). After a second principal
approves the ticket, the caller re-invokes the same tool with the `approval_id` and the
operation executes (the ticket is consumed exactly once, args-bound, replay-rejected).

> An earlier development iteration returned `-32004` (`TierDenied`) for these operations
> because the approval re-dispatch path was unbuilt. That intermediate behaviour **never
> shipped in a release** and is fully superseded by the flow above — there is no `-32004`
> approval-denial in the released product.

**Who this affects:** any MCP client that matched on the approval-gated denial. Match
`-32006` and read `error.data.approval_id` / `status_url` to drive the approval workflow;
`operator`-tier executions are auto-approved and are unaffected. On the REST transport an
approval-gated operation by an MCP-tier token is denied (there is no JSON-RPC ticket
channel on REST) — use the MCP `/mcp/v1/` flow or the dashboard.

Three review-round hardenings in the same release (PR #1796):

- **Supervised REST quarantine is now mirror-denied.** `POST /api/v1/quarantine` and
  `DELETE /api/v1/quarantine/{agent_id}` return `403` for a supervised-tier token. An
  operation-mapping mismatch previously let a supervised token quarantine via REST with
  **no approval** — if any automation relied on that, it was riding the bug; route it
  through the MCP `quarantine_device` ticket flow or use a non-tiered token.
- **Approved-but-unconsumed approval tickets expire after 7 days** (measured from the
  review). An approved ticket is a live one-time capability; it now ages out on the same
  window as unreviewed pending requests. Recalling an expired ticket returns the standard
  "approval was expired" denial — submit a fresh request.
- **`consumed_by` traceability column** (additive, auto-migrated): the approvals store
  records WHO recalled each consumed ticket alongside the existing `consumed_at`
  (SOC 2 CC7.2 evidence chain: `submitted_by` → `reviewed_by` → `consumed_by`).

## Behaviour change: `POST /api/v1/tokens` now honors `mcp_tier`

The token-mint endpoint now applies the `mcp_tier` field from the request body
(`readonly` / `operator` / `supervised`). Previous releases **silently dropped**
it: a token requested with an `mcp_tier` was stored **tier-empty** (RBAC-deferred),
which means it was *over-privileged* relative to the tier the operator intended —
a `readonly` request behaved as a full RBAC-scoped token, not a read-only MCP
token. The endpoint also now validates at mint time: an unrecognised tier, or a
tiered/service-scoped token whose `expires_at` is missing or more than 90 days
out, returns `400` (previous releases returned a misleading `503`).

**Who this affects:** any operator who minted an MCP token via `POST /api/v1/tokens`
**before** this upgrade and relied on the `mcp_tier` to constrain it. Those tokens
are still tier-empty and therefore broader than the requested tier.

**Remediate:** **rotate any pre-upgrade `mcp_tier` tokens** — revoke the old token
(`DELETE /api/v1/tokens/{id}`) and re-mint it; the new token stores the tier and is
constrained as intended. Tokens minted with no `mcp_tier` are unaffected.

**Additive (no operator action required):** the `discover_plugins` discovery response
(REST `GET /api/v1/discover/plugins` and the MCP tool) is now `version: 2` — it adds an
inline `parameter_schema` per action (where a published `InstructionDefinition` exists and
the caller holds `InstructionDefinition:Read`) plus a top-level `actions_enriched_with_schema`
count. The change is purely additive; any client that pinned `version == 1` should relax the
check to a minimum (`>= 1`).

## ⚠️ Breaking: API and MCP bearer tokens are invalidated on upgrade (ApiTokenStore → Postgres, ADR-0030)

`ApiTokenStore` — the store backing every `Authorization: Bearer` API token and
every MCP token — moves from SQLite (`api-tokens.db`) to the server's PostgreSQL
substrate in this release (engine-principals PR 4.1; ADR-0006/ADR-0030). This is
a **fresh-start cutover with no data migration**: the new server creates an empty
Postgres `api_token_store.api_tokens` table and **never reads the old
`api-tokens.db`**, so every API/MCP token minted before the upgrade stops working
the instant the new server starts. Interactive cookie-session login (dashboard,
OIDC/SAML SSO) is **not** affected — only bearer tokens.

The rationale for no backfill (convention with every prior server-store migration,
plus the token store holds only verify-only hashes) is in ADR-0030.

**Who this affects:** every external automation consumer that authenticates with an
API or MCP bearer token — CI/CD scripts, SIEM/webhook pollers, cron jobs, MCP
clients. Because it is a fresh-start cutover, **all of them break at once** at the
moment of upgrade; there is no rolling/staged token continuity.

**Remediate:** after upgrading, **re-mint every API/MCP bearer token** (`POST
/api/v1/tokens`) and update the credential wherever it is stored (CI secrets, cron
configs, MCP client configs). Plan the upgrade in a **maintenance window** and
**notify automation/integration owners in advance** so a batch of `401`s across
every integration is expected, not a surprise incident.

**Diagnostic:** if the legacy `api-tokens.db` is still on disk, the server logs
`[auth] Legacy SQLite api-tokens.db found at … — API/MCP tokens now live in
PostgreSQL and any prior tokens were INVALIDATED by the migration (ADR-0030)` at
boot. The old file is inert (never read again) and can be removed once you have
re-minted; it contains only token hashes + metadata, no plaintext secret.

**Multi-instance note:** the Postgres substrate now permits running multiple server
replicas against one database. Token *validation* uses a per-process 60-second
cache, so a token revoked on one replica may remain accepted on another replica for
up to that window — see ADR-0030 for the tracked hardening.

## ⚠️ Breaking: `engine:` namespace reservation — server refuses to start on a pre-existing collision (engine principals PR 4.2)

This release introduces the **engine principal** class — a distinct identity
class for autonomous/agentic callers, stored in the new `EnginePrincipalStore`
and resolved through RBAC/`ApiTokenStore` (design doc §3.1/§3.3). To make that
resolution unambiguous, the `engine:` prefix is now a **reserved namespace**
for both local usernames (`users.username`) and local RBAC group names
(`groups.name`).

**Pre-upgrade collision check** (mirrors the plugin-trust-bundle filename
collision check above). At boot, the server now scans for any pre-existing
`engine:`-prefixed local user or local RBAC group and **refuses to start** if
it finds one — silently coexisting with (or being shadowed by) a real engine
principal is not an acceptable outcome, so this fails closed rather than
booting into an ambiguous state (decision log #3). Before upgrading, run
against both stores.

> **Superseded by the RbacStore → PostgreSQL migration (ADR-0041):** the
> per-node `sqlite3 rbac.db` query below is a HISTORICAL artifact from the era
> when local RBAC groups were SQLite. RBAC config is now a **single shared
> PostgreSQL** `rbac_store` schema, so run **one** `psql` query, **not**
> per-node `sqlite3`. Both queries below target Postgres:

```bash
# Local users — Postgres.
psql "$YUZU_POSTGRES_DSN" -c \
  "SELECT username FROM auth.users WHERE username LIKE 'engine:%';"

# Local RBAC groups — PostgreSQL (shared; one query, not per-node — ADR-0041).
psql "$YUZU_POSTGRES_DSN" -c \
  "SELECT name FROM rbac_store.groups WHERE source = 'local' AND name LIKE 'engine:%';"
```

If either query returns rows, rename or remove those users/groups **before**
upgrading — the new server will not boot until the collision is cleared (or,
if the boot-time collision scan itself fails, e.g. a mid-scan database error,
the server also fails closed rather than guessing). See
[`docs/ops-runbooks/engine-principal-store-recovery.md`](../ops-runbooks/engine-principal-store-recovery.md)
for the full recovery procedure if you hit this at boot.

**Scope of this release:** PR 4.2 ships the engine-principal store, RBAC
resolution, and attribution plumbing only — there is **no operator-facing
surface yet** (no dashboard/REST CRUD for minting or managing engine
principals). That ships in PR 4.3.

## ⚠️ Breaking: `--mfa-enforcement` now enforces

Releases before this one accepted `--mfa-enforcement=admin-only` and
`--mfa-enforcement=required` but treated them as **no-ops** (the parser
accepted the value for forward-compat and the server emitted a startup
`WARN`). **This release makes them enforce.** If you staged the flag based
on that prior documentation, enforcement goes live the instant you start
the new build.

What changes on upgrade if the flag is set to `admin-only` or `required`:

- An **un-enrolled** user covered by the mode can no longer log in directly.
  `POST /login` returns a 202 `mfa_enrollment_required` challenge and the
  user must complete TOTP enrollment (scan QR → enter first code at
  `POST /login/mfa/enroll`) before a session is minted. This is a no-lockout
  bootstrap, **but** it requires the user to enroll at their next login.
- The startup log line for non-default modes changes from `WARN` (no-op) to
  `INFO` (enforcement active).
- An operator can no longer disable their own MFA while the mode protects
  their role.

**Before upgrading with the flag set, do ONE of:**

1. **Recommended:** leave the flag at `optional`, upgrade, have all affected
   users enroll (Settings → Multi-Factor Authentication), *then* set
   `admin-only`/`required` and restart. or
2. Upgrade with the flag set and accept that affected un-enrolled users will
   be walked through enrollment on their next login.

**SSO / OIDC pre-flight (required reading if you use SSO):** under
`required` (and `admin-only` for admin SSO users), OIDC sessions are
MFA-gated by the IdP's `amr` claim — an SSO login the IdP did **not** MFA
is blocked from high-risk endpoints (it must re-authenticate via SSO),
symmetric with a local user being forced to enrol. Yuzu cannot mint a
second factor for an external identity, so **before enabling
`required`/`admin-only` with SSO you MUST verify your IdP asserts an `amr`
claim containing a recognized MFA method** (Entra: `mfa`; others:
`otp`/`hwk`/etc., RFC 8176). If it does not, affected SSO users will be
unable to reach high-risk endpoints — recoverable by restarting in
`optional` (see `docs/ops-runbooks/auth-db-recovery.md` § "Locked out by MFA
enforcement misconfiguration"; that runbook is now Postgres-native throughout).
Under `optional`, no IdP `amr` configuration is required (SSO sessions pass
the gate).

**Single-admin deployments:** do not first-boot a fresh single-admin
deployment straight into `required`. Enroll the admin under `optional` first,
then switch. If you do start with `required`, the admin must complete
login-time enrollment within `--mfa-login-pending-secs` (default 120s); if
the token expires, restart with `optional`, log in, enroll, then re-enable.

**Recovery if you get locked out** (IdP doesn't assert `amr`, or the sole
admin can't enroll): restart the server with `--mfa-enforcement=optional`
(this re-seeds the in-memory config), log in, resolve enrollment, then
re-enable. See `docs/ops-runbooks/auth-db-recovery.md` — that runbook is now
Postgres-native throughout, so both the restart procedure above and its SQL
steps apply as written to a Postgres-backed AuthDB.

## Hardened auth mode (`--auth-mode=sso-only`) — opt-in (SOC 2 CC6.3/CC6.6)

**No operator action on upgrade.** Existing deployments default to
`--auth-mode=standard` and behave exactly as before. This release adds the
*option* to disable local-password login fleet-wide so only an SSO provider can mint a
session.

If you intend to enable `sso-only`, do this **first** — the server **fails
closed (non-zero exit, refuses to serve)** otherwise:

1. Configure OIDC (`--oidc-issuer` + the related flags) and confirm SSO works in
   `standard` mode. `sso-only` without an SSO provider (OIDC, or a complete SAML
   SP config on Linux/macOS with HTTPS) refuses to start (it would lock every
   operator out).
2. (Recommended) Create a single break-glass local account and **enroll MFA on
   it** (Settings → Multi-Factor Authentication). Point `--break-glass-user` at
   it. `sso-only` refuses to start if the named break-glass user doesn't exist or
   has no MFA enrolled — a break-glass account must carry a second factor.
3. Restart with `--auth-mode=sso-only`. Local-password login is now rejected for
   everyone except the break-glass account, and only **while armed**.

**Breaking the glass (IdP outage).** The break-glass account is dormant until
armed out-of-band on the server host: `yuzu-server --break-glass-arm
--break-glass-user <name> --config … --data-dir … --postgres-dsn …` arms it for
`--break-glass-window-secs` (default 24 h, auto-expiring). It still requires the
account's MFA at login. Since the AuthDB→Postgres migration this one-shot opens
the **Postgres** auth store, so `--postgres-dsn` (or `YUZU_POSTGRES_DSN`) is
**required** — point it at the same database the server uses; without it the
command fails closed with "requires the Postgres auth store" and does nothing.
`--data-dir` is still needed for the audit record. Full runbook:
`docs/ops-runbooks/auth-db-recovery.md` § Break-glass arm (that runbook is now
Postgres-native throughout).

**Migration.** `break_glass_armed_until` is a nullable column on `auth.users`.
It arrived as SQLite `auth.db` migration v4, but the AuthDB→Postgres cutover
folded every historical migration into the born-on-PG schema, which starts at
**v1** — there is no v4 to apply and no rollback-past-v4 question. See the
AuthDB→Postgres section above for the (fresh-start, no-backfill) upgrade
contract that replaces it.

## ⚠️ Breaking: server generates default TLS certificates on first boot (v0.13.0)

Before v0.13.0 the server **refused to start** without operator-provided certs
(or `--no-tls`/`--no-https`). From v0.13.0, when a TLS surface has no certs the
server **auto-generates a per-install ECDSA CA + leaf certs** on first boot and
serves encrypted with no operator action.

Impact by prior configuration:

| Prior startup flags | After upgrade |
|---|---|
| `--cert`/`--key` (+ `--https-cert`/`--https-key`) supplied | No change — operator certs always win; defaults are never generated for a supplied surface. |
| `--no-tls --no-https` (plaintext dev) | No change — both surfaces disabled; no certs generated. |
| `--no-tls` only (HTTPS previously errored without certs) | **HTTPS now serves an auto-generated default cert** instead of failing. The agent surface stays plaintext. |
| No cert flags (previously refused to start) | **Now starts, encrypted, on default certs**, with a loud banner. |

What to expect / do:

- **Browsers show an untrusted-issuer warning** for the dashboard until you trust
  the per-install CA (`<ca-dir>/default-ca.pem`, default `/etc/yuzu/certs`) or
  replace the cert with `--https-cert`/`--https-key`. The connection is encrypted;
  only issuer verification is missing.
- **Agents:** while on default certs the agent listener is encrypted but does
  **not require** client certs (per-agent mTLS arrives in a later release).
  Agents that previously connected over plaintext must switch to TLS — point them
  at the CA with `--ca-cert <ca-dir>/default-ca.pem`.
- **To keep the legacy refuse-to-start behaviour**, pass `--no-default-certs`.
- **Back up `<ca-dir>/default-ca.key` (0600) and the `ca_store` Postgres schema**
  (`pg_dump`/`pg_restore`, ADR-0053) — losing the CA key forces a full fleet
  re-enrollment.
- Relocate the cert directory with `--ca-dir` (e.g. a dedicated container volume).

## Generic inventory store no longer reads or scrubs a legacy `inventory.db` (ADR-0037)

`InventoryStore`'s one-time first-boot backfill from a legacy `inventory.db` SQLite file
(`migrate_from_sqlite()`) has been retired (#3623) — no production fleet ever ran a
pre-Postgres build, so there was no real legacy data to migrate. Two separate behaviors changed:

- A reachable Postgres database whose schema can't migrate or open **is** still a fatal startup
  error (fail-closed), same as before.
- A legacy `inventory.db` file with real content **does NOT** fail startup and its content is
  **never imported** — the server opens it read-only, purely to count rows in `inventory_data`
  for a diagnostic warning, then boots regardless of what it finds.
- **`delete_agent()` no longer erases anything from a legacy `inventory.db` either** — the
  previous "erase from Postgres AND the retained legacy SQLite copy" behaviour is gone. A
  leftover legacy file is inert: never read on boot beyond the diagnostic warning above, and
  never scrubbed by a device decommission. If your environment genuinely still has a legacy
  `inventory.db` you need gone (e.g. for a completed decommission's data-retention obligations),
  delete it manually.

**Verify:** after the server reports ready, generic inventory reads (`GET /api/v1/inventory` or
equivalent) behave exactly as before — this store's runtime read/write/query behavior is
unchanged, only the one-time backfill and the legacy-file erasure are gone.

**Rollback caution.** Rolling back to a build older than this release, against a database that
has already run this store's retirement migration, **unconditionally** fails that older
binary's boot with a Postgres `undefined_table` error on its own idempotency-marker check — not
only when a legacy `inventory.db` happens to be present. This is a deliberate fail-safe (a clear
startup error, never silent data loss), not a bug, but it means "just roll back the binary" is
not a supported recovery path once this migration has run. The same is true for
CaStore/ManagementGroupStore/QuarantineStore/WebhookStore below, each for its own dropped marker
table. RbacStore is the one genuine exception (see its own section): its retirement migration
**poisons** the marker rows to a sentinel value rather than deleting them, so an old binary's own
lookup finds them present (not 0 rows) and — reading a value it understands as "no verified
source, but not a failure" — boots normally UNLESS a real, unmigrated legacy file is also present
on that specific host. This is RbacStore's own deliberate choice to tolerate rollback, not an
artifact of a row count. AuditStore also removes marker rows rather than dropping a table, but do
NOT assume it behaves the same way as either group — its own section explains why an old binary's
boot fails just as reliably as the DROP-TABLE group's, via a CHECK constraint rather than a SQL
error on a missing table.

## ⚠️ Behaviour change: internal-CA store moves to Postgres (ADR-0053)

`CaStore` (internal-CA root metadata, issued-certificate inventory, CRL version
history — everything the mTLS-accept revocation gate and `GET /api/v1/ca/*`
read) moves from the SQLite `ca.db` file to the server's PostgreSQL substrate
in this release (schema `ca_store`). The private CA root key is unaffected —
it was never in `ca.db` and stays a local file behind `KeyProvider` (`--ca-dir`).

- **No legacy-SQLite migration path.** No production fleet ever ran a
  pre-Postgres build of this store, so there was no real `ca.db` data to carry
  over — the one-time backfill this section originally described was retired
  under ADR-0009's fresh-start-by-default amendment (see ADR-0053's Update). A
  reachable Postgres database whose schema can't migrate or open is still a
  fatal startup error (fail-closed); a legacy `ca.db` file with real content
  does NOT fail startup and its content is never imported — the server opens
  it read-only, purely to count rows in `ca_root`/`ca_issued`/`ca_crl_versions`
  for a diagnostic warning, then boots regardless of what it finds.
- **New fail-closed-at-boot behaviour.** A genuine Postgres error while wiring
  the per-agent mTLS revocation checker at boot now refuses to start the
  server, rather than starting with revocation enforcement silently unwired.
  If the server previously started cleanly on a working Postgres connection,
  this changes nothing observable; it only changes what happens during a
  Postgres outage at exactly that boot step, from "starts degraded" to
  "refuses to start."
- **`GET`/`POST /api/v1/ca/*` and the CA MCP tools now return a `503`/internal
  error on a genuine database error**, instead of a silently-empty or
  silently-false result.
- Every other CA behavior — revocation semantics, CRL numbering, the single
  `sign_agent_csr` chokepoint — was unchanged by that migration. CRL numbering and
  publication were later reworked for multiple server replicas (HA WS-6 slice 6.1):
  see `docs/user-manual/server-admin.md` "vNEXT — CRL publishing is serialised in
  Postgres". Detail: `docs/pki-architecture.md`,
  `docs/adr/0053-ca-store-postgres-migration.md`.
- **Rollback caution:** see the InventoryStore section's "Rollback caution" note above — the
  same unconditional rollback-refusal applies to this store (its own dropped marker table).
- **New: an established, already-running default-cert install can now self-heal
  its own listener leaves without operator action.** This is not limited to a
  first-boot crash window — any boot where the on-disk `--ca-dir` default
  leaves are missing, corrupt, or a leaf was later lost (a bad partial restore,
  a lost volume file) hits the same path, as long as `ca_store` already holds
  a root and this instance's local CA key file still matches it. When that
  holds, the server automatically **re-mints its own https/server/gateway
  leaves with fresh private keys** under the existing root and resumes,
  instead of refusing to start. It never touches the CA root itself or any
  agent-issued certificate. Every occurrence logs a `spdlog::warn` line, but
  there is currently no dedicated audit-log row for it (unlike enrollment-time
  `ca.cert.issued`) — tracked as a follow-up, not fixed in this release.
- **HA note: a losing first-boot replica self-heals within the same boot attempt
  (UP-3), bounded.** Multiple server instances sharing one `--ca-dir` cert
  volume and one `ca_store` Postgres substrate is not an officially supported
  deployment topology today (see ADR-0053's Decision section) — this note
  describes what happens if it's done anyway, safely, not a recommendation to
  do it. If two instances start against the same fresh `ca_store` at once,
  exactly one wins the root race and generates the live default certs; the
  other polls the shared cert directory for up to 15s for the winner's
  complete set to land (it only adopts a fully-written set — the winner's
  completion marker is written last, so a partial/in-flight write is never
  picked up) and, on success, continues booting on the winner's certs without
  a restart. If the winner hasn't finished within that window (a slow
  Postgres, lock contention, or a winner that's itself still starting up), the
  loser falls back to the original behavior: it **exits** (refuses to start,
  non-zero) rather than serving with its own discarded material — it does not
  reach a running-but-unready state, so a readiness-probe-driven restart never
  applies here. Recovery in that case is a plain process-supervisor restart
  (systemd `Restart=on-failure`, Kubernetes `restartPolicy`) once the winner's
  certs are in place, so the losing instance picks them up from disk on its
  next boot attempt. On systemd specifically, a slow winner (e.g. Postgres
  itself under load) can interact with the crash-loop guard
  (`StartLimitBurst`/`StartLimitIntervalSec`) — a losing replica that exhausts
  its restart budget first lands in the service's "failed" state and needs a
  manual `systemctl reset-failed` once the winner has actually finished,
  rather than retrying forever on its own. Diagnosing a bootstrap that seems
  permanently stuck (neither replica ever finishes): check `pg_locks` for a
  lingering `yuzu:default_certs_bootstrap` session advisory lock with no live
  backend behind it (a host crash or network partition can leave one held
  until Postgres notices the dead session) and `pg_terminate_backend` it — see
  `docs/pki-architecture.md`'s operator runbook.

## ⚠️ Behaviour change: webhook store moves to Postgres (ADR-0057)

`WebhookStore` (operator-registered outbound webhooks and their delivery log —
everything behind `GET`/`POST`/`DELETE /api/webhooks` and
`GET /api/webhooks/{id}/deliveries`) moves from the SQLite `webhooks.db` file
to the server's PostgreSQL substrate in this release (schema `webhook_store`).
The webhook HMAC signing secret is now envelope-encrypted at rest
(`SecretCodec`, AES-256-GCM, ADR-0010) instead of a plaintext column.

- **No legacy-SQLite migration path.** No production fleet ever ran a
  pre-Postgres build of this store, so there was no real `webhooks.db` data
  to carry over — the mandatory, both-tables backfill this section originally
  described was retired under ADR-0009's fresh-start-by-default amendment
  (see ADR-0057's Update). A reachable Postgres database whose schema can't
  migrate or open is still a fatal startup error (fail-closed); a legacy
  `webhooks.db` file with real content does NOT fail startup and its content
  is never imported — the server hardens it to 0600 (main file and any
  `-wal`/`-shm`/`-journal` sidecars, since it may still hold a pre-cutover
  signing secret in plaintext — POSIX only, a no-op on Windows, #3593) and
  counts rows in `webhooks`/`webhook_deliveries` for a diagnostic warning, then
  boots regardless of what it finds. There is no move-aside: the legacy
  file stays at its original path.
- **New fail-closed-at-boot behaviour.** A Postgres/`SecretCodec` error at any
  point in this store's boot sequence (schema migration or KEK verification)
  now refuses to start the server, rather than starting with webhooks
  silently unwired.
- **If you have a real `webhooks.db` you need re-imported:** there is no
  automated recovery path — recreate the webhooks (and, if used, their
  signing secrets) via `POST /api/webhooks` after the server starts. See
  [`rest-api.md`](rest-api.md#post-apiwebhooks) for guidance on securely
  disposing of a legacy file that still holds a plaintext secret.
- **If you already upgraded through an EARLIER release** (one where the
  now-retired backfill genuinely ran), check for a `webhooks.db.migrated-
  <unix-epoch>` file (and its `-wal`/`-shm` sidecars) at the same directory —
  that historical rename-on-success behavior is gone in this release (a
  legacy file is never renamed any more), but a file it already produced is
  NOT cleaned up by this upgrade and still holds every pre-cutover signing
  secret in **plaintext**. Dispose of it securely if you no longer need it;
  the current probe only checks the un-renamed `webhooks.db` path, so it will
  never warn about a `.migrated-<epoch>` file left over from before.
- **Rollback caution:** see the InventoryStore section's "Rollback caution" note above — the
  same unconditional rollback-refusal applies to this store (its own dropped marker table).
- **`POST`/`DELETE /api/webhooks` now distinguish a caller error from a store
  failure**: `POST` returns `400` for an invalid URL scheme (previously an
  ambiguous non-error response), and `GET`/`POST`/`DELETE /api/webhooks`
  (list/create/delete) return `503` on a genuine database error instead of a
  silently-empty or silently-failed result. `GET /api/webhooks/{id}/deliveries`'s
  degrade-vs-error handling specifically is unchanged by this migration — a
  degraded read there still renders an empty delivery list rather than a
  `503`, the same as before the cutover.
- **`GET /api/webhooks/{id}/deliveries`'s `?limit=` handling changed.**
  `limit=0` (or any non-positive value) previously meant "return zero rows";
  it now falls back to the default of 50, the same as an omitted `limit`. A
  value above 10000 was previously passed through unbounded; it is now
  silently capped at 10000. If your integration relies on `limit=0` meaning
  "give me nothing," or on retrieving more than 10000 rows in one call,
  update it.
- Every other webhook behavior — event-type matching, HMAC-SHA256 signature
  format (`X-Yuzu-Signature: sha256=<hex>`), unsigned delivery when no secret
  is configured — is unchanged. Detail:
  `docs/adr/0057-webhook-store-postgres-migration.md`.

## ⚠️ Behaviour change: response history resets on Postgres cutover (ADR-0039)

`ResponseStore` (agentic command/instruction results — the executions drawer
and TAR read source) moves from the SQLite `responses.db` file to the server's
PostgreSQL substrate in this release (ADR-0006 Wave 1, schema `response_store`).
Like the `ApiTokenStore` and AuthDB cutovers, this is a **fresh-start cutover
with no data migration** — response results are expendable, TTL'd telemetry
(ADR-0009 skippable backfill), so the legacy `responses.db` is **never read** on
upgrade.

**What happens on first PG boot:**
- The server logs a one-time `response history reset on Postgres cutover`
  warning.
- Executions-drawer and TAR views for commands issued **before** the cutover
  are empty; results for commands issued after are unaffected and refill
  immediately as agents report.
- No operator action required. To preserve pre-cutover response history,
  export it from the old `responses.db` before upgrading (see
  `docs/user-manual/response-store.md` → periodic exports).

**Also in this release:** non-UTF-8 bytes in a plugin's output/error (which
the old SQLite `TEXT` column tolerated but PostgreSQL `TEXT` rejects) are now
replaced with the Unicode replacement character (U+FFFD) at ingest — the
response row is still stored and still renders, defanged, rather than being
dropped (governance #1593). Retention moved from an hourly background thread
to a clock-guarded, capped reap on the maintenance tick (no operator-visible
behaviour change beyond the same 90-day default).

## ⚠️ Behaviour change: directory sync state resets on Postgres cutover (ADR-0063)

`DirectorySync` (AD/Entra ID integration — synced users/groups, group
memberships, and group→role mappings) moves from the SQLite
`directory-sync.db` file to the server's PostgreSQL substrate in this release
(migration-programme PR 3, schema `directory_sync`). This is a **fresh-start
cutover with no data migration** (ADR-0009) — the legacy `directory-sync.db`
is **never read** on upgrade.

**What happens on first PG boot:**
- The server logs a one-time `DirectorySync initialized (schema
  directory_sync) — fresh start, no legacy backfill` line, and a separate
  warning naming a row count if the legacy `directory-sync.db` still holds
  synced users/groups/mappings.
- `GET /api/directory/users`, `GET /api/directory/status`, and the group→role
  mapping list all start empty.
- **Before upgrading, capture your current group→role mappings** (they will
  NOT survive the cutover): `PUT /api/directory/group-mappings` with an empty
  `{"mappings": []}` body is a safe, non-mutating read — an empty input array
  is a no-op, and the response always echoes the store's full current
  mapping list regardless. There is no dedicated read-only endpoint for this
  today; save the response's `mappings` array (each entry
  `{"group_id": "...", "role_name": "..."}`) somewhere durable before you
  upgrade.
- **Operator action required, after upgrading:** re-run `POST /api/directory/sync` with the
  same `tenant_id`/`client_id`/`client_secret` you already supply on every
  sync call — this store never persisted the credential, so this migration
  adds no new credential-gathering step, but you still need it in hand to
  re-populate synced users and groups. Then re-apply every mapping you saved
  above via one `PUT /api/directory/group-mappings` call with body
  `{"mappings": [{"group_id": "...", "role_name": "..."}, ...]}` — those
  mappings ARE lost by the cutover and must be recreated from your saved copy.
  **Verify the re-sync captured everything**: compare `GET
  /api/directory/status`'s `user_count`/`group_count` against your Entra
  tenant's own user/group counts before considering the upgrade complete.
- The MCP `export_access_review`/REST access-review export's optional email
  enrichment (matched off synced users' UPN) is unaffected in shape — it
  degrades to "no enrichment" until the first post-upgrade sync completes,
  exactly as it already did whenever directory sync was never configured.

**Also in this release:** `directory_memberships` gained a real foreign key
(`ON DELETE CASCADE` on both `user_id` and `group_id`) — the SQLite era had
none. `/readyz` and `/healthz` now report `directory_sync` — the SQLite-era
store was never checked at boot or reflected in either probe.

**Behaviour change beyond the storage cutover itself:** a user or group
deleted from Entra now actually disappears from `DirectorySync` on the next
successful sync — the SQLite era kept every previously-synced user/group
around forever, upserting but never removing one Entra had deleted. If your
integration (or a saved report) relied on a removed identity remaining
visible via `GET /api/directory/users`/`GET /api/directory/status` after
leaving Entra, it will stop being visible starting with the first
post-upgrade sync. Relatedly, a malformed/unexpected Microsoft Graph groups
API response is now a hard sync failure (surfaced in
`GET /api/directory/status`'s `last_error`) rather than a silently-empty
group sync — this closes a gap the deletion behavior above would otherwise
have introduced (a transient Graph glitch wiping every synced group).

## ⚠️ Behaviour change: schedules, approvals, and execution history reset on Postgres cutover (ADR-0065)

`ScheduleEngine`, `ApprovalManager`, and `ExecutionTracker` move from the
shared SQLite `instructions.db` file (via `InstructionDbPool`) to their own
independent PostgreSQL schemas in this release (migration-programme PR 5,
the last of the components the postgres-migration ladder had never tracked
— `WorkflowEngine`/ADR-0064 having already made the same move in PR 4 —
schemas `schedule_engine`, `approval_manager`, `execution_tracker`
respectively). This is a **fresh-start cutover with no data migration**
(ADR-0009) — the legacy `instructions.db` is **never read** for data on
upgrade. `InstructionDbPool` itself is deleted; `instructions.db` is retired
and no Yuzu store writes to it again.

**Before upgrading, capture what you'll lose** (none of it carries over):
`GET /api/schedules`, `GET /api/approvals`, and `GET /api/executions` are
safe, non-mutating reads — use them to record your active recurring
schedules and any outstanding (pending or approved-but-unconsumed) approval
tickets before you cut over, so you know what to re-create afterward rather
than discovering gaps after the fact. `GET /api/executions` defaults to the
100 most recent rows (`?limit=<N>` to raise it — there is no offset/cursor
parameter) — for a fleet with more history than that, raise the limit
before relying on this as a full capture. **This capture step runs on the
pre-upgrade binary, which necessarily predates #3789** — the ADR-0065 Postgres cutover this
section documents shipped before #3789 did, so any binary old enough to still need this
procedure cannot yet carry #3789's `limit` cap; raise `?limit` as high as needed for this
specific step. (A binary that already carries #3789, by contrast, caps `GET /api/executions`'
`limit` at 500 regardless of the value requested, with no offset/cursor to page past it — see
`docs/user-manual/rest-api.md`'s "Executions" section — but that cap cannot bite on this
already-completed cutover's capture step.) The retired `instructions.db` file is **left on disk,
not deleted** — if you need to recover consumed-approval audit evidence
(the `submitted_by → reviewed_by → consumed_by` chain) after upgrading,
that file is the most complete source (the audit store also carries
`approval.approve`/`approval.reject` and `mcp.<tool>` consume events for
the same tickets, but not the full row); back it up separately before any
unrelated disk cleanup removes it, since Yuzu itself never will.

**What happens on first PG boot:**
- The server logs three one-time lines — `ScheduleEngine initialized (schema
  schedule_engine) — fresh start, no legacy backfill`, similarly for
  `ApprovalManager`/`approval_manager`, and `ExecutionTracker`/
  `execution_tracker` — plus a separate warning naming a row count for any
  of `schedules`/`approvals`/`executions`/`agent_exec_status` still present
  in the legacy `instructions.db`.
- `GET /api/schedules` starts empty. **Operator action required:** re-create
  any recurring schedules via `POST /api/schedules`.
- Any MCP or REST instruction-approval ticket pending, approved-but-unconsumed,
  or already consumed at the moment of cutover is gone. **Operator action
  required:** a pending approval must be re-requested by whatever flow
  originally submitted it (MCP `execute_instruction`'s approval gate, a
  scheduled run requiring approval, or a direct REST submission) — there is
  no way to recover an in-flight ticket across the cutover. Consumed-ticket
  audit history (the `submitted_by → reviewed_by → consumed_by` evidence
  chain) does not carry forward either.
- The executions drawer, REST execution routes (`GET /api/v1/executions/{id}`,
  `GET /api/v1/execution-statistics` + its `/agents`/`/definitions` sub-routes),
  and MCP execution-status tools
  (`get_execution_status`, `query_responses`'s execution-id join) all start
  empty. No gRPC `CommandResponse` in flight at the exact moment of upgrade
  has anywhere to land until the next dispatch. No operator action required
  — new executions populate normally from first boot.
- `/readyz` now lists all three stores (`ExecutionTracker` was already
  present, re-keyed off its own `is_open()` instead of the shared pool's);
  `/healthz` gains net-new `schedule_engine` and `execution_tracker` rows —
  neither was ever reported there before this release (`ApprovalManager` was
  already in both, unchanged).

**Also in this release:** `advance_schedule`'s locked select-then-compute-
then-update collapses into one atomic `UPDATE ... RETURNING`, closing a
two-statement race an app-level lock previously covered — no operator-visible
behavior change. `ExecutionTracker`'s one `sqlite3_changes()` call (gating
the terminal-transition SSE event on the shared SQLite connection) is closed
via `UPDATE ... RETURNING`, fixing a latent race under concurrent callers —
also no operator-visible change; the executions-history SSE contract
(progress-before-terminal event ordering) is unchanged. The MCP approval
error envelope's permanent-vs-transient discriminator changes internally
from a raw SQLite extended error code to a Postgres SQLSTATE string — the
same two response shapes are still chosen by the same rule, so no client
migration is needed.

## Behaviour change: `per-device` dispatch can now refuse a target it always accepted before (ADR-1007)

`ExecutionTracker` gains a new table, `concurrency_claims` (same
`execution_tracker` schema introduced above), backing real enforcement of
the `per-device` concurrency mode — the shipped default and the only one of
the five documented modes that was ever actually enforced (see
`docs/user-manual/instructions.md` §8 and ADR-1007 for the full
real-usage audit; `per-definition`/`global`/`global-singleton`/`per-set`
remain accepted but unenforced, unchanged from before this release).

**Operator-visible:** dispatching a `per-device` definition (via `POST
/api/instructions/:id/execute` or a `ScheduleEngine` run) to a device that
already has an execution of that same definition in flight now **excludes**
that device from the target list instead of sending a second, overlapping
command as it always did before. This is the intended fix, not a
regression — but any automation that dispatches the same definition
repeatedly in quick succession to the same fleet (e.g. a tight retry loop)
may see partial dispatch where it previously always saw full dispatch.
Watch the new `yuzu_server_dispatch_concurrency_skipped_total` counter (or
`ExecutionTracker::claim_concurrency_slots`'s `spdlog::info` line, which
reports a count — how many of the dispatch's candidates were already busy
for the definition — not individual device ids) to see when this fires —
the executions API's `agents_targeted` field is the post-claim SENT count,
not a pre-claim total, so there is no "targeted vs. claimed" comparison to
read it against. Error code `3003` (`ConcurrencyBlocked`) is registered for
this condition but not yet surfaced through the dispatch response.

Quarantining a device mid-flight (after it was claimed but before it
reports a terminal status) behaves the same as a crash for this purpose —
its claim ages out at the reconciler's TTL rather than releasing
immediately, so a device released from quarantine may still read as "busy"
for a `per-device` definition for up to that TTL window.

The claim's exclusion window is bounded by a flat one-hour timeout, renewed
by a dedicated agent-core keepalive that runs independently of any given
plugin — so a long-running `script_exec.*` action (a MUTATING instruction —
runs an operator-named program or authored script that can hold real state)
with an operator-configured timeout near the one-hour ceiling stays
correctly excluded even if it produces little or no output. The keepalive
sends one empty gRPC frame every 5 minutes per in-flight `per-device`
command — negligible traffic even at fleet scale, but worth knowing about
if you're diffing agent-to-server wire volume before/after this release.
See ADR-1007 for the full mechanism.

**Rolling-upgrade behaviour:** the keepalive lives in the agent binary, not
the server — during a staged agent rollout, a `per-device` command running
on an agent still on a build older than this release has no keepalive
thread, so its claim relies on the same rarer, less reliable renewal
signals this release replaces (a plugin's own output volume crossing an
internal threshold, or nothing at all for a quiet action). This is a
narrowing of a pre-existing exposure, not a new one — an old agent's
long-running quiet command was *always* at risk of this race before this
release; upgrading the server first only protects commands running on
already-upgraded agents. Upgrade agents promptly to get full coverage; per
the standing rule below, never upgrade agents before the server.

A claim is released when the excluded-from device's prior execution reaches
a terminal state; an execution that never gets a terminal response (agent
crash or disconnect mid-run) has its claim force-released by a periodic
reconciler, bounded by the claim's own `expires_at` — worst case, a device
can be excluded from a repeat `per-device` dispatch of the same definition
for up to one hour (a claim's lease is capped at one hour regardless of the
originating command's own expiry). **Cancelling an execution does not
release its claim** — there is no way to tell the agent to stop, so a
cancelled-but-still-running execution's claim behaves exactly like a normal
in-flight one until a terminal response or the reconciler's TTL bound
releases it. A `per-device` definition dispatched via a workflow step
(rather than a direct `POST /api/instructions/:id/execute` call or a
schedule) releases on the agent's real terminal response and renews on its
keepalive the same as every other dispatch path — workflow-step dispatch
still does not correlate a real execution id for the executions drawer
(so its progress won't show there), but that gap no longer affects claim
timing: it is not release-by-TTL-only. Raw MCP `execute_instruction` and
any other dispatch call that does not resolve an `InstructionDefinition`
are unaffected (no `definition_id` in scope, so this gate never fires for
them), as is the
fleet-broadcast dispatch arm. No operator action is required to upgrade.

**Also in this release:** `DirectorySync::sync_entra` (`POST
/api/directory/sync`) now rejects a concurrent call while a sync is already
in progress with `409 Conflict` instead of racing — previously two
overlapping sync calls could interleave writes. A caller that retries on
`409` behaves correctly; one that treated every non-2xx response as a hard
failure should special-case `409` as "try again shortly." `ConcurrencyManager`
(dead code with zero production callers, already flagged in
`docs/postgres-migration-ladder.md`) is deleted rather than migrated to
Postgres.

## ⚠️ Behaviour change: buffered analytics events reset on Postgres cutover (ADR-0049)

`AnalyticsEventStore` (the outbox spool behind `/api/analytics/status` and
`/api/analytics/recent` — login/MFA/OIDC/SAML/role-elevation and agent/gateway
command-lifecycle events, drained to any configured JSONL/ClickHouse sink)
moves from the SQLite `analytics.db` file to the server's PostgreSQL
substrate in this release (ADR-0049, Wave 2 batch 3, schema
`analytics_event_store`). Like `ResponseStore`, this is a **fresh-start
cutover with no data migration** — the buffer is a transient spool, not
authoritative or compliance evidence (ADR-0009 skippable backfill), so the
legacy `analytics.db` is **never read** on upgrade.

**What happens on first PG boot:**
- The server logs `[PG] analytics spool on Postgres ...` at info level — this
  line appears on every subsequent restart too (it states the store's
  steady-state configuration, not a one-time cutover event), so don't expect
  it to disappear after the first boot.
- Any events buffered but not yet drained to a sink at the moment of cutover
  are lost. In healthy operation this is bounded by the drain interval
  (10s default); if a sink was failing before the upgrade, whatever backlog
  had accumulated is lost too. Already-drained events were already delivered
  and are unaffected.
- New events buffer and drain normally from first boot. No operator action
  required.
- If analytics collection is disabled (`--no-analytics`), no store is
  constructed and no log line is emitted for it. If it's enabled but the
  schema fails to migrate, the server logs an error
  (`[PG] analytics-event store migration/open failed ...`) and the store
  stays constructed but degraded for that run (`is_open()==false`) — it
  keeps accepting `emit()` calls, which fail-soft and count a
  `store_not_open` drop, and `/api/analytics/status`/`/api/analytics/recent`
  return `503` rather than a `200`. Either way, a broken analytics store
  never blocks server startup (this store is the one Postgres-backed store
  on this ladder that does NOT fail the server closed on a construction
  failure; see ADR-0049) — `/readyz`'s `degraded` field (not
  `failed_stores`) names it when it's on but dead, without affecting the
  node's ready/not-ready status.
- **The store does not retry a failed open.** `is_open()` is latched once at
  construction — a Postgres blip that resolves moments after boot still
  leaves the store degraded for the rest of that process's uptime. Restart
  the server once Postgres connectivity for the configured DSN is confirmed
  restored; there is no in-process self-heal to wait out instead.
- **The Settings page's Enabled/Disabled analytics label is not accurate in
  the migration-failed case above** (governance Gate 6 finding, 2026-08-16) —
  it reads the `--no-analytics` config flag directly, not whether the store
  actually opened, so it can still say "Enabled" while a failed migration has
  left collection degraded for the run. Check `/readyz`'s `degraded` field
  or `GET /api/analytics/status` (`503 {"error":{"message":"analytics store
  degraded"}}` in this case — NOT `"enabled":false`, which is reserved for
  `--no-analytics`) for the accurate state, not the Settings page, until
  this is wired up.
- **Security note, separate from the cutover itself:** this release also
  fixes a pre-existing issue in the same store — `AnalyticsEvent.session_id`
  is now a hash of the session cookie, not the raw bearer token. If a token
  may have reached a shared analytics sink or a broadly-read analytics row
  before upgrading, see the rotation guidance in
  `changelog.d/20260816-analytics-session-id-hash.security.md` (assembled
  into the release's Security section at release time).

## RBAC store moves to PostgreSQL (RbacStore → Postgres, ADR-0041)

`RbacStore` — the authorization substrate holding **role definitions,
role→permission grants, principal→role assignments, RBAC groups + membership,
and the global `rbac_enabled` flag** — moves from the SQLite `rbac.db` file to
the server's PostgreSQL substrate in this release (ADR-0041, Wave 2.1), schema
`rbac_store`. No new flag or environment variable is added (it reuses the
shared server `PgPool`).

**No legacy-SQLite migration path.** No production fleet ever ran a
pre-Postgres build of this store, so there was no real `rbac.db` data to carry
over — the mandatory backfill this section originally described (including
the `rbac_enabled`-flag-first transfer and the move-aside/fingerprint-verify
mechanism) was retired under ADR-0009's fresh-start-by-default amendment (see
ADR-0041's Update). These are two SEPARATE behaviors, not one — do not
conflate them:

- A reachable Postgres database whose schema can't migrate or open **is**
  still a fatal startup error (fail-closed), unchanged from before.
- A legacy `rbac.db` file with real content **does NOT** fail startup and its
  content is **never imported** — the server opens it read-only, purely to
  count rows in `rbac_config` (the table that held the `rbac_enabled` flag),
  `securable_types`, `operations`, `roles`, `role_permissions`,
  `principal_roles`, `groups`, and `group_members` for a diagnostic warning,
  then boots regardless of what it finds. Fresh installs are unaffected — no
  legacy file, nothing to warn about.

**If you see the legacy-row-count warning and the environment genuinely has
real RBAC config to keep, there is no automated recovery path**: re-author
the equivalent roles/grants/groups against the new Postgres-backed store via
the RBAC admin UI/REST API, and re-check `rbac_enabled` after boot (it seeds
`false` on a fresh schema — it does NOT carry over from a legacy file, so an
operator who had RBAC enabled must re-enable it explicitly).

**Rollback caution.** Do not roll back to a build older than this release
while a legacy `rbac.db` file with real content still sits at its configured
path on any replica. An older binary's own (now-removed-from-current-code)
backfill logic still runs on that replica and, seeing this database already
past this migration, refuses to auto-migrate rather than silently doing
anything to `rbac_enabled` — you'll see a clear startup refusal, not silent
corruption, but it IS a startup refusal. Move the legacy file aside first if
a rollback is genuinely needed.

**What to expect / do:**

- **Routine (not just one-time) boot-time cost, every deployment.** Every
  server boot's `seed_defaults()` reseed now coordinates its built-in-default
  grants against any concurrent revoke via a cluster-wide advisory lock
  (closes a rare Postgres race where a revoked permission could otherwise be
  silently resurrected mid-boot). This adds a small, ordinarily negligible
  amount of boot time on every restart, not just first boot — but if you
  bulk-restart or scale out MANY replicas of the same RBAC-on-Postgres
  deployment **simultaneously**, their reseed passes serialize against each
  other, which can add up at large replica counts. Prefer a rolling (not
  all-at-once) restart/redeploy
  strategy for this reason, as you likely already do for other reasons.
- **Reads now FAIL CLOSED (deny-on-degrade).** A degraded or unreachable
  `rbac_store` (pool-acquire timeout, query error) now **denies** authorization
  rather than falling through to an allow — this **closes** the prior
  "corrupt `rbac.db` fails open" behavior. Watch the new
  `yuzu_server_rbac_read_degrade_total` metric and the `YuzuRbacReadDegraded`
  alert after upgrade; a degrade denies authz fleet-wide.
- **Multi-replica staleness caveat.** If you run multiple server replicas, a
  role/permission/enabled-flag change on one replica is typically visible on
  the others within a **~1 s** window under normal conditions (a durable
  generation token, refreshed at most once per second) — this is a target the
  refresh loop aims for, not a hard guarantee: a replica whose refresh is
  genuinely slow (pool saturation, a Postgres blip) can observe staleness
  beyond the window, now counted via a `stale_beyond_accepted_bound` degrade
  rather than silently assumed. A revoke is therefore not strictly
  instantaneous cross-replica — well inside the fleet's existing
  revocation-latency envelope (heartbeat + session/token TTLs measured in
  minutes), and an accepted residual risk (`LISTEN/NOTIFY` is the named
  follow-up).
- **Bounded stale-serve, then fail-fast deny, under backend degradation —
  two independent mechanisms.** An already-cached authorization decision
  keeps answering from cache for up to a **~5 s** bound past the last
  confirmed-good refresh, regardless of anything else failing (bounded
  staleness for continuity) — a brief blip does not deny cached decisions
  immediately. Separately, a fail-fast breaker governs *pool access, not
  cache validity*: once it sees **2 consecutive** pool-acquire/query
  failures, any check that is not already a cache hit denies immediately
  rather than blocking on the acquire budget first, and it stops touching
  the pool for a ~1 s cooldown between recovery probes. **"How fast" depends
  on the degradation mode:** pool exhaustion (no connection available) trips
  the breaker in well under a second (2 × the 250 ms acquire budget); a
  query blocked on a PostgreSQL-side lock (e.g. a migration touching
  `rbac_meta`) instead inherits `PgPool`'s `lock_timeout` (10 s default) per
  attempt — measured ~18.5 s for 2 such attempts against a live held lock
  (#3016). Both converge on the same fail-closed deny, just not at the same
  speed. Net effect on a sustained outage: previously-seen decisions keep
  answering for up to ~5 s regardless of breaker state; new/uncached
  decisions deny once the breaker trips, at whichever of the two speeds
  above applies; once the 5 s bound elapses, every check denies until the
  backend recovers. **Not just a sustained outage — flapping (repeated
  short degrade/recover cycles, the shape a managed-Postgres failover or a
  brief network partition actually produces) is arguably the worse case for
  this mechanism, not a milder one:** the breaker's closed-state failure
  streak resets to 0 on a single success, so each recovery — even one that
  lasts only as long as the next probe — reopens the breaker back to FULL
  concurrency rather than easing back in; a Postgres backend that is
  flapping rather than cleanly down can therefore see repeated full-
  concurrency retry bursts instead of a single clean trip-and-stay-open
  (tracked for a half-open concurrency cap, see #3016). **Blast radius while
  open is bounded by the shared connection pool, not the breaker itself:**
  every authz check on this replica denies while the breaker is open —
  including checks against securable types that have nothing to do with
  whatever degraded — because the breaker gates pool ACCESS, shared across
  every `RbacStore` caller on the process, not per-query health. **No
  operator action is needed for recovery** — the breaker self-heals: once a
  probe succeeds (the next attempt after its ~1 s cooldown), it closes
  again automatically and normal service resumes. Watch
  `yuzu_server_rbac_breaker_open` (gauge) and
  `yuzu_server_rbac_authz_check_seconds` (histogram) after upgrade.
- **If you alert on the raw `generation_refresh_failed` reason label,
  re-baseline after upgrade.** This release splits what was previously a
  single reason into two: `generation_refresh_failed` (still denying —
  unchanged meaning) and the new `generation_refresh_failed_within_bound`
  (a refresh failure that landed inside the bounded ~5 s stale-serve window
  above and denied nobody). A custom alert or dashboard built against the
  pre-upgrade single-reason series may see its rate drop after upgrade —
  that is the intended effect of the split, not a sign the underlying
  condition stopped occurring. The shipped `YuzuRbacReadDegraded` alert
  already accounts for this (see `docs/prometheus/yuzu-alerts.yml`); a
  custom query built directly against `yuzu_server_rbac_read_degrade_total`
  should be reviewed against the reason list in `metrics.md` before relying
  on it post-upgrade.
- **Shutdown grace bounds now stack; raise your orchestrator's termination
  grace period, but understand what that does and does not buy you.** A
  graceful `SIGTERM` walks several independently-bounded waits — up to 30 s
  draining in-flight executions (plus any `--shutdown-drain-seconds` grace, HA WS-8, which runs
  before everything listed here and adds to it — raise your stop timeout by the same amount), up to 5 s on the gRPC shutdown deadline
  (moved up by #3495 to run earlier in the sequence, ahead of the four
  joins below and several other quick housekeeping joins not separately
  listed here, though still after the execution drain — see below),
  up to 5 s waiting on the NVD-sync background thread, up to 15 s waiting on
  the HTTP listener thread (#2703 Gate 7 item 2), and (#3261 governance
  hardening) up to 60 s waiting for WebhookStore and OffloadTargetStore to
  drain their delivery queues — the last of which runs the two stores
  CONCURRENTLY, not sequentially, so it adds 60 s to the total rather than
  120 s. Stacked, this can reach **~115 s** in the worst case if more than
  one stage is genuinely wedged; the total and each stage's own bound are
  unchanged by the reorder, only their relative sequence is. **(#3495) The policy
  evaluation, pre-flight runner, quarantine containment reconciler, and
  schedule tick background threads' gRPC dispatch calls now ride on the
  same 5 s gRPC shutdown deadline bucket above, not a separate stage** —
  `ServerImpl::stop()` now cancels in-flight gRPC RPCs before joining those
  four threads (previously it cancelled them after, so a thread genuinely
  blocked inside a gRPC stream write had no bound at
  all — not covered by the ~115 s figure, and not fixable by raising the
  grace period, since nothing in `stop()` would ever reach the cancellation
  that unblocks it). This is a strictly protective fix — no grace-period
  change is needed on upgrade, whether or not you ever hit the pre-#3495
  gap in practice; it was a real but narrow window (a stalled agent stream
  during shutdown), not a routine occurrence. **One narrower residual is NOT covered by this fix**:
  the policy-evaluation thread's join can also stall on its own Postgres
  claim call (`PolicyStore::claim_due_policies`), which isn't a gRPC
  operation and isn't bounded by `Shutdown(deadline)` — tracked separately
  (#3706), not fixed here. The shipped
  docker-compose/systemd units already set a 210 s grace period
  (`stop_grace_period` / `TimeoutStopSec`), which comfortably covers this
  residual's ordinary-contention case —
  but if you deploy under Kubernetes or another orchestrator, its default is
  frequently far shorter (Kubernetes' own default
  `terminationGracePeriodSeconds` is **30**), and a pod with slow-draining
  work in more than one of those stages can be `SIGKILL`ed mid-sequence
  before the server finishes its own bounded teardown. Raise the grace
  period to comfortably exceed ~115 s rather than relying on the platform
  default. **Two things a longer grace period does NOT fix:** (1) the 30 s
  drain window re-queries `execution_tracker_` for
  `running` executions on each of its one-second iterations — so it also
  picks up work that starts mid-drain, not just what was already running
  when `SIGTERM` arrived — but it never stops the HTTP listener from
  ACCEPTING new requests during that window, so a request that lands late in
  the drain is not bounded by the ~115 s figure at all; raising the grace
  period does not close this gap, because the gap is about admission, not
  about how long the drain itself waits. (2) if the 15 s HTTP-listener bound
  or the 60 s WebhookStore/OffloadTargetStore bound IS exceeded, the server
  force-exits (`std::_Exit(1)`) on its OWN internal schedule, independent of
  whatever grace period the orchestrator was configured with — a longer
  external grace period only prevents the orchestrator from `SIGKILL`ing
  the process BEFORE that internal bound fires; it cannot prevent or delay
  the force-exit itself, and the force-exit skips
  `offload_target_store_->flush_all()` and any other still-pending teardown
  the same way a `SIGKILL` would (this is also true of the 60 s webhook/
  offload bound itself: batched offload events flushed into the delivery
  queue immediately before the wait are abandoned, not delivered, if that
  wait times out). Note the 60 s webhook/offload bound is a heuristic sized
  against this deployment's overall shutdown budget, not a proven per-
  delivery ceiling — a slow-but-legitimate delivery target can legitimately
  push close to it under load; if you see this bound trip in production
  under otherwise-healthy conditions, that is a signal to look at your
  configured webhook/offload endpoints' latency, not necessarily a wedged
  delivery. If any of these bounds is exceeded, the diagnostic line is
  written directly to **stderr** (not through the configured logger,
  and naming which store timed out for the webhook/offload case) before the
  process force-exits. `stop()` now runs on an ordinary thread, not inside
  the SIGTERM handler (#3007), so `spdlog` would be legal here — the raw
  write stays anyway because `std::_Exit()` skips any buffered sink flush,
  and this line must reach the operator regardless. If you rely on the log
  file or a structured log sink rather than captured stderr, this one line will not
  appear there; check container/service stderr capture for it instead.
- Confirm on first boot: no `RbacStore` open/migrate errors, and that RBAC is
  enabled if you intend it to be — remember it does NOT carry over from a
  legacy `rbac.db` (Settings → RBAC, or check that confined operators see
  only their scoped fleet).

See `docs/auth-architecture.md` § "RbacStore — the authorization substrate" and
[ADR-0041](../adr/0041-rbac-store-postgres-migration.md) for the full design.

## ⚠️ Breaking: local accounts + MFA enrolments reset (AuthDB/ScimStore → Postgres, ADR-0006)

`AuthDB` (local user accounts, MFA enrolments, enrollment tokens) and
`ScimStore` (SCIM-provisioned users/groups) move from the SQLite `auth.db`
file to the server's PostgreSQL substrate in this release (ADR-0006 Wave 3),
schemas `auth` and `scim_store`. Like the earlier `ApiTokenStore` cutover,
this is a **fresh-start cutover with no data migration**: on first boot
against a Postgres database whose `auth.users` table is empty, the server
seeds exactly the config-file admin and **never reads the old `auth.db`**.
Sessions are (and always were) in-memory-only, so they are unaffected beyond
the usual "log in again after a restart."

**Who this affects:** every local-password operator, everyone with TOTP MFA
enrolled, and every SCIM-provisioned user/group. This is **not** limited to
password auth — SSO/OIDC/SAML session establishment itself is unaffected
(the IdP still asserts identity), but any RBAC role/group mapping recorded
only in the old `auth.db` local-account tables is gone until re-established.

**What happens on first PG boot:**

- Prior local accounts, roles, and MFA enrolments that existed only in the
  pre-cutover `auth.db` are gone. The server re-seeds a single admin account
  from `yuzu-server.cfg` (the same config-as-seed-only behavior as the
  original v0.12.0 AuthDB bring-up).
- SCIM-provisioned users/groups are **not** lost long-term: `ScimStore`
  self-heals on the IdP's next scheduled sync cycle, which re-provisions
  everything from the IdP as the source of truth. There is a gap between
  first PG boot and that next sync during which SCIM-provisioned users
  cannot log in.
- Anyone with TOTP MFA enrolled must **re-enrol** — the encrypted
  `mfa_totp_secret` blob and enrolment state do not carry over.
- The server logs a loud boot warning: **`AUTH DATA RESET ON POSTGRES
  CUTOVER`**. If you do not see this line on first boot against the new
  Postgres database, the cutover did not happen as expected — investigate
  before assuming accounts are intact.

**Remediate:**

1. Plan the upgrade in a maintenance window and notify every local-password
   operator, MFA-enrolled user, and SCIM administrator in advance — expect a
   batch of failed logins immediately after cutover, not a surprise incident.
2. After upgrade, log in as the re-seeded admin using the credentials in
   `yuzu-server.cfg`.
3. Re-create any other local operator accounts that are not SCIM-provisioned
   (Settings → Users), and have every user re-enrol MFA
   (Settings → Multi-Factor Authentication).
4. For SCIM-provisioned users, either wait for the next scheduled IdP sync or
   trigger one manually if your SCIM setup supports it; do not manually
   re-create SCIM-managed users (they will be re-provisioned).
5. Confirm the `AUTH DATA RESET ON POSTGRES CUTOVER` line appeared in the
   server log at the boot where the cutover ran.

**Not affected:** the `PgTestTemplate` config, engine principals (a separate
store), and API/MCP bearer tokens (already migrated to Postgres in an
earlier release, see "⚠️ Breaking: API and MCP bearer tokens are invalidated
on upgrade" above — this AuthDB/ScimStore cutover is independent of that one
and does not re-invalidate already-reissued tokens).

See `docs/auth-architecture.md` § "AuthDB — persistent authentication store"
for the full design rationale, and
[`docs/ops-runbooks/auth-db-recovery.md`](../ops-runbooks/auth-db-recovery.md)
for lockout/break-glass recovery — that runbook has been rewritten for this
cutover and is Postgres-native throughout (`psql "$YUZU_POSTGRES_DSN"` against
the `auth` schema).

## Notification feed moves to PostgreSQL (NotificationStore, ADR-0046)

`NotificationStore` — the dashboard toast/badge feed — moves from the SQLite
`notifications.db` file to the server's PostgreSQL substrate in this release
(ADR-0006 Wave 2, ADR-0046), schema `notification_store`. No new flag or
environment variable is added (it reuses the shared server `PgPool`).

**No legacy-SQLite migration path.** No production fleet ever ran a pre-Postgres build
of this store, so there was no real `notifications.db` data to carry over — the
one-time mandatory backfill this section originally described was retired under
ADR-0009's fresh-start-by-default amendment (see ADR-0046's Update).

These are two SEPARATE failure/detection behaviors, not one — do not conflate them:

- A reachable Postgres database whose schema can't migrate or open **is** a fatal
  startup error (fail-closed, matching every other Postgres-migrated store's
  contract): the server logs `[PG] Refusing to start` and refuses to serve at all.
- A legacy `notifications.db` file with real content **does NOT** fail startup and
  its content is **never imported** — the server opens it read-only, purely to
  count rows in `notifications` for a diagnostic warning, then boots fresh-started
  regardless of what it finds. If that table has rows, it logs a
  `NotificationStore` legacy-row-count warning at WARN; boot proceeds unaffected
  either way. There is no automated recovery path for old unread/dismissed history
  — this is display-only state (never an authorization, targeting, or enforcement
  decision), so a fresh start is acceptable in a way it would not be for an
  authoritative store.
- **Fresh installs are unaffected** — no legacy file, nothing to warn about.

**Not affected:** `/api/notifications*` request/response behavior is
unchanged — this is a storage-engine swap only, no API change.

## Audit trail on PostgreSQL — legacy `audit.db` no longer imported (AuditStore, ADR-0040)

The audit log (`AuditStore`, the SOC 2 evidence chain) runs on the server's
PostgreSQL substrate (ADR-0006 Wave 1.3, schema `audit_store`). No new flag or
environment variable is needed: the store reuses the shared `--postgres-dsn` /
`YUZU_POSTGRES_DSN` connection the rest of the server already requires, and
(like every server store) it **fails closed** at boot if Postgres is
unreachable — there is no SQLite fallback.

**No legacy-SQLite migration path.** This release retires `AuditStore`'s
one-time, mandatory, streamed backfill from a legacy `audit.db` (`#3623`,
`chore/retire-migrate-from-sqlite-auditstore`, ADR-0009's hard-cutover Update)
— no production Yuzu fleet has ever run a pre-Postgres build, and this is a
hard cutover with no migration path held open for any store, including this
one, accepting permanent audit-trail loss as the failure mode if that premise
is ever wrong for a specific host. `AuditStore` had been the
one deliberate, permanent exception to ADR-0009's fresh-start default — audit
evidence cannot be regenerated the way config or cache state can — until this
release withdrew it. These are two SEPARATE behaviors, not one — do not
conflate them:

- A reachable Postgres database whose schema can't migrate or open **is**
  still a fatal startup error (fail-closed), unchanged from before.
- A legacy `audit.db` file with real content **does NOT** fail startup and its
  content is **never imported**. Its permissions are forced to owner-only
  (`0600`, plus its `-wal`/`-shm`/`-journal` sidecars) if they aren't already —
  this file may hold plaintext secret material from a since-fixed historical
  bug, same obligation as every other legacy-file-hardening store on this page
  — POSIX only, a no-op on Windows, #3593 — then the server opens it
  read-only, purely to count rows in `audit_events` for a diagnostic warning,
  then boots regardless of what it finds. Beyond that row count, its content
  is never read, and it is never renamed, moved, or written to. Fresh installs
  are unaffected — no legacy file, nothing to warn about.

**If you see the legacy-row-count warning and the environment genuinely has
real audit history to keep, there is no automated recovery path**: the
pre-cutover trail stays exactly where it is, at its configured path (0600
now enforced on POSIX, #3593; content otherwise untouched) — and is your operator-managed
record going forward (export it, archive it, keep it under your own
retention policy; Yuzu will never import it). The generic "reapply manually"
phrasing in the boot warning fits config-shaped stores below (a webhook
subscription, a notification preference) where reapplying means re-creating
the row through the API; it does not apply here in that sense — an audit
trail is historical evidence, not something you recreate, so "reapply" for
AuditStore means export-and-archive, never re-import.

**Rollback caution.** Do not roll back to a build older than this release.
Unlike RbacStore above, this is not just a caution about a leftover legacy
file — an older binary's own (now-removed-from-current-code) backfill logic
refuses to boot **unconditionally**, with or without a legacy `audit.db`
present: seeing this database already past this migration (the marker rows
are gone, but `audit_retention_meta` itself is not — see ADR-0040's Update),
its own idempotency-marker write hits the SAME migration's CHECK constraint
(`audit_retention_meta_no_retired_backfill_markers`) and fails with a
Postgres `23514 check_violation`, table empty or not, legacy file present or
not. This is the same class of guarantee the DROP-TABLE-group stores above
get from their `undefined_table` error — a schema-level rejection, not a
live-row-count race — with one caveat: if a legacy `audit.db` is present,
the old binary's row inserts into `audit_events` still run and commit before
this final write fails, so the refusal is loud and deterministic but not
zero-data-movement the way a first-touch `undefined_table` error is. "Just
roll back the binary" is not a supported recovery path once this migration
has run, the same as every DROP-TABLE-group store above. **If AuditStore
runs as more than one replica, upgrade every replica and any
`--mfa-reset`/`--break-glass-arm` CLI image together** during a staged
rollout — a replica or one-shot CLI still on the old binary that boots after
this migration has run on the shared database will refuse to start, same as
any other rollback attempt.

**What to do:** the `YuzuAuditBackfillFailing` alert is removed with this
release. If you copied it into your own alerting config instead of
re-importing `docs/prometheus/yuzu-alerts.yml`, remove it or it fires
permanently via `absent_over_time` on a stale local copy — a CRITICAL page
that never clears, pointing at boot-log remediation steps that no longer
exist.

**Reads deny-on-degrade.** An audit-store or connection-pool failure makes
`GET /api/v1/audit*` return `503` rather than an empty `200`, so an
infrastructure blip can never be mistaken for "no audit activity."

**Not affected:** the audit event vocabulary and REST/MCP query surface are
unchanged; SIEM export recipes keep working. One deliberate behaviour change: on
a multi-replica deployment an identical-magnitude repeat clock step no longer
re-emits `yuzu_server_audit_clock_anomaly_skips_total` on every pass (only a
distinct anomaly does) — if you alerted on that counter's *cadence*, alert on a
sustained increase instead. See
[Audit Log](audit-log.md#the-retention-clock-guard).
## Management-group confinement config migrates to Postgres (ADR-0042)

The `ManagementGroupStore` — the confinement hierarchy that backs operator
scoping and the ADR-0017 `authorize_list_read` gate — moves from the SQLite
`management-groups.db` file to the server's PostgreSQL substrate in this release
(ADR-0006 Wave 2.2), schema `management_group_store`. It reuses the existing
shared connection pool, so **no new connection flag or config is required** —
the same `--postgres-dsn` / `YUZU_POSTGRES_DSN` that every other server store
uses.

**No legacy-SQLite migration path.** No production fleet ever ran a
pre-Postgres build of this store, so there was no real `management-groups.db`
data to carry over — the mandatory backfill this section originally described
was retired under ADR-0009's fresh-start-by-default amendment (see ADR-0042's
Update). These are two SEPARATE behaviors, not one:

- A reachable Postgres database whose schema can't migrate or open **is**
  still a fatal startup error (fail-closed), unchanged from before.
- A legacy `management-groups.db` file with real content **does NOT** fail
  startup and its content is **never imported** — the server opens it
  read-only, purely to count rows in `management_groups`,
  `management_group_members`, and `management_group_roles` for a diagnostic
  warning, then boots regardless of what it finds (an empty confinement
  hierarchy, same as a fresh install). The over-deep/cyclic-tree refusal this
  section used to describe has no remaining trigger — the write path's
  depth-5 cap is now the sole guard, since nothing backfills a legacy tree
  past it anymore.

**If you see the legacy-row-count warning and the environment genuinely has
real management groups to keep, there is no automated recovery path**:
re-author the equivalent groups/memberships/role assignments against the new
Postgres-backed store via the REST API.

**Rollback caution:** see the InventoryStore section's "Rollback caution" note above — the
same unconditional rollback-refusal applies to this store (its own dropped marker table).

**Operator-visible behaviour change (fail-closed reads).** After cutover, a
confinement-feeding read that degrades (store not open, pool-acquire timeout, or
query error) now returns a distinguishable failure that the caller resolves to
**DenyAll** — a scoped operator sees a reduced or empty list rather than the
store silently returning an empty deny-set and **under-restricting** (the old
fail-open hazard). A re-parent (`PUT /api/v1/management-groups/{id}`) whose
hierarchy reads degrade now returns **503** rather than a misleading success.
Watch the new `yuzu_server_mgmt_group_read_degrade_total{reason}` counter — a
non-zero rate means scoped operators are seeing reduced/empty lists because the
confinement substrate is degraded, **not** that groups actually shrank (see
`docs/user-manual/metrics.md` § "Management group metrics" and the shipped
`YuzuMgmtGroupReadDegraded` alert).

**Not affected:** the confinement hierarchy's semantics, the REST/MCP surface,
and dynamic-group scope expressions are unchanged — only the storage substrate
and the fail-closed read posture change.

## Custom properties migrate to Postgres (ADR-0045)

The `CustomPropertiesStore` — operator-authored per-agent metadata (properties
and their optional type/validation schemas) used in scope expressions via
`props.<key>` — moves from the SQLite `custom-properties.db` file to the
server's PostgreSQL substrate in this release (ADR-0006 Wave 2), schema
`custom_properties_store`. It reuses the existing shared connection pool —
**no new connection flag or config is required**.

**No legacy-SQLite migration path.** No production fleet ever ran a pre-Postgres build
of this store, so there was no real `custom-properties.db` data to carry over — the
one-time mandatory backfill this section originally described was retired under
ADR-0009's fresh-start-by-default amendment (see ADR-0045's Update).

These are two SEPARATE failure/detection behaviors, not one — do not conflate them:

- A reachable Postgres database whose schema can't migrate or open **is** a fatal
  startup error (fail-closed), same as every other born-on-Postgres store.
- A legacy `custom-properties.db` file with real content **does NOT** fail startup
  and its content is **never imported** — the server opens it read-only, purely to
  count rows across `custom_properties`/`custom_property_schemas` for a diagnostic
  warning, then boots fresh-started regardless of what it finds. If either table has
  rows, it logs a `CustomPropertiesStore` legacy-row-count warning at WARN; boot
  proceeds unaffected either way. If you see this warning and the environment
  genuinely has real properties/schemas to keep, there is no automated recovery
  path: re-author the equivalent properties/schemas against the new Postgres-backed
  store via `PUT /api/agents/:id/properties/:key` / `POST /api/property-schemas`
  before relying on it.
- **Fresh installs are unaffected** — no legacy file, nothing to warn about.

**Operator-visible behaviour change (fail-closed reads).** After cutover, a
`props.<key>`-feeding read that degrades (store not open, pool-acquire
timeout, or query error) now aborts the whole scope evaluation rather than
silently resolving the property as absent — a `props.<key>`-scoped
dispatch/policy/push rule now matches **nobody** while degraded, instead of
(under a `NOT`/`!=` scope) silently matching **everybody**. `GET
/api/agents/:id/properties` now returns **503** on a degraded read rather
than an empty list. Watch the new
`yuzu_server_custom_properties_read_degrade_total{reason}` counter — a
non-zero rate means `props.<key>`-scoped rules may be silently matching
nobody, not that operators removed the properties (see `docs/user-manual/
metrics.md` and the shipped `YuzuCustomPropertiesReadDegraded` alert).

**Operator-visible behaviour change (fail-closed writes, 2026-08-14 follow-up).**
`PUT /api/agents/:id/properties/:key` and `POST /api/property-schemas` now return
**503** (instead of `400`) when the failure is a genuine database/store outage rather
than caller-input or schema-validation error — previously every failure from either
write, including a transient Postgres blip, surfaced as the same `400` a caller could
not distinguish from their own bad input. A caller that branches specifically on `400`
to mean "don't retry" should treat the new `503`s the same as any other transient
server error (retry with backoff); a caller that already treats any `5xx` as retryable
is unaffected. See `docs/user-manual/rest-api.md`'s per-route notes for the exact
response shapes.

**Not affected:** the `props.<key>` scope-DSL syntax and property/schema semantics are
unchanged; the `GET`/`DELETE` property routes and `GET` schema route keep their prior
response shapes — only the two write routes' failure-mode status codes changed, as
described above.

## Network-discovered device data migrates to Postgres (DiscoveryStore, ADR-0044)

The `DiscoveryStore` — the network-discovered devices behind `POST /api/discovery/scan`
and `GET /api/discovery/results` — moves from the SQLite `discovery.db` file to the
server's PostgreSQL substrate in this release (ADR-0006 Wave 2), schema
`discovery_store`. It reuses the existing shared connection pool — no new connection
flag or config is required.

**No legacy-SQLite migration path.** No production fleet ever ran a pre-Postgres build
of this store, so there was no real `discovery.db` data to carry over — the one-time
mandatory backfill this section originally described was retired under ADR-0009's
fresh-start-by-default amendment (see ADR-0044's Update).

These are two SEPARATE failure/detection behaviors, not one — do not conflate them:

- A reachable Postgres database whose schema can't migrate or open **is** a fatal
  startup error (fail-closed), same as every other born-on-Postgres store.
- A legacy `discovery.db` file with real content **does NOT** fail startup and its
  content is **never imported** — the server opens it read-only, purely to count rows
  in `discovered_devices` for a diagnostic warning, then boots fresh-started regardless
  of what it finds. If that table has rows, it logs a `DiscoveryStore` legacy-row-count
  warning at WARN; boot proceeds unaffected either way. If you see this warning and the
  environment genuinely has real discovered-device data (particularly the operator-set
  `managed` flag) to keep, there is no automated recovery path: re-run
  `POST /api/discovery/scan` and re-apply `mark_managed` against the new Postgres-backed
  store before relying on it.
- **Fresh installs are unaffected** — no legacy file, nothing to warn about.

**Operator-visible behaviour change (fail-closed reads).** `GET /api/discovery/results`
now returns **503** on a degraded read (store not open, pool-acquire timeout, or query
error) instead of silently rendering an empty device list — previously, a local SQLite
read essentially never failed short of file corruption, so this failure mode was not
practically reachable. Watch the `yuzu_server_discovery_read_degrade_total{reason}`
counter — a non-zero rate means the discovery view is degraded, **not** that no devices
were found.

**Breaking — `POST /api/discovery/scan`'s response contract changed.** The endpoint no
longer always returns `200 {"status":"ok",...}`: the response gains a `devices_failed`
count, `status` is `"partial"` when some but not all devices in a batch persisted, and
the endpoint returns **503** when every attempted device failed to persist (previously
this was silently reported as `200`/`"ok"`, with the `discovery.scan` audit row always
saying `"success"` regardless of outcome — the audit outcome is now
`"success"`/`"partial"`/`"failure"`). A caller that asserts a bare `status == "ok"`, or
that treats any 5xx from this endpoint as a hard failure needing operator escalation,
should account for the new value and status code. Re-sending the exact same request body
is safe — `upsert_device` is idempotent per `ip_address`, so a byte-identical retry cannot
double-count or corrupt already-stored devices — but a fresh re-scan is not the same
thing: `mac_address`/`subnet` overwrite unconditionally on every upsert, so a re-scan that
fails to resolve a device's MAC this time will blank a previously known-good value rather
than simply retry the earlier failure. See the REST API reference's Network Discovery
section for the full response shapes.

## Guardian quarantine records migrate to Postgres (QuarantineStore, ADR-0047)

The `QuarantineStore` — the Guardian device-quarantine bookkeeping behind
`POST /api/v1/quarantine`, `DELETE /api/v1/quarantine/{agent_id}`, and the MCP
`quarantine_device` tool — moves from the SQLite `quarantine.db` file to the server's
PostgreSQL substrate in this release (ADR-0006 Wave 2), schema `quarantine_store`. It
reuses the existing shared connection pool — no new connection flag or config is
required.

**No legacy-SQLite migration path.** No production fleet ever ran a pre-Postgres
build of this store, so there was no real `quarantine.db` data to carry over — the
mandatory, fingerprint-verified backfill this section originally described (all of
the pre-upgrade checks, refusal conditions, and move-aside/fingerprint mechanics)
was retired under ADR-0009's fresh-start-by-default amendment (see ADR-0047's
Update). These are two SEPARATE behaviors, not one:

- A reachable Postgres database whose schema can't migrate or open **is** still a
  fatal startup error (fail-closed), unchanged from before.
- A legacy `quarantine.db` file with real content **does NOT** fail startup and its
  content is **never imported** — the server opens it read-only, purely to count
  rows in `quarantine_records` for a diagnostic warning, then boots regardless of
  what it finds.

**This is a stronger warning than it looks, and a deliberate choice despite the
stakes.** Unlike most other stores retiring their legacy-SQLite path in this same
release, a genuinely non-empty `quarantine.db` here means a device an operator
quarantined is **not** re-quarantined in the server's view after upgrade — the
server's view of containment does not include whatever the warning names, though
agent-side firewall enforcement (out of scope for this store) may still be
independently in effect. This was reopened and explicitly reconsidered for this
store given the containment stakes, not defaulted by uniformity with the rest of
this retirement batch — see ADR-0047's Update for the full reasoning. **If you see
the legacy-row-count warning and the environment genuinely has real quarantine
records to keep, there is no automated recovery path**: re-quarantine the affected
device(s) via `POST /api/v1/quarantine` after confirming which devices need it.

**Rollback caution:** see the InventoryStore section's "Rollback caution" note above — the
same unconditional rollback-refusal applies to this store (its own dropped marker table).

**Operator-visible behaviour change (fail-closed reads).** `GET /api/v1/quarantine`
can now return **503** for two DISTINCT reasons — the response body's message
distinguishes them, since only one is covered by the existing metric:

- **`"quarantine list unavailable — try again"`** — a genuine store/pool/query
  degrade (store not open, pool-acquire timeout, or query error) instead of
  silently rendering an empty quarantine list; previously, a local SQLite read
  essentially never failed short of file corruption, so this failure mode was not
  practically reachable. Watch the `yuzu_server_quarantine_read_degrade_total{reason}`
  counter — a non-zero rate means the quarantine view is degraded, **not** that no
  devices are quarantined.
- **`"authorization check unavailable — try again"`** (new) — the per-record
  admit-then-filter loop that scopes the list to the caller's management groups hit
  an anomalous outcome (neither an explicit allow nor an explicit 403 deny) partway
  through, most commonly a transient engine-principal-store outage landing between
  the request's initial auth check and a later per-record scope check. The whole
  list fails closed rather than silently omitting just the affected record(s) — the
  alternative is rendering a partial list that reads as complete. **This cause does
  NOT increment `yuzu_server_quarantine_read_degrade_total`** — that counter is
  wired to the store-layer degrade above only; if you see 503s here with the
  authorization-check message and the counter isn't moving, the RBAC/engine-principal
  path is what to investigate, not the quarantine store itself.

**Verify:** after the server reports ready, `GET /api/v1/quarantine` (quarantine has
no dashboard surface — REST/MCP only) shows the expected active quarantine records —
either already-live Postgres data on a redeploy, or an empty list plus the
legacy-row-count warning above on a fresh install with a real legacy file.

**Not affected:** the agent-side quarantine firewall enforcement (WFP/nftables/pf
block-all + exceptions) is untouched by this migration — only the server-side
bookkeeping's storage substrate changes. `POST /api/v1/quarantine` and
`DELETE /api/v1/quarantine/{agent_id}`'s request/response shapes, and the MCP
`quarantine_device` tool's ticket-then-recall approval flow, are unchanged.

## Device tags migrate to Postgres (TagStore, ADR-0050)

The `TagStore` — device tags behind `GET/PUT/DELETE /api/v1/tags`, the legacy
`/api/tags*` routes, the MCP `get_tags`/`set_tag`/`delete_tag`/`search_agents_by_tag`
tools, and every `tag:<key>` scope expression — moves from the SQLite `tags.db` file
to the server's PostgreSQL substrate in this release (ADR-0006 Wave 2 batch 3),
schema `tag_store`, on the existing shared pool. Tags are **dispatch-critical**:
scope expressions decide which agents a command reaches, and service-scoped API
tokens are confined by the `service` tag — which is why the read/write failure
modes below fail closed rather than degrading silently.

**No legacy-SQLite migration path.** No production fleet ever ran a pre-Postgres build
of this store, so there was no real `tags.db` data to carry over — the one-time
mandatory backfill this section originally described was retired under ADR-0009's
fresh-start-by-default amendment (see ADR-0050's Update).

These are two SEPARATE failure/detection behaviors, not one — do not conflate them:

- A reachable Postgres database whose schema can't migrate or open **is** a fatal
  startup error (fail-closed), same as every other born-on-Postgres store.
- A legacy `tags.db` file with real content **does NOT** fail startup and its
  content is **never imported** — the server opens it read-only, purely to count
  rows in `tags` for a diagnostic warning, then boots fresh-started regardless of
  what it finds. If that table has rows, it logs a `TagStore` legacy-row-count
  warning at WARN; boot proceeds unaffected either way. If you see this warning and
  the environment genuinely has real tags to keep, there is no automated recovery
  path: re-apply the equivalent tags against the new Postgres-backed store via
  `PUT /api/v1/tags` / `set_tag` before relying on `tag:`-scoped targeting.
- **Fresh installs are unaffected** — no legacy file, nothing to warn about.

**Operator-visible behaviour changes (fail-closed reads/writes).**

- A degraded tag store now returns **503** (`retry_after_ms: 5000`) on the tag
  REST surfaces and `-32603` on the MCP tools — never an empty tag list, a false
  `deleted:false`, or a silent `200` over a failed write (the legacy
  `POST /api/tags/set` previously reported `ok` even when nothing was written).
  A caller whose error handling treats `400` as "don't retry" should treat these
  `503`s as retryable.
- A `tag:<key>`-scoped dispatch **fails the whole evaluation** on a degraded tag
  read — the operation errors rather than reaching fewer or more devices than
  the expression names. Watch `yuzu_server_tag_store_read_degrade_total{reason}`
  (alert `YuzuTagStoreReadDegraded`): while it fires, the policy evaluator is
  also silently skipping `tag:`-scoped checks (`last_check_at` stops advancing).
- Agent tag syncs are bounded: an agent reporting more than 256 tags in one
  Register has the sync refused whole (logged; the agent keeps its prior tag
  set). Realistic agents report 5–20. If an agent legitimately exceeds the
  cap, reduce what it self-reports (its `scopable_tags` come from the agent's
  own configuration/plugins) — there is no server-side override knob; treat a
  sustained refusal in the server log as an agent-configuration defect.

**Verify:** after the server reports ready, `GET /api/v1/tags?agent_id=<id>` (or
the device page) shows the expected tags (re-applied via the REST/MCP surface on a
fresh install, or already-live Postgres data on a redeploy).

## ⚠️ Behaviour change: quarantine containment now covers IPv6, and reports honestly (#3282, #3283, #3284, #3285, #3286, #3260)

Six issues close against the `quarantine` agent plugin across Windows, Linux and macOS. Every
one is the same class: an outcome reported as success when it was partial, failed, or unknown.
**Read §1 before quarantining a dual-stack Linux host — it needs operator action.**

The server-side dispatch enforcement (#881) and the MCP tool's honesty fixes (#3127) ship
separately and have their own upgrade note.

### 1. Linux containment now covers IPv6 (#3282)

The Linux leg installed its `yuzu-quarantine` chain in `iptables` only. On a dual-stack or
IPv6-capable host the device stayed fully reachable over IPv6 while reporting a clean
`status|quarantined` — containment that was not containing. The plugin now mirrors the chain into
`ip6tables`, and a failure on either family is reported (`status|quarantined_partial`), never
counted as applied.

**Action required for dual-stack fleets.** Whitelist entries are routed to the chain matching
their own family, so a **v4-only whitelist now leaves IPv6 contained**. There is no blanket
"keep existing connections alive" rule on either family — only a whitelisted address survives,
in any connection state. The agent automatically whitelists its own configured server address
(an IP literal directly, a hostname resolved to its address(es) **once, at agent startup** —
never at quarantine time, and using the endpoint's own resolver), so most fleets need no manual
action here. Prefer an IP-literal `--server` config for endpoints where containment integrity
matters most, since that removes DNS from the equation entirely. If your agents reach the
server over IPv6 through a path DNS resolution of the configured address wouldn't reproduce
(split-horizon DNS, a manually pinned route), or if the server's address changes after an agent
was last started, **add the server's address to the whitelist explicitly**. See
[Security Hardening](security-hardening.md#whitelisting-on-a-dual-stack-host-read-this-before-quarantining-one).

### 2. Reporting is more conservative again (#3283, #3285, #3286, #3260)

As with the Wave-2 argv migration before it, **nothing got more broken — the reporting got more
honest**, so expect these to fire more often after upgrading:

- **macOS**: a blocking pf ruleset that is loaded while pf itself is **disabled** now reads
  `state|degraded` (traffic is not actually blocked); a pf status read that returns nothing
  recognisable reads `state|uncertain` (#3283).
- **`quarantine.status` exits non-zero** on `degraded` and `uncertain`, and sets the ABI result
  status to `UNAVAILABLE`/`PARTIAL`. A consumer that only inspects the return code can no longer
  read an unenforced or unreadable host as a clean status (#3285).
- **Windows**: containment now sets the profile default policy rather than relying on rule
  precedence alone, and the pre-quarantine profile policy is captured **write-once** — a
  re-quarantine no longer overwrites the genuine capture with the quarantine's own
  block/block policy, which previously made release replay it and strand the host while
  reporting `status|released` (#3284).
- **Concurrent mutations are serialised** — two overlapping `quarantine`/`unquarantine`/
  `whitelist` actions on one host can no longer interleave firewall mutations (#3286).

### No migration, no schema change

Rollback is data-safe. A mixed fleet is safe: an older agent simply keeps the older, less
honest plugin reporting until it is upgraded.
## Product packs migrate to Postgres (ProductPackStore, ADR-0054)

The `ProductPackStore` — operator-installed product packs behind `POST/GET/DELETE
/api/product-packs*` — moves from the SQLite `product-packs.db` file to the server's
PostgreSQL substrate in this release (ADR-0006), schema `product_pack_store`, on the
existing shared pool.

**No legacy-SQLite migration path.** No production fleet ever ran a pre-Postgres build
of this store, so there was no real `product-packs.db` data to carry over — the
one-time mandatory backfill this section originally described was retired under
ADR-0009's fresh-start-by-default amendment (see ADR-0054's Update).

These are two SEPARATE failure/detection behaviors, not one — do not conflate them:

- A reachable Postgres database whose schema can't migrate or open **is** a fatal
  startup error (fail-closed), same as every other born-on-Postgres store.
- A legacy `product-packs.db` file with real content **does NOT** fail startup and its
  content is **never imported** — the server opens it read-only, purely to count rows
  across `product_packs`/`product_pack_items` for a diagnostic warning, then boots
  fresh-started regardless of what it finds. If either table has rows, it logs a
  `ProductPackStore` legacy-row-count warning at WARN; boot proceeds unaffected either
  way. If you see this warning and the environment genuinely has real installed packs
  to keep, there is no automated recovery path: re-install the equivalent packs
  against the new Postgres-backed store via `POST /api/product-packs` before relying
  on it.
- **Fresh installs are unaffected** — no legacy file, nothing to warn about.
- `deleted_pack_ids` (the uninstall tombstone table) and its coordination lock are
  unchanged by this retirement — they still exist and `uninstall()` still writes to
  them; whether they are now themselves vestigial (their original purpose was
  guarding against the now-retired backfill resurrecting an uninstalled pack) is a
  separate, undecided question.

**Operator-visible behaviour changes.**

- `GET /api/product-packs`, `GET /api/product-packs/{id}`, and
  `DELETE /api/product-packs/{id}` now return **HTTP 503** on a genuine database outage
  instead of a misleadingly-empty pack list or a false "not found". Watch the new
  `yuzu_server_product_pack_read_degrade_total{reason}` counter (alert
  `YuzuProductPackReadDegraded`) — while it fires, `GET /api/product-packs`/
  `GET /api/product-packs/{id}` are failing closed rather than returning a
  silently-wrong result; see `docs/user-manual/metrics.md`'s "Product pack store
  metrics" section for the `reason` label vocabulary.
- **`DELETE /api/product-packs/{id}` on a missing id now returns 404** (previously 400).
- **Breaking — the error body on a rejected `POST /api/product-packs` or
  `DELETE /api/product-packs/{id}` is now the standard A4 envelope**
  (`{"error":{"code","message","correlation_id",...}}`) instead of the previous flat
  `{"error": "<message>"}` — a client parsing the old flat shape must switch to reading
  `error.message`. A genuine database error no longer echoes raw driver text to the
  caller (logged server-side instead; see `docs/user-manual/rest-api.md`'s Product
  Packs section).
- Installing a bundle whose documents assign the same item id twice now fails the whole
  install as a **400 validation error** instead of silently discarding the duplicate
  item (a pre-migration bug, not a preserved behavior) — detected before any Postgres
  interaction, so unlike a genuine database error this is **not retryable**: the same
  bundle always fails the same way.
- No change to the `#802`/W7.4 signed-pack enforcement default, the Ed25519 signature
  verification path, or the `--allow-unsigned-packs` / `YUZU_ALLOW_UNSIGNED_PACKS`
  operator escape hatch.

**Verify:** after the server reports ready, `GET /api/product-packs` shows the expected
packs (re-installed via the REST API on a fresh install, or already-live Postgres data
on a redeploy).

## Guardian Baselines migrate to Postgres (BaselineStore, ADR-0055)

`BaselineStore` — Guardian's deployable Baseline unit (`/guardian` → Baselines,
`GET /api/v1/guaranteed-state/device-compliance`) — moves from the SQLite
`guardian-baselines.db` file to the server's PostgreSQL substrate in this release,
schema `baseline_store`, on the existing shared pool. A **Baseline** is the only
deployable unit in Guardian: what a deploy enforces across the fleet is read from
each Baseline's `deployed_snapshot`, never its live member set.

**No legacy-SQLite migration path.** No production fleet ever ran a pre-Postgres build
of this store, so there was no real `guardian-baselines.db` data to carry over — the
one-time backfill mechanism this section originally described was retired under
ADR-0009's fresh-start-by-default amendment (see ADR-0055's Update).

These are two SEPARATE failure/detection behaviors, not one — do not conflate them:

- A reachable Postgres database whose schema can't migrate or open **is** a fatal
  startup error (fail-closed, matching the ladder's "authoritative" posture for this
  store), same as every other born-on-Postgres store.
- A legacy `guardian-baselines.db` file with real content **does NOT** fail startup
  and its content is **never imported** — the server opens it read-only, purely to
  count rows across `guaranteed_state_baselines`/`guaranteed_state_baseline_rules`/
  `guaranteed_state_baseline_groups` for a diagnostic warning, then boots
  fresh-started regardless of what it finds. If any of those tables has rows, it
  logs a `BaselineStore` legacy-row-count warning at WARN; boot proceeds unaffected
  either way. If you see this warning and the environment genuinely has real
  Baselines to keep, there is no automated recovery path: re-author the equivalent
  Baselines against the new Postgres-backed store via the Guardian UI/REST API
  before relying on it.
- **Fresh installs are unaffected** — no legacy file, nothing to warn about.

**Operator-visible behaviour changes (fail-closed reads).** A degraded read on
the enforcement-feeding path (`deployed_member_rule_ids()` — the source for the
push fan-out, the heartbeat reconcile, and the per-device compliance view) now
returns a distinguishable failure that the caller resolves to an explicit
abort/503, never a silent empty/"fully compliant" enforced set. `GET
/api/v1/guaranteed-state/device-compliance` returns **503** rather than a
misleadingly-empty or false-compliant result when the underlying read degrades;
Guardian deploy/delete dashboard actions show a degraded-modal rather than
reporting success. There is no dedicated backfill-outcome metric for this store —
a schema-migration failure is boot-fatal and never serves `/metrics`, so the boot
log and `/readyz` are the channels to watch during an upgrade.

**Verify:** after the server reports ready, `/guardian` shows the expected Baselines
(re-authored via the Guardian UI/REST API on a fresh install, or already-live
Postgres data on a redeploy).

## Guardian rules, events, and DEX observations retire their legacy-SQLite path (GuaranteedStateStore, ADR-0038)

`GuaranteedStateStore` — the live agent-side policy enforcement store (`/guardian`
rule authoring, drift/remediation events, DEX observations) — no longer copies a
legacy `guaranteed-state.db` file into Postgres on first boot.

**No legacy-SQLite migration path.** No production fleet ever ran a pre-Postgres
build of this store, so there was no real `guaranteed-state.db` data to carry
over — the one-time backfill mechanism this store originally shipped was retired
under ADR-0009's fresh-start-by-default amendment (see ADR-0038's Update).

These are two SEPARATE failure/detection behaviors, not one — do not conflate them:

- A reachable Postgres database whose schema can't migrate or open **is** a fatal
  startup error (fail-closed), same as every other born-on-Postgres store.
- A legacy `guaranteed-state.db` file with real content **does NOT** fail startup
  and its content is **never imported** — the server opens it read-only, purely to
  count rows across `guaranteed_state_rules`/`guardian_meta`/
  `guardian_agent_rule_status`/`guaranteed_state_events`/`guardian_observations`
  for a diagnostic warning, then boots fresh-started regardless of what it finds.
  If any of those tables has rows, it logs a `GuaranteedStateStore`
  legacy-row-count warning at WARN; boot proceeds unaffected either way.
- **Fresh installs are unaffected** — no legacy file, nothing to warn about.

**This is a stronger warning than it looks.** Unlike most other stores retiring
their legacy-SQLite path in this same release, a genuinely non-empty
`guaranteed-state.db` here means real Guardian rules an operator authored are
silently NOT loaded — enforcement resumes from an empty rule set, not the
operator's prior policy. (Guardian Baselines carry the same consequence — see
the BaselineStore section above.) If you see the legacy-row-count warning above and the
environment genuinely has real rules to keep, there is no automated recovery
path: re-author the equivalent rules against the new Postgres-backed store via
the Guardian UI/REST API before relying on it, and confirm the expected rules
are actually present (see Verify below) rather than assuming they carried over.

**Verify:** after the server reports ready, `/guardian` shows the expected rules
(re-authored via the Guardian UI/REST API on a fresh install, or already-live
Postgres data on a redeploy) — do not rely on the absence of the legacy-row-count
warning alone as confirmation that nothing was lost.

## Compliance policy engine moves to Postgres (PolicyStore, ADR-0056)

The `PolicyStore` — compliance policy fragments/policies behind `POST/DELETE
/api/policy-fragments*`, `POST/DELETE /api/policies*`, `POST /api/policies/{id}/{enable,
disable,invalidate,evaluate,remediate}`, `GET /api/compliance*`, and every dispatched
compliance check/fix/verify — runs on the server's PostgreSQL substrate, schema
`policy_store`, on the existing shared pool. Six operator-authored tables (fragments,
policies, and their input/trigger/group associations, plus per-agent `policy_status`)
plus a new operational-only seventh table, `policy_dispatch_state`, which coordinates
fleet-wide compliance-check dispatch across replicas.

**No legacy-SQLite migration path.** No production fleet ever ran a pre-Postgres build
of this store, so there was no real `policies.db` data to carry over — the one-time
backfill mechanism this section originally described was retired shortly after this
store's Postgres migration merged, under ADR-0009's fresh-start-by-default amendment.

These are two SEPARATE failure/detection behaviors, not one — do not conflate them:

- A reachable Postgres database whose schema can't migrate or open **is** a fatal
  startup error (fail-closed, matching the ladder's "authoritative" posture for this
  store), same as every other born-on-Postgres store.
- A legacy `policies.db` file with real content **does NOT** fail startup and its
  content is **never imported** — the server opens it read-only, purely to count rows
  for a diagnostic warning, then boots fresh-started regardless of what it finds. If
  either the `policies` or `policy_fragments` table has rows, it logs `A legacy
  policies.db (<path>) has <N> policy row(s) and <N> fragment row(s) but PolicyStore no
  longer backfills it...` at WARN; if the file exists but its row counts can't be read
  (corrupt, unreadable, or a locked file), it logs a similar countless warning instead.
  Either way, boot proceeds unaffected. If you see either warning and the environment
  genuinely has real compliance-policy data to keep, there is no automated recovery
  path: re-author the equivalent fragments and policies against the new Postgres-backed
  store via `POST /api/policy-fragments` and `POST /api/policies` before relying on it.

**Operator-visible behaviour changes (fail-closed reads/writes).**

- A genuine store degrade on any of the six policy/fragment mutator routes, `/evaluate`,
  or `/remediate` now returns **503** (`{"error":{"code":503,"message":...}}`) instead
  of collapsing into the same `400`/`500` a validation error or business rejection gets
  — the earlier behaviour leaked the internal error string into the response body and
  gave callers no way to distinguish "retry" from "don't retry."
- Compliance-check dispatch is now a durable, fleet-wide single-sweeper claim
  (`pg_try_advisory_xact_lock`) rather than each replica's own in-memory timer — a
  persistently-failing claim (compliance checks silently stop running fleet-wide) now
  logs at `error` and increments `yuzu_server_policy_eval_errors_total{phase="claim"}`,
  where it previously only warned with no counter.
- `POST /api/policies/{id}/remediate` now rejects (409) a second call for the same
  policy while a remediation it already started is still in flight — same-process
  dedup only; a cross-replica race is a documented, tracked gap, not yet closed.
- The compliance dashboard's hero no longer claims a "Last evaluated: just now"
  freshness that the server was not actually tracking — no dashboard regression, since
  no timestamp was ever computed; the freshness claim itself has simply been removed
  rather than shipped false. A real evaluation-health signal is tracked as a follow-up.

**Verify:** after the server reports ready, `GET /api/compliance` returns the expected
policies and fleet compliance percentage.

## Runtime configuration migrates to Postgres — OIDC client secret now encrypted at rest, config resets on cutover (RuntimeConfigStore, ADR-0060)

`RuntimeConfigStore` — the Settings-configurable overrides behind `GET`/`PUT
/api/config/:key` (retention windows, `log_level`, DEX alert-routing knobs, and the
`oidc_*` OIDC parameters) — moves from the SQLite `runtime-config.db` file to the
server's PostgreSQL substrate in this release, schema `runtime_config_store`.
`WebhookStore` and `InstructionStore` have both since merged; `OffloadTargetStore` is
now the only server store remaining on the Postgres migration ladder.

**Before you upgrade, if you use OIDC/SSO configured through Settings (not
`--oidc-client-secret`/the environment): record your IdP client secret now.** Yuzu
cannot recover it for you — `GET /api/config` never returns a secret's real value — and
this cutover does not carry it forward (see below). Without it on hand, restoring SSO
after this upgrade means generating a new client secret with your identity provider.

- **Your stored overrides do NOT carry over on this cutover.** Per ADR-0009's
  fresh-start-by-default amendment, the legacy `runtime-config.db` is never copied — no
  production fleet has ever run a pre-Postgres Yuzu build, so the mandate to preserve
  real operator config across the cutover has nothing real to preserve for this
  migration. If your `runtime-config.db` DID hold real overrides, the server checks for
  this at boot and logs a warning naming the exact count found (e.g. "legacy
  runtime-config.db holds 2 override(s) that will NOT be carried over"). **This check
  only ever inspects the legacy SQLite file — it has no way to know whether you have
  already reapplied the warned-about overrides, so it repeats on every boot for as
  long as that file still holds rows, not just the first one after cutover.** Reapply
  your overrides via Settings once, then either delete the legacy file (see below) or
  ignore the repeated warning — it is expected until you do. Every key starts at its
  CLI/env default until you do.
- **This does NOT affect OIDC configured via `--oidc-client-secret`/the environment.**
  Only Settings-configured values are reset; a secret supplied at the process level is
  read at every boot regardless of this store and is untouched by this migration.
- **`oidc_client_secret` is now encrypted at rest** (SecretCodec envelope, AES-256-GCM)
  instead of plaintext, from the point you reapply it onward.
- **The legacy `runtime-config.db`'s CONTENT is left in place, and may still contain your
  old OIDC client secret in plaintext.** This release never reads its content beyond a
  boot-time row count, never moves it, never deletes it — but it DOES force the file's
  permission bits (and any `-wal`/`-shm` sidecar's) to 0600 on every boot as a defence-in-depth
  hardening step, so "untouched" applies to content only, not to permission bits. If you
  previously configured `oidc_client_secret`, delete this file (or otherwise secure it)
  after confirming you no longer need it — it is not required for the server to run, and
  leaving it in place is a plaintext-credential-on-disk exposure this migration does not close
  on your behalf.
- **`GET`/`PUT /api/config/:key` now return an honest 503** on a genuine database
  error, rather than a response indistinguishable from "nothing configured" (`GET`)
  or a `400` validation failure (`PUT`). No change to either route's success-path
  response shape.
- **Rolling back:** because the legacy `runtime-config.db`'s content is never moved or renamed
  (only its permission bits change, per above), reverting to a pre-cutover binary restores your
  pre-cutover overrides — including a plaintext OIDC client secret, if one was there — exactly
  as they were. Anything you
  set through Settings on the Postgres-backed binary lives only in Postgres and is
  lost on rollback (reapply it after rolling forward again).
- No Settings UI or dashboard-visible change beyond the one-time reset. See
  [`security-hardening.md`](security-hardening.md) for the pre-existing OIDC secret
  redaction behaviour (unchanged by this migration) and `docs/adr/0060-runtime-config-store-postgres-migration.md`
  for the full design.

## ⚠️ Behaviour change: offload targets reset on Postgres cutover (ADR-0059)

`OffloadTargetStore` — the response-offload control plane behind
`/api/v1/offload-targets` — moves from the SQLite `offload_targets.db` file to the
server's PostgreSQL substrate in this release, schema `offload_target_store`, on the
existing shared pool. Like `ResponseStore`/`AnalyticsEventStore`, this is a
**fresh-start cutover with no data migration** (ADR-0009's 2026-08-25
fresh-start-by-default amendment — no production fleet has ever run a pre-Postgres
build of this store, so there is no legacy backfill to protect), so the legacy
`offload_targets.db` is **never read** on upgrade.

**Before you upgrade, if you have offload targets configured:** the non-secret fields
(`name`, `url`, `auth_type`, `event_types`, `batch_size`, `enabled`) are recoverable via
`GET /api/v1/offload-targets` — list them now to speed up re-registration after the
cutover. Credential values themselves were never GET-recoverable even before this
migration (`auth_credential` has always been redacted from every response), so there
is nothing new to lose there — only the non-secret configuration is worth capturing.

**What happens on first PG boot:**
- The server logs a one-time `OffloadTargetStore initialized (schema
  offload_target_store) — fresh start, no legacy backfill` line.
- Every previously-configured offload target and its delivery history is gone; targets
  must be re-registered via `POST /api/v1/offload-targets` (including credentials —
  they were never durably exportable in plaintext form to begin with).
- No operator action required beyond re-registering targets.

**Also in this release:** `auth_credential` is now encrypted at rest app-side
(ADR-0010) rather than a plaintext column; `GET`/`list()` responses gain a
`has_credential` boolean alongside the already-redacted `auth_credential`. A delivery
whose target's credential fails to decrypt (KEK unavailable, a tampered/corrupted
stored blob) is skipped entirely and logged with `error=credential_unavailable` — it is
never fired unsigned. A degraded read on `GET /api/v1/offload-targets` or
`GET /api/v1/offload-targets/{id}` now returns **503**, distinguishable from a genuine
"no targets configured" (empty list) or "no such id" (404).

**Rolling back:** because the legacy `offload_targets.db` is never touched by the
Postgres-backed binary (not read, not moved, not deleted), reverting to a pre-cutover
binary restores whatever was in that file **before** the cutover, exactly as it was.
Any target registered through `POST /api/v1/offload-targets` on the Postgres-backed
binary lives only in Postgres and is lost on rollback (re-register it after rolling
forward again).

## ⚠️ Behaviour change: OTA package catalog resets on Postgres cutover (UpdateRegistry, ADR-0061)

`UpdateRegistry` — the OTA agent-update catalog behind the gRPC `CheckForUpdate`/
`DownloadUpdate` handlers and the Settings → Updates admin page — moves from the SQLite
`update_packages.db` file to the server's PostgreSQL substrate in this release, schema
`update_registry`, on the existing shared pool. Like `OffloadTargetStore`/`ResponseStore`,
this is a **fresh-start cutover with no data migration** (ADR-0009's 2026-08-25
fresh-start-by-default amendment), so the legacy `update_packages.db` is **never read for
data migration/backfill** on upgrade — the server does open it read-only once, at boot, to
count rows and warn if it finds any (see "What happens on first PG boot" below), but never
to carry any of them over.

**Before you upgrade, if you have OTA packages configured:** list them via the Settings →
Updates page first so you know what to re-upload. Package **binaries already on disk under
your configured `update_dir` are untouched** by this cutover — only the metadata row (sha256,
rollout percentage, mandatory flag) is lost — so re-uploading the same file after upgrading
reproduces the identical sha256/size.

**What happens on first PG boot (OTA is on by default — see the note below if you've passed
`--no-ota`):**
- The server logs a one-time `UpdateRegistry initialized (schema update_registry) — fresh
  start, no legacy backfill` line.
- Every previously-configured package's metadata is gone; agents see "no update available"
  until packages are re-uploaded via `POST /api/settings/updates/upload`.
- No operator action required beyond re-uploading packages.

**Also in this release:** construction is now fail-closed for OTA (on by default; disable with
`--no-ota`, not an opt-in flag) — a reachable database whose `update_registry` schema fails to
migrate/open now refuses to start the server, rather than silently serving with OTA dead (the
pre-migration code had no such check). `ca_store`/`scim_store`'s own fail-closed construction
is already unconditional on every deployment (only their probe checks are gated, on whether
you're using default certs / have SCIM enabled) — `UpdateRegistry` is simply the first of the
three where that same construction-time posture applies with **no opt-out flag set by
default**. Plan accordingly if you're upgrading a fleet you haven't audited for Postgres
reachability — this now affects the ordinary default deployment, not an opt-in minority. `UpdateRegistry` now appears in `/readyz`'s check list and in
`/health`'s `stores` object (previously absent from both). On `/readyz`, a deployment running
with `--no-ota` sees no change — the check is vacuously true and never enters the failed list. On
`/health`/`/api/health`, a new `stores.update_registry: "ok"`/`"error"` key appears in the JSON
body for **every** deployment, `--no-ota` or not.

**Rolling back:** because the legacy `update_packages.db` is never written by the
Postgres-backed binary (opened read-only at most once, at boot, for the row-count warning
above — never moved, never deleted, never modified), reverting to a pre-cutover binary
restores whatever was in that file **before** the cutover, exactly as it was. Any package
uploaded through the Postgres-backed binary lives only in Postgres and is lost on rollback
(re-upload it after rolling forward again) — but its binary on disk under `update_dir`
survives regardless, since the cutover never touches that directory.

## ⚠️ Behaviour change: quarantine is now enforced at instruction dispatch (#881, #3127)

Quarantine previously isolated a device's network without stopping the control plane from
sending it commands. This release closes that, and separately removes two paths on which the
MCP `quarantine_device` tool claimed an isolation it had not achieved. Read this before
upgrading a deployment that quarantines devices — the alert-rule item needs operator action.

The agent-side plugin containment fixes (IPv6 coverage, and honest reporting on all three
platforms) ship separately and have their own upgrade note.

### A quarantined device is now refused at dispatch (#881)

Quarantine previously isolated a device's network without stopping the control plane from
sending it commands: the feature was enforced at the endpoint and nowhere else. Instruction
dispatch now consults containment state at the server's single dispatch chokepoint, and a
quarantined device is dropped from **every** targeting arm — by id, by scope, by management
group, and by broadcast — before the command reaches the agent.

- Denials increment `yuzu_server_dispatch_target_rejected_total{reason="quarantined"}` and write
  a `quarantine.dispatch_denied` audit row (`result=denied`).
- **The quarantine plugin's own four actions are exempt** — `quarantine`, `unquarantine`,
  `status`, `whitelist` — so release stays reachable on a contained host. The exemption is keyed
  on the action, not the plugin, so a future fifth action arrives gated rather than inheriting the
  bypass.
- **Three server-internal pushes are also exempt** — `tar.fleet_snapshot`, `__guard__.push_rules`
  and `asset_tags.sync`. These are the server keeping its own state coherent, not operator
  dispatch, and gating the Guardian push would stop a contained device receiving the enforcement
  rules that make containment meaningful. If your threat model treats quarantine as a total
  boundary, note that it is not: those three channels stay open. They are a closed set in code and
  are counted by `yuzu_server_system_reserved_push_total{capability,result}` — counted, not
  per-event audited: there is no row tying a particular push to a particular contained
  device, so this is a fleet-level signal rather than per-device evidence. Nothing outside that
  set and the plugin's own four actions reaches a quarantined device.
- **Operator-visible:** automation that dispatched to quarantined devices and appeared to succeed
  will now receive denials. That is the correction, not a regression — those commands were never
  going to be safe to run on a device you had isolated.

**Fail-closed under a degraded store.** If containment state cannot be read, the server serves a
last-known-good snapshot for up to **60 seconds**; past that, or when the store is durably
unavailable, dispatch **fails closed and refuses every target fleet-wide** rather than guess who
is contained. A background refresher re-reads containment state every 20 seconds, so the snapshot
is warm even on a server with no operator traffic — without it the budget would only have
absorbed anything on a busy server, which is not when you need it.

**The snapshot window cuts both ways, and the other direction is the quieter one.** While a
stale snapshot is being served, a device quarantined *after* that snapshot was taken is absent
from it — so dispatch to that device is **permitted**, and audited as an ordinary success. For
up to the snapshot's remaining budget, containment does not hold for a freshly-quarantined
device. The refresher bounds that window to roughly the refresh interval in the common case, and
`YuzuQuarantineGateServingStaleState` alerts on it; if you quarantine a device while
`yuzu_server_quarantine_read_degrade_total` is non-zero, confirm with `quarantine.status`
rather than assuming the dispatch gate is already holding.

**There is no operator override.** The 60-second budget is a fixed bound, not a tunable, and
there is no flag to disable enforcement — a knob that let an operator turn the gate off under
pressure would be the first thing reached for during exactly the incident it exists for. What
survives a store outage regardless: the quarantine plugin's own four actions (they never read the
store), and the three server-internal pushes below. So containment, release and whitelist repair
all remain possible while the store is down; what stops is other operator dispatch. Alert on `yuzu_server_quarantine_gate_total{outcome="fail_closed"}` — it means
instruction dispatch has stopped, and it is an outage signal rather than a quarantine one. All four `outcome` values are pre-seeded at boot, so a **zero is a measurement** rather than an absent series — you can alert on `fail_closed` before it has ever fired. Absence of the family then means the server is not exporting it at all (an older build, or a scrape that is failing), not that the gate is idle: a booted server publishes all four from boot whether or not any dispatch has happened yet.

**Alert-rule change (action may be required).** `YuzuDispatchTargetRejected` now excludes
`reason="quarantined"`. Without that exclusion, correct enforcement fires the alert: any looping
automation against one contained host clears its `>3/15m` threshold, and a fail-closed episode
increments by the whole fleet at once. If you maintain a fork of `docs/prometheus/yuzu-alerts.yml`,
apply the same exclusion — otherwise the rule gets silenced and the genuine #2500 near-miss signal
goes with it.

### MCP `quarantine_device` no longer reports phantom isolation (#3127)

Two independent bugs made the tool claim containment it had not achieved. Both are fixed, and
both are **wire-visible to an MCP client**:

- `agents_reached=0` (the agent was offline) or a dispatch that threw previously returned a
  success envelope. It now answers `-32603` — *"quarantine recorded but isolation was not
  confirmed"* — with `retry_after_ms: 5000` on a first failure. A **repeat** failure against a device that already
  has a record backs off to `60000`: the device is offline rather than busy, and (**at the time
  #3127 shipped**) nothing changed until an operator re-issued the call once the device
  reconnected — a device quarantined while offline was contained at the control plane
  (dispatch to it was refused) but **not** at its own firewall until a quarantine dispatch
  actually reached it. **#3425 closed that gap**: `QuarantineContainmentReconciler` now
  re-applies the stored whitelist automatically on reconnect (heartbeat-triggered, with a
  periodic tick backstop), so a manual re-issue is no longer required — it remains
  harmless if issued anyway. **The record still persists**; retry the same call to
  re-drive dispatch if you prefer not to wait for the automatic reconciler.
- An **already-quarantined** device was a terminal error. It is now a retryable re-dispatch
  against the **stored** `reason`/`whitelist`, not the retry's own arguments — a retry cannot
  silently rewrite a contained device's allow-list with no store update and no audit trail.

`dispatch_confirmed:true` means the plugin registry **accepted the frame**, never that the device
is provably isolated (for a gateway-attached agent the frame is only queued). Confirming
containment still requires a follow-up `status` read returning `state|active`.

**Note the REST twin has diverged on one case.** `POST /api/v1/quarantine` records only — it has
never dispatched — so it still answers `400` on an already-quarantined device: there is nothing
for it to re-drive. The `400`-vs-`503` split is otherwise unchanged.

### No migration, no schema change

Rollback is data-safe. A mixed fleet is safe: the dispatch gate is server-side and applies
regardless of agent version.

## ⚠️ Behaviour change: raw dispatch now enforces InstructionDefinition approval governance (#1398)

An `InstructionDefinition`'s declared `approval.mode` (`role-gated`/`always`) was previously
enforced only on the governed `POST /api/instructions/:id/execute` path — raw dispatch
(`POST /api/command`, MCP `execute_instruction`/`execute_bundle`/`quarantine_device`, the
dashboard, workflow, schedules, and `/auto` Deploy) never resolved a definition, so a caller who
held plain RBAC permission on an action could bypass its declared review requirement entirely by
dispatching directly instead of through the governed path. This release closes that at the single
shared dispatch chokepoint. **Read this before upgrading if any automation, integration, or
scripted workflow dispatches commands as a non-admin principal** — an operation that previously
succeeded may now be refused.

### What changed

Every dispatchable `plugin.action` pair now carries a compiled `ExecuteGate`
(`None`/`AdminOrApproval`/`AlwaysApproval`), derived strictest-wins from every shipped
`InstructionDefinition` targeting that pair. **42 pairs are gated** as of this release —
including every `script_exec.*` action, `filesystem.delete_lines`/`.write_content`/`.replace`,
`registry.set_value`/`.delete_key`/`.delete_value`, `interaction.*`, `network_actions.*`,
`wol.*`, `quarantine.quarantine`/`.unquarantine`/`.whitelist`, `rdp_control.set_state`,
`certificates.delete`, `storage.*`, `tags.clear`, `discovery.scan_subnet`, `chargen.chargen_start`,
`http_client.download`, `installed_apps.list_per_user`, `services.set_start_mode`,
`tar.configure`, and `content_dist.*` — the complete, authoritative list is
`tests/fixtures/1398_pair_gate_table.json` (search for `"AdminOrApproval"`/`"AlwaysApproval"`,
excluding the `server`/`server_internal`/`_server`-prefixed rows, which are server-internal and
never agent-dispatched).

A gated pair now denies a non-admin caller with no covering approval, **regardless of which
surface dispatched it**:

- **REST** (`/api/command`, and the legacy `chargen`/`procfetch` routes): `403`, naming the gate
  and pointing at the governed alternative (`{"error":{"code":403,"message":"approval required
  for <plugin>.<action> — ... dispatch it via POST /api/instructions/{id}/execute instead,
  which supports the approval workflow"}}`). Denials are audited (`command.dispatch`,
  `result=denied`, `detail=reason=approval_required`) and counted
  (`yuzu_server_dispatch_denied_total{reason="approval_required"}`).
- **MCP** (`execute_instruction` at `operator` tier — `supervised` tier already goes through the
  approval workflow): the denial is now a discriminated JSON-RPC error naming the reason
  (`error.data.reason: "approval_required"`), not the `no_agents_reached` tool result an
  offline/unreachable agent gets (CLOSED by #3687 — a `no_agents_reached` result no longer needs a
  manual check for whether a pair is gated before you trust it, aside from the same narrow
  dry-run-then-real-check TOCTOU window every pre-dispatch authorization check in this codebase
  accepts). **`approval_required` is one of six discriminated reasons, not the only one** — the
  same fix discriminates `Unclassified`/`Ambiguous`/`AnonymousOperator`/`Forbidden`/`KillSwitched`
  too, so a caller that only added handling for this release's `approval_required` change gets no
  warning that `Forbidden` (the most common denial in practice — a caller with no covering grant
  at all, not just an ungated approval gap) now arrives as the same kind of discriminated
  JSON-RPC error rather than the old `no_agents_reached`/ambiguous-success shape. **This coverage
  is no longer `execute_instruction`-only**: #3893 extended the identical pre-dispatch dry run
  (both the C8 pre-mint check and the main-handler backstop) to `execute_bundle` (a denied step
  now refuses the whole bundle call up front — previously an entirely-denied bundle returned a
  false JSON-RPC success naming the requested step count) and `quarantine_device` (a denial now
  runs before the quarantine record is written, and before dispatch, instead of mapping every
  denial reason to the same "retry" hint an offline device gets).
- **Schedules**: a schedule dispatching a gated pair now requires an approval ticket exactly like
  the interactive governed path (`ScheduleRunner` mints one and holds the occurrence until an
  admin approves it via the existing `/api/approvals` workflow) — this was already the behavior
  for schedules with their own `requires_approval` flag set; it now ALSO applies whenever the
  target pair itself is gated, independent of that flag.
- **`/auto` Deploy**: content_dist dispatches are unaffected — the deployment pipeline's own
  re-authorization, guarded state transitions, and audit trail are accepted as the equivalent
  control (`ApprovalProvenance::GovernedPipeline`), so no new ticket is required there.

### How to check your exposure before upgrading

Query the audit log for `command.dispatch` rows (or your own automation's recent activity) whose
`plugin`/`action` appears in the gated list above, dispatched by a non-admin principal. If you
find any, either grant the dispatching principal an admin role, or migrate that automation to
dispatch through the governed path (`POST /api/instructions/:id/execute`, or an MCP
`supervised`-tier token) so it goes through the approval workflow instead of raw dispatch.

### Schedule approval tickets are now bound to their reviewed content

A separate hardening in this same release: a schedule's approval ticket is now bound to the
specific `plugin`/`action` it was approved for, not just the definition's id. If a definition's
`plugin`/`action` is edited (`PUT /api/instructions/{id}`) after a schedule's ticket for it was
approved but before the schedule's next fire, the stale ticket no longer redeems — the schedule
correctly requests a fresh ticket for the new content instead of firing under review that was
never given for it. This is self-healing (no manual database intervention needed): approve the
new ticket the same way you approved the original. You would only notice this if you edit a
scheduled definition's target action between approval and fire, which is unusual but not
unsupported.

### Migration

`ApprovalManager`'s SQLite schema gains two additive columns (`target_plugin`, `target_action`,
migration v8) — no backfill, no data loss, safe on a large existing `approvals` table (constant
default, metadata-only `ALTER TABLE`). Rollback is safe: an older binary ignores the two new
columns on read and simply doesn't populate them on write, which the new binary's fail-closed
matching correctly treats as "must re-request" rather than a corruption state.

### No config flag, no override

There is no flag to disable the new gate. An admin caller, or a caller dispatching via the
governed path with a redeemed approval ticket, is not subject to it.

## Behaviour change: a `rule_id` outside the documented charset is now rejected at creation (#4665)

`POST /api/v1/guaranteed-state/rules` and MCP `create_guardian_rule` now enforce the documented
`rule_id` charset (`[A-Za-z0-9._-]+`, at most 256 bytes) at creation — a request whose `rule_id`
violates it now gets `400` (REST) or an error (MCP), audited as `guaranteed_state.rule.create`
`denied`, instead of being accepted on any non-empty string. This closes an operator-authored
log-injection exposure (#4665): log lines across the Guardian/Spark subsystem now also neutralise
a rule id or Spark key before printing it, but a `rule_id` that never conformed to the documented
shape (a space, a newline, or any other disallowed byte) could previously still be created.

**Who this affects:** almost nobody — the charset was already documented before this release, just
not enforced, so create requests generated by the dashboard, the REST/MCP tooling, or any client
following the documented contract are unaffected. This only changes behaviour for a caller that was
relying on the previously-permissive accept-anything-non-empty behaviour to create a `rule_id`
outside `[A-Za-z0-9._-]+` or longer than 256 bytes.

**What to do — this is a hard cutover, not a migration, by deliberate decision:** enforcement at
the server is create-only, so an existing rule whose `rule_id` predates this release and doesn't
conform to the charset is never torn down *by the creation check itself*. But the server-side push
builder now **excludes** any such row from every push it builds (logged at `error` with a sampled
rate limit as `Guardian push: rule ... has a rule_id that fails the .../256-byte charset check
(#4665) — excluding it from this push`, and counted in
`yuzu_guardian_push_rule_excluded_total{reason="invalid_rule_id"}`), the same way an over-depth
`spec_json` is already excluded — and the agent's `full_sync` path unconditionally tears down and
rebuilds its ENTIRE active rule set from whatever the push actually contains. Put together: **the
first `full_sync` an upgraded agent receives permanently disarms every rule with a non-conforming
`rule_id`** (logged at `warn` on the agent, matching `full_sync is disarming N rule(s) with a
rule_id outside the [A-Za-z0-9._-]+/256-byte charset (#4665) -- hard cutover, not preserved`). This
is not silent — the server-side exclusion is both logged AND metered
(`yuzu_guardian_push_rule_excluded_total`); the agent-side disarm is logged only, with no metric of
its own yet — but it IS a real, one-time loss of a previously-enforcing control if you don't act
first. Every OTHER rule in scope is unaffected either way — this only ever touches rows that were
already unenforceable by the documented contract.

**Finding a non-conforming legacy `rule_id` — do this BEFORE upgrading, not after:** `GET
/api/v1/guaranteed-state/rules` returns every rule regardless of its `rule_id`'s shape; filter the
response for any `rule_id` that doesn't match `^[A-Za-z0-9._-]{1,256}$` — that's the same predicate
the server now enforces at creation. For each one you find, either delete it (see below) and
recreate it under a conforming `rule_id`, or accept the loss consciously — there is no third option
that preserves it under its existing id.

**Removing a non-conforming `rule_id`:** the two delete surfaces have DIFFERENT restrictions, not
a simple REST-restricted/MCP-unrestricted split. REST `DELETE
/guaranteed-state/rules/{rule_id}` routes on the same charset regex the create path now enforces
(`[A-Za-z0-9._-]+`, no length bound), so it **can't** reach a `rule_id` containing a byte outside
that charset, but it has no length cap of its own and so **can** reach one that's charset-clean but
over 256 bytes (a shape only possible pre-#4665, when creation had no length bound either). MCP
`delete_guardian_rule`'s own input schema caps at `maxLength: 256` with no charset `pattern`, so it
has the exact opposite gap: it **can** reach a charset-violating id (any length up to 256), but
**can't** reach one that's charset-clean and over 256 bytes — the request is rejected by schema
validation before the handler's own logic ever runs. A `rule_id` that violates BOTH (wrong charset
AND over-length) is reachable by neither REST nor MCP; fall back to a direct database delete
(`guaranteed_state_store.guaranteed_state_rules`) for that case.

## Upgrade Order

Always upgrade in this order:

1. **Server** -- new server versions accept connections from older agents
2. **Gateway** -- updated to match server protocol changes
3. **Agents** -- can be upgraded via OTA or manually, in batches

Never upgrade agents before the server -- the server must understand the agent's protocol version.

## Pre-Upgrade Checklist

Before upgrading any component:

- [ ] Back up all data (see [Server Administration](server-admin.md))
  - `yuzu-server.cfg`, `enrollment-tokens.cfg`, `pending-agents.cfg`, `auto-approve.cfg`
  - The NVD cache `nvd_cves.db` in `--data-dir` (the one remaining server SQLite store) — use `sqlite3 <path> ".backup ..."` rather than `cp` against a live database
  - The blob directories `agent-updates/` (or your `--update-dir`) and `upload-blobs/` in `--data-dir` — the database holds only the OTA-package and completed-upload records that point into them, so a restored dump without these directories leaves records with no files
  - The **PostgreSQL database** (ADR-0006 — bundled in the composes; provisioned natively by `install-server-postgres.sh`) **and the whole `--ca-dir`**, taken at the same point in time — use `pg_dump --format=custom`; see [Server Administration § PostgreSQL Substrate](server-admin.md#postgresql-substrate) for the full backup/restore procedure and the ADR-0010 restore-pairing invariant (DB and `KeyProvider` keys-dir backups restore **together**)
- [ ] **Verify the server's clock before upgrading** (`timedatectl status` or
  `chronyc tracking`; under Docker it is the host's clock that matters). Rows
  already stamped cannot be protected retroactively by any setting, and a server
  upgraded to schema v3 while its clock was skewed FORWARD could delete expired
  audit rows unremarked on its first guarded pass - see [Retention clock
  guards](#retention-clock-guards-2360-server-audit-store-2361-tar-agent-warehouse)
  below and #2579. Fixed forward: that pass now declines instead, so the risk is
  to servers upgrading FROM an affected version with a wrong clock.
- [ ] Check the [CHANGELOG](../../CHANGELOG.md) for breaking changes
- [ ] Verify disk space (at least 500 MB free for migration)
- [ ] Note current version: `yuzu-server --version` / `yuzu-agent --version`
- [ ] Plan a maintenance window (upgrades take < 5 minutes per component)
- [ ] **Review new opt-in telemetry:** this release adds DEX per-application
  performance sampling (`procperf`), a new usage-class data category. It is
  **off by default** (no action needed to keep it off) — but if you intend to
  enable it for an EU workforce, treat it as a works-council co-determination
  trigger. See the *DEX per-application sampling* upgrade note in
  [Server Administration](server-admin.md#upgrade-notes).
- [ ] **New device performance sampling on Linux:** this release wires the TAR
  `perf` collector on **Linux**, and because it is default-ON, Linux agents
  **begin recording on-device performance samples automatically on agent
  upgrade** (device-level, no user identity; opt out per host with
  `tar.configure perf_enabled=false`). These rows carry no per-user or per-app
  identity, but the project treats the *capability to observe* as the
  works-council co-determination trigger, so EU deployments should note the new
  Linux coverage as they did for the Windows network facts below.
  Per-application sampling (`procperf`) is now also implemented on Linux but
  remains **opt-in on every OS** — the works-council posture above applies
  unchanged. Details and caveats: the upgrade note in
  [the TAR user manual](tar.md#performance-impact).
- [ ] **New network telemetry on Windows:** this release makes **Windows** agents
  emit device-aggregate network facts (throughput + interval retransmit rate) on
  the heartbeat, automatically on agent upgrade — gated by the existing
  `--dex-disable` / `YUZU_AGENT_DEX_DISABLE` flag (no separate opt-in). These
  carry no per-user or per-application identity (lighter than `procperf`), but the
  project treats the *capability to observe* as the works-council co-determination
  trigger, so EU deployments should note the new Windows coverage as they did for
  the DEX signals. See [Network Quality](network.md) → Collection & privacy.
- [ ] **New daily installed-software sync (ADR-0016):** on agent upgrade, agents
  begin syncing their **machine-wide installed-software** inventory to the server
  once per ~24 h over the existing gRPC channel (hash-skip keeps unchanged hosts
  to a tiny hash, not the full list). Three operator-visible effects: (a) new daily
  outbound `ReportInventory` traffic per agent — adjust egress baselines/firewall
  expectations; (b) the data lands in a **new Postgres schema**
  (`software_inventory_store`, auto-migrated at boot, fail-closed); (c) it requires
  the `installed_apps` plugin to be loaded — a build with `-Dbuild_agent=false`
  (or a plugin dir missing it) collects **nothing**, silently (agent logs only at
  debug). Machine-scope only, no end-user PII (no username collection) — but the
  data is device-attributable, and on **personally-assigned devices** installed-
  software enumeration may be **works-council co-determination-relevant** (see the
  works-council note in [Installed-Software Inventory](inventory.md)). To suppress
  collection entirely, pass **`--inventory-disable`** / set
  `YUZU_AGENT_INVENTORY_DISABLE` on the agent (deploy-time opt-out). Reads are
  gated on the new `Inventory:Read` RBAC securable; today the data is queryable via
  direct SQL (see [Installed-Software Inventory](inventory.md)). On a **non-English
  fleet**, upgrading across #1662 changes stored names: app/publisher names that
  earlier builds mangled to `?` (cp1252) are rewritten to correct UTF-8 on each
  agent's next daily sync, so any query automation that matched the corrupted `?`
  strings will return nothing afterward — see the non-ASCII troubleshooting note in
  [Installed-Software Inventory](inventory.md) for the force-resync path.
- [ ] **`installed_apps list` rows carry two more fields (breaking for fixed-width parsers):** the operator `list`
  action now emits seven fields instead of five (`…|install_date|install_location|bundle_id`). Check any script,
  SIEM parser or export that reads `crossplatform.software.inventory` output; agents not yet upgraded keep
  emitting five and do not escape `|`, so accept a row only when it has exactly 5 or exactly 7 escape-aware
  tokens, reading the sixth/seventh only from agents known to be on plugin 1.2.0+. See
  [Server Administration](server-admin.md#upgrade-notes).
- [ ] **New SparkEngine health telemetry (auto-on, engine-health only):** on agent
  upgrade, agents begin shipping SparkEngine posture tags on the existing
  heartbeat (2 keys when quiescent), and the server exposes 11 new
  `yuzu_fleet_spark_*` gauges. The engine is **observe-only at this rung** —
  nothing about Guard detection or enforcement changes — and the tags are pure
  engine-health counts (no user, process, or path identity; no works-council
  trigger). During a staged rollout, not-yet-upgraded agents are simply absent
  from the new gauges — expected, see the staged-rollout example in
  [Metrics](metrics.md#sparkengine-fleet-gauges). Deploy-time opt-out:
  `--spark-disable` / `YUZU_AGENT_SPARK_DISABLE` (the opt-out itself stays
  visible as `yuzu_fleet_spark_disabled`). See
  [Guaranteed State](guaranteed-state.md#sparkengine--the-next-generation-detection-engine-observe-only).
- [ ] **Changed agent signal handling (Linux/macOS):** graceful shutdown now runs
  on a dedicated watcher thread (fixes an abort/hang class on `SIGTERM`), and a
  **second** `SIGTERM`/`SIGINT` immediately hard-exits the agent (exit 1) —
  by design, with **no grace window**: the second signal is read as "the stop is
  wedged". Stop scripts that deliberately double-signal agents will now
  force-kill them; send one signal and wait instead. On Windows a second Ctrl-C
  also terminates promptly. See *Stopping a wedged agent* in
  [Server Administration](server-admin.md).
- [ ] **New agent shutdown watchdog (#2233 item 3, "S+"):** on upgrade, both
  `AgentImpl::stop()` and the agent's own `run()`-exit teardown arm a 20-second
  internal deadline; if guardian/spark/DEX teardown or any other blocking step
  hasn't returned within it, the agent self-terminates (`hard_exit`, **exit
  code 4** — new, distinct from the existing codes 1 and 3 above) instead of
  hanging indefinitely. You do not need to send a second signal to recover from
  this class of wedge — sending one just makes the exit happen sooner (code 1)
  instead of after the 20s deadline (code 4); which code is actually reported
  is a race if both happen for the same wedge, so treat it as a hint, not a
  certain diagnosis. On Windows, `sc stop`/service shutdown is now also bounded
  by the same 20s watchdog; the agent's `--install-service` recovery-actions
  configuration (#1822) auto-restarts on a watchdog fire similarly to the
  Linux `Restart=always` unit, but the exit shows up as a generic unexpected
  termination rather than one of the SCM's own "specific error" buckets.
  `AgentImpl::stop()` and the run()-exit teardown each arm this deadline
  separately, and in the worst case the two can compose sequentially to as
  much as ~40s before either one fires, past the 30s SCM hint — but that
  specific case is a slow clean stop, not a hang or a restart (a clean
  `SERVICE_STOPPED` report doesn't trigger the recovery actions above
  either). See *Stopping a wedged agent* in
  [Server Administration](server-admin.md).
- [ ] **Changed server signal handling (Linux/macOS, #3007):** the identical fix
  as above, now applied to the server — graceful shutdown runs on a dedicated
  watcher thread (fixes the same abort/hang class on `SIGTERM`, previously
  reproducible as a debug-build `SIGABRT` from a deadlock detector), and a
  **second** `SIGTERM`/`SIGINT` immediately hard-exits the server (exit 1) with
  **no grace window**. Also new: a `SIGTERM`/`SIGINT` arriving before the server
  finishes starting up now exits promptly with code 1, instead of being
  silently ignored — a boot-time signal genuinely cannot be handled gracefully,
  so this is a fail-visible improvement, but it means a very-early stop attempt
  during a fast redeploy or a mistuned `livenessProbe.initialDelaySeconds`
  (a failing *readiness* probe only pulls a pod from Service endpoints — it
  never sends a stop signal; a failing *liveness* probe is what triggers a
  kill-and-restart) will now observably exit rather than continue booting.
  Stop scripts that
  deliberately double-signal the server will now force-kill it; send one
  signal and wait instead. See *Stopping a wedged server* in
  [Server Administration](server-admin.md).
- **Non-English fleets — additional plugins (#1682).** The same `Reg*A` → `Reg*W`
  encoding fix was extended to four more Windows plugins: `vuln_scan` (app
  DisplayName/Publisher/Version in vulnerability findings), `os_info` (OS
  ProductName / edition), `sccm` (client version), and `windows_updates` (the WSUS
  `WUServer` URL). Unlike `installed_apps`, these produce **transient** response
  data — no stored names are rewritten; each call simply delivers correct UTF-8
  immediately after the agent upgrade. Any operator automation that matched
  previously-mangled non-ASCII strings in those plugins' responses (e.g. a vuln
  finding filtered on `title == "Caf?"`) will need updating.

## Upgrading the Server

### Linux (systemd)

```bash
# 1. Stop the server
sudo systemctl stop yuzu-server

# 2. Back up data
sudo cp /var/lib/yuzu/*.db /var/lib/yuzu/backup/
sudo cp /etc/yuzu/*.cfg /var/lib/yuzu/backup/
# ... and the Postgres database, if provisioned. The DSN lives only in the
# root-only env file (NOT in interactive shells) — load it, and keep the
# password off the argv via PGPASSWORD. Full recipe + restore procedure:
# server-admin.md § PostgreSQL Substrate.
sudo sh -c '. /etc/yuzu/yuzu-server.env
  export PGPASSWORD="$(printf "%s\n" "$YUZU_POSTGRES_DSN" | sed -E "s!^[a-z]+://[^:/@]*:([^@]*)@.*\$!\1!")"
  pg_dump --format=custom --file=/var/lib/yuzu/backup/yuzu-pg.dump \
    "$(printf "%s\n" "$YUZU_POSTGRES_DSN" | sed -E "s!^([a-z]+://[^:/@]*):[^@]*@!\1@!")"'

# 3. Replace the binary
sudo cp yuzu-server /usr/local/bin/yuzu-server
sudo chmod +x /usr/local/bin/yuzu-server

# 4. Start the server (schema migrations run automatically)
sudo systemctl start yuzu-server

# 5. Verify
sudo systemctl status yuzu-server
curl -s http://localhost:8080/livez
```

### Docker

The reference deployment template lives at `deploy/docker/docker-compose.reference.yml` — copy it into your deployment directory next to a `.env` file, set `YUZU_VERSION`, and harden per the inline TLS checklist in the file header **before** exposing the stack to any untrusted network. The compose file declares a named volume (`server-data`) that survives container replacement and holds every piece of mutable state: `yuzu-server.cfg`, all SQLite databases, `enrollment-tokens.cfg`, `pending-agents.cfg`, `auto-approve.cfg`, and OTA binaries.

An upgrade is a pull-and-restart:

```bash
# 1. Back up first (see below) — the old data is the only recovery path
#    if a migration fails on your specific DB.

# 2. Pick the new release tag (use an .env file or export)
export YUZU_VERSION=0.10.1

# 3. Pull the new image and recreate the container
docker compose -f docker-compose.reference.yml pull server
docker compose -f docker-compose.reference.yml up -d server

# 4. Verify the new version came up and schema migrations ran
docker compose -f docker-compose.reference.yml logs server | tail -40
docker compose -f docker-compose.reference.yml ps server    # should be "healthy"
```

Schema migrations execute automatically during the first `up` with the new image — look for `MigrationRunner: <store> migrated to v<N>` lines in the log (one per store on first upgrade, silent on subsequent restarts). The healthcheck used by `depends_on: service_healthy` probes `/readyz`, which returns 200 only after every store in the readiness conjunction has successfully migrated — so a healthy server container genuinely reflects migration success, not just liveness.

**Back up before upgrading** (run from a dedicated backup directory so `$PWD` is predictable):

```bash
mkdir -p ~/yuzu-backups && cd ~/yuzu-backups
docker run --rm -v server-data:/data -v "$PWD":/backup alpine \
  tar czf "/backup/yuzu-data-$(date +%F).tar.gz" -C /data .

# PostgreSQL state (the postgres-data volume) — pg_dump is consistent
# against a LIVE database, no stop required:
docker exec yuzu-postgres pg_dump -U postgres --format=custom yuzu \
  > "yuzu-pg-$(date +%F).dump"
```

> **Note:** this recipe is a cold-ish backup — SQLite is running in WAL mode and a filesystem-level `tar` of a live database may capture a torn snapshot. For strong consistency, `docker compose -f docker-compose.reference.yml stop server` before backup (seconds of downtime) and `start` after. A fully hot backup via SQLite's online-backup API is tracked in the roadmap. The `pg_dump` half has no such caveat — logical dumps are transactionally consistent by construction. **Never** back up Postgres by `tar`-ing the `postgres-data` volume while the database is running; a torn copy of `pg_wal/` is unrecoverable, which is why the procedure above dumps through the database instead.

> **Restore-pairing (ADR-0010 — forward reference):** once envelope-encrypted secrets land, the Postgres dump contains ciphertext + wrapped DEKs only and is unusable without the matching `KeyProvider` keys directory. Back up and restore the two **as a pair** — full procedure in [Server Administration § PostgreSQL Substrate](server-admin.md#postgresql-substrate), key-management runbook tracked in #1341.

**Rollback if a migration fails** (Docker):

```bash
# 1. Stop the new server (KEEPING the named volume — do NOT use -v)
docker compose -f docker-compose.reference.yml down server

# 2. Restore the previous backup over the existing volume
docker run --rm -v server-data:/data -v "$PWD":/backup alpine \
  sh -c 'rm -rf /data/* && tar xzf /backup/yuzu-data-YYYY-MM-DD.tar.gz -C /data'

# 2b. Restore the Postgres dump (postgres container still running)
docker exec -i yuzu-postgres pg_restore --clean --if-exists --no-owner \
  --role=yuzu -U postgres --dbname=yuzu < "yuzu-pg-YYYY-MM-DD.dump"

# 3. Pin the previous release
export YUZU_VERSION=0.9.0

# 4. Start the previous version
docker compose -f docker-compose.reference.yml up -d server
```

**Never** run `docker compose down -v` unless you intend to delete `server-data`, `postgres-data` (the PostgreSQL substrate — the server's primary data store), and every bit of server state. `down` alone is safe; the `-v` flag removes named volumes.

### Windows

```powershell
# 1. Stop the service (if running as service) or kill the process
Stop-Service yuzu-server  # or: taskkill /IM yuzu-server.exe /F

# 2. Back up data
Copy-Item C:\ProgramData\Yuzu\*.db C:\ProgramData\Yuzu\backup\
Copy-Item C:\ProgramData\Yuzu\*.cfg C:\ProgramData\Yuzu\backup\

# 3. Replace the binary
Copy-Item yuzu-server.exe "C:\Program Files\Yuzu\yuzu-server.exe"

# 4. Start
Start-Service yuzu-server  # or start manually
```

## Upgrading the Gateway

### Linux (systemd)

> **Breaking (#659):** the gateway refuses to start without a non-default Erlang
> distribution cookie. `.deb`/`.rpm` installs auto-generate `/etc/yuzu/gateway.env`;
> for tarball/manual installs create it once (see "Gateway distribution cookie now
> required" under *Upgrade notes by release* below) before the restart step.
>
> **Breaking (`#4555`):** the cookie must additionally be **32+ characters**
> (every documented generation path already clears this), and the gateway's
> Erlang node short name changed from `yuzu_gw1` to a shared `yuzu_gw` — update
> any external tooling hardcoding the old full node name. See "Gateway
> distribution-cookie length floor + shared node identity" below.

```bash
sudo systemctl stop yuzu-gateway
# Replace the release directory
sudo rm -rf /opt/yuzu_gw
sudo tar xzf yuzu-gateway-linux-x64.tar.gz -C /opt/
sudo systemctl start yuzu-gateway
```

### Docker

```bash
docker pull ghcr.io/<owner>/yuzu-gateway:v0.1.1
docker compose up -d yuzu-gateway
```

## Upgrading Agents

### OTA (Recommended)

If the server has OTA updates enabled (`--update-dir`):

1. Place the new agent binary in the server's update directory
2. Agents will check for updates on their configured interval (default: 6 hours)
3. Monitor the fleet dashboard for version rollout progress

### Manual

Follow the same stop/replace/start pattern as the server, per platform.

### Batch Rollout

For large fleets, upgrade in stages:
1. Upgrade a pilot group (5-10 agents) first
2. Monitor for 24 hours
3. Roll out to remaining agents in batches of 10-20%

## Plugin Code Signing (vNEXT, #80)

A new operator-managed plugin trust bundle ships in this release. **Default behaviour is unchanged**: agents that don't pass `--plugin-trust-bundle` and operators that don't upload a bundle through Settings → Plugin Code Signing see identical behaviour to prior releases.

If you turn the feature on, three things change:

1. **New on-disk artifact at `<cert-dir>/plugin-trust-bundle.pem`.** Linux/macOS: `/etc/yuzu/certs/plugin-trust-bundle.pem`; Windows: `C:\ProgramData\Yuzu\certs\plugin-trust-bundle.pem`. **Add this path to your backup procedure** alongside the SQLite databases. A backup that captures the DBs but not the cert dir restores `plugin_signing_required=true` (in `runtime_config`) without the bundle, and require-mode agents reject every plugin until the bundle is restored. The Docker reference `docker-compose.reference.yml` mounts only `server-data`; if your cert dir is outside that volume you must add a separate bind-mount or named volume and include it in the backup script.

2. **Cert-dir filename collision check.** The server now treats `plugin-trust-bundle.pem` in the cert dir as authoritative. The filename was unused in prior releases, but if any deployment placed an unrelated PEM at that exact path for another purpose, it will be interpreted as the plugin trust bundle on first read after upgrade. Run `ls <cert-dir>/plugin-trust-bundle.pem` on every server host before upgrading and rename any pre-existing file.

3. **DO NOT enable "Require signed plugins" yet.** The Yuzu release pipeline does not currently sign the 44 in-tree plugins under `agents/plugins/`. Enabling Require with an operator-only trust bundle will reject every Yuzu-shipped plugin on next agent restart — fleet-wide outage. Use the transitional mode (bundle uploaded, Require off) until you have signed every plugin your fleet uses, including the in-tree ones. The Settings card displays this warning inline.

The new audit actions (`plugin_signing.bundle.uploaded` / `.cleared` / `.require.changed`) and metric labels on `yuzu_agent_plugin_rejected_total` (`signature_missing` / `signature_invalid` / `signature_untrusted_chain`) are documented in `audit-log.md` and `metrics.md` respectively. SIEM and alert rules already filtering on the existing `success`/`failure`/`denied` audit vocabulary pick these up unchanged — no new vocabulary tokens were introduced.

## Schema Migrations

Starting with **v0.10.0**, every server-side SQLite store is wired through a single `MigrationRunner` that tracks schema version per store and applies pending migrations in a transaction. Prior releases relied on `CREATE TABLE IF NOT EXISTS` plus silent `ALTER TABLE ADD COLUMN` statements, which made rollbacks opaque and left no audit trail of what had been applied.

How it works:

- Each store declares an ordered `std::vector<Migration>` where each entry is `{version, sql}`.
- On startup, the runner creates the `schema_meta` table if missing, reads the current version for the store, and runs any migration with a higher version number inside a `BEGIN IMMEDIATE` / `COMMIT` transaction.
- If a migration SQL statement fails, the transaction rolls back and the store stays at its previous version — the server logs `MigrationRunner: migration v<N> failed for <store>: <sqlite error>` and the corresponding store constructor logs `<Store>: schema migration failed`.
- Already-applied migrations are skipped; running the same server binary twice against the same database is a no-op.
- Multiple stores share one database connection but keep independent version counters.

**Indexes are normally migration entries. `audit_store`'s retention index is a
deliberate, single exception** (`idx_audit_ttl_id`, #2360) - every other index in
the server is created inside `MigrationRunner`, and new code should follow that
rule, not this one. Two conditions justify the exception here and both must hold
before it is copied: (a) a failed migration closes the store, and for
`audit_store` that means every audit write then fails, taking the SOC 2 trail
offline; and (b) the build is `O(N log N)` over an existing multi-million-row
table, unlike the v1 indexes which are created on an empty one. A best-effort
object may silently not exist, so nothing with a CORRECTNESS dependency may use
this path - the retention guard is correct without its index, only slower.

Cost on a large existing `audit_events`: a one-time build at first boot after
upgrade, measured at ~81 MB and ~1.8-3.3 s at 5M rows on NVMe. At 50M rows the
build reads a ~16 GB table - tens of seconds on local NVMe, and potentially
minutes on container overlayfs or network storage.

**This runs synchronously, before the server binds its listeners**, so nothing
answers `/livez` or `/readyz` until it finishes. If your orchestrator's
kill-before-ready budget is shorter than the build you get a CRASH LOOP rather
than a slow boot: `CREATE INDEX` is one atomic statement, so every killed attempt
rolls back and the next boot re-pays it in full, indefinitely. Budget at least
**5 minutes** before the first liveness kill for an `audit_events` above ~20M
rows on non-NVMe storage. The shipped
`deploy/docker/docker-compose.reference.yml` sets `start_period: 30s`, which is
fine for a fresh install and NOT enough for a large first post-upgrade boot -
raise it before upgrading such a deployment. The
elapsed time is logged when it exceeds a second, and subsequent boots are a
no-op. If the build fails, retention still runs, but each pass then scans the
table AND sorts the whole expired backlog for its `ORDER BY ... LIMIT` (measured
2.0 s versus ~285-315 ms for the same capped pass WITH the index; the range
reflects different benchmark runs, not two different operations) - still far better than the unguarded code it
replaced, but the failure is logged as an error.

**Upgrading from v0.9.x or earlier** is data-preserving: the first 0.10.x startup stamps every database at schema v1. A small set of stores (`api_token_store`, `instruction_store`, `patch_manager`, `policy_store`, `product_pack_store`, `response_store`) also runs a one-time legacy compatibility shim that re-applies the historical `ALTER TABLE` statements before stamping, so databases from very old releases that never received those columns still converge to the latest schema. These shims are kept in code for one release cycle and can be removed after v0.11.

**No manual migration steps are required.** Just replace the binary (or pull the new image and `up -d`) and start the server. Migration progress is logged at `info` level as:

```
[info] MigrationRunner: rbac_store migrated to v1
[info] MigrationRunner: response_store migrated to v1
...
```

**Expect a log burst on first startup after upgrade.** 30+ `MigrationRunner: <store> migrated to v1` info lines appear on the first run against a pre-v0.10 database — one per store. On every subsequent restart the runner is silent at info level. If your log-shipping pipeline has per-second rate limits, widen them for the upgrade window or filter this single line pattern.

**Verifying migration state after startup**, query the per-store audit trail directly:

```bash
docker exec -i yuzu-server sqlite3 /var/lib/yuzu/rbac.db \
  "SELECT store, version, datetime(upgraded_at, 'unixepoch') FROM schema_meta ORDER BY upgraded_at;"
```

Every store that has ever run through the migration runner has a row here with its current version and the wall-clock timestamp of the last stamp. This is the operator-side audit trail for schema evolution.

**The Postgres-backed stores are not in that file.** Stores migrated onto the PostgreSQL
substrate — `audit_store` among them (ADR-0040) — run through `PgMigrationRunner`, log
`PgMigrationRunner: <store> migrated to v<N>`, and stamp `public.schema_meta` **in
PostgreSQL**. Query those there instead:

```bash
psql "$YUZU_POSTGRES_DSN" -c \
  "SELECT store, version, to_timestamp(upgraded_at) FROM public.schema_meta ORDER BY upgraded_at;"
```

For `audit_store` specifically, a legacy `audit.db` — if one still exists — is never renamed,
moved, or modified: Yuzu only opens it read-only, at boot, to warn if it holds rows (see the
Audit trail section above). `sqlite3 /var/lib/yuzu/audit.db` still opens it normally on a
migrated server; there is nothing to restore or account for here.

If a migration fails:

1. Check the log for `MigrationRunner: migration v<N> failed for <store>: <sqlite error>` and note both the store name and the SQLite error.
2. The server will have **closed the failing store's database handle**, so `/readyz` returns 503 with the failed store name in the `failed_stores` body field — the probe accurately reflects degraded state. Don't rely on `/livez` for readiness; it only checks process liveness, not schema integrity.
3. Stop the server and restore the **affected** database file from backup — not the whole data directory. Restoring all databases to fix one broken store wipes in-flight approvals, pending agents, and enrollment tokens. **This step does not apply to a Postgres-backed store** such as `audit_store`: there is no per-store file to restore, so use the Postgres dump procedure under "Rollback if a migration fails" above.
4. Start the previous server version against the restored data.
5. Open an issue with the full error line, the source/target version numbers, and the output of the `schema_meta` query above.

## Upgrade notes by release

### vNEXT — Decommission securable replaces the SLE/Inventory/GuaranteedState conjunction (breaking for custom roles)

`DELETE /api/v1/sle/agents/{id}` (the whole-device erasure cascade — see
[REST API § Software Licensing (SLE)](rest-api.md#software-licensing-sle)) used to gate on a
**three-securable conjunction**: `SoftwareLicensing:Delete` **and** `Inventory:Delete` **and**
`GuaranteedState:Delete`, all required together. A companion Wave 7 PR7.2 package adds a sixth
per-agent store (`app_usage`) to the cascade, and rather than grow the conjunction to a fourth
securable, ADR-0024 Decision 9 was amended ahead of that landing to promote a single dedicated
**`Decommission`** securable — the route now
gates on **`Decommission:Delete` alone**, replacing the old conjunction outright (not adding to it).

**Seeded roles are auto-preserved** — the same `INSERT OR IGNORE` role-default seeding as the SLE
securable above runs on every boot, so `Administrator` (full CRUD via the generic per-securable
loop) and `ITServiceOwner` (a targeted `Decommission:Delete` grant) pick up the new securable
automatically on upgrade, with no operator action required.

**A previously revoked decommission ability is NOT silently regained.** If you had used
`remove_permission()` to revoke `ITServiceOwner`'s `SoftwareLicensing:Delete`,
`Inventory:Delete`, or `GuaranteedState:Delete` specifically to strip its decommission ability
under the old conjunction, the upgrade detects that revocation and carries it forward onto the new
`Decommission:Delete` grant automatically — `ITServiceOwner` stays unable to decommission a device
after upgrading, exactly as before. No operator action is needed for this case; it is the inverse
of the custom-role gap above (a seeded role *losing* access it deliberately had revoked is checked
for, not just a custom role *gaining* an unrelated 403).

**This is breaking only for a custom role.** Any custom role an operator built by hand-assembling
the old three-securable conjunction (`SoftwareLicensing:Delete` + `Inventory:Delete` +
`GuaranteedState:Delete`) specifically to reach this endpoint will start getting `403 Decommission:Delete`
on its next call — **the three old grants no longer suffice**, because the route no longer checks
them at all. Audit your custom roles before upgrading:

```sql
SELECT pr.principal_type, pr.principal_id, pr.role_name
  FROM rbac_store.principal_roles pr
  JOIN rbac_store.role_permissions rp ON rp.role_name = pr.role_name
  WHERE rp.securable_type IN ('SoftwareLicensing', 'Inventory', 'GuaranteedState')
    AND rp.operation = 'Delete'
    AND rp.effect = 'allow'
  GROUP BY pr.principal_type, pr.principal_id, pr.role_name
  HAVING COUNT(DISTINCT rp.securable_type) = 3;
```

The old gate was a strict three-way AND — all three grants required together, `effect = 'allow'`
on each. Matching on any ONE of the three (or including an explicit `effect = 'deny'` row, a legal
`role_permissions` state) over-reports: a role holding, say, only `Inventory:Delete` for an
unrelated purpose never had decommission ability under the old conjunction, and granting it
`Decommission:Delete` now would be a NEW grant, not a preserved one.

Grant `Decommission:Delete` to any custom role in that list that must retain the ability to erase a
decommissioned device's data. `SoftwareLicensing:Delete`, `Inventory:Delete`, and
`GuaranteedState:Delete` continue to gate their own unrelated surfaces exactly as before — only the
erasure cascade's gate moved.

### vNEXT — Hardware CI list requires `Inventory:Read`, not the old Devices page's `Infrastructure:Read` (breaking for custom roles)

`/devices` now 302-redirects to `/hardware` (the Hardware CI list) and `/device?id=` redirects to
`/hardware/ci?id=` — bookmarked links and existing browser navigation keep working transparently,
since browsers follow redirects. The **permission the list itself checks** changed, though: the old
Devices page gated on `Infrastructure:Read`; the Hardware CI list gates on `Inventory:Read` (the
same securable the rest of the Inventory/Software surface already uses).

**Seeded roles are unaffected.** Every built-in role that held `Infrastructure:Read` (Administrator,
ITServiceOwner) also holds `Inventory:Read`, so no default-role regression on upgrade.

**This is breaking only for a custom role granted `Infrastructure:Read` without `Inventory:Read`.**
Such a role could see the device list via the old `/devices` page pre-upgrade and will get a `403`
reaching the redirected `/hardware` page post-upgrade. Audit custom roles before upgrading:

```sql
SELECT pr.principal_type, pr.principal_id, pr.role_name
  FROM rbac_store.principal_roles pr
  JOIN rbac_store.role_permissions rp ON rp.role_name = pr.role_name
  WHERE rp.securable_type = 'Infrastructure' AND rp.operation = 'Read' AND rp.effect = 'allow'
    AND NOT EXISTS (
      SELECT 1 FROM rbac_store.role_permissions rp2
      WHERE rp2.role_name = pr.role_name
        AND rp2.securable_type = 'Inventory' AND rp2.operation = 'Read' AND rp2.effect = 'allow'
    );
```

Grant `Inventory:Read` to any custom role in that list that must retain device-list visibility.
`Infrastructure:Read` continues to gate the fleet-wide agent list (`/api/agents`) and other
infrastructure-tier reads exactly as before — only the Hardware CI list's own gate moved.

### Retention clock guards (#2360 server audit store, #2361 TAR agent warehouse, #2964 rotation sweep)

Both retention paths used to issue an unbounded `DELETE` driven by the local wall
clock, so one forward clock step could wipe a store in a single statement. They
are now guarded and capped. Two operator-visible consequences on upgrade:

- **Audit retention is now a floor, not a ceiling.** A pass that would expire
  every datable row declines once, and every accepted pass is capped at 25,000
  rows, so a large backlog ages out over hours rather than in one statement.
  Watch `yuzu_server_audit_retention_cap_reached_total` alongside
  `yuzu_server_audit_rows_deleted_total` to see whether a backlog is draining.
  The cap paces at two different cadences depending on whether a backlog is
  forming — see [Audit Log § Capacity](audit-log.md#capacity) for both
  figures; comparing your event rate against only the quiet-operation one is
  overly conservative by roughly three orders of magnitude. Note that
  changing `--audit-retention-days` never re-dates
  existing rows (`ttl_expires_at` is stamped at INSERT), so a reduction does not
  reclaim disk retroactively. Operator triage when the guard declines a pass:
  [audit-log.md § The retention clock guard](audit-log.md#the-retention-clock-guard).
- **`audit_store` gains schema v3** (a small `audit_retention_meta` key/value
  table holding the durable clock reading - one row, instant) plus the
  best-effort index build described under Schema Migrations above.
- **`YuzuAuditRetentionNotRunning` now fires for a crash-looping server
  (#2553, redesigned by #2854 rung D), and there is a new
  `YuzuAuditRetentionNeverRan` alert to route.** The old rule's young-server
  grace keyed on uptime, so a process restarting more often than the 3-hour
  alert window never accumulated enough uptime to leave the grace and was
  excused on every evaluation - silently, and for one of the leading causes of
  the exact condition the rule detects. The grace is now the restart-surviving
  last-pass stamp (`yuzu_server_audit_retention_last_pass_unixtime`, seeded
  from the durable anchor at startup): the rule excuses only a database no
  retention pass has EVER run against, fires at every restart cadence on an
  anchored one, and stays firing while the reaper stays dead. The excused
  never-ran state gets its own alert, `YuzuAuditRetentionNeverRan` (stamp
  still `0` after 3 hours) - **a new alertname: give it an Alertmanager route**.
  **If you re-apply this rules file and have a crash-looping server, expect a
  new-to-you firing** that reflects a pre-existing condition rather than a new
  fault - including on crash loops faster than the 60-minute first-pass sleep,
  a true positive the old grace hid. The rules file is a copy you apply
  yourself; the server does not upgrade it for you, and a stack that does not
  re-apply it keeps the old blind rule and never gains the new alert. In a
  staged rollout apply SERVERS first, rules second: an old, not-yet-upgraded
  server restarting under the new rules reads a `0` stamp even on an anchored
  database and pages `YuzuAuditRetentionNeverRan` with a fresh-install story
  that is false for it (see the runbook's rollout note). The same
  re-apply also removes an `on(instance)` join from the liveness rule, so a
  server that was being silenced by an unrelated series sharing its `instance`
  value (a canary, an HA pair, a federated series) can now correctly fire too -
  the same new-to-you-firing shape as the crash-loop fix, for the same reason.
- **You must ADD a new rule by hand: `YuzuAuditRetentionMetricMissing` (#2553).**
  `YuzuAuditRetentionNotRunning` cannot detect its own input going missing -
  `increase()` over a metric with no series is an empty vector, so the rule selects
  nothing and never fires. A Prometheus holding these rules against a server that
  does not export `yuzu_server_audit_retention_passes_total` therefore reports
  healthy forever while the audit reaper is entirely unmonitored, which is exactly
  the state you are in if you apply this rules file ahead of upgrading your
  servers. The new rule keys on `absent(...)` and fires after 15m. It is
  **fleet-wide by construction**: it cannot see one server among many going quiet.
  **A `up`-based target-down alert does NOT close that gap** — a server that is
  running an older build is alive and scraped, so its `up` is 1; it simply does
  not export this counter. Measured (#2553): in a fleet where one server exports
  the counter and another does not, *neither* retention rule fires, for either
  server, indefinitely. During a staged upgrade the practical mitigation is to
  confirm coverage directly rather than to rely on an alert —
  `count(yuzu_server_audit_retention_passes_total)` against your expected server
  count — until every server is upgraded. A per-target rule for this is tracked
  separately.
- **The first guarded pass now declines when it has no stored reading and rows
  are already expired (#2579).** The stored clock reading (the anchor) is new in
  schema v3, so every database starts its first guarded pass without one. An
  ABSENT reading is not a statement about the clock - it is the ordinary
  fresh-install case - which previously left one shape unguarded: a host already
  skewed FORWARD, where rows written after the skew were still inside the window,
  so the would-expire-everything test did not fire either, and the pass deleted up
  to the 25,000-row cap unremarked. Such a pass now declines ONCE, warns, and
  anchors the reading; the next pass proceeds normally, paced by the cap. A fresh
  install with nothing expired does not decline at all. **Expect at most one such
  decline per server on this upgrade**, counted by the new
  `yuzu_server_audit_retention_bootstrap_declines_total` and NOT by
  `yuzu_server_audit_clock_anomaly_skips_total` - so it does not fire
  `YuzuAuditRetentionClockAnomaly`, and you should not stand that alert down for
  it. Servers upgrading FROM an affected version with a wrong clock may already
  have lost rows; there is no reliable retrospective test, and the loss is not
  recoverable without a backup predating it. Detail:
  [audit-log.md § The retention clock
  guard](audit-log.md#the-retention-clock-guard).
- **Expect a first-pass retention decline on the AGENT, and only conditionally on
  the server.** The two guards differ here and the difference matters:
  - **TAR declines on a missing anchor, by design.** It checks per warehouse
    table, so on an agent upgrade every enabled time-based table declines in that
    same pass and `retention_guard_declines_total` rises by the number of those
    tables (5-10 on a default agent), not by 1. That is the benign bootstrap
    case, not a fleet of separate anomalies, and it needs no action.
  - **The audit store's triggers are NOT the same**, so do not carry the agent's
    expectation across to it and do not pre-emptively stand down
    `YuzuAuditRetentionClockAnomaly` on a fleet upgrade. If one fires, work it as
    an alert rather than assuming a benign bootstrap:
    [audit-log.md § The retention clock guard](audit-log.md#the-retention-clock-guard)
    states when the server's guard declines, and
    [the ops runbook](../ops-runbooks/audit-store-clock-guard.md) is the response
    path.
- **Agents surface new `tar status` lines**: `storage_state`,
  `retention_guard_declines_total`, `retention_guard_failures_total`, and
  per-table detail. On the healthy path `storage_state|ok` is the first line,
  and existing consumers filter on the `config|` prefix and ignore unknown
  lines, so nothing breaks. **On the offline path they do break**: when the TAR
  database has been closed after a wedged rollback, `tar status` returns
  non-zero and emits only an `error|` line followed by `storage_state|offline` -
  no `record_count`, no `config|` lines at all. Note the order is REVERSED
  there: `error|` comes first, because server and dashboard consumers key off
  the output starting with `error|`. A consumer keyed on the presence of
  `record_count` must handle that. See
  [tar.md](tar.md#the-retention-clock-guard). TAR persists its own clock reading
  in `tar_config` (`retention_guard_last_pass`) - no schema change.
- **TAR row-count retention is now paced.** Its ceiling semantics are unchanged,
  but a large excess (after a long disable, or an upgrade backlog) drains over
  several 900 s rollup ticks rather than in one statement.
- **`ApiTokenStore` gains a THIRD, independent clock guard (#2964) — the
  rotation sweep that auto-revokes rotation predecessors.** Same shape as the
  audit store's, same schema-migration pattern (a new `rotation_retention_meta`
  key/value table holding the durable anchor), same bootstrap-decline
  consequence, but a much shorter cadence: this sweep ticks every 60 seconds,
  not hourly. **If you are upgrading a populated store that already has
  elapsed, not-yet-swept rotation pairs** — a predecessor whose overlap
  window has already ended, sitting there because nothing has run the guard
  against it before — **expect the sweep's first tick after the migration to
  decline once**, the same "no durable anchor yet, and there is already
  something eligible" bootstrap case #2579 describes for the audit store.
  Both credentials in every affected pair simply stay active for that one
  tick; the very next tick has an anchor and proceeds normally, so at a
  60-second cadence this resolves in roughly two minutes, not the audit
  store's next-hourly-pass timescale. Nothing is lost or at risk here (an
  auto-revoke deferred by one tick is the intended failure mode, not the
  audit store's deletion-risk case) — this is a heads-up so the log line and
  the one-off decline are not mistaken for something wrong with the upgrade.
  See `docs/user-manual/metrics.md` "Rotation-sweep clock guard metrics" and
  `docs/ops-runbooks/rotation-sweep-clock-guard.md`.

New Prometheus alert rules ship in `docs/prometheus/yuzu-alerts.yml`, which is the
current set. The declined-pass and failed-pass
counters must be alerted on separately: both leave rows undeleted, so an audit
table that never shrinks looks identical either way. One rule,
`YuzuAuditRetentionNotRunning`, fires on the reaper NOT running - the state in
which none of the other counter-driven rules can fire, because they all key on a
counter rising.

### SLE — the `SoftwareLicensing` securable auto-grants on upgrade (ADR-0024)

This release adds the **SLE** (Software Licensing & Entitlements) **discovery** surface,
gated on a new **`SoftwareLicensing`** RBAC securable. Per **ADR-1005** the server ships
the discovery mechanism only: the per-device **`GET /api/v1/sle/agents/{id}`** drill, its
machine-scope MCP twin `query_software_licenses`, and the audited erasure
**`DELETE /api/v1/sle/agents/{id}`**. The licence **compliance / entitlement / reclamation**
views and the fleet **posture** reads (a `/sle` page and `/api/v1/sle/summary` ·
`/licenses` · the per-product device fan-out) **interpret** discovered facts and ship with
the future **SAM use-case-engine module** — they are *not* in this release, so a reader
who saw the earlier ADR expecting an in-server compliance page should not look for one yet.
Because RBAC role defaults are seeded with `INSERT OR IGNORE` on **every** boot, an
upgrading deployment **silently auto-grants** the new securable to the built-in roles the
first time it starts the new build:

| Role | Grant |
|---|---|
| Viewer, PlatformEngineer | Read |
| Operator | Read + Write |
| ITServiceOwner, Administrator | full CRUD |
| ApiTokenManager | none |

**No action is required** if that matches your intent — the securable gates the SLE
discovery reads/erasure (`GET`/`DELETE /api/v1/sle/agents/{id}` and the MCP twin); the
`/inventory` software catalog is unchanged and remains under `Inventory:Read`.

**But** the per-device drill exposes each endpoint's **detected-licence facts** —
product, vendor, channel, status, expiry, and, on per-user surfaces, the per-user
**`user_ref`** identifier — **to every Read holder, including `Viewer`**. **A deployment
that must restrict this visibility should deny or remove the `SoftwareLicensing` Read
grant from `Viewer` (and any other broad role) BEFORE enabling the SLE sources.** A
**deny rule wins** over the seeded allow (deny-override), so an explicit deny is the
durable control — re-seeding on the next boot cannot re-open it. (Entitlement/purchase
**cost** metadata is *not* served in-server this release — it is the SAM UCE module's,
governed by that module's own RBAC when it ships.)

The SLE detection source also collects a new, suppressible **per-user identifier**
(`user_ref`) on per-user licence surfaces. It defaults to a per-device keyed-HMAC
pseudonym; see [Software licence detection](software-licensing.md) for the
`--license-scan-user-ref` flag, the honest limits of that default, and the
`--inventory-disable` source-level opt-out.

### Gateway distribution cookie now required (#659) — **BREAKING**

The Erlang gateway shipped a hardcoded default distribution cookie
(`yuzu_gw_secret_change_me`). The cookie is the sole authentication for
inter-node RPC, so a publicly-known value is unauthenticated remote code
execution for anyone who can reach EPMD (TCP 4369). The gateway now **refuses to
boot** with the default (or an empty/unsubstituted) cookie unless explicitly
overridden.

**Before upgrading:**

- **`.deb` / `.rpm` installs** auto-generate a unique cookie into
  `/etc/yuzu/gateway.env` (mode `0640`, `root:yuzu-gw`) on first install and
  never clobber it on upgrade — no action needed for a single node.
- **Tarball / manual systemd installs** must create the env file once:
  ```bash
  sudo install -d -m 0755 /etc/yuzu
  printf 'YUZU_GW_COOKIE=%s\n' "$(openssl rand -hex 32)" | sudo tee /etc/yuzu/gateway.env >/dev/null
  sudo chown root:yuzu-gw /etc/yuzu/gateway.env && sudo chmod 0640 /etc/yuzu/gateway.env
  ```
  The systemd unit loads it via `EnvironmentFile=-/etc/yuzu/gateway.env`.
- **Docker / Compose** deployments must set `YUZU_GW_COOKIE` in the gateway
  service environment (e.g. `export YUZU_GW_COOKIE=$(openssl rand -hex 32)` then
  reference it). Dev/CI may instead set `YUZU_GW_ALLOW_DEFAULT_COOKIE=1`.
- **Multi-node clusters:** every node must share the **same** cookie — set an
  identical `YUZU_GW_COOKIE` (or write the same `/etc/yuzu/gateway.env`) on all
  nodes; the per-host auto-generated value will NOT match across hosts.

**Recovery — gateway won't start after upgrade:**

| Symptom | Diagnose | Fix |
|---|---|---|
| `systemctl status yuzu-gateway` shows `start-limit-hit` / `failed` | `journalctl -t yuzu-gateway \| grep -i cookie` shows "insecure distribution cookie" (for manual/`foreground` or container runs, check stdout / `gateway.log` instead) | Create `/etc/yuzu/gateway.env` with `YUZU_GW_COOKIE=$(openssl rand -hex 32)` (see above), then `systemctl reset-failed yuzu-gateway && systemctl start yuzu-gateway`. **Do not** use `YUZU_GW_ALLOW_DEFAULT_COOKIE=1` in production. |

> The generated `/etc/yuzu/gateway.env` is intentionally **preserved across
> `apt purge` / `rpm -e`** (the `/etc/yuzu` directory may be shared with other
> Yuzu packages). To remove the cookie after uninstall: `sudo shred -u /etc/yuzu/gateway.env`.

> **Never set `YUZU_GW_ALLOW_DEFAULT_COOKIE=1` in production** — it disables the
> guard and restores the unauthenticated-RPC surface. It exists only for
> ephemeral dev/CI stacks.

### Gateway distribution-cookie length floor + shared node identity (HA WS-4 `#4555`) — **BREAKING**

Extends the `#659` cookie requirement above with two further changes, both
shipped together as part of gateway multi-node cluster formation:

- **Cookie length floor.** The gateway now additionally refuses to boot with
  a distribution cookie **shorter than 32 characters**, even a genuinely
  custom (non-default) one. DNS-based cluster discovery means a node now
  dials addresses it did not choose by hand, and the distribution
  handshake's INITIATOR sends the cookie hash first — a short cookie is
  brute-forceable offline from a legitimately-dialing node. **Every
  documented cookie-generation path already clears this floor with room to
  spare** (`openssl rand -hex 32` produces 64 characters) — no action
  needed if you followed the `#659` guidance above verbatim. Only an
  operator who hand-picked a short custom cookie is affected; the same
  `YUZU_GW_ALLOW_DEFAULT_COOKIE=1` override (dev/CI only, never production)
  bypasses this check too.
- **Node identity change.** The Erlang node short name changed from a
  hardcoded `yuzu_gw1` to a shared `yuzu_gw` — every gateway replica in a
  cluster now advertises the SAME short name, distinguished only by an
  address resolved at boot (`YUZU_GW_ADVERTISE_ADDR`, auto-detected by
  default), so that identical replicas can boot from one image/env (a
  prerequisite for `docker compose up --scale gateway=N`). A single-node
  deployment boots identically otherwise (the address defaults to
  `127.0.0.1`, matching the old hardcoded value) — but any external
  tooling that hardcodes the OLD full node name (`yuzu_gw1@127.0.0.1`) in a
  `erl -remsh`/`recon` script, a health check, or a monitoring probe will
  silently stop matching after upgrade. Update any such tooling to match
  `yuzu_gw@` (a prefix, since the address suffix may vary).

**Recovery** for the cookie-length case uses the same diagnostic path as
`#659` above (`journalctl -t yuzu-gateway | grep -i cookie` / stdout /
`gateway.log`) — the log line names the specific failure (`shorter than 32
characters`) separately from the known-default rejection.

### InstructionDefinition import signature enforcement now on-by-default (#1073 / W7.4 sibling-gap) — **BREAKING**

`InstructionStore::import_definition_json` (the storage path behind
`POST /api/instructions/import`) previously accepted unsigned JSON
envelopes without verification. After upgrade, unsigned imports are
rejected with:

```
instruction-import is unsigned and signature enforcement is enabled (set --allow-unsigned-definitions / YUZU_ALLOW_UNSIGNED_DEFINITIONS=1 to bypass)
```

This is intentional and closes the sibling-gap to #802. Without the
gate, any operator with `InstructionDefinition:Write` permission can
import a definition that dispatches an arbitrary plugin invocation on
every targeted agent — same fleet-RCE blast radius the pack-signing
default closed.

**Two migration paths, in order of preference:**

1. **Sign your imports.** Generate an Ed25519 keypair, sign the
   `yaml_source` field's bytes with the private key, and wrap the
   envelope with `signature: <hex>` + `publicKey: <hex>` top-level
   fields. The wire format mirrors ProductPack: signature is hex-
   encoded over the verbatim `yaml_source` bytes; `publicKey` is the
   hex-encoded raw Ed25519 public key (32 bytes / 64 hex chars).
   Until the dedicated helper script lands (tracked as a follow-up
   issue covering both pack-signing and definition-signing tooling),
   use the raw `openssl` recipe directly:

   ```bash
   # One-time: generate a keypair (rotate periodically per your policy).
   openssl genpkey -algorithm Ed25519 -out yuzu-signing.pem
   openssl pkey -in yuzu-signing.pem -pubout -outform DER \
       | tail -c 32 | xxd -p -c 64    # → 64-hex publicKey

   # Per definition: sign yaml_source bytes, hex-encode the output.
   echo -n "$YAML_SOURCE" \
       | openssl pkeyutl -sign -inkey yuzu-signing.pem -rawin \
       | xxd -p -c 128                # → 128-hex signature
   ```

   Inject `signature` and `publicKey` as top-level string fields in
   the JSON envelope POSTed to `/api/instructions/import`. See the
   REST API reference (`docs/user-manual/rest-api.md` →
   `POST /api/instructions/import`) for the full signing-rules table
   and per-rejection error strings.

2. **Opt out temporarily** (legacy environments only). Pass
   `--allow-unsigned-definitions` to `yuzu-server` or set
   `YUZU_ALLOW_UNSIGNED_DEFINITIONS=1` in the service environment. The
   server emits an `InstructionStore: signature enforcement DISABLED
   by configuration` warning on every start AND a
   `server.unsigned_definitions_allowed` audit row at boot, so the
   relaxed posture is recoverable from both operator logs and the
   audit store. **Remove the flag** as soon as the signing migration
   completes.

**Pre-existing imported definitions are unaffected.** The gate fires
only on the public import path. The bundled-content boot seed (the
`kBundledDefinitions` baked into `yuzu-server` at build time) routes
through an internal `import_definition_json_trusted` variant that
bypasses the gate; its authenticity comes from binary linkage, not
runtime signature.

**Authoring surfaces are NOT gated.** `POST /api/instructions`,
`POST /api/instructions/yaml`, and `PUT /api/instructions/{id}` — the
dashboard and CLI surfaces where operators author definitions in-
session — continue to trust `InstructionDefinition:Write` as the
author trust boundary (the operator IS the source; there is no
supply chain to authenticate). The `--allow-unsigned-definitions`
flag does NOT affect those surfaces; they have always accepted
unsigned author-time input and continue to. The architectural
question of whether authoring surfaces should ALSO require signed
envelopes is tracked as a follow-up issue with operator-decision-
required framing (UX trade-off: gating authoring would break in-
browser definition authoring).

**Audit-trail evidence chain.** Every rejection emits an
`instruction.import / denied` audit row with the store error string
in `detail` (stable SIEM-keyable tokens listed in the
`audit-log.md` reference). If the audit-store write itself fails
(locked DB, disk full), the response carries `Sec-Audit-Failed: true`
header AND `audit_emitted: false` in the JSON body, surfacing the
SOC 2 CC7.2 evidence gap to the operator immediately rather than
silently dropping the event.

### Product pack signature enforcement now on-by-default (#802 / W7.4) — **BREAKING**

The `ProductPackStore` previously shipped with signature enforcement
**disabled** by default and the setter to enable it was never wired to
any operator-facing flag — the protection was effectively unreachable.
After upgrade, calls to install a `ProductPack` without a `signature:`
field are rejected with:

```
pack '<name>' is unsigned and signature enforcement is enabled (set --allow-unsigned-packs / YUZU_ALLOW_UNSIGNED_PACKS=1 to bypass)
```

This is intentional. Unsigned packs are a fleet-wide arbitrary-code-
execution surface: any operator with `Pack:Install` permission, or a
MITM on pack delivery, could install a pack containing
`InstructionDefinition` or plugin payloads that would then execute on
every enrolled agent.

**Two migration paths, in order of preference:**

1. **Sign your packs.** Generate an Ed25519 keypair, sign each pack's
   non-metadata YAML content with the private key, and add
   `signature: <hex>` + `publicKey: <hex>` fields to each pack's
   `ProductPack` metadata document. The existing verify path
   (`ProductPackStore::verify_signature`) accepts the result. Pack
   install then succeeds and the `verified` column in the store is set
   to true so a future "show only verified packs" query has the data
   it needs.

2. **Opt out temporarily** (legacy environments only). Pass
   `--allow-unsigned-packs` to `yuzu-server` or set
   `YUZU_ALLOW_UNSIGNED_PACKS=1` in the service environment. The
   server emits a `[SECURITY] product pack signature enforcement
   DISABLED by configuration` warning on every start and writes a
   `server.unsigned_packs_allowed` audit row, so the relaxed posture
   is recoverable from both operator logs and the audit store.
   **Remove the flag** as soon as the pack-signing migration completes;
   it is not intended as a permanent configuration.

**Pre-existing installed packs are unaffected.** The check fires only
on the install path (`POST /api/product-packs`). List, get, and
uninstall paths do not re-verify, so already-installed unsigned packs
remain queryable and uninstallable after upgrade.

### Executions-history PR 2 — `responses.execution_id` exact correlation

PR 2 of the executions-history ladder closes a forensic-data correctness
gap (UP-8) where two concurrent executions of the same definition to
overlapping agent sets could show each other's responses in the
Instructions → Executions detail drawer. Operators upgrading to a
release that includes PR 2 should expect the following:

**Schema migration v2 on `response_store`.** The migration adds an
`execution_id TEXT NOT NULL DEFAULT ''` column to the `responses` table
plus a partial index `idx_resp_execution_ts ON responses(execution_id,
timestamp) WHERE execution_id != ''`. The migration is automatic and
data-preserving — `MigrationRunner::run` wraps the ALTER + CREATE INDEX
in a single transaction. Pre-upgrade rows are NOT deleted; they receive
the empty-string sentinel value `''`. The migration is idempotent: a
pre-stamp probe at startup detects an already-altered DB and skips the
duplicate ALTER (mirrors the precedent at `instruction_store.cpp` v2).

Observable after upgrade:

```sql
SELECT execution_id, COUNT(*) FROM responses GROUP BY execution_id;
```

will show ALL pre-upgrade rows under the empty string `''`. This is
expected — there's no way to retroactively attribute pre-upgrade
responses to executions because the dispatch path didn't record the
linkage. The Executions drawer detects empty-`execution_id` rows and
falls back to the legacy timestamp-window-plus-agent-set join so they
render correctly without operator action. **No operator action
required** for the migration itself.

**Dispatch-path coverage gap (PR 2.x follow-ups).** Only executions
dispatched via `POST /api/instructions/:id/execute` (the dashboard's
Execute Instruction form goes through this path) get exact correlation
in PR 2. Three dispatch surfaces continue to write rows with
`execution_id=''` until follow-up PRs close them:

- **MCP `execute_instruction`** — agent dispatches issued through the
  MCP protocol.
- **Workflow steps** (`POST /api/workflows/:id/execute` step dispatch
  via `cmd_dispatch` callback) — multi-step workflows.
- **Scheduled / approval-triggered dispatches** — the dispatch path
  inside `schedule_engine` / approval-fired execution.
- **Reruns** (`/api/executions/:id/rerun`) — `create_rerun` creates
  the execution row but does not dispatch; the operator-triggered
  follow-up dispatch will be wired in PR 2.x.

For runs from these surfaces, the drawer's responses section uses the
legacy timestamp-window join. Cross-execution contamination (UP-8) is
still possible if two such runs overlap on the same definition + agent
set. Track via the executions-history follow-up issues.

**Mixed-mode detail drawer behaviour.** During an upgrade transition
window (executions in flight at restart time, or in-progress executions
that started pre-upgrade and finished post-upgrade), some responses for
a single execution may carry `execution_id=''` while others are
correctly tagged. The drawer prefers exact-correlation rows when they
exist and only falls back to the legacy join when zero exact rows are
returned — this means **mixed-mode runs may show only the
post-upgrade subset of their responses** in the drawer. Pre-upgrade
responses for those runs remain in the database and are queryable via
SQL; the upcoming admin backfill CLI (PR 2.1) will stamp them with
their correct execution_id once it ships.

**Server restart caveat.** The dispatch-time `command_id → execution_id`
mapping is held in memory inside `AgentServiceImpl`. If the server is
restarted while a command is in flight, the mapping is lost and any
agent responses arriving post-restart will be tagged `execution_id=''`
and use the legacy fallback. Avoid restarting the server during active
executions where possible, or accept that the affected runs will use
legacy correlation.

**Admin backfill (planned in PR 2.1, not in this release).** A
`yuzu-server admin backfill-responses` CLI is filed as a follow-up. It
will walk the executions table cross-store and stamp pre-upgrade
responses with their best-effort execution_id (timestamp + agent set
heuristic). Until it ships, pre-upgrade rows remain queryable via the
legacy fallback in the drawer; no operator action is required.

**Verifying the migration.** After upgrade, the server log should
contain `MigrationRunner: response_store migrated to v2`. To verify the
column directly:

```bash
sqlite3 /var/lib/yuzu/responses.db ".schema responses"
# Expected: execution_id TEXT NOT NULL DEFAULT ''
sqlite3 /var/lib/yuzu/responses.db ".schema idx_resp_execution_ts"
# Expected: CREATE INDEX idx_resp_execution_ts ON responses(...) WHERE execution_id != ''
```

### v0.12.0 — AuthDB persistent authentication (#618)

v0.12.0 replaces the in-memory + on-config-flush authentication model
with a SQLite-backed `auth.db` that holds user accounts, sessions, and
enrollment tokens.

**First boot after upgrade:**

- The server probes `--data-dir` for `auth.db`. If absent, it creates
  the file with mode `0600` (Linux) or restricted ACL (Windows), runs
  the initial schema migration via `MigrationRunner`, then seeds users
  from `yuzu-server.cfg`. Subsequent boots read from `auth.db`
  directly; the config file is no longer the live source of truth.
- The seed is one-shot. Editing `yuzu-server.cfg` after first boot
  does NOT re-seed users into `auth.db` — use the dashboard or
  `POST /api/settings/users` instead.
- Existing in-flight sessions are NOT preserved across the upgrade
  (sessions live in memory before this release; `auth.db` starts fresh
  on first boot). Operators must log in again.

**`role` parameter ignored on `POST /api/settings/users`.** New users
are always created as `user` (security finding C1). To assign or
change a role, use the dedicated `POST
/api/settings/users/{username}/role` endpoint introduced in v0.12.0
(see [REST API → Settings → User Management](rest-api.md#settings--user-management)).
The dashboard exposes a **Change Role** button on each user row that
calls the new endpoint.

**Live drawer updates via SSE.** The Executions tab opens an
`EventSource` to `/sse/executions/{id}` for in-progress runs. Reverse
proxies in the request path must NOT buffer SSE — the server emits
`X-Accel-Buffering: no` and `Cache-Control: no-cache` but a poorly-
configured proxy can still chunk the stream. Verify with
`curl -N https://<server>/sse/executions/<id>` from inside your
network if the drawer freezes mid-execution.

**`LimitNOFILE=65536` on systemd units.** v0.12.0 raises the systemd
file-descriptor limit from the default 1024 to 65536. SSE
connections + agent gRPC streams + SQLite WAL handles can saturate
the default soft limit on busy fleets. The new value matches Docker
compose's `ulimits.nofile` so containerised and bare-metal deployments
behave identically.

**Restart-loop guard.** `StartLimitIntervalSec=60` +
`StartLimitBurst=3` in the systemd `[Unit]` section so a corrupt
`auth.db` failing the integrity check at startup puts the unit
cleanly into `failed` instead of spinning. Recovery procedure:
[`docs/ops-runbooks/auth-db-recovery.md`](../ops-runbooks/auth-db-recovery.md).

**Rollback to a pre-AuthDB release** (only if you have not yet
written user state via the new dashboard):

1. Stop the v0.12.0 server.
2. Move `auth.db` aside (`mv auth.db auth.db.v0.12.0`).
3. Restore `yuzu-server.cfg` from your pre-upgrade backup.
4. Reinstall the prior release binary.
5. Start the server. It reads `yuzu-server.cfg` as before.

If you HAVE written user state via v0.12.0's dashboard, that state
is in `auth.db` only — rolling back loses it. Export users via
`GET /api/v1/settings/users` first if rollback is required.

### v0.12.0 — Guardian PR 2

Guardian PR 2 ships the Guaranteed State control plane + agent skeleton. Two items require operator awareness on upgrade:

**Stale `*:Push` RBAC grants on deployments that ran pre-hardening Guardian PR 2 code.** Between commits `7c83911` and `1f39401`, the RBAC seed granted the `Push` operation to `Administrator` and `ITServiceOwner` on **every** securable type, not just `GuaranteedState`. The H-4 fix (commit `21c0ba4`, hardening round 2) restricted the seed to `GuaranteedState` only going forward — but because `seed_defaults()` uses `INSERT OR IGNORE`, the stale cross-type grants already written to `role_permissions` are not removed on upgrade. These grants are semantically inert today (only the Guardian REST handlers consult `Push`), but become a latent privilege for any future release that adds a non-Guardian handler checking `perm_fn(..., "Push")`.

Manual remediation until the auto-migration in issue #485 lands. **Run each step in order:**

1. **Back up the RBAC database first.** Destructive SQL with no rollback.

   ```bash
   docker exec yuzu-server cp /var/lib/yuzu/rbac.db /var/lib/yuzu/rbac.db.bak.$(date +%Y%m%d)
   # or for a systemd install:
   cp /var/lib/yuzu/rbac.db /var/lib/yuzu/rbac.db.bak.$(date +%Y%m%d)
   ```

2. **Preview the rows that will be deleted.** This should return only `Administrator` and `ITServiceOwner` rows on a fresh Guardian PR 2 upgrade. If it returns rows for any other principal_id, you have custom RBAC grants that the bulk `DELETE` below would silently wipe — in that case stop and prune by hand.

   ```bash
   docker exec -i yuzu-server sqlite3 /var/lib/yuzu/rbac.db \
     "SELECT principal_id, securable_type FROM role_permissions \
       WHERE operation = 'Push' AND securable_type != 'GuaranteedState' \
       ORDER BY principal_id, securable_type;"
   ```

3. **Delete the stale grants.** Scoped to the two seeded roles so custom grants are left alone:

   ```bash
   docker exec -i yuzu-server sqlite3 /var/lib/yuzu/rbac.db \
     "DELETE FROM role_permissions \
       WHERE operation = 'Push' \
         AND securable_type != 'GuaranteedState' \
         AND principal_id IN ('Administrator', 'ITServiceOwner');"
   ```

4. **Confirm cleanup:** re-run the preview query from step 2 — zero rows expected.

Safe on fresh installs (no matching rows). If you are upgrading **from** a v0.11.x release directly **to** v0.12.0 or later, skip this entire sub-section — your RBAC database never carried the stale grants.

**Retention changes take effect on restart, not on runtime PUT.** BL-2 wired `--guardian-event-retention-days` (default 30) through `RuntimeConfigStore` + `PUT /api/config/guardian_event_retention_days`, matching the existing `response_retention_days` and `audit_retention_days` pattern. However, all three retention-bearing stores (`AuditStore`, `ResponseStore`, `GuaranteedStateStore`) capture their retention value at construction time and never re-read it — the runtime PUT mutates `cfg_` and `RuntimeConfigStore` but the running reaper continues using the startup value. An operator who PUTs a new retention value sees `200 {"applied": true}` but the store behaviour does not change until the next server restart. This is a systemic limitation shared across all three stores, not a Guardian-specific bug; it is tracked as issue #483.

**Runtime config PUT now rejects non-numeric and negative integer values with HTTP 400.** Hardening round 4 (UP-R5) added `std::from_chars` validation to `PUT /api/config/<key>` for `heartbeat_timeout`, `response_retention_days`, `audit_retention_days`, and `guardian_event_retention_days`. The previous handler silently wrote invalid strings to `RuntimeConfigStore` and swallowed the `stoi` error, leaving `cfg_` unchanged. If your automation relied on setting retention to a **negative** value (e.g., `"-1"`) to disable retention — which the store then treated as "never reap" via the `<= 0` sentinel — that automation will now receive `400 {"error":{"code":400,"message":"value must be a non-negative integer"}}`. Use `"0"` instead **only for `guardian_event_retention_days`**, where it preserves the disable-retention semantic and passes validation. For `heartbeat_timeout`, `response_retention_days` and `audit_retention_days` the store applies its own `> 0` check *after* the route's, so `"0"` is also rejected - with a different, bare-shaped body, `{"error":"value must be a positive integer"}`. There is no supported way to disable retention for those three through this endpoint. Automation that previously set non-numeric strings (anything other than a base-10 integer) was silently a no-op before this release — the 400 now surfaces the configuration error that had been hidden.

### v0.12.0 — A3 UX ladder (#620, #622, #624)

Three operator-visible behaviour changes ship in the v0.12.0 A3 ladder. None require code changes on the operator side, but two of them require **action if you maintain a local compose override**:

**1. Container healthchecks now pass (#622).** The shipped `docker-compose.uat.yml` healthcheck blocks were updated to use tools available in each runtime image (`bash` + `/dev/tcp` for the server; busybox `wget --spider` for the gateway). After upgrade, `docker compose ps` reports `(healthy)` instead of `(unhealthy)`.

> **If you maintain a local copy of the compose file** (e.g. `docker-compose.local.yml` or a pinned vendored copy), your override still uses the broken pre-fix healthcheck pattern and will continue showing `(unhealthy)` until you sync the change. Replace your server-service healthcheck stanza with:
>
> ```yaml
>     healthcheck:
>       test:
>         - "CMD"
>         - "bash"
>         - "-c"
>         - "exec 3<>/dev/tcp/localhost/8080 && printf 'GET /livez HTTP/1.0\\r\\nHost: localhost\\r\\n\\r\\n' >&3 && grep -q '200 OK' <&3 ; rc=$? ; exec 3>&- ; exit $rc"
> ```
>
> And the gateway-service healthcheck stanza with:
>
> ```yaml
>     healthcheck:
>       test: ["CMD", "wget", "--spider", "-q", "http://localhost:8081/healthz"]
> ```

**2. `/api/health` is restored as an alias of `/health` (#620).** The pre-#401 endpoint path is back. Monitoring integrations that point at `/api/health` work without reconfiguration; both URLs serve identical JSON. Both are exempt from rate limiting (a follow-up hardening over the bare `/health` behaviour). For load-balancer probes that should drain in-flight traffic before stopping, continue using `/readyz` — `/health` and `/api/health` are intentionally not draining-aware (Kubernetes pattern: liveness/health probes are not draining-aware).

**3. File-logger boot messages are now quieter (#624).** The previous `WARN: Could not create log directory /var/log/yuzu` + `ERROR: file logger setup failed` pair on every container boot is replaced by a single INFO-level line when the default path cannot be created. The Docker server image now pre-creates `/var/log/yuzu` (mode 0750, owned by `yuzu`) so the path is writable out of the box. **If your monitoring previously alerted on the WARN/ERROR lines as a misconfig signal, those signals will no longer fire** — the failure mode is now a single INFO line. Operators who require explicit on-disk logs should pass `--log-file <path>`; explicit-path failures still log at ERROR and are not silently degraded.

### `quarantine` plugin: reporting is now more conservative (Wave-2 argv migration)

The `quarantine` plugin's Windows/Linux/macOS `netsh`/`iptables`/`pfctl` invocations were migrated off shell-outs onto a bounded argv runner. Alongside the mechanism change, two reporting bugs were fixed: a Linux chain-flush could previously be miscounted as an applied containment rule (`status|quarantined|rules_applied|1` reported with zero rules actually installed), and macOS whitelist mutations could silently proceed on a failed prerequisite read or report success despite `pfctl -e` failing to enable pf.

**If your automation alerts on `status|failed`/`status|release_uncertain`/`status|update_uncertain` from `quarantine` actions, you may see these fire more often after upgrading** — this is expected. Nothing got more broken; the plugin's failure reporting simply got more honest about cases it previously reported as clean success. No action is required beyond expecting the change.

## Rollback

If an upgrade causes issues:

1. Stop the new version
2. Restore the backed-up `.db` and `.cfg` files
3. Start the previous version binary

**Important:** Rolling back after a schema migration requires restoring the database files from backup. The old binary cannot read the new schema.

## Troubleshooting

| Symptom | Cause | Fix |
|---|---|---|
| Server won't start after upgrade | Schema migration failure | Check logs, restore backup, report issue |
| Agents can't connect | Protocol version mismatch | Ensure server was upgraded first |
| Dashboard shows errors | Browser cache | Clear browser cache, hard refresh |
| Gateway disconnects | Version mismatch with server | Upgrade gateway to match server version |
| Slow startup | Large database migration | Normal for first start; wait for migration to complete |
