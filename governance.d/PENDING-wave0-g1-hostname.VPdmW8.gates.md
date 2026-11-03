# Gate ledger for `governance.d/PENDING-wave0-g1-hostname.VPdmW8.jsonl`

Companion to the run-ledger fragment of the same stem. The fragment holds one row per finding; this file records gate status and the Gate 1 Change Summary. Branch `perf/gateway-wave0-g1-hostname`, LOCAL ONLY (no push, no PR). Every reviewer is a subagent of one orchestrator session.

## Gate 1 — Change Summary (range `3f4eea595..192ee0864`, merge base with origin/dev `3f4eea59534c0d0238adf430c9805b8b05358c81`)

### Commits in scope (all unpushed)

| sha | subject |
|---|---|
| `ae59273ea` | perf(gateway): the agent owner keeps the hostname, not the whole AgentInfo (Phase 1c G1) (cherry-pick -x of `4e4f50b5c`) |
| `10c1a8abb` | test(gateway): code_change reduces a pre-G1 AgentInfo field to its hostname |
| `ed6c4ce8d` | docs(changelog): owner keeps the hostname only (G1) fragment |
| `192ee0864` | fix(gateway): match a pre-G1 record as a tuple in code_change/4 (dialyzer) |

### Files touched

| path | delta |
|---|---|
| `gateway/apps/yuzu_gw/src/yuzu_gw_agent.erl` | `#data.agent_info :: map()` becomes `#data.hostname :: binary()` at the same tuple position; new `hostname_of/1`; `init_owner`, `restored_data` store only the hostname; `registering/3` and `register_again/1` read the field; `format_info/2` (the `get_info/1` answer) drops the `agent_info` key; new `code_change/4` clause reduces a same-size pre-G1 tuple whose hostname slot is a map |
| `gateway/apps/yuzu_gw/test/yuzu_gw_agent_tests.erl` | two tests: no other AgentInfo field survives in the owner state; hot upgrade from the old record shape |
| `changelog.d/PENDING-gateway-owner-hostname-only.changed.md` | new fragment, placeholder name (renamed when the PR exists) |

### Interfaces affected

- Internal Erlang API `yuzu_gw_agent:get_info/1`: the `agent_info` key is removed from the answer. Callers in tree: `yuzu_gw_mgmt_service:get_agent/2` (reads `plugins`, `hostname`, `connected_at` only) and tests/CT suites (read `agent_id`, `state`, `hostname`, `plugins`).
- The owner `#data` record layout (positions unchanged; field 3 changes type). Hot code upgrade path via `code_change/4`.
- No proto, no wire, no registry schema, no config, no metric change. The registry row's hostname is still passed to `register_agent`/`recover_agent` from the same source.
- Decision 97: ListAgents (registry hostname), GetAgent (`get_info` hostname/plugins/connected_at) and QueryInventory (registry plugins/session/connected_at) are still served; the gates must confirm none of them goes empty.

### Security surface

Net-neutral to narrowing: the owner no longer holds the whole AgentInfo (less data in a crash dump or `sys:get_state`); `register_req` (token, cert, CSR) is still kept and still redacted by `format_status/1`. No authz, TLS, origin or mgmt-auth code touched. `yuzu_gw_mgmt_service.erl` (PKI row file) is not changed but consumes the changed `get_info/1` answer.

### User-facing impact

None for operators beyond memory (about -22.9 KiB live per agent at 69 plugins, Phase 1c N=3000). No flag, env var or default changes. The changelog fragment states it.

### Resource Ledger

Not applicable: no C++ in the diff. Erlang processes: no new process, monitor, link, ETS table or timer.

### Prior validation performed

Build agent: eunit 2480/2480, dialyzer clean (OTP 28.4, 2026-11-03). Re-run by the orchestrator at `192ee0864` (OTP 28.4, bash `source scripts/ensure-erlang.sh`): `rebar3 eunit --dir apps/yuzu_gw/test` exit 0, All 2480 tests passed; `rebar3 dialyzer` exit 0, no warnings.

### Governance domains triggered

Routed-concern walk, row by row, against the `origin/dev` copies of all four tables (the working-tree `routed-concerns.md` and `routed-concerns-software-estate.md` differ from origin/dev, in the daily-sync and `middleware` plugin rows only; SKILL.md and the other two tables are current): **no row matches** `yuzu_gw_agent.erl`, `yuzu_gw_agent_tests.erl` or `changelog.d/`. Nearest rows, not matched by path: the PKI row (names `yuzu_gw_mgmt_service.erl`, a consumer of `get_info/1`, unchanged) and the gateway origin-trust row (names `yuzu_gw_agent_service.erl`, unchanged). Decision matrix: `gateway/` → gateway-erlang; test file → quality-engineer; spans three directories and changes an internal contract that ADR-0073 D14 governs → architect; a memory/scaling claim → performance. No C++, so no cpp-expert/cpp-safety/Resource Ledger.

## Gate status

| gate | status | agents | findings (C/H/M/L/I) | pass |
|---|---|---|---|---|
| 1 | PASS | orchestrator | — | 1 |
| 2 | PASS (no blocking) | security-guardian (PASS, 0 findings), docs-writer (2 wording) | 0/0/0/0/2 | 1 |
| 3 | FINDINGS | gateway-erlang (PASS), quality-engineer, architect (PASS), performance (PASS) | 0/2 derived HIGH (qe-1, qe-2) + 1 speculative floor candidate (ge-3)/0/0/7 NICE | 1 |
| 4 | FINDINGS | happy-path (PASS), unhappy-path, consistency-auditor (PASS) | 0/0/3 (up-1, up-2, up-5 pre-existing)/0/5 NICE (incl. 1 speculative hp-1); UP-4/6/7 INFO, refuted or no defect, not filed | 1 |
| 5 | DONE | chaos-injector | scenarios CH-1..CH-7 (design only). Scope: CH-3 (chained code_change unit test) and CH-6 (resolve g4-hp-1 sub-binary retention) in this branch; CH-1/2/7 (hot load/downgrade, appup), CH-4 (malformed owner row, pre-existing), CH-5 to follow-up issues | 1 |
| 6 | PASS (no blocking) | compliance-officer, sre, enterprise-readiness (all PASS) | 0/0/0/0/3 (cmp-1 recorded at derived NICE, native SHOULD; sre-1, sre-2). enterprise-readiness F1/F2 (native SHOULD) are echoes of g2-doc-1 and g3-perf-1 (shown the ledger), not independent | 1 |
| 7 | DONE (round 1) | gateway-erlang (producing agent) | fixed: g3-qe-1, g3-qe-2 (pending g8-ge-1), g3-qe-3, g3-qe-4, g2-doc-1, g2-doc-2, g3-perf-1, g3-perf-2, g3-ge-1, g4-cons-2, g4-up-3, g6-sre-2; investigated g4-hp-1 (refuted); commits 00e2f6afd, ce2daaeb0, 94b00367f, ffe960eb3; eunit 2484/2484, dialyzer clean | 1 |
| 8 | FINDINGS (pass 2) | security-guardian, docs-writer, gateway-erlang, quality-engineer, architect, performance, consistency-auditor, enterprise-readiness (fix diff 68ed79ae9..ffe960eb3; happy-path, unhappy-path, sre, compliance-officer not re-run: no logic, error-path, metric, probe, thread, audit or evidence change; no routed row matches the fix diff) | 0/1 derived HIGH (g8-ge-1)/0/0/4 NICE; g3-ge-3 and g4-hp-1 refuted; orchestrator eunit 2484/2484 and dialyzer clean at ffe960eb3 | 2 |
| 7 | DONE (round 2) | gateway-erlang (producing agent) | g8-ge-1 (eb25ee3b6), g8-er-1, g8-doc-1 (partial), g8-perf-1 (de065b23f); mutant of restore_args agent_info_from_req fails restarted_owner_keeps_hostname | 2 |
| 8 | FINDINGS (pass 3) | security-guardian, docs-writer, gateway-erlang, quality-engineer, enterprise-readiness (fix diff a36406e00..de065b23f; no routed row matches) | 0/0/1 (g8p3-ge-1, I7)/0/1 NICE (g8-doc-1 residual); g3-qe-2 and g8-ge-1 confirmed closed; orchestrator eunit 2484/2484, dialyzer clean at de065b23f | 3 |
