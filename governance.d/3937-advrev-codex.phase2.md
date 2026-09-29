# Codex Phase 2 — cross-examination and revised position

## Peer finding cross-examination

| PEER-ID | label | evidence I checked (file:line / command) | my severity |
|---|---|---|---|
| K1 | false-positive/unfair | Full-file enumeration: `rg -n 'tool_name == "(create_engine_principal\|revoke_engine_principal\|transfer_engine_principal_owner\|mint_engine_credential\|rotate_engine_credential\|confirm_engine_rotation\|assign_engine_role\|unassign_engine_role)"' server/core/src/mcp_server.cpp` finds exactly the eight documented mutation branches at 12011, 12124, 12286, 12489, 12624, 12741, 12877, and 13341; `docs/mcp-server.md:163` enumerates the same closed set. K1 supplied no positive defect and its falsifier is satisfied. | none |
| K2 | false-positive/unfair | `server/core/src/api_token_store.hpp:350-374` specifies same-operator same-secret grace replay; `tests/unit/server/test_api_token_store.cpp:1379-1444` exercises same-secret replay and cross-operator denial; the MCP handler calls rotation by `principal_id` plus authenticated `session->username` at `mcp_server.cpp:12802-12803`, not by possession of the withheld secret. Mint creates the sole active credential and rotate's one-active arm creates/re-serves the successor. The remediation is supported. K2 also conflates the short replay grace window with the longer overlap window, but that wording defect is already independently captured more precisely by CDX-P1-002's missing decision-grade live descriptions and is not the hypothetical lifecycle failure K2 claims. | none |
| K3 | false-positive/unfair | `create_engine_principal` takes caller-chosen `principal_id` (`mcp_server.cpp:976-1004`), so the caller already knows the created identifier; its “list and guess” scenario is false. Mint is principal-scoped and the documented recovery is list then principal-scoped rotate; `mcp_server.cpp:12741-12803` does not require the unknown token id. An identifier could improve ergonomics, but the claimed nondeterministic recovery is not established. | none |
| K4 | false-positive/unfair | `mcp_server.cpp:12103-12118` (representative) gates success on the domain mutation audit; only afterward is the separate generic `mcp.<tool>` invocation audit attempted. `docs/mcp-server.md:163` expressly scopes #3937 to “their audit row” and `mcp_audit` is the generic invocation record. ADR-1005's mutation evidence obligation is met once the domain row persists; requiring two independently successful audit rows is neither anchor nor plugin-config precedent. | none |
| K5 | false-positive/unfair | Contrary to K5's premise, the actual range changes four documentation/changelog files and two test files in addition to production (`git diff --name-only e05935e7b..f6fe774d2`). `docs/mcp-server.md:163` and `docs/user-manual/mcp.md:468-476` document the 503 behavior; `tests/unit/server/test_mcp_server.cpp:1829-1950` and `test_mcp_engine_principal_roles.cpp:240-300` add five fail-close tests. There remains narrower documentation drift, captured by CDX-P1-003, but not the claimed absence of docs/tests. | none |

## Peer coverage adoption/rebuttal

- Security/injection and secret withholding: adopted after independent inspection. All new envelope strings are literals and the mint/rotate early returns precede payload construction. This does not cure the throwing-audit gap below.
- Correctness/full-surface completeness: independently completed. K1 is rebutted: the eight handlers are the full documented engine-principal mutation set. The peer missed exception semantics and the live `tools/list` descriptions.
- Rotation lifecycle: independently completed and K2 rebutted using the store contract and tests. The same authenticated operator can re-serve the same successor during the bounded grace period without presenting the old/raw credential.
- Resource/concurrency/lifetime and portability: adopted. The patch adds no state, ownership, threads, handles, or platform branches; server scope is Linux-only and the changed TU compiled under GCC in Phase 1.
- Cross-component/docs: the peer's conclusion is rejected because it inspected no docs. Current docs partially changed but retain the contradictions in CDX-P1-003.
- Tests: independently completed. Five false-return paths are covered; create/revoke/transfer are explicitly deferred in a test comment, and no throwing-`AuditFn` case exists.

## Revised full finding list

[CDX-P1-001]  MEDIUM · CONFIDENCE(hi) · PROVENANCE(compiled) · unchanged (claim narrowed after cross-exam)
Throwing domain audit writes bypass the promised JSON-RPC 503/A4 response
- Location:  server/core/src/mcp_server.cpp:12103 (+ 12171, 12353, 12601, 12711, 12843, 12960, 13418); server/core/src/rest_audit.hpp:64; server/core/src/mcp_server.cpp:14117
- Claim:     The eight handlers call the domain `audit_fn` directly, so a throw after commit prevents a normal success (the narrow fail-closed security property holds) but escapes before the specified JSON-RPC 503/A4 recovery envelope is produced.
- Evidence:  Each changed site directly evaluates `audit_fn(...)` and only handles a returned `false`; `try_persist_audit` catches both `std::exception` and non-standard exceptions at `rest_audit.hpp:81-89`; the MCP generic helper explicitly uses it at `mcp_server.cpp:3952-3963`; the returned POST handler ends at `mcp_server.cpp:14117` without a surrounding catch, and the in-file comment at 14014 states no server-wide exception handler is installed.
- Scenario:  An authorized caller commits an engine role/principal/credential mutation -> the audit sink throws -> control never reaches `a4_error(503, ..., audit_ok=false)` -> the HTTP library supplies an uncaught-exception 500 rather than the correlation/remediation/audit-gap response; mint/rotate still do not disclose their secret.
- Inference: The core “never report mutation success without its audit row” property is preserved because stack unwinding precludes the success response. The defect is nevertheless a real A4 and explicit #3937 wire-contract violation, and REST/MCP parity is false for exceptions because REST twins use the catching kernel.
- Anchor:    `docs/agentic-first-principle.md` A4 (“Every failure response”) and A5 item 5 (self-recovering errors); `docs/mcp-server.md:163` promises JSON-RPC 503 whenever the row cannot persist. The ADR-1005 mutation-fail-closed security invariant itself is not violated by this throw path.
- Fix:       Route all eight domain success audits through `detail::try_persist_audit`, then add a throwing-`AuditFn` regression test asserting the same 503/A4 body, `audit_persisted:false`, and secret withholding as the false-return path.

[CDX-P1-002]  MEDIUM · CONFIDENCE(hi) · PROVENANCE(static-read) · unchanged
The live MCP tool descriptions omit the new audit-failure recovery behavior
- Location:  server/core/src/mcp_server.cpp:976-1112 (+ 1308-1359)
- Claim:     The machine-served `kTools[]` descriptions for all eight changed mutation tools omit the new committed-but-unconfirmed audit-failure state and its safe, tool-specific recovery.
- Evidence:  The affected descriptions contain no `audit`, `audit_persisted`, `503`, or new reconciliation instruction; for example mint still says it returns the raw value exactly once (`mcp_server.cpp:1030-1046`) while its new handler can commit and withhold it, whereas the human manual documents this distinction at `docs/user-manual/mcp.md:468-476`.
- Scenario:  An agentic worker using only `tools/list` receives the new 503 after a committed mutation -> generic retry logic repeats an unsafe mutation or cannot discover the required read/rotate/no-reconfirm recovery.
- Inference: External prose cannot supply MCP-native decision context, and the correct next action materially differs among the eight tools.
- Anchor:    `docs/agentic-first-principle.md` A5 items 2 and 5 (decision-grade workflow chaining and self-recovering errors; machine-readable context must teach as much as prose).
- Fix:       Add the concise audit-failure outcome and exact safe recovery to each affected served description; assert at least credential and confirmation distinctions through `tools/list` tests.

[CDX-P1-003]  MEDIUM · CONFIDENCE(hi) · PROVENANCE(static-read) · unchanged
Audit documentation and source commentary retain the superseded set-and-proceed contract
- Location:  docs/user-manual/audit-log.md:184; server/core/src/mcp_server.cpp:11333; docs/mcp-server.md:163
- Claim:     Retained authorities still say MCP engine mutations proceed non-fatally on audit failure and name `assign_engine_role` as set-and-proceed precedent, while another sentence guarantees an error audit record through the same failing sink.
- Evidence:  `audit-log.md:184` says MCP signals the same mutation failure “non-fatally”; `mcp_server.cpp:11333` describes `assign_engine_role` as a mutate-then-audit sibling while plugin-config now audits before mutation; `docs/mcp-server.md:163` says `mcp_audit("error") records the outcome server-side`, but `mcp_audit` calls the same supplied audit sink through `try_persist_audit` at 3961-3962 and cannot guarantee persistence during that sink failure.
- Scenario:  A maintainer follows the stale named precedent and implements another privileged mutation as success-with-warning, or an operator expects an `mcp.*|error` record that cannot exist during an audit outage.
- Inference: These contradictions undermine the very contract-alignment purpose of #3937 and can reintroduce drift.
- Anchor:    `docs/mcp-server.md:163` engine-mutation fail-closed contract and ADR-1005 Consequences (“mutations fail closed on audit failure”); documentation completeness otherwise judgment.
- Fix:       Correct `audit-log.md`, replace the stale plugin-config comment, and call `mcp_audit("error")` best-effort telemetry rather than a guaranteed durable record.

## Withdrawals

None. Kimi ignored rather than contradicted all three Phase-1 findings; re-verification supports them. CDX-P1-001 is expressly limited: it does **not** allege the throwing path returns success or violates the narrow mutation-fail-closed security invariant.

VERDICT:  PASS — no CRITICAL/HIGH defect remains; throwing audits preserve the no-success security property but violate the promised 503/A4 contract, and the live metadata/documentation remain materially incomplete.
COVERAGE: Deep on all required axes: security/privilege and secret disclosure; correctness/error propagation including the top-level MCP catch question; resource/concurrency/lifetime; Linux server portability; REST/MCP/store/documentation contract consistency; full mutation enumeration; rotation recovery semantics; and tests. Portability is low-risk because no platform-specific code changed and the server is Linux-only.
RAN:      Phase 2: full-file `rg` enumeration of all engine-principal mutation handlers, all direct/catching audit calls, server exception-handler installation, and rotation store/tests; all static checks resolved as described. Phase 1 empirical results retained: `git diff --check e05935e7b..f6fe774d2` PASS; `meson compile -C build-linux tests/yuzu_server_tests` PASS; `./build-linux/tests/yuzu_server_tests 'MCP A4:*' --reporter compact` PASS (1 case/9 assertions); `[audit_failclose]` could not execute because `YUZU_TEST_POSTGRES_DSN` is unset (11 skipped, exit 4), and Postgres provisioning was unavailable; `[mcp]~[pg]` ran 421 cases (408 pass, 10 unrelated localhost-listener failures, 3 PG skips). `clang-format --dry-run --Werror` was unusable due to pre-existing whole-file drift. PR CI status remains UNKNOWN because `gh` could not reach GitHub.
FILES:    `/tmp/yuzu-advrev-mcp-3937/codex.phase1.md`; `/tmp/yuzu-advrev-mcp-3937/kimi.phase1.md`; `.claude/routed-concerns.md`; `.claude/routed-concerns-access-control.md`; `docs/adr/1005-headless-platform-use-case-engines.md`; `docs/agentic-first-principle.md`; `docs/mcp-server.md`; `docs/user-manual/mcp.md`; `docs/user-manual/audit-log.md`; `server/core/src/mcp_server.cpp`; `server/core/src/rest_audit.hpp`; `server/core/src/api_token_store.hpp`; `server/core/src/api_token_store.cpp`; `tests/unit/server/test_api_token_store.cpp`; `tests/unit/server/test_mcp_server.cpp`; `tests/unit/server/test_mcp_engine_principal_roles.cpp`.

## Delta since Phase 1

- All three Codex findings remain MEDIUM; none is withdrawn or newly added.
- CDX-P1-001 is sharpened: the throw path does fail closed in the narrow security sense because it cannot return success, but no top-level catch produces the required JSON-RPC 503/A4 envelope.
- All five peer findings are rebutted as hypothetical or premise-false after full-repository verification; none is adopted.
- Rotation recovery and the complete eight-tool mutation set are independently verified; the remaining disagreement is that Kimi called all shown semantics correct while omitting exception, live-description, and stale-documentation checks.
