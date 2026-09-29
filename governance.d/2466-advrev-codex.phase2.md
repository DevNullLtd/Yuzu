# Codex Phase 2 — cross-examination and revised position

## Peer finding cross-examination

| PEER-ID | label | evidence I checked (file:line / command) | my severity |
|---|---|---|---|
| K1 | false-positive/unfair | `docs/auth-architecture.md:2975-2987` explicitly says mutations fail closed while reads set the header and proceed, and explains that these reads expose authorization-topology metadata rather than behavioural PII; `docs/user-manual/rest-api.md:941-945` publishes the same contract. The exact outcomes are pinned by `tests/unit/server/test_engine_principal_lifecycle.cpp:1244-1407` and `tests/unit/server/test_rest_engine_principal_roles.cpp:402-465`. | none |
| K2 | false-positive/unfair | `server/core/src/rest_api_v1.cpp:4092-4106` says “treat as unconfirmed and reconcile,” not “retry confirm”; the surface-wide recovery contract at `docs/user-manual/rest-api.md:945` defines reconciliation as a read. The committed state is intentionally tested at `tests/unit/server/test_engine_principal_lifecycle.cpp:1301-1318`. A more verbose message is taste, not a demonstrated non-actionable or incorrect error. | none |
| K3 | false-positive/unfair | `server/core/src/rest_a4_envelope_http.hpp:54-57` shows `a4_error` only calls `ensure_correlation_id(res)` and builds JSON; it neither clears nor replaces `Sec-Audit-Failed`. Exact route tests assert header survival on the 503 paths at `tests/unit/server/test_engine_principal_lifecycle.cpp:1255-1354` and roles paths at `tests/unit/server/test_rest_engine_principal_roles.cpp:407-446`. | none |
| K4 | false-positive/unfair | `server/core/src/rest_api_v1.cpp:314-322` names the credential-level recovery route `DELETE /api/v1/tokens/{token_id}` and distinguishes it from terminal principal deletion; `docs/user-manual/rest-api.md:907-933` documents token rotation/revocation behavior. Revoking the unusable active credential leaves the principal active, so mint can succeed; the peer inferred absence from incomplete context. | none |
| K5 | false-positive/unfair | `server/core/src/rest_api_v1.cpp:4088-4094` intentionally increments after `confirm_rotation` commits and before audit emission. `tests/unit/server/test_engine_principal_lifecycle.cpp:1301-1318` verifies the successor is sole active credential despite the audit 503. The metric is an operation/store-outcome counter, and the peer itself acknowledged the explicit policy; no contradictory metric contract or operational defect was shown. | none |
| K6 | false-positive/unfair | `server/core/src/rest_audit.hpp:132-153` defines `Sec-Audit-Failed` as the shared HTTP persist-failure signal, and `docs/auth-architecture.md:2980-2987` expressly applies set-and-proceed signaling to reads and denials. `tests/unit/server/test_engine_principal_lifecycle.cpp:1394-1407` pins the 403-plus-header behavior. A coarse health signal to an already authenticated denied caller is an intentional contract here, and the proposed “fix” would make the audit drop silent on that response. | none |

## Coverage adoption and rebuttal

The peer went no deeper than my Phase 1 review on security/control flow, but raised four areas it could not inspect from its supplied context. I independently completed all four against the full tree: `a4_error` header preservation (K3), credential-level revoke recovery (K4), full route inventory/tests, and MCP/read-posture documentation. K3 and K4 are rebutted by direct source facts above. The peer’s information-disclosure and metric-semantics observations (K5/K6) were also checked, but neither identifies a violated anchor, inconsistent implementation, or actionable defect. Its test-adequacy axis was skimmed; I adopt none of its findings because the full tests directly falsify or intentionally pin the questioned behavior.

## Own findings under cross-examination

Kimi did not contradict C1-LOW-1 and did not inspect the changelog wording against the detailed REST contract. I re-verified `changelog.d/2466-engine-principal-rest-audit-failclose.security.md:7`, `server/core/src/rest_api_v1.cpp:3939-3950`, and `docs/user-manual/rest-api.md:1134`: the route re-serves the same successor secret, while the fragment says “fresh.” C1-LOW-1 remains LOW/high-confidence. No Phase-1 finding is withdrawn or re-graded.

## Revised full finding list

[C1-LOW-1]  LOW · CONFIDENCE(hi) · PROVENANCE(static-read) · unchanged
Changelog promises a fresh credential where recovery actually re-serves the same successor secret
- Location:  changelog.d/2466-engine-principal-rest-audit-failclose.security.md:7; server/core/src/rest_api_v1.cpp:3939; docs/user-manual/rest-api.md:1134
- Claim:     The changelog tells operators that retrying after a rotate-audit failure yields a “fresh” credential, but the implemented and fully documented recovery returns the same already-created successor secret.
- Evidence:  The changelog says “rotate again for a fresh, audited credential”; the route comment says “re-rotate re-serves the SAME successor,” and its 503 says “re-serve the same audited successor secret”; the REST manual likewise says “re-serve the *same* audited successor secret.”
- Scenario:  An operator treats the first successor as abandoned/rotated-away based on the release note, retries, and incorrectly records the returned bytes as a newly issued credential even though the credential identity and secret are unchanged.
- Inference: This is operator-facing recovery wording drift, not a security-control bypass; the detailed REST manual and response body state the correct behavior.
- Anchor:    judgment
- Fix:       Replace “for a fresh, audited credential” with “to re-serve the same successor under a successfully persisted reveal audit” (and distinguish mint recovery if desired).

No withdrawn findings.

VERDICT:  PASS — the anchored mutation fail-closed contract is satisfied; only a non-blocking changelog wording mismatch remains.
COVERAGE: Security/privilege, correctness/logic, cross-component/schema/contract consistency, and test adequacy deep across both Phase-1 reports, all changed routes, REST/MCP posture docs, helper kernel, A4 response helper, recovery paths, metrics, and focused tests. Resource/concurrency safety deep enough for the patch’s changed captures and post-mutation reads; no ownership/thread/handle/schema primitive changed. Cross-platform/portability skimmed because the patch is platform-neutral and adds no conditional path; Linux GCC compiled in Phase 1, while MSVC and Apple Clang hosts were unavailable.
RAN:      Phase 2: `rg`/`sed` source verification of every K1-K6 claim and all cited anchors/tests — completed; no new execution was needed to resolve the static disputes. Phase 1 empirical results retained: `meson compile -C build-linux tests/yuzu_server_tests` PASS; `./build-linux/tests/yuzu_server_tests '[audit_failclose]'` 6/6 SKIPPED, exit 4 because `YUZU_TEST_POSTGRES_DSN` was unset and `pg_isready` unavailable; `./build-linux/tests/yuzu_server_tests '[rest][audit][helper]'` PASS (5 cases/12 assertions); `git diff --check 9707e7219..fe7bebbb9` PASS; change-local formatting could not be isolated because whole-file `clang-format --dry-run --Werror` reported extensive pre-existing violations. CI status on PR head not checked because outward GitHub access/action was prohibited by the protocol.
FILES:    /tmp/yuzu-advrev-eng-principal-audit/codex.phase1.md; /tmp/yuzu-advrev-eng-principal-audit/kimi.phase1.md; CLAUDE.md; .codex/skills/auth-and-authz/SKILL.md; .claude/routed-concerns.md; .claude/routed-concerns-access-control.md; docs/adr/1005-headless-platform-use-case-engines.md; docs/adr-1005-execution-plan.md; docs/auth-architecture.md; docs/agentic-first-principle.md; docs/user-manual/audit-log.md; docs/user-manual/rest-api.md; server/core/src/rest_audit.hpp; server/core/src/rest_a4_envelope_http.hpp; server/core/src/rest_api_v1.cpp; server/core/src/mcp_server.cpp; server/core/src/engine_principal_store.hpp; server/core/src/engine_principal_store.cpp; tests/unit/server/test_rest_audit_helper.cpp; tests/unit/server/test_engine_principal_lifecycle.cpp; tests/unit/server/test_rest_engine_principal_roles.cpp; changelog.d/2466-engine-principal-rest-audit-failclose.security.md.

## Delta since Phase 1

- Verdict remains PASS; C1-LOW-1 remains unchanged.
- Independently checked all six peer findings; none is adopted.
- K1/K3/K4 are directly falsified by the new posture docs, `a4_error` implementation/tests, and the credential-level revoke route respectively.
- K2/K5/K6 describe intentional/documented behavior without showing an incorrect contract or concrete defect.
- Remaining disagreement: Kimi grades K1 MEDIUM and K2/K3/K4/K5/K6 LOW; I grade all six as false-positive/unfair with no finding severity.
