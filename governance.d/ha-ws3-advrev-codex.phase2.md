# Phase 2 — cross-examination and revised review (`codex`)

## Peer finding cross-examination

| PEER-ID | label | evidence I checked (file:line / command) | my severity |
|---|---|---|---|
| K1 | false-positive/unfair | `server/core/src/server.cpp:4003-4050` explicitly makes an empty/unreachable PostgreSQL substrate set `startup_failed_`; `run()` refuses to serve at `server.cpp:7434`. The four worker objects are themselves PostgreSQL-backed and conditionally constructed only after the substrate succeeds. The guard does not imply a supported null-pool runtime. | none |
| K2 | confirmed-independently | `server/core/src/server.cpp:7361-7400` has no exception boundary around the `std::thread` entry function, while the three newly gated sibling tick loops catch `std::exception` and `...`. The called APIs are not declared `noexcept` (`leader_elector.hpp:67-84`). | LOW |
| K3 | confirmed-independently | `server/core/src/server.cpp:385-421` places `build_coord_dsn` in the anonymous namespace; `rg -n "build_coord_dsn" server tests` finds only its definition and production call. The URI/keyword and operator-override branches therefore have no direct tests. | LOW |
| K4 | not-verified | `tests/unit/server/test_leader_elector.cpp:252-280` does call `heartbeat()` immediately after `pg_terminate_backend` and later polls reacquisition. The PostgreSQL-backed case cannot run here (`YUZU_TEST_POSTGRES_DSN` unset), so I could not reproduce an actual flake or establish that the victim can successfully process a subsequent query after the termination signal. | LOW (lo confidence) |
| K5 | false-positive/unfair | `server/core/src/background_jobs.hpp:31-48` already states the exact enforcement limit, records follow-up #4094, and mandates routed review for additions. The peer identifies no currently ungated table row; this is future architecture preference, not a defect in `origin/dev..HEAD`. | none |
| K6 | confirmed-independently | `server/core/src/server.cpp:7336-7364` says `is_leader()` “already has a value” before first worker tick, but acquisition happens only inside the asynchronously started lambda at `server.cpp:7361-7373`. | LOW |

Severity adjudication: K2, K3, and K6 are real robustness/documentation defects but have no anchor establishing a merge-blocking contract and no demonstrated current correctness failure, so LOW is appropriate. K4 remains LOW and low-confidence because its asynchronous premise was not empirically reproduced. K1 is falsified by the explicit mandatory-Postgres boot failure. K5 is not a present change defect and should not enter the finding set.

## Peer coverage adoption/rebuttal

The peer went deeper than my Phase 1 on exception containment, DSN-builder unit-testability, backend-kill test timing, and comment accuracy. I independently adopt K2, K3, and K6 below; I retain K4 only as an unverified low-confidence test-robustness concern. I rebut K1 from the production boot path and K5 from the header's already-documented enforcement boundary. On the peer's deep SQL-injection, secret logging, atomic publication, state-machine, teardown, and two-dispatch-plane checks, my independent Phase-1 inspection found the same paths clean; the fresh compile and focused tests produced no contrary evidence. The peer skimmed the authoritative anchors and did not inspect the startup CRL path, so its silence does not undercut CDX-P1-01.

## Revised full finding list

[CDX-P1-01]  MEDIUM · CONFIDENCE(hi) · PROVENANCE(static-read) · unchanged
The startup CRL publication bypasses the newly wired leader gate
- Location:  server/core/src/server.cpp:7176-7182 (+ periodic gated duplicate at server/core/src/server.cpp:7831-7847)
- Claim:     every replica publishes a CRL during startup before the elector exists, so concurrent starts can still race automatic CRL-number publication outside the new single-writer attempt gate.
- Evidence:  `run()` invokes `if (!publish_crl())` at line 7181; the elector is constructed only at lines 7346-7349; `publish_crl()` is process-mutex-protected but advances store-backed CRL state; the periodic call checks `leader_gate_permits<background_job_class("ca.publish_crl")>` at lines 7839-7841.
- Scenario:  two replicas start concurrently against the same PostgreSQL database → each executes the ungated startup publication → both attempt the same automatic CRL state transition/number allocation outside leader serialization → one fails or automatic publication races during rolling start/failover.
- Inference: the one-shot is the same automatic state-mutating primitive as the classified freshness pass, but the checked-in inventory defines background passes and does not expressly classify boot-time one-shots; therefore this remains a judgment finding, not a contract block. WS-6 may later make allocation intrinsically safe.
- Anchor:    judgment (ADR-2002 §6 single-core singleton-work model and the fenced-leader-election routed-concern row's `ca.publish_crl` rationale support the concern, but neither unambiguously includes this startup one-shot).
- Fix:       perform startup publication after leadership acquisition through the same classified gate, or explicitly classify the startup operation separately and make its cross-replica state transition atomic.

[CDX-P2-02]  LOW · CONFIDENCE(med) · PROVENANCE(static-read) · new-from-cross-exam
The election thread lacks an exception boundary
- Location:  server/core/src/server.cpp:7361-7400
- Claim:     an exception escaping `try_acquire()` or `heartbeat()` terminates the whole process instead of degrading and retrying the coordination loop.
- Evidence:  the `std::thread` lambda directly invokes both methods without `try`/`catch`; their declarations at `leader_elector.hpp:67-84` are not `noexcept`; the sibling policy/quarantine/schedule loops catch both `std::exception` and unknown exceptions.
- Scenario:  an allocation or logging failure throws during one election iteration → the exception crosses the thread entry point → `std::terminate` ends the server and forces failover.
- Inference: libpq reports ordinary failures without throwing, so the realistic exceptions are exceptional process-health conditions; this limits severity.
- Anchor:    judgment.
- Fix:       catch at the thread-entry iteration boundary, log, clear/resign leadership as needed, and continue with backoff; alternatively document and enforce `noexcept` through every called path.

[CDX-P2-03]  LOW · CONFIDENCE(med) · PROVENANCE(static-read) · new-from-cross-exam
Coordination DSN augmentation has no direct tests
- Location:  server/core/src/server.cpp:385-421
- Claim:     the pure URI/keyword parameter-augmentation logic is inaccessible to unit tests and its branch behavior is not pinned, so a separator or override regression only appears as all fenced loops pausing at runtime.
- Evidence:  `build_coord_dsn` is defined in `server.cpp`'s anonymous namespace; `rg -n "build_coord_dsn" server tests` finds only that definition and the production call at `server.cpp:7348`.
- Scenario:  a future edit mishandles a URI query separator or existing operator parameter → the dedicated coordination connection rejects the DSN → leadership never establishes although the main pool DSN is valid.
- Inference: the current common URI and keyword branches read correctly; this is missing regression coverage, not a demonstrated current malformed output.
- Anchor:    judgment.
- Fix:       extract the helper to a testable internal unit and cover keyword/URI forms, existing query strings, all operator overrides, and empty input.

[CDX-P2-04]  LOW · CONFIDENCE(lo) · PROVENANCE(static-read) · new-from-cross-exam
Backend-termination test may assume synchronous victim exit
- Location:  tests/unit/server/test_leader_elector.cpp:252-280
- Claim:     the test immediately requires the next heartbeat to fail after requesting backend termination, which may be timing-sensitive if signal delivery/session exit is not complete.
- Evidence:  `PQexec(...pg_terminate_backend...)` is followed immediately by `CHECK_FALSE(a.heartbeat())`; the subsequent reacquisition uses a bounded polling loop.
- Scenario:  a loaded PostgreSQL CI host acknowledges the termination request before the victim session is observably dead → the immediate heartbeat result differs from the test's expectation → an intermittent failure.
- Inference: I could not execute this PostgreSQL-backed case, and an idle backend normally exits promptly; an actual successful post-signal heartbeat remains unproven.
- Anchor:    judgment.
- Fix:       poll heartbeat or victim-session disappearance with a deadline before asserting the stable post-termination state.

[CDX-P2-05]  LOW · CONFIDENCE(hi) · PROVENANCE(static-read) · new-from-cross-exam
Startup comment overstates initial leadership readiness
- Location:  server/core/src/server.cpp:7336-7364
- Claim:     the comment promises leadership state is established before a worker's first tick, but acquisition is asynchronous and the first tick can legitimately be denied.
- Evidence:  the comment says `is_leader()` “already has a value”; `try_acquire()` first runs inside the newly spawned election-thread lambda.
- Scenario:  a worker starts and ticks before the election thread completes its first database round-trip → it skips one periodic pass despite the comment's stated ordering guarantee.
- Inference: fail-closed skipping is correct and later ticks recover, so impact is documentation/operational expectation only.
- Anchor:    judgment.
- Fix:       say the elector is wired before workers and that initial ticks may deny until asynchronous acquisition succeeds.

No Phase-1 finding is withdrawn or severity-changed. CDX-P1-01 was ignored rather than contradicted by the peer; I rechecked both call sites and defend it at MEDIUM/judgment because the ungated automatic startup call is factual, while the anchors do not clearly make a boot-time one-shot part of this slice's blocking contract.

VERDICT:  PASS — the startup automatic-CRL gap remains MEDIUM/judgment and the independently verified peer additions are LOW, so there is no CRITICAL/HIGH block.
COVERAGE: deep on correctness/logic, attempt-gate coverage, startup and periodic CRL dispatch, mandatory-Postgres boot semantics, election state machine, exception/thread/resource lifetime, classification anti-drift, two dispatch planes, security parameterization/logging, and targeted test adequacy; cross-platform portability remains skimmed because the changed runtime path is portable C++/libpq and this host cannot execute MSVC or Apple-Clang, though GCC compiled the changed TUs.
RAN:      Phase 2: `meson compile -C build-linux tests/yuzu_server_tests` — pass (GCC/C++23); `./build-linux/tests/yuzu_server_tests '[leader-gate]'` — 3 passed, 1 PostgreSQL case skipped (`YUZU_TEST_POSTGRES_DSN` unset); `./build-linux/tests/yuzu_server_tests '[leader-elector]'` — 3 passed, 14 PostgreSQL cases skipped for the same reason; focused `rg`/`sed` checks listed in the table. Phase 1 additionally ran `git diff --check` (pass), `[background-jobs]` (3 cases/243 assertions pass), and the server suite (15 targets pass; 3 environment/sandbox failures, final stalled target interrupted). No TSan or cross-platform executable build. CI status remains unavailable because GitHub API access failed in Phase 1.
FILES:    both Phase-1 reports; CLAUDE.md; docs/adr/2002-high-availability-architecture.md; docs/agentic-first-principle.md; .claude/routed-concerns.md; .claude/routed-concerns-access-control.md; docs/cpp-conventions.md; .codex/skills/cpp-expert/SKILL.md; .codex/skills/cpp-safety/SKILL.md; server/core/src/background_jobs.hpp; server/core/src/leader_elector.hpp; server/core/src/leader_elector.cpp; server/core/src/leader_gate.hpp; server/core/src/server.cpp; server/core/src/ca_routes.cpp; server/core/meson.build; tests/meson.build; tests/unit/server/test_leader_elector.cpp; tests/unit/server/test_leader_gate.cpp; tests/unit/server/test_background_jobs.cpp; docs/ha-delivery-matrix.md; docs/user-manual/server-admin.md; changelog.d/4013-ha-ws3-leader-loop-gate.added.md; governance.d/ha-ws3-loop-gate.8y1WLY.jsonl.

## Delta since Phase 1

- CDX-P1-01 remains MEDIUM/judgment after rechecking the startup and periodic CRL sites; the peer did not inspect or rebut it.
- I adopt independently verified LOW findings for election-thread exception containment, DSN-helper test coverage, and the inaccurate readiness comment.
- I retain the backend-kill timing concern only as LOW/low-confidence because PostgreSQL execution was unavailable.
- I reject K1 as falsified by mandatory-Postgres fail-closed startup and K5 as future-safety commentary rather than a current defect.
