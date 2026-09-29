# Adversarial-review synthesis — WS-3 3.2 fenced-leader loop gate (8e67c2df6)

Panel: Codex (empirical, gpt-5.6-sol, compiled+ran non-PG tests on GCC 15.2/C++23) + Kimi-K3 (static).
Orchestrator/adjudicator: Opus, verifying each finding against the real code.

## VERDICT: PASS — no CRITICAL/HIGH. All surviving findings LOW.

Both reviewers independently returned PASS. The only MEDIUM (Codex CDX-P1-01) was adjudicated to LOW by
Kimi's cross-exam (K7) and by me — E6-capped (multi-replica-only), WS-6-deferred, and the literal fix
regresses single-replica boot. Kimi's K1 was falsified by both Codex and me (Postgres is mandatory).

## Consolidated findings (ranked)

1. **[both-independently] Election thread has no exception boundary — LOW.** (K2 + CDX-P2-02.) The
   `leader_thread_` lambda calls try_acquire()/heartbeat() with no try/catch, unlike the three sibling
   tick loops in the same diff; an escaping throw (bad_alloc, throwing spdlog sink) → std::terminate.
   Provenance: static, both. **FIX: wrap the loop body in try/catch, mirroring the siblings.**

2. **[Codex-found, Kimi-adopted-down] Boot CRL pre-publish is ungated — LOW (E6-capped).** (CDX-P1-01 /
   K7.) VERIFIED by me: `publish_crl()` at server.cpp:7181 runs before the elector is constructed
   (7347); the freshness republish (7841) is gated. `crl_publish_mu_` is in-process only. Concurrent
   multi-replica *starts* race crlNumber — impossible on single-replica (the only topology today), and
   cross-replica numbering atomicity is explicitly WS-6. Codex's literal "gate it" fix would skip the
   boot CRL on single-replica (leadership is async). **FIX: a code comment marking it a known-ungated
   automatic publish (WS-6 owns cross-replica numbering) + a WS-6 tracking follow-up. NOT a runtime gate.**

3. **[both-confirmed] build_coord_dsn untestable + untested — LOW.** (K3 + CDX-P2-03.) Pure string logic
   (6 keys, keyword/URI branch, operator-wins) in server.cpp's anon namespace, zero coverage; K3 also
   flags a leading-whitespace URI-detection edge. **FIX: extract to a testable header + unit tests.**

4. **[Kimi-found, Codex-retained-lowconf] #4013 backend-kill test races async termination — LOW.** (K4 /
   CDX-P2-04.) `CHECK_FALSE(a.heartbeat())` fires immediately after `pg_terminate_backend` with no
   wait; the same test's re-acquire loop already tolerates async death. Never executed in this review
   (Codex's env skipped all PG cases). **FIX: poll until the victim backend is gone before the assertion.**

5. **[both-confirmed] run() comment overclaims initial leadership readiness — LOW.** (K6 + CDX-P2-05.)
   Comment says is_leader() "already has a value" by first tick, but acquisition is async. Practical
   outcome fine (happy-path verified: workers sleep before first tick; acquire is ms). **FIX: reword.**

6. **[Kimi, Codex-rebutted-as-future-safety] pass⇒gated not enforced — LOW.** (K5.) Same as governance
   sec-L1, already filed **#4121**; the header already documents the limit. **FIX: a note at the
   FencedLeaderOnly enumerator; #4121 tracks the CI sweep.**

REFUTED: K1 (null-pg_pool_) — Postgres is mandatory (server.cpp:4012/4044 → startup_failed_ → run()
refuses; workers never spawn). Not a finding.

## Empiricism note
Codex carried empiricism (compiled the changed TUs, ran the non-PG [leader-gate]/[background-jobs]
cases green) but its env had YUZU_TEST_POSTGRES_DSN unset, so ALL [pg] cases + the TSan concurrency
test were SKIPPED there — the lock-free publish protocol and K4 remain empirically unexercised by the
panel (I ran the [pg] suite myself locally: 135 assertions/20 cases green). Kimi is static-only.
Two-dispatch-planes clean was upgraded from comment-trust to Codex's empirical ca_routes.cpp read.

## Disposition
All six fold or track (all LOW): fixes 1,3,4,5 folded as code/test changes; 2 as a comment + WS-6
follow-up; 6 as a comment (+#4121). None blocks.
