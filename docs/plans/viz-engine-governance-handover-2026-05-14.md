# Handover — feat/viz-engine governance + hardening round + PR — 2026-05-14

**Branch:** `feat/viz-engine`, worktree `/Users/<user>/Yuzu-viz`.
**HEAD:** `94a4075`, **pushed**, in sync with `origin/feat/viz-engine`.
**State:** PR raised, **CI in flight**. Read this first on pickup.

---

## Where things stand

`feat/viz-engine` → `dev` merge request is open: **PR #1032**
(https://github.com/Tr3kkR/Yuzu/pull/1032). Waiting on CI as of handover.

The branch is governance-clean and visually verified:

1. Full `/governance` pipeline run on `origin/dev..feat/viz-engine` (45 commits).
   The range had already been governed incrementally (10 rounds in-log); this
   was the pre-merge-to-dev integration pass.
2. Governance hardening round committed as `94a4075`
   `fix(server,gateway,docs): governance hardening round ...` — addresses every
   BLOCKING finding. **Gate 2 security re-review on the hardening commit: clean.**
3. Visual UAT **passed** — viz-UAT rebuilt from `94a4075` in cedar-vale mode,
   90 s traffic loop warmed 17 `internal_fleet` edges, blue cross-VM tubes
   confirmed rendering on the live Cedar & Vale 3-VM rig.

## What the hardening round (`94a4075`) changed

7 fix clusters — see the commit message for the full per-finding mapping:

- **IP-ownership lifecycle** — `kIpClaimReclaimAfter` (300 s) reclaim window so a
  crashed agent doesn't strand its IPs forever (UP-3); CAP-1 eviction victim
  keyed on server-stamped `server_received_at` not agent `ts` (UP-4);
  `agent_ips_` reverse index replaces three O(N) `ip_owner_` scans (UP-15);
  `topology.push.evicted_for_cap` audit event.
- **Parser field clamps** — `hostname`, process `name`/`cmdline`/`user`, conn
  meta strings now length-clamped at parse time (qe-B1/sec-M1).
- **Mixed-fleet split-brain** — `RosterProvider` seam; `get()` emits a
  `stale=true` placeholder for registered-but-unpushed agents instead of
  dropping them once any agent pushes (UP-9).
- **Batch isolation** — per-entry try/catch around `heartbeat_ingestion ingest()`
  in gateway `BatchHeartbeat` and direct `Heartbeat` (UP-10).
- **Kill switch** — `--viz-disable` now 503s the `/viz/fleet` + `/viz/host/<id>`
  page shells, not just the REST endpoints; `server.viz_disabled` startup audit
  event (sec-L1/compliance F-1).
- **Gateway** — `replay_registrations` no longer restarts an in-flight drip from
  scratch on every redundant trigger (replay-storm fix, UP-5);
  `yuzu_gw_registration_replay_total` / `_queue_depth` telemetry (OBS-4).
- **Tests + docs** — 8 new `[gate7]` regression cases; `test_trigger_engine`
  switched to `unique_temp_path` (qe-S1); CHANGELOG, metrics.md, gateway.md,
  server-admin.md, upgrading.md, rest-api.md updated.

## Open / next

1. **PR #1032 CI** — watch it. If it goes green, the merge is a clean
   fast-forwardable merge (`git merge-tree` against `origin/dev` was
   conflict-free; dev's 20 commits are all CI/infra).
2. **Deferred follow-up issues filed this session** — **#1020** (perf-B1:
   gateway `BatchHeartbeat` does N synchronous JSON parses on one gRPC thread —
   architectural, ADR-0002 scale), **#1021** (KS-1: runtime `--viz-disable`
   toggle endpoint — new mutating admin endpoint, needs its own governance
   pass). Both consciously deferred, not merge blockers.
3. **Still open from earlier sessions** — #1018 (function-aware tier
   classification), #1019 (kernel eventing for short-lived connections).

## Verification performed (`94a4075`)

- Server build clean (macOS); C++ server/agent/echo Catch2 suites all pass.
- Gateway: `rebar3 compile` + `rebar3 dialyzer` clean; eunit 135 pass / 0 fail.
  (Note: a pre-existing `yuzu_gw_circuit_breaker_nf_tests:backoff_capped`
  timeout/`cancelled` is a known flake, unrelated — present in the baseline run
  before any changes.)
- Gate 2 security-guardian re-review of the hardening diff: clean, no findings.

## Environment state at handover

- **viz-UAT stack is UP** — server + gateway containers rebuilt from `94a4075`,
  running, healthy. cedar-vale mode: the 3 Alpine OrbStack VMs (`yuzu-frontend`,
  `yuzu-app`, `yuzu-db`) have native agents registered. Dashboard at
  `http://localhost:8080` (`admin` / `adminpassword1`). `internal_fleet` edges
  are warm (the `last_seen` merge carries them ~1 h). Stop with
  `bash scripts/start-viz-uat.sh stop` when done.
- Erlang toolchain note: `source scripts/ensure-erlang.sh` did **not** work in
  this session's harness shell (sourced-detection tripped); worked around with
  `export PATH="/opt/homebrew/bin:$PATH"` for `rebar3`.

## Gotchas carried forward (unchanged from prior handover)

- viz JS bundles now `no-cache` — but a browser may still hold the pre-fix
  cached `yuzu-viz.js`; one `Cmd+Option+R` clears it.
- Recreating the viz-UAT **server** container strands gateway-proxied VM agents;
  recovery is to restart the 3 VM agents (the `ad1fc5c` replay fix mitigates
  this on upstream reconnect but a full container recreate still needs it).
- Blue cross-VM tubes are **not automatic** — they only render for
  `internal_fleet`-scope edges, which need ~90 s of sustained inter-VM traffic
  to warm. See the prior handover (`viz-host-drilldown-handover-2026-05-14.md`)
  for the traffic loop.

Standing renderer/store invariants: `docs/fleet-viz-invariants.md`.
Full ladder plan: `docs/plans/feat-viz-engine-plan-2026-05-09.md`.
