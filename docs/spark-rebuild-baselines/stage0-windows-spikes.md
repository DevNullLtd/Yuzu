# Stage 0 baseline — Windows spike results

Executed 2026-07-05/06 on DGRHP (Windows 11 Pro, `dgrhp\daver`, reached via Tailscale SSH once OpenSSH Server was enabled). Authority: `docs/adr/0021-spark-reflex-architecture.md`; issue #1907; scratch spike sources in `spark-spikes/` (not committed — see that directory's README).

Build toolchain: MSYS2 bash + `setup_msvc_env.sh` per `docs/windows-build.md`, `cl.exe` 19.44.35227 (MSVC 14.44.35207), `/EHsc /std:c++20 /W4`. Gotcha hit and fixed: MSYS2 mangles single-leading-slash MSVC flags (`/EHsc` → parsed as a Unix path) — `export MSYS2_ARG_CONV_EXCL='*'` before invoking `cl.exe` fixes it; not yet documented anywhere in the repo, worth adding to `docs/windows-build.md` if this SSH-into-a-dev-box workflow recurs.

## 1. TP_WAIT (#1907) — RESULT: mechanism sound, adopt it — but only 2 of 4 conditions were runtime-tested, and latency-under-burst is a separate probe (§1b)

`tpwait_spike.exe`, 200 real `RegNotifyChangeKeyValue` watches on a private thread pool (min=2/max=4), stimulus thread touching one key every 250ms:

```
[tpwait_spike] private pool created, min=2 max=4
[tpwait_spike] armed 200/200 keys
[tpwait_spike] threads=6 rss_bytes=4497408 wakeups/sec=4 rearm_failures=0
[tpwait_spike] threads=6 rss_bytes=4521984 wakeups/sec=5 rearm_failures=0
... (steady state, 8 samples) ...
```

- **Thread count: flat at 6** (2 always-on: main + stimulus; up to 4 pool workers, pinned min/max) for 200 armed watches — confirms the private pool's own thread count, not the watch count, dominates; no per-handle thread cost.
- **`rearm_failures=0` throughout** — the re-arm-before-processing discipline (condition 4) holds under continuous stimulus; no dropped-window bug.
- **`wakeups/sec` tracks the stimulus rate** (4-5/sec against a 250ms touch interval ≈ 4/sec expected) — confirms events are actually being delivered and counted, not silently lost.
- RSS stable ~4.4-4.5MB, no growth over the run — no handle/memory leak from the re-arm cycle.
- Bug found and fixed during this run: the spike's reporter loop used buffered `fwprintf(stdout, ...)` with no flush — invisible when run detached/redirected (no console attached). Fixed with `setvbuf(stdout, nullptr, _IONBF, 0)` at start. Worth remembering for any future headless Windows spike/tool: buffered stdio is silent-by-default off a real console.

**Honest breakdown of the four #1907 conditions (NOT "all 4 confirmed" — the earlier framing overclaimed):**
- Condition 2 (pinned private pool, bounded min/max) — **demonstrated** (thread count flat at 6 = 2 always-on + ≤4 pinned pool workers regardless of 200 watches).
- Condition 4 (re-arm before processing) — **demonstrated** (`rearm_failures=0` under continuous stimulus; no dropped-window).
- Condition 1 (`REG_NOTIFY_THREAD_AGNOSTIC`) — **present in code and the watches worked**, but its *necessity* was NOT proven — the spike didn't run a control that *omits* the flag and shows breakage under TP thread recycling. Present-in-code, not necessity-proven.
- Condition 3 (separate private pool per trust domain — core vs plugin watchers never share threads) — **NOT tested**. The spike ran a SINGLE pool; there was no second pool and no plugin watcher to isolate. Deferred to Stage 1, where two pools actually exist.

**Decision: adopt TP_WAIT** as SparkEngine's event-handle wait-pool mechanism — the mechanism is sound (watches fire, pool bounded, no dropped notifications, no leak). Fallback (hand-rolled wait-pool) not needed. **But** this spike measured **throughput + footprint, not tail latency under burst** — and TP_WAIT was chosen specifically to underwrite the inline-tier µs-bounded enforce path (ADR §3), for which tail-latency-under-burst is THE load-bearing number. It ran ~4-5 wakeups/sec against a pool sized for 4 — utterly unsaturated. See §1b for the burst-latency probe that closes this gap.

## 1b. TP_WAIT burst latency — RESULT: µs median, but the tail is NOT µs-bounded — the "µs enforce" claim is median, not worst-case

`burst_latency_spike.exe`: N=200 `RegNotifyChangeKeyValue` watches on a pool pinned min=max=4, each callback busy-spinning 20µs to simulate inline enforce work, all keys written in a tight burst. Measures signal→callback-entry latency (QPC, captured at the very top of the callback, vs each key's own write timestamp). Three runs:

| run | fired | median | p90 | p99 | max |
|---|---|---|---|---|---|
| 1 | 200/200 | 18.5µs | 66.5µs | 639.7µs | **9996µs** |
| 2 | 200/200 | 16.6µs | 36.5µs | 122.4µs | 130.7µs |
| 3 | 200/200 | 15.7µs | 35.1µs | 161.8µs | 190.8µs |

**What this says:**
- **No notifications lost** (200/200 every run) — TP_WAIT delivers the whole burst. Good.
- **Median dispatch ~16µs** — genuinely microsecond-fast in the common case. Good.
- **The tail is heavy and variable: p99 = 120–640µs, and one run hit ~10ms max.** The ~9996µs ≈ one 10ms Windows scheduler quantum — a pool thread was descheduled and didn't wake for a full timer tick. This is inherent to a **bounded shared thread pool on a general-purpose (non-real-time) OS under contention** (the box was also running SSH + an existing agent), not a bug in TP_WAIT.

**Design consequence — the inline-tier "µs enforce" (ADR §3) must be read as MEDIAN, not a hard worst-case bound.** TP_WAIT gives µs *typical* dispatch and sub-ms *usual* tail, but a simultaneous-change storm plus OS scheduling produces occasional multi-hundred-µs to low-ms outliers for unlucky callbacks. Two forks Stage 1/2 must decide explicitly:
1. **If the enforce SLO is "median µs, tolerate rare ms"** — TP_WAIT as-is is fine; keep the shared bounded pool, and the resource win (O(mechanisms) threads) stands. This is almost certainly the right SLO for config-drift enforce (a 10ms-late registry write-back is operationally irrelevant).
2. **If any guard genuinely needs a HARD µs bound** — a shared pool on Windows cannot guarantee it; that guard's enforce would need a **dedicated thread at elevated/RT priority**, reintroducing O(rules) thread cost for the enforce-critical subset only. The ADR should not claim a hard µs bound it can't keep.

**Tuning levers noted for Stage 1** (not applied here): `timeBeginPeriod(1)` to tighten the scheduler quantum (shrinks the ~10ms outlier toward ~1ms), raising the pool threads' priority, and sizing the inline pool to the enforce-critical guard count rather than a fixed 4. These narrow the tail but do not make it hard-bounded.

**Caveat on the measurement:** the burst isn't perfectly simultaneous — 200 `RegSetValueExW` calls are serialized by one thread (~µs each), so signals spread over the write-loop window; each latency is measured from that key's own write, so this is fair but represents a dense storm, not an instantaneous one. Real fleet bursts are likelier dense-storm than instantaneous, so this is representative. Re-measure on the quiet UAT rig at Stage 1/11 (this box had background load) and with the real enforce handler's actual per-callback cost substituted for the 20µs spin.

## 2a. `WTSSendMessageW` reachability — RESULT: works, but answers the wrong question

`session0_spike.exe`, run as `dgrhp\daver` (SSH exec session, non-interactive) targeting the real active console session (session 1, `daver`, `WTSActive`):

```
[session0_spike] session 0 name=Services state=WTSDisconnected
[session0_spike] session 1 name=Console state=WTSActive
[session0_spike] WTSSendMessageW to session 1 OK, response=1
[session0_spike] done
```

`response=1` is `IDOK` — the message reached the interactive session and was dismissed (not a timeout). **Confirms cross-session delivery works** for at least this identity/session pairing. Caveat unchanged from the file's header: `WTSSendMessageW` only renders standard `MB_*` button sets, so this mechanism still can't deliver the driving use case's 3 custom buttons — kept as a fallback-path option only (plain OK/dismiss notifications), never the primary Stage 10 mechanism.

## 2b. `CreateProcessAsUser` helper (the actual Stage 10 decision point) — RESULT: works in principle, blocked by a privilege this account doesn't hold — and that's informative, not a bug

`session0_helper_spike.exe`, same identity (`dgrhp\daver`):

```
[session0_helper_spike] starting
[session0_helper_spike] AdjustTokenPrivileges(SeTcbPrivilege) did not fully succeed, gle=1300
[session0_helper_spike] AdjustTokenPrivileges(SeAssignPrimaryTokenPrivilege) did not fully succeed, gle=1300
[session0_helper_spike] active console session=1
[session0_helper_spike] WTSQueryUserToken FAILED, gle=1314 (ERROR_PRIVILEGE_NOT_HELD)
```

Failed exactly where the file header predicted: `daver` (an interactive admin user, not a service) doesn't hold `SeTcbPrivilege`, so `WTSQueryUserToken` correctly refuses. This is **not a bug in the mechanism** — it's the OS enforcing exactly the boundary the spike was designed to probe.

### Cross-cutting finding: this interacts with issue #1442

`docs/agent-privilege-model.md` (Correction, 2026-07-03): the shipped Windows agent service **currently registers and runs as LocalSystem**, not the intended least-privilege virtual service account `NT SERVICE\YuzuAgent` — tracked as open issue **#1442**. LocalSystem inherently holds `SeTcbPrivilege`, so **today**, the agent's actual runtime identity would pass the `WTSQueryUserToken` check this spike just failed under `daver`. But **once #1442 lands** (moving the agent to `NT SERVICE\YuzuAgent`), the agent will very likely lose `SeTcbPrivilege` — virtual service accounts don't hold it by default — and this exact `ERROR_PRIVILEGE_NOT_HELD` failure would reproduce in production.

**This is a real design conflict between Stage 10 (interactive Reflex UI) and #1442 (least-privilege hardening) that didn't exist as a documented risk before this spike.** Three ways to resolve it, for whoever picks up Stage 10 to choose among (not decided here):

1. **Grant `SeTcbPrivilege` to `NT SERVICE\YuzuAgent` explicitly** via GPO/Local Security Policy (`secpol.msc` → User Rights Assignment → "Act as part of the operating system"), mirroring the existing documented pattern for `rdp_control.set_state`'s Administrators-membership grant in the same privilege-model doc. Keeps the mechanism as designed; adds one more out-of-band grant to the install/hardening runbook, and is a comparatively broad privilege to request (Act-as-part-of-OS is one of the most powerful rights on Windows — worth security-guardian scrutiny before choosing this option).
2. **Use Task Scheduler instead of `CreateProcessAsUser` directly** — a scheduled task with `/RU` set to the interactive user and the "run only when user is logged on" (interactive) flag lets the Task Scheduler service (which already runs as SYSTEM) perform the cross-session hop, so the agent process itself never needs `SeTcbPrivilege`. Shifts the privileged operation to an OS-owned service instead of granting the agent a new broad right.
3. **A persistent per-session helper process** (launched once at logon via a scheduled task/Run-key, not per-Reaction) that stays resident and receives Reaction requests from the main service over a local IPC channel (named pipe). Avoids repeated privileged cross-session launches entirely; costs a small always-on per-user process footprint, similar to how several commercial EDR/agent products handle user-session UI today.

Whichever path Stage 10 picks, it must be re-validated against **the account #1442 actually lands on**, not against LocalSystem — the passing case observed today would be a false positive for the shipped least-privilege target.

### RESOLUTION (decided 2026-07-06): per-user companion helper process — option 3

Stage 10 will use a **per-user companion helper process** (option 3 above), NOT the service-side `CreateProcessAsUser` path the `session0_helper_spike` prototyped. A small Yuzu user-session GUI helper runs as the logged-on user (no elevation, no `SeTcbPrivilege`), spawned by a logon-triggered scheduled task registered at MSI-install time — Task Scheduler (SYSTEM) performs the privileged session-launch, so the agent process itself never calls `WTSQueryUserToken`/`CreateProcessAsUser` and never needs `SeTcbPrivilege`. Service ↔ helper communicate over a secured local IPC channel (named pipe or localhost gRPC).

**This dissolves the #1442 conflict rather than working around it:** the agent needs no new privilege, so it's fully compatible with #1442 landing the agent on the least-privilege `NT SERVICE\YuzuAgent` account. The `session0_helper_spike` `ERROR_PRIVILEGE_NOT_HELD` result stands as the evidence that ruled OUT the service-side path — not a blocker to fix, but the reason the architecture went the other way.

**Why this option over 1/2:** option 1 (grant `SeTcbPrivilege`) was rejected — it re-opens a session-impersonation privilege hole that partially defeats #1442's purpose. Options 2 and 3 both put the privileged launch in Task Scheduler; option 3's *persistent* helper was chosen over option 2's *per-Reaction* task launch because it's the only shape that scales to the planned **pop-up sentiment-survey** capability (a resident user-session GUI process can host rich forms / WebView2 HTML surveys; a `MessageBox` or per-prompt task launch cannot), and it matches the industry-standard endpoint-agent split of a privileged session-0 service plus a per-user-session UI helper process. The current in-process `MessageBoxW(nullptr,…)` in `interaction_plugin.cpp:293` is already non-functional under a real session-0 service (invisible dialog) and the helper replaces it; `WTSSendMessageW` is retained only as a lightweight no-helper-present fallback for plain OK/dismiss.

**Residual Stage-10 design work (shifted from privilege to correctness):** (1) IPC security both directions — helper verifies the server end is the service (server-process token/SID check, not just pipe name); service verifies the client is a helper in the intended user's session (impersonate + token/session check). (2) Session lifecycle — logon/logoff, fast-user-switch, multiple simultaneous RDS sessions, no-user-logged-on (queue/drop; aligns with ADR-0021 workstation-vs-server device classification — server-class Reflexes proceed-on-exhaustion without an interactive user). Toast notifications are a complementary lightweight surface layered on the helper, not a replacement (activation callbacks still run in-session).

## 3. Companion-helper spike (the CHOSEN Stage 10 mechanism) — RESULT: works end-to-end, with two findings

The `session0_helper_spike` above only validated the *rejected* service-side path (its failure half). The chosen mechanism — a logon-triggered scheduled task launching a per-user helper that talks to the SYSTEM service over an authenticated named pipe — had zero spike coverage until this one. `service_spike.exe` (run as SYSTEM via a scheduled task, matching the agent's identity) + `helper_spike.exe` (run as the interactive user via a scheduled task with an **Interactive** principal), round-tripping a simulated consent request/response over `\\.\pipe\yuzu_spike_ipc`.

**Confirmed working (the load-bearing proof):**

```
[service] start; own session=0 user=NT AUTHORITY\SYSTEM
[service] helper connected
[service] client pid=7940 session=1
[service] recv: HELLO helper_ready session=1
[service] client AUTHENTICATED as user=DGRHP\daver
[service] sent REQUEST
[service] recv: RESPONSE choice=Snooze
[helper] start; own session=1 user=DGRHP\daver activeConsoleSession=1
[helper] connected to service pipe
[helper] server pipe OWNER = NT AUTHORITY\SYSTEM
[helper] recv: REQUEST show_consent id=42 text=DiskFull buttons=Snooze;ClearSelf;ClearAuto
[helper] sent RESPONSE choice=Snooze
```

- **The Interactive-principal scheduled task lands the helper in the user's interactive session as the user** — `own session=1` == `activeConsoleSession=1`, `user=DGRHP\daver`. **No `SeTcbPrivilege`, no `CreateProcessAsUser` from the service.** This is the whole point: Task Scheduler (SYSTEM) does the session placement, so the mechanism is fully compatible with the agent running as the least-privilege `NT SERVICE\YuzuAgent` (#1442) — it dissolves the conflict rather than working around it.
- **Cross-session named pipe** (SYSTEM session 0 ↔ user session 1) connects and round-trips bidirectionally.
- **Server-verifies-client:** client session (`session=1`) via `GetNamedPipeClientProcessId`; full client user (`DGRHP\daver`) via `ImpersonateNamedPipeClient` — the mechanism real IPC auth is built on.
- **Client-verifies-server:** the pipe's OWNER SID reads back as `NT AUTHORITY\SYSTEM` via `GetSecurityInfo` — the robust check. (`OpenProcess` on the SYSTEM server from the user's filtered token is denied with gle=5, as predicted; the owner-SID path is why that denial doesn't matter.)

**Finding 1 — `ImpersonateNamedPipeClient` has an ordering requirement.** The first run failed with `gle=1368` (`ERROR_CANNOT_IMPERSONATE`) because the server called it *before* reading from the pipe. The documented (and here empirically confirmed) fix: the server must `ReadFile` at least once before impersonating. Trivial, but the design doc had treated "impersonate + check the user" as a one-liner — it isn't, and the real IPC handler must read-then-impersonate. Client *session* id (via `GetNamedPipeClientProcessId`) is available with no read; only full-token impersonation needs the prior read.

**Finding 2 — impersonation depends on the server holding `SeImpersonatePrivilege`, which re-introduces the "validate against the #1442 account" caveat here too.** The spike's server ran as SYSTEM (has the privilege). `NT SERVICE\YuzuAgent` *also* holds `SeImpersonatePrivilege` by default (service logon grants it), so this should keep working post-#1442 — but "should" is exactly what tripped us on the `CreateProcessAsUser` path, so the `ImpersonateNamedPipeClient` call must be **re-verified against the actual `NT SERVICE\YuzuAgent` account once #1442 lands**, not assumed from the SYSTEM run.

**What this spike deliberately did NOT prove (carried into Stage 10 as known-open, not silently assumed):**
1. **The logon-event firing itself.** The helper was triggered on-demand (`Start-ScheduledTask`), a faithful proxy for session placement + identity (both follow the Interactive principal's token, not the trigger kind) but NOT a test that the task actually fires at real user logon. Stage 10 must verify the `AtLogOn` trigger on a genuine logon.
2. **Multi-session targeting.** Only one interactive session existed. When >1 user is logged on (RDS, fast-user-switch), the service must decide *which* session a given Reaction targets and route to the right helper instance — unspecified and untested.
3. **Pipe SD restriction.** The spike used a NULL DACL (any user may connect) and *identified* the peer; a production build must additionally *restrict* the pipe's DACL so only the intended helper/service can connect. Identification (proven) is the input to restriction (not built here).
4. **No-user-present queue/drop**, and **the real UI** (custom dialog / WebView2 survey) — the helper simulated the choice rather than rendering anything.

**Net:** the chosen mechanism is validated in its load-bearing respect (no-privilege cross-session launch + authenticated round-trip) — Stage 0 now de-risks the path we're actually taking, not just the one we rejected. The four items above are genuine Stage-10 design work, now explicit.

## Cleanup note

Both crash/registry side effects were cleaned up after the runs: `HKCU\Software\YuzuSpike` deleted (tpwait_spike's own `RegDeleteTreeW` cleanup didn't run because the process was force-killed after the timed sampling window, not because of a bug); no other persistent state left on DGRHP by these spikes. `C:\yuzu-spike-test\` (the 3 spike binaries/sources + helper scripts) is left in place on DGRHP for future reference — not part of any repo checkout, does not need cleanup unless the box is reclaimed for other use.
