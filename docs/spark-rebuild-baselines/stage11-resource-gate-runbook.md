# Stage 11 resource-gate runbook

Committed 2026-08-18 (F11, #2298; D1 ruling 2026-08-05: port-lite). Companion to
`stage0-resource-baseline.md` (protocol + premise validation) and the 2026-07-13 grill
settlement (memory `project-spark-rung2-plan.md`). That baseline doc scoped the metrics
and flagged that no harness existed; this doc + the two files alongside it
(`resource_sampler.cpp`, `generate_resgate_load.py`) are that harness. Previously a
local-only spike (same posture as `tpwait_spike.cpp`); committed now per D1 so the
sampler and load generator survive as tracked measurement artifacts rather than
re-invented next time they're needed.

**Status as of this writing: harness built, committed, and used for F11's flood
measurement (its errored-load mode, below). The ORIGINAL resource-gate load (`arm` /
`teardown`, Known/compliant targets, legacy-vs-spark A/B) is still NOT run as the real
gate.** The real legacy-vs-spark capture needs the flip's `--spark-disable` flag so both
configurations run from the *same* binary, toggled - see "Why not now" below. Everything
here is ready to fire the moment the flip lands.

## Two load profiles

`generate_resgate_load.py` now has two independent, separately-prefixed profiles (see
its module docstring for the full rationale):

- **`arm` / `teardown`** (prefix `resgate-`) - the ORIGINAL resource-gate load: 20
  registry + 20 file + 20 service guards, all Known/compliant. This is what "Why not
  now" below still applies to.
- **`arm-errored` / `teardown-errored`** (prefix `resgate-err-`) - F11's flood-
  measurement load: 20 registry + 20 file guards (no service variant - a nonexistent
  service reads Known-Stopped, not Unknown, per `guardian_state_reader.cpp`) whose
  targets exist but are unreadable by the agent's service account, so every evaluation
  reads Unknown and drives the errored-refresh (F5 6b) / priority-lane-demotion (F5 6c)
  paths. This profile needs spark ACTIVE (see "Activating spark for the errored-load
  run" below) - it exercises a path that is entirely dormant in a stock binary.

## Why not now (the ORIGINAL resource-gate load only)

Rung 1 (`feat/spark-rung1-observe-v2`) instantiates SparkEngine
*alongside* the legacy Guardian engine, observing - it does not replace it.
Sampling an agent built from rung 1 measures **legacy-enforcing +
spark-observing running at once**, not spark in isolation. That's not a
partial answer, it's the wrong question: any number you get is contaminated
and cannot be subtracted apart cleanly (they share OS threads/handles you
can't attribute back to one engine vs the other from outside the process).

The clean A/B needs the flip's `--spark-disable`: one binary selects legacy XOR
spark, same rig, same session, back-to-back - exactly the protocol in
`stage0-resource-baseline.md`.

## What's ready now

- `resource_sampler.cpp` - external, PID-targeted, zero-Yuzu-dependency
  sampler. Thread count / handle count / RSS / CPU% / wakeups-per-sec
  (context-switches/sec via PDH, matched by PID - the Windows analogue of the
  Linux `voluntary_ctxt_switches`+`nonvoluntary_ctxt_switches` proxy the
  baseline doc names). Full methodology notes in its header comment.
- `generate_resgate_load.py` - arms either fixed load against a running rig via the
  real REST surface, and tears it down again.

Windows-only, not meson-wired (see the sampler's header comment) - rebuild with the
one-line `cl.exe` command in Step 1.

## Step 1 - build the sampler (DGRHP)

Check the rig isn't mid-verify first (`tasklist | grep -iE 'cl.exe|msbuild|ninja'`
over SSH).

```bash
scp docs/spark-rebuild-baselines/resource_sampler.cpp dgrhp:C:/yuzu-devrig1/
ssh dgrhp "C:\\msys64\\usr\\bin\\bash.exe -lc \"source /c/yuzu-devrig1/setup_msvc_env.sh && export MSYS2_ARG_CONV_EXCL='*' && cd /c/yuzu-devrig1 && cl.exe /EHsc /std:c++20 /W4 resource_sampler.cpp Advapi32.lib Psapi.lib Pdh.lib /Fe:resource_sampler.exe\""
```

`resource_sampler.exe` needs an **elevated (Administrator)** console to open
a process it doesn't own - the agent runs as a service account
(`docs/agent-privilege-model.md`), not as `daver`. It self-enables
`SeDebugPrivilege`; that still requires the token to already be an admin
token.

## Step 2 - build + start the agent under test

**Original resource-gate load (legacy-vs-spark A/B):** any `dev`/`main` build for legacy;
spark isolation still needs the flip's `--spark-disable` - not available yet.

**Errored-load flood measurement (F11):** spark must be ACTIVE, which no shipped build
does (`prefer_spark` hardcoded false at `agent.cpp`'s 2-arg construction site). Build
from a **rig-side-only, never-committed** one-argument patch adding `/*prefer_spark=*/
true` as the 3rd constructor argument at that call site - diff must be quoted in the
F11 run doc's provenance section and reviewed out of any PR before push. Confirm spark
is actually armed via the agent log (the "spark path WIRED" line at boot) and the
`yuzu.guardian_backend` heartbeat tag before trusting any sample or count.

Point the agent at a real reachable server, or consistently at none - per
`stage0-resource-baseline.md`'s gotcha, a gRPC reconnect backoff loop adds
wakeup noise if connectivity differs between runs. For the errored-load run,
the server must be reachable and its ingested heartbeat tags readable (the
refresh/demotion/suppression counters are observed server-side too).

## Step 3 - arm the load

**Original profile:**
```bash
export YUZU_ADMIN_PASS='<rig admin password>'
python docs/spark-rebuild-baselines/generate_resgate_load.py arm
```

Creates `C:\YuzuResGate\watch-01.txt`..`watch-20.txt`, 20 `HKCU\SOFTWARE\YuzuResGate\Key01..20`
registry guards, and 20 service-status watches against real, already-running
Windows services (Spooler, Themes, BITS, ...) - read-only, nothing is
started/stopped. Creates + deploys a `resgate-baseline` Baseline covering all 60
rules and pushes `full_sync` (governance Gate 4, 2026-08-18: an earlier version of
this script - and this line - assumed a bare `full_sync` was enough; it is not,
since `guardian_push_fn_` only delivers rules that are members of a *deployed*
Baseline, and this profile had the same gap `arm-errored` was found and fixed for).

**Errored profile (F11) - deny-ACL setup FIRST, as Administrator, before `arm-errored`:**

```powershell
# File targets: create + deny read to Everyone (denies the service account too)
New-Item -ItemType Directory -Force -Path C:\YuzuResGateDenied | Out-Null
1..20 | ForEach-Object {
    $p = "C:\YuzuResGateDenied\watch-{0:D2}.txt" -f $_
    New-Item -ItemType File -Force -Path $p | Out-Null
    icacls $p /deny "Everyone:(R)"
    icacls $p /deny "SYSTEM:(R)"
}

# Registry targets: create key + deny read (inherited to the value)
New-Item -Path "HKLM:\SOFTWARE\YuzuResGateDenied" -Force | Out-Null
1..20 | ForEach-Object {
    $k = "HKLM:\SOFTWARE\YuzuResGateDenied\Key{0:D2}" -f $_
    New-Item -Path $k -Force | Out-Null
    New-ItemProperty -Path $k -Name Flag -Value 1 -PropertyType DWord -Force | Out-Null
    $acl = Get-Acl $k
    $deny = New-Object System.Security.AccessControl.RegistryAccessRule(
        "Everyone", "ReadKey", "ContainerInherit", "None", "Deny")
    $acl.AddAccessRule($deny)
    Set-Acl -Path $k -AclObject $acl
}
```

**Verify the deny actually took, as the agent's own account** (interactive-admin can
often still read past a deny via other privileges - proves nothing):

```powershell
# Adjust for however the DGRHP rig's agent service account is named/invoked.
psexec -s cmd /c "type C:\YuzuResGateDenied\watch-01.txt" # expect Access is denied.
psexec -s cmd /c "reg query HKLM\SOFTWARE\YuzuResGateDenied\Key01 /v Flag" # expect ERROR
```

Only once both confirm denial:

```bash
python docs/spark-rebuild-baselines/generate_resgate_load.py arm-errored
```

Confirm arming: `tasklist`/handle count should visibly move once armed vs
before - if it doesn't, the guards didn't actually take (check the agent log
for "did not start" warnings per-guard before trusting a sample).

**Pre-register expected counts before sampling** (production defaults: `errored_refresh_ms`
= 300 000 ms, `pending_demote_sweeps` = 12 @ 5 s priority-lane cadence = demotion at
t=60 s, then registry's 60 s type-lane cadence): over a 30-minute (1800 s) window, each
registry rule should show 1 edge + 5 refreshes at t=300/600/900/1200/1500s, plus a 6th
refresh if the sample captures the inclusive t=1800s boundary itself (refreshes recur
every 300 s once past the errored_refresh_ms floor, first landing at t=300 s from the
edge - don't treat a 6th refresh at the exact window edge as suspicious), `priority_demoted`
should read 1 per rule once past t=60 s. File rules follow the same demotion timing (the
priority lane is type-agnostic) but land on the 600 s file cadence afterward, subject to
the scheduler's default +/-20% jitter (spacing anywhere from 480s-720s, never below
300s so still refreshing on every sweep) - expect 1 edge + 2-3 refreshes in the same
window (2 at exact 600s cadence, up to 3 under jitter; see the F11 run doc's corrected
Claims section for the full-day worst-case derivation, 180/day not 144/day).

## Step 4 - sample

```bash
# find the agent PID first (tasklist /FI "IMAGENAME eq yuzu-agent.exe")
resource_sampler.exe <pid> 1800 5 f11-errored-run.csv
```

1800 s (30 min) duration, 5 s interval. First 2 samples dropped as warm-up. Label the
capture explicitly as a **sanity/pipeline check, not the resource gate** - the A/B
against legacy stays blocked on the flip.

## Step 5 - teardown

```bash
python docs/spark-rebuild-baselines/generate_resgate_load.py teardown
python docs/spark-rebuild-baselines/generate_resgate_load.py teardown-errored
```

Deletes the rules + pushes `full_sync`. Does **not** remove
`C:\YuzuResGate\` / `C:\YuzuResGateDenied\` or the registry keys under either
`HKCU\SOFTWARE\YuzuResGate` or `HKLM\SOFTWARE\YuzuResGateDenied` - harmless leftovers,
clean up by hand (`Remove-Item -Recurse`, `Remove-Item -Path HKLM:\...\YuzuResGateDenied
-Recurse`) if the rig needs to be pristine for something else. Also revert the rig-side
`prefer_spark` patch from Step 2 - it must never reach a commit.

## Result table - original profile, paste into the flip PR as gate evidence

**`cpu_pct` convention (restated here, not just in the .cpp header, since this table
is where the raw CSV numbers actually get pasted, governance Gate 6/sre finding):**
100% = one full core busy, unbounded above that (ps/top's per-process convention,
NOT normalized by core count) - 250% means two and a half cores' worth of CPU time.

| Metric | Legacy (`--spark-disable`) | Spark | Delta |
|---|---|---|---|
| Threads (steady-state) | | | |
| Handles (steady-state) | | | |
| RSS bytes (steady-state) | | | |
| Idle CPU% (steady-state, ps/top convention - see above) | | | |
| Wakeups/sec (steady-state) | | | |

Report the Guardian-attributable delta separately from anything
TriggerEngine-attributable if both moved - `stage0-resource-baseline.md`
already found TriggerEngine is O(mechanisms) on the old code too, so it
shouldn't move much; if it does, that's worth flagging as a surprise, not
folding into the headline number.

Related: `project-spark-rung2-plan.md`, `project-dgrhp-windows-rig.md`,
`project-spark-tpwait-spike.md`, `f11-flood-measurement-run.md` (this doc's F11
companion - the flood-measurement result).
