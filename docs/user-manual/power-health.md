# Power Health

The `power_health` plugin reports battery, thermal, and power-plan state,
and can switch the active Windows power scheme.

## Actions

| Action | Class | Windows | macOS | Linux |
|---|---|---|---|---|
| `battery` | ReadOnly | SUPPORTED — `GetSystemPowerStatus` + `CallNtPowerInformation(SystemBatteryState)` | SUPPORTED — `IOPSCopyPowerSourcesInfo`/`IOPSCopyPowerSourcesList` | CONSTRAINED — `/sys/class/power_supply` |
| `thermal` | ReadOnly | CONSTRAINED — PDH `\Thermal Zone Information(*)\Temperature` | CONSTRAINED — `NSProcessInfo.thermalState` + `IOPMGetThermalWarningLevel` | CONSTRAINED — `/sys/class/thermal` |
| `power_plan` | ReadOnly | SUPPORTED — PowrProf (`PowerEnumerate`/`PowerReadFriendlyName`/`PowerGetActiveScheme`) | UNSUPPORTED — no named power schemes | PLANNED — `platform_profile` |
| `set_power_plan` | **Destructive** (Reversible) | SUPPORTED — PowrProf `PowerSetActiveScheme` | UNSUPPORTED | PLANNED |

No leg uses WMI, `powercfg`, any subprocess, or COM/`CoInitialize*` — every
Windows leg is a direct native API call (ADR-3002 rung 1).

## `battery`

One row per power source:

```
battery|<present>|<state>|<percent>|<time_to_empty_min>|<cycle_count>|<health_percent>
```

`state` is one of `charging`, `discharging`, `full`, `not_charging`,
`ac_no_battery`, `unknown`. **`not_charging` is a reported state, not a failed
read**: a present battery on AC that is neither charging nor discharging and
below 100% — the firmware is holding at a charge stop threshold (commonly
80-95%) to preserve cell life, which is the ordinary state of a docked laptop.
`unknown` means the opposite — the OS declined to answer, or the read failed. `percent`/`time_to_empty_min`/`cycle_count`/`health_percent` are
`-1` when the platform's mechanism has no honest source for that field —
never a fabricated value.

On a Windows desktop with no system battery, `GetSystemPowerStatus` reports
`BatteryFlag=128`, which this plugin honestly maps to
`present=false, state=ac_no_battery` (measured live, not inferred). The
battery-PRESENT path on Windows **has since been verified on real hardware**
(HP ZBook Firefly, PR #4009 review) — see "Hardware checks" below for what that
run found and the criteria it now passes. macOS battery-PRESENT remains
fixture-only.

## `thermal`

```
thermal|<status>|<detail_or_zone>[|<celsius>]
```

`status` is `ok`, `constrained`, or `unavailable`. On Windows and Linux, zero
live thermal-zone instances is the **measured normal case on desktop
hardware** and produces the explicit success line
`thermal|constrained|no_thermal_zones_exposed` — never an error, never a
fabricated zero-degree reading. That line is a POSITIVE claim that the host
exposes no thermal sensors, so it is kept distinct from every way the read
itself can fail: `pdh_open_failed`, `pdh_add_counter_failed`,
`pdh_collect_failed`, `pdh_collect_timed_out`, `pdh_collect_rejected` and
`pdh_fetch_failed` all report `unavailable` instead. An empty result means the
sensors are absent; it never means we failed to look. On macOS, `status` is always `ok` and
`detail` carries `NSProcessInfo.thermalState`'s 4-level enum
(`nominal`/`fair`/`serious`/`critical`), never a temperature; a "no thermal
warning ever recorded" result from `IOPMGetThermalWarningLevel`
(`kIOReturnNotFound`) is the healthy default, not an error.

## `power_plan` / `set_power_plan`

`power_plan` enumerates schemes:

```
power_plan|<guid>|<friendly_name>|<active 0/1/->|<status>
```

A `guid` of `-` (status != `ok`) means no scheme rows were produced at all
(bounded-call timeout, an incomplete PowerEnumerate sweep, or the
platform doesn't support named schemes); `active` of `-` means every
scheme WAS enumerated but the active-scheme read itself failed
(`status=active_unknown`) — never fabricated as 0.

`set_power_plan` is this plugin's **only mutating action**. It takes one
required parameter, `scheme` — a GUID, or a friendly name that must match
**exactly one** live scheme (case-insensitive). Its failure semantics are
fully specified:

1. Zero or more than one name match → typed error, no mutation.
2. An incomplete PowerEnumerate sweep (an ordinary mid-list error, not
   `ERROR_NO_MORE_ITEMS`) → typed error, no mutation — never resolved
   against a partial list that might be hiding a duplicate name.
3. Reading the active scheme fails (before any mutation) → typed error, no
   mutation.
4. `PowerSetActiveScheme` fails **or times out** → typed error, and the
   outcome is **NOT** "no mutation". The call is made through a bounded
   wait, so a timeout means it did not report back in time — not that it
   did not happen. The status text says so in as many words ("the mutation
   was NOT confirmed and, on a timeout, may still have been applied — final
   state is unknown") and `previous_guid` is reported so the scheme can be
   reverted. **Go and check the machine.** Claiming no mutation here is the
   one wording that would stop an operator doing that, which is why the
   code refuses to.
5. The post-set read-back fails or does not match the target scheme after
   `PowerSetActiveScheme` already reported success → typed error naming
   both GUIDs (mismatch case) or `previous_guid` alone (read-back-failed
   case). **The mutation may already be applied at this point** — final
   state is reported as unknown, never claimed unchanged; `previous_guid`
   lets the caller verify/revert manually.
6. Success emits `previous_guid` and `new_guid`.

Every failure branch pairs a non-zero exit code with a typed status — never
one without the other. `set_power_plan` is gated Destructive/Reversible,
`PowerManagement` securable, Administrator-only by default, requiring
Admin-or-approval at execution (`ExecuteGate::AdminOrApproval`). The gate
covers REST `/api/command`, MCP `execute_instruction`, and the dashboard
exec console with no further wiring. `ScheduleRunner` deliberately keeps its
own approval-gated scope/broadcast fan-out rather than this gate, so an
**approved fleet-wide scheduled `set_power_plan` is permitted** under the
platform's normal schedule-approval posture.

macOS and Linux never mutate: macOS has no named power schemes
(`IOPMSetPMPreferences` is a private SPI and is not adopted here), and Linux
`power_plan` support is PLANNED (`platform_profile`) but not implemented in
this package.

## Hardware checks

The battery-PRESENT path on Windows was built and fixture-tested against an
injected boundary, and has **since been verified on real battery hardware** —
an HP ZBook Firefly, during PR #4009's review. That run earned its keep: it
found the plugin reporting `battery|1|unknown|99|-1|-1|-1` for a battery
resting on AC at a firmware charge threshold, i.e. the "could not read it"
sentinel for a reading the OS had supplied in full. That state is now
`not_charging` and has a parser fixture on each branch that reaches it.

**macOS battery-PRESENT is still fixture-only** — the run host was a desktop,
and the same class of defect could be hiding there.

To repeat the check on a Windows laptop, or to close the macOS gap:

1. Get an API token (`docs/user-manual/authentication.md`) and run this
   exact command against your agent's server, targeting only that one
   agent (replace `<server>`, `<token>`, and `<agent-id>` —
   `GET /api/agents` lists connected agent IDs):

   ```bash
   curl -s -X POST http://<server>:8080/api/command \
     -H "Authorization: Bearer <token>" \
     -H "Content-Type: application/json" \
     -d '{"plugin":"power_health","action":"battery","agent_ids":["<agent-id>"]}'
   ```

   Then fetch the result rows with the `execution_id` the above returns
   (`GET /api/v1/executions/{id}`, documented alongside `POST /api/command`
   in `docs/user-manual/instructions.md`), or run the same `battery` action
   from the dashboard's exec console instead and read the rows directly.
   Paste the raw `battery|...` output rows here.
2. **Expected output shape**: one line per power source,
   `battery|<present>|<state>|<percent>|<time_to_empty_min>|<cycle_count>|<health_percent>`.
3. **Pass criteria** (ALL must hold — the no-battery `SKIP` below must be
   ABSENT):
   - At least one row shows `present=1`.
   - That row's `state` is `charging`, `discharging`, `full`, or
     `not_charging` — **never** `unknown`. A plugged-in laptop resting at a
     firmware charge threshold reports `not_charging`, and that is a PASS: it
     is a state the OS reported, not a failure to read one.
   - That row's `percent` is between `0` and `100` — **never** the `-1`
     unknown sentinel.
   - If on battery power, `time_to_empty_min` is a plausible positive
     number, not `-1`.
4. Confirm the automated test suite's explicit no-battery `SKIP`
   (`test_power_health_local_dispatcher.cpp`, "no system battery on this
   host — battery-present leg not exercised") does **NOT** appear when you
   run the tests on your laptop — its absence is the signal that the real
   battery-present leg executed and was asserted, not skipped.

### Second check, if you have a MacBook

The same gap exists on macOS and for the same reason: the run host was a Mac
mini (`hw.model` = Mac16,10), which has no battery, so the macOS
battery-PRESENT path is fixture-tested too. It is a separate ask from the
Windows one above — neither covers the other.

Run the same `battery` dispatch against a macOS agent on a MacBook and apply
the identical pass criteria (`present=1`; `state` never `unknown`, with
`not_charging` an accepted answer; `percent`
in `0`-`100`, never `-1`; the no-battery `SKIP` absent from the suite run).

Worth knowing while you check: this leg reads `IOPSCopyPowerSourcesInfo`
rather than the `AppleSmartBattery` IORegistry node **on purpose**. That node
is present, matched and active even on the battery-less Mac mini, so a leg
built on it would have reported a phantom battery on every desktop Mac. If a
future change "simplifies" this to an `ioreg` read, that is a regression.

The battery-PRESENT path is described as verified on **Windows** only — the
HP ZBook Firefly run above. On **macOS** it is not described as verified
anywhere in this plugin's docs, changelog, or capability declaration, and must
not be until a capture lands: the Windows run found a state no fixture had
thought to cover, so the macOS leg's fixtures are not evidence that its
classification is complete either.
