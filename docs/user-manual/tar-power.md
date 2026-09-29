# TAR power source (`power`)

The `power` cursor-model source records two kinds of transitions on every managed
endpoint: **sleep/wake** (the device suspended, woke, or briefly woke into
DarkWake) and **AC-source changes** (the device was plugged into or unplugged
from mains power). See [`tar.md`](tar.md) for the rest of what TAR captures;
this page covers `power` specifically because its collection model — a
replayed OS log on macOS, a live-only subscription on Windows and Linux — is
different enough from every other TAR source to need its own explanation.

## It ships default-on

Every other opt-in TAR source (`software`, `ARP`, `DNS`, `mapdrive`, `netconn`)
defaults to **off** because it is either high-volume, behaviorally sensitive,
or both. `power` is the deliberate exception: sleep/wake and AC-source events are
low-volume and directly useful for baseline device-health and
battery/charging-posture investigations from day one. `power` (and its
sibling `removable`) therefore ship **enabled by default** — set
`power_enabled=false` to opt out on a host where this is not wanted.

Default-on is **not** a finding that these events are privacy-neutral. The
*timing* of sleep/wake and AC transitions is a presence and working-hours
proxy, exactly as connectivity history is, so the same works-council posture
as `netconn` applies in full. Under the Wave 6 ruling
(`docs/tar-implementer.md`) that posture attaches to the **lookback control**
rather than to the enable flag: set `power_lookback_seconds=0` for
forward-only collection on a host where a retrospective read of the OS's
retained power log is not lawful. Because the obligation now lands at
*upgrade* rather than at an operator's opt-in, it is a stronger duty to
disclose, not a weaker one.

## Collection model differs by OS — read this before comparing hosts

Unlike every snapshot-diff TAR source (services, ARP, mapped drives, ...),
`power` is a **cursor-model** source: it does not poll-and-diff a current
state, it tracks a position in an append-only OS-logged stream of past
transitions. That stream exists in a fundamentally different shape on each
platform:

| Platform | Mechanism | Retrospective read | Live/forward capture |
|---|---|---|---|
| **macOS** | `pmset -g log` (polled, parsed, replayed via an exact-tail cursor) | Yes — honours `power_lookback_seconds` on first enable | Yes |
| **Windows** | `PowerRegisterSuspendResumeNotification` + `PowerSettingRegisterNotification` (live callbacks only) | **No — no OS history API exists** | Yes, from the moment the source starts |
| **Linux** | sleep/wake: systemd-logind `PrepareForSleep` sd-bus signal (live only), **and only where the agent was built with libsystemd** — a build without it, or a host where logind is unreachable, cannot capture sleep or wake at all. The source says so rather than staying quiet: it writes a single standing `capture_gap` naming the unarmed window, so an empty result is never mistaken for "nothing happened". AC attach/detach is unaffected — it is a polled `/sys/class/power_supply` read each tick | **No history for sleep/wake.** AC state has no "history" concept — it is read fresh every tick | Yes |

**This means a host's own history is only as deep as its platform allows.**
macOS is the only platform where enabling `power` on a machine that has been
running for weeks can backfill that machine's past sleep/wake and AC history
(bounded by `power_lookback_seconds`). On Windows and Linux, enabling `power`
starts recording from that moment forward only — there is no OS-side log to
read backward through, so pretending otherwise would be dishonest. Any window
during which the source was disabled, or the agent was not running, is
reported as an explicit `capture_gap` event on the next successful tick (with
a `detail` describing the window) rather than silently vanishing from the
timeline — this applies on every platform, including macOS's own log-wrap
case (see below).

### Why macOS reads a log instead of subscribing live

macOS *does* have a live power-notification API (IOKit's
`IORegisterForSystemPower`), and a Windows-shaped live-only implementation
was considered. It was rejected in favour of `pmset -g log` specifically so
macOS's `power_lookback_seconds` retrospective backfill is possible at all —
without a log to read, macOS would degrade to the exact same "no history,
forward only" posture as Windows and Linux, which is a real capability loss
on the platform that happens to have the option not to. The log is read
through the bounded subprocess runner (never `popen`) with a hard deadline
and output cap, exactly like every other TAR subprocess call site — see
`docs/agent-spawn-sink-manifest.md`'s `tar/power_pmset#1` row for the full
acquisition-ladder review.

### The exact-tail cursor (macOS) — why a timestamp alone is not enough

A naive "skip every log line with a timestamp at or before the last one we
saw" replay model is provably wrong: a live capture on this project's own
development host produced two **distinct** `pmset` assertion-summary lines in
the *same second*, differing only in which process assertions were active at
that instant. A timestamp-only cursor cannot tell "this line was already
recorded" from "a second, genuinely new line arrived in the same second" —
it would silently drop the second line forever. The macOS cursor instead
identifies its own position by `(timestamp, a CRC32 of the exact log line,
which occurrence of that line within its timestamp second)`, locates that
exact line in each fresh read of the log, and replays everything strictly
after it — same-second lines included, each getting its own distinct,
replay-stable event. If the log has wrapped or rotated far enough that the
cursor's own line can no longer be found (macOS's `pmset` log is a bounded
buffer, not unbounded storage), the source reports a `capture_gap`, records
the gap, and re-baselines forward at the log's current end — it never
replays the whole log from the beginning to "catch up", which would flood
the timeline with events that already happened.

### AC transitions are edge-triggered, not status reports

Every platform's underlying signal for AC state (macOS's `Using AC`/`Using
Batt` summary lines, Windows' `GUID_ACDC_POWER_SOURCE` setting, Linux's
`/sys/class/power_supply` read) is a **current-state reading**, not an
edge notification. `power` only ever records `ac_attached`/`ac_detached`
when a reading genuinely differs from the last one it saw — a reading that
matches the already-known state produces nothing, and the very first reading
after enablement seeds the known state silently (never fires a spurious
first transition).

## Configuration

| Key | Values | Default | Description |
|---|---|---|---|
| `power_enabled` | `true` / `false` | **`true`** | Toggle the `power` source. **On by default** — see "It ships default-on" above. |
| `power_lookback_seconds` | integer seconds | **`604800`** (7 days) | macOS only: how far before enablement the first `pmset -g log` read backfills sleep/wake/AC history. Set to **`0`** to disable the retrospective read entirely (forward-only from enablement, matching Windows'/Linux's own unavoidable posture). Clamped to `[0, 90 days]`. Windows and Linux ignore this key — there is no history to bound. |

## Data captured

One row per transition in the `$Power_Live` warehouse table: `ts`, `action`
(`sleep`, `wake`, `ac_attached`, `ac_detached`, or `capture_gap`), and
`detail` (a free-form reason string — the pmset log's own reason text on
macOS, or a description of what happened on Windows/Linux/for a
`capture_gap`). No process, user, or location information is ever attached
to a power event.
