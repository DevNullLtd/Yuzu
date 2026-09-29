# Windows Firewall Block-vs-Allow Precedence — #3284

## Status: VERIFIED LIVE — BOTH PROPOSITIONS MEASURED

`scripts/test/win-quarantine-precedence-probe.ps1` was executed against
the-rig (a Windows 11 Pro test host, build 26200) on 2026-08-21. The probe
applied the exact rule set `win_quarantine` builds today, measured
reachability on a physical path from the box itself, tore the rules down,
and verified zero residue.

Two scenarios were measured, because the redesign does not rest on the same
proposition the original defect does:

- **Scenario A, `LegacyBlockRules`** — the shape the plugin shipped. Answers
  *does a Block RULE beat an Allow RULE*. **It does**, so the
  `AllowIn_<ip>`/`AllowOut_<ip>` rules layered over
  `BlockAllInbound`/`BlockAllOutbound` are inert and a quarantined host loses
  its management channel.
- **Scenario B, `ProfileDefaultBlock`** — the redesign. Answers the *different*
  question the redesign depends on: *does an Allow RULE beat a PROFILE-DEFAULT
  block*. **It does**, so the redesign preserves the whitelist and loopback
  while still containing everything else.

Scenario B exists because shipping the redesign on scenario A alone would have
been a category error: A justifies abandoning the named Block rules but says
nothing about what replaces them. Documented Windows behaviour said the
replacement was safe — and documented behaviour is precisely what produced this
defect, so it was measured rather than assumed.

## Purpose

win_quarantine (`agents/plugins/quarantine/src/quarantine_plugin.cpp`) used to apply
`YuzuQuarantine_BlockAllInbound`/`BlockAllOutbound` and then layer narrower
`AllowIn_<ip>`/`AllowOut_<ip>` rules for whitelisted addresses — that is Scenario A above,
the shape that shipped. Whether a later, narrower Allow rule actually overrides an earlier,
broader Block rule at the same (default) priority is a live Windows Firewall behaviour
question, not something inferable from the netsh invocations alone. #3284 asks for ground
truth on a real box before any redesign is considered. This doc is that ground truth — and
Scenario B is the redesign that shipped as a result: win_quarantine no longer creates named
Block rules at all, containing via the profile-default policy instead (see `## Status` above),
so the question this doc actually answers today is whether an Allow rule overrides a
PROFILE-DEFAULT block, not a named Block rule.

## The safety harness

The script defaults to `-DryRun` (never writes a Block rule) and gates the
destructive `-Execute` path behind two independent scheduled-task watchdogs
(+5m primary, +15m backstop, SYSTEM principal) that must each be **observed
removing a real firewall rule** — not merely registered as `Ready` — before
anything that blocks traffic runs. Both watchdogs passed their proving runs
on this host before any Block rule was applied, and are re-armed with fresh
triggers immediately before the destructive step. `-Execute` relaunches
itself through a one-shot SYSTEM scheduled task so it survives the loss of
the driving session — which does occur, since blocking all outbound severs
the very link used to start it. Full design, exit codes and manual-recovery
commands are in the script's header comment.

## Method

The load-bearing measurement is taken against an address reachable over a
**physical** NIC — here the host's default gateway, whitelisted by the rule
set and confirmed reachable immediately before the rules were applied. This
matters: Windows Firewall filters the transport actually on the wire, so a
whitelisted overlay (Tailscale, CGNAT 100.64.0.0/10) address proves nothing
about precedence — a failed connection there is fully explained by the
tunnel's own transport being blocked. Overlay reachability is recorded as
informational only and never feeds the verdict.

## Results table — scenario A (`LegacyBlockRules`, the original defect)

Measured on-box, after the rule set was applied, 2026-08-21.

| Measurement | Result | Notes |
|---|---|---|
| Whitelisted physical-path target, BEFORE rules (baseline) | **reachable** | gateway `:53`, proves the target and port are live |
| Whitelisted physical-path target, AFTER rules | **NOT reachable** | the Allow rule did not survive the Block rule |
| Non-whitelisted control | not reachable | expected; confirms the Block rules took effect |
| Loopback `127.0.0.1:22` | reachable | loopback is unaffected |
| Drop-log entries naming the whitelisted flow | 0 | see caveat below |
| Watchdog proving run (primary, +5m) | PASS | observed removing a real rule |
| Watchdog proving run (backstop, +15m) | PASS | observed removing a real rule |
| Teardown residue check | PASS | no rules, no tasks, profile defaults restored |

The baseline/after pair on the *same* address and port is what carries the
verdict: the only variable between them is the rule set.

Caveat on the drop log: zero entries naming the whitelisted flow is not
counter-evidence. Drop logging was enabled at run time and the connection
attempt may be dropped before a logged decision, or logged without the
remote address in a form this grep matched. The reachability transition is
the load-bearing observation; the drop log was a corroborating signal that
did not corroborate either way.

## Results table — scenario B (`ProfileDefaultBlock`, the shipped shape)

Same host, same target, same port, 2026-08-21. Containment is the profile
default policy (`blockinbound,blockoutbound`); no named Block rule exists.

| Measurement | Result | Notes |
|---|---|---|
| Whitelisted physical-path target, BEFORE rules (baseline) | **reachable** | gateway `:53` |
| Whitelisted physical-path target, AFTER rules | **reachable** | the Allow rule outranks the profile default |
| Non-whitelisted control | not reachable | containment still holds |
| Loopback | reachable | |
| Watchdog proving runs (primary + backstop) | PASS | each observed removing a real rule |
| Teardown residue check | PASS | profile defaults restored verbatim |

The two scenarios differ in exactly one variable — the rule shape. Scenario A
cuts the whitelisted target off; scenario B keeps it reachable.

An incidental corroboration: the driving SSH session over a physical NIC
survived scenario B intact, while scenario A severed it for roughly two
minutes. Consistent with the measured result, but not offered as evidence — it
rides the same transport question the method section warns about.

## Verdict

**Scenario A — BLOCK OVERRIDES ALLOW = TRUE.** A whitelisted address that was
reachable seconds earlier became unreachable the moment `win_quarantine`'s rule
set went live, while loopback stayed up and the non-whitelisted control behaved
as expected.

**Scenario B — ALLOW RULE OVERRIDES PROFILE-DEFAULT BLOCK = TRUE.** With the
named Block rules gone and containment coming from the profile default, the
same whitelisted address stayed reachable while the non-whitelisted control was
cut off. The redesign's premise holds on real hardware.

The operational consequence is the one #3284 predicted: a quarantined
Windows host loses the management channel quarantine is specifically
designed to preserve, so it cannot receive its own `unquarantine`. That is
the same failure class as the macOS incident in commit 672896112 — a
containment action that strands the host it contains — reached by a
different mechanism.

This also means the plugin's whitelist parameter is currently misleading on
Windows: it is accepted, rules are created for it, `rules_applied` counts
them, and none of it has any effect on reachability.

## Reproducing

On an elevated session on the target host:

```
powershell -NoProfile -ExecutionPolicy Bypass -File scripts/test/win-quarantine-precedence-probe.ps1 -DryRun -Scenario ProfileDefaultBlock
powershell -NoProfile -ExecutionPolicy Bypass -File scripts/test/win-quarantine-precedence-probe.ps1 -Execute -Scenario ProfileDefaultBlock
```

`-Scenario LegacyBlockRules` (the default) reproduces the original defect;
`-Scenario ProfileDefaultBlock` exercises the shipped shape. The session must
be ELEVATED — a non-elevated run aborts before it writes a transcript, which
looks identical to nothing having happened.

`-DryRun` must be clean (both watchdogs proven, zero residue) before
`-Execute`. Do not run `-Execute` against a host you cannot physically
reach: it deliberately severs the network, and the watchdogs — not the
driving session — are what bring it back. Expect the session to drop for
roughly the hold interval.
