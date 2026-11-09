# macOS device containment through a pf sub-anchor

Status: design note for PRQ.1 (the `firewall` plugin's `quarantine`, `release`,
`quarantine_status` and `quarantine_allow` on macOS). **The leg is built** in
`agents/plugins/firewall/src/firewall_quarantine_parsers.hpp` (`PfLeg` and the
pure pf pieces, unit-tested on every host) and wired in `firewall_plugin.cpp`.
The security-guardian review of the first draft of this note returned
PASS-WITH-CONDITIONS (two HIGH, six MEDIUM, three LOW findings); every condition
is met or restated as a residual below, and section 9 maps each finding to where.
What no unit test can show is how pf itself behaves: section 8 lists what the
live capture on a disposable macOS VM must still answer. Until that capture is in
the PR body the descriptors say `constrained` for `quarantine` and
`quarantine_allow`.

Related: `docs/quarantine-windows-firewall-precedence.md` (the Windows rule this
design mirrors in spirit: default-block, never a Block rule over an Allow),
`docs/agent-privilege-model.md`, issue #2272 (durable pf-anchor quarantine).

## 1. The fault this design starts from

Commit `672896112` (2026-05-06, "fix(quarantine): macOS - set skip on lo0 +
single-call ruleset load") records a live UAT regression in the legacy
`quarantine` plugin:

1. The plugin ran **two** reloads: `pfctl -a yuzu-quarantine -f <tmp>`, then
   `echo 'anchor "yuzu-quarantine"' | pfctl -f -`.
2. The second reload **replaced the whole main ruleset** with only the anchor
   reference, evicting the system rules macOS loads from `/etc/pf.conf`
   (including whatever the OS relied on for loopback).
3. Loopback state then died 29 seconds later. The gateway-to-server TCP stream
   on `localhost` timed out, the agent's reply to the quarantine command never
   reached the server, and the box stayed firewalled until an operator flushed
   pf by hand.

The failure was main-ruleset replacement plus loopback state, not anchors as
such. The fix that shipped is one atomic `pfctl -f` of a main ruleset that starts
with `set skip on lo0`, and `unquarantine` reloads `/etc/pf.conf`. That fix has a
cost the catalogue records: release restores the OS default, not what the
customer had, so any runtime pf rules the endpoint carried before the quarantine
are lost, and the action is classed Irreversible.

This design removes the cause instead of containing it. **The main ruleset is
never loaded, not even once.**

## 2. Mechanism

### 2.1 One sub-anchor, loaded with `-a ... -f` only, named to sort first

All containment rules live in the sub-anchor `com.apple/000.yuzu_quarantine`:

```
pfctl -a com.apple/000.yuzu_quarantine -f <staged file>
```

macOS ships `/etc/pf.conf` with Apple's own wildcard anchor references
(`anchor "com.apple/*"` and the matching `scrub-anchor`, `nat-anchor`,
`rdr-anchor`, `dummynet-anchor` lines). pf evaluates the sub-anchors directly
attached to `com.apple`, **in name order**, and a `quick` rule inside any of them
is final: it ends the evaluation of the other anchors and of the main ruleset.
Using the wildcard that is already there means nothing in the main ruleset
changes, so there is no moment at which the system rules are replaced, and
`release` cannot "restore" anything because nothing was taken. This is the
correction to the roadmap's flat `yuzu-quarantine` anchor plus an explicit
`anchor` line added by a main-ruleset load.

**Name order matters.** `/etc/pf.anchors/com.apple` attaches `200.AirDrop` and
`250.ApplicationFirewall`, and system services and customer tools insert anchors
dynamically. Digits sort before letters, so a first draft named
`yuzu_quarantine` would have been evaluated *after* those, and any
`pass ... quick` in them would have won. The anchor is therefore
`com.apple/000.yuzu_quarantine` and the leg checks, rather than assumes, that it
leads:

- `quarantine_status` runs `pfctl -a com.apple -s Anchors`; a sibling that sorts
  before ours reads `degraded|anchor_not_first`, never `active`.
- an apply that finds such a sibling still loads (the anchor is contained as far
  as it can be) but reports `partial` with `note|anchor_not_first=1`.
- a re-apply cannot fix a sibling, so `quarantine` on a degraded record answers
  `degraded` and does not flush every pf state again on each retry.

A hard rule for the coder: **never run a bare `pfctl -f`, never write
`/etc/pf.conf`, never `pfctl -d`.** The sudoers lines below do not grant them
(the bare grant that does is the retained plugin's, section 5).

### 2.2 The anchor ruleset

Built by `pf_anchor_ruleset()` from the allow set; every filter rule is `quick`:

```
no nat all
no rdr all
pass quick on lo0 all no state
pass out quick inet proto tcp from any to <control-ip> port <control-port> no state
pass in  quick inet proto tcp from <control-ip> port <control-port> to any no state
pass out quick inet proto udp from any port 68 to 255.255.255.255 port 67 keep state
pass in  quick inet proto udp from any port 67 to any port 68 keep state
pass out quick inet proto udp from any to <resolver> port 53 keep state
pass out quick inet proto tcp from any to <resolver> port 53 keep state
pass quick inet6 proto icmp6 icmp6-type { 133, 134, 135, 136 } no state
<operator exceptions, each direction and protocol as given, keep state>
block drop quick all
```

- **`no nat all` / `no rdr all` first.** The main ruleset has
  `nat-anchor "com.apple/*"` and `rdr-anchor "com.apple/*"`, translation rules are
  evaluated first-match, and a `nat pass` / `rdr pass` in another anchor (Internet
  Sharing, a port forward) would otherwise let packets through without filter
  evaluation. A `no` translation rule leaves the packet untranslated, the way
  `block drop quick` does for filtering. Translation rules must precede filter
  rules in a pf file (pfctl rejects the reverse order). The syntax of the whole
  generated ruleset was checked with `pfctl -n -f` on macOS 26.6.2 (parse only, no
  privilege, no load); that the kernel then applies it first-match against a
  sibling's `nat pass` is part of the live capture (open question 7).
- **`pass quick on lo0 all no state` first among the filter rules.** Loopback
  never depends on a state entry, so there is no loopback state to die: the
  incident class is designed out rather than papered over with `set skip`, which
  is a main-ruleset directive and so is unavailable to an anchor.
- **The control channel is stateless in both directions.** A state created from a
  mid-stream packet (`flags any keep state`) "may be missing connection details
  such as the TCP window scaling factor" (pf.conf(5)); macOS negotiates window
  scaling, so a state rebuilt after the flush in 2.3 can drop in-window segments
  of the live gRPC stream and the agent's reply would never reach the server.
  With `no state` the packets match a rule every time, there is no state for
  `-F states` to remove, and pf.conf(5) applies its default `flags S/SA` only to
  stateful rules, so no `flags` clause is needed or emitted.
- **DHCP leaves only toward the broadcast address.** macOS lets an unprivileged
  process bind below 1024, so `from any port 68 to any port 67` would be an exit
  to any host. Unicast lease renewal to the server is therefore not allowed; a
  client whose renewal gets no answer falls back to broadcast at rebinding, so the
  lease survives with a delay and no lease-file read is added. The reply direction
  (`from any port 67 to any port 68`) stays: it is inbound only and not an exit.
  This tightening is macOS-only because its premise is the macOS bind rule; the
  Windows leg's rule is recorded as a follow-up.
- **ICMPv6 neighbour discovery is types 133-136.** Redirect (137) is not needed for
  neighbour discovery and would let a router steer traffic; it is dropped on every
  leg.
- **`block drop quick all` last** so no rule that happens to sort after the anchor
  in the main ruleset can override the containment.
- Every address, port and protocol is built from a parsed, typed value and then
  re-checked against a strict charset; see section 5.

### 2.3 Killing pre-existing state

pf passes a packet that matches a state entry **without evaluating any rule**
(pf.conf(5)). Loading the anchor alone therefore leaves every connection that was
established before the quarantine untouched: a prohibited stream an attacker
already has open would keep working. After the anchor load the leg runs:

```
pfctl -F states
```

- A failure of that call is retried once and then **is a failed apply**
  (`state_flush_failed`): the prohibited streams are still alive, so the result is
  never `active`. An initial apply is rolled back (anchor emptied, enable
  reference released, record deleted). A failed `quarantine_allow` update reports
  `update_failed` and keeps the record; the anchor already holds the new
  generation (the load is atomic, the flush is not), which is a residual: an
  allowance that was *removed* may keep serving its old connections until they
  end.
- Prohibited streams die (their next packet matches no state and then
  `block drop quick all`). Loopback survives (stateless). The agent's control
  channel survives: it is stateless, so the flush has nothing of it to remove and
  the reply to the quarantine command travels on the gRPC stream that was already
  open, with no reconnect.
- **Every other application's pf state on the host is dropped once per apply and
  once per allow-set update, and the flush is one-way.** Release does not restore
  those connections. Most clients reconnect; long-lived flows that cannot (some VPN
  control channels, an SSH session not covered by an operator exception) are cut.
  A TCP exception rule is stateful with pf's default `flags S/SA`, so a stream it
  covers that was established before the flush resumes only after the peer opens a
  new connection.

### 2.4 The enable reference and the order of one apply

pf on macOS is reference-counted: `pfctl -E` enables it and prints a token on
stderr (`Token : 3665316113424588829`); `pfctl -X <token>` releases that
reference and the packet filter is disabled when the last reference goes.

The order of one apply (the leg, `PfLeg::apply`):

1. `pfctl -s info`: is pf on?
2. The enable reference, by `pf_enable_plan`:
   - **enable**: no token stored, or the stored token's boot time is not the
     current one (`kern.boottime`, read in-process): the kernel's count reset at
     reboot, so the old token means nothing. Take a fresh `-E`; the stale token is
     not released.
   - **reuse**: a token for this boot and pf is on. A second `-E` would take a
     second reference we would then have to track.
   - **repair**: a token for this boot but pf is **off**. Someone ran `pfctl -d`
     (it disables pf whatever the tokens), so the token is dead. Release it
     best-effort (whether `-d` clears the references on xnu is unverified, and a
     vanished token is expected), then take a fresh `-E`.
   After a `-E` the token and boot time are handed to the driver's `persist`
   callback **immediately**, before `-f` or `-F states`, and a failed write
   releases the reference again and fails the apply. The `applying` record already
   exists: the driver writes it before it calls the leg at all, so the order is
   *record, then `-E`, then token into the record*; the token cannot be recorded
   before it exists.
3. `pfctl -s rules`: the main ruleset must reference Apple's wildcard
   (section 2.5), else fail `anchor_not_referenced` before anything is loaded or
   flushed.
4. `pfctl -a com.apple -s Anchors`: sibling order (section 2.1).
5. `pfctl -a com.apple/000.yuzu_quarantine -f <staged file>`.
6. `pfctl -F states` (section 2.3).

A failure before step 5 gives back a reference taken in that call (`-X`), so a
failed apply leaves the reference count as it found it. After the anchor is loaded
the reference is kept, because releasing it would switch pf off under a loaded
anchor; an initial apply's rollback then empties the anchor and releases the
token, and a failed update's record carries the token so a later release can.

**Residual: a crash between `-E` and the token write** (the process dies in the
instant between pfctl printing the token and the record being written) leaks one
enable reference until reboot. The record still exists (`applying`), so the next
start converges, takes its own reference, and the host holds one extra; it is
visible as `note|pf_references=<n>` on `quarantine_status` and `release`, and it
only keeps pf enabled. It is tested (`pf: a crash between -E and the token write`).

`release` is `pfctl -a com.apple/000.yuzu_quarantine -F rules`, then `-F nat`, then
`pfctl -X <token>`. A token pf no longer knows (after a `pfctl -d`, say) fails to
release: that is `note|pf_token_release_failed=1`, not a failed release, and the
release succeeds once the anchor is empty. With no token on record the `-X` is
skipped and `note|pf_left_enabled_no_token=1` is added when pf is on: we never
disable a packet filter we did not enable, because another holder (the Application
Firewall, a customer tool) may need it.

Why not `-a <anchor> -F all`: pfctl scopes only rules, nat and tables by anchor;
`-F states`, `Sources`, `info` and `osfp` are global whatever `-a` says, so `-F
all` would cut every host connection a second time at release and zero the global
counters. Release touches only what the quarantine created.

`pfctl -s References` lists the live references (pfctl(8): "pid/name of enabler,
token, timestamp"). Status and release report the count
(`note|pf_references=<n>`). The column order is **unverified** on a live host
(open question 3); `parse_pf_references()` counts a line once when any field is a
15-24 digit decimal.

**When another holder disabled pf.** Status reads `pfctl -s info`; `Status:
Disabled` with our anchor loaded is `degraded|pf_disabled`, never `active`, with
`note|pf_token_dead=1` when a token is on record. `quarantine_status` stays
read-only; the repair runs in the mutating paths: the boot-time recovery
(`recover_at_init`) and the shared driver, where `quarantine` on an `active`
record whose leg reads *not enforcing* converges (re-applies the **stored** allow
set, `note|repaired=1`) instead of answering `already_active`. That driver rule
also closes the analogous Windows `degraded|policy_not_blocking` case.

### 2.5 Dangling-anchor detection

The anchor does nothing unless the main ruleset references it. The leg runs
`pfctl -s rules` and looks for the **whole line** `anchor "com.apple/*" all` (or the
explicit `anchor "com.apple/000.yuzu_quarantine" all`). A qualified form such as
`anchor "com.apple/*" on en0 all` covers one interface only and does not count, and
a reference is necessary, not sufficient: a `pass quick` rule before the anchor
line in a customer's `/etc/pf.conf` matches first and overrides the containment for
what it covers. Only the verify probe can catch that, and only if the probe target
is among the affected traffic, which is why the result is `active_unproven` rather
than `active` when no probe target was supplied.

- present: the reference is live;
- absent: **dangling**. An apply fails `anchor_not_referenced` (an initial apply is
  rolled back, with nothing loaded and no state flushed); status reports
  `degraded|anchor_not_referenced`.

Status reads the live `pfctl -s rules` on every call, so whatever rewrote
`/etc/pf.conf` (a customer's replacement, a tool) is detected at the next status or
boot-time recovery. This note does not claim what a macOS update does to the file.

### 2.6 What release undoes, and what it does not

Release is exactly two operations on objects the quarantine created: empty the
anchor (rules, then translation rules), release our enable token. There is no
snapshot of customer state because there is nothing of the customer's to restore:
their ruleset and their enable state were never modified. After a release the
following equal their pre-quarantine values, and that is the leg's acceptance test
(section 8): the main ruleset (`pfctl -s rules`), the `Status:` line of
`pfctl -s info`, and the `-s References` count. `pfctl -s info` as a whole is
**not** compared: it carries counters and uptime and is never byte-identical.

**Not undone: connections.** The state flush at apply time (2.3) is one-way, so
"Reversible" in the capability catalogue means *rules and enable state*, not every
connection the host had. That is a change from the legacy row's Irreversible (it
restored the OS default, not what the customer had) and the catalogue row says so.

### 2.7 Residuals, in one place

- DNS tunnelling through an allowed resolver is inherent to allowing DNS.
- The inbound half of DHCP (`from any port 67 to any port 68`) is not an exit but
  does admit unsolicited UDP to port 68.
- A crash between `-E` and the token write leaks one enable reference until reboot.
- A failed update after the anchor load leaves the new generation in the anchor and
  the previous one in the record.
- A sibling anchor inserted later that sorts before ours, or a `pass quick` before
  the anchor line in a customer's main ruleset, defeats containment; the first is
  detected by status, the second only by the probe.
- The reboot gap (section 4) and the legacy clash (section 3).
- Connections cut by the state flush are never restored.

## 3. Coexistence with the legacy plugin

The retained `quarantine` plugin's pf path replaces the main ruleset with its own
(a block-all plus its whitelist, loaded by `pfctl -f`) and has **no unique marker**
in `pfctl -s rules` that a second plugin could test for. On Windows and Linux the
`firewall` actions refuse (`refused|legacy_quarantine_active`) when the legacy
plugin's own objects are present (rules named `YuzuQuarantine_*`; the iptables
chain `yuzu-quarantine`). On macOS that check is not possible, so the clash is a
**stated residual until the legacy plugin is deleted (PRQ.2)**:

- if the legacy plugin is quarantined first, the `firewall` leg's anchor loads but
  the main ruleset is the legacy one, which does not reference `com.apple/*`: the
  apply fails `anchor_not_referenced` (nothing is loaded);
- if `firewall` is quarantined first and the legacy plugin then quarantines, the
  legacy single-call load replaces the main ruleset and our anchor goes dangling
  the same way; the legacy `unquarantine` then reloads `/etc/pf.conf`, which makes
  the reference live again, and the next status or boot re-apply sees a healthy
  anchor.

Neither order strands the host (both end in a block-all), but the operator can
see two quarantines that disagree. PRQ.2 removes the legacy plugin.

## 4. Persistence across reboot, and the gap before it

The leg uses the same record and recovery as the other two legs
(`quarantine.state`, phases `applying` / `active` / `releasing`). `init()` runs
after the KV store opens and before the agent registers: a record in `releasing`
is finished; a record in `applying` or `active` whose OS state is not enforcing
(after a reboot the kernel holds no anchor and no reference, and pf starts
disabled; or pf was switched off behind our back) is re-applied as a generation
update, with the token rule of 2.4 (a new boot always takes a fresh `-E`). A
re-apply never rolls back and never releases when the server is unreachable.

**Residual: the reboot gap.** Between boot and the agent's `init()` the host is
uncontained, and if the agent never starts it stays uncontained. Nothing in this
design persists containment at OS level; an Apple-owned launchd plist or a change
to `/etc/pf.conf` would reintroduce exactly the ownership of the main ruleset this
design avoids, and is not recommended. The same gap exists on the other legs and in
the legacy plugin. The catalogue row and the README say so.

## 5. Sudoers, staging, and what actually bounds the privileged call

The agent runs as an unprivileged account and shells out under `sudo -n --`. The
firewall plugin's macOS block in `scripts/install-agent-user.sh` grants exactly
the argv the leg uses, **beside** the existing bare `/sbin/pfctl` grant, which
stays until the legacy plugin is deleted:

```
/sbin/pfctl -E
/sbin/pfctl -X *
/sbin/pfctl -a com.apple/000.yuzu_quarantine -f *
/sbin/pfctl -a com.apple/000.yuzu_quarantine -F rules
/sbin/pfctl -a com.apple/000.yuzu_quarantine -F nat
/sbin/pfctl -a com.apple/000.yuzu_quarantine -s rules
/sbin/pfctl -a com.apple -s Anchors
/sbin/pfctl -F states
/sbin/pfctl -s info
/sbin/pfctl -s rules
/sbin/pfctl -s References
```

**These lines narrow the argv shape. They do not confine pfctl.** A sudoers
argument glob matches the concatenated argument string, `-X *` and `-f *` accept
any text, the bare grant beside them accepts anything, and the file named by
`-a ... -f` is generated by the agent, so what the privileged process executes is
agent-authored content. The control that actually bounds the privileged call is the
pure core: every token that reaches an argv or a ruleset line is built from a
typed, validated value and re-checked against a strict charset (`is_safe_token`,
`is_safe_ruleset_line`: no whitespace in a token, no `;`, quote, `$`, backtick,
`|`, `&`, `#`, backslash or newline anywhere; the pf token is digits only, 1-24),
and the only way into those functions is a server-dispatched, catalogue-gated
action. The same statement applies to the Linux `nft -f *` grant and is repeated in
`docs/agent-privilege-model.md`. Anyone who gains arbitrary code execution as the
agent account can already author any ruleset these grants will load; that is an
accepted property of the grant, not a reason to widen it.

**PRQ.2 obligation: remove the bare `/sbin/pfctl` grant** when the legacy plugin
is deleted. Until then the narrow lines above are cosmetic next to it, and the real
boundary is server dispatch plus the integrity of the agent process.

**Private staging.** The ruleset is written to `<agent.data_dir>/firewall-staging`,
a directory the agent creates mode 0700 and verifies (a real directory, owned by
the agent, no group or other access) before every use, in a file created with
`mkstemps` (`O_CREAT|O_EXCL`, mode 0600). It is never staged in the world-writable
system temp directory, where another local user could swap the content between the
write and the privileged read. When `agent.data_dir` is unset or the directory
cannot be made safe the apply is refused (`refused|staging_unavailable`) before
anything is touched. The Linux `nft -f` leg shares the same staging.

For the Linux leg, sized in the same pass: the unused bare `/usr/sbin/nft` grant
is replaced by `nft -f *`, `nft delete table inet yuzu_quarantine` and
`nft list table inet yuzu_quarantine` (the status fallback when the netlink dump
is refused for lack of `CAP_NET_ADMIN`). The iptables and ip6tables grants are
unchanged.

## 6. Why the leg is allowed to rely on the pure core

The pf leg (`PfLeg`) is an ordinary member of the pure core, like the nft and
iptables legs: a sequence of calls through an injected runner, an injected stager
and an injected boot-time reader, driven by the same drivers and tested the same
way against a fake pf world (the enable-reference table, the anchor, the main
ruleset's wildcard reference, sibling anchors, a state flush that can fail), a
fake clock for the 60 second operation deadline, an in-memory record, and a crash
simulated after every runner call. What no unit test can cover is how pf itself
behaves; that is section 8.

## 7. Preflight signals for the server cut-over (PRQ.2)

A quarantine whose allow set cannot reach the control channel strands the host.
The agent verifies after applying and rolls back on failure (so the agent is safe
on its own), but the server should warn before dispatching. Signals PRQ.2 should
read, recorded here because they size the contract:

- **Hostname-only server address.** The control endpoints are the addresses the
  agent resolved once at startup (`agent.server_address_resolved`). If it resolved
  to nothing, the control set is empty and the action is refused
  (`control_set_empty`); the server should not dispatch.
- **Proxy.** A channel through an HTTP/SOCKS proxy has the proxy as its real peer,
  not the server address the agent knows.
- **Full-tunnel VPN.** The control channel rides a tunnel interface whose far end
  is not an allowed address.
- **A re-addressed server.** ADR-2002 (lines 487-489) already records that a
  server that moves to a new address strands a quarantined agent, because an
  agent never auto-releases on lost contact. The optional TTL is the offline
  bound; break-glass is PRQ.2.

## 8. Open questions and the reproduction plan

The live capture is taken on a **disposable macOS VM**, never on a shared build
host: the apply flushes every pf state on the machine, and the live test
(`tests/unit/test_firewall_quarantine_live.cpp`, hidden, gated on
`YUZU_FIREWALL_QUARANTINE_LIVE=1`) switches pf off and on behind the plugin's back.
The narrative and the answers below go in the PR body; no probe source is
committed.

Verified on the development host (macOS 26.6.2, no privilege): `pfctl -n -f` parses
the generated anchor ruleset, `no nat all` and `no rdr all` included, and rejects a
translation rule that follows a filter rule. That is syntax only.

Open questions the capture answers:

1. Does a sub-anchor created under `com.apple/` with `pfctl -a ... -f` get
   evaluated through Apple's wildcard on every supported macOS release, with pf
   enabled by `-E` and no other change? (The premise of 2.1.)
2. Does a `quick` match inside the anchor end evaluation for the whole ruleset, as
   2.2 assumes?
3. What is the exact output of `pfctl -s References` (column order), does it list
   only `-E` tokens, and does `pfctl -d` clear the references? (The repair does not
   depend on the answer; `pf_references` reads and the live comparisons do.)
4. Does `pfctl -a <anchor> -F rules` exit zero for an anchor that does not exist?
   (The leg treats a failing flush as a clean release when pf is readable and the
   anchor holds no containment, so either answer is safe.)
5. Which holders besides the Application Firewall take `-E` references on a
   managed Mac, and does any of them run `pfctl -d`?
6. What does `pfctl -a com.apple -s Anchors` print: full paths or leaf names?
   (`pf_siblings_before` accepts both and ignores anything that is not one token.)
7. Does the kernel apply `no nat all` / `no rdr all` first-match against a sibling
   anchor's `nat pass` / `rdr pass`? If the live capture shows the load rejected,
   the fallback is the finding's other branch: drop the two lines and record the
   translation-`pass` bypass as a stated residual, tested the same way.

Reproduction plan (the leg's acceptance test):

1. Record the pre-state: `pfctl -s rules`, the `Status:` line of `pfctl -s info`
   and the `-s References` count.
2. Open a long-lived TCP stream to a reachable test target (the **pre-established
   prohibited stream**).
3. With the agent connected to a server on the VM, dispatch `firewall.quarantine`
   under the detached survivor pattern
   (`scripts/test/instructions-quarantine.sh`, whose ceremony confirms that the
   agent's reply reaches the server and that loopback TCP is unaffected across 60
   seconds, where the incident died at 29). That ceremony dispatches
   `security.quarantine.*` today, so for this leg the same steps are run against
   `firewall.quarantine` / `firewall.release`. What this step must assert is that
   **the reply arrives on the gRPC stream that was already open before the
   apply**: the server log shows no new Subscribe between the dispatch and the
   reply. That is the property `no state` provides across `pfctl -F states`. The
   live test's control-stream case checks the same at socket level.
4. Confirm the pre-established stream from step 2 **stops carrying data** after the
   apply, and that a fresh connection to the test target times out while the
   control channel still connects.
5. `pfctl -d` behind the plugin's back: `quarantine_status` reads
   `degraded|pf_disabled`; `quarantine` again reads `status|active` with
   `note|repaired=1` and a fresh token; the probe is blocked again.
6. Reboot. Confirm the quarantine is re-applied at agent start before the agent
   registers, that a fresh `-E` token was taken (the stored boot time differs) and
   that the stale token was not released.
7. `quarantine_allow add` then `remove` an exception; confirm each is one anchor
   reload plus one state flush and the main ruleset is untouched
   (`pfctl -s rules` unchanged).
8. Release. Confirm `pfctl -s rules`, the `Status:` line and the `-s References`
   count equal the pre-state, that the anchor is empty, and that no `-F states`,
   `-F all` or `-f` without `-a` ran. Connections cut in step 4 are not expected
   back.
9. Forced rollback: point `agent.server_address` and `agent.server_address_resolved`
   at a TEST-NET address; confirm `rolled_back|control_unreachable` and the same
   post-state as step 8.
10. Dangling anchor: load a main ruleset without `anchor "com.apple/*"` on the
    disposable host, quarantine, and confirm `rolled_back|apply_failed:
    anchor_not_referenced` with no state flush, never `active`.
11. Sibling order: load an anchor `com.apple/000.aaa` containing `pass quick all`,
    quarantine, and confirm `partial` with `note|anchor_not_first=1`, then
    `quarantine_status` reading `degraded|anchor_not_first`.

If any of questions 1 or 2 is answered the wrong way, the leg stops here and
returns to the programme owner for a different mechanism.

## 9. Security review record

The security-guardian review of the first draft: PASS-WITH-CONDITIONS. Where each
condition landed:

| Finding | Condition | Where |
|---|---|---|
| HIGH 1 | control channel stateless, both directions, no `flags any` | 2.2, `pf_anchor_ruleset`; live and survivor step 3 |
| HIGH 2 | anchor sorts first; sibling check in status | 2.1, `kPfAnchor`, `pf_siblings_before`, `read_status` |
| MEDIUM 3 | `no nat` / `no rdr` in the anchor | 2.2, open question 7 |
| MEDIUM 4 | Disabled with a stored token is repaired; `-X` failure tolerated | 2.4, `pf_enable_plan`, `apply_and_verify` repair |
| MEDIUM 5 | honest undo; compare rules, Status line, references; flush is one-way; no `-a -F all` | 2.3, 2.4, 2.6 |
| MEDIUM 6 | `-F states` failure is a failed apply; record before `-E`, leak as residual | 2.3, 2.4 |
| MEDIUM 7 | bare grant removal; private 0700 `O_EXCL` staging; digits-only token | 5 (bare grant: PRQ.2) |
| MEDIUM 8 | reboot gap stated | 4, catalogue row, README |
| LOW 9 | tighter DHCP and ICMPv6; DNS tunnelling residual | 2.2, 2.7 |
| LOW 10 | exact anchor-reference match; necessary, not sufficient | 2.5 |
| LOW 11 | no unverified claims; open questions stay open | 2.5, 8 |
