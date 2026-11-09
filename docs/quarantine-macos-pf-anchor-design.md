# macOS device containment through a pf sub-anchor

Status: design note for PRQ.1 (the `firewall` plugin's `quarantine`, `release`,
`quarantine_status` and `quarantine_allow` on macOS). **The macOS leg is not coded
yet.** It is built only after this note passes a security-guardian review; until
then the four actions answer one typed `refused|unsupported_platform` row on
macOS and the descriptor says `planned`. The OS-neutral pieces the leg will use
(the anchor ruleset text, the pfctl argv builders, the token and boot-time state
model, the pfctl output parsers) are already written and unit-tested in
`agents/plugins/firewall/src/firewall_quarantine_parsers.hpp`.

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

### 2.1 One sub-anchor, loaded with `-a ... -f` only

All containment rules live in the sub-anchor `com.apple/yuzu_quarantine`:

```
pfctl -a com.apple/yuzu_quarantine -f <TempFile>
```

macOS ships `/etc/pf.conf` with Apple's own wildcard anchor reference
(`anchor "com.apple/*"` and the matching `scrub-anchor`, `nat-anchor`,
`rdr-anchor`, `dummynet-anchor` lines). pf evaluates every sub-anchor that
exists under that wildcard, so an anchor Apple's file does not name explicitly
is still evaluated once it is loaded. The roadmap row proposed a flat
`yuzu-quarantine` anchor plus one atomic main-ruleset load that adds an explicit
`anchor "yuzu-quarantine"` line. Using the wildcard that is already there removes
that load: nothing in the main ruleset changes, so there is no moment at which
the system rules are replaced, and `release` cannot "restore" anything because
nothing was taken. This is the correction to the roadmap's framing.

A hard rule for the coder: **never run a bare `pfctl -f`, never write
`/etc/pf.conf`, never `pfctl -d`.** The sudoers lines below do not grant them.

### 2.2 The anchor ruleset

Built by `pf_anchor_ruleset()` from the allow set; every rule is `quick`:

```
pass quick on lo0 all no state
pass out quick inet proto tcp from any to <control-ip> port <control-port> flags any keep state
pass in  quick inet proto tcp from <control-ip> port <control-port> to any flags any keep state
pass out quick inet proto udp from any port 68 to any port 67 keep state
pass in  quick inet proto udp from any port 67 to any port 68 keep state
pass out quick inet proto udp from any to <resolver> port 53 keep state
pass out quick inet proto tcp from any to <resolver> port 53 keep state
pass quick inet6 proto icmp6 icmp6-type { 133, 134, 135, 136, 137 } no state
<operator exceptions, each direction and protocol as given>
block drop quick all
```

- **`pass quick on lo0 all no state` first.** Loopback never depends on a state
  entry, so there is no loopback state to die: the incident class is designed
  out rather than papered over with `set skip`, which is a main-ruleset
  directive and so is unavailable to an anchor.
- **Control-channel rules carry `flags any keep state`**, in both directions.
  `flags any` lets a rule match (and create state for) a packet in the middle of
  a TCP stream, which is what an in-flight gRPC stream looks like after the state
  flush in 2.3. The inbound half exists because the first post-flush packet can
  be the server's, not the agent's.
- **`block drop quick all` last** so no rule that happens to sort after the
  anchor in the main ruleset can override the containment.
- Every address, port and protocol is built from a parsed, typed value and then
  re-checked against a strict charset; see section 6.

### 2.3 Killing pre-existing state

pf passes a packet that matches a state entry **without evaluating any rule**
(pf.conf(5)). Loading the anchor alone therefore leaves every connection that was
established before the quarantine untouched: a prohibited stream an attacker
already has open would keep working. After the anchor load the leg runs:

```
pfctl -F states
```

Consequences, stated plainly:

- Prohibited streams die (their next packet matches no state and then `block drop
  quick all`).
- Loopback survives (stateless, 2.2).
- The agent's control channel reconnects without a dropped command: its next
  packet, in either direction, matches a `flags any keep state` rule and creates a
  new state.
- **Every other application's pf state on the host is dropped once per apply and
  once per allow-set update.** Most clients reconnect transparently; long-lived
  flows that cannot (some VPN control channels, SSH sessions not covered by an
  operator exception) are cut. That is the point of a quarantine, but it is a
  property the operator should know.

### 2.4 The enable token (`pfctl -E` / `-X`)

pf on macOS is reference-counted: `pfctl -E` enables it and prints a token on
stderr (`Token : 3665316113424588829`); `pfctl -X <token>` releases that
reference and the packet filter is disabled when the last reference goes.

- The leg runs `pfctl -E` **only when no token is stored for this boot**. The
  token and `sysctl -n kern.boottime` are written together into the quarantine
  record (`os.pf_token`, `os.boot_time`) **before** the leg does anything else
  that depends on pf being on.
- Same boot, token stored: reuse it; a second `-E` would take a second reference
  we would then have to track.
- Different boot: the kernel's reference count reset at reboot, so the stored
  token is meaningless. Take a fresh `-E` and overwrite the record.
  (`pf_should_enable()` is the pure decision.)
- `release` is `pfctl -a com.apple/yuzu_quarantine -F all` then
  `pfctl -X <token>`. With no token stored the `-X` is skipped and the result
  carries `note|pf_left_enabled_no_token`: we never disable a packet filter we
  did not enable, because another holder (the Application Firewall, a customer
  tool) may need it.
- `pfctl -s References` lists the live references. Status reports the count
  (`note|pf_references=<n>`), and `release` uses it to confirm our token is gone.
  The exact column layout of that output is **unverified** on a live host (open
  question 3); `parse_pf_references()` keys only on a long decimal token at the
  start of a line.

**When another holder disabled pf.** `pfctl -d` disables the filter regardless of
tokens. Status reads `pfctl -s info`; `Status: Disabled` with a stored token is
`degraded|pf_disabled`, never `active`. The boot-time re-apply (section 4)
re-enables with a fresh `-E`.

### 2.5 Dangling-anchor detection

The anchor does nothing unless the main ruleset references it. Status runs
`pfctl -s rules` and looks for `anchor "com.apple/*"` (or the explicit anchor
name):

- present: the reference is live;
- absent: **dangling**, reported as `degraded|anchor_not_referenced`.

**A macOS update that rewrites `/etc/pf.conf`** reinstalls Apple's own file,
which keeps the wildcard anchor, so the reference survives updates. A customer who
replaced `/etc/pf.conf` with a ruleset that has no `anchor "com.apple/*"` line has
a dangling anchor. Two defences: status reports it on every call, and the
verify-after-apply probe fails in that case (the blocked target stays reachable),
which on an **initial apply** rolls the leg back with
`rolled_back|probe_still_reachable` (or `anchor_not_referenced` when the reference
check itself runs first). The leg checks the reference before it declares success.

A related residual: a customer `/etc/pf.conf` with a **`pass quick` rule before
the anchor line** matches first and overrides the containment for what it
covers. Only the probe can catch that, and only if the probe target is among the
affected traffic; this is why the quarantine reports `active_unproven` rather than
`active` when no probe target was supplied.

### 2.6 True undo

Release is exactly two operations on objects the quarantine created: empty the
anchor, release our token. There is no snapshot of customer state because there
is nothing of the customer's to restore: their ruleset and their enable state
were never modified. After a release the expected state is byte-identical:
`pfctl -s rules`, `pfctl -s info` and the `-s References` count equal their
pre-quarantine values. That property is the leg's acceptance test (section 8) and
the basis for classing `firewall.quarantine` Reversible in the capability
catalogue, a change from the legacy row's Irreversible.

## 3. Coexistence with the legacy plugin

The retained `quarantine` plugin's pf path replaces the main ruleset with its own
(a block-all plus its whitelist, loaded by `pfctl -f`) and has **no unique marker**
in `pfctl -s rules` that a second plugin could test for. On Windows and Linux the
`firewall` actions refuse (`refused|legacy_quarantine_active`) when the legacy
plugin's own objects are present (rules named `YuzuQuarantine_*`; the iptables
chain `yuzu-quarantine`). On macOS that check is not possible, so the clash is a
**stated residual until the legacy plugin is deleted (PRQ.2)**:

- if the legacy plugin is quarantined first, the `firewall` leg's anchor loads but
  the main ruleset is the legacy one, which does not reference
  `com.apple/*`: status reports the anchor dangling;
- if `firewall` is quarantined first and the legacy plugin then quarantines, the
  legacy single-call load replaces the main ruleset and our anchor goes dangling
  the same way; the legacy `unquarantine` then reloads `/etc/pf.conf`, which makes
  the reference live again, and the next status or boot re-apply sees a healthy
  anchor.

Neither order strands the host (both end in a block-all), but the operator can
see two quarantines that disagree. PRQ.2 removes the legacy plugin.

## 4. Persistence across reboot

The leg uses the same record and recovery as the other two legs
(`quarantine.state`, phases `applying` / `active` / `releasing`). `init()` runs
after the KV store opens and before the agent registers: a record in `releasing`
is finished; a record in `applying` or `active` whose OS state is not enforcing
(after a reboot the kernel holds no anchor and no reference) is re-applied as a
generation update, with the token rule of 2.4 (a new boot always takes a fresh
`-E`). A re-apply never rolls back and never releases when the server is
unreachable.

## 5. Sudoers

The agent runs as an unprivileged account and shells out under `sudo -n --`. The
firewall plugin's macOS block in `scripts/install-agent-user.sh` grants exactly
the argv the leg uses, **beside** the existing bare `/sbin/pfctl` grant, which
stays until the legacy plugin is deleted:

```
/sbin/pfctl -E
/sbin/pfctl -X *
/sbin/pfctl -a com.apple/yuzu_quarantine -f *
/sbin/pfctl -a com.apple/yuzu_quarantine -F all
/sbin/pfctl -a com.apple/yuzu_quarantine -s rules
/sbin/pfctl -F states
/sbin/pfctl -s info
/sbin/pfctl -s rules
/sbin/pfctl -s References
```

**These lines narrow the argv shape. They do not confine pfctl.** A sudoers
argument glob matches the concatenated argument string, `-X *` and `-f *` accept
any text, and the file named by `-a ... -f` is generated by the agent, so what the
privileged process executes is agent-authored content. The control that actually
bounds the privileged call is the pure core: every token that reaches an argv or a
ruleset line is built from a typed, validated value and re-checked against a strict
charset (`is_safe_token`, `is_safe_ruleset_line`: no whitespace in a token, no
`;`, quote, `$`, backtick, `|`, `&`, `#`, backslash or newline anywhere), and the
only way into those functions is a server-dispatched, catalogue-gated action.
The same statement applies to the Linux `nft -f *` grant and is repeated in
`docs/agent-privilege-model.md`. Anyone who gains arbitrary code execution as the
agent account can already author any ruleset these grants will load; that is an
accepted property of the grant, not a reason to widen it.

For the Linux leg, sized in the same pass: the unused bare `/usr/sbin/nft` grant
is replaced by `nft -f *`, `nft delete table inet yuzu_quarantine` and
`nft list table inet yuzu_quarantine` (the status fallback when the netlink dump
is refused for lack of `CAP_NET_ADMIN`). The iptables and ip6tables grants are
unchanged.

## 6. Why the leg is allowed to rely on the pure core

Everything the macOS leg will do is a sequence of calls through an injected runner
and stager, driven by the same drivers the Linux legs use and tested the same
way: a fake runner that stops after every call, a fake clock for the 60 second
operation deadline, an in-memory record. The pf-specific behaviour (token reuse by
boot time, the ruleset text, the pfctl argv, the output parsers, the order
`load -> flush states -> verify`) is pure and already covered. What no unit test can
cover is how pf itself behaves; that is section 8.

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

The leg is coded only after a security-guardian pass and after the following are
settled on a **disposable macOS VM** (or braga through the detached survivor
pattern with `ttl_seconds=90`, accepting a 90 second session blackout). `pfctl -F
states` drops every pf state on the capture host, once per apply.

Open questions the review should rule on:

1. Does a sub-anchor created under `com.apple/` with `pfctl -a ... -f` get
   evaluated through Apple's wildcard on every supported macOS release, with `pf`
   enabled by `-E` and no other change? (This is the premise of 2.1.)
2. Does a `quick` match inside the anchor end evaluation for the whole ruleset, as
   2.2 assumes?
3. What is the exact output of `pfctl -s References`, and does it list only
   `-E` tokens? (`parse_pf_references` is deliberately tolerant.)
4. Is `pfctl -F states` plus `flags any keep state` enough for the live gRPC stream
   to survive without a reconnect, or does it reconnect? (Either is acceptable;
   which one it is changes only a log line.)
5. Which holders besides the Application Firewall take `-E` references on a
   managed Mac, and does any of them run `pfctl -d`?

Reproduction plan (the leg's acceptance test):

1. Record `pfctl -s rules`, `pfctl -s info` and `pfctl -s References` (the
   pre-state) and note the count.
2. Open a long-lived TCP stream to a reachable test target and confirm traffic
   flows (the **pre-established prohibited stream**).
3. Run the incident's survivor test (`scripts/test/instructions_quarantine_
   survivor.py`): isolate, confirm the agent's reply reaches the server, confirm
   loopback TCP is unaffected across 60 seconds (the incident died at 29).
4. Confirm the pre-established stream from step 2 **stops carrying data** after the
   apply, and that a fresh connection to the test target times out while the
   control channel still connects.
5. Reboot. Confirm the quarantine is re-applied at agent start before the agent
   registers, and that a fresh `-E` token was taken (the stored boot time differs).
6. `quarantine_allow add` then `remove` an exception; confirm each is one anchor
   reload plus one state flush and the main ruleset is untouched
   (`pfctl -s rules` unchanged).
7. Release. Confirm `pfctl -s rules`, `pfctl -s info` and the `-s References` count
   equal the pre-state byte for byte.
8. Forced rollback: point `agent.server_address` and `agent.server_address_resolved`
   at a TEST-NET address; confirm `rolled_back|control_unreachable` and the same
   byte-identical post-state.
9. Dangling anchor: load a main ruleset without `anchor "com.apple/*"` on the
   disposable host, quarantine, and confirm either `anchor_not_referenced` or
   `probe_still_reachable`, never `active`.

If the security-guardian review fails, or any of questions 1 or 2 is answered the
wrong way, the leg stops here and returns to the programme owner for a different
mechanism.
