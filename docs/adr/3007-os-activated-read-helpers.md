---
status: proposed
date: 2026-11-22
owner: "@Doomgoose (Alex Young)"
deciders: >-
  @Doomgoose (author and product owner for this decision). Ratified by PR approval from the
  engineering colleagues under the dev-branch protection rule (at least one non-author
  approval).
effective: >-
  Binding on merge as the contract for a helper that the operating system's service manager
  starts on demand to read host state for the agent and that takes no input. The first user is
  the firewall plugin's read-only snapshot on packaged Linux. A helper that mutates state, takes
  a parameter or is activated per user is outside it.
scope: >-
  agent, Linux packaging and service units: a root-owned, socket-activated, no-input helper that
  returns data to the unprivileged agent
builds-on: >-
  ADR-3002 (acquisition ladder; Decision 8, the sudo boundary and the "separately approved
  brokered replacement"), ADR-3003 (user-session helper; item (a), the governed contract for
  OS-managed activation, which it leaves unwritten)
related: ["3002-acquisition-ladder", "3003-user-session-helper"]
context-refs: ["docs/agent-privilege-model.md", "docs/os-capability-matrix.md", "deploy/systemd/yuzu-fw-snapshot.socket", "deploy/systemd/yuzu-fw-snapshot@.service", "deploy/systemd/yuzu-fw-snapshot.sh"]
---

# ADR-3007: OS-activated read helpers

## Context

The packaged Linux agent runs as `yuzu-agent` under `NoNewPrivileges=true` with a bounding set of
one capability, `CAP_DAC_READ_SEARCH` (`deploy/systemd/yuzu-agent.service`). It can therefore read
neither the nftables ruleset (a netlink dump needs `CAP_NET_ADMIN`) nor `iptables -S` (root), and
`sudo` cannot elevate under `NoNewPrivileges`. The firewall plugin's `state` and `rules` reads
returned `unknown` there. ADR-3002 Decision 8 keeps the sudo boundary for privileged Linux work and
says the agent must not hold the privilege in-process; it also says a "separately approved brokered
replacement" is not foreclosed. The privilege model lists "a privileged broker beside an
unprivileged worker" as reserved for a later pass (`docs/agent-privilege-model.md`, option 3).
ADR-3003 item (a) names the governed contract for OS-managed activation of a helper as not yet
written.

This ADR writes that contract for one narrow kind of helper: started by the service manager, no
input, fixed read-only work, returns data. It is the first narrow instance of option 3. It is not
a path to elevate the agent, and it does not widen what the agent unit may do.

## Decision

A helper that follows these clauses may be shipped as a socket-activated unit. A change that
breaks any of them is outside this ADR and needs its own threat model.

1. **Activation by the service manager only.** The helper is started by the operating system's
   service manager (systemd) when something connects to its socket. The agent never spawns,
   signals or owns the helper, and nothing is inherited from the agent: the helper starts from the
   service manager's clean state.
2. **No input.** Standard input is `/dev/null`. The connection is the only trigger and the only
   output. A helper that needs a parameter is outside this contract: the work it does is fixed
   when the package is built. The client sends nothing, and bytes it does send are never read.
3. **Fixed, read-only work.** The program is a root-owned file shipped by the package. It names
   each tool by its literal absolute path with literal arguments, under a reset `PATH` and locale,
   and changes no ruleset. One decision is made before a tool runs, from host state and never from
   input: a legacy `iptables` or `ip6tables` whose core kernel module is not loaded is not run,
   because the service may not load a module and the same command run by an unconfined root does.
   The section is the marker `[unloaded]` when all four hold: the tool is executable; it is the same
   file as the legacy multi-call binary; `/proc/net/dev` exists; and the family's table list under
   `/proc/net` does not, which is so exactly while the family's core module is loaded, so the family
   holds no rule. In every other state the tool runs, and one that fails is `[failed]`. What a read
   that does run was seen to do to the host was measured on Ubuntu 26.04 ARM64 (kernel 7.0.0-43,
   systemd 259, iptables 1.8.11, 2026-11-23) and is the whole claim: with `ip_tables` loaded and
   `iptable_filter` not, one read was followed by the kernel loading `iptable_filter`; on the nft
   shim `lsmod` was identical around one read; with `/run/xtables.lock` removed the reply was
   unchanged, no module was added and the file was there again afterwards (root, mode `0600`; what
   created it was not established); AppArmor logged no new denial over 30 reads and the broker
   processes ran unconfined. A legacy tool run by an unconfined root with its modules not loaded
   loaded `ip_tables` and `iptable_filter` on that host.
4. **Bounded.** The output is cut at a size cap, the instance has `RuntimeMaxSec` and `TasksMax`,
   the socket has `MaxConnections`, and the client has its own deadline and size cap. A listing
   over the cap is cut and read as unknown, never as a shorter ruleset.
5. **Authorisation is the socket.** Who may connect is the socket's owner, group and mode. That
   proves identity and not authenticity, so only data that is acceptable to disclose to the agent
   account may be served. What the firewall snapshot serves is the host's full nftables ruleset
   (rule handles and rule comments included) and the `iptables` and `ip6tables` listings.
6. **The client verifies and fails closed.** The client checks that the socket was created by root
   (the peer credentials of a connected unix socket are those of the process that listened), and
   treats the reply as untrusted text: strict framing, and anything that does not parse is
   unknown. A reply never produces a false-safe value: `inactive` is answered only when every
   section that was read shows no content, and a section that failed or was cut is never read as
   empty. The reply has four markers: `[absent]` (tool not installed), `[failed]` (tool exited
   non-zero), `[unloaded]` (clause 3: a legacy `iptables` tool whose core module is not loaded, not
   run) and the closing `== end`. `[unloaded]` is honoured only as the whole body of an `iptables`
   or `ip6tables` section: there it is a section that was read and holds no rule, adds nothing to
   the count and makes the family neither unknown nor active by itself. In the `nft` section, beside
   other text, or as an empty section it is not a marker: it is text the parser does not
   recognise, which reads unknown.
7. **The helper has its own minimum sandbox, and the agent unit never changes.** The helper
   service runs with its own bounding set, system call filter, address families and file system
   protections, each documented where it is set. The helper service does not set
   `NoNewPrivileges`: measured on Rocky 9.9 with SELinux enforcing, under it every exec of the
   three tools was a denied `nnp_transition` (three audit denials per read) and the tools ran in
   the script's domain instead of their own, so the unit is bounded by root with two capabilities
   (an exec yields no more capabilities than the bounding set) and by the filters, which systemd
   applies to every process the script starts. One thing does change without the flag: an exec of a
   setuid or setgid program that belongs to another user or group changes the process to that
   identity; that adds no capability beyond the two in the bounding set, the filters still apply, and
   the script runs only its three fixed tools with no input. Measured on the Rocky 9.9 host
   (aarch64, systemd 252, SELinux enforcing, 2026-11-23) with the service as shipped: no denial in
   the audit log over 30 broker reads under the policy's default audit configuration; with the
   policy's `dontaudit` rules switched off for the experiment (`semodule -DB`, still enforcing),
   `nft`, now running in `iptables_t`, was denied about 127 `search` accesses per read on other
   processes' `/proc/<pid>` directories and the listing was unchanged (30 of 30 reads complete,
   count 103). `NoNewPrivileges` and the one-capability bounding
   set on the agent unit are untouched: the helper returns data, it is never a way for the agent to
   gain a privilege. The IP egress filter in the helper's unit is defence in depth and takes effect
   only on hosts with the unified cgroup hierarchy; the family list is what bounds its sockets.
8. **Evidence.** Each helper has a row in the spawn-sink manifest's OS-activated helpers table
   (`docs/agent-spawn-sink-manifest.md`): unit, trigger, commands, interpreter, privilege, input
   surface and capabilities. The plugin's declared mechanism names the broker. The declared rung is
   the agent-side acquisition: a connection to a socket is rung 1 (the agent spawns no process),
   while the helper's own script is a `#!/bin/sh` program, which is rung 3 by ADR-3002 Decision 5 if
   it were started by the agent, and is not here because the service manager starts it.
9. **Ownership.** The service manager starts, bounds, kills and reaps the helper. The `== end`
   line the script writes last is the acknowledgement that the work ran to completion, which is
   what ADR-3002 asks of an ownership-transferring launch (the exec-success acknowledgement); a
   reply without it is incomplete.
10. **A mutating helper is out of scope.** A helper that changes host state (a containment,
    for example) needs its own threat model and its own ADR.

## What this discharges

- ADR-3003 item (a), the governed contract for OS-managed activation of a helper, for helpers that
  the system service manager starts and that take no input. Per-user resident activation (a helper
  in a login session) stays open.
- ADR-3002 Decision 8's "separately approved brokered replacement", for the firewall snapshot read.
- Option 3 of the privilege model, "a privileged broker beside an unprivileged worker", as its
  first narrow instance: read-only, no input, one fixed work item.

## Consequences

- The packaged Linux agent reads nftables and iptables state and rules through
  `yuzu-fw-snapshot.socket` (`/run/yuzu-fw-snapshot.sock`, `root:yuzu-agent`, `0660`). A host can
  opt out with `systemctl stop yuzu-fw-snapshot.socket` and then `systemctl mask
  yuzu-fw-snapshot.socket` (measured on Rocky 9.9, systemd 252: `mask --now` alone left the socket
  file, and the agent reported `error|snapshot:connect:refused`), after which the plugin answers as
  it did before: firewalld's own rows on a firewalld host, `unknown` elsewhere, after the error rows
  of the reads it was refused.
- On a host the installer provisioned (no packaged socket), the plugin reads the same listing from the
  root helper's `snapshot` word through `sudo -n --`, a rung-3 site registered in the manifest
  (`firewall/try_snapshot#1`); a sudo that refuses is a silent decline. It is not an OS-activated helper
  and is outside this contract; it is recorded here only because it feeds the same parser, and the
  descriptors' `fallback` field names it.
- The agent account can now read the host's full nftables ruleset and the iptables listings. That
  is the cost, and `docs/user-manual/security-hardening.md` says so.
- The units are designed for systemd 239 and later; the plugin README names the versions the
  lab measured.
