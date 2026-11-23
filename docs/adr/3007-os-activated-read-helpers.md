---
status: accepted
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
neither the nftables ruleset (a netlink dump needs `CAP_NET_ADMIN`) nor the legacy iptables tables (root), and
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
   and changes no ruleset, writes no file and takes no lock, and, for the tables the kernel lists,
   loads no kernel module. It reads two
   kernel rulesets, one reader each: the nf_tables ruleset with `/usr/sbin/nft -a list ruleset`,
   and the legacy xtables tables of each address family with that family's legacy save tool under
   its own name, `/usr/sbin/iptables-legacy-save` and `/usr/sbin/ip6tables-legacy-save`, run with
   no argument, which list every instantiated table. The alternatives-selected `iptables` and
   `ip6tables` are never run: on an nft-backed host they are the shim, whose listing repeats rules
   the nft section lists and says nothing of the legacy tables. Two decisions are made before a
   tool runs, from host state and never from input. If `/proc/net/dev` cannot be stat'ed, the
   process cannot see the kernel's tables, and a save tool reads a missing table list as no table,
   so both legacy sections are `[failed]` and no tool is run. If a family has no legacy save tool,
   nothing here can list its tables, so the kernel's own list of them is printed under `[tables]`;
   the family's table list under `/proc/net` is absent exactly while the family's core module is
   not loaded. A table list that cannot be stat'ed is read as no table, behind the `/proc/net`
   check, which rules out every cause at directory level. `head` is named by name under the reset
   `PATH`, as the size cut is. The legacy save tools were measured on Ubuntu 26.04 ARM64 (kernel
   7.0.0-43, systemd 259, iptables 1.8.11, 2026-11-23) unconfined and in the sandbox of the
   shipped unit: they loaded no module, ran no `modprobe` and created no `/run/xtables.lock`. The
   broker's processes ran unconfined by AppArmor there. A save tool that cannot open its table-list
   file for a reason other than the file not existing must exit non-zero, which the script prints as
   `[failed]`: `for_each_table` in `iptables/iptables-save.c` returns quietly only for `ENOENT` and
   prints `Failed to list table names` and calls `exit(1)` for any other error number, as read in the
   Debian archive's source at iptables 1.8.2-4, 1.8.7-1, 1.8.9-2, 1.8.11-2 and 1.8.13-1 (and in
   `ip6tables-save.c` at 1.8.2-4; one file serves both families from 1.8.7), and as measured on
   1.8.11 in the broker's sandbox. A release not named here is not covered by that statement. Release
   1.6.0 returns quietly on any failure, but it has no `-legacy-save` name, so the script never runs
   it. A table that goes away between the kernel listing it and the tool reading it is the one case
   in which a save tool asks for a module: `do_output` runs `xtables_load_ko`, which runs `modprobe`
   for the family's core module and asks again, in every release read, and then fails. That
   `modprobe` can load nothing in the broker's instance under `ProtectKernelModules` and runs as
   root in the installer's helper, which has no such sandbox; the section is `[failed]`. One side
   effect is measured and stays: an nft read on a host where nf_tables is not loaded makes the
   kernel load nf_tables (an empty ruleset: no table, no rule). It cannot be avoided inside this
   contract: skipping nft needs proof that nf_tables is absent, and no existence test gives it on a
   kernel that builds nf_tables in.
4. **Bounded.** The output is cut at 4 MiB (4194304 bytes), which is the bound the plugin's netlink
   leg already has for the same host ruleset (`kNftDumpMaxBytes`), so the plugin has one bound for
   it; the instance has `RuntimeMaxSec` and `TasksMax`, the socket has `MaxConnections`, and the
   client has its own deadline and the same size cap (the installer helper's run is capped at twice
   that). A listing over the cap is cut and read as unknown, never as a shorter ruleset.
5. **Authorisation is the socket.** Who may connect is the socket's owner, group and mode. That
   proves identity and not authenticity, so only data that is acceptable to disclose to the agent
   account may be served. What the firewall snapshot serves is the host's full nftables ruleset
   (rule handles and rule comments included) and every instantiated legacy `iptables` and `ip6tables` table.
6. **The client verifies and fails closed.** The client checks that the socket was created by root
   (the peer credentials of a connected unix socket are those of the process that listened), and
   treats the reply as untrusted text: strict framing, and anything that does not parse is
   unknown. The reply has these markers: `[absent]` (the nft tool is not installed, so that
   section was NOT read; the script prints it for nft only), `[failed]` (a tool exited non-zero,
   or the section could not be tried), `[tables]` (a legacy family with no save tool: the marker,
   then the kernel's list of the family's tables, one name per line) and the closing `== end`.
   `[tables]` is honoured only as the first line of a legacy section; in the nft section it is text
   the parser does not recognise. What each section vouches for: the nft section, the whole
   nf_tables ruleset; each legacy section, every instantiated legacy table of its family, from the
   save tool's listing or, with no tool, from the kernel's list. A section is READ when it vouches
   for its own ruleset: nft text that parses;
   a legacy save listing in the shape the client knows (empty output is a family that holds no
   table); `[tables]` with no name after it. It is UNREAD otherwise: `[absent]`, `[failed]`, text
   that does not parse, and `[tables]` followed by a name (tables exist that nothing listed). The
   decision: `active` when any READ section shows content; `unknown` when none does and a section
   is UNREAD; `inactive` when all three sections were READ and none shows content in two snapshots
   taken one after the other (the second is taken only when the first reads `inactive`, and its
   answer is the answer), and then `unknown` again if the netlink read saw a table. A rule count is
   written whenever all three sections of the answering snapshot were READ and the netlink read did
   not turn the state to `unknown`: the nft rules plus the `-A` rules of both legacy families.
   `inactive` therefore means that, twice in a row, the nf_tables ruleset (every family nft lists,
   arp and bridge included) and every legacy IPv4 and IPv6 table held no rule, no user-defined chain
   and no policy other than accept. Outside that statement: legacy `arptables` and `ebtables`
   tables, which no read of this plugin lists; a family with no save tool whose table list cannot be
   stat'ed while `/proc/net/dev` can (read as no table, clause 3); and rules that move between
   rulesets more than once inside one read. The count is the sum of one pass of three reads, so a
   rule that moves during it can be counted twice or not at all. An `[absent]` nft section is never
   evidence of an empty ruleset, so with no content anywhere the rung declines and the read ladder
   goes on, and a reply that failed or was cut is never read as empty.
7. **The helper has its own minimum sandbox, and the agent unit never changes.** The helper
   service runs with its own bounding set, system call filter, address families and file system
   protections, each documented where it is set. The helper service does not set
   `NoNewPrivileges`: measured on Rocky 9.9 (systemd 252, SELinux enforcing), under it the exec of
   `nft` was a denied `nnp_transition` from `initrc_t` to `iptables_t` and `nft` ran in the script's
   domain instead of its own, so the unit is bounded by root with two capabilities
   (an exec yields no more capabilities than the bounding set) and by the filters, which systemd
   applies to every process the script starts. One thing does change without the flag: an exec of a
   setuid or setgid program that belongs to another user or group changes the process to that
   identity; that adds no capability beyond the two in the bounding set, the filters still apply, and
   the script runs only the tools clause 3 names, with no input. The script must not create files: with
   SELinux enforcing on Rocky 8.10, a file left in the instance's private `/tmp` was not removed
   when the instance ended. `/run` is made read-only by name (`ReadOnlyPaths=/run`), because with
   `ProtectSystem=strict` it stayed writable in the instance whenever `ProtectKernelTunables` or
   `ProtectControlGroups` was set (measured on Ubuntu 26.04, systemd 259); nothing the script runs
   writes there. `NoNewPrivileges` and the one-capability bounding
   set on the agent unit are untouched: the helper returns data, it is never a way for the agent to
   gain a privilege. The IP egress filter in the helper's unit is defence in depth and takes effect
   only on hosts with the unified cgroup hierarchy; the family list is what bounds its sockets. On
   Rocky 8.10 (systemd 239, legacy cgroup hierarchy) `IPAddressDeny` is parsed and not enforced.
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
10. **A mutating helper is out of scope.** A helper whose work is to change host state (a
    containment, for example) needs its own threat model and its own ADR. The kernel loading
    nf_tables on demand, which clause 3 records, is a side effect of a read, not work the helper does.

## What this discharges

- ADR-3003 item (a), the governed contract for OS-managed activation of a helper, for helpers that
  the system service manager starts and that take no input. Per-user resident activation (a helper
  in a login session) stays open.
- ADR-3002 Decision 8's "separately approved brokered replacement", for the firewall snapshot read.
- Option 3 of the privilege model, "a privileged broker beside an unprivileged worker", as its
  first narrow instance: read-only, no input, one fixed work item.

## Consequences

- The packaged Linux agent reads nftables and legacy iptables state and rules through
  `yuzu-fw-snapshot.socket` (`/run/yuzu-fw-snapshot.sock`, `root:yuzu-agent`, `0660`). A host can
  opt out with `systemctl stop yuzu-fw-snapshot.socket` and then `systemctl mask
  yuzu-fw-snapshot.socket` (measured on Rocky 9.9, systemd 252: `mask --now` alone left the socket
  file, and the agent reported `error|snapshot:connect:refused`), after which the plugin answers as
  a host without the broker does: firewalld's own rows on a firewalld host, `unknown` elsewhere,
  after the error rows of the reads it was refused. A host that masks the socket before the package
  is installed keeps the broker from ever starting, and the agent starts without it.
- A host without the `nft` command reads nf_tables through nothing: the broker lists it only
  through `/usr/sbin/nft`. With no content in any section that was read, the rung declines with
  `error|nftables:snapshot:absent` and the ladder's own `unknown` follows; with legacy content it
  answers `active` with no count. The real fix is the package depending on `nftables`, or a
  compiled netlink reader under this contract, which is a decision for the owner.
- `inactive` is a bounded statement (clause 6): it does not cover legacy `arptables` and `ebtables`
  tables, a family whose table list cannot be stat'ed while `/proc/net/dev` can, or two or more
  rule moves between rulesets inside one read, and the count is one pass of three reads. The
  table-list residual is not closed in the script: `[ -e ]` cannot tell a missing file from a refused
  stat, and the only shell test that could (a glob over `/proc/net`) is switched off in the helper
  (`set -f`). The real fix for it, and for a host without the `nft` command, is a compiled reader
  under this contract, which can tell a missing file from a refused one.
- On a host the installer provisioned (no packaged socket), the plugin reads the same listing from the
  root helper's `snapshot` word through `sudo -n --`, a rung-3 site registered in the manifest
  (`firewall/try_snapshot#1`); a host with no helper file makes no sudo call and says nothing, and a
  sudo that refuses, or a helper that times out, is clipped, does not accept the word or fails, is
  `error|snapshot:helper:<token>`. It is not an OS-activated helper
  and is outside this contract; it is recorded here only because it feeds the same parser, and the
  descriptors' `fallback` field names it.
- The agent account can now read the host's full nftables ruleset and the legacy iptables listings.
  That is the cost, and `docs/user-manual/security-hardening.md` says so.
- The units need systemd 239 or later; the plugin README names the versions the lab measured.
