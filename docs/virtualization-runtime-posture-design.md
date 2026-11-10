# `virtualization.runtime_posture`: read-only container-runtime posture

**Status:** design, written before any code and since built. The privilege change it describes was
approved by the owner on 2026-11-08; the security review (section 11) requires one re-acknowledgement,
marked in section 1. The code was built from this note and every qualifier is kept true of it: where
this note says the plugin "does" something, it describes the code in this PR. Any difference found in
review is fixed in the note or the code, never left standing (section 11 records the ones found so
far). The sentences marked **binding** in sections 4, 5, 6 and 8 are the statements the code must keep
true; section 11 lists them together.

Related: [`agent-privilege-model.md`](agent-privilege-model.md) (the privileged-actions row and the
"Deliberately NOT granted" row for this action), `agents/plugins/virtualization/` (the plugin),
`deploy/systemd/yuzu-agent.service` (the packaged unit, not changed by this work).

## 1. Scope and threat model

**What it is.** A new Linux-only action `runtime_posture` on the `virtualization` plugin. It answers:
which container runtimes (docker, podman, containerd) are present on this device, how are they
configured from a security point of view, and which containers exist and with what risky settings.

**What it is not.** It never creates, starts, stops, execs into, attaches to or removes anything. An
honest agent never reads a container's environment, command line, labels, ports or any mount other
than the one host-socket flag defined in section 8. macOS and Windows answer one `unsupported` status
row.

**Opt-in.** With no endpoint configured (the default) the plugin never opens a socket. It still reports
what it can learn from `stat` and a bounded config read (section 6), because those need no new access.

**The privilege change.** The agent gains one new ability: `connect(2)` to a single, operator-provided
unix socket, and to send four fixed `GET` requests over it (section 2). That is a read access to a
container runtime control plane, so it is security-gated (this note, a security review before any code,
and the owner's approval of both).

**Threat model.** The asset is the host. A container runtime's control socket is root-equivalent when it
accepts writes: whoever can start a privileged container with `/` mounted owns the machine. So the design
assumes the agent process may be compromised and asks what it can do with the access it is given.

| Actor and move | What it can and cannot do |
|---|---|
| A compromised agent holding the endpoint | **The agent's verb table binds only an honest agent.** A compromised agent can send any request the operator's endpoint admits. The endpoint contract (section 4) filters requests, not response bodies: an admitted `/containers/{id}/json` returns the runtime's whole inspect document (`Config.Env`, `Cmd`, `Entrypoint`, `Healthcheck`, `Labels`, `LogConfig` options, `HostConfig.Binds`, `Mounts`, `ExecIDs`, network addresses), and the admitted list reply carries `Command`, `Labels` and `Mounts` for every container. Container environments commonly hold credentials. Under the packaged unit this is not new reach: `CAP_DAC_READ_SEARCH` already reads the same documents from the runtime's data root on disk. On a host that took the capability opt-out (`docs/user-manual/upgrading.md`), the endpoint is new credential access. It still cannot create, exec into, attach to or stop anything, because the endpoint admits only the four `GET` requests. **Owner re-acknowledgement required** (security review finding 1, section 11): the earlier text said the endpoint exposed "names, images, states and the six posture fields"; that was false. |
| A compromised agent trying to reach the real socket | The four default sockets are `root`-owned (docker's is `root:docker`). The agent account is not in the `docker` group and is not granted any capability that bypasses socket permissions. The packaged unit's only capability is `CAP_DAC_READ_SEARCH` (read and directory search, not write); `connect(2)` on a unix socket needs write permission on the socket. This is the expected behaviour under `unix(7)` and is confirmed on a real host before release (section 9). If an operator drop-in has added the agent to the `docker` group, or a default socket is other-writable, the agent reports it (`overprivileged`, section 4) rather than relying on the refusal. |
| A compromised agent changing its own configuration | The endpoint comes from `/etc/yuzu-agent/yuzu-agent.env` (`root:root 0600`) or a unit drop-in, both root-owned. The agent process cannot write either. |
| An operator who points the endpoint at a default socket by mistake | Refused and reported as `endpoint_refused` (section 4). The refusal is a structural guard, not the enforcement. |
| A hostile or broken peer on the endpoint (huge reply, trickling bytes, never answers) | Bounded by a 1 MiB body cap, connect and inactivity timeouts, and a 20 s overall action deadline (section 5). Repeated dispatch against such a peer cannot pin more than one worker: the action is single-flight (section 5). |
| Hostile JSON from the peer (wrong types, deep nesting, huge arrays) | Nesting over 32 is refused by a parse callback that discards the over-deep part as it starts (it is never built) and the whole reply reads `malformed`; the rest is parsed without exceptions and read with accessors that tolerate a wrong type; counts and field lengths are capped; every emitted field is checked against a per-field character allow-list (section 8). |
| Hostile text from the peer (control characters, bidi overrides, pipe grammar) | The wire escaping alone does not stop ESC, other C0/C1 bytes or bidi characters. Every free-text field is admitted only if it matches its allow-list (section 8); otherwise the field reads `invalid`. |

**Data exposure.** Container names and image references reach the server as device-scope rows. They are
stored responses, so they are readable by every holder of `Response:Read` (which includes the `Viewer`
role); the action's `Security:Read` grant governs who may dispatch it, not who may read the stored rows,
and the Forensics tier does not apply. An honest agent never emits environment, command line, labels,
ports or non-socket mounts. If container names are judged too sensitive, the row shape changes (the owner
chose to ship them on 2026-11-08).

## 2. Verb table: the only requests the agent can send

The agent builds requests from a fixed table indexed by an enum, never from a string. There is one
constructor of a request, `build_request(Verb, container_id)`, and the method is `GET` in every row.

| Verb | Request | Used for | Keys read from the reply (no other key is accessed) |
|---|---|---|---|
| `version` | `GET /version` | endpoint liveness, runtime dialect (docker or podman, only when the reply names one), version and API version | `Version`, `ApiVersion`, `Components[].Name` |
| `info` | `GET /info` | runtime-reported posture facts, emitted as `config` rows from a fixed key allow-list (section 6) | `CgroupDriver`, `SecurityOptions` (count, and whether one entry is `name=rootless`) |
| `containers_list` | `GET /containers/json?all=1` | the container list | `Id`, `Names`, `Image`, `State` |
| `container_inspect` | `GET /containers/{id}/json` | privileged flag, network mode, socket-mount flag for one container | `HostConfig.Privileged`, `HostConfig.NetworkMode`, `Mounts[].Source` |

These are the unversioned Docker-compatible paths, which podman's compatibility API also serves.
`{id}` is substituted only after it matches `^[0-9a-f]{12,64}$` (taken from the list reply); an id that
does not match, or an id given to any other verb, produces no request. A compile-time check pins the
table size to the enum. There is no fifth verb and no way to build a request outside this table. Every
request carries `Connection: close`; the agent never reuses a connection.

**binding:** the list-reply reader is an allow-list too (`Id`, `Names`, `Image`, `State` only): `Command`,
`Labels`, `Mounts`, `Ports` and every other key in the list reply are never read, so an honest agent's
output cannot grow to include them without a change to this note.

**containerd.** containerd's control plane is gRPC (CRI), and no plugin links a gRPC client today.
containerd is therefore detected by presence only (section 6); an endpoint pointed at a containerd socket
reads `not_http`. The CRI verb set is fixed here as the only calls a future change may add: `Version`,
`Status`, `ListContainers`, `ContainerStatus`. Adding any other, or adding gRPC at all, needs a new note
and a new security review. That follow-up is deferred (section 10).

## 3. Opt-in mechanism

- New agent option `--runtime-endpoint <absolute unix-socket path>`, environment name
  `YUZU_AGENT_RUNTIME_ENDPOINT`, field `AgentConfig::runtime_endpoint` (default empty).
- The agent publishes it to plugins as the config key `agent.runtime_endpoint`, beside `agent.data_dir`.
- Validation is not done in the command-line library: that library silently drops an environment value
  its validator rejects, which would turn a refused endpoint into a silent "unset". The plugin's pure
  `parse_endpoint()` decides, so a rejected value always surfaces as a typed `endpoint_refused` row.
- A server-pushed switch cannot carry a path and is not used. The packaged unit is not changed.

## 4. Endpoint contract

The operator supplies the endpoint. Yuzu ships no proxy. The contract an endpoint must meet:

1. **The socket.** One unix stream socket, owned by `root`, group = the agent's group (`yuzu-agent` on
   the packaged unit, `yuzu` from `scripts/install-agent-user.sh`), mode `0660`. Its directory, and
   every ancestor of that directory, is owned by `root` and not writable by group or other. The
   directory is owned by the **proxy's** unit (`RuntimeDirectory=` on the proxy's service, which runs as
   root), never by the agent's unit: a `RuntimeDirectory=yuzu-agent` drop-in on `yuzu-agent.service`
   would make `/run/yuzu-agent` agent-owned and defeat the check below. The directory is not covered by
   the agent unit's `PrivateTmp` (so not under `/tmp`), and the path is at most 107 bytes (the
   `sun_path` limit). `/run/yuzu-agent/runtime.sock` is the convention used in the recipes below.
2. **Request admission.** `GET`-only is insufficient: the docker daemon registers `GET` on
   `/containers/{id}/attach/ws`, `/archive`, `/export`, `/logs`, `/top` and `HEAD` on `/archive`;
   podman adds `GET` logs and export under both its compatibility and `/libpod` trees and serves the
   same routes under versioned (`/v1.41/...`, `/v4.0.0/...`) and unversioned paths. The endpoint
   therefore admits a request only when its method is `GET` and its **undecoded origin-form
   request-target byte-matches** one of `/version`, `/info`, `/containers/json?all=1`, or
   `^/containers/[0-9a-f]{12,64}/json$`. It refuses any target containing `%`, `\`, `#` or `..`, an
   absolute-form target, a version prefix, `/libpod`, any other query string, and any request carrying
   a body (`Content-Length` other than `0`, or `Transfer-Encoding`), an `Upgrade` header, or a method
   other than `GET` (including `HEAD`). A pattern such as `/containers/.+/json`, or a match performed
   after percent-decoding, admits more than the four requests and is not acceptable.
3. **Every request, not the first.** The endpoint validates every request on a connection, or forces
   `Connection: close` so a connection carries one request. A proxy that checks only a connection's
   first request is bypassed by HTTP keep-alive.
4. It forwards to the runtime's own API socket, so the answer is the runtime's, not a copy.
5. It adds no credentials the agent could reuse. The agent sends none.
6. **It does not filter response bodies.** An admitted request returns whatever the runtime returns
   (section 1, first row). The contract is a request filter.

**What the agent enforces, and what it does not.**

The agent refuses to use as an endpoint (each refusal is `endpoint_refused` with a reason, and the
transport is never invoked):

- a relative path, one containing a `..` segment, or one longer than 107 bytes;
- any of the four default sockets: `/run/docker.sock`, `/var/run/docker.sock`,
  `/run/podman/podman.sock`, `/run/containerd/containerd.sock`. The path is first normalised lexically
  (repeated `/` collapsed, `/./` segments removed, a trailing `/` stripped), so `//run//docker.sock`,
  `/run/./docker.sock` and `/var/run/docker.sock/` are refused as the same path;
- any path whose identity (`st_dev`, `st_ino`) equals that of a default socket that is present on the
  host, which closes symlink and bind-mount aliases of those sockets;
- **binding:** a path whose properties do not match the contract. The agent opens the endpoint with
  `open(O_PATH | O_NOFOLLOW)` and inspects the opened object with `fstat`: it must be a socket, owned by
  uid 0, group equal to the agent's effective gid, mode exactly `0660`. It then walks the ancestors
  (`/run/yuzu-agent`, `/run`, `/`) and requires each to be a directory owned by uid 0 and not writable
  by group or other. The walk is lexical and `stat`-based: it names each ancestor of the normalised
  path and `stat`s it, following links, so an ancestor that is itself a link is judged by its target.
  That is sound because the object that matters is the leaf, which is already held as a checked
  descriptor that the agent connects through, so an ancestor swapped for a link after the check cannot
  change which object is connected to; the walk only refuses a layout in which a user other than root
  could replace the socket before the next run. A symlink at the leaf is not followed: with `O_PATH`, `O_NOFOLLOW` returns a
  descriptor for the link itself rather than failing with `ELOOP` (`open(2)`), so `fstat` reports a
  link and the refusal reason is `symlink`. A wrong type, owner, group or mode, or an insecure
  ancestor is `endpoint_refused` with that reason. A `stat`/`open` error other than `ENOENT`
  (`EACCES`, `ELOOP` from a looping ancestor, `ENAMETOOLONG`, `ENOTDIR`, anything else) is also
  `endpoint_refused`, never read as "absent": only `ENOENT` means `unreachable`.
- **binding:** the agent connects through the descriptor it inspected, not through the path again: the
  transport's socket path is `/proc/self/fd/<N>` for the `O_PATH` descriptor held open across the
  connect, so the object that was checked is the object connected to. Whether `connect(2)` resolves a
  `/proc/self/fd` link to an `O_PATH` socket descriptor is measured in section 9 before the code is
  relied on; if it does not, the shell connects by the checked path and this note records the
  check-to-connect window as a residual. Until that measurement says so the shell never retries by
  path on its own: a request whose `/proc/self/fd/<N>` connect fails reads `unreachable`.

**binding (`overprivileged`):** for each default socket that is present, the agent checks its mode and its
`st_gid`. The socket is `overprivileged` when its mode has the other-write bit, or has the group-write bit
and its `st_gid` is one of the agent's effective or supplementary groups (`getgroups`). Either way the
agent could connect to the real socket (a `SupplementaryGroups=docker` drop-in, or a `0666` socket),
which the privilege model forbids. The agent emits the token
`linux:virtualization:runtime_posture:<runtime>:overprivileged`, the result is `constrained`, and the
action otherwise proceeds. It never probes by connecting.

**The limits of that refusal, stated plainly.** It is a structural guard that stops the shortcut the
privilege model forbids (pointing the agent at the real socket). It is not the security boundary:

- Inode comparison only sees default sockets that exist when the action runs, and only the four known
  paths. A runtime socket at another path (a second daemon listener, a rootless socket under
  `/run/user/<uid>/`, `/run/containerd/containerd.sock.ttrpc`, a TCP listener) is not known to the agent.
- A default socket whose `stat` fails with an error other than `ENOENT` (for example an unreadable
  `/run/podman` on a host that took the `CAP_DAC_READ_SEARCH` opt-out) cannot be compared by inode. The
  endpoint is not refused for that: the opt-in would be unusable on exactly such a host. The failure is
  reported as `<runtime>:socket:<errno>` and the status is `constrained`, and the alias must still match
  the endpoint's owner, group and mode, which a bind mount of the real socket carries from the real
  socket.
- The enforcement is the socket's permission bits (root-owned, agent-group `0660`, so only the agent and
  root can connect) and the operator's proxy (only the four `GET` requests get through). If the proxy is
  permissive, a compromised agent reaches whatever it permits. The agent's own verb table limits what an
  uncompromised agent sends; it cannot limit a compromised one, and it cannot verify the proxy's filter.

## 5. Bounds

| Bound | Value | Behaviour when hit |
|---|---|---|
| Action deadline | 20 s total, monotonic clock | No further requests are issued; every completed row is kept; token `deadline_exhausted`; status `constrained`, completeness `partial` |
| Per-request budget | the time remaining of the 20 s, enforced by a watchdog that shuts the in-flight socket at the budget and by a clock check when the request returns, independent of socket readiness; the HTTP client's own per-request total timeout is set to it as well | a request over budget, or back at or past it, ends as a timeout (`version:timeout`, `info:timeout` or `list:timeout`), never as an answer |
| Connect timeout | `min(2 s, remaining)` | `unreachable` |
| Read inactivity timeout | `min(5 s, remaining)` | the request fails |
| Response body | 1 MiB, enforced by a declared-length check before the body is read and by a receiver that stops reading; the client's own payload cap sits one read buffer above it as a backstop | token `version:response_oversized`, `info:response_oversized` or `list:response_oversized`; no rows from that verb |
| JSON nesting | 32 levels; a parse callback discards anything deeper as it starts, so it is never built, and records the breach | the whole reply is `malformed` (`<verb>:malformed`); no field of it is read |
| Container rows | at most 256; the 1 MiB body cap is the effective ceiling, because `all=1` lists exited containers too (about 2 to 3 KB each): a list reply over 1 MiB, roughly 350 to 500 containers, is `list:response_oversized` with no rows, so 256 applies to a reply that fit | token `rows_capped` |
| Inspections | at most 64, taken from the first 64 listed | token `inspect_capped`; the rest read `unknown` |
| `daemon.json` | read at most 256 KiB | token `oversized` |
| Free-text field | charset-checked (section 8), then truncated to 256 bytes before escaping | `invalid` on a charset miss; truncation is silent |
| Concurrency | one dispatch in flight per process | a second dispatch returns at once with one status row (`constrained`, token `busy`) and no other row |

**binding (transport pins):** the per-request total timeout is never set to zero or a negative value,
which the HTTP client reads as "no limit" (its default is zero, and it tests `<= 0`): the plugin stops
issuing requests when the remaining budget is below 1 ms, so a sub-millisecond remainder cannot round
to zero. The
client has redirects off, decompression off and a payload cap one read buffer (16 KiB) above the 1 MiB
body cap, and every request is sent with `Connection: close`. The 1 MiB cap itself is enforced ahead of
the client's, by a declared-length check and by the receiver, because the client's check runs before the
receiver and would otherwise report an oversized chunked reply as a plain read error. Response bodies and parser error text are never logged, at any level.

**binding (the deadline is absolute):** the HTTP client's own total timeout is only consulted when it
next has to wait for data, and once the budget is spent it clamps to a zero-time poll that still reads
whatever is ready. A peer that is always readable (an endless stream of `100 Continue` lines, which the
client skips with no count bound and no clock check) is therefore never made to wait, and would hold the
request, and the agent worker, for as long as it keeps writing. The deadline is enforced independently
of socket readiness, twice. (1) In the Linux shell a watchdog thread, owned and joined by an RAII guard
declared after the client (so it is joined before the client is destroyed on every exit path, with no
detached thread), waits out the request's budget and then calls the client's `stop()`, which shuts the
in-flight socket down; it repeats the call every 100 ms until the request returns, because a call that
lands before the request has marked its socket in flight does nothing. (2) Whatever a request reported,
one that returns at or past its budget is a `timeout` (`budget_outcome`, one pure function): the shell
applies it to the request, and the seam applies it again to every result of any transport, so a late
reply is never read and an overrun can never end `supported`. A failure to start the thread is an
exception like any other and reaches the one ABI `try/catch`. A peer that is not readable (a trickle) is
unaffected: the client's own timeouts end it first.

**binding (single-flight):** the agent's dispatch pool has one worker per hardware thread and no
per-action serialisation, so without a guard repeated dispatch against a trickling peer pins the pool.
The action holds a process-wide flag for its whole run; a concurrent dispatch returns `busy` without
touching the filesystem or the socket.

**binding (`stat` on a network filesystem):** the HTTP deadline does not cover `stat`, and `stat` of a
data root on a dead network mount has no deadline. The Linux shell reads `/proc/self/mountinfo` once per
dispatch and does not `stat` a data root that is on, under or containing a network filesystem
(`agents/shared/network_fstype.hpp`, the `runtimes` precedent): that root reads `absent` for detection
purposes with the token `<runtime>:network_fs_skipped`; an unreadable mount table is
`mountinfo:unreadable` and the data roots are then stat'd anyway. Sockets and config files live under
`/run` and `/etc`; they are not guarded.

The read timeout alone does not bound a peer that sends one byte just inside each window, which is why
the overall deadline exists: before each request the plugin computes the remaining budget from an
injected clock, passes it to the transport, checks the clock again when the request returns, and stops
issuing requests at zero. **The request ceiling is
67:** three fixed requests plus 64 inspections, inside 20 s; a healthy local socket answers all of them
in well under a second. The action holds one agent worker for at most 20 s plus the unguarded `stat`
calls. The deadline logic is unit tested with a fake clock (no sleeps); the real transport's behaviour
against a trickling peer is measured once on a real host and the elapsed time is recorded in the PR
(section 9).

**Output size.** One status row, one endpoint row, three runtime rows, at most one config row per
allow-listed key, and at most 256 container rows of about 800 bytes in the worst case (256 bytes per
free-text field is the ceiling for name and image; the other fields are short). That is about 200 KiB,
against the agent's 2 MiB output capture cap.

## 6. What is read without the endpoint

No subprocess, no `PATH` walk. Per runtime, `stat` of the default socket(s), the config file(s) and the
data root (section 5's network-filesystem guard applies to the data root); ownership and mode of a
socket are reported, nothing else about it.

| Runtime | Config looked for | Data root | Default socket(s) |
|---|---|---|---|
| docker | `/etc/docker/daemon.json` | `/var/lib/docker` | `/run/docker.sock`, `/var/run/docker.sock` |
| podman | `/etc/containers/containers.conf`, `/etc/containers/storage.conf`, `/etc/containers/registries.conf` | `/var/lib/containers` | `/run/podman/podman.sock` |
| containerd | `/etc/containerd/config.toml` | `/var/lib/containerd` | `/run/containerd/containerd.sock` |

`daemon.json` is parsed with the JSON library in non-throwing mode (comments ignored, nesting over 32
refused as in section 5, so the file reads `malformed`) and only an allow-list of posture keys is emitted: `live-restore`, `userns-remap`,
`no-new-privileges`, `icc`, `iptables`, `tls`, `tlsverify`, `data-root`, `log-driver`, `storage-driver`,
`selinux-enabled`, `userland-proxy`. `hosts` is reduced to a count and a `hosts_tcp yes|no` flag (any
`tcp://` listener); `insecure-registries` and `registry-mirrors` are reduced to counts. Every other key,
including anything that looks like a credential, is dropped and never emitted. A key with a value of the
wrong type (or a `hosts` element that is not a string) is skipped and the file reads `malformed` (the
well-typed keys still report). A malformed file reports `config|docker|daemon_json|malformed` beside any
well-typed rows, and a constraint token.

**binding (`/info` rows):** when an endpoint is configured, the `/info` reply is reduced to at most three
`config` rows and nothing else: `rootless yes|no` (whether any `SecurityOptions` entry is
`name=rootless`), `cgroup_driver <value>` (`CgroupDriver`, charset-checked), and
`security_options_count <n>` (the length of `SecurityOptions`). A key that is missing omits its row. A
`SecurityOptions` or `CgroupDriver` of the wrong type, a `SecurityOptions` element that is not a string
(neither `rootless` nor the count is emitted then: unknown is never rendered as `no`), or a reply that is
not an object, is `info:malformed` (the well-typed key still reports). No other `/info` key is read; the reply is
otherwise dropped. The reviewer judged these three fields safe; the reviewer could not verify how a
runtime masks credentials elsewhere in `/info`, which is why no other key is read.

The TOML files are presence and `stat` only: no hand-written TOML parser is added, so podman's and
containerd's own configuration contributes little posture in this PR.

## 7. Statuses

Attribution is split in two so every outcome has exactly one owner.

**The `endpoint` row owns the endpoint outcome:**

`endpoint|<state>|<reason>|<dialect>` where `state` is one of:

| State | Meaning |
|---|---|
| `unset` | no endpoint configured; no socket was opened |
| `endpoint_refused` | the configured value was refused; `reason` is one of `relative`, `dotdot`, `too_long`, `default_socket`, `same_inode`, `not_socket`, `symlink`, `owner`, `group`, `mode`, `insecure_ancestor`, `stat_error` |
| `permission_denied` | `connect` failed with `EACCES` or `EPERM` |
| `unreachable` | `ENOENT` at the endpoint path, `ECONNREFUSED`, a connect timeout, or no complete `/version` reply within the budget (token `version:timeout`) |
| `not_http` | connected, but `/version` was not a parseable HTTP reply with a JSON body within 1 MiB (token `version:not_http` or `version:response_oversized`; for example a containerd socket) |
| `ok` | `/version` answered; `dialect` is `docker` or `podman` when the reply identified one, from the `Components[].Name` of the reply (`Podman Engine` means podman, `Engine` means docker) or, for older daemons that send no components, a string `ApiVersion` (docker); `-` when it answered non-200 or malformed, or when a well-typed reply named no runtime (`{}`, `{"message":"ok"}`, a bare `Version`): that is neither malformed nor a token, and no runtime row reads `served` (section 7, per-response recovery) |

Every state other than `unset` and `ok` is also a failed read, so each adds one token to the status as
well as being named by the endpoint row: `endpoint:<reason>` for a refusal (`endpoint:default_socket`,
`endpoint:symlink`, ...), `endpoint:unreachable` for an endpoint path that is not there, and
`version:<cause>` (`permission_denied`, `unreachable`, `timeout`, `response_oversized`, `not_http`) for a
first request that failed or whose reply was not a runtime API. The result is `constrained`, never a clean
`OK` with no containers. The row says what the endpoint is, the token says the read failed, and neither
changes a runtime row.

**Each `runtime` row carries only detection facts:**

`runtime|<docker|podman|containerd>|<detection>|<default socket>|<config>|<version>|<api_version>`

| Detection | Meaning |
|---|---|
| `not_detected` | none of that runtime's standard-path artefacts exists (socket, config, data root) |
| `detected` | at least one standard-path artefact exists; for podman these include `/etc/containers/{storage,registries}.conf` and `/var/lib/containers`, which CRI-O, buildah and skopeo create too |
| `served` | the endpoint's `/version` identified this runtime; `version` and `api_version` are filled only on this row |

`not_detected` is a statement about the standard paths, not proof of absence. A stopped runtime, a
rootless runtime and a custom-root install can all read `not_detected`, and the contract text in the
README says so. `detected` is a statement about the same paths in the other direction: podman
`detected` means the shared `containers` configuration or storage artefacts exist, which a node with
only CRI-O, buildah or skopeo also has. An endpoint failure never changes any runtime row.

The result status is `OK` and `FULL` unless a read failed (a refused `stat` or `daemon.json` read, a
configured endpoint that was refused, absent, denied, unreachable or not a runtime API
(`endpoint:<reason>` / `version:<cause>`), an oversized or malformed reply, a non-200 reply, a cap, the
deadline, `busy`, `overprivileged` or a skipped network-mounted data root), in which case it is `CONSTRAINED` and `PARTIAL` through the shared
constraint accumulator. An endpoint that is merely unset is not a constraint. Tokens follow the plugin's
grammar `linux:virtualization:runtime_posture:<source>:<cause>`; an HTTP status inside a token is
emitted only when it is numeric and in 100-599, otherwise the cause is `http_other`.

**Per-response recovery.** A non-200, malformed or wrong-typed `/version`, `/info` or list reply yields
unknown fields for that verb plus one token `<verb>:http_<status>` or `<verb>:malformed`, where `<verb>` is
`version`, `info` or `list`; earlier rows are kept and later verbs still run while budget remains.
Wrong-typed means a key the parser reads is present with a non-null value, or an element it reads, of another
type; a missing key, or a key whose value is null, is never wrong-typed and only omits its row or leaves its field
unknown, with no token (Go runtimes emit null for an empty slice or pointer, so it is the honest common shape; a
null element inside an array the parser walks is still wrong-typed). The keys read are `/version` `Version`, `ApiVersion`, `Components`, each
`Components` element (an object) and its `Name`; `/info` as in section 6; and in a list entry `Names`, its
first element, `Image` and `State`. A wrong-typed key withholds its own field and the reply reads
`malformed` while the well-typed keys still report; a list entry keeps its row with `-` or `invalid` for the
field. A list entry that is not an object or carries no valid id is skipped and counted in the token
`list:entries_skipped`. When `/version` answers non-200, is not an object, carries a malformed
`Components` or names no runtime the dialect is not known: the later verbs still run and their `config` and `container` rows
carry `-` as the runtime, while the runtime rows are unchanged. A `/version` request that fails at the transport (refused, timed out, oversized, not HTTP)
or answers 200 with a body that is not JSON stops the action: the endpoint row says which and the
`version:<cause>` token says it was a failed read. A failed inspection (a transport or HTTP failure, a body that is not JSON, or a
wrong-typed `HostConfig.Privileged`, `NetworkMode`, `Mounts` or `Mounts[].Source`) keeps the list-derived
row with the three inspect fields `unknown` and continues; the failures are counted in one token
`inspect:failed:<n>`. An HTTP 404 on inspect (the container was removed between list and inspect) is
expected churn: fields `unknown`, no token and no constraint.

**Exceptions.** The plugin's entry point is one `try/catch(...)` at the ABI seam (the existing
`execute_action` in `virtualization_legs.hpp`, which `runtime_posture` joins as a further leg); the
plugin ABI header (`sdk/include/yuzu/plugin.hpp`) provides none, so nothing may throw across it. The
catch reports the seam's existing `unsupported` status row with its `<os>:leg:exception` token and no
body text.

## 8. Rows

```
status|runtime_posture|<supported|constrained|unsupported>|<reason|->
endpoint|<state>|<reason|->|<dialect|->
runtime|<runtime>|<detection>|<present:<mode>:<uid>:<gid>|absent|unreadable>|<present|absent|unreadable>|<version|->|<api_version|->
config|<runtime|->|<key>|<value>
container|<runtime|->|<id12>|<name>|<image>|<state>|<privileged yes|no|unknown>|<network_mode|unknown>|<host_runtime_socket_mounted yes|no|unknown>
```

`unreadable` means the `stat` failed with an error other than `ENOENT` or `ENOTDIR` (never read as
`absent`), and the status carries the token. The runtime of an `/info` `config` row or a `container` row is the dialect
`/version` identified, `-` when it did not identify one (section 7, per-response recovery); `daemon.json`
rows are always `docker`.

**binding (per-field allow-lists):** the wire escaping (`wire_field`: NUL and malformed UTF-8 to `?`,
then `\`, CR, LF and `|` handled) is the second layer, not the first. ESC and the other C0/C1 bytes and
bidi override characters pass through it, so every field that comes from a peer or a config file is
admitted only when it matches its allow-list, and otherwise reads `invalid`:

| Field | Allow-list |
|---|---|
| `state` | closed docker enum: `created`, `running`, `paused`, `restarting`, `removing`, `exited`, `dead`; anything else `invalid` |
| `name` | the first `Names` entry, `^[A-Za-z0-9][A-Za-z0-9_.-]*$` after the leading `/` is stripped |
| `image` | `^[A-Za-z0-9][A-Za-z0-9._:/@+-]*$` |
| `network_mode` | `^[A-Za-z0-9][A-Za-z0-9_.:-]*$` |
| `version`, `api_version` | `^[A-Za-z0-9][A-Za-z0-9._+-]*$` |
| `config` values | booleans render `yes`/`no`; counts are digits; string values (`data-root`, `log-driver`, `storage-driver`, `userns-remap`, `cgroup_driver`) `^[A-Za-z0-9][A-Za-z0-9/._:@+-]*$` |
| `privileged`, `host_runtime_socket_mounted` | `yes`, `no`, `unknown` only |
| `id12` | the first 12 of an id that matched `^[0-9a-f]{12,64}$` |

The `state` enum is the docker set. Whether podman's compatibility list reply ever returns a state
outside it is not verified here, and the set is never widened from memory: section 9 item 1 records the
states a real podman answers with, and the enum is amended in this note, with the code, only from that
record. Until then a podman state outside the set reads `invalid`, which is a visible gap and not a
wrong value.

The allow-lists bound the characters, not the length: a value that matches is then truncated to 256 bytes
(64 for `network_mode`, `version` and `api_version`), so an over-long name is cut, never `invalid`.
The check runs before truncation and before `wire_field`. `privileged` and `network_mode` come from the
inspect reply. `host_runtime_socket_mounted` is `yes` when any mount source of the container equals one
of the four default socket paths or is a parent directory of one (`/`, `/run`, `/var/run`, `/run/podman`,
`/run/containerd`), `no` when none is, and `unknown` when the container was never inspected (cap), inspection
failed, or the reply carried no `Mounts` (a missing or null key). `unknown` is never rendered as `no`.

## 9. Evidence the PR carries

Measured once on a Linux host (the build host's WSL2 lane) after the gates settle, recorded in the PR
body, with no probe committed:

1. A real capture with an operator-style proxy in front of a runtime: endpoint `ok`, runtime `served`;
   for podman, the container `state` strings it answers with are recorded (section 8).
2. The negative: endpoint unset gives `endpoint|unset` and detection rows, zero container rows.
3. A symlink to a default socket used as the endpoint gives `endpoint_refused` (`symlink`, from the
   `fstat` type check on the `O_PATH | O_NOFOLLOW` descriptor, before the identity check gets a
   chance). A bind mount or hard link of a default socket, which `O_NOFOLLOW` does not catch, gives
   `endpoint_refused` (`same_inode`).
4. A fake peer that sends one byte every 4 s: the action returns within the 20 s deadline, status
   `constrained` with `version:timeout` (plus `deadline_exhausted` when a further request was due; with a
   trickling `/version` the client's total timeout ends the one request and no further request is sent, so
   `deadline_exhausted` alone is not the expected token); the elapsed time is recorded.
5. `connect(2)` to a default runtime socket as an account holding only `CAP_DAC_READ_SEARCH` fails with
   `EACCES`. This note and the privilege-model row are amended with the measured fact; until then the
   claim in section 1 is an expectation from `unix(7)`.
6. `connect(2)` through `/proc/self/fd/<N>` of an `O_PATH` descriptor on a unix socket succeeds (section
   4). If it does not, the fallback and its residual are recorded here and in section 4.
7. **The negative request matrix against the evidence proxy**, each refused (non-2xx or connection
   closed) and recorded: `HEAD /version`; `POST /containers/create`; `GET /containers/<id>/logs`;
   `GET /containers/<id>/archive?path=/`; `GET /containers/<id>/export`; `GET /containers/<id>/top`;
   `GET /containers/<id>/attach/ws` with `Upgrade: websocket`; `GET /v1.41/version`;
   `GET /libpod/containers/json`; `GET /containers/%2e%2e/json`; `GET /containers/<id>/json?size=1`;
   `GET /containers/json?all=1&filters=x`; `GET http://x/version` (absolute-form); `GET /version` with
   `Transfer-Encoding: chunked` and a body; and a keep-alive connection whose second request is
   `POST /containers/create` after an admitted `GET /version`.
8. A default socket made group-connectable for the agent (a throwaway `SupplementaryGroups=` drop-in
   on a test copy of the unit) reports the `overprivileged` token.
9. **A continuously readable peer, at the real 20 s budget.** A fake peer that passes the endpoint
   contract and writes `HTTP/1.1 100 Continue\r\n\r\n` in a tight loop forever: the action returns within
   20 s plus 1 s, status `constrained`, `version:timeout`, endpoint `unreachable`; a dispatch made while it
   runs reads `busy` and one made after it returns runs normally. This is the case the client's own total
   timeout does not bound (section 5). The item 4 trickle peer is re-run alongside it to show no
   regression, and the elapsed times of both are recorded.

## 10. Recipes, packaging impact and the defer clause

**Recipes.** The note names recipe shapes, not products.

- *docker.* A forwarding proxy, running as root under its own unit that owns `/run/yuzu-agent`
  (`RuntimeDirectory=yuzu-agent`), listening on `/run/yuzu-agent/runtime.sock` (root-owned, group
  `yuzu-agent`, `0660`) and forwarding to `/run/docker.sock`, with the exact-match request filter of
  section 4 applied to every request. A proxy that cannot match the undecoded request-target byte for
  byte, or that validates only a connection's first request, is not acceptable. A docker authorization
  plugin is **not** a recipe: authorization plugins apply daemon-wide, so one that admits only the four
  requests breaks every other client of the daemon, and the daemon gives a plugin no caller identity on
  a unix socket, so it cannot be loosened for other clients without loosening it for the agent.
- *podman.* `podman system service` for the system (root) instance on a socket behind the same proxy
  contract. Running podman rootless under a dedicated service user is not recommended: it shows only that
  user's containers, so a clean answer would be misleading.
- *containerd.* Presence and `stat` only in this PR (section 2).

**Packaging impact.** Nothing in `yuzu-agent.service` changes, and no package script changes. The operator
sets `YUZU_AGENT_RUNTIME_ENDPOINT=/run/yuzu-agent/runtime.sock` in `/etc/yuzu-agent/yuzu-agent.env` (the
unit's existing `EnvironmentFile=`) or in an `Environment=` drop-in, then restarts the agent. The unit
keeps only `CAP_DAC_READ_SEARCH`; connecting needs the socket's write bit, which that capability does not
grant (section 9, item 5). The agent runs under `ProtectSystem=strict`, so `/run` is read-only to it and
it cannot create the endpoint directory itself; connecting to a socket does not need a writable
filesystem.

**Defer clause.** If the security review rejects the recipe, nothing ships: the roadmap row is recorded as
deferred, the allow-list is not weakened to make it pass, and the action is revived only when the roadmap
item that needs a container-runtime control plane is scheduled or a named customer requires it. The same
revive condition applies to the containerd CRI verbs in section 2.

## 11. Security review

**Round 1, `security-guardian` charter, against this note and the two privilege-model rows at
`466f60aa5`, before any code. Verdict: PASS-WITH-CONDITIONS, no CRITICAL findings, twelve conditions.**
Every condition was adopted; the Architect's rulings and where each landed:

| # | Severity | Condition | Disposition |
|---|---|---|---|
| 1 | HIGH | The threat table understated what a compromised agent reads; the contract does not filter response bodies | Adopted. Section 1, first row, rewritten with the true statement; **owner re-acknowledgement required** and marked there |
| 2 | HIGH | The docker authorization-plugin recipe is daemon-wide and has no unix-socket caller identity | Adopted. Recipe deleted from section 10, with the reason recorded there |
| 3 | HIGH | `GET` on four paths does not pin the raw request (other `GET` routes, versioned paths, `/libpod`, encodings, queries, keep-alive) | Adopted. Section 4 items 2-3: byte match on the undecoded origin-form target, the refusal list, per-request validation or `Connection: close`; section 9 item 7 is the recorded negative matrix |
| 4 | HIGH | Privilege rows overclaimed ("can never", "any alias", "exposes four paths and nothing else") | Adopted. Both rows reworded; "exposes" is now an operator requirement; NOT-granted lists other runtime sockets, TCP endpoints and a permissive endpoint |
| 5 | MEDIUM | Endpoint properties unchecked; the race mitigation was prose | Adapted. Section 4: `O_PATH\|O_NOFOLLOW` + `fstat` + ancestor walk + connect through `/proc/self/fd/N`, non-`ENOENT` errors refuse, 107-byte limit, the proxy's unit owns the directory. Adapted in one respect: whether `connect(2)` accepts the `/proc/self/fd` link of an `O_PATH` socket is unverified by the reviewer and by us, so section 9 item 6 measures it and names the fallback |
| 6 | MEDIUM | Hostile text passes the wire escaping | Adopted. Section 8 per-field allow-lists; `state` a closed enum; HTTP status in tokens numeric 100-599 |
| 7 | MEDIUM | Worker exhaustion: no single-flight; `stat` on a network mount has no deadline | Adopted. Section 5: process-wide single-flight returning `busy`; the `runtimes` mountinfo guard applied to data roots |
| 8 | MEDIUM | Audience misstated: stored rows are served at `Response:Read`, not `Security` | Adopted. Section 1 "Data exposure" corrected |
| 9 | MEDIUM | Docker-group membership or a `0666` socket is never detected | Adopted. Section 4 `overprivileged` token from gid and mode, no probe connect |
| 10 | LOW | Transport settings unstated; a zero total timeout is unbounded | Adopted. Section 5 transport pins: stop below 1 ms, connect `min(2 s, remaining)`, redirects off, decompression off, 1 MiB payload cap |
| 11 | LOW | Depth was claimed but not capped; no `try/catch` at the ABI seam in the SDK | Adopted. Depth 32 before the tree is built (sections 5-6); bodies and parse errors never logged; section 7 names the one `try/catch(...)` at the seam |
| 12 | LOW | `host_runtime_socket_mounted=no` covers default paths only; `root:yuzu-agent` is wrong for the dev account | Adopted. Section 8 states the default-path scope; every `root:yuzu-agent` became "root-owned, group = the agent's group" |

**Reviewer's answers recorded.** The endpoint is read-only only via an exact-match proxy (finding 3); the
inode check is sound as a guard, with the race closed by finding 5; the `/info` rows are safe; the
`Security` securable with `ExecuteGate::None` matches `system_hardening`; keeping validation out of the
command-line library is right.

**Could not verify (reviewer), carried into section 9:** `connect(2)` versus `CAP_DAC_READ_SEARCH`
(item 5); `connect` via `/proc/self/fd/N` on an `O_PATH` socket (item 6); `RuntimeDirectory=`
ownership under `ProtectSystem=strict` (from `systemd.exec(5)`, hence the "proxy's unit owns the
directory" rule); docker's path cleaning and `%2F` handling and `/info` credential masking (item 7
covers the encodings; the `/info` reader touches three keys only); podman's `Components[].Name` and
its `/libpod` `GET` routes (item 7); the HTTP client version on the Linux triplet (the build checks
it); whether the dispatch pool gives protective actions priority (not relied on: single-flight bounds
this action regardless).

**Corrections made against the code while applying the conditions.** (a) The seam is `execute_action`
(with a `Legs` table), not `execute_host`; section 7 now names it. (b) `open(O_PATH | O_NOFOLLOW)` does
not fail with `ELOOP` on a symlink leaf, it returns a descriptor for the link, so the `symlink` refusal
comes from the `fstat` type check (section 4, section 9 item 3). (c) The HTTP client treats a total
timeout of zero or below as unbounded (its default is zero), so the pin is "never zero or negative"
(section 5). (d) The depth limit is a parse callback that discards the over-deep part and marks the
reply malformed; it does not stop the scan of a body already capped at 1 MiB (sections 1, 5, 6).

**Corrections made against the code during the gate 1 code review.** (e) A failed or slow read could
answer `OK` and `FULL` with no container rows: a trickling or oversized `/version`, a wrong-typed `/info`,
and an endpoint that was refused, absent or denied at its stat or open each set the endpoint row and no
token. The code now adds a token for each (`version:<cause>`, `info:malformed`, `endpoint:<cause>`) and the
note changed, not the mapping, where it said otherwise: the `unreachable` and `not_http` definitions and
the result-status list (section 7), the `-` runtime on `config` and `container` rows after a non-200
`/version` and the `unreadable` field values (section 8), at most three `/info` rows (section 6),
`list:entries_skipped` and the verb names in tokens (section 7), the `overprivileged` condition including
the group-write bit (section 4) and section 9 item 4. (f) The 1 MiB cap is enforced by a declared-length
check and the receiver ahead of the client's own payload cap, which sits one read buffer above it
(section 5). (g) The shell connects only through the checked descriptor; the earlier per-request retry by
path is gone (section 4, section 9 item 6). (h) A default-socket `stat` failure does not refuse the
endpoint; the residual is recorded in section 4. (i) The wrong-typed class was closed across every JSON
reader in one rule (section 7, per-response recovery): a wrong-typed `/version` key, a non-string
`SecurityOptions` element, a wrong-typed list-entry key, a wrong-typed inspect key and a wrong-typed
`daemon.json` key each add a token and withhold their own field, so none reads as `no` or answers a clean
`OK`; the well-typed keys still report in every reader.

**Binding statements for the build (every one is marked `binding` above):** the list-reply allow-list
(section 2); the `O_PATH|O_NOFOLLOW` open, `fstat` properties, ancestor walk, connect through
`/proc/self/fd/N`, non-`ENOENT` errors refuse, 107-byte limit (section 4); the `overprivileged` check
without a probe connect (section 4); the transport pins, single-flight `busy`, the 32-level depth limit,
no body or parse-error logging, and the network-filesystem `stat` guard (section 5); the at-most-three `/info`
rows (section 6); the per-field allow-lists and numeric HTTP status in tokens (section 8); the one
`try/catch(...)` at the ABI seam (section 7). The verb allow-list itself was not weakened.
