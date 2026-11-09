# `virtualization.runtime_posture`: read-only container-runtime posture

**Status:** design, written before any code. The privilege change it describes was approved by the
owner on 2026-11-08. Nothing below is built yet: where this note says the plugin "does" something it
describes the code to be written in this PR, and every qualifier is meant to stay true of that code.
Any difference found in review is fixed in the note or the code, never left standing.

Related: [`agent-privilege-model.md`](agent-privilege-model.md) (the privileged-actions row and the
"Deliberately NOT granted" row for this action), `agents/plugins/virtualization/` (the plugin),
`deploy/systemd/yuzu-agent.service` (the packaged unit, not changed by this work).

## 1. Scope and threat model

**What it is.** A new Linux-only action `runtime_posture` on the `virtualization` plugin. It answers:
which container runtimes (docker, podman, containerd) are present on this device, how are they
configured from a security point of view, and which containers exist and with what risky settings.

**What it is not.** It never creates, starts, stops, execs into, attaches to or removes anything. It
never reads a container's environment, command line, labels, ports or any mount other than the one
host-socket flag defined in section 8. macOS and Windows answer one `unsupported` status row.

**Opt-in.** With no endpoint configured (the default) the plugin never opens a socket. It still reports
what it can learn from `stat` and a bounded config read (section 6), because those need no new access.

**The privilege change.** The agent gains one new ability: `connect(2)` to a single, operator-provided
unix socket, and to send four fixed `GET` requests over it (section 3). That is a read access to a
container runtime control plane, so it is security-gated (this note, a security review before any code,
and the owner's approval of both).

**Threat model.** The asset is the host. A container runtime's control socket is root-equivalent when it
accepts writes: whoever can start a privileged container with `/` mounted owns the machine. So the design
assumes the agent process may be compromised and asks what it can do with the access it is given.

| Actor and move | Why it cannot do more than read |
|---|---|
| A compromised agent holding the endpoint | The endpoint exposes four `GET` paths. It can read container names, images, states and the six posture fields, and the runtime configuration keys in section 6. It cannot create, exec into, attach to or stop anything, because the operator's proxy (section 4) refuses every other method and path. |
| A compromised agent trying to reach the real socket | The four default sockets are `root`-owned (docker's is `root:docker`). The agent account is not in the `docker` group and is not granted any capability that bypasses socket permissions. The packaged unit's only capability is `CAP_DAC_READ_SEARCH` (read and directory search, not write); `connect(2)` on a unix socket needs write permission on the socket. This is the expected behaviour under `unix(7)` and is confirmed on a real host before release (section 9). |
| A compromised agent changing its own configuration | The endpoint comes from `/etc/yuzu-agent/yuzu-agent.env` (`root:root 0600`) or a unit drop-in, both root-owned. The agent process cannot write either. |
| An operator who points the endpoint at a default socket by mistake | Refused and reported as `endpoint_refused` (section 4). The refusal is a structural guard, not the enforcement. |
| A hostile or broken peer on the endpoint (huge reply, trickling bytes, never answers) | Bounded by a 1 MiB body cap, 2 s connect and 5 s inactivity timeouts, and a 20 s overall action deadline (section 5). |
| Hostile JSON from the peer (wrong types, deep nesting, huge arrays) | Parsed without exceptions and with accessors that tolerate a wrong type; counts and field lengths are capped (section 5). |

**Data exposure.** Container names and image references reach the server as device-scope rows readable by
the readers of the `Security` securable. Environment, command line, labels, ports and non-socket mounts
are never emitted. If container names are judged too sensitive, the row shape changes (the owner chose
to ship them on 2026-11-08).

## 2. Verb table: the only requests the agent can send

The agent builds requests from a fixed table indexed by an enum, never from a string. There is one
constructor of a request, `build_request(Verb, container_id)`, and the method is `GET` in every row.

| Verb | Request | Used for |
|---|---|---|
| `version` | `GET /version` | endpoint liveness, runtime dialect (docker or podman), version and API version |
| `info` | `GET /info` | runtime-reported posture facts, emitted as `config` rows from a fixed key allow-list (section 6) |
| `containers_list` | `GET /containers/json?all=1` | the container list |
| `container_inspect` | `GET /containers/{id}/json` | privileged flag, network mode, socket-mount flag for one container |

These are the unversioned Docker-compatible paths, which podman's compatibility API also serves.
`{id}` is substituted only after it matches `^[0-9a-f]{12,64}$` (taken from the list reply); an id that
does not match, or an id given to any other verb, produces no request. A compile-time check pins the
table size to the enum. There is no fifth verb and no way to build a request outside this table.

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

1. One unix stream socket, owned `root:yuzu-agent`, mode `0660`, in a directory the agent can traverse
   and that is not covered by the unit's `PrivateTmp` (so not under `/tmp`). A path under
   `/run/yuzu-agent/` is the convention used in the recipes below.
2. It accepts `GET` on exactly the four paths in section 2 and refuses every other method and every
   other path, including `POST`, `PUT`, `DELETE`, `HEAD`, upgrades (`Connection: Upgrade`, hijacked
   `attach` and `exec` streams) and any query other than `all=1` on the list path.
3. It forwards to the runtime's own API socket, so the answer is the runtime's, not a copy.
4. It adds no credentials the agent could reuse. The agent sends none.

**What the agent enforces, and what it does not.**

The agent refuses to use as an endpoint:

- a relative path, or one containing a `..` segment;
- any of the four default sockets: `/run/docker.sock`, `/var/run/docker.sock`,
  `/run/podman/podman.sock`, `/run/containerd/containerd.sock`. The path is first normalised lexically
  (repeated `/` collapsed, `/./` segments removed, a trailing `/` stripped), so `//run//docker.sock`,
  `/run/./docker.sock` and `/var/run/docker.sock/` are refused as the same path;
- any path whose `stat` identity (`st_dev`, `st_ino`) equals that of a default socket that is present on
  the host, which closes symlink and bind-mount aliases of those sockets.

Each refusal is reported as `endpoint_refused` with a reason, and the transport is never invoked.

**The limits of that refusal, stated plainly.** It is a structural guard that stops the shortcut the
privilege model forbids (pointing the agent at the real socket). It is not the security boundary:

- The identity check and the later `connect` are two separate system calls, so an attacker who can
  replace the endpoint path between them (a writable directory) could win a race. The operator's
  directory for the endpoint must therefore be root-owned and not writable by the agent.
- Inode comparison only sees default sockets that exist when the action runs, and only the four known
  paths. A runtime socket at another path is not known to the agent.
- The enforcement is the socket's permission bits (`root:yuzu-agent 0660`, so only the agent and root can
  connect) and the operator's proxy or authorization layer (only the four `GET`s get through). If the
  proxy is permissive, a compromised agent reaches whatever it permits. The agent's own verb table limits
  what an uncompromised agent sends; it cannot limit a compromised one.

## 5. Bounds

| Bound | Value | Behaviour when hit |
|---|---|---|
| Action deadline | 20 s total, monotonic clock | No further requests are issued; every completed row is kept; token `deadline_exhausted`; status `constrained`, completeness `partial` |
| Per-request budget | the time remaining of the 20 s, applied with the HTTP client's per-request total timeout | a request over budget ends as a timeout |
| Connect timeout | 2 s | `unreachable` |
| Read inactivity timeout | 5 s | the request fails |
| Response body | 1 MiB, enforced by a receiver that stops reading | token `response_oversized`; no rows from that verb |
| Container rows | at most 256 | token `rows_capped` |
| Inspections | at most 64, taken from the first 64 listed | token `inspect_capped`; the rest read `unknown` |
| `daemon.json` | read at most 256 KiB | token `oversized` |
| Free-text field | truncated to 256 bytes before escaping | silent (the cap is documented, not an error) |

The read timeout alone does not bound a peer that sends one byte just inside each window, which is why
the overall deadline exists: before each request the plugin computes the remaining budget from an
injected clock, passes it to the transport, and stops issuing requests at zero. The worst case is three
fixed requests plus 64 inspections (67 requests) inside 20 s; a healthy local socket answers all of them
in well under a second. The action holds one agent worker for at most 20 s. The deadline logic is unit
tested with a fake clock (no sleeps); the real transport's behaviour against a trickling peer is
measured once on a real host and the elapsed time is recorded in the PR (section 9).

**Output size.** One status row, one endpoint row, three runtime rows, at most one config row per
allow-listed key, and at most 256 container rows of about 800 bytes in the worst case (256 bytes per
free-text field is the ceiling for name and image; the other fields are short). That is about 200 KiB,
against the agent's 2 MiB output capture cap.

## 6. What is read without the endpoint

No subprocess, no `PATH` walk. Per runtime, `stat` of the default socket(s), the config file(s) and the
data root; ownership and mode of a socket are reported, nothing else about it.

| Runtime | Config looked for | Data root | Default socket(s) |
|---|---|---|---|
| docker | `/etc/docker/daemon.json` | `/var/lib/docker` | `/run/docker.sock`, `/var/run/docker.sock` |
| podman | `/etc/containers/containers.conf`, `/etc/containers/storage.conf`, `/etc/containers/registries.conf` | `/var/lib/containers` | `/run/podman/podman.sock` |
| containerd | `/etc/containerd/config.toml` | `/var/lib/containerd` | `/run/containerd/containerd.sock` |

`daemon.json` is parsed with the JSON library in non-throwing mode (comments ignored) and only an
allow-list of posture keys is emitted: `live-restore`, `userns-remap`, `no-new-privileges`, `icc`,
`iptables`, `tls`, `tlsverify`, `data-root`, `log-driver`, `storage-driver`, `selinux-enabled`,
`userland-proxy`. `hosts` is reduced to a count and a `hosts_tcp yes|no` flag (any `tcp://` listener);
`insecure-registries` and `registry-mirrors` are reduced to counts. Every other key, including anything
that looks like a credential, is dropped and never emitted. A key with a value of the wrong type is
skipped. Malformed JSON reports `config|docker|daemon_json|malformed` and a constraint token.
The `/info` reply (when an endpoint is configured) is treated the same way: parsed without exceptions, a fixed allow-list
of posture keys (rootless, cgroup driver, the count of security options) is emitted as `config` rows, everything else is dropped.
The TOML files are presence and `stat` only: no hand-written TOML parser is added, so podman's and
containerd's own configuration contributes little posture in this PR.

## 7. Statuses

Attribution is split in two so every outcome has exactly one owner.

**The `endpoint` row owns the endpoint outcome:**

`endpoint|<state>|<reason>|<dialect>` where `state` is one of:

| State | Meaning |
|---|---|
| `unset` | no endpoint configured; no socket was opened |
| `endpoint_refused` | the configured value was refused (relative, `..`, default socket, or same inode); `reason` says which |
| `permission_denied` | `connect` failed with `EACCES` or `EPERM` |
| `unreachable` | `ENOENT`, `ECONNREFUSED` or a connect timeout |
| `not_http` | connected, but `/version` was not a parseable HTTP reply with a JSON body (for example a containerd socket) |
| `ok` | `/version` answered; `dialect` is `docker` or `podman` (from the `Components[].Name` of the reply; `Podman Engine` means podman) |

**Each `runtime` row carries only detection facts:**

`runtime|<docker|podman|containerd>|<detection>|<default socket>|<config>|<version>|<api_version>`

| Detection | Meaning |
|---|---|
| `not_detected` | none of that runtime's standard-path artefacts exists (socket, config, data root) |
| `detected` | at least one standard-path artefact exists |
| `served` | the endpoint's `/version` identified this runtime; `version` and `api_version` are filled only on this row |

`not_detected` is a statement about the standard paths, not proof of absence. A stopped runtime, a
rootless runtime and a custom-root install can all read `not_detected`, and the contract text in the
README says so. An endpoint failure never changes any runtime row.

The result status is `OK` and `FULL` unless a read failed (a refused `stat` or `daemon.json` read, an
oversized or malformed reply, a non-200 reply, a cap, or the deadline), in which case it is
`CONSTRAINED` and `PARTIAL` through the shared constraint accumulator. An endpoint that is merely
unset is not a constraint. Tokens follow the plugin's grammar
`linux:virtualization:runtime_posture:<source>:<cause>`.

**Per-response recovery.** A non-200, malformed or wrong-typed `/version`, `/info` or list reply yields
unknown fields for that verb plus one token `<verb>:http_<status>` or `<verb>:malformed`; earlier rows are
kept and later verbs still run while budget remains. A failed inspection keeps the list-derived row with
the three inspect fields `unknown` and continues; the failures are counted in one token
`inspect:failed:<n>`. An HTTP 404 on inspect (the container was removed between list and inspect) is
expected churn: fields `unknown`, counted as `inspect:vanished:<n>`, no constraint.

## 8. Rows

```
status|runtime_posture|<supported|constrained|unsupported>|<reason|->
endpoint|<state>|<reason|->|<dialect|->
runtime|<runtime>|<detection>|<present:<mode>:<uid>:<gid>|absent>|<present|absent>|<version|->|<api_version|->
config|<runtime>|<key>|<value>
container|<runtime>|<id12>|<name>|<image>|<state>|<privileged yes|no|unknown>|<network_mode|unknown>|<host_runtime_socket_mounted yes|no|unknown>
```

Every free-text field goes through the plugin's wire escaping before it is written. `privileged` and
`network_mode` come from the inspect reply. `host_runtime_socket_mounted` is `yes` when any mount source
of the container equals one of the four default socket paths or is a parent directory of one (`/`, `/run`,
`/var/run`, `/run/podman`, `/run/containerd`), `no` when none is, and `unknown` when the container was
never inspected (cap) or inspection failed. `unknown` is never rendered as `no`.

## 9. Evidence the PR carries

Measured once on a Linux host (the build host's WSL2 lane) after the gates settle, recorded in the PR
body, with no probe committed:

1. A real capture with an operator-style proxy in front of a runtime: endpoint `ok`, runtime `served`.
2. The negative: endpoint unset gives `endpoint|unset` and detection rows, zero container rows.
3. A symlink to a default socket used as the endpoint gives `endpoint_refused` (identity check).
4. A fake peer that sends one byte every 4 s: the action returns within the 20 s deadline with
   `deadline_exhausted`; the elapsed time is recorded.
5. `connect(2)` to a default runtime socket as an account holding only `CAP_DAC_READ_SEARCH` fails with
   `EACCES`. This note and the privilege-model row are amended with the measured fact; until then the
   claim in section 1 is an expectation from `unix(7)`.

## 10. Recipes, packaging impact and the defer clause

**Recipes.** The note names recipe shapes, not products.

- *docker.* A forwarding proxy that listens on `/run/yuzu-agent/runtime.sock` (`root:yuzu-agent 0660`) and
  forwards to `/run/docker.sock`, with a method-and-path allow-list of the four `GET`s; or a docker
  authorization plugin that admits only those four requests on the daemon socket and is combined with a
  proxy socket for the agent. A proxy that cannot restrict by method and path is not acceptable.
- *podman.* `podman system service` for the system (root) instance on a socket behind the same proxy
  contract. Running podman rootless under a dedicated service user is not recommended: it shows only that
  user's containers, so a clean answer would be misleading.
- *containerd.* Presence and `stat` only in this PR (section 2).

**Packaging impact.** Nothing in `yuzu-agent.service` changes, and no package script changes. The operator
sets `YUZU_AGENT_RUNTIME_ENDPOINT=/run/yuzu-agent/runtime.sock` in `/etc/yuzu-agent/yuzu-agent.env` (the
unit's existing `EnvironmentFile=`) or in an `Environment=` drop-in, then restarts the agent. The unit
keeps only `CAP_DAC_READ_SEARCH`; connecting needs the socket's write bit, which that capability does not
grant (section 9, item 5). The agent runs under `ProtectSystem=strict`; connecting to a socket does not
need a writable filesystem.

**Defer clause.** If the security review rejects the recipe, nothing ships: the roadmap row is recorded as
deferred, the allow-list is not weakened to make it pass, and the action is revived only when the roadmap
item that needs a container-runtime control plane is scheduled or a named customer requires it. The same
revive condition applies to the containerd CRI verbs in section 2.

## 11. Security review

Pending. Reviewed against the `security-guardian` charter before any code is written; the verdict and
each finding, with how it was resolved, are recorded here.
