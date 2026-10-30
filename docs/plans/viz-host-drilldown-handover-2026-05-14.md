# Handover — viz host drill-down, trigger-engine fix, Cedar & Vale rig — 2026-05-14

**Branch:** `feat/viz-engine`. **All work this session is committed** — 5 commits
on top of `6415f64`, plus this handover. **Not yet pushed** to
`origin/feat/viz-engine`. The Cedar & Vale demo rig is live and the new builds
are deployed to it.

---

## Commits this session (6415f64..HEAD)

| sha | commit |
|---|---|
| `9640688` | `fix(agent)`: wire the trigger engine so interval triggers actually fire |
| `a6b808c` | `feat(echo)`: widen fleet_snapshot to connections seen within a window |
| `ad1fc5c` | `fix(gateway)`: replay agent registrations on upstream reconnect |
| `dcd10d7` | `feat(server,viz)`: per-host IPC-graph drill-down + tier & cache fixes |
| `6076d77` | `chore(uat)`: start-viz-uat.sh cedar-vale mode for the 3-VM rig |
| _(this doc)_ | `docs`: handover |

Each commit is self-contained and builds. Full macOS build green; per-thread
test suites green (see each thread below). **Not pushed** — `git push` is the
operator's call.

---

## What shipped

### `9640688` — Trigger-engine wiring fix (highest-impact)

`yuzu_register_trigger` was a no-op stub; no `TriggerEngine` was instantiated;
`start()` was never called — so `collect_fast` / `collect_slow` / `rollup` never
ran for **any** plugin agent-wide, and the Echo warehouse (`*_live` tables) sat
permanently empty in the field. Fixed: `parse_trigger_config()` (new, 5 tests),
`yuzu_register_trigger`/`yuzu_unregister_trigger` rewired, `TriggerEngine`
instantiated + dispatch + start/stop. **All 384 agent tests pass.** Verified
live: `collect_fast` fires every 60 s, `*_live` tables populate.

### `a6b808c` — Echo `last_seen_seconds_ago` connection-memory

`echo.fleet_snapshot` now merges live `/proc` connections with recently-seen ones
from the `tcp_live` warehouse. `query_recent_tcp_connections`,
`merge_live_and_recent_connections`, `NetConnection.last_seen_seconds_ago`,
`fleet_snapshot.v1` `schema_minor` 1→2, operator-tunable
`fleet_snapshot_window_seconds`. Tests in `test_echo_store.cpp` +
`test_fleet_snapshot.cpp`. **Issue #1019** filed: the 60 s sampler still can't
see sub-interval connections — that needs kernel eventing.

### `ad1fc5c` — Gateway replay agent registrations on upstream reconnect

When the gateway's upstream link to the server re-established, it reconnected
the transport but never re-proxied held agent registrations — a restarted
server came up with an empty registry while the gateway still held the agent
connections, stranding them. Fixed: on upstream recovery (`half_open→closed`,
*or* a `closed`-state success with prior failures — the latter is the actual
observed bug: idle agents + fast recreate never trip the 5-failure threshold),
`yuzu_gw_upstream` self-paced-drips a `ProxyRegister` per held agent, 20 ms
apart, circuit-gated. Registry stashes the verbatim `RegisterRequest` (carries
the `enrollment_token` the flattened registry fields can't reconstruct). **5 new
eunit tests; eunit 135 passed / 0 failed; dialyzer clean.** Server-side
`ProxyRegister` idempotency confirmed safe — it has an explicit
"already-enrolled → re-register, return OK" fast path, so replays never trip the
breaker. **Caveat:** a future hot upgrade from a pre-change build needs a real
`code_change/3` (registry ETS row 7→8-tuple; upstream state record +2 fields).

### `dcd10d7` — Per-host IPC-graph drill-down + tier & cache fixes

Double-clicking a cube in `/viz/fleet` opens `/viz/host/<agent_id>` in a new
tab: a 2D bipartite IPC graph (Cytoscape, built-in `cose` layout) over the Echo
process tree. Slices 1–4 (server endpoints + `HostTopologySnapshot` wire type;
`yuzu-viz-host.js` renderer + vendored `cytoscape.min.js`; 3D dblclick +
heartbeat flash + new-tab; cross-pane sync + resizable splitter). **24 viz-host
test cases pass.** Plus two fixes folded in:
- **WEB_PORTS trimmed** — dev-server ports (3000/4200/5173/8000) no longer score
  as "web", so a node app on `:3000` classifies app-tier not frontend. **Issue
  #1018** tracks the deeper function-aware classification problem.
- **`yuzu-viz.js` + `yuzu-viz-host.js` served `no-cache`** — renderer code
  changes every viz PR; a `max-age` silently served a stale renderer for up to
  24 h. Vendored libs (`cytoscape.min.js`, `three.*`) keep `max-age` —
  content-stable.
- **fcose → built-in `cose`** — `cytoscape-fcose` is a UMD bundle with an
  unresolvable `cose-base` dependency against an ESM importmap. `cose` is
  force-directed and ships in cytoscape core; no extension, no dependency tree.

### `6076d77` — `start-viz-uat.sh` cedar-vale mode

`VIZ_UAT_AGENT_MODE=cedar-vale` registers agents on the three Alpine OrbStack VMs
that model the fictional Cedar & Vale three-tier company. Re-writes each VM's
`run-agent.sh` with the fresh enrollment token via `orb -u root`, restarts the
agent, waits for registration.

---

## Demo environment — current state (deployed + verified)

**Three OrbStack Alpine VMs** model Cedar & Vale:
`yuzu-frontend` (nginx `:80`) → `yuzu-app` (nodejs `:3000`) → `yuzu-db`
(postgres `:5432`). VM→host = `192.168.139.2`.

**Deployed this session, all verified live:**
- viz-UAT **server** + **gateway** containers rebuilt from the committed source
  and recreated. `/viz/fleet` topology: 3 machines, **correctly tiered**
  (app / database / frontend). `no-cache` headers confirmed on both renderer
  bundles. Gateway shows 3 agents registered; `yuzu_fleet_agents_healthy = 3`.
- All 3 VM agents restarted onto the committed-source builds
  (`libyuzu_agent_core.so` = trigger-engine fix, `echo.so` = last_seen merge),
  re-registered through the rebuilt gateway.
- **`yuzu-db`**: PostgreSQL fixed earlier this session — `/etc/conf.d/postgresql`
  points `data_dir` + `conf_dir` at `/var/lib/postgresql/data` (the real
  cluster); added to the `default` runlevel. `/customers` serves the 3-row
  customer list.
- **`yuzu-frontend`**: nginx upstream `keepalive 16` added
  (`default.conf.bak-pre-keepalive` is the backup).
- **`yuzu-app`**: `/opt/app/server.js` `keepAliveTimeout = 75000` /
  `headersTimeout = 76000` (`server.js.bak-pre-keepalive` backup), `corp-app`
  restarted. Verified: an nginx→app connection now survives 15 s+ post-request
  (was 5 s) — outlives both the 30 s snapshot pump and the 60 s `collect_fast`.

### Blue tubes (cross-VM edges) need live traffic — they are NOT automatic

A blue tube only renders for an `internal_fleet`-scope connection — one cube's
ESTABLISHED outbound socket whose `remote_addr` is another fleet VM's IP. After
*any* agent or server restart there are **zero** inter-VM connections (verified:
`internal_fleet=0` on all three right after the deploy) — the keepalive pools
don't exist until a request flows through. The renderer is working; there's just
nothing to draw.

To light them up: send **~90 s of sustained traffic** to the frontend (longer
than one `collect_fast` cycle) —
`for i in $(seq 1 45); do curl -s -o /dev/null http://192.168.139.141/customers; sleep 2; done`.
Each request warms nginx→app (held ~75 s by the keepalive + `keepAliveTimeout`
bump) **and** app→db (node-pg pool, ~10 s idle) — traffic every 2 s keeps both
continuously warm across a `collect_fast` cycle, so they land in `tcp_live` and
the `last_seen_seconds_ago` merge then carries them for the full 1-hour window
after the traffic stops. This is the "refresh for a minute → good for an hour"
behaviour; it works now because all four enablers landed this session (nginx
keepalive, the `keepAliveTimeout` bump, the `last_seen` merge, and the trigger
fix that makes `collect_fast` actually run).

---

## Open / next

1. **Push.** `git push origin feat/viz-engine` — not done; operator's call.
2. **Visual UAT — still not done.** Per `feedback_visual_features_need_visual_proof`,
   the viz slices need a human to eyeball the rendered result. Hard-refresh is no
   longer needed for *future* changes (the `no-cache` fix), but the browser still
   has the pre-fix cached `yuzu-viz.js` — do **one** `Cmd+Option+R` on `/viz/fleet`
   first. Then confirm: three correctly-tiered cubes; double-click a cube → host
   page → IPC graph renders with `cose`, Echo tree below, splitter drags,
   cross-pane highlight works. **For the blue cross-VM tubes specifically, run the
   ~90 s traffic loop first** (see "Blue tubes" under Demo environment) — they are
   not automatic and will be absent on a freshly-restarted rig. (The host page
   already had its renderer verified served as `cose`; the visual itself is
   unconfirmed.)
3. **Governance.** None of the 5 commits has been through `/governance`. Slices
   1–4 want docs-writer gate work; the trigger fix, Echo `last_seen`, and gateway
   replay each warrant a review pass.
4. **Gateway hot-upgrade `code_change/3`** — see the `ad1fc5c` caveat; needed
   before the next release that hot-upgrades a pre-change gateway.
5. **Plan file** `~/.claude/plans/when-an-analyst-selects-curious-spring.md` is
   stale on the fcose detail (predates the cose switch) — cosmetic.

---

## Operational gotchas (carried forward)

- **`source scripts/ensure-erlang.sh` breaks the Bash-tool shell** — every
  command starting with it produces total silence + exit 1 (it appears to `exit`
  in a sourced path). `erl` + `rebar3` are already on PATH via Homebrew — just
  call `rebar3` directly from `gateway/`.
- **zsh doesn't word-split unquoted variables** — `git add $FILES` passes the
  whole string as one pathspec. List paths inline.
- **Pre-commit `clang-format` hook reformats staged C++ then fails the commit** —
  the commit didn't happen; re-`git add` the (now-formatted) files and commit
  again. Erlang/shell/JS files aren't touched by it.
- **`orb` + backgrounded services** — `rc-service <svc> start` as the last
  command in a short-lived / stdin-redirected `orb ... sh -c` gets the daemon
  SIGHUP'd on session close. Run each `rc-service start` as its own standalone
  `orb` call.
- **`rc-service yuzu-agent restart` is unreliable** (slow graceful shutdown trips
  `start-stop-daemon`). Use `pkill -9 -f /opt/yuzu/yuzu-agent` → `rc-service zap`
  → standalone `rc-service start`.
- **Server-recreate → agent recovery:** with `ad1fc5c` deployed the gateway now
  replays registrations on reconnect, so recreating the server *should* no
  longer strand agents. Until that's been exercised in anger, the safe sequence
  is still: recreate server + gateway → restart the 3 VM agents.
- **Alpine `ss` is unreliable** on these VMs — read `/proc/net/tcp` +
  `/proc/net/tcp6` directly. nginx connects to a bare IPv4 literal → AF_INET →
  it's in `/proc/net/tcp`.

## Verification commands

```bash
docker ps --filter name=yuzu-viz
curl -fsS http://localhost:8080/login -d 'username=admin&password=adminpassword1' -c /tmp/ck.txt -o /dev/null
curl -fsS -b /tmp/ck.txt http://localhost:8080/api/v1/viz/fleet/topology | python3 -m json.tool | head -40
curl -sI http://localhost:8080/static/yuzu-viz.js | grep -i cache-control   # expect: no-cache
for vm in yuzu-frontend yuzu-app yuzu-db; do
  orb -u root -m "$vm" sh -c 'grep -c "Trigger .echo.fast. fired" /var/log/yuzu-agent.log'
done
```

## GitHub issues filed

- **#1018** — viz: function-aware tier classification (port heuristics
  misrepresent real three-tier topologies)
- **#1019** — echo: short-lived connections need kernel eventing (sampled-diff
  can't capture them)
