# ADR-0073: A liveness-only heartbeat over an opaque gateway relay: status tags as deltas, topology on its own RPC, registration replay by ids

- **Status:** Proposed
- **Date:** 2026-10-29. First drafted 2026-10-26; revised 2026-10-29 for ADR-0074 and the merged PR #5695.
- **Authors:** Nathan Dornbrook (platform block `0xxx`; see `docs/adr/README.md`)
- **Deciders:** Nathan Dornbrook. Owner rulings of 2026-10-26:
  - adopt the architect's heartbeat/topology split;
  - no backward compatibility;
  - jitter everything;
  - fold the status-tag shrink into this ADR;
  - the gateway is an opaque relay. As reworded on 2026-10-28 for both this ADR and ADR-0074: the
    gateway keeps **no per-agent state beyond the connection**. Fleet-level state that any gateway
    could rebuild (ADR-0074's cached CRL, drain flag, gateway list and cluster membership) is allowed;
  - fold in S1: registration replay by ids only;
  - no proto subtraction: "proto subtractions are breaking, so we should just not use the field, not
    remove it from the protobufs" (recorded in #6555 and enforced by `proto/buf.yaml`).

  The reviewers this ADR routes to are listed under *Routed concerns*.
- **Amends:** `docs/fleet-viz-invariants.md` "Push-ingestion invariants — PR 10". That section is the
  only design record for the current topology vehicle, which arrived in `ba7e34a8d` (2026-05-12,
  merged in PR #1032) with no ADR.
- **Related:**
  - ADR-0074 (`0074-gateway-transport-security-and-topology.md`, PR #6703): its D14 sets the gateway
    budget this ADR is measured against, its D5 decides which messages are signed, and its Conflicts
    items 4 and 5 are resolved by this revision.
  - ADR-0016 (`0016-agent-daily-sync-framework.md`): its "cost tracks change" principle, not its
    transport.
  - ADR-0021 Decision 5: built-in schedules become Reflexes.
  - ADR-0069: the owned gRPC gateway over Cowboy and gun (PR #5695, merged).
  - ADR-2002: the stuck heartbeat-batch incident, WS-0 command dedup, and WS-4 route adoption.
  - ADR-0034: held-open connection scaling.
  - ADR-0066: gRPC stays the transport.
- **Depends on:** ADR-0074 (PR #6703) being ratified, for the budget (D14) and the signing scope (D5).
  Every code reference below is cited at `origin/dev` `dfdffa4c0`, which includes PR #5695.

## Decision

1. **The heartbeat becomes a liveness message.** It carries `session_id`, `sent_at`, a
   `StatusTags` delta serialized into an **opaque `bytes` field** the gateway never decodes (D2),
   and a ~70-byte `TopologyDigest` (D5).
   - "Liveness-only", here and in the title, means no bulk body. The heartbeat still carries
     liveness plus state-tag deltas and a topology digest, and that state content is not signed
     (D16).
   - `fleet_snapshot_json` (field 4) is **no longer used**.
   - The flat `status_tags` map (field 3) is **no longer used** either. It is replaced, not extended.
   - Both stay in the proto, marked `[deprecated = true]` with a comment naming ADR-0073 (D15). The
     agent stops populating them and every receiver ignores them. Nothing parses the old fields and
     nothing falls back to them.
2. **Status tags are split by how they change** (D1).
   - **Six interval tags** (`yuzu.perf_*`, `yuzu.net_*`) are measured over each heartbeat interval.
     They are sent **whole on every beat** with replace semantics, exactly as today.
   - Every other tag is **state**. Register sends the full state set, and each heartbeat sends only
     the state tags that changed since the last acknowledged beat, plus explicit removals and a
     digest of the agent's full state set.
3. **The server detects divergence on every heartbeat.** It recomputes the state-set digest over its
   merged view after applying the delta, using one shared, pure function (D3). If the digests
   differ, or the server has no base, it asks for the full set.
4. **The topology body moves to a new unary RPC, `AgentService.ReportTopology`**, proxied by the
   gateway as `GatewayUpstream.ProxyTopology`. It is sent when the topology digest changes, when a
   jittered 15-minute floor expires, at agent start, or on server request (D5-D7).
5. **The server derives topology liveness from the heartbeat's digest**, not from body arrival. The
   90 s stale rule and the 300 s IP-claim reclaim keep their meaning, keyed on server receipt of a
   *confirming heartbeat* (D6).
6. **One resync mechanism serves both: a system-only reserved Subscribe command, `__resync__`**
   (actions `tags` and `topology`). It is rate-limited at the server, and the gateway relays it like
   any other command (D8).
7. **The gateway is an opaque relay for everything this ADR introduces** (D4):
   - no per-agent state beyond the connection;
   - no parsing, validation or composition of tag deltas or digests;
   - heartbeat-buffer coalescing is keep-newest over whole heartbeats;
   - it retains **less** than before: with D14 it no longer keeps the RegisterRequest at all.

   The existing gateway tag checks move to the server, so the gateway does *less* than today.
8. **Everything periodic is jittered and nothing is clock-aligned** (D9).
9. **The fleet-wide pull paths go away** (D10):
   - the server's legacy `tar.fleet_snapshot` dispatch fetcher;
   - the gateway heartbeat buffer's snapshot handling.
10. **The topology pump stays an agent-core thread**, made tunable and disableable now. Converting
    it to an ADR-0021 Reflex is deferred (D11).
11. **Server-pull when `/viz` is viewed is not adopted** (D12).
12. **The gateway no longer keeps the RegisterRequest** (D14). Today it holds it three times. On an
    upstream reconnect or a server "unknown session" verdict, it sends **ids only**: a new
    `GatewayUpstream.ProxyReattach{agent_id, session_id, observed_peer}`.
    - The server rebuilds the session from a new durable, born-on-Postgres
      `AgentRegistrationStore`, written at every successful registration.
    - If that record is missing or unreadable, the gateway closes the agent's stream and the agent
      registers again on its own.
    - Enrollment tokens are no longer retained in gateway memory. A Register's token still passes
      through the gateway transiently, while the request is decoded and forwarded.
13. **The agent's reconnect backoff gets full jitter** (D9). Today it is a pure power of two, which
    phase-aligns the fleet after a mass disconnect.
14. **No proto subtraction; deprecate and ignore** (owner ruling 2026-10-26). A field, RPC or message
    this ADR retires stays in the `.proto`: fields are marked `[deprecated = true]`, RPCs and messages
    `option deprecated = true;`, each with a comment naming ADR-0073. Senders stop populating them
    and receivers ignore them; a retired RPC answers `UNIMPLEMENTED`. Additions are unaffected.

This ruling governs the proto schema only. It does not restore support for old agents: the
no-back-compat stance on behaviour stands, and an old agent's deprecated fields are ignored, not
honoured.

**Upgrade consequence, stated plainly: server, gateways and agents must be upgraded together.** This
is a wire break in both directions. An agent older than this release sends a heartbeat whose fields
3 and 4 the new server ignores. **It contributes no status tags at all**, so for that agent the
following stop:
- every fleet gauge;
- DEX performance and network quality;
- Spark and Guardian health;
- Guardian generation reconcile;
- dedup and OTA telemetry;
- topology.

It still counts as connected and still receives commands.

An upgraded agent behind an old server or gateway has its tags and topology ignored the same way.
Command dispatch, responses, inventory and liveness are unaffected in either direction.

## Context

### What the heartbeat carries today

`HeartbeatRequest` (`proto/yuzu/agent/v1/agent.proto:138-161`) carries `session_id`, `sent_at`, a
flat `status_tags` map, and `fleet_snapshot_json`. Both thread timings are fixed with no jitter:
- the heartbeat sleeps `cfg_.heartbeat_interval` (default 30 s, `agents/core/include/yuzu/agent/agent.hpp:19`)
  in its loop in `agents/core/src/agent.cpp` (about l.2514-2522);
- the snapshot pump sleeps a fixed 30 s (`agent.cpp`, `snapshot_pump_thread_`, about l.1645-1685).

**Topology body.** `fleet_snapshot_json` carries TAR's `fleet_snapshot.v1` document: every process
(user and redacted cmdline), the live connections merged with the last hour's closed `tcp_live` rows,
and the local IPs. Its embedded `ts` and per-connection `last_seen_seconds_ago` change every run. The
pump bumps its sequence on every run and never compares content. So the 50-800 KB body rides nearly
every beat. The proto comment's "5-20 KB, about once per two heartbeats" is wrong on both counts.

Its sole consumer is `FleetTopologyStore`, which feeds:
- the `/viz` fleet and host views;
- MCP `get_fleet_topology` and `get_host_topology`;
- the Hardware list's claimed-IPs column.

**Status tags.** About 97 `yuzu.*` tags are rebuilt and sent whole every beat (`agent.cpp`, from
`req.mutable_status_tags()` at about l.2547 to about l.3080):

| Family | Keys (approx.) | Producer | Server consumers |
|---|---|---|---|
| Identity | `yuzu.os`, `.arch`, `.agent_version`, `.healthy` (constant `"1"`), `.plugins_loaded`, `.plugins_failed` | agent core | `AgentHealthStore::recompute_metrics`: `yuzu_fleet_agents_by_{os,arch,version}`, `yuzu_fleet_plugin_init_failed` |
| Activity counters | `yuzu.uptime_s`, `.commands_executed` | agent core | `commands_executed` feeds the fleet rollup. `uptime_s` has no server consumer found on `origin/dev`; only gateway tests read it. |
| Dedup (HA WS-0) | `yuzu.dedup_degraded`, `_replays`, `_claim_errors`, `_record_terminal_misses`, `_record_errors`, `_release_errors` (6) | agent core | fleet gauges, `docs/command-dedup.md` |
| OTA | `yuzu.ota_signature_refused`, `yuzu.ota_signature_mode` | agent core | fleet gauge (#416/#3807) |
| Guardian | about 65 `yuzu.guardian_*` (generation, backend, arm counts, journal counters and gauges, `*_age_seconds` / `*_stale_seconds` gauges) | `GuardianEngine` emitters, groups A-D2 | `server/core/src/guardian_*_fleet_tags.hpp` gauges. **`yuzu.guardian_generation` drives per-heartbeat re-push of lagging agents** (`server/core/src/heartbeat_ingestion.cpp`, about l.104-150). |
| Spark | `yuzu.spark_running`, `_disabled`, `_mechs`, `_armed_faulted`, `_watch_faults`, `_queued_dropped`, `_consumer_errors`, plus per-mechanism keys | `SparkEngine` | `server/core/src/spark_fleet_tags.hpp` gauges. **Absence is a posture** (shutting down emits nothing). |
| DEX observer | `yuzu.dex_observer_armed`, `yuzu.dex_observed` | DEX signal observer | fleet gauges via `recompute_metrics` |
| Plugin facts | `yuzu.plugin.<p>.<k>` (bounded `heartbeat.*` KV facts) | plugins via KV | **`yuzu.plugin.tar.db_corruption_total` + `db_quarantine_last` drive the tar-corruption audit sink on every heartbeat** (`AgentHealthStore::upsert`, #1567) |
| Daily-sync skips | `yuzu.sync.<source>.skip_streak`, `.last_skip` | `emit_sync_skip_tags` | fleet gauge, inventory runbook |
| Perf (interval) | `yuzu.perf_cpu_pct`, `_commit_pct`, `_disk_lat_ms` | agent core, per-interval deltas | `yuzu_fleet_perf_*`, `/dex` performance (`server/core/src/dex_perf_rules.hpp`) |
| Network quality (interval) | `yuzu.net_rtt_p50_ms`, `_retrans_pct`, `_throughput_bps`, pinned to `kNetTag*` by `static_assert` (`server/core/src/network_perf_rules.hpp`) | agent core, interval deltas over `steady_clock` baselines | `yuzu_fleet_net_*` (absent-not-zero), `/network` read model (`docs/user-manual/network.md`) |

The server stores them with `AgentHealthStore::upsert` (`server/core/src/agent_registry.hpp`), which
**clears and replaces** the agent's map on every beat. Fleet gauges are rebuilt from that map on a
timer, pruning agents not seen in 90 s.

Most of these values do not change from beat to beat:
- identity is static;
- counters move only on events;
- Guardian and Spark health is flat in steady state.

Only the six interval tags change by nature.

### Freshness is store-defined, not an SLO

| Rule | Constant | Keyed on |
|---|---|---|
| Topology render cache | 60 s (`FleetTopologyStore` constructor default) | server time |
| Topology stale flag (stuck-pump detector) | `kPushedStaleAfter{90}` (`fleet_topology_store.hpp`) | body `server_received_at` |
| IP-claim reclaim (anti-spoof liveness) | `kIpClaimReclaimAfter{300}` (`fleet_topology_store.hpp`) | body `server_received_at` |
| Health map pruning | 90 s (`server.cpp`, the `recompute_metrics(metrics_, std::chrono::seconds{90})` call) | last heartbeat |

Both topology liveness rules are keyed on body arrival. A scheme that sends the body less often
without a server change therefore breaks both:
- every quiet host goes stale at 90 s;
- its IPs become claimable by another agent at 300 s.

### What it costs the gateway (budget: ADR-0074 D14)

The budget is ADR-0074 D14: one gateway on 8 cores and 16 GB holds **100,000 idle agents** with
mutual TLS, inside 8 GB of memory; and a CI regression check of **64 KiB per idle agent, all-in
including the kernel's per-connection memory**. (D14 replaces the 8 KiB-per-connection goal that an
earlier draft of this ADR cited.) The measurements below show why the heartbeat's payload is a large
part of the gap to that check.

**Idle-memory harness, 2026-10-26.** N = 10,000 simulated agents on the PR #5695 code (OTP 28.4.2),
150 KB body every 30 s.
- With TLS: 826 KiB/conn BEAM (a second run gave 707).
- Plaintext: 431 KiB/conn.
- Forced GC brings TLS down to 194 KiB/conn.
- A real 836-process Mac produced a 150,178 B body.

**No-snapshot sensitivity, 2026-10-26.** Same harness, macOS, N = 5,000, body 0 bytes; two runs agree
within about 2 %.
- TLS: about 411 KiB/conn BEAM. The binary term **collapses from 475 to 38 KiB**, but process heaps
  stay about **310 KiB**. Forced GC gives 173 KiB.
- Plaintext: about 311 KiB/conn, of which about 231 KiB is heap. Forced GC gives 142 KiB.
- The heaps are grown by **decoding the 97-tag heartbeat and Register**, and they persist until GC.
  Forced GC takes the connection process from 89 to 15 KiB and the stream process from 87 to 4 KiB.
- **The post-GC floor (about 140-175 KiB) is the same with or without the snapshot.**

**100 real Windows agents, 2026-10-26**, on the PR #5695 stack at `fa10fa135`. Marginal cost per
TLS connection: 213-219 KiB BEAM and 417-468 KiB OS anon. Forced GC takes per-agent process memory
from 189 to 60 KB.

**1,000 agents, 2026-10-25:** 544 MiB anon, about 557 KiB/conn naive.

ADR-0074 D14 records the same order of magnitude on merged `dev` at 5,000 agents (about 320 to 470 KB
per agent).

**Collection and buffering.**
- The gateway's connection process collects only after 1 MiB of request bytes
  (`gateway/apps/yuzu_gw/src/yuzu_grpc_stream_h.erl:79`, `COLLECT_AFTER_BYTES`).
- **Live state after GC, 2026-10-26** (term-level ledger, harness, macOS, TLS, snapshot 0 B, marginal
  from N = 1,000 to 3,000, two forced GCs per process): **131.8 KiB live per agent**. About two thirds
  of it is the decoded RegisterRequest, **kept three times**, with a 69-plugin registration:
  - the `yuzu_gw_agents` registry row (`yuzu_gw_registry.erl`): 30,112 B, of which the Register is
    26,696 and its PluginInfo list 25,696;
  - the `yuzu_gw_owner_sessions` row (`yuzu_gw_agent_sup.erl`): 27,104 B, the same Register again;
  - the `yuzu_gw_agent` owner process's `agent_info` (`yuzu_gw_agent.erl`): 26,392 B, of which only
    `hostname` is ever read.

  Those copies serve only:
  - the rare registration replay (`yuzu_gw_registry:entries_for_sessions/1` and
    `all_register_reqs/0`, sent by `yuzu_gw_upstream:replay_send/4`);
  - an owner restart (`yuzu_gw_agent_sup:restore_args/1`);
  - the management plane's `GetAgent`, `ListAgents` and `QueryInventory`
    (`yuzu_gw_mgmt_service.erl`).

  The server calls none of the management reads; it uses only `SendCommand` (`server.cpp`, the
  gateway `SendCommand` forwarder, and `gateway_mgmt_stub_pool.hpp`). Both registration rows also keep
  the agent's **enrollment token** for the whole session.

  The 100-agent Windows rig's agents loaded 6 plugins, which is why this did not show there.
  Production agents with most plugins look like the harness.
- ADR-2002 (the "stuck heartbeat batch" observation, about l.1445) records the operational version of
  the same cost: a 24.8 MB retained heartbeat batch wedged recovery until a gateway restart.

**Reading.** The retained Register is *live* state, about 87 KB per agent, removable only by
changing what replay sends (D14). The two wire payloads are a garbage-retention problem, not live
state:
- the snapshot inflates off-heap binary references;
- re-decoding a mostly unchanged 97-tag map every 30 s inflates process heaps.

Removing the snapshot alone is necessary but not sufficient: it leaves about 310 KiB/conn of tag
garbage. This ADR removes the wire cause of both terms. It does **not** move the post-GC floor
(process count, ssl processes, ETS, allocator slack). That belongs to ADR-0074's gateway-only memory
measures and its kTLS work, which these changes make measurable.

### Precedent

**No ADR chose either vehicle.** The topology field's recorded rationale is a commit message
(`ba7e34a8d`: "Cache-miss latency 800ms → 2ms"). The flat tag map grew one family at a time.

The accepted ADRs point the other way:
- ADR-0016's Context objects to resending unchanged data every cycle ("be kind to the network at
  fleet scale").
- ADR-0021 Decision 5 says "TAR snapshot pumps etc." become visible, tunable, disableable
  Reflexes.

Commercial endpoint platforms follow the same pattern:
- liveness is the session plus a small, randomised keepalive or state check-in;
- telemetry is pulled, batched, or sent as events;
- bulk content goes on a separate channel.

Frequent check-ins are fine when they are small.

**The stampede rule.** The owner's standing transport rule is that idle connections must be
near-free, and no periodic mechanism may fire across connections on a uniform clock. The repo
already applies it elsewhere, in `CommandRequest.stagger_seconds` and daily-sync's enrollment-herd
guard. Today's fixed 30 s timers phase-align the fleet after any mass reconnect.

## Decision detail

### D1. Tag classes

Every tag key belongs to exactly one class. The classification is one table in
`common/include/yuzu/status_tag_classes.hpp`, keyed by exact key or by declared prefix. It is pure
data, so it is allowed under the #2549 firewall.

| Class | Keys | Wire rule | Server rule | Why |
|---|---|---|---|---|
| **Interval** | `yuzu.perf_cpu_pct`, `yuzu.perf_commit_pct`, `yuzu.perf_disk_lat_ms`, `yuzu.net_rtt_p50_ms`, `yuzu.net_retrans_pct`, `yuzu.net_throughput_bps` | every heartbeat, all present values | **replace** the agent's interval map on each heartbeat; a key absent this beat is absent on the server | Each value is a measurement **over this beat's interval**, from `hb_prev_*` baselines. Absent means "not measured this interval", and the gauges are absent-not-zero (`docs/user-manual/network.md`). Carrying an old rate forward under a delta would publish a stale rate as current, which is a false reading in `yuzu_fleet_net_*` and `/network`. The `kNetTag*` pins and their `static_assert` are unchanged. |
| **State** | every other `yuzu.*` key, including the dynamic `yuzu.plugin.<p>.*`, `yuzu.sync.<src>.*` and per-mechanism `yuzu.spark_*` keys | full set at Register; afterwards upserts and removals since the last acknowledged beat, plus the digest | **merge** into the agent's state map, then verify the digest (D3) | Values are static or change on events. Re-sending them every 30 s is the garbage the harness measured. |

**Unknown keys** (an agent emitting a key the table does not list) are classified **state** by
default. A unit test fails if any key the agent core can emit is not explicitly listed. The default
exists only so an unlisted plugin fact degrades to "sent on change" rather than being dropped.

**Tag caps, applied by the agent.** The same header holds the tag caps, next to the class table: at
most 512 keys, at most 64 KiB per key or value, at most 256 KiB of keys and values in total, and
every key and value valid UTF-8. The numbers are today's gateway caps (D3, step 2). The agent applies
them to the set it is about to emit, interval and state together, **before** it diffs against its
base and computes the digest:
- a key or value over 64 KiB, or not valid UTF-8, is dropped;
- the remaining keys are admitted in key order, interval keys first, until the next one would pass
  512 keys or 256 KiB in total; the rest are dropped;
- every drop is counted (`yuzu_agent_status_tags_dropped_total{reason}`, D13) and logged once per
  key per process.

A value is dropped, never truncated, because a truncated value would be published as a real one. So
the digest covers exactly the set that is sent, and a payload the server rejects for a cap (D3) is a
defect, not an oversize agent.

**Retired and changed keys** (no back-compat):
- **`yuzu.uptime_s` is retired.** It changes every beat by construction, which makes it the worst
  possible state tag, and no server code reads it.
- **`yuzu.started_at`** (agent epoch seconds at process start, a static state tag) replaces it. The
  server derives uptime at read time.
- **`yuzu.healthy`** stays as a static state tag. Its value is always `"1"`, so it costs nothing
  under deltas. Retiring it is left to its consumers.

**Age-valued Guardian gauges** (`yuzu.guardian_*_age_seconds`, `*_stale_seconds`,
`*_headroom_blocked_seconds`) stay in the state class. They are emitted only while their condition
holds, so they cost bytes only during an incident, when the information is wanted. Re-expressing them
as "since" timestamps would remove even that. That is not decided here, because it changes their
emitters' contract (`guardian_*_fleet_tags.hpp`).

### D2. Wire shape

```proto
// agent.proto
message StatusTags {
  map<string, string> interval = 1;   // complete interval set for this beat (replace)
  map<string, string> upsert   = 2;   // state keys added or changed since the base
  repeated string     removed  = 3;   // state keys deleted since the base
  string state_digest          = 4;   // "v1:" + 32 lowercase hex over the agent's FULL state set after this change
  bool   full                  = 5;   // true: `upsert` IS the complete state set; server replaces, `removed` must be empty
  string base_digest           = 6;   // state_digest of the base this delta was computed against; empty when full = true
}

message RegisterRequest {
  // fields 1-7 unchanged
  bytes status_tags_pb = 8;           // serialized StatusTags, full = true, interval empty; base for the first heartbeat
}

message HeartbeatRequest {
  string session_id = 1;
  yuzu.common.v1.Timestamp sent_at = 2;
  map<string, string> status_tags = 3 [deprecated = true];  // ADR-0073: not populated; ignored by every receiver
  bytes fleet_snapshot_json = 4 [deprecated = true];        // ADR-0073: not populated; ignored by every receiver
  TopologyDigest topology = 5;        // D5; the gateway passes it through untouched
  bytes status_tags_pb = 6;           // serialized StatusTags; OPAQUE to the gateway (D4)
}
// HeartbeatResponse and BatchHeartbeatResponse are unchanged.
```

**Why the tags are `bytes`, not a typed sub-message.** The gateway decodes `HeartbeatRequest` to
admit it (it needs `session_id`) and re-encodes it into a batch. A typed `StatusTags` would be
decoded into Erlang terms on every beat, which is the heap growth the harness measured. It would
also tie gateway gpb regeneration to every tag-schema change. As `bytes`, the payload stays one
sub-binary of the received frame. The gateway cannot interpret it, so opacity is enforced by the
type, not by review discipline.

The cost is one extra decode on the server and agent, which is negligible. Producers (agent) and
consumers (server) use the generated `StatusTags` type.

`buf breaking` runs with `WIRE_JSON` plus the explicit no-delete rules in `proto/buf.yaml` (the
`proto-compat` job in `.github/workflows/ci.yml`). It accepts this shape with no exemption, because
nothing is subtracted: fields 3 and 4 stay, deprecated, and everything else is an addition.

**Deletions are explicit.** A state key the agent no longer emits goes in `removed` once, and the
server erases it. This preserves every "absence is meaningful" posture:
- Spark's ABSENT posture on shutdown;
- a cleared `yuzu.plugins_failed`;
- a sync source with no skips.

A key cannot appear in both `upsert` and `removed`; the server rejects such a payload (D3, step 3).

**Base and acknowledgement.**
- The agent's base is the state set as of its last **acknowledged** heartbeat, or the Register's
  full set right after (re)registration. The heartbeat thread owns it (D8).
- "Acknowledged" means the RPC returned OK. That comes from the gateway (which answers locally) or
  from the server.
- A failed or timed-out heartbeat does not advance the base, so its changes repeat in the next
  delta.
- Every delta names its base in `base_digest`. The server applies a delta only to the base it names
  (D3, step 6), so a delta computed against a base the server never reached, or a reordered older
  delta, cannot be applied to the wrong map and pass by coincidence.
- A heartbeat the gateway acknowledged but later lost (keep-newest coalescing, buffer drop, oversize
  drop) is caught by the digest (D3), not by the agent.

### D3. Divergence detection

The **state digest** is SHA-256 over the full state set, truncated to the first 16 bytes and
rendered as `"v1:"` plus 32 lowercase hex characters. Each `(key, value)` pair is encoded as two
u32-little-endian length-prefixed byte strings, and pairs are sorted by key bytes. Interval tags are
excluded, since they are complete on every beat. An empty set has a defined digest.

**One implementation.** The digest function lives in `common/include/yuzu/status_tag_digest.hpp`,
used by the agent and by the server alike. It is pure computation with no I/O, store or wire types,
which the #2549 firewall permits. OpenSSL is already a dependency of both binaries. Unlike ADR-0016's
blob hash, the canonical form therefore exists once, and the two sides cannot drift.

**Versioning.** The server verifies only the digest prefixes it implements; this ADR defines `v1:`.
Any other prefix is counted `unverifiable` and never triggers a repeating resync (step 5). Golden
test vectors for `v1` (the empty set, one pair, key ordering, a multi-byte UTF-8 value) live in one
checked-in file that both the agent and the server test suites read, so a change to the canonical
form fails both.

**On each heartbeat** the server (`HeartbeatIngestion`, `server/core/src/heartbeat_ingestion.{hpp,cpp}`,
shared by direct `Heartbeat` and gateway `BatchHeartbeat`):

1. **Absent payload.** An empty `status_tags_pb` comes from an agent older than this ADR: an
   upgraded agent always sends a `state_digest`, so its payload is never empty. The server applies
   nothing, requests no resync and counts `absent`. `absent` heartbeats are excluded from the
   divergence alert (D13). They are what an un-upgraded agent produces during the upgrade window
   (*Upgrade consequence* above).
2. **Decode and caps.** Decodes `status_tags_pb` and checks it against the tag caps: at most 512 keys, 64 KiB per key or
   value, 256 KiB in total, valid UTF-8. These caps are enforced at the gateway today
   (`yuzu_gw_heartbeat_buffer.erl`: `MAX_STATUS_TAGS`, `MAX_TAG_ITEM_BYTES`, `MAX_TAG_BYTES_TOTAL`
   at l.117-130, and `screen/1` with the UTF-8 repair at about l.460-583). A payload that fails them
   is discarded and counted `rejected`; the agent is treated as `diverged`, subject to the backoff
   below. The agent applies
   the same caps before it digests (D1), so a rejection means an agent or encoding defect. Two
   differences from today, stated so they are not mistaken for parity:
   - the caps are checked **after** the server decodes the bytes, so the decode itself is bounded
     only by the size of the RPC message that carried it, not by the tag caps;
   - invalid UTF-8 is **rejected, not repaired**. The tag maps are proto3 `string` fields, whose
     C++ parse fails on invalid UTF-8, so the whole payload is rejected where the gateway today
     repairs the offending bytes and keeps the rest.

   A per-agent resync backoff (D8) stops a persistently rejected agent from re-requesting a full
   set every minute.
3. **Class check.** A key in `interval` that the class table (D1) does not classify interval, a key
   in `upsert` or `removed` that it classifies interval, or a key in both `upsert` and `removed`,
   makes the payload `rejected`, as in step 2. Nothing from it is applied.
4. **Interval.** Replaces the agent's interval map with `interval`. A heartbeat that ended at step
   1, 2 or 3 clears the interval map instead: nothing measured this interval reached the server, and
   a kept value would be a stale rate published as current.
5. **Digest version.** If `state_digest` carries a prefix the server does not implement, the server
   counts `unverifiable`, leaves the state map unchanged and requests no resync, because a resync
   would bring back the same prefix (see *Versioning* above).
6. **State.** Then branches:
   - If `full`: compute the digest of `upsert`. If it equals `state_digest`, replace the state map
     with `upsert`, store the digest, and count `full`; the agent is **synced**. If not, the payload
     is `rejected`: a full set that does not match its own digest is a defect.
   - Else if the server holds no state map for the agent (server restart, HA replica change, an
     entry pruned after 90 s without a heartbeat, a Register that never reached this replica): apply
     nothing, **request `__resync__.tags`** (D8), and count `no_base`.
   - Else if `base_digest` differs from the stored digest: if `state_digest` already equals the
     stored digest, the delta is a duplicate or its changes are already applied, and the agent is
     **synced** with nothing applied. Otherwise keep the map, **request `__resync__.tags`** (D8), and
     count `diverged`.
   - Else if the delta is empty (no `upsert`, no `removed`): the agent is **synced** if
     `state_digest` equals the stored digest, with no copy and no hash; otherwise `diverged`, as
     above. This is the steady-state case, so a quiet agent costs one string compare per heartbeat.
   - Else: apply `removed`, then `upsert`, to a copy. Recompute the digest. If it equals
     `state_digest`, commit it with its digest and the agent is **synced**. Otherwise keep the
     pre-delta map (the last verified state), **request `__resync__.tags`** (D8), and count
     `diverged`.

A diverged or unbased agent keeps its last verified state, if any, until the full set arrives. Its
interval tags are always current. The full set arrives on the agent's next heartbeat after
`__resync__.tags` reaches it (D8): at most 36 s after delivery (a jittered 30 s beat, D9). Delivery
itself can wait for the per-replica rate limit and the per-agent interval (D8).

**An agent rejected three times in a row is withheld.** Its last verified state map is kept but not
served: its state-derived gauges are absent and the per-heartbeat hooks see no state, as for
`no_base`, until a payload is accepted. A defect
that keeps an agent rejected must not show its last verified Guardian, dedup or Spark state as
current indefinitely.

**Per-heartbeat side effects read the merged view, never the wire:**
- Guardian generation reconcile (`yuzu.guardian_generation`);
- the tar-corruption audit sink (`yuzu.plugin.tar.db_corruption_*`).

Both depend on firing on **every** heartbeat, not only on change. The reconcile re-pushes a still
lagging agent; the corruption sink retries a candidate the gate skipped. So they run after step 6,
over the agent's current merged state.

**At registration.** Direct `Register` and `ProxyRegister` pass `RegisterRequest.status_tags_pb` to
the same function, as a `full` payload, on the replica that handles the registration. The caps, the
class check and the digest check all apply. An empty field is `absent`. A rejected Register payload
installs no state map, so the agent's first heartbeat is `no_base` and requests a resync.
Registration itself never fails because of the tags.

**Locking.** `AgentHealthStore::apply` holds the store's `mu_` only to copy and to commit:
- under `mu_`, it copies the agent's state map, its stored digest and a per-agent version counter;
- it decodes, applies the delta to the copy and hashes **outside** `mu_`, so no SHA-256 runs under
  the fleet-wide mutex;
- under `mu_` again, it commits only if the agent's version is unchanged, and bumps it. A changed
  version means two heartbeats for one agent raced. The later one is counted `diverged`, and the
  next delta or a resync settles it;
- the per-heartbeat hooks receive copies of the values they read and run outside `mu_`, as the
  corruption sink does today, so the 90 s prune cannot erase anything they hold;
- `apply` only returns an outcome. The caller makes any resync request after `apply` returns, never
  under `mu_` (D8).

Deprecating `HeartbeatRequest.status_tags` makes any surviving direct read a deprecation warning,
not a compile error. The enforcement for this invariant is a lexical test that no non-generated
source reads or writes heartbeat fields 3 or 4.

### D4. The gateway is an opaque relay

**Owner ruling, 2026-10-26, reworded 2026-10-28: no per-agent state beyond the connection.** The
gateway relays what this ADR introduces without interpreting it. Fleet-level state that any gateway
could rebuild, such as ADR-0074's cached CRL, drain flag, gateway list and cluster membership, is
outside this rule; this ADR adds none of it.

- **No parsing.**
  - `status_tags_pb` is `bytes` (D2), never decoded.
  - `TopologyDigest` is passed through as a field of the heartbeat it already decodes, never read.
  - `ReportTopology` is forwarded as received (D7).
- **No new per-agent state.** Resync is a server-to-agent command on the existing command path
  (D8). The gateway holds no resync bits and no per-agent tag or digest state. There are no new
  `BatchHeartbeatResponse` fields.
- **Coalescing is keep-newest, over whole heartbeats.**
  - **Today:** the buffer keeps one entry per session, and a newer heartbeat replaces the older
    one's fields except the snapshot, which keeps the newest non-empty one
    (`yuzu_gw_heartbeat_buffer.erl`, header l.13-24 and `coalesce/2` at about l.588).
  - **Under this ADR:** a newer heartbeat **replaces the older one whole**. That is simpler than
    today and needs no understanding of deltas.
  - **Rejected alternative: forward-all** (keep every heartbeat per session). It would make buffer
    memory grow per session with outage length, which is exactly ADR-2002's stuck-batch failure.
  - **The cost of keep-newest:**
    - any state change carried only in a dropped older heartbeat is missing at the server;
    - the next delta then fails the digest check (D3), and the server re-requests the full set with
      `__resync__.tags`. The agent answers with full heartbeats until two are acknowledged (D8), so
      one more coalescing during the resync does not lose the full set.
    - Coalescing happens only when a session sends two beats before a flush. In steady state that is
      rare at the default flush interval (`heartbeat_batch_interval_ms`, 1000 ms, valid 100 to
      60,000), far below the 24 s minimum jittered heartbeat. The gateway does not enforce that
      relation: a flush interval configured near 24 s or above makes coalescing routine, and each
      coalesced state change then costs a resync. `docs/user-manual/gateway.md` states the relation.
    - It is routine during an **upstream outage**. `AgentHealthStore` entries are not removed when a
      stream or upstream connection ends (`AgentHealthStore::remove` has no production caller); they
      are pruned after 90 s without a heartbeat. So an outage shorter than 90 s leaves the server's
      bases in place, and only the agents whose state tags changed during it diverge once. After a
      longer outage every entry is gone, every agent's next heartbeat is `no_base`, and all of them
      resync once. Either way the server issues at the configured rate: N / 2000 s per replica, where
      N is the agents whose heartbeats reach it, so about 50 s of issuing for N = 100,000 (D8).
  - The digest makes keep-newest correct, not merely tolerable. Whatever a lost heartbeat carried,
    the next delta's `base_digest` no longer matches the server's stored digest, and the server
    re-requests the full set (D3, step 6). A later heartbeat whose `state_digest` already equals the
    server's view needs no resync.
- **Every other lossy path is unchanged in behaviour and becomes self-healing.** All of these lose a
  delta, and the server then diverges and resyncs:
  - the buffer-full drop;
  - the oversize drop, now judged on the **whole encoded heartbeat's** byte size only;
  - the non-transient rejection.
- **What the gateway stops doing.** It no longer decodes, counts, size-checks or UTF-8-repairs
  individual tags (`yuzu_gw_heartbeat_buffer.erl`, about l.460-583); that moves to the server (D3,
  step 2). The tag-strip path is removed. The `heartbeat_invalid` drop reason **stays**, for the
  drops that remain: a heartbeat whose session id cannot be keyed (admission already rejects such a
  session), and one the encoder raises on when a chunk is sent (`yuzu_gw_heartbeat_buffer.erl`,
  `screen/1` at about l.460-489 and the flush's encoder-raise split at about l.782-789). Both
  `status_tags_pb` and `TopologyDigest.digest` are `bytes`, so no field this ADR adds can make the
  encoder raise; a typed `string` digest would have, silently dropping every heartbeat of a session
  that sent a bad one. The gateway does **less** per
  heartbeat than today.

**Pre-existing gateway state.**
- **Removed by this ADR:** the retained RegisterRequest, in all three session copies, and the
  transient fourth copy in the pending Register-to-Subscribe row (D14).
- **Kept, because it is the connection:**
  - the per-session `yuzu_gw_agent` process and its routing record (ids, connection, stream home,
    owner key, `connected_at`, observed peer);
  - the session-index ETS rows;
  - local heartbeat answering (`yuzu_gw_agent_service:heartbeat/2`, about l.448-466).
- **Removed with the Register:** the plugin-name list (D14).
- **Kept, and outside this ADR's scope:** two kinds of per-agent state beyond the connection that
  today's gateway already holds, which ADR-0074 Conflict 5 leaves to its wave 4 (to keep as
  rebuildable state, or to change):
  - the per-agent `pg` groups across cluster members (`pg:join` in `yuzu_gw_registry.erl`);
  - the DISCONNECTED resend window after a connection ends (the held-notification resend in
    `yuzu_gw_upstream.erl`).

  This ADR neither adds to them nor removes them. D4's "no per-agent state beyond the connection"
  is a claim about what this ADR introduces, not a claim that the gateway meets the rule today.

A fresh Register is decoded **transiently** to forward it as `ProxyRegister`, and nothing from it
is kept, so its `status_tags_pb` (field 8) never enters gateway state. Its enrollment token is in
gateway memory only for that decode and forward.

### D5. Topology digest and pump

**`TopologyDigest`** (heartbeat field 5):

```proto
message TopologyDigest {
  bytes digest = 1;                           // ASCII "v1:" + 32 lowercase hex; empty until the first good run
  yuzu.common.v1.Timestamp last_pump_at = 2;  // agent clock, last COMPLETED run, any outcome; compared for CHANGE only
  TopologyPumpOutcome last_outcome = 3;       // OK | TRUNCATED | FAILED | DISABLED
  uint32 pump_interval_s = 4;                 // configured base pump interval (--topology-interval); 0 when DISABLED
}
```

- `last_pump_at` advances at the end of every run the pump completes, whatever its outcome (`OK`,
  `TRUNCATED` or `FAILED`). It is the pump's progress marker, so the server can tell a pump that
  stopped running from one that runs and fails. It never advances under `DISABLED`, because no run
  happens.
- `pump_interval_s` is the base interval before jitter. The server needs it because
  `--topology-interval` is tunable from 30 to 900 s (D9), so no fixed staleness threshold fits
  every agent (D6).
- `last_outcome` is the wire view of the last run. `yuzu_agent_topology_pump_total{outcome}` (D13)
  splits `OK` into `ok` (the digest changed) and `unchanged` (the digest equals the previous
  run's); the wire carries `OK` for both. `DISABLED` has no metric label, because no run happens.

The owner's ruling described "one tiny digest tag". It is a typed field instead, for three reasons:
- a per-run-changing tag would turn into a state-tag delta on every pump;
- tags count against the tag caps;
- a typed field is visible in the contract.

**The topology digest is computed by TAR**, inside its `fleet_snapshot` builder (the plugin is now
named `echo`: `agents/plugins/echo/src/echo_fleet_snapshot.{hpp,cpp}`, action
`echo.fleet_snapshot`), and emitted as a top-level `content_digest` member. That is a
`schema_minor` bump from 2 to 3; the schema name `fleet_snapshot.v1` is unchanged, and the digest
input includes the new `schema_minor`. Definition `v1`: SHA-256, first 16 bytes, `"v1:"` plus 32 hex
characters, over a u32/i64 little-endian, length-prefixed encoding of:

1. `schema`, `schema_minor`, `hostname`.
2. `local_ips`, sorted and de-duplicated.
3. `processes[]` as tuples `(pid, ppid, name, cmdline, user)`, sorted, duplicates kept.
4. `connections[]` as tuples `(proto, local_addr, local_port, remote_addr, remote_port, remote_host,
   state, pid, process_name)`, sorted, duplicates kept.
5. The truncation flags and the source-paused flags.

**Excluded as volatile:** `ts`, and every row's `last_seen_seconds_ago`.

The builder holds one static list classifying every key it can emit, at the top level and in each
row, as digested, volatile, or `content_digest` itself (the output, never an input). The list covers
the keys emitted only on some runs: `process_source_paused`, `tcp_source_paused`, and a
connection row's `last_seen_seconds_ago`, which a live row omits. A test builds documents that
exercise every such key (both sources paused, both truncation flags set, live and closed rows)
and fails if any built document contains an unclassified key. **The server treats this digest as opaque.**
It stores the value that arrived with the body, rejects a report whose `digest` disagrees with the
body's `content_digest`, and never recomputes it. That keeps one implementation (TAR) and keeps JSON
canonicalisation out of the server.

**Pump.** The pump stays a Run()-lifetime thread (`snapshot_pump_thread_` in `agent.cpp`). Each run:
1. execute `echo.fleet_snapshot` via `LocalDispatcher`;
2. publish the body, digest, `last_pump_at`, outcome and `pump_interval_s` as **one record**;
3. sleep a jittered 60 s.

Truncated runs (over 2 MiB) keep the previous body and digest and record `TRUNCATED`; a failed run
keeps them too and records `FAILED`.

**One record, published and read whole.** The pump builds an immutable record and replaces the
shared pointer to it under `snapshot_mu_` in one step. The heartbeat thread (for `TopologyDigest`)
and the topology sender (for `ReportTopology`) each copy that pointer once under the same mutex
and read every field from the copy. Neither reads the body and the digest in two steps, so a report
can never pair one run's body with another run's digest, which the server would reject as
`DIGEST_MISMATCH`. Today's pump publishes the body under `snapshot_mu_` and a sequence number as a
separate atomic (`latest_snapshot_`, `latest_snapshot_seq_`); both go.

### D6. Server topology liveness from the digest

Each topology slot gains these fields:
- `digest`;
- `body_received_at`, held twice: on `steady_clock` for every duration, and on the wall clock for
  display only;
- `last_heartbeat_at`: the last heartbeat that carried a `TopologyDigest` field for the agent,
  whatever its digest. It is the liveness key for `agent_silent`;
- `confirmed_at`: the last heartbeat whose digest equalled the slot's. It is the key for the IP-claim
  refresh only;
- `pump_marker` and `pump_advanced_at`: when `last_pump_at` last **changed**. The comparison is
  inequality, never ordering, so an agent clock step cannot keep a slot fresh or age it. It is
  updated on every heartbeat for an agent that has a slot, whether or not the digest matches, since
  a pump that runs and finds new content is not stuck;
- `last_outcome`, `outcome_since` (when `last_outcome` last changed value) and `pump_interval_s`,
  from the latest heartbeat;
- `mismatch_since`.

**Every D6 duration is measured on the server's `steady_clock`.** That covers `last_heartbeat_at`,
`confirmed_at`, `pump_advanced_at`, `outcome_since`, `mismatch_since`, the no-slot first sighting,
the 300 s IP-claim reclaim, the 300 s retain-on-disconnect, `kReportGrace` and the connection-age
rebase. The wall clock only renders ages and `body_received_at` for display, and stamps audit rows.
A wall-clock step therefore cannot show a dead agent as live, expire every slot at once, or free a
live agent's IP claims. This changes today's store: `push_snapshot` and the stale check key on
`server_received_at` from `system_clock` (`fleet_topology_store.cpp`), and the 90 s stale and 300 s
reclaim rules move to `steady_clock` with it. Only the render cache's age already uses
`steady_clock`. The store's tests inject the clock, so a test advances it rather than pre-setting a
receipt time.

Every row below sets `last_heartbeat_at` and the pump fields when the agent has a slot.

| Heartbeat says | Server does |
|---|---|
| digest equals slot | `confirmed_at = now`; refresh the slot's IP claims; clear `mismatch_since` |
| non-empty digest, differs from slot | set `mismatch_since` if unset. The agent's change report is expected; past `kReportGrace` (120 s), issue `__resync__.topology` (D8) |
| non-empty digest, no slot | record the first sighting in the agent's no-slot entry (below). The agent's STARTUP or CHANGED report is expected; past `kReportGrace` from the first sighting, issue `__resync__.topology` (D8). No request while the agent's last report was rejected and the digest has not changed since (below) |
| empty digest (no good run since the agent started) | no request: there is no body to ask for. The slot, if any, is not confirmed, so its claims are not refreshed |
| no field, or `DISABLED` | no request. Drop any slot and release its IP claims: there is no evict rule for a connected agent's slot, so it is not left to age |

**An accepted report** (any reason) installs or replaces the slot. It sets `digest` and
`body_received_at`, sets `confirmed_at = now`, clears `mismatch_since`, and claims the body's
`local_ips` through first-claim-wins, which also refreshes them. It drops the agent's no-slot entry.
`last_heartbeat_at` and the pump fields stay heartbeat-driven. The owner-live test inside
`push_snapshot` (today `now - server_received_at > kIpClaimReclaimAfter` on the owner's slot) reads
the owner's `confirmed_at`, so a quiet owner confirmed by heartbeats keeps its IPs, and a
retained `disconnected` slot holds no claims to defend.

**The slot cap.** `kPushedMapHardCap` (100,000) still bounds the map. When it is reached and a new
agent's slot is installed, the victim is chosen in this order: a retained `disconnected` slot
first, oldest disconnect first; otherwise the slot with the oldest `confirmed_at`. Today the victim
is the oldest `server_received_at` (`fleet_topology_store.cpp`), which under this ADR would be the
quietest healthy host, whose body is the oldest because nothing changed. Each eviction still writes
`topology.push.evicted_for_cap`.

**No-slot entries.** For a connected agent with no slot, the store keeps a small entry: the first
sighting of a non-empty digest, `last_heartbeat_at`, and the digest and reason of the agent's last
rejected report. An entry is dropped when a slot is installed or the agent's stream closes, so the
entries are bounded by the agents whose heartbeats reach this replica, under the same cap as the
slots (`kPushedMapHardCap`).

**The grace for an agent with no slot.** An agent's own report normally arrives first: its STARTUP
report goes within 60 s of its first body (D7), and the heartbeat that first shows the digest can
arrive before it. Waiting `kReportGrace` from the first sighting means a normal start sends the body
once, not once as STARTUP and again as RESYNC.

**After a rejected report.** A report the server rejects (`PARSE`, `DIGEST_MISMATCH`, `OVERSIZE`,
`IP_CONFLICT`) installs no slot. While the heartbeat digest still equals the rejected report's
digest, the server issues no `__resync__.topology` for that agent: a resync would bring back the same
body and the same rejection, every 5 minutes, defeating the agent's own back-off. The agent's retry
rule covers it instead (D7: a full floor after `IP_CONFLICT`, exponential back-off otherwise). A new
digest clears the record. `UNKNOWN_SESSION` is refused before the store and records nothing.

**`stale_reason` is a closed enum.** Every rendered machine carries `stale` and `stale_reason`.
`stale` is true exactly when `stale_reason` is not null; a fresh machine has `stale_reason = null`.
When several conditions hold, the first in this order wins:

| Order | `stale_reason` | Condition | Notes |
|---|---|---|---|
| 1 | `offline` | a host added from the durable offline-host roster (`merge_offline_topology`): no slot and no live session on this replica | today's offline placeholder: `ts = 0`, empty rows. It outlives every slot rule, so a host offline for more than 300 s is never confused with a connected one. |
| 2 | `disconnected` | slot retained after its stream closed | below |
| 3 | `agent_silent` | connected slot, `now - last_heartbeat_at > 90 s` | Same 90 s as `kPushedStaleAfter`: two jittered heartbeats (at most 36 s each) plus gateway flush slack. Keyed on any heartbeat, so a live agent whose report is late reads `body_pending`, never `agent_silent`. |
| 4 | `pump_stuck` | `now - pump_advanced_at > T`, or `last_outcome ∈ {TRUNCATED, FAILED}` and `now - outcome_since > T`, where `T = 3 × 1.2 × pump_interval_s + 90 s` | Three missed runs at the longest jittered sleep, plus the 90 s heartbeat window, because the server sees a run only on the next heartbeat after it. `pump_interval_s` is clamped to the 30-900 s flag range before use, and a value of 0 (`DISABLED`) never evaluates this row. At the 60 s default `T` is 306 s; at 900 s it is 3,330 s. The server never assumes the default. |
| 5 | `body_pending` | `mismatch_since` older than `kReportGrace` | new |
| 6 | `report_rejected` | connected, no slot, last report rejected, digest unchanged since | new; the reason is in the metric and, for `IP_CONFLICT`, the audit row (D7) |
| 7 | `awaiting_report` | connected, no slot, a non-empty digest seen: within `kReportGrace` of the first sighting, or a resync sent or `deferred` | new. After a server restart every reporting agent reads this until its body lands, which can take about 8 min per 100,000 agents (D8). |
| 8 | `not_reported` | connected, no slot, and no non-empty digest: no field, an empty digest, `DISABLED`, or no heartbeat on this replica yet | today's roster placeholder |

- **IP-claim reclaim** stays at 300 s, keyed on `confirmed_at`. A quiet host keeps its claim with a
  ~70-byte field; a silent host loses it at 300 s, as today.
- **Retain on disconnect** replaces evict-on-disconnect (`FleetTopologyStore::evict_pushed`). This
  **amends** fleet-viz invariant UP-5 ("Eviction on disconnect", `docs/fleet-viz-invariants.md`):
  its claim-release half stands, and its slot-drop half is replaced (open point 2). On stream close,
  IP claims are released **immediately**, but the body and digest are kept for 300 s, rendered
  `disconnected`.
- **Only the current session's close marks the slot.** Both disconnect paths call
  `mark_disconnected` only when `registry_.remove_agent_if_session` returned true
  (`removed_current_session`). The gateway path already gates `evict_pushed` that way
  (`gateway_service_impl.cpp`); the direct Subscribe path calls it ungated today
  (`agent_service_impl.cpp`, after `mirror_departure_to_presence`), and gains the gate. Ungated, a
  superseded session's late close would release a live session's IP claims and mark its slot
  `disconnected`. Today the next heartbeat's body repairs that; under D6 no body is due, so the
  damage would last until the next report. On the first confirming heartbeat after a reconnect, the
  stored `local_ips` are re-claimed. The re-claim and `push_snapshot` call **one claim function**
  (the IP scan, the owner-live test and the install), so the two can never judge a conflict
  differently:
  - if they are free, the slot is live again with no body sent;
  - if any IP is held by another live agent, the server first writes `topology.push.rejected`
    (detail `reason=reclaim_conflict` with the claimant, the IP and the owner, each sanitised as
    today), then drops the slot and requests topology, so the fresh body goes through
    first-claim-wins. The anti-spoof evidence chain therefore records a refused re-claim exactly as
    it records a refused push.

  A gateway restart thus costs zero bodies for agents back within five minutes. Eviction is lazy (in
  `confirm` and `build_snapshot`), so no background loop is added.
- **Connection ages.** Only **closed** rows are rebased: the rows that carry
  `last_seen_seconds_ago`, which the builder sets only on rows from TAR's connection history. At
  render time they show `last_seen_seconds_ago + (now - body_received_at)`, measured on
  `steady_clock`, and a closed row older than 3600 s is dropped. A **live** row carries no
  `last_seen_seconds_ago` and keeps age 0. Age 0 means "live when the body was built, and the
  digest has not changed since". It does not mean the connection was observed at render time: the
  body may be up to one refresh floor (12-18 min) old, and its build time is the machine's `ts`.

### D7. `ReportTopology` and its gateway proxy

```proto
// AgentService
rpc ReportTopology(TopologyReport) returns (TopologyAck);
message TopologyReport {
  string session_id = 1;
  yuzu.common.v1.Timestamp sent_at = 2;
  string digest = 3;                // must equal the body's content_digest
  bytes fleet_snapshot_json = 4;    // fleet_snapshot.v1, <= 2 MiB
  TopologyReportReason reason = 5;  // CHANGED | REFRESH | STARTUP | RESYNC
}
message TopologyAck {
  bool accepted = 1;
  TopologyRejectReason reject_reason = 2; // PARSE | DIGEST_MISMATCH | IP_CONFLICT | OVERSIZE | UNKNOWN_SESSION
}
// GatewayUpstream
rpc ProxyTopology(yuzu.agent.v1.TopologyReport) returns (yuzu.agent.v1.TopologyAck);
```

**Server.**
- Each new handler, `AgentServiceImpl::ReportTopology` and `GatewayUpstreamServiceImpl::ProxyTopology`,
  begins with `onbehalf::enforce(context)` before any side effect, like every existing handler in
  `agent_service_impl.cpp` and `gateway_service_impl.cpp`. Direct `ReportTopology` then calls
  `reject_revoked_peer(context, "report_topology")`, as `ReportInventory` does
  (`"report_inventory"`).
- Both paths call the one shared parser, `FleetTopologyStore::parse_fleet_snapshot_json`. After D10
  there are exactly two callers.
- **Session resolution.** `ProxyTopology` resolves the session through the route directory
  exactly as `ProxyInventory` does (`resolve_sessions` in `gateway_service_impl.cpp`): a degraded
  read with a local hint resolves; an unknown, ambiguous or unhinted-degraded id is refused
  `UNKNOWN_SESSION`, and the agent retries with its backoff (below).
- The trust boundary is unchanged: `agent_id` comes from the resolved session, and `os` from this
  replica's installed `AgentSession` for that agent, never from the report. A replica that resolves
  the id but has no installed session for the agent yet (its reattach has not landed) also refuses
  `UNKNOWN_SESSION`.
- The 2 MiB and 4096-row caps are checked before parsing.
- **Audit.** The three verbs stay, and each is written by named paths only:
  - `topology.push.first`: the first accepted report per agent per server process lifetime. A
    re-claim of a retained slot is not a push and writes none.
  - `topology.push.rejected` (`result=denied`): a report rejected `IP_CONFLICT` in `push_snapshot`
    (detail `reason=ip_conflict`), and a heartbeat-driven re-claim conflict (D6,
    `reason=reclaim_conflict`). The detail keeps today's `claimant`, `ip` and `owner`, each through
    `sanitise_for_audit`.
  - `topology.push.evicted_for_cap` (`result=warning`): a cap eviction when a new agent's slot is
    installed (D6).
  - **Rejections before the store write no row.** `PARSE`, `DIGEST_MISMATCH`, `OVERSIZE` and
    `UNKNOWN_SESSION` are refused before `push_snapshot`, as a parse failure is today. They are
    counted on `yuzu_viz_topology_report_rejected_total{via,reason}` (D13). They say nothing about
    another agent's claim, which is what the audit chain records.
  - **Volume.** An honest agent retries an `IP_CONFLICT` only after a full floor (below), and the
    server's resync for it is suppressed meanwhile (D6), so it writes about one `rejected` row per
    12-18 minutes at most. A re-claim conflict happens at most once per reconnect. A sender that
    ignores the retry rule is bounded only by the gateway's permit pool and the server's handler
    rate, as today. No per-agent audit rate limit is added; the code already records
    threshold-based audit as a follow-up (`fleet_topology_store.cpp`).

**Gateway:**
- a `report_topology/2` handler in `yuzu_gw_agent_service.erl`, admitted like `report_inventory/2`
  (`yuzu_gw_heartbeat_admission:admit_inventory/2`) but with its **own** permit pool;
- a 2 MiB per-RPC message cap;
- forwarding via `ProxyTopology` on the gateway's upstream connection. The gateway has one upstream
  and no per-session replica routing; the server resolves the session (above);
- **no buffering**: an unforwardable report fails `UNAVAILABLE` and the agent retries.

**Peer authorization.** `ProxyTopology` is a new gateway-upstream RPC. It gets an explicit
`GatewayPeerGuardedService` override (`server/core/src/gateway_peer_guard.hpp`) that calls
`gateway_peer::decide` first, an `rpc` label, and a test row. When ADR-0074 D1 moves gateway and
server from pins to CA trust plus identity plus revocation, this RPC follows the same admission as
every other upstream RPC; it adds no path of its own.

**Collect after large requests.** `yuzu_grpc_stream_h` collects the connection process after any
single request of 64 KiB or more, not only after 1 MiB cumulative. The body still crosses the agent's
long-lived connection process and its TLS receiver, because the unary shares the agent's HTTP/2
connection. So this ADR saves by **rate**, not location, and the collection stops the rare body from
lingering.

**Agent send rules.** A per-connection topology sender mirrors the daily-sync thread (its own stub,
joined on disconnect). It sends when:
- **CHANGED:** the latest digest differs from the last accepted one; delay uniform 0-10 s.
- **REFRESH:** the floor expires; drawn uniformly from 12-18 min, restarted on every accepted
  report.
- **STARTUP:** first report of the process; delay uniform 0-60 s.
- **RESYNC:** on `__resync__.topology` (D8); delay uniform `[0, window_s]` from the command.

It does not send on reconnect; the heartbeat digest lets the server decide. Failures back off
exponentially with full jitter (base 15 s, cap 15 min). `UNIMPLEMENTED` is logged once per
connection, counted, and retried only at the floor; it is never a fallback. `IP_CONFLICT` waits a
full floor.

**Why a 15-minute floor.** Liveness no longer depends on body arrival (D6). The floor's only job is to
bound a defect that keeps the digest constant while rendered content changes: a misclassified field,
or a lost ack. A visible mismatch is already caught within one heartbeat plus `kReportGrace`.
Fifteen minutes:
- keeps that blind window well inside TAR's one-hour connection history;
- is three times the IP-claim window;
- is a minutes-scale refresh, consistent with how commercial endpoint platforms refresh host details.

At 10k agents with 150 KB bodies, the floor costs about 1.7 MB/s fleet-wide, against about 50 MB/s
today.

### D8. Resync: a reserved Subscribe command, `__resync__`

The server needs a way to tell one agent "send me your full tag set" or "send me your topology"
without per-agent gateway state. Four options were weighed:

**(a) Piggyback the verdict on a synchronous response.**
- `HeartbeatResponse` is answered locally by the gateway, so it cannot carry the verdict without
  per-agent gateway state.
- `TopologyAck` (the proxied `ReportTopology` response) is synchronous end-to-end, but it reaches
  only agents that are *sending a body*. A quiet agent, or one with `--no-topology`, never asks, and
  tag divergence is independent of topology.
- A new small jittered "check" unary (agent sends its digests, server answers with the verdict)
  works without gateway state. But it adds a proxied round trip per agent per check interval, so
  convergence latency equals that interval. To converge within a minute it costs about 1,700
  unaries/s at 100k agents, steady, forever, to serve a condition that is rare outside restarts.
- **Rejected.**

**(b) A reserved Subscribe command.** Server to agent, on the stream every agent already holds open,
relayed by the gateway like any command (no new gateway state).
- The cost, re-weighed honestly:
  - one row per command in the agent's `CommandDedupStore` ring. The ring is a bounded, clock-free
    rowid ring over terminal rows (`kMaxDedupRows`, 20,000), so the cost is transient. Each
    `__resync__` does take one terminal slot, and so shortens by one command the window in which
    ADR-0074 D5's replay bar can rely on the ring. The per-agent intervals below cap that at one
    `tags` per 60 s and one `topology` per 5 min, and only while the agent diverges;
  - one capability-catalogue row per action with an `ExecuteGate` (compile-time, once);
  - one `command_execution` record per dispatch, written by `build_classified_command` like every
    other dispatch: a Postgres upsert on the issuing replica, made by the resync issuer off the
    heartbeat path (below). It is kept, because the Forensics provenance rule needs one record per
    dispatch;
  - one id-prefix skip in `notify_exec_tracker`;
  - a small `CommandResponse` relayed back up, and dropped at ingest (below): no `ResponseStore`
    row and no provenance lookup.
  - **Combined Postgres rate after a server restart.** A reattach costs about three Postgres
    operations (enrollment read, route CAS, record read; D14) at up to `--reattach-rate`, and each
    issued resync one record write at up to `--tag-resync-rate` plus `--topology-resync-rate`. At
    the defaults, overlapping, that is up to about 8,000 operations per second per replica against
    the default `--postgres-pool-size` of 16. Agents that re-register instead (`NO_RECORD`) add one
    registration-record transaction each (D14). It is unmeasured. It is to be measured against the
    pool size alongside ADR-0074's wave-2 measurement of a mass re-enrollment after an outage,
    before the defaults are relied on.
- It is paid **only when divergence occurs**: after a server restart, replica change, upstream
  outage or real loss. It is zero in steady state.
- Latency is one stream hop.
- **Adopted.**

**(c) Agent-driven self-healing:** a jittered periodic full set, with no server signal.
- Bandwidth is trivial: about 4 KB per agent per period.
- But the period *is* the worst-case divergence and post-restart latency. At 15 min, state-derived
  fleet gauges, Guardian generation reconcile and the corruption sink would run on missing data for
  up to 15 min after every server restart.
- At 1 min, the full set rides every second beat, and the gateway decodes about half today's tag
  volume, which forfeits much of the saving.
- **Rejected as the mechanism.** It is also not added as a backstop: the digest checks every beat,
  so (b) is triggered whenever a backstop could have helped.

**(d) Lean on reconnection.** A full set already goes with every Register, so the server could
force a reconnect. That tears down the connection, costing the gateway a TLS handshake and per-agent
process churn, to fix a 4 KB discrepancy. **Rejected.**

**Mechanism.**
- **Reserved name `__resync__`**, actions `tags` and `topology` (parameter `window_s`, default 60).
  It is handled in the agent's Subscribe command loop alongside `__sync__` (`agent.cpp`, the
  reserved-name dispatch from about l.3430, with `__sync__` at about l.3483-3531). The decision logic is a pure, unit-tested function,
  like `agents/core/src/sync_now_decision.hpp`.
- **Dedup.** The command is **dedup-claimed**; only `__guard__` bypasses the claim (ADR-2002 WS-0).
  `record_command_terminal` runs **before** the stream write.
- **Agent handler.** It runs inline on the Subscribe reader thread, as `__sync__`'s does. It only
  arms a request and wakes the thread that acts on it, records the terminal, and writes the
  response. It never sends tags or a body itself.
  - `tags` sets a member atomic that the heartbeat thread reads. SUCCESS means armed.
  - `topology` arms the topology sender and wakes it. SUCCESS means armed. With no running topology
    sender (`--no-topology`, or none yet on this connection) the answer is a FAILURE terminal.
  - An unknown action is a FAILURE terminal.
- **Agent response.**
  - `tags`: the heartbeat thread sends `full = true` on **every** heartbeat until two full
    heartbeats have been acknowledged after the request. There is no extra RPC, because the
    heartbeat is already jittered. Keep-newest coalescing (D4) can replace one full heartbeat with a
    newer one before a flush; repeating the full set means a single coalescing cannot lose it, and
    the gateway stays opaque. It is not a guarantee under a sustained upstream outage: a full set
    that is still lost leaves the agent `no_base` or `diverged`, and the server asks again after the
    per-agent interval.
  - `topology`: the topology sender sends `RESYNC` after a uniform delay in `[0, window_s]` (D7).
- **Ownership on the agent.** The delta base (the last acknowledged state set and its digest) is
  owned by the heartbeat thread: only it reads or writes the base. The `tags` request atomic is set
  by the reader thread and cleared by the heartbeat thread, only after the second acknowledged full
  heartbeat. A new connection resets the base to the Register's full set (D2) and clears the
  request.
- **Reserved name on the agent.** `__resync__` is added to `kReservedPluginNames`
  (`agents/core/include/yuzu/agent/plugin_loader.hpp`, #822), so no plugin can claim the name.
- **Server.**
  - Command ids are minted `__resync__-<action>-<epoch seconds>-<random hex>`, the reserved-literal
    convention `mint_sync_now_command_id` uses for `__sync__-now-` (`server.cpp`). An id is never
    derived from the agent id or from a previous id. `notify_exec_tracker` skips the
    `__resync__-` prefix like `polchk-` and `preflight-` (`server/core/src/agent_service_impl.cpp`):
    no tracker row, no SSE, not in the executions drawer. Every issuance mints a fresh id, because
    an agent answers a repeated id from its dedup ring without acting on it again.
  - The pairs `(__resync__, tags)` and `(__resync__, topology)` are two rows in
    `server/core/src/capability_decls/core_dispatch_capabilities.hpp`, the fragment for dispatches
    the server issues itself: `system_reserved = true`, ReadOnly, `ExecuteGate::None`. The change
    updates that array's size, the file comment's row list, and the docstring of
    `tests/test_capability_catalogue_complete.py`.
  - Operator surfaces (REST `/api/command`, MCP `execute_instruction`, workflows, dashboard) are
    refused centrally: `classify_and_authorize_dispatch` (`agent_registry.hpp`) denies any
    non-system caller a `system_reserved` row. No per-surface rule is added.
  - They are built with `build_classified_command(DispatchCaller{.system = true}, ...)` and sent
    with `send_system_reserved` to the agent's own stream (plus `forward_gateway_pending` for a
    gateway agent), as `__sync__.now` is. That is a `DispatchCaller` construction, of the
    existing system kind; it threads no operator authority and adds no `approval_provenance`
    stamping site. It is not a fleet dispatch. `SystemReservedPush` gains one enumerator for it.
  - `__resync__` is **not** in the protective set. A kill switch on it, or a degraded enablement
    store, refuses it at `build_classified_command`; that is counted `send_failed`, and divergence
    persists until the next permitted issuance.
  - **Ingestion only marks.** A heartbeat that requests a resync (D3, D6) adds the agent to a
    per-replica pending set: one entry per agent and action, deduplicated, so the set is bounded by
    the agents whose heartbeats reach this replica (gauge `yuzu_server_resync_pending{action}`).
    Ingestion does no Postgres work and no send for it, so a resync adds nothing to a batch's
    #5686 per-batch Postgres budget or to the gateway's 5 s BatchHeartbeat call timeout
    (`yuzu_grpc_client`'s default, per the `yuzu_gw_heartbeat_buffer.erl` header). A slow pool
    cannot push a batch past the timeout and make the gateway resend it.
  - **A per-replica issuer drains the set** on its own thread, at the configured rate and per-agent
    interval. It is not leader-gated: the replica that lacks the state is the one that must ask.
    Each drain pass is one loop with one `DispatchRecordLatch` (`dispatch_record_policy.hpp`), so
    each record write uses the 250 ms fan-out lease budget. At the first failed write the issuer
    ends the pass, rather than sending the rest with skipped records, and leaves the remaining
    marks in the set, counted `deferred`. A Postgres outage therefore delays resyncs and never
    blocks heartbeat ingestion.
  - **No installed session yet.** A mark for an agent this replica has no installed session for
    (after a restart, until its reattach lands, D14) stays in the set, counted `deferred`, and is
    tried on a later pass. Only a send attempted on an installed session is ever `send_failed`.
  - **The reply is dropped at ingest.** Like a solicited `__guard__` reply on the direct Subscribe
    loop (`agent_service_impl.cpp`, about l.1561-1569), a `__resync__` reply is dropped on both
    ingest paths before the provenance lookup: no `ResponseStore` row and no
    `resolve_response_provenance` call. The acknowledgement that matters is the `full = true`
    heartbeat or the topology report, not the reply.
  - Under ADR-0074 D5 every command is server-signed and every result agent-signed; `__resync__` is
    a command like any other and takes no exemption.
- **Rate limits** (per replica, applied by the issuer). A mark over the rate stays in the set for a
  later pass and is counted `deferred`; nothing is dropped permanently, because divergence persists
  until fixed.
  - **Figures are per replica.** Issuing takes N / rate seconds, where N is the number of agents
    whose heartbeats reach that replica. Every figure here is for N = 100,000 on one replica. Both
    defaults are unmeasured (see the combined Postgres rate above).
  - `tags`: `--tag-resync-rate`, default 2000/s, at most one per agent per 60 s. A full set is about
    4 KB. Issuing takes about 50 s for N = 100,000, but tags converge in about **two minutes**: the
    first heartbeat after a restart (up to 36 s) marks the agent, issuing drains over about 50 s,
    and the full set rides the agent's next heartbeat after delivery (up to 36 s more).
  - `topology`: `--topology-resync-rate`, default 200/s, at most one per agent per 5 min. N / 200 s:
    about 8 min for N = 100,000, at about 30 MB/s of body ingest.
  - **Per-agent backoff after `rejected`.** The per-agent `tags` interval starts at 60 s and doubles
    for each consecutive `rejected` outcome, to a cap of 15 min. An accepted payload resets it. A
    `diverged` or `no_base` outcome keeps the 60 s interval.
- **Loss.** A command that cannot be sent (no stream) is not retried by itself. The agent's next
  diverged heartbeat marks it again, and it is issued after the per-agent interval. An agent whose stream is down
  reconnects, and its Register carries the full set anyway.

**Direct-connected agents use the same command.** There is one mechanism, not a response flag on one
path and a command on the other.

### D9. Jitter: no clock-aligned periodic work

| Timer | Value |
|---|---|
| Heartbeat | 30 s, each sleep uniform ×[0.8, 1.2]; first beat after connect uniform [0, 30 s]. The cadence is unchanged so the interval tags keep their meaning. Rates divide by measured `steady_clock` elapsed (`agents/core/src/net_quality_sampler.cpp`), so jitter does not bias them. |
| Topology pump | 60 s, each sleep uniform ×[0.8, 1.2]; first run uniform 5-65 s. Flags: `--topology-interval` (30-900 s; the base value rides every heartbeat as `TopologyDigest.pump_interval_s`, D5) and `--no-topology` (no pump; `DISABLED` on the wire). |
| Change report | uniform 0-10 s after change |
| Refresh floor | uniform 12-18 min |
| Startup report | uniform 0-60 s |
| Resync report | uniform `[0, window_s]` from `__resync__.topology`, default 60 s |
| Server `kReportGrace` | 120 s |
| Agent reconnect backoff | full jitter: uniform [0, min(2^n, 300) s]. Today it is exactly `min(2^n, 300)` (`agent.cpp`, `kMaxReconnectDelaySecs` and the backoff at about l.1689-1724), so every agent dropped by one gateway restart retries on the same schedule. |

Every timer is re-drawn per cycle. None is derived from wall-clock boundaries. Server-originated
work is rate-limited at the source (D8). Reviewers reject any new heartbeat or topology timer that
lacks jitter. ADR-0074 D11's two-phase jittered drain follows the same rule.

### D10. What is removed (no backward compatibility)

The owner ruled 2026-10-26: no live customers; aggressive changes for the better.

- **Proto:**
  - `HeartbeatRequest` fields 3 and 4 stay but are marked `[deprecated = true]`, with a comment
    naming ADR-0073, in `proto/yuzu/agent/v1/agent.proto` and both gateway copies
    (`gateway/priv/proto/agent.proto`, `gateway/priv/proto/yuzu/agent/v1/agent.proto`). The agent
    stops populating them and the server and gateway ignore them (D15: no proto subtraction);
  - `agent_pb.erl`, `gateway_pb.erl` and `management_pb.erl` (`gateway/apps/yuzu_gw/src/`) are
    regenerated;
  - no dual parsing and no agent fallback.
- **Agent:**
  - the flat tag build becomes a state map plus an interval map, diffed against the base;
  - the topology attach block (`agent.cpp`, about l.3083-3101) and `last_attached_seq` go;
  - `yuzu.uptime_s` goes.
- **Server:**
  - `AgentHealthStore::upsert(Map)` becomes `apply(agent_id, StatusTags) -> ApplyOutcome`, with
    separate interval and state maps;
  - the field-4 branch of `HeartbeatIngestion::ingest` (`heartbeat_ingestion.cpp`, about l.176-200)
    goes;
  - the **legacy dispatch fetcher** (`server.cpp`, the `tar.fleet_snapshot` fan-out at about
    l.5528-5700) goes, with the store's `Fetcher` seam and
    `yuzu_viz_topology_fetch_duration_seconds`. Cold start becomes roster placeholders filled by
    resync, not a fleet-wide pull down the Subscribe streams;
  - the `echo.fleet_snapshot` row in `core_dispatch_capabilities.hpp` stays `system_reserved`
    with no server caller. It must not move to an operator-dispatchable catalogue fragment.
- **Gateway heartbeat buffer** (`yuzu_gw_heartbeat_buffer.erl`): these go:
  - newest-snapshot coalescing (header l.13-24, `coalesce/2` at about l.588), snapshot-first
    eviction and send-without-snapshot;
  - per-tag counting, size checks and UTF-8 repair (about l.460-583; moved to the server, D3);
  - the `snapshot_oversize` and `snapshot_evicted` drop reasons (`drop_reason()` at l.169-170).
    `heartbeat_invalid` stays, for the unkeyable-session and encoder-raise drops (D4).

  Keep-newest coalescing, chunking, the byte cap and the session cap stay, applied to opaque
  heartbeats.

An old agent still populates fields 3 and 4. The new gateway and server decode them as the
deprecated fields they remain and ignore them. They still cost bytes until the agent is upgraded,
which is why this is one coordinated release.

### D11. The pump and ADR-0021

Converting the pump to an embedded-content Reflex is **out of scope**. The Reflex deployment runtime
is not live (`prefer_spark_` is false in production), and coupling a transport-cost fix to it would
stall the fix.

This ADR delivers the tunable and disableable parts now (`--topology-interval`, `--no-topology`,
`DISABLED`). It structures the pump as schedule, then action, then digest compare, then report, which
is the Spark-to-Reaction shape. The later conversion replaces only the schedule.

### D12. Server-pull when `/viz` is viewed: deferred

On-change push keeps a changed host's body within about 82 s (72 s pump plus 10 s send delay), and an
unchanged host's body is current by definition. Pull-on-view would add little.

It would also make a `Response:Read` page view dispatch work to agents, a read causing execution that
the dispatch-authorization model would have to admit and audit. A future single-host "refresh now"
would be an explicit operator action with its own gate and audit verb. It would issue
`__resync__.topology` for one agent, not run as a side effect of a read. Fleet-view pull is rejected
outright for the same burst reason the dispatch fetcher is removed.

### D13. Observability

Labels are bounded enums. Counters are pre-seeded to 0. Changes follow
`docs/observability-conventions.md`.

**Agent:**
- `yuzu_agent_heartbeat_bytes` (histogram);
- `yuzu_agent_heartbeat_tag_upserts` (histogram per beat);
- `yuzu_agent_status_tags_dropped_total{reason}`, with
  `key_oversize|value_oversize|invalid_utf8|count_cap|total_cap` (D1);
- `yuzu_agent_heartbeat_full_tags_total{reason}`, with `register|resync`;
- `yuzu_agent_commands_executed_total{plugin="__resync__"}` (the existing family);
- `yuzu_agent_topology_pump_total{outcome}`, with `ok|unchanged|truncated|failed` (`ok` and
  `unchanged` are both `OK` on the wire, D5);
- `yuzu_agent_topology_reports_total{reason,result}`;
- `yuzu_agent_topology_report_bytes` (histogram).

**Server:**
- `yuzu_server_heartbeat_tags_total{via,outcome}`, with
  `synced|full|diverged|no_base|rejected|absent|unverifiable` (`via` includes `register`, D3);
- `yuzu_server_tag_resync_total{outcome}`, with `sent|deferred|send_failed`;
- gauge `yuzu_server_resync_pending{action}`, with `tags|topology`: the size of the pending set
  (D8);
- `yuzu_server_agent_reattach_total{outcome}`, with
  `accepted|no_record|not_enrolled|superseded|malformed_session|degraded|rate_limited` (D14);
- `yuzu_server_agent_registration_store_failed_total{op}` (D14);
- `yuzu_viz_topology_pushed_total{via,reason}` (gains `reason`);
- `yuzu_viz_topology_push_parse_errors_total{via}` (unchanged);
- `yuzu_viz_topology_report_rejected_total{via,reason}`, with
  `parse|digest_mismatch|ip_conflict|oversize|unknown_session` (D7; `parse` also moves the parse
  counter above);
- `yuzu_viz_topology_reclaim_total{outcome}`, with `reclaimed|conflict` (D6);
- `yuzu_viz_topology_digest_total{via,outcome}`, with `match|mismatch|no_slot|empty|disabled|absent`
  (`empty`: an empty digest; `disabled`: `DISABLED`; `absent`: no field);
- `yuzu_viz_topology_resync_total{outcome}`, with `sent|deferred|send_failed`;
- gauge `yuzu_viz_topology_slots{state}`, with `fresh` plus every `stale_reason` value except
  `offline` (D6), computed from the same enum when a snapshot is built. `offline` hosts are added at
  read time from the durable roster and are not store entries.

**Gateway:**
- `yuzu_gw_topology_proxied_total{result}`;
- `yuzu_gw_heartbeat_coalesced_total` (unchanged; it counts keep-newest replacements, which now
  predict server-side `diverged` verdicts);
- `rpc="ProxyTopology"` on the peer-guard metrics;
- `snapshot_oversize` and `snapshot_evicted` are retired from
  `yuzu_gw_heartbeat_buffer_dropped_total{reason}`, and their documentation is removed.
  `heartbeat_invalid` stays and now counts only unkeyable-session and encoder-raise drops; its
  documentation is updated to say so.

**Alerts** (`docs/prometheus/yuzu-alerts.yml`, ticket severity, never paging):
- `YuzuHeartbeatTagDivergenceSustained`: the `diverged` share stays above 1 % of heartbeats for
  30 min **while the gateway's coalescing rate is near zero**. Outside an outage, that indicates a
  canonical-form or agent delta defect rather than a fleet event. Its runbook also names the
  per-RPC-balancing symptom (*Server stores*): a `diverged` plus `no_base` share near 100 %.
- `YuzuVizTopologyResyncBacklog`: `deferred` stays above 0 for 30 min.

**Fleet-gauge semantics.** `yuzu_fleet_*` are rebuilt from the merged views. While an agent is
`no_base` (after a server restart, until its full set lands), its state-derived gauges are absent,
not zero, and its interval-derived gauges are present. The documented consequence: after a server
restart, state-derived fleet gauges converge in about two minutes for N = 100,000 agents on one
replica (N / `--tag-resync-rate` of issuing plus up to two jittered heartbeats, D8) instead of one
heartbeat.

### D14. Registration replay by ids: the gateway keeps no RegisterRequest

**Why.** This is the no-per-agent-state ruling applied to the largest piece of per-agent state the
gateway holds. The gateway is a relay. A registration's facts belong to the server, which already
decides enrollment, owns the route directory (ADR-2002 WS-4) and holds the durable endpoint store.
Keeping the request so the gateway can replay it later makes the gateway a second, weaker copy of
server state. That copy is about 87 KB per agent, and it holds a credential.

**What the gateway keeps per agent.** Each item is part of the connection and is justified by a
reader, not by habit:

| Fact | Why the gateway needs it |
|---|---|
| `agent_id` | the routing key for command fan-out and the registry; sent on reattach |
| `session_id` | heartbeat admission and binding (`yuzu_gw_heartbeat_admission`); sent on reattach for the route-directory CAS |
| connection, stream and owner references | delivering commands down the agent's own Subscribe stream |
| `stream_home_id`, owner key | already sent in the CONNECTED notification that follows a reattach (`yuzu_gw_upstream.erl`, `handle_cast({notify_stream_status, ...})` at about l.1442-1478), unchanged |
| observed peer address | a transport fact only the gateway sees. It fills `RegisterRequest.gateway_observed_peer` today and is sent on reattach so the server's session keeps it. The gateway keeps the raw origin it decided (`origin_text/1` in `yuzu_gw_agent_service.erl`), empty when it has no observation. Today's `peer_addr` substitutes `<<"unknown">>` for empty; that display value is never what reattach sends. |
| `connected_at` | management-plane liveness answers |

It keeps **no** hostname, platform, version, plugin list, plugin names, scopable tags, status tags,
enrollment token, CSR, certificate or attestation.

**The pending row.** Between Register and Subscribe, `yuzu_gw_agent_service:register_upstream/4`
stores a `yuzu_gw_pending` row (`yuzu_gw_registry:store_pending/3`) that today holds the verbatim
`register_req` and its `agent_info`: a fourth copy, with the token, for the pending TTL. Under this
ADR that row keeps only `agent_id`, the observed origin, `conn_key` and `registered_at`, the
connection facts the Subscribe match and the per-connection session cap need.

**Replay becomes reattach.**

```proto
// GatewayUpstream
rpc ProxyReattach(ReattachRequest) returns (ReattachResponse);
message ReattachRequest {
  string agent_id = 1;
  string session_id = 2;          // authoritative; x-yuzu-session-id must equal it or MALFORMED_SESSION
  string observed_peer = 3;
}
message ReattachResponse {
  bool accepted = 1;
  string session_id = 2;          // the adopted session
  ReattachRefusal refusal = 3;    // NO_RECORD | NOT_ENROLLED | SUPERSEDED | MALFORMED_SESSION | DEGRADED | RATE_LIMITED
  uint32 retry_after_ms = 4;      // set with RATE_LIMITED and DEGRADED
}
```

- **Triggers and pacing are unchanged.** `yuzu_gw_upstream`'s replay (described in its module
  header, "Registration replay: what the server says it does not know") keeps everything it has
  today:
  - targeted replay of `unknown_session_ids`;
  - full replay only on evidence the server lost state;
  - start jitter (`registration_replay_start_jitter_ms`);
  - the replay permit pool and concurrency cap (`upstream_replay_concurrency`);
  - the 60 s full-replay cooldown (`FULL_REPLAY_COOLDOWN_MS`);
  - re-announcing CONNECTED after an adopt (`yuzu_gw_agent:reannounce/2`).

  Only the payload changes, from a stored request to two ids and a peer address. That removes the
  `local_error` encode-failure branch of `replay_send/4`.
- **The observed peer on the server.** `observed_peer` is parsed with the same strict
  `normalize_bare_ip` that ProxyRegister applies to `gateway_observed_peer`. Empty, or a value
  that does not parse, means "not observed": the session's source IP and any reattach audit row
  fall back to the gateway's own IP and record `origin_observed=false`, exactly as ProxyRegister's
  audit attribution does today (`gateway_service_impl.cpp`).
- **Which session id counts.** The body's `session_id` is the session presented. The gateway also
  sends it as `x-yuzu-session-id`, as replay does today. The server refuses `MALFORMED_SESSION`
  when the metadata value is present and differs from the body, or when the body's id is not a
  server-minted session id (`is_server_minted_session_id`, the check ProxyRegister applies).
- **Server** (`GatewayUpstreamServiceImpl::ProxyReattach`, `server/core/src/gateway_service_impl.cpp`):
  0. `onbehalf::enforce(context)`, before any side effect, as in every gateway-upstream handler;
  1. gateway peer authorization (`GatewayPeerGuardedService` override; D7's rule for a new upstream
     RPC);
  2. `registration_lock_for(agent_id)`;
  3. enrollment status read (the existing fast-path read, `get_pending_status`). Only
     `PendingStatus::approved` proceeds. `pending`, `denied` or no row answers `NOT_ENROLLED`. A
     store error answers `DEGRADED` (the fast path's `UNAVAILABLE` semantics), never
     `NOT_ENROLLED`. Reattach can never enrol. "Revoked" is not an enrollment state: certificate
     revocation is serial-scoped, and it does not gate reattach, just as it does not gate the
     ProxyRegister fast path today;
  4. read the agent's `AgentRegistrationStore` record and its interned plugin set. A missing
     record, or one whose stored `session_id` is not the presented session id, answers
     `NO_RECORD`; a degraded read answers `DEGRADED`, retryable and fail-closed. The read comes
     before the adopt step, so a refusal here leaves the route directory untouched. **Never
     install a session from partial facts:** an empty plugin list would make dispatch report
     `plugin_not_found`, and empty scopable tags would silently change scope results;
  5. **the same adopt decision ProxyRegister uses** (`renew_leases` / `reclaim_tombstoned_session`
     CAS, `server/core/src/gateway_route_store.hpp` and its FORWARD NOTE), extracted into one shared
     function and called from both RPCs. Never a second copy. Whatever ADR-0074 decides about
     cluster affinity (its Conflict 1) therefore applies to both RPCs at once;
  6. install the `AgentSession` through `AgentRegistry::register_agent`, from an `AgentInfo`
     rebuilt from the record, then map the adopted session id and `observed_peer` as
     ProxyRegister's adopt path does. Because the install
     runs the same code as a Register:
     - `plugin_names`, `plugin_meta` and `legacy_echo_wire_name` are derived from the stored
       PluginInfo list exactly as at registration, including the pre-rename `tar` to `echo`
       normalisation (`agent_registry.cpp`);
     - the stored scopable tags go through the same ingest validation, including dropping a
       self-reported `service` key (#3295), and are treated as a fresh Register treats them.
       `TagStore` stays the authority wherever it has a row for the agent; the record's copy is only
       the in-memory fallback a gateway-proxied session already has. Reattach never writes to
       `TagStore`, so it never re-creates a tag an operator removed there.

  The CONNECTED re-announce then sets `gateway_node`, wire capabilities, `stream_home_id` and
  `cluster_id`, as today. Status tags and topology are **not** in the record. A replica that still
  holds the agent's `AgentHealthStore` entry (an upstream reconnect to the same replica within 90 s)
  continues from that base. On a replica with none (a server restart, another replica, an entry
  pruned after 90 s without a heartbeat) the next heartbeat is `no_base`, and `__resync__.tags`,
  then `__resync__.topology`, converge them (D3, D8).
- **Reattach is a continuation, not a registration.** A successful reattach fires no
  `agent.registered` webhook or offload event and writes no registration audit row, because the
  agent did not enrol or register again. Every outcome is counted on
  `yuzu_server_agent_reattach_total{outcome}` (D13). The refusals that say something about the
  caller, `NOT_ENROLLED`, `SUPERSEDED` and `MALFORMED_SESSION`, also write an `agent.reattach`
  audit row with `result=refused` and the refusal. `NO_RECORD`, `DEGRADED` and `RATE_LIMITED` are
  counted only, so a store outage or a restart storm cannot flood the audit log.
- **Every outcome, in one table.** The adopt decision is shared (step 5), so ProxyRegister and
  ProxyReattach answer from the same outcome. ProxyReattach always answers `OK` with a
  `ReattachResponse`; its refusals are values, never gRPC error statuses, so the gateway's breaker
  (`yuzu_gw_upstream:record_result/2`) sees an answer it can classify.

  | Outcome | ProxyRegister answers (today) | ProxyReattach refusal | Gateway action | Breaker |
  |---|---|---|---|---|
  | adopted | `OK`, adopted session | none (`accepted = true`) | re-announce CONNECTED (`yuzu_gw_agent:reannounce/2`) | success |
  | no record, or a record from another session (step 4) | not applicable | `NO_RECORD` | disconnect the agent's stream | success |
  | not `approved` (step 3) | rejected enrollment (`accepted = false`) | `NOT_ENROLLED` | disconnect the agent's stream | success |
  | superseded by a different live session, or held by another agent | `FAILED_PRECONDITION` | `SUPERSEDED` | disconnect the agent's stream | success |
  | presented id malformed, or body and metadata differ | `FAILED_PRECONDITION` | `MALFORMED_SESSION` | disconnect the agent's stream | neutral |
  | enrollment, record or directory read degraded | `UNAVAILABLE` | `DEGRADED` | **keep the stream**; leave the session to the next targeted replay, after `retry_after_ms` | neutral |
  | over `--reattach-rate` | not applicable | `RATE_LIMITED` | keep the stream; requeue the session after `retry_after_ms` | neutral |

  `DEGRADED` must never disconnect: a Postgres outage would otherwise tear down every agent the
  gateway holds. `SUPERSEDED` stays a breaker success, as `FAILED_PRECONDITION` is on replay today,
  so a run of stale replays after a reconnect storm cannot trip the breaker.
- **Fallback is re-registration by the agent, not `__resync__`.** On `NO_RECORD` or `NOT_ENROLLED`,
  the gateway does what it already does for a replay answered `accepted = false`
  (`yuzu_gw_upstream:replay_send/4`, about l.1964-1976): it disconnects the agent's stream. The agent
  reconnects with its jittered backoff (D9) and sends a fresh Register, which runs the full
  enrollment path and writes a new record.

  `__resync__` cannot serve here. It is a Subscribe command, so the server must already hold an
  installed session to route it, and installing a session without the registration facts is exactly
  what step 4 refuses.
- **Authority is unchanged, and stated so it stays that way.** Today's replay presents the stored
  request, but for an enrolled agent the server takes the fast path and ignores the token. Replay
  authority already rests on two things:
  - the gateway's peer authorization;
  - the agent's durable enrolled status.

  The route-directory CAS is a supersession fence, not proof that the gateway holds the session: it
  refuses a session superseded by a different live one, but a tombstoned or absent row is reclaimed
  under any well-formed session id. Reattach rests on the same two things as the ProxyRegister fast
  path, so removing the token removes exposure, not a check.
- **Reattach and ADR-0074 D5's per-session signature, stated plainly.** As designed here, reattach
  has no agent step: it carries ids only and is invisible to the agent. It therefore cannot carry
  the D5 per-session proof, which is the agent signing a server challenge at session start. Until
  the owner resolves this (open point 13), a reattached session, and the route its CONNECTED
  re-announce writes, inherit ADR-0074 Conflict 1's accepted route-claim risk: a compromised
  gateway with a valid certificate can reattach any enrolled agent whose route row is not held by
  a different live session, and claim that route.

**What the server persists: `AgentRegistrationStore`.**
- **Placement.** Born on Postgres, schema `agent_registration_store` (ADR-0006/0008 naming,
  ADR-0012 store contract, `docs/postgres-store-playbook.md`). Construction fails closed per
  ADR-0007/0012.
- **Table `registrations`:**
  - columns: `agent_id TEXT PRIMARY KEY`, `session_id TEXT NOT NULL` (the session of the
    registration that wrote the row), `hostname`, `os`, `arch`, `agent_version`,
    `scopable_tags JSONB` (as the agent sent them; filtered again on every install, step 6),
    `plugin_set_hash TEXT NOT NULL`, `registered_at BIGINT NOT NULL`;
  - `registered_at` is authored by Postgres `now()` in SQL, never the replica's clock (the ADR-2002
    #3715 DB-clock rule);
  - no secret is stored: no enrollment token, CSR, certificate or attestation;
  - no `cluster_id`: it is a per-connection routing fact, not a registration fact, and it comes
    only from the CONNECTED re-announce that follows a reattach. Storing it would be the gateway
    affinity D16 says reattach does not add.
- **Table `plugin_sets`:**
  - columns: `plugin_set_hash TEXT PRIMARY KEY`, `plugins JSONB NOT NULL`;
  - the PluginInfo list is stored as the agent sent it, before any server-side normalisation, so
    that reattach derives the session's plugin facts through the same code as Register (step 6);
  - the list is interned by a SHA-256 over its canonical encoding;
  - PluginInfo is compiled into the agent, so a fleet has one row per (version, OS, build), not one
    per agent. Replicas cache rows by hash in memory; the table is immutable per hash.
- **Writes.** One upsert of the agent's row, plus an insert-if-absent of its plugin set, in one
  transaction, after every successful fresh registration (direct `Register` and `ProxyRegister`).
  - It runs synchronously in the registration handler, after the session is installed and before
    the RPC returns, with the store's bounded lease acquire (ADR-0012). On `ProxyRegister` it runs
    inside `registration_lock_for(agent_id)`; direct `Register` has no such lock today. It is not on
    the enrollment decision.
  - `registration_lock_for` is per replica, so it does not order a Register on one replica against
    a reattach on another. The session binding does: a reattach installs only from a row written by
    the session it presents (step 4).
  - A failed write is logged and counted (`yuzu_server_agent_registration_store_failed_total{op}`)
    and the registration proceeds. A failed upsert leaves the previous row, which names the previous
    session, so the agent's next reattach answers `NO_RECORD` rather than installing stale plugin or
    tag facts, and the agent re-registers.
  - **Cost at storm rates.** It is one transaction per registration, so it runs at the Register
    rate: during a gateway-restart reconnect storm inside ADR-0074 D14's 60-second target, about
    1,700 per second for 100,000 agents fleet-wide. The `registrations` row changes on every
    registration, because `session_id` does, so the upsert cannot be skipped as unchanged. The
    `plugin_sets` insert is skipped when the replica's in-memory cache already holds the hash, and
    is otherwise an insert-if-absent. The write's bounded lease acquire adds to Register latency
    under pool contention; it is measured with the combined rate in D8. A lost write is paid back
    later, as one reconnect: the agent's next reattach answers `NO_RECORD`, and the agent pays a TLS
    handshake and a full Register.
  - Reads on reattach fail closed (step 4).
- **Backup and restore.** The schema is in the standard Postgres backup scope, like every
  server store. After a restore, rows whose `session_id` no longer matches the session an agent
  presents answer `NO_RECORD`, and those agents re-register once.
- **Lifecycle and retention.**
  - A `registrations` row persists until the agent is decommissioned. There is no retention pass:
    the table holds one row per agent that has registered, the same population and lifetime as the
    agent's enrollment record, and a row is only useful while that agent may still reattach. A
    device retired without a decommission keeps its row, as it keeps its enrollment record; the
    decommission cascade is the erasure path. No clock-guarded-retention apparatus applies,
    because nothing is deleted on a wall-clock cutoff.
  - Rows are deleted by the agent decommission cascade (`server/core/src/agent_decommission.hpp`).
    The header's four mandatory steps all apply: (a) append the store to
    `AgentDecommissionStores`; (b) register it in `agent_decommission.cpp`'s registration list;
    (c) bump `kCascadeStoreCount` in `tests/unit/server/test_agent_decommission.cpp`; (d) add it
    to the blast-radius lists in `sle_routes.hpp`/`.cpp`, `rest_api_v1.cpp`'s delete block,
    ADR-0024 Decisions 9 and 11, and `docs/user-manual/rest-api.md`.
  - **Cascade against a concurrent registration.** The cascade's delete does not take
    `registration_lock_for`. A registration that commits after the delete re-creates the row. That
    is by design: an agent still connected after a decommission re-registers and is present
    again, as it repopulates the cascade's other per-agent stores until a decommission tombstone
    exists (`agent_decommission.cpp`). A reattach that reads after the delete answers `NO_RECORD`.
  - `plugin_sets` rows are never deleted. They are bounded by the number of distinct agent builds,
    so no retention pass applies to them either. They hold no per-agent data.
- **HA.** The record is fleet-wide, so a reattach succeeds on **any** replica. Today a replay needs
  the stored request, so it can only come from the gateway that holds it. `OfflineEndpointStore`
  presence, `gateway_route_store` and `AgentRegistry` presence are unchanged. The registry's
  per-replica `AgentSession` is rebuilt from the record exactly as from a Register.
- **Not merged into `OfflineEndpointStore`** (`server/core/src/offline_endpoint_store.hpp`), though
  both hold hostname, os, arch and version. That store is written on every heartbeat for presence.
  This one is written once per registration for replay. Separate owners keep the per-heartbeat write
  narrow. A later change may make the presence store read identity from this one.

**Storm behaviour after a server restart at 100k agents.**
1. **The gateway replays sessions as ids.** Pacing is the existing replay start jitter and permit
   concurrency. The server adds a per-replica token bucket, `--reattach-rate`, default 2000/s.
   An over-rate call answers `OK` with refusal `RATE_LIMITED` and `retry_after_ms`, and the
   gateway requeues the session after that delay without touching the breaker. It is not answered
   `RESOURCE_EXHAUSTED`: the gateway counts that status as a breaker failure today
   (`yuzu_gw_upstream:record_result/2`), so a reattach storm would open the breaker. Each reattach costs one lock,
   one enrollment-status read, one route CAS and one primary-key read, with the plugin set usually
   cached. That is lighter than today's ProxyRegister replay, which carries a 9 KB, 69-plugin
   request.

   **Throughput** is min(`--reattach-rate`, gateways × `upstream_replay_concurrency` / per-call
   latency). The replay concurrency defaults to 24, half of `upstream_register_concurrency`'s 48
   (`yuzu_gw_upstream_regulator.erl`). So one gateway at 50 ms per call reattaches about 480 agents
   per second, and 100k agents behind one gateway take about 3.5 min; spread over ten or more
   gateways they reach the 2000/s server cap and take about 50 s. A targeted replay queue holds at
   most 10,000 agents per gateway (`registration_replay_queue_max`); a verdict that overflows it is
   dropped and counted `queue_full`, and a later verdict queues those sessions again. The 2000/s
   default and the per-call latency are unmeasured.
2. **Tags follow.** A mark for an agent that has not reattached yet stays `deferred` (D8), so tag
   issuing trails the reattach wave. At 2000/s per replica it adds about 50 s of issuing for
   N = 100,000, and tags converge in about two minutes after an agent's reattach.
3. **Topology follows.** `__resync__.topology` runs at 200/s per replica, about 8 min for
   N = 100,000.
4. **Agents do not reconnect** in steady state. Reattach is invisible to them. Only `NO_RECORD`
   agents reconnect, under jittered backoff.

   After this release every agent has registered at least once (no back-compat: agents are
   upgraded with the server, and the upgraded agent's first connection registers fresh), so
   `NO_RECORD` is the exception: lost writes, and agents that never re-registered since a
   decommission cascade.

This is a server restart, not a gateway restart: agents keep their connections, so ADR-0074 D14's
60-second full-reconnect target is not consumed by it.

**Gateway owner restart.** `yuzu_gw_agent_sup:restore_args/1` (about l.315) restores from the ids
row, not a stored request, and re-registers through reattach, like any replay.

**Management plane: `ListAgents`, `GetAgent` and `QueryInventory` are retired** (owner ruling
2026-10-26).
- **Why.** They are the only readers of the gateway's hostname and plugin data
  (`yuzu_gw_mgmt_service.erl`: `list_agents/2`, `get_agent/2`, `query_inventory/2`). The server
  calls only `SendCommand` (`gateway_mgmt_stub_pool.hpp`); a search of `server/core/src` at
  `dfdffa4c0` finds no call to the other three.
- **What stays.** `SendCommand` and `WatchEvents` stay live. The three retired RPCs and their
  request and response messages also stay in `proto/yuzu/server/v1/management.proto` (and the
  gateway's copy), marked `option deprecated = true;` with a comment naming ADR-0073 (D15: no proto
  subtraction). The gateway answers them `UNIMPLEMENTED`. The gateway gpb module is regenerated.
- **Where agent views come from.** The server's REST and MCP surfaces are the only agent views.
  No back-compat.
- **Status.** The retirement is gateway-only and may land ahead of the rest of this ADR (slice 0b).
  It needs no server change, because the server never called these RPCs. It is not on `dev` at the
  time of writing.

### D15. No proto subtraction (owner ruling 2026-10-26)

"Proto subtractions are breaking, so we should just not use the field, not remove it from the
protobufs." Nothing this ADR retires is deleted or `reserved`:
- `HeartbeatRequest.status_tags` (3) and `fleet_snapshot_json` (4): `[deprecated = true]`, not
  populated, ignored;
- management `ListAgents`, `GetAgent`, `QueryInventory`: `option deprecated = true;`, the gateway
  answers `UNIMPLEMENTED`; their request and response messages: `option deprecated = true;`, unused.

Each carries a comment naming ADR-0073. New fields, messages and RPCs are added as usual. The ruling
is about the schema only; behaviour toward old agents is still no back-compat (D10). `proto/buf.yaml`
enforces it with the `*_NO_DELETE` breaking rules.

### D16. Relationship to ADR-0074

ADR-0074 is the transport-security and topology decision for the same gateway. This ADR changes what
crosses the agent connection; ADR-0074 changes how the connection is authenticated and where it
lands. The two are kept consistent as follows.

- **Budget.** ADR-0074 D14 is the budget this ADR is measured against: 100,000 idle agents per
  8-core, 16 GB gateway, and the 64 KiB-per-agent CI regression check including the kernel. This ADR
  removes the per-agent payload terms (the snapshot binary, the tag-decode heap, the retained
  Register). It does not by itself meet the check; the remaining live state (TLS, the Cowboy
  connection, the relay, the inet port and buffer, the index rows) is addressed by ADR-0074's memory
  measures and kTLS (its D8).
- **State.** Both ADRs use the same rule: no per-agent state beyond the connection. Fleet-level state
  any gateway could rebuild is allowed (ADR-0074's Conflict 5, decided 2026-10-28).
- **Signing.** ADR-0074 D5's scope was decided on 2026-10-29: the server signs every command and
  the gateway list, the agent signs every result, and the agent signs a per-session challenge.
  Liveness heartbeats stay unsigned. That scope does not include `ReportTopology` or the state
  tags. ADR-0074 accepts unsigned heartbeats as **liveness** only, and it lists "honest heartbeats"
  among what D5 does not give.
- **What that leaves a compromised gateway, stated plainly.** The tag delta and the topology
  digest ride the unsigned heartbeat, and the topology body rides an unsigned unary. They carry no
  integrity beyond the agent's TLS session to the gateway.
  - The state digest (D3) detects loss and coalescing. It does not detect tampering: it is
    unkeyed, and it travels in the same unsigned bytes, so a gateway that rewrites a delta can
    rewrite the digest to match.
  - A gateway can therefore set any state tag value the server will accept as synced. Examples:
    suppress the Guardian generation re-push by reporting the current generation; mask
    `yuzu.dedup_degraded` or `yuzu.ota_signature_refused`; forge or suppress the plugin
    `db_corruption` facts that feed the corruption audit sink.
  - A full set sent in answer to a signed `__resync__.tags` is itself an unsigned heartbeat, so the
    signed command does not make the answer honest.
  - A forged topology digest keeps a host's slot confirmed and its IP claims alive (D6). A forged
    `ReportTopology` body can claim IPs for the agent.
  - This is wider than ADR-0074's accepted heartbeat risk, which is liveness only. Open point 12
    asks the owner to accept it or to require agent signatures on this content.
- **Gateway choice.** ADR-0074 lets agents move freely between gateways. Reattach adds no gateway
  affinity: a reattach succeeds on any server replica (D14, *HA*), and its adopt decision is the one
  ProxyRegister uses. The connection-level precondition in *Server stores* is about the gateway's
  own upstream connection to a server replica, not about which gateway an agent chooses.

## Considered options

1. **Keep the body and the full tag map on the heartbeat** (status quo). Rejected. Liveness carries
   bulk, and the gateway retains both terms as garbage: about 475 KiB binary plus about 310 KiB heap
   per TLS connection in the harness, far above ADR-0074 D14's 64 KiB check.
2. **Agent-only topology hash-skip** (attach the body only on content change, no server change).
   Rejected. Both topology liveness rules are keyed on body arrival, so every quiet host goes stale
   at 90 s and its IP claim lapses at 300 s, a quiet anti-spoof regression.
3. **ADR-0016 daily sync for topology.** Rejected. ADR-0016 deliberately excludes volatile data (IP
   addresses included) from hashed sources, and its cadence is daily. Its principle is adopted; its
   transport is not.
4. **Server-pull as the topology main path.** Rejected. At 10k agents × 150 KB, one refresh is a
   1.5 GB burst through the Subscribe streams. Pull-on-view as an addition is deferred (D12).
5. **Topology digest as a status tag** (the ruling's wording). Not chosen; D5 gives the reasons.
6. **Back-compat** (keep parsing fields 3 and 4, fall back on `UNIMPLEMENTED`). Rejected by owner
   ruling. It would also keep every path this ADR deletes.
7. **Tag deltas without a digest** (sequence numbers and acks only). Rejected. The gateway
   acknowledges heartbeats before the server sees them, and it coalesces and can drop them. A
   sequence scheme would need the server's ack to travel back through the gateway on every beat,
   which is per-agent gateway state or a new round trip. A state digest detects every loss and
   coalescing effect at the receiver with an opaque gateway.
8. **Server-opaque tag digest** (trust the agent's digest, as topology does). Rejected for tags. The
   server's merged view *is* the product here, and only a server-side recomputation proves it equals
   the agent's set. The shared `common/include` function removes the two-implementation hazard that
   made opacity attractive for topology.
9. **Every tag on change, including perf and net.** Rejected. Interval values are per-interval
   measurements whose absence is meaningful. Merging would publish stale rates as current.
10. **Longer heartbeat** (60-120 s). Deferred. With deltas, the beat is small, and the interval tags'
    30 s semantics (`/network`, `/dex` performance) would change with it. That is its own decision.
11. **Resync flags in `HeartbeatResponse`, delivered through per-session gateway bits.** This was
    the previous draft. Rejected by owner ruling (no per-agent gateway state). The alternatives
    weighed for the replacement are in D8: (a) a synchronous-response piggyback or a check unary,
    (c) a periodic agent full set, (d) a forced reconnect.
12. **Topology delta encoding** (send only changed rows). Deferred until D13's
    `yuzu_agent_topology_pump_total{outcome}` shows busy hosts dominate bytes.
13. **Topology body over the Subscribe stream.** Rejected. It puts bulk on the longest-lived flow; a
    unary gets its own admission, cap and failure semantics.
14. **Delta-aware gateway coalescing** (compose older and newer deltas in the buffer). Rejected by
    owner ruling (no parsing in the gateway). Keep-newest plus server-side digest repair costs one
    resync per changed agent after an outage under 90 s (one per agent after a longer one, D4), and
    nothing in steady state.
15. **Typed `StatusTags` in the heartbeat.** Rejected for `bytes` (D2), so the gateway never decodes
    tags.
16. **Keep the Register once at the gateway** (a registry row read by replay; about −29 KiB).
    Rejected. It still keeps per-agent registration state and the enrollment token, and only removes
    a duplicate.
17. **Keep the encoded Register as one refcounted binary** (about 9 KB, decoded on replay).
    Rejected for the same reasons. Smaller, but still per-agent state and a credential.
18. **Persist the verbatim RegisterRequest at the server.** Rejected. It would put the enrollment
    token, CSR and attestation at rest as a plain column (ADR-0010 forbids secrets as plain
    columns), and it is opaque to the queries the record will serve. The store keeps the derived
    facts only.
19. **Reattach by asking the agent to re-register** (always, not only as a fallback), through
    `__resync__` or a forced disconnect.
    - `__resync__` cannot reach an agent whose session is not yet installed (D14).
    - A forced disconnect of 100k agents after every server restart costs 100k TLS handshakes and
      full enrollment paths, where a primary-key read suffices. It would also spend ADR-0074 D14's
      reconnect budget on every server restart.
    - Kept only as the `NO_RECORD` fallback.

## Consequences

### Upgrade (breaking)

`docs/user-manual/upgrading.md` gains: "⚠️ Breaking: the heartbeat carries status-tag changes and a
topology digest; fleet topology moved to its own RPC; upgrade server, gateways and agents together".
It should say:
- the order: server, then gateways, then agents, in one maintenance window;
- un-upgraded agents keep connecting and executing commands, but contribute **no** status tags and no
  topology until upgraded (absent from fleet gauges, DEX performance, `/network`, Spark and Guardian
  health, and `/viz`). Operators see their heartbeats counted `absent` on
  `yuzu_server_heartbeat_tags_total`; they are sent no `__resync__` and do not move the divergence
  alert;
- after a server restart, state-derived gauges converge in about two minutes per 100,000 agents on a
  replica, after those agents reattach, and topology over several minutes;
- the new flags: `--topology-interval`, `--no-topology`, `--tag-resync-rate`,
  `--topology-resync-rate`, `--reattach-rate`;
- `yuzu.uptime_s` is replaced by `yuzu.started_at`;
- the gateway management RPCs `ListAgents`, `GetAgent` and `QueryInventory` stay in the proto,
  deprecated, but the gateway answers them `UNIMPLEMENTED`; use the server's REST or MCP agent views;
- a gateway from before this release cannot reattach to the new server (no `ProxyReattach`), and
  the new gateway cannot replay to an old server.

The *Version Compatibility* table's row states minimum agent and gateway versions equal to this
release. Changelog: one fragment, `changelog.d/<PR#>-liveness-heartbeat.changed.md`, with the bold
lead "**Breaking: liveness-only heartbeat**". It names the deprecated, no-longer-populated fields,
the new RPCs, the tag-delta semantics and the upgrade-together requirement. `CHANGELOG.md` is not
edited.

### Gateway memory

Idle connections stop receiving:
- a 50-800 KB body every 30 s;
- a ~97-tag map every 30 s.

A quiet host sends six interval tags, a digest and about 70 bytes of topology digest each beat, one
body per 12-18 min, and changes.

Expectation, to be measured rather than claimed:
- the binary term falls as in the no-snapshot runs (TLS 475 to about 38 KiB);
- the tag-decode heap term (about 310 KiB TLS) shrinks in proportion to bytes decoded per beat;
- the per-session buffer entry shrinks (it holds an opaque binary, not a decoded tag map);
- **live state falls by the retained Register (D14).** In the ledger that is about 87 KB per agent
  of 131.8 KiB (the two registration rows, `agent_info`, and the plugin-name lists). The plugin-count
  dependence goes with it.

**No per-agent gateway state is added, and about two thirds of today's per-agent live state is
removed.** The gateway decodes fewer fields per heartbeat than today.

**This alone does not meet ADR-0074 D14's 64 KiB check.** With the Register gone, the ledger's
remaining live state is about 45 KiB of BEAM terms:
- OTP ssl, about 19 KiB;
- the Cowboy connection, about 9 KiB;
- the relay, the inet port and buffer, and the index rows.

The check is all-in, so the kernel's per-connection memory and allocator slack count on top of that.
Closing the rest is ADR-0074's work: its memory measures and kTLS at the agent edge (its D8). This
ADR is a precondition for that work, because without it the payload terms dominate any measurement.

**Bandwidth.** At 10k agents and 150 KB bodies, topology falls from about 50 MB/s to about 1.7 MB/s
plus churn. Tags fall from about 4 KB to a few hundred bytes per beat.

### Server stores

**`AgentHealthStore`** (`server/core/src/agent_registry.{hpp,cpp}`):
- `apply()` with interval and state maps and per-agent sync state;
- `perf_snapshot` and `net_snapshot` read the interval map;
- `recompute_metrics` reads both;
- the per-heartbeat hooks (corruption sink, Guardian reconcile) run on the merged view after
  `apply` (D3);
- the 90 s prune is unchanged.

**`FleetTopologyStore`** (`server/core/src/fleet_topology_store.{hpp,cpp}`):
- the D6 slot fields;
- `push_snapshot(raw, digest, reason)`;
- `confirm()`;
- `mark_disconnected` replaces `evict_pushed`;
- `stale_reason`;
- age rebasing;
- the `Fetcher` seam is removed;
- the `kPushedMapHardCap` victim order: retained `disconnected` slots first, then the oldest
  `confirmed_at` (D6);
- the no-slot entries (D6).

Both stores stay in-memory and per-replica. That rests on one precondition, stated so it is not
assumed.

**All heartbeats of one agent session reach one server replica for the life of a gateway upstream
connection** (connection-level affinity). Today a gateway has one upstream (`upstream_addr` in
`gateway/config/sys.config`) over one HTTP/2 connection, so the precondition holds when that
connection terminates on one replica. ADR-0074 lists several upstream servers per gateway as open
work (#5647 to #5651); this precondition binds that work.
- **Per-RPC balancing of `GatewayUpstream` is unsupported.** A load balancer that spreads one
  connection's RPCs across replicas leaves each replica a partial delta base, and most agents are
  `diverged` or `no_base` on most heartbeats, resyncing without end.
- **An upstream reconnect that lands on another replica is a replica change.** It costs one tag
  resync per agent the gateway holds, and one topology resync per agent with no slot there, at the
  rates in D8.
- **Runbook symptom.** A `diverged` plus `no_base` share near 100 % of heartbeats, sustained, while
  the gateway's coalescing rate is near zero, means per-RPC balancing in front of the server. The
  divergence alert's runbook (D13) names it.

Under the precondition, HA is no worse than today: a replica that lacks a base or a body asks for
it, rate-limited. It is not cleaner: a replica change costs a resync wave. A shared or
per-session-sticky delta base, which per-RPC balancing would need, is not decided here (open
point 14).

### Consumers

- **DEX performance and `/network`:** unchanged semantics. They read interval tags, which are still
  sent and replaced every beat. `network.md`'s interval-delta and absent-not-zero statements stay
  true.
- **After a gateway upstream outage:** after an outage under 90 s, agents whose state tags changed
  during it diverge once (keep-newest coalescing); after a longer one, every agent is `no_base`
  once. Both are resynced at the configured rate (D4).
- **Guardian:**
  - generation reconcile still fires every heartbeat, from the merged view;
  - its `yuzu.guardian_*` fleet gauges are unchanged once synced;
  - a diverged agent shows its last verified values until its full set lands: normally within two
    heartbeats plus any rate-limit wait (D3, D8). An agent rejected three times in a row shows none
    (D3).
- **Spark:** the ABSENT posture travels as explicit removals.
- **Fleet gauges:** unchanged values in steady state. After a server restart they are briefly absent
  for `no_base` agents (D13).
- **Viz:**
  - a non-stale host's topology is at most one pump interval plus 10 s behind, plus the 60 s render
    cache;
  - `stale` is true exactly when `stale_reason` is not null (D6);
  - a machine's `ts` keeps its meaning, the time the agent built the body, and stops being a
    freshness signal: a quiet host's `ts` can be up to 18 min old while it is fresh. Freshness is
    `stale` and `stale_reason`. An `offline` placeholder keeps `ts = 0`;
  - **`fresh`.** REST `?fresh=1` and MCP `fresh=true` drop the 60 s render cache and rebuild from
    the slots the store already holds. With the dispatch fetcher removed (D10) they never contact
    an agent. The `viz.fleet_topology.invalidate` audit verb keeps its name and now records only
    that rebuild. The MCP parameter's description changes from "Force a live re-fetch" to "Rebuild
    from the latest reported bodies, bypassing the shared 60 s render cache", and the REST and
    OpenAPI descriptions and the audit-log row change with it.
- **MCP tools:** `get_fleet_topology` and `get_host_topology` gain `stale_reason` in their typed
  output schema (A5), with updated descriptions. It is declared as a closed JSON-schema `enum` of
  the eight D6 values plus `null`, in both MCP output schemas and in the OpenAPI schemas of both REST
  twins, `/api/v1/viz/fleet/topology` and `/api/v1/viz/host/{id}/topology`. A new value is a schema
  change, never a free string.
- **`get_host_topology` and its REST twin** slice one machine from the same snapshot, so they carry
  the same `stale` and `stale_reason`. A connected agent with no slot (`not_reported`,
  `awaiting_report`, `report_rejected`) and a retained `disconnected` slot are found. Not-found
  (MCP `kInvalidParams` "host not found", REST 404) means the agent has neither a slot nor a
  connected session on this replica. The host call does not merge the durable offline roster,
  unchanged from today, so an `offline` host is not-found there.

### Security

- **Enrollment tokens are no longer retained by the gateway.** Today each connected agent's token
  is held twice in ETS for the whole session, only for replay, and once more in the pending row
  until Subscribe. A token still transits the gateway while a Register is decoded and forwarded;
  the accurate claim is "not retained", not "never in gateway memory".
- **Reattach is a new gateway-upstream RPC.** It gets a peer-guard override, an `rpc` label and a
  test row.
- **Its authority is unchanged and cannot enrol** (D14). It rests on the gateway's peer
  authorization and the same enrolled-status read as the ProxyRegister fast path; the shared adopt
  CAS fences supersession but proves no session possession. Reattach cannot carry ADR-0074 D5's
  per-session agent signature as designed (D14; open point 13).
- **`AgentRegistrationStore` holds no secret** (ADR-0010).
- **Heartbeat state content and the topology body are unsigned** under ADR-0074 D5's decided
  scope. D16 states what a compromised gateway can do with that; it is not covered by ADR-0074's
  liveness-only acceptance (open point 12).
- **Quarantine containment is unchanged:**
  - a reattach installs a session exactly as a replay-adopt does, so the heartbeat-driven
    reconnect reconciler (#3425) applies;
  - no quarantine-store read is added to the reattach path, matching the rule for `Register`.

### Privacy

The process user and redacted cmdline cross the gateway on change and roughly every 15 min, instead
of every ~30 s. The content is unchanged.

### Tests

**Shared function:**
- the `status_tag_digest` canonical form, including empty-set and ordering cases;
- the class table's completeness: every key the agent core can emit is listed.

**Agent:**
- delta computation, including removals, base-only-on-ack, and full-on-Register and full-on-resync;
- the tag caps applied before the diff and the digest: an oversize or invalid-UTF-8 key is dropped
  and counted, the digest covers only what is sent, and a capped set passes the server's checks;
- the `__resync__` decision function, dedup claim, and terminal recorded before the write; the
  handler only arms and wakes (SUCCESS means armed), and answers FAILURE with no topology sender or
  an unknown action;
- after `__resync__.tags`, every heartbeat is full until two full heartbeats are acknowledged, and a
  coalesced first full heartbeat does not end the repetition;
- the topology send rules, with an injected RNG for jitter bounds, never timing;
- the pump record is published and read whole: a reader racing a publish sees one run's body,
  digest, `last_pump_at` and outcome, never a mix.

**Server:**
- `ReportTopology`, `ProxyTopology` and `ProxyReattach` each refuse an on-behalf-of request before
  any side effect (`onbehalf::enforce` first); direct `ReportTopology` refuses a revoked peer
  (`reject_revoked_peer`, label `report_topology`);
- `ProxyReattach`: adopt via the shared decision (one function, called by both RPCs); every refusal;
  fail-closed on a degraded record read; never installs from partial facts; the rate limit;
  a record written by a different session (a failed upsert, a cross-replica race, a restored
  backup) answers `NO_RECORD`; a body and metadata session-id mismatch answers `MALFORMED_SESSION`;
  a stored `service` scopable tag is dropped on install; a stored `tar` plugin sets
  `legacy_echo_wire_name` as at registration;
  a refusal before the adopt step leaves the route directory untouched; a successful reattach
  fires no `agent.registered` event; each outcome moves `yuzu_server_agent_reattach_total`, and
  the three caller-attributable refusals write an `agent.reattach` audit row;
- `AgentRegistrationStore` under the ADR-0012 test conventions (`YUZU_REQUIRE_PG_DB`): upsert, plugin
  interning, the decommission cascade (including the `kCascadeStoreCount` bump), DB-authored
  timestamps;
- the `apply` outcomes (synced, full, diverged, no_base, rejected, absent, unverifiable), and the
  moved tag caps; a wrong-class key and a key in both `upsert` and `removed` are rejected; a
  rejected or absent heartbeat clears the interval map; a full set that fails its own digest is
  rejected; a delta whose `base_digest` differs is diverged unless its `state_digest` already
  matches (duplicate, synced); an empty delta is synced without a hash; three consecutive rejections
  withhold the state map; the per-agent backoff after `rejected`;
- the `v1` golden vectors, read by both the agent and server suites;
- the Register-side consumer: Register and ProxyRegister apply `status_tags_pb` as a full payload,
  and a rejected one leaves the agent `no_base` without failing the registration;
- keep-newest loss producing `diverged` and then `__resync__.tags`;
- the `__resync__-` exec-tracker skip, and fresh ids per issuance;
- a kill-switched `__resync__` counted `send_failed`;
- heartbeat ingestion only marks a resync: no Postgres call and no send on the BatchHeartbeat path;
  the issuer ends a pass at the first failed record write and leaves the rest `deferred`; a mark for
  an agent with no installed session stays `deferred`, never `send_failed`; a `__resync__` reply
  writes no `ResponseStore` row and makes no provenance lookup;
- the catalogue pair's system-only refusal at operator surfaces;
- hooks firing on unchanged-tag heartbeats (generation reconcile, corruption sink);
- interval replace semantics (a missing net tag disappears);
- the D6 confirm, mismatch, grace, `stale_reason`, retain-on-disconnect, re-claim and conflict
  cases;
- on both the direct and the gateway path, a superseded session's late close does not mark the
  current session's slot `disconnected` or release its IP claims;
- `stale_reason` precedence: each pair of simultaneous conditions renders the earlier value; a live
  agent with a late report reads `body_pending`, not `agent_silent`; an offline host past 300 s
  reads `offline` and a `--no-topology` agent `not_reported`; every reporting agent after a restart
  reads `awaiting_report` until its body lands; the schema enum matches the C++ enum;
- a re-claim conflict writes `topology.push.rejected` with `reason=reclaim_conflict` before the slot
  is dropped; re-claim and push share one claim function; a `PARSE`, `DIGEST_MISMATCH`, `OVERSIZE`
  or `UNKNOWN_SESSION` rejection writes no audit row and moves the rejection counter;
- an accepted report sets `confirmed_at` and claims its IPs; the owner-live test reads
  `confirmed_at`, so a quiet, confirmed owner keeps its IPs past 300 s without a new body;
- at the cap, a `disconnected` slot is evicted before any connected one, and a quiet confirmed host
  is never the victim while a less recently confirmed one exists;
- age rebasing touches only rows carrying `last_seen_seconds_ago`; a live row renders age 0 however
  old the body is;
- `fresh` rebuilds from stored slots and dispatches nothing;
- a wall-clock step of an hour in either direction changes no `stale_reason`, no IP claim and no
  retention outcome (an injected `steady_clock` and wall clock that move independently);
- the no-slot grace (a normal start sends one body, no RESYNC), and no resync while a rejected
  report's digest is unchanged;
- `pump_stuck` derived from `pump_interval_s` at 30, 60, 300 and 900 s: a healthy pump at each
  interval never reads `pump_stuck`, a stopped one does after `T`, a `FAILED` outcome held past `T`
  does, a busy pump whose digest changes every run does not, and `pump_interval_s = 0` never
  evaluates the row;
- resync rate limits.

**Gateway eunit:**
- a heartbeat's `status_tags_pb` and `topology` pass through byte-identical;
- keep-newest replaces the whole entry;
- `heartbeat_invalid` still counts an unkeyable session id and an encoder-raise drop, and a
  heartbeat with an arbitrary-byte `TopologyDigest.digest` encodes;
- no gateway code path reads either field (a lexical test, like the existing peer-guard
  registration gate);
- no RegisterRequest is retained (registry row, owner-sessions row, owner state, and the
  `yuzu_gw_pending` row, which holds no `register_req` or `agent_info`). A size test on the
  per-agent rows is part of the harness;
- replay sends `ProxyReattach` with exactly the three fields, and `observed_peer` is the raw
  origin (empty when unobserved), never the `unknown` display substitute;
- every row of D14's outcome table: `NO_RECORD`, `NOT_ENROLLED`, `SUPERSEDED` and
  `MALFORMED_SESSION` close the agent's stream; `DEGRADED` and `RATE_LIMITED` keep it and requeue
  after `retry_after_ms`; each is classified for the breaker as the table says;
- owner restart restores from ids;
- the management service serves only `SendCommand` and `WatchEvents` (the three deprecated RPCs
  answer UNIMPLEMENTED);
- `ProxyTopology` admission, permit pool, cap, no buffering and peer-guard row;
- collect-after-64 KiB;
- the gateway tests that assert `yuzu.uptime_s` are updated.

**Elsewhere:**
- `buf breaking` passes with no exemption (nothing is subtracted; fields 3 and 4 and the three
  management RPCs remain, deprecated);
- a lexical test that no non-generated source reads or writes heartbeat fields 3 or 4 (D3);
- a UAT rig check that a quiet agent stays synced and non-stale for 30 min with one or two bodies
  sent;
- the idle-memory harness rerun with ADR-0074 D14's method (OS anonymous memory plus kernel, after
  settling, TLS on) at 5,000 and 10,000 agents, as the recorded before/after.

### Routed concerns and agents this touches

- **Network quality** (`docs/user-manual/network.md`): `security-guardian` and `docs-writer`. The
  `yuzu.net_*` heartbeat block's wire envelope changes, and its interval semantics and `kNetTag*`
  pins must be shown unchanged.
- **Guardian / Guaranteed State and DEX** (the `__observation__` / `kDexCohortFloor` row):
  `security-guardian` and `docs-writer`, for the `yuzu.guardian_*` and `yuzu.dex_*` / `yuzu.perf_*`
  carriage and the reconcile hook.
- **Spark detection layer:** `security-guardian` and `cpp-safety`, for the Spark fleet-tag emit
  site and its ABSENT posture.
- **Fleet visualization** (`docs/fleet-viz-invariants.md`): `security-guardian` and `docs-writer`.
  The push-ingestion invariants are rewritten. The trust boundary, shared parser, IP-spoof and audit
  invariants are preserved.
- **Gateway-upstream peer authorization:** `security-guardian`, `cpp-safety`, `architect` and
  `docs-writer`, for the `ProxyTopology` and `ProxyReattach` overrides.
- **`common/include/` firewall (#2549):** `architect` and `security-guardian`, for the two new pure
  headers (no I/O; no CLAUDE.md annotation change needed).
- **Durable agent command idempotency** (`docs/command-dedup.md`): `cpp-safety` and `architect`, for
  the new `__resync__` reserved dispatch (dedup-claimed, terminal before write).
- **Executions-history ladder:** the `__resync__-` skip in `notify_exec_tracker`.
- **Dispatch-caller approval provenance / ExecuteGate:** `security-guardian` and `cpp-safety`, for
  the two `system_reserved` rows in `core_dispatch_capabilities.hpp`, and confirmation that the
  new `DispatchCaller{.system = true}` construction adds no `approval_provenance` stamping site.
- **Prometheus metrics and alert rules** (`docs/observability-conventions.md`): `sre` and
  `architect`.
- **TAR** (the `echo` plugin's `echo_fleet_snapshot`, schema minor 2 to 3): `architect`,
  `plugin-developer`.
- **Erlang gateway:** `gateway-erlang`, for the gpb regen, keep-newest opacity, moving the tag
  checks out, replay-as-reattach, the owner-restart path, and the management-RPC retirement.
- **Server storage substrate (Postgres):** `architect` and `sre`, for the born-on-PG
  `AgentRegistrationStore` (ADR-0012 contract, playbook, a migration-ladder row) and the
  decommission cascade.
- **Authentication and enrollment:** `security-guardian`. The `ProxyReattach` enrollment gate must
  stay equivalent to the ProxyRegister fast path, and the token leaves gateway memory.
- **HA WS-4 route adoption** (ADR-2002, `gateway_route_store.hpp` FORWARD NOTE): `security-guardian`
  and `cpp-safety`. The adopt decision is extracted into one function shared by ProxyRegister and
  ProxyReattach.
- **PKI / gateway management plane** (the rows naming `yuzu_gw_mgmt_service.erl`):
  `security-guardian` and `gateway-erlang`, for retiring three RPCs on the `:50063` management
  surface (deprecated, answering `UNIMPLEMENTED`). Its peer check and `SendCommand`/`WatchEvents` are
  unchanged.
- **Device quarantine / containment:** `security-guardian`, to confirm the reattach path adds no
  synchronous quarantine read and keeps the reconnect reconciler semantics.
- **All C++:** `cpp-expert` and `cpp-safety`.
- **Proto and cross-module shape:** `architect`.

### Docs to update in the implementing PRs

- `docs/fleet-viz-invariants.md`: push-ingestion section and the Metrics fetch-histogram bullet,
  including the UP-5 "Eviction on disconnect" bullet, amended: claims are still released on close,
  the slot is retained for 300 s.
- `docs/user-manual/network.md`: the carriage note; the semantics are unchanged.
- `docs/user-manual/gateway.md`: the heartbeat batching text (about l.199-227), including that
  `heartbeat_batch_interval_ms` must stay well below the heartbeat interval (D4); registration replay
  becomes reattach; the live management RPCs are `SendCommand` and `WatchEvents`, the other three
  deprecated and `UNIMPLEMENTED`.
- `docs/user-manual/metrics.md`.
- `docs/observability-conventions.md`: the heartbeat-buffer drop reasons (about l.109), plus the new
  families.
- `docs/user-manual/rest-api.md` and `docs/user-manual/mcp.md`: `stale_reason` and freshness, `ts`
  as the body's build time, `fresh` as a render-cache rebuild that never contacts an agent, and the
  host call's not-found meaning.
- `docs/command-dedup.md`: the dedup tags are carried as state; `__resync__` is a second
  dedup-claimed reserved name alongside `__sync__`.
- `docs/user-manual/upgrading.md`.
- `docs/architecture.md`, `docs/capability-map.md` and `docs/erlang-gateway-blueprint.md`: mark
  `ListAgents`, `GetAgent` and `QueryInventory` deprecated and `UNIMPLEMENTED` on the gateway
  management surface (slice 0b's own PR).
- `docs/postgres-migration-ladder.md`: the `AgentRegistrationStore` row.
- `docs/data-architecture.md` and the server-side PostgreSQL data-inventory table in
  `docs/enterprise-readiness-soc2-first-customer.md`: the `agent_registration_store` schema, its
  fields (hostname, os, arch, version, scopable tags, plugin set; no secret) and its retention
  (until decommission).
- The decommission blast-radius lists: `sle_routes.hpp`/`.cpp`, `rest_api_v1.cpp`'s delete block,
  ADR-0024 Decisions 9 and 11, and `docs/user-manual/rest-api.md` (the cascade header's step (d)).
- `docs/auth-architecture.md`: the gateway no longer holds enrollment tokens; reattach authority.
- `docs/user-manual/audit-log.md`: the `agent.reattach` refusal row; the
  `viz.fleet_topology.invalidate` row, which today says the request forced a cache invalidation
  and now records a rebuild from stored bodies with no agent contacted; `topology.push.rejected`'s
  `reason` detail (`ip_conflict`, `reclaim_conflict`) and the paths that write each topology verb.
- The agent CLI reference.
- The ADR-2002 incident paragraph: a pointer to this ADR.

The same changes fix known truth-drift:
- the proto comment's "5-20 KB" and "once per two heartbeats" (`agent.proto:155-159`);
- `fleet_topology_store.hpp:194` ("invalidates the cache");
- `fleet-viz-invariants.md`'s "whose `ts`" and "5-20 KB struct";
- the `server.cpp` "60 s cache" comment on `claimed_ips()` (about l.19169).

## Implementation slices

Small PRs, in order. Slices 0-2b are wire-compatible and can land early. Slices 3-10 are the breaking
release and merge to `dev` inside one release window. ADR-0074 gates its own waves at 5,000 agents
(its Conflict 7); the measurements in slices 1 and 10 use the same counts.

0. **Gateway: collect after any request of 64 KiB or more** (`yuzu_grpc_stream_h.erl`). Interim and
   independent; measurable on the harness at once.
0b. **Gateway: retire management `ListAgents`, `GetAgent` and `QueryInventory`** (D14, D15). It
    includes the proto deprecation (`option deprecated = true;`, the gateway answering
    `UNIMPLEMENTED`; nothing deleted), the gpb regen, the eunit updates, and the docs
    (`architecture.md`, `capability-map.md`, `erlang-gateway-blueprint.md`, `user-manual/gateway.md`).
    It is independent of every other slice.
1. **Agent jitter and measurement.**
   - Jittered heartbeat and pump sleeps (D9).
   - `yuzu_agent_heartbeat_bytes`, plus a would-be-delta histogram computed locally. That measures the
     tag saving before the wire changes.
   - An audit that no server heartbeat-age threshold sits under 1.2 × 30 s plus margin.
2. **Shared pure headers and TAR digest.**
   - `common/include/yuzu/status_tag_classes.hpp` and `status_tag_digest.hpp`, with completeness
     and canonical-form tests.
   - TAR `content_digest` (`schema_minor` bump) and its classification list.
   - The pump records digest, `last_pump_at` and outcome.
2b. **`AgentRegistrationStore`, written on every successful registration** (direct and gateway).
    It is additive and wire-compatible, so it can land early. Records accumulate before anything
    reads them.
3. **Proto and gpb.**
   - `StatusTags` (carried as `bytes`), `TopologyDigest`, `ReportTopology`, `ProxyTopology` and
     `ProxyReattach`.
   - Mark heartbeat fields 3 and 4 `[deprecated = true]` (not removed, D15), and add Register
     field 8.
   - Regenerate the gateway gpb modules.
   - The minimal compiling removal of every field-3/4 reader and writer.

   The tree is coherent but tags and topology are inert until slices 4-9 land.
4. **Server tags.** `AgentHealthStore::apply`, the D3 ingestion order (including the tag caps moved
   from the gateway), the Register-side consumer, hooks on the merged view, and
   `yuzu_server_heartbeat_tags_total`. An outcome that needs a resync is counted only; slice 6 adds
   the request.
5. **Agent tags.** State and interval maps, the base and delta, full on Register,
   `yuzu.started_at`, `yuzu.uptime_s` removed, agent tag metrics.
6. **`__resync__`, both ends.**
   - Agent: reserved dispatch, decision function, dedup claim.
   - Server: the pending set and the issuer, and its call site in heartbeat ingestion (D3);
     `--tag-resync-rate` and `--topology-resync-rate`, the per-agent intervals and the backoff after
     `rejected`; the resync metrics (`yuzu_server_tag_resync_total`,
     `yuzu_viz_topology_resync_total`, `yuzu_server_resync_pending`); the reply drop at ingest;
     minting, the exec-tracker skip, the catalogue pairs, and the operator-surface refusal.

   Covers both `tags` and `topology`; the `topology` action is inert until slice 8.
7. **Gateway opacity.** Keep-newest whole-heartbeat coalescing; the per-tag checks and the
   tag-strip path removed (`heartbeat_invalid` stays for the remaining drops); pass-through and
   lexical eunit.
7b. **Reattach, both ends.**
    - Server: `ProxyReattach` with the shared adopt function, its rate limit, and the peer-guard
      override.
    - Gateway: replay sends ids; all three Register copies and the plugin-name lists removed; owner
      restart from ids; `NO_RECORD` closes the stream.
    - Agent: reconnect backoff with full jitter.
8. **Server topology.** `ReportTopology`, digest confirm, the D6 slot changes, `stale_reason`,
   retain-on-disconnect, age rebasing, the topology resync trigger, the fetcher removed, server
   topology metrics.
9. **Gateway topology and agent sender.**
   - Gateway: `report_topology/2` with its permit pool and cap, `ProxyTopology`, the peer-guard
     override.
   - Agent: the per-connection sender (D7), pump default 60 s, `--topology-interval` and
     `--no-topology`.
10. **Surfaces and docs.**
    - MCP and REST `stale_reason` and descriptions.
    - Both alert rules (`YuzuHeartbeatTagDivergenceSustained` and `YuzuVizTopologyResyncBacklog`);
      this is the only slice that adds them.
    - Every doc listed above, the upgrading.md section and the changelog fragment.
    - The harness and rig rerun recorded as the measured outcome, using ADR-0074 D14's method.

## Open points for the owner

1. **Typed `TopologyDigest` field instead of a status tag** (D5). Recommended. Under tag deltas, a tag
   would also churn the state digest on every pump.
2. **Retain-on-disconnect for 300 s** replaces evict-on-disconnect (D6). It amends a fleet-viz
   invariant (UP-5). IP claims are still released immediately; a `disconnected` cube lingers up to
   five minutes.
3. **Removing the legacy dispatch fetcher** (D10). Cold start becomes placeholders that fill over
   minutes.
4. **`StatusTags` carried as `bytes`** (D2). Opacity by type. The cost is a nested-serialization
   idiom unusual in this proto set.
5. **The gateway's per-tag checks move to the server** (D3, D4). The gateway protects the server
   only from an oversize heartbeat.
6. **Keep-newest coalescing** (D4). An upstream outage costs one tag resync per agent whose state
   changed during it.
7. **A new `AgentRegistrationStore` rather than widening `OfflineEndpointStore`** (D14). They have
   different write cadences and owners, at the cost of some overlapping columns.
8. **Registration-store write failures are set-and-proceed** (D14). The agent still registers; the
   cost is a later re-registration on reattach.
9. **`observed_peer` stays at the gateway and is sent on reattach.** It is the one registration-time
   fact the server cannot rebuild.
10. **`yuzu.uptime_s` retired for `yuzu.started_at`** (D1).
11. **Pump default 60 s**: changed-host topology lags up to about 82 s instead of about 40 s.
12. **Unsigned state content on the heartbeat, and the unsigned topology body** (D16). ADR-0074 D5
    accepts unsigned heartbeats as liveness only, and excludes heartbeat honesty. It does not
    cover state tags or `ReportTopology`: a compromised gateway can set any state tag the server
    accepts as synced, keep IP claims alive with a forged topology digest, and claim IPs with a
    forged body. The digest check does not bound this. The owner either accepts it, as a new row in
    ADR-0074's accepted-risks table, or requires the agent to sign the `StatusTags` bytes and the
    `TopologyReport` under its D5 key.
13. **How reattach meets ADR-0074 D5's per-session signature** (D14). Reattach is ids-only and has
    no agent step, so it cannot carry the per-session proof as written. Until this is decided, a
    reattached session inherits ADR-0074 Conflict 1's route-claim risk. The owner chooses:
    - (a) after the reattach, the server sends a signed session-start challenge down the existing
      stream. The route is not published, and no command but the challenge is dispatched, until the
      agent's signature verifies. A failure tears the stream down and the agent registers again; or
    - (b) reattach is exempt from the D5 per-session proof, recorded as a new row in ADR-0074's
      accepted-risks table.
14. **Per-RPC balancing of `GatewayUpstream`** (*Server stores*). As written, the per-replica,
    in-memory delta base needs every heartbeat of one agent session to reach one replica for the
    life of a gateway upstream connection, and per-RPC balancing is unsupported. Supporting it needs
    either a shared delta base (a fleet-wide store written on every state change) or a
    per-session-sticky route from gateway to replica. The owner decides whether to support it, and
    if so which; until then the precondition stands and is documented for operators.
