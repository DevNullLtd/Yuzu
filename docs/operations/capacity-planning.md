# Capacity Planning

## Server Sizing

| Fleet Size | CPU | RAM | Disk | Notes |
|-----------|-----|-----|------|-------|
| 1-100 agents | 1 core | 1 GB | 1 GB | Development / small office |
| 100-1,000 | 2 cores | 2 GB | 5 GB | Department / single site |
| 1,000-5,000 | 4 cores | 4 GB | 20 GB | Enterprise single-server |
| 5,000-10,000 | 4 cores | 8 GB | 50 GB | Enterprise with gateway |

### Storage Growth

| Data Type | Per-Row Size | Growth Rate (1,000 agents) |
|-----------|-------------|---------------------------|
| Response rows | ~1 KB | ~100 MB/day (100 commands/day/agent) |
| Audit events | ~0.5 KB | ~50 MB/day |
| Policy compliance | ~0.2 KB | ~10 MB/day |
| TAR events (per agent) | ~0.3 KB/event | ~2-3 MB/day/agent |

**Retention impact:** At default retention (90 days responses, 365 days audit), a 1,000-agent fleet needs ~15 GB for responses and ~18 GB for audit data.

### SQLite Performance

- WAL mode is enabled by default for concurrent read/write
- `busy_timeout=5000` prevents lock contention errors
- For >5,000 agents, consider splitting audit and response stores onto separate disks
- Monitor WAL file size: if `*.db-wal` exceeds 100 MB, run a manual checkpoint

## Agent Sizing

| Resource | Typical | With TAR | Notes |
|----------|---------|----------|-------|
| RAM | 30-50 MB | 50-80 MB | Depends on active plugins |
| Disk | 50 MB | 100 MB | Plugins + TAR database |
| CPU | < 1% idle | < 2% idle | Spikes during command execution |
| Network | ~1 KB/30s | ~1 KB/30s | Heartbeat only when idle |

The "Typical"/"With TAR" RAM figures above do not yet include one fixed addition: since #4666 PR-2,
the agent's async log hand-off queue pre-allocates 8193 x 408 bytes = 3,342,744 bytes (~3.34 MB, about
3.19 MiB) of RSS unconditionally at startup, whether or not anything is logged. This is on top of both
figures, on every OS.

TAR disk usage: ~2-3 MB/day with 7-day retention (default). A busy workstation with many processes may use up to 10 MB/day.

## Gateway Sizing

The Erlang/OTP gateway uses one process per connected agent:

| Fleet Size | RAM | CPU | Notes |
|-----------|-----|-----|-------|
| 1,000 agents | 256 MB | 1 core | ~2 KB per agent process |
| 5,000 agents | 512 MB | 2 cores | Heartbeat batching reduces upstream load |
| 10,000 agents | 1 GB | 2 cores | Consider multiple gateways |

The gateway process limit defaults to 262,144 (Erlang default), sufficient for 10,000+ agents.

## Network Bandwidth

| Operation | Size | Frequency | Bandwidth (1,000 agents) |
|-----------|------|-----------|--------------------------|
| Heartbeat | ~1 KB | Every 30s | ~33 KB/s |
| Command request | ~2-5 KB | On demand | Burst |
| Command response | ~1-50 KB | On demand | Burst |
| Metrics scrape | ~5-10 KB | Every 15s | < 1 KB/s |

**Total steady-state for 1,000 agents:** ~40 KB/s (heartbeats only).

## Monitoring Thresholds

| Metric | Warning | Critical | Action |
|--------|---------|----------|--------|
| Disk usage | > 80% | > 90% | Reduce retention, add storage |
| Memory | > 70% | > 85% | Check WAL sizes, reduce max_agents |
| CPU | > 70% sustained | > 90% | Scale vertically or add gateway |
| Heartbeat loss | > 5% of fleet | > 20% | Check network, server capacity |
| Response latency (p99) | > 2s | > 10s | Check disk I/O, SQLite locks |

## Scaling Patterns

1. **Vertical first** — Increase server CPU/RAM. Yuzu is single-server by design (SQLite).
2. **Gateway sharding** — Deploy multiple gateways, each handling a subset of agents (consistent hashing).
3. **Read replicas** — Use Litestream to replicate SQLite to a read-only analytics node.
4. **Retention tuning** — Reduce `--response-retention-days` and `--audit-retention-days` to control disk growth.
5. **External analytics** — Offload response data to ClickHouse via analytics drain, keep SQLite lean.
