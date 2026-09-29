# Troubleshooting Guide

## Agent Won't Connect

**Symptoms:** Agent logs `Failed to register` or `UNAVAILABLE` errors.

| Check | Fix |
|-------|-----|
| Wrong server address | Verify `--server host:port` matches server's `--listen` address |
| TLS mismatch | Ensure agent has `--ca-cert` pointing to the server's CA |
| Enrollment not approved | Check Settings > Pending Agents in the dashboard |
| Firewall | Verify port 50051 is open between agent and server |
| Gateway mode | If using gateway, agent connects to gateway port (50051), not server directly |

```bash
# Test connectivity
nc -zv yuzu-server 50051

# Check agent logs
yuzu-agent --server yuzu-server:50051 --no-tls --log-level debug
```

## Dashboard Returns 502/503

| Check | Fix |
|-------|-----|
| Server not running | `systemctl status yuzu-server` |
| Port conflict | `ss -tlnp | grep 8080` — kill conflicting process |
| HTTPS redirect loop | Use `--no-https-redirect` if HTTPS cert is not set up |
| Draining/shutdown | Check if `/readyz` returns 503 — server may be shutting down |

## All API/Dashboard Requests Return 403 (Probes Stay Healthy)

| Check | Fix |
|-------|-----|
| Proxy/mesh/SSO gateway injecting a reserved on-behalf-of header on every request | grep server logs for `[ADR-1005]` (throttled — 1 warn per 100 rejections) or check `yuzu_onbehalf_rejected_total`; strip the header (`On-Behalf-Of`, `X-On-Behalf-Of`, `X-Yuzu-On-Behalf-Of`, `X-Yuzu-Delegated-Operator`, `X-Yuzu-Delegation-Artifact`) at the proxy |
| Single integration getting 403 with `on-behalf-of assertions are not accepted` | The client sends a reserved header — remove it; delegation via headers is never accepted (ADR-1005, see `docs/auth-architecture.md`) |

Health probes (`/livez`, `/readyz`, `/health`, `/api/health`) are exempt from this rejection, so the pod stays in rotation while all real traffic 403s — a green probe with a 100% 403 rate is this failure's signature.

## Policy Non-Compliance

| Check | Fix |
|-------|-----|
| Stale compliance data | POST `/api/v1/policies/{id}/evaluate` to force re-evaluation |
| CEL expression error | Check policy store logs for parse errors |
| Trigger not firing | Verify trigger type and interval in policy YAML |
| Wrong scope | Test scope expression against target device |

## Guardian Dashboard Compliance Looks Wrong

| Symptom | Explanation / fix |
|-------|-----|
| A Guard shows compliant but the customer says it isn't enforcing | Check the `yuzu_server_guardian_platform_matrix_stale_total{spark_type}` Prometheus counter (render-time only — a `0` doesn't rule this out if nobody has loaded the affected fragment since, see [metrics.md](../user-manual/metrics.md)) and whether that rule's `spark.type` was re-authored (a PUT changing e.g. Service → Registry on the same rule id) — a status row from before the change can survive and render as compliant. Root cause tracked in issue #4263 (not yet fixed); confirm by comparing the rule's `updated_at` against the device's last-reported status timestamp. |
| A Linux agent disappeared from the honesty banner or from a Guard's device list after an upgrade | Expected if that agent's only deployed Guard is a Service Guard that never armed (no system D-Bus — every containerized/compose agent — a disabled build flag, or an invalid unit name): it reports nothing, so it's indistinguishable from an unreported pair and silently drops out rather than showing "not implemented". Not a regression — verify D-Bus/systemd reachability on the endpoint before assuming a bug. |
| The "% compliant" number for a rule jumped after an upgrade, with no configuration change | Expected, one-time, if the fleet has Linux endpoints with deployed Service-type Guards — see the #4252 upgrade note in [server-admin.md](../user-manual/server-admin.md). Part of the jump is the double-count fix (a genuine correction); if the fleet also has Service Guards that never actually arm (row above — no D-Bus, disabled build flag, invalid unit name), part of it can be those pairs moving from "counted as not implemented" to "not counted at all" — also raises the %, but isn't new enforcement. Check the row above's D-Bus/systemd guidance before treating the whole jump as pure correctness. |

## High Memory Usage

| Check | Fix |
|-------|-----|
| SQLite WAL growth | Run `PRAGMA wal_checkpoint(TRUNCATE)` on large .db files |
| Response retention too long | Reduce `--response-retention-days` (default: 90) |
| Too many connected agents | Check `--max-agents` limit, consider gateway for distribution |
| Agent thread pool | Agent thread pool is bounded (4-32 workers, 1000 max queue) |

## Gateway Disconnections

| Check | Fix |
|-------|-----|
| Heartbeat timeout | Increase agent `--heartbeat` interval or server `--session-timeout` |
| Erlang VM crash | Check `/var/log/yuzu/gateway-crash.dump` |
| Upstream unreachable | Verify server `--gateway-upstream` address matches gateway config |
| Process limit | Erlang default process limit is 262144 — sufficient for most fleets |

## Certificate Errors

| Check | Fix |
|-------|-----|
| Expired cert | `openssl x509 -enddate -noout -in server.crt` |
| Wrong CA | Agent's `--ca-cert` must match server's signing CA |
| SAN mismatch | Server cert SAN must include the hostname agents connect to |
| Windows cert store | Verify thumbprint: `certutil -store MY` |
| "Refusing to connect with the SYSTEM trust store" | Agent has TLS on but no CA pinned (#1303 fail-closed). Pass `--ca-cert /etc/yuzu/certs/default-ca.pem`, ensure the install CA exists at that path, add `--tls-system-roots` only if the server cert chains to a public/corporate CA already in the system store, or `--no-tls` for a dev/demo stack. |

## Log Diagnosis

Key log patterns to search for:

```bash
# Authentication failures
grep -i "unauthorized\|auth.*fail\|invalid.*token" /var/log/yuzu/server.log

# gRPC errors
grep -i "UNAVAILABLE\|DEADLINE_EXCEEDED\|PERMISSION_DENIED" /var/log/yuzu/server.log

# SQLite errors
grep -i "sqlite\|database.*locked\|busy" /var/log/yuzu/server.log

# Migration issues
grep -i "MigrationRunner\|migrat" /var/log/yuzu/server.log
```

**Recommended log levels:**
- Production: `info` (default)
- Investigating issues: `debug`
- Deep trace: `trace` (generates high volume)
