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
| Gateway container keeps restarting at boot on an Intel host (`docker ps` shows `Restarting (134)`); the log has `sys_sigaltstack(): Internal error: Failed to set alternate signal stack` | The CPU supports AMX (Sapphire Rapids or newer, e.g. AWS c7i/m7i/r7i; `grep -m1 -o amx_tile /proc/cpuinfo` prints `amx_tile`) and the `yuzu-gateway` image is 0.13.0 through 0.14.0-rc4, which run on Alpine 3.24 (#2150). Pull an image that carries the #2150 fix (0.14.0-rc5 or later). Until you can, run the gateway on a host without AMX. A single-node gateway can instead use the `yuzu-gateway-chisel` image of the same version (glibc, unaffected); do not use it for a clustered gateway, because it lacks the entrypoint that resolves the node's cluster address, so the node starts but never joins. In a gateway cluster, a node that is `Down` while the others report the cluster partially formed may be this. Rolling back the gateway to 0.13.x does not help on such a host: it is affected too. |
| Upstream unreachable | Verify server `--gateway-upstream` address matches gateway config. If the server did not start, or calls reach it and are answered with status 16 (`UNAUTHENTICATED`), the cause is gateway peer authorization (pin or acknowledgement), described in the rows below |
| Server exits at boot after `--gateway-upstream` is set, with a `gateway peer authorization` error | The gateway-upstream service requires an authorized gateway peer. On the server's generated default certificates the default gateway certificate is pinned automatically. Otherwise supply `--gateway-peer-pin` or `--gateway-peer-pin-file`; a plaintext (`--no-tls`) rig must pass `--insecure-gateway-peer` (development only), and `--no-tls` alone is refused. If you run no gateway, omit `--gateway-upstream` instead. See [Gateway upstream peer authorization](../user-manual/server-admin.md#gateway-upstream-peer-authorization) |
| Gateway is up and TLS works but upstream calls fail with `UNAUTHENTICATED` (status 16) | The gateway's key is not pinned on the server, or its certificate is expired or lacks `serverAuth`. A pin refusal is not a TLS-handshake failure: the session completes and each call is answered with status 16, so the gateway shows upstream RPC errors (`yuzu_gw_upstream_rpc_errors_total{code="16"}`, the `YuzuGatewayUpstreamAuthRefused` alert if the gateway is scraped), not `yuzu_gw_upstream_tls_handshake_failures_total` (a bring-your-own gateway leaf without `clientAuth` is the exception: it fails the handshake and raises `YuzuGatewayUpstreamTlsHandshakeFailures`, with no server-side signal). On the server `yuzu_server_gateway_peer_denied_total{reason=...}` rises (the critical `YuzuGatewayPeerDeniedBatchHeartbeat` means the gateway's own heartbeat is refused: a total gateway-fronted outage), and `session.gateway_peer_denied` audit rows are written for peers whose certificate parsed. Pin the gateway leaf's key (`--gateway-peer-pin`, `--gateway-peer-pin-file`; explicit pins replace the automatic one) and restart the server. **After the cause is fixed, check convergence before restarting any gateway:** compare `yuzu_gw_agents_current` (gateways) with `yuzu_agents_connected` (servers). Restart gateway nodes **only if agents have not reappeared and the gateway circuit is closed, one node at a time**: the gateway never retries a refused `NotifyStreamStatus` (it logs `Failed to notify stream status for <agent>` and drops it), so a session whose CONNECTED notice was refused can stay without its placement, but a restarted server reports unknown sessions and the gateway replays them. A gateway restart disconnects every agent it holds, and on agents without the #5183 fix (in no release yet) released agents stay wedged: see [Gateway](../user-manual/gateway.md), "What happens when the server restarts". See the incident runbook in [Gateway upstream peer authorization](../user-manual/server-admin.md#gateway-upstream-peer-authorization) |
| `not_pinned` and you cannot tell which side is wrong | Compute the SPKI hash of the certificate the gateway presents (the command under "Pinning your own gateway" in [Gateway upstream peer authorization](../user-manual/server-admin.md#gateway-upstream-peer-authorization)) and compare its first 16 hex characters with the `spki=` in the server's `gateway peer denied: ... reason=not_pinned spki=<16 hex>` line and with the `pin prefixes (first 16 hex)` in the server's boot line `gateway peer authorization: enforcing N pin(s) ...` (read it on every replica). Values the server refuses at boot: the colon-separated `openssl x509 -fingerprint` form, a `SHA256 Fingerprint=`, `SHA2-256(stdin)=` or `sha256:` prefix, 63 or 65 characters. The silent mistake that boots and then fails `not_pinned` is a hash of the whole certificate instead of its public key |
| `outside_validity` on every call although the certificate was renewed | The guard re-checks the certificate on every call, but the gateway keeps its long-lived connection and presents the certificate it had when it dialled; status 16 does not make it redial. Renew **before** `notAfter` and reconnect the gateway (restart the node, one at a time, under the conditional guidance in the row above). A renewal over the same key needs no pin change; a new key needs its pin first |
| Process limit | Erlang default process limit is 262144 — sufficient for most fleets |

### Gateway image build fails at abi-guard

When you build `deploy/docker/Dockerfile.gateway` yourself, a step in the
runtime stage prints `abi-guard: builder Alpine ... runtime Alpine ...` and
fails the build when the two stages cannot safely run the same release:

| Message | Fix |
|---------|-----|
| `runtime Alpine/musl (...) differs from the builder's (...)` | The `erlang:28-alpine` builder and the runtime `alpine:` image are on different Alpine releases. Point the runtime `FROM` at the builder's Alpine release (`docker run --rm <erlang image> cat /etc/alpine-release`). |
| `musl ... with OTP ...: beam.smp aborts at boot on AMX CPUs` | The runtime is on musl 1.2.6 or newer (Alpine 3.24+) with an OTP older than 29.1. Keep both stages on Alpine 3.23, or move the builder to OTP 29.1 or newer. |
| `... is not a plain dotted version` | A version could not be read, for example an OTP release candidate or a patched OTP (`28.5.0.2**`). Build from a released OTP. |
| `could not compare versions (apk printed ...)` | `apk version -t` gave no usable answer for versions that looked valid. Report it with the `abi-guard:` line; do not bypass the step. |

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
