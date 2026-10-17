#!/usr/bin/env python3
"""Print a one-screen summary of a gateway scale run.

Reads the run file the gateway scale suite writes at the end of a run
(yuzu_gw_scale-<run>.json: every scenario's result) or one scenario's file
(yuzu_gw_scale-<run>-<n>-<scenario>.json) and prints the headline numbers and
the invariants that did not hold. See docs/testing/gateway-scale-tests.md.

Usage: python3 scripts/test/gateway-scale-report.py <file.json> [...]
"""
import json
import sys


def get(d, *path, default="-"):
    for p in path:
        if not isinstance(d, dict) or p not in d:
            return default
        d = d[p]
    return d


def pcts(stats):
    if not isinstance(stats, dict) or not stats.get("n"):
        return "-"
    return "p50 %s / p95 %s / p99 %s ms (n=%s)" % (stats["p50"], stats["p95"], stats["p99"], stats["n"])


def hwm(r):
    probe = get(r, "gateway", "probe", default=None) or get(r, "gateway", "probe_during_stop", default={})
    boxes = probe.get("mailbox_hwm", {}) if isinstance(probe, dict) else {}
    top = sorted(boxes.items(), key=lambda kv: -kv[1])[:4]
    return ", ".join("%s %s" % kv for kv in top if kv[1] > 0) or "all 0"


def scenario(r):
    s = r["scenario"]
    lines = ["== %s (N=%s)" % (s, r.get("agents"))]
    if s in ("ramp", "storm"):
        lines.append("  registered: first-attempt ok %s, failed %s %s; unregistered at budget %s; all in %s ms"
                     % (get(r, "register", "first_attempt_ok"), get(r, "register", "first_attempt_failed"),
                        get(r, "register", "first_attempt_failure_reasons"),
                        get(r, "register", "unregistered_at_budget"), get(r, "time_to_all_registered_ms")))
        lines.append("  first-attempt latency: %s" % pcts(get(r, "register", "first_attempt_latency_ms")))
        lines.append("  server: peak Register in flight %s; Register calls %s, of which wasted (the agent never got the session) %s, stale (arrived after the agent gave up) %s"
                     % (get(r, "upstream", "register_peak_inflight"), get(r, "upstream", "fresh_register_rpcs"),
                        get(r, "upstream", "wasted_register_rpcs"), get(r, "upstream", "stale_register_rpcs")))
    elif s == "server_crash":
        lines.append("  replay: %s of %s, full replay %s ms after restart, peak in flight %s"
                     % (get(r, "replay", "replayed"), get(r, "replay", "expected"),
                        get(r, "replay", "time_to_full_replay_ms"), get(r, "replay", "peak_inflight")))
        lines.append("  DISCONNECTED raised in the outage: %s, received %s, lost %s"
                     % (get(r, "disconnected_expected"), get(r, "disconnected_received"),
                        get(r, "disconnected_lost")))
    elif s == "gateway_crash":
        lines.append("  re-registered %s in %s ms after the kill (gateway back in %s ms); failures after restart %s %s"
                     % (get(r, "reregistered"), get(r, "time_to_all_reregistered_ms"),
                        get(r, "gateway_restart_ms"), get(r, "register_failures_after_restart"),
                        get(r, "register_failure_reasons_after_restart")))
        lines.append("  latency after restart: %s" % pcts(get(r, "register", "ok_attempt_latency_ms")))
    elif s == "planned_stop":
        lines.append("  stop took %s ms; DISCONNECTED received %s of %s (lost %s)"
                     % (get(r, "stop_ms"), get(r, "disconnected_received"), get(r, "sessions"),
                        get(r, "disconnected_lost")))
    elif s == "fanout":
        lines.append("  answered %s of %s in %s ms; failed %s %s; mgmt connection drops %s; refusals %s"
                     % (get(r, "fanout", "answered"), get(r, "fanout", "targets"),
                        get(r, "fanout", "completion_ms"), get(r, "fanout", "failed"),
                        get(r, "fanout", "failure_reasons"), get(r, "fanout", "connection_drops"),
                        get(r, "fanout", "stream_refusals")))
        lines.append("  per-command latency: %s" % pcts(get(r, "latency_ms")))
    conv = r.get("convergence")
    if conv:
        lines.append("  server view: missing CONNECTED %s, ghost sessions %s" %
                     (conv.get("missing_connected"), conv.get("ghost_sessions")))
    mem = get(r, "gateway", "memory_per_connection_bytes", default=None) or get(r, "setup", "memory_per_connection_bytes")
    sched = get(r, "gateway", "scheduler", "weighted", default=None)
    lines.append("  gateway: memory/connection %s B; mailbox peaks: %s%s"
                 % (mem, hwm(r), "; scheduler (weighted) %.3f" % sched if isinstance(sched, float) else ""))
    bad = [i["name"] for i in r.get("invariants", []) if not i["ok"]]
    lines.append("  invariants violated: %s" % (", ".join(bad) if bad else "none"))
    return "\n".join(lines)


def main(paths):
    for p in paths:
        with open(p, encoding="utf-8") as f:
            data = json.load(f)
        for r in data.get("scenarios", [data]):
            print(scenario(r))
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
