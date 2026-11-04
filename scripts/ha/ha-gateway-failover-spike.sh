#!/usr/bin/env bash
# ha-gateway-failover-spike.sh - HA WS-13 slice 13.0: a real-TLS gateway failover
# MEASUREMENT rig runner (not a pass/fail gate; it records timings and checks the
# spike's stated predictions).
#
# Rig: deploy/docker/docker-compose.ha-gateway-failover.yml = server + Postgres +
# three clustered gateways + HAProxy (L4 VIP) + CoreDNS (static multi-A zone) +
# N real agents, all over real TLS. The images are built by the caller from the
# commit under test (see `up --tag`); this script builds nothing.
#
#   ha-gateway-failover-spike.sh up --tag <image-tag> [--agents N] [--mgmt vip|node1]
#                                    [--dns-order fixed|shuffled]
#   ha-gateway-failover-spike.sh scenario <ID> --mode dns|vip [--window SECS]
#   ha-gateway-failover-spike.sh status | down
#
# Scenarios (ID):
#   NOFAULT  self-validation: no fault, expect zero re-attachments
#   F1       docker kill the node holding the most agents (FIN/RST depends on the stack)
#   F1g      docker stop (graceful: the gateway ends its sessions first)
#   F2       silent partition: DROP agent-edge traffic (:50051) in and out on the node
#   F2p      full silent partition: DROP everything on the node except loopback
#            (F2 only blackholes the agent port, so a VIP health check on :8081 stays green)
#   F3       node up, its path to the server DROPped (agent edge and management plane intact)
#   F3x      node fully isolated from the server (both directions, all ports)
#   F5       (after a fault) undo it: restart the node / flush the rules; per-node counts
#
# Faults are injected from a sidecar that joins the node's network namespace
# (docker run --net container:<node> --cap-add NET_ADMIN), so no host root is needed.
# Every fault is classified by a packet capture on three agents attached to the
# victim (FIN/RST seen, or silence), because `docker kill` is not guaranteed to
# produce the same wire behaviour as a real node loss.
#
# State (secrets, enrolment token, results) lives under $SPIKE_STATE_ROOT
# (default ~/.local/share/yuzu/ws13-spike/<salt>), never in the repo. Timings are
# single-host numbers and are labelled so in the summaries.

set -uo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$HERE/../.." && pwd)"
COMPOSE_FILE="$REPO_ROOT/deploy/docker/docker-compose.ha-gateway-failover.yml"
STATE_ROOT="${SPIKE_STATE_ROOT:-$HOME/.local/share/yuzu/ws13-spike}"
NETFAULT_IMAGE="yuzu-spike-netfault:1"

FAILS=0
say()  { printf '\033[1;34m==>\033[0m %s\n' "$*"; }
ok()   { printf '\033[1;32m  ok\033[0m %s\n' "$*"; }
note() { printf '      %s\n' "$*"; }
fail() { printf '\033[1;31mFAIL\033[0m %s\n' "$*"; FAILS=$((FAILS + 1)); }
die()  { printf '\033[1;31mdie\033[0m %s\n' "$*" >&2; exit 2; }
ms()   { date +%s%3N; }

# ---- state / compose plumbing ------------------------------------------------
STATE=""
load_state() {
    STATE="${SPIKE_STATE_DIR:-$STATE_ROOT/current}"
    [ -f "$STATE/env" ] || die "no rig state at $STATE (run 'up' first)"
    # shellcheck disable=SC1091
    set -a; . "$STATE/env"; set +a
    # The REST port is published on a random host port that changes when the server
    # container is recreated or restarted, so never trust the stored value.
    local p; p="$(docker compose -p "$SPIKE_PROJECT" --env-file "$STATE/env" -f "$COMPOSE_FILE" port server 8443 2>/dev/null | sed 's/.*://')"
    [ -n "$p" ] && SPIKE_SERVER_URL="https://127.0.0.1:$p"
}
compose() { docker compose -p "$SPIKE_PROJECT" --env-file "$STATE/env" -f "$COMPOSE_FILE" "$@"; }
cname()   { printf '%s-%s-1' "$SPIKE_PROJECT" "$1"; }
setenv()  { # setenv KEY VALUE : upsert into the state env file
    grep -v "^$1=" "$STATE/env" > "$STATE/env.tmp" 2>/dev/null || true
    printf '%s=%s\n' "$1" "$2" >> "$STATE/env.tmp"; mv "$STATE/env.tmp" "$STATE/env"; chmod 600 "$STATE/env"
}
psql_q() { # psql_q SQL : tuples-only, comma separated
    docker exec -e PGPASSWORD="$YUZU_DB_PASSWORD" "$(cname postgres)" \
        psql -h 127.0.0.1 -U yuzu -d yuzu -tA -F, -c "$1" 2>/dev/null
}
gw_http() { # gw_http NODE URL : body on stdout, empty on failure
    docker exec "$(cname "$1")" wget -qO- -T 2 "$2" 2>/dev/null
}
netfault() { # netfault CONTAINER 'shell command'
    docker run --rm --net "container:$1" --cap-add NET_ADMIN "$NETFAULT_IMAGE" -c "$2"
}
wait_for() { # wait_for DESC TIMEOUT cmd... : echoes elapsed seconds
    local desc="$1" t="$2"; shift 2; local s; s=$(date +%s)
    until "$@" >/dev/null 2>&1; do
        [ $(( $(date +%s) - s )) -ge "$t" ] && { fail "timed out waiting for $desc (${t}s)"; return 1; }
        sleep 1
    done
    note "$desc ready in $(( $(date +%s) - s ))s"
}
connected_count() { psql_q "SELECT count(*) FROM gateway_route_store.agent_routes WHERE session_id IS NOT NULL AND lease_until > now()"; }
node_counts()     { psql_q "SELECT coalesce(gateway_node,'-'), count(*) FROM gateway_route_store.agent_routes WHERE session_id IS NOT NULL AND lease_until > now() GROUP BY 1 ORDER BY 1"; }

# ---- up ----------------------------------------------------------------------
cmd_up() {
    local tag="" agents=20 mgmt=vip order=fixed
    while [ $# -gt 0 ]; do case "$1" in
        --tag) tag="$2"; shift 2;; --agents) agents="$2"; shift 2;;
        --mgmt) mgmt="$2"; shift 2;; --dns-order) order="$2"; shift 2;;
        *) die "up: unknown arg $1";; esac; done
    [ -n "$tag" ] || die "up: --tag <image tag> required (images yuzu-spike-{server,gateway,agent}:<tag>)"
    for i in server gateway agent; do docker image inspect "yuzu-spike-$i:$tag" >/dev/null 2>&1 || die "missing image yuzu-spike-$i:$tag"; done
    docker image inspect "$NETFAULT_IMAGE" >/dev/null 2>&1 \
        || docker build -q -t "$NETFAULT_IMAGE" -f "$REPO_ROOT/deploy/docker/ha-gateway-failover/Dockerfile.netfault" "$REPO_ROOT/deploy/docker/ha-gateway-failover" >/dev/null \
        || die "cannot build $NETFAULT_IMAGE"
    docker network ls --format '{{.Name}}' | grep -q . && \
        [ -z "$(docker network ls -q -f name=yuzu-ha-gw-spike)" ] || die "a yuzu-ha-gw-spike network already exists (a rig is up?)"

    local salt="$$-$RANDOM"; STATE="$STATE_ROOT/$salt"
    mkdir -p "$STATE"; chmod 700 "$STATE"; ln -sfn "$STATE" "$STATE_ROOT/current"
    local admin_pass; admin_pass="$(openssl rand -hex 12)"
    python3 -I - admin "$admin_pass" > "$STATE/yuzu-server.cfg" <<'PY'
import hashlib, os, sys
user, password = sys.argv[1], sys.argv[2]
salt = os.urandom(16)
dk = hashlib.pbkdf2_hmac('sha256', password.encode(), salt, 100000, dklen=32)
print(f"{user}:admin:{salt.hex()}:{dk.hex()}")
PY
    # 0644: the server runs as a different uid in its container; the file holds a
    # throwaway PBKDF2 hash for a rig-only admin account.
    chmod 644 "$STATE/yuzu-server.cfg"
    local mgmt_addr="gw-mgmt.ha.test:50063" corefile="Corefile.fixed"
    [ "$mgmt" = node1 ] && mgmt_addr="gateway-1:50063"
    [ "$order" = shuffled ] && corefile="Corefile.shuffled"
    cat > "$STATE/env" <<EOF
SPIKE_PROJECT=yuzu-ha-gw-spike
SPIKE_TAG=$tag
SPIKE_MGMT_ADDR=$mgmt_addr
SPIKE_COREFILE=$corefile
SPIKE_SERVER_CFG=$STATE/yuzu-server.cfg
SPIKE_ADMIN_PASS=$admin_pass
YUZU_POSTGRES_PASSWORD=$(openssl rand -hex 24)
YUZU_DB_PASSWORD=$(openssl rand -hex 24)
YUZU_GW_COOKIE=$(openssl rand -hex 32)
SPIKE_ENROLL_TOKEN=pending
SPIKE_SERVER_ADDR=gw-dns.ha.test:50051
EOF
    chmod 600 "$STATE/env"; load_state
    say "rig up (tag $tag, mgmt=$mgmt_addr, dns=$corefile) state=$STATE"
    compose up -d postgres coredns || die "compose up postgres failed"
    compose up -d server ca-export gateway-1 gateway-2 gateway-3 haproxy || die "compose up infra failed"
    local port; port="$(compose port server 8443 | sed 's/.*://')"
    setenv SPIKE_SERVER_URL "https://127.0.0.1:$port"; load_state
    wait_for "server REST" 120 curl -ksf "$SPIKE_SERVER_URL/login"
    for n in gateway-1 gateway-2 gateway-3; do
        wait_for "$n /readyz" 90 gw_http "$n" http://127.0.0.1:8081/readyz
    done
    # login + one multi-use enrolment token (never committed; lives in $STATE only)
    curl -ksf -c "$STATE/cookies" "$SPIKE_SERVER_URL/login" -d "username=admin&password=$SPIKE_ADMIN_PASS" -o /dev/null || die "admin login failed"
    local html tok
    html="$(curl -ksf -b "$STATE/cookies" -X POST "$SPIKE_SERVER_URL/api/settings/enrollment-tokens" \
        -H "Origin: $SPIKE_SERVER_URL" -d "label=spike&max_uses=100000&ttl_hours=72")" || die "token request failed"
    tok="$(printf '%s' "$html" | grep -oE '[a-f0-9]{64}' | head -1)"; [ -n "$tok" ] || die "no token in response"
    setenv SPIKE_ENROLL_TOKEN "$tok"; load_state
    ramp "$agents"
    say "up complete"; cmd_status
}

# ramp N : bring the agent count up in batches of 50, recording footprint per step
ramp() {
    local n="$1" k step=20; k="$(compose ps -q agent | wc -l)"; [ "$k" -gt 0 ] && step=50
    while [ "$k" -lt "$n" ]; do
        k=$(( k + step )); [ "$k" -gt "$n" ] && k="$n"; step=50
        say "agents -> $k"
        compose up -d --scale agent="$k" --no-recreate agent >/dev/null 2>&1 || die "scale to $k failed"
        local s; s=$(date +%s)
        until [ "$(connected_count)" = "$k" ]; do
            [ $(( $(date +%s) - s )) -ge 300 ] && { fail "only $(connected_count)/$k agents registered after 300s"; return 1; }
            sleep 2
        done
        note "$k agents registered in $(( $(date +%s) - s ))s; per node: $(node_counts | tr '\n' ' ')"
        footprint "$k"
    done
}
footprint() { # footprint K : RSS/threads/CPU of the agents, appended to $STATE/footprint.tsv
    local first pid; first="$(compose ps -q agent | head -1)"
    pid="$(docker inspect -f '{{.State.Pid}}' "$first" 2>/dev/null)"
    printf '%s\t%s\tthreads_of_first_agent=%s\n' "$(date -u +%FT%TZ)" "$1" "$(ls "/proc/$pid/task" 2>/dev/null | wc -l)" >> "$STATE/footprint.tsv"
    docker stats --no-stream --format '{{.MemUsage}} {{.CPUPerc}}' $(compose ps -q agent | head -5) 2>/dev/null | sed 's/^/      agent sample: /'
}

cmd_status() {
    load_state
    say "containers"; compose ps --format '{{.Name}} {{.State}}' | sed 's/^/      /'
    say "agents per gateway_node"; node_counts | sed 's/^/      /'
    for n in gateway-1 gateway-2 gateway-3; do
        printf '      %s /readyz=%s agents_current=%s\n' "$n" \
            "$(docker exec "$(cname $n)" wget -qO- -T 2 -S http://127.0.0.1:8081/readyz 2>&1 | grep -oE 'HTTP/[0-9.]+ [0-9]{3}' | head -1 | cut -d' ' -f2)" \
            "$(gw_http "$n" http://127.0.0.1:9568/metrics | awk '/^yuzu_gw_agents_current/{print $2; exit}')"
    done
}

# restore : undo every fault (start stopped nodes, flush the iptables rules). F5 is
# `restore` followed by `status`: agents do not rebalance onto the returned node.
cmd_restore() {
    load_state
    for n in gateway-1 gateway-2 gateway-3; do
        docker start "$(cname $n)" >/dev/null 2>&1
        netfault "$(cname $n)" 'iptables -F INPUT; iptables -F OUTPUT' 2>/dev/null
        wait_for "$n /readyz" 90 gw_http "$n" http://127.0.0.1:8081/readyz
    done
    ok "faults undone"; cmd_status
}

cmd_down() { load_state; compose down -v --remove-orphans; rm -f "$STATE_ROOT/current"; ok "rig removed (state kept in $STATE)"; }

# ---- sampling ----------------------------------------------------------------
sampler_start() { # writes routes.csv (state), gw.csv (per node) at 1 Hz
    local run="$1"
    ( while :; do
        t=$(ms)
        psql_q "SELECT $t, agent_id, coalesce(gateway_node,''), connection_epoch, coalesce(session_id,''), coalesce((lease_until > now())::int,0) FROM gateway_route_store.agent_routes ORDER BY agent_id" >> "$run/routes.csv"
        for n in gateway-1 gateway-2 gateway-3; do
            rc="$(timeout 3 docker exec "$(cname $n)" wget -qO- -T 2 -S http://127.0.0.1:8081/readyz 2>&1 | grep -oE 'HTTP/[0-9.]+ [0-9]{3}' | head -1 | cut -d' ' -f2)"
            ac="$(gw_http "$n" http://127.0.0.1:9568/metrics | awk '/^yuzu_gw_agents_current/{print $2; exit}')"
            echo "$t,$n,${rc:-down},${ac:-na}" >> "$run/gw.csv"
        done
        sleep 1
    done ) & echo $! > "$run/sampler.pid"
}
sampler_stop() { [ -f "$1/sampler.pid" ] && kill "$(cat "$1/sampler.pid")" 2>/dev/null; wait 2>/dev/null; }

# agent_map RUN : container -> agent_id, session (from agent logs + routes), one line each
agent_map() {
    local run="$1"
    for c in $(compose ps -q agent); do
        local name sess
        name="$(docker inspect -f '{{.Name}}' "$c" | tr -d /)"
        sess="$(docker logs "$c" 2>&1 | sed -n 's/.*Registered with server (session=\([^,]*\),.*/\1/p' | tail -1)"
        echo "$name,$c,$sess"
    done > "$run/agent_map.csv"
}

dispatch_probe() { # dispatch_probe RUN LABEL AGENT_ID : one os_info command to one agent
    local run="$1" label="$2" aid="$3" body cmd status n
    body="$(curl -ks -m 15 -w '\n%{http_code}' -b "$STATE/cookies" -H "Origin: $SPIKE_SERVER_URL" \
        -X POST -H 'Content-Type: application/json' \
        -d "{\"plugin\":\"os_info\",\"action\":\"os_name\",\"agent_ids\":[\"$aid\"]}" "$SPIKE_SERVER_URL/api/command")"
    status="$(printf '%s' "$body" | tail -1)"
    cmd="$(printf '%s' "$body" | head -n -1 | sed -n 's/.*"command_id" *: *"\([^"]*\)".*/\1/p')"
    sleep 6
    # delivered = a response for this agent with no error_detail and non-empty output
    n="$(curl -ks -m 10 -b "$STATE/cookies" "$SPIKE_SERVER_URL/api/responses/$cmd" | python3 -I -c '
import json, sys
try: r = json.load(sys.stdin).get("responses", [])
except Exception: r = []
ok = [x for x in r if not x.get("error_detail") and x.get("output")]
bad = [x.get("error_detail", "")[:40] for x in r if x.get("error_detail")]
print("delivered=%d error=%s" % (len(ok), bad[0] if bad else "none"))')"
    echo "$(ms),$label,$aid,http=$status,cmd=${cmd:-none},$n" >> "$run/dispatch.csv"
}

# settle_fleet : undo faults and re-spread the agents so every scenario starts from the
# same shape (agents do not rebalance on their own; that is hypothesis H5).
settle_fleet() {
    local n; n="$(compose ps -q agent | wc -l)"
    say "settling: undo faults, restart $n agents"
    for g in gateway-1 gateway-2 gateway-3; do
        docker start "$(cname $g)" >/dev/null 2>&1
        netfault "$(cname $g)" 'iptables -F INPUT; iptables -F OUTPUT' 2>/dev/null
    done
    for g in gateway-1 gateway-2 gateway-3; do wait_for "$g /readyz" 90 gw_http "$g" http://127.0.0.1:8081/readyz; done
    sleep 12   # let HAProxy see the returned node healthy (rise 2 x 3 s)
    # restart in batches of 50; each agent keeps its tmpfs identity across a restart
    local ids; ids=($(compose ps -q agent)); local i=0
    while [ "$i" -lt "${#ids[@]}" ]; do
        docker restart -t 5 "${ids[@]:$i:50}" >/dev/null 2>&1; i=$((i + 50)); sleep 3
    done
    local s; s=$(date +%s)
    until [ "$(connected_count)" = "$n" ]; do
        [ $(( $(date +%s) - s )) -ge 300 ] && { fail "settle: only $(connected_count)/$n registered after 300s"; break; }
        sleep 2
    done
    sleep 20
    # a restart burst leaves the host loaded; timings taken on a busy host are inflated, so
    # wait (bounded) for the 1-minute load average to fall before the baseline starts
    local w=0
    while [ "$w" -lt 300 ] && awk '{exit !($1 > 12)}' /proc/loadavg; do sleep 5; w=$((w + 5)); done
    note "settled: $(node_counts | tr '\n' ' ') (load $(cut -d' ' -f1-3 /proc/loadavg), waited ${w}s for it)"
}

# mgmt vip|node1 : point the server's --gateway-command-addr at the VIP frontend or at
# gateway-1 only (the production-default single address; hypothesis H7), then restart it
cmd_mgmt() {
    load_state
    case "${1:-}" in vip) a="gw-mgmt.ha.test:50063";; node1) a="gateway-1:50063";; *) die "usage: mgmt vip|node1";; esac
    setenv SPIKE_MGMT_ADDR "$a"; load_state
    compose up -d --force-recreate server >/dev/null 2>&1 || die "server recreate failed"
    load_state   # the REST port is published on a fresh random host port after a recreate
    wait_for "server REST" 120 curl -ksf "$SPIKE_SERVER_URL/login"
    curl -ksf -c "$STATE/cookies" "$SPIKE_SERVER_URL/login" -d "username=admin&password=$SPIKE_ADMIN_PASS" -o /dev/null || die "re-login failed"
    sleep 15; ok "management address now $a"
}

# haproxy default|redispatch : swap the VIP's config (redispatch retries a refused connection
# on another node instead of closing the client's connection) and recreate it
cmd_haproxy() {
    load_state
    case "${1:-}" in default) c=haproxy.cfg;; redispatch) c=haproxy-redispatch.cfg;; *) die "usage: haproxy default|redispatch";; esac
    setenv SPIKE_HAPROXY_CFG "$c"; load_state
    compose up -d --force-recreate haproxy >/dev/null 2>&1 || die "haproxy recreate failed"
    sleep 15; ok "haproxy config now $c"
}

# export OUTDIR [redispatch-run,...] [void-run=reason,...] : summarised results (one CSV row per
# run) for the committed record. Raw logs and secrets are NOT exported.
cmd_export() {
    load_state
    local out="${1:?export OUTDIR}"; mkdir -p "$out"
    python3 -I - "$STATE" "$out" "${2:-}" "${3:-}" <<'PY'
import csv, glob, json, os, re, sys
state, out, redisp, void = sys.argv[1:5]
redisp = set(x for x in redisp.split(",") if x)
void = dict(x.split("=", 1) for x in void.split(",") if "=" in x)
cols = ["run", "scenario", "mode", "haproxy", "agents", "victim_agents", "load1_at_fault",
        "lost_p50_s", "lost_max_s", "rereg_p50_s", "rereg_p99_s", "rereg_max_s", "register_peak_per_s",
        "overloaded_log_lines", "first_fin_rst_ms", "readyz_flip_victim_s", "dispatch_delivered",
        "victim_readyz_200_s_after_undo", "all_routable_s_after_undo", "note"]
rows = []
for f in sorted(glob.glob(state + "/run-*/summary.json")):
    d = json.load(open(f)); run = os.path.basename(os.path.dirname(f))
    m = re.match(r"run-(\w+)-(dns|vip)-", run); sc, mode = m.group(1), m.group(2)
    meta = d.get("meta", "")
    def sec(k, q):
        v = d[k].get(q); return "" if v is None else f"{v/1000:.1f}"
    rec = {}
    rp = os.path.join(os.path.dirname(f), "recovery.txt")
    if os.path.exists(rp):
        rec = dict(kv.split("=", 1) for kv in open(rp).read().split() if "=" in kv)
    caps = [c.get("first_fin_rst_ms_after_fault") for c in d.get("fin_rst_capture", {}).values()]
    caps = [c for c in caps if c is not None]
    flips = [v for v in d["readyz_first_non200_s_after_fault"].values() if v is not None]
    vagents = d["agents_that_changed_gateway_node"]
    load = re.search(r"load=([0-9.]+)", meta)
    ov = sum(v.get("overloaded", 0) for v in d.get("log_refusal_counts", {}).values())
    rows.append({
        "run": run, "scenario": sc, "mode": mode,
        "haproxy": ("redispatch" if run in redisp else "default") if mode == "vip" else "",
        "agents": d["agents"], "victim_agents": vagents, "load1_at_fault": load.group(1) if load else "",
        "lost_p50_s": sec("lost_connection_ms_after_fault", "p50"), "lost_max_s": sec("lost_connection_ms_after_fault", "max"),
        "rereg_p50_s": sec("reregistered_ms_after_fault", "p50"), "rereg_p99_s": sec("reregistered_ms_after_fault", "p99"),
        "rereg_max_s": sec("reregistered_ms_after_fault", "max"), "register_peak_per_s": d.get("register_peak_per_s", ""),
        "overloaded_log_lines": ov, "first_fin_rst_ms": min(caps) if caps else "",
        "readyz_flip_victim_s": min(flips) if flips else "",
        "dispatch_delivered": "".join("Y" if "delivered=1" in x else "n" for x in d.get("dispatch", [])),
        "victim_readyz_200_s_after_undo": rec.get("victim_readyz_200_s", ""), "all_routable_s_after_undo": rec.get("all_routable_s", ""),
        "note": void.get(run, ""),
    })
with open(os.path.join(out, "results.csv"), "w", newline="") as fh:
    w = csv.DictWriter(fh, fieldnames=cols); w.writeheader(); w.writerows(rows)
print(f"{len(rows)} runs -> {out}/results.csv")
PY
}

# report : one markdown table over every summary.json under the state dir
cmd_report() {
    load_state
    python3 -I - "$STATE" <<'PY'
import glob, json, os, sys
rows = []
for f in sorted(glob.glob(sys.argv[1] + "/run-*/summary.json")):
    d = json.load(open(f)); rows.append((os.path.basename(os.path.dirname(f)), d))
def g(d, k, q): v = d[k].get(q); return "-" if v is None else f"{v/1000:.1f}"
print("| run | agents | moved | lost p50/max (s) | re-reg p50/p99/max (s) | reg peak/s | readyz flip (s) | dispatch (delivered) |")
print("|---|---|---|---|---|---|---|---|")
for name, d in rows:
    disp = d.get("dispatch", [])
    dd = "".join("Y" if "delivered=1" in x else "n" for x in disp)
    flip = ",".join(f"{k[-1]}:{v}" for k, v in d["readyz_first_non200_s_after_fault"].items() if v is not None) or "-"
    print(f"| {name} | {d['agents']} | {d['agents_that_changed_gateway_node']} | {g(d,'lost_connection_ms_after_fault','p50')}/{g(d,'lost_connection_ms_after_fault','max')} | {g(d,'reregistered_ms_after_fault','p50')}/{g(d,'reregistered_ms_after_fault','p99')}/{g(d,'reregistered_ms_after_fault','max')} | {d.get('register_peak_per_s','-')} | {flip} | {dd} |")
PY
}

# ---- scenarios ---------------------------------------------------------------
cmd_scenario() {
    local id="${1:-}" mode="" window="" force_victim="" settle=1; shift || true
    while [ $# -gt 0 ]; do case "$1" in
        --mode) mode="$2"; shift 2;; --window) window="$2"; shift 2;;
        --victim) force_victim="$2"; shift 2;; --no-settle) settle=0; shift;;
        *) die "scenario: unknown arg $1";; esac; done
    [ -n "$id" ] && [ -n "$mode" ] || die "usage: scenario <ID> --mode dns|vip [--window SECS]"
    load_state
    case "$mode" in dns) addr="gw-dns.ha.test:50051";; vip) addr="gw-vip.ha.test:50051";; *) die "bad mode";; esac
    if [ "$SPIKE_SERVER_ADDR" != "$addr" ]; then
        say "switching agents to $addr (recreate)"
        setenv SPIKE_SERVER_ADDR "$addr"; load_state
        local n; n="$(compose ps -q agent | wc -l)"
        compose up -d --scale agent="$n" --force-recreate agent >/dev/null 2>&1 || die "agent recreate failed"
        local s; s=$(date +%s)
        until [ "$(connected_count)" = "$n" ]; do
            [ $(( $(date +%s) - s )) -ge 300 ] && { fail "only $(connected_count)/$n agents re-registered after 300s"; break; }
            sleep 2
        done
    fi
    [ -n "$window" ] || case "$id" in F3|F3x) window=400;; *) window=150;; esac
    [ "$settle" = 1 ] && settle_fleet

    local run="$STATE/run-$id-$mode-$(date +%H%M%S)"; mkdir -p "$run"
    local total; total="$(compose ps -q agent | wc -l)"
    say "scenario $id mode=$mode agents=$total window=${window}s -> $run"
    agent_map "$run"
    local victim; victim="$(node_counts | sort -t, -k2 -nr | head -1 | cut -d, -f1)"
    if [ -n "$force_victim" ]; then
        local fip; fip="$(docker inspect -f '{{(index .NetworkSettings.Networks "'"$SPIKE_PROJECT"'_spike").IPAddress}}' "$(cname "$force_victim")")"
        victim="yuzu_gw@$fip"
    fi
    [ -n "$victim" ] && [ "$victim" != "-" ] || { fail "no victim node found"; return 1; }
    local vnode="${victim%%.*}"; vnode="${vnode#*@}"
    note "per node before: $(node_counts | tr '\n' ' ') ; victim node name=$victim"
    # the compose container for the victim: match by the node's address (gateway_node is address-only)
    local vc=""
    for n in gateway-1 gateway-2 gateway-3; do
        docker exec "$(cname $n)" sh -c 'ip -4 -o addr show scope global' 2>/dev/null | grep -q "${victim#*@}\b" && vc="$n"
    done
    [ -n "$vc" ] || vc="gateway-1"
    note "victim container: $vc"
    echo "victim=$victim container=$vc total=$total mode=$mode load=$(cut -d' ' -f1-3 /proc/loadavg)" > "$run/meta.txt"

    sampler_start "$run"
    # packet capture on up to three agents attached to the victim (FIN/RST vs silence)
    local vip_ip; vip_ip="$(docker inspect -f '{{(index .NetworkSettings.Networks "'"$SPIKE_PROJECT"'_spike").IPAddress}}' "$(cname $vc)" 2>/dev/null)"
    local caps=() k=0
    while IFS=, read -r aname acid asess; do
        [ -n "$asess" ] || continue
        [ "$(psql_q "SELECT gateway_node FROM gateway_route_store.agent_routes WHERE session_id='$asess'")" = "$victim" ] || continue
        docker run -d --net "container:$acid" --cap-add NET_ADMIN --name "spike-cap-$$-$k" "$NETFAULT_IMAGE" \
            -c "timeout $((window + 30)) tcpdump -nn -tt -i any -w /tmp/cap.pcap 'tcp and (host $vip_ip or host 10.77.12.20)' >/dev/null 2>&1; tcpdump -nn -tt -r /tmp/cap.pcap 'tcp[tcpflags] & (tcp-rst|tcp-fin) != 0' 2>/dev/null" >/dev/null 2>&1 && caps+=("spike-cap-$$-$k")
        k=$((k + 1)); [ "$k" -ge 3 ] && break
    done < "$run/agent_map.csv"
    note "baseline 15s (capturing on ${#caps[@]} agents)"; sleep 15

    local t0; t0=$(ms); echo "$t0" > "$run/fault_ms"; date -u -d "@$((t0 / 1000))" +%FT%T > "$run/fault_iso"
    case "$id" in
        NOFAULT) note "no fault injected";;
        F1)  docker kill "$(cname $vc)" >/dev/null;;
        F1g) docker stop -t 40 "$(cname $vc)" >/dev/null &;;
        F2)  netfault "$(cname $vc)" 'iptables -I INPUT -p tcp --dport 50051 -j DROP; iptables -I OUTPUT -p tcp --sport 50051 -j DROP';;
        F2p) netfault "$(cname $vc)" 'iptables -I INPUT -j DROP; iptables -I OUTPUT -j DROP; iptables -I INPUT -i lo -j ACCEPT; iptables -I OUTPUT -o lo -j ACCEPT';;
        F3)  netfault "$(cname $vc)" 'iptables -I OUTPUT -p tcp -d 10.77.12.4 --dport 50055 -j DROP';;
        F3x) netfault "$(cname $vc)" 'iptables -I OUTPUT -d 10.77.12.4 -j DROP; iptables -I INPUT -s 10.77.12.4 -j DROP';;
        *) sampler_stop "$run"; die "unknown scenario $id";;
    esac
    note "fault $id injected at $(cat "$run/fault_iso")Z"

    # dispatch probes at +10 s, +120 s, +300 s (to three agents: two on the victim, one elsewhere)
    local probed=0
    for at in 10 120 300; do
        [ "$at" -lt "$window" ] || continue
        local now_rel=$(( ($(ms) - t0) / 1000 )); [ "$now_rel" -lt "$at" ] && sleep $(( at - now_rel ))
        local aid
        aid="$(psql_q "SELECT agent_id FROM gateway_route_store.agent_routes WHERE gateway_node='$victim' AND session_id IS NOT NULL LIMIT 1")"
        [ -n "$aid" ] && dispatch_probe "$run" "+${at}s victim-attached" "$aid"
        aid="$(psql_q "SELECT agent_id FROM gateway_route_store.agent_routes WHERE gateway_node<>'$victim' AND session_id IS NOT NULL LIMIT 1")"
        [ -n "$aid" ] && dispatch_probe "$run" "+${at}s other-node" "$aid"
        probed=$((probed + 1))
    done
    local now_rel=$(( ($(ms) - t0) / 1000 )); [ "$now_rel" -lt "$window" ] && sleep $(( window - now_rel ))

    sampler_stop "$run"
    note "per node after: $(node_counts | tr '\n' ' ')"
    for c in "${caps[@]}"; do
        docker wait "$c" >/dev/null 2>&1   # the capture ends window+30 s after it started
        docker logs "$c" > "$run/$c.fin_rst.txt" 2>&1; docker rm "$c" >/dev/null 2>&1
    done
    # collect agent logs since the baseline
    local since; since="$(date -u -d "@$((t0 / 1000 - 15))" +%FT%TZ)"
    for c in $(compose ps -q agent); do
        docker logs --timestamps --since "$since" "$c" > "$run/agentlog-$(docker inspect -f '{{.Name}}' "$c" | tr -d /).txt" 2>&1
    done
    for n in gateway-1 gateway-2 gateway-3; do
        docker logs --since "$since" "$(cname $n)" > "$run/gwlog-$n.txt" 2>&1
    done
    docker logs --since "$since" "$(cname server)" > "$run/serverlog.txt" 2>&1
    agent_map "$run.after" 2>/dev/null; mv "$run.after/agent_map.csv" "$run/agent_map_after.csv" 2>/dev/null; rmdir "$run.after" 2>/dev/null
    analyse "$run" "$id" "$mode"
    case "$id" in
    F2|F2p|F3|F3x)
        # Time the undo: until the victim reports /readyz 200 again, and until every agent is
        # routable again. (Under F3/F3x the agents never moved, so the second is the gateway
        # re-adopting them, not a reconnect.)
        local r0 t_ready t_all; r0=$(date +%s)
        for g in gateway-1 gateway-2 gateway-3; do netfault "$(cname $g)" 'iptables -F INPUT; iptables -F OUTPUT' 2>/dev/null; done
        until [ "$(docker exec "$(cname $vc)" wget -qO- -T 2 -S http://127.0.0.1:8081/readyz 2>&1 | grep -oE 'HTTP/[0-9.]+ [0-9]{3}' | head -1 | cut -d' ' -f2)" = 200 ]; do
            [ $(( $(date +%s) - r0 )) -ge 900 ] && break; sleep 1
        done
        t_ready=$(( $(date +%s) - r0 ))
        until [ "$(connected_count)" = "$total" ]; do
            [ $(( $(date +%s) - r0 )) -ge 900 ] && { fail "recovery: only $(connected_count)/$total routable after 900s"; break; }
            sleep 1
        done
        t_all=$(( $(date +%s) - r0 ))
        echo "victim_readyz_200_s=$t_ready all_routable_s=$t_all routable=$(connected_count)/$total" > "$run/recovery.txt"
        note "RECOVERY after undoing $id: victim /readyz 200 after ${t_ready}s, $(connected_count)/$total routable after ${t_all}s"
        ;;
    esac
}

# ---- analysis ----------------------------------------------------------------
analyse() {
    python3 -I - "$1" "$2" "$3" <<'PY'
import csv, glob, json, os, re, statistics, sys
from datetime import datetime, timezone
run, sid, mode = sys.argv[1:4]
t0 = int(open(f"{run}/fault_ms").read())
def ts(s):  # docker RFC3339Nano -> ms
    s = s.rstrip("Z"); head, _, frac = s.partition(".")
    dt = datetime.strptime(head, "%Y-%m-%dT%H:%M:%S").replace(tzinfo=timezone.utc)
    return int(dt.timestamp() * 1000) + int((frac + "000")[:3])
lost, regd, recon = {}, {}, {}
for f in glob.glob(f"{run}/agentlog-*.txt"):
    name = os.path.basename(f)[9:-4]
    for line in open(f, errors="replace"):
        m = re.match(r"(\S+)\s", line)
        if not m: continue
        try: t = ts(m.group(1))
        except Exception: continue
        if t < t0: continue
        if ("Connection lost" in line or "Subscribe stream ended" in line) and name not in lost: lost[name] = t - t0
        if "Registered with server" in line and name not in regd: regd[name] = t - t0
        if "Reconnecting in" in line: recon.setdefault(name, []).append(t - t0)
agents = [r[0] for r in csv.reader(open(f"{run}/agent_map.csv"))]
def pct(xs, p):
    xs = sorted(xs); return xs[min(len(xs) - 1, int(round(p / 100 * (len(xs) - 1))))] if xs else None
def summ(d):
    v = list(d.values()); return {"n": len(v), "p50": pct(v, 50), "p95": pct(v, 95), "p99": pct(v, 99), "max": max(v) if v else None}
# reversion / movement from the 1 Hz route samples
rows = {}
for r in csv.reader(open(f"{run}/routes.csv")):
    if len(r) < 6: continue
    rows.setdefault(r[1], []).append((int(r[0]), r[2], r[4]))
moved = revert = 0
for a, seq in rows.items():
    nodes = [n for _, n, s in seq if n]
    if len(set(nodes)) > 1: moved += 1
    comp = [n for i, n in enumerate(nodes) if i == 0 or nodes[i - 1] != n]
    if len(comp) >= 3 and comp[0] == comp[2]: revert += 1
import collections
per_s = collections.Counter(v // 1000 for v in regd.values())
refusals = {}
for f in glob.glob(f"{run}/gwlog-*.txt") + [f"{run}/serverlog.txt"]:
    if not os.path.exists(f): continue
    txt = open(f, errors="replace").read().lower()
    refusals[os.path.basename(f)] = {"overloaded": txt.count("overloaded"), "unavailable": txt.count("unavailable"), "refus": txt.count("refus")}
caps = {}
for f in glob.glob(f"{run}/spike-cap-*.fin_rst.txt"):
    txt = open(f, errors="replace").read()
    pk = [l for l in txt.splitlines() if re.search(r"Flags \[[^\]]*[FR][^\]]*\]", l)]
    after = [float(l.split()[0]) * 1000 - t0 for l in pk if re.match(r"\d+\.\d+ ", l) and float(l.split()[0]) * 1000 >= t0]
    caps[os.path.basename(f)] = {"fin_rst_packets": len(pk), "first_fin_rst_ms_after_fault": round(min(after)) if after else None}
gw = {}
for r in csv.reader(open(f"{run}/gw.csv")):
    if len(r) == 4: gw.setdefault(r[1], []).append((int(r[0]) - t0, r[2], r[3]))
readyz_flip = {n: next((t // 1000 for t, rc, _ in v if t >= 0 and rc != "200"), None) for n, v in gw.items()}
out = {
    "scenario": sid, "mode": mode, "agents": len(agents), "meta": open(f"{run}/meta.txt").read().strip(),
    "label": "single host; timings are not production figures",
    "lost_connection_ms_after_fault": summ(lost),
    "reregistered_ms_after_fault": summ(regd),
    "agents_that_never_reregistered_in_window": len(agents) - len(regd),
    "register_peak_per_s": max(per_s.values()) if per_s else 0,
    "register_per_s_histogram": {str(k): v for k, v in sorted(per_s.items())},
    "log_refusal_counts": refusals,
    "agents_that_changed_gateway_node": moved, "agents_that_reverted_to_first_node": revert,
    "fin_rst_capture": caps, "readyz_first_non200_s_after_fault": readyz_flip,
    "dispatch": [l.strip() for l in open(f"{run}/dispatch.csv")] if os.path.exists(f"{run}/dispatch.csv") else [],
}
json.dump(out, open(f"{run}/summary.json", "w"), indent=2)
print(json.dumps(out, indent=2))
PY
    local rc=$?; [ "$rc" -eq 0 ] || fail "analysis failed ($rc)"
    # prediction checks that need no judgement
    if [ "$2" = NOFAULT ]; then
        local moved; moved="$(python3 -I -c "import json,sys;print(json.load(open('$1/summary.json'))['agents_that_changed_gateway_node'])")"
        [ "$moved" = 0 ] && ok "NOFAULT: no agent changed node" || fail "NOFAULT: $moved agents changed node (sampler or rig is not quiet)"
    fi
}

main() {
    local sub="${1:-}"; shift || true
    case "$sub" in
        up) cmd_up "$@";; scenario) cmd_scenario "$@";; status) cmd_status;; restore) cmd_restore;; mgmt) cmd_mgmt "$@";; haproxy) cmd_haproxy "$@";; ramp) load_state; ramp "${1:?ramp N}";; report) cmd_report;; export) cmd_export "$@";; down) cmd_down;;
        *) sed -n '2,/^set -uo/p' "$0" | sed '$d' | sed 's/^# \{0,1\}//'; exit 2;;
    esac
    [ "$FAILS" -eq 0 ] || { echo "$FAILS check(s) failed"; exit 1; }
}
main "$@"
