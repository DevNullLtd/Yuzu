#!/usr/bin/env bash
# ha-gateway-two-replica-probe.sh - HA WS-13 slice 13.6 (#7082): a two-replica dispatch PROBE.
#
# LAB MEASUREMENT RIG, NOT A DEPLOYMENT PATTERN. A second server replica is NOT supported until the
# HA safe-to-scale gate lifts (docs/ha-delivery-matrix.md). This script measures one thing: with a
# gateway node that is UP but cut off from its servers (the 13.0 spike's F3), can an agent still
# attached to that node be dispatched to through each of two server replicas, including the replica
# that does not hold its session? A pass is evidence for this rig only and removes no known gap.
#
# Rig: the 13.0 spike rig (deploy/docker/docker-compose.ha-gateway-failover.yml) plus the overlay
# deploy/docker/docker-compose.ha-gateway-two-replica.yml = TWO server replicas on one Postgres and one
# CA, three clustered gateways each dialling ONE upstream endpoint (an L4 VIP over both replicas, so a
# gateway has one holder replica), HAProxy, CoreDNS and N real agents, all over real TLS. The images are
# built by the caller from the commit under test (`up --tag`); this script builds nothing.
#
#   ha-gateway-two-replica-probe.sh up --tag <image-tag> [--agents N]
#   ha-gateway-two-replica-probe.sh scenario NOFAULT|F3-2r [--victim gateway-N] [--sample K]
#                                    [--window SECS] [--recovery SECS]
#   ha-gateway-two-replica-probe.sh scale N | status | holders | restore | down
#
# F3-2r = the spike's F3 on two replicas: in the victim gateway's network namespace DROP tcp traffic
# to the upstream VIP (HAProxy, :50055) ONLY. The agent edge (:50051) and the management plane (:50063)
# stay up, so a command can still reach the agent and its response can return on the same SendCommand
# stream. Probes (os_info.os_name, read-only) go through BOTH replicas at -30 s (control) and +60,
# +120, +300, +420 s, then every 10 s after the path returns. Faults are injected from a sidecar that
# joins the node's network namespace (no host root needed) and are classified by a packet capture
# taken IN the victim gateway's namespace.
#
# Platform: Linux with Docker only (bash 5, GNU date, network namespaces, cpusets).
# Credentials are per-rig, random and throwaway; they appear in this host's process list while the rig
# runs, which is acceptable for a local measurement rig and for nothing shared or long-lived.
# State (secrets, enrolment token, raw results) lives under $TWOREP_STATE_ROOT
# (default ~/.local/share/yuzu/ws13-7082/<salt>), never in the repo.

set -uo pipefail
export LC_ALL=C
[ "${BASH_VERSINFO[0]}" -ge 5 ] || { echo "needs bash 5 or newer (EPOCHREALTIME)" >&2; exit 2; }

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$HERE/../.." && pwd)"
COMPOSE_BASE="$REPO_ROOT/deploy/docker/docker-compose.ha-gateway-failover.yml"
COMPOSE_OVERLAY="$REPO_ROOT/deploy/docker/docker-compose.ha-gateway-two-replica.yml"
CLIENT="$HERE/ha-two-replica-probe-client.py"
STATE_ROOT="${TWOREP_STATE_ROOT:-$HOME/.local/share/yuzu/ws13-7082}"
PROJECT="yuzu-ha-gw-2r"
NETFAULT_IMAGE="yuzu-spike-netfault:1"
HAPROXY_IP="10.77.12.20"
GATEWAYS=(gateway-1 gateway-2 gateway-3)

FAILS=0
say()  { printf '\033[1;34m==>\033[0m %s\n' "$*"; }
ok()   { printf '\033[1;32m  ok\033[0m %s\n' "$*"; }
note() { printf '      %s\n' "$*"; }
fail() { printf '\033[1;31mFAIL\033[0m %s\n' "$*"; FAILS=$((FAILS + 1)); }
die()  { printf '\033[1;31mdie\033[0m %s\n' "$*" >&2; exit 2; }
# Milliseconds from bash's own clock (not `date +%s%3N`: see ha-gateway-failover-spike.sh for why).
ms()   { local t=${EPOCHREALTIME/[.,]/}; echo $(( t / 1000 )); }

# ---- state / compose plumbing ------------------------------------------------
STATE=""
load_state() {
    STATE="${TWOREP_STATE_DIR:-$STATE_ROOT/current}"
    [ -f "$STATE/env" ] || die "no rig state at $STATE (run 'up' first)"
    # shellcheck disable=SC1091
    set -a; . "$STATE/env"; set +a
    # The REST ports are published on random host ports that change when a container is recreated, so
    # never trust a stored value; an empty lookup makes every curl fail rather than reach another listener.
    local p
    p="$(compose port server 8443 2>/dev/null | sed 's/.*://')";   URL1=""; [ -n "$p" ] && URL1="https://127.0.0.1:$p"
    p="$(compose port server-2 8443 2>/dev/null | sed 's/.*://')"; URL2=""; [ -n "$p" ] && URL2="https://127.0.0.1:$p"
}
need_rest() { [ -n "${URL1:-}" ] && [ -n "${URL2:-}" ] || die "a replica's REST port is not published right now (is the rig up?); refusing to send a login anywhere"; }
compose() { docker compose -p "$PROJECT" --env-file "$STATE/env" -f "$COMPOSE_BASE" -f "$COMPOSE_OVERLAY" "$@"; }
cname()   { printf '%s-%s-1' "$PROJECT" "$1"; }
setenv()  { # setenv KEY VALUE : upsert into the state env file (atomic; any failure aborts, nothing is truncated)
    local tmp="$STATE/env.tmp.$$" rc=0
    if [ -f "$STATE/env" ]; then
        grep -v "^$1=" "$STATE/env" > "$tmp"; rc=$?
        [ "$rc" -le 1 ] || { rm -f "$tmp"; die "cannot read $STATE/env while updating $1 (grep exit $rc); the file was left unchanged"; }
    else
        : > "$tmp" || die "cannot create $tmp"
    fi
    printf '%s=%s\n' "$1" "$2" >> "$tmp" && chmod 600 "$tmp" && grep -q "^$1=" "$tmp" && mv "$tmp" "$STATE/env" \
        || { rm -f "$tmp"; die "cannot update $STATE/env ($1); the file was left unchanged"; }
}
psql_q() { # psql_q SQL : tuples-only, comma separated
    docker exec -e PGPASSWORD="$YUZU_DB_PASSWORD" "$(cname postgres)" \
        psql -h 127.0.0.1 -U yuzu -d yuzu -tA -F, -c "$1" 2>/dev/null
}
gw_http() { docker exec "$(cname "$1")" wget -qO- -T 2 "$2" 2>/dev/null; }
netfault() { docker run --rm --net "container:$1" --cap-add NET_ADMIN "$NETFAULT_IMAGE" -ec "$2"; }
flush_faults() { # remove every injected iptables rule on all three gateways; non-zero if any node could not be flushed
    local g rc=0
    for g in "${GATEWAYS[@]}"; do
        netfault "$(cname "$g")" 'iptables -F INPUT; iptables -F OUTPUT' >/dev/null 2>&1 || { fail "could not flush the fault rules on $g"; rc=1; }
    done
    return $rc
}
wait_for() { # wait_for DESC TIMEOUT cmd...
    local desc="$1" t="$2"; shift 2; local s; s=$(date +%s)
    until "$@" >/dev/null 2>&1; do
        [ $(( $(date +%s) - s )) -ge "$t" ] && { fail "timed out waiting for $desc (${t}s)"; return 1; }
        sleep 1
    done
    note "$desc ready in $(( $(date +%s) - s ))s"
}
connected_count() { psql_q "SELECT count(*) FROM gateway_route_store.agent_routes WHERE session_id IS NOT NULL AND lease_until > now()"; }
node_counts()     { psql_q "SELECT coalesce(gateway_node,'-'), count(*) FROM gateway_route_store.agent_routes WHERE session_id IS NOT NULL AND lease_until > now() GROUP BY 1 ORDER BY 1"; }
login() { # login URL COOKIEJAR
    curl -ksf -c "$2" "$1/login" -d "username=admin&password=$SPIKE_ADMIN_PASS" -o /dev/null
}

# ---- up ----------------------------------------------------------------------
cmd_up() {
    local tag="" agents=20
    while [ $# -gt 0 ]; do case "$1" in
        --tag) tag="$2"; shift 2;; --agents) agents="$2"; shift 2;;
        *) die "up: unknown arg $1";; esac; done
    [ -n "$tag" ] || die "up: --tag <image tag> required (images yuzu-spike-{server,gateway,agent}:<tag>)"
    for i in server gateway agent; do docker image inspect "yuzu-spike-$i:$tag" >/dev/null 2>&1 || die "missing image yuzu-spike-$i:$tag"; done
    docker image inspect yuzu-postgres:local >/dev/null 2>&1 || die "missing image yuzu-postgres:local (docker build -f deploy/docker/Dockerfile.postgres)"
    docker image inspect "$NETFAULT_IMAGE" >/dev/null 2>&1 \
        || docker build -q -t "$NETFAULT_IMAGE" -f "$REPO_ROOT/deploy/docker/ha-gateway-failover/Dockerfile.netfault" "$REPO_ROOT/deploy/docker/ha-gateway-failover" >/dev/null \
        || die "cannot build $NETFAULT_IMAGE"
    # The rig's addresses are fixed (10.77.12.0/22) so the DNS zone can be static: refuse if ANY resource of
    # this rig or of the spike rig exists, or any docker network already holds that subnet.
    for p in "$PROJECT" yuzu-ha-gw-spike; do
        if [ -n "$(docker network ls -q -f "name=$p")" ] || [ -n "$(docker ps -aq -f "name=$p")" ] || [ -n "$(docker volume ls -q -f "name=$p")" ]; then
            die "resources of the $p project already exist (a rig is up or was not removed with 'down')"
        fi
    done
    if docker network ls -q | xargs -r docker network inspect --format '{{range .IPAM.Config}}{{.Subnet}} {{end}}' 2>/dev/null | grep -q '10\.77\.12\.'; then
        die "another docker network already uses 10.77.12.0/22"
    fi

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
    # 0644: the servers run as a different uid in their containers; the file holds a throwaway PBKDF2
    # hash for a rig-only admin account.
    chmod 644 "$STATE/yuzu-server.cfg"
    # The gateways' sys.config = the shipped reference with ONE change: the upstream endpoint host is the
    # L4 VIP over both replicas (gw-srv.ha.test), so each gateway has one upstream connection (pool_size 1).
    sed 's|{https, "server", 50055|{https, "gw-srv.ha.test", 50055|' "$REPO_ROOT/deploy/docker/reference-gateway-sys.config" > "$STATE/gateway-sys.config"
    grep -q '"gw-srv.ha.test", 50055' "$STATE/gateway-sys.config" || die "could not point the gateway sys.config at gw-srv.ha.test (the reference file changed shape)"
    chmod 644 "$STATE/gateway-sys.config"
    local ncpu; ncpu="$(nproc)"; [ "$ncpu" -ge 4 ] || die "need at least 4 CPUs (found $ncpu)"
    local infra_cpus="0-$((ncpu / 2 - 1))" agent_cpus="$((ncpu / 2))-$((ncpu - 1))"
    cat > "$STATE/env" <<EOF
SPIKE_PROJECT=$PROJECT
SPIKE_TAG=$tag
SPIKE_MGMT_ADDR=gw-mgmt.ha.test:50063
SPIKE_COREFILE=Corefile.fixed
SPIKE_HAPROXY_CFG=haproxy-two-replica.cfg
SPIKE_GW_SYSCONFIG=$STATE/gateway-sys.config
SPIKE_INFRA_CPUS=$infra_cpus
SPIKE_AGENT_CPUS=$agent_cpus
SPIKE_SERVER_CFG=$STATE/yuzu-server.cfg
SPIKE_ADMIN_PASS=$admin_pass
YUZU_POSTGRES_PASSWORD=$(openssl rand -hex 24)
YUZU_DB_PASSWORD=$(openssl rand -hex 24)
YUZU_GW_COOKIE=$(openssl rand -hex 32)
SPIKE_ENROLL_TOKEN=pending
SPIKE_SERVER_ADDR=gw-vip.ha.test:50051
EOF
    chmod 600 "$STATE/env"; load_state
    say "rig up (tag $tag, two replicas, upstream VIP gw-srv.ha.test:50055) state=$STATE"
    compose up -d postgres coredns || die "compose up postgres failed"
    # server-2 depends_on server healthy, so the first replica migrates the schema alone first
    compose up -d server server-2 ca-export "${GATEWAYS[@]}" haproxy || die "compose up infra failed"
    load_state
    wait_for "server REST" 120 curl -ksf "$URL1/login"
    wait_for "server-2 REST" 120 curl -ksf "$URL2/login"
    for n in "${GATEWAYS[@]}"; do wait_for "$n /readyz" 90 gw_http "$n" http://127.0.0.1:8081/readyz; done
    need_rest
    # The probe client verifies the servers' chain against the rig's own install CA. The curl logins below
    # go to loopback-published ports of a throwaway rig and keep -k, as the 13.0 spike runner does.
    docker cp "$(cname server):/etc/yuzu/certs/default-ca.pem" "$STATE/ca.pem" || die "cannot export the rig CA"
    setenv TWOREP_CA "$STATE/ca.pem"; load_state
    login "$URL1" "$STATE/cookies1" || die "admin login failed on replica 1"
    login "$URL2" "$STATE/cookies2" || die "admin login failed on replica 2"
    local html tok
    html="$(curl -ksf -b "$STATE/cookies1" -X POST "$URL1/api/settings/enrollment-tokens" \
        -H "Origin: $URL1" -d "label=probe&max_uses=100000&ttl_hours=72")" || die "token request failed"
    tok="$(printf '%s' "$html" | grep -oE '[a-f0-9]{64}' | head -1)"; [ -n "$tok" ] || die "no token in response"
    setenv SPIKE_ENROLL_TOKEN "$tok"; load_state
    ramp "$agents"
    say "up complete"; cmd_status
}

ramp() { # ramp N : bring the agent count up in batches of 50
    case "${1:-}" in ''|*[!0-9]*|0) die "ramp: the agent count must be a positive integer (got '${1:-}')";; esac
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
    done
    setenv SPIKE_AGENTS "$k"
}

# HAProxy's view of the upstream VIP: current sessions per replica (srv1 = server, srv2 = server-2)
upstream_sessions() {
    docker run --rm --net "container:$(cname haproxy)" "$NETFAULT_IMAGE" -c \
        "wget -qO- 'http://127.0.0.1:8404/stats;csv'" 2>/dev/null \
        | awk -F, '$1=="srv_upstream" && ($2=="srv1"||$2=="srv2"){print $2"="$5"(status "$18")"}' | tr '\n' ' '
}

cmd_status() {
    load_state
    say "containers"; compose ps --format '{{.Name}} {{.State}}' | sed 's/^/      /'
    say "agents per gateway_node"; node_counts | sed 's/^/      /'
    for n in "${GATEWAYS[@]}"; do
        printf '      %s /readyz=%s agents_current=%s\n' "$n" \
            "$(docker exec "$(cname "$n")" wget -qO- -T 2 -S http://127.0.0.1:8081/readyz 2>&1 | grep -oE 'HTTP/[0-9.]+ [0-9]{3}' | head -1 | cut -d' ' -f2)" \
            "$(gw_http "$n" http://127.0.0.1:9568/metrics | awk '/^yuzu_gw_agents_current/{print $2; exit}')"
    done
    say "upstream VIP sessions per replica: $(upstream_sessions)"
}

cmd_restore() {
    load_state
    flush_faults || return 1
    for n in "${GATEWAYS[@]}"; do wait_for "$n /readyz" 90 gw_http "$n" http://127.0.0.1:8081/readyz; done
    ok "faults undone"; cmd_status
}

cmd_down() {
    load_state
    if compose down -v --remove-orphans; then
        rm -f "$STATE_ROOT/current"; ok "rig removed (state kept in $STATE)"
    else
        fail "compose down failed: the rig may still be running (state kept, 'current' link kept)"
    fi
}

# ---- holders -----------------------------------------------------------------
# holders RUN : which replica holds each agent's session. Two independent methods, both recorded:
#  (1) each replica's own agent listing (GET /api/agents; the manual says it is local-only, and this
#      records whether that holds on THIS rig: if both replicas list every agent, method 1 is void);
#  (2) which replica's own log holds the agent's CURRENT session id (the route directory's session_id) in a
#      `ProxyRegister succeeded` line. The agent id alone is NOT enough: an agent's first enrolment can register
#      it through two gateways within milliseconds (the per-agent certificate is issued, the agent reconnects),
#      leaving a stale session on the replica of the first gateway; settle_fleet restarts the agents so a run
#      starts from one clean registration each. Method 2 is the attribution; method 1 is a cross-check.
# Written to RUN/holders.csv: agent_id,gateway_node,hostname,listed_on_1,listed_on_2,logged_on_1,logged_on_2
holders() {
    local run="$1"
    python3 -I "$CLIENT" holders --run "$run" --url1 "$URL1" --url2 "$URL2" \
        --cookies1 "$STATE/cookies1" --cookies2 "$STATE/cookies2" \
        --routes <(psql_q "SELECT agent_id, coalesce(gateway_node,''), session_id FROM gateway_route_store.agent_routes WHERE session_id IS NOT NULL") \
        --log1 <(docker logs "$(cname server)" 2>&1) --log2 <(docker logs "$(cname server-2)" 2>&1)
}

# ---- sampling ----------------------------------------------------------------
sampler_start() { # routes.jsonl (every column of agent_routes + DB now()), gw.csv, upstream.csv at 1 Hz
    local run="$1"
    ( exec 9>&-
      while :; do
        t=$(ms)
        psql_q "SELECT $t, now(), row_to_json(r) FROM gateway_route_store.agent_routes r ORDER BY agent_id" >> "$run/routes.csv"
        for n in "${GATEWAYS[@]}"; do
            rc="$(timeout 3 docker exec "$(cname "$n")" wget -qO- -T 2 -S http://127.0.0.1:8081/readyz 2>&1 | grep -oE 'HTTP/[0-9.]+ [0-9]{3}' | head -1 | cut -d' ' -f2)"
            ac="$(gw_http "$n" http://127.0.0.1:9568/metrics | awk '/^yuzu_gw_agents_current/{print $2; exit}')"
            echo "$t,$n,${rc:-down},${ac:-na}" >> "$run/gw.csv"
        done
        echo "$t,$(upstream_sessions)" >> "$run/upstream.csv"
        sleep 1
      done ) & echo $! > "$run/sampler.pid"
}
sampler_stop() {
    [ -f "$1/sampler.pid" ] || return 0
    kill "$(cat "$1/sampler.pid")" 2>/dev/null; rm -f "$1/sampler.pid"; wait 2>/dev/null; return 0
}

agent_map() { # container,agent id,session per agent (from the agent log)
    local run="$1"
    for c in $(compose ps -q agent); do
        local name sess
        name="$(docker inspect -f '{{.Name}}' "$c" | tr -d /)"
        sess="$(docker logs "$c" 2>&1 | sed -n 's/.*Registered with server (session=\([^,]*\),.*/\1/p' | tail -1)"
        echo "$name,$c,$sess"
    done > "$run/agent_map.csv"
}

# settle_fleet : undo faults and restart the agents so every scenario starts from the same shape
settle_fleet() {
    local n; n="$(compose ps -q agent | wc -l)"
    say "settling: undo faults, restart $n agents"
    flush_faults || die "settle: could not remove the injected faults; refusing to measure on a faulted rig"
    for g in "${GATEWAYS[@]}"; do wait_for "$g /readyz" 90 gw_http "$g" http://127.0.0.1:8081/readyz; done
    sleep 12
    local ids; ids=($(compose ps -q agent)); local i=0
    while [ "$i" -lt "${#ids[@]}" ]; do
        docker restart -t 5 "${ids[@]:$i:50}" >/dev/null 2>&1; i=$((i + 50)); sleep 3
    done
    local s; s=$(date +%s)
    until [ "$(connected_count)" = "$n" ]; do
        [ $(( $(date +%s) - s )) -ge 300 ] && { fail "settle: only $(connected_count)/$n registered after 300s"; return 1; }
        sleep 2
    done
    sleep 20
    local w=0
    while [ "$w" -lt 300 ] && awk '{exit !($1 > 12)}' /proc/loadavg; do sleep 5; w=$((w + 5)); done
    note "settled: $(node_counts | tr '\n' ' ') (load $(cut -d' ' -f1-3 /proc/loadavg), waited ${w}s for it)"
}

RUN_ACTIVE=""
RUN_FINISHED=0
scenario_cleanup() {
    [ -n "$RUN_ACTIVE" ] && sampler_stop "$RUN_ACTIVE"
    # an interrupted run is marked, so that no later export summarises it as if it had completed
    [ -n "$RUN_ACTIVE" ] && [ "$RUN_FINISHED" -ne 1 ] && [ ! -e "$RUN_ACTIVE/INVALID" ] && echo "interrupted before the run completed" > "$RUN_ACTIVE/INVALID"
    docker rm -f "spike-2r-cap-$$" >/dev/null 2>&1
    # never leave a fault behind
    [ -n "${STATE:-}" ] && flush_faults >/dev/null 2>&1
    return 0
}

# probe RUN LABEL : send one probe round through both replicas to the sample and score it
probe() {
    python3 -I "$CLIENT" probe --run "$1" --label "$2" --t0 "$(cat "$1/fault_ms" 2>/dev/null || echo 0)" \
        --url1 "$URL1" --url2 "$URL2" --cookies1 "$STATE/cookies1" --cookies2 "$STATE/cookies2" \
        --agents "$1/sample.txt" --deadline "${PROBE_DEADLINE:-30}" || fail "probe $2 failed to run"
}

cmd_scenario() {
    local id="${1:-}" window=480 sample=10 recovery=600 victim_c=""; shift || true
    while [ $# -gt 0 ]; do case "$1" in
        --window) window="$2"; shift 2;; --sample) sample="$2"; shift 2;;
        --recovery) recovery="$2"; shift 2;; --victim) victim_c="$2"; shift 2;;
        *) die "scenario: unknown arg $1";; esac; done
    case "$id" in NOFAULT|F3-2r) ;; *) die "usage: scenario NOFAULT|F3-2r [--victim gateway-N] [--sample K] [--window S] [--recovery S]";; esac
    for v in "$window" "$sample" "$recovery"; do
        case "$v" in ''|*[!0-9]*) die "scenario: --window, --sample and --recovery must be non-negative integers (got '$v')";; esac
    done
    [ "$window" -ge 60 ] && [ "$sample" -ge 1 ] || die "scenario: --window must be at least 60 and --sample at least 1"
    if [ -n "$victim_c" ]; then
        case " ${GATEWAYS[*]} " in *" $victim_c "*) ;; *) die "scenario: --victim must be one of: ${GATEWAYS[*]}";; esac
    fi
    trap 'scenario_cleanup' EXIT
    trap 'scenario_cleanup; exit 130' INT TERM
    load_state; need_rest
    login "$URL1" "$STATE/cookies1" && login "$URL2" "$STATE/cookies2" || die "login failed"
    settle_fleet || die "settle failed: the fleet is not fully registered, so the run would not start from the shape it states; refusing to measure"
    login "$URL1" "$STATE/cookies1" && login "$URL2" "$STATE/cookies2" || die "login failed after settle"

    local run="$STATE/run-$id-$(date +%H%M%S)"; mkdir -p "$run"; RUN_ACTIVE="$run"
    local total; total="$(compose ps -q agent | wc -l)"
    say "scenario $id agents=$total window=${window}s sample=$sample -> $run"
    agent_map "$run"

    # victim = the requested gateway, else the one holding the most agents
    local vc="$victim_c" victim_node=""
    if [ -z "$vc" ]; then
        local top; top="$(node_counts | sort -t, -k2 -nr | head -1 | cut -d, -f1)"
        for n in "${GATEWAYS[@]}"; do
            docker exec "$(cname "$n")" sh -c 'ip -4 -o addr show scope global' 2>/dev/null | grep -q "${top#*@}\b" && vc="$n"
        done
    fi
    [ -n "$vc" ] || { fail "cannot determine the victim gateway"; return 1; }
    local vip; vip="$(docker inspect -f '{{(index .NetworkSettings.Networks "'"$PROJECT"'_spike").IPAddress}}' "$(cname "$vc")")"
    victim_node="yuzu_gw@$vip"
    note "victim: $vc ($victim_node); per node: $(node_counts | tr '\n' ' ')"
    note "upstream VIP sessions per replica: $(upstream_sessions)"

    holders "$run" || fail "holder attribution failed"
    # the sample: agents attached to the victim (agent_id and hostname, one per line)
    python3 -I "$CLIENT" sample --run "$run" --victim-node "$victim_node" --k "$sample" --stale 2
    [ -s "$run/sample.txt" ] || { fail "no agents are attached to $victim_node"; return 1; }
    echo "id=$id victim=$vc victim_node=$victim_node total=$total window=$window sample=$(wc -l < "$run/sample.txt") tag=$SPIKE_TAG script_sha=$(git -C "$REPO_ROOT" hash-object "${BASH_SOURCE[0]}" 2>/dev/null | cut -c1-12) client_sha=$(git -C "$REPO_ROOT" hash-object "$CLIENT" 2>/dev/null | cut -c1-12) overlay_sha=$(git -C "$REPO_ROOT" hash-object "$COMPOSE_OVERLAY" 2>/dev/null | cut -c1-12) load=$(cut -d' ' -f1-3 /proc/loadavg) upstream=$(upstream_sessions)" > "$run/meta.txt"

    sampler_start "$run"
    # capture IN the victim gateway's namespace on the upstream VIP port: an agent sees nothing of this fault
    docker run -d --net "container:$(cname "$vc")" --cap-add NET_ADMIN --name "spike-2r-cap-$$" "$NETFAULT_IMAGE" \
        -c "timeout $((window + recovery + 60)) tcpdump -nn -tt -i any -w /tmp/cap.pcap 'tcp and port 50055' >/dev/null 2>&1; tcpdump -nn -tt -r /tmp/cap.pcap 'tcp[tcpflags] & (tcp-rst|tcp-fin) != 0' 2>/dev/null; echo ---COUNTS---; tcpdump -nn -tt -r /tmp/cap.pcap 2>/dev/null | awk '{t=int(\$1/10)*10; if (\$3 == \"Out\") o[t]++; else i[t]++} END {for (k in o) print \"out10s\",k,o[k]; for (k in i) print \"in10s\",k,i[k]}'" >/dev/null 2>&1
    note "control probe in 20 s"; sleep 20
    echo "$(ms)" > "$run/control_ms"
    PROBE_DEADLINE=30 probe "$run" control

    local t0; t0=$(ms); echo "$t0" > "$run/fault_ms"; date -u -d "@$((t0 / 1000))" +%FT%T > "$run/fault_iso"
    local frc=0
    case "$id" in
        NOFAULT) note "no fault injected";;
        F3-2r)   netfault "$(cname "$vc")" "iptables -I OUTPUT -p tcp -d $HAPROXY_IP --dport 50055 -j DROP" || frc=$?;;
    esac
    if [ "$frc" -ne 0 ]; then
        fail "fault $id was NOT injected (exit $frc): this run is INVALID and must not be used"; echo "fault $id exited $frc" > "$run/INVALID"
    else
        note "fault $id injected at $(cat "$run/fault_iso")Z"
    fi
    for at in 60 120 300 420; do
        [ "$at" -lt "$window" ] || continue
        local rel=$(( ($(ms) - t0) / 1000 )); [ "$rel" -lt "$at" ] && sleep $(( at - rel ))
        probe "$run" "+${at}s"
    done
    local rel=$(( ($(ms) - t0) / 1000 )); [ "$rel" -lt "$window" ] && sleep $(( window - rel ))

    if [ "$id" = F3-2r ] && [ "$recovery" -gt 0 ]; then
        say "undoing the fault; recovery probes every 10 s for up to ${recovery}s"
        local u0; u0=$(ms); echo "$u0" > "$run/undo_ms"
        if ! flush_faults; then echo "undo failed" > "$run/INVALID"; fail "fault rules could not be removed"; else
            while [ $(( ($(ms) - u0) / 1000 )) -lt "$recovery" ]; do
                PROBE_DEADLINE=10 probe "$run" "recovery+$(( ($(ms) - u0) / 1000 ))s"
                python3 -I "$CLIENT" recovered --run "$run" >/dev/null 2>&1 && { note "all sampled agents dispatchable through both replicas"; break; }
                sleep 5
            done
        fi
    fi
    sampler_stop "$run"
    # a server-synthesised terminal can arrive up to the 300 s SendCommand deadline after the send: re-read every send now
    python3 -I "$CLIENT" resolve --run "$run" --url1 "$URL1" --url2 "$URL2" --cookies1 "$STATE/cookies1" --cookies2 "$STATE/cookies2"
    docker wait "spike-2r-cap-$$" >/dev/null 2>&1; docker logs "spike-2r-cap-$$" > "$run/cap-victim-50055.txt" 2>&1; docker rm "spike-2r-cap-$$" >/dev/null 2>&1
    local since; since="$(date -u -d "@$((t0 / 1000 - 60))" +%FT%TZ)"
    for c in $(compose ps -q agent); do
        docker logs --timestamps --since "$since" "$c" > "$run/agentlog-$(docker inspect -f '{{.Name}}' "$c" | tr -d /).txt" 2>&1
    done
    for n in "${GATEWAYS[@]}"; do docker logs --since "$since" "$(cname "$n")" > "$run/gwlog-$n.txt" 2>&1; done
    docker logs --since "$since" "$(cname server)"   > "$run/serverlog-1.txt" 2>&1
    docker logs --since "$since" "$(cname server-2)" > "$run/serverlog-2.txt" 2>&1
    python3 -I "$CLIENT" analyse --run "$run"
    RUN_FINISHED=1
}

# One command at a time per rig: a second scenario, a `down` or a `scale` against a rig that is mid-run would
# invalidate it without a trace. The lock is held on fd 9 for the life of the command; the sampler and the other
# background children close it (`exec 9>&-`) so an orphan can never block the next command.
take_lock() {
    mkdir -p "$STATE_ROOT" && chmod 700 "$STATE_ROOT"
    exec 9>"$STATE_ROOT/.rig.lock" || die "cannot open $STATE_ROOT/.rig.lock"
    flock -n 9 || die "another command already holds the rig lock ($STATE_ROOT/.rig.lock)"
}

main() {
    local sub="${1:-}"; shift || true
    case "$sub" in up|scenario|scale|restore|down|holders) take_lock;; esac
    case "$sub" in
        up) cmd_up "$@";;
        scenario) cmd_scenario "$@";;
        scale) load_state; ramp "${1:-}";;
        status) cmd_status;;
        holders) load_state; need_rest; login "$URL1" "$STATE/cookies1"; login "$URL2" "$STATE/cookies2"; mkdir -p "$STATE/holders-$$"; holders "$STATE/holders-$$"; cat "$STATE/holders-$$/holders.csv";;
        restore) cmd_restore;;
        down) cmd_down;;
        *) sed -n '2,/^$/p' "${BASH_SOURCE[0]}" | sed 's/^# \{0,1\}//'; exit 2;;
    esac
    [ "$FAILS" -eq 0 ] || { echo "$FAILS failure(s)" >&2; exit 1; }
}
main "$@"
