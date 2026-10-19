#!/usr/bin/env bash
# start-viz-uat.sh -- Stand up the feat/viz-engine UAT stack in containers.
#
# Brings up server + gateway + agent in linux/$ARCH containers (arm64 native on
# Apple Silicon, x64 on Linux). Generates yuzu-server.cfg with hashed admin
# password, builds the three images via Dockerfile.server / Dockerfile.gateway
# / Dockerfile.agent (TARGETARCH-driven), starts server + gateway, issues an
# enrollment token via REST, then starts the agent. Verifies registration.
#
# Usage:
#   bash scripts/start-viz-uat.sh                # full bring-up (build if needed)
#   bash scripts/start-viz-uat.sh stop           # docker compose down -v + clean state
#   bash scripts/start-viz-uat.sh status         # ps + recent logs
#   bash scripts/start-viz-uat.sh fleet-snapshot # dispatch tar.fleet_snapshot to the agent
#
# Environment overrides:
#   VIZ_UAT_DIR           default: /tmp/yuzu-viz-uat
#   VIZ_UAT_AGENTS        default: 1     (compose --scale agent=N)
#   VIZ_UAT_AGENT_MODE    default: container
#                           container  : in-container agent (default; thin host;
#                                        scale with VIZ_UAT_AGENTS, opaque
#                                        container-hash hostnames)
#                           cedar-vale-local : three NAMED in-container agents
#                                        (yuzu-frontend / yuzu-app / yuzu-db) via
#                                        the cedar-vale-local compose profile, so
#                                        /viz/fleet labels the three tiers by name
#                                        WITHOUT needing OrbStack VMs. No orb, no
#                                        macOS dependency. Each tier is exactly one
#                                        replica (VIZ_UAT_AGENTS is ignored).
#                           cedar-vale-app : three NAMED tiers running REAL
#                                        services (Envoy -> node -> Postgres),
#                                        each co-hosting an agent, so /viz/fleet
#                                        renders the stack (frontend top / app
#                                        middle / db bottom) with two persistent
#                                        blue tubes. node serves an impress.js
#                                        deck whose slides live in Postgres; the
#                                        deck is at http://localhost:8088.
#                           vm         : skip in-container agent, print enrollment-
#                                        token + host gateway addr for native
#                                        yuzu-agent on OrbStack VM / bare metal
#                           cedar-vale : skip in-container agent; refresh the
#                                        enrollment token on the three Alpine
#                                        OrbStack VMs that model the Cedar & Vale
#                                        three-tier company (yuzu-frontend /
#                                        yuzu-app / yuzu-db) and restart their
#                                        agents so /viz/fleet renders all three
#                                        tiers with real loopback IPC traffic.
#                                        (macOS/orb only — use cedar-vale-local
#                                        on a Linux/WSL2 box.)
#                           none       : skip agent startup entirely
#   VIZ_UAT_CV_VMS        default: "yuzu-frontend yuzu-app yuzu-db"
#                           Space-separated list of OrbStack VMs for cedar-vale
#                           mode. Override for adding tier members or running
#                           against alternate VM names.
#   VIZ_UAT_SKIP_BUILD    default: ""    (set to 1 to skip docker build)
#   VIZ_UAT_PLATFORM      default: linux/$(uname -m mapped)

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
COMPOSE_FILE="$REPO_ROOT/deploy/docker/docker-compose.viz-uat.yml"

VIZ_UAT_DIR=${VIZ_UAT_DIR:-/tmp/yuzu-viz-uat}
VIZ_UAT_AGENTS=${VIZ_UAT_AGENTS:-1}
VIZ_UAT_SKIP_BUILD=${VIZ_UAT_SKIP_BUILD:-}
VIZ_UAT_CV_VMS=${VIZ_UAT_CV_VMS:-"yuzu-frontend yuzu-app yuzu-db"}
# Compose references ${VIZ_UAT_CONFIG:?...} so it must be set for every
# subcommand, not just `start`. The path itself only has to exist for `up`
# (bind mount); `down`/`ps`/`logs` just need the variable defined to pass
# compose's interpolation pass.
export VIZ_UAT_CONFIG="${VIZ_UAT_CONFIG:-$VIZ_UAT_DIR/viz-uat/yuzu-server.cfg}"

ADMIN_USER=admin
ADMIN_PASS=adminpassword1

case "$(uname -m)" in
  arm64|aarch64) DEFAULT_PLATFORM=linux/arm64 ;;
  x86_64|amd64)  DEFAULT_PLATFORM=linux/amd64 ;;
  *) DEFAULT_PLATFORM=linux/$(uname -m) ;;
esac
VIZ_UAT_PLATFORM=${VIZ_UAT_PLATFORM:-$DEFAULT_PLATFORM}

# ── Pretty output ──────────────────────────────────────────────────────────
COLOR_R="\033[31m" COLOR_G="\033[32m" COLOR_Y="\033[33m" COLOR_B="\033[34m" COLOR_0="\033[0m"
ok()    { printf "${COLOR_G}[ok]${COLOR_0} %s\n" "$*"; }
info()  { printf "${COLOR_B}[..]${COLOR_0} %s\n" "$*"; }
warn()  { printf "${COLOR_Y}[!!]${COLOR_0} %s\n" "$*"; }
fail()  { printf "${COLOR_R}[xx]${COLOR_0} %s\n" "$*"; }

# ── Subcommands ────────────────────────────────────────────────────────────

cmd_stop() {
  info "Stopping viz-UAT stack..."
  # YUZU_ENROLLMENT_TOKEN must be set to satisfy compose's `:?` interpolation
  # check, but the value doesn't matter for `down` -- no agent is started.
  # --profile in-container-agent ensures profile-gated services are torn
  # down explicitly rather than relying on --remove-orphans heuristic
  # (gov R8 build-ci SHOULD).
  ( cd "$REPO_ROOT" && YUZU_ENROLLMENT_TOKEN=stub \
      docker compose -f "$COMPOSE_FILE" \
        --profile in-container-agent --profile cedar-vale-local --profile cedar-vale-app \
        down -v --remove-orphans ) || true

  # Stop the Cedar & Vale VM agents (if present) so they don't sit in a
  # reconnect loop against the dead viz-UAT server. The VMs themselves
  # stay running — they're operator-managed via `orb`, not by this
  # script. orb command failures are swallowed: a missing VM is fine.
  # -u root because rc-service needs to write the pidfile and signal the
  # agent process (which runs as root).
  if command -v orb >/dev/null 2>&1; then
    for vm in $VIZ_UAT_CV_VMS; do
      orb -u root -m "$vm" rc-service yuzu-agent stop >/dev/null 2>&1 || true
    done
  fi

  rm -rf "$VIZ_UAT_DIR"
  ok "Stopped + cleaned $VIZ_UAT_DIR"
}

cmd_status() {
  ( cd "$REPO_ROOT" && YUZU_ENROLLMENT_TOKEN=stub \
      docker compose -f "$COMPOSE_FILE" \
        --profile in-container-agent --profile cedar-vale-local --profile cedar-vale-app ps )
  echo ""
  info "Last 20 lines from each service:"
  for svc in server gateway agent agent-frontend agent-app agent-db cv-frontend cv-app cv-db; do
    echo "── $svc ──"
    ( cd "$REPO_ROOT" && YUZU_ENROLLMENT_TOKEN=stub \
        docker compose -f "$COMPOSE_FILE" \
          --profile in-container-agent --profile cedar-vale-local --profile cedar-vale-app \
          logs --tail=20 "$svc" 2>/dev/null ) || true
    echo ""
  done
}

cmd_restart() {
  cmd_stop
  cmd_start
}

cmd_fleet_snapshot() {
  if [ ! -f "$VIZ_UAT_DIR/cookies.txt" ]; then
    fail "$VIZ_UAT_DIR/cookies.txt missing — run start first"
    exit 1
  fi

  # Re-login to refresh the cookie -- the start-time session may have been
  # idle past the inactivity window. Cookie domain is "localhost" (the host
  # name used for login), so all subsequent calls also go via localhost.
  info "Refreshing operator session..."
  curl -fsS -c "$VIZ_UAT_DIR/cookies.txt" \
      "http://localhost:8080/login" \
      -d "username=${ADMIN_USER}&password=${ADMIN_PASS}" -o /dev/null

  info "Looking up registered agents..."
  local agents_json
  agents_json=$(curl -fsS -b "$VIZ_UAT_DIR/cookies.txt" \
      "http://localhost:8080/api/agents" 2>/dev/null)
  local agent_ids_json
  agent_ids_json=$(echo "$agents_json" \
      | python3 -c 'import json,sys; print(json.dumps([a["agent_id"] for a in json.load(sys.stdin)]))')
  local count
  count=$(echo "$agent_ids_json" | python3 -c 'import json,sys; print(len(json.load(sys.stdin)))')
  if [ "$count" -lt 1 ]; then
    fail "No registered agents -- run 'bash scripts/start-viz-uat.sh status' to inspect"
    exit 1
  fi
  ok "Found $count registered agent(s)"

  info "Dispatching crossplatform.tar.fleet_snapshot..."
  local resp
  resp=$(curl -fsS -b "$VIZ_UAT_DIR/cookies.txt" \
      -H "Content-Type: application/json" -H "Origin: http://localhost:8080" \
      -X POST "http://localhost:8080/api/instructions/crossplatform.tar.fleet_snapshot/execute" \
      -d "{\"agent_ids\":$agent_ids_json}" || true)
  local cmd_id
  cmd_id=$(echo "$resp" | python3 -c \
    'import json,sys;j=json.load(sys.stdin);print(j.get("command_id",""))' 2>/dev/null || true)
  if [ -z "$cmd_id" ]; then
    fail "Could not dispatch tar.fleet_snapshot:"
    fail "  $resp"
    exit 1
  fi
  ok "Dispatched: command_id=$cmd_id  (agents_reached=$(echo "$resp" | python3 -c 'import json,sys;print(json.load(sys.stdin).get("agents_reached",0))'))"

  info "Waiting up to 20s for response..."
  local waited=0 response="" body
  while [ "$waited" -lt 20 ]; do
    body=$(curl -fsS -b "$VIZ_UAT_DIR/cookies.txt" \
        "http://localhost:8080/api/responses/$cmd_id" 2>/dev/null || true)
    if echo "$body" | grep -q '"output"'; then
      response=$body
      break
    fi
    sleep 1
    waited=$((waited + 1))
  done

  if [ -z "$response" ]; then
    fail "Timed out waiting for fleet_snapshot response"
    fail "  curl -b $VIZ_UAT_DIR/cookies.txt 'http://localhost:8080/api/responses/$cmd_id'"
    exit 1
  fi

  ok "Response received. Parsed fleet_snapshot.v1:"
  YUZU_VIZ_RESP="$response" python3 - <<'PY'
import json, os
data = json.loads(os.environ['YUZU_VIZ_RESP'])
rows = data if isinstance(data, list) else data.get('responses', data.get('data', [data]))
if not isinstance(rows, list):
    rows = [rows]
for r in rows:
    out = r.get('output', '')
    try:
        snap = json.loads(out)
        agent_id = r.get('agent_id', '?')
        schema = snap.get('schema')
        minor = snap.get('schema_minor')
        host = snap.get('hostname')
        ips = snap.get('local_ips')
        nproc = len(snap.get('processes', []))
        nconn = len(snap.get('connections', []))
        tp = snap.get('truncated_processes')
        tc = snap.get('truncated_connections')
        print('  agent_id:      ' + str(agent_id))
        print('  schema:        ' + str(schema) + ' (minor=' + str(minor) + ')')
        print('  hostname:      ' + str(host))
        print('  local_ips:     ' + str(ips))
        print('  processes:     ' + str(nproc) + ' entries (truncated=' + str(tp) + ')')
        print('  connections:   ' + str(nconn) + ' entries (truncated=' + str(tc) + ')')
        if snap.get('process_source_paused'):
            print('  process_source_paused: TRUE')
        if snap.get('tcp_source_paused'):
            print('  tcp_source_paused:     TRUE')
        if nproc:
            sample = [(p['pid'], p['name'], p.get('user', '')) for p in snap['processes'][:5]]
            print('  first 5 procs: ' + str(sample))
        if nconn:
            sample = [(c['proto'], c['local_addr'] + ':' + str(c['local_port']),
                       '->', c['remote_addr'] + ':' + str(c['remote_port']),
                       c['state']) for c in snap['connections'][:5]]
            print('  first 5 conns: ' + str(sample))
        print()
    except Exception as e:
        print('  (unparseable output, len=' + str(len(out)) + ': ' + str(e) + ')')
        print('  raw[:300]: ' + out[:300])
PY
}

# ── Generate server config ─────────────────────────────────────────────────

generate_config() {
  mkdir -p "$VIZ_UAT_DIR/viz-uat"
  python3 -c "
import hashlib, os
salt = os.urandom(16)
dk = hashlib.pbkdf2_hmac('sha256', '${ADMIN_PASS}'.encode(), salt, 100000, dklen=32)
print(f'${ADMIN_USER}:admin:{salt.hex()}:{dk.hex()}')
" > "$VIZ_UAT_DIR/viz-uat/yuzu-server.cfg"
  # 644 (not 600): this file is bind-mounted into yuzu-viz-server, which runs
  # as uid 999 (`yuzu`) inside the container. The host file is owned by the
  # operator's uid (typically 1000), so mode 600 made it unreadable from the
  # container → the server's first-run setup fired, read empty stdin (no TTY),
  # and the password floor killed the start. The content is a PBKDF2-SHA256
  # hash (no cleartext password) so 644 is the right mode for a containerized
  # launcher on a single-operator dev box.
  chmod 644 "$VIZ_UAT_DIR/viz-uat/yuzu-server.cfg"
  ok "Generated server config (admin / adminpassword1) at $VIZ_UAT_DIR/viz-uat/yuzu-server.cfg"
}

# ── Build images ───────────────────────────────────────────────────────────

build_images() {
  if [ -n "$VIZ_UAT_SKIP_BUILD" ]; then
    info "VIZ_UAT_SKIP_BUILD=1 — skipping docker build"
    return
  fi

  # vcpkg triplet derived from host arch. Server + agent Dockerfiles take a
  # --build-arg TRIPLET= (default x64-linux, override for arm64-linux).
  local triplet
  case "$VIZ_UAT_PLATFORM" in
    linux/arm64) triplet=arm64-linux ;;
    linux/amd64|linux/x64) triplet=x64-linux ;;
    *) fail "unsupported VIZ_UAT_PLATFORM=$VIZ_UAT_PLATFORM"; exit 1 ;;
  esac
  info "Building images for $VIZ_UAT_PLATFORM (vcpkg triplet=$triplet) — first run is 25-40 min..."
  cd "$REPO_ROOT"

  info "  building yuzu-server-viz-uat:latest ..."
  docker build --platform "$VIZ_UAT_PLATFORM" \
      --build-arg "TRIPLET=$triplet" \
      -t yuzu-server-viz-uat:latest \
      -f deploy/docker/Dockerfile.server .
  ok "  built yuzu-server-viz-uat:latest"

  info "  building yuzu-gateway-viz-uat:latest ..."
  docker build --platform "$VIZ_UAT_PLATFORM" \
      -t yuzu-gateway-viz-uat:latest \
      -f deploy/docker/Dockerfile.gateway .
  ok "  built yuzu-gateway-viz-uat:latest"

  info "  building yuzu-agent-viz-uat:latest ..."
  docker build --platform "$VIZ_UAT_PLATFORM" \
      --build-arg "TRIPLET=$triplet" \
      -t yuzu-agent-viz-uat:latest \
      -f deploy/docker/Dockerfile.agent .
  ok "  built yuzu-agent-viz-uat:latest"
}

# ── Wait helpers ───────────────────────────────────────────────────────────

wait_for_url() {
  local url=$1 desc=$2 timeout=${3:-90}
  local waited=0
  while [ "$waited" -lt "$timeout" ]; do
    if curl -fsS -o /dev/null "$url" 2>/dev/null; then
      ok "$desc reachable ($url)"
      return 0
    fi
    sleep 2
    waited=$((waited + 2))
  done
  fail "$desc not reachable at $url within ${timeout}s"
  return 1
}

# ── Cedar & Vale: register agents on the three Alpine OrbStack VMs ─────────
#
# The Cedar & Vale rig models a fictional three-tier company:
#   yuzu-frontend  (nginx, web tier)        — frontend plane in the viz
#   yuzu-app       (nodejs app, mid-tier)   — app plane
#   yuzu-db        (database tier)          — database plane
#
# Each VM is a long-lived Alpine 3.23 OrbStack VM that the operator
# provisioned by hand (orb-style — see orb list). Each has yuzu-agent
# installed at /opt/yuzu/ and an OpenRC init script `yuzu-agent` whose
# wrapper at /opt/yuzu/run-agent.sh holds the registration CLI args.
#
# Because the wrapper hardcodes the enrollment token, restarting the
# viz-UAT Docker stack (which generates a fresh token every time)
# leaves the VM agents unable to register. This function repaints the
# wrapper on each VM with the current token and bounces the agent.
#
# Idempotent: VMs already running are not restarted; missing VMs are
# logged and skipped (the operator can `orb create` them and re-run).
# Missing `orb` CLI is a hard fail — there's no Plan B for reaching
# OrbStack VMs from the host.
register_cedar_vale_agents() {
  local enroll_token=$1

  if ! command -v orb >/dev/null 2>&1; then
    fail "VIZ_UAT_AGENT_MODE=cedar-vale needs the 'orb' CLI on PATH"
    fail "  install OrbStack: https://orbstack.dev/"
    exit 1
  fi

  info "Cedar & Vale rig: configuring agents on the three-tier VMs..."

  # Snapshot of running OrbStack VMs (one per line: NAME ...). orb list's
  # output format is "NAME STATE DISTRO ..."; awk on column 1+2 captures
  # name+state without depending on column counts that may grow.
  local orb_status
  orb_status=$(orb list 2>/dev/null) || {
    fail "orb list failed — is OrbStack running?"
    exit 1
  }

  local registered_vms=0
  local missing_vms=()
  for vm in $VIZ_UAT_CV_VMS; do
    local state
    state=$(printf '%s\n' "$orb_status" | awk -v n="$vm" '$1==n {print $2; exit}')
    if [ -z "$state" ]; then
      missing_vms+=("$vm")
      warn "  $vm — not present (skip; create with 'orb create alpine $vm')"
      continue
    fi
    if [ "$state" != "running" ]; then
      info "  $vm — state=$state, starting..."
      orb start "$vm" >/dev/null 2>&1 || true
    fi
    # Sanity-check the agent layout. If /opt/yuzu is missing, this VM
    # hasn't been provisioned for Cedar & Vale yet — bail with a clear
    # error rather than silently leaving a tier off the viz.
    if ! orb -m "$vm" test -x /opt/yuzu/yuzu-agent 2>/dev/null; then
      fail "  $vm — /opt/yuzu/yuzu-agent missing or non-executable"
      fail "    The Cedar & Vale rig expects /opt/yuzu/{yuzu-agent,run-agent.sh,plugins/} on each tier."
      exit 1
    fi

    info "  $vm — refreshing enrollment token + restarting yuzu-agent"
    # /opt/yuzu/run-agent.sh is root-owned (the agent itself runs as root
    # to read /proc/<pid>/net/* and similar privileged paths). `orb -m`
    # without -u maps to the host user (nathan), who can't write into
    # /opt/yuzu/. `orb -u root -m <vm>` elevates without prompting; sudo
    # would also work but requires NOPASSWD config we don't manage.
    #
    # OrbStack VM->macOS-host = 192.168.139.2 (NOT .1 — see
    # memory/reference_orbstack_vm_addressing.md).
    orb -u root -m "$vm" sh -c "
      cat > /opt/yuzu/run-agent.sh.new <<'AGENT_EOF'
#!/bin/sh
exec /opt/yuzu/libs/ld-linux-aarch64.so.1 \\
  --library-path /opt/yuzu/libs:/opt/yuzu/usr-local-lib \\
  /opt/yuzu/yuzu-agent \\
  --server 192.168.139.2:50051 \\
  --no-tls \\
  --plugin-dir /opt/yuzu/plugins \\
  --data-dir /var/lib/yuzu-agent \\
  --log-level info \\
  --enrollment-token $enroll_token
AGENT_EOF
      chmod 0700 /opt/yuzu/run-agent.sh.new
      mv /opt/yuzu/run-agent.sh.new /opt/yuzu/run-agent.sh
      rc-service yuzu-agent restart >/dev/null 2>&1 || rc-service yuzu-agent start >/dev/null 2>&1
    " || {
      fail "  $vm — failed to refresh agent (see 'orb -u root -m $vm rc-service yuzu-agent status')"
      exit 1
    }
    ok "  $vm — agent restarted"
    registered_vms=$((registered_vms + 1))
  done

  if [ "$registered_vms" -eq 0 ]; then
    fail "No Cedar & Vale VMs were configured. Missing: ${missing_vms[*]:-none}"
    fail "  Provision with: orb create alpine <name>  (then install yuzu-agent under /opt/yuzu)"
    exit 1
  fi

  info "Waiting for $registered_vms VM agent(s) to register..."
  local waited=0 reg=0
  while [ "$waited" -lt 90 ]; do
    reg=$(curl -fsS "http://localhost:8080/metrics" 2>/dev/null \
            | awk '/^yuzu_agents_registered_total /{print $2; exit}' || echo 0)
    reg=${reg:-0}
    if awk "BEGIN { exit !($reg >= $registered_vms) }"; then
      break
    fi
    sleep 2
    waited=$((waited + 2))
  done
  if ! awk "BEGIN { exit !($reg >= $registered_vms) }"; then
    fail "Only $reg of $registered_vms Cedar & Vale agents registered within 90s."
    fail "  Inspect: orb -m yuzu-app rc-service yuzu-agent status"
    fail "  Logs:    orb -m yuzu-app tail -50 /var/log/yuzu-agent.log"
    exit 1
  fi
  ok "$reg Cedar & Vale agent(s) registered"
  if [ "${#missing_vms[@]}" -gt 0 ]; then
    warn "Note: ${#missing_vms[@]} expected tier VM(s) absent: ${missing_vms[*]}"
  fi
}

# ── Bring-up ───────────────────────────────────────────────────────────────

cmd_start() {
  echo ""
  echo "╔══════════════════════════════════════════════════╗"
  printf '║  Yuzu Viz-UAT (%s) %*s║\n' "$VIZ_UAT_PLATFORM" $((33 - ${#VIZ_UAT_PLATFORM})) " "
  echo "╚══════════════════════════════════════════════════╝"
  echo ""

  # Stop any prior stack
  if [ -d "$VIZ_UAT_DIR" ]; then
    info "Tearing down any prior viz-UAT state..."
    cmd_stop || true
  fi
  mkdir -p "$VIZ_UAT_DIR"
  # 0700 keeps coresident users from listing token + cookie filenames.
  # Files inside also get explicit 0600 -- this dir-perm tightening is the
  # final round-2 hygiene fix (compliance-F3 follow-up).
  chmod 700 "$VIZ_UAT_DIR"

  build_images
  generate_config

  cd "$REPO_ROOT"

  # Phase 1: server + gateway (no token needed yet)
  info "Starting server + gateway..."
  YUZU_ENROLLMENT_TOKEN=stub docker compose -f "$COMPOSE_FILE" up -d server gateway
  wait_for_url "http://localhost:8080/login" "server dashboard" 90
  wait_for_url "http://localhost:8081/healthz" "gateway healthz" 60

  # Phase 2: login + create enrollment token
  info "Issuing enrollment token..."
  curl -fsS -c "$VIZ_UAT_DIR/cookies.txt" \
      "http://localhost:8080/login" \
      -d "username=${ADMIN_USER}&password=${ADMIN_PASS}" -o /dev/null
  local token_html
  # Field name is `ttl_hours` per settings_routes.cpp:3167; the previous
  # `ttl=86400` was silently dropped (resulting token had time_point::max
  # expiry). 24h is plenty for a UAT session. (gov round 2, DEP-R2-1.)
  token_html=$(curl -fsS -b "$VIZ_UAT_DIR/cookies.txt" \
      -X POST "http://localhost:8080/api/settings/enrollment-tokens" \
      -H "Origin: http://localhost:8080" \
      -d "label=viz-uat&max_uses=1000&ttl_hours=24")
  local enroll_token
  enroll_token=$(echo "$token_html" | grep -oE '[a-f0-9]{64}' | head -1)
  if [ -z "$enroll_token" ]; then
    fail "Could not parse enrollment token from /api/settings/enrollment-tokens response"
    fail "  raw: $token_html"
    exit 1
  fi
  echo "$enroll_token" > "$VIZ_UAT_DIR/enrollment-token"
  chmod 600 "$VIZ_UAT_DIR/enrollment-token"
  chmod 600 "$VIZ_UAT_DIR/cookies.txt" 2>/dev/null || true
  ok "Enrollment token issued (saved to $VIZ_UAT_DIR/enrollment-token)"

  # Phase 3: agent(s) — gated on VIZ_UAT_AGENT_MODE
  # Three modes:
  #   container (default): spin up the dockerised yuzu-agent under the
  #                        in-container-agent compose profile. Thin agent on a
  #                        debian:trixie-slim base — almost no loopback chatter,
  #                        useful as a smoke test for the registration path but
  #                        weak for PR-8+ visual demos.
  #   vm:                  do not start a containerised agent. Print the
  #                        enrollment-token + gateway-host:port the operator
  #                        will need to run yuzu-agent natively on an OrbStack
  #                        VM (or bare-metal host) reachable via the bridge
  #                        network. The host-exposed gateway port 50051 is the
  #                        registration target.
  #   none:                do not start an agent and do not block waiting for
  #                        registration. Useful for renderer iteration with an
  #                        empty fleet.
  local mode="${VIZ_UAT_AGENT_MODE:-container}"
  case "$mode" in
    container)
      info "Starting agent in container (scale=$VIZ_UAT_AGENTS)..."
      YUZU_ENROLLMENT_TOKEN="$enroll_token" \
        docker compose -f "$COMPOSE_FILE" --profile in-container-agent \
          up -d --scale "agent=$VIZ_UAT_AGENTS" agent

      info "Waiting for agent registration..."
      local waited=0 reg=0
      while [ "$waited" -lt 60 ]; do
        reg=$(curl -fsS "http://localhost:8080/metrics" 2>/dev/null \
                | awk '/^yuzu_agents_registered_total /{print $2; exit}' || echo 0)
        reg=${reg:-0}
        if awk "BEGIN { exit !($reg >= 1) }"; then
          break
        fi
        sleep 2
        waited=$((waited + 2))
      done
      if ! awk "BEGIN { exit !($reg >= 1) }"; then
        fail "No agents registered within 60s. Check 'bash scripts/start-viz-uat.sh status'"
        exit 1
      fi
      ok "$reg agent(s) registered"
      ;;
    cedar-vale)
      register_cedar_vale_agents "$enroll_token"
      ;;
    cedar-vale-local)
      # Three NAMED in-container agents (yuzu-frontend / yuzu-app / yuzu-db)
      # via the cedar-vale-local compose profile. Unlike `cedar-vale` this
      # needs no OrbStack/orb — it's the macOS-VM-free way to get tier-labelled
      # hostnames in /viz/fleet. NOT scaled: each tier is exactly one replica
      # so the hostnames stay distinct (VIZ_UAT_AGENTS is ignored here).
      info "Starting 3 named Cedar & Vale tier agents (frontend / app / db)..."
      YUZU_ENROLLMENT_TOKEN="$enroll_token" \
        docker compose -f "$COMPOSE_FILE" --profile cedar-vale-local \
          up -d agent-frontend agent-app agent-db

      info "Waiting for the 3 tier agents to register..."
      local waited=0 reg=0
      while [ "$waited" -lt 90 ]; do
        reg=$(curl -fsS "http://localhost:8080/metrics" 2>/dev/null \
                | awk '/^yuzu_agents_registered_total /{print $2; exit}' || echo 0)
        reg=${reg:-0}
        if awk "BEGIN { exit !($reg >= 3) }"; then
          break
        fi
        sleep 2
        waited=$((waited + 2))
      done
      if ! awk "BEGIN { exit !($reg >= 3) }"; then
        fail "Only $reg of 3 Cedar & Vale tier agents registered within 90s."
        fail "  Inspect: bash scripts/start-viz-uat.sh status"
        exit 1
      fi
      ok "$reg Cedar & Vale tier agent(s) registered (yuzu-frontend / yuzu-app / yuzu-db)"
      ;;
    cedar-vale-app)
      # Three-tier REAL app: Envoy (frontend) -> node (app) -> Postgres (db),
      # each co-hosting a yuzu-agent. Renders in /viz/fleet as a stack (frontend
      # top / app middle / db bottom) with two persistent blue tubes. The node
      # app serves an impress.js deck whose slide content lives in Postgres.
      # Container hostnames are yuzu-frontend/app/db (what the viz labels);
      # container_names are yuzu-cv-* to avoid colliding with the plain-agent
      # cedar-vale-local containers. VIZ_UAT_AGENTS is ignored (one per tier).
      if [ -z "$VIZ_UAT_SKIP_BUILD" ]; then
        info "Building Cedar & Vale tier images (Envoy / node / Postgres + agent)..."
        YUZU_ENROLLMENT_TOKEN=stub \
          docker compose -f "$COMPOSE_FILE" --profile cedar-vale-app \
            build cv-db cv-app cv-frontend
      fi
      info "Starting Cedar & Vale 3-tier app (frontend -> app -> db)..."
      YUZU_ENROLLMENT_TOKEN="$enroll_token" \
        docker compose -f "$COMPOSE_FILE" --profile cedar-vale-app \
          up -d cv-db cv-app cv-frontend

      info "Waiting for the 3 tiers to register..."
      local waited=0 reg=0
      while [ "$waited" -lt 120 ]; do
        reg=$(curl -fsS "http://localhost:8080/metrics" 2>/dev/null \
                | awk '/^yuzu_agents_registered_total /{print $2; exit}' || echo 0)
        reg=${reg:-0}
        if awk "BEGIN { exit !($reg >= 3) }"; then
          break
        fi
        sleep 2
        waited=$((waited + 2))
      done
      if ! awk "BEGIN { exit !($reg >= 3) }"; then
        fail "Only $reg of 3 Cedar & Vale tiers registered within 120s."
        fail "  Inspect: bash scripts/start-viz-uat.sh status"
        exit 1
      fi
      ok "$reg Cedar & Vale tier(s) registered (yuzu-frontend / yuzu-app / yuzu-db)"
      ok "Presentation: http://localhost:8088  (Envoy -> node -> Postgres, slides from db)"
      ;;
    vm)
      ok "Skipping in-container agent; VM-agent mode selected."
      info "Run yuzu-agent on the OrbStack VM (or bare-metal host):"
      info "  enroll-token: $(cat "$VIZ_UAT_DIR/enrollment-token")"
      # OrbStack proxies VM->macOS-host TCP through .2 on the VM bridge.
      # Default-route gateway .1 answers ICMP but no TCP forwards (a
      # common footgun — operators reading 'ip route show default' on
      # the VM get .1 and find connect-refused). The .2 address is the
      # canonical port-forward target. (gov R8 build-ci SHOULD;
      # memory/reference_orbstack_vm_addressing.md)
      info "  gateway addr: 192.168.139.2:50051   (OrbStack VM->host port-forward IP — NOT .1)"
      printf '%s\n' "192.168.139.2:50051" > "$VIZ_UAT_DIR/gateway-host-addr"
      chmod 600 "$VIZ_UAT_DIR/gateway-host-addr" 2>/dev/null || true
      info "  example:      yuzu-agent --server 192.168.139.2:50051 --no-tls \\"
      info "                  --plugin-dir <path-to-plugins> \\"
      info "                  --data-dir /var/lib/yuzu-agent \\"
      info "                  --enrollment-token <token>"
      info "(host addr also written to \$VIZ_UAT_DIR/gateway-host-addr)"
      ;;
    none)
      ok "Skipping agent startup; VIZ_UAT_AGENT_MODE=none"
      ;;
    *)
      fail "Unknown VIZ_UAT_AGENT_MODE='$mode'. Allowed: container | cedar-vale-local | cedar-vale-app | vm | cedar-vale | none"
      exit 1
      ;;
  esac

  echo ""
  echo "╔══════════════════════════════════════════════════╗"
  echo "║  Viz-UAT is up                                    ║"
  echo "╚══════════════════════════════════════════════════╝"
  echo ""
  echo "  Dashboard:   http://localhost:8080         (admin / adminpassword1)"
  echo "  Server API:  http://localhost:8080/api/v1/"
  echo "  Gateway:     http://localhost:8081/healthz | http://localhost:9568/metrics"
  echo "  State dir:   $VIZ_UAT_DIR"
  echo ""
  echo "  Exercise tar.fleet_snapshot:"
  echo "    bash scripts/start-viz-uat.sh fleet-snapshot"
  echo ""
  echo "  Tail logs:"
  echo "    docker compose -f $COMPOSE_FILE logs -f"
  echo ""
  echo "  Stop everything:"
  echo "    bash scripts/start-viz-uat.sh stop"
  echo ""
}

# ── Dispatch ────────────────────────────────────────────────────────────────

case "${1:-start}" in
  start)            cmd_start ;;
  stop|down)        cmd_stop ;;
  status|ps)        cmd_status ;;
  restart)          cmd_restart ;;
  fleet-snapshot)   cmd_fleet_snapshot ;;
  *)
    cat <<USAGE
Usage: $(basename "$0") [start|stop|restart|status|fleet-snapshot]

  start            (default) build + start + verify registration
  stop             docker compose down -v + clean \$VIZ_UAT_DIR
  restart          stop + start
  status           docker compose ps + last log lines
  fleet-snapshot   dispatch crossplatform.tar.fleet_snapshot to all agents

Env overrides:
  VIZ_UAT_DIR=/tmp/yuzu-viz-uat
  VIZ_UAT_AGENTS=1     (--scale agent=N)
  VIZ_UAT_SKIP_BUILD=1 (skip docker build)
  VIZ_UAT_PLATFORM=linux/arm64
  VIZ_UAT_AGENT_MODE=container|cedar-vale-local|cedar-vale-app|vm|cedar-vale|none
                       cedar-vale-local = three NAMED in-container agents
                                    (yuzu-frontend / yuzu-app / yuzu-db) so
                                    /viz/fleet labels the tiers by name with
                                    NO OrbStack/orb dependency. Best choice on
                                    a Linux / WSL2 box.
                       cedar-vale-app = three NAMED tiers running REAL services
                                    (Envoy -> node -> Postgres), each co-hosting
                                    an agent, so /viz/fleet shows the stack with
                                    live blue tubes. node serves an impress.js
                                    deck whose slides live in Postgres; the deck
                                    is at http://localhost:8088.
                       cedar-vale = register agents on the three Alpine
                                    OrbStack VMs that model the Cedar &
                                    Vale three-tier company so /viz/fleet
                                    renders all three tiers (macOS/orb only)
  VIZ_UAT_CV_VMS="yuzu-frontend yuzu-app yuzu-db"
                       VM names for cedar-vale mode
USAGE
    exit 2
    ;;
esac
