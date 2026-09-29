#!/usr/bin/env bash
# qa-stack.sh — Pre-release QA harness around the shipped reference template
# deploy/docker/docker-compose.reference-gateway.yml (server + Erlang gateway
# + agent + Postgres; TLS everywhere; agents enrol with a token and get a
# per-agent mTLS leaf). Pre-release QA exercises the stack operators copy
# rather than a workflow-private stack that drifts from it.
#
# Usage (from a checkout; state lives in $QA_STATE_DIR, default /tmp/yuzu-qa):
#   qa-stack.sh up <version>        start server+gateway (+postgres), enrol an agent
#   qa-stack.sh upgrade <version>   move every service to <version>, wait for recovery
#   qa-stack.sh wait-agent          wait until the server reports >= 1 registered agent
#   qa-stack.sh login               (re)create the admin session cookie
#   qa-stack.sh api <METHOD> <path> [json-body]   authenticated HTTPS call, body to stdout
#   qa-stack.sh metric <server|gateway> <name>    print a metric's value (0 if absent)
#   qa-stack.sh running             print how many of the four services are running
#   qa-stack.sh stats               one line of per-service memory usage
#   qa-stack.sh logs <file>         write all service logs to <file>
#   qa-stack.sh down                stop and delete the stack and its volumes
#
# The gateway's sys.config is taken from the git tag of the version being run
# (v<version>), not from this checkout: a config naming a module the older
# gateway image lacks (e.g. the #1422 mgmt peer-pin auth_fun) closes every
# mgmt-plane connection, and an operator on that release has that release's
# config on disk. Only the compose file itself comes from this checkout — its
# images are all pinned by YUZU_VERSION.
#
# The dashboard is verified against the stack's own install CA (copied out of
# the server's cert volume); its HTTPS leaf carries SANs localhost/127.0.0.1.
# Gateway health (:8081) and metrics (:9568) are plain HTTP and are published
# on 127.0.0.1 only by the QA override below.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
COMPOSE_FILE="$ROOT/deploy/docker/docker-compose.reference-gateway.yml"
STATE="${QA_STATE_DIR:-/tmp/yuzu-qa}"
PROJECT="${QA_PROJECT:-yuzu-qa}"
BASE_URL="https://localhost:8443"
ENV_FILE="$STATE/qa.env"
OVERRIDE="$STATE/qa.override.yml"

log() { printf '[qa-stack] %s\n' "$*" >&2; }
die() { printf '::error::qa-stack: %s\n' "$*" >&2; exit 1; }

compose() {
  docker compose -p "$PROJECT" --env-file "$ENV_FILE" \
    -f "$COMPOSE_FILE" -f "$OVERRIDE" "$@"
}

set_env() {  # set_env KEY VALUE  (qa.env is KEY=VALUE, one per line)
  local k="$1" v="$2"
  if grep -q "^${k}=" "$ENV_FILE" 2>/dev/null; then
    sed -i "s|^${k}=.*|${k}=${v}|" "$ENV_FILE"
  else
    printf '%s=%s\n' "$k" "$v" >> "$ENV_FILE"
  fi
}
get_env() { sed -n "s/^${1}=//p" "$ENV_FILE"; }

prepare() {
  mkdir -p "$STATE"
  if [[ ! -f "$ENV_FILE" ]]; then
    : > "$ENV_FILE"
    # Distinct superuser / app-role passwords (first-boot init refuses equal ones).
    set_env YUZU_POSTGRES_PASSWORD "$(openssl rand -hex 24)"
    set_env YUZU_DB_PASSWORD "$(openssl rand -hex 24)"
    # The agent service interpolates this; the real token is set after the
    # server is up (compose validates required vars for every service).
    set_env YUZU_ENROLL_TOKEN "not-yet-issued"
    set_env QA_ADMIN_PASSWORD "$(openssl rand -hex 16)"
  fi
  if [[ ! -f "$STATE/yuzu-server.cfg" ]]; then
    QA_PW="$(get_env QA_ADMIN_PASSWORD)" python3 - > "$STATE/yuzu-server.cfg" <<'PY'
import hashlib, os
salt = os.urandom(16)
dk = hashlib.pbkdf2_hmac('sha256', os.environ['QA_PW'].encode(), salt, 100000, dklen=32)
print(f"qaadmin:admin:{salt.hex()}:{dk.hex()}")
PY
  fi
  write_override
}

gateway_sys_config() {  # gateway_sys_config VERSION -> $STATE/gateway-sys.config
  local ver="$1" url
  url="https://raw.githubusercontent.com/${QA_REPO:-DevNullLtd/Yuzu}/v${ver}/deploy/docker/reference-gateway-sys.config"
  curl -sSfL --retry 3 -o "$STATE/gateway-sys.config.new" "$url" \
    || die "could not fetch the v${ver} gateway sys.config ($url)"
  mv "$STATE/gateway-sys.config.new" "$STATE/gateway-sys.config"
  log "gateway sys.config: v${ver}"
}

write_override() {
  cat > "$OVERRIDE" <<EOF
services:
  server:
    volumes:
      - $STATE/yuzu-server.cfg:/etc/yuzu/yuzu-server.cfg:ro
  gateway:
    volumes:
      - $STATE/gateway-sys.config:/opt/yuzu_gw/releases/0.2.0/sys.config:ro
      - certs:/etc/yuzu/certs:ro
    ports:
      - "127.0.0.1:8081:8081"
      - "127.0.0.1:9568:9568"
EOF
}

# Origin is the stack's own origin: cookie-authenticated mutations are
# same-site-checked (Origin/Referer vs Host), and a script sends neither.
curl_tls() { curl -sS --cacert "$STATE/ca.pem" -H "Origin: $BASE_URL" "$@"; }

wait_server() {
  log "waiting for the server (HTTPS /livez, verified against the install CA)"
  local i
  for i in $(seq 1 60); do
    if compose cp server:/etc/yuzu/certs/default-ca.pem "$STATE/ca.pem" >/dev/null 2>&1 \
       && [[ "$(curl_tls -o /dev/null -w '%{http_code}' "$BASE_URL/livez" 2>/dev/null)" == "200" ]]; then
      log "server is live"; return 0
    fi
    sleep 3
  done
  compose ps >&2 || true
  compose logs --tail 80 server >&2 || true
  die "server did not become live over HTTPS within 180s"
}

wait_gateway() {
  log "waiting for the gateway (/readyz)"
  local i
  for i in $(seq 1 60); do
    curl -sf http://127.0.0.1:8081/readyz 2>/dev/null | grep -q '"ready"' && { log "gateway is ready"; return 0; }
    sleep 3
  done
  compose logs --tail 80 gateway >&2 || true
  die "gateway did not report ready within 180s"
}

login() {
  local code
  code="$(curl_tls -c "$STATE/cookies.txt" -o /dev/null -w '%{http_code}' \
    --data-urlencode "username=qaadmin" \
    --data-urlencode "password=$(get_env QA_ADMIN_PASSWORD)" \
    "$BASE_URL/login")"
  [[ "$code" == 200 || "$code" == 302 || "$code" == 303 ]] || die "login returned HTTP $code"
  grep -q . "$STATE/cookies.txt" || die "login set no session cookie"
}

api() {  # api METHOD PATH [JSON]
  local m="$1" p="$2" body="${3:-}"
  if [[ -n "$body" ]]; then
    curl_tls -b "$STATE/cookies.txt" -X "$m" -H 'Content-Type: application/json' -d "$body" "$BASE_URL$p"
  else
    curl_tls -b "$STATE/cookies.txt" -X "$m" "$BASE_URL$p"
  fi
}

metric() {  # metric server|gateway NAME
  local src="$1" name="$2" text
  if [[ "$src" == server ]]; then
    text="$(api GET /metrics 2>/dev/null || true)"
  else
    text="$(curl -s http://127.0.0.1:9568/metrics 2>/dev/null || true)"
  fi
  # Sum every series of the family (labelled or not); 0 when absent.
  printf '%s\n' "$text" | awk -v n="$name" '
    $1 == n || index($1, n "{") == 1 { s += $NF; f = 1 }
    END { if (f) printf "%d\n", s; else print 0 }'
}

wait_agent() {
  log "waiting for an agent to register"
  local i c=0
  for i in $(seq 1 60); do
    c="$(metric server yuzu_agents_registered_total)"
    [[ "$c" -ge 1 ]] && { log "$c agent(s) registered"; return 0; }
    sleep 3
  done
  compose logs --tail 80 agent gateway >&2 || true
  die "no agent registered within 180s"
}

issue_token() {
  local resp tok
  resp="$(api POST /api/settings/enrollment-tokens/batch '{"label":"pre-release-qa","count":"1","max_uses":"10"}')"
  tok="$(printf '%s' "$resp" | python3 -c 'import sys,json; t=json.load(sys.stdin).get("tokens") or []; print(t[0] if t else "")' 2>/dev/null || true)"
  [[ -n "$tok" ]] || die "could not issue an enrollment token: $resp"
  set_env YUZU_ENROLL_TOKEN "$tok"
}

cmd_up() {
  local ver="${1:?version required}"
  prepare
  set_env YUZU_VERSION "$ver"
  gateway_sys_config "$ver"
  log "starting server + gateway (+postgres) at $ver"
  compose pull -q
  compose up -d server gateway
  wait_server
  wait_gateway
  login
  issue_token
  log "starting the agent (enrolls with a one-off token, TLS to the gateway)"
  compose up -d agent
  wait_agent
}

cmd_upgrade() {
  local ver="${1:?version required}"
  [[ -f "$ENV_FILE" ]] || die "no stack to upgrade (run 'up' first)"
  set_env YUZU_VERSION "$ver"
  gateway_sys_config "$ver"
  log "upgrading every service to $ver"
  compose pull -q
  compose up -d
  wait_server
  wait_gateway
  login
  wait_agent
}

cmd_running() {
  local s n=0
  for s in server gateway agent postgres; do
    [[ "$(docker inspect -f '{{.State.Running}}' "$(compose ps -q "$s" 2>/dev/null)" 2>/dev/null)" == true ]] && n=$((n + 1))
  done
  echo "$n"
}

cmd_stats() {
  local s id out=""
  for s in server gateway agent postgres; do
    id="$(compose ps -q "$s" 2>/dev/null || true)"
    out+="$s=$( [[ -n "$id" ]] && docker stats --no-stream --format '{{.MemUsage}}' "$id" 2>/dev/null | cut -d/ -f1 | tr -d ' ' || echo '?') "
  done
  echo "$out"
}

case "${1:-}" in
  up)         shift; cmd_up "$@" ;;
  upgrade)    shift; cmd_upgrade "$@" ;;
  wait-agent) wait_agent ;;
  login)      login ;;
  api)        shift; api "$@" ;;
  metric)     shift; metric "$@" ;;
  running)    cmd_running ;;
  stats)      cmd_stats ;;
  logs)       shift; { compose ps; compose logs --no-color; } > "${1:?file required}" 2>&1 || true ;;
  down)       compose down -v --remove-orphans || true ;;
  *) echo "usage: $0 {up|upgrade|wait-agent|login|api|metric|running|stats|logs|down}" >&2; exit 2 ;;
esac
