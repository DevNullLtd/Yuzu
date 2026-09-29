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
#   qa-stack.sh has-stack <version> exit 0 if release <version> ships the reference
#                                   template, 1 if it predates it
#   qa-stack.sh wait-agent          wait until the server reports >= 1 connected agent
#   qa-stack.sh login               (re)create the admin session cookie
#   qa-stack.sh api <METHOD> <path> [json-body]   authenticated HTTPS call, body to stdout
#   qa-stack.sh roundtrip <plugin> <action> <key> [polls]
#                                   dispatch a command, print the agent's `<key>|` value
#   qa-stack.sh agents              connected agents, one `<agent_id> <agent_version>` per line
#   qa-stack.sh metric <server|gateway> <name>    print a metric's value (0 if absent)
#   qa-stack.sh running             how many of the four services are in state "running"
#   qa-stack.sh restarts            total restart count across the four services
#   qa-stack.sh state               one line: <service>=<status>/<restarts> for each
#   qa-stack.sh stats               one line of per-service memory usage
#   qa-stack.sh logs <file>         write all service logs to <file>
#   qa-stack.sh down                stop and delete the stack and its volumes
#
# What comes from where. The compose file is THIS checkout's template; its
# images are pinned by YUZU_VERSION, so the binaries are the release's own. The
# gateway's sys.config, and the path it is mounted at, come from the git tag of
# the version being run (v<version>) in $QA_REPO: a config naming a module the
# older gateway image lacks (e.g. the #1422 mgmt peer-pin auth_fun) closes every
# mgmt-plane connection, and the mount path follows the gateway's relx release
# version, which can change between releases. Where this checkout's template
# differs from the tagged one, the difference is printed as a warning and
# written to the job summary, so the report says which template was exercised.
#
# The dashboard is verified against the stack's own install CA (copied out of
# the server's cert volume); its HTTPS leaf carries SANs localhost/127.0.0.1.
# Gateway health (:8081) and metrics (:9568) are plain HTTP and are published
# on 127.0.0.1 only by the QA override below.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
COMPOSE_FILE="$ROOT/deploy/docker/docker-compose.reference-gateway.yml"
TEMPLATE_PATH="deploy/docker/docker-compose.reference-gateway.yml"
SYS_CONFIG_PATH="deploy/docker/reference-gateway-sys.config"
STATE="${QA_STATE_DIR:-/tmp/yuzu-qa}"
PROJECT="${QA_PROJECT:-yuzu-qa}"
QA_REPO="${QA_REPO:-DevNullLtd/Yuzu}"
BASE_URL="https://localhost:8443"
ENV_FILE="$STATE/qa.env"
OVERRIDE="$STATE/qa.override.yml"
SERVICES=(server gateway agent postgres)

log() { printf '[qa-stack] %s\n' "$*" >&2; }
die() { printf '::error::qa-stack: %s\n' "$*" >&2; exit 1; }

compose() {
  docker compose -p "$PROJECT" --env-file "$ENV_FILE" \
    -f "$COMPOSE_FILE" -f "$OVERRIDE" "$@"
}

# A version reaches a sed replacement, a URL and an image tag, so it is checked
# against the release-tag shape before any of them.
check_version() {
  [[ "$1" =~ ^[0-9]+\.[0-9]+\.[0-9]+(-[0-9A-Za-z][0-9A-Za-z.]*)?$ ]] \
    || die "not a release version: '$1' (expected e.g. 0.14.0 or 0.14.0-rc3)"
}

set_env() {  # set_env KEY VALUE  (qa.env is KEY=VALUE, one per line)
  local k="$1" v="$2"
  # The value is a sed replacement below: refuse the characters that change its meaning.
  [[ "$v" != *[\|\&\\$'\n']* ]] || die "refusing to store $k: value has a character sed would interpret"
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
}

# fetch_tag_file VERSION REPO_PATH OUT
#   0 = fetched to OUT; 3 = the file does not exist at that tag (HTTP 404).
#   Anything else (network, TLS, 5xx after retries) is fatal: an unreachable
#   GitHub must never read as "this release has no such file".
fetch_tag_file() {
  local ver="$1" path="$2" out="$3" url code
  url="https://raw.githubusercontent.com/${QA_REPO}/v${ver}/${path}"
  code="$(curl -sSL --proto '=https' --max-time 30 --retry 3 \
            -o "$out.part" -w '%{http_code}' "$url")" \
    || die "could not fetch $url"
  case "$code" in
    200) mv "$out.part" "$out" ;;
    404) rm -f "$out.part"; return 3 ;;
    *)   rm -f "$out.part"; die "fetching $url returned HTTP $code" ;;
  esac
}

cmd_has_stack() {
  local ver="${1:?version required}" rc=0
  check_version "$ver"
  mkdir -p "$STATE"
  fetch_tag_file "$ver" "$TEMPLATE_PATH" "$STATE/probe-template.yml" || rc=$?
  rm -f "$STATE/probe-template.yml"
  case "$rc" in
    0) log "v${ver} ships $TEMPLATE_PATH"; return 0 ;;
    3) log "v${ver} predates $TEMPLATE_PATH"; return 1 ;;
    *) return "$rc" ;;
  esac
}

# stage_version VERSION: fetch that release's gateway sys.config and template,
# note any drift between the tagged template and this checkout's, and write the
# override that mounts the config where that release's gateway reads it.
stage_version() {
  local ver="$1" tagged="$STATE/template-v$1.yml" target drift rc=0
  fetch_tag_file "$ver" "$TEMPLATE_PATH" "$tagged" || rc=$?
  [[ "$rc" -eq 0 ]] || die "v${ver} has no $TEMPLATE_PATH, so it predates the reference stack QA runs"
  rc=0
  fetch_tag_file "$ver" "$SYS_CONFIG_PATH" "$STATE/gateway-sys.config" || rc=$?
  [[ "$rc" -eq 0 ]] || die "v${ver} has no $SYS_CONFIG_PATH"

  target="$(grep -oE '/opt/yuzu_gw/releases/[^/:[:space:]]+/sys\.config' "$tagged" | head -1 || true)"
  [[ -n "$target" ]] || die "v${ver}'s template mounts no /opt/yuzu_gw/releases/<vsn>/sys.config"
  log "gateway sys.config: v${ver}, mounted at $target"

  drift="$STATE/template-drift-v${ver}.diff"
  rc=0
  diff -u --label "v${ver}/$TEMPLATE_PATH" --label "checkout/$TEMPLATE_PATH" \
    "$tagged" "$COMPOSE_FILE" > "$drift" || rc=$?
  [[ "$rc" -le 1 ]] || die "could not compare v${ver}'s template with $COMPOSE_FILE"
  if [[ "$rc" -eq 1 ]]; then
    local n
    n="$(grep -cE '^[-+][^-+]' "$drift" || true)"
    echo "::warning::QA runs this checkout's $TEMPLATE_PATH, which differs from the one tagged v${ver} ($n changed lines). Images are v${ver}'s; the service definitions are the checkout's. Diff in the job summary."
    if [[ -n "${GITHUB_STEP_SUMMARY:-}" ]]; then
      {
        echo "**Reference template drift: v${ver} tag vs this checkout** ($n changed lines)"
        echo
        echo "<details><summary>diff</summary>"
        echo
        echo '```diff'
        head -n 300 "$drift"
        echo '```'
        echo "</details>"
        echo
      } >> "$GITHUB_STEP_SUMMARY"
    fi
  else
    log "this checkout's template matches v${ver}'s"
  fi

  cat > "$OVERRIDE" <<EOF
services:
  server:
    volumes:
      - $STATE/yuzu-server.cfg:/etc/yuzu/yuzu-server.cfg:ro
  gateway:
    volumes:
      - $STATE/gateway-sys.config:$target:ro
      - certs:/etc/yuzu/certs:ro
    ports:
      - "127.0.0.1:8081:8081"
      - "127.0.0.1:9568:9568"
EOF
  set_env YUZU_VERSION "$ver"
}

dump_stack() {
  compose ps -a >&2 || true
  compose logs --no-color --tail 120 >&2 || true
}

pull() {
  local n
  for n in 1 2 3; do
    compose pull -q && return 0
    log "compose pull failed (attempt $n/3)"
    sleep $((n * 10))
  done
  die "compose pull failed 3 times"
}

up() {  # up [SERVICE...]
  compose up -d "$@" || { dump_stack; die "compose up -d $* failed"; }
}

# Origin is the stack's own origin: cookie-authenticated mutations are
# same-site-checked (Origin/Referer vs Host), and a script sends neither.
curl_tls() { curl -sS --max-time 30 --cacert "$STATE/ca.pem" -H "Origin: $BASE_URL" "$@"; }

wait_server() {
  log "waiting for the server (HTTPS /livez, verified against the install CA)"
  for _ in $(seq 1 60); do
    if compose cp server:/etc/yuzu/certs/default-ca.pem "$STATE/ca.pem" >/dev/null 2>&1 \
       && [[ "$(curl_tls -o /dev/null -w '%{http_code}' "$BASE_URL/livez" 2>/dev/null)" == "200" ]]; then
      log "server is live"; return 0
    fi
    sleep 3
  done
  dump_stack
  die "server did not become live over HTTPS within 180s"
}

wait_gateway() {
  log "waiting for the gateway (/readyz)"
  for _ in $(seq 1 60); do
    curl -sf --max-time 5 http://127.0.0.1:8081/readyz 2>/dev/null | grep -q '"ready"' \
      && { log "gateway is ready"; return 0; }
    sleep 3
  done
  dump_stack
  die "gateway did not report ready within 180s"
}

login() {
  local code
  code="$(curl_tls -c "$STATE/cookies.txt" -o /dev/null -w '%{http_code}' \
    --data-urlencode "username=qaadmin" \
    --data-urlencode "password=$(get_env QA_ADMIN_PASSWORD)" \
    "$BASE_URL/login")"
  [[ "$code" == 200 || "$code" == 302 || "$code" == 303 ]] || die "login returned HTTP $code"
  # A failed login also answers 200 (the form again), so the proof is the
  # session cookie itself, not the status code or a non-empty jar.
  awk -F'\t' '$6 == "yuzu_session" && $7 != "" { f = 1 } END { exit !f }' "$STATE/cookies.txt" \
    || die "login (HTTP $code) set no yuzu_session cookie"
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
    text="$(curl -s --max-time 10 http://127.0.0.1:9568/metrics 2>/dev/null || true)"
  fi
  # Sum every series of the family (labelled or not); 0 when absent.
  printf '%s\n' "$text" | awk -v n="$name" '
    $1 == n || index($1, n "{") == 1 { s += $NF; f = 1 }
    END { if (f) printf "%d\n", s; else print 0 }'
}

# The CONNECTED gauge, not yuzu_agents_registered_total: that counter never
# goes down, so after the first registration it stays >= 1 through a
# disconnect, a crash loop or an upgrade that never reconnects.
wait_agent() {
  log "waiting for an agent to connect"
  local c=0
  for _ in $(seq 1 60); do
    c="$(metric server yuzu_agents_connected)"
    [[ "$c" -ge 1 ]] && { log "$c agent(s) connected"; return 0; }
    sleep 3
  done
  compose logs --no-color --tail 80 agent gateway >&2 || true
  die "no agent connected within 180s"
}

cmd_agents() {
  api GET /api/agents | python3 -c '
import sys, json
for a in json.load(sys.stdin):
    print(a.get("agent_id", ""), a.get("agent_version", ""))'
}

# roundtrip PLUGIN ACTION KEY [POLLS]: dispatch PLUGIN.ACTION and wait (POLLS x 2s)
# for a response line `KEY|value`; print value. A rejection such as
# `plugin not found: <name>` has no such line and fails.
roundtrip() {
  local plugin="$1" action="$2" key="$3" polls="${4:-20}" resp id out
  [[ "$plugin" =~ ^[a-z_]+$ && "$action" =~ ^[a-z_]+$ && "$key" =~ ^[a-z_]+$ && "$polls" =~ ^[0-9]+$ ]] \
    || die "roundtrip: bad arguments"
  resp="$(api POST /api/command "{\"plugin\":\"$plugin\",\"action\":\"$action\"}" 2>&1)" || true
  id="$(printf '%s' "$resp" | python3 -c 'import sys,json; print(json.load(sys.stdin).get("command_id",""))' 2>/dev/null || true)"
  [[ -n "$id" ]] || { log "dispatching $plugin.$action returned no command_id: $resp"; return 1; }
  for _ in $(seq 1 "$polls"); do
    sleep 2
    out="$(api GET "/api/responses/$id" 2>/dev/null | KEY="$key" python3 -c '
import os, sys, json
k = os.environ["KEY"] + "|"
for r in json.load(sys.stdin).get("responses", []):
    for line in r.get("output", "").splitlines():
        if line.startswith(k):
            print(line[len(k):]); sys.exit(0)' 2>/dev/null || true)"
    [[ -n "$out" ]] && { printf '%s\n' "$out"; return 0; }
  done
  log "no '$key|' line in any response to $plugin.$action ($id) after $((polls * 2))s"
  api GET "/api/responses/$id" >&2 2>/dev/null || true
  return 1
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
  check_version "$ver"
  prepare
  stage_version "$ver"
  log "starting server + gateway (+postgres) at $ver"
  pull
  up server gateway
  wait_server
  wait_gateway
  login
  issue_token
  log "starting the agent (enrolls with a one-off token, TLS to the gateway)"
  up agent
  wait_agent
}

cmd_upgrade() {
  local ver="${1:?version required}"
  check_version "$ver"
  [[ -f "$ENV_FILE" ]] || die "no stack to upgrade (run 'up' first)"
  stage_version "$ver"
  log "upgrading every service to $ver"
  pull
  up
  wait_server
  wait_gateway
  login
  wait_agent
}

# .State.Status, not .State.Running: Running stays true while Docker is
# restarting a crash-looping container, so a counter of Running containers
# reads 4/4 through a crash loop.
svc_field() {  # svc_field SERVICE GO-TEMPLATE  (prints "missing" when there is no container)
  local id
  id="$(compose ps -a -q "$1" 2>/dev/null | head -1 || true)"
  [[ -n "$id" ]] || { echo missing; return 0; }
  docker inspect -f "$2" "$id" 2>/dev/null || echo missing
}

cmd_running() {
  local s n=0
  for s in "${SERVICES[@]}"; do
    [[ "$(svc_field "$s" '{{.State.Status}}')" == running ]] && n=$((n + 1))
  done
  echo "$n"
}

cmd_restarts() {
  local s r n=0
  for s in "${SERVICES[@]}"; do
    r="$(svc_field "$s" '{{.RestartCount}}')"
    [[ "$r" =~ ^[0-9]+$ ]] && n=$((n + r))
  done
  echo "$n"
}

cmd_state() {
  local s out=""
  for s in "${SERVICES[@]}"; do
    out+="$s=$(svc_field "$s" '{{.State.Status}}/{{.RestartCount}}') "
  done
  echo "${out% }"
}

cmd_stats() {
  local s id out=""
  for s in "${SERVICES[@]}"; do
    id="$(compose ps -q "$s" 2>/dev/null || true)"
    out+="$s=$( [[ -n "$id" ]] && docker stats --no-stream --format '{{.MemUsage}}' "$id" 2>/dev/null | cut -d/ -f1 | tr -d ' ' || echo '?') "
  done
  echo "$out"
}

case "${1:-}" in
  up)         shift; cmd_up "$@" ;;
  upgrade)    shift; cmd_upgrade "$@" ;;
  has-stack)  shift; cmd_has_stack "$@" ;;
  wait-agent) wait_agent ;;
  login)      login ;;
  api)        shift; api "$@" ;;
  roundtrip)  shift; roundtrip "$@" ;;
  agents)     cmd_agents ;;
  metric)     shift; metric "$@" ;;
  running)    cmd_running ;;
  restarts)   cmd_restarts ;;
  state)      cmd_state ;;
  stats)      cmd_stats ;;
  logs)       shift; { compose ps -a; compose logs --no-color; } > "${1:?file required}" 2>&1 || true ;;
  down)       compose down -v --remove-orphans || true ;;
  *) echo "usage: $0 {up|upgrade|has-stack|wait-agent|login|api|roundtrip|agents|metric|running|restarts|state|stats|logs|down}" >&2; exit 2 ;;
esac
