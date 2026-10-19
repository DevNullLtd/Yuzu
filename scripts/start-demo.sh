#!/usr/bin/env bash
# start-demo.sh — Cedar & Vale demo stack launcher
#
# Stands up the repeatable, release-pinned Yuzu sales demo: a chiselled
# Ubuntu 26.04 server + gateway and a fleet of the smallest chiselled
# Ubuntu 26.04 agents (default 10) as clients.
#
# This stack is intentionally pinned to ${YUZU_VERSION}. In steady state it
# PULLS immutable, released GHCR images, so the demo only ever changes when you
# point it at a new release. Until those images are published (agent image +
# multi-arch + chiselled — see docs/demo-environment.md), use --build to build
# them locally from the current tree and tag them as that version.
#
# Gateway image: the gateway config this mounts (demo-gateway-sys.config) uses the
# {yuzu_gw, grpc_listeners} shape, so the pinned gateway image must be from the
# first release containing the yuzu_gw grpc_listeners shape
# (GATEWAY_GRPC_LISTENERS_MIN_VERSION below). An older image binds no listener and
# still reports healthy. The launcher therefore (1) refuses an older pinned image
# before starting anything (unless it is a local --build of this tree), (2) checks
# the started gateway is really listening on its agent and management ports, and
# (3) exits non-zero, without the "demo is up" banner, if the agents do not all
# register in time.
#
# Usage:
#   bash scripts/start-demo.sh [start] [--build|--pull] [--agents N] [--version X.Y.Z] [--keep]
#   bash scripts/start-demo.sh status
#   bash scripts/start-demo.sh stop [--keep]
#   bash scripts/start-demo.sh logs [service]
#   bash scripts/start-demo.sh token        # reprint the current enrollment token
#
# Flags:
#   --build         Build the chiselled images locally and tag them as the
#                   pinned version (bootstrap; required before images publish).
#   --pull          Force `docker compose pull` of the pinned images.
#   --agents N      Number of agent clients (default 10; env DEMO_AGENT_COUNT).
#   --version X.Y.Z Image version to pin (default: project version; env YUZU_VERSION).
#   --keep          Do not wipe state on start / stop (default is a clean start).
#
# Environment:
#   DEMO_HTTP_PORT            host port for the dashboard + REST API (default 8080)
#   DEMO_GATEWAY_AGENT_PORT   host port for the gateway's agent gRPC  (default 50051)
#   DEMO_GATEWAY_HEALTH_PORT  host port for the gateway /healthz      (default 8081)
#   DEMO_GATEWAY_METRICS_PORT host port for the gateway /metrics      (default 9568)
#   DEMO_REGISTER_TIMEOUT     seconds to wait for every agent to register (default 120)

set -euo pipefail

# ── Resolve repo + paths ──────────────────────────────────────────────────
REPO_ROOT="$(git rev-parse --show-toplevel 2>/dev/null || true)"
[ -n "$REPO_ROOT" ] || { echo "error: not inside the Yuzu git repo" >&2; exit 1; }
cd "$REPO_ROOT"

COMPOSE_FILE="deploy/docker/docker-compose.demo.yml"
PROJECT="yuzu-demo"
DEMO_DIR="${YUZU_DEMO_DIR:-/tmp/yuzu-demo}"

# ── Defaults / config ─────────────────────────────────────────────────────
ADMIN_USER="admin"
ADMIN_PASS="adminpassword1"

# Version: explicit env wins, else parse meson.build project() version.
default_version() {
  grep -m1 -oE "version: *'[0-9]+\.[0-9]+\.[0-9]+" meson.build 2>/dev/null \
    | grep -oE "[0-9]+\.[0-9]+\.[0-9]+" || echo "0.12.0"
}
YUZU_VERSION="${YUZU_VERSION:-$(default_version)}"
DEMO_AGENT_COUNT="${DEMO_AGENT_COUNT:-10}"
DEMO_REGISTER_TIMEOUT="${DEMO_REGISTER_TIMEOUT:-120}"
# Published host ports. The defaults are the demo's documented topology; override
# them only to run the demo beside another rig that already holds them.
DEMO_HTTP_PORT="${DEMO_HTTP_PORT:-8080}"
DEMO_GATEWAY_AGENT_PORT="${DEMO_GATEWAY_AGENT_PORT:-50051}"
DEMO_GATEWAY_HEALTH_PORT="${DEMO_GATEWAY_HEALTH_PORT:-8081}"
DEMO_GATEWAY_METRICS_PORT="${DEMO_GATEWAY_METRICS_PORT:-9568}"
SERVER_URL="http://localhost:${DEMO_HTTP_PORT}"

# First release whose gateway image understands the {yuzu_gw, grpc_listeners}
# config that demo-gateway-sys.config uses. An older gateway given that config
# binds no listener, yet /healthz and /readyz still answer 200, so the demo looks
# up while no agent can ever connect (docs/user-manual/upgrading.md: the image
# and its sys.config are an atomic pair).
#
# Why 0.15.0: the latest release is v0.14.1 (CHANGELOG.md, git tags), whose
# gateway still reads {grpcbox, [{servers, ...}]}. The grpc_listeners move is a
# BREAKING gateway-config change, which this pre-1.0 project ships in a minor
# release, and docs/user-manual/upgrading.md files it under "0.15.x (next)". So
# a 0.14.x patch release does not carry it and must be refused. If the change
# ever ships under a different number, change this constant to that release.
# A pre-release of the floor (0.15.0-rc1) is judged by its X.Y.Z core and
# passes: release candidates are cut from the tree that carries the change.
GATEWAY_GRPC_LISTENERS_MIN_VERSION="0.15.0"
# Label --build stamps on a gateway image built from a tree whose gateway reads
# grpc_listeners. It lets a local bootstrap build tagged with a pre-floor version
# (the default tag is meson.build's version, e.g. 0.14.1) pass the check above.
GATEWAY_CONFIG_SHAPE_LABEL="io.github.devnullltd.yuzu.gateway-config-shape"
GATEWAY_CONFIG_SHAPE="grpc_listeners"

# Registry owner: derive from origin remote (lowercased), default devnullltd.
derive_owner() {
  local url owner
  url="$(git remote get-url origin 2>/dev/null || true)"
  owner="$(printf '%s' "$url" | sed -E 's|.*github\.com[:/]([^/]+)/.*|\1|' | tr '[:upper:]' '[:lower:]')"
  [ -n "$owner" ] && [ "$owner" != "$url" ] && printf '%s' "$owner" || printf 'devnullltd'
}
REGISTRY="${YUZU_REGISTRY:-ghcr.io/$(derive_owner)}"

# Host arch -> vcpkg triplet (for --build).
case "$(uname -m)" in
  arm64|aarch64) TRIPLET="arm64-linux" ;;
  x86_64|amd64)  TRIPLET="x64-linux" ;;
  *) TRIPLET="x64-linux" ;;
esac

# ── Pretty output ─────────────────────────────────────────────────────────
if [ -t 1 ]; then C_G=$'\e[32m'; C_B=$'\e[34m'; C_Y=$'\e[33m'; C_R=$'\e[31m'; C_0=$'\e[0m'; else C_G=; C_B=; C_Y=; C_R=; C_0=; fi
ok()   { printf "${C_G}[ok]${C_0} %s\n" "$*"; }
info() { printf "${C_B}[..]${C_0} %s\n" "$*"; }
warn() { printf "${C_Y}[!!]${C_0} %s\n" "$*"; }
fail() { printf "${C_R}[xx]${C_0} %s\n" "$*"; }

# ── compose wrapper: always pass the required env so interpolation succeeds ─
# YUZU_ENROLLMENT_TOKEN is "stub" until phase 2 issues the real one; compose
# parses every service (incl. agent) on any subcommand, so it must be set even
# for `up server gateway`, `down`, and `ps`.
dc() {
  DEMO_SERVER_CONFIG="$DEMO_DIR/yuzu-server.cfg" \
  DEMO_GATEWAY_CONFIG="$REPO_ROOT/deploy/docker/demo-gateway-sys.config" \
  YUZU_VERSION="$YUZU_VERSION" \
  YUZU_REGISTRY="$REGISTRY" \
  DEMO_AGENT_COUNT="$DEMO_AGENT_COUNT" \
  YUZU_ENROLLMENT_TOKEN="${YUZU_ENROLLMENT_TOKEN:-stub}" \
  DEMO_HTTP_PORT="$DEMO_HTTP_PORT" \
  DEMO_GATEWAY_AGENT_PORT="$DEMO_GATEWAY_AGENT_PORT" \
  DEMO_GATEWAY_HEALTH_PORT="$DEMO_GATEWAY_HEALTH_PORT" \
  DEMO_GATEWAY_METRICS_PORT="$DEMO_GATEWAY_METRICS_PORT" \
    docker compose -p "$PROJECT" -f "$COMPOSE_FILE" "$@"
}

# Chiselled demo images are published under a -chisel repo suffix so they never
# collide with the debian/alpine production images of the same version (whose
# compose healthchecks assume a bash userland the chiselled images don't have).
img() { printf '%s/yuzu-%s-chisel:%s' "$REGISTRY" "$1" "$YUZU_VERSION"; }
# yuzu-postgres has no -chisel variant — the demo runs the same release-pinned
# substrate image production composes use (#1318).
img_pg() { printf '%s/yuzu-postgres:%s' "$REGISTRY" "$YUZU_VERSION"; }

# ── Image acquisition ──────────────────────────────────────────────────────
build_images() {
  info "Building chiselled Ubuntu 26.04 images ($TRIPLET) tagged $YUZU_VERSION..."
  DOCKER_BUILDKIT=1 docker build -t "$(img server)"  --build-arg TRIPLET="$TRIPLET" \
    -f deploy/docker/Dockerfile.server.chisel  .
  DOCKER_BUILDKIT=1 docker build -t "$(img agent)"   --build-arg TRIPLET="$TRIPLET" \
    -f deploy/docker/Dockerfile.agent.chisel   .
  # Stamp the config-shape label only when this tree's gateway really reads
  # grpc_listeners, so the label is evidence rather than an assertion.
  local gw_label=()
  if grep -q "grpc_listeners" gateway/apps/yuzu_gw/src/yuzu_gw_app.erl 2>/dev/null; then
    gw_label=(--label "${GATEWAY_CONFIG_SHAPE_LABEL}=${GATEWAY_CONFIG_SHAPE}")
  fi
  DOCKER_BUILDKIT=1 docker build -t "$(img gateway)" ${gw_label[@]+"${gw_label[@]}"} \
    -f deploy/docker/Dockerfile.gateway.chisel .
  DOCKER_BUILDKIT=1 docker build -t "$(img_pg)" \
    -f deploy/docker/Dockerfile.postgres       .
  ok "Built $(img server), $(img gateway), $(img agent), $(img_pg)"
}

images_present_locally() {
  docker image inspect "$(img server)" "$(img gateway)" "$(img agent)" "$(img_pg)" >/dev/null 2>&1
}

# ── Gateway image vs. mounted config (refuse a mismatched pair up front) ───
# semver_core X.Y.Z[-pre][+build] (optional leading v) -> "X Y Z"; non-zero if
# the string is not a release version (e.g. "latest", "local").
semver_core() {
  local v="${1#v}"
  v="${v%%+*}"; v="${v%%-*}"
  [[ "$v" =~ ^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)$ ]] || return 1
  printf '%s %s %s' "${BASH_REMATCH[1]}" "${BASH_REMATCH[2]}" "${BASH_REMATCH[3]}"
}

# version_ge A B: true when A's X.Y.Z core >= B's, compared numerically field by
# field (so 0.15.0 > 0.9.9 and 0.14.10 > 0.14.9). Returns 2 if either is not a
# release version.
version_ge() {
  local a b a1 a2 a3 b1 b2 b3
  a="$(semver_core "$1")" || return 2
  b="$(semver_core "$2")" || return 2
  read -r a1 a2 a3 <<<"$a"; read -r b1 b2 b3 <<<"$b"
  (( 10#$a1 != 10#$b1 )) && { (( 10#$a1 > 10#$b1 )); return; }
  (( 10#$a2 != 10#$b2 )) && { (( 10#$a2 > 10#$b2 )); return; }
  (( 10#$a3 >= 10#$b3 ))
}

refuse_old_gateway() {
  fail "The pinned gateway image $(img gateway) predates the gateway config this demo mounts."
  fail "  deploy/docker/demo-gateway-sys.config uses {yuzu_gw, grpc_listeners}, first understood by"
  fail "  release ${GATEWAY_GRPC_LISTENERS_MIN_VERSION}. A ${YUZU_VERSION} gateway would bind no listener while still"
  fail "  reporting healthy, so no agent could connect. Nothing has been started. Either:"
  fail "    bash scripts/start-demo.sh --build          # build every image from this tree"
  fail "  or pin a release that carries the new config:"
  fail "    YUZU_VERSION=${GATEWAY_GRPC_LISTENERS_MIN_VERSION} bash scripts/start-demo.sh   (or --version X.Y.Z, >= ${GATEWAY_GRPC_LISTENERS_MIN_VERSION})"
  exit 1
}

# Runs before any image is pulled or any container started, in auto and pull
# mode (--build produces a matching image by construction).
check_gateway_image_version() {
  local mode="${IMAGE_MODE:-auto}" shape rc=0
  [ "$mode" = build ] && return 0
  if [ "$mode" = auto ] && docker image inspect "$(img gateway)" >/dev/null 2>&1; then
    shape="$(docker image inspect -f "{{ index .Config.Labels \"${GATEWAY_CONFIG_SHAPE_LABEL}\" }}" "$(img gateway)" 2>/dev/null || true)"
    if [ "$shape" = "$GATEWAY_CONFIG_SHAPE" ]; then
      ok "Local gateway image $(img gateway) was built from a tree that reads grpc_listeners"
      return 0
    fi
  fi
  version_ge "$YUZU_VERSION" "$GATEWAY_GRPC_LISTENERS_MIN_VERSION" || rc=$?
  case "$rc" in
    0) return 0 ;;
    1) refuse_old_gateway ;;
    *) warn "Cannot tell from version '$YUZU_VERSION' whether the gateway understands grpc_listeners;"
       warn "relying on the listener check after the gateway starts." ;;
  esac
}

# The gateway's own /healthz and /readyz cannot tell an old image that bound no
# listener from a working one, so look at the gateway container's socket table:
# both the agent (50051) and management (50063) listeners must be in LISTEN
# state. /proc/net/tcp{,6} is per network namespace, so this is the container's
# own view; busybox is in every chiselled gateway image (the healthcheck uses it).
gateway_listening() {
  local port_hex
  port_hex="$(printf '%04X' "$1")"
  dc exec -T gateway /bin/busybox cat /proc/net/tcp /proc/net/tcp6 2>/dev/null \
    | awk -v p=":${port_hex}" 'toupper($2) ~ p"$" && $4 == "0A" { found=1 } END { exit !found }'
}

wait_for_gateway_listeners() {
  local waited=0 timeout=30
  info "Checking the gateway is listening on its agent (50051) and management (50063) ports..."
  while [ "$waited" -lt "$timeout" ]; do
    if gateway_listening 50051 && gateway_listening 50063; then
      ok "Gateway is listening on 50051 (agents) and 50063 (management)"
      return 0
    fi
    sleep 2; waited=$((waited + 2))
  done
  fail "The gateway reports healthy but is NOT listening on 50051 and 50063 after ${timeout}s."
  fail "Most likely its image ($(img gateway)) does not understand the {yuzu_gw, grpc_listeners}"
  fail "config this demo mounts. Rebuild with --build, or pin YUZU_VERSION >= ${GATEWAY_GRPC_LISTENERS_MIN_VERSION}."
  fail "Last 30 gateway log lines:"
  dc logs --no-color --tail=30 gateway 2>&1 | sed 's/^/    /' || true
  fail "Stack left running for inspection; remove it with:  bash scripts/start-demo.sh stop"
  exit 1
}

ensure_images() {
  case "${IMAGE_MODE:-auto}" in
    build) build_images ;;
    pull)  info "Pulling pinned images..."; dc pull ;;
    auto)
      if images_present_locally; then
        ok "Using local images for $YUZU_VERSION (pass --build to rebuild, --pull to refresh)"
      else
        info "Pinned images not present locally; pulling..."
        if ! dc pull; then
          fail "Pull failed. The images may not be published yet, or the GHCR"
          fail "packages are private — try 'docker login ghcr.io' (PAT w/ read:packages)."
          fail "Or bootstrap from source with:  bash scripts/start-demo.sh --build"
          exit 1
        fi
      fi
      ;;
  esac
}

# ── Server config (PBKDF2-SHA256 admin hash; same creds every run) ─────────
generate_config() {
  mkdir -p "$DEMO_DIR"; chmod 700 "$DEMO_DIR"
  python3 - "$ADMIN_USER" "$ADMIN_PASS" > "$DEMO_DIR/yuzu-server.cfg" <<'PY'
import hashlib, os, sys
user, password = sys.argv[1], sys.argv[2]
salt = os.urandom(16)
dk = hashlib.pbkdf2_hmac('sha256', password.encode(), salt, 100000, dklen=32)
print(f"{user}:admin:{salt.hex()}:{dk.hex()}")
PY
  chmod 600 "$DEMO_DIR/yuzu-server.cfg"
  ok "Generated server config ($ADMIN_USER / $ADMIN_PASS)"
}

wait_for_url() {
  local url="$1" name="$2" timeout="${3:-90}" waited=0
  info "Waiting for $name ($url)..."
  while [ "$waited" -lt "$timeout" ]; do
    if curl -fsS -o /dev/null "$url" 2>/dev/null; then ok "$name is up"; return 0; fi
    sleep 2; waited=$((waited + 2))
  done
  fail "$name did not come up within ${timeout}s"; return 1
}

agents_connected() {
  # Poll the live gauge (currently-connected agents), NOT the monotonic
  # yuzu_agents_registered_total counter — reconnects/restarts inflate the
  # counter and would make the wait loop report false success.
  curl -fsS "${SERVER_URL}/metrics" 2>/dev/null \
    | awk '/^yuzu_agents_connected /{print $2; exit}' || echo 0
}

# ── Subcommands ────────────────────────────────────────────────────────────
cmd_start() {
  echo ""
  echo "╔══════════════════════════════════════════════════╗"
  echo "║  Yuzu — Cedar & Vale demo stack                   ║"
  echo "╚══════════════════════════════════════════════════╝"
  info "version=$YUZU_VERSION  agents=$DEMO_AGENT_COUNT  registry=$REGISTRY  arch=$TRIPLET"

  check_gateway_image_version
  ensure_images

  if [ "${KEEP:-0}" != "1" ]; then
    info "Clean start: wiping any prior demo state..."
    dc down -v --remove-orphans >/dev/null 2>&1 || true
    # Drop stale cfg/token/cookies so a clean start is reproducible. Guard the
    # wipe to temp-ish paths — YUZU_DEMO_DIR is operator-set; never rm -rf a
    # system dir if it is misconfigured.
    case "$DEMO_DIR" in
      /tmp/*|/private/tmp/*|*/yuzu-demo) rm -rf "$DEMO_DIR" ;;
      *) warn "not auto-wiping non-temp DEMO_DIR=$DEMO_DIR (remove it manually if intended)" ;;
    esac
    # Refuse to start on top of another stack already bound to our host ports.
    for p in "$DEMO_HTTP_PORT" "$DEMO_GATEWAY_AGENT_PORT" "$DEMO_GATEWAY_HEALTH_PORT" "$DEMO_GATEWAY_METRICS_PORT"; do
      if command -v nc >/dev/null 2>&1 && nc -z -w1 localhost "$p" >/dev/null 2>&1; then
        fail "Port $p is already in use — another stack (viz-UAT / start-UAT) is running."
        fail "Stop it first, or move the demo with DEMO_HTTP_PORT / DEMO_GATEWAY_*_PORT (see --help)."
        exit 1
      fi
    done
  fi

  # Regenerate the admin config on a clean start, or when it is missing. Under
  # --keep do NOT regenerate: the server seeds admin from the cfg only on first
  # boot (empty DB), so a fresh random salt would 401 against the retained DB.
  if [ "${KEEP:-0}" != "1" ] || [ ! -f "$DEMO_DIR/yuzu-server.cfg" ]; then
    generate_config
  else
    ok "Reusing existing server config (--keep)"
  fi

  # Phase 1: server + gateway (stub token).
  info "Starting server + gateway..."
  dc up -d server gateway
  wait_for_url "${SERVER_URL}/login"    "server dashboard" 120
  wait_for_url "http://localhost:${DEMO_GATEWAY_HEALTH_PORT}/healthz"  "gateway health"   90
  wait_for_gateway_listeners

  # Phase 2: login + issue a multi-use enrollment token.
  info "Issuing enrollment token..."
  curl -fsS -c "$DEMO_DIR/cookies.txt" "${SERVER_URL}/login" \
    -d "username=${ADMIN_USER}&password=${ADMIN_PASS}" -o /dev/null
  local token_html token
  token_html="$(curl -fsS -b "$DEMO_DIR/cookies.txt" \
    -X POST "${SERVER_URL}/api/settings/enrollment-tokens" \
    -d "label=demo&max_uses=100000&ttl_hours=720")"
  # Prefer the token inside its <code> element; fall back to the first 64-hex run
  # so a stray hex id elsewhere in the HTML can't be mistaken for the token.
  token="$(printf '%s' "$token_html" | grep -oE '<code[^>]*>[a-f0-9]{64}</code>' | grep -oE '[a-f0-9]{64}' | head -1)"
  [ -n "$token" ] || token="$(printf '%s' "$token_html" | grep -oE '[a-f0-9]{64}' | head -1)"
  if [ -z "$token" ]; then
    fail "Could not parse enrollment token from response:"; fail "  $token_html"; exit 1
  fi
  printf '%s\n' "$token" > "$DEMO_DIR/enrollment-token"
  chmod 600 "$DEMO_DIR/enrollment-token" "$DEMO_DIR/cookies.txt" 2>/dev/null || true
  ok "Enrollment token issued"

  # Phase 3: agents (scaled). deploy.replicas honours DEMO_AGENT_COUNT.
  info "Starting $DEMO_AGENT_COUNT agent client(s)..."
  YUZU_ENROLLMENT_TOKEN="$token" dc up -d agent

  info "Waiting up to ${DEMO_REGISTER_TIMEOUT}s for agent registration..."
  local waited=0 reg=0
  while [ "$waited" -lt "$DEMO_REGISTER_TIMEOUT" ]; do
    reg="$(agents_connected)"; reg="${reg:-0}"
    if awk "BEGIN { exit !(${reg%.*} >= $DEMO_AGENT_COUNT) }"; then break; fi
    sleep 3; waited=$((waited + 3))
  done
  reg="$(agents_connected)"; reg="${reg:-0}"
  if awk "BEGIN { exit !(${reg%.*} >= $DEMO_AGENT_COUNT) }"; then
    ok "$reg / $DEMO_AGENT_COUNT agents registered"
  else
    # A demo with no agents is not a demo: fail loudly, never print the banner.
    echo ""
    fail "Only ${reg%.*} / $DEMO_AGENT_COUNT agents registered with the server after ${DEMO_REGISTER_TIMEOUT}s"
    fail "(server gauge yuzu_agents_connected at ${SERVER_URL}/metrics). The demo is NOT up."
    fail "Last 30 gateway log lines:"
    dc logs --no-color --tail=30 gateway 2>&1 | sed 's/^/    /' || true
    fail "Inspect with:  bash scripts/start-demo.sh status | logs agent | logs server"
    fail "Stack left running for inspection; remove it with:  bash scripts/start-demo.sh stop"
    exit 1
  fi

  echo ""
  echo "╔══════════════════════════════════════════════════╗"
  echo "║  Cedar & Vale demo is up                          ║"
  echo "╚══════════════════════════════════════════════════╝"
  echo "  Dashboard:  ${SERVER_URL}      ($ADMIN_USER / $ADMIN_PASS)"
  echo "  REST API:   ${SERVER_URL}/api/v1/"
  echo "  Gateway:    http://localhost:${DEMO_GATEWAY_HEALTH_PORT}/healthz | http://localhost:${DEMO_GATEWAY_METRICS_PORT}/metrics"
  echo "  Join more:  point a native yuzu-agent at  <host>:${DEMO_GATEWAY_AGENT_PORT}  with token in"
  echo "              $DEMO_DIR/enrollment-token"
  echo ""
}

cmd_stop()    { info "Stopping demo stack..."; if [ "${KEEP:-0}" = "1" ]; then dc down --remove-orphans; else dc down -v --remove-orphans; fi; ok "Stopped"; }
cmd_status()  { dc ps; echo; if curl -fsS "${SERVER_URL}/readyz" >/dev/null 2>&1; then printf "agents connected: "; agents_connected; echo; else warn "server not reachable on ${SERVER_URL} — is the stack up?"; fi; }
cmd_logs()    { dc logs --tail=100 -f ${1:-}; }
cmd_token()   { cat "$DEMO_DIR/enrollment-token" 2>/dev/null || { fail "no token yet — run start first"; exit 1; }; }

# ── Arg parsing ────────────────────────────────────────────────────────────
SUB="start"
case "${1:-}" in start|stop|status|logs|token) SUB="$1"; shift ;; esac
LOG_SVC=""
while [ $# -gt 0 ]; do
  case "$1" in
    --build)   IMAGE_MODE="build" ;;
    --pull)    IMAGE_MODE="pull" ;;
    --keep)    KEEP=1 ;;
    --agents)  DEMO_AGENT_COUNT="$2"; shift ;;
    --agents=*) DEMO_AGENT_COUNT="${1#*=}" ;;
    --version) YUZU_VERSION="$2"; shift ;;
    --version=*) YUZU_VERSION="${1#*=}" ;;
    -h|--help) sed -n '2,/^set -euo pipefail/p' "$0" | sed '$d' | sed -E 's/^# ?//'; exit 0 ;;
    *) [ "$SUB" = logs ] && LOG_SVC="$1" || { fail "unknown arg: $1"; exit 1; } ;;
  esac
  shift
done

case "$SUB" in
  start)  cmd_start ;;
  stop)   cmd_stop ;;
  status) cmd_status ;;
  logs)   cmd_logs "$LOG_SVC" ;;
  token)  cmd_token ;;
esac
