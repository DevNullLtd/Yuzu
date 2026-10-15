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
  DOCKER_BUILDKIT=1 docker build -t "$(img gateway)" \
    -f deploy/docker/Dockerfile.gateway.chisel .
  DOCKER_BUILDKIT=1 docker build -t "$(img_pg)" \
    -f deploy/docker/Dockerfile.postgres       .
  ok "Built $(img server), $(img gateway), $(img agent), $(img_pg)"
}

images_present_locally() {
  docker image inspect "$(img server)" "$(img gateway)" "$(img agent)" "$(img_pg)" >/dev/null 2>&1
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
  curl -fsS "http://localhost:8080/metrics" 2>/dev/null \
    | awk '/^yuzu_agents_connected /{print $2; exit}' || echo 0
}

# ── Subcommands ────────────────────────────────────────────────────────────
cmd_start() {
  echo ""
  echo "╔══════════════════════════════════════════════════╗"
  echo "║  Yuzu — Cedar & Vale demo stack                   ║"
  echo "╚══════════════════════════════════════════════════╝"
  info "version=$YUZU_VERSION  agents=$DEMO_AGENT_COUNT  registry=$REGISTRY  arch=$TRIPLET"

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
    for p in 8080 50051; do
      if command -v nc >/dev/null 2>&1 && nc -z -w1 localhost "$p" >/dev/null 2>&1; then
        fail "Port $p is already in use — another stack (viz-UAT / start-UAT) is running. Stop it first."
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
  wait_for_url "http://localhost:8080/login"    "server dashboard" 120
  wait_for_url "http://localhost:8081/healthz"  "gateway health"   90

  # Phase 2: login + issue a multi-use enrollment token.
  info "Issuing enrollment token..."
  curl -fsS -c "$DEMO_DIR/cookies.txt" "http://localhost:8080/login" \
    -d "username=${ADMIN_USER}&password=${ADMIN_PASS}" -o /dev/null
  local token_html token
  token_html="$(curl -fsS -b "$DEMO_DIR/cookies.txt" \
    -X POST "http://localhost:8080/api/settings/enrollment-tokens" \
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

  info "Waiting for agent registration..."
  local waited=0 reg=0
  while [ "$waited" -lt 120 ]; do
    reg="$(agents_connected)"; reg="${reg:-0}"
    if awk "BEGIN { exit !(${reg%.*} >= $DEMO_AGENT_COUNT) }"; then break; fi
    sleep 3; waited=$((waited + 3))
  done
  reg="$(agents_connected)"; reg="${reg:-0}"
  if awk "BEGIN { exit !(${reg%.*} >= $DEMO_AGENT_COUNT) }"; then
    ok "$reg / $DEMO_AGENT_COUNT agents registered"
  else
    warn "$reg / $DEMO_AGENT_COUNT agents registered after 120s — check 'start-demo.sh status'"
  fi

  echo ""
  echo "╔══════════════════════════════════════════════════╗"
  echo "║  Cedar & Vale demo is up                          ║"
  echo "╚══════════════════════════════════════════════════╝"
  echo "  Dashboard:  http://localhost:8080      ($ADMIN_USER / $ADMIN_PASS)"
  echo "  REST API:   http://localhost:8080/api/v1/"
  echo "  Gateway:    http://localhost:8081/healthz | http://localhost:9568/metrics"
  echo "  Join more:  point a native yuzu-agent at  <host>:50051  with token in"
  echo "              $DEMO_DIR/enrollment-token"
  echo ""
}

cmd_stop()    { info "Stopping demo stack..."; if [ "${KEEP:-0}" = "1" ]; then dc down --remove-orphans; else dc down -v --remove-orphans; fi; ok "Stopped"; }
cmd_status()  { dc ps; echo; if curl -fsS http://localhost:8080/readyz >/dev/null 2>&1; then printf "agents connected: "; agents_connected; echo; else warn "server not reachable on http://localhost:8080 — is the stack up?"; fi; }
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
    -h|--help) sed -n '2,30p' "$0" | sed 's/^# \?//'; exit 0 ;;
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
