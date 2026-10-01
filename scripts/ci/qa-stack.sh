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
#                                   template, 3 if it predates it (the file is absent
#                                   at the tag); 1 for anything else, e.g. GitHub
#                                   unreachable — never read that as "predates"
#   qa-stack.sh wait-agent          wait until the server reports >= 1 connected agent
#   qa-stack.sh login               (re)create the admin session cookie
#   qa-stack.sh api <METHOD> <path> [json-body]   authenticated HTTPS call, body to stdout
#   qa-stack.sh roundtrip <plugin> <action> <key> [polls]
#                                   dispatch a command, print the agent's `<key>|` value
#   qa-stack.sh agents              connected agents, one `<agent_id> <agent_version>` per line
#   qa-stack.sh metric <server|gateway> <name>    print a metric's value (0 if the
#                                   family is absent); exit 1, printing nothing, if
#                                   /metrics cannot be fetched after one retry
#   qa-stack.sh wait-metric <server|gateway> <name> <min> <seconds>
#                                   poll until the metric is >= <min>; print it, or fail
#   qa-stack.sh running             how many of the four services are in state "running"
#   qa-stack.sh restarts            total restart count across the four services
#   qa-stack.sh state               one line: <service>=<status>/<restarts> for each
#   qa-stack.sh check-stable        print `state`; fail, naming the service, unless all
#                                   four are running with a restart count of 0
#   qa-stack.sh crash-check         grep each service's log for crash signatures
#                                   (not postgres'); fail naming the service
#   qa-stack.sh stats               one line of per-service memory usage
#   qa-stack.sh mem-growth <first> <last>
#                                   given two `stats` lines, print each service whose
#                                   memory more than doubled (always exits 0)
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
#
# Time budget. Every wait is driven by a $SECONDS deadline, so it ends within
# its budget plus ONE probe (an iteration that started just before the
# deadline), never "N iterations x however long each probe took". Ceilings,
# which the job timeouts in .github/workflows/pre-release.yml are sized from:
#   fetch one tagged file   <= 3 x 20s (--retry 2) + backoff        ~ 65s
#   pull                    <= 3 x 120s + 10s + 20s sleeps          = 390s
#   compose up -d           <= UP_SECS = 420s per call. `up -d server gateway`
#                           waits on two healthchecks in turn: Postgres
#                           (start_period 10s + 12 x 5s = 70s to be declared
#                           unhealthy), then the server, which the gateway
#                           depends on (10s + 30 x 10s = 310s). 380s lets
#                           compose report its own verdict; 420s is that
#                           plus margin. Those sums count interval x retries
#                           only: a probe that hangs to its own timeout (psql
#                           5s, the server's 3s) adds that per retry, so a
#                           hung stack can outlast 420s before compose
#                           decides. The 420s bound then fires first; the
#                           run still fails, bounded, after dump_stack.
#   wait_server             <= 180s + one probe (cp + 10s curl + 3s) ~ 195s
#   wait_gateway            <= 180s + one probe (5s curl + 3s)      ~ 190s
#   wait_agent              <= 180s + one metric read (<= 3 x 30s)  = 270s
#   login / one api call    <= 30s
#   `up`      = 2 fetches + pull + 2 x up -d + the three waits + login
#               + token                                             ~ 2080s (35 min)
#   `upgrade` = the same without the agent's up -d and the token    ~ 1630s (27 min)
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
WAIT_SECS=180
UP_SECS=420
COMPOSE=(docker compose -p "$PROJECT" --env-file "$ENV_FILE" -f "$COMPOSE_FILE" -f "$OVERRIDE")

log() { printf '[qa-stack] %s\n' "$*" >&2; }
die() { printf '::error::qa-stack: %s\n' "$*" >&2; exit 1; }

compose() { "${COMPOSE[@]}" "$@"; }

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
#   Anything else (DNS, network, TLS, 5xx after retries) DIES with exit 1: an
#   unreachable GitHub must never read as "this release has no such file".
fetch_tag_file() {
  local ver="$1" path="$2" out="$3" url code rc=0
  url="https://raw.githubusercontent.com/${QA_REPO}/v${ver}/${path}"
  code="$(curl -sSL --proto '=https' --max-time 20 --retry 2 \
            -o "$out.part" -w '%{http_code}' "$url")" || rc=$?
  [[ "$rc" -eq 0 ]] || { rm -f "$out.part"; die "could not fetch $url (curl exit $rc)"; }
  case "$code" in
    200) mv "$out.part" "$out" ;;
    404) rm -f "$out.part"; return 3 ;;
    *)   rm -f "$out.part"; die "fetching $url returned HTTP $code" ;;
  esac
}

# Exit 3 — not 1 — for "predates": 1 is what `die` (and so every fetch
# failure) exits with, and the upgrade job turns "predates" into a NOT TESTED
# that still passes. Sharing a code let a GitHub outage report green.
cmd_has_stack() {
  local ver="${1:?version required}" rc=0
  check_version "$ver"
  mkdir -p "$STATE"
  fetch_tag_file "$ver" "$TEMPLATE_PATH" "$STATE/probe-template.yml" || rc=$?
  rm -f "$STATE/probe-template.yml"
  case "$rc" in
    0) log "v${ver} ships $TEMPLATE_PATH"; return 0 ;;
    3) log "v${ver} predates $TEMPLATE_PATH"; exit 3 ;;
    *) die "has-stack: unexpected status $rc probing v${ver}" ;;
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

  # Exactly one: with two different paths, which one the gateway reads is
  # not ours to guess.
  local targets n
  # Distinct paths: the same path named twice (a volume and a comment) is
  # still one target.
  targets="$(grep -oE '/opt/yuzu_gw/releases/[^/:[:space:]]+/sys\.config' "$tagged" | sort -u || true)"
  n="$(printf '%s' "$targets" | grep -c . || true)"
  [[ "$n" -eq 1 ]] \
    || die "v${ver}'s template names $n /opt/yuzu_gw/releases/<vsn>/sys.config paths, expected exactly one: $(printf '%s' "$targets" | tr '\n' ' ')"
  target="$targets"
  log "gateway sys.config: v${ver}, mounted at $target"

  drift="$STATE/template-drift-v${ver}.diff"
  rc=0
  diff -u --label "v${ver}/$TEMPLATE_PATH" --label "checkout/$TEMPLATE_PATH" \
    "$tagged" "$COMPOSE_FILE" > "$drift" || rc=$?
  [[ "$rc" -le 1 ]] || die "could not compare v${ver}'s template with $COMPOSE_FILE"
  if [[ "$rc" -eq 1 ]]; then
    local n
    # Every +/- line after the two ---/+++ header lines (a changed line may
    # itself start with - or +, so a pattern excluding those would undercount).
    n="$(tail -n +3 "$drift" | grep -c '^[-+]' || true)"
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
    timeout 120 "${COMPOSE[@]}" pull -q && return 0
    log "compose pull failed or took over 120s (attempt $n/3)"
    [[ "$n" -lt 3 ]] && sleep $((n * 10))
  done
  die "compose pull failed 3 times"
}

up() {  # up [SERVICE...]
  timeout "$UP_SECS" "${COMPOSE[@]}" up -d "$@" \
    || { dump_stack; die "compose up -d $* failed or took over ${UP_SECS}s"; }
}

# Origin is the stack's own origin: cookie-authenticated mutations are
# same-site-checked (Origin/Referer vs Host), and a script sends neither.
curl_tls() { curl -sS --max-time 30 --cacert "$STATE/ca.pem" -H "Origin: $BASE_URL" "$@"; }

# The waits below loop until a $SECONDS deadline (see "Time budget" above).
# The probe's own curl is capped at 10s (a later --max-time overrides
# curl_tls's 30s), so one probe cannot eat the budget.
wait_server() {
  local end=$((SECONDS + WAIT_SECS))
  log "waiting for the server (HTTPS /livez, verified against the install CA)"
  while :; do
    if compose cp server:/etc/yuzu/certs/default-ca.pem "$STATE/ca.pem" >/dev/null 2>&1 \
       && [[ "$(curl_tls --max-time 10 -o /dev/null -w '%{http_code}' "$BASE_URL/livez" 2>/dev/null)" == "200" ]]; then
      log "server is live"; return 0
    fi
    [[ "$SECONDS" -lt "$end" ]] || break
    sleep 3
  done
  dump_stack
  die "server did not become live over HTTPS within ${WAIT_SECS}s"
}

wait_gateway() {
  local end=$((SECONDS + WAIT_SECS))
  log "waiting for the gateway (/readyz)"
  while :; do
    curl -sf --max-time 5 http://127.0.0.1:8081/readyz 2>/dev/null | grep -q '"ready"' \
      && { log "gateway is ready"; return 0; }
    [[ "$SECONDS" -lt "$end" ]] || break
    sleep 3
  done
  dump_stack
  die "gateway did not report ready within ${WAIT_SECS}s"
}

login() {
  local code
  # The password goes to curl on stdin (password@-), never on its argv, where
  # any process on the runner could read it. get_env's trailing newline is
  # stripped: curl encodes the whole stream.
  code="$(get_env QA_ADMIN_PASSWORD | tr -d '\n' | curl_tls -c "$STATE/cookies.txt" -o /dev/null -w '%{http_code}' \
    --data-urlencode "username=qaadmin" \
    --data-urlencode "password@-" \
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

# fetch_metrics SRC: print SRC's /metrics text; non-zero (with the reason on
# stderr) unless it answered HTTP 200.
fetch_metrics() {
  local src="$1" body code
  body="$(mktemp)"
  if [[ "$src" == server ]]; then
    code="$(curl_tls -b "$STATE/cookies.txt" -o "$body" -w '%{http_code}' "$BASE_URL/metrics" 2>/dev/null)" \
      || code="curl exit $?"
  else
    code="$(curl -s --max-time 10 -o "$body" -w '%{http_code}' http://127.0.0.1:9568/metrics 2>/dev/null)" \
      || code="curl exit $?"
  fi
  if [[ "$code" == 200 ]]; then
    cat "$body"; rm -f "$body"; return 0
  fi
  rm -f "$body"
  log "GET $src /metrics: ${code}"
  return 1
}

# A failed fetch (timeout, 5xx, or a 401/redirect once the session cookie has
# expired) is NOT a zero: that turned one slow scrape into "0 agents" and
# failed a whole soak sample for the wrong reason. Re-login (server) and retry
# once; if it still fails, say so and exit 1 with nothing on stdout.
metric() {  # metric server|gateway NAME
  local src="$1" name="$2" text
  [[ "$src" == server || "$src" == gateway ]] || die "metric: source must be server or gateway, not '$src'"
  if ! text="$(fetch_metrics "$src")"; then
    if [[ "$src" == server ]]; then
      ( login ) >/dev/null 2>&1 || log "re-login before the retry failed"
    fi
    text="$(fetch_metrics "$src")" || { log "metric fetch failed: $src $name"; return 1; }
  fi
  # Sum every series of the family (labelled or not); 0 when absent.
  printf '%s\n' "$text" | awk -v n="$name" '
    $1 == n || index($1, n "{") == 1 { s += $NF; f = 1 }
    END { if (f) printf "%d\n", s; else print 0 }'
}

# wait_metric SRC NAME MIN SECONDS: poll every 2s. The gateway's gauges are set
# on a timer (yuzu_gw_gauge, telemetry_gauge_interval_ms, 10s by default), so a
# single read straight after a change can still show the previous value.
wait_metric() {
  local src="$1" name="$2" min="$3" secs="$4" v=0 end
  [[ "$min" =~ ^[0-9]+$ && "$secs" =~ ^[0-9]+$ ]] || die "wait-metric: bad arguments"
  end=$((SECONDS + secs))
  while :; do
    if v="$(metric "$src" "$name")"; then
      [[ "$v" -ge "$min" ]] && { echo "$v"; return 0; }
    else
      v="(metric fetch failed)"
    fi
    [[ "$SECONDS" -ge "$end" ]] && break
    sleep 2
  done
  log "$src $name = $v after ${secs}s, wanted >= $min"
  echo "$v"
  return 1
}

# The CONNECTED gauge, not yuzu_agents_registered_total: that counter never
# goes down, so after the first registration it stays >= 1 through a
# disconnect, a crash loop or an upgrade that never reconnects.
wait_agent() {
  log "waiting for an agent to connect"
  local c=0 end=$((SECONDS + WAIT_SECS))
  while :; do
    if c="$(metric server yuzu_agents_connected)"; then
      [[ "$c" -ge 1 ]] && { log "$c agent(s) connected"; return 0; }
    else
      c="(metric fetch failed)"
    fi
    [[ "$SECONDS" -lt "$end" ]] || break
    sleep 3
  done
  compose logs --no-color --tail 80 agent gateway >&2 || true
  die "no agent connected within ${WAIT_SECS}s (last reading: $c)"
}

cmd_agents() {
  api GET /api/agents | python3 -c '
import sys, json
for a in json.load(sys.stdin):
    print(a.get("agent_id", ""), a.get("agent_version", ""))'
}

# roundtrip PLUGIN ACTION KEY [POLLS]: dispatch PLUGIN.ACTION and wait up to
# POLLS x 2 seconds (a deadline, polling every 2s) for a response line
# `KEY|value`; print value. A rejection such as `plugin not found: <name>` has
# no such line and fails.
roundtrip() {
  local plugin="$1" action="$2" key="$3" polls="${4:-20}" resp id out end
  [[ "$plugin" =~ ^[a-z_]+$ && "$action" =~ ^[a-z_]+$ && "$key" =~ ^[a-z_]+$ && "$polls" =~ ^[0-9]+$ ]] \
    || die "roundtrip: bad arguments"
  resp="$(api POST /api/command "{\"plugin\":\"$plugin\",\"action\":\"$action\"}" 2>&1)" || true
  id="$(printf '%s' "$resp" | python3 -c 'import sys,json; print(json.load(sys.stdin).get("command_id",""))' 2>/dev/null || true)"
  [[ -n "$id" ]] || { log "dispatching $plugin.$action returned no command_id: $resp"; return 1; }
  end=$((SECONDS + polls * 2))
  while :; do
    sleep 2
    out="$(api GET "/api/responses/$id" 2>/dev/null | KEY="$key" python3 -c '
import os, sys, json
k = os.environ["KEY"] + "|"
for r in json.load(sys.stdin).get("responses", []):
    for line in r.get("output", "").splitlines():
        if line.startswith(k):
            print(line[len(k):]); sys.exit(0)' 2>/dev/null || true)"
    [[ -n "$out" ]] && { printf '%s\n' "$out"; return 0; }
    [[ "$SECONDS" -lt "$end" ]] || break
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

# A restart before the check is a crash too: a baseline that absorbs earlier
# restarts (the soak used to compare against whatever count it started with)
# hides a crash loop during bring-up.
cmd_check_stable() {
  local s st out="" bad=()
  for s in "${SERVICES[@]}"; do
    st="$(svc_field "$s" '{{.State.Status}}/{{.RestartCount}}')"
    out+="$s=$st "
    [[ "$st" == running/0 ]] || bad+=("$s=$st")
  done
  echo "${out% }"
  [[ "${#bad[@]}" -eq 0 ]] \
    || die "not stable: ${bad[*]} (every service must be running with a restart count of 0)"
}

# Postgres is excluded: its own vocabulary (PANIC is a log level) is not ours
# to police, and a Postgres crash already shows as a restart.
#
# The gateway is an OTP release. A crashed process, or a supervisor restarting
# a child, is logged while the node itself stays up and never restarts. The
# reference sys.config's logger template ([time, " [", level, "] ", pid, " ",
# msg]) has NO legacy report header, so OTP 28 writes those as
#   ... [error] <0.85.0> crasher: initial call: ...
#   ... [error] <0.84.0> Supervisor: {local,x}. Context: child_terminated. Reason: ...
# (captured from the real formatter), not "=CRASH REPORT====". The legacy
# spellings stay for any other template. A bare "Supervisor:" must NOT match:
# every child start at boot logs "Supervisor: {local,x}. Started: ...".
GW_CRASH_PAT='\] <[0-9.]+> crasher: |crasher: initial call'
GW_CRASH_PAT+='|[Ss]upervisor: .*[Cc]ontext: (child_terminated|start_error|shutdown_error)|Reason: reached_max_restart_intensity'
GW_CRASH_PAT+='|CRASH REPORT|crash_report|SUPERVISOR REPORT|supervisor_report'
cmd_crash_check() {
  local s pat log hits found=()
  for s in "${SERVICES[@]}"; do
    [[ "$s" == postgres ]] && continue
    pat='segfault|ASAN|UBSAN|panic|SIGABRT|core dump'
    [[ "$s" == gateway ]] && pat+="|$GW_CRASH_PAT"
    log="$STATE/crash-check-$s.log"
    compose logs --no-color --no-log-prefix "$s" > "$log" 2>&1 \
      || die "crash-check: could not read the $s logs"
    hits="$(grep -iE "$pat" "$log" || true)"   # -i: "Supervisor:"/"Context:" too
    if [[ -n "$hits" ]]; then
      printf '%s\n' "$hits" | head -n 20 | sed "s/^/[$s] /" >&2
      found+=("$s")
    fi
  done
  [[ "${#found[@]}" -eq 0 ]] || die "crash signatures in the logs of: ${found[*]}"
  log "no crash signatures in the server, gateway or agent logs"
}

cmd_stats() {
  local s id out=""
  for s in "${SERVICES[@]}"; do
    id="$(compose ps -q "$s" 2>/dev/null || true)"
    out+="$s=$( [[ -n "$id" ]] && docker stats --no-stream --format '{{.MemUsage}}' "$id" 2>/dev/null | cut -d/ -f1 | tr -d ' ' || echo '?') "
  done
  echo "$out"
}

# mem-growth FIRST LAST: each is a `stats` line (svc=12.3MiB ...). Informational.
cmd_mem_growth() {
  awk -v a="${1:-}" -v b="${2:-}" '
    function bytes(v,   n, u) {
      if (!match(v, /^[0-9.]+/)) return -1
      n = substr(v, 1, RLENGTH); u = substr(v, RLENGTH + 1)
      if (u == "B") return n
      if (u == "KiB") return n * 1024
      if (u == "MiB") return n * 1048576
      if (u == "GiB") return n * 1073741824
      if (u == "kB") return n * 1000
      if (u == "MB") return n * 1000000
      if (u == "GB") return n * 1000000000
      return -1
    }
    BEGIN {
      na = split(a, A, " ")
      for (i = 1; i <= na; i++) { split(A[i], kv, "="); first[kv[1]] = kv[2] }
      nb = split(b, B, " ")
      for (i = 1; i <= nb; i++) {
        split(B[i], kv, "="); s = kv[1]
        if (!(s in first)) continue
        x = bytes(first[s]); y = bytes(kv[2])
        if (x > 0 && y > 2 * x) printf "%s %s -> %s\n", s, first[s], kv[2]
      }
    }'
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
  wait-metric) shift; wait_metric "$@" ;;
  running)    cmd_running ;;
  restarts)   cmd_restarts ;;
  state)      cmd_state ;;
  check-stable) cmd_check_stable ;;
  crash-check) cmd_crash_check ;;
  stats)      cmd_stats ;;
  mem-growth) shift; cmd_mem_growth "$@" ;;
  logs)       shift; { compose ps -a; compose logs --no-color; } > "${1:?file required}" 2>&1 || true ;;
  down)       compose down -v --remove-orphans || true ;;
  *) echo "usage: $0 {up|upgrade|has-stack|wait-agent|login|api|roundtrip|agents|metric|wait-metric|running|restarts|state|check-stable|crash-check|stats|mem-growth|logs|down}" >&2; exit 2 ;;
esac
