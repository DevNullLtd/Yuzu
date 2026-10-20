#!/usr/bin/env bash
# uat-netns.sh — run a command inside a private network + PID namespace so
# several UAT / test rigs can use the SAME fixed ports (8080, 50051, 50063, ...)
# at the same time without colliding with each other or with the host.
#
# The rigs in docs/uat-environment.md all bind 8080 + 50051 on the host, so only
# one can run at once. bubblewrap (`bwrap --unshare-net`) gives each invocation
# its own loopback: 127.0.0.1:8080 inside one rig is unrelated to 127.0.0.1:8080
# inside another, or on the host. `--unshare-pid` additionally hides every other
# rig's processes, so a rig's `stop` (PID records) and its port-free checks can
# only ever see its own stack, and every process in the rig dies when the command
# exits.
#
# THIS IS NOT A SANDBOX. Only the network, the PID table and /tmp/yuzu-uat are
# private. A rig has full read/write access to the host filesystem (--dev-bind), to
# the Docker socket (root-equivalent), and to the shared Postgres below as its
# superuser — so any rig can read or drop any other rig's database. Do not run
# code you do not trust in a rig.
#
# Postgres: published Docker ports live in the HOST namespace and are not
# reachable from a private one, but unix sockets are filesystem objects and cross
# it. One shared container (yuzu-netns-pg-<hash of the state dir>) runs with
# `--network none` — no published port, no bridge address, so it is reachable ONLY
# through its unix socket. Each rig gets its own database (yuzu_<rig>, recreated on
# every `run`) and is handed YUZU_UAT_PG_DSN, which start-UAT.sh uses in place of
# its Docker sidecar. Credentials never appear on a command line: they travel in
# the environment (`docker run -e NAME`, an exported YUZU_UAT_PG_DSN), because argv
# is world-readable through /proc.
#
# Usage:
#   scripts/uat-netns.sh run <rig> -- <command> [args...]
#   scripts/uat-netns.sh status
#   scripts/uat-netns.sh pg-up
#   scripts/uat-netns.sh pg-down [--force]     (refuses while a rig is running)
#
# Example — two full stacks at once (separate terminals; my-rig.sh is your own
# script that starts the stack, drives it, and stops it — see docs/uat-environment.md):
#   scripts/uat-netns.sh run a -- bash my-rig.sh
#   scripts/uat-netns.sh run b -- bash my-rig.sh
#
# The command is run directly (no shell is interposed); put multi-step rigs in a
# script file. Inside the namespace /tmp/yuzu-uat is a private tmpfs, so
# start-UAT.sh's start-time wipe never touches another rig's state — and so its
# logs vanish with the rig: copy them out before exiting if you want them (the
# example in docs/uat-environment.md does). Starting a rig whose name is already
# running is refused (a per-rig lock held by this wrapper for the rig's lifetime).
# Inside a rig, YUZU_NETNS_RIG names it and YUZU_UAT_PG_DSN is set.
#
# Limits (documented in docs/uat-environment.md "Concurrent rigs"):
#   - the rig's processes are gone when <command> exits (that is the point), so it
#     must run the tests itself; there is no attaching to it afterwards. The shared
#     Postgres container and the rig's database OUTLIVE the command, until the next
#     `run` of that rig or `pg-down`. Processes a rig starts THROUGH the Docker
#     daemon (compose, `docker run`) are outside the namespace and are not killed;
#   - only native rigs: the Docker rigs (start-viz-uat.sh, start-demo.sh,
#     docker-start-UAT.sh) publish ports in the host namespace and are not isolated;
#   - no `sudo` inside (user namespace): start-UAT.sh --as-user is unsupported;
#   - Linux only (bubblewrap, flock). Needs unprivileged user namespaces (Ubuntu
#     24.04+ may need an AppArmor profile for bwrap:
#     kernel.apparmor_restrict_unprivileged_userns).
#
# Not isolated, and still shared between rigs: the build tree, ~/.local/share/yuzu,
# and CPU/RAM/tmpfs. Do not run two builds in one worktree concurrently.
#
# YUZU_NETNS_STATE overrides the state directory (default /tmp/yuzu-netns-<uid>);
# it exists so the test suite can run the wrapper against stub docker/bwrap without
# touching a real one. It must still be a 0700 directory you own. The container name
# is derived from it, so two state directories never share (or remove) a container.
# YUZU_NETNS_READY_TIMEOUT (seconds, default 60) is the readiness wait; also a test hook.

set -euo pipefail

PG_IMAGE="yuzu-postgres:local"
# Short on purpose: an AF_UNIX path is limited to 108 bytes. The 0700 parent keeps
# other local users away from the socket (the image's `local` auth is trust).
STATE="${YUZU_NETNS_STATE:-/tmp/yuzu-netns-$(id -u)}"
SOCK="$STATE/sock"
# The container name is global to the Docker daemon but the credentials are per state
# dir, so key the name by the state dir: another user (or another YUZU_NETNS_STATE)
# must never find "its" container missing its pgapp and remove ours.
PG_CONTAINER="yuzu-netns-pg-$(printf '%s' "$STATE" | cksum | cut -d' ' -f1)"
# Each server opens a pool of 16; the image default (100) fits about 6 rigs.
PG_MAX_CONNECTIONS=300

die() { echo "uat-netns: $*" >&2; exit 1; }

need_tools() {
    command -v bwrap >/dev/null 2>&1 || die "bwrap not found (this tool is Linux-only; apt install bubblewrap / dnf install bubblewrap)"
    command -v flock >/dev/null 2>&1 || die "flock not found (util-linux)"
    command -v docker >/dev/null 2>&1 || die "docker not found (needed only for the shared Postgres container)"
    docker info >/dev/null 2>&1 || die "cannot reach the Docker daemon (is it running, and are you allowed to use it?)"
    # The probe uses the same namespace flags as the real call, --proc included: a
    # host where --proc is refused would otherwise pass the probe and fail the run.
    bwrap --unshare-net --unshare-pid --dev-bind / / --proc /proc true 2>/dev/null \
        || die "bwrap cannot create a namespace here (unprivileged user namespaces disabled or AppArmor-restricted)"
}

# The state directory is the ONLY access control on a trust-auth Postgres socket,
# so every entry point re-checks it: owned by us, not a symlink, mode exactly 0700.
state_guard() {
    mkdir -p -m 700 "$STATE"
    [ -d "$STATE" ] && [ ! -L "$STATE" ] && [ -O "$STATE" ] && [ "$(stat -c %a "$STATE")" = "700" ] \
        || die "$STATE is not a private directory owned by you (remove it, or set YUZU_NETNS_STATE to another directory)"
}

pg_running() {
    docker ps --filter "name=^${PG_CONTAINER}$" --format '{{.Names}}' 2>/dev/null | grep -q .
}

# Real readiness: the loopback TCP probe INSIDE the container. The entrypoint's
# init-phase server is unix-socket-only and answers a socket probe before the `yuzu`
# role exists (a CREATE DATABASE ... OWNER yuzu then fails); only the final server
# listens on TCP. (--network none leaves loopback in the container.)
pg_ready() {
    docker exec "$PG_CONTAINER" pg_isready -h 127.0.0.1 -U yuzu -d yuzu >/dev/null 2>&1
}

# Serialise start/stop of the shared container. Bounded: a wedged holder must not
# block every other caller silently and forever.
pg_lock() {
    exec 9>"$STATE/.pg.lock"
    flock -w 180 9 || die "timed out waiting for another uat-netns command ($STATE/.pg.lock)"
}

# Names of rigs whose lock is held, i.e. that are running. Each rig's wrapper holds
# its lock for the rig's whole life.
live_rigs() {
    local f
    for f in "$STATE"/rig-*.lock; do
        [ -e "$f" ] || continue
        # The probe takes and drops the lock in a subshell; failing to take it means held.
        ( flock -n 8 ) 8>"$f" 2>/dev/null || basename "$f" .lock | sed 's/^rig-//'
    done
}

pg_up() {
    need_tools
    state_guard
    pg_lock
    if pg_running; then
        [ -s "$STATE/pgapp" ] \
            || die "$PG_CONTAINER is running but its credentials ($STATE/pgapp) are gone; rigs may be using it — stop them and run '$0 pg-down --force'"
        # A probe can fail transiently (load, crash recovery): retry before concluding
        # the container is broken, and never recreate it under a live rig — that would
        # destroy the rig's database and invalidate its DSN with no warning.
        local tries="${YUZU_NETNS_READY_TIMEOUT:-60}" t
        [ "$tries" -le 10 ] || tries=10
        for t in $(seq 1 "$tries"); do
            if pg_ready; then flock -u 9; return 0; fi
            sleep 1
        done
        local live
        live=$(live_rigs | tr '\n' ' ')
        [ -z "$live" ] \
            || die "$PG_CONTAINER is running but not answering while rig(s) are live ($live) — not recreating it under them; wait for it, or '$0 pg-down --force'"
        # Running with credentials, not answering, and nothing live: a start that
        # never became ready. Nothing to protect — fall through and recreate it.
    fi

    docker image inspect "$PG_IMAGE" >/dev/null 2>&1 \
        || die "image $PG_IMAGE missing — build it once: docker build -t $PG_IMAGE -f deploy/docker/Dockerfile.postgres ."

    docker rm -fv "$PG_CONTAINER" >/dev/null 2>&1 || true
    mkdir -p "$SOCK"
    # The postgres entrypoint re-owns this directory to the container's uid, so a
    # chmod can fail on a reused directory; it is not needed for correctness.
    chmod 777 "$SOCK" 2>/dev/null || true
    # Sockets left by an abnormally removed container belong to the container's uid
    # and sit in a sticky directory: clear them from inside a throwaway container.
    if [ -n "$(ls -A "$SOCK" 2>/dev/null)" ]; then
        docker run --rm --network none -v "$SOCK:/s" --entrypoint sh "$PG_IMAGE" \
            -c 'rm -f /s/.s.PGSQL.*' >/dev/null 2>&1 || true
    fi
    local app su
    app=$(openssl rand -hex 24)
    su=$(openssl rand -hex 24)
    ( umask 077; printf '%s\n' "$app" > "$STATE/pgapp" )
    # NAME-only `-e`: docker reads the value from its own environment, so neither
    # password is ever on a command line (argv is world-readable via /proc).
    # `--network none`: no bridge address, so the only way in is the unix socket.
    POSTGRES_PASSWORD="$su" YUZU_DB_PASSWORD="$app" \
        docker run -d --name "$PG_CONTAINER" --network none \
            -e POSTGRES_PASSWORD -e YUZU_DB_PASSWORD \
            -v "$SOCK:/var/run/postgresql" "$PG_IMAGE" \
            postgres -c "max_connections=$PG_MAX_CONNECTIONS" >/dev/null
    local i
    for i in $(seq 1 "${YUZU_NETNS_READY_TIMEOUT:-60}"); do
        if pg_ready; then
            echo "uat-netns: shared Postgres up ($PG_CONTAINER, unix socket only: $SOCK)"
            flock -u 9
            return 0
        fi
        sleep 1
    done
    docker logs --tail 20 "$PG_CONTAINER" >&2 2>&1 || true
    # Leave nothing that a later pg-up would mistake for a ready container.
    docker rm -fv "$PG_CONTAINER" >/dev/null 2>&1 || true
    rm -f "$STATE/pgapp"
    die "Postgres did not become ready in ${YUZU_NETNS_READY_TIMEOUT:-60}s (last container log above)"
}

pg_down() {
    local force=0
    case "${1:-}" in
        "") ;;
        --force) force=1 ;;
        *) die "usage: $0 pg-down [--force]" ;;
    esac
    state_guard
    pg_lock
    if [ "$force" = 0 ]; then
        local held
        held=$(live_rigs | tr '\n' ' ')
        [ -z "$held" ] || die "rig(s) still running: $held— stop them first, or '$0 pg-down --force' (drops their databases)"
    fi
    # A graceful stop lets postgres remove its own socket files, which the host
    # user cannot delete (owned by the container's postgres uid, sticky dir).
    docker stop "$PG_CONTAINER" >/dev/null 2>&1 || true
    docker rm -fv "$PG_CONTAINER" >/dev/null 2>&1 || true
    rm -f "$STATE/pgapp"
    rm -rf "$SOCK" 2>/dev/null || echo "uat-netns: could not remove $SOCK (stale socket files): re-run '$0 pg-up' to clear them, or sudo rm -rf $STATE" >&2
    echo "uat-netns: shared Postgres removed"
}

run_rig() {
    local rig="${1:-}"
    [ -n "$rig" ] || die "usage: $0 run <rig> -- <command> [args...]"
    shift
    [[ "$rig" =~ ^[a-z][a-z0-9_]{0,23}$ ]] || die "rig name must match ^[a-z][a-z0-9_]{0,23}\$ (it becomes a database name)"
    [ "${1:-}" = "--" ] || die "usage: $0 run <rig> -- <command> [args...]"
    shift
    [ $# -gt 0 ] || die "no command given after --"

    pg_up
    # One live run per rig name: a second would DROP the first one's database. This
    # wrapper stays the parent of the rig and holds the lock itself (the rig gets fd 8
    # closed), so a rig that closes or reuses its descriptors cannot drop the lock.
    exec 8>"$STATE/rig-$rig.lock"
    flock -n 8 || die "rig '$rig' is already running (lock: $STATE/rig-$rig.lock)"
    local app db="yuzu_$rig"
    app=$(cat "$STATE/pgapp")
    # Fresh database per run, matching the sidecar's wipe-state semantics (#947).
    # The container's own `local` trust auth is used via exec; $db is validated above.
    docker exec "$PG_CONTAINER" psql -U postgres -v ON_ERROR_STOP=1 -q \
        -c "DROP DATABASE IF EXISTS $db WITH (FORCE)" \
        -c "CREATE DATABASE $db OWNER yuzu" >/dev/null

    echo "uat-netns: rig '$rig' → private net+pid namespace, database $db" >&2
    # Exported, not `--setenv`: bwrap passes its environment through, and an
    # environment variable is not world-readable the way bwrap's argv is.
    export YUZU_UAT_PG_DSN="postgresql://yuzu:${app}@/${db}?host=${SOCK}"
    export YUZU_NETNS_RIG="$rig"
    local rc=0
    bwrap --dev-bind / / --proc /proc \
        --unshare-net --unshare-pid --die-with-parent \
        --tmpfs /tmp/yuzu-uat \
        "$@" 8>&- 9>&- || rc=$?
    exit "$rc"
}

show_status() {
    state_guard
    if pg_running; then echo "shared Postgres: running ($PG_CONTAINER, $SOCK)"
    else echo "shared Postgres: not running"; fi
    if pg_running; then
        docker exec "$PG_CONTAINER" psql -U postgres -tAc \
            "select datname from pg_database where datname like 'yuzu\\_%' escape '\\' and datname <> 'yuzu' order by 1" 2>/dev/null \
            | sed 's/^/  rig database (may outlive its run): /'
    fi
    live_rigs | sed 's/^/  rig running: /'
}

case "${1:-}" in
    run)     shift; run_rig "$@" ;;
    pg-up)   pg_up ;;
    pg-down) shift; pg_down "$@" ;;
    status)  show_status ;;
    -h|--help|"") sed -n '2,/^set -euo/p' "$0" | sed '$d' | sed 's/^# \{0,1\}//'; ;;
    *)       die "unknown subcommand '$1' (run | pg-up | pg-down | status)" ;;
esac
