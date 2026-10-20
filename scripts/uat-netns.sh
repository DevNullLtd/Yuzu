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
# only ever see its own stack, and the whole rig dies when the command exits.
#
# Postgres: published Docker ports live in the HOST namespace and are not
# reachable from a private one, but unix sockets are filesystem objects and cross
# it. One shared container (yuzu-netns-pg) listens on a unix socket only; each rig
# gets its own database (yuzu_<rig>, recreated on every `run`) and is handed
# YUZU_UAT_PG_DSN, which start-UAT.sh uses in place of its Docker sidecar.
#
# Usage:
#   scripts/uat-netns.sh run <rig> -- <command> [args...]
#   scripts/uat-netns.sh pg-up | pg-down | status
#
# Example — two full stacks at once (separate terminals):
#   scripts/uat-netns.sh run a -- scripts/my-rig.sh      # start-UAT.sh, tests, stop
#   scripts/uat-netns.sh run b -- scripts/my-rig.sh
#
# The command is exec'd directly (no shell is interposed); put multi-step rigs in
# a script file. Inside the namespace /tmp/yuzu-uat is a private tmpfs, so
# start-UAT.sh's start-time wipe never touches another rig's state.
#
# Limits (documented in docs/uat-environment.md "Concurrent rigs"):
#   - the stack is gone when <command> exits (that is the point), so it must run
#     the tests itself; there is no attaching to it afterwards;
#   - only native rigs: the Docker rigs (start-viz-uat.sh, start-demo.sh,
#     docker-start-UAT.sh) publish ports in the host namespace and are not isolated;
#   - no `sudo` inside (user namespace): start-UAT.sh --as-user is unsupported;
#   - Linux only. Needs unprivileged user namespaces (Ubuntu 24.04+ may need an
#     AppArmor profile for bwrap: kernel.apparmor_restrict_unprivileged_userns).
#
# Not isolated, and still shared between rigs: the build tree, ~/.local/share/yuzu,
# and CPU/RAM/tmpfs. Do not run two builds in one worktree concurrently.

set -euo pipefail

PG_CONTAINER="yuzu-netns-pg"
PG_IMAGE="yuzu-postgres:local"
# Short on purpose: an AF_UNIX path is limited to 108 bytes. The 0700 parent keeps
# other local users away from the socket (the image's `local` auth is trust).
STATE="/tmp/yuzu-netns-$(id -u)"
SOCK="$STATE/sock"

die() { echo "uat-netns: $*" >&2; exit 1; }

need_tools() {
    command -v bwrap >/dev/null 2>&1 || die "bwrap not found (apt install bubblewrap)"
    command -v docker >/dev/null 2>&1 || die "docker not found (needed only for the shared Postgres container)"
    bwrap --unshare-net --unshare-pid --dev-bind / / true 2>/dev/null \
        || die "bwrap cannot create a namespace here (unprivileged user namespaces disabled or AppArmor-restricted)"
}

pg_running() {
    docker ps --filter "name=^${PG_CONTAINER}$" --format '{{.Names}}' 2>/dev/null | grep -q .
}

pg_up() {
    need_tools
    mkdir -p -m 700 "$STATE"
    [ -O "$STATE" ] && [ "$(stat -c %a "$STATE")" = "700" ] \
        || die "$STATE is not a private directory owned by you"
    if pg_running && [ -s "$STATE/pgapp" ]; then return 0; fi

    docker image inspect "$PG_IMAGE" >/dev/null 2>&1 \
        || die "image $PG_IMAGE missing — build it once: docker build -t $PG_IMAGE -f deploy/docker/Dockerfile.postgres ."

    docker rm -f "$PG_CONTAINER" >/dev/null 2>&1 || true
    rm -f "$SOCK"/.s.PGSQL.* 2>/dev/null || true
    # 0777 so the container's postgres uid can create the socket; the 0700 parent
    # is the access control. The container publishes NO port.
    mkdir -p "$SOCK" && chmod 777 "$SOCK"
    local app su
    app=$(openssl rand -hex 24)
    su=$(openssl rand -hex 24)
    umask 077
    printf '%s\n' "$app" > "$STATE/pgapp"
    docker run -d --name "$PG_CONTAINER" \
        -e POSTGRES_PASSWORD="$su" -e YUZU_DB_PASSWORD="$app" \
        -v "$SOCK:/var/run/postgresql" "$PG_IMAGE" >/dev/null
    local i
    for i in $(seq 1 60); do
        if docker exec -e PGPASSWORD="$app" "$PG_CONTAINER" \
            pg_isready -h 127.0.0.1 -U yuzu -d yuzu >/dev/null 2>&1; then
            echo "uat-netns: shared Postgres up ($PG_CONTAINER, unix socket $SOCK)"
            return 0
        fi
        sleep 1
    done
    die "Postgres did not become ready in 60s — docker logs $PG_CONTAINER"
}

pg_down() {
    # A graceful stop lets postgres remove its own socket files, which the host
    # user cannot delete (owned by the container's postgres uid, sticky dir).
    docker stop "$PG_CONTAINER" >/dev/null 2>&1 || true
    docker rm -f "$PG_CONTAINER" >/dev/null 2>&1 || true
    rm -f "$STATE/pgapp"
    rm -rf "$SOCK" 2>/dev/null || echo "uat-netns: could not remove $SOCK (socket left behind): sudo rm -rf $STATE" >&2
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
    local app db="yuzu_$rig"
    app=$(cat "$STATE/pgapp")
    # Fresh database per run, matching the sidecar's wipe-state semantics (#947).
    # The container's own `local` trust auth is used via exec; $db is validated above.
    docker exec "$PG_CONTAINER" psql -U postgres -v ON_ERROR_STOP=1 -q \
        -c "DROP DATABASE IF EXISTS $db WITH (FORCE)" \
        -c "CREATE DATABASE $db OWNER yuzu" >/dev/null

    echo "uat-netns: rig '$rig' → private net+pid namespace, database $db" >&2
    exec bwrap --dev-bind / / --proc /proc \
        --unshare-net --unshare-pid --die-with-parent \
        --tmpfs /tmp/yuzu-uat \
        --setenv YUZU_UAT_PG_DSN "postgresql://yuzu:${app}@/${db}?host=${SOCK}" \
        --setenv YUZU_NETNS_RIG "$rig" \
        "$@"
}

show_status() {
    if pg_running; then echo "shared Postgres: running ($PG_CONTAINER, $SOCK)"
    else echo "shared Postgres: not running"; fi
    if pg_running; then
        docker exec "$PG_CONTAINER" psql -U postgres -tAc \
            "select datname from pg_database where datname like 'yuzu\\_%' escape '\\' and datname <> 'yuzu' order by 1" 2>/dev/null \
            | sed 's/^/  rig database: /'
    fi
}

case "${1:-}" in
    run)     shift; run_rig "$@" ;;
    pg-up)   pg_up ;;
    pg-down) pg_down ;;
    status)  show_status ;;
    -h|--help|"") sed -n '2,/^set -euo/p' "$0" | sed '$d' | sed 's/^# \{0,1\}//'; ;;
    *)       die "unknown subcommand '$1' (run | pg-up | pg-down | status)" ;;
esac
