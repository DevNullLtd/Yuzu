#!/usr/bin/env bash
#
# Verify the healthcheck RUNTIME INVARIANTS of the Yuzu application images (#751).
#
# The composes healthcheck these containers with a probe that depends on a tool
# baked into the image, not on the application:
#
#   Dockerfile.server         bash + /dev/tcp + grep   (apt-installed bash)
#   Dockerfile.gateway        wget --spider            (alpine busybox, on PATH)
#   Dockerfile.server.chisel  /bin/busybox wget --spider
#   Dockerfile.gateway.chisel /bin/busybox wget --spider
#   Dockerfile.agent.chisel   /bin/busybox wget --spider   (see PRE-EMPTIVE below)
#
# KEEP IN SYNC. The probes below are a hard-coded COPY of the healthcheck
# commands in these files. If you change a healthcheck there, change the probe
# here -- otherwise this gate goes on proving the OLD command and reports green
# while the real healthcheck is broken. The workflow's `changes` filter lists the
# same set, so an edit to any of them forces this gate to run:
#
#   docker-compose.uat.yml (root)                    server: bash /dev/tcp + grep '200 OK'
#   deploy/docker/docker-compose.uat.yml             gateway: wget --spider
#   deploy/docker/docker-compose.demo.yml            server/gateway-chisel: /bin/busybox wget
#   deploy/docker/docker-compose.reference.yml       server: bash /dev/tcp (connect-only)
#   deploy/docker/docker-compose.reference-gateway.yml  server: bash /dev/tcp
#   deploy/docker/docker-compose.reference-gateway-cluster.yml  gateway: wget --spider
#     (same shape/probe as docker-compose.uat.yml's gateway row above — no new
#     probe branch needed, HA WS-4 #4555)
#   deploy/docker/docker-compose.viz-uat.yml         server: bash /dev/tcp + head + grep
#   scripts/test/docker-compose.upgrade-test.yml     server: bash /dev/tcp + grep
#   .github/workflows/pre-release.yml (3 heredocs)   server: bash /dev/tcp
#
# NOT COVERED, deliberately:
#   - yuzu-postgres is also published and also healthchecked (pg_isready + psql
#     via CMD-SHELL), but it is FROM postgres:* and those tools are the image's
#     entire reason to exist, so the invariant is not at risk in the same way.
#     It has no role here and no pre-push gate in docker-publish-postgres.
#   - agent-chisel is PRE-EMPTIVE: no compose healthchecks any agent image today.
#     The busybox invariant is gated anyway so the demo stack can gain an agent
#     healthcheck later without a silent break.
#
# Those dependencies are invisible to the application and to every test we run:
# a base-image swap (trixie-slim -> a variant without bash), a dropped apt
# package, or a chisel slice change that stops shipping the busybox symlink
# breaks nothing at build time and nothing at boot. It breaks only the
# healthcheck -- so Compose parks every container in `unhealthy` forever, and
# anything with `depends_on: condition: service_healthy` never starts. The
# application itself is fine, which is what makes it so easy to ship.
#
# This script is the gate. It runs each image's REAL healthcheck probe against
# a known-good HTTP listener and requires it to succeed.
#
# Why a live listener rather than a bare capability check: the obvious probe --
# connect to a closed port and accept "connection refused" -- cannot tell a
# working bash from a bash built without /dev/tcp. Both exit 1 (a bash without
# net redirections treats /dev/tcp/... as an ordinary missing file). Probing
# against a listener that IS accepting connections collapses that ambiguity:
# exit 0 is the only passing outcome, so a bash that has lost /dev/tcp fails
# here instead of passing.
#
# Usage:
#   scripts/ci/verify-healthcheck-invariants.sh <role>=<image> [<role>=<image> ...]
#
# Example:
#   scripts/ci/verify-healthcheck-invariants.sh \
#       server=ghcr.io/devnullltd/yuzu-server:0.13.0 \
#       gateway-chisel=yuzu-gateway-chisel:ci
#
# Exits non-zero, naming the missing tool, if any invariant is broken.

set -euo pipefail

# The gate runs on Linux runners, but it is also meant to be runnable by hand on
# a dev box. Under Git Bash / MSYS2 on Windows, absolute-looking arguments such
# as `/bin/busybox` are silently rewritten into Windows paths
# (`C:/Program Files/Git/usr/bin/busybox`) before docker ever sees them, which
# makes every probe fail with a bogus "tool is missing". Opt out of that
# rewriting. Both variables are inert on Linux and macOS.
export MSYS_NO_PATHCONV=1
export MSYS2_ARG_CONV_EXCL='*'

# Listener image, pinned by digest for supply-chain hygiene. It is a test fixture
# only -- nothing is shipped from it, and it is never the image under test.
#
# The pin lives in deploy/docker/Dockerfile.hc-probe, NOT inline here, because
# Dependabot's docker ecosystem scans /deploy/docker and parses Dockerfiles but
# cannot scan a shell script -- an inline pin would be the one image reference in
# the repo that nothing ever updates. We read it back out of that FROM line, so a
# Dependabot bump there needs no change here. The literal below is only a fallback
# for running this script outside a checkout.
_pin_file="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/../../deploy/docker/Dockerfile.hc-probe"
if [ -z "${PROBE_IMAGE:-}" ] && [ -r "$_pin_file" ]; then
    PROBE_IMAGE="$(awk '/^FROM /{print $2; exit}' "$_pin_file")"
fi
PROBE_IMAGE="${PROBE_IMAGE:-busybox:1.37@sha256:9532d8c39891ca2ecde4d30d7710e01fb739c87a8b9299685c63704296b16028}"

# Port the probe listener serves on, inside the shared network namespace. Not
# published to the host, so it cannot collide with anything on the runner.
PROBE_PORT="${PROBE_PORT:-18080}"

# Sidecar name. $$ alone is not enough: Big Tam runs four runners against ONE
# dockerd, and the PR gate sets cancel-in-progress, so a cancelled job can be
# killed before the EXIT trap fires and leak a still-running listener. A later
# job that happened to draw the same PID would then collide on the name and fail
# for a reason that has nothing to do with the image under test. $RANDOM makes
# the name unique per run; stale leaks are swept below.
SIDECAR="yuzu-hc-probe-$$-${RANDOM}"

usage() {
    # $1 = exit status. `--help` is a successful, deliberate request for the
    # usage text; a malformed argument is an error. Same text, different status.
    local rc="${1:-2}"
    if [ "$rc" -eq 0 ]; then
        exec 3>&1     # `--help`: usage is the requested output -> stdout
    else
        exec 3>&2     # bad invocation: usage is a diagnostic -> stderr
    fi
    cat >&3 <<EOF
usage: $0 <role>=<image> [<role>=<image> ...]

roles:
  server           requires: bash, /dev/tcp, grep
  gateway          requires: wget (busybox applet) supporting --spider
  server-chisel    requires: /bin/busybox with a wget applet supporting --spider
  gateway-chisel   requires: /bin/busybox with a wget applet supporting --spider
  agent-chisel     requires: /bin/busybox with a wget applet supporting --spider

Each probe runs the image's REAL healthcheck command against a live listener, so
a tool that is present but has lost the capability the healthcheck needs (a bash
built without /dev/tcp, a wget without --spider) fails here rather than passing.
EOF
    exit "$rc"
}

# Remove THIS run's listener, and only this run's. Trapped on the cancellation
# signals as well as EXIT: the PR gate sets cancel-in-progress, and a superseded
# run is signalled before it is killed, so trapping TERM/INT/HUP is what actually
# prevents a leaked listener.
#
# Deliberately NOT a broad sweep of `^yuzu-hc-probe-*`. Big Tam runs four runners
# against ONE dockerd and the verify matrix is 5-wide, so sibling jobs' listeners
# are live on the same daemon at the same time: a startup sweep would `docker rm
# -f` a sibling's listener mid-probe, and that job would fail with "the tool is
# missing" for an image that is perfectly fine. A flaky gate that blocks merges
# and releases is far worse than the thing it was cleaning up -- a leaked 4 MB
# busybox container. The $RANDOM-suffixed name already makes collisions
# impossible, so a leak is inert.
cleanup() {
    docker rm -f "$SIDECAR" >/dev/null 2>&1 || true
}

# Start the known-good HTTP listener. Serves a 200 on /healthz, which is what
# both probe families (bash /dev/tcp + HTTP parse; busybox wget --spider) need.
start_listener() {
    # Deliberately NOT `--rm`: if httpd dies on startup, `--rm` would delete the
    # container before we could read its logs, and the failure would be
    # undiagnosable. cleanup() removes it either way.
    docker run -d --name "$SIDECAR" "$PROBE_IMAGE" \
        sh -c "mkdir -p /www && echo ok > /www/healthz && exec httpd -f -p ${PROBE_PORT} -h /www" >/dev/null

    # C-style loop, not `seq`: keeps the script dependent on bash alone, so it
    # runs the same by hand on a dev box as it does on the Linux runners.
    local i
    for (( i = 0; i < 50; i++ )); do
        if docker exec "$SIDECAR" \
            wget -q -O /dev/null "http://127.0.0.1:${PROBE_PORT}/healthz" 2>/dev/null; then
            return 0
        fi
        sleep 0.2
    done

    echo "FATAL: probe listener ($PROBE_IMAGE) never came up on port ${PROBE_PORT}" >&2
    echo "       This is a bug in the gate (or the docker daemon), NOT in the image" >&2
    echo "       under test. Nothing about the image has been verified." >&2
    echo "       listener state: $(docker inspect -f '{{.State.Status}} (exit {{.State.ExitCode}})' "$SIDECAR" 2>/dev/null || echo 'gone')" >&2
    echo "       listener logs:" >&2
    docker logs "$SIDECAR" 2>&1 | tail -20 | sed 's/^/         /' >&2 || true
    return 1
}

# Run a probe inside the image under test, joined to the listener's network
# namespace so 127.0.0.1:$PROBE_PORT is the listener.
#
# The image's own ENTRYPOINT is overridden: we are testing the image's TOOLS,
# not booting the application. The default USER is deliberately NOT overridden
# -- the real healthcheck runs as that user, so the probe must too (a tool that
# exists but is not executable by the runtime user is still a broken invariant).
#
# The probe's own output is CAPTURED, not discarded, into $PROBE_OUT. When a
# probe fails, that output is the only evidence of why -- throwing it away is
# what turns a docker-level fault into an unfalsifiable accusation against the
# image.
PROBE_OUT=""
probe() {
    local entrypoint="$1"; shift
    local image="$1"; shift
    PROBE_OUT="$(docker run --rm \
        --network "container:${SIDECAR}" \
        --entrypoint "$entrypoint" \
        "$image" "$@" 2>&1)"
}

# Is the listener still alive? A probe failure means nothing if the thing it was
# probing against died underneath it.
listener_alive() {
    [ "$(docker inspect -f '{{.State.Running}}' "$SIDECAR" 2>/dev/null)" = "true" ]
}

# Map a docker-run exit status onto a diagnosis that names the tool.
#
#   125 = DOCKER could not run the container  -> INFRA fault, says nothing about the image
#   127 = executable not found                -> the tool is GONE from the image
#   126 = found but not executable            -> present, but the runtime user cannot run it
#   other non-zero = the tool ran and failed  -> present, but the CAPABILITY is gone
#
# 125 must never be reported as an image regression. It is docker's generic
# "could not run the container": a dead sidecar (so `--network container:` has
# nothing to join), a busy daemon, a cgroup error, a full disk. This gate sits
# between build and push in release.yml, so misreading an infrastructure blip as
# "the image lost bash" would block a release AND send whoever debugs it hunting
# a binary that was never missing.
diagnose() {
    local rc="$1" role="$2" tool="$3" capability="$4"

    if [ "$rc" -eq 125 ] || ! listener_alive; then
        echo "  ERROR [$role]: the PROBE could not run -- this says nothing about the image." >&2
        echo "        docker exited $rc, and the probe listener is $(listener_alive && echo 'alive' || echo 'GONE')." >&2
        echo "        This is a fault in the gate or the docker daemon (a dead sidecar, a busy" >&2
        echo "        daemon, no disk), NOT a broken healthcheck invariant. Do not \"fix\" the image." >&2
        [ -n "$PROBE_OUT" ] && echo "        docker said: ${PROBE_OUT}" >&2
        return 0
    fi

    case "$rc" in
        127)
            echo "  FAIL [$role]: \`$tool\` is MISSING from the image." >&2
            echo "        The healthcheck for this image invokes \`$tool\`; with the tool gone," >&2
            echo "        every container from this image parks in \`unhealthy\` forever and" >&2
            echo "        anything with \`depends_on: condition: service_healthy\` never starts." >&2
            echo "        Restore \`$tool\`, or update EVERY compose healthcheck for this image." >&2
            echo "        NOTE: the healthcheck also needs the tools \`$tool\` itself invokes" >&2
            echo "        (the server probe pipes through \`grep\`); a 127 can mean one of those" >&2
            echo "        is the thing that vanished. The probe output below says which." >&2
            ;;
        126)
            echo "  FAIL [$role]: \`$tool\` exists but is NOT EXECUTABLE by the image's runtime user." >&2
            echo "        The healthcheck runs as that user, so this breaks it exactly as if" >&2
            echo "        the tool were missing." >&2
            ;;
        *)
            echo "  FAIL [$role]: \`$tool\` is present, but $capability" >&2
            echo "        The probe ran against a listener that IS still accepting connections" >&2
            echo "        and serving 200s (checked just now), so this is a lost capability --" >&2
            echo "        not a connection error." >&2
            ;;
    esac
    [ -n "$PROBE_OUT" ] && echo "        probe output: ${PROBE_OUT}" >&2
    return 0
}

main() {
    case "${1:-}" in
        -h|--help) usage 0 ;;
    esac

    [ "$#" -gt 0 ] || usage 2
    command -v docker >/dev/null 2>&1 || { echo "FATAL: docker not on PATH" >&2; exit 1; }

    # Validate arguments before doing any work, so a typo fails in <1s.
    local pair role image
    for pair in "$@"; do
        role="${pair%%=*}"
        image="${pair#*=}"
        if [ "$role" = "$pair" ] || [ -z "$role" ] || [ -z "$image" ]; then
            echo "FATAL: expected <role>=<image>, got '$pair'" >&2
            usage 2
        fi
        case "$role" in
            server|gateway|server-chisel|gateway-chisel|agent-chisel) ;;
            *) echo "FATAL: unknown role '$role'" >&2; usage 2 ;;
        esac
        if ! docker image inspect "$image" >/dev/null 2>&1; then
            echo "FATAL: image '$image' is not present locally (build or pull it first)" >&2
            exit 1
        fi
    done

    trap cleanup EXIT INT TERM HUP
    start_listener

    local failures=0 rc
    local url="http://127.0.0.1:${PROBE_PORT}/healthz"

    for pair in "$@"; do
        role="${pair%%=*}"
        image="${pair#*=}"
        echo "==> [$role] $image"

        rc=0
        case "$role" in
            server)
                # The real healthcheck (docker-compose.uat.yml): open a TCP
                # connection via bash's /dev/tcp, speak HTTP/1.0, and grep the
                # status line. Reproduced verbatim in shape, so bash, /dev/tcp
                # and grep are all exercised the way production exercises them.
                probe bash "$image" -c \
                    "exec 3<>/dev/tcp/127.0.0.1/${PROBE_PORT} \
                     && printf 'GET /healthz HTTP/1.0\r\nHost: localhost\r\n\r\n' >&3 \
                     && grep -q '200 OK' <&3 ; rc=\$? ; exec 3>&- ; exit \$rc" \
                    || rc=$?
                [ "$rc" -eq 0 ] || diagnose "$rc" "$role" "bash" \
                    "its /dev/tcp support (or grep) no longer works."
                ;;
            gateway)
                # The real healthcheck: `wget --spider -q <url>` off PATH.
                probe wget "$image" --spider -q "$url" || rc=$?
                [ "$rc" -eq 0 ] || diagnose "$rc" "$role" "wget" \
                    "it no longer supports --spider (is this still busybox wget?)."
                ;;
            server-chisel|gateway-chisel|agent-chisel)
                # The real healthcheck (docker-compose.demo.yml) invokes busybox
                # by ABSOLUTE PATH: ["CMD", "/bin/busybox", "wget", "--spider", ...].
                # Probing that exact path is the point -- the chisel images build
                # busybox into /usr/bin and rely on the usrmerge /bin symlink, so
                # a slice change that breaks the path breaks the healthcheck even
                # though busybox itself is still in the image.
                probe /bin/busybox "$image" wget --spider -q "$url" || rc=$?
                [ "$rc" -eq 0 ] || diagnose "$rc" "$role" "/bin/busybox" \
                    "its wget applet no longer supports --spider."
                ;;
        esac

        if [ "$rc" -eq 0 ]; then
            echo "  ok"
        else
            failures=$((failures + 1))
        fi
    done

    echo
    if [ "$failures" -ne 0 ]; then
        echo "FAILED: $failures image(s) have a broken healthcheck invariant." >&2
        echo "See the RUNTIME INVARIANT comments in deploy/docker/Dockerfile.* and #751." >&2
        return 1
    fi
    echo "All healthcheck runtime invariants hold."
}

main "$@"
