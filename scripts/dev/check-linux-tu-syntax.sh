#!/usr/bin/env bash
# check-linux-tu-syntax.sh — syntax-check the Linux-only plugin TUs on a
# non-Linux dev box, using a throwaway Debian container.
#
# WHY THIS EXISTS. A `#if defined(__linux__)` translation unit compiles to
# NOTHING on macOS, so a fully green local `meson test` can hide a Linux-leg
# compile break — the mirror-image problem check-windows-tu-syntax.sh already
# covers for the Windows leg. The nftables NETLINK_NETFILTER probe reaches
# straight into the kernel UAPI headers (linux/netfilter/nfnetlink.h,
# linux/netlink.h) for struct layouts (offsetof/static_assert guards on
# nlmsghdr et al.) that only exist on Linux — this Mac never compiles that
# code, so a real Linux compiler against real UAPI headers is the only way to
# prove it before CI does.
#
# This is a SYNTAX check, not a build. It cannot validate kernel-version
# skew, netlink runtime behaviour, or link correctness — CI remains the
# enforcement point. What it does catch is the large class of ordinary C++
# errors (and UAPI struct-layout assumptions) in code the local toolchain
# never reads.
#
# The container is command-only: no image is built or tagged, no Yuzu build
# runs inside it, and the repo is bind-mounted READ-ONLY. It installs g++ +
# libsystemd-dev (matching deploy/docker/Dockerfile.agent's debian:trixie-slim
# base) fresh each run — this script is a local dev check, not CI, so the
# apt cost is traded for zero image-maintenance burden.
#
# Usage:  bash scripts/dev/check-linux-tu-syntax.sh [extra TU paths...]
# Install: Docker Desktop — https://docs.docker.com/desktop/setup/install/mac-install/

set -uo pipefail

DOCKER=${DOCKER_BIN:-docker}
if ! command -v "$DOCKER" >/dev/null 2>&1; then
    echo "check-linux-tu-syntax: $DOCKER not found — install Docker to use this check." >&2
    echo "  macOS: https://docs.docker.com/desktop/setup/install/mac-install/" >&2
    exit 127
fi
if ! "$DOCKER" info >/dev/null 2>&1; then
    echo "check-linux-tu-syntax: Docker daemon not reachable (is Docker Desktop running?)." >&2
    exit 127
fi

repo_root=$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)
cd "$repo_root" || exit 1

image="debian:trixie-slim"

# Linux-only TUs worth checking. Extend as new ones land.
tus=(
    agents/plugins/firewall/src/firewall_plugin.cpp
)
[ "$#" -gt 0 ] && tus+=("$@")

# test_firewall_parsers.cpp is header-pure (firewall_parsers.hpp has no OS
# ifdefs) so it never fails for a Linux-specific reason, but it is cheap
# corroboration that the header the Linux TU depends on still parses under a
# real Linux g++ + libstdc++, not just clang/libc++. Checked with a real
# catch2 (apt package `catch2`, header-only — same rationale as the Windows
# sibling's nlohmann/libxml2 handling: a faithful catch2 shim isn't a
# handful-of-calls job) when available in-container; skipped gracefully,
# never failing the whole check, when it is not.
test_tu="tests/unit/test_firewall_parsers.cpp"

# The container script below runs entirely inside the debian:trixie-slim
# container against the read-only bind-mounted repo at /repo. It prints
# "ok"/"FAIL" lines per TU (mirroring the Windows sibling's format) and exits
# non-zero if any TU failed to compile.
container_script='
set -u
cd /repo || exit 1

apt-get update -qq >/tmp/apt-update.log 2>&1
if [ "$?" -ne 0 ]; then
    echo "check-linux-tu-syntax: apt-get update failed inside container" >&2
    tail -n 20 /tmp/apt-update.log >&2
    exit 2
fi

apt-get install -y --no-install-recommends g++ libsystemd-dev >/tmp/apt-toolchain.log 2>&1
if [ "$?" -ne 0 ]; then
    echo "check-linux-tu-syntax: g++/libsystemd-dev install failed inside container" >&2
    tail -n 20 /tmp/apt-toolchain.log >&2
    exit 2
fi

have_catch2=1
apt-get install -y --no-install-recommends catch2 >/tmp/apt-catch2.log 2>&1 || have_catch2=0

incs="-Isdk/include -Iagents/core/include -Icommon/include -Iagents/shared -Iagents/plugins/firewall/src"
rc=0

for tu in '"${tus[@]}"'; do
    if [ ! -f "$tu" ]; then
        echo "  SKIP  $tu (not present)"
        continue
    fi
    if g++ -std=c++23 -fsyntax-only -Wall -Wextra -DYUZU_HAVE_LIBSYSTEMD $incs "$tu" 2>/tmp/err.log; then
        echo "  ok    $tu"
    else
        echo "  FAIL  $tu"
        sed "s/^/        /" /tmp/err.log
        rc=1
    fi
done

if [ -f '"$test_tu"' ]; then
    if [ "$have_catch2" -eq 1 ]; then
        # Same $incs as the plugin TU above, not just -Iagents/plugins/
        # firewall/src -- firewall_parsers.hpp now includes
        # <yuzu/agent/subprocess_runner.hpp> (the subprocess_complete()
        # hoist, code-review round 1), so the test TU needs agent-core on
        # its include path too, or it fails identically to a real build
        # even though the header itself is fine (caught when this drifted).
        if g++ -std=c++23 -fsyntax-only -Wall -Wextra $incs '"$test_tu"' 2>/tmp/err.log; then
            echo "  ok    '"$test_tu"'"
        else
            echo "  FAIL  '"$test_tu"'"
            sed "s/^/        /" /tmp/err.log
            rc=1
        fi
    else
        echo "  SKIP  '"$test_tu"' (catch2 unavailable in-container — checking firewall_parsers.hpp directly instead)"
        wrapper=/tmp/firewall_parsers_syntax_check.cpp
        echo "#include \"firewall_parsers.hpp\"" > "$wrapper"
        if g++ -std=c++23 -fsyntax-only -Wall -Wextra $incs "$wrapper" 2>/tmp/err.log; then
            echo "  ok    firewall_parsers.hpp"
        else
            echo "  FAIL  firewall_parsers.hpp"
            sed "s/^/        /" /tmp/err.log
            rc=1
        fi
    fi
else
    echo "  SKIP  '"$test_tu"' (not present)"
fi

exit "$rc"
'

"$DOCKER" run --rm \
    --mount "type=bind,source=${repo_root},target=/repo,readonly" \
    "$image" \
    bash -c "$container_script"
rc=$?

if [ "$rc" -eq 0 ]; then
    echo "check-linux-tu-syntax: all Linux TUs syntax-check clean."
else
    echo "check-linux-tu-syntax: at least one Linux TU does not compile." >&2
fi
exit "$rc"
