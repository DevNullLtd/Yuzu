#!/usr/bin/env bash
# Hold a SHARED lock on a buildx type=local cache directory for the rest of a
# CI job (WP15/S9, governance G8-chaos-1).
#
#   scripts/ci/buildcache-lock.sh hold DIR
#
# release.yml's Big Tam publish jobs import and export
# $RUNNER_TOOL_CACHE/yuzu-docker-buildcache/<image>. cache-prune.yml prunes
# those directories (this runner's and its three siblings', which run as the
# same OS identity) with scripts/ci/prune-buildcache.py, which takes an
# EXCLUSIVE, non-blocking lock on the same file and skips a directory whose
# lock is held. Without this, a prune overlapping an export could remove a
# blob the export re-references (the next import then fails "NotFound
# content") or the whole directory mid-export.
#
# The lock file is DIR.lock (beside the directory, so removing the directory
# never removes a held lock). A background `flock --shared --close` holds it
# while it runs `sleep`; the runner's end-of-job orphan-process cleanup kills
# them, which releases the lock; HOLD seconds (default 4 h, above every publish job's
# timeout) bound it if that cleanup ever does not run. The step waits up to
# WAIT seconds (default 30 min) while a prune holds the lock; a prune of one
# directory takes seconds to a few minutes. Failing to get it fails the step:
# building without it could break this runner's cache.
#
# Environment (tests): YUZU_BUILDCACHE_LOCK_WAIT, YUZU_BUILDCACHE_LOCK_HOLD.
# Exit status: 0 the lock is held; 1 it could not be taken; 2 usage.
set -euo pipefail

if [ $# -ne 2 ] || [ "$1" != hold ] || [ -z "$2" ]; then
    echo "usage: $0 hold DIR" >&2
    exit 2
fi
dir="${2%/}"
lock="${dir}.lock"
wait_s="${YUZU_BUILDCACHE_LOCK_WAIT:-1800}"
hold_s="${YUZU_BUILDCACHE_LOCK_HOLD:-14400}"
[[ "$wait_s" =~ ^[0-9]+$ && "$hold_s" =~ ^[1-9][0-9]*$ ]] || { echo "bad WAIT/HOLD" >&2; exit 2; }
command -v flock >/dev/null 2>&1 || { echo "::error::flock is not installed; cannot lock $dir against cache-prune" >&2; exit 1; }

mkdir -p "$(dirname "$lock")"
ready="$(mktemp -u "${RUNNER_TEMP:-${TMPDIR:-/tmp}}/yuzu-buildcache-lock.XXXXXX")"
# No inherited stdio: the step must not wait for this process to exit.
# --close: flock itself holds the lock (the sleep child does not inherit it),
# so killing the flock process releases it.
# shellcheck disable=SC2016 # $1/$2 are expanded by the inner sh
nohup flock --shared --close --wait "$wait_s" "$lock" \
    sh -c ': > "$1"; exec sleep "$2"' sh "$ready" "$hold_s" </dev/null >/dev/null 2>&1 &
holder=$!
deadline=$(( $(date +%s) + wait_s + 5 ))
while [ "$(date +%s)" -le "$deadline" ]; do
    if [ -e "$ready" ]; then
        rm -f "$ready"
        echo "holding a shared lock on $lock (pid $holder) until the job ends"
        echo "holder=$holder"
        exit 0
    fi
    kill -0 "$holder" 2>/dev/null || break
    sleep 1
done
kill "$holder" 2>/dev/null || true
rm -f "$ready"
echo "::error::could not take the lock on $lock within ${wait_s}s (cache-prune.yml holds it, or flock failed); re-run the job" >&2
exit 1
