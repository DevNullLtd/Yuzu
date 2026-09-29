#!/bin/bash
# vcpkg x-script asset fetcher — BOOTSTRAPPING AID for warming the binary cache
# on BigMags through a flaky/degraded or rate-limited GitHub.
#
# This is NOT used by the runner CI jobs. The runners rely on a warm local
# VCPKG_DEFAULT_BINARY_CACHE (no downloads → no 429s), exactly like Big Tam /
# Wee Tam, neither of which carries a fetcher. Use this only for the one-time
# cache warm (README step 2a) or to re-warm when a dependency changes / GitHub
# is degraded, by exporting:
#
#   export X_VCPKG_ASSET_SOURCES="clear;x-script,/opt/ci/vcpkg-fetch.sh {url} {sha512} {dst};x-block-origin"
#
# vcpkg invokes it as: vcpkg-fetch.sh <url> <sha512> <dst>
# It downloads <url> to <dst>; vcpkg verifies <sha512> afterwards, so this only
# needs to place the bytes. Two properties beat vcpkg's built-in 3-fast-retry
# downloader on a struggling endpoint:
#   1. patient curl backoff (--retry 15 --retry-delay 15 --retry-all-errors)
#   2. an authenticated header for github hosts, so downloads count against the
#      per-user rate limit (5000/hr) rather than the shared per-IP limit.
#
# NOT `set -u`: macOS ships bash 3.2, where expanding an EMPTY array under
# nounset ("${auth[@]}" with no auth header, e.g. a non-github mirror like
# ftp.postgresql.org) throws "unbound variable" — a 3.2 bug fixed in 4.4+.
# Arg validation uses ${1:?}, which needs no nounset.
set -o pipefail
url="${1:?url}"; sha="${2:-}"; dst="${3:?dst}"

auth=()
# Match the AUTHORITY (host), never the whole URL. A shell `case` glob's `*`
# crosses `/`, so `https://*.githubusercontent.com/*` ALSO matches an attacker
# host that merely carries the string in its PATH
# (https://attacker.invalid/x.githubusercontent.com/…) and would leak the token
# to it. Extracting the host first removes every `/` for the glob to cross.
host="${url#*://}"; host="${host%%/*}"
case "$host" in
  github.com|api.github.com|codeload.github.com|*.githubusercontent.com)
    tok="${GH_TOKEN:-$(gh auth token 2>/dev/null || true)}"
    [ -n "$tok" ] && auth=(-H "Authorization: token $tok")
    ;;
esac

mkdir -p "$(dirname "$dst")"
curl -fSL --retry 15 --retry-delay 15 --retry-all-errors --connect-timeout 30 \
  "${auth[@]}" "$url" -o "$dst"
