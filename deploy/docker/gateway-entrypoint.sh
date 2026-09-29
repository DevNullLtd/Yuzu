#!/bin/sh
# Gateway container entrypoint — resolves this node's own advertised
# distribution address BEFORE the relx boot script starts the BEAM,
# per HA WS-4 #4555 (ADR-2002 §7b "WHERE dynamic naming happens").
#
# WHY THIS HAS TO RUN HERE, NOT IN ERLANG: relx's `.src` config
# substitution (config/vm.args.src's `${YUZU_GW_ADVERTISE_ADDR:-127.0.0.1}`)
# happens in the boot script BEFORE the VM starts, so the address must be
# known and exported as an env var before `bin/yuzu_gw` runs — it cannot be
# computed from application code after boot without breaking
# yuzu_gw_app:check_distribution_cookie/0's ordering (that guard's
# 'nonode@nohost' short-circuit assumes distribution is already up by the
# time application code runs; starting distribution later from app code
# would silently turn it into dead code, reopening #659).
#
# WHY AN IP LITERAL, NOT A HOSTNAME: every gateway node shares one fixed
# short name (`yuzu_gw`) and is distinguished only by address. The OTP
# distribution handshake requires the dialed node name to match the
# target's own registered name EXACTLY, and the discovery loop
# (yuzu_gw_cluster_discovery) only ever has IP addresses from resolving the
# seed DNS name — so this node's own advertised name must also be an IP
# literal, never a hostname string (a Docker PTR lookup on a container's IP
# returns the container name, not a name that round-trips through a fresh
# forward lookup).
#
# Resolution order (first that yields an address wins):
#   1. YUZU_GW_ADVERTISE_ADDR already set — explicit operator override,
#      silently wins over everything below (bare-VM/multi-NIC/NAT case).
#   2. Resolve YUZU_GW_SEED_DNS_NAME (default "gateway") to a set of A
#      records, then intersect with this container's own local interface
#      addresses — "which of the addresses my peers would also see is
#      mine". This is the address Docker Compose's embedded DNS already
#      answers for a scaled service with zero extra configuration.
#   3. Resolve this container's own hostname to an IP (last resort — covers
#      a deployment where the seed name doesn't include this node yet, e.g.
#      DNS propagation lag on first boot).
#   4. 127.0.0.1 — matches vm.args.src's own single-node fallback default,
#      so leaving this entirely unset still boots a working single-node
#      gateway exactly as it does today.
set -eu

log() {
    printf '[gateway-entrypoint] %s\n' "$1" >&2
}

# Local, non-loopback IPv4 addresses this container actually owns.
local_addrs() {
    ip -4 -o addr show scope global 2>/dev/null \
        | awk '{print $4}' | cut -d/ -f1
}

# A records for a DNS name, one address per line. Empty output on any
# resolution failure (unset/misconfigured name, no records, timeout) —
# every caller treats "nothing" as "fall through to the next resolution
# step", never as an error.
resolve_a_records() {
    name="$1"
    [ -n "$name" ] || return 0
    dig +short +time=2 +tries=1 A "$name" 2>/dev/null | grep -E '^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$' || true
}

# First address common to both address lists (one per line each), or empty.
first_common_addr() {
    set_a="$1"
    set_b="$2"
    printf '%s\n' "$set_a" | while IFS= read -r addr; do
        [ -n "$addr" ] || continue
        if printf '%s\n' "$set_b" | grep -qx "$addr"; then
            printf '%s\n' "$addr"
            return 0
        fi
    done
}

if [ -n "${YUZU_GW_ADVERTISE_ADDR:-}" ]; then
    log "YUZU_GW_ADVERTISE_ADDR already set (${YUZU_GW_ADVERTISE_ADDR}) — using it as-is"
else
    seed_name="${YUZU_GW_SEED_DNS_NAME:-gateway}"
    seed_addrs="$(resolve_a_records "$seed_name")"
    mine="$(local_addrs)"
    advertise=""

    if [ -n "$seed_addrs" ]; then
        advertise="$(first_common_addr "$seed_addrs" "$mine")"
        if [ -n "$advertise" ]; then
            log "resolved seed name '$seed_name', matched local interface: $advertise"
        else
            log "resolved seed name '$seed_name' but none of its addresses are local yet (DNS propagation lag?) — falling back to own hostname"
        fi
    else
        log "seed name '$seed_name' did not resolve — falling back to own hostname"
    fi

    if [ -z "$advertise" ]; then
        own_addrs="$(resolve_a_records "$(hostname)")"
        advertise="$(printf '%s\n' "$own_addrs" | head -n1)"
        [ -n "$advertise" ] && log "resolved own hostname to $advertise"
    fi

    if [ -z "$advertise" ]; then
        log "no address resolved by any method — defaulting to 127.0.0.1 (single-node)"
        advertise="127.0.0.1"
    fi

    export YUZU_GW_ADVERTISE_ADDR="$advertise"
fi

exec /opt/yuzu_gw/bin/yuzu_gw "$@"
