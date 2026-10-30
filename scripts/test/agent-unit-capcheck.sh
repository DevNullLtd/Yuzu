#!/usr/bin/env bash
#
# Live capability check of the SHIPPED agent systemd unit (deploy/systemd/yuzu-agent.service).
# Needs no server and no Postgres, but needs systemd as PID 1 and root (or passwordless sudo).
#
# WHY THIS EXISTS
# ---------------
# The unit grants the agent CAP_DAC_READ_SEARCH as an ambient capability, the agent clears
# its inheritable and ambient sets at start so exec'd children do not inherit it, and a root
# ExecStartPre helper copies the DMI tables into the agent's state directory. None of that
# can be seen from a unit test: a typo in a directive name, a missing NoNewPrivileges, or a
# removed clear_child_capabilities() call all leave every compile and unit suite green. This
# script installs the shipped unit file VERBATIM under unique runtime names and reads the
# kernel's view (/proc/<pid>/status) of what a process really holds.
#
# WHAT IS ASSERTED
# ----------------
#   control unit (a plain shell child, oneshot):
#     * CapAmb = CapEff = CapBnd = 0x4 and NoNewPrivs = 1   (positive control: proves the
#       "child holds nothing" assertions below can fail)
#     * a 1-byte read of the 0400 DMI serial file succeeds (when the file exists)
#     * snapshot success over a pre-existing loose directory (0755 -> 0700, files 0600,
#       byte-identical to the source, no dmi.tmp left)
#     * snapshot refresh with a partial source removes the pair (all-or-none, never stale)
#     * the documented opt-out drop-in (taken verbatim from docs/user-manual/upgrading.md)
#       drops the capability and removes the snapshot
#   agent unit (the real binary):
#     * CapEff = CapPrm = CapBnd = 0x4 exactly, NoNewPrivs = 1
#     * every thread has CapInh = CapAmb = 0 once plugins have loaded
#     * the real firmware tables, when the host has them, are copied byte-identically; on a
#       host with none, a stale snapshot is removed and the agent still starts
#
# The test drop-ins override paths only. A guard asserts they contain no User/Group/
# NoNewPrivileges/Capability/Protect/Private directive, so the shipped hardening is what runs.
#
# This prints PASS/FAIL lines and capability hex only. It never prints firmware bytes or
# serial numbers (CI logs are public).
#
# Inputs (mirroring agent-shutdown-smoke.sh):
#   YUZU_AGENT_BIN      agent binary           (default build-linux/agents/core/yuzu-agent)
#   YUZU_PLUGIN_DIR     built plugins          (default build-linux/agents/plugins)
#   YUZU_AGENT_LIB_DIR  dir holding libyuzu_agent_core.so* (default: found under the build dir)
#
# Exit: 0 all passed, 1 a check failed, 77 skipped (local runs only; in CI a missing
# precondition is a FAIL, never a skip).

set -euo pipefail

AGENT=${YUZU_AGENT_BIN:-build-linux/agents/core/yuzu-agent}
PLUGINS=${YUZU_PLUGIN_DIR:-build-linux/agents/plugins}
REPO_ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)
UNIT_FILE=$REPO_ROOT/deploy/systemd/yuzu-agent.service
HELPER=$REPO_ROOT/deploy/systemd/yuzu-agent-dmi-snapshot.sh
UPGRADING_DOC=$REPO_ROOT/docs/user-manual/upgrading.md
CAP_READ_SEARCH=0000000000000004
CAP_NONE=0000000000000000
SVC_USER=yuzu-agent

precondition() {
    if [[ -n ${GITHUB_ACTIONS:-} ]]; then
        echo "FAIL: precondition not met: $1" >&2
        exit 1
    fi
    echo "SKIP: $1"
    exit 77
}

[[ $(uname -s) == Linux ]] || precondition "not Linux"
[[ -d /run/systemd/system ]] || precondition "systemd is not PID 1"
SUDO=()
if [[ $(id -u) -ne 0 ]]; then
    SUDO=(sudo -n)
    sudo -n true 2>/dev/null || precondition "passwordless sudo is required"
fi
as_root() { ${SUDO[@]+"${SUDO[@]}"} "$@"; }

[[ -x $AGENT ]] || { echo "FAIL: agent binary not found or not executable: $AGENT" >&2; exit 1; }
[[ -d $PLUGINS ]] || { echo "FAIL: plugin dir not found: $PLUGINS" >&2; exit 1; }
for f in "$UNIT_FILE" "$HELPER" "$UPGRADING_DOC"; do
    [[ -f $f ]] || { echo "FAIL: missing input file: $f" >&2; exit 1; }
done

LIB_DIR=${YUZU_AGENT_LIB_DIR:-}
if [[ -z $LIB_DIR ]]; then
    build_root=${AGENT%/agents/core/*}
    found=$(find "$build_root" -name 'libyuzu_agent_core.so*' \( -type f -o -type l \) -print -quit 2>/dev/null || true)
    [[ -n $found ]] && LIB_DIR=$(dirname "$found")
fi
[[ -n $LIB_DIR ]] || { echo "FAIL: libyuzu_agent_core.so* not found; set YUZU_AGENT_LIB_DIR" >&2; exit 1; }

# Unique names so concurrent runners on one box never collide (shared-identity CI pools).
id=$(printf 'yuzu-capcheck-%s-%s-%s' "${GITHUB_RUN_ID:-local}" "${RUNNER_NAME:-host}" "$$" |
         tr '[:upper:]' '[:lower:]' | tr -c 'a-z0-9-' '-')
ctl="$id-ctl"
run_dir=/run/$id
sysd=/run/systemd/system

cleanup() {
    local rc=$?
    set +e
    if [[ -n $id ]]; then
        as_root systemctl stop "$id.service" "$ctl.service" >/dev/null 2>&1
        as_root rm -rf "$sysd/$id.service" "$sysd/$id.service.d" \
                       "$sysd/$ctl.service" "$sysd/$ctl.service.d"
        as_root systemctl daemon-reload >/dev/null 2>&1
        as_root systemctl reset-failed "$id.service" "$ctl.service" >/dev/null 2>&1
        as_root rm -rf "$run_dir" "/var/lib/$id" "/var/lib/$ctl"
    fi
    exit $rc
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

FAILS=0
pass() { echo "PASS: $1"; }
fail() { echo "FAIL: $1" >&2; FAILS=$((FAILS + 1)); }
eq() { if [[ $2 == "$3" ]]; then pass "$1 ($2)"; else fail "$1 (got '$2', want '$3')"; fi; }
absent() { if as_root test -e "$2"; then fail "$1 (present)"; else pass "$1"; fi; }

# --- account and staging -----------------------------------------------------------------
getent passwd "$SVC_USER" >/dev/null ||
    as_root useradd --system --user-group --no-create-home --shell /usr/sbin/nologin "$SVC_USER" ||
    getent passwd "$SVC_USER" >/dev/null   # a concurrent runner may have created it first

# /tmp is unusable here: the unit sets PrivateTmp. /run/$id is root 0755 and readable by the account.
as_root install -d -m 0755 "$run_dir" "$run_dir/bin" "$run_dir/lib" "$run_dir/plugins" "$run_dir/src"
as_root install -m 0755 "$AGENT" "$run_dir/bin/yuzu-agent"
find "$LIB_DIR" -maxdepth 1 -name 'libyuzu_agent_core.so*' \( -type f -o -type l \) -print0 |
    as_root xargs -0 -r install -m 0755 -t "$run_dir/lib"
find "$PLUGINS" -name '*.so' -type f -print0 |
    as_root xargs -0 -r install -m 0755 -t "$run_dir/plugins"
as_root install -m 0755 "$HELPER" "$run_dir/yuzu-agent-dmi-snapshot.sh"

# Control program: records what a plain child of the unit holds. No '$' in the unit file itself.
as_root tee "$run_dir/ctl.sh" >/dev/null <<'EOF'
#!/bin/sh
d=$1
grep -E '^(Cap|NoNewPrivs)' /proc/self/status > "$d/status.txt"
if [ -e /sys/class/dmi/id/product_serial ]; then
    head -c1 /sys/class/dmi/id/product_serial >/dev/null 2>&1
    echo $? > "$d/serial_rc"
fi
EOF
as_root chmod 0755 "$run_dir/ctl.sh"

# Install the shipped unit byte-for-byte, twice.
as_root install -m 0644 "$UNIT_FILE" "$sysd/$id.service"
as_root install -m 0644 "$UNIT_FILE" "$sysd/$ctl.service"
as_root install -d -m 0755 "$sysd/$id.service.d" "$sysd/$ctl.service.d"

# Path-only drop-ins. The agent's snapshot source is the real /sys (helper SRC omitted); the
# control unit's is the fixture dir.
as_root tee "$sysd/$id.service.d/00-capcheck-paths.conf" >/dev/null <<EOF
[Service]
ExecStart=
ExecStart=$run_dir/bin/yuzu-agent --server 127.0.0.1:1 --no-tls --data-dir /var/lib/$id --plugin-dir $run_dir/plugins
ExecStartPre=
ExecStartPre=-/bin/rm -rf /var/lib/$id/dmi /var/lib/$id/dmi.tmp
ExecStartPre=-+/bin/bash $run_dir/yuzu-agent-dmi-snapshot.sh /var/lib/$id $SVC_USER
StateDirectory=
StateDirectory=$id
WorkingDirectory=/var/lib/$id
ReadWritePaths=
Environment=LD_LIBRARY_PATH=$run_dir/lib
StandardOutput=file:$run_dir/agent.log
StandardError=file:$run_dir/agent.log
Restart=no
EOF
as_root tee "$sysd/$ctl.service.d/00-capcheck-paths.conf" >/dev/null <<EOF
[Service]
Type=oneshot
ExecStart=
ExecStart=/bin/sh $run_dir/ctl.sh /var/lib/$ctl
ExecStartPre=
ExecStartPre=-/bin/rm -rf /var/lib/$ctl/dmi /var/lib/$ctl/dmi.tmp
ExecStartPre=-+/bin/bash $run_dir/yuzu-agent-dmi-snapshot.sh /var/lib/$ctl $SVC_USER $run_dir/src
StateDirectory=
StateDirectory=$ctl
WorkingDirectory=/var/lib/$ctl
ReadWritePaths=
StandardOutput=file:$run_dir/ctl.log
StandardError=file:$run_dir/ctl.log
Restart=no
EOF
as_root systemctl daemon-reload

# Guard: the test drop-ins must not touch the hardening under test.
for u in "$id" "$ctl"; do
    if as_root grep -Eqi '^(User|Group|NoNewPrivileges|Capabilit|Ambient|Protect|Private)' \
            "$sysd/$u.service.d/00-capcheck-paths.conf"; then
        fail "drop-in guard: $u path drop-in overrides hardening"
    else
        pass "drop-in guard: $u path drop-in overrides paths only"
    fi
done
if as_root cmp -s "$UNIT_FILE" "$sysd/$id.service"; then
    pass "shipped unit installed verbatim"
else
    fail "shipped unit installed verbatim"
fi

# --- helpers -----------------------------------------------------------------------------
ctl_state=/var/lib/$ctl
write_fixtures() {
    head -c 4096 /dev/urandom | as_root tee "$run_dir/src/DMI" >/dev/null
    head -c 32 /dev/urandom | as_root tee "$run_dir/src/smbios_entry_point" >/dev/null
}
seed_stale() { # $1 = state dir; leaves a loose 0755 dmi/ owned by the account with a stale file
    as_root install -d -o "$SVC_USER" -g "$SVC_USER" -m 0755 "$1" "$1/dmi"
    printf 'stale' | as_root tee "$1/dmi/DMI" >/dev/null
    as_root chown "$SVC_USER:$SVC_USER" "$1/dmi/DMI"
}
start_ctl() {
    as_root rm -f "$ctl_state/status.txt" "$ctl_state/serial_rc"
    as_root systemctl start "$ctl.service" || fail "control unit failed to start"
}
ctl_field() { as_root cat "$ctl_state/status.txt" 2>/dev/null | awk -v k="$1:" '$1 == k {print $2}'; }
perm() { as_root stat -c '%a %U' "$1" 2>/dev/null || echo "missing"; }

# --- (i) positive control ----------------------------------------------------------------
start_ctl
eq "control: CapAmb" "$(ctl_field CapAmb)" "$CAP_READ_SEARCH"
eq "control: CapEff" "$(ctl_field CapEff)" "$CAP_READ_SEARCH"
eq "control: CapBnd" "$(ctl_field CapBnd)" "$CAP_READ_SEARCH"
eq "control: NoNewPrivs" "$(ctl_field NoNewPrivs)" "1"
if [[ -e /sys/class/dmi/id/product_serial ]]; then
    eq "control: 1-byte read of the 0400 DMI serial file exit code" \
       "$(as_root cat "$ctl_state/serial_rc" 2>/dev/null || echo missing)" "0"
else
    echo "NOTE: no /sys/class/dmi/id/product_serial on this host; serial-read control not run"
fi

# --- (ii) snapshot success over a pre-existing loose directory ---------------------------
write_fixtures
seed_stale "$ctl_state"
start_ctl
eq "snapshot: dmi/ owner and mode" "$(perm "$ctl_state/dmi")" "700 $SVC_USER"
for n in DMI smbios_entry_point; do
    eq "snapshot: $n owner and mode" "$(perm "$ctl_state/dmi/$n")" "600 $SVC_USER"
    if as_root cmp -s "$run_dir/src/$n" "$ctl_state/dmi/$n"; then
        pass "snapshot: $n identical to source"
    else
        fail "snapshot: $n identical to source"
    fi
done
absent "snapshot: dmi.tmp is absent" "$ctl_state/dmi.tmp"

# --- (iii) refresh with a partial source removes the existing pair -----------------------
as_root rm -f "$run_dir/src/DMI"
start_ctl
absent "partial source: dmi/ removed (all-or-none)" "$ctl_state/dmi"
absent "partial source: dmi.tmp removed" "$ctl_state/dmi.tmp"

# --- (iv) documented opt-out, taken verbatim from the upgrading guide --------------------
# The second ```ini block under the opt-out heading is the capability-and-snapshot opt-out.
optout=$(awk '
    /^[[:space:]]*```ini/ {inblk = 1; blk = ""; next}
    /^[[:space:]]*```/    {if (inblk && blk ~ /rm -rf/) {printf "%s", blk; exit} inblk = 0; next}
    inblk                 {sub(/^[[:space:]]+/, ""); blk = blk $0 "\n"}
' "$UPGRADING_DOC")
if [[ $optout == *'AmbientCapabilities='* && $optout == *'ExecStartPre=-/bin/rm -rf /var/lib/yuzu-agent/dmi'* ]]; then
    pass "opt-out text found in upgrading guide"
else
    fail "opt-out text found in upgrading guide"
fi
printf '%s' "${optout//\/var\/lib\/yuzu-agent/\/var\/lib\/$ctl}" |
    as_root tee "$sysd/$ctl.service.d/50-optout.conf" >/dev/null
as_root systemctl daemon-reload
write_fixtures
seed_stale "$ctl_state"
start_ctl
eq "opt-out: CapAmb" "$(ctl_field CapAmb)" "$CAP_NONE"
eq "opt-out: CapEff" "$(ctl_field CapEff)" "$CAP_NONE"
absent "opt-out: existing snapshot removed" "$ctl_state/dmi"
as_root rm -f "$sysd/$ctl.service.d/50-optout.conf"
as_root systemctl daemon-reload

# --- agent unit: the real binary ---------------------------------------------------------
agent_state=/var/lib/$id
seed_stale "$agent_state"
if ! as_root systemctl start "$id.service"; then
    fail "agent unit failed to start"
fi

ready=0
for _ in $(seq 1 120); do
    if as_root grep -qiE 'Loaded .* plugin' "$run_dir/agent.log" 2>/dev/null; then ready=1; break; fi
    as_root systemctl is-active --quiet "$id.service" || break
    sleep 0.5
done
if [[ $ready -ne 1 ]]; then
    fail "agent never finished loading plugins within 60s"
    echo "--- agent log tail (startup only) ---" >&2
    as_root tail -n 20 "$run_dir/agent.log" 2>/dev/null | grep -viE 'serial|uuid' >&2 || true
else
    pid=$(as_root systemctl show -p MainPID --value "$id.service")
    if [[ -z $pid || $pid == 0 ]] || [[ ! -r /proc/$pid/status ]]; then
        fail "agent main process not found"
    else
        field() { awk -v k="$1:" '$1 == k {print $2}' "/proc/$pid/status"; }
        eq "agent: CapEff" "$(field CapEff)" "$CAP_READ_SEARCH"
        eq "agent: CapPrm" "$(field CapPrm)" "$CAP_READ_SEARCH"
        eq "agent: CapBnd" "$(field CapBnd)" "$CAP_READ_SEARCH"
        eq "agent: NoNewPrivs" "$(field NoNewPrivs)" "1"

        threads=0 bad=0
        for t in /proc/"$pid"/task/*/status; do
            inh=$(awk '$1 == "CapInh:" {print $2}' "$t" 2>/dev/null || true)
            amb=$(awk '$1 == "CapAmb:" {print $2}' "$t" 2>/dev/null || true)
            [[ -n $inh ]] || continue   # thread exited while scanning
            threads=$((threads + 1))
            if [[ $inh != "$CAP_NONE" || $amb != "$CAP_NONE" ]]; then
                bad=$((bad + 1))
                [[ $bad -le 3 ]] &&   # first few only; the summary below carries the count
                    echo "FAIL: thread $(basename "$(dirname "$t")") CapInh=$inh CapAmb=$amb" >&2
            fi
        done
        if [[ $threads -gt 0 && $bad -eq 0 ]]; then
            pass "agent: CapInh and CapAmb are 0 on all $threads threads"
        else
            fail "agent: CapInh/CapAmb not cleared (threads checked $threads, offenders $bad)"
        fi

        if [[ -e /sys/firmware/dmi/tables/DMI ]]; then
            for n in DMI smbios_entry_point; do
                if as_root cmp -s "/sys/firmware/dmi/tables/$n" "$agent_state/dmi/$n"; then
                    pass "real source: $n copied byte-identically"
                else
                    fail "real source: $n copied byte-identically"
                fi
                eq "real source: $n owner and mode" "$(perm "$agent_state/dmi/$n")" "600 $SVC_USER"
            done
            eq "real source: dmi/ owner and mode" "$(perm "$agent_state/dmi")" "700 $SVC_USER"
        else
            absent "no DMI on this host: stale snapshot removed" "$agent_state/dmi"
        fi
    fi
fi
as_root systemctl stop "$id.service" >/dev/null 2>&1 || true

if [[ $FAILS -ne 0 ]]; then
    echo "agent-unit-capcheck: $FAILS check(s) FAILED" >&2
    exit 1
fi
echo "agent-unit-capcheck: all checks passed"
