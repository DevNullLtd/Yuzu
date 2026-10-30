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
#   shipped files (static):
#     * the unit's helper path is the path build-deb.sh and yuzu-agent.spec install the helper
#       to (with its mode); the test drop-ins run the unit's own two ExecStartPre lines
#   control unit (a plain shell child, oneshot):
#     * CapAmb = CapEff = CapBnd = 0x4 and NoNewPrivs = 1   (positive control: proves the
#       "child holds nothing" assertions below can fail)
#     * a 1-byte read of the 0400 DMI serial file succeeds (when the file exists)
#     * snapshot success over a pre-existing loose directory with a stale dmi.tmp (0755 -> 0700,
#       files 0600, byte-identical to the source, no dmi.tmp left)
#     * snapshot refresh with a partial source removes the pair (all-or-none, never stale)
#     * both documented opt-outs (taken verbatim from docs/user-manual/upgrading.md): the
#       capability-only one drops the capability and still publishes the snapshot; the
#       capability-and-snapshot one drops the capability and removes the snapshot
#     * the snapshot helper, run directly: no arguments, a state dir the account cannot write,
#       and a non-regular source each exit 0 with a stderr diagnostic and publish nothing
#   agent unit (the real binary):
#     * CapEff = CapPrm = CapBnd = 0x4 exactly, NoNewPrivs = 1
#     * every thread has CapInh = CapAmb = 0 once plugins have loaded
#     * the startup log line reports the same effective mask as /proc
#     * with capset denied by seccomp (SystemCallFilter=~capset) the agent refuses to start:
#       non-zero exit, the exact refusal line, no plugin loaded (the fail-closed path)
#     * the real firmware tables, when the host has them, are copied byte-identically; on a
#       host with none, a stale snapshot is removed and the agent still starts
#
# NOT RUN, AND WHY. No child process is exec'd by the agent here: the check is server-less, so
# no instruction can be dispatched to make it spawn one. A child's capabilities follow from the
# per-thread CapInh = CapAmb = 0 assertion by the kernel rule (capabilities(7)): a non-root exec
# of a file without file capabilities gives P' = (I & F_I) | A' = 0. The EINVAL branch of
# clear_child_capabilities (a kernel without ambient capability support) cannot be injected by
# a unit setting and is covered by reading only.
#
# The test drop-ins override paths (and, for the refusal case, the seccomp filter and log file)
# only. A guard asserts the path drop-ins contain no User/Group/NoNewPrivileges/Capability/
# Protect/Private directive, so the shipped hardening is what runs.
#
# This prints PASS/FAIL lines and capability hex only. It never prints firmware bytes or
# serial numbers (CI logs are public).
#
# Inputs (mirroring agent-shutdown-smoke.sh):
#   YUZU_AGENT_BIN      agent binary           (default build-linux/agents/core/yuzu-agent)
#   YUZU_PLUGIN_DIR     built plugins          (default build-linux/agents/plugins)
#   YUZU_AGENT_LIB_DIR  dir holding libyuzu_agent_core.so (default: found under the build dir)
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
DEB_SCRIPT=$REPO_ROOT/deploy/packaging/debian/build-deb.sh
RPM_SPEC=$REPO_ROOT/deploy/packaging/rpm/yuzu-agent.spec
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
for f in "$UNIT_FILE" "$HELPER" "$UPGRADING_DOC" "$DEB_SCRIPT" "$RPM_SPEC"; do
    [[ -f $f ]] || { echo "FAIL: missing input file: $f" >&2; exit 1; }
done

# The library itself only: meson also writes libyuzu_agent_core.so.p/libyuzu_agent_core.so.symbols,
# a regular file that a bare 'libyuzu_agent_core.so*' glob matches, and 'find -quit' can return it
# before the library (the agent then fails to load in the unit).
lib_match=( -name libyuzu_agent_core.so \( -type f -o -type l \) )
LIB_DIR=${YUZU_AGENT_LIB_DIR:-}
if [[ -z $LIB_DIR ]]; then
    build_root=${AGENT%/agents/core/*}
    found=$(find "$build_root" "${lib_match[@]}" -print -quit 2>/dev/null || true)
    [[ -n $found ]] && LIB_DIR=$(dirname "$found")
fi
[[ -n $LIB_DIR ]] || { echo "FAIL: libyuzu_agent_core.so not found; set YUZU_AGENT_LIB_DIR" >&2; exit 1; }

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

# --- the shipped unit's ExecStartPre lines, and where the packages install the helper ------
# The test drop-ins run the SHIPPED ExecStartPre lines, so a typo in their flags, interpreter,
# helper path or arguments fails here instead of passing CI: only the two paths are substituted.
die() { echo "FAIL: $1" >&2; exit 1; }
[[ $(grep -c '^ExecStartPre=' "$UNIT_FILE" || true) -eq 2 ]] ||
    die "the shipped unit must have exactly two ExecStartPre lines (pre-clean, then helper)"
shipped_clean=$(grep '^ExecStartPre=' "$UNIT_FILE" | sed -n 1p)
shipped_helper=$(grep '^ExecStartPre=' "$UNIT_FILE" | sed -n 2p)
sub_paths() { sed -e "s|/var/lib/yuzu-agent|/var/lib/$1|g" -e "s|/usr/share/yuzu/scripts/|$run_dir/|g"; }
pre_clean() { printf '%s\n' "$shipped_clean" | sub_paths "$1"; }
pre_helper() { printf '%s\n' "$shipped_helper" | sub_paths "$1"; }
for u in "$id" "$ctl"; do
    [[ $(pre_clean "$u") == *"/var/lib/$u/dmi"* && $(pre_helper "$u") == *" $run_dir/yuzu-agent-dmi-snapshot.sh /var/lib/$u "* ]] ||
        die "shipped ExecStartPre lines do not point at /var/lib/yuzu-agent and /usr/share/yuzu/scripts/; the test would run the real paths"
done

unit_helper=$(sed -n 's|^ExecStartPre=-+/bin/bash \([^ ]*\) .*|\1|p' "$UNIT_FILE")
rpm_helper="%{_datadir}${unit_helper#/usr/share}"
# Comment lines are dropped first, so a commented-out cp or chmod cannot keep this green.
deb_code=$(grep -v '^[[:space:]]*#' "$DEB_SCRIPT" || true)
deb_cp="deploy/systemd/${unit_helper##*/}\" \"\$PKG${unit_helper%/*}/\""
deb_chmod="chmod 0755 \"\$PKG$unit_helper\""
if [[ $unit_helper == /usr/share/*/yuzu-agent-dmi-snapshot.sh &&
      $deb_code == *"$deb_cp"* && $deb_code == *"$deb_chmod"* ]]; then
    pass "unit helper path ($unit_helper) is copied and installed 0755 by build-deb.sh"
else
    fail "unit helper path ('$unit_helper') is not copied and installed 0755 by build-deb.sh"
fi
if [[ $unit_helper == /usr/share/* ]] &&
   grep -qF "install -D -m 0755 %{_sourcedir}/${unit_helper##*/} %{buildroot}$rpm_helper" "$RPM_SPEC" &&
   grep -qxF "$rpm_helper" "$RPM_SPEC"; then
    pass "unit helper path ($unit_helper) is installed 0755 and listed by yuzu-agent.spec"
else
    fail "unit helper path ('$unit_helper') is not installed 0755 and listed by yuzu-agent.spec"
fi

# --- account and staging -----------------------------------------------------------------
getent passwd "$SVC_USER" >/dev/null ||
    as_root useradd --system --user-group --no-create-home --shell /usr/sbin/nologin "$SVC_USER" ||
    getent passwd "$SVC_USER" >/dev/null   # a concurrent runner may have created it first

# /tmp is unusable here: the unit sets PrivateTmp. /run/$id is root 0755 and readable by the account.
as_root install -d -m 0755 "$run_dir" "$run_dir/bin" "$run_dir/lib" "$run_dir/plugins" "$run_dir/src"
as_root install -m 0755 "$AGENT" "$run_dir/bin/yuzu-agent"
find "$LIB_DIR" -maxdepth 1 "${lib_match[@]}" -print0 |
    as_root xargs -0 -r install -m 0755 -t "$run_dir/lib"
# The name the agent links against (its NEEDED entry). Without it the unit fails to load the
# binary and every assertion that needs the real agent would otherwise be reached too late.
[[ -e $run_dir/lib/libyuzu_agent_core.so ]] ||
    { echo "FAIL: libyuzu_agent_core.so was not staged from '$LIB_DIR'; set YUZU_AGENT_LIB_DIR" >&2; exit 1; }
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
$(pre_clean "$id")
$(pre_helper "$id")
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
$(pre_clean "$ctl")
$(pre_helper "$ctl") $run_dir/src
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
seed_stale() { # $1 = state dir; leaves a loose 0755 dmi/ with a stale file and a stale dmi.tmp (interrupted staging)
    as_root install -d -o "$SVC_USER" -g "$SVC_USER" -m 0755 "$1" "$1/dmi" "$1/dmi.tmp"
    printf 'stale' | as_root tee "$1/dmi/DMI" >/dev/null
    as_root chown "$SVC_USER:$SVC_USER" "$1/dmi/DMI"
}
start_ctl() {
    as_root rm -f "$ctl_state/status.txt" "$ctl_state/serial_rc"
    # The shipped unit rate-limits starts (StartLimitBurst=5 per 300s); this runs more than 5.
    as_root systemctl reset-failed "$ctl.service" >/dev/null 2>&1 || true
    as_root systemctl start "$ctl.service" || fail "control unit failed to start"
}
ctl_field() { as_root cat "$ctl_state/status.txt" 2>/dev/null | awk -v k="$1:" '$1 == k {print $2}'; }
perm() { as_root stat -c '%a %U' "$1" 2>/dev/null || echo "missing"; }
check_snapshot_published() { # $1 = label; dmi/ holds both fixtures, owned and moded as documented
    eq "$1: dmi/ owner and mode" "$(perm "$ctl_state/dmi")" "700 $SVC_USER"
    for n in DMI smbios_entry_point; do
        eq "$1: $n owner and mode" "$(perm "$ctl_state/dmi/$n")" "600 $SVC_USER"
        if as_root cmp -s "$run_dir/src/$n" "$ctl_state/dmi/$n"; then
            pass "$1: $n identical to source"
        else
            fail "$1: $n identical to source"
        fi
    done
    absent "$1: dmi.tmp is absent" "$ctl_state/dmi.tmp"
}
# ini_block NEED LACK: the first ```ini block of the upgrading guide that contains NEED and not
# LACK (LACK empty = no exclusion), verbatim apart from leading indentation.
ini_block() {
    awk -v need="$1" -v lack="$2" '
        /^[[:space:]]*```ini/ {inblk = 1; blk = ""; next}
        /^[[:space:]]*```/    {if (inblk && index(blk, need) && (lack == "" || !index(blk, lack))) {printf "%s", blk; exit} inblk = 0; next}
        inblk                 {sub(/^[[:space:]]+/, ""); blk = blk $0 "\n"}
    ' "$UPGRADING_DOC"
}
apply_optout() { # $1 = ini text from the guide; its state paths are pointed at the control unit's
    printf '%s\n' "${1//\/var\/lib\/yuzu-agent/\/var\/lib\/$ctl}" |
        as_root tee "$sysd/$ctl.service.d/50-optout.conf" >/dev/null
    as_root systemctl daemon-reload
}
remove_optout() {
    as_root rm -f "$sysd/$ctl.service.d/50-optout.conf"
    as_root systemctl daemon-reload
}

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

# --- (ii) snapshot success over a loose directory and a stale dmi.tmp --------------------
write_fixtures
seed_stale "$ctl_state"
start_ctl
check_snapshot_published "snapshot"

# --- (iii) refresh with a partial source removes the existing pair -----------------------
as_root rm -f "$run_dir/src/DMI"
start_ctl
absent "partial source: dmi/ removed (all-or-none)" "$ctl_state/dmi"
absent "partial source: dmi.tmp removed" "$ctl_state/dmi.tmp"

# --- (iv) the two documented opt-outs, taken verbatim from the upgrading guide -----------
# The guide's capability-only block (AmbientCapabilities= alone) keeps the snapshot; its
# capability-and-snapshot block (the one with the rm -rf line) removes it.
optout_cap=$(ini_block 'AmbientCapabilities=' 'rm -rf')
optout_both=$(ini_block 'rm -rf' '')
if [[ $optout_cap == *'AmbientCapabilities='* ]]; then
    pass "capability-only opt-out text found in upgrading guide"
else
    fail "capability-only opt-out text found in upgrading guide"
fi
if [[ $optout_both == *'AmbientCapabilities='* && $optout_both == *'ExecStartPre=-/bin/rm -rf /var/lib/yuzu-agent/dmi'* ]]; then
    pass "capability-and-snapshot opt-out text found in upgrading guide"
else
    fail "capability-and-snapshot opt-out text found in upgrading guide"
fi

apply_optout "$optout_cap"
write_fixtures
seed_stale "$ctl_state"
start_ctl
eq "capability-only opt-out: CapAmb" "$(ctl_field CapAmb)" "$CAP_NONE"
eq "capability-only opt-out: CapEff" "$(ctl_field CapEff)" "$CAP_NONE"
check_snapshot_published "capability-only opt-out snapshot"
remove_optout

apply_optout "$optout_both"
write_fixtures
seed_stale "$ctl_state"
start_ctl
eq "opt-out: CapAmb" "$(ctl_field CapAmb)" "$CAP_NONE"
eq "opt-out: CapEff" "$(ctl_field CapEff)" "$CAP_NONE"
absent "opt-out: existing snapshot removed" "$ctl_state/dmi"
remove_optout

# --- (v) the snapshot helper's failure states, run directly as root ----------------------
# Each exits 0 with one stderr diagnostic and publishes no dmi/ and no dmi.tmp.
helper_case() { # $1 = label, $2 = expected stderr fragment, $3.. = helper arguments
    local label=$1 want=$2 err rc=0
    shift 2
    err=$(as_root bash "$run_dir/yuzu-agent-dmi-snapshot.sh" "$@" 2>&1 >/dev/null) || rc=$?
    eq "$label: exit code" "$rc" "0"
    if [[ $err == *"$want"* ]]; then
        pass "$label: stderr diagnostic"
    else
        fail "$label: stderr diagnostic (got '${err:0:120}', want '$want')"
    fi
}
write_fixtures
helper_case "helper without arguments" "usage"

as_root install -d -m 0755 "$run_dir/st-ro"   # root-owned: the account cannot create dmi.tmp in it
helper_case "helper with an unwritable state dir" "cannot create" "$run_dir/st-ro" "$SVC_USER" "$run_dir/src"
absent "unwritable state dir: dmi/ not published" "$run_dir/st-ro/dmi"
absent "unwritable state dir: dmi.tmp not left" "$run_dir/st-ro/dmi.tmp"

as_root install -d -o "$SVC_USER" -g "$SVC_USER" -m 0755 "$run_dir/st-nr"
as_root install -d -m 0755 "$run_dir/src-nr" "$run_dir/src-nr/DMI"   # DMI is a directory
as_root install -m 0644 "$run_dir/src/smbios_entry_point" "$run_dir/src-nr/smbios_entry_point"
helper_case "helper with a non-regular source" "not a readable file" "$run_dir/st-nr" "$SVC_USER" "$run_dir/src-nr"
absent "non-regular source: dmi/ not published" "$run_dir/st-nr/dmi"
absent "non-regular source: dmi.tmp removed" "$run_dir/st-nr/dmi.tmp"

# The helper's own stale-pair removal. In the unit path the shipped pre-clean line runs before
# the helper, so only a direct run shows the helper cleaning up: seed a stale dmi/ and dmi.tmp
# in an agent-owned state dir and give it a source with DMI missing.
as_root install -d -m 0755 "$run_dir/src-part"
as_root install -m 0644 "$run_dir/src/smbios_entry_point" "$run_dir/src-part/smbios_entry_point"
seed_stale "$run_dir/st-stale"
helper_case "helper over a stale pair with a partial source" "not a readable file" "$run_dir/st-stale" "$SVC_USER" "$run_dir/src-part"
absent "stale pair, partial source: stale dmi/ removed" "$run_dir/st-stale/dmi"
absent "stale pair, partial source: stale dmi.tmp removed" "$run_dir/st-stale/dmi.tmp"

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

        # The startup log line carries the effective mask the agent saw; it must equal /proc.
        cap_eff=$(field CapEff)
        logged=$(as_root sed -n 's/.*Linux capabilities: effective \(0x[0-9a-f]*\);.*/\1/p' \
                     "$run_dir/agent.log" 2>/dev/null | head -n 1)
        if [[ $logged =~ ^0x[0-9a-f]+$ && $cap_eff =~ ^[0-9a-f]{16}$ ]] &&
           [[ $((logged)) -eq $((16#$cap_eff)) ]]; then
            pass "agent: startup log reports the live effective mask ($logged)"
        else
            fail "agent: startup log line 'Linux capabilities: effective ...' (got '${logged:-none}') does not match CapEff $cap_eff"
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

# --- agent unit: fail-closed refusal -----------------------------------------------------
# Deny capset with a seccomp filter (systemd applies it last, just before execve, so its own
# capability setup is unaffected). clear_child_capabilities() then fails and the agent must
# refuse to start rather than run with inheritable/ambient capabilities children could keep.
# Its own log file: file: does not truncate and agent.log holds the earlier run.
as_root tee "$sysd/$id.service.d/60-capset-deny.conf" >/dev/null <<EOF
[Service]
SystemCallFilter=~capset
SystemCallErrorNumber=EPERM
StandardOutput=file:$run_dir/refuse.log
StandardError=file:$run_dir/refuse.log
EOF
as_root systemctl daemon-reload
as_root systemctl reset-failed "$id.service" >/dev/null 2>&1 || true
as_root systemctl start "$id.service" >/dev/null 2>&1 || true   # simple unit: returns at fork
for _ in $(seq 1 60); do
    st=$(as_root systemctl show -p ActiveState --value "$id.service")
    [[ $st == active || $st == activating ]] || break
    sleep 0.5
done
st=$(as_root systemctl show -p ActiveState --value "$id.service")
status=$(as_root systemctl show -p ExecMainStatus --value "$id.service")
# Exactly 1 (main()'s EXIT_FAILURE): a loader failure is 127 and a crash is 128+signal, and
# neither is the agent refusing.
if [[ $st == failed && $status == 1 ]]; then
    pass "refusal: agent exited 1 when capset is denied"
else
    fail "refusal: agent did not fail when capset is denied (state '$st', exit status '$status')"
fi
if as_root grep -qxF 'yuzu-agent: cannot clear inheritable/ambient capabilities; refusing to start' \
        "$run_dir/refuse.log" 2>/dev/null; then
    pass "refusal: exact refusal line written"
else
    fail "refusal: exact refusal line written"
    as_root tail -n 5 "$run_dir/refuse.log" 2>/dev/null | grep -viE 'serial|uuid' >&2 || true
fi
if as_root grep -qiE 'Loaded .* plugin' "$run_dir/refuse.log" 2>/dev/null; then
    fail "refusal: a plugin loaded after the refusal"
else
    pass "refusal: no plugin loaded"
fi
as_root systemctl stop "$id.service" >/dev/null 2>&1 || true
as_root rm -f "$sysd/$id.service.d/60-capset-deny.conf"
as_root systemctl daemon-reload

if [[ $FAILS -ne 0 ]]; then
    echo "agent-unit-capcheck: $FAILS check(s) FAILED" >&2
    exit 1
fi
echo "agent-unit-capcheck: all checks passed"
