#!/usr/bin/env bash
#
# Graceful-shutdown smoke test for the agent. Needs NO server and no Postgres.
#
# WHY THIS EXISTS
# ---------------
# Nothing in the unit suites, the integration script, or CI failed if graceful shutdown broke
# completely. scripts/integration-test.sh kills agents in an EXIT trap (kill -> sleep 1 ->
# kill -9) and never asserts an exit code. Several shutdown defects shipped and were caught only
# by a human sending a signal by hand:
#   * pipe2(O_CLOEXEC|O_NONBLOCK) set O_NONBLOCK on BOTH ends, so the watcher's read() returned
#     EAGAIN, the thread exited, and SIGTERM silently stopped being graceful. Nothing LOOKED
#     broken -- the process still died, via the default disposition.
#   * a nested lock_guard self-deadlocked Agent::stop(): the agent hung on EVERY SIGTERM while
#     the unit suites and TSan stayed green.
#   * the signal handlers were installed even when the watcher failed to start, which SWALLOWED
#     the signal and left the agent unkillable by SIGTERM.
#   * Register had no deadline and no cancellable context, so against a server that accepted TCP
#     and never answered, SIGTERM cancelled everything EXCEPT the RPC main was parked in.
#
# THREE RULES, all learned the hard way
# -------------------------------------
# 1. WAIT FOR RUN-LOOP ENTRY, don't just sleep. If the agent is still booting, run()'s ScopeExit
#    performs the teardown and the ShutdownWatcher is never exercised -- the test would pass
#    while the signal path is dead.
#
# 2. EVERY ASSERTION MUST BE ABLE TO FAIL. This file has now twice contained an assertion that
#    could not. First it took a single expected code and RE-RAN the case with the opposite
#    expectation on mismatch (a broken escalation failed run 1, passed run 2, reported PASS).
#    Then it accepted the SET {0,1} for the escalation case -- and BOTH members were reachable by
#    a defect: a broken escalation exits 0, and (at the time) the shutdown deadline was still
#    deferred to a later PR and had no exit code of its own to collide with 1. #2233 item 3 has
#    since landed that deadline as exit code 4, not 1 -- this harness does not yet exercise it.
#    An assertion that accepts the failure mode is a green light wired to the bug.
#    (governance: quality-engineer, twice.)
#
# 3. A TIMEOUT MUST BE JUSTIFIED AGAINST A MEASURED BASELINE. An earlier harness called the agent
#    "hung" if it was still alive 7-8s after SIGTERM -- while a healthy shutdown took 8.6s. Every
#    slow-but-correct shutdown scored as a permanent wedge, and a whole phantom bug (root cause,
#    repro, proposed fix) was built on top of it. "Still alive after N seconds" is a hang ONLY if
#    N exceeds the known-good time.
#
# MEASURED BASELINE -- re-measured on THIS rig, 2026-07-14, on the branch head, because a number
# you inherited is not a number you measured (Linux, idle, 49 plugins):
#     run loop, dead port, single SIGTERM ............ 3-4s    (n=5)
#     parked in Register vs a BLACK-HOLE server ...... 8-9s    (n=4; 18.0s BEFORE the Register fix)
#     second-signal escalation ....................... ~1s     (n=4)
#
# NOTE: an earlier note in this file claimed 3.0s for the black-hole case. It does not reproduce
# here -- the honest figure on this rig is 8-9s, and the bound below is set against THAT, not
# against the inherited number. The fix it proves is still enormous (18.0s -> 8.5s), and the bound
# still discriminates: 15s sits well below the 18.0s regression and well above the 9s healthy case.
#
# HANG_TIMEOUT is 30s -- above every one of those. It is a HANG DETECTOR, not a latency assertion.
# The per-case latency bounds below ARE latency assertions and are set individually.
#
# WHAT THIS DOES *NOT* COVER, so nobody reads a pass as more than it is: the agent never
# REGISTERS here, so the heartbeat / OTA / daily-sync threads (spawned only after a successful
# Register) never exist. A connected agent's teardown is longer -- 0.5-8.5s measured. Do not quote
# these numbers as production shutdown latency. (governance: consistency-auditor.)
# Also NOT covered: the PID-1 hard-exit posture (main.cpp on_signal_hard_exit) -- this harness
# never runs the agent as pid 1, and neither does any CI leg, so the pid-1 discard semantics
# the fallback exists for are verified by inspection only. (governance gate round: QE-4.)
set -uo pipefail

AGENT=${YUZU_AGENT_BIN:-build-linux/agents/core/yuzu-agent}
PLUGINS=${YUZU_PLUGIN_DIR:-build-linux/agents/plugins}

# THE TEST'S HANG DETECTOR, AND IT MUST NOT SHARE A NAME WITH A PRODUCT KNOB. This was
# YUZU_SHUTDOWN_TIMEOUT -- a name the agent itself may take for a product knob. The agent is a
# CHILD of this script and inherits the environment, so a test knob sharing a product knob's name
# silently RECONFIGURES THE SYSTEM UNDER TEST. Keep the test's knob in its own namespace.
HANG_TIMEOUT=${YUZU_SMOKE_TIMEOUT:-30}

# The second-signal escalation leaves without unwinding via _exit(1) / TerminateProcess(...,1), so
# its code is 1.
#
# BUT 1 IS NOW OVERLOADED THREE WAYS, AND THE OLD SCOPING ARGUMENT HERE WAS FALSE. It used to say
# "every case reaches the run loop, and a startup failure never does, so a 1 can only be the
# escalation". Both halves broke: a reconnect-path thread-pool exhaustion now sets startup_failed
# from INSIDE the run loop, and -- worse for this suite -- a watcher that fails to CONSTRUCT (fd
# pressure, i.e. exactly a loaded 4-runner shared box) installs a degrade handler that exits 1 on
# the FIRST signal. In that state a COMPLETELY BROKEN escalation would still exit 1 and case 2
# would go green for the wrong reason: a green light wired to the bug, which is rule 2 of this
# file's own header, violated by a later commit.
#
# So every case now ALSO asserts the watcher was live (assert_watcher_live below). If it was not,
# the run is void -- not passed. (governance: consistency-auditor.)
readonly RC_SECOND_SIGNAL=1   # operator sent a second SIGINT/SIGTERM during teardown

# A FIXED PORT IS A CROSS-JOB SHARED RESOURCE ON A SHARED RUNNER, and 59999 -- the value this
# script used -- is INSIDE the Linux ephemeral range (32768-60999). A concurrent job binding port
# 0 can be handed it, at which point this test's agent issues a Register RPC INTO ANOTHER JOB'S
# PROCESS. Both self-hosted pools run several runner agents as ONE OS identity on ONE box, so this
# is the same class as the RegistryGuard family (#1871): salt the identifier per process.
# 61000-64999 sits above the ephemeral range. (governance: security-guardian.)
# `ss` is Linux-only. On macOS the pipeline failed, `grep -q` failed, and the `||` branch handed
# back the FIRST candidate WITHOUT checking it -- the guard was silently inert on the one platform
# where it was never tested. Probe with whatever the host actually has.
_port_in_use() {
    local p=$1
    if command -v ss >/dev/null 2>&1; then
        ss -lnt 2>/dev/null | grep -q ":$p "
    elif command -v lsof >/dev/null 2>&1; then
        lsof -nP -iTCP:"$p" -sTCP:LISTEN >/dev/null 2>&1
    else
        netstat -an 2>/dev/null | grep -q "[.:]$p .*LISTEN"
    fi
}
pick_dead_port() {
    local p
    for _ in $(seq 1 20); do
        p=$(( 61000 + (($$ + RANDOM) % 4000) ))
        _port_in_use "$p" || { echo "$p"; return 0; }
    done
    echo "could not find a free port above the ephemeral range" >&2
    return 1
}
DEAD_PORT=$(pick_dead_port) || exit 2

rc=0
[[ -x $AGENT ]] || { echo "agent binary not found: $AGENT" >&2; exit 2; }

_pids_file=$(mktemp "${TMPDIR:-/tmp}/yuzu-shutdown-pids.XXXXXX")
_blackhole_pid=""

# Never leak an agent onto a shared CI box: a cancelled job would otherwise orphan one with a
# --data-dir in a since-deleted tmpdir. Kills only PIDs THIS script started.
#
# AND IT CHECKS IDENTITY BEFORE KILLING. A recorded PID that has already exited can be REUSED by
# the OS, and `kill -9` on a recycled PID would kill an unrelated process -- on these shared
# runners, plausibly another CI job's. Confirm the PID is still OUR agent before signalling it.
# (governance: security-guardian.)
_kill_if_ours() {
    local p=$1 comm ppid
    [[ -n $p ]] || return 0
    kill -0 "$p" 2>/dev/null || return 0
    # BSD `ps -o comm=` prints the FULL PATH (basename is `ucomm`), so a bare name match never
    # fired on macOS and the trap leaked every agent and the black-hole listener. Strip the path.
    comm=$(ps -o comm= -p "$p" 2>/dev/null | tr -d '[:space:]')
    comm=${comm##*/}
    # AND require it to still be OUR child. A recorded PID that has already exited can be REUSED,
    # and `python3` is one of the commonest comms on a CI box -- on these shared runners the
    # victim of a mistaken kill is plausibly another job. Every PID we record is a background
    # child of THIS shell, so ppid == $$ is exact.
    ppid=$(ps -o ppid= -p "$p" 2>/dev/null | tr -d '[:space:]')
    [[ "$ppid" == "$$" ]] || return 0
    case "$comm" in
        yuzu-agent|python3|python) kill -9 "$p" 2>/dev/null ;;
        *) ;; # PID reused by something else -- leave it alone
    esac
}
cleanup() {
    local p
    while read -r p; do _kill_if_ours "$p"; done < "$_pids_file"
    _kill_if_ours "$_blackhole_pid"
    rm -f "$_pids_file"
}
# The INT/TERM traps EXIT. Without the explicit exit, bash runs cleanup and then CARRIES ON with
# the next command in the script -- reaping the agents and then continuing to test against them.
trap cleanup EXIT
trap 'cleanup; exit 130' INT
trap 'cleanup; exit 143' TERM

# A server that completes the TCP handshake and then NEVER ANSWERS. This is the shape that wedged
# the agent for 18s: Register had no deadline and no cancellable ClientContext, so SIGTERM
# cancelled subscribe/heartbeat/sync (all still null -- they are not published until Register
# SUCCEEDS) and main stayed parked in the one RPC nothing could reach. It binds port 0 and reports
# the port through a file, so it cannot collide with a concurrent job by construction.
#
# SETS GLOBALS; DOES NOT ECHO. `port=$(start_blackhole)` would run this in a SUBSHELL, and the
# backgrounded python would inherit that subshell's stdout -- so the command substitution would
# block forever waiting for a pipe that a deliberately-immortal listener never closes. The
# listener's stdio is detached for the same reason.
BLACKHOLE_PORT=""
start_blackhole() {
    local portfile; portfile=$(mktemp "${TMPDIR:-/tmp}/yuzu-blackhole.XXXXXX")
    python3 - "$portfile" >/dev/null 2>&1 <<'PY' &
import socket, sys, time
s = socket.socket()
s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
s.bind(("127.0.0.1", 0))
s.listen(16)
with open(sys.argv[1], "w") as f:
    f.write(str(s.getsockname()[1]))
    f.flush()
held = []            # keep the accepted sockets open: accept, then say nothing, forever
while True:
    try:
        c, _ = s.accept()
        held.append(c)
    except Exception:
        time.sleep(0.1)
PY
    _blackhole_pid=$!
    disown "$_blackhole_pid" 2>/dev/null || true  # else bash prints a 'Killed' banner when we reap it
    local i
    BLACKHOLE_PORT=""
    for ((i = 0; i < 100; i++)); do
        BLACKHOLE_PORT=$(cat "$portfile" 2>/dev/null)
        [[ -n $BLACKHOLE_PORT ]] && break
        sleep 0.1
    done
    rm -f "$portfile"
    [[ -n $BLACKHOLE_PORT ]] || { echo "black-hole listener never bound" >&2; return 1; }
    return 0
}

# run_case <name> <signals> <expect_rc> <max_secs> <server>
#   expect_rc  EXACTLY ONE code. No sets: see rule 2.
#   max_secs   a real latency assertion, justified per-case against the baseline above.
#   server     "dead" (nothing listening) | "blackhole" (accepts, never answers)
run_case() {
    local name=$1 signals=$2 expect_rc=$3 max_secs=$4 server=${5:-dead}
    local port=$DEAD_PORT ready_pat="reconnect"
    if [[ $server == blackhole ]]; then
        start_blackhole || return 1
        port=$BLACKHOLE_PORT
        # It never reaches the reconnect loop -- it is stuck INSIDE Register. Plugins-loaded is
        # the last thing logged before the RPC, and is what proves boot finished.
        ready_pat="Loaded .* plugin"
    fi

    # BSD/macOS mktemp REQUIRES a template -- a bare `mktemp -d` exits with a usage error, so this
    # script simply did not run on macOS.
    local work; work=$(mktemp -d "${TMPDIR:-/tmp}/yuzu-shutdown.XXXXXX")
    local log="$work/agent.log"

    "$AGENT" --server "127.0.0.1:$port" --no-tls \
             --data-dir "$work" --plugin-dir "$PLUGINS" >"$log" 2>&1 &
    local pid=$!
    echo "$pid" >> "$_pids_file" # so the EXIT trap can reap it if we are cancelled

    # RULE 1: wait for run-loop entry. A boot-time signal is torn down by run()'s ScopeExit and
    # never exercises the watcher, so a test that signals during boot proves nothing.
    local booted=0 i
    for ((i = 0; i < 120; i++)); do
        if grep -qiE "$ready_pat" "$log" 2>/dev/null; then booted=1; break; fi
        kill -0 "$pid" 2>/dev/null || break
        sleep 0.5
    done
    if [[ $booted -ne 1 ]]; then
        echo "FAIL [$name]: agent never reached its run loop" >&2
        tail -15 "$log" >&2
        _kill_if_ours "$pid"; wait "$pid" 2>/dev/null; rm -rf "$work"
        _kill_if_ours "$_blackhole_pid"; _blackhole_pid=""
        return 1
    fi
    [[ $server == blackhole ]] && sleep 1   # let it get properly parked inside Register

    local start; start=$SECONDS
    for ((i = 0; i < signals; i++)); do kill -TERM "$pid" 2>/dev/null; sleep 0.2; done

    local alive=1
    for ((i = 0; i < HANG_TIMEOUT * 10; i++)); do
        kill -0 "$pid" 2>/dev/null || { alive=0; break; }
        sleep 0.1
    done

    if [[ $alive -eq 1 ]]; then
        echo "FAIL [$name]: still alive ${HANG_TIMEOUT}s after SIGTERM — WEDGED" >&2
        tail -15 "$log" >&2
        _kill_if_ours "$pid"; wait "$pid" 2>/dev/null; rm -rf "$work"
        _kill_if_ours "$_blackhole_pid"; _blackhole_pid=""
        return 1
    fi

    wait "$pid"; local got=$?
    local took=$((SECONDS - start))

    # THE WATCHER MUST HAVE BEEN LIVE, or the exit code proves nothing. A degraded watcher makes the
    # agent exit 1 on the FIRST signal, which would make a broken escalation look like a pass.
    if grep -qi "shutdown watcher unavailable" "$log" 2>/dev/null; then
        echo "VOID [$name]: the shutdown watcher failed to construct — the agent was in its degraded" >&2
        echo "  (exit-on-first-signal) posture, so this case's exit code proves NOTHING. Not a pass." >&2
        tail -5 "$log" >&2
        rm -rf "$work"
        return 1
    fi
    rm -rf "$work"
    _kill_if_ours "$_blackhole_pid"; _blackhole_pid=""

    # ONE code, and a latency bound. 143 = SIGTERM's default disposition (the handler never ran,
    # so shutdown was never graceful). 134 = std::terminate. 141 = SIGPIPE from the shutdown pipe
    # itself. 139 = segv. Each is a real defect this suite exists to catch, and each now FAILS
    # instead of being absorbed into an accepted set.
    if [[ $got -ne $expect_rc ]]; then
        echo "FAIL [$name]: exit $got, expected exactly $expect_rc" >&2
        echo "  (143=handler never ran  134=terminate  141=SIGPIPE  139=segv)" >&2
        tail -15 "$log" >&2
        return 1
    fi
    if (( took > max_secs )); then
        echo "FAIL [$name]: rc=$got but took ${took}s, bound is ${max_secs}s" >&2
        tail -15 "$log" >&2
        return 1
    fi

    echo "ok [$name]: rc=$got in ${took}s (bound ${max_secs}s)"
    return 0
}

# A fully-booted agent must shut down gracefully via the ShutdownWatcher, and exit 0.
# Bound: 15s against a measured 3.5s dead-port teardown.
run_case "single SIGTERM in the run loop" 1 0 15 dead || rc=1

# The SECOND signal must escalate and leave immediately. This is NOT racy on this configuration
# and must not be written as though it were: the healthy dead-port teardown is 3-4s and the second
# signal lands at 0.2s, so the escalation always wins by an order of magnitude. An earlier version
# accepted the SET {0,1} here -- and 0 is exactly what a COMPLETELY BROKEN escalation returns, so
# the assertion could not fail. Exactly one code, and a latency bound.
run_case "double SIGTERM escalates" 2 $RC_SECOND_SIGNAL 5 dead || rc=1

# THE REGRESSION TEST FOR THE 18-SECOND WEDGE -- AND *ONLY* THAT.
#
# IT DOES NOT COVER THE PUBLISH-THEN-RE-CHECK ORDERING FIX, and an earlier version of this comment
# implied it did. A reviewer mutation-proved otherwise: delete the `stop_requested_` re-check after
# the CtxSlot publish in agent.cpp and ALL THREE CASES STILL PASS. Of course they do -- this script
# signals ~1s after boot, and that race window is a few INSTRUCTIONS wide. What this case really
# covers is the Register deadline + cancellable context in steady state, which is the 18.0s -> 8-9s
# fix. The ordering fix needs a synchronisation hook (a stub RPC that blocks exactly at publish
# time) and has NO coverage today. Say so rather than let a green case imply otherwise.
# (governance: quality-engineer.) Against a server that accepts TCP and never
# answers, the agent parks in Register. Before the cancellable CtxSlot + Register deadline, SIGTERM
# could not reach that RPC at all and shutdown took 18.0s. Measured here now: 8-9s (n=4).
# Bound 15s -- above the measured 9s with room for a slower CI box, and below the 18.0s regression
# it exists to catch. This case is the ONLY coverage of the Register deadline + CtxSlot: the other
# two point at a dead port, where Register fails instantly and none of that code is reached.
run_case "SIGTERM while parked in Register (black-hole server)" 1 0 15 blackhole || rc=1

[[ $rc -eq 0 ]] && echo "PASS: agent graceful shutdown" || echo "FAIL: agent graceful shutdown" >&2
exit $rc
