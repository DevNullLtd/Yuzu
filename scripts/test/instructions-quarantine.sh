#!/usr/bin/env bash
# instructions-quarantine.sh — entry point for /test --instructions-quarantine.
#
# Detaches scripts/test/instructions_quarantine_survivor.py so the survivor
# outlives:
#   - Claude Code's TTY (which loses the Anthropic API during the blackout)
#   - any shell invoked via Claude's Bash tool
#   - the network blackout itself (everything it needs is localhost)
#
# DO NOT RUN ON A REMOTE / SSH-ONLY HOST. The ceremony briefly cuts ALL
# external network. If your only access path is SSH-over-the-network, you
# will lock yourself out until the un-quarantine fires (~25-30s) — and if
# the un-quarantine fails, you stay locked out until you physically reach
# the box. Run only on your local dev box.
#
# Sequence:
#   1. Probe preconditions (UAT stack reachable, agent registered)
#   2. Capture current Claude session UUID from
#      ~/.claude/projects/-Users-<user>-Yuzu/<uuid>.jsonl by mtime
#   3. Write ceremony.cfg + initial progress.json to state dir
#   4. Spawn survivor detached via `setsid nohup ... &` so it survives
#      this shell exiting
#   5. Print PID + state dir + reading-the-results instructions, exit 0.
#
# Operator workflow inside Claude Code:
#   /test --instructions-quarantine
#   ... Claude runs this script, which prints instructions
#   ... operator types /exit (Claude's API will likely time out anyway)
#   ... ~25-30s later, a new Terminal window opens with `claude --resume`
#   ... resumed Claude reads results.json and reports
#
# Usage:
#   bash scripts/test/instructions-quarantine.sh \
#       --dashboard http://localhost:8080 \
#       --user admin --password 'YuzuUatAdmin1!' \
#       --launch-resume
#
# Exit codes:
#   0  - survivor backgrounded successfully (the ceremony itself runs
#        async; operator inspects state-dir/results.json after it
#        completes)
#   2  - argument or precondition error; nothing was scheduled
#   3  - YOU MUST UN-QUARANTINE: the survivor was spawned but a prior
#        run's results.json indicates the previous release failed and
#        the firewall may still be partially closed. (Reserved — the
#        bash entry never actually exits 3 on its own; this is the
#        Python survivor's exit code, recorded for the operator.)

set -uo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"
REPO_ROOT="$(cd "$HERE/../.." && pwd)"

DASHBOARD_URL=""
USERNAME="admin"
PASSWORD=""
LAUNCH_RESUME=0
PROBE_ONLY=0
STATE_DIR_OVERRIDE=""

usage() {
    cat <<EOF
usage: $0 --dashboard URL --password PASS [options]

Required:
  --dashboard URL          Yuzu server dashboard root, e.g. http://localhost:8080
  --password PASS          admin password

Optional:
  --user NAME              admin user (default: admin)
  --launch-resume          attempt to spawn a new Terminal with
                           \`claude --resume <session>\` after the survivor
                           finishes. macOS: osascript. Other: tmux.
                           Falls back to writing the resume command to
                           state-dir/relaunch.sh if neither is available.
  --probe-only             run only the precondition probes; no firewall
                           change. Use to verify the agent has the quarantine
                           plugin loaded and the YAML reaches the right
                           plugin/action.
  --state-dir DIR          override default state dir (default:
                           /tmp/yuzu-quarantine-test)

Reads:
  ~/.claude/projects/-Users-<user>-Yuzu/<uuid>.jsonl  (most recent → session id)

Writes:
  <state-dir>/ceremony.cfg     ─ ceremony configuration
  <state-dir>/survivor.pid     ─ background survivor PID
  <state-dir>/survivor.log     ─ stdout/stderr of survivor
  <state-dir>/progress.json    ─ updated by survivor at each phase
  <state-dir>/results.json     ─ final results when survivor exits
  <state-dir>/relaunch.sh      ─ manual resume command (always written)

DO NOT RUN ON REMOTE / SSH-ONLY HOST. See the comment at the top of this
script for why.
EOF
}

while [[ $# -gt 0 ]]; do
    case "$1" in
        --dashboard)        DASHBOARD_URL="$2"; shift 2 ;;
        --user)             USERNAME="$2"; shift 2 ;;
        --password)         PASSWORD="$2"; shift 2 ;;
        --launch-resume)    LAUNCH_RESUME=1; shift ;;
        --probe-only)       PROBE_ONLY=1; shift ;;
        --state-dir)        STATE_DIR_OVERRIDE="$2"; shift 2 ;;
        -h|--help)          usage; exit 0 ;;
        *)                  echo "unknown arg: $1" >&2; usage >&2; exit 2 ;;
    esac
done

if [[ -z "$DASHBOARD_URL" || -z "$PASSWORD" ]]; then
    echo "error: --dashboard and --password are required" >&2
    usage >&2
    exit 2
fi

STATE_DIR="${STATE_DIR_OVERRIDE:-/tmp/yuzu-quarantine-test}"
mkdir -p "$STATE_DIR"

# ── Phase A: precondition probes (no firewall side effect) ───────────────

echo "[ceremony] probing UAT stack at $DASHBOARD_URL"
HTTP_CODE=$(curl -s -o /dev/null -w "%{http_code}" --max-time 5 "$DASHBOARD_URL/" 2>/dev/null || echo "000")
if [[ ! "$HTTP_CODE" =~ ^[23] ]]; then
    echo "error: dashboard not reachable (HTTP $HTTP_CODE)" >&2
    echo "       bring up UAT first: bash scripts/start-UAT.sh" >&2
    exit 2
fi

if [[ "$PROBE_ONLY" -eq 1 ]]; then
    echo "[ceremony] --probe-only: checking quarantine plugin presence via "\
"security.quarantine.status"
    bash "$HERE/instructions-tests.sh" \
        --dashboard "$DASHBOARD_URL" \
        --user "$USERNAME" \
        --password "$PASSWORD" \
        --only-id security.quarantine.status \
        --verbose
    exit $?
fi

# ── Phase B: capture Claude session id ────────────────────────────────────

# Sessions live at ~/.claude/projects/<encoded-cwd>/<uuid>.jsonl. The
# encoded-cwd directory is `-` separators replacing `/` of the project root.
PROJECT_DIR="$HOME/.claude/projects/$(echo "$REPO_ROOT" | sed 's|/|-|g')"
SESSION_FILE=""
SESSION_ID=""

if [[ -d "$PROJECT_DIR" ]]; then
    # Use macOS-compat find: print mtime + path, sort numerically, take the
    # latest. `find -printf` is not portable; fall back to stat + sort.
    SESSION_FILE=$(find "$PROJECT_DIR" -maxdepth 1 -name '*.jsonl' -type f 2>/dev/null \
                       | xargs -I {} stat -f '%m %N' {} 2>/dev/null \
                       | sort -nr | head -1 | cut -d' ' -f2-)
    if [[ -z "$SESSION_FILE" ]]; then
        # Linux stat fallback (different format)
        SESSION_FILE=$(find "$PROJECT_DIR" -maxdepth 1 -name '*.jsonl' -type f 2>/dev/null \
                           | xargs -I {} stat -c '%Y %n' {} 2>/dev/null \
                           | sort -nr | head -1 | cut -d' ' -f2-)
    fi
    if [[ -n "$SESSION_FILE" ]]; then
        SESSION_ID=$(basename "$SESSION_FILE" .jsonl)
    fi
fi

if [[ -z "$SESSION_ID" ]]; then
    echo "[ceremony] WARN: no Claude session file found in $PROJECT_DIR"
    echo "          (auto-resume will not be attempted; ceremony continues)"
fi

# ── Phase C: write ceremony.cfg + relaunch.sh ─────────────────────────────

cat > "$STATE_DIR/ceremony.cfg" <<EOF
{
  "dashboard": "$DASHBOARD_URL",
  "user": "$USERNAME",
  "session_id": "$SESSION_ID",
  "session_file": "$SESSION_FILE",
  "cwd": "$REPO_ROOT",
  "started_at_unix": $(date +%s)
}
EOF

if [[ -n "$SESSION_ID" ]]; then
    cat > "$STATE_DIR/relaunch.sh" <<EOF
#!/usr/bin/env bash
# Manual fallback: open a fresh terminal, then run this script to resume
# the Claude Code session that scheduled the ceremony.
cd "$REPO_ROOT" && exec claude --resume "$SESSION_ID"
EOF
    chmod +x "$STATE_DIR/relaunch.sh"
fi

# ── Phase D: spawn detached survivor ──────────────────────────────────────

SURVIVOR_ARGS=(
    --state-dir "$STATE_DIR"
    --dashboard "$DASHBOARD_URL"
    --user "$USERNAME"
    --password "$PASSWORD"
)
[[ -n "$SESSION_ID" ]]    && SURVIVOR_ARGS+=(--session-id "$SESSION_ID" --cwd "$REPO_ROOT")
[[ "$LAUNCH_RESUME" -eq 1 && -n "$SESSION_ID" ]] && SURVIVOR_ARGS+=(--launch-resume)

# Use `setsid` to put the survivor in its own session/process group so it
# truly survives the parent shell. Redirect stdio to a log file so it
# doesn't share fds with Claude's TTY.
#
# macOS doesn't ship `setsid` by default; fall back to a python double-fork
# if missing. Python double-fork uses os.setsid() which is the Unix daemon
# pattern.
LAUNCHER_LOG="$STATE_DIR/survivor.log"
: > "$LAUNCHER_LOG"

if command -v setsid >/dev/null 2>&1; then
    setsid nohup python3 "$HERE/instructions_quarantine_survivor.py" "${SURVIVOR_ARGS[@]}" \
        > "$LAUNCHER_LOG" 2>&1 < /dev/null &
    SURVIVOR_PID=$!
else
    # macOS: spawn via Python with os.setsid() to detach the session.
    python3 - "$HERE/instructions_quarantine_survivor.py" "${SURVIVOR_ARGS[@]}" \
        > "$LAUNCHER_LOG" 2>&1 < /dev/null <<'PYEOF' &
import os, sys, subprocess
script = sys.argv[1]
args   = sys.argv[2:]
# Double-fork: detach from parent's process group + session
if os.fork() == 0:
    os.setsid()
    if os.fork() == 0:
        os.execvp("python3", ["python3", script] + args)
    os._exit(0)
os._exit(0)
PYEOF
    SURVIVOR_PID=$!
fi

# Give the survivor a moment to write its own pid file, then verify it's
# actually alive in case spawn failed.
sleep 1
if [[ -f "$STATE_DIR/survivor.pid" ]]; then
    REAL_PID=$(cat "$STATE_DIR/survivor.pid" 2>/dev/null || echo "")
    if [[ -n "$REAL_PID" ]] && kill -0 "$REAL_PID" 2>/dev/null; then
        SURVIVOR_PID="$REAL_PID"
    fi
fi

# ── Phase E: print operator instructions ─────────────────────────────────

cat <<EOF

═══════════════════════════════════════════════════════════════════════════
 Quarantine ceremony scheduled.

 Survivor PID:  $SURVIVOR_PID
 State dir:    $STATE_DIR
 Session ID:   ${SESSION_ID:-<none captured>}
 Auto-resume:  $([[ "$LAUNCH_RESUME" -eq 1 ]] && echo "ENABLED" || echo "disabled (use --launch-resume to opt in)")

 The survivor will:
   1. probe preconditions  (~3s)
   2. dispatch isolate     (~5s)
   3. confirm blackout     (~5s grace + 10s sustained)
   4. dispatch release     (~5s)
   5. confirm recovery     (~5s)
   6. write results.json + attempt auto-resume

 Total: ~30-40 seconds. During the ~15-second blackout, this Claude Code
 session may lose its connection to api.anthropic.com. If so, exit Claude
 (\`/exit\` or Ctrl+D) and let the ceremony proceed.

 Read results when done:
   cat $STATE_DIR/results.json

 Manual resume (if auto-resume didn't open a new Terminal):
   $([[ -n "$SESSION_ID" ]] && echo "bash $STATE_DIR/relaunch.sh" || echo "<no session id captured — start fresh: claude>")

 Watch the survivor live:
   tail -f $STATE_DIR/survivor.log

═══════════════════════════════════════════════════════════════════════════
EOF

exit 0
