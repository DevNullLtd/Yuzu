#!/usr/bin/env bash
# Shulgi (Windows MSVC, self-hosted) Instructions-gate runner.
#
# Pre-reqs that need to be in place BEFORE this script runs:
#   - Tailscale up to Shulgi (or any other path that gives you ssh)
#   - On Shulgi: MSYS2 installed at C:\msys64
#   - On Shulgi: setup_msvc_env.sh at C:\Users\<user>\Yuzu\setup_msvc_env.sh
#   - On Shulgi: Windows Firewall allow rules for
#       C:\Users\<user>\Yuzu\build-windows\server\core\yuzu-server.exe
#       C:\Users\<user>\Yuzu\build-windows\agents\core\yuzu-agent.exe
#     (one-time, run by user in admin PowerShell via:
#        netsh advfirewall firewall add rule name=yuzu-server dir=in
#            action=allow program=<path> enable=yes)
#   - On Shulgi: PyYAML for MSYS2 python3
#       ssh Shulgi 'C:\msys64\usr\bin\bash.exe -lc "pacman -S --noconfirm
#                       --needed python-yaml"'
#
# Usage from the Mac:
#   bash docs/plans/instructions-cross-platform-handover-2026-05-13.shulgi.sh

set -euo pipefail

ssh Shulgi 'C:\msys64\usr\bin\bash.exe -l' <<'OUTER_EOF'
set -e

# 0. clean slate
taskkill //F //IM yuzu-server.exe 2>/dev/null || true
taskkill //F //IM yuzu-agent.exe  2>/dev/null || true
sleep 2

# 1. environment
WINHOME="$(cygpath -u "$USERPROFILE")"   # e.g. /c/Users/<user>
source "$WINHOME/Yuzu/setup_msvc_env.sh" >/dev/null 2>&1
cd "$WINHOME/Yuzu"

# 2. fetch + checkout feat/viz-engine
git fetch origin feat/viz-engine 2>&1 | tail -1
git checkout feat/viz-engine
git pull --ff-only 2>&1 | tail -1

# 3. build (incremental)
meson compile -C build-windows-debug \
    || meson compile -C build-windows

BUILDDIR="$WINHOME/Yuzu/build-windows-debug"
[ -x "$BUILDDIR/server/core/yuzu-server.exe" ] \
    || BUILDDIR="$WINHOME/Yuzu/build-windows"

# 4. UAT scaffold
UAT_DIR="/tmp/yuzu-uat-win-noGW"
ADMIN_USER="admin"
ADMIN_PASS='YuzuUatAdmin1!'
WEB_PORT=18080         # NOT 8080 — iphlpsvc owns it on Shulgi
AGENT_PORT=50054

rm -rf "$UAT_DIR"
mkdir -p "$UAT_DIR/agent-data"

# PBKDF2-SHA256 admin config — same format as scripts/start-UAT.sh's generate_config
/c/Python314/python.exe -c "
import hashlib, os
salt = os.urandom(16)
dk = hashlib.pbkdf2_hmac('sha256', '$ADMIN_PASS'.encode(), salt, 100000, dklen=32)
print(f'$ADMIN_USER:admin:{salt.hex()}:{dk.hex()}')
" > "$UAT_DIR/yuzu-server.cfg"

# 5. server — 127.0.0.1 bind to avoid Defender's 0.0.0.0-as-public heuristic
"$BUILDDIR/server/core/yuzu-server.exe" \
    --no-tls --no-https \
    --listen 127.0.0.1:$AGENT_PORT \
    --web-address 127.0.0.1 --web-port $WEB_PORT \
    --log-level info --metrics-no-auth \
    --rate-limit 2000 --login-rate-limit 200 \
    --config "$UAT_DIR/yuzu-server.cfg" \
    > "$UAT_DIR/server.log" 2>&1 &
SERVER_PID=$!
echo "server pid=$SERVER_PID"

# Wait for /health 200. NEVER use `curl -sf` inside `set -e`.
i=0
while [ $i -lt 30 ]; do
    code=$(curl -s -o /dev/null -w "%{http_code}" --max-time 2 \
           http://127.0.0.1:$WEB_PORT/health 2>/dev/null || echo 000)
    if [ "$code" = "200" ]; then
        echo "server ready at i=$i"
        break
    fi
    sleep 1; i=$((i+1))
done
[ "$code" = "200" ] || { echo "server never ready"; tail -20 "$UAT_DIR/server.log"; exit 1; }

# 6. enrollment token
curl -s -c "$UAT_DIR/cookies.txt" http://127.0.0.1:$WEB_PORT/login \
    -d "username=$ADMIN_USER&password=$ADMIN_PASS" -o /dev/null
token_html=$(curl -s -b "$UAT_DIR/cookies.txt" \
    -X POST http://127.0.0.1:$WEB_PORT/api/settings/enrollment-tokens \
    -d "label=uat-win&max_uses=1000&ttl=86400")
ENROLL_TOKEN=$(echo "$token_html" | grep -oE '[a-f0-9]{64}' | head -1)
[ -n "$ENROLL_TOKEN" ] || { echo "failed to mint token"; exit 1; }
echo "enrollment token: ${ENROLL_TOKEN:0:16}..."

# 7. agent
"$BUILDDIR/agents/core/yuzu-agent.exe" \
    --server 127.0.0.1:$AGENT_PORT --no-tls \
    --data-dir "$UAT_DIR/agent-data" \
    --plugin-dir "$BUILDDIR/agents/plugins" \
    --log-level info \
    --enrollment-token "$ENROLL_TOKEN" \
    > "$UAT_DIR/agent.log" 2>&1 &
AGENT_PID=$!
echo "agent pid=$AGENT_PID"

i=0
while [ $i -lt 30 ]; do
    grep -q "Registered with server" "$UAT_DIR/agent.log" 2>/dev/null && {
        echo "agent registered at i=$i"; break
    }
    sleep 1; i=$((i+1))
done
grep -q "Registered with server" "$UAT_DIR/agent.log" \
    || { echo "agent did not register"; tail -30 "$UAT_DIR/agent.log"; exit 1; }

# 8. Instructions gate
bash scripts/test/instructions-tests.sh \
    --dashboard http://127.0.0.1:$WEB_PORT \
    --user "$ADMIN_USER" --password "$ADMIN_PASS" \
    --run-id windows-validate --gate-name instructions \
    --output "$UAT_DIR/instructions-outcomes.json"

# 9. quick outcome summary
python3 -c "
import json
from collections import Counter
d = json.load(open('$UAT_DIR/instructions-outcomes.json'))
c = Counter(o['status'] for o in d['outcomes'])
print('outcomes:', dict(c))
fails = [o for o in d['outcomes'] if o['status'] in ('fail','error')]
print('fails:', len(fails))
for o in fails[:30]:
    print(' ', o['id'], '|', o.get('note',''))
print('platform skips:')
for o in d['outcomes']:
    if o['status']=='skip':
        print(' ', o['id'], '|', o.get('note',''))
"

echo "=== done ==="
OUTER_EOF
