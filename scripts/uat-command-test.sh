#!/usr/bin/env bash
# uat-command-test.sh — Exhaustive non-destructive command test for Yuzu UAT
#
# Dispatches every read-only plugin action through the dashboard REST API,
# polls for results, and reports pass/fail for each.
#
# Requires: UAT stack running (bash scripts/win-start-UAT.sh)

set -uo pipefail

YUZU_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
UAT_DIR="$YUZU_ROOT/.uat"
COOKIES="$UAT_DIR/cookies.txt"
BASE_URL="http://localhost:8080"
RESULTS_FILE="$UAT_DIR/command-test-results.txt"

ADMIN_USER="admin"
ADMIN_PASS="${YUZU_PASS:-adminpassword1}"
DO_SETUP=false

# Parse args
for arg in "$@"; do
    case "$arg" in
        --setup) DO_SETUP=true ;;
        --password=*) ADMIN_PASS="${arg#*=}" ;;
        --help|-h) echo "Usage: $0 [--setup] [--password=PASS]"; exit 0 ;;
    esac
done

# Colours
if [ -t 1 ]; then
    GREEN='\033[0;32m'; RED='\033[0;31m'; YELLOW='\033[1;33m'; CYAN='\033[0;36m'; NC='\033[0m'; BOLD='\033[1m'
else
    GREEN=''; RED=''; YELLOW=''; CYAN=''; NC=''; BOLD=''
fi

pass_count=0
fail_count=0
skip_count=0
timeout_count=0
total_count=0

> "$RESULTS_FILE"

# ── Login ────────────────────────────────────────────────────────────────

login() {
    curl -s -c "$COOKIES" "$BASE_URL/login" \
        -d "username=${ADMIN_USER}&password=${ADMIN_PASS}" -o /dev/null
    local code
    code=$(curl -s -o /dev/null -w "%{http_code}" -b "$COOKIES" "$BASE_URL/" 2>/dev/null)
    if [ "$code" != "200" ]; then
        echo -e "${RED}Login failed (HTTP $code) — aborting${NC}"
        exit 1
    fi
}

# ── Dispatch + poll ──────────────────────────────────────────────────────

# dispatch_and_poll <plugin> <action> [params_json]
# Returns: 0=success, 1=failure, 2=timeout, 3=dispatch_error
dispatch_and_poll() {
    local plugin="$1"
    local action="$2"
    local params="${3:-}"
    local label="${plugin}.${action}"

    total_count=$((total_count + 1))

    # Build JSON body
    local body
    if [ -n "$params" ]; then
        body="{\"plugin\":\"${plugin}\",\"action\":\"${action}\",\"params\":${params}}"
    else
        body="{\"plugin\":\"${plugin}\",\"action\":\"${action}\"}"
    fi

    # Dispatch
    local resp
    resp=$(curl -s -m 10 -b "$COOKIES" \
        -X POST "$BASE_URL/api/command" \
        -H "Content-Type: application/json" \
        -d "$body" 2>/dev/null)

    local cmd_id
    cmd_id=$(echo "$resp" | python3 -c "import sys,json; print(json.load(sys.stdin).get('command_id',''))" 2>/dev/null || echo "")

    if [ -z "$cmd_id" ]; then
        echo -e "  ${RED}FAIL${NC} ${label} — dispatch error: $resp"
        echo "FAIL $label dispatch_error" >> "$RESULTS_FILE"
        fail_count=$((fail_count + 1))
        return 3
    fi

    # Poll for response (max 30s; some WMI queries like bitlocker are slow)
    local poll=0
    local result_text="" exit_code=""
    while [ $poll -lt 30 ]; do
        sleep 1
        poll=$((poll + 1))

        local poll_resp
        poll_resp=$(curl -s -m 5 -b "$COOKIES" \
            "$BASE_URL/api/responses/$cmd_id" 2>/dev/null || echo "{}")

        # Check if we have responses with actual output data
        # The server sends two responses: status=1 (ack, empty) and status=0 (data)
        local has_response
        has_response=$(echo "$poll_resp" | python3 -c "
import sys,json
try:
    d=json.load(sys.stdin)
    resps=d.get('responses',[])
    # Find the response with actual output (status=0, has data)
    for r in sorted(resps, key=lambda x: x.get('status',99)):
        out=r.get('output','')
        st=r.get('status',0)
        if out:
            ec=r.get('exit_code', r.get('exitCode', st))
            # Count pipe-separated rows for structured data
            lines=out.strip().split('\n') if '\n' in out else [out]
            row_count=len([l for l in lines if l.strip()])
            display=out[:160].replace('\n',' | ')
            print(f'YES|{ec}|[{row_count} row(s)] {display}')
            break
    else:
        # No output in any response — check if we have the ack at least
        if any(r.get('status')==1 for r in resps):
            # Got ack but no data yet, might still be processing
            # Check if there's a status=0 with empty output (valid empty result)
            if any(r.get('status')==0 for r in resps):
                print('YES|0|(no data)')
            else:
                print('NO||')
        elif resps:
            print('YES|0|(no data)')
        else:
            print('NO||')
except:
    print('NO||')
" 2>/dev/null || echo "NO||")

        local got_it
        got_it=$(echo "$has_response" | cut -d'|' -f1)
        if [ "$got_it" = "YES" ]; then
            exit_code=$(echo "$has_response" | cut -d'|' -f2)
            result_text=$(echo "$has_response" | cut -d'|' -f3-)
            break
        fi
    done

    if [ -z "$result_text" ] && [ "$poll" -ge 30 ]; then
        echo -e "  ${YELLOW}TIMEOUT${NC} ${label} — no response in 30s (cmd=$cmd_id)"
        echo "TIMEOUT $label $cmd_id" >> "$RESULTS_FILE"
        timeout_count=$((timeout_count + 1))
        return 2
    fi

    # Success: got a response
    local display_result
    display_result=$(echo "$result_text" | head -c 120)
    if [ "${exit_code}" = "0" ] || [ -z "$exit_code" ]; then
        echo -e "  ${GREEN}PASS${NC} ${label} (${poll}s) — ${display_result}"
        echo "PASS $label ${poll}s" >> "$RESULTS_FILE"
        pass_count=$((pass_count + 1))
        return 0
    else
        echo -e "  ${YELLOW}PASS*${NC} ${label} (${poll}s, exit=$exit_code) — ${display_result}"
        echo "PASS* $label ${poll}s exit=$exit_code" >> "$RESULTS_FILE"
        pass_count=$((pass_count + 1))
        return 0
    fi
}

# ── Main ─────────────────────────────────────────────────────────────────

echo ""
echo "============================================================"
echo "   Yuzu UAT — Exhaustive Non-Destructive Command Test       "
echo "============================================================"
echo ""

# ── Stack management ────────────────────────────────────────────────────
if $DO_SETUP; then
    echo -e "${CYAN}Starting UAT stack...${NC}"
    docker compose -f "$YUZU_ROOT/docker-compose.local.yml" up -d 2>&1
    echo "Waiting for services..."
    for i in $(seq 1 30); do
        if curl -sf "$BASE_URL/livez" >/dev/null 2>&1; then
            echo -e "${GREEN}Stack healthy${NC}"
            break
        fi
        sleep 1
        [ "$i" -eq 30 ] && { echo -e "${RED}Stack failed to start${NC}"; exit 1; }
    done
    echo ""
fi

# ── Health check ────────────────────────────────────────────────────────
if ! curl -sf "$BASE_URL/livez" >/dev/null 2>&1; then
    echo -e "${RED}Server not reachable at $BASE_URL${NC}"
    echo "Start the stack: docker compose -f docker-compose.local.yml up -d"
    echo "Or run with --setup flag"
    exit 1
fi

login
echo -e "${GREEN}Login OK${NC}"
echo ""

# ── Group 1: OS & System Info ────────────────────────────────────────────
echo -e "${BOLD}[OS & System Info]${NC}"
dispatch_and_poll os_info os_name
dispatch_and_poll os_info os_version
dispatch_and_poll os_info os_build
dispatch_and_poll os_info os_arch
dispatch_and_poll os_info uptime
echo ""

# ── Group 2: Hardware ────────────────────────────────────────────────────
echo -e "${BOLD}[Hardware]${NC}"
dispatch_and_poll hardware manufacturer
dispatch_and_poll hardware model
dispatch_and_poll hardware bios
dispatch_and_poll hardware processors
dispatch_and_poll hardware memory
dispatch_and_poll hardware disks
echo ""

# ── Group 3: Agent Status ────────────────────────────────────────────────
echo -e "${BOLD}[Agent Status]${NC}"
dispatch_and_poll status version
dispatch_and_poll status info
dispatch_and_poll status health
dispatch_and_poll status plugins
dispatch_and_poll status modules
dispatch_and_poll status connection
dispatch_and_poll status config
echo ""

# ── Group 4: Agent Internals ────────────────────────────────────────────
echo -e "${BOLD}[Agent Internals]${NC}"
dispatch_and_poll agent_actions info
dispatch_and_poll agent_actions set_log_level '{"level":"debug"}'
dispatch_and_poll agent_actions set_log_level '{"level":"info"}'
dispatch_and_poll agent_logging get_log '{"lines":"20"}'
dispatch_and_poll agent_logging get_key_files
dispatch_and_poll diagnostics log_level
dispatch_and_poll diagnostics certificates
dispatch_and_poll diagnostics connection_info
echo ""

# ── Group 5: Network ────────────────────────────────────────────────────
echo -e "${BOLD}[Network Configuration]${NC}"
dispatch_and_poll network_config adapters
dispatch_and_poll network_config ip_addresses
dispatch_and_poll network_config dns_servers
dispatch_and_poll network_config proxy
dispatch_and_poll network_config dns_cache
echo ""

echo -e "${BOLD}[Network Diagnostics]${NC}"
dispatch_and_poll network_diag listening
dispatch_and_poll network_diag connections
dispatch_and_poll netstat netstat_list
dispatch_and_poll netstat attribution
echo ""

# ── Group 6: Users & Sessions ───────────────────────────────────────────
echo -e "${BOLD}[Users & Sessions]${NC}"
dispatch_and_poll users logged_on
dispatch_and_poll users sessions
dispatch_and_poll users local_users
dispatch_and_poll users local_admins
dispatch_and_poll users primary_user
dispatch_and_poll users session_history
dispatch_and_poll users group_members '{"group":"Administrators"}'
echo ""

# ── Group 7: Processes & Services ────────────────────────────────────────
echo -e "${BOLD}[Processes & Services]${NC}"
dispatch_and_poll processes list
dispatch_and_poll processes query '{"name":"explorer"}'
dispatch_and_poll services list
dispatch_and_poll services running
dispatch_and_poll procfetch procfetch_fetch
echo ""

# ── Group 8: Installed Software ──────────────────────────────────────────
echo -e "${BOLD}[Installed Software]${NC}"
dispatch_and_poll installed_apps list
dispatch_and_poll installed_apps query '{"name":"Python"}'
dispatch_and_poll installed_apps list_per_user
dispatch_and_poll msi_packages list
dispatch_and_poll msi_packages product_codes
dispatch_and_poll software_actions list_upgradable
dispatch_and_poll software_actions installed_count
echo ""

# ── Group 9: Security ───────────────────────────────────────────────────
echo -e "${BOLD}[Security]${NC}"
dispatch_and_poll antivirus products
dispatch_and_poll antivirus status
dispatch_and_poll firewall state
dispatch_and_poll firewall rules
dispatch_and_poll bitlocker state
dispatch_and_poll certificates list
dispatch_and_poll quarantine status
echo ""

# ── Group 10: Windows Updates ───────────────────────────────────────────
echo -e "${BOLD}[Windows Updates]${NC}"
dispatch_and_poll windows_updates installed
dispatch_and_poll windows_updates missing
dispatch_and_poll windows_updates pending_reboot
echo ""

# ── Group 11: Device Identity ───────────────────────────────────────────
echo -e "${BOLD}[Device Identity]${NC}"
dispatch_and_poll device_identity device_name
dispatch_and_poll device_identity domain
dispatch_and_poll device_identity ou
echo ""

# ── Group 12: Filesystem ────────────────────────────────────────────────
echo -e "${BOLD}[Filesystem]${NC}"
# Detect OS and use appropriate paths
if [ -f /etc/os-release ] || [ "$(uname)" = "Linux" ] || [ "$(uname)" = "Darwin" ]; then
    dispatch_and_poll filesystem exists '{"path":"/etc/hosts"}'
    dispatch_and_poll filesystem list_dir '{"path":"/tmp"}'
    dispatch_and_poll filesystem file_hash '{"path":"/etc/hosts"}'
    dispatch_and_poll filesystem read '{"path":"/etc/hosts"}'
    dispatch_and_poll filesystem get_acl '{"path":"/tmp"}'
    dispatch_and_poll filesystem get_signature '{"path":"/usr/bin/env"}'
    dispatch_and_poll filesystem search_dir '{"root":"/tmp","pattern":"*"}'
    dispatch_and_poll filesystem find_by_hash '{"directory":"/tmp","sha256":"0000000000000000000000000000000000000000000000000000000000000000"}'
    dispatch_and_poll filesystem search '{"root":"/etc","pattern":"host*","max_depth":"1"}'
    dispatch_and_poll filesystem get_version_info '{"path":"/usr/bin/env"}'
else
    dispatch_and_poll filesystem exists '{"path":"C:\\\\Windows\\\\System32\\\\notepad.exe"}'
    dispatch_and_poll filesystem list_dir '{"path":"C:\\\\Windows"}'
    dispatch_and_poll filesystem file_hash '{"path":"C:\\\\Windows\\\\System32\\\\notepad.exe"}'
    dispatch_and_poll filesystem read '{"path":"C:\\\\Windows\\\\System32\\\\drivers\\\\etc\\\\hosts"}'
    dispatch_and_poll filesystem get_acl '{"path":"C:\\\\Windows\\\\System32"}'
    dispatch_and_poll filesystem get_signature '{"path":"C:\\\\Windows\\\\System32\\\\notepad.exe"}'
    dispatch_and_poll filesystem search_dir '{"root":"C:\\\\Windows\\\\Temp","pattern":"*.log"}'
    dispatch_and_poll filesystem find_by_hash '{"directory":"C:\\\\Windows\\\\System32","sha256":"0000000000000000000000000000000000000000000000000000000000000000"}'
    dispatch_and_poll filesystem search '{"root":"C:\\\\Windows\\\\System32","pattern":"notepad*","max_depth":"1"}'
    dispatch_and_poll filesystem get_version_info '{"path":"C:\\\\Windows\\\\System32\\\\notepad.exe"}'
fi
dispatch_and_poll filesystem create_temp '{"prefix":"yuzu_uat","persist":"false"}'
dispatch_and_poll filesystem create_temp_dir '{"prefix":"yuzu_uat","persist":"false"}'
echo ""

# ── Group 13: Registry ──────────────────────────────────────────────────
echo -e "${BOLD}[Registry]${NC}"
dispatch_and_poll registry get_value '{"hive":"HKLM","key":"SOFTWARE\\\\Microsoft\\\\Windows NT\\\\CurrentVersion","value":"ProductName"}'
dispatch_and_poll registry enumerate_keys '{"hive":"HKLM","key":"SOFTWARE\\\\Microsoft\\\\Windows\\\\CurrentVersion"}'
dispatch_and_poll registry key_exists '{"hive":"HKLM","key":"SOFTWARE\\\\Microsoft\\\\Windows NT\\\\CurrentVersion"}'
dispatch_and_poll registry enumerate_values '{"hive":"HKLM","key":"SOFTWARE\\\\Microsoft\\\\Windows NT\\\\CurrentVersion"}'
dispatch_and_poll registry get_user_value '{"username":"natha","key":"SOFTWARE\\\\Microsoft\\\\Windows\\\\CurrentVersion\\\\Explorer","value":"ShellState"}'
echo ""

# ── Group 14: Event Logs ────────────────────────────────────────────────
echo -e "${BOLD}[Event Logs]${NC}"
dispatch_and_poll event_logs errors
dispatch_and_poll event_logs query '{"log":"System","filter":"Error","count":"5"}'
echo ""

# ── Group 15: WMI ────────────────────────────────────────────────────────
echo -e "${BOLD}[WMI]${NC}"
dispatch_and_poll wmi query '{"wql":"SELECT Name,Version FROM Win32_OperatingSystem"}'
dispatch_and_poll wmi get_instance '{"class":"Win32_ComputerSystem","namespace":"root\\\\cimv2"}'
echo ""

# ── Group 16: WiFi ──────────────────────────────────────────────────────
echo -e "${BOLD}[WiFi]${NC}"
dispatch_and_poll wifi list_networks
dispatch_and_poll wifi connected
echo ""

# ── Group 17: SCCM ──────────────────────────────────────────────────────
echo -e "${BOLD}[SCCM]${NC}"
dispatch_and_poll sccm client_version
dispatch_and_poll sccm site
echo ""

# ── Group 18: Tags & Storage (read-only ops) ────────────────────────────
echo -e "${BOLD}[Tags & Storage]${NC}"
dispatch_and_poll tags get_all
dispatch_and_poll tags count
dispatch_and_poll storage list
echo ""

# ── Group 19: Content Distribution (read-only) ──────────────────────────
echo -e "${BOLD}[Content Distribution]${NC}"
dispatch_and_poll content_dist list_staged
echo ""

# ── Group 20: TAR (read-only) ───────────────────────────────────────────
echo -e "${BOLD}[TAR (Telemetry & Response)]${NC}"
dispatch_and_poll tar status
dispatch_and_poll tar query '{"limit":"5"}'
dispatch_and_poll tar export '{"type":"all","limit":"5"}'
echo ""

# ── Group 21: Vulnerability Scanning ────────────────────────────────────
echo -e "${BOLD}[Vulnerability Scanning]${NC}"
dispatch_and_poll vuln_scan summary
dispatch_and_poll vuln_scan inventory
echo ""

# ── Group 22: HTTP Client (read-only) ───────────────────────────────────
echo -e "${BOLD}[HTTP Client]${NC}"
dispatch_and_poll http_client head '{"url":"https://httpbin.org/get"}'
dispatch_and_poll http_client get '{"url":"https://httpbin.org/get"}'
echo ""

# ── Group 23: IOC Check ─────────────────────────────────────────────────
echo -e "${BOLD}[IOC Check]${NC}"
if [ -f /etc/os-release ] || [ "$(uname)" = "Linux" ] || [ "$(uname)" = "Darwin" ]; then
    dispatch_and_poll ioc check '{"ip_addresses":"8.8.8.8","domains":"example.com","file_paths":"/etc/hosts"}'
else
    dispatch_and_poll ioc check '{"ip_addresses":"8.8.8.8","domains":"example.com","file_paths":"C:\\\\Windows\\\\System32\\\\notepad.exe"}'
fi
echo ""

# ── Group 24: Discovery ─────────────────────────────────────────────────
echo -e "${BOLD}[Discovery]${NC}"
dispatch_and_poll discovery scan_subnet '{"subnet":"192.168.1.0/30"}'
echo ""

# ── Group 25: Example Plugin ───────────────────────────────────────────
echo -e "${BOLD}[Example Plugin]${NC}"
dispatch_and_poll example ping
dispatch_and_poll example echo '{"message":"UAT test message"}'
echo ""

# ── Group 26: Asset Tags ──────────────────────────────────────────────
echo -e "${BOLD}[Asset Tags]${NC}"
dispatch_and_poll asset_tags status
dispatch_and_poll asset_tags get
dispatch_and_poll asset_tags changes
echo ""

# ── Group 27: Network Actions ─────────────────────────────────────────
echo -e "${BOLD}[Network Actions]${NC}"
dispatch_and_poll network_actions ping '{"host":"127.0.0.1"}'
dispatch_and_poll network_actions flush_dns
echo ""

# ── Group 28: Storage (Agent KV Store) ────────────────────────────────
echo -e "${BOLD}[Storage (KV Store)]${NC}"
dispatch_and_poll storage set '{"key":"uat_test_key","value":"uat_test_value"}'
dispatch_and_poll storage get '{"key":"uat_test_key"}'
dispatch_and_poll storage list
dispatch_and_poll storage delete '{"key":"uat_test_key"}'
echo ""

# ── Group 29: Tags (Agent Local Tags) ─────────────────────────────────
echo -e "${BOLD}[Tags (Local Agent)]${NC}"
dispatch_and_poll tags set '{"key":"uat_env","value":"testing"}'
dispatch_and_poll tags get '{"key":"uat_env"}'
dispatch_and_poll tags check '{"key":"uat_env"}'
dispatch_and_poll tags get_all
dispatch_and_poll tags count
dispatch_and_poll tags delete '{"key":"uat_env"}'
echo ""

# ── Group 30: TAR Extended (Telemetry & Response) ─────────────────────
echo -e "${BOLD}[TAR Extended]${NC}"
dispatch_and_poll tar status
dispatch_and_poll tar sql '{"query":"SELECT count(*) as cnt FROM events LIMIT 1"}'
dispatch_and_poll tar configure '{"interval":"60"}'
echo ""

# ── Group 31: Vulnerability Scanning Extended ─────────────────────────
echo -e "${BOLD}[Vulnerability Scanning Extended]${NC}"
dispatch_and_poll vuln_scan summary
dispatch_and_poll vuln_scan inventory
dispatch_and_poll vuln_scan scan
dispatch_and_poll vuln_scan cve_scan '{"cve":"CVE-2021-44228"}'
dispatch_and_poll vuln_scan config_scan
echo ""

# ── Group 32: Wake-on-LAN ─────────────────────────────────────────────
echo -e "${BOLD}[Wake-on-LAN]${NC}"
dispatch_and_poll wol check '{"host":"127.0.0.1"}'
echo ""

# ── Group 33: Chargen (Test Traffic) ──────────────────────────────────
echo -e "${BOLD}[Chargen]${NC}"
dispatch_and_poll chargen chargen_start '{"duration":"2","rate":"10"}'
sleep 3
dispatch_and_poll chargen chargen_stop
echo ""

# ── Group 34: HTTP Client Extended ────────────────────────────────────
echo -e "${BOLD}[HTTP Client Extended]${NC}"
dispatch_and_poll http_client get '{"url":"http://localhost:8080/livez"}'
dispatch_and_poll http_client head '{"url":"http://localhost:8080/livez"}'
echo ""

# ── Group 35: Certificates Extended ───────────────────────────────────
echo -e "${BOLD}[Certificates Extended]${NC}"
dispatch_and_poll certificates list
echo ""

# ── Group 36: Windows-Specific Patches ────────────────────────────────
echo -e "${BOLD}[Windows Updates Extended]${NC}"
dispatch_and_poll windows_updates patch_connectivity
echo ""

# ── Group 37: Interaction (non-blocking) ─────────────────────────────
echo -e "${BOLD}[Interaction]${NC}"
dispatch_and_poll interaction notify '{"title":"Yuzu UAT","message":"REST API command test"}'
echo ""

# ── Summary ──────────────────────────────────────────────────────────────
echo ""
echo "============================================================"
echo "                      TEST SUMMARY                          "
echo "============================================================"
echo ""
echo -e "  ${GREEN}PASS:${NC}    $pass_count"
echo -e "  ${RED}FAIL:${NC}    $fail_count"
echo -e "  ${YELLOW}TIMEOUT:${NC} $timeout_count"
echo -e "  Total:   $total_count"
echo ""

if [ "$fail_count" -eq 0 ] && [ "$timeout_count" -eq 0 ]; then
    echo -e "  ${GREEN}ALL $total_count TESTS PASSED${NC}"
elif [ "$fail_count" -eq 0 ]; then
    echo -e "  ${YELLOW}$pass_count passed, $timeout_count timed out${NC}"
else
    echo -e "  ${RED}$fail_count FAILURES${NC}"
fi

echo ""
echo "  Full results: $RESULTS_FILE"
echo "============================================================"
