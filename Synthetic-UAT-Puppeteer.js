#!/usr/bin/env node
// ============================================================================
// Synthetic UAT — Puppeteer Dashboard Command Exerciser
// ============================================================================
// Logs into the Yuzu Dashboard UI and executes every non-destructive plugin
// command, capturing results via SSE. Verifies that the full dispatch path
// (server → gateway → agent → response → SSE) works end-to-end.
//
// Usage:
//   node Synthetic-UAT-Puppeteer.js [--headed] [--slow] [--filter <plugin>]
//
// Requires: npm install puppeteer  (already in node_modules/)
// ============================================================================

const puppeteer = require('puppeteer');
const path = require('path');
const fs = require('fs');

// ── Configuration ──────────────────────────────────────────────────────────

const BASE_URL = process.env.YUZU_URL || 'http://127.0.0.1:8080';
const USERNAME = process.env.YUZU_USER || 'admin';
const PASSWORD = process.env.YUZU_PASS || 'adminpassword1';

// Cross-platform path selection: set YUZU_AGENT_OS=windows to use Windows paths
const IS_WINDOWS = (process.env.YUZU_AGENT_OS || 'linux').toLowerCase() === 'windows';

const HEADED = process.argv.includes('--headed');
const SLOW_MO = process.argv.includes('--slow') ? 200 : 0;
const FILTER_IDX = process.argv.indexOf('--filter');
const FILTER = FILTER_IDX >= 0 ? process.argv[FILTER_IDX + 1] : null;

const SETUP = process.argv.includes('--setup');

// Timeout for each command to receive SSE results (ms)
const COMMAND_TIMEOUT_MS = 15_000;
// Pause between commands (ms)
const INTER_COMMAND_PAUSE_MS = 500;

// ── Non-destructive command catalog ────────────────────────────────────────
// Each entry: [command_string, description, expected_behaviour]
// expected_behaviour: 'rows' = expect result rows, 'any' = may return 0 rows
//
// Cross-platform: filesystem paths use P() helper for Windows/Linux compat.
// Set YUZU_AGENT_OS=windows to use Windows paths.

function P(linuxPath, winPath) { return IS_WINDOWS ? winPath : linuxPath; }

const COMMANDS = [
  // ─── Example / Diagnostics ───
  ['example ping',                                'Ping agent',                  'rows'],
  ['example echo message="Hello from Puppeteer"', 'Echo with message param',     'rows'],

  // ─── Status ───
  ['status version',    'Agent version',       'rows'],
  ['status info',       'Agent info',          'rows'],
  ['status health',     'Agent health',        'rows'],
  ['status plugins',    'Loaded plugins',      'rows'],
  ['status modules',    'Loaded modules',      'any'],
  ['status connection', 'Connection info',     'rows'],
  ['status config',     'Agent config',        'rows'],

  // ─── OS Info ───
  ['os_info os_name',    'OS name',       'rows'],
  ['os_info os_version', 'OS version',    'rows'],
  ['os_info os_build',   'OS build',      'rows'],
  ['os_info os_arch',    'OS arch',       'rows'],
  ['os_info uptime',     'System uptime', 'rows'],

  // ─── Hardware ───
  ['hardware manufacturer', 'HW manufacturer', 'rows'],
  ['hardware model',        'HW model',        'rows'],
  ['hardware bios',         'BIOS info',       'rows'],
  ['hardware processors',   'CPU info',        'rows'],
  ['hardware memory',       'Memory info',     'rows'],
  ['hardware disks',        'Disk info',       'rows'],

  // ─── Network Config ───
  ['network_config adapters',     'Network adapters',  'rows'],
  ['network_config ip_addresses', 'IP addresses',      'rows'],
  ['network_config dns_servers',  'DNS servers',       'rows'],
  ['network_config proxy',        'Proxy settings',    'any'],
  ['network_config dns_cache',    'DNS cache',         'any'],

  // ─── Network Actions (read-only) ───
  ['network_actions ping host=127.0.0.1', 'Ping loopback', 'rows'],

  // ─── Network Diagnostics ───
  ['network_diag listening',    'Listening ports',    'rows'],
  ['network_diag connections',  'Active connections', 'rows'],

  // ─── Netstat ───
  ['netstat netstat_list', 'Netstat listing', 'rows'],

  // ─── Device Identity ───
  ['device_identity device_name', 'Device name', 'rows'],
  ['device_identity domain',     'Domain',       'any'],
  ['device_identity ou',         'OU',           'any'],

  // ─── Users ───
  ['users logged_on',       'Logged-on users',   'rows'],
  ['users sessions',        'User sessions',     'rows'],
  ['users local_users',     'Local users',       'rows'],
  ['users local_admins',    'Local admins',      'rows'],
  [`users group_members group=${IS_WINDOWS ? 'Administrators' : 'root'}`,
                             'Group members',     'any'],
  ['users primary_user',    'Primary user',      'rows'],
  ['users session_history', 'Session history',   'any'],

  // ─── Processes ───
  ['processes list',                           'Process list',          'rows'],
  [`processes query name=${IS_WINDOWS ? 'explorer.exe' : 'bash'}`,
                                               'Query process by name', 'any'],

  // ─── Installed Apps ───
  ['installed_apps list',              'Installed apps list',   'rows'],
  ['installed_apps installed_count',   'Installed count',       'rows'],

  // ─── MSI Packages (Windows-specific) ───
  ['msi_packages list',          'MSI packages list',    'any'],
  ['msi_packages product_codes', 'MSI product codes',    'any'],

  // ─── Software Actions (read-only) ───
  ['software_actions list_upgradable', 'Upgradable software', 'any'],
  ['software_actions installed_count', 'Installed count',     'rows'],

  // ─── Windows Updates ───
  ['windows_updates installed',      'Installed updates',   'any'],
  ['windows_updates missing',        'Missing updates',     'any'],
  ['windows_updates pending_reboot', 'Pending reboot',      'any'],
  ['windows_updates patch_connectivity', 'Patch connectivity', 'any'],

  // ─── SCCM ───
  ['sccm status',   'SCCM status',   'any'],

  // ─── Event Logs ───
  ['event_logs errors log_name=System', 'System error logs',  'any'],
  ['event_logs query keyword=error',    'Query event logs',   'any'],

  // ─── Firewall ───
  ['firewall state', 'Firewall state', 'rows'],
  ['firewall rules', 'Firewall rules', 'any'],

  // ─── Antivirus ───
  ['antivirus products', 'AV products',  'any'],
  ['antivirus status',   'AV status',    'rows'],

  // ─── BitLocker / Disk Encryption ───
  ['bitlocker state', 'Disk encryption state', 'any'],

  // ─── Certificates (read-only) ───
  ['certificates list', 'Certificate list', 'any'],

  // ─── Services ───
  ['services list',    'Services list',    'rows'],
  ['services running', 'Running services', 'rows'],

  // ─── WMI (Windows-specific, returns 'any' on Linux) ───
  ['wmi query wql_select="SELECT Caption, Version FROM Win32_OperatingSystem"',
                              'WMI OS query',  'any'],
  ['wmi get_instance class_name=Win32_ComputerSystem',
                              'WMI instance',  'any'],

  // ─── Registry (read-only, Windows-specific) ───
  ...(IS_WINDOWS ? [
    ['registry key_exists path="HKLM\\\\SOFTWARE\\\\Microsoft"', 'Registry key exists',  'rows'],
    ['registry enumerate_keys path="HKLM\\\\SOFTWARE\\\\Microsoft"', 'Enumerate reg keys', 'any'],
  ] : []),

  // ─── WiFi ───
  ['wifi list_networks', 'WiFi networks', 'any'],
  ['wifi connected',     'WiFi connected', 'any'],

  // ─── Filesystem (read-only) ───
  [`filesystem exists path=${P('/etc/hosts', 'C:\\\\Windows\\\\System32\\\\cmd.exe')}`,
                                        'File exists check',   'rows'],
  [`filesystem list_dir path=${P('/tmp', 'C:\\\\Windows\\\\Temp')}`,
                                        'Directory listing',   'any'],
  [`filesystem file_hash path=${P('/etc/hosts', 'C:\\\\Windows\\\\System32\\\\cmd.exe')}`,
                                        'File hash',           'rows'],
  [`filesystem read path=${P('/etc/hosts', 'C:\\\\Windows\\\\System32\\\\drivers\\\\etc\\\\hosts')}`,
                                        'Read file',           'rows'],
  [`filesystem get_acl path=${P('/etc/hosts', 'C:\\\\Windows\\\\System32\\\\cmd.exe')}`,
                                        'File ACL',            'any'],
  [`filesystem search_dir path=${P('/tmp', 'C:\\\\Windows\\\\Temp')} pattern="*"`,
                                        'Search directory',    'any'],
  [`filesystem search path=${P('/etc/hosts', 'C:\\\\Windows\\\\System32\\\\drivers\\\\etc\\\\hosts')} pattern="localhost"`,
                                        'Search file content', 'any'],
  ...(IS_WINDOWS ? [
    ['filesystem get_signature path=C:\\\\Windows\\\\System32\\\\cmd.exe',
                                        'File signature',      'any'],
    ['filesystem get_version_info path=C:\\\\Windows\\\\System32\\\\cmd.exe',
                                        'File version info',   'any'],
  ] : []),
  // Filesystem safe mutating: create temp file/dir
  ['filesystem create_temp prefix=yuzu_uat persist=false',     'Create temp file', 'rows'],
  ['filesystem create_temp_dir prefix=yuzu_uat persist=false', 'Create temp dir',  'rows'],

  // ─── HTTP Client ───
  ['http_client request url=http://127.0.0.1:8080/livez method=GET',
                                    'HTTP GET livez', 'rows'],

  // ─── IOC / Vuln Scan ───
  ['ioc check',              'IOC check',         'any'],
  ['vuln_scan scan',         'Vulnerability scan', 'any'],
  ['vuln_scan cve_scan',     'CVE scan',           'any'],
  ['vuln_scan config_scan',  'Config compliance',  'any'],
  ['vuln_scan summary',      'Vuln scan summary',  'any'],
  ['vuln_scan inventory',    'Vuln inventory',     'any'],

  // ─── Process Fetch / Socket Who ───
  ['procfetch procfetch',   'Process fetch with hashes', 'any'],
  ['netstat attribution',   'Socket-to-process map',     'any'],

  // ─── Diagnostics ───
  ['diagnostics log_level',       'Agent log level',       'rows'],
  ['diagnostics certificates',    'Agent certificates',    'any'],
  ['diagnostics connection_info', 'Agent connection info',  'rows'],

  // ─── Agent Logging ───
  ['agent_logging get_log lines=20', 'Agent log tail',   'rows'],
  ['agent_logging get_key_files',    'Agent key files',   'any'],

  // ─── Agent Actions ───
  ['agent_actions info',                         'Agent actions info',      'rows'],
  ['agent_actions set_log_level level=debug',    'Set log level (debug)',   'any'],
  ['agent_actions set_log_level level=info',     'Set log level (info)',    'any'],

  // ─── Asset Tags ───
  ['asset_tags status',  'Asset tag status',  'any'],
  ['asset_tags changes', 'Asset tag changes', 'any'],

  // ─── Storage (safe mutating: write → read → list) ───
  ['storage set key=uat_puppeteer value=hello',   'KV store set',   'any'],
  ['storage get key=uat_puppeteer',               'KV store get',   'rows'],
  ['storage list',                                'KV store list',  'rows'],

  // ─── Tags (safe mutating: write → read → check → count) ───
  ['tags set key=uat_env value=puppeteer',   'Tag set',         'any'],
  ['tags get key=uat_env',                   'Tag get',         'rows'],
  ['tags get_all',                           'Tag get all',     'rows'],
  ['tags check key=uat_env',                 'Tag check',       'rows'],
  ['tags count',                             'Tag count',       'rows'],

  // ─── Content Distribution (read-only) ───
  ['content_dist list_staged', 'List staged content', 'any'],

  // ─── TAR (Timeline Activity Record) ───
  ['tar status',       'TAR status',        'any'],
  ['tar collect_fast', 'TAR collect fast',  'any'],
  ['tar collect_slow', 'TAR collect slow',  'any'],
  ['tar query',        'TAR query',         'any'],
  ['tar snapshot',     'TAR snapshot',      'any'],

  // ─── Chargen (safe mutating: start then stop) ───
  ['chargen chargen_start',  'Chargen start', 'any'],
  ['chargen chargen_stop',   'Chargen stop',  'any'],

  // ─── Quarantine (status check only) ───
  ['quarantine status', 'Quarantine status', 'any'],

  // ─── Discovery ───
  ['discovery scan_subnet subnet=127.0.0.1/32', 'Loopback subnet scan', 'any'],

  // ─── WoL (safe: check reachability only + wake to loopback) ───
  ['wol check host=127.0.0.1', 'WoL reachability check', 'any'],

  // ─── Network Actions (safe mutating) ───
  ['network_actions flush_dns', 'Flush DNS cache', 'any'],

  // ─── Interaction (non-destructive desktop notification) ───
  ['interaction notify title="Yuzu UAT" message="Synthetic test complete"',
                                  'Desktop notification', 'any'],
];

// ── Helpers ────────────────────────────────────────────────────────────────

const RESET  = '\x1b[0m';
const GREEN  = '\x1b[32m';
const RED    = '\x1b[31m';
const YELLOW = '\x1b[33m';
const CYAN   = '\x1b[36m';
const DIM    = '\x1b[2m';
const BOLD   = '\x1b[1m';

function pad(s, n) { return (s + ' '.repeat(n)).slice(0, n); }
function elapsed(ms) {
  if (ms < 1000) return `${ms}ms`;
  return `${(ms / 1000).toFixed(1)}s`;
}

// ── Main ───────────────────────────────────────────────────────────────────

const { execSync } = require('child_process');

(async () => {
  const startTime = Date.now();
  const results = [];
  let passed = 0, failed = 0, skipped = 0, warned = 0;

  console.log(`\n${BOLD}${CYAN}` +
    `+--------------------------------------------------------------+\n` +
    `|        Yuzu Synthetic UAT -- Puppeteer Dashboard Test        |\n` +
    `+--------------------------------------------------------------+${RESET}\n`);
  console.log(`  Target:    ${BASE_URL}`);
  console.log(`  User:      ${USERNAME}`);
  console.log(`  Headed:    ${HEADED}`);
  console.log(`  Filter:    ${FILTER || '(all commands)'}`);
  console.log(`  Commands:  ${COMMANDS.length} non-destructive\n`);

  // ── Stack management ──────────────────────────────────────────────────
  if (SETUP) {
    console.log(`${CYAN}[setup]${RESET} Starting UAT stack via docker-compose.local.yml...`);
    try {
      execSync('docker compose -f docker-compose.local.yml up -d', { stdio: 'inherit' });
    } catch {
      console.log(`${RED}FATAL: Failed to start UAT stack${RESET}`);
      process.exit(1);
    }
    // Wait for health
    for (let i = 0; i < 30; i++) {
      try {
        const resp = execSync(`curl -sf ${BASE_URL}/livez`, { encoding: 'utf8', timeout: 3000 });
        if (resp.includes('ok')) break;
      } catch {}
      await new Promise(r => setTimeout(r, 1000));
      if (i === 29) { console.log(`${RED}FATAL: Stack did not become healthy${RESET}`); process.exit(1); }
    }
    console.log(`${GREEN}[setup]${RESET} Stack healthy\n`);
  }

  // Health check (always)
  try {
    const http = require('http');
    await new Promise((resolve, reject) => {
      http.get(`${BASE_URL}/livez`, (res) => {
        if (res.statusCode === 200) resolve();
        else reject(new Error(`Server returned HTTP ${res.statusCode}`));
        res.resume();
      }).on('error', reject);
    });
  } catch (err) {
    console.log(`${RED}FATAL: Server not reachable at ${BASE_URL} (${err.message})${RESET}`);
    console.log(`  Start the stack: docker compose -f docker-compose.local.yml up -d`);
    console.log(`  Or run with --setup flag`);
    process.exit(1);
  }

  const browser = await puppeteer.launch({
    headless: HEADED ? false : 'shell',
    slowMo: SLOW_MO,
    args: ['--no-sandbox', '--disable-setuid-sandbox', '--disable-dev-shm-usage', '--disable-gpu'],
  });

  const page = await browser.newPage();
  await page.setViewport({ width: 1440, height: 900 });

  const pageErrors = [];
  page.on('pageerror', err => pageErrors.push(err.message));

  try {
    // ── Step 1: Login via the Dashboard UI ─────────────────────────────

    console.log(`${DIM}[login]${RESET} Navigating to ${BASE_URL}/login ...`);
    await page.goto(`${BASE_URL}/login`, { waitUntil: 'networkidle2', timeout: 15_000 });

    await page.type('input[name="username"]', USERNAME);
    await page.type('input[name="password"]', PASSWORD);
    await Promise.all([
      page.waitForNavigation({ waitUntil: 'networkidle2', timeout: 15_000 }),
      page.click('button[type="submit"]'),
    ]);

    if (page.url().includes('login')) {
      console.log(`${RED}FATAL: Login failed${RESET}`);
      process.exit(1);
    }
    console.log(`${GREEN}[login]${RESET} Dashboard loaded at ${page.url()}`);

    // Wait for scope list to populate
    await page.waitForSelector('#scope-list', { timeout: 10_000 });
    await new Promise(r => setTimeout(r, 3000));

    const agentCount = await page.$eval('#agent-count', el => el.textContent.trim());
    console.log(`${CYAN}[scope]${RESET} ${agentCount}\n`);

    // Take a screenshot of the loaded dashboard
    const screenshotDir = path.join(__dirname, '.uat');
    if (!fs.existsSync(screenshotDir)) fs.mkdirSync(screenshotDir, { recursive: true });
    await page.screenshot({ path: path.join(screenshotDir, 'puppeteer-dashboard.png'), fullPage: true });

    // ── Step 2: Execute each command via SSE-instrumented dispatch ────

    const commandsToRun = FILTER
      ? COMMANDS.filter(([cmd]) => cmd.startsWith(FILTER))
      : COMMANDS;

    console.log(`${BOLD}Running ${commandsToRun.length} commands...${RESET}\n`);
    console.log(`  ${pad('#', 4)} ${pad('Command', 55)} ${pad('Result', 8)} ${pad('Rows', 6)} Time`);
    console.log(`  ${'~'.repeat(4)} ${'~'.repeat(55)} ${'~'.repeat(8)} ${'~'.repeat(6)} ${'~'.repeat(8)}`);

    for (let i = 0; i < commandsToRun.length; i++) {
      const [cmd, desc, expectation] = commandsToRun[i];
      const num = String(i + 1).padStart(3, ' ');
      const cmdStart = Date.now();

      let status = 'UNKNOWN';
      let rowCount = 0;
      let errorMsg = '';
      let firstValue = '';

      try {
        // Execute command via page context:
        // 1. Open a fresh EventSource to /events
        // 2. POST URL-encoded form data to /api/dashboard/execute
        // 3. Collect SSE events until DONE or timeout
        // This exercises the full server dispatch path through the browser.
        const sseResult = await page.evaluate(
          (instruction, timeoutMs) => {
            return new Promise((resolve) => {
              const collected = { rows: 0, values: [], done: false, error: null };
              const es = new EventSource('/events');
              let timer = null;

              es.addEventListener('output', (e) => {
                // Count result-row elements in the SSE data
                const matches = e.data.match(/class="result-row"/g);
                if (matches) {
                  collected.rows += matches.length;
                }
                // Extract first value from result row
                const valMatch = e.data.match(/title="([^"]*)">[^<]*<\/td><\/tr>/);
                if (valMatch && collected.values.length < 3) {
                  collected.values.push(valMatch[1].substring(0, 120));
                }
              });

              es.addEventListener('command-status', (e) => {
                if (e.data.includes('badge-done')) {
                  collected.done = true;
                  // Give a moment for any trailing output events
                  setTimeout(() => { es.close(); resolve(collected); }, 300);
                }
              });

              es.onerror = () => {
                collected.error = 'SSE connection error';
              };

              // After SSE is open, dispatch the command
              es.onopen = () => {
                fetch('/api/dashboard/execute', {
                  method: 'POST',
                  headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
                  body: 'instruction=' + encodeURIComponent(instruction) + '&scope=__all__'
                }).catch(err => {
                  collected.error = err.message;
                });
              };

              // Timeout safety
              timer = setTimeout(() => {
                es.close();
                if (!collected.done) collected.error = 'timeout';
                resolve(collected);
              }, timeoutMs);
            });
          },
          cmd,
          COMMAND_TIMEOUT_MS
        );

        rowCount = sseResult.rows;
        firstValue = sseResult.values.length > 0 ? sseResult.values[0] : '';

        if (sseResult.error === 'timeout' && rowCount === 0 && expectation === 'rows') {
          status = 'FAIL';
          errorMsg = 'Timeout waiting for results';
          failed++;
        } else if (sseResult.error && sseResult.error !== 'timeout') {
          status = 'FAIL';
          errorMsg = sseResult.error;
          failed++;
        } else if (rowCount > 0) {
          status = 'PASS';
          passed++;
        } else if (expectation === 'any') {
          status = 'WARN';
          warned++;
        } else {
          status = 'FAIL';
          errorMsg = `Expected rows but got 0 (done: ${sseResult.done})`;
          failed++;
        }

      } catch (err) {
        status = 'FAIL';
        errorMsg = err.message.split('\n')[0].slice(0, 80);
        failed++;
      }

      const dt = Date.now() - cmdStart;
      const statusColor = status === 'PASS' ? GREEN
                        : status === 'WARN' ? YELLOW
                        : RED;
      const cmdDisplay = cmd.length > 53 ? cmd.slice(0, 50) + '...' : cmd;
      const valDisplay = firstValue ? `  ${DIM}${firstValue.slice(0, 40)}${RESET}` : '';

      console.log(
        `  ${num}. ${pad(cmdDisplay, 55)} ${statusColor}${pad(status, 8)}${RESET} ${pad(String(rowCount), 6)} ${elapsed(dt)}${valDisplay}`
      );
      if (errorMsg) {
        console.log(`       ${DIM}> ${errorMsg}${RESET}`);
      }

      results.push({ command: cmd, description: desc, status, rowCount, firstValue, errorMsg, timeMs: dt });

      await new Promise(r => setTimeout(r, INTER_COMMAND_PAUSE_MS));
    }

    // ── Step 3: Take final screenshot ────────────────────────────────

    // Execute the last command via the actual UI too, for a visual screenshot
    try {
      const input = await page.$('#instr-input');
      await input.click({ count: 3 });
      await input.press('Backspace');
      await page.type('#instr-input', 'example ping');
      await page.keyboard.press('Escape');
      await page.click('#btn-send');
      await new Promise(r => setTimeout(r, 3000));
    } catch {}
    await page.screenshot({ path: path.join(screenshotDir, 'puppeteer-final.png'), fullPage: true });

    // ── Step 4: Summary ──────────────────────────────────────────────

    const totalTime = Date.now() - startTime;

    console.log(`\n${'='.repeat(80)}`);
    console.log(`${BOLD}${CYAN}  SYNTHETIC UAT SUMMARY${RESET}`);
    console.log(`${'~'.repeat(80)}`);
    console.log(`  Total commands:  ${commandsToRun.length}`);
    console.log(`  ${GREEN}Passed:${RESET}          ${passed}`);
    console.log(`  ${YELLOW}Warnings:${RESET}        ${warned}  ${DIM}(0 rows but acceptable for this plugin)${RESET}`);
    console.log(`  ${RED}Failed:${RESET}          ${failed}`);
    console.log(`  Total time:      ${elapsed(totalTime)}`);
    console.log(`  Screenshot:      ${path.join(screenshotDir, 'puppeteer-final.png')}`);

    if (pageErrors.length > 0) {
      console.log(`\n  ${YELLOW}Browser console errors (${pageErrors.length}):${RESET}`);
      pageErrors.slice(0, 5).forEach(e => console.log(`    ${DIM}${e.slice(0, 120)}${RESET}`));
      if (pageErrors.length > 5) console.log(`    ${DIM}... and ${pageErrors.length - 5} more${RESET}`);
    }

    if (failed > 0) {
      console.log(`\n  ${RED}${BOLD}Failed commands:${RESET}`);
      results.filter(r => r.status === 'FAIL').forEach(r => {
        console.log(`    ${RED}x${RESET} ${r.command}`);
        if (r.errorMsg) console.log(`      ${DIM}${r.errorMsg}${RESET}`);
      });
    }

    // Pass rate
    const passRate = ((passed + warned) / commandsToRun.length * 100).toFixed(1);
    const passColor = passRate >= 90 ? GREEN : passRate >= 70 ? YELLOW : RED;
    console.log(`\n  ${passColor}${BOLD}Pass rate: ${passRate}%${RESET} (${passed} passed + ${warned} acceptable = ${passed + warned}/${commandsToRun.length})`);
    console.log(`${'='.repeat(80)}\n`);

    // ── Write JSON report ────────────────────────────────────────────

    const report = {
      timestamp: new Date().toISOString(),
      target: BASE_URL,
      user: USERNAME,
      duration_ms: totalTime,
      summary: { total: commandsToRun.length, passed, warned, failed, skipped },
      pass_rate: parseFloat(passRate),
      browser_errors: pageErrors.length,
      results,
    };

    const reportPath = path.join(screenshotDir, 'puppeteer-report.json');
    fs.writeFileSync(reportPath, JSON.stringify(report, null, 2));
    console.log(`  Report: ${reportPath}\n`);

    process.exit(failed > 0 ? 1 : 0);

  } catch (err) {
    console.error(`\n${RED}FATAL: ${err.message}${RESET}`);
    console.error(err.stack);
    try {
      await page.screenshot({ path: path.join(__dirname, '.uat', 'puppeteer-error.png'), fullPage: true });
    } catch {}
    process.exit(2);
  } finally {
    await browser.close();
  }
})();
