/**
 * Puppeteer Plugin Suite — sends every non-destructive plugin action
 * through the Dashboard UI and verifies responses appear.
 *
 * Mirrors scripts/uat-command-test.sh but uses Chrome + HTMX instead of the API.
 *
 * Usage: node tests/puppeteer/dashboard-plugin-suite.mjs
 */

import puppeteer from 'puppeteer';

const BASE_URL = 'http://localhost:8080';
const USERNAME = 'admin';
const PASSWORD = 'YuzuUatAdmin1!';

// Every non-destructive plugin action, grouped.
// Format: [displayGroup, [[instruction, expectedMinRows], ...]]
// Instruction text matches what a user would type in the dashboard.
const GROUPS = [
  ['OS & System Info', [
    ['os_info os_name', 1],
    ['os_info os_version', 1],
    ['os_info os_build', 1],
    ['os_info os_arch', 1],
    ['os_info uptime', 1],
  ]],
  ['Hardware', [
    ['hardware manufacturer', 1],
    ['hardware model', 1],
    ['hardware bios', 1],
    ['hardware processors', 1],
    ['hardware memory', 1],
    ['hardware disks', 1],
  ]],
  ['Agent Status', [
    ['status version', 1],
    ['status info', 1],
    ['status health', 1],
    ['status plugins', 1],
    ['status modules', 1],
    ['status connection', 1],
    ['status switch', 1],
    ['status config', 1],
  ]],
  ['Agent Internals', [
    ['agent_actions info', 1],
    ['agent_logging get_log', 1],
    ['agent_logging get_key_files', 1],
    ['diagnostics log_level', 1],
    ['diagnostics certificates', 1],
    ['diagnostics connection_info', 1],
  ]],
  ['Network Configuration', [
    ['network_config adapters', 1],
    ['network_config ip_addresses', 1],
    ['network_config dns_servers', 1],
    ['network_config proxy', 1],
    ['network_config dns_cache', 1],
  ]],
  ['Network Diagnostics', [
    ['network_diag listening', 1],
    ['network_diag connections', 1],
    ['netstat netstat_list', 1],
    ['netstat attribution', 1],
  ]],
  ['Users & Sessions', [
    ['users logged_on', 1],
    ['users sessions', 1],
    ['users local_users', 1],
    ['users local_admins', 1],
    ['users primary_user', 1],
    ['users session_history', 1],
    ['users group_members group=Administrators', 1],
  ]],
  ['Processes & Services', [
    ['processes list', 1],
    ['processes query name=explorer', 1],
    ['services list', 1],
    ['services running', 1],
    ['procfetch procfetch_fetch', 1],
  ]],
  ['Installed Software', [
    ['installed_apps list', 1],
    ['installed_apps query name=Python', 1],
    ['installed_apps list_per_user', 1],
    ['msi_packages list', 1],
    ['msi_packages product_codes', 1],
    ['software_actions list_upgradable', 0],  // may be 0 on fresh system
    ['software_actions installed_count', 1],
  ]],
  ['Security', [
    ['antivirus products', 1],
    ['antivirus status', 1],
    ['firewall state', 1],
    ['firewall rules', 1],
    ['bitlocker state', 1],
    ['certificates list', 1],
    ['quarantine status', 1],
  ]],
  ['Windows Updates', [
    ['windows_updates installed', 0],  // may be 0
    ['windows_updates missing', 0],
    ['windows_updates pending_reboot', 1],
  ]],
  ['Device Identity', [
    ['device_identity device_name', 1],
    ['device_identity domain', 1],
    ['device_identity ou', 1],
  ]],
  ['Filesystem', [
    ['filesystem exists path=C:\\Windows\\System32\\notepad.exe', 1],
    ['filesystem list_dir path=C:\\Windows', 1],
    ['filesystem file_hash path=C:\\Windows\\System32\\notepad.exe', 1],
    ['filesystem read path=C:\\Windows\\System32\\drivers\\etc\\hosts', 1],
    ['filesystem get_acl path=C:\\Windows\\System32', 1],
    ['filesystem get_signature path=C:\\Windows\\System32\\notepad.exe', 1],
    ['filesystem search_dir root=C:\\Windows\\Temp pattern=*.log', 0],
    ['filesystem find_by_hash directory=C:\\Windows\\System32 sha256=dummy_will_not_match', 0],
  ]],
  ['Registry', [
    ['registry get_value hive=HKLM key=SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion value=ProductName', 1],
    ['registry enumerate_keys hive=HKLM key=SOFTWARE\\Microsoft\\Windows\\CurrentVersion', 1],
    ['registry key_exists hive=HKLM key=SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion', 1],
    ['registry enumerate_values hive=HKLM key=SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion', 1],
    ['registry get_user_value username=natha key=SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Explorer value=ShellState', 1],
  ]],
  ['Event Logs', [
    ['event_logs errors', 1],
    ['event_logs query log=System filter=Error count=5', 1],
  ]],
  ['WMI', [
    ['wmi query wql=SELECT Name,Version FROM Win32_OperatingSystem', 1],
    ['wmi get_instance class=Win32_ComputerSystem namespace=root\\cimv2', 1],
  ]],
  ['WiFi', [
    ['wifi list_networks', 0],  // may be 0 on desktops
    ['wifi connected', 0],
  ]],
  ['SCCM', [
    ['sccm client_version', 1],
    ['sccm site', 1],
  ]],
  ['Tags & Storage', [
    ['tags get_all', 0],  // may be empty
    ['tags count', 1],
    ['storage list', 0],
  ]],
  ['Content Distribution', [
    ['content_dist list_staged', 0],
  ]],
  ['TAR (Telemetry & Response)', [
    ['tar status', 1],
    ['tar query limit=5', 0],
    ['tar export type=all limit=5', 0],
  ]],
  ['Vulnerability Scanning', [
    ['vuln_scan summary', 1],
    ['vuln_scan inventory', 1],
  ]],
  ['HTTP Client', [
    ['http_client head url=https://httpbin.org/get', 1],
    ['http_client get url=https://httpbin.org/get', 1],
  ]],
  ['IOC Check', [
    ['ioc check ip_addresses=8.8.8.8 domains=example.com file_paths=C:\\Windows\\System32\\notepad.exe', 1],
  ]],
  ['Discovery', [
    ['discovery scan_subnet subnet=192.168.1.0/30', 0],
  ]],
];

const sleep = ms => new Promise(r => setTimeout(r, ms));

async function sendCommand(page, instruction) {
  // Clear and type
  await page.click('#instr-input', { count: 3 });
  await page.keyboard.press('Backspace');
  await page.type('#instr-input', instruction);
  await page.click('#btn-send');

  // Wait for response — poll for result rows or DONE badge
  let rows = 0;
  let waited = 0;
  const maxWait = 15000;  // 15s max (some plugins are slow)

  while (waited < maxWait) {
    await sleep(500);
    waited += 500;

    const state = await page.evaluate(() => {
      const badge = document.getElementById('status-badge');
      const badgeText = badge?.textContent?.trim() || '';
      const rows = document.querySelectorAll('#results-tbody .result-row');
      const rowCount = document.getElementById('row-count');
      const context = document.getElementById('result-context');
      return {
        badge: badgeText,
        rows: rows.length,
        rowCount: rowCount?.textContent || '0',
        isError: context?.style?.color?.includes('f85149') || false,
        context: context?.textContent?.trim()?.substring(0, 80) || '',
      };
    }).catch(() => ({ badge: '?', rows: 0, rowCount: '0', isError: false, context: '' }));

    // Unknown command — fail immediately
    if (state.isError && state.context.includes('Unknown command')) {
      return { rows: 0, waited, status: 'UNKNOWN', detail: state.context };
    }

    // Done with results
    if (state.badge === 'DONE' && state.rows > 0) {
      return { rows: state.rows, waited, status: 'PASS', detail: '' };
    }

    // Done but no rows (might be expected for some commands)
    if (state.badge === 'DONE') {
      return { rows: 0, waited, status: 'DONE_EMPTY', detail: '' };
    }

    rows = state.rows;
  }

  // Timed out — check final state
  const finalRows = await page.$$eval('#results-tbody .result-row', r => r.length).catch(() => 0);
  if (finalRows > 0)
    return { rows: finalRows, waited, status: 'PASS', detail: '(slow)' };
  return { rows: 0, waited, status: 'TIMEOUT', detail: '' };
}

async function main() {
  console.log('');
  console.log('============================================================');
  console.log('   Yuzu Dashboard — Exhaustive Plugin Test (Puppeteer)       ');
  console.log('============================================================');
  console.log('');

  const browser = await puppeteer.launch({
    headless: false,
    args: ['--window-size=1400,900', '--no-sandbox'],
    defaultViewport: { width: 1400, height: 900 },
  });

  const page = await browser.newPage();

  // Login
  await page.goto(`${BASE_URL}/login`, { waitUntil: 'networkidle2' });
  await page.type('input[name="username"]', USERNAME);
  await page.type('input[name="password"]', PASSWORD);
  await page.click('button[type="submit"]');
  await page.waitForNavigation({ waitUntil: 'networkidle2' });
  await sleep(2000);
  console.log('Login OK\n');

  let pass = 0, fail = 0, timeout = 0, total = 0;
  const failures = [];

  for (const [group, commands] of GROUPS) {
    console.log(`[${group}]`);

    for (const [instruction, minRows] of commands) {
      total++;
      const result = await sendCommand(page, instruction);

      if (result.status === 'UNKNOWN') {
        console.log(`  SKIP  ${instruction} — ${result.detail}`);
        fail++;
        failures.push(`${instruction}: ${result.detail}`);
      } else if (result.status === 'TIMEOUT') {
        console.log(`  TOUT  ${instruction} — no response in ${result.waited}ms`);
        timeout++;
        failures.push(`${instruction}: timeout`);
      } else if (result.status === 'DONE_EMPTY' && minRows === 0) {
        console.log(`  PASS  ${instruction} — (empty, expected) ${result.waited}ms`);
        pass++;
      } else if (result.rows > 0) {
        console.log(`  PASS  ${instruction} — ${result.rows} row(s) in ${result.waited}ms`);
        pass++;
      } else {
        console.log(`  FAIL  ${instruction} — 0 rows (expected >=${minRows})`);
        fail++;
        failures.push(`${instruction}: 0 rows`);
      }

      // Brief pause between commands
      await sleep(500);
    }
    console.log('');
  }

  // Summary
  console.log('============================================================');
  console.log('                      TEST SUMMARY                          ');
  console.log('============================================================');
  console.log('');
  console.log(`  PASS:    ${pass}`);
  console.log(`  FAIL:    ${fail}`);
  console.log(`  TIMEOUT: ${timeout}`);
  console.log(`  Total:   ${total}`);
  console.log('');

  if (failures.length > 0) {
    console.log('  Failures:');
    for (const f of failures) {
      console.log(`    - ${f}`);
    }
    console.log('');
  }

  if (fail === 0 && timeout === 0) {
    console.log(`  ALL ${total} TESTS PASSED`);
  }
  console.log('============================================================');

  await browser.close();
  process.exit(fail + timeout > 0 ? 1 : 0);
}

main().catch(err => {
  console.error('Suite failed:', err);
  process.exit(1);
});
