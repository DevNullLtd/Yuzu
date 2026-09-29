/**
 * Puppeteer test: Dashboard SSE response display bug - verification
 *
 * Sends multiple commands through the dashboard and checks that
 * result rows appear in the UI.
 */

import puppeteer from 'puppeteer';

const BASE_URL = 'http://localhost:8080';
const USERNAME = 'admin';
const PASSWORD = 'YuzuUatAdmin1!';

const COMMANDS = [
  'os_info os_name',
  'os_info os_version',
  'os_info uptime',
  'os_info os_name',
  'os_info os_version',
];

async function sleep(ms) {
  return new Promise(r => setTimeout(r, ms));
}

async function main() {
  console.log('=== Dashboard SSE Response Bug Test ===\n');

  const browser = await puppeteer.launch({
    headless: false,
    args: ['--window-size=1400,900', '--no-sandbox'],
    defaultViewport: { width: 1400, height: 900 },
  });

  const page = await browser.newPage();

  // ── Login ─────────────────────────────────────────────────────
  console.log('[1] Logging in...');
  await page.goto(`${BASE_URL}/login`, { waitUntil: 'networkidle2' });
  await page.type('input[name="username"]', USERNAME);
  await page.type('input[name="password"]', PASSWORD);
  await page.click('button[type="submit"]');
  await page.waitForNavigation({ waitUntil: 'networkidle2' });
  console.log(`  URL: ${page.url()}\n`);
  await sleep(2000);

  // ── Send commands ──────────────────────────────────────────────
  const results = [];

  for (let i = 0; i < COMMANDS.length; i++) {
    const cmd = COMMANDS[i];
    console.log(`[${i + 2}] Sending: "${cmd}"`);

    await page.click('#instr-input', { count: 3 });
    await page.type('#instr-input', cmd);
    await page.click('#btn-send');

    // Wait for result rows to appear
    let rows = 0;
    let waited = 0;
    while (waited < 8000) {
      await sleep(500);
      waited += 500;
      rows = await page.$$eval('.result-row', r => r.length).catch(() => 0);
      if (rows > 0) break;
    }

    const rowCount = await page.$eval('#row-count', el => el.textContent).catch(() => '?');
    const status = await page.$eval('#result-context', el => el.textContent).catch(() => '');
    const badge = await page.$eval('#status-badge', el => el.textContent).catch(() => '?');

    results.push({ command: cmd, rows, rowCount, status: status.trim(), badge, waited });
    console.log(`  rows=${rows}, count=${rowCount}, badge=${badge}, waited=${waited}ms`);
    console.log(`  status: "${status.trim()}"\n`);

    await sleep(1500);
  }

  // ── Summary ────────────────────────────────────────────────────
  console.log('=== Results Summary ===');
  let allPassed = true;
  for (const r of results) {
    const ok = r.rows > 0;
    if (!ok) allPassed = false;
    console.log(`  [${ok ? 'PASS' : 'FAIL'}] "${r.command}" - ${r.rows} rows (${r.waited}ms)`);
  }
  console.log('');
  if (allPassed) {
    console.log('  ALL COMMANDS SHOWED RESPONSES - BUG IS FIXED!');
  } else {
    console.log('  BUG STILL PRESENT: Some commands showed no responses');
  }

  await browser.close();
  process.exit(allPassed ? 0 : 1);
}

main().catch(err => {
  console.error('Test failed:', err);
  process.exit(1);
});
