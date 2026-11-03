// Smoke-test the Echo timeline page script (yuzu-echo-timeline.js) in a real browser.
//
// The script is event-driven, the dashboard CSP has no 'unsafe-eval', and the repo has no JS
// runner for the page, so string pins and the node driver cannot show that the real page runs
// under the real CSP. This loads /echo/timeline?id=<device> as the UAT admin, presses Play,
// scrubs the range, and clicks a drawn block, and fails on any uncaught page error or CSP
// violation. Nothing is written, so the stack is left as found.
//
// Needs a flag-enabled local server (the timeline page is hidden by default) and a device that
// has rows. Set YUZU_BASE_URL (default http://localhost:8080) and YUZU_ECHO_DEVICE_ID (the UAT
// device's agent id). Run from a directory where `puppeteer` resolves.
//
// What it does NOT prove: that the panels show the right records (the renderer tests and the
// goldens cover that).
//
// Failure modes it catches:
//   - an uncaught exception while the script loads or a handler runs (pageerror)
//   - a CSP block of an inline or eval'd handler (console "Content Security Policy" error)
//   - the script not binding (no scrub range, or Play does not engage)
import puppeteer from 'puppeteer';

const BASE = process.env.YUZU_BASE_URL || 'http://localhost:8080';
const DEVICE = process.env.YUZU_ECHO_DEVICE_ID;

async function main() {
  if (!DEVICE) {
    console.error('FAIL: set YUZU_ECHO_DEVICE_ID to the UAT device agent id');
    process.exit(2);
  }
  const browser = await puppeteer.launch({
    headless: true,
    args: ['--window-size=1400,900', '--no-sandbox'],
    defaultViewport: { width: 1400, height: 900 },
  });
  const page = await browser.newPage();

  const problems = [];
  page.on('pageerror', err => { problems.push('pageerror: ' + err.message); console.log('[pageerror]', err.message); });
  page.on('console', msg => {
    if (msg.type() !== 'error') return;
    const text = msg.text();
    console.log('[console.error]', text);
    if (/Content Security Policy|Refused to (execute|evaluate)/i.test(text)) problems.push('csp: ' + text);
  });

  await page.goto(`${BASE}/login`, { waitUntil: 'networkidle2', timeout: 15000 });
  await page.type('input[name="username"]', 'admin');
  await page.type('input[name="password"]', 'YuzuUatAdmin1!');
  // Arm the navigation wait before the click: a fast redirect would otherwise be missed.
  await Promise.all([
    page.waitForNavigation({ waitUntil: 'networkidle2', timeout: 15000 }),
    page.click('button[type="submit"]'),
  ]);

  await page.goto(`${BASE}/echo/timeline?id=${encodeURIComponent(DEVICE)}`, { waitUntil: 'networkidle2', timeout: 15000 });
  // The run fragment loads by htmx on page load; the script binds the range when it settles.
  await page.waitForSelector('#tl-run .tl-scrub', { timeout: 15000 });
  console.log('  OK  script bound: scrub range present');

  // Play: engages when the window allows it (the button starts disabled).
  const playEnabled = await page.$eval('#tl-play', b => !b.disabled);
  if (!playEnabled) {
    problems.push('Play is still disabled after the script bound');
  } else {
    await page.click('#tl-play');
    const pressed = await page.$eval('#tl-play', b => b.getAttribute('aria-pressed'));
    console.log(`  ${pressed === 'true' ? 'OK' : 'FAIL'}  Play pressed: aria-pressed=${pressed}`);
    if (pressed !== 'true') problems.push('Play did not engage');
    await new Promise(r => setTimeout(r, 1500)); // let the panels refresh at least once
    await page.click('#tl-play'); // Pause
  }

  // Scrub: move the range with the keyboard (a manual move stops playback and commits).
  await page.focus('#tl-run .tl-scrub');
  await page.keyboard.press('ArrowLeft');
  await page.keyboard.press('PageUp');
  await new Promise(r => setTimeout(r, 1200));
  console.log('  OK  scrubbed the range');

  // Click a drawn block; the selected panel follows.
  const block = await page.$('#tl-run button[data-ref]');
  if (!block) {
    problems.push('no block with data-ref to click: the device has no rows in the window');
  } else {
    await block.click();
    await new Promise(r => setTimeout(r, 1200));
    console.log('  OK  clicked a block');
  }

  await browser.close();

  if (problems.length > 0) {
    console.log(`FAIL: ${problems.length} problem(s)`);
    for (const p of problems) console.log('  -', p);
    process.exit(1);
  }
  console.log('PASS');
}

main().catch(e => { console.error(e); process.exit(1); });
