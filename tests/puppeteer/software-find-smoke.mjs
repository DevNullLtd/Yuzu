// Smoke-test the Find software panel on /software in a real browser.
//
// The panel is form- and button-driven and the dashboard CSP has no 'unsafe-eval', so string
// pins cannot show that a click runs. This loads /software as the UAT admin, searches for a name
// with the Find button, switches the kind chip to Java (the delegated click handler, fsKind) and
// back, and fails on any uncaught page error or CSP violation. The searches read only; the stack
// is left as found.
//
// What it does NOT prove: the counts or rows (the route tests compare them with the REST lookup
// through the same model), or that the stack holds any software to find; an empty answer is a pass.
//
// Failure modes it catches:
//   - an uncaught exception while the page script loads or a handler runs (pageerror)
//   - a CSP block of an inline or eval'd handler (console "Content Security Policy" error)
//   - the form or the chips not binding (the results region never changes, or the kind never moves)
import puppeteer from 'puppeteer';

const BASE = process.env.YUZU_BASE_URL || 'http://localhost:8080';

async function main() {
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

  await page.goto(`${BASE}/software`, { waitUntil: 'networkidle2', timeout: 15000 });
  // The page body is an htmx fragment; the panel is part of it.
  await page.waitForSelector('#fs-form', { timeout: 15000 });
  const first = await page.$eval('#fs-results', n => n.innerHTML);

  // Search by name with the Find button: the htmx form swaps #fs-results.
  await page.type('#fs-name', 'Example Application');
  await page.click('#fs-form button[type="submit"]');
  try {
    await page.waitForFunction(prev => document.querySelector('#fs-results').innerHTML !== prev, { timeout: 10000 }, first);
    console.log('  OK  Find swapped the results region');
  } catch {
    problems.push('Find did not change the results region');
    console.log('  FAIL  Find did not change the results region');
  }

  // The Java chip: the delegated handler moves the hidden kind and presses the chip, then re-runs the search.
  await page.click('.inv-chip[data-fs-kind="java"]');
  const kind = await page.$eval('#fs-kind', n => n.value);
  const pressed = await page.$eval('.inv-chip[data-fs-kind="java"]', n => n.getAttribute('aria-pressed'));
  const appPressed = await page.$eval('.inv-chip[data-fs-kind="app"]', n => n.getAttribute('aria-pressed'));
  const chipOk = kind === 'java' && pressed === 'true' && appPressed === 'false';
  console.log(`  ${chipOk ? 'OK' : 'FAIL'}  Java chip: kind=${kind} java=${pressed} app=${appPressed}`);
  if (!chipOk) problems.push(`Java chip did not move the kind (kind=${kind}, java=${pressed}, app=${appPressed})`);
  try {
    await page.waitForFunction(() => /Coverage\./.test(document.querySelector('#fs-results').textContent), { timeout: 10000 });
    console.log('  OK  the component search answered with its coverage note');
  } catch {
    problems.push('the Java search did not answer');
    console.log('  FAIL  the Java search did not answer');
  }

  // Back to Applications.
  await page.click('.inv-chip[data-fs-kind="app"]');
  const back = await page.$eval('#fs-kind', n => n.value);
  if (back !== 'app') problems.push(`Applications chip left kind=${back}`);

  await browser.close();

  if (problems.length > 0) {
    console.log(`FAIL: ${problems.length} problem(s)`);
    for (const p of problems) console.log('  -', p);
    process.exit(1);
  }
  console.log('PASS');
}

main().catch(e => { console.error(e); process.exit(1); });
