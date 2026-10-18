// Smoke-test the Tokens and principals write glue (yuzu-tokens-actions.js) in a real browser.
//
// The glue is button-driven, the dashboard CSP has no 'unsafe-eval', and the repo has no JS
// runner, so string pins alone cannot show that a click runs. This loads the page as the UAT
// admin, opens the New API token and New principal dialogs by clicking their real buttons, and
// fails on any uncaught page error or CSP violation. Nothing is submitted, so the stack is left
// as found.
//
// What it does NOT prove: that a submitted create / rotate / revoke reaches the REST route (the
// route tests and the server's own audit cover that), or the one-time-secret strip after a
// mint (it needs a real mint).
//
// Failure modes it catches:
//   - an uncaught exception while the glue loads or a handler runs (pageerror)
//   - a CSP block of an inline or eval'd handler (console "Content Security Policy" error)
//   - the glue not binding at all (no <dialog> after a click on a drawn control)
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
  await page.click('button[type="submit"]');
  await page.waitForNavigation({ waitUntil: 'networkidle2', timeout: 15000 });

  await page.goto(`${BASE}/access/tokens`, { waitUntil: 'networkidle2', timeout: 15000 });
  // The lists load by htmx on page load; the controls are part of those fragments.
  await page.waitForSelector('[data-tk="token-new"]', { timeout: 15000 });
  await page.waitForSelector('[data-tk="principal-new"]', { timeout: 15000 });

  const bound = await page.evaluate(() => typeof window.YuzuDialog === 'object');
  console.log('  YuzuDialog on window:', bound);
  if (!bound) problems.push('YuzuDialog not on window: the dialog module did not load');

  for (const [tk, title] of [['token-new', /API token/i], ['principal-new', /principal/i]]) {
    await page.click(`[data-tk="${tk}"]`);
    try {
      await page.waitForSelector('dialog.dlg[open]', { timeout: 5000 });
    } catch {
      problems.push(`${tk}: no dialog opened after the click`);
      console.log(`  FAIL  ${tk}: no dialog`);
      continue;
    }
    const heading = await page.$eval('dialog.dlg[open] #dlg-title', n => n.textContent);
    const ok = title.test(heading);
    console.log(`  ${ok ? 'OK' : 'FAIL'}  ${tk}: dialog titled "${heading}"`);
    if (!ok) problems.push(`${tk}: unexpected dialog title "${heading}"`);
    // Escape cancels; the module removes the dialog.
    await page.keyboard.press('Escape');
    await page.waitForFunction(() => !document.querySelector('dialog.dlg[open]'), { timeout: 5000 });
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
