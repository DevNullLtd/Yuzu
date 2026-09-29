/**
 * Quick test: "help" command then a real command
 */
import puppeteer from 'puppeteer';
const sleep = ms => new Promise(r => setTimeout(r, ms));

async function main() {
  const browser = await puppeteer.launch({
    headless: true,
    args: ['--window-size=1400,900', '--no-sandbox'],
    defaultViewport: { width: 1400, height: 900 },
  });
  const page = await browser.newPage();

  // Login
  await page.goto('http://localhost:8080/login', { waitUntil: 'networkidle2' });
  await page.type('input[name="username"]', 'admin');
  await page.type('input[name="password"]', 'YuzuUatAdmin1!');
  await page.click('button[type="submit"]');
  await page.waitForNavigation({ waitUntil: 'networkidle2' });
  await sleep(2000);

  // Send "help"
  console.log('[1] Sending "help"...');
  await page.click('#instr-input', { count: 3 });
  await page.type('#instr-input', 'help');
  await page.click('#btn-send');
  await sleep(2000);
  let helpRows = await page.$$eval('.result-row', r => r.length).catch(() => 0);
  console.log(`  help rows: ${helpRows}`);

  // Now send a real command — should clear help rows
  console.log('[2] Sending "os_info os_name"...');
  await page.click('#instr-input', { count: 3 });
  await page.type('#instr-input', 'os_info os_name');
  await page.click('#btn-send');
  await sleep(3000);
  let cmdRows = await page.$$eval('.result-row', r => r.length).catch(() => 0);
  let tbodyHTML = await page.$eval('#results-tbody', el => el.innerHTML.substring(0, 300)).catch(() => '');
  console.log(`  command rows: ${cmdRows}`);
  console.log(`  tbody: ${tbodyHTML}`);

  const pass = helpRows > 10 && cmdRows >= 1;
  console.log(`\n${pass ? 'PASS' : 'FAIL'}: help=${helpRows} rows, command=${cmdRows} rows`);

  await browser.close();
  process.exit(pass ? 0 : 1);
}
main().catch(e => { console.error(e); process.exit(1); });
