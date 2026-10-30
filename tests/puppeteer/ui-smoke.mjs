// Browser smoke gate (/test Phase 5 "Browser smoke"). Runs against a live dashboard
// (YUZU_BASE_URL, YUZU_UI_USER, YUZU_UI_PASSWORD; see README.md) in three stages:
//   1. NAV CRAWL  every shell nav route answers 200 with the CSP header and no page errors,
//                 and the discovered set matches EXPECTED (nav drift fails both ways).
//   2. OVERFLOW   submit controls stay inside their form/dialog and the viewport (#5576).
//   3. SCENARIOS  stubbed write paths (#6076, add user, #5840, #6074); each forces its own
//                 precondition with a request stub, nothing is written to the server.
// One line per check; exit 1 when any check fails.
import { mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import {
  DESKTOP, NARROW, WAIT_MS, assertCsp, cfg, clearStubs, launch, login, requestLog, setValue,
  settled, stub, submitControlsInBounds, trace, visit, watch,
} from './lib/harness.mjs';

// The shell nav hrefs of server/core/src/app_shell.cpp (kOperate, kInstructionsSub, kPosture,
// kEstate, kSoftwareSub, kFleetSub, kAccess, kSystem, kSettingsSub). A nav change must edit
// this list in the same PR.
const EXPECTED = [
  '/', '/instructions', '/executions', '/workflows', '/approvals', '/result-sets',
  '/compliance', '/guardian', '/dex', '/echo', '/crypto',
  '/groups', '/hardware', '/software', '/auto', '/viz/fleet', '/network',
  '/access/users', '/access/tokens', '/access/audit',
  '/settings', '/settings/general', '/settings/security', '/settings/integrations',
  '/settings/pki', '/settings/plugins', '/settings/data', '/settings/developer',
];

let failures = 0;
function check(name, ok, detail) {
  if (!ok) failures++;
  console.log((ok ? 'PASS ' : 'FAIL ') + name + (detail ? ' -- ' + detail : ''));
}

async function stage(name, fn) {
  try {
    await fn();
  } catch (e) {
    check(name, false, 'threw: ' + (e && e.message ? e.message : e));
  }
}

// ---- stage 1 -------------------------------------------------------------------------

const harvestNav = (page) => page.$$eval('aside.shell-side nav a[href^="/"]',
  (as) => as.map((a) => a.getAttribute('href')));

async function crawl(page) {
  const w = watch(page);
  const seen = new Set();
  const queue = ['/'];
  while (queue.length) {
    const href = queue.shift();
    if (seen.has(href)) continue;
    seen.add(href);
    w.reset();
    const { status, headers } = await visit(page, href);
    const landed = new URL(page.url()).pathname;
    const problems = [];
    if (status !== 200) problems.push('status ' + status);
    if (landed !== href) problems.push('landed on ' + landed);
    problems.push(...assertCsp(headers));
    problems.push(...w.errors().map((e) => 'page error: ' + e));
    check('crawl ' + href, problems.length === 0, problems.join('; '));
    for (const h of await harvestNav(page)) if (!seen.has(h)) queue.push(h);
  }
  const missing = EXPECTED.filter((h) => !seen.has(h));
  const extra = [...seen].filter((h) => !EXPECTED.includes(h));
  check('nav matches EXPECTED (' + EXPECTED.length + ' routes)', !missing.length && !extra.length,
    (missing.length ? 'never discovered: ' + missing.join(', ') + '. ' : '') +
    (extra.length ? 'not in EXPECTED: ' + extra.join(', ') : ''));
}

// ---- stage 2 -------------------------------------------------------------------------

const FORMS = [
  { path: '/settings/plugins', ready: '#updates-section form[data-confirm]', open: null },
  { path: '/access/users', ready: '[data-act="add"]', open: '[data-act="add"]' },
  { path: '/access/tokens', ready: '[data-tk="token-new"]', open: '[data-tk="token-new"]' },
];

async function overflow(page) {
  for (const f of FORMS) {
    for (const vp of [DESKTOP, NARROW]) {
      const name = 'overflow ' + f.path + ' @' + vp.width + 'x' + vp.height;
      await page.setViewport(vp);
      await visit(page, f.path);
      await page.waitForSelector(f.ready, { timeout: WAIT_MS });
      if (f.open) {
        await page.click(f.open);
        await page.waitForSelector('dialog[open] .f button.btn-primary', { timeout: WAIT_MS });
      }
      const r = await submitControlsInBounds(page);
      check(name, r.checked > 0 && r.violations.length === 0,
        r.checked === 0 ? 'no submit control found' : r.violations.join('; '));
      if (f.open) {
        await page.keyboard.press('Escape');
        await page.waitForFunction(() => !document.querySelector('dialog[open]'), { timeout: WAIT_MS });
      }
    }
  }
  await page.setViewport(DESKTOP);
}

// ---- stage 3 -------------------------------------------------------------------------

// #6076: the upload form shares the htmx:confirm handler and the rollout check with the
// per-package rollout forms.
async function scenarioRolloutPct(page, tmp) {
  const w = watch(page);
  const file = join(tmp, 'yuzu_test_smoke.bin');
  writeFileSync(file, 'x');
  await trace(page);
  await visit(page, '/settings/plugins');
  const form = '#updates-section form[data-confirm]';
  await page.waitForSelector(form, { timeout: WAIT_MS });
  const input = await page.$(form + ' input[name="file"]');
  await input.uploadFile(file);
  await setValue(page, form + ' input[name="rollout_pct"]', '1e2');
  await page.click(form + ' button[type="submit"]');
  // A malformed percentage is refused by the field's own pattern before any request is made.
  await page.waitForFunction((sel) => !document.querySelector(sel + ' input[name="rollout_pct"]').validity.valid,
    { timeout: WAIT_MS }, form);
  const msg = await page.$eval(form + ' input[name="rollout_pct"]', (el) => el.validationMessage);
  const uploads = () => requestLog(page).filter((r) => r.method === 'POST' && r.path === '/api/settings/updates/upload');
  check('#6076 rollout "1e2" is refused client-side, no upload request', msg !== '' && uploads().length === 0,
    'validationMessage=' + JSON.stringify(msg) + ' uploads=' + uploads().length);

  const rule = await stub(page, {
    method: 'POST', path: '/api/settings/updates/upload', status: 500, body: '{"error":"boom"}',
  });
  await page.evaluate(() => { window.confirm = () => true; });
  await setValue(page, form + ' input[name="rollout_pct"]', '50');
  await page.click(form + ' button[type="submit"]');
  await page.waitForFunction(() => document.querySelector('#toast-container .toast-error'), { timeout: WAIT_MS });
  check('#6076 stubbed upload 500 renders the error toast, no page error',
    rule.calls.length === 1 && w.pageErrors().length === 0,
    'stub calls=' + rule.calls.length + ' pageErrors=' + JSON.stringify(w.pageErrors()));
}

async function scenarioAddUser(page) {
  const w = watch(page);
  const user = 'yuzu_smoke_user';
  const rule = await stub(page, {
    method: 'POST', path: '/api/settings/users', status: 201,
    body: JSON.stringify({ data: { username: user } }),
  });
  await visit(page, '/access/users');
  await page.waitForSelector('[data-act="add"]', { timeout: WAIT_MS });
  await page.click('[data-act="add"]');
  await page.waitForSelector('dialog[open] input[name="username"]', { timeout: WAIT_MS });
  await page.type('dialog[open] input[name="username"]', user);
  await page.type('dialog[open] input[name="password"]', 'Sm0ke-Only-Pa55word!');
  await page.click('dialog[open] .f button.btn-primary');
  await page.waitForFunction((u) => document.getElementById('acc-msg').textContent === 'Added ' + u + '.',
    { timeout: WAIT_MS }, user);
  const body = rule.calls[0] ? rule.calls[0].body : '';
  check('add-user: stubbed POST carries the typed username, page confirms, no page error',
    rule.calls.length === 1 && new URLSearchParams(body).get('username') === user && w.pageErrors().length === 0,
    'calls=' + rule.calls.length + ' pageErrors=' + JSON.stringify(w.pageErrors()));
}

// #5840: the page has no search or reset control; the open item is the Ctrl+K guard that
// must not hijack a focused field.
async function scenarioCtrlK(page) {
  const w = watch(page);
  await visit(page, '/executions');
  await page.waitForSelector('#f-def', { timeout: WAIT_MS });
  // Registered after the shell's own listener, so it sees the event after the guard has run.
  await page.evaluate(() => {
    window.__ctrlK = null;
    window.addEventListener('keydown', (e) => {
      if (e.ctrlKey && e.key === 'k') window.__ctrlK = { prevented: e.defaultPrevented };
    });
  });
  await page.focus('#f-def');
  await page.keyboard.down('Control');
  await page.keyboard.press('k');
  await page.keyboard.up('Control');
  await page.waitForFunction(() => window.__ctrlK !== null, { timeout: WAIT_MS });
  const seen = await page.evaluate(() => ({ ...window.__ctrlK, path: location.pathname,
    focused: document.activeElement && document.activeElement.id }));
  check('#5840 Ctrl+K with #f-def focused is left alone',
    seen.prevented === false && seen.path === '/executions' && seen.focused === 'f-def',
    JSON.stringify(seen));

  await page.evaluate(() => { document.activeElement.blur(); });
  const navs = [];
  page.on('request', (r) => { if (r.isNavigationRequest()) navs.push(r.url()); });
  await Promise.all([
    page.waitForNavigation({ waitUntil: 'load', timeout: WAIT_MS }),
    (async () => {
      await page.keyboard.down('Control');
      await page.keyboard.press('k');
      await page.keyboard.up('Control');
    })(),
  ]);
  // The console strips ?palette=1 once it has acted on it, so assert the navigation request
  // and the open palette rather than the final URL.
  await page.waitForFunction(() => {
    const p = document.getElementById('cmd-palette');
    return p && getComputedStyle(p).display !== 'none';
  }, { timeout: WAIT_MS });
  const target = navs.map((u) => new URL(u)).find((u) => u.pathname === '/' && u.searchParams.get('palette') === '1');
  check('#5840 Ctrl+K with nothing focused opens the console palette',
    !!target && w.pageErrors().length === 0,
    'navigations=' + JSON.stringify(navs) + ' pageErrors=' + JSON.stringify(w.pageErrors()));
}

// #6074: the audit-failed banner and the panel load error on the PKI page.
async function scenarioPki(page) {
  const w = watch(page);
  const frag = { method: 'GET', path: '/fragments/settings/ca', search: 'view=pki' };
  await stub(page, { ...frag, status: 200, contentType: 'text/html', body: '<div>ok</div>',
    headers: { 'Sec-Audit-Failed': 'true' } });
  await visit(page, '/settings/pki');
  await page.waitForSelector('#pki-notices .alert-warning', { timeout: WAIT_MS });
  const shown = await page.$eval('#pki-notices .alert-warning', (a) => !!a.querySelector('button') &&
    /audit record/.test(a.textContent));
  await page.click('#pki-notices .alert-warning button');
  await page.waitForFunction(() => !document.querySelector('#pki-notices .alert-warning'), { timeout: WAIT_MS });
  check('#6074 Sec-Audit-Failed renders the warning with Dismiss, Dismiss removes it', shown);

  clearStubs(page);
  await stub(page, { ...frag, status: 500, contentType: 'text/html', body: '<div>down</div>' });
  await visit(page, '/settings/pki');
  await page.waitForFunction(() => /HTTP 500/.test(document.getElementById('ca-section').textContent),
    { timeout: WAIT_MS });
  check('#6074 a 500 on the CA fragment says HTTP 500 in #ca-section, no page error',
    w.pageErrors().length === 0, JSON.stringify(w.pageErrors()));
}

// ---- main ----------------------------------------------------------------------------

async function main() {
  const tmp = mkdtempSync(join(tmpdir(), 'yuzu_test_smoke_'));
  const browser = await launch();
  try {
    const page = await browser.newPage();
    await login(page);
    await stage('crawl', () => crawl(page));
    await stage('overflow', () => overflow(page));
    // A fresh page per scenario: interception, stubs and window overrides never leak.
    const scenarios = [
      ['rollout_pct', (p) => scenarioRolloutPct(p, tmp)],
      ['add-user', scenarioAddUser],
      ['ctrl-k', scenarioCtrlK],
      ['pki', scenarioPki],
    ];
    for (const [name, fn] of scenarios) {
      const p = await browser.newPage();
      await stage('scenario ' + name, () => fn(p));
      await p.close();
    }
  } finally {
    await browser.close();
    rmSync(tmp, { recursive: true, force: true });
  }
  console.log(failures ? failures + ' check(s) FAILED' : 'ui-smoke: all checks passed');
  process.exit(failures ? 1 : 0);
}

main().catch((e) => {
  console.log('FAIL ui-smoke aborted: ' + (e && e.stack ? e.stack : e));
  process.exit(1);
});
