// Browser smoke gate (/test Phase 5 "Browser smoke"). Runs against a live dashboard
// (YUZU_BASE_URL, YUZU_UI_USER, YUZU_UI_PASSWORD; see README.md) in three stages:
//   1. NAV CRAWL  every shell nav route answers 200 with the CSP header and no page errors,
//                 and the discovered set matches EXPECTED (nav drift fails both ways).
//   2. OVERFLOW   submit controls stay inside their form/dialog and the viewport (#5576).
//   3. SCENARIOS  stubbed write paths (#6076, add user, #5840, #6074); each forces its own
//                 precondition with a request stub, nothing is written to the server.
// One line per check; exit 1 when any check fails.
//
// `--selftest` needs no stack and no login: it proves the checks can fail, against a local
// fixture server (see the SELFTEST section).
import { mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { createServer } from 'node:http';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import {
  DESKTOP, NARROW, WAIT_MS, assertCsp, cfg, clearStubs, launch, login, quiesce, requestLog,
  setValue, settled, stub, submitControlsInBounds, trace, visit, watch,
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
const printRecord = (r) => {
  if (!r.ok) failures++;
  console.log((r.ok ? 'PASS ' : 'FAIL ') + r.name + (r.detail ? ' -- ' + r.detail : ''));
};
// The selftest swaps this to collect results instead of printing them.
let record = printRecord;
function check(name, ok, detail) {
  record({ name, ok, detail: detail || '' });
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
  const seen = new Set(); // routes already visited; the '/' seed is in here from the start
  const harvested = new Set(); // hrefs the shell chrome actually linked to; compared with EXPECTED
  const queue = ['/'];
  while (queue.length) {
    const href = queue.shift();
    if (seen.has(href)) continue;
    seen.add(href);
    w.reset();
    const { status, headers } = await visit(page, href);
    const navHrefs = await harvestNav(page);
    // Errors are read only once the page has gone quiet, and before the next route resets them.
    await quiesce(page);
    const landed = new URL(page.url()).pathname;
    const problems = [];
    if (status !== 200) problems.push('status ' + status);
    if (landed !== href) problems.push('landed on ' + landed);
    problems.push(...assertCsp(headers));
    problems.push(...w.errors().map((e) => 'page error: ' + e));
    check('crawl ' + href, problems.length === 0, problems.join('; '));
    for (const h of navHrefs) {
      harvested.add(h);
      if (!seen.has(h)) queue.push(h);
    }
  }
  const missing = EXPECTED.filter((h) => !harvested.has(h));
  const extra = [...harvested].filter((h) => !EXPECTED.includes(h));
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

async function overflow(page, forms = FORMS) {
  for (const f of forms) {
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

// Error toasts never auto-remove (settings_plugins_ui.cpp), so a toast is matched by its exact
// text: an earlier one cannot satisfy a later wait.
const errorToast = (page, text) => page.waitForFunction(
  (t) => [...document.querySelectorAll('#toast-container .toast-error')].some((el) => el.textContent === t),
  { timeout: WAIT_MS }, text);
const ROLLOUT_REFUSAL = 'Rollout must be a whole number from 0 to 100.'; // htmx:confirm handler
const UPLOAD_REFUSED = 'smoke: upload refused'; // the stubbed 500's error.message

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
  const pct = form + ' input[name="rollout_pct"]';
  const submit = form + ' button[type="submit"]';
  await (await page.$(form + ' input[name="file"]')).uploadFile(file);
  const uploads = () => requestLog(page).filter((r) => r.method === 'POST' && r.path === '/api/settings/updates/upload');

  // 1. The field's own pattern refuses "1e2" before htmx sees a submit. The browser moves
  // focus to the invalid field once it has refused, which is what we wait on.
  await setValue(page, pct, '1e2');
  await page.click(submit);
  await page.waitForFunction((sel) => document.activeElement === document.querySelector(sel),
    { timeout: WAIT_MS }, pct);
  check('#6076 the rollout pattern refuses "1e2", no upload request', uploads().length === 0,
    'uploads=' + uploads().length);

  // 2. Without the pattern only the page's own guard (the htmx:confirm handler) stands between
  // "1e2" and the request; its refusal is a toast with this exact text.
  await page.$eval(pct, (el) => el.removeAttribute('pattern'));
  await page.click(submit);
  await errorToast(page, ROLLOUT_REFUSAL);
  check('#6076 the JS guard refuses "1e2" without the pattern, no upload request', uploads().length === 0,
    'uploads=' + uploads().length);

  // 3. A valid percentage reaches the (stubbed) request; the page shows the server's message.
  const rule = await stub(page, {
    method: 'POST', path: '/api/settings/updates/upload', status: 500,
    body: JSON.stringify({ error: { message: UPLOAD_REFUSED } }),
  });
  await page.evaluate(() => { window.confirm = () => true; });
  await setValue(page, pct, '50');
  await page.click(submit);
  await errorToast(page, UPLOAD_REFUSED);
  check('#6076 a stubbed upload 500 shows the server message, no page error',
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

// #6749: the Engine Principals roster read answers 200 with Sec-Audit-Failed when its audit row
// was not saved; the Settings page says so once, outside the section that refreshes. A stub
// proves the PAGE half only (the server half is the dropped-audit C++ test).
async function scenarioEngineAudit(page) {
  const w = watch(page);
  const ROSTER = '/fragments/settings/engine-principals';
  const SENTENCE = 'An audit record for this read could not be saved. The data shown is still current.';
  const refresh = async () => {
    await Promise.all([
      page.waitForResponse((r) => new URL(r.url()).pathname === ROSTER, { timeout: WAIT_MS }),
      page.evaluate(() => htmx.trigger(document.body, 'refreshEnginePrincipals')),
    ]);
    await settled(page);
    await quiesce(page);
  };
  const banners = () => page.$$eval('#engine-principals-notices .failbox',
    (els) => els.map((e) => ({ text: e.textContent, role: e.getAttribute('role') })));
  const rosterShown = () => page.waitForFunction(
    () => !!document.querySelector('#engine-principals-section #ep-stub'), { timeout: WAIT_MS });
  const body = '<p id="ep-stub">roster stub</p>';

  // Positive: a failed audit write shows exactly one banner; repeated failures keep one; the
  // secret-reveal element outside the section survives a refresh; a later healthy refresh keeps it.
  const rule = await stub(page, { method: 'GET', path: ROSTER, status: 200, contentType: 'text/html',
    body, headers: { 'Sec-Audit-Failed': 'true' } });
  await visit(page, '/settings');
  await rosterShown();
  await page.waitForSelector('#engine-principals-notices .failbox', { timeout: WAIT_MS });
  await page.evaluate(() => { document.getElementById('engine-principal-reveal').textContent = 'reveal-sentinel'; });
  await refresh();
  await refresh();
  const shown = await banners();
  const reveal = await page.$eval('#engine-principal-reveal', (e) => e.textContent);
  const nested = await page.$eval('#engine-principals-notices',
    (e) => !e.closest('#engine-principals-section') && !e.closest('#engine-principal-reveal'));
  check('#6749 a dropped roster audit row shows one alert banner with the Tokens and principals page sentence, '
    + 'after three failed reads', shown.length === 1 && shown[0].role === 'alert' &&
    shown[0].text === SENTENCE && rule.calls.length >= 3, JSON.stringify({ shown, calls: rule.calls.length }));
  check('#6749 the banner sits outside the refreshing section and the reveal survives refreshes',
    nested && reveal === 'reveal-sentinel', JSON.stringify({ nested, reveal }));
  rule.headers = {};
  await refresh();
  check('#6749 a later healthy refresh keeps the banner (it is not auto-cleared) and still one',
    (await banners()).length === 1);
  await quiesce(page);
  check('#6749 no console error, HTTP >= 400 or page error on the positive leg',
    w.errors().length === 0, JSON.stringify(w.errors()));

  // Negative control 1: a healthy read shows no banner.
  clearStubs(page);
  const healthy = await stub(page, { method: 'GET', path: ROSTER, status: 200, contentType: 'text/html', body });
  await visit(page, '/settings');
  await rosterShown();
  await refresh();
  check('#6749 control: a healthy roster read shows no banner', (await banners()).length === 0 &&
    healthy.calls.length >= 2, JSON.stringify({ calls: healthy.calls.length }));
  await quiesce(page);
  check('#6749 control: no console error or HTTP >= 400 on the healthy leg', w.errors().length === 0,
    JSON.stringify(w.errors()));

  // Negative control 2: Sec-Audit-Failed on an UNRELATED fragment (200) and an unrelated 500 show
  // no Engine Principals banner.
  clearStubs(page);
  w.reset();
  await stub(page, { method: 'GET', path: ROSTER, status: 200, contentType: 'text/html', body });
  const tokensRule = await stub(page, { method: 'GET', path: '/fragments/settings/tokens', status: 200,
    contentType: 'text/html', body: '<p>t</p>', headers: { 'Sec-Audit-Failed': 'true' } });
  const apiRule = await stub(page, { method: 'GET', path: '/fragments/settings/api-tokens', status: 500,
    contentType: 'text/html', body: '<p>down</p>' });
  await visit(page, '/settings');
  await rosterShown();
  await quiesce(page);
  check('#6749 control: an unrelated fragment (audit-failed 200, or a 500) shows no Engine Principals banner',
    (await banners()).length === 0 && w.pageErrors().length === 0 &&
    tokensRule.calls.length >= 1 && apiRule.calls.length >= 1,
    JSON.stringify({ banners: await banners(), pageErrors: w.pageErrors(),
      tokensCalls: tokensRule.calls.length, apiCalls: apiRule.calls.length }));

  // Negative control 3: the roster itself failing (403, with the header) is not a "data is still
  // current" claim: no banner, the permission note instead.
  clearStubs(page);
  w.reset();
  await stub(page, { method: 'GET', path: ROSTER, status: 403, contentType: 'text/html',
    body: '<p>no</p>', headers: { 'Sec-Audit-Failed': 'true' } });
  await visit(page, '/settings');
  await page.waitForFunction(() => /EnginePrincipal:Read/.test(
    document.getElementById('engine-principals-section').textContent), { timeout: WAIT_MS });
  check('#6749 control: a 403 roster read with the header shows the permission note, no banner',
    (await banners()).length === 0 && w.pageErrors().length === 0, JSON.stringify(w.pageErrors()));
}

// ---- selftest ------------------------------------------------------------------------
// A gate whose checks can pass vacuously is worse than none, so every crawl and overflow check
// gets a positive control. A local fixture serves a fake shell (28 nav links, forms) with the
// real CSP shape; each case bends it one way and asserts the REAL check reports that failure.
// The baseline case first proves the clean fixture passes, so a negative case cannot be
// failing for some other reason. The scenarios need the live app and are not covered here.

const CSP_OK = "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; object-src 'none'";
const FORM_BODY = {
  '/form-ok': '<button type="submit">Save</button>',
  '/form-out': '<button type="submit" style="position:absolute;left:5000px">Save</button>',
  '/form-none': '<input name="a">',
};
// Errors raised after a stalled main thread, well past the point where visit() returns: the
// stall starts two frames after load and holds the thread for 60 ms, so they are delivered later
// than anything read straight after visit(), yet still ahead of quiesce()'s own two frames and
// timer, which queue behind this chain.
const LATE_ERRORS = `<script>addEventListener('load', () => requestAnimationFrame(() =>
  requestAnimationFrame(() => {
    for (const t = Date.now(); Date.now() - t < 60;) { /* stall */ }
    setTimeout(() => console.error('late console error'), 0);
    setTimeout(() => { throw new Error('late throw'); }, 0);
  })));</script>`;
const BASE = { nav: EXPECTED, csp: CSP_OK, late: false, notFound: '' };

function fixturePage(path, v) {
  const nav = v.nav.map((h) => '<a href="' + h + '">' + h + '</a>').join('');
  const form = FORM_BODY[path] ? '<form>' + FORM_BODY[path] + '</form>' : '';
  return '<!doctype html><title>fixture</title><aside class="shell-side"><nav>' + nav +
    '</nav></aside>' + form + (v.late ? LATE_ERRORS : '');
}

function startFixture() {
  const fx = { v: BASE, server: null, url: '' };
  fx.server = createServer((req, res) => {
    const path = new URL(req.url, 'http://fixture').pathname;
    const { v } = fx;
    if (path === v.notFound) { res.writeHead(404).end('gone'); return; }
    res.writeHead(200, { 'content-type': 'text/html', ...(v.csp ? { 'content-security-policy': v.csp } : {}) });
    res.end(fixturePage(path, v));
  });
  return new Promise((resolve) => fx.server.listen(0, '127.0.0.1', () => {
    fx.url = 'http://127.0.0.1:' + fx.server.address().port;
    resolve(fx);
  }));
}

const formPage = (path) => [{ path, ready: 'form', open: null }];
const SELF_CASES = [
  { id: 'baseline', note: 'the clean fixture passes every crawl and overflow check',
    variant: {}, run: async (p) => { await crawl(p); await overflow(p, formPage('/form-ok')); },
    expect: { passing: EXPECTED.length + 3 } }, // 28 routes + the nav match + 2 viewports
  { id: 'a', note: 'nav chrome without the "/" anchor',
    variant: { nav: EXPECTED.filter((h) => h !== '/') }, run: crawl,
    expect: { name: 'nav matches EXPECTED', detail: ['never discovered: /.'] } },
  { id: 'b', note: 'an href that is not in EXPECTED',
    variant: { nav: [...EXPECTED, '/zz-drift'] }, run: crawl,
    expect: { name: 'nav matches EXPECTED', detail: ['not in EXPECTED: /zz-drift'] } },
  { id: 'c', note: 'a delayed console.error and a delayed uncaught throw',
    variant: { nav: ['/'], late: true }, run: crawl,
    expect: { name: 'crawl /', detail: ['page error: late throw', 'page error: late console error'] } },
  { id: 'd1', note: 'a response with no Content-Security-Policy',
    variant: { nav: ['/'], csp: null }, run: crawl,
    expect: { name: 'crawl /', detail: ['no Content-Security-Policy header'] } },
  { id: 'd2', note: "a Content-Security-Policy that allows 'unsafe-eval'",
    variant: { nav: ['/'], csp: "script-src 'self' 'unsafe-inline' 'unsafe-eval'; object-src 'none'" }, run: crawl,
    expect: { name: 'crawl /', detail: ["allows 'unsafe-eval'"] } },
  { id: 'e', note: 'a submit button outside its form and the viewport',
    variant: {}, run: (p) => overflow(p, formPage('/form-out')),
    expect: { name: 'overflow /form-out', detail: ['outside its form horizontally'] } },
  { id: 'f', note: 'a form with no submit control',
    variant: {}, run: (p) => overflow(p, formPage('/form-none')),
    expect: { name: 'overflow /form-none', detail: ['no submit control found'] } },
  { id: 'g', note: 'a route that answers 404',
    variant: { nav: ['/', '/gone'], notFound: '/gone' }, run: crawl,
    expect: { name: 'crawl /gone', detail: ['status 404'] } },
];

// '' when the recorded checks are what the case expects, else why not.
function judge(expect, got) {
  const failed = got.filter((r) => !r.ok);
  if (expect.passing !== undefined) {
    return !failed.length && got.length === expect.passing ? ''
      : got.length + ' checks (want ' + expect.passing + '), failing: ' + JSON.stringify(failed);
  }
  const hit = failed.find((r) => r.name.startsWith(expect.name) && expect.detail.every((d) => r.detail.includes(d)));
  return hit ? '' : 'no failing "' + expect.name + '" check with ' + JSON.stringify(expect.detail) +
    '; failing: ' + JSON.stringify(failed);
}

async function selftest() {
  let fx;
  let browser;
  let bad = 0;
  try {
    fx = await startFixture();
    cfg.baseUrl = fx.url;
    browser = await launch();
    for (const c of SELF_CASES) {
      fx.v = { ...BASE, ...c.variant };
      const got = [];
      record = (r) => got.push(r);
      const page = await browser.newPage();
      try {
        await c.run(page);
      } catch (e) {
        got.push({ name: 'selftest ' + c.id, ok: false, detail: 'threw: ' + (e && e.message ? e.message : e) });
      }
      await page.close();
      record = printRecord;
      const why = judge(c.expect, got);
      if (why) bad++;
      console.log((why ? 'FAIL ' : 'PASS ') + 'selftest ' + c.id + ': ' + c.note + (why ? ' -- ' + why : ''));
    }
  } finally {
    if (browser) await browser.close();
    if (fx) fx.server.close();
  }
  console.log(bad ? bad + ' selftest case(s) FAILED' : 'ui-smoke selftest: every check fails when it should');
  process.exit(bad ? 1 : 0);
}

// ---- main ----------------------------------------------------------------------------

async function main() {
  let tmp;
  let browser;
  try {
    tmp = mkdtempSync(join(tmpdir(), 'yuzu_test_smoke_'));
    browser = await launch();
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
      ['engine-audit', scenarioEngineAudit],
    ];
    for (const [name, fn] of scenarios) {
      const p = await browser.newPage();
      await stage('scenario ' + name, () => fn(p));
      await p.close();
    }
  } finally {
    try {
      if (browser) await browser.close();
    } finally {
      if (tmp) rmSync(tmp, { recursive: true, force: true });
    }
  }
  console.log(failures ? failures + ' check(s) FAILED' : 'ui-smoke: all checks passed');
  process.exit(failures ? 1 : 0);
}

(process.argv.includes('--selftest') ? selftest() : main()).catch((e) => {
  console.log('FAIL ui-smoke aborted: ' + (e && e.stack ? e.stack : e));
  process.exit(1);
});
