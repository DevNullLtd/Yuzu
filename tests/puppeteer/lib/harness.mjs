// Shared helpers for the browser smoke gate (ui-smoke.mjs). Pure mechanics: launch, login,
// error collection, CSP and layout assertions, request stubbing. No page-specific selectors
// live here, and nothing waits on a fixed delay: every wait is a waitForFunction or an
// event, bounded by WAIT_MS.
import puppeteer from 'puppeteer';

export const cfg = {
  baseUrl: (process.env.YUZU_BASE_URL || 'http://localhost:8080').replace(/\/+$/, ''),
  user: process.env.YUZU_UI_USER || 'admin',
  password: process.env.YUZU_UI_PASSWORD || 'YuzuUatAdmin1!',
};

export const WAIT_MS = 15000;
export const DESKTOP = { width: 1400, height: 900 };
export const NARROW = { width: 1024, height: 768 };

// PUPPETEER_EXECUTABLE_PATH, when set, is honoured by puppeteer itself.
export function launch() {
  return puppeteer.launch({
    headless: true,
    args: ['--no-sandbox'],
    defaultViewport: DESKTOP,
  });
}

export async function login(page) {
  await page.goto(cfg.baseUrl + '/login', { waitUntil: 'load', timeout: WAIT_MS });
  await page.type('input[name="username"]', cfg.user);
  await page.type('input[name="password"]', cfg.password);
  await Promise.all([
    page.waitForNavigation({ waitUntil: 'load', timeout: WAIT_MS }),
    page.click('button[type="submit"]'),
  ]);
  if (new URL(page.url()).pathname === '/login') throw new Error('login refused for ' + cfg.user);
}

// Collects uncaught page exceptions and console.error output. A CSP violation raised by an
// inline handler or eval shows up as one of these.
export function watch(page) {
  let pageErrors = [];
  let consoleErrors = [];
  page.on('pageerror', (err) => pageErrors.push(String(err && err.message ? err.message : err)));
  // The browser asks for /favicon.ico by itself, once, on the first page it loads; the
  // dashboard serves none, so that 404 is not a page defect and is not counted.
  const isFavicon = (url) => /\/favicon\.ico(\?|$)/.test(url || '');
  page.on('console', (msg) => {
    if (msg.type() === 'error' && !isFavicon(msg.location().url)) consoleErrors.push(msg.text());
  });
  // The console line for a failed load names no URL; this one does.
  page.on('response', (res) => {
    if (res.status() >= 400 && !isFavicon(res.url())) consoleErrors.push('HTTP ' + res.status() + ' ' + res.request().method() + ' ' + res.url());
  });
  return {
    pageErrors: () => [...pageErrors],
    errors: () => [...pageErrors, ...consoleErrors],
    reset() { pageErrors = []; consoleErrors = []; },
  };
}

// Waits until no htmx request is in flight (htmx puts .htmx-request on the requesting
// element for the whole round trip, swap and settle included).
export function settled(page) {
  return page.waitForFunction(
    () => document.readyState === 'complete' && !document.querySelector('.htmx-request'),
    { timeout: WAIT_MS },
  );
}

// Waits until the page has gone quiet: two animation frames and a zero-delay timer have run
// since the call, so errors raised by work scheduled during load are already delivered to
// watch(). Event-based and bounded by WAIT_MS. Call it before reading a watcher.
export async function quiesce(page) {
  await page.evaluate(() => {
    window.__quiet = false;
    requestAnimationFrame(() => requestAnimationFrame(() => setTimeout(() => { window.__quiet = true; }, 0)));
  });
  await page.waitForFunction(() => window.__quiet === true, { timeout: WAIT_MS });
}

export async function visit(page, path) {
  const res = await page.goto(path.startsWith('http') ? path : cfg.baseUrl + path, {
    waitUntil: 'load',
    timeout: WAIT_MS,
  });
  await settled(page);
  return { status: res ? res.status() : 0, headers: res ? res.headers() : {} };
}

// The shape build_csp emits (security_headers.cpp). Returns a list of problems, empty when ok.
export function assertCsp(headers) {
  const csp = headers['content-security-policy'];
  if (!csp) return ['no Content-Security-Policy header'];
  const problems = [];
  if (!csp.includes("script-src 'self' 'unsafe-inline'")) problems.push("script-src is not 'self' 'unsafe-inline'");
  if (/unsafe-eval/.test(csp)) problems.push("script-src allows 'unsafe-eval'");
  if (!csp.includes("object-src 'none'")) problems.push("object-src is not 'none'");
  return problems;
}

// Every visible submit control must sit inside its form (or dialog) and inside the viewport
// horizontally; a dialog must also fit vertically (a page form may scroll). Returns the
// violations, empty when ok. #5576: a submit button that overflows its form is unreachable.
export function submitControlsInBounds(page) {
  return page.evaluate(() => {
    const EPS = 0.5;
    const bad = [];
    const controls = document.querySelectorAll(
      'form button[type="submit"], form input[type="submit"], dialog[open] .f button.btn-primary');
    for (const el of controls) {
      const r = el.getBoundingClientRect();
      if (r.width === 0 || r.height === 0) continue; // not rendered
      const box = el.closest('dialog, form');
      const b = box.getBoundingClientRect();
      const inDialog = box.tagName === 'DIALOG';
      const label = (el.textContent || el.value || el.type).trim();
      const why = [];
      if (r.right > b.right + EPS || r.left < b.left - EPS) why.push('outside its ' + box.tagName.toLowerCase() + ' horizontally');
      if (r.bottom > b.bottom + EPS || r.top < b.top - EPS) why.push('outside its ' + box.tagName.toLowerCase() + ' vertically');
      if (r.right > window.innerWidth + EPS || r.left < -EPS) why.push('outside the viewport horizontally');
      if (inDialog && (r.bottom > window.innerHeight + EPS || r.top < -EPS)) why.push('outside the viewport vertically');
      if (why.length) bad.push(label + ': ' + why.join(', '));
    }
    return { checked: controls.length, violations: bad };
  });
}

// ---- request stubbing ----------------------------------------------------------------

const stubState = new WeakMap();

function stateFor(page) {
  let st = stubState.get(page);
  if (st) return st;
  st = { rules: [], log: [] };
  stubState.set(page, st);
  // Requests a `hold` rule is holding, so a cancellation can be attributed to the rule.
  const held = new Map();
  page.on('requestfailed', (req) => {
    const h = held.get(req);
    if (!h) return;
    // The page cancelled the request while it was paused (htmx hx-sync, an xhr abort). This event,
    // not respond() failing, is the signal: the pinned Puppeteer may swallow the protocol error for
    // a request the page has already cancelled.
    h.entry.aborted = true;
    h.rule.aborted = true;
    h.rule.onAbort();
  });
  page.on('request', (req) => {
    if (req.isInterceptResolutionHandled()) return;
    const u = new URL(req.url());
    const entry = { method: req.method(), path: u.pathname, search: u.search, body: req.postData() || '' };
    st.log.push(entry);
    const rule = st.rules.find((r) => r.method === entry.method && r.path === entry.path &&
      (!r.search || u.search.includes(r.search)));
    if (!rule) {
      // A write nobody stubbed must not reach the server (the default target is a live UAT
      // stack): it is logged above, then refused.
      if (entry.method === 'GET' || entry.method === 'HEAD') req.continue();
      else req.abort('blockedbyclient');
      return;
    }
    rule.calls.push(entry);
    const answer = () => req.respond({
      status: rule.status,
      contentType: rule.contentType,
      headers: rule.headers,
      body: rule.body,
    });
    if (!rule.hold) {
      answer();
      return;
    }
    // A held rule records the call when the request ARRIVES, then answers once `hold` settles. The
    // wait and the respond share one try/catch: an async handler that throws is an unhandled
    // rejection and ends the Node process, and answering a request the page already cancelled
    // throws. A failure of either is noted on the call entry, never raised.
    held.set(req, { rule, entry });
    (async () => {
      try {
        await rule.hold;
        await answer();
      } catch (e) {
        entry.respondError = String(e && e.message ? e.message : e);
      }
    })();
  });
  return st;
}

// Starts recording every request the page issues (requestLog). GET and HEAD pass through
// unless a stub answers them; any other method is stubbed or aborted, never sent.
export async function trace(page) {
  stateFor(page);
  await page.setRequestInterception(true);
}

// Answers matching requests inside the browser, so nothing reaches the server. Returns the
// rule; `rule.calls` lists the requests it answered. Must be installed before the request
// it targets is issued (before goto for a page that fetches on load).
//
// `hold` (optional): a promise. The request is recorded in `rule.calls` when it arrives and answered
// only after `hold` settles, so a test can supersede it first. When the page cancels it while held,
// the call entry and the rule gain `aborted = true`; `waitAborted(page, rule)` waits for that.
export async function stub(page, { method = 'GET', path, search = '', status = 200, body = '',
  contentType = 'application/json', headers = {}, hold = null }) {
  await trace(page);
  const st = stateFor(page);
  const rule = { method, path, search, status, body, contentType, headers, hold, calls: [], aborted: false };
  rule.abortSeen = new Promise((resolve) => { rule.onAbort = resolve; });
  st.rules.push(rule);
  if (hold) await installAbortProbe(page);
  return rule;
}

// Fallback abort signal, from the page itself: htmx fires `htmx:xhr:abort` on the element whose
// request it cancels. Installed with a plain addEventListener (never hx-on, which the CSP blocks),
// on this document and on every later one. Each abort is logged as the element's hx-get value.
async function installAbortProbe(page) {
  const probe = () => {
    if (window.__yuzuAborts) return;
    window.__yuzuAborts = [];
    document.addEventListener('htmx:xhr:abort', (ev) => {
      const t = ev.target;
      window.__yuzuAborts.push((t && t.getAttribute && t.getAttribute('hx-get')) || '');
    }, true);
  };
  await page.evaluateOnNewDocument(probe);
  await page.evaluate(probe);
}

// Resolves once the held request of `rule` was cancelled by the page: through the browser's
// request-failed event, or through htmx's abort event for an element whose hx-get names the rule's
// path. Bounded by WAIT_MS; the error says which signals were missing.
export async function waitAborted(page, rule) {
  let timer;
  const deadline = new Promise((_, reject) => {
    timer = setTimeout(() => reject(new Error('held request for ' + rule.path +
      ' was never observed aborted (no request-failed event, no htmx:xhr:abort)')), WAIT_MS);
  });
  const viaPage = page.waitForFunction(
    (p) => (window.__yuzuAborts || []).some((u) => u.split('?')[0] === p), { timeout: WAIT_MS }, rule.path)
    .then(() => { rule.aborted = true; }, () => new Promise(() => {}));
  try {
    await Promise.race([rule.abortSeen, viaPage, deadline]);
  } finally {
    clearTimeout(timer);
  }
}

export function clearStubs(page) {
  stateFor(page).rules.length = 0;
}

// Every request the page issued since interception was enabled, stubbed or not.
export function requestLog(page) {
  return [...stateFor(page).log];
}

// Sets a text input's value the way typing would (input event included), without keystroke
// timing.
export function setValue(page, selector, value) {
  return page.$eval(selector, (el, v) => {
    el.value = v;
    el.dispatchEvent(new Event('input', { bubbles: true }));
    el.dispatchEvent(new Event('change', { bubbles: true }));
  }, value);
}
