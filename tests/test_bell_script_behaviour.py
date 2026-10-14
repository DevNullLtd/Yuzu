#!/usr/bin/env python3
"""Behavioural check of the shell's notifications-bell script (kBellScript).

test_nav_shells.cpp pins the script's text; this runs it. The script is cut out of
server/core/src/app_shell.cpp and executed under node against a minimal fake DOM, fake
clock, fake timers and a queued fetch, then asserts what an operator would see:
rendering (99+, text-only title, level fallback, 500-char clamp, relative time, no
action buttons for an unsafe id), the idle gate (a foregrounded tab after more than
five minutes without input does not fetch until the next input), 401 stopping the
poll for good, a failed refresh clearing the stale count, and the two-click action
(first click sends nothing, second sends the exact POST, 200 removes the row).

Skips cleanly when `node` is not on PATH. Stdlib only.
"""
import pathlib
import shutil
import subprocess
import sys

SRC = pathlib.Path(__file__).resolve().parents[1] / "server/core/src/app_shell.cpp"
OPEN, CLOSE = 'kBellScript = R"JS(<script>', "</script>)JS\""

DRIVER = r"""
const js = require('fs').readFileSync(0, 'utf8');
class E {
  constructor(t) { this.tag = t; this.children = []; this.attrs = {}; this._t = ''; this.parentNode = null;
    this.hidden = false; this.className = ''; this.L = {}; this.open = false; this.disabled = false;
    this.classList = { add: c => { this.className += ' ' + c; }, remove: () => {} }; }
  get textContent() { return this._t + this.children.map(c => c.textContent).join(''); }
  set textContent(v) { this._t = String(v); this.children = []; }
  appendChild(c) { c.parentNode = this; this.children.push(c); return c; }
  removeChild(c) { this.children = this.children.filter(x => x !== c); }
  remove() { if (this.parentNode) this.parentNode.removeChild(this); }
  setAttribute(k, v) { this.attrs[k] = String(v); }
  addEventListener(t, f) { (this.L[t] = this.L[t] || []).push(f); }
  get nextElementSibling() { const p = this.parentNode; return p ? p.children[p.children.indexOf(this) + 1] || null : null; }
  all(tag, out = []) { this.children.forEach(c => { if (c.tag === tag) out.push(c); c.all(tag, out); }); return out; }
  querySelector(s) { return this.all(s)[0] || null; }
  querySelectorAll(s) { return this.all(s); }
  contains(n) { for (let x = n; x; x = x.parentNode) if (x === this) return true; return false; }
  focus() { doc.activeElement = this; }
  click() { (this.L.click || []).forEach(f => f({ target: this })); }
}
const ids = {};
for (const i of ['shell-bell', 'shell-bell-sum', 'shell-bell-n', 'shell-bell-list', 'shell-bell-note']) ids[i] = new E('x');
ids['shell-bell'].hidden = true;
const DL = {};
const doc = { activeElement: null, hidden: false, getElementById: i => ids[i], createElement: t => new E(t),
  createTextNode: t => { const e = new E('#t'); e._t = String(t); return e; },
  addEventListener(t, f) { (DL[t] = DL[t] || []).push(f); } };
let now = 1e12, fetches = [], queue = [], timers = [];
const realDate = Date;
globalThis.Date = class extends realDate { static now() { return now; } };
globalThis.document = doc;
globalThis.AbortSignal = { timeout: () => ({}) };
globalThis.setInterval = (f, ms) => { timers.push({ f, ms }); return timers.length; };
globalThis.setTimeout = () => 1; globalThis.clearTimeout = () => {};
globalThis.fetch = (u, o) => { fetches.push({ u, m: (o && o.method) || 'GET' });
  const r = queue.shift() || { status: 200, body: { notifications: [], unread_count: 0 } };
  if (r.fail) return Promise.reject(new Error('net'));
  return Promise.resolve({ status: r.status, ok: r.status >= 200 && r.status < 300, json: () => Promise.resolve(r.body) }); };
const feed = (n, items) => ({ status: 200, body: { unread_count: n, notifications: items } });
queue.push(feed(150, [
  { id: 7, timestamp: now - 5000, level: '<img onerror=1>', title: '<b>x</b>', message: 'm'.repeat(900) },
  { id: '7;1', timestamp: now - 7200e3, level: 'warn', title: null, message: null }]));
(0, eval)(js);
const tick = async () => { for (let i = 0; i < 6; i++) await new Promise(r => setImmediate(r)); };
const fire = t => (DL[t] || []).forEach(f => f({ type: t, key: '' }));
const fails = [];
const ok = (c, m) => { if (!c) fails.push(m); };
const R = ids['shell-bell'], list = ids['shell-bell-list'], chip = ids['shell-bell-n'], note = ids['shell-bell-note'];
(async () => {
  await tick();
  ok(fetches[0].u === '/api/notifications?limit=10', 'poll url');
  ok(R.hidden === false, 'bell revealed after a valid answer');
  ok(chip.textContent === '99+', '99+ clamp');
  const rows = list.children;
  ok(rows.length === 2, 'two rows');
  ok(rows[0].textContent.startsWith('<b>x</b>'), 'title is literal text');
  ok(rows[0].attrs['data-level'] === 'info', 'unknown level falls back to info');
  ok(rows[0].children[1].textContent.length === 500 && rows[0].children[1].attrs.title.length === 500, 'message clamp');
  ok(rows[0].children[2].textContent === 'just now' && rows[1].children[2].textContent === '2 h ago', 'relative time');
  ok(rows[1].children.length === 3 && rows[1].textContent.startsWith(''), 'unsafe id gets no buttons; null title is empty');
  ok(note.textContent.includes('Showing the newest 2 of 150'), 'truncation note');

  // two-click action: first click sends nothing, second sends the exact POST, 200 removes the row
  const before = fetches.length;
  const mark = rows[0].children[3].children[0];
  mark.click();
  ok(fetches.length === before, 'first click sends nothing');
  queue.push({ status: 200, body: { status: 'ok' } }, feed(149, [rows[1] ? { id: 8, timestamp: now, level: 'info', title: 't', message: 'm' } : null]));
  mark.click();
  await tick();
  ok(fetches[before].u === '/api/notifications/7/read' && fetches[before].m === 'POST', 'second click POSTs read');

  // idle gate: > 5 min without input, a foregrounded tab must not fetch until input
  const n0 = fetches.length;
  now += 300001; fire('visibilitychange'); await tick();
  ok(fetches.length === n0, 'no fetch on foreground after idle');
  fire('pointerdown'); await tick();
  ok(fetches.length === n0 + 1, 'input resumes polling at once');

  // failed refresh clears the stale count and says so
  queue.push({ status: 500, body: {} });
  now += 61000; fire('keydown'); timers.forEach(t => t.f()); await tick();
  ok(chip.hidden === true && note.textContent.includes('could not be refreshed'), 'failure clears stale count');

  // 401 hides the bell and stops for good
  queue.push({ status: 401, body: {} });
  now += 61000; fire('keydown'); timers.forEach(t => t.f()); await tick();
  const n1 = fetches.length;
  ok(R.hidden === true, '401 hides the bell');
  now += 61000; fire('keydown'); timers.forEach(t => t.f()); await tick();
  ok(fetches.length === n1, 'no polling after 401');
  if (fails.length) { console.log(fails.join('\n')); process.exit(1); }
  console.log('bell script behaviour ok');
})();
"""


def main() -> int:
    node = shutil.which("node")
    if node is None:
        print("SKIP: node not on PATH")
        return 77
    text = SRC.read_text()
    a = text.index(OPEN) + len(OPEN)
    js = text[a:text.index(CLOSE, a)]
    r = subprocess.run([node, "-e", DRIVER], input=js, capture_output=True, text=True, timeout=30)
    sys.stdout.write(r.stdout + r.stderr)
    return r.returncode


if __name__ == "__main__":
    sys.exit(main())
