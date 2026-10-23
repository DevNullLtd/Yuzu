#!/usr/bin/env python3
"""Behavioural check of the TAR timeline page script (yuzu-tar-timeline.js).

test_tar_timeline_page.cpp pins the script's text; this runs it under node. The pure helpers
are checked as tables. The DOM shell is driven through tl.shell(env) against a minimal fake
DOM, a recording fetch whose promises the test settles by hand, and a fake clock whose timers
the test fires by hand, so nothing sleeps and nothing touches a network.

Rules under test:
  - a run instance binds once, from its own window and moment; an invalid window or a missing
    playhead gets no controls and no requests; a repeated or unrelated settle changes nothing;
  - every committed time change (pointer release, key, range change, nav link, block click)
    requests the moment panel, and the selected panel too while an item is selected;
  - a failed panel reports the HTTP status, a rejected fetch says the server was not reached,
    an aborted (superseded) one writes nothing, and a failed poll inside the run slot is shown;
  - playback moves the line by speed x elapsed time, commits at most once a second, and stops
    at the window end, on Pause, on any manual move, on a failed panel, when the tab is hidden
    and when the instance is replaced.

Skips (77) when `node` is not on PATH. Stdlib only.
"""
import os
import pathlib
import shutil
import subprocess
import sys

JS = pathlib.Path(__file__).resolve().parents[1] / "server/core/static/yuzu-tar-timeline.js"

DRIVER = r"""
const tl = require(process.env.YUZU_TL_JS);
const fails = [];
const eq = (a, b, msg) => { const x = JSON.stringify(a), y = JSON.stringify(b);
  if (x !== y) fails.push(msg + ': got ' + x + ' want ' + y); };
const ok = (c, msg) => { if (!c) fails.push(msg); };

// ---------------------------------------------------------------- pure helpers
{
  const k = (key, t, f, to) => tl.keyStep(key, t, f, to);
  eq([k('ArrowLeft', 150, 100, 200), k('ArrowDown', 150, 100, 200)], [149, 149], 'keyStep left/down');
  eq([k('ArrowRight', 150, 100, 200), k('ArrowUp', 150, 100, 200)], [151, 151], 'keyStep right/up');
  eq([k('PageDown', 150, 100, 200), k('PageUp', 150, 100, 200)], [140, 160], 'keyStep page');
  eq([k('Home', 150, 100, 200), k('End', 150, 100, 200)], [100, 200], 'keyStep home/end');
  eq([k('PageUp', 195, 100, 200), k('PageDown', 105, 100, 200), k('ArrowLeft', 100, 100, 200),
      k('ArrowRight', 200, 100, 200)], [200, 100, 100, 200], 'keyStep clamps at both ends');
  eq([k('a', 150, 100, 200), k('Enter', 150, 100, 200), k('Tab', 150, 100, 200)], [null, null, null],
     'keyStep leaves other keys alone');
  eq([tl.step(100, 110), tl.page(100, 110)], [1, 1], 'step is at least one second on a 10 s window');
  eq([tl.step(0, 3600), tl.page(0, 3600)], [18, 360], 'step and page scale with the window');

  eq([tl.validWindow(100, 200), tl.validWindow(0, 200), tl.validWindow(200, 100), tl.validWindow(100, 100),
      tl.validWindow(NaN, 200), tl.validWindow('100', 200), tl.validWindow(100, 200.5)],
     [true, false, false, false, false, false, false], 'validWindow');

  eq([tl.edgeClass(0.04), tl.edgeClass(0.05), tl.edgeClass(0.9), tl.edgeClass(0.91)], ['s', '', '', 'e'],
     'edgeClass thresholds');
  eq(tl.frac(150, 100, 200), 0.5, 'frac');
  eq(tl.frac(900, 100, 200), 1, 'frac clamps');
  eq(tl.playheadLeft(0.5), 'calc(var(--gut) + (100% - var(--gut)) * 0.50000)', 'playheadLeft');
  eq(tl.playheadLeft(0.5, ' + 1px'), 'calc(var(--gut) + (100% - var(--gut)) * 0.50000 + 1px)',
     'playheadLeft with an offset');

  const at = (px) => tl.tsAtPointer(px, 0, 1280, 280, 1000, 2000);
  eq([at(100), at(279), at(280), at(780), at(1280), at(5000)], [null, null, 1000, 1500, 2000, 2000],
     'tsAtPointer: gutter is null, edges map to the window, never outside it');
  eq([tl.tsAtPointer(300, 100, 1280, 280, 1000, 2000), tl.tsAtPointer(1380, 100, 1280, 280, 1000, 2000)],
     [null, 2000], 'tsAtPointer honours the rect left');
  eq(tl.tsAtPointer(500, 0, 200, 280, 1000, 2000), null, 'tsAtPointer: a plot of no width is null');

  eq([tl.isoUtc(1792486800), tl.isoUtc(0), tl.isoUtc(-5), tl.isoUtc(1709164800), tl.isoUtc(150.9)],
     ['2026-10-20T09:00:00Z', '—', '—', '2024-02-29T00:00:00Z', '1970-01-01T00:02:30Z'], 'isoUtc');
  eq(tl.isoUtc(1e15), '—', 'isoUtc: out of range is a dash');

  eq(tl.momentUrl('/f/moment?id=agent-1', 150), '/f/moment?id=agent-1&at=150', 'momentUrl appends');
  eq(tl.momentUrl('/f/moment', 150), '/f/moment?at=150', 'momentUrl starts the query when there is none');
  eq(tl.momentUrl('/f/moment?id=a', 150.9), '/f/moment?id=a&at=150', 'momentUrl floors');
  eq(tl.selectedUrl('/f/sel?id=a', 'a&b=c#d', 5), '/f/sel?id=a&ref=a%26b%3Dc%23d&at=5',
     'selectedUrl encodes the ref');
  eq(tl.pageLink('/tar/timeline', '?id=agent-1&stale=1', 42), '/tar/timeline?id=agent-1&at=42',
     'pageLink keeps only id');
  eq(tl.pageLink('/tar/timeline', '?id=a%20b', 42), '/tar/timeline?id=a+b&at=42', 'pageLink round-trips id');
  eq(tl.pageLink('/tar/timeline', '?id=x', null), '/tar/timeline?id=x', 'pageLink without a moment');

  eq([tl.playbackAllowed(100, 200), tl.playbackAllowed(100, 100 + 86399), tl.playbackAllowed(100, 100 + 86400),
      tl.playbackAllowed(200, 100), tl.playbackAllowed(0, 50)], [true, true, false, false, false],
     'playbackAllowed: under a day and valid only');
  eq([tl.nextSpeed(1), tl.nextSpeed(10), tl.nextSpeed(60), tl.nextSpeed(7)], [10, 60, 1, 1], 'nextSpeed cycles');
  eq(tl.speeds, [1, 10, 60], 'speeds');
  eq(tl.nextPlayhead(150, 10, 500, 100, 200), { t: 155, done: false }, 'nextPlayhead advances by speed x dt');
  eq(tl.nextPlayhead(198, 60, 1000, 100, 200), { t: 200, done: true }, 'nextPlayhead clamps and finishes');
  eq(tl.nextPlayhead(150, 1, -500, 100, 200), { t: 150, done: false }, 'nextPlayhead: no time travel');
  eq(tl.nextPlayhead(150, 1, 600000, 100, 200), { t: 151, done: false }, 'nextPlayhead: a stall does not jump');
  eq(tl.nextPlayhead(200, 1, 0, 100, 200).done, true, 'nextPlayhead: at the end is done');
  eq([tl.throttleDue(null, 5), tl.throttleDue(1000, 1999), tl.throttleDue(1000, 2000), tl.throttleDue(1000, 5000)],
     [true, false, true, true], 'throttleDue');
}

// ---------------------------------------------------------------- fake DOM
function parseCompound(s) {
  const c = { tag: null, classes: [], id: null, attrs: [] };
  const re = /^(?:([a-zA-Z][\w-]*)|\.([\w-]+)|#([\w-]+)|\[([\w-]+)(?:=([^\]]+))?\])/;
  while (s) {
    const m = re.exec(s);
    if (!m) throw new Error('fake DOM: unsupported selector ' + s);
    if (m[1]) c.tag = m[1]; else if (m[2]) c.classes.push(m[2]); else if (m[3]) c.id = m[3];
    else c.attrs.push([m[4], m[5]]);
    s = s.slice(m[0].length);
  }
  return c;
}
function matchesCompound(el, c) {
  if (c.tag && el.tag !== c.tag) return false;
  for (const k of c.classes) if (!el.classes.has(k)) return false;
  if (c.id && el.attrs.id !== c.id) return false;
  for (const [n, v] of c.attrs) {
    if (!(n in el.attrs)) return false;
    if (v !== undefined && el.attrs[n] !== v) return false;
  }
  return true;
}
function matchChain(el, parts, i) {
  if (!matchesCompound(el, parts[i])) return false;
  if (i === 0) return true;
  for (let a = el.parent; a; a = a.parent) if (matchChain(a, parts, i - 1)) return true;
  return false;
}
class El {
  constructor(tag) {
    this.tag = tag; this.attrs = {}; this.classes = new Set(); this.children = []; this.parent = null;
    this.listeners = {}; this.style = {}; this._text = ''; this.innerHTML = ''; this.rect = { left: 0, width: 0 };
    this.disabled = false; this.value = ''; this.captured = [];
    this.classList = { add: (c) => this.classes.add(c), remove: (c) => this.classes.delete(c),
                       contains: (c) => this.classes.has(c) };
  }
  get className() { return [...this.classes].join(' '); }
  set className(v) { this.classes = new Set(String(v).split(/\s+/).filter(Boolean)); }
  get textContent() { return this._text; }
  set textContent(v) { this._text = String(v); this.children = []; }
  setAttribute(k, v) { if (k === 'class') this.className = v; else this.attrs[k] = String(v); }
  getAttribute(k) { if (k === 'class') return this.classes.size ? this.className : null;
                    return k in this.attrs ? this.attrs[k] : null; }
  appendChild(c) { c.parent = this; this.children.push(c); return c; }
  after(n) { const p = this.parent, i = p.children.indexOf(this); n.parent = p; p.children.splice(i + 1, 0, n); }
  addEventListener(t, f) { (this.listeners[t] = this.listeners[t] || []).push(f); }
  getBoundingClientRect() { return this.rect; }
  setPointerCapture(id) { this.captured.push(id); }
  closest(sel) { const c = parseCompound(sel); for (let n = this; n; n = n.parent) if (matchesCompound(n, c)) return n; return null; }
  querySelectorAll(sel) {
    const parts = sel.split(/\s+/).map(parseCompound), out = [];
    const walk = (n) => { for (const ch of n.children) { if (matchChain(ch, parts, parts.length - 1)) out.push(ch); walk(ch); } };
    walk(this);
    return out;
  }
  querySelector(sel) { return this.querySelectorAll(sel)[0] || null; }
}
function fire(el, type, init) {
  const e = Object.assign({ type, target: el, defaultPrevented: false, button: 0,
                            preventDefault() { this.defaultPrevented = true; } }, init || {});
  for (let n = el; n; n = n.parent) for (const f of (n.listeners[type] || [])) f(e);
  return e;
}
class AC { constructor() { this.signal = { aborted: false }; } abort() { this.signal.aborted = true; } }
const flush = async () => { for (let i = 0; i < 25; i++) await Promise.resolve(); };

function build(o) {
  const body = new El('body');
  const doc = { readyState: 'complete', hidden: false, body, listeners: {},
    createElement: (t) => new El(t),
    addEventListener(t, f) { (this.listeners[t] = this.listeners[t] || []).push(f); },
    getElementById(id) { const f = (n) => { for (const c of n.children) { if (c.attrs.id === id) return c; const r = f(c); if (r) return r; } return null; }; return f(body); } };
  const mk = (tag, id, parent) => { const e = new El(tag); if (id) e.attrs.id = id; (parent || body).appendChild(e); return e; };
  const ctx = { doc, body, fetches: [], assigned: [], clip: [], clockNow: 1000000, intervals: new Map(), nextH: 1, timeouts: [] };
  ctx.copy = mk('button', 'tl-copy'); ctx.copy.textContent = 'Copy link to this moment';
  ctx.clock = mk('b', 'tl-clock');
  ctx.play = mk('button', 'tl-play'); ctx.play.disabled = true; ctx.play.attrs['aria-pressed'] = 'false'; ctx.play.textContent = 'Play';
  ctx.speed = mk('button', 'tl-speed'); ctx.speed.disabled = true; ctx.speed.textContent = 'Speed 1x';
  ctx.note = mk('span', 'tl-play-note');
  ctx.run = mk('div', 'tl-run');
  ctx.run.attrs['data-moment-url'] = '/fragments/tar/timeline/moment?id=agent-1';
  ctx.run.attrs['data-selected-url'] = '/fragments/tar/timeline/selected?id=agent-1';
  ctx.moment = mk('div', 'tl-moment');
  ctx.selected = mk('div', 'tl-selected');
  const fetchStub = (url, opts) => new Promise((resolve, reject) => ctx.fetches.push({ url, opts, signal: opts.signal, resolve, reject }));
  const env = { document: doc, fetch: fetchStub, AbortController: AC,
    location: { origin: 'https://yuzu.test', pathname: '/tar/timeline', search: '?id=agent-1&stale=1',
                assign: (u) => ctx.assigned.push(u) },
    navigator: { clipboard: { writeText: (t) => { ctx.clip.push(t); return o && o.clipFail ? Promise.reject(new Error('no')) : Promise.resolve(); } } },
    now: () => ctx.clockNow,
    setInterval: (f, ms) => { const h = ctx.nextH++; ctx.intervals.set(h, { f, ms }); return h; },
    clearInterval: (h) => { ctx.intervals.delete(h); },
    setTimeout: (f, ms) => { const h = ctx.nextH++; ctx.timeouts.push({ h, f, ms }); return h; },
    clearTimeout: (h) => { ctx.timeouts = ctx.timeouts.filter((t) => t.h !== h); } };
  ctx.tick = (ms) => { ctx.clockNow += (ms === undefined ? 250 : ms); for (const { f } of [...ctx.intervals.values()]) f(); };
  tl.shell(env).start();
  return ctx;
}
// A run instance as the renderer emits it: head, grid-less body with blocks, future shade, playhead.
function makeTl(o) {
  o = Object.assign({ from: 100, to: 200, ts: 150, blocks: [{ ref: 'p1', ts: 130 }, { ref: 'p2', ts: 170 }, { ref: null, ts: 180 }], ph: true }, o);
  const root = new El('div'); root.classes.add('tl');
  const head = new El('div'); head.classes.add('tl-head'); root.appendChild(head);
  const g = new El('div'); g.classes.add('g'); g.rect = { left: 0, width: 280 }; head.appendChild(g);
  const body = new El('div'); body.classes.add('tl-body'); body.rect = { left: 0, width: 1280 };
  body.attrs['data-from'] = String(o.from); body.attrs['data-to'] = String(o.to); root.appendChild(body);
  const buttons = o.blocks.map((b) => { const e = new El('button'); e.classes.add('tl-b'); if (b.ref) e.attrs['data-ref'] = b.ref;
    e.attrs['data-ts'] = String(b.ts); body.appendChild(e); return e; });
  const fut = new El('div'); fut.classes.add('tl-fut'); root.appendChild(fut);
  let ph = null, chip = null;
  if (o.ph) { ph = new El('div'); ph.classes.add('tl-ph'); ph.attrs['data-ts'] = String(o.ts); chip = new El('b'); ph.appendChild(chip); root.appendChild(ph); }
  return { root, head, g, body, fut, ph, chip, buttons };
}
function show(ctx, o) {
  const t = makeTl(o);
  ctx.run.children = []; ctx.run.appendChild(t.root);
  fire(ctx.body, 'htmx:afterSettle', { target: t.body });
  ctx.t = t;
  return t;
}
const urls = (ctx) => ctx.fetches.map((f) => f.url);
const ok200 = (f, html) => f.resolve({ status: 200, ok: true, text: () => Promise.resolve(html) });
const status = (f, s) => f.resolve({ status: s, ok: false, text: () => Promise.resolve('x') });
const MOM = '/fragments/tar/timeline/moment?id=agent-1&at=';
const SEL = '/fragments/tar/timeline/selected?id=agent-1&ref=';
const key = (ctx, k, init) => fire(ctx.t.body, 'keydown', Object.assign({ key: k }, init || {}));

(async () => {
  // ---- bind, once, from its own instance
  {
    const c = build(); const t = show(c);
    eq(urls(c), [MOM + '150'], 'bind requests the moment panel at the resolved moment');
    eq(t.root.querySelectorAll('.tl-scrub').length, 1, 'bind inserts one range');
    eq(t.root.children[1].classes.has('tl-scrub'), true, 'the range sits right after the head');
    eq(t.root.getAttribute('data-tl-bound'), '1', 'bound marker');
    eq(t.ph.style.left, 'calc(var(--gut) + (100% - var(--gut)) * 0.50000)', 'playhead position');
    eq(t.fut.style.left, 'calc(var(--gut) + (100% - var(--gut)) * 0.50000 + 1px)', 'future shade position');
    eq([t.chip.textContent, c.clock.textContent], ['1970-01-01T00:02:30Z', '1970-01-01T00:02:30Z'], 'chip and clock');
    eq(t.body.getAttribute('tabindex'), '0', 'body is focusable');
    eq([c.play.disabled, c.speed.disabled, c.note.textContent], [false, false, ''], 'playback is available');
    fire(c.body, 'htmx:afterSettle', { target: t.body });
    eq([urls(c).length, t.root.querySelectorAll('.tl-scrub').length], [1, 1], 'a repeated settle is a no-op');
    key(c, 'ArrowRight');
    eq(urls(c)[1], MOM + '151', 'ArrowRight steps one second on a 100 s window and commits');
    fire(c.body, 'htmx:afterSettle', { target: c.body });
    eq([urls(c).length, t.root.querySelectorAll('.tl-scrub').length], [2, 1], 'an unrelated settle neither resets t nor requests');
    key(c, 'End'); eq([t.chip.className, t.root.querySelector('.tl-scrub').value], ['e', '200'], 'End: chip hangs left, range follows');
    key(c, 'Home'); eq(t.chip.className, 's', 'Home: chip edge class');
    const e = key(c, 'x'); eq([e.defaultPrevented, urls(c).length], [false, 4], 'another key is left alone');
    ok(key(c, 'ArrowLeft').defaultPrevented, 'a handled key is prevented');
    ok(!key(c, 'ArrowLeft', { ctrlKey: true }).defaultPrevented, 'a modified key is left to the browser');

    const fresh = show(c, { from: 1000, to: 2000, ts: 1200 });
    eq(urls(c)[urls(c).length - 1], MOM + '1200', 'a new instance rebinds from its own moment');
    eq(fresh.root.querySelectorAll('.tl-scrub').length, 1, 'the new instance gets its own range');
  }

  // ---- invalid window, missing playhead
  {
    const c = build(); const t = show(c, { from: 200, to: 100, ph: false });
    eq([urls(c).length, t.root.querySelectorAll('.tl-scrub').length, t.root.getAttribute('data-tl-bound')], [0, 0, '1'], 'invalid window: no controls, no requests');
    eq([c.play.disabled, c.speed.disabled, c.note.textContent], [true, true, 'Play is not available: this window is not valid.'], 'invalid window: honest note');
    const c2 = build(); show(c2, { ph: false });
    eq(urls(c2).length, 0, 'a valid window with no playhead is not bound');
  }

  // ---- nav link, in-flight abort
  {
    const c = build(); show(c);
    const a = new El('a'); a.attrs.href = '/x'; a.attrs['data-ts'] = '120'; c.moment.appendChild(a);
    const e = fire(a, 'click', {});
    eq([e.defaultPrevented, urls(c)[1]], [true, MOM + '120'], 'nav link commits at its time and does not navigate');
    eq(c.fetches[0].signal.aborted, true, 'the superseded moment request is aborted');
    const dis = new El('button'); c.moment.appendChild(dis);
    fire(dis, 'click', {}); eq(urls(c).length, 2, 'a disabled nav button does nothing');
  }

  // ---- item click, selected panel follows
  {
    const c = build(); const t = show(c);
    fire(t.buttons[0], 'click', {});
    eq(urls(c).slice(1), [MOM + '130', SEL + 'p1&at=130'], 'a block click requests both panels');
    eq([t.buttons[0].classes.has('on'), t.buttons[1].classes.has('on')], [true, false], 'the clicked block is marked');
    key(c, 'ArrowLeft');
    eq(urls(c).slice(3), [MOM + '129', SEL + 'p1&at=129'], 'a later move refreshes both panels at the new t');
    const lk = new El('a'); lk.attrs['data-ref'] = 'p2'; lk.attrs['data-ts'] = '129'; c.selected.appendChild(lk);
    const e = fire(lk, 'click', {});
    eq([e.defaultPrevented, urls(c).slice(5)], [true, [SEL + 'p2&at=129']], 'a linked item changes the selection, not the time');
    eq([t.buttons[0].classes.has('on'), t.buttons[1].classes.has('on')], [false, true], 'the mark follows the selection');
    fire(t.buttons[2], 'click', {});
    eq(urls(c).slice(6), [MOM + '180'], 'a block with no item id requests the moment panel only');
    key(c, 'ArrowLeft');
    eq(urls(c).slice(7), [MOM + '179'], 'and clears the selection');
  }

  // ---- pointer scrubbing
  {
    const c = build(); const t = show(c);
    fire(t.body, 'pointerdown', { clientX: 100, pointerId: 7 });
    eq([t.root.classes.has('scrubbing'), t.body.captured.length], [false, 0], 'a press in the label gutter is not a scrub');
    fire(t.buttons[0], 'pointerdown', { clientX: 600, pointerId: 7 });
    eq(t.root.classes.has('scrubbing'), false, 'a press on a block is a click, not a scrub');
    fire(t.body, 'pointerdown', { clientX: 780, pointerId: 7 });
    eq([t.root.classes.has('scrubbing'), t.body.captured, t.chip.textContent], [true, [7], '1970-01-01T00:02:30Z'], 'press on the plot starts a scrub');
    fire(t.body, 'pointermove', { clientX: 1280 });
    eq(t.chip.textContent, '1970-01-01T00:03:20Z', 'moving updates the line without a request');
    eq(urls(c).length, 1, 'no request while dragging');
    fire(t.body, 'pointerup', {});
    eq([t.root.classes.has('scrubbing'), urls(c)[1]], [false, MOM + '200'], 'release commits');
    fire(t.body, 'pointermove', { clientX: 300 });
    eq(urls(c).length, 2, 'moving after release does nothing');
    const r = t.root.querySelector('.tl-scrub');
    r.value = '120'; fire(r, 'input', {});
    eq([urls(c).length, c.clock.textContent], [2, '1970-01-01T00:02:00Z'], 'range input moves the line only');
    fire(r, 'change', {});
    eq(urls(c)[2], MOM + '120', 'range change commits');
  }

  // ---- failures
  {
    const c = build(); show(c);
    status(c.fetches[0], 403); await flush();
    eq([c.moment.textContent, c.moment.innerHTML, c.moment.classes.has('busy')], ['Could not load this panel (HTTP 403).', '', false], 'non-2xx: status in text, never markup');
    key(c, 'ArrowRight');
    c.fetches[1].reject(new Error('net')); await flush();
    eq(c.moment.textContent, 'Could not reach the server.', 'rejected fetch');
    key(c, 'ArrowRight'); key(c, 'ArrowRight');
    c.fetches[2].reject(new Error('aborted')); await flush();
    eq([c.moment.textContent, c.moment.classes.has('busy')], ['Could not reach the server.', true], 'an aborted request writes nothing and the slot stays busy');
    ok200(c.fetches[3], '<b>ok</b>'); await flush();
    eq([c.moment.innerHTML, c.moment.classes.has('busy')], ['<b>ok</b>', false], 'the replacement lands and clears busy');
    key(c, 'ArrowRight'); status(c.fetches[4], 401); await flush();
    eq(c.assigned, ['/login'], '401 goes to the sign-in page');
    const inner = new El('div'); c.run.children[0].appendChild(inner);
    fire(inner, 'htmx:responseError', { detail: { xhr: { status: 500 } } });
    eq([c.run.textContent, c.run.children.length], ['Could not load the record (HTTP 500).', 0], 'a failed poll inside the run slot is reported there');
    const other = new El('div'); c.body.appendChild(other);
    fire(other, 'htmx:responseError', { detail: { xhr: { status: 500 } } });
    eq(c.run.textContent, 'Could not load the record (HTTP 500).', 'an error elsewhere is ignored');
  }

  // ---- a superseded response that still arrives is dropped
  {
    const c = build(); show(c);
    key(c, 'ArrowRight');
    ok200(c.fetches[0], '<i>old</i>'); await flush();
    eq([c.moment.innerHTML, c.moment.classes.has('busy')], ['', true], 'a superseded response writes nothing');
    ok200(c.fetches[1], '<i>new</i>'); await flush();
    eq(c.moment.innerHTML, '<i>new</i>', 'the newest response lands');
  }

  // ---- copy link
  {
    const c = build(); show(c);
    key(c, 'ArrowRight');
    fire(c.copy, 'click', {}); await flush();
    eq([c.clip, c.copy.textContent], [['https://yuzu.test/tar/timeline?id=agent-1&at=151'], 'Link copied'], 'copy link is absolute and keeps only id');
    eq(c.timeouts.length, 1, 'one label timer');
    c.timeouts[0].f(); eq(c.copy.textContent, 'Copy link to this moment', 'label restores');
    const d = build({ clipFail: true }); show(d);
    fire(d.copy, 'click', {}); await flush();
    eq(d.copy.textContent, 'Could not copy', 'copy failure is said');
  }

  // ---- playback availability
  {
    const c = build(); show(c, { from: 100, to: 100 + 86400, ts: 200 });
    eq([c.play.disabled, c.speed.disabled, c.note.textContent], [true, true, 'Play is not available for a window of a day or more.'], 'long window: Play disabled with a note');
    fire(c.play, 'click', {}); eq([c.intervals.size, c.play.attrs['aria-pressed']], [0, 'false'], 'a long window cannot be played even by a stray click');
  }

  // ---- playback: pace, throttle, coalesce
  {
    const c = build(); const t = show(c);
    fire(c.play, 'click', {});
    eq([c.play.attrs['aria-pressed'], c.play.textContent, c.intervals.size, [...c.intervals.values()][0].ms], ['true', 'Pause', 1, 250], 'Play starts one timer');
    c.tick(); c.tick(); c.tick();
    eq([urls(c).length, t.chip.textContent], [1, '1970-01-01T00:02:30Z'], 'three ticks: the line moves, nothing is requested');
    c.tick();
    eq(urls(c).slice(1), [MOM + '151'], 'the fourth tick (one second) commits once');
    for (let i = 0; i < 8; i++) c.tick();
    eq(urls(c).slice(2), [MOM + '152', MOM + '153'], 'two more seconds: two more requests, one a second');
    eq(c.fetches[urls(c).length - 2].signal.aborted, true, 'an in-flight request is aborted by the next commit (latest wins)');
    fire(c.speed, 'click', {});
    eq(c.speed.textContent, 'Speed 10x', 'speed cycles 1x to 10x');
    c.tick(); c.tick(); c.tick(); c.tick();
    eq(urls(c).length, 5, 'at 10x the next second is still one request');
    eq(urls(c)[4], MOM + '163', 'and carries the latest t (153 + 4 ticks of 2.5 s)');
    fire(c.speed, 'click', {}); eq(c.speed.textContent, 'Speed 60x', '10x to 60x');
    fire(c.speed, 'click', {}); eq(c.speed.textContent, 'Speed 1x', '60x back to 1x');
  }

  // ---- playback: Pause flushes the exact stop time once; Play resumes from there
  {
    const c = build(); const t = show(c);
    fire(c.speed, 'click', {});       // 10x
    fire(c.play, 'click', {});
    c.tick();                         // 150 + 2.5
    eq(urls(c).length, 1, 'inside the first second: no request');
    fire(c.play, 'click', {});        // Pause
    eq([c.play.attrs['aria-pressed'], c.play.textContent, c.intervals.size], ['false', 'Play', 0], 'Pause stops the timer');
    eq([urls(c)[1], t.chip.textContent], [MOM + '152', '1970-01-01T00:02:32Z'], 'Pause commits the whole second it stopped on');
    fire(c.play, 'click', {});        // Play again
    c.tick(); c.tick(); c.tick(); c.tick();
    eq(urls(c)[2], MOM + '162', 'Play resumes from the paused moment (152 + 10 s in one second)');
  }

  // ---- playback: window end stops, no loop; Play at the end starts over
  {
    const c = build(); const t = show(c, { from: 100, to: 110, ts: 108 });
    fire(c.play, 'click', {});
    for (let i = 0; i < 8; i++) c.tick();
    eq([c.play.attrs['aria-pressed'], c.intervals.size, t.chip.textContent], ['false', 0, '1970-01-01T00:01:50Z'], 'stops at the window end');
    eq(urls(c)[urls(c).length - 1], MOM + '110', 'and commits the end');
    const n = urls(c).length; c.tick(); eq(urls(c).length, n, 'no loop: nothing after the end');
    fire(c.play, 'click', {});
    eq([urls(c)[urls(c).length - 1], c.play.attrs['aria-pressed']], [MOM + '100', 'true'], 'Play at the end starts from the window start');
  }

  // ---- playback: every manual move stops it
  {
    const manual = {
      'key': (c) => key(c, 'ArrowRight'),
      'block click': (c) => fire(c.t.buttons[0], 'click', {}),
      'nav link': (c) => { const a = new El('a'); a.attrs['data-ts'] = '120'; c.moment.appendChild(a); fire(a, 'click', {}); },
      'pointer scrub': (c) => fire(c.t.body, 'pointerdown', { clientX: 780, pointerId: 1 }),
      'range input': (c) => { const r = c.t.root.querySelector('.tl-scrub'); r.value = '120'; fire(r, 'input', {}); },
    };
    for (const [name, act] of Object.entries(manual)) {
      const c = build(); show(c); fire(c.play, 'click', {}); c.tick();
      act(c);
      eq([name, c.play.attrs['aria-pressed'], c.intervals.size], [name, 'false', 0], 'manual ' + name + ' stops playback');
    }
    const c = build(); show(c); fire(c.play, 'click', {});
    key(c, 'ArrowRight');
    eq(urls(c).length, 2, 'a manual key while playing is one request, not a playback request as well');
  }

  // ---- playback: failure, hidden, unbind
  {
    const c = build(); show(c); fire(c.play, 'click', {});
    status(c.fetches[0], 500); await flush();
    eq([c.play.attrs['aria-pressed'], c.intervals.size, c.moment.textContent], ['false', 0, 'Could not load this panel (HTTP 500).'], 'a failed panel stops playback');
  }
  {
    const c = build(); show(c); fire(c.play, 'click', {});
    c.fetches[0].reject(new Error('net')); await flush();
    eq([c.play.attrs['aria-pressed'], c.intervals.size], ['false', 0], 'a rejected panel request stops playback');
  }
  {
    const c = build(); show(c); fire(c.speed, 'click', {}); fire(c.play, 'click', {}); c.tick();
    c.doc.hidden = true;
    for (const f of c.doc.listeners.visibilitychange) f({});
    eq([c.play.attrs['aria-pressed'], c.intervals.size, urls(c)[1]], ['false', 0, MOM + '152'], 'a hidden tab stops playback and keeps the panels honest');
  }
  {
    const c = build(); show(c); fire(c.play, 'click', {}); c.tick();
    const before = urls(c).length;
    show(c, { from: 1000, to: 1050, ts: 1010 });
    eq([c.play.attrs['aria-pressed'], c.intervals.size], ['false', 0], 'replacing the instance unbinds playback');
    eq(urls(c).slice(before), [MOM + '1010'], 'and the new instance binds from its own moment');
    c.tick(); eq(urls(c).length, before + 1, 'no stray timer survives');
    const d = build(); show(d); fire(d.play, 'click', {});
    fire(d.run.children[0], 'htmx:responseError', { detail: { xhr: { status: 502 } } });
    eq([d.play.attrs['aria-pressed'], d.intervals.size], ['false', 0], 'a failed poll unbinds playback');
  }

  console.log(fails.length ? 'FAIL\n' + fails.join('\n') : 'OK');
  process.exit(fails.length ? 1 : 0);
})();
"""


def main() -> int:
    node = shutil.which("node")
    if not node:
        print("SKIP: node is not on PATH")
        return 77
    # YUZU_TL_JS may point at a mutated copy of the script (mutation checks).
    env = dict(os.environ, YUZU_TL_JS=os.environ.get("YUZU_TL_JS", str(JS)))
    r = subprocess.run([node, "-e", DRIVER], capture_output=True, text=True, timeout=30, env=env)
    sys.stdout.write(r.stdout)
    sys.stderr.write(r.stderr)
    return r.returncode


if __name__ == "__main__":
    sys.exit(main())
