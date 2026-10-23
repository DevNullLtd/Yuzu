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
    an aborted (superseded) one writes nothing, and a failed, unreachable or timed-out poll
    inside the run slot is shown;
  - every panel request carries HX-Request; a 401 or a redirect ends the session once: playback
    stops, both panels are aborted, nothing else is written and /login is assigned once;
  - a held key moves the line on every repeat but requests at most once a second (one immediate,
    one trailing with the newest time, none at all at the window edge, none when it comes back to
    the time already shown); a request in flight is never answered with another one from the
    timer, unless it has gone unanswered for ten seconds;
  - a click (block, Previous / Next) is one deliberate choice: it requests at once, even inside
    the second after another commit, and a click that changes nothing requests nothing, unless
    a panel failed and a repeat click retries it;
  - playback moves the line by speed x elapsed time, commits at most once a second and only once
    the previous answer is in, and stops at the window end, on Pause, on any manual move, on a
    failed panel, when the tab is hidden and when the instance is replaced;
  - a scrub that cannot capture the pointer, is cancelled or loses its button or its capture
    never sticks, and Play cannot start during one; a modified or middle click on a link is left
    to the browser.

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

  eq(['150', '0', '999999999999999', '007'].map(tl.epochAttr), [150, 0, 999999999999999, 7], 'epochAttr: plain digits');
  eq(['0x10', '1e3', '', null, undefined, ' 150', '150 ', '-5', '1.5', '+5', '1234567890123456'].map(tl.epochAttr)
       .map((v) => (Number.isNaN(v) ? 'NaN' : v)),
     Array(11).fill('NaN'), 'epochAttr: hex, exponent, empty, missing, spaces, signs, decimals and 16 digits are NaN');

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
  eq([tl.throttleDue(-Infinity, 5), tl.throttleDue(1000, 1999), tl.throttleDue(1000, 2000), tl.throttleDue(1000, 5000)],
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
    this.listeners = {}; this.style = {}; this._text = ''; this._html = ''; this.rect = { left: 0, width: 0 };
    this.disabled = false; this.value = ''; this.captured = [];
    this.classList = { add: (c) => this.classes.add(c), remove: (c) => this.classes.delete(c),
                       contains: (c) => this.classes.has(c),
                       toggle: (c, f) => (f ? this.classes.add(c) : this.classes.delete(c)) };
  }
  get className() { return [...this.classes].join(' '); }
  set className(v) { this.classes = new Set(String(v).split(/\s+/).filter(Boolean)); }
  get textContent() { return this._text; }
  set textContent(v) { this._text = String(v); this._html = ''; this.children = []; }
  get innerHTML() { return this._html; }
  set innerHTML(v) { this._html = String(v); this._text = ''; this.children = []; }
  setAttribute(k, v) { if (k === 'class') this.className = v; else this.attrs[k] = String(v); }
  getAttribute(k) { if (k === 'class') return this.classes.size ? this.className : null;
                    return k in this.attrs ? this.attrs[k] : null; }
  removeAttribute(k) { delete this.attrs[k]; }
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
  const ctx = { doc, body, fetches: [], assigned: [], clip: [], clockNow: 1000000, intervals: new Map(), nextH: 1 };
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
  ctx.prompt = new El('p'); ctx.prompt.classes.add('tl-empty'); ctx.selected.appendChild(ctx.prompt);
  const fetchStub = (url, opts) => new Promise((resolve, reject) => ctx.fetches.push({ url, opts, signal: opts.signal, resolve, reject }));
  const env = { document: doc, fetch: fetchStub, AbortController: AC,
    location: { origin: 'https://yuzu.test', pathname: '/tar/timeline', search: '?id=agent-1&stale=1',
                assign: (u) => ctx.assigned.push(u) },
    navigator: o && o.noClip ? {} : { clipboard: { writeText: (t) => { ctx.clip.push(t); return o && o.clipFail ? Promise.reject(new Error('no')) : Promise.resolve(); } } },
    now: () => ctx.clockNow,
    setInterval: (f, ms) => { const h = ctx.nextH++; ctx.intervals.set(h, { f, ms }); return h; },
    clearInterval: (h) => { ctx.intervals.delete(h); } };
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
  if (o.ph) { ph = new El('div'); ph.classes.add('tl-ph'); if (o.ts !== null) ph.attrs['data-ts'] = String(o.ts); chip = new El('b'); ph.appendChild(chip); root.appendChild(ph); }
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
// Answer every request still waiting (the settled ones and the superseded ones ignore a second answer).
const settle = async (ctx) => { for (const f of ctx.fetches) ok200(f, '<i>ok</i>'); await flush(); };
// A key as a person taps it and a click as a person makes it: a second after the last commit,
// so each one commits at once. keyRaw is a key with no time passing (a held key's repeat).
const keyRaw = (ctx, k, init) => fire(ctx.t.body, 'keydown', Object.assign({ key: k }, init || {}));
const key = (ctx, k, init) => { ctx.clockNow += 1000; return keyRaw(ctx, k, init); };
const tap = (ctx, el, init) => { ctx.clockNow += 1000; return fire(el, 'click', init); };

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
    eq([t.body.getAttribute('role'), t.body.getAttribute('aria-label')],
       ['group', 'Timeline. Arrow, Page, Home and End keys move the moment.'], 'the focus stop is named');
    const rg = t.root.querySelector('.tl-scrub');
    eq([rg.getAttribute('aria-label'), rg.getAttribute('aria-valuetext')], ['Time, in seconds', '1970-01-01T00:02:30Z'],
       'the range is named and reads the moment as a time');
    eq([c.play.disabled, c.speed.disabled, c.note.textContent], [false, false, ''], 'playback is available');
    eq(c.speed.getAttribute('aria-label'), null, 'the speed button is named by its text, not an aria-label that would hide it');
    fire(c.body, 'htmx:afterSettle', { target: t.body });
    eq([urls(c).length, t.root.querySelectorAll('.tl-scrub').length], [1, 1], 'a repeated settle is a no-op');
    key(c, 'ArrowRight');
    eq(urls(c)[1], MOM + '151', 'ArrowRight steps one second on a 100 s window and commits');
    eq(rg.getAttribute('aria-valuetext'), '1970-01-01T00:02:31Z', 'the range reads the new moment');
    fire(c.body, 'htmx:afterSettle', { target: c.body });
    eq([urls(c).length, t.root.querySelectorAll('.tl-scrub').length], [2, 1], 'an unrelated settle neither resets t nor requests');
    key(c, 'End'); eq([t.chip.className, t.root.querySelector('.tl-scrub').value], ['e', '200'], 'End: chip hangs left, range follows');
    key(c, 'Home'); eq(t.chip.className, 's', 'Home: chip edge class');
    const e = key(c, 'x'); eq([e.defaultPrevented, urls(c).length], [false, 4], 'another key is left alone');
    ok(key(c, 'ArrowLeft').defaultPrevented, 'a handled key is prevented');
    eq(urls(c).length, 4, 'a key at the window edge changes nothing and requests nothing');
    for (const m of [{ ctrlKey: true }, { altKey: true }, { metaKey: true }])
      ok(!key(c, 'ArrowRight', m).defaultPrevented, 'a modified key is left to the browser: ' + Object.keys(m)[0]);
    eq(urls(c).length, 4, 'and requests nothing');
    ok(!fire(c.run, 'keydown', { key: 'ArrowRight' }).defaultPrevented, 'a key outside the timeline is left alone');
    eq(urls(c).length, 4, 'and requests nothing either');

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
    const c3 = build(); const t3 = show(c3, { ts: null });
    eq([urls(c3).length, t3.root.querySelectorAll('.tl-scrub').length, c3.play.disabled, c3.note.textContent],
       [0, 0, true, 'Play is not available: this window is not valid.'], 'a playhead with no data-ts is not bound at 0');
    for (const bad of [{ from: '0x10', to: 200 }, { from: 100, to: '2e2' }, { ts: '1e2' }, { ts: ' 150' }, { ts: '' }, { ts: '-5' }]) {
      const d = build(); const td = show(d, bad);
      eq([JSON.stringify(bad), urls(d).length, td.root.querySelectorAll('.tl-scrub').length], [JSON.stringify(bad), 0, 0],
         'markup numbers that are not plain digits bind nothing');
    }
  }

  // ---- nav link, in-flight abort
  {
    const c = build(); show(c);
    const a = new El('a'); a.attrs.href = '/x'; a.attrs['data-ts'] = '120'; c.moment.appendChild(a);
    const e = tap(c, a, {});
    eq([e.defaultPrevented, urls(c)[1]], [true, MOM + '120'], 'nav link commits at its time and does not navigate');
    eq(c.fetches[0].signal.aborted, true, 'the superseded moment request is aborted');
    const dis = new El('button'); c.moment.appendChild(dis);
    fire(dis, 'click', {}); eq(urls(c).length, 2, 'a disabled nav button does nothing');
  }

  // ---- modified and middle clicks on a link are the browser's, not ours
  {
    const c = build(); const t = show(c);
    const a = new El('a'); a.attrs['data-ts'] = '120'; c.moment.appendChild(a);
    const lk = new El('a'); lk.attrs['data-ref'] = 'p2'; lk.attrs['data-ts'] = '129'; c.selected.appendChild(lk);
    tap(c, t.buttons[0], {}); await settle(c);
    fire(c.play, 'click', {});
    const n = urls(c).length;
    for (const init of [{ ctrlKey: true }, { metaKey: true }, { shiftKey: true }, { altKey: true }, { button: 1 }]) {
      for (const el of [a, lk]) {
        c.clockNow += 1000;
        const e = fire(el, 'click', init);
        eq([JSON.stringify(init), el === a ? 'nav' : 'linked', e.defaultPrevented, urls(c).length, c.play.attrs['aria-pressed'], c.intervals.size],
           [JSON.stringify(init), el === a ? 'nav' : 'linked', false, n, 'true', 1], 'a modified or middle click is left alone and playback keeps running');
      }
    }
    ok(tap(c, a, {}).defaultPrevented, 'a plain click on the same link is still ours');
  }

  // ---- item click, selected panel follows
  {
    const c = build(); const t = show(c);
    tap(c, t.buttons[0], {});
    eq(urls(c).slice(1), [MOM + '130', SEL + 'p1&at=130'], 'a block click requests both panels');
    eq([t.buttons[0].classes.has('on'), t.buttons[1].classes.has('on')], [true, false], 'the clicked block is marked');
    key(c, 'ArrowLeft');
    eq(urls(c).slice(3), [MOM + '129', SEL + 'p1&at=129'], 'a later move refreshes both panels at the new t');
    const lk = new El('a'); lk.attrs['data-ref'] = 'p2'; lk.attrs['data-ts'] = '129'; c.selected.appendChild(lk);
    const e = fire(lk, 'click', {});
    eq([e.defaultPrevented, urls(c).slice(5)], [true, [SEL + 'p2&at=129']], 'a linked item changes the selection, not the time');
    eq([t.buttons[0].classes.has('on'), t.buttons[1].classes.has('on')], [false, true], 'the mark follows the selection');
    tap(c, t.buttons[2], {});
    eq(urls(c).slice(6), [MOM + '180'], 'a block with no item id requests the moment panel only');
    key(c, 'ArrowLeft');
    eq(urls(c).slice(7), [MOM + '179'], 'and clears the selection');
  }

  // ---- a click is one deliberate choice: immediate, even inside the second after another commit
  {
    const c = build(); const t = show(c);
    fire(t.body, 'pointerdown', { clientX: 780, pointerId: 1 });
    fire(t.body, 'pointermove', { clientX: 1280, buttons: 1 });
    fire(t.body, 'pointerup', {});                    // the release commits 200
    c.clockNow += 100;
    fire(t.buttons[0], 'click', {});
    eq(urls(c).slice(2), [MOM + '130', SEL + 'p1&at=130'], 'a block click 100 ms after a scrub release requests both panels at once');
    eq([t.buttons[0].classes.has('on'), c.intervals.size], [true, 0], 'the highlight and the panels agree, and nothing is owed to the timer');
    const a = new El('a'); a.attrs['data-ts'] = '120'; c.moment.appendChild(a);
    c.clockNow += 100;
    ok(fire(a, 'click', {}).defaultPrevented, 'Previous / Next is ours');
    eq(urls(c).slice(4), [MOM + '120', SEL + 'p1&at=120'], 'and so is its refresh, 100 ms after that: both panels, at once');
    eq(c.intervals.size, 0, 'again with nothing owed to the timer');
  }

  // ---- a click that changes nothing requests nothing: a held Enter on a button repeats the click
  {
    const c = build(); const t = show(c, { blocks: [{ ref: 'p1', ts: 130 }, { ref: 'p2', ts: 130 }, { ref: null, ts: 180 }] });
    tap(c, t.buttons[0], {});
    const n = urls(c).length;
    eq(n, 3, 'the first click on a block requests both panels');
    for (let i = 0; i < 20; i++) fire(t.buttons[0], 'click', {});
    eq(urls(c).length, n, 'twenty more clicks on the same block request nothing');
    const a = new El('a'); a.attrs['data-ts'] = '130'; c.moment.appendChild(a);
    ok(fire(a, 'click', {}).defaultPrevented, 'a Previous / Next link to the time already shown is still ours');
    eq(urls(c).length, n, 'and requests nothing');
    fire(t.buttons[1], 'click', {});
    eq(urls(c).slice(n), [MOM + '130', SEL + 'p2&at=130'], 'the same time with another item is a change: both panels');
    keyRaw(c, 'ArrowRight');                          // inside the second: the line moves, the commit is owed
    eq(c.intervals.size, 1, 'the key owes a commit');
    fire(t.buttons[1], 'click', {});
    eq([t.chip.textContent, urls(c).length], ['1970-01-01T00:02:10Z', n + 2], 'a click back on the block shown moves the line back and requests nothing');
    c.tick();
    eq([c.intervals.size, urls(c).length], [0, n + 2], 'and the commit the key had owed is dropped');
    tap(c, t.buttons[2], {});
    eq(urls(c).slice(n + 2), [MOM + '180'], 'a block with no item is a change when the item or time differs');
    for (let i = 0; i < 5; i++) fire(t.buttons[2], 'click', {});
    eq(urls(c).length, n + 3, 'and then asks for nothing more');
  }

  // ---- a failed panel is asked again by a repeat click, but a held Enter does not repeat the retry
  {
    const c = build(); const t = show(c);
    tap(c, t.buttons[0], {});                          // p1 at 130
    status(c.fetches[2], 500); await flush();          // the selected panel failed
    eq(c.selected.getAttribute('role'), 'alert', 'the selected panel failed');
    const m = c.fetches.length;
    fire(t.buttons[0], 'click', {});
    eq(urls(c).slice(m), [MOM + '130', SEL + 'p1&at=130'], 'a repeat click on the item whose panel failed asks again');
    for (let i = 0; i < 20; i++) fire(t.buttons[0], 'click', {});
    eq(urls(c).length, m + 2, 'and twenty more while that retry is out ask for nothing');
    const d = build(); show(d);
    status(d.fetches[0], 500); await flush();          // the moment panel failed
    const k = d.fetches.length;
    const a = new El('a'); a.attrs['data-ts'] = '150'; d.moment.appendChild(a);
    fire(a, 'click', {});
    eq(urls(d).slice(k), [MOM + '150'], 'a failed moment panel is asked again by a click on the time shown');
  }

  // ---- no selection puts the shell's prompt back: on a count-block click and on a rebind
  {
    const c = build(); const t = show(c);
    tap(c, t.buttons[0], {});                          // p1 at 130
    ok200(c.fetches[2], '<b>p1 at 130</b>'); await flush();
    eq([c.selected.innerHTML, c.selected.children.length], ['<b>p1 at 130</b>', 0], 'a selected response replaces the prompt');
    tap(c, t.buttons[2], {});                          // a count block: no item id
    eq([c.selected.children[0] === c.prompt, c.selected.children.length, c.selected.innerHTML], [true, 1, ''],
       'a click with no item puts the prompt node back');
    key(c, 'ArrowRight');
    eq(urls(c).slice(3), [MOM + '180', MOM + '181'], 'and no selected panel is requested any more');
    tap(c, t.buttons[1], {});                          // p2 at 170, selected request in flight
    tap(c, t.buttons[2], {});
    eq([c.fetches[6].signal.aborted, c.selected.children[0] === c.prompt], [true, true], 'an in-flight selected request is aborted and the prompt is back');
    ok200(c.fetches[6], '<i>late</i>'); await flush();
    eq([c.selected.children[0] === c.prompt, c.selected.innerHTML], [true, ''], 'its late answer writes nothing');
    tap(c, t.buttons[0], {});                          // p1 again
    status(c.fetches[c.fetches.length - 1], 500); await flush();
    eq([c.selected.textContent, c.selected.getAttribute('role')], ['Could not load this panel (HTTP 500).', 'alert'],
       'a failed selected panel is announced');
    tap(c, t.buttons[0], {});
    ok200(c.fetches[c.fetches.length - 1], '<b>p1 again</b>'); await flush();
    eq([c.selected.innerHTML, c.selected.getAttribute('role')], ['<b>p1 again</b>', null], 'the next selection lands and stops being an alert');
    tap(c, t.buttons[1], {}); status(c.fetches[c.fetches.length - 1], 500); await flush();
    eq(c.selected.getAttribute('role'), 'alert', 'a failed selection is an alert again');
    tap(c, t.buttons[2], {});
    eq([c.selected.children[0] === c.prompt, c.selected.getAttribute('role')], [true, null], 'the prompt put back is not an alert');
    show(c, { from: 1000, to: 1050, ts: 1010 });
    eq([c.selected.children[0] === c.prompt, c.selected.innerHTML], [true, ''], 'a rebind clears the previous instance\'s selection');
  }

  // ---- the run slot swapped for markup with no timeline unbinds, playback included
  {
    const c = build(); show(c); fire(c.play, 'click', {}); c.tick();
    const before = urls(c).length;
    const gone = new El('div'); c.run.children = []; c.run.appendChild(gone);
    fire(c.body, 'htmx:afterSettle', { target: gone });
    eq([c.play.attrs['aria-pressed'], c.intervals.size, c.play.disabled, c.speed.disabled], ['false', 0, true, true],
       'a run with no timeline stops playback and disables the controls');
    eq(c.fetches[0].signal.aborted, true, 'and aborts the pending panel request');
    c.tick(5000);
    fire(c.body, 'htmx:afterSettle', { target: gone });
    eq(urls(c).length, before, 'no panel request is made for the removed window');
    show(c, { from: 1000, to: 1050, ts: 1010 });
    eq([urls(c).slice(before), c.play.disabled], [[MOM + '1010'], false], 'a later instance binds normally');
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
    fire(t.body, 'pointerdown', { clientX: 100, pointerId: 7, button: 2 });
    fire(t.body, 'pointerdown', { clientX: 780, pointerId: 7, button: 2 });
    eq(t.root.classes.has('scrubbing'), false, 'a press with another button is not a scrub');
    const caps = t.body.captured.length, before = urls(c).length;
    fire(t.body, 'pointerdown', { clientX: 780, pointerId: 7, button: 1 });
    eq([t.root.classes.has('scrubbing'), t.body.captured.length, urls(c).length], [false, caps, before],
       'a middle-button press is not a scrub, captures nothing and requests nothing');
  }

  // ---- a scrub never sticks and never races Play
  {
    const c = build(); const t = show(c);
    t.body.setPointerCapture = () => { throw new Error('NotFoundError'); };
    fire(t.body, 'pointerdown', { clientX: 780, pointerId: 7 });
    eq(t.root.classes.has('scrubbing'), false, 'a refused pointer capture starts no scrub');
    fire(t.body, 'pointermove', { clientX: 1280 });
    eq([t.chip.textContent, urls(c).length], ['1970-01-01T00:02:30Z', 1], 'and the line does not follow the pointer');
    fire(t.body, 'pointerup', {});
    eq(urls(c).length, 1, 'nor does a release commit');
  }
  {
    const c = build(); const t = show(c);
    fire(t.body, 'pointerdown', { clientX: 780, pointerId: 1 });
    fire(t.body, 'pointermove', { clientX: 1280, buttons: 1 });
    eq(t.chip.textContent, '1970-01-01T00:03:20Z', 'a drag with a button down follows the pointer');
    fire(t.body, 'pointercancel', {});
    eq([t.root.classes.has('scrubbing'), t.chip.textContent, c.clock.textContent, t.root.querySelector('.tl-scrub').value, urls(c).length],
       [false, '1970-01-01T00:02:30Z', '1970-01-01T00:02:30Z', '150', 1], 'pointercancel puts the line back at the committed time and requests nothing');
    fire(t.body, 'pointermove', { clientX: 300, buttons: 1 });
    eq(t.chip.textContent, '1970-01-01T00:02:30Z', 'and the drag is over');
  }
  {
    const c = build(); const t = show(c);
    fire(t.body, 'pointerdown', { clientX: 780, pointerId: 1 });
    fire(t.body, 'pointermove', { clientX: 100, buttons: 1 });
    eq(t.chip.textContent, '1970-01-01T00:01:40Z', 'a drag into the label gutter holds the line at the window start');
    fire(t.body, 'pointermove', { clientX: 1280, buttons: 0 });
    eq([t.root.classes.has('scrubbing'), urls(c)[1]], [false, MOM + '100'], 'a move with every button up is the release: the scrub ends and commits where the line was');
  }
  {
    const c = build(); const t = show(c);
    fire(t.body, 'pointerdown', { clientX: 780, pointerId: 1 });
    fire(c.play, 'click', {});
    eq([c.play.attrs['aria-pressed'], c.intervals.size], ['false', 0], 'Play during a scrub starts nothing');
    fire(t.body, 'pointerup', {});
    fire(c.play, 'click', {});
    eq(c.play.attrs['aria-pressed'], 'true', 'and works once the scrub is over');
  }
  {
    const c = build(); const t = show(c);
    fire(t.body, 'pointerdown', { clientX: 780, pointerId: 1 });
    fire(t.body, 'pointermove', { clientX: 1280, buttons: 1 });
    fire(t.body, 'lostpointercapture', {});          // the capture went and no pointerup came
    eq([t.root.classes.has('scrubbing'), urls(c)[1]], [false, MOM + '200'], 'losing the pointer capture with no pointerup ends the scrub and commits where the line was');
    fire(t.body, 'pointermove', { clientX: 300, buttons: 1 });
    eq(t.chip.textContent, '1970-01-01T00:03:20Z', 'and the drag is over');
    const n = urls(c).length;
    fire(t.body, 'pointerdown', { clientX: 780, pointerId: 1 });
    fire(t.body, 'pointerup', {});
    fire(t.body, 'lostpointercapture', {});          // the browser's own release after a normal pointerup
    eq(urls(c).length, n + 1, 'after a normal release the capture going adds no second request');
  }

  // ---- failures
  {
    const c = build(); show(c);
    status(c.fetches[0], 403); await flush();
    eq([c.moment.textContent, c.moment.innerHTML, c.moment.classes.has('busy')], ['Could not load this panel (HTTP 403).', '', false], 'non-2xx: status in text, never markup');
    eq(c.moment.getAttribute('role'), 'alert', 'the failure copy is announced');
    key(c, 'ArrowRight');
    c.fetches[1].reject(new Error('net')); await flush();
    eq(c.moment.textContent, 'Could not reach the server.', 'rejected fetch');
    key(c, 'ArrowRight'); key(c, 'ArrowRight');
    c.fetches[2].reject(new Error('aborted')); await flush();
    eq([c.moment.textContent, c.moment.classes.has('busy')], ['Could not reach the server.', true], 'an aborted request writes nothing and the slot stays busy');
    ok200(c.fetches[3], '<b>ok</b>'); await flush();
    eq([c.moment.innerHTML, c.moment.classes.has('busy')], ['<b>ok</b>', false], 'the replacement lands and clears busy');
    eq(c.moment.getAttribute('role'), null, 'a landed panel is not an alert');
    key(c, 'ArrowRight'); fire(c.play, 'click', {});
    eq(c.play.attrs['aria-pressed'], 'true', '401 case: playback is running when the answer arrives');
    status(c.fetches[4], 401); await flush();
    eq([c.assigned, c.play.attrs['aria-pressed'], c.intervals.size], [['/login'], 'false', 0],
       '401 goes to the sign-in page and stops playback (no timer left to 401 again)');
    eq(c.fetches.length, 5, '401 stops without a flush request');
    const inner = new El('div'); c.run.children[0].appendChild(inner);
    fire(inner, 'htmx:responseError', { detail: { xhr: { status: 500 } } });
    eq([c.run.textContent, c.run.children.length], ['Could not load the record (HTTP 500).', 0], 'a failed poll inside the run slot is reported there');
    // The same message twice proves nothing: leave a sentinel, bind a fresh instance with playback
    // running, then send errors from outside the run slot.
    c.run.textContent = 'sentinel';
    show(c); fire(c.play, 'click', {});
    const other = new El('div'); c.body.appendChild(other);
    for (const ev of ['htmx:responseError', 'htmx:sendError', 'htmx:timeout'])
      fire(other, ev, { detail: { xhr: { status: 500 } } });
    eq([c.run.textContent, c.run.children.length, c.play.attrs['aria-pressed'], c.intervals.size], ['sentinel', 1, 'true', 1],
       'an error outside the run slot changes nothing and leaves the bound instance playing');
  }

  // ---- the run slot: refused, never reached, timed out
  for (const [ev, code, want] of [['htmx:responseError', 502, 'Could not load the record (HTTP 502).'],
                                  ['htmx:sendError', 0, 'Could not reach the server.'],
                                  ['htmx:timeout', 0, 'Could not reach the server.']]) {
    const c = build(); show(c); fire(c.play, 'click', {});
    fire(c.run.children[0], ev, { detail: { xhr: { status: code } } });
    eq([ev, c.run.textContent, c.play.attrs['aria-pressed'], c.intervals.size, c.play.disabled], [ev, want, 'false', 0, true],
       ev + ' in the run slot is said, and playback and the controls stop');
  }

  // ---- signed out: one path, once
  {
    const c = build(); const t = show(c);
    tap(c, t.buttons[0], {});                     // moment and selected requests in flight
    ok(c.fetches.every((f) => f.opts.headers['HX-Request'] === 'true' && f.opts.headers.Accept === 'text/html'),
       'every panel request says HX-Request');
    eq(c.fetches.length, 3, 'a block click with an item makes both requests');
    status(c.fetches[1], 401); status(c.fetches[2], 401); await flush();
    eq(c.assigned, ['/login'], 'two 401s send the browser to sign in once');
    eq([c.moment.classes.has('busy'), c.selected.classes.has('busy'), c.moment.textContent, c.selected.textContent], [false, false, '', ''],
       'and write no error copy');
    const n = c.fetches.length;
    key(c, 'ArrowRight'); tap(c, t.buttons[1], {});
    eq(c.fetches.length, n, 'a signed-out page makes no further requests');
  }
  {
    const c = build(); const t = show(c);
    tap(c, t.buttons[0], {});
    fire(c.play, 'click', {});
    status(c.fetches[1], 401); await flush();
    ok200(c.fetches[2], '<i>late</i>'); await flush();
    eq([c.selected.innerHTML, c.moment.innerHTML, c.assigned, c.play.attrs['aria-pressed'], c.intervals.size],
       ['', '', ['/login'], 'false', 0], 'a late 200 on the other panel after a 401 writes nothing, and nothing keeps running');
  }
  {
    const c = build(); const t = show(c);
    tap(c, t.buttons[0], {});
    status(c.fetches[2], 401); await flush();       // the selected panel is told first
    ok200(c.fetches[1], '<i>late</i>'); await flush();
    eq([c.moment.innerHTML, c.selected.innerHTML, c.assigned], ['', '', ['/login']], 'and the same the other way round');
  }
  {
    const c = build(); show(c);
    c.fetches[0].resolve({ status: 200, ok: true, redirected: true, text: () => Promise.resolve('<h1>landing page</h1>') }); await flush();
    eq([c.moment.innerHTML, c.assigned], ['', ['/login']], 'a redirected answer is the sign-in page, not a panel');
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
    key(c, 'ArrowRight');
    eq(c.copy.textContent, 'Copy link to this moment', 'the label returns when the moment moves on');
    const d = build({ clipFail: true }); show(d);
    fire(d.copy, 'click', {}); await flush();
    eq(d.copy.textContent, 'Could not copy', 'copy failure is said');
    const e = build({ noClip: true }); show(e);
    fire(e.copy, 'click', {}); await flush();
    eq([e.copy.textContent, e.clip], ['Could not copy', []], 'a browser with no clipboard is told so, not thrown at');
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
    await settle(c);
    fire(c.play, 'click', {});
    eq([c.play.attrs['aria-pressed'], c.play.textContent, c.intervals.size, [...c.intervals.values()][0].ms], ['true', 'Pause', 1, 250], 'Play starts one timer');
    c.tick(); c.tick(); c.tick();
    eq([urls(c).length, t.chip.textContent], [1, '1970-01-01T00:02:30Z'], 'three ticks: the line moves, nothing is requested');
    c.tick();
    eq(urls(c).slice(1), [MOM + '151'], 'the fourth tick (one second) commits once');
    const second = async () => { for (let i = 0; i < 4; i++) c.tick(); await settle(c); };
    await settle(c); await second(); await second();
    eq(urls(c).slice(2), [MOM + '152', MOM + '153'], 'two more seconds: two more requests, one a second');
    fire(c.speed, 'click', {});
    eq(c.speed.textContent, 'Speed 10x', 'speed cycles 1x to 10x');
    await second();
    eq(urls(c).length, 5, 'at 10x the next second is still one request');
    eq(urls(c)[4], MOM + '163', 'and carries the latest t (153 + 4 ticks of 2.5 s)');
    fire(c.speed, 'click', {}); eq(c.speed.textContent, 'Speed 60x', '10x to 60x');
    fire(c.speed, 'click', {}); eq(c.speed.textContent, 'Speed 1x', '60x back to 1x');
    eq(c.speed.getAttribute('aria-label'), null, 'and the speed button still has no aria-label');
  }

  // ---- playback never answers an unanswered request with another one
  {
    const c = build(); show(c);                    // the bind request never settles
    fire(c.play, 'click', {});
    for (let i = 0; i < 8; i++) c.tick();
    eq([c.fetches.length, c.fetches[0].signal.aborted], [1, false], 'two seconds of playback over a slow answer: no second request, nothing aborted');
    eq(c.intervals.size, 1, 'and the line keeps playing');
    await settle(c);                               // positive control: the answer lands
    c.tick();
    eq(urls(c).slice(1), [MOM + '152'], 'the next tick after the answer commits the latest time');
  }

  // ---- ... unless that request never settles: it is given up on after ten seconds
  {
    const c = build(); show(c);                    // the bind request never settles
    fire(c.play, 'click', {});
    for (let i = 0; i < 39; i++) c.tick();         // 9.75 s of playback
    eq([c.fetches.length, c.fetches[0].signal.aborted], [1, false], 'inside the bound the stalled request is still waited for');
    c.tick();                                      // 10 s
    eq([urls(c).slice(1), c.fetches[0].signal.aborted, c.intervals.size], [[MOM + '160'], true, 1],
       'past the bound it is abandoned and the newest time asked for, and playback goes on');
    c.fetches[0].reject(new Error('aborted')); await flush();
    eq([c.moment.textContent, c.moment.getAttribute('role'), c.moment.classes.has('busy')], ['', null, true],
       'the abandoned request says nothing when it dies, and the new one still holds the slot');
    ok200(c.fetches[1], '<b>fresh</b>'); await flush();
    eq([c.moment.innerHTML, c.moment.classes.has('busy')], ['<b>fresh</b>', false], 'the new request lands');
  }
  {
    const d = build(); show(d);
    d.clockNow += 1000; keyRaw(d, 'ArrowRight');   // immediate, and never answered
    d.clockNow += 100; keyRaw(d, 'ArrowRight');    // owed
    for (let i = 0; i < 39; i++) d.tick();
    eq([d.fetches.length, d.fetches[1].signal.aborted, d.intervals.size], [2, false, 1], 'an owed commit still waits for an answer inside the bound');
    d.tick();
    eq([urls(d).slice(2), d.fetches[1].signal.aborted, d.intervals.size], [[MOM + '152'], true, 0],
       'past it the owed commit is made over the stalled request, and the timer goes');
  }

  // ---- playback with an item selected: both panels are requested together at each second
  {
    const c = build(); const t = show(c);
    tap(c, t.buttons[0], {});           // p1 at 130
    await settle(c);
    fire(c.play, 'click', {});
    for (let i = 0; i < 4; i++) c.tick();
    eq(urls(c).slice(1), [MOM + '130', SEL + 'p1&at=130', MOM + '131', SEL + 'p1&at=131'],
       'one second of playback refreshes the moment and the selected panel at the same t');
    await settle(c);
    for (let i = 0; i < 4; i++) c.tick();
    eq(urls(c).slice(5), [MOM + '132', SEL + 'p1&at=132'], 'and the next second does the same');
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
    await settle(c);
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
      'block click': (c) => tap(c, c.t.buttons[0], {}),
      'nav link': (c) => { const a = new El('a'); a.attrs['data-ts'] = '120'; c.moment.appendChild(a); tap(c, a, {}); },
      'pointer scrub': (c) => fire(c.t.body, 'pointerdown', { clientX: 780, pointerId: 1 }),
      'range input': (c) => { const r = c.t.root.querySelector('.tl-scrub'); r.value = '120'; fire(r, 'input', {}); },
      'linked item': (c) => { const a = new El('a'); a.attrs['data-ref'] = 'p2'; a.attrs['data-ts'] = '150'; c.selected.appendChild(a); fire(a, 'click', {}); },
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

  // ---- a held key: every repeat moves the line, the panels follow at most once a second
  {
    const c = build(); const t = show(c);
    tap(c, t.buttons[0], {});                        // p1 at 130: both panels in use
    await settle(c);
    c.clockNow += 1000;
    const base = c.fetches.length;
    for (let i = 1; i <= 30; i++) {                  // 30 repeats in 0.96 s; the interval fires every 250 ms
      c.clockNow += 32;
      ok(keyRaw(c, 'ArrowRight').defaultPrevented, 'repeat ' + i + ' is ours');
      if (i % 8 === 0) c.tick(0);
    }
    eq(t.chip.textContent, '1970-01-01T00:02:40Z', 'the line followed all 30 repeats');
    eq(urls(c).slice(base), [MOM + '131', SEL + 'p1&at=131'], 'the first repeat requested at once, the other 29 did not');
    eq(c.intervals.size, 1, 'a commit is owed to the one timer');
    await settle(c);
    c.tick(250);
    eq(urls(c).slice(base + 2), [MOM + '160', SEL + 'p1&at=160'], 'the trailing commit carries the newest time, for both panels');
    eq(c.intervals.size, 0, 'and the timer is gone once nothing is owed');
    c.tick(5000);
    eq(urls(c).length, base + 4, 'exactly two requests per panel for the whole burst');
  }
  {
    const c = build(); show(c);
    key(c, 'End');                                   // 200: the window edge
    const base = urls(c).length;
    for (let i = 0; i < 30; i++) ok(keyRaw(c, 'End').defaultPrevented, 'a held End is still our key');
    for (let i = 0; i < 30; i++) keyRaw(c, 'ArrowRight');
    eq([urls(c).length, c.intervals.size], [base, 0], 'a held key at the window edge requests nothing and leaves no timer');
  }
  {
    const c = build(); show(c);
    keyRaw(c, 'ArrowRight');                         // inside the second: out ...
    eq(c.intervals.size, 1, 'the key owes a commit');
    keyRaw(c, 'ArrowLeft');                          // ... and back to the committed time
    c.tick();
    eq([c.intervals.size, urls(c).length], [0, 1], 'a key back at the committed time owes nothing: the timer goes, no request');
    c.tick(5000);
    eq(urls(c).length, 1, 'and none follows');
  }
  {
    const c = build(); show(c, { ts: 100 });          // the line sits exactly at the window start
    fire(c.play, 'click', {});
    eq(c.play.attrs['aria-pressed'], 'true', 'playing from the window start');
    const e = keyRaw(c, 'Home');                      // resolves to the time already shown
    eq([e.defaultPrevented, c.play.attrs['aria-pressed'], c.intervals.size, urls(c).length], [true, 'false', 0, 1],
       'a key that resolves to the time already shown still stops playback, and requests nothing');
  }
  {
    const c = build(); show(c); await settle(c);
    fire(c.play, 'click', {}); c.tick();            // playing, 250 ms after the last commit
    keyRaw(c, 'ArrowRight');
    eq([c.play.attrs['aria-pressed'], urls(c).length, c.intervals.size], ['false', 1, 1],
       'a key inside the second stops playback and moves the line; its commit is owed to the timer');
    c.tick(); c.tick();
    eq(urls(c).length, 1, 'not before the second is up');
    c.tick();
    eq([urls(c).slice(1), c.intervals.size], [[MOM + '151'], 0], 'then it is made once, and the timer goes');
    const d = build(); show(d);                      // a request in flight: the owed commit waits for its answer
    d.clockNow += 1000; keyRaw(d, 'ArrowRight');     // immediate, and unanswered
    d.clockNow += 100; keyRaw(d, 'ArrowRight');      // owed
    for (let i = 0; i < 8; i++) d.tick();
    eq([d.fetches.length, d.fetches[1].signal.aborted], [2, false], 'an owed commit never aborts an unanswered request');
    await settle(d); d.tick();
    eq(urls(d).slice(2), [MOM + '152'], 'it is made on the first tick after the answer');
  }
  {
    const c = build(); show(c); fire(c.speed, 'click', {}); fire(c.play, 'click', {}); c.tick();   // 10x: 152.5
    const a = new El('a'); a.attrs['data-ref'] = 'p2'; a.attrs['data-ts'] = '152'; c.selected.appendChild(a);
    const e = fire(a, 'click', {});
    eq([e.defaultPrevented, c.play.attrs['aria-pressed'], c.intervals.size], [true, 'false', 0], 'a linked-item click stops playback');
    eq(urls(c).slice(1), [MOM + '152', SEL + 'p2&at=152', SEL + 'p2&at=152'],
       'the stop time is flushed once with the new selection, then the explicit request carries the same URL');
    eq(c.fetches.slice(2).map((f) => f.signal.aborted), [true, false], 'and the explicit selected request supersedes the flushed one');
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
    for (const f of c.doc.listeners.visibilitychange) f({});
    eq([c.play.attrs['aria-pressed'], c.intervals.size], ['true', 1], 'a visibility change to visible leaves playback alone');
    c.doc.hidden = true;
    for (const f of c.doc.listeners.visibilitychange) f({});
    eq([c.play.attrs['aria-pressed'], c.intervals.size, urls(c)[1]], ['false', 0, MOM + '152'], 'a hidden tab stops playback and keeps the panels honest');
  }
  {
    const c = build(); show(c);
    fire(c.play, 'click', {}); fire(c.play, 'click', {});
    eq(urls(c).length, 1, 'Pause at the time already shown requests nothing');
    key(c, 'ArrowRight');                            // the bind request is superseded
    status(c.fetches[0], 500); await flush();
    eq([c.moment.textContent, c.moment.classes.has('busy'), c.moment.getAttribute('role')], ['', true, null],
       'a superseded failure says nothing');
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
