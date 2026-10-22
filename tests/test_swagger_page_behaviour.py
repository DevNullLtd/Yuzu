#!/usr/bin/env python3
"""Behavioural check of the /swagger page's renderer.

test_swagger_page.cpp pins the page text (no innerHTML and so on); this runs the script. The
two script pieces (kSwaggerJs1 and kSwaggerJs2) are cut out of server/core/src/swagger_page_ui.cpp
and executed under node against a minimal fake DOM and a queued fetch, then asserts what an
operator would see: one panel per group and one row per operation, the typed / untyped /
unavailable pills, a guide that opens on demand, oneOf alternatives rendered as tables, hostile
spec text shown as text and never as an element, a malformed URL fragment that must not take the
page down, deep links, the v2 route's curl path, and the failure view (status-aware message,
correlation id, Retry that fetches again).

Skips cleanly (exit 77) when `node` is not on PATH. Stdlib only.
"""
import json
import pathlib
import re
import shutil
import subprocess
import sys

SRC = pathlib.Path(__file__).resolve().parents[1] / "server/core/src/swagger_page_ui.cpp"

DRIVER = r"""
const js = require('fs').readFileSync(0, 'utf8');
class E {
  constructor(t) { this.tag = t; this.children = []; this.attrs = {}; this._t = ''; this.parentNode = null;
    this.hidden = false; this.className = ''; this.L = {}; this.value = ''; this.selectedIndex = 0; this.id = ''; }
  get textContent() { return this._t + this.children.map(c => c.textContent).join(''); }
  set textContent(v) { this._t = String(v); this.children = []; }
  set innerHTML(v) { throw new Error('innerHTML was assigned'); }
  get innerHTML() { throw new Error('innerHTML was read'); }
  set outerHTML(v) { throw new Error('outerHTML was assigned'); }
  insertAdjacentHTML() { throw new Error('insertAdjacentHTML was called'); }
  get lastChild() { return this.children[this.children.length - 1] || null; }
  appendChild(c) { c.parentNode = this; this.children.push(c); return c; }
  insertBefore(c, ref) { c.parentNode = this; const i = this.children.indexOf(ref); this.children.splice(i < 0 ? this.children.length : i, 0, c); return c; }
  setAttribute(k, v) { this.attrs[k] = String(v); }
  getAttribute(k) { return k in this.attrs ? this.attrs[k] : null; }
  addEventListener(t, f) { (this.L[t] = this.L[t] || []).push(f); }
  fire(t) { (this.L[t] || []).forEach(f => f({ target: this })); }
  click() { this.fire('click'); }
  scrollIntoView() { scrolled.push(this); }
  all(pred, out = []) { this.children.forEach(c => { if (pred(c)) out.push(c); c.all(pred, out); }); return out; }
  byClass(cls) { return this.all(c => (' ' + c.className + ' ').includes(' ' + cls + ' ')); }
  byTag(tag) { return this.all(c => c.tag === tag); }
}
const scrolled = [];
const root = new E('div'); root.id = 'sw-root';
globalThis.window = globalThis;
globalThis.document = { getElementById: i => (i === 'sw-root' ? root : null), createElement: t => new E(t),
  createTextNode: t => { const e = new E('#text'); e._t = String(t); return e; } };
globalThis.location = { origin: 'https://yuzu.test', hash: '' };
globalThis.history = { replaceState: (a, b, h) => { globalThis.location.hash = h; } };
globalThis.setTimeout = () => 1; globalThis.clearTimeout = () => {};
let queue = [], fetches = [];
globalThis.fetch = (u, o) => { fetches.push(u); const r = queue.shift();
  if (r.fail) return Promise.reject(new Error('net'));
  return Promise.resolve({ ok: r.status === 200, status: r.status, json: () => (r.body === undefined ? Promise.reject(new Error('no body')) : Promise.resolve(r.body)) }); };

const R = (extra) => ({ '200': Object.assign({ description: 'ok' }, extra || {}) });
const typed = { content: { 'application/json': { schema: { $ref: '#/components/schemas/Thing' } } } };
const spec = {
  openapi: '3.0.3', info: { title: 't', version: '1' }, servers: [{ url: '/api/v1' }],
  tags: [
    { name: 'Alpha', description: 'Alpha summary', 'x-yuzu-guide': { overview: ['Alpha overview.'], how_it_works: [{ title: 'One', text: 'First.' }, { title: 'Two', text: 'Second.' }, { title: 'Three', text: 'Third.' }],
        tables: [{ title: 'T', columns: ['a', 'b'], rows: [['1', '2']] }], access: { permissions: ['X:Read'], audit: ['x.read'], notes: ['n'] },
        good_to_know: [{ label: 'Paging', text: 'none' }], docs: ['docs/x.md'] } },
    { name: 'Beta', description: 'Beta summary' }
  ],
  paths: {
    '/a': { get: { operationId: 'getA', summary: '<img src=x onerror=alert(1)> hostile', description: 'd <b>x</b>', tags: ['Alpha'], responses: R(typed) } },
    '/a/{id}': { get: { operationId: 'getAById', summary: 'one', tags: ['Alpha'], parameters: [{ name: 'id', in: 'path', required: true, schema: { type: 'string' } }],
        responses: R({ content: { 'application/json': { schema: { oneOf: [{ $ref: '#/components/schemas/Thing' }, { type: 'object', properties: { z: { type: 'string' } } }] } } } }) } },
    '/b': { get: { operationId: 'getB', summary: 'untyped', tags: ['Beta'], responses: R() } },
    '/gone': { delete: { operationId: 'deleteGone', summary: 'unserved', tags: ['Beta'], 'x-yuzu-unavailable': 'Not served by this build.', responses: R() } },
    '/v2/agent/plugin-policy': { get: { operationId: 'getV2', summary: 'v2', tags: ['Beta'], responses: R() } },
    '/c': { post: { operationId: 'postC', summary: 'shared', tags: ['Beta'], responses: R(),
        requestBody: { content: { 'application/json': { schema: { type: 'object', properties: { source: { type: 'string', description: 'shared field' } },
          oneOf: [{ type: 'object', properties: { id: { type: 'string' } } }, { type: 'object', properties: { group: { type: 'string' } } }] } } } } } }
  },
  components: { schemas: { Thing: { type: 'object', required: ['id'], properties: { id: { type: 'string' }, n: { type: 'integer', nullable: true } } } } }
};
const settle = () => new Promise(r => setImmediate(r));
const out = {};
(async () => {
  queue.push({ status: 200, body: spec });
  location.hash = '#%E0%A4%A';           // a malformed fragment must not take the page down
  (0, eval)(js);
  await settle();
  const panels = root.byTag('section');
  out.panels = panels.length;
  out.rows = root.byClass('sw-op').length;
  out.loaded_url = fetches[0];
  out.pills = root.byClass('pill').map(p => p.textContent);
  out.malformed_hash_survived = panels.length === 2;
  out.hostile_img_elements = root.all(c => c.tag === 'img').length;
  const summaries = root.byClass('sw-sum').map(s => s.textContent);
  out.hostile_text_kept = summaries.some(s => s.includes('<img src=x onerror=alert(1)>'));
  // guide: closed until asked, then built
  const alphaGuideBtn = panels[0].byClass('sw-gbtn')[0];
  out.guide_before = panels[0].byClass('sw-guide').length;
  alphaGuideBtn.click();
  out.guide_after = panels[0].byClass('sw-guide').length;
  out.guide_text = panels[0].textContent.includes('Alpha overview.') && panels[0].textContent.includes('X:Read');
  out.beta_has_guide_button = panels[1].byClass('sw-gbtn').length;
  // oneOf operation shows both options as tables
  const rows = root.byClass('sw-op');
  const oneOfHead = rows[1].byClass('sw-op-h')[0]; oneOfHead.click();
  out.oneof_options = rows[1].byClass('sw-alt').length;
  out.oneof_tables = rows[1].byTag('table').length;
  // unavailable note and v2 curl base
  const goneRow = rows.filter(r => r.textContent.includes('unserved'))[0]; goneRow.byClass('sw-op-h')[0].click();
  out.unavailable_note = goneRow.textContent.includes('Not served by this build.');
  const v2Row = rows.filter(r => r.textContent.includes('/v2/agent/plugin-policy'))[0]; v2Row.byClass('sw-op-h')[0].click();
  out.v2_curl = v2Row.byTag('pre')[0].textContent.includes('https://yuzu.test/api/v2/agent/plugin-policy');
  const sharedRow = rows.filter(r => r.textContent.includes('shared'))[0]; sharedRow.byClass('sw-op-h')[0].click();
  out.shared_props_shown = sharedRow.textContent.includes('shared field');
  out.shared_alts = sharedRow.byClass('sw-alt').length;
  out.deep_link_hash = location.hash;
  // failure view: 403 with a correlation id, then Retry fetches again and renders
  root.textContent = '';
  queue.push({ status: 403, body: { error: { correlation_id: 'req-1' } } });
  queue.push({ status: 200, body: spec });
  const before = fetches.length;
  location.hash = '';
  (0, eval)(js);   // a second instance on the same root models a reload
  await settle();
  out.error_text = root.textContent;
  const retry = root.byTag('button')[0];
  retry.click(); await settle();
  out.retry_fetched = fetches.length - before;
  out.after_retry_panels = root.byTag('section').length;
  // a 500 with no body still produces a message and a Retry button
  root.textContent = '';
  queue.push({ status: 500 });
  (0, eval)(js); await settle();
  out.err500 = root.textContent;
  out.err500_retry = root.byTag('button').length;
  console.log(JSON.stringify(out));
})().catch(e => { console.log(JSON.stringify({ crash: String(e && e.stack || e) })); process.exit(1); });
"""


def extract_js():
    text = SRC.read_text(encoding="utf-8")
    parts = []
    for name in ("kSwaggerJs1", "kSwaggerJs2"):
        m = re.search(r'extern const char\* const %s = R"SWG\((.*?)\)SWG";' % name, text, re.S)
        if not m:
            raise SystemExit("cannot find %s in %s" % (name, SRC))
        parts.append(m.group(1))
    return "".join(parts)


def main():
    node = shutil.which("node")
    if not node:
        print("node not on PATH: skipping")
        return 77
    js = extract_js()
    # The driver reads the script from stdin and evaluates it; a second argument-free node run.
    proc = subprocess.run([node, "-e", DRIVER], input=js, capture_output=True, text=True, timeout=60)
    if proc.returncode != 0:
        print(proc.stdout, proc.stderr)
        return 1
    out = json.loads(proc.stdout.strip().splitlines()[-1])
    errors = []

    def check(cond, msg):
        if not cond:
            errors.append(msg)

    check(out["loaded_url"] == "/api/v1/openapi.json?guides=true", "loads the full document with guides: %r" % out["loaded_url"])
    check(out["panels"] == 2, "one panel per group, got %r" % out["panels"])
    check(out["rows"] == 6, "one row per operation, got %r" % out["rows"])
    check(out["malformed_hash_survived"], "a malformed URL fragment took the page down")
    for pill in ("typed", "untyped", "unavailable"):
        check(pill in out["pills"], "missing %s pill" % pill)
    check(out["hostile_img_elements"] == 0, "hostile spec text created an element")
    check(out["hostile_text_kept"], "hostile spec text was not shown as text")
    check(out["guide_before"] == 0 and out["guide_after"] == 1, "guide must be built on demand")
    check(out["guide_text"], "guide text missing after opening")
    check(out["beta_has_guide_button"] == 0, "a group without a guide must not get a Guide button")
    check(out["oneof_options"] == 2 and out["oneof_tables"] >= 2, "oneOf must render both alternatives as tables")
    check(out["shared_props_shown"] and out["shared_alts"] == 2, "properties declared beside oneOf must be shown with both options")
    check(out["unavailable_note"], "unavailable note missing from the detail view")
    check(out["v2_curl"], "the v2 route's curl line must use /api/v2")
    check(out["deep_link_hash"].startswith("#"), "opening an operation should set a fragment")
    check("HTTP 403" in out["error_text"] and "Infrastructure:Read" in out["error_text"] and "req-1" in out["error_text"],
          "403 view must name the status, the permission and the correlation id: %r" % out["error_text"])
    check(out["retry_fetched"] == 2 and out["after_retry_panels"] == 2, "Retry must fetch again and render (fetches %r)" % out["retry_fetched"])
    check("HTTP 500" in out["err500"] and out["err500_retry"] == 1, "a bodyless 500 must show a message and a Retry button")
    if errors:
        print("FAIL")
        for e in errors:
            print("  -", e)
        return 1
    print("swagger page behaviour: OK")
    return 0


if __name__ == "__main__":
    sys.exit(main())
