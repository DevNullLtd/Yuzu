#!/usr/bin/env python3
"""Behavioural check of the /swagger page's renderer.

test_swagger_page.cpp pins the page text (no innerHTML and so on); this runs the script. The
two script pieces (kSwaggerJs1 and kSwaggerJs2) are cut out of server/core/src/swagger_page_ui.cpp
and executed under node against a minimal fake DOM and a queued fetch, then asserts what an
operator would see: one panel per group and one row per operation, the typed / untyped /
unavailable pills, a guide that opens on demand, oneOf alternatives rendered as tables, hostile
spec text shown as text and never as an element, a malformed URL fragment that must not take the
page down, deep links, the v2 route's curl path, and the failure view (status-aware message,
correlation id, Retry that fetches again). It also feeds hostile specs: schemas that reach themselves,
a schema that throws, very wide schemas (the row budget), malformed entries, tags named after
Object.prototype keys, and every failure shape (non-JSON 200, bodyless 502, network down, a null
document), which must show a fixed message and never the raw JavaScript error.

Skips cleanly (exit 77) when `node` is not on PATH, unless YUZU_REQUIRE_NODE=1 is set, in which
case a missing node fails (exit 1). docs-lint.yml sets it on a hosted image that ships node, so
the only check of the page's script cannot silently skip there. Stdlib only.
"""
import json
import os
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
  if (r.fail) return Promise.reject(new Error('NETRAW'));
  return Promise.resolve({ ok: r.status === 200, status: r.status, headers: { get: k => ((r.headers || {})[k] !== undefined ? r.headers[k] : null) },
    json: () => (r.body === undefined ? Promise.reject(new SyntaxError("Unexpected token '<' RAWBODY")) : Promise.resolve(r.body)) }); };
const consoleErrors = [];
console.error = (...a) => { consoleErrors.push(a.map(String).join(' ')); };

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
  const oneOfHead = rows[1].byClass('sw-op-h')[0];
  location.hash = '';                    // the fake replaceState writes here: start from empty
  oneOfHead.click();
  out.deep_link_hash = location.hash;    // what the page itself wrote for GET /a/{id}
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

  // ---- a valid deep link on load opens the right operation and the right group ----
  const reload = async (body, hash) => { root.textContent = ''; queue.push(body); location.hash = hash || ''; (0, eval)(js); await settle(); };
  const pathOf = r => r.byClass('sw-path')[0].textContent;
  scrolled.length = 0;
  await reload({ status: 200, body: spec }, '#GET%20%2Fa%2F%7Bid%7D');
  const dlRows = root.byClass('sw-op');
  out.dl_expanded = dlRows.filter(r => r.byClass('sw-op-h')[0].getAttribute('aria-expanded') === 'true').map(pathOf);
  out.dl_scrolled_op = scrolled.some(e => e.byClass && e.byClass('sw-path').length && pathOf(e) === '/a/{id}');
  scrolled.length = 0;
  await reload({ status: 200, body: spec }, '#g-Alpha');
  const dlPanels = root.byTag('section');
  out.dg_alpha_guide_open = dlPanels[0].byClass('sw-gbtn')[0].getAttribute('aria-expanded') === 'true' && dlPanels[0].byClass('sw-guide').length === 1;
  out.dg_scrolled = scrolled.length === 1 && scrolled[0] === dlPanels[0];
  out.dg_ops_closed = root.byClass('sw-op').every(r => r.byClass('sw-op-h')[0].getAttribute('aria-expanded') === 'false');
  await reload({ status: 200, body: spec }, '#GET%20%2Fnope');
  out.dl_unknown_opens_nothing = root.byClass('sw-op').every(r => r.byClass('sw-op-h')[0].getAttribute('aria-expanded') === 'false') && root.byTag('section').length === 2;

  // ---- hostile schemas: self-reference, a schema that throws, breadth ----
  const guide = { overview: ['g'] };
  const refResp = n => R({ content: { 'application/json': { schema: { $ref: '#/components/schemas/' + n } } } });
  const wideProps = {}; for (let i = 0; i < 3000; i++) wideProps['f' + i] = { type: 'string' };
  const chain = {}; for (let i = 0; i < 8; i++) { const ps = {}; for (let j = 0; j < 6; j++) ps['p' + j] = i < 7 ? { $ref: '#/components/schemas/L' + (i + 1) } : { type: 'string' }; chain['L' + i] = { type: 'object', properties: ps }; }
  const spec2 = {
    openapi: '3.0.3', info: { title: 't', version: '1' },
    tags: [{ name: 'Rec', description: 'rec', 'x-yuzu-guide': guide }, { name: 'Big', description: 'big', 'x-yuzu-guide': guide }],
    paths: {
      '/r1': { get: { summary: 'self', tags: ['Rec'], responses: refResp('C') } },
      '/r2': { get: { summary: 'mutual', tags: ['Rec'], responses: refResp('A') } },
      '/r3': { get: { summary: 'throws', tags: ['Rec'], responses: refResp('D') } },
      '/w1': { get: { summary: 'wide', tags: ['Big'], responses: refResp('Wide') } },
      '/w2': { get: { summary: 'deep', tags: ['Big'], responses: refResp('L0') } },
      '/n': { get: { summary: 'nested', tags: ['Big'], responses: R({ content: { 'application/json': { schema: { type: 'object', properties: { outer: { type: 'object', properties: { inner: { type: 'string' } } } } } } } }) } }
    },
    components: { schemas: Object.assign({
      C: { oneOf: [{ $ref: '#/components/schemas/C' }] },
      A: { oneOf: [{ $ref: '#/components/schemas/B' }] }, B: { anyOf: [{ $ref: '#/components/schemas/A' }] },
      D: { oneOf: [null] },
      Wide: { type: 'object', properties: wideProps } }, chain) }
  };
  await reload({ status: 200, body: spec2 });
  const opRow = name => root.byClass('sw-op').filter(r => r.textContent.includes(name))[0];
  opRow('self').byClass('sw-op-h')[0].click();
  opRow('mutual').byClass('sw-op-h')[0].click();
  out.rec_op_text = opRow('self').textContent + ' | ' + opRow('mutual').textContent;
  out.rec_op_errors = root.byClass('sw-error').length;
  const recPanel = root.byTag('section').filter(p => p.textContent.includes('self'))[0];
  recPanel.byClass('sw-gbtn')[0].click();
  const models = {}; recPanel.byClass('sw-model').forEach(m => { models[m.byClass('pill')[0].textContent] = m; });
  out.model_names = Object.keys(models).sort();
  ['C', 'A', 'D'].forEach(n => models[n].byClass('sw-model-h')[0].click());
  out.model_c = models.C.textContent;
  out.model_a = models.A.textContent;
  out.model_d_text = models.D.textContent;
  const dBtn = models.D.byClass('sw-model-h')[0];
  out.model_d_state = dBtn.getAttribute('aria-expanded') + '/' + dBtn.lastChild.textContent + '/' + models.D.byClass('sw-error').length;
  dBtn.click();
  out.model_d_closed = dBtn.getAttribute('aria-expanded') + '/' + dBtn.lastChild.textContent + '/' + models.D.byClass('sw-error')[0].hidden;
  opRow('wide').byClass('sw-op-h')[0].click();
  out.wide_rows = opRow('wide').byClass('sw-name').length;
  out.wide_note = opRow('wide').textContent.includes('Truncated: at least 1000 more fields');
  opRow('deep').byClass('sw-op-h')[0].click();
  out.deep_rows = opRow('deep').byClass('sw-name').length;
  out.deep_note = /Truncated: at least \d+ more fields/.test(opRow('deep').textContent);
  opRow('nested').byClass('sw-op-h')[0].click();
  out.indent_nbsp = opRow('nested').byClass('sw-indent').map(e => e.textContent).includes('\u00a0\u00a0\u00a0');
  // a small schema is not truncated
  out.small_note = opRow('nested').textContent.includes('Truncated');

  // ---- malformed spec entries and Object.prototype names ----
  const spec3 = {
    openapi: '3.0.3', info: { title: 't', version: '1' },
    tags: [null, 'str', 7, { description: 'no name' }, { name: 'Alpha', 'x-yuzu-guide': 'not an object' },
      { name: 'constructor', description: 'ctor summary', 'x-yuzu-guide': { overview: ['ctor guide'] } },
      { name: '__proto__', description: 'proto summary' }, { name: 'toString' }],
    paths: {
      '/n': null, '/s': 'text', '/o': { get: null, post: { summary: 'untagged post', tags: [null], responses: { '200': null } } },
      '/a': { get: { summary: 'alpha op', tags: ['Alpha'], responses: R() } },
      '/c': { get: { summary: 'ctor op', tags: ['constructor'], responses: R() } },
      '/p': { get: { summary: 'proto op', tags: ['__proto__'], responses: R() } },
      '/t': { get: { summary: 'tostring op', tags: ['toString'], responses: R() } }
    }
  };
  await reload({ status: 200, body: spec3 });
  const p3 = root.byTag('section');
  out.m_panels = p3.length;
  out.m_headers = p3.map(p => p.byTag('h2')[0].textContent + ':' + p.byClass('sub')[0].textContent + ':' + p.byClass('sw-gbtn').length).sort();
  const ctor = p3.filter(p => p.byTag('h2')[0].textContent === 'constructor')[0];
  ctor.byClass('sw-gbtn')[0].click();
  out.m_ctor_guide = ctor.textContent.includes('ctor guide');
  out.m_no_error_box = root.byClass('sw-error').length;
  const post = root.byClass('sw-op').filter(r => r.textContent.includes('untagged post'))[0];
  post.byClass('sw-op-h')[0].click();
  out.m_post_opened = post.byClass('sw-op-h')[0].getAttribute('aria-expanded') === 'true' && post.byClass('sw-error').length === 0;

  // ---- failure messages: never a raw JS error, always a way forward ----
  consoleErrors.length = 0;
  await reload({ status: 200, headers: { 'X-Correlation-Id': 'req-hdr-1' } });          // 200, body is not JSON
  out.f_html200 = root.textContent; out.f_html200_retry = root.byTag('button').length;
  await reload({ status: 502, headers: { 'X-Correlation-Id': 'req-hdr-2' } });          // 502, body not JSON, id only in the header
  out.f_502 = root.textContent;
  await reload({ status: 500, body: { error: { correlation_id: 'req-body-3' } }, headers: { 'X-Correlation-Id': 'req-hdr-3' } });
  out.f_500_body_cid = root.textContent;
  await reload({ fail: true });                                                          // the network is down
  out.f_net = root.textContent; out.f_net_retry = root.byTag('button').length;
  await reload({ status: 200, body: null });                                              // build() throws on a null document
  out.f_null_doc = root.textContent; out.f_null_doc_retry = root.byTag('button').length;
  await reload({ status: 200, body: { tags: [], paths: {} } });                           // an empty but valid document renders
  out.f_empty_panels = root.byTag('section').length;
  out.f_empty_text = root.textContent;
  out.console_errors = consoleErrors.length;
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
        if os.environ.get("YUZU_REQUIRE_NODE") == "1":
            # docs-lint.yml runs this on a hosted image that ships node: a missing node
            # there must fail, not skip the only check of the page's script.
            print("YUZU_REQUIRE_NODE=1 but node is not on PATH")
            return 1
        print("node not on PATH: skipping")
        return 77
    js = extract_js()
    page = SRC.read_text(encoding="utf-8")
    body = re.search(r'kSwaggerBody = R"SWG\((.*?)\)SWG";', page, re.S).group(1)
    if not re.search(r'<div id="sw-root"[^>]*><noscript>[^<]*JavaScript[^<]*</noscript>', body):
        print("FAIL")
        print("  - the page body must carry a <noscript> message inside #sw-root saying the reference needs JavaScript")
        return 1
    # The driver reads the script from stdin and evaluates it. Bytes both ways, UTF-8 explicitly:
    # the page script contains U+00A0 characters, which a locale codec such as cp1252 would
    # mangle in transit.
    proc = subprocess.run([node, "-e", DRIVER], input=js.encode("utf-8"), capture_output=True, timeout=120)
    stdout = proc.stdout.decode("utf-8")
    stderr = proc.stderr.decode("utf-8", "replace")
    if proc.returncode != 0:
        print(stdout, stderr)
        return 1
    out = json.loads(stdout.strip().splitlines()[-1])
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
    check(out["deep_link_hash"] == "#GET%20%2Fa%2F%7Bid%7D",
          "opening GET /a/{id} must write its encoded fragment itself: %r" % out["deep_link_hash"])
    check(out["dl_expanded"] == ["/a/{id}"] and out["dl_scrolled_op"],
          "a valid deep link must open and scroll to exactly that operation: %r" % out["dl_expanded"])
    check(out["dg_alpha_guide_open"] and out["dg_scrolled"] and out["dg_ops_closed"],
          "a group deep link must open that group's guide and scroll to it, and open no operation")
    check(out["dl_unknown_opens_nothing"], "an unknown fragment must open nothing and keep the page")
    check("HTTP 403" in out["error_text"] and "Infrastructure:Read" in out["error_text"] and "req-1" in out["error_text"],
          "403 view must name the status, the permission and the correlation id: %r" % out["error_text"])
    check(out["retry_fetched"] == 2 and out["after_retry_panels"] == 2, "Retry must fetch again and render (fetches %r)" % out["retry_fetched"])
    check("HTTP 500" in out["err500"] and out["err500_retry"] == 1, "a bodyless 500 must show a message and a Retry button")
    # A schema that reaches itself stops at a note, in an operation and in the data-model block.
    check(out["rec_op_errors"] == 0 and "(recursive: C)" in out["rec_op_text"] and "(recursive: A)" in out["rec_op_text"],
          "self and mutual oneOf/anyOf recursion must end in a note, not an error: %r" % out["rec_op_text"])
    check(out["model_names"] == ["A", "B", "C", "D"], "data model must list every reachable schema: %r" % out["model_names"])
    check("(recursive: C)" in out["model_c"] and "(recursive: A)" in out["model_a"] and "Hide fields" in out["model_c"],
          "the model-fields click on a recursive schema must open with a note")
    # A schema that cannot be drawn must show a message and keep the button honest.
    check("These fields could not be shown." in out["model_d_text"] and out["model_d_state"] == "true/Hide fields/1",
          "a model that throws must open to an inline message: %r" % out["model_d_state"])
    check(out["model_d_closed"] == "false/Show fields/true", "a failed model block must still close: %r" % out["model_d_closed"])
    # Breadth: wide and deep acyclic schemas stop at the budget and say so.
    check(out["wide_rows"] == 2000 and out["wide_note"], "a 3000-field schema must stop at 2000 rows and say 1000 more: %r" % out["wide_rows"])
    check(out["deep_rows"] == 2000 and out["deep_note"], "a wide 8-level chain must stop at 2000 rows with a note: %r" % out["deep_rows"])
    check(not out["small_note"], "a small schema must not carry a truncation note")
    check(out["indent_nbsp"], "nested rows must indent with three U+00A0 characters (UTF-8 survived the pipe)")
    # Malformed entries are skipped; prototype names are ordinary names.
    check(out["m_panels"] == 5 and out["m_no_error_box"] == 0 and out["m_post_opened"],
          "a malformed spec must still render its good entries: panels %r" % out["m_panels"])
    check(out["m_headers"] == ["Alpha:1 of 1 operations:0", "Untagged:1 of 1 operations:0", "__proto__:1 of 1 operations:0",
                               "constructor:1 of 1 operations:1", "toString:1 of 1 operations:0"],
          "groups named after Object.prototype keys need clean headers and no phantom Guide button: %r" % out["m_headers"])
    check(out["m_ctor_guide"], "the guide of a group named constructor must open")
    # Failure messages: no raw JS error text, a hint where one helps, the correlation id wherever the server sent one.
    check("not with an API description" in out["f_html200"] and "session may have expired" in out["f_html200"]
          and "req-hdr-1" in out["f_html200"] and out["f_html200_retry"] == 1 and "RAWBODY" not in out["f_html200"] and "Unexpected" not in out["f_html200"],
          "a non-JSON 200 must say so, hint at sign-in, show the header id and offer Retry: %r" % out["f_html200"])
    check("HTTP 502" in out["f_502"] and "req-hdr-2" in out["f_502"], "a non-JSON 502 must show the header correlation id: %r" % out["f_502"])
    check("req-body-3" in out["f_500_body_cid"] and "req-hdr-3" not in out["f_500_body_cid"], "the A4 body id wins over the header: %r" % out["f_500_body_cid"])
    check("could not be reached" in out["f_net"] and "NETRAW" not in out["f_net"] and out["f_net_retry"] == 1,
          "a network failure must be explained, not echoed: %r" % out["f_net"])
    check("could not be shown" in out["f_null_doc"] and "Cannot read" not in out["f_null_doc"] and out["f_null_doc_retry"] == 1,
          "a build failure must be a fixed message with Retry: %r" % out["f_null_doc"])
    check(out["console_errors"] == 5, "each failure must be logged to the console for diagnosis, got %r" % out["console_errors"])
    check(out["f_empty_panels"] == 0 and "Operations" in out["f_empty_text"], "an empty but valid document must render without error")
    if errors:
        print("FAIL")
        for e in errors:
            print("  -", e)
        return 1
    print("swagger page behaviour: OK")
    return 0


if __name__ == "__main__":
    sys.exit(main())
