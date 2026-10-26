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
document), which must show a fixed message and never the raw JavaScript error. It drives the search box and
the method / group / response-schema selects (rows hidden, counts, the empty view, the typed and
untyped pills, the summary chips, the live regions) and runs the renderer once over the real
document, the OpenAPI literal of rest_api_v1.cpp (the text openapi_spec_with_guides_json() serves).

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
import tempfile

ROOT = pathlib.Path(__file__).resolve().parents[1]
SRC = ROOT / "server/core/src/swagger_page_ui.cpp"
SPEC_SRC = ROOT / "server/core/src/rest_api_v1.cpp"
sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
import test_openapi_literal_segments as literal  # noqa: E402  (the one lexer of the literal chain)

# The inner subprocess limit stays under the meson timeout (60 s) so a hang reports itself
# instead of being killed by the harness with no output.
NODE_TIMEOUT = 45

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
const live = new E('div'); live.id = 'sw-status';
globalThis.document = { getElementById: i => (i === 'sw-root' ? root : i === 'sw-status' ? live : null), createElement: t => new E(t),
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
      '/m1': { get: { summary: 'combo', tags: ['Big'], responses: refResp('Detail') } },
      '/m2': { get: { summary: 'loopall', tags: ['Big'], responses: refResp('SelfAll') } },
      '/q1': { get: { summary: 'fanout', tags: ['Big'], responses: refResp('Fan0') } },
      '/q2': { get: { summary: 'chain12', tags: ['Big'], responses: refResp('Ch0') } },
      '/q3': { get: { summary: 'protoname', tags: ['Big'], responses: refResp('ProtoN') } },
      '/q4': { get: { summary: 'oneofm', tags: ['Big'], responses: refResp('OneOfM') } },
      '/q5': { get: { summary: 'nonarr', tags: ['Big'], responses: refResp('NonArr') } },
      '/q6': { get: { summary: 'arrwrap', tags: ['Big'], responses: refResp('ArrHolder') } },
      '/q7': { get: { summary: 'refine', tags: ['Big'], responses: refResp('Refined') } },
      '/n': { get: { summary: 'nested', tags: ['Big'], responses: R({ content: { 'application/json': { schema: { type: 'object', properties: { outer: { type: 'object', properties: { inner: { type: 'string' } } } } } } } }) } }
    },
    components: { schemas: Object.assign({
      C: { oneOf: [{ $ref: '#/components/schemas/C' }] },
      A: { oneOf: [{ $ref: '#/components/schemas/B' }] }, B: { anyOf: [{ $ref: '#/components/schemas/A' }] },
      D: { oneOf: [null] },
      Wide: { type: 'object', properties: wideProps },
      Row: { type: 'object', properties: { name: { type: 'string' }, steps: { type: 'array', items: { type: 'string' } } }, required: ['name'] },
      Detail: { allOf: [{ $ref: '#/components/schemas/Row' }, { type: 'object', properties: { yaml_source: { type: 'string' } }, required: ['yaml_source'] }] },
      ProtoN: { allOf: [{ type: 'object', properties: JSON.parse('{"__proto__": {"type": "string"}, "a": {"type": "string"}}') }, { type: 'object', properties: { b: { type: 'string' } } }] },
      OneOfM: { allOf: [{ type: 'object', properties: { x: { type: 'string' } } }, { oneOf: [{ type: 'object', properties: { alt_a: { type: 'string' } } }, { type: 'object', properties: { alt_b: { type: 'string' } } }] }] },
      NonArr: { allOf: 'oops', properties: { ok: { type: 'string' } } },
      ArrHolder: { type: 'object', properties: { rows: { allOf: [{ $ref: '#/components/schemas/ArrOfRow' }] } } },
      ArrOfRow: { type: 'array', items: { $ref: '#/components/schemas/RowItem' } },
      RowItem: { type: 'object', properties: { item_name: { type: 'string' } } },
      Refined: { allOf: [{ type: 'object', properties: { t: { type: 'integer' } } }, { type: 'object', properties: { t: { type: 'integer', format: 'int64', description: 'Unix epoch seconds.' } } }] },
      SelfAll: { allOf: [{ $ref: '#/components/schemas/SelfAll' }, { type: 'object', properties: { own: { type: 'string' } } }] } }, chain) }
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
  // A model written as allOf of several members lists every member's fields (and a member that
  // is the schema itself adds nothing and does not loop).
  opRow('combo').byClass('sw-op-h')[0].click();
  out.allof_names = opRow('combo').byClass('sw-name').map(e => e.textContent.trim());
  out.allof_required = opRow('combo').byClass('pill').map(e => e.textContent).filter(t => t === 'required').length;
  opRow('loopall').byClass('sw-op-h')[0].click();
  out.allof_self_names = opRow('loopall').byClass('sw-name').map(e => e.textContent.trim());
  // Hostile allOf shapes: wide acyclic fan-out must stay bounded, a long chain and a
  // non-array allOf must say they are cut, and the plain cases must list what they hold.
  for (let i = 0; i < 8; i++) { const ms = []; for (let j = 0; j < 6; j++) ms.push({ $ref: '#/components/schemas/Fan' + (i + 1) }); spec2.components.schemas['Fan' + i] = { allOf: ms }; }
  spec2.components.schemas.Fan8 = { type: 'object', properties: { leaf: { type: 'string' } } };
  for (let i = 0; i < 13; i++) { const f = {}; f['f' + i] = { type: 'string' }; const ms = [{ type: 'object', properties: f }]; if (i < 12) ms.push({ $ref: '#/components/schemas/Ch' + (i + 1) }); spec2.components.schemas['Ch' + i] = { allOf: ms }; }
  await reload({ status: 200, body: spec2 });
  const t0 = Date.now(); opRow('fanout').byClass('sw-op-h')[0].click(); out.fan_ms = Date.now() - t0;
  out.fan_note = opRow('fanout').textContent.includes('Truncated');
  opRow('chain12').byClass('sw-op-h')[0].click();
  out.chain_note = opRow('chain12').textContent.includes('Truncated');
  opRow('protoname').byClass('sw-op-h')[0].click();
  out.proto_names = opRow('protoname').byClass('sw-name').map(e => e.textContent.trim()).sort();
  opRow('oneofm').byClass('sw-op-h')[0].click();
  out.oneofm_text = opRow('oneofm').textContent;
  opRow('nonarr').byClass('sw-op-h')[0].click();
  out.nonarr = { errors: opRow('nonarr').byClass('sw-error').length, names: opRow('nonarr').byClass('sw-name').map(e => e.textContent.trim()), note: opRow('nonarr').textContent.includes('Truncated') };
  opRow('arrwrap').byClass('sw-op-h')[0].click();
  out.arrwrap_names = opRow('arrwrap').byClass('sw-name').map(e => e.textContent.trim());
  opRow('refine').byClass('sw-op-h')[0].click();
  out.refine_text = opRow('refine').textContent;
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

  // ---- the live regions: loading and failure are announced, the success view is not ----
  queue.push({ status: 503 }); location.hash = ''; (0, eval)(js);
  out.live_loading = live.textContent;             // before the fetch settles
  await settle();
  out.live_error = live.textContent;
  out.live_attrs = (document.getElementById('sw-status') === live);
  await reload({ status: 403, body: { error: { correlation_id: 'req-live' } } });
  out.live_403 = live.textContent;
  await reload({ status: 200, body: spec });
  out.live_cleared = live.textContent;

  // ---- search and filter: events on the controls, rows hidden, counts, pills, chips ----
  const rc = (extra) => ({ '200': Object.assign({ description: 'ok' }, extra || {}) });
  const t200 = { content: { 'application/json': { schema: { type: 'object' } } } };
  const specF = {
    openapi: '3.0.3', info: { title: 't', version: '1' },
    tags: [{ name: 'Alpha', description: 'a' }, { name: 'Beta', description: 'b' }],
    paths: {
      '/t1': { get: { summary: 'typed one', tags: ['Alpha'], responses: rc(t200) } },
      '/t2': { post: { summary: 'typed two', tags: ['Alpha'], responses: rc(t200) } },
      '/u1': { get: { summary: 'untyped one', tags: ['Beta'], responses: rc() } },
      // A schema on an error response only: the success response is still untyped.
      '/e1': { get: { summary: 'error schema', tags: ['Beta'], responses: Object.assign(rc(), { '404': t200 }) } },
      '/x1': { delete: { summary: 'unserved', tags: ['Beta'], 'x-yuzu-unavailable': 'Not served.', responses: rc() } },
      '/d1': { put: { summary: 'plain', description: 'Needle-Desc here', tags: ['Beta'], responses: rc() } }
    }
  };
  await reload({ status: 200, body: specF });
  const q = root.byTag('input')[0];
  const [msel, tsel, ysel] = root.byTag('select');
  const countEl = () => root.all(c => c.getAttribute('aria-live') === 'polite')[0];
  const emptyEl = () => root.byClass('sw-empty')[0];
  const rowsF = () => root.byClass('sw-op');
  const keyOf = r => r.byClass('pill')[0].textContent + ' ' + pathOf(r);
  const shown = () => rowsF().filter(r => !r.hidden).map(keyOf).sort();
  const act = (el, type, mutate) => { mutate(); el.fire(type); };
  const setQ = v => act(q, 'input', () => { q.value = v; });
  const setSel = (el, i) => act(el, 'change', () => { el.selectedIndex = i; });
  const reset = () => { setQ(''); setSel(msel, 0); setSel(tsel, 0); setSel(ysel, 0); };
  out.f_all_shown = shown().length;
  out.f_count0 = countEl().textContent;
  out.f_count_live = countEl().getAttribute('role') + '/' + countEl().getAttribute('aria-live');
  out.f_empty0 = emptyEl().hidden;
  out.f_pills = rowsF().map(r => pathOf(r) + '=' + r.byClass('pill').slice(-1)[0].textContent).sort();
  out.f_chips = root.byClass('chip').map(c => c.textContent);
  setSel(ysel, 1); out.f_typed = shown(); out.f_typed_count = countEl().textContent;
  setSel(ysel, 2); out.f_untyped = shown(); out.f_untyped_count = countEl().textContent;
  reset();
  setSel(msel, 1); out.f_get = shown();                       // GET
  setSel(msel, 5); out.f_delete = shown(); out.f_delete_count = countEl().textContent;   // DELETE
  reset();
  setSel(tsel, 1); out.f_alpha = shown();
  out.f_beta_panel_hidden = root.byTag('section').filter(p => p.byTag('h2')[0].textContent === 'Beta')[0].hidden;
  // The table-of-contents link of a group with no matching row is hidden with its panel.
  const tocHidden = () => root.byClass('sw-toc')[0].byTag('a').map(a => a.textContent + ':' + a.hidden);
  out.f_alpha_toc = tocHidden();
  out.f_alpha_sub = root.byTag('section').filter(p => p.byTag('h2')[0].textContent === 'Alpha')[0].byClass('sub')[0].textContent;
  reset();
  setQ('NEEDLE-desc'); out.f_search_desc = shown();           // matches the description, case-insensitively
  setQ('typed'); out.f_search_summary = shown();              // matches "typed one", "typed two", "untyped one"
  setSel(ysel, 1); out.f_search_and_typed = shown();          // narrowed again by the typed filter
  reset();
  setQ('no-such-operation'); out.f_none = shown().length; out.f_none_count = countEl().textContent;
  out.f_none_empty = emptyEl().hidden; out.f_none_panels = root.byTag('section').filter(p => !p.hidden).length;
  out.f_none_toc = tocHidden();
  setQ(''); out.f_back_toc = tocHidden(); out.f_back_empty = emptyEl().hidden; out.f_back_shown = shown().length;

  // ---- the real document: every operation drawn, every pill and filter agreeing with it ----
  const real = JSON.parse(require('fs').readFileSync(process.argv[2], 'utf8'));
  const M = ['get', 'post', 'put', 'patch', 'delete'];
  const expect = []; Object.keys(real.paths).forEach(p => M.forEach(m => { const op = real.paths[p][m]; if (op && typeof op === 'object') {
    const typedOp = Object.keys(op.responses || {}).some(c => /^2/.test(c) && op.responses[c] && op.responses[c].content &&
      Object.keys(op.responses[c].content).some(mt => op.responses[c].content[mt].schema));
    expect.push({ k: m.toUpperCase() + ' ' + p, typed: typedOp, unavail: !!op['x-yuzu-unavailable'] }); } }));
  consoleErrors.length = 0;
  await reload({ status: 200, body: real });
  const rr = root.byClass('sw-op');
  out.r_expect = expect.length; out.r_rows = rr.length;
  out.r_expect_typed = expect.filter(e => e.typed && !e.unavail).length;
  out.r_expect_untyped = expect.filter(e => !e.typed && !e.unavail).length;
  out.r_expect_unavail = expect.filter(e => e.unavail).length;
  const lastPill = r => r.byClass('pill').slice(-1)[0].textContent;
  out.r_typed = rr.filter(r => lastPill(r) === 'typed').length;
  out.r_untyped = rr.filter(r => lastPill(r) === 'untyped').length;
  out.r_unavail = rr.filter(r => lastPill(r) === 'unavailable').length;
  const rq = root.byTag('input')[0], [rm, rt, ry] = root.byTag('select');
  const rcount = () => root.all(c => c.getAttribute('aria-live') === 'polite')[0].textContent;
  out.r_count0 = rcount();
  ry.selectedIndex = 1; ry.fire('change');
  out.r_filter_typed = root.byClass('sw-op').filter(r => !r.hidden).length; out.r_expect_filter_typed = expect.filter(e => e.typed).length;
  ry.selectedIndex = 2; ry.fire('change');
  out.r_filter_untyped = root.byClass('sw-op').filter(r => !r.hidden).length; out.r_expect_filter_untyped = expect.filter(e => !e.typed).length;
  ry.selectedIndex = 0; ry.fire('change');
  rm.selectedIndex = 5; rm.fire('change');
  out.r_filter_delete = root.byClass('sw-op').filter(r => !r.hidden).length; out.r_expect_delete = expect.filter(e => e.k.startsWith('DELETE ')).length;
  rm.selectedIndex = 0; rm.fire('change');
  out.r_panels = root.byTag('section').length;
  out.r_expect_panels = new Set(Object.keys(real.paths).flatMap(p => M.map(m => real.paths[p][m]).filter(o => o && typeof o === 'object').map(o => (o.tags && o.tags[0]) || 'Untagged'))).size;
  // WorkflowDetail is allOf [WorkflowRow, {yaml_source}]: the page must list the row's fields too.
  const wfRow = rr.filter(r => pathOf(r) === '/workflows/{id}' && r.textContent.startsWith('GET'))[0];
  wfRow.byClass('sw-op-h')[0].click();
  out.r_wf_names = wfRow.byClass('sw-name').map(e => e.textContent.trim());
  out.r_console_errors = consoleErrors.length;
  out.r_guides = root.byClass('sw-gbtn').length;
  out.r_expect_guides = (real.tags || []).filter(t => t['x-yuzu-guide']).length;
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


def real_spec():
    """The document openapi_spec_with_guides_json() serves: the literal chain of
    rest_api_v1.cpp with its three ecosystem tokens substituted (here by stand-in names; the
    renderer only reads the structure)."""
    text = literal.chain_text(SPEC_SRC.read_bytes()).decode("utf-8")
    text = (text.replace('"@@ECOSYSTEM_ENUM@@"', '"eco-a", "eco-b"')
                .replace('"@@ECOSYSTEM_ENUM_OR_EMPTY@@"', '"", "eco-a", "eco-b"')
                .replace("@@ECOSYSTEM_LIST@@", "eco-a|eco-b"))
    # A renamed token would otherwise sit through json.loads as an ordinary string.
    assert "@@ECOSYSTEM_" not in text, "an ecosystem token was left unsubstituted in the spec literal"
    doc = json.loads(text)
    if len(doc.get("paths", {})) < 100:
        raise ValueError("only %d paths in the literal: the chain was probably cut" % len(doc.get("paths", {})))
    return doc


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
    try:
        real = real_spec()
    except (literal.ChainError, ValueError) as e:
        print("FAIL")
        print("  - cannot read the real OpenAPI document from rest_api_v1.cpp: %s" % e)
        return 1
    # The driver (16 KB) and the real document (about 1 MB) go to node as files, not as
    # `node -e <source>`: a command line has a length limit on Windows, and a .cmd shim on PATH
    # would be re-parsed by cmd.exe. The prefix keeps the name inside the Defender exclusion.
    with tempfile.TemporaryDirectory(prefix="yuzu_test_swagger_") as tmp:
        driver = pathlib.Path(tmp) / "driver.js"
        spec_file = pathlib.Path(tmp) / "openapi_with_guides.json"
        driver.write_text(DRIVER, encoding="utf-8")
        spec_file.write_text(json.dumps(real), encoding="utf-8")
        proc = subprocess.run([node, str(driver), str(spec_file)], input=js.encode("utf-8"),
                              capture_output=True, timeout=NODE_TIMEOUT)
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
    check(out["allof_names"] == ["name", "steps", "yaml_source"] and out["allof_required"] >= 2,
          "an allOf of several members must list the merged fields, with required: %r" % out["allof_names"])
    check(out["allof_self_names"] == ["own"], "an allOf member that names its own schema must be skipped, not looped: %r" % out["allof_self_names"])
    check(out["fan_ms"] < 1500 and out["fan_note"], "wide acyclic allOf fan-out must stay bounded and say it is cut: %r ms, note %r" % (out["fan_ms"], out["fan_note"]))
    check(out["chain_note"], "an allOf chain deeper than the cap must say it is truncated")
    check(out["proto_names"] == ["__proto__", "a", "b"], "a property named __proto__ must be listed through an allOf: %r" % out["proto_names"])
    check("alt_a" in out["oneofm_text"] and "alt_b" in out["oneofm_text"] and "Option 2" in out["oneofm_text"],
          "an allOf member that is a oneOf must show its options: %r" % out["oneofm_text"][:200])
    check(out["nonarr"]["errors"] == 0 and out["nonarr"]["names"] == ["ok"] and out["nonarr"]["note"],
          "an allOf that is not an array must not hide the operation: %r" % out["nonarr"])
    check("item_name" in out["arrwrap_names"], "a one-member allOf around an array must still descend into its rows: %r" % out["arrwrap_names"])
    check("Unix epoch seconds." in out["refine_text"], "a later allOf member must fill a missing description: %r" % out["refine_text"][:200])
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
    # Live regions: a persistent polite region says that the page is loading or why it failed.
    check(out["live_loading"] == "Loading the API description...", "loading must be announced: %r" % out["live_loading"])
    check("HTTP 503" in out["live_error"] and out["live_attrs"], "a failure must be announced: %r" % out["live_error"])
    check("HTTP 403" in out["live_403"] and "Infrastructure:Read" in out["live_403"] and "req-live" in out["live_403"],
          "the announced failure must carry the status, the permission and the id: %r" % out["live_403"])
    check(out["live_cleared"] == "", "the loading/failure announcement must clear once the page is drawn: %r" % out["live_cleared"])
    # Search and filters.
    check(out["f_all_shown"] == 6 and out["f_count0"] == "6 of 6 operations" and out["f_empty0"] is True,
          "all six operations shown at first, with a count and no empty view: %r %r" % (out["f_all_shown"], out["f_count0"]))
    check(out["f_count_live"] == "status/polite", "the filter count must be a polite live region: %r" % out["f_count_live"])
    check(out["f_pills"] == ["/d1=untyped", "/e1=untyped", "/t1=typed", "/t2=typed", "/u1=untyped", "/x1=unavailable"],
          "each row's pill: typed only for a 2xx schema, unavailable over both: %r" % out["f_pills"])
    check(any(c == "Typed responses2 (33%)" for c in out["f_chips"]) and any(c == "Unavailable1" for c in out["f_chips"])
          and any(c == "Operations6" for c in out["f_chips"]), "summary chips must count 6 / 2 typed (33%%) / 1 unavailable: %r" % out["f_chips"])
    check(out["f_typed"] == ["GET /t1", "POST /t2"] and out["f_typed_count"] == "2 of 6 operations",
          "the typed filter must keep only typed rows: %r %r" % (out["f_typed"], out["f_typed_count"]))
    check(out["f_untyped"] == ["DELETE /x1", "GET /e1", "GET /u1", "PUT /d1"] and out["f_untyped_count"] == "4 of 6 operations",
          "the untyped filter must keep the other four (an error-response schema is not typed): %r" % out["f_untyped"])
    check(out["f_get"] == ["GET /e1", "GET /t1", "GET /u1"], "the GET filter: %r" % out["f_get"])
    check(out["f_delete"] == ["DELETE /x1"] and out["f_delete_count"] == "1 of 6 operations", "the DELETE filter: %r" % out["f_delete"])
    check(out["f_alpha"] == ["GET /t1", "POST /t2"] and out["f_beta_panel_hidden"] is True and out["f_alpha_sub"] == "2 of 2 operations",
          "the group filter must hide the other group's panel: %r" % out["f_alpha"])
    check(out["f_alpha_toc"] == ["Alpha 2:false", "Beta 0:true"] and out["f_none_toc"] == ["Alpha 0:true", "Beta 0:true"]
          and out["f_back_toc"] == ["Alpha 2:false", "Beta 4:false"],
          "a group with no matching row must hide its table-of-contents link, and show it again: %r %r %r" % (
              out["f_alpha_toc"], out["f_none_toc"], out["f_back_toc"]))
    check(out["f_search_desc"] == ["PUT /d1"], "search must match descriptions, ignoring case: %r" % out["f_search_desc"])
    check(out["f_search_summary"] == ["GET /t1", "GET /u1", "POST /t2"], "search must match summaries: %r" % out["f_search_summary"])
    check(out["f_search_and_typed"] == ["GET /t1", "POST /t2"], "search and the typed filter must combine: %r" % out["f_search_and_typed"])
    check(out["f_none"] == 0 and out["f_none_count"] == "0 of 6 operations" and out["f_none_empty"] is False and out["f_none_panels"] == 0,
          "a search that matches nothing must show the empty view and no panels: %r" % out["f_none_count"])
    check(out["f_back_empty"] is True and out["f_back_shown"] == 6, "clearing the search must bring every row back")
    # The real document.
    check(out["r_expect"] > 200 and out["r_rows"] == out["r_expect"], "one row per real operation: %r of %r" % (out["r_rows"], out["r_expect"]))
    check(out["r_typed"] == out["r_expect_typed"] and out["r_untyped"] == out["r_expect_untyped"] and out["r_unavail"] == out["r_expect_unavail"],
          "typed/untyped/unavailable pills over the real document: %r/%r/%r expected %r/%r/%r" % (
              out["r_typed"], out["r_untyped"], out["r_unavail"], out["r_expect_typed"], out["r_expect_untyped"], out["r_expect_unavail"]))
    check(out["r_count0"] == "%d of %d operations" % (out["r_expect"], out["r_expect"]), "the real document's count: %r" % out["r_count0"])
    check(out["r_filter_typed"] == out["r_expect_filter_typed"] and out["r_filter_untyped"] == out["r_expect_filter_untyped"]
          and out["r_filter_typed"] + out["r_filter_untyped"] == out["r_expect"],
          "typed + untyped filters must partition the real operations: %r + %r" % (out["r_filter_typed"], out["r_filter_untyped"]))
    check(out["r_filter_delete"] == out["r_expect_delete"] and out["r_filter_delete"] > 0, "the DELETE filter over the real document: %r" % out["r_filter_delete"])
    check(out["r_panels"] == out["r_expect_panels"] and out["r_guides"] == out["r_expect_guides"] and out["r_guides"] > 0,
          "one panel per group and a Guide button for every group that has one: %r/%r guides %r/%r" % (
              out["r_panels"], out["r_expect_panels"], out["r_guides"], out["r_expect_guides"]))
    check(all(n in out["r_wf_names"] for n in ("name", "steps", "yaml_source")),
          "GET /workflows/{id} (an allOf of two members) must list name, steps and yaml_source: %r" % out["r_wf_names"])
    check(out["r_console_errors"] == 0, "the real document must draw without a console error: %r" % out["r_console_errors"])
    if errors:
        print("FAIL")
        for e in errors:
            print("  -", e)
        return 1
    print("swagger page behaviour: OK")
    return 0


if __name__ == "__main__":
    sys.exit(main())
