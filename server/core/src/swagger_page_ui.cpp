// API reference page (/swagger): renders the OpenAPI document served at
// GET /api/v1/openapi.json as a searchable, grouped reference, with the guide of each
// group (the document's top-level `tags[].x-yuzu-guide`) above its operations. A page
// shell only: no store, no mutation, no audit trail (page_routes.hpp). The document is
// fetched by the browser with the operator's own session, so the existing
// Infrastructure:Read gate on /api/v1/openapi.json still decides what is readable;
// /swagger takes the same gate so a denied operator gets a 403 instead of a shell that
// cannot load. The renderer builds the DOM with textContent only: spec text contains
// literal "<plugin>" and similar.
//
// The page is assembled from named pieces so each raw literal can be measured against
// MSVC's 16,380-byte C2026 cap (docs/cpp-conventions.md); test_swagger_page.cpp keeps
// every piece under 15,000 bytes.

#include "app_shell.hpp"

#include <string>

// NOLINTBEGIN(cert-err58-cpp)
// Document head up to the opening <style>.
extern const char* const kSwaggerHead = R"SWG(<!DOCTYPE html>
<html lang="en"><head>
<meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Yuzu — API reference</title>
<link rel="stylesheet" href="/static/yuzu.css">
<script src="/static/htmx.js"></script>
<style>
)SWG";

// Page-local styles; colours come from yuzu.css tokens.
extern const char* const kSwaggerCss = R"SWG(.sw-page{padding:22px 28px 36px;display:flex;flex-direction:column;gap:16px;max-width:1440px}
.sw-chips{display:flex;flex-wrap:wrap;gap:6px 18px}
.sw-bar{display:flex;flex-wrap:wrap;gap:8px;align-items:center}
.sw-ctl{background:var(--surface2);color:var(--ink);border:1px solid var(--line2);border-radius:var(--rad-ctl);height:32px;padding:0 10px;font-size:13px}
#sw-q{flex:1 1 280px;min-width:0}
.sw-ctl:focus-visible,.sw-op-h:focus-visible,.sw-toc a:focus-visible{outline:2px solid var(--focus);outline-offset:2px}
.sw-grid{display:grid;grid-template-columns:210px minmax(0,1fr);gap:16px;align-items:start}
.sw-toc{position:sticky;top:12px;max-height:calc(100vh - 24px);overflow:auto;display:flex;flex-direction:column;gap:1px;font-size:13px}
.sw-toc-h{font-size:12.5px;color:var(--mut);padding:0 8px 6px}
.sw-toc a{display:flex;justify-content:space-between;gap:8px;padding:4px 8px;color:var(--mut);text-decoration:none;border-radius:3px}
.sw-toc a:hover{color:var(--ink);background:var(--mds-color-state-hover)}
.sw-main{display:flex;flex-direction:column;gap:16px;min-width:0}
.sw-op{border-bottom:1px solid var(--line)}
.sw-op:last-child{border-bottom:0}
.sw-op-h{width:100%;display:flex;align-items:center;gap:10px;padding:9px 16px;background:none;border:0;color:inherit;font:inherit;text-align:left;cursor:pointer;transition:background .12s}
.sw-op-h:hover,.sw-op-h[aria-expanded=true]{background:var(--surface2)}
.sw-m{min-width:60px;justify-content:center}
.sw-path{font-family:var(--mds-font-family-mono);font-size:12.5px;color:var(--ink);overflow-wrap:anywhere}
.sw-sum{color:var(--mut);flex:1;min-width:0;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
.sw-detail{padding:2px 16px 16px;border-top:1px solid var(--line);background:var(--bg)}
.sw-detail h3{margin:16px 0 8px;font-size:12.5px;font-weight:500;color:var(--mut)}
.sw-text{color:var(--ink2);max-width:90ch;margin-top:12px;white-space:pre-wrap;overflow-wrap:anywhere}
.sw-detail pre{margin:0;background:var(--surface2);border:1px solid var(--line);border-radius:var(--rad-ctl);padding:10px 12px;overflow-x:auto;font-family:var(--mds-font-family-mono);font-size:12.5px;color:var(--ink2)}
.sw-tw{border:1px solid var(--line);border-radius:var(--rad-ctl);background:var(--surface)}
.sw-detail table{width:100%;border-collapse:collapse}
.panel .sw-detail th{text-align:left;font-size:12.5px;font-weight:500;color:var(--mut);padding:6px 12px;background:var(--surface2);border-bottom:1px solid var(--line);white-space:nowrap}
.panel .sw-detail td{padding:5px 12px;white-space:normal;border-bottom:1px solid var(--line);color:var(--ink2);vertical-align:top}
.panel .sw-detail tr:last-child td{border-bottom:0}
.sw-name{white-space:nowrap;color:var(--ink)}
.sw-desc{min-width:220px;overflow-wrap:anywhere}
.sw-enum{display:flex;flex-wrap:wrap;gap:4px;margin-top:4px}
.sw-resp{margin-top:10px;display:flex;flex-direction:column;gap:6px}
.sw-resp-head{display:flex;gap:10px;align-items:baseline}
.sw-hdrs{display:flex;flex-direction:column;gap:2px;color:var(--mut);font-size:13px;padding-left:4px}
.sw-ct{margin-top:2px}
.sw-schema-head{display:flex;gap:10px;align-items:center;margin:4px 0 6px}
.sw-untyped{color:var(--faint);font-size:13px}
.sw-empty,.sw-error{padding:24px;border:1px solid var(--line);border-radius:var(--rad-panel);background:var(--surface);color:var(--mut)}
.sw-error{border-color:color-mix(in srgb,var(--bad) 50%,var(--line2));color:var(--ink)}
@media(max-width:900px){.sw-grid{grid-template-columns:minmax(0,1fr)}.sw-toc{display:none}.sw-sum{display:none}.sw-page{padding:16px}}
.sw-page [hidden]{display:none!important}

.sw-gsum{padding:10px 16px;color:var(--ink2);border-bottom:1px solid var(--line)}
.sw-gbtn{margin-left:auto}
.sw-guide{padding:4px 16px 16px;border-bottom:1px solid var(--line);background:var(--bg)}
.sw-guide h3{margin:16px 0 8px;font-size:12.5px;font-weight:500;color:var(--mut)}
.sw-guide .sw-text{margin-top:12px}
.sw-cap{margin:0 0 8px;font-size:13px}
.sw-flow{display:grid;grid-template-columns:repeat(auto-fit,minmax(200px,1fr));gap:12px;margin-top:14px}
.sw-flow>div{min-width:0;border:1px solid var(--line);border-radius:var(--rad-ctl);background:var(--surface2);padding:10px 12px}
.sw-flow b{display:block;color:var(--ink);font-weight:600;margin-bottom:4px}
.sw-flow span{color:var(--mut);font-size:13px}
.sw-gcols{display:grid;grid-template-columns:repeat(auto-fit,minmax(260px,1fr));gap:16px;margin-top:4px}
.sw-gcol{min-width:0}
.sw-gcol ul{margin:0;padding-left:18px;color:var(--ink2);font-size:13px;display:flex;flex-direction:column;gap:4px}
.sw-gtn{display:flex;gap:10px;align-items:baseline;padding:4px 0;color:var(--ink2);max-width:100ch}
.sw-gtn .pill{flex:none}
.sw-docs{margin-top:14px;font-size:13px}
.sw-model{border-top:1px solid var(--line)}
.sw-model-h{width:100%;display:flex;align-items:center;gap:10px;padding:7px 4px;background:none;border:0;color:inherit;font:inherit;text-align:left;cursor:pointer}
.sw-model-h:hover{background:var(--surface2)}
.sw-model-h:focus-visible{outline:2px solid var(--focus);outline-offset:2px}
.sw-model .sw-tw{margin-bottom:10px}
.panel .sw-guide th{text-align:left;font-size:12.5px;font-weight:500;color:var(--mut);padding:6px 12px;background:var(--surface2);border-bottom:1px solid var(--line);white-space:nowrap}
.panel .sw-guide td{padding:6px 12px;border-bottom:1px solid var(--line);color:var(--ink2);vertical-align:top;white-space:normal}
.panel .sw-guide tr:last-child td{border-bottom:0}
.panel .sw-guide table{width:100%;border-collapse:collapse}
.sw-unavail{display:flex;gap:10px;align-items:baseline;margin-top:12px;padding:8px 12px;border:1px solid color-mix(in srgb,var(--warn) 50%,var(--line2));border-radius:var(--rad-ctl);background:var(--mds-color-bg-warning-tinted);color:var(--ink2)}
.sw-unavail .pill{flex:none})SWG";

// End of <style>, the shell marker, the page header and the opening <script>.
extern const char* const kSwaggerBody = R"SWG(
</style>
</head><body>

  <!--yuzu:shell--><!--/yuzu:shell-->

<div class="sw-page">
  <header class="page-header"><div>
    <h1>API reference</h1>
    <div class="subtitle">Every REST v1 operation this server documents, read live from <code>/api/v1/openapi.json</code>. The same document is available to agentic workers over MCP as <code>yuzu://openapi</code>. Each group opens with a guide to what it is for, who may call it and what to watch for.</div>
  </div></header>
  <div id="sw-root" class="mut">Loading the API description...</div>
</div>
<div id="toast-container" class="toast-container"></div>
<script>
)SWG";

// Renderer, part 1 of 2 (split at a line boundary).
extern const char* const kSwaggerJs1 = R"SWG((function () {
  'use strict';
  var SPEC_URL = '/api/v1/openapi.json?guides=true';
  var METHODS = ['get', 'post', 'put', 'patch', 'delete'];
  var MPILL = { get: 'ok', post: 'info', put: 'warn', patch: 'warn', 'delete': 'bad' };
  var spec = null, ops = [], tags = [], st = { q: '', method: '', tag: '', typed: '' };
  var root = document.getElementById('sw-root');

  // DOM helper: strings become text nodes, never markup (spec text contains "<plugin>").
  function h(tag, cls, kids) {
    var e = document.createElement(tag);
    if (cls) e.className = cls;
    (kids || []).forEach(function (k) {
      if (k == null || k === false) return;
      e.appendChild(typeof k === 'string' ? document.createTextNode(k) : k);
    });
    return e;
  }
  function pill(text, cls) { return h('span', 'pill ' + (cls || 'idle'), [text]); }
  function mono(text) { return h('span', 'mono', [text]); }

  function refName(r) { return r.split('/').pop(); }
  function deref(s, seen) {
    if (!s || !s.$ref) return s || {};
    var n = refName(s.$ref);
    if (seen && seen.indexOf(n) >= 0) return { type: 'object', description: '(recursive: ' + n + ')' };
    var t = spec.components && spec.components.schemas && spec.components.schemas[n];
    return t || {};
  }
  function label(s) {
    if (!s) return 'any';
    if (s.$ref) return refName(s.$ref);
    if (s.allOf && s.allOf.length === 1) return label(s.allOf[0]) + (s.nullable ? ' | null' : '');
    var t = s.type || (s.properties ? 'object' : s.oneOf ? 'oneOf' : s.anyOf ? 'anyOf' : 'any');
    if (t === 'array') t = label(s.items) + '[]';
    if (s.enum) t = (s.type || 'string') + ' enum';
    return t + (s.nullable ? ' | null' : '');
  }
  function successSchema(op) {
    var found = false, r = op.responses || {};
    Object.keys(r).forEach(function (c) {
      if (/^2/.test(c) && r[c].content) {
        Object.keys(r[c].content).forEach(function (m) { if (r[c].content[m].schema) found = true; });
      }
    });
    return found;
  }

  // Schema -> table rows. depth/seen guard against recursion.
  function schemaRows(s, depth, seen, req, out, indent) {
    var base = s.allOf && s.allOf.length === 1 && !s.properties ? s.allOf[0] : s;
    var n = base.$ref ? refName(base.$ref) : null;
    var d = deref(base, seen);
    var nseen = n ? (seen || []).concat([n]) : seen;
    if (d.type === 'array' && d.items) { return schemaRows(d.items, depth, nseen, req, out, indent); }
    var props = d.properties || {};
    var required = d.required || [];
    Object.keys(props).forEach(function (k) {
      var p = props[k], pd = deref(p, nseen);
      var tr = h('tr', '', [
        h('td', 'sw-name', [h('span', 'sw-indent', [new Array(indent + 1).join('   ')]), mono(k)]),
        h('td', '', [pill(label(p), 'idle mono')]),
        h('td', '', [required.indexOf(k) >= 0 ? pill('required', 'ok') : pill('optional', 'idle')]),
        h('td', 'sw-desc', [pd.description || p.description || '', pd.enum ? h('div', 'sw-enum', pd.enum.map(function (v) { return h('code', '', [String(v)]); })) : null])
      ]);
      out.push(tr);
      var inner = p.items ? p.items : p;
      var innerD = deref(inner, nseen);
      if (depth < 5 && (innerD.properties || (innerD.allOf && innerD.allOf.length === 1))) {
        schemaRows(inner, depth + 1, nseen, false, out, indent + 1);
      }
    });
    return out;
  }
  function schemaBlock(s) {
    var d = deref(s.allOf && s.allOf.length === 1 ? s.allOf[0] : s);
    var head = h('div', 'sw-schema-head', [pill(label(s), 'info mono'), d.description ? h('span', 'mut', [d.description]) : null]);
    var rows = schemaRows(s, 0, [], false, [], 0);
    if (!rows.length) return h('div', '', [head]);
    var table = h('table', '', [
      h('thead', '', [h('tr', '', ['Property', 'Type', '', 'Description'].map(function (t) { return h('th', '', [t]); }))]),
      h('tbody', '', rows)
    ]);
    return h('div', '', [head, h('div', 'tw sw-tw', [table])]);
  }

  function paramsTable(list) {
    var rows = list.map(function (p) {
      var s = p.schema || {};
      var extra = [];
      if (s.enum) extra.push(h('div', 'sw-enum', s.enum.map(function (v) { return h('code', '', [String(v)]); })));
      var lim = [];
      if (s['default'] !== undefined) lim.push('default ' + s['default']);
      if (s.minimum !== undefined || s.maximum !== undefined) lim.push((s.minimum !== undefined ? s.minimum : '') + ' to ' + (s.maximum !== undefined ? s.maximum : ''));
      if (s.maxLength) lim.push('max ' + s.maxLength + ' B');
      return h('tr', '', [
        h('td', 'sw-name', [mono(p.name)]), h('td', '', [pill(p['in'], 'idle')]),
        h('td', '', [pill(label(s), 'idle mono')]), h('td', '', [p.required ? pill('required', 'ok') : pill('optional', 'idle')]),
        h('td', 'mut', [lim.join(', ')]), h('td', 'sw-desc', [p.description || '', extra[0] || null])
      ]);
    });
    return h('div', 'tw sw-tw', [h('table', '', [
      h('thead', '', [h('tr', '', ['Name', 'In', 'Type', '', 'Limit', 'Description'].map(function (t) { return h('th', '', [t]); }))]),
      h('tbody', '', rows)])]);
  }

  function responseBlock(code, r) {
    var cls = /^2/.test(code) ? 'ok' : /^4/.test(code) ? 'warn' : /^5/.test(code) ? 'bad' : 'idle';
    var kids = [h('div', 'sw-resp-head', [pill(code, cls + ' mono'), h('span', 'sw-desc', [r.description || ''])])];
    if (r.headers) {
      kids.push(h('div', 'sw-hdrs', Object.keys(r.headers).map(function (k) {
        return h('div', '', [mono(k), ' ', h('span', 'mut', [(r.headers[k].description || '')])]);
      })));
    }
    if (r.content) {
      Object.keys(r.content).forEach(function (m) {
        kids.push(h('div', 'sw-ct', [pill(m, 'idle mono')]));
        var s = r.content[m].schema;
        if (s) kids.push(schemaBlock(s));
      });
    } else if (/^2/.test(code)) {
      kids.push(h('div', 'sw-untyped', ['No response schema is declared for this status; the description above is the only documentation.']));
    }
    return h('div', 'sw-resp', kids);
  }

  function detail(o) {
    var op = o.op, kids = [];
    if (o.unavail) kids.push(h('div', 'sw-unavail', [pill('unavailable', 'warn'), h('span', '', [o.unavail])]));
    if (op.description) kids.push(h('p', 'sw-text', [op.description]));
    var curl = 'curl -s -X ' + o.method.toUpperCase() + ' \\\n  -H "Authorization: Bearer $YUZU_TOKEN" \\\n  "' + location.origin + '/api/v1' + o.path + '"';
    kids.push(h('h3', '', ['Request']));
    kids.push(h('pre', '', [curl]));
    if (op.parameters && op.parameters.length) { kids.push(h('h3', '', ['Parameters'])); kids.push(paramsTable(op.parameters)); }
    var rb = op.requestBody;
    if (rb && rb.content) {
      kids.push(h('h3', '', ['Request body' + (rb.required ? ' (required)' : '')]));
      Object.keys(rb.content).forEach(function (m) {
        kids.push(h('div', 'sw-ct', [pill(m, 'idle mono')]));
        if (rb.content[m].schema) kids.push(schemaBlock(rb.content[m].schema));
      });
    }
    kids.push(h('h3', '', ['Responses']));
    Object.keys(op.responses || {}).forEach(function (c) { kids.push(responseBlock(c, op.responses[c])); });
    return h('div', 'sw-detail', kids);
  }


  // ---- group guides (spec.tags[].x-yuzu-guide) ----
  var guides = {};
  var SKIP_MODEL = { ApiMeta: 1, ApiPagination: 1, A4ErrorEnvelope: 1, ApiEnvelope: 1 };
  function collectRefs(node, acc) {
    if (!node || typeof node !== 'object') return;
    if (Array.isArray(node)) { node.forEach(function (n) { collectRefs(n, acc); }); return; }
    if (node.$ref) { acc[refName(node.$ref)] = 1; return; }
    Object.keys(node).forEach(function (k) { collectRefs(node[k], acc); });
  }
  function modelNames(list) {
    var seen = {}, queue = {}, order = [];
    list.forEach(function (o) { collectRefs(o.op.responses, queue); collectRefs(o.op.requestBody, queue); });
    var names = Object.keys(queue);
    while (names.length && order.length < 60) {
      var n = names.shift();
      if (seen[n] || SKIP_MODEL[n]) continue;
      seen[n] = 1; order.push(n);
      var sub = {}; collectRefs(spec.components.schemas[n], sub);
      Object.keys(sub).forEach(function (m) { if (!seen[m]) names.push(m); });
    }
    return order;
  }
  function plainTable(cols, rows) {
    return h('div', 'tw sw-tw', [h('table', '', [
      h('thead', '', [h('tr', '', cols.map(function (c) { return h('th', '', [c]); }))]),
      h('tbody', '', rows.map(function (r) { return h('tr', '', r.map(function (c) { return h('td', 'sw-desc', [String(c)]); })); }))])]);
  }
  function listBlock(title, items) {
    if (!items || !items.length) return null;
    return h('div', 'sw-gcol', [h('h3', '', [title]), h('ul', '', items.map(function (i) { return h('li', '', [i]); }))]);
  }
  function modelBlock(names) {
    if (!names.length) return null;
    var kids = [h('h3', '', ['Data model'])];
    names.forEach(function (n) {
      var body = null;
      var btn = h('button', 'sw-model-h', [pill(n, 'info mono'), h('span', 'mut', ['Show fields'])]);
      btn.type = 'button'; btn.setAttribute('aria-expanded', 'false');
      var wrap = h('div', 'sw-model', [btn]);
      btn.addEventListener('click', function () {
        var open = btn.getAttribute('aria-expanded') !== 'true';
        btn.setAttribute('aria-expanded', open ? 'true' : 'false');
        btn.lastChild.textContent = open ? 'Hide fields' : 'Show fields';
)SWG";

// Renderer, part 2 of 2.
extern const char* const kSwaggerJs2 = R"SWG(        if (open && !body) { body = schemaBlock({ $ref: '#/components/schemas/' + n }); wrap.appendChild(body); }
        if (body) body.hidden = !open;
      });
      kids.push(wrap);
    });
    return h('div', '', kids);
  }
  function guideBlock(g, list) {
    var kids = [];
    (g.overview || []).forEach(function (p) { kids.push(h('p', 'sw-text', [p])); });
    if (g.how_it_works && g.how_it_works.length) {
      kids.push(h('div', 'sw-flow', g.how_it_works.map(function (s) {
        return h('div', '', [h('b', '', [s.title]), h('span', '', [s.text])]);
      })));
    }
    (g.tables || []).forEach(function (t) {
      kids.push(h('h3', '', [t.title]));
      if (t.caption) kids.push(h('p', 'mut sw-cap', [t.caption]));
      kids.push(plainTable(t.columns, t.rows));
    });
    var a = g.access || {};
    var cols = [listBlock('Permissions', a.permissions), listBlock('Audit', a.audit), listBlock('Notes on access', a.notes)].filter(Boolean);
    if (cols.length) kids.push(h('div', 'sw-gcols', cols));
    if (g.good_to_know && g.good_to_know.length) {
      kids.push(h('h3', '', ['Good to know']));
      g.good_to_know.forEach(function (x) { kids.push(h('div', 'sw-gtn', [pill(x.label, 'warn'), h('span', '', [x.text])])); });
    }
    var m = modelBlock(modelNames(list)); if (m) kids.push(m);
    if (g.docs && g.docs.length) kids.push(h('div', 'mut sw-docs', ['Further reading: ', h('span', 'mono', [g.docs.join(', ')])]));
    return h('div', 'sw-guide', kids);
  }

  function build() {
    (spec.tags || []).forEach(function (t) {
      var g = t['x-yuzu-guide'];
      if (g) { g.summary = t.description || ''; guides[t.name] = g; }
    });
    Object.keys(spec.paths).forEach(function (p) {
      METHODS.forEach(function (m) {
        var op = spec.paths[p][m];
        if (!op) return;
        var t = (op.tags && op.tags[0]) || 'Untagged';
        ops.push({ method: m, path: p, op: op, tag: t, typed: successSchema(op), unavail: op['x-yuzu-unavailable'] || '', key: m.toUpperCase() + ' ' + p });
      });
    });
    ops.forEach(function (o) { if (tags.indexOf(o.tag) < 0) tags.push(o.tag); });
    tags.sort();

    var typed = ops.filter(function (o) { return o.typed; }).length;
    var unavailable = ops.filter(function (o) { return o.unavail; }).length;
    var q = h('input', 'sw-ctl'); q.type = 'search'; q.id = 'sw-q'; q.placeholder = 'Search path, summary or description'; q.setAttribute('aria-label', 'Search operations');
    var msel = h('select', 'sw-ctl', [h('option', '', ['All methods'])].concat(METHODS.map(function (m) { return h('option', '', [m.toUpperCase()]); }))); msel.id = 'sw-m'; msel.setAttribute('aria-label', 'Method');
    var tsel = h('select', 'sw-ctl', [h('option', '', ['All groups'])].concat(tags.map(function (t) { return h('option', '', [t]); }))); tsel.id = 'sw-t'; tsel.setAttribute('aria-label', 'Group');
    var ysel = h('select', 'sw-ctl', ['Any response schema', 'Typed response', 'Untyped response'].map(function (t) { return h('option', '', [t]); })); ysel.id = 'sw-y'; ysel.setAttribute('aria-label', 'Response schema');
    var count = h('span', 'mut', ['']);

    var summary = h('div', 'sw-chips', [
      h('span', 'chip', ['Operations', h('b', '', [String(ops.length)])]),
      h('span', 'chip', ['Groups', h('b', '', [String(tags.length)])]),
      h('span', 'chip', ['Typed responses', h('b', '', [typed + ' (' + Math.round(100 * typed / ops.length) + '%)'])]),
      unavailable ? h('span', 'chip', ['Unavailable', h('b', '', [String(unavailable)])]) : null,
      h('span', 'chip', ['Auth', h('b', '', ['Bearer token, X-Yuzu-Token, or session cookie'])])
    ]);
    var bar = h('div', 'sw-bar', [q, msel, tsel, ysel, count]);

    var toc = h('nav', 'sw-toc', [h('div', 'sw-toc-h', ['Groups'])]);
    var main = h('div', 'sw-main', []);
    var panels = {}, tocLinks = {};
    tags.forEach(function (t) {
      var id = 'g-' + t.replace(/[^A-Za-z0-9]+/g, '-');
      var list = h('div', 'sw-ops', []);
      var g = guides[t];
      var gbtn = null, gbody = null;
      var allOff = ops.filter(function (o) { return o.tag === t; }).every(function (o) { return o.unavail; });
      var hd = h('div', 'hd', [h('h2', '', [t]), allOff ? pill('unavailable', 'warn') : null, h('span', 'sub', [''])]);
      var sub = hd.lastChild;
      var kids = [hd];
      if (g) {
        gbtn = h('button', 'btn btn-sm sw-gbtn', ['Guide']); gbtn.type = 'button'; gbtn.setAttribute('aria-expanded', 'false');
        hd.appendChild(h('span', 'end', [gbtn]));
        kids.push(h('div', 'sw-gsum', [g.summary || '']));
      }
      kids.push(list);
      var panel = h('section', 'panel', kids); panel.id = id;
      var entry = { panel: panel, list: list, sub: sub, toggleGuide: null };
      if (g) {
        entry.toggleGuide = function (force) {
          var open = force !== undefined ? force : gbtn.getAttribute('aria-expanded') !== 'true';
          gbtn.setAttribute('aria-expanded', open ? 'true' : 'false');
          gbtn.textContent = open ? 'Hide guide' : 'Guide';
          if (open && !gbody) {
            gbody = guideBlock(g, ops.filter(function (o) { return o.tag === t; }));
            panel.insertBefore(gbody, list);
          }
          if (gbody) gbody.hidden = !open;
        };
        gbtn.addEventListener('click', function () { entry.toggleGuide(); });
      }
      panels[t] = entry;
      main.appendChild(panel);
      var a = h('a', '', [t, h('span', 'mut', [''])]); a.href = '#' + id;
      tocLinks[t] = a; toc.appendChild(a);
    });
    var empty = h('div', 'sw-empty', ['No operations match these filters.']); empty.hidden = true; main.appendChild(empty);

    ops.forEach(function (o) {
      var row = h('div', 'sw-op', []);
      var head = h('button', 'sw-op-h', [
        pill(o.method.toUpperCase(), (MPILL[o.method] || 'idle') + ' mono sw-m'), h('span', 'sw-path', [o.path]),
        h('span', 'sw-sum', [o.op.summary || '']), o.unavail ? pill('unavailable', 'warn') : pill(o.typed ? 'typed' : 'untyped', o.typed ? 'ok' : 'idle')
      ]);
      head.type = 'button'; head.setAttribute('aria-expanded', 'false');
      var body = null;
      function toggle(force) {
        var open = force !== undefined ? force : head.getAttribute('aria-expanded') !== 'true';
        head.setAttribute('aria-expanded', open ? 'true' : 'false');
        if (open && !body) { body = detail(o); row.appendChild(body); }
        if (body) body.hidden = !open;
        if (open && force === undefined) { try { history.replaceState(null, '', '#' + encodeURIComponent(o.key)); } catch (e) {} }
      }
      head.addEventListener('click', function () { toggle(); });
      row.appendChild(head);
      o.el = row; o.toggle = toggle;
      panels[o.tag].list.appendChild(row);
    });

    function apply() {
      var needle = st.q.toLowerCase(), shown = 0, per = {};
      ops.forEach(function (o) {
        var ok = (!st.method || o.method === st.method) && (!st.tag || o.tag === st.tag) &&
          (!st.typed || (st.typed === 'typed') === o.typed) &&
          (!needle || (o.path + ' ' + (o.op.summary || '') + ' ' + (o.op.description || '') + ' ' + o.tag).toLowerCase().indexOf(needle) >= 0);
        o.el.hidden = !ok;
        if (ok) { shown++; per[o.tag] = (per[o.tag] || 0) + 1; }
      });
      tags.forEach(function (t) {
        var n = per[t] || 0;
        panels[t].panel.hidden = n === 0;
        panels[t].sub.textContent = n + ' of ' + ops.filter(function (o) { return o.tag === t; }).length + ' operations';
        tocLinks[t].lastChild.textContent = ' ' + n;
        tocLinks[t].hidden = n === 0;
      });
      count.textContent = shown + ' of ' + ops.length + ' operations';
      empty.hidden = shown !== 0;
    }
    q.addEventListener('input', function () { st.q = q.value; apply(); });
    msel.addEventListener('change', function () { st.method = msel.selectedIndex ? METHODS[msel.selectedIndex - 1] : ''; apply(); });
    tsel.addEventListener('change', function () {
      st.tag = tsel.selectedIndex ? tags[tsel.selectedIndex - 1] : ''; apply();
      if (st.tag && panels[st.tag].toggleGuide) panels[st.tag].toggleGuide(true);
    });
    ysel.addEventListener('change', function () { st.typed = ['', 'typed', 'untyped'][ysel.selectedIndex]; apply(); });

    root.textContent = '';
    root.appendChild(summary);
    root.appendChild(bar);
    root.appendChild(h('div', 'sw-grid', [toc, main]));
    apply();

    var hash = decodeURIComponent((location.hash || '').slice(1));
    tags.forEach(function (t) { if (hash === 'g-' + t.replace(/[^A-Za-z0-9]+/g, '-') && panels[t].toggleGuide) { panels[t].toggleGuide(true); panels[t].panel.scrollIntoView(); } });
    ops.forEach(function (o) { if (o.key === hash) { o.toggle(true); o.el.scrollIntoView(); } });
  }

  function fail(msg) {
    root.textContent = '';
    root.appendChild(h('div', 'sw-error', [msg]));
  }
  fetch(SPEC_URL, { credentials: 'same-origin', headers: { Accept: 'application/json' } })
    .then(function (r) {
      if (!r.ok) throw new Error('The API description could not be loaded (HTTP ' + r.status + ').');
      return r.json();
    })
    .then(function (j) { spec = j; build(); })
    .catch(function (e) { fail(e && e.message ? e.message : 'The API description could not be loaded.'); });
})();)SWG";

// Closing tags.
extern const char* const kSwaggerTail = R"SWG(
</script>
</body></html>
)SWG";

namespace {
const std::string kSwaggerTemplate = std::string(kSwaggerHead) + kSwaggerCss + kSwaggerBody +
                                     kSwaggerJs1 + kSwaggerJs2 + kSwaggerTail;
} // namespace

// A page with no nav entry, like Help: the shell carries the title and no active key.
extern const char* const kSwaggerPageHtml =
    yuzu::server::shell::bake(kSwaggerTemplate.c_str(), {.title = "API reference"});
// NOLINTEND(cert-err58-cpp)
