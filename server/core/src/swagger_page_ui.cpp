// API reference page (/swagger): renders the OpenAPI document served at
// GET /api/v1/openapi.json as a searchable, grouped reference, with the guide of each
// group (the document's top-level `tags[].x-yuzu-guide`) above its operations. A page
// shell only: no store, no mutation, no audit trail (page_routes.hpp). The document is
// fetched by the browser with the operator's own session, so the existing
// Infrastructure:Read gate on /api/v1/openapi.json still decides what is readable;
// /swagger takes the same gate so a denied operator gets a 403 instead of a shell that
// cannot load. The renderer builds the DOM with textContent only, because spec text contains
// literal "<plugin>" and similar, which innerHTML would parse as markup.
//
// The page is assembled from named pieces so each raw literal can be measured against
// MSVC's 16,380-byte C2026 cap (docs/cpp-conventions.md); test_swagger_page.cpp keeps
// every piece under 15,000 bytes.
//
// The kSwagger* pieces have external linkage on purpose, like kHelpHtml: there is no header for
// them, test_swagger_page.cpp declares them extern to measure each piece, and page_routes.cpp
// declares kSwaggerPageHtml the same way. They are link-namespace names, not an API: nothing
// else should read them, and a new piece must be added to that test's list. kSwaggerPageHtml
// points into shell::bake()'s static storage, which lives for the process.

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
.sw-unavail .pill{flex:none}
.sw-alt{margin-top:6px;padding-left:10px;border-left:2px solid var(--line)}
.sw-error .btn{margin-top:10px}
.sw-sr{position:absolute;width:1px;height:1px;margin:-1px;padding:0;overflow:hidden;clip:rect(0 0 0 0);white-space:nowrap;border:0})SWG";

// End of <style>, the shell marker, the page header and the opening <script>.
extern const char* const kSwaggerBody = R"SWG(
</style>
</head><body>

  <!--yuzu:shell--><!--/yuzu:shell-->

<div class="sw-page">
  <header class="page-header"><div>
    <h1>API reference</h1>
    <div class="subtitle">Every REST v1 operation this server documents, read live from <code>/api/v1/openapi.json</code>. Agentic workers can read the same document over MCP as <code>yuzu://openapi</code>, without the group guides this page adds. Each group opens with a guide to what it is for, who may call it and what to watch for.</div>
  </div></header>
  <div id="sw-status" class="sw-sr" role="status" aria-live="polite"></div>
  <div id="sw-root" class="mut"><noscript>The API reference needs JavaScript. Turn it on for this site, then reload the page.</noscript></div>
</div>
<div id="toast-container" class="toast-container"></div>
<script>
)SWG";

// Renderer, part 1 of 3 (split at a line boundary).
extern const char* const kSwaggerJs1 = R"SWG((function () {
  'use strict';
  var SPEC_URL = '/api/v1/openapi.json?guides=true';
  var METHODS = ['get', 'post', 'put', 'patch', 'delete'];
  var MPILL = { get: 'ok', post: 'info', put: 'warn', patch: 'warn', 'delete': 'bad' };
  var spec = null, ops = [], tags = [], st = { q: '', method: '', tag: '', typed: '' };
  var root = document.getElementById('sw-root');
  // A polite live region that outlives every re-render of #sw-root, so a screen reader hears
  // that the page is loading, or why it failed. Text nodes only, like the rest of the page.
  var live = document.getElementById('sw-status');
  function say(t) { if (live) live.textContent = t; }

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
  // Own keys only: a schema named "constructor" or "toString" must not resolve to Object.prototype.
  function schemaOf(n) {
    var sc = spec.components && spec.components.schemas;
    return (sc && Object.prototype.hasOwnProperty.call(sc, n) && sc[n]) || {};
  }
  function deref(s, seen) {
    if (!s || !s.$ref) return s || {};
    var n = refName(s.$ref);
    if (seen && seen.indexOf(n) >= 0) return { type: 'object', description: '(recursive: ' + n + ')' };
    return schemaOf(n);
  }
  function label(s) {
    if (!s) return 'any';
    if (s.$ref) return refName(s.$ref);
    if (s.allOf && s.allOf.length === 1) return label(s.allOf[0]) + (s.nullable ? ' | null' : '');
    var t = s.type || (s.properties || s.allOf ? 'object' : s.oneOf ? 'oneOf' : s.anyOf ? 'anyOf' : 'any');
    if (t === 'array') t = label(s.items) + '[]';
    if (s.enum) t = (s.type || 'string') + ' enum';
    return t + (s.nullable ? ' | null' : '');
  }
  function successSchema(op) {
    var found = false, r = op.responses || {};
    Object.keys(r).forEach(function (c) {
      if (/^2/.test(c) && r[c] && r[c].content) {
        Object.keys(r[c].content).forEach(function (m) { if (r[c].content[m].schema) found = true; });
      }
    });
    return found;
  }

  // Breadth budget for one schema block. The depth cap below bounds a chain, not a wide spec
  // edit, and a wide acyclic schema multiplies per level. Measured on the compiled-in
  // document: the largest block has 97 rows, so this cap is about twenty times that.
  var MAX_ROWS = 2000;

  // Schema -> table rows. depth/seen guard against recursion; budget bounds the row count.
  function schemaRows(s, depth, seen, req, out, indent, budget) {
    var base = s.allOf && s.allOf.length === 1 && !s.properties ? s.allOf[0] : s;
    var n = base.$ref ? refName(base.$ref) : null;
    var nseen = n ? (seen || []).concat([n]) : seen;
    var d = flat(deref(base, seen), nseen, 0, { n: 0 });
    if (d.xCut) budget.skipped++;
    if (d.type === 'array' && d.items) { return schemaRows(d.items, depth, nseen, req, out, indent, budget); }
    var props = d.properties || {};
    var required = d.required || [];
    Object.keys(props).forEach(function (k) {
      if (budget.rows >= MAX_ROWS) { budget.skipped++; return; }
      budget.rows++;
      var p = props[k], pd = deref(p, nseen);
      var tr = h('tr', '', [
        h('td', 'sw-name', [h('span', 'sw-indent', [new Array(indent + 1).join('   ')]), mono(k)]),
        h('td', '', [pill(label(p), 'idle mono')]),
        h('td', '', [required.indexOf(k) >= 0 ? pill('required', 'ok') : pill('optional', 'idle')]),
        h('td', 'sw-desc', [pd.description || p.description || '', pd.enum ? h('div', 'sw-enum', pd.enum.map(function (v) { return h('code', '', [String(v)]); })) : null])
      ]);
      out.push(tr);
      var inner = p.items ? p.items : p;
      var innerD = depth < 5 ? flat(deref(inner, nseen), nseen, 0, { n: 0 }) : {};
      if (depth < 5 && (innerD.properties || (innerD.type === 'array' && innerD.items))) {
        schemaRows(inner, depth + 1, nseen, false, out, indent + 1, budget);
      }
    });
    return out;
  }
  // seen carries the schema names already open above this block, so a schema that reaches
  // itself through oneOf/anyOf stops at a note instead of recursing forever.
  function schemaBlock(s, seen, budget) {
    if (budget) return schemaBlockIn(s, seen || [], budget);
    budget = { rows: 0, skipped: 0 };
    var blk = schemaBlockIn(s, seen || [], budget);
    if (budget.skipped) blk.appendChild(h('div', 'sw-untyped', ['Truncated: at least ' + budget.skipped + ' more fields or options are not shown.']));
    return blk;
  }
  function schemaBlockIn(s, seen, budget) {
    var inner = s.allOf && s.allOf.length === 1 ? s.allOf[0] : s;
    var n = inner.$ref ? refName(inner.$ref) : null;
    if (n && seen.indexOf(n) >= 0) return h('div', 'sw-untyped', ['(recursive: ' + n + ')']);
    var nseen = n ? seen.concat([n]) : seen;
    var d = flat(deref(inner), seen, 0, { n: 0 });
    var alts = d.oneOf || d.anyOf;
    if (alts && alts.length) {
      if (d.xCut && !d.properties) budget.skipped++;
      var akids = [h('div', 'sw-schema-head', [pill(d.oneOf ? 'one of' : 'any of', 'info mono'), d.description ? h('span', 'mut', [d.description]) : null])];
      // Properties declared beside the alternatives apply to every option; show them first.
      var shared = d.properties ? schemaRows(s, 0, seen, false, [], 0, budget) : [];
      if (shared.length) akids.push(tableWrap(shared));
      alts.forEach(function (a, i) {
        if (budget.rows >= MAX_ROWS) { budget.skipped++; return; }
        budget.rows++;
        akids.push(h('div', 'sw-alt', [h('h3', '', ['Option ' + (i + 1)]), schemaBlockIn(a, nseen, budget)]));
      });
      return h('div', '', akids);
    }
    var head = h('div', 'sw-schema-head', [pill(label(s), 'info mono'), d.description ? h('span', 'mut', [d.description]) : null]);
    var rows = schemaRows(s, 0, seen, false, [], 0, budget);
    if (!rows.length) return h('div', '', [head]);
    return h('div', '', [head, tableWrap(rows)]);
  }
  function tableWrap(rows) {
    var table = h('table', '', [
      h('thead', '', [h('tr', '', ['Property', 'Type', '', 'Description'].map(function (t) { return h('th', '', [t]); }))]),
      h('tbody', '', rows)
    ]);
    return h('div', 'tw sw-tw', [table]);
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
    r = r || {};
    var cls = /^2/.test(code) ? 'ok' : /^4/.test(code) ? 'warn' : /^5/.test(code) ? 'bad' : 'idle';
    var kids = [h('div', 'sw-resp-head', [pill(code, cls + ' mono'), h('span', 'sw-desc', [r.description || ''])])];
    if (r.headers) {
      kids.push(h('div', 'sw-hdrs', Object.keys(r.headers).map(function (k) {
        return h('div', '', [mono(k), ' ', h('span', 'mut', [hdrOf(r.headers[k]).description || ''])]);
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
    var base = o.path.indexOf('/v2/') === 0 ? '/api' : '/api/v1'; // the only v2 route is keyed /v2/... and served at /api/v2/...
    var mth = o.method.toUpperCase(), sends = mth === 'POST' || mth === 'PUT' || mth === 'PATCH';
    // -g: curl's URL globbing would rewrite the braces of a path parameter.
    var curl = 'curl -s -g -X ' + mth + ' \\\n  -H "Authorization: Bearer $YUZU_TOKEN" \\\n' +
      (sends ? '  -H "Content-Type: application/json" \\\n  -d \'{}\' \\\n' : '') + '  "' + location.origin + base + o.path + '"';
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
  // Name-keyed maps have no prototype, so a tag or schema named "constructor" or "__proto__"
  // is an ordinary key.
  function dict() { return Object.create(null); }
  var guides = dict();
  var SKIP_MODEL = dict();
  ['ApiMeta', 'ApiPagination', 'A4ErrorEnvelope', 'ApiEnvelope'].forEach(function (n) { SKIP_MODEL[n] = 1; });
  var MODEL_CAP = 60;
  function collectRefs(node, acc) {
    if (!node || typeof node !== 'object') return;
    if (Array.isArray(node)) { node.forEach(function (n) { collectRefs(n, acc); }); return; }
    if (node.$ref) { acc[refName(node.$ref)] = 1; return; }
    Object.keys(node).forEach(function (k) { collectRefs(node[k], acc); });
  }
  function modelNames(list) {
    var seen = dict(), queue = dict(), order = [];
    list.forEach(function (o) { collectRefs(o.op.responses, queue); collectRefs(o.op.requestBody, queue); });
    var names = Object.keys(queue);
    while (names.length && order.length < MODEL_CAP) {
      var n = names.shift();
      if (seen[n] || SKIP_MODEL[n]) continue;
      seen[n] = 1; order.push(n);
      var sub = dict(); collectRefs(schemaOf(n), sub);
      Object.keys(sub).forEach(function (m) { if (!seen[m]) names.push(m); });
    }
    order.cut = names.some(function (m) { return !seen[m] && !SKIP_MODEL[m]; });
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
    if (names.cut) kids.push(h('p', 'mut sw-cap', ['Only the first ' + MODEL_CAP + ' models are listed.']));
    names.forEach(function (n) {
      var body = null;
      var btn = h('button', 'sw-model-h', [pill(n, 'info mono'), h('span', 'mut', ['Show fields'])]);
      btn.type = 'button'; btn.setAttribute('aria-expanded', 'false');
      var wrap = h('div', 'sw-model', [btn]);
      btn.addEventListener('click', function () {
        var open = btn.getAttribute('aria-expanded') !== 'true';
        // Build first, then flip the state, so a schema that cannot be drawn never leaves a
        // Hide button above an empty body.
        if (open && !body) {
          try { body = schemaBlock({ $ref: '#/components/schemas/' + n }); }
          catch (e) { note('model ' + n, e); body = h('div', 'sw-error', ['These fields could not be shown.']); }
          wrap.appendChild(body);
        }
        btn.setAttribute('aria-expanded', open ? 'true' : 'false');
        btn.lastChild.textContent = open ? 'Hide fields' : 'Show fields';
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
    ops = []; tags = []; guides = dict(); st = { q: '', method: '', tag: '', typed: '' };
)SWG";

// Renderer, part 2 of 3.
extern const char* const kSwaggerJs2 = R"SWG(    // A malformed entry (a null tag, a guide that is not an object, a null path item) is
    // skipped, not allowed to take the whole page down.
    (Array.isArray(spec.tags) ? spec.tags : []).forEach(function (t) {
      if (!isObj(t) || typeof t.name !== 'string') return;
      var g = t['x-yuzu-guide'];
      if (isObj(g)) { g.summary = t.description || ''; guides[t.name] = g; }
    });
    var paths = isObj(spec.paths) ? spec.paths : {};
    Object.keys(paths).forEach(function (p) {
      if (!isObj(paths[p])) return;
      METHODS.forEach(function (m) {
        var op = paths[p][m];
        if (!isObj(op)) return;
        var t = (Array.isArray(op.tags) && typeof op.tags[0] === 'string' && op.tags[0]) || 'Untagged';
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
    var count = h('span', 'mut', ['']); count.id = 'sw-count'; // read by the filters; announced by announce(), not live itself

    var summary = h('div', 'sw-chips', [
      h('span', 'chip', ['Operations', h('b', '', [String(ops.length)])]),
      h('span', 'chip', ['Groups', h('b', '', [String(tags.length)])]),
      h('span', 'chip', ['Typed responses', h('b', '', [typed + ' (' + (ops.length ? Math.round(100 * typed / ops.length) : 0) + '%)'])]),
      unavailable ? h('span', 'chip', ['Unavailable', h('b', '', [String(unavailable)])]) : null,
      h('span', 'chip', ['Auth', h('b', '', ['Bearer token, X-Yuzu-Token, or session cookie'])])
    ]);
    var bar = h('div', 'sw-bar', [q, msel, tsel, ysel, count]);

    var toc = h('nav', 'sw-toc', [h('div', 'sw-toc-h', ['Groups'])]);
    var main = h('div', 'sw-main', []);
    var panels = dict(), tocLinks = dict();
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
          if (open && !gbody) {
            try { gbody = guideBlock(g, ops.filter(function (o) { return o.tag === t; })); }
            catch (e) { note('guide ' + t, e); gbody = h('div', 'sw-guide', [h('div', 'sw-error', ['This guide could not be shown.'])]); }
            panel.insertBefore(gbody, list);
          }
          gbtn.setAttribute('aria-expanded', open ? 'true' : 'false');
          gbtn.textContent = open ? 'Hide guide' : 'Guide';
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
        if (open && !body) {
          try { body = detail(o); } catch (e) { note('operation ' + o.key, e); body = h('div', 'sw-detail', [h('div', 'sw-error', ['This operation could not be shown.'])]); }
          row.appendChild(body);
        }
        head.setAttribute('aria-expanded', open ? 'true' : 'false');
        if (body) body.hidden = !open;
        if (open && force === undefined) { try { history.replaceState(null, '', '#' + encodeURIComponent(o.key)); } catch (e) {} }
      }
      head.addEventListener('click', function () { toggle(); });
      row.appendChild(head);
      o.el = row; o.toggle = toggle;
      panels[o.tag].list.appendChild(row);
    });

    function apply() {
      var needle = st.q.toLowerCase(), shown = 0, per = dict();
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
    // The count updates on every keystroke; a screen reader hears it once, when typing pauses.
    var said = null;
    function announce() { clearTimeout(said); said = setTimeout(function () { say(count.textContent); }, 500); }
    q.addEventListener('input', function () { st.q = q.value; apply(); announce(); });
    msel.addEventListener('change', function () { st.method = msel.selectedIndex ? METHODS[msel.selectedIndex - 1] : ''; apply(); announce(); });
    tsel.addEventListener('change', function () {
      st.tag = tsel.selectedIndex ? tags[tsel.selectedIndex - 1] : ''; apply(); announce();
      if (st.tag && panels[st.tag].toggleGuide) panels[st.tag].toggleGuide(true);
    });
    ysel.addEventListener('change', function () { st.typed = ['', 'typed', 'untyped'][ysel.selectedIndex]; apply(); announce(); });

    root.textContent = '';
    say('');
    root.appendChild(summary);
    root.appendChild(bar);
    root.appendChild(h('div', 'sw-grid', [toc, main]));
    apply();

    var hash = '';
    try { hash = decodeURIComponent((location.hash || '').slice(1)); } catch (e) { /* a malformed fragment selects nothing */ }
    tags.forEach(function (t) { if (hash === 'g-' + t.replace(/[^A-Za-z0-9]+/g, '-') && panels[t].toggleGuide) { panels[t].toggleGuide(true); panels[t].panel.scrollIntoView(); } });
    ops.forEach(function (o) { if (o.key === hash) { o.toggle(true); o.el.scrollIntoView(); } });
  }

  function fail(msg, status, cid, hint) {
    root.textContent = '';
    var box = h('div', 'sw-error', [h('div', '', [msg])]);
    var said = [msg];
    function note(t, cls) { box.appendChild(h('div', cls, [t])); said.push(t); }
    if (hint) note(hint, 'mut');
    if (status === 401) note('Your session may have ended. Sign in again, then reload this page.', 'mut');
    if (status === 403) note('The API description needs the Infrastructure:Read permission. If your account holds it, the permission check itself could not be completed: reload to retry.', 'mut');
    if (cid) note('Correlation id: ' + cid, 'mut mono');
    say(said.join(' '));
    var retry = h('button', 'btn btn-sm', ['Retry']);
    retry.type = 'button';
    retry.addEventListener('click', load);
    box.appendChild(retry);
    root.appendChild(box);
  }
  // An error whose text is safe to show. Anything else that reaches the catch below (a
  // SyntaxError from a non-JSON body, a TypeError from a bad spec) is logged to the console and
  // replaced by a fixed message, so the operator never reads "Unexpected token '<'".
  function problem(msg, extra) {
    var e = new Error(msg);
    e.friendly = true;
    if (extra) Object.keys(extra).forEach(function (k) { e[k] = extra[k]; });
    return e;
  }
  // The A4 body carries the correlation id; the X-Correlation-Id header is the fallback for a
  // failure whose body is not JSON (a proxy page, for example).
  function headerCid(r) {
    try { return (r.headers && r.headers.get('X-Correlation-Id')) || ''; } catch (e) { return ''; }
  }
  // Logged with what could not be drawn, since the page shows only a fixed line.
  function note(what, e) { try { console.error('API reference page: could not draw ' + what, e); } catch (x) { /* no console */ } }
  // A plain object, not null and not an array: the one test build() and load() share.
  function isObj(x) { return !!x && typeof x === 'object' && !Array.isArray(x); }
  // A response header is inline or a $ref into components.headers; own keys only.
  function hdrOf(x) {
    if (!x || typeof x.$ref !== 'string') return x || {};
    var c = spec.components && spec.components.headers, n = refName(x.$ref);
    return (c && Object.prototype.hasOwnProperty.call(c, n) && c[n]) || {};
  }
  function load() {
    root.textContent = 'Loading the API description...';
    say('Loading the API description...');
    var ctl = typeof AbortController === 'function' ? new AbortController() : null;
    var timer = setTimeout(function () { if (ctl) ctl.abort(); }, 30000);
    var opts = { credentials: 'same-origin', headers: { Accept: 'application/json' } };
    if (ctl) opts.signal = ctl.signal;
    fetch(SPEC_URL, opts)
      .then(function (r) {
        // The timer stays armed until the body is read, so a stalled body also reaches Retry.
        if (r.ok) {
          return r.json().catch(function (x) {
            if (x && x.name === 'AbortError') throw x;
            throw problem('The server answered, but not with an API description.',
              { hint: 'Your session may have expired. Sign in again, then reload this page.', cid: headerCid(r), raw: x });
          });
        }
        return r.json().then(function (j) { return j; }, function () { return null; }).then(function (j) {
          throw problem('The API description could not be loaded (HTTP ' + r.status + ').',
            { status: r.status, cid: (j && j.error && j.error.correlation_id) || headerCid(r) });
        });
      }, function (x) {
        if (x && x.name === 'AbortError') throw x;
        throw problem('The API description could not be reached. Check the network connection, then retry.', { raw: x });
      })
      .then(function (j) {
        clearTimeout(timer);
        if (!isObj(j) || !isObj(j.paths)) throw problem('The server answered, but not with an API description.');
        spec = j;
        try { build(); } catch (x) { throw problem('The API description was loaded but could not be shown.', { raw: x }); }
      })
      .catch(function (e) {
        clearTimeout(timer);
        try { console.error('API reference page:', e && e.raw ? e.raw : e); } catch (x) { /* no console */ }
        var msg = e && e.name === 'AbortError' ? 'The API description took too long to load.' : (e && e.friendly ? e.message : 'The API description could not be loaded.');
        fail(msg, e && e.status, e && e.cid, e && e.hint);
      });
  }
  load();
)SWG";

// Renderer, part 3 of 3: the schema flattening, kept apart so no piece nears the size gate.
extern const char* const kSwaggerJs3 = R"SWG(  // allOf -> one schema (in this piece to keep the first under the size gate; declarations
  // hoist). Members are followed through $ref; properties and required merge in order, the
  // first definition wins and a later one only fills a missing description or format; type,
  // description, oneOf, anyOf, items and enum come from the first member having one. seen
  // stops a cycle, b.n bounds total expansions, and anything cut sets xCut (shown as
  // truncated). A member open in an ancestor adds nothing.
  function flat(s, seen, depth, b) {
    if (!s || !s.allOf) return s || {};
    var out = {}, props = Object.create(null), req = (s.required || []).slice();
    Object.keys(s).forEach(function (k) { if (k !== 'allOf') out[k] = s[k]; });
    delete out.xCut;
    Object.keys(s.properties || {}).forEach(function (k) { props[k] = s.properties[k]; });
    if (!Array.isArray(s.allOf) || depth >= 8) out.xCut = true;
    else s.allOf.forEach(function (m) {
      var n = m && m.$ref ? refName(m.$ref) : null;
      if (n && seen && seen.indexOf(n) >= 0) return;
      if (++b.n > 200) { out.xCut = true; return; }
      var f = flat(deref(m, seen), n ? (seen || []).concat([n]) : seen, depth + 1, b);
      if (f.xCut) out.xCut = true;
      Object.keys(f.properties || {}).forEach(function (k) {
        var e = props[k], x = f.properties[k];
        if (!(k in props)) props[k] = x;
        else if (e && x && ((!e.description && x.description) || (!e.format && x.format))) {
          props[k] = Object.assign({}, e, { description: e.description || x.description, format: e.format || x.format });
        }
      });
      (f.required || []).forEach(function (k) { if (req.indexOf(k) < 0) req.push(k); });
      ['type', 'description', 'oneOf', 'anyOf', 'items', 'enum'].forEach(function (k) {
        if (f[k] === undefined) return;
        if (out[k] === undefined) out[k] = f[k];
        else if ((k === 'oneOf' || k === 'anyOf') && out[k] !== f[k]) out.xCut = true;
      });
    });
    if (Object.keys(props).length) out.properties = props;
    if (req.length) out.required = req;
    return out;
  }
})();)SWG";

// Closing tags.
extern const char* const kSwaggerTail = R"SWG(
</script>
</body></html>
)SWG";

namespace {
const std::string kSwaggerTemplate = std::string(kSwaggerHead) + kSwaggerCss + kSwaggerBody +
                                     kSwaggerJs1 + kSwaggerJs2 + kSwaggerJs3 + kSwaggerTail;
} // namespace

// A page with no nav entry, like Help: the shell carries the title and no active key.
extern const char* const kSwaggerPageHtml =
    yuzu::server::shell::bake(kSwaggerTemplate.c_str(), {.title = "API reference"});
// NOLINTEND(cert-err58-cpp)
