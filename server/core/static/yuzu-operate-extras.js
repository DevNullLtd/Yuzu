/* yuzu-operate-extras.js: page controllers for the Operate extras (Dashboard,
   Result sets). One controller per page, keyed on document.body.dataset.page.

   Rules this file keeps (pinned by test_operate_extras_ui.cpp):
   - server data reaches the DOM through textContent only: no markup sinks and
     no dynamic code evaluation;
   - every request is same-origin and bounded by a 15 s timeout;
   - every fan-out or destructive action goes through oxConfirm first, because
     none of the routes it calls carries a step-up. */
(function () {
  'use strict';

  var body = document.body;
  var page = body && body.dataset ? body.dataset.page : '';

  function $(id) { return document.getElementById(id); }

  function el(tag, cls, text) {
    var n = document.createElement(tag);
    if (cls) n.className = cls;
    if (text !== undefined && text !== null) n.textContent = String(text);
    return n;
  }

  function clear(n) { while (n.firstChild) n.removeChild(n.firstChild); }

  /* Same-origin JSON call that never rejects: {status, ok, data}. Status 0 means
     the network or the 15 s timeout failed, which is "may not have applied". The
     shared helper also runs the MFA step-up prompt and the 401-to-login redirect. */
  function api(method, url, json) {
    return window.YuzuDialog.request(method, url, json === undefined ? {} : { json: json });
  }

  /* A4 envelope {error:{message}} or the legacy {error:"..."}. */
  function errText(d, fallback) {
    if (d && d.error) {
      if (typeof d.error === 'string') return d.error;
      if (typeof d.error.message === 'string' && d.error.message) return d.error.message;
    }
    return fallback;
  }

  /* grant_secret and grant_id are redacted at persistence by the server; the
     same keys are masked here wherever typed text is echoed back. */
  var SECRET_RE = /\b(grant_secret|grant_id)=("[^"]*"|'[^']*'|\S+)/gi;
  function maskSecrets(s) { return String(s).replace(SECRET_RE, '$1=•••'); }

  /* Confirm through the shared dialog. title, paragraphs[], facts[[k,v]], pre (a
     bounded verbatim block), confirmLabel, danger. Resolves true only on the
     confirm button; Esc and Cancel resolve false, and so does a second dialog
     while one is open ('dialog busy'). */
  function oxConfirm(o) {
    var b = el('div');
    b.style.display = 'contents';
    (o.paragraphs || []).forEach(function (p) { b.appendChild(el('p', null, p)); });
    if (o.facts && o.facts.length) {
      var dl = el('dl', 'ox-facts');
      o.facts.forEach(function (kv) {
        var row = el('div');
        row.appendChild(el('dt', null, kv[0]));
        row.appendChild(el('dd', null, kv[1]));
        dl.appendChild(row);
      });
      b.appendChild(dl);
    }
    if (o.pre) b.appendChild(el('pre', 'ox-sql', o.pre));
    return window.YuzuDialog.confirm({
      title: o.title, body: b, danger: !!o.danger,
      confirmLabel: o.confirmLabel, cancelLabel: o.cancelLabel
    }).catch(function () { return false; });
  }

  
  /* ---------------------------------------------------------------------- */
  /* Dashboard                                                              */
  /* ---------------------------------------------------------------------- */
  function dashboard() {
    var PREVIEW_IDS = 25;
    var exprIn = $('ox-expr');
    var btnValidate = $('ox-validate');
    var btnPreview = $('ox-preview');
    var out = $('ox-expr-out');
    var kinds = $('ox-kinds');
    var kindsList = $('ox-kinds-list');
    var btnTar = $('ox-tar-open');

    function setContext(msg, isError) {
      var c = $('result-context');
      if (!c) return;
      c.textContent = msg;
      c.className = 'result-context' + (isError ? ' is-error' : '');
    }

    function note(kind, text) {
      clear(out);
      out.appendChild(el('div', 'ox-note ' + (kind || ''), text));
      return out;
    }

    /* The picker selection is what Send and Run on TAR history consume. */
    function pickerItem() { return document.querySelector('.scope-item.selected'); }
    function pickerScope() {
      var it = pickerItem();
      return (it && (it.getAttribute('data-scope') || it.getAttribute('data-agent-id'))) || '__all__';
    }
    function sendTarget() {
      var scope = pickerScope();
      var it = pickerItem();
      var nameEl = it && it.querySelector('.scope-item-name');
      var metaEl = it && it.querySelector('.scope-item-meta');
      var t = { scope: scope, single: false, label: scope, count: '' };
      if (scope === '__all__') {
        t.label = 'All agents';
        var cnt = $('agent-count');
        t.count = cnt ? cnt.textContent.trim() : '';
      } else if (scope.indexOf('group:') === 0) {
        t.label = 'Group ' + (nameEl ? nameEl.textContent.trim() : scope.slice(6));
        var m = metaEl ? /^(\d+)\s+agents?/.exec(metaEl.textContent.trim()) : null;
        t.count = m ? m[1] + (m[1] === '1' ? ' agent' : ' agents') : '';
      } else {
        t.single = true;
        t.label = 'Agent ' + (nameEl ? nameEl.textContent.trim() : scope);
        t.count = '1 agent';
      }
      return t;
    }

    /* E-1: a non-empty expression IS the Send target. Choosing it disables and omits
       scope-input (the route answers 400 target_conflict when both arrive, S8) and
       enables the scope_expression field. previewed is the expression whose Preview
       succeeded in this page state, with its match count (rule 8). */
    var exprField = $('ox-scope-expression');
    var scopeField = $('scope-input');
    var previewed = null;
    function exprValue() { return exprIn ? exprIn.value.trim() : ''; }
    function syncTarget() {
      var e = exprValue();
      if (exprField) { exprField.value = e; exprField.disabled = !e; }
      if (scopeField) scopeField.disabled = !!e;
      if (previewed && previewed.expression !== e) previewed = null;
    }
    function syncButtons() {
      var empty = !exprValue();
      if (btnValidate) btnValidate.disabled = empty;
      if (btnPreview) btnPreview.disabled = empty;
      syncTarget();
    }

    /* ---- Validate: syntax only, never "will match" ---- */
    function validate() {
      var expression = exprIn.value.trim();
      if (!expression) return;
      btnValidate.disabled = true;
      note('', 'Checking…');
      api('POST', '/api/v1/scope/validate', { expression: expression }).then(function (r) {
        syncButtons();
        var d = r.data && r.data.data;
        if (r.status === 200 && d && d.valid === true) {
          note('ok', 'Syntax is valid. Unknown attributes are refused on Send.');
        } else if (r.status === 200 && d && d.valid === false) {
          note('bad', String(d.error || 'The expression is not valid.'));
        } else if (r.status === 0) {
          note('warn', 'Could not reach the server. Nothing was checked.');
        } else {
          note('bad', errText(r.data, 'The expression could not be checked.'));
        }
      });
    }

    /* ---- Preview: matched_count and a bounded id list. The route's own
       caution string promises an approval rule that does not exist, so that
       field is never read or rendered. ---- */
    function preview() {
      var expression = exprIn.value.trim();
      if (!expression) return;
      btnPreview.disabled = true;
      note('', 'Previewing…');
      api('POST', '/api/v1/scope/preview', { expression: expression }).then(function (r) {
        syncButtons();
        var d = r.data && r.data.data;
        if (r.status === 200 && d) {
          var n = Number(d.matched_count) || 0;
          previewed = { expression: expression, count: n };
          if (n === 0) { note('', 'No devices match.'); return; }
          clear(out);
          out.appendChild(el('div', 'ox-note ok', n + (n === 1 ? ' device matches' : ' devices match')));
          var ids = Array.isArray(d.matched_agents) ? d.matched_agents : [];
          var ul = el('ul', 'ox-ids');
          ids.slice(0, PREVIEW_IDS).forEach(function (id) { ul.appendChild(el('li', null, id)); });
          out.appendChild(ul);
          if (n > PREVIEW_IDS) out.appendChild(el('div', 'ox-hint', 'and ' + (n - PREVIEW_IDS) + ' more'));
        } else if (r.status === 404) {
          note('bad', 'That result set was not found, or is not yours.');
        } else if (r.status === 403) {
          note('warn', 'Previewing a scope needs the Infrastructure read permission.');
        } else if (r.status === 503) {
          note('warn', 'Preview unavailable. This is not zero matches. Retry shortly.');
        } else if (r.status === 0) {
          note('warn', 'Could not reach the server. This is not zero matches.');
        } else {
          note('bad', errText(r.data, 'The preview failed.'));
        }
      });
    }

    if (exprIn) {
      exprIn.addEventListener('input', syncButtons);
      exprIn.addEventListener('keydown', function (e) {
        if (e.key === 'Enter') { e.preventDefault(); if (!btnPreview.disabled) preview(); }
      });
      btnValidate.addEventListener('click', validate);
      btnPreview.addEventListener('click', preview);
      syncButtons();
    }

    /* ---- Scope kinds: loaded once, on first open, so a page view that
       never opens the panel costs no request (and no denied-audit row for a
       role without Infrastructure:Read). Rendered from fetched JSON with
       textContent. ---- */
    var kindsLoaded = false;
    function renderKinds(doc) {
      clear(kindsList);
      var groups = [['Targets', doc.ground_kinds], ['Attributes', doc.attribute_kinds]];
      groups.forEach(function (g) {
        if (!Array.isArray(g[1])) return;
        var h = el('li', 'ox-hint', g[0]);
        kindsList.appendChild(h);
        g[1].forEach(function (k) {
          var li = el('li');
          li.appendChild(el('code', null, k.syntax || k.kind || ''));
          li.appendChild(el('span', null, k.description || ''));
          kindsList.appendChild(li);
        });
      });
      var foot = el('li', 'ox-hint',
        'group: takes a group id here, not a name; the picker below emits the id.');
      kindsList.appendChild(foot);
    }
    function loadKinds() {
      if (kindsLoaded) return;
      kindsLoaded = true;
      clear(kindsList);
      kindsList.appendChild(el('li', 'ox-hint', 'Loading…'));
      api('GET', '/api/v1/discover/scope-kinds').then(function (r) {
        if (r.status === 200 && r.data) { renderKinds(r.data); return; }
        kindsLoaded = false; /* let a later open retry */
        clear(kindsList);
        var msg = r.status === 403
          ? 'Listing scope kinds needs the Infrastructure read permission.'
          : 'Scope kinds are unavailable. This is not an empty list.';
        kindsList.appendChild(el('li', 'ox-hint', msg));
      });
    }
    if (kinds) kinds.addEventListener('toggle', function () { if (kinds.open) loadKinds(); });

    /* ---- Fan-out confirm (Q6): any target that is not one agent. htmx holds
       the request at htmx:confirm; issueRequest(true) releases it. A
       programmatic replay (the MFA step-up path) has no triggering event and
       was already confirmed once, so it is not asked again. ---- */
    body.addEventListener('htmx:confirm', function (evt) {
      var d = evt.detail;
      if (!d || !d.elt || d.elt.id !== 'instr-form' || !d.triggeringEvent) return;
      var input = $('instr-input');
      var cmd = input ? input.value.trim() : '';
      if (!cmd || /^help(\s|$)/i.test(cmd)) return;
      var expr = exprValue();
      var t = expr ? { scope: '', single: false, label: 'Expression: ' + expr, count: '' } : sendTarget();
      if (t.single) return;
      evt.preventDefault();
      var facts = [['Command', maskSecrets(cmd)], ['Target', t.label]];
      if (expr) {
        /* Rule 8: a Preview of this same expression gives a count; without one the
           operator retypes the expression, since the count (and a typo) is unseen. */
        if (previewed && previewed.expression === expr) {
          facts.push(['Reaches', previewed.count + (previewed.count === 1 ? ' device' : ' devices')]);
        } else {
          window.YuzuDialog.form({
            title: 'Send to an unpreviewed expression?',
            body: ['This sends the command to every device the expression matches. The match ' +
                   'count is unknown because the expression was not previewed.',
                   'Command: ' + maskSecrets(cmd), 'Retype the expression to confirm.'],
            fields: [{ name: 'typed', label: 'Expression', type: 'text', required: true,
                       maxlength: 8192 }],
            submitLabel: 'Send',
            danger: true,
            validate: function (v) {
              return v.typed.trim() === expr ? null : 'That does not match the expression.';
            }
          }).then(function (v) { if (v) d.issueRequest(true); }, function () { /* dialog busy */ });
          return;
        }
      } else if (t.count) {
        facts.push(['Reaches', t.count]);
      }
      oxConfirm({
        title: 'Send to more than one agent?',
        paragraphs: ['This sends the command to every agent in the target below.'],
        facts: facts,
        confirmLabel: 'Send'
      }).then(function (ok) { if (ok) d.issueRequest(true); });
    });

    /* ---- History: the Console's History panel has had no caller since the
       HTMX refactor (e39654155); feed it from a completed send, masked. ---- */
    var form = $('instr-form');
    if (form) {
      form.addEventListener('htmx:afterRequest', function (evt) {
        if (evt.target !== form || !evt.detail || !evt.detail.successful) return;
        var input = $('instr-input');
        var cmd = input ? input.value.trim() : '';
        if (!cmd || typeof window.addHistory !== 'function') return;
        window.addHistory(maskSecrets(cmd), exprValue() ? 'Expression: ' + exprValue() : sendTarget().label);
      });
    }

    /* ---- H-16: htmx drops a 4xx body, so a 403 from Send or Run on TAR
       history used to do nothing at all. Say why in the context line. ---- */
    body.addEventListener('htmx:responseError', function (evt) {
      var d = evt.detail;
      var x = d && d.xhr;
      if (!x) return;
      var path = (d.pathInfo && d.pathInfo.requestPath) ||
                 (d.requestConfig && d.requestConfig.path) || '';
      if (path.indexOf('/api/dashboard/execute') !== 0 &&
          path.indexOf('/api/dashboard/tar-execute') !== 0) return;
      if (x.status === 403) {
        setContext('Your role may not run instructions. Ask an administrator for the Execution permission.', true);
      } else if (x.status === 400 && path.indexOf('/api/dashboard/execute') === 0) {
        /* The route's refusal reason rides in an OOB span; read its text, never its markup. */
        var msg = '';
        try {
          var span = new DOMParser().parseFromString(x.responseText || '', 'text/html')
            .querySelector('[data-reason]');
          msg = span ? span.textContent : '';
        } catch (e) { msg = ''; }
        setContext(msg || 'The request was refused. Nothing was sent.', true);
      }
    });

    /* ---- Run on TAR history (D9): form, then a confirm that shows the SQL. ---- */
    function runTar(sql, scope) {
      if (!window.htmx) return;
      window.htmx.ajax('POST', '/api/dashboard/tar-execute',
        { values: { sql: sql, scope: scope }, swap: 'none', target: '#result-context' });
    }

    function openTarForm() {
      var t = sendTarget();
      window.YuzuDialog.form({
        title: 'Run on TAR history',
        body: ['Target: ' + t.label + (t.count ? ' (' + t.count + ')' : '') +
               '. Results appear in the Results table; no result set is saved.',
               'Up to 4096 characters. The server refuses any text containing INSERT, UPDATE, ' +
               'DELETE, DROP, ALTER, CREATE, ATTACH, DETACH, PRAGMA or LOAD_EXTENSION, even ' +
               'inside a name such as updated_at or created_by.'],
        fields: [{ name: 'sql', label: 'SQL (SELECT only)', type: 'textarea', rows: 6,
                   maxlength: 4096, required: true,
                   placeholder: "SELECT name, pid FROM process_live WHERE name = 'chrome.exe'" }],
        submitLabel: 'Review'
      }).then(function (v) {
        if (!v) return;
        var sql = v.sql.trim();
        var shown = sql.length > 200 ? sql.slice(0, 200) + '… (' + sql.length + ' characters)' : sql;
        return oxConfirm({
          title: 'Run this query?',
          paragraphs: ['Queries every device in this scope. The text below is exactly what is sent.'],
          facts: [['Target', t.label]].concat(t.count ? [['Reaches', t.count]] : []),
          pre: shown,
          confirmLabel: 'Run query',
          danger: true
        }).then(function (go) { if (go) runTar(sql, t.scope); });
      }, function () { /* dialog busy */ });
    }
    if (btnTar) btnTar.addEventListener('click', openTarForm);
  }

  /* ---------------------------------------------------------------------- */
  /* Result sets                                                            */
  /* ---------------------------------------------------------------------- */
  function resultSets() {
    var out = $('ox-rs-out');
    var busy = false;

    function say(kind, text) {
      clear(out);
      if (text) out.appendChild(el('div', 'ox-note ' + (kind || ''), text));
    }
    function refresh() {
      if (window.htmx) window.htmx.trigger(body, 'resultSetsChanged');
    }

    /* Route errors, SPEC 5.4. The 500 after dispatch is the one that must not be re-sent. */
    function failText(r) {
      var m = errText(r.data, '');
      if (r.status === 0) return 'The request may not have applied. Check the list before retrying.';
      if (r.status === 500 && /FAULT_AFTER_DISPATCH/.test(m)) {
        return 'The command was sent but the result set was not saved. Do not send it again; ' +
               'check the Executions page.';
      }
      if (r.status === 403) return 'Your role may not do this. Ask an administrator for the permission.';
      if (r.status === 429) return m || 'You have reached the result set limit. Delete one first.';
      return m || 'The request failed. Nothing was created.';
    }

    /* Run one producer call: dialogs finished, show the outcome, reload the list. */
    function send(url, json, what) {
      if (busy) return Promise.resolve();
      busy = true;
      say('', 'Sending...');
      return api('POST', url, json).then(function (r) {
        busy = false;
        if (r.ok) {
          var d = r.data && r.data.data;
          say('ok', what + ' ' + (r.status === 202 ? 'started' : 'created') +
              (d && d.name ? ': ' + d.name : '') + '.' +
              (r.status === 202 ? ' It stays Pending until devices respond.' : ''));
          refresh();
        } else {
          say('bad', failText(r));
        }
      });
    }

    /* The caller's own sets, for the parent select (`__all__` = no parent). */
    function parentOptions() {
      return api('GET', '/api/v1/result-sets?limit=200').then(function (r) {
        var opts = [{ label: 'Entire fleet (no parent)', value: '' }];
        var sets = r.ok && r.data && r.data.data && r.data.data.result_sets;
        (Array.isArray(sets) ? sets : []).forEach(function (s) {
          opts.push({ label: (s.name || s.id) + ' (' + s.device_count + ' devices)', value: s.id });
        });
        return opts;
      });
    }

    function add(json, f) { if (f.parent) json.parent_id = f.parent; if (f.name.trim()) json.name = f.name.trim(); return json; }

    /* ---- R3 From instruction ---- */
    function fromInstruction() {
      /* The one raw fetch: the producer picker is an HTML fragment, which the shared JSON helper
         does not return. Same-origin, no cache, bounded by a 15 s timeout. */
      var init = { credentials: 'same-origin', cache: 'no-store' };
      try { init.signal = AbortSignal.timeout(15000); } catch (e) { /* older browsers: no timeout */ }
      window.fetch('/fragments/result-sets/producers', init)
        .then(function (r) { return r.text(); })
        .then(function (t) {
          var doc = new DOMParser().parseFromString(t, 'text/html');
          if (doc.querySelector('[data-denied]') || doc.querySelector('[data-degraded]') ||
              doc.querySelector('[data-empty]') || !doc.querySelector('option')) {
            var n = doc.querySelector('[data-denied],[data-degraded],[data-empty]');
            say('warn', n ? n.textContent : 'No instruction can produce a result set.');
            return null;
          }
          var instr = [];
          doc.querySelectorAll('option').forEach(function (o) {
            instr.push({ label: o.textContent, value: o.value });
          });
          return Promise.all([parentOptions()]).then(function (p) { return { instr: instr, parents: p[0] }; });
        })
        .then(function (c) {
          if (!c) return;
          return window.YuzuDialog.form({
            title: 'Create from an instruction',
            body: ['Runs the instruction on every device in the parent scope and keeps the ' +
                   'devices that answer. Approval rules are not applied; only read-only ' +
                   'instructions that need no approval are listed.'],
            fields: [
              { name: 'instruction', label: 'Instruction', type: 'select', options: c.instr },
              { name: 'parent', label: 'Parent scope', type: 'select', options: c.parents },
              { name: 'name', label: 'Name (optional)', type: 'text', maxlength: 128 },
              { name: 'column', label: 'Keep devices where column (optional)', type: 'text', maxlength: 128 },
              { name: 'op', label: 'Operator', type: 'select', options: [
                { label: 'equals', value: '==' }, { label: 'not equal', value: '!=' },
                { label: 'contains', value: 'contains' }, { label: 'greater than', value: '>' },
                { label: 'less than', value: '<' }] },
              { name: 'value', label: 'Value', type: 'text', maxlength: 512 }
            ],
            submitLabel: 'Review',
            validate: function (v) {
              return v.column.trim() && !v.value.trim() ? 'Enter a value for the column.' : null;
            }
          }).then(function (v) {
            if (!v) return;
            var json = add({ instruction_id: v.instruction }, v);
            if (v.column.trim()) json.matcher = { column: v.column.trim(), op: v.op, value: v.value };
            return oxConfirm({
              title: 'Run this instruction?',
              paragraphs: ['This dispatches to every device in the parent scope.'],
              facts: [['Parent', v.parent || 'Entire fleet']],
              confirmLabel: 'Create result set',
              danger: true
            }).then(function (ok) { if (ok) return send('/api/v1/result-sets/from-instruction-result', json, 'Result set'); });
          });
        })
        .catch(function () { say('bad', 'The producer list could not be read.'); });
    }

    /* ---- R4 From inventory (reads inventory only, synchronous) ---- */
    function fromInventory() {
      parentOptions().then(function (parents) {
        return window.YuzuDialog.form({
          title: 'Create from an inventory query',
          body: ['Keeps the devices whose stored inventory matches. Nothing is sent to devices.'],
          fields: [
            { name: 'plugin', label: 'Plugin', type: 'text', required: true, maxlength: 128 },
            { name: 'field', label: 'Field', type: 'text', required: true, maxlength: 128 },
            { name: 'op', label: 'Operator', type: 'select', options: [
              { label: 'equals', value: '==' }, { label: 'not equal', value: '!=' },
              { label: 'contains', value: 'contains' }, { label: 'exists', value: 'exists' },
              { label: 'at least version', value: 'version_gte' },
              { label: 'at most version', value: 'version_lte' },
              { label: 'greater or equal', value: '>=' }, { label: 'less or equal', value: '<=' }] },
            { name: 'value', label: 'Value', type: 'text', maxlength: 512 },
            { name: 'parent', label: 'Parent scope', type: 'select', options: parents },
            { name: 'name', label: 'Name (optional)', type: 'text', maxlength: 128 }
          ],
          submitLabel: 'Create result set',
          validate: function (v) {
            return v.op !== 'exists' && !v.value.trim() ? 'Enter a value.' : null;
          }
        });
      }).then(function (v) {
        if (!v) return;
        var cond = { plugin: v.plugin.trim(), field: v.field.trim(), op: v.op };
        if (v.op !== 'exists') cond.value = v.value;
        return send('/api/v1/result-sets/from-inventory-query',
                    add({ conditions: [cond], combine: 'all' }, v), 'Result set');
      });
    }

    /* ---- R5 From TAR query: the home of the retired Ad-hoc TAR SQL frame ---- */
    function fromTar() {
      parentOptions().then(function (parents) {
        return window.YuzuDialog.form({
          title: 'Create from a TAR query',
          body: ['Runs the SELECT on every device in the parent scope and keeps the devices ' +
                 'that return rows.'],
          fields: [
            { name: 'parent', label: 'Parent scope', type: 'select', options: parents },
            { name: 'sql', label: 'SQL (SELECT only)', type: 'textarea', rows: 6,
              maxlength: 100000, required: true,
              placeholder: "SELECT DISTINCT pid FROM process_live WHERE name = 'chrome.exe'" },
            { name: 'name', label: 'Name (optional)', type: 'text', maxlength: 120 },
            { name: 'empty', label: 'Devices that return 0 rows', type: 'select', options: [
              { label: 'Leave out', value: 'no' }, { label: 'Include', value: 'yes' }] }
          ],
          submitLabel: 'Review'
        });
      }).then(function (v) {
        if (!v) return;
        var sql = v.sql.trim();
        var shown = sql.length > 200 ? sql.slice(0, 200) + '... (' + sql.length + ' characters)' : sql;
        return oxConfirm({
          title: 'Run this query?',
          paragraphs: ['Queries every device in the parent scope. The text below is exactly ' +
                       'what is sent.'],
          facts: [['Parent', v.parent || 'Entire fleet']],
          pre: shown,
          confirmLabel: 'Create result set',
          danger: true
        }).then(function (ok) {
          if (!ok) return;
          return send('/api/v1/result-sets/from-tar-query',
                      add({ sql: sql, include_empty: v.empty === 'yes' }, v), 'Result set');
        });
      });
    }

    /* ---- R8 Re-evaluate: always a NEW set; the existing one is unchanged ---- */
    function rerun(id, name) {
      oxConfirm({
        title: 'Re-evaluate this result set?',
        paragraphs: ['This runs the original query again on every device in scope. It creates a ' +
                     'new set; the existing set is unchanged.'],
        facts: [['Result set', name || id]],
        confirmLabel: 'Re-evaluate',
        danger: true
      }).then(function (ok) {
        if (ok) return send('/api/v1/result-sets/' + encodeURIComponent(id) + '/re-eval', undefined,
                            'Re-evaluation');
      });
    }

    var b = $('ox-rs-instr'); if (b) b.addEventListener('click', fromInstruction);
    b = $('ox-rs-inv'); if (b) b.addEventListener('click', fromInventory);
    b = $('ox-rs-tar'); if (b) b.addEventListener('click', fromTar);

    /* The detail pane is swapped by htmx, so its buttons are handled by delegation
       (the page CSP forbids inline handlers). */
    body.addEventListener('click', function (e) {
      var t = e.target && e.target.closest ? e.target.closest('[data-ox-copy],[data-ox-reeval]') : null;
      if (!t) return;
      if (t.hasAttribute('data-ox-copy')) {
        var text = t.getAttribute('data-ox-copy');
        var done = function () { t.textContent = 'Copied'; };
        if (navigator.clipboard && navigator.clipboard.writeText) {
          navigator.clipboard.writeText(text).then(done, function () { t.textContent = 'Copy failed'; });
        } else { t.textContent = 'Copy failed'; }
      } else {
        rerun(t.getAttribute('data-ox-reeval'), t.getAttribute('data-ox-name'));
      }
    });
  }

  var controllers = { dashboard: dashboard, 'result-sets': resultSets };
  function boot() {
    var c = controllers[page];
    if (c) c();
  }
  if (document.readyState === 'loading') document.addEventListener('DOMContentLoaded', boot);
  else boot();
})();
