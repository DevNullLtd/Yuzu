/* yuzu-operate-extras.js: page controllers for the Operate extras, one per page, keyed on
   document.body.dataset.page. This file carries the `instructions` controller first, then the
   `dashboard` and `result-sets` controllers, each in its own scope.

   Rules this file keeps (pinned by test_instruction_extras_ui.cpp):
   - server data reaches the DOM through textContent only, with no markup or
     dynamic-code sink of any kind;
   - every request is same-origin and goes through YuzuDialog.request (15 s timeout);
   - every destructive or fan-out action goes through YuzuDialog first, because none of
     the routes it calls carries a step-up;
   - secret parameters (the server's `secret_params` list on the definition detail) are
     write-only password inputs;
   - Execute stays disabled until the definition detail has loaded, and the legacy inline
     dispatcher refuses to run unless this module is present, so a missing script or a failed
     detail request never leaves a one-click, unconfirmed dispatch. */
(function () {
  'use strict';

  var doc = document;
  var page = doc.body && doc.body.dataset ? doc.body.dataset.page : '';
  var D = window.YuzuDialog;
  if (page !== 'instructions' || !D) return;
  // The legacy inline executeInstruction() refuses to dispatch unless this is set.
  window.__yuzuExtrasReady = true;

  // Parameter names the server marks write-only (definition detail `secret_params`).
  var secretParams = {};

  function $(id) { return doc.getElementById(id); }
  function el(tag, cls, text) {
    var n = doc.createElement(tag);
    if (cls) n.className = cls;
    if (text !== undefined && text !== null) n.textContent = String(text);
    return n;
  }
  function clear(n) { while (n.firstChild) n.removeChild(n.firstChild); }
  function toast(msg, level) {
    if (typeof window.showToast === 'function') window.showToast(msg, level || 'success');
  }
  function enc(s) { return encodeURIComponent(s); }
  // Unwraps the REST v1 {data: ...} envelope.
  function payload(res) {
    var d = res && res.data;
    return d && typeof d === 'object' && d.data && typeof d.data === 'object' ? d.data : d;
  }
  function failText(res, fallback) {
    if (res.status === 0) return 'The request may not have applied. Check the list before retrying.';
    if (res.status === 403) return 'You do not have permission to do that.';
    return res.message || fallback;
  }

  /* Reload the library fragment, keeping the current filter. */
  function reloadLibrary() {
    var form = doc.querySelector('#tab-definitions form.ox-filter');
    var qs = form ? new URLSearchParams(new FormData(form)).toString() : '';
    if (window.htmx) {
      window.htmx.ajax('GET', '/fragments/instructions' + (qs ? '?' + qs : ''),
                       { target: '#tab-definitions', swap: 'innerHTML' });
    }
  }
  function reloadTemplates(defId) {
    if (window.htmx) {
      window.htmx.ajax('GET', '/fragments/instructions/templates?id=' + enc(defId),
                       { target: '#ox-templates', swap: 'innerHTML' });
    }
  }

  /* After a write: a failed audit write is stated, never hidden. */
  function auditNote(res) {
    return res.auditFailed ?
      'The action succeeded but its audit record could not be written. Tell an administrator.' : '';
  }
  function done(res, okMsg) {
    toast(okMsg + (res.auditFailed ? ' ' + auditNote(res) : ''), res.auditFailed ? 'warning' : 'success');
  }

  /* ---- sets ---- */

  function newSet() {
    D.form({
      title: 'New instruction set',
      body: 'A set groups definitions. It has no effect on dispatch.',
      fields: [
        { name: 'name', label: 'Name', type: 'text', required: true, maxlength: 128 },
        { name: 'description', label: 'Description', type: 'text', maxlength: 512 }
      ],
      submitLabel: 'Create set',
      validate: function (v) { return v.name.trim() ? null : 'A name is required.'; },
      submit: function (v) {
        return D.request('POST', '/api/instruction-sets',
                         { json: { name: v.name.trim(), description: (v.description || '').trim() } })
          .then(function (r) {
            if (!r.ok) return failText(r, 'The set was not created.');
            done(r, 'Instruction set created');
            return null;
          });
      }
    }).then(function (v) { if (v) reloadLibrary(); });
  }

  function deleteSet(btn) {
    var id = btn.dataset.setId, name = btn.dataset.setName, n = btn.dataset.setMembers || '0';
    D.confirm({
      title: 'Delete instruction set',
      body: ['Delete the set "' + name + '" (' + id + ').',
             'Its ' + n + ' definition(s) stay and become unassigned.'],
      confirmLabel: 'Delete set', danger: true
    }).then(function (yes) {
      if (!yes) return;
      D.request('DELETE', '/api/instruction-sets/' + enc(id)).then(function (r) {
        if (!r.ok) { toast(failText(r, 'The set was not deleted.'), 'error'); return; }
        done(r, 'Instruction set deleted');
        reloadLibrary();
      });
    });
  }

  function assignSet(sel) {
    var defId = sel.dataset.defId, prev = sel.dataset.prev || '';
    D.request('PUT', '/api/instructions/' + enc(defId), { json: { instruction_set_id: sel.value } })
      .then(function (r) {
        if (!r.ok) {
          sel.value = prev; // the change did not apply; show what is stored
          toast(failText(r, 'The set was not changed.'), 'error');
          return;
        }
        sel.dataset.prev = sel.value;
        done(r, 'Set updated');
      });
  }

  /* ---- import / export ---- */

  function importDefinition() {
    D.form({
      title: 'Import definition',
      body: ['Paste a definition export document (JSON, as produced by Export).',
             'Unsigned definitions may be rejected by policy; a duplicate id is refused.'],
      fields: [{ name: 'doc', label: 'Definition document', type: 'textarea', rows: 12, required: true }],
      submitLabel: 'Import', danger: false,
      validate: function (v) {
        try { JSON.parse(v.doc); } catch (e) { return 'That is not valid JSON.'; }
        return null;
      },
      submit: function (v) {
        return D.request('POST', '/api/instructions/import', { json: JSON.parse(v.doc) })
          .then(function (r) {
            if (!r.ok) return failText(r, 'The import was refused.');
            done(r, 'Definition imported');
            return null;
          });
      }
    }).then(function (v) { if (v) reloadLibrary(); });
  }

  function exportDefinition(btn) {
    D.request('GET', '/api/v1/instructions/' + enc(btn.dataset.defId) + '/export').then(function (r) {
      var d = payload(r);
      if (!r.ok || !d) { toast(failText(r, 'The export failed.'), 'error'); return; }
      var blob = new Blob([JSON.stringify(d, null, 2)], { type: 'application/json' });
      var a = el('a');
      a.href = URL.createObjectURL(blob);
      a.download = (btn.dataset.defId || 'definition') + '.json';
      doc.body.appendChild(a);
      a.click();
      doc.body.removeChild(a);
      setTimeout(function () { URL.revokeObjectURL(a.href); }, 0);
    });
  }

  /* ---- response templates ---- */

  var OPS = ['equals', 'not_equals', 'contains', 'starts_with', 'ends_with'];

  function filtersToText(fs) {
    return (fs || []).map(function (f) { return [f.column, f.op, f.value].join(' | '); }).join('\n');
  }
  // One filter per line: column | op | value.
  function textToFilters(t) {
    var out = [];
    var bad = null;
    (t || '').split('\n').forEach(function (line) {
      if (!line.trim()) return;
      var p = line.split('|').map(function (s) { return s.trim(); });
      if (p.length < 3 || !p[0] || OPS.indexOf(p[1]) < 0) { bad = line.trim(); return; }
      out.push({ column: p[0], op: p[1], value: p.slice(2).join('|').trim() });
    });
    return { filters: out, bad: bad };
  }

  function templateDialog(defId, existing) {
    var editing = !!existing;
    var t = existing || {};
    D.form({
      title: editing ? 'Edit response template' : 'New response template',
      body: 'A template picks the columns, sort and filters the Console applies to a result.',
      note: 'Filter lines are "column | op | value"; op is one of ' + OPS.join(', ') + '.',
      fields: [
        { name: 'name', label: 'Name', type: 'text', required: true, maxlength: 128, value: t.name || '' },
        { name: 'description', label: 'Description', type: 'text', maxlength: 512, value: t.description || '' },
        { name: 'columns', label: 'Columns (comma separated, empty for all)', type: 'text',
          value: (t.columns || []).join(', ') },
        { name: 'sort_column', label: 'Sort column', type: 'text', value: t.sort && t.sort.column || '' },
        { name: 'sort_dir', label: 'Sort direction', type: 'select',
          options: [{ value: 'asc', label: 'Ascending' }, { value: 'desc', label: 'Descending' }],
          value: t.sort && t.sort.dir || 'asc' },
        { name: 'filters', label: 'Filters', type: 'textarea', rows: 4, value: filtersToText(t.filters) },
        { name: 'is_default', label: 'Use as the default', type: 'select',
          options: [{ value: 'no', label: 'No' }, { value: 'yes', label: 'Yes' }],
          value: t.default ? 'yes' : 'no' }
      ],
      submitLabel: editing ? 'Save template' : 'Create template',
      validate: function (v) {
        if (!v.name.trim()) return 'A name is required.';
        var f = textToFilters(v.filters);
        return f.bad ? 'Filter line not understood: ' + f.bad : null;
      },
      submit: function (v) {
        var body = {
          name: v.name.trim(),
          description: (v.description || '').trim(),
          columns: (v.columns || '').split(',').map(function (s) { return s.trim(); })
                                    .filter(function (s) { return s; }),
          filters: textToFilters(v.filters).filters,
          'default': v.is_default === 'yes'
        };
        if (v.sort_column && v.sort_column.trim())
          body.sort = { column: v.sort_column.trim(), dir: v.sort_dir || 'asc' };
        var url = '/api/v1/definitions/' + enc(defId) + '/response-templates' +
                  (editing ? '/' + enc(t.id) : '');
        return D.request(editing ? 'PUT' : 'POST', url, { json: body }).then(function (r) {
          if (!r.ok) return failText(r, 'The template was not saved.');
          done(r, 'Template saved');
          return null;
        });
      }
    }).then(function (v) { if (v) reloadTemplates(defId); });
  }

  function editTemplate(btn) {
    var t = null;
    try { t = JSON.parse(btn.dataset.tpl); } catch (e) { t = null; }
    if (t) templateDialog(btn.dataset.defId, t);
  }

  function deleteTemplate(btn) {
    var defId = btn.dataset.defId, tid = btn.dataset.tplId;
    D.confirm({
      title: 'Delete response template',
      body: ['Delete the template "' + btn.dataset.tplName + '".', 'The built-in default stays.'],
      confirmLabel: 'Delete template', danger: true
    }).then(function (yes) {
      if (!yes) return;
      D.request('DELETE', '/api/v1/definitions/' + enc(defId) + '/response-templates/' + enc(tid))
        .then(function (r) {
          if (!r.ok) { toast(failText(r, 'The template was not deleted.'), 'error'); return; }
          done(r, 'Template deleted');
          reloadTemplates(defId);
        });
    });
  }

  /* ---- dispatch (extends the Execute form; the legacy handler stays as the fallback) ---- */

  var detail = null;      // v1 detail of the selected definition
  var previewed = null;   // {expr, count} after a successful Preview of that exact expression

  function note(msg, kind) {
    var host = $('ox-expr-note');
    if (!host) return;
    host.className = 'note' + (kind ? ' ' + kind : '');
    host.textContent = msg;
    host.style.display = msg ? 'block' : 'none';
  }

  function onDefChange() {
    detail = null;
    secretParams = {};
    var id = $('exec-def-select').value;
    var btn = $('exec-btn');
    if (!id) return;
    // The legacy handler enables Execute the moment a row is picked; hold it until the
    // detail (approval mode, plugin, action, secret parameters) is in hand.
    if (btn) btn.disabled = true;
    // The legacy list row carries no parameter_schema; the v1 detail does (F11).
    D.request('GET', '/api/v1/instructions/' + enc(id)).then(function (r) {
      if ($('exec-def-select').value !== id) return;
      var d = payload(r);
      if (!r.ok || !d) {
        note('Could not load this instruction\'s details, so it cannot be dispatched. Reload the page and try again.', 'warn');
        return;
      }
      note('');
      detail = d;
      (Array.isArray(d.secret_params) ? d.secret_params : []).forEach(function (k) { secretParams[k] = true; });
      renderParams(d.parameter_schema);
      if (btn) btn.disabled = false;
    });
  }

  function renderParams(schemaText) {
    var host = $('exec-params-fields'), area = $('exec-params-area');
    if (!host || !area) return;
    var schema = {};
    try { schema = typeof schemaText === 'string' ? JSON.parse(schemaText || '{}') : (schemaText || {}); }
    catch (e) { schema = {}; }
    var props = schema.properties || {}, req = schema.required || [];
    var keys = Object.keys(props);
    clear(host);
    area.style.display = keys.length ? 'block' : 'none';
    keys.forEach(function (k) {
      var p = props[k] || {};
      var g = el('div', 'form-group');
      g.appendChild(el('label', '', k + (req.indexOf(k) >= 0 ? ' *' : '')));
      var inp = el('input');
      inp.name = 'param_' + k;
      inp.placeholder = p.description || p.type || '';
      if (secretParams[k]) {
        inp.type = 'password';
        inp.autocomplete = 'off';
        inp.placeholder = 'Write-only';
      } else if (p['default'] !== undefined) {
        inp.value = p['default'];
      }
      g.appendChild(inp);
      host.appendChild(g);
    });
  }

  function exprText() { var e = $('ox-expr'); return e ? e.value.trim() : ''; }
  function expressionMode() { var m = $('ox-target-mode'); return !!m && m.value === 'expression'; }

  function syncMode() {
    var on = expressionMode();
    $('ox-expr-box').style.display = on ? 'block' : 'none';
    $('exec-scope').disabled = on;
    previewed = null;
    note('');
  }

  function scopeCheck(kind) {
    var expr = exprText();
    if (!expr) return;
    note('Checking...');
    D.request('POST', '/api/v1/scope/' + kind, { json: { expression: expr } }).then(function (r) {
      if (exprText() !== expr) return; // edited while in flight
      var d = payload(r);
      if (r.status === 403) {
        note('Previewing a scope needs the Infrastructure read permission.', 'warn');
        previewed = null;
        return;
      }
      if (r.status === 404) { note('That result set was not found, or is not yours.', 'warn'); return; }
      if (r.status === 503 || r.status === 0) {
        note('Preview unavailable. This is not zero matches. Retry shortly.', 'warn');
        return;
      }
      if (!r.ok || !d) { note(r.message || 'The expression was refused.', 'warn'); return; }
      if (kind === 'validate') {
        if (d.valid === false) { note(d.error || 'The expression is not valid.', 'warn'); return; }
        note('Syntax is valid. Unknown attributes are refused on Send.');
        return;
      }
      var n = d.matched_count || 0;
      previewed = { expr: expr, count: n };
      var ids = (d.matched_agents || []).slice(0, 25);
      note(n === 0 ? 'No devices match.' :
           n + ' device(s) match. ' + ids.join(', ') + (n > ids.length ? ' and ' + (n - ids.length) + ' more.' : ''));
    });
  }

  function targetLabel() {
    if (expressionMode()) return 'expression: ' + exprText();
    var s = $('exec-scope');
    return s.options[s.selectedIndex] ? s.options[s.selectedIndex].textContent : s.value;
  }

  function confirmDispatch() {
    // Never confirm a dispatch the operator cannot read: without the detail the dialog
    // would show "?" for the plugin/action and omit the approval line.
    if (!detail) {
      note('The instruction details have not loaded yet. Wait a moment, or reload the page.', 'warn');
      return Promise.resolve(false);
    }
    var d = detail;
    var sel = $('exec-def-select');
    var name = d.name || (sel.options[sel.selectedIndex] ? sel.options[sel.selectedIndex].textContent : '');
    var lines = ['Instruction: ' + name + ' (' + (d.plugin || '?') + ':' + (d.action || '?') + ', ' +
                 (d.type || '?') + ')',
                 'Target: ' + targetLabel()];
    var scopeVal = $('exec-scope').value;
    var fanOut = expressionMode() || scopeVal === '__all__' || scopeVal.indexOf('group:') === 0;
    if (expressionMode() && previewed && previewed.expr === exprText())
      lines.push('Previewed: ' + previewed.count + ' device(s) match.');
    if (d.approval_mode && d.approval_mode !== 'auto')
      lines.push('This will be submitted for approval, not run.');
    else if (fanOut)
      lines.push('This dispatches to every device in scope.');
    if (expressionMode() && !(previewed && previewed.expr === exprText())) {
      // Preview is denied or was not run for this exact expression: a typed confirmation
      // replaces the count the operator could not see.
      lines.push('This expression has not been previewed. Type DISPATCH to send it.');
      return D.form({
        title: 'Dispatch instruction', body: lines,
        fields: [{ name: 'word', label: 'Confirmation', type: 'text', required: true }],
        submitLabel: 'Dispatch', danger: true,
        validate: function (v) { return v.word.trim() === 'DISPATCH' ? null : 'Type DISPATCH to continue.'; },
        submit: function () { return Promise.resolve(null); }
      }).then(function (v) { return !!v; });
    }
    return D.confirm({ title: 'Dispatch instruction', body: lines,
                       confirmLabel: 'Dispatch', danger: fanOut });
  }

  function dispatch() {
    var id = $('exec-def-select').value;
    var status = $('exec-status'), out = $('exec-result'), btn = $('exec-btn');
    if (!id) return;
    if (expressionMode() && !exprText()) { note('Enter a scope expression first.', 'warn'); return; }
    confirmDispatch().then(function (yes) {
      if (!yes) return;
      var params = {};
      Array.prototype.forEach.call(doc.querySelectorAll('#exec-params-fields input'), function (i) {
        var k = i.name.replace('param_', '');
        if (i.value.trim()) params[k] = i.value.trim();
      });
      var body = { params: params };
      var scope = $('exec-scope').value;
      if (expressionMode()) body.scope = exprText();
      else if (scope === '__all__' || scope.indexOf('group:') === 0) body.scope = scope;
      else body.agent_ids = [scope];
      btn.disabled = true;
      status.textContent = 'Dispatching...';
      D.request('POST', '/api/instructions/' + enc(id) + '/execute', { json: body }).then(function (r) {
        btn.disabled = false;
        status.textContent = '';
        clear(out);
        var box = el('div', 'alert');
        var p = payload(r) || {};
        if (r.status === 202) {
          box.className = 'alert alert-success';
          box.textContent = 'Submitted for approval' +
            (p.approval_id ? ' (request ' + p.approval_id + ')' : '') + '. Nothing has run yet.';
        } else if (r.ok) {
          box.className = 'alert alert-success';
          box.textContent = 'Command ' + (p.command_id || '') + ' dispatched to ' +
            (p.agents_reached || 0) + ' agent(s).';
        } else {
          box.className = 'alert alert-error';
          box.textContent = r.status === 403 ? 'You do not have permission to dispatch instructions.'
                                             : failText(r, 'The dispatch failed.');
        }
        out.appendChild(box);
      });
    });
  }

  /* ---- wiring: one delegated listener per event type ---- */

  var ACTIONS = {
    'set-new': newSet, 'set-delete': deleteSet, 'import': importDefinition,
    'export': exportDefinition, 'tpl-new': function (b) { templateDialog(b.dataset.defId, null); },
    'tpl-edit': editTemplate, 'tpl-delete': deleteTemplate
  };

  doc.addEventListener('click', function (ev) {
    var t = ev.target && ev.target.closest ? ev.target : null;
    if (!t) return;
    var run = t.closest('#exec-btn');
    if (run) {
      // Capture phase: this replaces the page's inline Execute handler, which stays as the
      // fallback when this file does not load.
      ev.stopImmediatePropagation();
      ev.preventDefault();
      dispatch();
      return;
    }
    var b = t.closest('[data-ox]');
    if (!b) return;
    var key = b.dataset.ox;
    if (key === 'expr-validate') { scopeCheck('validate'); return; }
    if (key === 'expr-preview') { scopeCheck('preview'); return; }
    if (ACTIONS[key]) ACTIONS[key](b);
  }, true);

  doc.addEventListener('change', function (ev) {
    var t = ev.target;
    if (!t || !t.matches) return;
    if (t.matches('select[data-ox="set-assign"]')) assignSet(t);
    else if (t.id === 'exec-def-select') onDefChange();
    else if (t.id === 'ox-target-mode') syncMode();
  });

  doc.addEventListener('input', function (ev) {
    if (ev.target && ev.target.id === 'ox-expr') { previewed = null; }
  });

  /* ---- #6061: the Approvals tab's Approve/Reject buttons post with hx-swap="none", so
     htmx drops a 401/403 body and the click did nothing. A 403 or an expired session says
     so in a toast. A 401 step-up goes through YuzuDialog.request, the Approvals page's own
     code prompt, which replays the decision once the code is accepted. ---- */
  function stepUpEnvelope(env) {
    return !!(env && env.meta && env.meta.mfa_step_up_required === true);
  }
  doc.body.addEventListener('htmx:responseError', function (evt) {
    var d = evt.detail;
    var x = d && d.xhr;
    if (!x || (x.status !== 401 && x.status !== 403)) return;
    var path = (d.pathInfo && d.pathInfo.requestPath) ||
               (d.requestConfig && d.requestConfig.path) || '';
    var m = /^\/api\/approvals\/[^\/]+\/(approve|reject)$/.exec(path);
    if (!m) return;
    var env = null;
    try { env = JSON.parse(x.responseText); } catch (e) { env = null; }
    var msg = env && env.error && typeof env.error.message === 'string' ? env.error.message : '';
    if (x.status === 403) {
      toast(msg || 'You do not have permission to decide approvals.', 'error');
      return;
    }
    if (!stepUpEnvelope(env)) {
      toast('Your session expired; sign in again.', 'error');
      return;
    }
    D.request('POST', path, { json: {} }).then(function (r) {
      if (r.ok) {
        toast(m[1] === 'approve' ? 'Approved' : 'Rejected', 'success');
        doc.body.dispatchEvent(new CustomEvent('refreshApprovals'));
      } else if (r.status === 401) {
        if (!stepUpEnvelope(r.data)) toast('Your session expired; sign in again.', 'error');
      } else if (r.status === 403) {
        toast(r.message || 'You do not have permission to decide approvals.', 'error');
      } else if (r.status === 400) {
        toast(r.message || 'The request was refused.', 'error');
      } else {
        toast('Could not confirm the decision. Refresh to see the current state.', 'error');
      }
    }, function () { /* another dialog is open: nothing to do */ });
  });
})();

/* Dashboard and Result sets controllers, keyed on document.body.dataset.page.

   Rules this controller keeps (pinned by test_operate_extras_ui.cpp):
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

  /* Typed text is masked wherever it is echoed back (confirm dialog, history). The key list
     is the server's own classification (sensitive_instruction_params.hpp), rendered into
     <body data-secret-params> by the page; this file keeps no list of its own. With no list
     the text is withheld, never echoed unmasked. */
  var SECRET_KEYS = String(body && body.dataset && body.dataset.secretParams || '')
    .split(',').filter(function (k) { return /^[A-Za-z0-9_]+$/.test(k); });
  var SECRET_RE = SECRET_KEYS.length
    ? new RegExp('\\b(' + SECRET_KEYS.join('|') + ')=("[^"]*"|\'[^\']*\'|\\S+)', 'gi') : null;
  function maskSecrets(s) {
    return SECRET_RE ? String(s).replace(SECRET_RE, '$1=•••')
                     : '(hidden: the secret parameter list is unavailable)';
  }

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
    /* The page's own htmx:confirm guard on #instr-form holds every Send until this flag is
       set, so a missing dialog module or script can never leave a one-click fan-out. */
    if (window.YuzuDialog) window.__yuzuDashboardConfirmReady = true;

    /* ---- History: the Console's History panel has had no caller since the
       HTMX refactor (e39654155); feed it from a send the server dispatched.
       The route answers 200 for a refusal too (destructive target, no agent reached,
       unknown command), so success is not a status: only the dispatch response carries
       X-Yuzu-Dispatched. Only the masked text is ever stored. An entry whose text changed
       under the mask carries masked=true, and the page does not replay it. ---- */
    var form = $('instr-form');
    if (form) {
      form.addEventListener('htmx:afterRequest', function (evt) {
        if (evt.target !== form || !evt.detail || !evt.detail.successful) return;
        var xhr = evt.detail.xhr;
        if (!xhr || !xhr.getResponseHeader('X-Yuzu-Dispatched')) return;
        var input = $('instr-input');
        var cmd = input ? input.value.trim() : '';
        if (!cmd || typeof window.addHistory !== 'function') return;
        var shown = maskSecrets(cmd);
        window.addHistory(shown, exprValue() ? 'Expression: ' + exprValue() : sendTarget().label,
                          shown !== cmd);
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
      } else if ((x.status === 400 || x.status === 503) && path.indexOf('/api/dashboard/execute') === 0) {
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
        .then(function (r) {
          /* A 401/403/5xx body is not an empty list; say it failed. */
          if (!r.ok) throw new Error('producers ' + r.status);
          return r.text();
        })
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
