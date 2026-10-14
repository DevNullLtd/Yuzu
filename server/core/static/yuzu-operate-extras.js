/* yuzu-operate-extras.js: page controllers for the Operate extras, one per page, keyed on
   document.body.dataset.page. This file carries the `instructions` controller.

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
})();
