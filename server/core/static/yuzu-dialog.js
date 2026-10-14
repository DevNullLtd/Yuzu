/* yuzu-dialog.js -- the shared modal dialog and request helper (window.YuzuDialog).
 *
 * One native <dialog class="dlg"> per open call, shown with showModal(), removed on close.
 * Pages call confirm(), form() or request(); no framework, no markup sinks: every string is
 * set with textContent and a caller-built Node is appended as-is.
 *
 *   YuzuDialog.confirm({title, body, confirmLabel, cancelLabel, danger}) -> Promise<boolean>
 *   YuzuDialog.form({title, body, note, fields, submitLabel, cancelLabel, danger,
 *                    validate(values) -> string|null,
 *                    submit(values) -> Promise<string|null>}) -> Promise<object|null>
 *   YuzuDialog.request(method, url, {json, form, headers, timeoutMs})
 *       -> Promise<{ok, status, data, auditFailed, warning, message}>   (never rejects)
 *
 *   body:   string | string[] (one <p> each) | Node
 *   fields: [{name, label, type: text|password|textarea|select, hint, autocomplete,
 *             inputmode, maxlength, rows, placeholder, required, value, options}]
 *
 * submit() runs with the buttons disabled and keeps the dialog open: null closes it and
 * resolves the values, a string is shown in the error slot. One dialog at a time (a second
 * call rejects Error('dialog busy')); the one exception is the MFA step-up prompt that
 * request() raises while a dialog's own submit() is in flight. Focus returns to the opener.
 *
 * request() is a same-origin fetch with a 15 s timeout (timeoutMs overrides it, 1 s to 5 min
 * only; anything else keeps 15 s): a url that resolves to another
 * origin is refused without a request. The body is serialised once, so a 401 carrying
 * meta.mfa_step_up_required prompts for the code (POST /login/mfa/stepup) and replays the
 * original request once with byte-identical content; any other 401 goes to /login.
 */
(function () {
  'use strict';

  var doc = document;
  var depth = 0;

  function el(tag, cls, text) {
    var e = doc.createElement(tag);
    if (cls) e.className = cls;
    if (text !== undefined && text !== null) e.textContent = String(text);
    return e;
  }

  function bodyNodes(body) {
    var out = [];
    if (body === undefined || body === null || body === '') return out;
    if (typeof body === 'string') { out.push(el('p', '', body)); return out; }
    if (Array.isArray(body)) {
      body.forEach(function (s) { out.push(el('p', '', s)); });
      return out;
    }
    out.push(body);
    return out;
  }

  // ---- request ----

  function summarise(status, ok, data, auditHeader) {
    var message = '';
    if (data && typeof data.error === 'string') message = data.error;
    else if (data && data.error && typeof data.error.message === 'string') message = data.error.message;
    var inner = data && data.data && typeof data.data === 'object' ? data.data : null;
    var persisted = inner && (inner.db_persisted === false || inner.api_tokens_db_persisted === false);
    return {
      ok: ok, status: status, data: data,
      auditFailed: auditHeader || !!(inner && inner.audit_emitted === false),
      warning: persisted ? 'The change may not have persisted; retry.' : '',
      message: message
    };
  }

  // Serialise once. The MFA replay re-sends these exact bytes, so a caller mutating
  // opts while the step-up dialog is open cannot authorise one body and replay another.
  function prepare(opts) {
    opts = opts || {};
    var headers = {};
    if (opts.headers) Object.keys(opts.headers).forEach(function (k) { headers[k] = opts.headers[k]; });
    var body;
    if (opts.json !== undefined) {
      headers['Content-Type'] = 'application/json';
      body = JSON.stringify(opts.json);
    } else if (opts.form) {
      headers['Content-Type'] = 'application/x-www-form-urlencoded';
      body = new URLSearchParams(opts.form).toString();
    }
    // A caller that knows its request is slow (a 100-row batch insert) may widen the timeout.
    // Out-of-range or non-numeric values fall back to the default rather than disabling it.
    var ms = opts.timeoutMs;
    var timeoutMs = (typeof ms === 'number' && ms >= 1000 && ms <= 300000) ? ms : 15000;
    return { headers: headers, body: body, timeoutMs: timeoutMs };
  }

  function send(method, url, prep) {
    // Resolved against the page, then required to be same-origin, so credentials: 'same-origin'
    // is not the only thing standing between a caller-supplied url and another host.
    var target;
    try {
      var u = new URL(String(url), location.href);
      if (u.origin !== location.origin) throw new Error('cross-origin');
      target = u.href;
    } catch (e) {
      return Promise.resolve({ ok: false, status: 0, data: null, auditFailed: false, warning: '',
                               message: 'Only same-origin requests are allowed.' });
    }
    var headers = {};
    Object.keys(prep.headers).forEach(function (k) { headers[k] = prep.headers[k]; });
    var init = { method: method, credentials: 'same-origin', cache: 'no-store', headers: headers };
    if (prep.body !== undefined) init.body = prep.body;
    // Built inside try/catch: an old browser degrades to no timeout, not a throw.
    try { init.signal = AbortSignal.timeout(prep.timeoutMs); } catch (e) { /* no timeout available */ }
    return fetch(target, init).then(function (r) {
      var ct = r.headers.get('Content-Type') || '';
      var audit = r.headers.get('Sec-Audit-Failed') === 'true';
      var parsed = ct.indexOf('application/json') >= 0 ?
        r.json().catch(function () { return null; }) : Promise.resolve(null);
      return parsed.then(function (data) { return summarise(r.status, r.ok, data, audit); });
    }).catch(function () {
      return { ok: false, status: 0, data: null, auditFailed: false, warning: '',
               message: 'The request may not have applied.' };
    });
  }

  function rawRequest(method, url, opts) {
    return send(method, url, prepare(opts));
  }

  function request(method, url, opts) {
    var prep = prepare(opts);
    return send(method, url, prep).then(function (res) {
      if (res.status !== 401) return res;
      var meta = res.data && res.data.meta;
      if (!(meta && meta.mfa_step_up_required === true)) {
        location.assign('/login');
        return res;
      }
      var challenge = typeof meta.challenge_url === 'string' ? meta.challenge_url : '/login/mfa/stepup';
      // The OIDC challenge is a redirect flow, not a code prompt; send the user to sign in.
      if (challenge !== '/login/mfa/stepup') { location.assign('/login'); return res; }
      return form({
        title: 'Confirm it is you',
        body: 'This action needs a fresh second-factor check. Enter your authenticator code or a recovery code.',
        fields: [{ name: 'code', label: 'Code', type: 'text', autocomplete: 'one-time-code',
                   required: true, maxlength: 64 }],
        submitLabel: 'Verify',
        nested: true,
        submit: function (v) {
          return rawRequest('POST', challenge, { form: { code: v.code.trim() } }).then(function (r) {
            return r.ok ? null : 'That code was not accepted. Check it and try again.';
          });
        }
      }).then(function (ok) {
        if (!ok) return res;
        return send(method, url, prep);
      });
    });
  }

  // ---- dialog ----

  // Builds and shows one dialog. spec: {title, nodes, note, danger, actions, onAction}.
  // actions: [{label, value, kind, autofocus}] in left-to-right order. Without onAction a
  // click closes with the action's value.
  function show(spec) {
    var opener = doc.activeElement;
    var dlg = el('dialog', 'dlg');
    dlg.setAttribute('aria-labelledby', 'dlg-title');
    var h = el('h2', '', spec.title || '');
    h.id = 'dlg-title';
    var b = el('div', 'b');
    spec.nodes.forEach(function (n) { b.appendChild(n); });
    if (spec.note) b.appendChild(el('div', 'note' + (spec.danger ? ' warn' : ''), spec.note));
    var err = el('p', 'err');
    err.setAttribute('role', 'alert');
    err.hidden = true;
    b.appendChild(err);
    var f = el('div', 'f');
    var buttons = [];
    spec.actions.forEach(function (a) {
      var btn = el('button', 'btn' + (a.kind === 'primary' ? ' btn-primary' :
                                      a.kind === 'danger' ? ' btn-danger' : ''), a.label);
      btn.type = 'button';
      btn.addEventListener('click', function () {
        if (spec.onAction) spec.onAction(a.value, handle); else handle.close(a.value);
      });
      buttons.push(btn);
      f.appendChild(btn);
    });
    dlg.appendChild(h);
    dlg.appendChild(b);
    dlg.appendChild(f);

    var isBusy = false;
    var resolveDone;
    var done = new Promise(function (r) { resolveDone = r; });
    var settled = false;
    var handle = {
      el: dlg,
      done: done,
      busy: function () { return isBusy; },
      setBusy: function (on) {
        isBusy = !!on;
        buttons.forEach(function (x) { x.disabled = isBusy; });
        Array.prototype.forEach.call(dlg.querySelectorAll('input,textarea,select'), function (x) {
          x.disabled = isBusy;
        });
      },
      setError: function (text) {
        err.textContent = text || '';
        err.hidden = !text;
      },
      close: function (value) {
        if (settled) return;
        settled = true;
        resolveDone(value === undefined ? null : value);
        try { dlg.close(); } catch (e) { /* not open */ }
        if (dlg.parentNode) dlg.parentNode.removeChild(dlg);
        depth--;
        if (opener && opener.focus && doc.contains(opener)) {
          try { opener.focus(); } catch (e) { /* focus is best effort */ }
        }
      }
    };
    // Esc: resolve as cancelled, except while a submit is in flight.
    dlg.addEventListener('cancel', function (e) {
      e.preventDefault();
      if (!isBusy) handle.close(null);
    });
    depth++;
    doc.body.appendChild(dlg);
    dlg.showModal();
    var auto = null;
    spec.actions.forEach(function (a, i) { if (a.autofocus) auto = buttons[i]; });
    if (auto) auto.focus();
    return handle;
  }

  function buildField(spec, cleaners) {
    var wrap = el('div', 'fld');
    var id = 'dlg-f-' + spec.name;
    var lab = el('label', '', spec.label || spec.name);
    lab.setAttribute('for', id);
    wrap.appendChild(lab);
    var input;
    if (spec.type === 'textarea') {
      input = el('textarea');
      input.rows = spec.rows || 3;
    } else if (spec.type === 'select') {
      input = el('select');
      (spec.options || []).forEach(function (o) {
        var opt = el('option', '', o.label);
        opt.value = o.value;
        input.appendChild(opt);
      });
    } else {
      input = el('input');
      input.type = spec.type === 'password' ? 'password' : 'text';
      // A secret is never sent to a spell-check service or kept in a dictionary.
      if (spec.type === 'password') input.setAttribute('spellcheck', 'false');
    }
    input.id = id;
    input.name = spec.name;
    if (spec.maxlength) input.maxLength = spec.maxlength;
    if (spec.placeholder) input.placeholder = spec.placeholder;
    if (spec.autocomplete) input.setAttribute('autocomplete', spec.autocomplete);
    if (spec.inputmode) input.setAttribute('inputmode', spec.inputmode);
    if (spec.value !== undefined && spec.value !== null) input.value = String(spec.value);
    wrap.appendChild(input);
    if (spec.type === 'textarea' && spec.maxlength) {
      var counter = el('span', 'hint');
      var upd = function () { counter.textContent = input.value.length + ' / ' + spec.maxlength; };
      input.addEventListener('input', upd);
      upd();
      wrap.appendChild(counter);
    }
    if (spec.hint) wrap.appendChild(el('span', 'hint', spec.hint));
    if (spec.type === 'password' || spec.autocomplete === 'one-time-code') {
      cleaners.push(function () { input.value = ''; });
    }
    return { wrap: wrap, input: input };
  }

  function form(o) {
    o = o || {};
    if (depth > 0 && !o.nested) return Promise.reject(new Error('dialog busy'));
    var fields = o.fields || [];
    var cleaners = [];
    var inputs = [];
    var nodes = bodyNodes(o.body);
    fields.forEach(function (fs) {
      var built = buildField(fs, cleaners);
      inputs.push({ spec: fs, input: built.input });
      nodes.push(built.wrap);
    });
    function values() {
      var v = {};
      inputs.forEach(function (x) { v[x.spec.name] = x.input.value; });
      return v;
    }
    function clearSecrets() { cleaners.forEach(function (fn) { fn(); }); }
    function attempt(handle) {
      if (handle.busy()) return;
      var v = values();
      for (var i = 0; i < inputs.length; i++) {
        var s = inputs[i].spec;
        if (s.required && !String(v[s.name]).trim()) {
          handle.setError((s.label || s.name) + ' is required.');
          return;
        }
      }
      var bad = o.validate ? o.validate(v) : null;
      if (bad) { handle.setError(bad); return; }
      handle.setError(null);
      if (!o.submit) { clearSecrets(); handle.close(v); return; }
      handle.setBusy(true);
      Promise.resolve(o.submit(v)).then(function (msg) {
        handle.setBusy(false);
        if (msg) { clearSecrets(); handle.setError(msg); return; }
        clearSecrets();
        handle.close(v);
      }, function () {
        handle.setBusy(false);
        clearSecrets();
        handle.setError('The request may not have applied.');
      });
    }
    var handle = show({
      title: o.title,
      nodes: nodes,
      note: o.note,
      danger: !!o.danger,
      actions: [
        { label: o.cancelLabel || 'Cancel', value: 'cancel', kind: 'default', autofocus: !!o.danger },
        { label: o.submitLabel || 'Save', value: 'submit', kind: o.danger ? 'danger' : 'primary' }
      ],
      onAction: function (value, h) {
        if (value === 'cancel') { clearSecrets(); h.close(null); return; }
        attempt(h);
      }
    });
    // Enter in a single-line input submits; a textarea keeps its newline.
    handle.el.addEventListener('keydown', function (e) {
      if (e.key === 'Enter' && e.target && e.target.tagName === 'INPUT') {
        e.preventDefault();
        attempt(handle);
      }
    });
    if (inputs.length && !o.danger) inputs[0].input.focus();
    return handle.done;
  }

  function confirm(o) {
    o = o || {};
    return form({
      title: o.title, body: o.body, danger: !!o.danger,
      submitLabel: o.confirmLabel || 'Confirm', cancelLabel: o.cancelLabel
    }).then(function (v) { return v !== null; });
  }

  window.YuzuDialog = { confirm: confirm, form: form, request: request };
})();
