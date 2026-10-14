/* Access pages: client glue (Phase 2). Delegated listeners only; nothing inline.
 *
 *  - [data-act] buttons are dispatched to ACTS[name]. Mutations go through YuzuDialog
 *    (confirm / form / request), which handles the MFA step-up and its single replay.
 *  - [data-act="reload"][data-target=<id>]  re-fetches the panel's data-src into itself.
 *  - htmx:responseError / htmx:sendError on any [data-denied] panel: the gate's 401/403 and
 *    any other non-2xx become an in-panel note (text from the panel's own data attributes, so
 *    the sentences live in one place, in C++). All text goes in with textContent.
 *
 * Every stored string that reaches a request path goes through seg(), which percent-encodes
 * it AND refuses a dot segment: a browser resolves "." and ".." (even as %2e) away, so
 * encodeURIComponent alone would let a value of ".." walk up the path.
 */
(function () {
  'use strict';

  function el(tag, cls, text) {
    var n = document.createElement(tag);
    if (cls) n.className = cls;
    if (text !== undefined) n.textContent = text;
    return n;
  }

  // ---- panel states ----

  function denied(target) {
    var box = el('div', 'empty');
    box.appendChild(el('b', null, 'Not available to your account'));
    box.appendChild(el('span', null, target.dataset.denied || ''));
    target.replaceChildren(box);
  }

  function unavailable(target) {
    var box = el('div', 'failbox');
    box.setAttribute('role', 'alert');
    var msg = el('div');
    msg.appendChild(el('b', null, 'This panel could not be loaded.'));
    msg.appendChild(document.createElement('br'));
    msg.appendChild(el('span', 'guard', target.dataset.unavailable || ''));
    var end = el('div', 'end');
    var btn = el('button', 'btn sm', 'Retry');
    btn.type = 'button';
    btn.dataset.act = 'reload';
    btn.dataset.target = target.id;
    end.appendChild(btn);
    box.appendChild(msg);
    box.appendChild(end);
    target.replaceChildren(box);
  }

  function reload(id) {
    var t = document.getElementById(id);
    if (t && t.dataset.src) htmx.ajax('GET', t.dataset.src, { target: '#' + t.id });
  }

  function reloadDetail(username) {
    var t = document.getElementById('acc-detail');
    if (!t) return;
    var url = t.dataset.src + (username ? '?username=' + encodeURIComponent(username) : '');
    htmx.ajax('GET', url, { target: '#acc-detail' });
  }

  // ---- request paths ----

  // One path segment from a stored string, or null when it cannot be sent safely.
  function seg(s) {
    s = String(s === undefined || s === null ? '' : s);
    if (s === '' || /^\.+$/.test(s)) return null;
    return encodeURIComponent(s);
  }

  // ---- feedback ----

  function say(kind, text) {
    var ok = document.getElementById('acc-msg');
    var bad = document.getElementById('acc-alert');
    if (ok) ok.textContent = kind === 'ok' ? text : '';
    if (bad) bad.textContent = kind === 'bad' ? text : '';
  }

  function audit(r) {
    if (r.auditFailed)
      say('bad', 'The action succeeded but its audit record could not be written. Report this to your administrator.');
  }

  // The state is unknown after a 5xx or a dropped connection: say so, and reload.
  function unknown(r) { return r.status === 0 || r.status >= 500; }

  function failure(r) {
    var text = r.message || ('The request was refused (HTTP ' + r.status + ').');
    return unknown(r) ? text + ' The change may or may not have been applied; the lists have been reloaded.' : text;
  }

  // ---- actions ----

  var ACTS = {};

  // POST/DELETE and report. `done()` runs after a success; the panels reload after any
  // outcome that leaves the state unknown.
  function mutate(method, url, opts, okText, done) {
    return window.YuzuDialog.request(method, url, opts).then(function (r) {
      if (r.ok) {
        say('ok', okText + (r.warning ? ' ' + r.warning : ''));
        audit(r);
        done();
        return r;
      }
      say('bad', failure(r));
      if (unknown(r)) done();
      return r;
    });
  }

  function reloadBoth() { reload('acc-users'); reloadDetail(''); }

  ACTS.add = function () {
    return window.YuzuDialog.form({
      title: 'Add user',
      fields: [
        { name: 'username', label: 'Username', type: 'text', autocomplete: 'off', required: true, maxlength: 64 },
        { name: 'password', label: 'Password', type: 'password', autocomplete: 'new-password', required: true }
      ],
      note: 'New accounts start as User. Set the account role afterwards.',
      submitLabel: 'Add user',
      // The POST runs inside the dialog, so a refusal (duplicate name, weak password) keeps
      // it open and nobody retypes the password.
      submit: function (v) {
        return window.YuzuDialog.request('POST', '/api/settings/users',
          { form: { username: v.username.trim(), password: v.password } }).then(function (r) {
          if (r.ok) return null;
          if (unknown(r)) reload('acc-users');
          return failure(r);
        });
      }
    }).then(function (v) {
      if (v) { say('ok', 'Added ' + v.username.trim() + '.'); reload('acc-users'); }
    });
  };

  ACTS.remove = function (btn) {
    var name = btn.dataset.username, s = seg(name);
    if (!s) return say('bad', 'That account name cannot be used in a request.');
    return window.YuzuDialog.confirm({
      title: 'Remove user',
      body: ['Remove user "' + name + '"?',
             'Their sessions and API tokens are revoked first. The account stays out of the list afterwards.'],
      confirmLabel: 'Remove user', danger: true
    }).then(function (ok) {
      if (ok) return mutate('DELETE', '/api/settings/users/' + s, {}, 'Removed ' + name + '.', reloadBoth);
    });
  };

  ACTS.role = function (btn) {
    var name = btn.dataset.username, s = seg(name);
    var sel = document.getElementById('acc-role');
    var role = sel ? sel.value : '';
    if (!s || (role !== 'admin' && role !== 'user')) return say('bad', 'Choose Admin or User.');
    return window.YuzuDialog.confirm({
      title: 'Change account role',
      body: ['Set the account role of "' + name + '" to ' + role + '?', 'They are signed out of the dashboard.'],
      confirmLabel: 'Change role'
    }).then(function (ok) {
      if (ok) return mutate('POST', '/api/settings/users/' + s + '/role', { json: { role: role } },
        'Changed the account role of ' + name + ' to ' + role + '.',
        function () { reload('acc-users'); reloadDetail(name); });
    });
  };

  ACTS.revoke = function (btn) {
    var name = btn.dataset.username;
    if (!name) return;
    return window.YuzuDialog.confirm({
      title: 'Revoke sessions',
      body: 'Force "' + name + '" to log in again? Active dashboard sessions will end immediately. Their API tokens are NOT revoked.',
      confirmLabel: 'Revoke sessions', danger: true
    }).then(function (ok) {
      // A query value, not a path segment: encodeURIComponent is the right encoder here.
      if (ok) return mutate('DELETE', '/api/v1/sessions?username=' + encodeURIComponent(name), {},
        'Revoked the sessions of ' + name + '.', function () {});
    });
  };

  ACTS.reload = function (btn) { reload(btn.dataset.target); };

  document.addEventListener('click', function (e) {
    var b = e.target.closest('[data-act]');
    if (!b || !Object.prototype.hasOwnProperty.call(ACTS, b.dataset.act)) return;
    var p = ACTS[b.dataset.act](b);
    // A second click while a dialog is open rejects ('dialog busy'); that is not an error.
    if (p && p.catch) p.catch(function () {});
  });

  document.body.addEventListener('htmx:responseError', function (e) {
    var t = e.detail.target;
    if (!t || !t.hasAttribute('data-denied')) return;
    var s = e.detail.xhr.status;
    if (s === 401) { location.assign('/login'); return; }
    if (s === 403) denied(t); else unavailable(t);
  });

  document.body.addEventListener('htmx:sendError', function (e) {
    var t = e.detail.target;
    if (t && t.hasAttribute('data-denied')) unavailable(t);
  });
})();
