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

  // ---- role assignments ----

  var NAME = /^[A-Za-z0-9._-]+$/;

  ACTS.assign = function (btn) {
    var roles = (btn.dataset.roles || '').split(',').filter(Boolean);
    if (!roles.length) return;
    var created = null;
    return window.YuzuDialog.form({
      title: 'Assign role',
      fields: [
        { name: 'principal_id', label: 'Username', type: 'text', autocomplete: 'off', required: true,
          hint: 'The account does not need to exist yet.' },
        { name: 'role', label: 'Role', type: 'select', value: roles.indexOf('Viewer') >= 0 ? 'Viewer' : roles[0],
          options: roles.map(function (r) { return { value: r, label: r }; }),
          hint: 'ITServiceOwner is not offered: it needs a management group.' }
      ],
      submitLabel: 'Assign role',
      // The role is a path segment: only a value the server offered, and only as a vetted segment.
      validate: function (v) { return roles.indexOf(v.role) >= 0 && seg(v.role) ? null : 'Choose one of the listed roles.'; },
      submit: function (v) {
        var id = v.principal_id.trim();
        return window.YuzuDialog.request('POST', '/api/v1/rbac/roles/' + seg(v.role) + '/assignments',
          { json: { principal_type: 'user', principal_id: id } }).then(function (r) {
          if (r.ok) { created = r; return null; }
          if (unknown(r)) reload('acc-assignments');
          return failure(r);
        });
      }
    }).then(function (v) {
      if (!v) return;
      var d = created && created.data && created.data.data;
      say('ok', 'Role assigned.' + (d && d.target_provisioned === 'false' ? ' The account has not signed in yet.' : '') +
                ' It may take a moment to appear on other servers.');
      reload('acc-assignments');
    });
  };

  ACTS.unassign = function (btn) {
    var tr = btn.closest('tr');
    var role = tr && tr.dataset.role, id = tr && tr.dataset.principalId;
    // Both land in the request path: a plain segment, re-checked here whatever the server drew.
    if (!role || !id || !NAME.test(role) || !NAME.test(id) || !seg(role) || !seg(id))
      return say('bad', 'That assignment cannot be removed from here.');
    return window.YuzuDialog.confirm({
      title: 'Remove role assignment',
      body: 'Remove ' + role + ' from "' + id + '"? They keep their account and any other roles.',
      confirmLabel: 'Remove', danger: true
    }).then(function (ok) {
      if (!ok) return;
      return window.YuzuDialog.request('DELETE', '/api/v1/rbac/roles/' + seg(role) + '/assignments/' + seg(id), {})
        .then(function (r) {
          if (r.ok) { say('ok', 'Removed ' + role + ' from ' + id + '. It may take a moment to disappear on other servers.'); audit(r); }
          else say('bad', failure(r));
          // A 5xx can mean the change took effect: the list always shows what the store holds.
          if (r.ok || unknown(r)) reload('acc-assignments');
        });
    });
  };

  // ---- derived cells ----
  // The Users "RBAC roles" and Roles "Assigned" cells are filled from the assignments table. They
  // read "Not shown" unless that table was read in full: a denied, unreadable or capped table
  // never produces a count, and 0 is written only when the table was read.
  function derive() {
    var tbl = document.querySelector('#acc-assignments table[data-assignments]');
    var full = !!tbl && tbl.dataset.capped === '0';
    var byUser = new Map(), byRole = new Map();
    if (full) {
      tbl.querySelectorAll('tbody tr[data-role]').forEach(function (tr) {
        var r = tr.dataset.role;
        byRole.set(r, (byRole.get(r) || 0) + 1);
        if (tr.dataset.principalType !== 'user') return;
        if (!byUser.has(tr.dataset.principalId)) byUser.set(tr.dataset.principalId, []);
        byUser.get(tr.dataset.principalId).push(r);
      });
    }
    document.querySelectorAll('[data-rbac-for]').forEach(function (td) {
      var roles = byUser.get(td.dataset.rbacFor) || [];
      td.replaceChildren();
      if (!full) { td.textContent = 'Not shown'; return; }
      if (!roles.length) { td.appendChild(el('span', 'hint', 'None')); return; }
      roles.forEach(function (r, i) {
        if (i) td.appendChild(document.createTextNode(' '));
        td.appendChild(el('span', 'pill tag', r));
      });
    });
    document.querySelectorAll('[data-assigned-for]').forEach(function (td) {
      td.textContent = full ? String(byRole.get(td.dataset.assignedFor) || 0) : 'Not shown';
    });
  }

  document.body.addEventListener('htmx:afterSwap', function (e) {
    var id = e.detail.target && e.detail.target.id;
    if (id === 'acc-users' || id === 'acc-roles' || id === 'acc-assignments') derive();
  });

  // ---- your account ----

  ACTS['pw-change'] = function () {
    return window.YuzuDialog.form({
      title: 'Change password',
      fields: [
        { name: 'current_password', label: 'Current password', type: 'password', autocomplete: 'current-password', required: true },
        { name: 'new_password', label: 'New password', type: 'password', autocomplete: 'new-password', required: true },
        { name: 'confirm', label: 'Confirm new password', type: 'password', autocomplete: 'new-password', required: true }
      ],
      note: 'Changing your password ends all of your sessions; you sign in again.',
      submitLabel: 'Change password',
      validate: function (v) { return v.new_password === v.confirm ? null : 'The new passwords do not match.'; },
      submit: function (v) {
        return window.YuzuDialog.request('POST', '/api/v1/users/me/password',
          { json: { current_password: v.current_password, new_password: v.new_password } }).then(function (r) {
          return r.ok ? null : failure(r);
        });
      }
    }).then(function (v) { if (v) location.assign('/login'); });
  };

  ACTS['goto-login'] = function () { location.assign('/login'); };

  ACTS['signout-all'] = function () {
    return window.YuzuDialog.confirm({
      title: 'Sign out everywhere',
      body: 'Sign out of every device AND revoke every API token you own? You will be redirected to the login page; ' +
            'any of your CI/CD or automation tokens will need to be re-issued.',
      confirmLabel: 'Sign out everywhere', danger: true
    }).then(function (ok) {
      if (!ok) return;
      return window.YuzuDialog.request('DELETE', '/api/v1/sessions/me', {}).then(function (r) {
        var d = r.data && r.data.data;
        var notes = [];
        // A "success" that hides a failed token revoke is the stolen-laptop failure: say so and
        // make the user choose to continue.
        if (r.ok && d && d.api_tokens_db_persisted === false) notes.push('Your sessions ended but an API token may still be active.');
        if (r.ok && d && d.db_persisted === false) notes.push('Your sessions may not all have ended.');
        if (r.auditFailed) notes.push('The audit record for this could not be written. Report this to your administrator.');
        if ((r.ok || r.status === 401) && !notes.length) { location.assign('/login'); return; }
        if (!r.ok && r.status !== 401) { say('bad', failure(r)); return; }
        say('bad', notes.join(' '));
        var msg = document.getElementById('acc-msg');
        if (msg) {
          var go = el('button', 'btn sm', 'Go to sign in');
          go.type = 'button';
          go.dataset.act = 'goto-login';
          msg.replaceChildren(go);
        }
      });
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
    if (t.id === 'acc-assignments') derive();
  });

  document.body.addEventListener('htmx:sendError', function (e) {
    var t = e.detail.target;
    if (t && t.hasAttribute('data-denied')) unavailable(t);
    if (t && t.id === 'acc-assignments') derive();
  });
})();
