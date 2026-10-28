/* Tokens and principals page: client glue (Phase 2, read side; yuzu-tokens-actions.js holds the writes).
 *
 * Delegated listeners keyed on data-tk; nothing inline, no HTML strings, no storage.
 *   tokens-state       Active / All toggle: reload the token list
 *   principal-select   load one principal's detail into #side-principal
 *   reload             Retry on a failed panel: re-fetch the target's data-src
 *
 * Each panel loads on its own and is gated by its own fragment (quiet probes: a refused cookie
 * session writes no audit row). The no-admin REST check runs only when the principals fragment
 * says the caller holds AuditLog:Read (data-check="1"), because that route's own gate is loud.
 * All server text goes in with textContent.
 */
(function () {
  'use strict';

  var TOKENS = '/fragments/access/tokens/list';
  var NO_ADMIN = '/api/v1/engine-principals/audit/no-admin';
  var AUDIT_FAILED = 'An audit record for this read could not be saved. The data shown is still current.';
  var tokensState = 'active';
  var lastPrincipalId = '';

  function el(tag, cls, text) {
    var n = document.createElement(tag);
    if (cls) n.className = cls;
    if (text !== undefined) n.textContent = text;
    return n;
  }
  function byId(id) { return document.getElementById(id); }

  function deniedBox(target) {
    var box = el('div', 'empty');
    box.appendChild(el('b', null, 'Not available to your account'));
    box.appendChild(el('span', null, target.dataset.denied || ''));
    target.replaceChildren(box);
  }

  function unavailableBox(target) {
    var box = el('div', 'failbox');
    box.setAttribute('role', 'alert');
    var msg = el('div');
    msg.appendChild(el('b', null, 'This panel could not be loaded.'));
    msg.appendChild(document.createElement('br'));
    msg.appendChild(el('span', 'guard', target.dataset.unavailable || ''));
    var end = el('div', 'end');
    var btn = el('button', 'btn sm', 'Retry');
    btn.type = 'button';
    btn.dataset.tk = 'reload';
    btn.dataset.target = target.id;
    end.appendChild(btn);
    box.appendChild(msg);
    box.appendChild(end);
    target.replaceChildren(box);
  }

  function ajax(url, targetId) {
    htmx.ajax('GET', url, { target: '#' + targetId });
  }

  function setNote(nodes) {
    var s = byId('principals-note');
    if (!s) return;
    s.replaceChildren.apply(s, nodes);
  }

  // ---- no-admin strip (JSON route, plain fetch, textContent only) ----------------------
  var REASONS = {
    admin_role: 'holds the Administrator role',
    system_role: 'holds a built-in role',
    wildcard_grant: 'holds every permission (a permitted custom role)',
    orphan_grant: 'holds a grant but has no active principal record'
  };
  // Only these two reasons mean the write-path guard was bypassed. A wildcard or orphan
  // grant is reported for review and is not an incident on its own.
  var INCIDENT_REASONS = { admin_role: true, system_role: true };

  function noteBox(text) {
    var n = el('div', 'note');
    n.textContent = text;
    return n;
  }

  function checkNoAdmin(count) {
    setNote([noteBox('Checking engine principal roles...')]);
    var ctl = typeof AbortSignal !== 'undefined' && AbortSignal.timeout ? AbortSignal.timeout(10000) : undefined;
    fetch(NO_ADMIN, { credentials: 'same-origin', cache: 'no-store', signal: ctl })
      .then(function (r) {
        if (r.status === 401) { location.assign('/login'); return null; }
        if (r.status === 403) {
          setNote([noteBox('Running this check needs the AuditLog:Read permission, or it could not be confirmed.')]);
          return null;
        }
        if (!r.ok) {
          setNote([noteBox('Could not verify. The role reference data was unavailable. This is not a clean result.')]);
          return null;
        }
        return r.json();
      })
      .then(function (j) {
        if (!j) return;
        var d = j && j.data;
        if (!d || typeof d.ok !== 'boolean' || !Array.isArray(d.violations)) {
          setNote([noteBox('Could not verify. The response was not understood. This is not a clean result.')]);
          return;
        }
        if (d.ok && d.violations.length === 0) {
          // The auditor reports no count, so the listed total is stated as listed, not as checked.
          setNote([noteBox('No violations found in the roles and grants the server could read. ' +
                           count + (count === '1' ? ' principal is' : ' principals are') + ' listed below.')]);
          return;
        }
        var box = el('div', 'failbox');
        box.setAttribute('role', 'alert');
        var body = el('div');
        var incident = d.violations.some(function (v) { return INCIDENT_REASONS[v.reason] === true; });
        body.appendChild(el('b', null, incident
          ? d.violations.length + ' finding(s), including administrator-class authority.'
          : d.violations.length + ' finding(s) to review.'));
        d.violations.forEach(function (v) {
          var line = el('div', 'guard');
          line.textContent = String(v.principal_id) + ' ' + (REASONS[v.reason] || 'violates the no-admin rule') +
            (v.role ? ' (' + String(v.role) + ')' : '');
          body.appendChild(line);
        });
        if (incident) {
          body.appendChild(el('div', 'guard',
            'This means the write-path guard was bypassed. Treat it as a security incident.'));
        }
        if (d.violations.some(function (v) { return v.reason === 'wildcard_grant'; })) {
          body.appendChild(el('div', 'guard',
            'A wildcard custom role is permitted by design under the maintainer ruling. Review whether each such grant is intended.'));
        }
        if (d.violations.some(function (v) { return v.reason === 'orphan_grant'; })) {
          body.appendChild(el('div', 'guard',
            'A grant with no active principal record is unexpected. Find out how it was created.'));
        }
        box.appendChild(body);
        setNote([box]);
      })
      .catch(function () {
        setNote([noteBox('Could not reach the server.')]);
      });
  }

  // ---- load handling -------------------------------------------------------------------
  document.body.addEventListener('htmx:afterSwap', function (e) {
    var t = e.detail.target;
    if (!t) return;
    if (t.id === 'principals-body') {
      var root = byId('principals-root');
      var n = root ? root.dataset.count : '';
      if (n === '' || n === undefined) { setNote([]); return; }
      if (root.dataset.check === '1') checkNoAdmin(n);
      else setNote([noteBox('Running the no-administrator check needs the AuditLog:Read permission, or it could not be confirmed.')]);
    }
  });

  // A fragment whose audit row could not be saved still renders; say so, persistently.
  document.body.addEventListener('htmx:afterRequest', function (e) {
    var xhr = e.detail.xhr;
    if (!xhr || xhr.getResponseHeader('Sec-Audit-Failed') !== 'true') return;
    if (byId('audit-failed')) return;
    var b = el('div', 'failbox', AUDIT_FAILED);
    b.id = 'audit-failed';
    b.setAttribute('role', 'alert');
    var main = document.querySelector('main.page');
    if (main) main.insertBefore(b, main.children[1] || null);
  });

  document.body.addEventListener('htmx:responseError', function (e) {
    var t = e.detail.target;
    if (!t || !t.hasAttribute('data-denied')) return;
    var s = e.detail.xhr.status;
    if (s === 401) { location.assign('/login'); return; }
    if (s === 403) deniedBox(t); else unavailableBox(t);
  });

  document.body.addEventListener('htmx:sendError', function (e) {
    var t = e.detail.target;
    if (!t || !t.hasAttribute('data-denied')) return;
    unavailableBox(t);
  });

  document.addEventListener('click', function (e) {
    var b = e.target.closest('[data-tk]');
    if (!b) return;
    var act = b.dataset.tk;
    if (act === 'tokens-state') {
      tokensState = b.dataset.state === 'all' ? 'all' : 'active';
      ajax(TOKENS + '?state=' + tokensState, 'tokens-body');
    } else if (act === 'principal-select') {
      var side = byId('side-principal');
      var id = b.dataset.principalId;
      if (!side || !id) return;
      lastPrincipalId = id;
      document.querySelectorAll('#principals-body tr.sel').forEach(function (r) { r.classList.remove('sel'); });
      var row = b.closest('tr');
      if (row) row.classList.add('sel');
      ajax(side.dataset.src + '?id=' + encodeURIComponent(id), 'side-principal');
    } else if (act === 'reload') {
      var t = byId(b.dataset.target);
      if (!t || !t.dataset.src) return;
      // Keep the caller's place: the active filter, or the selected principal.
      if (t.id === 'tokens-body') ajax(TOKENS + '?state=' + tokensState, t.id);
      else if (t.id === 'side-principal' && lastPrincipalId)
        ajax(t.dataset.src + '?id=' + encodeURIComponent(lastPrincipalId), t.id);
      else ajax(t.dataset.src, t.id);
    }
  });
})();
