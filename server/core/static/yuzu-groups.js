/* Groups and enrolment page: client glue. Delegated listeners only; no inline handlers, no htmx eval attributes.
 * All server-derived text goes in with textContent.
 *
 *  - showToast (HX-Trigger from the enrolment routes): a toast. Error toasts stay until closed.
 *  - htmx:responseError / htmx:sendError on a LOAD-triggered fetch of a [data-denied] panel:
 *    401 -> /login, 403 -> the panel's denied note, anything else -> a failbox with Retry.
 *    A mutation's 4xx/5xx never reaches this: the list stays and the toast above reports it.
 *  - [data-copy-token]: copy the sibling <code> to the clipboard.
 *  - [data-token-form]: the "unlimited, never expires" warning follows the two limit fields.
 *  - htmx:confirm on [data-rule-form]: the Add-rule confirm names the match-everything case.
 */
(function () {
  'use strict';

  var TOAST_MS = { success: 4000, info: 4000, warning: 8000 };

  function el(tag, cls, text) {
    var n = document.createElement(tag);
    if (cls) n.className = cls;
    if (text !== undefined) n.textContent = text;
    return n;
  }

  function toast(message, level) {
    var box = document.getElementById('toast-container');
    if (!box) return;
    var lvl = TOAST_MS.hasOwnProperty(level) || level === 'error' ? level : 'info';
    var t = el('div', 'toast toast-' + lvl, String(message == null ? 'Done' : message));
    t.setAttribute('role', lvl === 'error' ? 'alert' : 'status');
    var close = el('button', 'btn-ghost', '×');
    close.type = 'button';
    close.setAttribute('aria-label', 'Dismiss');
    close.addEventListener('click', function () { t.remove(); });
    t.appendChild(close);
    box.appendChild(t);
    if (lvl !== 'error') setTimeout(function () { t.remove(); }, TOAST_MS[lvl]);
  }

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

  // True only for the panel's own GET (load, SSE or refresh trigger), never for a button in it.
  function ownLoad(e) {
    var t = e.detail && e.detail.target;
    var cfg = e.detail && e.detail.requestConfig;
    return !!t && t === e.target && t.hasAttribute('data-denied') && !!cfg && cfg.verb === 'get';
  }

  document.body.addEventListener('showToast', function (e) {
    var d = e.detail || {};
    toast(d.message, d.level);
  });

  document.body.addEventListener('htmx:responseError', function (e) {
    if (!ownLoad(e)) return;
    var s = e.detail.xhr.status;
    if (s === 401) { location.assign('/login'); return; }
    if (s === 403) denied(e.detail.target); else unavailable(e.detail.target);
  });

  document.body.addEventListener('htmx:sendError', function (e) {
    if (ownLoad(e)) unavailable(e.detail.target);
  });

  document.addEventListener('click', function (e) {
    var r = e.target.closest('[data-act="reload"]');
    if (r) {
      var t = document.getElementById(r.dataset.target);
      if (t && t.dataset.src) htmx.ajax('GET', t.dataset.src, { target: '#' + t.id });
      return;
    }
    var c = e.target.closest('[data-copy-token]');
    if (!c) return;
    var code = c.parentElement && c.parentElement.querySelector('code');
    if (!code) return;
    var done = function (text) {
      c.textContent = text;
      setTimeout(function () { c.textContent = 'Copy to Clipboard'; }, 2000);
    };
    if (!navigator.clipboard || !navigator.clipboard.writeText) { done('Copy failed. Select the text.'); return; }
    navigator.clipboard.writeText(code.textContent).then(
      function () { done('Copied!'); },
      function () { done('Copy failed. Select the text.'); });
  });

  // Unlimited-token warning: shown while both limit fields are empty or zero.
  document.addEventListener('input', function (e) {
    var f = e.target.closest('[data-token-form]');
    if (!f) return;
    var zero = function (n) {
      var i = f.querySelector('[name="' + n + '"]');
      var v = i ? i.value.trim() : '';
      return v === '' || /^0+$/.test(v);
    };
    var w = f.querySelector('[data-token-unlimited]');
    if (w) w.hidden = !(zero('max_uses') && zero('ttl_hours'));
  });

  // Mirrors enrolment::rule_matches_everything (enrolment_render.cpp): the server draws the
  // same warning on rules that already exist.
  function matchesEverything(type, value) {
    if (type === 'hostname_glob') return /^[*?]*\*[*?]*$/.test(value);
    if (type === 'ip_subnet') {
      var m = /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})\/0$/.exec(value);
      return !!m && m.slice(1).every(function (o) { return Number(o) <= 255; });
    }
    return false;
  }

  document.body.addEventListener('htmx:confirm', function (e) {
    var f = e.detail.elt;
    if (!f || !f.matches || !f.matches('[data-rule-form]')) return;
    e.preventDefault();
    var type = f.querySelector('[name="type"]').value;
    var value = f.querySelector('[name="value"]').value.trim();
    var q = 'Add this rule? Agents matching it join the fleet without approval.';
    if (type === 'hostname_glob') q += ' Hostnames are reported by the agent and are not verified.';
    if (matchesEverything(type, value)) q += ' This matches every agent.';
    if (window.confirm(q)) e.detail.issueRequest(true);
  });
})();
