/* Groups and enrolment page: client glue. Delegated listeners only; no inline handlers, no htmx eval attributes.
 * All server-derived text goes in with textContent.
 *
 *  - showToast (HX-Trigger from the enrolment routes): a toast. Error toasts stay until closed.
 *  - htmx:responseError / htmx:sendError on a panel's OWN load ([data-denied] panel, GET, the
 *    panel itself as source): 401 -> /login, 403 -> the panel's denied note, anything else ->
 *    a failbox with Retry. The panel is replaced because its content is now unknown.
 *  - The same two events on anything else (a mutation button or form in a panel): the list
 *    stays and a persistent error toast says why. 401 -> /login. A response that already
 *    carries a toast in HX-Trigger is not toasted a second time.
 *  - htmx:beforeSwap on a 409 with an HTML body (a stale row; the body is the refreshed list):
 *    the body is swapped in, which htmx does not do for any 4xx by default.
 *  - [data-copy-token]: copy the sibling <code> to the clipboard.
 *  - [data-token-form]: the "unlimited, never expires" warning follows the two limit fields.
 *  - htmx:confirm on [data-rule-form]: the server's Add-rule question, plus a sentence when
 *    the typed rule matches every agent.
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
    btn.dataset.gact = 'reload';
    btn.dataset.target = target.id;
    end.appendChild(btn);
    box.appendChild(msg);
    box.appendChild(end);
    target.replaceChildren(box);
  }

  // True only for the panel's own GET (load, SSE or refresh trigger, or Retry), never for a
  // button in it: htmx fires these events on the source element, and the panel is its own
  // source and target only when it asked for itself.
  function ownLoad(e) {
    var t = e.detail && e.detail.target;
    var cfg = e.detail && e.detail.requestConfig;
    return !!t && t === e.target && t.hasAttribute('data-denied') && !!cfg && cfg.verb === 'get';
  }

  // Source = the panel so a failed Retry is an own load too (a 401 on retry still signs out).
  function reload(panel) {
    if (panel && panel.dataset.src) htmx.ajax('GET', panel.dataset.src, { source: panel, target: panel });
  }

  // True when the response already carries a toast in HX-Trigger: the user has been told.
  function serverToasted(xhr) {
    var h = xhr && xhr.getResponseHeader ? xhr.getResponseHeader('HX-Trigger') : null;
    return !!h && h.indexOf('showToast') !== -1;
  }

  var STALE = 'That changed since you loaded it - the list has been refreshed';
  var REFUSED = { 403: 'Not allowed', 409: STALE };

  // A request from inside a panel that the server refused (status) or that never arrived
  // (status 0), other than the panel's own load. The list is left as it is and a persistent
  // toast says what went wrong. Requests from outside the panels (the shell's sign-out) are
  // not ours.
  function mutationFailed(e, status) {
    if (!e.target.closest || !e.target.closest('[data-denied]')) return;
    if (status === 401) { location.assign('/login'); return; }
    if (serverToasted(e.detail.xhr)) return;
    toast(status === 0 ? 'Could not reach the server'
                       : REFUSED[status] || 'The server could not do that (HTTP ' + status + ')', 'error');
    if (status === 409) reload(e.target.closest('[data-denied]'));
  }

  // A 409 on an enrolment action means the row had already changed, and its body is the
  // refreshed list. htmx drops every 4xx body by default; this one is shown, so the stale
  // row goes away (the toast comes from the response, or from here if it carried none).
  document.body.addEventListener('htmx:beforeSwap', function (e) {
    var d = e.detail;
    if (d.xhr.status !== 409 || !d.target || !d.target.closest || !d.target.closest('[data-denied]')) return;
    if ((d.xhr.getResponseHeader('Content-Type') || '').indexOf('text/html') === -1) return;
    d.shouldSwap = true;
    d.isError = false;
    if (!serverToasted(d.xhr)) toast(STALE, 'error');
  });

  document.body.addEventListener('showToast', function (e) {
    var d = e.detail || {};
    toast(d.message, d.level);
  });

  document.body.addEventListener('htmx:responseError', function (e) {
    var s = e.detail.xhr.status;
    if (!ownLoad(e)) { mutationFailed(e, s); return; }
    if (s === 401) { location.assign('/login'); return; }
    if (s === 403) denied(e.detail.target); else unavailable(e.detail.target);
  });

  document.body.addEventListener('htmx:sendError', function (e) {
    if (ownLoad(e)) unavailable(e.detail.target); else mutationFailed(e, 0);
  });

  document.addEventListener('click', function (e) {
    var r = e.target.closest('[data-gact="reload"]');
    if (r) { reload(document.getElementById(r.dataset.target)); return; }
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

  // The question is the one the server wrote on the form (e.detail.question); this adds the
  // one fact only the typed value knows.
  document.body.addEventListener('htmx:confirm', function (e) {
    var f = e.detail.elt;
    if (!f || !f.matches || !f.matches('[data-rule-form]') || !e.detail.question) return;
    e.preventDefault();
    var type = f.querySelector('[name="type"]').value;
    var value = f.querySelector('[name="value"]').value.trim();
    var q = e.detail.question;
    if (matchesEverything(type, value)) q += ' This matches every agent.';
    if (window.confirm(q)) e.detail.issueRequest(true);
  });
})();
