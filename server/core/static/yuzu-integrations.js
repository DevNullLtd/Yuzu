// Yuzu System > Integrations page script.
//
// Delegated listeners only. No inline handlers (the CSP blocks `hx-on`) and no eval; text
// that came from the server reaches the DOM only through textContent. The panels are
// server-rendered fragments that htmx loads and swaps; this file adds what htmx has no
// CSP-safe equivalent for: the toast host, error feedback for refused requests, and the
// MCP save confirm that depends on the state the form is about to save.
(function () {
  'use strict';

  function toast(message, level) {
    var c = document.getElementById('toast-container');
    if (!c) return;
    var t = document.createElement('div');
    t.className = 'toast toast-' + (level || 'info');
    t.textContent = message;
    c.appendChild(t);
    setTimeout(function () { t.remove(); }, level === 'error' ? 8000 : 4000);
  }

  // The MCP save answers with `HX-Trigger: {"showToast": {...}}`.
  document.body.addEventListener('showToast', function (e) {
    var d = e.detail || {};
    toast(d.message || 'Done', d.level || 'success');
  });

  // htmx does not swap a 4xx/5xx body, so a refused save would otherwise be silent. The
  // server's own message is shown; a lapsed session goes to sign-in.
  document.body.addEventListener('htmx:responseError', function (e) {
    var x = e.detail && e.detail.xhr;
    if (!x) return;
    if (x.status === 401) { window.location.href = '/login'; return; }
    var msg = '';
    try {
      var d = JSON.parse(x.responseText);
      msg = (d && d.error && d.error.message) || (d && typeof d.error === 'string' ? d.error : '');
    } catch (err) { /* not JSON: fall back to the status */ }
    toast(msg || ('The server answered ' + x.status + '.'), 'error');
  });

  // MCP Save: the question depends on the state being saved (off, read-only, or full access).
  // The three texts ride on the form as data attributes; the form's own hx-confirm is the
  // fallback where this script is not loaded.
  document.body.addEventListener('htmx:confirm', function (e) {
    var f = e.detail && e.detail.elt;
    if (!f || f.id !== 'mcp-form') return;
    // A markup change that drops a radio group must not leave Save dead: fall through to
    // the form's own hx-confirm instead of cancelling the request.
    if (!f.elements.enabled || !f.elements.read_only) return;
    e.preventDefault();
    var enabled = f.elements.enabled.value === 'true';
    var readOnly = f.elements.read_only.value === 'true';
    var q = !enabled ? f.dataset.confirmOff : (readOnly ? f.dataset.confirmReadonly : f.dataset.confirmFull);
    if (window.confirm(q)) e.detail.issueRequest(true);
  });
})();
