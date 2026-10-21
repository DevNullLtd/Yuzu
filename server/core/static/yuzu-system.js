/* yuzu-system.js -- the System pages' write helper (window.YuzuSystem).
 *
 * The small part the Plugins, Certificates and Developer controllers share, kept out of the
 * shared dialog module (yuzu-dialog.js, which only offers a 15 s JSON request). Nothing here
 * writes markup: every string a caller shows goes through textContent.
 *
 *   YuzuSystem.send(method, url, {json, body, contentType, headers, timeoutMs})
 *       -> Promise<{ok, status, data, message, remediation, reason, auditFailed, network}>
 *          never rejects; a same-origin fetch with credentials, cache: 'no-store' and a bounded
 *          wait (default 15 s; a slow server operation passes a longer timeoutMs)
 *   YuzuSystem.failText(res, fallback) -> the sentence to show for a failed result
 *   YuzuSystem.bytes(s)                -> UTF-8 byte length (HTML maxlength counts UTF-16 units)
 *   YuzuSystem.toast(message, level)   -> the page's showToast, when it has one
 *
 * A server error body is read as {error:{message, remediation, reason}} (the A4 envelope) or
 * {error:"text"}; those server-authored strings are the only text taken from a response.
 */
(function () {
  'use strict';

  var encoder = new TextEncoder();

  function bytes(s) { return encoder.encode(String(s)).length; }

  function str(v) { return typeof v === 'string' ? v : ''; }

  function summarise(status, ok, data, auditHeader) {
    var err = data && data.error;
    var message = '', remediation = '', reason = '';
    if (typeof err === 'string') {
      message = err;
    } else if (err && typeof err === 'object') {
      message = str(err.message);
      remediation = str(err.remediation);
      reason = str(err.reason);
    }
    return {
      ok: ok, status: status, data: data, message: message, remediation: remediation,
      reason: reason, network: false,
      auditFailed: auditHeader || !!(data && data.audit_emitted === false)
    };
  }

  function networkFailure(message) {
    return { ok: false, status: 0, data: null, message: message, remediation: '', reason: '',
             network: true, auditFailed: false };
  }

  function send(method, url, opts) {
    opts = opts || {};
    var target;
    try {
      var u = new URL(String(url), location.href);
      if (u.origin !== location.origin) throw new Error('cross-origin');
      target = u.href;
    } catch (e) {
      return Promise.resolve(networkFailure('Only same-origin requests are allowed.'));
    }
    var headers = {};
    if (opts.headers) Object.keys(opts.headers).forEach(function (k) { headers[k] = opts.headers[k]; });
    var init = { method: method, credentials: 'same-origin', cache: 'no-store', headers: headers };
    if (opts.json !== undefined) {
      headers['Content-Type'] = 'application/json';
      init.body = JSON.stringify(opts.json);
    } else if (opts.body !== undefined) {
      if (opts.contentType) headers['Content-Type'] = opts.contentType;
      init.body = opts.body;
    }
    try { init.signal = AbortSignal.timeout(opts.timeoutMs || 15000); } catch (e) { /* no timeout available */ }
    return fetch(target, init).then(function (r) {
      var ct = r.headers.get('Content-Type') || '';
      var parsed = ct.indexOf('application/json') >= 0 ?
        r.json().catch(function () { return null; }) : Promise.resolve(null);
      return parsed.then(function (data) {
        return summarise(r.status, r.ok, data, r.headers.get('Sec-Audit-Failed') === 'true');
      });
    }).catch(function () {
      // A timeout or dropped connection after the request left says nothing about whether the
      // server applied it, so it is never reported as "nothing happened".
      return networkFailure('The request did not complete and may have applied.');
    });
  }

  function failText(res, fallback) {
    if (res.status === 401) return 'Your session has ended. Sign in again.';
    return res.message || fallback || ('The request failed (' + res.status + ').');
  }

  function toast(message, level) {
    if (typeof window.showToast === 'function') window.showToast(message, level || 'info');
  }

  window.YuzuSystem = { send: send, failText: failText, bytes: bytes, toast: toast };
})();
