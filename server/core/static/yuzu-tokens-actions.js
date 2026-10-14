/* Tokens and principals page: write actions (Phase 2).
 *
 * Every write is a call to an existing REST v1 route through YuzuDialog.request, so the route's
 * own step-up, validation and audit apply; the dashboard twins are not used. The dialog module
 * owns the step-up prompt, the audit-failed flag and the network-error sentence.
 *
 * Delegated click listener keyed on data-tk. Nothing inline, no HTML strings, no storage.
 *
 * One-time secrets: a secret exists in the DOM only in #reveal-secret, set with textContent. It is
 * never put in a URL, a data-* attribute, storage or a log, and the response object that carried
 * it is emptied the moment it is read. The strip has no timer: it stays until the operator says
 * "I have stored this", so an unsaved secret is never discarded on a clock. While it is showing,
 * minting another secret is refused rather than overwriting it.
 *
 * Every path built from a data-* value is checked against the charset its route accepts and then
 * percent-encoded with encodeURIComponent.
 */
(function () {
  'use strict';

  var D = window.YuzuDialog;
  if (!D) return;

  var API = '/api/v1/';
  var TOKENS = '/fragments/access/tokens/list';
  var DAY = 86400;
  // The server caps an MCP token at 90 days from its own clock; 2160 h plus page-measured
  // elapsed time can tip a few seconds over, so the form stops one hour short.
  var MCP_MAX_HOURS = 2159;
  var MAX_HOURS = 876000;
  var TOKEN_ID = /^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$/;
  var AUDIT_FAILED = 'The change was made, but its audit record could not be saved.';

  var secretShown = false;
  var nowBase = 0;
  var nowAt = 0;

  function el(tag, cls, text) {
    var n = document.createElement(tag);
    if (cls) n.className = cls;
    if (text !== undefined) n.textContent = text;
    return n;
  }
  function byId(id) { return document.getElementById(id); }
  function seg(v) { return encodeURIComponent(v); }
  function flash(text) { var f = byId('flash'); if (f) f.textContent = text || ''; }

  // ---- server clock -----------------------------------------------------------------------
  // expires_at is computed from the fragment's server time plus time elapsed on this page, so a
  // skewed workstation clock cannot mint a wrong lifetime. The server validates it anyway.
  document.body.addEventListener('htmx:afterSwap', function (e) {
    var t = e.detail && e.detail.target;
    if (!t || t.id !== 'tokens-body') return;
    var root = byId('tokens-root');
    nowBase = root ? Number(root.dataset.now) || 0 : 0;
    nowAt = performance.now();
  });
  function serverNow() { return nowBase ? Math.floor(nowBase + (performance.now() - nowAt) / 1000) : 0; }

  // ---- reloads ----------------------------------------------------------------------------
  function load(url, targetId) { htmx.ajax('GET', url, { target: '#' + targetId }); }
  function reloadTokens() {
    var on = document.querySelector('#tokens-body .seg .on');
    load(TOKENS + '?state=' + (on && on.dataset.state === 'all' ? 'all' : 'active'), 'tokens-body');
  }
  // ---- one-time reveal strip --------------------------------------------------------------
  function reveal(title, secret, hint) {
    var box = byId('reveal');
    var code = byId('reveal-secret');
    if (!box || !code) return;
    byId('reveal-title').textContent = title;
    byId('reveal-msg').textContent = 'Copy this secret now. It will not be shown again.' + (hint ? ' ' + hint : '');
    code.textContent = secret;
    code.hidden = false;
    byId('reveal-btns').hidden = false;
    var copy = box.querySelector('[data-tk="reveal-copy"]');
    copy.textContent = 'Copy';
    box.hidden = false;
    secretShown = true;
    copy.focus();
  }

  function clearReveal() {
    var code = byId('reveal-secret');
    if (code) { code.textContent = ''; code.hidden = true; }
    var btns = byId('reveal-btns');
    if (btns) btns.hidden = true;
    var msg = byId('reveal-msg');
    if (msg) msg.textContent = 'Secret cleared. It cannot be shown again.';
    secretShown = false;
  }

  function copySecret(btn) {
    var code = byId('reveal-secret');
    if (!code || !code.textContent) return;
    var done = function (label) { btn.textContent = label; };
    if (!navigator.clipboard || !navigator.clipboard.writeText) { done('Copy failed. Select the text.'); return; }
    navigator.clipboard.writeText(code.textContent).then(function () { done('Copied'); },
                                                         function () { done('Copy failed. Select the text.'); });
  }

  // True = blocked: minting another secret would overwrite one the operator has not stored.
  function blockedBySecret() {
    if (!secretShown) return false;
    flash('Confirm you have stored the secret above ("I have stored this") before creating another.');
    var stored = document.querySelector('[data-tk="reveal-stored"]');
    if (stored) stored.focus();
    return true;
  }

  // A secret on screen is not lost to a stray navigation, and never survives into bfcache.
  window.addEventListener('beforeunload', function (e) {
    if (secretShown) { e.preventDefault(); e.returnValue = ''; }
  });
  window.addEventListener('pagehide', function () { clearReveal(); });

  // The response is emptied as it is read, so the secret has one owner: the strip.
  function takeToken(r) {
    var d = r.data && r.data.data;
    var s = d && typeof d.token === 'string' ? d.token : '';
    r.data = null;
    return s;
  }
  function showOrExplain(title, secret, hint, missing) {
    if (secret) reveal(title, secret, hint);
    else flash(missing);
  }

  // ---- mutation plumbing ------------------------------------------------------------------
  function auditBanner() {
    if (byId('audit-failed')) return;
    var b = el('div', 'failbox', AUDIT_FAILED);
    b.id = 'audit-failed';
    b.setAttribute('role', 'alert');
    var main = document.querySelector('main.page');
    if (main) main.insertBefore(b, main.children[1] || null);
  }

  function why(r) { return r.message || 'The request failed (HTTP ' + r.status + ').'; }

  // One form-with-submit dialog: a refusal keeps the dialog open with the server's sentence, so
  // the operator does not retype. Resolves the response on success, null on cancel.
  function mutate(o) {
    var res = null;
    return D.form({
      title: o.title, body: o.body, note: o.note, fields: o.fields || [],
      submitLabel: o.submitLabel, danger: !!o.danger, validate: o.validate,
      submit: function (v) {
        var opts = {};
        var j = o.json ? o.json(v) : undefined;
        if (j !== undefined) opts.json = j;
        return D.request(o.method, o.path, opts).then(function (r) {
          if (!r.ok) {
            if (o.onFail) o.onFail(r);
            return why(r);
          }
          res = r;
          return null;
        });
      }
    }).then(function (v) {
      var r = res;
      res = null;
      if (v === null || !r) return null;
      if (r.auditFailed) auditBanner();
      if (r.warning) flash(r.warning);
      return r;
    }, function () { return null; });  // 'dialog busy': another dialog is open, do nothing
  }

  function wholeNumber(text, lo, hi) {
    var t = String(text).trim();
    if (!/^\d{1,15}$/.test(t)) return NaN;  // 15 digits stay inside Number's exact integers
    var n = parseInt(t, 10);
    return n >= lo && n <= hi ? n : NaN;
  }

  function overlapField() {
    return {
      name: 'overlap', label: 'Keep the old one valid for', type: 'select', value: String(7 * DAY),
      options: [1, 3, 7, 14, 30].map(function (d) {
        return { value: String(d * DAY), label: d + (d === 1 ? ' day' : ' days') };
      })
    };
  }

  function tokenPath(id, tail) {
    if (!TOKEN_ID.test(id || '')) { flash('This row cannot be changed from this page.'); return null; }
    return API + 'tokens/' + seg(id) + (tail || '');
  }
  // ---- API tokens -------------------------------------------------------------------------
  function tokenNew() {
    if (blockedBySecret()) return;
    mutate({
      title: 'New API token',
      note: 'The secret is shown once.',
      fields: [
        { name: 'name', label: 'Name', type: 'text', maxlength: 256, required: true },
        { name: 'type', label: 'Type', type: 'select', options: [
          { value: '', label: 'API' }, { value: 'readonly', label: 'MCP readonly' },
          { value: 'operator', label: 'MCP operator' }, { value: 'supervised', label: 'MCP supervised' }] },
        { name: 'hours', label: 'Expires after (hours)', type: 'text', inputmode: 'numeric',
          hint: 'Leave empty for no expiry. MCP tokens need 1 to ' + MCP_MAX_HOURS + ' hours.' }
      ],
      submitLabel: 'Create',
      validate: function (v) {
        var blank = String(v.hours).trim() === '';
        var h = blank ? 0 : wholeNumber(v.hours, 0, MAX_HOURS);
        if (isNaN(h)) return 'Hours must be a whole number.';
        if (v.type && (h < 1 || h > MCP_MAX_HOURS))
          return 'MCP tokens need a lifetime of 1 to ' + MCP_MAX_HOURS + ' hours.';
        if (h > 0 && !serverNow()) return 'The token list has not loaded yet. Reload the page.';
        return null;
      },
      method: 'POST', path: API + 'tokens',
      json: function (v) {
        var h = String(v.hours).trim() === '' ? 0 : parseInt(v.hours, 10);
        var body = { name: v.name.trim(), expires_at: h > 0 ? serverNow() + h * 3600 : 0 };
        if (v.type) body.mcp_tier = v.type;
        return body;
      }
    }).then(function (r) {
      if (!r) return;
      showOrExplain('API token created', takeToken(r), '',
        'The token was created but the response did not include it. Revoke it and create another.');
      reloadTokens();
    });
  }

  function tokenRotate(d) {
    if (blockedBySecret()) return;
    var path = tokenPath(d.tokenId, '/rotate');
    if (!path) return;
    mutate({
      title: 'Rotate API token',
      body: ['Create a replacement for "' + (d.name || d.tokenId) + '"? Both tokens stay valid until the overlap ends. ' +
             'Move your automation to the new secret, then use Confirm rotation to retire the old one.',
             'Rotating again within 2 minutes returns the same secret.'],
      fields: [overlapField()],
      submitLabel: 'Rotate',
      method: 'POST', path: path,
      json: function (v) { return { overlap_secs: parseInt(v.overlap, 10) }; }
    }).then(function (r) {
      if (!r) return;
      showOrExplain('Replacement API token', takeToken(r),
        'Lost it? Rotate again within 2 minutes to get the same secret. After that, revoke the new token and rotate again.',
        'The replacement was created but the response did not include it. Rotate again within 2 minutes.');
      reloadTokens();
    });
  }

  function tokenConfirm(d) {
    var path = tokenPath(d.tokenId, '/confirm');
    if (!path) return;
    mutate({
      title: 'Confirm rotation',
      body: 'Paste the new secret to prove you received it. Confirming revokes "' + (d.predecessor || 'the old token') +
            '" immediately.',
      fields: [{ name: 'secret', label: 'New secret', type: 'password', autocomplete: 'off', required: true }],
      submitLabel: 'Confirm rotation', danger: true,
      method: 'POST', path: path,
      json: function (v) { return { secret: v.secret.trim() }; }
    }).then(function (r) {
      if (!r) return;
      flash('Rotation confirmed. The old token is revoked.');
      reloadTokens();
    });
  }

  function tokenRevoke(d) {
    var path = tokenPath(d.tokenId);
    if (!path) return;
    mutate({
      title: 'Revoke API token', danger: true, submitLabel: 'Revoke',
      body: 'Revoke API token "' + (d.name || d.tokenId) + '"? Applications using this token will lose access.',
      method: 'DELETE', path: path
    }).then(function (r) {
      if (!r) return;
      flash('Token revoked.');
      reloadTokens();
    });
  }

  // ---- dispatch ---------------------------------------------------------------------------
  var ACTIONS = {
    'token-new': tokenNew, 'token-rotate': tokenRotate, 'token-confirm': tokenConfirm,
    'token-revoke': tokenRevoke
  };

  document.addEventListener('click', function (e) {
    var b = e.target.closest('[data-tk]');
    if (!b || b.disabled) return;
    var act = b.dataset.tk;
    if (act === 'reveal-copy') { copySecret(b); return; }
    if (act === 'reveal-stored') { clearReveal(); flash(''); return; }
    if (Object.prototype.hasOwnProperty.call(ACTIONS, act)) ACTIONS[act](b.dataset);
  });
})();
