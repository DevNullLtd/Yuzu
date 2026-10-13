/* yuzu-operate.js -- page controllers for the Operate pages (Approvals, Executions).
 *
 * Read-only: the server renders every list and panel as an HTML fragment (the fragment
 * routes' `view=page` branches); this file only fetches them, swaps them into their host
 * and fills the single detail panel from the selected row's data-* attributes with
 * textContent. One controller per page, chosen by <body data-page>.
 *
 * Rules this file keeps (pinned by test_operate_pages_ui.cpp):
 *   - no dynamic-code or raw-markup sinks of any kind (the test pins the exact list);
 *   - innerHTML is assigned ONLY from a 200 fragment the server rendered (and escaped), to
 *     the one list host (#ap-list); a non-200 body is never written anywhere;
 *   - every fetch has a bounded timeout, and a late response never overwrites a newer one
 *     (request token).
 */
(function () {
  'use strict';

  var doc = document;
  var FETCH_TIMEOUT_MS = 15000;
  var RELOAD_AFTER_MS = 30000;

  function $(sel, root) { return (root || doc).querySelector(sel); }
  function $$(sel, root) { return Array.prototype.slice.call((root || doc).querySelectorAll(sel)); }
  function field(root, name) { return $('[data-f="' + name + '"]', root); }

  // AbortSignal.timeout is missing on old browsers (and could throw): no timeout beats no
  // request.
  function timeoutSignal(ms) {
    try { return AbortSignal.timeout(ms); } catch (e) { return undefined; }
  }

  // Resolves {status, html}; a network failure or timeout is status 0 (never rejects).
  function fetchFragment(url) {
    var init = { credentials: 'same-origin', cache: 'no-store' };
    var sig = timeoutSignal(FETCH_TIMEOUT_MS);
    if (sig) init.signal = sig;
    return fetch(url, init).then(function (r) {
      return r.text().then(function (t) { return { status: r.status, html: t }; });
    }).catch(function () { return { status: 0, html: '' }; });
  }

  // The copy for every non-200 answer of a LIST call. Never the response body.
  function failureCopy(status, what) {
    if (status === 0) return 'Could not load. Check your connection and retry.';
    if (status === 401) return 'Your session has expired. Sign in again.';
    if (status === 403) return 'You do not have permission to view ' + what + '.';
    if (status >= 500) return 'Could not load ' + what + ': the server reported a problem. Retry shortly.';
    return 'Could not load ' + what + ' (HTTP ' + status + ').';
  }

  function setNote(host, text) {
    var n = doc.createElement('div');
    n.className = 'empty-state';
    n.textContent = text;
    host.replaceChildren(n);
  }

  function readQs() {
    try { return new URLSearchParams(location.search); } catch (e) { return null; }
  }

  // Writes the filter state to the address bar without a navigation; best effort.
  function writeQs(mutate) {
    try {
      var p = new URLSearchParams(location.search);
      mutate(p);
      var q = p.toString();
      history.replaceState(null, '', location.pathname + (q ? '?' + q : '') + location.hash);
    } catch (e) { /* the page works without a shareable URL */ }
  }

  function approvalsController() {
    var host = $('#ap-list');
    var detail = $('#ap-detail');
    var chip = $('#ap-pending');
    if (!host || !detail) return;

    var seq = 0;          // request token: only the newest list response is applied
    var loadedAt = 0;
    var selectedId = '';

    // Status filter: absent = pending, present-but-empty = every status (the server's
    // contract, so the URL and the request agree).
    function initialStatus() {
      var p = readQs();
      if (p && p.has('status')) {
        var v = p.get('status');
        return ['', 'approved', 'rejected', 'expired', 'pending'].indexOf(v) >= 0 ? v : 'pending';
      }
      return 'pending';
    }
    function currentStatus() {
      var r = $('input[name="ast"]:checked');
      return r ? r.value : 'pending';
    }

    function resetDetail() {
      selectedId = '';
      field(detail, 'pill').hidden = true;
      field(detail, 'kv').hidden = true;
      field(detail, 'actions').hidden = true;
      field(detail, 'notes').hidden = true;
      field(detail, 'empty').hidden = false;
    }

    function markSelected(row) {
      $$('tr.row', host).forEach(function (r) {
        var on = r === row;
        r.classList.toggle('sel', on);
        r.setAttribute('aria-selected', on ? 'true' : 'false');
      });
    }

    function isoUtc(epochSeconds) {
      var n = Number(epochSeconds);
      if (!n) return '';
      try { return new Date(n * 1000).toISOString(); } catch (e) { return ''; }
    }

    function select(row) {
      var d = row.dataset;
      selectedId = d.id || '';
      markSelected(row);

      var srcPill = $('.pill', row);
      var pill = field(detail, 'pill');
      pill.className = srcPill ? srcPill.className : 'pill idle';
      pill.textContent = d.status || '';
      pill.hidden = false;

      field(detail, 'name').textContent = d.name || '';
      field(detail, 'def').textContent = d.def || '';
      field(detail, 'by').textContent = d.by || '';
      field(detail, 'by').title = d.by || '';
      var at = field(detail, 'at');
      at.textContent = d.age || '';
      at.title = isoUtc(d.at);

      var scope = d.scope || '';
      var scopeEl = field(detail, 'scope');
      scopeEl.textContent = scope;
      scopeEl.hidden = !scope;
      field(detail, 'no-scope').hidden = !!scope;

      var decided = !!d.revBy;
      field(detail, 'rev-by-row').hidden = !decided;
      field(detail, 'rev-at-row').hidden = !decided;
      field(detail, 'rev-by').textContent = d.revBy || '';
      field(detail, 'rev-by').title = d.revBy || '';
      var revAt = field(detail, 'rev-at');
      revAt.textContent = d.revAge || '';
      revAt.title = isoUtc(d.revAt);

      var comment = d.comment || '';
      field(detail, 'comment-row').hidden = !comment;
      field(detail, 'comment').textContent = comment;

      field(detail, 'id').textContent = d.id || '';
      field(detail, 'id').title = d.id || '';

      var pending = d.status === 'pending';
      var mine = d.mine === '1';
      var mcp = d.mcp === '1';
      field(detail, 'self').hidden = !(pending && mine);
      field(detail, 'where').hidden = !(pending && !mine);
      field(detail, 'actions').hidden = !pending;
      field(detail, 'n-mcp').hidden = !mcp;
      field(detail, 'n-params').hidden = mcp;
      field(detail, 'notes').hidden = !pending;

      field(detail, 'empty').hidden = true;
      field(detail, 'kv').hidden = false;
    }

    function updateChip(list) {
      var status = currentStatus();
      var shows = list && (status === 'pending' || status === '');
      if (!shows) { chip.hidden = true; return; }
      $('b', chip).textContent = list.getAttribute('data-pending') || '0';
      chip.hidden = false;
    }

    function load() {
      var mine = ++seq;
      var status = currentStatus();
      var url = '/fragments/approvals?view=page&status=' + encodeURIComponent(status);
      return fetchFragment(url).then(function (res) {
        if (mine !== seq) return; // a newer request owns the host now
        loadedAt = Date.now();
        if (res.status !== 200) {
          setNote(host, failureCopy(res.status, 'approvals'));
          chip.hidden = true;
          resetDetail();
          return;
        }
        host.innerHTML = res.html; // server-rendered and escaped; the only innerHTML sink
        var list = $('.ops-list', host);
        updateChip(list);
        // Re-apply the selection without a refetch; drop it when the row left the list.
        var row = null;
        if (selectedId) {
          $$('tr.row', host).forEach(function (r) { if (r.dataset.id === selectedId) row = r; });
        }
        if (row) select(row); else resetDetail();
      });
    }

    host.addEventListener('click', function (e) {
      var row = e.target.closest ? e.target.closest('tr.row') : null;
      if (row && host.contains(row)) select(row);
    });
    host.addEventListener('keydown', function (e) {
      if (e.key !== 'Enter' && e.key !== ' ') return;
      var row = e.target.closest ? e.target.closest('tr.row') : null;
      if (!row || !host.contains(row)) return;
      e.preventDefault();
      select(row);
    });
    $$('input[name="ast"]').forEach(function (r) {
      r.addEventListener('change', function () {
        var v = currentStatus();
        writeQs(function (p) { if (v === 'pending') p.delete('status'); else p.set('status', v); });
        selectedId = '';
        load();
      });
    });
    doc.addEventListener('visibilitychange', function () {
      if (!doc.hidden && loadedAt && Date.now() - loadedAt > RELOAD_AFTER_MS) load();
    });

    var start = initialStatus();
    var radio = $('input[name="ast"][value="' + start + '"]');
    if (radio) radio.checked = true;
    load();
  }

  var controllers = { approvals: approvalsController };
  var page = doc.body ? doc.body.getAttribute('data-page') : '';
  if (controllers[page]) controllers[page]();
})();
