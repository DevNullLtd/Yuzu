/* yuzu-operate.js -- page controllers for the Operate pages (Approvals, Executions).
 *
 * The server renders every list and panel as an HTML fragment (the fragment
 * routes' `view=page` branches); this file fetches them, swaps them into their host
 * and fills the single detail panel from the selected row's data-* attributes with
 * textContent. The decision and cancel actions are dialogs from /static/yuzu-dialog.js. One controller per page, chosen by <body data-page>.
 *
 * Rules this file keeps (pinned by test_operate_pages_ui.cpp):
 *   - no dynamic-code or raw-markup sinks of any kind (the test pins the exact list);
 *   - innerHTML is assigned ONLY from a 200 fragment the server rendered (and escaped), to
 *     the two list hosts (#ap-list, #exec-list); the selected and devices panels receive
 *     parsed [data-slot] nodes (DOMParser + replaceChildren); a non-200 body is never
 *     written anywhere;
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

  // Transient confirmation in #toasts (textContent only); removed after 4 s.
  function showToast(msg, level) {
    var host = $('#toasts');
    if (!host) return;
    var t = doc.createElement('div');
    t.className = 'toast toast-' + (level || 'info');
    t.textContent = msg;
    host.appendChild(t);
    setTimeout(function () { if (t.parentNode) t.parentNode.removeChild(t); }, 4000);
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

  // Local wall-clock text for an epoch in ms: HH:MM:SS, prefixed "D Mon " when not today.
  var MONTHS = ['Jan', 'Feb', 'Mar', 'Apr', 'May', 'Jun', 'Jul', 'Aug', 'Sep', 'Oct', 'Nov', 'Dec'];
  function fmtLocal(ms) {
    var d = new Date(Number(ms));
    if (isNaN(d.getTime())) return '';
    function p2(n) { return (n < 10 ? '0' : '') + n; }
    var t = p2(d.getHours()) + ':' + p2(d.getMinutes()) + ':' + p2(d.getSeconds());
    var now = new Date();
    var today = d.getFullYear() === now.getFullYear() && d.getMonth() === now.getMonth() &&
      d.getDate() === now.getDate();
    return today ? t : d.getDate() + ' ' + MONTHS[d.getMonth()] + ' ' + t;
  }
  // The server renders UTC text (no-JS fallback) and the ISO instant in the title; the
  // epoch in data-epoch-ms is the source for the local text.
  function renderLocalTimes(root) {
    $$('[data-epoch-ms]', root).forEach(function (el) {
      var t = fmtLocal(el.getAttribute('data-epoch-ms'));
      if (t) el.textContent = t;
    });
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
      var list = $('.ops-list', host);
      var canDecide = !!list && list.getAttribute('data-can-decide') === '1';
      field(detail, 'self').hidden = !(pending && mine);
      field(detail, 'actions').hidden = !(pending && !mine && canDecide);
      field(detail, 'n-mcp').hidden = !mcp;
      field(detail, 'n-params').hidden = mcp;
      field(detail, 'notes').hidden = !pending;

      field(detail, 'empty').hidden = true;
      field(detail, 'kv').hidden = false;
    }

    function factRow(label, text, code) {
      var r = doc.createElement('div');
      var l = doc.createElement('span');
      l.textContent = label;
      var v = doc.createElement(code ? 'code' : 'b');
      v.textContent = text;
      r.appendChild(l);
      r.appendChild(v);
      return r;
    }

    // Approve / reject dialog for the selected pending request. The facts are the row's
    // own data-* attributes (no refetch); the decision is one POST through YuzuDialog.
    function decide(kind) {
      var row = $('tr.row.sel', host);
      if (!row || !window.YuzuDialog) return;
      var d = row.dataset;
      var id = d.id || '';
      var approve = kind === 'approve';
      var facts = doc.createElement('div');
      facts.className = 'kvl dlg-facts';
      facts.appendChild(factRow('Request', (d.name || '') + (d.def ? ' (' + d.def + ')' : '')));
      facts.appendChild(factRow('Requested by', d.by || ''));
      facts.appendChild(factRow('Scope', d.scope || 'None recorded', true));
      facts.appendChild(factRow('Requested', d.age || ''));
      var note = approve ?
        'Your decision is recorded in the audit log. Your comment is saved on the request and is ' +
        'visible to anyone who can read approvals. Approving does not run the instruction itself. ' +
        'You cannot approve your own request. ' +
        (d.mcp === '1' ?
          'The requesting agent must re-call the tool with this approval id for it to run.' :
          'The parameter values are not stored with this request. You are deciding on the ' +
          'instruction and scope only.') :
        'Your decision and reason are recorded. The requester can read the reason on the request.';
      var url = '/api/approvals/' + encodeURIComponent(id) + '/' + kind;
      YuzuDialog.form({
        title: approve ? 'Approve request' : 'Reject request',
        body: facts,
        note: note,
        danger: !approve,
        fields: [{ name: 'comment', type: 'textarea', maxlength: 1000, rows: 3,
                   label: approve ? 'Comment (optional)' : 'Reason (saved with your decision)' }],
        cancelLabel: 'Go back',
        submitLabel: approve ? 'Approve request' : 'Reject request',
        submit: function (v) {
          var comment = v.comment.trim();
          return YuzuDialog.request('POST', url, { json: comment ? { comment: comment } : {} })
            .then(function (r) {
              if (r.ok) return null;
              if (r.status === 400) return r.message || 'The request was refused.';
              if (r.status === 401) return 'Your session has expired. Sign in again.';
              if (r.status === 403) return 'You do not have permission to decide approvals.';
              return 'Could not confirm the decision. Refresh to see the current state.';
            });
        }
      }).then(function (v) {
        if (v === null) return;
        showToast(approve ? 'Approved' : 'Rejected', 'success');
        doc.dispatchEvent(new CustomEvent('yuzu:approvals-changed'));
        load();
      }, function () { /* another dialog is open: nothing to do */ });
    }

    detail.addEventListener('click', function (e) {
      var b = e.target.closest ? e.target.closest('button[data-act]') : null;
      if (!b || !detail.contains(b)) return;
      var act = b.getAttribute('data-act');
      if (act === 'approve' || act === 'reject') decide(act);
    });

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

  function executionsController() {
    var host = $('#exec-list');
    var panel = $('#exec-selected');
    var devices = $('#exec-devices');
    var chip = $('#exec-chip');
    var confinedNote = $('#exec-confined');
    var defSel = $('#f-def');
    var defHint = $('#f-def-hint');
    if (!host || !panel || !devices || !defSel) return;

    var STATUSES = ['', 'running', 'succeeded', 'completed', 'cancelled', 'pending'];
    var lseq = 0;          // request tokens: only the newest list / detail response is applied
    var dseq = 0;
    var loadedAt = 0;
    var selectedId = '';

    function currentStatus() {
      var r = $('input[name="est"]:checked');
      return r ? r.value : '';
    }

    // Keeps the select showing the filter that is really applied: an id from the URL that
    // is not among the loaded options (outside the first 500, or the load failed) gets a
    // synthetic option rather than silently reading as "All instructions".
    function ensureOption(id) {
      if (!id) return;
      var found = false;
      $$('option', defSel).forEach(function (o) { if (o.value === id) found = true; });
      if (found) return;
      var o = doc.createElement('option');
      o.value = id;
      o.textContent = id;
      defSel.appendChild(o);
    }

    function loadOptions(wanted) {
      var init = { credentials: 'same-origin', cache: 'no-store' };
      var sig = timeoutSignal(10000);
      if (sig) init.signal = sig;
      return fetch('/api/instructions?limit=500', init).then(function (r) {
        if (!r.ok) throw new Error('http');
        return r.json();
      }).then(function (body) {
        var defs = (body && Array.isArray(body.definitions)) ? body.definitions : [];
        defs = defs.filter(function (d) { return d && typeof d.id === 'string' && d.id; });
        defs.sort(function (a, b) {
          return String(a.name || a.id).localeCompare(String(b.name || b.id));
        });
        defs.forEach(function (d) {
          var o = null;
          $$('option', defSel).forEach(function (x) { if (x.value === d.id) o = x; });
          if (!o) { o = doc.createElement('option'); o.value = d.id; defSel.appendChild(o); }
          o.textContent = d.name || d.id; // names a synthetic deep-link option in place
        });
      }).catch(function () {
        defHint.hidden = false;
      }).then(function () {
        ensureOption(wanted);
        defSel.value = wanted || '';
      });
    }

    function panelNote(text) {
      var hd = doc.createElement('div');
      hd.className = 'hd';
      var h = doc.createElement('h2');
      h.textContent = 'Selected execution';
      hd.appendChild(h);
      var n = doc.createElement('div');
      n.className = 'empty-state';
      n.textContent = text;
      panel.replaceChildren(hd, n);
      stopLive();
      devices.hidden = true;
      devices.replaceChildren();
    }

    // Moves each top-level [data-slot] of a page-view response into the host that carries
    // its name. The response is parsed into an inert document (nothing in it runs) and the
    // slot nodes are adopted whole, so no markup is ever assigned as a string here.
    var SLOT_HOSTS = { selected: panel, devices: devices };
    function applySlots(html) {
      var parsed = new DOMParser().parseFromString(html, 'text/html');
      var seen = {};
      $$('[data-slot]', parsed.body).forEach(function (slot) {
        var name = slot.getAttribute('data-slot');
        var target = SLOT_HOSTS[name];
        if (!target || seen[name]) return;
        seen[name] = true;
        target.replaceChildren(slot);
        target.hidden = false;
        renderLocalTimes(target);
      });
      if (!seen.devices) { devices.hidden = true; devices.replaceChildren(); }
    }

    // ---- Live updates (OpsLive) for the selected running|pending execution ----
    // One EventSource per tab. Started only after a FRESH detail response says the
    // execution is running|pending; closed by selecting another row, completion, a CLOSED
    // source, or pagehide. Counters of the Selected panel are not patched from events (a
    // confined caller's stream is sanitised); they arrive with the throttled refresh.
    var MIN_GAP_MS = 3000;     // trailing refresh gap; every refresh is an audited read
    var LARGE_GAP_MS = 15000;  // used when the execution targets more than 2000 devices
    var es = null;
    var opened = false;
    var liveId = '';
    var refreshTimer = 0;
    var lastRefresh = 0;
    var gapMs = MIN_GAP_MS;
    var liveChip = doc.createElement('span');
    liveChip.className = 'ops-live';
    liveChip.setAttribute('role', 'status');
    liveChip.hidden = true;

    function setChip(state) {
      var copy = { live: 'Live', reconnecting: 'Reconnecting\u2026',
                   unavailable: 'Live updates unavailable.' };
      if (!state || !copy[state]) { liveChip.hidden = true; liveChip.textContent = ''; return; }
      liveChip.setAttribute('data-state', state);
      var dot = doc.createElement('i');
      var txt = doc.createElement('span');
      txt.textContent = copy[state];
      liveChip.replaceChildren(dot, txt);
      liveChip.hidden = false;
    }
    // The slots are replaced on every refresh; the chip is re-seated into the new header.
    function seatChip() {
      var hd = $('[data-slot="selected"] > .hd', panel);
      if (hd && liveChip.parentNode !== hd) hd.appendChild(liveChip);
    }
    function closeStream() {
      if (es) { try { es.close(); } catch (e) { /* already closed */ } es = null; }
      opened = false;
    }
    function cancelRefresh() {
      if (refreshTimer) { clearTimeout(refreshTimer); refreshTimer = 0; }
    }
    function stopLive() {
      closeStream();
      cancelRefresh();
      liveId = '';
      setChip('');
    }
    function refreshNow() {
      cancelRefresh();
      lastRefresh = Date.now();
      if (liveId) showDetail(liveId, true);
    }
    function scheduleRefresh() {
      if (refreshTimer || !liveId) return;
      var wait = Math.max(0, gapMs - (Date.now() - lastRefresh));
      refreshTimer = setTimeout(function () { refreshTimer = 0; refreshNow(); }, wait);
    }

    function cssEsc(s) {
      if (typeof CSS !== 'undefined' && CSS.escape) return CSS.escape(String(s));
      return String(s).replace(/(["\\])/g, '\\$1');
    }
    function applyAgentTransition(id, payload) {
      if (!payload || !payload.agent_id) return;
      var status = String(payload.status || '');
      var dom = 'pending';
      if (status === 'success') dom = 'succeeded';
      else if (status === 'failure' || status === 'timeout' || status === 'rejected') dom = 'failed';
      else if (status === 'running') dom = 'running';
      var key = '[data-agent-id="' + cssEsc(payload.agent_id) + '"][data-exec-id="' + cssEsc(id) + '"]';
      $$('.agent-cell' + key, devices).forEach(function (c) {
        c.className = 'agent-cell agent-cell--' + dom;
      });
      $$('tr' + key, devices).forEach(function (r) {
        var badge = $('.per-agent-status', r);
        if (badge) {
          badge.textContent = status;
          badge.className = 'status-badge per-agent-status status-' + dom;
        }
        var ex = $('.per-agent-exit-code', r);
        if (ex && typeof payload.exit_code === 'number') ex.textContent = String(payload.exit_code);
      });
    }
    function applyProgress(id, payload) {
      var strip = $('#exec-kpi-' + cssEsc(id), devices);
      if (!strip || !payload) return;
      var vals = $$('.exec-kpi-value', strip);
      if (vals.length < 3) return;
      if (typeof payload.agents_targeted === 'number') vals[0].textContent = String(payload.agents_targeted);
      if (typeof payload.agents_success === 'number') vals[1].textContent = String(payload.agents_success);
      if (typeof payload.agents_failure === 'number') vals[2].textContent = String(payload.agents_failure);
    }

    function startLive(id, targeted) {
      stopLive();
      liveId = id;
      gapMs = targeted > 2000 ? LARGE_GAP_MS : MIN_GAP_MS;
      lastRefresh = Date.now();
      try { es = new EventSource('/sse/executions/' + encodeURIComponent(id)); } catch (e) { es = null; liveId = ''; return; }
      var mine = es;
      mine.addEventListener('open', function () { opened = true; setChip('live'); });
      mine.addEventListener('agent-transition', function (ev) {
        if (mine !== es) return;
        try { applyAgentTransition(id, JSON.parse(ev.data)); } catch (e) { /* bad frame */ }
        scheduleRefresh();
      });
      mine.addEventListener('execution-progress', function (ev) {
        if (mine !== es) return;
        try { applyProgress(id, JSON.parse(ev.data)); } catch (e) { /* bad frame */ }
      });
      mine.addEventListener('execution-completed', function () {
        if (mine !== es) return;
        closeStream();
        setChip('');
        refreshNow(); // exactly one final read for the terminal state
      });
      mine.addEventListener('heartbeat', function () {});
      mine.onerror = function () {
        if (mine !== es) return;
        if (mine.readyState === 2) {
          // CLOSED: before open it was refused (410 or the stream budget; the browser cannot
          // read which), after open the server ended it, so read the final state once.
          var wasOpen = opened;
          closeStream();
          if (wasOpen) { setChip(''); refreshNow(); } else { setChip('unavailable'); }
        } else {
          setChip('reconnecting');
        }
      };
    }
    window.addEventListener('pagehide', stopLive);

    function markSelected() {
      $$('tr.row', host).forEach(function (r) {
        var on = !!selectedId && r.dataset.executionId === selectedId;
        r.classList.toggle('sel', on);
        r.setAttribute('aria-selected', on ? 'true' : 'false');
      });
    }

    function detailCopy(status) {
      if (status === 404) return 'This execution was not found, or part of it is outside your scope.';
      if (status === 403) return 'You do not have permission to view this execution.';
      if (status === 401) return 'Your session has expired. Sign in again.';
      if (status === 503) return 'Execution tracker degraded, retry shortly.';
      if (status === 0) return 'Could not load. Check your connection and retry.';
      return 'Could not load this execution (HTTP ' + status + ').';
    }

    // One audited detail read per call. Never run on load without an explicit ?id=.
    // fromLive: a refresh of the already-selected execution; the stream stays as it is.
    function showDetail(id, fromLive) {
      var mine = ++dseq;
      if (!fromLive) {
        stopLive();
        selectedId = id;
        markSelected();
        writeQs(function (p) { p.set('id', id); });
      }
      return fetchFragment('/fragments/executions/' + encodeURIComponent(id) +
                           '/detail?view=page').then(function (res) {
        if (mine !== dseq) return;
        if (res.status !== 200) { panelNote(detailCopy(res.status)); return; }
        applySlots(res.html); // server-rendered and escaped
        var sel = $('[data-slot="selected"]', panel);
        var status = sel ? sel.getAttribute('data-execution-status') : '';
        var running = status === 'running' || status === 'pending';
        if (fromLive) {
          if (!running) stopLive();   // terminal: nothing more to watch
        } else if (running) {
          startLive(id, Number(sel.getAttribute('data-targeted')) || 0);
        }
        seatChip();
      });
    }

    function updateChrome(list) {
      var count = Number(list.getAttribute('data-count')) || 0;
      confinedNote.hidden = list.getAttribute('data-confined') !== '1';
      if (count > 0) {
        $('b', chip).textContent = String(count);
        chip.hidden = false;
      } else {
        chip.hidden = true;
      }
    }

    function loadList() {
      var mine = ++lseq;
      var params = [];
      if (currentStatus()) params.push('status=' + encodeURIComponent(currentStatus()));
      if (defSel.value) params.push('definition_id=' + encodeURIComponent(defSel.value));
      var url = '/fragments/executions?view=page' + (params.length ? '&' + params.join('&') : '');
      return fetchFragment(url).then(function (res) {
        if (mine !== lseq) return;
        loadedAt = Date.now();
        if (res.status !== 200) {
          setNote(host, failureCopy(res.status, 'executions'));
          chip.hidden = true;
          return;
        }
        host.innerHTML = res.html; // server-rendered and escaped
        var list = $('.ops-list', host);
        // A 200 note (denied, degraded, invalid) has no list: clear the previous list's chrome.
        if (list) updateChrome(list); else { chip.hidden = true; confinedNote.hidden = true; }
        renderLocalTimes(host);
        markSelected(); // re-apply the selection without a refetch
      });
    }

    function selectRow(row) {
      var id = row.dataset.executionId;
      if (id) showDetail(id);
    }

    host.addEventListener('click', function (e) {
      var row = e.target.closest ? e.target.closest('tr.row') : null;
      if (row && host.contains(row)) selectRow(row);
    });
    host.addEventListener('keydown', function (e) {
      if (e.key !== 'Enter' && e.key !== ' ') return;
      var row = e.target.closest ? e.target.closest('tr.row') : null;
      if (!row || !host.contains(row)) return;
      e.preventDefault();
      selectRow(row);
    });
    function onFilter() {
      writeQs(function (p) {
        if (currentStatus()) p.set('status', currentStatus()); else p.delete('status');
        if (defSel.value) p.set('definition_id', defSel.value); else p.delete('definition_id');
      });
      loadList();
    }
    $$('input[name="est"]').forEach(function (r) { r.addEventListener('change', onFilter); });
    defSel.addEventListener('change', onFilter);
    doc.addEventListener('visibilitychange', function () {
      if (!doc.hidden && loadedAt && Date.now() - loadedAt > RELOAD_AFTER_MS) loadList();
    });

    // Deep link: /executions?definition_id=<id>&status=<s>&id=<execution>. The id is read
    // once; there is no auto-select otherwise (each selection is one audited read).
    var qs = readQs();
    var wantStatus = qs ? (qs.get('status') || '') : '';
    var wantDef = qs ? (qs.get('definition_id') || '') : '';
    var wantId = qs ? (qs.get('id') || '') : '';
    var radio = $('input[name="est"][value="' + (STATUSES.indexOf(wantStatus) >= 0 ? wantStatus : '') + '"]');
    if (radio) radio.checked = true;
    ensureOption(wantDef);
    defSel.value = wantDef;
    loadOptions(wantDef);
    loadList().then(function () {
      // A row that is not in the (capped, filtered) list is still fetched directly.
      if (wantId) showDetail(wantId);
    });
  }

  var controllers = { approvals: approvalsController, executions: executionsController };
  var page = doc.body ? doc.body.getAttribute('data-page') : '';
  if (controllers[page]) controllers[page]();
})();
