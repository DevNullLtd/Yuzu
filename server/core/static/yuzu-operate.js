/* yuzu-operate.js -- page controllers for the Operate pages (Approvals, Executions, Workflows).
 *
 * The server renders every list and panel as an HTML fragment (the fragment
 * routes' `view=page` branches); this file fetches them, swaps them into their host
 * and fills the single detail panel from the selected row's data-* attributes with
 * textContent. The decision and cancel actions are dialogs from /static/yuzu-dialog.js. One controller per page, chosen by <body data-page>.
 *
 * Rules this file keeps (pinned by test_operate_pages_ui.cpp):
 *   - no dynamic-code or raw-markup sinks of any kind (the test pins the exact list);
 *   - innerHTML is assigned ONLY from a 200 fragment the server rendered (and escaped), to
 *     the list and store hosts (#ap-list, #exec-list, #wf-list, #sc-list, #wf-runs-store,
 *     #wf-run-body, #wf-recent-body); the selected-execution and devices panels receive
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

      // A bound ticket (#6062) carries the frozen request as plain text: the reviewer reads
      // what is being approved, not a bare digest. textContent only - never innerHTML.
      var request = d.request || '';
      var requestEl = field(detail, 'request');
      requestEl.textContent = request;
      requestEl.title = d.digest ? 'sha256:' + d.digest : '';
      field(detail, 'request-row').hidden = !request;

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
      var excluded = d.excluded === '1';
      var list = $('.ops-list', host);
      var canDecide = !!list && list.getAttribute('data-can-decide') === '1';
      field(detail, 'self').hidden = !(pending && mine);
      field(detail, 'excluded').hidden = !(pending && !mine && excluded);
      field(detail, 'actions').hidden = !(pending && !mine && !excluded && canDecide);
      field(detail, 'n-mcp').hidden = !mcp;
      field(detail, 'n-params').hidden = mcp || !!request;
      field(detail, 'notes').hidden = !pending;

      field(detail, 'empty').hidden = true;
      field(detail, 'kv').hidden = false;
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
      if (d.request) {
        var reqRow = factRow('Requested effect', d.request, true);
        reqRow.lastChild.className = 'req';
        facts.appendChild(reqRow);
      }
      facts.appendChild(factRow('Requested', d.age || ''));
      var note = approve ?
        'Your decision is recorded in the audit log. Your comment is saved on the request and is ' +
        'visible to anyone who can read approvals. Approving does not run the instruction itself. ' +
        'You cannot approve your own request. ' +
        (d.mcp === '1' ?
          'The requesting agent must re-call the tool with this approval id for it to run.' :
          d.request ?
          'You are approving exactly the effect shown above; it is frozen on the request and ' +
          'cannot change after your decision.' :
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
    var statsHost = $('#exec-stats');
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
    var TONES = { succeeded: 'ok', failed: 'bad', running: 'info', pending: 'idle' };
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
        var bar = $('.dbar', r);
        if (bar) bar.className = 'dbar dbar--' + dom;
        var badge = $('.per-agent-status', r);
        if (badge) {
          badge.textContent = status;
          // Same pill vocabulary the server renders (pill_tone in executions_page_render.cpp).
          badge.className = 'pill ' + TONES[dom] + ' per-agent-status';
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
        var cb = sel ? $('button[data-act="cancel"]', sel) : null;
        if (cb && sel.getAttribute('data-can-cancel') === '0') {
          cb.disabled = true;
          cb.title = 'You do not have permission to cancel executions.';
        }
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

    // Cancel: the facts come from the selected slot's own data-* attributes (no refetch);
    // the decision is one POST through YuzuDialog. The server stays the gate (a render hint
    // only decides whether the button is offered).
    function cancelExecution() {
      var sel = $('[data-slot="selected"]', panel);
      if (!sel || !window.YuzuDialog) return;
      var d = sel.dataset;
      var id = d.executionId || '';
      if (!id) return;
      var facts = doc.createElement('div');
      facts.className = 'kvl dlg-facts';
      facts.appendChild(factRow('Instruction', d.defName || ''));
      facts.appendChild(factRow('Started by', d.by || ''));
      facts.appendChild(factRow('Devices', (d.targeted || '0') + (d.confined === '1' ? ' in your scope' : ' targeted')));
      facts.appendChild(factRow('Execution id', id, true));
      var url = '/api/executions/' + encodeURIComponent(id) + '/cancel';
      YuzuDialog.form({
        title: 'Cancel execution',
        body: facts,
        note: 'Devices that have not started will not run it. Work already running on a device ' +
              'is not interrupted. Your action is recorded in the audit log.',
        danger: true,
        fields: [],
        cancelLabel: 'Go back',
        submitLabel: 'Cancel execution',
        submit: function () {
          return YuzuDialog.request('POST', url, { json: {} }).then(function (r) {
            if (r.ok) return null;
            if (r.status === 409) return r.message || 'This execution has already finished.';
            if (r.status === 401) return 'Your session has expired. Sign in again.';
            if (r.status === 403) return 'You do not have permission to cancel executions.';
            if (r.status === 404) return 'This execution was not found, or is outside your scope.';
            return 'Could not confirm the cancellation. Refresh to see the current state.';
          });
        }
      }).then(function (v) {
        if (v === null) return;
        showToast('Execution cancelled', 'success');
        stopLive();
        showDetail(id, true);
        loadList();
      }, function () { /* another dialog is open: nothing to do */ });
    }
    panel.addEventListener('click', function (e) {
      var b = e.target.closest ? e.target.closest('button[data-act="cancel"]') : null;
      if (b && panel.contains(b) && !b.disabled) cancelExecution();
    });

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
        // The optional fleet strip rides in the list response; adopt it into its own host
        // (absent for a confined view or a store failure: the host is emptied, never stale).
        var strip = $('[data-slot="stats"]', host);
        if (statsHost) {
          if (strip) statsHost.replaceChildren(strip); else statsHost.replaceChildren();
        }
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

  function workflowsController() {
    var wfHost = $('#wf-list');
    var scHost = $('#sc-list');
    var stepsTitle = $('#wf-steps-title');
    var stepsBody = $('#wf-steps-body');
    var runsStore = $('#wf-runs-store');
    var runBody = $('#wf-run-body');
    var recentDet = $('#wf-recent-det');
    var recentBody = $('#wf-recent-body');
    var newBtn = $('#wf-new');
    var delBtn = $('#wf-del');
    var scNewBtn = $('#sc-new');
    if (!wfHost || !scHost || !stepsTitle || !stepsBody || !runsStore || !runBody ||
        !recentDet || !recentBody) return;

    var wseq = 0;          // request tokens: only the newest answer of each kind lands
    var sseq = 0;
    var rseq = 0;          // newest-run-per-workflow list
    var dseq = 0;          // run detail
    var qseq = 0;          // recent runs
    var loadedAt = 0;
    var selectedId = '';
    var runsDone = false;  // a runs answer (list or note) has arrived
    var panelFor = '';     // the workflow whose Latest run panel has been requested
    var polling = {};      // workflow id -> true while its run is watched (Run is disabled)

    function stepsEmpty(text) {
      stepsTitle.textContent = 'Steps';
      setNote(stepsBody, text);
    }

    function markSelected() {
      $$('tr.row', wfHost).forEach(function (r) {
        var on = !!selectedId && r.getAttribute('data-workflow-id') === selectedId;
        r.classList.toggle('sel', on);
        r.setAttribute('aria-selected', on ? 'true' : 'false');
      });
    }

    // The step list of every listed workflow rides in the definitions fragment (a hidden
    // store), so a selection is a clone of server-rendered, escaped nodes: no request, no
    // markup assignment. Compared by attribute value, never interpolated into a selector.
    function stepsFor(id) {
      var found = null;
      $$('[data-steps-for]', wfHost).forEach(function (b) {
        if (b.getAttribute('data-steps-for') === id) found = b;
      });
      return found;
    }

    function showSteps(id) {
      var block = id ? stepsFor(id) : null;
      if (!block) { dseq++; selectedId = ''; markSelected(); return false; }
      selectedId = id;
      markSelected();
      stepsTitle.textContent = (block.getAttribute('data-name') || id) + ': steps';
      stepsBody.replaceChildren(block.cloneNode(true));
      return true;
    }

    // Each definitions row carries empty Last run / Result cells (data-c). A run row of the
    // runs fragment has the same two cells: a swap is a clone of server-rendered nodes.
    function applyLatest() {
      if (!runsDone) return;
      var list = $('.ops-list', runsStore);
      var confined = !!list && list.getAttribute('data-confined') === '1';
      var cut = !!list && list.getAttribute('data-truncated') === '1';
      $$('tr.row', wfHost).forEach(function (row) {
        var wid = row.getAttribute('data-workflow-id');
        var src = null;
        if (list) {
          $$('tr.row', runsStore).forEach(function (r) {
            if (r.getAttribute('data-workflow-id') === wid) src = r;
          });
        }
        var when = $('[data-c="started"]', row);
        var res = $('[data-c="status"]', row);
        if (!when || !res) return;
        if (src) {
          when.replaceWith($('[data-c="started"]', src).cloneNode(true));
          res.replaceWith($('[data-c="status"]', src).cloneNode(true));
          return;
        }
        when.removeAttribute('data-epoch-ms');
        // A cut-off runs list cannot say a workflow has no run: never a false 'Not run'.
        when.textContent = !list ? 'Unavailable'
          : (cut ? 'Unknown' : (confined ? 'None visible' : 'Not run'));
        res.textContent = '-';
      });
      renderLocalTimes(wfHost);
    }

    function runCopy(status) {
      if (status === 404) return 'Run not found, or not in your scope.';
      if (status === 0) return 'Could not load. Check your connection and retry.';
      return failureCopy(status, 'this run');
    }

    // One audited detail read per explicit call (a row click or a ?wf= deep link).
    function showRun(id) {
      var mine = ++dseq;
      return fetchFragment('/fragments/workflow-runs/' + encodeURIComponent(id)).then(function (res) {
        if (mine !== dseq) return;
        if (res.status !== 200) { setNote(runBody, runCopy(res.status)); return; }
        runBody.innerHTML = res.html; // server-rendered and escaped
        renderLocalTimes(runBody);
      });
    }

    // The newest run of the selected workflow, from the runs store (no list request here).
    function showLatest() {
      if (!selectedId || panelFor === selectedId) return;
      if (!runsDone) { setNote(runBody, 'Loading\u2026'); return; }
      panelFor = selectedId;
      var list = $('.ops-list', runsStore);
      if (!list) { setNote(runBody, runsStore.textContent || 'Run history unavailable.'); return; }
      var src = null;
      $$('tr.row', runsStore).forEach(function (r) {
        if (r.getAttribute('data-workflow-id') === selectedId) src = r;
      });
      if (!src && list.getAttribute('data-truncated') === '1') {
        setNote(runBody, 'The run list was cut off, so this workflow\'s latest run is not shown.');
        return;
      }
      if (!src) {
        setNote(runBody, list.getAttribute('data-confined') === '1'
          ? 'No runs include devices in your scope.' : 'No runs yet.');
        return;
      }
      showRun(src.getAttribute('data-run-id') || '');
    }

    function loadRecent() {
      if (!selectedId) return;
      var mine = ++qseq;
      var url = '/fragments/workflow-runs?limit=10&workflow_id=' + encodeURIComponent(selectedId);
      setNote(recentBody, 'Loading\u2026');
      fetchFragment(url).then(function (res) {
        if (mine !== qseq) return;
        if (res.status !== 200) { setNote(recentBody, failureCopy(res.status, 'runs')); return; }
        recentBody.innerHTML = res.html; // server-rendered and escaped
        renderLocalTimes(recentBody);
      });
    }

    function loadRuns() {
      var mine = ++rseq;
      return fetchFragment('/fragments/workflow-runs?latest_per_workflow=true&limit=500')
        .then(function (res) {
          if (mine !== rseq) return;
          if (res.status === 200) runsStore.innerHTML = res.html; // server-rendered and escaped
          else runsStore.textContent = failureCopy(res.status, 'workflow runs');
          runsDone = true;
          applyLatest();
          showLatest();
        });
    }

    function select(row) {
      var id = row.getAttribute('data-workflow-id') || '';
      if (!id) return;
      dseq++; // a detail still in flight belongs to the workflow just left
      showSteps(id);
      applyActions();
      writeQs(function (p) { p.set('wf', id); });
      panelFor = '';
      showLatest();
      if (recentDet.open) loadRecent();
      else setNote(recentBody, 'Open to list the ten most recent runs.');
    }

    function loadWorkflows() {
      var mine = ++wseq;
      return fetchFragment('/fragments/workflows').then(function (res) {
        if (mine !== wseq) return;
        loadedAt = Date.now();
        if (res.status !== 200) {
          setNote(wfHost, failureCopy(res.status, 'workflows'));
          selectedId = '';
          stepsEmpty('Select a workflow to see its steps.');
          applyActions();
          return;
        }
        wfHost.innerHTML = res.html; // server-rendered and escaped
        // Re-apply the selection without a refetch; a workflow that left the list
        // (deleted, or a product pack was uninstalled) clears it and says so.
        if (selectedId && !showSteps(selectedId))
          stepsEmpty('That workflow is no longer listed.');
        applyLatest();
        applyActions();
      });
    }

    function loadSchedules() {
      var mine = ++sseq;
      return fetchFragment('/fragments/schedules?view=page').then(function (res) {
        if (mine !== sseq) return;
        if (res.status !== 200) {
          setNote(scHost, failureCopy(res.status, 'schedules'));
          return;
        }
        scHost.innerHTML = res.html; // server-rendered and escaped
        renderLocalTimes(scHost);
        applyScheduleActions();
      });
    }

    // ---- actions (WF-3a) ----
    // The data-can-* hints on the definitions list decide which controls are offered. They
    // are render hints from a probe, never a gate: every write route checks its own grant.
    var RUN_POLL_MS = 5000;
    var RUN_POLL_MAX_MS = 600000;   // stop watching a run after 10 minutes
    var RUN_POST_TIMEOUT_MS = 8000; // the server holds the request for the whole run
    var AGENT_SHOW_MAX = 200;       // devices drawn in the checklist
    var AGENT_SELECT_MAX = 500;     // devices one run may name
    var AGENT_ID_RE = /^[A-Za-z0-9._-]{1,128}$/;
    var TERMINAL = { completed: 1, failed: 1, cancelled: 1 };

    function can(name) {
      var list = $('.ops-list', wfHost);
      return !!list && list.getAttribute('data-can-' + name) === '1';
    }

    function setReason(btn, allowed, reason) {
      btn.disabled = !allowed;
      if (allowed) btn.removeAttribute('title');
      else btn.setAttribute('title', reason);
    }

    // Re-applied after every definitions render and after a selection or a poll changes.
    function applyActions() {
      var listed = !!$('.ops-list', wfHost);
      newBtn.hidden = !listed;
      setReason(newBtn, can('write'), 'Requires Workflow:Write');
      delBtn.hidden = !(listed && selectedId);
      setReason(delBtn, can('delete'), 'Requires Workflow:Delete');
      $$('tr.row', wfHost).forEach(function (row) {
        var b = $('button[data-act="run"]', row);
        if (!b) return;
        var watched = !!polling[row.getAttribute('data-workflow-id')];
        // Disabled while its run is watched: the server accepts duplicate executes, and the
        // earlier one may still be running although the request timed out.
        setReason(b, can('run') && !watched, watched
          ? 'A run of this workflow may still be in progress.' : 'Requires Workflow:Execute');
      });
    }

    function errText(r, fallback) {
      if (r.status === 401) return 'Your session has expired. Sign in again.';
      return r.message || fallback;
    }

    function newWorkflow() {
      if (!window.YuzuDialog) return;
      YuzuDialog.form({
        title: 'New workflow',
        body: 'Paste the workflow definition as YAML. Nothing runs until you use Run now.',
        fields: [{ name: 'yaml', label: 'Workflow YAML', type: 'textarea', rows: 14,
                   maxlength: 200000, required: true,
                   hint: 'Steps name instructions by id, in the order they run.' }],
        submitLabel: 'Create workflow',
        submit: function (v) {
          return YuzuDialog.request('POST', '/api/workflows', { json: { yaml_source: v.yaml } })
            .then(function (r) {
              if (r.ok) return null;
              if (r.status === 403) return 'You do not have permission to create workflows.';
              return errText(r, 'Could not create the workflow (HTTP ' + r.status + ').');
            });
        }
      }).then(function (v) {
        if (v === null) return;
        showToast('Workflow created', 'success');
        loadWorkflows();
        loadRuns();
      }, function () { /* another dialog is open: nothing to do */ });
    }

    function deleteWorkflow() {
      if (!window.YuzuDialog || !selectedId) return;
      var id = selectedId;
      var block = stepsFor(id);
      var name = (block && block.getAttribute('data-name')) || id;
      YuzuDialog.form({
        title: 'Delete workflow',
        body: ['Deletes "' + name + '". Run history is kept. There is no undelete in the console.'],
        danger: true,
        fields: [],
        cancelLabel: 'Go back',
        submitLabel: 'Delete workflow',
        submit: function () {
          return YuzuDialog.request('DELETE', '/api/workflows/' + encodeURIComponent(id))
            .then(function (r) {
              if (r.ok && r.data && r.data.deleted === false)
                return 'That workflow was already deleted or does not exist.';
              if (r.ok) return null;
              if (r.status === 403) return 'You do not have permission to delete workflows.';
              return errText(r, 'Could not delete the workflow (HTTP ' + r.status + ').');
            });
        }
      }).then(function (v) {
        if (v === null) return;
        showToast('Workflow deleted', 'success');
        if (selectedId === id) {
          selectedId = '';
          writeQs(function (p) { p.delete('wf'); });
          stepsEmpty('Select a workflow to see its steps.');
          applyActions();
        }
        loadWorkflows();
        loadRuns();
      }, function () { /* another dialog is open: nothing to do */ });
    }

    // Watches the newest run of a workflow after the Run request timed out: the server keeps
    // working, so poll the runs fragment every 5 s until a run newer than the one that was
    // newest before the request reaches a terminal status, or 10 minutes pass.
    function watchRun(id, baselineRunId) {
      if (polling[id]) return;
      polling[id] = true;
      applyActions();
      var started = Date.now();
      function finish(msg) {
        delete polling[id];
        applyActions();
        if (msg) showToast(msg, 'info');
        loadRuns();
        if (recentDet.open && selectedId === id) loadRecent();
      }
      function tick() {
        if (Date.now() - started > RUN_POLL_MAX_MS) {
          finish('Stopped watching the run. Check Recent runs before running it again.');
          return;
        }
        fetchFragment('/fragments/workflow-runs?limit=1&workflow_id=' + encodeURIComponent(id))
          .then(function (res) {
            var row = null;
            if (res.status === 200)
              row = new DOMParser().parseFromString(res.html, 'text/html').querySelector('tr.row');
            if (row && row.getAttribute('data-run-id') !== baselineRunId &&
                TERMINAL[row.getAttribute('data-status')]) {
              finish('The run finished.');
              return;
            }
            setTimeout(tick, RUN_POLL_MS);
          });
      }
      setTimeout(tick, RUN_POLL_MS);
    }

    function newestRunId(wid) {
      var found = '';
      $$('tr.row', runsStore).forEach(function (r) {
        if (!found && r.getAttribute('data-workflow-id') === wid)
          found = r.getAttribute('data-run-id') || '';
      });
      return found;
    }

    function agentList(data) {
      var arr = Array.isArray(data) ? data : (data && Array.isArray(data.agents) ? data.agents : null);
      if (!arr) return null;
      return arr.filter(function (a) { return a && typeof a.agent_id === 'string' && a.agent_id; })
        .map(function (a) {
          return { id: a.agent_id, host: typeof a.hostname === 'string' ? a.hostname : '',
                   os: typeof a.os === 'string' ? a.os : '' };
        });
    }

    // The device chooser inside the Run dialog. Returns {node, ids()}; its content arrives
    // from GET /api/agents (a bare array; an object with .agents is also accepted). Without
    // Infrastructure:Read (or when the list cannot be read) it falls back to a textarea of
    // device ids, which the server confines to the caller's scope anyway.
    function deviceChooser() {
      var root = doc.createElement('div');
      var chosen = {};      // agent id -> true
      var chosenCount = 0;
      var agents = null;    // null until loaded; [] when none are connected
      var shownList = [];   // the devices currently drawn (at most AGENT_SHOW_MAX)
      var area = null;      // the textarea of the fallback

      var note = doc.createElement('p');
      note.className = 'hint';
      note.textContent = 'Loading devices…';
      root.appendChild(note);

      function countText() { note.textContent = chosenCount + ' of ' + AGENT_SELECT_MAX + ' maximum selected.'; }

      function drawList(host, filter) {
        host.replaceChildren();
        shownList = [];
        var q = filter.trim().toLowerCase();
        var shown = 0;
        var matched = 0;
        agents.forEach(function (a) {
          if (q && (a.host + ' ' + a.id + ' ' + a.os).toLowerCase().indexOf(q) < 0) return;
          matched++;
          if (shown >= AGENT_SHOW_MAX) return;
          shown++;
          shownList.push(a);
          var lab = doc.createElement('label');
          lab.className = 'dev';
          var cb = doc.createElement('input');
          cb.type = 'checkbox';
          cb.checked = !!chosen[a.id];
          cb.addEventListener('change', function () {
            if (cb.checked && chosenCount >= AGENT_SELECT_MAX) { cb.checked = false; return; }
            if (cb.checked) { chosen[a.id] = true; chosenCount++; }
            else if (chosen[a.id]) { delete chosen[a.id]; chosenCount--; }
            countText();
          });
          var t = doc.createElement('span');
          t.textContent = (a.host || a.id) + (a.os ? ' · ' + a.os : '');
          lab.appendChild(cb);
          lab.appendChild(t);
          host.appendChild(lab);
        });
        if (matched > shown) {
          var more = doc.createElement('p');
          more.className = 'hint';
          more.textContent = 'Showing the first ' + shown + ' of ' + matched +
            ' matching devices. Narrow the filter to see the rest.';
          host.appendChild(more);
        }
        if (!matched) {
          var none = doc.createElement('p');
          none.className = 'hint';
          none.textContent = agents.length ? 'No device matches the filter.' : 'No devices are connected.';
          host.appendChild(none);
        }
      }

      function showChecklist() {
        var filt = doc.createElement('input');
        filt.type = 'text';
        filt.placeholder = 'Filter devices';
        filt.setAttribute('aria-label', 'Filter devices');
        var host = doc.createElement('div');
        host.className = 'devs';
        var all = doc.createElement('button');
        all.type = 'button';
        all.className = 'btn btn-sm';
        all.textContent = 'Select shown';
        all.addEventListener('click', function () {
          shownList.forEach(function (a) {
            if (!chosen[a.id] && chosenCount < AGENT_SELECT_MAX) { chosen[a.id] = true; chosenCount++; }
          });
          drawList(host, filt.value);
          countText();
        });
        filt.addEventListener('input', function () { drawList(host, filt.value); });
        root.appendChild(filt);
        root.appendChild(all);
        root.appendChild(host);
        drawList(host, '');
        countText();
      }

      function showFallback(why) {
        note.textContent = why + ' Enter device ids, one per line (letters, digits, . _ -).';
        area = doc.createElement('textarea');
        area.rows = 6;
        area.setAttribute('aria-label', 'Device ids');
        root.appendChild(area);
      }

      var init = { credentials: 'same-origin', cache: 'no-store' };
      var sig = timeoutSignal(FETCH_TIMEOUT_MS);
      if (sig) init.signal = sig;
      fetch('/api/agents', init).then(function (r) {
        if (r.status === 403) { showFallback('You cannot list devices.'); return null; }
        if (r.status !== 200) { showFallback('The device list could not be loaded.'); return null; }
        return r.json().then(function (d) {
          agents = agentList(d);
          if (agents === null) { showFallback('The device list could not be read.'); return; }
          showChecklist();
        });
      }).catch(function () { showFallback('The device list could not be loaded.'); });

      return {
        node: root,
        // The chosen ids, or an error string when the input is not usable.
        read: function () {
          if (area) {
            var seen = {};
            var out = [];
            var lines = area.value.split('\n');
            for (var i = 0; i < lines.length; i++) {
              var t = lines[i].trim();
              if (!t) continue;
              if (!AGENT_ID_RE.test(t)) return 'Not a valid device id: ' + t.slice(0, 40);
              if (!seen[t]) { seen[t] = true; out.push(t); }
            }
            if (out.length > AGENT_SELECT_MAX) return 'Name at most ' + AGENT_SELECT_MAX + ' devices.';
            return out;
          }
          return Object.keys(chosen);
        }
      };
    }

    function runWorkflow(id) {
      if (!window.YuzuDialog || polling[id] || !can('run')) return;
      var block = stepsFor(id);
      var name = (block && block.getAttribute('data-name')) || id;
      var body = doc.createElement('div');
      var intro = doc.createElement('p');
      intro.textContent = 'Runs "' + name + '". Each step is sent to every selected device, in ' +
        'order. Steps whose instruction needs approval are refused. Device results are not ' +
        'collected here.';
      body.appendChild(intro);
      var chooser = deviceChooser();
      body.appendChild(chooser.node);
      var baseline = newestRunId(id);
      var outcome = '';   // 'ok' (202) or 'timeout' (the request did not finish in time)
      YuzuDialog.form({
        title: 'Run workflow',
        body: body,
        fields: [],
        submitLabel: 'Run on selected devices',
        validate: function () {
          var ids = chooser.read();
          if (typeof ids === 'string') return ids;
          return ids.length ? null : 'Choose at least one device.';
        },
        submit: function () {
          var ids = chooser.read();
          if (typeof ids === 'string' || !ids.length) return Promise.resolve('Choose at least one device.');
          var init = { method: 'POST', credentials: 'same-origin', cache: 'no-store',
                       headers: { 'Content-Type': 'application/json' },
                       body: JSON.stringify({ agent_ids: ids }) };
          var sig = timeoutSignal(RUN_POST_TIMEOUT_MS);
          if (sig) init.signal = sig;
          return fetch('/api/workflows/' + encodeURIComponent(id) + '/execute', init).then(function (r) {
            return r.text().then(function (t) {
              var data = null;
              try { data = JSON.parse(t); } catch (e) { /* not JSON */ }
              if (r.ok) { outcome = 'ok'; return null; }
              if (r.status === 401) return 'Your session has expired. Sign in again.';
              var msg = data && data.error && typeof data.error.message === 'string' ? data.error.message : '';
              if (r.status === 403) return msg || 'You do not have permission to run this workflow.';
              return msg || 'Could not start the run (HTTP ' + r.status + ').';
            });
          }, function () {
            // Timeout or a dropped connection: the server may still be running it.
            outcome = 'timeout';
            return null;
          });
        }
      }).then(function (v) {
        if (v === null) return;
        if (outcome === 'timeout') {
          showToast('The run may keep running on the server. Check Recent runs before running it again.', 'warning');
          watchRun(id, baseline);
          return;
        }
        showToast('Workflow run started', 'success');
        loadRuns();
        if (recentDet.open && selectedId === id) loadRecent();
      }, function () { /* another dialog is open: nothing to do */ });
    }


    // ---- schedule actions (WF-3b) ----
    // data-can-* on the schedules list are render hints; the routes stay the gate and are
    // owner-scoped (a non-owner request answers 200 and changes nothing), so every outcome is
    // confirmed by re-reading the stored state rather than trusting the 200.
    function scCan(name) {
      var list = $('.ops-list', scHost);
      return !!list && list.getAttribute('data-can-' + name) === '1';
    }

    function applyScheduleActions() {
      if (!scNewBtn) return;
      scNewBtn.hidden = !$('.ops-list', scHost);
      setReason(scNewBtn, scCan('write') && scCan('enable'),
        'Requires Schedule:Write and Execution:Execute');
    }

    function scheduleRow(id) {
      var found = null;
      $$('tr.row', scHost).forEach(function (r) {
        if (r.getAttribute('data-schedule-id') === id) found = r;
      });
      return found;
    }

    function scheduleFacts(row) {
      var cells = row.children;
      var nm = $('.nm', row);
      var subs = $$('.sub', row);
      return {
        name: nm ? nm.textContent : '',
        instruction: subs.length ? subs[0].textContent : '',
        target: subs.length > 1 ? subs[1].textContent : '',
        cadence: cells.length > 1 ? cells[1].textContent : ''
      };
    }

    function setScheduleEnabled(id, want) {
      return YuzuDialog.request('POST', '/api/schedules/' + encodeURIComponent(id) + '/enable',
        { json: { enabled: want } }).then(function (r) {
        if (!r.ok) {
          showToast(r.status === 403 ? 'You do not have permission to change this schedule.'
            : errText(r, 'Could not change the schedule (HTTP ' + r.status + ').'), 'error');
          return;
        }
        return loadSchedules().then(function () {
          var row = scheduleRow(id);
          var now = row ? row.getAttribute('data-enabled') === '1' : null;
          if (now === want) showToast(want ? 'Schedule enabled' : 'Schedule disabled', 'success');
          else showToast('The schedule was not changed. Only its creator can enable or disable it.', 'warning');
        });
      });
    }

    function toggleSchedule(row) {
      if (!window.YuzuDialog) return;
      var id = row.getAttribute('data-schedule-id') || '';
      var want = row.getAttribute('data-enabled') !== '1';
      if (!want) { setScheduleEnabled(id, false); return; }
      var f = scheduleFacts(row);
      YuzuDialog.form({
        title: 'Enable schedule',
        body: ['Enabling "' + f.name + '" arms it: it runs instruction ' + f.instruction +
                 ' on ' + f.target + ', ' + f.cadence + ', and runs without anyone present.',
               'It can still be refused when it fires (for example by approval rules).'],
        fields: [],
        submitLabel: 'Enable schedule',
        submit: function () {
          return YuzuDialog.request('POST', '/api/schedules/' + encodeURIComponent(id) + '/enable',
            { json: { enabled: true } }).then(function (r) {
            if (r.ok) return null;
            if (r.status === 403) return 'You do not have permission to enable schedules.';
            return errText(r, 'Could not enable the schedule (HTTP ' + r.status + ').');
          });
        }
      }).then(function (v) {
        if (v === null) return;
        return loadSchedules().then(function () {
          var again = scheduleRow(id);
          if (again && again.getAttribute('data-enabled') === '1') showToast('Schedule enabled', 'success');
          else showToast('The schedule was not changed. Only its creator can enable or disable it.', 'warning');
        });
      }, function () { /* another dialog is open: nothing to do */ });
    }

    function deleteSchedule(row) {
      if (!window.YuzuDialog) return;
      var id = row.getAttribute('data-schedule-id') || '';
      var f = scheduleFacts(row);
      YuzuDialog.form({
        title: 'Delete schedule',
        body: ['Deletes "' + f.name + '". It stops running and cannot be restored.'],
        danger: true,
        fields: [],
        cancelLabel: 'Go back',
        submitLabel: 'Delete schedule',
        submit: function () {
          return YuzuDialog.request('DELETE', '/api/schedules/' + encodeURIComponent(id))
            .then(function (r) {
              if (r.ok && r.data && r.data.deleted === false)
                return 'Not deleted: only the schedule\'s creator can delete it, or it no longer exists.';
              if (r.ok) return null;
              if (r.status === 403) return 'You do not have permission to delete schedules.';
              return errText(r, 'Could not delete the schedule (HTTP ' + r.status + ').');
            });
        }
      }).then(function (v) {
        if (v === null) return;
        showToast('Schedule deleted', 'success');
        loadSchedules();
      }, function () { /* another dialog is open: nothing to do */ });
    }

    var CADENCES = [
      { value: 'once', label: 'Once (at the next scheduler tick)' },
      { value: 'interval', label: 'Every N minutes' },
      { value: 'daily', label: 'Daily (every 24 hours)' },
      { value: 'weekly', label: 'Weekly (every 7 days)' },
      { value: 'monthly', label: 'Monthly (every 30 days)' }
    ];
    var YES_NO = [{ value: 'no', label: 'No' }, { value: 'yes', label: 'Yes' }];

    function newSchedule() {
      if (!window.YuzuDialog) return;
      YuzuDialog.request('GET', '/api/instructions?enabled_only=1&limit=500').then(function (r) {
        var defs = r.ok && r.data && Array.isArray(r.data.definitions) ? r.data.definitions : null;
        if (!defs) {
          showToast(r.status === 403
            ? 'Choosing an instruction needs the InstructionDefinition:Read permission.'
            : errText(r, 'Could not load instructions (HTTP ' + r.status + ').'), 'error');
          return;
        }
        if (!defs.length) { showToast('There are no enabled instructions to schedule.', 'warning'); return; }
        var byId = {};
        var options = defs.map(function (d) {
          byId[d.id] = d;
          return { value: d.id, label: d.name + (d.plugin ? ' (' + d.plugin + ')' : '') };
        });
        return YuzuDialog.form({
          title: 'New schedule',
          body: 'Runs one instruction on a repeat, without anyone present. You confirm the details next.',
          fields: [
            { name: 'name', label: 'Name', type: 'text', maxlength: 200, required: true },
            { name: 'definition_id', label: 'Instruction', type: 'select', options: options },
            { name: 'frequency_type', label: 'Cadence', type: 'select', options: CADENCES,
              hint: 'The scheduler applies the cadence only; it ignores time of day.' },
            { name: 'interval_minutes', label: 'Interval minutes', type: 'text', value: '60',
              inputmode: 'numeric', hint: 'Used by "Every N minutes" only.' },
            { name: 'scope_expression', label: 'Targets (scope expression)', type: 'text',
              maxlength: 2000, hint: 'Leave empty to target every device.' },
            { name: 'all_ack', label: 'Targets are empty: run on All devices?', type: 'select',
              options: YES_NO, hint: 'Choose Yes to acknowledge that an empty scope reaches every device.' },
            { name: 'requires_approval', label: 'Require approval for each run', type: 'select',
              options: YES_NO },
            { name: 'parameters', label: 'Parameters (JSON object)', type: 'textarea', rows: 4,
              value: '{}', maxlength: 20000 }
          ],
          submitLabel: 'Review',
          validate: function (v) {
            if (v.frequency_type === 'interval') {
              var n = Number(v.interval_minutes);
              if (!/^\d+$/.test(v.interval_minutes.trim()) || n < 1 || n > 525600)
                return 'Interval minutes must be a whole number from 1 to 525600.';
            }
            if (!v.scope_expression.trim() && v.all_ack !== 'yes')
              return 'No targets entered. Choose Yes under "run on All devices" to confirm every device.';
            var p = null;
            try { p = JSON.parse(v.parameters.trim() || '{}'); } catch (e) { p = null; }
            if (!p || typeof p !== 'object' || Array.isArray(p)) return 'Parameters must be a JSON object.';
            return null;
          }
        }).then(function (v) {
          if (v === null) return;
          return confirmSchedule(v, byId[v.definition_id]);
        });
      }).then(null, function () { /* another dialog is open: nothing to do */ });
    }

    // The mandatory last step: a plain-language summary, including the instruction's approval
    // mode (read from the definition), because the schedule starts enabled and fires unattended.
    function confirmSchedule(v, def) {
      return YuzuDialog.request('GET', '/api/v1/instructions/' + encodeURIComponent(v.definition_id))
        .then(function (r) {
          var d = r.ok && r.data && r.data.data ? r.data.data : null;
          var mode = d && typeof d.approval_mode === 'string' && d.approval_mode ? d.approval_mode : 'unknown';
          var scope = v.scope_expression.trim();
          var cadence = v.frequency_type === 'interval'
            ? 'every ' + v.interval_minutes.trim() + ' minutes'
            : (v.frequency_type === 'once' ? 'once, at the next scheduler tick (about now)' : v.frequency_type);
          var lines = [
            'Schedule "' + v.name.trim() + '" runs ' + (def ? def.name : v.definition_id) + ' ' + cadence + '.',
            'Targets: ' + (scope ? scope : 'ALL DEVICES') + '.',
            'Instruction approval mode: ' + mode + '. Require approval for each run: ' +
              (v.requires_approval === 'yes' ? 'yes' : 'no') + '.',
            'It starts enabled and runs without anyone present. A run can still be refused when it ' +
              'fires (for example by approval rules, or because the instruction needs one-time credentials).'
          ];
          return YuzuDialog.form({
            title: 'Create this schedule?',
            body: lines,
            fields: [],
            cancelLabel: 'Go back',
            submitLabel: 'Create schedule',
            submit: function () {
              var body = {
                name: v.name.trim(), definition_id: v.definition_id,
                frequency_type: v.frequency_type, scope_expression: scope,
                requires_approval: v.requires_approval === 'yes',
                parameters: JSON.parse(v.parameters.trim() || '{}')
              };
              if (v.frequency_type === 'interval') body.interval_minutes = Number(v.interval_minutes.trim());
              return YuzuDialog.request('POST', '/api/schedules', { json: body }).then(function (res) {
                if (res.ok) return null;
                if (res.status === 403) return 'You do not have permission to create schedules.';
                return errText(res, 'Could not create the schedule (HTTP ' + res.status + ').');
              });
            }
          });
        }).then(function (done) {
          if (done === null || done === undefined) return;
          showToast('Schedule created', 'success');
          loadSchedules();
        });
    }

    if (scNewBtn) scNewBtn.addEventListener('click', function () { if (!scNewBtn.disabled) newSchedule(); });
    scHost.addEventListener('click', function (e) {
      var b = e.target.closest ? e.target.closest('button[data-act]') : null;
      if (!b || !scHost.contains(b) || b.disabled) return;
      var row = b.closest('tr.row');
      if (!row) return;
      var act = b.getAttribute('data-act');
      if (act === 'sc-toggle') toggleSchedule(row);
      else if (act === 'sc-delete') deleteSchedule(row);
    });

    newBtn.addEventListener('click', function () { if (!newBtn.disabled) newWorkflow(); });
    delBtn.addEventListener('click', function () { if (!delBtn.disabled) deleteWorkflow(); });
    wfHost.addEventListener('click', function (e) {
      var b = e.target.closest ? e.target.closest('button[data-act="run"]') : null;
      if (!b || !wfHost.contains(b) || b.disabled) return;
      var brow = b.closest('tr.row');
      if (brow) runWorkflow(brow.getAttribute('data-workflow-id') || '');
    });

    wfHost.addEventListener('click', function (e) {
      var row = e.target.closest ? e.target.closest('tr.row') : null;
      if (row && wfHost.contains(row)) select(row);
    });
    wfHost.addEventListener('keydown', function (e) {
      if (e.key !== 'Enter' && e.key !== ' ') return;
      if (e.target && e.target.tagName === 'BUTTON') return; // let the button's own click run
      var row = e.target.closest ? e.target.closest('tr.row') : null;
      if (!row || !wfHost.contains(row)) return;
      e.preventDefault();
      select(row);
    });
    recentBody.addEventListener('click', function (e) {
      var row = e.target.closest ? e.target.closest('tr.row') : null;
      if (!row || !recentBody.contains(row)) return;
      panelFor = selectedId;
      $$('tr.row', recentBody).forEach(function (r) {
        var on = r === row;
        r.classList.toggle('sel', on);
        r.setAttribute('aria-selected', on ? 'true' : 'false');
      });
      showRun(row.getAttribute('data-run-id') || '');
    });
    recentDet.addEventListener('toggle', function () {
      if (recentDet.open && selectedId) loadRecent();
    });
    // A denied or degraded panel is not polled: each refresh of one writes a denial audit
    // row server-side, so a returning tab reloads only what answered with a list.
    doc.addEventListener('visibilitychange', function () {
      if (doc.hidden || !loadedAt || Date.now() - loadedAt <= RELOAD_AFTER_MS) return;
      if ($('.ops-list', wfHost)) loadWorkflows();
      if ($('.ops-list', scHost)) loadSchedules();
      if ($('.ops-list', runsStore)) loadRuns();
    });

    var qs = readQs();
    var wantId = qs ? (qs.get('wf') || '') : '';
    loadSchedules();
    loadRuns();
    loadWorkflows().then(function () {
      if (!wantId) return;
      if (showSteps(wantId)) { applyActions(); showLatest(); }
      else stepsEmpty('That workflow is not listed, or you may not see it.');
    });
  }

  var controllers = {
    approvals: approvalsController,
    executions: executionsController,
    workflows: workflowsController
  };
  var page = doc.body ? doc.body.getAttribute('data-page') : '';
  if (controllers[page]) controllers[page]();
})();
