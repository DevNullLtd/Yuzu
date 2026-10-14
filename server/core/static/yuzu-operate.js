/* yuzu-operate.js -- page controllers for the Operate pages (Approvals, Executions, Workflows).
 *
 * Read-only: the server renders every list and panel as an HTML fragment (the fragment
 * routes' `view=page` branches); this file only fetches them, swaps them into their host
 * and fills the single detail panel from the selected row's data-* attributes with
 * textContent. One controller per page, chosen by <body data-page>.
 *
 * Rules this file keeps (pinned by test_operate_pages_ui.cpp):
 *   - no dynamic-code or raw-markup sinks of any kind (the test pins the exact list);
 *   - innerHTML is assigned ONLY from a 200 fragment the server rendered (and escaped), to
 *     the fragment hosts (#ap-list, #exec-list, #exec-selected, #wf-list, #sc-list, #wf-runs-store,
 *     #wf-run-body, #wf-recent-body); a non-200 body is
 *     never written anywhere;
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

  function executionsController() {
    var host = $('#exec-list');
    var panel = $('#exec-selected');
    var chip = $('#exec-chip');
    var confinedNote = $('#exec-confined');
    var defSel = $('#f-def');
    var defHint = $('#f-def-hint');
    if (!host || !panel || !defSel) return;

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
    }

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
    function showDetail(id) {
      var mine = ++dseq;
      selectedId = id;
      markSelected();
      writeQs(function (p) { p.set('id', id); });
      return fetchFragment('/fragments/executions/' + encodeURIComponent(id) +
                           '/detail?view=page').then(function (res) {
        if (mine !== dseq) return;
        if (res.status !== 200) { panelNote(detailCopy(res.status)); return; }
        panel.innerHTML = res.html; // server-rendered and escaped
        renderLocalTimes(panel);
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

  function workflowsController() {
    var wfHost = $('#wf-list');
    var scHost = $('#sc-list');
    var stepsTitle = $('#wf-steps-title');
    var stepsBody = $('#wf-steps-body');
    var runsStore = $('#wf-runs-store');
    var runBody = $('#wf-run-body');
    var recentDet = $('#wf-recent-det');
    var recentBody = $('#wf-recent-body');
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
      if (!block) { selectedId = ''; markSelected(); return false; }
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
        when.textContent = !list ? 'Unavailable' : (confined ? 'None visible' : 'Not run');
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
      showSteps(id);
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
          return;
        }
        wfHost.innerHTML = res.html; // server-rendered and escaped
        // Re-apply the selection without a refetch; a workflow that left the list
        // (deleted, or a product pack was uninstalled) clears it and says so.
        if (selectedId && !showSteps(selectedId))
          stepsEmpty('That workflow is no longer listed.');
        applyLatest();
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
      });
    }

    wfHost.addEventListener('click', function (e) {
      var row = e.target.closest ? e.target.closest('tr.row') : null;
      if (row && wfHost.contains(row)) select(row);
    });
    wfHost.addEventListener('keydown', function (e) {
      if (e.key !== 'Enter' && e.key !== ' ') return;
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
      if (showSteps(wantId)) showLatest();
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
