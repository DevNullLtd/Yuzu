// Compliance dashboard page — fleet policy compliance overview.
// Uses HTMX for fragment loading; mock data until PolicyStore is wired.

#include "app_shell.hpp"

// NOLINTBEGIN(cert-err58-cpp)
const char* const kCompliancePageTemplate =
    R"HTM(<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>Yuzu — Compliance</title>
  <link rel="stylesheet" href="/static/yuzu.css">
  <script src="/static/htmx.js"></script>
  <style>
    /* ── Content ───────────────────────────────────────────── */
    .content {
      padding: 22px 28px 36px; display: flex; flex-direction: column; gap: 22px;
    }

    /* ── Page header ──────────────────────────────────────── */
    .page-header {
      display: flex; flex-wrap: wrap; align-items: flex-end; gap: 12px 24px;
    }
    .page-header h1 {
      font-size: 24px; font-weight: 600; letter-spacing: -.015em; line-height: 1.2;
      color: var(--ink);
    }
    .page-header .subtitle { font-size: 14px; color: var(--mut); margin-top: 4px; max-width: 70ch; }
    .page-header .btn { margin-left: auto; }

    /* ── Layout: a stack of shared .readout / .panel blocks ──── */
    #compliance-summary { display: flex; flex-direction: column; gap: 16px; }
    .page-stack { display: flex; flex-direction: column; gap: 16px; }
    .tw { overflow-x: auto; }
    .panel > .pb + .tw { border-top: 1px solid var(--line); }
    .compliance-bar { margin-top: 8px; }

    /* ── Tables ────────────────────────────────────────────── */
    .policy-table, .detail-table { width: 100%; min-width: 640px; border-collapse: collapse; }
    .policy-table th, .detail-table th {
      text-align: left; padding: 8px 16px; white-space: nowrap;
      font-size: 12.5px; font-weight: 500; color: var(--mut);
      background: var(--surface2); border-bottom: 1px solid var(--line);
    }
    .policy-table td, .detail-table td {
      padding: var(--cell-y) 16px; white-space: nowrap;
      color: var(--ink2); border-bottom: 1px solid var(--line);
    }
    .policy-table tbody tr:last-child td, .detail-table tbody tr:last-child td { border-bottom: 0; }
    .policy-table tbody tr:hover td, .detail-table tbody tr:hover td { background: var(--surface2); }
    .policy-table td:last-child { text-align: right; }
    /* Cell classes carry the table prefix so they outrank the table's own td rule above */
    .policy-table .policy-name { font-weight: 600; color: var(--ink); }
    .policy-scope, .mono-id {
      font-family: var(--mds-font-family-mono); font-size: 12.5px;
    }
    .policy-table .policy-scope { color: var(--mut); white-space: normal; min-width: 14ch; }
    .policy-pct { font-weight: 600; }
    .policy-pct.good { color: var(--ok); }
    .policy-pct.warn { color: var(--warn); }
    .policy-pct.bad  { color: var(--bad); }
    .policy-table .policy-count, .detail-table .cell-mut { color: var(--mut); }
    .policy-count { font-size: 12.5px; }
    .detail-table .cell-wrap { white-space: normal; }

    /* ── Mini compliance bars in table ─────────────────────── */
    .mini-bar {
      width: 80px; height: 6px; background: var(--line); border-radius: 2px;
      overflow: hidden; display: inline-block; vertical-align: middle; margin-left: 8px;
    }
    .mini-fill { height: 100%; }
    .mini-fill.good { background: var(--ok); }
    .mini-fill.warn { background: var(--warn); }
    .mini-fill.bad  { background: var(--bad); }

    /* ── Detail panel (per-policy agent breakdown) ──────── */
    .detail-panel h3 {
      display: flex; align-items: baseline; gap: 8px;
      padding: 14px 16px 0; font-size: 14px; font-weight: 600; color: var(--ink);
    }
    .detail-id { font-size: 12.5px; font-weight: 400; color: var(--mut); }
    .detail-badges { display: flex; flex-wrap: wrap; gap: 8px; padding: 12px 16px 14px; }

    /* ── Empty / loading states ───────────────────────────── */
    .empty-state, .policy-table td.empty-state {
      text-align: center; padding: 28px 16px; white-space: normal;
      color: var(--mut); font-size: 14px;
    }

    /* ── Buttons ──────────────────────────────────────────── */
    .btn.btn-secondary {
      height: var(--ctl); padding: 0 14px; font-size: 14px; font-weight: 500;
      color: var(--ink); background: var(--raise); border: 1px solid var(--line2);
      border-radius: var(--rad-ctl); transition: background-color .12s, border-color .12s;
    }
    .btn.btn-secondary:hover:not(:disabled) { opacity: 1; background: var(--surface2); border-color: var(--mut); }
    .btn.btn-sm { height: 28px; padding: 0 10px; font-size: 13px; }
    /* Row action: text button at the table's right edge */
    .policy-table .btn.btn-secondary {
      padding: 0 6px; color: var(--primary); background: none; border-color: transparent;
    }
    .policy-table .btn.btn-secondary:hover:not(:disabled) {
      background: none; border-color: transparent; text-decoration: underline;
    }

    /* ── Refresh indicator ────────────────────────────────── */
    .htmx-indicator {
      display: none; color: var(--mut); font-size: 13px; font-weight: 400;
    }
    .htmx-request .htmx-indicator,
    .htmx-request.htmx-indicator { display: inline; }

    /* ── Actions: summary header, detail row, per-viewer visibility ──── */
    .hd .acts, .detail-actions { display: flex; flex-wrap: wrap; gap: 8px; }
    .hd .acts { margin-left: auto; }
    .detail-actions { padding: 0 16px 14px; }
    /* Detail and fragment controls stay hidden until the summary probe says the
       viewer holds the permission (body classes set from #policies-panel). */
    [data-perm] { display: none; }
    body.can-write [data-perm="write"], body.can-execute [data-perm="execute"],
    body.can-delete [data-perm="delete"] { display: inline-flex; }
    [hidden] { display: none !important; }

    @media (max-width: 640px) { .content { padding: 16px; } }
  </style>
</head>
<body>

  <!--yuzu:shell--><!--/yuzu:shell-->

  <div class="content">

    <div class="page-header">
      <div>
        <h1>Compliance</h1>
        <div class="subtitle">Policy compliance status across the fleet</div>
      </div>
      <button class="btn btn-secondary"
              hx-get="/fragments/compliance/summary"
              hx-target="#compliance-summary"
              hx-swap="innerHTML">
        <svg class="icon" style="width:14px;height:14px"><use href="/static/icons.svg#refresh-cw"></use></svg>
        Refresh
      </button>
    </div>

    <div class="page-stack">
      <div id="compliance-summary"
           hx-get="/fragments/compliance/summary"
           hx-trigger="load"
           hx-swap="innerHTML"
           data-denied="Needs the Policy Read permission.">
        <div class="empty-state">Loading compliance data...</div>
      </div>

      <div class="panel">
        <div class="hd"><h2>Policy detail</h2><span class="sub">Per-device results for one policy</span></div>
        <div id="compliance-detail" data-denied="Needs the Policy Read permission.">
          <div class="empty-state">Click <strong>View</strong> on a policy above to see per-device compliance.</div>
        </div>
      </div>

      <div id="policy-fragments"
           hx-get="/fragments/policy-fragments"
           hx-trigger="load"
           hx-swap="innerHTML"
           data-denied="Needs the Policy Read permission.">
        <div class="empty-state">Loading policy fragments...</div>
      </div>

      <div class="panel">
        <div class="hd"><h2>Compliance by tag</h2>
          <span class="sub">Devices should have all structured tag categories assigned. Devices missing tags are flagged but keep working.</span></div>
        <div id="tag-compliance"
             hx-get="/fragments/settings/tag-compliance"
             hx-trigger="load"
             hx-swap="innerHTML"
             data-denied="Needs the Tag Read permission.">
          <div class="empty-state">Loading tag compliance...</div>
        </div>
      </div>
    </div>

  </div>

  <div id="toast-container" class="toast-container"></div>

  <!-- Shared dialog module: must precede the page script. Absent (404) means the
       page falls back to window.confirm and hides the YAML dialogs. -->
  <script src="/static/yuzu-dialog.js"></script>
)HTM"
    R"HTM(  <script>
    /* ── Toast notification system ─────────────────────────── */
    function showToast(message, level) {
      var c = document.getElementById('toast-container');
      if (!c) return;
      var t = document.createElement('div');
      t.className = 'toast toast-' + (level || 'info');
      t.textContent = message;
      var close = document.createElement('button');
      close.textContent = '\u00d7';
      close.style.cssText = 'background:none;border:none;color:var(--muted);cursor:pointer;margin-left:auto;font-size:1.2rem;padding:0 0 0 var(--sp-3);';
      close.onclick = function() { t.remove(); };
      t.style.display = 'flex';
      t.style.alignItems = 'center';
      t.appendChild(close);
      c.appendChild(t);
      if (level !== 'error') {
        setTimeout(function() { t.style.opacity = '0'; t.style.transition = 'opacity 0.3s'; setTimeout(function() { t.remove(); }, 300); }, level === 'warning' ? 8000 : 4000);
      }
    }
    document.body.addEventListener('showToast', function(e) {
      var d = e.detail || {};
      showToast(d.message || 'Done', d.level || 'success');
    });

    /* htmx drops 4xx/5xx bodies, so a refused or failed panel would sit on
       "Loading..." forever: say why in the panel the request targeted. */
    document.body.addEventListener('htmx:responseError', function(e) {
      var d = e.detail || {};
      var t = d.target;
      if (!t || !t.hasAttribute || !t.hasAttribute('data-denied')) return;
      var st = d.xhr ? d.xhr.status : 0;
      t.textContent = (st === 401 || st === 403)
        ? t.getAttribute('data-denied')
        : 'Temporarily unavailable. Try Refresh in a moment.';
      t.className = 'empty-state';
    });

    /* Per-viewer controls: the summary render probes Policy:Write/Execute/Delete
       once and leaves the answer on #policies-panel; the detail and fragment
       panels read it from there. No panel (summary refused or degraded) = none. */
    function applyPerms() {
      var p = document.getElementById('policies-panel');
      var b = document.body.classList;
      b.toggle('can-write', !!p && p.getAttribute('data-can-write') === '1');
      b.toggle('can-execute', !!p && p.getAttribute('data-can-execute') === '1');
      b.toggle('can-delete', !!p && p.getAttribute('data-can-delete') === '1');
    }
    function showDialogControls(root) {
      if (!(window.YuzuDialog && window.YuzuDialog.form)) return;
      var n = root.querySelectorAll('[data-needs-dialog]');
      for (var i = 0; i < n.length; i++) n[i].hidden = false;
    }
    document.body.addEventListener('htmx:afterSwap', function(e) {
      applyPerms();
      showDialogControls(e.target || document);
    });
  </script>
)HTM"
    R"HTM(  <script>
    /* ── Policy actions: one delegated listener over [data-act] ─────────
       fetch() ignores HX-Trigger, so toasts are composed here from the JSON
       body. Server text is only ever set with textContent. */
    function api(method, url, body) {
      var init = { method: method, credentials: 'same-origin', cache: 'no-store', headers: {} };
      if (body !== undefined) {
        init.headers['Content-Type'] = 'application/json';
        init.body = JSON.stringify(body);
      }
      return fetch(url, init).then(function(r) {
        var audit = r.headers.get('Sec-Audit-Failed') === 'true';
        return r.json().catch(function() { return null; }).then(function(d) {
          return { ok: r.ok, status: r.status, data: d, audit: audit };
        });
      }, function() { return { ok: false, status: 0, data: null, audit: false }; });
    }
    function errText(r, fallback) {
      var d = r.data;
      if (d && typeof d.error === 'string') return d.error;
      if (d && d.error && typeof d.error.message === 'string') return d.error.message;
      if (r.status === 403) return 'You do not have permission for this action.';
      if (r.status === 0) return 'The request may not have applied. Refresh to check.';
      return fallback;
    }
    function done(r, okMsg, failMsg) {
      if (r.status === 401) { location.assign('/login'); return false; }
      if (!r.ok) { showToast(errText(r, failMsg), 'error'); return false; }
      showToast(okMsg + (r.audit ? ' The audit record could not be written.' : ''),
                r.audit ? 'warning' : 'success');
      return true;
    }
    function confirmAct(title, lines, label, danger) {
      if (window.YuzuDialog && window.YuzuDialog.confirm) {
        return window.YuzuDialog.confirm({ title: title, body: lines, confirmLabel: label, danger: !!danger });
      }
      return Promise.resolve(window.confirm(title + '\n\n' + lines.join('\n')));
    }
    function reload(sel, url) {
      if (window.htmx) htmx.ajax('GET', url, { target: sel, swap: 'innerHTML' });
    }
    function reloadSummary() { reload('#compliance-summary', '/fragments/compliance/summary'); }
    function reloadFragments() { reload('#policy-fragments', '/fragments/policy-fragments'); }
    function reloadDetail(id) { reload('#compliance-detail', '/fragments/compliance/' + encodeURIComponent(id)); }
    function clearDetail(text) {
      var d = document.getElementById('compliance-detail');
      d.textContent = text;
      d.className = 'empty-state';
    }
    var MAX_YAML = 1048576;
    function yamlDialog(title, note, url, okMsg) {
      return window.YuzuDialog.form({
        title: title, note: note, submitLabel: 'Create',
        fields: [{ name: 'yaml', label: 'YAML', type: 'textarea', rows: 14, required: true }],
        validate: function(v) { return v.yaml.length > MAX_YAML ? 'The YAML is larger than 1 MiB.' : null; },
        submit: function(v) {
          return api('POST', url, { yaml_source: v.yaml }).then(function(r) {
            if (r.ok) { showToast(okMsg, 'success'); return null; }
            return errText(r, 'The server refused the YAML.');
          });
        }
      });
    }
    var ACTS = {
      'toggle-enabled': function(el, id, name) {
        var on = el.getAttribute('data-enabled') !== '1';
        var lines = on
          ? ['It will be re-checked on its schedule, dispatching a read-only check to the devices in its scope.']
          : ['Scheduled checks stop for this policy. Its last results stay on the page and go stale.'];
        return confirmAct((on ? 'Enable ' : 'Disable ') + name + '?', lines, on ? 'Enable' : 'Disable', !on)
          .then(function(ok) {
            if (!ok) return;
            return api('POST', '/api/policies/' + encodeURIComponent(id) + (on ? '/enable' : '/disable'))
              .then(function(r) {
                done(r, name + (on ? ' enabled.' : ' disabled.'), 'Could not change the policy.');
                reloadSummary();
              });
          });
      },
      'evaluate': function(el, id, name) {
        return api('POST', '/api/policies/' + encodeURIComponent(id) + '/evaluate').then(function(r) {
          var eid = r.data && r.data.execution_id;
          if (done(r, 'Evaluation of ' + name + ' dispatched' + (eid ? ' (execution ' + eid + ').' : '.'),
                   'Could not evaluate the policy.')) reloadSummary();
        });
      },
      'invalidate-all': function() {
        return confirmAct('Invalidate all compliance results?', [
          'Every policy result is reset to unknown, so fleet compliance reads 0% until devices check in again.',
          'This cannot be undone.'], 'Invalidate all', true).then(function(ok) {
          if (!ok) return;
          return api('POST', '/api/policies/invalidate-all').then(function(r) {
            done(r, 'All results invalidated.', 'Could not invalidate results.');
            reloadSummary();
          });
        });
      },
      'invalidate': function(el, id, name) {
        return confirmAct('Invalidate cache for ' + name + '?', [
          'Its results reset to unknown until devices check in again, and fix attempt counts restart.'],
          'Invalidate', true).then(function(ok) {
          if (!ok) return;
          return api('POST', '/api/policies/' + encodeURIComponent(id) + '/invalidate').then(function(r) {
            if (done(r, 'Cache invalidated for ' + name + '.', 'Could not invalidate the policy.')) {
              reloadSummary();
              reloadDetail(id);
            }
          });
        });
      },
      'remediate': function(el, id, name) {
        var n = el.getAttribute('data-n');
        var lines = [(n !== null ? 'Currently ' + n + ' non-compliant devices; the fix runs on whichever are non-compliant when you confirm.'
                                : 'The fix runs on whichever devices are non-compliant when you confirm.'),
          'It dispatches the policy fragment\u2019s fix instruction directly, with no approval step. Review the fragment before you proceed.'];
        return confirmAct('Remediate ' + name + '?', lines, 'Remediate', true).then(function(ok) {
          if (!ok) return;
          return api('POST', '/api/policies/' + encodeURIComponent(id) + '/remediate', {}).then(function(r) {
            var d = r.data || {};
            if (done(r, 'Remediation dispatched' + (d.agents !== undefined ? ' to ' + d.agents + ' devices' : '') +
                        (d.execution_id ? ' (execution ' + d.execution_id + ').' : '.'),
                     'Could not remediate the policy.')) {
              reloadSummary();
              reloadDetail(id);
            }
          });
        });
      },
      'delete-policy': function(el, id, name) {
        return confirmAct('Delete ' + name + '?', [
          'The policy and its compliance results are removed. This cannot be undone.'],
          'Delete', true).then(function(ok) {
          if (!ok) return;
          return api('DELETE', '/api/policies/' + encodeURIComponent(id)).then(function(r) {
            /* The route answers 200 {"deleted":false} when nothing was removed. */
            if (r.ok && !(r.data && r.data.deleted === true)) {
              showToast(name + ' was not deleted; it may already be gone.', 'warning');
              reloadSummary();
              return;
            }
            if (done(r, name + ' deleted.', 'Could not delete the policy.')) {
              clearDetail('Policy deleted.');
              reloadSummary();
              reloadFragments();
            }
          });
        });
      },
      'delete-fragment': function(el, id, name) {
        return confirmAct('Delete fragment ' + name + '?', [
          'This cannot be undone. A fragment that a policy still uses is refused.'],
          'Delete', true).then(function(ok) {
          if (!ok) return;
          return api('DELETE', '/api/policy-fragments/' + encodeURIComponent(id)).then(function(r) {
            if (r.ok && !(r.data && r.data.deleted === true)) {
              showToast(name + ' was not deleted; a policy may still use it.', 'warning');
            } else if (!done(r, name + ' deleted.', 'Could not delete the fragment.')) {
              return;
            }
            reloadFragments();
          });
        });
      },
      'new-policy': function() {
        return yamlDialog('New policy',
          'Paste a Policy YAML document (kind: Policy). Once enabled it dispatches a read-only check on a schedule.',
          '/api/policies', 'Policy created.').then(function(v) { if (v) reloadSummary(); });
      },
      'new-fragment': function() {
        return yamlDialog('New fragment',
          'Paste a PolicyFragment YAML document (kind: PolicyFragment). Its fix instruction runs on devices when a policy using it is remediated, so author it with the care of any instruction.',
          '/api/policy-fragments', 'Fragment created.').then(function(v) { if (v) reloadFragments(); });
      }
    };
    var busy = false;
    document.addEventListener('click', function(e) {
      var el = e.target.closest ? e.target.closest('[data-act]') : null;
      if (!el || el.disabled) return;
      var fn = ACTS[el.getAttribute('data-act')];
      if (!fn) return;
      /* A switch must not flip until the server confirms: the refresh redraws it. */
      if (el.type === 'checkbox') e.preventDefault();
      if (busy) return;
      busy = true;
      Promise.resolve(fn(el, el.getAttribute('data-id') || '', el.getAttribute('data-name') || ''))
        .catch(function() { showToast('The action did not complete.', 'error'); })
        .then(function() { busy = false; });
    });
  </script>
</body>
</html>
)HTM";

// The shell (sidebar + header) is rendered into the template once, at static init (app_shell.hpp).
extern const char* const kComplianceHtml =
    yuzu::server::shell::bake(kCompliancePageTemplate, {.active_key = "compliance"});
// NOLINTEND(cert-err58-cpp)
