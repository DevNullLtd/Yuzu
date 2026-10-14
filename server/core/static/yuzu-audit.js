/* Audit and reviews page: client glue. Delegated listeners only; nothing inline.
 *
 *  - [data-act="toggle-row"]  opens and closes an audit row's detail (the next row). Real
 *    <button aria-expanded aria-controls>, so it works from the keyboard. State is read and
 *    written on the DOM only; all text arrives from the server already escaped.
 *
 *  - Access reviews: Open review, Close campaign, Attest and Flag. Each calls an existing REST
 *    v1 route through YuzuDialog.request; the campaign list and body reload afterwards.
 *
 * The denied / unavailable notes and the Retry button come from yuzu-access.js, which the page
 * loads first and which keys on each panel's data-denied attribute.
 */
(function () {
  'use strict';

  document.addEventListener('click', function (e) {
    var b = e.target.closest('[data-act="toggle-row"]');
    if (!b) return;
    var row = b.closest('tr');
    var det = row && row.nextElementSibling;
    if (!det || !det.classList.contains('result-detail')) return;
    var open = det.classList.toggle('open');
    row.classList.toggle('expanded', open);
    b.setAttribute('aria-expanded', open ? 'true' : 'false');
  });

  // ---- Access reviews -------------------------------------------------------------------
  // Every change goes through the existing REST v1 routes via YuzuDialog.request (same-origin
  // fetch; the module prompts for MFA step-up if the server ever asks). Nothing here builds
  // markup from a stored string: dialog text is set with textContent by the module, a campaign
  // id is validated before it is placed in a URL, and a principal travels in the JSON body,
  // never in a path.

  var ID_RE = /^[A-Za-z0-9_-]{1,64}$/;
  var API = '/api/v1/access-reviews';

  function banner(text) {
    var b = document.getElementById('ar-banner');
    if (b) b.textContent = text || '';
  }

  // The write succeeded; a dropped audit row is the one outcome the page must not hide.
  function written(r) {
    banner(r.auditFailed ?
      'The change was applied but its audit record could not be written. Treat it as unconfirmed ' +
      'and check the audit log once the audit store recovers.' : '');
  }

  // A rejected write: the server's own message when it gave one, else a fixed sentence.
  function failure(r) {
    return r.message || (r.status >= 500 || r.status === 0 ?
      'The server could not complete that request. Try again.' :
      'The request was not accepted (status ' + r.status + ').');
  }

  function post(url, body) {
    return YuzuDialog.request('POST', url, body === undefined ? {} : { json: body });
  }

  function loadCampaign(id) {
    htmx.ajax('GET', '/fragments/access/reviews/campaign?id=' + encodeURIComponent(id),
              { target: '#ar-campaign' });
  }

  function loadCampaigns() {
    htmx.ajax('GET', '/fragments/access/reviews/campaigns',
              { target: '#ar-campaigns' });
  }

  function openReview() {
    var created = '';
    YuzuDialog.form({
      title: 'Open review campaign',
      fields: [{ name: 'title', label: 'Campaign title', required: true, maxlength: 200,
                 placeholder: 'e.g. Q3 2026 access review' }],
      note: 'Freezes every current grant (one row per principal and role) for attestation. ' +
            'Closed campaigns are kept permanently.',
      submitLabel: 'Open review campaign',
      submit: function (v) {
        return post(API, { title: v.title.trim() }).then(function (r) {
          if (!r.ok) return failure(r);
          written(r);
          // The REST envelope nests the id: {data: {campaign_id, grant_count}}.
          var id = r.data && r.data.data && r.data.data.campaign_id;
          created = typeof id === 'string' && ID_RE.test(id) ? id : '';
          return null;
        });
      }
    }).then(function (vals) {
      if (!vals) return;
      loadCampaigns();
      if (created) {
        loadCampaign(created);
        history.replaceState(null, '', '/access/audit?campaign=' + encodeURIComponent(created));
      }
    }, function () {});
  }

  function closeCampaign(id) {
    if (!ID_RE.test(id)) return;
    YuzuDialog.form({
      title: 'Close review campaign',
      body: 'Close review campaign ' + id + '? An incomplete review can still be closed.',
      note: 'Closing is one-way. The decisions stay as evidence.',
      submitLabel: 'Close campaign',
      danger: true,
      submit: function () {
        return post(API + '/' + encodeURIComponent(id) + '/close').then(function (r) {
          if (!r.ok) return failure(r);
          written(r);
          return null;
        });
      }
    }).then(function (vals) {
      if (!vals) return;
      loadCampaigns();
      loadCampaign(id);
    }, function () {});
  }

  // Records one decision. The decision value comes from the button the server drew, so this
  // script cannot swap attest and flag. Resolves to null on success or an error sentence.
  function decide(btn, justification) {
    var root = document.querySelector('#ar-campaign [data-campaign-id]');
    var row = btn.closest('tr');
    var id = root && root.getAttribute('data-campaign-id');
    if (!row || !id || !ID_RE.test(id)) return Promise.resolve('That campaign is no longer selected.');
    var d = row.dataset;
    return post(API + '/' + encodeURIComponent(id) + '/attestations', {
      principal_type: d.principalType, principal_id: d.principalId, role_name: d.roleName,
      decision: btn.dataset.decision, justification: justification
    }).then(function (r) {
      if (!r.ok) return failure(r);
      written(r);
      loadCampaign(id);
      return null;
    });
  }

  function justificationOf(btn) {
    var row = btn.closest('tr');
    var input = row && row.querySelector('[data-ar-justification]');
    return input ? input.value : '';
  }

  function attest(btn) {
    btn.disabled = true;
    decide(btn, justificationOf(btn)).then(function (err) {
      if (err) { banner(err); btn.disabled = false; }
    });
  }

  function flag(btn) {
    var row = btn.closest('tr');
    if (!row) return;
    var d = row.dataset;
    var just = justificationOf(btn);
    YuzuDialog.form({
      title: 'Flag for revocation',
      body: 'Flag ' + d.principalType + ' "' + d.principalId + '" role "' + d.roleName +
            '" for revocation? This records evidence only. It does NOT revoke the grant.',
      submitLabel: 'Flag for revocation',
      danger: true,
      submit: function () { return decide(btn, just); }
    }).then(function () {}, function () {});
  }

  document.addEventListener('click', function (e) {
    var b = e.target.closest('[data-act^="ar-"]');
    if (!b) return;
    var act = b.getAttribute('data-act');
    if (act === 'ar-open') openReview();
    else if (act === 'ar-close') closeCampaign(b.getAttribute('data-campaign-id') || '');
    else if (act === 'ar-attest') attest(b);
    else if (act === 'ar-flag') flag(b);
  });

  // Mark the selected campaign in the list. The two panels swap independently, so the mark is
  // recomputed after either; the campaign body always carries its id (even closed or read-only).
  document.body.addEventListener('htmx:afterSwap', function () {
    var root = document.querySelector('#ar-campaign [data-campaign-id]');
    var id = root ? root.getAttribute('data-campaign-id') : '';
    Array.prototype.forEach.call(document.querySelectorAll('#ar-campaigns tr[data-campaign-id]'),
      function (tr) {
        tr.classList.toggle('sel', !!id && tr.getAttribute('data-campaign-id') === id);
      });
  });

  // Deep link: /access/audit?campaign=<id> selects that campaign on load.
  document.addEventListener('DOMContentLoaded', function () {
    var m = /[?&]campaign=([^&]*)/.exec(location.search);
    var id = '';
    try { id = m ? decodeURIComponent(m[1]) : ''; } catch (e) { id = ''; }
    if (ID_RE.test(id)) loadCampaign(id);
  });
})();
