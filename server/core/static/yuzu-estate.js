/* yuzu-estate.js -- device containment (quarantine) controls on /hardware.
 *
 * One delegated click listener (capture phase) over `[data-act]` controls rendered by the
 * containment fragments and the hardware list. No inline handlers, no markup sinks: every
 * string is set with textContent; ids and keys are encodeURIComponent-ed into paths.
 * Depends on window.YuzuDialog (yuzu-dialog.js).
 *
 *   data-act="row-containment"  list row link: stop the row's own click handler so the
 *                               anchor opens the Containment lens, not the plain record.
 *   data-act="quarantine"       two steps: form (reason, whitelist) then a danger confirm
 *                               that performs POST /api/v1/quarantine.
 *   data-act="release"          danger confirm that performs DELETE /api/v1/quarantine/{id}.
 */
(function () {
  'use strict';

  var D = window.YuzuDialog;
  var WHITELIST_TOKEN = /^[0-9A-Fa-f.:]{1,45}$/;

  function enc(s) { return encodeURIComponent(s); }

  function failMessage(res) {
    if (res.status === 0) return res.message || 'The request may not have applied.';
    if (res.status >= 500) {
      var cid = res.data && res.data.error && res.data.error.correlation_id;
      return 'The server could not complete this request.' + (cid ? ' Reference: ' + cid : '');
    }
    return res.message || 'The request was refused.';
  }

  function refresh(agent) {
    if (!window.htmx) { location.reload(); return; }
    var path = '/fragments/hardware/ci/containment?id=' + enc(agent);
    if (document.getElementById('hw-containment'))
      window.htmx.ajax('GET', path, { target: '#hw-containment', swap: 'outerHTML' });
    if (document.getElementById('hw-quarantine-banner'))
      window.htmx.ajax('GET', path + '&banner=1', { target: '#hw-quarantine-banner', swap: 'outerHTML' });
  }

  // Page-session state after a release: the record is gone but the firewall rules are not
  // known to be. The fragment cannot say this (it only sees active records), so the page
  // does, once, and a reload honestly falls back to "No active quarantine record".
  function showReleased(agent) {
    var root = document.getElementById('hw-containment');
    if (!root) return;
    root.textContent = '';
    var box = document.createElement('div');
    box.className = 'hw-empty';
    var b = document.createElement('b');
    b.textContent = 'Record released, firewall not confirmed removed. ';
    box.appendChild(b);
    box.appendChild(document.createTextNode(
      'The server record is ended. The device keeps its firewall rules until the quarantine ' +
      "plugin's unquarantine action runs. "));
    var a = document.createElement('a');
    a.href = '/hardware/ci?id=' + enc(agent) + '&lens=actions';
    a.textContent = 'Open Actions';
    box.appendChild(a);
    root.appendChild(box);
  }

  function validateWhitelist(v) {
    var raw = (v.whitelist || '').trim();
    if (!raw) return null;
    var parts = raw.split(',');
    for (var i = 0; i < parts.length; i++) {
      if (!WHITELIST_TOKEN.test(parts[i].trim()))
        return 'Use comma-separated IPv4 or IPv6 addresses only (no ranges, no host names).';
    }
    return null;
  }

  function quarantine(btn) {
    var agent = btn.getAttribute('data-agent') || '';
    var host = btn.getAttribute('data-host') || agent;
    var online = btn.getAttribute('data-online');
    var mac = btn.getAttribute('data-mac') === '1';
    D.form({
      title: 'Quarantine ' + host,
      body: 'Say why this device is being contained. The reason is stored with the record.',
      fields: [
        { name: 'reason', label: 'Reason', type: 'textarea', maxlength: 1024, rows: 3, required: true },
        { name: 'whitelist', label: 'Allowed addresses (optional)', type: 'text', maxlength: 512,
          hint: 'Comma-separated IPv4 or IPv6 addresses (no ranges, no host names). The agent adds its ' +
                'configured server address on its own; on a dual-stack host, with a pinned route, or ' +
                'after a server address change, add the server explicitly. A device that cannot reach ' +
                'the server needs out-of-band recovery. See security-hardening.md, "Whitelisting on a ' +
                'dual-stack host".' }
      ],
      submitLabel: 'Continue',
      validate: validateWhitelist
    }).then(function (v) {
      if (!v) return null;
      var body = [
        host + ' will be cut off from the network except the addresses you list and the Yuzu server ' +
          'address the agent resolved when it last started.',
        'Instructions sent from Yuzu to this device are withheld until it is released.'
      ];
      if (online === '0')
        body.push('This device is offline. The quarantine is recorded now and applied when it next connects.');
      if (mac)
        body.push('On macOS, releasing restores the default firewall rules. Custom pf rules that were ' +
                  'active before are not restored.');
      return D.form({
        title: 'Quarantine ' + host + '?',
        body: body,
        fields: [],
        danger: true,
        submitLabel: 'Quarantine device',
        submit: function () {
          return D.request('POST', '/api/v1/quarantine', {
            json: { agent_id: agent, reason: v.reason.trim(), whitelist: (v.whitelist || '').trim() }
          }).then(function (res) { return res.ok ? null : failMessage(res); });
        }
      }).then(function (done) { if (done) refresh(agent); });
    }).catch(function () { /* a dialog was already open; the click is ignored */ });
  }

  function release(btn) {
    var agent = btn.getAttribute('data-agent') || '';
    var host = btn.getAttribute('data-host') || agent;
    D.form({
      title: 'Release ' + host + ' from quarantine?',
      body: [
        'This ends the quarantine record on the server, so Yuzu can send instructions to the device again.',
        "It does not remove the device's firewall rules. To restore its network access, run the " +
          "quarantine plugin's unquarantine action from this device's Actions tab (needs an " +
          'administrator or an approval).'
      ],
      fields: [],
      danger: true,
      submitLabel: 'Release record',
      submit: function () {
        return D.request('DELETE', '/api/v1/quarantine/' + enc(agent))
          .then(function (res) { return res.ok ? null : failMessage(res); });
      }
    }).then(function (done) {
      if (!done) return;
      showReleased(agent);
      var b = document.getElementById('hw-quarantine-banner');
      if (b && window.htmx)
        window.htmx.ajax('GET', '/fragments/hardware/ci/containment?id=' + enc(agent) + '&banner=1',
                         { target: '#hw-quarantine-banner', swap: 'outerHTML' });
    }).catch(function () { /* a dialog was already open */ });
  }

  document.addEventListener('click', function (e) {
    var t = e.target && e.target.closest ? e.target.closest('[data-act]') : null;
    if (!t) return;
    var act = t.getAttribute('data-act');
    if (act === 'row-containment') {
      e.stopPropagation();
      return;
    }
    if (act === 'quarantine' || act === 'release') {
      e.preventDefault();
      if (!D) return;
      if (act === 'quarantine') quarantine(t); else release(t);
    }
  }, true);
})();
