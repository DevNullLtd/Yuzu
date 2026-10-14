/* Integrations page controller: webhooks, offload targets, directory sync.
 *
 * Server HTML arrives only through htmx swaps of server-rendered fragments.
 * This file never assigns server text as markup, never evals, and writes
 * every message with textContent. Writes go to the existing JSON routes; the
 * three routes 400 on form encoding and there is no JSON extension bundled, so
 * they are fetch calls rather than hx-post. A confirm is a click-through (no
 * server step-up exists on these routes), not an approval. */
(function () {
  'use strict';

  var CONTROL = /[\u0000-\u001f\u007f]/;

  // ---- shared ----

  function resultBox(el) {
    var form = el.closest('form');
    if (form) { return form.querySelector('[data-int-result]'); }
    var panel = el.closest('.panel');
    return panel ? panel.querySelector('[data-int-panel-result]') : null;
  }

  function say(el, text, kind) {
    var box = resultBox(el);
    if (!box) { return; }
    box.textContent = text;
    box.hidden = false;
    box.classList.toggle('warn', kind !== 'ok');
  }

  function refresh(eventName) {
    if (window.htmx && document.body) { window.htmx.trigger(document.body, eventName); }
  }

  function errorText(res, data) {
    if (res.status === 401) { return 'Your session has ended. Sign in again.'; }
    if (data && data.error) {
      if (typeof data.error === 'string') { return data.error; }
      if (typeof data.error.message === 'string') { return data.error.message; }
    }
    return 'The server answered ' + res.status + '.';
  }

  function sendJson(method, url, body) {
    var opts = {
      method: method,
      credentials: 'same-origin',
      cache: 'no-store',
      headers: { 'Content-Type': 'application/json', 'Accept': 'application/json' }
    };
    if (body !== undefined) { opts.body = JSON.stringify(body); }
    return fetch(url, opts).then(function (res) {
      return res.json().catch(function () { return null; }).then(function (data) {
        return { res: res, data: data };
      });
    });
  }

  function fill(template, map) {
    return template.replace(/\{(\w+)\}/g, function (m, k) {
      return Object.prototype.hasOwnProperty.call(map, k) ? map[k] : m;
    });
  }

  function clearSecrets(form) {
    var secrets = form.querySelectorAll('input[type="password"]');
    for (var i = 0; i < secrets.length; i++) { secrets[i].value = ''; }
  }

  // Destination check mirrored from the server (which also refuses these).
  function parseDestination(raw) {
    var value = (raw || '').trim();
    if (!value) { return { error: 'Enter a URL.' }; }
    if (CONTROL.test(value)) { return { error: 'The URL contains control characters.' }; }
    var u;
    try { u = new URL(value); } catch (e) { return { error: 'Enter a full URL starting with http:// or https://.' }; }
    if (u.protocol !== 'http:' && u.protocol !== 'https:') {
      return { error: 'The URL must start with http:// or https://.' };
    }
    if (u.username || u.password) {
      return { error: 'Remove user:password from the URL. Use the credential field instead.' };
    }
    return { url: value, host: u.protocol + '//' + u.host };
  }

  function selectedEvents(form) {
    var all = form.querySelector('[data-int-all]');
    var boxes = form.querySelectorAll('input[type="checkbox"][value]');
    var labels = [];
    var classes = [];
    var ids = [];
    for (var i = 0; i < boxes.length; i++) {
      var b = boxes[i];
      if (all.checked || b.checked) {
        ids.push(b.value);
        labels.push(b.getAttribute('data-label') || b.value);
        var c = b.getAttribute('data-class');
        if (c && classes.indexOf(c) < 0) { classes.push(c); }
      }
    }
    if (!all.checked && ids.length === 0) { return null; }
    return {
      value: all.checked ? '*' : ids.join(','),
      labels: all.checked ? 'all fleet events' : labels.join(', '),
      classes: classes.join('; ')
    };
  }

  // "All events" and the four specific events are mutually exclusive.
  document.addEventListener('change', function (ev) {
    var t = ev.target;
    if (!t || t.type !== 'checkbox') { return; }
    var form = t.closest('form[data-int-action]');
    if (!form) { return; }
    if (t.hasAttribute('data-int-all') && t.checked) {
      var specific = form.querySelectorAll('input[type="checkbox"][value]');
      for (var i = 0; i < specific.length; i++) { specific[i].checked = false; }
    } else if (t.hasAttribute('value') && t.checked) {
      var all = form.querySelector('[data-int-all]');
      if (all) { all.checked = false; }
    }
  });

  // ---- webhooks ----

  function createWebhook(form) {
    var dest = parseDestination(form.elements['url'].value);
    if (dest.error) { say(form, dest.error, 'bad'); return; }
    var ev = selectedEvents(form);
    if (!ev) { say(form, 'Choose at least one event, or All events.', 'bad'); return; }
    var text = fill(form.getAttribute('data-confirm') || '',
      { events: ev.labels, host: dest.host, data: ev.classes });
    if (!window.confirm(text)) { return; }
    var body = { url: dest.url, event_types: ev.value, enabled: !!form.elements['enabled'].checked };
    var secret = form.elements['secret'].value;
    if (secret) { body.secret = secret; }
    var submit = form.querySelector('button[type="submit"]');
    submit.disabled = true;
    sendJson('POST', '/api/webhooks', body).then(function (r) {
      if (r.res.ok) { form.reset(); refresh('refreshWebhooks'); return; }
      say(form, errorText(r.res, r.data), 'bad');
    }, function () {
      say(form, 'No answer was received. Check the webhook list before trying again.', 'bad');
    }).then(function () { clearSecrets(form); submit.disabled = false; });
  }

  function deleteTarget(btn, base) {
    if (!window.confirm(btn.getAttribute('data-confirm') || '')) { return; }
    btn.disabled = true;
    sendJson('DELETE', base + encodeURIComponent(btn.getAttribute('data-id')), undefined)
      .then(function (r) {
        if (r.res.ok) { refresh(base.indexOf('webhooks') >= 0 ? 'refreshWebhooks' : 'refreshOffload'); return; }
        btn.disabled = false;
        say(btn, errorText(r.res, r.data), 'bad');
      }, function () {
        btn.disabled = false;
        say(btn, 'No answer was received. Check the list before trying again.', 'bad');
      });
  }

  // ---- offload targets ----

  function createOffload(form) {
    var dest = parseDestination(form.elements['url'].value);
    if (dest.error) { say(form, dest.error, 'bad'); return; }
    var name = form.elements['name'].value.trim();
    if (!name) { say(form, 'Enter a name.', 'bad'); return; }
    if (CONTROL.test(name)) { say(form, 'The name contains control characters.', 'bad'); return; }
    var ev = selectedEvents(form);
    if (!ev) { say(form, 'Choose at least one event, or All events.', 'bad'); return; }
    var batch = parseInt(form.elements['batch_size'].value, 10);
    if (!(batch >= 1 && batch <= 10000)) { say(form, 'Batch size must be 1 to 10000.', 'bad'); return; }
    var text = fill(form.getAttribute('data-confirm') || '',
      { events: ev.labels, host: dest.host, data: ev.classes });
    if (!window.confirm(text)) { return; }
    var body = {
      name: name,
      url: dest.url,
      auth_type: form.elements['auth_type'].value,
      event_types: ev.value,
      batch_size: batch,
      enabled: !!form.elements['enabled'].checked
    };
    var cred = form.elements['auth_credential'].value;
    if (cred) { body.auth_credential = cred; }
    var submit = form.querySelector('button[type="submit"]');
    submit.disabled = true;
    sendJson('POST', '/api/v1/offload-targets', body).then(function (r) {
      if (r.res.ok) { form.reset(); refresh('refreshOffload'); return; }
      say(form, errorText(r.res, r.data), 'bad');
    }, function () {
      say(form, 'No answer was received. Check the target list before trying again.', 'bad');
    }).then(function () { clearSecrets(form); submit.disabled = false; });
  }

  // ---- directory sync ----

  var syncPending = false;

  function syncDirectory(form) {
    if (syncPending) { return; }
    var tenant = form.elements['tenant_id'].value.trim();
    var client = form.elements['client_id'].value.trim();
    var secret = form.elements['client_secret'].value;
    if (!tenant || !client || !secret) { say(form, 'Tenant ID, client ID and client secret are required.', 'bad'); return; }
    if (!/^[A-Za-z0-9.\-]+$/.test(tenant)) { say(form, 'Tenant ID may contain only letters, digits, dots and hyphens.', 'bad'); return; }
    if (!window.confirm(form.getAttribute('data-confirm') || '')) { return; }
    syncPending = true;
    var submit = form.querySelector('button[type="submit"]');
    submit.disabled = true;
    say(form, 'Sync in progress. This can take several minutes.', 'ok');
    sendJson('POST', '/api/directory/sync',
      { provider: 'entra', tenant_id: tenant, client_id: client, client_secret: secret })
      .then(function (r) {
        if (r.res.ok && r.data) {
          say(form, 'Synced ' + Number(r.data.user_count) + ' users and ' +
            Number(r.data.group_count) + ' groups.', 'ok');
          refresh('refreshDirectory');
        } else if (r.res.status === 409) {
          say(form, 'A sync is already running.', 'bad');
        } else {
          say(form, errorText(r.res, r.data), 'bad');
        }
      }, function () {
        // The request is synchronous and long; a dropped connection does not
        // mean the server stopped. Never re-POST: refresh the status instead.
        say(form, 'No answer was received. The sync may still be running on the server. Check Status.', 'bad');
        refresh('refreshDirectory');
      })
      .then(function () {
        clearSecrets(form);
        syncPending = false;
        submit.disabled = false;
      });
  }

  function saveMappings(form) {
    var selects = form.querySelectorAll('select[data-group-id]');
    var changes = [];
    for (var i = 0; i < selects.length; i++) {
      var s = selects[i];
      if (s.value !== s.getAttribute('data-original')) {
        changes.push({ group_id: s.getAttribute('data-group-id'), role_name: s.value });
      }
    }
    if (changes.length === 0) { say(form, 'No changes to save.', 'ok'); return; }
    var text = fill(form.getAttribute('data-confirm') || '', { n: String(changes.length) });
    if (!window.confirm(text)) { return; }
    var submit = form.querySelector('button[type="submit"]');
    submit.disabled = true;
    sendJson('PUT', '/api/directory/group-mappings', { mappings: changes }).then(function (r) {
      if (!r.res.ok) { say(form, errorText(r.res, r.data), 'bad'); return; }
      // The server answers 200 even when a store write was swallowed, so
      // compare the echoed set with what was requested.
      var echoed = {};
      var list = (r.data && Array.isArray(r.data.mappings)) ? r.data.mappings : [];
      for (var j = 0; j < list.length; j++) { echoed[list[j].group_id] = list[j].role_name; }
      var notSaved = [];
      var notRemoved = [];
      for (var k = 0; k < changes.length; k++) {
        var c = changes[k];
        if (c.role_name === '' && Object.prototype.hasOwnProperty.call(echoed, c.group_id)) {
          notRemoved.push(c.group_id);
        } else if (c.role_name !== '' && echoed[c.group_id] !== c.role_name) {
          notSaved.push(c.group_id);
        }
      }
      if (notSaved.length || notRemoved.length) {
        var parts = [];
        if (notSaved.length) { parts.push('Not saved: ' + notSaved.join(', ') + '.'); }
        if (notRemoved.length) { parts.push('Not removed: ' + notRemoved.join(', ') + '.'); }
        say(form, parts.join(' '), 'bad');
        return;
      }
      say(form, 'Saved ' + changes.length + ' mappings. They are recorded for reference and are not applied to sign-in.', 'ok');
      refresh('refreshDirectory');
    }, function () {
      say(form, 'No answer was received. Reload the panel to see what was saved.', 'bad');
    }).then(function () { submit.disabled = false; });
  }

  // ---- dispatch ----

  document.addEventListener('submit', function (ev) {
    var form = ev.target && ev.target.closest ? ev.target.closest('form[data-int-action]') : null;
    if (!form) { return; }
    ev.preventDefault();
    switch (form.getAttribute('data-int-action')) {
      case 'webhook-create': createWebhook(form); break;
      case 'offload-create': createOffload(form); break;
      case 'directory-sync': syncDirectory(form); break;
      case 'directory-mapping': saveMappings(form); break;
      default: break;
    }
  });

  document.addEventListener('click', function (ev) {
    var btn = ev.target && ev.target.closest ? ev.target.closest('button[data-int-action]') : null;
    if (!btn) { return; }
    switch (btn.getAttribute('data-int-action')) {
      case 'webhook-delete': deleteTarget(btn, '/api/webhooks/'); break;
      case 'offload-delete': deleteTarget(btn, '/api/v1/offload-targets/'); break;
      default: break;
    }
  });
})();
