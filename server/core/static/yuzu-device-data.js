/* yuzu-device-data.js -- controls of the Hardware record "Tags and properties" lens.
 *
 * ONE delegated click listener on document handles every [data-act] the server renders
 * (device_data_render.cpp, hardware_ui.cpp). Dialogs come from window.YuzuDialog
 * (yuzu-dialog.js, loaded first). Nothing here writes markup: server data is only ever
 * read from attributes and shown through textContent inside the dialog module.
 *
 *   tag-add      Add a tag          POST /api/tags/set
 *   tag-del      Remove a tag       POST /api/tags/delete
 *   prop-add     Add a property     PUT  /api/agents/{id}/properties/{key}
 *   prop-set     Edit a property    PUT  /api/agents/{id}/properties/{key}
 *   prop-delete  Delete a property  DELETE /api/agents/{id}/properties/{key}
 *   schema-save  Save a schema      POST /api/property-schemas (confirms an overwrite)
 *
 * These routes ignore a failed audit write, so no audit-failed banner is shown here.
 */
(function () {
  'use strict';

  var KEY_RE = /^[A-Za-z0-9_.:-]{1,64}$/;
  var KEY_HINT = 'Letters, digits, _ . : - (1 to 64 characters).';
  var SERVER_ERROR = 'The server could not complete the request. Retry shortly.';
  var TYPES = ['string', 'int', 'bool', 'datetime'];

  function enc(s) { return encodeURIComponent(s); }

  function toast(msg, kind) {
    if (typeof window.showToast === 'function') window.showToast(msg, kind);
  }

  // The lens (tags, properties, schemas) is reloaded as a whole, the same call
  // hwReloadCi makes after a tag change (htmx's default swap replaces the target's contents).
  function reload(agent) {
    var mount = document.getElementById('guardian-detail');
    if (mount && window.htmx) {
      window.htmx.ajax('GET', '/fragments/hardware/ci?id=' + enc(agent) + '&lens=tags',
                       { target: '#guardian-detail' });
    } else {
      location.reload();
    }
  }

  // A 4xx carries a message worth showing verbatim; anything else is a fixed sentence.
  function failure(res) {
    if (res.status >= 400 && res.status < 500 && res.message) return res.message;
    return SERVER_ERROR;
  }

  function send(method, url, json) {
    return window.YuzuDialog.request(method, url, json === undefined ? {} : { json: json });
  }

  function done(agent, msg) {
    toast(msg, 'success');
    reload(agent);
  }

  // confirm() cannot nest; a field-less form() with nested:true is the same dialog and
  // may open on top of the form whose submit() is in flight.
  function nestedConfirm(o) {
    o.nested = true;
    o.fields = [];
    return window.YuzuDialog.form(o).then(function (v) { return v !== null; });
  }

  function keyError(key) {
    if (!key) return 'Key is required.';
    if (!KEY_RE.test(key)) return KEY_HINT;
    return null;
  }

  function dlgError(err) {
    toast(err && err.message === 'dialog busy' ? 'Finish the open dialog first.' : SERVER_ERROR, 'error');
  }

  // ---- tags ----

  function tagAdd(btn) {
    var agent = btn.getAttribute('data-agent');
    var hint = btn.getAttribute('data-hint') || '';
    var serviceNote = btn.getAttribute('data-service-set-note') || '';
    return window.YuzuDialog.form({
      title: 'Add tag',
      fields: [
        { name: 'key', label: 'Key', type: 'text', maxlength: 64, required: true, hint: hint },
        { name: 'value', label: 'Value', type: 'text', maxlength: 448 }
      ],
      submitLabel: 'Add tag',
      validate: function (v) { return keyError(v.key.trim()); },
      submit: function (v) {
        var key = v.key.trim();
        var go = function () {
          return send('POST', '/api/tags/set', { agent_id: agent, key: key, value: v.value.trim() })
            .then(function (res) { return res.ok ? null : failure(res); });
        };
        if (key === 'service' && serviceNote) {
          return nestedConfirm({
            title: 'Set the service tag?', body: serviceNote, submitLabel: 'Set service tag'
          }).then(function (ok) { return ok ? go() : 'Not applied.'; });
        }
        return go();
      }
    }).then(function (v) {
      if (v) done(agent, 'Tag ' + v.key.trim() + ' set');
    });
  }

  function tagDelete(btn) {
    var agent = btn.getAttribute('data-agent');
    var key = btn.getAttribute('data-key');
    var body = ['Remove tag ' + key + ' from this device?'];
    var note = btn.getAttribute('data-service-note');
    if (note) body.push(note);
    return window.YuzuDialog.confirm({
      title: 'Remove tag', body: body, confirmLabel: 'Remove tag', danger: true
    }).then(function (ok) {
      if (!ok) return null;
      return send('POST', '/api/tags/delete', { agent_id: agent, key: key }).then(function (res) {
        if (res.ok) done(agent, 'Tag ' + key + ' removed');
        else toast(failure(res), 'error');
      });
    });
  }

  // ---- properties ----

  function propUrl(agent, key) {
    return '/api/agents/' + enc(agent) + '/properties/' + enc(key);
  }

  function propForm(btn, isNew) {
    var agent = btn.getAttribute('data-agent');
    var key0 = isNew ? '' : btn.getAttribute('data-key');
    var schemaType = isNew ? '' : (btn.getAttribute('data-schema-type') || '');
    var fields = [];
    if (isNew) fields.push({ name: 'key', label: 'Key', type: 'text', maxlength: 64, required: true, hint: KEY_HINT });
    fields.push({ name: 'value', label: 'Value', type: 'text', maxlength: 1024,
                  value: isNew ? '' : btn.getAttribute('data-value') });
    if (!schemaType) {
      fields.push({ name: 'type', label: 'Type', type: 'select',
                    options: TYPES.map(function (t) { return { value: t, label: t }; }),
                    value: isNew ? 'string' : (btn.getAttribute('data-type') || 'string') });
    }
    return window.YuzuDialog.form({
      title: isNew ? 'Add property' : 'Edit property ' + key0,
      fields: fields,
      submitLabel: 'Save property',
      validate: function (v) { return isNew ? keyError(v.key.trim()) : null; },
      submit: function (v) {
        var key = isNew ? v.key.trim() : key0;
        var body = { value: v.value };
        body.type = schemaType || v.type || 'string';
        return send('PUT', propUrl(agent, key), body).then(function (res) {
          return res.ok ? null : failure(res);
        });
      }
    }).then(function (v) {
      if (v) done(agent, 'Property ' + (isNew ? v.key.trim() : key0) + ' saved');
    });
  }

  function propDelete(btn) {
    var agent = btn.getAttribute('data-agent');
    var key = btn.getAttribute('data-key');
    return window.YuzuDialog.confirm({
      title: 'Delete property ' + key + '?',
      body: ['Scope expressions that use props.' + key + ' will no longer match this device.'],
      confirmLabel: 'Delete property', danger: true
    }).then(function (ok) {
      if (!ok) return null;
      return send('DELETE', propUrl(agent, key)).then(function (res) {
        if (res.ok) done(agent, 'Property ' + key + ' deleted');
        else toast(failure(res), 'error');
      });
    });
  }

  // ---- schemas ----

  function schemaSave(btn) {
    var agent = (document.getElementById('dd-props') || btn).getAttribute('data-agent') || '';
    var existing = {};
    Array.prototype.forEach.call(document.querySelectorAll('tr[data-schema-key]'), function (tr) {
      existing[tr.getAttribute('data-schema-key')] = true;
    });
    return window.YuzuDialog.form({
      title: 'Save property schema',
      note: 'A schema applies to every device.',
      fields: [
        { name: 'key', label: 'Key', type: 'text', maxlength: 64, required: true, hint: KEY_HINT },
        { name: 'display_name', label: 'Display name', type: 'text', maxlength: 128 },
        { name: 'type', label: 'Type', type: 'select', value: 'string',
          options: TYPES.map(function (t) { return { value: t, label: t }; }) },
        { name: 'description', label: 'Description', type: 'textarea', maxlength: 512 },
        { name: 'validation_regex', label: 'Validation pattern', type: 'text', maxlength: 256 }
      ],
      submitLabel: 'Save schema',
      validate: function (v) { return keyError(v.key.trim()); },
      submit: function (v) {
        var key = v.key.trim();
        var go = function () {
          return send('POST', '/api/property-schemas', {
            key: key, display_name: v.display_name, type: v.type,
            description: v.description, validation_regex: v.validation_regex
          }).then(function (res) { return res.ok ? null : failure(res); });
        };
        if (existing[key]) {
          return nestedConfirm({
            title: 'Replace schema ' + key + '?',
            body: ['A schema named ' + key + ' already exists and will be replaced. ' +
                   'Values already stored are not re-checked.'],
            submitLabel: 'Replace schema', danger: true
          }).then(function (ok) { return ok ? go() : 'Not applied.'; });
        }
        return go();
      }
    }).then(function (v) {
      if (v) done(agent, 'Schema ' + v.key.trim() + ' saved');
    });
  }

  var ACTS = {
    'tag-add': tagAdd,
    'tag-del': tagDelete,
    'prop-add': function (b) { return propForm(b, true); },
    'prop-set': function (b) { return propForm(b, false); },
    'prop-delete': propDelete,
    'schema-save': schemaSave
  };

  document.addEventListener('click', function (ev) {
    var t = ev.target;
    var btn = t && t.closest ? t.closest('[data-act]') : null;
    if (!btn) return;
    var fn = ACTS[btn.getAttribute('data-act')];
    if (!fn || !window.YuzuDialog) return;
    ev.preventDefault();
    var p;
    try { p = fn(btn); } catch (e) { dlgError(e); return; }
    if (p && p.catch) p.catch(dlgError);
  });
})();
