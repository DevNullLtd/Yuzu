/* yuzu-developer.js -- the System > Developer and API Load generator controller.
 *
 * Loaded after yuzu-dialog.js and yuzu-system.js. Start and Stop are the only dispatch on any
 * System page, and both go through the existing POST /api/command, which feeds the single
 * dispatch_confined chokepoint (and shows its approval gate and permission text verbatim; this
 * page never offers a way around either). No new route and no new seam.
 *
 * The (plugin, action) pairs are a fixed table keyed by button id. They are never read from the
 * DOM, the URL or a response, and the request body is exactly {plugin, action}: no params,
 * agent_ids, scope, stagger or delay, so a run always means "every device the caller can see" and
 * the generator's rate is the plugin's own default. The response's table-header markup is never read;
 * only counts are shown. The page opens no event stream.
 */
(function () {
  'use strict';

  var D = window.YuzuDialog, S = window.YuzuSystem;
  if (!D || !S) return;

  var TABLE = {
    'dev-chargen-start': { plugin: 'chargen', action: 'chargen_start', confirm: true },
    'dev-chargen-stop': { plugin: 'chargen', action: 'chargen_stop', confirm: false }
  };

  var START_BODY = [
    'Every connected device you can see will start streaming test text to the server, about 10 lines a second each, until you stop it.',
    'This adds network and database load across the fleet, and every open Dashboard will receive the rows.',
    'A device that is already running restarts its session.'
  ];

  var busy = false;

  function $(id) { return document.getElementById(id); }

  function setButtons(disabled, reason) {
    Object.keys(TABLE).forEach(function (id) {
      var b = $(id);
      if (!b) return;
      b.disabled = disabled;
      if (reason) b.setAttribute('title', reason); else b.removeAttribute('title');
    });
  }

  function say(text, cls) {
    var r = $('dev-result');
    if (!r) return;
    r.textContent = text;
    r.className = 'hint' + (cls ? ' ' + cls : '');
  }

  /** "Sent to N devices at HH:MM." plus only the withheld counts that are not zero. Sent never
   *  means running or stopped. */
  function sentLine(d, now) {
    var n = Number.isInteger(d.agents_reached) ? d.agents_reached : 0;
    var hh = ('0' + now.getHours()).slice(-2), mm = ('0' + now.getMinutes()).slice(-2);
    var t = 'Sent to ' + n + (n === 1 ? ' device' : ' devices') + ' at ' + hh + ':' + mm + '.';
    [['withheld_quarantined', 'quarantined'], ['withheld_unknown_plugin', 'plugin not found'],
     ['withheld_kill_switched_os', 'OS switched off']].forEach(function (p) {
      if (Number.isInteger(d[p[0]]) && d[p[0]] > 0) t += ' ' + d[p[0]] + ' withheld (' + p[1] + ').';
    });
    return t;
  }

  // ---- devices online (the shell's own count: connected to this server, unauthenticated read) ----

  function readOnline() {
    var out = $('dev-online');
    var opts = { credentials: 'omit', cache: 'no-store' };
    try { opts.signal = AbortSignal.timeout(5000); } catch (e) { /* no timeout available */ }
    return fetch('/api/health', opts).then(function (r) { return r.ok ? r.json() : null; }).then(function (d) {
      var n = d && d.agents ? d.agents.online : null;
      if (!Number.isInteger(n)) throw new Error('unreadable');
      if (out) out.textContent = n + ' (connected to this server)';
      setButtons(n === 0, n === 0 ? 'No device is connected.' : '');
    }).catch(function () {
      // An unreadable count must not block the action: the server answers with its own reason.
      if (out) out.textContent = 'Unknown';
      setButtons(false, '');
    });
  }

  // ---- the request ----

  function request(spec) {
    return S.send('POST', '/api/command', { json: { plugin: spec.plugin, action: spec.action } });
  }

  function finish(res) {
    busy = false;
    if (res.ok) {
      var line = sentLine(res.data || {}, new Date());
      if (res.auditFailed) say(line + ' The action was sent but its audit record could not be written.', 'dev-err');
      else say(line);
    } else {
      say(S.failText(res), 'dev-err');
    }
    return readOnline();
  }

  function run(id) {
    var spec = TABLE[id];
    if (busy) return;
    busy = true;
    setButtons(true, 'Waiting for the server.');
    if (!spec.confirm) {
      say('Sending...');
      return request(spec).then(finish);
    }
    D.form({
      title: 'Start the load generator on every device?', body: START_BODY, danger: true,
      submitLabel: 'Start on all devices',
      submit: function () {
        return request(spec).then(function (res) {
          if (res.ok) { finish(res); return null; }
          // Failed: the dialog shows the server's own text and stays open; the buttons free up.
          busy = false;
          return S.failText(res);
        });
      }
    }).then(function (v) {
      if (v === null) { busy = false; return readOnline(); }
    }, function () { busy = false; return readOnline(); });
  }

  document.addEventListener('click', function (e) {
    var btn = e.target && e.target.closest ? e.target.closest('button') : null;
    if (!btn || btn.disabled || !Object.prototype.hasOwnProperty.call(TABLE, btn.id)) return;
    run(btn.id);
  });

  readOnline();
})();
