/* TAR timeline page (GET /tar/timeline, hidden behind kTarTimelineUi).
 *
 * The page shell holds the slots; the run fragment draws the lanes; this script moves the
 * moment line and asks the server what the record says at that moment. It never works out
 * state itself: the moment and selected panels are whatever the timeline fragments return.
 *
 * What it reads from the fragments (all emitted by tar_timeline_render.cpp):
 *   .tl-body[data-from][data-to]   the window, in epoch seconds
 *   .tl-ph[data-ts]                the resolved moment; present only for a valid window
 *   button[data-ts][data-ref]      a block or marker: its time and (optionally) its item id
 *   #tl-moment a[data-ts]          Previous / Next event
 *   #tl-selected a[data-ref]       linked items of the selected item
 * It reads these from the page shell (#tl-run): data-moment-url, data-selected-url.
 *
 * Every committed time change (pointer release, key, range change, nav link, block click,
 * playback step) goes through commit(): it requests the moment panel and, when an item is
 * selected, the selected panel at the same time. Playback only advances the line through the
 * window already shown; it is throttled to one commit a second and stops on any manual move,
 * a failed panel request, a hidden tab, the window end, or an unbind.
 *
 * Pure helpers are exported (module.exports) for the node test; the DOM shell takes its
 * environment (document, fetch, clock, timers) as a parameter so the test never sleeps.
 */
(function () {
  'use strict';

  var DAY_S = 86400;
  var SPEEDS = [1, 10, 60];
  var TICK_MS = 250;       // playback timer period
  var THROTTLE_MS = 1000;  // at most one playback commit a second
  var MAX_DT_MS = 1000;    // a stalled timer never makes the line jump
  var MAX_ISO_TS = 253402300799; // 9999-12-31T23:59:59Z

  var tl = {
    speeds: SPEEDS,

    clamp: function (t, from, to) { return Math.min(Math.max(t, from), to); },

    validWindow: function (from, to) {
      return Number.isSafeInteger(from) && Number.isSafeInteger(to) && from > 0 && to > from;
    },

    step: function (from, to) { return Math.max(1, Math.round((to - from) / 200)); },
    page: function (from, to) { return Math.max(1, Math.round((to - from) / 10)); },

    // The new moment for a key, clamped to the window, or null when the key is not ours.
    keyStep: function (key, t, from, to) {
      var s = tl.step(from, to), p = tl.page(from, to), n;
      switch (key) {
        case 'ArrowLeft': case 'ArrowDown': n = t - s; break;
        case 'ArrowRight': case 'ArrowUp': n = t + s; break;
        case 'PageDown': n = t - p; break;
        case 'PageUp': n = t + p; break;
        case 'Home': n = from; break;
        case 'End': n = to; break;
        default: return null;
      }
      return tl.clamp(n, from, to);
    },

    frac: function (t, from, to) { return (tl.clamp(t, from, to) - from) / (to - from); },

    // The renderer's own position formula (plot_left in tar_timeline_render.cpp).
    playheadLeft: function (f, plus) {
      return 'calc(var(--gut) + (100% - var(--gut)) * ' + f.toFixed(5) + (plus || '') + ')';
    },

    // The renderer's chip edge thresholds: near the end the chip hangs left, near the start right.
    edgeClass: function (f) { return f > 0.9 ? 'e' : (f < 0.05 ? 's' : ''); },

    // Epoch seconds under a pointer, or null inside the label gutter / on a degenerate plot.
    tsAtPointer: function (px, rectLeft, rectWidth, gutterPx, from, to) {
      var x = px - rectLeft;
      if (!(rectWidth > gutterPx) || x < gutterPx) return null;
      var f = Math.min(1, Math.max(0, (x - gutterPx) / (rectWidth - gutterPx)));
      return tl.clamp(Math.round(from + f * (to - from)), from, to);
    },

    isoUtc: function (t) {
      if (!(t > 0) || t > MAX_ISO_TS) return '—';
      return new Date(Math.floor(t) * 1000).toISOString().replace(/\.\d{3}Z$/, 'Z');
    },

    // The page-given bases always carry `?id=`, so these only append.
    momentUrl: function (base, t) { return base + '&at=' + Math.floor(t); },
    selectedUrl: function (base, ref, t) { return base + '&ref=' + encodeURIComponent(ref) + '&at=' + Math.floor(t); },

    // Root-relative link to this page at moment t; only `id` is kept from the current query.
    pageLink: function (pathname, search, t) {
      var id = new URLSearchParams(search).get('id'), q = new URLSearchParams();
      if (id !== null) q.set('id', id);
      if (typeof t === 'number' && isFinite(t)) q.set('at', String(Math.floor(t)));
      return pathname + '?' + q.toString();
    },

    // Playback: the design ignores Play on a window of a day or more.
    playbackAllowed: function (from, to) { return tl.validWindow(from, to) && to - from < DAY_S; },
    nextSpeed: function (s) {
      var i = SPEEDS.indexOf(s);
      return SPEEDS[(i + 1) % SPEEDS.length];
    },
    // One playback step: speed x elapsed wall seconds, clamped to the window; done at its end.
    nextPlayhead: function (t, speed, dtMs, from, to) {
      var dt = Math.min(Math.max(dtMs, 0), MAX_DT_MS);
      var n = tl.clamp(t + speed * dt / 1000, from, to);
      return { t: n, done: n >= to };
    },
    throttleDue: function (lastCommitMs, nowMs) { return nowMs - lastCommitMs >= THROTTLE_MS; }
  };

  // The DOM shell. env = { document, fetch, AbortController, location, navigator, now,
  // setInterval, clearInterval }.
  tl.shell = function (env) {
    var doc = env.document;
    var run, clockEl, playBtn, speedBtn, noteEl, copyBtn;
    var copyIdle = '';      // the copy button's own label, restored when the moment moves
    var selectedIdle = null; // the Selected panel's own prompt node, restored when nothing is selected
    var moment = { el: null, ctl: null };
    var selected = { el: null, ctl: null };
    var st = null;          // the bound run instance, or null
    var speed = 1;
    var playing = false, timer = null, lastTick = 0, lastCommit = -Infinity;
    var scrubbing = false;

    function abortSlot(slot) {
      if (slot.ctl) {
        slot.ctl.abort();
        slot.ctl = null;
      }
      if (slot.el) slot.el.classList.remove('busy');
    }

    // No item selected: stop any selected request and put the server's own prompt back.
    function clearSelection() {
      abortSlot(selected);
      if (selected.el && selectedIdle) {
        selected.el.textContent = '';
        selected.el.appendChild(selectedIdle);
      }
    }

    function fail(slot, ctl, msg) {
      if (slot.ctl !== ctl) return;
      slot.el.textContent = msg;
      stopPlayback(false);
    }

    // The ONE way a panel is refreshed: fetch a page-given relative URL, newest request wins.
    function request(slot, url) {
      if (!slot.el || !url) return;
      if (slot.ctl) slot.ctl.abort();
      var ctl = new env.AbortController();
      slot.ctl = ctl;
      slot.el.classList.add('busy');
      env.fetch(url, { credentials: 'same-origin', headers: { Accept: 'text/html' }, signal: ctl.signal })
        .then(function (res) {
          // Stop first: no flush (it would request again, and 401 again) and no timer left firing.
          if (res.status === 401) { stopPlayback(false); env.location.assign('/login'); return null; }
          if (!res.ok) { fail(slot, ctl, 'Could not load this panel (HTTP ' + res.status + ').'); return null; }
          return res.text().then(function (html) {
            if (slot.ctl === ctl) slot.el.innerHTML = html;
          });
        })
        .catch(function () {
          if (!ctl.signal.aborted) fail(slot, ctl, 'Could not reach the server.');
        })
        .then(function () {
          if (slot.ctl === ctl) {
            slot.ctl = null;
            slot.el.classList.remove('busy');
          }
        });
    }

    function setPlayAvailability(allowed, note) {
      if (playBtn) playBtn.disabled = !allowed;
      if (speedBtn) speedBtn.disabled = !allowed;
      if (noteEl) noteEl.textContent = note;
    }

    function setT(t) {
      if (!st) return;
      var v = tl.clamp(t, st.from, st.to), f = tl.frac(v, st.from, st.to), iso = tl.isoUtc(v);
      st.t = v;
      st.ph.style.left = tl.playheadLeft(f);
      if (st.fut) st.fut.style.left = tl.playheadLeft(f, ' + 1px');
      if (st.chip) {
        st.chip.textContent = iso;
        st.chip.className = tl.edgeClass(f);
      }
      st.range.value = String(Math.floor(v));
      st.range.setAttribute('aria-valuetext', iso);
      if (clockEl) clockEl.textContent = iso;
    }

    function commit(t) {
      if (!st) return;
      setT(t);
      lastCommit = env.now();
      st.committed = Math.floor(st.t);
      if (copyBtn) copyBtn.textContent = copyIdle; // "Link copied" is about the moment that has just moved on
      request(moment, tl.momentUrl(run.getAttribute('data-moment-url') || '', st.t));
      if (st.ref) request(selected, tl.selectedUrl(run.getAttribute('data-selected-url') || '', st.ref, st.t));
    }

    // A time change the operator made: playback yields to it.
    function manualCommit(t) {
      stopPlayback(false);
      commit(t);
    }

    // flush: commit the exact stop time once (outside the throttle) so the panels agree with the line.
    function stopPlayback(flush) {
      if (!playing) return;
      playing = false;
      env.clearInterval(timer);
      timer = null;
      playBtn.setAttribute('aria-pressed', 'false');
      playBtn.textContent = 'Play';
      if (!st) return;
      setT(Math.floor(st.t));
      if (flush && st.committed !== st.t) commit(st.t);
    }

    function tick() {
      if (!st) return;
      var n = env.now(), dt = n - lastTick;
      lastTick = n;
      var r = tl.nextPlayhead(st.t, speed, dt, st.from, st.to);
      setT(r.t);
      if (r.done) { stopPlayback(true); return; }
      if (tl.throttleDue(lastCommit, n)) commit(r.t);
    }

    function startPlayback() {
      if (!st || playing || !tl.playbackAllowed(st.from, st.to)) return;
      if (st.t >= st.to) commit(st.from); // at the end: start over from the window start
      playing = true;
      lastTick = env.now();
      timer = env.setInterval(tick, TICK_MS);
      playBtn.setAttribute('aria-pressed', 'true');
      playBtn.textContent = 'Pause';
    }

    function unbind() {
      stopPlayback(false);
      abortSlot(moment);
      clearSelection();
      st = null;
      scrubbing = false;
      setPlayAvailability(false, '');
    }

    function markOn(ref) {
      st.root.querySelectorAll('button[data-ref]').forEach(function (b) {
        b.classList.toggle('on', ref !== null && b.getAttribute('data-ref') === ref);
      });
    }

    // Binds a run instance once. Anything else (an unrelated or repeated settle) is a no-op.
    function bind() {
      if (!run) return;
      var root = run.querySelector('.tl');
      if (!root) { if (st) unbind(); return; } // the instance was replaced by markup with no timeline
      if (root.getAttribute('data-tl-bound')) return;
      unbind();
      root.setAttribute('data-tl-bound', '1');
      var body = root.querySelector('.tl-body'), ph = root.querySelector('.tl-ph');
      var from = body ? Number(body.getAttribute('data-from')) : NaN;
      var to = body ? Number(body.getAttribute('data-to')) : NaN;
      var t0 = ph ? Number(ph.getAttribute('data-ts')) : NaN;
      if (!ph || !tl.validWindow(from, to) || !isFinite(t0)) {
        // The server's own banner says the window is not valid: no controls, no requests.
        setPlayAvailability(false, 'Play is not available: this window is not valid.');
        return;
      }
      var range = doc.createElement('input');
      range.setAttribute('type', 'range');
      range.setAttribute('class', 'tl-scrub');
      range.setAttribute('min', String(from));
      range.setAttribute('max', String(to));
      range.setAttribute('step', '1');
      range.setAttribute('aria-label', 'Time, in seconds');
      var head = root.querySelector('.tl-head');
      if (head) head.after(range); else root.appendChild(range);
      body.setAttribute('tabindex', '0');
      st = {
        root: root, body: body, ph: ph, range: range, from: from, to: to, t: t0, ref: null,
        chip: ph.querySelector('b'), fut: root.querySelector('.tl-fut'), committed: null
      };
      var ok = tl.playbackAllowed(from, to);
      setPlayAvailability(ok, ok ? '' : 'Play is not available for a window of a day or more.');
      commit(t0);
    }

    function pointerTs(e) {
      var g = st.root.querySelector('.tl-head .g');
      if (!g) return null;
      var r = st.body.getBoundingClientRect();
      return tl.tsAtPointer(e.clientX, r.left, r.width, g.getBoundingClientRect().width, st.from, st.to);
    }

    function onPointerDown(e) {
      if (!st || e.button > 0) return;
      if (!e.target.closest('.tl-body') || e.target.closest('button[data-ts]')) return;
      var t = pointerTs(e);
      if (t === null) return;
      stopPlayback(false);
      scrubbing = true;
      st.root.classList.add('scrubbing');
      if (st.body.setPointerCapture) st.body.setPointerCapture(e.pointerId);
      setT(t);
    }

    function onPointerMove(e) {
      if (!scrubbing || !st) return;
      var t = pointerTs(e);
      setT(t === null ? st.from : t);
    }

    function onPointerEnd() {
      if (!scrubbing || !st) return;
      scrubbing = false;
      st.root.classList.remove('scrubbing');
      commit(st.t);
    }

    function onClick(e) {
      if (!st) return;
      var b = e.target.closest('button[data-ts]');
      if (!b) return;
      var ts = Number(b.getAttribute('data-ts'));
      if (!isFinite(ts)) return;
      st.ref = b.getAttribute('data-ref') || null;
      markOn(st.ref);
      if (st.ref === null) clearSelection();
      manualCommit(ts);
    }

    function onCopy() {
      var link = env.location.origin + tl.pageLink(env.location.pathname, env.location.search, st ? st.t : null);
      function say(text) { copyBtn.textContent = text; }
      if (!env.navigator || !env.navigator.clipboard) { say('Could not copy'); return; }
      env.navigator.clipboard.writeText(link).then(function () { say('Link copied'); },
                                                   function () { say('Could not copy'); });
    }

    function setup() {
      run = doc.getElementById('tl-run');
      if (!run) return;
      moment.el = doc.getElementById('tl-moment');
      selected.el = doc.getElementById('tl-selected');
      selectedIdle = selected.el ? selected.el.children[0] || null : null;
      clockEl = doc.getElementById('tl-clock');
      playBtn = doc.getElementById('tl-play');
      speedBtn = doc.getElementById('tl-speed');
      noteEl = doc.getElementById('tl-play-note');
      copyBtn = doc.getElementById('tl-copy');
      copyIdle = copyBtn ? copyBtn.textContent : '';

      run.addEventListener('pointerdown', onPointerDown);
      run.addEventListener('pointermove', onPointerMove);
      run.addEventListener('pointerup', onPointerEnd);
      run.addEventListener('pointercancel', onPointerEnd);
      run.addEventListener('click', onClick);
      run.addEventListener('input', function (e) {
        if (!st || e.target !== st.range) return;
        stopPlayback(false);
        setT(Number(e.target.value));
      });
      run.addEventListener('change', function (e) {
        if (st && e.target === st.range) commit(st.t);
      });
      run.addEventListener('keydown', function (e) {
        if (!st || e.altKey || e.ctrlKey || e.metaKey || !e.target.closest('.tl')) return;
        var n = tl.keyStep(e.key, st.t, st.from, st.to);
        if (n === null) return;
        e.preventDefault();
        manualCommit(n);
      });
      if (moment.el) moment.el.addEventListener('click', function (e) {
        var a = e.target.closest('a[data-ts]');
        if (!a || !st) return;
        var ts = Number(a.getAttribute('data-ts'));
        if (!isFinite(ts)) return;
        e.preventDefault();
        manualCommit(ts);
      });
      if (selected.el) selected.el.addEventListener('click', function (e) {
        var a = e.target.closest('a[data-ref]');
        if (!a || !st) return;
        e.preventDefault();
        st.ref = a.getAttribute('data-ref');
        markOn(st.ref);
        stopPlayback(true); // a selection change is a manual action: the line stops, the panels catch up
        request(selected, tl.selectedUrl(run.getAttribute('data-selected-url') || '', st.ref, st.t));
      });
      if (copyBtn) copyBtn.addEventListener('click', onCopy);
      if (playBtn) playBtn.addEventListener('click', function () {
        if (playing) stopPlayback(true); else startPlayback();
      });
      if (speedBtn) speedBtn.addEventListener('click', function () {
        speed = tl.nextSpeed(speed);
        speedBtn.textContent = 'Speed ' + speed + 'x';
      });

      doc.addEventListener('visibilitychange', function () {
        if (doc.hidden) stopPlayback(true);
      });
      doc.body.addEventListener('htmx:afterSettle', bind);
      // The run slot, or the self-replacing poll inside it (its target is its own element).
      doc.body.addEventListener('htmx:responseError', function (e) {
        if (!e.target || !e.target.closest || !e.target.closest('#tl-run')) return;
        var status = e.detail && e.detail.xhr ? e.detail.xhr.status : 0;
        unbind();
        run.textContent = 'Could not load the record (HTTP ' + status + ').';
      });
      bind();
    }

    return {
      bind: bind,
      start: function () {
        if (doc.readyState === 'loading') doc.addEventListener('DOMContentLoaded', setup);
        else setup();
      }
    };
  };

  if (typeof module !== 'undefined' && module.exports) module.exports = tl;
  if (typeof document === 'undefined') return;

  // fetch and the timers throw on a detached `this`, so they are bound to window.
  tl.shell({
    document: document,
    fetch: window.fetch.bind(window),
    AbortController: window.AbortController,
    location: window.location,
    navigator: window.navigator,
    now: Date.now,
    setInterval: window.setInterval.bind(window),
    clearInterval: window.clearInterval.bind(window)
  }).start();
})();
