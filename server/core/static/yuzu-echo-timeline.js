/* Echo timeline page (GET /echo/timeline, hidden behind kEchoTimelineUi).
 *
 * The page shell holds the slots; the run fragment draws the lanes; this script moves the
 * moment line and asks the server what the record says at that moment. It never works out
 * state itself: the moment and selected panels are whatever the timeline fragments return.
 *
 * What it reads from the fragments (all emitted by echo_timeline_render.cpp):
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
 * window already shown; it stops on any manual move, a failed panel request, a hidden tab, the
 * window end, or an unbind.
 *
 * Request rate: only a held key (and playback) is throttled. A key moves the line at once, but
 * commits straight away only when the last commit is a second old; inside that second it marks a
 * commit owed and the ONE interval (shared with playback) makes it, with the newest time, once
 * the second is up. A block click, Previous / Next, a scrub release and Play
 * restart commit at once, so the line, the highlight and the panels agree (the newest request
 * wins and aborts the older). A click that changes nothing (the time and item already shown)
 * requests nothing, so a held Enter on a focused button cannot repeat a request; a panel that
 * failed is the exception, and a repeat click asks it again. The interval never commits while
 * the moment request is still in flight (a slow fragment is not answered with an abort per tick)
 * unless that request has gone unanswered for STALE_MS: it is then abandoned and the owed commit
 * made. The interval is cleared when playback is off and nothing is owed.
 * A 401 or a redirect from a panel request means the session ended: one path stops everything
 * and goes to /login once.
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
  var STALE_MS = 10 * THROTTLE_MS; // a moment request unanswered this long no longer holds back the next commit
  var MAX_DT_MS = 1000;    // a stalled timer never makes the line jump
  var MAX_ISO_TS = 253402300799; // 9999-12-31T23:59:59Z

  var tl = {
    speeds: SPEEDS,

    clamp: function (t, from, to) { return Math.min(Math.max(t, from), to); },

    // An epoch-seconds attribute: plain digits only (no hex, exponent, sign or space), else NaN.
    epochAttr: function (s) { return /^\d{1,15}$/.test(s) ? Number(s) : NaN; },

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

    // The renderer's own position formula (plot_left in echo_timeline_render.cpp).
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
    var moment = { el: null, ctl: null, at: 0 };   // at: when the request in ctl started
    var selected = { el: null, ctl: null, at: 0 };
    var st = null;          // the bound run instance, or null
    var speed = 1;
    var playing = false, timer = null, lastTick = 0, lastCommit = -Infinity;
    var pending = false;    // a manual time change whose panel request is owed to the timer
    var scrubbing = false;
    var ended = false;      // the session ended: no more requests from this page

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
        selected.el.removeAttribute('role');
        selected.el.appendChild(selectedIdle);
      }
    }

    function fail(slot, ctl, msg) {
      if (slot.ctl !== ctl) return;
      slot.el.textContent = msg;
      slot.el.setAttribute('role', 'alert'); // only the failure copy is announced, never a routine refresh
      stopPlayback(false);
    }

    // A 401, or a redirect to the landing page, on a panel request: stop everything, sign in once.
    function sessionEnded() {
      if (ended) return;
      ended = true;
      pending = false;
      stopPlayback(false);
      releaseTimer();
      abortSlot(moment);
      abortSlot(selected);
      env.location.assign('/login');
    }

    // The ONE way a panel is refreshed: fetch a page-given relative URL, newest request wins.
    function request(slot, url) {
      if (ended || !slot.el || !url) return;
      if (slot.ctl) slot.ctl.abort();
      var ctl = new env.AbortController();
      slot.ctl = ctl;
      slot.at = env.now();
      slot.el.classList.add('busy');
      // HX-Request makes the server answer a signed-out request with 401, not a redirect to a page.
      env.fetch(url, { credentials: 'same-origin', headers: { Accept: 'text/html', 'HX-Request': 'true' }, signal: ctl.signal })
        .then(function (res) {
          if (res.status === 401 || res.redirected) { sessionEnded(); return null; }
          if (!res.ok) { fail(slot, ctl, 'Could not load this panel (HTTP ' + res.status + ').'); return null; }
          return res.text().then(function (html) {
            if (slot.ctl !== ctl) return;
            slot.el.innerHTML = html;
            slot.el.removeAttribute('role');
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
      if (copyBtn) copyBtn.textContent = copyIdle; // "Link copied" is about a moment the line has left
    }

    function commit(t) {
      if (!st) return;
      setT(t);
      pending = false;
      lastCommit = env.now();
      st.committed = Math.floor(st.t);
      request(moment, tl.momentUrl(run.getAttribute('data-moment-url') || '', st.t));
      if (st.ref) request(selected, tl.selectedUrl(run.getAttribute('data-selected-url') || '', st.ref, st.t));
      releaseTimer();
    }

    // The one interval: playback steps and owed manual commits share it.
    function ensureTimer() {
      if (timer !== null) return;
      timer = env.setInterval(tick, TICK_MS);
    }

    function releaseTimer() {
      if (timer === null || playing || pending) return;
      env.clearInterval(timer);
      timer = null;
    }

    // A key press: playback yields to it and the line moves now. The panels follow at once when
    // the last commit is a second old; otherwise the commit is owed and the timer makes it with
    // the newest time (a held key repeats far faster than a second). This is the only throttled
    // manual path: a click is one deliberate choice and goes through choose().
    function keyCommit(t) {
      stopPlayback(false);
      if (tl.throttleDue(lastCommit, env.now())) { commit(t); return; }
      setT(t);
      pending = true;
      ensureTimer();
    }

    // flush: commit the exact stop time once (outside the throttle) so the panels agree with the line.
    function stopPlayback(flush) {
      if (!playing) return;
      playing = false;
      playBtn.setAttribute('aria-pressed', 'false');
      playBtn.textContent = 'Play';
      if (st) {
        setT(Math.floor(st.t));
        if (flush && st.committed !== st.t) commit(st.t);
      }
      releaseTimer();
    }

    function tick() {
      if (!st) return;
      var n = env.now(), dt = n - lastTick;
      lastTick = n;
      if (playing) {
        var r = tl.nextPlayhead(st.t, speed, dt, st.from, st.to);
        setT(r.t);
        if (r.done) { stopPlayback(true); return; }
      }
      // A key that came back to the committed time owes nothing.
      if (pending && Math.floor(st.t) === st.committed) pending = false;
      // Commit when owed, a second after the last one, and once the previous answer is in; an
      // answer missing for STALE_MS is given up on (commit aborts it), so a hung request cannot
      // freeze the panels while the line moves on.
      var owed = pending || (playing && Math.floor(st.t) !== st.committed);
      var waiting = moment.ctl !== null && n - moment.at < STALE_MS;
      if (owed && !scrubbing && !waiting && tl.throttleDue(lastCommit, n)) commit(st.t);
      releaseTimer();
    }

    function startPlayback() {
      if (!st || playing || scrubbing || !tl.playbackAllowed(st.from, st.to)) return;
      if (st.t >= st.to) commit(st.from); // at the end: start over from the window start
      playing = true;
      lastTick = env.now();
      ensureTimer();
      playBtn.setAttribute('aria-pressed', 'true');
      playBtn.textContent = 'Pause';
    }

    function unbind() {
      pending = false;
      stopPlayback(false);
      releaseTimer();
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
      var from = body ? tl.epochAttr(body.getAttribute('data-from')) : NaN;
      var to = body ? tl.epochAttr(body.getAttribute('data-to')) : NaN;
      var t0 = ph ? tl.epochAttr(ph.getAttribute('data-ts')) : NaN;
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
      body.setAttribute('role', 'group');
      body.setAttribute('aria-label', 'Timeline. Arrow, Page, Home and End keys move the moment.');
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
      // A refused capture (the pointer is already gone) means no scrub: never a stuck one.
      try { st.body.setPointerCapture(e.pointerId); } catch (x) { return; }
      stopPlayback(false);
      scrubbing = true;
      st.root.classList.add('scrubbing');
      setT(t);
    }

    function endScrub(release) {
      if (!scrubbing || !st) return;
      scrubbing = false;
      st.root.classList.remove('scrubbing');
      if (release) commit(st.t); else setT(st.committed); // a cancelled drag goes back, it commits nothing
    }

    function onPointerMove(e) {
      if (!scrubbing || !st) return;
      // Every button is up: the release happened where no pointerup reaches us.
      if (typeof e.buttons === 'number' && e.buttons === 0) { endScrub(true); return; }
      var t = pointerTs(e);
      setT(t === null ? st.from : t);
    }

    function onPointerEnd() { endScrub(true); }
    function onPointerCancel() { endScrub(false); }

    // Only a plain left click is ours; a modified or middle click keeps the browser's own meaning of a link.
    function plainClick(e) { return e.button === 0 && !e.ctrlKey && !e.metaKey && !e.shiftKey && !e.altKey; }

    // A panel that answered with a failure and has no request out: asking again is how it recovers.
    function failedIdle(slot) {
      return !slot.ctl && slot.el !== null && slot.el.getAttribute('role') === 'alert';
    }

    // One deliberate choice (a block, Previous / Next): the line, the highlight and both panels
    // move together, now. A choice that changes nothing asks for nothing (a held Enter repeats the
    // click), unless a panel failed and is idle: a repeat click retries it.
    function choose(ts, ref) {
      stopPlayback(false);
      var same = ref === st.ref && Math.floor(ts) === st.committed && !failedIdle(moment) && !failedIdle(selected);
      if (ref !== st.ref) {
        st.ref = ref;
        markOn(ref);
        if (ref === null) clearSelection();
      }
      if (same) setT(ts); else commit(ts);
    }

    function onClick(e) {
      if (!st) return;
      var b = e.target.closest('button[data-ts]');
      if (!b) return;
      var ts = tl.epochAttr(b.getAttribute('data-ts'));
      if (isNaN(ts)) return;
      choose(ts, b.getAttribute('data-ref') || null);
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
      // The browser drops the capture when the pointer goes away or the body leaves the document,
      // even if pointerup never arrives; after a normal pointerup this is a no-op.
      run.addEventListener('lostpointercapture', onPointerEnd);
      run.addEventListener('pointercancel', onPointerCancel);
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
        // Already there (a held key at the window edge): nothing to request, but a key is still a
        // manual move and playback yields to it.
        if (n === st.t) { stopPlayback(false); return; }
        keyCommit(n);
      });
      if (moment.el) moment.el.addEventListener('click', function (e) {
        var a = e.target.closest('a[data-ts]');
        if (!a || !st || !plainClick(e)) return;
        var ts = tl.epochAttr(a.getAttribute('data-ts'));
        if (isNaN(ts)) return;
        e.preventDefault();
        choose(ts, st.ref);
      });
      if (selected.el) selected.el.addEventListener('click', function (e) {
        var a = e.target.closest('a[data-ref]');
        if (!a || !st || !plainClick(e)) return;
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
      // A refused answer, a request that never reached the server, or one that timed out.
      ['htmx:responseError', 'htmx:sendError', 'htmx:timeout'].forEach(function (name) {
        doc.body.addEventListener(name, function (e) {
          if (!e.target || !e.target.closest || !e.target.closest('#tl-run')) return;
          var status = e.detail && e.detail.xhr ? e.detail.xhr.status : 0;
          unbind();
          run.textContent = status ? 'Could not load the record (HTTP ' + status + ').' : 'Could not reach the server.';
        });
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
    now: function () { return window.performance.now(); }, // monotonic: a clock step never silences playback
    setInterval: window.setInterval.bind(window),
    clearInterval: window.clearInterval.bind(window)
  }).start();
})();
