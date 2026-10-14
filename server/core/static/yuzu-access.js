/* Access pages: client glue (Phase 2). Delegated listeners only; nothing inline.
 *
 *  - [data-act="reload"][data-target=<id>]  re-fetches the panel's data-src into itself.
 *  - htmx:responseError / htmx:sendError on any [data-denied] panel: the gate's 401/403 and
 *    any other non-2xx become an in-panel note (text from the panel's own data attributes, so
 *    the sentences live in one place, in C++). All text goes in with textContent.
 */
(function () {
  'use strict';

  function el(tag, cls, text) {
    var n = document.createElement(tag);
    if (cls) n.className = cls;
    if (text !== undefined) n.textContent = text;
    return n;
  }

  function denied(target) {
    var box = el('div', 'empty');
    box.appendChild(el('b', null, 'Not available to your account'));
    box.appendChild(el('span', null, target.dataset.denied || ''));
    target.replaceChildren(box);
  }

  function unavailable(target) {
    var box = el('div', 'failbox');
    box.setAttribute('role', 'alert');
    var msg = el('div');
    msg.appendChild(el('b', null, 'This panel could not be loaded.'));
    msg.appendChild(document.createElement('br'));
    msg.appendChild(el('span', 'guard', target.dataset.unavailable || ''));
    var end = el('div', 'end');
    var btn = el('button', 'btn sm', 'Retry');
    btn.type = 'button';
    btn.dataset.act = 'reload';
    btn.dataset.target = target.id;
    end.appendChild(btn);
    box.appendChild(msg);
    box.appendChild(end);
    target.replaceChildren(box);
  }

  document.addEventListener('click', function (e) {
    var b = e.target.closest('[data-act="reload"]');
    if (!b) return;
    var t = document.getElementById(b.dataset.target);
    if (t && t.dataset.src) htmx.ajax('GET', t.dataset.src, { target: '#' + t.id, swap: 'innerHTML' });
  });

  document.body.addEventListener('htmx:responseError', function (e) {
    var t = e.detail.target;
    if (!t || !t.hasAttribute('data-denied')) return;
    var s = e.detail.xhr.status;
    if (s === 401) { location.assign('/login'); return; }
    if (s === 403) denied(t); else unavailable(t);
  });

  document.body.addEventListener('htmx:sendError', function (e) {
    var t = e.detail.target;
    if (t && t.hasAttribute('data-denied')) unavailable(t);
  });
})();
