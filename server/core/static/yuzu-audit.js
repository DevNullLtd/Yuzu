/* Audit and reviews page: client glue. Delegated listeners only; nothing inline.
 *
 *  - [data-act="toggle-row"]  opens and closes an audit row's detail (the next row). Real
 *    <button aria-expanded aria-controls>, so it works from the keyboard. State is read and
 *    written on the DOM only; all text arrives from the server already escaped.
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
})();
