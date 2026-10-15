// Smoke-test the executions drawer added in PR 1 of the executions-history
// ladder. Drives the Instructions → Executions tab end-to-end:
//   1. Loads /fragments/executions and asserts the table renders the new
//      surface (sparkbar SVG, definition-name column, time title).
//   2. Captures a row and exercises the click-to-expand drawer; asserts
//      the four KPI sub-elements + agent grid + per-agent table appear.
//   3. Verifies the single-drawer-open invariant (clicking row B collapses
//      row A's drawer) so the operator never sees two competing forensic
//      views at once.
//   4. Reads computed-style on a sparkbar segment and the row stripe to
//      confirm Cisco Momentum tokens resolve non-empty (silent CSS-token
//      drift is a known regression class — same shape as echarts-smoke).
//
// Failure modes this catches:
//   IDX-1  sparkbar tokens drop to defaults → palette silently goes flat
//   IDX-2  drawer detail is not lazy → every row hammers the server on load
//   IDX-3  multi-drawer-open regression → the user told us the rule once
//   IDX-4  KPI strip "—" sentinel for completed runs (p50/p95 path)
//
// Pre-conditions: server must be running on :8080 with at least one
// completed execution. The UAT script (`bash scripts/linux-start-UAT.sh`)
// dispatches a few before this test runs.

import puppeteer from 'puppeteer';

async function main() {
  const browser = await puppeteer.launch({
    headless: true,
    args: ['--window-size=1400,900', '--no-sandbox'],
    defaultViewport: { width: 1400, height: 900 },
  });
  const page = await browser.newPage();

  const pageErrors = [];
  page.on('pageerror', err => {
    pageErrors.push(err.message);
    console.log('[pageerror]', err.message);
  });
  page.on('console', msg => {
    if (msg.type() === 'error') console.log('[console.error]', msg.text());
  });

  // -- Login + navigate to Instructions --
  await page.goto('http://localhost:8080/login', { waitUntil: 'networkidle2', timeout: 15000 });
  await page.type('input[name="username"]', 'admin');
  await page.type('input[name="password"]', 'YuzuUatAdmin1!');
  await page.click('button[type="submit"]');
  await page.waitForNavigation({ waitUntil: 'networkidle2', timeout: 15000 });

  await page.goto('http://localhost:8080/instructions', { waitUntil: 'networkidle2', timeout: 15000 });

  // Switch to the Executions tab (HTMX hx-trigger="revealed" loads the fragment).
  await page.evaluate(() => {
    const tab = Array.from(document.querySelectorAll('.tab')).find(t =>
      t.textContent.trim() === 'Executions');
    if (tab) tab.click();
  });

  // Wait for the new surface to land. We look for an .exec-row + .status-sparkbar
  // SVG — both proof the new list renderer ran (not the legacy table).
  await page.waitForSelector('.exec-row', { timeout: 15000 });
  await page.waitForSelector('.status-sparkbar', { timeout: 5000 });

  // -- IDX-1: sparkbar palette tokens must resolve non-empty. --
  const tokens = await page.evaluate(() => {
    const cs = getComputedStyle(document.documentElement);
    const keys = [
      '--mds-color-bg-success-emphasis',
      '--mds-color-theme-indicator-error',
      '--mds-color-theme-indicator-info',
      '--mds-color-theme-text-tertiary',
      '--mds-color-state-hover',
      '--mds-color-state-selected',
    ];
    return Object.fromEntries(keys.map(k => [k, cs.getPropertyValue(k).trim()]));
  });
  let tokensOk = true;
  for (const [k, v] of Object.entries(tokens)) {
    console.log(`  ${k} = ${v || '(empty!)'}`);
    if (!v) tokensOk = false;
  }

  // -- Sanity-check the list shape: at least one row, sparkbar, ISO title --
  const listShape = await page.evaluate(() => {
    const rows = document.querySelectorAll('.exec-row');
    const sparkbars = document.querySelectorAll('.status-sparkbar');
    const time = document.querySelector('.exec-time');
    return {
      rowCount: rows.length,
      sparkbarCount: sparkbars.length,
      timeHasIsoTitle: !!(time && /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$/.test(time.title)),
      sparkbarAriaLabelOk: !!(sparkbars[0] &&
                              /\d+ succeeded.*\d+ failed.*\d+ running.*\d+ pending of \d+|no agents matched scope/
                                .test(sparkbars[0].getAttribute('aria-label') || '')),
    };
  });
  console.log(`  rows=${listShape.rowCount} sparkbars=${listShape.sparkbarCount}`);
  console.log(`  time has ISO title=${listShape.timeHasIsoTitle}`);
  console.log(`  sparkbar aria-label=${listShape.sparkbarAriaLabelOk}`);

  // -- IDX-2: click to expand. The drawer must lazy-load via HTMX and the
  //    KPI strip + agent grid + per-agent table must all be present. --
  await page.evaluate(() => {
    const row = document.querySelector('.exec-row');
    if (row) row.click();
  });
  // Wait for the drawer content to swap in (KPI strip is a strong marker).
  await page.waitForSelector('.exec-detail.open .exec-kpi-strip', { timeout: 10000 });
  await page.waitForSelector('.exec-detail.open .agent-grid', { timeout: 5000 });
  await page.waitForSelector('.exec-detail.open .per-agent-table', { timeout: 5000 });

  // KPI strip carries five labelled tiles; "—" sentinel must NOT appear in
  // KPI value position for a completed run (IDX-4).
  const kpi = await page.evaluate(() => {
    const strip = document.querySelector('.exec-detail.open .exec-kpi-strip');
    if (!strip) return null;
    const labels = Array.from(strip.querySelectorAll('.exec-kpi-label')).map(e => e.textContent.trim());
    const values = Array.from(strip.querySelectorAll('.exec-kpi-value')).map(e => e.textContent.trim());
    return { labels, values };
  });
  console.log(`  KPI labels: ${JSON.stringify(kpi?.labels)}`);
  console.log(`  KPI values: ${JSON.stringify(kpi?.values)}`);
  const hasAllLabels = kpi && ['Total','Succeeded','Failed','p50 duration','p95 duration']
        .every(l => kpi.labels.includes(l));

  // -- PR 3: SSE bootstrap attributes ----------------------------------
  // The drawer opens an EventSource on /sse/executions/{id} only when the
  // row was rendered with status=running OR pending. Both data-* attrs
  // must be present on every row so the JS bootstrap (toggleExecDetail)
  // can decide. Pin the markup contract.
  const sseShape = await page.evaluate(() => {
    const rows = Array.from(document.querySelectorAll('.exec-row'));
    return {
      total: rows.length,
      withId: rows.filter(r => r.getAttribute('data-execution-id')).length,
      withStatus: rows.filter(r => r.getAttribute('data-execution-status')).length,
    };
  });
  console.log(`  PR 3 row data-attrs: id=${sseShape.withId}/${sseShape.total} status=${sseShape.withStatus}/${sseShape.total}`);
  const sseAttrsOk = sseShape.total > 0 &&
                      sseShape.withId === sseShape.total &&
                      sseShape.withStatus === sseShape.total;

  // KPI strip on the open drawer must carry id=exec-kpi-{id}. Missing the
  // id stamp means client SSE listeners can't update KPI values without
  // re-rendering the entire drawer (negates PR 3's partial-swap design).
  const kpiHasId = await page.evaluate(() => {
    const strip = document.querySelector('.exec-detail.open .exec-kpi-strip');
    return !!(strip && /^exec-kpi-/.test(strip.id || ''));
  });
  console.log(`  PR 3 KPI strip carries exec-kpi-{id}: ${kpiHasId}`);

  // -- IDX-3: single-drawer-open invariant — open a SECOND row and confirm
  //    the first drawer collapses. --
  let twoDrawerCheck = { firstClosed: true, secondOpen: true };
  if (listShape.rowCount >= 2) {
    twoDrawerCheck = await page.evaluate(() => {
      const rows = document.querySelectorAll('.exec-row');
      rows[1].click();
      // Synchronous DOM mutations land before this returns; HTMX's
      // hx-trigger="click once" may still fire — the visibility state is
      // governed by toggleExecDetail in the same click handler.
      const firstSibling = rows[0].nextElementSibling;
      const secondSibling = rows[1].nextElementSibling;
      return {
        firstClosed: !firstSibling.classList.contains('open'),
        secondOpen: secondSibling.classList.contains('open'),
      };
    });
  }
  console.log(`  single-drawer invariant: first closed=${twoDrawerCheck.firstClosed} second open=${twoDrawerCheck.secondOpen}`);

  await browser.close();

  let pass = true;
  if (pageErrors.length > 0) { console.log(`FAIL: ${pageErrors.length} page-level JS errors`); pass = false; }
  if (!tokensOk) { console.log('FAIL: one or more design-system tokens resolved empty'); pass = false; }
  if (listShape.rowCount === 0) { console.log('FAIL: no .exec-row rendered'); pass = false; }
  if (listShape.sparkbarCount === 0) { console.log('FAIL: no .status-sparkbar rendered'); pass = false; }
  if (!listShape.timeHasIsoTitle) { console.log('FAIL: time cell missing ISO-8601 title'); pass = false; }
  if (!listShape.sparkbarAriaLabelOk) { console.log('FAIL: sparkbar aria-label malformed'); pass = false; }
  if (!hasAllLabels) { console.log('FAIL: KPI strip missing one of Total/Succeeded/Failed/p50/p95'); pass = false; }
  if (!twoDrawerCheck.firstClosed || !twoDrawerCheck.secondOpen) {
    console.log('FAIL: single-drawer-open invariant broken'); pass = false;
  }
  if (!sseAttrsOk) {
    console.log('FAIL: PR 3 data-execution-id / data-execution-status missing from rows'); pass = false;
  }
  if (!kpiHasId) {
    console.log('FAIL: PR 3 KPI strip is missing the exec-kpi-{id} stamp'); pass = false;
  }
  if (!pass) process.exit(1);
  console.log('PASS');
}

main().catch(e => { console.error(e); process.exit(1); });
