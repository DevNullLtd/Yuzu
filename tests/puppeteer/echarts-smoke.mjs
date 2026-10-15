// Smoke-test the ECharts adapter. Loads the dashboard, confirms ECharts +
// the Yuzu adapter are on window, calls YuzuCharts.render() against a
// synthetic chart payload of every supported type, and verifies that
// each chart-card host element contains a <canvas> the renderer drew.
//
// Failure modes that this regression net catches (governance Gate 4):
//   UP-1  empty design-token resolution → asserted non-empty below
//   UP-15 in-page JS error mid-render → trapped via pageerror
//   UP-3  blank-canvas-passes-OK → still partially open; canvas dimensions
//         alone don't prove rendering happened. Pixel-content check is a
//         separate follow-up.
//   QA-S4 wall-clock dependency → replaced with waitForFunction below
import puppeteer from 'puppeteer';

async function main() {
  const browser = await puppeteer.launch({
    headless: true,
    args: ['--window-size=1400,900', '--no-sandbox'],
    defaultViewport: { width: 1400, height: 900 },
  });
  const page = await browser.newPage();

  // UP-15: page-level JS errors must fail the test, not just log. Any
  // uncaught exception during init / render proves the adapter is
  // broken; we collect them and assert empty at the end so a single
  // bad payload doesn't hide downstream errors.
  const pageErrors = [];
  page.on('pageerror', err => { pageErrors.push(err.message); console.log('[pageerror]', err.message); });
  page.on('console', msg => {
    if (msg.type() === 'error') console.log('[console.error]', msg.text());
  });

  await page.goto('http://localhost:8080/login', { waitUntil: 'networkidle2', timeout: 15000 });
  await page.type('input[name="username"]', 'admin');
  await page.type('input[name="password"]', 'YuzuUatAdmin1!');
  await page.click('button[type="submit"]');
  await page.waitForNavigation({ waitUntil: 'networkidle2', timeout: 15000 });
  // Sign-in now ends on the landing page (/home); the console is the Dashboard at /.
  await page.goto('http://localhost:8080/', { waitUntil: 'networkidle2', timeout: 15000 });

  // QA-S4: wait for the adapter to finish booting deterministically
  // rather than wall-clock-sleeping. ECharts and YuzuCharts globals
  // are populated by the inline scripts in dashboard.html.
  await page.waitForFunction(
    () => typeof window.echarts === 'object' && typeof window.YuzuCharts === 'object',
    { timeout: 15000 }
  );

  // Confirm ECharts loaded
  const ec = await page.evaluate(() => ({
    echartsType: typeof window.echarts,
    echartsVersion: window.echarts?.version,
    yuzuChartsType: typeof window.YuzuCharts,
  }));
  console.log('  globals:', JSON.stringify(ec));
  if (ec.echartsType !== 'object' || ec.yuzuChartsType !== 'object') {
    console.log('FAIL: ECharts or YuzuCharts not on window');
    process.exit(1);
  }

  // Inject five chart hosts and render synthetic payloads through the
  // adapter — exercises every chart_type the engine emits.
  const result = await page.evaluate(async () => {
    const samples = [
      { chart_type: 'pie',    title: 'Pie',
        labels: ['CRITICAL','HIGH','MEDIUM','LOW','INFO'],
        series: [{ name: 'Findings', data: [3, 8, 22, 41, 60] }] },
      { chart_type: 'bar',    title: 'Bar',
        labels: ['Win','Lin','Mac'],
        series: [{ name: 'Hosts', data: [12, 7, 4] }] },
      { chart_type: 'column', title: 'Column',
        labels: ['Q1','Q2','Q3','Q4'],
        series: [
          { name: 'Patched',   data: [40, 55, 60, 72] },
          { name: 'Unpatched', data: [12,  9,  7,  4] },
        ] },
      { chart_type: 'line',   title: 'Line', x_axis: 'datetime',
        x: [1714300000, 1714386400, 1714472800, 1714559200, 1714645600],
        series: [{ name: 'Online', data: [40, 42, 41, 45, 47] }] },
      { chart_type: 'area',   title: 'Area',
        labels: ['Mon','Tue','Wed','Thu','Fri'],
        series: [{ name: 'Events', data: [120, 132, 101, 134, 90] }] },
    ];

    const deck = document.createElement('div');
    deck.id = 'smoke-deck';
    deck.style.cssText = 'display:flex;flex-wrap:wrap;gap:1rem;'
      + 'padding:1rem;background:var(--mds-color-theme-background-canvas);';
    document.body.appendChild(deck);

    const out = [];
    for (const s of samples) {
      const card = document.createElement('div');
      card.className = 'yuzu-chart-card';
      card.style.cssText = 'flex:1 1 360px;min-width:320px;max-width:600px;'
        + 'height:280px;background:var(--mds-color-theme-background-solid-primary);'
        + 'border:1px solid var(--mds-color-theme-outline-primary);'
        + 'border-radius:6px;padding:0.5rem 0.75rem;';
      deck.appendChild(card);
      window.YuzuCharts.render(card, s);
      // ECharts is async-ish on init; one frame is enough.
      await new Promise(r => requestAnimationFrame(r));
      const canvas = card.querySelector('canvas');
      out.push({
        type: s.chart_type,
        rendered: !!canvas,
        canvasSize: canvas
          ? { w: canvas.width, h: canvas.height }
          : null,
        bound: !!window.echarts.getInstanceByDom(card),
      });
    }
    return out;
  });

  let allOk = true;
  for (const r of result) {
    const ok = r.rendered && r.bound && r.canvasSize.w > 0 && r.canvasSize.h > 0;
    console.log(`  ${ok ? 'OK' : 'FAIL'}  ${r.type.padEnd(6)} `
      + `canvas=${r.rendered}  bound=${r.bound}  `
      + `size=${r.canvasSize ? r.canvasSize.w + 'x' + r.canvasSize.h : 'none'}`);
    if (!ok) allOk = false;
  }

  // Snapshot of resolved design-system tokens — confirms the bridge works.
  // UP-1: assert each token resolves non-empty. If yuzu.css fails to
  // load or the :root token block is dropped, every value comes back
  // as the empty string and the chart palette silently falls through
  // to ECharts defaults. We refuse to pass in that state.
  const tokens = await page.evaluate(() => {
    const cs = getComputedStyle(document.documentElement);
    const keys = ['--mds-color-chart-1','--mds-color-chart-2','--mds-color-chart-3',
                  '--mds-color-theme-background-canvas',
                  '--mds-color-theme-text-secondary',
                  '--mds-color-chart-axis','--mds-color-chart-grid'];
    return Object.fromEntries(keys.map(k => [k, cs.getPropertyValue(k).trim()]));
  });
  console.log('  resolved design-system tokens:');
  let tokensOk = true;
  for (const [k, v] of Object.entries(tokens)) {
    console.log(`    ${k} = ${v || '(empty!)'}`);
    if (!v) tokensOk = false;
  }

  await browser.close();

  // UP-15: pageerror trap surfaces as a fail, not just logs.
  if (pageErrors.length > 0) {
    console.log(`FAIL: ${pageErrors.length} page-level JS error(s) during run`);
    process.exit(1);
  }
  if (!tokensOk) { console.log('FAIL: one or more design-system tokens resolved empty'); process.exit(1); }
  if (!allOk)    { console.log('FAIL: at least one chart did not render'); process.exit(1); }
  console.log('PASS');
}

main().catch(e => { console.error(e); process.exit(1); });
