/**
 * Puppeteer diagnostic: SSE event flow through HTMX
 *
 * Hooks into EventSource and HTMX at the JS level to find
 * where the output events are being dropped.
 */

import puppeteer from 'puppeteer';

const BASE_URL = 'http://localhost:8080';
const USERNAME = 'admin';
const PASSWORD = 'YuzuUatAdmin1!';

async function sleep(ms) {
  return new Promise(r => setTimeout(r, ms));
}

async function main() {
  console.log('=== SSE Debug Diagnostic ===\n');

  const browser = await puppeteer.launch({
    headless: false,
    args: ['--window-size=1400,900', '--no-sandbox'],
    defaultViewport: { width: 1400, height: 900 },
  });

  const page = await browser.newPage();

  // Capture all console messages
  page.on('console', msg => {
    const text = msg.text();
    if (text.startsWith('[SSE-DBG]') || text.startsWith('[HTMX-DBG]'))
      console.log(`  ${text}`);
  });

  // ── Login ─────────────────────────────────────────────────────
  console.log('[1] Logging in...');
  await page.goto(`${BASE_URL}/login`, { waitUntil: 'networkidle2' });
  await page.type('input[name="username"]', USERNAME);
  await page.type('input[name="password"]', PASSWORD);
  await page.click('button[type="submit"]');
  await page.waitForNavigation({ waitUntil: 'networkidle2' });
  console.log(`  URL: ${page.url()}`);

  // ── Inject SSE + HTMX event monitors ──────────────────────────
  console.log('\n[2] Injecting event monitors...');
  await page.evaluate(() => {
    // Hook into native EventSource to monitor events
    const origES = window.EventSource;
    window._sseDebug = { events: [], errors: [] };

    // Monitor the existing EventSource if HTMX already created one
    // The SSE extension creates an EventSource when it processes sse-connect
    // We need to intercept it
    const origAddEventListener = EventSource.prototype.addEventListener;
    EventSource.prototype.addEventListener = function(type, listener, options) {
      console.log(`[SSE-DBG] EventSource.addEventListener("${type}")`);
      // Wrap listener to log events
      const wrappedListener = function(event) {
        console.log(`[SSE-DBG] Event received: type="${event.type}", data="${event.data?.substring(0, 100)}..."`);
        window._sseDebug.events.push({
          type: event.type,
          dataLen: event.data?.length || 0,
          dataPreview: event.data?.substring(0, 200),
          time: Date.now()
        });
        return listener.call(this, event);
      };
      return origAddEventListener.call(this, type, wrappedListener, options);
    };

    // Also monitor HTMX events
    document.body.addEventListener('htmx:sseMessage', (e) => {
      console.log(`[HTMX-DBG] htmx:sseMessage - type="${e.detail?.type}", data="${e.detail?.data?.substring(0, 100)}..."`);
    });
    document.body.addEventListener('htmx:sseBeforeMessage', (e) => {
      console.log(`[HTMX-DBG] htmx:sseBeforeMessage - type="${e.detail?.type}"`);
    });
    document.body.addEventListener('htmx:beforeSwap', (e) => {
      const target = e.detail?.target;
      console.log(`[HTMX-DBG] htmx:beforeSwap - target="${target?.id}", trigger="${e.detail?.requestConfig?.triggerType}"`);
    });
    document.body.addEventListener('htmx:afterSwap', (e) => {
      const target = e.detail?.target;
      console.log(`[HTMX-DBG] htmx:afterSwap - target="${target?.id}"`);
    });
    document.body.addEventListener('htmx:oobAfterSwap', (e) => {
      const target = e.detail?.target;
      console.log(`[HTMX-DBG] htmx:oobAfterSwap - target="${target?.id}"`);
    });
    document.body.addEventListener('htmx:sseError', (e) => {
      console.log(`[HTMX-DBG] htmx:sseError - ${JSON.stringify(e.detail)}`);
    });
    document.body.addEventListener('htmx:sseOpen', (e) => {
      console.log(`[HTMX-DBG] htmx:sseOpen`);
    });
    document.body.addEventListener('htmx:sseClose', (e) => {
      console.log(`[HTMX-DBG] htmx:sseClose`);
    });

    console.log('[SSE-DBG] Monitors injected');
  });

  // Wait a moment then check if the existing EventSource is working
  await sleep(2000);

  // Check the current SSE state
  const sseState = await page.evaluate(() => {
    const sseEl = document.querySelector('[sse-connect]');
    // The HTMX SSE extension stores the EventSource on the element's internal data
    const internalData = htmx._('getInternalData') ? htmx._('getInternalData')(sseEl) : null;
    // Try to find EventSource via internal HTMX data
    const api = htmx.find('[sse-connect]');

    return {
      element: sseEl ? sseEl.tagName : null,
      sseConnect: sseEl?.getAttribute('sse-connect'),
      hxExt: sseEl?.getAttribute('hx-ext'),
      // Check if there are any sse-swap elements
      sseSwapElements: [...document.querySelectorAll('[sse-swap]')].map(el => ({
        tag: el.tagName,
        id: el.id,
        sseSwap: el.getAttribute('sse-swap'),
        hxSwap: el.getAttribute('hx-swap'),
      })),
    };
  });

  console.log('\n[3] Current SSE state:');
  console.log(`  Container: ${sseState.element}, sse-connect="${sseState.sseConnect}", hx-ext="${sseState.hxExt}"`);
  console.log(`  SSE swap elements:`);
  for (const el of sseState.sseSwapElements) {
    console.log(`    <${el.tag} id="${el.id}" sse-swap="${el.sseSwap}" hx-swap="${el.hxSwap}">`);
  }

  // ── Force reconnect the SSE to pick up our monitors ────────────
  console.log('\n[4] Reconnecting SSE to attach monitors...');
  await page.evaluate(() => {
    // Force SSE reconnection so our addEventListener wrapper catches events
    const w = document.querySelector('[sse-connect]');
    if (w) {
      w.removeAttribute('sse-connect');
      setTimeout(() => {
        w.setAttribute('sse-connect', '/events');
        htmx.process(w);
        console.log('[SSE-DBG] SSE reconnected');
      }, 200);
    }
  });

  await sleep(3000);

  // ── Send a command ──────────────────────────────────────────────
  console.log('\n[5] Sending command: "os_info os_name"...');

  // Find and use the command input
  const inputSelector = await page.evaluate(() => {
    // Try various selectors
    for (const sel of ['#command-input', 'input[name="instruction"]', '#instruction-input', 'input[type="text"]']) {
      const el = document.querySelector(sel);
      if (el) return { selector: sel, tag: el.tagName, name: el.name, id: el.id, placeholder: el.placeholder };
    }
    // List all inputs
    const inputs = [...document.querySelectorAll('input')];
    return {
      selector: null,
      allInputs: inputs.map(i => ({ tag: i.tagName, type: i.type, name: i.name, id: i.id, placeholder: i.placeholder }))
    };
  });
  console.log(`  Input element: ${JSON.stringify(inputSelector)}`);

  if (inputSelector.selector) {
    const input = await page.$(inputSelector.selector);
    await input.click({ count: 3 });
    await input.type('os_info os_name');

    // Find and click Send
    const btnInfo = await page.evaluate(() => {
      const btns = [...document.querySelectorAll('button')];
      return btns.map(b => ({ text: b.textContent.trim(), type: b.type, id: b.id, className: b.className }));
    });
    console.log(`  Buttons: ${JSON.stringify(btnInfo.filter(b => b.text.includes('Send') || b.type === 'submit'))}`);

    const sendBtn = await page.$('button[type="submit"]');
    if (sendBtn) {
      await sendBtn.click();
      console.log('  Command submitted');
    }
  }

  // Wait and watch for events
  console.log('\n[6] Waiting 8 seconds for SSE events...');
  await sleep(8000);

  // Check results
  const results = await page.evaluate(() => {
    const tbody = document.getElementById('results-tbody');
    return {
      tbodyHTML: tbody?.innerHTML?.substring(0, 500),
      tbodyChildren: tbody?.children?.length,
      resultRows: document.querySelectorAll('.result-row').length,
      rowCount: document.getElementById('row-count')?.textContent,
      sseDebug: window._sseDebug,
    };
  });

  console.log('\n[7] Results:');
  console.log(`  Result rows: ${results.resultRows}`);
  console.log(`  Row count: ${results.rowCount}`);
  console.log(`  Tbody children: ${results.tbodyChildren}`);
  console.log(`  SSE events captured: ${results.sseDebug?.events?.length || 0}`);
  if (results.sseDebug?.events) {
    for (const ev of results.sseDebug.events) {
      console.log(`    type="${ev.type}" dataLen=${ev.dataLen} preview="${ev.dataPreview?.substring(0, 100)}"`);
    }
  }
  console.log(`  Tbody HTML: ${results.tbodyHTML}`);

  console.log('\nBrowser open for inspection. Ctrl+C to exit.');
  await new Promise(() => {});
}

main().catch(err => {
  console.error('Test failed:', err);
  process.exit(1);
});
