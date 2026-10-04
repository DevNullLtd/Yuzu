// Apache ECharts adapter for Yuzu's instruction-response visualization
// cards (issue #253).
//
// This file replaces the original vanilla-SVG renderer. The adapter still
// exposes the original surface — `window.YuzuCharts.render(el, data)` and
// the [data-yuzu-chart-url] auto-render hook — so dashboard_routes.cpp
// emits the same chart-card markup it always has. What changed is the
// engine underneath: charts are now drawn by Apache ECharts 5
// (Apache-2.0, vendored at server/core/vendor/echarts.min.js) using a
// dynamically-built theme that resolves every colour, font, and
// gridline from the Yuzu design-system CSS custom properties at render time.
// Re-skinning Yuzu = changing --mds-color-* tokens; charts pick up
// the new palette on the next render with no JS rebuild.
//
// Contract (unchanged):
//   render(target, data) where data = {
//     chart_type: 'pie'|'bar'|'column'|'line'|'area',
//     title, labels[], x[], series:[{name,data}], x_axis?:'datetime',
//     error?: string
//   }
//
// Loads after /static/echarts.min.js, registered in dashboard_ui.cpp.

#include <string>

namespace yuzu::server {

// `extern` is load-bearing here: namespace-scope `const` variables have
// internal linkage by default in C++, which would make this symbol invisible
// to server.cpp's reference. Mirrors the pattern used by kHtmxJs in
// static_js_bundle.cpp.
extern const std::string kYuzuChartsJs = R"JS((function () {
  'use strict';

  // ── Token bridge ────────────────────────────────────────────────────────
  // Resolve design-system tokens at render time so theme switches take effect
  // without a rebuild. getComputedStyle is cheap on :root.
  function tok(name, fallback) {
    var v = getComputedStyle(document.documentElement)
      .getPropertyValue(name).trim();
    return v || fallback;
  }

  function palette() {
    return [
      tok('--mds-color-chart-1',  '#58a6ff'),
      tok('--mds-color-chart-2',  '#04a77b'),
      tok('--mds-color-chart-3',  '#9c5bd9'),
      tok('--mds-color-chart-4',  '#f7b500'),
      tok('--mds-color-chart-5',  '#e93e69'),
      tok('--mds-color-chart-6',  '#6fbf40'),
      tok('--mds-color-chart-7',  '#58c9f3'),
      tok('--mds-color-chart-8',  '#c8208e'),
      tok('--mds-color-chart-9',  '#ed7d31'),
      tok('--mds-color-chart-10', '#8e51c8'),
      tok('--mds-color-chart-11', '#b5bc36'),
      tok('--mds-color-chart-12', '#ff6b81'),
    ];
  }

  function themeOption() {
    var fg     = tok('--mds-color-theme-text-secondary', '#c9d1d9');
    var muted  = tok('--mds-color-theme-text-tertiary',  '#8b949e');
    var axis   = tok('--mds-color-chart-axis',           '#8b949e');
    var grid   = tok('--mds-color-chart-grid',           '#30363d');
    var tipBg  = tok('--mds-color-chart-tooltip-bg',     '#1c232c');
    var tipFg  = tok('--mds-color-chart-tooltip-fg',     '#f4f5f6');
    var tipBd  = tok('--mds-color-chart-tooltip-border', '#30363d');
    var family = tok('--mds-font-family-default',
                     '-apple-system,BlinkMacSystemFont,sans-serif');
    return {
      color: palette(),
      backgroundColor: 'transparent',
      textStyle: { color: fg, fontFamily: family, fontSize: 12 },
      title: {
        textStyle: { color: fg, fontFamily: family, fontWeight: 600,
                     fontSize: 13 },
        left: 'left', top: 4,
      },
      tooltip: {
        backgroundColor: tipBg, borderColor: tipBd,
        textStyle: { color: tipFg, fontFamily: family, fontSize: 12 },
        confine: true,
      },
      legend: {
        textStyle: { color: muted, fontFamily: family, fontSize: 11 },
        bottom: 0, type: 'scroll', icon: 'circle', itemWidth: 8,
        itemHeight: 8, itemGap: 14,
      },
      grid: { left: 56, right: 24, top: 36, bottom: 48, containLabel: true },
      xAxis: {
        axisLine:  { lineStyle: { color: axis } },
        axisTick:  { lineStyle: { color: axis } },
        axisLabel: { color: muted, fontFamily: family, fontSize: 10 },
        splitLine: { lineStyle: { color: grid, type: 'dashed' } },
      },
      yAxis: {
        axisLine:  { lineStyle: { color: axis } },
        axisTick:  { lineStyle: { color: axis } },
        axisLabel: { color: muted, fontFamily: family, fontSize: 10 },
        splitLine: { lineStyle: { color: grid, type: 'dashed' } },
      },
    };
  }

  // ── Option builders ─────────────────────────────────────────────────────
  // Each builder returns a partial ECharts option that is merged with the
  // theme option above. ECharts deep-merges so anything declared here
  // overrides theme defaults of the same key.

  function pieOption(data) {
    var labels = data.labels || [];
    var s = (data.series && data.series[0]) || { data: [] };
    var values = s.data || [];
    var pts = labels.map(function (l, i) {
      return { name: String(l), value: Number(values[i]) || 0 };
    }).filter(function (p) { return p.value > 0; });
    return {
      title: { text: data.title || '' },
      tooltip: { trigger: 'item', formatter: '{b}: {c} ({d}%)' },
      legend: { bottom: 0, type: 'scroll' },
      series: [{
        type: 'pie', radius: ['38%', '68%'], center: ['50%', '50%'],
        avoidLabelOverlap: true,
        itemStyle: {
          borderColor: tok('--mds-color-theme-background-solid-primary',
                           '#161b22'),
          borderWidth: 2, borderRadius: 4,
        },
        label: { color: tok('--mds-color-theme-text-secondary', '#c9d1d9'),
                 fontSize: 11 },
        labelLine: { lineStyle: { color: tok('--mds-color-chart-axis',
                                              '#8b949e') } },
        data: pts,
      }],
    };
  }

  function barOption(data, horizontal) {
    var labels = data.labels || [];
    var series = (data.series || []).map(function (s, i) {
      return {
        type: 'bar', name: s.name || ('series ' + (i + 1)),
        data: s.data || [],
        barMaxWidth: 28,
        itemStyle: { borderRadius: horizontal ? [0, 4, 4, 0] : [4, 4, 0, 0] },
        emphasis: { focus: 'series' },
      };
    });
    var cat = { type: 'category', data: labels.map(String),
                axisLabel: { interval: 0, rotate: horizontal ? 0 : 30 } };
    var val = { type: 'value' };
    return {
      title: { text: data.title || '' },
      tooltip: { trigger: 'axis', axisPointer: { type: 'shadow' } },
      legend: series.length > 1 ? { bottom: 0 } : { show: false },
      xAxis: horizontal ? val : cat,
      yAxis: horizontal ? cat : val,
      series: series,
    };
  }

  function lineOption(data, fillArea) {
    var isTime = data.x_axis === 'datetime';
    var xs = data.x || (data.labels || []).map(function (_, i) { return i; });
    var pal = palette();
    var series = (data.series || []).map(function (s, i) {
      var color = pal[i % pal.length];
      var pts = (s.data || []).map(function (v, idx) {
        if (isTime) {
          return [xs[idx] * 1000, Number(v)];
        }
        return [xs[idx], Number(v)];
      });
      return {
        type: 'line', name: s.name || ('series ' + (i + 1)),
        data: pts, smooth: 0.25, showSymbol: pts.length <= 64,
        symbol: 'circle', symbolSize: 6,
        lineStyle: { width: 2 },
        areaStyle: fillArea ? {
          opacity: 0.18,
          color: {
            type: 'linear', x: 0, y: 0, x2: 0, y2: 1,
            colorStops: [
              { offset: 0, color: color },
              { offset: 1, color: color + '00' },
            ],
          },
        } : undefined,
        emphasis: { focus: 'series' },
      };
    });
    return {
      title: { text: data.title || '' },
      tooltip: { trigger: 'axis' },
      legend: series.length > 1 ? { bottom: 0 } : { show: false },
      xAxis: isTime
        ? { type: 'time' }
        : { type: 'category',
            data: (data.labels || xs).map(String),
            boundaryGap: false },
      yAxis: { type: 'value' },
      series: series,
    };
  }

  // ── Render entrypoint ───────────────────────────────────────────────────
  function deepMerge(a, b) {
    if (!b) return a;
    Object.keys(b).forEach(function (k) {
      if (b[k] && typeof b[k] === 'object' && !Array.isArray(b[k])
          && a[k] && typeof a[k] === 'object' && !Array.isArray(a[k])) {
        deepMerge(a[k], b[k]);
      } else {
        a[k] = b[k];
      }
    });
    return a;
  }

  // True when the payload has nothing for the renderer to draw — every
  // series array is empty, or pie has zero positive values. Distinct
  // from `data.error` (a backend-reported failure) and from missing
  // chart_type (a malformed payload).
  function isEmptyData(d) {
    var series = d.series || [];
    if (!series.length) return true;
    var anyPositive = false;
    for (var i = 0; i < series.length; i++) {
      var arr = series[i].data || [];
      if (arr.length > 0) {
        for (var j = 0; j < arr.length; j++) {
          var v = Number(arr[j]);
          if (v && v > 0) { anyPositive = true; break; }
        }
      }
      if (anyPositive) break;
    }
    if (d.chart_type === 'pie') return !anyPositive;
    // For bar/column/line/area: require at least one non-empty series
    // array. Zero-valued points are legitimate.
    return !series.some(function (s) { return (s.data || []).length > 0; });
  }

  function emptyState(target, msg) {
    target.innerHTML = '<div class="yuzu-chart-empty" style="padding:24px;'
      + 'text-align:center;color:var(--mds-color-theme-text-tertiary,#888);'
      + 'font:13px var(--mds-font-family-default,sans-serif);">'
      + escapeHtml(msg) + '</div>';
  }

  function escapeHtml(s) {
    return String(s).replace(/[&<>"']/g, function (c) {
      return ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]);
    });
  }

  // A chart built from a cut result is a wrong picture, not a smaller one.
  // The visualization route says so with rows_capped (row cap only) and
  // result_truncated_by_cap + truncation_cause (row_cap | byte_cap). Show it
  // in-card, above the chart host, and clear it on a re-render that is not cut.
  // textContent only: nothing from the payload is interpreted as markup.
  function truncationNotice(target, data) {
    var prior = target.previousElementSibling;
    if (prior && prior.classList && prior.classList.contains('yuzu-chart-truncated')) {
      prior.parentNode.removeChild(prior);
    }
    var cut = !!(data && (data.result_truncated_by_cap || data.rows_capped));
    if (!cut || !target.parentNode) return;
    var msg;
    if (data.truncation_cause === 'byte_cap') {
      msg = 'Partial result: this chart was built from responses cut at the '
          + '50 MiB payload cap, so some agents are missing from it.';
    } else {
      var n = Number(data.rows_cap);
      msg = 'Partial result: this chart was built from the first '
          + (n > 0 ? n.toLocaleString('en-US') : 'capped number of') + ' rows only, '
          + 'so some agents are missing from it.';
    }
    var note = document.createElement('div');
    note.className = 'result-degrade-banner yuzu-chart-truncated';
    note.setAttribute('data-chart-truncated',
        data.truncation_cause === 'byte_cap' ? 'byte_cap' : 'row_cap');
    note.style.marginBottom = '0.5rem';
    note.textContent = msg;
    target.parentNode.insertBefore(note, target);
  }

  function chartHostHeight(target) {
    // Cards are typically ~280px; let CSS height: drive it if set, else
    // default to a comfortable 280px.
    var h = target.clientHeight;
    return h > 80 ? h : 280;
  }

  function render(target, data) {
    if (!target || !data) return;
    if (!window.echarts) {
      // ECharts hasn't finished loading yet — defer one tick. The
      // /static/echarts.min.js script tag is in dashboard <head> so this
      // path is only hit on extremely cold loads.
      setTimeout(function () { render(target, data); }, 50);
      return;
    }
    truncationNotice(target, data);
    if (data.error) { emptyState(target, data.error); return; }
    if (!data.chart_type) { emptyState(target, 'No chart type configured.'); return; }

    // Empty-data guard — match the pre-rewrite SVG renderer's behaviour
    // (governance Gate 4 HP-1). A chart-bearing instruction with zero
    // responses (clean fleet, scope mismatch, agents offline) used to
    // show 'No data to plot'; the ECharts adapter would otherwise paint
    // a blank canvas with no signal to the operator.
    if (isEmptyData(data)) {
      emptyState(target, 'No data to plot.');
      return;
    }

    // Dispose any prior ECharts instance bound to this target — happens
    // when HTMX re-swaps a chart card with new data.
    var prior = window.echarts.getInstanceByDom(target);
    if (prior) { prior.dispose(); }
    target.innerHTML = '';
    target.style.height = chartHostHeight(target) + 'px';

    var inst = window.echarts.init(target, null, { renderer: 'canvas' });
    var opt = themeOption();
    var partial;
    switch (data.chart_type) {
      case 'pie':    partial = pieOption(data);            break;
      case 'bar':    partial = barOption(data, true);      break;
      case 'column': partial = barOption(data, false);     break;
      case 'line':   partial = lineOption(data, false);    break;
      case 'area':   partial = lineOption(data, true);     break;
      default:
        emptyState(target, 'Unsupported chart type: ' + data.chart_type);
        return;
    }
    deepMerge(opt, partial);
    inst.setOption(opt);

    // Reflow on viewport resize. ECharts' resize() is idempotent.
    if (!target._yuzuResize) {
      target._yuzuResize = function () {
        var i = window.echarts.getInstanceByDom(target);
        if (i) { i.resize(); }
      };
      window.addEventListener('resize', target._yuzuResize);
    }
  }

  // ── Auto-render hook (HTMX-friendly) ────────────────────────────────────
  function autoRender(root) {
    var els = (root || document).querySelectorAll('[data-yuzu-chart-url]');
    els.forEach(function (el) {
      if (el.dataset.yuzuChartLoaded === '1') return;
      el.dataset.yuzuChartLoaded = '1';
      fetch(el.dataset.yuzuChartUrl, { credentials: 'same-origin' })
        .then(function (r) { return r.json(); })
        .then(function (j) { render(el, (j && j.data) ? j.data : j); })
        .catch(function (err) {
          render(el, { error: 'Chart load failed: ' + err });
        });
    });
  }

  document.addEventListener('htmx:afterSettle', function (e) {
    autoRender(e.target || document);
  });
  document.addEventListener('DOMContentLoaded', function () {
    autoRender(document);
  });

  window.YuzuCharts = { render: render, autoRender: autoRender };
})();
)JS";

} // namespace yuzu::server
