/* ── Wizard Navigation & UI Logic ── */

let currentStep = 1;

function goStep(n) {
  // Hide current
  document.getElementById(`step-${currentStep}`).classList.remove('active');
  document.querySelector(`.step[data-step="${currentStep}"]`).classList.remove('active');

  currentStep = n;

  // Show new
  document.getElementById(`step-${currentStep}`).classList.add('active');
  document.querySelector(`.step[data-step="${currentStep}"]`).classList.add('active');

  // If review step, build summary
  if (n === 6) buildReview();

  window.scrollTo({ top: 0, behavior: 'smooth' });
}

// Step nav click handlers
document.querySelectorAll('.step').forEach(btn => {
  btn.addEventListener('click', () => {
    const s = parseInt(btn.dataset.step);
    if (s <= currentStep) goStep(s); // only allow going back, not skipping ahead
  });
});

// Toggle visibility for optional sections
document.getElementById('tls-mode').addEventListener('change', e => {
  const mode = e.target.value;
  document.getElementById('tls-default-fields').style.display = mode === 'default' ? '' : 'none';
  document.getElementById('tls-operator-fields').style.display = mode === 'operator' ? '' : 'none';
  document.getElementById('tls-plaintext-fields').style.display = mode === 'plaintext' ? '' : 'none';
});

document.getElementById('pg-mode').addEventListener('change', e => {
  const bundled = e.target.value === 'bundled';
  document.getElementById('pg-bundled-fields').style.display = bundled ? '' : 'none';
  document.getElementById('pg-external-fields').style.display = bundled ? 'none' : '';
});

document.getElementById('include-clickhouse').addEventListener('change', e => {
  document.getElementById('clickhouse-fields').style.display = e.target.checked ? '' : 'none';
});

document.getElementById('include-prometheus').addEventListener('change', e => {
  document.getElementById('prom-port-field').style.display = e.target.checked ? '' : 'none';
});

document.getElementById('include-grafana').addEventListener('change', e => {
  document.getElementById('grafana-fields').style.display = e.target.checked ? '' : 'none';
});

document.getElementById('include-gateway').addEventListener('change', e => {
  document.getElementById('gateway-fields').style.display = e.target.checked ? '' : 'none';
});

// ── Helpers ──

function val(id) { return document.getElementById(id).value.trim(); }
function num(id) { return parseInt(document.getElementById(id).value) || 0; }
function chk(id) { return document.getElementById(id).checked; }

function tlsModeLabel(mode) {
  if (mode === 'operator') return '🔐 Operator certs';
  if (mode === 'plaintext') return '⚠️ Plaintext (insecure)';
  return '✅ Default certs (auto-generated)';
}

// Fill a field with a cryptographically-random 24-byte hex secret. Used for
// the Postgres credentials so operators can avoid weak / shared passwords —
// the secret only ever lands in the generated .env, never in the compose YAML.
function genSecret(id) {
  const bytes = new Uint8Array(24);
  crypto.getRandomValues(bytes);
  document.getElementById(id).value =
    Array.from(bytes, b => b.toString(16).padStart(2, '0')).join('');
}

// ── Port conflict detection ──
const COMMON_PORTS = {
  80: 'HTTP',
  443: 'HTTPS',
  3000: 'Grafana (default)',
  3306: 'MySQL',
  5000: 'Flask/Python',
  5432: 'PostgreSQL',
  6379: 'Redis',
  8080: 'Common app server',
  8123: 'ClickHouse HTTP (default)',
  9000: 'ClickHouse Native (default)',
  9090: 'Prometheus (default)',
  27017: 'MongoDB',
};

function detectPortConflicts() {
  const ports = {};
  if (chk('include-clickhouse') || true) {
    // Always include server ports
    ports[num('dashboard-port')] = 'Yuzu Dashboard';
    ports[num('grpc-port')] = 'Yuzu Agent gRPC';
    ports[num('mgmt-port')] = 'Yuzu Management gRPC';
    ports[num('gateway-upstream-port')] = 'Yuzu Gateway Upstream';
  }
  if (chk('include-clickhouse')) {
    ports[num('ch-http-port')] = 'ClickHouse HTTP';
    ports[num('ch-native-port')] = 'ClickHouse Native';
  }
  if (chk('include-prometheus')) {
    ports[num('prom-port')] = 'Prometheus';
  }
  if (chk('include-grafana')) {
    ports[num('grafana-port')] = 'Grafana';
  }
  if (chk('include-gateway')) {
    ports[num('gw-agent-port')] = 'Gateway Agent';
    // #1422: the gateway mgmt plane (:50063) is never published, so it holds
    // no host port to collide.
    ports[num('gw-health-port')] = 'Gateway Health';
    ports[num('gw-metrics-port')] = 'Gateway Metrics';
  }

  const warnings = [];
  const seen = {};

  for (const [port, label] of Object.entries(ports)) {
    if (seen[port]) {
      warnings.push(`⚠️ Port ${port} used by both "${seen[port]}" and "${label}"`);
    }
    seen[port] = label;

    if (COMMON_PORTS[port] && !ports[port]?.includes(COMMON_PORTS[port].split(' ')[0])) {
      warnings.push(`ℹ️ Port ${port} is commonly used by ${COMMON_PORTS[port]}`);
    }
  }

  return warnings;
}

// ── Review Summary ──
function buildReview() {
  const pgBundled = val('pg-mode') === 'bundled';
  const items = [
    ['Yuzu Version', val('yuzu-version')],
    ['Admin User', val('admin-user')],
    ['Dashboard Port', num('dashboard-port')],
    ['Agent gRPC Port', num('grpc-port')],
    ['TLS', tlsModeLabel(val('tls-mode'))],
    ['PostgreSQL', pgBundled ? '✅ Bundled container' : '🔗 External / managed'],
    ['ClickHouse', chk('include-clickhouse') ? '✅ Included' : '❌ Skipped'],
    ['Prometheus', chk('include-prometheus') ? '✅ Included' : '❌ Skipped'],
    ['Grafana', chk('include-grafana') ? '✅ Included' : '❌ Skipped'],
    ['Gateway', chk('include-gateway') ? '✅ Included' : '❌ Skipped'],
    ['Named Volumes', chk('persistent-volumes') ? '✅ Yes' : '❌ No'],
  ];

  let html = '<div class="review-grid">';
  for (const [label, value] of items) {
    html += `<div class="review-item"><span class="review-label">${label}</span><span class="review-value">${value}</span></div>`;
  }
  html += '</div>';
  document.getElementById('review-summary').innerHTML = html;

  // Port warnings + Postgres credential checks
  const warnings = detectPortConflicts();
  if (pgBundled) {
    const su = val('pg-superuser-pass');
    const app = val('pg-app-pass');
    if (!su || !app) {
      warnings.push('⚠️ Bundled Postgres: set BOTH the superuser and app-role passwords (🎲 Generate) — the image refuses to boot without them.');
    } else if (su === app) {
      warnings.push('⚠️ Bundled Postgres: superuser and app-role passwords are identical — first-boot init refuses to run. Make them distinct.');
    }
  } else if (!val('pg-dsn')) {
    warnings.push('⚠️ External Postgres selected but no DSN supplied — the server will have no database to talk to.');
  }

  // TLS sanity checks
  const tlsMode = val('tls-mode');
  if (tlsMode === 'operator') {
    if (!val('tls-cert') || !val('tls-key')) {
      warnings.push('⚠️ Operator certs selected but the cert and/or key path is blank — supply both, or switch to Default certs.');
    }
    if (!val('tls-ca-cert')) {
      warnings.push('⚠️ Operator certs need a CA path — the server refuses to start with operator certs and no CA (mandatory mTLS client verification).');
    }
  } else if (tlsMode === 'plaintext') {
    warnings.push('⚠️ Plaintext TLS mode: the agent↔server channel is unencrypted (--no-tls --no-https). Dev only — do not internet-expose port 50051.');
  } else if (tlsMode === 'default' && !chk('persist-certs')) {
    warnings.push('ℹ️ Default certs without persistence: the per-install CA will be regenerated on every container recreate, breaking already-enrolled agents. Enable "Persist generated certs".');
  }
  // Gateway + TLS is not generated yet (secure gateway topology is #1314).
  if (chk('include-gateway') && tlsMode !== 'plaintext') {
    warnings.push('⛔ Gateway + ' + tlsMode + ' certs can\'t be generated yet (secure gateway wiring is in flight, #1314). Pick Plaintext for the gateway, or disable the gateway for a TLS server-only stack.');
  }
  const warnEl = document.getElementById('port-warnings');
  if (warnings.length) {
    warnEl.innerHTML = warnings.join('<br>');
    warnEl.style.display = '';
  } else {
    warnEl.style.display = 'none';
  }
}

// ── Copy & Download ──
function copyToClipboard(id) {
  const text = document.getElementById(id).textContent;
  navigator.clipboard.writeText(text).then(() => {
    // brief visual feedback
    const btn = event.target;
    const orig = btn.textContent;
    btn.textContent = '✅ Copied!';
    setTimeout(() => btn.textContent = orig, 1500);
  });
}

function downloadFile(filename, id) {
  const text = document.getElementById(id).textContent;
  const blob = new Blob([text], { type: 'text/plain' });
  const a = document.createElement('a');
  a.href = URL.createObjectURL(blob);
  a.download = filename;
  a.click();
  URL.revokeObjectURL(a.href);
}