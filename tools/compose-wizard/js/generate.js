/* ── Compose File Generator ── */

async function generate() {
  const pgMode = val('pg-mode');
  const pgSuperPass = val('pg-superuser-pass');
  const pgAppPass = val('pg-app-pass');
  const pgDsn = val('pg-dsn');

  // Guard the load-bearing substrate invariants before emitting anything —
  // a compose/.env pair that the postgres image will refuse to boot is worse
  // than no output.
  if (pgMode === 'bundled') {
    if (!pgSuperPass || !pgAppPass) {
      alert('Bundled PostgreSQL: set BOTH the superuser and app-role passwords on the Data step (use 🎲 Generate). The yuzu-postgres image refuses to boot without them.');
      return;
    }
    if (pgSuperPass === pgAppPass) {
      alert('Bundled PostgreSQL: the superuser and app-role passwords must be DISTINCT — the image\'s first-boot init refuses to run if they are equal.');
      return;
    }
  } else if (!pgDsn) {
    alert('External PostgreSQL: supply a DSN on the Data step, or switch to the bundled mode. The server needs a database to talk to.');
    return;
  }

  const tlsMode = val('tls-mode');
  const gateway = chk('include-gateway');

  if (tlsMode === 'operator' && (!val('tls-cert') || !val('tls-key'))) {
    alert('Operator certs: set BOTH the certificate and key path on the Core step, or switch to Default certs (the server then auto-generates them).');
    return;
  }

  // H2: with operator certs the server requires a CA (require_client_cert =
  // !using_default_agent_certs = true) and refuses to start without one unless
  // --insecure-skip-client-verify + YUZU_ALLOW_INSECURE_TLS=1 are set. Don't emit
  // a non-booting server — require the CA path.
  if (tlsMode === 'operator' && !val('tls-ca-cert')) {
    alert('Operator certs: the CA certificate path is required — the server refuses to start with operator certs and no CA (mTLS client verification is mandatory). Supply it, or run the server with --insecure-skip-client-verify + YUZU_ALLOW_INSECURE_TLS=1 yourself.');
    return;
  }

  // C1/N2: the secure gateway↔server topology (mutual-TLS upstream, --cert-group
  // cert sharing, TLS mgmt listener) depends on server features that live in the
  // PKI go-live PR (#1314) and are NOT on the current images — emitting them
  // produces a stack that crash-loops at argv parse (--cert-group) or fails command
  // forwarding (server dials the mgmt port plaintext). Until that ships, the gateway
  // is only generated for Plaintext mode. (Tracked: re-enable once #1314 lands.)
  if (gateway && tlsMode !== 'plaintext') {
    alert('Gateway + TLS is not generated yet: the secure gateway↔server wiring depends on server features still in flight (PKI go-live, #1314) that no current image ships, so the stack would not boot. Either pick Plaintext for the gateway, or disable the gateway and use Default/Operator certs for a server-only stack. For a secure gateway today, follow deploy/docker/docker-compose.reference.yml + gateway/config/sys.config.prod.');
    return;
  }

  // N1: cert-san values are interpolated into the server command list; an unescaped
  // quote+newline payload could break out and inject standalone flags (e.g.
  // --no-tls → silent plaintext). Validate each token to DNS/IP shape before use.
  const sanCheck = validateCertSans(val('cert-san'));
  if (sanCheck.bad.length) {
    alert('Invalid --cert-san value(s): ' + sanCheck.bad.join(', ') +
          '\nUse only DNS names / IPs, optionally prefixed dns:/ip: (letters, digits, dot, hyphen, colon). No quotes, spaces, or control characters.');
    return;
  }

  // #1488: the admin credential row is PBKDF2-HMAC-SHA256 (100k iters), derived
  // in-browser via SubtleCrypto. Requires a secure context (https / localhost /
  // file://) — fail loudly rather than emit a stale, non-validating hash.
  if (!window.crypto || !crypto.subtle) {
    alert('Cannot hash the admin password: this browser exposes no Web Crypto Subtle API. Serve the wizard over http://localhost (e.g. `python3 -m http.server`) or open it via file:// in a modern browser, then retry.');
    return;
  }
  const authLine = await computeAuthLine(val('admin-user'), 'admin', val('admin-pass'));

  // #1483: a fresh Erlang distribution cookie so the gateway doesn't fail-closed
  // on the insecure default. Lands only in .env.
  const gwCookie = randHex(32);

  const config = {
    authLine: authLine,
    gwCookie: gwCookie,
    version: val('yuzu-version'),
    adminUser: val('admin-user'),
    adminPass: val('admin-pass'),
    dashboardPort: num('dashboard-port'),
    grpcPort: num('grpc-port'),
    mgmtPort: num('mgmt-port'),
    gwUpstreamPort: num('gateway-upstream-port'),
    tlsMode: tlsMode,
    tlsCert: val('tls-cert'),
    tlsKey: val('tls-key'),
    tlsCaCert: val('tls-ca-cert'),
    certSans: val('cert-san'),
    persistCerts: chk('persist-certs'),
    dataDir: val('data-dir'),
    pgMode: pgMode,
    pgBundled: pgMode === 'bundled',
    pgSuperPass: pgSuperPass,
    pgAppPass: pgAppPass,
    pgDsn: pgDsn,
    clickhouse: chk('include-clickhouse'),
    chHttpPort: num('ch-http-port'),
    chNativePort: num('ch-native-port'),
    chUser: val('ch-user'),
    chPass: val('ch-pass'),
    chDb: val('ch-db'),
    persistentVolumes: chk('persistent-volumes'),
    prometheus: chk('include-prometheus'),
    promPort: num('prom-port'),
    grafana: chk('include-grafana'),
    grafanaPort: num('grafana-port'),
    grafanaPass: val('grafana-pass'),
    gateway: chk('include-gateway'),
    gwAgentPort: num('gw-agent-port'),
    gwHealthPort: num('gw-health-port'),
    gwMetricsPort: num('gw-metrics-port'),
    gwPoolSize: num('gw-pool-size'),
    gwTls: chk('gw-tls'),
  };

  const compose = generateCompose(config);
  const env = generateEnv(config);

  document.getElementById('compose-output').textContent = compose;
  document.getElementById('env-output').textContent = env;
  document.getElementById('output').style.display = '';
  document.getElementById('output').scrollIntoView({ behavior: 'smooth' });
}

// Hex-encode `n` cryptographically-random bytes.
function randHex(n) {
  return Array.from(crypto.getRandomValues(new Uint8Array(n)),
                    b => b.toString(16).padStart(2, '0')).join('');
}

// #1488: produce a server auth-config row `username:role:salt_hex:hash_hex`
// matching the server's KDF exactly — PBKDF2-HMAC-SHA256, 100000 iterations,
// 32-byte derived key, random 16-byte salt (auth.cpp pbkdf2_sha256 /
// kPbkdf2Iterations). The previous hardcoded row put the *password* in the role
// field and shipped a hash for no current KDF, so `admin/admin` 401'd.
async function computeAuthLine(user, role, password) {
  const enc = new TextEncoder();
  const salt = crypto.getRandomValues(new Uint8Array(16));
  const keyMaterial = await crypto.subtle.importKey(
    'raw', enc.encode(password), { name: 'PBKDF2' }, false, ['deriveBits']);
  const bits = await crypto.subtle.deriveBits(
    { name: 'PBKDF2', salt: salt, iterations: 100000, hash: 'SHA-256' }, keyMaterial, 256);
  const hex = buf => Array.from(new Uint8Array(buf),
                                b => b.toString(16).padStart(2, '0')).join('');
  return `${user}:${role}:${hex(salt)}:${hex(bits)}`;
}

function generateEnv(c) {
  return `# ── Yuzu Environment Variables ──
# Generated by Yuzu Compose Wizard
# Edit this file to reconfigure without touching docker-compose.yml

# Yuzu version (container image tag)
YUZU_VERSION=${c.version}

# ── Server ──
YUZU_DASHBOARD_PORT=${c.dashboardPort}
YUZU_GRPC_PORT=${c.grpcPort}
YUZU_MGMT_PORT=${c.mgmtPort}
YUZU_GATEWAY_UPSTREAM_PORT=${c.gwUpstreamPort}
YUZU_ADMIN_USER=${c.adminUser}
${c.pgBundled ? `
# ── PostgreSQL (server storage substrate, ADR-0006/0008) ──
# Two DISTINCT credentials — keep both in a secrets manager, not in git.
# The superuser password stays inside the postgres container; the app-role
# password is what the server's DSN carries. They MUST differ (the image's
# first-boot init refuses to run if they are equal). Rotate with:
#   openssl rand -hex 24
YUZU_POSTGRES_PASSWORD=${c.pgSuperPass}
YUZU_DB_PASSWORD=${c.pgAppPass}` : `
# ── PostgreSQL (external / managed substrate) ──
# Full server DSN — carries the app-role password, never a superuser
# credential. Keep it out of git; this file is the only place it lives.
YUZU_POSTGRES_DSN=${c.pgDsn}`}
${c.clickhouse ? `YUZU_CLICKHOUSE_PASSWORD=${c.chPass}
YUZU_CLICKHOUSE_DB=${c.chDb}
YUZU_CLICKHOUSE_USER=${c.chUser}` : ''}
${c.prometheus ? `
# ── Prometheus ──
YUZU_PROMETHEUS_PORT=${c.promPort}` : ''}
${c.grafana ? `
# ── Grafana ──
YUZU_GRAFANA_PORT=${c.grafanaPort}
YUZU_GRAFANA_ADMIN_PASSWORD=${c.grafanaPass}` : ''}
${c.gateway ? `
# ── Gateway ──
YUZU_GW_AGENT_PORT=${c.gwAgentPort}
YUZU_GW_HEALTH_PORT=${c.gwHealthPort}
YUZU_GW_METRICS_PORT=${c.gwMetricsPort}
# Erlang distribution cookie — the gateway fail-closes on the insecure default.
# Generated unique per stack; keep it out of git. Rotate with: openssl rand -hex 32
# (Single ephemeral node? You may instead set YUZU_GW_ALLOW_DEFAULT_COOKIE=1.)
YUZU_GW_COOKIE=${c.gwCookie}` : ''}`;
}

// N1: validate operator-supplied --cert-san tokens to DNS/IP shape so they can't
// break out of the YAML scalar / argv list and inject standalone flags. Returns
// { sans: [valid, deduped], bad: [rejected] }. The server's parse_extra_sans does
// the authoritative parse; this only stops the pre-server YAML breakout.
function validateCertSans(raw) {
  const sans = [], bad = [];
  for (const piece of (raw || '').split(',')) {
    const s = piece.trim();
    if (!s) continue;
    const m = /^(?:(?:dns|ip):)?(.+)$/i.exec(s);
    const value = m ? m[1] : s;
    // DNS-label / IPv4 / IPv6 characters only; reject flag-like leading '-'.
    const ok = /^[A-Za-z0-9._:-]+$/.test(value) && !value.startsWith('-');
    if (ok) { if (!sans.includes(s)) sans.push(s); }
    else bad.push(s);
  }
  return { sans, bad };
}

// Effective (validated) --cert-san set for the auto-generated default certs.
// Gateway service names aren't added — gateway + TLS isn't generated yet (the
// secure gateway topology is #1314; see the C1/N2 guard in generate()).
function effectiveCertSans(c) {
  return validateCertSans(c.certSans || '').sans;
}

function generateCompose(c) {
  // HTTPS is served unless plaintext mode explicitly disables it. In TLS modes
  // the dashboard/API is HTTPS on container port 8443 (8080 is an HTTP→HTTPS
  // redirect); plaintext serves HTTP on 8080 (#1484).
  const tls = c.tlsMode !== 'plaintext';
  const webScheme = tls ? 'https' : 'http';
  const webContainerPort = tls ? 8443 : 8080;
  // Named cert volume: every mode except operator, whenever named volumes are on.
  // /etc/yuzu/certs holds the secrets KEK, which is registered in Postgres, so it
  // must live exactly as long as the Postgres volume, in Plaintext mode too (the
  // server still writes the KEK there with --no-tls). Not optional (#5370).
  // (Gateway + TLS isn't generated — see the C1/N2 guard — so there's no
  // cross-container cert sharing to force a named volume.)
  const certVolNamed = c.tlsMode !== 'operator' && c.persistentVolumes;

  let y = `## Yuzu Stack — Generated by Yuzu Compose Wizard
##
## Customised for your deployment. Edit .env for quick reconfiguration.
##
## Usage:
##   docker compose up -d
##   docker compose logs -f
##   docker compose down -v    # ⚠️ -v removes data volumes!
##
${tls ? `## ⚠️ REQUIRES SECURE-BY-DEFAULT IMAGES. This TLS config relies on the server
##    auto-generating a per-install CA + leaf certs on first boot and serving HTTPS
##    on 8443 — behaviour from the secure-by-default release (v0.13.0+, tracked by
##    the 'latest' tag). Older images (incl. 0.12.0) don't support it; use Plaintext
##    mode there. (Plaintext works on any image.)
##
` : ``}## Dashboard:   ${webScheme}://localhost:${c.dashboardPort}  (${c.adminUser} / <your-password>)
${c.grafana ? `## Grafana:     http://localhost:${c.grafanaPort}  (admin / ${c.grafanaPass})` : ''}
${c.prometheus ? `## Prometheus:  http://localhost:${c.promPort}` : ''}
${c.clickhouse ? `## ClickHouse:  http://localhost:${c.chHttpPort}  (${c.chUser} / ${c.chPass})` : ''}
##
## Connect an agent:
${c.tlsMode === 'plaintext'
  ? `##   yuzu-agent --server localhost:${c.gateway ? c.gwAgentPort : c.grpcPort} --no-tls`
  : `##   # TLS is on. Give the agent the server's CA so it can verify the cert:
##   #   curl -sk ${webScheme}://localhost:${c.dashboardPort}/api/v1/ca/root -o ca.pem
##   yuzu-agent --server localhost:${c.gateway ? c.gwAgentPort : c.grpcPort} --ca-cert ca.pem`}
##   (approve the agent in Settings, then restart the agent)
##

`;

  // ── Configs ──
  y += `configs:\n`;
  y += `  # ── Server RBAC config ──\n`;
  y += `  # NOTE: RBAC is enabled but may not enforce in all Yuzu versions.\n`;
  y += `  # See: https://github.com/DevNullLtd/Yuzu/issues/388\n`;
  y += `  server-cfg:\n`;
  y += `    content: |\n`;
  y += `      # ${c.adminUser} / <the password you entered> — PBKDF2-HMAC-SHA256, 100k iters.\n`;
  y += `      # Regenerate with: yuzu-server hash-password ${c.adminUser} <password>\n`;
  y += `      ${c.authLine}\n`;
  y += `      \n`;
  y += `      [rbac]\n`;
  y += `      enabled = true\n`;

  if (c.gateway) {
    y += `\n  # ── Gateway (Erlang/OTP) sys.config ──\n`;
    y += `  gateway-sys-config:\n`;
    y += `    content: |\n`;
    y += `      [\n`;
    y += `          {yuzu_gw, [\n`;
    y += `              {agent_listen_addr, "0.0.0.0"},\n`;
    y += `              {agent_listen_port, 50051},\n`;
    y += `              {mgmt_listen_addr, "0.0.0.0"},\n`;
    y += `              {mgmt_listen_port, 50063},\n`;
    y += `              {upstream_addr, "server"},\n`;
    y += `              {upstream_port, ${c.gwUpstreamPort}},\n`;
    y += `              {upstream_pool_size, ${c.gwPoolSize}},\n`;
    y += `              {heartbeat_batch_interval_ms, 1000},\n`;
    y += `              {default_command_timeout_s, 300},\n`;
    y += `              {prometheus_port, 9568},\n`;
    y += `              {health_port, 8081},\n`;
    y += `              {telemetry_gauge_interval_ms, 10000},\n`;
    y += `              {circuit_breaker_failure_threshold, 5},\n`;
    y += `              {circuit_breaker_reset_timeout_ms, 10000},\n`;
    y += `              {circuit_breaker_max_reset_timeout_ms, 300000},\n`;
    y += `              {backpressure_threshold, 1000},\n`;
    y += `              {hash_ring_vnodes, 256},\n`;
    y += `              %% #1422 escape hatch: this generated stack's mgmt listener is\n`;
    y += `              %% plaintext on 0.0.0.0 and the gateway otherwise refuses to\n`;
    y += `              %% boot. Safe only while :50063 stays unpublished on this\n`;
    y += `              %% compose network. Never copy into production.\n`;
    y += `              {allow_insecure_mgmt, true}\n`;
    y += `          ]},\n`;
    // Plaintext gateway: gateway + TLS isn't generated yet (see the C1/N2 guard),
    // so this path is only reached in plaintext mode — the gateway dials the server
    // over plain HTTP/2 and its listeners are plaintext.
    // ⚠️ Do NOT internet-expose :50051 in this mode (command fan-out = fleet RCE).
    y += `          {grpcbox, [\n`;
    y += `              {client, #{channels => [\n`;
    y += `                  {default_channel, [{http, "server", ${c.gwUpstreamPort}, []}], #{}}\n`;
    y += `              ]}},\n`;
    y += `              {servers, [\n`;
    y += `                  #{grpc_opts => #{\n`;
    y += `                      service_protos => [agent_pb],\n`;
    y += `                      services => #{'yuzu.agent.v1.AgentService' => yuzu_gw_agent_service}\n`;
    y += `                  },\n`;
    y += `                  listen_opts => #{port => 50051, ip => {0,0,0,0}}},\n`;
    y += `                  #{grpc_opts => #{\n`;
    y += `                      service_protos => [management_pb],\n`;
    y += `                      services => #{'yuzu.server.v1.ManagementService' => yuzu_gw_mgmt_service}\n`;
    y += `                  },\n`;
    y += `                  listen_opts => #{port => 50063, ip => {0,0,0,0}}}\n`;
    y += `              ]}\n`;
    y += `          ]},\n`;
    y += `          {kernel, [\n`;
    y += `              {connect_all, false},\n`;
    y += `              {net_ticktime, 30},\n`;
    y += `              {logger_level, info},\n`;
    y += `              {logger, [\n`;
    y += `                  {handler, default, logger_std_h, #{\n`;
    y += `                      level => info,\n`;
    y += `                      formatter => {logger_formatter, #{\n`;
    y += `                          template => [time, " [", level, "] ", pid, " ", msg, "\\n"]\n`;
    y += `                      }}\n`;
    y += `                  }}\n`;
    y += `              ]}\n`;
    y += `          ]}\n`;
    y += `      ].\n`;
  }

  if (c.prometheus) {
    y += `\n  # ── Prometheus config ──\n`;
    y += `  prometheus-config:\n`;
    y += `    content: |\n`;
    y += `      global:\n`;
    y += `        scrape_interval: 15s\n`;
    y += `        evaluation_interval: 15s\n`;
    y += `      scrape_configs:\n`;
    y += `        - job_name: 'yuzu-server'\n`;
    y += `          metrics_path: '/metrics'\n`;
    if (tls) {
      // TLS modes: the server serves /metrics over HTTPS on 8443 (8080 just
      // redirects). Scrape https and skip verification (internal default CA).
      y += `          scheme: https\n`;
      y += `          tls_config:\n`;
      y += `            insecure_skip_verify: true\n`;
    }
    y += `          static_configs:\n`;
    y += `            - targets: ['server:${webContainerPort}']\n`;
    y += `              labels:\n`;
    y += `                component: 'server'\n`;
    if (c.gateway) {
      y += `        - job_name: 'yuzu-gateway'\n`;
      y += `          metrics_path: '/metrics'\n`;
      y += `          static_configs:\n`;
      y += `            - targets: ['gateway:9568']\n`;
      y += `              labels:\n`;
      y += `                component: 'gateway'\n`;
    }
  }

  if (c.grafana) {
    y += `\n  # ── Grafana provisioning ──\n`;
    y += `  grafana-datasource:\n`;
    y += `    content: |\n`;
    y += `      apiVersion: 1\n`;
    y += `      datasources:\n`;
    y += `        - name: Prometheus\n`;
    y += `          type: prometheus\n`;
    y += `          access: proxy\n`;
    y += `          url: http://prometheus:9090\n`;
    y += `          isDefault: true\n`;
    y += `          editable: false\n`;
    y += `  grafana-dashboard-provider:\n`;
    y += `    content: |\n`;
    y += `      apiVersion: 1\n`;
    y += `      providers:\n`;
    y += `        - name: Yuzu\n`;
    y += `          orgId: 1\n`;
    y += `          folder: Yuzu\n`;
    y += `          type: file\n`;
    y += `          disableDeletion: false\n`;
    y += `          editable: true\n`;
    y += `          options:\n`;
    y += `            path: /var/lib/grafana/dashboards\n`;
    y += `            foldersFromFilesStructure: false\n`;
    y += `  # Dashboard JSON files — requires deploy/grafana/ in your Yuzu checkout\n`;
    y += `  grafana-dashboard-main:\n`;
    y += `    file: deploy/grafana/yuzu-dashboard.json\n`;
    y += `  grafana-dashboard-fleet:\n`;
    y += `    file: deploy/grafana/yuzu-fleet-dashboard.json\n`;
    y += `  grafana-dashboard-gateway:\n`;
    y += `    file: deploy/grafana/yuzu-gateway-dashboard.json\n`;
    y += `  grafana-dashboard-analytics:\n`;
    y += `    file: deploy/grafana/yuzu-analytics-dashboard.json\n`;
  }

  if (c.clickhouse) {
    y += `\n  # ── ClickHouse init SQL ──\n`;
    y += `  clickhouse-init:\n`;
    y += `    content: |\n`;
    y += `      CREATE DATABASE IF NOT EXISTS ${c.chDb};\n`;
    y += `      CREATE TABLE IF NOT EXISTS ${c.chDb}.yuzu_events (\n`;
    y += `          tenant_id       LowCardinality(String)  DEFAULT 'default',\n`;
    y += `          agent_id        String                  DEFAULT '',\n`;
    y += `          session_id      String                  DEFAULT '',\n`;
    y += `          event_type      LowCardinality(String),\n`;
    y += `          event_time      DateTime64(3, 'UTC'),\n`;
    y += `          ingest_time     DateTime64(3, 'UTC')    DEFAULT now64(3),\n`;
    y += `          plugin          LowCardinality(String)  DEFAULT '',\n`;
    y += `          capability      LowCardinality(String)  DEFAULT '',\n`;
    y += `          correlation_id  String                  DEFAULT '',\n`;
    y += `          severity        Enum8('debug'=0,'info'=1,'warn'=2,'error'=3,'critical'=4) DEFAULT 'info',\n`;
    y += `          source          LowCardinality(String)  DEFAULT 'server',\n`;
    y += `          hostname        String                  DEFAULT '',\n`;
    y += `          os              LowCardinality(String)  DEFAULT '',\n`;
    y += `          arch            LowCardinality(String)  DEFAULT '',\n`;
    y += `          agent_version   LowCardinality(String)  DEFAULT '',\n`;
    y += `          principal       String                  DEFAULT '',\n`;
    y += `          principal_role  LowCardinality(String)  DEFAULT '',\n`;
    y += `          attributes      String                  DEFAULT '{}',\n`;
    y += `          payload         String                  DEFAULT '{}',\n`;
    y += `          schema_version  UInt8                   DEFAULT 1\n`;
    y += `      ) ENGINE = MergeTree()\n`;
    y += `        PARTITION BY toYYYYMM(event_time)\n`;
    y += `        ORDER BY (tenant_id, event_type, event_time, agent_id)\n`;
    y += `        TTL toDate(event_time) + INTERVAL 365 DAY;\n`;
    y += `      ALTER TABLE ${c.chDb}.yuzu_events ADD INDEX IF NOT EXISTS idx_agent_id agent_id TYPE bloom_filter GRANULARITY 4;\n`;
    y += `      ALTER TABLE ${c.chDb}.yuzu_events ADD INDEX IF NOT EXISTS idx_correlation_id correlation_id TYPE bloom_filter GRANULARITY 4;\n`;
    y += `      ALTER TABLE ${c.chDb}.yuzu_events ADD INDEX IF NOT EXISTS idx_hostname hostname TYPE bloom_filter GRANULARITY 4;\n`;
    y += `      CREATE MATERIALIZED VIEW IF NOT EXISTS ${c.chDb}.mv_command_duration_hourly\n`;
    y += `      ENGINE = AggregatingMergeTree()\n`;
    y += `      PARTITION BY toYYYYMM(hour)\n`;
    y += `      ORDER BY (tenant_id, plugin, hour)\n`;
    y += `      AS SELECT\n`;
    y += `          tenant_id, plugin,\n`;
    y += `          toStartOfHour(event_time) AS hour,\n`;
    y += `          quantileState(0.5)(JSONExtractFloat(payload, 'duration_ms'))  AS p50,\n`;
    y += `          quantileState(0.95)(JSONExtractFloat(payload, 'duration_ms')) AS p95,\n`;
    y += `          quantileState(0.99)(JSONExtractFloat(payload, 'duration_ms')) AS p99,\n`;
    y += `          countState() AS total\n`;
    y += `      FROM ${c.chDb}.yuzu_events\n`;
    y += `      WHERE event_type = 'command.completed'\n`;
    y += `      GROUP BY tenant_id, plugin, hour;\n`;
    y += `      CREATE MATERIALIZED VIEW IF NOT EXISTS ${c.chDb}.mv_agent_activity_daily\n`;
    y += `      ENGINE = SummingMergeTree()\n`;
    y += `      PARTITION BY toYYYYMM(day)\n`;
    y += `      ORDER BY (tenant_id, agent_id, day, event_type)\n`;
    y += `      AS SELECT\n`;
    y += `          tenant_id, agent_id,\n`;
    y += `          toDate(event_time) AS day,\n`;
    y += `          event_type,\n`;
    y += `          count() AS event_count\n`;
    y += `      FROM ${c.chDb}.yuzu_events\n`;
    y += `      GROUP BY tenant_id, agent_id, day, event_type;\n`;
  }

  // ── Services ──
  y += `\nservices:\n`;

  // Yuzu Server
  y += `  # ── Yuzu Server ──────────────────────────────────────────────────────\n`;
  y += `  server:\n`;
  y += `    image: ghcr.io/devnullltd/yuzu-server:\${YUZU_VERSION:-${c.version}}\n`;
  y += `    container_name: yuzu-server\n`;
  y += `    restart: unless-stopped\n`;
  y += `    ports:\n`;
  y += `      - "${c.dashboardPort}:${webContainerPort}"     # Web dashboard + REST API (${webScheme.toUpperCase()})\n`;
  y += `      - "${c.grpcPort}:50051"   # Agent gRPC (direct-connect agents)\n`;
  y += `      - "${c.mgmtPort}:50052"   # Management gRPC\n`;
  y += `      - "${c.gwUpstreamPort}:${c.gwUpstreamPort}"   # Gateway upstream\n`;
  y += `    environment:\n`;
  y += `      - YUZU_LOG_LEVEL=info\n`;
  y += `      - YUZU_LOG_FORMAT=json\n`;
  // Postgres substrate DSN (ADR-0006/0008). Consumed via env var, NOT a CLI
  // flag — the server reads YUZU_POSTGRES_DSN from the environment. The DSN
  // carries the APP role password (interpolated from .env), never the
  // superuser's, so a leaked server environment can't disclose superuser creds.
  if (c.pgBundled) {
    y += `      # Postgres substrate DSN (ADR-0006/0008). App-role password comes\n`;
    y += `      # from .env (YUZU_DB_PASSWORD) — never baked into this file.\n`;
    y += `      - YUZU_POSTGRES_DSN=postgresql://yuzu:\${YUZU_DB_PASSWORD}@postgres:5432/yuzu\n`;
  } else {
    y += `      # External/managed Postgres — full DSN supplied via .env.\n`;
    y += `      - YUZU_POSTGRES_DSN=\${YUZU_POSTGRES_DSN}\n`;
  }
  y += `    command:\n`;
  y += `      - "--listen"\n`;
  y += `      - "0.0.0.0:50051"\n`;
  if (c.tlsMode === 'plaintext') {
    // Insecure dev mode — overrides secure-by-default. Do NOT expose :50051.
    y += `      - "--no-tls"\n`;
    y += `      - "--no-https"\n`;
  } else if (c.tlsMode === 'operator') {
    // Operator-supplied PEM material, bind-mounted read-only below.
    y += `      - "--cert"\n`;
    y += `      - "${c.tlsCert}"\n`;
    y += `      - "--key"\n`;
    y += `      - "${c.tlsKey}"\n`;
    if (c.tlsCaCert) {
      y += `      - "--ca-cert"\n`;
      y += `      - "${c.tlsCaCert}"\n`;
    }
  } else {
    // Default mode: emit NO --cert/--key/--no-tls. The server auto-generates a
    // per-install CA + leaf certs on first boot (encrypted-by-default). Extra
    // SANs make those leaves validate for the names agents actually dial.
    const sans = effectiveCertSans(c);
    if (sans.length) {
      y += `      # Auto-generated default certs get these extra SANs so agents can\n`;
      y += `      # validate the gateway/server hostname (see PKI default-certs).\n`;
      for (const s of sans) {
        y += `      - "--cert-san"\n`;
        y += `      - "${s}"\n`;
      }
    }
  }
  y += `      - "--web-address"\n`;
  y += `      - "0.0.0.0"\n`;
  if (tls) {
    // TLS modes: dashboard/API is HTTPS on 8443 (8080 stays an auto HTTP→HTTPS
    // redirect). #1484.
    y += `      - "--https-port"\n`;
    y += `      - "8443"\n`;
  } else {
    y += `      - "--web-port"\n`;
    y += `      - "8080"\n`;
  }
  y += `      - "--config"\n`;
  y += `      - "/etc/yuzu/yuzu-server.cfg"\n`;
  y += `      - "--data-dir"\n`;
  y += `      - "${c.dataDir}"\n`;
  y += `      # ⚠️ --data-dir is REQUIRED. Without it, SQLite stores fail silently.\n`;
  if (c.gateway) {
    y += `      - "--gateway-upstream"\n`;
    y += `      - "0.0.0.0:${c.gwUpstreamPort}"\n`;
    y += `      - "--gateway-mode"\n`;
    y += `      - "--gateway-command-addr"\n`;
    y += `      - "gateway:50063"\n`;
  }
  y += `      - "--metrics-no-auth"\n`;
  if (c.clickhouse) {
    y += `      - "--clickhouse-url"\n`;
    y += `      - "http://clickhouse:8123"\n`;
    y += `      - "--clickhouse-database"\n`;
    y += `      - "${c.chDb}"\n`;
    y += `      - "--clickhouse-table"\n`;
    y += `      - "yuzu_events"\n`;
    y += `      - "--clickhouse-user"\n`;
    y += `      - "${c.chUser}"\n`;
    y += `      - "--clickhouse-password"\n`;
    y += `      - "${c.chPass}"\n`;
  }
  y += `    configs:\n`;
  y += `      - source: server-cfg\n`;
  y += `        target: /etc/yuzu/yuzu-server.cfg\n`;
  y += `    volumes:\n`;
  if (c.persistentVolumes) {
    y += `      - server-data:${c.dataDir}\n`;
  } else {
    y += `      - ${c.dataDir}\n`;
  }
  // Cert directory (/etc/yuzu/certs = auth::default_cert_dir()). It holds the
  // secrets KEK (registered in Postgres) and, in default mode, the auto-generated
  // CA, so in every non-operator mode it MUST persist across recreates: losing it
  // leaves a server that refuses to boot (kek_unresolvable, #5370). With named
  // volumes off it is an anonymous volume, ephemeral exactly like postgres-data
  // in that mode. In operator mode bind-mount the host PEM material read-only
  // (that mount cannot hold the KEK — tracked in #5420).
  if (c.tlsMode !== 'operator') {
    if (certVolNamed) {
      y += `      - server-certs:/etc/yuzu/certs\n`;
    } else {
      y += `      - /etc/yuzu/certs\n`;
    }
  } else {
    y += `      # Put server.pem / server.key (and ca.pem for mTLS) in ./certs.\n`;
    y += `      - ./certs:/etc/yuzu/certs:ro\n`;
  }
  y += `    healthcheck:\n`;
  // #1487: the server image ships bash but NOT curl, so probe the listening port
  // with a bash /dev/tcp TCP connect (matches docker-compose.uat.yml). Targets the
  // real serving port: 8443 in TLS modes, 8080 in plaintext (#1484). A TCP-connect
  // check avoids speaking HTTP to the wrong scheme.
  y += `      test: ["CMD", "bash", "-c", "exec 3<>/dev/tcp/127.0.0.1/${webContainerPort}"]\n`;
  y += `      interval: 10s\n`;
  y += `      timeout: 3s\n`;
  y += `      retries: 30\n`;
  y += `      start_period: 10s\n`;
  // Gate server start on Postgres (bundled mode) and ClickHouse readiness so
  // migrations don't race an unready substrate.
  if (c.pgBundled || c.clickhouse) {
    y += `    depends_on:\n`;
    if (c.pgBundled) {
      y += `      postgres:\n`;
      y += `        condition: service_healthy\n`;
    }
    if (c.clickhouse) {
      y += `      clickhouse:\n`;
      y += `        condition: service_healthy\n`;
    }
  }

  // PostgreSQL (server storage substrate) — bundled mode only. In external
  // mode the server's YUZU_POSTGRES_DSN points at a managed instance and no
  // local container is generated.
  if (c.pgBundled) {
    y += `\n  # ── PostgreSQL (server storage substrate, ADR-0006/0008) ─────────────\n`;
    y += `  # Release-pinned yuzu-postgres image: PostgreSQL 18 + pgvector + a\n`;
    y += `  # first-boot init that creates the app role/database. Per-store schemas\n`;
    y += `  # are created at runtime by the server's migration runner. Using an\n`;
    y += `  # external/managed Postgres instead is first-class — re-run the wizard\n`;
    y += `  # and pick "External / managed".\n`;
    y += `  postgres:\n`;
    y += `    image: ghcr.io/devnullltd/yuzu-postgres:\${YUZU_VERSION:-${c.version}}\n`;
    y += `    container_name: yuzu-postgres\n`;
    y += `    restart: unless-stopped\n`;
    y += `    environment:\n`;
    y += `      # Both passwords come from .env — the actual secrets never appear\n`;
    y += `      # in this compose file. They MUST be distinct (first-boot init\n`;
    y += `      # refuses to run otherwise); the superuser password stays inside\n`;
    y += `      # this container and is never carried by the server DSN.\n`;
    y += `      - POSTGRES_PASSWORD=\${YUZU_POSTGRES_PASSWORD}\n`;
    y += `      - YUZU_DB_PASSWORD=\${YUZU_DB_PASSWORD}\n`;
    y += `    volumes:\n`;
    // PG18 mount point is the PARENT /var/lib/postgresql, NOT .../data. The
    // postgres:18 image keeps data in a version-pinned subdir
    // ($PGDATA=/var/lib/postgresql/18/docker) and reads a volume at the legacy
    // /data path as an un-migrated upgrade — the container refuses to boot
    // (docker-library/postgres#1259). Leave PGDATA at the image default.
    y += `      # PG18 stores data under \$PGDATA=/var/lib/postgresql/18/docker; mount\n`;
    y += `      # the volume at the PARENT, not the legacy .../data path (which the\n`;
    y += `      # postgres:18 entrypoint refuses to boot from). docker-library/postgres#1259.\n`;
    if (c.persistentVolumes) {
      y += `      - postgres-data:/var/lib/postgresql\n`;
    } else {
      y += `      - /var/lib/postgresql\n`;
    }
    y += `    healthcheck:\n`;
    // -h 127.0.0.1 forces a TCP probe (initdb's temporary server is socket-only
    // mid-init); the psql leg dials the container hostname (not loopback, which
    // initdb leaves on 'trust') so it actually verifies the app credential.
    // $$ defers expansion to the container shell so the password never appears
    // in `docker compose config` output.
    y += `      test: ["CMD-SHELL", "pg_isready -h 127.0.0.1 -U yuzu -d yuzu && psql \\"postgresql://yuzu:$\${YUZU_DB_PASSWORD}@$$(hostname):5432/yuzu\\" -tA -c 'SELECT 1' >/dev/null"]\n`;
    y += `      interval: 5s\n`;
    y += `      timeout: 5s\n`;
    y += `      retries: 12\n`;
    y += `      start_period: 10s\n`;
  }

  // Gateway
  if (c.gateway) {
    y += `\n  # ── Yuzu Gateway (Erlang/OTP) ────────────────────────────────────────\n`;
    y += `  gateway:\n`;
    y += `    image: ghcr.io/devnullltd/yuzu-gateway:\${YUZU_VERSION:-${c.version}}\n`;
    y += `    container_name: yuzu-gateway\n`;
    y += `    restart: unless-stopped\n`;
    y += `    ports:\n`;
    y += `      - "${c.gwAgentPort}:50051"   # Agent-facing gRPC (mapped to avoid conflict with server)\n`;
    // #1422: NEVER publish :50063 (management/command fan-out) from this
    // generator — the wizard's gateway is plaintext (no TLS mode generated
    // yet), so its mgmt plane is unauthenticated and must stay reachable only
    // on the compose network (the server dials gateway:50063 internally).
    y += `      # :50063 (management/command fan-out) is deliberately NOT published:\n`;
    y += `      # this gateway's mgmt plane is plaintext+unauthenticated, safe only\n`;
    y += `      # inside the compose network. See #1422.\n`;
    y += `      - "${c.gwHealthPort}:8081"     # Health/readiness\n`;
    y += `      - "${c.gwMetricsPort}:9568"     # Prometheus metrics\n`;
    y += `    environment:\n`;
    // #1483: a real distribution cookie from .env (the gateway fail-closes on the
    // insecure default). YUZU_GW_TLS_ENABLED is advisory only (#1291); the gateway
    // here is plaintext (gateway + TLS isn't generated — see the C1/N2 guard).
    y += `      - YUZU_GW_COOKIE=\${YUZU_GW_COOKIE}\n`;
    y += `      - YUZU_GW_TLS_ENABLED=false\n`;
    y += `    configs:\n`;
    y += `      - source: gateway-sys-config\n`;
    y += `        target: /opt/yuzu_gw/releases/0.2.0/sys.config\n`;
    // #1486: probe /healthz with busybox wget (the gateway image ships busybox,
    // which provides `wget --spider`; it has NO bash/curl, so the old
    // `echo > /dev/tcp` CMD-SHELL probe always failed). Matches docker-compose.uat.yml.
    y += `    healthcheck:\n`;
    y += `      test: ["CMD", "wget", "--spider", "-q", "http://localhost:8081/healthz"]\n`;
    y += `      interval: 10s\n`;
    y += `      timeout: 5s\n`;
    y += `      retries: 5\n`;
    y += `      start_period: 10s\n`;
    // Gate the gateway on the server being healthy so its upstream is reachable.
    y += `    depends_on:\n`;
    y += `      server:\n`;
    y += `        condition: service_healthy\n`;
  }

  // Prometheus
  if (c.prometheus) {
    y += `\n  # ── Prometheus ───────────────────────────────────────────────────────\n`;
    y += `  prometheus:\n`;
    y += `    image: prom/prometheus:latest\n`;
    y += `    container_name: yuzu-prometheus\n`;
    y += `    restart: unless-stopped\n`;
    y += `    ports:\n`;
    y += `      - "${c.promPort}:9090"\n`;
    y += `    configs:\n`;
    y += `      - source: prometheus-config\n`;
    y += `        target: /etc/prometheus/prometheus.yml\n`;
    y += `    volumes:\n`;
    // M1: only a NAMED volume when named volumes are enabled; otherwise anonymous,
    // so the top-level volumes: block (which only declares names) stays consistent.
    y += c.persistentVolumes ? `      - prometheus-data:/prometheus\n` : `      - /prometheus\n`;
    y += `    depends_on:\n`;
    y += `      - server\n`;
    if (c.gateway) y += `      - gateway\n`;
  }

  // Grafana
  if (c.grafana) {
    y += `\n  # ── Grafana ──────────────────────────────────────────────────────────\n`;
    y += `  grafana:\n`;
    y += `    image: grafana/grafana:latest\n`;
    y += `    container_name: yuzu-grafana\n`;
    y += `    restart: unless-stopped\n`;
    y += `    ports:\n`;
    y += `      - "${c.grafanaPort}:3000"\n`;
    y += `    environment:\n`;
    y += `      - GF_SECURITY_ADMIN_PASSWORD=${c.grafanaPass}\n`;
    y += `    configs:\n`;
    y += `      - source: grafana-datasource\n`;
    y += `        target: /etc/grafana/provisioning/datasources/prometheus.yml\n`;
    y += `      - source: grafana-dashboard-provider\n`;
    y += `        target: /etc/grafana/provisioning/dashboards/yuzu.yml\n`;
    y += `      - source: grafana-dashboard-main\n`;
    y += `        target: /var/lib/grafana/dashboards/yuzu-dashboard.json\n`;
    y += `      - source: grafana-dashboard-fleet\n`;
    y += `        target: /var/lib/grafana/dashboards/yuzu-fleet-dashboard.json\n`;
    y += `      - source: grafana-dashboard-gateway\n`;
    y += `        target: /var/lib/grafana/dashboards/yuzu-gateway-dashboard.json\n`;
    y += `      - source: grafana-dashboard-analytics\n`;
    y += `        target: /var/lib/grafana/dashboards/yuzu-analytics-dashboard.json\n`;
    y += `    volumes:\n`;
    y += c.persistentVolumes ? `      - grafana-data:/var/lib/grafana\n` : `      - /var/lib/grafana\n`;
    y += `    depends_on:\n`;
    y += `      - prometheus\n`;
  }

  // ClickHouse
  if (c.clickhouse) {
    y += `\n  # ── ClickHouse ───────────────────────────────────────────────────────\n`;
    y += `  clickhouse:\n`;
    y += `    image: clickhouse/clickhouse-server:latest\n`;
    y += `    container_name: yuzu-clickhouse\n`;
    y += `    restart: unless-stopped\n`;
    y += `    ports:\n`;
    y += `      - "${c.chHttpPort}:8123"     # HTTP interface\n`;
    y += `      - "${c.chNativePort}:9000"     # Native protocol\n`;
    y += `    environment:\n`;
    y += `      - CLICKHOUSE_DB=${c.chDb}\n`;
    y += `      - CLICKHOUSE_USER=${c.chUser}\n`;
    y += `      - CLICKHOUSE_PASSWORD=${c.chPass}\n`;
    y += `    configs:\n`;
    y += `      - source: clickhouse-init\n`;
    y += `        target: /docker-entrypoint-initdb.d/init.sql\n`;
    y += `    volumes:\n`;
    y += c.persistentVolumes ? `      - clickhouse-data:/var/lib/clickhouse\n` : `      - /var/lib/clickhouse\n`;
    y += `    ulimits:\n`;
    y += `      nofile:\n`;
    y += `        soft: 262144\n`;
    y += `        hard: 262144\n`;
    y += `    healthcheck:\n`;
    y += `      test: ["CMD", "clickhouse-client", "--password", "${c.chPass}", "-q", "SELECT 1"]\n`;
    y += `      interval: 10s\n`;
    y += `      timeout: 5s\n`;
    y += `      retries: 5\n`;
  }

  // Volumes — only named volumes are declared here; services use anonymous volumes
  // when named volumes are off (M1), so every name referenced above is declared.
  if (c.persistentVolumes) {
    y += `\nvolumes:\n`;
    y += `  server-data:\n`;
    if (certVolNamed) y += `  server-certs:\n`;
    if (c.persistentVolumes && c.pgBundled) y += `  postgres-data:\n`;
    if (c.persistentVolumes && c.prometheus) y += `  prometheus-data:\n`;
    if (c.persistentVolumes && c.grafana) y += `  grafana-data:\n`;
    if (c.persistentVolumes && c.clickhouse) y += `  clickhouse-data:\n`;
  }

  return y;
}