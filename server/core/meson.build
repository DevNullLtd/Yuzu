# Platform-specific crypto for auth module
# Windows: bcrypt.lib + winhttp.lib linked via #pragma comment(lib) in source
if host_machine.system() == 'windows'
  auth_crypto_deps = []
else
  openssl_dep = dependency('openssl', required: true, include_type: 'system')
  auth_crypto_deps = [openssl_dep]
endif

# OpenSSL for HTTPS (cpp-httplib SSLServer support)
# On Linux/macOS, openssl_dep is already declared above.
# On Windows, OpenSSL is available transitively via gRPC/vcpkg.
if host_machine.system() == 'windows'
  openssl_dep = dependency('openssl', method: 'cmake', modules: ['OpenSSL::SSL', 'OpenSSL::Crypto'], required: false, include_type: 'system')
  if not openssl_dep.found()
    # Fallback: try pkg-config or find_library
    _ssl_lib = cxx.find_library('libssl', required: false)
    _crypto_lib = cxx.find_library('libcrypto', required: false)
    if _ssl_lib.found() and _crypto_lib.found()
      openssl_dep = declare_dependency(dependencies: [_ssl_lib, _crypto_lib])
    else
      openssl_dep = disabler()
    endif
  endif
endif

# #3109: file_retrieval_routes.cpp's admit_to_write_lock() switches over the
# 5-value SessionAuthOutcome with no `default:`, relying on the compiler to
# fail the build if the enum ever grows without that switch being updated.
# Promote -Wswitch (MSVC: C4062, the exact analogue) to an error so that
# guarantee is actually enforced rather than merely warned about.
switch_werror_args = cxx.get_id() == 'msvc' ? ['/we4062'] : ['-Werror=switch']

https_cpp_args = []
https_deps = []
if not is_disabler(openssl_dep) and openssl_dep.found()
  https_cpp_args = ['-DCPPHTTPLIB_OPENSSL_SUPPORT']
  https_deps = [openssl_dep]
endif

sqlite3_dep = dependency('sqlite3', required: false, include_type: 'system')
if not sqlite3_dep.found()
  sqlite3_dep = dependency('unofficial-sqlite3', method: 'cmake', modules: ['unofficial::sqlite3::sqlite3'], required: false, include_type: 'system')
endif
if not sqlite3_dep.found()
  sqlite3_dep = cxx.find_library('sqlite3')
endif
nlohmann_json_dep = dependency('nlohmann_json', required: true, include_type: 'system')

# RE2 for linear-time regex (replaces std::regex to prevent ReDoS)
re2_dep = dependency('re2', method: 'cmake', modules: ['re2::re2'], required: false, include_type: 'system')
if not re2_dep.found()
  re2_dep = dependency('re2', required: false, include_type: 'system')
endif
if not re2_dep.found()
  re2_dep = cxx.find_library('re2')
endif

# SAML 2.0 SP — libxml2 (XML parser), xmlsec with the openssl backend
# (XML-DSig enveloped signature verification), and zlib (HTTP-Redirect binding
# DEFLATE decompression). Linux/macOS only; SAML is deferred on Windows and
# the server fails closed (saml_deps is an empty list on Windows so no symbols
# from these libraries are required at link time). A future saml_provider.cpp
# must guard its platform-specific #include blocks with #if !defined(_WIN32).
# Do NOT add Windows wiring here — the grpc/abseil/libpq Windows static-link
# block in the root meson.build is load-bearing and must not be disturbed
# (see CLAUDE.md "Windows grpc/protobuf/abseil is load-bearing").
if host_machine.system() != 'windows'
  # libxml2_dep itself is declared once, unconditionally, at root scope
  # (see meson.build's own comment on that declaration) -- reuse it here
  # rather than re-declaring the same dependency under the same variable
  # name. Meson has no subdir()-local scoping (one flat variable
  # namespace across every subdir() call), so a second declaration here
  # would not "shadow" anything -- it would just deterministically
  # overwrite the root value, order notwithstanding. Two declarations of
  # the same dependency under the same name is simply redundant and a
  # future-drift risk (e.g. if one copy's method/fallback ever changes
  # without the other), not a shadowing hazard.
  xmlsec_dep = dependency('unofficial-xmlsec', method: 'cmake',
    modules: ['unofficial::xmlsec::xmlsec1-openssl'],
    required: false, include_type: 'system')
  if not xmlsec_dep.found()
    xmlsec_dep = dependency('xmlsec1-openssl', required: true, include_type: 'system')
  endif

  zlib_dep = dependency('ZLIB', method: 'cmake', modules: ['ZLIB::ZLIB'],
    required: false, include_type: 'system')
  if not zlib_dep.found()
    zlib_dep = dependency('zlib', required: true, include_type: 'system')
  endif

  saml_deps = [libxml2_dep, xmlsec_dep, zlib_dep]
else
  saml_deps = []
endif

# Build-time embed of vendored ECharts into a generated .cpp containing
# chunked raw string literals (sliced to fit MSVC's 16,380-byte limit on
# raw string literals — error C2026). Symbol: kEChartsJs.
echarts_embed = custom_target(
  'echarts_js_bundle',
  input: 'vendor/echarts.min.js',
  output: 'echarts_js_bundle.cpp',
  command: [
    find_program('python3', 'python'),
    files('scripts/embed_js.py'),
    '@INPUT@',
    '@OUTPUT@',
    'EChartsJs',
  ],
)

# Build-time embed of vendored Three.js r168 + OrbitControls (PR 4 of
# feat/viz-engine ladder). Same chunked-raw-string pattern as ECharts;
# fragment loader in PR 5 wires `<script type="importmap">` so the
# OrbitControls module's `import ... from 'three'` resolves to the
# vendored file. We ship the ES-module form rather than UMD because
# Three.js dropped UMD in r150+ -- modern releases only publish
# `three.module.min.js`. Symbols: kThreeJs (~685 KB), kThreeOrbitControlsJs (~32 KB).
three_embed = custom_target(
  'three_js_bundle',
  input: 'vendor/three.module.min.js',
  output: 'three_js_bundle.cpp',
  command: [
    find_program('python3', 'python'),
    files('scripts/embed_js.py'),
    '@INPUT@',
    '@OUTPUT@',
    'ThreeJs',
  ],
)

three_orbit_embed = custom_target(
  'three_orbit_controls_js_bundle',
  input: 'vendor/three-orbit-controls.js',
  output: 'three_orbit_controls_js_bundle.cpp',
  command: [
    find_program('python3', 'python'),
    files('scripts/embed_js.py'),
    '@INPUT@',
    '@OUTPUT@',
    'ThreeOrbitControlsJs',
  ],
)

# Build-time embed of the Yuzu fleet-viz renderer module (PR 5 + PR 6 of
# feat/viz-engine ladder). Hand-written before PR 6 (~10 KB) when it fit
# under MSVC's 16,380-byte raw-string-literal limit; PR 6 took the bundle
# past that limit, so we now codegen via embed_js.py like ECharts and
# Three.js. Symbol: kYuzuVizJs (std::string).
yuzu_viz_js_embed = custom_target(
  'yuzu_viz_js_bundle',
  input: 'static/yuzu-viz.js',
  output: 'yuzu_viz_js_bundle.cpp',
  command: [
    find_program('python3', 'python'),
    files('scripts/embed_js.py'),
    '@INPUT@',
    '@OUTPUT@',
    'YuzuVizJs',
  ],
)

# PR 9-pre: per-host renderer module + vendored Cytoscape.js 3.33.3 (MIT).
# Cytoscape ships as ESM minified (cytoscape.esm.min.mjs from the npm
# tarball) so the importmap entry in viz_host_page_ui.cpp can resolve
# `import cytoscape from "cytoscape"`. The renderer uses cytoscape's
# built-in `cose` force-directed layout — no layout extension is vendored
# (the faster `fcose` is a UMD bundle with an external cose-base
# dependency that doesn't resolve cleanly against an ESM importmap).
yuzu_viz_host_js_embed = custom_target(
  'yuzu_viz_host_js_bundle',
  input: 'static/yuzu-viz-host.js',
  output: 'yuzu_viz_host_js_bundle.cpp',
  command: [
    find_program('python3', 'python'),
    files('scripts/embed_js.py'),
    '@INPUT@',
    '@OUTPUT@',
    'YuzuVizHostJs',
  ],
)

cytoscape_js_embed = custom_target(
  'cytoscape_js_bundle',
  input: 'static/cytoscape.min.js',
  output: 'cytoscape_js_bundle.cpp',
  command: [
    find_program('python3', 'python'),
    files('scripts/embed_js.py'),
    '@INPUT@',
    '@OUTPUT@',
    'CytoscapeJs',
  ],
)

# Build-time embed of the Yuzu Design System CSS bundle. The source
# kYuzuCss exceeded MSVC's 16,380-byte raw-string-literal limit (C2026)
# after the design-token expansion. Chunking into ~14 KB
# fragments concatenated at static-init time keeps every chunk under
# the limit. Symbol: kYuzuCss (std::string).
yuzu_css_embed = custom_target(
  'yuzu_css_bundle',
  input: 'static/yuzu.css',
  output: 'yuzu_css_bundle.cpp',
  command: [
    find_program('python3', 'python'),
    files('scripts/embed_js.py'),
    '@INPUT@',
    '@OUTPUT@',
    'YuzuCss',
  ],
)

# Build-time embed of vendored Inter variable webfont as a constexpr
# byte array (woff2 binary; cannot use raw string literals). Symbol:
# kInterVariableWoff2 — std::string_view of the bytes.
inter_embed = custom_target(
  'inter_woff2_bundle',
  input: 'vendor/inter/InterVariable.woff2',
  output: 'inter_woff2_bundle.cpp',
  command: [
    find_program('python3', 'python'),
    files('scripts/embed_binary.py'),
    '@INPUT@',
    '@OUTPUT@',
    'InterVariableWoff2',
  ],
)

# Build-time YAML→JSON conversion for shipped Yuzu content. The
# server iterates kBundledDefinitions / kBundledSets on startup and
# upserts them into the instruction store, so charts are populated
# without operator intervention. Sidesteps yaml-cpp on Windows MSVC
# (#625) by doing the parse at build time with PyYAML.
#
# PyYAML is a hard build dependency: the embedded vector is the only
# path by which shipped InstructionDefinitions reach the server (no
# filesystem fallback at runtime), so a missing PyYAML used to silently
# produce a binary with an empty Instructions tab. Probe at configure
# time so the failure surfaces here rather than mid-compile.
embed_python = find_program('python3', 'python')
_yaml_probe = run_command(embed_python, '-c', 'import yaml', check: false)
if _yaml_probe.returncode() != 0
  error(
    'PyYAML is required to embed shipped InstructionDefinitions but is '
    + 'not importable from ' + embed_python.full_path() + '. '
    + 'Install with `pip install pyyaml` (Linux/macOS) or '
    + '`pacman -S python-yaml` (MSYS2). If you have just installed PyYAML, '
    + 're-run with `meson setup --wipe <builddir>` -- meson caches '
    + 'run_command results in introspection state, so --reconfigure will '
    + 'not re-probe. See CLAUDE.md "Instruction Engine".'
  )
endif

content_embed = custom_target(
  'bundled_content',
  output: 'bundled_content.cpp',
  command: [
    embed_python,
    files('scripts/embed_content.py'),
    meson.project_source_root() / 'content',
    '@OUTPUT@',
  ],
  build_always_stale: true,  # always re-scan content/ for edits
)

# Build-time embed of the curated CPE map (PR 3, ADR-0018). Lives under
# content/cpe-map/ deliberately — embed_content.py above globs ONLY
# content/{definitions,packs}/**/*.yaml and content/plugin-docs/*.json, so
# this CSV is NOT swept into the
# Instruction-Engine bundle; it is embedded on its own as a std::string_view
# (kCuratedCpeMap) that CpeIdentityResolver parses at construction.
#
# Build-time LOWER-BOUND guard on WELL-FORMED rows (NOT the authoritative
# floor). This probe counts only lines that share the shape the runtime parser
# accepts — non-blank, non-`#`, split on `,` into EXACTLY 5 fields with a
# non-empty name (field[2]) AND non-empty cpe_product (field[4]) — so 13
# malformed / empty-product lines can no longer pass configure and then crash
# the server at boot. It deliberately does NOT replicate the runtime's `\x1f`
# key-dedup (impractical in a one-liner), so it is an over-count relative to
# distinct keys: the runtime ctor (map_.size() < kMinCuratedRows in
# cpe_identity_resolver.cpp) remains the AUTHORITATIVE floor. See ADR-0018.
cpe_map_csv = files('../../content/cpe-map/curated-cpe-map.csv')
_cpe_probe = run_command(
  embed_python, '-c',
  '''import sys
lines = open(sys.argv[1], encoding="utf-8").read().splitlines()
n = 0
for l in lines:
    s = l.strip()
    if not s or s.startswith("#"):
        continue
    parts = l.split(",")
    if len(parts) == 5 and parts[2].strip() and parts[4].strip():
        n += 1
print(n)''',
  cpe_map_csv,
  check: true,
)
_cpe_rows = _cpe_probe.stdout().strip().to_int()
if _cpe_rows < 13
  error(
    'Curated CPE map has ' + _cpe_rows.to_string() + ' well-formed data rows but '
    + 'kMinCuratedRows is 13 (server/core/src/cpe_identity_resolver.hpp). Build-time '
    + 'lower-bound guard: a thin map ships a resolver that high-confidence-matches '
    + 'almost nothing. The runtime ctor is the authoritative floor. See ADR-0018.'
  )
endif

cpe_map_embed = custom_target(
  'cpe_map_bundle',
  input: cpe_map_csv,
  output: 'cpe_map_bundle.cpp',
  command: [
    embed_python,
    files('scripts/embed_binary.py'),
    '@INPUT@',
    '@OUTPUT@',
    'CuratedCpeMap',
  ],
)

# Vendored Nayuki QR-Code-generator (MIT, pinned v1.8.0; see
# server/core/vendor/qrcodegen/qrcodegen-NOTICE.txt). Built as its own
# static lib with warnings off so third-party source does not trip our
# warning_level=3 — same isolation the vcpkg deps get via include_type:'system'.
qrcodegen_lib = static_library(
  'qrcodegen',
  files('vendor/qrcodegen/qrcodegen.cpp'),
  include_directories: include_directories('vendor/qrcodegen'),
  override_options: ['warning_level=0', 'werror=false'],
)
qrcodegen_dep = declare_dependency(
  link_with: qrcodegen_lib,
  include_directories: include_directories('vendor/qrcodegen'),
)

# KeyProvider leaf target (ADR-0010, #1320 PR 4, governance arch-S3).
# key_provider.{hpp,cpp} is extracted from yuzu_server_core_lib so the pg/
# substrate (SecretCodec takes a KekProvider&) can grow into its own library
# later without a meson graph cycle: pg → key_provider is a leaf edge, while
# key_provider → server_core would have been a back edge. OpenSSL is required
# here unconditionally (AES-256-GCM KEK wrap/unwrap + SHA-256 check values +
# OPENSSL_cleanse zeroization). A disabler would NOT fail loudly — it would
# silently disable this target and everything that links it (the whole
# server), so guard explicitly (governance build-S1).
if is_disabler(openssl_dep) or not openssl_dep.found()
  error('OpenSSL is required for yuzu_key_provider (ADR-0010 secrets seam); '
        + 'vcpkg.json makes it an unconditional dependency on every platform')
endif
yuzu_key_provider_lib = static_library(
  'yuzu_key_provider',
  files('src/key_provider.cpp'),
  dependencies: [spdlog_dep, openssl_dep],
)
yuzu_key_provider_dep = declare_dependency(
  link_with: yuzu_key_provider_lib,
  dependencies: [openssl_dep],
)

yuzu_server_core_lib = static_library(
  'yuzu_server_core',
  [echarts_embed, three_embed, three_orbit_embed, yuzu_viz_js_embed,
   yuzu_viz_host_js_embed, cytoscape_js_embed,
   yuzu_css_embed, inter_embed, content_embed, cpe_map_embed,
  files(
    'src/config_secret_keys.cpp',
    'src/runtime_config_store.cpp',
    'src/runtime_config_view.cpp',
    'src/server.cpp',
    'src/agent_registry.cpp',
    'src/agent_service_impl.cpp',
    'src/gateway_service_impl.cpp',
    'src/auth.cpp',
    'src/auth_db.cpp',
    'src/auth_routes.cpp',
    'src/authz_gates.cpp',
    'src/mfa_step_up.cpp',
    'src/mfa_qr.cpp',
    'src/totp.cpp',
    'src/auto_approve.cpp',
    'src/cidr_match.cpp',
    'src/dashboard_ui.cpp',
    'src/chargen_ui.cpp',
    'src/procfetch_ui.cpp',
    'src/login_ui.cpp',
    'src/settings_ui.cpp',
    'src/settings_routes.cpp',
    'src/settings_model.cpp', # #4028 — shared REST/fragment Settings read-twin builders
    'src/plugin_signing_helpers.cpp',
    'src/nvd_db.cpp',
    'src/nvd_version.cpp',
    'src/cpe_identity_resolver.cpp',
    'src/nvd_client.cpp',
    'src/nvd_sync.cpp',
    'src/ota_signature_sidecar.cpp',
    'src/update_registry.cpp',
    'src/response_store.cpp',
    'src/response_routes.cpp',
    'src/response_query_model.cpp', # #2146 A2-R2: shared REST v1 + MCP builder for the
                                     # instruction/command-ID-keyed response query/aggregate/export surface
    'src/bundle_service.cpp',
    'src/bundle_orchestrator.cpp',
    'src/audit_store.cpp',
    'src/tag_store.cpp',
    'src/tag_routes.cpp',
    'src/scope_engine.cpp',
    'src/scope_preview.cpp', # #2146 Batch B2: shared REST v1 + MCP scope-preview builder
    'src/yaml_scan.cpp',
    'src/scope_yaml.cpp',
    'src/analytics_event_store.cpp',
    'src/analytics_sinks.cpp',
    'src/data_export.cpp',
    'src/instruction_store.cpp',
    'src/instruction_yaml.cpp',
    'src/instruction_definition_model.cpp', # #4029: shared REST v1 + MCP builder
    'src/instruction_routes.cpp',
    'src/execution_tracker.cpp',
    'src/execution_model.cpp',
    'src/execution_routes.cpp',
    'src/health_routes.cpp',
    'src/leader_elector.cpp',
    'src/pg_reachability_probe.cpp', # HA WS-8: runtime Postgres-reachability signal for /readyz
    'src/command_outbox_store.cpp',
    'src/command_outbox_delivery.cpp',
    'src/gateway_route_store.cpp', # HA WS-4 4.1: fenced agent->cluster routing directory
    'src/execution_event_bus.cpp',
    'src/fleet_topology_store.cpp',
    'src/heartbeat_ingestion.cpp',
    'src/approval_manager.cpp',
    'src/approval_model.cpp',
    'src/schedule_engine.cpp',
    'src/schedule_routes.cpp',
    'src/schedule_runner.cpp',
    'src/schedule_model.cpp', # ADR-0031 WS-A4: seventh per-family seam, pure JSON row builder
    'src/schedule_api.cpp', # ADR-0031 WS-A4: the seventh per-family in-process API seam
    'src/help_ui.cpp',
    'src/instruction_ui.cpp',
    'src/tar_page_ui.cpp',
    'src/result_sets_ui.cpp',
    'src/rbac_store.cpp',
    'src/oidc_provider.cpp',
    'src/oidc_scim_link.cpp',
    'src/saml_provider.cpp',
    'src/saml_scim_link.cpp',
    'src/error_codes.cpp',
    'src/result_envelope.cpp',
    'src/legacy_shim.cpp',
    'src/management_group_store.cpp',
    'src/api_token_store.cpp',
    'src/engine_principal_store.cpp',
    'src/access_review_model.cpp',
    'src/access_review_store.cpp',
    'src/session_store.cpp',
    'src/plugin_config_store.cpp',
    'src/plugin_config_routes.cpp',
    'src/upload_grant_store.cpp',
    'src/file_retrieval_routes.cpp',
    'src/secure_random.cpp',
    'src/scim_store.cpp',
    'src/scim_json.cpp',
    'src/scim_routes.cpp',
    'src/sso_boot_guard.cpp',
    'src/deprovision_revoke.cpp',
    'src/quarantine_store.cpp',
    'src/quarantine_reapply.cpp',
    'src/quarantine_containment_reconciler.cpp',
    'src/result_set_store.cpp',
    'src/result_set_routes.cpp',
    'src/result_set_matcher.cpp',
    'src/result_set_model.cpp', # #2146 Batch B2: shared REST v1 + MCP builder
    'src/policy_store.cpp',
    'src/policy_evaluator.cpp',
    'src/guaranteed_state_store.cpp',
    'src/baseline_store.cpp',
    'src/guardian_push_builder.cpp',
    'src/guardian_ingest.cpp',
    'src/guardian_resilience_schema.cpp',
    'src/guardian_rule_spec.cpp',
    'src/guardian_schema_registry.cpp',
    'src/guardian_form_render.cpp',
    'src/guardian_model.cpp',
    'src/guardian_api.cpp', # ADR-0031 WS-A4: the ninth per-family in-process API seam
    'src/dex_alert_router.cpp',
    'src/dex_blast_radius.cpp',
    'src/custom_properties_store.cpp',
    'src/custom_properties_routes.cpp',
    'src/mcp_server.cpp',
    'src/mcp_input_schema.cpp',
    'src/mcp_orientation.cpp',
    'src/mcp_session.cpp',
    'src/mcp_stream.cpp',
    'src/mcp_stream_bridge.cpp',
    'src/mcp_transport.cpp',
    'src/rest_api_v1.cpp',
    'src/compliance_model.cpp',
    'src/compliance_api.cpp', # ADR-0031 WS-A4: the third per-family in-process API seam
    'src/compliance_routes.cpp',
    'src/policy_admin_routes.cpp', # ADR-0031 WS-A4 Task B: policy/fragment mutator routes (no public twin — outside the seam)
    'src/guardian_routes.cpp',
    'src/dex_routes.cpp',
    'src/dex_read_model.cpp',
    'src/execution_statistics_model.cpp', # #2146 Batch B3 -- shared REST+MCP builder (Rule 1)
    'src/management_group_model.cpp', # #2146 Batch B4 -- shared REST+MCP builder (Rule 1)
    'src/api_token_model.cpp', # #2146 Batch B4 -- shared REST+MCP builder (Rule 1)
    'src/offload_target_model.cpp', # #2146 Batch B5 -- shared REST+MCP builder (Rule 1)
    'src/license_model.cpp', # #2146 Batch B5 -- shared REST+MCP builder (Rule 1)
    'src/software_deployment_model.cpp', # #2146 Batch B5 -- shared REST+MCP builder (Rule 1)
    'src/dex_perf_model.cpp',
    'src/dex_app_perf_model.cpp',
    'src/dex_app_perf_ui.cpp',
    'src/dex_perf_ui.cpp',
    'src/network_perf_model.cpp',
    'src/network_api.cpp', # ADR-0031 WS-A4: the first per-family in-process API seam pilot
    'src/network_routes.cpp',
    'src/network_ui.cpp',
    'src/device_api.cpp', # ADR-0031 WS-A4: the fourth per-family in-process API seam
    'src/device_routes.cpp',
    'src/device_lens_routes.cpp', # ADR-0031 WS-A4 wave 2: DEX/Guardian device lenses (no public twin — outside the seam)
    'src/device_ui.cpp',
    'src/group_agent_count_preview.cpp',
    'src/inventory_routes.cpp',
    'src/inventory_ui.cpp',
    'src/inventory_ci_join.cpp',
    'src/hardware_list_model.cpp',
    'src/hardware_routes.cpp',
    'src/hardware_ui.cpp',
    'src/hardware_actions_ui.cpp',
    'src/sle_routes.cpp',
    'src/software_catalog_rollup.cpp',
    'src/preflight_routes.cpp',
    'src/preflight_ui.cpp',
    'src/preflight_eval.cpp',
    'src/preflight_run_store.cpp',
    'src/preflight_runner.cpp',
    'src/verify_routes.cpp',
    'src/verify_ui.cpp',
    'src/verify_api.cpp', # ADR-0031 WS-A4: the second per-family in-process API seam
    'src/dex_api.cpp', # ADR-0031 WS-A4: the fifth per-family in-process API seam (DEX signals)
    'src/dex_perf_api.cpp', # ADR-0031 WS-A4: the sixth per-family in-process API seam (DEX app-perf-over-time)
    'src/deployment_routes.cpp',
    'src/deployment_ui.cpp',
    'src/deployment_run_store.cpp',
    'src/deployment_engine.cpp',
    'src/tar_process_tree.cpp',
    'src/tar_tree_routes.cpp',
    'src/dashboard_routes.cpp',
    'src/workflow_routes.cpp',
    'src/notification_routes.cpp',
    'src/command_routes.cpp',
    'src/page_routes.cpp',
    'src/dashboard_api_routes.cpp',
    'src/nvd_routes.cpp',
    'src/approval_routes.cpp',
    'src/config_routes.cpp', # #2542 PR-12: the 2-route Runtime Configuration API (7.3), extracted onto the HttpRouteSink seam
    'src/diagnostics_routes.cpp', # #2542 PR-12: the 5-route Chargen + Procfetch diagnostic API, extracted onto the HttpRouteSink seam
    'src/legacy_events_routes.cpp', # #2542 PR-12: the legacy GET /events SSE stream, extracted onto the HttpRouteSink seam
    'src/instruction_fragment_routes.cpp', # #2542 PR-12: the 2-route Instructions HTMX fragment pair, extracted onto the HttpRouteSink seam
    'src/approvals_fragment_routes.cpp', # #2542 PR-12: the Approvals HTMX fragment, extracted onto the HttpRouteSink seam
    'src/mcp_disabled_routes.cpp', # #2542 PR-12: the 3-route MCP-disabled stub triple, extracted onto the HttpRouteSink seam
    'src/webhook_routes.cpp',
    'src/offload_routes.cpp',
    'src/discovery_routes.cpp',
    'src/discover_routes.cpp', # A2 discovery surface: /api/v1/discover/* (Issue 17.1)
    'src/enrollment_directory_model.cpp', # #4031: shared row builders — directory/enrollment/OIDC-config read twins
    'src/enrollment_directory_routes.cpp', # #4031: REST v1 read twins — /api/v1/{directory,enrollment,settings/oidc}
    'src/viz_routes.cpp',
    'src/viz_page_ui.cpp',
    'src/viz_host_page_ui.cpp',
    'src/compliance_ui.cpp',
    'src/guardian_ui.cpp',
    'src/guardian_page_ui.cpp',
    'src/cel_eval.cpp',
    'src/compliance_eval.cpp',
    'src/workflow_engine.cpp',
    'src/workflow_model.cpp',
    'src/workflow_api.cpp', # ADR-0031 WS-A4: the eighth per-family in-process API seam
    'src/product_pack_store.cpp',
    'src/product_pack_model.cpp', # #4029: shared REST v1 + MCP builder
    'src/app_perf_daily_store.cpp',
    'src/app_perf_fleet_store.cpp',
    'src/app_perf_group_reader.cpp',
    'src/app_perf_compare.cpp',
    'src/app_perf_cohort_reader.cpp',
    'src/app_perf_ingestion.cpp',
    'src/app_perf_rollup.cpp',
    'src/inventory_ingestion.cpp',
    'src/inventory_store.cpp',
    'src/data_inventory_routes.cpp',
    'src/software_inventory_store.cpp',
    'src/vuln_finding_store.cpp',
    'src/product_normalize.cpp',
    'src/product_registry_store.cpp',
    'src/software_licensing_store.cpp',
    'src/software_licensing_ingestion.cpp',
    'src/app_usage_store.cpp',           # Wave 7b PR7b.2
    'src/app_usage_ingestion.cpp',       # Wave 7b PR7b.2
    'src/app_usage_routes.cpp',          # Wave 7b PR7b.2
    'src/app_usage_read_model.cpp',      # Wave 7b PR7b.2 (Rule 1 shared builder)
    'src/device_ci_ingestion.cpp',
    'src/device_inventory_store.cpp',
    'src/agent_decommission.cpp',
    'src/offline_endpoint_store.cpp',
    'src/notification_store.cpp',
    'src/webhook_store.cpp',
    'src/offload_target_store.cpp',
    'src/directory_sync.cpp',
    'src/patch_manager.cpp',
    'src/deployment_store.cpp',
    'src/discovery_store.cpp',
    'src/inventory_eval.cpp',
    'src/device_token_store.cpp',
    'src/software_deployment_store.cpp',
    'src/license_store.cpp',
    'src/topology_ui.cpp',
    'src/statistics_ui.cpp',
    # css_bundle.cpp removed in favour of build-time chunked embed (Gate 4
    # cpp-B1: kYuzuCss exceeds MSVC's 16,380-byte raw-string-literal limit).
    # Source CSS lives at server/core/static/yuzu.css; embed_js.py emits
    # yuzu_css_bundle.cpp with the chunked literal pattern.
    'src/static_js_bundle.cpp',
    'src/charts_js_bundle.cpp',
    'src/visualization_engine.cpp',
    'src/response_templates_engine.cpp',
    'src/icons_svg.cpp',
    'src/migration_runner.cpp',
    # Postgres substrate (ADR-0006/0008, #1320 PR 1): RAII owners + shared
    # pool + migration runner under src/pg/. Header pg_raii.hpp is
    # header-only; canary_main.cpp is the separate yuzu_pg_canary exe below.
    'src/pg/pg_pool.cpp',
    'src/pg/pg_migration_runner.cpp',
    'src/pg/pg_retention_guard.cpp',
    'src/pg/multi_host_dsn.cpp', # HA WS-8: multi-host DSN must use target_session_attrs=read-write
    # SecretCodec (ADR-0010, #1320 PR 4): app-side envelope encryption for
    # secret columns. Depends on the yuzu_key_provider leaf target above.
    'src/pg/secret_codec.cpp',
    'src/rate_limiter.cpp',
    'src/ota_transfer_watchdog.cpp',
    'src/principal_quota.cpp',
    'src/cert_reloader.cpp',
    'src/grpc_tls_credentials.cpp',
    'src/x509_ca.cpp',
    # key_provider.cpp lives in the yuzu_key_provider leaf target above
    # (ADR-0010 arch-S3); the dep below carries it.
    'src/ca_store.cpp',
    'src/default_certs.cpp',
    'src/ca_routes.cpp',
    'src/kek_routes.cpp',
    'src/security_headers.cpp',
  )],
  include_directories: ['include', '../../common/include'],
  cpp_args: https_cpp_args + ['-DCPPHTTPLIB_LISTEN_BACKLOG=128'] + (cxx.get_id() == 'msvc' ? ['/bigobj'] : []) + switch_werror_args,
  dependencies: [yuzu_sdk_dep, yuzu_proto_dep, spdlog_dep, httplib_dep,
                 sqlite3_dep, nlohmann_json_dep, re2_dep, qrcodegen_dep,
                 libpq_dep, yuzu_key_provider_dep] + auth_crypto_deps + https_deps
               + saml_deps,
)

yuzu_server_core_dep = declare_dependency(
  link_with: yuzu_server_core_lib,
  include_directories: [include_directories('include'), include_directories('../../common/include')],
  # CPPHTTPLIB_OPENSSL_SUPPORT gates real data members on httplib::ClientImpl/
  # SSLClient (header-only, inline definitions) — every consumer TU must define
  # it identically to yuzu_server_core_lib's own cpp_args, or the linker folds
  # mismatched-layout definitions of the same class into one symbol (ODR
  # violation). main.cpp transitively includes <httplib.h> via scim_routes.hpp
  # without this propagated, which corrupted httplib::Client objects on first
  # use (SIGSEGV in NvdClient::fetch_paginated's first request).
  # CPPHTTPLIB_LISTEN_BACKLOG doesn't affect class layout (no ODR hazard), but
  # is propagated for the same reason: without it, a consumer TU falls back to
  # httplib's default listen() backlog of 5 instead of the intended 128.
  compile_args: https_cpp_args + ['-DCPPHTTPLIB_LISTEN_BACKLOG=128'],
  dependencies: [yuzu_sdk_dep, yuzu_proto_dep, spdlog_dep, httplib_dep,
                 sqlite3_dep, nlohmann_json_dep, re2_dep, qrcodegen_dep,
                 libpq_dep, yuzu_key_provider_dep] + auth_crypto_deps + https_deps
               + saml_deps,
)

executable(
  'yuzu-server',
  files('src/main.cpp'),
  dependencies: [yuzu_server_core_dep, cli11_dep] + auth_crypto_deps,
  install: true,
)

# Postgres link canary (#1317 F0, ADR-0008): proves libpq builds at the pinned
# vcpkg baseline and links on MSVC with no LNK-class errors (the #375 lesson).
# Linkage is static on Linux/macOS, dynamic DLL on Windows (see the libpq_dep
# comment in the root meson.build and the ADR-0008 Correction). The F1
# substrate (#1320 PR 1) folded its body onto the pg_raii owners, but the
# TARGET stays: the CI link-provenance assertions on all four Tier-1 legs
# (ldd/otool/dumpbin in ci.yml) inspect this binary path. Do not remove or
# rename without updating those workflow steps.
executable(
  'yuzu_pg_canary',
  files('src/pg/canary_main.cpp'),
  dependencies: [libpq_dep],
  install: false,
)

# Drogon build canary (WS-B1 / ADR-0031 Gate G10). Proves Drogon links into the
# existing Meson/vcpkg matrix — Windows MSVC static leg included — WITHOUT
# disturbing the #375 grpc/protobuf/abseil static-linkage config. Sibling of
# yuzu_pg_canary above; server-only (this whole subdir is build_server-gated).
#
# Wiring rationale — mirror the sqlite3/libxml2 DYNAMIC-DLL pattern, NOT the
# grpc/protobuf hand-wired static find_library() branch. Drogon and its
# transitive deps (trantor, jsoncpp, brotli) are NOT in
# triplets/x64-windows.cmake's static-linkage override list (scoped to
# abseil/grpc/protobuf/upb/re2/c-ares/utf8-range only), so on Windows they
# resolve as ordinary dynamic DLLs + import libs — the same shape as
# sqlite3/libxml2 (which use method:'cmake' on Windows) and libpq
# (hand-wired find_library on Windows — same dynamic-DLL shape, see the libpq
# block in the root meson.build), none of which hits LNK2038. So one uniform cmake dependency() call across every
# platform, with a pkg-config fallback, is correct here. Do NOT hand-wire this
# into the Windows find_library() branch: that machinery exists solely for the
# forced-static #375 stack.
#
# Trantor (Drogon's I/O layer) pulls c-ares and OpenSSL. c-ares IS in the #375
# static-override list (already forced static for grpc), and OpenSSL is our own
# — Drogon's TLS therefore rides our existing OpenSSL with no feature flag.
# Default features only (no orm/postgres/sqlite3/...): ADR-0031 Decision 5.
drogon_dep = dependency('Drogon', method: 'cmake', modules: ['Drogon::Drogon'],
  required: false, include_type: 'system')
if not drogon_dep.found()
  drogon_dep = dependency('drogon', required: true, include_type: 'system')
endif

# meson's cmake dep translator does NOT evaluate CMake generator expressions,
# so trantor's transitive link deps — declared as
# `$<LINK_ONLY:OpenSSL::SSL>;$<LINK_ONLY:OpenSSL::Crypto>;$<LINK_ONLY:c-ares::cares>`
# in TrantorTargets.cmake — are silently dropped from Drogon::Drogon's closure.
# On static-link platforms (Linux .a / macOS .a) the final link then fails with
# undefined OpenSSL EVP_* and c-ares ares_* symbols. Append them explicitly,
# exactly as libpq_dep appends OpenSSL for the same reason (see the libpq
# comment in the root meson.build). openssl_dep is already in scope (declared at
# the top of this file on every platform). c-ares is best-effort via pkg-config
# (`libcares`): needed at final link on static Linux/macOS; on Windows drogon/
# trantor are dynamic DLLs that resolve their own deps at load, so a missing
# libcares.pc there is harmless. Brotli/zlib/uuid are LINK_ONLY-dropped in the
# same way, and — proven by `nm` on the minimal canary — ARE load-bearing even
# for this link: the bare drogon::app() path drags in trantor's EventLoop/DNS/
# TLS plus drogon's Utilities.cc (getUuid / gzip / brotli), so a static-link
# platform genuinely needs the lot. The presentation binary (WS-B2) will append
# whatever else its used surface pulls.
# The dropped transitive set is trantor's (OpenSSL, c-ares) PLUS drogon's own
# (`$<LINK_ONLY:ZLIB::ZLIB>`, `$<LINK_ONLY:Brotli_lib>`, `$<LINK_ONLY:UUID_lib>`
# in DrogonTargets.cmake) — libdrogon.a's Utilities.cc (getUuid / gzip / brotli)
# references all of them, so even the minimal drogon::app() link needs the lot
# on a static-link platform. All resolve via pkg-config in the vcpkg tree on
# Linux; each is best-effort (required:false) so the dynamic-DLL Windows leg and
# macOS (where libuuid is a system framework, not a vcpkg port) don't fail
# configure on a missing .pc.
#
# openssl_dep guard (cross-platform FINDING 2): on Windows the required:false
# cmake + find_library both-fail path (top of this file) leaves openssl_dep a
# disabler(). A disabler propagated into a declare_dependency() dependency list
# SILENTLY disables the executable() that consumes it — the canary would then
# never build and CI would go green having proven nothing. Guard the append with
# the same is_disabler()/found() check https_deps uses above; on Windows a
# dynamic drogon DLL resolves its own OpenSSL at load, so omitting it is correct.
_drogon_transitive = []
if not is_disabler(openssl_dep) and openssl_dep.found()
  _drogon_transitive += openssl_dep
endif
foreach _pc : ['libcares', 'zlib', 'uuid', 'libbrotlienc', 'libbrotlidec']
  _d = dependency(_pc, method: 'pkg-config', required: false, include_type: 'system')
  if _d.found()
    _drogon_transitive += _d
  endif
endforeach
drogon_dep = declare_dependency(dependencies: [drogon_dep] + _drogon_transitive)

yuzu_drogon_canary_exe = executable(
  'yuzu_drogon_canary',
  files('src/drogon_canary_main.cpp'),
  dependencies: [drogon_dep],
  install: false,
)

# Actually RUN the canary in CI (cross-platform FINDING 1a / unhappy-path): a
# link alone does not prove the process loads. The main() returns 0 after
# forcing an out-of-line libdrogon symbol, so running it surfaces a load-time
# failure (a missing/unresolvable Drogon or transitive DLL on the Windows
# dynamic leg — precisely the #375-class regression this canary exists to
# catch) that a pure link step would miss. Suite 'server-checks' because this is
# a build/link/load structural assertion, not a functional server test — the
# same suite as the sibling structural checks in tests/meson.build (the pg
# shard-partition invariant, the mcp-bridge alloc-budget probe). CI executes it
# on the Windows leg via `--suite server-checks` (ci.yml, where dynamic DLL
# resolution actually matters) and on the unfiltered nightly ASan/TSan legs;
# the self-hosted Linux PR/push leg selects server-checks members by name, so
# there it still builds+links (its primary Linux value) but is not run.
# Gated on build_tests for consistency with every other registered test
# (tests/meson.build is only walked under build_tests); the executable itself
# still builds whenever build_server is set (its Linux link-check value, like
# the sibling yuzu_pg_canary). CI legs that RUN this (Windows server-checks,
# nightly ASan/TSan) enable build_tests to invoke `meson test`.
if build_tests
  test(
    'drogon build canary',
    yuzu_drogon_canary_exe,
    suite: ['server', 'server-checks'],
    timeout: 30,
  )
endif
