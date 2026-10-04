/**
 * test_static_js_bundle.cpp — Unit tests for every JavaScript / CSS / WOFF2
 * asset embedded into the server binary.
 *
 * Two embed pipelines feed this file:
 *
 *   * Hand-written: `server/core/src/static_js_bundle.cpp` carries `kHtmxJs`
 *     (HTMX 2.0.4 minified, 50918 bytes) and `kSseJs` (htmx-ext-sse 2.2.2,
 *     8897 bytes) as raw-string-literal chunks. Update the file by hand
 *     when bumping HTMX / SSE; update the pinned-size constants below in
 *     lock-step.
 *
 *   * Build-time codegen via `server/core/scripts/embed_js.py` (and
 *     `embed_binary.py` for woff2): the source files live under
 *     `server/core/static/` and `server/core/vendor/`. Each compile
 *     regenerates a `*_bundle.cpp` exposing the symbol as a
 *     `std::string` (or `std::string_view` for binary). Symbols covered
 *     here: `kEChartsJs`, `kThreeJs`, `kThreeOrbitControlsJs`,
 *     `kYuzuVizJs`, `kInterVariableWoff2`, `kYuzuCss`, `kYuzuChartsJs`.
 *
 * Plus the page HTML constant `kVizFleetPageHtml` from
 * `server/core/src/viz_page_ui.cpp` (separate TU at namespace scope).
 *
 * Tests guard against:
 *   - Chunk-boundary corruption (size drift) for hand-written bundles
 *   - IDE reformatting that breaks raw-string-literal continuity
 *   - Accidental tampering with embedded payloads
 *   - Drift from upstream byte-identity (vendored bundles match upstream)
 *   - Codegen-bundle contract drift (expected substrings, version pins,
 *     ABI invariants for the renderer JS)
 *
 * If you intentionally update a vendored asset or refactor the renderer
 * (`server/core/static/yuzu-viz.js` ↔ `kYuzuVizJs`), update the relevant
 * pinned constants below in lock-step.
 */

#include <catch2/catch_test_macros.hpp>
#include <catch2/matchers/catch_matchers_string.hpp>

#include <string>
#include <string_view>

// External symbols from server/core/src/static_js_bundle.cpp.
extern const std::string kHtmxJs;
extern const std::string kSseJs;

// External symbols from build-time embed targets (governance Gate 3 QE-B1):
//   * kEChartsJs            — embed_js.py over server/core/vendor/echarts.min.js
//   * kInterVariableWoff2   — embed_binary.py over vendor/inter/InterVariable.woff2
//   * kYuzuCss              — embed_js.py over server/core/static/yuzu.css
//   * kYuzuChartsJs         — server/core/src/charts_js_bundle.cpp (hand-written)
namespace yuzu::server {
extern const std::string kEChartsJs;
extern const std::string kThreeJs;
extern const std::string kThreeOrbitControlsJs;
extern const std::string kYuzuVizJs;
extern const std::string_view kInterVariableWoff2;
extern const std::string kYuzuCss;
extern const std::string kYuzuChartsJs;
} // namespace yuzu::server

// Page HTML constants (separate TUs at namespace scope -- not in
// yuzu::server like the JS bundles).
extern const char* const kVizFleetPageHtml;
extern const char* const kVizHostPageHtml;

using Catch::Matchers::ContainsSubstring;

namespace {
constexpr std::size_t kExpectedHtmxBytes = 50918;
constexpr std::size_t kExpectedSseBytes = 8897;
// Pinned upstream byte counts. If you intentionally update vendor/, bump
// these in lock-step. ECharts 5.6.0 minified is 1,034,102 bytes; Inter v4.0
// variable woff2 is 345,588 bytes; Yuzu CSS bundle is content-addressed by
// the source file and approximate-pinned (a 1% drift tolerance lets the
// design system iterate without re-flowing this file every commit).
constexpr std::size_t kExpectedEChartsBytes = 1'034'102;
constexpr std::size_t kExpectedInterWoff2Bytes = 345'588;
constexpr std::size_t kYuzuCssMinBytes = 20'000;   // ≥20 KB sanity floor
constexpr std::size_t kYuzuChartsMinBytes = 6'000; // ≥6 KB adapter floor
// Three.js r168 ES-module minified bundle + OrbitControls ES module
// (PR 4 of feat/viz-engine ladder). Both pinned to upstream byte counts;
// any change here must coincide with a deliberate vendor refresh.
constexpr std::size_t kExpectedThreeJsBytes = 685'408;
constexpr std::size_t kExpectedThreeOrbitJsBytes = 32'134;
} // namespace

// ── HTMX core ───────────────────────────────────────────────────────────────

TEST_CASE("static_js_bundle: kHtmxJs has expected pinned size", "[static-js][htmx]") {
    CHECK(kHtmxJs.size() == kExpectedHtmxBytes);
}

TEST_CASE("static_js_bundle: kHtmxJs starts with HTMX 2.0.4 IIFE preamble", "[static-js][htmx]") {
    // The minified bundle starts with `var htmx=function(){"use strict";...`
    REQUIRE(kHtmxJs.size() >= 30);
    CHECK(std::string_view(kHtmxJs).substr(0, 9) == "var htmx=");
    CHECK_THAT(kHtmxJs, ContainsSubstring("\"use strict\""));
}

TEST_CASE("static_js_bundle: kHtmxJs contains the version string", "[static-js][htmx]") {
    CHECK_THAT(kHtmxJs, ContainsSubstring("version:\"2.0.4\""));
}

TEST_CASE("static_js_bundle: kHtmxJs contains core public API symbols", "[static-js][htmx]") {
    // Sanity-check that core HTMX surface is present and the chunk
    // boundaries didn't lose anything mid-payload. The minified runtime
    // assigns the public API onto a Q object via `Q.<name>=<short>;`
    // statements after the IIFE body, so we look for those exact tokens.
    for (auto needle : {
             "Q.onLoad",
             "Q.process",
             "Q.ajax",
             "Q.swap",
             "Q.defineExtension",
             "Q.removeExtension",
             "Q.find",
             "Q.closest",
         }) {
        CAPTURE(needle);
        CHECK_THAT(kHtmxJs, ContainsSubstring(needle));
    }
}

TEST_CASE("static_js_bundle: kHtmxJs has no embedded NULs or unexpected delimiter",
          "[static-js][htmx]") {
    // Raw string literal delimiter must not appear inside the payload —
    // would silently corrupt the file. The static-init concat is also a
    // place where a stray NUL would terminate the std::string early.
    CHECK(kHtmxJs.find('\0') == std::string::npos);
    CHECK(kHtmxJs.find(")HTMXEOF") == std::string::npos);
}

TEST_CASE("static_js_bundle: kHtmxJs has no leading whitespace", "[static-js][htmx]") {
    // Regression guard: an earlier draft preserved a `\n` at byte 0
    // because `R"HTMXEOF(` was followed by a newline before the payload.
    // The reassembled bundle should be byte-identical to upstream, which
    // begins with `var` directly.
    REQUIRE_FALSE(kHtmxJs.empty());
    CHECK(kHtmxJs.front() == 'v');
    CHECK(kHtmxJs.front() != '\n');
    CHECK(kHtmxJs.front() != ' ');
}

// ── HTMX-SSE extension ──────────────────────────────────────────────────────

TEST_CASE("static_js_bundle: kSseJs has expected pinned size", "[static-js][sse]") {
    CHECK(kSseJs.size() == kExpectedSseBytes);
}

TEST_CASE("static_js_bundle: kSseJs starts with the SSE banner comment", "[static-js][sse]") {
    REQUIRE(kSseJs.size() >= 30);
    CHECK(std::string_view(kSseJs).substr(0, 2) == "/*");
    CHECK_THAT(kSseJs, ContainsSubstring("Server Sent Events Extension"));
}

TEST_CASE("static_js_bundle: kSseJs registers the 'sse' extension", "[static-js][sse]") {
    // The extension self-registers via htmx.defineExtension('sse', {...}).
    CHECK_THAT(kSseJs, ContainsSubstring("htmx.defineExtension"));
    CHECK_THAT(kSseJs, ContainsSubstring("'sse'"));
}

TEST_CASE("static_js_bundle: kSseJs has no embedded NULs or stray delimiter", "[static-js][sse]") {
    CHECK(kSseJs.find('\0') == std::string::npos);
    CHECK(kSseJs.find(")SSEEOF") == std::string::npos);
}

TEST_CASE("static_js_bundle: kSseJs has no leading whitespace", "[static-js][sse]") {
    REQUIRE_FALSE(kSseJs.empty());
    CHECK(kSseJs.front() == '/');
    CHECK(kSseJs.front() != '\n');
}

// ── Apache ECharts ──────────────────────────────────────────────────────────

TEST_CASE("static_js_bundle: kEChartsJs has expected pinned size", "[static-js][echarts]") {
    CHECK(yuzu::server::kEChartsJs.size() == kExpectedEChartsBytes);
}

TEST_CASE("static_js_bundle: kEChartsJs starts with the Apache license header",
          "[static-js][echarts]") {
    REQUIRE(yuzu::server::kEChartsJs.size() >= 100);
    // The vendored bundle preserves the Apache 2.0 header banner (License
    // §4(c) compliance check).
    CHECK_THAT(yuzu::server::kEChartsJs,
               ContainsSubstring("Licensed to the Apache Software Foundation"));
}

TEST_CASE("static_js_bundle: kEChartsJs exposes the global echarts API", "[static-js][echarts]") {
    // ContainsSubstring("init") alone is too generic (every minified JS
    // contains the substring) — governance Gate 4 UP-8. The minifier
    // renames public methods, so `echarts.init` doesn't appear literally
    // in the bundle. Pin two ECharts-unique tokens instead:
    //   * the UMD wrapper assignment that exposes the global
    //   * the internal property name used by getInstanceByDom (lib-unique)
    CHECK_THAT(yuzu::server::kEChartsJs, ContainsSubstring(".echarts={})"));
    CHECK_THAT(yuzu::server::kEChartsJs, ContainsSubstring("echarts_instance_"));
}

TEST_CASE("static_js_bundle: kEChartsJs is the expected vendored version", "[static-js][echarts]") {
    // Pin the upstream version string so a silent vendor swap to a newer
    // minor (5.7.x) that happens to match the byte count fails LOUD
    // (governance Gate 4 UP-5 / QA-N2).
    CHECK_THAT(yuzu::server::kEChartsJs, ContainsSubstring("5.6.0"));
}

TEST_CASE("static_js_bundle: kEChartsJs has no embedded NULs", "[static-js][echarts]") {
    CHECK(yuzu::server::kEChartsJs.find('\0') == std::string::npos);
    // A stray `)ECHARTSEMBED"` close-delimiter cannot appear at runtime —
    // raw-string literal grammar consumes it at compile time, and
    // embed_js.py's collision check at build time refuses to emit if the
    // input bytes contain it. The runtime check that earlier sat here
    // was therefore tautological (governance Gate 6 SRE-1). Build-time
    // protection is at server/core/scripts/embed_js.py.
}

// ── Three.js r168 + OrbitControls (PR 4 of feat/viz-engine ladder) ──────────

TEST_CASE("static_js_bundle: kThreeJs has expected pinned size", "[static-js][three]") {
    CHECK(yuzu::server::kThreeJs.size() == kExpectedThreeJsBytes);
}

TEST_CASE("static_js_bundle: kThreeJs starts with the MIT license header", "[static-js][three]") {
    REQUIRE(yuzu::server::kThreeJs.size() >= 100);
    // The vendored ES-module minified bundle preserves the SPDX/MIT header
    // at the top of build/three.module.min.js (license attribution).
    CHECK_THAT(yuzu::server::kThreeJs, ContainsSubstring("Three.js Authors"));
    CHECK_THAT(yuzu::server::kThreeJs, ContainsSubstring("SPDX-License-Identifier: MIT"));
}

TEST_CASE("static_js_bundle: kThreeJs is the expected vendored release", "[static-js][three]") {
    // gov R4 QA-B1: pin the QUOTED form `"168"` rather than the bare
    // substring `168`. Bare-digit search hits arbitrary numeric tokens
    // throughout 685 KB of minified JS (a silent r169 swap would still
    // contain `168` somewhere). The bundle exposes `REVISION = "168"`
    // exactly once -- pin that.
    CHECK_THAT(yuzu::server::kThreeJs, ContainsSubstring("\"168\""));
    // Sanity: confirm exactly one occurrence so the assertion above
    // remains discriminating across future minor refreshes that may
    // happen to embed the digit pattern elsewhere.
    auto pos = yuzu::server::kThreeJs.find("\"168\"");
    REQUIRE(pos != std::string::npos);
    CHECK(yuzu::server::kThreeJs.find("\"168\"", pos + 1) == std::string::npos);
}

TEST_CASE("static_js_bundle: kThreeJs has no embedded NULs", "[static-js][three]") {
    CHECK(yuzu::server::kThreeJs.find('\0') == std::string::npos);
}

TEST_CASE("static_js_bundle: kThreeOrbitControlsJs has expected pinned size",
          "[static-js][three]") {
    CHECK(yuzu::server::kThreeOrbitControlsJs.size() == kExpectedThreeOrbitJsBytes);
}

TEST_CASE("static_js_bundle: kThreeOrbitControlsJs imports from 'three'", "[static-js][three]") {
    REQUIRE(yuzu::server::kThreeOrbitControlsJs.size() >= 50);
    // The unmodified ES-module file uses a bare specifier `from 'three'`
    // that the page's importmap resolves to `/static/three.module.min.js`.
    // Without this top-level import, the importmap contract in PR 5 is
    // broken; pin the substring so a vendor refresh that swaps the
    // import path fails the build instead of producing a runtime
    // ReferenceError on Quaternion / Spherical / Vector3.
    CHECK_THAT(yuzu::server::kThreeOrbitControlsJs, ContainsSubstring("from 'three'"));
    // Public class still named OrbitControls.
    CHECK_THAT(yuzu::server::kThreeOrbitControlsJs, ContainsSubstring("class OrbitControls"));
}

TEST_CASE("static_js_bundle: kThreeOrbitControlsJs has no embedded NULs", "[static-js][three]") {
    CHECK(yuzu::server::kThreeOrbitControlsJs.find('\0') == std::string::npos);
}

// ── Yuzu fleet renderer (PR 5 of feat/viz-engine ladder) ────────────────────

TEST_CASE("static_js_bundle: kYuzuVizJs is a non-empty ES module", "[static-js][viz]") {
    REQUIRE(yuzu::server::kYuzuVizJs.size() >= 1000);
    // ES module top-level imports are the load contract that the
    // /viz/fleet page's importmap maps. Without these substrings the
    // module wouldn't be loadable as a module at all.
    CHECK_THAT(yuzu::server::kYuzuVizJs, ContainsSubstring("import * as THREE from 'three'"));
    CHECK_THAT(yuzu::server::kYuzuVizJs,
               ContainsSubstring("import { OrbitControls } "
                                 "from 'three/addons/controls/OrbitControls.js'"));
}

TEST_CASE("static_js_bundle: kYuzuVizJs registers htmx:afterSettle mount", "[static-js][viz]") {
    // Mount-once on htmx:afterSettle is the canvas-survival contract --
    // an HTMX swap of the overlay panel must not blow away the renderer.
    CHECK_THAT(yuzu::server::kYuzuVizJs, ContainsSubstring("htmx:afterSettle"));
}

TEST_CASE("static_js_bundle: kYuzuVizJs idempotency guard present", "[static-js][viz]") {
    // The mount-once guard reads root.dataset.yuzuVizMounted; any future
    // refactor that drops this leaves the door open for double-mount on
    // HTMX swap (two WebGLRenderer instances on the same canvas).
    // gov R4 QA-S2: pin BOTH sides of the sentinel so a regression that
    // changes the assignment to `'true'` while the check stays `'1'`
    // breaks idempotency silently. The bare-substring assertion alone
    // would pass either way.
    CHECK_THAT(yuzu::server::kYuzuVizJs, ContainsSubstring("yuzuVizMounted === '1'"));
    CHECK_THAT(yuzu::server::kYuzuVizJs, ContainsSubstring("yuzuVizMounted = '1'"));
}

TEST_CASE("static_js_bundle: kYuzuVizJs registers webglcontextlost handler", "[static-js][viz]") {
    // gov R4 UP-3 / CHAOS-2: WebGL context loss must be handled or the
    // rAF loop spams "context-lost" warnings on every frame after a GPU
    // sleep/wake. Pin both event-name listeners so a refactor that drops
    // either fails the test instead of producing silent freezes.
    CHECK_THAT(yuzu::server::kYuzuVizJs, ContainsSubstring("'webglcontextlost'"));
    CHECK_THAT(yuzu::server::kYuzuVizJs, ContainsSubstring("'webglcontextrestored'"));
}

TEST_CASE("static_js_bundle: kYuzuVizJs guards WASD against editable targets", "[static-js][viz]") {
    // gov R4 sec-M1 / UP-6: WASD preventDefault MUST NOT fire when a
    // text-editable element is focused, or typing W/A/S/D into a future
    // overlay-panel <input> silently eats the keystroke.
    CHECK_THAT(yuzu::server::kYuzuVizJs, ContainsSubstring("isEditableTarget"));
    CHECK_THAT(yuzu::server::kYuzuVizJs, ContainsSubstring("isContentEditable"));
}

TEST_CASE("static_js_bundle: kYuzuVizJs disables OrbitControls panning", "[static-js][viz]") {
    // OrbitControls.enablePan = false is the WASD-owns-translation
    // contract. Built-in pan steals the mouse event from rotate; pin the
    // disable.
    CHECK_THAT(yuzu::server::kYuzuVizJs, ContainsSubstring("controls.enablePan = false"));
}

TEST_CASE("static_js_bundle: kYuzuVizJs draws PR 8 intra-cube edges as LineSegments",
          "[static-js][viz][pr8]") {
    // PR 8 contract: for every Local-scope connection with both src_pid and
    // dst_pid populated, the renderer constructs a THREE.LineSegments inside
    // the cube's processGroup so the disposeNode walk releases it on
    // clearFleet. Pin (a) the scope discriminator, (b) the LineSegments +
    // LineBasicMaterial construction, and (c) the dst_pid handling so a
    // refactor that drops the pair drops the test along with it.
    CHECK_THAT(yuzu::server::kYuzuVizJs, ContainsSubstring("scope !== 'local'"));
    CHECK_THAT(yuzu::server::kYuzuVizJs, ContainsSubstring("THREE.LineSegments"));
    CHECK_THAT(yuzu::server::kYuzuVizJs, ContainsSubstring("LineBasicMaterial"));
    CHECK_THAT(yuzu::server::kYuzuVizJs, ContainsSubstring("c.dst_pid"));
}

TEST_CASE("static_js_bundle: kYuzuVizJs has no embedded NULs", "[static-js][viz]") {
    CHECK(yuzu::server::kYuzuVizJs.find('\0') == std::string::npos);
}

// ── PR 6: cube layer ────────────────────────────────────────────────────────

TEST_CASE("static_js_bundle: kYuzuVizJs declares per-OS palette for linux/darwin/windows",
          "[static-js][viz]") {
    // PR 6 colour palette. The hex values double as a contract: changing
    // the palette is a deliberate UX decision, not a stealth refactor.
    CHECK_THAT(yuzu::server::kYuzuVizJs, ContainsSubstring("OS_PALETTE"));
    CHECK_THAT(yuzu::server::kYuzuVizJs, ContainsSubstring("linux:"));
    CHECK_THAT(yuzu::server::kYuzuVizJs, ContainsSubstring("darwin:"));
    CHECK_THAT(yuzu::server::kYuzuVizJs, ContainsSubstring("windows:"));
    CHECK_THAT(yuzu::server::kYuzuVizJs, ContainsSubstring("pickOsColor"));
}

TEST_CASE("static_js_bundle: kYuzuVizJs uses FNV-1a 32-bit hash for stable layout",
          "[static-js][viz]") {
    // Stable per-agent positions across reloads require a deterministic
    // hash. FNV-1a 32-bit is identifiable by the 0x811c9dc5 offset basis
    // and the 0x01000193 prime; pin both so a refactor that swaps to a
    // randomised hash (and breaks the "same fleet renders the same way"
    // contract) fails the test.
    CHECK_THAT(yuzu::server::kYuzuVizJs, ContainsSubstring("0x811c9dc5"));
    CHECK_THAT(yuzu::server::kYuzuVizJs, ContainsSubstring("0x01000193"));
    CHECK_THAT(yuzu::server::kYuzuVizJs, ContainsSubstring("Math.imul"));
}

TEST_CASE("static_js_bundle: kYuzuVizJs lays machines out on a ceil(sqrt(N)) grid",
          "[static-js][viz]") {
    // The grid layout is the placement contract -- without ceil(sqrt(N))
    // the cubes pile up at the origin or fly off-screen at high N. Pin
    // the function name + the ceil/sqrt math so a refactor to a different
    // packing breaks the test rather than silently regressing UX.
    CHECK_THAT(yuzu::server::kYuzuVizJs, ContainsSubstring("layoutMachines"));
    CHECK_THAT(yuzu::server::kYuzuVizJs, ContainsSubstring("Math.ceil(Math.sqrt"));
}

TEST_CASE("static_js_bundle: kYuzuVizJs stacks machines into three architecture tiers",
          "[static-js][viz]") {
    // PR 12: the canvas reads like a three-tier architecture diagram --
    // frontend on top, application middle, database on the bottom. Pin
    // the classifier name + the TIER_Y dict + the per-tier Y derivations
    // so a refactor that collapses the layout back to a single grid (or
    // that re-orders the tiers — top tier MUST be frontend, bottom MUST
    // be database) fails the test instead of silently producing a flat
    // grid with surprised operators.
    CHECK_THAT(yuzu::server::kYuzuVizJs, ContainsSubstring("classifyTier"));
    CHECK_THAT(yuzu::server::kYuzuVizJs, ContainsSubstring("TIER_Y"));
    CHECK_THAT(yuzu::server::kYuzuVizJs, ContainsSubstring("database: CUBE_SIZE / 2,"));
    CHECK_THAT(yuzu::server::kYuzuVizJs, ContainsSubstring("app:      CUBE_SIZE / 2 + TIER_GAP,"));
    CHECK_THAT(yuzu::server::kYuzuVizJs,
               ContainsSubstring("frontend: CUBE_SIZE / 2 + 2 * TIER_GAP"));
    // Classification priority is db > frontend > app; pin the return
    // ordering so a refactor that flips priorities (and lands every
    // co-located db-and-web box in the frontend tier) regresses loudly.
    // Use rfind for the fall-through `return 'app'` so the test matches
    // the trailing default-tier return, not the null-guard early return
    // at the top of classifyTier.
    auto pos_db = yuzu::server::kYuzuVizJs.find("if (dbScore > 0) return 'database'");
    auto pos_web = yuzu::server::kYuzuVizJs.find("if (webScore > 0) return 'frontend'");
    auto pos_default = yuzu::server::kYuzuVizJs.rfind("return 'app'");
    REQUIRE(pos_db != std::string::npos);
    REQUIRE(pos_web != std::string::npos);
    REQUIRE(pos_default != std::string::npos);
    CHECK(pos_db < pos_web);
    CHECK(pos_web < pos_default);
}

TEST_CASE("static_js_bundle: WEB_PORTS contains only classic frontend-tier ports",
          "[static-js][viz][tier-classify]") {
    // Port-based tier classification is a starting heuristic, not the final
    // answer (see follow-up issue on function-aware classification). The
    // contract today: WEB_PORTS is the set of listener ports that mean
    // "this machine is an HTTP-serving frontend / reverse proxy / load
    // balancer" — the **first tier** in a classic three-tier deployment
    // (HSBC-style: API gateway / reverse proxy → app servers → database).
    //
    // Dev-server defaults (express on :3000, angular on :4200, vite on
    // :5173, django dev on :8000) are NOT frontend tier — they're
    // application servers in disguise. A nodejs API listening on :3000
    // belongs on the app plane; the reverse proxy in front of it (on :80)
    // is what owns the frontend plane.
    //
    // Lock the inclusion + exclusion lists so a future "let's just add a
    // port" change can't silently re-misclassify app-tier dev servers.
    CHECK_THAT(yuzu::server::kYuzuVizJs, ContainsSubstring("const WEB_PORTS = new Set(["));
    // Included — classic web tier
    CHECK_THAT(yuzu::server::kYuzuVizJs, ContainsSubstring("80, 443, 8080, 8443"));
    // Excluded — common dev-server ports that are architecturally app-tier
    auto& js = yuzu::server::kYuzuVizJs;
    auto web_start = js.find("const WEB_PORTS = new Set([");
    REQUIRE(web_start != std::string::npos);
    auto web_end = js.find("])", web_start);
    REQUIRE(web_end != std::string::npos);
    auto web_block = js.substr(web_start, web_end - web_start);
    CHECK(web_block.find("3000") == std::string::npos);
    CHECK(web_block.find("4200") == std::string::npos);
    CHECK(web_block.find("5173") == std::string::npos);
    CHECK(web_block.find("8000") == std::string::npos);
}

TEST_CASE("static_js_bundle: kYuzuVizJs drops the origin AxesHelper", "[static-js][viz]") {
    // PR 12 regression guard. The original PR 5 scaffold shipped an
    // AxesHelper(5) so the empty-scene scaffold had an orientation cue;
    // once the three-tier stacked layout landed, the RGB gizmo clipped
    // through the bottom tier and read as a fourth, unexplained signal.
    // It has been deleted; pin the absence so a future "add an axes
    // gizmo" PR has to consciously revisit this decision.
    //
    // Gate 7 QA F6 — if a future PR legitimately needs an orientation
    // gizmo back (e.g., toggled by a URL param for a debug overlay),
    // confirm the new geometry does NOT clip through TIER_Y.database
    // and update this guard to allow the controlled re-introduction
    // (perhaps narrowing to "no unconditional AxesHelper in buildScene").
    CHECK_THAT(yuzu::server::kYuzuVizJs, !ContainsSubstring("AxesHelper"));
}

TEST_CASE("static_js_bundle: kYuzuVizJs renders talking sockets and anchors cross-tier wires",
          "[static-js][viz]") {
    // PR 12: every cube grows a mirror ring of "talking socket" dots on
    // the BOTTOM face — one per unique outbound (proto, dst_ip, dst_port)
    // tuple aggregated from ESTABLISHED connections. The cross-machine
    // edge pass anchors the source end of every wire at the matching dot
    // (looked up via talkingWorldPos) so both ends of a wire are concrete
    // socket primitives, not a cube-centre approximation.
    //
    // Pin: the helper function names, the bottom-face Y constant
    // (negative — mirror of the listener ring above the cube), the
    // userData payload shape, raycast/lifecycle parity with socketMeshes,
    // and the source-end anchor lookup in the edge pass.
    CHECK_THAT(yuzu::server::kYuzuVizJs, ContainsSubstring("extractTalkingDests"));
    CHECK_THAT(yuzu::server::kYuzuVizJs, ContainsSubstring("placeTalkingSocketsOnCube"));
    CHECK_THAT(yuzu::server::kYuzuVizJs, ContainsSubstring("buildTalkingSocketSphere"));
    CHECK_THAT(yuzu::server::kYuzuVizJs,
               ContainsSubstring("TALKING_SOCKET_BOTTOM_Y = -CUBE_SIZE * 0.5"));
    CHECK_THAT(yuzu::server::kYuzuVizJs, ContainsSubstring("yuzuTalkingSocket"));
    // Flat raycast index lives alongside socketMeshes and follows the same
    // lifecycle (declare / reset in clearFleet / push during add).
    CHECK_THAT(yuzu::server::kYuzuVizJs, ContainsSubstring("const talkingSocketMeshes = []"));
    CHECK_THAT(yuzu::server::kYuzuVizJs, ContainsSubstring("talkingSocketMeshes.length = 0"));
    CHECK_THAT(yuzu::server::kYuzuVizJs, ContainsSubstring("talkingSocketMeshes.push(sphere)"));
    // Gate 7 QA F1 BLOCKING — pin that extractTalkingDests filters
    // loopback DESTINATIONS too (mirror of the listener-side filter).
    // A refactor that drops the dst-side `continue` would silently
    // re-introduce intra-host loopback wires as cross-machine talking
    // dots; the F1 pin is specific to that `continue` site.
    CHECK_THAT(yuzu::server::kYuzuVizJs, ContainsSubstring("if (isLoopbackBind(dstIp)) continue"));
    // Gate 7 UP-6 BLOCKING — talkingSocketMeshes must follow the
    // same reset-before-traverse R7 UP-1 invariant as cubeMeshes /
    // processMeshes / socketMeshes. Verify the reset precedes the
    // traverse(disposeNode) walk in clearFleet so a mid-render hover
    // raycast never resolves against a half-disposed mesh.
    auto pos_talk_reset = yuzu::server::kYuzuVizJs.find("talkingSocketMeshes.length = 0");
    auto pos_traverse_for_talk = yuzu::server::kYuzuVizJs.find("child.traverse(disposeNode)");
    REQUIRE(pos_talk_reset != std::string::npos);
    REQUIRE(pos_traverse_for_talk != std::string::npos);
    CHECK(pos_talk_reset < pos_traverse_for_talk);
    // Hover dispatch goes after the listener pass and surfaces the
    // outbound-side tooltip.
    CHECK_THAT(yuzu::server::kYuzuVizJs,
               ContainsSubstring("intersectObjects(talkingSocketMeshes, false)"));
    CHECK_THAT(yuzu::server::kYuzuVizJs, ContainsSubstring("showTalkingSocketTooltip"));
    // Source-end anchor lookup — the edge pass reads the cube's
    // talking-socket world position via `agentId + '|' + dst_ip + ':' + dst_port`.
    CHECK_THAT(yuzu::server::kYuzuVizJs, ContainsSubstring("talkingWorldPos"));
    CHECK_THAT(yuzu::server::kYuzuVizJs, ContainsSubstring("talkingWorldPos.get(talkingKey)"));
    // Listener hits should fire BEFORE talking-socket hits so a hover on
    // a peer's incoming port doesn't get hijacked by an unrelated
    // outgoing dot underneath it (no realistic overlap today, but pin
    // the ordering so refactors don't quietly swap them).
    auto pos_listener = yuzu::server::kYuzuVizJs.find("intersectObjects(socketMeshes, false)");
    auto pos_talking =
        yuzu::server::kYuzuVizJs.find("intersectObjects(talkingSocketMeshes, false)");
    REQUIRE(pos_listener != std::string::npos);
    REQUIRE(pos_talking != std::string::npos);
    CHECK(pos_listener < pos_talking);
}

TEST_CASE("static_js_bundle: kYuzuVizJs renders cross-machine wires as curved tubes",
          "[static-js][viz]") {
    // PR 12: cross-machine edges switched from THREE.Line (1px on every
    // shipping browser) to TubeGeometry along a QuadraticBezierCurve3 so
    // wires get real 3D thickness AND a gentle arc that keeps parallel
    // wires from collapsing onto the same path. The intra-cube loopback
    // edges (PR 8) stay as THREE.LineSegments — their pin is in a
    // different test case and stays satisfied. Pin: the helper name, the
    // curve + tube constructors, and the per-edge bow-key keyed on
    // (srcAgentId, dstIp:dstPort).
    CHECK_THAT(yuzu::server::kYuzuVizJs, ContainsSubstring("buildWireTube"));
    // Internal cross-tier wires use a CubicBezier with vertical
    // end-tangents (exit cube floor going down, re-enter cube ceiling
    // coming down) so the wire reads as "leaves the talking socket
    // straight, runs straight in the middle, lands on the listener
    // straight". External stubs keep the quadratic upward bow.
    CHECK_THAT(yuzu::server::kYuzuVizJs, ContainsSubstring("THREE.CubicBezierCurve3"));
    CHECK_THAT(yuzu::server::kYuzuVizJs, ContainsSubstring("THREE.QuadraticBezierCurve3"));
    CHECK_THAT(yuzu::server::kYuzuVizJs, ContainsSubstring("THREE.TubeGeometry"));
    CHECK_THAT(yuzu::server::kYuzuVizJs, ContainsSubstring("EDGE_TUBE_RADIUS_INTERNAL"));
    CHECK_THAT(yuzu::server::kYuzuVizJs, ContainsSubstring("bowKey:"));
}

TEST_CASE("static_js_bundle: kYuzuVizJs filters loopback-bound listeners off the surface",
          "[static-js][viz]") {
    // PR 12: only listeners that another instance could reach belong on
    // the cube surface. extractListenSockets honours the schema_minor 4
    // `local_addr` field and drops 127.0.0.0/8 and ::1 binds via
    // isLoopbackBind. Pin the helper name, the loopback string literals,
    // and the call site so a refactor that removes the filter (and lets
    // every loopback-only postgres / redis sidecar render on the cube
    // top face) regresses loudly. Pinning v4-mapped-in-v6 separately
    // prevents a half-fix that drops it.
    CHECK_THAT(yuzu::server::kYuzuVizJs, ContainsSubstring("isLoopbackBind"));
    CHECK_THAT(yuzu::server::kYuzuVizJs,
               ContainsSubstring("if (isLoopbackBind(l.local_addr)) continue"));
    CHECK_THAT(yuzu::server::kYuzuVizJs, ContainsSubstring("'::1'"));
    CHECK_THAT(yuzu::server::kYuzuVizJs, ContainsSubstring("'127.'"));
    CHECK_THAT(yuzu::server::kYuzuVizJs, ContainsSubstring("^::ffff:127\\."));
}

TEST_CASE("static_js_bundle: kYuzuVizJs builds translucent cubes with MeshPhysicalMaterial",
          "[static-js][viz]") {
    // gov R6 PR-6: the cube material contract -- transparent + opacity
    // 0.18 (live) / 0.08 (stale). A refactor that swaps to opaque cubes
    // would obscure interior process nodes (PR 7+) and break the visual
    // model.
    //
    // gov R6 QE SHOULD-1/SHOULD-2: bare `0.08` substring matches
    // `dampingFactor=0.08` elsewhere in the bundle (false positive); bare
    // `0.18` has no positional context. Pin the full ternary so the test
    // measures the live-vs-stale opacity *relationship*, not just two
    // numeric tokens that happen to appear somewhere.
    CHECK_THAT(yuzu::server::kYuzuVizJs, ContainsSubstring("MeshPhysicalMaterial"));
    CHECK_THAT(yuzu::server::kYuzuVizJs, ContainsSubstring("transparent: true"));
    CHECK_THAT(yuzu::server::kYuzuVizJs,
               ContainsSubstring("opacity: machine && machine.stale ? 0.08 : 0.18"));
}

TEST_CASE("static_js_bundle: kYuzuVizJs builds Sprite hostname labels", "[static-js][viz]") {
    // Hostname labels via Sprite + CanvasTexture so they always face the
    // camera. Pin both Three classes so a swap to TextGeometry (which
    // doesn't billboard) fails the test.
    CHECK_THAT(yuzu::server::kYuzuVizJs, ContainsSubstring("THREE.Sprite"));
    CHECK_THAT(yuzu::server::kYuzuVizJs, ContainsSubstring("THREE.CanvasTexture"));
    CHECK_THAT(yuzu::server::kYuzuVizJs, ContainsSubstring("buildHostnameLabel"));
}

TEST_CASE("static_js_bundle: kYuzuVizJs uses Raycaster for hover tooltip", "[static-js][viz]") {
    // Hover tooltip is the discovery affordance for a cube's hostname /
    // OS / counts. Without the raycaster wiring the tooltip never fires.
    // Pin both the class and the listener.
    CHECK_THAT(yuzu::server::kYuzuVizJs, ContainsSubstring("THREE.Raycaster"));
    CHECK_THAT(yuzu::server::kYuzuVizJs, ContainsSubstring("'mousemove'"));
    CHECK_THAT(yuzu::server::kYuzuVizJs, ContainsSubstring("intersectObjects"));
}

TEST_CASE("static_js_bundle: kYuzuVizJs creates #viz-tooltip dynamically", "[static-js][viz]") {
    // The tooltip element is created lazily by the renderer (not
    // pre-existing in the page HTML) so the page shell stays minimal.
    // Pin the id so a refactor that renames it doesn't break the
    // tooltip without anybody noticing.
    CHECK_THAT(yuzu::server::kYuzuVizJs, ContainsSubstring("'viz-tooltip'"));
    CHECK_THAT(yuzu::server::kYuzuVizJs, ContainsSubstring("ensureTooltip"));
}

TEST_CASE("static_js_bundle: kYuzuVizJs escapes HTML in tooltip content", "[static-js][viz]") {
    // gov R6 sec-M1: hostname / os come from agent-controlled fields.
    // The tooltip uses .innerHTML for layout convenience, so the values
    // MUST be escaped or an agent-controlled hostname like
    // `<img onerror=alert()>` would execute. Pin both the helper and the
    // mention of escaped chars.
    CHECK_THAT(yuzu::server::kYuzuVizJs, ContainsSubstring("escapeHtml"));
    CHECK_THAT(yuzu::server::kYuzuVizJs, ContainsSubstring("&amp;"));
    CHECK_THAT(yuzu::server::kYuzuVizJs, ContainsSubstring("&lt;"));
}

TEST_CASE("static_js_bundle: kYuzuVizJs fetches with same-origin credentials", "[static-js][viz]") {
    // Same-origin credentials are required so the session cookie travels
    // with the fetch. Without it a logged-in operator would see 401 even
    // though their browser cookie is set.
    CHECK_THAT(yuzu::server::kYuzuVizJs, ContainsSubstring("data-yuzu-viz-url"));
    CHECK_THAT(yuzu::server::kYuzuVizJs, ContainsSubstring("credentials: 'same-origin'"));
}

TEST_CASE("static_js_bundle: kYuzuVizJs handles 401 / 403 / 503 fetch outcomes",
          "[static-js][viz]") {
    // gov R5 UP-17: an admin who is demoted mid-session must see an
    // explicit access-denied message rather than a blank scene. 503
    // covers --viz-disable kill switch flipping under the operator's
    // feet. Pin all three status codes; a refactor that collapses them
    // into a generic catch-all breaks the granular UX.
    CHECK_THAT(yuzu::server::kYuzuVizJs, ContainsSubstring("r.status === 401"));
    CHECK_THAT(yuzu::server::kYuzuVizJs, ContainsSubstring("r.status === 403"));
    CHECK_THAT(yuzu::server::kYuzuVizJs, ContainsSubstring("r.status === 503"));
}

TEST_CASE("static_js_bundle: kYuzuVizJs validates fleet_topology.v1 schema string",
          "[static-js][viz]") {
    // The renderer must reject anything that isn't fleet_topology.v1 --
    // a future schema bump (v2) would land at the same URL during a
    // staged rollout, and rendering with the wrong shape gives nonsense.
    CHECK_THAT(yuzu::server::kYuzuVizJs, ContainsSubstring("fleet_topology.v1"));
}

TEST_CASE("static_js_bundle: kYuzuVizJs guards camera position against NaN/Infinity",
          "[static-js][viz]") {
    // gov R5 UP-7: a single bad input that pushes camera.position into
    // NaN cascades through every subsequent frame (renderer.render with
    // NaN matrices crashes WebGL on some drivers). The render loop must
    // detect and reset to a safe default.
    //
    // gov R6 architect NICE-2: the reset must cover BOTH camera.position
    // and controls.target -- the latter feeds back into camera.position
    // via controls.update() each frame, so resetting only one would
    // re-poison within one frame.
    CHECK_THAT(yuzu::server::kYuzuVizJs, ContainsSubstring("Number.isFinite"));
    CHECK_THAT(yuzu::server::kYuzuVizJs, ContainsSubstring("camera.position.set"));
    CHECK_THAT(yuzu::server::kYuzuVizJs, ContainsSubstring("controls.target.set"));
}

// ── PR 7: process layer (interior nodes coloured by category) ───────────────

TEST_CASE("static_js_bundle: kYuzuVizJs declares CATEGORY_PALETTE for the six categories",
          "[static-js][viz][pr7]") {
    // PR 7 category palette. Each colour is a UX contract — it carries
    // semantic meaning to the operator (browser=blue, db=amber, web=green
    // etc.) so a stealth refactor that swaps a hex code is a deliberate
    // UX decision worth surfacing in PR review. Pin both the palette
    // constant name and every category=hex pair so a refactor that drops
    // or recolours a category fails this test loud.
    CHECK_THAT(yuzu::server::kYuzuVizJs, ContainsSubstring("CATEGORY_PALETTE"));
    CHECK_THAT(yuzu::server::kYuzuVizJs, ContainsSubstring("pickCategoryColor"));
    CHECK_THAT(yuzu::server::kYuzuVizJs, ContainsSubstring("system:   '#6e7681'"));
    CHECK_THAT(yuzu::server::kYuzuVizJs, ContainsSubstring("browser:  '#58a6ff'"));
    CHECK_THAT(yuzu::server::kYuzuVizJs, ContainsSubstring("database: '#d29922'"));
    CHECK_THAT(yuzu::server::kYuzuVizJs, ContainsSubstring("web:      '#56d364'"));
    CHECK_THAT(yuzu::server::kYuzuVizJs, ContainsSubstring("runtime:  '#bc8cff'"));
    CHECK_THAT(yuzu::server::kYuzuVizJs, ContainsSubstring("other:    '#8b949e'"));
}

TEST_CASE("static_js_bundle: kYuzuVizJs lays processes out on hash(pid|ppid)-mod-bucket grid",
          "[static-js][viz][pr7]") {
    // Deterministic interior layout — same fleet renders identically
    // across reloads (mirrors the cube-layout contract above). Pin the
    // function name + the cbrt-derived bucket math + the dual-key hash
    // (pid|ppid for placement, j|pid for jitter). A refactor that swaps
    // to Math.random() breaks the determinism contract; pinning the
    // hash composition catches it.
    CHECK_THAT(yuzu::server::kYuzuVizJs, ContainsSubstring("placeProcessesInCube"));
    CHECK_THAT(yuzu::server::kYuzuVizJs, ContainsSubstring("Math.cbrt"));
    CHECK_THAT(yuzu::server::kYuzuVizJs, ContainsSubstring("hash32(pidStr + '|' + ppidStr)"));
    CHECK_THAT(yuzu::server::kYuzuVizJs, ContainsSubstring("hash32('j|' + pidStr)"));
}

TEST_CASE("static_js_bundle: kYuzuVizJs builds process dots as low-poly spheres",
          "[static-js][viz][pr7]") {
    // Per-process SphereGeometry (6×4 segments) + per-process
    // MeshBasicMaterial. Per-instance materials match the cube pattern
    // so clearFleet's recursive disposeNode walk releases everything
    // without a shared-resource skip flag. A refactor to an InstancedMesh
    // would need its own dispose contract — pin the current pattern so
    // the polish PR makes that decision deliberately.
    CHECK_THAT(yuzu::server::kYuzuVizJs, ContainsSubstring("buildProcessNode"));
    CHECK_THAT(yuzu::server::kYuzuVizJs,
               ContainsSubstring("THREE.SphereGeometry(PROCESS_DOT_RADIUS, 6, 4)"));
    CHECK_THAT(yuzu::server::kYuzuVizJs, ContainsSubstring("THREE.MeshBasicMaterial"));
}

TEST_CASE("static_js_bundle: kYuzuVizJs attaches processGroup as a child of each cube",
          "[static-js][viz][pr7]") {
    // gov R6 architect NICE-1 decision: per-machine subgroup, NOT a
    // single sibling processGroup. Attaching the dots as cube children
    // (a) makes PR 8 localhost edges trivial (per-cube lookup), (b)
    // gives clearFleet's traverse() walk free dispose without an extra
    // sweep pass, (c) makes per-cube LOD culling in PR 11 a one-liner.
    // Pin both the named-group string and the cube.add(processGroup)
    // call so a refactor to a sibling-group model fails loud.
    CHECK_THAT(yuzu::server::kYuzuVizJs, ContainsSubstring("processGroup.name = 'yuzu-processes'"));
    CHECK_THAT(yuzu::server::kYuzuVizJs, ContainsSubstring("cube.add(processGroup)"));
}

TEST_CASE("static_js_bundle: kYuzuVizJs raycasts processMeshes BEFORE cubeMeshes",
          "[static-js][viz][pr7]") {
    // PR 7 hover-ordering invariant. Process dots are inside translucent
    // cubes; if intersectObjects picks the closest hit across both sets
    // the cube's outer face always wins by distance and the operator
    // can never hover a dot to see process details. Pin the
    // processMeshes-first raycast pattern so a refactor that combines
    // both arrays (or flips the order) fails loud.
    auto pos_proc = yuzu::server::kYuzuVizJs.find("intersectObjects(processMeshes, false)");
    auto pos_cube = yuzu::server::kYuzuVizJs.find("intersectObjects(cubeMeshes, false)");
    REQUIRE(pos_proc != std::string::npos);
    REQUIRE(pos_cube != std::string::npos);
    CHECK(pos_proc < pos_cube);
}

TEST_CASE("static_js_bundle: kYuzuVizJs surfaces process tooltip with pid/name/user/category",
          "[static-js][viz][pr7]") {
    // Demo target for PR 7: hover a process and see pid/name/user/category.
    // Pin the function name and every interpolated label so a refactor
    // that drops a field (e.g. "user") fails loud.
    CHECK_THAT(yuzu::server::kYuzuVizJs, ContainsSubstring("showProcessTooltip"));
    CHECK_THAT(yuzu::server::kYuzuVizJs, ContainsSubstring("'pid '"));
    CHECK_THAT(yuzu::server::kYuzuVizJs, ContainsSubstring("'<div>user: '"));
    CHECK_THAT(yuzu::server::kYuzuVizJs, ContainsSubstring("'<div>category: '"));
}

TEST_CASE("static_js_bundle: kYuzuVizJs escapes HTML in process tooltip fields",
          "[static-js][viz][pr7]") {
    // Process name + user are agent-controlled. Without escapeHtml on
    // every interpolated string an agent-controlled name like
    // `<img onerror=alert()>` would execute on hover. The cube tooltip
    // already pins escapeHtml; this test pins that the SAME helper is
    // applied to the process tooltip's three interpolated string fields.
    // We assert via the showProcessTooltip body presence (above) plus
    // a `(process && process.<field>)` substring inside the per-field
    // tooltip null-coalesce. The full wrap is
    // `escapeHtml(clampForTooltip((process && process.<field>) || ...))`
    // — clampForTooltip caps agent-controlled strings at TOOLTIP_NAME_MAX
    // BEFORE escapeHtml's synchronous regex (gov R7 UP-10), then
    // escapeHtml escapes the bytes. Pinning `clampForTooltip((process &&`
    // catches refactors that drop either wrap.
    CHECK_THAT(yuzu::server::kYuzuVizJs,
               ContainsSubstring("clampForTooltip((process && process.name)"));
    CHECK_THAT(yuzu::server::kYuzuVizJs,
               ContainsSubstring("clampForTooltip((process && process.user)"));
    CHECK_THAT(yuzu::server::kYuzuVizJs,
               ContainsSubstring("clampForTooltip((process && process.category)"));
}

TEST_CASE("static_js_bundle: kYuzuVizJs coerces process pid through Number(...) | 0",
          "[static-js][viz][pr7]") {
    // Mirror of the cube tooltip's pid coercion — agent-controlled pids
    // could theoretically be strings; coerce to a 32-bit integer so the
    // template never interpolates raw agent strings as numerics.
    CHECK_THAT(yuzu::server::kYuzuVizJs, ContainsSubstring("Number(process && process.pid) | 0"));
}

TEST_CASE("static_js_bundle: kYuzuVizJs maintains a flat processMeshes raycast index",
          "[static-js][viz][pr7]") {
    // The flat array (rather than walking the per-cube subgroups every
    // frame) is the perf contract: raycaster does one matrixWorld read
    // per dot instead of recursing into N machines × M children. Pin
    // both the declaration AND the clearFleet reset so a refactor that
    // drops the array but keeps the raycast call (or vice versa) fails.
    CHECK_THAT(yuzu::server::kYuzuVizJs, ContainsSubstring("const processMeshes = []"));
    CHECK_THAT(yuzu::server::kYuzuVizJs, ContainsSubstring("processMeshes.length = 0"));
    CHECK_THAT(yuzu::server::kYuzuVizJs, ContainsSubstring("processMeshes.push(dot)"));
}

// ── PR 7 hardening (R7 round) ───────────────────────────────────────────────

TEST_CASE("static_js_bundle: kYuzuVizJs hardens pickCategoryColor against prototype walk",
          "[static-js][viz][pr7][hardening]") {
    // gov R7 sec-MEDIUM / UP-8: agent-controlled (or future-bug-injected)
    // category="constructor"/"toString"/"__proto__" must not walk the
    // prototype chain and return a truthy non-string that `||` fallback
    // accepts as a valid hex. Pin the hasOwnProperty.call guard + the
    // String(category).trim().toLowerCase() normalisation so a refactor
    // that drops either falls loud.
    CHECK_THAT(yuzu::server::kYuzuVizJs,
               ContainsSubstring("Object.prototype.hasOwnProperty.call(CATEGORY_PALETTE, k)"));
    CHECK_THAT(yuzu::server::kYuzuVizJs,
               ContainsSubstring("String(category).trim().toLowerCase()"));
}

TEST_CASE("static_js_bundle: kYuzuVizJs raycaster ordering occurs exactly twice",
          "[static-js][viz][pr7][hardening]") {
    // gov R7 qe-S1 (PR 7) pinned this to == 1: the position-ordering
    // assertion (procHits before cubeHits) is correct but only checks
    // FIRST occurrences, so a future refactor adding a SECOND
    // `intersectObjects(processMeshes ...)` call AFTER the cube call
    // (e.g. a debug fallback) would still satisfy the position
    // invariant. Pinned to a hard count to catch accidental duplicate
    // raycasts.
    //
    // Slice 3 (PR 9-pre) deliberately adds a SECOND raycast site —
    // the dblclick handler must run its own hit-test to know whether
    // the user double-clicked a cube vs a higher-priority hover
    // target (socket / process). The invariant relaxes from "== 1"
    // to "== 2": exactly the mousemove site + exactly the dblclick
    // site, no more. Any third call still regresses the test.
    auto count_substr = [](const std::string& hay, const std::string& needle) {
        size_t n = 0;
        size_t pos = 0;
        while ((pos = hay.find(needle, pos)) != std::string::npos) {
            ++n;
            pos += needle.size();
        }
        return n;
    };
    CHECK(count_substr(yuzu::server::kYuzuVizJs, "intersectObjects(processMeshes, false)") == 2);
    CHECK(count_substr(yuzu::server::kYuzuVizJs, "intersectObjects(cubeMeshes, false)") == 2);
}

TEST_CASE("static_js_bundle: kYuzuVizJs processGroup is parented to cube (not fleetGroup)",
          "[static-js][viz][pr7][hardening]") {
    // gov R7 qe-S2: the architecture pick is per-machine subgroup
    // attached to the cube. A refactor that re-parents the group to
    // fleetGroup (sibling pattern) without removing `cube.add(processGroup)`
    // would still pass the positive substring check above. Pin the
    // negative — `fleetGroup.add(processGroup)` MUST NOT appear.
    CHECK_THAT(yuzu::server::kYuzuVizJs, !ContainsSubstring("fleetGroup.add(processGroup)"));
}

TEST_CASE("static_js_bundle: kYuzuVizJs guards process build with try/catch",
          "[static-js][viz][pr7][hardening]") {
    // gov R7 UP-2: a throw inside buildProcessNode (e.g. THREE.Color on
    // a malformed palette hex from a future typo) must NOT cascade out
    // of addMachines. Pin the try/catch surrounding the per-process
    // mesh construction so a refactor that drops the guard fails loud.
    CHECK_THAT(yuzu::server::kYuzuVizJs,
               ContainsSubstring("Yuzu viz: buildProcessNode failed; skipping dot."));
}

TEST_CASE("static_js_bundle: kYuzuVizJs clearFleet resets indices BEFORE traverse",
          "[static-js][viz][pr7][hardening]") {
    // gov R7 UP-1: if `traverse(disposeNode)` throws partway through
    // (corrupt child material, future PR 8 edgeMesh with already-disposed
    // geometry), the function exits without resetting cubeMeshes or
    // processMeshes — leaving stale references the next mousemove
    // raycasts against. Reset BEFORE the loop so a throw still leaves
    // the indices empty (worst case: benign empty raycast). Pin the
    // ordering: both `length = 0` resets must appear before the
    // `while (fleetGroup.children.length > 0)` loop body.
    auto pos_cube_reset = yuzu::server::kYuzuVizJs.find("cubeMeshes.length = 0");
    auto pos_proc_reset = yuzu::server::kYuzuVizJs.find("processMeshes.length = 0");
    auto pos_traverse = yuzu::server::kYuzuVizJs.find("child.traverse(disposeNode)");
    REQUIRE(pos_cube_reset != std::string::npos);
    REQUIRE(pos_proc_reset != std::string::npos);
    REQUIRE(pos_traverse != std::string::npos);
    CHECK(pos_cube_reset < pos_traverse);
    CHECK(pos_proc_reset < pos_traverse);
}

TEST_CASE("static_js_bundle: kYuzuVizJs caps tooltip name length (CPU DoS guard)",
          "[static-js][viz][pr7][hardening]") {
    // gov R7 UP-10: a 1MB process.name from a pathological cmdline-as-comm
    // parse would stutter the tooltip render via synchronous regex over
    // the full string in escapeHtml. Truncate to 256 chars before
    // escapeHtml so the worst-case hover stays under the 16ms frame
    // budget. Pin both the helper and the cap constant.
    CHECK_THAT(yuzu::server::kYuzuVizJs, ContainsSubstring("clampForTooltip"));
    CHECK_THAT(yuzu::server::kYuzuVizJs, ContainsSubstring("TOOLTIP_NAME_MAX = 256"));
}

TEST_CASE("static_js_bundle: kYuzuVizJs soft-caps process count per cube",
          "[static-js][viz][pr7][hardening]") {
    // gov R7 CAP-1 / SRE: agent-side kFleetSnapshotMaxRows is 4096.
    // 4096 procs × 5000 machines = 20M dots worst-case — well past
    // anything WebGL can handle pre-InstancedMesh (PR 11). Soft-cap
    // dots per cube at PROCESS_PER_CUBE_SOFT_CAP for graceful
    // degradation; the cube tooltip still shows the true count.
    CHECK_THAT(yuzu::server::kYuzuVizJs, ContainsSubstring("PROCESS_PER_CUBE_SOFT_CAP = 1000"));
}

TEST_CASE("static_js_bundle: kYuzuVizJs rAF-throttles the raycaster",
          "[static-js][viz][pr7][hardening]") {
    // gov R7 perf-F1: mousemove fires up to 120 Hz on macOS trackpads;
    // bidirectional intersectObjects against potentially 10k+ meshes
    // makes raycast the dominant CPU cost. Coalesce events to one
    // raycast per requestAnimationFrame tick (~60 Hz cap). Pin the
    // throttle pattern so a refactor that re-introduces direct
    // mousemove → raycast fails the test.
    CHECK_THAT(yuzu::server::kYuzuVizJs, ContainsSubstring("_rafScheduled"));
    CHECK_THAT(yuzu::server::kYuzuVizJs, ContainsSubstring("_pendingMouseEvt"));
    CHECK_THAT(yuzu::server::kYuzuVizJs, ContainsSubstring("processPendingMouse"));
    CHECK_THAT(yuzu::server::kYuzuVizJs,
               ContainsSubstring("requestAnimationFrame(processPendingMouse)"));
}

TEST_CASE("static_js_bundle: kYuzuVizJs has a sane size budget",
          "[static-js][viz][pr7][hardening]") {
    // gov R7 OBS-1 / perf-F4: every other vendored bundle has a pinned
    // size or floor. kYuzuVizJs only had `>= 1000`. Add a sane upper
    // bound so PR 8/9/10/11 additions trip a guard rather than silently
    // bloating the served asset to multi-MB. The cap was 80KB after R7;
    // PR 12 (three-tier layout + loopback filter + talking sockets +
    // curved-tube cross-tier wires) pushed the bundle to ~82KB. Cap
    // raised to 96KB to give the remaining feature PRs ~13KB of
    // headroom without making the cap perpetually irrelevant. If a
    // future PR legitimately needs more, raise this constant
    // deliberately.
    REQUIRE(yuzu::server::kYuzuVizJs.size() >= 1000);
    CHECK(yuzu::server::kYuzuVizJs.size() < 96 * 1024);
}

// ── Fleet viz page HTML scaffold ────────────────────────────────────────────

TEST_CASE("viz page: contains the persistent canvas + viz-root structure", "[viz][page]") {
    REQUIRE(kVizFleetPageHtml != nullptr);
    std::string html(kVizFleetPageHtml);
    REQUIRE(html.size() >= 500);
    // The yuzu-viz.js mount contract relies on these three exact
    // attributes/ids; pinning them here means a future refactor that
    // renames either side fails the test instead of producing a
    // working-on-localhost-broken-on-server-restart silent regression.
    CHECK_THAT(html, ContainsSubstring("data-yuzu-viz-url=\"/api/v1/viz/fleet/topology\""));
    CHECK_THAT(html, ContainsSubstring("id=\"viz-root\""));
    CHECK_THAT(html, ContainsSubstring("id=\"viz-canvas\""));
    CHECK_THAT(html, ContainsSubstring("id=\"viz-overlay-panel\""));
}

TEST_CASE("viz page: declares importmap for three + addons", "[viz][page]") {
    // Three.js (r150+) is ES-module-only upstream; the importmap resolves
    // the bare `import 'three'` specifier in OrbitControls and yuzu-viz.js
    // to the vendored bundle. Without this map, the module network request
    // would 404 against the bare name.
    std::string html(kVizFleetPageHtml);
    CHECK_THAT(html, ContainsSubstring("type=\"importmap\""));
    CHECK_THAT(html, ContainsSubstring("\"three\": \"/static/three.module.min.js\""));
    CHECK_THAT(html, ContainsSubstring("/static/three-orbit-controls.js"));
}

TEST_CASE("viz page: importmap appears EXACTLY ONCE", "[viz][page]") {
    // gov R4 sec-L2 / QA-S3 / CHAOS-1: HTML spec allows only one
    // importmap per document. A second declaration is silently ignored
    // by the browser. Pin exactly-one occurrence so a future refactor
    // that accidentally inserts a second importmap (e.g. a copy-paste
    // into a sibling page shell) fails this test instead of breaking
    // module resolution at runtime.
    std::string html(kVizFleetPageHtml);
    auto first = html.find("type=\"importmap\"");
    REQUIRE(first != std::string::npos);
    CHECK(html.find("type=\"importmap\"", first + 1) == std::string::npos);
}

TEST_CASE("viz page: yuzu-viz.js module loader appears EXACTLY ONCE", "[viz][page]") {
    // Two `<script type="module" src="/static/yuzu-viz.js">` tags would
    // load the renderer twice. The mount() guard absorbs double-mount
    // for HTMX swaps but the duplicate load itself wastes 6 KB and
    // duplicates the global `htmx:afterSettle` listener registration
    // (UP-5 amplifier). Pin singleton.
    std::string html(kVizFleetPageHtml);
    auto needle = "<script type=\"module\" src=\"/static/yuzu-viz.js\">";
    auto first = html.find(needle);
    REQUIRE(first != std::string::npos);
    CHECK(html.find(needle, first + 1) == std::string::npos);
}

TEST_CASE("viz page: importmap precedes the type=module loader", "[viz][page]") {
    // gov R4 UP-1 / CHAOS-1: HTML spec requires the importmap to be
    // parsed BEFORE any `<script type="module">` that depends on it.
    // A future refactor that moves the importmap into <body>, or
    // injects a module-script ahead of it, would silently break module
    // resolution. Assert the position invariant directly.
    std::string html(kVizFleetPageHtml);
    auto importmap_pos = html.find("type=\"importmap\"");
    auto module_pos = html.find("<script type=\"module\" src=\"/static/yuzu-viz.js\">");
    REQUIRE(importmap_pos != std::string::npos);
    REQUIRE(module_pos != std::string::npos);
    CHECK(importmap_pos < module_pos);
}

TEST_CASE("viz page: importmap-support detection runs before importmap", "[viz][page]") {
    // gov R4 UP-16 / ER-SHOULD-1: browsers without importmap support
    // need a non-module fallback that surfaces a visible error rather
    // than leaving a blank canvas. Detection uses
    // HTMLScriptElement.supports('importmap'); pin the substring AND
    // its position relative to the importmap so a refactor can't move
    // it after.
    std::string html(kVizFleetPageHtml);
    auto detect_pos = html.find("HTMLScriptElement.supports");
    auto importmap_pos = html.find("type=\"importmap\"");
    REQUIRE(detect_pos != std::string::npos);
    REQUIRE(importmap_pos != std::string::npos);
    CHECK(detect_pos < importmap_pos);
    CHECK_THAT(html, ContainsSubstring("__yuzuVizImportmapSupported"));
}

TEST_CASE("viz page: loads yuzu-viz.js as type=module", "[viz][page]") {
    // type="module" is required so the ES imports resolve. A
    // type="text/javascript" (or omitted-type) tag would parse the file
    // as a classic script and the `import` statements at the top would
    // be SyntaxErrors at parse time.
    std::string html(kVizFleetPageHtml);
    CHECK_THAT(html, ContainsSubstring("<script type=\"module\" src=\"/static/yuzu-viz.js\">"));
}

TEST_CASE("viz page: nav highlights Fleet Viz when on the page", "[viz][page]") {
    std::string html(kVizFleetPageHtml);
    CHECK_THAT(html, ContainsSubstring("href=\"/viz/fleet\" class=\"nav-link active\""));
}

// ── Inter variable webfont (woff2 binary) ───────────────────────────────────

TEST_CASE("static_js_bundle: kInterVariableWoff2 has expected pinned size", "[static-js][inter]") {
    CHECK(yuzu::server::kInterVariableWoff2.size() == kExpectedInterWoff2Bytes);
}

TEST_CASE("static_js_bundle: kInterVariableWoff2 begins with WOFF2 magic", "[static-js][inter]") {
    REQUIRE(yuzu::server::kInterVariableWoff2.size() >= 4);
    // WOFF2 file format: signature 0x774F4632 ('wOF2') at offset 0.
    auto sv = yuzu::server::kInterVariableWoff2;
    CHECK(static_cast<unsigned char>(sv[0]) == 0x77);
    CHECK(static_cast<unsigned char>(sv[1]) == 0x4F);
    CHECK(static_cast<unsigned char>(sv[2]) == 0x46);
    CHECK(static_cast<unsigned char>(sv[3]) == 0x32);
}

// ── Yuzu Design System CSS bundle ───────────────────────────────────────────

TEST_CASE("static_js_bundle: kYuzuCss is at least 20 KB", "[static-js][yuzu-css]") {
    // Sanity floor — a single-chunk truncation would silently drop content.
    CHECK(yuzu::server::kYuzuCss.size() >= kYuzuCssMinBytes);
}

TEST_CASE("static_js_bundle: kYuzuCss carries the design-system token layer",
          "[static-js][yuzu-css]") {
    // Anchor on tokens introduced in the design-system sweep.
    CHECK_THAT(yuzu::server::kYuzuCss, ContainsSubstring("--mds-color-theme-background-canvas"));
    CHECK_THAT(yuzu::server::kYuzuCss,
               ContainsSubstring("--mds-color-theme-accent-primary-normal"));
    CHECK_THAT(yuzu::server::kYuzuCss, ContainsSubstring("--mds-color-chart-1"));
    CHECK_THAT(yuzu::server::kYuzuCss, ContainsSubstring("@font-face"));
    CHECK_THAT(yuzu::server::kYuzuCss, ContainsSubstring("'Inter'"));
}

TEST_CASE("static_js_bundle: kYuzuCss has no embedded NULs", "[static-js][yuzu-css]") {
    CHECK(yuzu::server::kYuzuCss.find('\0') == std::string::npos);
    // (See kEChartsJs counterpart — stray-delimiter check is tautological
    // at runtime; build-time guard in embed_js.py is the real protection.)
}

// ── Yuzu chart adapter (kYuzuChartsJs) ──────────────────────────────────────

TEST_CASE("static_js_bundle: kYuzuChartsJs is at least 6 KB", "[static-js][yuzu-charts]") {
    CHECK(yuzu::server::kYuzuChartsJs.size() >= kYuzuChartsMinBytes);
}

TEST_CASE("static_js_bundle: kYuzuChartsJs exposes the YuzuCharts global",
          "[static-js][yuzu-charts]") {
    CHECK_THAT(yuzu::server::kYuzuChartsJs, ContainsSubstring("window.YuzuCharts"));
    CHECK_THAT(yuzu::server::kYuzuChartsJs, ContainsSubstring("echarts.init"));
    CHECK_THAT(yuzu::server::kYuzuChartsJs, ContainsSubstring("htmx:afterSettle"));
}

TEST_CASE("static_js_bundle: kYuzuChartsJs reads design-system chart tokens",
          "[static-js][yuzu-charts]") {
    // The adapter resolves --mds-color-chart-* via getComputedStyle at
    // render time (governance Gate 3 architecture-N3). Drift in this
    // surface should fail the test.
    CHECK_THAT(yuzu::server::kYuzuChartsJs, ContainsSubstring("--mds-color-chart-1"));
    CHECK_THAT(yuzu::server::kYuzuChartsJs,
               ContainsSubstring("--mds-color-theme-background-solid-primary"));
}

TEST_CASE("static_js_bundle: kYuzuChartsJs has no embedded NULs", "[static-js][yuzu-charts]") {
    CHECK(yuzu::server::kYuzuChartsJs.find('\0') == std::string::npos);
}

TEST_CASE("static_js_bundle: kYuzuChartsJs renders an empty-state message on no data",
          "[static-js][yuzu-charts]") {
    // Governance Gate 4 HP-1: empty-data payloads should fall through to
    // emptyState() with an operator-facing message instead of painting a
    // blank canvas. Pin the message string so a future renderer rewrite
    // can't silently remove it.
    CHECK_THAT(yuzu::server::kYuzuChartsJs, ContainsSubstring("No data to plot."));
    CHECK_THAT(yuzu::server::kYuzuChartsJs, ContainsSubstring("isEmptyData"));
}

TEST_CASE("static_js_bundle: kYuzuChartsJs surfaces a cut visualization result in-card",
          "[static-js][yuzu-charts]") {
    // The visualization route stamps rows_capped (row cap only) and
    // result_truncated_by_cap + truncation_cause (row_cap | byte_cap) on a cut
    // payload. The chart is fetched independently of the results table, so the
    // adapter is the only place an operator can see that the picture is partial.
    // Pin that it consumes all three fields and renders the notice with
    // textContent (never innerHTML) from the payload.
    const auto& js = yuzu::server::kYuzuChartsJs;
    CHECK_THAT(js, ContainsSubstring("function truncationNotice"));
    CHECK_THAT(js, ContainsSubstring("data.result_truncated_by_cap"));
    CHECK_THAT(js, ContainsSubstring("data.rows_capped"));
    CHECK_THAT(js, ContainsSubstring("data.truncation_cause"));
    CHECK_THAT(js, ContainsSubstring("yuzu-chart-truncated"));
    CHECK_THAT(js, ContainsSubstring("result-degrade-banner"));
    CHECK_THAT(js, ContainsSubstring("note.textContent = msg"));
    CHECK_THAT(js, ContainsSubstring("Partial result:"));
    // CSP is script-src 'self' 'unsafe-inline' with no unsafe-eval.
    CHECK_THAT(js, !ContainsSubstring("new Function("));
    CHECK_THAT(js, !ContainsSubstring("eval("));
}

// ── Per-host page shell (PR 9-pre, /viz/host/<agent_id>) ────────────────────

TEST_CASE("static_js_bundle: kVizHostPageHtml renders IPC graph mount point", "[viz-host][page]") {
    REQUIRE(kVizHostPageHtml != nullptr);
    std::string html(kVizHostPageHtml);
    CHECK_THAT(html, ContainsSubstring("id=\"ipc-graph\""));
}

TEST_CASE("static_js_bundle: kVizHostPageHtml renders TAR tree mount point", "[viz-host][page]") {
    std::string html(kVizHostPageHtml);
    CHECK_THAT(html, ContainsSubstring("id=\"tar-tree\""));
}

TEST_CASE("static_js_bundle: kVizHostPageHtml binds via data-agent-id attribute",
          "[viz-host][page]") {
    // The renderer reads agent_id from data-agent-id on the mount root.
    // The attribute is templated by the page-route handler at request time;
    // the static HTML uses a sentinel placeholder.
    std::string html(kVizHostPageHtml);
    CHECK_THAT(html, ContainsSubstring("data-agent-id"));
}

TEST_CASE("static_js_bundle: kVizHostPageHtml imports cytoscape via importmap",
          "[viz-host][page]") {
    std::string html(kVizHostPageHtml);
    // Vendored, not CDN — page must not reach off-box for the graph lib.
    CHECK_THAT(html, ContainsSubstring("\"cytoscape\""));
    CHECK_THAT(html, ContainsSubstring("/static/cytoscape"));
}

// ── Per-host renderer bundle (yuzu-viz-host.js) ─────────────────────────────

namespace yuzu::server {
extern const std::string kYuzuVizHostJs;
extern const std::string kCytoscapeJs;
} // namespace yuzu::server

TEST_CASE("static_js_bundle: kYuzuVizHostJs imports cytoscape", "[static-js][viz-host]") {
    CHECK_THAT(yuzu::server::kYuzuVizHostJs, ContainsSubstring("cytoscape"));
}

TEST_CASE("static_js_bundle: kYuzuVizHostJs fetches per-host topology endpoint",
          "[static-js][viz-host]") {
    // Renderer must call fetch() with /api/v1/viz/host/<agent_id>/topology.
    // The "fetch(" call site + URL fragment together is much harder to
    // satisfy with a comment than either alone.
    CHECK_THAT(yuzu::server::kYuzuVizHostJs, ContainsSubstring("fetch("));
    CHECK_THAT(yuzu::server::kYuzuVizHostJs, ContainsSubstring("/api/v1/viz/host/"));
    // Schema gate (UP-17 mirror — render must reject non-host_topology.v1
    // responses, just like the fleet renderer rejects non-fleet_topology.v1).
    CHECK_THAT(yuzu::server::kYuzuVizHostJs, ContainsSubstring("host_topology.v1"));
}

TEST_CASE("static_js_bundle: kYuzuVizHostJs builds bipartite process + socket nodes",
          "[static-js][viz-host]") {
    // Schema decision: nodes are typed by `kind` so the renderer can apply
    // distinct styles per node type. Process nodes from machine.processes,
    // socket nodes from machine.listeners + the local-loopback halves of
    // machine.connections.
    CHECK_THAT(yuzu::server::kYuzuVizHostJs, ContainsSubstring("\"process\""));
    CHECK_THAT(yuzu::server::kYuzuVizHostJs, ContainsSubstring("\"socket\""));
    CHECK_THAT(yuzu::server::kYuzuVizHostJs, ContainsSubstring("\"owns\""));
}

TEST_CASE("static_js_bundle: kYuzuVizHostJs uses the built-in cose layout",
          "[static-js][viz-host]") {
    // cose ("Compound Spring Embedder") is force-directed and ships in
    // cytoscape core — no extension, no cytoscape.use(), no dependency
    // tree. fcose (a faster reimplementation) was dropped because it's a
    // UMD bundle with an external cose-base dependency that doesn't
    // resolve cleanly alongside an ESM importmap.
    CHECK_THAT(yuzu::server::kYuzuVizHostJs, ContainsSubstring("name: \"cose\""));
    // Guard the actual regression — not the word "fcose" (which appears in
    // an explanatory comment) but its *use*: a `name: "fcose"` layout or a
    // cytoscape.use() extension-registration call. cose is built into
    // cytoscape core; needing neither is the whole point of the switch.
    CHECK(yuzu::server::kYuzuVizHostJs.find("name: \"fcose\"") == std::string::npos);
    CHECK(yuzu::server::kYuzuVizHostJs.find("cytoscape.use(") == std::string::npos);
}

TEST_CASE("static_js_bundle: kYuzuVizHostJs wires a refresh button", "[static-js][viz-host]") {
    // Slice 2: manual refresh fetches the topology again. Locked here to
    // prevent a future renderer rewrite from silently dropping the button.
    CHECK_THAT(yuzu::server::kYuzuVizHostJs, ContainsSubstring("refresh"));
}

TEST_CASE("static_js_bundle: kYuzuVizHostJs surfaces stale banner on stale topology",
          "[static-js][viz-host]") {
    // UX invariant: a stale snapshot must visibly inform the operator —
    // never render stale data silently as fresh.
    CHECK_THAT(yuzu::server::kYuzuVizHostJs, ContainsSubstring("stale"));
}

TEST_CASE("static_js_bundle: kYuzuVizHostJs handles 401, 403, 503 explicitly",
          "[static-js][viz-host]") {
    // UP-17 mirror: do not collapse auth/disable failures into a generic
    // error. Each must produce its own user-visible message.
    CHECK_THAT(yuzu::server::kYuzuVizHostJs, ContainsSubstring("401"));
    CHECK_THAT(yuzu::server::kYuzuVizHostJs, ContainsSubstring("403"));
    CHECK_THAT(yuzu::server::kYuzuVizHostJs, ContainsSubstring("503"));
}

// ── 3D viz dblclick → drill-down (Slice 3) ──────────────────────────────────

TEST_CASE("static_js_bundle: kYuzuVizJs listens for dblclick on the canvas",
          "[static-js][viz][dblclick]") {
    CHECK_THAT(yuzu::server::kYuzuVizJs, ContainsSubstring("dblclick"));
}

TEST_CASE("static_js_bundle: kYuzuVizJs dblclick opens /viz/host/<id> in a new tab",
          "[static-js][viz][dblclick]") {
    // window.open is the bridge; noopener+noreferrer is mandatory for any
    // operator-triggered cross-window navigation (gov sec — child window
    // must not get window.opener back to a privileged context).
    CHECK_THAT(yuzu::server::kYuzuVizJs, ContainsSubstring("window.open"));
    CHECK_THAT(yuzu::server::kYuzuVizJs, ContainsSubstring("/viz/host/"));
    CHECK_THAT(yuzu::server::kYuzuVizJs, ContainsSubstring("noopener"));
    CHECK_THAT(yuzu::server::kYuzuVizJs, ContainsSubstring("noreferrer"));
    // The path parameter must be URI-encoded — agent_id may contain
    // characters that would otherwise re-route. encodeURIComponent is
    // the smallest sufficient encoder.
    CHECK_THAT(yuzu::server::kYuzuVizJs, ContainsSubstring("encodeURIComponent"));
}

TEST_CASE("static_js_bundle: kYuzuVizJs dblclick respects raycast hit-order",
          "[static-js][viz][dblclick]") {
    // Slice 3 invariant: dblclick must not steal hits from sockets,
    // processes, or talking-sockets — they have higher priority on the
    // hover surface and reserving them for future per-port/per-process
    // drill-down keeps the cube the single "open new tab" target. The
    // implementation reuses the existing _ray Raycaster rather than
    // constructing a new one (every Raycaster instantiation allocates
    // a couple of Vec3s).
    CHECK_THAT(yuzu::server::kYuzuVizJs, ContainsSubstring("socketMeshes"));
    CHECK_THAT(yuzu::server::kYuzuVizJs, ContainsSubstring("processMeshes"));
    // Bundle contains exactly one "new THREE.Raycaster()" instantiation
    // — the existing _ray used by mousemove. dblclick must not add a
    // second one.
    const auto& js = yuzu::server::kYuzuVizJs;
    auto count = std::size_t{0};
    for (auto pos = js.find("new THREE.Raycaster"); pos != std::string::npos;
         pos = js.find("new THREE.Raycaster", pos + 1)) {
        ++count;
    }
    CHECK(count == 1u);
}

TEST_CASE("static_js_bundle: kYuzuVizJs heartbeat flash has 100/200/350 ms timing",
          "[static-js][viz][dblclick]") {
    // Locked by spec: first (lower) peak at 100 ms, second (higher) peak
    // at 200 ms, settles by 350 ms. All three constants must appear in
    // the same renderer source.
    CHECK_THAT(yuzu::server::kYuzuVizJs, ContainsSubstring("100"));
    CHECK_THAT(yuzu::server::kYuzuVizJs, ContainsSubstring("200"));
    CHECK_THAT(yuzu::server::kYuzuVizJs, ContainsSubstring("350"));
    // Heartbeat metaphor named explicitly so a future refactor doesn't
    // silently drop the visual feedback.
    CHECK_THAT(yuzu::server::kYuzuVizJs, ContainsSubstring("heartbeat"));
}

TEST_CASE("static_js_bundle: kYuzuVizJs wires Cmd/Ctrl-click accelerator",
          "[static-js][viz][dblclick]") {
    // Browser parity: Cmd-click (macOS) / Ctrl-click (Linux/Windows) on a
    // hyperlink opens it in a new tab. The cube should honour the same
    // convention so power users don't have to double-click for the same
    // result.
    CHECK_THAT(yuzu::server::kYuzuVizJs, ContainsSubstring("metaKey"));
    CHECK_THAT(yuzu::server::kYuzuVizJs, ContainsSubstring("ctrlKey"));
}

// ── Slice 4: cross-pane sync + resizable splitter ───────────────────────────

TEST_CASE("static_js_bundle: kYuzuVizHostJs dispatches process-select CustomEvent",
          "[static-js][viz-host][sync]") {
    // Slice 4 invariant: clicking a process node in the IPC graph dispatches
    // a 'yuzu:select-process' CustomEvent carrying the pid; the page-shell
    // listens for it and scrolls/highlights the matching <details data-pid>
    // in the TAR tree below. One-way (IPC graph → TAR tree) for v1.
    CHECK_THAT(yuzu::server::kYuzuVizHostJs, ContainsSubstring("yuzu:select-process"));
    CHECK_THAT(yuzu::server::kYuzuVizHostJs, ContainsSubstring("CustomEvent"));
}

TEST_CASE("static_js_bundle: kVizHostPageHtml listens for process-select CustomEvent",
          "[viz-host][page][sync]") {
    // The receiver side lives inline in the page-shell HTML so the TAR
    // fragment's <details data-pid> can be reached after HTMX swap.
    std::string html(kVizHostPageHtml);
    CHECK_THAT(html, ContainsSubstring("yuzu:select-process"));
    CHECK_THAT(html, ContainsSubstring("scrollIntoView"));
}

TEST_CASE("static_js_bundle: kVizHostPageHtml has a resizable splitter persisted in localStorage",
          "[viz-host][page][splitter]") {
    // The splitter between #ipc-graph and #tar-tree is draggable; the
    // ratio persists across reloads via localStorage so an operator's
    // preferred layout sticks. Default 60/40 (IPC top, TAR bottom) per
    // the grilling decisions.
    std::string html(kVizHostPageHtml);
    CHECK_THAT(html, ContainsSubstring("yuzuVizHostSplitRatio"));
    CHECK_THAT(html, ContainsSubstring("localStorage"));
    CHECK_THAT(html, ContainsSubstring("splitter"));
}

TEST_CASE("static_js_bundle: kVizHostPageHtml does not reference any CDN",
          "[viz-host][page][security]") {
    // Sec invariant: no off-box dependency loading. cytoscape must be
    // vendored and served from /static (mirrors three.module.min.js).
    std::string html(kVizHostPageHtml);
    CHECK(html.find("cdn.") == std::string::npos);
    CHECK(html.find("unpkg.") == std::string::npos);
    CHECK(html.find("jsdelivr.") == std::string::npos);
}
