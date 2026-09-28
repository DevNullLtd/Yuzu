#pragma once

/// @file dex_types.hpp
/// PURE value types for the DEX (Digital Employee Experience) family — the
/// leaf read-model PODs shared across the store, the read-model builders, the
/// dashboard fragments, and the in-process `DexApi` seam (ADR-0031 WS-A4).
///
/// This header is store-free and httplib-free BY CONSTRUCTION: only `<cstdint>`
/// / `<string>` / `<vector>` / `<utility>`. It exists so the abstract
/// `dex_api.hpp` (and the pure `dex_read_model.hpp`) can name these types
/// without dragging in `guaranteed_state_store.hpp` (a CATASTROPHIC
/// Guardian/Guaranteed-State store header) or `dex_routes.hpp` (which pulls
/// `<httplib.h>`). Those two headers now `#include` THIS one and keep re-
/// exporting these types transitively, so every existing includer is
/// unaffected (ODR-safe relocation, not a duplication).
///
/// Three groups live here:
///   1. The DEX read-model aggregations over `guardian_observations`
///      (relocated verbatim from `guaranteed_state_store.hpp`).
///   2. `DexFleet` / `DexSignalGroup` — the cross-store fleet denominator and
///      the display-family descriptor (relocated verbatim from
///      `dex_routes.hpp`; both are pure PODs the store header never needed).
///   3. The pure signal-catalogue accessors and health/roll-up COMPUTATION
///      over the above types (`dex_signal_groups`, `dex_catalogued_type_count`,
///      `dex_family_index`, `dex_obs_platforms`, `dex_family_rollup` +
///      `DexFamilyRollup`, `DexFamilyWeight`/`dex_family_weights`/
///      `dex_severity_points`/`dex_preset_mult`, `dex_family_health_deduction`,
///      `dex_compute_health` + `DexHealthResult`) — pure functions over groups
///      1–2 only. Their DECLARATIONS were relocated to this header in PR #4582;
///      their DEFINITIONS stayed behind in the presentation TU `dex_routes.cpp`
///      until ADR-0031 WS-A4 PR-1's F1 fix (Fable review, 2026-09-28) moved
///      them, verbatim, into this header's own `dex_types.cpp` — closing the
///      core-links-against-presentation link residual #4579 noted for its two
///      siblings in `dex_read_builders.hpp`. Unlike the sibling `*_types.hpp`
///      (pure PODs only), this header therefore also hosts pure computation; a
///      dedicated `dex_catalogue.hpp` is a legitimate future split (not
///      required — the store-type-free seam property holds either way).

#include <cstddef>
#include <cstdint>
#include <string>
#include <utility>
#include <vector>

namespace yuzu::server {

// ── One captured Guardian observation (the raw event journal projection) ─────
struct GuardianObservationRow {
    std::string event_id;          // shares the event journal dedup key
    std::string agent_id;
    std::string observed_at;       // ISO-8601 (= event timestamp)
    std::string obs_type;          // = event_type, e.g. "process.crashed", "os.boot"
    std::string subject;           // e.g. "notepad.exe", "Spooler", "HP LaserJet"
    std::string reason;            // e.g. "0xC0000005", "0x80070643", "timeout"
    std::string symbolic;          // e.g. "ACCESS_VIOLATION", "WIFI_DISCONNECT"
    std::string component;         // e.g. "ntdll.dll" (faulting module)
    std::string version;           // crashed/hung app's file version "a.b.c.d", "" if unknown
    double metric{0.0};            // numeric payload (boot duration ms); 0 = none
    std::string platform;          // "windows" | "linux" | "macos"
};

// ── DEX read-model aggregations over guardian_observations ───────────────────
struct DexCrashSummary {
    int64_t total_crashes{0};
    int64_t distinct_devices{0};   // devices impacted (crash-free numerator)
    int64_t distinct_apps{0};
};
struct DexAppCrashCount {          // top unreliable apps + blast radius
    std::string subject;           // process name
    std::string version;           // app file version, "" = unknown/all (version-blind query)
    int64_t crashes{0};
    int64_t hangs{0};
    int64_t distinct_devices{0};   // blast radius = distinct devices, not event count
    std::string last_seen;
};
struct DexModuleCrashCount {       // top faulting modules (crash-scoped)
    std::string component;         // module name
    int64_t crashes{0};
    int64_t distinct_apps{0};
};
struct DexDeviceCrashCount {       // most-affected devices (crash-scoped)
    std::string agent_id;
    int64_t crashes{0};
    std::string last_seen;
};
struct DexOsCrashCount {           // per-OS split (coverage-normalised at the route)
    std::string platform;
    int64_t crashes{0};
    int64_t distinct_devices{0};
};
struct DexDayCrashCount {          // crashes-per-day trend
    std::string day;               // YYYY-MM-DD
    int64_t crashes{0};
};
struct DexExceptionCount {         // top failure reasons (per-app drill-down)
    std::string reason;            // e.g. "0xC0000005"
    std::string symbolic;          // e.g. "ACCESS_VIOLATION"
    int64_t crashes{0};
};
struct DexEntitySummary {          // per-app / per-device drill-down summary
    int64_t crashes{0};
    int64_t hangs{0};
    int64_t signals{0};            // ALL observation rows for the entity (any type)
    int64_t distinct_devices{0};
    int64_t distinct_apps{0};
    std::string first_seen;
    std::string last_seen;
};
struct DexSignalCount {            // the whole-catalogue rollup (overview panel)
    std::string obs_type;
    int64_t count{0};
    int64_t distinct_devices{0};
    std::string last_seen;
};
struct DexSubjectCount {           // top subjects for ONE obs_type (signal drill-down)
    std::string subject;
    int64_t count{0};
    int64_t distinct_devices{0};
    std::string last_seen;
};
struct DexOsScope {                // per-OS coverage: how many types each OS collects
    std::string platform;
    int64_t distinct_types{0};
    int64_t total_events{0};
};
struct DexDaySignal {              // one (day, obs_type) cell of the trends matrix
    std::string day;               // YYYY-MM-DD
    std::string obs_type;
    int64_t count{0};
};
struct DexBootStats {              // boot-performance rollup (os.boot metric, ms)
    int64_t boots{0};
    double avg_ms{0.0};
    double max_ms{0.0};
    int64_t distinct_devices{0};
};
struct DexDeviceBoot {             // slowest-booting devices
    std::string agent_id;
    double avg_ms{0.0};
    double max_ms{0.0};
    int64_t boots{0};
};

// ── Cross-store fleet denominator + display-family descriptor ────────────────

/// Fleet-size denominator for the DEX rates — sourced cross-store from the agent
/// registry (NOT the crash store). `windows_online` remains the established
/// headline crash-rate denominator (and the "all" catalogue lens's denominator,
/// kept for continuity); macOS and Linux crash/reliability collectors now exist
/// too, and the per-OS counters below denominate the catalogue's single-OS
/// lenses. `total_online` is context. A struct (not a registry dep) keeps
/// render pure + testable.
struct DexFleet {
    int64_t windows_online{0};
    int64_t total_online{0};
    /// Distinct OS tokens (lowercased: "windows"/"linux"/"darwin") of the agents
    /// CONNECTED right now — the coverage scope for the Catalogue's "All connected"
    /// lens. Empty when nothing is connected.
    std::vector<std::string> connected_os;
    /// CONNECTED agents as (agent_id, normalized-os: "windows"/"linux"/"macos").
    /// The Overview computes a per-device DEX score for each (window-respecting) to
    /// build the experience distribution AND groups by os for the segment breakdown.
    /// Kept here (not pre-scored) so only the Overview pays the per-device cost.
    std::vector<std::pair<std::string, std::string>> connected_agents;
    /// Per-OS online-agent denominators (#1746) — the same coverage-honest count as
    /// windows_online, split by platform, so the Catalogue's single-OS filter can
    /// score a family against THAT OS's own online count instead of borrowing
    /// windows_online. APPENDED here (not alongside windows_online) so the many
    /// positional aggregate initializers of this struct across the test suite keep
    /// compiling unchanged — trailing members default-init to 0.
    int64_t linux_online{0};
    int64_t macos_online{0};
};

/// One display family of the server-side signal catalogue. PUBLIC since F1:
/// the Settings → DEX alerts panel renders the routable-type list from this
/// same single source of truth (the /dex Catalogue's grouping).
struct DexSignalGroup {
    const char* name;
    std::vector<const char*> types;
};

// ── Signal-catalogue accessors ───────────────────────────────────────────────
// PURE accessors over the static server-side signal catalogue — they return
// only pure types (a DexSignalGroup vector / size_t / int), so they belong with
// DexSignalGroup here, not in the httplib-coupled dex_routes.hpp. Relocated
// (declarations) from dex_routes.hpp (PR #4582 FIX 4) so dex_read_model.cpp can
// call dex_signal_groups() without including dex_routes.hpp (which pulls
// <httplib.h>); dex_routes.hpp re-includes this header, so its own callers are
// unaffected. Definitions are unchanged in their .cpp.

/// The catalogued signal types, grouped for display — the server-side mirror of
/// the agent catalogue (keep in sync; the paired drift-net tests bite).
const std::vector<DexSignalGroup>& dex_signal_groups();

/// Total catalogued display types (sum over the groups).
std::size_t dex_catalogued_type_count();

/// obs_type -> index into dex_signal_groups(), or -1 when uncatalogued. Shared
/// by the Trends fragment's family x day matrix and (#4035) its REST/MCP twin.
int dex_family_index(const std::string& obs_type);

/// Per-obs_type platform coverage: which OSes collect this signal type today.
std::vector<std::string> dex_obs_platforms(const std::string& obs_type);

// ── PURE catalogue roll-up + health computation (over DexSignalGroup/
//    DexSignalCount only; no store, no httplib) — relocated from dex_routes.hpp
//    (PR #4582 FIX 4) so dex_read_model.cpp can call them without that
//    httplib-coupled header. dex_routes.hpp re-includes this header, so its
//    own callers are unaffected; definitions are unchanged in their .cpp.

/// One family's rolled-up signal counts — the shared basis both the Catalogue
/// grid and the health-score deduction read.
struct DexFamilyRollup {
    int64_t events = 0;
    int active = 0;
    int total = 0;
    int64_t max_signal_devices = 0; ///< #1374: max of member signals, not the family union
    const DexSignalCount* top = nullptr;
    bool benign = false;
};
DexFamilyRollup dex_family_rollup(const DexSignalGroup& g,
                                  const std::vector<DexSignalCount>& signals);

/// The composite-score weighting policy (mockup dex-health-score.html) — shared
/// by `dex_compute_health`/`dex_family_health_deduction` below AND the
/// per-device scoring formula `dex_score_from_signals` (declared in
/// `dex_read_builders.hpp`, defined in core's `dex_read_model.cpp`), so every
/// consumer scores against the SAME severity/preset weights (relocated from
/// the presentation TU `dex_routes.cpp`, ADR-0031 WS-A4 PR-1 F1 fix — Fable
/// review, 2026-09-28). `severity` = how much a failure of this family hurts
/// experience; the four multipliers are the server-chosen weighting PRESETS —
/// this is policy (transparent + shown), not data.
struct DexFamilyWeight {
    const char* name;
    const char* severity; // "high" | "med" | "low"
    double m_default, m_stability, m_productivity, m_security;
};

/// The full weighting table, one row per catalogue family (names MUST match
/// `dex_signal_groups()`).
const std::vector<DexFamilyWeight>& dex_family_weights();

/// Severity label -> deduction points (policy constant).
double dex_severity_points(const std::string& sev);

/// The multiplier for one family's weight row under a named preset
/// ("stability"/"productivity"/"security"; anything else -> `m_default`).
double dex_preset_mult(const DexFamilyWeight& fw, const std::string& preset);

/// One family's health deduction (the per-family term of dex_compute_health,
/// "default" preset).
double dex_family_health_deduction(const DexSignalGroup& g,
                                   const std::vector<DexSignalCount>& signals, int64_t N);

/// The composite-health result: score (100 − Σ deductions; -1 when N<=0) + the
/// per-family deduction breakdown.
struct DexHealthResult {
    double score = -1.0;
    struct Ded {
        std::string name, sev;
        double deduction = 0.0;
    };
    std::vector<Ded> deds;
};

/// PURE: the shared health-score computation — the Health page and the Overview
/// hub's health teaser both call this (`preset` = default/stability/
/// productivity/security).
DexHealthResult dex_compute_health(const std::vector<DexSignalCount>& signals, int64_t N,
                                   const std::string& preset);

} // namespace yuzu::server
