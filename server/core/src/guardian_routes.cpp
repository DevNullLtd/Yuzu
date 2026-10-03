/// @file guardian_routes.cpp
/// Guardian dashboard HTMX routes + fragment renderers. See guardian_routes.hpp
/// for the coordination/mock contract.

#include "guardian_routes.hpp"

#include "guaranteed_state_store.hpp"
#include "baseline_store.hpp"
#include "http_route_sink.hpp"
#include "guardian_form_render.hpp"
#include "guardian_model.hpp" // #4037 — shared per-guard census builder
                              // (guardian_rule_agent_status_rows), so this
                              // fragment computes the SAME census as the REST
                              // /rules/{rule_id}/status and MCP
                              // get_guardian_rule_status twins
#include "guardian_push_builder.hpp"  // guardian_guard_supported_on_platform / platform_display_name / os_target_matches
#include "guardian_rule_spec.hpp"
#include "mcp_jsonrpc.hpp" // mcp::json_exceeds_depth / kMcpMaxJsonDepth: shared #2437 depth guard
#include "rest_a4_envelope_http.hpp" // detail::a4_denial — mints/reuses X-Correlation-Id so
                                     // header and body always agree
#include "secure_random.hpp"
#include "store_errors.hpp"
#include "web_utils.hpp"

#include <yuzu/metrics.hpp>

#include <nlohmann/json.hpp>
#include <spdlog/spdlog.h>

#include <algorithm>
#include <array>
#include <atomic>
#include <cctype>
#include <cstdint>
#include <exception>
#include <map>
#include <string>
#include <unordered_map>
#include <unordered_set>
#include <utility>
#include <vector>

// Guardian page HTML (defined in guardian_ui.cpp).
extern const char* const kGuardianHtml;
// Shared full-page detail shell (defined in guardian_page_ui.cpp); {{TITLE}} +
// {{FRAGMENT}} are substituted per request by the page-route handlers below.
extern const char* const kGuardianDetailPageHtml;

namespace yuzu::server {

namespace {

// ── Mock fixtures ───────────────────────────────────────────────────────────
// Contract-shaped sample data so the dashboard is self-demonstrating before the
// backend status/baseline/schema surfaces land (docs/guardian-mvp-contract.md
// §8, §10). Every renderer that uses these is marked TODO(guardian-backend).

struct MockGuard {
    const char* id;
    const char* name;
    const char* os;          // "W" | "L" | "M"
    const char* status;      // compliant|drifted|remediation_failed|errored|exempt|stale
    const char* severity;    // critical|high|medium|low
    int compliant;
    int total;
    bool healthy;            // guard_healthy signal (startup-wiring), distinct from status
};

constexpr std::array<MockGuard, 6> kMockGuards{{
    {"block-smb-445", "block-smb-445", "W", "compliant", "high", 148, 148, true},
    {"edr-agent-running", "edr-agent-running", "W", "compliant", "critical", 148, 148, true},
    {"ssh-no-root-login", "ssh-no-root-login", "L", "drifted", "high", 28, 30, true},
    {"av-scan-7d", "av-scan-7d", "W", "remediation_failed", "high", 144, 148, true},
    {"macos-alf-on", "macos-alf-on", "M", "compliant", "high", 20, 20, true},
    {"reg-watch-legacy", "reg-watch-legacy", "W", "errored", "medium", 0, 148, false},
}};

struct MockEvent {
    const char* time;
    const char* type;        // frozen v1 taxonomy
    const char* guard;
    const char* agent;
    const char* detail;
};

constexpr std::array<MockEvent, 6> kMockEvents{{
    {"10:42:31", "drift.remediated", "block-smb-445", "DESKTOP-A3F", "Port 445 opened &rarr; blocked (2ms)"},
    {"10:41:08", "drift.detected", "av-scan-7d", "LAPTOP-B92", "Last scan 9d ago &rarr; triggered"},
    {"10:39:55", "remediation.failed", "av-scan-7d", "LAPTOP-B92", "Defender service start denied (attempt 3)"},
    {"10:38:12", "guard.armed", "edr-agent-running", "SRV-DC01", "Self-test round-trip OK"},
    {"10:36:40", "guard.unhealthy", "reg-watch-legacy", "DESKTOP-K7M", "KEY_NOTIFY denied &mdash; watch deaf"},
    {"10:35:14", "resilience.escalated", "block-smb-445", "DESKTOP-K7M", "firewall-api &rarr; registry-write"},
}};

// ── Display helpers ─────────────────────────────────────────────────────────

// Slugify a Guard name into the rule_id prefix: lowercase, keep [a-z0-9._-],
// collapse other runs to a single '-', trim; falls back to "guard".
std::string slugify(const std::string& name) {
    std::string s;
    bool dash = false;
    for (unsigned char c : name) {
        char lc = static_cast<char>(std::tolower(c));
        const bool ok = (lc >= 'a' && lc <= 'z') || (lc >= '0' && lc <= '9') || lc == '.' ||
                        lc == '_' || lc == '-';
        if (ok) {
            s.push_back(lc);
            dash = false;
        } else if (!dash && !s.empty()) {
            s.push_back('-');
            dash = true;
        }
    }
    if (s.size() > 48) s.resize(48);
    while (!s.empty() && s.back() == '-') s.pop_back();
    return s.empty() ? "guard" : s;
}

// Short unique suffix for a generated rule_id. CSPRNG hex; epoch fallback if the
// PRNG is unavailable (id uniqueness is a UNIQUE-constraint concern, not security).
std::string short_id() {
    if (auto h = random_hex(4); h) return *h;
    return std::to_string(now_epoch_seconds());
}

// Worst-of severity ranking for a fleet/rollup badge (contract decision 5):
// remediation_failed/errored (red) > drifted (amber) > compliant (green).
// exempt is out of the denominator; stale is surfaced distinctly elsewhere.
const char* worst_badge_class(int drifted, int remediation_failed, int errored) {
    if (remediation_failed > 0 || errored > 0) return "worst-bad";
    if (drifted > 0) return "worst-warn";
    return "worst-good";
}

const char* worst_badge_label(int drifted, int remediation_failed, int errored) {
    if (remediation_failed > 0 || errored > 0) return "Action required";
    if (drifted > 0) return "Drift present";
    return "All compliant";
}

// Map a status taxonomy value to its badge CSS class + human label.
std::string status_badge(const std::string& status) {
    std::string label = status;
    if (status == "remediation_failed") label = "remediation failed";
    return "<span class=\"gs-badge gs-" + status + "\">" + label + "</span>";
}

// ── Honest-state helpers (M2 / #1209) ────────────────────────────────────────
// Contract-shaped MOCK fixtures render ONLY when no Guardian backend is present
// (store null / not open) — a pure UI-development fallback. When the store is
// live, an empty result renders an honest empty state, never fabricated guards
// or "148/148 compliant" rollups: on an enforcement console, inventing
// compliance numbers is an observability-integrity hazard. Any mock that does
// render is wrapped in an unmistakable banner so it can never be read as live
// fleet state.
std::string demo_banner(const std::string& what) {
    return "<div style=\"background:rgba(255,176,32,0.12);border:1px solid var(--yellow);"
           "color:var(--yellow);padding:0.45rem 0.7rem;border-radius:0.4rem;margin-bottom:0.6rem;"
           "font-size:0.72rem;font-weight:600\">&#9888; DEMO DATA &mdash; " +
           what + ". Not live fleet state.</div>";
}

std::string empty_state(const std::string& title, const std::string& hint) {
    return "<div style=\"text-align:center;color:var(--muted);padding:1.6rem 1rem;font-size:0.8rem\">"
           "<div style=\"font-weight:600;color:var(--fg);margin-bottom:0.25rem\">" +
           title + "</div>" + hint + "</div>";
}

// Normalise an event_type ("drift.detected") to a CSS-safe suffix
// ("drift_detected") for the .et-* chip classes; unknown types render generic.
std::string event_type_class(const std::string& type) {
    std::string s = type;
    for (auto& c : s)
        if (c == '.') c = '_';
    static const std::array<const char*, 6> known{
        {"drift_detected", "drift_remediated", "remediation_failed", "guard_armed",
         "guard_unhealthy", "resilience_escalated"}};
    for (const auto* k : known)
        if (s == k) return "et-" + s;
    return "et-generic";
}

// "value_name" / "expected-hash" → "Value name" / "Expected hash" (generic
// fallback label for an assertion param not given an explicit label below).
std::string humanize_key(const std::string& key) {
    std::string s = key;
    for (auto& c : s)
        if (c == '_' || c == '-') c = ' ';
    if (!s.empty()) s[0] = static_cast<char>(std::toupper(static_cast<unsigned char>(s[0])));
    return s;
}

// Render the assertion's specific values (what the guard checks) as <div class=kv>
// rows: a label + value, with the expected value highlighted in `hi`. Registry +
// file params get friendly labels (Key combines hive\\key, Name = value_name,
// Type = value_type); anything else is humanised. Empty if no params.
std::string render_assertion_values(const nlohmann::json& asrt, const std::string& hi) {
    if (!asrt.is_object())
        return {};
    const auto& p = asrt.value("params", nlohmann::json::object());
    if (!p.is_object() || p.empty())
        return {};
    auto as_str = [](const nlohmann::json& v) {
        return v.is_string() ? v.get<std::string>() : v.dump();
    };
    auto row = [&](const std::string& label, const std::string& val, bool highlight) {
        return "<div class=\"k\">" + html_escape(label) + "</div><div" +
               (highlight ? (" style=\"color:" + hi + ";font-weight:700\"") : std::string{}) + ">" +
               html_escape(val) + "</div>";
    };
    std::string out;
    std::unordered_set<std::string> shown;
    if (p.contains("key")) {  // registry: combine hive\\key into one "Key"
        std::string key = p.contains("hive") ? as_str(p["hive"]) + "\\" : "";
        key += as_str(p["key"]);
        out += row("Key", key, false);
        shown.insert("hive");
        shown.insert("key");
    } else if (p.contains("hive")) {
        out += row("Hive", as_str(p["hive"]), false);
        shown.insert("hive");
    }
    if (p.contains("value_name")) { out += row("Name", as_str(p["value_name"]), false); shown.insert("value_name"); }
    if (p.contains("value_type")) { out += row("Type", as_str(p["value_type"]), false); shown.insert("value_type"); }
    if (p.contains("path")) { out += row("Path", as_str(p["path"]), false); shown.insert("path"); }
    if (p.contains("expected")) { out += row("Expected value", as_str(p["expected"]), true); shown.insert("expected"); }
    if (p.contains("expected_hash")) { out += row("Expected hash", as_str(p["expected_hash"]), true); shown.insert("expected_hash"); }
    for (auto it = p.begin(); it != p.end(); ++it) {
        if (shown.count(it.key())) continue;
        out += row(humanize_key(it.key()), as_str(it.value()), it.key().rfind("expected", 0) == 0);
    }
    return out;
}

// Distinct colour for the "not yet implemented" class (an (agent, rule) pair whose
// GUARD TYPE the agent-side Guardian can't arm on that agent's platform — see
// guardian::guardian_guard_supported_on_platform for the per-type matrix; it is NOT a
// blanket macOS/Linux exclusion, e.g. Service arms on Linux today). Deliberately NOT
// green/grey so it can never read as compliant or as a stale-offline "unknown" — used
// by the fleet census, the By-Guard/By-Baseline "N not impl" tags, and the per-device
// drill-down.
constexpr const char* kNotImplColor = "#a78bfa";  // violet

// agent_id -> raw platform token ("windows"|"linux"|"darwin"|...) for currently-
// connected agents, parsed from the registry JSON (registry_.to_json()). Used both to
// fold liveness (a status row whose agent_id is absent is "unknown" — offline, can't
// verify) and, together with a rule's guard type, to flag pairs the agent-side
// Guardian does not arm yet (guardian::guardian_guard_supported_on_platform — NOT a
// blanket per-platform rule; see the #4252 matrix), so they are reported "not yet
// implemented" rather than silently looking compliant/unknown. Callers derive the
// online-id set from its keys.
std::unordered_map<std::string, std::string> parse_online_agent_os(const std::string& agents_json) {
    std::unordered_map<std::string, std::string> m;
    auto j = nlohmann::json::parse(agents_json, nullptr, false);
    const nlohmann::json* arr =
        j.is_array() ? &j
        : (j.is_object() && j.contains("agents") && j["agents"].is_array()) ? &j["agents"] : nullptr;
    if (arr)
        for (const auto& a : *arr)
            if (a.contains("agent_id") && a["agent_id"].is_string())
                m[a["agent_id"].get<std::string>()] = a.value("os", std::string{});
    return m;
}

// Per-rule current compliance rollup. THE single source for "state now", "needs
// attention", the fleet census, and the drill-downs — all derived from the pruning-
// immune status table (not the prunable event log), with the same liveness fold
// (offline agent → unknown). Keyed by rule_id; absent rule = no device has reported.
struct StateRollup {
    int64_t ok = 0, drift = 0, err = 0, unk = 0;
    // (agent, rule) pairs the rule targets on a platform the agent-side Guardian
    // does not arm THIS GUARD TYPE on (e.g. Registry/File on macOS+Linux; Service
    // on macOS only — guardian::guardian_guard_supported_on_platform is the single
    // source of the matrix). Tracked separately so it is never folded into
    // compliant or into the offline "unknown" bucket — an unenforceable pair
    // must never read as protected. Only counted when the pair has NO real
    // status row (see has_real_status below) — #4252: a pair the agent-side
    // Guardian DOES now arm (Linux Service) must not be counted here just
    // because it is also absent from some OTHER, stricter bucket.
    int64_t notimpl = 0;
    int64_t total() const { return ok + drift + err + unk + notimpl; }
};
std::unordered_map<std::string, StateRollup>
rollup_by_rule(const std::vector<yuzu::server::GuardianAgentRuleStatus>& rows,
               const std::unordered_set<std::string>& online) {
    std::unordered_map<std::string, StateRollup> m;
    for (const auto& s : rows) {
        StateRollup& c = m[s.rule_id];
        const std::string st = online.count(s.agent_id) ? s.state : std::string("unknown");
        if (st == "compliant") ++c.ok;
        else if (st == "drifted") ++c.drift;
        else if (st == "errored") ++c.err;
        else ++c.unk;
    }
    return m;
}

// ── #4252 shared machinery: guard-type-aware "not implemented" + double-count
//    exclusion, used by all 3 synthetic-notimpl fold sites in this file ──────

// Composite key for one (agent, rule) pair. A real struct + hash functor, NOT a
// delimiter-joined string — and its correctness never leans on either field's
// charset, which is why it stays correct even though only one of the two now
// carries a guarantee: agent_id is client-supplied at Register (length-checked
// only, agent_service_impl.cpp), still charset-unrestricted; rule_id created
// via REST/MCP now IS charset-restricted (is_valid_rule_id, #4665), but a
// rule_id predating that check, or one reaching this struct via any other,
// non-charset-checked path, is not guaranteed charset-safe either — a
// delimiter would still be ambiguous for either field. Governance Gate 2/3/6
// independently confirmed a crafted "\x1f"-containing agent_id or rule_id
// collided the prior delimited-string key
// (`agentA\x1fextra` + `ruleX` == `agentA` + `extra\x1fruleX`), silently
// dropping a real status row from every fold. A struct key has no delimiter to
// collide on, for any byte content, by construction — this is the fix, not a
// stricter escape. Owned std::string fields (not string_view): status_pair_index
// is consumed by the baseline fold AFTER the scope where its backing status rows
// were fetched closes (see render_baseline_page_fragment), so a view-based key
// would dangle there. Precedent: stream_budget.hpp's Key/KeyHash.
struct PairStatusKey {
    std::string agent_id;
    std::string rule_id;

    bool operator==(const PairStatusKey& o) const noexcept {
        return agent_id == o.agent_id && rule_id == o.rule_id;
    }
};
struct PairStatusKeyHash {
    std::size_t operator()(const PairStatusKey& k) const noexcept {
        return std::hash<std::string>{}(k.agent_id) ^
               (std::hash<std::string>{}(k.rule_id) * 0x9e3779b97f4a7c15ULL);
    }
};

// (agent_id, rule_id) pairs that already own a REAL status row — built once
// per fragment render from the SAME status vector `rollup_by_rule()` (or, for
// the single-rule guard page, `guardian_rule_agent_status_rows()`) already
// consumes, never a second store query.
std::unordered_set<PairStatusKey, PairStatusKeyHash>
status_pair_index(const std::vector<yuzu::server::GuardianAgentRuleStatus>& rows) {
    std::unordered_set<PairStatusKey, PairStatusKeyHash> s;
    s.reserve(rows.size());
    for (const auto& r : rows) s.insert(PairStatusKey{r.agent_id, r.rule_id});
    return s;
}

// True iff `pairs` (built by a caller via status_pair_index, or the single-
// rule equivalent) already contains a real status row for (agent_id,
// rule_id). THE one exclusion predicate shared by every synthetic "not
// implemented" fold in this file: a pair that already reports real state
// must NEVER also get a synthetic notimpl increment — that additive
// double-count (present pre-#4252 for Linux Service, once Service became
// guard-type-aware-supported on Linux) is exactly the bug this predicate
// closes. Not folding this into guardian_guard_supported_on_platform itself:
// that function answers a pure "can this platform arm this guard type"
// question with no store/status dependency, and stays unit-testable as such.
bool has_real_status(const std::unordered_set<PairStatusKey, PairStatusKeyHash>& pairs,
                     std::string_view agent_id, std::string_view rule_id) {
    return pairs.contains(PairStatusKey{std::string(agent_id), std::string(rule_id)});
}

// Extract a rule's spark.type token from its canonical spec_json — the input
// to guardian::guardian_guard_supported_on_platform's guard-type-aware check.
// Parse once per rule (outside the per-agent loop at each call site), mirroring
// how build_agent_push / render_guard_page_fragment already parse spec_json
// per-render. Malformed/absent spec_json, a non-object "spark" block, or a
// non-string "type" all yield an empty token, never throw — an empty token
// reads as "unknown type" to guardian_guard_supported_on_platform, which falls
// back to the pre-#4252 Windows-only rule, so a bad row can never regress
// Registry/File support.
std::string spark_type_of(const std::string& spec_json) {
    if (spec_json.empty())
        return {};
    auto j = nlohmann::json::parse(spec_json, nullptr, /*allow_exceptions=*/false);
    if (!j.is_object() || !j.contains("spark") || !j["spark"].is_object())
        return {};
    const auto& spark = j["spark"];
    return spark.contains("type") && spark["type"].is_string() ? spark["type"].get<std::string>()
                                                               : std::string{};
}

// ── Detectability (#4252): server support-matrix stale vs. agent-observed
//    reality ────────────────────────────────────────────────────────────────
// Fires when a call site below would have counted an (agent, rule) pair as
// "not implemented" per guardian_guard_supported_on_platform's hardcoded
// matrix, but has_real_status says the agent already reports REAL status for
// that exact pair — i.e. the matrix disagrees with what the agent has
// actually observed. This is the double-count #4252 fixes; firing it here
// pins the fix and gives a live signal if the matrix ever drifts stale again
// (e.g. a future guard type ships agent-side support before this file's
// matrix is updated to match). Render-time only — it fires when an operator
// loads a Guardian fragment, NOT a continuous background monitor; naming and
// docs below say so explicitly, per the plan's detectability note. Mirrors
// app_perf_daily_store.cpp's note_read_degrade() shape (atomic relaxed
// counter + modulo-sampled log + a real bounded-label Prometheus counter,
// docs/observability-conventions.md's pre-seed rule) — deliberately NOT the
// engine_principal_store.cpp/LogCapture pattern an earlier draft of this fix
// cited, which does not exist anywhere in this tree.
// #4252 consolidated round: kMatrixStaleSparkTypes used to be its own separate
// std::array here — a THIRD independent enumeration of Guardian spark types
// alongside the schema catalog and the platform matrix, with no cross-check
// binding them (governance Gate 4 consistency-auditor finding). Now an alias
// for guardian::kKnownGuardSparkTypes (guardian_push_builder.hpp) — no third
// copy. That header's own comment states precisely what IS and is NOT bound
// by the schema-registry cross-check test: this array, not
// guardian_guard_supported_on_platform's literal if-chain.
constexpr auto& kMatrixStaleSparkTypes = guardian::kKnownGuardSparkTypes;
constexpr const char* kMatrixStaleSparkTypeUnknown = "unknown";
constexpr std::uint64_t kMatrixStaleLogSample = 50;

std::atomic<std::uint64_t> g_matrix_stale_count{0};

void note_platform_matrix_stale(yuzu::MetricsRegistry* metrics, std::string_view agent_id,
                                std::string_view rule_id, std::string_view spark_type) {
    // The metric label is the CLOSED set advertised in docs/user-manual/metrics.md — never
    // the raw authored token. spark.type is operator-authored free text with no membership
    // check on the create/update path (guardian_rule_spec.cpp's derive_rule_spec validates
    // only non-emptiness), so passing it through verbatim would let a privileged operator
    // mint an unbounded, never-evicted Prometheus series per distinct typo/garbage value —
    // exactly what docs/observability-conventions.md's closed/bounded/pre-seeded-label rule
    // exists to prevent (precedent: dispatch_confined_arms.hpp's kQuarantineGateOutcomes
    // drives both the pre-seed and the emit side from one closed constant). The raw token
    // still reaches the sampled log line below for forensics.
    const bool known = std::ranges::find(kMatrixStaleSparkTypes, spark_type) !=
                       kMatrixStaleSparkTypes.end();
    const std::string label = known ? std::string(spark_type) : std::string(kMatrixStaleSparkTypeUnknown);
    if (metrics)
        metrics
            ->counter("yuzu_server_guardian_platform_matrix_stale_total", {{"spark_type", label}})
            .increment();
    const std::uint64_t n = g_matrix_stale_count.fetch_add(1, std::memory_order_relaxed) + 1;
    if (n % kMatrixStaleLogSample == 1)
        // #4665 governance-external-review finding (fjarvis, PR #4979): this line is
        // "agent={} rule={} spark_type={}" -- a k=v k=v shape, so the threat here is
        // not just a forged extra PHYSICAL line (log_safe's control-byte-only fold
        // closes that much) but a forged ADJACENT FIELD on this same line via a
        // space or '=' in an operator/agent-controlled value (e.g. a crafted
        // rule_id like "x result=success"). audit_token (web_utils.hpp, forwards to
        // yuzu::log_token) folds space/'='/',' too -- the correct neutraliser for a
        // k=v-shaped line, not log_safe, which this site used before this fix and
        // which the #4665 tripwire's own allowlist of "log_safe(" as safe made
        // invisible to the regression net. Do not revert to log_safe here.
        spdlog::info("guardian: platform support-matrix stale vs. agent-observed reality — "
                     "agent={} rule={} spark_type={} (metric_label={}) already reports real "
                     "status; suppressed a synthetic not-implemented double-count (occurrence {})",
                     audit_token(agent_id), audit_token(rule_id),
                     spark_type.empty() ? "<empty>" : audit_token(spark_type),
                     label, n);
}

} // namespace

bool GuardianRoutes::deny_service_scoped_(const httplib::Request& req,
                                          httplib::Response& res) const {
    auto session = auth_fn_(req, res);
    if (!session)
        return true; // auth_fn_ already wrote 401/redirect; caller returns.
    if (session->token_scope_service.empty())
        return false;
    // Write the 403 FIRST, audit after: the audit call is fire-and-forget
    // (GuardianRoutes::AuditFn is void, no persist signal to route through a
    // kernel like try_persist_audit), and a THROWING audit_fn must not be able
    // to prevent the 403 from ever being written — a Gate 8 finding on an
    // earlier draft of this function had the audit call first, so an
    // uncaught throw turned the intended 403 into a bare httplib 500 with
    // no response body at all (worse than silence: it also broke the deny).
    res.status = 403;
    // No `.permission`: `kServiceScopeGlobalSafe` is compile-time-empty, so
    // no grant admits a service-scoped caller here — naming one is the false
    // self-remediation claim the routed-concern MUST clause forbids (gov-fix,
    // Gate 8, #2298 PR 3 hardening round). `a4_denial` (not a hand-built
    // `error_json_a4` + bare cid) also fixes a second bug found in the same
    // pass: the hand-built id never reached the X-Correlation-Id header.
    res.set_content(
        detail::a4_denial(res, 403,
                          "service-scoped tokens may not read this fleet-wide Guardian view"),
        "application/json");
    // One shared verb across every fragment this gate covers (data-bearing:
    // status, guards, events, guard/page, baselines, baseline/page; and the
    // create/edit forms: guard-form, baseline-form, baseline/{id}/edit) - a
    // probing service token leaves a trace, not silence, mirroring the REST
    // fleet-wide deny's own denial audit (rest_api_v1.cpp's events route).
    // `req.path` in `detail` disambiguates which fragment was probed, since
    // the verb itself does not. try/catch (not routed through
    // try_persist_audit, which requires a bool-returning AuditFn): the 403
    // above is already durably written, so this is belt-and-suspenders
    // against a throwing sink, not a functional requirement.
    if (audit_fn_) {
        try {
            audit_fn_(req, "guaranteed_state.fragment.access_denied", "denied", "GuaranteedState",
                      "",
                      "fleet-wide Guardian dashboard fragment denied to a service-scoped token "
                      "(path=" +
                          req.path + ")");
        } catch (const std::exception& e) {
            spdlog::warn("guaranteed_state.fragment.access_denied: audit_fn_ threw: {}", e.what());
        } catch (...) {
            spdlog::warn("guaranteed_state.fragment.access_denied: audit_fn_ threw (non-std)");
        }
    }
    return true;
}

bool GuardianRoutes::deny_service_scoped_mutation_(const httplib::Request& req,
                                                    httplib::Response& res,
                                                    const std::string& operation,
                                                    const std::string& audit_action,
                                                    const std::string& target_id) const {
    auto session = auth_fn_(req, res);
    if (!session)
        return true; // auth_fn_ already wrote 401/redirect; caller returns.
    if (session->token_scope_service.empty())
        return false;
    // Write the 403 FIRST, audit after — same throw-safety rationale as
    // deny_service_scoped_ above.
    res.status = 403;
    // No `.permission`: same reasoning as deny_service_scoped_ above — the
    // allow-list is compile-time-empty, no grant admits this caller.
    res.set_content(
        detail::a4_denial(
            res, 403, "service-scoped tokens may not modify this fleet-wide Guardian resource"),
        "application/json");
    if (audit_fn_) {
        try {
            audit_fn_(req, audit_action, "denied", "GuaranteedState", target_id,
                      "fleet-wide Guardian mutation denied to a service-scoped token (path=" +
                          req.path + ")");
        } catch (const std::exception& e) {
            spdlog::warn("{}: audit_fn_ threw: {}", audit_action, e.what());
        } catch (...) {
            spdlog::warn("{}: audit_fn_ threw (non-std)", audit_action);
        }
    }
    return true;
}

// ── Fragment renderers ───────────────────────────────────────────────────────

std::string GuardianRoutes::render_status_fragment(const std::string& view) const {
    if (!store_ || !store_->is_open())
        return empty_state("Guardian store unavailable", "Check server /healthz.");

    // 7-day window for activity/effectiveness/trend.
    const std::string since = format_iso_utc(now_epoch_seconds() - 7 * 86400);
    const auto activity = store_->rule_activity(since);
    std::unordered_map<std::string, const GuardianRuleActivity*> act;
    for (const auto& a : activity) act[a.rule_id] = &a;

    // Liveness + the SINGLE per-rule compliance rollup, from the pruning-immune status
    // table (offline agent → unknown). Drives "state now", "needs attention", the
    // census, and the drill-downs identically — there is no second, event-log-derived
    // source that could drift out of sync once a quiet guard's events age out.
    // online_os carries each connected agent's platform so we can flag the pairs
    // the agent-side Guardian cannot arm THIS GUARD TYPE on yet as "not
    // implemented" — see guardian::guardian_guard_supported_on_platform.
    const std::unordered_map<std::string, std::string> online_os =
        agents_json_fn_ ? parse_online_agent_os(agents_json_fn_())
                        : std::unordered_map<std::string, std::string>{};
    std::unordered_set<std::string> online;
    online.reserve(online_os.size());
    for (const auto& [aid, aos] : online_os) online.insert(aid);

    // list_rules / agent_rule_statuses are now type-distinguishable (ADR-0038
    // catastrophic-read set): a degraded read renders the same "store
    // unavailable" empty-state as the !store_ guard above, never a silent
    // empty/partial fleet view.
    const auto rules_result = store_->list_rules();
    const auto statuses_result = store_->agent_rule_statuses();
    if (!rules_result || !statuses_result)
        return empty_state("Guardian store degraded", "Check server /healthz.");
    const auto& rules = *rules_result;
    auto by_rule = rollup_by_rule(*statuses_result, online);
    // Pairs that already own a REAL status row — the #4252 exclusion index, built
    // from the SAME status vector rollup_by_rule() just consumed (never a second
    // store query). Feeds has_real_status() below.
    const auto real_status_pairs = status_pair_index(*statuses_result);

    // Deployed Baselines per rule (coverage + per-Guard "deployed"). Computed BEFORE
    // the not-implemented fold because the fold is gated on deployment (below).
    std::unordered_map<std::string, std::vector<std::pair<std::string, std::string>>> deployed_by_rule;
    if (baseline_store_ && baseline_store_->is_open())
        for (const auto& b : baseline_store_->list_deployed_baselines())
            for (const auto& rid : baseline_store_->get_members(b.baseline_id))
                deployed_by_rule[rid].emplace_back(b.baseline_id, b.name);

    // Fold "not yet implemented": for each rule that is a member of a DEPLOYED
    // Baseline, every ONLINE agent the rule targets whose platform Guardian cannot
    // arm THIS rule's guard type is a deployed-but-unenforced (agent, rule) pair —
    // UNLESS the pair already owns a real status row (#4252: e.g. a Linux Service
    // guard, which the agent-side Guardian DOES now arm — treating "unsupported"
    // as "unreported" there double-counted the pair, once as its real state and
    // again as synthetic notimpl). Counted here so the census, the By-Guard /
    // By-Baseline "state now" cells, and the fleet rollup all reflect it — never
    // as compliant, never as offline-unknown. GATED ON DEPLOYMENT (matching the
    // coverage cards): a draft Guard in no deployed Baseline reaches no device, so
    // it owns no device-guard pairs and must not inflate the census denominator /
    // depress the headline % compliant.
    //
    // Also collects, per agent, whether it owns AT LEAST ONE real (i.e. not
    // suppressed by has_real_status) unsupported pair — pair-level attribution
    // for the honesty banner below, so an agent with zero actually-unenforced
    // pairs (e.g. its only deployed guard is a now-supported Linux Service guard)
    // does not trip a banner claiming it enforces nothing (#4252 banner-semantics
    // decision: pair-level, not "any agent on a platform we don't fully support").
    std::unordered_set<std::string> agents_with_notimpl_pair;
    for (const auto& r : rules) {
        if (!deployed_by_rule.count(r.rule_id))
            continue;
        const std::string spark_type = spark_type_of(r.spec_json);
        for (const auto& [aid, aos] : online_os) {
            if (guardian::guardian_guard_supported_on_platform(aos, spark_type) ||
                !guardian::os_target_matches(r.os_target, aos))
                continue;
            if (has_real_status(real_status_pairs, aid, r.rule_id)) {
                note_platform_matrix_stale(metrics_, aid, r.rule_id, spark_type);
                continue;
            }
            ++by_rule[r.rule_id].notimpl;
            agents_with_notimpl_pair.insert(aid);
        }
    }

    auto sech = [](const std::string& t) {
        return "<div style=\"font-size:0.66rem;text-transform:uppercase;letter-spacing:0.06em;"
               "color:var(--muted);font-weight:700;margin:0.9rem 0 0.4rem\">" + t + "</div>";
    };
    auto card = [](const std::string& num, const char* tone, const std::string& label,
                   const std::string& sub) {
        std::string h = "<div class=\"stat-card\"><div class=\"stat-num " + std::string(tone) +
                        "\">" + num + "</div><div class=\"stat-label\">" + label + "</div>";
        if (!sub.empty())
            h += "<div style=\"font-size:0.62rem;color:var(--muted);margin-top:0.15rem\">" + sub + "</div>";
        return h + "</div>";
    };
    // Clickable variant: a Fleet stat card that doubles as navigation into the
    // matching status sub-view (onclick → gsGoView, which switches the view tab and
    // pre-applies a filter). Plain onclick — CSP-safe, see project memory on hx-on.
    auto navcard = [](const std::string& num, const char* tone, const std::string& label,
                      const std::string& sub, const std::string& onclick) {
        std::string h = "<div class=\"stat-card stat-card-nav\" style=\"cursor:pointer\" onclick=\"" +
                        onclick + "\"><div class=\"stat-num " + std::string(tone) + "\">" + num +
                        "</div><div class=\"stat-label\">" + label + "</div>";
        if (!sub.empty())
            h += "<div style=\"font-size:0.62rem;color:var(--muted);margin-top:0.15rem\">" + sub + "</div>";
        return h + "</div>";
    };

    // ── By Guard (filterable stats-forward cards) ─────────────────────────
    if (view == "guard") {
        if (rules.empty())
            return empty_state("No Guards yet", "Create a Guard to start enforcing desired state.");
        auto lower = [](std::string s) {
            for (auto& ch : s) if (ch >= 'A' && ch <= 'Z') ch = static_cast<char>(ch + 32);
            return s;
        };
        int n_drift = 0, n_ok = 0, n_unhealthy = 0, n_nodep = 0;
        std::string cards;
        for (const auto& r : rules) {
            const bool enforcing = r.enforcement_mode == "enforce";
            const auto* a = act.count(r.rule_id) ? act[r.rule_id] : nullptr;
            const auto sit = by_rule.find(r.rule_id);
            const StateRollup s = sit != by_rule.end() ? sit->second : StateRollup{};
            const bool dep = deployed_by_rule.count(r.rule_id) > 0;
            const int64_t tot = s.total();
            std::string st;
            if (!dep) { st = "nodep"; ++n_nodep; }
            else if (s.err > 0) { st = "unhealthy"; ++n_unhealthy; }
            else if (s.drift > 0) { st = "drift"; ++n_drift; }
            else if (s.ok > 0) { st = "ok"; ++n_ok; }
            else st = "unk";
            const std::string rid = html_escape(r.rule_id);

            // Middle column — compliance bar + one-line summary.
            std::string mid;
            if (!dep)
                mid = "<div class=\"gs-legend\">Not in a deployed Baseline</div>";
            else if (tot == 0)
                mid = "<div class=\"gs-legend\">No device reports yet</div>";
            else {
                auto seg = [&](const char* col, int64_t n) -> std::string {
                    if (n <= 0) return {};
                    return "<span style=\"width:" + std::to_string((n * 100) / tot) + "%;background:" + col + "\"></span>";
                };
                std::string sum;
                if (s.err > 0)
                    sum = "<span style=\"color:var(--red);font-weight:600\">enforcement failing on " +
                          std::to_string(s.err) + "</span>";
                else if (s.drift > 0)
                    sum = "<span style=\"color:var(--yellow);font-weight:600\">drifted on " +
                          std::to_string(s.drift) + " of " + std::to_string(tot) + " agents</span>";
                else
                    sum = "<span style=\"color:var(--green);font-weight:600\">compliant &middot; " +
                          std::to_string(s.ok) + " / " + std::to_string(tot) + "</span>";
                if (s.notimpl > 0)  // macOS/Linux agents the guard targets but can't arm (acb332a)
                    sum += " <span style=\"color:" + std::string(kNotImplColor) + ";font-weight:600\">&middot; " +
                           std::to_string(s.notimpl) + " not impl</span>";
                mid = "<div class=\"gs-pbar\">" + seg("var(--green)", s.ok) + seg("var(--yellow)", s.drift) +
                      seg("var(--red)", s.err) + seg("#5b6b80", s.unk) + seg(kNotImplColor, s.notimpl) +
                      "</div><div class=\"gs-legend\">" + sum + "</div>";
            }

            std::string pills;
            if (!r.severity.empty())
                pills += "<span class=\"gs-cpill sev-" + html_escape(r.severity) + "\">" + html_escape(r.severity) +
                         "</span>";
            pills += "<span class=\"gs-cpill " + std::string(enforcing ? "enforce" : "observe") + "\">" +
                     (enforcing ? "Enforce" : "Observe") + "</span><span class=\"gs-cpill " +
                     std::string(r.enabled ? "on" : "off") + "\">" +
                     (r.enabled ? "&#9679; enabled" : "&#9675; disabled") + "</span>";

            std::string right = "<div class=\"big\">" +
                (enforcing ? std::to_string(a ? a->remediated : 0) : std::to_string(a ? a->detected : 0)) +
                "</div><div>" + (enforcing ? "remediated" : "detected") + " &middot; 7d</div>"
                "<div style=\"margin-top:0.35rem\">" +
                (dep ? std::to_string(deployed_by_rule[r.rule_id].size()) + " Baseline(s)" : "not deployed") +
                "</div><div class=\"gs-view\">View &rarr;</div>";

            cards += "<a class=\"gs-card\" href=\"/guardian/guard/" + rid + "\" data-gstate=\"" + st +
                     "\" data-gsev=\"" + html_escape(r.severity) + "\" data-gmode=\"" +
                     std::string(enforcing ? "enforce" : "observe") + "\" data-gname=\"" +
                     html_escape(lower(r.name)) + "\"><div><div class=\"gs-card-name\">" + html_escape(r.name) +
                     "</div><div class=\"gs-cpills\">" + pills + "</div></div><div>" + mid +
                     "</div><div class=\"gs-cr\">" + right + "</div></a>";
        }
        const int total = static_cast<int>(rules.size());
        return "<div class=\"gs-filterbar\">"
               "<input id=\"gs-guard-q\" type=\"search\" placeholder=\"Search guards&hellip;\" "
               "oninput=\"gsGuardFilter()\"><div class=\"gs-chips\">"
               "<span class=\"gs-chip on\" data-gstate=\"all\" onclick=\"gsGuardState(this)\">All " +
               std::to_string(total) + "</span><span class=\"gs-chip\" data-gstate=\"drift\" "
               "onclick=\"gsGuardState(this)\">Drifting " + std::to_string(n_drift) +
               "</span><span class=\"gs-chip\" data-gstate=\"ok\" onclick=\"gsGuardState(this)\">Compliant " +
               std::to_string(n_ok) + "</span><span class=\"gs-chip\" data-gstate=\"unhealthy\" "
               "onclick=\"gsGuardState(this)\">Unhealthy " + std::to_string(n_unhealthy) +
               "</span><span class=\"gs-chip\" data-gstate=\"nodep\" onclick=\"gsGuardState(this)\">Not deployed " +
               std::to_string(n_nodep) + "</span></div>"
               "<select id=\"gs-guard-sev\" onchange=\"gsGuardFilter()\"><option value=\"all\">Any severity</option>"
               "<option value=\"critical\">Critical</option><option value=\"high\">High</option>"
               "<option value=\"medium\">Medium</option><option value=\"low\">Low</option></select>"
               "<select id=\"gs-guard-mode\" onchange=\"gsGuardFilter()\"><option value=\"all\">Any mode</option>"
               "<option value=\"observe\">Observe</option><option value=\"enforce\">Enforce</option></select>"
               "<span class=\"gs-rescount\" id=\"gs-guard-rc\">" + std::to_string(total) + " of " +
               std::to_string(total) + " guards</span></div><div class=\"gs-list\">" + cards + "</div>";
    }

    // ── By Baseline (stats-forward cards) ─────────────────────────────────
    if (view == "baseline") {
        if (!baseline_store_ || !baseline_store_->is_open())
            return empty_state("Baseline store unavailable", "Check server /healthz.");
        auto baselines = baseline_store_->list_baselines();
        if (baselines.empty())
            return empty_state("No Baselines yet", "Create a Baseline to deploy Guards.");
        std::string cards;
        for (const auto& b : baselines) {
            const bool deployed = b.lifecycle == kBaselineDeployed;
            auto members = baseline_store_->get_members(b.baseline_id);
            int64_t det = 0;
            int guards_drifting = 0;
            StateRollup bc; // member rollup → baseline compliance
            for (const auto& rid : members) {
                if (auto it = act.find(rid); it != act.end()) det += it->second->detected;
                if (auto it = by_rule.find(rid); it != by_rule.end()) {
                    bc.ok += it->second.ok; bc.drift += it->second.drift;
                    bc.err += it->second.err; bc.unk += it->second.unk;
                    bc.notimpl += it->second.notimpl;
                    if (it->second.drift > 0 || it->second.err > 0) ++guards_drifting;
                }
            }
            const int64_t tot = bc.total();
            const std::string bid = html_escape(b.baseline_id);

            std::string mid;
            if (!deployed)
                mid = "<div class=\"gs-legend\">Draft &mdash; deploy to start reporting</div>";
            else if (tot == 0)
                mid = "<div class=\"gs-legend\">No device check-ins yet</div>";
            else {
                auto seg = [&](const char* col, int64_t n) -> std::string {
                    if (n <= 0) return {};
                    return "<span style=\"width:" + std::to_string((n * 100) / tot) + "%;background:" + col + "\"></span>";
                };
                const int pct = static_cast<int>((bc.ok * 100) / tot);
                mid = "<div class=\"gs-pbar\">" + seg("var(--green)", bc.ok) + seg("var(--yellow)", bc.drift) +
                      seg("var(--red)", bc.err) + seg("#5b6b80", bc.unk) + seg(kNotImplColor, bc.notimpl) +
                      "</div><div class=\"gs-legend\">" +
                      std::to_string(pct) + "% compliant &middot; <span style=\"color:var(--yellow)\">" +
                      std::to_string(guards_drifting) + " of " + std::to_string(members.size()) +
                      " guards drifting</span>" +
                      (bc.notimpl > 0 ? " <span style=\"color:" + std::string(kNotImplColor) + "\">&middot; " +
                                            std::to_string(bc.notimpl) + " not impl</span>"
                                      : std::string{}) +
                      "</div>";
            }

            std::string right = "<div class=\"big\">" + std::to_string(members.size()) +
                "</div><div>guards</div><div style=\"margin-top:0.35rem\">" + std::to_string(det) +
                " drift events &middot; 7d</div><div style=\"margin-top:0.2rem\">" +
                (deployed && b.deployed_at > 0
                     ? "deployed " + html_escape(format_iso_utc(b.deployed_at).substr(0, 10))
                     : "never deployed") +
                "</div><div class=\"gs-view\">View &rarr;</div>";

            const std::string life = "<span class=\"gs-cpill\" style=\"border:none;padding-left:0;color:" +
                std::string(deployed ? "var(--green)" : "var(--muted)") + "\">" +
                (deployed ? "&#9679; deployed" : "&#9675; draft") + "</span>";
            const std::string pending =
                baseline_members_drifted(b)
                    ? "<span class=\"gs-cpill\" style=\"color:var(--yellow);border-color:rgba(255,204,0,0.45)\">"
                      "&#9888; changes pending</span>"
                    : "";

            cards += "<a class=\"gs-card\" href=\"/guardian/baseline/" + bid +
                     "\"><div><div class=\"gs-card-name\">" + html_escape(b.name) + "</div>" +
                     (b.description.empty() ? "" : "<div class=\"gs-card-sub\">" + html_escape(b.description) + "</div>") +
                     "<div class=\"gs-cpills\">" + life + pending + "</div></div><div>" + mid +
                     "</div><div class=\"gs-cr\">" + right + "</div></a>";
        }
        return "<div class=\"gs-list\">" + cards + "</div>";
    }

    // ── Fleet (default) ───────────────────────────────────────────────────
    int deployed_guards = 0;
    for (const auto& r : rules)
        if (deployed_by_rule.count(r.rule_id)) ++deployed_guards;
    const int total_guards = static_cast<int>(rules.size());
    int bl_total = 0, bl_deployed = 0;
    if (baseline_store_ && baseline_store_->is_open())
        for (const auto& b : baseline_store_->list_baselines()) {
            ++bl_total;
            if (b.lifecycle == kBaselineDeployed) ++bl_deployed;
        }
    const int agents = static_cast<int>(online.size()); // connected agents (registry)

    // Census + "needs attention" in ONE pass over the LIVE rules, from the shared
    // by_rule rollup. Orphan status rows for a deleted guard are simply never looked
    // up, so the fleet total stays consistent with the By-Guard table; and because the
    // rollup is the status table (not the prunable event log), a quiet guard does not
    // vanish from "needs attention" once its events age out.
    int64_t cc_ok = 0, cc_drift = 0, cc_err = 0, cc_unk = 0, cc_notimpl = 0;
    int guards_drifting = 0, drift_instances = 0, guards_errored = 0;
    for (const auto& r : rules) {
        auto it = by_rule.find(r.rule_id);
        if (it == by_rule.end()) continue;
        const StateRollup& c = it->second;
        cc_ok += c.ok; cc_drift += c.drift; cc_err += c.err; cc_unk += c.unk; cc_notimpl += c.notimpl;
        if (c.drift > 0) { ++guards_drifting; drift_instances += static_cast<int>(c.drift); }
        if (c.err > 0) ++guards_errored;
    }
    // notimpl is IN the denominator on purpose: you are not "100% compliant" when
    // targeted Macs/Linux boxes can't be enforced, so the headline % must drop.
    const int64_t cc_total = cc_ok + cc_drift + cc_err + cc_unk + cc_notimpl;

    // Agents that own AT LEAST ONE real, currently-unenforced (agent, rule) pair
    // (from the notimpl fold above — #4252 pair-level attribution), grouped by
    // display name (macOS / Linux) for the honesty banner below. std::map for a
    // stable, alphabetical order. Deliberately NOT "any connected agent on a
    // platform we don't fully support everything on" — that agent-level rule
    // would trip the banner for an agent whose only deployed guard IS supported
    // on its platform (e.g. a Linux box running only a Service guard), which is
    // exactly the double-count class #4252 fixes, just on the banner instead of
    // the census.
    std::map<std::string, int> notimpl_agents;
    for (const auto& aid : agents_with_notimpl_pair)
        if (auto it = online_os.find(aid); it != online_os.end())
            ++notimpl_agents[guardian::platform_display_name(it->second)];
    int notimpl_agent_total = 0;
    for (const auto& [name, n] : notimpl_agents) notimpl_agent_total += n;

    int64_t det = 0, rem = 0, fail = 0;
    for (const auto& a : activity) { det += a.detected; rem += a.remediated; fail += a.failed; }
    const int success_pct = (rem + fail > 0) ? static_cast<int>((rem * 100) / (rem + fail)) : 100;

    std::string html;
    html += "<div style=\"display:flex;align-items:center;gap:1rem;flex-wrap:wrap;margin-bottom:0.5rem\">"
            "<span class=\"worst-badge " +
            std::string(worst_badge_class(guards_drifting, static_cast<int>(fail), guards_errored)) + "\">" +
            worst_badge_label(guards_drifting, static_cast<int>(fail), guards_errored) +
            "</span><span style=\"font-size:0.7rem;color:var(--muted)\">activity window: last 7 days</span></div>";

    // Honesty banner: guard support is per GUARD TYPE, not a blanket "Windows
    // only" (Registry/File are Windows-only; Service also runs on Linux, but not
    // macOS — guardian::guardian_guard_supported_on_platform is the single
    // source), and deploy is fleet-wide — so without this an operator who
    // deploys a Baseline could read it as protecting the whole fleet when a
    // connected agent's deployed guard(s) enforce nothing on its platform. State
    // it plainly, with the per-platform count of agents that actually own an
    // unenforced pair (pair-level, #4252), so a no-op platform is never mistaken
    // for an armed one — and Guardian's real Linux Service support is never
    // mistaken for a blanket capability it doesn't have either.
    if (notimpl_agent_total > 0) {
        std::string breakdown;
        for (const auto& [name, n] : notimpl_agents) {
            if (!breakdown.empty()) breakdown += " &middot; ";
            breakdown += html_escape(name) + " " + std::to_string(n);
        }
        html += "<div style=\"background:#241b3a;border:1px solid " + std::string(kNotImplColor) +
                ";color:var(--fg);padding:0.5rem 0.75rem;border-radius:0.4rem;margin-bottom:0.6rem;"
                "font-size:0.74rem;max-width:560px\">&#9888; <b>" + std::to_string(notimpl_agent_total) +
                "</b> connected agent(s) have a deployed Guard that can't arm on their platform (" +
                breakdown + ") &mdash; those Guards are <b>no-ops</b> there, so they are "
                "<b>not enforced</b> and never count as compliant. Registry and File Guards run on "
                "<b>Windows only</b>; Service Guards also run on Linux, but not macOS."
                "</div>";
    }

    html += sech("Coverage");
    html += "<div class=\"stat-cards\">";
    html += navcard(std::to_string(total_guards), "info", "Guards",
                    std::to_string(deployed_guards) + " deployed &middot; " +
                        std::to_string(total_guards - deployed_guards) + " not",
                    "gsGoView('guard')");
    html += navcard(std::to_string(bl_total), "info", "Baselines",
                    std::to_string(bl_deployed) + " deployed &middot; " +
                        std::to_string(bl_total - bl_deployed) + " draft",
                    "gsGoView('baseline')");
    html += navcard(std::to_string(agents), "mute", "Agents", "known to the server",
                    "window.location='/viz/fleet'");
    html += "</div>";

    // ── Compliance census ── proportion bar + legend (NOT a donut), from the
    // per-(agent,rule) status feed. "as of last check-in" framing: figures reflect
    // each Guard's last reported state, not a live probe.
    html += sech("Compliance &mdash; as of last check-in");
    if (cc_total == 0) {
        html += "<div style=\"font-size:0.72rem;color:var(--muted);max-width:520px\">No device "
                "check-ins recorded yet &mdash; as deployed agents report each Guard's state (on change, "
                "piggybacked on the heartbeat) the breakdown appears here.</div>";
    } else {
        const int ok_pct = static_cast<int>((cc_ok * 100) / cc_total);
        // flex:N segments fill the bar exactly in proportion — no integer-% rounding gap.
        auto seg = [](int64_t n, const char* col, const std::string& inner) -> std::string {
            if (n <= 0) return std::string{};
            return "<div style=\"flex:" + std::to_string(n) + ";background:" + col +
                   ";display:flex;align-items:center;justify-content:center;overflow:hidden;"
                   "white-space:nowrap;font-size:0.6rem;color:#04101f;font-weight:700\">" + inner +
                   "</div>";
        };
        html += "<div style=\"display:flex;height:20px;border-radius:4px;overflow:hidden;"
                "border:1px solid rgba(255,255,255,0.1);max-width:520px\">";
        html += seg(cc_ok, "var(--green)", std::to_string(ok_pct) + "% compliant");
        html += seg(cc_drift, "var(--yellow)", "");
        html += seg(cc_err, "var(--red)", "");
        html += seg(cc_unk, "#5b6b80", "");
        html += seg(cc_notimpl, kNotImplColor, "");
        html += "</div>";
        auto leg = [](const char* col, const char* lbl, int64_t n, const std::string& extra) {
            return "<span><i style=\"display:inline-block;width:.55rem;height:.55rem;border-radius:2px;"
                   "margin-right:.3rem;vertical-align:middle;background:" + std::string(col) + "\"></i>" +
                   lbl + " <b style=\"color:var(--fg)\">" + std::to_string(n) + "</b>" + extra + "</span>";
        };
        html += "<div style=\"display:flex;flex-wrap:wrap;gap:1rem;margin-top:0.45rem;"
                "font-size:0.66rem;color:var(--muted)\">";
        html += leg("var(--green)", "Compliant", cc_ok, "");
        html += leg("var(--yellow)", "Drifted", cc_drift, "");
        html += leg("var(--red)", "Error", cc_err, "");
        html += leg("#5b6b80", "Unknown", cc_unk,
                    " <span style=\"color:var(--muted)\">(agent offline &mdash; last state stale)</span>");
        if (cc_notimpl > 0)
            html += leg(kNotImplColor, "Not implemented", cc_notimpl,
                        " <span style=\"color:var(--muted)\">(macOS / Linux &mdash; guard is a no-op on the "
                        "agent)</span>");
        html += "</div>";
        html += "<div style=\"font-size:0.62rem;color:var(--muted);margin-top:0.3rem\">" +
                std::to_string(cc_total) + " device-guard checks across " + std::to_string(agents) +
                " online agent(s), as of each Guard's last reported change." +
                (cc_notimpl > 0 ? " The compliant share is of all targeted device-guard pairs, "
                                  "including the unenforceable ones."
                                : "") +
                "</div>";
    }

    html += sech("Needs attention");
    html += "<div class=\"stat-cards\">";
    html += navcard(std::to_string(guards_drifting), guards_drifting ? "warn" : "good", "Guards drifting",
                    "on " + std::to_string(drift_instances) + " agent(s) now",
                    "gsGoView('guard','drift')");
    // "Enforcement failures" is a 7-day remediation-failure count, which is a
    // different population than the current-state `unhealthy` (err>0) chip — route
    // it to `drift` (the guards that needed remediation) so the card never lands on
    // an empty filtered list (gov Gate-4 happy/UP-7/consistency).
    html += navcard(std::to_string(fail), fail ? "bad" : "good", "Enforcement failures", "last 7d",
                    "gsGoView('guard','drift')");
    html += navcard(std::to_string(guards_errored), guards_errored ? "bad" : "good", "Unhealthy Guards",
                    "errored / watch-deaf now", "gsGoView('guard','unhealthy')");
    html += "</div>";

    html += sech("Enforcement effectiveness (7d)");
    html += "<div class=\"stat-cards\">";
    html += card(std::to_string(det), "warn", "Drift detected", "");
    html += card(std::to_string(rem), "good", "Remediated", "");
    html += card(std::to_string(fail), "bad", "Enforcement failed", "");
    html += card(std::to_string(success_pct) + "%", "good", "Enforcement success",
                 std::to_string(rem) + " / " + std::to_string(rem + fail));
    html += "</div>";

    // 7-day remediation trend (bars). Build today-6 .. today buckets.
    std::unordered_map<std::string, GuardianDayCount> dmap;
    for (const auto& d : store_->daily_remediations(since)) dmap[d.day] = d;
    int64_t dmax = 1;
    struct Bucket { std::string label; int64_t rem; int64_t fail; };
    std::vector<Bucket> buckets;
    for (int i = 6; i >= 0; --i) {
        const std::string iso = format_iso_utc(now_epoch_seconds() - i * 86400);
        const std::string day = iso.substr(0, 10);
        const auto it = dmap.find(day);
        const int64_t r = it != dmap.end() ? it->second.remediated : 0;
        const int64_t f = it != dmap.end() ? it->second.failed : 0;
        dmax = std::max<int64_t>(dmax, r + f);
        buckets.push_back({iso.substr(5, 5), r, f});  // MM-DD
    }
    html += sech("Remediations trend (7d)");
    html += "<div style=\"display:flex;align-items:flex-end;gap:0.4rem;height:84px;margin-top:0.3rem\">";
    for (const auto& b : buckets) {
        const int h = static_cast<int>(((b.rem + b.fail) * 72) / dmax);
        const int rh = (b.rem + b.fail) ? static_cast<int>((b.rem * 100) / (b.rem + b.fail)) : 0;
        html += "<div style=\"flex:1;display:flex;flex-direction:column;align-items:center;gap:0.2rem\">"
                "<div style=\"width:60%;height:" + std::to_string(h) + "px;display:flex;"
                "flex-direction:column-reverse;border-radius:2px 2px 0 0;overflow:hidden;min-height:2px\">"
                "<div style=\"height:" + std::to_string(rh) + "%;background:var(--green)\"></div>"
                "<div style=\"height:" + std::to_string(100 - rh) + "%;background:var(--red)\"></div></div>"
                "<small style=\"font-size:0.56rem;color:var(--muted)\">" + b.label + "</small></div>";
    }
    html += "</div>";
    html += "<div style=\"font-size:0.62rem;color:var(--muted);margin-top:0.3rem\">"
            "<span style=\"color:var(--green)\">&#9632;</span> enforced &nbsp; "
            "<span style=\"color:var(--red)\">&#9632;</span> failed</div>";

    // Data-source honesty: compliance is the per-(agent,rule) status feed (agents
    // report a Guard's state only when it CHANGES — nothing in steady state, so it is
    // network-kind); effectiveness + trend are the drift-event log. Offline agents'
    // last-known states count as Unknown until they re-report.
    html += "<div class=\"mock-note\">Compliance reflects each Guard's last reported state (agents send a "
            "state only when it <em>changes</em>, piggybacked on the heartbeat &mdash; no steady-state "
            "chatter). Effectiveness &amp; the 7-day trend come from the drift-event log. Offline agents "
            "show as Unknown until they re-report.</div>";
    return html;
}

std::string GuardianRoutes::render_guards_fragment(const std::string& status_filter) const {
    std::string html = "<div class=\"guard-list\">";

    // Prefer real authored rules when the store has any; otherwise mock so the
    // page demonstrates the full taxonomy. Per-guard live status aggregation is
    // not yet available, so status/counts remain mock either way.
    // TODO(guardian-backend): fold in GET /api/v1/guaranteed-state/status per guard.
    bool used_real = false;
    if (store_ && store_->is_open()) {
        // list_rules is now type-distinguishable (ADR-0038): a degrade (!rules_result)
        // falls through to the mock demonstration render below — the same fallback
        // this file already applies for `!store_`/`!is_open()` — rather than being
        // treated as "zero authored rules" (which renders the honest empty state).
        auto rules_result = store_->list_rules();
        if (rules_result && !rules_result->empty()) {
            const auto& rules = *rules_result;
            used_real = true;
            // Precompute, per guard rule_id, the DEPLOYED Baselines that contain it
            // (id + name) — one pass over deployed baselines rather than a query per
            // guard — so each row can render "Deployed: <baseline links>".
            std::unordered_map<std::string, std::vector<std::pair<std::string, std::string>>>
                deployed_by_rule;
            if (baseline_store_ && baseline_store_->is_open())
                for (const auto& b : baseline_store_->list_deployed_baselines())
                    for (const auto& mid : baseline_store_->get_members(b.baseline_id))
                        deployed_by_rule[mid].emplace_back(b.baseline_id, b.name);

            for (const auto& r : rules) {
                const std::string os = r.os_target.empty() ? "ALL"
                                       : (r.os_target == "windows" ? "W"
                                          : r.os_target == "linux"  ? "L"
                                          : r.os_target == "macos"  ? "M" : r.os_target);
                const bool on = r.enabled;
                // Mode is the guard's immutable posture: Observe (watch/audit — empty/
                // unknown renders Observe, never a false-green Enforce; C1/B2) or
                // Enforce. Coloured by posture (CSS .gi-mode.observe/.enforce).
                const bool enforcing = (r.enforcement_mode == "enforce");
                const std::string mode_label = enforcing ? "Enforce" : "Observe";
                const char* mode_cls = enforcing ? "enforce" : "observe";
                const std::string rid = html_escape(r.rule_id);

                // Deployment line: the deployed Baselines that deliver this guard, as
                // links to each baseline's view; otherwise an honest "not deployed".
                std::string deploy_html;
                if (auto dit = deployed_by_rule.find(r.rule_id);
                    dit != deployed_by_rule.end() && !dit->second.empty()) {
                    deploy_html = "<span class=\"gi-dep-on\">&#9679; Deployed:</span> ";
                    bool first = true;
                    for (const auto& [bid, bname] : dit->second) {
                        if (!first) deploy_html += ", ";
                        first = false;
                        deploy_html += "<a class=\"gi-bl\" href=\"/guardian/baseline/" +
                                       html_escape(bid) + "\">" + html_escape(bname) + "</a>";
                    }
                } else {
                    deploy_html = "<span class=\"gi-dep-off\">&#9675; not deployed</span>";
                }

                // Left content column carries the detail-nav (clicking it opens the
                // guard); the control button (gi-right) and baseline links (gi-deploy)
                // are outside it, so they keep their own click behaviour.
                html += "<div class=\"guard-item\">"
                        "<div class=\"gi-main\">"
                        "<div class=\"gi-left\" style=\"cursor:pointer\" "
                        "onclick=\"window.location='/guardian/guard/" + rid + "'\">"
                        "<div class=\"gi-row1\">"
                        "<span class=\"guard-name\">" + html_escape(r.name) + "</span>"
                        "<span class=\"gi-mode " + std::string(mode_cls) + "\">" + mode_label +
                        "</span></div>"
                        "<div class=\"gi-meta\">"
                        "<span>" + html_escape(r.severity.empty() ? "medium" : r.severity) + "</span>"
                        "<span class=\"guard-os\">" + html_escape(os) + "</span>"
                        "</div></div>"
                        "<div class=\"gi-right\">"
                        "<span class=\"gi-state " + std::string(on ? "on" : "off") + "\">" +
                        (on ? "ENABLED" : "DISABLED") + "</span>"
                        "<button class=\"btn btn-secondary gi-act\" "
                        "hx-post=\"/fragments/guardian/guard/" + rid + "/enabled?value=" +
                        (on ? "0" : "1") +
                        "\" hx-target=\"#guardian-guards\" hx-swap=\"innerHTML\">" +
                        (on ? "Disable" : "Enable") + "</button>"
                        "</div></div>"
                        "<div class=\"gi-deploy\">" + deploy_html + "</div>"
                        "</div>";
            }
        }
    }

    const bool live = store_ && store_->is_open();
    if (!used_real && live) {
        // Live store, zero authored rules → honest empty state, not fabricated
        // example guards (M2 / #1209; also the empty-store UX wart, where the mock
        // guards had no enable/mode controls and so made the toggle look missing).
        html += empty_state("No Guards defined yet",
                            "Create a Guard to start enforcing desired state across the fleet.");
    } else if (!used_real) {
        // No Guardian backend present (pure UI development) → contract-shaped
        // example guards, loudly labelled below so they cannot be read as live.
        for (const auto& g : kMockGuards) {
            if (!status_filter.empty() && status_filter != g.status) continue;
            const char* health_cls = g.healthy ? "health-ok" : "health-bad";
            const char* health_lbl = g.healthy ? "&#9679; healthy" : "&#9679; unhealthy";
            html += "<div class=\"guard-item\" style=\"cursor:pointer\" "
                    "onclick=\"window.location='/guardian/guard/" + std::string(g.id) + "'\">"
                    "<div class=\"guard-item-top\">"
                    "<span class=\"guard-name\">" + std::string(g.name) + "</span>"
                    "<span class=\"guard-os\">" + std::string(g.os) + "</span>"
                    "<span style=\"margin-left:auto\">" + status_badge(g.status) + "</span>"
                    "</div>"
                    "<div class=\"guard-meta\">"
                    "<span>" + std::string(g.severity) + "</span>"
                    "<span>" + std::to_string(g.compliant) + "/" + std::to_string(g.total) + " agents</span>"
                    "<span class=\"" + health_cls + "\">" + health_lbl + "</span>"
                    "</div></div>";
        }
    }
    html += "</div>";
    if (!used_real && !live)
        html += demo_banner("example Guards, not authored rules");
    return html;
}

void GuardianRoutes::apply_guard_change(const httplib::Request& req, httplib::Response& res,
                                        const std::string& rule_id, bool enabled) {
    // Error responses return 200 with an inline banner PREPENDED to the
    // re-rendered guard list. The dashboard's htmx config does not swap 4xx/5xx
    // bodies (responseHandling swap:false), so a 4xx/5xx error fragment would
    // silently never render and the operator would get no feedback (governance
    // S1). 200 + banner + list keeps the list visible and shows what failed.
    auto fail = [this, &res](const std::string& msg) {
        res.status = 200;
        res.set_content("<div class=\"gs-error-banner\" style=\"background:#3a1a1a;"
                        "color:var(--red);padding:0.5rem 0.75rem;border-radius:0.4rem;"
                        "margin-bottom:0.5rem;font-size:0.78rem\">&#9888; " +
                            html_escape(msg) + "</div>" + render_guards_fragment(""),
                        "text/html; charset=utf-8");
    };

    if (!store_ || !store_->is_open())
        return fail("Guardian store unavailable.");
    // get_rule is now three-state (ADR-0038): found / genuinely absent / degraded.
    auto rule = store_->get_rule(rule_id);
    if (!rule)
        return fail("Guardian store degraded.");
    if (!*rule)
        return fail("No such Guard: " + rule_id);

    (*rule)->enabled = enabled;
    if (auto r = store_->update_rule(**rule); !r)
        return fail("Update failed: " + r.error());

    // STATE-ONLY (no push). A Guard's enabled flag is global state, not an
    // individual deploy — Guards are not deployable on their own; only Baselines
    // are (docs/guardian-baseline-model.md). The change persists now and takes
    // effect on the next Baseline deploy or heartbeat reconcile, both of which
    // re-push the union of *deployed* Baselines' enabled members. (Mode is set at
    // creation and immutable — a different posture is a different Guard — so there
    // is no mode change here.) Audited under its own rule.update verb so "who
    // enabled / disabled this guard" stays queryable.
    audit_fn_(req, "guaranteed_state.rule.update", "success", "GuaranteedState", rule_id,
              std::string(enabled ? "enabled=true" : "enabled=false") +
                  " (state-only; applies on next deploy/reconcile)");
    res.set_content(render_guards_fragment(""), "text/html; charset=utf-8");
}

void GuardianRoutes::create_guard_from_form(const httplib::Request& req, httplib::Response& res) {
    auto get = [&](const std::string& k) -> std::string {
        return req.has_param(k) ? req.get_param_value(k) : std::string{};
    };
    // Errors return 200 + the form re-rendered with an inline banner at its top —
    // htmx's swap:false on 4xx/5xx would otherwise drop the body and the operator
    // would see nothing (same convention as apply_guard_change). Re-entry of values
    // is a known wart (the form re-renders blank); the banner names what to fix.
    auto fail = [&res](const std::string& msg) {
        res.status = 200;
        const std::string banner = "<div class=\"gs-error-banner\" style=\"background:#3a1a1a;"
                                   "color:var(--red);padding:0.5rem 0.75rem;border-radius:0.4rem;"
                                   "margin-bottom:0.6rem;font-size:0.78rem\">&#9888; " +
                                   html_escape(msg) + "</div>";
        res.set_content(guardian::render_guard_form(banner), "text/html; charset=utf-8");
    };

    if (!store_ || !store_->is_open())
        return fail("Guardian store unavailable.");

    const std::string name = get("name");
    if (name.empty())
        return fail("Name is required.");
    // One "Mode" control (Watch | Enforce) replaces the old enforcement-mode +
    // remediation-action pair. Watch = observe & alert (no write-back); Enforce =
    // auto-remediate. The dashboard speaks "Watch"; the stored enforcement_mode
    // value stays "audit" for back-compat (the agent arms enforce only on an exact
    // "enforce" match, so any non-enforce value behaves as observe).
    const bool enforce_mode = get("mode") == "enforce";
    const std::string enforcement_mode = enforce_mode ? "enforce" : "audit";

    // Trigger type IS the assertion type; the schema-driven decoder reads exactly
    // that type's params (namespaced field names), validates required, and derives
    // the paired spark from the assertion family. Single source with render_guard_form.
    const std::string trigger = get("trigger_type").empty() ? "registry-value-equals" : get("trigger_type");
    auto sa = guardian::assemble_spark_assertion(trigger, get);
    if (sa.error)
        return fail(*sa.error);

    // Remediation params = the resilience policy. Only include fields the operator
    // actually set so blanks fall through to defaults rather than being rejected as
    // a non-numeric "" (lenient-in).
    nlohmann::json rem_params;
    rem_params["mode"] = get("resilience_mode").empty() ? "persist" : get("resilience_mode");
    auto add_num = [&](const char* k) {
        const std::string v = get(k);
        if (!v.empty()) rem_params[k] = v;
    };
    add_num("max_attempts");
    add_num("quiet_reset_s");
    add_num("resume_after_s");
    add_num("backoff_initial_ms");
    add_num("backoff_max_ms");
    add_num("event_debounce_ms");

    const std::string action = enforce_mode ? "enforce" : "alert-only";

    nlohmann::json body;
    body["spark"] = std::move(sa.spark);
    body["assertion"] = std::move(sa.assertion);
    body["remediation"] = {{"type", action}, {"params", std::move(rem_params)}};

    // Single source: the same derivation + resilience validation the REST create
    // uses, so the dashboard and the API produce identical specs.
    auto spec = guardian::derive_rule_spec(body, name, /*version=*/1, /*enabled=*/true,
                                           enforcement_mode);
    if (spec.error)
        return fail(spec.error->message);

    GuaranteedStateRuleRow row;
    row.rule_id = slugify(name) + "-" + short_id(); // matches [A-Za-z0-9._-]+
    row.name = name;
    row.spec_json = std::move(spec.spec_json);
    row.yaml_source = std::move(spec.yaml_source);
    row.version = 1;
    row.enabled = true;
    row.enforcement_mode = enforcement_mode;
    // Validate severity against the closed enum — the dashboard renders it into a
    // CSS class attribute, so an unconstrained value is an XSS vector (gov sec-H1).
    // Anything not in {critical,high,low} (incl. empty/garbage) falls back to medium.
    {
        const std::string sv = get("severity");
        row.severity = (sv == "critical" || sv == "high" || sv == "low") ? sv : "medium";
    }
    // The dashboard create-form doesn't expose an os_target choice, so it always
    // stamps Windows — this predates #4252 and is still correct for two of the
    // three spark types (registry-change RegNotifyChangeKeyValue, file-change
    // ReadDirectoryChangesW ARE Windows-only), but is now a real gap for
    // service-status-change: SystemdServiceGuard arms on Linux too
    // (guardian_guard_supported_on_platform), yet a dashboard-created Service
    // Guard can never reach a Linux agent — only REST/MCP (an explicit
    // os_target in the request body) can author one that does. Not fixed here
    // (dashboard-form scope, not this rollup fix's); device targeting proper is
    // set at the Baseline, not per-Guard, regardless.
    row.os_target = "windows";
    row.scope_expr = ""; // unscoped draft — device targeting is set at the Baseline
    const std::string now = format_iso_utc(now_epoch_seconds());
    row.created_at = now;
    row.updated_at = now;
    if (auto session = auth_fn_(req, res)) {
        row.created_by = session->username;
        row.updated_by = session->username;
    }

    if (auto r = store_->create_rule(row); !r)
        return fail("Create failed: " + r.error());

    audit_fn_(req, "guaranteed_state.rule.create", "success", "GuaranteedState", row.rule_id,
              row.name + " (trigger=" + trigger + ", mode=" + row.enforcement_mode + ", action=" +
                  action + ")");

    // Success: a confirmation card in the modal, an out-of-band refresh of the
    // guards list, and a toast (the dashboard's HX-Trigger convention).
    res.set_header("HX-Trigger", R"({"showToast":{"message":"Guard created","level":"success"}})");
    std::string html =
        "<div class=\"gs-modal-card\">"
        "<div class=\"gs-modal-header\"><h3>Guard created</h3>"
        "<button type=\"button\" class=\"gs-modal-close\" onclick=\"guardianCloseModal()\" "
        "aria-label=\"Close\">&times;</button></div>"
        "<div class=\"gs-modal-body\"><div class=\"kv\">"
        "<div class=\"k\">Name</div><div>" +
        html_escape(row.name) +
        "</div>"
        "<div class=\"k\">ID</div><div style=\"font-family:var(--mono);font-size:0.75rem\">" +
        html_escape(row.rule_id) +
        "</div>"
        "<div class=\"k\">Trigger</div><div>" +
        html_escape(trigger) +
        "</div>"
        "<div class=\"k\">Mode</div><div>" +
        std::string(enforce_mode ? "Enforce" : "Observe") + "</div></div>"
        "<div class=\"mock-note\">Created unscoped (draft). Add it to a Baseline to deploy it to "
        "agents.</div></div>"
        "<div class=\"gs-modal-footer\">"
        "<button type=\"button\" class=\"btn btn-secondary\" "
        "hx-get=\"/fragments/guardian/guard-form\" hx-target=\"#guardian-modal-content\" "
        "hx-swap=\"innerHTML\">Create another</button>"
        "<button type=\"button\" class=\"btn btn-secondary\" onclick=\"guardianCloseModal()\">"
        "Close</button></div></div>"
        "<div id=\"guardian-guards\" hx-swap-oob=\"innerHTML\">" +
        render_guards_fragment("") + "</div>";
    res.set_content(html, "text/html; charset=utf-8");
}

void GuardianRoutes::create_baseline_from_form(const httplib::Request& req,
                                               httplib::Response& res) {
    // Errors return 200 + the form re-rendered with an inline banner (htmx's
    // swap:false on 4xx would drop the body) — same convention as the guard form.
    auto fail = [this, &res](const std::string& msg) {
        std::vector<std::string> names;
        if (store_ && store_->is_open())
            for (const auto& r : store_->list_rules().value_or(std::vector<GuaranteedStateRuleRow>{}))
                names.push_back(r.name);
        const std::string banner = "<div class=\"gs-error-banner\" style=\"background:#3a1a1a;"
                                   "color:var(--red);padding:0.5rem 0.75rem;border-radius:0.4rem;"
                                   "margin-bottom:0.6rem;font-size:0.78rem\">&#9888; " +
                                   html_escape(msg) + "</div>";
        res.status = 200;
        // render_baseline_form has no error slot; prepend the banner to its body.
        res.set_content(banner + guardian::render_baseline_form(names),
                        "text/html; charset=utf-8");
    };

    if (!baseline_store_ || !baseline_store_->is_open())
        return fail("Baseline store unavailable.");

    auto get = [&](const std::string& k) -> std::string {
        return req.has_param(k) ? req.get_param_value(k) : std::string{};
    };
    const std::string name = get("name");
    if (name.empty())
        return fail("Name is required.");

    // The create form's member chips carry friendly guard NAMES; the store keys
    // membership on rule_id, so resolve name → rule_id via the Guard store. An
    // unknown name (free-typed, not from the datalist) is reported rather than
    // silently dropped.
    std::vector<std::string> member_ids;
    if (store_ && store_->is_open()) {
        std::unordered_map<std::string, std::string> name_to_id;
        for (const auto& r : store_->list_rules().value_or(std::vector<GuaranteedStateRuleRow>{}))
            name_to_id.emplace(r.name, r.rule_id);
        std::string unknown;
        const size_t n = req.get_param_value_count("guards");
        for (size_t i = 0; i < n; ++i) {
            const std::string gname = req.get_param_value("guards", i);
            if (gname.empty())
                continue;
            if (auto it = name_to_id.find(gname); it != name_to_id.end())
                member_ids.push_back(it->second);
            else
                unknown += (unknown.empty() ? "" : ", ") + gname;
        }
        if (!unknown.empty())
            return fail("Unknown Guard(s): " + unknown + ". Pick from the dropdown.");
    }

    Baseline b;
    b.name = name;
    b.description = get("description");
    if (auto session = auth_fn_(req, res)) {
        b.created_by = session->username;
        b.updated_by = session->username;
    }
    auto created = baseline_store_->create_baseline(b);
    if (!created)
        return fail("Create failed: " + std::string(strip_conflict_prefix(created.error())));
    const std::string id = *created;

    if (!member_ids.empty())
        if (auto r = baseline_store_->set_members(id, member_ids); !r)
            return fail("Baseline created, but adding Guards failed: " + r.error());

    audit_fn_(req, "guaranteed_state.baseline.create", "success", "GuaranteedState", id,
              name + " (members=" + std::to_string(member_ids.size()) + ", draft)");

    // Success: confirmation card in the modal + out-of-band refresh of the
    // baselines list + a toast (the dashboard's HX-Trigger convention).
    res.set_header("HX-Trigger", R"({"showToast":{"message":"Baseline created","level":"success"}})");
    std::string html =
        "<div class=\"gs-modal-card\">"
        "<div class=\"gs-modal-header\"><h3>Baseline created</h3>"
        "<button type=\"button\" class=\"gs-modal-close\" onclick=\"guardianCloseModal()\" "
        "aria-label=\"Close\">&times;</button></div>"
        "<div class=\"gs-modal-body\"><div class=\"kv\">"
        "<div class=\"k\">Name</div><div>" + html_escape(name) + "</div>"
        "<div class=\"k\">Member Guards</div><div>" + std::to_string(member_ids.size()) + "</div>"
        "<div class=\"k\">Lifecycle</div><div>draft</div></div>"
        "<div class=\"mock-note\">Created as a draft. Assign it to management groups and deploy it "
        "from the Baseline's detail panel.</div></div>"
        "<div class=\"gs-modal-footer\">"
        "<button type=\"button\" class=\"btn btn-secondary\" "
        "hx-get=\"/fragments/guardian/baseline-form\" hx-target=\"#guardian-modal-content\" "
        "hx-swap=\"innerHTML\">Create another</button>"
        "<button type=\"button\" class=\"btn btn-secondary\" onclick=\"guardianCloseModal()\">"
        "Close</button></div></div>"
        "<div id=\"guardian-baselines\" hx-swap-oob=\"innerHTML\">" +
        render_baselines_fragment() + "</div>";
    res.set_content(html, "text/html; charset=utf-8");
}

void GuardianRoutes::deploy_baseline(const httplib::Request& req, httplib::Response& res,
                                     const std::string& baseline_id) {
    // Errors render inside the modal (the action buttons target #guardian-modal-content).
    auto panel = [](const std::string& msg) {
        return "<div class=\"gs-modal-card\"><div class=\"gs-modal-body\"><div class=\"empty-state\">" +
               msg + "</div></div><div class=\"gs-modal-footer\"><button type=\"button\" "
               "class=\"btn btn-secondary\" onclick=\"guardianCloseModal()\">Close</button></div></div>";
    };
    if (!baseline_store_ || !baseline_store_->is_open()) {
        audit_fn_(req, "guaranteed_state.baseline.deploy", "denied", "GuaranteedState", baseline_id,
                  "baseline store unavailable");
        res.set_content(panel("Baseline store unavailable."), "text/html; charset=utf-8");
        return;
    }
    bool baseline_store_ok = true;
    auto b = baseline_store_->get_baseline(baseline_id, &baseline_store_ok);
    if (!b) {
        // store_ok disambiguates a transient store fault from a genuine
        // not-found (governance UP-3 finding) — a pool-lease timeout must
        // not be misreported as "Baseline not found" and audit-logged
        // "denied" for a baseline that still exists.
        if (!baseline_store_ok) {
            audit_fn_(req, "guaranteed_state.baseline.deploy", "degraded", "GuaranteedState",
                      baseline_id, "baseline read degraded");
            res.set_content(
                panel("Deploy failed: baseline store degraded, could not read the baseline. Retry."),
                "text/html; charset=utf-8");
            return;
        }
        audit_fn_(req, "guaranteed_state.baseline.deploy", "denied", "GuaranteedState", baseline_id,
                  "no such baseline");
        res.set_content(panel("Baseline not found."), "text/html; charset=utf-8");
        return;
    }

    // Read the live member set via the degrade-DISTINGUISHABLE twin
    // (get_members_checked, not the plain get_members()) — this read is about
    // to be written into a DURABLE enforced snapshot below, so a pool-lease
    // timeout or query error here MUST abort the deploy, never persist an
    // empty "[]" snapshot (a durable fleet-wide disarm of this Baseline).
    // ADR-0055 (baseline_store.hpp get_members_checked doc).
    auto members_result = baseline_store_->get_members_checked(baseline_id);
    if (!members_result) {
        audit_fn_(req, "guaranteed_state.baseline.deploy", "degraded", "GuaranteedState",
                  baseline_id, "member read degraded: " + members_result.error());
        res.set_content(panel("Deploy failed: baseline store degraded, could not read the "
                              "current member set. Retry."),
                        "text/html; charset=utf-8");
        return;
    }

    // Mark deployed (lifecycle + deploy stamps). Re-deploy just refreshes them.
    b->lifecycle = kBaselineDeployed;
    b->deployed_at = now_epoch_seconds();
    // Snapshot exactly the member set being deployed. This is now the AUTHORITATIVE
    // enforced set: BaselineStore::deployed_member_rule_ids() (the push/reconcile
    // gate) reads this snapshot, NOT the live member set — so deploying is the only
    // act (Push-gated) that changes what the fleet enforces. The detail/list
    // renderers diff live members against this to flag "members changed since last
    // deploy — Re-deploy to apply" (baseline_members_drifted); re-deploy refreshes
    // it, clearing the flag and converging the fleet to the new set. Format: a JSON
    // array of rule_id strings (parsed back in baseline_store.cpp).
    b->deployed_snapshot = nlohmann::json(*members_result).dump();
    if (auto session = auth_fn_(req, res)) {
        b->deployed_by = session->username;
        b->updated_by = session->username;
    }
    if (auto r = baseline_store_->update_baseline(*b); !r) {
        audit_fn_(req, "guaranteed_state.baseline.deploy", "failure", "GuaranteedState", baseline_id,
                  "update failed: " + r.error());
        res.set_content(panel("Deploy failed: " + html_escape(r.error())),
                        "text/html; charset=utf-8");
        return;
    }

    // Deploy changes the desired guard set WITHOUT mutating any rule, so bump the
    // policy generation explicitly — otherwise the heartbeat reconcile (which keys
    // off the generation to detect a stale agent) would never fire for a deploy.
    if (store_)
        store_->bump_policy_generation();

    // Converge the fleet to the new deployed-Baseline union. Empty scope = all
    // agents (management-group targeting deferred); full_sync so agents rebuild to
    // exactly the deployed set — a Guard dropped from every deployed Baseline is
    // thereby removed. The push reads the freshly-bumped generation.
    int pushed = -2;
    if (push_fn_)
        pushed = push_fn_(/*scope=*/"", /*full_sync=*/true);

    // Gate 2 LOW2: -2 is "rule store degraded" (distinct from -1 "not wired /
    // other push failure"). The Baseline IS persisted and the generation bumped,
    // so reconcile converges once the store heals — but the operator/SIEM must
    // not be told "deployed" when the fan-out was refused. Branch the audit
    // result + toast on the degraded case.
    const bool degraded = (pushed == -2);
    const std::string deploy = pushed >= 0 ? ("agents=" + std::to_string(pushed))
                               : degraded  ? "store degraded — fan-out deferred to reconcile"
                                           : "push not wired/failed";
    audit_fn_(req, "guaranteed_state.baseline.deploy", degraded ? "degraded" : "success",
              "GuaranteedState", baseline_id,
              b->name + " deployed fleet-wide (" + deploy +
                  ", members=" + std::to_string(baseline_store_->member_count(baseline_id)) + ")");

    if (degraded)
        res.set_header(
            "HX-Trigger",
            R"json({"showToast":{"message":"Baseline saved; fleet fan-out deferred - rule store degraded, reconcile will converge","level":"warning"}})json");
    else
        res.set_header("HX-Trigger",
                       R"({"showToast":{"message":"Baseline deployed","level":"success"}})");
    // Detail is a full page now (/guardian/baseline/<id>) — there is no modal to
    // re-render. Just refresh both lists out-of-band (the baseline lifecycle badge
    // and the guards' "Deployed:" links both change on deploy). The Baselines-list
    // Deploy button uses hx-swap="none"; the page's Re-deploy reloads.
    std::string html = "<div id=\"guardian-baselines\" hx-swap-oob=\"innerHTML\">" +
                       render_baselines_fragment() + "</div>"
                       "<div id=\"guardian-guards\" hx-swap-oob=\"innerHTML\">" +
                       render_guards_fragment("") + "</div>";
    res.set_content(html, "text/html; charset=utf-8");
}

void GuardianRoutes::update_baseline_from_form(const httplib::Request& req, httplib::Response& res,
                                               const std::string& baseline_id) {
    // Re-render the edit form (pre-filled from the store's current state) with an
    // inline banner on error — htmx won't swap a 4xx body.
    auto fail = [this, &res, &baseline_id](const std::string& msg) {
        const std::string banner = "<div class=\"gs-error-banner\" style=\"background:#3a1a1a;"
                                   "color:var(--red);padding:0.5rem 0.75rem;border-radius:0.4rem;"
                                   "margin-bottom:0.6rem;font-size:0.78rem\">&#9888; " +
                                   html_escape(msg) + "</div>";
        res.status = 200;
        res.set_content(banner + render_baseline_edit_form_fragment(baseline_id),
                        "text/html; charset=utf-8");
    };

    if (!baseline_store_ || !baseline_store_->is_open())
        return fail("Baseline store unavailable.");
    auto b = baseline_store_->get_baseline(baseline_id);
    if (!b)
        return fail("Baseline not found.");

    auto get = [&](const std::string& k) -> std::string {
        return req.has_param(k) ? req.get_param_value(k) : std::string{};
    };
    const std::string name = get("name");
    if (name.empty())
        return fail("Name is required.");

    // Resolve posted member-guard NAMES → rule_ids (same as create).
    std::vector<std::string> member_ids;
    if (store_ && store_->is_open()) {
        std::unordered_map<std::string, std::string> name_to_id;
        for (const auto& r : store_->list_rules().value_or(std::vector<GuaranteedStateRuleRow>{}))
            name_to_id.emplace(r.name, r.rule_id);
        std::string unknown;
        const size_t n = req.get_param_value_count("guards");
        for (size_t i = 0; i < n; ++i) {
            const std::string gname = req.get_param_value("guards", i);
            if (gname.empty())
                continue;
            if (auto it = name_to_id.find(gname); it != name_to_id.end())
                member_ids.push_back(it->second);
            else
                unknown += (unknown.empty() ? "" : ", ") + gname;
        }
        if (!unknown.empty())
            return fail("Unknown Guard(s): " + unknown + ". Pick from the dropdown.");
    }

    // Rename only — preserve lifecycle + deploy stamps + description (the form has
    // no description field, so don't let an absent value wipe it).
    b->name = name;
    if (auto session = auth_fn_(req, res))
        b->updated_by = session->username;
    if (auto r = baseline_store_->update_baseline(*b); !r)
        return fail("Save failed: " + std::string(strip_conflict_prefix(r.error())));
    if (auto r = baseline_store_->set_members(baseline_id, member_ids); !r)
        return fail("Saved name, but updating Guards failed: " + r.error());

    const bool deployed = b->lifecycle == kBaselineDeployed;
    audit_fn_(req, "guaranteed_state.baseline.update", "success", "GuaranteedState", baseline_id,
              name + " (members=" + std::to_string(member_ids.size()) + ")");

    // Member edits to a DEPLOYED baseline only reach agents on the next Re-deploy
    // (no generation bump here — the deferred Q-A behaviour). Nudge the operator.
    // The edit form lives in a modal; on save, close it (guardianModalClose) — the
    // detail itself is a full page now, not a modal — and refresh both lists OOB
    // (member edits can change which guards show as deployed-under this baseline).
    const std::string toast =
        deployed
            ? R"({"guardianModalClose":true,"showToast":{"message":"Saved — Re-deploy to apply to agents","level":"warning"}})"
            : R"({"guardianModalClose":true,"showToast":{"message":"Baseline saved","level":"success"}})";
    res.set_header("HX-Trigger", toast);
    std::string html = "<div id=\"guardian-baselines\" hx-swap-oob=\"innerHTML\">" +
                       render_baselines_fragment() + "</div>"
                       "<div id=\"guardian-guards\" hx-swap-oob=\"innerHTML\">" +
                       render_guards_fragment("") + "</div>";
    res.set_content(html, "text/html; charset=utf-8");
}

void GuardianRoutes::delete_baseline_action(const httplib::Request& req, httplib::Response& res,
                                            const std::string& baseline_id) {
    // Errors render inside the modal (the Delete button targets #guardian-modal-content).
    auto panel = [](const std::string& msg) {
        return "<div class=\"gs-modal-card\"><div class=\"gs-modal-body\"><div class=\"empty-state\">" +
               msg + "</div></div><div class=\"gs-modal-footer\"><button type=\"button\" "
               "class=\"btn btn-secondary\" onclick=\"guardianCloseModal()\">Close</button></div></div>";
    };
    if (!baseline_store_ || !baseline_store_->is_open()) {
        audit_fn_(req, "guaranteed_state.baseline.delete", "denied", "GuaranteedState", baseline_id,
                  "baseline store unavailable");
        res.set_content(panel("Baseline store unavailable."), "text/html; charset=utf-8");
        return;
    }
    auto b = baseline_store_->get_baseline(baseline_id);
    if (!b) {
        audit_fn_(req, "guaranteed_state.baseline.delete", "denied", "GuaranteedState", baseline_id,
                  "no such baseline");
        res.set_content(panel("Baseline not found."), "text/html; charset=utf-8");
        return;
    }
    const bool was_deployed = b->lifecycle == kBaselineDeployed;
    const std::string nm = b->name;
    if (auto r = baseline_store_->delete_baseline(baseline_id); !r) {
        audit_fn_(req, "guaranteed_state.baseline.delete", "failure", "GuaranteedState", baseline_id,
                  "delete failed: " + r.error());
        res.set_content(panel("Delete failed: " + html_escape(r.error())), "text/html; charset=utf-8");
        return;
    }

    // If it was deployed, converge the fleet: bump generation + fleet-wide full_sync
    // so its Guards are torn down where no other deployed Baseline still delivers
    // them (the union recomputes without this Baseline's members).
    int pushed = -2;
    if (was_deployed) {
        if (store_)
            store_->bump_policy_generation();
        if (push_fn_)
            pushed = push_fn_(/*scope=*/"", /*full_sync=*/true);
    }
    const std::string detail =
        nm + (was_deployed ? (" (was deployed; reconciled agents=" + std::to_string(pushed) + ")")
                           : " (draft)");
    audit_fn_(req, "guaranteed_state.baseline.delete", "success", "GuaranteedState", baseline_id,
              detail);

    // Close the modal (its subject is gone) and refresh both lists out-of-band.
    // No main-target content → htmx clears #guardian-modal-content; guardianModalClose
    // then hides the overlay.
    res.set_header("HX-Trigger",
                   R"({"guardianModalClose":true,"showToast":{"message":"Baseline deleted","level":"success"}})");
    std::string html = "<div id=\"guardian-baselines\" hx-swap-oob=\"innerHTML\">" +
                       render_baselines_fragment() + "</div>"
                       "<div id=\"guardian-guards\" hx-swap-oob=\"innerHTML\">" +
                       render_guards_fragment("") + "</div>";
    res.set_content(html, "text/html; charset=utf-8");
}

std::string GuardianRoutes::render_events_fragment(const std::string& type_filter,
                                                   const std::string& severity_filter) const {
    (void)severity_filter;
    std::string html = "<div class=\"event-list\">";

    bool used_real = false;
    if (store_ && store_->is_open()) {
        // Resolve rule_id → human Guard name (events store the id) so rows read —
        // and the client-side search filters — by the name the operator knows.
        std::unordered_map<std::string, std::string> rule_name;
        for (const auto& r : store_->list_rules().value_or(std::vector<GuaranteedStateRuleRow>{}))
            rule_name[r.rule_id] = r.name;
        GuaranteedStateEventQuery q;
        q.limit = 20;
        auto rows = store_->query_events(q);
        if (!rows.empty()) {
            used_real = true;
            for (const auto& e : rows) {
                if (!type_filter.empty() && type_filter != e.event_type) continue;
                auto it = rule_name.find(e.rule_id);
                const std::string gname =
                    (it != rule_name.end() && !it->second.empty()) ? it->second : e.rule_id;
                html += "<div class=\"event-item\"><div class=\"event-top\">"
                        "<span class=\"event-time\">" + html_escape(e.timestamp) + "</span>"
                        "<span class=\"event-type " + event_type_class(e.event_type) + "\">" +
                        html_escape(e.event_type) + "</span></div>"
                        "<div class=\"event-detail\"><strong>" + html_escape(gname) +
                        "</strong> on <strong>" + html_escape(e.agent_id) + "</strong></div></div>";
            }
        }
    }

    const bool live = store_ && store_->is_open();
    if (!used_real && live) {
        // Live store, no drift events recorded yet → honest empty state (M2 / #1209).
        html += empty_state("No drift events yet",
                            "Drift detections and remediations from your Guards will appear here.");
    } else if (!used_real) {
        // No Guardian backend present (pure UI development) → example timeline.
        for (const auto& e : kMockEvents) {
            if (!type_filter.empty() && type_filter != e.type) continue;
            html += "<div class=\"event-item\"><div class=\"event-top\">"
                    "<span class=\"event-time\">" + std::string(e.time) + "</span>"
                    "<span class=\"event-type " + event_type_class(e.type) + "\">" +
                    std::string(e.type) + "</span></div>"
                    "<div class=\"event-detail\"><strong>" + std::string(e.guard) +
                    "</strong> on <strong>" + std::string(e.agent) + "</strong> &middot; " +
                    std::string(e.detail) + "</div></div>";
        }
    }
    html += "</div>";
    if (!used_real && !live)
        html += demo_banner("example drift timeline");
    return html;
}

bool GuardianRoutes::baseline_members_drifted(const Baseline& b) const {
    if (b.lifecycle != kBaselineDeployed || b.deployed_snapshot.empty() || !baseline_store_)
        return false;
    auto snap = nlohmann::json::parse(b.deployed_snapshot, nullptr, /*allow_exceptions=*/false);
    if (!snap.is_array())
        return false;
    std::vector<std::string> deployed;
    for (const auto& e : snap)
        if (e.is_string())
            deployed.push_back(e.get<std::string>());
    std::sort(deployed.begin(), deployed.end());
    auto current = baseline_store_->get_members(b.baseline_id);  // ORDER BY rule_id
    std::sort(current.begin(), current.end());                   // defensive
    return current != deployed;
}

std::string GuardianRoutes::render_baselines_fragment() const {
    if (!baseline_store_ || !baseline_store_->is_open())
        return empty_state("Baseline store unavailable",
                           "The Baseline backend is not initialised. Check server /healthz.");

    auto baselines = baseline_store_->list_baselines();
    if (baselines.empty())
        return empty_state("No Baselines yet",
                           "A Baseline is a deployable collection of Guards, targeted at "
                           "management groups. Create one to start deploying Guards to your fleet.");

    std::string html;
    for (const auto& b : baselines) {
        const bool deployed = b.lifecycle == kBaselineDeployed;
        const bool drifted = baseline_members_drifted(b);
        const std::size_t members = baseline_store_->member_count(b.baseline_id);
        const auto assign = baseline_store_->get_assignment(b.baseline_id);
        int inc = 0, exc = 0;
        for (const auto& a : assign)
            (a.disposition == kAssignInclude ? inc : exc)++;
        const std::string rid = html_escape(b.baseline_id);
        const std::string target =
            assign.empty() ? std::string("No management groups assigned")
                           : (std::to_string(inc) + " included &middot; " + std::to_string(exc) +
                              " excluded group(s)");
        // A deployed Baseline whose members changed since last deploy gets an amber
        // "changes pending" marker beside the lifecycle badge.
        const std::string pending =
            drifted ? "<span title=\"Member Guards changed since last deploy — Re-deploy to apply\" "
                      "style=\"font-size:0.66rem;font-weight:600;color:var(--yellow);"
                      "margin-left:0.4rem\">&#9888; changes pending</span>"
                    : "";
        html += "<div class=\"baseline-card\">"
                "<div class=\"baseline-top\">"
                "<a class=\"baseline-name\" href=\"/guardian/baseline/" + rid +
                "\" style=\"color:inherit;text-decoration:none;cursor:pointer\">" + html_escape(b.name) +
                "</a>"
                "<span class=\"lifecycle-" + std::string(deployed ? "deployed" : "draft") +
                "\" style=\"font-size:0.72rem;font-weight:600\">" +
                (deployed ? "&#9679; deployed" : "&#9675; draft") + "</span>" + pending +
                "</div>"
                "<div class=\"baseline-scope\">" + target + "</div>"
                "<div class=\"guard-meta\">"
                "<span>" + std::to_string(members) + " Guards</span>"
                "<span style=\"margin-left:auto;display:flex;gap:0.4rem\">"
                // Edit opens the authoring form (a modal); Deploy posts and lets the
                // handler's out-of-band response refresh both lists in place (hx-swap
                // none) — no detail modal. The name links to the full Baseline page.
                "<button class=\"btn btn-secondary btn-sm\" onclick=\"guardianOpenModal()\" "
                "hx-get=\"/fragments/guardian/baseline/" + rid + "/edit\" "
                "hx-target=\"#guardian-modal-content\" hx-swap=\"innerHTML\">Edit</button>"
                "<button class=\"btn btn-secondary btn-sm\" "
                "hx-post=\"/fragments/guardian/baseline/" + rid + "/deploy\" hx-swap=\"none\">" +
                (deployed ? "Re-deploy" : "Deploy") + "</button></span>"
                "</div></div>";
    }
    return html;
}

// ── Full-page detail renderers ───────────────────────────────────────────────
// Page-shaped (non-modal) content for /guardian/baseline/<id> and
// /guardian/guard/<id> — the Guard and Baseline read views. (These replaced the
// old detail modals, which were retired once every entry point linked to a page.)
// Reuse the store rollups (compliance, activity, baseline membership) laid out as
// a stats-forward page (compliance hero + tiles + filterable table). The shell
// (guardian_page_ui.cpp) provides the nav chrome + .gp-* component CSS.

std::string GuardianRoutes::render_baseline_page_fragment(const std::string& baseline_id) const {
    auto stub = [](const std::string& msg) {
        return "<a class=\"gp-back\" href=\"/guardian\">&larr; All baselines</a>"
               "<div class=\"gp-placeholder\"><b>" + msg + "</b></div>";
    };
    if (!baseline_store_ || !baseline_store_->is_open())
        return stub("Baseline store unavailable");
    auto b = baseline_store_->get_baseline(baseline_id);
    if (!b)
        return stub("Baseline not found");

    const bool deployed = b->lifecycle == kBaselineDeployed;
    const auto members = baseline_store_->get_members(baseline_id);
    const auto assign = baseline_store_->get_assignment(baseline_id);
    const std::string bid = html_escape(b->baseline_id);

    // 7-day activity (detection/remediation sums + per-member last activity).
    const std::string since = format_iso_utc(now_epoch_seconds() - 7 * 86400);
    const auto activity =
        (store_ && store_->is_open()) ? store_->rule_activity(since) : std::vector<GuardianRuleActivity>{};
    std::unordered_map<std::string, const GuardianRuleActivity*> act;
    for (const auto& a : activity) act[a.rule_id] = &a;

    // Per-member compliance rollup (same status-table source as the overview).
    // online_os also carries each agent's platform so a member guard targeting a
    // platform it can't arm THIS guard type on (guardian::
    // guardian_guard_supported_on_platform) folds into a "not implemented" count,
    // never compliant, unless the pair already has a real status row (#4252).
    const std::unordered_map<std::string, std::string> online_os =
        agents_json_fn_ ? parse_online_agent_os(agents_json_fn_())
                        : std::unordered_map<std::string, std::string>{};
    std::unordered_set<std::string> online;
    online.reserve(online_os.size());
    for (const auto& [aid, aos] : online_os) online.insert(aid);
    // ADR-0038 fix (governance finding SEC-2, ledger
    // governance.d/4037-guardian-read-twins.*.jsonl): a degraded read now
    // returns the same "store degraded" placeholder the top-of-function
    // guards already use, instead of folding to an empty rollup via
    // value_or and rendering every member as compliance-blank —
    // indistinguishable from a baseline with no reported status at all.
    // `!store_->is_open()` (store never wired) is a SEPARATE, pre-existing,
    // deliberately unchanged case — this page still renders Baseline
    // metadata with an empty rollup when GuaranteedStateStore isn't wired.
    std::unordered_map<std::string, StateRollup> by_rule;
    // Pairs that already own a REAL status row — the #4252 exclusion index (see
    // has_real_status below), built from the SAME statuses read as by_rule, never
    // a second store query.
    std::unordered_set<PairStatusKey, PairStatusKeyHash> real_status_pairs;
    if (store_ && store_->is_open()) {
        auto statuses = store_->agent_rule_statuses();
        if (!statuses)
            return stub("Guardian store degraded");
        by_rule = rollup_by_rule(*statuses, online);
        real_status_pairs = status_pair_index(*statuses);
    }

    // One list_rules() into a rid->row map (reused for enforcement_mode + os_target +
    // the member labels below) so the page does not issue a get_rule() per member.
    // .value_or({}) (ADR-0038): a degrade renders this baseline page with unresolved
    // member labels (falls back to rule_id below), never a hard failure of the page.
    std::unordered_map<std::string, GuaranteedStateRuleRow> rule_by_id;
    if (store_ && store_->is_open())
        for (auto& r : store_->list_rules().value_or(std::vector<GuaranteedStateRuleRow>{})) {
            const std::string id = r.rule_id;
            rule_by_id.emplace(id, std::move(r));
        }
    // Rules delivered by at least one DEPLOYED Baseline — the not-implemented count is
    // gated on this (the same deployment gate as the fleet census), so a draft member
    // never inflates the chip and this page can never disagree with the By-Baseline row.
    std::unordered_set<std::string> deployed_rules;
    if (baseline_store_ && baseline_store_->is_open())
        for (const auto& db : baseline_store_->list_deployed_baselines())
            for (const auto& mid : baseline_store_->get_members(db.baseline_id))
                deployed_rules.insert(mid);

    StateRollup total;
    int64_t det = 0, rem = 0, fail = 0;
    int guards_drifting = 0, guards_ok = 0, enforce_members = 0;
    for (const auto& rid : members) {
        if (auto it = by_rule.find(rid); it != by_rule.end()) {
            total.ok += it->second.ok; total.drift += it->second.drift;
            total.err += it->second.err; total.unk += it->second.unk;
            if (it->second.drift > 0 || it->second.err > 0) ++guards_drifting;
            else if (it->second.ok > 0) ++guards_ok;
        }
        if (auto it = act.find(rid); it != act.end()) {
            det += it->second->detected; rem += it->second->remediated; fail += it->second->failed;
        }
        if (auto it = rule_by_id.find(rid); it != rule_by_id.end()) {
            if (it->second.enforcement_mode == "enforce") ++enforce_members;
            // Member guards (delivered by a deployed Baseline) targeting ONLINE agents
            // on a platform Guardian can't arm THIS guard type on yet → not-implemented,
            // never compliant (acb332a parity), gated on deployment like the census —
            // UNLESS the pair already owns a real status row (#4252: a pair the
            // agent-side Guardian DOES now arm, e.g. Linux Service, must not be
            // double-counted as both its real state and a synthetic notimpl).
            if (deployed_rules.count(rid)) {
                const std::string spark_type = spark_type_of(it->second.spec_json);
                for (const auto& [aid, aos] : online_os) {
                    if (guardian::guardian_guard_supported_on_platform(aos, spark_type) ||
                        !guardian::os_target_matches(it->second.os_target, aos))
                        continue;
                    if (has_real_status(real_status_pairs, aid, rid)) {
                        note_platform_matrix_stale(metrics_, aid, rid, spark_type);
                        continue;
                    }
                    ++total.notimpl;
                }
            }
        }
    }
    const int64_t obs_total = total.total();  // includes notimpl
    const int pct = obs_total > 0 ? static_cast<int>((total.ok * 100) / obs_total) : 0;
    const int agents = static_cast<int>(online.size());

    auto lower = [](std::string s) {
        for (auto& c : s) if (c >= 'A' && c <= 'Z') c = static_cast<char>(c + 32);
        return s;
    };

    std::string h = "<a class=\"gp-back\" href=\"/guardian\">&larr; All baselines</a>";

    // Header + actions.
    h += "<div class=\"gp-head\"><div><div class=\"gp-titleline\"><h1>" + html_escape(b->name) +
         "</h1><span class=\"gp-pill " + std::string(deployed ? "dep" : "draft") + "\">" +
         (deployed ? "&#9679; deployed" : "&#9675; draft") + "</span></div><div class=\"gp-sub\">" +
         (b->description.empty() ? std::string("Baseline") : html_escape(b->description));
    if (deployed && b->deployed_at > 0)
        h += " &middot; deployed " + html_escape(format_iso_utc(b->deployed_at)) +
             (b->deployed_by.empty() ? "" : " by " + html_escape(b->deployed_by));
    // Actions use onclick + fetch (gpAction), not htmx hx-on: the page CSP forbids
    // 'unsafe-eval' and htmx compiles hx-on handlers with new Function.
    h += "</div></div><div class=\"gp-actions\">"
         "<button class=\"gp-btn accent\" onclick=\"gpAction('POST','/fragments/guardian/baseline/" + bid +
         "/deploy')\">" + std::string(deployed ? "Re-deploy" : "Deploy") +
         "</button><button class=\"gp-btn danger\" onclick=\"gpAction('POST','/fragments/guardian/baseline/" +
         bid + "/delete',{confirm:'Delete this baseline? Guards it uniquely delivers will be removed from "
         "agents on the next reconcile.',go:'/guardian'})\">Delete</button></div></div>";

    if (baseline_members_drifted(*b))
        h += "<div style=\"background:rgba(255,176,32,0.12);border:1px solid var(--yellow);"
             "color:var(--yellow);padding:0.5rem 0.7rem;border-radius:0.4rem;margin-top:0.8rem;"
             "font-size:0.76rem;font-weight:600\">&#9888; Member Guards changed since last deploy &mdash; "
             "<strong>Re-deploy</strong> to apply to agents.</div>";

    // Compliance hero.
    h += "<div class=\"gp-sech\">Compliance &mdash; as of last check-in</div>";
    if (obs_total == 0) {
        h += "<div class=\"gp-note\">No device check-ins recorded yet &mdash; as deployed agents report each "
             "Guard's state (on change, piggybacked on the heartbeat) the breakdown appears here.</div>";
    } else {
        auto seg = [&](const char* col, int64_t n) -> std::string {
            if (n <= 0) return {};
            const int64_t w = (n * 100) / obs_total;
            return "<span style=\"width:" + std::to_string(w) + "%;background:" + col + "\">" +
                   (w >= 8 ? std::to_string(n) : "") + "</span>";
        };
        h += "<div class=\"gp-hero\"><div class=\"gp-pct\">" + std::to_string(pct) +
             "%<small>compliant &middot; " + std::to_string(agents) + " agent(s)</small></div>"
             "<div style=\"flex:1;min-width:320px\"><div class=\"gp-bar\">" +
             seg("var(--green)", total.ok) + seg("var(--yellow)", total.drift) +
             seg("var(--red)", total.err) + seg("#5b6b80", total.unk) + seg(kNotImplColor, total.notimpl) +
             "</div><div class=\"gp-legend\">"
             "<span><i style=\"background:var(--green)\"></i>Compliant <b>" + std::to_string(total.ok) +
             "</b></span><span><i style=\"background:var(--yellow)\"></i>Drifted <b>" +
             std::to_string(total.drift) + "</b></span><span><i style=\"background:var(--red)\"></i>Error <b>" +
             std::to_string(total.err) + "</b></span><span><i style=\"background:#5b6b80\"></i>Unknown <b>" +
             std::to_string(total.unk) + "</b></span>" +
             (total.notimpl > 0 ? "<span><i style=\"background:" + std::string(kNotImplColor) +
                                      "\"></i>Not implemented <b>" + std::to_string(total.notimpl) + "</b></span>"
                                : std::string{}) +
             "</div></div></div>";
    }

    // Stat tiles (mode-aware: remediation tiles only when an Enforce member exists).
    auto tile = [](const std::string& n, const char* tone, const std::string& l, const std::string& sx) {
        return "<div class=\"gp-tile\"><div class=\"n " + std::string(tone) + "\">" + n +
               "</div><div class=\"l\">" + l + "</div>" +
               (sx.empty() ? "" : "<div class=\"sx\">" + sx + "</div>") + "</div>";
    };
    h += "<div class=\"gp-tiles\">";
    h += tile(std::to_string(members.size()), "info", "Member guards",
              std::to_string(guards_drifting) + " drifting &middot; " + std::to_string(guards_ok) + " clean");
    h += tile(std::to_string(agents), "", "Agents", "reporting now");
    h += tile(std::to_string(guards_drifting), guards_drifting ? "warn" : "good", "Guards drifting", "");
    h += tile(std::to_string(det), det ? "warn" : "mute", "Drift detected", "7d");
    if (enforce_members > 0) {
        const int success_pct = (rem + fail > 0) ? static_cast<int>((rem * 100) / (rem + fail)) : 100;
        h += tile(std::to_string(rem), "good", "Remediated", "7d");
        h += tile(std::to_string(fail), fail ? "bad" : "mute", "Enforcement failed", "7d");
        h += tile(std::to_string(success_pct) + "%", "good", "Enforcement success", "");
    }
    h += "</div>";
    if (enforce_members == 0)
        h += "<div class=\"gp-note\"><b>Observe baseline</b> &mdash; no auto-remediation, so no "
             "enforcement-success tiles. Add an Enforce-mode Guard and a remediation block appears here.</div>";

    // Member guards — filterable table.
    h += "<div class=\"gp-sech\">Member guards (" + std::to_string(members.size()) + ")</div>";
    if (members.empty()) {
        h += "<div class=\"gp-placeholder\"><b>No Guards in this Baseline</b>"
             "Add Guards from the Baselines list on the Guardian page.</div>";
    } else {
        h += "<div class=\"gp-filters\">"
             "<span class=\"gp-chip on\" data-gpf=\"m\" data-gpk=\"all\" onclick=\"gpFilter(this)\">All " +
             std::to_string(members.size()) + "</span>"
             "<span class=\"gp-chip\" data-gpf=\"m\" data-gpk=\"drift\" onclick=\"gpFilter(this)\">Drifting " +
             std::to_string(guards_drifting) + "</span>"
             "<span class=\"gp-chip\" data-gpf=\"m\" data-gpk=\"ok\" onclick=\"gpFilter(this)\">Compliant " +
             std::to_string(guards_ok) + "</span>"
             "<input class=\"gp-search\" type=\"search\" placeholder=\"Search guards&hellip;\" "
             "data-gpf=\"m\" oninput=\"gpSearch(this)\"></div>";
        h += "<table class=\"gp-table\"><thead><tr><th>Guard</th><th>Severity</th><th>Mode</th>"
             "<th>State now</th><th class=\"gp-num\">Detected 7d</th><th>Last activity</th></tr></thead><tbody>";
        for (const auto& rid : members) {
            std::string name = rid, sev;
            bool enf = false;
            if (auto it = rule_by_id.find(rid); it != rule_by_id.end()) {
                if (!it->second.name.empty()) name = it->second.name;
                sev = it->second.severity;
                enf = (it->second.enforcement_mode == "enforce");
            }
            StateRollup c;
            if (auto it = by_rule.find(rid); it != by_rule.end()) c = it->second;
            std::string rowstate, state;
            if (c.err > 0) { rowstate = "drift"; state = "<span class=\"gp-err\">errored &middot; " + std::to_string(c.err) + "</span>"; }
            else if (c.drift > 0) { rowstate = "drift"; state = "<span class=\"gp-drift\">drifted on " + std::to_string(c.drift) + "</span>"; }
            else if (c.ok > 0) { rowstate = "ok"; state = "<span class=\"gp-ok\">compliant &middot; " + std::to_string(c.ok) + "</span>"; }
            else if (c.unk > 0) { rowstate = "unk"; state = "<span class=\"gp-unk\">unknown &middot; " + std::to_string(c.unk) + "</span>"; }
            else { rowstate = "unk"; state = "<span class=\"gp-mute\">&mdash;</span>"; }
            const auto* a = act.count(rid) ? act[rid] : nullptr;
            const std::string sevpill =
                sev.empty() ? "<span class=\"gp-mute\">&mdash;</span>"
                            : "<span class=\"gp-pill sev-" + html_escape(sev) + "\">" + html_escape(sev) + "</span>";
            const std::string rurl = "/guardian/guard/" + html_escape(rid);
            h += "<tr class=\"click\" data-gpf=\"m\" data-gpstate=\"" + rowstate + "\" data-gpname=\"" +
                 html_escape(lower(name)) + "\" onclick=\"window.location='" + rurl + "'\">"
                 "<td><a href=\"" + rurl + "\">" + html_escape(name) + "</a></td><td>" + sevpill +
                 "</td><td><span class=\"gp-pill " + std::string(enf ? "enforce" : "observe") + "\">" +
                 (enf ? "Enforce" : "Observe") + "</span></td><td>" + state + "</td><td class=\"gp-num\">" +
                 std::to_string(a ? a->detected : 0) + "</td><td class=\"gp-mute\">" +
                 (a && !a->last_activity.empty() ? html_escape(a->last_activity.substr(0, 16)) : "&mdash;") +
                 "</td></tr>";
        }
        h += "</tbody></table>";
    }

    // Recent events for this Baseline's member Guards (from the drift-event log; a
    // quiet Baseline simply shows none — no extra fleet traffic).
    {
        std::unordered_set<std::string> member_set(members.begin(), members.end());
        std::string evs;
        int shown = 0;
        if (store_ && store_->is_open() && !member_set.empty()) {
            GuaranteedStateEventQuery q;
            q.limit = 100;
            for (const auto& e : store_->query_events(q)) {
                if (!member_set.count(e.rule_id)) continue;
                std::string gname = e.rule_id;
                if (auto it = rule_by_id.find(e.rule_id); it != rule_by_id.end() && !it->second.name.empty())
                    gname = it->second.name;
                evs += "<div class=\"gp-ev\"><span class=\"t\">" + html_escape(e.timestamp.substr(0, 19)) +
                       "</span><span class=\"gp-badge\">" + html_escape(e.event_type) + "</span><span>" +
                       html_escape(gname) + " &middot; <b>" + html_escape(e.agent_id.substr(0, 12)) +
                       "</b></span></div>";
                if (++shown >= 12) break;
            }
        }
        h += "<div class=\"gp-sech\">Recent events</div>";
        h += evs.empty() ? std::string("<div class=\"gp-note\">No drift events recorded for this "
                                       "Baseline's Guards yet.</div>")
                         : "<div>" + evs + "</div>";
    }

    // Assignment (deferred until management groups land).
    h += "<div class=\"gp-sech\">Assignment <span style=\"font-weight:400;color:var(--muted);"
         "text-transform:none;letter-spacing:0\">(management groups)</span></div>";
    if (assign.empty()) {
        h += "<div class=\"gp-placeholder\"><b>Targeting not available yet</b>"
             "Management-group targeting (included / excluded groups) lands when the global "
             "management-group feature is ready. Deploy currently applies this Baseline's enabled "
             "Guards fleet-wide (all agents, OS-filtered per Guard).</div>";
    } else {
        h += "<ul style=\"margin:0;padding-left:1.1rem;font-size:0.8rem\">";
        for (const auto& a : assign)
            h += "<li>" + html_escape(a.disposition) + ": <code>" + html_escape(a.group_id) + "</code></li>";
        h += "</ul>";
    }
    return h;
}

std::string GuardianRoutes::render_guard_page_fragment(const std::string& guard_id) const {
    std::string name = guard_id, severity, os = "all", os_target_raw = "windows", yaml, spec_json;
    bool real_rule = false, enabled = true, enforcing = false;
    if (store_ && store_->is_open()) {
        // get_rule is now three-state (ADR-0038): found / genuinely absent / degraded.
        // Both "not found" and "degraded" fall through to the same "Guard not found"
        // placeholder below — a degrade here is a page-render failure either way.
        if (auto r = store_->get_rule(guard_id); r && *r) {
            const auto& rr = **r;
            real_rule = true;
            name = rr.name;
            severity = rr.severity;
            enforcing = (rr.enforcement_mode == "enforce");
            enabled = rr.enabled;
            os_target_raw = rr.os_target;  // raw (empty = all OSes), for os_target_matches
            os = rr.os_target.empty() ? "all" : rr.os_target;
            yaml = rr.yaml_source;
            spec_json = rr.spec_json;
        }
    }
    if (!real_rule)
        return "<a class=\"gp-back\" href=\"/guardian\">&larr; All guards</a>"
               "<div class=\"gp-placeholder\"><b>Guard not found</b></div>";

    // #2437-class guard: check nesting on the RAW stored spec_json text
    // BEFORE any parse of it below - spark_type_of's own parse, and the
    // "what it checks" parse further down that feeds render_assertion_values'
    // as_str(), which dump()s any non-string params value. B1/B2 close the
    // REST write side (both create and update reject an over-deep body
    // before derive_rule_spec), but this read path stays reachable against a
    // row written before that fix shipped, or by direct DB manipulation - a
    // routine page load must not crash the whole process. Treat a poisoned
    // spec_json as unusable for rendering rather than partially parsing it;
    // the rest of this page (fleet compliance, device census) does not
    // depend on spec_json and still renders normally. This is a read-only
    // display decision: it does not heal/rewrite the stored row, which this
    // function does not own.
    const bool spec_poisoned =
        !spec_json.empty() && mcp::json_exceeds_depth(spec_json, mcp::kMcpMaxJsonDepth);

    // Parsed once, outside the per-agent loop below (#4252): the input to
    // guardian::guardian_guard_supported_on_platform's guard-type-aware check.
    const std::string spark_type = spec_poisoned ? std::string{} : spark_type_of(spec_json);

    const std::string mode = enforcing ? "Enforce" : "Observe";
    const std::string mode_color = enforcing ? "var(--yellow)" : "#a5d6ff";

    // Which DEPLOYED Baselines deliver this guard (link to their pages).
    std::string delivered = "<span class=\"gp-mute\">not in a deployed Baseline</span>";
    int baseline_count = 0;
    if (baseline_store_ && baseline_store_->is_open()) {
        std::string links;
        for (const auto& bid : baseline_store_->baselines_containing_rule(guard_id)) {
            auto b = baseline_store_->get_baseline(bid);
            if (!b || b->lifecycle != kBaselineDeployed) continue;
            ++baseline_count;
            if (!links.empty()) links += ", ";
            links += "<a href=\"/guardian/baseline/" + html_escape(bid) + "\">" + html_escape(b->name) + "</a>";
        }
        if (!links.empty()) delivered = links;
    }

    // "What it checks" — parse the structured spec for the assertion values.
    // Skipped entirely when spec_poisoned (see the guard above): values_html
    // stays empty and the "What it checks" section below renders the
    // explicit invalid-data state instead of attempting the parse.
    std::string values_html;
    if (!spec_poisoned && !spec_json.empty())
        if (auto j = nlohmann::json::parse(spec_json, nullptr, false); j.is_object())
            values_html = render_assertion_values(j.value("assertion", nlohmann::json::object()), mode_color);

    // Per-device census (current state per agent, from the status feed; offline → unknown).
    struct DevRow { std::string host; std::string agent_id; std::string state; std::string updated; bool online{false}; };
    std::vector<DevRow> devs;
    int64_t d_ok = 0, d_drift = 0, d_err = 0, d_unk = 0, d_notimpl = 0;
    if (store_ && store_->is_open()) {
        std::unordered_map<std::string, std::string> hostname;
        std::unordered_map<std::string, std::string> agent_os;  // connected agents → platform
        if (agents_json_fn_) {
            auto j = nlohmann::json::parse(agents_json_fn_(), nullptr, false);
            const nlohmann::json* arr =
                j.is_array() ? &j
                : (j.is_object() && j.contains("agents") && j["agents"].is_array()) ? &j["agents"] : nullptr;
            if (arr)
                for (const auto& a : *arr)
                    if (a.contains("agent_id") && a["agent_id"].is_string()) {
                        const auto id = a["agent_id"].get<std::string>();
                        hostname[id] = a.value("hostname", std::string{});
                        agent_os[id] = a.value("os", std::string{});
                    }
        }
        // (agent_id, guard_id) pair-keys that already have a real status row — the
        // #4252 exclusion index (see has_real_status); guard_id is fixed for this
        // whole page, so the composite key just carries it through for the one
        // predicate shared with the other 2 fold sites in this file.
        std::unordered_set<PairStatusKey, PairStatusKeyHash> seen;
        // #4037: same shared builder as the REST/MCP twins
        // (guardian_model.hpp::guardian_rule_agent_status_rows), so all three
        // surfaces compute this census identically. ADR-0038 fix (governance
        // finding SEC-2, ledger governance.d/4037-guardian-read-twins.*.jsonl):
        // a degraded read (nullopt) now returns a distinct placeholder BELOW,
        // instead of folding to an empty vector via value_or and rendering
        // "no devices report this guard" — indistinguishable from a genuinely
        // unreported guard. Matches the main guards-overview route's existing
        // posture (this file, ~line 401) and the per-device Guardian lens
        // (device_routes.cpp). See the sibling fix in
        // render_baseline_page_fragment's by_rule computation above in this
        // file for the same class of gap on the baseline detail page.
        auto status_rows = yuzu::server::guardian_rule_agent_status_rows(*store_, guard_id);
        if (!status_rows)
            return "<a class=\"gp-back\" href=\"/guardian\">&larr; All guards</a>"
                   "<div class=\"gp-placeholder\"><b>Guard status degraded</b><br>"
                   "Check server /healthz.</div>";
        for (const auto& s : *status_rows) {
            seen.insert(PairStatusKey{s.agent_id, guard_id});
            DevRow d;
            d.online = hostname.count(s.agent_id) > 0;
            d.host = (d.online && !hostname[s.agent_id].empty()) ? hostname[s.agent_id] : s.agent_id.substr(0, 12);
            d.agent_id = s.agent_id;
            d.updated = s.updated_at;
            d.state = d.online ? s.state : "unknown";
            if (d.state == "compliant") ++d_ok;
            else if (d.state == "drifted") ++d_drift;
            else if (d.state == "errored") ++d_err;
            else ++d_unk;
            devs.push_back(std::move(d));
        }
        // Connected agents this guard targets but whose platform Guardian cannot arm
        // THIS guard type on yet — they own no status row; surface them as "not
        // implemented" so a Mac never silently looks compliant or is omitted
        // (acb332a parity). Gated on the guard being DEPLOYED (baseline_count > 0):
        // a draft Guard reaches no device, so it has no not-implemented
        // device-guard pairs to show. `seen` (built above from the SAME
        // status_rows) already excludes any pair with a real status row — #4252:
        // a pair the agent-side Guardian DOES now arm (e.g. Linux Service) must
        // never be double-counted as both its real state and a synthetic
        // not-implemented row. Unlike the other 2 fold sites, this page was
        // ALREADY pair-deduped pre-#4252 (this `seen` check pre-dates the fix),
        // so a real-status pair here was never at risk of a duplicate DevRow —
        // note_platform_matrix_stale() is deliberately NOT called on this path;
        // the sites that could actually double-count (fleet/baseline additive
        // rollups) already fire it for the identical (agent, rule) pair whenever
        // those views are rendered.
        if (baseline_count > 0)
            for (const auto& [aid, aos] : agent_os) {
                if (has_real_status(seen, aid, guard_id)) continue;
                if (guardian::guardian_guard_supported_on_platform(aos, spark_type)) continue;
                if (!guardian::os_target_matches(os_target_raw, aos)) continue;
                DevRow d;
                d.online = true;
                d.agent_id = aid;
                d.host = !hostname[aid].empty() ? hostname[aid] : aid.substr(0, 12);
                d.state = "not-implemented";
                d.updated = guardian::platform_display_name(aos);  // platform name in the "As of" slot
                ++d_notimpl;
                devs.push_back(std::move(d));
            }
        auto rank = [](const std::string& st) {
            return st == "drifted" ? 0 : st == "errored" ? 1 : st == "compliant" ? 2
                   : st == "not-implemented" ? 3 : 4;
        };
        std::sort(devs.begin(), devs.end(), [&](const DevRow& a, const DevRow& b) {
            const int ra = rank(a.state), rb = rank(b.state);
            return ra != rb ? ra < rb : a.host < b.host;
        });
    }
    const int64_t d_total = d_ok + d_drift + d_err + d_unk + d_notimpl;
    const int pct = d_total > 0 ? static_cast<int>((d_ok * 100) / d_total) : 0;

    // 7-day activity for this guard.
    int64_t det = 0; std::string last_activity;
    if (store_ && store_->is_open())
        for (const auto& a : store_->rule_activity(format_iso_utc(now_epoch_seconds() - 7 * 86400)))
            if (a.rule_id == guard_id) { det = a.detected; last_activity = a.last_activity; break; }

    const std::string sevclass = severity.empty() ? "" : "sev-" + html_escape(severity);

    std::string h = "<a class=\"gp-back\" href=\"/guardian\">&larr; All guards</a>";
    h += "<div class=\"gp-head\"><div><div class=\"gp-titleline\"><h1>" + html_escape(name) + "</h1>";
    if (!severity.empty())
        h += "<span class=\"gp-pill " + sevclass + "\">" + html_escape(severity) + "</span>";
    h += "<span class=\"gp-pill " + std::string(enforcing ? "enforce" : "observe") + "\">" + mode +
         "</span><span class=\"gp-pill\" style=\"color:" +
         std::string(enabled ? "var(--green)" : "var(--muted)") + "\">" +
         (enabled ? "&#9679; enabled" : "&#9675; disabled") + "</span></div>"
         "<div class=\"gp-sub\">Delivered by <b style=\"color:#a5d6ff\">" + std::to_string(baseline_count) +
         " Baseline(s)</b> &middot; " + delivered + " &middot; reports on change (heartbeat)</div></div>"
         "<div class=\"gp-actions\">"
         "<button class=\"gp-btn accent\" onclick=\"location.reload()\">&#10227; Refresh</button>"
         "<button class=\"gp-btn\" onclick=\"gpAction('POST','/fragments/guardian/guard/" +
         html_escape(guard_id) + "/enabled?value=" + (enabled ? "0" : "1") + "')\">" +
         (enabled ? "Disable" : "Enable") + "</button></div></div>";

    // What it checks.
    h += "<div class=\"gp-sech\">What it checks</div>";
    if (spec_poisoned) {
        // Distinct from "not available" below: this Guard DOES have a
        // stored structured spec, but it cannot be safely parsed/displayed
        // (#2437-class). Must never read as "no spec" or "guard not found".
        h += "<div class=\"gp-note\">This Guard's stored spec could not be displayed "
             "(invalid data).</div>";
    } else if (values_html.empty()) {
        h += "<div class=\"gp-note\">This Guard's structured spec is not available.</div>";
    } else {
        h += "<div class=\"gp-spec\"><div class=\"k\">Mode</div><div style=\"color:" + mode_color +
             ";font-weight:700\">" + mode + "</div><div class=\"k\">OS target</div><div>" + html_escape(os) +
             "</div>" + values_html + "</div>";
    }

    // Fleet compliance hero.
    h += "<div class=\"gp-sech\">Fleet compliance &mdash; as of last check-in</div>";
    if (d_total == 0) {
        h += "<div class=\"gp-note\">No device has reported this Guard's state yet &mdash; states appear as "
             "deployed agents report (on change).</div>";
    } else {
        auto seg = [&](const char* col, int64_t n) -> std::string {
            if (n <= 0) return {};
            const int64_t w = (n * 100) / d_total;
            return "<span style=\"width:" + std::to_string(w) + "%;background:" + col + "\">" +
                   (w >= 8 ? std::to_string(n) : "") + "</span>";
        };
        h += "<div class=\"gp-hero\"><div class=\"gp-pct\">" + std::to_string(pct) +
             "%<small>compliant &middot; " + std::to_string(d_total) + " device(s)</small></div>"
             "<div style=\"flex:1;min-width:320px\"><div class=\"gp-bar\">" +
             seg("var(--green)", d_ok) + seg("var(--yellow)", d_drift) + seg("var(--red)", d_err) +
             seg("#5b6b80", d_unk) + seg(kNotImplColor, d_notimpl) + "</div><div class=\"gp-legend\">"
             "<span><i style=\"background:var(--green)\"></i>Compliant <b>" + std::to_string(d_ok) +
             "</b></span><span><i style=\"background:var(--yellow)\"></i>Drifted <b>" + std::to_string(d_drift) +
             "</b></span><span><i style=\"background:var(--red)\"></i>Error <b>" + std::to_string(d_err) +
             "</b></span><span><i style=\"background:#5b6b80\"></i>Unknown <b>" + std::to_string(d_unk) +
             "</b></span>" +
             (d_notimpl > 0 ? "<span><i style=\"background:" + std::string(kNotImplColor) +
                                  "\"></i>Not implemented <b>" + std::to_string(d_notimpl) + "</b></span>"
                            : std::string{}) +
             "</div></div></div>";
    }
    {
        auto tile = [](const std::string& n, const char* tone, const std::string& l, const std::string& sx) {
            return "<div class=\"gp-tile\"><div class=\"n " + std::string(tone) + "\">" + n +
                   "</div><div class=\"l\">" + l + "</div>" +
                   (sx.empty() ? "" : "<div class=\"sx\">" + sx + "</div>") + "</div>";
        };
        h += "<div class=\"gp-tiles\">";
        h += tile(std::to_string(d_drift), d_drift ? "warn" : "good", "Agents drifted",
                  "of " + std::to_string(d_total));
        h += tile(std::to_string(det), det ? "warn" : "mute", "Drift detected", "7d");
        h += tile(last_activity.empty() ? "&mdash;" : html_escape(last_activity.substr(0, 16)), "", "Last activity", "");
        h += tile(std::to_string(baseline_count), "info", "Baselines", "delivering this guard");
        h += "</div>";
    }
    if (!enforcing)
        h += "<div class=\"gp-note\"><b>Observe guard</b> &mdash; reports drift, no auto-remediation. Switch "
             "to Enforce and a remediation-effectiveness block appears here.</div>";

    // Per-device census (filterable, on-demand).
    h += "<div class=\"gp-sech\">Per-device status <span style=\"font-weight:400;color:var(--muted);"
         "text-transform:none;letter-spacing:0\">&mdash; on-demand census</span></div>";
    if (d_total == 0) {
        h += "<div class=\"gp-note\">No device reports yet.</div>";
    } else {
        h += "<div class=\"gp-filters\">"
             "<span class=\"gp-chip on\" data-gpf=\"d\" data-gpk=\"all\" onclick=\"gpFilter(this)\">All " +
             std::to_string(d_total) + "</span>"
             "<span class=\"gp-chip\" data-gpf=\"d\" data-gpk=\"drifted\" onclick=\"gpFilter(this)\">Drifted " +
             std::to_string(d_drift + d_err) + "</span>"
             "<span class=\"gp-chip\" data-gpf=\"d\" data-gpk=\"compliant\" onclick=\"gpFilter(this)\">Compliant " +
             std::to_string(d_ok) + "</span>"
             "<span class=\"gp-chip\" data-gpf=\"d\" data-gpk=\"unknown\" onclick=\"gpFilter(this)\">Unknown " +
             std::to_string(d_unk) + "</span>" +
             (d_notimpl > 0 ? "<span class=\"gp-chip\" data-gpf=\"d\" data-gpk=\"notimpl\" "
                              "onclick=\"gpFilter(this)\">Not impl " + std::to_string(d_notimpl) + "</span>"
                            : std::string{}) +
             "<input class=\"gp-search\" type=\"search\" placeholder=\"Search devices&hellip;\" "
             "data-gpf=\"d\" oninput=\"gpSearch(this)\"></div>";
        h += "<table class=\"gp-table\"><thead><tr><th>Device</th><th>Status</th><th>As of</th></tr></thead><tbody>";
        auto lower = [](std::string s) {
            for (auto& c : s) if (c >= 'A' && c <= 'Z') c = static_cast<char>(c + 32);
            return s;
        };
        for (const auto& d : devs) {
            const bool ni = d.state == "not-implemented";
            const char* cls = d.state == "compliant" ? "gp-ok"
                            : d.state == "drifted"   ? "gp-drift"
                            : d.state == "errored"   ? "gp-err" : "gp-unk";
            const std::string statecell =
                ni ? "<span style=\"color:" + std::string(kNotImplColor) +
                         ";font-weight:600\">&#9679; not yet implemented</span>"
                   : "<span class=\"" + std::string(cls) + "\">&#9679; " + html_escape(d.state) + "</span>";
            // not-impl rows carry the platform display name in `updated`, not a timestamp.
            const std::string as_of =
                ni ? "guard is a no-op on " + html_escape(d.updated)
                   : (d.updated.empty() ? "&mdash;" : html_escape(d.updated.substr(0, 16)));
            const std::string rowstate = ni ? "notimpl" : (d.state == "errored" ? "drifted" : d.state);
            h += "<tr data-gpf=\"d\" data-gpstate=\"" + rowstate + "\" data-gpname=\"" +
                 html_escape(lower(d.host)) + "\"><td class=\"" + std::string(d.online ? "" : "gp-mute") +
                 "\"><a href=\"/viz/host/" + html_escape(d.agent_id) +
                 "\" style=\"color:inherit;text-decoration:none\" title=\"Open host detail\">" +
                 html_escape(d.host) + "</a>" +
                 (d.online ? "" : " <span style=\"font-size:0.66rem\">(offline)</span>") +
                 "</td><td>" + statecell + "</td>"
                 "<td class=\"gp-mute\" style=\"font-size:0.72rem\">" + as_of + "</td></tr>";
        }
        h += "</tbody></table>";
        h += "<div class=\"gp-note\">The census is a scoped, on-demand re-check &mdash; it loads when you open "
             "this page or hit Refresh, never on a timer.</div>";
    }
    return h;
}

std::string GuardianRoutes::render_guard_form_fragment() const {
    // Schema-driven "New Guard" modal: the operator picks a trigger type and only
    // that trigger's fields are shown, rendered from the compiled-in schema catalog
    // (so a new trigger/assertion type appears here with no UI change). Field names
    // map 1:1 to the structured Guard create_guard_from_form() decodes and feeds to
    // derive_rule_spec — the dashboard and the REST API produce identical specs +
    // validation. See guardian_form_render.{hpp,cpp}.
    return guardian::render_guard_form();
}

std::string GuardianRoutes::render_baseline_form_fragment() const {
    // Seed the Member-guards datalist with existing guard names (live wherever the
    // store has authored rules). The create itself is still a mock — the Baseline
    // backend (store + M:N membership + deploy fan-out) is deferred (contract
    // §6/§7). See guardian_form_render.cpp.
    std::vector<std::string> names;
    if (store_ && store_->is_open())
        for (const auto& r : store_->list_rules().value_or(std::vector<GuaranteedStateRuleRow>{}))
            names.push_back(r.name);
    return guardian::render_baseline_form(names);
}

std::string GuardianRoutes::render_baseline_edit_form_fragment(const std::string& baseline_id) const {
    std::vector<std::string> names;
    if (store_ && store_->is_open())
        for (const auto& r : store_->list_rules().value_or(std::vector<GuaranteedStateRuleRow>{}))
            names.push_back(r.name);

    guardian::BaselineFormEdit ec;
    ec.baseline_id = baseline_id;
    if (baseline_store_ && baseline_store_->is_open()) {
        if (auto b = baseline_store_->get_baseline(baseline_id))
            ec.name = b->name;
        // Pre-chip current members by their human name (fall back to rule_id).
        for (const auto& rid : baseline_store_->get_members(baseline_id)) {
            std::string nm = rid;
            if (store_ && store_->is_open())
                if (auto r = store_->get_rule(rid); r && *r && !(*r)->name.empty())
                    nm = (*r)->name;
            ec.selected.push_back(nm);
        }
    }
    return guardian::render_baseline_form(names, ec);
}

// ── Route registration ───────────────────────────────────────────────────────

void GuardianRoutes::register_routes(httplib::Server& svr,
                                     AuthFn auth_fn,
                                     PermFn perm_fn,
                                     AuditFn audit_fn,
                                     EmitEventFn emit_event_fn,
                                     GuaranteedStateStore* store,
                                     BaselineStore* baseline_store,
                                     AgentsJsonFn agents_json_fn,
                                     PushFn push_fn,
                                     yuzu::MetricsRegistry* metrics) {
    // Production adapter: wrap the httplib server in the route-sink seam and
    // delegate to the testable overload below (mirrors RestApiV1 / SettingsRoutes;
    // see http_route_sink.hpp). Lets the handlers be unit-tested in-process via
    // TestRouteSink without httplib's threaded acceptor (the #438 TSan trap).
    HttplibRouteSink sink(svr);
    register_routes(sink, std::move(auth_fn), std::move(perm_fn), std::move(audit_fn),
                    std::move(emit_event_fn), store, baseline_store, std::move(agents_json_fn),
                    std::move(push_fn), metrics);
}

void GuardianRoutes::register_routes(HttpRouteSink& sink,
                                     AuthFn auth_fn,
                                     PermFn perm_fn,
                                     AuditFn audit_fn,
                                     EmitEventFn emit_event_fn,
                                     GuaranteedStateStore* store,
                                     BaselineStore* baseline_store,
                                     AgentsJsonFn agents_json_fn,
                                     PushFn push_fn,
                                     yuzu::MetricsRegistry* metrics) {
    auth_fn_ = std::move(auth_fn);
    perm_fn_ = std::move(perm_fn);
    audit_fn_ = std::move(audit_fn);
    emit_event_fn_ = std::move(emit_event_fn);
    store_ = store;
    baseline_store_ = baseline_store;
    agents_json_fn_ = std::move(agents_json_fn);
    push_fn_ = std::move(push_fn);
    metrics_ = metrics;
    if (metrics_) {
        // Pre-seed the closed spark_type label set (#4252), per
        // docs/observability-conventions.md: a bounded-label counter is
        // initialised at startup so the family (+ HELP/TYPE) is present on a
        // healthy server and absent()-style alerts stay meaningful.
        metrics_->describe(
            "yuzu_server_guardian_platform_matrix_stale_total",
            "Guardian dashboard renders where the server's static guard-type/platform "
            "support matrix said an (agent, rule) pair could not arm, but the agent "
            "already reported real status for it - i.e. the matrix is stale for this "
            "spark type. Render-time only; not a continuous monitor.",
            "counter");
        for (std::string_view t : kMatrixStaleSparkTypes)
            metrics_->counter("yuzu_server_guardian_platform_matrix_stale_total",
                              {{"spark_type", std::string(t)}});
        metrics_->counter("yuzu_server_guardian_platform_matrix_stale_total",
                          {{"spark_type", kMatrixStaleSparkTypeUnknown}});
    }

    // -- Guardian dashboard page ------------------------------------------
    sink.Get("/guardian", [this](const httplib::Request& req, httplib::Response& res) {
        auto session = auth_fn_(req, res);
        if (!session) {
            res.set_redirect("/login");
            return;
        }
        res.set_content(kGuardianHtml, "text/html; charset=utf-8");
    });

    // -- Full-page detail (Baseline / Guard) ------------------------------
    // Auth-only static shell (mirrors /guardian); the page-content fragment it
    // hx-gets on load gates on GuaranteedState:Read. The id is already restricted
    // by the route's char class (the allowlist), so the {{FRAGMENT}}/{{TITLE}}
    // token substitution is safe — same approach as Fleet-Viz /viz/host/<id>.
    auto serve_detail_page = [](httplib::Response& res, const char* title,
                                const std::string& fragment) {
        std::string html(kGuardianDetailPageHtml);
        auto sub = [&](const std::string& tok, const std::string& val) {
            for (auto p = html.find(tok); p != std::string::npos; p = html.find(tok, p + val.size()))
                html.replace(p, tok.size(), val);
        };
        sub("{{TITLE}}", title);
        sub("{{FRAGMENT}}", fragment);
        res.set_header("Cache-Control", "no-cache, no-store, must-revalidate");
        res.set_content(std::move(html), "text/html; charset=utf-8");
    };
    sink.Get(R"(/guardian/baseline/([A-Za-z0-9._\-]+))",
            [this, serve_detail_page](const httplib::Request& req, httplib::Response& res) {
                auto session = auth_fn_(req, res);
                if (!session) { res.set_redirect("/login"); return; }
                serve_detail_page(res, "Yuzu \xE2\x80\x94 Baseline",
                                  "/fragments/guardian/baseline/" + req.matches[1].str() + "/page");
            });
    sink.Get(R"(/guardian/guard/([A-Za-z0-9._\-]+))",
            [this, serve_detail_page](const httplib::Request& req, httplib::Response& res) {
                auto session = auth_fn_(req, res);
                if (!session) { res.set_redirect("/login"); return; }
                serve_detail_page(res, "Yuzu \xE2\x80\x94 Guard",
                                  "/fragments/guardian/guard/" + req.matches[1].str() + "/page");
            });

    // The data-bearing GET fragments below gate on GuaranteedState:Read (M1 /
    // #1209) — they expose rule names, scope expressions, yaml_source and the
    // drift timeline, which for an enforcement subsystem must require the same
    // securable the REST read API does, not bare authentication. perm_fn_
    // subsumes the auth check (it authenticates, then authorises), matching the
    // Write/Push POST handlers below. The page shell stays auth-only: it is
    // static chrome with no rule data, and a non-Read principal simply sees every
    // fragment return 403.

    // -- Status rollup (view = fleet|guard|agent|mgroup|baseline) ----------
    // deny_service_scoped_ runs BEFORE perm_fn_ (independent of RBAC on/off
    // branch ordering inside require_permission — see its doc comment):
    // require_permission's service-token branch checks only the ITServiceOwner
    // ROLE, never the token's own service-tag scope, so perm_fn_ alone would
    // let a token scoped to one service read this fleet-wide view. Blanket
    // deny (not a per-agent scope, mirrors the fleet /guaranteed-state/events
    // REST deny) since these fragments have no single agent_id to confine a
    // per-target check against.
    sink.Get("/fragments/guardian/status",
            [this](const httplib::Request& req, httplib::Response& res) {
                if (deny_service_scoped_(req, res)) return;
                if (!perm_fn_(req, res, "GuaranteedState", "Read")) return;
                const std::string view = req.has_param("view") ? req.get_param_value("view") : "fleet";
                res.set_content(render_status_fragment(view), "text/html; charset=utf-8");
            });

    // -- Guards list (optional ?status= filter) ----------------------------
    sink.Get("/fragments/guardian/guards",
            [this](const httplib::Request& req, httplib::Response& res) {
                if (deny_service_scoped_(req, res)) return;
                if (!perm_fn_(req, res, "GuaranteedState", "Read")) return;
                const std::string sf = req.has_param("status") ? req.get_param_value("status") : "";
                res.set_content(render_guards_fragment(sf), "text/html; charset=utf-8");
            });

    // -- Event timeline (optional ?type= / ?severity= filters) — fleet-wide,
    // full agent_id per row (SEC-2): same blanket deny as /status above.
    sink.Get("/fragments/guardian/events",
            [this](const httplib::Request& req, httplib::Response& res) {
                if (deny_service_scoped_(req, res)) return;
                if (!perm_fn_(req, res, "GuaranteedState", "Read")) return;
                const std::string tf = req.has_param("type") ? req.get_param_value("type") : "";
                const std::string sf = req.has_param("severity") ? req.get_param_value("severity") : "";
                res.set_content(render_events_fragment(tf, sf), "text/html; charset=utf-8");
            });

    // -- Per-guard detail (content for the /guardian/guard/<id> full page) --
    // Worst SEC-2 disclosure: agent_id + hostname + state + updated_at for
    // EVERY reporting agent, fleet-wide, for one rule. Blanket service-token
    // deny (as above) plus an accountability audit-on-open — a control
    // separate from authorization. Verb is `guaranteed_state.rule.view`, NOT
    // device_routes.cpp's `guardian.device.view`: that verb's established
    // contract (its only other emitter, target_type="Agent") means "an
    // operator viewed THIS DEVICE's Guardian state" — this drilldown is the
    // opposite shape, fleet-wide agents for ONE rule, so reusing it would
    // silently corrupt a SIEM/works-council query filtering that verb by
    // target_type=Agent. `target_type="GuaranteedState"` matches every other
    // rule/guard-scoped verb in this file (guaranteed_state.rule.*,
    // guaranteed_state.baseline.*). GuardianRoutes::AuditFn is void (no
    // persist-failure signal, unlike RestApiV1::AuditFn), so both calls below
    // are direct fire-and-forget — the same set-and-proceed idiom every other
    // audit_fn_ call site in this file already uses; a transient audit hiccup
    // must not blank this operator's lens, and a denial is not a leak.
    sink.Get(R"(/fragments/guardian/guard/([A-Za-z0-9._\-]+)/page)",
            [this](const httplib::Request& req, httplib::Response& res) {
                if (deny_service_scoped_(req, res)) return;
                if (!perm_fn_(req, res, "GuaranteedState", "Read")) return;
                const std::string guard_id = req.matches[1].str();
                if (audit_fn_)
                    audit_fn_(req, "guaranteed_state.rule.view", "success", "GuaranteedState",
                              guard_id,
                              "per-guard fleet-wide agent status drilldown via dashboard fragment");
                res.set_content(render_guard_page_fragment(guard_id), "text/html; charset=utf-8");
            });

    // -- Baselines list ----------------------------------------------------
    sink.Get("/fragments/guardian/baselines",
            [this](const httplib::Request& req, httplib::Response& res) {
                if (deny_service_scoped_(req, res)) return;
                if (!perm_fn_(req, res, "GuaranteedState", "Read")) return;
                res.set_content(render_baselines_fragment(), "text/html; charset=utf-8");
            });

    // -- Per-baseline detail (content for the /guardian/baseline/<id> page) --
    // Discloses an agent_id 12-char prefix per member (SEC-2, milder than the
    // guard drilldown but still identity-adjacent fleet-wide): same blanket
    // deny as /status above.
    sink.Get(R"(/fragments/guardian/baseline/([A-Za-z0-9._\-]+)/page)",
            [this](const httplib::Request& req, httplib::Response& res) {
                if (deny_service_scoped_(req, res)) return;
                if (!perm_fn_(req, res, "GuaranteedState", "Read")) return;
                res.set_content(render_baseline_page_fragment(req.matches[1].str()),
                                "text/html; charset=utf-8");
            });

    // -- Create forms ------------------------------------------------------
    // Important finding from external review (PR #3156): missed alongside
    // the data-bearing fragments above - baseline-form and the edit form
    // both call store_->list_rules() to seed a Member-guards datalist,
    // disclosing the fleet-wide rule catalogue (and, for edit, one
    // baseline's own name + member rules) to an otherwise-unconfined
    // service-scoped token. guard-form only serves the compiled-in schema
    // catalog (no live data), but is brought under the same deny for
    // consistency with every other GuaranteedState:Read fragment in this
    // file.
    sink.Get("/fragments/guardian/guard-form",
            [this](const httplib::Request& req, httplib::Response& res) {
                if (deny_service_scoped_(req, res)) return;
                if (!perm_fn_(req, res, "GuaranteedState", "Read")) return;
                res.set_content(render_guard_form_fragment(), "text/html; charset=utf-8");
            });
    sink.Get("/fragments/guardian/baseline-form",
            [this](const httplib::Request& req, httplib::Response& res) {
                if (deny_service_scoped_(req, res)) return;
                if (!perm_fn_(req, res, "GuaranteedState", "Read")) return;
                res.set_content(render_baseline_form_fragment(), "text/html; charset=utf-8");
            });
    // Edit-Baseline modal form (pre-filled name + member chips).
    sink.Get(R"(/fragments/guardian/baseline/([A-Za-z0-9._\-]+)/edit)",
            [this](const httplib::Request& req, httplib::Response& res) {
                if (deny_service_scoped_(req, res)) return;
                if (!perm_fn_(req, res, "GuaranteedState", "Read")) return;
                res.set_content(render_baseline_edit_form_fragment(req.matches[1].str()),
                                "text/html; charset=utf-8");
            });

    // -- Structured create (Guard) ----------------------------------------
    // Build a structured Guard from the create-form fields and persist it via
    // the shared derive_rule_spec path (single source with the REST create).
    sink.Post("/fragments/guardian/guards",
             [this](const httplib::Request& req, httplib::Response& res) {
                 if (deny_service_scoped_mutation_(req, res, "Write",
                                                   "guaranteed_state.rule.create", ""))
                     return;
                 if (!perm_fn_(req, res, "GuaranteedState", "Write")) return;
                 create_guard_from_form(req, res);
             });

    // -- Live guard control: enable/disable (STATE-ONLY) ------------------
    // Edits a Guard's global enabled flag; does NOT deploy (Guards are not
    // individually deployable — only Baselines are). Write only — no Push — since
    // the change propagates on the next Baseline deploy / heartbeat reconcile
    // (docs/guardian-baseline-model.md). There is deliberately NO mode toggle:
    // Watch/Enforce is fixed at creation (a different posture is a different Guard).
    sink.Post(R"(/fragments/guardian/guard/([A-Za-z0-9._\-]+)/enabled)",
             [this](const httplib::Request& req, httplib::Response& res) {
                 const std::string id = req.matches[1].str();
                 if (deny_service_scoped_mutation_(req, res, "Write",
                                                   "guaranteed_state.rule.update", id))
                     return;
                 if (!perm_fn_(req, res, "GuaranteedState", "Write")) return;
                 const bool enable = req.has_param("value") && req.get_param_value("value") == "1";
                 apply_guard_change(req, res, id, enable);
             });

    // -- Structured create (Baseline) -------------------------------------
    // Persist a draft Baseline (name + member guards) via BaselineStore. Device
    // targeting (management-group assignment) + deploy are set afterwards.
    sink.Post("/fragments/guardian/baselines",
             [this](const httplib::Request& req, httplib::Response& res) {
                 if (deny_service_scoped_mutation_(req, res, "Write",
                                                   "guaranteed_state.baseline.create", ""))
                     return;
                 if (!perm_fn_(req, res, "GuaranteedState", "Write")) return;
                 create_baseline_from_form(req, res);
             });

    // -- Deploy / Re-deploy (Baseline-level) ------------------------------
    // Marks the Baseline deployed and converges the fleet to the union of all
    // deployed Baselines' enabled members (fleet-wide for now — management-group
    // targeting is deferred). Requires Push (it changes what agents enforce).
    sink.Post(R"(/fragments/guardian/baseline/([A-Za-z0-9._\-]+)/deploy)",
             [this](const httplib::Request& req, httplib::Response& res) {
                 const std::string id = req.matches[1].str();
                 if (deny_service_scoped_mutation_(req, res, "Push",
                                                   "guaranteed_state.baseline.deploy", id))
                     return;
                 if (!perm_fn_(req, res, "GuaranteedState", "Push")) return;
                 deploy_baseline(req, res, id);
             });

    // -- Edit a Baseline (rename + add/remove member guards) --------------
    // Note: this no-suffix POST is registered AFTER /deploy and /delete; the
    // member regex excludes '/', so it never shadows the suffixed routes.
    sink.Post(R"(/fragments/guardian/baseline/([A-Za-z0-9._\-]+)/delete)",
             [this](const httplib::Request& req, httplib::Response& res) {
                 const std::string id = req.matches[1].str();
                 if (deny_service_scoped_mutation_(req, res, "Delete",
                                                   "guaranteed_state.baseline.delete", id))
                     return;
                 if (!perm_fn_(req, res, "GuaranteedState", "Delete")) return;
                 delete_baseline_action(req, res, id);
             });
    sink.Post(R"(/fragments/guardian/baseline/([A-Za-z0-9._\-]+))",
             [this](const httplib::Request& req, httplib::Response& res) {
                 const std::string id = req.matches[1].str();
                 if (deny_service_scoped_mutation_(req, res, "Write",
                                                   "guaranteed_state.baseline.update", id))
                     return;
                 if (!perm_fn_(req, res, "GuaranteedState", "Write")) return;
                 update_baseline_from_form(req, res, id);
             });
}

} // namespace yuzu::server
