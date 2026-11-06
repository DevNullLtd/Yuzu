/**
 * test_settings_routes_dex_scoring.cpp -- the DEX Scoring tab's route shell (GET
 * /fragments/dex/scoring and POST /api/settings/dex-scoring/{save,preview,reset}) driven
 * in-process through TestRouteSink with the writer deps and the Apps scorer faked: the read gate
 * and its order, the quiet role test, the unwired and degraded states, the dual htmx / plain
 * answer, row-mapped field errors, stale refusal, preview, reset, the cross-site and audit
 * fail-closed paths, and the equivalence of the form and PUT /api/v1/dex/score-policy. No store,
 * no sleeps, no I/O, no [pg].
 */
#include "dex_score_policy_form.hpp"
#include "dex_score_policy_writer.hpp"
#include "rest_api_v1.hpp"
#include "settings_routes.hpp"
#include "store_errors.hpp"

#include "test_route_sink.hpp"

#include <yuzu/server/auth.hpp>
#include <yuzu/server/auto_approve.hpp>
#include <yuzu/server/server.hpp>

#include <catch2/catch_test_macros.hpp>
#include <nlohmann/json.hpp>

#include <cctype>
#include <chrono>
#include <memory>
#include <optional>
#include <shared_mutex>
#include <string>
#include <unordered_map>
#include <utility>
#include <vector>

using namespace yuzu::server;
using json = nlohmann::json;

namespace {

constexpr const char* kGet = "/fragments/dex/scoring";
constexpr const char* kSave = "/api/settings/dex-scoring/save";
constexpr const char* kPreview = "/api/settings/dex-scoring/preview";
constexpr const char* kReset = "/api/settings/dex-scoring/reset";
constexpr const char* kForm = "application/x-www-form-urlencoded";

bool has(const std::string& hay, const std::string& needle) {
    return hay.find(needle) != std::string::npos;
}

std::string encode(const std::string& s) {
    static constexpr char kHex[] = "0123456789ABCDEF";
    std::string out;
    for (const unsigned char c : s) {
        if (std::isalnum(c) || c == '-' || c == '_')
            out += static_cast<char>(c);
        else {
            out += '%';
            out += kHex[c >> 4];
            out += kHex[c & 15];
        }
    }
    return out;
}

std::string form_body(const DexFormValues& v, const std::string& if_match) {
    std::string out;
    if (!if_match.empty())
        out += "if_match=" + encode(if_match);
    for (const auto& [k, val] : v)
        out += (out.empty() ? "" : "&") + encode(k) + "=" + encode(val);
    return out;
}

DexScorePolicy policy_with_excellent(double e) {
    DexScorePolicy p;
    p.tiers.edges.excellent = e;
    return p;
}

std::string doc_with_excellent(double e) {
    return dex_score_policy_canonical(policy_with_excellent(e));
}

struct Row {
    std::string principal, role, action, result, target_type, target_id, detail;
};

const std::unordered_map<std::string, std::string> kHx{{"HX-Request", "true"}};

DexStabilityFigures scored(StabilityBand b) {
    DexStabilityFigures f;
    f.score.band = b;
    return f;
}

struct Harness {
    Config cfg{};
    auth::AuthManager auth_mgr{};
    auth::AutoApproveEngine auto_approve{};
    std::shared_mutex oidc_mu;
    std::unique_ptr<oidc::OidcProvider> oidc_provider;
    SettingsRoutes routes;
    yuzu::server::test::TestRouteSink sink; // after the owner (test_route_sink.hpp invariant 1)

    // The fake store.
    std::optional<std::string> stored;
    bool read_fails{false};
    bool cas_fails{false}; // the commit answers a store error (an ambiguous outcome)
    int cas_calls{0};
    int reads{0};
    std::shared_ptr<DexScorePolicyProvider> provider;

    // The seams.
    bool is_admin{true};
    int admin_calls{0};
    bool perm_allow{true};
    std::string auth_source{"local"};
    std::vector<std::pair<std::string, std::string>> perm_calls;
    std::vector<std::string> events; // "perm" / "read" in the order they happened
    std::vector<Row> rows;           // session-stamped (the writer's rows)
    std::vector<std::string> fn_rows; // re-resolving audit_fn (csrf.denied)
    std::string refuse_result;
    int apps_calls{0};
    bool apps_degraded{false};
    // What the shared scorer's provider cache still holds when it is asked for "the policy in
    // force" (nullopt): unset = the store, set = a replica-lagged older write.
    std::optional<std::string> lagging_cache;
    // A write that lands right after the first store read (the handler's own), before the
    // writer's.
    std::optional<std::string> write_after_first_read;

    explicit Harness(bool wire_writer = true, bool wire_apps = true) {
        provider = std::make_shared<DexScorePolicyProvider>(
            [this]() -> std::expected<std::optional<std::string>, std::string> { return stored; },
            [] { return std::int64_t{1'000'000}; }, std::chrono::milliseconds{1});
        sink.default_headers = {{"Host", "yuzu.test"}, {"Origin", "https://yuzu.test"}};

        auto auth_fn = [this](const httplib::Request&,
                              httplib::Response&) -> std::optional<auth::Session> {
            return session();
        };
        auto admin_fn = [this](const httplib::Request&, httplib::Response& res) {
            ++admin_calls;
            if (!is_admin) {
                res.status = 403;
                return false;
            }
            return true;
        };
        auto perm_fn = [this](const httplib::Request&, httplib::Response& res,
                              const std::string& type, const std::string& op) {
            perm_calls.emplace_back(type, op);
            events.push_back("perm");
            if (!perm_allow) {
                res.status = 403;
                return false;
            }
            return true;
        };
        auto audit_fn = [this](const httplib::Request&, const std::string& action,
                               const std::string& result, const std::string&, const std::string&,
                               const std::string&) -> bool {
            fn_rows.push_back(action + "/" + result);
            return true;
        };
        routes.set_audit_as_session_fn(audit_as_session());
        routes.register_routes(sink, auth_fn, admin_fn, perm_fn, audit_fn, cfg, auth_mgr,
                               auto_approve, /*api_token_store=*/nullptr,
                               /*mgmt_group_store=*/nullptr, /*tag_store=*/nullptr,
                               /*update_registry=*/nullptr, /*runtime_config=*/nullptr,
                               /*audit_store=*/nullptr, /*gateway_enabled=*/false,
                               []() -> std::size_t { return 0; },
                               []() -> std::string { return "[]"; }, oidc_mu, oidc_provider);
        if (wire_writer)
            routes.set_dex_score_policy_writer(deps());
        if (wire_apps)
            routes.set_dex_apps_fn([this](const std::optional<DexPolicyInForce>& p) {
                ++apps_calls;
                DexAppsModel m;
                m.window = "7d";
                m.degraded = apps_degraded;
                m.policy = p ? *p : dex_policy_in_force_from_stored(lagging_cache ? lagging_cache : stored);
                // outlook.exe is Excellent until the excellent edge rises above 90.
                m.apps = {DexAppStability{.subject = "outlook.exe",
                                          .figures = scored(m.policy.policy.tiers.edges.excellent > 90.0
                                                                ? StabilityBand::Good
                                                                : StabilityBand::Excellent)},
                          DexAppStability{.subject = "teams.exe",
                                          .figures = scored(StabilityBand::Excellent)}};
                return m;
            });
    }

    auth::Session session() const {
        auth::Session s;
        s.username = "alice";
        s.role = is_admin ? auth::Role::admin : auth::Role::user;
        s.auth_source = auth_source;
        return s;
    }

    SettingsRoutes::AuditAsSessionFn audit_as_session() {
        return [this](const httplib::Request&, const auth::Session& s, const std::string& role,
                      const std::string& action, const std::string& result,
                      const std::string& target_type, const std::string& target_id,
                      const std::string& detail) {
            if (!refuse_result.empty() && result == refuse_result)
                return false;
            rows.push_back({s.username, role, action, result, target_type, target_id, detail});
            return true;
        };
    }

    DexScorePolicyWriteDeps deps() {
        DexScorePolicyWriteDeps d;
        d.read_stored = [this]() -> std::expected<std::optional<std::string>, std::string> {
            events.push_back("read");
            ++reads;
            if (read_fails)
                return std::unexpected(std::string("store down"));
            const auto seen = stored;
            if (reads == 1 && write_after_first_read)
                stored = write_after_first_read;
            return seen;
        };
        d.compare_and_set = [this](const std::optional<std::string>& expected,
                                   const std::string& canonical,
                                   const std::string&) -> std::expected<bool, std::string> {
            ++cas_calls;
            if (cas_fails)
                return std::unexpected(std::string(kDbErrorPrefix) + "database write failed");
            if (stored != expected)
                return false;
            stored = canonical;
            return true;
        };
        d.compare_and_remove = [this](const std::string& expected)
            -> std::expected<bool, std::string> {
            if (stored != expected)
                return false;
            stored.reset();
            return true;
        };
        d.provider = provider;
        return d;
    }

    std::unique_ptr<httplib::Response>
    get(const std::string& path = kGet) {
        auto res = sink.dispatch("GET", path);
        REQUIRE(res);
        return res;
    }
    std::unique_ptr<httplib::Response>
    post(const std::string& path, const std::string& body,
         std::unordered_map<std::string, std::string> headers = {}) {
        auto res = sink.dispatch("POST", path, body, kForm, headers);
        REQUIRE(res);
        return res;
    }
    std::string stored_revision() const { return dex_score_policy_revision(stored.value_or("")); }
};

std::vector<std::string> control_tags(const std::string& html) {
    std::vector<std::string> out;
    for (const char* open : {"<input", "<button"})
        for (auto at = html.find(open); at != std::string::npos; at = html.find(open, at + 1))
            out.push_back(html.substr(at, html.find('>', at) - at + 1));
    return out;
}

std::size_t count_of(const std::string& hay, const std::string& needle) {
    std::size_t n = 0;
    for (auto at = hay.find(needle); at != std::string::npos; at = hay.find(needle, at + 1))
        ++n;
    return n;
}

} // namespace

TEST_CASE("scoring GET: an administrator gets the whole form after the read gate, with no admin probe",
          "[server][routes][dex][score_policy][scoring]") {
    Harness h;
    SECTION("nothing stored") {
        const auto res = h.get();
        CHECK(res->status == 200);
        REQUIRE(h.perm_calls.size() == 1);
        CHECK(h.perm_calls[0] == std::pair<std::string, std::string>{"GuaranteedState", "Read"});
        REQUIRE(h.events.size() >= 2);
        CHECK(h.events[0] == "perm"); // the gate ran before the store was read
        CHECK(h.events[1] == "read");
        CHECK(h.admin_calls == 0); // the quiet role test, no denied-row probe
        CHECK(has(res->body, "<a class=\"on\" hx-get=\"/fragments/dex/scoring?window=7d\""));
        CHECK(count_of(res->body, "id=\"dex-scoring-section\"") == 1);
        for (const char* name : {"tiers.edges.excellent", "tiers.names.poor", "weights.regression",
                                 "model.per_device_event_cap", "model.interval_confidence"})
            CHECK(has(res->body, std::string("name=\"") + name + "\""));
        CHECK(has(res->body, "name=\"if_match\" value=\"default\""));
        CHECK(has(res->body, "<datalist id=\"dxs-apps\">"));
        CHECK(has(res->body, "<option value=\"outlook.exe\">"));
    }
    SECTION("a stored policy") {
        h.stored = doc_with_excellent(95.0);
        const auto res = h.get();
        CHECK(has(res->body, "name=\"if_match\" value=\"" + h.stored_revision() + "\""));
        CHECK(has(res->body, "name=\"tiers.edges.excellent\" value=\"95\""));
        CHECK(has(res->body, "Custom"));
    }
    SECTION("a stored text that was refused: the fault is shown and the defaults are in force") {
        h.stored = R"({"version":3})";
        const auto res = h.get();
        CHECK(has(res->body, "unsupported_version at version: 3 above the supported 2"));
        CHECK(has(res->body, "Shipped defaults"));
    }
}

TEST_CASE("scoring GET: a reader without GuaranteedState:Read learns nothing",
          "[server][routes][dex][score_policy][scoring]") {
    Harness h;
    h.perm_allow = false;
    const auto res = h.get();
    CHECK(res->status == 403);
    CHECK(h.reads == 0);
    CHECK(h.apps_calls == 0);
    CHECK_FALSE(has(res->body, "tiers.edges"));
    CHECK_FALSE(has(res->body, "outlook.exe"));
}

TEST_CASE("scoring GET: a reader who is not an administrator sees every control disabled",
          "[server][routes][dex][score_policy][scoring]") {
    Harness h;
    h.is_admin = false;
    const auto res = h.get();
    CHECK(res->status == 200);
    CHECK(has(res->body, "data-denied=\"admin\""));
    const auto tags = control_tags(res->body);
    REQUIRE(tags.size() > 20);
    for (const auto& t : tags) {
        INFO(t);
        CHECK(has(t, " disabled"));
    }
    CHECK(h.admin_calls == 0);
}

TEST_CASE("scoring GET: an unwired or unreadable store shows the unavailable note inside the wrapper",
          "[server][routes][dex][score_policy][scoring]") {
    SECTION("writer unwired") {
        Harness h(/*wire_writer=*/false);
        const auto res = h.get();
        CHECK(res->status == 200);
        CHECK(has(res->body, "Config store unavailable"));
        CHECK(has(res->body, "<div id=\"dex-scoring-section\"><div class=\"note warn\">"));
        CHECK_FALSE(has(res->body, "<form"));
    }
    SECTION("store read fails") {
        Harness h;
        h.read_fails = true;
        const auto res = h.get();
        CHECK(res->status == 200);
        CHECK(has(res->body, "Config store unavailable"));
        CHECK_FALSE(has(res->body, "<form"));
    }
}

TEST_CASE("scoring GET: without the signals-store scorer the tab still edits, without suggestions",
          "[server][routes][dex][score_policy][scoring]") {
    Harness h(/*wire_writer=*/true, /*wire_apps=*/false);
    const auto res = h.get();
    CHECK(res->status == 200);
    CHECK(has(res->body, "<form"));
    CHECK_FALSE(has(res->body, "<datalist"));
    CHECK_FALSE(has(res->body, "list=\"dxs-apps\""));
}

TEST_CASE("scoring save: a valid form stores the document, audits it and answers the body only",
          "[server][routes][dex][score_policy][scoring]") {
    Harness h;
    const auto res = h.post(kSave, form_body(dex_form_values(policy_with_excellent(95.0)), "default"), kHx);
    CHECK(res->status == 200);
    CHECK(h.cas_calls == 1);
    CHECK(h.stored == doc_with_excellent(95.0));
    CHECK_FALSE(has(res->body, "id=\"dex-scoring-section\""));
    CHECK(has(res->body, "name=\"if_match\" value=\"" + h.stored_revision() + "\""));
    CHECK(has(res->get_header_value("HX-Trigger"), "Scoring policy saved"));
    REQUIRE(h.rows.size() == 2);
    for (const auto& r : h.rows) {
        CHECK(r.action == "dex.score_policy.update");
        CHECK(r.principal == "alice");
        CHECK(r.target_type == "RuntimeConfig");
        CHECK(r.target_id == "dex_score_policy");
    }
    CHECK(h.rows[0].result == "attempted");
    CHECK(h.rows[1].result == "success");
}

TEST_CASE("scoring save: an invalid document re-renders against its field, stores nothing",
          "[server][routes][dex][score_policy][scoring]") {
    Harness h;
    auto v = dex_form_values(dex_default_score_policy());
    SECTION("a range fault marks the group (htmx)") {
        v["weights.breadth"] = "-1";
        const auto res = h.post(kSave, form_body(v, "default"), kHx);
        CHECK(res->status == 200);
        CHECK(has(res->body, "data-refused=\"invalid\""));
        CHECK(has(res->body, "<span class=\"err\" data-field=\"weights\""));
        CHECK(has(res->body, "weight_invalid at weights"));
        CHECK(has(res->body, "name=\"weights.breadth\" value=\"-1\"")); // the bad input stays visible
        CHECK(has(res->get_header_value("HX-Trigger"), "fix the marked field"));
        CHECK(h.cas_calls == 0);
        CHECK_FALSE(h.stored);
        REQUIRE(h.rows.size() == 1);
        CHECK(h.rows[0].result == "denied");
    }
    SECTION("a value that is not a number marks that exact field") {
        v["weights.hangs"] = "abc";
        const auto res = h.post(kSave, form_body(v, "default"), kHx);
        CHECK(has(res->body, "<span class=\"err\" data-field=\"weights.hangs\""));
        CHECK(has(res->body, "unparseable at weights.hangs: must be a number"));
    }
    SECTION("without HX-Request the real status and the A4 envelope") {
        v["weights.breadth"] = "-1";
        const auto res = h.post(kSave, form_body(v, "default"));
        CHECK(res->status == 400);
        const auto j = json::parse(res->body);
        CHECK(j["error"]["message"] == "weight_invalid at weights");
    }
}

TEST_CASE("scoring save: the error lands on the submitted row after earlier rows were removed",
          "[server][routes][dex][score_policy][scoring]") {
    Harness h;
    auto v = dex_form_values(dex_default_score_policy());
    v["overrides[0].image"] = "gone.exe";
    v["overrides[0].remove"] = "on";
    v["overrides[1].image"] = "dup.exe";
    v["overrides[2].image"] = "dup.exe";
    const auto res = h.post(kSave, form_body(v, "default"), kHx);
    CHECK(has(res->body, "<span class=\"err\" data-field=\"overrides[2].image\""));
    CHECK_FALSE(has(res->body, "<span class=\"err\" data-field=\"overrides[1].image\""));
    CHECK(has(res->body, "override_key_duplicate at overrides[2].image"));
    CHECK(h.cas_calls == 0);
}

TEST_CASE("scoring save: a stale revision is refused and never overwrites",
          "[server][routes][dex][score_policy][scoring]") {
    Harness h;
    h.stored = doc_with_excellent(95.0);
    const auto body = form_body(dex_form_values(policy_with_excellent(96.0)), "default");
    SECTION("htmx") {
        const auto res = h.post(kSave, body, kHx);
        CHECK(res->status == 200);
        CHECK(has(res->body, "data-refused=\"stale\""));
        CHECK(has(res->body, "changed by someone else"));
        for (const auto& t : control_tags(res->body)) {
            if (has(t, "hx-get="))
                continue; // the Reload button
            INFO(t);
            CHECK(has(t, " disabled"));
        }
    }
    SECTION("plain") {
        CHECK(h.post(kSave, body)->status == 409);
    }
    CHECK(h.cas_calls == 0);
    CHECK(h.stored == doc_with_excellent(95.0));
}

TEST_CASE("scoring save: a missing if_match is a 428 or a refusal token",
          "[server][routes][dex][score_policy][scoring]") {
    Harness h;
    const auto body = form_body(dex_form_values(policy_with_excellent(95.0)), "");
    CHECK(h.post(kSave, body)->status == 428);
    CHECK(has(h.post(kSave, body, kHx)->body, "data-refused=\"if_match_missing\""));
    CHECK(h.cas_calls == 0);
}

TEST_CASE("scoring save: a writer failure keeps the edits, with its token and toast (htmx) or its status (plain)",
          "[server][routes][dex][score_policy][scoring]") {
    Harness h;
    h.stored = doc_with_excellent(95.0);
    std::string if_match = h.stored_revision();
    std::string token, toast;
    int status = 0;
    SECTION("a malformed revision") {
        if_match = "zz";
        token = "if_match_malformed";
        toast = "Score policy not saved: reload and try again";
        status = 400;
    }
    SECTION("the store cannot be read") {
        h.read_fails = true;
        token = "store_unavailable";
        toast = "Score policy not saved: try again shortly";
        status = 503;
    }
    SECTION("the commit fails with a store error, so the outcome is unknown") {
        h.cas_fails = true;
        token = "outcome_unknown";
        toast = "Score policy not saved: try again shortly";
        status = 503;
    }
    const auto body = form_body(dex_form_values(policy_with_excellent(96.0)), if_match);

    const auto hx = h.post(kSave, body, kHx);
    CHECK(hx->status == 200);
    CHECK(has(hx->body, "data-refused=\"" + token + "\""));
    CHECK(has(hx->get_header_value("HX-Trigger"), toast));
    CHECK(has(hx->body, "name=\"tiers.edges.excellent\" value=\"96\"")); // the edit stays visible

    const auto plain = h.post(kSave, body);
    CHECK(plain->status == status);
    const auto j = json::parse(plain->body);
    CHECK(j["error"]["message"].is_string());
    if (status == 503)
        CHECK(j["error"]["retry_after_ms"].is_number());
    CHECK(h.stored == doc_with_excellent(95.0)); // nothing was overwritten
}

TEST_CASE("scoring preview: validates, stores nothing, keeps the edits and the current revision",
          "[server][routes][dex][score_policy][scoring]") {
    Harness h;
    const auto res = h.post(kPreview, form_body(dex_form_values(policy_with_excellent(95.0)), "default"), kHx);
    CHECK(res->status == 200);
    CHECK(h.cas_calls == 0);
    CHECK_FALSE(h.stored);
    REQUIRE(h.rows.size() == 1);
    CHECK(h.rows[0].action == "dex.score_policy.validate");
    CHECK(h.rows[0].result == "success");
    CHECK(has(res->body, "name=\"if_match\" value=\"default\""));
    CHECK(has(res->body, "name=\"tiers.edges.excellent\" value=\"95\""));
    CHECK(has(res->body, "1 of 2 applications change tier"));
    CHECK(has(res->body, "<td>outlook.exe</td><td>excellent</td><td>good</td>"));
    CHECK(has(res->get_header_value("HX-Trigger"), "Preview only"));
}

TEST_CASE("scoring preview: the current side is scored under the revision being edited, not the cache",
          "[server][routes][dex][score_policy][scoring]") {
    // The shared scorer's provider cache still holds another replica's older write (excellent
    // edge 95, so outlook.exe is Good); the store, and the form's revision, are the default.
    // Previewing the unchanged default must change nothing, whatever the cache says.
    Harness h;
    h.lagging_cache = doc_with_excellent(95.0);
    const auto res =
        h.post(kPreview, form_body(dex_form_values(dex_default_score_policy()), "default"), kHx);
    CHECK(res->status == 200);
    CHECK(has(res->body, "0 of 2 applications change tier"));
    CHECK(h.cas_calls == 0);
    CHECK_FALSE(h.stored);
}

TEST_CASE("scoring preview: a write between the handler's read and the dry run is unavailable",
          "[server][routes][dex][score_policy][scoring]") {
    // The handler reads the default; before the writer's own read the store moves to a document
    // whose revision the form carries, so the dry run passes while the two reads disagree.
    Harness h;
    h.write_after_first_read = doc_with_excellent(95.0);
    const auto rev = dex_score_policy_revision(*h.write_after_first_read);
    const auto res = h.post(kPreview, form_body(dex_form_values(policy_with_excellent(95.0)), rev), kHx);
    CHECK(res->status == 200);
    CHECK(has(res->get_header_value("HX-Trigger"), "Preview only"));
    CHECK(has(res->body, "Preview unavailable"));
    CHECK(h.cas_calls == 0);
    CHECK(h.stored == doc_with_excellent(95.0));
}

TEST_CASE("scoring preview: degraded or unwired scoring says unavailable and stores nothing",
          "[server][routes][dex][score_policy][scoring]") {
    const auto body = form_body(dex_form_values(policy_with_excellent(95.0)), "default");
    SECTION("the Apps read is degraded") {
        Harness h;
        h.apps_degraded = true;
        CHECK(has(h.post(kPreview, body, kHx)->body, "Preview unavailable"));
        CHECK_FALSE(h.stored);
    }
    SECTION("no scorer wired") {
        Harness h(/*wire_writer=*/true, /*wire_apps=*/false);
        CHECK(has(h.post(kPreview, body, kHx)->body, "Preview unavailable"));
        CHECK_FALSE(h.stored);
    }
}

TEST_CASE("scoring reset: removes the stored policy through the writer",
          "[server][routes][dex][score_policy][scoring]") {
    Harness h;
    SECTION("a stored policy") {
        h.stored = doc_with_excellent(95.0);
        const auto res = h.post(kReset, "if_match=" + h.stored_revision(), kHx);
        CHECK(res->status == 200);
        CHECK_FALSE(h.stored);
        REQUIRE(h.rows.size() == 2);
        CHECK(h.rows[0].action == "dex.score_policy.reset");
        CHECK(h.rows[0].result == "attempted");
        CHECK(h.rows[1].result == "success");
        CHECK(has(res->body, "name=\"if_match\" value=\"default\""));
        CHECK(has(res->get_header_value("HX-Trigger"), "reset to the shipped defaults"));
    }
    SECTION("nothing stored is a no-change") {
        const auto res = h.post(kReset, "if_match=default", kHx);
        CHECK(res->status == 200);
        REQUIRE(h.rows.size() == 2);
        CHECK(h.rows[1].result == "no_change");
    }
}

TEST_CASE("scoring POST: every refusal before the writer leaves nothing behind",
          "[server][routes][dex][score_policy][scoring]") {
    const auto body = form_body(dex_form_values(policy_with_excellent(95.0)), "default");
    SECTION("a non-administrator is refused by admin_fn") {
        Harness h;
        h.is_admin = false;
        for (const char* path : {kSave, kPreview, kReset})
            CHECK(h.post(path, body, kHx)->status == 403);
        CHECK(h.rows.empty());
        CHECK(h.cas_calls == 0);
        CHECK_FALSE(h.stored);
    }
    SECTION("a caller without GuaranteedState:Read is refused first, before the role test or any read") {
        Harness h;
        h.perm_allow = false;
        for (const char* path : {kSave, kPreview, kReset}) {
            const auto res = h.post(path, body, kHx);
            CHECK(res->status == 403);
            CHECK_FALSE(has(res->body, "outlook.exe")); // no application name leaves with a refusal
        }
        REQUIRE(h.perm_calls.size() == 3);
        for (const auto& call : h.perm_calls)
            CHECK(call == std::pair<std::string, std::string>{"GuaranteedState", "Read"});
        CHECK(h.admin_calls == 0);
        CHECK(h.reads == 0);
        CHECK(h.apps_calls == 0);
        CHECK(h.cas_calls == 0);
        CHECK(h.rows.empty());
        CHECK_FALSE(h.stored);
    }
    SECTION("a cross-site browser write is refused with a csrf.denied row") {
        Harness h;
        const auto res = h.post(kSave, body, {{"HX-Request", "true"}, {"Origin", "https://evil.example"}});
        CHECK(res->status == 403);
        REQUIRE(h.fn_rows.size() == 1);
        CHECK(h.fn_rows[0] == "csrf.denied/denied");
        CHECK(h.cas_calls == 0);
        CHECK(h.rows.empty());
    }
    SECTION("an unwired writer is a 503 with an A4 body") {
        Harness h(/*wire_writer=*/false);
        const auto res = h.post(kSave, body, kHx);
        CHECK(res->status == 503);
        CHECK(json::parse(res->body)["error"]["message"] == "Config store unavailable");
    }
}

TEST_CASE("scoring save: an audit store that refuses the attempted row fails closed",
          "[server][routes][dex][score_policy][scoring]") {
    Harness h;
    h.refuse_result = "attempted";
    const auto body = form_body(dex_form_values(policy_with_excellent(95.0)), "default");
    CHECK(h.post(kSave, body)->status == 503);
    const auto res = h.post(kSave, body, kHx);
    CHECK(res->status == 200);
    CHECK(has(res->body, "data-refused=\"audit_unavailable\""));
    CHECK(h.cas_calls == 0);
    CHECK_FALSE(h.stored);
}

namespace {

// The REST v1 route over the SAME fake store, to compare the two surfaces.
struct RestSide {
    RestApiV1 api;
    yuzu::server::test::TestRouteSink sink;
    explicit RestSide(Harness& h) {
        sink.default_headers = {{"Host", "yuzu.test"}, {"Origin", "https://yuzu.test"}};
        api.set_audit_as_session_fn(h.audit_as_session());
        api.set_dex_score_policy_writer(h.deps());
        RestApiV1::AuthFn auth_fn = [&h](const httplib::Request&,
                                         httplib::Response&) -> std::optional<auth::Session> {
            return h.session();
        };
        RestApiV1::PermFn perm_fn = [](const httplib::Request&, httplib::Response&,
                                       const std::string&, const std::string&) { return true; };
        RestApiV1::AuditFn audit_fn = [](const httplib::Request&, const std::string&,
                                         const std::string&, const std::string&,
                                         const std::string&, const std::string&) { return true; };
        api.register_routes(sink, auth_fn, perm_fn, audit_fn, nullptr, nullptr, nullptr, nullptr,
                            nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr);
    }
    std::unique_ptr<httplib::Response> put(const std::string& body, const std::string& if_match) {
        auto res = sink.dispatch("PUT", "/api/v1/dex/score-policy", body, "application/json",
                                 {{"If-Match", "\"" + if_match + "\""}});
        REQUIRE(res);
        return res;
    }
};

std::vector<std::string> trail(const std::vector<Row>& rows) {
    std::vector<std::string> out;
    for (const auto& r : rows)
        out.push_back(r.action + "/" + r.result + "/" + r.principal + "/" + r.role + "/" +
                      r.target_type + "/" + r.target_id);
    return out;
}

} // namespace

TEST_CASE("scoring save is equivalent to PUT /api/v1/dex/score-policy",
          "[server][routes][dex][score_policy][scoring][equivalence]") {
    Harness h;
    RestSide rest(h);

    DexScorePolicy p = policy_with_excellent(93.0);
    p.tiers.names[0] = "Top";
    p.model.per_device_event_cap = 7;
    DexScoreOverride o;
    o.image = "outlook.exe";
    o.excellent = 97.0;
    o.names[1] = "Fine";
    p.overrides.push_back(o);
    REQUIRE_FALSE(dex_score_policy_fault(p));
    const std::string rest_body = dex_score_policy_to_json(p).dump();
    const std::string form = form_body(dex_form_values(p), "default");

    // (a) the same document on both surfaces from an empty store.
    REQUIRE(rest.put(rest_body, "default")->status == 200);
    const auto stored_rest = h.stored;
    const auto trail_rest = trail(h.rows);
    h.rows.clear();
    h.stored.reset();
    REQUIRE(h.post(kSave, form, kHx)->status == 200);
    REQUIRE(stored_rest);
    CHECK(h.stored == stored_rest);
    CHECK(dex_score_policy_revision(*h.stored) == dex_score_policy_revision(*stored_rest));
    CHECK(trail(h.rows) == trail_rest);
    const std::string who = "alice/" + std::string(auth::role_to_string(auth::effective_role(h.session()))) +
                            "/RuntimeConfig/dex_score_policy";
    CHECK(trail_rest == std::vector<std::string>{"dex.score_policy.update/attempted/" + who,
                                                 "dex.score_policy.update/success/" + who});

    // (b) a stale write on both: refused, nothing written, one denied row each.
    const int cas_before = h.cas_calls;
    h.rows.clear();
    const std::string newer = form_body(dex_form_values(policy_with_excellent(96.0)), "default");
    CHECK(rest.put(dex_score_policy_canonical(policy_with_excellent(96.0)), "default")->status == 409);
    REQUIRE(h.rows.size() == 1);
    CHECK(h.rows[0].result == "denied");
    h.rows.clear();
    CHECK(has(h.post(kSave, newer, kHx)->body, "data-refused=\"stale\""));
    REQUIRE(h.rows.size() == 1);
    CHECK(h.rows[0].result == "denied");
    CHECK(h.cas_calls == cas_before);

    // (c) an out-of-range weight on both: the same refusal message.
    h.rows.clear();
    auto bad = dex_form_values(p);
    bad["weights.breadth"] = "-1";
    const auto rev = h.stored_revision();
    DexScorePolicy bad_policy = p;
    bad_policy.weights.breadth = -1.0;
    const auto rest_bad = rest.put(dex_score_policy_to_json(bad_policy).dump(), rev);
    CHECK(rest_bad->status == 400);
    const std::string message = json::parse(rest_bad->body)["error"]["message"];
    CHECK(has(h.post(kSave, form_body(bad, rev), kHx)->body, message));
}
