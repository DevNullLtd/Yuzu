/**
 * test_guardian_resilience_schema.cpp — C3b server-side resilience param
 * validation + the published JSON Schema catalog (guardian_resilience_schema.hpp
 * / guardian_schema_registry.hpp).
 *
 * The DRIFT GUARD that matters: the param-spec table is the single source for
 * BOTH the validator and the schema, and the final TEST_CASE binds that table's
 * key set to the agent's resilience_keys (the contract G9 schema↔handler
 * cross-check). A rename on either side fails here. This file is the only place
 * the server test binary reaches into the agent include tree — header-only
 * constexpr, no link (see tests/meson.build).
 */

#include "guardian_push_builder.hpp" // guardian::kKnownGuardSparkTypes (cross-check)
#include "guardian_resilience_schema.hpp"
#include "guardian_rule_spec.hpp" // derive_rule_spec + dangerous-key denylist (H1)
#include "guardian_schema_registry.hpp"

#include <yuzu/agent/guard_registry.hpp>      // registry_support::kHives / kValueTypes (cross-check)
#include <yuzu/agent/guard_service.hpp>       // service_support::kStates (cross-check)
#include <yuzu/agent/resilience_strategy.hpp> // resilience_keys (cross-check)

#include <catch2/catch_test_macros.hpp>

#include <nlohmann/json.hpp>

#include <algorithm>
#include <string>
#include <string_view>
#include <vector>

using namespace yuzu::server::guardian;
using nlohmann::json;

namespace {
// Validate a params object built from a JSON literal; return the (mutated)
// params plus whether it was accepted.
struct Outcome {
    bool ok;
    std::string message;
    json params;
};
Outcome run(json params) {
    auto err = validate_and_canonicalize_resilience_params(params);
    return {!err.has_value(), err ? err->message : std::string{}, std::move(params)};
}
} // namespace

TEST_CASE("resilience validate: empty / persist defaults accepted", "[guardian][resilience][validate]") {
    CHECK(run(json::object()).ok);
    CHECK(run(json{{"mode", "persist"}}).ok);
    // mode canonicalised to lowercase token
    auto o = run(json{{"mode", "PERSIST"}});
    CHECK(o.ok);
    CHECK(o.params["mode"] == "persist");
}

TEST_CASE("resilience validate: mode must be a known token", "[guardian][resilience][validate]") {
    CHECK_FALSE(run(json{{"mode", "nonsense"}}).ok);
    CHECK_FALSE(run(json{{"mode", 3}}).ok); // not a string
    auto o = run(json{{"mode", "Backoff"}});
    CHECK(o.ok);
    CHECK(o.params["mode"] == "backoff");
}

TEST_CASE("resilience validate: Bounded max_attempts bounds", "[guardian][resilience][validate][bounded]") {
    // 0 degenerates to never-give-up (== Persist) — rejected (min 1).
    CHECK_FALSE(run(json{{"mode", "bounded"}, {"max_attempts", 0}}).ok);
    // absent → default 5, accepted.
    CHECK(run(json{{"mode", "bounded"}}).ok);
    // present + in range → accepted and canonicalised to a decimal string.
    auto o = run(json{{"mode", "bounded"}, {"max_attempts", 3}});
    CHECK(o.ok);
    CHECK(o.params["max_attempts"] == "3");
    // numeric string accepted equally (lenient-in).
    CHECK(run(json{{"mode", "bounded"}, {"max_attempts", "3"}}).ok);
}

TEST_CASE("resilience validate: quiet_reset_s=0 rejected when relevant",
          "[guardian][resilience][validate][bounded]") {
    // quiet_reset_s=0 → quiet always true → never gives up; min is 1.
    CHECK_FALSE(run(json{{"mode", "bounded"}, {"quiet_reset_s", 0}}).ok);
    CHECK(run(json{{"mode", "bounded"}, {"quiet_reset_s", 30}}).ok);
}

TEST_CASE("resilience validate: resume_after_s=0 and event_debounce_ms=0 are valid",
          "[guardian][resilience][validate]") {
    CHECK(run(json{{"mode", "bounded"}, {"resume_after_s", 0}}).ok); // 0 = stay given up
    CHECK(run(json{{"mode", "persist"}, {"event_debounce_ms", 0}}).ok); // 0 = no debounce
}

TEST_CASE("resilience validate: Backoff initial <= max cross-field",
          "[guardian][resilience][validate][backoff]") {
    CHECK(run(json{{"mode", "backoff"}, {"backoff_initial_ms", 500}, {"backoff_max_ms", 8000}}).ok);
    CHECK_FALSE(
        run(json{{"mode", "backoff"}, {"backoff_initial_ms", 8000}, {"backoff_max_ms", 500}}).ok);
    // initial against the DEFAULT max (60000): 100000 > 60000 → rejected even
    // though max is absent (effective-value cross-check).
    CHECK_FALSE(run(json{{"mode", "backoff"}, {"backoff_initial_ms", 100000}}).ok);
}

TEST_CASE("resilience validate: overflow-bounded seconds", "[guardian][resilience][validate]") {
    // Far beyond the 1-year cap — must reject, not wrap when the agent does *1000.
    CHECK_FALSE(run(json{{"mode", "bounded"}, {"quiet_reset_s", 99999999999ull}}).ok);
}

TEST_CASE("resilience validate: lenient-in passes through mode-irrelevant params",
          "[guardian][resilience][validate][lenient]") {
    // A Persist rule carrying backoff_* is NOT rejected, and the irrelevant value
    // is passed through untouched (even if it would be out of range / garbage for
    // Backoff).
    auto o = run(json{{"mode", "persist"}, {"backoff_initial_ms", 999999999}});
    CHECK(o.ok);
    CHECK(o.params["backoff_initial_ms"] == 999999999); // untouched (still a number)
    CHECK(run(json{{"mode", "persist"}, {"backoff_initial_ms", "fast"}}).ok); // garbage, irrelevant
}

TEST_CASE("resilience validate: load-bearing param must be a non-negative integer",
          "[guardian][resilience][validate]") {
    CHECK_FALSE(run(json{{"mode", "bounded"}, {"max_attempts", "abc"}}).ok);
    CHECK_FALSE(run(json{{"mode", "bounded"}, {"max_attempts", -1}}).ok);
    CHECK_FALSE(run(json{{"mode", "bounded"}, {"max_attempts", 1.5}}).ok);
}

TEST_CASE("resilience schema: shape + bounds", "[guardian][resilience][schema]") {
    auto s = resilience_params_schema();
    REQUIRE(s.is_object());
    CHECK(s["type"] == "object");
    const auto& props = s["properties"];
    REQUIRE(props.contains("mode"));
    CHECK(props["mode"]["enum"] == json::array({"persist", "backoff", "bounded"}));
    REQUIRE(props.contains("max_attempts"));
    CHECK(props["max_attempts"]["minimum"] == 1);
    // mode-relevance is machine-discoverable
    CHECK(props["max_attempts"]["x-applies-to-modes"] == json::array({"bounded"}));
    // other remediation params may coexist in remediation.params
    CHECK(s["additionalProperties"] == true);
}

TEST_CASE("schema catalog: parses, lists Slice-A types, stable content ETag",
          "[guardian][schema][catalog]") {
    const auto& cat = guardian_schema_catalog();
    CHECK_FALSE(cat.etag.empty());
    // built-once cache → identical ETag across calls
    CHECK(guardian_schema_catalog().etag == cat.etag);

    auto j = json::parse(cat.json);
    REQUIRE(j.contains("schemas"));
    REQUIRE(j["schemas"].is_array());
    std::vector<std::string> types;
    for (const auto& e : j["schemas"]) {
        CHECK(e.contains("kind"));
        CHECK(e.contains("type"));
        // G9 shape: {kind, type, json_schema} — the schema is nested and is a
        // WELL-FORMED JSON Schema (type:object), not the discriminator clobbered
        // over the schema's own type keyword.
        REQUIRE(e.contains("json_schema"));
        CHECK(e["json_schema"]["type"] == "object");
        CHECK(e["json_schema"]["properties"].contains("type"));
        types.push_back(e["type"].get<std::string>());
    }
    auto has = [&](const char* t) {
        return std::find(types.begin(), types.end(), t) != types.end();
    };
    CHECK(has("registry-change"));
    CHECK(has("registry-value-equals"));
    CHECK(has("alert-only"));
    CHECK(has("enforce"));
    // Change B file types.
    CHECK(has("file-change"));
    CHECK(has("file-exists"));
    CHECK(has("file-hash-equals"));
    // PR5 service types.
    CHECK(has("service-status-change"));
    CHECK(has("service-running"));
    CHECK(has("service-stopped"));
    // service-disabled (start-type config) is deliberately NOT published until the
    // agent arms it — it is registry-expressible today.
    CHECK_FALSE(has("service-disabled"));

    // The assertion type publishes the registry value-equals params + the
    // discriminated `expected` encoding (decision 3).
    for (const auto& e : j["schemas"]) {
        if (e["type"] == "registry-value-equals") {
            const auto& props = e["json_schema"]["properties"]["params"]["properties"];
            CHECK(props.contains("hive"));
            CHECK(props.contains("value_type"));
            CHECK(props.contains("expected"));
            CHECK(e["json_schema"]["properties"]["params"].contains("allOf")); // discriminators
        }
        if (e["type"] == "file-hash-equals") {
            const auto& props = e["json_schema"]["properties"]["params"]["properties"];
            CHECK(props.contains("path"));
            CHECK(props.contains("expected_hash"));
            // hex-digest format check (the file-type analogue of the registry
            // discriminated subschemas).
            CHECK(props["expected_hash"].contains("pattern"));
        }
        if (e["type"] == "file-exists") {
            const auto& props = e["json_schema"]["properties"]["params"]["properties"];
            CHECK(props.contains("path"));
            CHECK(props["expected"]["enum"] == json::array({"present", "absent"}));
        }
        if (e["type"] == "service-running" || e["type"] == "service-stopped") {
            const auto& props = e["json_schema"]["properties"]["params"]["properties"];
            CHECK(props.contains("service_name"));
            // charset pattern (the service analogue of the registry discriminators).
            CHECK(props["service_name"].contains("pattern"));
        }
    }
}

TEST_CASE("CROSS-CHECK: server param-spec keys == agent resilience_keys (G9 drift guard)",
          "[guardian][resilience][crosscheck]") {
    using namespace yuzu::agent::resilience_keys;
    std::vector<std::string_view> agent_keys = {kMode,
                                                kMaxAttempts,
                                                kQuietResetS,
                                                kResumeAfterS,
                                                kBackoffInitialMs,
                                                kBackoffMaxMs,
                                                kEventDebounceMs};
    std::sort(agent_keys.begin(), agent_keys.end());

    auto server_keys = resilience_param_keys(); // already sorted

    // If this fails, the server schema/validator and the agent parser disagree on
    // a key name — an author following GET /schemas would set a param the agent
    // silently ignores. Re-sync resilience_keys (agent) and the kParams table
    // (server) before merging.
    CHECK(server_keys.size() == agent_keys.size());
    CHECK(std::vector<std::string_view>(server_keys.begin(), server_keys.end()) == agent_keys);
}

namespace {
// Pull the `enum` array of a registry-value-equals param out of the published
// catalog, as sorted std::strings.
std::vector<std::string> schema_registry_enum(const char* param) {
    auto j = json::parse(guardian_schema_catalog().json);
    std::vector<std::string> out;
    for (const auto& e : j["schemas"]) {
        if (e["type"] == "registry-value-equals") {
            const auto& p = e["json_schema"]["properties"]["params"]["properties"][param]["enum"];
            for (const auto& v : p)
                out.push_back(v.get<std::string>());
        }
    }
    std::sort(out.begin(), out.end());
    return out;
}
std::vector<std::string> sorted_strings(const std::vector<std::string_view>& in) {
    std::vector<std::string> out;
    for (auto sv : in)
        out.emplace_back(sv);
    std::sort(out.begin(), out.end());
    return out;
}
template <std::size_t N>
std::vector<std::string> sorted_strings(const std::string_view (&in)[N]) {
    std::vector<std::string> out;
    for (auto sv : in)
        out.emplace_back(sv);
    std::sort(out.begin(), out.end());
    return out;
}
} // namespace

TEST_CASE("CROSS-CHECK: registry hive/value_type schema == server set == agent set (H2 drift guard)",
          "[guardian][registry][crosscheck]") {
    using namespace yuzu::agent;

    // If any of these fail, the menu we publish (and the dashboard form, and the
    // derive_rule_spec validator — all driven from the server accessors) offers a
    // registry hive or value type the agent's RegistryGuard can't read/write. A
    // guard authored against it reports perpetual false drift (audit) or perpetual
    // remediation.failed (enforce). Re-sync registry_support::kHives / kValueTypes
    // (agent) and kRegistryHives / kRegistryValueTypes (server) before merging.
    SECTION("hives") {
        auto schema = schema_registry_enum("hive");
        auto server = sorted_strings(supported_registry_hives());
        auto agent = sorted_strings(registry_support::kHives);
        CHECK(schema == server);
        CHECK(server == agent);
        // The unsupported hive that previously leaked through must be gone.
        CHECK(std::find(agent.begin(), agent.end(), "HKCC") == agent.end());
    }
    SECTION("value types") {
        auto schema = schema_registry_enum("value_type");
        auto server = sorted_strings(supported_registry_value_types());
        auto agent = sorted_strings(registry_support::kValueTypes);
        CHECK(schema == server);
        CHECK(server == agent);
        CHECK(std::find(agent.begin(), agent.end(), "REG_BINARY") == agent.end());
        CHECK(std::find(agent.begin(), agent.end(), "REG_MULTI_SZ") == agent.end());
    }
}

TEST_CASE("CROSS-CHECK: spark-kind schema catalog == guardian::kKnownGuardSparkTypes "
          "(#4252 consolidated-round drift guard)",
          "[guardian][spark][crosscheck]") {
    // Governance Gate 4 (consistency-auditor) finding on the #4252 double-count fix:
    // the new platform-support-stale counter's closed label set was a THIRD
    // independent enumeration of Guardian spark types, alongside the published
    // schema catalog (build_catalog(), guardian_schema_registry.cpp) and
    // guardian::kKnownGuardSparkTypes (guardian_push_builder.hpp) — with nothing
    // binding them, unlike this file's existing G9/H2 cross-checks for the same
    // class of drift. guardian_routes.cpp's counter now aliases
    // kKnownGuardSparkTypes instead of keeping its own list, so this test binds
    // the REMAINING two: the schema catalog's "spark"-kind entries must be
    // exactly kKnownGuardSparkTypes.
    //
    // This does NOT bind guardian_guard_supported_on_platform's actual if-chain
    // (governance Gate 8 re-review, architect + consistency-auditor) — that
    // function matches string LITERALS, not this array, so a 4th entry added
    // here and to the catalog with no corresponding branch there would pass
    // THIS test while the platform-support matrix silently defaults the new
    // type to Windows-only. test_guardian_push_builder.cpp's platform test
    // pins the array against those literal branches directly; both tests must
    // be updated when a spark type is added, not just this one.
    auto j = json::parse(guardian_schema_catalog().json);
    std::vector<std::string> published;
    for (const auto& e : j["schemas"])
        if (e["kind"] == "spark")
            published.push_back(e["type"].get<std::string>());
    std::sort(published.begin(), published.end());

    std::vector<std::string> matrix;
    for (std::string_view t : yuzu::server::guardian::kKnownGuardSparkTypes)
        matrix.emplace_back(t);
    std::sort(matrix.begin(), matrix.end());

    CHECK(published == matrix);
}

TEST_CASE("CROSS-CHECK: service-state schema == server set == agent set (H2 drift guard)",
          "[guardian][service][crosscheck]") {
    using namespace yuzu::agent;

    // The agent arms exactly the run-state assertions in service_support::kStates;
    // the server publishes a service-<state> assertion + a supported_service_states()
    // accessor that derive_rule_spec gates on. If these drift, an author following
    // GET /schemas could create a service guard the agent never arms (silent G11
    // errored) — the confidently-wrong-guard failure the registry cross-check closes.
    // Re-sync service_support::kStates (agent) and kServiceStates (server) on merge.
    auto server = sorted_strings(supported_service_states());
    auto agent = sorted_strings(service_support::kStates);
    CHECK(server == agent);

    // Every supported state has a published service-<state> assertion, and the
    // published service-* assertion set is EXACTLY that set — no service-disabled.
    auto j = json::parse(guardian_schema_catalog().json);
    std::vector<std::string> published;
    for (const auto& e : j["schemas"]) {
        const std::string t = e["type"].get<std::string>();
        if (e["kind"] == "assertion" && t.rfind("service-", 0) == 0)
            published.push_back(t.substr(std::string_view("service-").size()));
    }
    std::sort(published.begin(), published.end());
    CHECK(published == server);
    CHECK(std::find(published.begin(), published.end(), "disabled") == published.end());
}

namespace {
// Build a registry-value-equals rule body for derive_rule_spec.
json reg_rule_body(const std::string& key, const std::string& remediation_type) {
    return json{
        {"spark", {{"type", "registry-change"}, {"params", json::object()}}},
        {"assertion",
         {{"type", "registry-value-equals"},
          {"params",
           {{"hive", "HKLM"}, {"key", key}, {"value_name", "Flag"}, {"value_type", "REG_SZ"},
            {"expected", "1"}}}}},
        {"remediation", {{"type", remediation_type}, {"params", json::object()}}},
    };
}

// Build a service run-state rule body for derive_rule_spec.
json service_rule_body(const std::string& assertion_type, const std::string& service_name,
                       const std::string& remediation_type) {
    return json{
        {"spark", {{"type", "service-status-change"}, {"params", json::object()}}},
        {"assertion", {{"type", assertion_type}, {"params", {{"service_name", service_name}}}}},
        {"remediation", {{"type", remediation_type}, {"params", json::object()}}},
    };
}

// Build a file-hash-equals rule body for derive_rule_spec. `max_bytes_str`, if
// non-null, is authored as a JSON STRING (the dashboard form's wire shape,
// test_guardian_form_render.cpp); the #2233 item 6 ceiling check fires
// regardless of wire encoding (see guardian_rule_spec.cpp's
// validate_assertion_params) — `max_bytes_str` only selects which of that
// function's two branches (string vs numeric) a given test case exercises.
json file_hash_rule_body(const char* max_bytes_str) {
    json params = {{"path", "/etc/hosts"}};
    if (max_bytes_str)
        params["max_bytes"] = max_bytes_str;
    return json{
        {"spark", {{"type", "file-change"}, {"params", {{"path", "/etc/hosts"}}}}},
        {"assertion", {{"type", "file-hash-equals"}, {"params", params}}},
        {"remediation", {{"type", "alert-only"}, {"params", json::object()}}},
    };
}
} // namespace

TEST_CASE("#2233 item 6: file-hash-equals max_bytes above the 1 GiB ceiling is "
          "rejected at authoring time (string form)",
          "[guardian][file][derive][max_bytes]") {
    // Exactly at the ceiling: accepted.
    auto at = derive_rule_spec(file_hash_rule_body("1073741824"), "fh", 1, true, "audit");
    CHECK_FALSE(at.error.has_value());
    CHECK(at.structured);

    // One byte over: rejected, naming the ceiling.
    auto over = derive_rule_spec(file_hash_rule_body("1073741825"), "fh", 1, true, "audit");
    REQUIRE(over.error.has_value());
    CHECK(over.error->message.find("1 GiB") != std::string::npos);

    // Absent: accepted (agent default applies).
    CHECK_FALSE(derive_rule_spec(file_hash_rule_body(nullptr), "fh", 1, true, "audit")
                    .error.has_value());

    // Zero: still rejected by the pre-existing check, not this new one.
    auto zero = derive_rule_spec(file_hash_rule_body("0"), "fh", 1, true, "audit");
    REQUIRE(zero.error.has_value());
    CHECK(zero.error->message.find("positive integer") != std::string::npos);

    // A JSON-integer (unsigned) max_bytes is checked against the ceiling too, so
    // the two wire forms can't drift apart on enforcement (its zero-check stays
    // deferred to the agent, matching this file's pre-existing design for that
    // form — only the new ceiling closes for both).
    json int_over = file_hash_rule_body(nullptr);
    int_over["assertion"]["params"]["max_bytes"] = 5ull * 1024 * 1024 * 1024; // 5 GiB, as int
    REQUIRE(derive_rule_spec(int_over, "fh", 1, true, "audit").error.has_value());

    json int_at = file_hash_rule_body(nullptr);
    int_at["assertion"]["params"]["max_bytes"] = 1073741824ull; // exactly at ceiling, as int
    CHECK_FALSE(derive_rule_spec(int_at, "fh", 1, true, "audit").error.has_value());

    // One over the ceiling, as an int: rejected, same message shape as the string form.
    json int_over_by_one = file_hash_rule_body(nullptr);
    int_over_by_one["assertion"]["params"]["max_bytes"] = 1073741825ull;
    auto int_over_res = derive_rule_spec(int_over_by_one, "fh", 1, true, "audit");
    REQUIRE(int_over_res.error.has_value());
    CHECK(int_over_res.error->message.find("1 GiB") != std::string::npos);
}

TEST_CASE("#2233 item 6 / Gate 8: a JSON float or negative max_bytes is rejected as "
          "malformed, not silently substituted with the default (unhappy-path UP8-1)",
          "[guardian][file][derive][max_bytes]") {
    // A float, even one comfortably under the ceiling, was previously accepted and
    // then silently discarded (server AND agent both fell through to the 64 MiB
    // default) with no signal anywhere - reject it outright instead.
    json flt = file_hash_rule_body(nullptr);
    flt["assertion"]["params"]["max_bytes"] = 10000000.0; // 10 MB, as a JSON float
    auto flt_res = derive_rule_spec(flt, "fh", 1, true, "audit");
    REQUIRE(flt_res.error.has_value());
    CHECK(flt_res.error->message.find("positive integer") != std::string::npos);

    // Negative: same rejection, not a silent fallback either.
    json neg = file_hash_rule_body(nullptr);
    neg["assertion"]["params"]["max_bytes"] = -1;
    auto neg_res = derive_rule_spec(neg, "fh", 1, true, "audit");
    REQUIRE(neg_res.error.has_value());
    CHECK(neg_res.error->message.find("positive integer") != std::string::npos);

    // A literal that overflows uint64_t: nlohmann parses this as number_float (no
    // C++ literal can construct it directly - std::numeric_limits<uint64_t>::max()
    // is 18446744073709551615, one less), so it hits the same !is_number_unsigned()
    // shape reject as the float/negative cases above, not the ceiling check.
    json overflow = json::parse(R"({"assertion":{"params":{"max_bytes":18446744073709551616}}})");
    json over_body = file_hash_rule_body(nullptr);
    over_body["assertion"]["params"]["max_bytes"] = overflow["assertion"]["params"]["max_bytes"];
    REQUIRE(over_body["assertion"]["params"]["max_bytes"].is_number_float());
    auto over_res = derive_rule_spec(over_body, "fh", 1, true, "audit");
    REQUIRE(over_res.error.has_value());
    CHECK(over_res.error->message.find("positive integer") != std::string::npos);
}

TEST_CASE("PR5: service-running/stopped with a valid service_name authors a structured spec",
          "[guardian][service][derive]") {
    for (const char* atype : {"service-running", "service-stopped"}) {
        auto r = derive_rule_spec(service_rule_body(atype, "Spooler", "alert-only"), "svc", 1, true,
                                  "audit");
        CHECK_FALSE(r.error.has_value());
        CHECK(r.structured);
        auto spec = json::parse(r.spec_json);
        CHECK(spec["assertion"]["type"] == atype);
        CHECK(spec["assertion"]["params"]["service_name"] == "Spooler");
    }
}

TEST_CASE("PR5: service-disabled is rejected until the agent arms it",
          "[guardian][service][derive]") {
    auto r = derive_rule_spec(service_rule_body("service-disabled", "Spooler", "alert-only"), "svc",
                              1, true, "audit");
    REQUIRE(r.error.has_value());
    CHECK_FALSE(r.structured);
}

TEST_CASE("PR5: service assertion requires a valid service_name", "[guardian][service][derive]") {
    // empty service_name
    CHECK(derive_rule_spec(service_rule_body("service-running", "", "alert-only"), "svc", 1, true,
                           "audit")
              .error.has_value());
    // shell metacharacters / out-of-charset name
    CHECK(derive_rule_spec(service_rule_body("service-running", "Spooler; rm -rf /", "alert-only"),
                           "svc", 1, true, "audit")
              .error.has_value());
    // a name using the full allowed charset passes
    CHECK_FALSE(derive_rule_spec(service_rule_body("service-running", "My_Svc.1-2@x", "alert-only"),
                                 "svc", 1, true, "audit")
                    .error.has_value());
}

TEST_CASE("H1: enforce-mode write to a denylisted key is rejected (contract §6)",
          "[guardian][denylist][h1]") {
    // Every named §6 class is refused when the rule is in enforce mode.
    const std::vector<std::string> denied = {
        "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run",
        "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\RunOnce",
        "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options\\sethc.exe",
        "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon",
        "SYSTEM\\CurrentControlSet\\Services\\YuzuFake",
        "SOFTWARE\\Policies\\Microsoft\\Windows\\System",
    };
    for (const auto& key : denied) {
        INFO("denied key=" << key);
        auto r = derive_rule_spec(reg_rule_body(key, "enforce"), "g", 1, true, "enforce");
        CHECK(r.error.has_value());
    }
    // The SAME key is permitted in AUDIT mode — detection must still observe it.
    auto audit = derive_rule_spec(
        reg_rule_body("SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run", "alert-only"), "g", 1,
        true, "audit");
    CHECK_FALSE(audit.error.has_value());
    CHECK(audit.structured);
    // A benign key in enforce mode is allowed.
    auto benign =
        derive_rule_spec(reg_rule_body("SOFTWARE\\YuzuTest\\Flag", "enforce"), "g", 1, true, "enforce");
    CHECK_FALSE(benign.error.has_value());
}

TEST_CASE("H1: denylist normalisation resists separator/case evasion",
          "[guardian][denylist][h1]") {
    // doubled backslash, forward slashes, leading separator, mixed case all canonicalise.
    CHECK_FALSE(dangerous_enforce_registry_key(
                    "software\\microsoft\\windows\\currentversion\\\\run")
                    .empty());
    CHECK_FALSE(dangerous_enforce_registry_key("SOFTWARE/Microsoft/Windows/CurrentVersion/Run")
                    .empty());
    CHECK_FALSE(
        dangerous_enforce_registry_key("\\SYSTEM\\CurrentControlSet\\Services\\Foo").empty());
    CHECK_FALSE(dangerous_enforce_registry_key("system\\currentcontrolset\\services\\bar").empty());
    // benign keys are not over-matched: 'run' as a non-autorun substring is fine.
    CHECK(dangerous_enforce_registry_key("software\\acme\\running_total").empty());
    CHECK(dangerous_enforce_registry_key("software\\acme\\services_list").empty());
    CHECK(dangerous_enforce_registry_key("software\\yuzutest\\flag").empty());
}

TEST_CASE("H1: dangerous_enforce_in_spec inspects the stored spec_json",
          "[guardian][denylist][h1]") {
    // The audit→enforce bypass guard relies on detecting a denylisted key in a
    // stored (already-created, audit-mode) spec.
    auto clean = derive_rule_spec(reg_rule_body("SOFTWARE\\YuzuTest\\Flag", "alert-only"), "g", 1,
                                  true, "audit");
    REQUIRE(clean.structured);
    CHECK(dangerous_enforce_in_spec(clean.spec_json).empty());

    auto stored = derive_rule_spec(
        reg_rule_body("SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run", "alert-only"), "g", 1,
        true, "audit");
    REQUIRE(stored.structured);
    CHECK_FALSE(dangerous_enforce_in_spec(stored.spec_json).empty());

    // Robust to junk.
    CHECK(dangerous_enforce_in_spec("").empty());
    CHECK(dangerous_enforce_in_spec("not json").empty());
    CHECK(dangerous_enforce_in_spec("{}").empty());

    // #1946: a present-but-non-string assertion.type used to throw
    // json::type_error.302 out of the gate (nlohmann value() only defaults on an
    // ABSENT key). The gate runs unguarded at the push chokepoint on stored rows,
    // so it must treat this shape as not-dangerous junk, never throw.
    CHECK(dangerous_enforce_in_spec(R"({"assertion":{"type":5}})").empty());
    CHECK(dangerous_enforce_in_spec(R"({"assertion":{"type":null}})").empty());
    CHECK(dangerous_enforce_in_spec(R"({"assertion":{"type":true}})").empty());
    CHECK(dangerous_enforce_in_spec(R"({"assertion":{"type":["service-stopped"]}})").empty());
    CHECK(dangerous_enforce_in_spec(
              R"({"assertion":{"type":{},"params":{"key":"currentversion\\run"}}})")
              .empty());
}

TEST_CASE("PR5: enforce service-stopped on a security service is denied at every promote path",
          "[guardian][service][denylist]") {
    // Enforce-STOPPING Defender / the agent's own service would disable a security
    // control / self-destruct — the service-control mirror of the H1 registry gate.
    // enforce service-RUNNING is protective and must stay allowed.
    SECTION("raw denylist: security services + self, case-insensitive; others allowed") {
        CHECK_FALSE(dangerous_enforce_service_stop("WinDefend").empty());
        CHECK_FALSE(dangerous_enforce_service_stop("windefend").empty()); // case-insensitive
        CHECK_FALSE(dangerous_enforce_service_stop("Sense").empty());
        CHECK_FALSE(dangerous_enforce_service_stop("wscsvc").empty());
        CHECK_FALSE(dangerous_enforce_service_stop("WdFilter").empty());   // #1285 Defender minifilter
        CHECK_FALSE(dangerous_enforce_service_stop("wdfilter").empty());   // case-insensitive
        CHECK_FALSE(dangerous_enforce_service_stop("BFE").empty());        // #1285 firewall WFP engine
        CHECK_FALSE(dangerous_enforce_service_stop("RpcSs").empty());      // critical infra
        CHECK_FALSE(dangerous_enforce_service_stop("dcomlaunch").empty()); // critical infra
        CHECK_FALSE(dangerous_enforce_service_stop("YuzuAgent").empty()); // self-destruct
        CHECK(dangerous_enforce_service_stop("Spooler").empty());         // ordinary service
        CHECK(dangerous_enforce_service_stop("").empty());
    }
    SECTION("create path: enforce service-stopped on WinDefend rejected") {
        auto r = derive_rule_spec(service_rule_body("service-stopped", "WinDefend", "enforce"),
                                  "svc", 1, true, "enforce");
        CHECK(r.error.has_value());
    }
    SECTION("create path: enforce service-stopped on WdFilter / BFE rejected (#1285)") {
        // The #1285 additions (Defender minifilter, firewall WFP engine) must be
        // refused on the operator-facing author path, not only the raw helper.
        for (const char* svc : {"WdFilter", "BFE"}) {
            INFO("service=" << svc);
            auto r = derive_rule_spec(service_rule_body("service-stopped", svc, "enforce"), "svc", 1,
                                      true, "enforce");
            CHECK(r.error.has_value());
        }
    }
    SECTION("create path: enforce service-RUNNING on WinDefend allowed (protective)") {
        auto r = derive_rule_spec(service_rule_body("service-running", "WinDefend", "enforce"),
                                  "svc", 1, true, "enforce");
        CHECK_FALSE(r.error.has_value());
    }
    SECTION("audit path: service-stopped on WinDefend allowed (observation only)") {
        auto r = derive_rule_spec(service_rule_body("service-stopped", "WinDefend", "alert-only"),
                                  "svc", 1, true, "audit");
        CHECK_FALSE(r.error.has_value());
    }
    SECTION("toggle/push/update backstop: stored spec detected via dangerous_enforce_in_spec") {
        auto stored = derive_rule_spec(
            service_rule_body("service-stopped", "WinDefend", "alert-only"), "svc", 1, true,
            "audit");
        REQUIRE(stored.structured);
        CHECK_FALSE(dangerous_enforce_in_spec(stored.spec_json).empty());
    }
}
