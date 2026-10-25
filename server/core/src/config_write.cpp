#include "config_write.hpp"

#include "admin_gate.hpp"            // authz::admin_gate_verdict
#include "dex_score_policy_json.hpp" // kDexScorePolicyKey
#include "runtime_config_store.hpp"
#include "runtime_config_view.hpp" // build_overrides_json

#include <yuzu/log_token.hpp>
#include <yuzu/server/auto_approve.hpp>
#include <yuzu/server/server.hpp> // struct Config

#include <spdlog/spdlog.h>

#include <charconv>
#include <chrono>
#include <mutex>
#include <set>
#include <string_view>
#include <system_error>

namespace yuzu::server::config {

namespace {

bool is_int_key(std::string_view key) {
    return key == "heartbeat_timeout" || key == "response_retention_days" ||
           key == "audit_retention_days" || key == "guardian_event_retention_days";
}

} // namespace

bool store_ready(const Backing& b) noexcept {
    return b.store != nullptr && b.cfg != nullptr && b.auto_approve != nullptr &&
           b.store->is_open();
}

std::optional<WriteRefusal> write_refusal(const std::string& key, const auth::Session& session) {
    const auto write_class = RuntimeConfigStore::write_class(key);
    if (!write_class)
        return std::nullopt;

    // A route-owned key (today only dex_score_policy: one document with its own writer,
    // PUT/DELETE /api/v1/dex/score-policy, which validates it whole; a generic
    // single-value write could leave it half-edited).
    if (*write_class == ConfigWriteClass::RouteOwned) {
        const bool dex = key == kDexScorePolicyKey;
        return WriteRefusal{
            .kind = WriteRefusal::Kind::RouteOwned,
            .message = dex ? std::string("dex_score_policy is written only through "
                                         "PUT /api/v1/dex/score-policy")
                           : key + " is written only through its own route",
            .remediation = dex ? "send the whole policy document to PUT /api/v1/dex/score-policy "
                                 "with If-Match"
                               : "use the route that owns this key",
            .audit_detail = {}};
    }

    // A key whose own settings route is administrator-only is not writable here by a weaker
    // caller (RuntimeConfigStore::write_class). Infrastructure:Write admits a JIT-elevated session
    // and an MCP-tier token; the settings routes refuse an MCP-tier or service-scoped token
    // through require_admin, so a generic write must too. The oidc_* keys decide who becomes an
    // administrator at an SSO login (oidc_admin_group is read from the stored value at the next
    // start), so they additionally refuse an elevation: the caller's OWN role must be admin. That
    // is the one rule here that is not authz::admin_gate_verdict, on purpose. Every other key
    // stays writable under Infrastructure:Write.
    const char* refusal_detail = nullptr;
    const char* refusal_message = "changing this setting needs your own administrator role";
    // No `default`: a new ConfigWriteClass enumerator must be handled here (-Wswitch), not fall
    // through as General.
    switch (*write_class) {
    case ConfigWriteClass::AdminRouteInteractiveOnly:
        refusal_message = "changing sign-in provider settings needs your own administrator role";
        // The cause picks the detail: a token credential (whatever its creator's role), then an
        // elevation, then a plain non-administrator.
        if (!session.mcp_tier.empty() || !session.token_scope_service.empty()) {
            refusal_detail = "token_session_oidc_setting_blocked";
            refusal_message = "an administrator account is required; MCP-tier and service-scoped "
                              "tokens cannot change sign-in provider settings";
        } else if (session.role != auth::Role::admin) {
            refusal_detail = auth::is_elevated(session) ? "elevated_session_oidc_setting_blocked"
                                                        : "admin_role_required_oidc_setting_blocked";
        }
        break;
    case ConfigWriteClass::AdminRoute:
        switch (authz::admin_gate_verdict(session)) {
        case authz::AdminGate::Admit:
            break;
        case authz::AdminGate::ServiceScoped:
        case authz::AdminGate::McpTier:
            refusal_detail = "token_session_admin_setting_blocked";
            refusal_message = "an administrator account is required; MCP-tier and service-scoped "
                              "tokens cannot change this setting";
            break;
        case authz::AdminGate::NotAdmin:
            refusal_detail = "admin_role_required_setting_blocked";
            break;
        }
        break;
    case ConfigWriteClass::General:
    case ConfigWriteClass::RouteOwned: // returned above
        break;
    }
    if (!refusal_detail)
        return std::nullopt;
    return WriteRefusal{.kind = WriteRefusal::Kind::Denied,
                        .message = refusal_message,
                        .remediation = "change this setting with an administrator API token that is "
                                       "not MCP-tier, or as an administrator from the Settings "
                                       "page where one exists",
                        .audit_detail = refusal_detail};
}

std::expected<int, std::string> validate_value(std::string_view key, std::string_view value) {
    if (!is_int_key(key))
        return 0;
    // Validated BEFORE persisting, so a non-numeric or negative value does not land in
    // RuntimeConfigStore while leaving the live Config at the old value (the earlier
    // `try { stoi } catch (...) {}` was a ghost write: the store persisted, the config ignored it,
    // the operator saw 200 with no effect). UP-R5 from the Guardian PR 2 governance re-run.
    // A leading '-' is refused outright: from_chars accepts "-0" into an int, which would be
    // stored (and echoed) as the text "-0" while the live value is 0.
    if (!value.empty() && value.front() == '-')
        return std::unexpected("value must be a non-negative integer");
    int parsed = 0;
    const char* first = value.data();
    const char* last = value.data() + value.size();
    auto [ptr, ec] = std::from_chars(first, last, parsed);
    if (ec != std::errc{} || ptr != last || parsed < 0)
        return std::unexpected("value must be a non-negative integer");
    return parsed;
}

std::expected<void, WriteFault> write_and_apply(const Backing& b, const std::string& key,
                                                const std::string& value, int parsed_int,
                                                const std::string& username) {
    // One writer at a time across the store write and the live apply, so two concurrent writes of
    // the same key cannot leave the store holding one value and the live config the other. This
    // orders writers only; readers take no lock and rely on the atomic Config fields (LiveInt,
    // LiveSeconds).
    static std::mutex write_mutex;
    const std::scoped_lock lock(write_mutex);
    auto result = b.store->set(key, value, username);
    if (!result) {
        // A refusal of the value is operator-written text (no value, no secret). A database
        // failure may have committed before the acknowledgement was lost, so it is not recorded
        // as "not applied", and its detail is never echoed to the caller.
        if (result.error().starts_with(kRuntimeConfigDbErrorPrefix)) {
            spdlog::error("runtime config write {}: failed: {}", ::yuzu::log_key_token(key),
                          ::yuzu::log_key_token(result.error()));
            return std::unexpected(WriteFault{.kind = WriteFault::Kind::StoreFault,
                                              .message = "runtime config store unavailable",
                                              .audit_detail = "store error; outcome unknown"});
        }
        return std::unexpected(WriteFault{.kind = WriteFault::Kind::Rejected,
                                          .message = result.error(),
                                          .audit_detail = result.error()});
    }

    // Apply to the live config. Integer keys were parsed by validate_value; direct assignment
    // here means no second parse that could swallow an error.
    if (key == "heartbeat_timeout") {
        b.cfg->session_timeout = std::chrono::seconds(parsed_int);
    } else if (key == "response_retention_days") {
        b.cfg->response_retention_days = parsed_int;
    } else if (key == "audit_retention_days") {
        b.cfg->audit_retention_days = parsed_int;
    } else if (key == "guardian_event_retention_days") {
        b.cfg->guardian_event_retention_days = parsed_int;
    }
    // log_level is applied inside RuntimeConfigStore::set()
    return {};
}

std::string success_audit_detail(const std::string& key, const std::string& value) {
    // NOT the raw value of a secret. An audit detail is durable, retained by policy, and readable
    // by every role seeded AuditLog:Read (Operator among them), so a credential here is a worse
    // sink than the log, and it is not rotatable away afterwards.
    return "value=" + (RuntimeConfigStore::is_secret_key(key)
                           ? std::string(RuntimeConfigStore::redacted_placeholder())
                           : value);
}

nlohmann::json applied_json(const std::string& key, const std::string& value, bool with_effect) {
    auto body = RuntimeConfigStore::is_secret_key(key)
                    ? nlohmann::json{{"key", key}, {"applied", true}}
                    : nlohmann::json{{"key", key}, {"value", value}, {"applied", true}};
    if (with_effect)
        body["effect"] = effect_of(key);
    return body;
}

std::string_view effect_of(std::string_view key) {
    if (key == "heartbeat_timeout" || key == "log_level")
        return "immediate";
    if (key == "dex_alert_routing" || key == "dex_blast_min_devices" ||
        key == "dex_blast_window_seconds" || key == "dex_blast_cooldown_seconds" ||
        key == "dex_cohort_export_key")
        return "deferred";
    // Applied into the live config by the boot loader, and read from it at every SSO login
    // (/auth/callback), so a restart makes them take effect.
    if (key == "oidc_admin_group" || key == "oidc_redirect_uri")
        return "deferred";
    return "stored_only";
}

std::expected<nlohmann::json, ViewFault> build_config_view(const Backing& b,
                                                           const auth::Session& viewer,
                                                           bool declare_withheld) {
    // Checked first: a degraded store must not read as "nothing is configured" (see ViewFault).
    if (!store_ready(b))
        return std::unexpected(ViewFault{});
    auto overrides_result = b.store->get_all();
    if (!overrides_result.has_value()) {
        spdlog::error("runtime config read failed: {}",
                      ::yuzu::log_key_token(overrides_result.error()));
        return std::unexpected(ViewFault{});
    }

    // Keys this viewer may not see. Only a DENIED key is withheld: a route-owned key's value is not
    // authority, and it stays listed.
    std::set<std::string> withheld;
    for (const auto& k : RuntimeConfigStore::allowed_keys()) {
        auto refusal = write_refusal(k, viewer);
        if (refusal && refusal->kind == WriteRefusal::Kind::Denied)
            withheld.insert(k);
    }
    const bool viewer_is_admin = authz::admin_gate_verdict(viewer) == authz::AdminGate::Admit;

    nlohmann::json config_obj;
    // Current effective values (from cfg + overrides)
    config_obj["heartbeat_timeout"] = b.cfg->session_timeout.count();
    config_obj["response_retention_days"] = b.cfg->response_retention_days.get();
    if (!withheld.contains("audit_retention_days"))
        config_obj["audit_retention_days"] = b.cfg->audit_retention_days.get();
    config_obj["guardian_event_retention_days"] = b.cfg->guardian_event_retention_days.get();
    config_obj["auto_approve_enabled"] = !b.auto_approve->list_rules().empty();
    // spdlog names the level "warning"; the write accepts "warn". Report the writable spelling so
    // a read followed by a write of the same value round-trips.
    const auto level_sv = spdlog::level::to_string_view(spdlog::default_logger()->level());
    const std::string level(level_sv.data(), level_sv.size());
    config_obj["log_level"] = level == "warning" ? std::string("warn") : level;

    // Drop what this viewer may not see: a withheld key, and a stored row whose key has no write
    // class at all (stale or renamed), which only an effective administrator is shown. This
    // default is deny: a row we cannot classify is not shown to a caller we cannot vouch for.
    std::erase_if(*overrides_result, [&](const RuntimeConfigEntry& e) {
        if (withheld.contains(e.key))
            return true;
        return !RuntimeConfigStore::write_class(e.key).has_value() && !viewer_is_admin;
    });
    // The omission rule for a secret's value lives in build_overrides_json
    // (runtime_config_view.hpp), the site the secret leaked from twice.
    nlohmann::json overrides = build_overrides_json(*overrides_result);

    nlohmann::json allowed = nlohmann::json::array();
    for (const auto& k : RuntimeConfigStore::allowed_keys())
        allowed.push_back(k);

    // Allowed keys that are listed but not written by the generic write: they have their own
    // route. Derived from the write class, so a second route-owned key is listed without a
    // second edit.
    nlohmann::json read_only = nlohmann::json::array();
    for (const auto& k : RuntimeConfigStore::allowed_keys())
        if (RuntimeConfigStore::write_class(k) == ConfigWriteClass::RouteOwned)
            read_only.push_back(k);

    nlohmann::json view({{"config", config_obj},
                         {"overrides", overrides},
                         {"allowed_keys", allowed},
                         {"read_only_keys", read_only}});
    if (declare_withheld)
        view["withheld_keys"] = withheld; // a std::set serialises as a sorted array
    return view;
}

} // namespace yuzu::server::config
