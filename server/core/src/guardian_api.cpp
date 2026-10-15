#include "guardian_api_local.hpp"

#include "baseline_store.hpp"
#include "guardian_model.hpp"
#include "guaranteed_state_store.hpp"

namespace yuzu::server {

/// Store-backed `GuardianApi` implementation — a thin wrap of
/// `GuaranteedStateStore::list_rules`/`get_rule`/`query_events` and the five
/// shared `guardian_model.hpp` functions (ADR-0031 WS-A4, ninth family).
/// Behaviour preserved exactly: every wrapped call already returned the
/// SAME `std::optional`/`std::expected`/plain-vector shape to its pre-seam
/// REST v1/MCP/dashboard callers, so this seam introduces no new
/// honest-empty-vs-failure distinction anywhere — it only removes the
/// direct presentation -> store reach.
///
/// `store_`/`baseline_store_` are NULLABLE (see `guardian_api_local.hpp`'s
/// factory doc comment for why) — every method null-guards its OWN
/// dependency and degrades exactly like a genuine store-read failure would,
/// mirroring `LocalDexPerfApi`'s own per-method null tolerance. The
/// resulting wording is a DELIBERATE, disclosed simplification versus the
/// pre-seam REST/MCP handlers, which distinguished a null-store 503
/// ("service unavailable", non-retryable) from a genuine read-degrade 503
/// ("guaranteed-state store degraded", retry_after_ms=5000) via two separate
/// guard clauses — this seam folds both into the SAME "degraded" signal,
/// same trade-off `LocalDexPerfApi` already made ("a null store/reader
/// degrades the corresponding method to nullopt, matching the resource's
/// existing store-unavailable 503 today"). Neither REST nor MCP surfaces the
/// distinction to the caller today (both branches already render a generic
/// 503 without inspecting which guard fired), and in production the null
/// case is unreachable regardless. One exception to the 503 parity:
/// `list_events` returns a plain vector (the ADR-0038 deferred widening this
/// seam preserves), so a null store there answers an EMPTY 200 — the same
/// result `query_events` already gives on a genuine read failure — where the
/// pre-seam handler's own null-store guard answered 503. That path is
/// unreachable in production too — `guaranteed_state_store_`/
/// `baseline_store_` fail the WHOLE server closed at boot if either can't
/// open (ADR-0012 §1), so by the time any request reaches this class both
/// are always live.
class LocalGuardianApi final : public GuardianApi {
public:
    LocalGuardianApi(GuaranteedStateStore* store, BaselineStore* baseline_store)
        : store_(store), baseline_store_(baseline_store) {}

    LocalGuardianApi(const LocalGuardianApi&) = delete;
    LocalGuardianApi& operator=(const LocalGuardianApi&) = delete;

    [[nodiscard]] std::expected<std::vector<GuaranteedStateRuleRow>, std::string>
    list_rules() const override {
        if (!store_)
            return std::unexpected("Guaranteed State store unavailable");
        return store_->list_rules();
    }

    [[nodiscard]] std::expected<std::optional<GuaranteedStateRuleRow>, GuaranteedStateReadError>
    get_rule(const std::string& rule_id) const override {
        if (!store_)
            return std::unexpected(GuaranteedStateReadError::kDegraded);
        return store_->get_rule(rule_id);
    }

    [[nodiscard]] std::optional<GuardianStatusRollup>
    status(const std::optional<std::vector<std::string>>& agent_scope) const override {
        if (!store_)
            return std::nullopt;
        return guardian_status_rollup(*store_, agent_scope);
    }

    [[nodiscard]] std::optional<GuardianAgentStatusRollup>
    agent_status(const std::string& agent_id) const override {
        if (!store_)
            return std::nullopt;
        return guardian_agent_status_rollup(*store_, agent_id);
    }

    [[nodiscard]] std::optional<std::vector<GuardianRuleAgentStatusRow>>
    rule_status(const std::string& rule_id) const override {
        if (!store_)
            return std::nullopt;
        return guardian_rule_agent_status_rows(*store_, rule_id);
    }

    [[nodiscard]] std::optional<std::vector<GuardianDeviceGuardRow>>
    device_guards(const std::string& agent_id) const override {
        if (!store_)
            return std::nullopt;
        return guardian_device_all_guards(*store_, agent_id);
    }

    [[nodiscard]] std::optional<GuardianDeviceComplianceRollup>
    device_compliance(const std::string& baseline_name, const std::string& agent_id,
                      bool* store_degraded, bool* pii_access_began) const override {
        if (!store_ || !baseline_store_) {
            *store_degraded = true;
            *pii_access_began = false;
            return std::nullopt;
        }
        return guardian_device_compliance_rollup(*baseline_store_, *store_, baseline_name, agent_id,
                                                  store_degraded, pii_access_began);
    }

    [[nodiscard]] std::vector<GuaranteedStateEventRow>
    list_events(const GuaranteedStateEventQuery& q) const override {
        if (!store_)
            return {};
        return store_->query_events(q);
    }

private:
    GuaranteedStateStore* store_;
    BaselineStore* baseline_store_;
};

std::shared_ptr<GuardianApi> make_local_guardian_api(GuaranteedStateStore* store,
                                                      BaselineStore* baseline_store) {
    return std::make_shared<LocalGuardianApi>(store, baseline_store);
}

} // namespace yuzu::server
