#include "agent_decommission.hpp"

#include <exception>
#include <utility>

#include <spdlog/spdlog.h>

#include "app_perf_daily_store.hpp"
#include "device_inventory_store.hpp"
#include "inventory_store.hpp"
#include "software_inventory_store.hpp"
#include "software_licensing_store.hpp"
#include "app_usage_store.hpp"

namespace yuzu::server {

const char* to_string(DecommissionOutcome o) noexcept {
    switch (o) {
    case DecommissionOutcome::Deleted:
        return "deleted";
    case DecommissionOutcome::Skipped:
        return "skipped";
    case DecommissionOutcome::Failed:
        return "failed";
    }
    return "unknown";
}

AgentDecommission::AgentDecommission(const AgentDecommissionStores& stores) {
    // Fixed registration order: the generic inventory store first, then each
    // typed projection (all born-on-PG). Every store is registered even when
    // null so the result reports it as Skipped. The lambdas bind the raw store
    // pointer by value (non-owning) and RETURN delete_agent's commit status
    // (true iff the delete committed). InventoryStore takes `const
    // std::string&`; the four sibling PG stores take `std::string_view` — the
    // adapter unifies them under one `bool(std::string_view)` deleter
    // signature.
    using Fn = std::function<bool(std::string_view)>;

    targets_.push_back({"inventory", stores.inventory
                                         ? Fn([p = stores.inventory](std::string_view id) {
                                               return p->delete_agent(std::string(id));
                                           })
                                         : nullptr});
    targets_.push_back({"software_inventory",
                        stores.software_inventory
                            ? Fn([p = stores.software_inventory](std::string_view id) {
                                  return p->delete_agent(id);
                              })
                            : nullptr});
    targets_.push_back({"app_perf_daily",
                        stores.app_perf_daily ? Fn([p = stores.app_perf_daily](std::string_view id) {
                            return p->delete_agent(id);
                        })
                                              : nullptr});
    targets_.push_back({"device_inventory",
                        stores.device_inventory
                            ? Fn([p = stores.device_inventory](std::string_view id) {
                                  return p->delete_agent(id);
                              })
                            : nullptr});
    // The Decision 11 store: its agent_licenses / agent_license_state rows carry
    // the per-user `user_ref` pseudonyms, so a decommission MUST reach it.
    targets_.push_back({"software_licensing",
                        stores.software_licensing
                            ? Fn([p = stores.software_licensing](std::string_view id) {
                                  return p->delete_agent(id);
                              })
                            : nullptr});
    // The sixth store (Wave 7 PR7.2): agent_last_used per-executable rows,
    // read-gated by the Forensics securable — the decommission cascade must
    // reach it for the same reason it reaches software_licensing.
    targets_.push_back({"app_usage",
                        stores.app_usage ? Fn([p = stores.app_usage](std::string_view id) {
                            return p->delete_agent(id);
                        })
                                         : nullptr});
}

void AgentDecommission::add_store(std::string name, std::function<bool(std::string_view)> deleter) {
    targets_.push_back({std::move(name), std::move(deleter)});
}

DecommissionResult AgentDecommission::decommission(std::string_view agent_id) {
    DecommissionResult result;
    result.agent_id = std::string(agent_id);
    result.stores.reserve(targets_.size());

    if (agent_id.empty()) {
        // Mirror each store's own empty-id guard: nothing to erase, and an empty
        // agent_id must never reach a `DELETE ... WHERE agent_id = ''`. Every
        // target is reported Skipped so the audit trail is complete.
        spdlog::warn("AgentDecommission: empty agent_id — nothing to decommission");
        for (const auto& t : targets_) {
            result.stores.push_back({t.name, DecommissionOutcome::Skipped, {}});
            ++result.skipped;
        }
        return result;
    }

    for (const auto& t : targets_) {
        DecommissionStoreResult r;
        r.store = t.name;
        if (!t.deleter) {
            r.outcome = DecommissionOutcome::Skipped;
            ++result.skipped;
            result.stores.push_back(std::move(r));
            continue;
        }
        // Best-effort: neither a false return nor an exception from one store
        // aborts the fan-out — the remaining stores are still attempted.
        // delete_agent reports a transient PG failure as `false` (the DELETE did
        // not commit); that is recorded `Failed`, NOT `Deleted`, so the result
        // never claims an erasure that did not happen. A throw is the additional
        // exceptional case (an unexpected bug/bad_alloc), likewise Failed.
        try {
            if (t.deleter(agent_id)) {
                r.outcome = DecommissionOutcome::Deleted;
                ++result.deleted;
            } else {
                r.outcome = DecommissionOutcome::Failed;
                r.error = "delete_agent reported failure (delete did not commit)";
                ++result.failed;
                spdlog::error("AgentDecommission: store '{}' delete_agent reported failure for "
                              "agent={} (delete did not commit — recorded Failed, not Deleted)",
                              t.name, agent_id);
            }
        } catch (const std::exception& e) {
            r.outcome = DecommissionOutcome::Failed;
            r.error = e.what();
            ++result.failed;
            spdlog::error("AgentDecommission: store '{}' delete_agent threw for agent={}: {}",
                          t.name, agent_id, e.what());
        } catch (...) {
            r.outcome = DecommissionOutcome::Failed;
            r.error = "unknown exception";
            ++result.failed;
            spdlog::error("AgentDecommission: store '{}' delete_agent threw a non-std exception for "
                          "agent={}",
                          t.name, agent_id);
        }
        result.stores.push_back(std::move(r));
    }

    // One audit-friendly summary line per decommission.
    if (result.failed == 0)
        spdlog::info("AgentDecommission: agent={} decommissioned (deleted={} skipped={})", agent_id,
                     result.deleted, result.skipped);
    else
        spdlog::warn(
            "AgentDecommission: agent={} decommission PARTIAL (deleted={} skipped={} failed={})",
            agent_id, result.deleted, result.skipped, result.failed);
    return result;
}

} // namespace yuzu::server
