#include "instruction_referrers.hpp"

#include "instruction_execute.hpp" // bounded_definition_id
#include "policy_store.hpp"
#include "product_pack_store.hpp"
#include "refusal_log_throttle.hpp"
#include "schedule_engine.hpp"
#include "workflow_engine.hpp"

#include <yuzu/log_token.hpp>

#include <spdlog/spdlog.h>

#include <algorithm>
#include <chrono>
#include <memory>

namespace yuzu::server {

namespace {
constexpr int kPerSourceLimit = static_cast<int>(kMaxReferrersListed) + 1;
// How many pack ids the advisory read asks for: more than `kMaxPacksNoted` so "+N" is usually exact.
constexpr int kPackAdvisoryQueryLimit = 20;
} // namespace

DefinitionReferrersFn make_definition_referrers_fn(ScheduleEngine* schedules,
                                                   WorkflowEngine* workflows,
                                                   PolicyStore* policies) {
    // A failed source read refuses the delete (fail closed) and reaches the caller as one generic
    // "check unavailable" text; this names WHICH source for the operator, once a minute per source
    // (the refusal is the caller's, audited every time; only the log line is throttled).
    auto warn_throttle = std::make_shared<RefusalLogThrottle>(std::chrono::seconds(60), 8);
    const auto source_failed = [warn_throttle](const char* source, const char* what) {
        if (warn_throttle->should_warn(source))
            spdlog::warn("definition referrer check: {}; every definition delete is refused until "
                         "it recovers",
                         what);
    };
    auto single = [schedules, workflows, policies, source_failed](
               const std::string& definition_id,
               const DefinitionReferrerExclusions& exclude)
               -> std::expected<std::vector<DefinitionReferrer>, std::string> {
        if (!schedules || !workflows || !policies) {
            source_failed("unwired", "a referrer source is not wired");
            return std::unexpected(std::string("a referrer source is not wired"));
        }
        std::vector<DefinitionReferrer> out;

        // Device tokens scoped to a definition (`DeviceToken::definition_id`) are NOT a source
        // yet: DeviceTokenStore is passed nullptr to the REST API and no AgentRegistry setter is
        // called (server.cpp), so no such row can exist. Add that source here, with the same
        // fail-closed handling, when the store is wired.

        // The schedule list is capped by the engine, not by us; any match is enough to refuse, so
        // a truncated answer is still a complete reason. Only the first kPerSourceLimit are kept.
        auto sched = schedules->query_schedules_checked(ScheduleQuery{.definition_id = definition_id});
        if (!sched) {
            source_failed("schedule", "the schedule read failed");
            return std::unexpected(std::string("schedule read failed"));
        }
        for (const auto& s : sched->schedules) {
            if (out.size() >= static_cast<std::size_t>(kPerSourceLimit))
                break;
            out.push_back({"schedule", s.id});
        }

        auto wf = workflows->workflows_referencing_instruction(definition_id, kPerSourceLimit,
                                                          exclude.workflow_ids);
        if (!wf) {
            source_failed("workflow", "the workflow read failed");
            return std::unexpected(std::string("workflow read failed"));
        }
        for (auto& id : *wf)
            out.push_back({"workflow", std::move(id)});

        auto frag = policies->fragments_referencing_instruction(definition_id, kPerSourceLimit,
                                                         exclude.fragment_ids);
        if (!frag) {
            source_failed("policy fragment", "the policy fragment read failed");
            return std::unexpected(std::string("policy fragment read failed"));
        }
        for (auto& id : *frag)
            out.push_back({"policy fragment", std::move(id)});
        return out;
    };

    // The batch form (the pack uninstall): ONE read per source for the whole id list, in the same
    // source order, so the number of store reads is at most three however many definitions are
    // asked about. A source's ids are distinct (one row per schedule, workflow or fragment), and
    // the three kinds never collide, so no de-duplication is needed here. A later source is not
    // read once `limit` referrers are in hand: the caller only needs to know the list is longer
    // than it shows.
    auto batch = [schedules, workflows, policies, source_failed](
                     const std::vector<std::string>& definition_ids,
                     const DefinitionReferrerExclusions& exclude, std::size_t limit)
        -> std::expected<std::vector<DefinitionReferrer>, std::string> {
        if (!schedules || !workflows || !policies) {
            source_failed("unwired", "a referrer source is not wired");
            return std::unexpected(std::string("a referrer source is not wired"));
        }
        std::vector<DefinitionReferrer> out;
        if (definition_ids.empty() || limit == 0)
            return out;
        const int per_source = static_cast<int>(std::min<std::size_t>(limit, 1000000));
        const auto full = [&] { return out.size() >= limit; };

        auto sched = schedules->schedules_referencing_definitions(definition_ids, per_source);
        if (!sched) {
            source_failed("schedule", "the schedule read failed");
            return std::unexpected(std::string("schedule read failed"));
        }
        for (auto& id : *sched)
            out.push_back({"schedule", std::move(id)});

        if (!full()) {
            auto wf = workflows->workflows_referencing_instructions(definition_ids, per_source,
                                                                    exclude.workflow_ids);
            if (!wf) {
                source_failed("workflow", "the workflow read failed");
                return std::unexpected(std::string("workflow read failed"));
            }
            for (auto& id : *wf)
                out.push_back({"workflow", std::move(id)});
        }

        if (!full()) {
            auto frag = policies->fragments_referencing_instructions(definition_ids, per_source,
                                                                     exclude.fragment_ids);
            if (!frag) {
                source_failed("policy fragment", "the policy fragment read failed");
                return std::unexpected(std::string("policy fragment read failed"));
            }
            for (auto& id : *frag)
                out.push_back({"policy fragment", std::move(id)});
        }
        if (out.size() > limit)
            out.resize(limit);
        return out;
    };
    return DefinitionReferrersFn::with_batch(DefinitionReferrersFn(std::move(single)),
                                             std::move(batch));
}

DefinitionReferrersFn::Result
DefinitionReferrersFn::lookup_many(const std::vector<std::string>& definition_ids,
                                   const Exclusions& exclusions, std::size_t limit) const {
    if (!fn_)
        return std::unexpected(std::string("the referrer lookup is not wired"));
    std::vector<std::string> ids;
    ids.reserve(definition_ids.size());
    for (const auto& id : definition_ids)
        if (!id.empty())
            ids.push_back(id);
    if (ids.empty() || limit == 0)
        return std::vector<DefinitionReferrer>{};
    if (batch_)
        return batch_(ids, exclusions, limit);

    // No batch form: one call per id, de-duplicated by (kind, id) with a hash set, stopping as
    // soon as `limit` distinct referrers are in hand.
    std::vector<DefinitionReferrer> out;
    std::unordered_set<std::string> seen;
    for (const auto& id : ids) {
        auto found = fn_(id, exclusions);
        if (!found)
            return std::unexpected(std::move(found.error()));
        for (auto& r : *found) {
            // kind never contains a NUL, so the separator keeps (kind, id) pairs distinct
            if (!seen.insert(r.kind + '\0' + r.id).second)
                continue;
            out.push_back(std::move(r));
            if (out.size() >= limit)
                return out;
        }
    }
    return out;
}

DefinitionPackAdvisoryFn make_definition_pack_advisory_fn(ProductPackStore* packs) {
    auto warn_throttle = std::make_shared<RefusalLogThrottle>(std::chrono::seconds(60), 4);
    return [packs, warn_throttle](const std::string& definition_id)
               -> std::expected<std::vector<std::string>, std::string> {
        if (!packs)
            return std::unexpected(std::string("the product pack store is not wired"));
        auto ids = packs->packs_containing_item("InstructionDefinition", definition_id,
                                                kPackAdvisoryQueryLimit);
        if (!ids && warn_throttle->should_warn("pack"))
            spdlog::warn("definition delete: the product pack lookup failed, so the audit row "
                         "carries no packs= note (the delete is not affected)");
        return ids;
    };
}

std::string pack_advisory_note(const DefinitionPackAdvisoryFn& fn,
                               const std::string& definition_id) {
    if (!fn)
        return {};
    try {
        const auto ids = fn(definition_id);
        if (!ids || ids->empty())
            return {};
        std::string out = "packs=";
        const std::size_t shown = std::min(ids->size(), kMaxPacksNoted);
        for (std::size_t i = 0; i < shown; ++i) {
            if (i > 0)
                out += ',';
            out += ::yuzu::log_token(instruction_execute::bounded_definition_id((*ids)[i]));
        }
        if (ids->size() > shown)
            out += ",+" + std::to_string(ids->size() - shown);
        return out;
    } catch (...) {
        return {}; // advisory only: a throwing lookup must not turn a completed delete into a 500
    }
}

namespace {
/// "(used by policy <id> (<name>), <id>, +N)": the policies holding a pack-own fragment alive, at
/// most `kMaxHeldByPoliciesNamed` of them, each id and name bounded and folded; the name is left
/// out when empty. `N` is a lower bound (the caller reads one policy past the cap). Empty when
/// `held_by` is.
std::string held_by_suffix(const std::vector<HeldByPolicy>& held_by) {
    if (held_by.empty())
        return {};
    std::string out = " (used by policy ";
    const std::size_t shown = std::min(held_by.size(), kMaxHeldByPoliciesNamed);
    for (std::size_t i = 0; i < shown; ++i) {
        if (i > 0)
            out += ", ";
        out += ::yuzu::log_token(instruction_execute::bounded_definition_id(held_by[i].id));
        if (!held_by[i].name.empty())
            out += " (" +
                   ::yuzu::log_token(instruction_execute::bounded_definition_id(held_by[i].name)) +
                   ")";
    }
    if (held_by.size() > shown)
        out += ", +" + std::to_string(held_by.size() - shown);
    return out + ")";
}

/// "<kind> <id>, <kind> <id>, and N more": the first `kMaxReferrersListed`, ids bounded and folded.
std::string list_referrers(const std::vector<DefinitionReferrer>& referrers) {
    std::string out;
    const std::size_t shown = std::min(referrers.size(), kMaxReferrersListed);
    for (std::size_t i = 0; i < shown; ++i) {
        if (i > 0)
            out += ", ";
        out += referrers[i].kind + " " +
               ::yuzu::log_token(instruction_execute::bounded_definition_id(referrers[i].id)) +
               held_by_suffix(referrers[i].held_by);
    }
    if (referrers.size() > shown)
        out += ", and " + std::to_string(referrers.size() - shown) + " more";
    return out;
}
} // namespace

std::string describe_definition_referrers(const std::vector<DefinitionReferrer>& referrers) {
    return "the definition is referenced by " + std::to_string(referrers.size()) +
           (referrers.size() == 1 ? " item" : " items") + " and was NOT deleted: " +
           list_referrers(referrers) +
           ". Remove each of them (or point it at another definition), then delete this one.";
}

std::string describe_pack_uninstall_blockers(const std::vector<DefinitionReferrer>& referrers) {
    const bool policy_held = std::any_of(referrers.begin(), referrers.end(), [](const auto& r) {
        return !r.held_by.empty();
    });
    return "the pack was NOT uninstalled; " + std::to_string(referrers.size()) +
           (referrers.size() == 1 ? " item still uses" : " items still use") +
           " one of its definitions: " + list_referrers(referrers) +
           ". Remove each of them (or point it at another definition), then retry the uninstall." +
           (policy_held ? " A pack policy fragment that a policy uses survives the uninstall: "
                          "delete that policy, then retry."
                        : "");
}

} // namespace yuzu::server
