#include "management_group_model.hpp"

#include <nlohmann/json.hpp>

namespace yuzu::server {

std::string management_group_detail_json(const ManagementGroup& g,
                                          const std::vector<ManagementGroupMember>& members) {
    nlohmann::json member_arr = nlohmann::json::array();
    for (const auto& m : members) {
        member_arr.push_back(
            {{"agent_id", m.agent_id}, {"source", m.source}, {"added_at", m.added_at}});
    }
    nlohmann::json data{
        {"id", g.id},
        {"name", g.name},
        {"description", g.description},
        {"parent_id", g.parent_id},
        {"membership_type", g.membership_type},
        {"scope_expression", g.scope_expression},
        {"created_by", g.created_by},
        {"created_at", g.created_at},
        {"updated_at", g.updated_at},
        {"members", member_arr},
    };
    // error_handler_t::replace, not the strict default: these fields trace
    // back to store-persisted operator-authored strings (name/description/
    // scope_expression), and dump()'s strict default throws on invalid UTF-8
    // with no exception_handler wired on either call site (matches the
    // execution_statistics_model.cpp / #2970B-class precedent).
    return data.dump(-1, ' ', false, nlohmann::json::error_handler_t::replace);
}

} // namespace yuzu::server
