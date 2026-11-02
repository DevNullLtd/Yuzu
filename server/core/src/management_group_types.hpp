#pragma once

/// @file management_group_types.hpp
/// The plain row types of the management-group store. Store-free by design: a TU enrolled in
/// `STORE_DEFINITION_FREE_TUS` (`scripts/ci/check-seam-closure.py`) can name a group or a
/// member without reaching `management_group_store.hpp`. `management_group_store.hpp` includes
/// this header, so existing users of the store see the same names.

#include <cstdint>
#include <string>

namespace yuzu::server {

struct ManagementGroup {
    std::string id;
    std::string name;
    std::string description;
    std::string parent_id;        // empty for root groups
    std::string membership_type;  // "static" or "dynamic"
    std::string scope_expression; // for dynamic groups (evaluated by scope engine)
    std::string created_by;
    int64_t created_at{0};
    int64_t updated_at{0};
};

struct ManagementGroupMember {
    std::string group_id;
    std::string agent_id;
    std::string source; // "static" or "dynamic"
    int64_t added_at{0};
};

} // namespace yuzu::server
