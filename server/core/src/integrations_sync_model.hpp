#pragma once

/// @file integrations_sync_model.hpp
/// Pure helpers shared by the Integrations sync routes and the directory
/// route audit rows. No I/O, no store types.

#include <cstddef>
#include <string>
#include <utility>
#include <vector>

namespace yuzu::server::integrations {

/// One requested group-to-role change. An empty `role_name` removes the mapping.
struct MappingChange {
    std::string group_id;
    std::string role_name;
};

/// Audit detail for `directory.group_mapping.update`: the count plus the
/// group-to-role pairs, so the row records WHAT was configured, not just how
/// many. Free text is operator- and directory-supplied, so control bytes are
/// replaced (an audit row must not line-split) and the whole detail is bounded.
[[nodiscard]] inline std::string
mapping_audit_detail(const std::vector<MappingChange>& changes, std::size_t cap = 1000) {
    auto clean = [](const std::string& s) {
        std::string out = s;
        for (auto& c : out) {
            const auto u = static_cast<unsigned char>(c);
            if (u < 0x20 || u == 0x7f)
                c = '?';
        }
        return out;
    };
    std::string out = std::to_string(changes.size()) + " mappings updated:";
    bool first = true;
    for (const auto& ch : changes) {
        std::string piece = std::string(first ? " " : ", ") + clean(ch.group_id) + "=" +
                            (ch.role_name.empty() ? std::string("(removed)") : clean(ch.role_name));
        first = false;
        if (out.size() + piece.size() > cap) {
            out += " ...";
            break;
        }
        out += piece;
    }
    return out;
}

} // namespace yuzu::server::integrations
