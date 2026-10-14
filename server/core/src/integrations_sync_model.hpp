#pragma once

/// @file integrations_sync_model.hpp
/// Pure helpers shared by the Integrations sync routes and the directory
/// route audit rows. No I/O, no store types.

#include <cstddef>
#include <map>
#include <string>
#include <string_view>
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
mapping_audit_detail(const std::vector<MappingChange>& changes, std::size_t cap = 1000,
                     std::string_view verb = "updated") {
    auto clean = [](const std::string& s) {
        std::string out = s;
        for (auto& c : out) {
            const auto u = static_cast<unsigned char>(c);
            if (u < 0x20 || u == 0x7f)
                c = '?';
        }
        return out;
    };
    std::string out = std::to_string(changes.size()) + " mappings " + std::string(verb) + ":";
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

/// The requested changes the stored mapping set does not show. The store's
/// mapping writers swallow a failed write (void return), so the route reads the
/// set back and audits only what is actually there: a requested role must be
/// the stored role, a removal must be absent.
[[nodiscard]] inline std::vector<MappingChange>
unconfirmed_mapping_changes(const std::vector<MappingChange>& changes,
                            const std::map<std::string, std::string>& stored) {
    std::vector<MappingChange> out;
    for (const auto& ch : changes) {
        const auto it = stored.find(ch.group_id);
        const bool ok = ch.role_name.empty() ? it == stored.end()
                                              : it != stored.end() && it->second == ch.role_name;
        if (!ok)
            out.push_back(ch);
    }
    return out;
}

} // namespace yuzu::server::integrations
