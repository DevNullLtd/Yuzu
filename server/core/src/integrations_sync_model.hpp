#pragma once

/// @file integrations_sync_model.hpp
/// Pure helpers shared by the Integrations sync routes and the directory
/// route audit rows. No I/O, no store types.

#include <cstddef>
#include <map>
#include <optional>
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

/// Audit details for `directory.group_mapping.update`: the group-to-role pairs,
/// so a row records WHAT was configured, not just how many. Free text is
/// operator- and directory-supplied, so control bytes are replaced (an audit
/// row must not line-split) and each value is clipped. Every pair is recorded:
/// a long list is split across several details, each at most `cap` bytes, so
/// padding a request can never push an applied pair out of the trail. An empty
/// list yields one detail ("0 mappings <verb>:").
[[nodiscard]] inline std::vector<std::string>
mapping_audit_chunks(const std::vector<MappingChange>& changes, std::string_view verb = "updated",
                     std::size_t cap = 1000) {
    auto clean = [](const std::string& s) {
        std::string out = s.size() > 256 ? s.substr(0, 256) + "..." : s;
        for (auto& c : out) {
            const auto u = static_cast<unsigned char>(c);
            if (u < 0x20 || u == 0x7f)
                c = '?';
        }
        return out;
    };
    std::vector<std::string> out;
    std::string body;
    std::size_t in_chunk = 0;
    auto flush = [&] {
        out.push_back(std::to_string(in_chunk) + " mappings " + std::string(verb) + ":" + body);
        body.clear();
        in_chunk = 0;
    };
    for (const auto& ch : changes) {
        const std::string pair = clean(ch.group_id) + "=" +
                                 (ch.role_name.empty() ? std::string("(removed)")
                                                        : clean(ch.role_name));
        // 24 bytes of headroom for the "<n> mappings <verb>:" prefix, 2 for the separator.
        if (in_chunk && body.size() + pair.size() + 2 + 24 + verb.size() > cap)
            flush();
        body += (in_chunk ? ", " : " ") + pair;
        ++in_chunk;
    }
    if (in_chunk || out.empty())
        flush();
    return out;
}

/// The requested changes after the store's own last-write-wins rule: one entry
/// per group, in order of last occurrence (a body naming a group twice ends
/// with the later entry stored, so the earlier one is not an outcome).
[[nodiscard]] inline std::vector<MappingChange>
last_wins_mapping_changes(const std::vector<MappingChange>& changes) {
    std::vector<MappingChange> out;
    for (std::size_t i = 0; i < changes.size(); ++i) {
        bool later = false;
        for (std::size_t j = i + 1; j < changes.size(); ++j)
            if (changes[j].group_id == changes[i].group_id) {
                later = true;
                break;
            }
        if (!later)
            out.push_back(changes[i]);
    }
    return out;
}

/// Which requested changes the stored mapping set shows (`confirmed`) and which
/// it does not (`unconfirmed`). The store's mapping writers swallow a failed
/// write (void return), so the route reads the set back and audits what is
/// actually there: a requested role must be the stored role, a removal must be
/// absent. `stored` empty-optional means the read-back itself failed: nothing
/// is confirmed, and an absent group must not read as a confirmed removal.
struct MappingOutcome {
    std::vector<MappingChange> confirmed;
    std::vector<MappingChange> unconfirmed;
};

[[nodiscard]] inline MappingOutcome
classify_mapping_changes(const std::vector<MappingChange>& changes,
                         const std::optional<std::map<std::string, std::string>>& stored) {
    MappingOutcome out;
    for (const auto& ch : last_wins_mapping_changes(changes)) {
        bool ok = false;
        if (stored) {
            const auto it = stored->find(ch.group_id);
            ok = ch.role_name.empty() ? it == stored->end()
                                      : it != stored->end() && it->second == ch.role_name;
        }
        (ok ? out.confirmed : out.unconfirmed).push_back(ch);
    }
    return out;
}

} // namespace yuzu::server::integrations
