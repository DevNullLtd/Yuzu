/**
 * echo_software_core.cpp -- Pure orchestration core for the `software` source.
 * See echo_software_core.hpp. No registry I/O, no DB access — unit-testable
 * off-Windows.
 */

#include "echo_software_core.hpp"

#include <nlohmann/json.hpp>

#include <utility>

namespace yuzu::echo {

using json = nlohmann::json;

std::string software_state_to_json(const std::vector<SoftwareInfo>& apps) {
    json arr = json::array();
    for (const auto& a : apps) {
        arr.push_back({{"name", a.name},
                       {"version", a.version},
                       {"publisher", a.publisher},
                       {"install_date", a.install_date}});
    }
    return arr.dump();
}

std::vector<SoftwareInfo> software_state_from_json(const std::string& s) {
    std::vector<SoftwareInfo> result;
    if (s.empty()) {
        return result;
    }
    auto arr = json::parse(s, nullptr, /*allow_exceptions=*/false);
    if (arr.is_discarded() || !arr.is_array()) {
        return result;
    }
    for (const auto& j : arr) {
        if (!j.is_object()) {
            continue;
        }
        SoftwareInfo a;
        a.name = j.value("name", "");
        a.version = j.value("version", "");
        a.publisher = j.value("publisher", "");
        a.install_date = j.value("install_date", "");
        result.push_back(std::move(a));
    }
    return result;
}

SoftwareCollectResult software_collect_core(const std::string& prev_json,
                                            std::vector<SoftwareInfo> enumerated,
                                            int64_t timestamp, int64_t snapshot_id) {
    SoftwareCollectResult r;

    // Cold start: no prior state row. Seed the baseline silently — an 'installed'
    // event must mean "installed now", not "already present when the agent began
    // watching". get_state returns "" only when no row exists.
    if (prev_json.empty()) {
        r.kind = SoftwareCollectResult::Kind::kColdStartSeed;
        r.new_state_json = software_state_to_json(enumerated);
        return r;
    }

    // Corrupt/unreadable prior state (truncated write, tampering): a non-empty
    // blob that is not a JSON array must NOT be treated as cold-start (would
    // silently re-seed and lose the baseline) nor diffed against empty (would emit
    // a spurious full install/remove storm). Skip the tick; the baseline is
    // preserved for the next tick / manual repair (UP-1/UP-2).
    auto parsed = json::parse(prev_json, nullptr, /*allow_exceptions=*/false);
    if (parsed.is_discarded() || !parsed.is_array()) {
        r.kind = SoftwareCollectResult::Kind::kCorruptSkip;
        return r;
    }

    auto previous = software_state_from_json(prev_json);

    // Steady state. Machine scope only: there are no logged-off users to carry
    // forward, so the freshly enumerated machine inventory IS the current snapshot.
    std::vector<SoftwareInfo> current = std::move(enumerated);

    r.kind = SoftwareCollectResult::Kind::kSteady;
    r.events = compute_software_events(previous, current, timestamp, snapshot_id);
    r.new_state_json = software_state_to_json(current);
    return r;
}

} // namespace yuzu::echo
