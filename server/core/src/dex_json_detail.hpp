#pragma once

/// @file dex_json_detail.hpp
/// Core-only JSON helpers shared by the DEX read-model serializers, so the
/// per-version join and the application list publish one interval shape.

#include <cmath>
#include <cstdint>
#include <optional>

#include <nlohmann/json.hpp>

#include "dex_stats.hpp"

namespace yuzu::server::dex_json_detail {

inline nlohmann::json interval_json(const DexInterval& i, bool ratio) {
    using json = nlohmann::json;
    const bool inf_upper = !std::isfinite(i.upper);
    json o{{"lower", i.lower}, {"reliable", i.reliable}};
    o["estimate"] = std::isfinite(i.estimate) ? json(i.estimate) : json(nullptr);
    o["upper"] = inf_upper ? json(nullptr) : json(i.upper);
    if (ratio)
        o["unbounded"] = inf_upper;
    return o;
}

inline nlohmann::json opt_i64(const std::optional<std::int64_t>& v) {
    using json = nlohmann::json;
    return v ? json(*v) : json(nullptr);
}

} // namespace yuzu::server::dex_json_detail
