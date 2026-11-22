#pragma once

#include <nlohmann/json_fwd.hpp>

#include <cstddef>
#include <optional>
#include <set>
#include <string>
#include <string_view>
#include <vector>

namespace yuzu::server::rs_matcher {

// Unknown carries a reason through every boolean operation. Only a final True selects a device.
enum class RowMatch { False, True, MissingValue, MalformedValue, RowBound, CoverageUnproven };

inline constexpr std::size_t kQuantifiedRowLimit = 10000;
bool is_quantified_matcher(const nlohmann::json& matcher);
std::optional<std::string> validate_quantified_matcher(const nlohmann::json& matcher);

class QuantifiedMatcher {
public:
    // The caller owns matcher and keeps it immutable for this object's lifetime.
    explicit QuantifiedMatcher(const nlohmann::json& matcher);
    RowMatch evaluate(std::string_view output, bool complete) const;

private:
    struct Predicate {
        enum class Kind { Leaf, And, Or, Not };
        Kind kind{Kind::Leaf};
        std::string column;
        std::string op;
        std::string value;
        std::set<std::string_view> values;
        std::vector<Predicate> children;

        explicit Predicate(const nlohmann::json& expression);
        RowMatch evaluate(const nlohmann::json& row) const;
    };

    const nlohmann::json& matcher_;
    Predicate where_;
};

} // namespace yuzu::server::rs_matcher
