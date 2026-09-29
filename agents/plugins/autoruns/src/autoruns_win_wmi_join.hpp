// autoruns_win_wmi_join.hpp -- pure join of WMI __FilterToConsumerBinding rows
// against the __EventFilter / __EventConsumer rows they reference (P12
// respec delta 1). Plain C++, no Windows headers, no #ifdef -- compiles and
// is exercised by tests on every OS, since the join logic itself has nothing
// Windows-specific about it (only the three SELECT * FROM ... queries that
// produce its inputs are Windows-only).
//
// Without this join, autoruns_win.cpp used to concatenate every filter,
// consumer and binding row into one blob and call
// parse_wmi_subscription_triple once -- last-block-wins per CIM class, so a
// host with N>1 bindings silently reported only 1 row. This header restores
// one row per binding by matching each binding's Filter/Consumer CIM
// reference to the row it names.
#pragma once

#include <map>
#include <string>
#include <string_view>
#include <vector>

namespace yuzu::autoruns {

// The exact shape of yuzu::shared::wmi::WmiRow, restated locally so this
// header never has to include wmi_bounded.hpp (Windows-only by construction).
using WmiJoinRow = std::map<std::string, std::string>;

// Extracts the first double-quoted substring from a CIM reference value.
// Accepts both shapes seen in practice:
//   - the COM object path run_bounded_wmi_query's variant_to_string produces
//     for a CIM_REFERENCE (VT_BSTR): __EventFilter.Name="SCM Event Log Filter"
//   - the PowerShell Format-List capture shape (A1's fixture):
//     __EventFilter (Name = "SCM Event Log Filter")
// A value with no quoted substring (or no closing quote) returns empty --
// never throws.
inline std::string wmi_ref_name(std::string_view ref) {
    const std::size_t open = ref.find('"');
    if (open == std::string_view::npos) return {};
    const std::size_t close = ref.find('"', open + 1);
    if (close == std::string_view::npos) return {};
    return std::string{ref.substr(open + 1, close - open - 1)};
}

struct WmiJoinedBinding {
    WmiJoinRow binding;
    WmiJoinRow filter;
    WmiJoinRow consumer;
    bool filter_matched = false;
    bool consumer_matched = false;
};

namespace detail {

// Finds the row whose "Name" field equals `ref_name`. Returns the first
// match; an empty `ref_name` or no match leaves `matched` false and returns
// a default-constructed (empty) row -- never a throw.
inline WmiJoinRow find_by_name(const std::vector<WmiJoinRow>& rows, const std::string& ref_name,
                                bool& matched) {
    matched = false;
    if (ref_name.empty()) return {};
    for (const auto& row : rows) {
        const auto it = row.find("Name");
        if (it != row.end() && it->second == ref_name) {
            matched = true;
            return row;
        }
    }
    return {};
}

} // namespace detail

// One output element per binding, in enumeration order. Each binding's
// Filter/Consumer ref is resolved against `filters`/`consumers` by name; a
// ref that is missing, unparsable, or names a row that was never enumerated
// simply leaves the corresponding *_matched flag false and that half of the
// joined element empty -- the binding itself is still emitted.
inline std::vector<WmiJoinedBinding> join_wmi_bindings(const std::vector<WmiJoinRow>& filters,
                                                        const std::vector<WmiJoinRow>& consumers,
                                                        const std::vector<WmiJoinRow>& bindings) {
    std::vector<WmiJoinedBinding> out;
    out.reserve(bindings.size());
    for (const auto& binding : bindings) {
        WmiJoinedBinding joined;
        joined.binding = binding;

        if (const auto it = binding.find("Filter"); it != binding.end()) {
            joined.filter = detail::find_by_name(filters, wmi_ref_name(it->second), joined.filter_matched);
        }
        if (const auto it = binding.find("Consumer"); it != binding.end()) {
            joined.consumer =
                detail::find_by_name(consumers, wmi_ref_name(it->second), joined.consumer_matched);
        }
        out.push_back(std::move(joined));
    }
    return out;
}

} // namespace yuzu::autoruns
