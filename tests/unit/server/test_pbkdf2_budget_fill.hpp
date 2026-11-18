#pragma once
// Test helper: saturate a Pbkdf2Budget in every class so any caller is refused.

#include "../../../server/core/src/pbkdf2_budget.hpp"

#include <string>
#include <vector>

namespace yuzu::test {

/// Takes every slot of both shared lanes (unauthenticated, one source each; authenticated, one
/// principal each) and the whole break-glass floor (one source each). The returned slots hold them until destroyed.
inline std::vector<yuzu::server::Pbkdf2Budget::Slot> fill_pbkdf2_budget(
    yuzu::server::Pbkdf2Budget& b) {
    using yuzu::server::Pbkdf2Class;
    std::vector<yuzu::server::Pbkdf2Budget::Slot> held;
    for (int i = 0; i < 1000; ++i) {
        auto s = b.try_acquire(Pbkdf2Class::kUnauthenticated, "fill-u" + std::to_string(i));
        if (!s.ok())
            break;
        held.push_back(std::move(s));
    }
    for (int i = 0; i < 1000; ++i) {
        auto s = b.try_acquire(Pbkdf2Class::kAuthenticated, {}, "fill-p" + std::to_string(i));
        if (!s.ok())
            break;
        held.push_back(std::move(s));
    }
    for (int i = 0; i < 1000; ++i) {
        auto s = b.try_acquire(Pbkdf2Class::kBreakGlass, "fill-b" + std::to_string(i));
        if (!s.ok())
            break;
        held.push_back(std::move(s));
    }
    return held;
}

} // namespace yuzu::test
