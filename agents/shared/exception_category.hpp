// exception_category.hpp -- the one bounded, wire-safe name for "what was just thrown".
//
// A plugin that contains an exception at the ABI seam reports WHAT KIND it was, so a triager can
// tell an allocation failure from a logic error from a foreign throw without reading logs (the
// plugin API has no log channel). The result is a FINITE three-token grammar:
//
//     bad_alloc | std_exception | unknown
//
// `what()` is deliberately NOT carried: it is unbounded, untrusted text (it can embed a file
// name, a path or attacker-influenced bytes) and must not travel on the wire.
//
// Consumers: browser_policy (run_guarded), update_source_trust, later plugins.
//
// Platform-agnostic pure C++, no OS call, no I/O.
#pragma once

#include <exception>
#include <new>
#include <string_view>

namespace yuzu::shared {

/// Category of the exception currently being handled. Call ONLY from inside a `catch (...)`
/// block (it rethrows the active exception to classify it; with none active it would call
/// std::terminate). Never throws.
[[nodiscard]] inline std::string_view exception_category() noexcept {
    try {
        throw;
    } catch (const std::bad_alloc&) {
        return "bad_alloc";
    } catch (const std::exception&) {
        return "std_exception";
    } catch (...) {
        return "unknown";
    }
}

} // namespace yuzu::shared
