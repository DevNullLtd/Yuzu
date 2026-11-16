// list_walk.hpp -- pure decisions for reading an index-driven OS list (RegEnumKeyExW and its
// kin) as COMPLETE or as a failed read.
//
// windows.h-free by design (mirrors value_enumeration.hpp): the OS shell supplies the per-index
// step and the "did the list change under me" stamp as callables, so both decisions are
// unit-tested on every host (tests/unit/test_value_enumeration.cpp) without a live registry.
//
//   walk_enumeration -- an error part-way is a failed read, never a short list.
//   stable_walk      -- a walk is accepted only when the same stamp was observed before and after
//                       it; a changed stamp walks again, and a stamp that cannot be taken, or
//                       never settles, is a failed read.

#pragma once

#include <optional>
#include <string>
#include <utility>
#include <vector>

namespace yuzu::shared {

/// What an index-driven enumerator answers for one index.
enum class ListStep { Item, End, Error };

/// The result of walking such a list. `error` is empty exactly when the walk ended at the
/// list's end. A walk that ended on an error is a FAILED READ, never a short list: `names` is
/// then empty, so a partial list cannot be mistaken for a complete one.
struct ListWalk {
    std::vector<std::string> names;
    std::string error; // "index <i> (<the detail the step supplied>)" when the walk failed
};

/// Walk `step(i, name, err)` from index 0: it fills `name` and answers Item, answers End at
/// the end of the list, or fills `err` and answers Error. Only End completes a walk. (An
/// index-driven walk can still skip an entry that appears or disappears while it runs, with no
/// error code; stable_walk below is the guard for a caller that cannot accept that.)
template <class Step>
[[nodiscard]] ListWalk walk_enumeration(Step&& step) {
    ListWalk walk;
    for (unsigned i = 0;; ++i) {
        std::string name;
        std::string err;
        switch (step(i, name, err)) {
        case ListStep::Item:
            walk.names.push_back(std::move(name));
            break;
        case ListStep::End:
            return walk;
        case ListStep::Error:
            walk.names.clear();
            walk.error = "index " + std::to_string(i) + " (" + err + ")";
            return walk;
        }
    }
}

/// `error` values stable_walk adds to walk_enumeration's own.
inline constexpr const char* kStampFailed = "stamp_failed"; // a stamp could not be taken
inline constexpr const char* kStampUnstable = "unstable";   // the stamp changed on every attempt

/// Walk with a change guard. `stamp_fn()` answers a `std::optional<Stamp>` (Stamp is
/// equality-comparable) describing the list's current state, or nullopt when it cannot be read;
/// `walk_fn()` answers a ListWalk. Each attempt takes a stamp, walks, takes a stamp:
///   - a stamp that cannot be taken ends the call at once with `stamp_failed` (two failed stamps
///     never compare equal, so they never certify a listing);
///   - a walk that failed is returned as it is (its own error);
///   - equal stamps accept the walk; unequal stamps try again, up to `max_attempts` attempts, and
///     the last one reports `unstable`.
/// A failed result carries no names.
template <class StampFn, class WalkFn>
[[nodiscard]] ListWalk stable_walk(StampFn&& stamp_fn, WalkFn&& walk_fn, unsigned max_attempts) {
    for (unsigned attempt = 0; attempt < max_attempts; ++attempt) {
        const auto before = stamp_fn();
        if (!before)
            return ListWalk{{}, kStampFailed};
        ListWalk walk = walk_fn();
        if (!walk.error.empty())
            return walk;
        const auto after = stamp_fn();
        if (!after)
            return ListWalk{{}, kStampFailed};
        if (*before == *after)
            return walk;
    }
    return ListWalk{{}, kStampUnstable};
}

} // namespace yuzu::shared
