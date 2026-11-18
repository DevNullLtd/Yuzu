// list_walk.hpp -- pure decisions for reading an index-driven OS list (RegEnumKeyExW and its
// kin) as COMPLETE or as a failed read.
//
// windows.h-free by design (mirrors value_enumeration.hpp): the OS shell supplies the per-index
// step and the whole-walk callable, so both decisions are unit-tested on every host
// (tests/unit/test_value_enumeration.cpp) without a live registry.
//
//   walk_enumeration -- an error part-way is a failed read, never a short list.
//   stable_walk      -- a list is accepted only when two CONSECUTIVE walks returned the same
//                       names; a walk that failed is returned as it is, and a list that never
//                       settles is a failed read.

#pragma once

#include <algorithm>
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

/// `error` value stable_walk adds to walk_enumeration's own.
inline constexpr const char* kWalkUnstable = "unstable"; // no two consecutive walks agreed

/// Walk until two consecutive walks return the same names. `walk_fn()` answers a ListWalk.
///   - a walk that failed is returned as it is (its own error), whichever walk it was;
///   - each walk's names are sorted, and a walk is accepted only when its sorted names equal the
///     previous walk's; a walk that differs becomes the one the next is compared with;
///   - `max_walks` walks that never produced an agreeing pair report `unstable`. With
///     `max_walks` < 2 no pair can form, so nothing is ever accepted.
/// A failed result carries no names; an accepted one carries them sorted. The comparison is
/// between walks' own names: it does not rely on any separate "did the list change" probe, so a
/// walk that skipped an entry is never accepted on the strength of a probe that read the list
/// before and after it.
template <class WalkFn>
[[nodiscard]] ListWalk stable_walk(WalkFn&& walk_fn, unsigned max_walks) {
    ListWalk prev;
    for (unsigned walk_no = 0; walk_no < max_walks; ++walk_no) {
        ListWalk walk = walk_fn();
        if (!walk.error.empty())
            return walk;
        std::sort(walk.names.begin(), walk.names.end());
        if (walk_no > 0 && walk.names == prev.names)
            return walk;
        prev = std::move(walk);
    }
    return ListWalk{{}, kWalkUnstable};
}

} // namespace yuzu::shared
