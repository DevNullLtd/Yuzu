// constraint_accumulator.hpp -- one shared shape for a collector that walks
// multiple roots/entries (several directories, several per-directory files,
// several per-user scans) and must never let a genuine acquisition failure
// on ANY of them (a directory-open error, a per-entry stat/metadata
// failure, a per-file read error, a parse failure) be silently absorbed
// just because SOME roots succeeded.
//
// Lifted out of the autoruns plugin (agents/plugins/autoruns/src/
// autoruns_parsers.hpp) during the Wave-7b prerequisite pass so
// execution_artifacts and app_usage don't reinvent or copy it. It
// generalizes the pattern `lnx_cron_d` (autoruns_linux.cpp) had already
// gotten right on its own -- a directory-level absent/permission_denied/
// other-errno trichotomy plus a per-file `classify_read_error`-driven
// dedup -- into one reusable type, after PR #4154 round 9 found six OTHER
// autoruns collectors in the same file had each independently reinvented a
// narrower version that tracked only EACCES/EPERM and dropped every other
// failure class (EIO, oversized reads, non-regular leaves, stat failures).
//
// Exact-string deduplication (NOT `note_file_constraint`'s substring
// `reason.find(token)` check elsewhere in this codebase, which silently
// conflates e.g. "permission_denied" with "partial_permission_denied"
// since the former is a substring of the latter), insertion order
// preserved. A later successful sibling read never erases or hides an
// earlier recorded failure -- there is no operation that removes a token
// once added.
//
// Platform-agnostic pure C++, no OS call, no I/O -- the zero-dependency,
// core/plugin-edge-free "leaf helper" convention every other file in this
// directory (win_str.hpp, wmi_bounded.hpp, posix_dir_walk.hpp, ...) follows
// per docs/cpp-conventions.md. Call sites use it fully qualified
// (`yuzu::shared::ConstraintAccumulator`), matching this directory's
// existing convention (see `posix_dir_walk.hpp`'s `yuzu::shared::
// walk_dir_capped`) rather than a `using` import.
#pragma once

#include <algorithm>
#include <string>
#include <string_view>
#include <vector>

namespace yuzu::shared {

class ConstraintAccumulator {
public:
    /// Records one failure token (e.g. "permission_denied", a lowercased
    /// errno token, "oversized", "not_regular", "row_cap"). A caller that
    /// already has a `FileStatus`/`(support, reason)` pair from
    /// `classify_read_error` passes its `.reason` here directly.
    void add_failure(std::string_view token) {
        any_failure_ = true;
        std::string s{token};
        if (std::find(tokens_.begin(), tokens_.end(), s) == tokens_.end())
            tokens_.push_back(std::move(s));
    }

    /// Marks that some acquisition step a downstream row/enablement decision
    /// depends on (a directory listing, a wants-symlink scan, a cross-user
    /// discovery pass) was genuinely incomplete -- distinct from
    /// add_failure(): this carries no token of its own (the caller has
    /// usually already added one), it exists so a caller computing e.g. an
    /// Enabled decision can ask "was ANYTHING this decision depends on
    /// incomplete" without re-deriving it from the token list.
    void mark_incomplete() { incomplete_ = true; }

    bool any_failure() const { return any_failure_; }
    bool incomplete() const { return incomplete_; }

    /// Every accumulated token, comma-joined -- this schema's existing
    /// multi-token reason convention (see e.g. lnx_cron_periodic's own
    /// hand-built "reason1,reason2" strings).
    std::string reason() const {
        std::string out;
        for (const auto& t : tokens_) {
            if (!out.empty()) out += ',';
            out += t;
        }
        return out;
    }

    /// Composes with a caller-supplied PERMANENT catalog-level token (e.g.
    /// lnx_systemd_timers_user's own narrow_search_path_coverage) --
    /// appended after every accumulated failure token, never replacing or
    /// being replaced by them. `permanent_token` empty is the common case
    /// (most sources carry no permanent limitation) and is a no-op.
    std::string reason_with(std::string_view permanent_token) const {
        std::string out = reason();
        if (!permanent_token.empty()) {
            if (!out.empty()) out += ',';
            out += permanent_token;
        }
        return out;
    }

private:
    std::vector<std::string> tokens_;
    bool any_failure_ = false;
    bool incomplete_ = false;
};

} // namespace yuzu::shared
