#pragma once

/// #4990: the Forensics tier on stored-response reads.
///
/// A Forensics-tier plugin (see `kForensicsSecurable`) is gated at DISPATCH, but its stored
/// response rows land in `ResponseStore` where the read tier is `Response:Read`. This header is the
/// seam that makes the Forensics tier a property of every read: `ResponseStore`'s public read
/// methods take a `const ResponseTierFilter&` with NO default value, so a read cannot be written
/// without deciding what the caller may see, and the filter is pushed into the SQL (beside
/// `append_scope_clause`) so LIMIT, paging, aggregates and facets are computed over the permitted set.
///
/// Semantics of the `forensics_visible` argument follow ADR-0033 (`authz::VisibleSet`):
///   * `nullopt`        = the caller may read every Forensics row (a global `Forensics:Read`).
///   * present subset   = only Forensics rows whose `agent_id` is in the subset.
///   * present EMPTY    = no Forensics row (also the fail-closed sink: unwired, degraded, no grant).
/// Spell the empty case with `authz::deny_all()`, never `VisibleSet{}` (that is `nullopt`).
///
/// This header holds only types: no store, no lock, no SQL. The plugin set is derived from the
/// capability catalogue in `forensics_plugin_set.hpp`, never hand-kept.

#include <algorithm>
#include <optional>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

#include "ascii_fold.hpp" // ascii_lower: the one plugin-name fold
#include "authz_model.hpp"

namespace yuzu::server {

/// The plugins whose stored rows are Forensics-tier: lowercase, sorted, unique, NON-EMPTY.
/// The only ways to obtain one are `from_names` (which refuses an empty set) and the catalogue
/// derivation in `forensics_plugin_set.hpp`; an empty set is unrepresentable, so a filter built from
/// one can never silently exclude nothing.
class ForensicsPluginSet {
public:
    ForensicsPluginSet() = delete;

    /// Lowercases (ASCII), drops empty names, sorts and de-duplicates. `std::nullopt` when nothing
    /// is left: the caller must treat that as a refusal (boot refuses), never as "no Forensics plugins".
    [[nodiscard]] static std::optional<ForensicsPluginSet> from_names(std::vector<std::string> names) {
        for (auto& n : names)
            n = ascii_lower(n);
        std::erase_if(names, [](const std::string& n) { return n.empty(); });
        std::ranges::sort(names);
        names.erase(std::unique(names.begin(), names.end()), names.end());
        if (names.empty())
            return std::nullopt;
        return ForensicsPluginSet{std::move(names)};
    }

    [[nodiscard]] const std::vector<std::string>& names() const noexcept { return names_; }

    /// True when `plugin` (any ASCII case) is a Forensics-tier plugin.
    [[nodiscard]] bool contains(std::string_view plugin) const {
        return std::binary_search(names_.begin(), names_.end(), ascii_lower(plugin));
    }

private:
    explicit ForensicsPluginSet(std::vector<std::string> names) : names_(std::move(names)) {}

    std::vector<std::string> names_;
};

/// What a `ResponseStore` read may return with respect to the Forensics tier. Not
/// default-constructible; built only through the factories below (`exclude`,
/// `for_fixed_plugin_poll`, `refuse_unwired`, `unrestricted_internal_consumer`) so every call site
/// names its decision.
class ResponseTierFilter {
public:
    ResponseTierFilter() = delete;

    /// Operator-facing read: Forensics-plugin rows are excluded unless `forensics_visible` admits them.
    [[nodiscard]] static ResponseTierFilter exclude(const ForensicsPluginSet& plugins,
                                                    authz::VisibleSet forensics_visible) {
        ResponseTierFilter f{Key{}};
        if (!forensics_visible)
            return f; // global Forensics:Read: no clause
        f.excluded_ = plugins.names();
        f.exempt_agents_.assign(forensics_visible->begin(), forensics_visible->end());
        std::ranges::sort(f.exempt_agents_);
        return f;
    }

    /// A server-internal consumer that is not an operator read surface: it reads back a command the
    /// server dispatched itself from a fixed, non-Forensics plugin set. The four live callers are
    /// the tar fleet snapshot poll, the deployment collect, the pre-flight check collation and the
    /// quarantine containment reconciler; they are frozen by
    /// tests/test_response_store_read_tripwire.py. The policy evaluator, the bundle collate and the
    /// result-set materializer read through a real filter instead. Do not use this to silence a
    /// filter on anything an operator can reach.
    [[nodiscard]] static ResponseTierFilter unrestricted_internal_consumer() {
        return ResponseTierFilter{Key{}};
    }

    /// A server-side poll that reads back the reply to a command the server dispatched itself from
    /// a FIXED set of plugins, none of them Forensics-tier (the device live snapshots, the DEX and
    /// TAR result polls). Excludes the Forensics plugins outright (present-empty visibility), so
    /// the poll could never return a Forensics row even if the command id were tampered with. A
    /// null set (a surface that was never wired; impossible in production, boot refuses without
    /// one) is `refuse_unwired()`: the fixed plugin does not make an unwired poll safe to run
    /// unfiltered, since the same wiring gap would then hide a real filter.
    [[nodiscard]] static ResponseTierFilter for_fixed_plugin_poll(const ForensicsPluginSet* plugins) {
        return plugins ? exclude(*plugins, authz::deny_all()) : refuse_unwired();
    }

    /// Fail-closed sink for a surface whose plugin set was never wired (impossible in production:
    /// boot refuses without one). Without the set the Forensics rows cannot be told apart from the
    /// rest, so EVERY row is refused rather than any being admitted.
    [[nodiscard]] static ResponseTierFilter refuse_unwired() {
        ResponseTierFilter f{Key{}};
        f.refuse_all_ = true;
        return f;
    }

    /// Whether this filter lets a stored row of `plugin` from `agent_id` through: the same decision
    /// the SQL predicate makes, for a surface that must know BEFORE it reads (a result poll that
    /// would otherwise wait on a row it can never be shown). A plugin outside the Forensics set is
    /// admitted by every filter except `refuse_unwired()`.
    [[nodiscard]] bool admits(std::string_view plugin, std::string_view agent_id) const {
        if (refuse_all_)
            return false;
        if (excluded_.empty())
            return true; // unrestricted: a global Forensics:Read, or an internal consumer
        if (!std::binary_search(excluded_.begin(), excluded_.end(), ascii_lower(plugin)))
            return true; // not a Forensics-tier plugin
        return std::binary_search(exempt_agents_.begin(), exempt_agents_.end(), agent_id,
                                  [](std::string_view a, std::string_view b) { return a < b; });
    }

    // -- Accessors for response_store.cpp (the SQL builder); not a policy surface. -----------------

    /// True when a SQL clause is needed: the filter excludes plugins for at least some agents.
    [[nodiscard]] bool restricts() const noexcept { return refuse_all_ || !excluded_.empty(); }
    /// True for `refuse_unwired()`: the read matches no row at all (`AND 1=0`).
    [[nodiscard]] bool refuses_every_row() const noexcept { return refuse_all_; }
    /// Lowercase plugin names to exclude (empty iff `!restricts()`).
    [[nodiscard]] const std::vector<std::string>& excluded_plugins() const noexcept { return excluded_; }
    /// Sorted agent ids whose Forensics rows are still readable; empty = none.
    [[nodiscard]] const std::vector<std::string>& exempt_agents() const noexcept { return exempt_agents_; }

private:
    struct Key {};
    explicit ResponseTierFilter(Key) {}

    std::vector<std::string> excluded_;
    std::vector<std::string> exempt_agents_;
    bool refuse_all_{false};
};

} // namespace yuzu::server
