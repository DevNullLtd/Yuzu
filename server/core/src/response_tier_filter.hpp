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
#include <cctype>
#include <optional>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

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
            for (auto& c : n)
                c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
        std::erase_if(names, [](const std::string& n) { return n.empty(); });
        std::ranges::sort(names);
        names.erase(std::unique(names.begin(), names.end()), names.end());
        if (names.empty())
            return std::nullopt;
        return ForensicsPluginSet{std::move(names)};
    }

    [[nodiscard]] const std::vector<std::string>& names() const noexcept { return names_; }

private:
    explicit ForensicsPluginSet(std::vector<std::string> names) : names_(std::move(names)) {}

    std::vector<std::string> names_;
};

/// What a `ResponseStore` read may return with respect to the Forensics tier. Not
/// default-constructible; built only through the two factories below so every call site names its
/// decision.
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

    /// A server-internal consumer that is not an operator read surface (dispatch correlation,
    /// compliance evaluation, deployment collection). Every call site is reviewed and named in the
    /// PR; do not use it to silence a filter on anything an operator can reach.
    [[nodiscard]] static ResponseTierFilter unrestricted_internal_consumer() {
        return ResponseTierFilter{Key{}};
    }

    /// TRANSITIONAL (#4990 wave 1): the call sites that will take a `ForensicsVisibilityFn` pass this
    /// until it is wired. It produces the same no-clause filter as `exclude(set, nullopt)` and,
    /// where the plugin set has not been plumbed to the site (nullptr), the same. REMOVED when the
    /// surfaces are wired; do not add a new caller.
    [[nodiscard]] static ResponseTierFilter operator_surface_pending_wiring(
        const ForensicsPluginSet* plugins) {
        return plugins ? exclude(*plugins, std::nullopt) : ResponseTierFilter{Key{}};
    }

    // -- Accessors for response_store.cpp (the SQL builder); not a policy surface. -----------------

    /// True when a SQL clause is needed: the filter excludes plugins for at least some agents.
    [[nodiscard]] bool restricts() const noexcept { return !excluded_.empty(); }
    /// Lowercase plugin names to exclude (empty iff `!restricts()`).
    [[nodiscard]] const std::vector<std::string>& excluded_plugins() const noexcept { return excluded_; }
    /// Sorted agent ids whose Forensics rows are still readable; empty = none.
    [[nodiscard]] const std::vector<std::string>& exempt_agents() const noexcept { return exempt_agents_; }

private:
    struct Key {};
    explicit ResponseTierFilter(Key) {}

    std::vector<std::string> excluded_;
    std::vector<std::string> exempt_agents_;
};

} // namespace yuzu::server
