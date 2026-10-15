#pragma once

/// @file name_lookup_memo.hpp
/// One render's definition-id -> display-name lookups, memoised, with a stop rule.
///
/// The Operate pages (Approvals, Executions) show an instruction's NAME where the
/// stored row carries only its `definition_id`. A page lists up to 100 rows but few
/// distinct definitions, and each `InstructionStore::get_definition` is a pool lease
/// bounded at 2 s, so:
///   * each distinct id is resolved at most once per render, and
///   * after the FIRST read failure no further lookup is attempted for this render
///     (a degraded store then costs one lease wait, not one per row); every id that
///     was not resolved falls back to the id itself.
///
/// Pure: the lookup is an injected `Resolver`, so the rule is testable with a counting
/// double and no database. Intended lifetime: one instance per render, never shared
/// across requests (it is not thread-safe, and a cached failure must not outlive the
/// render that saw it).

#include <expected>
#include <functional>
#include <optional>
#include <string>
#include <unordered_map>
#include <utility>

namespace yuzu::server::operate_pages {

class NameLookupMemo {
public:
    /// The shape of `InstructionStore::get_definition`: a name (found), `nullopt` (a
    /// successful read that found none), or `unexpected` (a genuine read failure).
    /// An empty name is treated as not found.
    using Resolver =
        std::function<std::expected<std::optional<std::string>, std::string>(const std::string&)>;

    /// An empty `Resolver` resolves nothing: every label is the id (no store wired).
    explicit NameLookupMemo(Resolver resolve = {}) : resolve_(std::move(resolve)) {}

    /// The display name for `id`, else `id` itself. Never empty unless `id` is.
    [[nodiscard]] std::string label(const std::string& id) {
        if (id.empty() || !resolve_)
            return id;
        if (const auto it = memo_.find(id); it != memo_.end())
            return it->second;
        std::string out = id;
        if (!failed_) {
            if (auto r = resolve_(id); !r)
                failed_ = true; // stop: the rest of this render uses ids
            else if (*r && !(*r)->empty())
                out = **r;
        }
        // Cache the outcome whatever it was, so a failing id is not retried per row.
        memo_.emplace(id, out);
        return out;
    }

    /// True once a lookup failed (callers may surface a hint; the labels already fell
    /// back to ids).
    [[nodiscard]] bool failed() const noexcept { return failed_; }

private:
    Resolver resolve_;
    std::unordered_map<std::string, std::string> memo_;
    bool failed_{false};
};

/// The resolver over `InstructionStore::get_definition` (templated so this header stays
/// store-free). Empty -- every label is the id -- when no store is wired or it is not open.
template <class Store>
[[nodiscard]] NameLookupMemo::Resolver instruction_name_resolver(Store* store) {
    if (!store || !store->is_open())
        return {};
    return [store](const std::string& id)
               -> std::expected<std::optional<std::string>, std::string> {
        auto def = store->get_definition(id);
        if (!def)
            return std::unexpected(def.error());
        if (!*def)
            return std::optional<std::string>{};
        return std::optional<std::string>{(*def)->name};
    };
}

} // namespace yuzu::server::operate_pages
