#pragma once

#include "runtime_config_store.hpp"

#include <nlohmann/json.hpp>

#include <vector>

/// Response shapes for the runtime-config REST surface.
///
/// Separate from the store because a SQLite persistence class has no business
/// producing a wire body, and because putting `nlohmann/json.hpp` in the store's
/// header pulled ~25k lines into every TU that includes it -- including
/// `audit_store.cpp`, which wanted a secret-key predicate and nothing else.
namespace yuzu::server {

/// The `overrides` object of `GET /api/config`, built from `RuntimeConfigStore::get_all()`.
///
/// A secret's `value` is OMITTED and replaced by `is_set`, NOT placeholdered: the
/// placeholder is itself a legal value, so a config-as-code or backup-restore client
/// reading it and writing it back would silently set the literal string as the
/// credential. `updated_by`/`updated_at` are kept for both kinds, so an operator can
/// still see that a secret is set and who set it.
///
/// Safe under EITHER input: it omits a secret's value whether it was handed redacted
/// or plaintext entries (`is_secret_key()` decides, not whether the caller already
/// redacted), so a future caller building a `RuntimeConfigEntry` list some OTHER way
/// still does not leak through this function. That is deliberate -- do not
/// "simplify" it into trusting the caller to have redacted first.
///
/// `is_set` is derived from a non-empty value, which is why `get_all()` leaves an
/// EMPTY secret empty rather than placeholdering it.
nlohmann::json build_overrides_json(const std::vector<RuntimeConfigEntry>& entries);

} // namespace yuzu::server
