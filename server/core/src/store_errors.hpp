#pragma once

#include <spdlog/spdlog.h>

#include <string>
#include <string_view>

namespace yuzu::server {

// Shared error-message prefix that store-layer methods use to signal
// duplicate-resource conflicts (#396, #399, #402, governance Gate 3 arch-B1).
//
// Routes that call create_* on a store check the returned error string with
// `error.rfind(kConflictPrefix, 0) == 0` and map matches to HTTP 409 instead
// of the default 400. The constant lives in one place so a typo on either
// side is a compile error rather than a silent 409→400 downgrade.
//
// New duplicate-class error sites MUST format as:
//   std::string(kConflictPrefix) + " <human-readable detail>"
//
// Routes returning JSON should strip the prefix before placing the message
// in the response body — see strip_conflict_prefix() below.
inline constexpr std::string_view kConflictPrefix = "conflict:";

// Strip the kConflictPrefix (and the single space that follows it in the
// canonical form) from an error string for inclusion in operator-facing
// error responses. Returns the input unchanged if the prefix is absent.
inline std::string_view strip_conflict_prefix(std::string_view msg) {
    if (msg.rfind(kConflictPrefix, 0) != 0)
        return msg;
    auto rest = msg.substr(kConflictPrefix.size());
    while (!rest.empty() && rest.front() == ' ')
        rest.remove_prefix(1);
    return rest;
}

inline bool is_conflict_error(std::string_view msg) {
    return msg.rfind(kConflictPrefix, 0) == 0;
}

// Shared kind-validation wording (#753) so operators see one message
// regardless of which store rejected their YAML. These are 400s, not
// 409s — do NOT route them through kConflictPrefix.
//
// kind_mismatch_error() covers "kind" present but wrong; kind_missing_error()
// covers "kind" absent entirely — a missing kind is not a mismatch, so it
// gets its own honest verb rather than being force-fitted into the
// mismatch string.
//
// Byte-exact outputs (verify any change against these before committing):
//   kind_mismatch_error("X", "Y") ==
//     "kind must be 'X', got 'Y'. yaml_source must be a complete YAML "
//     "document including 'apiVersion: yuzu.io/v1alpha1' and 'kind: X'."
//   kind_mismatch_error("X", "Y", example) appends " Example:\n" + example
//   kind_mismatch_error("X", "Y", example, docs_ref) further appends
//     "See " + docs_ref + "."
//   kind_missing_error() ==
//     "kind is required. yaml_source must be a complete YAML document "
//     "including 'apiVersion: yuzu.io/v1alpha1' and a 'kind:' field."
inline std::string kind_mismatch_error(std::string_view expected, std::string_view actual,
                                        std::string_view example = {},
                                        std::string_view docs_ref = {}) {
    std::string msg = "kind must be '";
    msg += expected;
    msg += "', got '";
    msg += actual;
    msg += "'. yaml_source must be a complete YAML document including "
           "'apiVersion: yuzu.io/v1alpha1' and 'kind: ";
    msg += expected;
    msg += "'.";
    if (!example.empty()) {
        msg += " Example:\n";
        msg += example;
    }
    if (!docs_ref.empty()) {
        msg += "See ";
        msg += docs_ref;
        msg += ".";
    }
    return msg;
}

inline std::string kind_missing_error() {
    return "kind is required. yaml_source must be a complete YAML document "
           "including 'apiVersion: yuzu.io/v1alpha1' and a 'kind:' field.";
}

// Shared error-message prefix that migrated-store methods use to signal a genuine DB/lease
// failure, distinct from not-found/validation (ADR-0036 typed-read policy; governance Gate 3
// architect finding). Each store previously defined its own independent
// `"db_error: "` literal (`kInstructionStoreDbErrorPrefix`, `kProductPackDbErrorPrefix`) —
// coupled only by string-equality convention, not by type, so a future store adopting a
// differently-spelled prefix would silently fall into a caller's "tolerated" branch instead
// of its "genuine failure, abort" branch (the exact class of bug found in
// `ProductPackStore::uninstall`'s `ItemUninstallFn` classification). New migrated stores
// should reference `kDbErrorPrefix` directly rather than minting their own literal.
inline constexpr std::string_view kDbErrorPrefix = "db_error: ";

// Named `is_generic_db_error` (not `is_db_error`) because `policy_store.hpp` — landed via
// this branch's merge with origin/dev's independent PolicyStore migration, ADR-0056 —
// already defines its own `is_db_error(std::string_view)` against its own
// `kPolicyDbErrorPrefix` in this same namespace; that name was taken before this helper was
// written, so a second free function of the identical name is an ODR violation the moment
// both headers reach one translation unit (workflow_routes.cpp, server.cpp,
// compliance_routes.cpp, mcp_server.cpp, policy_evaluator.cpp all do). Not unified with
// PolicyStore's copy here — that would mean editing another store's already-merged
// migration from this one's scope.
inline bool is_generic_db_error(std::string_view msg) {
    return msg.starts_with(kDbErrorPrefix);
}

// Governance Gate 2/3/4/6 (SEC-1/ARCH-1/Finding-B/CO-1, InstructionStore PG migration): three
// independent call sites let a kDbErrorPrefix error — raw PQerrorMessage() text, which can
// carry connection/schema detail, occasionally host:port — reach a client response body or a
// persisted audit row verbatim instead of being genericized, because each site re-derived its
// own ad hoc check rather than sharing one. Mirrors the already-correct
// product_pack_client_message()/sw_deploy_client_message() shape (rest_api_v1.cpp,
// workflow_routes.cpp) — this is that same pattern promoted here so a fourth call site reaches
// for it instead of re-deriving a fourth ad hoc check. A not_found/conflict/validation error
// (never carries the prefix) is safe to echo verbatim — it's operator-authored request
// feedback, not database internals.
inline std::string genericize_db_error(std::string_view op, const std::string& err) {
    if (is_generic_db_error(err)) {
        spdlog::error("{}: {}", op, err);
        return "service unavailable";
    }
    return err;
}

} // namespace yuzu::server
