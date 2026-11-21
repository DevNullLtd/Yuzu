#pragma once

#include <array>
#include <cstdint>
#include <expected>
#include <initializer_list>
#include <span>
#include <algorithm>
#include <stdexcept>
#include <string>
#include <string_view>
#include <unordered_map>
#include <vector>
#include "ascii_fold.hpp" // #4990: the one ASCII plugin-name fold

#include "authz_model.hpp"

/// @file command_capability.hpp
/// PR1.9a: the core-owned command capability CLASSIFICATION — the seam
/// `ServerImpl::dispatch_confined` (and every other dispatch chokepoint) will
/// eventually consult to decide a `plugin.action` pair's `DispatchClass` /
/// `Mutability` before it ever reaches an agent. Header-only, zero
/// `server.cpp` involvement: this file defines the vocabulary and the pure
/// lookup, nothing wires it into a live dispatch path yet.
///
/// WHAT THIS IS NOT: a place that DECLARES `plugin.action` rows. The real
/// catalogue ships as several per-group fragment headers under
/// `capability_decls/` (this package owns only the five system-initiated
/// ones — see `capability_decls/core_dispatch_capabilities.hpp`); every other
/// plugin's rows are authored elsewhere and injected into a
/// `CommandCapabilityRegistry` instance at composition time. This header
/// never aggregates them itself — no file-scope singleton, no global
/// registry instance — so a future composition point picks exactly which
/// fragments it wants classified.
namespace yuzu::server {

/// Whether a dispatch reads or changes device state. Deliberately NOT
/// inferred from `authz::Operation` (ADR-0033 §1: "the one typing that must
/// not be self-certified") — a fragment's author sets this explicitly per
/// row.
enum class DispatchClass : uint8_t {
    ReadOnly,
    Mutating,
    Destructive,
};

/// Whether a mutating dispatch can be undone by a subsequent dispatch of the
/// same or a compensating action. `None` pairs with `DispatchClass::ReadOnly`
/// in every seeded row; a `Mutating`/`Destructive` row is `Reversible` or
/// `Irreversible` depending on the actual device-side effect, never inferred
/// from `DispatchClass` alone.
enum class Mutability : uint8_t {
    None,
    Reversible,
    Irreversible,
};

/// Whether raw dispatch of this pair requires proof of an approval decision
/// beyond the base RBAC grant (#1398 — `InstructionDefinition`-declared
/// `approval.mode` was enforced only on the governed `POST
/// /api/instructions/:id/execute` path; this is the same control, derived
/// strictest-wins from every shipped definition targeting the pair, applied
/// at the ONE chokepoint every dispatch surface — REST, MCP, dashboard,
/// schedule, deployment — already funnels through). Approval-class-shaped,
/// deliberately NOT role-shaped: this enum never names a role, matching the
/// `CapabilityDeclaration` doctrine (`authz_model.hpp`: "this schema
/// classifies a capability, it never grants one").
///
/// `Unspecified` is the value-initialized default for an omitted
/// `.execute_gate` designated initializer — deliberately NOT `None`, so a
/// future row that forgets to author this field cannot be silently mistaken
/// for an authored "no gate" decision. Two independent enforcement layers
/// keep `Unspecified` from ever reaching a live dispatch decision: (1) every
/// `capability_decls/*.hpp` fragment's own `constexpr` array is swept by a
/// `static_assert(detail::all_gates_specified(...))` immediately after its
/// definition — a build with an omitted field fails to compile; (2) the
/// dispatch chokepoint (`classify_and_authorize_dispatch`,
/// `agent_registry.hpp`) treats `Unspecified` as a classify-miss (deny, same
/// as `Unclassified`/`Ambiguous`) as defense in depth, in case a future
/// fragment source is composed into the registry without its own sweep.
enum class ExecuteGate : uint8_t {
    Unspecified,
    None,
    AdminOrApproval,
    AlwaysApproval,
};

/// One classified `plugin.action` row — view/enum over static storage only,
/// so a `std::span<const CommandCapability>` fragment can live in a
/// `constexpr` array with no static-init-order or heap concern.
struct CommandCapability {
    std::string_view plugin;
    std::string_view action;
    DispatchClass dispatch_class;
    Mutability mutability;
    /// Reuses an existing `RbacStore` securable type (see `rbac_store.cpp`'s
    /// `seed_defaults()` `types[]`) — this struct never mints a new one.
    std::string_view securable;
    authz::Operation operation;
    authz::RiskTier risk_tier;
    /// True for a dispatch the server issues to itself (never a
    /// caller-attributable RBAC decision) — see
    /// `capability_decls/core_dispatch_capabilities.hpp`.
    bool system_reserved{false};
    /// See `ExecuteGate`'s doc comment above. No default member initializer
    /// distinct from `Unspecified` — an omitted `.execute_gate` in a
    /// designated-initializer row value-initializes to `Unspecified` (the
    /// zero enumerator), which every fragment's compile-time sweep rejects.
    ExecuteGate execute_gate{ExecuteGate::Unspecified};
    /// OPTIONAL parameter-dependent securable (sg10). When BOTH are non-empty and the dispatch's
    /// parameters carry a NON-EMPTY value under `param_escalation_key`, the RBAC check (and the
    /// securable reported on a denial and on the returned row) uses `param_escalation_securable`
    /// instead of `securable`. Empty (the default) = the row's securable is the only one. Today
    /// only `windows_updates.patch_connectivity` (a caller-supplied `targets` probe is an
    /// `Infrastructure` read, the built-in default targets stay `SoftwareDeployment`). Evaluated
    /// ONLY where the parameters are passed to `classify_and_authorize_dispatch`
    /// (`ServerImpl::build_classified_command`, the one send path).
    std::string_view param_escalation_key{};
    std::string_view param_escalation_securable{};
};

/// The ONE well-formedness rule for dispatch parameters (sg10, UP-1). A parameter KEY must hold no
/// byte below 0x20 and no 0x7F and be valid UTF-8; a VALUE must hold no NUL. The agent hands every
/// key to a plugin as a C string and the SDK compares C strings, so a key `targets\0x` is read by
/// the plugin as `targets` while a server-side exact `find("targets")` misses it: a gate keyed on a
/// parameter name would be silently bypassed. Rejecting (never truncating) such a key at the listed
/// ingress surfaces (see `check_params_key_shape`'s list in dispatch_target_shape.hpp) and at the chokepoint closes that split; a path with no ingress check is refused at the chokepoint as a Forbidden denial. EXTEND this function; never fork a second one.
[[nodiscard]] inline bool parameter_key_well_formed(std::string_view key) noexcept {
    std::size_t i = 0;
    const std::size_t n = key.size();
    while (i < n) {
        const auto c = static_cast<unsigned char>(key[i]);
        if (c < 0x20 || c == 0x7F)
            return false;
        std::size_t len = 1;
        if (c >= 0x80) {
            if (c >= 0xC2 && c <= 0xDF)
                len = 2;
            else if (c >= 0xE0 && c <= 0xEF)
                len = 3;
            else if (c >= 0xF0 && c <= 0xF4)
                len = 4;
            else
                return false;
            if (i + len > n)
                return false;
            for (std::size_t k = 1; k < len; ++k)
                if ((static_cast<unsigned char>(key[i + k]) & 0xC0) != 0x80)
                    return false;
            const auto c1 = static_cast<unsigned char>(key[i + 1]);
            if ((c == 0xE0 && c1 < 0xA0) || (c == 0xED && c1 > 0x9F) ||
                (c == 0xF0 && c1 < 0x90) || (c == 0xF4 && c1 > 0x8F))
                return false;
        }
        i += len;
    }
    return true;
}

[[nodiscard]] inline bool
parameters_well_formed(const std::unordered_map<std::string, std::string>& parameters) noexcept {
    for (const auto& [k, v] : parameters) {
        if (!parameter_key_well_formed(k) || v.find('\0') != std::string::npos)
            return false;
    }
    return true;
}

/// The ONE rule for a row's parameter-dependent securable (sg10). Returns
/// `param_escalation_securable` when the row declares an escalation AND `parameters` carries a
/// NON-EMPTY value (whitespace counts as non-empty, a non-string value arrives already stringified
/// by the caller's decoder) under `param_escalation_key`; otherwise the row's own `securable`.
/// `parameters == nullptr` = the caller cannot know them: the row's own securable (the escalation
/// is then NOT evaluated). Used by BOTH `classify_and_authorize_dispatch` (send) and
/// `schedule_arming_permitted` (schedule/outbox arming) so the two can never judge a dispatch
/// under different securables.
[[nodiscard]] inline std::string_view
effective_securable(const CommandCapability& cap,
                    const std::unordered_map<std::string, std::string>* parameters) {
    if (parameters != nullptr && !cap.param_escalation_key.empty() &&
        !cap.param_escalation_securable.empty()) {
        // A malformed parameter set is never truncated or ignored: it is judged under the
        // escalated (stricter) securable, and the callers additionally DENY it outright
        // (`parameters_well_formed`).
        if (!parameters_well_formed(*parameters))
            return cap.param_escalation_securable;
        if (const auto it = parameters->find(std::string(cap.param_escalation_key));
            it != parameters->end() && !it->second.empty())
            return cap.param_escalation_securable;
    }
    return cap.securable;
}

namespace detail {
/// The per-fragment compile-time sweep every `capability_decls/*.hpp` file
/// must invoke via `static_assert` immediately after its `constexpr` array —
/// see `ExecuteGate`'s doc comment above. `std::span`'s constructor from a
/// contiguous constexpr range is itself constexpr (C++20), so this is a
/// genuine compile-time check, not a runtime one that merely looks like it.
[[nodiscard]] inline consteval bool
all_gates_specified(std::span<const CommandCapability> rows) {
    for (const auto& row : rows) {
        if (row.execute_gate == ExecuteGate::Unspecified)
            return false;
        // sg10: `param_escalation_key` and `param_escalation_securable` are set together or not at
        // all; half a pair would silently disable `effective_securable`'s escalation.
        if (row.param_escalation_key.empty() != row.param_escalation_securable.empty())
            return false;
    }
    return true;
}
} // namespace detail

/// `CommandCapabilityRegistry::classify`'s failure modes. A miss is
/// `Unclassified`, never a permissive default (ADR-0033 §2: "a missing or
/// unparseable classification means the capability does not exist"). Two
/// fragments independently declaring the same `plugin.action` is
/// `Ambiguous`, never first-wins — a silent first-wins would let whichever
/// fragment header happens to be listed first in the composing
/// `initializer_list` win over a conflicting, equally-valid declaration
/// elsewhere, exactly the kind of un-auditable outcome ADR-0033 §2 rules
/// out.
enum class ClassificationError : uint8_t {
    Unclassified,
    Ambiguous,
};

/// Composes SEVERAL independently-authored `CommandCapability` fragments
/// (the catalogue ships as multiple per-group `capability_decls/*.hpp`
/// headers) into one lookup surface. Constructed once from an
/// `initializer_list` of spans — never a file-scope singleton, so the
/// composition point (not this header) decides which fragments are live.
///
/// `classify` is `const noexcept` and performs no heap allocation: every
/// span it holds is a view over fragment-owned static storage, and the
/// case-insensitive comparison it runs is a plain byte loop, never a
/// `std::string` materialization.
class CommandCapabilityRegistry {
public:
    /// A handful of fragments compose here (five per-group headers plus this
    /// package's own `core_dispatch_capabilities()`); `kMaxSources` is a
    /// generous ceiling, not a tight fit, so an additional fragment group
    /// does not silently overflow it. Exceeding it is a construction-time
    /// programmer error — fail loud via an exception, never silently drop a
    /// fragment (a dropped fragment would make every one of its rows
    /// `Unclassified`, indistinguishable from an honest miss).
    /// Raised 16 to 24 across the Wave 8/10 merge cascade: firmware_posture
    /// (#4719), browser_inventory (#4729) and app_control each ship their own
    /// fragment file and landed via overlapping PRs, so #4719 and #4729 each
    /// independently observed 17 live sources without accounting for the
    /// other's addition. Composing all three lands the true count at 18 — the
    /// prior value (16) was already at capacity with zero headroom, contrary
    /// to its own "generous, not a tight fit" contract. 24 gives room for
    /// several more individually-fragmented plugins before this needs raising
    /// again.
    /// Raised 24 to 32 (2026-09-28): the same overlapping-PR pattern repeated
    /// — privacy_permissions (#5064) and local_security_policy each ship
    /// their own fragment file and landed via independent PRs off the same
    /// dev tip, so composing both lands the true count at 25, one over the
    /// prior ceiling with zero headroom. 32 restores real headroom rather
    /// than bumping to the bare minimum again.
    /// Raised 32 to 48 (2026-11-17): dev already composed exactly 32 sources, so
    /// the ceiling had zero headroom again, and process_introspect's fragment
    /// made the 33rd. The constructor threw and the server could not start. No
    /// compile caught it, because an overflow is a runtime throw. It surfaced
    /// only on the first Linux server run of that change (the server is Linux-only,
    /// ADR-0035). 48 restores real headroom, and capability_fragments.hpp now
    /// static_asserts that the production composition leaves at least two slots
    /// free, so a composition of 47 or more sources (for example two overlapping
    /// PRs off one dev tip, the pattern behind both earlier raises) fails the
    /// build before it can fail a boot.
    static constexpr std::size_t kMaxSources = 48;

    explicit CommandCapabilityRegistry(
        std::initializer_list<std::span<const CommandCapability>> sources) {
        if (sources.size() > kMaxSources) {
            throw std::invalid_argument(
                "CommandCapabilityRegistry: too many capability sources (raise kMaxSources)");
        }
        for (auto src : sources) {
            sources_[source_count_++] = src;
        }
    }

    /// Case-insensitive on both `plugin` and `action`, matching the
    /// lowercase normalisation `server.cpp` (`:6360-6368`) applies to the
    /// action before dispatch — extended here to the plugin half too, so
    /// `classify("Echo", "Fleet_Snapshot")` and `classify("echo",
    /// "fleet_snapshot")` resolve to the same row regardless of which case a
    /// caller used.
    [[nodiscard]] std::expected<CommandCapability, ClassificationError>
    classify(std::string_view plugin, std::string_view action) const noexcept {
        const CommandCapability* found = nullptr;
        for (std::size_t i = 0; i < source_count_; ++i) {
            for (const auto& cap : sources_[i]) {
                if (ci_equal(cap.plugin, plugin) && ci_equal(cap.action, action)) {
                    if (found != nullptr) {
                        // A second, independent match for the same
                        // plugin.action — never silently first-wins.
                        return std::unexpected(ClassificationError::Ambiguous);
                    }
                    found = &cap;
                }
            }
        }
        if (found == nullptr) {
            return std::unexpected(ClassificationError::Unclassified);
        }
        return *found;
    }

    /// True when any row of the composed catalogue names `plugin` (case-insensitive). The one
    /// "is this a plugin the server dispatches" lookup: callers validate against it rather than
    /// keep a list of their own.
    [[nodiscard]] bool knows_plugin(std::string_view plugin) const noexcept {
        for (std::size_t i = 0; i < source_count_; ++i) {
            for (const auto& cap : sources_[i]) {
                if (ci_equal(cap.plugin, plugin))
                    return true;
            }
        }
        return false;
    }

    /// Calls `f(const CommandCapability&)` for every row of every composed source (boot-time and
    /// test use; a handful of fragments). Lets a consistency check read the catalogue without
    /// the registry growing one accessor per question.
    template <class F>
    void for_each_row(F&& f) const {
        for (std::size_t i = 0; i < source_count_; ++i)
            for (const auto& cap : sources_[i])
                f(cap);
    }

    /// Every distinct plugin name carrying at least one row whose `securable` equals `securable`,
    /// lowercased and sorted. Derived from the composed sources on each call (a handful of
    /// fragments, boot-time use), so a new fragment row is reflected with no second list to keep.
    /// A plugin is reported if ANY of its rows is on the securable: a mixed-tier plugin is
    /// therefore over-inclusive by design (the store records only the plugin, not the action).
    [[nodiscard]] std::vector<std::string> plugins_on_securable(std::string_view securable) const {
        std::vector<std::string> out;
        for (std::size_t i = 0; i < source_count_; ++i) {
            for (const auto& cap : sources_[i]) {
                if (cap.securable != securable)
                    continue;
                out.push_back(ascii_lower(cap.plugin));
            }
        }
        std::ranges::sort(out);
        out.erase(std::unique(out.begin(), out.end()), out.end());
        return out;
    }

private:
    [[nodiscard]] static bool ci_equal(std::string_view a, std::string_view b) noexcept {
        if (a.size() != b.size())
            return false;
        for (std::size_t i = 0; i < a.size(); ++i) {
            if (ascii_lower_char(a[i]) != ascii_lower_char(b[i]))
                return false;
        }
        return true;
    }

    std::array<std::span<const CommandCapability>, kMaxSources> sources_{};
    std::size_t source_count_{0};
};

} // namespace yuzu::server
