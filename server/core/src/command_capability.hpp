#pragma once

#include <array>
#include <cstdint>
#include <expected>
#include <initializer_list>
#include <span>
#include <stdexcept>
#include <string_view>

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
/// `capability_decls/` (this package owns only the four system-initiated
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
};

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
    static constexpr std::size_t kMaxSources = 24;

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
    /// `classify("TAR", "Fleet_Snapshot")` and `classify("tar",
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

private:
    [[nodiscard]] static constexpr char to_lower_ascii(char c) noexcept {
        return (c >= 'A' && c <= 'Z') ? static_cast<char>(c - 'A' + 'a') : c;
    }

    [[nodiscard]] static bool ci_equal(std::string_view a, std::string_view b) noexcept {
        if (a.size() != b.size())
            return false;
        for (std::size_t i = 0; i < a.size(); ++i) {
            if (to_lower_ascii(a[i]) != to_lower_ascii(b[i]))
                return false;
        }
        return true;
    }

    std::array<std::span<const CommandCapability>, kMaxSources> sources_{};
    std::size_t source_count_{0};
};

} // namespace yuzu::server
