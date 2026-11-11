#pragma once

/// @file instruction_referrers.hpp
/// "What still points at this instruction definition?" for the delete twins (#2146 batch C,
/// UP-6): `DELETE /api/v1/instructions/{id}` and MCP `delete_definition`. A definition that other
/// things name by id is not deleted out from under them: a schedule skips as `definition_unknown`,
/// a policy fragment's check/fix resolve to nothing so verdicts stop maturing while the last status
/// still displays, a workflow step cannot dispatch. Both transports take ONE `DefinitionReferrersFn`
/// (built once, `make_definition_referrers_fn`, wired in server.cpp) and format the refusal with
/// ONE function (`describe_definition_referrers`), so the two cannot disagree about what blocks a
/// delete or how it reads.
///
/// FAIL CLOSED. A referrer source that cannot answer (store closed, pool exhausted, query error)
/// makes the whole lookup an error, and the caller answers a retryable 503 and deletes nothing;
/// an unwired function is the same. "Could not look" is never "no referrers".
///
/// What it covers: schedules, workflows (live ones), policy fragments (check, fix or post-check).
/// What it does NOT cover, on purpose or for want of a cheap read: device tokens scoped to a
/// definition (moot today: the store is not wired live), past execution/response history (which
/// keeps its recorded definition id), and instruction-set membership (the store unlinks that
/// itself). Product-pack item records are ADVISORY, not a referrer: `DefinitionPackAdvisoryFn`
/// below names the packs that contain the definition in the delete's audit detail and never
/// blocks. The v1 `DELETE /api/v1/instructions/{id}` and MCP `delete_definition` take the same
/// `DefinitionReferrersFn`.

#include <concepts>
#include <cstddef>
#include <expected>
#include <functional>
#include <string>
#include <type_traits>
#include <unordered_set>
#include <utility>
#include <vector>

namespace yuzu::server {

class PolicyStore;
class ProductPackStore;
class ScheduleEngine;
class WorkflowEngine;

/// The most policies a pack-uninstall refusal names per held fragment; the rest are counted
/// (`+N`). The uninstall handler reads one policy more than this per fragment, so `N` is a LOWER
/// BOUND (it never exceeds 1): it says "at least one more", not how many.
inline constexpr std::size_t kMaxHeldByPoliciesNamed = 3;

/// A policy that uses a pack-own policy fragment. The refusal names it `<id> (<name>)`: the id is
/// what the delete route takes, the name is what the operator recognises.
struct HeldByPolicy {
    std::string id;
    std::string name; ///< may be empty (then only the id is named)
};

struct DefinitionReferrer {
    std::string kind; ///< "schedule", "workflow" or "policy fragment"
    std::string id;
    /// Set only for a policy fragment that policies still use, when the lookup was given
    /// exclusions (below): the policies that use it, which is why it is still a referrer. Empty
    /// everywhere else.
    std::vector<HeldByPolicy> held_by{};
};

/// Items the lookup must NOT count, applied INSIDE each source's capped query so an excluded row
/// never takes a slot of the per-source window (a filter applied after the cap would let a pack's
/// own rows fill the window and hide a foreign referrer). A caller that removes related rows in
/// the same operation passes the workflow ids and policy fragment ids it is about to remove; the
/// v1 and MCP deletes pass none.
struct DefinitionReferrerExclusions {
    std::unordered_set<std::string> workflow_ids;
    std::unordered_set<std::string> fragment_ids;
};

/// Every referrer of `definition_id`, or the reason the question could not be answered (a fixed
/// internal text: the caller does not echo it). An empty vector means "looked, nothing found".
/// ONE closure, two call forms: `fn(id)` counts everything; `fn(id, exclusions)` leaves the named
/// workflows and policy fragments out. It can be built from a callable taking just the id (the
/// exclusions are then ignored) or from one taking both.
class DefinitionReferrersFn {
public:
    using Result = std::expected<std::vector<DefinitionReferrer>, std::string>;
    using Exclusions = DefinitionReferrerExclusions;

    DefinitionReferrersFn() = default;
    DefinitionReferrersFn(std::nullptr_t) {}
    template <class F>
        requires(!std::same_as<std::remove_cvref_t<F>, DefinitionReferrersFn> &&
                 std::is_invocable_r_v<Result, F&, const std::string&, const Exclusions&>)
    DefinitionReferrersFn(F f) {
        // An empty callable (null function pointer, empty std::function) stays an EMPTY fn_, so
        // `explicit operator bool` keeps reporting "unwired" instead of a wrapper that throws.
        // Not `static_cast<bool>(f)`: on a captureless lambda that is the function-pointer
        // conversion, always true, and g++ warns (-Waddress) on every such lambda.
        if constexpr (std::is_pointer_v<F>) {
            if (f == nullptr)
                return;
        } else if constexpr (requires { f.operator bool(); }) {
            if (!f.operator bool())
                return;
        }
        fn_ = std::move(f);
    }
    template <class F>
        requires(!std::same_as<std::remove_cvref_t<F>, DefinitionReferrersFn> &&
                 !std::is_invocable_r_v<Result, F&, const std::string&, const Exclusions&> &&
                 std::is_invocable_r_v<Result, F&, const std::string&>)
    DefinitionReferrersFn(F f) {
        // Same empty-callable guard as the two-argument constructor above.
        if constexpr (std::is_pointer_v<F>) {
            if (f == nullptr)
                return;
        } else if constexpr (requires { f.operator bool(); }) {
            if (!f.operator bool())
                return;
        }
        fn_ = [g = std::move(f)](const std::string& id, const Exclusions&) mutable -> Result {
            return g(id);
        };
    }

    explicit operator bool() const noexcept { return static_cast<bool>(fn_); }
    [[nodiscard]] Result operator()(const std::string& definition_id) const {
        return fn_(definition_id, Exclusions{});
    }
    [[nodiscard]] Result operator()(const std::string& definition_id,
                                    const Exclusions& exclusions) const {
        return fn_(definition_id, exclusions);
    }

private:
    std::function<Result(const std::string&, const Exclusions&)> fn_;
};

/// The most referrers a refusal names; the rest are counted ("and N more").
inline constexpr std::size_t kMaxReferrersListed = 20;

/// Builds the one lookup over the real stores. A null or closed source makes the lookup an error
/// (fail closed), so wire exactly the stores the build has. Each source is asked for at most
/// `kMaxReferrersListed + 1` rows (after any exclusions): enough to know the list is longer than
/// it shows.
[[nodiscard]] DefinitionReferrersFn make_definition_referrers_fn(ScheduleEngine* schedules,
                                                                 WorkflowEngine* workflows,
                                                                 PolicyStore* policies);

/// The ids of the installed product packs that contain `definition_id`, or the reason the read
/// failed. ADVISORY: every caller treats an error, an unwired function and an empty list alike,
/// as "nothing to note" and carries on with the delete; it is never a `kReferenced` source.
using DefinitionPackAdvisoryFn = std::function<std::expected<std::vector<std::string>, std::string>(
    const std::string& definition_id)>;

/// The most pack ids `pack_advisory_note` names; the rest are counted (`+N`).
inline constexpr std::size_t kMaxPacksNoted = 5;

/// Builds the advisory lookup over the real pack store. A null store is an error result (the
/// caller drops it), and a failing read is logged once a minute, never counted in a metric.
[[nodiscard]] DefinitionPackAdvisoryFn make_definition_pack_advisory_fn(ProductPackStore* packs);

/// The audit-detail fragment `packs=<id>,<id>,...[,+N]` for `definition_id` (at most
/// `kMaxPacksNoted` ids, each folded through `log_token`, CWE-117), or an empty string when `fn` is
/// unwired, the read failed, or no pack contains the definition. NEVER throws and never changes a
/// delete's outcome. The three call sites read it BEFORE the delete (so a failed read cannot lose
/// the outcome row) and append it to the success detail only if the delete then succeeds. `N` is a
/// lower bound (the lookup itself is capped).
[[nodiscard]] std::string pack_advisory_note(const DefinitionPackAdvisoryFn& fn,
                                             const std::string& definition_id);

/// The 409 / conflict message for a non-empty `referrers`: how many things reference the
/// definition, the first `kMaxReferrersListed` as `<kind> <id>` (each id bounded and folded
/// through `log_token`, CWE-117), then "and N more" for the rest, then how to unlink. `N` counts
/// what the sources returned, so it is a lower bound when a source was itself capped.
[[nodiscard]] std::string describe_definition_referrers(const std::vector<DefinitionReferrer>& referrers);

} // namespace yuzu::server
