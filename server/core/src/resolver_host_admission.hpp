#pragma once

/// @file resolver_host_admission.hpp
/// Admission in front of the OIDC name lookup (`resolve_host_addresses_status` in
/// `oidc_provider.cpp`, POSIX builds): a limit on the lookups outstanding for one name, and a short
/// memory of names whose lookup was refused or timed out. Pure decision code: one mutex, no I/O,
/// no logging, an injectable monotonic clock, no thread. `bounded_resolver.hpp` is not touched, so
/// the process pool used by CRL source registration is not affected.
///
/// PER-NAME LIMIT. At most `kLookupPerNameLimit` (8) lookups for one name are outstanding at once,
/// and at most `kLookupMaxNames` (64) distinct names have one. A lookup beyond either is refused
/// without being started. A name is counted from `admit` until its lookup RETURNS, so a lookup
/// whose caller stopped waiting at the time bound still counts against its name:
///  - the count is held by a `Lease`, which the WORKER releases (`hold_lease_during` wraps the
///    lookup function), exactly once, on every path: the lookup returns, throws, is refused by the
///    pool, or its thread cannot be created;
///  - a name's table entry is erased when its count returns to 0, so the table holds only names
///    with a lookup outstanding;
///  - a name that cannot be keyed (empty, longer than 253 bytes, a control byte) shares ONE
///    sentinel key and so one limit like any other name: failing to key it never means it is
///    untracked;
///  - a refusal by the limit is not remembered: only a lookup that was actually run arms the
///    refusal memory below.
///
/// REFUSAL MEMORY. A name whose lookup ended `kBusy` or `kTimeout` is refused again, without
/// starting a lookup, for `kLookupRefusalTtl` (3 s). The memory holds at most
/// `kLookupRefusalMaxNames` (32) names; a new name at the cap replaces the entry that expires
/// first, and entries already past their expiry go first.
///  - Only a lookup that was actually run arms the memory (`note_outcome`). A refusal made by this
///    class never does.
///  - A refusal served from memory never changes the entry: the block ends `kLookupRefusalTtl`
///    after the lookup that armed it, however often the name is asked for meanwhile.
///  - `kOk` removes the entry. `kNotFound` and `kTemporary` are never remembered.
///  - A success is never cached: nothing here returns an address.
///  - A name that cannot be keyed is never remembered and never refused from memory (it is still
///    limited, above).
///
/// The NAT64 prefix probe (`ipv4only.arpa`) is exempt from both: the adapter does not call this
/// class for it, so it takes no lease, is never refused here and never feeds the memory; only the
/// pool's cap applies to it. That cap is the probe's only bound: the probe is not single-flight, so
/// stuck probe lookups are limited by the pool alone (open owner decision: its own small cap, or
/// single-flight).
///
/// The caller treats a refusal like any other refused lookup: the same `kBusy` status and the
/// same reason text as a full pool, so no caller learns a new failure kind. Nothing here returns an
/// address, so a refusal can never become a success.

// First, before the standard headers: on Windows bounded_resolver.hpp must see winsock2.h before any
// header that pulls in windows.h.
#include "bounded_resolver.hpp"

#include <chrono>
#include <cstddef>
#include <cstdint>
#include <functional>
#include <memory>
#include <mutex>
#include <string>
#include <string_view>
#include <unordered_map>
#include <utility>

namespace yuzu::server::net {

/// The most lookups outstanding for one name at once.
inline constexpr std::size_t kLookupPerNameLimit = 8;
/// The most distinct names with a lookup outstanding at once.
inline constexpr std::size_t kLookupMaxNames = 64;
/// How long a name whose lookup was refused or timed out is refused again.
inline constexpr std::chrono::seconds kLookupRefusalTtl{3};
/// The most names the refusal memory holds at once.
inline constexpr std::size_t kLookupRefusalMaxNames = 32;

class HostLookupAdmission : public std::enable_shared_from_this<HostLookupAdmission> {
public:
    using Clock = std::chrono::steady_clock;
    /// Must not call back into this object.
    using NowFn = std::function<Clock::time_point()>;

    struct Limits {
        std::size_t per_name_in_flight{kLookupPerNameLimit};
        std::size_t max_names_in_flight{kLookupMaxNames};
        Clock::duration refusal_ttl{kLookupRefusalTtl};
        /// A value below 1 is raised to 1: a memory that can hold nothing would still insert the
        /// entry it was asked to make.
        std::size_t max_refusal_entries{kLookupRefusalMaxNames};
    };

    enum class Verdict : std::uint8_t {
        kAdmitted,
        kRefusedRecent,    ///< the name's lookup was refused or timed out within the TTL
        kRefusedNameLimit, ///< the name already has `per_name_in_flight` lookups outstanding
        kRefusedTableFull, ///< `max_names_in_flight` other names have a lookup outstanding
        kRefusedError      ///< the check itself failed: refused, never admitted
    };

    /// One lookup's count against its name. Move-only; releases on destruction, and `release()` is
    /// idempotent. It keeps the admission object alive, so a worker that outlives the call (or a
    /// test object) can still release.
    class Lease {
    public:
        Lease() noexcept = default;
        Lease(Lease&& other) noexcept
            : owner_(std::move(other.owner_)), key_(std::move(other.key_)), active_(other.active_) {
            other.active_ = false;
        }
        Lease& operator=(Lease&& other) noexcept {
            if (this != &other) {
                release();
                owner_ = std::move(other.owner_);
                key_ = std::move(other.key_);
                active_ = other.active_;
                other.active_ = false;
            }
            return *this;
        }
        Lease(const Lease&) = delete;
        Lease& operator=(const Lease&) = delete;
        ~Lease() { release(); }

        void release() noexcept {
            if (!active_)
                return;
            active_ = false;
            const auto owner = std::move(owner_);
            owner->release_key(key_);
        }
        explicit operator bool() const noexcept { return active_; }

    private:
        friend class HostLookupAdmission;
        std::shared_ptr<HostLookupAdmission> owner_;
        std::string key_;
        bool active_{false}; ///< set only after the name's count was incremented
    };

    struct Admission {
        Verdict verdict{Verdict::kRefusedError};
        Lease lease; ///< holds a count only when `verdict == kAdmitted`
    };

    [[nodiscard]] static std::shared_ptr<HostLookupAdmission> create(Limits limits,
                                                                     NowFn now = &Clock::now) {
        return std::shared_ptr<HostLookupAdmission>(
            new HostLookupAdmission(limits, std::move(now)));
    }
    /// The documented limits and the real clock.
    [[nodiscard]] static std::shared_ptr<HostLookupAdmission> create() {
        return create(Limits{});
    }

    /// Whether a lookup for `host` may be started. On `kAdmitted` the lease holds one count for the
    /// name until it is released. Every lookup that reaches this class is checked against both the
    /// per-name limit and the refusal memory; the NAT64 probe never reaches it (see
    /// `resolve_host_addresses_status`).
    [[nodiscard]] Admission admit(std::string_view host) noexcept {
        try {
            const std::string key = normalise_key(host);
            const auto now = now_();
            std::lock_guard lock(mu_);
            if (key != unkeyed_name()) {
                if (const auto it = refused_until_.find(key); it != refused_until_.end()) {
                    if (now < it->second)
                        return {Verdict::kRefusedRecent, {}}; // the entry is left as it is
                    refused_until_.erase(it);
                }
            }
            const auto counted = in_flight_.find(key);
            const std::size_t count = counted == in_flight_.end() ? 0 : counted->second;
            if (count >= limits_.per_name_in_flight)
                return {Verdict::kRefusedNameLimit, {}};
            if (count == 0 && in_flight_.size() >= limits_.max_names_in_flight)
                return {Verdict::kRefusedTableFull, {}};
            Lease lease; // everything that can throw happens before the count moves
            lease.owner_ = shared_from_this();
            lease.key_ = key;
            ++in_flight_[key];
            lease.active_ = true;
            return {Verdict::kAdmitted, std::move(lease)};
        } catch (...) {
            return {Verdict::kRefusedError, {}};
        }
    }

    /// Feeds the status of a lookup that was actually run, never a refusal made by `admit`.
    /// `kBusy` and `kTimeout` arm the name (or re-arm it to now + TTL); `kOk` removes the entry;
    /// `kNotFound` and `kTemporary` change nothing.
    void note_outcome(std::string_view host, ResolveStatus status) noexcept {
        try {
            if (status != ResolveStatus::kBusy && status != ResolveStatus::kTimeout &&
                status != ResolveStatus::kOk)
                return;
            const std::string key = normalise_key(host);
            if (key == unkeyed_name())
                return;
            const auto now = now_();
            std::lock_guard lock(mu_);
            if (status == ResolveStatus::kOk) {
                refused_until_.erase(key);
                return;
            }
            if (refused_until_.find(key) == refused_until_.end() &&
                refused_until_.size() >= limits_.max_refusal_entries)
                make_room(now);
            refused_until_[key] = now + limits_.refusal_ttl;
        } catch (...) {
            // The memory is a mitigation: a failure to record leaves the name unremembered.
        }
    }

    /// Names currently remembered (expired ones not yet dropped included).
    [[nodiscard]] std::size_t refusal_entries() const {
        std::lock_guard lock(mu_);
        return refused_until_.size();
    }

    /// Lookups outstanding for `host` (counted from admission until the lookup returns).
    [[nodiscard]] std::size_t in_flight_for(std::string_view host) const {
        const std::string key = normalise_key(host);
        std::lock_guard lock(mu_);
        const auto it = in_flight_.find(key);
        return it == in_flight_.end() ? 0 : it->second;
    }

    /// Distinct names with a lookup outstanding.
    [[nodiscard]] std::size_t hosts_in_flight() const {
        std::lock_guard lock(mu_);
        return in_flight_.size();
    }

    [[nodiscard]] const Limits& limits() const noexcept { return limits_; }

private:
    HostLookupAdmission(Limits limits, NowFn now)
        : limits_(sanitised(limits)), now_(std::move(now)) {}

    static Limits sanitised(Limits limits) noexcept {
        if (limits.max_refusal_entries < 1)
            limits.max_refusal_entries = 1;
        return limits;
    }

    /// The key every name that cannot be keyed shares. It holds a NUL, which no vetted host has.
    static constexpr std::string_view unkeyed_name() noexcept {
        return std::string_view("\0unkeyed", 8);
    }

    /// ASCII-lowercase with one trailing '.' removed. A name that is empty after that, longer
    /// than 253 bytes or holding a byte <= 0x20 or 0x7f maps to `unkeyed_name()`.
    static std::string normalise_key(std::string_view host) {
        if (!host.empty() && host.back() == '.')
            host.remove_suffix(1);
        if (host.empty() || host.size() > 253)
            return std::string(unkeyed_name());
        std::string key(host);
        for (char& c : key) {
            const auto b = static_cast<unsigned char>(c);
            if (b <= 0x20 || b == 0x7f)
                return std::string(unkeyed_name());
            if (b >= 'A' && b <= 'Z')
                c = static_cast<char>(b - 'A' + 'a');
        }
        return key;
    }

    /// Called with `mu_` held when a new name would exceed the cap: drops the entries already
    /// past their expiry, and if the table is still full the one that expires first.
    void make_room(Clock::time_point now) {
        for (auto it = refused_until_.begin(); it != refused_until_.end();) {
            if (it->second <= now)
                it = refused_until_.erase(it);
            else
                ++it;
        }
        while (refused_until_.size() >= limits_.max_refusal_entries && !refused_until_.empty()) {
            auto earliest = refused_until_.begin();
            for (auto it = refused_until_.begin(); it != refused_until_.end(); ++it)
                if (it->second < earliest->second)
                    earliest = it;
            refused_until_.erase(earliest);
        }
    }

    /// Called by `Lease::release`. A failing mutex lock terminates, as for any std lock guard.
    void release_key(const std::string& key) noexcept {
        std::lock_guard lock(mu_);
        const auto it = in_flight_.find(key);
        if (it == in_flight_.end())
            return;
        if (it->second <= 1)
            in_flight_.erase(it); // the table holds only names with a lookup outstanding
        else
            --it->second;
    }

    mutable std::mutex mu_;
    const Limits limits_;
    const NowFn now_;
    std::unordered_map<std::string, std::size_t> in_flight_;
    std::unordered_map<std::string, Clock::time_point> refused_until_;
};

/// Wraps `inner` (empty means the system lookup) so the lookup holds `lease` for its whole life and
/// the WORKER releases it:
///  - explicitly at the end of the wrapper body, through a local object whose destructor also runs
///    when `inner` throws;
///  - and by the destructor of the last copy of the returned function, which covers a wrapper that
///    never runs (the pool refused it, or its thread could not be created).
/// The caller must not keep another copy of the lease: it would release early, at the caller's
/// time bound, and not when the lookup returns.
[[nodiscard]] inline LookupFn hold_lease_during(LookupFn inner,
                                                HostLookupAdmission::Lease lease) {
    auto held = std::make_shared<HostLookupAdmission::Lease>(std::move(lease));
    return [inner = std::move(inner), held](const std::string& host) -> ResolveResult {
        struct Release {
            HostLookupAdmission::Lease& lease;
            ~Release() { lease.release(); }
        } done{*held};
        return inner ? inner(host) : detail::system_lookup(host);
    };
}

} // namespace yuzu::server::net
