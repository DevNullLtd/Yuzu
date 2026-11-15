#pragma once

/// @file resolver_host_admission.hpp
/// Admission in front of the OIDC name lookup (`resolve_host_addresses_status` in
/// `oidc_provider.cpp`, POSIX builds): a short memory of names whose lookup was refused or timed
/// out. Pure decision code: one mutex, no I/O, no logging, an injectable monotonic clock, no
/// thread. `bounded_resolver.hpp` is not touched, so the process pool used by CRL source
/// registration is not affected.
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
///  - A name that cannot be keyed (empty, longer than 253 bytes, a control byte) is never
///    remembered and never refused from memory.
///
/// The caller treats a refusal like any other refused lookup: the same `kBusy` status and the
/// same reason text as a full pool, so no caller learns a new failure kind.

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

namespace yuzu::server::net {

/// How long a name whose lookup was refused or timed out is refused again.
inline constexpr std::chrono::seconds kLookupRefusalTtl{3};
/// The most names the refusal memory holds at once.
inline constexpr std::size_t kLookupRefusalMaxNames = 32;

class HostLookupAdmission {
public:
    using Clock = std::chrono::steady_clock;
    /// Must not call back into this object.
    using NowFn = std::function<Clock::time_point()>;

    struct Limits {
        Clock::duration refusal_ttl{kLookupRefusalTtl};
        std::size_t max_refusal_entries{kLookupRefusalMaxNames};
    };

    enum class Verdict : std::uint8_t {
        kAdmitted,
        kRefusedRecent, ///< the name's lookup was refused or timed out within the TTL
        kRefusedError   ///< the check itself failed: refused, never admitted
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

    /// Whether a lookup for `host` may be started. `consult_refusal_memory = false` skips the
    /// memory check (the NAT64 probe).
    [[nodiscard]] Verdict admit(std::string_view host, bool consult_refusal_memory = true) noexcept {
        try {
            if (!consult_refusal_memory)
                return Verdict::kAdmitted;
            const std::string key = normalise_key(host);
            if (key == unkeyed_name())
                return Verdict::kAdmitted;
            const auto now = now_();
            std::lock_guard lock(mu_);
            const auto it = refused_until_.find(key);
            if (it == refused_until_.end())
                return Verdict::kAdmitted;
            if (now < it->second)
                return Verdict::kRefusedRecent; // the entry is left as it is: no extension
            refused_until_.erase(it);
            return Verdict::kAdmitted;
        } catch (...) {
            return Verdict::kRefusedError;
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

private:
    HostLookupAdmission(Limits limits, NowFn now) : limits_(limits), now_(std::move(now)) {}

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

    mutable std::mutex mu_;
    const Limits limits_;
    const NowFn now_;
    std::unordered_map<std::string, Clock::time_point> refused_until_;
};

} // namespace yuzu::server::net
