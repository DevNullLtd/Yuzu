#pragma once

/// @file pbkdf2_budget.hpp
///
/// Process-wide cap on CONCURRENT password-hash (PBKDF2) work reachable from an
/// unauthenticated or lightly-authenticated request (POST /login, the password-change proof,
/// recovery-code checks at /login/mfa and /login/mfa/stepup). The per-IP login rate limiter
/// bounds one source; nothing bounded the SUM, and WP03 F38 makes an unknown username cost a
/// real PBKDF2 (to stop timing enumeration), so without this an unauthenticated client fleet
/// could pin every worker thread on hashing. Try-acquire only (never blocks a worker): when
/// full the caller answers a uniform 429 + Retry-After.
///
/// FAIRNESS: one global cap alone lets an unauthenticated flood starve the authenticated
/// paths, so slots are split by class. kUnauthenticated (POST /login, the recovery-code check
/// behind a pending login token) may hold at most `cap - reserve` slots, and at most
/// `per_source_cap` per source address; kAuthenticated (step-up recovery, password-change proof)
/// may use any free slot, so `reserve` slots are always left for it. kBreakGlass (a /login
/// naming the configured break-glass account under sso-only) is the escape hatch during an IdP
/// outage, so it too may use the reserved slots; it is capped at half the reserve (at least one slot) process-wide
/// and subject to the per-source cap, so naming that account is not a way to take the reserve.
/// Header-only, no I/O.

#include <algorithm>
#include <atomic>
#include <mutex>
#include <string>
#include <unordered_map>

namespace yuzu::server {

enum class Pbkdf2Class { kUnauthenticated, kAuthenticated, kBreakGlass };
enum class Pbkdf2Refusal { kNone, kPerSource, kClassFull, kGlobalFull };

class Pbkdf2Budget {
public:
    explicit Pbkdf2Budget(int cap = 2, int per_source_cap = 4) {
        set_cap(cap);
        per_source_cap_ = per_source_cap < 1 ? 1 : per_source_cap;
    }

    void set_cap(int cap) {
        std::lock_guard lk(mu_);
        cap_ = cap < 2 ? 2 : cap;
    }
    void set_per_source_cap(int c) {
        std::lock_guard lk(mu_);
        per_source_cap_ = c < 1 ? 1 : c;
    }
    int cap() const {
        std::lock_guard lk(mu_);
        return cap_;
    }
    /// Slots the unauthenticated class may NOT take (always free for authenticated callers).
    int reserve() const { return std::max(1, cap() / 2); }
    int in_flight() const {
        std::lock_guard lk(mu_);
        return total_;
    }

    /// RAII slot. `ok()` is false when refused (no slot held; `refusal()` says why).
    class Slot {
    public:
        Slot() = default;
        Slot(Slot&& o) noexcept
            : b_(o.b_), cls_(o.cls_), key_(std::move(o.key_)), refusal_(o.refusal_) {
            o.b_ = nullptr;
        }
        Slot& operator=(Slot&&) = delete;
        Slot(const Slot&) = delete;
        Slot& operator=(const Slot&) = delete;
        ~Slot() {
            if (b_)
                b_->release(cls_, key_);
        }
        [[nodiscard]] bool ok() const { return b_ != nullptr; }
        [[nodiscard]] Pbkdf2Refusal refusal() const { return refusal_; }

    private:
        friend class Pbkdf2Budget;
        Slot(Pbkdf2Budget* b, Pbkdf2Class c, std::string k) : b_(b), cls_(c), key_(std::move(k)) {}
        explicit Slot(Pbkdf2Refusal r) : refusal_(r) {}
        Pbkdf2Budget* b_{nullptr};
        Pbkdf2Class cls_{Pbkdf2Class::kAuthenticated};
        std::string key_;
        Pbkdf2Refusal refusal_{Pbkdf2Refusal::kNone};
    };

    /// `source` keys the per-source sub-budget (unauthenticated class only).
    [[nodiscard]] Slot try_acquire(Pbkdf2Class cls = Pbkdf2Class::kAuthenticated,
                                   const std::string& source = {}) {
        // Build everything that can throw (the key copy) BEFORE touching a counter, so a
        // bad_alloc cannot leak a slot.
        std::string key = cls == Pbkdf2Class::kAuthenticated ? std::string{} : source;
        std::lock_guard lk(mu_);
        if (total_ >= cap_)
            return Slot{Pbkdf2Refusal::kGlobalFull};
        if (cls == Pbkdf2Class::kUnauthenticated &&
            unauth_ >= std::max(1, cap_ - std::max(1, cap_ / 2)))
            return Slot{Pbkdf2Refusal::kClassFull};
        if (cls == Pbkdf2Class::kBreakGlass &&
            break_glass_ >= std::max(1, std::max(1, cap_ / 2) / 2))
            return Slot{Pbkdf2Refusal::kClassFull};
        if (cls != Pbkdf2Class::kAuthenticated) {
            auto it = per_source_.find(key);
            if (it != per_source_.end() && it->second >= per_source_cap_)
                return Slot{Pbkdf2Refusal::kPerSource};
            if (it == per_source_.end())
                it = per_source_.try_emplace(key, 0).first; // may throw: nothing counted yet
            ++it->second;
            (cls == Pbkdf2Class::kUnauthenticated ? unauth_ : break_glass_) += 1;
        }
        ++total_;
        return Slot{this, cls, std::move(key)};
    }

private:
    void release(Pbkdf2Class cls, const std::string& key) {
        std::lock_guard lk(mu_);
        --total_;
        if (cls != Pbkdf2Class::kAuthenticated) {
            (cls == Pbkdf2Class::kUnauthenticated ? unauth_ : break_glass_) -= 1;
            if (auto it = per_source_.find(key); it != per_source_.end() && --it->second <= 0)
                per_source_.erase(it); // bounded: only sources with a hash in flight
        }
    }

    mutable std::mutex mu_;
    int cap_{2};
    int per_source_cap_{1};
    int total_{0};
    int unauth_{0};
    int break_glass_{0};
    std::unordered_map<std::string, int> per_source_;
};

inline const char* to_string(Pbkdf2Refusal r) {
    switch (r) {
    case Pbkdf2Refusal::kPerSource: return "per_source";
    case Pbkdf2Refusal::kClassFull: return "class_full";
    case Pbkdf2Refusal::kGlobalFull: return "global_full";
    default: return "none";
    }
}

} // namespace yuzu::server
