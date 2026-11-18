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
/// FAIRNESS (cap C; the default pool of 264 gives C = 66): the budget is split so no class can
/// starve another.
///   - kBreakGlass (a /login naming the armed break-glass account under sso-only) owns a FLOOR of
///     `bg_cap = max(1, max(1, C/2)/2)` slots (16 at C = 66) that no other class can consume:
///     the other two classes together are bounded at `main_cap = C - bg_cap` (50). The lane is
///     also capped at `bg_cap` and subject to the per-source cap.
///   - kUnauthenticated (POST /login, the recovery-code check behind a pending login token) may
///     hold at most `main_cap - max(1, main_cap/2)` slots (25) and at most `per_source_cap` per
///     source address.
///   - kAuthenticated (step-up recovery, the password-change proof) may use any free slot of the
///     main share, so `max(1, main_cap/2)` (25) are always left for it, but at most
///     `per_principal_cap` (3) per principal, so one session holder cannot fill the share.
/// Header-only, no I/O.

#include <algorithm>
#include <atomic>
#include <mutex>
#include <string>
#include <unordered_map>

namespace yuzu::server {

enum class Pbkdf2Class { kUnauthenticated, kAuthenticated, kBreakGlass };
enum class Pbkdf2Refusal { kNone, kPerSource, kPerPrincipal, kClassFull, kGlobalFull };

class Pbkdf2Budget {
public:
    explicit Pbkdf2Budget(int cap = 4, int per_source_cap = 4) {
        set_cap(cap);
        per_source_cap_ = per_source_cap < 1 ? 1 : per_source_cap;
    }

    void set_cap(int cap) {
        std::lock_guard lk(mu_);
        cap_ = cap < 4 ? 4 : cap;
    }
    void set_per_source_cap(int c) {
        std::lock_guard lk(mu_);
        per_source_cap_ = c < 1 ? 1 : c;
    }
    int cap() const {
        std::lock_guard lk(mu_);
        return cap_;
    }
    /// Slots of the break-glass floor, and the bound on the other two classes together.
    int break_glass_cap() const { return bg_cap(cap()); }
    int main_cap() const { return cap() - bg_cap(cap()); }
    int per_principal_cap() const { return per_principal_cap_; }
    void set_per_principal_cap(int c) {
        std::lock_guard lk(mu_);
        per_principal_cap_ = c < 1 ? 1 : c;
    }
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

    /// `source` keys the per-source sub-budget (unauthenticated and break-glass lanes);
    /// `principal` keys the per-principal sub-budget (authenticated lane).
    [[nodiscard]] Slot try_acquire(Pbkdf2Class cls = Pbkdf2Class::kAuthenticated,
                                   const std::string& source = {},
                                   const std::string& principal = {}) {
        // Build everything that can throw (the key copy) BEFORE touching a counter, so a
        // bad_alloc cannot leak a slot.
        std::string key = cls == Pbkdf2Class::kAuthenticated ? principal : source;
        std::lock_guard lk(mu_);
        const int bgc = bg_cap(cap_);
        const int main_cap = cap_ - bgc;
        const int auth_reserve = std::max(1, main_cap / 2);
        const int unauth_cap = std::max(1, main_cap - auth_reserve);
        if (cls == Pbkdf2Class::kBreakGlass) {
            if (break_glass_ >= bgc)
                return Slot{Pbkdf2Refusal::kClassFull};
        } else {
            // The union bound: break-glass keeps its floor whatever the other classes do.
            if (auth_ + unauth_ >= main_cap)
                return Slot{Pbkdf2Refusal::kGlobalFull};
            if (cls == Pbkdf2Class::kUnauthenticated && unauth_ >= unauth_cap)
                return Slot{Pbkdf2Refusal::kClassFull};
        }
        auto& map = cls == Pbkdf2Class::kAuthenticated ? per_principal_ : per_source_;
        const int per_cap = cls == Pbkdf2Class::kAuthenticated ? per_principal_cap_ : per_source_cap_;
        if (!key.empty() || cls != Pbkdf2Class::kAuthenticated) {
            auto it = map.find(key);
            if (it != map.end() && it->second >= per_cap)
                return Slot{cls == Pbkdf2Class::kAuthenticated ? Pbkdf2Refusal::kPerPrincipal
                                                              : Pbkdf2Refusal::kPerSource};
            if (it == map.end())
                it = map.try_emplace(key, 0).first; // may throw: nothing counted yet
            ++it->second;
        }
        (cls == Pbkdf2Class::kUnauthenticated ? unauth_
         : cls == Pbkdf2Class::kBreakGlass    ? break_glass_
                                              : auth_) += 1;
        ++total_;
        return Slot{this, cls, std::move(key)};
    }

private:
    static int bg_cap(int cap) { return std::max(1, std::max(1, cap / 2) / 2); }

    void release(Pbkdf2Class cls, const std::string& key) {
        std::lock_guard lk(mu_);
        --total_;
        (cls == Pbkdf2Class::kUnauthenticated ? unauth_
         : cls == Pbkdf2Class::kBreakGlass    ? break_glass_
                                              : auth_) -= 1;
        auto& map = cls == Pbkdf2Class::kAuthenticated ? per_principal_ : per_source_;
        if (auto it = map.find(key); it != map.end() && --it->second <= 0)
            map.erase(it); // bounded: only keys with a hash in flight
    }

    mutable std::mutex mu_;
    int cap_{4};
    int per_source_cap_{1};
    int total_{0};
    int unauth_{0};
    int break_glass_{0};
    int auth_{0};
    int per_principal_cap_{3};
    std::unordered_map<std::string, int> per_principal_;
    std::unordered_map<std::string, int> per_source_;
};

inline const char* to_string(Pbkdf2Refusal r) {
    switch (r) {
    case Pbkdf2Refusal::kPerSource: return "per_source";
    case Pbkdf2Refusal::kPerPrincipal: return "per_principal";
    case Pbkdf2Refusal::kClassFull: return "class_full";
    case Pbkdf2Refusal::kGlobalFull: return "global_full";
    default: return "none";
    }
}

} // namespace yuzu::server
