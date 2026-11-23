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
///     `bg_cap = min(4, max(1, max(1, C/2)/2))` slots (4 at C = 66) that no other class can
///     consume: the other two classes together are bounded at `main_cap = C - bg_cap` (62). The
///     lane is exactly that size and is held to ONE slot per source address whatever the
///     configured per-source cap; it takes no per-username stripe.
///   - kUnauthenticated (POST /login, the recovery-code check behind a pending login token) may
///     hold at most `main_cap - max(1, main_cap/2)` slots (31) and at most `per_source_cap` per
///     source address.
///   - kAuthenticated (step-up recovery, the password-change proof) may hold at most
///     `max(1, main_cap/2)` (31), and at most `per_principal_cap` (3) per principal, so one
///     session holder cannot fill even that. The split with kUnauthenticated is fixed (no
///     borrowing), so neither class can fill the main share and starve /login or step-up.
/// Per-source keys are per class ("bg:" prefix for break-glass), so an unauthenticated hash from
/// an address never blocks that address's break-glass attempt and vice versa.
/// Header-only, no I/O.

#include <algorithm>
#include <atomic>
#include <chrono>
#include <mutex>
#include <string>
#include <unordered_map>

namespace yuzu::server {

/// Most concurrent break-glass attempts process-wide (the lane is min(this, cap/4), so 1 on
/// pools of 10-15 workers and 4 from a pool of 64). The lane, taken per source address and
/// non-blocking, IS the bound on concurrent break-glass guesses; there is no second gate.
inline constexpr int kBreakGlassLaneMax = 4;

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
    /// The lane sizes for a given cap: ONE place, used by the budget itself and by the boot
    /// sizing (server.cpp), so a documented number cannot drift from the enforced one.
    struct Lanes {
        int break_glass;
        int main;
        int authenticated;
        int unauthenticated;
    };
    static Lanes lanes_for_cap(int cap) {
        const int c = cap < 4 ? 4 : cap;
        const int bg = bg_cap(c);
        const int main = c - bg;
        const int auth = std::max(1, main / 2);
        return {bg, main, auth, std::max(1, main - auth)};
    }
    /// Slots of the break-glass floor, and the bound on the other two classes together.
    int break_glass_cap() const { return bg_cap(cap()); }
    int main_cap() const { return cap() - bg_cap(cap()); }
    int unauthenticated_cap() const { return lanes_for_cap(cap()).unauthenticated; }
    int per_principal_cap() const { return per_principal_cap_; }
    void set_per_principal_cap(int c) {
        std::lock_guard lk(mu_);
        per_principal_cap_ = c < 1 ? 1 : c;
    }
    int in_flight() const {
        std::lock_guard lk(mu_);
        return total_;
    }
    /// High-water mark of slots in use since the last call (then reset to the current level):
    /// a point-in-time gauge reads ~0 for a 50-150 ms hash, so the sweep publishes this.
    int take_peak() {
        std::lock_guard lk(mu_);
        const int p = peak_;
        peak_ = total_;
        return p;
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
        std::string key = cls == Pbkdf2Class::kAuthenticated ? principal
                          : cls == Pbkdf2Class::kBreakGlass   ? "bg:" + source
                                                              : source;
        std::lock_guard lk(mu_);
        const Lanes ln = lanes_for_cap(cap_);
        const int bgc = ln.break_glass;
        const int main_cap = ln.main;
        const int auth_reserve = ln.authenticated;
        const int unauth_cap = ln.unauthenticated;
        if (cls == Pbkdf2Class::kBreakGlass) {
            if (break_glass_ >= bgc)
                return Slot{Pbkdf2Refusal::kClassFull};
        } else {
            // The union bound: break-glass keeps its floor whatever the other classes do.
            if (auth_ + unauth_ >= main_cap)
                return Slot{Pbkdf2Refusal::kGlobalFull};
            // A fixed split, no borrowing: each of the two shared classes is capped at its own
            // half, so neither can fill the main share and starve the other.
            if (cls == Pbkdf2Class::kUnauthenticated && unauth_ >= unauth_cap)
                return Slot{Pbkdf2Refusal::kClassFull};
            if (cls == Pbkdf2Class::kAuthenticated && auth_ >= auth_reserve)
                return Slot{Pbkdf2Refusal::kClassFull};
        }
        auto& map = cls == Pbkdf2Class::kAuthenticated ? per_principal_ : per_source_;
        // The break-glass lane allows ONE concurrent attempt per source address whatever the
        // configured per-source cap, so a single address cannot fill the lane.
        const int per_cap = cls == Pbkdf2Class::kAuthenticated ? per_principal_cap_
                            : cls == Pbkdf2Class::kBreakGlass  ? 1
                                                               : per_source_cap_;
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
        if (total_ > peak_)
            peak_ = total_;
        return Slot{this, cls, std::move(key)};
    }

private:
    static int bg_cap(int cap) {
        return std::min(kBreakGlassLaneMax, std::max(1, std::max(1, cap / 2) / 2));
    }

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
    int peak_{0};
    int unauth_{0};
    int break_glass_{0};
    int auth_{0};
    int per_principal_cap_{3};
    std::unordered_map<std::string, int> per_principal_;
    std::unordered_map<std::string, int> per_source_;
};

/// The login concurrency sizing for an HTTP worker pool: PURE (no I/O), so it is unit-tested at
/// the real pool sizes and is the ONE source for the setter, the gauges, the boot log and the
/// boot warning in server.cpp.
struct LoginSizing {
    int cap;                    // process-wide PBKDF2 slots
    int break_glass_lane;       // min(4, cap/4), one per source address
    int unauthenticated_lane;
    int authenticated_lane;
    int stripe_waiters;         // global ceiling on requests waiting for a username stripe
    bool small_pool;            // pool < 64: lanes or waiter ceilings are reduced
    bool per_source_covers_lane; // per-source cap >= unauthenticated lane: one address can fill it
    bool pool_crowded;          // cap + waiters >= pool: logins alone can occupy every worker
};

inline LoginSizing login_sizing(std::size_t pool, int per_source_cap) {
    const std::size_t cap_want = std::max<std::size_t>(8, pool / 4);
    const int cap = static_cast<int>(std::min(cap_want, std::max<std::size_t>(4, pool / 2)));
    const auto ln = Pbkdf2Budget::lanes_for_cap(cap);
    const int waiters = static_cast<int>(std::max<std::size_t>(2, pool / 8));
    return {cap,
            ln.break_glass,
            ln.unauthenticated,
            ln.authenticated,
            waiters,
            pool < 64 || ln.break_glass < kBreakGlassLaneMax,
            per_source_cap >= ln.unauthenticated,
            static_cast<std::size_t>(cap + waiters) >= pool};
}

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
