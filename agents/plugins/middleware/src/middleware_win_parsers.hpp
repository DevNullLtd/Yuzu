/**
 * middleware_win_parsers.hpp -- the PURE half of the Windows leg: WinRegFs, the registry `Fs` the
 * generic runner's run_reg_leg reads through (middleware_runner.hpp, MiddlewareRegFs).
 *
 * No Windows header, no registry call: every registry touch goes through `RegOps`, the injected
 * boundary, so this header compiles and is unit-tested on EVERY OS (tests/unit/
 * test_middleware_win_parsers.cpp, over a FakeOps). The real RegOps is middleware_win.cpp's
 * RealRegOps (Reg*W on HKEY_LOCAL_MACHINE only).
 *
 * THE RegOps CONCEPT, two calls per registry view (`view` is the 64-bit or the 32-bit one):
 *
 *   RegListing list_subkeys(RegView view, std::string_view key, std::size_t max)
 *       the subkey NAMES of HKLM\<key> in that view, at most `max`; `truncated` = there were more.
 *   RegText    read_sz(RegView view, std::string_view key, std::string_view value, std::size_t cap)
 *       the text of one REG_SZ / REG_EXPAND_SZ value of HKLM\<key> (unexpanded), or why not.
 *
 * Both answer a RegStatus: ok | absent (key or value not there) | denied (access refused) | oversized
 * (a value over `cap`, read_sz only) | failed (anything else, including a value of any other type:
 * decide_value is the ONE rule for that, shared with the real ops).
 *
 * THE MERGE (a 32-bit installation registers under WOW6432Node, which the 32-bit view shows as the
 * plain key). FAILURE NEVER READS AS ABSENT:
 *
 *   reg_subkeys  names = the de-duplicated union of both views (ASCII case-insensitive, 64-bit
 *                spelling first);
 *                absent in BOTH views            -> absent
 *                any names                       -> ok
 *                else any view denied            -> denied (never absent: an unreadable hive is not
 *                                                   "none found")
 *                else any view failed            -> failed
 *                else                            -> ok, zero names
 *   reg_value    the 64-bit view first; the 32-bit view ONLY when the first is absent. A denied,
 *                failed or oversized first answer is the answer.
 *
 * ONE BUDGET. Every name a listing returns and every value read counts one entry against an
 * entries-visited budget (kMaxRegEntries); the listing that crosses it, or any read once it is
 * spent, sets exhausted(), and run_reg_leg then ends the walk with `windows:middleware:walk:row_cap`.
 */
#pragma once

#include "middleware_runner.hpp"

#include <user_profile_model.hpp> // yuzu::profiles::iequals_ascii

#include <algorithm>
#include <concepts>
#include <cstddef>
#include <cstdint>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

namespace yuzu::middleware::win {

/// The most registry entries (subkey names listed plus values read, both views) one action visits.
inline constexpr std::size_t kMaxRegEntries = 65536;

enum class RegView : std::uint8_t { v64, v32 };

enum class RegStatus : std::uint8_t { ok, absent, denied, oversized, failed };

struct RegListing {
    RegStatus status = RegStatus::failed; ///< a default-built answer is a failure, never "none"
    std::vector<std::string> names;
    bool truncated = false;
};

struct RegText {
    RegStatus status = RegStatus::failed;
    std::string text;
};

/// What the real ops learned about one value before reading it.
enum class RegValueKind : std::uint8_t { sz, expand_sz, other };

/// The ONE rule for a value's usability, used by RealRegOps and tested here: only REG_SZ and
/// REG_EXPAND_SZ are text (a DWORD or binary value is `failed`, never text), and a value over `cap`
/// bytes is `oversized`. `ok` means "go on and read it".
[[nodiscard]] constexpr RegStatus decide_value(RegValueKind kind, std::size_t size_bytes,
                                               std::size_t cap) noexcept {
    if (kind == RegValueKind::other)
        return RegStatus::failed;
    return size_bytes > cap ? RegStatus::oversized : RegStatus::ok;
}

template <class O>
concept RegOps = requires(O& o, RegView v, std::string_view s) {
    { o.list_subkeys(v, s, std::size_t{}) } -> std::same_as<RegListing>;
    { o.read_sz(v, s, s, std::size_t{}) } -> std::same_as<RegText>;
};

namespace detail {

[[nodiscard]] constexpr Read::Outcome to_outcome(RegStatus s) noexcept {
    switch (s) {
    case RegStatus::ok:        return Read::Outcome::ok;
    case RegStatus::absent:    return Read::Outcome::absent;
    case RegStatus::denied:    return Read::Outcome::denied;
    case RegStatus::oversized: return Read::Outcome::oversized;
    case RegStatus::failed:    break;
    }
    return Read::Outcome::failed;
}

} // namespace detail

/// The registry `Fs` of run_reg_leg over an injected RegOps (see the header comment for the merge).
template <RegOps Ops> class WinRegFs {
public:
    explicit WinRegFs(Ops ops, std::size_t entry_budget = kMaxRegEntries)
        : ops_(std::move(ops)), budget_(entry_budget) {}

    [[nodiscard]] RegKeys reg_subkeys(std::string_view hklm_key) {
        RegKeys out;
        int absent = 0;
        bool denied = false;
        bool failed = false;
        for (const RegView view : {RegView::v64, RegView::v32}) {
            RegListing l = ops_.list_subkeys(view, hklm_key, remaining());
            switch (l.status) {
            case RegStatus::ok:
                visited_ += l.names.size();
                if (l.truncated)
                    spent_ = true;
                for (std::string& n : l.names) {
                    const auto same = [&](const std::string& have) {
                        return yuzu::profiles::iequals_ascii(have, n);
                    };
                    if (!n.empty() && std::none_of(out.names.begin(), out.names.end(), same))
                        out.names.push_back(std::move(n));
                }
                break;
            case RegStatus::absent: ++absent; break;
            case RegStatus::denied: denied = true; break;
            case RegStatus::oversized:
            case RegStatus::failed: failed = true; break;
            }
        }
        if (absent == 2)
            out.out = Read::Outcome::absent;
        else if (!out.names.empty())
            out.out = Read::Outcome::ok;
        else if (denied)
            out.out = Read::Outcome::denied;
        else if (failed)
            out.out = Read::Outcome::failed;
        else
            out.out = Read::Outcome::ok; // the key exists and is empty
        return out;
    }

    [[nodiscard]] Read reg_value(std::string_view hklm_key, std::string_view subkey,
                                 std::string_view value, std::size_t cap) {
        std::string key{hklm_key};
        key += '\\';
        key.append(subkey);
        RegText t;
        for (const RegView view : {RegView::v64, RegView::v32}) {
            if (++visited_ > budget_)
                spent_ = true;
            t = ops_.read_sz(view, key, value, cap);
            if (t.status != RegStatus::absent)
                break; // only an absent value falls through to the other view
        }
        Read r;
        r.out = detail::to_outcome(t.status);
        if (t.status == RegStatus::ok)
            r.text = std::move(t.text);
        return r;
    }

    [[nodiscard]] bool exhausted() const noexcept { return spent_; }
    [[nodiscard]] std::string_view os() const noexcept { return "windows"; }

private:
    [[nodiscard]] std::size_t remaining() const noexcept {
        return visited_ >= budget_ ? 0 : budget_ - visited_;
    }

    Ops ops_;
    std::size_t budget_;
    std::size_t visited_ = 0;
    bool spent_ = false;
};

} // namespace yuzu::middleware::win
