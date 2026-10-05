#pragma once

/**
 * privacy_permissions_win_walk.hpp -- the ConsentStore registry walk behind an injectable seam.
 *
 * windows.h-free by design: the Win32 shell (privacy_permissions_win.cpp's Win32Registry) supplies
 * the OS through RegistryReader / ConsentStoreWatch, and everything that DECIDES -- enumeration
 * with its cap and probe, the per-value read and its size/type/error branches, the NonPackaged and
 * Executables key-name comparison, the stability watch and its one re-walk, the deadline order --
 * is plain code over those interfaces, so a fake registry in
 * tests/unit/test_privacy_permissions_win_walk.cpp locks each branch on every host. The decode
 * helpers it routes through live in privacy_permissions_win_parsers.hpp.
 *
 * The codes the seam returns are Win32 codes carried as `long`; the shell static_asserts each
 * mirrored constant against its SDK value.
 */

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <memory>
#include <span>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

#include "privacy_permissions_win_parsers.hpp"

namespace yuzu::privacy_permissions::win {

/// An opaque registry key handle (an HKEY in the Win32 shell).
using RegKeyHandle = void*;

/// Arms a change watch on a ConsentStore root when constructed and reports, on poll(), what the
/// stability facts are (win::classify_stability turns them into a verdict).
struct ConsentStoreWatch {
    ConsentStoreWatch() = default;
    ConsentStoreWatch(const ConsentStoreWatch&) = delete;
    ConsentStoreWatch& operator=(const ConsentStoreWatch&) = delete;
    virtual ~ConsentStoreWatch() = default;
    [[nodiscard]] virtual StabilityFacts poll() = 0;
};

/// The registry as the walk sees it. Every method mirrors one Win32 call and returns its code.
/// Raw `long` codes and out-parameters by design, an exception to cpp-conventions' std::expected
/// rule: each method mirrors one Win32 call, and query_value returns a partial result (type and
/// size) beside the code.
struct RegistryReader {
    RegistryReader() = default;
    RegistryReader(const RegistryReader&) = delete;
    RegistryReader& operator=(const RegistryReader&) = delete;
    virtual ~RegistryReader() = default;

    /// RegOpenKeyExW(KEY_READ): `out` is set only on success.
    virtual long open_key(RegKeyHandle parent, const wchar_t* name, RegKeyHandle& out) = 0;
    virtual void close_key(RegKeyHandle key) = 0;
    /// RegEnumKeyExW at `idx`: on success `name` holds the COUNTED name (it may contain a NUL).
    virtual long enum_key(RegKeyHandle parent, std::uint32_t idx, std::wstring& name) = 0;
    /// RegQueryValueExW. An empty `buf` is the size probe (success, `size` = the value's size);
    /// a buffer too small is kErrorMoreData with `size` = the size needed.
    virtual long query_value(RegKeyHandle key, const wchar_t* value_name, std::uint32_t& type,
                             std::span<std::byte> buf, std::uint32_t& size) = 0;
    [[nodiscard]] virtual std::unique_ptr<ConsentStoreWatch> watch(RegKeyHandle root) = 0;
    /// The registry's own key-name equality (ordinal, case-insensitive).
    [[nodiscard]] virtual bool key_name_equals(std::wstring_view a, std::wstring_view b) const = 0;
    [[nodiscard]] virtual std::string utf8(std::wstring_view s) const = 0;
    /// A REG_SZ payload (its first `size` bytes) decoded to UTF-8, stopping at the first NUL.
    [[nodiscard]] virtual std::string reg_sz_utf8(std::span<const std::byte> payload) const = 0;
};

/// Owns one opened key; closes it exactly once.
class ScopedKey {
public:
    explicit ScopedKey(RegistryReader& reg) noexcept : reg_(reg) {}
    ~ScopedKey() {
        if (key_) reg_.close_key(key_);
    }
    ScopedKey(const ScopedKey&) = delete;
    ScopedKey& operator=(const ScopedKey&) = delete;

    [[nodiscard]] long open(RegKeyHandle parent, const wchar_t* name) {
        return reg_.open_key(parent, name, key_);
    }
    [[nodiscard]] RegKeyHandle get() const noexcept { return key_; }

private:
    RegistryReader& reg_;
    RegKeyHandle key_ = nullptr;
};

/// A ConsentStore subtree is under the OWNING USER's write access, so an unbounded enumeration lets
/// that user pin the instruction worker -- and, on the offline-hive arm, hold the process-wide
/// offline_hive_mutex() -- for as long as they can keep stuffing subkeys. Same shape and order of
/// magnitude as win_profiles.hpp's own kMaxEnumeratedValueNames (4096), the precedent this copies.
inline constexpr std::uint32_t kMaxEnumeratedSubkeys = 4096;

inline constexpr std::wstring_view kConsentStorePath =
    L"Software\\Microsoft\\Windows\\CurrentVersion\\CapabilityAccessManager\\ConsentStore";
inline constexpr std::wstring_view kNonPackagedKeyName = L"NonPackaged";
inline constexpr std::wstring_view kExecutablesContainerKeyName = L"Executables";

/// An ASCII literal widened to a registry name (capability names are compile-time ASCII).
[[nodiscard]] inline std::wstring widen_ascii(std::string_view s) {
    return std::wstring(s.begin(), s.end());
}

struct SubkeyEnum {
    std::vector<std::wstring> names;
    EnumVerdict verdict;
};

/// Enumerates `parent`'s children (at most kMaxEnumeratedSubkeys).
/// When the loop stops at the cap, one extra, uncounted enumeration probe at the next index tells
/// "exactly cap children" (complete) from "more exist" (truncated) -- win_profiles.hpp's
/// enumerate_profile_records/profile_list_actually_truncated precedent.
/// A name that cannot be reopened by c_str() is skipped here, the one site both walks route
/// through, and counted: one with an embedded NUL (the open stops at the NUL, so it would read a
/// prefix sibling or, with a leading NUL, the parent itself) and a zero-length one
/// (RegOpenKeyExW(parent, L"") reopens the PARENT).
[[nodiscard]] inline SubkeyEnum enumerate_subkey_names(RegistryReader& reg, RegKeyHandle parent) {
    SubkeyEnum out{{}, {EnumOutcome::complete}};
    std::uint32_t idx = 0;
    long rc = kErrorSuccess;
    std::size_t embedded_nul = 0;
    std::wstring name;
    while (idx < kMaxEnumeratedSubkeys &&
           (rc = reg.enum_key(parent, idx++, name)) == kErrorSuccess) {
        if (name.empty() || name.find(L'\0') != std::wstring::npos)
            ++embedded_nul;
        else
            out.names.push_back(name);
    }
    long probe_rc = kErrorNoMoreItems;
    if (rc == kErrorSuccess) { // stopped by the cap alone
        std::wstring probe_name;
        probe_rc = reg.enum_key(parent, idx, probe_name);
    }
    out.verdict = classify_subkey_enum(rc, probe_rc);
    out.verdict.embedded_nul_names = embedded_nul;
    return out;
}

/// Reads one grant's `Value` (+ LastUsedTime*) from `app_key`. Every non-success outcome other
/// than "no Value here" (absent) sets a `cause`, so it is reported, never silently kept.
[[nodiscard]] inline RawGrant read_one_grant(RegistryReader& reg, RegKeyHandle app_key,
                                             std::string app_id, std::string_view category) {
    RawGrant g{std::move(app_id), category, PermissionState::unreadable, "-"};

    std::uint32_t type = 0, size = 0;
    const long probe_rc = reg.query_value(app_key, L"Value", type, {}, size);
    if (probe_rc == kErrorSuccess && size > kMaxConsentValueBytes) {
        // This subtree is under the OWNING USER's write access, so an unbounded
        // allocation sized from a provider-reported DWORD would let that user make the
        // privileged agent retain an arbitrarily large buffer per value -- capped at the small
        // ConsentStore-literal bound (kMaxConsentValueBytes), reported, never truncated.
        g.cause = "value_oversized";
    } else if (probe_rc == kErrorSuccess && size > 0) {
        std::vector<std::byte> buf(size);
        std::uint32_t sz = size;
        const long real_rc = reg.query_value(app_key, L"Value", type, std::span{buf}, sz);
        if (real_rc == kErrorSuccess) {
            // `sz` (the size the SECOND read returned) bounds the decode, not the probe's size.
            const std::string val = reg.reg_sz_utf8(
                std::span<const std::byte>{buf.data(), (std::min)(std::size_t{sz}, buf.size())});
            g.state = decode_consent_value(val, type == kRegSz);
            g.raw_value = val.empty() ? "-" : val;
            if (g.state == PermissionState::unreadable)
                g.cause = (type != kRegSz) ? "value_type_" + std::to_string(type) : "value_empty";
        } else if (real_rc == kErrorAccessDenied) {
            // The second read can itself be refused even though the size probe
            // succeeded (an ACL change between the two calls).
            g.state = PermissionState::denied;
            g.read_denied = true;
            g.cause = "value_access_denied";
        } else {
            // ERROR_MORE_DATA (the value grew between the two calls) or any other error.
            g.cause = "value_" + win32_cause(real_rc);
        }
    } else if (probe_rc == kErrorSuccess) {
        g.cause = "value_empty"; // a zero-size Value: present, but carries nothing to decode
    } else if (probe_rc == kErrorFileNotFound) {
        g.state = PermissionState::absent; // no Value under this key -- genuinely not there
    } else if (probe_rc == kErrorAccessDenied) {
        g.state = PermissionState::denied; // the read was refused, never collapsed into absent
        g.read_denied = true;
        g.cause = "value_access_denied";
    } else {
        g.cause = "value_" + win32_cause(probe_rc);
    }

    const auto read_last_used = [&](const wchar_t* name) {
        std::uint64_t ft = 0;
        std::uint32_t t = 0, sz = sizeof(ft);
        const long rc = reg.query_value(
            app_key, name, t, std::span<std::byte>{reinterpret_cast<std::byte*>(&ft), sizeof ft},
            sz);
        return decode_last_used(rc, t, sz, ft);
    };
    g.last_used_start = read_last_used(L"LastUsedTimeStart");
    g.last_used_stop = read_last_used(L"LastUsedTimeStop");
    return g;
}

/// One pass over every mapped CapabilityName under `hive`'s ConsentStore: the capability-level
/// Value (an `absent` entry when the capability key itself is not there, so every category is
/// represented) plus every packaged and NonPackaged app child. Every entry is charged against the
/// `budget` BEFORE it is retained; once the budget stops the walk (a limit, or the run's time) it
/// ends where it is and the collector reports which. A change the stability watch reports discards
/// the read (`refused`); walk_consent_store decides whether to try again.
[[nodiscard]] inline ConsentWalk walk_consent_store_once(RegistryReader& reg, RegKeyHandle hive,
                                                         RetentionBudget& budget) {
    ConsentWalk w;
    const auto keep = [&](std::vector<RawGrant>& into, RawGrant g) {
        if (budget.charge(retained_bytes(g))) into.push_back(std::move(g));
    };
    ScopedKey store(reg);
    w.root_rc = store.open(hive, std::wstring{kConsentStorePath}.c_str());
    if (w.root_rc == kErrorFileNotFound) {
        for (const auto& cap : kCapabilities)
            keep(w.grants, {"-", cap.category, PermissionState::absent, "-"});
        return w;
    }
    if (w.root_rc != kErrorSuccess) return w; // the caller reports the whole-source row
    const auto watch = reg.watch(store.get());

    for (const auto& cap : kCapabilities) {
        if (budget.walk_stopped()) break;
        ScopedKey cap_key(reg);
        const long cap_rc = cap_key.open(store.get(), widen_ascii(cap.capability_name).c_str());
        if (cap_rc == kErrorFileNotFound) {
            keep(w.grants, {"-", cap.category, PermissionState::absent, "-"});
            continue;
        }
        if (cap_rc != kErrorSuccess) {
            keep(w.structural, structural_failure("-", cap.category,
                                                  "capability:" + win32_cause(cap_rc),
                                                  cap_rc == kErrorAccessDenied));
            continue;
        }

        // The capability-level grant itself (no specific app -- "the global default").
        keep(w.grants, read_one_grant(reg, cap_key.get(), "-", cap.category));

        // One app child: a key that vanished since enumeration (FILE_NOT_FOUND) is simply gone;
        // any other open failure is that app's own failure row.
        const auto read_app = [&](RegKeyHandle parent, const std::wstring& child,
                                  std::string app_id, std::string_view kind) {
            ScopedKey app_key(reg);
            const long rc = app_key.open(parent, child.c_str());
            if (rc == kErrorSuccess)
                keep(w.grants, read_one_grant(reg, app_key.get(), std::move(app_id), cap.category));
            else if (rc != kErrorFileNotFound)
                keep(w.structural, structural_failure(std::move(app_id), cap.category,
                                                      std::string{kind} + ":" + win32_cause(rc),
                                                      rc == kErrorAccessDenied));
        };
        // Enumeration completeness (enum_failure): a complete walk -- including one of exactly the
        // cap -- adds nothing; a truncated or failed one is a structural row.
        const auto note_enum = [&](std::string_view kind, const EnumVerdict& v) {
            if (const auto f = enum_failure(kind, v))
                keep(w.structural, structural_failure("-", cap.category, f->cause, f->denied));
        };

        // Packaged apps: direct children of the capability key OTHER than "NonPackaged". The
        // registry's key names are case-insensitive, so the compare is the registry's own.
        const auto packaged = enumerate_subkey_names(reg, cap_key.get());
        for (const auto& child : packaged.names) {
            if (budget.walk_stopped()) break;
            if (reg.key_name_equals(child, kNonPackagedKeyName)) continue;
            read_app(cap_key.get(), child, reg.utf8(child), "packaged_app");
        }
        note_enum("packaged", packaged.verdict);

        // Win32 (non-packaged) apps, keyed by an escaped executable path.
        ScopedKey nonpkg(reg);
        const long nonpkg_rc =
            nonpkg.open(cap_key.get(), std::wstring{kNonPackagedKeyName}.c_str());
        if (nonpkg_rc == kErrorSuccess) {
            // The "let desktop apps access" toggle: the NonPackaged key's own Value, one row.
            keep(w.grants, read_one_grant(reg, nonpkg.get(), std::string{kNonPackagedToggleAppId},
                                          cap.category));
            const auto nonpackaged = enumerate_subkey_names(reg, nonpkg.get());
            for (const auto& child : nonpackaged.names) {
                if (budget.walk_stopped()) break;
                // `Executables` is a container of per-exe prompt flags, not an app (measured on
                // the-rig); skipped by the registry's own name compare, any other child is an app.
                if (reg.key_name_equals(child, kExecutablesContainerKeyName)) continue;
                read_app(nonpkg.get(), child, unescape_nonpackaged_app_id(reg.utf8(child)),
                         "nonpackaged_app");
            }
            note_enum("nonpackaged", nonpackaged.verdict);
        } else {
            // A missing NonPackaged key is the toggle row reading `absent`; any other code is a
            // structural failure (nonpackaged_open_failure decides).
            auto g = nonpackaged_open_failure(cap.category, nonpkg_rc);
            const bool toggle_absent = (g.state == PermissionState::absent);
            keep(toggle_absent ? w.grants : w.structural, std::move(g));
        }
    }
    if (const auto token = classify_stability(watch->poll())) {
        w.refused = *token;
        w.grants.clear();
        w.structural.clear();
    }
    return w;
}

/// walk_consent_store_once, tried again once after a `changed_during_read` -- and never once the
/// run's deadline has passed (a timed-out first walk keeps its honest `changed_during_read`
/// refusal rather than being replaced by an empty second walk). The re-walk
/// starts the source's retention counters from zero (begin_profile), since the discarded walk
/// charged them; the deadline is sticky and is not reset.
[[nodiscard]] inline ConsentWalk walk_consent_store(RegistryReader& reg, RegKeyHandle hive,
                                                    RetentionBudget& budget) {
    ConsentWalk w = walk_consent_store_once(reg, hive, budget);
    if (w.refused != kChangedDuringRead || budget.expired()) return w;
    budget.begin_profile();
    return walk_consent_store_once(reg, hive, budget);
}

} // namespace yuzu::privacy_permissions::win
