/**
 * local_security_policy_legs.hpp -- the seam between the portable plugin TU and the
 * per-OS leg TUs, plus the thin OS shells the legs share (POSIX readers, the
 * CFPropertyList bridge). Every decision lives in local_security_policy_parsers.hpp.
 * Each collect_* is defined by exactly one leg TU; a read returns 0, degradation is the status.
 *
 * All three legs and all four actions are real: Linux and macOS read files (macOS also
 * pwpolicy), Windows decodes `secedit /export` (local_security_policy_win.cpp), and `sudoers`
 * reads /etc/sudoers and /etc/sudoers.d on Linux and macOS (Windows has no sudoers: it reports
 * `unsupported`). Every leg reports degradation as the status, never an empty success.
 *
 * Sites that still name a leg's support level and must be revisited if one changes: the per-OS
 * descriptors in local_security_policy_plugin.cpp (support level, mechanism, fallback; the
 * leg-hash changes, so run `plugin_doc_gen.py --stamp`), the yaml `platforms` column and row
 * descriptions, the README (How it works, Privileges, Result status, Sample, Caveats),
 * docs/agent-privilege-model.md's row, the capability matrix row, the capability-map cell, the
 * .claude/routed-concerns-security-posture.md row, and the capability catalogue header.
 */
#pragma once

#include "local_security_policy_parsers.hpp"

#include <yuzu/agent/subprocess_runner.hpp>
#include <yuzu/plugin.hpp>

#include <spdlog/spdlog.h>

#include <algorithm>
#include <cerrno>
#include <optional>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

#if !defined(_WIN32)
#include <yuzu/agent/scoped_fd.hpp>

#include <dirent.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>

#include <posix_dir_walk.hpp>
#endif
#if defined(__APPLE__)
#include <yuzu/agent/scoped_cfref.hpp>

#include <CoreFoundation/CoreFoundation.h>
#endif

namespace yuzu::local_security_policy {

/// The runner's termination reason as the pure layer's RunEnd (both rung-2 legs).
inline RunEnd to_run_end(yuzu::agent::TerminationReason r) noexcept {
    using T = yuzu::agent::TerminationReason;
    switch (r) {
    case T::exited:
        return RunEnd::Exited;
    case T::deadline:
        return RunEnd::Deadline;
    case T::cancelled:
        return RunEnd::Cancelled;
    case T::signaled:
        return RunEnd::Signaled;
    case T::spawn_error:
        return RunEnd::SpawnError;
    case T::line_limit:
        break;
    }
    return RunEnd::Other; // line_limit cannot occur: neither leg sets stop_after_max_lines
}

int collect_linux_policy(yuzu::CommandContext& ctx, std::string_view action);
int collect_macos_policy(yuzu::CommandContext& ctx, std::string_view action);
int collect_windows_policy(yuzu::CommandContext& ctx, std::string_view action,
                           std::string_view data_dir);

/// Writes the rows and the one status every leg reports (PERMISSION_DENIED only
/// when nothing existing was readable -- see select_status). `action_prefix` is
/// this action's row prefix (`action_row_prefix(...)`), needed only for the
/// fallback row below -- every OTHER row already carries it via `c.rows`.
/// A non-OK status with no collected rows (every source failed before producing
/// one, e.g. a pwpolicy spawn error) still writes ONE fallback row naming the
/// reason, in this plugin's own 4-field `<action>|status|<state>|<reason>` shape
/// (matching every other row this plugin emits -- NOT the Windows leg's separate
/// 2-field `constrained|<token>` diagnostic shape, which is a different wire
/// contract for a leg that never goes through this function). The routed
/// concern's "a refused read is permission_denied, never an empty result"
/// applies to the wire output, not just the status field, and every sibling
/// plugin in this diff pairs a non-OK status with an explicit row.
///
/// Today the fallback is reachable ONLY from the macOS pwpolicy path, and only with
/// state `constrained`: every file-backed source pairs each denial/failure with its
/// own row as it records it, so `collect_file_policy` returns empty rows with a non-OK
/// status only from its unreachable `unsupported_action` guard, and the pwpolicy path
/// never reports PERMISSION_DENIED (a refused run is not distinguishable from any other
/// non-zero exit). The `permission_denied`
/// arm below is therefore defensive; the docs describe the status row as
/// `constrained` only. That matters for the `sudoers` action, whose normal row is 7
/// fields, not 4 -- if a future file-source failure is ever counted WITHOUT emitting
/// its row, this fallback would write a 4-field row into a 7-field contract. Keep the
/// pairing, or give this function the action-shaped fallback before you break it.
/// No direct test pins this specific pairing: the empty-rows fallback (the `if (c.rows.empty())`
/// arms below) is reachable only from a real pwpolicy subprocess failure, which
/// LocalDispatcher-based tests can't force deterministically, and a bare CommandContext
/// can't be cheaply constructed outside that harness for a standalone call. The `sudoers.d`
/// truncation arm was the one site that counted without emitting, and it no longer does.
inline int apply_collected(yuzu::CommandContext& ctx, const Collected& c,
                           std::string_view action_prefix) {
    for (const auto& r : c.rows) ctx.write_output(r);
    switch (c.status) {
    case PolicyStatus::Ok:
        ctx.set_result_status(YUZU_RESULT_STATUS_OK, YUZU_RESULT_COMPLETENESS_FULL, "");
        break;
    case PolicyStatus::PermissionDenied:
        spdlog::warn("local_security_policy: permission denied ({})",
                     yuzu::util::safe_output_field(c.reason));
        ctx.set_result_status(YUZU_RESULT_STATUS_PERMISSION_DENIED, YUZU_RESULT_COMPLETENESS_PARTIAL,
                              c.reason);
        if (c.rows.empty())
            ctx.write_output(format_kv_row(action_prefix, "status", "permission_denied", c.reason));
        break;
    case PolicyStatus::Constrained:
        spdlog::warn("local_security_policy: degraded read ({})",
                     yuzu::util::safe_output_field(c.reason));
        ctx.set_result_status(YUZU_RESULT_STATUS_CONSTRAINED, YUZU_RESULT_COMPLETENESS_PARTIAL,
                              c.reason);
        if (c.rows.empty())
            ctx.write_output(format_kv_row(action_prefix, "status", "constrained", c.reason));
        break;
    }
    return 0;
}

#if !defined(_WIN32)

/// Bounded regular-file read. On the non-strict path symlinks ARE followed:
/// /etc/pam.d/system-auth is a symlink into /etc/authselect on RHEL-family hosts (real capture,
/// fedora:40); all paths are under /etc. `strict` (the sudoers sources, see is_sudoers_source)
/// is the opposite: the leaf is opened O_NOFOLLOW (a link is kReadSymlink) and the opened object
/// must be owned by `owner_uid` (uid 0 in production) and not group/other-writable
/// (kReadInsecure; stricter than sudo), so a planted link or a loose file can never be read back to a
/// Security:Read caller as policy content. Only the LEAF is checked: a symlinked parent
/// directory is followed (root-owned /etc is the trust anchor).
///
/// O_NONBLOCK is LOAD-BEARING, the same way certificates_linux_store.hpp's
/// read_cert_entry and guardian_state_reader.cpp's state read say it is: open(2)
/// on a FIFO with no writer blocks forever, and the S_ISREG check below cannot
/// run until open returns, so a blocking open would wedge the dispatch thread
/// before the type filter ever got to reject the node. On the non-strict path a followed
/// symlink means the node need not sit under /etc itself. Once fstat proves
/// S_ISREG the flag is inert (POSIX: reads of a regular file never block), so
/// nothing clears it afterwards and no real host behaves differently.
inline FileRead posix_read_file_at(const std::string& path, bool strict,
                                   uid_t owner_uid = kSudoersOwnerUid) {
    yuzu::agent::ScopedFd fd(
        ::open(path.c_str(), O_RDONLY | O_NONBLOCK | O_CLOEXEC | (strict ? O_NOFOLLOW : 0)));
    if (!fd) return {strict && errno == ELOOP ? kReadSymlink : errno, {}};
    struct stat st{};
    if (::fstat(fd.get(), &st) != 0) return {errno, {}};
    if (!S_ISREG(st.st_mode)) return {kReadNotRegular, {}};
    if (strict && (st.st_uid != owner_uid || (st.st_mode & (S_IWGRP | S_IWOTH)) != 0))
        return {kReadInsecure, {}};
    FileRead out;
    char buf[8192];
    for (;;) {
        const ssize_t n = ::read(fd.get(), buf, sizeof(buf));
        if (n < 0) {
            if (errno == EINTR) continue;
            return {errno, {}};
        }
        if (n == 0) break;
        out.data.append(buf, static_cast<std::size_t>(n));
        if (out.data.size() > kMaxFileBytes) return {kReadOversized, {}};
    }
    return out;
}

/// The production reader: sudoers sources strict, everything else lenient. `root` and
/// `sudoers_owner_uid` exist so a test can drive this exact routing over a temporary tree
/// (`<root>/etc/sudoers.d/x`) as any user; production passes neither (real /etc, uid 0).
inline FileReader make_posix_reader(std::string root = {},
                                    uid_t sudoers_owner_uid = kSudoersOwnerUid) {
    return [root = std::move(root), sudoers_owner_uid](const std::string& path) {
        return posix_read_file_at(root + path, is_sudoers_source(path), sudoers_owner_uid);
    };
}

inline DirList posix_list_dir(const std::string& path) {
    DirList out;
    DIR* d = ::opendir(path.c_str());
    if (d == nullptr) {
        out.err = errno;
        return out;
    }
    // RAII, not a bare closedir() after the walk: the callback appends to a vector, so a
    // throw between opendir and the close would leak the stream. Same three-line guard
    // autoruns_linux.cpp puts around this same shared primitive.
    struct DirGuard {
        DIR* d;
        ~DirGuard() {
            if (d) ::closedir(d);
        }
    } guard{d};
    const auto walk = yuzu::shared::walk_dir_capped(d, kMaxDirEntries, [&](const dirent* e) {
        out.names.emplace_back(e->d_name);
        return true;
    });
    out.truncated = walk.truncated;
    if (walk.enumeration_error) out.err = EIO;
    std::sort(out.names.begin(), out.names.end());
    return out;
}

#endif // !_WIN32

#if defined(__APPLE__)

namespace detail {

// nullopt on a CFStringGetCString conversion failure, and when the rendered C string
// is shorter than the CF string's exact UTF-8 length -- an embedded U+0000, which would
// otherwise cut the value at the NUL with no defect (the caller reports nullopt as a
// malformed_* / unconvertible_key defect). Never nullopt on a merely-long string: the
// buffer is sized from the string itself (macos_console_user.hpp / peripherals_macos.cpp).
inline std::optional<std::string> cf_to_utf8(CFStringRef s) {
    const CFIndex len = CFStringGetLength(s);
    if (len == 0) return std::string{};
    const CFIndex max_size = CFStringGetMaximumSizeForEncoding(len, kCFStringEncodingUTF8) + 1;
    std::string buf(static_cast<std::size_t>(max_size), '\0');
    if (!CFStringGetCString(s, buf.data(), max_size, kCFStringEncodingUTF8)) return std::nullopt;
    CFIndex utf8_len = 0; // exact byte count; a NULL buffer only measures
    if (CFStringGetBytes(s, CFRangeMake(0, len), kCFStringEncodingUTF8, 0, false, nullptr, 0,
                         &utf8_len) != len)
        return std::nullopt;
    std::string out{buf.c_str()};
    if (out.size() != static_cast<std::size_t>(utf8_len)) return std::nullopt;
    return out;
}

/// Scalar CF value -> text; nullopt for a nested/unknown type (never guessed).
inline std::optional<std::string> cf_scalar_text(CFTypeRef v) {
    if (v == nullptr) return std::nullopt;
    if (CFGetTypeID(v) == CFStringGetTypeID()) return cf_to_utf8(static_cast<CFStringRef>(v));
    if (CFGetTypeID(v) == CFBooleanGetTypeID())
        return std::string{CFBooleanGetValue(static_cast<CFBooleanRef>(v)) ? "true" : "false"};
    if (CFGetTypeID(v) == CFNumberGetTypeID()) {
        const auto n = static_cast<CFNumberRef>(v);
        long long i = 0;
        // Returns false for a value that does not convert losslessly (a plist <real> with a
        // fractional part or out of range; `<real>12.0</real>` converts to 12), leaving `i`
        // truncated. Emitting that would be a quietly-wrong number; nullopt reaches the
        // caller as a malformed_* defect, which is the honest answer.
        if (!CFNumberGetValue(n, kCFNumberLongLongType, &i)) return std::nullopt;
        return std::to_string(i);
    }
    return std::nullopt;
}

struct CfDictEntries {
    std::vector<std::pair<std::string, CFTypeRef>> entries; // key-sorted
    bool non_string_key = false; // a key that is not a CFString was skipped -- reported, not dropped
    bool unconvertible_key = false; // a CFString key with no UTF-8 rendering -- reported, not renamed
};

inline CfDictEntries cf_dict_entries(CFDictionaryRef d) {
    CfDictEntries out;
    const CFIndex n = CFDictionaryGetCount(d);
    std::vector<const void*> keys(static_cast<std::size_t>(n)), vals(static_cast<std::size_t>(n));
    CFDictionaryGetKeysAndValues(d, keys.data(), vals.data());
    for (CFIndex i = 0; i < n; ++i) {
        if (CFGetTypeID(static_cast<CFTypeRef>(keys[i])) != CFStringGetTypeID()) {
            out.non_string_key = true;
            continue;
        }
        auto key = cf_to_utf8(static_cast<CFStringRef>(keys[i]));
        if (!key) {
            out.unconvertible_key = true;
            continue;
        }
        out.entries.emplace_back(std::move(*key), static_cast<CFTypeRef>(vals[i]));
    }
    std::sort(out.entries.begin(), out.entries.end(),
              [](const auto& a, const auto& b) { return a.first < b.first; });
    return out;
}

inline void add_defect(PwPolicyItem& it, std::string_view d) {
    if (std::find(it.defects.begin(), it.defects.end(), d) == it.defects.end())
        it.defects.emplace_back(d);
}

inline void add_key_defects(PwPolicyItem& it, const CfDictEntries& e) {
    if (e.non_string_key) add_defect(it, "non_string_key");
    if (e.unconvertible_key) add_defect(it, "unconvertible_key");
}

} // namespace detail

/// pwpolicy plist half: XML -> PwPolicyItems via CFPropertyListCreateWithData (no hand-rolled
/// scan); nullopt when CF rejects the bytes or the root is not a dictionary. Anything below the
/// root that is not in the documented shape is recorded on an item (PwPolicyItem::defects),
/// never skipped. Element keys other than policyIdentifier / policyContent / policyParameters
/// (e.g. the localised policyContentDescription dictionary) are ignored by design.
inline std::optional<std::vector<PwPolicyItem>> pwpolicy_plist_to_items(std::string_view xml) {
    yuzu::agent::ScopedCFRef<CFDataRef> data(CFDataCreate(
        kCFAllocatorDefault, reinterpret_cast<const UInt8*>(xml.data()), static_cast<CFIndex>(xml.size())));
    if (!data) return std::nullopt;
    CFErrorRef raw_err = nullptr;
    yuzu::agent::ScopedCFRef<CFPropertyListRef> plist(CFPropertyListCreateWithData(
        kCFAllocatorDefault, data.get(), kCFPropertyListImmutable, nullptr, &raw_err));
    yuzu::agent::ScopedCFRef<CFErrorRef> err(raw_err);
    if (!plist || CFGetTypeID(plist.get()) != CFDictionaryGetTypeID()) return std::nullopt;

    std::vector<PwPolicyItem> items;
    const auto root = detail::cf_dict_entries(static_cast<CFDictionaryRef>(plist.get()));
    if (root.non_string_key || root.unconvertible_key) {
        PwPolicyItem it; // no category text to name: routed to both actions
        detail::add_key_defects(it, root);
        items.push_back(std::move(it));
    }
    for (const auto& [category, value] : root.entries) {
        if (CFGetTypeID(value) != CFArrayGetTypeID()) {
            PwPolicyItem it{.category = category};
            detail::add_defect(it, "malformed_category");
            items.push_back(std::move(it));
            continue;
        }
        const auto arr = static_cast<CFArrayRef>(value);
        for (CFIndex i = 0; i < CFArrayGetCount(arr); ++i) {
            const auto el = static_cast<CFTypeRef>(CFArrayGetValueAtIndex(arr, i));
            PwPolicyItem it{.category = category};
            if (CFGetTypeID(el) != CFDictionaryGetTypeID()) {
                detail::add_defect(it, "malformed_policy");
                items.push_back(std::move(it));
                continue;
            }
            const auto fields = detail::cf_dict_entries(static_cast<CFDictionaryRef>(el));
            detail::add_key_defects(it, fields);
            for (const auto& [k, v] : fields.entries) {
                // A modelled field whose value is not a scalar CF can render (nullopt: a
                // nested dictionary/array, a date, data) is a shape defect, recorded on the
                // item -- never replaced by an ordinary-looking value. A real empty string
                // from CF comes back as an empty std::string, not nullopt.
                if (k == "policyIdentifier") {
                    if (auto t = detail::cf_scalar_text(v)) it.identifier = std::move(*t);
                    else detail::add_defect(it, "malformed_identifier");
                } else if (k == "policyContent") {
                    if (auto t = detail::cf_scalar_text(v)) {
                        it.content = std::move(*t);
                        it.has_content = true;
                    } else detail::add_defect(it, "malformed_content");
                } else if (k == "policyParameters") {
                    if (CFGetTypeID(v) != CFDictionaryGetTypeID()) {
                        detail::add_defect(it, "malformed_parameters");
                        continue;
                    }
                    const auto params = detail::cf_dict_entries(static_cast<CFDictionaryRef>(v));
                    detail::add_key_defects(it, params);
                    for (const auto& [pk, pv] : params.entries) {
                        if (auto t = detail::cf_scalar_text(pv)) it.params.emplace_back(pk, std::move(*t));
                        else detail::add_defect(it, "malformed_parameter_value");
                    }
                }
            }
            items.push_back(std::move(it));
        }
    }
    return items;
}

#else

/// Off macOS there is no CFPropertyList. The stub keeps this header's surface identical
/// on every OS; it reports failure rather than guessing a shape, and its only caller
/// (the macOS leg) would map that to `pwpolicy:plist_unparseable`.
inline std::optional<std::vector<PwPolicyItem>> pwpolicy_plist_to_items(std::string_view) {
    return std::nullopt;
}

#endif // __APPLE__

} // namespace yuzu::local_security_policy
