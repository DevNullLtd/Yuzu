/**
 * system_hardening_parsers.hpp -- the PURE layer for system_hardening: the
 * per-OS key allowlists, the raw-value -> state mappers, the errno
 * classifier, the row formatter, and the collect loops that drive an
 * INJECTED reader. No OS call, no I/O, no platform header: the Linux/macOS
 * leg TUs supply the real reader (open/read, sysctlbyname); the unit suite
 * supplies a fake one and never spawns, sleeps or touches disk.
 *
 * ROW SCHEMA (one row per allowlisted key, always, in allowlist order):
 *   posture|<os>|<key>|<raw>|<state>
 * <state> is one of enabled, disabled, partial, unmodelled, absent,
 * unreadable. `enabled`/`disabled`/`partial` describe the HARDENING (a
 * protection that is on / off / on at a weaker level), NOT the sysctl's own
 * value: kernel.sysrq=0 is `enabled` (sysrq closed), kern.coredump=1 is
 * `disabled` (core dumps allowed). `unmodelled` = a value was read but this
 * table has no interpretation for it (the raw column still carries it).
 * `absent` (the OS definitively reports the key is not there) and `unreadable`
 * (it exists, or may exist, but the read failed) are distinct states; a failed
 * read NEVER reads as absent (the errno decides). ABSENCE IS NOT A FAILURE: an
 * optional key that is simply not present (Yama not built into the kernel, an
 * unknown sysctl oid) is the modal state on some hosts, so an `absent` row adds
 * NO reason token and does not lower the result status.
 *
 * <raw> is "-" when no value was read (absent/unreadable); an empty value that
 * WAS read (macOS kern.bootargs) is an empty column.
 *
 * REASON TOKENS (yuzu::shared::ConstraintAccumulator): one per UNREADABLE key,
 * plus one Linux backstop; an absent key adds none.
 *   <key>:eacces          -> unreadable (EACCES or EPERM) AND the run reports
 *                            PERMISSION_DENIED/PARTIAL
 *   <key>:not_regular     -> unreadable (Linux: the leaf opened but is not a
 *                            regular file -- a FIFO, device or directory)
 *   <key>:errno_<n>       -> unreadable (any other errno)
 *   proc_sys:not_visible  -> Linux only: ALL eleven keys read ENOENT on a
 *                            confirmed procfs (collect_linux_posture); every row
 *                            still reads `absent`, but the run is CONSTRAINED
 * ENOENT is the only errno that reads as `absent`, and it carries no token. The
 * Linux leg only ever hands this layer an ENOENT it has confirmed: a leaf ENOENT
 * whose nearest existing directory is not procfs arrives as ENODEV
 * (remap_enoent_for_surface below) and reads `unreadable` + `<key>:errno_19`, never
 * a clean `absent`. A leaf ENOENT whose confirmation probe was itself REFUSED
 * (EACCES/EPERM on an ancestor statfs, e.g. a seccomp or LSM syscall filter that
 * denies statfs while permitting open) is never remapped to ENODEV either --
 * resolve_leaf_errno propagates the refusal untouched, so it reads `unreadable` +
 * `<key>:eacces` like any other denial (see PERMISSION_DENIED below), not a
 * downgraded CONSTRAINED. A run whose every key is a value or `absent` therefore reports
 * OK/FULL, except that the all-absent Linux backstop reports CONSTRAINED/PARTIAL; a
 * run with an `unreadable` key reports PERMISSION_DENIED/PARTIAL when any read was
 * refused (a denial outranks every other cause), else CONSTRAINED/PARTIAL --
 * select_status below decides, for every leg.
 *
 * EMPTY IS NOT FAILED: an empty macOS kern.bootargs is a successful read of
 * an empty string (sysctlbyname size probe rc=0, len=1 -- a lone NUL); the
 * mapper defines it `enabled` (no boot-arg overrides) and it adds no token.
 * Emptiness is judged on the WHOLE value with whitespace and NULs trimmed from
 * both ends, never on its first line, so "\n-v" is not empty; the raw column
 * carries the whole value.
 */
#pragma once

#include <constraint_accumulator.hpp>

#include <yuzu/plugin.h> // YuzuResultStatus / Completeness (C ABI: no OS types)
#include <yuzu/string_utils.hpp>

#include <array>
#include <cerrno>
#include <charconv>
#include <cstddef>
#include <cstdint>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

namespace yuzu::system_hardening {

enum class PostureState { enabled, disabled, partial, unmodelled, absent, unreadable };

[[nodiscard]] constexpr std::string_view state_token(PostureState s) noexcept {
    switch (s) {
    case PostureState::enabled:    return "enabled";
    case PostureState::disabled:   return "disabled";
    case PostureState::partial:    return "partial";
    case PostureState::unmodelled: return "unmodelled";
    case PostureState::absent:     return "absent";
    case PostureState::unreadable: return "unreadable";
    }
    return "unmodelled";
}

inline constexpr std::array<std::string_view, 6> kStateTokens{
    "enabled", "disabled", "partial", "unmodelled", "absent", "unreadable"};

// ── value rules ─────────────────────────────────────────────────────────

/// Inclusive [lo, hi] integer range -> state. First matching rule wins; no
/// match is `unmodelled`.
struct ValueRule {
    std::int64_t lo;
    std::int64_t hi;
    PostureState state;
};

[[nodiscard]] constexpr PostureState apply_rules(std::span<const ValueRule> rules,
                                                 std::int64_t v) noexcept {
    for (const auto& r : rules)
        if (v >= r.lo && v <= r.hi) return r.state;
    return PostureState::unmodelled;
}

namespace rules {
using enum PostureState;

// Linux value semantics: Documentation/admin-guide/sysctl/{kernel,fs}.rst and
// Documentation/admin-guide/LSM/Yama.rst.
inline constexpr ValueRule kAslr[] = {{0, 0, disabled}, {1, 1, partial}, {2, 2, enabled}};
inline constexpr ValueRule kKptr[] = {{0, 0, disabled}, {1, 1, partial}, {2, 2, enabled}};
// Yama: 0 classic ptrace, 1 restricted to descendants (the hardened baseline),
// 2 admin-only, 3 no attach. Every non-zero level is an active restriction.
inline constexpr ValueRule kPtrace[] = {{0, 0, disabled}, {1, 3, enabled}};
inline constexpr ValueRule kBool[] = {{0, 0, disabled}, {1, 1, enabled}};
// 0 unprivileged BPF allowed; 1 locked off until reboot; 2 off but re-enableable by root.
inline constexpr ValueRule kBpf[] = {{0, 0, disabled}, {1, 2, enabled}};
// sysrq: 0 all functions off (hardened), 1 all on, 2..511 a function bitmask.
inline constexpr ValueRule kSysrq[] = {{0, 0, enabled}, {1, 1, disabled}, {2, 511, partial}};
// protected_fifos / protected_regular: 1 = restricted in world-writable sticky
// dirs, 2 = also group-writable sticky dirs.
inline constexpr ValueRule kProtectedFile[] = {{0, 0, disabled}, {1, 1, partial}, {2, 2, enabled}};
// suid_dumpable: 0 no dump (hardened), 1 debug (any dump), 2 root-readable only.
inline constexpr ValueRule kSuidDump[] = {{0, 0, enabled}, {1, 1, disabled}, {2, 2, partial}};

// kern.securelevel: -1/0 insecure, 1 secure, 2 highly secure (securelevel(7)).
inline constexpr ValueRule kSecurelevel[] = {{-1, 0, disabled}, {1, 1, partial}, {2, 2, enabled}};
// kern.coredump / kern.sugid_coredump: 1 = dumps allowed (hardening off).
inline constexpr ValueRule kCoreOff[] = {{0, 0, enabled}, {1, 1, disabled}};

} // namespace rules

// ── allowlists (the ONLY keys either leg ever reads) ────────────────────

struct LinuxKey {
    std::string_view key;
    std::string_view path;
    std::span<const ValueRule> rules;
};

// key -> path in ONE table; there is deliberately no /proc/sys walk and the
// action takes no parameters, so no request-supplied text reaches a path.
inline constexpr std::array<LinuxKey, 11> kLinuxAllowlist{{
    {"kernel.randomize_va_space", "/proc/sys/kernel/randomize_va_space", rules::kAslr},
    {"kernel.kptr_restrict", "/proc/sys/kernel/kptr_restrict", rules::kKptr},
    {"kernel.yama.ptrace_scope", "/proc/sys/kernel/yama/ptrace_scope", rules::kPtrace},
    {"kernel.dmesg_restrict", "/proc/sys/kernel/dmesg_restrict", rules::kBool},
    {"kernel.unprivileged_bpf_disabled", "/proc/sys/kernel/unprivileged_bpf_disabled", rules::kBpf},
    {"kernel.sysrq", "/proc/sys/kernel/sysrq", rules::kSysrq},
    {"fs.protected_hardlinks", "/proc/sys/fs/protected_hardlinks", rules::kBool},
    {"fs.protected_symlinks", "/proc/sys/fs/protected_symlinks", rules::kBool},
    {"fs.protected_fifos", "/proc/sys/fs/protected_fifos", rules::kProtectedFile},
    {"fs.protected_regular", "/proc/sys/fs/protected_regular", rules::kProtectedFile},
    {"fs.suid_dumpable", "/proc/sys/fs/suid_dumpable", rules::kSuidDump},
}};

enum class SysctlKind { integer, string };

struct MacosKey {
    std::string_view name;
    SysctlKind kind;
    std::span<const ValueRule> rules; // integer keys only
};

// kern.nx is deliberately absent: `unknown oid` on Apple Silicon (ENOENT).
inline constexpr std::array<MacosKey, 4> kMacosAllowlist{{
    {"kern.securelevel", SysctlKind::integer, rules::kSecurelevel},
    {"kern.coredump", SysctlKind::integer, rules::kCoreOff},
    {"kern.sugid_coredump", SysctlKind::integer, rules::kCoreOff},
    {"kern.bootargs", SysctlKind::string, {}},
}};

// ── pure mappers ────────────────────────────────────────────────────────

/// The WHOLE value with ASCII whitespace (newlines included) and NULs trimmed from both ends.
/// Never cut at the first line: content after a newline is part of the value, so it can neither
/// be hidden from the mapper nor dropped from the raw column. Every allowlisted Linux key is one
/// integer plus one trailing '\n', so a kernel-emitted value trims exactly as before; a
/// multi-line value (only possible from a forged leaf) now fails the strict integer parse
/// (`unmodelled`) instead of being judged on its first line.
[[nodiscard]] inline std::string_view trimmed_value(std::string_view data) noexcept {
    const auto ws = [](char c) {
        return c == ' ' || c == '\t' || c == '\r' || c == '\n' || c == '\v' || c == '\f' || c == '\0';
    };
    while (!data.empty() && ws(data.front())) data.remove_prefix(1);
    while (!data.empty() && ws(data.back())) data.remove_suffix(1);
    return data;
}

/// Strict base-10 integer: the whole (trimmed) value or nullopt.
[[nodiscard]] inline std::optional<std::int64_t> parse_int(std::string_view raw) noexcept {
    raw = trimmed_value(raw);
    std::int64_t v = 0;
    const auto* end = raw.data() + raw.size();
    const auto [p, ec] = std::from_chars(raw.data(), end, v);
    if (raw.empty() || ec != std::errc{} || p != end) return std::nullopt;
    return v;
}

[[nodiscard]] inline PostureState evaluate_linux(std::string_view key, std::string_view raw) noexcept {
    for (const auto& k : kLinuxAllowlist) {
        if (k.key != key) continue;
        const auto v = parse_int(raw);
        return v ? apply_rules(k.rules, *v) : PostureState::unmodelled;
    }
    return PostureState::unmodelled;
}

[[nodiscard]] inline PostureState evaluate_macos_int(std::string_view name, std::int64_t v) noexcept {
    for (const auto& k : kMacosAllowlist)
        if (k.name == name && k.kind == SysctlKind::integer) return apply_rules(k.rules, v);
    return PostureState::unmodelled;
}

/// Only kern.bootargs is a string sysctl. Empty (the whole value, whitespace and NULs trimmed)
/// = a successful read of "no boot-arg overrides" = enabled. A non-empty value is not interpreted
/// (boot args are an open vocabulary): unmodelled, raw column carries it -- including a value
/// whose overrides follow a leading newline or NUL.
[[nodiscard]] inline PostureState evaluate_macos_string(std::string_view name,
                                                        std::string_view raw) noexcept {
    if (name == "kern.bootargs")
        return trimmed_value(raw).empty() ? PostureState::enabled : PostureState::unmodelled;
    return PostureState::unmodelled;
}

// ── errno classification ────────────────────────────────────────────────

/// Only ENOENT means the key is not there; every other errno (EACCES, EPERM,
/// EIO, ...) is a failed read of a key that may well exist.
[[nodiscard]] constexpr PostureState classify_read_errno(int err) noexcept {
    return err == ENOENT ? PostureState::absent : PostureState::unreadable;
}

/// The read outcome of a leaf that OPENED but is not a regular file (a FIFO, character or block
/// device, directory, socket). Negative, so it can never collide with a real errno (all
/// positive): it classifies `unreadable`, is never a denial, and failure_token spells it
/// `<key>:not_regular`.
inline constexpr int kErrNotRegular = -1;

/// POSIX file-type bits (S_IFMT / S_IFREG) as plain numbers so this header stays free of
/// <sys/stat.h>; system_hardening_linux.cpp static_asserts both against the system header.
inline constexpr std::uint32_t kModeTypeMask = 0170000;
inline constexpr std::uint32_t kModeRegular = 0100000;

/// Decides whether an opened Linux leaf may be read, from its fstat() `st_mode`: 0 for a
/// regular file (every /proc/sys leaf is one), kErrNotRegular for anything else. The Linux leg
/// opens with O_NONBLOCK so a FIFO or device mounted at an allowlisted path returns from open()
/// at once, and never read()s a non-regular file -- a FIFO with no writer or a blocking device
/// would otherwise pin an agent worker indefinitely, and a device's bytes (NULs, non-UTF-8)
/// would reach the row. (A hung filesystem is a different case this cannot bound; see the
/// Linux leg's banner.)
[[nodiscard]] constexpr int opened_leaf_error(std::uint32_t st_mode) noexcept {
    return (st_mode & kModeTypeMask) == kModeRegular ? 0 : kErrNotRegular;
}

/// A leaf ENOENT is only evidence that a key is absent when the pseudo-filesystem it lives
/// on is actually there. `/proc/sys` hidden or replaced by the runtime (a `ProcSubset=pid`
/// mount, a container or chroot that does not expose it, a tmpfs overmount) turns EVERY read
/// into ENOENT without saying anything about the host's hardening, so an unconfirmed surface
/// remaps ENOENT to ENODEV: `unreadable` + `<key>:errno_19`, never a clean `absent`. Every
/// other errno passes through untouched. `surface_mounted` is surface_is_procfs() below, run by
/// the Linux leg with the real statfs(); this function is the errno half of that decision. The
/// sibling platform_security plugin applies the same rule to efivarfs/securityfs.
[[nodiscard]] constexpr int remap_enoent_for_surface(int err, bool surface_mounted) noexcept {
    return (err == ENOENT && !surface_mounted) ? ENODEV : err;
}

inline constexpr std::string_view kProcSysRoot = "/proc/sys";

/// The directories whose filesystem decides whether a leaf ENOENT is trustworthy, nearest
/// first: the leaf's parent, then each ancestor up to and including /proc/sys. surface_is_procfs
/// statfs()es them in order and trusts the FIRST that exists, so an overmount of a subtree (a
/// tmpfs over /proc/sys/kernel) is caught, while a directory that is legitimately missing
/// (kernel/yama without Yama built in) defers to its procfs parent. A path outside /proc/sys
/// yields just /proc/sys.
[[nodiscard]] inline std::vector<std::string> surface_probe_dirs(std::string_view leaf_path) {
    std::vector<std::string> dirs;
    const bool under_root = leaf_path.size() > kProcSysRoot.size() &&
                            leaf_path.starts_with(kProcSysRoot) &&
                            leaf_path[kProcSysRoot.size()] == '/';
    if (under_root) {
        std::string_view dir = leaf_path.substr(0, leaf_path.rfind('/'));
        while (dir.size() > kProcSysRoot.size()) {
            dirs.emplace_back(dir);
            dir = dir.substr(0, dir.rfind('/'));
        }
    }
    dirs.emplace_back(kProcSysRoot);
    return dirs;
}

/// linux/magic.h's ABI-stable PROC_SUPER_MAGIC, as a plain number (no kernel header here).
inline constexpr std::uint64_t kProcSuperMagic = 0x9fa0;

/// One statfs() answer, as the injected callable reports it: rc 0 = success with `f_type`;
/// otherwise `err` is the errno.
struct StatfsOutcome {
    int rc = 0;
    int err = 0;
    std::uint64_t f_type = 0;
};

/// EACCES/EPERM: the read was refused. The one pair failure_token spells `:eacces`
/// and select_status turns into PERMISSION_DENIED.
[[nodiscard]] constexpr bool is_denied_errno(int err) noexcept {
    return err == EACCES || err == EPERM;
}

/// The result of confirming the surface a leaf ENOENT arrived on. `refused_errno` is non-zero
/// (EACCES or EPERM) exactly when the confirmation probe itself -- not the leaf -- was refused;
/// that case is never "unconfirmed", it is a denial the caller must propagate as-is, so
/// `confirmed_procfs` carries no meaning when `refused_errno != 0`.
struct SurfaceCheck {
    bool confirmed_procfs = false;
    int refused_errno = 0;
};

/// Confirms whether the nearest EXISTING directory above `leaf` (surface_probe_dirs order,
/// stopping at /proc/sys) is a procfs mount. `statfs_dir(const std::string& dir) -> StatfsOutcome`
/// is the real statfs() in the Linux leg and a fake in the unit suite. The walk trusts the FIRST
/// directory that exists (so a tmpfs over /proc/sys/kernel is caught even with /proc/sys itself
/// procfs) and skips only a missing directory (ENOENT: kernel/yama without Yama defers to its
/// procfs parent). A REFUSED probe (EACCES/EPERM) stops the walk and reports the refusal --
/// distinct from "confirmed not procfs" -- so the caller never downgrades a denial to an
/// unconfirmed surface; any other statfs failure, or nothing existing up to /proc/sys, answers
/// not-confirmed with no refusal, never guessed true. At most surface_probe_dirs(leaf).size()
/// calls, never a directory outside /proc/sys.
template <typename StatfsFn>
[[nodiscard]] SurfaceCheck surface_is_procfs(std::string_view leaf, StatfsFn&& statfs_dir) {
    for (const auto& dir : surface_probe_dirs(leaf)) {
        const StatfsOutcome s = statfs_dir(dir);
        if (s.rc == 0) return {s.f_type == kProcSuperMagic, 0};
        if (s.err == ENOENT) continue;
        return {false, is_denied_errno(s.err) ? s.err : 0};
    }
    return {false, 0};
}

/// The errno a leaf open() failure resolves to, once the surface check (run only when the leaf
/// itself reported ENOENT) is in hand. A non-ENOENT open() errno returns untouched: the surface
/// was never consulted, so it never reaches remap_enoent_for_surface. A refused surface probe
/// reports ITS OWN refusal untouched -- never remapped, never downgraded to "unconfirmed" --
/// because a denial is the strongest signal available and collapsing it into ENODEV is exactly
/// the false-CONSTRAINED-instead-of-PERMISSION_DENIED defect this function exists to close. Only
/// a non-refused surface outcome (confirmed procfs, or nothing confirmed) reaches
/// remap_enoent_for_surface, unchanged from before.
[[nodiscard]] constexpr int resolve_leaf_errno(int open_errno, SurfaceCheck surface) noexcept {
    if (open_errno != ENOENT) return open_errno;
    if (surface.refused_errno != 0) return surface.refused_errno;
    return remap_enoent_for_surface(open_errno, surface.confirmed_procfs);
}

/// The reason token of a FAILED read: `<key>:eacces` | `<key>:not_regular` |
/// `<key>:errno_<n>`. Absence is not a failure: for ENOENT (classified `absent`)
/// there is no token, so the result is nullopt and nothing reaches the accumulator.
[[nodiscard]] inline std::optional<std::string> failure_token(std::string_view key, int err) {
    if (classify_read_errno(err) == PostureState::absent) return std::nullopt;
    std::string t{key};
    if (is_denied_errno(err)) t += ":eacces";
    else if (err == kErrNotRegular) t += ":not_regular";
    else t += ":errno_" + std::to_string(err);
    return t;
}

// ── rows ────────────────────────────────────────────────────────────────

// `os` and `key` are borrowed views into the constexpr allowlists / literals, never owned.
struct PostureRow {
    std::string_view os;
    std::string_view key;
    std::string raw; // "-" when nothing was read
    PostureState state;
    int err = 0; // errno of a FAILED read (0 for a value)
};

/// `raw` with every NUL folded to a space. write_output() hands the row across the plugin ABI
/// as a C string, so an embedded NUL would cut the row short (losing the state column);
/// safe_output_field folds newlines the same way but passes NUL through.
[[nodiscard]] inline std::string fold_nuls(std::string_view raw) {
    std::string out{raw};
    for (auto& c : out)
        if (c == '\0') c = ' ';
    return out;
}

[[nodiscard]] inline std::string format_posture_row(const PostureRow& r) {
    std::string out = "posture|";
    out += r.os;   // fixed vocabulary: "linux" / "macos" / "windows"
    out += '|';
    out += r.key;  // allowlist literal
    out += '|';
    out += yuzu::util::safe_output_field(fold_nuls(r.raw)); // OS-supplied text
    out += '|';
    out += state_token(r.state);
    return out;
}

/// The one row `execute()` writes after an internal error: the same five fields as every posture
/// row, so a schema-driven consumer maps it like any other (`os` is the host leg, the cause sits in
/// `key`, nothing was read). `os` is one of the fixed vocabulary, never OS-supplied text.
[[nodiscard]] inline std::string format_internal_error_row(std::string_view os) {
    std::string out = "constrained|";
    out += os;
    out += "|internal_error|-|";
    out += state_token(PostureState::unreadable);
    return out;
}

// ── collect loops over an injected reader ───────────────────────────────

/// What a reader returns. err == 0: a successful read (Linux `text`; macOS
/// `ival` for integer keys, `text` for string keys). err != 0: the read
/// failed with that errno and the value fields are ignored.
struct ReadOutcome {
    int err = 0;
    std::int64_t ival = 0;
    std::string text;
};

/// A read that returned errno `err`: an `absent` row with NO token for ENOENT,
/// otherwise an `unreadable` row whose one token is recorded in `acc` (the only
/// thing that can move the result status off OK/FULL).
[[nodiscard]] inline PostureRow failed_row(std::string_view os, std::string_view key, int err,
                                           yuzu::shared::ConstraintAccumulator& acc) {
    if (const auto token = failure_token(key, err)) acc.add_failure(*token);
    return {os, key, "-", classify_read_errno(err), err};
}

// ── status selection (pure; the one decision every leg shares) ──────────

[[nodiscard]] inline bool any_denied(std::span<const PostureRow> rows) noexcept {
    for (const auto& r : rows)
        if (is_denied_errno(r.err)) return true;
    return false;
}

struct PostureStatus {
    YuzuResultStatus status;
    YuzuResultCompleteness completeness;
    std::string provenance;
};

/// PERMISSION_DENIED/PARTIAL when any read was refused (a denial outranks every other
/// cause), else CONSTRAINED/PARTIAL when any token exists, else OK/FULL with no provenance.
[[nodiscard]] inline PostureStatus select_status(const yuzu::shared::ConstraintAccumulator& acc,
                                                 bool denied) {
    if (denied)
        return {YUZU_RESULT_STATUS_PERMISSION_DENIED, YUZU_RESULT_COMPLETENESS_PARTIAL,
                acc.reason()};
    if (acc.any_failure())
        return {YUZU_RESULT_STATUS_CONSTRAINED, YUZU_RESULT_COMPLETENESS_PARTIAL, acc.reason()};
    return {YUZU_RESULT_STATUS_OK, YUZU_RESULT_COMPLETENESS_FULL, {}};
}

/// `read(path)` -> ReadOutcome. One row per kLinuxAllowlist entry, in order.
///
/// Canary (a backstop): any ONE key legitimately not existing is a real, per-key `absent`
/// (some kernels lack `kernel.yama.ptrace_scope`, for instance, and that alone is not
/// suspicious). ALL ELEVEN keys reading ENOENT together is a different fact -- it means
/// `/proc/sys` itself is not the tree this plugin expects, not that every hardening knob
/// coincidentally vanished. The Linux leg already remaps ENOENT from an unconfirmed surface
/// (remap_enoent_for_surface), so a hidden /proc/sys -- `ProcSubset=pid`, a masked or tmpfs
/// /proc/sys -- arrives here as ENODEV (`errno_19`) and never as ENOENT; the canary fires only
/// when every leaf is ENOENT on a CONFIRMED procfs. That aggregate case adds one
/// `proc_sys:not_visible` token so the result downgrades to CONSTRAINED; it does not change any
/// individual row, which is still reporting a true fact (so the run is CONSTRAINED with zero
/// `unreadable` rows).
template <typename Reader>
[[nodiscard]] std::vector<PostureRow> collect_linux_posture(Reader&& read,
                                                            yuzu::shared::ConstraintAccumulator& acc) {
    std::vector<PostureRow> rows;
    rows.reserve(kLinuxAllowlist.size());
    std::size_t enoent_count = 0;
    for (const auto& k : kLinuxAllowlist) {
        const ReadOutcome o = read(k.path);
        if (o.err != 0) {
            if (o.err == ENOENT) ++enoent_count;
            rows.push_back(failed_row("linux", k.key, o.err, acc));
            continue;
        }
        std::string raw{trimmed_value(o.text)};
        const auto state = evaluate_linux(k.key, raw);
        rows.push_back({"linux", k.key, std::move(raw), state});
    }
    if (enoent_count == kLinuxAllowlist.size())
        acc.add_failure("proc_sys:not_visible");
    return rows;
}

/// `read(name, kind)` -> ReadOutcome. One row per kMacosAllowlist entry.
template <typename Reader>
[[nodiscard]] std::vector<PostureRow> collect_macos_posture(Reader&& read,
                                                            yuzu::shared::ConstraintAccumulator& acc) {
    std::vector<PostureRow> rows;
    rows.reserve(kMacosAllowlist.size());
    for (const auto& k : kMacosAllowlist) {
        const ReadOutcome o = read(k.name, k.kind);
        if (o.err != 0) {
            rows.push_back(failed_row("macos", k.name, o.err, acc));
            continue;
        }
        if (k.kind == SysctlKind::integer) {
            rows.push_back({"macos", k.name, std::to_string(o.ival), evaluate_macos_int(k.name, o.ival)});
        } else {
            // The whole value, untrimmed: emptiness is judged on all of it (evaluate_macos_string),
            // and the raw column carries all of it -- format_posture_row folds newlines and NULs,
            // so nothing after a leading "\n" is dropped. An empty value is a real read: the raw
            // column stays empty ("-" means "nothing read").
            const auto state = evaluate_macos_string(k.name, o.text);
            rows.push_back({"macos", k.name, o.text, state});
        }
    }
    return rows;
}

} // namespace yuzu::system_hardening
