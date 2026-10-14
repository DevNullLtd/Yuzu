/**
 * pkg_inventory_parsers.hpp — the PURE text/row layer for pkg_inventory.
 *
 * Every function here is over plain data: no OS call, no I/O, no POSIX header.
 * It compiles and is unit-tested on EVERY OS (Windows included) by an unguarded
 * test TU -- the repo's pure-core/thin-shell discipline, same shape as
 * peripherals_parsers.hpp. The O_NOFOLLOW / walk_dir_capped directory
 * primitives live in the guarded walk layer (pkg_inventory_legs.hpp, `posix::`).
 *
 * SCOPE. MACHINE-SCOPE package-manager state only: per-user package stores
 * (npm/pip/cargo/per-user Homebrew) are out of scope and deferred to the
 * user-session helper (ADR-3003). This release ships the macOS Homebrew
 * legs and the Linux `managers` (tool presence + capture-backed facts) and
 * `store_packages` (snap, flatpak) legs. Linux never reports a distro package
 * roster (installed_apps.list_inventory owns that), so Linux `packages` is
 * UNSUPPORTED by design. The Windows legs are PLANNED.
 *
 * WIRE GRAMMAR. Every action writes the status row FIRST, then data rows:
 *
 *   status|<action>|<supported|constrained|unsupported>|<tokens or ->
 *   manager|<dpkg|apt|rpm|dnf|pacman|apk|homebrew>|<present|unavailable>|<version or ->|<root_path or ->|<facts k=v;... or ->|<reason or ->
 *   package|homebrew|<id>|<version>|<formula|cask>
 *   package|<snap|flatpak>|<id>|<version or ->|<kind>|<revision or ->|<arch or ->|<branch or ->|<active|inactive|unknown>
 *
 * Every free-text field goes through yuzu::util::safe_output_field (a trailing
 * backslash or a pipe in an OS-supplied value can never shift a column).
 * `status` tokens follow the repo convention ^(windows|macos|linux):[a-z0-9_]+(:[a-z0-9_]+)*$
 * and are composed by make_token from compile-time literals; the grammar is
 * pinned by the test oracle in test_pkg_inventory_parsers.cpp. The one
 * deliberate exception is the fixed exception-firewall token
 * `pkg_inventory:exception` (kTokenException, emitted by run_guarded's firewall in
 * pkg_inventory_legs.hpp), which names no OS
 * because it reports a thrown exception, like autoruns' `autoruns:exception`.
 *
 * "FAILURE NEVER READS AS ABSENT". A genuinely absent manager/prefix yields
 * `supported` + zero data rows. A failed or unreadable read yields
 * `constrained` + a token (accumulated with yuzu::shared::ConstraintAccumulator),
 * never an empty success.
 *
 * TWO TOKEN CLASSES (store_packages). The installed-software collector fails any
 * constrained store_packages answer (a partial roster would delete server rows),
 * so a persistent per-item anomaly must never constrain the action:
 *   - PER-ITEM FIELD DEGRADATION is silent on the status row and visible on the
 *     data row: the row is still emitted with version `-` / kind `unknown` /
 *     state `unknown` or `inactive`, and the status stays `supported`.
 *   - `constrained` is reserved for LIST INCOMPLETENESS: an unlistable root or
 *     nested level, entry_cap, walk_budget, row_cap, byte_cap, busy.
 *
 * NOT IN kKeyValuePlugins: this plugin is not decoded by the server as a
 * two-cell key|rest plugin (the README states this; checked at wiring time).
 */
#pragma once

#include <yuzu/string_utils.hpp>

#include <constraint_accumulator.hpp>

#include <algorithm>
#include <cerrno>
#include <cstddef>
#include <optional>
#include <string>
#include <string_view>

namespace yuzu::pkg_inventory {

// ── limits ───────────────────────────────────────────────────────────────

/// Per-directory entry cap handed to walk_dir_capped.
inline constexpr std::size_t kMaxEntriesPerDir = 4096;
/// Whole-action package row cap (Homebrew): once reached, no further row is
/// added and the status carries `row_cap` (a later container is still opened, but
/// stops at its first version directory).
inline constexpr std::size_t kMaxPackageRows = 20000;
/// Whole-action cap on the bytes of package rows emitted (the row cap alone
/// allows ~10 MB of maximum-length names, and the command path applies no output
/// cap of its own). A real install is a few KB; beyond it no further row is
/// added and the status carries `byte_cap`.
inline constexpr std::size_t kMaxOutputBytes = 1024 * 1024;
/// Whole-ACTION entries budget across each action's entire walk (`packages`:
/// both prefixes x Cellar/Caskroom; `managers`: both prefixes x Taps, Cellar,
/// Caskroom): each directory's own listing is bounded by kMaxEntriesPerDir and
/// rows are bounded by kMaxPackageRows, but neither bounds the walk as a whole
/// -- a tree with kMaxEntriesPerDir id/org-directories x kMaxEntriesPerDir
/// entries each (or a Cellar full of plain files that never trip the row cap)
/// is otherwise read in full every call. Sized generously for a real large
/// Homebrew install.
inline constexpr std::size_t kMaxPackageWalkEntries = 200000;
/// Whole-action wall-clock budget (seconds) for the same walks.
inline constexpr std::size_t kMaxPackageWalkSeconds = 10;

/// The resource bounds as ONE injectable value. Production always uses
/// the defaults above; the unit suite passes small values so each bound (and its
/// failure token) is exercised at cap and cap+1 without building 4096 entries.
struct Limits {
    std::size_t max_entries_per_dir = kMaxEntriesPerDir;
    std::size_t max_package_rows = kMaxPackageRows;
    std::size_t max_output_bytes = kMaxOutputBytes;
    std::size_t max_walk_entries = kMaxPackageWalkEntries;
    std::size_t max_walk_seconds = kMaxPackageWalkSeconds;
};

// ── fixed vocabularies (emitted verbatim, never through safe_output_field) ──

/// The full manager-name vocabulary (a wire contract; the definition lists every
/// value). `homebrew` is emitted by the macOS leg, the other eight by the Linux
/// `managers` leg.
enum class Manager { dpkg, apt, rpm, dnf, pacman, apk, homebrew, snap, flatpak };

[[nodiscard]] constexpr std::string_view manager_name(Manager m) noexcept {
    switch (m) {
    case Manager::dpkg:     return "dpkg";
    case Manager::apt:      return "apt";
    case Manager::rpm:      return "rpm";
    case Manager::dnf:      return "dnf";
    case Manager::pacman:   return "pacman";
    case Manager::apk:      return "apk";
    case Manager::homebrew: return "homebrew";
    case Manager::snap:     return "snap";
    case Manager::flatpak:  return "flatpak";
    }
    return "dpkg";
}

/// `present`: the manager was detected and at least part of it was readable.
/// `unavailable`: detected (something exists) but nothing could be read; the
/// row's reason field carries the token. A manager that is simply not there
/// produces NO row at all.
enum class Presence { present, unavailable };

[[nodiscard]] constexpr std::string_view presence_token(Presence p) noexcept {
    switch (p) {
    case Presence::present:     return "present";
    case Presence::unavailable: return "unavailable";
    }
    return "unavailable";
}

enum class PackageKind { formula, cask };

[[nodiscard]] constexpr std::string_view package_kind_token(PackageKind k) noexcept {
    switch (k) {
    case PackageKind::formula: return "formula";
    case PackageKind::cask:    return "cask";
    }
    return "formula";
}

/// The store ecosystems of the `store_packages` action.
enum class Store { snap, flatpak };

[[nodiscard]] constexpr std::string_view store_name(Store s) noexcept {
    switch (s) {
    case Store::snap:    return "snap";
    case Store::flatpak: return "flatpak";
    }
    return "snap";
}

/// `active`: the installed revision/commit currently in use. `inactive`: present
/// on disk but not current. `unknown`: the state could not be determined.
enum class StoreState { active, inactive, unknown };

[[nodiscard]] constexpr std::string_view store_state_token(StoreState s) noexcept {
    switch (s) {
    case StoreState::active:   return "active";
    case StoreState::inactive: return "inactive";
    case StoreState::unknown:  return "unknown";
    }
    return "unknown";
}

enum class StatusLevel { supported, constrained, unsupported };

[[nodiscard]] constexpr std::string_view status_level_token(StatusLevel l) noexcept {
    switch (l) {
    case StatusLevel::supported:   return "supported";
    case StatusLevel::constrained: return "constrained";
    case StatusLevel::unsupported: return "unsupported";
    }
    return "constrained";
}

// ── tokens ───────────────────────────────────────────────────────────────

/// Fixed tokens for the by-design unsupported outcomes and the planned legs.
inline constexpr std::string_view kTokenLinuxPackagesOwned = "linux:owned_by_installed_apps";
inline constexpr std::string_view kTokenMacosStoreOwned = "macos:owned_by_installed_apps";
inline constexpr std::string_view kTokenWindowsPlanned = "windows:planned";
/// The exception firewall's fixed provenance (never the exception's own text).
inline constexpr std::string_view kTokenException = "pkg_inventory:exception";
/// The named unmodelled failure bucket of open_failure_token (EMFILE, EIO, ...).
/// It proves nothing about what is on disk, so it is never evidence a directory
/// exists.
inline constexpr std::string_view kDetailIoError = "io_error";

/// `<os>:<source>:<detail>` -- the per-location failure token. `source` names
/// the location (e.g. "apt_sources_d", "homebrew_cellar"), `detail` the
/// failure class (an open_failure_token value, "entry_cap", ...). All three
/// parts are compile-time literals at every call site.
[[nodiscard]] inline std::string make_token(std::string_view os, std::string_view source,
                                            std::string_view detail) {
    std::string t{os};
    t += ':';
    t += source;
    t += ':';
    t += detail;
    return t;
}

/// True when `err` (errno from an open/openat on a path this plugin reads)
/// means "the thing is not there". Only ENOENT is benign: every other errno is
/// a real constraint the caller must surface, never fold into zero rows.
[[nodiscard]] inline bool is_benign_absent_errno(int err) noexcept { return err == ENOENT; }

/// errno from a failed open/openat -> a stable detail token. `io_error` is the
/// named unmodelled bucket (distinct from "absent" and from every named class).
/// The walks open with O_DIRECTORY|O_NOFOLLOW, for which a symlink (to anything)
/// answers ENOTDIR, so a refused link reads `not_a_directory`; `symlink_refused`
/// (ELOOP) is a link LOOP in the path.
[[nodiscard]] inline std::string_view open_failure_token(int err) noexcept {
    switch (err) {
    case EACCES:
    case EPERM:   return "permission_denied";
    case ELOOP:   return "symlink_refused";
    case ENOTDIR: return "not_a_directory";
    default:      return kDetailIoError;
    }
}

// ── status + row formatters ──────────────────────────────────────────────
//
// Formatters take already-computed values, make no decisions and return the
// row WITHOUT a trailing newline (append_output() inserts the separator).

/// status|<action>|<level>|<tokens or ->
[[nodiscard]] inline std::string format_status_row(std::string_view action, StatusLevel level,
                                                   std::string_view tokens) {
    std::string out = "status|";
    out += yuzu::util::safe_output_field(action);
    out += '|';
    out += status_level_token(level);
    out += '|';
    out += tokens.empty() ? std::string{"-"} : yuzu::util::safe_output_field(tokens);
    return out;
}

/// status|<action>|unsupported|<token>
[[nodiscard]] inline std::string unsupported_status_row(std::string_view action,
                                                        std::string_view token) {
    return format_status_row(action, StatusLevel::unsupported, token);
}

/// Builder for the `facts` field: `k=v;k=v`, or "-" when empty. Keys and
/// values here are fixed tokens and counts by construction; the whole field
/// still goes through safe_output_field in format_manager_row.
class Facts {
public:
    void add(std::string_view key, std::string_view value) {
        if (!text_.empty()) text_ += ';';
        text_ += key;
        text_ += '=';
        text_ += value;
    }
    void add(std::string_view key, std::size_t value) { add(key, std::to_string(value)); }
    [[nodiscard]] std::string str() const { return text_.empty() ? std::string{"-"} : text_; }

private:
    std::string text_;
};

/// manager|<name>|<present|unavailable>|<version or ->|<root_path or ->|<facts or ->|<reason or ->
/// Empty `version` / `root_path` / `reason` are written as "-". `facts` is the
/// Facts::str() value ("-" when empty).
[[nodiscard]] inline std::string format_manager_row(Manager m, Presence p, std::string_view version,
                                                    std::string_view root_path,
                                                    std::string_view facts,
                                                    std::string_view reason) {
    auto field = [](std::string_view v) {
        return v.empty() ? std::string{"-"} : yuzu::util::safe_output_field(v);
    };
    std::string out = "manager|";
    out += manager_name(m);
    out += '|';
    out += presence_token(p);
    out += '|';
    out += field(version);
    out += '|';
    out += field(root_path);
    out += '|';
    out += field(facts);
    out += '|';
    out += field(reason);
    return out;
}

/// package|homebrew|<id>|<version>|<formula|cask>
[[nodiscard]] inline std::string format_package_row(std::string_view id, std::string_view version,
                                                    PackageKind kind) {
    std::string out = "package|homebrew|";
    out += yuzu::util::safe_output_field(id);
    out += '|';
    out += yuzu::util::safe_output_field(version);
    out += '|';
    out += package_kind_token(kind);
    return out;
}

/// package|<snap|flatpak>|<id>|<version or ->|<kind>|<revision or ->|<arch or ->|<branch or ->|<state>
/// Nine columns. Empty free fields are written as "-"; every free field goes
/// through safe_output_field. `kind` is a fixed token chosen by the caller
/// (snap_kind_token, or app/runtime for flatpak) and is written verbatim.
[[nodiscard]] inline std::string format_store_row(Store store, std::string_view id,
                                                  std::string_view version, std::string_view kind,
                                                  std::string_view revision, std::string_view arch,
                                                  std::string_view branch, StoreState state) {
    auto field = [](std::string_view v) {
        return v.empty() ? std::string{"-"} : yuzu::util::safe_output_field(v);
    };
    std::string out = "package|";
    out += store_name(store);
    out += '|';
    out += field(id);
    out += '|';
    out += field(version);
    out += '|';
    out += kind;
    out += '|';
    out += field(revision);
    out += '|';
    out += field(arch);
    out += '|';
    out += field(branch);
    out += '|';
    out += store_state_token(state);
    return out;
}

// ── pure name validation ─────────────────────────────────────────────────

/// True when `name` is an acceptable Homebrew directory name at the formula /
/// cask / version level (Cellar/<formula>/<version>, Caskroom/<cask>/<version>,
/// Library/Taps/<org>/<repo>): non-empty, at most 255 bytes, no leading `.`
/// (excludes `.metadata`, `.brew`, `.keepme`), and only printable ASCII other
/// than the path separator, the pipe and the wire-unsafe backslash. Cask
/// versions legitimately carry `,` and `:` (e.g. "1.2.3,456"); formulae carry
/// `@` and `+` (openssl@3, gtk+).
[[nodiscard]] inline bool version_dir_name_ok(std::string_view name) noexcept {
    if (name.empty() || name.size() > 255 || name.front() == '.') return false;
    return std::all_of(name.begin(), name.end(), [](char c) {
        const auto u = static_cast<unsigned char>(c);
        return u >= 0x20 && u < 0x7f && c != '/' && c != '\\' && c != '|';
    });
}

// ── snap / flatpak grammar (pure) ────────────────────────────────────────

/// Upper bound on the bytes read from one snap.yaml (captured files are 182-955
/// bytes). An oversized file is a silent `-`/unknown row, so the exact cap is not
/// load-bearing.
inline constexpr std::size_t kMaxSnapYamlBytes = 64 * 1024;

/// One `<name>_<revision>.snap` file of /var/lib/snapd/snaps.
struct SnapFile {
    std::string name;     ///< snap INSTANCE name == the /snap/<name> mount directory
    std::string revision; ///< `^x?[0-9]{1,10}$`
};

/// snapd's instance-name grammar (snap/naming/validate.go): a snap part of 2..40
/// bytes of [a-z0-9-] with at least one letter, no leading/trailing `-`, no `--`;
/// optionally `_` + an instance key of 1..10 [a-z0-9].
[[nodiscard]] inline bool snap_instance_name_ok(std::string_view name) noexcept {
    const auto us = name.find('_');
    const auto snap = name.substr(0, us);
    if (snap.size() < 2 || snap.size() > 40) return false;
    if (snap.front() == '-' || snap.back() == '-') return false;
    bool letter = false;
    char prev = 0;
    for (const char c : snap) {
        const bool lower = c >= 'a' && c <= 'z';
        const bool digit = c >= '0' && c <= '9';
        if (!lower && !digit && c != '-') return false;
        if (c == '-' && prev == '-') return false;
        if (lower) letter = true;
        prev = c;
    }
    if (!letter) return false;
    if (us == std::string_view::npos) return true;
    const auto key = name.substr(us + 1);
    if (key.empty() || key.size() > 10) return false;
    return std::all_of(key.begin(), key.end(), [](char c) {
        return (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9');
    });
}

/// `^x?[0-9]{1,10}$`
[[nodiscard]] inline bool snap_revision_ok(std::string_view rev) noexcept {
    if (!rev.empty() && rev.front() == 'x') rev.remove_prefix(1);
    if (rev.empty() || rev.size() > 10) return false;
    return std::all_of(rev.begin(), rev.end(), [](char c) { return c >= '0' && c <= '9'; });
}

/// `<instance>_<revision>.snap`, split at the LAST `_` (a parallel-instance file
/// `foo_bar_12.snap` is an ordinary row named `foo_bar`). nullopt for `partial`,
/// `README` and every other shape.
[[nodiscard]] inline std::optional<SnapFile> parse_snap_file_name(std::string_view file) {
    constexpr std::string_view kExt = ".snap";
    if (file.size() <= kExt.size() || file.substr(file.size() - kExt.size()) != kExt)
        return std::nullopt;
    file.remove_suffix(kExt.size());
    const auto us = file.rfind('_');
    if (us == std::string_view::npos) return std::nullopt;
    const auto name = file.substr(0, us);
    const auto rev = file.substr(us + 1);
    if (!snap_revision_ok(rev) || !snap_instance_name_ok(name)) return std::nullopt;
    return SnapFile{std::string{name}, std::string{rev}};
}

namespace detail {
[[nodiscard]] inline std::string_view trim_ws(std::string_view v) noexcept {
    constexpr std::string_view kWs = " \t\r";
    const auto b = v.find_first_not_of(kWs);
    if (b == std::string_view::npos) return {};
    return v.substr(b, v.find_last_not_of(kWs) - b + 1);
}
} // namespace detail

/// The value of the first COLUMN-0 `<key>:` line of a snap.yaml (an indented
/// `  version:` under `apps:` is not a hit). One-line scalars only:
///   - absent key or empty value                 -> nullopt
///   - quoted ('..' or "..")                     -> the text up to the closing
///                                                  quote (none -> nullopt; a `#`
///                                                  inside quotes is not a comment)
///   - starts with `|`, `>`, `[` or `{`          -> nullopt (not one line)
///   - plain scalar                              -> cut at the first ` #`/`\t#`
///                                                  (a YAML comment needs leading
///                                                  whitespace), trimmed
[[nodiscard]] inline std::optional<std::string> snap_yaml_top_level_value(std::string_view text,
                                                                          std::string_view key) {
    std::size_t pos = 0;
    while (pos <= text.size()) {
        const auto nl = text.find('\n', pos);
        const auto end = nl == std::string_view::npos ? text.size() : nl;
        const auto line = text.substr(pos, end - pos);
        pos = end + 1;
        if (line.size() <= key.size() || line.substr(0, key.size()) != key ||
            line[key.size()] != ':')
            continue;
        const auto v = detail::trim_ws(line.substr(key.size() + 1));
        if (v.empty()) return std::nullopt;
        const char c = v.front();
        if (c == '\'' || c == '"') {
            const auto close = v.find(c, 1);
            if (close == std::string_view::npos) return std::nullopt;
            return std::string{v.substr(1, close - 1)};
        }
        if (c == '|' || c == '>' || c == '[' || c == '{' || c == '#') return std::nullopt;
        auto cut = v.size();
        for (std::size_t i = 1; i < v.size(); ++i)
            if (v[i] == '#' && (v[i - 1] == ' ' || v[i - 1] == '\t')) {
                cut = i;
                break;
            }
        const auto plain = detail::trim_ws(v.substr(0, cut));
        if (plain.empty()) return std::nullopt;
        return std::string{plain};
    }
    return std::nullopt;
}

/// The snap `type:` of a snap.yaml that WAS read, as a closed token. No `type:` ->
/// `app` (snapd's default); `application` -> `app`; the snapd closed set passes
/// through; anything else is `other` (a snap author controls this text, so it never
/// reaches the wire).
[[nodiscard]] inline std::string_view snap_kind_token(std::optional<std::string_view> type) noexcept {
    if (!type) return "app";
    const auto t = *type;
    if (t == "application" || t == "app") return "app";
    for (const std::string_view known : {"gadget", "kernel", "base", "snapd", "os"})
        if (t == known) return known;
    return "other";
}

/// snapd's isValidVersion: `^[a-zA-Z0-9](?:[a-zA-Z0-9:.+~-]{0,30}[a-zA-Z0-9+~])?$`
/// (1..32 bytes), as a loop.
[[nodiscard]] inline bool snap_version_ok(std::string_view v) noexcept {
    if (v.empty() || v.size() > 32) return false;
    auto alnum = [](char c) {
        return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9');
    };
    if (!alnum(v.front())) return false;
    if (v.size() == 1) return true;
    for (std::size_t i = 1; i + 1 < v.size(); ++i)
        if (!alnum(v[i]) && v[i] != ':' && v[i] != '.' && v[i] != '+' && v[i] != '~' && v[i] != '-')
            return false;
    const char last = v.back();
    return alnum(last) || last == '+' || last == '~';
}

/// Exactly 64 lowercase hex digits (a flatpak commit checksum).
[[nodiscard]] inline bool is_hex64(std::string_view v) noexcept {
    return v.size() == 64 && std::all_of(v.begin(), v.end(), [](char c) {
               return (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f');
           });
}

} // namespace yuzu::pkg_inventory
