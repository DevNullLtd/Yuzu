#pragma once

// virtualization_wsl_parsers.hpp -- the pure core of the virtualization plugin's `wsl` action:
// every decision about "which WSL distributions does this machine have, per local profile"
// lives here, over an injected registry (Ops) and an injected per-profile hive-access function
// (HiveAccessFn). Header-only, portable and windows.h-free so the unit tests run on every host;
// the Windows shell (virtualization_win.cpp) supplies RealRegOps and binds HiveAccessFn to
// yuzu::win::with_user_hive.
//
// SHAPE. A profile is reached through the shared live-hive-first, offline-mount-fallback
// ladder (with_user_hive, default-on hive-file guard, process-wide offline-hive lock); this
// header never mounts anything. Inside the reached hive `read_lxss_hive` walks
// `Software\Microsoft\Windows\CurrentVersion\Lxss`: one `{GUID}` child per distribution.
//
// BOUNDS (trust boundary: the Lxss subtree is under the owning user's write access). ONE
// WalkBudget per dispatch, shared across every hive: rows and bytes are charged at COLLECTION,
// before a row is retained; `max_visited` counts every enum_key/query_value call; a value is
// never allocated past kMaxValueBytes. Each hive also has its own sub-caps (calls, rows and
// bytes): a hive that trips one ends THAT hive only (`hive_entry_cap` / `hive_row_cap`; the row
// and byte sub-caps share the one token), so one hostile hive can neither hold the offline lock
// for the whole dispatch budget nor starve the profiles after it; only the dispatch-wide caps
// (`entry_cap` / `row_cap`) stop the loop. These bound the NUMBER of registry calls made under
// the offline lock, not their duration (there is no wall-clock deadline on this action).
//
// NEVER EMITTED: BasePath, VhdFileName, ShortcutPath, TerminalProfilePath, PackageFamilyName,
// DefaultUid, KernelCommandLine, the SID (including the salted mount name, which embeds it),
// the distribution GUID. The first seven are never read; the SID (it keys the hive that is
// opened) and the GUID (the child name that is enumerated and compared with DefaultDistribution)
// are used but never put on a row, so none of the ten is ever emitted. DistributionName and
// Flavor are value-level e-mail redacted; the account is the profile-folder name (also e-mail
// redacted), `-` when unresolvable.
//
// REGISTRY LINKS. The shell opens every key with REG_OPTION_OPEN_LINK, so a planted registry
// link opens as the link object itself and is never followed; it carries none of the value names
// this walk reads. `is_link_key` DETECTS one (a `SymbolicLinkValue` value) on the Lxss key and on
// each distribution key: a link at Lxss is `lxss_link` and the profile is not counted as read, a
// link at a distribution key is `lxss_link` plus an `unknown` row. A decoy REG_SZ value of that
// name on a plain key reads the same way (constrained, never fail-open).
//
// TOKENS. Every constraint token is `windows:virtualization:wsl:<suffix>` (class (a) in
// virtualization_parsers.hpp). The suffix table is closed: see kFixedTokenSuffixes plus the
// two cause-bearing prefixes `package_` and `profile_list_`.

#include "virtualization_legs.hpp"
#include "virtualization_parsers.hpp"

#include <constraint_accumulator.hpp>
#include <email_redaction.hpp>
#include <row_byte_budget.hpp>
#include <user_profile_model.hpp>

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <functional>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <tuple>
#include <utility>
#include <vector>

namespace yuzu::virtualization::wsl {

// -- Win32 codes (mirrored; virtualization_win.cpp static_asserts each against the SDK) -------

inline constexpr long kErrorSuccess = 0;
inline constexpr long kErrorFileNotFound = 2;
inline constexpr long kErrorAccessDenied = 5;
inline constexpr long kErrorMoreData = 234;
inline constexpr long kErrorNoMoreItems = 259;
inline constexpr std::uint32_t kRegSz = 1;
inline constexpr std::uint32_t kRegDword = 4;

// -- bounds ------------------------------------------------------------------------------------

inline constexpr std::size_t kMaxValueBytes = 4096;
inline constexpr std::size_t kMaxPackageVersionBytes = 64;
inline constexpr std::size_t kDefaultMaxRows = 1024;
inline constexpr std::size_t kDefaultMaxBytes = 256 * 1024;
inline constexpr std::size_t kDefaultMaxVisited = 4096;
inline constexpr std::size_t kDefaultMaxVisitedPerHive = 512;
inline constexpr std::size_t kDefaultMaxRowsPerHive = 128;
/// An eighth of the dispatch byte budget; a real hive's rows are well under 10 KiB.
inline constexpr std::size_t kDefaultMaxBytesPerHive = 32 * 1024;

// -- tokens ------------------------------------------------------------------------------------

inline constexpr std::string_view kTokenPrefix = "windows:virtualization:wsl:";

/// Every fixed token suffix decide_wsl can emit. `package_<cause>` and `profile_list_<cause>`
/// (cause = `access_denied` or `win32_<n>`) are the only open-ended ones; kHeaderReserveBytes
/// reserves one of each at its maximum length.
inline constexpr std::array<std::string_view, 23> kFixedTokenSuffixes = {
    "hive_not_found",      "hive_privilege_missing", "hive_mount_failed",
    "hive_access_denied",  "hive_file_refused",      "hive_unload_failed",
    "hive_open_failed",    "hive_enum_failed",       "distro_open_failed",
    "lxss_link",           "value_unreadable",       "value_malformed",
    "value_oversized",     "package_malformed",      "row_cap",
    "entry_cap",           "hive_row_cap",           "hive_entry_cap",
    "profile_list_enum_failed", "profile_cap",       "profile_unreadable",
    "profile_backup_skipped",   "profile_sid_invalid",
};

/// Longest cause suffix win32_cause() can produce: "win32_" + a signed 32-bit decimal.
inline constexpr std::size_t kMaxCauseChars = 6 + 11;

[[nodiscard]] inline std::string win32_cause(long rc) {
    return rc == kErrorAccessDenied ? std::string{"access_denied"} : "win32_" + std::to_string(rc);
}

namespace detail {

constexpr std::size_t token_bytes_total() {
    std::size_t n = 0;
    for (const auto s : kFixedTokenSuffixes)
        n += kTokenPrefix.size() + s.size() + 1; // + the joining comma
    // package_<cause> and profile_list_<cause>, each once at its maximum length.
    n += kTokenPrefix.size() + std::string_view{"package_"}.size() + kMaxCauseChars + 1;
    n += kTokenPrefix.size() + std::string_view{"profile_list_"}.size() + kMaxCauseChars + 1;
    return n;
}

} // namespace detail

/// The proven maximum of the status row plus the summary row, in bytes (each + its newline).
/// status: "status|wsl|constrained|" + every token once. summary: "summary|" + four 20-digit
/// counts + a 64-byte package version escaped worst-case (every byte `|` -> `\|`) + separators.
inline constexpr std::size_t kHeaderReserveBytes =
    std::string_view{"status|wsl|constrained|"}.size() + detail::token_bytes_total() + 1 +
    std::string_view{"summary|"}.size() + 4 * (20 + 1) + 2 * kMaxPackageVersionBytes + 1;

// -- budget ------------------------------------------------------------------------------------

/// One budget per dispatch. Limits are constructor parameters (defaults = production) so a unit
/// test can prove each bound on its own; production never overrides them. The per-hive counters
/// belong to the hive being walked: `begin_hive()` resets them at the start of each hive.
struct WalkBudget {
    yuzu::shared::RowByteBudget rows;
    std::size_t max_visited;
    std::size_t max_visited_per_hive;
    std::size_t max_rows_per_hive;
    std::size_t max_bytes_per_hive;
    std::size_t visited = 0;
    std::size_t hive_visited = 0;
    std::size_t hive_rows = 0;
    std::size_t hive_bytes = 0;

    explicit WalkBudget(std::size_t max_rows = kDefaultMaxRows,
                        std::size_t max_bytes = kDefaultMaxBytes,
                        std::size_t max_visited_calls = kDefaultMaxVisited,
                        std::size_t max_visited_per_hive_calls = kDefaultMaxVisitedPerHive,
                        std::size_t max_rows_per_hive_rows = kDefaultMaxRowsPerHive,
                        std::size_t max_bytes_per_hive_bytes = kDefaultMaxBytesPerHive)
        : max_visited(max_visited_calls),
          max_visited_per_hive(max_visited_per_hive_calls),
          max_rows_per_hive(max_rows_per_hive_rows),
          max_bytes_per_hive(max_bytes_per_hive_bytes) {
        rows.max_rows = max_rows;
        rows.max_bytes = max_bytes;
        rows.add(kHeaderReserveBytes, 2); // the status + summary rows are reserved up front
    }

    /// Starts a new hive's accounting: its sub-caps count from zero.
    void begin_hive() noexcept { hive_visited = hive_rows = hive_bytes = 0; }

    /// Counts one enum_key/query_value call against the dispatch-wide cap AND the current hive's
    /// cap. False = either is reached and the call must NOT be made; `visits_exhausted()` tells
    /// which (the dispatch-wide cap wins when both are).
    [[nodiscard]] bool visit() noexcept {
        if (visited >= max_visited || hive_visited >= max_visited_per_hive)
            return false;
        ++visited;
        ++hive_visited;
        return true;
    }

    /// True once the dispatch-wide call cap is spent (every later hive would be refused too).
    [[nodiscard]] bool visits_exhausted() const noexcept { return visited >= max_visited; }

    /// True once the current hive has retained its per-hive row allowance.
    [[nodiscard]] bool hive_rows_full() const noexcept { return hive_rows >= max_rows_per_hive; }

    /// True when the current hive may not retain `row` (its bytes + the newline) without
    /// crossing its own byte allowance.
    [[nodiscard]] bool hive_bytes_exceeded_by(std::string_view row) const noexcept {
        return hive_bytes + row.size() + 1 > max_bytes_per_hive;
    }

    /// Charges one row (its bytes + the newline) before it is retained.
    [[nodiscard]] bool charge_row(std::string_view row) noexcept {
        return rows.charge(row.size() + 1);
    }
};

// -- model -------------------------------------------------------------------------------------

/// One distribution's SANITIZED output values (redaction + wire_field applied at collection, so
/// the retained bytes are the bytes that were charged).
struct DistroValues {
    std::optional<std::string> name;
    std::optional<std::string> flavor;
    std::optional<std::uint32_t> version;
    std::optional<std::uint32_t> state;
    bool is_default = false;
    bool open_failed = false;
};

struct HiveRead {
    std::string account; // wire_field'd profile-folder name, `-` when unresolvable
    std::vector<DistroValues> distros;
    bool read_ok = false; // Lxss read or absent, or opened but not examined (a cap refused the link probe); false for an open failure or a registry link
    std::vector<std::string> tokens;
};

/// One `profile|<account>|<outcome>|<detail>` row.
struct ProfileOutcome {
    std::string account;
    std::string outcome;
    std::string detail;
};

struct WslReads {
    std::optional<std::string> package_version;
    std::vector<HiveRead> hives;
    std::vector<ProfileOutcome> profile_rows;
    std::vector<std::string> tokens; // token suffixes not tied to one hive
    std::size_t profiles_not_loaded = 0;
};

/// What the injected hive-access function reports for one profile. There is deliberately no
/// mount-name field: it embeds the SID and never leaves the Windows shell (agent log only).
struct HiveAccess {
    yuzu::profiles::HiveAccessStatus status = yuzu::profiles::HiveAccessStatus::not_found;
    std::string refusal; // the hive-file guard literal when status == file_refused
    bool unload_failed = false;
    long live_open_rc = kErrorSuccess;
};

using HiveAccessFn = std::function<HiveAccess(const yuzu::profiles::ProfileInfo&,
                                              const std::function<void(void* root)>& fn)>;

// -- small pure helpers -------------------------------------------------------------------------

/// `S-1-<digits>(-<digits>)*`, at most 256 characters (copied from privacy_permissions, which
/// keeps its own copy in a plugin-local header).
[[nodiscard]] constexpr bool is_valid_sid_string(std::string_view sid) noexcept {
    constexpr std::size_t kMaxSidChars = 256;
    if (sid.size() > kMaxSidChars || !sid.starts_with("S-1-"))
        return false;
    std::size_t digits = 0;
    for (std::size_t i = 4; i < sid.size(); ++i) {
        const char c = sid[i];
        if (c >= '0' && c <= '9') {
            ++digits;
        } else if (c == '-' && digits > 0) {
            digits = 0;
        } else {
            return false;
        }
    }
    return digits > 0;
}

/// `{8-4-4-4-12}` hex, 38 characters. WSL's own non-GUID children (InstallStatus, ...) fail it.
[[nodiscard]] inline bool is_guid_shaped(std::wstring_view n) noexcept {
    if (n.size() != 38 || n.front() != L'{' || n.back() != L'}')
        return false;
    for (std::size_t i = 1; i + 1 < n.size(); ++i) {
        const wchar_t c = n[i];
        if (i == 9 || i == 14 || i == 19 || i == 24) {
            if (c != L'-')
                return false;
        } else if (!((c >= L'0' && c <= L'9') || (c >= L'a' && c <= L'f') ||
                     (c >= L'A' && c <= L'F'))) {
            return false;
        }
    }
    return true;
}

/// Redaction first (an e-mail shape becomes the placeholder), then the wire scrub/escape.
[[nodiscard]] inline std::string sanitize_text(std::string_view v) {
    if (yuzu::shared::looks_like_email_address(v))
        return wire_field(yuzu::shared::kRedactedEmailPlaceholder);
    return wire_field(v);
}

[[nodiscard]] inline std::string version_token(std::optional<std::uint32_t> v) {
    if (v && *v == 1)
        return "1";
    if (v && *v == 2)
        return "2";
    return "unknown";
}

/// The persisted `State` DWORD, labelled from the public WSL source (microsoft/WSL,
/// src/windows/service/inc/wslservice.idl, `_LxssDistributionState`): Invalid = 0, Installed = 1,
/// Running = 2, Installing = 3, Uninstalling = 4, Converting = 5, Exporting = 6, Compacting = 7.
/// DistributionRegistration.h reads the DWORD with that enum as its type. 0 (Invalid) and 2
/// (Running, a session state; whether it is ever persisted is unverified) are deliberately not
/// labelled and fall to `state_<n>`, as does any value past the enum. Only `installed` (1) has
/// been seen on a measured host.
[[nodiscard]] inline std::string state_token(std::optional<std::uint32_t> s) {
    if (!s)
        return "unknown";
    switch (*s) {
    case 1:
        return "installed";
    case 3:
        return "installing";
    case 4:
        return "uninstalling";
    case 5:
        return "converting";
    case 6:
        return "exporting";
    case 7:
        return "compacting";
    default:
        return "state_" + std::to_string(*s);
    }
}

[[nodiscard]] inline std::string format_distribution_row(std::string_view account,
                                                         const DistroValues& d) {
    std::string r = "distribution|";
    r += account;
    r += '|';
    r += d.name ? *d.name : std::string{"-"};
    r += '|';
    r += version_token(d.version);
    r += '|';
    r += state_token(d.state);
    r += '|';
    r += d.is_default ? "yes" : "no";
    r += '|';
    r += d.flavor ? *d.flavor : std::string{"-"};
    return r;
}

[[nodiscard]] inline std::string format_profile_row(const ProfileOutcome& p) {
    std::string r = "profile|";
    r += p.account;
    r += '|';
    r += p.outcome;
    r += '|';
    r += p.detail;
    return r;
}

// -- registry walk (Ops-templated, RAW: type/size/race checks live here, not in the shell) -----
//
// Ops supplies:
//   long open_key(void* parent, const wchar_t* name, void*& out)
//       RegOpenKeyExW with REG_OPTION_OPEN_LINK and KEY_READ: a registry link opens as the link
//       object itself and is never followed (is_link_key then detects it).
//   void close_key(void* key)
//   long enum_key(void* parent, std::uint32_t idx, std::wstring& name)
//   long query_value(void* key, const wchar_t* name, std::uint32_t& type,
//                    std::span<std::byte> buf, std::uint32_t& size)   empty buf = size probe
//   std::string utf8(std::wstring_view)
//   std::string reg_sz_utf8(std::span<const std::byte> payload)
//       payload.data() is wchar_t-aligned (read_string_value hands it a heap vector).

template <class Ops>
class ScopedKey {
public:
    explicit ScopedKey(Ops& ops) noexcept : ops_(ops) {}
    ~ScopedKey() {
        if (key_)
            ops_.close_key(key_);
    }
    ScopedKey(const ScopedKey&) = delete;
    ScopedKey& operator=(const ScopedKey&) = delete;

    [[nodiscard]] long open(void* parent, const wchar_t* name) {
        if (key_) {
            ops_.close_key(key_);
            key_ = nullptr;
        }
        return ops_.open_key(parent, name, key_);
    }
    [[nodiscard]] void* get() const noexcept { return key_; }

private:
    Ops& ops_;
    void* key_ = nullptr;
};

enum class ValueResult { ok, absent, malformed, oversized, unreadable, budget };

struct StringRead {
    ValueResult result = ValueResult::absent;
    std::string value; // raw UTF-8, valid only when result == ok
    long rc = kErrorSuccess;
};

struct DwordRead {
    ValueResult result = ValueResult::absent;
    std::uint32_t value = 0;
    long rc = kErrorSuccess;
};

/// REG_SZ, size-probe then fill. Never allocates past kMaxValueBytes.
template <class Ops>
[[nodiscard]] StringRead read_string_value(Ops& ops, void* key, const wchar_t* name,
                                           WalkBudget& budget) {
    StringRead r;
    if (!budget.visit()) {
        r.result = ValueResult::budget;
        return r;
    }
    std::uint32_t type = 0, size = 0;
    r.rc = ops.query_value(key, name, type, {}, size);
    if (r.rc == kErrorFileNotFound) {
        r.result = ValueResult::absent;
        return r;
    }
    if (r.rc != kErrorSuccess) {
        r.result = ValueResult::unreadable;
        return r;
    }
    if (size > kMaxValueBytes) {
        r.result = ValueResult::oversized;
        return r;
    }
    if (type != kRegSz) {
        r.result = ValueResult::malformed;
        return r;
    }
    if (size == 0) {
        r.result = ValueResult::ok;
        return r;
    }
    if (!budget.visit()) {
        r.result = ValueResult::budget;
        return r;
    }
    std::vector<std::byte> buf(size);
    std::uint32_t sz = size;
    r.rc = ops.query_value(key, name, type, std::span<std::byte>{buf}, sz);
    if (r.rc != kErrorSuccess || type != kRegSz) {
        // MORE_DATA (the value grew between the two calls) is a race, never a truncated read.
        r.result = ValueResult::unreadable;
        return r;
    }
    r.value = ops.reg_sz_utf8(
        std::span<const std::byte>{buf.data(), (std::min)(std::size_t{sz}, buf.size())});
    r.result = ValueResult::ok;
    return r;
}

/// REG_DWORD, one call into a 4-byte buffer.
template <class Ops>
[[nodiscard]] DwordRead read_dword_value(Ops& ops, void* key, const wchar_t* name,
                                         WalkBudget& budget) {
    DwordRead r;
    if (!budget.visit()) {
        r.result = ValueResult::budget;
        return r;
    }
    std::array<std::byte, 4> buf{};
    std::uint32_t type = 0, size = static_cast<std::uint32_t>(buf.size());
    r.rc = ops.query_value(key, name, type, std::span<std::byte>{buf}, size);
    if (r.rc == kErrorFileNotFound) {
        r.result = ValueResult::absent;
    } else if (r.rc == kErrorMoreData) {
        r.result = ValueResult::malformed; // larger than a DWORD
    } else if (r.rc != kErrorSuccess) {
        r.result = ValueResult::unreadable;
    } else if (type != kRegDword || size != buf.size()) {
        r.result = ValueResult::malformed;
    } else {
        r.value = static_cast<std::uint32_t>(buf[0]) | (static_cast<std::uint32_t>(buf[1]) << 8) |
                  (static_cast<std::uint32_t>(buf[2]) << 16) |
                  (static_cast<std::uint32_t>(buf[3]) << 24);
        r.result = ValueResult::ok;
    }
    return r;
}

/// What one registry-link probe found.
enum class LinkProbe { plain, link, unreadable, refused };

/// Is `key` a registry link? One charged size-probe of the `SymbolicLinkValue` value (the marker
/// the registry plugin's own link probe reads): present with any type = a link (or a decoy value
/// of that name, which is treated the same way: constrained, never fail-open), absent = a plain
/// key, any other failure = `unreadable` (reported, and the key is then read as a plain one).
/// `refused` = the call budget would not allow the probe, which was not made. The key was opened
/// with REG_OPTION_OPEN_LINK, so a link here is the link object itself, never its target.
template <class Ops>
[[nodiscard]] LinkProbe is_link_key(Ops& ops, void* key, WalkBudget& budget) {
    if (!budget.visit())
        return LinkProbe::refused;
    std::uint32_t type = 0, size = 0;
    const long rc = ops.query_value(key, L"SymbolicLinkValue", type, {}, size);
    if (rc == kErrorSuccess)
        return LinkProbe::link;
    return rc == kErrorFileNotFound ? LinkProbe::plain : LinkProbe::unreadable;
}

namespace detail {

inline const char* value_token(ValueResult r) noexcept {
    switch (r) {
    case ValueResult::malformed:
        return "value_malformed";
    case ValueResult::oversized:
        return "value_oversized";
    case ValueResult::unreadable:
        return "value_unreadable";
    case ValueResult::ok:
    case ValueResult::absent:
    case ValueResult::budget:
        break;
    }
    return nullptr;
}

/// Push-if-absent: a hostile hive repeating one defect thousands of times still yields ONE token,
/// so a HiveRead's token vector can never outgrow the closed suffix table.
inline void add_token(std::vector<std::string>& tokens, std::string_view t) {
    if (std::find(tokens.begin(), tokens.end(), t) == tokens.end())
        tokens.emplace_back(t);
}

inline void note_value(HiveRead& h, ValueResult r) {
    if (const char* t = value_token(r))
        add_token(h.tokens, t);
}

inline constexpr const wchar_t* kLxssPath = L"Software\\Microsoft\\Windows\\CurrentVersion\\Lxss";
inline constexpr const wchar_t* kMsiPath =
    L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Lxss\\MSI";

} // namespace detail

/// Walks one reached hive's Lxss key. `stop` is set only when a DISPATCH-WIDE cap refuses
/// something; a per-hive cap ends this hive alone (`hive_entry_cap` / `hive_row_cap`).
template <class Ops>
[[nodiscard]] HiveRead read_lxss_hive(Ops& ops, void* root, std::string account,
                                      WalkBudget& budget, bool& stop) {
    HiveRead h;
    h.account = std::move(account);
    budget.begin_hive();

    // A refused visit() is the dispatch-wide cap (stop the loop) or this hive's own (end this hive
    // only); the refused call is never made.
    const auto on_visit_refused = [&] {
        if (budget.visits_exhausted()) {
            detail::add_token(h.tokens, "entry_cap");
            stop = true;
        } else {
            detail::add_token(h.tokens, "hive_entry_cap");
        }
    };

    ScopedKey<Ops> lxss(ops);
    const long open_rc = lxss.open(root, detail::kLxssPath);
    if (open_rc == kErrorFileNotFound) {
        h.read_ok = true; // a profile with no WSL
        return h;
    }
    if (open_rc != kErrorSuccess) {
        detail::add_token(h.tokens, open_rc == kErrorAccessDenied ? "hive_access_denied"
                                                                  : "hive_open_failed");
        return h;
    }

    // A link planted at Lxss opens as the link object: no values, no children, so an unprobed walk
    // would report it as a clean profile with no WSL. Detect it, never read through it.
    switch (is_link_key(ops, lxss.get(), budget)) {
    case LinkProbe::link:
        detail::add_token(h.tokens, "lxss_link");
        return h; // not read: in neither summary count, like a denied Lxss open
    case LinkProbe::refused:
        h.read_ok = true; // opened but not examined: counted, and the cap token says why
        on_visit_refused();
        return h;
    case LinkProbe::unreadable:
        detail::add_token(h.tokens, "value_unreadable");
        break;
    case LinkProbe::plain:
        break;
    }
    h.read_ok = true;

    // DefaultDistribution first, so every row carries its final default flag at collection.
    std::string default_guid;
    {
        const StringRead d = read_string_value(ops, lxss.get(), L"DefaultDistribution", budget);
        if (d.result == ValueResult::budget) {
            on_visit_refused();
            return h;
        }
        if (d.result == ValueResult::ok)
            default_guid = d.value;
        else
            detail::note_value(h, d.result);
    }

    std::wstring child;
    for (std::uint32_t idx = 0;; ++idx) {
        if (!budget.visit()) {
            on_visit_refused();
            break;
        }
        const long rc = ops.enum_key(lxss.get(), idx, child);
        if (rc == kErrorNoMoreItems)
            break;
        if (rc == kErrorMoreData)
            continue; // a name past the fixed buffer: the visit is charged, the index skipped
        if (rc != kErrorSuccess) {
            detail::add_token(h.tokens, "hive_enum_failed");
            break;
        }
        if (!is_guid_shaped(child))
            continue; // InstallStatus, AppxInstallerCache, ...: skipped silently
        if (budget.hive_rows_full()) {
            detail::add_token(h.tokens, "hive_row_cap"); // a distribution this hive may not keep
            break;
        }

        DistroValues d;
        d.is_default =
            !default_guid.empty() && yuzu::profiles::iequals_ascii(ops.utf8(child), default_guid);

        ScopedKey<Ops> dk(ops);
        const long drc = dk.open(lxss.get(), child.c_str());
        const LinkProbe lp = drc == kErrorSuccess ? is_link_key(ops, dk.get(), budget)
                                                  : LinkProbe::plain;
        if (lp == LinkProbe::refused) {
            on_visit_refused();
            break; // the unexamined distribution is discarded, never emitted
        }
        if (drc != kErrorSuccess) {
            d.open_failed = true;
            detail::add_token(h.tokens, "distro_open_failed");
        } else if (lp == LinkProbe::link) {
            // A link at a distribution key: the same `unknown` row as an open failure, no reads.
            d.open_failed = true;
            detail::add_token(h.tokens, "lxss_link");
        } else {
            if (lp == LinkProbe::unreadable)
                detail::add_token(h.tokens, "value_unreadable");
            const StringRead name = read_string_value(ops, dk.get(), L"DistributionName", budget);
            const DwordRead ver = read_dword_value(ops, dk.get(), L"Version", budget);
            const DwordRead st = read_dword_value(ops, dk.get(), L"State", budget);
            const StringRead flavor = read_string_value(ops, dk.get(), L"Flavor", budget);
            if (name.result == ValueResult::budget || ver.result == ValueResult::budget ||
                st.result == ValueResult::budget || flavor.result == ValueResult::budget) {
                on_visit_refused();
                break; // the half-read distribution is discarded, never emitted
            }
            if (name.result == ValueResult::ok)
                d.name = sanitize_text(name.value);
            if (flavor.result == ValueResult::ok)
                d.flavor = sanitize_text(flavor.value);
            if (ver.result == ValueResult::ok)
                d.version = ver.value;
            if (st.result == ValueResult::ok)
                d.state = st.value;
            for (const ValueResult r : {name.result, ver.result, st.result, flavor.result})
                detail::note_value(h, r);
        }

        const std::string row = format_distribution_row(h.account, d);
        if (budget.hive_bytes_exceeded_by(row)) {
            detail::add_token(h.tokens, "hive_row_cap"); // this hive's byte allowance: end it alone
            break;
        }
        if (!budget.charge_row(row)) {
            detail::add_token(h.tokens, "row_cap");
            stop = true;
            break;
        }
        ++budget.hive_rows;
        budget.hive_bytes += row.size() + 1;
        h.distros.push_back(std::move(d));
    }
    return h;
}

/// HKLM `...\Lxss\MSI` `Version`. Absent = no WSL package record (no token); anything else that
/// stops a clean read is a token. Over kMaxPackageVersionBytes is `package_malformed`.
template <class Ops>
void read_package_version(Ops& ops, void* hklm, WalkBudget& budget, WslReads& out) {
    ScopedKey<Ops> msi(ops);
    const long rc = msi.open(hklm, detail::kMsiPath);
    if (rc == kErrorFileNotFound)
        return;
    if (rc != kErrorSuccess) {
        out.tokens.push_back("package_" + win32_cause(rc));
        return;
    }
    const StringRead v = read_string_value(ops, msi.get(), L"Version", budget);
    switch (v.result) {
    case ValueResult::ok:
        if (v.value.size() > kMaxPackageVersionBytes)
            out.tokens.emplace_back("package_malformed");
        else if (!v.value.empty()) // an empty Version is "unavailable", not a failure
            out.package_version = wire_field(v.value);
        break;
    case ValueResult::absent:
        break;
    case ValueResult::malformed:
    case ValueResult::oversized:
        out.tokens.emplace_back("package_malformed");
        break;
    case ValueResult::unreadable:
        out.tokens.push_back("package_" + win32_cause(v.rc));
        break;
    case ValueResult::budget:
        out.tokens.emplace_back("entry_cap");
        break;
    }
}

// -- ProfileList end classification --------------------------------------------------------------

enum class ProfileListEnd { complete, enum_failed, cap };

/// How the capped ProfileList enumeration ended. `last_rc` ended the loop (NO_MORE_ITEMS is the
/// only clean stop; SUCCESS = the loop stopped at the cap alone); `probe_rc` is the extra
/// enumeration run only at the cap: NO_MORE_ITEMS = exactly the cap (complete), SUCCESS = more
/// exist (cap), anything else = the probe itself failed, never read as complete.
[[nodiscard]] constexpr ProfileListEnd classify_profile_list_end(long last_rc,
                                                                 long probe_rc) noexcept {
    if (last_rc == kErrorNoMoreItems)
        return ProfileListEnd::complete;
    if (last_rc != kErrorSuccess)
        return ProfileListEnd::enum_failed;
    if (probe_rc == kErrorNoMoreItems)
        return ProfileListEnd::complete;
    if (probe_rc == kErrorSuccess)
        return ProfileListEnd::cap;
    return ProfileListEnd::enum_failed;
}

/// The whole-source token ProfileList discovery contributes (nullopt: every profile enumerated).
[[nodiscard]] inline std::optional<std::string> profile_list_token(long root_rc, long last_rc,
                                                                   long probe_rc) {
    if (root_rc != kErrorSuccess)
        return "profile_list_" + win32_cause(root_rc);
    switch (classify_profile_list_end(last_rc, probe_rc)) {
    case ProfileListEnd::complete:
        return std::nullopt;
    case ProfileListEnd::enum_failed:
        return std::string{"profile_list_enum_failed"};
    case ProfileListEnd::cap:
        return std::string{"profile_cap"};
    }
    return std::string{"profile_list_enum_failed"};
}

// -- collection ----------------------------------------------------------------------------------

namespace detail {

/// Charges and keeps one profile row; a refusal is `row_cap` + stop (counts stay truthful).
inline void add_profile_row(WslReads& out, WalkBudget& budget, bool& stop, std::string account,
                            std::string_view outcome, std::string detail,
                            std::string_view token) {
    ProfileOutcome p{std::move(account), std::string{outcome},
                     detail.empty() ? std::string{"-"} : std::move(detail)};
    add_token(out.tokens, token);
    if (!budget.charge_row(format_profile_row(p))) {
        add_token(out.tokens, "row_cap");
        stop = true;
        return;
    }
    out.profile_rows.push_back(std::move(p));
}

} // namespace detail

/// The per-profile loop. Skips `.bak` entries and invalid SIDs without ever accessing them,
/// runs the injected access function for the rest, and maps every outcome. Two INDEPENDENT
/// mappings: the access status (with the one access_denied precedence rule) and unload_failed
/// (a mount left behind, whatever else happened). Stops when the shared budget says so; the
/// profiles it never reached are counted in `profiles_not_loaded` (no row: the budget is spent).
template <class Ops>
void collect_wsl(std::span<const yuzu::profiles::ProfileInfo> profiles, const HiveAccessFn& access,
                 Ops& ops, WalkBudget& budget, WslReads& out) {
    using yuzu::profiles::HiveAccessStatus;
    bool stop = false;
    for (std::size_t i = 0; i < profiles.size(); ++i) {
        if (stop) {
            out.profiles_not_loaded += profiles.size() - i;
            break;
        }
        const auto& profile = profiles[i];
        // The account is a free-text folder name: an e-mail shape is redacted like any other field.
        const std::string account = sanitize_text(profile.profile_name);

        // A ProfileImagePath that is present but unusable (zero-length, wrong type, over the cap
        // or changed under the read) sets only this flag, not a record failure: report it whatever
        // the hive access then does. The profile is still accessed, under account `-`.
        if (profile.profile_path_unreadable)
            detail::add_token(out.tokens, "profile_unreadable");

        if (yuzu::profiles::is_profile_backup_entry(profile.sid)) {
            ++out.profiles_not_loaded;
            detail::add_profile_row(out, budget, stop, account, "backup_skipped", {},
                                    "profile_backup_skipped");
            continue;
        }
        if (!is_valid_sid_string(profile.sid)) {
            ++out.profiles_not_loaded;
            detail::add_profile_row(out, budget, stop, account, "sid_invalid", {},
                                    "profile_sid_invalid");
            continue;
        }

        const HiveAccess a = access(profile, [&](void* root) {
            out.hives.push_back(read_lxss_hive(ops, root, account, budget, stop));
        });

        if (a.status != HiveAccessStatus::ok) {
            ++out.profiles_not_loaded;
            const bool refused_file = (a.status == HiveAccessStatus::file_refused);
            std::string_view outcome, token;
            if (a.live_open_rc == kErrorAccessDenied) {
                // A refused live root is the denial, whatever the offline arm then did.
                outcome = "access_denied";
                token = "hive_access_denied";
            } else {
                switch (a.status) {
                case HiveAccessStatus::not_found:
                    outcome = "not_found";
                    token = "hive_not_found";
                    break;
                case HiveAccessStatus::privilege_missing:
                    outcome = "privilege_missing";
                    token = "hive_privilege_missing";
                    break;
                case HiveAccessStatus::file_refused:
                    outcome = "file_refused";
                    token = "hive_file_refused";
                    break;
                case HiveAccessStatus::mount_failed:
                case HiveAccessStatus::ok:
                    outcome = "mount_failed";
                    token = "hive_mount_failed";
                    break;
                }
            }
            detail::add_profile_row(out, budget, stop, account, outcome,
                                    refused_file ? wire_field(a.refusal) : std::string{}, token);
        }
        if (a.unload_failed)
            detail::add_profile_row(out, budget, stop, account, "unload_failed", {},
                                    "hive_unload_failed");
    }
}

// -- decision ------------------------------------------------------------------------------------

[[nodiscard]] inline Posture decide_wsl(const WslReads& r) {
    yuzu::shared::ConstraintAccumulator acc;
    const auto add = [&](const std::string& suffix) {
        acc.add_failure(std::string{kTokenPrefix} + suffix);
    };
    for (const auto& t : r.tokens)
        add(t);
    for (const auto& h : r.hives)
        for (const auto& t : h.tokens)
            add(t);

    struct Keyed {
        std::string account, name, row;
    };
    std::vector<Keyed> dist;
    std::size_t wsl2 = 0, profiles_read = 0;
    for (const auto& h : r.hives) {
        if (h.read_ok)
            ++profiles_read;
        for (const auto& d : h.distros) {
            if (d.version && *d.version == 2)
                ++wsl2;
            dist.push_back({h.account, d.name ? *d.name : std::string{"-"},
                            format_distribution_row(h.account, d)});
        }
    }
    std::stable_sort(dist.begin(), dist.end(), [](const Keyed& a, const Keyed& b) {
        return std::tie(a.account, a.name) < std::tie(b.account, b.name);
    });

    std::vector<ProfileOutcome> prof = r.profile_rows;
    std::stable_sort(prof.begin(), prof.end(),
                     [](const ProfileOutcome& a, const ProfileOutcome& b) {
                         return std::tie(a.account, a.outcome) < std::tie(b.account, b.outcome);
                     });

    Posture p;
    p.status = acc.any_failure() ? StatusState::constrained : StatusState::supported;
    p.reason = acc.reason();
    p.rows.push_back("summary|" + std::to_string(dist.size()) + '|' + std::to_string(wsl2) + '|' +
                     std::to_string(profiles_read) + '|' + std::to_string(r.profiles_not_loaded) +
                     '|' + (r.package_version ? *r.package_version : std::string{"-"}));
    for (const auto& pr : prof)
        p.rows.push_back(format_profile_row(pr));
    for (auto& d : dist)
        p.rows.push_back(std::move(d.row));
    return p;
}

} // namespace yuzu::virtualization::wsl
