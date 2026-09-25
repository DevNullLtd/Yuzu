/**
 * browser_inventory_linux_parsers.hpp — Linux leg (P2a-2): injected-root
 * walk over per-user Chromium-family profile directories, handing each
 * file's bytes to browser_inventory_parsers.hpp's pure JSON parsers
 * (P2a-1). Takes a `root` parameter throughout (production calls with "/",
 * the unit suite points it at a materialized fixture tree) — never
 * `std::filesystem::directory_iterator`; every directory this leg opens
 * goes through the private O_NOFOLLOW open_dir/open_dir_at trichotomy below,
 * copied in SHAPE (not verbatim) from autoruns_macos.cpp:123-182
 * (open_dir_no_follow_checked/open_dir_no_follow_at_checked) and its home-
 * directory walk_dir_capped precedent at autoruns_macos.cpp:554-560
 * (collect_user_launchagents) — this package does not share autoruns' copy,
 * per this plugin's own scope boundary (P2a-2 spec: "copy the pattern, not
 * verbatim autoruns code").
 *
 * WALK SHAPE. `<root>/home/<user>` (each entry's name is the "user") plus the
 * fixed `<root>/root` home (root's own login shell). For each home, each of
 * the three known Chromium-family config dirs (~/.config/{google-chrome,
 * chromium,microsoft-edge}) is opened (absent -> nothing for that browser,
 * not a failure). Within an opened browser root exactly ONE file is read:
 * "Local State" (1 MiB cap) -> profiles_from_local_state() -> the profile
 * rows. No profile directory is opened and no file inside one is read --
 * the per-profile `extensions` action follows as its own PR (it reads Secure
 * Preferences / Preferences / Extensions/<id>/<ver>/manifest.json).
 *
 * FAILURE CONTRACT (autoruns' AC4, shared via yuzu::shared::
 * ConstraintAccumulator per this repo's binding brief): ENOENT anywhere in
 * this walk is a legitimate absence and contributes nothing; any other open/
 * read failure (EACCES from a chmod'd-000 profile dir, EBUSY, a refused
 * symlink, a non-regular leaf) is accumulated and surfaces as the leg's
 * `status|<action>|constrained|<reason>` row (browser_inventory_linux.cpp).
 * A malformed JSON file (profiles_from_local_state returning std::nullopt)
 * is treated the same way — a real
 * acquisition failure, never silently folded into "zero rows".
 *
 * PRIVACY: every JSON-derived field this leg writes onto the wire comes
 * from BrowserProfileRow (browser_inventory_parsers.hpp). The dedicated-
 * identifier half (gaia_id/user_name/gaia_name) is structural — the
 * struct simply has no such field. The e-mail-address half arrives
 * ALREADY REDACTED: `profile_dir`/`display_name` are forwarded here only
 * after `profiles_from_local_state` has replaced either field WHOLE with
 * `[redacted-email]` when it contains an e-mail-shaped substring — see
 * that header's PRIVACY CONTRACT. This leg adds no e-mail filtering of its
 * own, only `safe_output_field` escaping (including the display_name
 * exception: a NON-e-mail personal name, forwarded here as-is, CAN
 * legitimately be the signed-in account's real name — an accepted
 * residual risk, not something this leg filters). This leg's OWN row builder
 * additionally prepends the LOCAL OS/home-directory name (the walk's
 * "user") ahead of every profile row — a second deliberate, documented
 * exception (decided 2026-09-22, see the plugin's README "PRIVACY
 * CONTRACT"): it disambiguates profiles across users sharing a machine,
 * is machine-local, and is never a browsing-account identifier. Nothing
 * inside a profile directory is opened by this leg.
 *
 * WIRE GRAMMAR: every dynamic string field (home-directory name, profile
 * directory name, display name)
 * goes through yuzu::util::safe_output_field before being joined with `|` —
 * server/core/src/result_parsing.hpp's shared decoder treats an unescaped
 * trailing backslash or embedded pipe specially (routed-concerns.md "Wire
 * grammar"/X12) and this leg's inputs are host filesystem/JSON content, not
 * data this plugin controls the shape of.
 *
 * POSIX only (`#if !defined(_WIN32)`, matching agents/shared/
 * posix_dir_walk.hpp's own guard, per run-context.md X2) — the O_NOFOLLOW/
 * walk_dir_capped shell below does not exist on Windows; the portable pure
 * parsers this header BUILDS ON (browser_inventory_parsers.hpp) are not
 * guarded and compile everywhere.
 */
#pragma once

#if !defined(_WIN32)

#include "browser_inventory_parsers.hpp"

#include <yuzu/agent/scoped_fd.hpp>
#include <yuzu/string_utils.hpp>

#include <constraint_accumulator.hpp>
#include <posix_dir_walk.hpp>

#include <dirent.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>

#include <cerrno>
#include <cstddef>
#include <filesystem>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

namespace yuzu::browser_inventory::lnx {

namespace detail {

constexpr std::size_t kMaxHomeEntries = 4096;
constexpr std::size_t kMaxLocalStateBytes = 1024 * 1024;      // 1 MiB

/// Chromium-family ~/.config dir name -> this plugin's browser identifier.
struct BrowserConfigSpec {
    const char* config_dir;
    const char* browser;
};
constexpr BrowserConfigSpec kBrowserConfigRoots[] = {
    {"google-chrome", "chrome"},
    {"chromium", "chromium"},
    {"microsoft-edge", "edge"},
};

/// Fixed system-wide binary paths the "browsers" action probes for
/// presence. No version/channel detection this wave (descriptor rung 1,
/// browser_inventory_plugin.cpp) — version is always "-".
struct BrowserBinarySpec {
    const char* rel_path;
    const char* browser;
};
constexpr BrowserBinarySpec kBrowserBinaries[] = {
    {"opt/google/chrome/chrome", "chrome"},
    {"opt/microsoft/msedge/msedge", "edge"},
    {"usr/lib/chromium/chromium", "chromium"},
};

/// Move-only RAII owner for a POSIX DIR*; closes exactly once, including on
/// an early return mid-walk. Private copy of autoruns_macos.cpp's own
/// DirHandle (:74-84) — see this file's banner.
class DirHandle {
public:
    explicit DirHandle(DIR* d) noexcept : dir_(d) {}
    ~DirHandle() {
        if (dir_ != nullptr) ::closedir(dir_);
    }
    DirHandle(const DirHandle&) = delete;
    DirHandle& operator=(const DirHandle&) = delete;
    DirHandle(DirHandle&& other) noexcept : dir_(other.dir_) { other.dir_ = nullptr; }
    DirHandle& operator=(DirHandle&& other) noexcept {
        if (this != &other) {
            if (dir_ != nullptr) ::closedir(dir_);
            dir_ = other.dir_;
            other.dir_ = nullptr;
        }
        return *this;
    }
    [[nodiscard]] DIR* get() const noexcept { return dir_; }
    [[nodiscard]] bool valid() const noexcept { return dir_ != nullptr; }

private:
    DIR* dir_;
};

/// True when `err` (from open/openat/fdopendir on a path this leg walks)
/// reflects a genuinely-absent location — not a permission failure, not a
/// refused symlink, not a resource limit, not a non-directory component.
/// Every other errno is a real constraint the caller must surface. Private
/// copy of autoruns_macos.hpp's is_benign_absent_errno; see this file's
/// banner ("copy the pattern, not verbatim autoruns code").
inline bool is_benign_absent_errno(int err) noexcept { return err == ENOENT; }

/// errno -> a stable `linux:browser_inventory:<reason>` token for a
/// `constrained` status line. Only called once is_benign_absent_errno has
/// been ruled out — there is no "absent" case here.
inline std::string dir_open_constraint_token(int err) noexcept {
    switch (err) {
    case EACCES:  return "linux:browser_inventory:permission_denied";
    case ELOOP:   return "linux:browser_inventory:symlink_refused";
    case ENOTDIR: return "linux:browser_inventory:not_a_directory";
    case EBUSY:   return "linux:browser_inventory:busy";
    default:      return "linux:browser_inventory:open_failed";
    }
}

/// Outcome of an O_NOFOLLOW directory open: the handle (invalid on any
/// failure), plus whether that failure is a real constraint and, if so, a
/// reason token. `reason` is empty whenever `constrained` is false.
struct DirOpenOutcome {
    DirHandle handle;
    bool constrained = false;
    std::string reason;
};

inline DirOpenOutcome dir_open_outcome_from_fd(int fd) {
    if (fd < 0) {
        const int err = errno;
        if (is_benign_absent_errno(err)) return DirOpenOutcome{DirHandle{nullptr}, false, {}};
        return DirOpenOutcome{DirHandle{nullptr}, true, dir_open_constraint_token(err)};
    }
    DIR* d = ::fdopendir(fd);
    if (d == nullptr) {
        const int err = errno;
        ::close(fd);
        if (is_benign_absent_errno(err)) return DirOpenOutcome{DirHandle{nullptr}, false, {}};
        return DirOpenOutcome{DirHandle{nullptr}, true, dir_open_constraint_token(err)};
    }
    return DirOpenOutcome{DirHandle{d}, false, {}};
}

/// Opens `path` refusing to follow a symlink at that final component.
inline DirOpenOutcome open_dir_no_follow_checked(const std::string& path) {
    return dir_open_outcome_from_fd(::open(path.c_str(), O_RDONLY | O_DIRECTORY | O_NOFOLLOW));
}

/// Resolves exactly one path COMPONENT (`name`) via `openat(parent_fd,...)`
/// rather than a fresh `open()` on a joined path string, so an intermediate
/// component swapped for a symlink cannot escape confinement to a caller-
/// verified parent — see autoruns_macos.cpp's open_dir_no_follow_at_checked
/// banner for the full reasoning this copies.
inline DirOpenOutcome open_dir_no_follow_at_checked(int parent_fd, const char* name) {
    return dir_open_outcome_from_fd(
        ::openat(parent_fd, name, O_RDONLY | O_DIRECTORY | O_NOFOLLOW));
}

/// Outcome of a hop-by-hop, O_NOFOLLOW-confined multi-component presence
/// check: whether the leaf exists as a REGULAR file, plus whether a real
/// constraint (as opposed to benign absence) occurred anywhere along the
/// walk.
struct RegularFilePresence {
    bool present = false;
    bool constrained = false;
    std::string reason;
};

/// Presence-checks `root / rel_path` (a fixed, '/'-joined relative path;
/// `rel_path` is always a compile-time literal in this file, never
/// caller-influenced) one component at a time via openat(..., O_NOFOLLOW),
/// exactly like every other multi-component open in this file — unlike a
/// single joined-path `::stat()`, an intermediate component swapped for a
/// symlink cannot escape confinement to the previously-verified parent.
/// The leaf itself is `fstatat(..., AT_SYMLINK_NOFOLLOW)`, never followed
/// either (adversarial-review finding, 2026-09-22: the `browsers` leg's
/// presence probe previously used a single `::stat()` on the whole joined
/// path, the one open in this file NOT sharing this discipline).
inline RegularFilePresence
regular_file_present_no_follow_at(const std::filesystem::path& root, std::string_view rel_path) {
    DirOpenOutcome cur = open_dir_no_follow_checked(root.string());
    if (!cur.handle.valid())
        return cur.constrained ? RegularFilePresence{false, true, cur.reason}
                                : RegularFilePresence{false, false, {}};

    // Split rel_path on '/'; every component but the last is a directory
    // hop, the last is the leaf file to stat.
    std::vector<std::string> parts;
    std::size_t start = 0;
    for (std::size_t i = 0; i <= rel_path.size(); ++i) {
        if (i == rel_path.size() || rel_path[i] == '/') {
            if (i > start) parts.emplace_back(rel_path.substr(start, i - start));
            start = i + 1;
        }
    }
    if (parts.empty()) return RegularFilePresence{false, false, {}};

    for (std::size_t i = 0; i + 1 < parts.size(); ++i) {
        cur = open_dir_no_follow_at_checked(::dirfd(cur.handle.get()), parts[i].c_str());
        if (!cur.handle.valid())
            return cur.constrained ? RegularFilePresence{false, true, cur.reason}
                                    : RegularFilePresence{false, false, {}};
    }

    struct stat st {};
    if (::fstatat(::dirfd(cur.handle.get()), parts.back().c_str(), &st, AT_SYMLINK_NOFOLLOW) != 0) {
        const int err = errno;
        if (is_benign_absent_errno(err)) return RegularFilePresence{false, false, {}};
        return RegularFilePresence{false, true, dir_open_constraint_token(err)};
    }
    // AT_SYMLINK_NOFOLLOW means a successful stat here always describes the
    // leaf itself, never a followed target -- so a non-regular leaf is a
    // real, distinguishable outcome, not benign absence. A deliberately-
    // refused symlink previously collapsed into `present=false,
    // constrained=false`, indistinguishable from the binary genuinely not
    // existing (adversarial-review finding, 2026-09-22). Token names match
    // the existing `linux:browser_inventory:symlink_refused`/`not_regular`
    // constants this file already emits elsewhere (see
    // dir_open_constraint_token / read_file_bounded_at), and the
    // symlink-vs-other split mirrors autoruns_linux.cpp's precedent.
    if (S_ISREG(st.st_mode))
        return RegularFilePresence{true, false, {}};
    if (S_ISLNK(st.st_mode))
        return RegularFilePresence{false, true, "linux:browser_inventory:symlink_refused"};
    return RegularFilePresence{false, true, "linux:browser_inventory:not_regular"};
}

/// Outcome of a bounded per-file read: whether a REAL failure (as opposed
/// to a benign absence) occurred, and its reason token.
struct FileReadOutcome {
    bool constrained = false;
    std::string reason;
};

/// Reads `name` inside the directory backing `dir_fd`, O_NOFOLLOW at the
/// leaf, capped at `cap` bytes. Returns false with `text` left empty on any
/// failure, including benign absence (ENOENT) — `outcome.constrained`
/// distinguishes the two for the caller. A non-regular leaf (e.g. a FIFO
/// planted where a profile expects a plain file) is a real constraint, not
/// an absence. O_NONBLOCK is LOAD-BEARING (adversarial-review finding,
/// 2026-09-22, same class as certificates_linux_store.hpp's read_cert_entry
/// banner): open(2) of a FIFO with no writer blocks forever, and the
/// S_ISREG check below cannot run until open returns, so a blocking open
/// lets a planted FIFO wedge this worker before the type filter gets a
/// chance to reject it. Inert once S_ISREG is confirmed — reads of a
/// regular file never block — so no fcntl clear is needed afterward.
inline bool read_file_bounded_at(int dir_fd, const char* name, std::size_t cap, std::string& text,
                                 FileReadOutcome& outcome) {
    text.clear();
    yuzu::agent::ScopedFd fd(::openat(dir_fd, name, O_RDONLY | O_NOFOLLOW | O_NONBLOCK));
    if (!fd.valid()) {
        const int err = errno;
        if (!is_benign_absent_errno(err)) outcome = {true, dir_open_constraint_token(err)};
        return false;
    }
    struct stat st {};
    if (::fstat(fd.get(), &st) != 0) {
        const int err = errno;
        if (!is_benign_absent_errno(err)) outcome = {true, dir_open_constraint_token(err)};
        return false;
    }
    if (!S_ISREG(st.st_mode)) {
        outcome = {true, "linux:browser_inventory:not_regular"};
        return false;
    }
    // A genuinely oversized file is a size-POLICY refusal, not invalid
    // content -- silently truncating it and letting the caller's JSON
    // parse fail on the cut point reported the same
    // `linux:browser_inventory:local_state_malformed` token as actually-
    // invalid JSON, conflating two different causes (adversarial-review
    // finding, 2026-09-22; precedent: execution_artifacts_win.cpp's
    // `hive_oversized`). This function currently has exactly one caller
    // (the "Local State" read below), hence the caller-specific token name
    // — a second bounded-read consumer should parameterise this instead of
    // reusing it verbatim.
    if (static_cast<std::size_t>(st.st_size) > cap) {
        outcome = {true, "linux:browser_inventory:local_state_too_large"};
        return false;
    }
    const std::size_t want = static_cast<std::size_t>(st.st_size);
    text.resize(want);
    std::size_t total = 0;
    while (total < want) {
        const ssize_t n = ::read(fd.get(), text.data() + total, want - total);
        if (n < 0) {
            if (errno == EINTR) continue;
            const int err = errno;
            outcome = {true, dir_open_constraint_token(err)};
            text.clear();
            return false;
        }
        if (n == 0) break;
        total += static_cast<std::size_t>(n);
    }
    text.resize(total);
    return true;
}

/// Enumerates every (user, browser, browser_root_fd) triple this leg cares
/// about: each home directory under `<root>/home/*` (by directory name)
/// plus the fixed `<root>/root` home, crossed with the three known
/// Chromium-family config dirs. Absence at any level (no /home, no
/// <user>'s ~/.config, no <user>'s config dir for a given browser)
/// contributes nothing and is not a failure; any other open error is
/// accumulated into `acc` and that (user[, browser]) is skipped.
/// `on_root(user, browser, browser_root_fd)` is called synchronously with
/// an OPEN, O_NOFOLLOW-verified directory fd valid only for the duration of
/// that call — it must not be stored past it.
template <typename OnRoot>
void walk_browser_profile_roots(const std::filesystem::path& root,
                                yuzu::shared::ConstraintAccumulator& acc, OnRoot&& on_root) {
    auto visit_home = [&](const std::string& user, int home_fd) {
        DirOpenOutcome config_open = open_dir_no_follow_at_checked(home_fd, ".config");
        if (config_open.constrained) acc.add_failure(config_open.reason);
        if (!config_open.handle.valid()) return; // no ~/.config -- nothing for any browser
        const int config_fd = ::dirfd(config_open.handle.get());
        for (const auto& spec : kBrowserConfigRoots) {
            DirOpenOutcome browser_open = open_dir_no_follow_at_checked(config_fd, spec.config_dir);
            if (browser_open.constrained) acc.add_failure(browser_open.reason);
            if (!browser_open.handle.valid()) continue;
            on_root(user, std::string_view{spec.browser}, ::dirfd(browser_open.handle.get()));
        }
    };

    // A per-user home this agent's own (unprivileged) account cannot enter
    // (EACCES -- e.g. root's 0700 home, or any other account's private
    // home on a real multi-user host) IS reported as a constraint, like
    // every other denied open this leg makes (decided 2026-09-22, adversarial
    // review: an earlier draft treated this specific EACCES as benign/
    // routine and silently skipped the user, which directly contradicted
    // this plugin's own docs/agent-privilege-model.md row -- "never a
    // silently empty result"). Yes, this means CONSTRAINED is the common,
    // expected status on most real multi-user hosts, since an unprivileged
    // agent normally cannot read another account's 0700 home -- that is
    // the honest signal: "profiles" could not fully check every home, not
    // "no profiles exist." ENOENT (no such home at all) is a different,
    // genuinely benign case, unaffected by this and still folded into
    // is_benign_absent_errno inside open_dir_no_follow_at_checked itself.

    DirOpenOutcome homes_open = open_dir_no_follow_checked((root / "home").string());
    if (homes_open.constrained) acc.add_failure(homes_open.reason);
    if (homes_open.handle.valid()) {
        const int homes_fd = ::dirfd(homes_open.handle.get());
        const auto walk = yuzu::shared::walk_dir_capped(
            homes_open.handle.get(), kMaxHomeEntries, [&](const struct dirent* entry) {
                const std::string user(entry->d_name);
                DirOpenOutcome home_open = open_dir_no_follow_at_checked(homes_fd, entry->d_name);
                if (home_open.constrained) acc.add_failure(home_open.reason);
                if (home_open.handle.valid()) visit_home(user, ::dirfd(home_open.handle.get()));
                return true;
            });
        if (walk.truncated) acc.add_failure("linux:browser_inventory:row_cap:home");
        if (walk.enumeration_error) acc.add_failure("linux:browser_inventory:readdir_error:home");
    }

    DirOpenOutcome root_home_open = open_dir_no_follow_checked((root / "root").string());
    if (root_home_open.constrained) acc.add_failure(root_home_open.reason);
    if (root_home_open.handle.valid())
        visit_home("root", ::dirfd(root_home_open.handle.get()));
}

} // namespace detail

/// "browsers" action: presence-only detection of the three known Chromium-
/// family system-wide binaries. Emits one row per candidate, present or
/// not (never silently omits a candidate) -- version is always "-" (no
/// version/channel probe this wave, descriptor rung 1).
[[nodiscard]] inline std::vector<std::string>
linux_browser_rows_at(const std::filesystem::path& root, std::optional<std::string>& failure_token) {
    failure_token.reset();
    std::vector<std::string> rows;
    yuzu::shared::ConstraintAccumulator acc;
    for (const auto& spec : detail::kBrowserBinaries) {
        const auto presence = detail::regular_file_present_no_follow_at(root, spec.rel_path);
        if (presence.constrained) acc.add_failure(presence.reason);
        rows.push_back(std::string{"browser|"} + spec.browser + "|" +
                       (presence.present ? "1" : "0") + "|-");
    }
    if (acc.any_failure()) failure_token = acc.reason();
    return rows;
}

/// "profiles" action: one row per profile directory found in each present
/// browser's "Local State", across every user this leg discovers.
[[nodiscard]] inline std::vector<std::string>
linux_profile_rows_at(const std::filesystem::path& root, std::optional<std::string>& failure_token) {
    failure_token.reset();
    std::vector<std::string> rows;
    yuzu::shared::ConstraintAccumulator acc;
    detail::walk_browser_profile_roots(
        root, acc, [&](const std::string& user, std::string_view browser, int browser_root_fd) {
            std::string local_state_text;
            detail::FileReadOutcome outcome;
            detail::read_file_bounded_at(browser_root_fd, "Local State", detail::kMaxLocalStateBytes,
                                         local_state_text, outcome);
            if (outcome.constrained) {
                acc.add_failure(outcome.reason);
                return;
            }
            auto parsed = profiles_from_local_state(local_state_text);
            if (!parsed.has_value()) {
                acc.add_failure("linux:browser_inventory:local_state_malformed");
                return;
            }
            for (const auto& p : *parsed) {
                rows.push_back(std::string{"profile|"} + yuzu::util::safe_output_field(user) + "|" +
                               std::string{browser} + "|" +
                               yuzu::util::safe_output_field(p.profile_dir) + "|" +
                               yuzu::util::safe_output_field(p.display_name));
            }
        });
    if (acc.any_failure()) failure_token = acc.reason();
    return rows;
}

} // namespace yuzu::browser_inventory::lnx

#endif // !defined(_WIN32)
