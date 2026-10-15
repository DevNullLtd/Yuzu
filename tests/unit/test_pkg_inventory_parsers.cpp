/**
 * test_pkg_inventory_parsers.cpp — pure text/row tests for the pkg_inventory
 * plugin (pkg_inventory_parsers.hpp) plus small injected-root walk tests for
 * the macOS Homebrew shell. This TU is UNGUARDED: the pure cases run on every
 * OS; only the walk cases (which need the POSIX shell that does not exist on
 * Windows) wrap their bodies in `#if !defined(_WIN32)`.
 *
 * No committed fixture is loaded here. The directory layouts the walk cases
 * build in code are SYNTHETIC in-code layouts (not captures, not committed
 * fixtures): they exercise the walk logic (nesting, caps, hidden names, two
 * prefixes, unreadable directories) over the layout the code ASSUMES Homebrew
 * uses. The cask, tap and Intel-prefix shapes here are that assumption, not an
 * observation: no capture host had a cask, a tap or /usr/local Homebrew
 * (README caveat 4). The Intel Library/Taps location is taken from Homebrew's
 * own scripts (HOMEBREW_DEFAULT_REPOSITORY in Library/Homebrew/utils/os.sh),
 * not from an Intel host. The real-capture tree manifest and the dispatcher test
 * are test_pkg_inventory_macos_parsers.cpp and
 * test_pkg_inventory_local_dispatcher.cpp.
 *
 * MUTATION NOTES (each names a wiring removal that would fail a case here):
 *  - dropping the macOS `/usr/local` prefix           -> "both prefixes" cases
 *  - dropping the macOS Caskroom walk                 -> casks=/cask row asserts
 *  - swallowing an open failure as zero rows          -> the constrained cases
 *  - ignoring Limits::max_entries_per_dir / max_package_rows
 *                                                     -> the cap / cap+1 cases
 *  - probing only <prefix>/Library/Taps (not <prefix>/Homebrew/Library/Taps)
 *                                                     -> the Intel taps cases
 *  - reporting a truncated listing's count as a fact  -> the managers entry_cap cases
 *  - counting an io_error (EMFILE) or a failing /usr/local root as Homebrew
 *                                                     -> the presence-evidence cases
 *  - following a symlink, or weakening the name filter, inside Cellar/Caskroom/Taps
 *                                                     -> the hostile-entries case
 *  - dropping the byte cap                            -> the byte_cap case
 */
#include <catch2/catch_test_macros.hpp>

#include "pkg_inventory_legs.hpp"
#include "pkg_inventory_macos_parsers.hpp"
#include "pkg_inventory_parsers.hpp"

#include "test_helpers.hpp" // yuzu::test::TempDir

#include <cerrno>
#include <filesystem>
#include <fstream>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

#if !defined(_WIN32)
#include <fcntl.h>
#include <sys/resource.h>
#include <sys/stat.h>
#include <unistd.h>
#endif

namespace pi = yuzu::pkg_inventory;

namespace {

/// The wire decoder's split (server/core/src/result_parsing.hpp): a backslash
/// immediately before a pipe makes it an escaped pipe, not a separator.
std::vector<std::string> split_wire(const std::string& row) {
    std::vector<std::string> fields;
    std::string cur;
    for (std::size_t i = 0; i < row.size(); ++i) {
        if (row[i] == '|' && !(i > 0 && row[i - 1] == '\\')) {
            fields.push_back(cur);
            cur.clear();
        } else {
            cur += row[i];
        }
    }
    fields.push_back(cur);
    return fields;
}

/// Test oracle for the token grammar the README/yaml document,
/// ^(windows|macos|linux):[a-z0-9_]+(:[a-z0-9_]+)*$. Production composes tokens
/// from compile-time literals (make_token) and never validates at runtime.
bool is_wellformed_token(std::string_view t) noexcept {
    const auto colon = t.find(':');
    if (colon == std::string_view::npos) return false;
    const auto os = t.substr(0, colon);
    if (os != "windows" && os != "macos" && os != "linux") return false;
    std::size_t seg_len = 0;
    std::size_t segments = 0;
    for (std::size_t i = colon + 1; i <= t.size(); ++i) {
        if (i == t.size() || t[i] == ':') {
            if (seg_len == 0) return false;
            ++segments;
            seg_len = 0;
            continue;
        }
        const char c = t[i];
        const bool ok = (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '_';
        if (!ok) return false;
        ++seg_len;
    }
    return segments >= 1;
}

} // namespace

// ── pure: tokens, status rows ────────────────────────────────────────────

TEST_CASE("pkg_inventory: tokens are wellformed and the fixed ones match the wire contract",
          "[pkg_inventory][parsers]") {
    CHECK(is_wellformed_token("linux:owned_by_installed_apps"));
    CHECK(is_wellformed_token("windows:planned"));
    CHECK(is_wellformed_token("macos:homebrew_cellar:permission_denied"));
    CHECK_FALSE(is_wellformed_token("planned"));
    CHECK_FALSE(is_wellformed_token("freebsd:planned"));
    CHECK_FALSE(is_wellformed_token("linux:"));
    CHECK_FALSE(is_wellformed_token("linux:a::b"));
    CHECK_FALSE(is_wellformed_token("linux:Upper"));
    CHECK(pi::kTokenLinuxPackagesOwned == "linux:owned_by_installed_apps");
    CHECK(pi::kTokenLinuxPlanned == "linux:planned");
    CHECK(pi::kTokenWindowsPlanned == "windows:planned");
    CHECK(is_wellformed_token(pi::kTokenLinuxPackagesOwned));
    CHECK(is_wellformed_token(pi::kTokenLinuxPlanned));
    CHECK(is_wellformed_token(pi::kTokenWindowsPlanned));
    CHECK(pi::make_token("linux", "apt_sources_d", "entry_cap") == "linux:apt_sources_d:entry_cap");
    CHECK(is_wellformed_token(pi::make_token("macos", "homebrew_taps", "io_error")));
    CHECK(is_wellformed_token(pi::make_token("macos", "homebrew_cellar", "byte_cap")));
    CHECK(is_wellformed_token(pi::make_token("macos", "managers", "busy")));
    // The one deliberate exception to the OS-prefixed grammar: the fixed
    // exception-firewall token names no OS (it reports a thrown exception).
    CHECK(pi::kTokenException == "pkg_inventory:exception");
    CHECK_FALSE(is_wellformed_token(pi::kTokenException));
    // The named unmodelled errno bucket.
    CHECK(pi::open_failure_token(EMFILE) == pi::kDetailIoError);
    CHECK(pi::open_failure_token(ENOTDIR) == "not_a_directory");
    CHECK(pi::open_failure_token(ELOOP) == "symlink_refused");
    CHECK(pi::open_failure_token(EACCES) == "permission_denied");
}

TEST_CASE("pkg_inventory: status row is supported+dash when nothing failed, constrained+tokens otherwise",
          "[pkg_inventory][parsers][status]") {
    // The decision (constrained iff any failure) lives at the emit seam
    // (emit_result) and is proven end to end by the seam cases in
    // test_pkg_inventory_macos_parsers.cpp; this pins the formatter and the
    // accumulator's exact-string dedupe + comma join.
    CHECK(pi::format_status_row("managers", pi::StatusLevel::supported, "") ==
          "status|managers|supported|-");

    yuzu::shared::ConstraintAccumulator bad;
    bad.add_failure("macos:homebrew_cellar:permission_denied");
    bad.add_failure("macos:homebrew_cellar:permission_denied"); // exact-string dedupe
    bad.add_failure("macos:homebrew_taps:entry_cap");
    CHECK(pi::format_status_row("packages", pi::StatusLevel::constrained, bad.reason()) ==
          "status|packages|constrained|"
          "macos:homebrew_cellar:permission_denied,macos:homebrew_taps:entry_cap");

    CHECK(pi::unsupported_status_row("packages", pi::kTokenLinuxPackagesOwned) ==
          "status|packages|unsupported|linux:owned_by_installed_apps");
    CHECK(pi::unsupported_status_row("managers", pi::kTokenLinuxPlanned) ==
          "status|managers|unsupported|linux:planned");
    CHECK(pi::unsupported_status_row("managers", pi::kTokenWindowsPlanned) ==
          "status|managers|unsupported|windows:planned");
}

TEST_CASE("pkg_inventory: action names round-trip and unknown names are rejected",
          "[pkg_inventory][parsers]") {
    CHECK(pi::parse_action("managers") == std::optional{pi::Action::managers});
    CHECK(pi::parse_action("packages") == std::optional{pi::Action::packages});
    CHECK_FALSE(pi::parse_action("list").has_value());
    CHECK_FALSE(pi::parse_action("").has_value());
    CHECK(pi::action_name(pi::Action::managers) == "managers");
    CHECK(pi::action_name(pi::Action::packages) == "packages");
}

TEST_CASE("pkg_inventory: errno -> token mapping keeps absence apart from every constraint",
          "[pkg_inventory][parsers][errno]") {
    CHECK(pi::is_benign_absent_errno(ENOENT));
    CHECK_FALSE(pi::is_benign_absent_errno(EACCES));
    CHECK_FALSE(pi::is_benign_absent_errno(ELOOP));
    CHECK(pi::open_failure_token(EACCES) == "permission_denied");
    CHECK(pi::open_failure_token(EPERM) == "permission_denied");
    CHECK(pi::open_failure_token(ELOOP) == "symlink_refused");
    CHECK(pi::open_failure_token(ENOTDIR) == "not_a_directory");
    // The named unmodelled bucket: distinct from absent and from every class above.
    CHECK(pi::open_failure_token(EIO) == "io_error");
}

// ── pure: row formatters + wire grammar (X12) ────────────────────────────

TEST_CASE("pkg_inventory: manager row has 7 fields and dashes for empty slots",
          "[pkg_inventory][parsers][rows]") {
    pi::Facts f;
    f.add("taps", std::size_t{3});
    f.add("formulae", std::size_t{66});
    const auto row = pi::format_manager_row(pi::Manager::homebrew, pi::Presence::present, "",
                                            "/opt/homebrew", f.str(), "");
    CHECK(row == "manager|homebrew|present|-|/opt/homebrew|taps=3;formulae=66|-");
    CHECK(split_wire(row).size() == 7);

    const auto bare = pi::format_manager_row(pi::Manager::rpm, pi::Presence::present, "", "",
                                             pi::Facts{}.str(), "");
    CHECK(bare == "manager|rpm|present|-|-|-|-");

    const auto unavailable =
        pi::format_manager_row(pi::Manager::homebrew, pi::Presence::unavailable, "", "/usr/local",
                               "-", "macos:homebrew_cellar:permission_denied");
    CHECK(unavailable ==
          "manager|homebrew|unavailable|-|/usr/local|-|macos:homebrew_cellar:permission_denied");
}

TEST_CASE("pkg_inventory: a trailing backslash or pipe in an OS value never shifts a column",
          "[pkg_inventory][parsers][rows][wire]") {
    // A trailing backslash would otherwise read as an escaped pipe and swallow
    // the separator; safe_output_field folds it to '/'.
    const auto manager = pi::format_manager_row(pi::Manager::apk, pi::Presence::present,
                                                "1.0\\", "C:\\pkgs\\", "k=v\\", "why\\");
    const auto fields = split_wire(manager);
    REQUIRE(fields.size() == 7);
    CHECK(fields[3] == "1.0/");
    CHECK(fields[4] == "C:/pkgs/");
    CHECK(fields[5] == "k=v/");
    CHECK(fields[6] == "why/");

    const auto pkg = pi::format_package_row("evil\\", "1|2\\", pi::PackageKind::cask);
    const auto pf = split_wire(pkg);
    REQUIRE(pf.size() == 5);
    CHECK(pf[0] == "package");
    CHECK(pf[1] == "homebrew");
    CHECK(pf[2] == "evil/");
    CHECK(pf[3] == "1\\|2/"); // the pipe survives as ONE escaped field character
    CHECK(pf[4] == "cask");

    const auto status = pi::format_status_row("managers", pi::StatusLevel::constrained, "a\\");
    CHECK(split_wire(status).size() == 4);
}

TEST_CASE("pkg_inventory: package row shape", "[pkg_inventory][parsers][rows]") {
    CHECK(pi::format_package_row("wget", "1.24.5", pi::PackageKind::formula) ==
          "package|homebrew|wget|1.24.5|formula");
    CHECK(pi::format_package_row("firefox", "130.0,1", pi::PackageKind::cask) ==
          "package|homebrew|firefox|130.0,1|cask");
}

TEST_CASE("pkg_inventory: production resource-bound defaults are pinned",
          "[pkg_inventory][parsers][limits]") {
    // Every cap case injects a small Limits; this is the only assertion on the
    // shipped values. MUTATION: silently shrinking, growing or unwiring any of the
    // five (Limits{} not built from its constant) fails here.
    CHECK(pi::Limits{}.max_entries_per_dir == 4096);
    CHECK(pi::Limits{}.max_package_rows == 20000);
    CHECK(pi::Limits{}.max_output_bytes == 1024 * 1024);
    CHECK(pi::Limits{}.max_walk_entries == 200000);
    CHECK(pi::Limits{}.max_walk_seconds == 10);
    CHECK(pi::kMaxEntriesPerDir == 4096);
    CHECK(pi::kMaxPackageRows == 20000);
    CHECK(pi::kMaxOutputBytes == 1024 * 1024);
    CHECK(pi::kMaxPackageWalkEntries == 200000);
    CHECK(pi::kMaxPackageWalkSeconds == 10);
}

TEST_CASE("pkg_inventory: the manager wire names are a pinned vocabulary",
          "[pkg_inventory][parsers][names]") {
    // The header calls these a wire contract and the definition lists every value,
    // although only `homebrew` is emitted today (the Linux leg follows). Pin all
    // seven so the follow-up PR cannot rename one silently.
    CHECK(pi::manager_name(pi::Manager::dpkg) == "dpkg");
    CHECK(pi::manager_name(pi::Manager::apt) == "apt");
    CHECK(pi::manager_name(pi::Manager::rpm) == "rpm");
    CHECK(pi::manager_name(pi::Manager::dnf) == "dnf");
    CHECK(pi::manager_name(pi::Manager::pacman) == "pacman");
    CHECK(pi::manager_name(pi::Manager::apk) == "apk");
    CHECK(pi::manager_name(pi::Manager::homebrew) == "homebrew");
}

// ── pure: Homebrew directory-name validation ─────────────────────────────

TEST_CASE("pkg_inventory: version_dir_name_ok accepts real Homebrew names, rejects the rest",
          "[pkg_inventory][parsers][names]") {
    for (const char* ok : {"wget", "1.24.5", "openssl@3", "gtk+", "3.3.1_1", "130.0,1",
                           "2024.09.01:abc"})
        CHECK(pi::version_dir_name_ok(ok));
    for (const char* bad : {"", ".metadata", ".keepme", ".", "..", "a/b", "a|b", "a\\b", "tab\there",
                            "nul\x01"})
        CHECK_FALSE(pi::version_dir_name_ok(bad));
    CHECK_FALSE(pi::version_dir_name_ok(std::string(256, 'a')));
    CHECK(pi::version_dir_name_ok(std::string(255, 'a')));
}

// ── walks: injected root (POSIX shell only; bodies guarded, see banner) ───

#if !defined(_WIN32)

namespace {

void write_file(const std::filesystem::path& root, const std::string& rel, const std::string& body,
                mode_t mode = 0644) {
    const auto p = root / rel;
    std::filesystem::create_directories(p.parent_path());
    {
        std::ofstream out(p, std::ios::binary);
        REQUIRE(out.good());
        out << body;
    }
    REQUIRE(::chmod(p.string().c_str(), mode) == 0);
}

void make_dir(const std::filesystem::path& root, const std::string& rel) {
    std::filesystem::create_directories(root / rel);
}

/// Restores a directory's permissions on scope exit so TempDir can remove it.
struct PermGuard {
    std::filesystem::path p;
    ~PermGuard() { ::chmod(p.string().c_str(), 0700); }
};

} // namespace

TEST_CASE("pkg_inventory walk: an absent root yields zero rows and NO constraint on the macOS shell",
          "[pkg_inventory][walk]") {
    yuzu::test::TempDir dir{"yuzu_test_pkg_inventory_absent_"};
    std::filesystem::create_directories(dir.path);

    std::optional<std::string> token;
    CHECK(pi::mac::macos_manager_rows_at(dir.path, token).empty());
    CHECK_FALSE(token.has_value());
    CHECK(pi::mac::macos_package_rows_at(dir.path, token).empty());
    CHECK_FALSE(token.has_value());

    // A root that does not exist at all is the same "nothing here", not a failure.
    CHECK(pi::mac::macos_package_rows_at(dir.path / "does_not_exist", token).empty());
    CHECK_FALSE(token.has_value());
}

TEST_CASE("pkg_inventory walk: macOS Homebrew over both prefixes",
          "[pkg_inventory][walk][macos]") {
    yuzu::test::TempDir dir{"yuzu_test_pkg_inventory_macos_"};
    const auto& r = dir.path;
    // Apple-silicon prefix
    make_dir(r, "opt/homebrew/Cellar/wget/1.24.5");
    make_dir(r, "opt/homebrew/Cellar/openssl@3/3.3.1");
    make_dir(r, "opt/homebrew/Cellar/openssl@3/3.3.2");
    make_dir(r, "opt/homebrew/Cellar/.hidden/9.9"); // dot-prefixed: skipped
    write_file(r, "opt/homebrew/Cellar/README", "a file, not a formula\n");
    write_file(r, "opt/homebrew/Cellar/wget/INSTALL_RECEIPT.json", "{}"); // file, not a version dir
    make_dir(r, "opt/homebrew/Caskroom/some-cask/1.2.3,456");
    make_dir(r, "opt/homebrew/Caskroom/some-cask/.metadata");
    make_dir(r, "opt/homebrew/Library/Taps/homebrew/homebrew-core");
    make_dir(r, "opt/homebrew/Library/Taps/homebrew/homebrew-cask");
    make_dir(r, "opt/homebrew/Library/Taps/acme/homebrew-tools");
    // Intel prefix (also present on this synthetic host)
    make_dir(r, "usr/local/Cellar/jq/1.7.1");

    std::optional<std::string> token;
    const auto managers = pi::mac::macos_manager_rows_at(r, token);
    CHECK_FALSE(token.has_value());
    REQUIRE(managers.size() == 2);
    CHECK(managers[0] == "manager|homebrew|present|-|/opt/homebrew|taps=3;formulae=2;casks=1|-");
    CHECK(managers[1] == "manager|homebrew|present|-|/usr/local|taps=0;formulae=1;casks=0|-");
    for (const auto& row : managers)
        CHECK(split_wire(row).size() == 7);

    const auto packages = pi::mac::macos_package_rows_at(r, token);
    CHECK_FALSE(token.has_value());
    const std::vector<std::string> expected{
        "package|homebrew|openssl@3|3.3.1|formula",
        "package|homebrew|openssl@3|3.3.2|formula",
        "package|homebrew|wget|1.24.5|formula",
        "package|homebrew|some-cask|1.2.3,456|cask",
        "package|homebrew|jq|1.7.1|formula",
    };
    CHECK(packages == expected);
    for (const auto& row : packages)
        CHECK(split_wire(row).size() == 5);
}

TEST_CASE("pkg_inventory walk: /usr/local without Homebrew markers is not Homebrew",
          "[pkg_inventory][walk][macos]") {
    yuzu::test::TempDir dir{"yuzu_test_pkg_inventory_macos_nobrew_"};
    make_dir(dir.path, "usr/local/bin");
    make_dir(dir.path, "usr/local/share");
    std::optional<std::string> token;
    CHECK(pi::mac::macos_manager_rows_at(dir.path, token).empty());
    CHECK_FALSE(token.has_value());
}

TEST_CASE("pkg_inventory walk: an unreadable Cellar is unavailable + constrained, not absent",
          "[pkg_inventory][walk][macos]") {
    if (::geteuid() == 0)
        SKIP("running as root (or CAP_DAC_OVERRIDE): permission bits bypassed");
    yuzu::test::TempDir dir{"yuzu_test_pkg_inventory_macos_eacces_"};
    make_dir(dir.path, "opt/homebrew/Cellar/wget/1.24.5");
    const auto cellar = dir.path / "opt/homebrew/Cellar";
    PermGuard guard{cellar};
    REQUIRE(::chmod(cellar.string().c_str(), 0000) == 0);

    std::optional<std::string> token;
    const auto managers = pi::mac::macos_manager_rows_at(dir.path, token);
    REQUIRE(token.has_value());
    CHECK(*token == "macos:homebrew_cellar:permission_denied");
    REQUIRE(managers.size() == 1);
    CHECK(managers[0] == "manager|homebrew|unavailable|-|/opt/homebrew|-|"
                         "macos:homebrew_cellar:permission_denied");

    std::optional<std::string> ptoken;
    CHECK(pi::mac::macos_package_rows_at(dir.path, ptoken).empty());
    REQUIRE(ptoken.has_value());
    CHECK(*ptoken == "macos:homebrew_cellar:permission_denied");
}

TEST_CASE("pkg_inventory walk: a symlinked Cellar is refused, never followed",
          "[pkg_inventory][walk][macos]") {
    yuzu::test::TempDir dir{"yuzu_test_pkg_inventory_macos_symlink_"};
    make_dir(dir.path, "elsewhere/wget/1.24.5");
    make_dir(dir.path, "opt/homebrew");
    std::error_code ec;
    std::filesystem::create_directory_symlink(dir.path / "elsewhere", dir.path / "opt/homebrew/Cellar", ec);
    REQUIRE_FALSE(ec);

    std::optional<std::string> token;
    const auto packages = pi::mac::macos_package_rows_at(dir.path, token);
    CHECK(packages.empty()); // the symlink target's contents must not appear
    REQUIRE(token.has_value());
    CHECK(token->find("macos:homebrew_cellar:") == 0);
}

TEST_CASE("pkg_inventory walk: macOS Cellar entry cap and package row cap (injected Limits)",
          "[pkg_inventory][walk][macos][limits]") {
    yuzu::test::TempDir dir{"yuzu_test_pkg_inventory_macos_caps_"};
    const auto& r = dir.path;
    make_dir(r, "opt/homebrew/Cellar/jq/1.7.1");
    make_dir(r, "opt/homebrew/Cellar/wget/1.24.4");
    make_dir(r, "opt/homebrew/Cellar/wget/1.24.5");

    {
        pi::Limits lim;
        lim.max_entries_per_dir = 2; // exactly the 2 formulae (jq, wget); wget has 2 versions
        std::optional<std::string> token;
        CHECK(pi::mac::macos_package_rows_at(r, token, lim).size() == 3);
        CHECK_FALSE(token.has_value()); // at the cap is complete

        make_dir(r, "opt/homebrew/Cellar/zsh/5.9"); // 3 formulae > cap 2
        const auto packages = pi::mac::macos_package_rows_at(r, token, lim);
        REQUIRE(token.has_value());
        CHECK(*token == "macos:homebrew_cellar:entry_cap");
        // The full walk yields 4 rows (jq 1, wget 2, zsh 1); a truncated listing
        // reads only 2 of the 3 formulae, so strictly fewer.
        CHECK(packages.size() < 4);
        std::filesystem::remove_all(r / "opt/homebrew/Cellar/zsh");
    }
    {
        pi::Limits lim; // row cap: 3 package rows exist
        lim.max_package_rows = 3;
        std::optional<std::string> token;
        CHECK(pi::mac::macos_package_rows_at(r, token, lim).size() == 3);
        CHECK_FALSE(token.has_value()); // at the cap is complete

        lim.max_package_rows = 2;
        const auto capped = pi::mac::macos_package_rows_at(r, token, lim);
        CHECK(capped.size() == 2);
        REQUIRE(token.has_value());
        CHECK(*token == "macos:homebrew_cellar:row_cap");
    }
}


// ── Intel layout: Library/Taps under <prefix>/Homebrew ───────────────────

TEST_CASE("pkg_inventory walk: Intel Homebrew keeps Library/Taps under <prefix>/Homebrew",
          "[pkg_inventory][walk][macos][taps]") {
    // Homebrew's REPOSITORY (the directory holding Library/) is <prefix>/Homebrew on
    // current Intel installs (HOMEBREW_DEFAULT_REPOSITORY in Library/Homebrew/utils/os.sh);
    // reading only <prefix>/Library/Taps reports taps=0 for a host that has taps.
    yuzu::test::TempDir dir{"yuzu_test_pkg_inventory_macos_intel_taps_"};
    const auto& r = dir.path;
    make_dir(r, "usr/local/Cellar/jq/1.7.1");
    make_dir(r, "usr/local/Homebrew/Library/Taps/homebrew/homebrew-core");
    make_dir(r, "usr/local/Homebrew/Library/Taps/acme/homebrew-tools");

    std::optional<std::string> token;
    const auto managers = pi::mac::macos_manager_rows_at(r, token);
    CHECK_FALSE(token.has_value());
    REQUIRE(managers.size() == 1);
    CHECK(managers[0] == "manager|homebrew|present|-|/usr/local|taps=2;formulae=1;casks=0|-");
}

TEST_CASE("pkg_inventory walk: an older Intel install keeps Library/Taps at the prefix, and the "
          "repository subdirectory wins when both exist",
          "[pkg_inventory][walk][macos][taps]") {
    {
        yuzu::test::TempDir dir{"yuzu_test_pkg_inventory_macos_flat_taps_"};
        make_dir(dir.path, "usr/local/Library/Taps/homebrew/homebrew-core");
        std::optional<std::string> token;
        const auto managers = pi::mac::macos_manager_rows_at(dir.path, token);
        CHECK_FALSE(token.has_value());
        REQUIRE(managers.size() == 1);
        CHECK(managers[0] == "manager|homebrew|present|-|/usr/local|taps=1;formulae=0;casks=0|-");
    }
    {
        yuzu::test::TempDir dir{"yuzu_test_pkg_inventory_macos_both_taps_"};
        make_dir(dir.path, "usr/local/Library/Taps/stale/homebrew-old");
        make_dir(dir.path, "usr/local/Homebrew/Library/Taps/homebrew/homebrew-core");
        make_dir(dir.path, "usr/local/Homebrew/Library/Taps/acme/homebrew-tools");
        std::optional<std::string> token;
        const auto managers = pi::mac::macos_manager_rows_at(dir.path, token);
        REQUIRE(managers.size() == 1);
        // The repository's own Taps (2), not the stale prefix-level directory (1).
        CHECK(managers[0] == "manager|homebrew|present|-|/usr/local|taps=2;formulae=0;casks=0|-");
    }
    {
        // Apple silicon is unchanged: Library/Taps sits at the prefix.
        yuzu::test::TempDir dir{"yuzu_test_pkg_inventory_macos_arm_taps_"};
        make_dir(dir.path, "opt/homebrew/Library/Taps/homebrew/homebrew-core");
        std::optional<std::string> token;
        const auto managers = pi::mac::macos_manager_rows_at(dir.path, token);
        REQUIRE(managers.size() == 1);
        CHECK(managers[0] == "manager|homebrew|present|-|/opt/homebrew|taps=1;formulae=0;casks=0|-");
    }
}

TEST_CASE("pkg_inventory walk: a Homebrew repository with no taps and no other marker is not Homebrew",
          "[pkg_inventory][walk][macos][taps]") {
    // Library/Taps is the marker, not the repository directory: an Intel host whose
    // <prefix>/Homebrew/Library holds no Taps and which has no Cellar/Caskroom has
    // no marker, so it reports nothing (and no false zero row).
    yuzu::test::TempDir dir{"yuzu_test_pkg_inventory_macos_no_taps_"};
    make_dir(dir.path, "usr/local/Homebrew/Library");
    std::optional<std::string> token;
    CHECK(pi::mac::macos_manager_rows_at(dir.path, token).empty());
    CHECK_FALSE(token.has_value());
}

// ── a truncated listing is not a fact ────────────────────────────────────

TEST_CASE("pkg_inventory walk: a truncated Cellar or Taps listing omits its count, never reports a "
          "lower bound as a fact",
          "[pkg_inventory][walk][macos][limits]") {
    {
        yuzu::test::TempDir dir{"yuzu_test_pkg_inventory_macos_trunc_cellar_"};
        make_dir(dir.path, "opt/homebrew/Cellar/jq/1.7.1");
        make_dir(dir.path, "opt/homebrew/Cellar/wget/1.24.5");
        make_dir(dir.path, "opt/homebrew/Cellar/zsh/5.9");
        pi::Limits lim;
        lim.max_entries_per_dir = 2;
        std::optional<std::string> token;
        const auto managers = pi::mac::macos_manager_rows_at(dir.path, token, lim);
        REQUIRE(token.has_value());
        CHECK(*token == "macos:homebrew_cellar:entry_cap");
        REQUIRE(managers.size() == 1);
        CHECK(managers[0] == "manager|homebrew|present|-|/opt/homebrew|taps=0;casks=0|-");
    }
    {
        yuzu::test::TempDir dir{"yuzu_test_pkg_inventory_macos_trunc_taps_"};
        for (const char* org : {"a-org", "b-org", "c-org"})
            make_dir(dir.path, std::string{"opt/homebrew/Library/Taps/"} + org + "/repo");
        pi::Limits lim;
        lim.max_entries_per_dir = 2;
        std::optional<std::string> token;
        const auto managers = pi::mac::macos_manager_rows_at(dir.path, token, lim);
        REQUIRE(token.has_value());
        CHECK(*token == "macos:homebrew_taps:entry_cap");
        REQUIRE(managers.size() == 1);
        CHECK(managers[0] == "manager|homebrew|present|-|/opt/homebrew|formulae=0;casks=0|-");
    }
}

TEST_CASE("pkg_inventory walk: note_listing names a truncated and an errored listing",
          "[pkg_inventory][walk][limits]") {
    // The readdir I/O error itself cannot be provoked deterministically on a real
    // directory, so the mapping from a DirListing to constraints is pinned purely.
    yuzu::shared::ConstraintAccumulator acc;
    pi::posix::DirListing clean;
    pi::posix::note_listing(acc, "macos", "homebrew_cellar", clean);
    CHECK_FALSE(acc.any_failure());
    CHECK_FALSE(acc.incomplete());

    pi::posix::DirListing bad;
    bad.walk.enumeration_error = true;
    bad.walk.truncated = true;
    pi::posix::note_listing(acc, "macos", "homebrew_cellar", bad);
    CHECK(acc.reason() ==
          "macos:homebrew_cellar:enumeration_error,macos:homebrew_cellar:entry_cap");
    CHECK(acc.incomplete());

    // The count-is-a-fact predicate both walks use: EITHER flag alone makes it a
    // lower bound. MUTATION: dropping either half of listing_complete survives every
    // walk case (no real readdir I/O error can be provoked) but fails here.
    pi::posix::DirListing cut;
    cut.walk.truncated = true;
    pi::posix::DirListing errored;
    errored.walk.enumeration_error = true;
    CHECK(pi::posix::listing_complete(clean));
    CHECK_FALSE(pi::posix::listing_complete(cut));
    CHECK_FALSE(pi::posix::listing_complete(errored));
}

// ── presence evidence ────────────────────────────────────────────────────

TEST_CASE("pkg_inventory walk: a /usr/local that cannot be read is not Homebrew, but a refused "
          "/opt/homebrew is",
          "[pkg_inventory][walk][macos]") {
    // /usr/local exists on every Mac, so a link, a file or an unreadable directory
    // there proves nothing; /opt/homebrew exists only when Homebrew does. Either
    // way the failure is reported, never swallowed.
    {
        yuzu::test::TempDir dir{"yuzu_test_pkg_inventory_macos_usrlocal_link_"};
        make_dir(dir.path, "elsewhere");
        make_dir(dir.path, "usr");
        std::error_code ec;
        std::filesystem::create_directory_symlink(dir.path / "elsewhere", dir.path / "usr/local", ec);
        REQUIRE_FALSE(ec);
        std::optional<std::string> token;
        CHECK(pi::mac::macos_manager_rows_at(dir.path, token).empty());
        REQUIRE(token.has_value());
        CHECK(token->find("macos:homebrew_taps:") == 0);
    }
    {
        yuzu::test::TempDir dir{"yuzu_test_pkg_inventory_macos_usrlocal_file_"};
        write_file(dir.path, "usr/local", "not a directory\n");
        std::optional<std::string> token;
        CHECK(pi::mac::macos_manager_rows_at(dir.path, token).empty());
        CHECK(token.has_value());
    }
    {
        yuzu::test::TempDir dir{"yuzu_test_pkg_inventory_macos_optbrew_file_"};
        write_file(dir.path, "opt/homebrew", "a stray file where the prefix should be\n");
        std::optional<std::string> token;
        const auto managers = pi::mac::macos_manager_rows_at(dir.path, token);
        REQUIRE(token.has_value());
        REQUIRE(managers.size() == 1);
        CHECK(managers[0].rfind("manager|homebrew|unavailable|-|/opt/homebrew|-|macos:homebrew_taps:", 0) == 0);
    }
}

namespace {

/// Burns every free fd, then hands back exactly `keep_free` of them, restoring
/// the fd limit and closing everything on scope exit.
class FdSqueeze {
public:
    explicit FdSqueeze(int keep_free) {
        ok_ = ::getrlimit(RLIMIT_NOFILE, &saved_) == 0;
        if (!ok_) return;
        int highest = -1;
        for (int fd = 0; fd < 4096; ++fd)
            if (::fcntl(fd, F_GETFD) != -1) highest = fd;
        rlimit tight = saved_;
        tight.rlim_cur = static_cast<rlim_t>(highest + 2 + keep_free);
        // Reserve before lowering the limit: a throwing push_back below would skip
        // the destructor and leave the limit lowered and the fds open.
        burned_.reserve(static_cast<std::size_t>(tight.rlim_cur));
        if (tight.rlim_cur > saved_.rlim_max || ::setrlimit(RLIMIT_NOFILE, &tight) != 0) {
            ok_ = false;
            return;
        }
        for (;;) {
            const int fd = ::open("/dev/null", O_RDONLY);
            if (fd < 0) break;
            burned_.push_back(fd);
        }
        for (int i = 0; i < keep_free && !burned_.empty(); ++i) {
            ::close(burned_.back());
            burned_.pop_back();
        }
    }
    ~FdSqueeze() {
        for (const int fd : burned_)
            ::close(fd);
        if (ok_) ::setrlimit(RLIMIT_NOFILE, &saved_);
    }
    FdSqueeze(const FdSqueeze&) = delete;
    FdSqueeze& operator=(const FdSqueeze&) = delete;
    [[nodiscard]] bool ok() const { return ok_; }

private:
    rlimit saved_{};
    bool ok_ = false;
    std::vector<int> burned_;
};

} // namespace

TEST_CASE("pkg_inventory walk: fd exhaustion is a constraint, never a fabricated Homebrew presence",
          "[pkg_inventory][walk][macos]") {
    // Only a Library/Taps marker exists, on /usr/local (which exists on every Mac).
    // With exactly ONE free fd the prefix root opens but the hop below it fails with
    // EMFILE (`io_error`): that proves nothing about the disk, so no manager row may
    // appear, while the failure is still reported.
    yuzu::test::TempDir dir{"yuzu_test_pkg_inventory_macos_emfile_"};
    make_dir(dir.path, "usr/local/Library/Taps/org/repo");

    {
        // Control, before any squeeze: the same tree reports the tap.
        std::optional<std::string> token;
        const auto managers = pi::mac::macos_manager_rows_at(dir.path, token);
        CHECK_FALSE(token.has_value());
        REQUIRE(managers.size() == 1);
        CHECK(managers[0] == "manager|homebrew|present|-|/usr/local|taps=1;formulae=0;casks=0|-");
    }

    // Zero free fds fails the prefix ROOT hop itself, which for /opt/homebrew would
    // otherwise read as "the prefix exists, so Homebrew does".
    for (const int free_fds : {0, 1}) {
        INFO("free fds: " << free_fds);
        std::vector<std::string> managers;
        std::optional<std::string> token;
        bool squeezed = false;
        {
            FdSqueeze squeeze{free_fds};
            squeezed = squeeze.ok();
            if (squeezed) managers = pi::mac::macos_manager_rows_at(dir.path, token);
        } // limits restored and fds closed BEFORE any assertion can need one
        if (!squeezed) SKIP("could not constrain RLIMIT_NOFILE on this host");

        CHECK(managers.empty());
        REQUIRE(token.has_value());
        // The kernel answers EMFILE before it resolves the path, so every hop that
        // needs a descriptor reports it: all of them are named `io_error` and none of
        // them became a manager row.
        CHECK(token->find("macos:homebrew_taps:io_error") == 0);
        for (std::size_t pos = 0; pos < token->size();) {
            const auto comma = token->find(',', pos);
            const auto end = comma == std::string::npos ? token->size() : comma;
            const std::string one = token->substr(pos, end - pos);
            REQUIRE(one.size() > 9);
            CHECK(one.compare(one.size() - 9, 9, ":io_error") == 0);
            pos = end + 1;
        }
    }
}

TEST_CASE("pkg_inventory walk: a refused marker under /usr/local proves Homebrew, and a broken "
          "repository directory is refused, not skipped past",
          "[pkg_inventory][walk][macos]") {
    // Below the prefix root a refused marker IS evidence (only the /usr/local ROOT
    // proves nothing), and the Intel repository probe must not fall through to the
    // prefix-level Library/Taps when Homebrew/ exists but cannot be entered.
    {
        yuzu::test::TempDir dir{"yuzu_test_pkg_inventory_macos_usrlocal_cellar_link_"};
        make_dir(dir.path, "elsewhere");
        make_dir(dir.path, "usr/local");
        std::error_code ec;
        std::filesystem::create_directory_symlink(dir.path / "elsewhere", dir.path / "usr/local/Cellar", ec);
        REQUIRE_FALSE(ec);
        std::optional<std::string> token;
        const auto managers = pi::mac::macos_manager_rows_at(dir.path, token);
        REQUIRE(managers.size() == 1);
        CHECK(managers[0] == "manager|homebrew|unavailable|-|/usr/local|-|macos:homebrew_cellar:not_a_directory");
    }
    {
        yuzu::test::TempDir dir{"yuzu_test_pkg_inventory_macos_repo_link_"};
        make_dir(dir.path, "elsewhere");
        make_dir(dir.path, "usr/local/Library/Taps/org/repo");
        std::error_code ec;
        std::filesystem::create_directory_symlink(dir.path / "elsewhere", dir.path / "usr/local/Homebrew", ec);
        REQUIRE_FALSE(ec);
        std::optional<std::string> token;
        const auto managers = pi::mac::macos_manager_rows_at(dir.path, token);
        REQUIRE(managers.size() == 1);
        // taps is NOT read from the flat Library/Taps behind the refused repository.
        CHECK(managers[0] == "manager|homebrew|unavailable|-|/usr/local|-|macos:homebrew_taps:not_a_directory");
    }
}

// ── hostile entries INSIDE the tree ──────────────────────────────────────

TEST_CASE("pkg_inventory walk: symlinked and oddly named entries inside Cellar, Caskroom and Taps "
          "never reach a row or a count",
          "[pkg_inventory][walk][macos]") {
    // Two defenses hold each other up here: classify_entry (fstatat, no follow) and
    // the O_NOFOLLOW openat, plus version_dir_name_ok on the names; no other case
    // observes them inside the tree.
    yuzu::test::TempDir dir{"yuzu_test_pkg_inventory_macos_hostile_"};
    const auto& r = dir.path;
    make_dir(r, "elsewhere/secret/9.9");
    make_dir(r, "elsewhere/secret/repo-in-secret-org");
    make_dir(r, "elsewhere_ver/evil-version");
    make_dir(r, "opt/homebrew/Cellar/good/1.0");
    make_dir(r, "opt/homebrew/Cellar/pipe|x/1.0");
    make_dir(r, "opt/homebrew/Cellar/back\\slash/1.0");
    make_dir(r, "opt/homebrew/Cellar/tab\there/1.0");
    make_dir(r, "opt/homebrew/Cellar/caf\xc3\xa9/1.0");
    make_dir(r, "opt/homebrew/Cellar/.hidden/1.0");
    make_dir(r, "opt/homebrew/Caskroom/goodcask/2.0");
    make_dir(r, "opt/homebrew/Library/Taps/realorg/realrepo");
    std::error_code ec;
    std::filesystem::create_directory_symlink(r / "elsewhere/secret", r / "opt/homebrew/Cellar/linkid", ec);
    REQUIRE_FALSE(ec);
    std::filesystem::create_directory_symlink(r / "elsewhere_ver/evil-version",
                                              r / "opt/homebrew/Cellar/good/linkver", ec);
    REQUIRE_FALSE(ec);
    std::filesystem::create_directory_symlink(r / "elsewhere/secret", r / "opt/homebrew/Caskroom/linkcask", ec);
    REQUIRE_FALSE(ec);
    std::filesystem::create_directory_symlink(r / "elsewhere/secret", r / "opt/homebrew/Library/Taps/linkorg", ec);
    REQUIRE_FALSE(ec);

    std::optional<std::string> token;
    const auto packages = pi::mac::macos_package_rows_at(r, token);
    // Skips are silent by design (Homebrew creates real, well-named directories).
    CHECK_FALSE(token.has_value());
    const std::vector<std::string> expected{
        "package|homebrew|good|1.0|formula",
        "package|homebrew|goodcask|2.0|cask",
    };
    CHECK(packages == expected);
    for (const auto& row : packages) {
        CHECK(row.find("link") == std::string::npos);
        CHECK(row.find("secret") == std::string::npos);
        CHECK(row.find("evil") == std::string::npos);
    }

    const auto managers = pi::mac::macos_manager_rows_at(r, token);
    CHECK_FALSE(token.has_value());
    REQUIRE(managers.size() == 1);
    CHECK(managers[0] == "manager|homebrew|present|-|/opt/homebrew|taps=1;formulae=1;casks=1|-");
}

TEST_CASE("pkg_inventory walk: a Cellar that lists but cannot be searched reports the stat failure, "
          "omits the fact and never a false zero",
          "[pkg_inventory][walk][macos]") {
    // chmod 0444: readable (so the listing works) but not searchable, so fstatat on
    // every entry fails with EACCES -- the per-entry stat-failure branch.
    if (::geteuid() == 0)
        SKIP("running as root (or CAP_DAC_OVERRIDE): permission bits bypassed");
    yuzu::test::TempDir dir{"yuzu_test_pkg_inventory_macos_statfail_"};
    make_dir(dir.path, "opt/homebrew/Cellar/wget/1.24.5");
    const auto cellar = dir.path / "opt/homebrew/Cellar";
    PermGuard guard{cellar};
    REQUIRE(::chmod(cellar.string().c_str(), 0444) == 0);

    std::optional<std::string> token;
    const auto managers = pi::mac::macos_manager_rows_at(dir.path, token);
    REQUIRE(token.has_value());
    CHECK(*token == "macos:homebrew_cellar:permission_denied");
    REQUIRE(managers.size() == 1);
    CHECK(managers[0] == "manager|homebrew|present|-|/opt/homebrew|taps=0;casks=0|-");

    std::optional<std::string> ptoken;
    CHECK(pi::mac::macos_package_rows_at(dir.path, ptoken).empty());
    REQUIRE(ptoken.has_value());
    CHECK(*ptoken == "macos:homebrew_cellar:permission_denied");
}

// ── output byte cap ──────────────────────────────────────────────────────

TEST_CASE("pkg_inventory walk: the output byte cap stops the rows and says so, complete at the cap",
          "[pkg_inventory][walk][macos][limits]") {
    // The row cap alone allows ~10 MB of maximum-length names, and the command path
    // applies no output cap of its own.
    yuzu::test::TempDir dir{"yuzu_test_pkg_inventory_macos_bytecap_"};
    for (const char* id : {"pkg-a", "pkg-b", "pkg-c"})
        make_dir(dir.path, std::string{"opt/homebrew/Cellar/"} + id + "/1.0");

    const std::size_t row_bytes =
        pi::format_package_row("pkg-a", "1.0", pi::PackageKind::formula).size() + 1;
    pi::Limits lim;
    lim.max_output_bytes = 2 * row_bytes; // exactly two rows fit
    std::optional<std::string> token;
    const auto capped = pi::mac::macos_package_rows_at(dir.path, token, lim);
    REQUIRE(token.has_value());
    CHECK(*token == "macos:homebrew_cellar:byte_cap");
    REQUIRE(capped.size() == 2);
    CHECK(capped[0] == "package|homebrew|pkg-a|1.0|formula");
    CHECK(capped[1] == "package|homebrew|pkg-b|1.0|formula");

    lim.max_output_bytes = 3 * row_bytes; // exactly all three fit: complete, no token
    const auto full = pi::mac::macos_package_rows_at(dir.path, token, lim);
    CHECK_FALSE(token.has_value());
    CHECK(full.size() == 3);

    // Once the cap trips it stays tripped (like row_cap): a SHORTER row in a later
    // container must not slip in. 30 spare bytes fit the 26-byte cask row.
    make_dir(dir.path, "opt/homebrew/Caskroom/z/1");
    lim.max_output_bytes = 2 * row_bytes + 30;
    const auto sticky = pi::mac::macos_package_rows_at(dir.path, token, lim);
    REQUIRE(token.has_value());
    CHECK(*token == "macos:homebrew_cellar:byte_cap,macos:homebrew_caskroom:byte_cap");
    CHECK(sticky.size() == 2); // pkg-a, pkg-b; neither pkg-c nor the cask
}

#endif // !defined(_WIN32)
