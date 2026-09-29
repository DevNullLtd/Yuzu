/**
 * test_autoruns_linux_local.cpp — loads the ACTUAL built autoruns plugin via
 * PluginHandle::load and drives it through yuzu::agent::LocalDispatcher,
 * asserting on the Linux-source rows/status of a real "list" capture.
 *
 * UNGUARDED, deliberately (see test_autoruns_local_dispatcher.cpp's own
 * banner: a `#ifndef __linux__` exclusion on a dispatcher TU is exactly how
 * a compiled-out leg ships green with no test ever loading it). On a
 * non-Linux build host, `collect_linux` resolves to autoruns_legs.hpp's
 * foreign-OS stub (P11), so every `lnx_*` SourceId is expected to report
 * `unsupported|0|foreign_os` -- asserted explicitly below rather than
 * skipped, so a future accidental narrowing of that stub is still caught on
 * every CI leg, not just Linux's.
 *
 * On a Linux build host this exercises the REAL `collect_linux`
 * (autoruns_linux.cpp, P13) against whatever cron/systemd/XDG state the
 * host actually has -- assertions here are host-tolerant by design (no
 * invented fixture data): they check the SHAPE every Linux source's status
 * line must have, never a specific row count, since a real capture's row
 * count depends on the host's own configuration.
 */
#include <catch2/catch_test_macros.hpp>

#include <yuzu/agent/plugin_loader.hpp>
#include <yuzu/plugin.h>
#include <yuzu/plugin.hpp>

#include "local_dispatcher.hpp"
#include "test_helpers.hpp"

#include "autoruns_catalog.hpp"

#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <optional>
#include <set>
#include <sstream>
#include <string>
#include <vector>

namespace fs = std::filesystem;

namespace {

std::vector<std::string> captured_rows(const std::string& captured) {
    std::vector<std::string> out;
    std::istringstream ss(captured);
    std::string line;
    while (std::getline(ss, line)) {
        if (!line.empty() && line.back() == '\r') line.pop_back();
        if (!line.empty()) out.push_back(line);
    }
    return out;
}

/// Autoruns folds '|' to U+2502 rather than escaping it, so a naive
/// split('|') is already safe -- no field can contain a raw '|'.
std::vector<std::string> fields_of(const std::string& row) {
    std::vector<std::string> out;
    std::string cur;
    for (char c : row) {
        if (c == '|') { out.push_back(cur); cur.clear(); }
        else cur += c;
    }
    out.push_back(cur);
    return out;
}

void require_plugin_or_skip() {
    if (std::getenv("MESON_BUILD_ROOT") != nullptr) {
        FAIL("autoruns plugin library not found under meson test -- the plugin did not build, "
             "or link_depends is not forcing it to build before this test runs");
    }
    WARN("autoruns plugin library not found -- skipping the LocalDispatcher round-trip");
}

#if defined(_WIN32)
constexpr const char* kPluginExt = ".dll";
#elif defined(__APPLE__)
constexpr const char* kPluginExt = ".dylib";
#else
constexpr const char* kPluginExt = ".so";
#endif

fs::path find_autoruns_plugin() {
    const std::string lib_name = std::string{"autoruns"} + kPluginExt;
    std::vector<fs::path> candidates;
    if (auto* build_root = std::getenv("MESON_BUILD_ROOT"))
        candidates.emplace_back(fs::path{build_root} / "agents" / "plugins" / "autoruns" / lib_name);
    candidates.emplace_back(fs::path{"agents"} / "plugins" / "autoruns" / lib_name);
    candidates.emplace_back(fs::path{".."} / "agents" / "plugins" / "autoruns" / lib_name);
    for (const char* b : {"build-macos", "build-linux", "build-windows"})
        candidates.emplace_back(fs::path{b} / "agents" / "plugins" / "autoruns" / lib_name);
    for (const auto& c : candidates)
        if (std::error_code ec; fs::exists(c, ec)) return c;
    return {};
}

struct LoadedPlugin {
    yuzu::agent::PluginHandle handle;
    const YuzuPluginDescriptor* descriptor{nullptr};
    explicit operator bool() const { return descriptor != nullptr; }
};

std::optional<LoadedPlugin> load_autoruns_plugin() {
    auto path = find_autoruns_plugin();
    if (path.empty()) return std::nullopt;
    auto loaded = yuzu::agent::PluginHandle::load(path);
    if (!loaded) return std::nullopt;
    const auto* d = loaded->descriptor();
    if (!d) return std::nullopt;
    return LoadedPlugin{std::move(*loaded), d};
}

std::vector<yuzu::autoruns::SourceId> linux_source_ids() {
    std::vector<yuzu::autoruns::SourceId> out;
    for (const auto& decl : yuzu::autoruns::kSourceCatalog)
        if (decl.linux != YUZU_SUPPORT_UNSUPPORTED) out.push_back(decl.id);
    return out;
}

struct SourceStatus {
    std::string status;
    std::string row_count;
    std::string reason;
};

std::optional<SourceStatus> find_status(const std::vector<std::string>& rows, const std::string& id) {
    for (const auto& r : rows) {
        auto f = fields_of(r);
        if (f.size() == 5 && f[0] == "source" && f[1] == id)
            return SourceStatus{f[2], f[3], f[4]};
    }
    return std::nullopt;
}

} // namespace

TEST_CASE("autoruns Linux leg: every lnx_* SourceId emits exactly one source| line",
          "[autoruns][actions][linux]") {
    auto plugin = load_autoruns_plugin();
    if (!plugin) {
        require_plugin_or_skip();
        return;
    }

    yuzu::agent::LocalDispatcher dispatcher;
    auto result = dispatcher.run(plugin->descriptor, "list");
    CHECK(result.rc == 0);

    const auto rows = captured_rows(result.captured);
    const auto ids = linux_source_ids();
    REQUIRE_FALSE(ids.empty());

    for (const auto id : ids) {
        const std::string id_str{yuzu::autoruns::source_id_string(id)};
        int count = 0;
        for (const auto& r : rows) {
            auto f = fields_of(r);
            if (f.size() == 5 && f[0] == "source" && f[1] == id_str) ++count;
        }
        INFO("source id: " << id_str);
        CHECK(count == 1);
    }
}

#ifndef YUZU_AGENT_SRC_DIR
#error "YUZU_AGENT_SRC_DIR must be injected by tests/meson.build."
#endif

TEST_CASE("autoruns Linux leg: every format_source_status() call inside collect_linux "
          "goes through the emit_status wrapper",
          "[autoruns][actions][linux]") {
    // collect_linux's local emit_status wrapper (autoruns_linux.cpp) is what
    // sets any_constrained, which feeds the typed CC-07 aggregate
    // (autoruns_plugin.cpp) -- but lnx_init_d and lnx_systemd_timers_user
    // are catalog-permanently-constrained, so that aggregate already reads
    // CONSTRAINED on every real run regardless of what any OTHER one of the
    // ~34 other call sites does. No behavioural/dispatch-level test can ever
    // observe one of those other sites silently bypassing emit_status (a
    // raw ctx.write_output(format_source_status(...)) call that skips the
    // any_constrained bookkeeping) -- lnx_init_d alone always saturates the
    // observable result. emit_status is a local lambda with no header seam
    // (deliberately not extracted for this polish round -- that's a
    // production-logic change out of scope here), so this closes the gap
    // the only way available without one: a lexical scan of the real source
    // asserting format_source_status(...) appears in collect_linux's body
    // exactly once (the call inside emit_status's own definition) -- a
    // silent bypass, or a new call site added without going through the
    // wrapper, fails this loudly by name instead of going unnoticed.
    //
    // Path resolution: there is no YUZU_AUTORUNS_SRC_DIR macro (only
    // YUZU_AGENT_SRC_DIR, pointed at agents/core/src by tests/meson.build) --
    // derives the autoruns plugin's own src dir relative to it rather than
    // adding a new build-system define for one test, mirroring
    // test_list_read_confinement.cpp's YUZU_SERVER_SRC_DIR-based scan.
    const fs::path autoruns_src = fs::path{YUZU_AGENT_SRC_DIR} / ".." / ".." / "plugins" /
                                  "autoruns" / "src" / "autoruns_linux.cpp";
    std::ifstream in(autoruns_src);
    REQUIRE(in.is_open());
    std::ostringstream buf;
    buf << in.rdbuf();
    const std::string text = buf.str();

    const std::string start_anchor =
        "int collect_linux(yuzu::CommandContext& ctx, std::string_view filter) {";
    const std::string end_anchor = "#endif // !YUZU_AUTORUNS_LINUX_UNIT_TEST_INTERNALS_ONLY";
    const auto start = text.find(start_anchor);
    REQUIRE(start != std::string::npos);
    const auto end = text.find(end_anchor, start);
    REQUIRE(end != std::string::npos);
    const std::string body = text.substr(start, end - start);

    const std::string needle = "format_source_status(";
    std::size_t count = 0;
    std::istringstream body_lines(body);
    std::string line;
    while (std::getline(body_lines, line)) {
        // Skip a full-line "//" comment -- the banner comment just above
        // emit_status's own definition quotes this exact call shape in
        // prose, which a naive substring scan would double-count.
        const auto first_non_ws = line.find_first_not_of(" \t");
        if (first_non_ws != std::string::npos && line.compare(first_non_ws, 2, "//") == 0) continue;
        if (line.find(needle) != std::string::npos) ++count;
    }
    CHECK(count == 1);
}

#if !defined(__linux__)

TEST_CASE("autoruns Linux leg: on a non-Linux build every lnx_* source reports "
          "unsupported|0|foreign_os",
          "[autoruns][actions][linux]") {
    auto plugin = load_autoruns_plugin();
    if (!plugin) {
        require_plugin_or_skip();
        return;
    }

    yuzu::agent::LocalDispatcher dispatcher;
    auto result = dispatcher.run(plugin->descriptor, "list");
    CHECK(result.rc == 0);
    const auto rows = captured_rows(result.captured);

    for (const auto id : linux_source_ids()) {
        const std::string id_str{yuzu::autoruns::source_id_string(id)};
        auto st = find_status(rows, id_str);
        REQUIRE(st.has_value());
        INFO("source id: " << id_str);
        CHECK(st->status == "unsupported");
        CHECK(st->row_count == "0");
        CHECK(st->reason == "foreign_os");
    }
}

#else // defined(__linux__)

#include <cerrno>
#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>

#include <yuzu/agent/scoped_fd.hpp>

TEST_CASE("autoruns Linux leg: real collect_linux never reports foreign_os for a lnx_* source",
          "[autoruns][actions][linux]") {
    auto plugin = load_autoruns_plugin();
    if (!plugin) {
        require_plugin_or_skip();
        return;
    }

    yuzu::agent::LocalDispatcher dispatcher;
    auto result = dispatcher.run(plugin->descriptor, "list");
    CHECK(result.rc == 0);
    const auto rows = captured_rows(result.captured);

    static const std::set<std::string> kValidStatus{"supported", "constrained", "unsupported"};
    for (const auto id : linux_source_ids()) {
        const std::string id_str{yuzu::autoruns::source_id_string(id)};
        auto st = find_status(rows, id_str);
        REQUIRE(st.has_value());
        INFO("source id: " << id_str);
        CHECK(kValidStatus.count(st->status) == 1);
        // This TU is compiled only when __linux__ is defined, so
        // collect_linux ran for real -- "foreign_os" (the non-Linux stub's
        // exclusive reason string) must never appear here.
        CHECK(st->reason != "foreign_os");
    }
}

TEST_CASE("autoruns Linux leg: lnx_init_d is always reported CONSTRAINED (catalog-declared, "
          "listing-only)",
          "[autoruns][actions][linux]") {
    auto plugin = load_autoruns_plugin();
    if (!plugin) {
        require_plugin_or_skip();
        return;
    }

    yuzu::agent::LocalDispatcher dispatcher;
    auto result = dispatcher.run(plugin->descriptor, "list");
    CHECK(result.rc == 0);
    const auto rows = captured_rows(result.captured);

    auto st = find_status(rows, "lnx_init_d");
    REQUIRE(st.has_value());
    // SysV enablement is distro-dependent and not modelled -- this source is
    // declared CONSTRAINED in the catalog on every real host, success or not.
    CHECK(st->status == "constrained");

    for (const auto& r : rows) {
        auto f = fields_of(r);
        if (f.size() == 12 && f[0] == "autorun" && f[1] == "lnx_init_d") {
            // field 7 (0-indexed) is `enabled` in the fixed row schema.
            CHECK(f[7] == "unknown");
        }
    }
}

TEST_CASE("autoruns Linux leg: systemd sources are self-consistent with /run/systemd/system "
          "tri-state on this real host",
          "[autoruns][actions][linux]") {
    auto plugin = load_autoruns_plugin();
    if (!plugin) {
        require_plugin_or_skip();
        return;
    }

    yuzu::agent::LocalDispatcher dispatcher;
    auto result = dispatcher.run(plugin->descriptor, "list");
    CHECK(result.rc == 0);
    const auto rows = captured_rows(result.captured);

    auto sys_st = find_status(rows, "lnx_systemd_timers_system");
    auto usr_st = find_status(rows, "lnx_systemd_timers_user");
    REQUIRE(sys_st.has_value());
    REQUIRE(usr_st.has_value());

    std::error_code ec;
    const bool systemd_dir_present = fs::is_directory("/run/systemd/system", ec) && !ec;
    if (!systemd_dir_present) {
        // absent -> both systemd sources must be honestly unsupported, never
        // silently reported as supported-with-zero-rows.
        CHECK(sys_st->status == "unsupported");
        CHECK(sys_st->reason == "no_systemd");
        CHECK(usr_st->status == "unsupported");
        CHECK(usr_st->reason == "no_systemd");
    } else {
        // present -> neither source is the no_systemd/undetermined tri-state;
        // the row count each carries depends on the host's real unit dirs.
        CHECK(sys_st->reason != "no_systemd");
        CHECK(usr_st->reason != "no_systemd");

        // lnx_systemd_timers_user is a permanent catalog-declared exception
        // (autoruns_catalog.hpp) -- CONSTRAINED with narrow_search_path_coverage
        // named in the reason on every reportable path, real ones included.
        // Drives the ACTUAL collect_linux integration points via a live
        // dispatch (RECONSTRUCTION: pins round 7's should-fix -- the
        // apply_narrow_search_path_coverage TEST_CASE above only calls the
        // function directly, so a later edit removing one of the three real
        // call sites would leave that test green while this one catches it).
        CHECK(usr_st->status == "constrained");
        CHECK(usr_st->reason.find("narrow_search_path_coverage") != std::string::npos);
    }
}

TEST_CASE("autoruns Linux leg: lnx_rc_local's real collect_linux status/row is "
          "self-consistent with this host's own /etc/rc.local",
          "[autoruns][actions][linux]") {
    // RECONSTRUCTION: the pre-existing rc.local coverage (below, "Direct
    // source inclusion") only ever calls read_file_bounded/is_root_executable
    // directly -- zero prior assertions anywhere touched the actual
    // /etc/rc.local block inside collect_linux at dispatch level. Drives the
    // ACTUAL collect_linux integration point via a live dispatch instead,
    // and builds its own ground truth by opening /etc/rc.local with the SAME
    // flags read_file_bounded uses (O_RDONLY|O_NOFOLLOW|O_CLOEXEC), so a
    // symlinked leaf (refused, not followed) is classified the same way
    // here as it is in production, independent of this host's actual
    // /etc/rc.local state. NOTE this does NOT deterministically catch the
    // specific "redundant second ::stat() call reinstated while out_st
    // plumbing stays in place" partial-revert regression: on a quiescent
    // host both the real fstat() and a fresh path-based ::stat() return the
    // same answer, so that class of regression needs an injectable-path
    // seam or fault injection to reproduce, not a real-filesystem read. What
    // this DOES pin: the real branch decision (absent/not_executable/row)
    // now has dispatch-level coverage at all, where before it had none.
    auto plugin = load_autoruns_plugin();
    if (!plugin) {
        require_plugin_or_skip();
        return;
    }

    yuzu::agent::ScopedFd fd{::open("/etc/rc.local", O_RDONLY | O_NOFOLLOW | O_CLOEXEC)};
    const int open_errno = errno;
    struct stat fst{};
    const bool opened = fd.valid();
    if (opened) {
        REQUIRE(::fstat(fd.get(), &fst) == 0);
    }

    yuzu::agent::LocalDispatcher dispatcher;
    auto result = dispatcher.run(plugin->descriptor, "list");
    CHECK(result.rc == 0);
    const auto rows = captured_rows(result.captured);

    auto st = find_status(rows, "lnx_rc_local");
    REQUIRE(st.has_value());

    int autorun_count = 0;
    std::vector<std::string> autorun_fields;
    for (const auto& r : rows) {
        auto f = fields_of(r);
        if (f.size() == 12 && f[0] == "autorun" && f[1] == "lnx_rc_local") {
            ++autorun_count;
            autorun_fields = f;
        }
    }

    if (!opened) {
        if (open_errno == ENOENT) {
            CHECK(st->status == "supported");
            CHECK(st->row_count == "0");
            CHECK(st->reason == "absent");
        } else {
            // A refused symlink leaf (ELOOP), permission_denied, or any
            // other real open failure -- never a confident supported/absent.
            CHECK(st->status == "constrained");
        }
        CHECK(autorun_count == 0);
    } else if (!S_ISREG(fst.st_mode)) {
        // open() itself can succeed against a non-regular leaf (a
        // directory, fifo, device -- O_NOFOLLOW alone doesn't catch this);
        // read_file_bounded's own S_ISREG check then fails the read as a
        // real error (NOT_REGULAR), so the real call site reports
        // constrained here too, never a confident supported/absent.
        CHECK(st->status == "constrained");
        CHECK(autorun_count == 0);
    } else if ((fst.st_mode & (S_IXUSR | S_IXGRP | S_IXOTH)) == 0) {
        // A regular file that opened and read cleanly but isn't
        // root-executable -- its own honest zero-row case, never folded
        // into absent nor promoted to a fabricated row.
        CHECK(st->status == "supported");
        CHECK(st->row_count == "0");
        CHECK(st->reason == "not_executable");
        CHECK(autorun_count == 0);
    } else {
        // Present, regular, root-executable: a real persistence mechanism,
        // exactly one row.
        CHECK(st->status == "supported");
        CHECK(st->row_count == "1");
        CHECK(st->reason == "-");
        REQUIRE(autorun_count == 1);
        REQUIRE(autorun_fields.size() == 12);
        CHECK(autorun_fields[3] == "/etc/rc.local"); // location
        CHECK(autorun_fields[5] == "/etc/rc.local"); // target
        CHECK(autorun_fields[7] == "enabled");       // enabled
        CHECK(autorun_fields[8] == "system");        // scope
    }
}

#endif // defined(__linux__)

#if defined(__linux__)

// Direct source inclusion, Linux-only: read_file_bounded and
// classify_read_error are declared and defined ONLY in autoruns_linux.cpp
// (by design -- see that file's own banner), with internal (anonymous-
// namespace) linkage, so there is no header seam to reach them through
// otherwise. The macro excludes collect_linux itself from this inclusion
// (see autoruns_linux.cpp's own guard comment) so the rung-2 subprocess
// fallback's runner symbols are never pulled into this test binary's link
// -- this TU never statically links the real plugin either way (the
// TEST_CASEs above load it via PluginHandle::load/dlopen at runtime), so a
// second compilation of the same free functions here creates no
// ODR/duplicate-symbol conflict.
#define YUZU_AUTORUNS_LINUX_UNIT_TEST_INTERNALS_ONLY 1
#include "../../agents/plugins/autoruns/src/autoruns_linux.cpp"
#undef YUZU_AUTORUNS_LINUX_UNIT_TEST_INTERNALS_ONLY

TEST_CASE("autoruns Linux leg: read_file_bounded/classify_read_error distinguish "
          "symlink_refused and oversized from a constructed fixture",
          "[autoruns][actions][linux]") {
    namespace fsx = std::filesystem;
    yuzu::test::TempDir tmp("yuzu_test_autoruns_linux_");
    fsx::create_directories(tmp.path);
    const fsx::path& dir = tmp.path;
    std::error_code ec;

    SECTION("a symlinked leaf is refused with symlink_refused, never resolved") {
        fsx::path target = dir / "target.txt";
        { std::ofstream(target) << "real file\n"; }
        fsx::path link = dir / "link.txt";
        fsx::create_symlink(target, link, ec);
        REQUIRE_FALSE(ec);

        auto result = yuzu::autoruns::read_file_bounded(link.string());
        REQUIRE_FALSE(result.has_value());
        auto cls = yuzu::autoruns::classify_read_error(result.error(), /*required_by_catalog=*/false);
        CHECK(cls.reason == "symlink_refused");
    }

    SECTION("a file over the byte cap is refused with oversized") {
        // The cap itself is injected (max_bytes), so the fixture only needs
        // to exceed a small, test-chosen cap -- not the real 1 MiB default --
        // keeping this unit test's I/O a few bytes rather than a megabyte-plus
        // write (test-efficiency discipline: no unjustified disk cost).
        fsx::path big = dir / "big.txt";
        {
            std::ofstream out(big, std::ios::binary);
            out << "0123456789"; // 10 bytes > the 4-byte cap below
        }
        auto result = yuzu::autoruns::read_file_bounded(big.string(), /*max_bytes=*/4);
        REQUIRE_FALSE(result.has_value());
        auto cls = yuzu::autoruns::classify_read_error(result.error(), /*required_by_catalog=*/false);
        CHECK(cls.reason == "oversized");
    }
}

TEST_CASE("autoruns Linux leg: read_file_bounded's optional out_st out-parameter "
          "carries the SAME fstat() metadata the read itself already verified "
          "(RECONSTRUCTION: pins the /etc/rc.local BLOCKER fix -- the eligibility "
          "check used to redo a second, separately racy path-based ::stat() after "
          "a successful read, which folded a genuine acquisition failure -- EIO "
          "from a real filesystem fault, not just a raced-removal ENOENT -- into "
          "the exact same confident not_executable status as an ordinary "
          "non-executable file. Threading the descriptor-based fstat() the "
          "function already performs internally out to the caller removes the "
          "second lookup entirely, so there is no longer a distinct stat-failure "
          "branch to misclassify. These cases confirm the refactor is "
          "behavior-preserving for the success path: an executable file's mode "
          "bits are visible via out_st exactly as they would have been via a "
          "second stat() call, and likewise for a non-executable one)",
          "[autoruns][actions][linux]") {
    namespace fsx = std::filesystem;
    yuzu::test::TempDir tmp("yuzu_test_autoruns_outst_");
    fsx::create_directories(tmp.path);
    const fsx::path& dir = tmp.path;
    std::error_code ec;

    SECTION("out_st is populated on a successful read, matching the file's real size") {
        fsx::path f = dir / "plain.txt";
        { std::ofstream(f) << "hello world\n"; }

        struct stat st{};
        auto result = yuzu::autoruns::read_file_bounded(f.string(), yuzu::autoruns::kDefaultMaxReadBytes, &st);
        REQUIRE(result.has_value());
        CHECK(static_cast<std::size_t>(st.st_size) == result->size());
    }

    SECTION("an executable rc.local-shaped file: out_st's mode bits make "
            "is_root_executable(st) true directly, no second stat() needed") {
        fsx::path f = dir / "rc.local";
        { std::ofstream(f) << "#!/bin/sh\nexit 0\n"; }
        fsx::permissions(f, fsx::perms::owner_all, ec);
        REQUIRE_FALSE(ec);

        struct stat st{};
        auto result = yuzu::autoruns::read_file_bounded(f.string(), yuzu::autoruns::kDefaultMaxReadBytes, &st);
        REQUIRE(result.has_value());
        CHECK(yuzu::autoruns::is_root_executable(st));
    }

    SECTION("a non-executable (0644) rc.local-shaped file: out_st's mode bits "
            "correctly evaluate not_executable via the same metadata path") {
        fsx::path f = dir / "rc.local";
        { std::ofstream(f) << "#!/bin/sh\nexit 0\n"; }
        fsx::permissions(f,
                         fsx::perms::owner_read | fsx::perms::owner_write |
                             fsx::perms::group_read | fsx::perms::others_read,
                         ec);
        REQUIRE_FALSE(ec);

        struct stat st{};
        auto result = yuzu::autoruns::read_file_bounded(f.string(), yuzu::autoruns::kDefaultMaxReadBytes, &st);
        REQUIRE(result.has_value());
        CHECK_FALSE(yuzu::autoruns::is_root_executable(st));
    }

    SECTION("out_st defaults to nullptr and is safely skipped -- every other "
            "call site's unchanged two-argument call form still compiles and reads") {
        fsx::path f = dir / "no_out_param.txt";
        { std::ofstream(f) << "unaffected call sites\n"; }

        auto result = yuzu::autoruns::read_file_bounded(f.string());
        REQUIRE(result.has_value());
        CHECK(*result == "unaffected call sites\n");
    }
}

TEST_CASE("autoruns Linux leg: list_dir reports truncated for exactly one real entry "
          "beyond the cap (RECONSTRUCTION: pins the fix for an adversarial-review "
          "falsifier -- an earlier version discarded the over-cap entry itself while "
          "probing for a SECOND one, so cap=2 with exactly 3 real entries reported "
          "truncated=false)",
          "[autoruns][actions][linux]") {
    yuzu::test::TempDir tmp("yuzu_test_autoruns_linux_listdir_");
    std::error_code ec;
    std::filesystem::create_directories(tmp.path, ec);
    REQUIRE_FALSE(ec);
    for (const char* name : {"a.txt", "b.txt", "c.txt"}) {
        std::ofstream(tmp.path / name) << "x";
    }

    SECTION("cap+1 real entries -> truncated") {
        auto listing = yuzu::autoruns::list_dir(tmp.path.string(), /*cap=*/2);
        CHECK(listing.opened);
        CHECK(listing.names.size() == 2);
        CHECK(listing.truncated);
    }

    SECTION("exactly cap entries -> not truncated") {
        auto listing = yuzu::autoruns::list_dir(tmp.path.string(), /*cap=*/3);
        CHECK(listing.opened);
        CHECK(listing.names.size() == 3);
        CHECK_FALSE(listing.truncated);
    }

    SECTION("cap well above the real entry count -> not truncated") {
        auto listing = yuzu::autoruns::list_dir(tmp.path.string(), /*cap=*/4096);
        CHECK(listing.opened);
        CHECK(listing.names.size() == 3);
        CHECK_FALSE(listing.truncated);
    }
}

TEST_CASE("autoruns Linux leg: timer_scan_status combines truncation and per-file "
          "constraints into one status/reason pair",
          "[autoruns][actions][linux]") {
    using yuzu::autoruns::TimerScan;
    using yuzu::autoruns::timer_scan_status;

    SECTION("neither flag set -> supported, dash reason") {
        TimerScan scan;
        const auto [support, reason] = timer_scan_status(scan);
        CHECK(support == YUZU_SUPPORT_SUPPORTED);
        CHECK(reason == "-");
    }

    SECTION("truncated only -> constrained, row_cap") {
        TimerScan scan;
        scan.any_truncated = true;
        const auto [support, reason] = timer_scan_status(scan);
        CHECK(support == YUZU_SUPPORT_CONSTRAINED);
        CHECK(reason == "row_cap");
    }

    SECTION("file-constrained only -> constrained, the file's reason") {
        TimerScan scan;
        scan.any_file_constrained = true;
        scan.file_constrained_reason = "permission_denied";
        const auto [support, reason] = timer_scan_status(scan);
        CHECK(support == YUZU_SUPPORT_CONSTRAINED);
        CHECK(reason == "permission_denied");
    }

    SECTION("both -> constrained, comma-joined reason") {
        TimerScan scan;
        scan.any_truncated = true;
        scan.any_file_constrained = true;
        scan.file_constrained_reason = "permission_denied";
        const auto [support, reason] = timer_scan_status(scan);
        CHECK(support == YUZU_SUPPORT_CONSTRAINED);
        CHECK(reason == "permission_denied,row_cap");
    }

    SECTION("permission-denied only -> constrained, partial_permission_denied "
            "(round-3 should-fix: a per-home directory-open failure must not "
            "be silently folded into Supported just because a global "
            "directory succeeded)") {
        TimerScan scan;
        scan.any_permission_denied = true;
        const auto [support, reason] = timer_scan_status(scan);
        CHECK(support == YUZU_SUPPORT_CONSTRAINED);
        CHECK(reason == "partial_permission_denied");
    }

    SECTION("permission-denied plus truncated -> both reasons, denial first") {
        TimerScan scan;
        scan.any_permission_denied = true;
        scan.any_truncated = true;
        const auto [support, reason] = timer_scan_status(scan);
        CHECK(support == YUZU_SUPPORT_CONSTRAINED);
        CHECK(reason == "partial_permission_denied,row_cap");
    }
}

TEST_CASE("autoruns Linux leg: apply_narrow_search_path_coverage always "
          "downgrades to Constrained and names the permanent gap "
          "(RECONSTRUCTION: pins round 4's should-fix -- extracted from the "
          "call site into a named function specifically so this integration "
          "point, previously unexercised by any test, is now directly "
          "testable)",
          "[autoruns][actions][linux]") {
    using yuzu::autoruns::apply_narrow_search_path_coverage;

    SECTION("Supported -> Constrained, standalone reason") {
        const auto [support, reason] =
            apply_narrow_search_path_coverage(YUZU_SUPPORT_SUPPORTED, "-");
        CHECK(support == YUZU_SUPPORT_CONSTRAINED);
        CHECK(reason == "narrow_search_path_coverage");
    }

    SECTION("already Constrained -> stays Constrained, reason appended") {
        const auto [support, reason] =
            apply_narrow_search_path_coverage(YUZU_SUPPORT_CONSTRAINED, "partial_permission_denied");
        CHECK(support == YUZU_SUPPORT_CONSTRAINED);
        CHECK(reason == "partial_permission_denied,narrow_search_path_coverage");
    }
}

TEST_CASE("autoruns Linux leg: timer_enabled correlates a global-directory "
          "unit against every enumerated user's own wants directory "
          "(RECONSTRUCTION: pins round 3's blocker -- an ordinary "
          "`systemctl --user enable` on a vendor-shipped unit writes its "
          "enablement symlink into the enabling user's OWN "
          "~/.config/systemd/user/timers.target.wants, which has no "
          "relationship to where the unit file itself lives; the fix must "
          "check that directory too, not just the unit's own dir and the "
          "global /etc/systemd/user root)",
          "[autoruns][actions][linux]") {
    using yuzu::autoruns::Enabled;
    using yuzu::autoruns::Scope;
    using yuzu::autoruns::timer_enabled;

    yuzu::test::TempDir vendor_dir("yuzu_test_autoruns_vendor_");
    yuzu::test::TempDir user_dir("yuzu_test_autoruns_user_");
    std::filesystem::create_directories(vendor_dir.path);
    std::filesystem::create_directories(user_dir.path / "timers.target.wants");

    // The unit file lives ONLY in the vendor (global) directory -- this
    // mirrors /usr/lib/systemd/user on a real host.
    const auto unit_file = vendor_dir.path / "backup.timer";
    { std::ofstream f(unit_file); f << "[Timer]\nOnCalendar=daily\n"; }

    // The enablement symlink lives ONLY in the user's own dir -- this
    // mirrors ~/.config/systemd/user/timers.target.wants after `systemctl
    // --user enable backup.timer`, and deliberately does NOT also appear
    // under the global /etc/systemd/user root this fix already handled.
    std::filesystem::create_symlink(unit_file, user_dir.path / "timers.target.wants" / "backup.timer");

    SECTION("without the user's wants dir threaded through -> disabled "
            "(reproduces the round-3 blocker)") {
        CHECK(timer_enabled(vendor_dir.path.string(), "backup.timer", "", Scope::user, {}) ==
             Enabled::disabled);
    }

    SECTION("with the user's wants dir threaded through -> enabled") {
        CHECK(timer_enabled(vendor_dir.path.string(), "backup.timer", "", Scope::user,
                            {user_dir.path.string()}) == Enabled::enabled);
    }

    SECTION("a different, unrelated user's wants dir does not falsely enable it") {
        yuzu::test::TempDir other_user_dir("yuzu_test_autoruns_other_user_");
        std::filesystem::create_directories(other_user_dir.path / "timers.target.wants");
        CHECK(timer_enabled(vendor_dir.path.string(), "backup.timer", "", Scope::user,
                            {other_user_dir.path.string()}) == Enabled::disabled);
    }

    SECTION("a same-named timer enabled in one user's own directory does not "
            "falsely enable an unrelated user's separate, never-enabled timer "
            "of the same name (RECONSTRUCTION: pins round 4's should-fix -- "
            "user_wants_bases must reach only the two GLOBAL-directory scans, "
            "never the per-home scans, whose own unit_dir is already the "
            "correct wants base; the round-3 fix passed it to every "
            "user-scope call, so Bob enabling his own same.timer used to "
            "falsely mark Alice's separate same.timer enabled too)") {
        using yuzu::autoruns::Row;
        using yuzu::autoruns::scan_systemd_timer_dir_unique;
        using yuzu::autoruns::TimerScan;

        yuzu::test::TempDir bob_dir("yuzu_test_autoruns_bob_");
        yuzu::test::TempDir alice_dir("yuzu_test_autoruns_alice_");
        std::filesystem::create_directories(bob_dir.path / "timers.target.wants");
        std::filesystem::create_directories(alice_dir.path);

        const auto bob_unit = bob_dir.path / "same.timer";
        { std::ofstream f(bob_unit); f << "[Timer]\nOnCalendar=daily\n"; }
        std::filesystem::create_symlink(bob_unit, bob_dir.path / "timers.target.wants" / "same.timer");

        const auto alice_unit = alice_dir.path / "same.timer";
        { std::ofstream f(alice_unit); f << "[Timer]\nOnCalendar=daily\n"; }
        // Alice never enables her copy -- no wants symlink in her directory.

        TimerScan scan;
        std::vector<std::pair<dev_t, ino_t>> seen_dirs;
        // Matches the real call site exactly: per-home scans get no
        // user_wants_bases argument at all.
        scan_systemd_timer_dir_unique(bob_dir.path.string(), Scope::user, "bob", scan, seen_dirs);
        scan_systemd_timer_dir_unique(alice_dir.path.string(), Scope::user, "alice", scan, seen_dirs);

        Enabled bob_enabled = Enabled::unknown, alice_enabled = Enabled::unknown;
        for (const auto& row : scan.rows) {
            if (row.user == "bob") bob_enabled = row.enabled;
            if (row.user == "alice") alice_enabled = row.enabled;
        }
        CHECK(bob_enabled == Enabled::enabled);
        CHECK(alice_enabled == Enabled::disabled);
    }
}

TEST_CASE("autoruns Linux leg: a wants-directory scan capped before reaching the real "
          "enablement symlink reports unknown, never a confident disabled "
          "(RECONSTRUCTION: pins PR #4154 round 8's blocker -- build_wants_listing's "
          "kMaxDirEntries cap carried no distinct truncation signal, so timer_enabled "
          "fell through to a confident Enabled::disabled exactly as if the symlink "
          "genuinely didn't exist; round 8's own falsifier used 5,000 real entries in a "
          ".wants directory with the real symlink placed beyond the cap)",
          "[autoruns][actions][linux]") {
    using yuzu::autoruns::Enabled;
    using yuzu::autoruns::Scope;
    using yuzu::autoruns::timer_enabled;

    yuzu::test::TempDir dir("yuzu_test_autoruns_cap_");
    std::filesystem::create_directories(dir.path / "timers.target.wants");

    const auto unit_file = dir.path / "backup.timer";
    { std::ofstream f(unit_file); f << "[Timer]\nOnCalendar=daily\n"; }

    // One real enablement symlink for the unit under test, PLUS enough
    // decoy entries (matching production's kMaxDirEntries, 4096) that a
    // correct implementation cannot promise it saw the real one -- the
    // decoys are named to sort well ahead of "backup.timer" so a
    // lexicographic-order filesystem walk (the common case) genuinely
    // exercises the cap-before-match path this test exists to pin, while a
    // hash-ordered filesystem still gets a real assertion out of it (never
    // confidently disabled, whether or not the match happened to survive).
    std::filesystem::create_symlink(unit_file, dir.path / "timers.target.wants" / "backup.timer");
    for (int i = 0; i < 4096; ++i) {
        const auto decoy = dir.path / "timers.target.wants" / ("aaa-decoy-" + std::to_string(i) + ".timer");
        std::filesystem::create_symlink(unit_file, decoy);
    }

    const auto result = timer_enabled(dir.path.string(), "backup.timer", "", Scope::user, {});
    CHECK(result != Enabled::disabled);
}

TEST_CASE("autoruns Linux leg: note_file_constraint dedups a repeated token "
          "(RECONSTRUCTION: pins a governance-Gate-4 finding -- a per-file "
          "constraint hit across many entries/profiles used to grow the "
          "reason string once per occurrence instead of once per distinct "
          "reason)",
          "[autoruns][actions][linux]") {
    bool any = false;
    std::string reason;
    yuzu::autoruns::note_file_constraint(any, reason, "permission_denied");
    yuzu::autoruns::note_file_constraint(any, reason, "permission_denied");
    yuzu::autoruns::note_file_constraint(any, reason, "permission_denied");
    CHECK(any);
    CHECK(reason == "permission_denied");

    yuzu::autoruns::note_file_constraint(any, reason, "oversized");
    CHECK(reason == "permission_denied,oversized");
}

TEST_CASE("autoruns Linux leg: trim_possibly_truncated_tail drops a partial "
          "trailing line only on a non-clean subprocess stop "
          "(RECONSTRUCTION: pins a governance-Gate-4 finding -- the rung-2 "
          "systemctl fallback could silently emit a truncated field as if "
          "it were a real, complete value)",
          "[autoruns][actions][linux]") {
    using yuzu::autoruns::trim_possibly_truncated_tail;

    CHECK(trim_possibly_truncated_tail("a.timer b.service\n", true) == "a.timer b.service\n");
    CHECK(trim_possibly_truncated_tail("a.timer b.service", true) == "a.timer b.service");
    CHECK(trim_possibly_truncated_tail("a.timer b.service\n", false) == "a.timer b.service\n");
    CHECK(trim_possibly_truncated_tail("a.timer b.service\nc.timer d.se", false) ==
         "a.timer b.service\n");
    CHECK(trim_possibly_truncated_tail("c.timer d.se", false).empty());
    CHECK(trim_possibly_truncated_tail("", false).empty());
}

TEST_CASE("autoruns Linux leg: list_dir reports permission_denied, not absent, for a "
          "genuinely unreadable existing directory "
          "(RECONSTRUCTION: pins round 5's should-fix -- the round-4 XDG-denial fix "
          "had no regression test; this follows the same try-then-verify pattern "
          "already established in this repo (test_guardian_state_reader.cpp's "
          "read_file permission test) rather than a geteuid()==0 precheck, since "
          "even a non-root but capability-elevated runner can bypass the check)",
          "[autoruns][actions][linux]") {
    using yuzu::autoruns::list_dir;

    yuzu::test::TempDir dir("yuzu_test_autoruns_denied_");
    std::filesystem::create_directories(dir.path);
    std::error_code ec;
    std::filesystem::permissions(dir.path, std::filesystem::perms::none, ec);
    if (ec) SKIP("could not remove directory permissions");

    const auto listing = list_dir(dir.path.string());

    std::filesystem::permissions(dir.path, std::filesystem::perms::owner_all, ec); // restore for cleanup
    if (listing.opened) SKIP("running as root (or CAP_DAC_OVERRIDE): permission bits bypassed");

    CHECK_FALSE(listing.absent);        // the directory demonstrably EXISTS...
    CHECK(listing.permission_denied);   // ...so this is a real denial, never folded into "absent"
}

TEST_CASE("autoruns Linux leg: is_root_executable tests raw execute-mode bits, not "
          "this process's own effective uid/gid "
          "(RECONSTRUCTION: pins PR #4154 round 9's blocker -- ::access(path, X_OK) "
          "answers whether the UNPRIVILEGED yuzu agent account could execute the "
          "file, not whether root's own scheduler (run-parts(8) for "
          "cron.{hourly,daily,weekly,monthly}, init for /etc/rc.local) will -- a "
          "root-owned mode-0700/0744 script was silently dropped from those two "
          "collectors' rows even though root's scheduler runs it)",
          "[autoruns][actions][linux]") {
    using yuzu::autoruns::is_root_executable;

    yuzu::test::TempDir tmp("yuzu_test_autoruns_rootexec_");
    std::error_code ec;
    std::filesystem::create_directories(tmp.path, ec);
    REQUIRE_FALSE(ec);

    auto stat_of = [](const std::filesystem::path& p) {
        struct stat st{};
        REQUIRE(::stat(p.c_str(), &st) == 0);
        return st;
    };

    SECTION("0700 (owner-only execute) is eligible -- the shape a root-only "
            "persistence script actually has on disk") {
        std::filesystem::path f = tmp.path / "owner_only.sh";
        { std::ofstream(f) << "#!/bin/sh\n"; }
        std::filesystem::permissions(f, std::filesystem::perms::owner_all, ec);
        REQUIRE_FALSE(ec);
        CHECK(is_root_executable(stat_of(f)));
    }

    SECTION("0744 (owner all, group/other read-only) is eligible") {
        std::filesystem::path f = tmp.path / "owner_all_rest_read.sh";
        { std::ofstream(f) << "#!/bin/sh\n"; }
        std::filesystem::permissions(f,
                                     std::filesystem::perms::owner_all |
                                         std::filesystem::perms::group_read |
                                         std::filesystem::perms::others_read,
                                     ec);
        REQUIRE_FALSE(ec);
        CHECK(is_root_executable(stat_of(f)));
    }

    SECTION("no execute bit set anywhere is excluded") {
        std::filesystem::path f = tmp.path / "no_exec.sh";
        { std::ofstream(f) << "#!/bin/sh\n"; }
        std::filesystem::permissions(f,
                                     std::filesystem::perms::owner_read |
                                         std::filesystem::perms::owner_write,
                                     ec);
        REQUIRE_FALSE(ec);
        CHECK_FALSE(is_root_executable(stat_of(f)));
    }

    SECTION("a non-regular entry (a directory) is excluded even though it carries "
            "the search/execute bit") {
        std::filesystem::path d = tmp.path / "a_directory";
        std::filesystem::create_directory(d, ec);
        REQUIRE_FALSE(ec);
        std::filesystem::permissions(d, std::filesystem::perms::owner_all, ec);
        REQUIRE_FALSE(ec);
        CHECK_FALSE(is_root_executable(stat_of(d)));
    }
}

// ── PR #4154 round 9 structural finding: acquisition-failure accumulation ──
//
// Six Linux collectors each independently reinvented a narrower version of
// lnx_cron_d's already-correct constraint-composition pattern, tracking
// only EACCES/EPERM and silently dropping every other genuine acquisition
// failure (a real, non-permission directory-open error; a per-entry stat
// failure; a per-file read failure other than EACCES/EPERM; a crontab file
// with rejected lines) -- reporting the source Supported with whatever
// partial rows it did get, instead of Constrained. These tests exercise
// the REAL, now-shared production functions (scan_run_parts_dirs,
// scan_user_crontabs, timer_enabled) directly, asserting on the same
// (rows, support, reason) a real dispatch would emit.

TEST_CASE("autoruns Linux leg: scan_run_parts_dirs reports one successful root's row "
          "alongside a sibling directory's real open failure, never silently dropping it",
          "[autoruns][actions][linux]") {
    using yuzu::autoruns::scan_run_parts_dirs;
    using yuzu::autoruns::SourceId;

    yuzu::test::TempDir good_dir("yuzu_test_autoruns_runparts_good_");
    std::error_code ec;
    std::filesystem::create_directories(good_dir.path, ec);
    REQUIRE_FALSE(ec);
    std::filesystem::path script = good_dir.path / "backup";
    { std::ofstream(script) << "#!/bin/sh\n"; }
    std::filesystem::permissions(script, std::filesystem::perms::owner_all, ec);
    REQUIRE_FALSE(ec);

    // A REGULAR FILE where a directory is expected: opendir() on it fails
    // with a real, non-ENOENT, non-EACCES errno (ENOTDIR) -- standing in
    // for any real directory-open failure class (the code path is
    // identical for EIO), without needing root/mount tricks to construct
    // literal EIO in a unit test.
    yuzu::test::TempDir bad_parent("yuzu_test_autoruns_runparts_bad_");
    std::filesystem::create_directories(bad_parent.path, ec);
    REQUIRE_FALSE(ec);
    std::filesystem::path not_a_dir = bad_parent.path / "not_a_dir";
    { std::ofstream(not_a_dir) << "x"; }

    auto scan = scan_run_parts_dirs({good_dir.path.string(), not_a_dir.string()},
                                    SourceId::lnx_cron_periodic);

    REQUIRE(scan.rows.size() == 1);
    CHECK(scan.rows[0].entry == "backup");
    CHECK(scan.support == YUZU_SUPPORT_CONSTRAINED);
    CHECK(scan.reason.find("enotdir") != std::string::npos);
}

TEST_CASE("autoruns Linux leg: scan_run_parts_dirs distinguishes zero successful roots "
          "that genuinely don't exist from zero successful roots that failed to open "
          "for a real reason",
          "[autoruns][actions][linux]") {
    using yuzu::autoruns::scan_run_parts_dirs;
    using yuzu::autoruns::SourceId;

    SECTION("every root genuinely absent -> supported|0|absent") {
        auto scan = scan_run_parts_dirs(
            {"/nonexistent/yuzu-test-a", "/nonexistent/yuzu-test-b"}, SourceId::lnx_cron_periodic);
        CHECK(scan.rows.empty());
        CHECK(scan.support == YUZU_SUPPORT_SUPPORTED);
        CHECK(scan.reason == "absent");
    }

    SECTION("every root fails to open for a real (non-absent) reason -> constrained, "
            "distinguishable from confirmed absence") {
        yuzu::test::TempDir parent("yuzu_test_autoruns_runparts_allbad_");
        std::error_code ec;
        std::filesystem::create_directories(parent.path, ec);
        REQUIRE_FALSE(ec);
        std::filesystem::path not_a_dir_1 = parent.path / "f1";
        std::filesystem::path not_a_dir_2 = parent.path / "f2";
        { std::ofstream(not_a_dir_1) << "x"; }
        { std::ofstream(not_a_dir_2) << "x"; }

        auto scan =
            scan_run_parts_dirs({not_a_dir_1.string(), not_a_dir_2.string()}, SourceId::lnx_cron_periodic);
        CHECK(scan.rows.empty());
        CHECK(scan.support == YUZU_SUPPORT_CONSTRAINED);
        CHECK(scan.reason.find("enotdir") != std::string::npos);
    }
}

TEST_CASE("autoruns Linux leg: scan_run_parts_dirs reports a total (never \"partial_\") "
          "degradation when EVERY root fails, even when the failures are a mix of "
          "permission-denied and another real open error "
          "(RECONSTRUCTION: pins the fix for a branch-ordering defect the accumulator "
          "migration introduced -- zero-readable-roots with a mixed EACCES+ENOTDIR "
          "failure set used to land in the any_dir_readable branch by virtue of "
          "any_extra alone, wrongly emitting \"partial_permission_denied,...\" when "
          "nothing actually succeeded)",
          "[autoruns][actions][linux]") {
    using yuzu::autoruns::scan_run_parts_dirs;
    using yuzu::autoruns::SourceId;

    yuzu::test::TempDir denied_parent("yuzu_test_autoruns_runparts_mixed_denied_");
    std::error_code ec;
    std::filesystem::create_directories(denied_parent.path, ec);
    REQUIRE_FALSE(ec);
    std::filesystem::path denied_dir = denied_parent.path / "denied";
    std::filesystem::create_directories(denied_dir, ec);
    REQUIRE_FALSE(ec);
    std::filesystem::permissions(denied_dir, std::filesystem::perms::none, ec);
    if (ec) SKIP("could not remove directory permissions");

    yuzu::test::TempDir other_parent("yuzu_test_autoruns_runparts_mixed_other_");
    std::filesystem::create_directories(other_parent.path, ec);
    REQUIRE_FALSE(ec);
    std::filesystem::path not_a_dir = other_parent.path / "not_a_dir";
    { std::ofstream(not_a_dir) << "x"; }

    auto scan = scan_run_parts_dirs({denied_dir.string(), not_a_dir.string()},
                                    SourceId::lnx_cron_periodic);

    std::filesystem::permissions(denied_dir, std::filesystem::perms::owner_all, ec); // restore for cleanup
    if (scan.rows.empty() && scan.support == YUZU_SUPPORT_CONSTRAINED &&
        scan.reason.find("permission_denied") == std::string::npos) {
        SKIP("running as root (or CAP_DAC_OVERRIDE): permission bits bypassed");
    }

    CHECK(scan.rows.empty());
    CHECK(scan.support == YUZU_SUPPORT_CONSTRAINED);
    CHECK(scan.reason.find("partial_") == std::string::npos);
    CHECK(scan.reason.find("permission_denied") != std::string::npos);
    CHECK(scan.reason.find("enotdir") != std::string::npos);
}

TEST_CASE("autoruns Linux leg: scan_run_parts_dirs records a per-entry stat() failure "
          "as a real acquisition failure, distinct from the entry simply not being "
          "executable, among otherwise-successful entries in the same directory",
          "[autoruns][actions][linux]") {
    using yuzu::autoruns::scan_run_parts_dirs;
    using yuzu::autoruns::SourceId;

    yuzu::test::TempDir dir("yuzu_test_autoruns_runparts_stat_");
    std::error_code ec;
    std::filesystem::create_directories(dir.path, ec);
    REQUIRE_FALSE(ec);

    std::filesystem::path good = dir.path / "good";
    { std::ofstream(good) << "#!/bin/sh\n"; }
    std::filesystem::permissions(good, std::filesystem::perms::owner_all, ec);
    REQUIRE_FALSE(ec);

    // A dangling symlink: present in the directory listing, but ::stat()
    // (which follows symlinks, unlike the lstat used for at-spool/user-
    // crontabs' own non-regular-leaf check) fails with ENOENT on it a
    // moment later -- a genuine eligibility-metadata acquisition failure,
    // not "not executable".
    std::filesystem::path dangling = dir.path / "dangling";
    std::filesystem::create_symlink(dir.path / "does_not_exist", dangling, ec);
    REQUIRE_FALSE(ec);

    auto scan = scan_run_parts_dirs({dir.path.string()}, SourceId::lnx_cron_periodic);

    REQUIRE(scan.rows.size() == 1);
    CHECK(scan.rows[0].entry == "good");
    CHECK(scan.support == YUZU_SUPPORT_CONSTRAINED);
    CHECK(scan.reason.find("enoent") != std::string::npos);
}

TEST_CASE("autoruns Linux leg: scan_user_crontabs records a non-permission per-file "
          "read failure (previously silently dropped -- only EACCES/EPERM were "
          "tracked) alongside a valid sibling file's still-emitted row",
          "[autoruns][actions][linux]") {
    using yuzu::autoruns::kDefaultMaxReadBytes;
    using yuzu::autoruns::scan_user_crontabs;
    using yuzu::autoruns::SourceId;

    yuzu::test::TempDir dir("yuzu_test_autoruns_usercrontabs_");
    std::error_code ec;
    std::filesystem::create_directories(dir.path, ec);
    REQUIRE_FALSE(ec);

    std::filesystem::path good = dir.path / "alice";
    { std::ofstream(good) << "*/5 * * * * /usr/bin/true\n"; }

    // A regular file exceeding read_file_bounded's byte cap: OVERSIZED, a
    // real per-file failure class this collector's own bespoke
    // EACCES/EPERM-only check never surfaced. Not a symlink or other
    // non-regular leaf -- those are already filtered out by this
    // function's own lstat pre-check before read_file_bounded is even
    // called, so they can't reach this specific failure path.
    std::filesystem::path oversized = dir.path / "bob";
    {
        std::ofstream out(oversized, std::ios::binary);
        out << std::string(kDefaultMaxReadBytes + 1, 'x');
    }

    auto scan = scan_user_crontabs({dir.path.string()}, SourceId::lnx_user_crontabs);

    bool found_alice = false;
    for (const auto& row : scan.rows)
        if (row.user == "alice") found_alice = true;
    CHECK(found_alice);
    CHECK(scan.support == YUZU_SUPPORT_CONSTRAINED);
    CHECK(scan.reason.find("oversized") != std::string::npos);
}

TEST_CASE("autoruns Linux leg: timer_enabled reports unknown when no match is found "
          "AND the user_wants_bases discovery feeding it was incomplete, but a real "
          "match still registers as enabled despite that same incompleteness "
          "(RECONSTRUCTION: pins PR #4154 round 9's blocker -- an incomplete /home "
          "listing previously produced an incomplete user_wants_bases set with no "
          "uncertainty propagated into this decision at all)",
          "[autoruns][actions][linux]") {
    using yuzu::autoruns::Enabled;
    using yuzu::autoruns::Scope;
    using yuzu::autoruns::timer_enabled;

    yuzu::test::TempDir vendor_dir("yuzu_test_autoruns_incomplete_vendor_");
    yuzu::test::TempDir enabling_user_dir("yuzu_test_autoruns_incomplete_user_");
    std::error_code ec;
    std::filesystem::create_directories(vendor_dir.path, ec);
    REQUIRE_FALSE(ec);
    std::filesystem::create_directories(enabling_user_dir.path / "timers.target.wants", ec);
    REQUIRE_FALSE(ec);

    const auto unit_file = vendor_dir.path / "backup.timer";
    { std::ofstream f(unit_file); f << "[Timer]\nOnCalendar=daily\n"; }

    SECTION("no user_wants_bases entry matches, discovery marked incomplete -> unknown, "
            "never a confident disabled") {
        CHECK(timer_enabled(vendor_dir.path.string(), "backup.timer", "", Scope::user, {},
                            /*user_wants_bases_incomplete=*/true) == Enabled::unknown);
    }

    SECTION("discovery marked incomplete but the SAME timer IS enabled in an entry that "
            "DID make it into user_wants_bases -> the real match still registers, "
            "incompleteness does not suppress a positive result") {
        std::filesystem::create_symlink(
            unit_file, enabling_user_dir.path / "timers.target.wants" / "backup.timer", ec);
        REQUIRE_FALSE(ec);
        CHECK(timer_enabled(vendor_dir.path.string(), "backup.timer", "", Scope::user,
                            {enabling_user_dir.path.string()},
                            /*user_wants_bases_incomplete=*/true) == Enabled::enabled);
    }
}

TEST_CASE("autoruns Linux leg: timer_enabled treats a real (non-ENOENT) open failure "
          "on ONE candidate wants dir as incomplete, even with no "
          "user_wants_bases_incomplete flag set and a SIBLING candidate opening fine "
          "with no match "
          "(RECONSTRUCTION: pins PR #4154 round 9's blocker -- build_wants_listing "
          "previously collapsed a real open failure and plain ENOENT absence into the "
          "same 'not opened' outcome, so a readable sibling wants dir with no match "
          "could yield a confident disabled instead of unknown)",
          "[autoruns][actions][linux]") {
    using yuzu::autoruns::Enabled;
    using yuzu::autoruns::Scope;
    using yuzu::autoruns::timer_enabled;

    yuzu::test::TempDir vendor_dir("yuzu_test_autoruns_openerr_vendor_");
    yuzu::test::TempDir good_base("yuzu_test_autoruns_openerr_good_");
    yuzu::test::TempDir bad_base("yuzu_test_autoruns_openerr_bad_");
    std::error_code ec;
    std::filesystem::create_directories(vendor_dir.path, ec);
    REQUIRE_FALSE(ec);
    const auto unit_file = vendor_dir.path / "backup.timer";
    { std::ofstream f(unit_file); f << "[Timer]\nOnCalendar=daily\n"; }

    // good_base's own wants dir opens fine and genuinely has no match.
    std::filesystem::create_directories(good_base.path / "timers.target.wants", ec);
    REQUIRE_FALSE(ec);

    // bad_base's wants dir is a REGULAR FILE where a directory is expected:
    // opendir() fails with a real, non-ENOENT errno (ENOTDIR) -- a real
    // open failure, not plain absence.
    std::filesystem::create_directories(bad_base.path, ec);
    REQUIRE_FALSE(ec);
    { std::ofstream(bad_base.path / "timers.target.wants") << "not a directory"; }

    // user_wants_bases_incomplete is explicitly FALSE here -- this isolates
    // build_wants_listing's own open_error signal from the separate
    // caller-supplied incompleteness signal covered by the TEST_CASE above.
    CHECK(timer_enabled(vendor_dir.path.string(), "backup.timer", "", Scope::user,
                        {good_base.path.string(), bad_base.path.string()},
                        /*user_wants_bases_incomplete=*/false) == Enabled::unknown);
}

TEST_CASE("autoruns Linux leg: timer_enabled's wants_scan_incomplete_out out-parameter "
          "surfaces a real (non-ENOENT) wants-dir open failure to its caller "
          "(RECONSTRUCTION: pins the adversarial-review should-fix -- "
          "timer_enabled's own row-level Enabled::unknown for this exact case was "
          "already correct, but the failure signal never reached TimerScan/"
          "timer_scan_status, so a genuine wants-dir acquisition failure was "
          "indistinguishable from every candidate wants dir being cleanly absent "
          "at the SOURCE-level status line)",
          "[autoruns][actions][linux]") {
    using yuzu::autoruns::Enabled;
    using yuzu::autoruns::Scope;
    using yuzu::autoruns::timer_enabled;

    yuzu::test::TempDir vendor_dir("yuzu_test_autoruns_wantsoutp_vendor_");
    yuzu::test::TempDir bad_base("yuzu_test_autoruns_wantsoutp_bad_");
    std::error_code ec;
    std::filesystem::create_directories(vendor_dir.path, ec);
    REQUIRE_FALSE(ec);
    const auto unit_file = vendor_dir.path / "backup.timer";
    { std::ofstream f(unit_file); f << "[Timer]\nOnCalendar=daily\n"; }

    SECTION("a real open failure on a candidate wants dir sets the out-param true") {
        // Same ENOTDIR-via-regular-file trick as the sibling TEST_CASE above:
        // a real, non-ENOENT opendir() failure, not plain absence.
        std::filesystem::create_directories(bad_base.path, ec);
        REQUIRE_FALSE(ec);
        { std::ofstream(bad_base.path / "timers.target.wants") << "not a directory"; }

        bool wants_scan_incomplete = false;
        CHECK(timer_enabled(vendor_dir.path.string(), "backup.timer", "", Scope::user,
                            {bad_base.path.string()},
                            /*user_wants_bases_incomplete=*/false,
                            &wants_scan_incomplete) == Enabled::unknown);
        CHECK(wants_scan_incomplete);
    }

    SECTION("no open failure anywhere -- ordinary absence -- leaves the "
            "out-param false, never a false positive") {
        yuzu::test::TempDir good_base("yuzu_test_autoruns_wantsoutp_good_");
        std::filesystem::create_directories(good_base.path, ec); // no timers.target.wants at all: ENOENT
        REQUIRE_FALSE(ec);

        bool wants_scan_incomplete = false;
        CHECK(timer_enabled(vendor_dir.path.string(), "backup.timer", "", Scope::user,
                            {good_base.path.string()},
                            /*user_wants_bases_incomplete=*/false,
                            &wants_scan_incomplete) == Enabled::disabled);
        CHECK_FALSE(wants_scan_incomplete);
    }
}

TEST_CASE("autoruns Linux leg: a real wants-dir open failure constrains "
          "timer_scan_status's SOURCE-level status, composing with (not "
          "replacing) the affected row's own enabled=unknown "
          "(RECONSTRUCTION: pins the adversarial-review should-fix end to end -- "
          "asserts BOTH the row-level and the newly-threaded source-level effect "
          "of the same real wants-dir open failure via the actual "
          "scan_systemd_timer_dir_unique -> TimerScan -> timer_scan_status path, "
          "not just the timer_enabled unit above)",
          "[autoruns][actions][linux]") {
    using yuzu::autoruns::Enabled;
    using yuzu::autoruns::Row;
    using yuzu::autoruns::scan_systemd_timer_dir_unique;
    using yuzu::autoruns::Scope;
    using yuzu::autoruns::TimerScan;
    using yuzu::autoruns::timer_scan_status;

    yuzu::test::TempDir unit_dir("yuzu_test_autoruns_scanwants_unit_");
    yuzu::test::TempDir bad_base("yuzu_test_autoruns_scanwants_bad_");
    std::error_code ec;
    std::filesystem::create_directories(unit_dir.path, ec);
    REQUIRE_FALSE(ec);
    { std::ofstream f(unit_dir.path / "backup.timer"); f << "[Timer]\nOnCalendar=daily\n"; }

    // bad_base's wants dir is a regular file, not a directory: opendir()
    // fails ENOTDIR, a real (non-ENOENT) open failure.
    std::filesystem::create_directories(bad_base.path, ec);
    REQUIRE_FALSE(ec);
    { std::ofstream(bad_base.path / "timers.target.wants") << "not a directory"; }

    TimerScan scan;
    std::vector<std::pair<dev_t, ino_t>> seen_dirs;
    scan_systemd_timer_dir_unique(unit_dir.path.string(), Scope::user, "carol", scan, seen_dirs,
                                  {bad_base.path.string()});

    REQUIRE(scan.rows.size() == 1);
    CHECK(scan.rows[0].enabled == Enabled::unknown); // row-level: unaffected, already correct

    const auto [support, reason] = timer_scan_status(scan);
    CHECK(support == YUZU_SUPPORT_CONSTRAINED); // source-level: now also constrained
    CHECK(reason.find("wants_scan_incomplete") != std::string::npos);
}

TEST_CASE("autoruns Linux leg: a wants-dir scan that hits its entry cap (truncated, "
          "no real open failure) ALSO constrains timer_scan_status's SOURCE-level "
          "status via the SAME wants_scan_incomplete reason, not just the affected "
          "row's own enabled=unknown "
          "(RECONSTRUCTION: pins the governance-run top finding -- Gate 4 unhappy-"
          "path, Gate 5 chaos-injector, and Gate 6 sre independently converged on "
          "this gap: timer_enabled's any_incomplete already forced the row to "
          "Enabled::unknown for a capped/mid-scan-failed .wants directory, but "
          "wants_open_failure_out/wants_scan_incomplete_out only ever fired on "
          "open_error, so the SOURCE-level status line stayed a plain, misleadingly-"
          "clean `supported|-` for exactly the acquisition-failure case this "
          "plugin's whole reason for existing is to surface)",
          "[autoruns][actions][linux]") {
    using yuzu::autoruns::Enabled;
    using yuzu::autoruns::Row;
    using yuzu::autoruns::scan_systemd_timer_dir_unique;
    using yuzu::autoruns::Scope;
    using yuzu::autoruns::TimerScan;
    using yuzu::autoruns::timer_scan_status;

    yuzu::test::TempDir unit_dir("yuzu_test_autoruns_scanwants_cap_unit_");
    yuzu::test::TempDir capped_base("yuzu_test_autoruns_scanwants_cap_base_");
    std::error_code ec;
    std::filesystem::create_directories(unit_dir.path, ec);
    REQUIRE_FALSE(ec);
    { std::ofstream f(unit_dir.path / "backup.timer"); f << "[Timer]\nOnCalendar=daily\n"; }

    // capped_base's wants dir opens fine but is packed with more entries
    // (kMaxDirEntries + 1, matching the sibling cap test above) than the
    // 4096 cap, none of which is the "backup.timer" symlink this timer
    // would need to read as enabled -- a real cap-truncation, not an open
    // failure, so the pre-fix code left both the out-param and the
    // source-level status untouched. Symlinks (not real files) to keep the
    // fixture cheap, matching the existing cap test's own approach.
    const auto wants_dir = capped_base.path / "timers.target.wants";
    std::filesystem::create_directories(wants_dir, ec);
    REQUIRE_FALSE(ec);
    for (int i = 0; i < 4097; ++i) {
        const auto decoy = wants_dir / ("aaa-decoy-" + std::to_string(i) + ".timer");
        std::filesystem::create_symlink(unit_dir.path / "backup.timer", decoy);
    }

    TimerScan scan;
    std::vector<std::pair<dev_t, ino_t>> seen_dirs;
    scan_systemd_timer_dir_unique(unit_dir.path.string(), Scope::user, "dave", scan, seen_dirs,
                                  {capped_base.path.string()});

    REQUIRE(scan.rows.size() == 1);
    // Row-level: unaffected, already correct pre-fix (any_incomplete already
    // covered truncated).
    CHECK(scan.rows[0].enabled == Enabled::unknown);

    const auto [support, reason] = timer_scan_status(scan);
    // Source-level: THIS is the fix -- a capped .wants scan must constrain
    // the source status too, not just the row.
    CHECK(support == YUZU_SUPPORT_CONSTRAINED);
    CHECK(reason.find("wants_scan_incomplete") != std::string::npos);
}

TEST_CASE("autoruns Linux leg: scan_cron_d wires a rejected crontab line into a "
          "'malformed' constraint while still emitting the file's other valid entries "
          "(RECONSTRUCTION: pins PR #4154 round 9's should-fix -- rejected_lines was "
          "computed and tested by parse_crontab since its introduction but never "
          "consumed by any caller)",
          "[autoruns][actions][linux]") {
    using yuzu::autoruns::scan_cron_d;
    using yuzu::autoruns::SourceId;

    yuzu::test::TempDir dir("yuzu_test_autoruns_crond_malformed_");
    std::error_code ec;
    std::filesystem::create_directories(dir.path, ec);
    REQUIRE_FALSE(ec);

    {
        std::ofstream f(dir.path / "myjob");
        f << "*/5 * * * * root /usr/bin/true\n"; // valid (5 schedule + user + command)
        f << "* * * *\troot\tcommand\n";          // malformed: only 4 schedule fields
    }

    auto scan = scan_cron_d(dir.path.string(), SourceId::lnx_cron_d);

    REQUIRE(scan.rows.size() == 1);
    CHECK(scan.rows[0].target == "/usr/bin/true");
    CHECK(scan.support == YUZU_SUPPORT_CONSTRAINED);
    CHECK(scan.reason.find("malformed") != std::string::npos);
}

TEST_CASE("autoruns Linux leg: scan_cron_d does NOT flag a crontab as malformed "
          "for spaced environment-variable assignments end to end "
          "(RECONSTRUCTION: pins the adversarial-review should-fix -- "
          "'MAILTO = root' (and the other spaced variants) used to be misparsed "
          "as a malformed cron command, wiring a constrained|...|malformed "
          "status onto an otherwise entirely valid crontab file via this exact "
          "collector)",
          "[autoruns][actions][linux]") {
    using yuzu::autoruns::scan_cron_d;
    using yuzu::autoruns::SourceId;

    yuzu::test::TempDir dir("yuzu_test_autoruns_crond_spaced_assign_");
    std::error_code ec;
    std::filesystem::create_directories(dir.path, ec);
    REQUIRE_FALSE(ec);

    {
        std::ofstream f(dir.path / "myjob");
        f << "MAILTO = root\n";       // spaces both sides
        f << "PATH= /usr/bin:/bin\n"; // space after '=' only
        f << "HOME =/root\n";         // space before '=' only
        f << "SHELL=/bin/sh\n";       // tight form -- no regression
        f << "*/5 * * * * root /usr/bin/true\n"; // one real, valid entry
    }

    auto scan = scan_cron_d(dir.path.string(), SourceId::lnx_cron_d);

    REQUIRE(scan.rows.size() == 1);
    CHECK(scan.rows[0].target == "/usr/bin/true");
    CHECK(scan.support == YUZU_SUPPORT_SUPPORTED);
    CHECK(scan.reason.find("malformed") == std::string::npos);
}

TEST_CASE("autoruns Linux leg: scan_xdg_autostart_user distinguishes a real "
          "(non-ENOENT) home-root open failure from genuine confirmed absence "
          "(RECONSTRUCTION: pins PR #4154 round 9's sharpest blocker -- this "
          "collector has NO permanent catalog-level constraint composing with it, "
          "unlike lnx_systemd_timers_user, so a real /home failure previously fell "
          "all the way through to a bare 'supported|0|absent')",
          "[autoruns][actions][linux]") {
    using yuzu::autoruns::scan_xdg_autostart_user;
    using yuzu::autoruns::SourceId;

    SECTION("home_root is a regular file, not a directory -> constrained, not "
            "confirmed absence") {
        yuzu::test::TempDir parent("yuzu_test_autoruns_xdguser_bad_");
        std::error_code ec;
        std::filesystem::create_directories(parent.path, ec);
        REQUIRE_FALSE(ec);
        std::filesystem::path not_a_dir = parent.path / "not_home";
        { std::ofstream(not_a_dir) << "x"; }

        auto scan = scan_xdg_autostart_user(SourceId::lnx_xdg_autostart_user, not_a_dir.string());
        CHECK(scan.rows.empty());
        CHECK(scan.support == YUZU_SUPPORT_CONSTRAINED);
        CHECK(scan.reason.find("enotdir") != std::string::npos);
    }

    SECTION("home_root genuinely does not exist -> supported|0|absent") {
        auto scan = scan_xdg_autostart_user(SourceId::lnx_xdg_autostart_user,
                                            "/nonexistent/yuzu-test-home-root");
        CHECK(scan.rows.empty());
        CHECK(scan.support == YUZU_SUPPORT_SUPPORTED);
        CHECK(scan.reason == "absent");
    }
}

TEST_CASE("autoruns Linux leg: systemd_user_timer_status's three dispatch branches "
          "each independently reachable, not just whichever one this host's own "
          "/run/systemd/system state happens to hit (PR #4154 round 8's should-fix, "
          "previously never actually driven into all three shapes by any test)",
          "[autoruns][actions][linux]") {
    using yuzu::autoruns::systemd_user_timer_status;
    using yuzu::autoruns::TimerScan;

    SECTION("branch 1: a readable directory somewhere -- routes through "
            "timer_scan_status, then the permanent narrow-search-path-coverage "
            "downgrade composes on top (a clean scan's would-be Supported "
            "becomes Constrained/narrow_search_path_coverage, never a bare "
            "Supported -- this source's catalog-declared permanent gap, "
            "apply_narrow_search_path_coverage's own banner)") {
        TimerScan scan; // clean: no truncation, no constraint of any kind
        const auto [support, reason, rows] =
            systemd_user_timer_status(/*any_dir_readable=*/true,
                                      /*home_listing_opened=*/false,
                                      /*home_listing_permission_denied=*/false, scan);
        CHECK(support == YUZU_SUPPORT_CONSTRAINED);
        CHECK(reason == "narrow_search_path_coverage");
        CHECK(rows == 0);
    }

    SECTION("branch 1, a genuinely constrained scan: the scan's own reason "
            "composes alongside the permanent coverage gap, not replaced by it") {
        TimerScan scan;
        scan.any_truncated = true;
        const auto [support, reason, rows] =
            systemd_user_timer_status(/*any_dir_readable=*/true,
                                      /*home_listing_opened=*/false,
                                      /*home_listing_permission_denied=*/false, scan);
        CHECK(support == YUZU_SUPPORT_CONSTRAINED);
        CHECK(reason == "row_cap,narrow_search_path_coverage");
        CHECK(rows == 0);
    }

    SECTION("branch 2: /home itself permission-denied (and branch 1's condition "
            "is false) -- permission_denied composes with the coverage gap") {
        TimerScan scan; // any_dir_readable/home_listing_opened/any_dir_open_failure all false
        const auto [support, reason, rows] =
            systemd_user_timer_status(/*any_dir_readable=*/false,
                                      /*home_listing_opened=*/false,
                                      /*home_listing_permission_denied=*/true, scan);
        CHECK(support == YUZU_SUPPORT_CONSTRAINED);
        CHECK(reason == "permission_denied,narrow_search_path_coverage");
        CHECK(rows == 0);
    }

    SECTION("branch 3: the terminal case -- no readable directory anywhere and "
            "/home itself is genuinely absent (neither branch 1 nor branch 2's "
            "condition holds) -- still Constrained via the coverage gap, never "
            "the bare Supported this source's own catalog declaration forbids") {
        TimerScan scan;
        const auto [support, reason, rows] =
            systemd_user_timer_status(/*any_dir_readable=*/false,
                                      /*home_listing_opened=*/false,
                                      /*home_listing_permission_denied=*/false, scan);
        CHECK(support == YUZU_SUPPORT_CONSTRAINED);
        CHECK(reason == "narrow_search_path_coverage");
        CHECK(rows == 0);
    }
}

#endif // defined(__linux__)

TEST_CASE("autoruns Linux leg: an unknown action is refused, not silently ignored",
          "[autoruns][actions][linux]") {
    auto plugin = load_autoruns_plugin();
    if (!plugin) {
        require_plugin_or_skip();
        return;
    }
    yuzu::agent::LocalDispatcher dispatcher;
    auto result = dispatcher.run(plugin->descriptor, "no_such_action");
    CHECK(result.rc != 0);
}
