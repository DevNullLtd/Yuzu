/**
 * test_middleware_linux_parsers.cpp -- tests for the middleware plugin's Linux leg
 * (middleware_linux_parsers.hpp): the path guards, the budgets and the injected-root walk over a
 * materialized tree, driven through a real CommandContext (LocalDispatcher) so the rows AND the
 * typed result status are what is asserted.
 *
 * SCOPED GUARD (reasoned exception to the never-guard-a-test-TU rule): the leg is built on openat /
 * posix_dir_walk.hpp, which do not exist on Windows, so the body sits in one `#if !defined(_WIN32)`
 * region; the generic runner and the table have their own unguarded suite
 * (test_middleware_parsers.cpp) and the plugin round-trip is unguarded in
 * test_middleware_local_dispatcher.cpp.
 *
 * FIXTURES. mqinst.ini is the REAL byte-exact file of a REGISTERED IBM MQ 9.4.5.0 install (one
 * stanza, `Installation1` at /opt/mqm, Description padded with 64 trailing spaces, no Primary key),
 * and the swidtag directories carry the REAL captured names (swidtag.listing, provenance.txt there).
 * The registered install's tree is DERIVED FROM tree.manifest: its one path is the install root,
 * which must be the mqinst.ini stanza's FilePath, and a manifest path with no fixture fails the
 * test, so a changed capture layout cannot slip past. It is materialized under a fresh
 * yuzu_test_middleware_ TempDir. A registered install holds one stanza, so every second
 * installation, every symlink, oversized file and 257-stanza file is built inline and labelled
 * SYNTHETIC.
 *
 * CANARIES. "Never opened" is proved two ways. By CONTENT: the path the walk must not take leads
 * (if followed, normalised or resolved) to a VALID swidtag directory, so a walk that reached it
 * would show its version in the row. By TOUCH LOG: lnx::t_touch_log records the identity of every
 * directory the walk opens, and each refusal asserts that its canary directories are absent from
 * it -- a refusal's rows and tokens are identical whether the guard ran before or after the open.
 * Every table runs a positive control first, which must show the same directories in the log.
 *
 * MUTATION NOTES: dropping the lexical guard, or running the mount guard after the walk, turns the
 * touch-log assertions of the `.`/`..`/relative/trailing-slash/network rows red; the path form of
 * open (follows intermediates) turns the symlinked-intermediate rows red; dropping O_NOFOLLOW on
 * the leaf turns the symlinked mqinst.ini / swidtag rows red; a tokened per-item reason turns
 * check_run red; resetting the entries budget per listing turns the cross-installation budget case
 * red; a second RowByteBudget built from the raw limits turns the rows / row_bytes cases red, and
 * dropping the clamp in make_row_budget turns the clamp case red; matching a component tag
 * (IBM_MQ_Runtime-...) as the product turns the component-tags-only cases red. The chmod cases
 * SKIP at euid 0; the symlink, cap and oversize cases cover the same constrained paths there.
 */
#include <catch2/catch_test_macros.hpp>

#include "middleware_legs.hpp"
#include "middleware_linux_parsers.hpp"
#include "middleware_parsers.hpp"

#include "test_helpers.hpp" // yuzu::test::TempDir, ScopeExit

#include <algorithm>
#include <cstddef>
#include <filesystem>
#include <fstream>
#include <functional>
#include <iterator>
#include <limits>
#include <sstream>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

#if !defined(_WIN32)
#include "local_dispatcher.hpp" // yuzu::agent::LocalDispatcher (a real CommandContext)
#include "test_log_capture.hpp" // yuzu::test::LogCapture (the leg is compiled into this binary)

#include <yuzu/plugin.h>

#include <sys/stat.h>
#include <unistd.h>

namespace mw = yuzu::middleware;
namespace lnx = yuzu::middleware::lnx;
namespace fs = std::filesystem;

namespace {

const mw::Product& ibm_mq() {
    const mw::Product* p = mw::find_product("ibm_mq");
    REQUIRE(p != nullptr);
    return *p;
}

// -- fixtures ---------------------------------------------------------------------------------

fs::path fixture_dir() {
#ifdef YUZU_TEST_FIXTURE_DIR
    return fs::path(YUZU_TEST_FIXTURE_DIR) / "middleware" / "linux";
#else
    return fs::path("tests/unit/fixtures/middleware/linux");
#endif
}

std::string read_fixture(const char* name) {
    std::ifstream in(fixture_dir() / name, std::ios::binary);
    REQUIRE(in.good());
    return std::string(std::istreambuf_iterator<char>(in), std::istreambuf_iterator<char>());
}

/// The file names of the swidtag.listing section whose `#` header contains `tag` (REAL CAPTURE
/// names; `ls -ln` file lines start with '-', directory lines with 'd').
std::vector<std::string> listing_names(std::string_view tag) {
    std::istringstream in(read_fixture("swidtag.listing"));
    std::vector<std::string> out;
    bool in_section = false;
    for (std::string line; std::getline(in, line);) {
        if (!line.empty() && line.front() == '#') {
            in_section = line.find(tag) != std::string::npos;
        } else if (in_section && !line.empty() && line.front() == '-') {
            out.push_back(line.substr(line.rfind(' ') + 1));
        }
    }
    REQUIRE_FALSE(out.empty());
    return out;
}

// The captured directories used here, by the text their listing section header carries.
constexpr const char* kTag945 = "9.4.5.0 debs"; // the REGISTERED install (mqinst.ini's source)
constexpr const char* kTag935 = "mq:9.3.5.1-r2";
constexpr const char* kTag925 = "mq:9.2.5.0-r3";

bool ends_with(const std::string& s, std::string_view suffix) {
    return s.size() >= suffix.size() && s.compare(s.size() - suffix.size(), suffix.size(), suffix) == 0;
}

std::string swidtag_of(const char* tag) {
    for (const auto& n : listing_names(tag))
        if (ends_with(n, ".swidtag")) return n;
    FAIL("no .swidtag in the listing section");
    return {};
}

// -- tree builders ------------------------------------------------------------------------------

void write_text(const fs::path& p, const std::string& text) {
    std::error_code ec;
    fs::create_directories(p.parent_path(), ec);
    REQUIRE_FALSE(ec);
    std::ofstream out(p, std::ios::binary);
    REQUIRE(out.good());
    out << text;
}

void make_dir(const fs::path& p) {
    std::error_code ec;
    fs::create_directories(p, ec);
    REQUIRE_FALSE(ec);
}

void touch_names(const fs::path& dir, const std::vector<std::string>& names) {
    make_dir(dir);
    for (const auto& n : names) write_text(dir / n, "");
}

/// A symlink at `link` with the (relative) link text `target`.
void make_link(const std::string& target, const fs::path& link) {
    make_dir(link.parent_path());
    std::error_code ec;
    fs::create_symlink(target, link, ec);
    REQUIRE_FALSE(ec);
}

/// Replaces `p` with a symlink to its renamed original: the content stays reachable through the
/// link, so a walk that followed it would read the real thing (the canary).
void relink(const fs::path& p) {
    const fs::path real = p.string() + ".real";
    fs::rename(p, real);
    make_link(real.filename().string(), p);
}

/// Restores a path's permission bits at scope exit (declared AFTER the TempDir so it runs first
/// and remove_all can descend).
struct PermRestore {
    fs::path path;
    ~PermRestore() { ::chmod(path.c_str(), 0755); }
};

bool running_privileged() { return ::geteuid() == 0; }

/// A walk config with one network mount at `mount`.
lnx::WalkConfig net(const char* mount) {
    lnx::WalkConfig cfg;
    cfg.network_mounts = {mount};
    return cfg;
}

/// One row of a path table: the install path under test, a hook that builds extra tree, a config,
/// and the directories (relative to the root) the walk must NEVER open for it.
struct PathCase {
    const char* label;
    std::string path;
    std::function<void(const fs::path&)> extra;
    lnx::WalkConfig cfg;
    std::vector<std::string> never;
};

std::string mq_stanza(const std::string& name, const std::string& file_path) {
    return "Installation:\n   Name=" + name + "\n   FilePath=" + file_path + "\n";
}

/// The mqinst.ini path and the swidtag sub-directory name, READ FROM THE TABLE so that a table
/// change cannot leave these tests passing against a tree nothing reads.
std::string enumerator_rel() { return std::string{ibm_mq().linux.probes[0].path}.substr(1); }
std::string swidtag_dir() { return ibm_mq().linux.probes[1].path; }

// -- the registered install, derived from tree.manifest -------------------------------------------

/// The captured install root: the manifest's ONE path, which must be the FilePath of the real
/// mqinst.ini stanza. A manifest path no fixture accounts for fails the test.
std::string captured_install_root() {
    std::vector<std::string> paths;
    std::istringstream in(read_fixture("tree.manifest"));
    for (std::string line; std::getline(in, line);)
        if (!line.empty() && line.front() != '#') paths.push_back(line.substr(line.rfind(' ') + 1));
    mw::ParseReport rep;
    const auto stanzas = mw::parse_kv_stanzas(read_fixture("mqinst.ini"), "Installation:", rep);
    REQUIRE(stanzas.size() == 1);
    const std::string* file_path = stanzas[0].get("FilePath");
    REQUIRE(file_path != nullptr);
    for (const auto& p : paths) {
        INFO("tree.manifest path with no fixture: " << p);
        REQUIRE(p == *file_path);
    }
    REQUIRE(paths.size() == 1);
    return *file_path;
}

/// The registered 9.4.5.0 install: the real mqinst.ini and, under its FilePath, the real swidtag
/// names of that install (the product swidtag and mqtag plus the two component tags).
void write_registered_install(const fs::path& root) {
    write_text(root / enumerator_rel(), read_fixture("mqinst.ini"));
    touch_names(root / captured_install_root().substr(1) / swidtag_dir(), listing_names(kTag945));
}

// -- CommandContext-level harness -----------------------------------------------------------------
// Drives the PRODUCTION leg body (lnx::run_linux_at) through a real CommandContext via
// LocalDispatcher (the test_runtimes_linux_parsers.cpp precedent).

struct LegRun {
    int rc = -1;
    std::vector<std::string> rows;
    YuzuResultStatus status = YUZU_RESULT_STATUS_UNDECLARED;
    YuzuResultCompleteness completeness = YUZU_RESULT_COMPLETENESS_UNKNOWN;
    std::string provenance;
    std::vector<lnx::FileId> touched; // every directory the walk opened (lnx::t_touch_log)

    /// True iff the walk opened directory `dir` (which must exist: a canary that is not there
    /// proves nothing). Call while the tree is still on disk.
    [[nodiscard]] bool opened(const fs::path& dir) const {
        struct stat st{};
        REQUIRE(::stat(dir.c_str(), &st) == 0);
        return std::find(touched.begin(), touched.end(), lnx::FileId{st.st_dev, st.st_ino}) !=
               touched.end();
    }
};

/// Asserts the walk opened every directory in `opened` (the positive control: it proves the touch
/// log sees this tree) and none in `never` (the canaries). Paths are relative to `root`.
void check_touched(const LegRun& r, const fs::path& root, const std::vector<std::string>& opened,
                   const std::vector<std::string>& never) {
    for (const auto& rel : opened) {
        INFO("expected opened: " << rel);
        CHECK(r.opened(root / rel));
    }
    for (const auto& rel : never) {
        INFO("must never be opened: " << rel);
        CHECK_FALSE(r.opened(root / rel));
    }
}

const fs::path* g_leg_root = nullptr;
const lnx::WalkConfig* g_leg_cfg = nullptr;

int leg_execute(YuzuCommandContext* raw, const char* action, const YuzuParam* /*params*/,
                std::size_t /*param_count*/) {
    yuzu::CommandContext ctx{raw};
    const mw::Product* p = mw::find_product(action);
    if (p == nullptr) return 1;
    return lnx::run_linux_at(ctx, *p, *g_leg_root, *g_leg_cfg);
}

std::vector<std::string> split_bar(const std::string& s) {
    std::vector<std::string> out;
    std::size_t pos = 0;
    for (;;) {
        const auto bar = s.find('|', pos);
        out.push_back(s.substr(pos, bar == std::string::npos ? std::string::npos : bar - pos));
        if (bar == std::string::npos) return out;
        pos = bar + 1;
    }
}

bool is_cause_name(std::string_view s) {
    for (int c = 0; c <= static_cast<int>(mw::Cause::internal_error); ++c)
        if (mw::cause_name(static_cast<mw::Cause>(c)) == s) return true;
    return false;
}

/// The `<source>` of a token: a probe id of the Linux leg, or `walk` / `mountinfo`.
bool is_source_name(std::string_view s) {
    if (s == "walk" || s == "mountinfo") return true;
    for (const mw::Probe& pr : ibm_mq().linux.probes)
        if (s == pr.id) return true;
    return false;
}

/// Applied by run_leg to every run: the status row is first and names the action; the typed status
/// is OK/FULL exactly when there is no token and CONSTRAINED/PARTIAL (provenance = the comma-joined
/// tokens) otherwise; and every token is `linux:middleware:<source>:<cause>` with a known source
/// and a cause from the closed set -- a per-item spelling in the status row is a leg bug.
void check_run(const LegRun& r, std::string_view action) {
    CHECK(r.rc == 0);
    REQUIRE_FALSE(r.rows.empty());
    const auto f = split_bar(r.rows.front());
    REQUIRE(f.size() == 4);
    CHECK(f[0] == "status");
    CHECK(f[1] == action);
    for (std::size_t i = 1; i < r.rows.size(); ++i) {
        const auto d = split_bar(r.rows[i]);
        CHECK(d.size() == 6);
        CHECK(d[0] == action);
    }
    if (f[3] == "-") {
        CHECK(f[2] == "supported");
        CHECK(r.status == YUZU_RESULT_STATUS_OK);
        CHECK(r.completeness == YUZU_RESULT_COMPLETENESS_FULL);
        CHECK(r.provenance.empty());
        return;
    }
    CHECK(f[2] == "constrained");
    CHECK(r.status == YUZU_RESULT_STATUS_CONSTRAINED);
    CHECK(r.completeness == YUZU_RESULT_COMPLETENESS_PARTIAL);
    CHECK(r.provenance == f[3]);
    constexpr std::string_view prefix = "linux:middleware:";
    std::size_t pos = 0;
    while (pos <= f[3].size()) {
        auto comma = f[3].find(',', pos);
        if (comma == std::string::npos) comma = f[3].size();
        const std::string token = f[3].substr(pos, comma - pos);
        pos = comma + 1;
        INFO("token: " << token);
        REQUIRE(token.substr(0, prefix.size()) == prefix);
        const auto rest = std::string_view{token}.substr(prefix.size());
        const auto colon = rest.find(':');
        REQUIRE(colon != std::string_view::npos);
        CHECK(is_source_name(rest.substr(0, colon)));
        CHECK(is_cause_name(rest.substr(colon + 1)));
    }
}

LegRun run_leg(const fs::path& root, const lnx::WalkConfig& cfg = {}) {
    LegRun out;
    g_leg_root = &root;
    g_leg_cfg = &cfg;
    lnx::t_touch_log = &out.touched;
    yuzu::test::ScopeExit reset{[] {
        g_leg_root = nullptr;
        g_leg_cfg = nullptr;
        lnx::t_touch_log = nullptr;
    }};
    YuzuPluginDescriptor descriptor{};
    descriptor.execute = &leg_execute;
    yuzu::agent::LocalDispatcher dispatcher;
    const auto result = dispatcher.run(&descriptor, ibm_mq().id);

    out.rc = result.rc;
    out.status = result.result_status;
    out.completeness = result.result_completeness;
    out.provenance = result.result_provenance;
    std::istringstream lines(result.captured);
    for (std::string line; std::getline(lines, line);)
        if (!line.empty()) out.rows.push_back(line);
    check_run(out, ibm_mq().id);
    return out;
}

/// The status row's token field ("-" when none).
std::string tokens_of(const LegRun& r) {
    REQUIRE_FALSE(r.rows.empty());
    const auto f = split_bar(r.rows.front());
    REQUIRE(f.size() == 4);
    return f[3];
}

std::vector<std::string> data_rows(const LegRun& r) {
    return r.rows.empty() ? std::vector<std::string>{}
                          : std::vector<std::string>(r.rows.begin() + 1, r.rows.end());
}

std::string tok(std::string_view source, std::string_view cause) {
    return std::string{"linux:middleware:"} + std::string{source} + ":" + std::string{cause};
}

/// The row of one installation (title, then name, version, install path, edition `-`).
std::string mq_row(const std::string& name, const std::string& version, const std::string& path) {
    return "ibm_mq|IBM MQ|" + name + "|" + version + "|" + path + "|-";
}

} // namespace

// == pure guards ===================================================================================

TEST_CASE("middleware linux: lexically_plain accepts only absolute paths of plain components",
          "[middleware][linux][guards]") {
    for (const char* ok : {"/opt/mqm", "/a", "/opt/ibm/mq/9.4", "/opt/a.b/c-d"}) {
        INFO("path: " << ok);
        CHECK(lnx::lexically_plain(ok));
    }
    for (const char* bad : {"", "/", "opt/mqm", "./opt", "/opt/mqm/", "//opt/mqm", "/opt//mqm",
                            "/opt/./mqm", "/opt/../mqm", "/opt/mqm/.", "/opt/mqm/..", "/..", "/."}) {
        INFO("path: " << bad);
        CHECK_FALSE(lnx::lexically_plain(bad));
    }
    CHECK_FALSE(lnx::lexically_plain(std::string_view{"/opt/m\0qm", 9})); // embedded NUL
}

TEST_CASE("middleware linux: a path touches a network mount when on, under or containing it",
          "[middleware][linux][guards]") {
    const std::vector<std::string> mounts{"/opt/mqm"};
    CHECK(lnx::touches_network_mount("/opt/mqm", mounts));
    CHECK(lnx::touches_network_mount("/opt/mqm/swidtag", mounts)); // under
    CHECK(lnx::touches_network_mount("/opt", mounts));             // contains
    CHECK_FALSE(lnx::touches_network_mount("/opt/mqm2", mounts));  // segment boundary
    CHECK_FALSE(lnx::touches_network_mount("/etc/opt/mqm", mounts));
    CHECK(lnx::touches_network_mount("/etc/opt/mqm", std::vector<std::string>{"/"})); // NFS root
    CHECK_FALSE(lnx::touches_network_mount("/etc/opt/mqm", std::vector<std::string>{}));
}

TEST_CASE("middleware linux: production_config reads the network mounts and flags an unreadable table",
          "[middleware][linux][mounts]") {
    yuzu::test::TempDir dir{"yuzu_test_middleware_mounts_"};
    // SYNTHETIC lines in /proc/self/mountinfo form: one nfs4 mount, one local root.
    write_text(dir.path / "mountinfo",
               "10 1 0:5 / /mnt/nfs rw shared:1 - nfs4 h:/x rw\n11 1 0:6 / / rw - ext4 /dev/x rw\n");
    const auto good = lnx::production_config((dir.path / "mountinfo").c_str());
    CHECK(good.network_mounts == std::vector<std::string>{"/mnt/nfs"});
    CHECK_FALSE(good.mountinfo_unreadable);
    CHECK(lnx::production_config((dir.path / "absent").c_str()).mountinfo_unreadable);
}

// == the budget ====================================================================================

TEST_CASE("middleware linux: the leg's row budget is the injected limits clamped to the production ceilings",
          "[middleware][linux][caps]") {
    // The defaults ARE the ceilings (and the walk's own entries allowance), pinned by value.
    static_assert(lnx::WalkLimits{}.rows == mw::kMaxRows &&
                  lnx::WalkLimits{}.row_bytes == mw::kMaxRowBytes &&
                  lnx::WalkLimits{}.dir_entries == mw::kMaxDirEntries &&
                  lnx::WalkLimits{}.entries_visited == 65536);
    static_assert(mw::kMaxRows == 256 && mw::kMaxRowBytes == 1048576);

    lnx::WalkLimits above;
    above.rows = 100000;
    above.row_bytes = (std::numeric_limits<std::size_t>::max)();
    auto b = mw::make_row_budget(above.rows, above.row_bytes);
    CHECK(b.max_rows == mw::kMaxRows); // a test (or a config) can lower a cap, never raise one
    CHECK(b.max_bytes == mw::kMaxRowBytes);
    CHECK(b.rows == 0);
    CHECK(b.bytes == 0);

    lnx::WalkLimits below;
    below.rows = 2;
    below.row_bytes = 10;
    b = mw::make_row_budget(below.rows, below.row_bytes);
    CHECK(b.max_rows == 2);
    CHECK(b.max_bytes == 10);

    const lnx::WalkLimits defaults;
    const auto def = mw::make_row_budget(defaults.rows, defaults.row_bytes);
    CHECK(def.max_rows == mw::kMaxRows);
    CHECK(def.max_bytes == mw::kMaxRowBytes);
}

// == ibm_mq ========================================================================================

TEST_CASE("middleware linux: the REAL registered install gives one row, typed OK/FULL",
          "[middleware][linux][ibm_mq]") {
    yuzu::test::TempDir dir{"yuzu_test_middleware_mq_"};
    write_registered_install(dir.path);

    const auto run = run_leg(dir.path); // check_run: status row first, OK/FULL, no token
    CHECK(tokens_of(run) == "-");
    CHECK(run.rows.front() == "status|ibm_mq|supported|-");
    // The version is the one in the REAL swidtag name (9.4.5), the Description padding is not echoed.
    CHECK(data_rows(run) == std::vector<std::string>{mq_row("Installation1", "9.4.5", "/opt/mqm")});
    CHECK(run.rc == 0);

    SECTION("without the swidtag the product mqtag still names 9.4.5, the component tags never do") {
        fs::remove(dir.path / "opt/mqm/swidtag" / swidtag_of(kTag945));
        const auto tag_only = run_leg(dir.path);
        CHECK(tokens_of(tag_only) == "-");
        CHECK(data_rows(tag_only) ==
              std::vector<std::string>{mq_row("Installation1", "9.4.5", "/opt/mqm")});
    }
}

TEST_CASE("middleware linux: two installations give two rows in file order (SYNTHETIC second stanza)",
          "[middleware][linux][ibm_mq]") {
    yuzu::test::TempDir dir{"yuzu_test_middleware_mq2_"};
    // SYNTHETIC: a registered install holds one stanza, so the second is built inline. Both swidtag
    // directories carry REAL captured names (the registered 9.4.5.0 and the 9.2.5 image's ~20 files).
    write_text(dir.path / enumerator_rel(),
               mq_stanza("Installation1", "/opt/mqm") + mq_stanza("Installation2", "/opt/mqm2"));
    touch_names(dir.path / "opt/mqm/swidtag", listing_names(kTag945));
    touch_names(dir.path / "opt/mqm2/swidtag", listing_names(kTag925));

    const auto run = run_leg(dir.path);
    CHECK(tokens_of(run) == "-");
    CHECK(data_rows(run) == std::vector<std::string>{mq_row("Installation1", "9.4.5", "/opt/mqm"),
                                                     mq_row("Installation2", "9.2.5", "/opt/mqm2")});
}

TEST_CASE("middleware linux: component tags alone name no product, so the version is - and nothing is tokened",
          "[middleware][linux][ibm_mq]") {
    yuzu::test::TempDir dir{"yuzu_test_middleware_mqcomp_"};
    write_text(dir.path / enumerator_rel(), mq_stanza("Inst", "/opt/mqm"));
    // The REAL 9.2.5 names minus its two PRODUCT tags (the .swidtag and IBM_MQ-9.2.5.mqtag): what
    // is left is the ~19 component tags (IBM_MQ_Runtime-9.2.5, IBM_MQ_Advanced-9.2.5, GSKit, JRE...).
    std::vector<std::string> names;
    for (const auto& n : listing_names(kTag925))
        if (!ends_with(n, ".swidtag") && n != "IBM_MQ-9.2.5.mqtag") names.push_back(n);
    REQUIRE(names.size() == listing_names(kTag925).size() - 2);
    REQUIRE(std::find(names.begin(), names.end(), "IBM_MQ_Runtime-9.2.5.mqtag") != names.end());
    touch_names(dir.path / "opt/mqm/swidtag", names);

    yuzu::test::LogCapture capture;
    const auto run = run_leg(dir.path);
    capture.stop();
    CHECK(tokens_of(run) == "-"); // per-item: the host is not constrained by one unknown version
    CHECK(data_rows(run) == std::vector<std::string>{mq_row("Inst", "-", "/opt/mqm")});
    CHECK(capture.text().find("middleware ibm_mq: mqtag: missing (Inst)") != std::string::npos);

    SECTION("the registered install's two component tags alone behave the same") {
        yuzu::test::TempDir d2{"yuzu_test_middleware_mqcomp2_"};
        write_text(d2.path / enumerator_rel(), mq_stanza("Inst", "/opt/mqm"));
        touch_names(d2.path / "opt/mqm/swidtag", {"IBM_MQ_GSKit-9.0.0.mqtag", "IBM_MQ_Runtime-9.4.5.mqtag"});
        CHECK(data_rows(run_leg(d2.path)) == std::vector<std::string>{mq_row("Inst", "-", "/opt/mqm")});
    }
}

TEST_CASE("middleware linux: absent sources (ENOENT at any hop) are supported with zero rows",
          "[middleware][linux]") {
    yuzu::test::TempDir dir{"yuzu_test_middleware_absent_"};
    for (const char* tree : {"", "etc", "etc/opt"}) {
        if (*tree != '\0') make_dir(dir.path / tree);
        INFO("tree: '" << tree << "'");
        CHECK(run_leg(dir.path).rows == std::vector<std::string>{"status|ibm_mq|supported|-"});
    }
}

TEST_CASE("middleware linux: 257 stanzas give 256 rows and mqinst_ini:row_cap; exactly 256 is complete (SYNTHETIC)",
          "[middleware][linux][ibm_mq][caps]") {
    yuzu::test::TempDir dir{"yuzu_test_middleware_mq257_"};
    const auto ini_of = [](std::size_t n) {
        std::string ini;
        for (std::size_t i = 1; i <= n; ++i)
            ini += mq_stanza("I" + std::to_string(i), "/opt/mq" + std::to_string(i));
        return ini;
    };
    write_text(dir.path / enumerator_rel(), ini_of(mw::kMaxRows));
    auto run = run_leg(dir.path);
    CHECK(tokens_of(run) == "-");
    CHECK(data_rows(run).size() == mw::kMaxRows);

    write_text(dir.path / enumerator_rel(), ini_of(mw::kMaxRows + 1));
    run = run_leg(dir.path);
    CHECK(tokens_of(run) == tok("mqinst_ini", "row_cap"));
    CHECK(data_rows(run).size() == mw::kMaxRows);
    CHECK(run.rows[1] == mq_row("I1", "-", "/opt/mq1")); // none of the FilePaths exists

    lnx::WalkConfig asks_for_more; // a limit above the ceiling changes nothing (clamped)
    asks_for_more.limits.rows = 100000;
    run = run_leg(dir.path, asks_for_more);
    CHECK(data_rows(run).size() == mw::kMaxRows);
}

TEST_CASE("middleware linux: a stanza without FilePath is a token and its siblings are kept",
          "[middleware][linux][ibm_mq]") {
    yuzu::test::TempDir dir{"yuzu_test_middleware_mqdrop_"};
    write_text(dir.path / enumerator_rel(),
               mq_stanza("A", "/opt/a") + "Installation:\n   Name=Broken\n" + mq_stanza("C", "/opt/c"));
    touch_names(dir.path / "opt/a/swidtag", {swidtag_of(kTag935)});
    const auto run = run_leg(dir.path);
    CHECK(tokens_of(run) == tok("mqinst_ini", "malformed"));
    CHECK(data_rows(run) == std::vector<std::string>{mq_row("A", "9.3.5", "/opt/a"),
                                                     mq_row("C", "-", "/opt/c")});
}

TEST_CASE("middleware linux: per-item swidtag shortfalls degrade the row and never reach the status row",
          "[middleware][linux][ibm_mq]") {
    yuzu::test::TempDir dir{"yuzu_test_middleware_mqitem_"};
    // Every installation is a different shortfall; the one control (/opt/ok) is read normally, so a
    // leg that stopped at the first shortfall would lose it.
    write_text(dir.path / enumerator_rel(),
               mq_stanza("NoDir", "/opt/nodir") + mq_stanza("NoSwid", "/opt/noswid") +
                   mq_stanza("NoVersion", "/opt/noversion") + mq_stanza("NotAFile", "/opt/notafile") +
                   mq_stanza("SwidLink", "/opt/swidlink") + mq_stanza("Ok", "/opt/ok"));
    const std::string swid = swidtag_of(kTag935);
    make_dir(dir.path / "opt/noswid");                                 // FilePath without swidtag/
    touch_names(dir.path / "opt/noversion/swidtag", {"readme.txt", "ibm.com_IBM_MQSeries-1.0.swidtag"});
    make_dir(dir.path / "opt/notafile/swidtag" / swid);                // a directory, not a file
    touch_names(dir.path / "opt/real/swidtag", {swid});                // CANARY behind a symlink
    make_dir(dir.path / "opt/swidlink");
    make_link("../real/swidtag", dir.path / "opt/swidlink/swidtag");
    touch_names(dir.path / "opt/ok/swidtag", {swid});

    const auto run = run_leg(dir.path);
    CHECK(tokens_of(run) == "-");
    CHECK(data_rows(run) ==
          std::vector<std::string>{mq_row("NoDir", "-", "/opt/nodir"),
                                   mq_row("NoSwid", "-", "/opt/noswid"),
                                   mq_row("NoVersion", "-", "/opt/noversion"),
                                   mq_row("NotAFile", "-", "/opt/notafile"),
                                   mq_row("SwidLink", "-", "/opt/swidlink"),
                                   mq_row("Ok", "9.3.5", "/opt/ok")});
}

TEST_CASE("middleware linux: an unreadable swidtag directory is a per-item shortfall",
          "[middleware][linux][ibm_mq]") {
    if (running_privileged()) SKIP("running as root (or CAP_DAC_OVERRIDE): permission bits bypassed");
    yuzu::test::TempDir dir{"yuzu_test_middleware_mqeacces_"};
    write_text(dir.path / enumerator_rel(), mq_stanza("Inst", "/opt/mqm"));
    touch_names(dir.path / "opt/mqm/swidtag", {swidtag_of(kTag935)});
    const PermRestore restore{dir.path / "opt/mqm/swidtag"};
    ::chmod((dir.path / "opt/mqm/swidtag").c_str(), 0);
    const auto run = run_leg(dir.path);
    CHECK(tokens_of(run) == "-");
    CHECK(data_rows(run) == std::vector<std::string>{mq_row("Inst", "-", "/opt/mqm")});
}

TEST_CASE("middleware linux: the per-directory entry cap is per-item, the entries budget is walk:row_cap",
          "[middleware][linux][ibm_mq][caps]") {
    yuzu::test::TempDir dir{"yuzu_test_middleware_mqentries_"};
    write_text(dir.path / enumerator_rel(), mq_stanza("Inst", "/opt/mqm"));
    touch_names(dir.path / "opt/mqm/swidtag", {"a.mqtag", "b.mqtag", swidtag_of(kTag935)});

    lnx::WalkConfig dir_cap;
    dir_cap.limits.dir_entries = 2; // the directory holds 3: oversized for THIS item only
    auto run = run_leg(dir.path, dir_cap);
    CHECK(tokens_of(run) == "-");
    CHECK(data_rows(run) == std::vector<std::string>{mq_row("Inst", "-", "/opt/mqm")});

    lnx::WalkConfig budget;
    budget.limits.entries_visited = 2; // the action's whole budget runs dry mid-listing
    run = run_leg(dir.path, budget);
    CHECK(tokens_of(run) == tok("walk", "row_cap"));
    CHECK(data_rows(run).empty()); // no row past the point the budget ran dry

    run = run_leg(dir.path); // control: the same tree under the defaults
    CHECK(data_rows(run) == std::vector<std::string>{mq_row("Inst", "9.3.5", "/opt/mqm")});
}

TEST_CASE("middleware linux: the entries budget is one allowance across installations, not per listing",
          "[middleware][linux][ibm_mq][caps]") {
    yuzu::test::TempDir dir{"yuzu_test_middleware_mqentries2_"};
    write_text(dir.path / enumerator_rel(), mq_stanza("A", "/opt/a") + mq_stanza("B", "/opt/b"));
    // Two listings of two entries each: either is inside a budget of 3, together they are not.
    const std::string swid = swidtag_of(kTag935);
    touch_names(dir.path / "opt/a/swidtag", {"a.mqtag", swid});
    touch_names(dir.path / "opt/b/swidtag", {"a.mqtag", swid});

    lnx::WalkConfig budget;
    budget.limits.entries_visited = 3;
    auto run = run_leg(dir.path, budget);
    CHECK(tokens_of(run) == tok("walk", "row_cap")); // the second listing runs dry
    CHECK(data_rows(run) == std::vector<std::string>{mq_row("A", "9.3.5", "/opt/a")});

    budget.limits.entries_visited = 4; // control: exactly both listings is complete
    run = run_leg(dir.path, budget);
    CHECK(tokens_of(run) == "-");
    CHECK(data_rows(run) == std::vector<std::string>{mq_row("A", "9.3.5", "/opt/a"),
                                                     mq_row("B", "9.3.5", "/opt/b")});
}

TEST_CASE("middleware linux: list_regular reports an entry it cannot examine as an I/O error",
          "[middleware][linux][ibm_mq]") {
    if (running_privileged()) SKIP("running as root (or CAP_DAC_OVERRIDE): permission bits bypassed");
    yuzu::test::TempDir dir{"yuzu_test_middleware_listerr_"};
    touch_names(dir.path / "d", {"a.mqtag"});
    const PermRestore restore{dir.path / "d"};
    const auto list = [&] {
        auto d = lnx::open_root((dir.path / "d").string());
        REQUIRE(d.out == lnx::Outcome::ok);
        lnx::WalkBudget budget{lnx::WalkLimits{}};
        return lnx::list_regular(d.dir.get(), budget, mw::kMaxDirEntries);
    };

    ::chmod((dir.path / "d").c_str(), 0555); // control: readable and searchable
    auto ents = list();
    CHECK(ents.names == std::vector<std::string>{"a.mqtag"});
    CHECK_FALSE(ents.io_error);

    ::chmod((dir.path / "d").c_str(), 0444); // readable, NOT searchable: readdir works, fstatat fails
    ents = list();
    CHECK(ents.names.empty());
    CHECK(ents.io_error);
}

TEST_CASE("middleware linux: a row cap injected through rows or row_bytes ends in walk:row_cap",
          "[middleware][linux][ibm_mq][caps]") {
    yuzu::test::TempDir dir{"yuzu_test_middleware_mqbudget_"};
    write_text(dir.path / enumerator_rel(), mq_stanza("A", "/opt/a") + mq_stanza("B", "/opt/b") +
                                                mq_stanza("C", "/opt/c"));
    const std::string row_a = mq_row("A", "-", "/opt/a");

    lnx::WalkConfig rows;
    rows.limits.rows = 2; // three stanzas, two rows admitted
    auto run = run_leg(dir.path, rows);
    CHECK(tokens_of(run) == tok("walk", "row_cap"));
    CHECK(data_rows(run) == std::vector<std::string>{row_a, mq_row("B", "-", "/opt/b")});

    lnx::WalkConfig bytes;
    bytes.limits.row_bytes = row_a.size(); // an exact fill is admitted, the next row is refused
    run = run_leg(dir.path, bytes);
    CHECK(tokens_of(run) == tok("walk", "row_cap"));
    CHECK(data_rows(run) == std::vector<std::string>{row_a});

    bytes.limits.row_bytes = row_a.size() - 1; // smaller than one row: none fits
    run = run_leg(dir.path, bytes);
    CHECK(tokens_of(run) == tok("walk", "row_cap"));
    CHECK(data_rows(run).empty());

    run = run_leg(dir.path); // control: the defaults hold all three
    CHECK(tokens_of(run) == "-");
    CHECK(data_rows(run).size() == 3);
}

TEST_CASE("middleware linux: mqinst.ini failures are enumeration tokens and nothing is guessed",
          "[middleware][linux][ibm_mq]") {
    yuzu::test::TempDir dir{"yuzu_test_middleware_mqfail_"};
    const fs::path ini = dir.path / enumerator_rel();

    write_text(ini, std::string(mw::kMaxKvFileBytes + 1, '#'));
    auto run = run_leg(dir.path);
    CHECK(tokens_of(run) == tok("mqinst_ini", "oversized"));
    CHECK(data_rows(run).empty());

    // The bracket form is not the grammar: IBM states the file's format is not fixed, so a wrong
    // guess must surface as a token, never as a silent empty inventory.
    write_text(ini, "[Installation]\nName=Old\nFilePath=/opt/mqm\n");
    run = run_leg(dir.path);
    CHECK(tokens_of(run) == tok("mqinst_ini", "malformed"));
    CHECK(data_rows(run).empty());

    fs::remove(ini);
    make_dir(ini); // a directory where the file should be
    run = run_leg(dir.path);
    CHECK(tokens_of(run) == tok("mqinst_ini", "unreadable"));
    CHECK(data_rows(run).empty());
}

TEST_CASE("middleware linux: an unreadable mqinst.ini is a permission token",
          "[middleware][linux][ibm_mq]") {
    if (running_privileged()) SKIP("running as root (or CAP_DAC_OVERRIDE): permission bits bypassed");
    yuzu::test::TempDir dir{"yuzu_test_middleware_mqperm_"};
    const fs::path ini = dir.path / enumerator_rel();
    write_text(ini, mq_stanza("Inst", "/opt/mqm"));
    const PermRestore restore{ini};
    ::chmod(ini.c_str(), 0);
    const auto run = run_leg(dir.path);
    CHECK(tokens_of(run) == tok("mqinst_ini", "permission_denied"));
    CHECK(data_rows(run).empty());
}

TEST_CASE("middleware linux: a symlink at any hop of the fixed mqinst.ini path is refused, nothing followed",
          "[middleware][linux][ibm_mq][symlink]") {
    // The real content stays behind each link (the canary), and the control (no link) shows it reads.
    for (const char* link_at : {"", "etc/opt", "etc/opt/mqm", "etc/opt/mqm/mqinst.ini"}) {
        INFO("symlink at: '" << link_at << "'");
        yuzu::test::TempDir dir{"yuzu_test_middleware_mqlink_"};
        write_registered_install(dir.path);
        if (*link_at != '\0') relink(dir.path / link_at);
        const auto run = run_leg(dir.path);
        if (*link_at == '\0') {
            CHECK(tokens_of(run) == "-");
            CHECK(data_rows(run) == std::vector<std::string>{mq_row("Installation1", "9.4.5", "/opt/mqm")});
            check_touched(run, dir.path, {"etc", "etc/opt", "etc/opt/mqm"}, {}); // positive control
        } else {
            CHECK(tokens_of(run) == tok("mqinst_ini", "symlink_refused"));
            CHECK(data_rows(run).empty());
            // The renamed original behind a link on a directory hop was never entered.
            if (fs::is_directory(dir.path / (std::string{link_at} + ".real")))
                check_touched(run, dir.path, {}, {std::string{link_at} + ".real"});
        }
    }
}

TEST_CASE("middleware linux: a FilePath that is not absolute and plain, or is a symlink, is never opened",
          "[middleware][linux][ibm_mq][symlink]") {
    const std::string swid = swidtag_of(kTag935);
    // The CANARY is /opt/mqm/swidtag/<9.3.5 swidtag>: any route that reaches it (by normalising a
    // `..`, resolving a relative path or following a link) puts "9.3.5" in the row, and opens its
    // directories, which the touch log records. The row alone cannot tell a refusal made before the
    // open from one made after it.
    const auto run_with = [&](const std::string& file_path,
                              const std::function<void(const fs::path&)>& extra,
                              const lnx::WalkConfig& cfg, const std::vector<std::string>& opened,
                              const std::vector<std::string>& never) {
        yuzu::test::TempDir dir{"yuzu_test_middleware_mqpath_"};
        write_text(dir.path / enumerator_rel(), mq_stanza("Inst", file_path));
        touch_names(dir.path / "opt/mqm/swidtag", {swid});
        make_dir(dir.path / "opt/x"); // so `/opt/x/../mqm` would resolve if it were opened
        if (extra) extra(dir.path);
        auto run = run_leg(dir.path, cfg);
        check_touched(run, dir.path, opened, never);
        return run;
    };

    // Positive control: the canary IS readable, and the log shows every directory of the walk.
    const auto control = run_with("/opt/mqm", {}, {}, {"opt", "opt/mqm", "opt/mqm/swidtag"}, {});
    REQUIRE(data_rows(control) == std::vector<std::string>{mq_row("Inst", "9.3.5", "/opt/mqm")});

    // Every directory a walk of the canary would enter. A refusal that opened any of them first and
    // discarded it afterwards would leave the rows below unchanged.
    const std::vector<std::string> all{"opt", "opt/x", "opt/mqm", "opt/mqm/swidtag"};
    const std::vector<PathCase> cases{
        {"relative", "opt/mqm", {}, {}, all},
        {"dotdot", "/opt/x/../mqm", {}, {}, all},
        {"dot", "/opt/./mqm", {}, {}, all},
        {"trailing slash", "/opt/mqm/", {}, {}, all},
        {"empty component", "//opt/mqm", {}, {}, all},
        {"symlink at an intermediate hop", "/lnk/mqm",
         [](const fs::path& r) { make_link("opt", r / "lnk"); }, {}, all},
        {"symlink at the leaf", "/optlink",
         [](const fs::path& r) { make_link("opt/mqm", r / "optlink"); }, {}, all},
        {"swidtag itself a symlink", "/opt/mqm2",
         [](const fs::path& r) {
             make_dir(r / "opt/mqm2");
             make_link("../mqm/swidtag", r / "opt/mqm2/swidtag");
         },
         {}, {"opt/x", "opt/mqm", "opt/mqm/swidtag"}}, // opt and opt/mqm2 are walked legitimately
        {"network mount at the install", "/opt/mqm", {}, net("/opt/mqm"), all},
        {"network mount above the install", "/opt/mqm", {}, net("/opt"), all},
        {"network mount inside the install", "/opt/mqm", {}, net("/opt/mqm/swidtag"), all},
    };
    for (const auto& c : cases) {
        INFO("case: " << c.label);
        const auto run = run_with(c.path, c.extra, c.cfg, {}, c.never);
        CHECK(tokens_of(run) == "-"); // per-item: no token
        CHECK(data_rows(run) == std::vector<std::string>{mq_row("Inst", "-", c.path)});
    }
}

TEST_CASE("middleware linux: a network mount on the enumeration root skips it with a token",
          "[middleware][linux][ibm_mq][mounts]") {
    yuzu::test::TempDir dir{"yuzu_test_middleware_mqnfs_"};
    write_registered_install(dir.path);

    auto run = run_leg(dir.path); // control: unguarded, the canary is readable
    REQUIRE(data_rows(run) == std::vector<std::string>{mq_row("Installation1", "9.4.5", "/opt/mqm")});
    check_touched(run, dir.path, {"etc", "etc/opt", "etc/opt/mqm", "opt", "opt/mqm"}, {});

    run = run_leg(dir.path, net("/etc/opt"));
    CHECK(tokens_of(run) == tok("mqinst_ini", "network_fs_skipped"));
    CHECK(data_rows(run).empty());
    // Not even `etc`: a path on a (possibly dead) network mount is refused before any open.
    check_touched(run, dir.path, {}, {"etc", "etc/opt", "etc/opt/mqm", "opt", "opt/mqm"});

    lnx::WalkConfig unreadable; // the guard could not be built: the walk runs, and says so
    unreadable.mountinfo_unreadable = true;
    run = run_leg(dir.path, unreadable);
    CHECK(tokens_of(run) == tok("mountinfo", "unreadable"));
    CHECK(data_rows(run) == std::vector<std::string>{mq_row("Installation1", "9.4.5", "/opt/mqm")});
}

#endif // !defined(_WIN32)
