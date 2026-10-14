/**
 * test_pkg_inventory_linux_parsers.cpp -- injected-root tests for the pkg_inventory
 * Linux legs (lnx::linux_manager_rows_at, lnx::linux_store_rows_at, lnx::run_linux_at,
 * lnx::run_linux_guarded in pkg_inventory_linux_parsers.hpp).
 *
 * The happy-path cases run over a committed REAL CAPTURE tree manifest
 * (tests/unit/fixtures/wave10/pkg_inventory/linux/tree.manifest, six verbatim
 * snap.yaml beside it; provenance.txt records the host: Kingsley WSL2 Ubuntu
 * 26.04.1, snapd 2.77.1, flatpak 1.16.6, 2026-10-14, and the WSL-vs-bare-metal
 * caveat). Every degraded, hostile, budget and seam case builds a small SYNTHETIC
 * tree in code and is labelled as such: none of those layouts was captured.
 *
 * MANIFEST GRAMMAR (TU-local on purpose: test_update_source_trust_linux_parsers.cpp
 * and the other suites each keep their own copy). One line per entry:
 *     <relative path> TAB <payload>
 * with payload  T:<text; escapes \n \t \\>  |  D:  |  L:<symlink target>  |
 * F:<committed fixture file relative to the manifest's directory>.
 * Blank lines and lines starting with '#' are skipped.
 *
 * POSIX ONLY: the walk shell is `#if !defined(_WIN32)`, so the whole TU body is
 * guarded the same way. The pure parsers have their own unguarded TU
 * (test_pkg_inventory_parsers.cpp). The walk reads an INJECTED root, so these
 * cases run on macOS and Windows-excluded CI legs alike; only Via::entry (the
 * plugin's own run_linux) is __linux__-gated. Permission cases SKIP at euid 0.
 *
 * MUTATION NOTES (each names a wiring removal that would fail a case here):
 *  - counting `partial` as a snap file / `ubuntu.sources.save` as an apt source
 *                                                       -> the managers capture / sibling cases
 *  - a token on a per-item degradation                  -> the [degraded] cases (supported, no token)
 *  - silencing a nested flatpak listing failure         -> the [constrained] cases
 *  - treating the snap `current` text as a path          -> the unexpected-target case
 *  - a 2-slot WalkSlot array                             -> the independent-slots case
 *  - dropping the constraint at the emit seam            -> the forced-constraint seam case
 *  - dropping the slot from run_linux_guarded            -> the busy cases
 *  - leaking a Dir/fd on an early return                 -> the fd-balance case
 */
#include <catch2/catch_test_macros.hpp>

#if !defined(_WIN32)

#include "pkg_inventory_legs.hpp"
#include "pkg_inventory_linux_parsers.hpp"
#include "pkg_inventory_parsers.hpp"

#include "local_dispatcher.hpp"
#include "pkg_inventory_test_support.hpp"
#include "test_helpers.hpp" // yuzu::test::TempDir

#include <yuzu/plugin.h>

#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>

#include <cstddef>
#include <filesystem>
#include <fstream>
#include <iterator>
#include <optional>
#include <sstream>
#include <string>
#include <string_view>
#include <vector>

using yuzu::test::pkg_inventory_support::captured_rows;
using yuzu::test::pkg_inventory_support::ModeGuard;
using yuzu::test::pkg_inventory_support::open_fd_count;
using yuzu::test::pkg_inventory_support::split_fields_escape_aware;

namespace {

namespace fs = std::filesystem;
namespace pkg = yuzu::pkg_inventory;
namespace lnx = yuzu::pkg_inventory::lnx;

fs::path fixture_dir() {
#ifdef YUZU_TEST_FIXTURE_DIR
    return fs::path(YUZU_TEST_FIXTURE_DIR) / "wave10" / "pkg_inventory" / "linux";
#else
    return fs::path("tests/unit/fixtures/wave10/pkg_inventory/linux");
#endif
}

// ── manifest materialiser ────────────────────────────────────────────────

std::optional<std::string> unescape_text(std::string_view in) {
    std::string out;
    for (std::size_t i = 0; i < in.size(); ++i) {
        if (in[i] != '\\') {
            out.push_back(in[i]);
            continue;
        }
        if (++i >= in.size()) return std::nullopt;
        switch (in[i]) {
        case 'n': out.push_back('\n'); break;
        case 't': out.push_back('\t'); break;
        case '\\': out.push_back('\\'); break;
        default: return std::nullopt;
        }
    }
    return out;
}

/// A manifest path must stay under the root: relative, no `..`, no backslash.
bool safe_rel_path(std::string_view rel) {
    if (rel.empty() || rel.front() == '/' || rel.find('\\') != std::string_view::npos) return false;
    std::size_t i = 0;
    while (i <= rel.size()) {
        const auto j = rel.find('/', i);
        const auto seg = rel.substr(i, j == std::string_view::npos ? j : j - i);
        if (seg.empty() || seg == "." || seg == "..") return false;
        if (j == std::string_view::npos) break;
        i = j + 1;
    }
    return true;
}

/// Writes every manifest entry under `root`. false + `error` on any malformed
/// line or I/O failure so the calling REQUIRE names the cause.
bool materialize_tree(std::string_view manifest, const fs::path& fixtures, const fs::path& root,
                      std::string& error) {
    std::error_code ec;
    fs::create_directories(root, ec);
    if (ec) {
        error = "create_directories(root): " + ec.message();
        return false;
    }
    std::size_t pos = 0;
    while (pos < manifest.size()) {
        const auto nl = manifest.find('\n', pos);
        auto line = manifest.substr(pos, nl == std::string_view::npos ? nl : nl - pos);
        pos = nl == std::string_view::npos ? manifest.size() : nl + 1;
        if (!line.empty() && line.back() == '\r') line.remove_suffix(1);
        if (line.empty() || line.front() == '#') continue;
        const auto tab = line.find('\t');
        if (tab == std::string_view::npos) {
            error = "no tab separator: " + std::string{line};
            return false;
        }
        const auto rel = line.substr(0, tab);
        const auto payload = line.substr(tab + 1);
        if (!safe_rel_path(rel) || payload.size() < 2 || payload[1] != ':') {
            error = "bad path or payload prefix: " + std::string{line.substr(0, 80)};
            return false;
        }
        const fs::path out = root / fs::path(std::string{rel});
        const auto body = payload.substr(2);
        if (payload[0] == 'D') {
            fs::create_directories(out, ec);
        } else {
            fs::create_directories(out.parent_path(), ec);
            if (ec) {
                error = "create_directories(" + out.parent_path().string() + "): " + ec.message();
                return false;
            }
            std::optional<std::string> bytes;
            switch (payload[0]) {
            case 'T': bytes = unescape_text(body); break;
            case 'F': {
                if (!safe_rel_path(body)) {
                    error = "bad F: path: " + std::string{body};
                    return false;
                }
                std::ifstream in(fixtures / fs::path(std::string{body}), std::ios::binary);
                if (!in) {
                    error = "F: source not readable: " + std::string{body};
                    return false;
                }
                bytes = std::string(std::istreambuf_iterator<char>(in),
                                    std::istreambuf_iterator<char>());
                break;
            }
            case 'L':
                // A link target is trusted only inside the tree.
                if (body.empty() || !safe_rel_path(body)) {
                    error = "unsafe link target for " + std::string{rel};
                    return false;
                }
                fs::create_symlink(std::string{body}, out, ec);
                break;
            default: error = "unknown payload kind: " + std::string{line.substr(0, 80)}; return false;
            }
            if (payload[0] != 'L') {
                if (!bytes) {
                    error = "undecodable payload for " + std::string{rel};
                    return false;
                }
                std::ofstream f(out, std::ios::binary);
                f.write(bytes->data(), static_cast<std::streamsize>(bytes->size()));
                if (!f) {
                    error = "write failed: " + out.string();
                    return false;
                }
            }
        }
        if (ec) {
            error = "materialize failed for " + out.string() + ": " + ec.message();
            return false;
        }
    }
    return true;
}

std::string slurp(const fs::path& p) {
    std::ifstream in(p, std::ios::binary);
    return std::string((std::istreambuf_iterator<char>(in)), std::istreambuf_iterator<char>());
}

bool build_capture_tree(const fs::path& root, std::string& error) {
    return materialize_tree(slurp(fixture_dir() / "tree.manifest"), fixture_dir(), root, error);
}

// ── tiny synthetic-tree helpers ──────────────────────────────────────────

void put(const fs::path& root, std::string_view rel, std::string_view text = {}) {
    const auto p = root / fs::path(std::string{rel});
    fs::create_directories(p.parent_path());
    std::ofstream f(p, std::ios::binary);
    f.write(text.data(), static_cast<std::streamsize>(text.size()));
}
void mkdirs(const fs::path& root, std::string_view rel) {
    fs::create_directories(root / fs::path(std::string{rel}));
}
void link(const fs::path& root, std::string_view rel, std::string_view target) {
    const auto p = root / fs::path(std::string{rel});
    fs::create_directories(p.parent_path());
    fs::create_symlink(std::string{target}, p);
}

/// One mounted, current snap `btop` revision 1073 whose snap.yaml is `yaml`.
void add_btop(const fs::path& root, std::string_view yaml) {
    put(root, "var/lib/snapd/snaps/btop_1073.snap");
    put(root, "snap/btop/1073/meta/snap.yaml", yaml);
    link(root, "snap/btop/current", "1073");
}

struct Walk {
    std::vector<std::string> rows;
    std::optional<std::string> token;
};

Walk store(const fs::path& root, const pkg::Limits& lim = {}) {
    Walk w;
    w.rows = lnx::linux_store_rows_at(root, w.token, lim);
    return w;
}
Walk managers(const fs::path& root, const pkg::Limits& lim = {}) {
    Walk w;
    w.rows = lnx::linux_manager_rows_at(root, w.token, lim);
    return w;
}

bool has_token(const Walk& w, std::string_view token) {
    return w.token && w.token->find(token) != std::string::npos;
}

// ── CommandContext-level harness (mirrors the macOS suite's run_leg) ──────

const fs::path* g_leg_root = nullptr;
pkg::Action g_leg_action = pkg::Action::managers;
/// Which seam the harness drives: the bare walk, the walk behind the single-flight
/// slot, or (Linux only) the plugin's own `run_linux` entry point.
enum class Via { at, guarded, entry };
Via g_leg_via = Via::at;

int leg_execute(YuzuCommandContext* raw, const char* /*action*/, const YuzuParam* /*params*/,
                std::size_t /*param_count*/) {
    yuzu::CommandContext ctx{raw};
    switch (g_leg_via) {
    case Via::guarded: return lnx::run_linux_guarded(ctx, g_leg_action, *g_leg_root);
#if defined(__linux__)
    case Via::entry: return pkg::run_linux(ctx, g_leg_action);
#else
    case Via::entry: break;
#endif
    case Via::at: break;
    }
    return lnx::run_linux_at(ctx, g_leg_action, *g_leg_root);
}

yuzu::agent::LocalDispatcher::Result run_leg(const fs::path& root, pkg::Action a,
                                             Via via = Via::at) {
    g_leg_root = &root;
    g_leg_action = a;
    g_leg_via = via;
    YuzuPluginDescriptor descriptor{};
    descriptor.execute = &leg_execute;
    yuzu::agent::LocalDispatcher dispatcher;
    auto result = dispatcher.run(&descriptor, "probe");
    g_leg_root = nullptr;
    g_leg_via = Via::at;
    return result;
}

const char* const kCalcCommit = "00516a24d410ad62ed3e955fa5deb5af221ab6b181ed5549103f3670d10d2fca";
const char* const kEditorCommit = "76ecd1d6e9ecfa26f6939c54eec4e9db3491fce949c8808bdee9fb55758a1a91";

} // namespace

// ── manifest ─────────────────────────────────────────────────────────────

TEST_CASE("pkg_inventory linux manifest: the committed capture materialises and F: payloads resolve",
          "[pkg_inventory][linux][manifest]") {
    yuzu::test::TempDir dir{"yuzu_test_pkg_inventory_linux_manifest_"};
    std::string err;
    REQUIRE(build_capture_tree(dir.path, err));
    INFO(err);
    for (const std::string_view n : {"btop", "core", "core24", "hello-world", "jq", "snapd"}) {
        const auto committed = slurp(fixture_dir() / ("snap-" + std::string{n} + "-snap.yaml"));
        REQUIRE_FALSE(committed.empty());
        const auto cur = fs::read_symlink(dir.path / "snap" / std::string{n} / "current");
        CHECK(slurp(dir.path / "snap" / std::string{n} / cur / "meta/snap.yaml") == committed);
    }
    // Every flatpak branch carries an `active` link whose text is the commit directory beside it.
    const auto active = dir.path / "var/lib/flatpak/app/org.gnome.Calculator/x86_64/stable";
    CHECK(fs::read_symlink(active / "active") == fs::path{kCalcCommit});
    CHECK(fs::is_directory(active / kCalcCommit));

    // A manifest path or F: source that escapes the root is refused, never written.
    yuzu::test::TempDir other{"yuzu_test_pkg_inventory_linux_manifest_bad_"};
    CHECK_FALSE(materialize_tree("a/b\tF:/etc/passwd\n", fixture_dir(), other.path, err));
    CHECK_FALSE(materialize_tree("a/b\tF:../x\n", fixture_dir(), other.path, err));
    CHECK_FALSE(materialize_tree("../a\tT:x\n", fixture_dir(), other.path, err));
    CHECK_FALSE(materialize_tree("a\tL:/tmp\n", fixture_dir(), other.path, err));
}

// ── real-capture cases ───────────────────────────────────────────────────

TEST_CASE("pkg_inventory linux: manager rows over the real-capture tree", "[pkg_inventory][linux][capture]") {
    yuzu::test::TempDir dir{"yuzu_test_pkg_inventory_linux_mgr_"};
    std::string err;
    REQUIRE(build_capture_tree(dir.path, err));

    // MUTATION: counting `partial` as a snap file, an `app/<id>/current` link as a flatpak id, or
    // the extra `.save` sibling below as an apt source changes a fact here.
    put(dir.path, "etc/apt/sources.list.d/ubuntu.sources.save");
    const auto w = managers(dir.path);
    CHECK_FALSE(w.token.has_value());
    const std::vector<std::string> expected{
        "manager|dpkg|present|-|-|-|-",
        "manager|apt|present|-|/etc/apt|sources_d_files=1|-",
        "manager|rpm|present|-|-|-|-",
        "manager|snap|present|-|/var/lib/snapd|snap_files=6|-",
        "manager|flatpak|present|-|/var/lib/flatpak|apps=2;runtimes=6|-",
    };
    CHECK(w.rows == expected);
    for (const auto& r : w.rows) {
        CHECK(split_fields_escape_aware(r).size() == 7);
        CHECK(r.find(dir.path.string()) == std::string::npos); // logical paths only
    }
}

TEST_CASE("pkg_inventory linux: store rows over the real-capture tree", "[pkg_inventory][linux][capture]") {
    yuzu::test::TempDir dir{"yuzu_test_pkg_inventory_linux_store_"};
    std::string err;
    REQUIRE(build_capture_tree(dir.path, err));

    const auto w = store(dir.path);
    CHECK_FALSE(w.token.has_value());
    auto fp = [](std::string_view id, std::string_view kind, std::string_view commit,
                 std::string_view branch) {
        return pkg::format_store_row(pkg::Store::flatpak, id, "", kind, commit, "x86_64", branch,
                                     pkg::StoreState::active);
    };
    const std::vector<std::string> expected{
        "package|snap|btop|1.4.7|app|1073|-|-|active",
        "package|snap|core|16-2.61.4-20260225|os|17292|-|-|active",
        "package|snap|core24|20260824|base|2124|-|-|active",
        "package|snap|hello-world|6.4|app|29|-|-|active",
        "package|snap|jq|1.5+dfsg-1|app|6|-|-|active",
        "package|snap|snapd|2.77.1|snapd|28254|-|-|active",
        fp("org.gnome.Calculator", "app", kCalcCommit, "stable"),
        fp("org.gnome.TextEditor", "app", kEditorCommit, "stable"),
        fp("org.freedesktop.Platform.GL.default", "runtime",
           "badc1097c419e73781cf098413ffa8e7bf7db3528572c11712265b9193921842", "26.08"),
        fp("org.freedesktop.Platform.GL.default", "runtime",
           "78bffb38496d50460493f1c19382be4e6a53fd7f90c82ea6339c26c33d46f272", "26.08-extra"),
        fp("org.freedesktop.Platform.codecs-extra", "runtime",
           "c39642255da41e44561bb095bcfad5ae86b003822c009eb5eb0d1c8d31ebc93e", "26.08-extra"),
        fp("org.gnome.Calculator.Locale", "runtime",
           "c96db504f5fafa32330402cb4dbe5d2ae137acb9cbe663ecaa0ef59b85ac97b9", "stable"),
        fp("org.gnome.Platform", "runtime",
           "4d844b325f24642e3bf33ddf04153bc312caafb3f9fd44dd90496813a181dee6", "51"),
        fp("org.gnome.Platform.Locale", "runtime",
           "296271c613e4cfdf5b04b8a432116cecd0de08d5a890417952c1605a35a6789c", "51"),
        fp("org.gnome.TextEditor.Locale", "runtime",
           "35e8fa7765473232dc1f702095bbcff0bac69201a2d81ddf90c7d28dead3228b", "stable"),
    };
    REQUIRE(w.rows.size() == expected.size()); // fifteen
    for (std::size_t i = 0; i < expected.size(); ++i) {
        INFO("row " << i);
        CHECK(w.rows[i] == expected[i]);
        CHECK(split_fields_escape_aware(w.rows[i]).size() == 9);
    }
    // `app/<id>/current` (a link) yields neither a row nor a token.
    for (const auto& r : w.rows) CHECK(r.find("current") == std::string::npos);
}

TEST_CASE("pkg_inventory linux: an absent root is supported with zero rows for both actions",
          "[pkg_inventory][linux][capture]") {
    yuzu::test::TempDir dir{"yuzu_test_pkg_inventory_linux_absent_"};
    const auto m = managers(dir.path);
    CHECK(m.rows.empty());
    CHECK_FALSE(m.token.has_value());
    const auto s = store(dir.path);
    CHECK(s.rows.empty());
    CHECK_FALSE(s.token.has_value());
}

// ── per-item degradation: row emitted, status SUPPORTED, NO token ─────────

TEST_CASE("pkg_inventory linux [degraded, SUPPORTED]: a per-item anomaly degrades the row, never the status",
          "[pkg_inventory][linux][degraded]") {
    // MUTATION: any token on these paths makes a persistent per-item anomaly stall the host's
    // installed_software cycle via constrained_fails=true.
    auto one_row = [](const Walk& w) {
        REQUIRE_FALSE(w.token.has_value());
        REQUIRE(w.rows.size() == 1);
        CHECK(split_fields_escape_aware(w.rows[0]).size() == 9);
        return w.rows[0];
    };

    SECTION("no mount dir at all: every snap row is unknown") {
        yuzu::test::TempDir dir{"yuzu_test_pkg_inventory_linux_nomount_"};
        put(dir.path, "var/lib/snapd/snaps/btop_1073.snap");
        CHECK(one_row(store(dir.path)) == "package|snap|btop|-|unknown|1073|-|-|unknown");
    }
    SECTION("an empty /snap beside the live /var/lib/snapd/snap does not empty the catalogue") {
        // MUTATION: taking the first mount tree that OPENS (not the first that CONTAINS the
        // snap) makes every capture row `inactive` and drops the host's snaps silently.
        yuzu::test::TempDir dir{"yuzu_test_pkg_inventory_linux_emptysnap_"};
        std::string err;
        REQUIRE(build_capture_tree(dir.path, err));
        fs::rename(dir.path / "snap", dir.path / "var/lib/snapd/snap");
        fs::create_directory(dir.path / "snap");
        const auto w = store(dir.path);
        CHECK_FALSE(w.token.has_value());
        REQUIRE(w.rows.size() >= 6);
        const std::vector<std::string> expected{
            "package|snap|btop|1.4.7|app|1073|-|-|active",
            "package|snap|core|16-2.61.4-20260225|os|17292|-|-|active",
            "package|snap|core24|20260824|base|2124|-|-|active",
            "package|snap|hello-world|6.4|app|29|-|-|active",
            "package|snap|jq|1.5+dfsg-1|app|6|-|-|active",
            "package|snap|snapd|2.77.1|snapd|28254|-|-|active",
        };
        for (std::size_t i = 0; i < expected.size(); ++i) {
            INFO("row " << i);
            CHECK(w.rows[i] == expected[i]);
        }
    }
    SECTION("a symlinked mount dir is refused, never followed") {
        yuzu::test::TempDir dir{"yuzu_test_pkg_inventory_linux_mountlink_"};
        put(dir.path, "var/lib/snapd/snaps/btop_1073.snap");
        add_btop(dir.path / "elsewhere", "version: 9.9\n");
        link(dir.path, "snap", "elsewhere/snap");
        CHECK(one_row(store(dir.path)) == "package|snap|btop|-|unknown|1073|-|-|unknown");
    }
    SECTION("an unreadable mount dir is unknown") {
        if (::geteuid() == 0) SKIP("running as root: permission bits bypassed");
        yuzu::test::TempDir dir{"yuzu_test_pkg_inventory_linux_mount000_"};
        add_btop(dir.path, "version: 1.0\n");
        const auto mount = dir.path / "snap";
        REQUIRE(::chmod(mount.string().c_str(), 0000) == 0);
        ModeGuard restore{mount, 0755};
        CHECK(one_row(store(dir.path)) == "package|snap|btop|-|unknown|1073|-|-|unknown");
    }
    SECTION("a missing `current` is inactive") {
        yuzu::test::TempDir dir{"yuzu_test_pkg_inventory_linux_nocurrent_"};
        add_btop(dir.path, "version: 1.0\n");
        fs::remove(dir.path / "snap/btop/current");
        CHECK(one_row(store(dir.path)) == "package|snap|btop|1.0|app|1073|-|-|inactive");
    }
    SECTION("a `current` for another revision is inactive") {
        yuzu::test::TempDir dir{"yuzu_test_pkg_inventory_linux_othercur_"};
        add_btop(dir.path, "version: 1.0\n");
        fs::remove(dir.path / "snap/btop/current");
        link(dir.path, "snap/btop/current", "1074");
        CHECK(one_row(store(dir.path)) == "package|snap|btop|1.0|app|1073|-|-|inactive");
    }
    SECTION("a `current` that is not a bare revision is unknown, the row still emitted") {
        // MUTATION: treating the link text as a path (or accepting `/`) follows it out of the tree.
        for (const std::string_view bad : {"../../etc", "1073/", "x/y", "abc"}) {
            yuzu::test::TempDir dir{"yuzu_test_pkg_inventory_linux_badcur_"};
            add_btop(dir.path, "version: 1.0\n");
            fs::remove(dir.path / "snap/btop/current");
            link(dir.path, "snap/btop/current", bad);
            INFO(bad);
            CHECK(one_row(store(dir.path)) == "package|snap|btop|1.0|app|1073|-|-|unknown");
        }
        yuzu::test::TempDir dir{"yuzu_test_pkg_inventory_linux_dircur_"};
        add_btop(dir.path, "version: 1.0\n");
        fs::remove(dir.path / "snap/btop/current");
        mkdirs(dir.path, "snap/btop/current"); // a directory, not a link
        CHECK(one_row(store(dir.path)) == "package|snap|btop|1.0|app|1073|-|-|unknown");
    }
    SECTION("an unmounted or missing revision: version -, kind unknown, still active") {
        yuzu::test::TempDir dir{"yuzu_test_pkg_inventory_linux_unmounted_"};
        add_btop(dir.path, "version: 1.0\n");
        fs::remove_all(dir.path / "snap/btop/1073/meta");
        CHECK(one_row(store(dir.path)) == "package|snap|btop|-|unknown|1073|-|-|active");
        fs::remove_all(dir.path / "snap/btop/1073");
        CHECK(one_row(store(dir.path)) == "package|snap|btop|-|unknown|1073|-|-|active");
    }
    SECTION("an unreadable meta dir degrades the same way") {
        if (::geteuid() == 0) SKIP("running as root: permission bits bypassed");
        yuzu::test::TempDir dir{"yuzu_test_pkg_inventory_linux_meta000_"};
        add_btop(dir.path, "version: 1.0\n");
        const auto meta = dir.path / "snap/btop/1073/meta";
        REQUIRE(::chmod(meta.string().c_str(), 0000) == 0);
        ModeGuard restore{meta, 0755};
        CHECK(one_row(store(dir.path)) == "package|snap|btop|-|unknown|1073|-|-|active");
    }
    SECTION("an unreadable snap/<name> dir is unknown, silently") {
        // MUTATION: treating a non-ABSENT open failure of the name dir as a constraint (or
        // as "try the next tree") stalls the cycle / flips the row's state.
        if (::geteuid() == 0) SKIP("running as root: permission bits bypassed");
        yuzu::test::TempDir dir{"yuzu_test_pkg_inventory_linux_name000_"};
        add_btop(dir.path, "version: 1.0\n");
        const auto name_dir = dir.path / "snap/btop";
        REQUIRE(::chmod(name_dir.string().c_str(), 0000) == 0);
        ModeGuard restore{name_dir, 0755};
        CHECK(one_row(store(dir.path)) == "package|snap|btop|-|unknown|1073|-|-|unknown");
    }
    SECTION("a snap.yaml that is a symlink, a FIFO or oversized degrades; the open never blocks") {
        yuzu::test::TempDir dir{"yuzu_test_pkg_inventory_linux_hostileyaml_"};
        add_btop(dir.path, "version: 1.0\n");
        const auto yaml = dir.path / "snap/btop/1073/meta/snap.yaml";
        fs::remove(yaml);
        put(dir.path, "elsewhere.yaml", "version: 9.9\n");
        link(dir.path, "snap/btop/1073/meta/snap.yaml", "../../../../elsewhere.yaml");
        CHECK(one_row(store(dir.path)) == "package|snap|btop|-|unknown|1073|-|-|active");
        fs::remove(yaml);
        REQUIRE(::mkfifo(yaml.string().c_str(), 0644) == 0);
        CHECK(one_row(store(dir.path)) == "package|snap|btop|-|unknown|1073|-|-|active");
        fs::remove(yaml);
        put(dir.path, "snap/btop/1073/meta/snap.yaml",
            "version: 1.0\n" + std::string(pkg::kMaxSnapYamlBytes + 1, '#'));
        CHECK(one_row(store(dir.path)) == "package|snap|btop|-|unknown|1073|-|-|active");
    }
    SECTION("snap.yaml value rules reach the row (one case each)") {
        struct C {
            std::string yaml;
            std::string expected;
        };
        const std::vector<C> cases{
            {"version: 1.0  # bump\n", "package|snap|btop|1.0|app|1073|-|-|active"},
            {"version: >-\n  1.0\n", "package|snap|btop|-|app|1073|-|-|active"},
            {"version: [1]\n", "package|snap|btop|-|app|1073|-|-|active"},
            {"name: btop\n", "package|snap|btop|-|app|1073|-|-|active"},
            {"version: '20260824'\ntype: base\n", "package|snap|btop|20260824|base|1073|-|-|active"},
            {"version: 1.0|app|x|y|z\n", "package|snap|btop|-|app|1073|-|-|active"},
            {"version: " + std::string(33, '1') + "\n", "package|snap|btop|-|app|1073|-|-|active"},
            {"version: -bad\n", "package|snap|btop|-|app|1073|-|-|active"},
            {"version: 1.0\ntype: evil|x\n", "package|snap|btop|1.0|other|1073|-|-|active"},
            {"version: 1.0\ntype: \xff\xfe\n", "package|snap|btop|1.0|other|1073|-|-|active"},
            {"version: 1.0\ntype: application\n", "package|snap|btop|1.0|app|1073|-|-|active"},
            {"apps:\n  btop:\n    version: 9.9\nversion: 1.0\n",
             "package|snap|btop|1.0|app|1073|-|-|active"},
        };
        for (const auto& c : cases) {
            yuzu::test::TempDir dir{"yuzu_test_pkg_inventory_linux_yaml_"};
            add_btop(dir.path, c.yaml);
            INFO(c.yaml);
            CHECK(one_row(store(dir.path)) == c.expected);
        }
    }
    SECTION("an unreadable flatpak branch dir is one unknown row, silently") {
        // MUTATION: a token on a per-item branch failure stalls the host's cycle.
        if (::geteuid() == 0) SKIP("running as root: permission bits bypassed");
        yuzu::test::TempDir dir{"yuzu_test_pkg_inventory_linux_branch000_"};
        const std::string base = "var/lib/flatpak/app/org.example.App/x86_64/stable";
        mkdirs(dir.path, base);
        const auto branch = dir.path / base;
        REQUIRE(::chmod(branch.string().c_str(), 0000) == 0);
        ModeGuard restore{branch, 0755};
        CHECK(one_row(store(dir.path)) ==
              "package|flatpak|org.example.App|-|app|-|x86_64|stable|unknown");
    }
    SECTION("flatpak active link anomalies degrade the row") {
        yuzu::test::TempDir dir{"yuzu_test_pkg_inventory_linux_fpactive_"};
        const std::string base = "var/lib/flatpak/app/org.example.App/x86_64/stable/";
        mkdirs(dir.path, base + kCalcCommit);
        link(dir.path, base + "active", "NOT-A-COMMIT");
        CHECK(one_row(store(dir.path)) ==
              "package|flatpak|org.example.App|-|app|-|x86_64|stable|unknown");
        fs::remove(dir.path / base / "active");
        mkdirs(dir.path, base + "active"); // a directory, not a link
        CHECK(one_row(store(dir.path)) ==
              "package|flatpak|org.example.App|-|app|-|x86_64|stable|unknown");
        fs::remove_all(dir.path / base / "active");
        CHECK(one_row(store(dir.path)) ==
              "package|flatpak|org.example.App|-|app|-|x86_64|stable|inactive");
    }
}

TEST_CASE("pkg_inventory linux [synthetic]: a parallel-instance snap is an ordinary row",
          "[pkg_inventory][linux][synthetic]") {
    yuzu::test::TempDir dir{"yuzu_test_pkg_inventory_linux_instance_"};
    put(dir.path, "var/lib/snapd/snaps/jq_foo_7.snap");
    put(dir.path, "snap/jq_foo/7/meta/snap.yaml", "name: jq\nversion: 2.0\n");
    link(dir.path, "snap/jq_foo/current", "7");
    const auto w = store(dir.path);
    CHECK_FALSE(w.token.has_value());
    REQUIRE(w.rows.size() == 1);
    CHECK(w.rows[0] == "package|snap|jq_foo|2.0|app|7|-|-|active");
}

// ── constrained: LIST incompleteness only ────────────────────────────────

TEST_CASE("pkg_inventory linux [constrained]: an unlistable root or nested level is a token, never a quiet gap",
          "[pkg_inventory][linux][constrained]") {
    SECTION("a symlinked snaps dir or flatpak container is refused, never followed") {
        yuzu::test::TempDir dir{"yuzu_test_pkg_inventory_linux_rootlink_"};
        put(dir.path, "elsewhere/evil_5.snap");
        mkdirs(dir.path, "elsewhere2/org.evil.App/x86_64/stable");
        mkdirs(dir.path, "var/lib/snapd");
        link(dir.path, "var/lib/snapd/snaps", "../../../elsewhere");
        mkdirs(dir.path, "var/lib/flatpak");
        link(dir.path, "var/lib/flatpak/app", "../../../elsewhere2");
        const auto w = store(dir.path);
        CHECK(w.rows.empty()); // the link targets hold rows that must NOT appear
        CHECK(has_token(w, "linux:snapd_snaps:not_a_directory"));
        CHECK(has_token(w, "linux:flatpak_app:not_a_directory"));
    }
    SECTION("an unreadable flatpak container") {
        if (::geteuid() == 0) SKIP("running as root: permission bits bypassed");
        yuzu::test::TempDir dir{"yuzu_test_pkg_inventory_linux_rt000_"};
        std::string err;
        REQUIRE(build_capture_tree(dir.path, err));
        const auto rt = dir.path / "var/lib/flatpak/runtime";
        REQUIRE(::chmod(rt.string().c_str(), 0000) == 0);
        ModeGuard restore{rt, 0755};
        const auto w = store(dir.path);
        CHECK(has_token(w, "linux:flatpak_runtime:permission_denied"));
        CHECK(w.rows.size() == 8); // six snaps + two apps; the runtimes are the missing rows
    }
    SECTION("one unreadable flatpak arch dir: its rows are missing and the token says so") {
        // MUTATION: silencing an arch-level open failure ships an incomplete roster as supported.
        if (::geteuid() == 0) SKIP("running as root: permission bits bypassed");
        yuzu::test::TempDir dir{"yuzu_test_pkg_inventory_linux_arch000_"};
        mkdirs(dir.path, "var/lib/flatpak/app/org.example.App/x86_64/stable");
        const auto arch = dir.path / "var/lib/flatpak/app/org.example.App/x86_64";
        REQUIRE(::chmod(arch.string().c_str(), 0000) == 0);
        ModeGuard restore{arch, 0755};
        const auto w = store(dir.path);
        CHECK(has_token(w, "linux:flatpak_app:permission_denied"));
        CHECK(w.rows.empty());
    }
    SECTION("one unreadable flatpak id dir: its rows are missing and the token says so") {
        // MUTATION: silencing a nested-level failure ships an incomplete roster as supported.
        if (::geteuid() == 0) SKIP("running as root: permission bits bypassed");
        yuzu::test::TempDir dir{"yuzu_test_pkg_inventory_linux_id000_"};
        std::string err;
        REQUIRE(build_capture_tree(dir.path, err));
        const auto id = dir.path / "var/lib/flatpak/app/org.gnome.Calculator";
        REQUIRE(::chmod(id.string().c_str(), 0000) == 0);
        ModeGuard restore{id, 0755};
        const auto w = store(dir.path);
        CHECK(has_token(w, "linux:flatpak_app:permission_denied"));
        CHECK(w.rows.size() == 14);
        for (const auto& r : w.rows) CHECK(r.find("org.gnome.Calculator|") == std::string::npos);
    }
}

TEST_CASE("pkg_inventory linux [synthetic]: injected limits are constraints, never a silent short result",
          "[pkg_inventory][linux][synthetic]") {
    yuzu::test::TempDir dir{"yuzu_test_pkg_inventory_linux_limits_"};
    std::string err;
    REQUIRE(build_capture_tree(dir.path, err));

    SECTION("entry_cap omits the affected fact (never a lower bound)") {
        pkg::Limits lim;
        lim.max_entries_per_dir = 1;
        const auto m = managers(dir.path, lim);
        CHECK(has_token(m, "linux:snapd_snaps:entry_cap"));
        bool saw_snap = false;
        for (const auto& r : m.rows)
            if (r.rfind("manager|snap|", 0) == 0) {
                saw_snap = true;
                CHECK(r == "manager|snap|present|-|/var/lib/snapd|-|-");
            }
        CHECK(saw_snap);
        const auto s = store(dir.path, lim);
        CHECK(has_token(s, "linux:snapd_snaps:entry_cap"));
    }
    SECTION("row_cap") {
        pkg::Limits lim;
        lim.max_package_rows = 3;
        const auto s = store(dir.path, lim);
        CHECK(s.rows.size() == 3);
        CHECK(has_token(s, "linux:store_packages:row_cap"));
    }
    SECTION("byte_cap") {
        pkg::Limits lim;
        lim.max_output_bytes = 100;
        const auto s = store(dir.path, lim);
        CHECK(s.rows.size() < 15);
        CHECK(has_token(s, "linux:store_packages:byte_cap"));
    }
    SECTION("walk_budget keeps the rows already found") {
        pkg::Limits lim;
        lim.max_walk_entries = 1; // the snaps listing spends it; flatpak is then refused
        const auto s = store(dir.path, lim);
        CHECK(s.rows.size() == 6);
        CHECK(has_token(s, "linux:flatpak_app:walk_budget"));
    }
    SECTION("an already-expired wall clock is a constraint, not zero rows") {
        pkg::Limits lim;
        lim.max_walk_seconds = 0;
        const auto s = store(dir.path, lim);
        CHECK(s.rows.empty()); // the snap loop stops at the first entry after expiry
        REQUIRE(s.token.has_value());
        CHECK(*s.token == "linux:snapd_snaps:walk_budget");
        const auto m = managers(dir.path, lim);
        CHECK(has_token(m, "walk_budget"));
    }
}

TEST_CASE("pkg_inventory linux [synthetic]: managers presence and fact failures",
          "[pkg_inventory][linux][synthetic]") {
    SECTION("a tool in sbin is present; a symlinked probe dir is skipped silently") {
        yuzu::test::TempDir dir{"yuzu_test_pkg_inventory_linux_sbin_"};
        put(dir.path, "usr/sbin/apk");
        put(dir.path, "elsewhere/dnf");
        link(dir.path, "bin", "elsewhere");
        const auto w = managers(dir.path);
        CHECK_FALSE(w.token.has_value());
        REQUIRE(w.rows.size() == 1);
        CHECK(w.rows[0] == "manager|apk|present|-|-|-|-");
    }
    SECTION("a symlinked tool binary is still a tool") {
        yuzu::test::TempDir dir{"yuzu_test_pkg_inventory_linux_toollink_"};
        link(dir.path, "usr/bin/pacman", "nowhere");
        const auto w = managers(dir.path);
        REQUIRE(w.rows.size() == 1);
        CHECK(w.rows[0] == "manager|pacman|present|-|-|-|-");
    }
    SECTION("an unreadable probe dir") {
        if (::geteuid() == 0) SKIP("running as root: permission bits bypassed");
        yuzu::test::TempDir dir{"yuzu_test_pkg_inventory_linux_probe000_"};
        put(dir.path, "usr/bin/dpkg");
        put(dir.path, "usr/sbin/rpm");
        const auto bin = dir.path / "usr/bin";
        REQUIRE(::chmod(bin.string().c_str(), 0000) == 0);
        ModeGuard restore{bin, 0755};
        const auto w = managers(dir.path);
        CHECK(has_token(w, "linux:tool_dir:permission_denied"));
        REQUIRE(w.rows.size() == 1);
        CHECK(w.rows[0] == "manager|rpm|present|-|-|-|-");
    }
    SECTION("a present tool whose fact dir is unreadable is STILL present, never unavailable") {
        if (::geteuid() == 0) SKIP("running as root: permission bits bypassed");
        yuzu::test::TempDir dir{"yuzu_test_pkg_inventory_linux_fact000_"};
        put(dir.path, "usr/bin/apt");
        put(dir.path, "etc/apt/sources.list.d/a.list");
        const auto d = dir.path / "etc/apt/sources.list.d";
        REQUIRE(::chmod(d.string().c_str(), 0000) == 0);
        ModeGuard restore{d, 0755};
        const auto w = managers(dir.path);
        CHECK(has_token(w, "linux:apt_sources_d:permission_denied"));
        REQUIRE(w.rows.size() == 1);
        CHECK(w.rows[0] == "manager|apt|present|-|/etc/apt|-|-");
    }
}

// ── seams ────────────────────────────────────────────────────────────────

TEST_CASE("pkg_inventory linux seam: run_linux_at over the capture tree reaches the wire and the typed status",
          "[pkg_inventory][linux][seam]") {
    yuzu::test::TempDir dir{"yuzu_test_pkg_inventory_linux_seam_"};
    std::string err;
    REQUIRE(build_capture_tree(dir.path, err));

    const auto s = run_leg(dir.path, pkg::Action::store_packages);
    CHECK(s.rc == 0);
    const auto rows = captured_rows(s.captured);
    REQUIRE(rows.size() == 16); // the status row, then fifteen package rows
    CHECK(rows[0] == "status|store_packages|supported|-");
    for (std::size_t i = 1; i < rows.size(); ++i) CHECK(rows[i].rfind("package|", 0) == 0);
    CHECK(s.result_status == YUZU_RESULT_STATUS_OK);
    CHECK(s.result_completeness == YUZU_RESULT_COMPLETENESS_FULL);

    const auto m = run_leg(dir.path, pkg::Action::managers);
    const auto mrows = captured_rows(m.captured);
    REQUIRE(mrows.size() == 6);
    CHECK(mrows[0] == "status|managers|supported|-");
    for (std::size_t i = 1; i < mrows.size(); ++i) CHECK(mrows[i].rfind("manager|", 0) == 0);
    CHECK(m.result_status == YUZU_RESULT_STATUS_OK);

    // `packages` is unsupported by design, answered before any walk (this root does not exist).
    const fs::path nowhere = dir.path / "does-not-exist";
    const auto p = run_leg(nowhere, pkg::Action::packages);
    CHECK(p.rc == 0);
    const auto prows = captured_rows(p.captured);
    REQUIRE(prows.size() == 1);
    CHECK(prows[0] == "status|packages|unsupported|linux:owned_by_installed_apps");
    CHECK(p.result_status == YUZU_RESULT_STATUS_UNAVAILABLE);
    CHECK(p.result_provenance == "linux:owned_by_installed_apps");
}

TEST_CASE("pkg_inventory linux seam: a forced constraint reaches BOTH the status row and the typed status",
          "[pkg_inventory][linux][seam]") {
    // MUTATION: passing std::nullopt instead of `constraint` in run_linux_at turns this into
    // supported|- and OK/FULL.
    yuzu::test::TempDir dir{"yuzu_test_pkg_inventory_linux_seam_constrained_"};
    put(dir.path, "elsewhere/btop_1.snap");
    mkdirs(dir.path, "var/lib/snapd");
    link(dir.path, "var/lib/snapd/snaps", "../../../elsewhere");

    const auto r = run_leg(dir.path, pkg::Action::store_packages);
    CHECK(r.rc == 0); // a degraded read is never a failed command
    const auto rows = captured_rows(r.captured);
    REQUIRE(rows.size() == 1); // the status row only: the link target must not appear
    const auto status = split_fields_escape_aware(rows[0]);
    REQUIRE(status.size() == 4);
    CHECK(status[2] == "constrained");
    CHECK(status[3] == "linux:snapd_snaps:not_a_directory");
    CHECK(r.result_status == YUZU_RESULT_STATUS_CONSTRAINED);
    CHECK(r.result_completeness == YUZU_RESULT_COMPLETENESS_PARTIAL);
    CHECK(r.result_provenance == status[3]);
}

TEST_CASE("pkg_inventory linux seam: a held slot answers busy at once and walks nothing",
          "[pkg_inventory][linux][seam][busy]") {
    yuzu::test::TempDir dir{"yuzu_test_pkg_inventory_linux_busy_"};
    std::string err;
    REQUIRE(build_capture_tree(dir.path, err));

    {
        const auto held = pkg::WalkSlot::try_acquire(pkg::Action::store_packages);
        REQUIRE(held.has_value());
        CHECK_FALSE(pkg::WalkSlot::try_acquire(pkg::Action::store_packages).has_value());

        const auto busy = run_leg(dir.path, pkg::Action::store_packages, Via::guarded);
        CHECK(busy.rc == 0);
        const auto rows = captured_rows(busy.captured);
        REQUIRE(rows.size() == 1);
        CHECK(rows[0] == "status|store_packages|constrained|linux:store_packages:busy");
        CHECK(busy.result_status == YUZU_RESULT_STATUS_CONSTRAINED);
        CHECK(busy.result_completeness == YUZU_RESULT_COMPLETENESS_PARTIAL);
        CHECK(busy.result_provenance == "linux:store_packages:busy");

        // The slots are per action. MUTATION: a 2-slot array breaks here (index 2 is out of range).
        const auto m = pkg::WalkSlot::try_acquire(pkg::Action::managers);
        const auto p = pkg::WalkSlot::try_acquire(pkg::Action::packages);
        CHECK(m.has_value());
        CHECK(p.has_value());
        const auto other = run_leg(dir.path, pkg::Action::managers, Via::guarded);
        CHECK(captured_rows(other.captured)[0] == "status|managers|constrained|linux:managers:busy");
    }
    // Released with the guard: the action walks again, and releases its own slot each time.
    for (int i = 0; i < 2; ++i) {
        const auto again = run_leg(dir.path, pkg::Action::store_packages, Via::guarded);
        CHECK(captured_rows(again.captured).size() == 16);
        CHECK(again.result_status == YUZU_RESULT_STATUS_OK);
    }
    CHECK(pkg::WalkSlot::try_acquire(pkg::Action::store_packages).has_value());
}

#if defined(__linux__)
TEST_CASE("pkg_inventory linux seam: the plugin's own run_linux entry point walks behind the slot",
          "[pkg_inventory][linux][seam][busy]") {
    // run_linux is what execute() calls in production. Holding the slot proves THAT call site is
    // the guarded one without walking this host's real "/" tree. MUTATION: calling run_linux_at
    // from run_linux walks instead.
    const auto held = pkg::WalkSlot::try_acquire(pkg::Action::store_packages);
    REQUIRE(held.has_value());
    const auto busy = run_leg(fs::path{"/"}, pkg::Action::store_packages, Via::entry);
    const auto rows = captured_rows(busy.captured);
    REQUIRE(rows.size() == 1);
    CHECK(rows[0] == "status|store_packages|constrained|linux:store_packages:busy");
}
#endif // defined(__linux__)

TEST_CASE("pkg_inventory linux: walks leave the process's file descriptors exactly as they found them",
          "[pkg_inventory][linux][walk]") {
    yuzu::test::TempDir dir{"yuzu_test_pkg_inventory_linux_fdbalance_"};
    std::string err;
    REQUIRE(build_capture_tree(dir.path, err));
    mkdirs(dir.path, "elsewhere");
    link(dir.path, "var/lib/flatpak/runtime/org.link", "../../../../elsewhere"); // a link, skipped
    pkg::Limits tight;
    tight.max_entries_per_dir = 1;
    pkg::Limits expired;
    expired.max_walk_seconds = 0;
    const pkg::Limits defaults;
    const pkg::Limits* const all[] = {&defaults, &tight, &expired};

    const auto before = open_fd_count();
    for (const pkg::Limits* lim : all) {
        (void)managers(dir.path, *lim);
        (void)store(dir.path, *lim);
    }
    CHECK(open_fd_count() == before);
}

#endif // !defined(_WIN32)
