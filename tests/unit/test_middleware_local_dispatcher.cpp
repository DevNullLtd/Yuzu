/**
 * test_middleware_local_dispatcher.cpp -- loads the ACTUAL built middleware plugin
 * (middleware.dylib / .so / .dll) via PluginHandle::load and drives it through
 * yuzu::agent::LocalDispatcher, exercising the real per-OS leg on the build host.
 *
 * RUNS ON ALL THREE PLATFORMS, deliberately: no platform guard on this TU (a
 * guarded dispatcher TU is how a sibling plugin once shipped a compiled-out
 * Windows leg and stayed green). Only the EXPECTATIONS differ per host, selected
 * with `#if` on the expectation, never on the test:
 *   Linux -- status row first (supported or constrained, never unsupported),
 *            following rows six escape-aware fields. Mutation: removing the
 *            run_linux wiring leaves a stub `unsupported` row and fails the
 *            never-unsupported status assertion.
 *   macOS / Windows -- exactly `status|<action>|unsupported|<os>:planned`: both legs are
 *            planned placeholders in this build.
 * No host-specific count or name assertion for ibm_mq: CI runners are unknown hosts where the
 * product is not installed. The populated rows are asserted host-independently in
 * test_middleware_linux_parsers.cpp.
 *
 * The plugin sources are also scanned for any way of starting a process (the shared bounded runner
 * included), because a version probe's output cannot show that a binary was never run.
 *
 * The descriptors and the action list are GENERATED from the product table
 * (agents/shared/middleware_products.hpp); the descriptor cases below pin them to that table, so
 * a hand-edited descriptor, a dropped leg or an action the table does not name fails here.
 */
#include <catch2/catch_test_macros.hpp>

#include <yuzu/agent/plugin_loader.hpp>
#include <yuzu/plugin.h>
#include <yuzu/plugin.hpp>

#include "local_dispatcher.hpp"
#include "middleware_legs.hpp"

#include <cctype>
#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <iterator>
#include <optional>
#include <set>
#include <sstream>
#include <stdexcept>
#include <string>
#include <string_view>
#include <vector>

namespace fs = std::filesystem;
namespace mw = yuzu::middleware;

namespace {

/// Escape-aware field split. yuzu::util::safe_output_field escapes a literal '|' as '\|', so a
/// naive split('|') overcounts fields on any row whose text happens to contain a pipe.
std::vector<std::string> split_fields_escape_aware(const std::string& row) {
    std::vector<std::string> out;
    std::string cur;
    for (std::size_t i = 0; i < row.size(); ++i) {
        if (row[i] == '\\' && i + 1 < row.size() && row[i + 1] == '|') {
            cur += '|';
            ++i;
        } else if (row[i] == '|') {
            out.push_back(cur);
            cur.clear();
        } else {
            cur += row[i];
        }
    }
    out.push_back(cur);
    return out;
}

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

/// Under `meson test` (MESON_BUILD_ROOT is always set) a missing plugin means the build is
/// genuinely broken and must NOT report "All tests passed".
///
/// getenv (not _dupenv_s) matches every sibling *_local_dispatcher.cpp's identical helper --
/// MSVC's C4996 is silenced locally rather than diverging from that shared idiom.
#if defined(_MSC_VER)
#pragma warning(push)
#pragma warning(disable : 4996)
#endif
void require_plugin_or_skip() {
    if (std::getenv("MESON_BUILD_ROOT") != nullptr) {
        FAIL("middleware plugin library not found under meson test -- the plugin did not build, "
             "or link_depends is not forcing it to build before this test runs");
    }
    WARN("middleware plugin library not found -- skipping the LocalDispatcher round-trip");
}
#if defined(_MSC_VER)
#pragma warning(pop)
#endif

#if defined(_WIN32)
constexpr const char* kPluginExt = ".dll";
#elif defined(__APPLE__)
constexpr const char* kPluginExt = ".dylib";
#else
constexpr const char* kPluginExt = ".so";
#endif

fs::path find_middleware_plugin() {
    const std::string lib_name = std::string{"middleware"} + kPluginExt;
    std::vector<fs::path> candidates;
#if defined(_MSC_VER)
#pragma warning(push)
#pragma warning(disable : 4996)
#endif
    auto* build_root = std::getenv("MESON_BUILD_ROOT");
#if defined(_MSC_VER)
#pragma warning(pop)
#endif
    if (build_root)
        candidates.emplace_back(fs::path{build_root} / "agents" / "plugins" / "middleware" / lib_name);
    candidates.emplace_back(fs::path{"agents"} / "plugins" / "middleware" / lib_name);
    candidates.emplace_back(fs::path{".."} / "agents" / "plugins" / "middleware" / lib_name);
    for (const char* b : {"build-macos", "build-linux", "build-windows"})
        candidates.emplace_back(fs::path{b} / "agents" / "plugins" / "middleware" / lib_name);
    for (const auto& c : candidates)
        if (std::error_code ec; fs::exists(c, ec)) return c;
    return {};
}

struct LoadedPlugin {
    yuzu::agent::PluginHandle handle;
    const YuzuPluginDescriptor* descriptor{nullptr};
    explicit operator bool() const { return descriptor != nullptr; }
};

std::optional<LoadedPlugin> load_middleware_plugin() {
    auto path = find_middleware_plugin();
    if (path.empty()) return std::nullopt;
    // PluginHandle::load returns std::expected<PluginHandle, LoadError>.
    auto loaded = yuzu::agent::PluginHandle::load(path);
    if (!loaded) return std::nullopt;
    const auto* d = loaded->descriptor();
    if (!d) return std::nullopt;
    return LoadedPlugin{std::move(*loaded), d};
}

/// Every action the TABLE names: the loop below runs every test case over each product, so a new
/// table row is exercised without an edit here.
std::vector<std::string> table_actions() {
    std::vector<std::string> out;
    for (const mw::Product& p : mw::kProducts) out.emplace_back(p.id);
    return out;
}

#if defined(__APPLE__)
constexpr const char* kPlannedToken = "macos:planned";
#elif defined(_WIN32)
constexpr const char* kPlannedToken = "windows:planned";
#endif

/// Seam probes: the production execute body (middleware_legs.hpp execute_action) over an
/// injected leg. The loaded plugin's exported execute() is that same function with the host leg
/// (`execute_action(ctx, action, &run_<host>)`), and no input makes a host leg throw without a
/// test hook in the plugin, so the fault is injected through the leg argument -- the seam
/// middleware_legs.hpp documents for exactly this. The unknown-action refusal, which runs inside
/// the same guard, is driven through the loaded plugin below. `kSecret` must never reach the wire.
constexpr const char* kSecret = "probe-secret-exception-text";

int throwing_leg(yuzu::CommandContext&, const mw::Product&) {
    throw std::runtime_error(kSecret);
}

int row_then_throw_leg(yuzu::CommandContext& ctx, const mw::Product& p) {
    mw::emit_read(ctx, p, {}, yuzu::shared::ConstraintAccumulator{});
    throw std::runtime_error(kSecret);
}

template <mw::LegFn Leg>
int seam_execute(YuzuCommandContext* raw, const char* action, const YuzuParam* /*params*/,
                 std::size_t /*param_count*/) {
    yuzu::CommandContext ctx{raw};
    return mw::execute_action(ctx, action, Leg);
}

/// `src` with comments and string/char literal contents blanked (newlines kept), so a banned name
/// that only appears in prose or in a quoted note cannot trip the scan. A `#include` line keeps its
/// quoted path, because `#include "subprocess_runner.hpp"` is exactly what the scan must see. The
/// plugin sources use no raw strings, so none are handled.
std::string blank_comments_and_literals(std::string_view src) {
    std::string out{src};
    enum class State { code, line_comment, block_comment, string_lit, char_lit } st = State::code;
    bool directive = false;  // this line's first non-blank character is '#'
    bool line_start = true;  // only blanks so far on this line
    for (std::size_t i = 0; i < src.size(); ++i) {
        const char c = src[i];
        const char next = i + 1 < src.size() ? src[i + 1] : '\0';
        if (c == '\n') {
            if (st == State::line_comment) st = State::code;
            directive = false;
            line_start = true;
            continue;
        }
        if (line_start && c != ' ' && c != '\t') {
            directive = (c == '#');
            line_start = false;
        }
        switch (st) {
        case State::code:
            if (c == '/' && next == '/') {
                st = State::line_comment;
                out[i] = ' ';
            } else if (c == '/' && next == '*') {
                st = State::block_comment;
                out[i] = ' ';
            } else if (c == '"' && !directive) {
                st = State::string_lit;
                out[i] = ' ';
            } else if (c == '\'' && !directive &&
                       !(i > 0 && std::isalnum(static_cast<unsigned char>(src[i - 1])))) {
                st = State::char_lit; // not a digit separator (65'536)
                out[i] = ' ';
            }
            break;
        case State::line_comment:
            out[i] = ' ';
            break;
        case State::block_comment:
            out[i] = ' ';
            if (c == '*' && next == '/') {
                out[++i] = ' ';
                st = State::code;
            }
            break;
        case State::string_lit:
        case State::char_lit:
            out[i] = ' ';
            if (c == '\\' && next != '\n') {
                if (i + 1 < src.size()) out[++i] = ' ';
            } else if (c == (st == State::string_lit ? '"' : '\'')) {
                st = State::code;
            }
            break;
        }
    }
    return out;
}

/// Every process-launch identifier in the code of `src`: the shared bounded runner and its header,
/// and the raw POSIX and Win32 spawn primitives. Whole identifiers only, so `system_error` and
/// `filesystem` do not match `system`.
std::set<std::string> spawn_identifiers(std::string_view src) {
    static const std::set<std::string, std::less<>> banned{
        "run_bounded_subprocess", "subprocess_runner", "system", "popen", "_popen", "fork",
        "vfork", "posix_spawn", "posix_spawnp", "execl", "execle", "execlp", "execv", "execve",
        "execvp", "execvpe", "fexecve", "CreateProcess", "CreateProcessA", "CreateProcessW",
        "CreateProcessAsUserW", "ShellExecute", "ShellExecuteA", "ShellExecuteW",
        "ShellExecuteExW", "WinExec"};
    const std::string code = blank_comments_and_literals(src);
    const auto is_id = [](char ch) {
        return std::isalnum(static_cast<unsigned char>(ch)) != 0 || ch == '_';
    };
    std::set<std::string> hits;
    for (std::size_t i = 0; i < code.size();) {
        if (!is_id(code[i])) {
            ++i;
            continue;
        }
        std::size_t j = i;
        while (j < code.size() && is_id(code[j])) ++j;
        if (std::string id = code.substr(i, j - i); banned.contains(id)) hits.insert(std::move(id));
        i = j;
    }
    return hits;
}

} // namespace

TEST_CASE("middleware plugin: a throwing leg is contained and reported as internal_error",
          "[middleware][actions][seam]") {
    yuzu::agent::LocalDispatcher dispatcher;
    YuzuPluginDescriptor throwing{};
    throwing.execute = &seam_execute<&throwing_leg>;

    // MUTATION: removing the catch in execute_action lets the exception escape (the test
    // aborts); returning 0 or dropping the row fails the assertions below.
    for (const auto& a : table_actions()) {
        INFO("action: " << a);
        const auto r = dispatcher.run(&throwing, a);
        CHECK(r.rc == 1); // a genuine internal failure is a failed command
        const auto rows = captured_rows(r.captured);
        REQUIRE(rows.size() == 1);
        CHECK(rows[0] == "status|" + a + "|constrained|internal_error");
        CHECK(r.captured.find(kSecret) == std::string::npos); // exception text never leaks
        CHECK(r.result_status == YUZU_RESULT_STATUS_CONSTRAINED);
        CHECK(r.result_completeness == YUZU_RESULT_COMPLETENESS_PARTIAL);
        CHECK(r.result_provenance == "internal_error");
    }

    // A leg that wrote its status row and then threw: two status rows, the LAST wins.
    YuzuPluginDescriptor late{};
    late.execute = &seam_execute<&row_then_throw_leg>;
    const auto l = dispatcher.run(&late, "ibm_mq");
    CHECK(l.rc == 1);
    const auto lrows = captured_rows(l.captured);
    REQUIRE(lrows.size() == 2);
    CHECK(lrows[0] == "status|ibm_mq|supported|-");
    CHECK(lrows[1] == "status|ibm_mq|constrained|internal_error");
    CHECK(l.result_status == YUZU_RESULT_STATUS_CONSTRAINED);

    // The unknown-action refusal runs inside the same guard and never reaches the leg.
    const auto u = dispatcher.run(&throwing, "no_such_action");
    CHECK(u.rc == 1);
    const auto urows = captured_rows(u.captured);
    REQUIRE(urows.size() == 1);
    CHECK(urows[0] == "unknown action: no_such_action");
}

// The plugin's zero-subprocess boundary. The output of a version probe cannot show that a binary
// was never started (a fallback could run `<FilePath>/bin/dspmqinst` through the shared runner,
// discard the output and still answer `-`), and scripts/ci/check-plugin-spawn-lexical.sh accepts
// `yuzu::agent::run_bounded_subprocess`. So the acquisition boundary is pinned at the source: the
// same source-tripwire family as the YUZU_AGENT_SRC_DIR tests, a few small files read once.
TEST_CASE("middleware plugin: no source spawns a process, directly or through the shared runner",
          "[middleware][contract][subprocess]") {
    // Positive controls: the scan sees each way of starting a process, and ignores prose and
    // quoted text, so the real scan below cannot pass vacuously.
    using Ids = std::set<std::string>;
    CHECK(spawn_identifiers("auto r = yuzu::agent::run_bounded_subprocess("
                            "{\"/opt/mqm/bin/dspmqinst\"}, {});") == Ids{"run_bounded_subprocess"});
    CHECK(spawn_identifiers("#include <yuzu/agent/subprocess_runner.hpp>") ==
          Ids{"subprocess_runner"});
    CHECK(spawn_identifiers("#include \"subprocess_runner.hpp\"") == Ids{"subprocess_runner"});
    CHECK(spawn_identifiers("FILE* f = popen(\"x\", \"r\"); ::system(cmd); CreateProcessW(0);") ==
          Ids{"popen", "system", "CreateProcessW"});
    CHECK(spawn_identifiers("const char* s = \"a \\\" fork\";\nfork();") == Ids{"fork"});
    CHECK(spawn_identifiers("// fork() and system()\n/* popen\n posix_spawn */ const char* n = "
                            "\"execve\"; char c = 'x'; auto k = 65'536; std::system_error e;")
              .empty());

    const fs::path plugins{YUZU_PLUGIN_SRC_DIR};
    std::vector<fs::path> files{plugins / ".." / "shared" / "middleware_products.hpp"};
    for (const auto& e : fs::directory_iterator{plugins / "middleware" / "src"}) {
        const auto ext = e.path().extension();
        if (ext == ".hpp" || ext == ".cpp") files.push_back(e.path());
    }
    std::set<std::string> scanned;
    for (const auto& f : files) {
        INFO("file: " << f.string());
        std::ifstream in{f, std::ios::binary};
        REQUIRE(in.is_open());
        const std::string text{std::istreambuf_iterator<char>{in},
                               std::istreambuf_iterator<char>{}};
        CHECK(spawn_identifiers(text).empty());
        scanned.insert(f.filename().string());
    }
    for (const char* must : {"middleware_products.hpp", "middleware_parsers.hpp",
                             "middleware_runner.hpp", "middleware_legs.hpp",
                             "middleware_linux_parsers.hpp", "middleware_linux.cpp",
                             "middleware_macos.cpp", "middleware_win.cpp",
                             "middleware_plugin.cpp"}) {
        INFO("expected source not scanned: " << must);
        CHECK(scanned.contains(must));
    }
}

TEST_CASE("middleware plugin: the actions and the ABI4 descriptors are generated from the product table",
          "[middleware][actions][descriptors]") {
    auto plugin = load_middleware_plugin();
    if (!plugin) {
        require_plugin_or_skip();
        return;
    }
    const YuzuPluginDescriptor& d = *plugin->descriptor;

    // action_descriptor_count() == the table size; every actions() entry resolves via find_product
    // and the list is null-terminated right after the last product.
    REQUIRE(d.action_descriptors != nullptr);
    REQUIRE(d.action_descriptor_count == mw::kProducts.size());
    REQUIRE(d.actions != nullptr);
    std::size_t n = 0;
    for (; d.actions[n] != nullptr; ++n) {
        INFO("actions()[" << n << "]: " << d.actions[n]);
        CHECK(mw::find_product(d.actions[n]) != nullptr);
    }
    CHECK(n == mw::kProducts.size());

    for (std::size_t i = 0; i < mw::kProducts.size(); ++i) {
        const mw::Product& p = mw::kProducts[i];
        const YuzuActionDescriptor& a = d.action_descriptors[i];
        INFO("product: " << p.id);
        CHECK(std::string_view{a.action} == p.id);
        CHECK(std::string_view{d.actions[i]} == p.id);

        // The per-OS support is the table's, and macOS is PLANNED for every product.
        CHECK(a.linux_leg.support == p.linux.support);
        CHECK(a.windows_leg.support == p.windows.support);
        CHECK(a.macos_leg.support == YUZU_SUPPORT_PLANNED);

        // All three legs are always populated (the capability-matrix generator contract): rung 1
        // and a mechanism on each, never an undeclared leg.
        for (const YuzuOsLeg* leg : {&a.linux_leg, &a.macos_leg, &a.windows_leg}) {
            CHECK(leg->support != YUZU_SUPPORT_UNDECLARED);
            CHECK(leg->rung == 1);
            REQUIRE(leg->mechanism != nullptr);
            CHECK(std::string_view{leg->mechanism}.size() > 0);
        }
        CHECK(std::string_view{a.linux_leg.mechanism} == p.linux.mechanism);
        CHECK(std::string_view{a.windows_leg.mechanism} == p.windows.mechanism);
        // A planned leg carries the shared note; the shipped Linux leg carries the table's.
        CHECK(std::string_view{a.macos_leg.fallback} == mw::kPlannedNote);
        if (p.linux.note == nullptr) CHECK(a.linux_leg.fallback == nullptr);
        else CHECK(std::string_view{a.linux_leg.fallback} == p.linux.note);
    }
}

TEST_CASE("middleware plugin: the status row is always first and well-formed",
          "[middleware][actions]") {
    auto plugin = load_middleware_plugin();
    if (!plugin) {
        require_plugin_or_skip();
        return;
    }
    yuzu::agent::LocalDispatcher dispatcher;
    for (const auto& a : table_actions()) {
        INFO("action: " << a);
        auto result = dispatcher.run(plugin->descriptor, a);
        CHECK(result.rc == 0); // a degraded read is never a failed command

        const auto rows = captured_rows(result.captured);
        // Every leg emits at least the status row, so a consumer never has to infer "no middleware"
        // from silence.
        REQUIRE_FALSE(rows.empty());
        const auto st = split_fields_escape_aware(rows[0]);
        REQUIRE(st.size() == 4);
        CHECK(st[0] == "status");
        CHECK(st[1] == a);
        // No data row may precede the status row.
        for (std::size_t i = 1; i < rows.size(); ++i)
            CHECK(rows[i].rfind("status|", 0) != 0);
    }
}

TEST_CASE("middleware plugin: an unknown action is refused, not silently ignored",
          "[middleware][actions]") {
    auto plugin = load_middleware_plugin();
    if (!plugin) {
        require_plugin_or_skip();
        return;
    }
    yuzu::agent::LocalDispatcher dispatcher;
    auto result = dispatcher.run(plugin->descriptor, "no_such_action");
    CHECK(result.rc != 0);
    // Deliberately not a data or status row: an unknown action has no status row. The
    // diagnostic is pinned. MUTATION: deleting or corrupting the `unknown action:` write in
    // execute_action (middleware_legs.hpp), or falling through to a leg, fails here.
    const auto rows = captured_rows(result.captured);
    REQUIRE(rows.size() == 1);
    CHECK(rows[0] == "unknown action: no_such_action");

    // The request-supplied name goes through safe_output_field: a pipe and a trailing
    // backslash can neither open a second field nor swallow the separator of what follows.
    const auto hostile = dispatcher.run(plugin->descriptor, "no|such\\");
    CHECK(hostile.rc != 0);
    const auto hrows = captured_rows(hostile.captured);
    REQUIRE(hrows.size() == 1);
    CHECK(hrows[0] == "unknown action: no\\|such/");
    CHECK(split_fields_escape_aware(hrows[0]).size() == 1);
}

#if defined(__APPLE__) || defined(_WIN32)

TEST_CASE("middleware plugin: the planned legs emit exactly the planned status row",
          "[middleware][actions]") {
    auto plugin = load_middleware_plugin();
    if (!plugin) {
        require_plugin_or_skip();
        return;
    }
    yuzu::agent::LocalDispatcher dispatcher;
    for (const auto& a : table_actions()) {
        INFO("action: " << a);
        auto result = dispatcher.run(plugin->descriptor, a);
        CHECK(result.rc == 0);
        const auto rows = captured_rows(result.captured);
        REQUIRE(rows.size() == 1);
        CHECK(rows[0] == "status|" + a + "|unsupported|" + kPlannedToken);
        // The typed status seam agrees: UNAVAILABLE / PARTIAL, the token as provenance.
        CHECK(result.result_status == YUZU_RESULT_STATUS_UNAVAILABLE);
        CHECK(result.result_completeness == YUZU_RESULT_COMPLETENESS_PARTIAL);
        CHECK(result.result_provenance == kPlannedToken);
    }
}

#else // Linux

TEST_CASE("middleware plugin: the shipped leg reads the host and never reports unsupported",
          "[middleware][actions]") {
    auto plugin = load_middleware_plugin();
    if (!plugin) {
        require_plugin_or_skip();
        return;
    }
    yuzu::agent::LocalDispatcher dispatcher;
    for (const auto& a : table_actions()) {
        INFO("action: " << a);
        auto result = dispatcher.run(plugin->descriptor, a);
        CHECK(result.rc == 0);
        const auto rows = captured_rows(result.captured);
        REQUIRE_FALSE(rows.empty());
        const auto st = split_fields_escape_aware(rows[0]);
        REQUIRE(st.size() == 4);
        // The real leg is either `supported` (with `-`) or `constrained` (with reason tokens). No
        // shipped code path emits a `<os>:leg:not_implemented` placeholder: the check below is the
        // build-completeness tripwire the peripherals TU also carries.
        CHECK((st[2] == "supported" || st[2] == "constrained"));
        CHECK(rows[0].find(":leg:not_implemented") == std::string::npos);
        if (st[2] == "supported") {
            CHECK(st[3] == "-");
            CHECK(result.result_status == YUZU_RESULT_STATUS_OK);
            CHECK(result.result_completeness == YUZU_RESULT_COMPLETENESS_FULL);
        } else {
            CHECK_FALSE(st[3].empty());
            CHECK(result.result_status == YUZU_RESULT_STATUS_CONSTRAINED);
            CHECK(result.result_completeness == YUZU_RESULT_COMPLETENESS_PARTIAL);
            CHECK(result.result_provenance == st[3]);
        }

        for (std::size_t i = 1; i < rows.size(); ++i) {
            INFO("row: " << rows[i]);
            const auto f = split_fields_escape_aware(rows[i]);
            REQUIRE(f.size() == 6);
            CHECK(f[0] == a);
            CHECK(f[1] == mw::find_product(a)->title);
        }
    }
}

#endif
