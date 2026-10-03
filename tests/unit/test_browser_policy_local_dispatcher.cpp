/**
 * test_browser_policy_local_dispatcher.cpp — loads the ACTUAL built browser_policy
 * plugin (browser_policy.dylib / .so / .dll) via PluginHandle::load and drives its one
 * action, `policies`, through yuzu::agent::LocalDispatcher, exercising the real
 * per-OS leg on the build host (modelled on test_peripherals_local_dispatcher.cpp).
 *
 * RUNS ON ALL THREE PLATFORMS, deliberately: no `#ifndef _WIN32` / `#ifdef __APPLE__`
 * around the TU. A platform-guarded dispatcher TU is how a sibling plugin once shipped a
 * leg that was compiled out entirely and stayed green. The per-OS expectations live
 * INSIDE the case bodies (`#if defined(...)`, the precedent's pattern), so every host
 * runs every case and asserts what its own leg must produce.
 *
 * A MISSING PLUGIN FAILS, on every host and under any runner. The precedents downgrade to
 * a WARN + return outside `meson test`; this TU never does, because a green run that did
 * not load the plugin proves nothing.
 *
 * SHAPE, NOT CONTENT. The Linux leg reads the host's real /etc/opt/{chrome,edge} and
 * /etc/chromium policy files (production root "/"), whose content is unknown on a shared
 * CI runner, so no policy name, value or count is asserted here. The Linux JSON walk over an
 * injected root (populated rows, every failure token, the caps) is proven in
 * test_browser_policy_parsers.cpp; this file proves the built plugin loads, registers the
 * action its definition names, and that a real dispatch reports the outcome the host's own
 * leg promises:
 *  - Windows and macOS (planned placeholders): rc 0, exactly ONE in-band `status` row
 *    (`unavailable`), UNAVAILABLE/PARTIAL and provenance exactly `windows:planned` /
 *    `macos:planned`, no policy rows;
 *  - Linux (the shipping leg): rc 0, OK/FULL with no `status` row, or CONSTRAINED/PARTIAL with
 *    `linux:` tokens and exactly one matching `constrained` `status` row; every other row (if
 *    any) conforms to the nine-field row model, `policy` first.
 * When the Windows or macOS leg ships, its own cases replace the matching planned block
 * below.
 *
 * Two committed source files are read at run time (located from YUZU_TEST_FIXTURE_DIR /
 * MESON_SOURCE_ROOT): content/definitions/browser_policy.yaml, so a rename of the action, or a
 * drift of the row_kind-first column list, is caught here; and browser_policy_linux.cpp, for the
 * run_linux tripwire below. On Linux the status case also
 * looks, read-only, for a `*.json` under the vendor policy directories to decide whether its
 * populated-read tier applies (a host with a policy file must yield a row or a CONSTRAINED
 * status; a host with none gets a WARN), and the shipped leg's whole result is compared with
 * run_linux_at(ctx, "/") -- the differential oracle. Neither of those can see a WRONG ROOT or an
 * unconditional empty OK on a host with no policy file (all three read the same empty tree), so
 * a source tripwire also pins run_linux's one line. No process is spawned and nothing sleeps.
 */
#include <catch2/catch_test_macros.hpp>

#include <yuzu/agent/plugin_loader.hpp>
#include <yuzu/plugin.h>

#include "local_dispatcher.hpp"

#include "browser_policy_parsers.hpp"
#include "browser_policy_legs.hpp" // run_guarded, kExceptionToken
#if defined(__linux__)
#include "browser_policy_linux_parsers.hpp" // run_linux_at: the oracle for the production leg
#endif

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <initializer_list>
#include <istream>
#include <optional>
#include <sstream>
#include <stdexcept>
#include <string>
#include <string_view>
#include <vector>

namespace fs = std::filesystem;
namespace bp = yuzu::browser_policy;

namespace {

// ── the expected schema ──────────────────────────────────────────────────

/// The definition's column names in wire order (content/definitions/browser_policy.yaml),
/// field 0 (the literal row tag) FIRST so the dashboard header lines up with the cells. The
/// row width is this list's size: browser_policy_parsers.hpp has no named constant for it (it
/// is implicit in format_policy_row), so the "row model" case below proves the real formatter
/// emits exactly this many fields.
constexpr std::array<std::string_view, 9> kDefinitionColumns{
    "row_kind", "browser", "level", "scope", "name", "value_type", "value", "source", "detail"};
constexpr std::size_t kPolicyFieldCount = kDefinitionColumns.size();

constexpr std::string_view kActionName = "policies";
constexpr std::string_view kPluginName = "browser_policy";

// ── row / field helpers ──────────────────────────────────────────────────

/// Escape-aware field split. yuzu::util::safe_output_field escapes a literal '|' as '\|', so
/// a naive split('|') overcounts fields on any row whose text happens to contain a pipe.
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
        if (!line.empty() && line.back() == '\r') {
            line.pop_back();
        }
        if (line.rfind("/* TRUNCATED", 0) == 0) {
            continue; // the HARNESS's own cap sentinel (agent.cpp append_output), never a plugin row
        }
        if (!line.empty()) {
            out.push_back(line);
        }
    }
    return out;
}

bool is_status_row(const std::string& row) {
    return row.rfind("status|", 0) == 0;
}

/// The one in-band outcome row a non-OK result must carry, spelled out independently of
/// format_status_row (the exact wire text, so a change to it is a visible test edit).
std::string expected_status_row(std::string_view state, std::string_view reason) {
    return "status|-|-|-|policies|-|" + std::string{state} + "|-|" + std::string{reason};
}

bool is_browser_token(std::string_view s) {
    for (const auto b : {bp::Browser::chrome, bp::Browser::chromium, bp::Browser::edge}) {
        if (bp::browser_token(b) == s) {
            return true;
        }
    }
    return false;
}

bool is_level_token(std::string_view s) {
    for (const auto l : {bp::Level::mandatory, bp::Level::recommended}) {
        if (bp::level_token(l) == s) {
            return true;
        }
    }
    return false;
}

bool is_type_token(std::string_view s) {
    for (const auto t : {bp::PolicyType::Bool, bp::PolicyType::Int, bp::PolicyType::Real,
                         bp::PolicyType::String, bp::PolicyType::List, bp::PolicyType::Dict,
                         bp::PolicyType::Null, bp::PolicyType::Unmodelled}) {
        if (bp::type_token(t) == s) {
            return true;
        }
    }
    return false;
}

/// One wire row against the row model's fixed vocabularies. Shape only: no name, value or
/// source content of the host's real policy files is asserted here.
void check_policy_row_shape(const std::string& row) {
    INFO("row: " << row);
    const auto f = split_fields_escape_aware(row);
    REQUIRE(f.size() == kPolicyFieldCount);
    CHECK(f[0] == "policy"); // row_kind FIRST: the literal row tag (definition column 0)
    CHECK(is_browser_token(f[1]));
    CHECK(is_level_token(f[2]));
    CHECK((f[3] == "machine" || f[3].rfind("user:", 0) == 0));
    CHECK(is_type_token(f[5]));
    CHECK_FALSE(f[8].empty()); // detail is "-" when there is no qualifier, never empty
}

/// The in-band/typed pairing, on a real dispatch result: a CONSTRAINED result carries exactly one
/// `constrained` status row with the typed provenance, an UNAVAILABLE result exactly one
/// `unavailable` row, and a complete read (OK) none; every OTHER row is a policy row that fits
/// the row model. Returns the policy rows.
std::vector<std::string> check_outcome_rows(const yuzu::agent::LocalDispatcher::Result& result) {
    std::vector<std::string> status_rows;
    std::vector<std::string> policy_rows;
    for (const auto& row : captured_rows(result.captured)) {
        (is_status_row(row) ? status_rows : policy_rows).push_back(row);
    }
    const auto all_rows = captured_rows(result.captured);
    if (!all_rows.empty() && !status_rows.empty()) {
        CHECK(is_status_row(all_rows.front())); // the outcome leads the stream
    }
    if (result.result_status == YUZU_RESULT_STATUS_CONSTRAINED) {
        REQUIRE(status_rows.size() == 1);
        CHECK(status_rows[0] == expected_status_row("constrained", result.result_provenance));
    } else if (result.result_status == YUZU_RESULT_STATUS_UNAVAILABLE) {
        REQUIRE(status_rows.size() == 1);
        CHECK(status_rows[0] == expected_status_row("unavailable", result.result_provenance));
    } else {
        CHECK(status_rows.empty()); // a complete read writes no outcome row
    }
    for (const auto& row : status_rows) {
        CHECK(split_fields_escape_aware(row).size() == kPolicyFieldCount);
    }
    for (const auto& row : policy_rows) {
        check_policy_row_shape(row);
    }
    return policy_rows;
}

// ── locating the built plugin ────────────────────────────────────────────

#if defined(_WIN32)
constexpr const char* kPluginExt = ".dll";
#elif defined(__APPLE__)
constexpr const char* kPluginExt = ".dylib";
#else
constexpr const char* kPluginExt = ".so";
#endif

/// getenv (not _dupenv_s) matches every sibling *_local_dispatcher.cpp's identical helper --
/// MSVC's C4996 is silenced locally rather than diverging from that shared idiom.
#if defined(_MSC_VER)
#pragma warning(push)
#pragma warning(disable : 4996)
#endif
const char* env_or_null(const char* name) {
    return std::getenv(name);
}
#if defined(_MSC_VER)
#pragma warning(pop)
#endif

/// Same candidate order as the sibling dispatcher tests. `searched` collects every path tried
/// so a failure names them.
fs::path find_browser_policy_plugin(std::string& searched) {
    const std::string lib_name = std::string{kPluginName} + kPluginExt;
    std::vector<fs::path> candidates;
    if (const char* build_root = env_or_null("MESON_BUILD_ROOT")) {
        candidates.emplace_back(fs::path{build_root} / "agents" / "plugins" / "browser_policy" /
                                lib_name);
    }
    candidates.emplace_back(fs::path{"agents"} / "plugins" / "browser_policy" / lib_name);
    candidates.emplace_back(fs::path{".."} / "agents" / "plugins" / "browser_policy" / lib_name);
    for (const char* b : {"build-macos", "build-linux", "build-windows"}) {
        candidates.emplace_back(fs::path{b} / "agents" / "plugins" / "browser_policy" / lib_name);
    }
    for (const auto& c : candidates) {
        if (!searched.empty()) {
            searched += ", ";
        }
        searched += c.string();
        std::error_code ec;
        if (fs::exists(c, ec) && !ec) {
            return fs::absolute(c, ec);
        }
    }
    return {};
}

struct LoadedPlugin {
    yuzu::agent::PluginHandle handle;
    const YuzuPluginDescriptor* descriptor{nullptr};
};

/// Loads the real built plugin or FAILS the case (FAIL aborts it) -- never skips, never warns.
LoadedPlugin load_browser_policy_plugin() {
    std::string searched;
    const fs::path path = find_browser_policy_plugin(searched);
    if (path.empty()) {
        FAIL("browser_policy plugin library not found (searched: "
             << searched
             << ") -- the plugin did not build, or link_depends is not forcing it to build "
                "before this test runs; run from the build root or via `meson test`");
    }
    auto loaded = yuzu::agent::PluginHandle::load(path);
    if (!loaded) {
        FAIL("browser_policy plugin failed to load from " << path.string() << ": "
                                                          << loaded.error().reason);
    }
    const YuzuPluginDescriptor* descriptor = loaded->descriptor();
    if (descriptor == nullptr) {
        FAIL("browser_policy plugin at " << path.string() << " loaded with a null descriptor");
    }
    return LoadedPlugin{std::move(*loaded), descriptor};
}

std::vector<std::string> registered_actions(const YuzuPluginDescriptor& d) {
    std::vector<std::string> out;
    if (d.actions != nullptr) {
        for (const char* const* a = d.actions; *a != nullptr; ++a) {
            out.emplace_back(*a);
        }
    }
    return out;
}

// ── reading the definition ───────────────────────────────────────────────

struct DefinitionFacts {
    std::string plugin;               // spec.execution.plugin
    std::string action;               // spec.execution.action
    std::vector<std::string> columns; // spec.result.columns[].name, in order
};

std::string_view trim(std::string_view s) {
    const auto b = s.find_first_not_of(" \t\r\n");
    if (b == std::string_view::npos) {
        return {};
    }
    const auto e = s.find_last_not_of(" \t\r\n");
    return s.substr(b, e - b + 1);
}

std::size_t leading_spaces(std::string_view s) {
    std::size_t n = 0;
    while (n < s.size() && s[n] == ' ') {
        ++n;
    }
    return n;
}

/// `key: value` -> the value (trimmed, one layer of matching quotes removed); nullopt when the
/// line is not that key.
std::optional<std::string> scalar_of(std::string_view line, std::string_view key) {
    if (line.size() <= key.size() || line.substr(0, key.size()) != key || line[key.size()] != ':') {
        return std::nullopt;
    }
    auto v = trim(line.substr(key.size() + 1));
    if (v.size() >= 2 && (v.front() == '\'' || v.front() == '"') && v.back() == v.front()) {
        v = v.substr(1, v.size() - 2);
    }
    return std::string{v};
}

/// A deliberately small block scan (indentation, no YAML library): the `execution:` scalars and
/// the `columns:` list of `- name:` items. Enough to bind this test to the definition's action
/// and column order without a parser dependency in the agent test binary.
DefinitionFacts parse_definition(std::istream& in) {
    DefinitionFacts facts;
    enum class Block { none, execution, columns };
    Block block = Block::none;
    std::size_t block_indent = 0;
    std::string raw;
    while (std::getline(in, raw)) {
        const std::string_view t = trim(raw);
        if (t.empty() || t.front() == '#') {
            continue;
        }
        const std::size_t indent = leading_spaces(raw);
        // Leaving the block: a line at or above its indent, except a list item written at the
        // key's own indent.
        if (block != Block::none &&
            (indent < block_indent || (indent == block_indent && !t.starts_with("- ")))) {
            block = Block::none;
        }
        if (block == Block::none) {
            if (t == "execution:") {
                block = Block::execution;
                block_indent = indent;
            } else if (t == "columns:") {
                block = Block::columns;
                block_indent = indent;
            }
            continue;
        }
        if (block == Block::execution) {
            if (const auto plugin_value = scalar_of(t, "plugin")) {
                facts.plugin = *plugin_value;
            } else if (const auto action_value = scalar_of(t, "action")) {
                facts.action = *action_value;
            }
        } else if (t.starts_with("- ")) {
            if (const auto name_value = scalar_of(trim(t.substr(2)), "name")) {
                facts.columns.push_back(*name_value);
            }
        }
    }
    return facts;
}

/// Reads a committed source file by its repo-relative path. Same shape as the plugin finder:
/// named candidates, FAIL (never skip) when none exists.
std::string read_repo_file(const fs::path& rel) {
    std::vector<fs::path> candidates;
#ifdef YUZU_TEST_FIXTURE_DIR
    // <source root>/tests/unit/fixtures -> <source root>; `..` keeps a trailing slash harmless.
    candidates.emplace_back(fs::path{YUZU_TEST_FIXTURE_DIR} / ".." / ".." / ".." / rel);
#endif
    if (const char* src_root = env_or_null("MESON_SOURCE_ROOT")) {
        candidates.emplace_back(fs::path{src_root} / rel);
    }
    candidates.emplace_back(rel);
    candidates.emplace_back(fs::path{".."} / rel);

    std::string searched;
    for (const auto& c : candidates) {
        if (!searched.empty()) {
            searched += ", ";
        }
        searched += c.string();
        std::error_code ec;
        if (!fs::exists(c, ec) || ec) {
            continue;
        }
        std::ifstream in(c, std::ios::binary);
        if (!in) {
            FAIL("could not open " << c.string());
        }
        std::ostringstream text;
        text << in.rdbuf();
        return text.str();
    }
    FAIL(rel.string() << " not found (searched: " << searched << ")");
    return {}; // unreachable: FAIL aborts the case
}

DefinitionFacts load_definition_facts() {
    std::istringstream in(
        read_repo_file(fs::path{"content"} / "definitions" / "browser_policy.yaml"));
    return parse_definition(in);
}

#if defined(_WIN32) || defined(__APPLE__)
/// The planned-leg contract: rc 0, exactly ONE row -- the in-band `unavailable` status row
/// (the response queries do not return the typed status, so without it a planned host reads as
/// "nothing managed") -- and no policy rows; UNAVAILABLE/PARTIAL (never CONSTRAINED, which would
/// count a planned leg as a degraded read, and never OK, which would read as "no policy
/// configured"); provenance exactly `<os>:planned`, repeated in the row.
void check_planned_placeholder(const yuzu::agent::LocalDispatcher::Result& result,
                               std::string_view token) {
    INFO("captured: " << result.captured);
    CHECK(result.rc == 0);
    const auto rows = captured_rows(result.captured);
    REQUIRE(rows.size() == 1);
    CHECK(rows[0] == expected_status_row("unavailable", token));
    CHECK(result.result_status == YUZU_RESULT_STATUS_UNAVAILABLE);
    CHECK(result.result_completeness == YUZU_RESULT_COMPLETENESS_PARTIAL);
    CHECK(result.result_provenance == std::string{token});
}
#endif

#if defined(__linux__)
/// The populated-read tier's host guard: true when at least one `*.json` sits under a vendor
/// policy directory the Linux leg walks. std::filesystem here is a TEST-side look (the production
/// walk is the O_NOFOLLOW openat chain, proven over an injected root in
/// test_browser_policy_parsers.cpp); it only decides whether a populated read is expected on
/// this host. An unreadable directory makes it false (WARN), never a false failure.
bool host_has_policy_file() {
    for (const char* vendor : {"/etc/opt/chrome", "/etc/chromium", "/etc/opt/edge"}) {
        for (const char* level : {"managed", "recommended"}) {
            std::error_code ec;
            const fs::path dir = fs::path{vendor} / "policies" / level;
            for (fs::directory_iterator it{dir, ec}, end; !ec && it != end; it.increment(ec)) {
                if (it->path().extension() == ".json") {
                    return true;
                }
            }
        }
    }
    return false;
}

/// The differential oracle for the production leg. The exported plugin's run_linux is one line,
/// run_linux_at(ctx, "/"), and run_linux_at itself is proven row by row over an injected root in
/// test_browser_policy_parsers.cpp. Running that same call here, on a real CommandContext, gives
/// the result the shipped leg must reproduce exactly on THIS host. That catches a run_linux that
/// reports an unconditional non-OK status, adds or drops a row, or returns nonzero -- on any Linux
/// host. It does NOT catch a wrong root or an unconditional empty OK on a host with no policy
/// file: all three read the same empty tree. Those two are covered by the populated-read tier on
/// a host that has a policy file (the seeded capture in docs/samples/linux.txt) and by the source
/// tripwire below on every host.
int production_root_execute(YuzuCommandContext* raw, const char* /*action*/,
                            const YuzuParam* /*params*/, std::size_t /*param_count*/) {
    yuzu::CommandContext ctx{raw};
    return bp::run_linux_at(ctx, "/");
}
#endif

/// Drives run_guarded with a leg that throws: the real plugin's legs cannot be made to throw on
/// demand, so the seam is exercised through the same synthetic-descriptor harness the parsers TU
/// uses, on a real CommandContext.
int throwing_execute(YuzuCommandContext* raw, const char* /*action*/, const YuzuParam* /*params*/,
                     std::size_t /*param_count*/) {
    yuzu::CommandContext ctx{raw};
    return bp::run_guarded(ctx, [](yuzu::CommandContext&) -> int {
        throw std::runtime_error("leg failure injected by the test");
    });
}

} // namespace

// ── registration ─────────────────────────────────────────────────────────

// MUTATION: rename the plugin, rename or drop the `policies` entry in actions(), or change the
// action string in kActionDescriptors -> the name / registered-actions / descriptor-action
// checks fail; delete the descriptor array -> the count check fails; a plugin that no longer
// builds or loads -> load_browser_policy_plugin() FAILs (never skips).
TEST_CASE("browser_policy plugin: loads and registers exactly the one action the definition names",
          "[browser_policy][descriptors]") {
    auto plugin = load_browser_policy_plugin();

    CHECK(std::string_view{plugin.descriptor->name} == kPluginName);
    const std::vector<std::string> only_policies{std::string{kActionName}};
    CHECK(registered_actions(*plugin.descriptor) == only_policies);

    REQUIRE(plugin.descriptor->action_descriptors != nullptr);
    REQUIRE(plugin.descriptor->action_descriptor_count == 1);
    const auto& d = plugin.descriptor->action_descriptors[0];
    REQUIRE(d.action != nullptr);
    CHECK(std::string_view{d.action} == kActionName);
}

// MUTATION: flip a leg's declared support without changing the code behind it (Windows or macOS
// to SUPPORTED while the leg is still the placeholder, Linux to PLANNED or UNDECLARED, or an
// ifdef'd-out leg reading UNDECLARED) -> the exact-level checks fail, so the descriptor, the
// generated README and the capability matrix cannot drift from what the legs really do.
TEST_CASE("browser_policy plugin: the descriptor declares Linux supported and macOS and Windows "
          "planned, never an undeclared leg",
          "[browser_policy][descriptors]") {
    auto plugin = load_browser_policy_plugin();
    REQUIRE(plugin.descriptor->action_descriptors != nullptr);
    REQUIRE(plugin.descriptor->action_descriptor_count == 1);
    const auto& d = plugin.descriptor->action_descriptors[0];

    CHECK(d.linux_leg.support == YUZU_SUPPORT_SUPPORTED);
    CHECK(d.macos_leg.support == YUZU_SUPPORT_PLANNED);
    CHECK(d.windows_leg.support == YUZU_SUPPORT_PLANNED);
}

// ── the definition binds to the plugin ───────────────────────────────────

// MUTATION: rename `action:` or `plugin:` under `execution:` in
// content/definitions/browser_policy.yaml, or rename the action in the plugin alone -> the
// plugin / registered-action equality checks fail. Drop the `row_kind` column, add or remove a
// column, or reorder them -> the exact ordered-list check fails, which is what stops the
// dashboard header from shifting one column left of the wire cells.
TEST_CASE("browser_policy definition: names this plugin's action and declares row_kind first, "
          "one column per wire field",
          "[browser_policy][definition]") {
    auto plugin = load_browser_policy_plugin();
    const auto def = load_definition_facts();

    CHECK(def.plugin == plugin.descriptor->name);
    const auto actions = registered_actions(*plugin.descriptor);
    CHECK(std::find(actions.begin(), actions.end(), def.action) != actions.end());
    CHECK(def.action == kActionName);

    REQUIRE_FALSE(def.columns.empty());
    CHECK(def.columns.front() == "row_kind");
    CHECK(def.columns.size() == kPolicyFieldCount);
    const std::vector<std::string> expected(kDefinitionColumns.begin(), kDefinitionColumns.end());
    CHECK(def.columns == expected);
}

// MUTATION: add, drop or merge a field in format_policy_row (or emit the row without its leading
// `policy` tag) -> the real formatter's field count no longer equals the width the definition and
// the dispatcher cases below expect, so this fails before a shifted row can reach a dashboard.
TEST_CASE("browser_policy row model: the expected field count is what format_policy_row emits",
          "[browser_policy][parsers]") {
    bp::PolicyRow r;
    r.browser = bp::Browser::chrome;
    r.level = bp::Level::mandatory;
    r.scope = bp::machine_scope();
    r.name = "HomepageLocation";
    r.value = {bp::PolicyType::String, "https://intranet.example.com", {}};
    r.source = "/etc/opt/chrome/policies/managed/corp.json";

    const auto fields = split_fields_escape_aware(bp::format_policy_row(r));
    CHECK(fields.size() == kPolicyFieldCount);
    REQUIRE_FALSE(fields.empty());
    CHECK(fields[0] == "policy");
}

// ── dispatch ─────────────────────────────────────────────────────────────

// MUTATION: delete the `action != "policies"` guard in execute() -> the unknown action runs the
// real leg, rc becomes 0 and the rc check fails; write the refusal as a `policy|...` row -> the
// data-row check fails; drop safe_output_field from the echoed action -> the hostile action's
// pipes become bare separators and the one-field check fails (a request-supplied string could
// otherwise forge extra columns).
TEST_CASE("browser_policy plugin: an unknown action is refused, and its echo cannot forge a row",
          "[browser_policy][actions]") {
    auto plugin = load_browser_policy_plugin();
    yuzu::agent::LocalDispatcher dispatcher;

    const auto plain = dispatcher.run(plugin.descriptor, "no_such_action");
    CHECK(plain.rc != 0);
    for (const auto& row : captured_rows(plain.captured)) {
        INFO("row: " << row);
        CHECK(row.rfind("policy|", 0) != 0); // a refusal is never a data row
    }

    const auto hostile = dispatcher.run(plugin.descriptor, "x|policy|chrome|mandatory");
    CHECK(hostile.rc != 0);
    const auto hostile_rows = captured_rows(hostile.captured);
    REQUIRE_FALSE(hostile_rows.empty()); // refused loudly, not silently ignored
    for (const auto& row : hostile_rows) {
        INFO("row: " << row);
        CHECK(split_fields_escape_aware(row).size() == 1);
    }
}

// MUTATION: a leg that emits a stray extra status row, an outcome row that disagrees with the typed
// status, or a policy row with a dropped or extra field or an out-of-vocabulary browser / level /
// type token -> check_outcome_rows fails on any host where the leg emits rows. On a host with no
// managed policy this is a no-op for policy rows by design: shape, not content. The populated row
// shape is proven over the injected root in test_browser_policy_parsers.cpp.
TEST_CASE("browser_policy plugin: policies returns rc 0 and only rows that fit the row model",
          "[browser_policy][actions]") {
    auto plugin = load_browser_policy_plugin();
    yuzu::agent::LocalDispatcher dispatcher;

    const auto result = dispatcher.run(plugin.descriptor, "policies");
    CHECK(result.rc == 0); // a degraded or planned read is never a failed command
    // The 2 MiB capture cap is the HARNESS's (LocalDispatcher::kCaptureMaxBytes), not a leg
    // outcome: a host with a few large policy values overruns it while the plugin behaves
    // correctly. A truncated capture drops the overflowing row whole and appends one sentinel
    // line (skipped by captured_rows), so every row checked below is still a complete row.
    if (result.truncated) {
        WARN("capture hit LocalDispatcher::kCaptureMaxBytes on this host -- shape-checking the "
             "whole rows before the sentinel");
    }
    // Policy rows fit the row model; the one in-band status row (if any) pairs with the typed
    // status exactly. Shape, not content, on a host whose real policy files are unknown.
    (void)check_outcome_rows(result);
}

// MUTATION (Windows / macOS): revert the placeholder to a CONSTRAINED status (or to
// mark_result_read), drop the mark_result_planned call (status stays UNDECLARED), change the
// `<os>:planned` token, drop the in-band status row (or write a second row), return nonzero, or
// delete the host's dispatch branch in execute() -> the matching check in
// check_planned_placeholder fails.
// MUTATION (Linux): drop the mark_result_read call in run_linux_at (UNDECLARED), report the
// planned outcome (UNAVAILABLE) or a wrong-OS token from the Linux leg -> the OK-or-CONSTRAINED
// and `linux:` token checks fail. A wrong production root or an unconditional empty OK -> the
// populated-read tier fails on a host with a policy file. Any run_linux that differs from
// run_linux_at(ctx, "/") in what it reports (an unconditional CONSTRAINED status included, which
// the tier accepts) -> the differential oracle fails on any host. Row source/scope are read from
// the host's real files, so they are asserted only when policy rows exist.
TEST_CASE("browser_policy plugin: the host's own leg reports the planned placeholder or the read "
          "status",
          "[browser_policy][status]") {
    auto plugin = load_browser_policy_plugin();
    yuzu::agent::LocalDispatcher dispatcher;
    const auto result = dispatcher.run(plugin.descriptor, "policies");

#if defined(_WIN32)
    check_planned_placeholder(result, "windows:planned");
#elif defined(__linux__)
    CHECK(result.rc == 0);
    if (result.result_status == YUZU_RESULT_STATUS_OK) {
        // A complete read, including a host with no managed policy at all: no provenance.
        CHECK(result.result_completeness == YUZU_RESULT_COMPLETENESS_FULL);
        CHECK(result.result_provenance.empty());
    } else {
        // Anything else must be the degraded-read outcome; UNAVAILABLE (planned or exception)
        // and UNDECLARED (the leg never reported) are both wrong here.
        REQUIRE(result.result_status == YUZU_RESULT_STATUS_CONSTRAINED);
        CHECK(result.result_completeness == YUZU_RESULT_COMPLETENESS_PARTIAL);
        REQUIRE_FALSE(result.result_provenance.empty());
        std::istringstream tokens(result.result_provenance);
        std::string token;
        while (std::getline(tokens, token, ',')) {
            INFO("provenance token: " << token);
            CHECK(token.rfind("linux:", 0) == 0);
        }
    }
    const auto policy_rows = check_outcome_rows(result);
    for (const auto& row : policy_rows) {
        INFO("row: " << row);
        const auto f = split_fields_escape_aware(row);
        REQUIRE(f.size() == kPolicyFieldCount);
        CHECK(f[3] == "machine");           // the Linux leg reads machine policy only
        CHECK(f[7].rfind("/etc/", 0) == 0); // the logical source path, never an injected root
    }
    // The populated-read tier. On a host that HAS a readable policy file the production root
    // binding ("/") must surface it: policy rows, or a CONSTRAINED status if the file exists but
    // cannot be decoded. On a host with none (most CI runners) the tier does not apply and says
    // so. MUTATION: run_linux passing any root but "/", or reporting an unconditional empty
    // OK/FULL, yields zero rows + OK on a host that has a policy file -> fails here (checked
    // against the seeded sample in docs/samples/linux.txt; on a policy-less host only the source
    // tripwire below catches those two).
    if (host_has_policy_file()) {
        CHECK((!policy_rows.empty() || result.result_status == YUZU_RESULT_STATUS_CONSTRAINED));
    } else {
        WARN("no *.json under /etc/{opt/chrome,chromium,opt/edge}/policies/{managed,recommended} "
             "on this host -- the populated-read tier does not apply");
    }
    // The differential oracle: the shipped leg must be exactly run_linux_at(ctx, "/"). MUTATION:
    // run_linux reporting an unconditional non-OK status, emitting or dropping a row, or returning
    // nonzero -> one of these fails on any host, policy-less included. (A wrong root or an
    // unconditional empty OK is NOT caught here on a policy-less host; see the tripwire case.)
    {
        YuzuPluginDescriptor oracle{};
        oracle.execute = &production_root_execute;
        const auto expected = dispatcher.run(&oracle, "policies");
        CHECK(result.rc == expected.rc);
        CHECK(result.captured == expected.captured);
        CHECK(result.result_status == expected.result_status);
        CHECK(result.result_completeness == expected.result_completeness);
        CHECK(result.result_provenance == expected.result_provenance);
    }
#elif defined(__APPLE__)
    check_planned_placeholder(result, "macos:planned");
#else
    FAIL("browser_policy has no leg for this host OS");
#endif
}

// ── the exception guard (no exception crosses the plugin ABI) ─────────────

// MUTATION: delete the catch in run_guarded (browser_policy_legs.hpp) -> the throw escapes the
// synthetic descriptor's execute and this case fails on an unexpected exception; drop the
// set_result_status call -> UNDECLARED, the status check fails; change the token -> the exact
// per-OS literal fails; drop the in-band status row from the catch -> the one-row check fails.
TEST_CASE("browser_policy plugin: an exception inside a leg is reported as UNAVAILABLE with the "
          "host's exception token, never thrown across the plugin ABI",
          "[browser_policy][status]") {
    YuzuPluginDescriptor descriptor{};
    descriptor.execute = &throwing_execute;
    yuzu::agent::LocalDispatcher dispatcher;
    const auto result = dispatcher.run(&descriptor, "policies");

    CHECK(result.rc == 1);
    const auto rows = captured_rows(result.captured);
    REQUIRE(rows.size() == 1); // no policy row, exactly the one in-band outcome row
    CHECK(rows[0] == expected_status_row("unavailable", bp::kExceptionToken));
    CHECK(result.result_status == YUZU_RESULT_STATUS_UNAVAILABLE);
    CHECK(result.result_completeness == YUZU_RESULT_COMPLETENESS_PARTIAL);
    CHECK(result.result_provenance == std::string{bp::kExceptionToken});
#if defined(_WIN32)
    CHECK(result.result_provenance == "windows:leg:exception");
#elif defined(__APPLE__)
    CHECK(result.result_provenance == "macos:leg:exception");
#else
    CHECK(result.result_provenance == "linux:leg:exception");
#endif
}

// MUTATION: narrow run_guarded's `catch (...)` to `catch (const std::exception&)` -> a throw of a
// type that is not a std::exception escapes the plugin ABI and this case fails.
namespace {
int throwing_non_std_execute(YuzuCommandContext* raw, const char* /*action*/,
                             const YuzuParam* /*params*/, std::size_t /*param_count*/) {
    yuzu::CommandContext ctx{raw};
    return bp::run_guarded(ctx, [](yuzu::CommandContext&) -> int { throw 42; });
}
} // namespace

TEST_CASE("browser_policy plugin: run_guarded contains an exception that is not a std::exception",
          "[browser_policy][status]") {
    YuzuPluginDescriptor descriptor{};
    descriptor.execute = &throwing_non_std_execute;
    yuzu::agent::LocalDispatcher dispatcher;
    const auto result = dispatcher.run(&descriptor, "policies");
    CHECK(result.rc == 1);
    CHECK(result.result_status == YUZU_RESULT_STATUS_UNAVAILABLE);
    CHECK(result.result_provenance == std::string{bp::kExceptionToken});
}

// The production root binding, pinned as source. run_linux is ONE line, `return
// run_linux_at(ctx, "/");`, and on a host with no policy file every wrong version of it (another
// root, an unconditional OK) reads the same empty tree as the right one, so no runtime check on
// such a host can tell them apart. This test fails the moment that line changes, on every OS; an
// intentional change to it is meant to be a reviewed edit of this test. MUTATION: any edit of the
// call's root argument or body -> the exact text below is no longer the whole function.
TEST_CASE("browser_policy plugin: run_linux is exactly run_linux_at(ctx, \"/\")",
          "[browser_policy][status]") {
    const auto source = read_repo_file(fs::path{"agents"} / "plugins" / "browser_policy" / "src" /
                                       "browser_policy_linux.cpp");
    const std::string needle = "int run_linux(yuzu::CommandContext& ctx) {\n"
                               "    return run_linux_at(ctx, \"/\");\n"
                               "}";
    CHECK(source.find(needle) != std::string::npos);
    // ...and it is the only definition of run_linux.
    CHECK(source.find("run_linux(", source.find("run_linux(") + 1) == std::string::npos);
}
