/**
 * test_script_exec_parsers.cpp -- pure, fixture-fed tests for
 * script_exec_parsers.hpp: resolve_executable()'s argv[0] resolution rules
 * (both the POSIX and Windows regimes, driven on any host via
 * `windows_rules`), assemble_argv()'s per-mode argv shape, and
 * split_path_entries()'s PATH splitting. No OS calls of any kind -- every
 * "is this executable" check is a scripted fake set, never a real
 * filesystem probe, and nothing here spawns a process or sleeps.
 */
#include <catch2/catch_test_macros.hpp>

#include "script_exec_parsers.hpp"

#include <yuzu/agent/subprocess_launch_spec.hpp> // yuzu::agent::quote_windows_arg (BR4-002 round-trip test)

#include <set>
#include <string>
#include <vector>

using yuzu::script_exec::assemble_argv;
using yuzu::script_exec::ExecMode;
using yuzu::script_exec::resolve_executable;
using yuzu::script_exec::split_args;
using yuzu::script_exec::split_args_windows;
using yuzu::script_exec::split_path_entries;

namespace {

/// A fixed set of candidate paths that "exist" -- resolve_executable's
/// IsExecutableFn plugs in exactly this shape at the real call site
/// (production: access()/GetFileAttributesA); here it's a scripted fake so
/// no filesystem is ever touched.
yuzu::script_exec::IsExecutableFn fake_fs(std::set<std::string> present) {
    return [present = std::move(present)](const std::string& candidate) {
        return present.count(candidate) != 0;
    };
}

} // namespace

TEST_CASE("resolve_executable: an absolute POSIX path passes through unchanged",
          "[script_exec][parsers]") {
    auto result = resolve_executable("/usr/bin/echo", "/", {}, fake_fs({}), /*windows_rules=*/false);
    REQUIRE(result.has_value());
    CHECK(*result == "/usr/bin/echo");
}

TEST_CASE("resolve_executable: an absolute Windows drive path passes through unchanged (windows_rules)",
          "[script_exec][parsers]") {
    auto result = resolve_executable("C:\\Windows\\System32\\whoami.exe", "C:\\Windows\\System32",
                                     {}, fake_fs({}), /*windows_rules=*/true);
    REQUIRE(result.has_value());
    CHECK(*result == "C:\\Windows\\System32\\whoami.exe");
}

TEST_CASE("resolve_executable: an absolute Windows UNC path passes through unchanged (windows_rules)",
          "[script_exec][parsers]") {
    auto result = resolve_executable("\\\\server\\share\\tool.exe", "C:\\Windows\\System32", {},
                                     fake_fs({}), /*windows_rules=*/true);
    REQUIRE(result.has_value());
    CHECK(*result == "\\\\server\\share\\tool.exe");
}

TEST_CASE("resolve_executable: a POSIX ./relative path resolves against the injected cwd",
          "[script_exec][parsers]") {
    auto result =
        resolve_executable("./tool", "/home/operator", {}, fake_fs({}), /*windows_rules=*/false);
    REQUIRE(result.has_value());
    CHECK(*result == "/home/operator/./tool");
}

TEST_CASE("resolve_executable: a Windows .\\relative path resolves against the injected cwd "
          "(windows_rules)",
          "[script_exec][parsers]") {
    auto result = resolve_executable(".\\tool.exe", "C:\\Windows\\System32", {}, fake_fs({}),
                                     /*windows_rules=*/true);
    REQUIRE(result.has_value());
    CHECK(*result == "C:\\Windows\\System32\\.\\tool.exe");
}

TEST_CASE("resolve_executable: a same-drive drive-relative cmd resolves against the injected "
          "cwd with the \"C:\" prefix stripped (windows_rules)",
          "[script_exec][parsers]") {
    // "C:foo" is path-like (second char ':') but NOT absolute (no
    // backslash/forward-slash third char) -- Windows treats this as "foo
    // relative to drive C's cwd," so the drive prefix must be stripped
    // before joining, never appended whole (which would embed a second,
    // invalid ':' in the joined path).
    auto result =
        resolve_executable("C:foo", "C:\\Windows\\System32", {}, fake_fs({}), /*windows_rules=*/true);
    REQUIRE(result.has_value());
    CHECK(*result == "C:\\Windows\\System32\\foo");
}

TEST_CASE("resolve_executable: a differing-drive drive-relative cmd is refused -- no cwd for "
          "that drive is available (windows_rules)",
          "[script_exec][parsers]") {
    auto result =
        resolve_executable("D:foo", "C:\\Windows\\System32", {}, fake_fs({}), /*windows_rules=*/true);
    CHECK_FALSE(result.has_value());
}

TEST_CASE("resolve_executable: a bare name is found in the first PATH entry",
          "[script_exec][parsers]") {
    std::vector<std::string> path_entries = {"/usr/bin", "/bin"};
    auto result = resolve_executable("echo", "/", path_entries, fake_fs({"/usr/bin/echo"}),
                                     /*windows_rules=*/false);
    REQUIRE(result.has_value());
    CHECK(*result == "/usr/bin/echo");
}

TEST_CASE("resolve_executable: a bare name is found in the second PATH entry when the first "
          "doesn't have it",
          "[script_exec][parsers]") {
    std::vector<std::string> path_entries = {"/usr/bin", "/bin"};
    auto result = resolve_executable("mytool", "/", path_entries, fake_fs({"/bin/mytool"}),
                                     /*windows_rules=*/false);
    REQUIRE(result.has_value());
    CHECK(*result == "/bin/mytool");
}

TEST_CASE("resolve_executable: a bare name probes both the plain name and name+.exe per PATH "
          "entry under windows_rules",
          "[script_exec][parsers]") {
    std::vector<std::string> path_entries = {"C:\\tools"};
    auto result = resolve_executable("mytool", "C:\\Windows\\System32", path_entries,
                                     fake_fs({"C:\\tools\\mytool.exe"}), /*windows_rules=*/true);
    REQUIRE(result.has_value());
    CHECK(*result == "C:\\tools\\mytool.exe");
}

TEST_CASE("resolve_executable: a bare name is NOT probed with .exe on POSIX",
          "[script_exec][parsers]") {
    std::vector<std::string> path_entries = {"/usr/bin"};
    // Only the .exe-suffixed candidate "exists" -- POSIX must never probe
    // that suffix, so this must still miss.
    auto result = resolve_executable("mytool", "/", path_entries, fake_fs({"/usr/bin/mytool.exe"}),
                                     /*windows_rules=*/false);
    CHECK_FALSE(result.has_value());
}

TEST_CASE("resolve_executable: an unresolvable bare name returns nullopt",
          "[script_exec][parsers]") {
    std::vector<std::string> path_entries = {"/usr/bin", "/bin"};
    auto result =
        resolve_executable("does-not-exist", "/", path_entries, fake_fs({}), /*windows_rules=*/false);
    CHECK_FALSE(result.has_value());
}

TEST_CASE("resolve_executable: a bare name found via a RELATIVE PATH entry resolves to an "
          "absolute path joined against the injected cwd",
          "[script_exec][parsers]") {
    std::vector<std::string> path_entries = {"tools", "/usr/bin"};
    auto result = resolve_executable("helper", "/home/operator", path_entries,
                                     fake_fs({"/home/operator/tools/helper"}),
                                     /*windows_rules=*/false);
    REQUIRE(result.has_value());
    CHECK(*result == "/home/operator/tools/helper");
}

TEST_CASE("resolve_executable: a bare name found via an EMPTY PATH entry (POSIX \"current "
          "directory\" convention) resolves against the injected cwd",
          "[script_exec][parsers]") {
    std::vector<std::string> path_entries = {"", "/usr/bin"};
    auto result = resolve_executable("helper", "/home/operator", path_entries,
                                     fake_fs({"/home/operator/helper"}), /*windows_rules=*/false);
    REQUIRE(result.has_value());
    CHECK(*result == "/home/operator/helper");
}

TEST_CASE("resolve_executable: an empty cmd returns nullopt", "[script_exec][parsers]") {
    auto result = resolve_executable("", "/", {}, fake_fs({}), /*windows_rules=*/false);
    CHECK_FALSE(result.has_value());
}

TEST_CASE("split_path_entries: splits a POSIX-style PATH on ':'", "[script_exec][parsers]") {
    auto entries = split_path_entries("/usr/bin:/bin:/usr/sbin", /*windows_rules=*/false);
    REQUIRE(entries.size() == 3);
    CHECK(entries[0] == "/usr/bin");
    CHECK(entries[1] == "/bin");
    CHECK(entries[2] == "/usr/sbin");
}

TEST_CASE("split_path_entries: splits a Windows-style PATH on ';' and preserves an interior "
          "empty segment (POSIX/Windows PATH convention: empty means \"current directory\")",
          "[script_exec][parsers]") {
    auto entries =
        split_path_entries("C:\\Windows;;C:\\Windows\\System32", /*windows_rules=*/true);
    REQUIRE(entries.size() == 3);
    CHECK(entries[0] == "C:\\Windows");
    CHECK(entries[1].empty());
    CHECK(entries[2] == "C:\\Windows\\System32");
}

TEST_CASE("split_path_entries: an empty PATH value yields no entries", "[script_exec][parsers]") {
    CHECK(split_path_entries("", false).empty());
}

TEST_CASE("split_args: splits on whitespace and strips quote characters",
          "[script_exec][parsers]") {
    auto args = split_args(R"(--flag "quoted value" 'single quoted' plain)");
    REQUIRE(args.size() == 4);
    CHECK(args[0] == "--flag");
    CHECK(args[1] == "quoted value");
    CHECK(args[2] == "single quoted");
    CHECK(args[3] == "plain");
}

TEST_CASE("assemble_argv: exec mode is {resolved_cmd, ...split_args(args)} on POSIX",
          "[script_exec][parsers]") {
    auto argv = assemble_argv(ExecMode::exec, "/usr/bin/echo", "hello world", "",
                              /*windows_rules=*/false);
    REQUIRE(argv.size() == 3);
    CHECK(argv[0] == "/usr/bin/echo");
    CHECK(argv[1] == "hello");
    CHECK(argv[2] == "world");
}

TEST_CASE("assemble_argv: exec mode with no args produces a single-element argv",
          "[script_exec][parsers]") {
    auto argv = assemble_argv(ExecMode::exec, "/usr/bin/whoami", "", "", /*windows_rules=*/false);
    REQUIRE(argv.size() == 1);
    CHECK(argv[0] == "/usr/bin/whoami");
}

TEST_CASE("assemble_argv: exec mode dispatches to split_args_windows under windows_rules "
          "(BR4-002)",
          "[script_exec][parsers]") {
    // The single-quote span below round-trips differently under each
    // regime (see split_args/split_args_windows' own comments) -- proof
    // assemble_argv actually threads windows_rules through to the right
    // splitter rather than always using one or the other.
    auto posix_argv = assemble_argv(ExecMode::exec, "C:\\tool.exe", "'two words'", "",
                                     /*windows_rules=*/false);
    REQUIRE(posix_argv.size() == 2);
    CHECK(posix_argv[1] == "two words");

    auto win_argv = assemble_argv(ExecMode::exec, "C:\\tool.exe", "'two words'", "",
                                  /*windows_rules=*/true);
    REQUIRE(win_argv.size() == 3);
    CHECK(win_argv[1] == "'two");
    CHECK(win_argv[2] == "words'");
}

TEST_CASE("assemble_argv: bash mode carries the script as ONE argv element (Decision-5)",
          "[script_exec][parsers]") {
    auto argv = assemble_argv(ExecMode::bash, "", "", "echo hi; echo bye",
                              /*windows_rules=*/false);
    REQUIRE(argv.size() == 3);
    CHECK(argv[0] == "/bin/bash");
    CHECK(argv[1] == "-c");
    CHECK(argv[2] == "echo hi; echo bye"); // one element -- never split on ';'/' '
}

TEST_CASE("assemble_argv: powershell mode carries the (already-encoded) script as ONE argv "
          "element (Decision-5)",
          "[script_exec][parsers]") {
    // BR3-001 (whole-branch review round 3): the PowerShell path is no
    // longer a compile-time constant this header owns -- the caller
    // (script_exec_plugin.cpp's do_powershell) resolves it via
    // yuzu::agent::windows_system_directory() and passes the result in as
    // resolved_cmd, so this pure test plugs in an arbitrary fixture value
    // rather than asserting on a hard-coded path.
    auto argv = assemble_argv(ExecMode::powershell,
                              "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
                              "", "QQBCAEMA", /*windows_rules=*/true);
    REQUIRE(argv.size() == 5);
    CHECK(argv[0] == "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe");
    CHECK(argv[1] == "-NoProfile");
    CHECK(argv[2] == "-NonInteractive");
    CHECK(argv[3] == "-EncodedCommand");
    CHECK(argv[4] == "QQBCAEMA"); // one element -- the Base64 blob is opaque to argv splitting
}

TEST_CASE("split_args: preserves explicitly quoted empty arguments (BR3-002)",
          "[script_exec][parsers]") {
    // Regression: the pre-migration Windows path never called this function
    // at all -- it appended the raw command line to CreateProcessA
    // verbatim, so the child's own CRT argv parser preserved a quoted empty
    // field. This function's own `!current.empty()` gate (already present,
    // and already lossy, in the pre-migration POSIX-only copy) silently
    // dropped an explicitly quoted empty argument. BR4-002 (whole-branch
    // review round 4) moved Windows off this parser entirely (see
    // split_args_windows below) -- this test now covers POSIX only, which
    // is this function's sole caller as of that fix.
    auto args = split_args(R"("" sentinel '')");
    REQUIRE(args.size() == 3);
    CHECK(args[0].empty());
    CHECK(args[1] == "sentinel");
    CHECK(args[2].empty());
}

// ── split_args_windows (BR4-002, whole-branch review round 4) ──────────────

TEST_CASE("split_args_windows: a single-quoted span is NOT one argument -- single quotes are "
          "ordinary content",
          "[script_exec][parsers][windows]") {
    auto args = split_args_windows(R"('two words')");
    REQUIRE(args.size() == 2);
    CHECK(args[0] == "'two");
    CHECK(args[1] == "words'");
}

TEST_CASE("split_args_windows: a double-quoted span with spaces is ONE argument, quotes "
          "stripped",
          "[script_exec][parsers][windows]") {
    auto args = split_args_windows(R"("a b" c)");
    REQUIRE(args.size() == 2);
    CHECK(args[0] == "a b");
    CHECK(args[1] == "c");
}

TEST_CASE("split_args_windows: an odd backslash run before a quote escapes it to a literal '\"' "
          "with no toggle",
          "[script_exec][parsers][windows]") {
    // a\"b -- one backslash (odd) before the quote: halved to zero literal
    // backslashes, the quote itself survives as a literal '"', quoting
    // never toggles on (so the trailing 'b' is NOT inside a quoted span).
    auto args = split_args_windows(R"(a\"b)");
    REQUIRE(args.size() == 1);
    CHECK(args[0] == "a\"b");
}

TEST_CASE("split_args_windows: an even backslash run before a quote halves and toggles quoting",
          "[script_exec][parsers][windows]") {
    // a\\"b c" -- two backslashes (even) before the quote: halved to one
    // literal backslash, the quote toggles quoting on, so the space before
    // 'c' stays inside the token.
    auto args = split_args_windows(R"(a\\"b c")");
    REQUIRE(args.size() == 1);
    CHECK(args[0] == "a\\b c");
}

TEST_CASE("split_args_windows: a trailing backslash run with no following quote is literal",
          "[script_exec][parsers][windows]") {
    auto args = split_args_windows(R"(C:\path\)");
    REQUIRE(args.size() == 1);
    CHECK(args[0] == "C:\\path\\");
}

TEST_CASE("split_args_windows: an explicitly quoted empty argument survives (BR3-002 parity)",
          "[script_exec][parsers][windows]") {
    auto args = split_args_windows(R"("" sentinel)");
    REQUIRE(args.size() == 2);
    CHECK(args[0].empty());
    CHECK(args[1] == "sentinel");
}

TEST_CASE("split_args_windows: empty input yields no arguments", "[script_exec][parsers][windows]") {
    CHECK(split_args_windows("").empty());
}

TEST_CASE("split_args_windows: round-trips quote_windows_arg's own encoding for an arg "
          "containing a space, a quote, and a trailing backslash",
          "[script_exec][parsers][windows]") {
    const std::string original = R"(has space, a "quote, and trail\)";
    const std::string encoded = yuzu::agent::quote_windows_arg(original);
    auto args = split_args_windows(encoded);
    REQUIRE(args.size() == 1);
    CHECK(args[0] == original);
}

// ── windows_runner_overrides (no_window / inherit_parent_env pairing) ──────
//
// run_via_runner (script_exec_plugin.cpp) only compiles its Windows-only
// `#ifdef _WIN32` block -- which sets opts.inherit_parent_env/opts.no_window
// -- on an actual Windows build, so neither flag is directly observable from
// a macOS/Linux test host. windows_runner_overrides() extracts the PAIRING
// of the two literals into this pure, OS-call-free header instead: it is
// portably testable on every host, and pins the CREATE_NO_WINDOW
// restoration (BR4-007) and the full-environment inheritance (A2-002) this
// plugin's Windows leg preserves from the deleted CreateProcessA call, so a
// future edit that silently flips either default away from `true` is caught
// here rather than only ever failing on the Windows CI leg.
TEST_CASE("windows_runner_overrides pins no_window and inherit_parent_env both true "
          "(BR4-007 / A2-002)",
          "[script_exec][parsers][windows][no_window]") {
    auto overrides = yuzu::script_exec::windows_runner_overrides();
    CHECK(overrides.no_window);
    CHECK(overrides.inherit_parent_env);
}
