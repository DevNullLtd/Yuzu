/**
 * test_subprocess_launch_spec.cpp -- host-agnostic tests for the PURE launch-
 * spec core (subprocess_launch_spec.hpp): argv/extension validation, the A5
 * clear-and-allow-list environment (POSIX and Windows shapes), the Colascione
 * Windows argument quoter, and the precomputed Windows handle policy.
 *
 * These exercise pure functions with NO process spawning, so -- unlike the
 * real-child vectors in test_subprocess_runner.cpp, which are `#ifndef _WIN32`
 * -- they compile and run on EVERY platform, INCLUDING Windows (K-10 / CDX-R2-
 * 004: the Windows-relevant quoting/NUL/env logic must actually run on the OS
 * it governs, not be compiled out of the Windows test binary).
 */

#include <catch2/catch_test_macros.hpp>

#include <yuzu/agent/subprocess_launch_spec.hpp>

#include <algorithm>
#include <optional>
#include <string>
#include <vector>

TEST_CASE("build_launch_spec rejects the same things run_bounded_subprocess rejects at runtime (B1)",
          "[subprocess][launch_spec]") {
    using yuzu::agent::build_launch_spec;
    using yuzu::agent::LaunchOptions;
    using yuzu::agent::LaunchSpecError;

    CHECK(build_launch_spec({}, LaunchOptions{}).error == LaunchSpecError::empty_argv);
    CHECK(build_launch_spec({"relative/bin"}, LaunchOptions{}).error == LaunchSpecError::relative_argv0);
    CHECK(build_launch_spec({"/bin/echo", std::string("a\0b", 3)}, LaunchOptions{}).error ==
          LaunchSpecError::embedded_nul);
    // BR-009 (whole-branch review round 2): the .bat/.cmd/.com ban is a
    // Windows cmd.exe/CreateProcess-quoting hazard (CVE-2024-24576) --
    // build_launch_spec now gates it on the COMPILE target, not every
    // platform, so a POSIX build must accept these suffixes as ordinary
    // filename bytes (a real ELF/Mach-O tool could legitimately be named
    // this) while a Windows build still refuses them.
#ifdef _WIN32
    CHECK(build_launch_spec({"/path/tool.bat"}, LaunchOptions{}).error ==
          LaunchSpecError::banned_windows_extension);
    CHECK(build_launch_spec({"/path/TOOL.CMD"}, LaunchOptions{}).error ==
          LaunchSpecError::banned_windows_extension); // case-insensitive
    CHECK(build_launch_spec({"/path/tool.com"}, LaunchOptions{}).error ==
          LaunchSpecError::banned_windows_extension);
#else
    CHECK(build_launch_spec({"/path/tool.bat"}, LaunchOptions{}).error == LaunchSpecError::none);
    CHECK(build_launch_spec({"/path/TOOL.CMD"}, LaunchOptions{}).error == LaunchSpecError::none);
    CHECK(build_launch_spec({"/path/tool.com"}, LaunchOptions{}).error == LaunchSpecError::none);
#endif
    CHECK(build_launch_spec({"C:\\tools\\thing.exe"}, LaunchOptions{}).error ==
          LaunchSpecError::none); // a valid Windows-absolute argv[0]
}

TEST_CASE("build_launch_spec assembles the A5 clear-and-allow-list env with no LD_/DYLD_ leakage (B1)",
          "[subprocess][launch_spec]") {
    using namespace yuzu::agent;
    LaunchOptions opts;
    opts.tz = std::string("UTC");
    LaunchSpec spec = build_launch_spec({"/bin/echo", "hi"}, opts);
    REQUIRE(spec.error == LaunchSpecError::none);

    bool has_path = false;
    bool has_lc_all = false;
    bool has_tz = false;
    for (const auto& e : spec.env) {
        CHECK(e.key.substr(0, 3) != "LD_");
        CHECK(e.key.substr(0, 5) != "DYLD_");
        CHECK(e.key != "IFS");
        CHECK(e.key != "BASH_ENV");
        CHECK(e.key != "GCONV_PATH");
        if (e.key == "PATH")
            has_path = true;
        if (e.key == "LC_ALL") {
            has_lc_all = true;
            CHECK(e.value == "C");
        }
        if (e.key == "TZ") {
            has_tz = true;
            CHECK(e.value == "UTC");
        }
    }
    CHECK(has_path);
    CHECK(has_tz);
    // CDX-P2-008: LC_ALL is a POSIX-only allow-list entry; the Windows leg gets
    // a Windows env with no LC_ALL. build_launch_spec targets the compile OS.
#ifdef _WIN32
    CHECK(!has_lc_all);
#else
    CHECK(has_lc_all);
#endif
}

TEST_CASE("default_launch_env gives Windows children a Windows allow-list, not the POSIX shape "
          "(CDX-P2-008)",
          "[subprocess][launch_spec]") {
    using namespace yuzu::agent;

    // POSIX branch: PATH + LC_ALL=C, no Windows system vars.
    auto posix_env = default_launch_env(/*windows=*/false, std::optional<std::string>{});
    auto find = [](const std::vector<EnvVar>& env, const std::string& k) -> const EnvVar* {
        for (const auto& e : env)
            if (e.key == k)
                return &e;
        return nullptr;
    };
    REQUIRE(find(posix_env, "PATH"));
    CHECK(find(posix_env, "PATH")->value == "/usr/bin:/bin:/usr/sbin:/sbin");
    CHECK(find(posix_env, "LC_ALL"));
    CHECK(find(posix_env, "SystemRoot") == nullptr);

    // Windows branch: system PATH + SystemRoot/windir/TEMP/TMP, no POSIX PATH,
    // no LC_ALL (locale left to the system default).
    auto win_env = default_launch_env(/*windows=*/true, std::optional<std::string>{});
    REQUIRE(find(win_env, "PATH"));
    CHECK(find(win_env, "PATH")->value.find("System32") != std::string::npos);
    CHECK(find(win_env, "PATH")->value.find("/usr/bin") == std::string::npos);
    CHECK(find(win_env, "SystemRoot"));
    CHECK(find(win_env, "windir"));
    CHECK(find(win_env, "TEMP"));
    CHECK(find(win_env, "TMP"));
    CHECK(find(win_env, "LC_ALL") == nullptr);

    // TZ is threaded into either branch when supplied.
    auto tz_env = default_launch_env(/*windows=*/true, std::optional<std::string>("UTC"));
    REQUIRE(find(tz_env, "TZ"));
    CHECK(find(tz_env, "TZ")->value == "UTC");
}

TEST_CASE("quote_windows_arg follows the Colascione backslash-before-quote algorithm (A2)",
          "[subprocess][launch_spec]") {
    using yuzu::agent::quote_windows_arg;
    CHECK(quote_windows_arg("") == "\"\"");
    CHECK(quote_windows_arg("simple") == "simple");
    CHECK(quote_windows_arg("a b c") == "\"a b c\"");
    CHECK(quote_windows_arg("ab\"c") == "\"ab\\\"c\"");
    CHECK(quote_windows_arg("a\\b") == "a\\b"); // no space/quote -> unquoted, backslash untouched
    CHECK(quote_windows_arg("a\\b c") == "\"a\\b c\""); // quoted for the space; a lone backslash
                                                          // not preceding a quote/end is NOT doubled
    CHECK(quote_windows_arg("a b\\") == "\"a b\\\\\""); // trailing backslash IS doubled before the
                                                          // closing quote we add
}

TEST_CASE("build_launch_spec precomputes the Windows handle policy from merge_stderr (A1/B1)",
          "[subprocess][launch_spec]") {
    using namespace yuzu::agent;
    LaunchOptions merged_opts;
    merged_opts.merge_stderr = true;
    LaunchSpec merged_spec = build_launch_spec({"/bin/echo"}, merged_opts);
    REQUIRE(merged_spec.error == LaunchSpecError::none);
    CHECK(merged_spec.windows_handles.inherit_stdout_write);
    CHECK(merged_spec.windows_handles.inherit_stderr_write);

    LaunchSpec default_spec = build_launch_spec({"/bin/echo"}, LaunchOptions{});
    REQUIRE(default_spec.error == LaunchSpecError::none);
    CHECK(default_spec.windows_handles.inherit_stdout_write);
    CHECK_FALSE(default_spec.windows_handles.inherit_stderr_write);
}

// --- merge_launch_env() / SubprocessOptions::extra_env (Alex plan-gate ruling,
// PLAN-04 option b: a bounded, opt-in widening of A5's clear-slate env) ---

TEST_CASE("merge_launch_env replaces a same-named base entry in place, never appends a duplicate",
          "[subprocess][launch_spec][extra_env]") {
    using namespace yuzu::agent;
    std::vector<EnvVar> base = {{"PATH", "/usr/bin:/bin"}, {"LC_ALL", "C"}};
    std::vector<EnvVar> extra = {{"PATH", "/opt/tool/bin"}};

    EnvMergeResult merged = merge_launch_env(base, extra, /*windows=*/false);
    CHECK(merged.rejected.empty());
    REQUIRE(merged.env.size() == 2); // still 2 -- PATH replaced, not duplicated
    CHECK(merged.env[0].key == "PATH");
    CHECK(merged.env[0].value == "/opt/tool/bin"); // replaced value
    CHECK(merged.env[1].key == "LC_ALL");
    CHECK(merged.env[1].value == "C"); // untouched
}

TEST_CASE("merge_launch_env appends a new name in caller order, preserving base order",
          "[subprocess][launch_spec][extra_env]") {
    using namespace yuzu::agent;
    std::vector<EnvVar> base = {{"PATH", "/usr/bin:/bin"}, {"LC_ALL", "C"}};
    std::vector<EnvVar> extra = {{"HOME", "/home/op"}, {"USER", "op"}};

    EnvMergeResult merged = merge_launch_env(base, extra, /*windows=*/false);
    CHECK(merged.rejected.empty());
    REQUIRE(merged.env.size() == 4);
    CHECK(merged.env[0].key == "PATH"); // base order preserved
    CHECK(merged.env[1].key == "LC_ALL");
    CHECK(merged.env[2].key == "HOME"); // new names appended in caller order
    CHECK(merged.env[2].value == "/home/op");
    CHECK(merged.env[3].key == "USER");
    CHECK(merged.env[3].value == "op");
}

TEST_CASE("merge_launch_env rejects every LD_*/DYLD_* prefix and each exact denylisted name",
          "[subprocess][launch_spec][extra_env]") {
    using namespace yuzu::agent;
    const std::vector<EnvVar> base = default_launch_env(/*windows=*/false, std::nullopt);

    for (const std::string& denied : {std::string("LD_PRELOAD"), std::string("LD_LIBRARY_PATH"),
                                       std::string("DYLD_INSERT_LIBRARIES"), std::string("DYLD_LIBRARY_PATH"),
                                       std::string("IFS"), std::string("BASH_ENV"), std::string("ENV"),
                                       std::string("GCONV_PATH"), std::string("NLSPATH"),
                                       std::string("LOCPATH")}) {
        EnvMergeResult merged = merge_launch_env(base, {{denied, "x"}}, /*windows=*/false);
        INFO("denylisted name: " << denied);
        REQUIRE(merged.rejected.size() == 1);
        CHECK(merged.rejected[0] == denied);
        // and never applied -- base is returned unchanged.
        CHECK(merged.env == base);
    }
}

TEST_CASE("merge_launch_env rejects malformed names and values", "[subprocess][launch_spec][extra_env]") {
    using namespace yuzu::agent;
    const std::vector<EnvVar> base = default_launch_env(/*windows=*/false, std::nullopt);

    // Empty name.
    CHECK(merge_launch_env(base, {{"", "x"}}, false).rejected == std::vector<std::string>{""});
    // '=' in name (ambiguous once serialized as "KEY=VALUE").
    CHECK(merge_launch_env(base, {{"FOO=BAR", "x"}}, false).rejected ==
          std::vector<std::string>{"FOO=BAR"});
    // NUL in name.
    CHECK(merge_launch_env(base, {{std::string("FO\0O", 4), "x"}}, false).rejected.size() == 1);
    // NUL in value.
    CHECK(merge_launch_env(base, {{"FOO", std::string("ba\0r", 4)}}, false).rejected ==
          std::vector<std::string>{"FOO"});
}

TEST_CASE("empty extra_env leaves default_launch_env's output byte-identical (no-regression guard)",
          "[subprocess][launch_spec][extra_env]") {
    using namespace yuzu::agent;
    const std::vector<EnvVar> base = default_launch_env(/*windows=*/false, std::optional<std::string>("UTC"));
    EnvMergeResult merged = merge_launch_env(base, /*extra=*/{}, /*windows=*/false);
    CHECK(merged.rejected.empty());
    CHECK(merged.env == base);

    // Same guarantee through the full build_launch_spec() path: an unset
    // extra_env must produce the identical LaunchSpec::env every existing
    // caller already gets today.
    LaunchOptions opts;
    opts.tz = std::string("UTC");
    LaunchSpec with_default_extra = build_launch_spec({"/bin/echo"}, opts);
    REQUIRE(with_default_extra.error == LaunchSpecError::none);

    LaunchOptions opts_explicit_empty = opts;
    opts_explicit_empty.extra_env = {}; // explicit, still empty
    LaunchSpec with_explicit_empty = build_launch_spec({"/bin/echo"}, opts_explicit_empty);
    REQUIRE(with_explicit_empty.error == LaunchSpecError::none);

    CHECK(with_default_extra.env == with_explicit_empty.env);
#ifdef _WIN32
    constexpr bool kThisTargetIsWindows = true;
#else
    constexpr bool kThisTargetIsWindows = false;
#endif
    CHECK(with_default_extra.env == default_launch_env(kThisTargetIsWindows, opts.tz));
}

TEST_CASE("build_launch_spec fails closed with denied_env_var and no spec on a denied extra_env name",
          "[subprocess][launch_spec][extra_env]") {
    using namespace yuzu::agent;
    LaunchOptions opts;
    opts.extra_env = {{"HOME", "/home/op"}, {"LD_PRELOAD", "/evil.so"}};

    LaunchSpec spec = build_launch_spec({"/bin/echo"}, opts);
    CHECK(spec.error == LaunchSpecError::denied_env_var);
    // The whole launch is refused -- env is not "HOME applied, LD_PRELOAD
    // skipped"; build_launch_spec returns before assembling anything past
    // the error (spec.argv is left unset, same as every other error path).
    CHECK(spec.argv.empty());
}

TEST_CASE("merge_launch_env's REPLACE matching is case-sensitive on POSIX, case-insensitive on Windows",
          "[subprocess][launch_spec][extra_env]") {
    using namespace yuzu::agent;
    const std::vector<EnvVar> base = {{"PATH", "/usr/bin:/bin"}};

    // POSIX target: differently-cased name is a NEW variable, coexisting
    // alongside base "PATH" (real POSIX env names are case-sensitive).
    EnvMergeResult posix_merged = merge_launch_env(base, {{"Path", "/opt/bin"}}, /*windows=*/false);
    CHECK(posix_merged.rejected.empty());
    REQUIRE(posix_merged.env.size() == 2);
    CHECK(posix_merged.env[0].key == "PATH");
    CHECK(posix_merged.env[0].value == "/usr/bin:/bin"); // untouched
    CHECK(posix_merged.env[1].key == "Path"); // appended as a distinct name

    // Windows target: differently-cased name REPLACES the base entry (real
    // Windows environment blocks are case-insensitive -- CreateProcessW
    // would otherwise be handed two entries the OS treats as one).
    EnvMergeResult win_merged = merge_launch_env(base, {{"Path", "/opt/bin"}}, /*windows=*/true);
    CHECK(win_merged.rejected.empty());
    REQUIRE(win_merged.env.size() == 1); // replaced, not appended
    CHECK(win_merged.env[0].key == "PATH"); // original casing kept -- REPLACE
                                             // updates the existing entry's
                                             // value in place, it does not
                                             // rename the key to the extra
                                             // entry's casing.
    CHECK(win_merged.env[0].value == "/opt/bin");
}

TEST_CASE("merge_launch_env's denylist follows the target's case rule, not a blanket "
          "case-insensitive one (A0-001)",
          "[subprocess][launch_spec][extra_env]") {
    using namespace yuzu::agent;
    const std::vector<EnvVar> base = default_launch_env(/*windows=*/false, std::nullopt);

    // POSIX target: "ld_preload" is a genuinely different variable from
    // "LD_PRELOAD" there (POSIX env names are case-sensitive), so it must be
    // ACCEPTED, not swept up by a case-insensitive rule that doesn't apply
    // to this target.
    EnvMergeResult posix_merged = merge_launch_env(base, {{"ld_preload", "marker"}}, /*windows=*/false);
    CHECK(posix_merged.rejected.empty());
    const auto it = std::find_if(posix_merged.env.begin(), posix_merged.env.end(),
                                  [](const EnvVar& v) { return v.key == "ld_preload"; });
    REQUIRE(it != posix_merged.env.end());
    CHECK(it->value == "marker");

    // Windows target: the same lowercase name IS caught, because Windows
    // environment-block comparison is case-insensitive.
    EnvMergeResult win_merged = merge_launch_env(base, {{"ld_preload", "marker"}}, /*windows=*/true);
    CHECK(win_merged.rejected == std::vector<std::string>{"ld_preload"});

    // The exact-name denylist (not just the LD_/DYLD_ prefixes) follows the
    // same rule: "bash_env" is accepted on POSIX, denied on Windows.
    CHECK(merge_launch_env(base, {{"bash_env", "x"}}, /*windows=*/false).rejected.empty());
    CHECK(merge_launch_env(base, {{"bash_env", "x"}}, /*windows=*/true).rejected ==
          std::vector<std::string>{"bash_env"});

    // Upper-case names remain denied on both targets -- this rule only
    // widens acceptance for a differently-cased POSIX name, it never
    // narrows the original upper-case contract.
    CHECK(merge_launch_env(base, {{"LD_PRELOAD", "x"}}, /*windows=*/false).rejected ==
          std::vector<std::string>{"LD_PRELOAD"});
    CHECK(merge_launch_env(base, {{"LD_PRELOAD", "x"}}, /*windows=*/true).rejected ==
          std::vector<std::string>{"LD_PRELOAD"});
}

TEST_CASE("merge_launch_env rejects non-ASCII env names fail-closed rather than mismatch "
          "Windows Unicode case folding (A0-002)",
          "[subprocess][launch_spec][extra_env]") {
    using namespace yuzu::agent;
    const std::vector<EnvVar> base = default_launch_env(/*windows=*/false, std::nullopt);

    // "\xc3\x85VAR" is UTF-8 for "AVAR" with a Latin capital letter A with
    // ring above (U+00C5); "\xc3\xa5var" is UTF-8 for its lowercase form
    // (U+00E5) followed by "var". A byte-wise ASCII fold cannot tell these
    // are the same name under Windows' real (Unicode ordinal) case-folding
    // rule, so both must be refused outright -- on EVERY target, not just
    // Windows, since is_denied/is_malformed validation does not vary by
    // target and a POSIX name is legitimately allowed to differ only in
    // case, never in encoding validity.
    const std::string upper_ring_name = "\xc3\x85VAR";
    const std::string lower_ring_name = "\xc3\xa5var";

    CHECK(merge_launch_env(base, {{upper_ring_name, "x"}}, /*windows=*/false).rejected ==
          std::vector<std::string>{upper_ring_name});
    CHECK(merge_launch_env(base, {{upper_ring_name, "x"}}, /*windows=*/true).rejected ==
          std::vector<std::string>{upper_ring_name});
    CHECK(merge_launch_env(base, {{lower_ring_name, "x"}}, /*windows=*/false).rejected ==
          std::vector<std::string>{lower_ring_name});
    CHECK(merge_launch_env(base, {{lower_ring_name, "x"}}, /*windows=*/true).rejected ==
          std::vector<std::string>{lower_ring_name});

    // Neither entry is silently applied -- base is returned unchanged, same
    // fail-closed contract as the other denylist/malformed cases.
    CHECK(merge_launch_env(base, {{upper_ring_name, "x"}}, /*windows=*/true).env == base);

    // build_launch_spec fails closed the same way an LD_PRELOAD name would.
    LaunchOptions opts;
    opts.extra_env = {{upper_ring_name, "x"}};
    LaunchSpec spec = build_launch_spec({"/bin/echo"}, opts);
    CHECK(spec.error == LaunchSpecError::denied_env_var);
    CHECK(spec.argv.empty());

    // An ASCII name with a non-ASCII VALUE is unaffected -- the restriction
    // is on names (matching semantics/comparison), not values.
    CHECK(merge_launch_env(base, {{"FOO", "\xc3\xa5var"}}, /*windows=*/false).rejected.empty());
}

// --- SubprocessOptions::inherit_parent_env / LaunchOptions::inherit_parent_env
// (Alex plan-gate ruling, A2-002 escalation: a second, Windows-only, opt-in
// widening of A5, additive to extra_env -- see subprocess_runner.hpp's field
// comment for the full contract). This header is PURE, so it can only test
// the passthrough shape and the merge algorithm the impure Windows OS shell
// (subprocess_runner.cpp) calls with a live-read parent environment --
// actually reading GetEnvironmentStringsW() and observing a real child's
// environment is exercised in test_subprocess_runner.cpp's Windows block. ---

TEST_CASE("LaunchOptions::inherit_parent_env defaults to false and build_launch_spec passes it "
          "through unchanged (A2-002)",
          "[subprocess][launch_spec][inherit_parent_env]") {
    using namespace yuzu::agent;

    CHECK_FALSE(LaunchOptions{}.inherit_parent_env);

    LaunchSpec default_spec = build_launch_spec({"/bin/echo"}, LaunchOptions{});
    REQUIRE(default_spec.error == LaunchSpecError::none);
    CHECK_FALSE(default_spec.inherit_parent_env);

    LaunchOptions opts_true;
    opts_true.inherit_parent_env = true;
    LaunchSpec true_spec = build_launch_spec({"/bin/echo"}, opts_true);
    REQUIRE(true_spec.error == LaunchSpecError::none);
    CHECK(true_spec.inherit_parent_env);
}

TEST_CASE("inherit_parent_env does not change what THIS pure header computes for spec.env -- only "
          "the impure Windows OS shell branches on it (A2-002)",
          "[subprocess][launch_spec][inherit_parent_env]") {
    using namespace yuzu::agent;
    // build_launch_spec is a pure, allocation-only core with no OS env I/O
    // (see the file header) -- it cannot itself read a "real parent
    // environment" to honour this flag, and must not silently change its own
    // A5-allow-list-plus-extra_env computation just because the flag is set.
    // Only subprocess_runner.cpp's Windows backend, AFTER calling this
    // function, substitutes a live parent-environment read for spec.env when
    // inherit_parent_env is true (see that file's comment at the call site).
    LaunchOptions opts_false;
    opts_false.tz = std::string("UTC");
    LaunchOptions opts_true = opts_false;
    opts_true.inherit_parent_env = true;

    LaunchSpec spec_false = build_launch_spec({"/bin/echo"}, opts_false);
    LaunchSpec spec_true = build_launch_spec({"/bin/echo"}, opts_true);
    REQUIRE(spec_false.error == LaunchSpecError::none);
    REQUIRE(spec_true.error == LaunchSpecError::none);
    CHECK(spec_false.env == spec_true.env);
    CHECK_FALSE(spec_false.inherit_parent_env);
    CHECK(spec_true.inherit_parent_env);
}

TEST_CASE("merge_launch_env layers extra_env on top of a live parent-environment base with the SAME "
          "replace-never-duplicate semantics as the ordinary A5 case (A2-002, design point (a))",
          "[subprocess][launch_spec][inherit_parent_env]") {
    using namespace yuzu::agent;
    // Stands in for a GetEnvironmentStringsW() read the impure Windows OS
    // shell performs at runtime when inherit_parent_env is true -- this is
    // the EXACT algorithm subprocess_runner.cpp's Windows backend calls
    // (merge_launch_env(parent_env, launch_opts.extra_env, /*windows=*/true))
    // once it has that live snapshot, so pinning it here proves the contract
    // without any OS I/O.
    std::vector<EnvVar> parent_env = {
        {"SystemRoot", "C:\\Windows"}, {"HTTPS_PROXY", "http://proxy:8080"}, {"USERNAME", "svc"}};

    // A name NOT in extra_env survives untouched from the parent snapshot.
    EnvMergeResult merged_passthrough = merge_launch_env(parent_env, {}, /*windows=*/true);
    CHECK(merged_passthrough.rejected.empty());
    CHECK(merged_passthrough.env == parent_env);

    // extra_env REPLACES a same-named parent entry in place (case-insensitive
    // on the Windows target) rather than appending a second, ambiguous entry.
    EnvMergeResult merged_replace =
        merge_launch_env(parent_env, {{"UserName", "override"}}, /*windows=*/true);
    CHECK(merged_replace.rejected.empty());
    REQUIRE(merged_replace.env.size() == 3); // still 3 -- replaced, not appended
    auto find = [](const std::vector<EnvVar>& env, const std::string& k) -> const EnvVar* {
        for (const auto& e : env)
            if (e.key == k)
                return &e;
        return nullptr;
    };
    REQUIRE(find(merged_replace.env, "USERNAME"));
    CHECK(find(merged_replace.env, "USERNAME")->value == "override");

    // extra_env can also ADD a name the parent never had at all.
    EnvMergeResult merged_add =
        merge_launch_env(parent_env, {{"YUZU_SITE", "site-1"}}, /*windows=*/true);
    CHECK(merged_add.rejected.empty());
    REQUIRE(merged_add.env.size() == 4);
    REQUIRE(find(merged_add.env, "YUZU_SITE"));
    CHECK(find(merged_add.env, "YUZU_SITE")->value == "site-1");

    // The denylist STILL applies over a parent-environment base -- this flag
    // widens what UNNAMED variables reach the child, never what extra_env
    // itself is allowed to name (design point (b): security stays gated).
    EnvMergeResult merged_denied =
        merge_launch_env(parent_env, {{"LD_PRELOAD", "/evil.so"}}, /*windows=*/true);
    CHECK(merged_denied.rejected == std::vector<std::string>{"LD_PRELOAD"});
    CHECK(merged_denied.env == parent_env); // refused entry never applied
}

// ── filter_inherited_env (BR-001 whole-branch review round 2) ───────────────
//
// Alex's binding ruling: content_dist's deleted POSIX launcher inherited the
// agent's FULL parent environment via execvp() (no environ replacement) --
// the migrated runner's A5 clear-slate silently narrowed that to just
// PATH/LC_ALL(/TZ), an undisclosed regression. The fix is to honour
// inherit_parent_env on POSIX too, but strip the ADR-3002 A5 injection class
// first. filter_inherited_env is the pure, host-testable core of that strip
// -- subprocess_runner.cpp's POSIX backend is the only impure caller (reads
// `environ`, calls this, then merge_launch_env()s extra_env on top exactly
// as the Windows backend already does).

TEST_CASE("filter_inherited_env passes through an ordinary parent snapshot untouched",
          "[subprocess][launch_spec][inherit_parent_env]") {
    using namespace yuzu::agent;
    std::vector<EnvVar> parent_env = {
        {"HOME", "/home/svc"}, {"HTTPS_PROXY", "http://proxy:8080"}, {"PATH", "/usr/bin"}};
    EnvInheritResult result = filter_inherited_env(parent_env, /*windows=*/false);
    CHECK(result.stripped.empty());
    CHECK(result.env == parent_env);
}

TEST_CASE("filter_inherited_env strips every LD_*/DYLD_* name and each exact denylisted name, "
          "silently -- never fails closed",
          "[subprocess][launch_spec][inherit_parent_env]") {
    using namespace yuzu::agent;
    for (const std::string& denied :
        {std::string("LD_PRELOAD"), std::string("LD_LIBRARY_PATH"), std::string("DYLD_INSERT_LIBRARIES"),
         std::string("DYLD_LIBRARY_PATH"), std::string("IFS"), std::string("BASH_ENV"),
         std::string("ENV"), std::string("GCONV_PATH"), std::string("NLSPATH"), std::string("LOCPATH")}) {
        std::vector<EnvVar> parent_env = {{"HOME", "/home/svc"}, {denied, "x"}};
        EnvInheritResult result = filter_inherited_env(parent_env, /*windows=*/false);
        // Dropped, not fatal: no LaunchSpecError-shaped signal here at all --
        // just absent from .env and named in .stripped.
        CHECK(result.stripped == std::vector<std::string>{denied});
        REQUIRE(result.env.size() == 1);
        CHECK(result.env[0].key == "HOME");
    }
}

TEST_CASE("filter_inherited_env's strip follows the target's case rule, matching "
          "merge_launch_env's own denylist case behaviour",
          "[subprocess][launch_spec][inherit_parent_env]") {
    using namespace yuzu::agent;
    // POSIX real environment names are case-sensitive -- "ld_preload" is a
    // genuinely different variable from "LD_PRELOAD" there, so the POSIX
    // strip must be exact-case, not a case-insensitive net that widens the
    // ban to names no real POSIX installer would ever collide with.
    std::vector<EnvVar> posix_env = {{"ld_preload", "marker"}};
    EnvInheritResult posix_result = filter_inherited_env(posix_env, /*windows=*/false);
    CHECK(posix_result.stripped.empty());
    CHECK(posix_result.env == posix_env);

    // Windows environment names are case-insensitive -- the strip must catch
    // any casing there.
    EnvInheritResult win_result = filter_inherited_env(posix_env, /*windows=*/true);
    CHECK(win_result.stripped == std::vector<std::string>{"ld_preload"});
    CHECK(win_result.env.empty());
}

TEST_CASE("filter_inherited_env's accepted entries still layer correctly under merge_launch_env, "
          "matching the POSIX backend's exact call sequence",
          "[subprocess][launch_spec][inherit_parent_env]") {
    using namespace yuzu::agent;
    std::vector<EnvVar> parent_env = {
        {"HOME", "/home/svc"}, {"LD_PRELOAD", "/evil.so"}, {"HTTPS_PROXY", "http://proxy:8080"}};
    EnvInheritResult filtered = filter_inherited_env(parent_env, /*windows=*/false);
    CHECK(filtered.stripped == std::vector<std::string>{"LD_PRELOAD"});

    // extra_env still applies ON TOP of the filtered base, replace-never-
    // duplicate, exactly as the Windows backend's identical sequence does.
    EnvMergeResult merged = merge_launch_env(filtered.env, {{"HOME", "/override"}}, /*windows=*/false);
    CHECK(merged.rejected.empty());
    REQUIRE(merged.env.size() == 2); // LD_PRELOAD never came back
    auto find = [](const std::vector<EnvVar>& env, const std::string& k) -> const EnvVar* {
        for (const auto& e : env)
            if (e.key == k)
                return &e;
        return nullptr;
    };
    REQUIRE(find(merged.env, "HOME"));
    CHECK(find(merged.env, "HOME")->value == "/override");
    REQUIRE(find(merged.env, "HTTPS_PROXY"));
    CHECK_FALSE(find(merged.env, "LD_PRELOAD"));
}
