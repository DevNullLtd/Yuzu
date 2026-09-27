/**
 * test_system_hardening_parsers.cpp -- pure coverage of
 * agents/plugins/system_hardening/src/system_hardening_parsers.hpp.
 *
 * No platform guard: the header is OS-free, and the readers are INJECTED, so
 * nothing here opens /proc, calls sysctlbyname or spawns anything. Fixtures
 * (tests/unit/fixtures/wave8/system_hardening/, each with a .provenance.txt):
 *   linux/proc_sys_debian12.txt             REAL CAPTURE (docker container)
 *   macos/sysctl_posture_macos26.txt        REAL CAPTURE (this Mac)
 *   linux/proc_sys_malformed.txt            RECONSTRUCTION (malformed values)
 * Line shape: <key>\t<ok|err>\t<value or the tool's error text>.
 */
#include <catch2/catch_test_macros.hpp>

#include "system_hardening_parsers.hpp"

#include <algorithm>
#include <cerrno>
#include <cstdint>
#include <filesystem>
#include <fstream>
#include <map>
#include <sstream>
#include <string>
#include <string_view>
#include <vector>

using namespace yuzu::system_hardening;
namespace fs = std::filesystem;
using yuzu::shared::ConstraintAccumulator;
using namespace std::string_view_literals;

namespace {

struct FixtureLine {
    bool ok;
    std::string text;
};

std::map<std::string, FixtureLine> load_fixture(const char* sub, const char* name) {
    const fs::path p = fs::path{YUZU_TEST_FIXTURE_DIR} / "wave8" / "system_hardening" / sub / name;
    std::ifstream f(p);
    REQUIRE(f.is_open()); // a missing fixture is a broken tree, never a skip
    std::map<std::string, FixtureLine> out;
    std::string line;
    while (std::getline(f, line)) {
        const auto t1 = line.find('\t');
        const auto t2 = line.find('\t', t1 + 1);
        REQUIRE(t1 != std::string::npos);
        REQUIRE(t2 != std::string::npos);
        out[line.substr(0, t1)] = {line.substr(t1 + 1, t2 - t1 - 1) == "ok", line.substr(t2 + 1)};
    }
    return out;
}

// The errno a captured tool error text stands for. Only the causes present in
// the captures (plus the two permission phrases) are recognised.
int errno_of(const std::string& text) {
    if (text.find("No such file or directory") != std::string::npos ||
        text.find("unknown oid") != std::string::npos)
        return ENOENT;
    if (text.find("Permission denied") != std::string::npos) return EACCES;
    if (text.find("Operation not permitted") != std::string::npos) return EPERM;
    return EIO;
}

ReadOutcome outcome_of(const FixtureLine& l) {
    return l.ok ? ReadOutcome{0, 0, l.text} : ReadOutcome{errno_of(l.text), 0, {}};
}

/// Linux reader over a fixture; a key the fixture does not mention is ENOENT.
auto linux_reader_over(std::map<std::string, FixtureLine> fx) {
    return [fx = std::move(fx)](std::string_view path) -> ReadOutcome {
        for (const auto& k : kLinuxAllowlist)
            if (k.path == path) {
                const auto it = fx.find(std::string{k.key});
                return it == fx.end() ? ReadOutcome{ENOENT, 0, {}} : outcome_of(it->second);
            }
        return {ENOENT, 0, {}};
    };
}

PostureState state_of(const std::vector<PostureRow>& rows, std::string_view key) {
    for (const auto& r : rows)
        if (r.key == key) return r.state;
    FAIL("no row for " << key);
    return PostureState::unmodelled;
}

std::string raw_of(const std::vector<PostureRow>& rows, std::string_view key) {
    for (const auto& r : rows)
        if (r.key == key) return r.raw;
    return "<missing>";
}

/// Does any accumulated reason token belong to `key` (`<key>:<cause>`)?
bool has_token_for(const ConstraintAccumulator& acc, std::string_view key) {
    const std::string reason = acc.reason();
    std::size_t pos = 0;
    while (pos <= reason.size()) {
        auto end = reason.find(',', pos);
        if (end == std::string::npos) end = reason.size();
        const std::string_view token{reason.data() + pos, end - pos};
        if (token.substr(0, key.size() + 1) == std::string{key} + ":") return true;
        pos = end + 1;
    }
    return false;
}

} // namespace

// ── allowlists ───────────────────────────────────────────────────────────

TEST_CASE("system_hardening: the Linux allowlist is exactly the specified 11 keys, path derived from key",
          "[system_hardening][allowlist]") {
    const std::vector<std::string_view> expected{
        "kernel.randomize_va_space", "kernel.kptr_restrict", "kernel.yama.ptrace_scope",
        "kernel.dmesg_restrict",     "kernel.unprivileged_bpf_disabled", "kernel.sysrq",
        "fs.protected_hardlinks",    "fs.protected_symlinks", "fs.protected_fifos",
        "fs.protected_regular",      "fs.suid_dumpable"};
    REQUIRE(kLinuxAllowlist.size() == expected.size());
    for (std::size_t i = 0; i < expected.size(); ++i) {
        CHECK(kLinuxAllowlist[i].key == expected[i]);
        std::string want = "/proc/sys/" + std::string{expected[i]};
        for (auto& c : want)
            if (c == '.') c = '/';
        CHECK(std::string{kLinuxAllowlist[i].path} == want);
        CHECK_FALSE(kLinuxAllowlist[i].rules.empty()); // every key has a value mapping
    }
}

TEST_CASE("system_hardening: the macOS allowlist has 4 keys, kern.nx removed, only bootargs is a string",
          "[system_hardening][allowlist]") {
    REQUIRE(kMacosAllowlist.size() == 4);
    for (const auto& k : kMacosAllowlist) {
        CHECK(k.name != "kern.nx");
        CHECK((k.kind == SysctlKind::string) == (k.name == "kern.bootargs"));
    }
    CHECK(kMacosAllowlist[0].name == "kern.securelevel");
    CHECK(kMacosAllowlist[3].name == "kern.bootargs");
}

// ── errno classification ─────────────────────────────────────────────────

TEST_CASE("system_hardening: only ENOENT is absent; every other errno is unreadable",
          "[system_hardening][errno]") {
    CHECK(classify_read_errno(ENOENT) == PostureState::absent);
    CHECK(classify_read_errno(EACCES) == PostureState::unreadable);
    CHECK(classify_read_errno(EPERM) == PostureState::unreadable);
    CHECK(classify_read_errno(EIO) == PostureState::unreadable);
    CHECK(classify_read_errno(EINVAL) == PostureState::unreadable);
}

TEST_CASE("system_hardening: only a FAILED read has a reason token; ENOENT (absent) has none",
          "[system_hardening][errno]") {
    // Absence is not a failure: no token can be minted for ENOENT.
    CHECK_FALSE(failure_token("k", ENOENT).has_value());
    // Failures carry distinct tokens: EACCES/EPERM share one, every other errno its own number.
    const auto eacces = failure_token("k", EACCES);
    const auto eperm = failure_token("k", EPERM);
    const auto eio = failure_token("k", EIO);
    REQUIRE(eacces.has_value());
    REQUIRE(eperm.has_value());
    REQUIRE(eio.has_value());
    CHECK(*eacces == "k:eacces");
    CHECK(*eperm == "k:eacces");
    CHECK(*eio == "k:errno_" + std::to_string(EIO));
    CHECK(*eio != *eacces);
    // A token exists exactly when the errno classifies as `unreadable`.
    for (const int err : {ENOENT, EACCES, EPERM, EIO, EINVAL})
        CHECK(failure_token("k", err).has_value() ==
              (classify_read_errno(err) == PostureState::unreadable));
}

TEST_CASE("system_hardening: failed_row -- ENOENT is an absent row with no token, any other errno "
          "an unreadable row with its token",
          "[system_hardening][errno]") {
    ConstraintAccumulator acc;
    const auto absent = failed_row("linux", "k.absent", ENOENT, acc);
    CHECK(absent.state == PostureState::absent);
    CHECK(absent.raw == "-");
    CHECK_FALSE(acc.any_failure()); // absence alone never moves the status
    CHECK(acc.reason().empty());

    const auto denied = failed_row("linux", "k.denied", EACCES, acc);
    CHECK(denied.state == PostureState::unreadable);
    CHECK(denied.raw == "-");
    CHECK(acc.any_failure());
    CHECK(acc.reason() == "k.denied:eacces");

    const auto io = failed_row("linux", "k.io", EIO, acc);
    CHECK(io.state == PostureState::unreadable);
    CHECK(acc.reason() == "k.denied:eacces,k.io:errno_" + std::to_string(EIO));
    // A later absent key adds nothing to the tokens already recorded.
    (void)failed_row("linux", "k.absent2", ENOENT, acc);
    CHECK(acc.reason() == "k.denied:eacces,k.io:errno_" + std::to_string(EIO));
}

// ── mappers ──────────────────────────────────────────────────────────────

TEST_CASE("system_hardening: evaluate_linux maps every allowlisted key's documented values",
          "[system_hardening][mapper]") {
    struct C { const char* key; const char* raw; PostureState want; };
    using P = PostureState;
    const C cases[] = {
        {"kernel.randomize_va_space", "0\n", P::disabled}, {"kernel.randomize_va_space", "1", P::partial},
        {"kernel.randomize_va_space", "2\n", P::enabled},
        {"kernel.kptr_restrict", "0", P::disabled}, {"kernel.kptr_restrict", "1", P::partial},
        {"kernel.kptr_restrict", "2", P::enabled},
        {"kernel.yama.ptrace_scope", "0", P::disabled}, {"kernel.yama.ptrace_scope", "1", P::enabled},
        {"kernel.yama.ptrace_scope", "3", P::enabled},
        {"kernel.dmesg_restrict", "0", P::disabled}, {"kernel.dmesg_restrict", "1", P::enabled},
        {"kernel.unprivileged_bpf_disabled", "0", P::disabled},
        {"kernel.unprivileged_bpf_disabled", "1", P::enabled},
        {"kernel.unprivileged_bpf_disabled", "2", P::enabled},
        {"kernel.sysrq", "0", P::enabled}, {"kernel.sysrq", "1", P::disabled},
        {"kernel.sysrq", "176", P::partial}, {"kernel.sysrq", "511", P::partial},
        {"fs.protected_hardlinks", "0", P::disabled}, {"fs.protected_hardlinks", "1", P::enabled},
        {"fs.protected_symlinks", "1", P::enabled},
        {"fs.protected_fifos", "0", P::disabled}, {"fs.protected_fifos", "1", P::partial},
        {"fs.protected_fifos", "2", P::enabled},
        {"fs.protected_regular", "2", P::enabled},
        {"fs.suid_dumpable", "0", P::enabled}, {"fs.suid_dumpable", "1", P::disabled},
        {"fs.suid_dumpable", "2", P::partial},
    };
    for (const auto& c : cases) {
        INFO(c.key << " = " << c.raw);
        CHECK(evaluate_linux(c.key, c.raw) == c.want);
    }
}

TEST_CASE("system_hardening: evaluate_linux returns unmodelled, never a guess, for unmapped input",
          "[system_hardening][mapper]") {
    for (const char* raw : {"", "\n", "banana", "3", "-1", "1.5", "0x2", "+1", "99999999999999999999999"})
        CHECK(evaluate_linux("kernel.randomize_va_space", raw) == PostureState::unmodelled);
    CHECK(evaluate_linux("kernel.sysrq", "512") == PostureState::unmodelled);
    CHECK(evaluate_linux("kernel.not_allowlisted", "1") == PostureState::unmodelled);
}

TEST_CASE("system_hardening: evaluate_macos_int / evaluate_macos_string", "[system_hardening][mapper]") {
    using P = PostureState;
    CHECK(evaluate_macos_int("kern.securelevel", -1) == P::disabled);
    CHECK(evaluate_macos_int("kern.securelevel", 0) == P::disabled);
    CHECK(evaluate_macos_int("kern.securelevel", 1) == P::partial);
    CHECK(evaluate_macos_int("kern.securelevel", 2) == P::enabled);
    CHECK(evaluate_macos_int("kern.securelevel", 3) == P::unmodelled);
    CHECK(evaluate_macos_int("kern.coredump", 0) == P::enabled);
    CHECK(evaluate_macos_int("kern.coredump", 1) == P::disabled);
    CHECK(evaluate_macos_int("kern.sugid_coredump", 0) == P::enabled);
    CHECK(evaluate_macos_int("kern.sugid_coredump", 2) == P::unmodelled);
    CHECK(evaluate_macos_int("kern.bootargs", 0) == P::unmodelled); // a string key, not an int
    CHECK(evaluate_macos_int("kern.nx", 1) == P::unmodelled);
    // The empty-bootargs contract: an empty value is a successful read, defined `enabled`.
    CHECK(evaluate_macos_string("kern.bootargs", "") == P::enabled);
    CHECK(evaluate_macos_string("kern.bootargs", " \n") == P::enabled);
    CHECK(evaluate_macos_string("kern.bootargs", "-v debug=0x144") == P::unmodelled);
    CHECK(evaluate_macos_string("kern.securelevel", "") == P::unmodelled);
}

// ── row formatting ───────────────────────────────────────────────────────

TEST_CASE("system_hardening: format_posture_row is posture|os|key|raw|state and escapes raw",
          "[system_hardening][row]") {
    CHECK(format_posture_row({"linux", "kernel.kptr_restrict", "1", PostureState::partial}) ==
          "posture|linux|kernel.kptr_restrict|1|partial");
    CHECK(format_posture_row({"linux", "k", "-", PostureState::absent}) == "posture|linux|k|-|absent");
    // OS-supplied raw text is untrusted: a pipe must not add a field.
    CHECK(format_posture_row({"macos", "kern.bootargs", "a|b", PostureState::unmodelled}) ==
          "posture|macos|kern.bootargs|a\\|b|unmodelled");
    for (const auto s : {PostureState::enabled, PostureState::disabled, PostureState::partial,
                         PostureState::unmodelled, PostureState::absent, PostureState::unreadable}) {
        bool found = false;
        for (const auto t : kStateTokens) found = found || t == state_token(s);
        CHECK(found);
    }
}

// ── collect loops through the injected reader ───────────────────────────

TEST_CASE("system_hardening: ENOENT, EACCES and a successful read give three distinct rows; only the "
          "failures carry tokens",
          "[system_hardening][collect]") {
    // kernel.randomize_va_space: value; kptr_restrict: EACCES; yama: ENOENT;
    // dmesg_restrict: EPERM; sysrq: EIO; everything else: value "1".
    auto reader = [](std::string_view path) -> ReadOutcome {
        if (path == "/proc/sys/kernel/kptr_restrict") return {EACCES, 0, {}};
        if (path == "/proc/sys/kernel/yama/ptrace_scope") return {ENOENT, 0, {}};
        if (path == "/proc/sys/kernel/dmesg_restrict") return {EPERM, 0, {}};
        if (path == "/proc/sys/kernel/sysrq") return {EIO, 0, {}};
        if (path == "/proc/sys/kernel/randomize_va_space") return {0, 0, "2\n"};
        return {0, 0, "1\n"};
    };
    ConstraintAccumulator acc;
    const auto rows = collect_linux_posture(reader, acc);
    REQUIRE(rows.size() == kLinuxAllowlist.size());
    CHECK(state_of(rows, "kernel.randomize_va_space") == PostureState::enabled);
    CHECK(raw_of(rows, "kernel.randomize_va_space") == "2");
    CHECK(state_of(rows, "kernel.kptr_restrict") == PostureState::unreadable);
    CHECK(state_of(rows, "kernel.yama.ptrace_scope") == PostureState::absent);
    CHECK(state_of(rows, "kernel.dmesg_restrict") == PostureState::unreadable);
    CHECK(state_of(rows, "kernel.sysrq") == PostureState::unreadable);
    CHECK(raw_of(rows, "kernel.yama.ptrace_scope") == "-");
    // The absent key (yama) adds NO token; the three unreadable keys carry exactly theirs. This
    // mixed run is therefore PERMISSION_DENIED/PARTIAL (EACCES present; select_status below).
    CHECK(acc.any_failure());
    CHECK(acc.reason() == "kernel.kptr_restrict:eacces,kernel.dmesg_restrict:eacces,"
                          "kernel.sysrq:errno_" + std::to_string(EIO));
    CHECK_FALSE(has_token_for(acc, "kernel.yama.ptrace_scope"));
    CHECK(acc.reason().find("enoent") == std::string::npos);
}

TEST_CASE("system_hardening: a run of only values and absent keys adds no token (OK/FULL)",
          "[system_hardening][collect]") {
    // Three keys ENOENT (yama, bpf, sysrq: e.g. a Docker kernel without them), the rest values.
    auto reader = [](std::string_view path) -> ReadOutcome {
        if (path == "/proc/sys/kernel/yama/ptrace_scope" ||
            path == "/proc/sys/kernel/unprivileged_bpf_disabled" ||
            path == "/proc/sys/kernel/sysrq")
            return {ENOENT, 0, {}};
        return {0, 0, "1\n"};
    };
    ConstraintAccumulator acc;
    const auto rows = collect_linux_posture(reader, acc);
    REQUIRE(rows.size() == kLinuxAllowlist.size());
    CHECK(state_of(rows, "kernel.yama.ptrace_scope") == PostureState::absent);
    CHECK(state_of(rows, "kernel.unprivileged_bpf_disabled") == PostureState::absent);
    CHECK(state_of(rows, "kernel.sysrq") == PostureState::absent);
    CHECK_FALSE(acc.any_failure()); // emit_posture reports OK/FULL exactly when this holds
    CHECK(acc.reason().empty());
}

// Fails under: dropping the all-ENOENT canary (a confirmed procfs that still hides every key
// reading as 11 independently-absent rows and a clean OK/FULL, indistinguishable from a healthy
// host). A hidden /proc/sys (ProcSubset=pid, a masked or tmpfs /proc/sys) never reaches this
// layer as ENOENT -- the Linux leg remaps it to ENODEV -- so it is covered by the hidden-surface
// case further down, not by this canary.
TEST_CASE("system_hardening: every key individually absent is a row fact; ALL of them absent "
          "together is a canary",
          "[system_hardening][collect]") {
    ConstraintAccumulator acc;
    const auto rows =
        collect_linux_posture([](std::string_view) { return ReadOutcome{ENOENT, 0, {}}; }, acc);
    REQUIRE(rows.size() == kLinuxAllowlist.size());
    for (const auto& r : rows) {
        // Each row still reports the true, per-key fact: this key was not there.
        CHECK(r.state == PostureState::absent);
        CHECK(r.raw == "-");
    }
    // But eleven-for-eleven ENOENT on a confirmed procfs is not a healthy host with nothing
    // configured -- it is /proc/sys not being the tree this plugin expects. That downgrades the
    // overall result (CONSTRAINED with zero unreadable rows), without touching any row above.
    CHECK(acc.any_failure());
    CHECK(acc.reason() == "proc_sys:not_visible");
    CHECK(select_status(acc, any_denied(rows)).status == YUZU_RESULT_STATUS_CONSTRAINED);
}

// Fails under: the canary firing on a real host where some keys are legitimately absent
// (e.g. no Yama LSM) but most keys read cleanly -- only ALL ELEVEN absent should trip it.
TEST_CASE("system_hardening: a mostly-present host with a few legitimately-absent keys "
          "never trips the all-absent canary",
          "[system_hardening][collect]") {
    auto reader = [](std::string_view path) -> ReadOutcome {
        if (path == "/proc/sys/kernel/yama/ptrace_scope") return {ENOENT, 0, {}};
        return {0, 0, "1"};
    };
    ConstraintAccumulator acc;
    const auto rows = collect_linux_posture(reader, acc);
    REQUIRE(rows.size() == kLinuxAllowlist.size());
    CHECK_FALSE(acc.any_failure());
    CHECK(acc.reason().empty());
}

// Fails under: remap_enoent_for_surface trusting a leaf ENOENT without the surface check
// (unmounted -> absent), remapping a confirmed ENOENT (mounted -> unreadable), or touching
// any errno other than ENOENT. The PR #4792 review's HIGH on the sibling plugin.
TEST_CASE("system_hardening: a leaf ENOENT is absence only when /proc/sys is confirmed mounted",
          "[system_hardening][classify]") {
    CHECK(remap_enoent_for_surface(ENOENT, true) == ENOENT);
    CHECK(remap_enoent_for_surface(ENOENT, false) == ENODEV);
    for (int err : {0, EACCES, EPERM, EIO, EINVAL, ENODEV}) {
        INFO("errno " << err);
        CHECK(remap_enoent_for_surface(err, false) == err);
        CHECK(remap_enoent_for_surface(err, true) == err);
    }
    CHECK(classify_read_errno(remap_enoent_for_surface(ENOENT, false)) == PostureState::unreadable);
    CHECK(classify_read_errno(remap_enoent_for_surface(ENOENT, true)) == PostureState::absent);
}

// Fails under: the probe list starting anywhere but the leaf's own directory, leaving /proc/sys,
// or dropping the /proc/sys entry that a legitimately missing directory (kernel/yama without
// Yama) defers to. This pins the LIST; how the walk consumes it is the surface_is_procfs case
// below.
TEST_CASE("system_hardening: the surface probe walks from the leaf's directory up to /proc/sys",
          "[system_hardening][classify]") {
    CHECK(surface_probe_dirs("/proc/sys/kernel/yama/ptrace_scope") ==
          std::vector<std::string>{"/proc/sys/kernel/yama", "/proc/sys/kernel", "/proc/sys"});
    CHECK(surface_probe_dirs("/proc/sys/fs/suid_dumpable") ==
          std::vector<std::string>{"/proc/sys/fs", "/proc/sys"});
    CHECK(surface_probe_dirs("/proc/sys/kernel") == std::vector<std::string>{"/proc/sys"});
    CHECK(surface_probe_dirs("/proc/sysfoo/x") == std::vector<std::string>{"/proc/sys"});
    CHECK(surface_probe_dirs("/etc/passwd") == std::vector<std::string>{"/proc/sys"});
    // Every allowlisted key probes its own directory first and /proc/sys last.
    for (const auto& k : kLinuxAllowlist) {
        INFO(k.path);
        const auto dirs = surface_probe_dirs(k.path);
        REQUIRE(dirs.size() >= 2);
        CHECK(std::string_view{k.path}.starts_with(dirs.front() + "/"));
        CHECK(dirs.back() == "/proc/sys");
    }
}

namespace {

constexpr std::uint64_t kTmpfsMagic = 0x01021994;

/// A fake statfs over a fixed table: a directory in `table` answers its outcome, any other
/// directory ENOENT. Every probed directory is recorded, in order.
struct FakeStatfs {
    std::map<std::string, StatfsOutcome> table;
    std::vector<std::string> calls;
    StatfsOutcome operator()(const std::string& dir) {
        calls.push_back(dir);
        const auto it = table.find(dir);
        return it == table.end() ? StatfsOutcome{-1, ENOENT, 0} : it->second;
    }
};

StatfsOutcome fs_of(std::uint64_t magic) { return {0, 0, magic}; }

} // namespace

// Fails under: the walk statfs()ing only /proc/sys (the subtree overmount then reads procfs),
// walking from the root down, trusting anything after the first existing directory, treating a
// non-ENOENT statfs failure as "keep looking" or as confirmed, returning true when nothing
// exists, probing past /proc/sys, or -- the review-5318560722 blocker -- folding a REFUSED probe
// (EACCES/EPERM) into the same "not confirmed" answer as a probe that simply found nothing.
TEST_CASE("system_hardening: surface_is_procfs trusts the nearest existing directory only",
          "[system_hardening][classify]") {
    const std::string leaf = "/proc/sys/kernel/yama/ptrace_scope";

    SECTION("a tmpfs over /proc/sys/kernel under a procfs /proc/sys is not procfs") {
        FakeStatfs f{{{"/proc/sys/kernel", fs_of(kTmpfsMagic)}, {"/proc/sys", fs_of(kProcSuperMagic)}},
                     {}};
        const auto s = surface_is_procfs(leaf, f);
        CHECK_FALSE(s.confirmed_procfs);
        CHECK(s.refused_errno == 0);
        CHECK(f.calls == std::vector<std::string>{"/proc/sys/kernel/yama", "/proc/sys/kernel"});
    }
    SECTION("a missing kernel/yama defers to its procfs parent") {
        FakeStatfs f{{{"/proc/sys/kernel", fs_of(kProcSuperMagic)}, {"/proc/sys", fs_of(kProcSuperMagic)}},
                     {}};
        const auto s = surface_is_procfs(leaf, f);
        CHECK(s.confirmed_procfs);
        CHECK(s.refused_errno == 0);
        CHECK(f.calls == std::vector<std::string>{"/proc/sys/kernel/yama", "/proc/sys/kernel"});
    }
    SECTION("the leaf's own directory, when present and procfs, decides at once") {
        FakeStatfs f{{{"/proc/sys/fs", fs_of(kProcSuperMagic)}}, {}};
        CHECK(surface_is_procfs("/proc/sys/fs/suid_dumpable", f).confirmed_procfs);
        CHECK(f.calls.size() == 1);
    }
    SECTION("a refused statfs (EACCES/EPERM) is reported as a refusal, never as confirmation, "
            "and stops the walk") {
        for (const int err : {EACCES, EPERM}) {
            INFO("errno " << err);
            FakeStatfs f{{{"/proc/sys/kernel/yama", StatfsOutcome{-1, err, 0}},
                          {"/proc/sys", fs_of(kProcSuperMagic)}},
                         {}};
            const auto s = surface_is_procfs(leaf, f);
            CHECK_FALSE(s.confirmed_procfs);
            CHECK(s.refused_errno == err);
            CHECK(f.calls.size() == 1);
        }
    }
    SECTION("a non-refusal statfs failure other than ENOENT carries no refusal, and stops the "
            "walk") {
        for (const int err : {EINTR, EIO}) {
            INFO("errno " << err);
            FakeStatfs f{{{"/proc/sys/kernel/yama", StatfsOutcome{-1, err, 0}},
                          {"/proc/sys", fs_of(kProcSuperMagic)}},
                         {}};
            const auto s = surface_is_procfs(leaf, f);
            CHECK_FALSE(s.confirmed_procfs);
            CHECK(s.refused_errno == 0);
            CHECK(f.calls.size() == 1);
        }
    }
    SECTION("nothing existing up to /proc/sys is not procfs, and the walk stops at /proc/sys") {
        FakeStatfs f{{{"/proc", fs_of(kProcSuperMagic)}, {"/", fs_of(kProcSuperMagic)}}, {}};
        const auto s = surface_is_procfs(leaf, f);
        CHECK_FALSE(s.confirmed_procfs);
        CHECK(s.refused_errno == 0);
        CHECK(f.calls ==
              std::vector<std::string>{"/proc/sys/kernel/yama", "/proc/sys/kernel", "/proc/sys"});
    }
    SECTION("the walk is bounded by the probe list for every allowlisted key") {
        for (const auto& k : kLinuxAllowlist) {
            INFO(k.path);
            FakeStatfs f; // every directory ENOENT: the longest possible walk
            CHECK_FALSE(surface_is_procfs(k.path, f).confirmed_procfs);
            CHECK(f.calls == surface_probe_dirs(k.path));
            for (const auto& d : f.calls)
                CHECK(d.starts_with("/proc/sys"));
        }
    }
    SECTION("the chosen answer drives the ENOENT remap end to end") {
        FakeStatfs hidden{{{"/proc/sys/kernel", fs_of(kTmpfsMagic)}}, {}};
        CHECK(resolve_leaf_errno(ENOENT, surface_is_procfs(leaf, hidden)) == ENODEV);
        FakeStatfs present{{{"/proc/sys/kernel", fs_of(kProcSuperMagic)}}, {}};
        CHECK(resolve_leaf_errno(ENOENT, surface_is_procfs(leaf, present)) == ENOENT);
    }
    SECTION("a refused probe is never downgraded to ENODEV, and surfaces PERMISSION_DENIED end "
            "to end (review-5318560722 blocker)") {
        FakeStatfs refused{{{"/proc/sys/kernel/yama", StatfsOutcome{-1, EACCES, 0}},
                            {"/proc/sys", fs_of(kProcSuperMagic)}},
                           {}};
        const int err = resolve_leaf_errno(ENOENT, surface_is_procfs(leaf, refused));
        CHECK(err == EACCES);
        CHECK(classify_read_errno(err) == PostureState::unreadable);

        ConstraintAccumulator acc;
        const auto row = failed_row("linux", "kernel.yama.ptrace_scope", err, acc);
        CHECK(row.state == PostureState::unreadable);
        CHECK(any_denied({&row, 1}));
        const auto status = select_status(acc, any_denied({&row, 1}));
        CHECK(status.status == YUZU_RESULT_STATUS_PERMISSION_DENIED);
        CHECK(status.completeness == YUZU_RESULT_COMPLETENESS_PARTIAL);
        CHECK(status.provenance == "kernel.yama.ptrace_scope:eacces");
    }
}

// Fails under: opened_leaf_error() admitting a non-regular st_mode, or its outcome being
// mistaken for an absence, a denial or an errno. It does NOT observe the leg's open flags or
// that the leg calls this before read(): the FIFO/device non-hang is evidenced by the
// privileged-container probe recorded in the PR body, not by this unit test.
TEST_CASE("system_hardening: only a regular file is read; anything else is unreadable not_regular",
          "[system_hardening][classify]") {
    CHECK(opened_leaf_error(0100644) == 0);           // S_IFREG | 0644: a /proc/sys leaf
    CHECK(opened_leaf_error(0100000) == 0);           // regular, mode 000
    CHECK(opened_leaf_error(0010644) == kErrNotRegular); // S_IFIFO
    CHECK(opened_leaf_error(0020666) == kErrNotRegular); // S_IFCHR (/dev/zero, /dev/urandom)
    CHECK(opened_leaf_error(0060660) == kErrNotRegular); // S_IFBLK
    CHECK(opened_leaf_error(0040555) == kErrNotRegular); // S_IFDIR
    CHECK(opened_leaf_error(0120777) == kErrNotRegular); // S_IFLNK
    CHECK(opened_leaf_error(0140755) == kErrNotRegular); // S_IFSOCK

    CHECK(kErrNotRegular < 0); // never a real errno
    CHECK(classify_read_errno(kErrNotRegular) == PostureState::unreadable);
    CHECK_FALSE(is_denied_errno(kErrNotRegular));
    REQUIRE(failure_token("kernel.sysrq", kErrNotRegular).has_value());
    CHECK(*failure_token("kernel.sysrq", kErrNotRegular) == "kernel.sysrq:not_regular");

    ConstraintAccumulator acc;
    const auto rows = collect_linux_posture(
        [](std::string_view path) -> ReadOutcome {
            if (path == "/proc/sys/kernel/sysrq") return {kErrNotRegular, 0, {}};
            return {0, 0, "1\n"};
        },
        acc);
    REQUIRE(rows.size() == kLinuxAllowlist.size());
    CHECK(state_of(rows, "kernel.sysrq") == PostureState::unreadable);
    CHECK(raw_of(rows, "kernel.sysrq") == "-");
    CHECK(acc.reason() == "kernel.sysrq:not_regular");
    const auto s = select_status(acc, any_denied(rows));
    CHECK(s.status == YUZU_RESULT_STATUS_CONSTRAINED);
    CHECK(s.provenance == "kernel.sysrq:not_regular");
}

// Fails under: cutting a Linux value at its first line again (a forged "2\n0" would read as a
// clean `enabled` on its first line), or trimming a kernel-emitted "N\n" differently.
TEST_CASE("system_hardening: a Linux value is judged whole, never on its first line",
          "[system_hardening][mapper]") {
    CHECK(trimmed_value("2\n") == "2");
    CHECK(trimmed_value(" \t2\r\n\0"sv) == "2");
    CHECK(trimmed_value("2\n0") == "2\n0");
    CHECK(evaluate_linux("kernel.randomize_va_space", "2\n") == PostureState::enabled);
    CHECK(evaluate_linux("kernel.randomize_va_space", "2\n0\n") == PostureState::unmodelled);
    ConstraintAccumulator acc;
    const auto rows = collect_linux_posture(
        [](std::string_view path) -> ReadOutcome {
            if (path == "/proc/sys/kernel/randomize_va_space") return {0, 0, "2\n0\n"};
            return {0, 0, "1\n"};
        },
        acc);
    CHECK(state_of(rows, "kernel.randomize_va_space") == PostureState::unmodelled);
    CHECK(raw_of(rows, "kernel.randomize_va_space") == "2\n0");
    CHECK(raw_of(rows, "kernel.kptr_restrict") == "1"); // a kernel-emitted value trims as before
}

// Fails under: judging kern.bootargs emptiness on its first line (a leading newline or NUL hides
// every override behind a clean `enabled`), or dropping the value after that first line from the
// raw column.
TEST_CASE("system_hardening: kern.bootargs is judged and emitted whole",
          "[system_hardening][mapper]") {
    using P = PostureState;
    const std::string long_ws_then_v = std::string(1024, ' ') + "\n\t" + "-v";
    struct C {
        std::string raw;
        P want;
    };
    const C cases[] = {
        {"", P::enabled},
        {" \n\t  \r\n", P::enabled},          // whitespace only: still no overrides
        {std::string{"\0\0", 2}, P::enabled}, // NULs only
        {"\n-v", P::unmodelled},
        {"\namfi_get_out_of_my_way=1", P::unmodelled},
        {std::string{"\0-v", 3}, P::unmodelled},
        {long_ws_then_v, P::unmodelled},
        {"-v\n", P::unmodelled},
    };
    for (const auto& c : cases) {
        INFO("raw size " << c.raw.size());
        CHECK(evaluate_macos_string("kern.bootargs", c.raw) == c.want);

        ConstraintAccumulator acc;
        const auto rows = collect_macos_posture(
            [&](std::string_view, SysctlKind kind) -> ReadOutcome {
                if (kind == SysctlKind::string) return {0, 0, c.raw};
                return {0, 0, {}};
            },
            acc);
        CHECK(state_of(rows, "kern.bootargs") == c.want);
        CHECK(raw_of(rows, "kern.bootargs") == c.raw); // the whole value, untrimmed
        CHECK_FALSE(acc.any_failure());

        // The emitted row keeps all five fields: newlines and NULs never split or cut it.
        std::string row;
        for (const auto& r : rows)
            if (r.key == "kern.bootargs") row = format_posture_row(r);
        CHECK(row.find('\0') == std::string::npos);
        CHECK(row.find('\n') == std::string::npos);
        CHECK(std::count(row.begin(), row.end(), '|') == 4);
        CHECK(row.ends_with(std::string{"|"} + std::string{state_token(c.want)}));
    }
    // The override after the leading newline reaches the raw column.
    CHECK(format_posture_row({"macos", "kern.bootargs", "\n-v", P::unmodelled}) ==
          "posture|macos|kern.bootargs| -v|unmodelled");
    CHECK(format_posture_row({"macos", "kern.bootargs", std::string{"\0-v", 3}, P::unmodelled}) ==
          "posture|macos|kern.bootargs| -v|unmodelled");
}

// Fails under: a hidden /proc/sys (what the Linux leg hands the pure layer after the surface
// check) reading as absent/OK, losing a per-key token, or double-reporting via the canary.
TEST_CASE("system_hardening: a hidden /proc/sys is eleven unreadable rows, never absent/OK",
          "[system_hardening][collect]") {
    ConstraintAccumulator acc;
    const auto rows = collect_linux_posture(
        [](std::string_view) { return ReadOutcome{remap_enoent_for_surface(ENOENT, false), 0, {}}; },
        acc);
    REQUIRE(rows.size() == kLinuxAllowlist.size());
    for (const auto& r : rows) {
        INFO(r.key);
        CHECK(r.state == PostureState::unreadable);
        CHECK(r.raw == "-");
        CHECK(has_token_for(acc, r.key));
    }
    CHECK(acc.reason().find(std::string{kLinuxAllowlist[0].key} + ":errno_" +
                            std::to_string(ENODEV)) != std::string::npos);
    CHECK(acc.reason().find("proc_sys:not_visible") == std::string::npos); // canary not needed
    CHECK(select_status(acc, any_denied(rows)).status == YUZU_RESULT_STATUS_CONSTRAINED);
}

TEST_CASE("system_hardening: a mixed absent + EACCES run reports exactly the EACCES token",
          "[system_hardening][collect]") {
    auto reader = [](std::string_view path) -> ReadOutcome {
        if (path == "/proc/sys/kernel/yama/ptrace_scope") return {ENOENT, 0, {}};
        if (path == "/proc/sys/kernel/kptr_restrict") return {EACCES, 0, {}};
        return {0, 0, "1\n"};
    };
    ConstraintAccumulator acc;
    const auto rows = collect_linux_posture(reader, acc);
    REQUIRE(rows.size() == kLinuxAllowlist.size());
    CHECK(state_of(rows, "kernel.yama.ptrace_scope") == PostureState::absent);
    CHECK(state_of(rows, "kernel.kptr_restrict") == PostureState::unreadable);
    CHECK(acc.any_failure()); // PERMISSION_DENIED/PARTIAL, because of the EACCES key alone
    CHECK(acc.reason() == "kernel.kptr_restrict:eacces");
}

TEST_CASE("system_hardening: a later successful read never erases an earlier failure",
          "[system_hardening][collect]") {
    auto reader = [](std::string_view path) -> ReadOutcome {
        if (path == "/proc/sys/kernel/randomize_va_space") return {EACCES, 0, {}}; // FIRST key fails
        return {0, 0, "1\n"};
    };
    ConstraintAccumulator acc;
    const auto rows = collect_linux_posture(reader, acc);
    REQUIRE(rows.size() == kLinuxAllowlist.size());
    CHECK(state_of(rows, "kernel.randomize_va_space") == PostureState::unreadable);
    CHECK(acc.reason() == "kernel.randomize_va_space:eacces");
}

TEST_CASE("system_hardening: an all-values Linux read adds no failure token and stays in allowlist order",
          "[system_hardening][collect]") {
    ConstraintAccumulator acc;
    const auto rows = collect_linux_posture([](std::string_view) { return ReadOutcome{0, 0, "1\n"}; }, acc);
    REQUIRE(rows.size() == kLinuxAllowlist.size());
    CHECK_FALSE(acc.any_failure());
    for (std::size_t i = 0; i < rows.size(); ++i) CHECK(rows[i].key == kLinuxAllowlist[i].key);
}

TEST_CASE("system_hardening: macOS collect classifies ENOENT/EPERM and treats empty bootargs as a value",
          "[system_hardening][collect]") {
    auto reader = [](std::string_view name, SysctlKind kind) -> ReadOutcome {
        if (name == "kern.securelevel") return {ENOENT, 0, {}};
        if (name == "kern.coredump") return {EPERM, 0, {}};
        if (kind == SysctlKind::string) return {0, 0, std::string{}}; // empty bootargs: success
        return {0, 1, {}};
    };
    ConstraintAccumulator acc;
    const auto rows = collect_macos_posture(reader, acc);
    REQUIRE(rows.size() == kMacosAllowlist.size());
    CHECK(state_of(rows, "kern.securelevel") == PostureState::absent);
    CHECK(state_of(rows, "kern.coredump") == PostureState::unreadable);
    CHECK(state_of(rows, "kern.sugid_coredump") == PostureState::disabled);
    CHECK(state_of(rows, "kern.bootargs") == PostureState::enabled);
    CHECK(raw_of(rows, "kern.bootargs").empty()); // read-and-empty, not "-"
    // The absent key (securelevel) and the empty bootargs add nothing: the EPERM key is the only token.
    CHECK(acc.reason() == "kern.coredump:eacces");
}

// ── status selection ─────────────────────────────────────────────────────

TEST_CASE("system_hardening: select_status -- no token is OK/FULL, any token CONSTRAINED, and a "
          "denial outranks every other cause",
          "[system_hardening][status]") {
    ConstraintAccumulator none;
    const auto ok = select_status(none, false);
    CHECK(ok.status == YUZU_RESULT_STATUS_OK);
    CHECK(ok.completeness == YUZU_RESULT_COMPLETENESS_FULL);
    CHECK(ok.provenance.empty());

    ConstraintAccumulator failed;
    failed.add_failure("k:errno_5");
    const auto constrained = select_status(failed, false);
    CHECK(constrained.status == YUZU_RESULT_STATUS_CONSTRAINED);
    CHECK(constrained.completeness == YUZU_RESULT_COMPLETENESS_PARTIAL);
    CHECK(constrained.provenance == "k:errno_5");

    ConstraintAccumulator refused;
    refused.add_failure("k:eacces");
    const auto denied = select_status(refused, true);
    CHECK(denied.status == YUZU_RESULT_STATUS_PERMISSION_DENIED);
    CHECK(denied.completeness == YUZU_RESULT_COMPLETENESS_PARTIAL);
    CHECK(denied.provenance == "k:eacces");

    // A denial outranks another unreadable cause in the same run; both tokens stay in the reason.
    ConstraintAccumulator both;
    both.add_failure("a:eacces");
    both.add_failure("b:errno_5");
    const auto outranks = select_status(both, true);
    CHECK(outranks.status == YUZU_RESULT_STATUS_PERMISSION_DENIED);
    CHECK(outranks.provenance == "a:eacces,b:errno_5");
}

TEST_CASE("system_hardening: is_denied_errno is EACCES/EPERM only; any_denied reads row errnos",
          "[system_hardening][status]") {
    CHECK(is_denied_errno(EACCES));
    CHECK(is_denied_errno(EPERM));
    for (const int err : {ENOENT, EIO, EINVAL, 0})
        CHECK_FALSE(is_denied_errno(err));

    ConstraintAccumulator acc;
    const auto mixed = collect_linux_posture(
        [](std::string_view path) -> ReadOutcome {
            if (path == "/proc/sys/kernel/kptr_restrict") return {EACCES, 0, {}};
            if (path == "/proc/sys/kernel/yama/ptrace_scope") return {ENOENT, 0, {}};
            return {0, 0, "1\n"};
        },
        acc);
    CHECK(any_denied(mixed));

    ConstraintAccumulator values_acc;
    const auto values = collect_linux_posture(
        [](std::string_view) { return ReadOutcome{0, 0, "1\n"}; }, values_acc);
    CHECK_FALSE(any_denied(values));

    // Absence is never a denial.
    ConstraintAccumulator absent_acc;
    const auto absent = collect_linux_posture(
        [](std::string_view) { return ReadOutcome{ENOENT, 0, {}}; }, absent_acc);
    CHECK_FALSE(any_denied(absent));

    // The macOS collector carries the errno the same way.
    ConstraintAccumulator mac_acc;
    const auto mac = collect_macos_posture(
        [](std::string_view name, SysctlKind) -> ReadOutcome {
            if (name == "kern.coredump") return {EPERM, 0, {}};
            return {0, 1, "x"};
        },
        mac_acc);
    CHECK(any_denied(mac));
}

// ── REAL CAPTURE fixtures ────────────────────────────────────────────────

TEST_CASE("system_hardening: REAL CAPTURE docker debian:12 /proc/sys reads",
          "[system_hardening][fixture]") {
    ConstraintAccumulator acc;
    const auto rows = collect_linux_posture(
        linux_reader_over(load_fixture("linux", "proc_sys_debian12.txt")), acc);
    REQUIRE(rows.size() == kLinuxAllowlist.size());
    using P = PostureState;
    CHECK(state_of(rows, "kernel.randomize_va_space") == P::enabled);
    CHECK(state_of(rows, "kernel.kptr_restrict") == P::disabled);
    CHECK(state_of(rows, "kernel.dmesg_restrict") == P::enabled);
    CHECK(state_of(rows, "kernel.unprivileged_bpf_disabled") == P::disabled);
    CHECK(state_of(rows, "kernel.sysrq") == P::disabled); // value 1
    CHECK(state_of(rows, "fs.protected_hardlinks") == P::enabled);
    CHECK(state_of(rows, "fs.protected_fifos") == P::disabled);
    CHECK(state_of(rows, "fs.suid_dumpable") == P::enabled);
    // Yama is genuinely not built into this kernel: the real ENOENT case. It is `absent`, and
    // absence is not a failure: this whole real-capture host reads with no token (OK/FULL).
    CHECK(state_of(rows, "kernel.yama.ptrace_scope") == P::absent);
    CHECK(raw_of(rows, "kernel.yama.ptrace_scope") == "-");
    CHECK_FALSE(acc.any_failure());
    CHECK(acc.reason().empty());
}

TEST_CASE("system_hardening: REAL CAPTURE this Mac's sysctl reads (empty bootargs, kern.nx unknown oid)",
          "[system_hardening][fixture]") {
    const auto fx = load_fixture("macos", "sysctl_posture_macos26.txt");
    auto reader = [&](std::string_view name, SysctlKind kind) -> ReadOutcome {
        const auto it = fx.find(std::string{name});
        if (it == fx.end()) return {ENOENT, 0, {}};
        if (!it->second.ok) return {errno_of(it->second.text), 0, {}};
        if (kind == SysctlKind::integer) return {0, std::stoll(it->second.text), {}};
        return {0, 0, it->second.text};
    };
    ConstraintAccumulator acc;
    const auto rows = collect_macos_posture(reader, acc);
    REQUIRE(rows.size() == kMacosAllowlist.size());
    CHECK(state_of(rows, "kern.securelevel") == PostureState::disabled); // 0
    CHECK(state_of(rows, "kern.coredump") == PostureState::disabled);    // 1
    CHECK(state_of(rows, "kern.sugid_coredump") == PostureState::enabled); // 0
    CHECK(state_of(rows, "kern.bootargs") == PostureState::enabled);     // empty string, a real read
    CHECK_FALSE(acc.any_failure()); // an empty bootargs is not a failure
    // The captured `sysctl: unknown oid 'kern.nx'` is ENOENT -> absent (kern.nx is why it was dropped).
    const auto nx = fx.at("kern.nx");
    REQUIRE_FALSE(nx.ok);
    CHECK(classify_read_errno(errno_of(nx.text)) == PostureState::absent);
    // ...and, being absent, it carries no reason token.
    CHECK_FALSE(failure_token("kern.nx", errno_of(nx.text)).has_value());
    ConstraintAccumulator nx_acc;
    const auto nx_row = failed_row("macos", "kern.nx", errno_of(nx.text), nx_acc);
    CHECK(nx_row.state == PostureState::absent);
    CHECK(nx_row.raw == "-");
    CHECK_FALSE(nx_acc.any_failure());
}

TEST_CASE("system_hardening: RECONSTRUCTION malformed values map to unmodelled, never a guess",
          "[system_hardening][fixture]") {
    ConstraintAccumulator acc;
    const auto rows =
        collect_linux_posture(linux_reader_over(load_fixture("linux", "proc_sys_malformed.txt")), acc);
    REQUIRE(rows.size() == kLinuxAllowlist.size());
    CHECK(state_of(rows, "kernel.randomize_va_space") == PostureState::unmodelled); // "banana"
    CHECK(state_of(rows, "kernel.kptr_restrict") == PostureState::unmodelled);      // 7
    CHECK(state_of(rows, "kernel.sysrq") == PostureState::unmodelled);              // empty file
    CHECK(state_of(rows, "fs.protected_fifos") == PostureState::unmodelled);        // overflow
    CHECK(raw_of(rows, "kernel.randomize_va_space") == "banana"); // the raw is still reported
    // Unmodelled values and the keys this fixture omits (ENOENT -> absent) are not failures.
    CHECK(state_of(rows, "kernel.yama.ptrace_scope") == PostureState::absent);
    CHECK_FALSE(acc.any_failure());
}

TEST_CASE("system_hardening internal-error row has the published five fields",
          "[system_hardening][parsers]") {
    for (const std::string_view os : {"linux", "macos", "windows"}) {
        const std::string row = format_internal_error_row(os);
        INFO("row: " << row);
        CHECK(row == "constrained|" + std::string{os} + "|internal_error|-|unreadable");
        CHECK(std::count(row.begin(), row.end(), '|') == 4); // five fields, like a posture row
    }
}
