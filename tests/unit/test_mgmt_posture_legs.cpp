/**
 * test_mgmt_posture_legs.cpp -- fault tests for the OS-free `posture_linux` / `posture_macos`:
 * every boundary is a canned fake (no disk, no spawn, no uid dependence). Provenance: the
 * unenrolled `profiles` text is a REAL capture; every other specimen is SYNTHETIC.
 */
#include <catch2/catch_test_macros.hpp>

#include "mgmt_posture_legs.hpp"

#include <algorithm>
#include <map>
#include <string>
#include <vector>

using namespace yuzu::mgmt_posture;
using namespace yuzu::agent;

namespace {

ReadResult ok(std::string text) { return {std::move(text), 0}; }
/// A string literal with embedded NULs, length taken from the array (no hand-counted size).
template <std::size_t N> std::string nul_text(const char (&lit)[N]) { return std::string(lit, N - 1); }
ReadResult fail(int err) { return {{}, err}; }
constexpr const char* kSnippet = "/etc/sssd/conf.d/10-b.conf";
constexpr const char* kTwoDomains = "[sssd]\ndomains = a\n[domain/a]\nid_provider = ad\n"
                                    "[domain/b]\nid_provider = ipa\n";
constexpr const char* kUnenrolled = "Enrolled via DEP: No\nMDM enrollment: No\n";

/// Canned Linux boundaries; a path missing from `files` reads as ENOENT.
struct FakeFs {
    std::map<std::string, ReadResult> files;
    int list_err = ENOENT; // no conf.d
    std::vector<std::string> names;
    bool too_many = false;
    int keytab = ENOENT;
    std::vector<std::string> reads; // every path `read` was asked for

    Posture run() {
        const LinuxFs fs{
            [this](const std::string& p) {
                reads.push_back(p);
                const auto it = files.find(p);
                return it == files.end() ? fail(ENOENT) : it->second;
            },
            [this](std::vector<std::string>& n, bool& tm) {
                n = names;
                tm = too_many;
                return list_err;
            },
            [this] { return keytab; },
        };
        const Posture p = posture_linux(fs);
        // L7: the keytab holds key material; it is probed, never read (checked on every run).
        CHECK(std::ranges::find(reads, std::string{kKeytab}) == reads.end());
        return p;
    }
};

bool has(const Posture& p, const std::string& row) {
    return std::ranges::find(p.rows, row) != p.rows.end();
}
void expect(const Posture& p, StatusState s, const std::string& token) {
    CHECK(p.status == s);
    CHECK(p.reason.find(token) != std::string::npos);
}
/// A constrained macOS run: exactly this reason token and NO data rows.
void check_constrained(const Posture& p, const std::string& token) {
    CHECK(p.status == StatusState::constrained);
    CHECK(p.reason == token);
    CHECK(p.rows.empty());
}

struct FakeRun { // records what posture_macos asked for, returns a fixed result
    SubprocessResult res;
    std::vector<std::string> argv;
    SubprocessOptions opts;

    Posture run() {
        return posture_macos([this](const std::vector<std::string>& a, const SubprocessOptions& o) {
            argv = a;
            opts = o;
            return res;
        });
    }
};

FakeRun exited(int code, std::string out) {
    FakeRun f;
    f.res.tool_ran = true;
    f.res.exit_code = code;
    f.res.termination_reason = TerminationReason::exited;
    f.res.output = std::move(out);
    return f;
}

} // namespace

TEST_CASE("L1 refused sssd.conf is permission_denied/unknown, never absent", "[mgmt_posture]") {
    FakeFs f;
    f.files[kSssdConf] = fail(EACCES);
    const auto p = f.run();
    expect(p, StatusState::permission_denied, "linux:mgmt_posture:sssd_conf:permission_denied");
    CHECK(has(p, "plane|unknown"));
}

TEST_CASE("L2 refused conf.d listing or snippet is permission_denied/unknown", "[mgmt_posture]") {
    FakeFs listing;
    listing.list_err = EACCES;
    FakeFs snippet;
    snippet.list_err = 0;
    snippet.names = {"10-b.conf"};
    snippet.files[kSnippet] = fail(EPERM);
    for (FakeFs* f : {&listing, &snippet}) {
        const auto p = f->run();
        expect(p, StatusState::permission_denied, "linux:mgmt_posture:sssd_conf_d:permission_denied");
        CHECK(has(p, "plane|unknown"));
    }
}

TEST_CASE("L3 a conf.d readdir error is constrained, not a clean absent", "[mgmt_posture]") {
    FakeFs f;
    f.list_err = EIO;
    expect(f.run(), StatusState::constrained, "linux:mgmt_posture:sssd_conf_d:eio");
}

TEST_CASE("L3b a failed conf.d listing reads none of the names it returned", "[mgmt_posture]") {
    // MUTATION: dropping the clear lets an unsorted, uncapped partial list (up to 4096 names of
    // up to 64 KiB each) be read and merged after the listing failed.
    FakeFs f;
    f.list_err = EIO;
    for (int i = 0; i < 40; ++i)
        f.names.push_back("snip" + std::to_string(i) + ".conf");
    const auto p = f.run();
    expect(p, StatusState::constrained, "linux:mgmt_posture:sssd_conf_d:eio");
    CHECK(std::ranges::none_of(f.reads, [](const std::string& r) {
        return r.find("snip") != std::string::npos;
    }));
}

TEST_CASE("L3c a failed read of sssd.conf is constrained with plane unknown, never none",
          "[mgmt_posture]") {
    // MUTATION: dropping config_read_failed reports `plane|none` (unmanaged) beside CONSTRAINED.
    for (int err : {EIO, EMFILE, ENOTDIR, kErrNotRegular, kErrOversized}) {
        FakeFs f;
        f.files[kSssdConf] = fail(err);
        const auto p = f.run();
        CHECK(p.status == StatusState::constrained);
        CHECK(has(p, "plane|unknown"));
    }
}

TEST_CASE("L3g a failed conf.d listing or snippet with nothing else found is plane unknown",
          "[mgmt_posture]") {
    // MUTATION: matching only the exact part name "sssd_conf" leaves `plane|none` for these.
    FakeFs listing;
    listing.list_err = EIO;
    CHECK(has(listing.run(), "plane|unknown"));
    FakeFs snippet;
    snippet.list_err = 0;
    snippet.names = {"10-a.conf"};
    snippet.files["/etc/sssd/conf.d/10-a.conf"] = fail(EIO);
    CHECK(has(snippet.run(), "plane|unknown"));
    FakeFs ipa;
    ipa.files[kIpaConf] = fail(EIO);
    CHECK(has(ipa.run(), "plane|unknown"));
}

TEST_CASE("L3h an AD domain positively found keeps plane ad when a snippet read failed",
          "[mgmt_posture]") {
    FakeFs f;
    f.files[kSssdConf] = ok("[sssd]\ndomains = corp\n[domain/corp]\nid_provider = ad\n");
    f.list_err = 0;
    f.names = {"10-a.conf"};
    f.files["/etc/sssd/conf.d/10-a.conf"] = fail(EIO);
    const auto p = f.run();
    CHECK(p.status == StatusState::constrained);
    CHECK(has(p, "plane|ad"));
}

TEST_CASE("L3i a refusal combined with another failure stays permission_denied and keeps both tokens",
          "[mgmt_posture]") {
    FakeFs f;
    f.files[kSssdConf] = fail(EACCES);
    f.keytab = EIO;
    const auto p = f.run();
    CHECK(p.status == StatusState::permission_denied);
    CHECK(p.reason.find("linux:mgmt_posture:sssd_conf:permission_denied") != std::string::npos);
    CHECK(p.reason.find("linux:mgmt_posture:krb5_keytab:eio") != std::string::npos);
    CHECK(has(p, "plane|unknown"));
}

TEST_CASE("L3d two refused snippets name the token once", "[mgmt_posture]") {
    FakeFs f;
    f.list_err = 0;
    f.names = {"10-a.conf", "20-b.conf"};
    f.files["/etc/sssd/conf.d/10-a.conf"] = fail(EACCES);
    f.files["/etc/sssd/conf.d/20-b.conf"] = fail(EACCES);
    const auto p = f.run();
    CHECK(p.status == StatusState::permission_denied);
    CHECK(p.reason == "linux:mgmt_posture:sssd_conf_d:permission_denied");
}

TEST_CASE("L3e IPA realm alone, and a conf.d-only AD snippet, reach the plane row",
          "[mgmt_posture]") {
    // MUTATION: hard-coding ipa_present=false or sssd_present=false keeps every other case green.
    FakeFs ipa;
    ipa.files[kIpaConf] = ok("[global]\nrealm = IPA.EXAMPLE.COM\n");
    const auto p1 = ipa.run();
    CHECK(p1.status == StatusState::supported);
    CHECK(has(p1, "plane|ipa"));

    FakeFs snip;
    snip.list_err = 0;
    snip.names = {"10-ad.conf"};
    snip.files["/etc/sssd/conf.d/10-ad.conf"] =
        ok("[sssd]\ndomains = corp\n[domain/corp]\nid_provider = ad\n");
    const auto p2 = snip.run();
    CHECK(p2.status == StatusState::supported);
    CHECK(has(p2, "plane|ad"));
}

TEST_CASE("L3f an IPA default.conf with an embedded NUL is constrained, never a clean none",
          "[mgmt_posture]") {
    // MUTATION: dropping the NUL check reports `supported` + `plane|none` for a corrupt file.
    FakeFs f;
    f.files[kIpaConf] = ok(nul_text("[global]\nrealm = IPA\0.EXAMPLE.COM\n"));
    expect(f.run(), StatusState::constrained, "linux:mgmt_posture:ipa_default_conf:invalid_bytes");
}

TEST_CASE("L4 too many snippets is constrained", "[mgmt_posture]") {
    FakeFs f;
    f.list_err = 0;
    f.too_many = true;
    expect(f.run(), StatusState::constrained, "linux:mgmt_posture:sssd_conf_d:too_many");
}
TEST_CASE("L5 a non-regular sssd.conf (FIFO, directory) is constrained", "[mgmt_posture]") {
    FakeFs f;
    f.files[kSssdConf] = fail(kErrNotRegular);
    expect(f.run(), StatusState::constrained, "linux:mgmt_posture:sssd_conf:not_regular");
}

TEST_CASE("L6 keytab presence is probed; an unknown probe is constrained", "[mgmt_posture]") {
    FakeFs f;
    f.keytab = 0;
    CHECK(has(f.run(), "krb5_keytab|present"));
    f.keytab = ENOENT;
    CHECK(has(f.run(), "krb5_keytab|absent"));
    f.keytab = EIO;
    const auto p = f.run();
    CHECK(has(p, "krb5_keytab|-"));
    expect(p, StatusState::constrained, "linux:mgmt_posture:krb5_keytab:eio");
    // A refusal elsewhere must not drop the keytab token on the early return.
    f.files[kSssdConf] = fail(EACCES);
    const auto both = f.run();
    expect(both, StatusState::permission_denied, "linux:mgmt_posture:sssd_conf:permission_denied");
    expect(both, StatusState::permission_denied, "linux:mgmt_posture:krb5_keytab:eio");
}

TEST_CASE("L7 the keytab path is never handed to the reader", "[mgmt_posture]") {
    FakeFs f; // run() also CHECKs this in every other case
    f.keytab = 0;
    f.files[kSssdConf] = ok(kTwoDomains);
    f.run();
    CHECK(f.reads == std::vector<std::string>{kSssdConf, kIpaConf});
}

TEST_CASE("L8 nothing present is a clean supported none", "[mgmt_posture]") {
    FakeFs f;
    const auto p = f.run();
    CHECK(p.status == StatusState::supported);
    CHECK(format_status_row(p.status, p.reason) == "status|posture|supported|-");
    CHECK(has(p, "plane|none"));
    CHECK(has(p, "krb5_keytab|absent"));
}

TEST_CASE("L9 sssd.conf without [sssd] domains is constrained, rows kept", "[mgmt_posture]") {
    FakeFs f;
    f.files[kSssdConf] = ok("[sssd]\nservices = nss, pam\n");
    const auto p = f.run();
    expect(p, StatusState::constrained, "linux:mgmt_posture:sssd_conf:no_domains_key");
    CHECK(p.rows.size() == 5);
}

TEST_CASE("L9b an sssd.conf with an embedded NUL is constrained, never a clean none",
          "[mgmt_posture]") {
    // MUTATION: dropping the NUL check reports `supported` + `plane|none` for a corrupt file.
    FakeFs f;
    f.files[kSssdConf] = ok(nul_text("[sssd]\ndomains = corp\0junk\n"));
    const auto p = f.run();
    expect(p, StatusState::constrained, "linux:mgmt_posture:sssd_conf:invalid_bytes");
    CHECK(p.rows.size() == 5);
}

TEST_CASE("L10 a refused IPA default.conf is only constrained", "[mgmt_posture]") {
    FakeFs f;
    f.files[kIpaConf] = fail(EACCES);
    expect(f.run(), StatusState::constrained, "linux:mgmt_posture:ipa_default_conf:permission_denied");
}

TEST_CASE("L11 a conf.d snippet overrides the main file (last wins)", "[mgmt_posture]") {
    FakeFs f;
    f.files[kSssdConf] = ok(kTwoDomains);
    CHECK(has(f.run(), "plane|ad")); // control: the main file alone names domain a (AD)
    f.list_err = 0;
    f.names = {"10-b.conf"};
    f.files[kSnippet] = ok("[sssd]\ndomains = b\n");
    CHECK(has(f.run(), "plane|ipa")); // the snippet's `domains = b` (IPA) wins
}

TEST_CASE("M1 profiles is run with the exact argv and bounds", "[mgmt_posture]") {
    auto f = exited(0, kUnenrolled);
    f.run();
    CHECK(f.argv == std::vector<std::string>{"/usr/bin/profiles", "status", "-type", "enrollment"});
    CHECK(f.opts.deadline == std::chrono::milliseconds{5000});
    CHECK(f.opts.max_lines == 16);
    CHECK(f.opts.output_cap_bytes == 16 * 1024);
    CHECK_FALSE(f.opts.merge_stderr);
}

TEST_CASE("M1b a DEP-only output is unrecognised, never a supported row with mdm_enrolled -",
          "[mgmt_posture]") {
    // MUTATION: accepting a DEP-only text reports `supported` with `mdm_enrolled|-`.
    auto f = exited(0, "Enrolled via DEP: Yes\n");
    check_constrained(f.run(), "macos:mgmt_posture:profiles:unrecognised_output");
}

TEST_CASE("M2 spawn failure is unsupported with the runner's token and no rows", "[mgmt_posture]") {
    // The shared classifier reports a spawn failure as UNAVAILABLE (nothing was read) and the
    // sibling plugins forward it; CONSTRAINED would claim a partial read that never happened.
    FakeRun f;
    f.res.termination_reason = TerminationReason::spawn_error;
    f.res.tool_ran = false;
    const auto p = f.run();
    CHECK(p.status == StatusState::unsupported);
    CHECK(p.reason == "subprocess_runner:spawn_error");
    CHECK(p.rows.empty());
}

TEST_CASE("M2b the other runner failures stay constrained with no rows", "[mgmt_posture]") {
    // cancelled, signaled and line_limit ran the tool, so the read is partial, not unavailable.
    // The output is parseable on purpose: the runner failure must win over a recognisable answer.
    struct Case {
        TerminationReason why;
        const char* token;
    };
    const Case cases[] = {{TerminationReason::cancelled, "subprocess_runner:cancelled"},
                          {TerminationReason::signaled, "subprocess_runner:signaled"},
                          {TerminationReason::line_limit, "subprocess_runner:line_limit"}};
    for (const auto& c : cases) {
        INFO(c.token);
        auto f = exited(0, kUnenrolled);
        f.res.termination_reason = c.why;
        check_constrained(f.run(), c.token);
    }
}

TEST_CASE("M3 a deadline is constrained with no rows", "[mgmt_posture]") {
    auto f = exited(-1, {});
    f.res.termination_reason = TerminationReason::deadline;
    f.res.timed_out = true;
    check_constrained(f.run(), "subprocess_runner:deadline");
}

TEST_CASE("M4 a nonzero exit is constrained with no rows", "[mgmt_posture]") {
    auto f = exited(1, kUnenrolled);
    check_constrained(f.run(), "macos:mgmt_posture:profiles:exit_nonzero");
}

TEST_CASE("M5 truncated output is constrained with no rows", "[mgmt_posture]") {
    auto f = exited(0, kUnenrolled);
    f.res.output_truncated = true;
    check_constrained(f.run(), "macos:mgmt_posture:profiles:output_truncated");
}

TEST_CASE("M6 unrecognised output is constrained, never an empty success", "[mgmt_posture]") {
    auto f = exited(0, "garbage\n");
    check_constrained(f.run(), "macos:mgmt_posture:profiles:unrecognised_output");
}

TEST_CASE("M7 the real unenrolled capture is supported with four rows", "[mgmt_posture]") {
    auto f = exited(0, kUnenrolled);
    const auto p = f.run();
    CHECK(p.status == StatusState::supported);
    CHECK(p.reason.empty());
    CHECK(p.rows == std::vector<std::string>{"plane|-", "mdm_enrolled|false", "mdm_provider|-", "tenant_id|-"});
}
