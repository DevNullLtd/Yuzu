/**
 * test_license_scan_surfaces.cpp -- the per-OS surface "shells" of the
 * license_scan plugin (SAM.10), driven through a controlled ProbeHost.
 *
 * The pure seams (licensing_x509.hpp, licensing_bplist.hpp,
 * entitlement_certs_outcome) have their own suites; what those cannot prove is
 * the WIRING: that bytes become authoritative rows, that the caps and the
 * start gate sit where the plan says, that a refusal reaches the outcome and
 * that the macOS receipt row carries the decoded identity. These tests call
 * run_entitlement_certs_surface (Linux) and run_mas_receipt_surface (macOS)
 * directly. Each is compiled only on its own OS (licensing_probes.hpp declares
 * them under #ifdef), so the Linux cases run on a Linux lane and the macOS
 * cases on a Mac; this TU is empty elsewhere.
 *
 * FakeProbeHost RECORDS every path, cap and entry limit it is asked for: an
 * argument-blind fake would stay green if the shell read the wrong path, passed
 * the wrong cap or listed with the wrong limit. It also honours the real
 * contract of the primitives it replaces (a file over the cap is `oversized`,
 * never truncated data; a listing over the limit is `truncated`), so the cap
 * boundaries below are exact: one byte or one entry past the cap flips the
 * result. Time is injected (now_steady / now_epoch); nothing sleeps and nothing
 * touches the real filesystem except the three committed macOS Info.plist
 * fixtures, which are read once to be served to the shell.
 *
 * Certificates: kCertA/B/C are the self-signed P-256 vectors of
 * test_licensing_x509.cpp (provenance recorded there): notAfter 2027-03-04
 * (wire 1804118400), 2028-12-31 (1861833600) and 2026-01-01 (1767225600).
 * The macOS cases serve the real Info.plist captures documented in
 * tests/unit/fixtures/software-estate/license_scan/macos/README.md.
 */

#include <catch2/catch_test_macros.hpp>

#include "licensing_parsers.hpp"
#include "licensing_probes.hpp"

#if defined(__linux__) || defined(__APPLE__)

#include <cerrno>
#include <chrono>
#include <cstddef>
#include <filesystem>
#include <fstream>
#include <iterator>
#include <map>
#include <optional>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

namespace fs = std::filesystem;
using namespace yuzu::license_scan;

namespace {

using Clock = std::chrono::steady_clock;

class FakeProbeHost final : public ProbeHost {
public:
    struct FileEntry {
        std::string data;
        int err = 0; // != 0: the read fails with this errno and no data
    };
    struct Read {
        std::string path;
        std::size_t cap;
    };
    struct Listing {
        std::string path;
        std::size_t max_entries;
    };

    // canned model
    std::map<std::string, DirListing> dirs;
    std::map<std::string, FileEntry> files;
    std::vector<std::string> glob_matches;
    long long epoch = 1793016000; // 2026-10-26 12:00:00 UTC
    Clock::time_point clock = Clock::time_point{} + std::chrono::hours(1);
    Clock::duration advance_per_read{0}; // injected clock: each read costs this much "time"

    // recorded
    std::vector<Read> reads;
    std::vector<Listing> listings;
    std::vector<std::string> globs;
    std::vector<std::string> prefix_reads;

    std::vector<std::string> glob(std::string_view pattern) override {
        globs.emplace_back(pattern);
        return glob_matches;
    }

    std::optional<std::string> read_file_prefix(std::string_view path, std::size_t) override {
        prefix_reads.emplace_back(path); // neither surface under test may use the lossy reader
        return std::nullopt;
    }

    CappedRead read_file_capped(std::string_view path, std::size_t cap) override {
        reads.push_back({std::string(path), cap});
        clock += advance_per_read;
        CappedRead out;
        const auto it = files.find(std::string(path));
        if (it == files.end()) {
            out.err = ENOENT;
        } else if (it->second.err != 0) {
            out.err = it->second.err;
        } else if (it->second.data.size() > cap) {
            out.oversized = true; // the real primitive never returns a truncated read
        } else {
            out.data = it->second.data;
        }
        return out;
    }

    DirListing list_dir(std::string_view path, std::size_t max_entries) override {
        listings.push_back({std::string(path), max_entries});
        const auto it = dirs.find(std::string(path));
        if (it == dirs.end()) {
            DirListing missing;
            missing.err = ENOENT;
            return missing;
        }
        DirListing out = it->second;
        if (out.err == 0 && out.names.size() > max_entries) {
            out.names.resize(max_entries);
            out.truncated = true; // an entry exists beyond the budget (the real contract)
        }
        return out;
    }

    long long now_epoch() override { return epoch; }
    Clock::time_point now_steady() override { return clock; }
};

struct Run {
    std::vector<LicRecord> records;
    std::vector<ProbeOutcome> outcomes;
};

} // namespace

#ifdef __linux__

// ── Linux: run_entitlement_certs_surface ────────────────────────────────────

namespace {

constexpr const char* kCertA = R"(-----BEGIN CERTIFICATE-----
MIIBejCCAR+gAwIBAgIUErPFZG+tXlGd7jAGQUOJxOYYL+MwCgYIKoZIzj0EAwIw
EjEQMA4GA1UEAwwHc2FtMTAtYTAeFw0yNTAxMDEwMDAwMDBaFw0yNzAzMDQxMjAw
MDBaMBIxEDAOBgNVBAMMB3NhbTEwLWEwWTATBgcqhkjOPQIBBggqhkjOPQMBBwNC
AAS7cbHHKFc0DycuXJcynDgJkXpW1bHT7Ab/SXVLKxsArDn65ZW6HndpT/5sEXuW
rYj5G7fKEF9fB1GqqQl42v6Yo1MwUTAdBgNVHQ4EFgQUe9jUh5URCGln+inE8CnT
dkuYA2AwHwYDVR0jBBgwFoAUe9jUh5URCGln+inE8CnTdkuYA2AwDwYDVR0TAQH/
BAUwAwEB/zAKBggqhkjOPQQDAgNJADBGAiEA5cZ0ujBp7EQ3Gf/GDdL7adHS8J3B
2KSyJ30d+efrGmwCIQDLuuO8ASAcRspYmRewnUuWJqHYgDWVzSF10b3I8w3/Cw==
-----END CERTIFICATE-----
)";

constexpr const char* kCertB = R"(-----BEGIN CERTIFICATE-----
MIIBejCCAR+gAwIBAgIUG2hF+CO5yCUdiklVS1nEt54UaUIwCgYIKoZIzj0EAwIw
EjEQMA4GA1UEAwwHc2FtMTAtYjAeFw0yNTAxMDEwMDAwMDBaFw0yODEyMzEyMzU5
NTlaMBIxEDAOBgNVBAMMB3NhbTEwLWIwWTATBgcqhkjOPQIBBggqhkjOPQMBBwNC
AARou+gyal15dHQtIQ2Rh/qk9upcgB5vpxSbYsqq5xmDxKazQqNzEtnAQly31wbl
CW8rk+JjdIscH4TZgIXBZjhYo1MwUTAdBgNVHQ4EFgQU7u110fvuqDuGG+mDlj9R
K+4wkgAwHwYDVR0jBBgwFoAU7u110fvuqDuGG+mDlj9RK+4wkgAwDwYDVR0TAQH/
BAUwAwEB/zAKBggqhkjOPQQDAgNJADBGAiEA2FwkyfUv+Mi3+HbtkxNFn5cFsqxq
1IjYrPzVzRJcoUICIQDr635iRaHq+Q0pJ+JV6M1Vx1nbADaHCB1Jj88gf+wTqA==
-----END CERTIFICATE-----
)";

constexpr const char* kCertC = R"(-----BEGIN CERTIFICATE-----
MIIBeTCCAR+gAwIBAgIULDo9j7hKsENBKP88Cw7e9FwExQ0wCgYIKoZIzj0EAwIw
EjEQMA4GA1UEAwwHc2FtMTAtYzAeFw0yNTAxMDEwMDAwMDBaFw0yNjAxMDEwMDAw
MDBaMBIxEDAOBgNVBAMMB3NhbTEwLWMwWTATBgcqhkjOPQIBBggqhkjOPQMBBwNC
AASPZOcZlvYOzSXEiQNyClG62jbH/L1ukSsg0ke6lU3q1W37WLsnw2NdnKMkAfk7
qwQ4BbcJEUbVs+NDhLDi++kpo1MwUTAdBgNVHQ4EFgQUHzNX+dLOY+n/XcoHtypa
Zekhs5UwHwYDVR0jBBgwFoAUHzNX+dLOY+n/XcoHtypaZekhs5UwDwYDVR0TAQH/
BAUwAwEB/zAKBggqhkjOPQQDAgNIADBFAiEA9+dJgYbyXj5OOjUKj4EawU50qYB8
3TbPJM+nY/5f6HsCICI0qLsd3Vwp26okKdnjqCSaXlYVJKuHyEcz9PXIw7mQ
-----END CERTIFICATE-----
)";

std::string repeat(const std::string& s, std::size_t n) {
    std::string out;
    for (std::size_t i = 0; i < n; ++i)
        out += s;
    return out;
}

constexpr const char* kDir = "/etc/pki/entitlement";
constexpr std::size_t kDirListCap = 4096;
constexpr std::size_t kPemFileCap = 64 * 1024;

constexpr const char* kWireA = "1804118400";
constexpr const char* kWireB = "1861833600";
constexpr const char* kWireC = "1767225600";

std::string path_of(const std::string& name) {
    return std::string(kDir) + "/" + name;
}

void add_file(FakeProbeHost& h, const std::string& name, const std::string& content) {
    h.dirs[kDir].names.push_back(name);
    h.files[path_of(name)] = {content, 0};
}

void add_failing_file(FakeProbeHost& h, const std::string& name, int err) {
    h.dirs[kDir].names.push_back(name);
    h.files[path_of(name)] = {{}, err};
}

Run run_linux(FakeProbeHost& h) {
    Run r;
    run_entitlement_certs_surface(h, r.records, r.outcomes);
    REQUIRE(r.outcomes.size() == 1);
    CHECK(r.outcomes[0].surface == "entitlement_certs");
    return r;
}

std::string numbered(const char* prefix, std::size_t i, const char* suffix) {
    std::string n = std::to_string(i);
    if (n.size() < 2)
        n.insert(0, 2 - n.size(), '0');
    return std::string(prefix) + n + suffix;
}

} // namespace

TEST_CASE("entitlement surface: an absent directory is ok|0 and nothing is read",
          "[licensing][license_scan][surface][linux]") {
    for (const int err : {ENOENT, ENOTDIR}) {
        FakeProbeHost h;
        DirListing absent;
        absent.err = err;
        h.dirs[kDir] = absent;
        const Run r = run_linux(h);
        INFO("errno " << err);
        CHECK(r.outcomes[0].ok);
        CHECK(r.outcomes[0].rows == 0);
        CHECK(r.records.empty());
        CHECK(h.reads.empty());
    }
    FakeProbeHost never_configured; // the fake reports ENOENT for an unknown directory
    CHECK(run_linux(never_configured).outcomes[0].ok);
}

TEST_CASE("entitlement surface: a directory the agent may not list is a refusal, never ok|0",
          "[licensing][license_scan][surface][linux]") {
    for (const int err : {EACCES, EPERM}) {
        FakeProbeHost h;
        DirListing refused;
        refused.err = err;
        h.dirs[kDir] = refused;
        const Run r = run_linux(h);
        INFO("errno " << err);
        CHECK_FALSE(r.outcomes[0].ok);
        CHECK(r.outcomes[0].error == "cert_permission_denied");
        CHECK(r.records.empty());
        CHECK(h.reads.empty());
    }
}

TEST_CASE("entitlement surface: any other listing failure is a failed surface, never an empty one",
          "[licensing][license_scan][surface][linux]") {
    for (const int err : {EIO, ELOOP, EMFILE}) {
        FakeProbeHost h;
        DirListing failed;
        failed.err = err;
        h.dirs[kDir] = failed;
        const Run r = run_linux(h);
        INFO("errno " << err);
        CHECK_FALSE(r.outcomes[0].ok);
        CHECK(r.outcomes[0].error == "cert_parse_failed");
        CHECK(r.records.empty());
        CHECK(h.reads.empty());
    }
}

TEST_CASE("entitlement surface: certificate bytes become sorted authoritative rows, key files are skipped",
          "[licensing][license_scan][surface][linux]") {
    FakeProbeHost h;
    // Deliberately unsorted listing: row order must follow the sorted names, not readdir order.
    add_file(h, "b.pem", kCertA);
    add_file(h, "a-key.pem", "-----BEGIN PRIVATE KEY-----\nnot read\n-----END PRIVATE KEY-----\n");
    add_file(h, "c.pem", kCertB);
    add_file(h, "a.pem", kCertC);
    add_file(h, "note.txt", "not a certificate");
    add_file(h, "b-key.pem", "not read");
    const Run r = run_linux(h);

    REQUIRE(h.reads.size() == 3);
    CHECK(h.reads[0].path == path_of("a.pem"));
    CHECK(h.reads[1].path == path_of("b.pem"));
    CHECK(h.reads[2].path == path_of("c.pem"));

    CHECK(r.outcomes[0].ok);
    CHECK(r.outcomes[0].rows == 3);
    REQUIRE(r.records.size() == 3);
    CHECK(r.records[0].expires_at == kWireC);
    CHECK(r.records[1].expires_at == kWireA);
    CHECK(r.records[2].expires_at == kWireB);
    for (const auto& rec : r.records) {
        CHECK(rec.product == "Red Hat subscription entitlement");
        CHECK(rec.vendor == "Red Hat");
        CHECK(rec.license_type == "subscription");
        CHECK(rec.source == "entitlement_cert");
        CHECK(rec.confidence == "authoritative");
    }
    // collection day is 2026-10-26: the 2026-01-01 certificate has lapsed, the others have not.
    CHECK(r.records[0].status == "expired");
    CHECK(r.records[1].status == "subscription_active");
    CHECK(r.records[2].status == "subscription_active");
}

TEST_CASE("entitlement surface: a certificate is expired only from the day AFTER its notAfter",
          "[licensing][license_scan][surface][linux]") {
    // kCertC's notAfter day is 2026-01-01 (wire 1767225600): whole-day granularity.
    for (const auto& [now, expected] : std::vector<std::pair<long long, const char*>>{
             {1767225600LL, "subscription_active"},         // 00:00:00 on the notAfter day
             {1767225600LL + 86399, "subscription_active"}, // 23:59:59 on the notAfter day
             {1767225600LL + 86400, "expired"}}) {          // 00:00:00 the next day
        FakeProbeHost h;
        h.epoch = now;
        add_file(h, "c.pem", kCertC);
        const Run r = run_linux(h);
        INFO("now " << now);
        REQUIRE(r.records.size() == 1);
        CHECK(r.records[0].status == expected);
    }
}

TEST_CASE("entitlement surface: -key.pem is filtered from the WHOLE listing before the 64-file cap",
          "[licensing][license_scan][surface][linux]") {
    FakeProbeHost h;
    for (std::size_t i = 0; i < 70; ++i)
        add_file(h, numbered("k", i, "-key.pem"), "not read");
    add_file(h, "z1.pem", kCertA);
    add_file(h, "z2.pem", kCertA);
    add_file(h, "z3.pem", kCertA);
    const Run r = run_linux(h);
    CHECK(r.outcomes[0].ok); // 3 certificate files, not 73 candidates
    CHECK(r.outcomes[0].rows == 3);
    REQUIRE(h.reads.size() == 3);
    for (const auto& rd : h.reads)
        CHECK(rd.path.find("-key.pem") == std::string::npos);
}

TEST_CASE("entitlement surface: 64 certificate files are accepted, a 65th is budget_exhausted",
          "[licensing][license_scan][surface][linux]") {
    {
        FakeProbeHost h;
        for (std::size_t i = 0; i < 64; ++i)
            add_file(h, numbered("c", i, ".pem"), kCertA);
        const Run r = run_linux(h);
        CHECK(r.outcomes[0].ok);
        CHECK(r.outcomes[0].rows == 64);
        CHECK(r.records.size() == 64);
        CHECK(h.reads.size() == 64);
    }
    {
        FakeProbeHost h;
        for (std::size_t i = 0; i < 65; ++i)
            add_file(h, numbered("c", i, ".pem"), kCertA);
        const Run r = run_linux(h);
        CHECK_FALSE(r.outcomes[0].ok);
        CHECK(r.outcomes[0].error == "cert_scan_budget_exhausted");
        CHECK(r.outcomes[0].rows == 64);   // the 64 examined rows are kept
        CHECK(r.records.size() == 64);
        REQUIRE(h.reads.size() == 64);
        CHECK(h.reads.back().path == path_of("c63.pem")); // the 65th sorted name was never read
    }
}

TEST_CASE("entitlement surface: a certificate file of exactly 64 KiB is read, one byte more fails",
          "[licensing][license_scan][surface][linux]") {
    std::string at_cap = kCertA;
    at_cap += std::string(kPemFileCap - at_cap.size(), '\n'); // trailing blank lines after the block
    REQUIRE(at_cap.size() == kPemFileCap);
    {
        FakeProbeHost h;
        add_file(h, "a.pem", at_cap);
        const Run r = run_linux(h);
        CHECK(r.outcomes[0].ok);
        REQUIRE(r.records.size() == 1);
        CHECK(r.records[0].expires_at == kWireA);
        REQUIRE(h.reads.size() == 1);
        CHECK(h.reads[0].cap == kPemFileCap);
    }
    {
        FakeProbeHost h;
        add_file(h, "a.pem", at_cap + "\n"); // 65537 bytes: oversized, NEVER a truncated parse
        const Run r = run_linux(h);
        CHECK_FALSE(r.outcomes[0].ok);
        CHECK(r.outcomes[0].error == "cert_parse_failed");
        CHECK(r.records.empty());
    }
    {
        FakeProbeHost h; // an oversized file beside a good one: rows kept, partial
        add_file(h, "a.pem", at_cap + "\n");
        add_file(h, "b.pem", kCertB);
        const Run r = run_linux(h);
        CHECK_FALSE(r.outcomes[0].ok);
        CHECK(r.outcomes[0].error == "cert_parse_partial");
        CHECK(r.outcomes[0].rows == 1);
        REQUIRE(r.records.size() == 1);
        CHECK(r.records[0].expires_at == kWireB);
    }
}

TEST_CASE("entitlement surface: 16 certificates in one file are accepted, a 17th is budget_exhausted",
          "[licensing][license_scan][surface][linux]") {
    {
        FakeProbeHost h;
        add_file(h, "bundle.pem", repeat(kCertA, 16));
        const Run r = run_linux(h);
        CHECK(r.outcomes[0].ok);
        CHECK(r.records.size() == 16);
    }
    {
        FakeProbeHost h;
        add_file(h, "bundle.pem", repeat(kCertA, 17));
        const Run r = run_linux(h);
        CHECK_FALSE(r.outcomes[0].ok);
        CHECK(r.outcomes[0].error == "cert_scan_budget_exhausted");
        CHECK(r.outcomes[0].rows == 16);
        CHECK(r.records.size() == 16);
    }
}

TEST_CASE("entitlement surface: a directory listing at the entry limit is complete, one past it is not",
          "[licensing][license_scan][surface][linux]") {
    {
        FakeProbeHost h; // exactly 4096 entries, none a certificate
        for (std::size_t i = 0; i < kDirListCap; ++i)
            h.dirs[kDir].names.push_back("f" + std::to_string(i) + ".txt");
        const Run r = run_linux(h);
        CHECK(r.outcomes[0].ok);
        CHECK(r.outcomes[0].rows == 0);
        CHECK(h.reads.empty());
    }
    {
        FakeProbeHost h; // 4097 entries: the listing is a prefix, so the scan is incomplete
        add_file(h, "a.pem", kCertA);
        for (std::size_t i = 0; i < kDirListCap; ++i)
            h.dirs[kDir].names.push_back("f" + std::to_string(i) + ".txt");
        const Run r = run_linux(h);
        CHECK_FALSE(r.outcomes[0].ok);
        CHECK(r.outcomes[0].error == "cert_scan_budget_exhausted");
        CHECK(r.outcomes[0].rows == 1); // what was seen is kept
        CHECK(r.records.size() == 1);
        // the recorded requests: the directory listed once with the limit, never globbed,
        // and the one certificate read through the capped reader (not the lossy prefix one)
        REQUIRE(h.listings.size() == 1);
        CHECK(h.listings[0].path == kDir);
        CHECK(h.listings[0].max_entries == kDirListCap);
        CHECK(h.globs.empty());
        CHECK(h.prefix_reads.empty());
    }
}

TEST_CASE("entitlement surface: the 10 s start gate is checked before each read on an injected clock",
          "[licensing][license_scan][surface][linux]") {
    using std::chrono::nanoseconds;
    using std::chrono::seconds;
    struct Gate {
        Clock::duration per_read;
        std::size_t files;
        std::size_t expected_reads;
        bool exhausted;
    };
    const std::vector<Gate> gates = {
        {seconds{11}, 3, 1, true},                         // jumps well past the budget after one read
        {seconds{10}, 2, 1, true},                         // lands exactly ON the deadline: gate trips
        {seconds{10} - nanoseconds{1}, 2, 2, false},       // one tick short of the deadline: still open
        {seconds{5}, 3, 2, true},                          // reads at +0 and +5; the third is at +10
        {seconds{0}, 5, 5, false},                         // a fast filesystem never trips it
    };
    for (const auto& g : gates) {
        FakeProbeHost h;
        h.advance_per_read = g.per_read;
        for (std::size_t i = 0; i < g.files; ++i)
            add_file(h, numbered("c", i, ".pem"), kCertA);
        const Run r = run_linux(h);
        INFO("per-read " << std::chrono::duration_cast<nanoseconds>(g.per_read).count() << " ns, "
                         << g.files << " files");
        CHECK(h.reads.size() == g.expected_reads);
        CHECK(r.records.size() == g.expected_reads); // rows already parsed are kept
        CHECK(r.outcomes[0].ok == !g.exhausted);
        if (g.exhausted) {
            CHECK(r.outcomes[0].error == "cert_scan_budget_exhausted");
            CHECK(r.outcomes[0].rows == g.expected_reads);
        }
    }
}

TEST_CASE("entitlement surface: a certificate the agent may not read is a refusal and keeps the other rows",
          "[licensing][license_scan][surface][linux]") {
    for (const int err : {EACCES, EPERM}) {
        FakeProbeHost h;
        add_file(h, "a.pem", kCertA);
        add_failing_file(h, "b.pem", err);
        add_file(h, "c.pem", kCertB);
        const Run r = run_linux(h);
        INFO("errno " << err);
        CHECK(h.reads.size() == 3); // the refusal does not stop the scan
        CHECK_FALSE(r.outcomes[0].ok);
        CHECK(r.outcomes[0].error == "cert_permission_denied");
        CHECK(r.outcomes[0].rows == 2);
        REQUIRE(r.records.size() == 2);
        CHECK(r.records[0].expires_at == kWireA);
        CHECK(r.records[1].expires_at == kWireB);
    }
}

TEST_CASE("entitlement surface: unreadable and unparseable certificates fail the surface, rows kept",
          "[licensing][license_scan][surface][linux]") {
    {
        FakeProbeHost h; // every file fails for a reason that is not a refusal
        add_failing_file(h, "a.pem", EIO);
        add_file(h, "b.pem", "this is not a certificate");
        const Run r = run_linux(h);
        CHECK_FALSE(r.outcomes[0].ok);
        CHECK(r.outcomes[0].error == "cert_parse_failed");
        CHECK(r.outcomes[0].rows == 0);
        CHECK(r.records.empty());
    }
    {
        FakeProbeHost h; // one good, one garbage: partial, never a clean success
        add_file(h, "a.pem", kCertA);
        add_file(h, "b.pem", "this is not a certificate");
        const Run r = run_linux(h);
        CHECK_FALSE(r.outcomes[0].ok);
        CHECK(r.outcomes[0].error == "cert_parse_partial");
        CHECK(r.outcomes[0].rows == 1);
        REQUIRE(r.records.size() == 1);
        CHECK(r.records[0].expires_at == kWireA);
    }
}

TEST_CASE("entitlement surface: a refusal outranks every other degradation and still carries the rows",
          "[licensing][license_scan][surface][linux]") {
    FakeProbeHost h;
    add_file(h, "a.pem", kCertA);                               // good: one row
    add_failing_file(h, "b.pem", EACCES);                       // refusal
    add_file(h, "c.pem", "garbage");                            // parse failure
    add_file(h, "d.pem", repeat(kCertB, 17));                   // cert cap hit: budget exhausted
    for (std::size_t i = 0; i < kDirListCap; ++i)               // truncated listing: budget exhausted
        h.dirs[kDir].names.push_back("f" + std::to_string(i) + ".txt");
    const Run r = run_linux(h);
    CHECK_FALSE(r.outcomes[0].ok);
    CHECK(r.outcomes[0].error == "cert_permission_denied");
    CHECK(r.outcomes[0].rows == 1 + 16);
    CHECK(r.records.size() == 1 + 16);
}

TEST_CASE("entitlement surface: an empty directory is ok|0 and nothing is read",
          "[licensing][license_scan][surface][linux]") {
    FakeProbeHost h;
    h.dirs[kDir] = DirListing{};
    const Run r = run_linux(h);
    CHECK(r.outcomes[0].ok);
    CHECK(r.outcomes[0].rows == 0);
    CHECK(h.reads.empty());
}

#endif // __linux__

#ifdef __APPLE__

// ── macOS: run_mas_receipt_surface ──────────────────────────────────────────

namespace {

constexpr const char* kGlobPattern = "/Applications/*.app/Contents/_MASReceipt/receipt";
constexpr std::size_t kInfoPlistCap = 4 * 1024 * 1024;
constexpr const char* kReceiptSuffix = "/Contents/_MASReceipt/receipt";

std::string receipt_of(const std::string& app) {
    return app + kReceiptSuffix;
}
std::string plist_of(const std::string& app) {
    return app + "/Contents/Info.plist";
}

std::string read_fixture(const char* name) {
    const fs::path p = fs::path{YUZU_TEST_FIXTURE_DIR} / "software-estate" / "license_scan" /
                       "macos" / name;
    REQUIRE(fs::exists(p));
    std::ifstream f(p, std::ios::binary);
    std::string out((std::istreambuf_iterator<char>(f)), std::istreambuf_iterator<char>());
    REQUIRE_FALSE(out.empty());
    return out;
}

// A real capture with one top-level key renamed in place (first byte 'C' -> 'X': same
// length, so every offset stays valid): the decoder then sees that key as absent. The key
// occurs exactly once in each capture as ASCII, which is REQUIRE'd so a rename cannot hit
// the wrong bytes.
std::string without_key(std::string plist, std::string_view key) {
    const auto pos = plist.find(key);
    REQUIRE(pos != std::string::npos);
    REQUIRE(plist.find(key, pos + 1) == std::string::npos);
    plist[pos] = 'X';
    return plist;
}

std::string xml_plist(const std::vector<std::pair<std::string, std::string>>& kvs) {
    std::string x =
        "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<plist version=\"1.0\">\n<dict>\n";
    for (const auto& [k, v] : kvs)
        x += "  <key>" + k + "</key>\n  <string>" + v + "</string>\n";
    x += "</dict>\n</plist>\n";
    return x;
}

void add_app(FakeProbeHost& h, const std::string& app, const std::string& info_plist) {
    h.glob_matches.push_back(receipt_of(app));
    h.files[plist_of(app)] = {info_plist, 0};
}

void add_app_unreadable(FakeProbeHost& h, const std::string& app, int err) {
    h.glob_matches.push_back(receipt_of(app));
    h.files[plist_of(app)] = {{}, err};
}

Run run_mac(FakeProbeHost& h) {
    Run r;
    run_mas_receipt_surface(h, r.records, r.outcomes);
    REQUIRE(r.outcomes.size() == 1);
    CHECK(r.outcomes[0].surface == "mas_receipt");
    return r;
}

} // namespace

TEST_CASE("mas_receipt surface: binary Info.plist identity reaches the row (real captures)",
          "[licensing][license_scan][surface][macos]") {
    FakeProbeHost h;
    add_app(h, "/Applications/WhatsApp.app", read_fixture("WhatsApp.Info.plist"));
    add_app(h, "/Applications/Pages Creator Studio.app", read_fixture("Pages-Creator-Studio.Info.plist"));
    add_app(h, "/Applications/Spotify.app", read_fixture("Spotify.Info.plist"));
    const Run r = run_mac(h);

    CHECK(r.outcomes[0].ok);
    CHECK(r.outcomes[0].rows == 3);
    REQUIRE(r.records.size() == 3); // glob order
    // UTF-16 DisplayName with a leading U+200E: not the bundle name "WhatsApp".
    CHECK(r.records[0].product == std::string("\xE2\x80\x8E" "WhatsApp"));
    CHECK(r.records[0].version == "26.41.28");
    // DisplayName ("Pages Creator Studio") wins over Name ("Pages").
    CHECK(r.records[1].product == "Pages Creator Studio");
    CHECK(r.records[1].version == "15.1.1");
    CHECK(r.records[2].product == "Spotify");
    CHECK(r.records[2].version == "1.3.5.3058");
    for (const auto& rec : r.records) {
        CHECK(rec.vendor.empty()); // unknown -- never synthesised
        CHECK(rec.license_type == "retail");
        CHECK(rec.status == "licensed");
        CHECK(rec.source == "app_receipt");
        CHECK(rec.confidence == "probable");
    }
}

TEST_CASE("mas_receipt surface: a binary plist falls back from DisplayName to Name, version may be absent",
          "[licensing][license_scan][surface][macos]") {
    FakeProbeHost h;
    // Spotify's CFBundleName is "Spotify": with DisplayName and ShortVersionString renamed
    // away, the product can only come from the Name fallback, never the directory "Café".
    add_app(h, "/Applications/Café.app",
            without_key(without_key(read_fixture("Spotify.Info.plist"), "CFBundleDisplayName"),
                        "CFBundleShortVersionString"));
    const Run r = run_mac(h);
    REQUIRE(r.records.size() == 1);
    CHECK(r.records[0].product == "Spotify");
    CHECK(r.records[0].version.empty());
}

TEST_CASE("mas_receipt surface: the XML plist path is unchanged",
          "[licensing][license_scan][surface][macos]") {
    FakeProbeHost h;
    add_app(h, "/Applications/Word.app",
            xml_plist({{"CFBundleName", "Word"},
                       {"CFBundleDisplayName", "Word &amp; Co"},
                       {"CFBundleShortVersionString", "16.9"}}));
    add_app(h, "/Applications/Excel.app",
            xml_plist({{"CFBundleName", "Excel Name"}, {"CFBundleShortVersionString", "16.8"}}));
    const Run r = run_mac(h);
    REQUIRE(r.records.size() == 2);
    CHECK(r.records[0].product == "Word & Co"); // DisplayName wins, entity decoded
    CHECK(r.records[0].version == "16.9");
    CHECK(r.records[1].product == "Excel Name"); // Name when there is no DisplayName
    CHECK(r.records[1].version == "16.8");
}

TEST_CASE("mas_receipt surface: a plist that cannot be decoded falls back to the bundle name",
          "[licensing][license_scan][surface][macos]") {
    FakeProbeHost h;
    add_app_unreadable(h, "/Applications/Gone.app", ENOENT);
    add_app_unreadable(h, "/Applications/Denied.app", EACCES);
    add_app(h, "/Applications/Truncated.app", std::string("bplist00") + "xyz");          // undecodable binary
    add_app(h, "/Applications/OtherKey.app",                                              // binary, no name key
            without_key(without_key(read_fixture("Spotify.Info.plist"), "CFBundleDisplayName"),
                        "CFBundleName"));
    add_app(h, "/Applications/NoNames.app", xml_plist({{"CFBundleShortVersionString", "2.0"}}));
    add_app(h, "/Applications/Big App.app", std::string(kInfoPlistCap + 1, ' '));        // oversized
    const Run r = run_mac(h);
    CHECK(r.outcomes[0].ok);
    REQUIRE(r.records.size() == 6);
    CHECK(r.records[0].product == "Gone");
    CHECK(r.records[1].product == "Denied");
    CHECK(r.records[2].product == "Truncated");
    CHECK(r.records[3].product == "OtherKey");
    CHECK(r.records[4].product == "NoNames");
    CHECK(r.records[5].product == "Big App");
    for (const auto& i : {0, 1, 2, 5})
        CHECK(r.records[static_cast<std::size_t>(i)].version.empty());
    // a readable plist's version is kept even without a name (binary and XML alike)
    CHECK(r.records[3].version == "1.3.5.3058");
    CHECK(r.records[4].version == "2.0");
}

TEST_CASE("mas_receipt surface: an Info.plist of exactly 4 MiB is decoded, one byte more is not",
          "[licensing][license_scan][surface][macos]") {
    std::string at_cap = xml_plist({{"CFBundleName", "Decoded Name"}});
    at_cap += std::string(kInfoPlistCap - at_cap.size(), '\n');
    REQUIRE(at_cap.size() == kInfoPlistCap);
    {
        FakeProbeHost h;
        add_app(h, "/Applications/Folder Name.app", at_cap);
        const Run r = run_mac(h);
        REQUIRE(r.records.size() == 1);
        CHECK(r.records[0].product == "Decoded Name");
        // the recorded requests: one receipt glob, one Info.plist read at the 4 MiB cap
        REQUIRE(h.globs.size() == 1);
        CHECK(h.globs[0] == kGlobPattern);
        REQUIRE(h.reads.size() == 1);
        CHECK(h.reads[0].path == plist_of("/Applications/Folder Name.app"));
        CHECK(h.reads[0].cap == kInfoPlistCap);
        CHECK(h.prefix_reads.empty());
    }
    {
        FakeProbeHost h;
        add_app(h, "/Applications/Folder Name.app", at_cap + "\n");
        const Run r = run_mac(h);
        REQUIRE(r.records.size() == 1);
        CHECK(r.records[0].product == "Folder Name"); // oversized: bundle name, never a partial parse
    }
}

TEST_CASE("mas_receipt surface: no receipts is ok|0, and a degenerate receipt path is skipped",
          "[licensing][license_scan][surface][macos]") {
    {
        FakeProbeHost h;
        const Run r = run_mac(h);
        CHECK(r.outcomes[0].ok);
        CHECK(r.outcomes[0].rows == 0);
        CHECK(r.records.empty());
    }
    {
        FakeProbeHost h;
        h.glob_matches.push_back(kReceiptSuffix); // nothing before the suffix: no app path
        add_app(h, "/Applications/Real.app", xml_plist({{"CFBundleName", "Real"}}));
        const Run r = run_mac(h);
        CHECK(r.outcomes[0].rows == 1);
        REQUIRE(r.records.size() == 1);
        CHECK(r.records[0].product == "Real");
        CHECK(h.reads.size() == 1); // the degenerate match was not read
    }
}

#endif // __APPLE__

#endif // __linux__ || __APPLE__
