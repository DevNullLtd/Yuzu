/**
 * test_default_certs.cpp — Unit tests for the first-boot default-cert bootstrap (PR2).
 *
 * Covers: first-boot generation of the full set, idempotent re-run,
 * regenerate-on-corruption, leaf chains-to-CA + SAN, 0600 key mode (POSIX),
 * leaf-not-after == CA-not-after (the leaf<=CA invariant), and ca_store
 * recording of the root + issued leaves.
 */

#include "default_certs.hpp"

#include "ca_store.hpp"
#include "key_provider.hpp"
#include "pg/pg_exec.hpp"
#include "pg/pg_pool.hpp"
#include "pg/pg_raii.hpp"
#include "x509_ca.hpp"

#include <catch2/catch_test_macros.hpp>

#include "../test_helpers.hpp"
#include "../test_log_capture.hpp"

#include <libpq-fe.h> // PQconnectdb/PQstatus/PGRES_* used directly by the UP-3 side-lock rendezvous

#include <openssl/bio.h>
#include <openssl/pem.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>

#include <algorithm>
#include <array>
#include <chrono>
#include <cstddef>
#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <string>
#include <string_view>
#include <system_error>
#include <thread>
#include <vector>

#ifndef _WIN32
#include <sys/stat.h> // stat (--cert-group perm assertions)
#include <unistd.h>   // getgid
#include <utility>    // pair
#endif

using namespace yuzu::server;

namespace {

// Shared with test_ca_store.cpp's "castore" key — identical setup, replay-verified by the
// PgTestTemplate registry (docs/postgres-store-playbook.md step 7).
yuzu::test::PgTestTemplate ca_store_tpl{
    "castore", [](const std::string& dsn) {
        yuzu::server::pg::PgPool pool{{.conninfo = dsn, .size = 1}};
        yuzu::server::CaStore store{pool};
        if (!store.is_open())
            throw std::runtime_error("ca_store template: store failed to migrate");
    }};

struct TempDir {
    std::filesystem::path path;
    TempDir() : path(yuzu::test::unique_temp_path("defcerts-")) {}
    ~TempDir() {
        std::error_code ec;
        std::filesystem::remove_all(path, ec);
    }
    TempDir(const TempDir&) = delete;
    TempDir& operator=(const TempDir&) = delete;
};

std::string read_file(const std::filesystem::path& p) {
    std::ifstream in(p, std::ios::binary);
    return std::string((std::istreambuf_iterator<char>(in)), std::istreambuf_iterator<char>());
}

bool contains(const std::vector<std::string>& v, const std::string& s) {
    return std::find(v.begin(), v.end(), s) != v.end();
}

std::size_t count_of(const std::vector<std::string>& v, const std::string& s) {
    return static_cast<std::size_t>(std::count(v.begin(), v.end(), s));
}

// Returns the X509 extended-key-usage flag word (XKU_SSL_SERVER / XKU_SSL_CLIENT
// bits) for a PEM leaf. UINT32_MAX means "no EKU extension" (all purposes).
uint32_t leaf_eku_flags(const std::filesystem::path& pem_path) {
    std::string pem = read_file(pem_path);
    BIO* bio = BIO_new_mem_buf(pem.data(), static_cast<int>(pem.size()));
    REQUIRE(bio != nullptr);
    X509* x = PEM_read_bio_X509(bio, nullptr, nullptr, nullptr);
    BIO_free(bio);
    REQUIRE(x != nullptr);
    uint32_t flags = X509_get_extended_key_usage(x); // forces the lazy EKU parse
    X509_free(x);
    return flags;
}

} // namespace

TEST_CASE("default_certs: first boot generates a full, chained set", "[default_certs]") {
    TempDir dir;
    DefaultCertSet set;
    REQUIRE(ensure_default_certs(dir.path, "test-host", nullptr, set));
    REQUIRE(set.freshly_generated);
    REQUIRE_FALSE(set.ca_fingerprint_sha256.empty());

    for (const auto& p : {set.ca_cert, set.https_cert, set.https_key, set.server_cert,
                          set.server_key, set.gateway_cert, set.gateway_key}) {
        REQUIRE(std::filesystem::exists(p));
    }

    const std::string ca_pem = read_file(set.ca_cert);
    auto ca_info = pki::parse_certificate(ca_pem);
    REQUIRE(ca_info);
    REQUIRE(ca_info->is_ca);

    // Every server-side leaf chains to the CA.
    for (const auto& leaf : {set.https_cert, set.server_cert, set.gateway_cert}) {
        REQUIRE(pki::verify_chain(read_file(leaf), ca_pem));
    }

    // HTTPS leaf SAN carries localhost / 127.0.0.1 / the hostname.
    auto https = pki::parse_certificate(read_file(set.https_cert));
    REQUIRE(https);
    REQUIRE(contains(https->san.dns, "localhost"));
    REQUIRE(contains(https->san.dns, "test-host"));
    REQUIRE(contains(https->san.ips, "127.0.0.1"));
    REQUIRE_FALSE(https->is_ca);

    // Leaf notAfter must equal the CA notAfter (sized to the issuer).
    REQUIRE(https->not_after == ca_info->not_after);
}

TEST_CASE("default_certs: leaf EKUs match each role (server is also a client — #1314)",
          "[default_certs]") {
    TempDir dir;
    DefaultCertSet set;
    REQUIRE(ensure_default_certs(dir.path, "test-host", nullptr, set));

    // The server forwards commands to the gateway's mgmt plane over MUTUAL TLS
    // (#1314), so it acts as a TLS *client* and its leaf MUST carry clientAuth in
    // addition to serverAuth — otherwise a strict verifier rejects it as a client
    // cert and the command-forwarding dial fails.
    const uint32_t server_eku = leaf_eku_flags(set.server_cert);
    REQUIRE((server_eku & XKU_SSL_SERVER) != 0);
    REQUIRE((server_eku & XKU_SSL_CLIENT) != 0);

    // The gateway is a server to agents AND a client to the server upstream.
    const uint32_t gateway_eku = leaf_eku_flags(set.gateway_cert);
    REQUIRE((gateway_eku & XKU_SSL_SERVER) != 0);
    REQUIRE((gateway_eku & XKU_SSL_CLIENT) != 0);

    // The HTTPS dashboard leaf is server-only — no need for clientAuth.
    const uint32_t https_eku = leaf_eku_flags(set.https_cert);
    REQUIRE((https_eku & XKU_SSL_SERVER) != 0);
    REQUIRE((https_eku & XKU_SSL_CLIENT) == 0);
}

TEST_CASE("default_certs: server leaves backdate notBefore by the clock-skew allowance (#1302)",
          "[default_certs]") {
    // An agent whose clock lags the server at first connect must not reject a
    // freshly-minted server leaf as not-yet-valid. The CA root + per-agent client
    // leaf already backdate notBefore by kClockSkewBackdate; this pins the same for
    // the server-facing default leaves (HTTPS / agent-gRPC / gateway), which the
    // PR3 H-2 fix had missed.
    TempDir dir;
    DefaultCertSet set;
    const auto now = std::chrono::system_clock::now();
    REQUIRE(ensure_default_certs(dir.path, "test-host", nullptr, set));
    // now is captured BEFORE generation, so notBefore <= now - backdate (minus a
    // little slack for test execution time). Use 280s against the 300s backdate.
    const auto floor = now - pki::kClockSkewBackdate + std::chrono::seconds(20);
    for (const auto& leaf : {set.https_cert, set.server_cert, set.gateway_cert}) {
        auto c = pki::parse_certificate(read_file(leaf));
        REQUIRE(c);
        REQUIRE(c->not_before <= floor); // genuinely backdated, not now()
    }
}

TEST_CASE("default_certs: --cert-san extra SANs land on every default leaf", "[default_certs]") {
    TempDir dir;
    DefaultCertSet set;
    // Exercise every form: dns:-prefixed, ip:-prefixed, a bare DNS value, a bare
    // IP value (auto-classified), a comma-joined value (single-env-var case), a
    // duplicate of the hostname (dedupe), and a bogus ip: (dropped with a warn).
    const std::vector<std::string> extra = {
        "dns:gateway", "ip:10.1.2.3",          "edge.example.com", "192.0.2.7",
        "dns:a.example,ip:198.51.100.9",       "dns:test-host",    "ip:not-an-ip",
    };
    REQUIRE(ensure_default_certs(dir.path, "test-host", nullptr, set, extra));

    for (const auto& leaf : {set.https_cert, set.server_cert, set.gateway_cert}) {
        auto c = pki::parse_certificate(read_file(leaf));
        REQUIRE(c);
        // Base SANs still present.
        REQUIRE(contains(c->san.dns, "localhost"));
        REQUIRE(contains(c->san.ips, "127.0.0.1"));
        // Extra DNS names (prefixed, bare, and comma-split).
        REQUIRE(contains(c->san.dns, "gateway"));
        REQUIRE(contains(c->san.dns, "edge.example.com"));
        REQUIRE(contains(c->san.dns, "a.example"));
        // Extra IPs (prefixed, bare, and comma-split) — never in the DNS set.
        REQUIRE(contains(c->san.ips, "10.1.2.3"));
        REQUIRE(contains(c->san.ips, "192.0.2.7"));
        REQUIRE(contains(c->san.ips, "198.51.100.9"));
        REQUIRE_FALSE(contains(c->san.dns, "10.1.2.3"));
        // The bogus "ip:not-an-ip" was dropped (neither set).
        REQUIRE_FALSE(contains(c->san.ips, "not-an-ip"));
        REQUIRE_FALSE(contains(c->san.dns, "not-an-ip"));
        // Hostname duplicate collapsed — appears exactly once.
        REQUIRE(count_of(c->san.dns, "test-host") == 1);
    }
}

TEST_CASE("default_certs: --cert-san input validation is robust (no boot-fail on bad input)",
          "[default_certs]") {
    TempDir dir;
    DefaultCertSet set;
    const std::string overlong_label(300, 'a'); // > 63-byte label → rejected
    const std::vector<std::string> extra = {
        "dns:10.0.0.1",        // explicit dns: of an IP literal → kept as DNS, NOT ip
        "1.2.3.4.5",           // bare, IPv4-shaped but invalid → must NOT boot-fail
        "9.9.9.9",             // bare, valid IPv4 → ip
        "with space",          // bad charset (space) → dropped, no crash
        "foo/bar.example",     // bad charset (slash, a templating mistake) → dropped
        std::string("ctl\twith\ttabs"), // control chars → dropped
        overlong_label,        // over-length DNS → dropped
        "*.corp.example",      // wildcard → REJECTED (#1271 UP-10/11; fleet-trusted CA)
        "",                    // empty → skipped
        "   ",                 // whitespace-only → skipped
    };
    // The whole point: a typo-laden extra set must still produce a valid cert set.
    REQUIRE(ensure_default_certs(dir.path, "h", nullptr, set, extra));
    REQUIRE(set.freshly_generated);

    auto c = pki::parse_certificate(read_file(set.gateway_cert));
    REQUIRE(c);
    // dns:<ip> stays a DNS-type SAN (Finding 8) — present in dns, absent from ips.
    REQUIRE(contains(c->san.dns, "10.0.0.1"));
    REQUIRE_FALSE(contains(c->san.ips, "10.0.0.1"));
    // Invalid IPv4 literal was NOT shunted to ips (would have hard-failed issue_leaf).
    REQUIRE_FALSE(contains(c->san.ips, "1.2.3.4.5"));
    // Valid bare IPv4 landed in ips.
    REQUIRE(contains(c->san.ips, "9.9.9.9"));
    // Wildcard REJECTED (#1271 UP-10/11): the install CA is distributed fleet-wide,
    // so a wildcard default leaf is not allowed — bring your own cert for that.
    REQUIRE_FALSE(contains(c->san.dns, "*.corp.example"));
    // Over-length label and bad-charset values dropped from both sets.
    REQUIRE_FALSE(contains(c->san.dns, overlong_label));
    REQUIRE_FALSE(contains(c->san.dns, "with space"));
    REQUIRE_FALSE(contains(c->san.dns, "foo/bar.example"));
    // Control-char entry dropped (the mid-string tabs make it invalid input).
    for (const auto& d : c->san.dns)
        REQUIRE(d.find('\t') == std::string::npos);
}

TEST_CASE("default_certs: a malformed gethostname() is omitted from the SAN, not baked in",
          "[default_certs]") {
    TempDir dir;
    DefaultCertSet set;
    // Container orchestration can set a hostname containing non-DNS bytes.
    REQUIRE(ensure_default_certs(dir.path, "bad/host name", nullptr, set));
    REQUIRE(set.freshly_generated);
    auto c = pki::parse_certificate(read_file(set.https_cert));
    REQUIRE(c);
    REQUIRE(contains(c->san.dns, "localhost"));        // base coverage intact
    REQUIRE(contains(c->san.ips, "127.0.0.1"));
    REQUIRE_FALSE(contains(c->san.dns, "bad/host name")); // malformed host name not baked in
}

TEST_CASE("default_certs: --cert-san total count is capped", "[default_certs]") {
    TempDir dir;
    DefaultCertSet set;
    std::vector<std::string> extra;
    for (int i = 0; i < 200; ++i)
        extra.push_back("dns:host" + std::to_string(i) + ".example");
    REQUIRE(ensure_default_certs(dir.path, "h", nullptr, set, extra));
    auto c = pki::parse_certificate(read_file(set.gateway_cert));
    REQUIRE(c);
    // base (localhost + h) + at most 64 extras; nowhere near 200.
    REQUIRE(c->san.dns.size() <= 2 + 64);
    REQUIRE(c->san.dns.size() > 2); // but some extras did land
}

TEST_CASE("default_certs: a --cert-san invalid-piece flood is bounded, not boot-fatal (#1271 UP-9)",
          "[default_certs]") {
    // The accepted-name cap counts only valid names; a flood of INVALID
    // comma-separated pieces (each dropped-with-warning) must still be bounded so
    // boot can't be CPU/log-flooded. One raw entry packed with thousands of bad
    // pieces must complete and still yield a valid cert set.
    TempDir dir;
    DefaultCertSet set;
    std::string flood = "with space"; // invalid (never accepted)
    for (int i = 0; i < 5000; ++i)
        flood += ",with space"; // 5001 invalid pieces in one raw entry
    REQUIRE(ensure_default_certs(dir.path, "h", nullptr, set, {flood}));
    REQUIRE(set.freshly_generated); // bounded + non-fatal
    auto c = pki::parse_certificate(read_file(set.gateway_cert));
    REQUIRE(c);
    REQUIRE_FALSE(contains(c->san.dns, "with space")); // none of the junk landed
}

TEST_CASE("default_certs: no --cert-san leaves the base SAN set unchanged", "[default_certs]") {
    TempDir dir;
    DefaultCertSet set;
    REQUIRE(ensure_default_certs(dir.path, "plain-host", nullptr, set)); // 4-arg / default {}
    auto c = pki::parse_certificate(read_file(set.gateway_cert));
    REQUIRE(c);
    REQUIRE(contains(c->san.dns, "localhost"));
    REQUIRE(contains(c->san.dns, "plain-host"));
    REQUIRE(contains(c->san.ips, "127.0.0.1"));
    // ::1 parses back UNCOMPRESSED — warn_on_san_drift's deliberate IPv6 skip
    // depends on this form, so pin it (a future OpenSSL change would fail here).
    REQUIRE(contains(c->san.ips, "0:0:0:0:0:0:0:1"));
    REQUIRE(c->san.ips.size() == 2); // 127.0.0.1 + ::1 (parsed uncompressed), nothing extra
    REQUIRE(c->san.dns.size() == 2); // localhost + hostname, nothing extra
}

#ifndef _WIN32
TEST_CASE("default_certs: key files are 0600", "[default_certs][posix]") {
    namespace fs = std::filesystem;
    TempDir dir;
    DefaultCertSet set;
    REQUIRE(ensure_default_certs(dir.path, "h", nullptr, set));
    for (const auto& key : {set.https_key, set.server_key, set.gateway_key}) {
        const auto p = fs::status(key).permissions();
        REQUIRE((p & fs::perms::group_all) == fs::perms::none);
        REQUIRE((p & fs::perms::others_all) == fs::perms::none);
    }
}
#endif

TEST_CASE("default_certs: second run is idempotent", "[default_certs]") {
    TempDir dir;
    DefaultCertSet first;
    REQUIRE(ensure_default_certs(dir.path, "host", nullptr, first));
    REQUIRE(first.freshly_generated);

    DefaultCertSet second;
    REQUIRE(ensure_default_certs(dir.path, "host", nullptr, second));
    REQUIRE_FALSE(second.freshly_generated);
    REQUIRE(second.ca_fingerprint_sha256 == first.ca_fingerprint_sha256);
}

TEST_CASE("default_certs: regenerates the whole set when a key is missing",
          "[default_certs]") {
    TempDir dir;
    DefaultCertSet first;
    REQUIRE(ensure_default_certs(dir.path, "host", nullptr, first));

    std::error_code ec;
    std::filesystem::remove(first.server_key, ec); // corrupt the set
    REQUIRE_FALSE(ec);

    DefaultCertSet second;
    REQUIRE(ensure_default_certs(dir.path, "host", nullptr, second));
    REQUIRE(second.freshly_generated);                                  // regenerated
    REQUIRE(second.ca_fingerprint_sha256 != first.ca_fingerprint_sha256); // brand-new CA
    REQUIRE(std::filesystem::exists(second.server_key));
}

TEST_CASE("default_certs: records root + leaves in ca_store", "[default_certs][ca_store][pg]") {
    TempDir dir;
    YUZU_REQUIRE_PG_DB_TPL(db, ca_store_tpl);
    yuzu::server::pg::PgPool pool{{.conninfo = db.dsn(), .size = 2}};
    CaStore store{pool};
    REQUIRE(store.is_open());

    DefaultCertSet set;
    REQUIRE(ensure_default_certs(dir.path, "host", &store, set));

    REQUIRE(store.has_root());
    auto root = store.get_root();
    REQUIRE(root.has_value());
    REQUIRE(root->has_value());
    REQUIRE((*root)->algo == "EcP384");
    REQUIRE((*root)->mode == CaMode::Builtin);
    REQUIRE((*root)->fingerprint_sha256 == set.ca_fingerprint_sha256);

    auto issued = store.list_issued();
    REQUIRE(issued.has_value());
    REQUIRE(issued->size() == 3); // https + server + gateway
    for (const auto& rec : *issued) {
        REQUIRE_FALSE(rec.cert_pem.empty());
        REQUIRE(rec.issued_by == "system:default-certs");
    }
}

TEST_CASE("default_certs: UP-2 self-heals a corrupt on-disk set when the local CA key "
          "still matches ca_store's root, WITHOUT re-rooting (Gate 4 unhappy-path fix, "
          "2026-08-21)",
          "[default_certs][ca_store][security][pg]") {
    // B-2 (#1238) originally refused OUTRIGHT on any on-disk corruption against a
    // populated ca_store — correct for the danger it targets (minting a FRESH CA,
    // which would re-root the fleet), but overbroad: it also refused the much
    // narrower "this exact instance crashed mid-completion (or one of its leaf
    // files was later lost) and still holds the same CA key" case, which has a
    // provable-safe self-heal — see the same-root assertions below. Red-first
    // regression recipe (advisor, 2026-08-21): complete a boot, delete a leaf file
    // (simulating the UP-2 crash window / later corruption) but keep the local CA
    // key + ca_store root, re-run, expect completion — NOT the old refusal.
    TempDir dir;
    YUZU_REQUIRE_PG_DB_TPL(db, ca_store_tpl);
    yuzu::server::pg::PgPool pool{{.conninfo = db.dsn(), .size = 2}};
    CaStore store{pool};
    DefaultCertSet a;
    REQUIRE(ensure_default_certs(dir.path, "host", &store, a));
    REQUIRE(store.has_root());
    REQUIRE(store.list_issued()->size() == 3);

    // Corrupt the on-disk set while ca_store stays populated; the local CA key
    // (default-ca.key, never touched here) is what makes this instance provably
    // the same one that established the root.
    std::error_code ec;
    std::filesystem::remove(a.server_key, ec);
    DefaultCertSet b;
    REQUIRE(ensure_default_certs(dir.path, "host", &store, b)); // self-heals, does not refuse
    REQUIRE(b.freshly_generated);
    // The invariant B-2 exists to protect is untouched: SAME root, not a new one.
    auto root_after = store.get_root();
    REQUIRE(root_after.has_value());
    REQUIRE(root_after->has_value());
    REQUIRE((*root_after)->fingerprint_sha256 == a.ca_fingerprint_sha256);
    REQUIRE(b.ca_fingerprint_sha256 == a.ca_fingerprint_sha256);
    // Leaves were re-minted (purge + fresh record), still exactly 3.
    REQUIRE(store.list_issued()->size() == 3);
}

TEST_CASE("default_certs: B-2 still refuses when the local CA key does NOT resolve — the "
          "genuine wiped-volume / botched-restore case (Gate 4 unhappy-path fix, 2026-08-21)",
          "[default_certs][ca_store][security][pg]") {
    // The self-heal above is gated on possessing the ORIGINAL instance's local CA
    // key file. A different instance/host/directory — no local "default-ca" key at
    // that ca_store-recorded key_ref (an absolute path under the FIRST instance's
    // own dir) — must still hit the original heavyweight refusal: this is the
    // actual danger B-2 exists for (an operator about to mint a fresh CA over a
    // fleet that already has one).
    TempDir dir_a;
    TempDir dir_b; // never shares dir_a's local key material
    YUZU_REQUIRE_PG_DB_TPL(db, ca_store_tpl);
    yuzu::server::pg::PgPool pool{{.conninfo = db.dsn(), .size = 2}};
    CaStore store{pool};
    DefaultCertSet a;
    REQUIRE(ensure_default_certs(dir_a.path, "host", &store, a));
    REQUIRE(store.has_root());

    DefaultCertSet b;
    REQUIRE_FALSE(ensure_default_certs(dir_b.path, "host", &store, b)); // refuse, don't re-root
    REQUIRE_FALSE(b.freshly_generated);
    auto root_after = store.get_root();
    REQUIRE(root_after.has_value());
    REQUIRE(root_after->has_value());
    REQUIRE((*root_after)->fingerprint_sha256 == a.ca_fingerprint_sha256);
    REQUIRE(store.list_issued()->size() == 3); // dir_a's inventory untouched
}

TEST_CASE("default_certs: two concurrent self-heal resumes on ONE shared cert dir never "
          "produce a mismatched cert/key pair (Gate 8 fix, 2026-08-21)",
          "[default_certs][ca_store][security][pg]") {
    // Gate 8 (security-guardian + unhappy-path) found the self-heal ownership
    // proof — local key resolves + cryptographically pairs with the stored root
    // — is a STATIC predicate every process sharing the same cert directory
    // satisfies IDENTICALLY. It is not a claim/CAS, so without a lock, two such
    // processes (e.g. two HA replicas restarting against one shared volume,
    // which docs/user-manual/upgrading.md's ADR-0053 HA note explicitly
    // describes as supported) could both reach complete_default_cert_set()
    // concurrently: unsynchronized per-file renames could leave a purpose's
    // on-disk .pem from one racer and .key from the other, and both purges
    // could each delete the other's just-recorded rows. The fix wraps entry to
    // complete_default_cert_set() in a Postgres advisory lock + re-validate.
    //
    // ONE shared TempDir (not two, unlike the fresh-root race test above) — this
    // is the multi-process-same-volume topology the bug required.
    //
    // HONEST LIMITATION (advisor-flagged, verified empirically 2026-08-21):
    // this test does NOT reliably reproduce the pre-fix corruption — run 60x
    // against the pre-lock commit (f4631a78a) in a throwaway worktree, it
    // passed 60/60. The vulnerable window (two threads' fs::rename() calls to
    // the SAME cert/key paths landing in an interleaved, mismatched order) is
    // narrow enough that ordinary OS thread scheduling for two threads doing a
    // short burst of synchronous file I/O essentially never lands there in
    // practice, even though the race is real (confirmed by three independent
    // code readings: security-guardian, unhappy-path, cpp-safety — plain
    // rename() has no O_EXCL-equivalent collision detection, and nothing
    // serialized entry before this fix). This test still asserts genuinely
    // useful correctness properties (exactly 3 issued rows, every on-disk
    // cert/key pair cryptographically matched) and DOES catch a
    // fully-broken/absent lock (e.g. a lock that never actually blocks), but
    // is NOT proof the specific corruption class is closed — that closure
    // rests on the by-construction verification of the lock's mutual
    // exclusion (lease/guard destruction ordering), not on this test having
    // been shown red. Do not cite this test alone as red/green closure
    // evidence for Finding A in a governance ledger.
    TempDir dir;
    YUZU_REQUIRE_PG_DB_TPL(db, ca_store_tpl);
    yuzu::server::pg::PgPool pool{{.conninfo = db.dsn(), .size = 6}};
    CaStore store{pool};
    DefaultCertSet first;
    REQUIRE(ensure_default_certs(dir.path, "host", &store, first));
    REQUIRE(store.list_issued()->size() == 3);

    // Simulate the UP-2 crash window: on-disk incomplete, ca_store root +
    // local CA key both still intact — the self-heal precondition.
    std::error_code ec;
    std::filesystem::remove(first.server_key, ec);

    DefaultCertSet set_a, set_b;
    bool ok_a = false, ok_b = false;
    std::thread ta([&] { ok_a = ensure_default_certs(dir.path, "host", &store, set_a); });
    std::thread tb([&] { ok_b = ensure_default_certs(dir.path, "host", &store, set_b); });
    ta.join();
    tb.join();

    // Both resolve successfully: whichever wins the advisory lock re-mints;
    // whichever loses re-validates inside the lock, finds the winner's work
    // already complete, and uses it — neither refuses (the lock never times
    // out here; the critical section is milliseconds).
    CHECK(ok_a);
    CHECK(ok_b);

    // The root itself is untouched — self-heal never re-roots.
    auto root_after = store.get_root();
    REQUIRE(root_after.has_value());
    REQUIRE(root_after->has_value());
    REQUIRE((*root_after)->fingerprint_sha256 == first.ca_fingerprint_sha256);

    // The core assertion: exactly 3 issued rows survive (never 0 from a
    // cross-purge, never 6 from double-recording), and — the specific
    // corruption class Gate 8 identified — every on-disk cert/key pair still
    // cryptographically matches, proving no interleaved rename left a
    // purpose's .pem from one racer paired with the other racer's .key.
    auto issued = store.list_issued();
    REQUIRE(issued.has_value());
    REQUIRE(issued->size() == 3);
    for (const auto& rec : *issued) {
        REQUIRE_FALSE(rec.cert_pem.empty());
        REQUIRE(rec.issuer_fingerprint == first.ca_fingerprint_sha256);
    }
    const std::pair<std::filesystem::path, std::filesystem::path> pairs[] = {
        {first.https_cert, first.https_key},
        {first.server_cert, first.server_key},
        {first.gateway_cert, first.gateway_key},
    };
    for (const auto& [cert_path, key_path] : pairs) {
        REQUIRE(std::filesystem::exists(cert_path));
        REQUIRE(std::filesystem::exists(key_path));
        const std::string cert_pem = read_file(cert_path);
        const std::string key_pem = read_file(key_path);
        CHECK(pki::cert_matches_key(cert_pem, key_pem));
        CHECK(pki::verify_chain(cert_pem, read_file(first.ca_cert)));
    }
}

TEST_CASE("default_certs: a present-but-WRONG local key falls through to the B-2 refusal, "
          "not a crash (Gate 8 fix, 2026-08-21)",
          "[default_certs][ca_store][security][pg]") {
    // Gate 8 (security-guardian NICE): the self-heal branch's KeyZeroGuard used
    // to wrap the loaded key only AFTER cert_matches_key succeeded, leaving the
    // load-succeeds-but-match-fails case unwiped in freed heap. Also: this exact
    // branch had no coverage — the "still refuses" test above never reaches
    // load_key() at all (has_key() short-circuits for an absent file). This
    // exercises the present-but-mismatched path directly: a stale/mistaken
    // local key from a botched restore, real operational case per the Gate 8
    // report, not hypothetical.
    TempDir dir_a;
    YUZU_REQUIRE_PG_DB_TPL(db, ca_store_tpl);
    yuzu::server::pg::PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    CaStore store{pool};
    DefaultCertSet a;
    REQUIRE(ensure_default_certs(dir_a.path, "host-a", &store, a));

    // Plant an unrelated, real, well-formed EC P-384 key at the exact path
    // ca_store's root already points at — key PRESENT, but the WRONG one
    // (simulating a botched restore that copied the wrong CA key into place).
    const auto root = store.get_root();
    REQUIRE(root.has_value());
    REQUIRE(root->has_value());
    std::error_code ec;
    std::filesystem::remove(a.server_key, ec); // force past the idempotent fast path
    yuzu::server::FileKeyProvider dir_a_kp(dir_a.path);
    auto unrelated_key = pki::generate_private_key(pki::KeyAlgo::EcP384);
    REQUIRE(unrelated_key.has_value());
    REQUIRE(dir_a_kp.store_key("default-ca", *unrelated_key)); // overwrite dir_a's real key

    DefaultCertSet c;
    REQUIRE_FALSE(ensure_default_certs(dir_a.path, "host-a", &store, c)); // still refuses
    REQUIRE_FALSE(c.freshly_generated);
    auto root_after = store.get_root();
    REQUIRE(root_after.has_value());
    REQUIRE(root_after->has_value());
    REQUIRE((*root_after)->fingerprint_sha256 == a.ca_fingerprint_sha256); // unchanged
}

TEST_CASE("default_certs: a mismatched cert/key pair that lands on disk (however it got "
          "there) self-heals on the very next boot, never validates as intact forever "
          "(chaos-injector C5-1, Gate 5, 2026-08-21)",
          "[default_certs][ca_store][security][pg]") {
    // C5-1's scenario: the bootstrap advisory lock's holding connection could
    // die mid-critical-section (killed, idle-reaped, network-blackholed)
    // without the process dying, silently releasing the session lock while a
    // sibling racer's writes interleave with this attempt's still-in-flight
    // ones — potentially leaving one purpose's on-disk cert from one racer
    // paired with its key from the other. The fencing check added alongside
    // this test (a liveness round-trip immediately before the marker write)
    // closes the PREVENTION side; this test proves the DETECTION side: if a
    // mismatched pair ever lands on disk regardless of cause, it must not
    // validate as an intact, trustworthy set on every subsequent boot
    // (before this fix, try_use_existing_complete_set() chain-verified but
    // never checked key-pairing — a corrupted pair would have survived
    // undetected indefinitely, worse than the crash-recovery gap UP-2 itself
    // was about).
    TempDir dir;
    DefaultCertSet set;
    REQUIRE(ensure_default_certs(dir.path, "host", nullptr, set));
    REQUIRE(set.freshly_generated);

    // Simulate the corruption directly: swap the server leaf's key for an
    // unrelated (but real, well-formed) one — same shape as an interleaved
    // rename would produce, without needing to actually win the race.
    auto unrelated_key = pki::generate_private_key(pki::KeyAlgo::EcP256);
    REQUIRE(unrelated_key.has_value());
    {
        std::ofstream out_key(set.server_key, std::ios::binary | std::ios::trunc);
        out_key << *unrelated_key;
    }
    // Sanity: the corruption is real — chain verification alone does NOT
    // catch it (both the cert and the unrelated key are independently valid).
    REQUIRE(pki::verify_chain(read_file(set.server_cert), read_file(set.ca_cert)));
    REQUIRE_FALSE(pki::cert_matches_key(read_file(set.server_cert), *unrelated_key));

    DefaultCertSet healed;
    REQUIRE(ensure_default_certs(dir.path, "host", nullptr, healed));
    REQUIRE(healed.freshly_generated); // did NOT accept the corrupted set as intact
    // (No ca_store here, so regeneration mints a fresh CA — expected for this
    // no-PG mode; the self-heal-under-the-SAME-root case is covered
    // separately by the ca_store-backed self-heal tests above.)
    // Post-heal, every pair is genuinely consistent again.
    for (const auto& [cert_path, key_path] :
        {std::pair{healed.https_cert, healed.https_key},
         std::pair{healed.server_cert, healed.server_key},
         std::pair{healed.gateway_cert, healed.gateway_key}}) {
        CHECK(pki::cert_matches_key(read_file(cert_path), read_file(key_path)));
    }
}

TEST_CASE("default_certs: two racing first-boot instances never cross-purge each other's "
          "leaf inventory (architect review, 2026-08-21)",
          "[default_certs][ca_store][security][pg]") {
    // Two SEPARATE local --ca-dir trees (simulating two server instances) racing the
    // SAME shared ca_store, both starting from a genuinely empty root — the exact
    // first-boot race ADR-0053's try_insert_root() exists to resolve. Before the fix,
    // try_insert_root() ran AFTER leaf generation/record_issued(), so both instances
    // could pass the B-2 empty-root check, generate + record their own 3 leaves, and
    // whichever purged ("system:default-certs", an unscoped WHERE) SECOND would
    // delete the FIRST instance's already-committed rows — including the eventual
    // winner's, permanently orphaning its certs from ca_store. The fix moved
    // try_insert_root() before any leaf generation/purge/record_issued() call, so a
    // losing thread returns before touching ca_store's issued-cert table at all.
    //
    // NOTE (security-guardian, Gate 8 domain re-review of the UP-3 fix, 2026-08-21):
    // since dir_a/dir_b are SEPARATE, the loser's UP-3 poll loop (default_certs.cpp)
    // can never find the winner's files (they land in the OTHER directory) — this
    // test now incurs the full kLoserSelfHealPollWindow (15s) wall-clock cost on the
    // loser before it correctly falls back to refuse-and-restart. Expected, not a
    // regression; noted so a slower run of this specific test isn't mistaken for
    // infra flakiness.
    TempDir dir_a;
    TempDir dir_b;
    YUZU_REQUIRE_PG_DB_TPL(db, ca_store_tpl);
    yuzu::server::pg::PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    CaStore store{pool};
    REQUIRE(store.is_open());
    REQUIRE_FALSE(store.has_root()); // genuinely empty — the race precondition

    DefaultCertSet set_a, set_b;
    bool ok_a = false, ok_b = false;
    std::thread ta([&] { ok_a = ensure_default_certs(dir_a.path, "host-a", &store, set_a); });
    std::thread tb([&] { ok_b = ensure_default_certs(dir_b.path, "host-b", &store, set_b); });
    ta.join();
    tb.join();

    // Exactly one side wins (generates a root + writes local certs); the other loses
    // (try_insert_root reads back the winner's DIFFERENT fingerprint and refuses,
    // per the existing single-instance loser-discards-material contract).
    REQUIRE(ok_a != ok_b);
    const DefaultCertSet& winner = ok_a ? set_a : set_b;
    REQUIRE(winner.freshly_generated);

    auto root = store.get_root();
    REQUIRE(root.has_value());
    REQUIRE(root->has_value());
    REQUIRE((*root)->fingerprint_sha256 == winner.ca_fingerprint_sha256);

    // The core assertion: exactly the WINNER's 3 leaves survive — never 0 (the
    // pre-fix cross-purge defect), never 6 (both sides' leaves double-counted).
    auto issued = store.list_issued();
    REQUIRE(issued.has_value());
    REQUIRE(issued->size() == 3);
    for (const auto& rec : *issued) {
        REQUIRE_FALSE(rec.cert_pem.empty());
        REQUIRE(rec.issuer_fingerprint == winner.ca_fingerprint_sha256);
    }
}

TEST_CASE("default_certs: a losing HA replica self-heals from the shared cert dir instead "
          "of needing a restart (UP-3, built on operator request)",
          "[default_certs][ca_store][pg]") {
    // Same race as above, but ONE SHARED cert directory (the only topology where
    // self-heal is even possible — it reads the WINNER's material off the same
    // disk both instances point at) instead of two separate ones. Before this
    // fix, a loser returned false unconditionally, needing a process restart to
    // pick up the winner's certs.
    //
    // SIX racers, not two: with a shared dir, a loser that checks get_root()
    // AFTER the winner has already committed short-circuits through the
    // pre-existing UP-2 self-heal branch (it finds the winner's key already on
    // disk and adopts it there) WITHOUT ever reaching this fix's own code. The
    // new fingerprint-mismatch poll loop only fires for a racer whose OWN
    // get_root() gate saw EMPTY, generated its own candidate, and only THEN
    // lost the try_insert_root() CAS.
    //
    // DETERMINISTIC RENDEZVOUS AT THE CAS (was a 15-attempt retry-until-lucky
    // loop, #3475 — deflaked here). The old test spawned the six racers and
    // RETRIED the whole scenario up to 15× hoping the scheduler produced that
    // interleaving; under a loaded runner (Big Tam: four agents + parallel PG
    // shards) every racer's get_root() could land after the winner committed
    // all 15× — a hard, mechanism-less red. A thread-launch start barrier was
    // tried and measured WORSE (it synchronizes thread launch, not the
    // get_root()-vs-commit ordering that actually matters).
    //
    // The rendezvous IS the CAS itself, forced at the Postgres layer with ZERO
    // production-code change (mirrors test_engine_principal_store.cpp's side
    // lock and test_auth.cpp's pg_stat_activity observation): a side connection
    // holds `LOCK TABLE ca_store.ca_root IN EXCLUSIVE MODE`, which ADMITS the
    // six get_root() SELECTs (ACCESS SHARE) but BLOCKS the six try_insert_root
    // INSERTs (ROW EXCLUSIVE). Because no INSERT can commit while the lock is
    // held, every racer's earlier empty-root gate necessarily sees empty → every
    // racer generates a candidate → every racer reaches the CAS. We poll
    // pg_stat_activity until all six backends are genuinely WAITING on that lock
    // (a direct observation of the mechanism, not a wall-clock proxy), then
    // ROLLBACK to release them together: ON CONFLICT DO NOTHING picks exactly
    // one winner and the other five read back the winner's fingerprint — five
    // GENUINE UP-3 losers, every run. The losers then poll the shared dir for
    // the winner's on-disk complete set (the real kLoserSelfHealPollWindow poll
    // — NOT stubbed), so the self-heal wait is still genuinely exercised.
    //
    // The rendezvous also eliminates the CAPG-042 deferred-key-write refusal
    // window the retry version had to tolerate: that refusal requires the
    // top-of-function B-2 check to observe a COMMITTED root, which cannot happen
    // while the lock blocks every INSERT — so all six racers succeed and the
    // tolerance block is gone.
    constexpr int kRacers = 6;

    TempDir dir;
    YUZU_REQUIRE_PG_DB_TPL(db, ca_store_tpl);
    // Racer pool: lock_timeout raised well above the poll budget below so a
    // racer INSERT blocked on the side lock can never lock_timeout-error before
    // the unconditional ROLLBACK releases it (the 10s default would race a slow
    // sixth racer on a loaded box). Sized generously above server-admin.md's
    // "N+1 connections per racer needing the bootstrap lock" floor — several
    // racers independently reach the lock, each needing an outer lease plus
    // nested per-call leases; a small pool would hit that documented capacity
    // limit, a property of this test's exaggerated concurrency, not a defect.
    yuzu::server::pg::PgPool pool{{.conninfo = db.dsn(), .size = 32, .lock_timeout_ms = 60000}};
    CaStore store{pool};
    REQUIRE(store.is_open());
    REQUIRE_FALSE(store.has_root());

    // Side connection holds ca_store.ca_root EXCLUSIVE so every racer blocks at
    // its INSERT while its get_root() SELECT still passes. Manual BEGIN/LOCK/
    // ROLLBACK (PgConn's dtor also PQfinishes, tearing down any open txn) —
    // matches test_engine_principal_store.cpp's side-lock shape.
    yuzu::server::pg::PgConn locker{PQconnectdb(db.dsn().c_str())};
    REQUIRE(PQstatus(locker.get()) == CONNECTION_OK);
    REQUIRE(yuzu::server::pg::exec_params(locker.get(), "BEGIN", std::vector<std::string>{})
                .status() == PGRES_COMMAND_OK);
    REQUIRE(yuzu::server::pg::exec_params(locker.get(),
                                          "LOCK TABLE ca_store.ca_root IN EXCLUSIVE MODE",
                                          std::vector<std::string>{})
                .status() == PGRES_COMMAND_OK);

    // Dedicated connection for observing the blocked backends — pg_stat_activity
    // reflects live backend state synchronously, not an MVCC snapshot.
    yuzu::server::pg::PgConn watch{PQconnectdb(db.dsn().c_str())};
    REQUIRE(PQstatus(watch.get()) == CONNECTION_OK);

    std::array<DefaultCertSet, kRacers> sets;
    std::array<bool, kRacers> oks{};
    std::string logs;
    int observed = 0;        // written on the main thread while racers are joinable
    bool rollback_ok = false;
    {
        yuzu::test::LogCapture log;
        std::vector<std::thread> threads;
        threads.reserve(kRacers);
        for (int i = 0; i < kRacers; ++i) {
            threads.emplace_back([&, i] {
                oks[static_cast<size_t>(i)] = ensure_default_certs(
                    dir.path, "host-" + std::to_string(i), &store,
                    sets[static_cast<size_t>(i)]);
            });
        }
        // Poll (≤15s, 5ms interval — well under the racer pool's 60s
        // lock_timeout) until all six racers are genuinely WAITING on the
        // ca_store.ca_root lock. Scoped to THIS test's own database and
        // excluding this connection's own backend: pg_stat_activity is
        // cluster-wide and this repo runs many [pg] shards concurrently against
        // one Postgres under the same role and table names (#1871), so an
        // unscoped query could match an unrelated shard. NO Catch2 macro runs
        // in this window — the racer threads are still joinable, and a throwing
        // REQUIRE here would unwind past them and std::terminate the shard
        // (test_auth.cpp's documented hazard); only plain locals are written,
        // and std::atoi never throws (garbage → 0 → keep polling).
        for (int i = 0; i < 3000 && observed < kRacers; ++i) {
            yuzu::server::pg::PgResult res = yuzu::server::pg::exec_params(
                watch.get(),
                "SELECT count(*) FROM pg_stat_activity WHERE wait_event_type = 'Lock' "
                "AND query ILIKE '%INSERT INTO ca_store.ca_root%' "
                "AND datname = current_database() AND pid <> pg_backend_pid()",
                std::vector<std::string>{});
            if (res.status() == PGRES_TUPLES_OK && PQntuples(res.get()) == 1)
                observed = std::atoi(PQgetvalue(res.get(), 0, 0));
            if (observed >= kRacers)
                break;
            std::this_thread::sleep_for(std::chrono::milliseconds(5));
        }
        // Release the blocked INSERTs together — UNCONDITIONAL, so a racer that
        // never blocked (a genuine keygen/dir failure → oks[i]==false, caught
        // below) still completes and the threads can join rather than hang.
        rollback_ok =
            yuzu::server::pg::exec_params(locker.get(), "ROLLBACK", std::vector<std::string>{})
                .status() == PGRES_COMMAND_OK;
        for (auto& t : threads)
            t.join();
        log.stop();
        logs = log.text();
    }
    INFO("captured boot logs:\n" << logs);

    REQUIRE(rollback_ok);
    // Every racer reached the CAS and blocked on the side lock — the whole point
    // of the rendezvous. Fewer than six means the interleaving this test asserts
    // never formed (investigate — never retry away).
    REQUIRE(observed == kRacers);

    // All six succeed: under the lock no INSERT commits, so no racer's top-of-
    // function gate can see a committed root, so none diverts to UP-2 and none
    // hits the CAPG-042 deferred-key-write refusal window.
    REQUIRE(std::count(oks.begin(), oks.end(), true) == kRacers);

    // Exactly one racer won the CAS and generated; the other five lost it and
    // self-healed via the NEW poll-loop branch. COUNT occurrences, not mere
    // presence (a presence check would let one masked case hide another): the
    // loser needle "lost the first-boot CA-root race" (default_certs.cpp) is
    // distinct from ca_store.cpp's "LOST the first-boot race" (case-sensitive,
    // no "CA-root"), so == kRacers - 1 is exact.
    auto count_occurrences = [&](std::string_view needle) {
        std::size_t n = 0;
        for (std::size_t pos = logs.find(needle); pos != std::string::npos;
             pos = logs.find(needle, pos + needle.size()))
            ++n;
        return n;
    };
    REQUIRE(count_occurrences("lost the first-boot CA-root race") ==
            static_cast<std::size_t>(kRacers - 1));
    REQUIRE(count_occurrences("self-healed onto the winning root") ==
            static_cast<std::size_t>(kRacers - 1));

    // Exactly one racer actually generated; try_use_existing_complete_set()
    // never sets this true, so every self-healed loser reads false.
    const auto winners = std::count_if(sets.begin(), sets.end(),
                                       [](const auto& s) { return s.freshly_generated; });
    REQUIRE(winners == 1);

    auto root = store.get_root();
    REQUIRE(root.has_value());
    REQUIRE(root->has_value());

    // Every racer converges on the SAME winning root's material — no divergent
    // view, and nobody adopted its own discarded generation.
    for (int i = 0; i < kRacers; ++i)
        REQUIRE(sets[static_cast<size_t>(i)].ca_fingerprint_sha256 ==
               (*root)->fingerprint_sha256);

    // Still exactly 3 issued rows — no racer re-purges or re-records once it
    // adopts the winner's already-written set.
    auto issued = store.list_issued();
    REQUIRE(issued.has_value());
    REQUIRE(issued->size() == 3);

    // Every on-disk pair is genuinely consistent (every racer's `out` points at
    // the same shared dir, so this checks the one real set on disk).
    for (const auto& [cert_path, key_path] :
        {std::pair{sets[0].https_cert, sets[0].https_key},
         std::pair{sets[0].server_cert, sets[0].server_key},
         std::pair{sets[0].gateway_cert, sets[0].gateway_key}}) {
        CHECK(pki::cert_matches_key(read_file(cert_path), read_file(key_path)));
    }
}

TEST_CASE("default_certs: returns false (refuse) when the cert dir cannot be created",
          "[default_certs][negative]") {
    // The "ensure_default_certs-fails" refuse-to-start branch (#1238 B-6): a dir
    // that can't be created (here, a path that is an existing FILE) must make
    // ensure_default_certs return false — not crash, not half-generate — so the
    // bootstrap caller turns it into a clean refuse-to-start. (The startup_failed()
    // wiring itself is exercised by the live boot-test; ServerImpl::run starts a
    // real server, so it is not unit-constructible.)
    const auto file_path = yuzu::test::unique_temp_path("defcerts-not-a-dir-");
    {
        std::ofstream f(file_path);
        f << "this is a file, not a directory";
    }
    DefaultCertSet set;
    REQUIRE_FALSE(ensure_default_certs(file_path, "h", nullptr, set));
    REQUIRE_FALSE(set.freshly_generated);
    std::error_code ec;
    std::filesystem::remove(file_path, ec);
}

// ── --cert-group (multi-container shared-cert TLS, PKI #1289) ─────────────────
#ifndef _WIN32

namespace {
// {permission bits, owning gid} of a path; {0, -1} on stat failure.
std::pair<unsigned, gid_t> mode_and_gid(const std::filesystem::path& p) {
    struct stat st{};
    if (::stat(p.c_str(), &st) != 0)
        return {0u, static_cast<gid_t>(-1)};
    return {static_cast<unsigned>(st.st_mode) & 07777u, st.st_gid};
}
} // namespace

TEST_CASE("default_certs: --cert-group shares the dir + gateway key, keeps the rest tight",
          "[default_certs][security]") {
    TempDir dir;
    DefaultCertSet set;
    // Use the test process's OWN gid: chgrp to a group you belong to always
    // succeeds, so this drives the real apply_cert_group_share path deterministically.
    const std::string own_gid = std::to_string(static_cast<unsigned long>(::getgid()));
    REQUIRE(ensure_default_certs(dir.path, "h", nullptr, set, {}, own_gid));

    // Cert dir: 0750 + chgrp'd to the shared group (so a different-uid sibling
    // container can traverse it).
    auto [dmode, dgid] = mode_and_gid(dir.path);
    REQUIRE(dmode == 0750u);
    REQUIRE(dgid == ::getgid());

    // Gateway leaf key: group-readable (0640) for the gateway uid.
    auto [gkmode, gkgid] = mode_and_gid(set.gateway_key);
    REQUIRE(gkmode == 0640u);
    REQUIRE(gkgid == ::getgid());

    // The server + HTTPS private keys are NEVER group-shared — owner-only 0600.
    REQUIRE(mode_and_gid(set.server_key).first == 0600u);
    REQUIRE(mode_and_gid(set.https_key).first == 0600u);

    // Public certs stay world-readable (group + other read bits set).
    REQUIRE((mode_and_gid(set.ca_cert).first & 044u) == 044u);
}

TEST_CASE("default_certs: no --cert-group keeps the tight single-host posture (0700/0600)",
          "[default_certs][security]") {
    TempDir dir;
    DefaultCertSet set;
    REQUIRE(ensure_default_certs(dir.path, "h", nullptr, set)); // empty cert_group
    REQUIRE(mode_and_gid(dir.path).first == 0700u);             // owner-only dir
    REQUIRE(mode_and_gid(set.gateway_key).first == 0600u);      // key owner-only
}

TEST_CASE("default_certs: a bogus --cert-group falls back to tight perms (no boot-fail)",
          "[default_certs][security]") {
    TempDir dir;
    DefaultCertSet set;
    REQUIRE(ensure_default_certs(dir.path, "h", nullptr, set, {},
                                 "no-such-group-xyzzy-1289"));
    REQUIRE(mode_and_gid(dir.path).first == 0700u); // resolves nothing → tight
}

#endif // !_WIN32
