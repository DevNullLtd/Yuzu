// software_licensing daily-sync source tests (SLE, ADR-0024; roadmap §5 PR1
// test-matrix row test_licensing_sync). Covers the user_ref knob (default hash;
// collect pass-through; omit), HMAC pseudonym stability + distinctness, the
// k_agent no-leak guarantee (blob AND logs — roadmap R16), the empty-vs-error
// structural guard (primary- AND authoritative-surface errors skip; probable/
// heuristic surfaces incl. per-user hives do not; all-ok zero rows is a valid
// empty blob — ADR-0024 D3 / R15), the cfg| config
// record (D-10), blob stability, skip-unknown-kinds tolerance, and the R5
// over-cap skips. Plugin output is injected through a fake descriptor whose
// `list` action writes canned lines (mirrors test_inventory_sync's bulk
// fixture) — no real plugin, no network.

#include <catch2/catch_test_macros.hpp>

#include "local_dispatcher.hpp"
#include "sync_canonical.hpp" // sha256_hex
#include "sync_source_software_licensing.hpp"
#include "test_log_capture.hpp"

#include <yuzu/plugin.h>

#include <cstddef>
#include <map>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

using yuzu::agent::apply_user_ref_knob;
using yuzu::agent::LicRecord;
using yuzu::agent::make_software_licensing_source;
using yuzu::agent::parse_license_scan_output;
using yuzu::agent::parse_user_ref_mode;
using yuzu::agent::sha256_hex;
using yuzu::agent::SoftwareLicensingConfig;
using yuzu::agent::software_licensing_canonical_blob;
using yuzu::agent::SyncSource;
using yuzu::agent::user_ref_hmac16;
using yuzu::agent::user_ref_mode_token;
using yuzu::agent::UserRefMode;

namespace {

// ── fake license_scan descriptor: its `list` action emits whatever the current
//    test placed in g_list_output (one write → the captured output is exactly
//    that string). ───────────────────────────────────────────────────────────
std::string g_list_output;

int fake_list_execute(YuzuCommandContext* ctx, const char* action, const YuzuParam* /*params*/,
                      std::size_t /*param_count*/) {
    if (std::string_view(action) == "list") {
        yuzu_ctx_write_output(ctx, g_list_output.c_str());
        return 0;
    }
    return 1; // unknown action
}

const char* const kFakeActions[] = {"list", "surfaces", nullptr};

const YuzuPluginDescriptor kFakeDescriptor = {
    /*abi_version=*/YUZU_PLUGIN_ABI_VERSION,
    /*name=*/"license_scan",
    /*version=*/"1.0.0",
    /*description=*/"test-only license_scan fixture",
    /*actions=*/kFakeActions,
    /*init=*/nullptr,
    /*shutdown=*/nullptr,
    /*execute=*/fake_list_execute,
    /*sdk_version=*/nullptr,
};

// A fake KvStore backing the injected k_agent accessors.
struct FakeKv {
    std::map<std::string, std::string> m;
    bool fail_set = false; // simulate a persist failure (disk-full / SQLite-busy)

    SoftwareLicensingConfig config(UserRefMode mode) {
        SoftwareLicensingConfig c;
        c.user_ref_mode = mode;
        c.kv_get = [this](std::string_view k) -> std::string {
            auto it = m.find(std::string(k));
            return it == m.end() ? std::string{} : it->second;
        };
        c.kv_set = [this](std::string_view k, std::string_view v) -> bool {
            if (fail_set)
                return false; // NOT persisted → sync source must skip the cycle (D-11)
            m[std::string(k)] = std::string(v);
            return true;
        };
        return c;
    }
};

// Run one collect against the fake descriptor with the given canned output.
std::optional<std::pair<std::string, std::string>>
collect_with(const std::string& list_output, FakeKv& kv, UserRefMode mode) {
    g_list_output = list_output;
    SyncSource src = make_software_licensing_source(&kFakeDescriptor, kv.config(mode));
    return src.collect();
}

// A fully-populated per-user lic line for `profile`. expires_at is a midnight-UTC
// epoch (§3.1 wire contract: BIGINT epoch seconds, NOT a YYYY-MM-DD string) —
// 1798675200 = 2026-12-31T00:00:00Z.
std::string user_lic_line(std::string_view profile) {
    return std::string("lic|JetBrains IDEA|JetBrains|2024.1|subscription||subscription_active|"
                       "1798675200|license_file|probable|ABCD|idea64.exe|user|") +
           std::string(profile);
}

LicRecord user_record(std::string profile) {
    LicRecord r;
    r.product = "JetBrains IDEA";
    r.user_scope = "user";
    r.user_ref = std::move(profile);
    return r;
}

const std::string kKnownKeyHex(64, 'a'); // 32 bytes of 0xAA — a valid hex k_agent

} // namespace

// ─────────────────────────────────────────────────────────────────────────────
// knob modes
// ─────────────────────────────────────────────────────────────────────────────

TEST_CASE("user_ref knob: default is hash", "[licensing_sync][knob]") {
    CHECK(SoftwareLicensingConfig{}.user_ref_mode == UserRefMode::hash);
    CHECK(parse_user_ref_mode("hash") == UserRefMode::hash);
    CHECK(parse_user_ref_mode("collect") == UserRefMode::collect);
    CHECK(parse_user_ref_mode("omit") == UserRefMode::omit);
    CHECK_FALSE(parse_user_ref_mode("nonsense").has_value());
    CHECK_FALSE(parse_user_ref_mode("").has_value());
}

TEST_CASE("user_ref knob: collect passes the profile through", "[licensing_sync][knob]") {
    std::vector<LicRecord> recs = {user_record("jsmith")};
    apply_user_ref_knob(recs, UserRefMode::collect, "");
    CHECK(recs[0].user_ref == "jsmith");
}

TEST_CASE("user_ref knob: omit empties the identifier but keeps the record",
          "[licensing_sync][knob]") {
    std::vector<LicRecord> recs = {user_record("jsmith")};
    apply_user_ref_knob(recs, UserRefMode::omit, "");
    CHECK(recs[0].user_ref.empty());
    CHECK(recs[0].user_scope == "user"); // scope preserved — the probe is not suppressed
    CHECK(recs.size() == 1);             // the record itself stays
}

TEST_CASE("user_ref hash: a failed key persist skips the cycle (stable pseudonym, D-11)",
          "[licensing_sync][knob]") {
    FakeKv kv;
    kv.fail_set = true; // the HMAC key cannot be persisted (disk-full / SQLite-busy)
    auto out = collect_with(user_lic_line("jsmith"), kv, UserRefMode::hash);
    // The freshly-generated key could not persist → skip this cycle rather than emit a
    // user_ref hashed under a key that won't survive to the next cycle (an unstable
    // pseudonym: the same profile would map to a new user_ref next time).
    CHECK_FALSE(out.has_value());
    CHECK(kv.m.empty()); // nothing was persisted
}

TEST_CASE("user_ref knob: hash replaces the profile with a 16-hex pseudonym",
          "[licensing_sync][knob]") {
    std::vector<LicRecord> recs = {user_record("jsmith")};
    apply_user_ref_knob(recs, UserRefMode::hash, "raw-key-bytes-....");
    CHECK(recs[0].user_ref.size() == 16);
    CHECK(recs[0].user_ref != "jsmith");
    // 16 lowercase hex chars.
    for (char c : recs[0].user_ref)
        CHECK(((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f')));
}

// ─────────────────────────────────────────────────────────────────────────────
// HMAC pseudonym stability + distinctness (roadmap R16 / ADR-0024 D11)
// ─────────────────────────────────────────────────────────────────────────────

TEST_CASE("user_ref_hmac16: stable for the same key+profile, distinct per profile",
          "[licensing_sync][hmac]") {
    const std::string key(32, '\x11');
    // Deterministic across "restarts" (recomputation with the same inputs).
    CHECK(user_ref_hmac16(key, "jsmith") == user_ref_hmac16(key, "jsmith"));
    // Distinct profiles → distinct pseudonyms.
    CHECK(user_ref_hmac16(key, "alice") != user_ref_hmac16(key, "bob"));
    // A different key yields a different pseudonym for the same profile
    // (key regeneration = deliberate pseudonym rotation, R16).
    const std::string key2(32, '\x22');
    CHECK(user_ref_hmac16(key, "alice") != user_ref_hmac16(key2, "alice"));
    // 16 hex chars.
    CHECK(user_ref_hmac16(key, "alice").size() == 16);
}

TEST_CASE("k_agent persists across a source 'restart' → identical blob",
          "[licensing_sync][hmac]") {
    // First collect (no key yet) generates + persists k_agent; a second collect
    // sharing the SAME KvStore reads the persisted key → identical pseudonyms →
    // byte-identical blob (proves the key is not regenerated each cycle).
    FakeKv kv;
    const std::string out = user_lic_line("alice") + "\nprobe_status|slp_wmi|ok|1\n";

    auto r1 = collect_with(out, kv, UserRefMode::hash);
    REQUIRE(r1.has_value());
    // The key was generated + persisted (64 hex chars), NOT left empty.
    REQUIRE(kv.m.count(std::string(yuzu::agent::kUserRefHmacKeyName)) == 1);
    CHECK(kv.m[std::string(yuzu::agent::kUserRefHmacKeyName)].size() == 64);

    auto r2 = collect_with(out, kv, UserRefMode::hash);
    REQUIRE(r2.has_value());
    CHECK(r1->first == r2->first);   // identical blob
    CHECK(r1->second == r2->second); // identical hash
}

// ─────────────────────────────────────────────────────────────────────────────
// k_agent never leaks into the blob or the logs (roadmap R16)
// ─────────────────────────────────────────────────────────────────────────────

TEST_CASE("k_agent never appears in the blob or in captured logs", "[licensing_sync][r16]") {
    // Capture ALL log output at trace during the collect.
    yuzu::test::LogCapture cap;

    FakeKv kv;
    kv.m[std::string(yuzu::agent::kUserRefHmacKeyName)] = kKnownKeyHex; // known key
    const std::string out = user_lic_line("alice") + "\n" + user_lic_line("bob") +
                            "\nprobe_status|slp_wmi|ok|2\n";
    auto res = collect_with(out, kv, UserRefMode::hash);

    cap.stop(); // restore before asserting

    REQUIRE(res.has_value());
    const std::string& blob = res->first;
    const std::string logs = cap.text();

    // The hex-encoded key never appears in the blob or the logs.
    CHECK(blob.find(kKnownKeyHex) == std::string::npos);
    CHECK(logs.find(kKnownKeyHex) == std::string::npos);
    // Nor do the raw 32 key bytes (0xAA repeated).
    const std::string raw_key(32, '\xaa');
    CHECK(blob.find(raw_key) == std::string::npos);
    CHECK(logs.find(raw_key) == std::string::npos);
    // Sanity: the pseudonyms ARE present (the knob ran), so absence above is
    // meaningful and not a vacuous empty-blob pass.
    CHECK(blob.find(user_ref_hmac16(raw_key, "alice")) != std::string::npos);
}

// ─────────────────────────────────────────────────────────────────────────────
// empty profile stays empty in every mode (ADR-0024 D11: no SID, no hash-of-empty)
// ─────────────────────────────────────────────────────────────────────────────

TEST_CASE("an empty (unresolvable) profile stays empty in every mode",
          "[licensing_sync][knob]") {
    for (UserRefMode mode : {UserRefMode::collect, UserRefMode::hash, UserRefMode::omit}) {
        std::vector<LicRecord> recs = {user_record("")}; // unresolvable profile → empty
        apply_user_ref_knob(recs, mode, std::string(32, '\x11'));
        CHECK(recs[0].user_ref.empty());   // never hashed-empty-to-something
        CHECK(recs[0].user_scope == "user");
    }
    // The HMAC helper itself refuses to pseudonymise an empty profile.
    CHECK(user_ref_hmac16(std::string(32, '\x11'), "").empty());
}

// ─────────────────────────────────────────────────────────────────────────────
// cfg| config record (ADR-0024 D-10)
// ─────────────────────────────────────────────────────────────────────────────

TEST_CASE("blob carries exactly one cfg|user_ref|<mode> record at the front",
          "[licensing_sync][cfg]") {
    const std::string sep_field = "\x1f";
    const std::string sep_rec = "\x1e";
    for (UserRefMode mode : {UserRefMode::collect, UserRefMode::hash, UserRefMode::omit}) {
        std::string blob = software_licensing_canonical_blob({user_record("x")}, mode);
        const std::string expected_cfg =
            "cfg" + sep_field + "user_ref" + sep_field + std::string(user_ref_mode_token(mode)) +
            sep_rec;
        // cfg record is first (fixed position, blob-stable).
        CHECK(blob.rfind(expected_cfg, 0) == 0);
        // Exactly one cfg record.
        std::size_t count = 0;
        for (std::size_t p = blob.find("cfg" + sep_field + "user_ref"); p != std::string::npos;
             p = blob.find("cfg" + sep_field + "user_ref", p + 1))
            ++count;
        CHECK(count == 1);
    }
}

TEST_CASE("cfg| record is blob-stable and changes only with the mode",
          "[licensing_sync][cfg]") {
    std::vector<LicRecord> recs = {user_record("x")};
    CHECK(software_licensing_canonical_blob(recs, UserRefMode::hash) ==
          software_licensing_canonical_blob(recs, UserRefMode::hash));
    CHECK(software_licensing_canonical_blob(recs, UserRefMode::hash) !=
          software_licensing_canonical_blob(recs, UserRefMode::omit));
}

// ─────────────────────────────────────────────────────────────────────────────
// blob stability (ADR-0024 D3 blob-stability rule)
// ─────────────────────────────────────────────────────────────────────────────

TEST_CASE("blob is order-independent: same state, any collection order → same bytes",
          "[licensing_sync][stability]") {
    std::vector<LicRecord> a = {user_record("alice"), user_record("bob"), user_record("carol")};
    std::vector<LicRecord> b = {user_record("carol"), user_record("alice"), user_record("bob")};
    CHECK(software_licensing_canonical_blob(a, UserRefMode::collect) ==
          software_licensing_canonical_blob(b, UserRefMode::collect));
}

TEST_CASE("blob dedups identical records", "[licensing_sync][stability]") {
    std::vector<LicRecord> dup = {user_record("alice"), user_record("alice")};
    std::vector<LicRecord> one = {user_record("alice")};
    CHECK(software_licensing_canonical_blob(dup, UserRefMode::collect) ==
          software_licensing_canonical_blob(one, UserRefMode::collect));
}

TEST_CASE("two collects of identical state → identical hash", "[licensing_sync][stability]") {
    FakeKv kv;
    const std::string out = "lic|Office|Microsoft|2021|volume|kms|licensed||os_licensing_api|"
                            "authoritative|XXXXX||machine|\nprobe_status|slp_wmi|ok|1\n";
    auto r1 = collect_with(out, kv, UserRefMode::hash);
    auto r2 = collect_with(out, kv, UserRefMode::hash);
    REQUIRE(r1.has_value());
    REQUIRE(r2.has_value());
    CHECK(r1->second == r2->second);
    // The hash is the SHA-256 of exactly the blob bytes (the server hashes the
    // same raw bytes — ADR-0024 D-2).
    CHECK(r1->second == sha256_hex(r1->first));
}

// ─────────────────────────────────────────────────────────────────────────────
// empty-vs-error structural guard (ADR-0024 D3 / roadmap R15)
// ─────────────────────────────────────────────────────────────────────────────

TEST_CASE("parse flags a primary-surface error, not a per-user-hive error",
          "[licensing_sync][guard]") {
    CHECK(parse_license_scan_output("probe_status|slp_wmi|error|access_denied\n")
              .blocking_surface_error);
    CHECK(parse_license_scan_output("probe_status|pkg_metadata|error|rpm_query_failed\n")
              .blocking_surface_error);
    CHECK(parse_license_scan_output("probe_status|mas_receipt|error|io\n").blocking_surface_error);
    // Per-user hives are NEVER primary (R15) — their error does not skip.
    CHECK_FALSE(parse_license_scan_output("probe_status|per_user_hives|error|privilege_missing\n")
                    .blocking_surface_error);
    CHECK_FALSE(parse_license_scan_output("probe_status|per_user_files|error|enum_failed\n")
                    .blocking_surface_error);
    // An OK primary surface is not an error.
    CHECK_FALSE(parse_license_scan_output("probe_status|slp_wmi|ok|0\n").blocking_surface_error);
}

TEST_CASE("collect skips the cycle when a primary surface errors", "[licensing_sync][guard]") {
    FakeKv kv;
    // Even with some rows, a primary-surface error means the enumeration failed
    // → keep last good state, do not full-replace to (partial) empty.
    const std::string out = user_lic_line("alice") + "\nprobe_status|slp_wmi|error|access_denied\n";
    CHECK_FALSE(collect_with(out, kv, UserRefMode::hash).has_value());
}

TEST_CASE("a per-user-hive error alone does NOT skip the cycle", "[licensing_sync][guard]") {
    FakeKv kv;
    const std::string out = user_lic_line("alice") +
                            "\nprobe_status|slp_wmi|ok|1\n"
                            "probe_status|per_user_hives|error|privilege_missing\n";
    CHECK(collect_with(out, kv, UserRefMode::omit).has_value());
}

TEST_CASE("parse flags an AUTHORITATIVE-surface error, not a probable-surface error (F4)",
          "[licensing_sync][guard]") {
    // Authoritative SECONDARY surfaces block the cycle just like a primary surface
    // — dropping their records via full-replace on a transient error reads as
    // "licence gone" (ADR-0024 D3). entitlement_certs (RHEL subscription expiry)
    // and flexlm_lic (feature expiry) are authoritative.
    CHECK(parse_license_scan_output("probe_status|entitlement_certs|error|cert_parse_failed\n")
              .blocking_surface_error);
    CHECK(parse_license_scan_output("probe_status|flexlm_lic|error|read_failed\n")
              .blocking_surface_error);
    // Probable/heuristic secondary surfaces erroring do NOT block: their records
    // are not authoritative, so a transient error must not wipe stored state.
    CHECK_FALSE(parse_license_scan_output("probe_status|office_c2r|error|read_failed\n")
                    .blocking_surface_error);
    CHECK_FALSE(parse_license_scan_output("probe_status|per_user_files|error|enum_failed\n")
                    .blocking_surface_error);
    // OK on an authoritative surface is not an error.
    CHECK_FALSE(
        parse_license_scan_output("probe_status|entitlement_certs|ok|2\n").blocking_surface_error);
}

TEST_CASE("collect skips on an authoritative-surface error but proceeds on a probable one (F4)",
          "[licensing_sync][guard]") {
    const std::string lic =
        "lic|RHEL sub|Red Hat|9|subscription||subscription_active||entitlement_cert|"
        "authoritative|||machine|\n";
    {
        FakeKv kv;
        // entitlement_certs errors even though the primary pkg_metadata surface is
        // fine → keep last good, skip (don't full-replace the authoritative rows away).
        const std::string out = lic +
                                "probe_status|pkg_metadata|ok|1\n"
                                "probe_status|entitlement_certs|error|cert_parse_failed\n";
        CHECK_FALSE(collect_with(out, kv, UserRefMode::hash).has_value());
    }
    {
        FakeKv kv;
        // A probable surface (per-user files) errors with every blocking surface ok
        // → proceed (valid state, full-replace).
        const std::string out = lic +
                                "probe_status|pkg_metadata|ok|1\n"
                                "probe_status|entitlement_certs|ok|1\n"
                                "probe_status|per_user_files|error|enum_failed\n";
        CHECK(collect_with(out, kv, UserRefMode::hash).has_value());
    }
}

TEST_CASE("zero rows with all surfaces ok is a VALID empty blob (full-replace-to-empty)",
          "[licensing_sync][guard]") {
    FakeKv kv;
    const std::string out = "probe_status|slp_wmi|ok|0\nprobe_status|office_c2r|ok|0\n";
    auto res = collect_with(out, kv, UserRefMode::hash);
    REQUIRE(res.has_value()); // NOT skipped — empty is a legitimate state
    // The blob carries the cfg record but no lic record.
    CHECK(res->first.find("cfg\x1fuser_ref") != std::string::npos);
    CHECK(res->first.find("lic\x1f") == std::string::npos);
    CHECK(parse_license_scan_output(out).records.empty());
}

// ─────────────────────────────────────────────────────────────────────────────
// skip-unknown-kinds tolerance (ADR-0024 D3 forward-compat)
// ─────────────────────────────────────────────────────────────────────────────

TEST_CASE("parse keeps lic| only and tolerates unknown/blank kinds",
          "[licensing_sync][forward-compat]") {
    const std::string out =
        "lic|Prod A|VendA|1|perpetual||licensed||registry_probe|probable|K|a.exe|machine|\n"
        "ent|Prod|Vend|feature|10|3|subscription|1798761600|flexlm|host:27000\n" // PR2 kind; term_end epoch 2027-01-01T00:00:00Z
        "cfg|user_ref|collect\n"    // config kind (source-emitted, not from plugin)
        "junk|whatever|stuff\n"     // unknown kind
        "\n"                        // blank
        "lic|Prod B|VendB|2|oem||licensed||registry_probe|probable|K2|b.exe|machine|\n"
        "probe_status|slp_wmi|ok|2\n";
    auto parsed = parse_license_scan_output(out);
    REQUIRE(parsed.records.size() == 2);
    CHECK(parsed.records[0].product == "Prod A");
    CHECK(parsed.records[1].product == "Prod B");
    CHECK_FALSE(parsed.blocking_surface_error);
}

TEST_CASE("parse drops a lic row with an empty product (no identity)",
          "[licensing_sync][forward-compat]") {
    // Leading empty product field → dropped (mirrors the server seam).
    auto parsed = parse_license_scan_output("lic||Vend|1|perpetual||licensed||heuristic|probable|"
                                            "||machine|\n");
    CHECK(parsed.records.empty());
}

// ─────────────────────────────────────────────────────────────────────────────
// over-cap skips (roadmap R5)
// ─────────────────────────────────────────────────────────────────────────────

TEST_CASE("collect skips when the record count reaches the cap", "[licensing_sync][cap]") {
    FakeKv kv;
    std::string out;
    out.reserve(10001 * 40);
    for (int i = 0; i < 10001; ++i)
        out += "lic|Prod" + std::to_string(i) +
               "|V|1|perpetual||licensed||registry_probe|probable|||machine|\n";
    // >= kMaxRecords lic rows would push the blob (with the cfg record) past the
    // server's record cap → skip rather than send an un-storable payload.
    CHECK_FALSE(collect_with(out, kv, UserRefMode::hash).has_value());
}

TEST_CASE("collect skips when the blob exceeds the 1 MiB byte cap", "[licensing_sync][cap]") {
    FakeKv kv;
    // ~1200 distinct records × ~1000-byte products ≈ 1.2 MiB blob, under the
    // 10k record cap but over the 1 MiB byte cap.
    std::string out;
    out.reserve(1200 * 1050);
    const std::string big(1000, 'a');
    for (int i = 0; i < 1200; ++i)
        out += "lic|" + big + std::to_string(i) +
               "|V|1|perpetual||licensed||registry_probe|probable|||machine|\n";
    CHECK_FALSE(collect_with(out, kv, UserRefMode::hash).has_value());
}

// ─────────────────────────────────────────────────────────────────────────────
// misc collect behaviour
// ─────────────────────────────────────────────────────────────────────────────

TEST_CASE("collect is idle when the license_scan plugin is not loaded",
          "[licensing_sync]") {
    SoftwareLicensingConfig cfg;
    cfg.user_ref_mode = UserRefMode::hash;
    SyncSource src = make_software_licensing_source(nullptr, std::move(cfg));
    CHECK_FALSE(src.collect().has_value());
}

TEST_CASE("collect in collect-mode passes the raw profile through to the blob",
          "[licensing_sync][knob]") {
    FakeKv kv;
    const std::string out = user_lic_line("jsmith") + "\nprobe_status|slp_wmi|ok|1\n";
    auto res = collect_with(out, kv, UserRefMode::collect);
    REQUIRE(res.has_value());
    CHECK(res->first.find("jsmith") != std::string::npos); // raw name present (opt-in)
    // No k_agent is generated in collect mode.
    CHECK(kv.m.count(std::string(yuzu::agent::kUserRefHmacKeyName)) == 0);
}

TEST_CASE("collect in omit-mode drops the profile from the blob", "[licensing_sync][knob]") {
    FakeKv kv;
    const std::string out = user_lic_line("jsmith") + "\nprobe_status|slp_wmi|ok|1\n";
    auto res = collect_with(out, kv, UserRefMode::omit);
    REQUIRE(res.has_value());
    CHECK(res->first.find("jsmith") == std::string::npos); // identifier suppressed
    CHECK(res->first.find("cfg\x1fuser_ref\x1fomit") != std::string::npos);
}
