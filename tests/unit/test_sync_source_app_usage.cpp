// app_usage daily-sync source tests (wave 7 PR7.2 / adjudication P5). Covers
// the `last_used` wire parse (field order, malformed-line tolerance,
// empty-exe_key drop, escaped-pipe exe_key round-trip), the `constrained|...`
// skip-cycle guard (never an empty replace), blob framing (leading
// cfg|scope|machine + sorted/deduped lu| records), the plugin-not-loaded idle
// path, and SyncScheduler composition with an injected tick. Plugin output is
// injected through a fake descriptor whose `last_used` action writes canned
// lines (mirrors test_licensing_sync.cpp's fixture pattern) — no real plugin,
// no network, no real clocks or spawns.
//
// FIXTURE PROVENANCE: the `last_used|` lines below are hand-built to the exact
// byte shape `agents/plugins/app_usage/src/app_usage_parsers.hpp`'s
// `format_last_used_row` emits (pinned by that file's own
// test_app_usage_parsers.cpp `format_last_used_row shapes` case) — this
// engineer package cannot build/run the app_usage plugin (no builds
// permitted; static verification only), so this is a shape-accurate
// hand-construction, NOT a live LocalDispatcher capture off the real dylib.
// Flagged in the package report for the integrator to swap in (or corroborate
// with) a real capture if higher fidelity is wanted.

#include <catch2/catch_test_macros.hpp>

#include "app_usage_parsers.hpp" // format_last_used_row -- real plugin formatter, for the format+parse round trip
#include "local_dispatcher.hpp"
#include "sync_canonical.hpp" // sha256_hex
#include "sync_scheduler.hpp"
#include "sync_source_app_usage.hpp"

#include <yuzu/plugin.h>

#include <cstddef>
#include <cstdint>
#include <optional>
#include <string>
#include <string_view>
#include <unordered_map>
#include <utility>
#include <vector>

using yuzu::agent::AppUsageParse;
using yuzu::agent::AppUsageRow;
using yuzu::agent::make_app_usage_source;
using yuzu::agent::parse_app_usage_last_used_output;
using yuzu::agent::render_app_usage_blob;
using yuzu::agent::sha256_hex;
using yuzu::agent::SyncScheduler;
using yuzu::agent::SyncSource;
using yuzu::app_usage::format_last_used_row;
using yuzu::app_usage::LastUsedRow;

namespace {

// ── fake app_usage descriptor: its `last_used` action emits whatever the
//    current test placed in g_output. ────────────────────────────────────────
std::string g_output;
int g_rc = 0;

int fake_execute(YuzuCommandContext* ctx, const char* action, const YuzuParam* /*params*/,
                 std::size_t /*param_count*/) {
    if (std::string_view(action) == "last_used") {
        yuzu_ctx_write_output(ctx, g_output.c_str());
        return g_rc;
    }
    return 1; // unknown action
}

const char* const kFakeActions[] = {"last_used", nullptr};

const YuzuPluginDescriptor kFakeDescriptor = {
    /*abi_version=*/YUZU_PLUGIN_ABI_VERSION,
    /*name=*/"app_usage",
    /*version=*/"1.0.0",
    /*description=*/"test-only app_usage fixture",
    /*actions=*/kFakeActions,
    /*init=*/nullptr,
    /*shutdown=*/nullptr,
    /*execute=*/fake_execute,
    /*sdk_version=*/nullptr,
};

// A server-style unescaped-pipe splitter, used ONLY by the round-trip test to
// prove the rendered blob recovers the original exe_key the way the server's
// own decoder would (mirrors result_parsing.hpp's find_unescaped_pipe, but
// this is test-local — it does not exercise the server code).
std::vector<std::string> split_on_framing(const std::string& blob, char sep) {
    std::vector<std::string> parts;
    std::size_t pos = 0;
    while (pos <= blob.size()) {
        auto p = blob.find(sep, pos);
        if (p == std::string::npos) {
            parts.push_back(blob.substr(pos));
            break;
        }
        parts.push_back(blob.substr(pos, p - pos));
        pos = p + 1;
    }
    return parts;
}

} // namespace

// ── parse: wire shape ────────────────────────────────────────────────────────

TEST_CASE("parse: last_used| rows project exe_key/last_seen/first_seen/run_count/"
          "total_seconds",
          "[app_usage_sync][parse]") {
    // Shape-accurate to format_last_used_row: last_used|<exe_key>|<last_seen>|
    // <first_seen>|<run_count_30d>|<total_seconds_30d>.
    const std::string captured = "last_used|chrome.exe|1700000500|1699000000|12|43200\n";
    AppUsageParse p = parse_app_usage_last_used_output(captured);
    REQUIRE(p.rows.size() == 1);
    CHECK_FALSE(p.constrained);
    CHECK(p.rows[0].exe_key == "chrome.exe");
    CHECK(p.rows[0].last_seen == 1700000500);
    CHECK(p.rows[0].first_seen == 1699000000);
    CHECK(p.rows[0].run_count_30d == 12);
    CHECK(p.rows[0].total_seconds_30d == 43200);
}

TEST_CASE("parse: multiple rows, blank lines and CRLF are tolerated",
          "[app_usage_sync][parse]") {
    const std::string captured = "last_used|chrome.exe|1700000500|1699000000|12|43200\r\n"
                                 "\r\n"
                                 "last_used|word.exe|1700000600|1698000000|3|900\n";
    AppUsageParse p = parse_app_usage_last_used_output(captured);
    REQUIRE(p.rows.size() == 2);
    CHECK(p.rows[0].exe_key == "chrome.exe");
    CHECK(p.rows[1].exe_key == "word.exe");
}

TEST_CASE("parse: a malformed (too-short) last_used line is skipped, not fatal",
          "[app_usage_sync][parse]") {
    const std::string captured = "last_used|chrome.exe|1700000500\n"
                                 "last_used|word.exe|1700000600|1698000000|3|900\n";
    AppUsageParse p = parse_app_usage_last_used_output(captured);
    REQUIRE(p.rows.size() == 1);
    CHECK(p.rows[0].exe_key == "word.exe");
}

TEST_CASE("parse: an empty exe_key row is dropped (no row identity)",
          "[app_usage_sync][parse]") {
    const std::string captured = "last_used||1700000500|1699000000|12|43200\n"
                                 "last_used|word.exe|1700000600|1698000000|3|900\n";
    AppUsageParse p = parse_app_usage_last_used_output(captured);
    REQUIRE(p.rows.size() == 1);
    CHECK(p.rows[0].exe_key == "word.exe");
}

TEST_CASE("parse: negative numeric fields clamp to 0", "[app_usage_sync][parse]") {
    const std::string captured = "last_used|chrome.exe|-5|-9|-1|-100\n";
    AppUsageParse p = parse_app_usage_last_used_output(captured);
    REQUIRE(p.rows.size() == 1);
    CHECK(p.rows[0].last_seen == 0);
    CHECK(p.rows[0].first_seen == 0);
    CHECK(p.rows[0].run_count_30d == 0);
    CHECK(p.rows[0].total_seconds_30d == 0);
}

// Governance Gate 8 (quality-engineer): regression for parse_i64's trailing-
// garbage fix (Gate 7 round 2) -- a valid numeric PREFIX followed by
// non-digit trailing bytes must parse to 0, not silently to the prefix's
// value. std::from_chars alone reports success for "1700000500x" (ec ==
// std::errc{}), so the fix requires checking the end pointer too.
TEST_CASE("parse: a valid-prefix-then-garbage numeric field parses to 0, not the prefix value",
          "[app_usage_sync][parse]") {
    const std::string captured = "last_used|chrome.exe|1700000500x|1699000000|12|43200\n";
    AppUsageParse p = parse_app_usage_last_used_output(captured);
    REQUIRE(p.rows.size() == 1);
    CHECK(p.rows[0].last_seen == 0); // not 1700000500
    CHECK(p.rows[0].first_seen == 1699000000);
    CHECK(p.rows[0].run_count_30d == 12);
    CHECK(p.rows[0].total_seconds_30d == 43200);
}

TEST_CASE("parse: unknown line kinds are skipped without error (forward-compat)",
          "[app_usage_sync][parse]") {
    const std::string captured = "meta|window_days|30|coverage_since|-\n"
                                 "last_used|chrome.exe|1700000500|1699000000|12|43200\n"
                                 "error|bad_param|by\n"
                                 "totally_new_kind|x|y\n";
    AppUsageParse p = parse_app_usage_last_used_output(captured);
    REQUIRE(p.rows.size() == 1);
    CHECK_FALSE(p.constrained);
}

// ── parse: escaped pipe in exe_key (adjudication P5) ─────────────────────────

TEST_CASE("parse: an escaped pipe in exe_key round-trips to a literal pipe",
          "[app_usage_sync][parse][P5]") {
    // The producer escapes a literal '|' in exe_key as `\|`; the unescaped
    // pipes inside exe_key must NOT be treated as field separators.
    const std::string captured = "last_used|a\\|b.exe|1700000500|1699000000|12|43200\n";
    AppUsageParse p = parse_app_usage_last_used_output(captured);
    REQUIRE(p.rows.size() == 1);
    CHECK(p.rows[0].exe_key == "a|b.exe");
    CHECK(p.rows[0].last_seen == 1700000500);
    CHECK(p.rows[0].first_seen == 1699000000);
    CHECK(p.rows[0].run_count_30d == 12);
    CHECK(p.rows[0].total_seconds_30d == 43200);
}

TEST_CASE("format -> parse: a >320-byte pipe-heavy exe_key round-trips intact — no "
          "truncation, no row loss (fixed-buffer overflow regression)",
          "[app_usage_sync][parse][P5]") {
    // Real plugin formatter (app_usage_parsers.hpp), not a hand-built fixture:
    // format_last_used_row used to snprintf into a fixed 320-byte stack buffer
    // with no truncation check. Neither normalise_exe_key nor TAR's own writer
    // caps executable-name length, and pipe-escaping roughly doubles a
    // pipe-heavy name's length, so a real basename could silently overflow
    // that buffer — and the daily-sync consumer below then DROPS (rather than
    // errors on) a resulting malformed/short row (`tok.size() < 6` -> skip).
    std::string long_exe_key;
    for (int i = 0; i < 40; ++i)
        long_exe_key += "abcdefghi|"; // 40 * 10 = 400 raw bytes, 40 literal pipes
    REQUIRE(long_exe_key.size() == 400);

    LastUsedRow row;
    row.exe_key = long_exe_key;
    row.last_seen = 1700000500;
    row.first_seen = 1699000000;
    row.run_count_30d = 12345;
    row.total_seconds_30d = 999999999;

    const std::string formatted = format_last_used_row(row);
    // Escaping every '|' as "\|" adds 40 bytes on top of the 400-byte raw
    // exe_key alone — well past the old 320-byte buffer once the
    // "last_used|" prefix and four numeric fields are added too.
    REQUIRE(formatted.size() > 320);

    AppUsageParse p = parse_app_usage_last_used_output(formatted + "\n");
    REQUIRE(p.rows.size() == 1); // not dropped as malformed
    CHECK(p.rows[0].exe_key == long_exe_key); // recovered byte-for-byte, not truncated
    CHECK(p.rows[0].last_seen == 1700000500);
    CHECK(p.rows[0].first_seen == 1699000000);
    CHECK(p.rows[0].run_count_30d == 12345);
    CHECK(p.rows[0].total_seconds_30d == 999999999);
}

TEST_CASE("parse: raw framing bytes in exe_key are stripped before render — record "
          "count unchanged, field count still 6",
          "[app_usage_sync][parse][P5]") {
    // A hostile/corrupt exe_key carrying the canonical framing bytes (0x1E
    // record sep / 0x1F field sep / NUL) directly, not via the plugin's own
    // escape — clamp_field (sync_canonical.hpp) strips these unconditionally,
    // so the row survives (not dropped) and the blob's structure can never be
    // corrupted by it.
    const std::string exe_key_raw = std::string("evil") + '\x1e' + "x" + '\x1f' + "y" + '\0' + "z";
    const std::string captured =
        "last_used|" + exe_key_raw + "|1700000500|1699000000|12|43200\n";
    AppUsageParse p = parse_app_usage_last_used_output(captured);
    REQUIRE(p.rows.size() == 1); // record count unchanged
    CHECK(p.rows[0].exe_key.find('\x1e') == std::string::npos);
    CHECK(p.rows[0].exe_key.find('\x1f') == std::string::npos);
    CHECK(p.rows[0].exe_key.find('\0') == std::string::npos);

    std::string blob = render_app_usage_blob(p.rows);
    // Exactly one lu| record after the cfg| record, and that record still
    // carries all 6 fields (kind + 5) once split on the real framing bytes.
    auto records = split_on_framing(blob, '\x1e');
    // records: [cfg-record, lu-record, "" trailing]
    REQUIRE(records.size() == 3);
    auto lu_fields = split_on_framing(records[1], '\x1f');
    CHECK(lu_fields.size() == 6); // field count still 6 (kind + 5 data fields)
}

// ── parse: constrained (never an empty blob) ─────────────────────────────────

TEST_CASE("parse: a constrained| line sets constrained and stops collecting rows",
          "[app_usage_sync][parse]") {
    SECTION("usage source disabled") {
        AppUsageParse p = parse_app_usage_last_used_output("constrained|usage_source_disabled\n");
        CHECK(p.constrained);
        CHECK(p.rows.empty());
    }
    SECTION("tar.db unavailable, with prior rows in the buffer") {
        // Even if rows had somehow already been captured, a constrained
        // report must not be treated as a valid detected-empty state.
        AppUsageParse p = parse_app_usage_last_used_output(
            "last_used|chrome.exe|1700000500|1699000000|12|43200\n"
            "constrained|tar_db_unavailable|/var/lib/yuzu/agent/tar.db|no such file\n");
        CHECK(p.constrained);
    }
}

// Governance Gate 2 finding (round-3 app_usage remediation): does the
// plugin's NEW trailing `constrained|last_used_truncated|<cap>` marker (added
// after exactly kMaxLastUsedRows=5000 real last_used| rows, when the plugin
// hit its own cap) get parsed as a genuine `constrained` capture here and
// discard all 5000 real rows? This parser's OWN loop condition
// (`out.rows.size() < kMaxRecords`, kMaxRecords=5000, coincidentally the same
// cap value as the plugin's) already terminates BEFORE the trailing marker
// line is ever read, once exactly 5000 last_used| rows have been collected --
// so the marker is provably unreachable by this parser in the boundary case
// that matters (the plugin's cap and this parser's cap being equal). This
// test locks that in: `constrained` stays false and all 5000 real rows
// survive parsing (make_app_usage_source's own separate
// `rows.size() >= kMaxRecords` guard then skips the cycle regardless --
// pre-existing behaviour, unrelated to and unaffected by the new marker).
TEST_CASE("parse: the plugin's trailing last_used_truncated marker, at exactly "
         "the parser's own kMaxRecords boundary, is never reached -- all real "
         "rows survive and constrained stays false",
          "[app_usage_sync][parse][regression]") {
    constexpr int kMaxRecords = 5000; // mirrors the file-local constant under test
    std::string captured;
    captured.reserve(static_cast<std::size_t>(kMaxRecords) * 40);
    for (int i = 0; i < kMaxRecords; ++i) {
        captured += "last_used|exe_" + std::to_string(i) + "|1700000000|1699000000|1|60\n";
    }
    captured += "constrained|last_used_truncated|5000\n";

    AppUsageParse p = parse_app_usage_last_used_output(captured);
    CHECK_FALSE(p.constrained);
    CHECK(p.rows.size() == static_cast<std::size_t>(kMaxRecords));
}

// ── render: blob framing ─────────────────────────────────────────────────────

TEST_CASE("render: leading cfg|scope|machine record, then sorted+deduped lu| records",
          "[app_usage_sync][render]") {
    std::vector<AppUsageRow> rows;
    rows.push_back({"word.exe", 1698000000, 1700000600, 3, 900});
    rows.push_back({"chrome.exe", 1699000000, 1700000500, 12, 43200});
    rows.push_back({"chrome.exe", 1699000000, 1700000500, 12, 43200}); // exact dup
    std::string blob = render_app_usage_blob(rows);
    CHECK(blob.rfind("cfg\x1fscope\x1fmachine\x1e", 0) == 0);
    const std::string chrome_rec =
        "lu\x1f"
        "chrome.exe\x1f"
        "1699000000\x1f"
        "1700000500\x1f"
        "12\x1f"
        "43200\x1e";
    const std::string word_rec =
        "lu\x1f"
        "word.exe\x1f"
        "1698000000\x1f"
        "1700000600\x1f"
        "3\x1f"
        "900\x1e";
    // Deduped: exactly one chrome.exe record, sorted before word.exe.
    CHECK(blob == "cfg\x1fscope\x1fmachine\x1e" + chrome_rec + word_rec);
}

TEST_CASE("render: an empty row set still carries the cfg| record",
          "[app_usage_sync][render]") {
    std::string blob = render_app_usage_blob({});
    CHECK(blob == "cfg\x1fscope\x1fmachine\x1e");
}

TEST_CASE("render: an escaped-pipe exe_key renders intact and a server-style split "
          "on the framing bytes recovers the original string",
          "[app_usage_sync][render][P5]") {
    AppUsageParse p =
        parse_app_usage_last_used_output("last_used|a\\|b.exe|1700000500|1699000000|12|43200\n");
    REQUIRE(p.rows.size() == 1);
    REQUIRE(p.rows[0].exe_key == "a|b.exe");

    std::string blob = render_app_usage_blob(p.rows);
    auto records = split_on_framing(blob, '\x1e');
    REQUIRE(records.size() == 3); // cfg, lu, trailing empty
    auto lu_fields = split_on_framing(records[1], '\x1f');
    REQUIRE(lu_fields.size() == 6);
    // The literal pipe survived render unescaped (the blob's structural
    // separators are 0x1E/0x1F, not '|' — a raw '|' in a field is inert), so
    // a server-style split on the REAL framing bytes recovers it whole.
    CHECK(lu_fields[1] == "a|b.exe");
}

TEST_CASE("hash: sha256_hex is deterministic over the rendered blob",
          "[app_usage_sync][hash]") {
    std::vector<AppUsageRow> rows = {{"chrome.exe", 1699000000, 1700000500, 12, 43200}};
    const std::string blob1 = render_app_usage_blob(rows);
    const std::string blob2 = render_app_usage_blob(rows);
    CHECK(blob1 == blob2);
    CHECK(sha256_hex(blob1) == sha256_hex(blob2));
}

// ── make_app_usage_source: collect() end-to-end via the fake descriptor ─────

TEST_CASE("make_app_usage_source: null descriptor idles (plugin not loaded)",
          "[app_usage_sync][source]") {
    SyncSource src = make_app_usage_source(nullptr);
    CHECK(src.name == "app_usage");
    CHECK_FALSE(src.collect().has_value());
}

TEST_CASE("make_app_usage_source: a normal capture yields a blob + hash",
          "[app_usage_sync][source]") {
    g_output = "last_used|chrome.exe|1700000500|1699000000|12|43200\n";
    g_rc = 0;
    SyncSource src = make_app_usage_source(&kFakeDescriptor);
    auto result = src.collect();
    REQUIRE(result.has_value());
    CHECK(result->first.find("chrome.exe") != std::string::npos);
    CHECK(result->second == sha256_hex(result->first));
}

TEST_CASE("make_app_usage_source: a constrained capture skips the cycle — never an "
          "empty blob",
          "[app_usage_sync][source]") {
    g_output = "constrained|usage_source_disabled\n";
    g_rc = 0;
    SyncSource src = make_app_usage_source(&kFakeDescriptor);
    CHECK_FALSE(src.collect().has_value());
}

TEST_CASE("make_app_usage_source: a nonzero plugin rc skips the cycle",
          "[app_usage_sync][source]") {
    g_output = "unavailable|query_failed|disk error\n";
    g_rc = 1;
    SyncSource src = make_app_usage_source(&kFakeDescriptor);
    CHECK_FALSE(src.collect().has_value());
    g_rc = 0; // restore for any later test ordering
}

// ── SyncScheduler composition: real scheduler, injected tick, in-memory kv ──

TEST_CASE("make_app_usage_source: composes into a real SyncScheduler and sends a "
          "full payload on first fire",
          "[app_usage_sync][source][scheduler]") {
    g_output = "last_used|chrome.exe|1700000500|1699000000|12|43200\n";
    g_rc = 0;

    std::unordered_map<std::string, std::string> kv;
    auto kv_get = [&kv](const std::string& key) -> std::string {
        auto it = kv.find(key);
        return it == kv.end() ? std::string{} : it->second;
    };
    auto kv_set = [&kv](const std::string& key, const std::string& value) { kv[key] = value; };

    std::vector<std::pair<std::string, std::string>> sent_hashes;
    std::vector<std::pair<std::string, std::string>> sent_blobs;
    auto sender = [&](const std::vector<std::pair<std::string, std::string>>& hashes,
                      const std::vector<std::pair<std::string, std::string>>& blobs)
        -> std::optional<std::vector<std::string>> {
        sent_hashes = hashes;
        sent_blobs = blobs;
        return std::vector<std::string>{}; // no need_full
    };

    SyncScheduler scheduler("test-agent", kv_get, kv_set, sender);
    scheduler.add_source(make_app_usage_source(&kFakeDescriptor));

    // First tick at an arbitrary but fixed epoch — no real clock, no sleep.
    // A first-ever run is jittered (kStartupJitterWindow, sync_scheduler.hpp)
    // by a stable per-(agent,source) offset, so this tick only persists
    // `next_fire` — it does not itself reach collection. Tick again at the
    // persisted `next_fire` to land on the (now-due) source.
    scheduler.tick(1700000000);
    scheduler.tick(std::stoll(kv.at("sync.app_usage.next_fire")));

    REQUIRE(sent_hashes.size() == 1);
    CHECK(sent_hashes[0].first == "app_usage");
    REQUIRE(sent_blobs.size() == 1); // first-ever sync sends the full payload
    CHECK(sent_blobs[0].first == "app_usage");
    CHECK(sent_blobs[0].second.find("chrome.exe") != std::string::npos);
    CHECK(sent_hashes[0].second == sha256_hex(sent_blobs[0].second));
}

// ── make_app_usage_source: cap-recovery guards (never partial/oversized) ────

TEST_CASE("make_app_usage_source: a capture at the byte cap is truncated and the "
          "cycle is skipped",
          "[app_usage_sync][source][caps]") {
    // A single write past LocalDispatcher::kCaptureMaxBytes (2 MiB) sets
    // r.truncated — the source must skip rather than sync a partial,
    // hash-unstable payload.
    g_rc = 0;
    g_output.assign(2u * 1024 * 1024 + 1, 'x');
    CHECK_FALSE(make_app_usage_source(&kFakeDescriptor).collect().has_value());
}

TEST_CASE("make_app_usage_source: hitting the record cap skips the cycle, before "
          "dedup could hide it",
          "[app_usage_sync][source][caps]") {
    // 5000 identical rows: parse's own `out.rows.size() < kMaxRecords` loop
    // guard fills to exactly kMaxRecords BEFORE render-time dedup would
    // collapse them to one — the >= kMaxRecords check must fire on the
    // pre-dedup count, not let a duplicate-heavy capture slip through.
    g_rc = 0;
    g_output.clear();
    for (int i = 0; i < 5000; ++i)
        g_output += "last_used|a.exe|1|2|3|4\n";
    CHECK_FALSE(make_app_usage_source(&kFakeDescriptor).collect().has_value());
}

TEST_CASE("make_app_usage_source: a rendered blob over the byte cap skips the cycle",
          "[app_usage_sync][source][caps]") {
    // 1024 distinct 512-byte exe_keys (under kMaxRecords, so the record-count
    // guard does not fire first) render to a blob past kMaxBlobBytes (512
    // KiB) — the source must not send an un-storable payload.
    g_rc = 0;
    g_output.clear();
    for (int i = 0; i < 1024; ++i) {
        std::string key = std::to_string(i);
        key.resize(512, 'x');
        g_output += "last_used|" + key + "|1|2|3|4\n";
    }
    CHECK_FALSE(make_app_usage_source(&kFakeDescriptor).collect().has_value());
}
