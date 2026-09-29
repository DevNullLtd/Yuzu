#include "sync_source_app_usage.hpp"

#include "local_dispatcher.hpp"
#include "sync_canonical.hpp" // clamp_field / sha256_hex

#include <spdlog/spdlog.h>

#include <algorithm>
#include <charconv>
#include <chrono>
#include <cstddef>
#include <optional>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

namespace yuzu::agent {

namespace {

// Caps — mirrors the server seam (app_usage_ingestion.cpp, comment-coordinated;
// the repo has no shared agent/server constants, C-2). A one-sided cap
// reintroduces the agent-sends/server-drops tight loop (UP-7): the agent must
// skip a cycle the server would reject, not send it.
constexpr std::size_t kMaxBlobBytes = 512u * 1024; // 512 KiB — MUST equal the seam
constexpr std::size_t kMaxRecords = 5000;
constexpr std::size_t kMaxFieldLen = 512;

// Per-call capture cap for the `app_usage last_used` dispatch — one line per
// distinct exe_key, well under the 4 MiB gRPC receive ceiling.
constexpr std::size_t kCaptureCap = 2u * 1024 * 1024; // 2 MiB

// ── Escape-aware pipe splitting (adjudication P5) ──────────────────────────
// The plugin escapes a literal '|' inside exe_key as `\|` so the line stays a
// well-formed pipe record. This is a local mirror of
// server/core/src/result_parsing.hpp:79-90's find_unescaped_pipe /
// unescape_pipes (that header is not reachable from agent core — kept a
// small, independent copy rather than a cross-module include).

/// Find the next unescaped '|' at/after `pos`. Returns npos if none.
std::size_t find_unescaped_pipe(std::string_view s, std::size_t pos) {
    while (pos < s.size()) {
        std::size_t p = s.find('|', pos);
        if (p == std::string_view::npos)
            return std::string_view::npos;
        if (p > 0 && s[p - 1] == '\\') {
            pos = p + 1;
            continue;
        }
        return p;
    }
    return std::string_view::npos;
}

/// Remove backslash-escaping from pipe characters: "foo\|bar" -> "foo|bar".
std::string unescape_pipes(std::string_view s) {
    std::string out;
    out.reserve(s.size());
    for (std::size_t i = 0; i < s.size(); ++i) {
        if (s[i] == '\\' && i + 1 < s.size() && s[i + 1] == '|')
            continue;
        out += s[i];
    }
    return out;
}

// Split `line` on UNESCAPED '|' into at most `max_tokens` pieces. Tokens are
// returned raw (still escaped) — the caller unescapes the fields that may
// carry a literal pipe (exe_key); the remaining fields are numeric and never
// need it.
std::vector<std::string_view> split_pipe(std::string_view line, std::size_t max_tokens) {
    std::vector<std::string_view> tok;
    std::size_t fp = 0;
    while (tok.size() < max_tokens) {
        std::size_t bar = find_unescaped_pipe(line, fp);
        if (bar == std::string_view::npos) {
            tok.push_back(line.substr(fp));
            break;
        }
        tok.push_back(line.substr(fp, bar - fp));
        fp = bar + 1;
    }
    return tok;
}

std::int64_t parse_i64(std::string_view s) {
    std::int64_t v = 0;
    const auto [p, ec] = std::from_chars(s.data(), s.data() + s.size(), v);
    // Require the WHOLE field to parse -- "123abc" must not silently become
    // 123 (governance Gate 7, cpp-expert finding; mirrors the fix already
    // applied to the sibling ws-7b2 branch's app_usage_ingestion.cpp).
    return (ec == std::errc{} && p == s.data() + s.size()) ? v : 0;
}

} // namespace

AppUsageParse parse_app_usage_last_used_output(const std::string& captured) {
    AppUsageParse out;
    std::size_t pos = 0;
    while (pos < captured.size() && out.rows.size() < kMaxRecords) {
        std::size_t eol = captured.find('\n', pos);
        if (eol == std::string::npos)
            eol = captured.size();
        std::string_view line(captured.data() + pos, eol - pos);
        while (!line.empty() && line.back() == '\r')
            line.remove_suffix(1);
        pos = eol + 1;
        if (line.empty())
            continue;

        // Peek the kind (first token, up to the first UNESCAPED pipe — the
        // kind itself is never escaped).
        std::size_t bar = find_unescaped_pipe(line, 0);
        std::string_view kind = line.substr(0, bar == std::string_view::npos ? line.size() : bar);

        if (kind == "constrained") {
            // A legitimate "nothing to say this cycle" (usage disabled, older
            // TAR schema, tar.db unavailable) — never treated as a zero-row
            // replace (see the header). Stop parsing; the caller skips.
            out.constrained = true;
            return out;
        }
        if (kind == "last_used") {
            // last_used|<exe_key>|<last_seen>|<first_seen>|<run_count_30d>|
            // <total_seconds_30d> (app_usage_parsers.hpp format_last_used_row).
            // exe_key may carry an escaped `\|` for a literal pipe in the
            // executable path/name — split only on unescaped pipes, then
            // unescape exe_key back to its literal form.
            std::vector<std::string_view> tok = split_pipe(line, 6);
            if (tok.size() < 6)
                continue; // malformed line — skip, don't fail the cycle
            AppUsageRow r;
            r.exe_key = clamp_field(unescape_pipes(tok[1]), kMaxFieldLen);
            if (r.exe_key.empty())
                continue; // no exe_key = no row identity — drop
            r.last_seen = parse_i64(tok[2]);
            r.first_seen = parse_i64(tok[3]);
            r.run_count_30d = parse_i64(tok[4]);
            r.total_seconds_30d = parse_i64(tok[5]);
            if (r.last_seen < 0)
                r.last_seen = 0;
            if (r.first_seen < 0)
                r.first_seen = 0;
            if (r.run_count_30d < 0)
                r.run_count_30d = 0;
            if (r.total_seconds_30d < 0)
                r.total_seconds_30d = 0;
            out.rows.push_back(std::move(r));
        }
        // else: "meta|" (not emitted by last_used, but tolerated), "error|",
        // "unavailable|", or any newer kind — SKIP without error (forward-compat).
    }
    return out;
}

std::string render_app_usage_blob(std::vector<AppUsageRow> rows) {
    std::string blob;

    // The single machine-scope config record, at a FIXED position (first) —
    // this source carries no per-user data, so the record is a constant, kept
    // purely for wire-shape parity with the sibling `cfg|` framing.
    blob += "cfg";
    blob += '\x1f';
    blob += "scope";
    blob += '\x1f';
    blob += "machine";
    blob += '\x1e';

    // `lu|` records, rendered then sorted + deduped for byte stability across
    // collects of the same detected state (no byte-identical-with-server
    // requirement — the server hashes the raw bytes we send). exe_key was
    // already clamp_field-stripped of the 0x1E/0x1F/NUL framing bytes on
    // parse, so it can never corrupt this blob's structure.
    std::vector<std::string> lines;
    lines.reserve(rows.size());
    for (const auto& r : rows) {
        std::string line = "lu";
        line += '\x1f';
        line += r.exe_key;
        line += '\x1f';
        line += std::to_string(r.first_seen);
        line += '\x1f';
        line += std::to_string(r.last_seen);
        line += '\x1f';
        line += std::to_string(r.run_count_30d);
        line += '\x1f';
        line += std::to_string(r.total_seconds_30d);
        lines.push_back(std::move(line));
    }
    std::sort(lines.begin(), lines.end());
    lines.erase(std::unique(lines.begin(), lines.end()), lines.end());
    for (const auto& l : lines) {
        blob += l;
        blob += '\x1e';
    }
    return blob;
}

SyncSource make_app_usage_source(const YuzuPluginDescriptor* descriptor) {
    SyncSource src;
    src.name = "app_usage";
    // 24 h interval — last-used state is stable day-to-day, so hash-skip is
    // meaningful at this cadence (mirrors software_licensing).
    src.interval = std::chrono::hours{24};
    src.collect = [descriptor]() -> std::optional<std::pair<std::string, std::string>> {
        if (descriptor == nullptr) {
            spdlog::debug("sync: app_usage plugin not loaded — source idle");
            return std::nullopt;
        }
        LocalDispatcher dispatcher;
        LocalDispatcher::Result r = dispatcher.run(descriptor, "last_used", {}, kCaptureCap);
        if (r.rc != 0) {
            spdlog::warn("sync: app_usage 'last_used' rc={} — skipping this cycle", r.rc);
            return std::nullopt;
        }
        if (r.truncated) {
            spdlog::warn("sync: app_usage 'last_used' output truncated at the capture cap — "
                         "skipping this cycle (won't sync a partial, hash-unstable payload)");
            return std::nullopt;
        }
        AppUsageParse parsed = parse_app_usage_last_used_output(r.captured);
        if (parsed.constrained) {
            spdlog::debug("sync: app_usage 'last_used' reported constrained — skipping this "
                          "cycle (never sending an empty blob for a constrained source)");
            return std::nullopt;
        }
        if (parsed.rows.size() >= kMaxRecords) {
            // The blob also carries the single cfg| record, which counts
            // toward the server's kMaxRecords budget (mirrors the
            // software_licensing >= guard) — skip rather than enter the
            // agent-sends/server-drops loop.
            spdlog::warn("sync: app_usage yielded {} records (cap {}) — skipping this cycle",
                         parsed.rows.size(), kMaxRecords);
            return std::nullopt;
        }
        std::string blob = render_app_usage_blob(std::move(parsed.rows));
        if (blob.size() > kMaxBlobBytes) {
            spdlog::warn("sync: app_usage blob {} B exceeds {} B cap — skipping this cycle "
                         "(won't send an un-storable payload)",
                         blob.size(), kMaxBlobBytes);
            return std::nullopt;
        }
        std::string hash = sha256_hex(blob);
        return std::make_pair(std::move(blob), std::move(hash));
    };
    return src;
}

} // namespace yuzu::agent
