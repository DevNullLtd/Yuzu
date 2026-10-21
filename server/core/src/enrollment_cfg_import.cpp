#include <yuzu/server/enrollment_cfg_import.hpp>

#include <yuzu/metrics.hpp>
#include <yuzu/server/auth.hpp>
#include <yuzu/server/auth_db.hpp>

#include <spdlog/spdlog.h>

#include <charconv>
#include <fstream>
#include <sstream>
#include <system_error>

namespace yuzu::server::enrollment_import {

namespace {

// The store rejects text longer than this; an oversize legacy field is skipped
// (counted), not truncated - unlike a live agent's descriptive fields, an
// operator-authored label / an already-recorded identity is not ours to alter.
constexpr std::size_t kMaxText = auth::kMaxEnrollmentTextLength;
// 9999-12-31T23:59:59Z: the largest epoch PG's to_timestamp() takes without a
// range error (which would abort the import txn and refuse boot).
constexpr std::int64_t kMaxEpoch = 253402300799LL;

bool parse_nonneg_int(std::string_view s, int& out) {
    if (s.empty())
        return false;
    int v = 0;
    const auto* end = s.data() + s.size();
    const auto [p, ec] = std::from_chars(s.data(), end, v);
    if (ec != std::errc{} || p != end || v < 0)
        return false;
    out = v;
    return true;
}

bool parse_epoch(std::string_view s, std::int64_t& out) {
    if (s.empty())
        return false;
    std::int64_t v = 0;
    const auto* end = s.data() + s.size();
    const auto [p, ec] = std::from_chars(s.data(), end, v);
    if (ec != std::errc{} || p != end || v < 0 || v > kMaxEpoch)
        return false;
    out = v;
    return true;
}

bool is_lower_hex64(std::string_view s) {
    if (s.size() != 64)
        return false;
    for (const char c : s) {
        if (!((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f')))
            return false;
    }
    return true;
}

bool text_ok(std::string_view s) {
    return s.size() <= kMaxText && s.find('\0') == std::string_view::npos;
}

std::vector<std::string_view> split_colon(std::string_view line) {
    std::vector<std::string_view> parts;
    std::size_t start = 0;
    for (;;) {
        const auto pos = line.find(':', start);
        if (pos == std::string_view::npos) {
            parts.push_back(line.substr(start));
            return parts;
        }
        parts.push_back(line.substr(start, pos - start));
        start = pos + 1;
    }
}

/// Iterate the data lines of a cfg file: strips CR, skips blanks and '#' lines,
/// recording an unsupported "# Version: N" header. `fn(line)` is called per data line.
template <typename Fn>
void for_each_data_line(std::string_view content, ParseStats& stats, Fn&& fn) {
    std::size_t pos = 0;
    while (pos <= content.size()) {
        auto nl = content.find('\n', pos);
        std::string_view line = content.substr(
            pos, (nl == std::string_view::npos ? content.size() : nl) - pos);
        pos = (nl == std::string_view::npos) ? content.size() + 1 : nl + 1;
        while (!line.empty() && (line.back() == '\r' || line.back() == '\n'))
            line.remove_suffix(1);
        if (line.empty())
            continue;
        if (line.front() == '#') {
            constexpr std::string_view kVer = "# Version: ";
            if (line.starts_with(kVer)) {
                int ver = 0;
                if (!parse_nonneg_int(line.substr(kVer.size()), ver) || ver != 1)
                    stats.unsupported_version = true;
            }
            continue;
        }
        ++stats.data_lines;
        fn(line);
    }
}

} // namespace

const char* to_string(Outcome o) noexcept {
    switch (o) {
    case Outcome::imported:
        return "imported";
    case Outcome::already_imported:
        return "already_imported";
    case Outcome::fingerprint_mismatch:
        return "fingerprint_mismatch";
    case Outcome::absent:
        return "absent";
    case Outcome::error:
        return "error";
    }
    return "error";
}

std::string content_fingerprint(std::string_view bytes) {
    return auth::AuthManager::sha256_hex(std::string(bytes));
}

ParsedTokens parse_tokens_cfg(std::string_view content) {
    ParsedTokens out;
    for_each_data_line(content, out.stats, [&](std::string_view line) {
        if (line.find('\0') != std::string_view::npos) {
            ++out.stats.garbled;
            return;
        }
        const auto parts = split_colon(line);
        const std::size_t n = parts.size();
        // Written as 8 ':'-separated fields; the label is the ONLY free-text field
        // and every field after it is a fixed-shape number, so a ':' inside the label
        // is recoverable UNAMBIGUOUSLY by counting fields from the right.
        if (n < 8) {
            ++out.stats.garbled;
            return;
        }
        LegacyToken t;
        int max_uses = 0, use_count = 0;
        std::int64_t created = 0, expires = 0;
        const auto revoked_s = parts[n - 1];
        if (parts[0].empty() || !is_lower_hex64(parts[1]) ||
            !parse_nonneg_int(parts[n - 5], max_uses) ||
            !parse_nonneg_int(parts[n - 4], use_count) || !parse_epoch(parts[n - 3], created) ||
            !parse_epoch(parts[n - 2], expires) || (revoked_s != "0" && revoked_s != "1")) {
            ++out.stats.garbled;
            return;
        }
        std::string label;
        for (std::size_t i = 2; i + 5 < n; ++i) { // parts[2 .. n-6]
            if (i > 2)
                label += ':';
            label.append(parts[i]);
        }
        if (!text_ok(label)) {
            ++out.stats.garbled;
            return;
        }
        if (n > 8)
            ++out.stats.recovered;
        t.token_hash = std::string(parts[1]);
        t.label = std::move(label);
        t.max_uses = max_uses;
        t.use_count = use_count;
        t.created_epoch = created;
        t.expires_epoch = expires;
        t.revoked = (revoked_s == "1");
        out.rows.push_back(std::move(t));
    });
    return out;
}

ParsedPending parse_pending_cfg(std::string_view content) {
    ParsedPending out;
    for_each_data_line(content, out.stats, [&](std::string_view line) {
        if (line.find('\0') != std::string_view::npos) {
            ++out.stats.garbled;
            return;
        }
        const auto parts = split_colon(line);
        // Seven fields with FIVE free-text ones: an extra ':' cannot be attributed to a
        // field (hostname? version?), so anything but exactly 7 is skipped + counted.
        if (parts.size() != 7) {
            ++out.stats.garbled;
            return;
        }
        LegacyPending p;
        std::int64_t requested = 0;
        const auto status = parts[6];
        if (parts[0].empty() || parts[0].size() > auth::kMaxAgentIdLength ||
            !text_ok(parts[1]) || !text_ok(parts[2]) || !text_ok(parts[3]) || !text_ok(parts[4]) ||
            !parse_epoch(parts[5], requested) ||
            (status != "pending" && status != "approved" && status != "denied")) {
            ++out.stats.garbled;
            return;
        }
        p.agent_id = std::string(parts[0]);
        p.hostname = std::string(parts[1]);
        p.os = std::string(parts[2]);
        p.arch = std::string(parts[3]);
        p.agent_version = std::string(parts[4]);
        p.requested_epoch = requested;
        p.status = std::string(status);
        out.rows.push_back(std::move(p));
    });
    return out;
}

// -- Orchestrator -------------------------------------------------------------

namespace {

namespace fs = std::filesystem;

bool default_rename(const fs::path& from, const fs::path& to) {
    std::error_code ec;
    fs::rename(from, to, ec);
    return !ec;
}

void count_outcome(yuzu::MetricsRegistry* m, const char* kind, Outcome o) {
    if (m)
        m->counter("yuzu_server_enrollment_import_total",
                   {{"kind", kind}, {"outcome", to_string(o)}})
            .increment();
}

void count_rows(yuzu::MetricsRegistry* m, const char* kind, const char* result, std::size_t n) {
    if (m && n > 0)
        m->counter("yuzu_server_enrollment_import_rows_total",
                   {{"kind", kind}, {"result", result}})
            .increment(static_cast<double>(n));
}

/// Read a whole file. false + `why` on failure (unreadable / over the size cap).
bool read_file(const fs::path& p, std::string& out, std::string& why) {
    std::error_code ec;
    const auto sz = fs::file_size(p, ec);
    if (ec) {
        why = "cannot stat: " + ec.message();
        return false;
    }
    if (sz > kMaxImportFileBytes) {
        why = "file exceeds the " + std::to_string(kMaxImportFileBytes) + "-byte import cap";
        return false;
    }
    std::ifstream f(p, std::ios::binary);
    if (!f.is_open()) {
        why = "cannot open for reading";
        return false;
    }
    std::ostringstream ss;
    ss << f.rdbuf();
    if (f.bad()) {
        why = "read error";
        return false;
    }
    out = ss.str();
    return true;
}

struct KindSpec {
    const char* kind;
    std::string_view file_name;
    std::string_view marker_key;
};

/// Pick the file the OLD code would have been running on: the data dir's copy if it
/// exists, else the config dir's. `other` gets the older copy when both exist.
bool locate(const Locations& where, std::string_view name, fs::path& chosen, fs::path& other) {
    std::error_code ec;
    fs::path in_data, in_cfg;
    if (!where.data_dir.empty()) {
        const auto p = where.data_dir / std::string(name);
        if (fs::is_regular_file(p, ec))
            in_data = p;
    }
    if (!where.config_dir.empty() && where.config_dir != where.data_dir) {
        const auto p = where.config_dir / std::string(name);
        if (fs::is_regular_file(p, ec))
            in_cfg = p;
    }
    if (!in_data.empty()) {
        chosen = in_data;
        other = in_cfg; // may be empty
        return true;
    }
    if (!in_cfg.empty()) {
        chosen = in_cfg;
        return true;
    }
    return false;
}

} // namespace

RunResult run_legacy_enrollment_import(AuthDB& db, const Locations& where,
                                       yuzu::MetricsRegistry* metrics, const Options& opts) {
    RunResult run;
    const auto rename_fn = opts.rename_fn ? opts.rename_fn : default_rename;
    const KindSpec kinds[] = {{"tokens", kTokensFileName, kTokensMarkerKey},
                              {"pending", kPendingFileName, kPendingMarkerKey}};

    for (const auto& k : kinds) {
        KindReport rep;
        rep.kind = k.kind;
        // Every path below `return`s out of this lambda with `rep` filled in; the single
        // push_back after the try/catch records it.
        auto handle = [&]() {
            fs::path chosen, other;
            if (!locate(where, k.file_name, chosen, other)) {
                // NEVER stamp on absence: a later boot with the file present must import.
                rep.outcome = Outcome::absent;
                count_outcome(metrics, k.kind, rep.outcome);
                return;
            }
            rep.source = chosen;
            rep.other_copy = other;
            if (!other.empty()) {
                spdlog::warn("[enrollment-import] {} exists in BOTH the data dir ({}) and the "
                             "config dir ({}); importing the data-dir copy (what the pre-6.2 "
                             "server loaded last) and leaving {} untouched",
                             k.file_name, chosen.string(), other.string(), other.string());
            }

            std::string bytes, why;
            if (!read_file(chosen, bytes, why)) {
                rep.outcome = Outcome::error;
                rep.detail = why;
                spdlog::critical("[enrollment-import] REFUSING TO START: {} is present but "
                                 "unreadable ({}): {}",
                                 chosen.string(), k.kind, why);
                count_outcome(metrics, k.kind, rep.outcome);
                run.fatal = true;
                return;
            }
            rep.fingerprint = content_fingerprint(bytes);

            std::expected<ImportDbResult, StoreError> res;
            if (k.marker_key == kTokensMarkerKey) {
                auto parsed = parse_tokens_cfg(bytes);
                rep.parse = parsed.stats;
                res = db.import_legacy_tokens(k.marker_key, rep.fingerprint, parsed.rows,
                                              "server-boot");
            } else {
                auto parsed = parse_pending_cfg(bytes);
                rep.parse = parsed.stats;
                res = db.import_legacy_pending(k.marker_key, rep.fingerprint, parsed.rows,
                                               "server-boot");
            }
            if (!res) {
                rep.outcome = Outcome::error;
                rep.detail = "auth store error during the import transaction";
                spdlog::critical("[enrollment-import] REFUSING TO START: the {} import "
                                 "transaction failed with {} present at {} (a half-known "
                                 "enrollment set is worse than no boot; fix Postgres and "
                                 "restart - the import is idempotent and re-runs)",
                                 k.kind, chosen.string(),
                                 res.error() == StoreError::InvalidInput ? "invalid input"
                                                                         : "a store error");
                count_outcome(metrics, k.kind, rep.outcome);
                run.fatal = true;
                return;
            }
            rep.counts = res->counts;

            if (res->status == ImportStatus::fingerprint_mismatch) {
                rep.outcome = Outcome::fingerprint_mismatch;
                rep.detail = "marker fingerprint " + res->stored_fingerprint +
                             " != file fingerprint " + rep.fingerprint;
                spdlog::critical(
                    "[enrollment-import] {} at {} DIFFERS from the file that was already "
                    "imported (imported fingerprint {}, this file {}). This is a restored old "
                    "backup or a hand-edited file: it is REFUSED, not merged - Postgres state "
                    "stands. The file is left in place; remove or archive it once you have "
                    "confirmed nothing in it is needed.",
                    k.file_name, chosen.string(), res->stored_fingerprint, rep.fingerprint);
                count_outcome(metrics, k.kind, rep.outcome);
                return;
            }

            const bool first_import = (res->status == ImportStatus::imported);
            rep.outcome = first_import ? Outcome::imported : Outcome::already_imported;
            if (first_import) {
                spdlog::warn(
                    "[enrollment-import] ONE-TIME import of legacy {} from {} (sha256 {}): "
                    "imported={} skipped_existing={} skipped_garbled={} recovered_colon_labels={} "
                    "id_disambiguated={} unplaceable={}{}. Enrollment state now lives in "
                    "Postgres; the file is renamed to '<name>.imported' and is never read again.",
                    k.kind, chosen.string(), rep.fingerprint, rep.counts.imported,
                    rep.counts.skipped_existing, rep.parse.garbled, rep.parse.recovered,
                    rep.counts.id_disambiguated, rep.counts.failed,
                    rep.parse.unsupported_version ? " (NOTE: unsupported '# Version' header, "
                                                    "parsed best-effort)"
                                                  : "");
                count_rows(metrics, k.kind, "imported", rep.counts.imported);
                count_rows(metrics, k.kind, "skipped_existing", rep.counts.skipped_existing);
                count_rows(metrics, k.kind, "skipped_garbled", rep.parse.garbled);
                count_rows(metrics, k.kind, "recovered_colon", rep.parse.recovered);
                count_rows(metrics, k.kind, "id_disambiguated", rep.counts.id_disambiguated);
                count_rows(metrics, k.kind, "unplaceable", rep.counts.failed);
            } else {
                spdlog::info("[enrollment-import] {} at {} was already imported (marker + equal "
                             "fingerprint {}); skipping",
                             k.file_name, chosen.string(), rep.fingerprint);
            }
            count_outcome(metrics, k.kind, rep.outcome);

            // Best-effort rename AFTER the commit. A failure is a warning, never an error:
            // the next boot sees marker + equal fingerprint and tries again.
            fs::path renamed_to = chosen;
            renamed_to += ".imported";
            if (rename_fn(chosen, renamed_to)) {
                rep.renamed = true;
            } else {
                spdlog::warn("[enrollment-import] could not rename {} to {} (import is already "
                             "committed; a later boot will retry the rename)",
                             chosen.string(), renamed_to.string());
            }
        };
        try {
            handle();
        } catch (const std::exception& e) {
            // Nothing in the importer is expected to throw; if it does (bad_alloc, ...)
            // treat it as an import failure with the file present => refuse to start.
            rep.outcome = Outcome::error;
            rep.detail = std::string("unexpected exception: ") + e.what();
            spdlog::critical("[enrollment-import] REFUSING TO START: unexpected exception "
                             "importing legacy {}: {}",
                             k.kind, e.what());
            count_outcome(metrics, k.kind, rep.outcome);
            run.fatal = true;
        }
        run.reports.push_back(std::move(rep));
    }
    return run;
}

} // namespace yuzu::server::enrollment_import
