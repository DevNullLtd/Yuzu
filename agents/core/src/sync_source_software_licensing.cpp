#include "sync_source_software_licensing.hpp"

#include "local_dispatcher.hpp"
#include "sync_canonical.hpp" // clamp_field / sha256_hex

#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/rand.h>

#include <spdlog/spdlog.h>

#include <algorithm>
#include <array>
#include <chrono>
#include <optional>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

namespace yuzu::agent {

namespace {

// ── Caps (roadmap R5) — comment-coordinated with the ALREADY-COMMITTED server
//    seam server/core/src/software_licensing_ingestion.cpp (kMaxBlobBytes /
//    kMaxRecords / kMaxFieldLen / kLicFieldCount). The repo has NO shared
//    agent/server constants (roadmap C-2), so these are duplicated literals
//    kept in step with that file. A one-sided cap reintroduces the
//    agent-sends / server-drops tight loop (UP-7): the agent must skip a cycle
//    the server would reject, not send it. Sized for per-user fan-out
//    (products × profiles + PR2 `ent|` records), below the 4 MiB gRPC ceiling.
constexpr std::size_t kMaxBlobBytes = 1u * 1024 * 1024; // 1 MiB — MUST equal the seam
constexpr std::size_t kMaxRecords = 10000;
constexpr std::size_t kMaxFieldLen = 1024;
// Positional `lic|` fields AFTER the kind prefix (§3.1). Extra tokens dropped
// (forward-version tolerance); missing trailing tokens stay empty.
constexpr std::size_t kLicFieldCount = 13;

// Per-call capture cap for the `license_scan list` dispatch. The plugin fans
// out over every detection surface and, on Windows, every user profile, so its
// raw output is larger than the sibling machine-scope sources. Sized above the
// 1 MiB blob cap (so the record-count / blob-size guards below — not a silent
// capture truncation — are what bound an outlier host) and well under the 4 MiB
// gRPC receive ceiling. A truncated capture is dropped (unstable hash), never
// parsed partially.
constexpr std::size_t kLicenseCaptureCap = 2u * 1024 * 1024; // 2 MiB

// Platform PRIMARY surfaces (ADR-0024 Decision 3 / roadmap R15). An error on
// one of these is a real failure that must NOT wipe stored state → skip the
// cycle. Per-user hives (`per_user_hives` / `per_user_files`) are deliberately
// absent: they are never a primary surface (a privilege-stripped fleet can
// neither wipe state nor stall its syncs). Cross-platform by construction —
// exactly one of these tokens appears in any single host's `list` output, so a
// static set needs no host-platform branch and keeps the guard unit-testable
// with canned output. Coordinated with the per-OS surface tokens in
// agents/plugins/license_scan/src/licensing_{win,linux,macos}.cpp.
constexpr std::array<std::string_view, 3> kPrimarySurfaces = {
    "slp_wmi",      // Windows: WMI SoftwareLicensingProduct enumeration
    "pkg_metadata", // Linux:   rpm / dpkg package-metadata enumeration
    "mas_receipt",  // macOS:   _MASReceipt presence scan
};

bool is_primary_surface(std::string_view s) {
    return std::find(kPrimarySurfaces.begin(), kPrimarySurfaces.end(), s) != kPrimarySurfaces.end();
}

// AUTHORITATIVE surfaces (ADR-0024 Decision 2 confidence `authoritative`; roadmap
// §5 PR1 surface table). These are not necessarily the platform PRIMARY
// enumeration surface, but they carry authoritative licence / expiry state, so
// dropping their records via full-replace on a transient error reads as "licence
// gone" (the exact silent-erasure failure the empty-vs-error guard exists to
// prevent). An error on one of these therefore skips the cycle (keep last good)
// just like a primary-surface error — see LicenseScanParse::blocking_surface_error.
// Kept in step with the plugin's confidence="authoritative" assignments and the
// per-OS surface tokens in licensing_{win,linux}.cpp:
//   slp_wmi           — Windows WMI SoftwareLicensingProduct (also primary)
//   entitlement_certs — Linux RHEL entitlement certs (subscription expiry)
//   flexlm_lic        — FlexLM .lic feature expiry (ProbeSpec surface token)
// Heuristic/probable surfaces (per-user hives/files, package metadata, ProbeSpec
// vendor probes) are deliberately ABSENT: their errors must NOT wipe state (R15).
constexpr std::array<std::string_view, 3> kAuthoritativeSurfaces = {
    "slp_wmi",
    "entitlement_certs",
    "flexlm_lic",
};

bool is_authoritative_surface(std::string_view s) {
    return std::find(kAuthoritativeSurfaces.begin(), kAuthoritativeSurfaces.end(), s) !=
           kAuthoritativeSurfaces.end();
}

// Split `line` on '|' into at most `max_tokens` pieces. The plugin's §3.3
// layer-1 sanitiser strips '|' from every field, so a simple split recovers
// the exact fields; a would-be (max_tokens+1)-th field is dropped, never
// merged into the last token (fields cannot shift).
std::vector<std::string_view> split_pipe(std::string_view line, std::size_t max_tokens) {
    std::vector<std::string_view> tok;
    std::size_t fp = 0;
    while (tok.size() < max_tokens) {
        std::size_t bar = line.find('|', fp);
        if (bar == std::string_view::npos) {
            tok.push_back(line.substr(fp));
            break;
        }
        tok.push_back(line.substr(fp, bar - fp));
        fp = bar + 1;
    }
    return tok;
}

const char* kHex = "0123456789abcdef";

std::string to_hex(std::string_view raw) {
    std::string out;
    out.reserve(raw.size() * 2);
    for (unsigned char c : raw) {
        out.push_back(kHex[c >> 4]);
        out.push_back(kHex[c & 0x0f]);
    }
    return out;
}

std::optional<std::string> from_hex(std::string_view hex) {
    if (hex.size() % 2 != 0)
        return std::nullopt;
    const auto nibble = [](char c) -> int {
        if (c >= '0' && c <= '9')
            return c - '0';
        if (c >= 'a' && c <= 'f')
            return c - 'a' + 10;
        return -1;
    };
    std::string out;
    out.reserve(hex.size() / 2);
    for (std::size_t i = 0; i < hex.size(); i += 2) {
        int hi = nibble(hex[i]);
        int lo = nibble(hex[i + 1]);
        if (hi < 0 || lo < 0)
            return std::nullopt;
        out.push_back(static_cast<char>((hi << 4) | lo));
    }
    return out;
}

// Resolve the per-agent 256-bit HMAC key (k_agent, roadmap R16): read the
// hex-encoded key from the injected KvStore (`license_scan` namespace); on
// first use — or if the stored value is malformed — generate 32 CSPRNG bytes,
// persist them hex-encoded, and return the raw bytes. Returns std::nullopt only
// on a CSPRNG failure. The key is NEVER logged or transmitted (R16): nothing in
// this function emits it, and callers keep it local to the HMAC computation.
std::optional<std::string> resolve_k_agent(const SoftwareLicensingConfig& cfg) {
    if (cfg.kv_get) {
        std::string stored = cfg.kv_get(kUserRefHmacKeyName);
        if (stored.size() == 64) {
            if (auto raw = from_hex(stored); raw && raw->size() == 32)
                return raw;
        }
    }
    unsigned char buf[32];
    if (RAND_bytes(buf, static_cast<int>(sizeof(buf))) != 1) {
        spdlog::warn("sync: software_licensing could not generate the user_ref HMAC key "
                     "(CSPRNG failure) — skipping this cycle");
        return std::nullopt;
    }
    std::string raw(reinterpret_cast<const char*>(buf), sizeof(buf));
    if (cfg.kv_set && !cfg.kv_set(kUserRefHmacKeyName, to_hex(raw))) {
        // The freshly-generated key could not be PERSISTED (disk-full, SQLite-busy).
        // Using it now and losing it means the next cycle regenerates a different key
        // and the same profile maps to a NEW user_ref — an unstable pseudonym
        // (Decision 11). Skip the cycle instead; retry next interval.
        spdlog::warn("sync: software_licensing could not persist the user_ref HMAC key "
                     "— skipping this cycle to keep the per-profile pseudonym stable");
        return std::nullopt;
    }
    return raw; // key persisted (or kv_set unwired, e.g. tests) — safe to use
}

} // namespace

std::string_view user_ref_mode_token(UserRefMode mode) {
    switch (mode) {
    case UserRefMode::collect:
        return "collect";
    case UserRefMode::hash:
        return "hash";
    case UserRefMode::omit:
        return "omit";
    }
    return "hash";
}

std::optional<UserRefMode> parse_user_ref_mode(std::string_view s) {
    if (s == "collect")
        return UserRefMode::collect;
    if (s == "hash")
        return UserRefMode::hash;
    if (s == "omit")
        return UserRefMode::omit;
    return std::nullopt;
}

std::string user_ref_hmac16(std::string_view key, std::string_view profile) {
    // Never hash an empty profile — an unresolvable profile ships with the
    // identifier omitted (ADR-0024 D11), never a hash-of-empty. The caller also
    // guards, but pin it here so no path can produce a pseudonym from "".
    if (profile.empty())
        return {};
    unsigned char mac[EVP_MAX_MD_SIZE];
    unsigned int maclen = 0;
    const unsigned char* rc =
        ::HMAC(EVP_sha256(), key.data(), static_cast<int>(key.size()),
               reinterpret_cast<const unsigned char*>(profile.data()), profile.size(), mac,
               &maclen);
    if (rc == nullptr || maclen < 8)
        return {};
    // First 8 MAC bytes → 16 lowercase hex chars.
    std::string out;
    out.reserve(16);
    for (unsigned int i = 0; i < 8; ++i) {
        out.push_back(kHex[mac[i] >> 4]);
        out.push_back(kHex[mac[i] & 0x0f]);
    }
    return out;
}

LicenseScanParse parse_license_scan_output(const std::string& out) {
    LicenseScanParse result;
    std::size_t pos = 0;
    while (pos < out.size() && result.records.size() < kMaxRecords) {
        std::size_t eol = out.find('\n', pos);
        if (eol == std::string::npos)
            eol = out.size();
        std::string_view line(out.data() + pos, eol - pos);
        while (!line.empty() && line.back() == '\r')
            line.remove_suffix(1);
        pos = eol + 1;
        if (line.empty())
            continue;

        // Peek the kind (first token) cheaply.
        std::size_t bar = line.find('|');
        std::string_view kind = line.substr(0, bar == std::string_view::npos ? line.size() : bar);

        if (kind == "lic") {
            std::vector<std::string_view> tok = split_pipe(line, 1 + kLicFieldCount);
            const auto field = [&tok](std::size_t i) -> std::string {
                return tok.size() > i ? clamp_field(tok[i], kMaxFieldLen) : std::string{};
            };
            LicRecord r;
            r.product = field(1);
            // No product = no row identity — drop (mirrors the server seam's
            // empty-product drop and the sibling sources' empty-name drop).
            if (r.product.empty())
                continue;
            r.vendor = field(2);
            r.version = field(3);
            r.license_type = field(4);
            r.channel = field(5);
            r.status = field(6);
            r.expires_at = field(7);
            r.source = field(8);
            r.confidence = field(9);
            r.key_hint = field(10);
            r.exe_hints = field(11);
            r.user_scope = field(12);
            r.user_ref = field(13);
            result.records.push_back(std::move(r));
        } else if (kind == "probe_status") {
            // probe_status|<surface>|ok|<rows>  or  |error|<message>.  LIVE-ONLY
            // diagnostics — consumed ONLY for the empty-vs-error structural guard
            // (ADR-0024 D3), never added to the blob.
            std::vector<std::string_view> tok = split_pipe(line, 4);
            if (tok.size() >= 3 && tok[2] == "error" &&
                (is_primary_surface(tok[1]) || is_authoritative_surface(tok[1])))
                result.blocking_surface_error = true;
        }
        // else: `ent|` (PR2), `cfg|`, blank, or any newer kind — SKIP without
        // error (ADR-0024 D3 forward-compat).
    }
    return result;
}

void apply_user_ref_knob(std::vector<LicRecord>& records, UserRefMode mode,
                         std::string_view k_agent) {
    for (auto& r : records) {
        switch (mode) {
        case UserRefMode::collect:
            break; // raw local profile name passes through (opt-in)
        case UserRefMode::hash:
            // Empty stays empty (never a hash-of-empty); a present name becomes
            // the per-agent keyed pseudonym.
            if (!r.user_ref.empty())
                r.user_ref = user_ref_hmac16(k_agent, r.user_ref);
            break;
        case UserRefMode::omit:
            r.user_ref.clear(); // suppress the identifier; user_scope stays "user"
            break;
        }
    }
}

std::string software_licensing_canonical_blob(std::vector<LicRecord> records, UserRefMode mode) {
    std::string blob;

    // 1) The single D-10 config record, at a FIXED position (first). It changes
    //    only when the knob changes, so it never defeats hash-skip on a stable
    //    estate. Kept separate from the lic| sort so its position is invariant
    //    to the record set. Framing: `cfg` 0x1F `user_ref` 0x1F `<mode>` 0x1E.
    blob += "cfg";
    blob += '\x1f';
    blob += "user_ref";
    blob += '\x1f';
    blob += user_ref_mode_token(mode);
    blob += '\x1e';

    // 2) The lic| records, rendered then sorted + deduped for byte stability
    //    across collects of the same detected state. Unlike the sibling sources
    //    this need NOT match a server re-derivation (D-2: the server hashes the
    //    raw bytes we send), so sorting the rendered lines is sufficient and
    //    simplest. Framing: `lic` 0x1F f0 0x1F … 0x1F f12 0x1E.
    std::vector<std::string> lines;
    lines.reserve(records.size());
    for (const auto& r : records) {
        const std::string* fields[kLicFieldCount] = {
            &r.product,  &r.vendor,     &r.version,   &r.license_type, &r.channel,
            &r.status,   &r.expires_at, &r.source,    &r.confidence,   &r.key_hint,
            &r.exe_hints, &r.user_scope, &r.user_ref};
        std::string line = "lic";
        for (const std::string* f : fields) {
            line += '\x1f';
            line += *f;
        }
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

SyncSource make_software_licensing_source(const YuzuPluginDescriptor* descriptor,
                                          SoftwareLicensingConfig config) {
    SyncSource src;
    src.name = "software_licensing";
    // ADR-0024 Decision 3: 24 h interval — licence estates are stable
    // day-to-day, so hash-skip is meaningful at this cadence.
    src.interval = std::chrono::hours{24};
    src.collect =
        [descriptor,
         cfg = std::move(config)]() -> std::optional<std::pair<std::string, std::string>> {
        if (descriptor == nullptr) {
            spdlog::debug("sync: license_scan plugin not loaded — software_licensing source idle");
            return std::nullopt;
        }
        LocalDispatcher dispatcher;
        LocalDispatcher::Result r = dispatcher.run(descriptor, "list", {}, kLicenseCaptureCap);
        if (r.rc != 0) {
            spdlog::warn("sync: license_scan 'list' rc={} — skipping this cycle", r.rc);
            return std::nullopt;
        }
        if (r.truncated) {
            spdlog::warn("sync: license_scan 'list' output truncated at the capture cap — "
                         "skipping this cycle (won't sync a partial, hash-unstable payload)");
            return std::nullopt;
        }
        LicenseScanParse parsed = parse_license_scan_output(r.captured);

        // Empty-vs-error structural guard (ADR-0024 D3): a primary-OR-authoritative
        // surface error means detection is unreliable this cycle — the enumeration
        // itself failed, or an authoritative surface's records would be wrongly
        // dropped. DON'T full-replace stored state to empty; keep the last good
        // state and retry next cycle. Zero records with all blocking surfaces ok is
        // a VALID empty state and proceeds (full-replace-to-empty).
        if (parsed.blocking_surface_error) {
            spdlog::warn("sync: license_scan primary/authoritative surface reported an error — "
                         "skipping this cycle (keeping last good state, not wiping stored "
                         "licences)");
            return std::nullopt;
        }
        if (parsed.records.size() >= kMaxRecords) {
            // The blob also carries the single cfg| record, which counts toward
            // the server's kMaxRecords budget: kMaxRecords lic rows + 1 cfg row
            // is kMaxRecords+1 records, which the server rejects + nacks (whole
            // blob — truncate-and-store is unsafe under the raw-byte hash). So
            // skip at >= kMaxRecords (not >) to leave room for the cfg record and
            // never enter the agent-sends / server-drops loop.
            spdlog::warn("sync: license_scan yielded {} records (cap {}) — skipping this cycle",
                         parsed.records.size(), kMaxRecords);
            return std::nullopt;
        }

        // Apply the user_ref knob before the blob is built (D-11). In hash mode
        // resolve k_agent (generated + persisted on first use); a CSPRNG failure
        // skips the cycle rather than emit raw or wrong identifiers.
        std::string k_agent;
        if (cfg.user_ref_mode == UserRefMode::hash) {
            auto key = resolve_k_agent(cfg);
            if (!key)
                return std::nullopt;
            k_agent = std::move(*key);
        }
        apply_user_ref_knob(parsed.records, cfg.user_ref_mode, k_agent);

        std::string blob =
            software_licensing_canonical_blob(std::move(parsed.records), cfg.user_ref_mode);
        if (blob.size() > kMaxBlobBytes) {
            spdlog::warn("sync: software_licensing blob {} B exceeds {} B cap — skipping this "
                         "cycle (won't send an un-storable payload)",
                         blob.size(), kMaxBlobBytes);
            return std::nullopt;
        }
        std::string hash = sha256_hex(blob);
        return std::make_pair(std::move(blob), std::move(hash));
    };
    return src;
}

} // namespace yuzu::agent
