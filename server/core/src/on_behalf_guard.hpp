// On-behalf-of assertion guard (ADR-1005 Interim rules, execution-plan PR 1.1).
//
// Until server-verifiable delegation ships (execution-plan Phase 5), the server
// accepts NO on-behalf-of assertion on ANY ingress surface — any such
// header/field is rejected, not ignored. This header defines the reserved
// names ONCE for both surfaces: the HTTP pre-routing chokepoint (REST + MCP —
// same httplib instance) and the agent-facing gRPC interceptor
// (grpc_on_behalf_interceptor.hpp). The names are reserved NOW, before any
// delegation mechanism exists, so no integration can squat on them and no
// future surface can accept them by accident.
//
// Phase 5 delegation will use a server-issued artifact, never a client-
// asserted header — so these names stay rejected permanently on client
// ingress; the list only ever grows. The list is published as an integration
// contract in docs/auth-architecture.md; this header is the source of truth.

#pragma once

#include <array>
#include <atomic>
#include <optional>
#include <string>
#include <string_view>

#include "yuzu/metrics.hpp"

namespace yuzu::server::onbehalf {

// Reserved names, lowercase. gRPC metadata keys arrive lowercase by protocol;
// HTTP names are matched case-insensitively via match_reserved_key.
inline constexpr std::array<std::string_view, 5> kReservedKeys{
    "on-behalf-of",
    "x-on-behalf-of",
    "x-yuzu-on-behalf-of",
    "x-yuzu-delegated-operator",
    "x-yuzu-delegation-artifact",
};

// ASCII-only fold — header/metadata names are ASCII by RFC 9110 / gRPC spec,
// and every reserved name is ASCII; avoids std::tolower's negative-char UB
// and locale dependence.
[[nodiscard]] constexpr char ascii_lower(char c) {
    return (c >= 'A' && c <= 'Z') ? static_cast<char>(c - 'A' + 'a') : c;
}

// Case-insensitive exact match of `name` against the reserved set. Returns
// the matching kReservedKeys entry (static storage — safe to hold and log;
// never the client-supplied bytes) or nullopt.
[[nodiscard]] constexpr std::optional<std::string_view> match_reserved_key(
    std::string_view name) {
    for (auto reserved : kReservedKeys) {
        if (reserved.size() != name.size()) continue;
        bool match = true;
        for (size_t i = 0; i < name.size(); ++i) {
            if (ascii_lower(name[i]) != reserved[i]) {
                match = false;
                break;
            }
        }
        if (match) return reserved;
    }
    return std::nullopt;
}

[[nodiscard]] constexpr bool is_reserved_key(std::string_view name) {
    return match_reserved_key(name).has_value();
}

// Scan a header/metadata collection (any range of pair-likes whose first
// element exposes data()/size()) for a reserved key. Returns the canonical
// (kReservedKeys, static storage) spelling of the first hit for logging —
// never the client-supplied value, which is untrusted input and does not
// belong in logs. Allocation-free on the clean path AND on the hit path.
template <typename Range>
[[nodiscard]] constexpr std::optional<std::string_view> find_reserved_key(
    const Range& headers) {
    for (const auto& [name, value] : headers) {
        if (auto hit = match_reserved_key({name.data(), name.size()})) return hit;
    }
    return std::nullopt;
}

// Make an untrusted string safe for a single log line: control chars
// (incl. CR/LF — httplib percent-decodes req.path, so "%0a" arrives as a raw
// newline and would forge log lines in a security-tagged warn) are replaced
// with '?', and the result is length-capped. Returns an owned string; only
// called on the (throttled) rejection-log path, never per clean request.
/// Drop a trailing INCOMPLETE UTF-8 sequence, and only an incomplete one.
///
/// The byte-wise cap below can sever a multi-byte character. That was harmless
/// while this helper only fed a log line, but #2500 started routing audit-detail
/// text through it, and an audit row holding a lone lead byte makes
/// `/api/v1/audit` emit a response that is not valid UTF-8 JSON — `json_escape`
/// passes bytes >= 0x20 through unvalidated — so a strict client cannot decode
/// the whole page. One truncated device name would poison the audit list.
///
/// PRECONDITION, and the limit of what this gives you: it **preserves** UTF-8
/// validity, it does not **establish** it. A caller passing already-invalid
/// bytes gets invalid bytes back (minus control chars). On `/api/command` the
/// inputs are valid by construction because they came through
/// `nlohmann::json::parse`, which rejects ill-formed UTF-8 — that is the only
/// reason the audit path is safe. Other callers pass httplib-percent-decoded
/// `req.path` / `remote_addr` / `ctx->peer()`, which CAN carry raw high bytes;
/// harmless while those only reach a log line, but a future caller routing one
/// of them into a durable column reintroduces the undecodable-page bug under a
/// name that reads as though it were covered.
inline void drop_partial_utf8_tail(std::string& out) {
    const size_t n = out.size();
    for (size_t back = 1; back <= 4 && back <= n; ++back) {
        const auto c = static_cast<unsigned char>(out[n - back]);
        if ((c & 0xC0) == 0x80)
            continue; // continuation byte - keep walking back to the lead
        size_t need = 1;
        if ((c & 0xE0) == 0xC0)
            need = 2;
        else if ((c & 0xF0) == 0xE0)
            need = 3;
        else if ((c & 0xF8) == 0xF0)
            need = 4;
        if (need > back)
            out.erase(n - back); // the sequence is cut short - drop it whole
        return;
    }
}

[[nodiscard]] inline std::string sanitize_for_log(std::string_view s,
                                                  size_t max_len = 200) {
    std::string out;
    out.reserve(std::min(s.size(), max_len));
    for (char c : s) {
        if (out.size() >= max_len) {
            drop_partial_utf8_tail(out);
            out += "...";
            break;
        }
        out += (static_cast<unsigned char>(c) < 0x20 || c == 0x7f) ? '?' : c;
    }
    return out;
}

// Record a rejection: always increments the per-surface security counter;
// returns true when this occurrence should also be logged. The log is
// throttled (first hit, then every kLogEvery-th, per surface per process)
// because the rejection path runs BEFORE the rate limiter — an unauthenticated
// reserved-header flood must not become a disk-fill amplifier via per-request
// warns, while the counter still records every event.
inline constexpr uint64_t kLogEvery = 100;

[[nodiscard]] inline bool note_rejection(yuzu::MetricsRegistry& metrics,
                                         std::string_view surface) {
    metrics
        .counter("yuzu_onbehalf_rejected_total",
                 {{"surface", std::string(surface)}, {"event", "security"}})
        .increment();
    static std::atomic<uint64_t> http_hits{0};
    static std::atomic<uint64_t> grpc_hits{0};
    auto& hits = (surface == "grpc") ? grpc_hits : http_hits;
    return hits.fetch_add(1, std::memory_order_relaxed) % kLogEvery == 0;
}

}  // namespace yuzu::server::onbehalf
