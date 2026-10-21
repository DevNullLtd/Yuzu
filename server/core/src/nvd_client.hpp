#pragma once

#include "nvd_db.hpp"

#include <array>
#include <atomic>
#include <chrono>
#include <optional>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

namespace httplib {
class Client;
}

namespace yuzu::server {

// Why a fetch failed, so the caller can label the failure metric and treat a
// config error (403) differently from a transient one (#1880). `kCancelled` is
// a cooperative shutdown, NOT a failure — the caller must not count it (#1879).
enum class NvdFailureReason { kNone, kConnection, kHttp429, kHttp403, kHttpOther, kParse, kCancelled };

struct NvdFetchResult {
    std::vector<CveRecord> records;
    int total_results = 0;
    std::string last_modified_timestamp; // latest lastModified in results
    // false if a request failed (connection/HTTP error) — distinguishes a real
    // failure from a genuinely-empty window so the caller doesn't treat a
    // transient error as "sync complete" and advance its cursor (#1875).
    bool ok = true;
    NvdFailureReason reason = NvdFailureReason::kNone; // set when ok == false
};

// Fetch seam so NvdSyncManager's backfill/freshness logic is unit-testable
// against a mock, without network. NvdClient is the production implementation.
class INvdFetcher {
public:
    virtual ~INvdFetcher() = default;
    // CVEs PUBLISHED in [pub_start, pub_end] (newest-first backfill).
    virtual NvdFetchResult fetch_by_published_window(const std::string& pub_start,
                                                     const std::string& pub_end) = 0;
    // CVEs last-MODIFIED in [mod_start, mod_end] (freshness re-check).
    virtual NvdFetchResult fetch_modified_between(const std::string& mod_start,
                                                  const std::string& mod_end) = 0;
};

// Where an HTTP proxy URL points. `host` is empty when the input is empty OR the URL has no usable
// host (an ambiguous URL is dropped whole; so is a scheme other than http/https, or a host holding
// whitespace or control characters). A caller that was given a non-empty URL and gets an empty host
// must treat the proxy as unusable, never as "no proxy". Any userinfo
// (`user:password@`) is dropped here and never reaches the host, the port, or a log line:
// the client does not authenticate to the proxy, so the credentials have no use past this
// parse. Pure, so the shapes can be pinned without a socket.
struct NvdProxyEndpoint {
    std::string host;
    int port = 8080;
};
[[nodiscard]] NvdProxyEndpoint parse_nvd_proxy_url(std::string_view url);

class NvdClient : public INvdFetcher {
public:
    // base_url overrides the NVD API root (default https://services.nvd.nist.gov). Only
    // used to point fetch_paginated at a local httplib::Server in tests; production passes {}.
    explicit NvdClient(std::string api_key = {}, std::string proxy_url = {},
                       std::string base_url = {});

    // Both ISO 8601; the window must be within NVD's 120-day cap (nvd_split_windows).
    NvdFetchResult fetch_by_published_window(const std::string& pub_start,
                                             const std::string& pub_end) override;
    NvdFetchResult fetch_modified_between(const std::string& mod_start,
                                          const std::string& mod_end) override;

    /// Parse a raw NVD API JSON response into CveRecords.
    NvdFetchResult parse_response(const std::string& json_body);

    // Point the client at a cooperative-cancellation flag (owned elsewhere, e.g.
    // NvdSyncManager::stopping_). When set true, fetch_paginated aborts between
    // pages and during its rate-limit / backoff sleeps (#1879). Pass nullptr to
    // clear. The pointee must outlive every fetch call.
    void set_cancel_flag(const std::atomic<bool>* cancel) { cancel_ = cancel; }

private:
    std::string api_key_;
    std::string proxy_host_;
    int proxy_port_ = 0;
    // A proxy URL was configured but has no usable host: fetches are refused (fail closed), not
    // sent direct, because the operator asked for the proxy.
    bool proxy_unusable_ = false;
    std::string base_url_; // NVD API root; set in the ctor (prod default or a test override)
    // std::nullopt until the first request — a sentinel time_point overflowed
    // the rate-limit subtraction and slept ~forever on the first call (#1867).
    std::optional<std::chrono::steady_clock::time_point> last_request_time_;
    const std::atomic<bool>* cancel_ = nullptr; // borrowed; see set_cancel_flag

    void rate_limit();
    void apply_proxy(httplib::Client& client) const;
    // Apply the shared per-request client config (timeouts, proxy).
    void configure_client(httplib::Client& client) const;
    // Paginate a query carrying the given NVD date filter (e.g.
    // "lastModStartDate=…&lastModEndDate=…" or "pubStartDate=…&pubEndDate=…").
    NvdFetchResult fetch_paginated(const std::string& date_params);
    // True if cancellation was requested via set_cancel_flag.
    bool cancelled() const { return cancel_ != nullptr && cancel_->load(); }
    // Sleep for `d`, waking early if cancellation is requested. Returns false if
    // it was cancelled (so callers abort), true if it slept the full duration.
    bool cancellable_sleep(std::chrono::steady_clock::duration d) const;
};

/// Partition [start, end] into consecutive windows each at most `max_window`
/// long (NVD caps pub/lastMod date ranges at 120 days), oldest-first. Pure.
std::vector<std::pair<std::chrono::system_clock::time_point, std::chrono::system_clock::time_point>>
nvd_split_windows(std::chrono::system_clock::time_point start,
                  std::chrono::system_clock::time_point end,
                  std::chrono::system_clock::duration max_window);

/// How long to sleep to honour `interval` since the `last` request — zero when
/// there was no prior request (nullopt) or `interval` has already elapsed.
/// Overflow-safe: a regression guard for the `time_point::min()` sentinel that
/// overflowed `now - last` and slept ~292 years on the first NVD request (#1867).
std::chrono::steady_clock::duration
nvd_rate_limit_wait(std::optional<std::chrono::steady_clock::time_point> last,
                    std::chrono::steady_clock::time_point now,
                    std::chrono::steady_clock::duration interval);

/// How long to back off after an HTTP 429 (#1880): a numeric-seconds `Retry-After`
/// if present (capped at 30 min), else exponential backoff by `attempt` (1-based:
/// 30s, 60s, 120s, … capped). Pure.
std::chrono::seconds nvd_backoff_delay(int attempt, const std::string& retry_after_hdr);

/// Stable Prometheus `reason` label for a failure (the SINGLE source of truth for
/// the yuzu_nvd_sync_failures_total label set — used by the metric wiring AND a
/// parity test so the strings can't drift). kNone/kCancelled → "none" (never
/// counted).
const char* nvd_reason_label(NvdFailureReason reason);

/// Number of failure reasons that are COUNTED in yuzu_nvd_sync_failures_total —
/// every reason except kNone/kCancelled (a cancel is not a failure).
inline constexpr int kNvdCountedFailureReasons = 5;

/// The counted reasons, in nvd_reason_index order — the SINGLE place the countable
/// enumerators are listed. Iterate this (not an inline brace-list) when zero-initing
/// or emitting the metric, so adding a 6th reason is one edit here (+ the label/index
/// switches + the array size), never a silently-forgotten series.
inline constexpr std::array<NvdFailureReason, kNvdCountedFailureReasons> kNvdCountedReasons = {
    NvdFailureReason::kConnection, NvdFailureReason::kHttp429, NvdFailureReason::kHttp403,
    NvdFailureReason::kHttpOther, NvdFailureReason::kParse};

/// Dense index in [0, kNvdCountedFailureReasons) for a counted reason, or -1 for
/// kNone/kCancelled. The order matches nvd_reason_label's counted labels. Used to
/// accumulate per-reason failure counts on the sync manager and emit them from the
/// /metrics scrape (the pull model that removed the cross-thread callback, #1909).
int nvd_reason_index(NvdFailureReason reason);

} // namespace yuzu::server
