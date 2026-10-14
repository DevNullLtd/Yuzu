#include "nvd_client.hpp"

#include "settings_model.hpp" // sanitize_url_userinfo

#include <httplib.h>
#include <nlohmann/json.hpp>
#include <spdlog/spdlog.h>

#include <algorithm>
#include <cctype>
#include <charconv>
#include <chrono>
#include <cstdint>
#include <ctime>
#include <iomanip>
#include <limits>
#include <sstream>
#include <string>
#include <system_error>
#include <thread>
#include <utility>
#include <vector>

namespace yuzu::server {

namespace {

constexpr const char* kNvdHost = "services.nvd.nist.gov";
constexpr const char* kNvdPath = "/rest/json/cves/2.0";
constexpr int kResultsPerPage = 2000;

// Rate limit intervals
constexpr auto kPublicInterval = std::chrono::milliseconds(6000); // 5 req / 30s
constexpr auto kApiKeyInterval = std::chrono::milliseconds(600);  // 50 req / 30s

// Per-request socket timeouts (tighten httplib's 300s connect/read defaults).
constexpr time_t kConnectTimeoutSec = 30;
constexpr time_t kReadTimeoutSec = 60;

// HTTP 429 backoff (#1880): start at 30s, double per attempt, cap at 30min; give
// up on a single window after this many consecutive 429s.
constexpr auto kBackoffBase = std::chrono::seconds(30);
constexpr auto kBackoffCap = std::chrono::seconds(1800);
constexpr int kMaxBackoffRetries = 5; // consecutive 429s before giving up a window
// Total 429s tolerated across ALL pages of one window (bounds a flaky
// 429/200/429/200 endpoint that would otherwise reset the consecutive counter
// every success and back off for hours — governance UP-3).
constexpr int kMaxTotal429sPerWindow = 10;

std::string url_encode(const std::string& value) {
    std::ostringstream escaped;
    escaped.fill('0');
    escaped << std::hex;
    for (char c : value) {
        if (std::isalnum(static_cast<unsigned char>(c)) || c == '-' || c == '_' || c == '.' ||
            c == '~') {
            escaped << c;
        } else {
            escaped << '%' << std::setw(2) << static_cast<int>(static_cast<unsigned char>(c));
        }
    }
    return escaped.str();
}

} // namespace

NvdProxyEndpoint parse_nvd_proxy_url(std::string_view raw) {
    NvdProxyEndpoint ep;
    // Config values arrive from a flag, an environment variable or a file: drop the whitespace and
    // newline a shell or editor leaves around them.
    const auto is_space = [](char ch) {
        return ch == ' ' || ch == '\t' || ch == '\r' || ch == '\n' || ch == '\v' || ch == '\f';
    };
    while (!raw.empty() && is_space(raw.front()))
        raw.remove_prefix(1);
    while (!raw.empty() && is_space(raw.back()))
        raw.remove_suffix(1);
    // Userinfo first, through the shared sanitiser: it ends userinfo at the LAST '@' anywhere and
    // over-strips on ambiguity, because a boundary-first parse cannot tell a password such as
    // "admin:1234/ss@host" from a host:port (the reasoning is in settings_model.hpp). A proxy URL
    // with a path containing '@' therefore takes the text after that '@' as its host, which no real
    // proxy URL has.
    const std::string sanitized = settings_model::sanitize_url_userinfo(raw);
    std::string_view url = sanitized;
    // Scheme: http:// or https:// (a URL scheme is case-insensitive, RFC 3986); a URL with no
    // scheme is "host:port". Any other scheme (socks5://) is not an HTTP proxy: unusable.
    std::string head(url.substr(0, 8));
    for (char& ch : head)
        ch = static_cast<char>(std::tolower(static_cast<unsigned char>(ch)));
    if (head.starts_with("http://"))
        url.remove_prefix(7);
    else if (head.starts_with("https://"))
        url.remove_prefix(8);
    else if (url.find("://") != std::string_view::npos)
        return ep;
    // The authority ends at the first path, query or fragment delimiter.
    if (const auto end = url.find_first_of("/?#"); end != std::string_view::npos)
        url = url.substr(0, end);

    std::string_view host = url;
    std::string_view port_text;
    if (!url.empty() && url.front() == '[') {
        // Bracketed IPv6 literal: "[::1]:3128". The port, if any, follows the closing bracket.
        const auto close = url.find(']');
        if (close == std::string_view::npos) {
            host = url.substr(1);
        } else {
            host = url.substr(1, close - 1);
            const auto rest = url.substr(close + 1);
            if (rest.starts_with(':'))
                port_text = rest.substr(1);
        }
    } else if (const auto colon = url.rfind(':'); colon != std::string_view::npos) {
        host = url.substr(0, colon);
        port_text = url.substr(colon + 1);
    }
    // A host holding whitespace or a control character is not a host, and would be written to the
    // log verbatim.
    const bool bad_host = std::any_of(host.begin(), host.end(), [](char ch) {
        const auto u = static_cast<unsigned char>(ch);
        return u <= 0x20 || u == 0x7f;
    });
    if (bad_host)
        return ep;
    ep.host = std::string(host);
    if (!port_text.empty()) {
        int port = 0;
        const char* const first = port_text.data();
        const char* const last = first + port_text.size();
        const auto [p, ec] = std::from_chars(first, last, port);
        if (ec == std::errc{} && p == last && port >= 1 && port <= 65535)
            ep.port = port;
        // else keep the 8080 default for a port that is not a plain number in 1..65535 (the
        // previous parse also did for a non-numeric port, but read "80x" as 80)
    }
    return ep;
}

NvdClient::NvdClient(std::string api_key, std::string proxy_url, std::string base_url)
    : api_key_(std::move(api_key)),
      base_url_(base_url.empty() ? (std::string("https://") + kNvdHost) : std::move(base_url)) {
    if (!proxy_url.empty()) {
        const auto ep = parse_nvd_proxy_url(proxy_url);
        proxy_host_ = ep.host;
        proxy_port_ = ep.port;
        if (proxy_url.find('@') != std::string::npos)
            spdlog::info("NVD proxy credentials in the URL are ignored; the client does not "
                         "authenticate to the proxy");
        if (proxy_host_.empty()) {
            // The operator asked for a proxy we cannot use. Say so without echoing the value,
            // and refuse to fetch (fetch_paginated) rather than go direct.
            proxy_unusable_ = true;
            spdlog::error("NVD proxy URL has no usable host (accepted forms: host:port, "
                          "http://host:port, https://host:port); NVD fetches are refused until "
                          "it is fixed and the server is restarted");
        } else {
            // Host and port only: the parse has already dropped any userinfo.
            spdlog::info("NVD client using proxy {}:{}", proxy_host_, proxy_port_);
        }
    }
}

void NvdClient::apply_proxy(httplib::Client& client) const {
    if (!proxy_host_.empty()) {
        client.set_proxy(proxy_host_, proxy_port_);
    }
}

void NvdClient::configure_client(httplib::Client& client) const {
    // Tighten httplib's very generous 300s connection/read defaults. (The write
    // timeout keeps httplib's 5s default — NVD requests are tiny GETs.)
    client.set_connection_timeout(kConnectTimeoutSec);
    client.set_read_timeout(kReadTimeoutSec);
    apply_proxy(client);
}

bool NvdClient::cancellable_sleep(std::chrono::steady_clock::duration d) const {
    // Sleep in small slices so a stop() (cancel flag) wakes us within ~200ms
    // instead of blocking shutdown for the full rate-limit/backoff interval (#1879).
    constexpr auto kSlice = std::chrono::milliseconds(200);
    const auto deadline = std::chrono::steady_clock::now() + d;
    while (std::chrono::steady_clock::now() < deadline) {
        if (cancelled())
            return false;
        std::this_thread::sleep_for(std::min<std::chrono::steady_clock::duration>(
            kSlice, deadline - std::chrono::steady_clock::now()));
    }
    return !cancelled();
}

void NvdClient::rate_limit() {
    const auto interval = api_key_.empty() ? kPublicInterval : kApiKeyInterval;
    const auto now = std::chrono::steady_clock::now();
    const auto wait = nvd_rate_limit_wait(last_request_time_, now, interval);
    if (wait > std::chrono::steady_clock::duration::zero()) {
        spdlog::debug("NVD rate limit: sleeping {}ms",
                      std::chrono::duration_cast<std::chrono::milliseconds>(wait).count());
        cancellable_sleep(wait); // wakes early on stop() (#1879)
    }
    last_request_time_ = std::chrono::steady_clock::now();
}

std::chrono::seconds nvd_backoff_delay(int attempt, const std::string& retry_after_hdr) {
    // Honour a numeric-seconds Retry-After if present (capped), else exponential
    // backoff by attempt (1-based): kBackoffBase, ×2 per attempt, capped.
    if (!retry_after_hdr.empty()) {
        try {
            const long long secs = std::stoll(retry_after_hdr); // NVD sends integer seconds
            if (secs > 0)
                return std::min(std::chrono::seconds(secs), kBackoffCap);
        } catch (...) {
            // fall through to exponential backoff (Retry-After may be an HTTP-date)
        }
    }
    auto d = kBackoffBase;
    for (int i = 1; i < attempt && d < kBackoffCap; ++i)
        d *= 2;
    return std::min(d, kBackoffCap);
}

const char* nvd_reason_label(NvdFailureReason reason) {
    switch (reason) {
    case NvdFailureReason::kConnection: return "connection";
    case NvdFailureReason::kHttp429:    return "http_429";
    case NvdFailureReason::kHttp403:    return "http_403";
    case NvdFailureReason::kHttpOther:  return "http_other";
    case NvdFailureReason::kParse:      return "parse";
    case NvdFailureReason::kNone:
    case NvdFailureReason::kCancelled:  return "none"; // never counted
    }
    return "none";
}

int nvd_reason_index(NvdFailureReason reason) {
    // Dense 0..4 index, in the same order as nvd_reason_label's counted labels.
    // kNone/kCancelled are not countable failures → -1.
    switch (reason) {
    case NvdFailureReason::kConnection: return 0;
    case NvdFailureReason::kHttp429:    return 1;
    case NvdFailureReason::kHttp403:    return 2;
    case NvdFailureReason::kHttpOther:  return 3;
    case NvdFailureReason::kParse:      return 4;
    case NvdFailureReason::kNone:
    case NvdFailureReason::kCancelled:  return -1;
    }
    return -1;
}

std::chrono::steady_clock::duration
nvd_rate_limit_wait(std::optional<std::chrono::steady_clock::time_point> last,
                    std::chrono::steady_clock::time_point now,
                    std::chrono::steady_clock::duration interval) {
    // No prior request → no wait. (The previous code used a time_point::min()
    // sentinel here, so `now - last` overflowed and slept ~292 years, #1867.)
    if (!last) {
        return std::chrono::steady_clock::duration::zero();
    }
    const auto elapsed = now - *last;
    // Only throttle for a positive elapsed strictly inside the interval. A
    // non-positive elapsed (a backwards/non-monotonic clock, or a stray future
    // `last`) returns zero rather than `interval - negative` — that is what
    // defends the ~292-year overflow class against ANY caller, not just the
    // real one (which is monotonic + nullopt-guarded).
    if (elapsed <= std::chrono::steady_clock::duration::zero() || elapsed >= interval) {
        return std::chrono::steady_clock::duration::zero();
    }
    return interval - elapsed;
}

NvdFetchResult NvdClient::fetch_paginated(const std::string& date_params) {
    NvdFetchResult combined;
    if (proxy_unusable_) {
        // Fail closed: a configured proxy that cannot be used must not become a direct connection.
        spdlog::error("NVD fetch refused: --nvd-proxy is set but unusable");
        combined.ok = false;
        combined.reason = NvdFailureReason::kConnection;
        return combined;
    }
    int start_index = 0;
    int backoff_attempts = 0; // consecutive 429s (reset on success)
    int total_429s = 0;       // total 429s this window (never reset — UP-3 cap)

    while (true) {
        // Cooperative cancellation between pages (#1879): abort promptly on stop().
        if (cancelled()) {
            combined.ok = false;
            combined.reason = NvdFailureReason::kCancelled;
            return combined;
        }

        rate_limit();

        // rate_limit()'s throttle/backoff sleep is cancellable and can wake early on
        // stop(); re-check before issuing the (uncancellable, up to 90s) GET so a
        // shutdown during the throttle isn't followed by one more in-flight request
        // (#1879 / PR2C unhappy-path UP-3).
        if (cancelled()) {
            combined.ok = false;
            combined.reason = NvdFailureReason::kCancelled;
            return combined;
        }

        httplib::Client client(base_url_);
        configure_client(client);

        std::string query = std::string(kNvdPath) + "?" + date_params +
                            "&resultsPerPage=" + std::to_string(kResultsPerPage) +
                            "&startIndex=" + std::to_string(start_index);

        httplib::Headers headers;
        headers.emplace("Accept", "application/json");
        if (!api_key_.empty()) {
            headers.emplace("apiKey", api_key_);
        }

        spdlog::info("NVD API request: startIndex={}", start_index);
        auto res = client.Get(query, headers);

        if (!res) {
            spdlog::error("NVD API request failed: connection error");
            combined.ok = false;
            combined.reason = NvdFailureReason::kConnection;
            return combined;
        }

        if (res->status == 429) {
            // Rate-limited: honour Retry-After / exponential backoff and retry the
            // SAME page a bounded number of times (#1880), instead of failing the
            // window and re-hammering NVD every tick. The backoff sleep is
            // cancellable so a 30-min wait can't wedge shutdown.
            // Two bounds: kMaxBackoffRetries CONSECUTIVE 429s, and
            // kMaxTotal429sPerWindow TOTAL across the window — the latter caps a
            // flaky endpoint that 429s intermittently (resetting the consecutive
            // counter on each intervening 200) from backing off for hours (UP-3).
            if (++backoff_attempts > kMaxBackoffRetries ||
                ++total_429s > kMaxTotal429sPerWindow) {
                spdlog::error("NVD HTTP 429 gave up this window ({} consecutive / {} total)",
                              backoff_attempts, total_429s);
                combined.ok = false;
                combined.reason = NvdFailureReason::kHttp429;
                return combined;
            }
            const auto delay = nvd_backoff_delay(backoff_attempts, res->get_header_value("Retry-After"));
            spdlog::warn("NVD HTTP 429 (rate limited) — backing off {}s (attempt {}/{})",
                         delay.count(), backoff_attempts, kMaxBackoffRetries);
            if (!cancellable_sleep(delay)) {
                combined.ok = false;
                combined.reason = NvdFailureReason::kCancelled;
                return combined;
            }
            continue; // retry the same start_index
        }

        if (res->status == 403) {
            // 403 = a CONFIG error (bad/revoked API key), not transient — do not
            // retry; surface it distinctly so it isn't silently retried forever.
            spdlog::error("NVD HTTP 403 (bad/revoked API key?) — not retrying: {}",
                          res->body.substr(0, 200));
            combined.ok = false;
            combined.reason = NvdFailureReason::kHttp403;
            return combined;
        }

        if (res->status != 200) {
            spdlog::error("NVD API returned HTTP {}: {}", res->status, res->body.substr(0, 200));
            combined.ok = false;
            combined.reason = NvdFailureReason::kHttpOther;
            return combined;
        }

        backoff_attempts = 0; // reset after a successful request

        auto page = parse_response(res->body);
        if (!page.ok) {
            // 200 with a bad/unexpected body mid-pagination — do NOT hand back a
            // truncated window as success (UP-1/UP-2). Fail the whole fetch so the
            // caller keeps its cursor and retries.
            combined.ok = false;
            combined.reason = NvdFailureReason::kParse;
            return combined;
        }
        if (page.records.empty() && page.total_results == 0) {
            // Genuinely-empty window (NVD returned totalResults:0). Nothing to page.
            return combined;
        }

        combined.total_results = page.total_results;
        if (!page.last_modified_timestamp.empty()) {
            if (combined.last_modified_timestamp.empty() ||
                page.last_modified_timestamp > combined.last_modified_timestamp) {
                combined.last_modified_timestamp = page.last_modified_timestamp;
            }
        }
        combined.records.insert(combined.records.end(),
                                std::make_move_iterator(page.records.begin()),
                                std::make_move_iterator(page.records.end()));

        spdlog::info("NVD fetch progress: {}/{} total results", combined.records.size(),
                     combined.total_results);

        start_index += kResultsPerPage;
        if (start_index >= combined.total_results) {
            break;
        }
    }

    return combined;
}

NvdFetchResult NvdClient::fetch_modified_between(const std::string& mod_start,
                                                const std::string& mod_end) {
    return fetch_paginated("lastModStartDate=" + url_encode(mod_start) + "&lastModEndDate=" +
                           url_encode(mod_end));
}

NvdFetchResult NvdClient::fetch_by_published_window(const std::string& pub_start,
                                                    const std::string& pub_end) {
    return fetch_paginated("pubStartDate=" + url_encode(pub_start) + "&pubEndDate=" +
                           url_encode(pub_end));
}

std::vector<std::pair<std::chrono::system_clock::time_point, std::chrono::system_clock::time_point>>
nvd_split_windows(std::chrono::system_clock::time_point start,
                  std::chrono::system_clock::time_point end,
                  std::chrono::system_clock::duration max_window) {
    std::vector<std::pair<std::chrono::system_clock::time_point,
                          std::chrono::system_clock::time_point>>
        out;
    if (start >= end || max_window <= std::chrono::system_clock::duration::zero()) {
        return out;
    }
    // Partition [start, end] into consecutive windows each at most max_window
    // long (NVD caps pub/lastMod date ranges at 120 days). Oldest-first; the
    // backfill walks the result in reverse for newest-first coverage.
    auto ws = start;
    while (ws < end) {
        const auto we = (end - ws > max_window) ? ws + max_window : end;
        out.emplace_back(ws, we);
        ws = we;
    }
    return out;
}

NvdFetchResult NvdClient::parse_response(const std::string& json_body) {
    NvdFetchResult result;

    nlohmann::json doc;
    try {
        doc = nlohmann::json::parse(json_body);
    } catch (const nlohmann::json::parse_error& e) {
        // A 200 with an unparseable body (proxy/error page, truncated response)
        // is a FAILURE, not an empty result — flag it so the caller doesn't treat
        // it as "window done" and advance its cursor past unfetched CVEs (UP-1/UP-2).
        spdlog::error("NVD JSON parse error: {}", e.what());
        result.ok = false;
        result.reason = NvdFailureReason::kParse;
        return result;
    }

    // totalResults is integrity-load-bearing (the empty-window contradiction guard AND
    // pagination key off it), so validate its RANGE, not just its JSON type. is_number_integer()
    // passes an oversized value that get<int>() then silently narrows NEGATIVE — 2147483648 ->
    // -2147483648, 9223372036854775807 -> -1 — with NO throw. A negative total slips past the
    // `total_results > 0` contradiction guard (false-"verifying" a stale/corrupt empty page) and
    // breaks `start_index >= total_results` pagination (silent truncation). So read it wide and
    // treat a present-but-out-of-range or non-integer totalResults as a parse failure, not a
    // silent 0 (PR #1912 review — HIGH). A MISSING totalResults stays a lenient 0; a body missing
    // the `vulnerabilities` array is caught as a parse failure below.
    if (doc.contains("totalResults")) {
        const auto& tr = doc["totalResults"];
        if (!tr.is_number_integer()) {
            spdlog::error("NVD response totalResults is not an integer — treating as a parse "
                          "failure (won't trust the window)");
            result.ok = false;
            result.reason = NvdFailureReason::kParse;
            return result;
        }
        const std::int64_t tr64 = tr.get<std::int64_t>();
        if (tr64 < 0 || tr64 > std::numeric_limits<int>::max()) {
            spdlog::error("NVD response totalResults={} out of [0, INT_MAX] — treating as a parse "
                          "failure (won't trust the window)",
                          tr64);
            result.ok = false;
            result.reason = NvdFailureReason::kParse;
            return result;
        }
        result.total_results = static_cast<int>(tr64);
    }

    // A well-formed NVD response always carries a "vulnerabilities" array (empty
    // for a genuinely-empty window). Its absence means an unexpected body shape —
    // treat as failure, not empty.
    if (!doc.contains("vulnerabilities") || !doc["vulnerabilities"].is_array()) {
        result.ok = false;
        result.reason = NvdFailureReason::kParse; // malformed body → parse failure (reason parity)
        return result;
    }

    for (const auto& vuln_entry : doc["vulnerabilities"]) {
        if (!vuln_entry.contains("cve") || !vuln_entry["cve"].is_object()) {
            continue;
        }

        const auto& cve = vuln_entry["cve"];
        std::string cve_id = cve.value("id", "");
        if (cve_id.empty()) {
            continue;
        }

        // Extract English description
        std::string description;
        if (cve.contains("descriptions") && cve["descriptions"].is_array()) {
            for (const auto& desc : cve["descriptions"]) {
                if (desc.value("lang", "") == "en") {
                    description = desc.value("value", "");
                    break;
                }
            }
        }

        // Extract severity from CVSS metrics (v3.1 > v3.0 > v2)
        std::string severity = "MEDIUM";
        if (cve.contains("metrics") && cve["metrics"].is_object()) {
            const auto& metrics = cve["metrics"];
            bool found = false;

            for (const char* metric_key : {"cvssMetricV31", "cvssMetricV30"}) {
                if (found)
                    break;
                if (metrics.contains(metric_key) && metrics[metric_key].is_array() &&
                    !metrics[metric_key].empty()) {
                    const auto& first = metrics[metric_key][0];
                    if (first.contains("cvssData") && first["cvssData"].is_object()) {
                        auto sev = first["cvssData"].value("baseSeverity", "");
                        if (!sev.empty()) {
                            severity = sev;
                            found = true;
                        }
                    }
                }
            }

            if (!found && metrics.contains("cvssMetricV2") && metrics["cvssMetricV2"].is_array() &&
                !metrics["cvssMetricV2"].empty()) {
                const auto& first = metrics["cvssMetricV2"][0];
                auto sev = first.value("baseSeverity", "");
                if (!sev.empty()) {
                    severity = sev;
                }
            }
        }

        // Normalize severity to uppercase
        std::transform(severity.begin(), severity.end(), severity.begin(),
                       [](unsigned char c) { return static_cast<char>(std::toupper(c)); });

        std::string published = cve.value("published", "");
        std::string last_modified = cve.value("lastModified", "");

        // Track latest lastModified
        if (!last_modified.empty()) {
            if (result.last_modified_timestamp.empty() ||
                last_modified > result.last_modified_timestamp) {
                result.last_modified_timestamp = last_modified;
            }
        }

        // One record per CVE; one CpeMatch per cpeMatch node. Keep the full
        // version-range tuple (NVD already provides it) instead of collapsing
        // to a single upper bound.
        CveRecord record;
        record.cve_id = cve_id;
        record.severity = severity;
        record.description = description;
        record.published = published;
        record.last_modified = last_modified;
        record.source = "nvd";

        if (cve.contains("configurations") && cve["configurations"].is_array()) {
            for (const auto& config : cve["configurations"]) {
                if (!config.contains("nodes") || !config["nodes"].is_array()) {
                    continue;
                }
                for (const auto& node : config["nodes"]) {
                    if (!node.contains("cpeMatch") || !node["cpeMatch"].is_array()) {
                        continue;
                    }
                    for (const auto& match : node["cpeMatch"]) {
                        std::string criteria = match.value("criteria", "");
                        if (criteria.empty()) {
                            continue;
                        }

                        // Parse CPE 2.3 URI: cpe:2.3:part:vendor:product:version:...
                        // Fields: 0=cpe, 1=2.3, 2=part, 3=vendor, 4=product, 5=version, ...
                        std::vector<std::string> parts;
                        std::istringstream cpe_stream(criteria);
                        std::string part;
                        while (std::getline(cpe_stream, part, ':')) {
                            parts.push_back(part);
                        }

                        if (parts.size() < 5) {
                            continue;
                        }

                        auto lower = [](std::string s) {
                            std::transform(s.begin(), s.end(), s.begin(), [](unsigned char c) {
                                return static_cast<char>(std::tolower(c));
                            });
                            return s;
                        };

                        CpeMatch cm;
                        cm.cpe_vendor = lower(parts[3]);
                        cm.cpe_product = lower(parts[4]);
                        if (parts.size() > 5) {
                            cm.cpe_version = parts[5]; // '*'/'-' = any (handled downstream)
                        }
                        cm.version_start_including = match.value("versionStartIncluding", "");
                        cm.version_start_excluding = match.value("versionStartExcluding", "");
                        cm.version_end_including = match.value("versionEndIncluding", "");
                        cm.version_end_excluding = match.value("versionEndExcluding", "");
                        cm.is_vulnerable = match.value("vulnerable", true);

                        record.matches.push_back(std::move(cm));
                    }
                }
            }
        }

        // Header-only records (no CPE configuration) are still kept so the CVE
        // metadata isn't lost; they simply never match inventory.
        result.records.push_back(std::move(record));
    }

    spdlog::debug("NVD parsed {} records from {} vulnerabilities", result.records.size(),
                  doc["vulnerabilities"].size());

    // Self-contradictory response: NVD's totalResults claims CVEs exist but we parsed
    // none (a stale cache/proxy serving a well-formed empty page, or a truncated body).
    // Treat as a FAILURE so the caller holds its cursor and retries rather than skipping a
    // populated window (#1889 review r5). A genuinely-empty window is totalResults==0,
    // which stays ok=true and is handled as verified-empty upstream.
    if (result.records.empty() && result.total_results > 0) {
        spdlog::warn("NVD parse: totalResults={} but 0 usable records — treating as failure "
                     "(won't skip a populated window)",
                     result.total_results);
        result.ok = false;
        result.reason = NvdFailureReason::kParse; // malformed/inconsistent body → parse failure
    }

    return result;
}

} // namespace yuzu::server
