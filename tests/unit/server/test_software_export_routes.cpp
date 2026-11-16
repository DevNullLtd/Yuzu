/**
 * test_software_export_routes.cpp - the streamed installed-software export route
 * (GET /api/v1/inventory/software/export) through TestRouteSink.
 *
 * No socket, no store, no libpq, no sleeps: the page reader is a fake over an in-memory, sorted
 * row vector that honours the store query's keyset (`after`), `skip`, `limit` and scope push-down;
 * the stream deadline reads an injected clock. The chunked provider is driven by hand, the way
 * httplib drives it: call until `done` or a false return, then run the resource-releaser.
 *
 * The pins: the gate decides before any read; the audit row is stored BEFORE the first chunk;
 * rows arrive in order with no duplicate at a page boundary; a confined caller streams only its
 * own rows; a wide scope whose reads hold none of the caller's rows is walked to the end, even
 * past the page-mode OFFSET ceiling, and no store read of the walk carries an OFFSET; a degraded
 * read, the deadline or a server shutdown aborts the transfer (provider returns false); an unwired
 * store or budget is a 503, never an empty 200.
 *
 * Admission (ADR-0034): every stream is one lease from a REAL StreamBudget on
 * SseSurface::kSoftwareExport, and each exit path (clean end, mid-stream degrade, deadline, client
 * abort, shutdown, a destroyed response) returns it, which the tests read back through
 * `active_for_surface`. Either limit refusing (the export cap, or the budget full from another
 * surface) is a 503 with a retry hint and a `denied` row; a request refused after admission holds
 * no lease; an engine principal's pending quota slot is adopted into the stream.
 */

#include <catch2/catch_test_macros.hpp>

#include "principal_quota.hpp"
#include "principal_quota_gate.hpp"
#include "software_export_routes.hpp"
#include "stream_budget.hpp"
#include "test_route_sink.hpp"

#include <yuzu/metrics.hpp>

#include <algorithm>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <functional>
#include <memory>
#include <optional>
#include <stdexcept>
#include <string>
#include <string_view>
#include <tuple>
#include <unordered_map>
#include <unordered_set>
#include <vector>

using namespace yuzu::server;
namespace swe = yuzu::server::software_export;
namespace swl = yuzu::server::software_list;
namespace sb = yuzu::server::detail;

namespace {

using Scope = std::optional<std::unordered_set<std::string>>;

Scope scope_of(std::initializer_list<std::string> ids) {
    return Scope{std::unordered_set<std::string>(ids)};
}

struct AuditRecord {
    std::string action;
    std::string result;
    std::string target_id;
    std::string detail;
};

std::string agent_id(const char* prefix, int n, int width = 6) {
    char buf[32];
    std::snprintf(buf, sizeof buf, "%s-%0*d", prefix, width, n);
    return buf;
}

SoftwareFleetRow install_row(const std::string& agent, std::int64_t install_id,
                             const std::string& publisher = "Acme") {
    SoftwareFleetRow r;
    r.agent_id = agent;
    r.install_id = install_id;
    r.entry.name = "pkg";
    r.entry.version = "1." + std::to_string(install_id);
    r.entry.publisher = publisher;
    r.entry.kind = "package";
    r.facet_status = "full";
    return r;
}

struct Harness {
    yuzu::MetricsRegistry metrics;     // outlives the routes that count into it
    sb::StreamBudget budget;           // the one held-open budget; outlives every Response lease
    SoftwareExportRoutes routes;       // declared BEFORE the sink that holds handlers capturing it
    yuzu::server::test::TestRouteSink sink;

    // The gate.
    bool admitted{true};
    int denial_status{403};
    Scope scope; // nullopt = unfiltered
    int gate_calls{0};

    // The audit sink.
    std::vector<AuditRecord> audit_log;
    bool audit_persists{true};
    bool audit_throws{false};

    // The data and the read counters.
    std::vector<SoftwareFleetRow> installs; // kept sorted by (name, agent_id, install_id)
    // Instead of `installs`: synthesise this many rows on demand (row n has install_id n+1 and
    // device a-<n>), so the large case never holds them in memory. With `generated_in_from` >= 0
    // the rows from that index on belong to the devices z-000, z-001, ... instead (the caller's
    // own, see wide_scope()), and the rows before it carry the publisher LEAK-<device>.
    int generated{0};
    int generated_in_from{-1};
    std::unordered_map<std::string, std::string> roster;
    std::vector<std::string> distinct;
    bool distinct_degrades{false};
    int install_reads{0};
    std::int64_t max_skip_seen{0}; // the largest OFFSET any installs read was handed
    int fail_read_at{0};      // the Nth installs read answers nullopt (0 = never)
    int last_seen_calls{0};
    int fail_last_seen_at{0}; // the Nth last-poll read answers nullopt (0 = never)
    SoftwareFleetQuery last_query;

    // The injected deadline clock (monotonic seconds).
    std::int64_t clock_s{1'000};

    [[nodiscard]] SoftwareFleetRow generated_row(int i) const {
        if (generated_in_from >= 0 && i >= generated_in_from)
            return install_row(agent_id("z", i - generated_in_from, 3), i + 1);
        const auto id = agent_id("a", i);
        return install_row(id, i + 1, generated_in_from >= 0 ? "LEAK-" + id : "Acme");
    }

    // `global_cap` is the budget's server-wide cap (the --max-sse-streams side); `concurrency` is the
    // export cap (--inventory-export-concurrency). `wire_budget` false leaves Deps::stream_budget null.
    explicit Harness(int concurrency = 2, bool wire_reads = true, bool wire_budget = true,
                     std::size_t global_cap = 64)
        : budget(sb::StreamBudget::Config{global_cap}) {
        SoftwareExportRoutes::Deps deps;
        deps.fleet_read_fn = [this](const httplib::Request&, httplib::Response& res,
                                    const std::string&,
                                    const std::string&) -> authz::FleetReadGate {
            ++gate_calls;
            if (!admitted) {
                res.status = denial_status;
                res.set_content(R"({"error":{"message":"denied"}})", "application/json");
                return {};
            }
            return {true, scope};
        };
        deps.audit_fn = [this](const httplib::Request&, const std::string& action,
                               const std::string& result, const std::string&,
                               const std::string& target_id, const std::string& detail) -> bool {
            if (audit_throws)
                throw std::runtime_error("audit sink down");
            audit_log.push_back({action, result, target_id, detail});
            return audit_persists;
        };
        deps.roster_fn = [this]() -> std::optional<OfflineRoster> {
            OfflineRoster out;
            for (const auto& [id, hostname] : roster)
                out.rows.push_back({.agent_id = id, .hostname = hostname});
            return out;
        };
        deps.seconds_fn = [this] { return clock_s; };
        deps.metrics = &metrics;
        deps.stream_budget = wire_budget ? &budget : nullptr;
        deps.concurrency = concurrency;
        if (wire_reads) {
            auto& r = deps.reads;
            r.installs = [this](const SoftwareFleetQuery& q)
                -> std::optional<std::vector<SoftwareFleetRow>> {
                ++install_reads;
                last_query = q;
                max_skip_seen = std::max(max_skip_seen, q.skip);
                if (fail_read_at != 0 && install_reads == fail_read_at)
                    return std::nullopt;
                if (generated > 0) {
                    std::vector<SoftwareFleetRow> page;
                    // Row n has install_id n+1, so the row after `after` is at index install_id;
                    // `skip` passes over rows after it, like the store's OFFSET.
                    const auto from = (q.after ? static_cast<int>(q.after->install_id) : 0) +
                                      static_cast<int>(q.skip);
                    for (int i = from; i < generated && page.size() < static_cast<std::size_t>(q.limit);
                         ++i)
                        page.push_back(generated_row(i));
                    return page;
                }
                using Key = std::tuple<std::string, std::string, std::int64_t>;
                auto it = installs.begin();
                if (q.after) {
                    const Key k{q.after->name, q.after->agent_id, q.after->install_id};
                    it = std::upper_bound(installs.begin(), installs.end(), k,
                                          [](const Key& key, const SoftwareFleetRow& row) {
                                              return key < Key{row.entry.name, row.agent_id,
                                                               row.install_id};
                                          });
                }
                std::int64_t skip = q.skip;
                std::vector<SoftwareFleetRow> out;
                for (; it != installs.end() && out.size() < static_cast<std::size_t>(q.limit);
                     ++it) {
                    if (q.agent_ids &&
                        std::ranges::find(*q.agent_ids, it->agent_id) == q.agent_ids->end())
                        continue;
                    if (q.versions &&
                        std::ranges::find(*q.versions, it->entry.version) == q.versions->end())
                        continue;
                    if (skip > 0) {
                        --skip;
                        continue;
                    }
                    out.push_back(*it);
                }
                return out;
            };
            r.last_seen = [this](const std::vector<std::string>& ids)
                -> std::optional<std::unordered_map<std::string, std::int64_t>> {
                ++last_seen_calls;
                if (fail_last_seen_at != 0 && last_seen_calls == fail_last_seen_at)
                    return std::nullopt;
                std::unordered_map<std::string, std::int64_t> m;
                for (const auto& id : ids)
                    m[id] = 1'699'000'000;
                return m;
            };
            r.distinct_versions = [this](const std::string&,
                                         const std::optional<std::vector<std::string>>&)
                -> std::optional<std::vector<std::string>> {
                if (distinct_degrades)
                    return std::nullopt;
                return distinct;
            };
        }
        routes.register_routes(sink, std::move(deps));
    }

    std::unique_ptr<httplib::Response> get(const std::string& query) {
        return sink.Get("/api/v1/inventory/software/export" + query);
    }

    [[nodiscard]] double count(const char* format, const char* result) {
        return metrics
            .counter("yuzu_server_software_export_total",
                     {{"format", format}, {"result", result}})
            .value();
    }
    [[nodiscard]] double rejected(const char* reason) {
        return metrics
            .counter("yuzu_server_software_export_rejected_total", {{"reason", reason}})
            .value();
    }
    // Export leases held right now (an open stream holds one until its releaser has run).
    [[nodiscard]] std::size_t held() const {
        return budget.active_for_surface(sb::SseSurface::kSoftwareExport);
    }
};

// What one hand-driven transfer produced.
struct Transfer {
    std::string body;
    bool done{false};
    bool aborted{false}; // the provider returned false
    int calls{0};
};

// Drives the provider the way httplib does. `on_chunk` sees every write (and may refuse it);
// `keep_body` false keeps only the byte count out of memory for the large case.
Transfer drive(httplib::Response& res, std::function<bool(const std::string&)> on_chunk = {},
               bool keep_body = true) {
    Transfer t;
    httplib::DataSink sink;
    sink.write = [&](const char* p, size_t n) {
        const std::string chunk(p, n);
        if (on_chunk && !on_chunk(chunk))
            return false;
        if (keep_body)
            t.body += chunk;
        return true;
    };
    sink.is_writable = [] { return true; };
    sink.done = [&] { t.done = true; };
    REQUIRE(res.content_provider_);
    while (!t.done && !t.aborted && t.calls < 1'000'000) {
        ++t.calls;
        if (!res.content_provider_(0, 0, sink))
            t.aborted = true;
    }
    return t;
}

// httplib runs the resource-releaser once the transfer is over, clean or not.
void release(httplib::Response& res, bool success) {
    if (res.content_provider_resource_releaser_)
        res.content_provider_resource_releaser_(success);
}

std::vector<std::string> lines_of(const std::string& body) {
    std::vector<std::string> out;
    std::size_t at = 0;
    while (at < body.size()) {
        const auto nl = body.find('\n', at);
        out.push_back(body.substr(at, nl - at));
        if (nl == std::string::npos)
            break;
        at = nl + 1;
    }
    return out;
}

// The install number in a JSONL row's "version":"1.<n>", or -1 (no assertion per row: the large
// case calls this once per row).
std::int64_t install_no(const std::string& line) {
    static const std::string key = "\"version\":\"1.";
    const auto at = line.find(key);
    return at == std::string::npos ? -1 : std::strtoll(line.c_str() + at + key.size(), nullptr, 10);
}

// A wide confined caller: more than kScopePushdownMaxIds devices, so the route reads rows the
// scope excludes and filters them in process. kOut out-of-scope rows sort first (4,500 > four full
// store reads of 1,000), then the caller's own rows.
constexpr int kOut = 4'500;
constexpr int kIn = 10;

// The caller's scope: the devices z-000..z-009 plus filler devices that own no rows, so it is wider
// than kScopePushdownMaxIds.
void wide_scope(Harness& h) {
    std::unordered_set<std::string> ids;
    for (int i = 0; i < kIn; ++i)
        ids.insert(agent_id("z", i, 3));
    for (int i = 0; ids.size() <= software_catalogue::kScopePushdownMaxIds; ++i)
        ids.insert(agent_id("f", i));
    h.scope = std::move(ids);
}

void wide_fixture(Harness& h) {
    wide_scope(h);
    for (int i = 0; i < kOut; ++i) {
        const auto id = agent_id("a", i);
        h.installs.push_back(install_row(id, i + 1, "LEAK-" + id));
        h.roster[id] = "leak-host-" + id;
    }
    for (int i = 0; i < kIn; ++i) {
        const auto id = agent_id("z", i, 3);
        h.installs.push_back(install_row(id, kOut + i + 1));
        h.roster[id] = "own-host-" + id;
    }
}

} // namespace

TEST_CASE("export route: three times the buffered export cap streams in order across pages with "
          "no duplicate at a boundary",
          "[software_export][routes]") {
    Harness h(/*concurrency=*/1);
    // 30,000 rows: past kExportCap (10,000), the most a buffered export may return, so a stream
    // that regressed to a capped or buffered read fails here. The cost is the row formatting
    // (~95 us a row unoptimised), which is why this is not larger.
    constexpr int kRows = 3 * static_cast<int>(software_catalogue::kExportCap);
    constexpr int kPages = kRows / swe::kPageRows;
    h.generated = kRows;

    auto res = h.get("?format=jsonl");
    REQUIRE(res);
    CHECK(res->status == 200);
    CHECK(res->get_header_value("Content-Type") == "application/x-ndjson");
    CHECK(res->get_header_value("Content-Disposition").find("software-installs.jsonl") !=
          std::string::npos);
    CHECK(res->get_header_value("Content-Disposition").starts_with("attachment"));
    CHECK(res->get_header_value("X-Content-Type-Options") == "nosniff");
    CHECK(h.install_reads == 0); // nothing is read until the provider runs
    CHECK(h.held() == 1);        // admitted: the stream holds its lease from the start

    std::int64_t next = 1;
    std::int64_t lines = 0;
    bool in_order = true;
    const auto t = drive(
        *res,
        [&](const std::string& chunk) {
            for (const auto& line : lines_of(chunk)) {
                in_order = in_order && install_no(line) == next;
                ++next;
                ++lines;
            }
            return true;
        },
        /*keep_body=*/false);
    release(*res, !t.aborted);

    CHECK(t.done);
    CHECK_FALSE(t.aborted);
    CHECK(lines == kRows);
    CHECK(in_order); // consecutive install numbers: no gap and no repeat at any page boundary
    CHECK(h.install_reads == kPages + 1); // the full pages, then the empty page that ends the walk
    CHECK(h.count("jsonl", "completed") == 1);
    CHECK(h.held() == 0);

    // The lease came back: with a capacity of one, a second export is admitted.
    auto again = h.get("?format=jsonl");
    REQUIRE(again);
    CHECK(again->status == 200);
}

TEST_CASE("export route: JSONL rows are the list rows, hostnames from the roster",
          "[software_export][routes]") {
    Harness h;
    h.installs = {install_row("a-1", 1), install_row("a-2", 2)};
    h.roster = {{"a-1", "host-one"}, {"a-2", ""}};
    auto res = h.get("?format=jsonl");
    REQUIRE(res);
    const auto t = drive(*res);
    REQUIRE(t.done);
    const auto lines = lines_of(t.body);
    REQUIRE(lines.size() == 2);
    const auto first = nlohmann::json::parse(lines[0]);
    const auto second = nlohmann::json::parse(lines[1]);
    CHECK(first["agent_id"] == "a-1");
    CHECK(first["hostname"] == "host-one");
    CHECK(first["status"] == "current");
    CHECK(first["last_seen"] == 1'699'000'000);
    CHECK(second["hostname"].is_null()); // a blank hostname reads as unknown
}

TEST_CASE("export route: a confined caller streams only its own rows; a deny-all scope streams "
          "an empty body",
          "[software_export][routes][scope]") {
    Harness h;
    for (int d = 0; d < 10; ++d)
        for (int k = 0; k < 2; ++k)
            h.installs.push_back(install_row(agent_id("a", d, 2), d * 2 + k + 1));

    SECTION("a confined caller") {
        h.scope = scope_of({agent_id("a", 3, 2), agent_id("a", 7, 2)});
        auto res = h.get("?format=jsonl");
        REQUIRE(res);
        const auto t = drive(*res);
        REQUIRE(t.done);
        const auto lines = lines_of(t.body);
        REQUIRE(lines.size() == 4);
        for (const auto& l : lines) {
            const auto agent = nlohmann::json::parse(l)["agent_id"].get<std::string>();
            CHECK((agent == agent_id("a", 3, 2) || agent == agent_id("a", 7, 2)));
        }
        REQUIRE(h.last_query.agent_ids.has_value()); // the scope was pushed into the read
        CHECK(h.last_query.agent_ids->size() == 2);
    }
    SECTION("deny-all, CSV: the header and nothing else") {
        h.scope = Scope{std::unordered_set<std::string>{}};
        auto res = h.get("?format=csv");
        REQUIRE(res);
        CHECK(res->get_header_value("Content-Type") == "text/csv; charset=utf-8");
        const auto t = drive(*res);
        CHECK(t.done);
        CHECK(t.body == std::string(swl::kListCsvHeader) + "\n");
    }
    SECTION("deny-all, JSONL: an empty body, still a clean end") {
        h.scope = Scope{std::unordered_set<std::string>{}};
        auto res = h.get("?format=jsonl");
        REQUIRE(res);
        const auto t = drive(*res);
        CHECK(t.done);
        CHECK(t.body.empty());
    }
}

TEST_CASE("export route: a wide scope's empty pages with non-empty cursors are followed to the "
          "empty cursor",
          "[software_export][routes][scope]") {
    Harness h;
    wide_fixture(h);

    SECTION("JSONL: the first call writes nothing and the stream carries on") {
        auto res = h.get("?format=jsonl");
        REQUIRE(res);
        httplib::DataSink sink;
        std::string body;
        bool done = false;
        sink.write = [&](const char* p, size_t n) {
            body.append(p, n);
            return true;
        };
        sink.is_writable = [] { return true; };
        sink.done = [&] { done = true; };
        REQUIRE(res->content_provider_);
        // The first page is empty (the scan hit its read bound inside the out-of-scope block)
        // but its cursor is not: the provider must neither write nor finish.
        CHECK(res->content_provider_(0, 0, sink));
        CHECK(body.empty());
        CHECK_FALSE(done);

        const auto rest = drive(*res);
        REQUIRE(rest.done);
        CHECK_FALSE(rest.aborted);
        const auto lines = lines_of(rest.body);
        REQUIRE(lines.size() == static_cast<std::size_t>(kIn));
        for (int i = 0; i < kIn; ++i)
            CHECK(nlohmann::json::parse(lines[static_cast<std::size_t>(i)])["agent_id"] ==
                  agent_id("z", i, 3)); // the later in-scope rows all arrived, in order
    }
    SECTION("CSV: the header is written by the first call even though it holds no rows") {
        auto res = h.get("?format=csv");
        REQUIRE(res);
        const auto t = drive(*res);
        REQUIRE(t.done);
        CHECK(t.body.starts_with(std::string(swl::kListCsvHeader) + "\n"));
        CHECK(lines_of(t.body).size() == static_cast<std::size_t>(kIn) + 1);
    }
}

TEST_CASE("export route: under a wide scope no field of an out-of-scope row reaches the body",
          "[software_export][routes][scope]") {
    Harness h;
    wide_fixture(h);
    for (const char* format : {"jsonl", "csv"}) {
        INFO("format=" << format);
        auto res = h.get(std::string("?format=") + format);
        REQUIRE(res);
        const auto t = drive(*res);
        REQUIRE(t.done);
        CHECK(t.body.find("LEAK") == std::string::npos);       // publisher of an excluded row
        CHECK(t.body.find("leak-host") == std::string::npos);  // its hostname from the roster
        CHECK(t.body.find("a-0") == std::string::npos);        // its device id
        CHECK(t.body.find("own-host-z-000") != std::string::npos);
        release(*res, true);
    }
}

TEST_CASE("export route: a run of hidden rows longer than the page-mode OFFSET ceiling is walked "
          "to a clean end, every store read at skip 0",
          "[software_export][routes][scope]") {
    // More consecutive out-of-scope rows than a page-mode cursor can carry: kWideScopeMaxSkip
    // scanned rows, then one more full call of kWideScopeMaxReads reads. A walk that resumed
    // through an OFFSET would be refused on its 27th call and cut the transfer; this one resumes
    // from the last row it scanned. The rows are generated on demand, never held.
    constexpr int kRun = static_cast<int>(software_catalogue::kWideScopeMaxSkip) +
                         software_catalogue::kWideScopeMaxReads * swe::kPageRows + 1;
    Harness h;
    wide_scope(h);
    h.generated_in_from = kRun; // rows 0..kRun-1 are out of scope, the next kIn are the caller's own
    h.generated = kRun + kIn;
    for (const int i : {0, kRun / 2, kRun - 1})
        h.roster[agent_id("a", i)] = "leak-host-" + agent_id("a", i);
    for (int i = 0; i < kIn; ++i)
        h.roster[agent_id("z", i, 3)] = "own-host-" + agent_id("z", i, 3);

    for (const char* format : {"jsonl", "csv"}) {
        INFO("format=" << format);
        h.install_reads = 0;
        auto res = h.get(std::string("?format=") + format);
        REQUIRE(res);
        const auto t = drive(*res);
        release(*res, !t.aborted);
        REQUIRE(t.done); // a clean end, not an aborted transfer
        CHECK_FALSE(t.aborted);
        CHECK(h.count(format, "completed") == 1);
        CHECK(h.count(format, "degraded") == 0);
        CHECK(h.held() == 0);
        // The walk really read past the run, and not one of its reads carried an OFFSET.
        CHECK(h.install_reads > static_cast<int>(software_catalogue::kWideScopeMaxSkip) / swe::kPageRows);
        CHECK(h.max_skip_seen == 0);

        // No field of a hidden row reaches the body.
        CHECK(t.body.find("LEAK") == std::string::npos);
        CHECK(t.body.find("leak-host") == std::string::npos);
        CHECK(t.body.find(agent_id("a", 0)) == std::string::npos);
        CHECK(t.body.find(agent_id("a", kRun - 1)) == std::string::npos);

        // Every in-scope row, once and in order.
        auto lines = lines_of(t.body);
        if (std::string_view(format) == "csv") {
            REQUIRE_FALSE(lines.empty());
            CHECK(lines.front() == std::string(swl::kListCsvHeader));
            lines.erase(lines.begin());
        }
        REQUIRE(lines.size() == static_cast<std::size_t>(kIn));
        for (int i = 0; i < kIn; ++i) {
            const auto& line = lines[static_cast<std::size_t>(i)];
            CHECK(line.find(agent_id("z", i, 3)) != std::string::npos);
            CHECK(line.find("own-host-" + agent_id("z", i, 3)) != std::string::npos);
            CHECK(line.find("1." + std::to_string(kRun + i + 1)) != std::string::npos);
        }
    }
}

TEST_CASE("export route: a wide scope that owns no row streams an empty body and ends cleanly",
          "[software_export][routes][scope]") {
    Harness h;
    wide_scope(h);
    // Two full provider calls of hidden rows and a third that ends exactly on a full read, so the
    // walk learns the end only from the empty read after it.
    h.generated = 2 * software_catalogue::kWideScopeMaxReads * swe::kPageRows + swe::kPageRows;

    SECTION("JSONL: an empty body") {
        auto res = h.get("?format=jsonl");
        REQUIRE(res);
        const auto t = drive(*res);
        release(*res, !t.aborted);
        CHECK(t.done);
        CHECK_FALSE(t.aborted);
        CHECK(t.body.empty());
        CHECK(h.count("jsonl", "completed") == 1);
    }
    SECTION("CSV: the header and nothing else") {
        auto res = h.get("?format=csv");
        REQUIRE(res);
        const auto t = drive(*res);
        release(*res, !t.aborted);
        CHECK(t.done);
        CHECK_FALSE(t.aborted);
        CHECK(t.body == std::string(swl::kListCsvHeader) + "\n");
        CHECK(h.count("csv", "completed") == 1);
    }
    CHECK(h.max_skip_seen == 0);
    CHECK(h.held() == 0);
}

TEST_CASE("export route: the audit row is stored before the first chunk",
          "[software_export][routes][audit]") {
    Harness h;
    h.installs = {install_row("a-1", 1)};

    SECTION("stored before the provider runs, with the stream details") {
        auto res = h.get("?format=csv&name=pkg");
        REQUIRE(res);
        REQUIRE(h.audit_log.size() == 1); // before any chunk
        CHECK(h.install_reads == 0);
        const auto& a = h.audit_log[0];
        CHECK(a.action == "inventory.software.export");
        CHECK(a.result == "success");
        CHECK_FALSE(a.target_id.empty());
        CHECK(a.detail.find("format=csv") != std::string::npos);
        CHECK(a.detail.find("stream=true") != std::string::npos);
        CHECK(a.detail.find("filters=") != std::string::npos);
        CHECK(a.detail.find("cid=") != std::string::npos);
        CHECK(res->get_header_value("Sec-Audit-Failed").empty());
        CHECK_FALSE(res->get_header_value("X-Correlation-Id").empty());
        (void)drive(*res);
        CHECK(h.audit_log.size() == 1); // no second row at stream end
    }
    SECTION("a row that did not persist sets Sec-Audit-Failed and still serves") {
        h.audit_persists = false;
        auto res = h.get("?format=jsonl");
        REQUIRE(res);
        CHECK(res->status == 200);
        CHECK(res->get_header_value("Sec-Audit-Failed") == "true");
        const auto t = drive(*res);
        CHECK(t.done);
        CHECK(lines_of(t.body).size() == 1);
    }
    SECTION("a throwing audit sink is the same, never a 500") {
        h.audit_throws = true;
        auto res = h.get("?format=jsonl");
        REQUIRE(res);
        CHECK(res->status == 200);
        CHECK(res->get_header_value("Sec-Audit-Failed") == "true");
        CHECK(drive(*res).done);
    }
}

TEST_CASE("export route: the export cap reached is a 503 with a retry hint and a denied row; "
          "nothing streams",
          "[software_export][routes][budget]") {
    Harness h(/*concurrency=*/1);
    h.installs = {install_row("a-1", 1)};

    auto first = h.get("?format=jsonl");
    REQUIRE(first);
    CHECK(first->status == 200);
    CHECK(h.held() == 1);

    auto second = h.get("?format=jsonl");
    REQUIRE(second);
    CHECK(second->status == 503);
    CHECK_FALSE(second->content_provider_);
    CHECK(second->body.find("retry_after_ms") != std::string::npos);
    CHECK(second->body.find("5000") != std::string::npos);
    CHECK(second->body.find("too many concurrent software exports") != std::string::npos);
    CHECK(second->get_header_value("Retry-After") == "5");
    REQUIRE(h.audit_log.size() == 2);
    CHECK(h.audit_log[1].result == "denied");
    CHECK(h.audit_log[1].action == "inventory.software.export");
    CHECK(h.audit_log[1].detail.find("export concurrency limit reached") != std::string::npos);
    CHECK(h.audit_log[1].detail.find("export_concurrency_cap") != std::string::npos);
    CHECK(h.install_reads == 0);
    CHECK(h.rejected("export_concurrency_cap") == 1);
    CHECK(h.rejected("global_stream_cap") == 0);
    CHECK(h.held() == 1); // the refusal took nothing

    // Finishing the first transfer frees the lease.
    const auto t = drive(*first);
    release(*first, !t.aborted);
    CHECK(h.held() == 0);
    auto third = h.get("?format=jsonl");
    REQUIRE(third);
    CHECK(third->status == 200);
}

TEST_CASE("export route: the server's held-open budget full from another surface is a 503 with a "
          "retry hint and a denied row; nothing streams",
          "[software_export][routes][budget]") {
    // Export cap 2 would admit this request; the budget's global cap (2) is spent elsewhere.
    Harness h(/*concurrency=*/2, /*wire_reads=*/true, /*wire_budget=*/true, /*global_cap=*/2);
    h.installs = {install_row("a-1", 1)};
    auto a = h.budget.try_acquire(sb::SseSurface::kDashboardExec, "someone", 0);
    auto b = h.budget.try_acquire(sb::SseSurface::kApiEvents, "someone-else", 0);
    REQUIRE(a.lease);
    REQUIRE(b.lease);

    auto res = h.get("?format=jsonl");
    REQUIRE(res);
    CHECK(res->status == 503);
    CHECK_FALSE(res->content_provider_);
    CHECK(res->body.find("retry_after_ms") != std::string::npos);
    CHECK(res->body.find("5000") != std::string::npos);
    CHECK(res->body.find("held-open") != std::string::npos);
    CHECK(res->body.find("too many concurrent software exports") == std::string::npos);
    CHECK(res->get_header_value("Retry-After") == "5");
    REQUIRE(h.audit_log.size() == 1);
    CHECK(h.audit_log[0].result == "denied");
    CHECK(h.audit_log[0].detail.find("held-open stream budget full") != std::string::npos);
    CHECK(h.audit_log[0].detail.find("global_stream_cap") != std::string::npos);
    CHECK(h.audit_log[0].detail.find("export concurrency limit") == std::string::npos);
    CHECK(h.install_reads == 0);
    CHECK(h.rejected("global_stream_cap") == 1);
    CHECK(h.rejected("export_concurrency_cap") == 0);
    CHECK(h.held() == 0);

    a.lease.release(); // room again
    auto ok = h.get("?format=jsonl");
    REQUIRE(ok);
    CHECK(ok->status == 200);
    CHECK(h.held() == 1);
}

TEST_CASE("export route: a cap of 0 is clamped to one export, never read as unlimited",
          "[software_export][routes][budget]") {
    // StreamBudget reads a per-key cap of 0 as "no limit"; the route clamps before it gets there.
    Harness h(/*concurrency=*/0);
    h.installs = {install_row("a-1", 1)};
    auto first = h.get("?format=jsonl");
    REQUIRE(first);
    CHECK(first->status == 200);
    CHECK(h.get("?format=jsonl")->status == 503);
    CHECK(h.held() == 1);
}

TEST_CASE("export route: a refused request consumes no slot and writes no audit row",
          "[software_export][routes][budget]") {
    Harness h(/*concurrency=*/1);
    h.installs = {install_row("a-1", 1)};
    for (const char* bad : {"", "?format=json", "?format=csv&cursor=x", "?format=csv&limit=10",
                            "?format=csv&version_min=1.0"}) {
        INFO("query=" << bad);
        auto res = h.get(bad);
        REQUIRE(res);
        CHECK(res->status == 400);
        CHECK_FALSE(res->content_provider_);
    }
    CHECK(h.audit_log.empty());
    CHECK(h.install_reads == 0);
    CHECK(h.held() == 0);
    auto ok = h.get("?format=jsonl");
    REQUIRE(ok);
    CHECK(ok->status == 200); // the one slot was never taken by a refused request
}

TEST_CASE("export route: a mid-stream read degrade aborts the transfer and frees the lease",
          "[software_export][routes][degrade][budget]") {
    Harness h(/*concurrency=*/1);
    for (int i = 0; i < 5'000; ++i)
        h.installs.push_back(install_row(agent_id("a", i), i + 1));

    SECTION("an installs read fails on the third page") {
        h.fail_read_at = 3;
        auto res = h.get("?format=jsonl");
        REQUIRE(res);
        const auto t = drive(*res);
        CHECK(t.aborted); // the provider returned false: httplib cuts the transfer
        CHECK_FALSE(t.done);
        CHECK(lines_of(t.body).size() == 2'000); // the two pages before the failure were sent
        CHECK(h.held() == 1);                    // held until the transfer is torn down
        release(*res, false);
        CHECK(h.count("jsonl", "degraded") == 1);
    }
    SECTION("a last-poll read fails on the second page") {
        h.fail_last_seen_at = 2;
        auto res = h.get("?format=csv");
        REQUIRE(res);
        const auto t = drive(*res);
        CHECK(t.aborted);
        CHECK_FALSE(t.done);
        release(*res, false);
        CHECK(h.count("csv", "degraded") == 1);
    }
    CHECK(h.held() == 0);
    auto next = h.get("?format=jsonl"); // the lease was released
    REQUIRE(next);
    CHECK(next->status == 200);
}

TEST_CASE("export route: the wall-clock deadline aborts the transfer and frees the lease",
          "[software_export][routes][deadline][budget]") {
    Harness h(/*concurrency=*/1);
    for (int i = 0; i < 3'000; ++i)
        h.installs.push_back(install_row(agent_id("a", i), i + 1));
    auto res = h.get("?format=jsonl");
    REQUIRE(res);

    httplib::DataSink sink;
    std::string body;
    bool done = false;
    sink.write = [&](const char* p, size_t n) {
        body.append(p, n);
        return true;
    };
    sink.is_writable = [] { return true; };
    sink.done = [&] { done = true; };
    REQUIRE(res->content_provider_);

    h.clock_s += swe::kExportMaxSeconds - 1; // one second inside the bound: still streaming
    CHECK(res->content_provider_(0, 0, sink));
    CHECK(lines_of(body).size() == 1'000);
    h.clock_s += 1; // the bound is reached
    CHECK_FALSE(res->content_provider_(0, 0, sink));
    CHECK_FALSE(done);
    CHECK(lines_of(body).size() == 1'000); // nothing further was written
    CHECK(h.held() == 1);
    release(*res, false);
    CHECK(h.count("jsonl", "deadline") == 1);
    CHECK(h.held() == 0);

    auto next = h.get("?format=jsonl");
    REQUIRE(next);
    CHECK(next->status == 200);
}

TEST_CASE("export route: a client that goes away frees the lease",
          "[software_export][routes][budget]") {
    Harness h(/*concurrency=*/1);
    for (int i = 0; i < 3'000; ++i)
        h.installs.push_back(install_row(agent_id("a", i), i + 1));

    SECTION("the releaser runs without done ever being called") {
        auto res = h.get("?format=jsonl");
        REQUIRE(res);
        REQUIRE(res->content_provider_resource_releaser_);
        CHECK(h.get("?format=jsonl")->status == 503); // the lease is held
        CHECK(h.held() == 1);
        release(*res, false);
        CHECK(h.count("jsonl", "aborted") == 1);
        CHECK(h.held() == 0);
        CHECK(h.get("?format=jsonl")->status == 200);
    }
    SECTION("a write the client refuses ends the provider") {
        auto res = h.get("?format=jsonl");
        REQUIRE(res);
        int chunks = 0;
        const auto t = drive(*res, [&](const std::string&) { return ++chunks < 2; });
        CHECK(t.aborted);
        CHECK_FALSE(t.done);
        release(*res, false);
        CHECK(h.count("jsonl", "aborted") == 1);
        CHECK(h.held() == 0);
        CHECK(h.get("?format=jsonl")->status == 200);
    }
    SECTION("the response being destroyed frees the lease even if the releaser never ran") {
        {
            auto res = h.get("?format=jsonl");
            REQUIRE(res);
            CHECK(h.get("?format=jsonl")->status == 503);
            CHECK(h.held() == 1);
        }
        CHECK(h.held() == 0);
        CHECK(h.get("?format=jsonl")->status == 200);
    }
}

namespace {

// A hand-driven sink for the cases that step the provider one call at a time.
struct ManualSink {
    httplib::DataSink sink;
    std::string body;
    bool done{false};
    ManualSink() {
        sink.write = [this](const char* p, size_t n) {
            body.append(p, n);
            return true;
        };
        sink.is_writable = [] { return true; };
        sink.done = [this] { done = true; };
    }
    ManualSink(const ManualSink&) = delete;
    ManualSink& operator=(const ManualSink&) = delete;
};

} // namespace

TEST_CASE("export route: a server shutdown aborts the stream and frees the lease",
          "[software_export][routes][budget]") {
    Harness h(/*concurrency=*/1);
    for (int i = 0; i < 3'000; ++i)
        h.installs.push_back(install_row(agent_id("a", i), i + 1));
    auto res = h.get("?format=jsonl");
    REQUIRE(res);
    REQUIRE(res->content_provider_);

    ManualSink out;
    CHECK(res->content_provider_(0, 0, out.sink)); // streaming: the first page goes out
    CHECK(lines_of(out.body).size() == 1'000);

    h.budget.begin_closing(); // ServerImpl::stop() sets this ahead of joining the web thread
    CHECK_FALSE(res->content_provider_(0, 0, out.sink)); // cut now, not after up to 900 s
    CHECK_FALSE(out.done);
    CHECK(lines_of(out.body).size() == 1'000); // no further read, no further write
    CHECK(h.held() == 1);
    release(*res, false);
    CHECK(h.held() == 0);
    CHECK(h.count("jsonl", "aborted") == 1); // the same label as a client that went away
}

TEST_CASE("export route: a pending engine quota slot is adopted into the stream and released "
          "only by the releaser",
          "[software_export][routes][budget][quota]") {
    using sb::tls_quota_slot;
    tls_quota_slot().reset(); // no carry-over from an earlier test on this thread

    PrincipalQuota quota{PrincipalQuotaConfig{.max_concurrency = 4}};
    Harness h(/*concurrency=*/2);
    h.installs = {install_row("a-1", 1)};

    auto slot = quota.try_acquire("engine:export", QuotaSide::kEngine);
    REQUIRE(slot.admitted());
    REQUIRE(quota.in_flight("engine:export") == 1);
    tls_quota_slot() = std::move(slot); // what the pre-routing chokepoint does

    SECTION("a streamed export keeps the slot for the stream's whole life") {
        auto res = h.get("?format=jsonl");
        REQUIRE(res);
        REQUIRE(res->status == 200);
        // Moved OUT of the thread_local by the adopter. Left behind, it would be released at
        // post-routing while the stream was still running (UP-1).
        CHECK_FALSE(tls_quota_slot().has_value());
        CHECK(quota.in_flight("engine:export") == 1);

        const auto t = drive(*res);
        REQUIRE(t.done);
        CHECK(quota.in_flight("engine:export") == 1); // the data ran out; the releaser has not
        release(*res, true);
        CHECK(quota.in_flight("engine:export") == 0);
        CHECK(h.held() == 0);
    }
    SECTION("a request refused before the stream leaves the slot for post-routing") {
        auto res = h.get("?format=json"); // 400: never reaches the content provider
        REQUIRE(res);
        CHECK(res->status == 400);
        CHECK(tls_quota_slot().has_value());
        CHECK(quota.in_flight("engine:export") == 1);
    }
    SECTION("a request refused by the budget leaves the slot for post-routing too") {
        Harness full(/*concurrency=*/2, true, true, /*global_cap=*/1);
        full.installs = h.installs;
        auto held = full.budget.try_acquire(sb::SseSurface::kApiEvents, "someone", 0);
        REQUIRE(held.lease);
        auto res = full.get("?format=jsonl");
        REQUIRE(res);
        CHECK(res->status == 503);
        CHECK(tls_quota_slot().has_value());
        CHECK(quota.in_flight("engine:export") == 1);
    }
    tls_quota_slot().reset(); // post-routing's release
    CHECK(quota.in_flight("engine:export") == 0);
}

TEST_CASE("export route: the surface name and the reject labels match the budget's",
          "[software_export][routes][budget]") {
    CHECK(std::string(sb::to_string(sb::SseSurface::kSoftwareExport)) == "software_export");
    // The route compares the budget's tokens; the metric label is the operator-facing spelling, and
    // the global one is the budget's own token.
    CHECK(swe::kRejectReasons[1] == sb::StreamBudget::kRejectGlobal);
}

TEST_CASE("export route: an unwired store or budget is a 503, never an empty 200; the gate "
          "decides first",
          "[software_export][routes][budget]") {
    SECTION("no store and no reads") {
        Harness h(/*concurrency=*/2, /*wire_reads=*/false);
        auto res = h.get("?format=csv");
        REQUIRE(res);
        CHECK(res->status == 503);
        CHECK_FALSE(res->content_provider_);
        CHECK(h.audit_log.empty());
    }
    SECTION("no budget is a 503 after the gate, never an unmetered export") {
        Harness h(/*concurrency=*/2, /*wire_reads=*/true, /*wire_budget=*/false);
        h.installs = {install_row("a-1", 1)};
        auto res = h.get("?format=jsonl");
        REQUIRE(res);
        CHECK(res->status == 503);
        CHECK_FALSE(res->content_provider_);
        CHECK(h.gate_calls == 1);
        CHECK(h.install_reads == 0);
        CHECK(h.audit_log.empty());
        CHECK(h.held() == 0);
    }
    SECTION("a denied caller with no budget wired sees the gate's answer, not the wiring") {
        Harness h(/*concurrency=*/2, /*wire_reads=*/true, /*wire_budget=*/false);
        h.admitted = false;
        auto res = h.get("?format=jsonl");
        REQUIRE(res);
        CHECK(res->status == 403);
        CHECK(h.gate_calls == 1);
    }
    SECTION("a denied caller reaches no read, no audit row and takes no slot") {
        Harness h(/*concurrency=*/1);
        h.installs = {install_row("a-1", 1)};
        h.admitted = false;
        auto res = h.get("?format=csv");
        REQUIRE(res);
        CHECK(res->status == 403);
        CHECK_FALSE(res->content_provider_);
        CHECK(h.gate_calls == 1);
        CHECK(h.install_reads == 0);
        CHECK(h.audit_log.empty());
        CHECK(h.held() == 0);
        h.admitted = true;
        CHECK(h.get("?format=csv")->status == 200);
    }
}

TEST_CASE("export route: a version range is resolved once, then held for the whole stream",
          "[software_export][routes][budget]") {
    Harness h;
    for (int i = 1; i <= 3; ++i)
        h.installs.push_back(install_row(agent_id("a", i), i));
    h.distinct = {"1.1", "1.2", "1.3"};

    SECTION("version_min narrows the read to the matching versions") {
        auto res = h.get("?format=jsonl&name=pkg&match=exact&version_min=1.2");
        REQUIRE(res);
        REQUIRE(res->status == 200);
        const auto t = drive(*res);
        REQUIRE(t.done);
        CHECK(lines_of(t.body).size() == 2);
        REQUIRE(h.last_query.versions.has_value());
        CHECK(*h.last_query.versions == std::vector<std::string>{"1.2", "1.3"});
    }
    SECTION("a degraded version read is a 503 that holds no lease") {
        Harness one(/*concurrency=*/1);
        one.installs = h.installs;
        one.distinct = h.distinct;
        one.distinct_degrades = true;
        auto res = one.get("?format=jsonl&name=pkg&match=exact&version_min=1.2");
        REQUIRE(res);
        CHECK(res->status == 503);
        CHECK_FALSE(res->content_provider_);
        CHECK(one.held() == 0); // admitted, then refused: the lease went back on the way out
        one.distinct_degrades = false;
        CHECK(one.get("?format=jsonl&name=pkg&match=exact&version_min=1.2")->status == 200);
    }
    SECTION("a range not resolvable for the title is a 400 that holds no lease") {
        Harness one(/*concurrency=*/1);
        one.installs = h.installs;
        for (int i = 0; i < kCatalogRowCap; ++i)
            one.distinct.push_back("1." + std::to_string(i)); // as many versions as the cap allows
        auto res = one.get("?format=jsonl&name=pkg&match=exact&version_min=1.2");
        REQUIRE(res);
        CHECK(res->status == 400);
        CHECK_FALSE(res->content_provider_);
        CHECK(one.held() == 0);
        CHECK(one.get("?format=jsonl")->status == 200); // the one export slot is still free
    }
}
