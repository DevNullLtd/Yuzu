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
 *
 * XLSX (`format=xlsx`) is built whole before the response starts, so its cases drive a SIZED
 * provider by hand (offset advancing to the content length) and read the body back as a workbook
 * through minizip. File justification: the export writes a real temporary workbook by design (the
 * property under test is that it is removed on every path), so those cases use a `yuzu_test_`
 * directory the TempDir removes at the end; the disk-free figure and the clock are injected, so
 * no case depends on the machine's disk or on time passing. One case makes a real write fail
 * (RLIMIT_FSIZE, the only way short of a full volume): a guard ignores SIGXFSZ, holds the soft
 * limit across one request only, with no assertion inside the window, and restores both.
 */

#include <catch2/catch_test_macros.hpp>
#include <catch2/generators/catch_generators.hpp>

#include "../test_helpers.hpp"
#include "principal_quota.hpp"
#include "principal_quota_gate.hpp"
#include "software_export_routes.hpp"
#include "software_export_xlsx.hpp"
#include "stream_budget.hpp"
#include "test_route_sink.hpp"

#include <yuzu/metrics.hpp>

#include <minizip/unzip.h>

#include <sys/resource.h>
#include <sys/stat.h>

#include <algorithm>
#include <cctype>
#include <csignal>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <functional>
#include <map>
#include <memory>
#include <optional>
#include <stdexcept>
#include <string>
#include <string_view>
#include <tuple>
#include <unordered_map>
#include <unordered_set>
#include <utility>
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

// Forwards every registration to the TestRouteSink and keeps the export route's handler, so a case
// can call it with a fresh httplib::Response (status -1, as httplib hands it to a handler), which
// TestRouteSink pre-sets to 200 and so cannot tell a handler that sets its own status from one
// that does not.
class TapSink : public HttpRouteSink {
public:
    TapSink(yuzu::server::test::TestRouteSink& inner, Handler& export_get)
        : inner_(inner), export_get_(export_get) {}
    void Get(const std::string& p, Handler h) override {
        if (p == "/api/v1/inventory/software/export")
            export_get_ = h;
        inner_.Get(p, std::move(h));
    }
    void Post(const std::string& p, Handler h) override { inner_.Post(p, std::move(h)); }
    void Put(const std::string& p, Handler h) override { inner_.Put(p, std::move(h)); }
    void Delete(const std::string& p, Handler h) override { inner_.Delete(p, std::move(h)); }
    void Patch(const std::string& p, Handler h) override { inner_.Patch(p, std::move(h)); }
    void Options(const std::string& p, Handler h) override { inner_.Options(p, std::move(h)); }

private:
    yuzu::server::test::TestRouteSink& inner_;
    Handler& export_get_;
};

struct Harness {
    yuzu::MetricsRegistry metrics;     // outlives the routes that count into it
    sb::StreamBudget budget;           // the one held-open budget; outlives every Response lease
    SoftwareExportRoutes routes;       // declared BEFORE the sink that holds handlers capturing it
    yuzu::server::test::TestRouteSink sink;
    httplib::Server::Handler export_handler; // the export route's handler, kept by TapSink

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

    // XLSX: the injected free-space figure (nullopt = unreadable) and, optionally, a script that
    // answers per call (1-based). Called once per disk grant.
    std::optional<std::uintmax_t> disk_free{std::uintmax_t{1} << 40};
    std::function<std::optional<std::uintmax_t>(int)> disk_free_at;
    int disk_free_calls{0};
    // Runs after every installs read is counted (1-based), before it answers: lets a case move
    // the clock or start the shutdown in the middle of a build.
    std::function<void(int)> on_install_read;

    [[nodiscard]] SoftwareFleetRow generated_row(int i) const {
        if (generated_in_from >= 0 && i >= generated_in_from)
            return install_row(agent_id("z", i - generated_in_from, 3), i + 1);
        const auto id = agent_id("a", i);
        return install_row(id, i + 1, generated_in_from >= 0 ? "LEAK-" + id : "Acme");
    }

    // `global_cap` is the budget's server-wide cap (the --max-sse-streams side); `concurrency` is the
    // export cap (--inventory-export-concurrency). `wire_budget` false leaves Deps::stream_budget null.
    explicit Harness(int concurrency = 2, bool wire_reads = true, bool wire_budget = true,
                     std::size_t global_cap = 64, swe::Limits limits = {},
                     std::filesystem::path xlsx_dir = {})
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
        deps.limits = limits;
        deps.xlsx_tmp_dir = std::move(xlsx_dir);
        deps.disk_free_fn = [this]() -> std::optional<std::uintmax_t> {
            ++disk_free_calls;
            return disk_free_at ? disk_free_at(disk_free_calls) : disk_free;
        };
        if (wire_reads) {
            auto& r = deps.reads;
            r.installs = [this](const SoftwareFleetQuery& q)
                -> std::optional<std::vector<SoftwareFleetRow>> {
                ++install_reads;
                if (on_install_read)
                    on_install_read(install_reads);
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
        TapSink tap(sink, export_handler);
        routes.register_routes(tap, std::move(deps));
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
    SECTION("a device outside the caller's scope named by agent_id: an empty export, no read") {
        h.scope = scope_of({agent_id("a", 3, 2), agent_id("a", 7, 2)});
        const auto denied = agent_id("a", 5, 2); // has rows in the fixture, is not in the scope
        for (const char* format : {"jsonl", "csv"}) {
            INFO("format=" << format);
            auto res = h.get(std::string("?format=") + format + "&agent_id=" + denied);
            REQUIRE(res);
            CHECK(res->status == 200);
            const auto t = drive(*res);
            CHECK(t.done);
            CHECK_FALSE(t.aborted);
            CHECK(t.body.find(denied) == std::string::npos);
            CHECK(t.body == (std::string_view(format) == "csv"
                                 ? std::string(swl::kListCsvHeader) + "\n"
                                 : std::string()));
            release(*res, true);
        }
        CHECK(h.install_reads == 0); // the confinement decides before any store read
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

TEST_CASE("export route: under a wide scope a named device outside it streams an empty export "
          "without a store read",
          "[software_export][routes][scope]") {
    Harness h;
    wide_fixture(h);
    const auto denied = agent_id("a", 5); // an out-of-scope device that has rows in the fixture
    for (const char* format : {"jsonl", "csv"}) {
        INFO("format=" << format);
        auto res = h.get(std::string("?format=") + format + "&agent_id=" + denied);
        REQUIRE(res);
        CHECK(res->status == 200);
        const auto t = drive(*res);
        CHECK(t.done);
        CHECK_FALSE(t.aborted);
        CHECK(t.body.find(denied) == std::string::npos);
        CHECK(t.body.find("LEAK") == std::string::npos);
        CHECK(t.body == (std::string_view(format) == "csv" ? std::string(swl::kListCsvHeader) + "\n"
                                                           : std::string()));
        release(*res, true);
    }
    CHECK(h.install_reads == 0); // not even the wide scope's bounded reads run
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

TEST_CASE("export route: the row limit cuts the stream before the page that would pass it, in both "
          "formats, and the metric says limit",
          "[software_export][routes][limit]") {
    for (const char* format : {"jsonl", "csv"}) {
        DYNAMIC_SECTION(format) {
            Harness h(/*concurrency=*/1, true, true, 64,
                      {.max_rows = swe::kMinMaxRows, .max_bytes = swe::kDefaultMaxBytes});
            h.generated = 3'500;
            auto res = h.get(std::string("?format=") + format);
            REQUIRE(res);
            const auto cut = drive(*res);
            CHECK(cut.aborted); // cut: no terminating chunk
            const auto lines = lines_of(cut.body);
            // One full page of 1,000 rows (+ the CSV header), never a row of the second.
            CHECK(lines.size() == 1'000 + (std::string(format) == "csv" ? 1u : 0u));
            CHECK(h.held() == 1);
            release(*res, false);
            CHECK(h.count(format, "limit") == 1);
            CHECK(h.count(format, "completed") == 0);
            CHECK(h.held() == 0);
        }
    }
}

TEST_CASE("export route: the byte limit cuts the stream and never lets the body pass it, in both "
          "formats",
          "[software_export][routes][limit]") {
    for (const char* format : {"jsonl", "csv"}) {
        DYNAMIC_SECTION(format) {
            Harness h(/*concurrency=*/1, true, true, 64,
                      {.max_rows = swe::kDefaultMaxRows, .max_bytes = swe::kMinMaxBytes});
            h.generated = 30'000; // far more than 1 MiB of rows
            auto res = h.get(std::string("?format=") + format);
            REQUIRE(res);
            const auto cut = drive(*res);
            CHECK(cut.aborted);
            CHECK(cut.body.size() <= static_cast<std::size_t>(swe::kMinMaxBytes));
            CHECK(cut.body.size() > 0); // at least one page fitted
            release(*res, false);
            CHECK(h.count(format, "limit") == 1);
        }
    }
}

TEST_CASE("export route: a result inside both limits still ends cleanly and counts completed",
          "[software_export][routes][limit]") {
    Harness h(/*concurrency=*/1, true, true, 64,
              {.max_rows = swe::kMinMaxRows, .max_bytes = swe::kDefaultMaxBytes});
    h.generated = 1'000; // exactly the row limit: allowed (a cap is a maximum, not a threshold)
    auto res = h.get("?format=jsonl");
    REQUIRE(res);
    const auto cut = drive(*res);
    CHECK(cut.done);
    CHECK_FALSE(cut.aborted);
    CHECK(lines_of(cut.body).size() == 1'000);
    release(*res, true);
    CHECK(h.count("jsonl", "completed") == 1);
    CHECK(h.count("jsonl", "limit") == 0);
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
        CHECK(res->get_header_value("Retry-After") == "5"); // the same hint as the budget refusals
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

// ── XLSX ────────────────────────────────────────────────────────────────────────────────────────

namespace {

namespace fs = std::filesystem;

constexpr auto kReserve = static_cast<std::uintmax_t>(swe::kXlsxDiskReserveBytes);
constexpr auto kGrant = static_cast<std::uintmax_t>(swe::kXlsxDiskGrantBytes);
constexpr auto kFactor = static_cast<std::uintmax_t>(swe::kXlsxPeakDiskFactor);
// Free space that covers exactly one export's first grant (every export here asks for kGrant).
constexpr std::uintmax_t kRoomForOne = kReserve + kFactor * kGrant;

// A Harness with a real temporary directory for the workbooks and a scratch place to read bodies
// back (outside the export directory, so "the export directory is empty" stays checkable).
struct XlsxHarness {
    yuzu::test::TempDir root{"yuzu_test_xlsx_route_"};
    fs::path dir;
    Harness h;
    explicit XlsxHarness(int concurrency = 2, swe::Limits limits = {},
                         const std::function<fs::path(const fs::path&)>& make_dir = {})
        : dir(make_dir ? make_dir(root.path) : root.path / "export-tmp"),
          h(concurrency, true, true, 64, limits, dir) {}

    [[nodiscard]] std::size_t files_in_dir() const {
        std::error_code ec;
        std::size_t n = 0;
        for (fs::directory_iterator it(dir, ec), end; !ec && it != end; it.increment(ec))
            ++n;
        return n;
    }
};

struct SizedTransfer {
    std::string body;
    bool aborted{false};
    int calls{0};
};

// Drives a SIZED provider the way httplib does: offset advances to the content length, the
// provider is handed what is left each time. `before_call` sees the 0-based call index.
SizedTransfer drive_sized(httplib::Response& res, const std::function<void(int)>& before_call = {}) {
    SizedTransfer t;
    httplib::DataSink sink;
    std::size_t offset = 0;
    sink.write = [&](const char* p, size_t n) {
        t.body.append(p, n);
        offset += n;
        return true;
    };
    sink.is_writable = [] { return true; };
    sink.done = [] {};
    REQUIRE(res.content_provider_);
    while (offset < res.content_length_) {
        if (before_call)
            before_call(t.calls);
        ++t.calls;
        const auto before = offset;
        if (!res.content_provider_(offset, res.content_length_ - offset, sink) || offset == before) {
            t.aborted = true;
            break;
        }
    }
    return t;
}

// The worksheet XML of a workbook held in `body` (nullopt when it is not a valid workbook).
std::optional<std::string> sheet_xml(const fs::path& scratch, const std::string& body) {
    fs::create_directories(scratch);
    const auto p = scratch / "readback.xlsx";
    {
        std::ofstream out(p, std::ios::binary);
        out.write(body.data(), static_cast<std::streamsize>(body.size()));
    }
    unzFile zf = unzOpen64(p.string().c_str());
    if (!zf)
        return std::nullopt;
    std::optional<std::string> xml;
    if (unzLocateFile(zf, "xl/worksheets/sheet1.xml", 0) == UNZ_OK &&
        unzOpenCurrentFile(zf) == UNZ_OK) {
        std::string got;
        char buf[16384];
        for (int n = unzReadCurrentFile(zf, buf, sizeof buf); n > 0;
             n = unzReadCurrentFile(zf, buf, sizeof buf))
            got.append(buf, static_cast<std::size_t>(n));
        unzCloseCurrentFile(zf);
        xml = std::move(got);
    }
    unzClose(zf);
    return xml;
}

std::size_t occurrences(const std::string& hay, std::string_view needle) {
    std::size_t n = 0;
    for (auto at = hay.find(needle); at != std::string::npos; at = hay.find(needle, at + 1))
        ++n;
    return n;
}

// Makes a real write fail: the soft file-size limit for one narrow window. SIGXFSZ is ignored so
// the failing write returns EFBIG instead of killing the process, and both are restored on every
// path. Hold it only around the request: no assertion inside the window. (The same guard is in
// test_software_export_xlsx.cpp; the shared test header is outside this change.)
class FsizeLimit {
public:
    explicit FsizeLimit(std::uintmax_t bytes) {
        if (getrlimit(RLIMIT_FSIZE, &old_) != 0)
            return;
        old_signal_ = std::signal(SIGXFSZ, SIG_IGN);
        rlimit lim = old_;
        lim.rlim_cur = static_cast<rlim_t>(bytes);
        armed_ = setrlimit(RLIMIT_FSIZE, &lim) == 0;
    }
    ~FsizeLimit() {
        if (armed_)
            setrlimit(RLIMIT_FSIZE, &old_);
        if (old_signal_ != SIG_ERR)
            std::signal(SIGXFSZ, old_signal_);
    }
    FsizeLimit(const FsizeLimit&) = delete;
    FsizeLimit& operator=(const FsizeLimit&) = delete;
    [[nodiscard]] bool armed() const { return armed_; }

private:
    rlimit old_{};
    void (*old_signal_)(int){SIG_ERR};
    bool armed_{false};
};

// Rows whose publisher is far past the cell cap: a few hundred of them fill a 16 MiB disk grant.
void fat_rows(Harness& h, int n) {
    for (int i = 0; i < n; ++i) {
        auto r = install_row(agent_id("a", i), i + 1);
        r.entry.publisher = std::string(40'000, 'p');
        h.installs.push_back(std::move(r));
    }
}

} // namespace

TEST_CASE("export route xlsx: a sized 200 whose body is the workbook, with the file gone once "
          "released",
          "[software_export][routes][xlsx]") {
    XlsxHarness x;
    x.h.installs = {install_row("a-1", 1), install_row("a-2", 2)};
    x.h.roster = {{"a-1", "host-one"}};

    auto res = x.h.get("?format=xlsx");
    REQUIRE(res);
    CHECK(res->status == 200);
    CHECK(res->get_header_value("Content-Type") ==
          "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet");
    CHECK(res->get_header_value("Content-Disposition") ==
          "attachment; filename=\"software-installs.xlsx\"");
    CHECK(res->get_header_value("X-Content-Type-Options") == "nosniff");
    CHECK_FALSE(res->get_header_value("X-Correlation-Id").empty());
    REQUIRE(res->content_provider_);
    CHECK_FALSE(res->is_chunked_content_provider_); // sized: httplib sends a Content-Length
    CHECK(res->content_length_ > 0);
    CHECK(x.h.held() == 1);        // the lease is held from admission to the last byte
    CHECK(x.files_in_dir() == 1);  // the built workbook waits for its delivery

    // One success audit row, written after the build, carrying what was built.
    REQUIRE(x.h.audit_log.size() == 1);
    const auto& a = x.h.audit_log[0];
    CHECK(a.action == "inventory.software.export");
    CHECK(a.result == "success");
    CHECK(a.detail.find("format=xlsx") != std::string::npos);
    CHECK(a.detail.find("stream=false") != std::string::npos);
    CHECK(a.detail.find("rows=2") != std::string::npos);
    CHECK(a.detail.find("bytes=" + std::to_string(res->content_length_)) != std::string::npos);
    CHECK(a.detail.find("truncated_cells=0") != std::string::npos);
    CHECK(a.detail.find("filters=") != std::string::npos);
    CHECK(a.detail.find("cid=") != std::string::npos);
    CHECK(res->get_header_value("Sec-Audit-Failed").empty());

    const auto t = drive_sized(*res);
    CHECK_FALSE(t.aborted);
    CHECK(t.body.size() == res->content_length_); // Content-Length equals the body
    // Default limits are far under 4 GiB: an ordinary zip, version-needed 20 in the first local
    // header (a ZIP64 container would say 45).
    REQUIRE(t.body.size() >= 6);
    CHECK((static_cast<unsigned>(static_cast<unsigned char>(t.body[4])) |
           (static_cast<unsigned>(static_cast<unsigned char>(t.body[5])) << 8)) == 20U);
    const auto xml = sheet_xml(x.root.path / "readback", t.body);
    REQUIRE(xml.has_value()); // the body opens as a workbook
    CHECK(occurrences(*xml, "<row ") == 3); // the header and two rows
    for (const char* cell : {">agent_id<", ">a-1<", ">a-2<", ">host-one<", ">1.1<", ">1.2<"})
        CHECK(xml->find(cell) != std::string::npos);
    CHECK(xml->find("<f>") == std::string::npos); // every cell is text

    release(*res, true);
    CHECK(x.files_in_dir() == 0);
    CHECK(x.h.held() == 0);
    CHECK(x.h.count("xlsx", "completed") == 1);
    CHECK(x.h.audit_log.size() == 1); // no second row at the end
}

TEST_CASE("export route xlsx: the audit miss still serves, and a cut cell is counted",
          "[software_export][routes][xlsx][audit]") {
    XlsxHarness x;
    auto r = install_row("a-1", 1);
    r.entry.publisher = std::string(40'000, 'p');
    x.h.installs = {r};
    x.h.audit_persists = false;
    auto res = x.h.get("?format=xlsx");
    REQUIRE(res);
    CHECK(res->status == 200);
    CHECK(res->get_header_value("Sec-Audit-Failed") == "true");
    REQUIRE(x.h.audit_log.size() == 1);
    CHECK(x.h.audit_log[0].detail.find("truncated_cells=1") != std::string::npos);
    const auto t = drive_sized(*res);
    CHECK_FALSE(t.aborted);
    CHECK(sheet_xml(x.root.path / "readback", t.body).has_value()); // the file is still served
}

TEST_CASE("export route xlsx: the row limit is a 413 naming it, at one row past; at the limit it "
          "serves",
          "[software_export][routes][xlsx][limits]") {
    swe::Limits limits;
    limits.max_rows = swe::kPageRows; // the floor: 1,000
    XlsxHarness x(2, limits);

    SECTION("one row past the limit") {
        x.h.generated = swe::kPageRows + 1;
        auto res = x.h.get("?format=xlsx");
        REQUIRE(res);
        CHECK(res->status == 413);
        CHECK_FALSE(res->content_provider_);
        CHECK(res->body.find("row limit of 1000 rows") != std::string::npos);
        CHECK(res->body.find("--inventory-export-max-rows") != std::string::npos);
        CHECK(res->body.find("narrow the filters, or use format=jsonl or csv") != std::string::npos);
        CHECK(res->get_header_value("Retry-After").empty());
        CHECK(x.files_in_dir() == 0);
        CHECK(x.h.held() == 0);
        CHECK(x.h.count("xlsx", "limit") == 1);
        REQUIRE(x.h.audit_log.size() == 1);
        CHECK(x.h.audit_log[0].result == "failure");
        CHECK(x.h.audit_log[0].detail.find("outcome=limit_rows") != std::string::npos);
        CHECK(x.h.audit_log[0].detail.find("format=xlsx") != std::string::npos);
        CHECK(x.h.audit_log[0].detail.find("cid=") != std::string::npos);
    }
    SECTION("exactly at the limit") {
        x.h.generated = swe::kPageRows;
        auto res = x.h.get("?format=xlsx");
        REQUIRE(res);
        CHECK(res->status == 200);
        const auto t = drive_sized(*res);
        const auto xml = sheet_xml(x.root.path / "readback", t.body);
        REQUIRE(xml.has_value());
        CHECK(occurrences(*xml, "<row ") == static_cast<std::size_t>(swe::kPageRows) + 1);
        release(*res, true);
        CHECK(x.h.count("xlsx", "limit") == 0);
    }
}

TEST_CASE("export route xlsx: the byte limit counts sheet bytes, not cell text",
          "[software_export][routes][xlsx][limits]") {
    swe::Limits limits;
    limits.max_bytes = std::int64_t{1} << 20; // the floor: 1 MiB
    XlsxHarness x(2, limits);

    SECTION("many short cells: the text is far under the limit, the markup is not") {
        x.h.generated = 3'000; // ~100 bytes of text a row; ~10x that as accounted sheet bytes
        auto res = x.h.get("?format=xlsx");
        REQUIRE(res);
        CHECK(res->status == 413);
        CHECK(res->body.find("--inventory-export-max-bytes") != std::string::npos);
        CHECK(res->body.find("narrow the filters, or use format=jsonl or csv") != std::string::npos);
        CHECK(x.files_in_dir() == 0);
        CHECK(x.h.held() == 0);
        CHECK(x.h.count("xlsx", "limit") == 1);
        REQUIRE(x.h.audit_log.size() == 1);
        CHECK(x.h.audit_log[0].detail.find("outcome=limit_bytes") != std::string::npos);
    }
    SECTION("escape-heavy text: ampersands cost five bytes each") {
        for (int i = 0; i < 30; ++i) { // 30 x 20,000 = 600,000 bytes of text, under 1 MiB
            auto r = install_row(agent_id("a", i), i + 1);
            r.entry.publisher = std::string(20'000, '&');
            x.h.installs.push_back(std::move(r));
        }
        auto res = x.h.get("?format=xlsx");
        REQUIRE(res);
        CHECK(res->status == 413);
        CHECK(res->body.find("--inventory-export-max-bytes") != std::string::npos);
        CHECK(x.files_in_dir() == 0);
        CHECK(x.h.count("xlsx", "limit") == 1);
        // The same rows stream as JSONL: that format counts body bytes, and 600 KB is under it.
        auto jsonl = x.h.get("?format=jsonl");
        REQUIRE(jsonl);
        CHECK(drive(*jsonl).done);
    }
}

TEST_CASE("export route xlsx: a degraded read, the deadline and a closing server during the build "
          "each answer their status with nothing left behind",
          "[software_export][routes][xlsx][build]") {
    XlsxHarness x(1);
    x.h.generated = 3'000;

    SECTION("a degraded read: 503 with a retry hint") {
        x.h.fail_read_at = 2;
        auto res = x.h.get("?format=xlsx");
        REQUIRE(res);
        CHECK(res->status == 503);
        CHECK(res->get_header_value("Retry-After") == "5");
        CHECK(res->body.find("\"retry_after_ms\":5000") != std::string::npos);
        CHECK(x.h.count("xlsx", "degraded") == 1);
        CHECK(x.h.audit_log.back().detail.find("outcome=degraded") != std::string::npos);
    }
    SECTION("a degraded last-poll read is the same") {
        x.h.fail_last_seen_at = 2;
        auto res = x.h.get("?format=xlsx");
        REQUIRE(res);
        CHECK(res->status == 503);
        CHECK(x.h.count("xlsx", "degraded") == 1);
    }
    SECTION("the deadline: 503 with the remediation and no retry hint") {
        x.h.on_install_read = [&x](int n) {
            if (n == 2)
                x.h.clock_s += swe::kExportMaxSeconds + 1;
        };
        auto res = x.h.get("?format=xlsx");
        REQUIRE(res);
        CHECK(res->status == 503);
        CHECK(res->get_header_value("Retry-After").empty());
        CHECK(res->body.find("narrow the filters, or use format=jsonl or csv") != std::string::npos);
        CHECK(x.h.count("xlsx", "deadline") == 1);
        CHECK(x.h.audit_log.back().detail.find("outcome=deadline") != std::string::npos);
    }
    SECTION("the server closing: 503 with a retry hint, counted as aborted") {
        x.h.on_install_read = [&x](int n) {
            if (n == 2)
                x.h.budget.begin_closing();
        };
        auto res = x.h.get("?format=xlsx");
        REQUIRE(res);
        CHECK(res->status == 503);
        CHECK(res->get_header_value("Retry-After") == "5");
        CHECK(x.h.count("xlsx", "aborted") == 1);
        CHECK(x.h.audit_log.back().detail.find("outcome=closing") != std::string::npos);
    }
    CHECK_FALSE(x.h.get("?format=xlsx&purl=nope")->content_provider_); // a 400 holds nothing either
    CHECK(x.files_in_dir() == 0); // no file left behind, whichever way the build ended
    CHECK(x.h.held() == 0);       // and the lease came back
    CHECK(x.h.audit_log.front().result == "failure");
}

TEST_CASE("export route xlsx: the deadline and a closing server during delivery end the transfer "
          "and free everything",
          "[software_export][routes][xlsx][delivery]") {
    XlsxHarness x(1);
    x.h.installs = {install_row("a-1", 1), install_row("a-2", 2)};
    x.h.disk_free = kRoomForOne; // room for exactly one export: the grant must come back too

    auto first_slice = [](httplib::Response& res, ManualSink& out) {
        REQUIRE(res.content_provider_);
        // httplib hands the provider what is left; it writes at most a slice, here a short one.
        CHECK(res.content_provider_(0, 10, out.sink));
        CHECK(out.body.size() == 10);
    };

    SECTION("the deadline passes after the workbook exists") {
        auto res = x.h.get("?format=xlsx");
        REQUIRE(res);
        REQUIRE(res->status == 200);
        ManualSink out;
        first_slice(*res, out);
        x.h.clock_s += swe::kExportMaxSeconds + 1;
        CHECK_FALSE(res->content_provider_(10, res->content_length_ - 10, out.sink));
        CHECK(out.body.size() == 10); // nothing more was written
        CHECK(x.h.held() == 1);
        release(*res, false);
        CHECK(x.h.held() == 0);
        CHECK(x.files_in_dir() == 0);
        CHECK(x.h.count("xlsx", "deadline") == 1);
        CHECK(x.h.count("xlsx", "completed") == 0);
        auto again = x.h.get("?format=xlsx"); // room for one: only if the grant was returned
        REQUIRE(again);
        CHECK(again->status == 200);
    }
    SECTION("the server closes during delivery: counted as aborted the same way") {
        auto res = x.h.get("?format=xlsx");
        REQUIRE(res);
        ManualSink out;
        first_slice(*res, out);
        x.h.budget.begin_closing();
        CHECK_FALSE(res->content_provider_(10, res->content_length_ - 10, out.sink));
        release(*res, false);
        CHECK(x.h.held() == 0);
        CHECK(x.files_in_dir() == 0);
        CHECK(x.h.count("xlsx", "aborted") == 1);
        // begin_closing() is one-way, so a new export is refused as closing whether or not the
        // grant came back. The grant comes first, so a leaked one would answer the disk 503
        // (no Retry-After) instead.
        auto next = x.h.get("?format=xlsx");
        REQUIRE(next);
        CHECK(next->status == 503);
        CHECK(next->get_header_value("Retry-After") == "5");
        CHECK(next->body.find("not enough free disk space") == std::string::npos);
        CHECK(x.h.audit_log.back().detail.find("outcome=closing") != std::string::npos);
    }
    SECTION("a client that goes away is aborted, and the grant goes back") {
        {
            auto res = x.h.get("?format=xlsx");
            REQUIRE(res);
            REQUIRE(res->status == 200);
            // Not driven at all: the response is destroyed, and ~Response runs the releaser.
        }
        CHECK(x.h.count("xlsx", "aborted") == 1);
        CHECK(x.files_in_dir() == 0);
        auto again = x.h.get("?format=xlsx"); // room for one: only if the grant was returned
        REQUIRE(again);
        CHECK(again->status == 200);
    }
}

TEST_CASE("export route xlsx: the disk guard refuses before a file exists and while building",
          "[software_export][routes][xlsx][disk]") {
    XlsxHarness x;

    SECTION("free space under the reserve: 503 before any read or file") {
        x.h.installs = {install_row("a-1", 1)};
        x.h.disk_free = kReserve - 1;
        auto res = x.h.get("?format=xlsx");
        REQUIRE(res);
        CHECK(res->status == 503);
        CHECK_FALSE(res->content_provider_);
        CHECK(res->body.find("not enough free disk space on the server for an xlsx export") !=
              std::string::npos);
        CHECK(res->body.find("use format=jsonl or csv, or ask the administrator to free space on "
                             "the data volume") != std::string::npos);
        CHECK(res->get_header_value("Retry-After").empty()); // no retry hint
        CHECK(x.h.install_reads == 0);
        CHECK(x.files_in_dir() == 0);
        CHECK(x.h.count("xlsx", "degraded") == 1);
        CHECK(x.h.audit_log.back().detail.find("outcome=disk") != std::string::npos);
        CHECK(x.h.held() == 0);
    }
    SECTION("an unreadable free-space figure refuses") {
        x.h.disk_free = std::nullopt;
        auto res = x.h.get("?format=xlsx");
        REQUIRE(res);
        CHECK(res->status == 503);
        CHECK(x.h.install_reads == 0);
        CHECK(x.h.count("xlsx", "degraded") == 1);
    }
    SECTION("a throwing free-space reader refuses the same way") {
        x.h.disk_free_at = [](int) -> std::optional<std::uintmax_t> {
            throw std::runtime_error("statvfs failed");
        };
        auto res = x.h.get("?format=xlsx");
        REQUIRE(res);
        CHECK(res->status == 503);
        CHECK(x.h.install_reads == 0);
    }
    SECTION("free space that runs out mid-build: 503, the file removed, the grant returned") {
        fat_rows(x.h, 600); // ~19 MiB of accounted sheet: past the first 16 MiB grant
        x.h.disk_free_at = [](int call) -> std::optional<std::uintmax_t> {
            return call == 1 ? std::optional<std::uintmax_t>(kRoomForOne)
                             : std::optional<std::uintmax_t>(kReserve); // nothing left for a second grant
        };
        auto res = x.h.get("?format=xlsx");
        REQUIRE(res);
        CHECK(res->status == 503);
        CHECK_FALSE(res->content_provider_);
        CHECK(res->body.find("not enough free disk space") != std::string::npos);
        CHECK(x.h.disk_free_calls == 2); // the first grant, then the refused second
        CHECK(x.files_in_dir() == 0);
        CHECK(x.h.held() == 0);
        CHECK(x.h.count("xlsx", "degraded") == 1);
        CHECK(x.h.audit_log.back().detail.find("outcome=disk") != std::string::npos);
        // The grant went back: with room for one export, the next small export is admitted.
        x.h.disk_free_at = nullptr;
        x.h.disk_free = kRoomForOne;
        x.h.installs.clear();
        x.h.installs = {install_row("a-1", 1)};
        auto next = x.h.get("?format=xlsx");
        REQUIRE(next);
        CHECK(next->status == 200);
    }
    SECTION("a second grant, when there is room, lets the export finish") {
        fat_rows(x.h, 600);
        x.h.disk_free = std::uintmax_t{1} << 40;
        auto res = x.h.get("?format=xlsx");
        REQUIRE(res);
        CHECK(res->status == 200);
        CHECK(x.h.disk_free_calls >= 2); // the sheet passed one grant and asked for the next
        const auto t = drive_sized(*res);
        CHECK_FALSE(t.aborted);
        const auto xml = sheet_xml(x.root.path / "readback", t.body);
        REQUIRE(xml.has_value());
        CHECK(occurrences(*xml, "<row ") == 601);
    }
}

TEST_CASE("export route xlsx: concurrent exports share one disk budget",
          "[software_export][routes][xlsx][disk]") {
    XlsxHarness x(/*concurrency=*/2);
    x.h.installs = {install_row("a-1", 1)};
    x.h.disk_free = kRoomForOne; // covers A's grant and nothing more

    auto a = x.h.get("?format=xlsx");
    REQUIRE(a);
    REQUIRE(a->status == 200); // built, its response not yet released: A holds its grant

    auto b = x.h.get("?format=xlsx");
    REQUIRE(b);
    CHECK(b->status == 503); // the same free space is not counted twice
    CHECK_FALSE(b->content_provider_);
    CHECK(b->body.find("not enough free disk space") != std::string::npos);
    CHECK(x.files_in_dir() == 1); // only A's workbook

    release(*a, true);
    CHECK(x.files_in_dir() == 0);
    auto c = x.h.get("?format=xlsx"); // served once A is released
    REQUIRE(c);
    CHECK(c->status == 200);
}

TEST_CASE("export route xlsx: the lease is held until release and a full budget refuses first",
          "[software_export][routes][xlsx][budget]") {
    XlsxHarness x(/*concurrency=*/1);
    x.h.installs = {install_row("a-1", 1)};

    auto first = x.h.get("?format=xlsx");
    REQUIRE(first);
    REQUIRE(first->status == 200);
    CHECK(x.h.held() == 1);
    const auto reads = x.h.install_reads;

    auto second = x.h.get("?format=xlsx");
    REQUIRE(second);
    CHECK(second->status == 503);
    CHECK(second->get_header_value("Retry-After") == "5");
    CHECK(x.h.rejected("export_concurrency_cap") == 1);
    CHECK(x.h.install_reads == reads); // refused before any build
    CHECK(x.files_in_dir() == 1);      // and before any file was created: only the first export's
    CHECK(x.h.audit_log.back().result == "denied");

    release(*first, true);
    CHECK(x.h.held() == 0);
    auto third = x.h.get("?format=xlsx");
    REQUIRE(third);
    CHECK(third->status == 200);
}

TEST_CASE("export route xlsx: a confined caller's workbook holds only in-scope rows",
          "[software_export][routes][xlsx][scope]") {
    XlsxHarness x;
    for (int d = 0; d < 10; ++d)
        for (int k = 0; k < 2; ++k)
            x.h.installs.push_back(install_row(agent_id("a", d, 2), d * 2 + k + 1, "pub-" + agent_id("a", d, 2)));
    x.h.scope = scope_of({agent_id("a", 3, 2), agent_id("a", 7, 2)});

    auto res = x.h.get("?format=xlsx");
    REQUIRE(res);
    REQUIRE(res->status == 200);
    const auto t = drive_sized(*res);
    const auto xml = sheet_xml(x.root.path / "readback", t.body);
    REQUIRE(xml.has_value());
    CHECK(occurrences(*xml, "<row ") == 5); // the header and four in-scope rows
    CHECK(xml->find(">a-03<") != std::string::npos);
    CHECK(xml->find(">a-07<") != std::string::npos);
    for (const int d : {0, 1, 2, 4, 5, 6, 8, 9}) {
        CHECK(xml->find(agent_id("a", d, 2)) == std::string::npos);
        CHECK(xml->find("pub-" + agent_id("a", d, 2)) == std::string::npos);
    }
}

TEST_CASE("export route xlsx: an unusable temporary directory answers 503 for xlsx only, and the "
          "directory is prepared at registration",
          "[software_export][routes][xlsx][dir]") {
    SECTION("a regular file where the directory should be") {
        XlsxHarness x(2, {}, [](const fs::path& root) {
            fs::create_directories(root);
            std::ofstream(root / "not-a-dir") << "x";
            return root / "not-a-dir";
        });
        x.h.installs = {install_row("a-1", 1)};
        auto res = x.h.get("?format=xlsx");
        REQUIRE(res);
        CHECK(res->status == 503);
        CHECK(res->body.find("xlsx export is not configured on this server") != std::string::npos);
        CHECK(x.h.count("xlsx", "degraded") == 1);
        CHECK(x.h.held() == 0);
        // The other two formats are unaffected.
        for (const char* format : {"jsonl", "csv"}) {
            auto other = x.h.get(std::string("?format=") + format);
            REQUIRE(other);
            CHECK(other->status == 200);
            CHECK(drive(*other).done);
            release(*other, true);
        }
    }
    SECTION("a link to a real directory: xlsx is off and nothing behind the link is swept") {
        fs::path keep;
        XlsxHarness x(2, {}, [&keep](const fs::path& root) {
            fs::create_directories(root / "real");
            keep = root / "real" / "keep.bin";
            std::ofstream(keep) << "keep";
            fs::create_directory_symlink(root / "real", root / "link");
            return root / "link";
        });
        auto res = x.h.get("?format=xlsx");
        REQUIRE(res);
        CHECK(res->status == 503);
        CHECK(fs::exists(keep)); // symlink_status refused the path, so no sweep ran
    }
    SECTION("no directory configured") {
        Harness h; // Deps::xlsx_tmp_dir left empty
        h.installs = {install_row("a-1", 1)};
        auto res = h.get("?format=xlsx");
        REQUIRE(res);
        CHECK(res->status == 503);
        CHECK(res->body.find("xlsx export is not configured on this server") != std::string::npos);
    }
    SECTION("leftover files are removed at registration and the directory is owner-only") {
        fs::path dir;
        XlsxHarness x(2, {}, [&dir](const fs::path& root) {
            dir = root / "export-tmp";
            fs::create_directories(dir);
            std::ofstream(dir / "yuzu_export_old.xlsx") << "crashed";
            std::ofstream(dir / "tmp.AbCdEfGhIj") << "library file";
            fs::create_directory(dir / "subdir"); // not a regular file: left alone
            return dir;
        });
        CHECK_FALSE(fs::exists(dir / "yuzu_export_old.xlsx"));
        CHECK_FALSE(fs::exists(dir / "tmp.AbCdEfGhIj"));
        CHECK(fs::is_directory(dir / "subdir"));
        struct stat st{};
        REQUIRE(::stat(dir.c_str(), &st) == 0);
        CHECK((st.st_mode & 0777) == 0700);
        x.h.installs = {install_row("a-1", 1)};
        auto res = x.h.get("?format=xlsx");
        REQUIRE(res);
        CHECK(res->status == 200); // a directory with a stray subdirectory still works
    }
    SECTION("a missing directory is created, owner-only, with its parents") {
        XlsxHarness x(2, {}, [](const fs::path& root) { return root / "a" / "b" / "export-tmp"; });
        CHECK(fs::is_directory(x.dir));
        struct stat st{};
        REQUIRE(::stat(x.dir.c_str(), &st) == 0);
        CHECK((st.st_mode & 0777) == 0700);
    }
}

TEST_CASE("export route xlsx: a created file name cannot be steered by the caller and a taken "
          "name is never overwritten",
          "[software_export][routes][xlsx][dir]") {
    // The name is built from the server's own correlation id; no query value reaches a path.
    XlsxHarness x;
    x.h.installs = {install_row("../../etc/passwd", 1)};
    auto res = x.h.get("?format=xlsx&name=../../escape&q=../x");
    REQUIRE(res);
    REQUIRE(res->status == 200);
    std::error_code ec;
    for (const auto& e : fs::directory_iterator(x.dir, ec)) {
        const auto name = e.path().filename().string();
        CHECK(name.starts_with("yuzu_export_"));
        CHECK(name.ends_with(".xlsx"));
        CHECK(name.find("..") == std::string::npos);
        CHECK(name.find('/') == std::string::npos);
    }
    CHECK_FALSE(fs::exists(x.root.path / "escape"));
}

// ── XLSX: review round 1 ────────────────────────────────────────────────────────────────────────

namespace {

// The first local zip header's version-needed-to-extract (bytes 4-5): 20 for an ordinary zip, 45
// for a ZIP64 container.
unsigned version_needed(const std::string& body) {
    REQUIRE(body.size() >= 6);
    return static_cast<unsigned>(static_cast<unsigned char>(body[4])) |
           (static_cast<unsigned>(static_cast<unsigned char>(body[5])) << 8);
}

// RFC 4180 records of `text` (quoted cells, doubled quotes, newlines inside quotes).
std::vector<std::vector<std::string>> csv_records(const std::string& text) {
    std::vector<std::vector<std::string>> out;
    std::vector<std::string> rec;
    std::string cell;
    bool quoted = false;
    bool open = false; // a record has started
    for (std::size_t i = 0; i < text.size(); ++i) {
        const char c = text[i];
        if (quoted) {
            if (c != '"')
                cell += c;
            else if (i + 1 < text.size() && text[i + 1] == '"') {
                cell += '"';
                ++i;
            } else
                quoted = false;
        } else if (c == '"') {
            quoted = true;
            open = true;
        } else if (c == ',') {
            rec.push_back(std::move(cell));
            cell.clear();
            open = true;
        } else if (c == '\n') {
            rec.push_back(std::move(cell));
            cell.clear();
            out.push_back(std::move(rec));
            rec.clear();
            open = false;
        } else {
            cell += c;
            open = true;
        }
    }
    if (open) {
        rec.push_back(std::move(cell));
        out.push_back(std::move(rec));
    }
    return out;
}

std::string xml_unescape(std::string in) {
    for (const auto& [from, to] : {std::pair<std::string_view, char>{"&lt;", '<'},
                                   {"&gt;", '>'},
                                   {"&quot;", '"'},
                                   {"&amp;", '&'}}) { // &amp; last: it must not create new escapes
        for (auto at = in.find(from); at != std::string::npos; at = in.find(from, at + 1))
            in.replace(at, from.size(), 1, to);
    }
    return in;
}

// The sheet's cells keyed by row number, each row `columns` wide and placed by the cell's own
// r="REF" column: the library writes no cell for empty text, so position says nothing.
std::map<int, std::vector<std::string>> sheet_cells(const std::string& xml, std::size_t columns) {
    constexpr std::string_view kOpen = "<c r=\"";
    std::map<int, std::vector<std::string>> rows;
    for (auto at = xml.find(kOpen); at != std::string::npos; at = xml.find(kOpen, at + 1)) {
        const auto ref_end = xml.find('"', at + kOpen.size());
        const std::string ref = xml.substr(at + kOpen.size(), ref_end - (at + kOpen.size()));
        std::size_t i = 0;
        std::size_t col = 0;
        while (i < ref.size() && std::isupper(static_cast<unsigned char>(ref[i])))
            col = col * 26 + static_cast<std::size_t>(ref[i++] - 'A' + 1);
        const int row = std::stoi(ref.substr(i));
        const auto t_open = xml.find("<t", ref_end);
        const auto t_gt = xml.find('>', t_open);
        const auto t_close = xml.find("</t>", t_gt);
        auto& r = rows[row];
        if (r.empty())
            r.resize(columns);
        REQUIRE((col >= 1 && col <= columns));
        r[col - 1] = xml_unescape(xml.substr(t_gt + 1, t_close - t_gt - 1));
    }
    return rows;
}

} // namespace

TEST_CASE("export route xlsx: ZIP64 is chosen exactly at the 0xFFFFFFFF sentinel, one byte under "
          "4 GiB",
          "[software_export][routes][xlsx][zip64]") {
    const auto param =
        GENERATE(std::pair<std::int64_t, unsigned>{swe::kXlsxZip64Threshold, 45U},
                 std::pair<std::int64_t, unsigned>{swe::kXlsxZip64Threshold - 1, 20U});
    const unsigned expected = param.second;
    swe::Limits limits;
    limits.max_bytes = param.first;
    XlsxHarness x(2, limits);
    x.h.installs = {install_row("a-1", 1), install_row("a-2", 2)};
    auto res = x.h.get("?format=xlsx");
    REQUIRE(res);
    REQUIRE(res->status == 200);
    const auto t = drive_sized(*res);
    CHECK_FALSE(t.aborted);
    CHECK(version_needed(t.body) == expected);
    const auto xml = sheet_xml(x.root.path / "readback", t.body);
    REQUIRE(xml.has_value()); // either container opens as a workbook
    CHECK(occurrences(*xml, "<row ") == 3);
    release(*res, true);
}

TEST_CASE("export route xlsx: the sheet carries the CSV's cells, in the CSV's order across pages",
          "[software_export][routes][xlsx][parity]") {
    XlsxHarness x;
    x.h.generated = 2'500; // three store pages
    constexpr auto kCols = swl::kListCsvColumns;

    auto csv = x.h.get("?format=csv");
    REQUIRE(csv);
    REQUIRE(csv->status == 200);
    const auto csv_body = drive(*csv).body;
    release(*csv, true);
    const auto records = csv_records(csv_body);
    REQUIRE(records.size() == 2'501); // header + rows
    for (const auto& r : records)
        REQUIRE(r.size() == kCols);

    auto xl = x.h.get("?format=xlsx");
    REQUIRE(xl);
    REQUIRE(xl->status == 200);
    const auto t = drive_sized(*xl);
    CHECK_FALSE(t.aborted);
    release(*xl, true);
    const auto xml = sheet_xml(x.root.path / "readback", t.body);
    REQUIRE(xml.has_value());
    const auto cells = sheet_cells(*xml, kCols);
    REQUIRE(cells.size() == records.size());

    // The two formats agree cell for cell. These rows have no leading = + - @ (CSV adds an
    // apostrophe there) and no cell over 32,767 bytes (XLSX cuts them): both are tested elsewhere.
    for (std::size_t i = 0; i < records.size(); ++i) {
        const auto& row = cells.at(static_cast<int>(i) + 1);
        for (std::size_t c = 0; c < kCols; ++c)
            REQUIRE(row[c] == records[i][c]);
    }

    // And the cells are the ones the fake store holds, written down here independently of the
    // projection, including the rows either side of both page boundaries.
    const auto col = [&](std::string_view name) {
        const auto& head = records[0];
        const auto it = std::ranges::find(head, std::string(name));
        REQUIRE(it != head.end());
        return static_cast<std::size_t>(it - head.begin());
    };
    for (const int i : {0, 999, 1000, 1999, 2000, 2499}) {
        const auto& row = cells.at(i + 2); // row 1 is the header
        CHECK(row[col("agent_id")] == agent_id("a", i));
        CHECK(row[col("name")] == "pkg");
        CHECK(row[col("version")] == "1." + std::to_string(i + 1));
        CHECK(row[col("publisher")] == "Acme");
        CHECK(row[col("kind")] == "package");
    }
}

TEST_CASE("export route xlsx: the same filters reach the store as for csv",
          "[software_export][routes][xlsx][parity]") {
    XlsxHarness x;
    x.h.generated = 5;
    const std::string filters =
        "&name=pkg&match=prefix&status=current&q=pk&kind=package&ecosystem=pypi&source=registry";

    auto csv = x.h.get("?format=csv" + filters);
    REQUIRE(csv);
    REQUIRE(csv->status == 200);
    (void)drive(*csv);
    release(*csv, true);
    const auto want = x.h.last_query;

    auto xl = x.h.get("?format=xlsx" + filters);
    REQUIRE(xl);
    REQUIRE(xl->status == 200);
    const auto got = x.h.last_query;
    release(*xl, true);

    // The request really carried the filters (the fake store ignores them, so this is the only
    // place they can be seen) ...
    CHECK(want.name == "pkg");
    CHECK(want.match == NameMatch::kPrefix);
    CHECK(want.status == "current");
    CHECK(want.q == "pk");
    CHECK(want.kind == "package");
    CHECK(want.ecosystem == "pypi");
    CHECK(want.source == "registry");
    // ... and xlsx hands the store the same ones.
    CHECK(got.name == want.name);
    CHECK(got.match == want.match);
    CHECK(got.status == want.status);
    CHECK(got.q == want.q);
    CHECK(got.kind == want.kind);
    CHECK(got.ecosystem == want.ecosystem);
    CHECK(got.source == want.source);
    CHECK(got.purl == want.purl);
    CHECK(got.version == want.version);
    CHECK(got.versions == want.versions);
    CHECK(got.agent_id == want.agent_id);
    CHECK(got.agent_ids == want.agent_ids);
}

TEST_CASE("export route xlsx: a Range request is answered with the whole workbook, not a slice",
          "[software_export][routes][xlsx][range]") {
    // httplib answers 206 and calls the provider at the range's offset when a handler leaves the
    // status unset (-1); the workbook is built per request and has no validator, so a ranged read
    // could stitch two builds into one corrupt file and the releaser would count a slice as a
    // completed export. The handler is called with a fresh Response (status -1) because
    // TestRouteSink pre-sets 200, which would pass without the fix.
    XlsxHarness x;
    x.h.installs = {install_row("a-1", 1), install_row("a-2", 2)};
    REQUIRE(x.h.export_handler);

    httplib::Request req;
    req.method = "GET";
    req.path = "/api/v1/inventory/software/export";
    httplib::detail::parse_query_text("format=xlsx", req.params);
    req.set_header("Range", "bytes=0-9");
    httplib::Response res;
    REQUIRE(res.status == -1);
    x.h.export_handler(req, res);

    CHECK(res.status == 200); // explicit, so httplib sends the whole body
    CHECK(res.content_length_ > 10);
    CHECK_FALSE(res.has_header("Content-Range"));
    const auto t = drive_sized(res);
    CHECK_FALSE(t.aborted);
    CHECK(t.body.size() == res.content_length_);
    CHECK(sheet_xml(x.root.path / "readback", t.body).has_value());
    release(res, true);
    CHECK(x.h.count("xlsx", "completed") == 1);
    CHECK(x.h.count("xlsx", "aborted") == 0);
    CHECK(x.files_in_dir() == 0);
}

TEST_CASE("export route xlsx: a workbook file that went short before delivery aborts the transfer "
          "and frees everything",
          "[software_export][routes][xlsx][delivery]") {
    XlsxHarness x(1);
    x.h.installs = {install_row("a-1", 1), install_row("a-2", 2)};
    x.h.disk_free = kRoomForOne; // room for exactly one export: the grant must come back too

    auto res = x.h.get("?format=xlsx");
    REQUIRE(res);
    REQUIRE(res->status == 200);
    REQUIRE(x.files_in_dir() == 1);
    const auto file = fs::directory_iterator(x.dir)->path();
    fs::resize_file(file, res->content_length_ - 5);

    const auto t = drive_sized(*res);
    CHECK(t.aborted); // the provider refused rather than send a short or padded file
    CHECK(t.body.size() < res->content_length_);
    release(*res, false);
    CHECK(x.h.count("xlsx", "degraded") == 1);
    CHECK(x.h.count("xlsx", "completed") == 0);
    CHECK(x.files_in_dir() == 0);
    CHECK(x.h.held() == 0);
    auto again = x.h.get("?format=xlsx"); // room for one: only if the grant was returned
    REQUIRE(again);
    CHECK(again->status == 200);
}

TEST_CASE("export route xlsx: a workbook that cannot be closed is a writer 503 with nothing left",
          "[software_export][routes][xlsx][build]") {
    XlsxHarness x(1);
    x.h.installs = {install_row("a-1", 1), install_row("a-2", 2)};
    x.h.disk_free = kRoomForOne;
    // The library opens its output path only when the workbook is closed, so replacing the
    // pre-created file with a directory during the first read makes close() fail.
    x.h.on_install_read = [&x](int n) {
        if (n != 1)
            return;
        std::error_code ec;
        for (const auto& e : fs::directory_iterator(x.dir, ec)) {
            const auto path = e.path();
            fs::remove(path, ec);
            fs::create_directory(path, ec);
            return;
        }
    };

    auto res = x.h.get("?format=xlsx");
    REQUIRE(res);
    CHECK(res->status == 503);
    CHECK_FALSE(res->content_provider_);
    CHECK(res->body.find("xlsx export failed on the server") != std::string::npos);
    CHECK(x.h.count("xlsx", "degraded") == 1);
    REQUIRE(x.h.audit_log.size() == 1);
    CHECK(x.h.audit_log[0].result == "failure");
    CHECK(x.h.audit_log[0].detail.find("outcome=writer") != std::string::npos);
    CHECK(x.files_in_dir() == 0); // the stand-in directory is removed with the file
    CHECK(x.h.held() == 0);
    x.h.on_install_read = nullptr;
    auto again = x.h.get("?format=xlsx"); // the grant went back
    REQUIRE(again);
    CHECK(again->status == 200);
}

TEST_CASE("export route xlsx: a volume that stops taking writes mid-build is a writer 503 with "
          "nothing left and no success row",
          "[software_export][routes][xlsx][build]") {
    XlsxHarness x(1);
    fat_rows(x.h, 40); // 40 x 32,767 compressible bytes: the row file dwarfs the finished workbook
    x.h.disk_free = kRoomForOne;

    // A clean request first, for the two sizes the limit goes between: the finished file's, and
    // the row file's (the sheet's <sheetData> content length).
    std::size_t finished = 0;
    std::size_t row_file = 0;
    {
        auto clean = x.h.get("?format=xlsx");
        REQUIRE(clean);
        REQUIRE(clean->status == 200);
        finished = clean->content_length_;
        const auto t = drive_sized(*clean);
        REQUIRE_FALSE(t.aborted);
        const auto xml = sheet_xml(x.root.path / "readback", t.body);
        REQUIRE(xml.has_value());
        row_file = xml->find("</sheetData>") - (xml->find("<sheetData>") + 11);
        release(*clean, true);
    }
    REQUIRE(finished < row_file);
    REQUIRE(x.files_in_dir() == 0);
    const std::size_t audit_rows = x.h.audit_log.size();
    const int reads_before = x.h.install_reads;
    const double completed_before = x.h.count("xlsx", "completed"); // the clean request's

    // The limit is set when the first page of the second request is read and lifted when the
    // response is back; nothing is asserted in between.
    std::optional<FsizeLimit> limit;
    x.h.on_install_read = [&](int n) {
        if (n == reads_before + 1)
            limit.emplace((finished + row_file) / 2);
    };
    auto res = x.h.get("?format=xlsx");
    const bool armed = limit && limit->armed();
    limit.reset();
    x.h.on_install_read = nullptr;
    REQUIRE(armed);

    REQUIRE(res);
    CHECK(res->status == 503);
    CHECK_FALSE(res->content_provider_); // no provider: not one byte of a short workbook is sent
    CHECK(res->body.find("xlsx export failed on the server") != std::string::npos);
    CHECK(x.h.count("xlsx", "degraded") == 1);
    CHECK(x.h.count("xlsx", "completed") == completed_before); // the failed request is no success
    REQUIRE(x.h.audit_log.size() == audit_rows + 1);
    CHECK(x.h.audit_log.back().result == "failure");
    CHECK(x.h.audit_log.back().detail.find("outcome=writer") != std::string::npos);
    const auto successes = std::ranges::count_if(
        x.h.audit_log, [](const AuditRecord& a) { return a.result == "success"; });
    CHECK(successes == 1); // the clean request's row; the failed one wrote none
    CHECK(x.files_in_dir() == 0);
    CHECK(x.h.held() == 0);
    auto again = x.h.get("?format=xlsx"); // room for one: only if the grant went back
    REQUIRE(again);
    CHECK(again->status == 200);
}
