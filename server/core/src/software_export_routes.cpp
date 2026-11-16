/// @file software_export_routes.cpp
/// See software_export_routes.hpp.

#include "software_export_routes.hpp"

#include "model_param_helpers.hpp"
#include "principal_quota_gate.hpp"
#include "rest_a4_envelope_http.hpp"
#include "rest_audit.hpp"
#include "software_list_model.hpp"

#include <spdlog/spdlog.h>

#include <chrono>
#include <memory>
#include <string>
#include <string_view>
#include <utility>

namespace yuzu::server {

namespace swc = software_catalogue;
namespace swl = software_list;
namespace swe = software_export;

namespace {

constexpr const char* kVerb = "inventory.software.export";
constexpr const char* kTargetType = "Inventory";

// How a stream ended. The default is kAborted: the response's resource-releaser can run with
// nothing recorded when the client went away, the transport failed, or the server began shutting
// down mid-stream.
enum class Outcome { kAborted, kCompleted, kDegraded, kDeadline };

// Indexes swe::kResults.
[[nodiscard]] std::string_view outcome_label(Outcome o) noexcept {
    static_assert(swe::kResults.size() == 4);
    switch (o) {
    case Outcome::kCompleted: return swe::kResults[0];
    case Outcome::kDegraded: return swe::kResults[1];
    case Outcome::kDeadline: return swe::kResults[2];
    case Outcome::kAborted: break;
    }
    return swe::kResults[3];
}

struct Ctx {
    SoftwareExportRoutes::FleetReadFn fleet_read_fn;
    SoftwareExportRoutes::AuditFn audit_fn;
    SoftwareExportRoutes::RosterFn roster_fn;
    SoftwareExportRoutes::SecondsFn seconds_fn;
    SoftwareExportRoutes::Reads reads;
    yuzu::MetricsRegistry* metrics{nullptr};
    detail::StreamBudget* budget{nullptr}; ///< borrowed; the one held-open budget (ADR-0034)
    std::size_t concurrency{0};            ///< the export cap: the lease's per-key cap
    bool ready{false};

    [[nodiscard]] std::int64_t seconds() const {
        if (seconds_fn)
            return seconds_fn();
        return std::chrono::duration_cast<std::chrono::seconds>(
                   std::chrono::steady_clock::now().time_since_epoch())
            .count();
    }
};

// Everything one open stream carries. Owned by the provider and the releaser (both hold it), so it
// lives exactly as long as the response and the lease is freed with it at the latest.
struct Stream {
    std::shared_ptr<const Ctx> ctx;
    swe::ExportRequest request;
    authz::VisibleSet scope;
    detail::StreamBudget::Lease lease; ///< one worker of the one budget, held for the whole stream
    std::unordered_map<std::string, std::string> hostnames;
    std::int64_t deadline{0};
    bool first_chunk{true};
    Outcome outcome{Outcome::kAborted};
    std::string cid;
};

void fail(httplib::Response& res, int status, std::string_view message,
          detail::A4ErrorOpts opts = {}) {
    res.status = status;
    res.set_content(detail::a4_error(res, message, opts), "application/json");
}

void bind_store_reads(SoftwareExportRoutes::Reads& r, SoftwareInventoryStore* s) {
    if (!s)
        return;
    if (!r.installs)
        r.installs = swc::devices_reader(*s);
    if (!r.last_seen)
        r.last_seen = [s](const std::vector<std::string>& ids) {
            return s->source_last_seen_bulk("installed_software", ids);
        };
    if (!r.distinct_versions)
        r.distinct_versions = [s](const std::string& name,
                                  const std::optional<std::vector<std::string>>& ids) {
            return s->installed_software_distinct_versions(name, ids);
        };
}

[[nodiscard]] bool reads_complete(const SoftwareExportRoutes::Reads& r) {
    return r.installs && r.last_seen && r.distinct_versions;
}

bool audit(const Ctx& c, const httplib::Request& req, const char* result,
           const std::string& target, const std::string& detail_text) {
    return detail::try_persist_audit(c.audit_fn, req, kVerb, result, kTargetType, target,
                                     detail_text);
}

void count_result(const Ctx& c, swe::ExportFormat format, Outcome o) {
    if (c.metrics)
        c.metrics
            ->counter("yuzu_server_software_export_total",
                      {{"format", std::string(swe::format_name(format))},
                       {"result", std::string(outcome_label(o))}})
            .increment();
}

// The per-page device facts: last polls from one bulk read, hostnames from the roster read once at
// the start of the stream. A blank hostname reads as unknown, like the list route. nullopt = the
// last-poll read degraded.
std::optional<swl::DeviceFacts> facts_for(const Stream& st, const std::vector<SoftwareFleetRow>& rows) {
    swl::DeviceFacts f;
    const auto ids = swl::page_agent_ids(rows);
    if (ids.empty())
        return f;
    auto seen = st.ctx->reads.last_seen(ids);
    if (!seen)
        return std::nullopt;
    f.last_seen = std::move(*seen);
    for (const auto& id : ids)
        if (const auto it = st.hostnames.find(id); it != st.hostnames.end() && !it->second.empty())
            f.hostname.emplace(id, it->second);
    return f;
}

// One provider call: one store read, at most one chunk. Returning false aborts the transfer without
// its terminating chunk (the only failure signal available once headers are sent).
bool pump(Stream& st, httplib::DataSink& sink) {
    // Shutdown close-signal (StreamBudget::closing): a stream does not hold the server's stop for up
    // to the 900 s deadline. Counted as `aborted`, like a client that went away.
    if (st.ctx->budget->closing()) {
        spdlog::info("{}: server closing; aborting stream; cid={}", kVerb, st.cid);
        return false;
    }
    if (st.ctx->seconds() >= st.deadline) {
        st.outcome = Outcome::kDeadline;
        spdlog::warn("{}: stream deadline reached; aborting; cid={}", kVerb, st.cid);
        return false;
    }
    const auto page = swl::read_list_page(st.ctx->reads.installs, st.request.list, st.scope);
    if (!page) {
        st.outcome = Outcome::kDegraded;
        spdlog::warn("{}: installs read failed mid-stream; aborting; cid={}", kVerb, st.cid);
        return false;
    }
    const auto facts = facts_for(st, page->rows);
    if (!facts) {
        st.outcome = Outcome::kDegraded;
        spdlog::warn("{}: last-poll read failed mid-stream; aborting; cid={}", kVerb, st.cid);
        return false;
    }
    // A wide scope can answer an EMPTY page with a non-empty cursor: nothing to write, carry on.
    const auto chunk = swe::format_chunk(page->rows, *facts, st.request.format, st.first_chunk);
    st.first_chunk = false;
    if (!chunk.empty() && !sink.write(chunk.data(), chunk.size()))
        return false; // client gone: outcome stays kAborted
    if (page->next_cursor.empty()) { // the ONLY end of the data
        st.outcome = Outcome::kCompleted;
        sink.done();
        return true;
    }
    st.request.list.base.cursor = page->next_cursor;
    return true;
}

} // namespace

void SoftwareExportRoutes::register_routes(HttpRouteSink& sink, Deps deps) {
    bind_store_reads(deps.reads, deps.store);
    Ctx built{.fleet_read_fn = std::move(deps.fleet_read_fn),
              .audit_fn = std::move(deps.audit_fn),
              .roster_fn = std::move(deps.roster_fn),
              .seconds_fn = std::move(deps.seconds_fn),
              .reads = std::move(deps.reads),
              .metrics = deps.metrics,
              .budget = deps.stream_budget,
              .concurrency = swe::clamp_concurrency(deps.concurrency)};
    built.ready = reads_complete(built.reads);
    const auto ctx = std::make_shared<const Ctx>(std::move(built));

    // GET /api/v1/inventory/software/export
    sink.Get("/api/v1/inventory/software/export", [ctx](const httplib::Request& req,
                                                       httplib::Response& res) {
        const auto cid = detail::make_correlation_id();
        res.set_header("X-Correlation-Id", cid); // echo on every path (A3)

        if (!ctx->fleet_read_fn) {
            spdlog::error("{}: fleet_read_fn unwired - misconfigured call site; failing closed; "
                          "cid={}",
                          kVerb, cid);
            fail(res, 503, "service unavailable");
            return;
        }
        // The SOLE authorization gate: renders 401/403/503 itself and returns !admitted. It runs
        // first, so a denied caller reaches no read and an unwired store is not visible to an
        // unauthenticated one.
        const auto gate = ctx->fleet_read_fn(req, res, "Inventory", "Read");
        if (!gate.admitted)
            return;
        if (!ctx->ready) {
            fail(res, 503, "software inventory store not available");
            return;
        }
        // Fail closed, never an unmetered export (the posture of the unwired fleet_read_fn above).
        // After the gate, so an unauthenticated caller cannot see the wiring.
        if (!ctx->budget) {
            spdlog::error("{}: stream_budget unwired - misconfigured call site; failing closed; "
                          "cid={}",
                          kVerb, cid);
            fail(res, 503, "service unavailable");
            return;
        }
        auto parsed = swe::parse_export_params(model_detail::to_params(req.params));
        if (!parsed) {
            fail(res, 400, parsed.error());
            return;
        }
        auto rq = std::move(*parsed);
        const std::string target = swl::audit_target(rq.list);

        // THE admission step (ADR-0034): one lease from the one budget, under the surface-wide key,
        // with the export cap as its per-key cap. Held by this frame until the stream takes it, so
        // every refusal below (a 400, a degraded version read) releases it on the way out.
        auto admitted = ctx->budget->try_acquire(detail::SseSurface::kSoftwareExport,
                                                 std::string(detail::kSoftwareExportSurfaceKey),
                                                 ctx->concurrency);
        if (!admitted.lease) {
            const bool export_cap =
                admitted.reject_reason != nullptr &&
                std::string_view(admitted.reject_reason) ==
                    detail::StreamBudget::kRejectPerPrincipal;
            const auto reason = export_cap ? swe::kRejectReasons[0] : swe::kRejectReasons[1];
            if (ctx->metrics)
                ctx->metrics
                    ->counter("yuzu_server_software_export_rejected_total",
                              {{"reason", std::string(reason)}})
                    .increment();
            (void)audit(*ctx, req, "denied", target,
                        std::string(export_cap ? "export concurrency limit reached"
                                               : "server held-open stream budget full") +
                            "; reason=" + std::string(reason) + "; cid=" + cid);
            res.set_header("Retry-After", "5");
            fail(res, 503,
                 export_cap ? "too many concurrent software exports"
                            : "the server is running as many held-open requests as it is sized for",
                 {.retry_after_ms = swe::kRetryAfterMs,
                  .remediation = export_cap ? "retry when a running export has finished"
                                            : "retry shortly"});
            return;
        }

        if (rq.list.has_range()) {
            // Resolved once, against the caller's own scope, and held fixed for the whole stream.
            const auto distinct = ctx->reads.distinct_versions(
                rq.list.base.query.name, swl::scope_ids(gate.scope));
            if (!distinct) {
                (void)audit(*ctx, req, "failure", target,
                            "version read degraded; cid=" + cid);
                fail(res, 503, "software inventory store degraded - version range read failed",
                     {.retry_after_ms = 5000, .remediation = "retry the request"});
                return;
            }
            auto set = swl::resolve_version_range(*distinct, *rq.list.range);
            if (!set) {
                fail(res, 400, set.error());
                return;
            }
            rq.list.base.query.versions = std::move(*set);
        }

        // Audit BEFORE the provider: set_chunked_content_provider seals the headers. Set-and-proceed
        // on a miss (`Sec-Audit-Failed`, the file is still served): machine-scope inventory data,
        // the posture of the buffered export.
        const bool audit_ok = audit(*ctx, req, "success", target,
                                    "installs format=" + std::string(swe::format_name(rq.format)) +
                                        " stream=true filters=" + swl::list_fingerprint(rq.list) +
                                        " cid=" + cid);
        if (!audit_ok)
            res.set_header("Sec-Audit-Failed", "true");

        auto st = std::make_shared<Stream>();
        st->ctx = ctx;
        st->scope = gate.scope;
        st->deadline = ctx->seconds() + swe::kExportMaxSeconds;
        st->cid = cid;
        // Display-only: a roster that is unwired or cannot be read leaves the hostnames null.
        if (ctx->roster_fn)
            if (auto roster = ctx->roster_fn())
                for (auto& e : roster->rows)
                    st->hostnames.emplace(std::move(e.agent_id), std::move(e.hostname));

        res.set_header("Content-Disposition",
                       "attachment; filename=\"" + std::string(swe::file_name(rq.format)) + "\"");
        res.set_header("X-Content-Type-Options", "nosniff");
        const std::string content_type(swe::content_type(rq.format));
        st->request = std::move(rq);
        st->lease = std::move(admitted.lease);
        res.set_chunked_content_provider(
            content_type,
            [st](size_t, httplib::DataSink& out) {
                try {
                    return pump(*st, out);
                } catch (...) {
                    st->outcome = Outcome::kDegraded;
                    spdlog::error("{}: unexpected exception mid-stream; aborting; cid={}", kVerb,
                                  st->cid);
                    return false;
                }
            },
            // Runs on every teardown path (clean end, abort, dropped client, deadline, shutdown),
            // from ~Response, where an escaping exception is std::terminate. The lease goes back
            // FIRST: it is the one step that must not be skipped (release is noexcept), and the
            // counter below can throw. The same releaser then frees an adopted engine quota slot
            // (UP-1) after this body, so the principal's concurrency reservation lasts as long as
            // the stream, not as long as the request.
            detail::adopt_quota_slot_into_stream([st](bool) noexcept {
                st->lease.release();
                try {
                    count_result(*st->ctx, st->request.format, st->outcome);
                } catch (...) { // NOLINT(bugprone-empty-catch) - a lost sample beats an abort
                }
            }));
    });
}

} // namespace yuzu::server
