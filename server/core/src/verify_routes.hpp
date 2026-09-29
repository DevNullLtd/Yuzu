#pragma once

/// @file verify_routes.hpp
/// The `/auto` VERIFY stage routes — the cohort-paired before/after app-perf
/// evidence (UAT non-functional). Three fragments on the /auto page:
///   * GET /fragments/auto/verify        — the config form (cohort + app + two
///     versions + window). Chrome; gates Infrastructure:Read like the page.
///   * GET /fragments/auto/verify/run     — the AGGREGATE result (summary +
///     shift cards + distribution). Reads DEX app-perf → GuaranteedState:Read.
///     OPERATIONAL audit `dex.app_perf.compare`, set-and-proceed (the aggregate
///     is unfloored + near-individual at canary scale, so the read is recorded —
///     the works-council accountability that replaces a floor; grilled 2026-06-30).
///   * GET /fragments/auto/verify/drill   — the per-machine pairs (the audited PII
///     surface, opened by a deliberate click). GuaranteedState:Read + audit.
///
/// Product UI: HTMX core attrs only (CSP blocks hx-on); every string escaped at
/// render (verify_ui.cpp). EVIDENTIAL ONLY — no verdict. NO cohort floor (real
/// canaries are 2-3 devices); a sub-floor paired set renders "indicative", never
/// suppressed. The numbers come from the ONE pure engine (build_comparison), so
/// this surface and the REST/MCP twins agree. The dashboard renders honest notes
/// at HTTP 200 on bad input / degrade (the dashboard htmx config drops 4xx/5xx
/// bodies — REST/MCP keep their fail-states; this is the HTML surface).

#include <yuzu/server/auth.hpp>

#include "verify_api.hpp"  // ADR-0031 WS-A4: the public in-process VERIFY API seam

#include <httplib.h>

#include <functional>
#include <memory>
#include <optional>
#include <string>
#include <utility>
#include <vector>

namespace yuzu::server {

class HttpRouteSink; // server/core/src/http_route_sink.hpp

class VerifyRoutes {
public:
    using AuthFn =
        std::function<std::optional<auth::Session>(const httplib::Request&, httplib::Response&)>;
    using PermFn = std::function<bool(const httplib::Request&, httplib::Response&,
                                      const std::string& securable_type, const std::string& operation)>;
    /// (id, name) of the management groups offered as the cohort dropdown.
    using GroupsFn = std::function<std::vector<std::pair<std::string, std::string>>()>;

    /// Audit hook — same shape as `DexRoutes::AuditFn`/`NetworkRoutes::AuditFn`
    /// (bool persist-signal), defined LOCALLY rather than borrowed from
    /// `dex_routes.hpp` (ADR-0031 WS-A4 #4250) — that header transitively
    /// reaches `app_perf_daily_store.hpp`/`app_perf_fleet_store.hpp` via
    /// `dex_app_perf_ui.hpp` -> `dex_app_perf_model.hpp`, which would defeat
    /// the whole point of this family's include-closure seam for the sake of
    /// one type alias. `detail::emit_behavioral_audit` (rest_audit.hpp) is
    /// templated on the callable shape, so any of the three call
    /// interchangeably.
    using AuditFn = std::function<bool(const httplib::Request&, const std::string& action,
                                       const std::string& result, const std::string& target_type,
                                       const std::string& target_id, const std::string& detail)>;

    /// The public in-process VERIFY API (ADR-0031 WS-A4) — the SAME seam
    /// GET /api/v1/dex/perf/compare and the MCP `compare_app_perf_versions`
    /// tool call, so this dashboard fragment can never disagree with those
    /// siblings. Nullable → the fragments render an honest "still warming
    /// up"/degrade note (the pre-seam behaviour of an unwired cohort_fn).
    using VerifyApiPtr = std::shared_ptr<const VerifyApi>;

    void register_routes(httplib::Server& svr, AuthFn auth_fn, PermFn perm_fn, GroupsFn groups_fn,
                         AuditFn audit_fn, VerifyApiPtr api = nullptr);

    /// HttpRouteSink overload — testable in-process via TestRouteSink (no httplib
    /// acceptor; the #438 TSan trap). The httplib::Server& overload wraps + delegates.
    void register_routes(HttpRouteSink& sink, AuthFn auth_fn, PermFn perm_fn, GroupsFn groups_fn,
                         AuditFn audit_fn, VerifyApiPtr api = nullptr);

private:
    AuthFn auth_fn_;
    PermFn perm_fn_;
    GroupsFn groups_fn_;
    AuditFn audit_fn_;
    VerifyApiPtr api_;
};

} // namespace yuzu::server
