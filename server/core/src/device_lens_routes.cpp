/// @file device_lens_routes.cpp
/// Route registration for the DEX + Guardian device-page lenses. Split
/// verbatim out of device_routes.cpp (ADR-0031 WS-A4 wave 2), then rewired
/// onto the `DexApi`/`GuardianApi` seams (issue #4576 + the deferred
/// guardian-lens rewire) — see device_lens_routes.hpp's file banner.

#include "device_lens_routes.hpp"

#include "http_route_sink.hpp"
#include "rest_audit.hpp" // detail::emit_behavioral_audit (Sec-Audit-Failed, #1647)

namespace yuzu::server {

void DeviceLensRoutes::register_routes(httplib::Server& svr, ScopedPermFn scoped_perm_fn,
                                       DexApiPtr dex_api, GuardianApiPtr guardian_api,
                                       AuditFn audit_fn) {
    HttplibRouteSink sink(svr);
    register_routes(sink, std::move(scoped_perm_fn), std::move(dex_api), std::move(guardian_api),
                    std::move(audit_fn));
}

void DeviceLensRoutes::register_routes(HttpRouteSink& sink, ScopedPermFn scoped_perm_fn,
                                       DexApiPtr dex_api, GuardianApiPtr guardian_api,
                                       AuditFn audit_fn) {
    scoped_perm_fn_ = std::move(scoped_perm_fn);
    dex_api_ = std::move(dex_api);
    guardian_api_ = std::move(guardian_api);
    audit_fn_ = std::move(audit_fn);

    // -- DEX lens: per-device score + signal summary (+ link to the full drill) --
    sink.Get("/fragments/device/dex", [this](const httplib::Request& req, httplib::Response& res) {
        const std::string id = req.has_param("id") ? req.get_param_value("id") : "";
        // bare=1: mounted as a lens inside the Hardware CI record, which already
        // renders its own 7-tab bar — suppress this fragment's own 3-chip bar.
        const bool tabs = !req.has_param("bare");
        // Per-device behavioral data (PII): GuaranteedState:Read SCOPED to this
        // device (tier + management group) + audit-on-open. Stronger than the
        // sibling /fragments/dex/device's bare Read gate — closes the cross-scope
        // read of another team's per-device DEX summary.
        if (!scoped_perm_fn_(req, res, "GuaranteedState", "Read", id)) return;
        if (!dex_api_) {
            res.set_content(render_device_lens_placeholder("dex", id, "DEX store unavailable.", tabs),
                            "text/html; charset=utf-8");
            return;
        }
        // Behavioural-PII access audit. HTML dashboard fragment → set-and-proceed:
        // a dropped evidence row flags via Sec-Audit-Failed but STILL renders, so
        // a transient audit hiccup never blanks the operator's lens (#1647). The
        // shared helper captures the persist bool behind a try/catch (the throw
        // arm is otherwise silent) — one pattern across every behavioural route.
        (void)detail::emit_behavioral_audit(audit_fn_, req, res, "dex.device.view", "success",
                                            "Agent", id,
                                            "device DEX lens (per-device signal summary)");
        // Fixed 7-day window — the lens's own pre-seam posture verbatim (never
        // the ?window= selector the full /dex drill exposes).
        const DexDeviceScoreModel m = dex_api_->device_score(id, "7d");
        // #4855: a degraded signal-summary read must render an honest "DEX
        // store degraded." placeholder AFTER the access audit above (parity
        // with the Guardian lens's device_guards()-degraded branch just
        // below) — never the pre-#4855 silent score-100/no-signals result.
        if (m.degraded) {
            res.set_content(render_device_lens_placeholder("dex", id, "DEX store degraded.", tabs),
                            "text/html; charset=utf-8");
            return;
        }
        std::vector<std::pair<std::string, std::int64_t>> sigs;
        for (const auto& s : m.signals)
            sigs.emplace_back(s.obs_type, s.count);
        res.set_content(render_device_dex_lens(id, m.score, sigs, tabs), "text/html; charset=utf-8");
    });

    // -- Guardian lens: per-guard compliance state for this device --
    sink.Get("/fragments/device/guardian", [this](const httplib::Request& req,
                                                  httplib::Response& res) {
        const std::string id = req.has_param("id") ? req.get_param_value("id") : "";
        // bare=1: mounted as a lens inside the Hardware CI record — see the dex
        // fragment above for the same suppression.
        const bool tabs = !req.has_param("bare");
        // Per-device compliance state: GuaranteedState:Read SCOPED to this device
        // (tier + management group) + audit-on-open (parity with the DEX lens above).
        if (!scoped_perm_fn_(req, res, "GuaranteedState", "Read", id)) return;
        if (!guardian_api_) {
            res.set_content(render_device_lens_placeholder("guardian", id, "Guardian store unavailable.",
                                                            tabs),
                            "text/html; charset=utf-8");
            return;
        }
        // Behavioural-PII access audit — set-and-proceed (HTML fragment), parity
        // with the DEX lens above and the shared #1647 helper.
        (void)detail::emit_behavioral_audit(audit_fn_, req, res, "guardian.device.view", "success",
                                            "Agent", id,
                                            "device Guardian lens (per-guard compliance)");
        // device_guards() is a single per-agent-scoped SQL read (ADR-0038
        // catastrophic-read set): a degraded read (std::nullopt) must render an
        // honest "Guardian store degraded." placeholder (distinct from the
        // unwired `!guardian_api_` "unavailable" one above), never a silent
        // empty/partial guard list (which would misreport
        // a device as having no guards, or drop live drift verdicts, for the
        // operator viewing this lens).
        auto guards_result = guardian_api_->device_guards(id);
        if (!guards_result) {
            res.set_content(render_device_lens_placeholder("guardian", id, "Guardian store degraded.",
                                                            tabs),
                            "text/html; charset=utf-8");
            return;
        }
        std::vector<DeviceGuardRow> guards;
        guards.reserve(guards_result->size());
        for (const auto& g : *guards_result) {
            DeviceGuardRow row;
            row.name = g.name; // already resolved + rule_id-fallback'd by the seam
            row.state = g.state;
            row.updated_at = g.updated_at;
            guards.push_back(std::move(row));
        }
        res.set_content(render_device_guardian_lens(id, guards, tabs), "text/html; charset=utf-8");
    });
}

} // namespace yuzu::server
