#pragma once

/// @file home_render.hpp
/// Home (`/home`) value types and PURE renderers. Nothing here reads a store, a
/// clock or a request: the route resolves every figure into these values and the
/// renderers turn them into HTML. Every dynamic string goes through `html_escape`.
///
/// Honesty contract (P17): each figure is a `Fact<T>` whose state is one of Ok /
/// Denied / Limited / Unavailable / Unwired. A figure that could not be read is
/// never rendered as 0 and never as an empty value; each non-Ok state has its own
/// sentence. The "Nothing needs attention" row appears only when every figure that
/// feeds the list is Ok (or is absent by a documented omission).

#include <cstdint>
#include <optional>
#include <string>
#include <utility>
#include <vector>

namespace yuzu::server::home {

enum class FactState {
    Ok,          ///< typed read succeeded
    Denied,      ///< the gate refused; `need` names `Securable:Op`
    Limited,     ///< admitted with an engaged scope on a fleet-wide aggregate
    Unavailable, ///< typed read degraded, or the store failed
    Unwired,     ///< no provider is bound on this server (rendered as unavailable)
};

template <class T> struct Fact {
    FactState state{FactState::Unavailable};
    T value{};
    std::string need; ///< `Securable:Op`, set only for Denied

    [[nodiscard]] bool ok() const noexcept { return state == FactState::Ok; }
    static Fact make_ok(T v) { return Fact{FactState::Ok, std::move(v), {}}; }
    static Fact with(FactState s, std::string need_ = {}) { return Fact{s, T{}, std::move(need_)}; }
};

// ── Figures ────────────────────────────────────────────────────────────────

/// Device estate. `online + not_seen + offline == total` always holds (a partition).
struct EstateCounts {
    std::int64_t total{0};
    std::int64_t online{0};
    std::int64_t not_seen{0}; ///< not online, heartbeat older than the stale threshold
    std::int64_t offline{0};  ///< not online, heartbeat inside the stale threshold
    /// The roster read hit its row cap, so every figure is a lower bound ("at least N").
    bool at_least{false};
};

struct ComplianceFigure {
    std::int64_t total_checks{0};
    std::int64_t compliant{0};
    std::int64_t non_compliant{0};
    std::int64_t unknown{0};
    double pct{0.0};
};

/// How exact a failed-executions count is. The read is the newest 100 `failed`
/// rows, so a full page can only ever give a lower bound.
enum class CountBound { Exact, AtLeast, Capped };

struct FailedFigure {
    std::int64_t count{0};
    CountBound bound{CountBound::Exact};
    std::int64_t newest_epoch{0}; ///< 0 = unknown
};

struct ApprovalFigure {
    std::int64_t count{0};             ///< exact `COUNT(*)`, always printed
    std::optional<std::int64_t> oldest; ///< epoch secs; nullopt when the list was truncated or empty
};

/// Resolved link targets (the route resolves them through `shell::nav_groups()`).
struct Links {
    std::string approvals{"/instructions"};
    std::string executions{"/instructions"};
    std::string devices{"/hardware"};
    std::string enrolment{"/settings#pending-section"};
};

struct SummaryView {
    std::int64_t now_epoch{0};
    Fact<EstateCounts> devices;
    Fact<ComplianceFigure> compliance;
    Fact<FailedFigure> failed;
    Fact<ApprovalFigure> approvals;
    Fact<std::int64_t> enrolment; ///< only meaningful when `show_enrolment`
    bool show_enrolment{false};   ///< Enrollment:Read admitted; a refused caller gets no row
    Links links;
};

// ── Pure helpers (exposed for tests) ───────────────────────────────────────

/// Clamp to 0..100 for an inline `style="width:N%"`.
[[nodiscard]] int clamp_pct(double v) noexcept;

/// Compliance level from the shared 90 / 70 thresholds: "ok", "warn" or "bad".
[[nodiscard]] const char* compliance_level(double pct) noexcept;

/// "HH:MM UTC" for an epoch-seconds value.
[[nodiscard]] std::string hhmm_utc(std::int64_t epoch_secs);

/// 12345 -> "12,345".
[[nodiscard]] std::string fmt_int(std::int64_t v);

/// One finished execution row, reduced to what the 24 h count needs.
struct FailedRow {
    std::int64_t completed_at{0};
    std::int64_t dispatched_at{0};
};

/// Counts rows whose `completed_at` (else `dispatched_at`) is within 24 h of
/// `now`. `row_cap` is the read's LIMIT: a full page where every row qualifies
/// is `Capped` ("100+"); a full page where some do not is `AtLeast` (an older
/// dispatch may have failed inside the window and sit outside the page); a short
/// page is `Exact`.
[[nodiscard]] FailedFigure failed_in_24h(const std::vector<FailedRow>& rows, std::int64_t now,
                                         std::size_t row_cap);

// ── Renderers ──────────────────────────────────────────────────────────────

/// The readout (four cells) as the main swap target `<section id="home-readout">`.
[[nodiscard]] std::string render_readout(const SummaryView& v);
/// Needs attention panel, `<section id="home-attention" hx-swap-oob="outerHTML">`.
[[nodiscard]] std::string render_attention(const SummaryView& v);
/// The whole `/fragments/home/summary` body: readout + the OOB attention panel.
[[nodiscard]] std::string render_summary(const SummaryView& v);

} // namespace yuzu::server::home
