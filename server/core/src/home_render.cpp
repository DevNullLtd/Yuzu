/// @file home_render.cpp
/// Home renderers: PURE value-in, string-out. See home_render.hpp.

#include "home_render.hpp"

#include "web_utils.hpp"

#include <algorithm>
#include <chrono>
#include <cmath>
#include <ctime>
#include <format>
#include <string_view>

namespace yuzu::server::home {

namespace {

std::string esc(const std::string& s) { return html_escape(s); }

constexpr std::int64_t kDay = 24 * 60 * 60;
/// Donut geometry: r = 54, circumference 2*pi*54 = 339.29 (x100 as integer).
constexpr std::int64_t kCircumferenceX100 = 33929;

std::string plural(std::int64_t n, const char* one, const char* many) {
    return n == 1 ? std::string(one) : std::string(many);
}

// ── Notes: one distinct sentence per non-Ok state ──────────────────────────

std::string denied_text(const std::string& need) {
    return "You do not have access to this figure. It needs <span class=\"mono\">" + esc(need) +
           "</span>.";
}

std::string limited_text() {
    return "Fleet totals are not shown to accounts limited to a group of devices.";
}

std::string unavailable_text(const char* what, bool unwired) {
    if (unwired)
        return std::string(what) + " is not available on this server. This is not zero.";
    return std::string("Could not read ") + what + ". This is not zero.";
}

template <class T>
std::string state_sentence(const Fact<T>& f, const char* what) {
    switch (f.state) {
    case FactState::Denied: return denied_text(f.need);
    case FactState::Limited: return limited_text();
    case FactState::Unwired: return unavailable_text(what, true);
    case FactState::Unavailable:
    case FactState::Ok: break;
    }
    return unavailable_text(what, false);
}

template <class T> const char* state_headline(const Fact<T>& f) {
    switch (f.state) {
    case FactState::Denied: return "No access";
    case FactState::Limited: return "Limited";
    default: return "Unknown";
    }
}

std::string note(const std::string& inner, bool warn = false) {
    return std::string("<div class=\"note") + (warn ? " warn" : "") + "\">" + inner + "</div>";
}

std::string panel_open(const char* id, const char* title, const char* sub_extra,
                       std::int64_t now_epoch, bool oob) {
    std::string out = "<section id=\"";
    out += id;
    out += "\" class=\"panel\"";
    if (oob)
        out += " hx-swap-oob=\"outerHTML\"";
    out += "><div class=\"hd\"><h2>";
    out += title;
    out += "</h2>";
    if (sub_extra && *sub_extra) {
        out += "<span class=\"sub\">";
        out += sub_extra;
        out += "</span>";
    }
    out += "<span class=\"sub end\">As of " + hhmm_utc(now_epoch) + "</span></div>";
    return out;
}

// ── Readout cells ──────────────────────────────────────────────────────────

std::string cell(const std::string& cls, const std::string& value_html, const std::string& label,
                 const std::string& d_html, const char* d_cls = "") {
    std::string out = "<div class=\"ro";
    if (!cls.empty())
        out += " " + cls;
    out += "\"><div class=\"v\">" + value_html + "</div><div class=\"l\">" + label + "</div>";
    if (!d_html.empty()) {
        out += "<div class=\"d";
        if (d_cls && *d_cls)
            out += std::string(" ") + d_cls;
        out += "\">" + d_html + "</div>";
    }
    out += "</div>";
    return out;
}

std::string devices_cell(const SummaryView& v) {
    const auto& f = v.devices;
    if (!f.ok())
        return cell("", state_headline(f), "Devices online", state_sentence(f, "The device roster"),
                    "wn");
    const auto& c = f.value;
    std::string label = "of " + fmt_int(c.total) + " seen in the last 30 days";
    std::string d;
    if (c.not_seen > 0)
        d = fmt_int(c.not_seen) + " not seen for 2 days or more";
    return cell("", fmt_int(c.online), label, d, "wn");
}

std::string compliance_cell(const SummaryView& v) {
    const auto& f = v.compliance;
    if (!f.ok())
        return cell("", state_headline(f), "Policy checks passing", state_sentence(f, "Compliance"),
                    "wn");
    const auto& c = f.value;
    if (c.total_checks <= 0)
        return cell("", "No results yet", "Policy checks passing", "No policy check has reported.");
    const int pct = clamp_pct(c.pct);
    const std::string cls = compliance_level(c.pct);
    std::string label = fmt_int(c.compliant) + " of " + fmt_int(c.total_checks) + " checks";
    std::string d = fmt_int(c.non_compliant) + " failing, " + fmt_int(c.unknown) + " unknown";
    return cell(cls, std::to_string(pct) + "%", label, d);
}

std::string failed_cell(const SummaryView& v) {
    const auto& f = v.failed;
    if (!f.ok())
        return cell("", state_headline(f), "Failed executions", state_sentence(f, "Executions"),
                    "wn");
    const auto& c = f.value;
    std::string value;
    switch (c.bound) {
    case CountBound::Capped: value = "100+"; break;
    case CountBound::AtLeast: value = "at least " + fmt_int(c.count); break;
    case CountBound::Exact: value = fmt_int(c.count); break;
    }
    std::string d;
    if (c.bound == CountBound::AtLeast)
        d = "Older failures may sit outside the newest 100 read.";
    else if (c.count > 0 && c.newest_epoch > 0)
        d = "Most recent " + format_relative_time(c.newest_epoch, v.now_epoch);
    return cell(c.count > 0 ? "bad" : "", value, "in the last 24 hours", d,
                c.bound == CountBound::AtLeast ? "wn" : "");
}

std::string approvals_cell(const SummaryView& v) {
    const auto& f = v.approvals;
    if (!f.ok())
        return cell("", state_headline(f), "Approvals waiting", state_sentence(f, "Approvals"),
                    "wn");
    const auto& c = f.value;
    std::string d;
    if (c.oldest && *c.oldest > 0)
        d = "oldest submitted " + format_relative_time(*c.oldest, v.now_epoch);
    return cell("", fmt_int(c.count), "Approvals waiting", d, "wn");
}

// ── Estate ────────────────────────────────────────────────────────────────

std::string donut_svg(const EstateCounts& c) {
    const auto seg = donut_segments(c.online, c.offline, c.not_seen, kCircumferenceX100);
    const std::string aria =
        "Estate state: " + fmt_int(c.online) + " online, " + fmt_int(c.offline) + " offline, " +
        fmt_int(c.not_seen) + " not seen for 2 days or more, of " + fmt_int(c.total) + " devices";
    std::string out = "<svg class=\"home-donut\" viewBox=\"0 0 140 140\" role=\"img\" aria-label=\"" +
                      esc(aria) + "\"><title>" + esc(aria) + "</title>";
    out += "<circle class=\"home-track\" cx=\"70\" cy=\"70\" r=\"54\" fill=\"none\"/>";
    static constexpr const char* kCls[3] = {"home-s-on", "home-s-off", "home-s-ns"};
    static constexpr const char* kName[3] = {"Online", "Offline", "Not seen for 2 days or more"};
    const std::int64_t vals[3] = {c.online, c.offline, c.not_seen};
    std::int64_t offset = 0;
    for (int i = 0; i < 3; ++i) {
        const std::int64_t len = seg.len_x100[i];
        if (len <= 0)
            continue;
        out += std::format(
            "<circle class=\"{}\" cx=\"70\" cy=\"70\" r=\"54\" fill=\"none\" "
            "stroke-dasharray=\"{}.{:02} {}.{:02}\" stroke-dashoffset=\"-{}.{:02}\" "
            "transform=\"rotate(-90 70 70)\"><title>{}: {}</title></circle>",
            kCls[i], len / 100, len % 100, (kCircumferenceX100 - len) / 100,
            (kCircumferenceX100 - len) % 100, offset / 100, offset % 100, kName[i],
            fmt_int(vals[i]));
        offset += len;
    }
    out += "</svg>";
    return out;
}

std::string platform_bar(const EstateCounts& c) {
    struct Seg { const char* cls; const char* name; std::int64_t n; };
    const Seg segs[] = {{"home-p-win", "Windows", c.windows},
                        {"home-p-lin", "Linux", c.linux_os},
                        {"home-p-mac", "macOS", c.macos},
                        {"home-p-oth", "Other", c.other}};
    std::string out = "<div class=\"home-sbar\" role=\"img\" aria-label=\"Devices by platform\">";
    if (c.total > 0) {
        for (const auto& s : segs) {
            if (s.n <= 0)
                continue;
            const int w = clamp_pct(100.0 * static_cast<double>(s.n) / static_cast<double>(c.total));
            out += std::format("<i class=\"{}\" style=\"width:{}%\" title=\"{}: {}\"></i>", s.cls, w,
                               s.name, fmt_int(s.n));
        }
    }
    out += "</div><div class=\"legend\">";
    for (const auto& s : segs) {
        // "Other" appears only when non-zero; the three named platforms always show.
        if (s.n <= 0 && std::string_view(s.name) == "Other")
            continue;
        out += std::format("<span class=\"chip\"><i class=\"{}\"></i>{}<b>{}</b></span>", s.cls,
                           s.name, fmt_int(s.n));
    }
    out += "</div>";
    return out;
}

// ── Needs attention ───────────────────────────────────────────────────────

std::string att_row(const char* dot, const std::string& title, const std::string& sub,
                    const std::string& href, const char* button) {
    std::string out = std::string("<div class=\"home-row\"><span class=\"sd ") + dot +
                      "\"></span><div class=\"home-rowb\"><b>" + title + "</b>";
    if (!sub.empty())
        out += "<div class=\"mut\">" + sub + "</div>";
    out += "</div>";
    if (!href.empty() && button && *button)
        out += "<a class=\"btn sm\" href=\"" + esc(href) + "\">" + button + "</a>";
    out += "</div>";
    return out;
}

} // namespace

// ── Pure helpers ──────────────────────────────────────────────────────────

int clamp_pct(double v) noexcept {
    if (!(v > 0.0)) // also catches NaN
        return 0;
    if (v >= 100.0)
        return 100;
    return static_cast<int>(std::lround(v));
}

const char* compliance_level(double pct) noexcept {
    if (pct >= 90.0)
        return "ok";
    if (pct >= 70.0)
        return "warn";
    return "bad";
}

std::string hhmm_utc(std::int64_t epoch_secs) {
    const std::time_t t = static_cast<std::time_t>(epoch_secs);
    std::tm tm{};
#ifdef _WIN32
    gmtime_s(&tm, &t);
#else
    gmtime_r(&t, &tm);
#endif
    return std::format("{:02}:{:02} UTC", tm.tm_hour, tm.tm_min);
}

std::string fmt_int(std::int64_t v) {
    const bool neg = v < 0;
    std::string digits = std::to_string(neg ? -v : v);
    std::string out;
    for (std::size_t i = 0; i < digits.size(); ++i) {
        if (i > 0 && (digits.size() - i) % 3 == 0)
            out += ',';
        out += digits[i];
    }
    return neg ? "-" + out : out;
}

EstateCounts partition_estate(std::int64_t total, std::int64_t online, std::int64_t stale) noexcept {
    EstateCounts c;
    c.total = std::max<std::int64_t>(total, 0);
    c.online = std::clamp<std::int64_t>(online, 0, c.total);
    c.not_seen = std::clamp<std::int64_t>(stale, 0, c.total - c.online);
    c.offline = c.total - c.online - c.not_seen;
    return c;
}

FailedFigure failed_in_24h(const std::vector<FailedRow>& rows, std::int64_t now,
                           std::size_t row_cap) {
    FailedFigure f;
    for (const auto& r : rows) {
        const std::int64_t t = r.completed_at > 0 ? r.completed_at : r.dispatched_at;
        if (t <= 0 || now - t > kDay)
            continue;
        ++f.count;
        f.newest_epoch = std::max(f.newest_epoch, t);
    }
    const bool full_page = row_cap > 0 && rows.size() >= row_cap;
    if (full_page) {
        f.bound = static_cast<std::size_t>(f.count) >= rows.size() ? CountBound::Capped
                                                                     : CountBound::AtLeast;
    }
    return f;
}

DonutSegments donut_segments(std::int64_t a, std::int64_t b, std::int64_t c,
                             std::int64_t circumference_x100) {
    DonutSegments s;
    const std::int64_t in[3] = {std::max<std::int64_t>(a, 0), std::max<std::int64_t>(b, 0),
                                std::max<std::int64_t>(c, 0)};
    const std::int64_t total = in[0] + in[1] + in[2];
    if (total <= 0 || circumference_x100 <= 0)
        return s;
    std::int64_t used = 0;
    int last = 0;
    for (int i = 0; i < 3; ++i)
        if (in[i] > 0)
            last = i;
    for (int i = 0; i < 3; ++i) {
        if (in[i] <= 0)
            continue;
        const std::int64_t len = (i == last) ? circumference_x100 - used
                                             : circumference_x100 * in[i] / total;
        s.len_x100[i] = len;
        used += len;
    }
    return s;
}

// ── Renderers ──────────────────────────────────────────────────────────────

std::string render_readout(const SummaryView& v) {
    std::string out = "<section id=\"home-readout\" class=\"readout\" aria-label=\"Estate readout\">";
    out += devices_cell(v);
    out += compliance_cell(v);
    out += failed_cell(v);
    out += approvals_cell(v);
    out += "</section>";
    return out;
}

std::string render_estate(const SummaryView& v) {
    std::string out = panel_open("home-estate", "Estate state", "", v.now_epoch, true);
    out += "<div class=\"pb\">";
    const auto& f = v.devices;
    if (!f.ok()) {
        out += note(state_sentence(f, "The device roster"), f.state != FactState::Denied);
    } else if (f.value.total == 0) {
        out += "<p class=\"mut\">No devices have reported in the last 30 days.</p>";
    } else {
        const auto& c = f.value;
        out += "<div class=\"home-estate\">" + donut_svg(c);
        out += "<div class=\"home-donut-c\"><b>" + fmt_int(c.total) + "</b><span>devices</span></div>";
        out += "<div class=\"legend home-legend\">";
        out += "<span><i class=\"home-s-on\"></i>Online<b>" + fmt_int(c.online) + "</b></span>";
        out += "<span><i class=\"home-s-off\"></i>Offline<b>" + fmt_int(c.offline) + "</b></span>";
        out += "<span><i class=\"home-s-ns\"></i>Not seen for 2 days or more<b>" +
               fmt_int(c.not_seen) + "</b></span>";
        out += "</div></div>";
        out += "<h3 class=\"home-sub\">By platform</h3>" + platform_bar(c);
    }
    out += "</div></section>";
    return out;
}

std::string render_attention(const SummaryView& v) {
    std::string out = panel_open("home-attention", "Needs attention", "", v.now_epoch, true);
    out += "<div class=\"pb home-att\">";
    int rows = 0;
    bool all_ok = true;

    // Approvals.
    if (v.approvals.ok()) {
        const auto& a = v.approvals.value;
        if (a.count > 0) {
            std::string sub;
            if (a.oldest && *a.oldest > 0)
                sub = "Oldest submitted " + format_relative_time(*a.oldest, v.now_epoch);
            out += att_row("s-w",
                           fmt_int(a.count) + plural(a.count, " approval is waiting",
                                                     " approvals are waiting"),
                           sub, v.links.approvals, "Review");
            ++rows;
        }
    } else {
        all_ok = false;
        out += note(state_sentence(v.approvals, "Approvals"), true);
    }

    // Failed executions.
    if (v.failed.ok()) {
        const auto& f = v.failed.value;
        if (f.count > 0) {
            std::string title;
            switch (f.bound) {
            case CountBound::Capped: title = "100+ executions failed in the last 24 hours"; break;
            case CountBound::AtLeast:
                title = "At least " + fmt_int(f.count) + " executions failed in the last 24 hours";
                break;
            case CountBound::Exact:
                title = fmt_int(f.count) +
                        plural(f.count, " execution failed in the last 24 hours",
                               " executions failed in the last 24 hours");
                break;
            }
            std::string sub;
            if (f.newest_epoch > 0)
                sub = "Most recent " + format_relative_time(f.newest_epoch, v.now_epoch);
            out += att_row("s-bad", title, sub, v.links.executions, "Open");
            ++rows;
        }
    } else {
        all_ok = false;
        out += note(state_sentence(v.failed, "Executions"), true);
    }

    // Devices not seen (same figure as the readout's warning line).
    if (v.devices.ok()) {
        const auto n = v.devices.value.not_seen;
        if (n > 0) {
            out += att_row("s-w",
                           fmt_int(n) + plural(n, " device has not reported for 2 days or more",
                                               " devices have not reported for 2 days or more"),
                           "", v.links.devices, "Show devices");
            ++rows;
        }
    } else {
        all_ok = false;
        out += note(state_sentence(v.devices, "The device roster"), true);
    }

    // Enrolment: an effective-admin-only row. Absent for everyone else by design.
    if (v.show_enrolment) {
        if (v.enrolment.ok()) {
            const auto n = v.enrolment.value;
            if (n > 0) {
                out += att_row("s-w",
                               fmt_int(n) + plural(n, " agent is awaiting enrolment",
                                                   " agents are awaiting enrolment"),
                               "", v.links.enrolment, "Review");
                ++rows;
            }
        } else {
            all_ok = false;
            out += note(state_sentence(v.enrolment, "Pending enrolments"), true);
        }
    }

    if (rows == 0 && all_ok)
        out += "<div class=\"home-row\"><span class=\"sd s-on\"></span><div class=\"home-rowb\">"
               "<b>Nothing needs attention</b></div></div>";
    out += "</div></section>";
    return out;
}

std::string render_summary(const SummaryView& v) {
    return render_readout(v) + render_estate(v) + render_attention(v);
}

} // namespace yuzu::server::home
