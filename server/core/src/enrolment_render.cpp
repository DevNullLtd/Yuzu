// Enrolment fragment renderers (see enrolment_render.hpp).

#include "enrolment_render.hpp"

#include "web_utils.hpp"

#include <algorithm>
#include <cstdint>
#include <format>

namespace yuzu::server::enrolment {

namespace {

using auth::AutoApproveRuleType;

constexpr std::string_view kFailboxSv =
    "<div class=\"failbox\" role=\"alert\"><div><b>Enrolment store unavailable.</b> "
    "State unknown. This is not an empty list. Retry shortly.</div></div>";

// What an enrolment token can still do, decided against an injected clock. Revoked beats
// exhausted beats expired; an expiry exactly at `now` is already expired (the consume path
// needs expires_at > now() to enrol, so a token the server refuses is never listed Active).
enum class TokenState { active, expired, exhausted, revoked };

TokenState token_state(const auth::EnrollmentToken& t,
                       std::chrono::system_clock::time_point now) {
    if (t.revoked)
        return TokenState::revoked;
    if (t.max_uses > 0 && t.use_count >= t.max_uses)
        return TokenState::exhausted;
    if (t.expires_at != (std::chrono::system_clock::time_point::max)() && t.expires_at <= now)
        return TokenState::expired;
    return TokenState::active;
}

// A denial is a durable record: the Forget route refuses to remove it (409) and nothing on the
// page re-approves it. Both Deny confirms say so, so one-row Deny is not the lighter choice.
constexpr std::string_view kNoReverseDenial = "This page offers no way to reverse a denial.";

// "Active" is mild information, never the green OK pill: a lapsed credential is not "healthy".
std::string pill(const char* cls, const char* text) {
    return std::string("<span class=\"pill ") + cls + "\">" + text + "</span>";
}

bool is_ipv4_literal(std::string_view s) {
    int octets = 0;
    std::size_t i = 0;
    while (i <= s.size()) {
        std::size_t digits = 0;
        int v = 0;
        while (i < s.size() && s[i] >= '0' && s[i] <= '9') {
            v = v * 10 + (s[i] - '0');
            if (++digits > 3 || v > 255)
                return false;
            ++i;
        }
        if (digits == 0)
            return false;
        ++octets;
        if (i == s.size())
            break;
        if (s[i] != '.')
            return false;
        ++i;
    }
    return octets == 4;
}

// Honest about what is matched. A hostname and a cloud provider are strings the REGISTERING
// AGENT states about itself (RegisterRequest.attestation_provider is a bare compare; verified
// attestation is a later tier), an address is what the server saw, and a CA fingerprint can
// never match at this release because Register does not populate it (auto_approve.cpp
// match_rule; docs/user-manual/device-management.md "Auto-Approval Policies").
const char* rule_phrase(AutoApproveRuleType t) {
    switch (t) {
    case AutoApproveRuleType::trusted_ca:
        return "Agent CA fingerprint ";
    case AutoApproveRuleType::hostname_glob:
        return "Agent-reported hostname matches ";
    case AutoApproveRuleType::ip_subnet:
        return "Address the server sees matches ";
    case AutoApproveRuleType::cloud_provider:
        return "Agent-reported provider ";
    }
    return "";
}

const char* rule_suffix(AutoApproveRuleType t) {
    switch (t) {
    case AutoApproveRuleType::trusted_ca:
        return " (never matches at this release)";
    case AutoApproveRuleType::hostname_glob:
    case AutoApproveRuleType::cloud_provider:
        return " (not verified)";
    case AutoApproveRuleType::ip_subnet:
        break;
    }
    return "";
}

// Static-confirm copy for one rule's Enable / Disable and Remove, by match mode AND by how many
// rules are enabled (`enabled_count`). In "all" mode every enabled rule is REQUIRED, so enabling
// narrows and disabling or removing widens, with one exception at each end: with ZERO enabled
// rules the engine matches nobody (auto_approve.cpp evaluate), so enabling the first rule WIDENS
// admission from nobody to whatever that rule matches, and disabling or removing the LAST
// enabled rule leaves nobody admitted. Each names the rule's value: the list can change under a
// stale view, and the operator confirms THIS rule. (attr_confirm escapes the finished text.)
std::string quoted(const std::string& value) {
    return "\"" + value + "\"";
}
std::string enable_confirm(bool require_all, std::size_t enabled_count, const std::string& value) {
    if (!require_all || enabled_count == 0)
        return "Enable rule " + quoted(value) + "? Matching agents will join without approval.";
    return "Require rule " + quoted(value) + " as well? Fewer agents will join without approval.";
}
std::string disable_confirm(bool require_all, std::size_t enabled_count,
                            const std::string& value) {
    if (!require_all)
        return "";
    if (enabled_count <= 1)
        return "Disable the last enabled rule " + quoted(value) +
               "? No agent will join without approval until a rule is enabled.";
    return "Stop requiring rule " + quoted(value) + "? More agents may join without approval.";
}
std::string remove_confirm(bool require_all, bool enabled, std::size_t enabled_count,
                           const std::string& value) {
    const std::string head = "Remove rule " + quoted(value) + "?";
    if (require_all && enabled) {
        if (enabled_count <= 1)
            return head + " It is the last enabled rule, so no agent will join without approval "
                          "until a rule is enabled.";
        return head + " It is currently required, so more agents may join without approval.";
    }
    return head;
}

// hx-vals naming the rule the operator is looking at (htmx 2 sends them as form fields on a
// POST and as query parameters on a DELETE). The list position alone shifts under a concurrent
// edit; the routes verify these against the rule now at that index and refuse a mismatch. An
// `enabled` state is added for a toggle, which flips whatever state it finds.
std::string attr_rule_vals(const auth::AutoApproveRule& r, bool with_enabled) {
    std::string json = "{\"type\":\"" + auth::rule_type_to_string(r.type) + "\",\"value\":\"" +
                       json_escape(r.value) + "\"";
    if (with_enabled)
        json += std::string(",\"enabled\":\"") + (r.enabled ? "1" : "0") + "\"";
    return " hx-vals=\"" + html_escape(json + "}") + "\"";
}

std::string attr_confirm(const std::string& question) {
    return question.empty() ? std::string() : " hx-confirm=\"" + html_escape(question) + "\"";
}

} // namespace


std::string utc_stamp_epoch_secs(std::int64_t secs) {
    using namespace std::chrono;
    // No CRT gmtime/strftime: past year 3000 MSVC's gmtime_s fails and strftime on the zeroed
    // result terminates the process via the invalid-parameter handler, and POSIX would print
    // a 1900-01-00 date. A legacy import can carry an epoch to year 9999, so the range is
    // stated rather than assumed: four-digit years from 1970 only. The check comes BEFORE any
    // chrono value is built, so no input (INT64_MIN included) can overflow a conversion.
    constexpr std::int64_t kLastSecond = 253'402'300'799; // 9999-12-31 23:59:59 UTC
    if (secs < 0 || secs > kLastSecond)
        return "out of range";
    const sys_seconds at{seconds{secs}};
    const sys_days day = floor<days>(at);
    const year_month_day cal{day};
    const hh_mm_ss tod{at - day};
    return std::format("{:04}-{:02}-{:02} {:02}:{:02} UTC", static_cast<int>(cal.year()),
                       static_cast<unsigned>(cal.month()), static_cast<unsigned>(cal.day()),
                       tod.hours().count(), tod.minutes().count());
}

std::string utc_stamp(std::chrono::system_clock::time_point tp) {
    // floor<seconds> of any representable time_point divides by the tick ratio, so it cannot
    // overflow whatever the clock's tick (nanoseconds on libstdc++, microseconds on libc++).
    return utc_stamp_epoch_secs(
        std::chrono::floor<std::chrono::seconds>(tp).time_since_epoch().count());
}

bool rule_matches_everything(AutoApproveRuleType type, std::string_view value) {
    if (type == AutoApproveRuleType::hostname_glob) {
        if (value.empty())
            return false;
        bool star = false;
        for (char c : value) {
            if (c == '*')
                star = true;
            else if (c != '?')
                return false;
        }
        return star;
    }
    if (type == AutoApproveRuleType::ip_subnet) {
        const auto slash = value.find('/');
        if (slash == std::string_view::npos)
            return false;
        return value.substr(slash + 1) == "0" && is_ipv4_literal(value.substr(0, slash));
    }
    return false;
}

// ── Enrolment tokens ─────────────────────────────────────────────────────

std::string render_tokens(const std::vector<auth::EnrollmentToken>* tokens,
                          std::string_view new_raw_token,
                          std::chrono::system_clock::time_point now) {
    std::string html;

    // The reveal comes first and is built before the list read matters: a freshly minted raw
    // token is shown ONCE, so it must survive a failed follow-up read. `<code>` and the Copy
    // button share one parent (the Settings page's copy handler walks parent -> code).
    if (!new_raw_token.empty()) {
        html += "<div class=\"note warn\" role=\"region\" aria-label=\"New enrolment token\">"
                "<b>Copy this token now. It will not be shown again.</b>"
                "<div class=\"revealrow\"><code class=\"mono\">" +
                html_escape(std::string(new_raw_token)) +
                "</code>"
                "<button class=\"btn sm\" type=\"button\" data-copy-token>Copy to Clipboard</button>"
                "<button class=\"btn sm primary\" type=\"button\" "
                "hx-get=\"/fragments/settings/tokens\" hx-target=\"#token-section\" "
                "hx-swap=\"innerHTML\">Done</button></div></div>";
    }

    if (!tokens) {
        html += std::string(kFailboxSv);
        return html;
    }

    struct Row {
        const auth::EnrollmentToken* t;
        TokenState state;
    };
    std::vector<Row> rows;
    rows.reserve(tokens->size());
    for (const auto& t : *tokens)
        rows.push_back({&t, token_state(t, now)});
    // Active first, otherwise the store's newest-first order is kept.
    std::stable_partition(rows.begin(), rows.end(),
                          [](const Row& r) { return r.state == TokenState::active; });

    if (rows.empty()) {
        html += "<div class=\"empty\"><b>No tokens yet.</b>"
                "<span>Generate one below to enrol agents without approval.</span></div>";
    } else {
        html += "<div class=\"tw\"><table><thead><tr><th>ID</th><th>Label</th><th>Uses</th>"
                "<th>Expires</th><th>Status</th><th></th></tr></thead><tbody>";
        const std::size_t shown = (std::min)(rows.size(), kRenderCap);
        for (std::size_t i = 0; i < shown; ++i) {
            const auto& t = *rows[i].t;
            const std::string uses =
                t.max_uses == 0
                    ? std::to_string(t.use_count) + " / \xe2\x88\x9e"
                    : std::to_string(t.use_count) + " / " + std::to_string(t.max_uses);
            const std::string exp =
                t.expires_at == (std::chrono::system_clock::time_point::max)()
                    ? std::string("Never")
                    : utc_stamp(t.expires_at);
            std::string status;
            switch (rows[i].state) {
            case TokenState::active:
                status = pill("info", "Active");
                break;
            case TokenState::expired:
                status = pill("warn", "Expired");
                break;
            case TokenState::exhausted:
                status = pill("idle", "Exhausted");
                break;
            case TokenState::revoked:
                status = pill("idle", "Revoked");
                break;
            }
            html += "<tr><td><code>" + html_escape(t.token_id) + "</code></td><td class=\"long\">" +
                    html_escape(t.label) + "</td><td>" + uses + "</td><td>" + exp + "</td><td>" +
                    status + "</td><td class=\"acts\">";
            if (!t.revoked) {
                html += "<button class=\"btn link danger\" type=\"button\" "
                        "hx-delete=\"/api/settings/enrollment-tokens/" +
                        url_path_segment(t.token_id) +
                        "\" hx-target=\"#token-section\" hx-swap=\"innerHTML\" "
                        "hx-confirm=\"Revoke token &quot;" +
                        html_escape(t.token_id) +
                        "&quot;? Agents using this token will no longer be able to enroll. "
                        "Agents already enrolled stay enrolled.\">Revoke</button>";
            }
            html += "</td></tr>";
        }
        html += "</tbody></table></div>";
        if (rows.size() > shown) {
            html += "<p class=\"hint pad\">Showing " + std::to_string(shown) + " of " +
                    std::to_string(rows.size()) + " tokens. Active tokens are listed first.</p>";
        }
    }

    // hx-disabled-elt (htmx core, not hx-on) disables the submit button while the request is in
    // flight, so a double click cannot mint two tokens.
    html += "<form class=\"form\" hx-post=\"/api/settings/enrollment-tokens\" "
            "hx-target=\"#token-section\" hx-swap=\"innerHTML\" "
            "hx-disabled-elt=\"find button[type=submit]\" data-token-form>"
            "<div class=\"fld\"><label for=\"tok-label\">Label</label>"
            "<input class=\"in\" id=\"tok-label\" type=\"text\" name=\"label\" maxlength=\"" +
            std::to_string(auth::kMaxEnrollmentTextLength) +
            "\" placeholder=\"e.g. Edinburgh rollout\"></div>"
            "<div class=\"row2\">"
            "<div class=\"fld\"><label for=\"tok-uses\">Max uses</label>"
            "<input class=\"in\" id=\"tok-uses\" type=\"text\" inputmode=\"numeric\" "
            "name=\"max_uses\" placeholder=\"0 = unlimited\"></div>"
            "<div class=\"fld\"><label for=\"tok-ttl\">Expires after (hours)</label>"
            "<input class=\"in\" id=\"tok-ttl\" type=\"text\" inputmode=\"numeric\" "
            "name=\"ttl_hours\" placeholder=\"0 = never\"></div></div>"
            "<p class=\"hint\" data-token-unlimited>Unlimited uses and no expiry. Anyone holding "
            "this token can enrol agents indefinitely.</p>"
            "<div><button class=\"btn primary\" type=\"submit\">Generate token</button></div>"
            "</form>";
    return html;
}

// ── Agents waiting for approval ──────────────────────────────────────────

std::string render_pending(const std::vector<auth::PendingAgent>* agents) {
    if (!agents)
        return std::string(kFailboxSv);

    std::vector<const auth::PendingAgent*> waiting, denied;
    for (const auto& a : *agents) {
        if (a.status == auth::PendingStatus::pending)
            waiting.push_back(&a);
        else if (a.status == auth::PendingStatus::denied)
            denied.push_back(&a);
        // approved rows are enrolled: they need no admin attention.
    }
    const std::size_t n_waiting = waiting.size(); // counted BEFORE the render cap
    std::vector<const auth::PendingAgent*> rows = waiting;
    rows.insert(rows.end(), denied.begin(), denied.end());
    const std::size_t shown = (std::min)(rows.size(), kRenderCap);

    std::string html;
    if (rows.empty()) {
        return "<div class=\"empty\"><b>No agents are waiting.</b>"
               "<span>New agents that register without a token appear here.</span></div>";
    }

    html += "<p class=\"hint pad\">" + std::to_string(n_waiting) + " waiting";
    if (!denied.empty())
        html += ", " + std::to_string(denied.size()) + " denied";
    html += "</p>";

    html += "<div class=\"tw\"><table><thead><tr><th>Agent</th><th>Hostname</th><th>OS</th>"
            "<th>Version</th><th>Requested</th><th>Status</th><th></th></tr></thead><tbody>";
    for (std::size_t i = 0; i < shown; ++i) {
        const auto& a = *rows[i];
        const std::string short_id =
            a.agent_id.size() > 12 ? a.agent_id.substr(0, 12) + "..." : a.agent_id;
        const bool is_pending = a.status == auth::PendingStatus::pending;
        html += "<tr><td><code title=\"" + html_escape(a.agent_id) + "\">" +
                html_escape(short_id) + "</code></td><td class=\"long\">" +
                html_escape(a.hostname) + "</td><td>" + html_escape(a.os) + " " +
                html_escape(a.arch) + "</td><td>" + html_escape(a.agent_version) + "</td><td>" +
                utc_stamp(a.requested_at) + "</td><td>" +
                (is_pending ? pill("warn", "Pending") : pill("bad", "Denied")) +
                "</td><td class=\"acts\">";
        if (is_pending && !path_segment_ok(a.agent_id)) {
            // Empty, `.` or `..` (also %2e forms): a browser collapses a dot-only path segment,
            // so no per-row URL can be built. Offer no row action; the bulk buttons below stay.
            html += "<span class=\"hint\">identifier not supported for row actions</span>";
        } else if (is_pending) {
            // The id is agent-supplied: ONE percent-encoded path segment (html_escape alone
            // leaves `/`, `?`, `#` and `.` live in the URL).
            const std::string base = "/api/settings/pending-agents/" + url_path_segment(a.agent_id);
            html += "<button class=\"btn link\" type=\"button\" hx-post=\"" + base +
                    "/approve\" hx-target=\"#pending-section\" hx-swap=\"innerHTML\">"
                    "Approve</button>"
                    "<button class=\"btn link danger\" type=\"button\" hx-post=\"" +
                    base +
                    "/deny\" hx-target=\"#pending-section\" hx-swap=\"innerHTML\" "
                    "hx-confirm=\"Deny agent enrollment? " + std::string(kNoReverseDenial) +
                    "\">Deny</button>"
                    "<button class=\"btn link\" type=\"button\" hx-delete=\"" +
                    base +
                    "\" hx-target=\"#pending-section\" hx-swap=\"innerHTML\" "
                    "hx-confirm=\"Remove this request from the queue? The agent is queued again "
                    "the next time it asks to join.\">Forget</button>";
        } else {
            // A denial is a durable record; removing it is refused server-side (409).
            html += "<span class=\"hint\">denial recorded</span>";
        }
        html += "</td></tr>";
    }
    html += "</tbody></table></div>";

    // Waiting rows come first, so the rows the cap cuts off are denied ones whenever every
    // waiting agent is shown. (When waiting agents are cut, the bulk-bar banner below says so.)
    if (rows.size() > shown && n_waiting <= kRenderCap) {
        html += "<p class=\"hint pad\">Showing " + std::to_string(shown) + " of " +
                std::to_string(rows.size()) + " agents. Every waiting agent is listed; the " +
                std::to_string(rows.size() - shown) + " other denied agents are not.</p>";
    }

    // A lone waiting row whose id cannot be addressed would otherwise have no action at all.
    const bool lone_unaddressable =
        n_waiting == 1 && !path_segment_ok(waiting.front()->agent_id);
    if (n_waiting > 1 || lone_unaddressable) {
        // The bulk routes act on EVERY pending row, including any beyond the cap and any that
        // arrive after this render, so the buttons are off whenever the list is not whole.
        const bool whole = n_waiting <= kRenderCap;
        std::string names;
        for (std::size_t i = 0; i < (std::min)(n_waiting, kBulkHostnamesListed); ++i)
            names += "\n- " + waiting[i]->hostname;
        if (n_waiting > kBulkHostnamesListed)
            names += "\n- and " + std::to_string(n_waiting - kBulkHostnamesListed) + " more";
        const std::string count = std::to_string(n_waiting);
        const std::string tail = " as of this view, including any that arrive since)?";
        const std::string approve_q =
            "Approve every agent currently waiting (" + count + tail +
            " They join the fleet and can receive instructions." + names;
        const std::string deny_q = "Deny every agent currently waiting (" + count + tail + " " +
                                   std::string(kNoReverseDenial) + names;
        const char* off = whole ? "" : " disabled";
        html += "<div class=\"btns\"><button class=\"btn primary\" type=\"button\"" +
                std::string(off) +
                " hx-post=\"/api/settings/pending-agents/bulk-approve\" "
                "hx-target=\"#pending-section\" hx-swap=\"innerHTML\" hx-confirm=\"" +
                html_escape(approve_q) + "\">Approve all (" + count +
                ")</button>"
                "<button class=\"btn danger\" type=\"button\"" +
                std::string(off) +
                " hx-post=\"/api/settings/pending-agents/bulk-deny\" "
                "hx-target=\"#pending-section\" hx-swap=\"innerHTML\" hx-confirm=\"" +
                html_escape(deny_q) + "\">Deny all (" + count + ")</button></div>";
        if (!whole) {
            html += "<p class=\"hint pad\">Showing " + std::to_string(kRenderCap) + " of " +
                    count + ". Approve or deny these individually; the bulk actions act on every "
                            "waiting agent, including the ones not shown.</p>";
        }
    }
    return html;
}

// ── Auto-approve rules ───────────────────────────────────────────────────

std::string render_auto_approve(const std::vector<auth::AutoApproveRule>& rules,
                                bool require_all) {
    std::string html;

    // Match mode. Two buttons, not a select: each direction carries its own consequence copy,
    // and a cancelled confirm leaves nothing half-switched.
    html += "<div class=\"pad\"><div class=\"fld\"><span class=\"lb\">Match mode</span>"
            "<div class=\"seg\" role=\"group\" aria-label=\"Match mode\">";
    const auto mode_btn = [&](bool all, const char* label, const char* confirm) {
        const bool current = all == require_all;
        if (current)
            return std::string("<button class=\"on\" type=\"button\" aria-pressed=\"true\" "
                               "disabled>") +
                   label + "</button>";
        return std::string("<button type=\"button\" aria-pressed=\"false\" "
                           "hx-post=\"/api/settings/auto-approve/mode\" "
                           "hx-vals=\"{&quot;mode&quot;:&quot;") +
               (all ? "all" : "any") +
               "&quot;}\" hx-target=\"#auto-approve-section\" hx-swap=\"innerHTML\" "
               "hx-confirm=\"" +
               confirm + "\">" + label + "</button>";
    };
    html += mode_btn(false, "Any rule matches (first match)",
                     "Approve an agent when any enabled rule matches? More agents may join "
                     "without approval.");
    html += mode_btn(true, "All enabled rules must match",
                     "Require every enabled rule to match? Fewer agents will join without "
                     "approval.");
    html += "</div></div></div>";

    if (rules.empty()) {
        html += "<div class=\"empty\"><b>No auto-approve rules.</b>"
                "<span>New agents wait for approval.</span></div>";
    } else {
        const auto enabled_count = static_cast<std::size_t>(
            std::count_if(rules.begin(), rules.end(), [](const auto& r) { return r.enabled; }));
        html += "<div class=\"tw\"><table><thead><tr><th>Rule</th><th>Label</th><th>State</th>"
                "<th></th></tr></thead><tbody>";
        for (std::size_t i = 0; i < rules.size(); ++i) {
            const auto& r = rules[i];
            const std::string idx = std::to_string(i);
            const std::string base = "/api/settings/auto-approve/" + idx;
            html += "<tr><td class=\"long\">" + std::string(rule_phrase(r.type)) + "<code>" +
                    html_escape(r.value) + "</code>" + rule_suffix(r.type);
            if (rule_matches_everything(r.type, r.value))
                html += " " + pill("warn", "Matches every agent");
            html += "</td><td class=\"long\">" + html_escape(r.label) + "</td><td>" +
                    (r.enabled ? pill("info", "Enabled") : pill("idle", "Disabled")) +
                    "</td><td class=\"acts\">";
            // Enabling widens (any mode) or narrows (all mode); the copy says which.
            const std::string q = r.enabled ? disable_confirm(require_all, enabled_count, r.value)
                                            : enable_confirm(require_all, enabled_count, r.value);
            html += "<button class=\"btn link\" type=\"button\" hx-post=\"" + base +
                    "/toggle\" hx-target=\"#auto-approve-section\" hx-swap=\"innerHTML\"" +
                    attr_rule_vals(r, /*with_enabled=*/true) + attr_confirm(q) + ">" +
                    (r.enabled ? "Disable" : "Enable") +
                    "</button>"
                    "<button class=\"btn link danger\" type=\"button\" hx-delete=\"" +
                    base + "\" hx-target=\"#auto-approve-section\" hx-swap=\"innerHTML\"" +
                    attr_rule_vals(r, /*with_enabled=*/false) +
                    attr_confirm(remove_confirm(require_all, r.enabled, enabled_count, r.value)) +
                    ">Remove</button>";
            html += "</td></tr>";
        }
        html += "</tbody></table></div>";
    }

    // An agent enrolling through a gateway reaches the server with no peer address
    // (gateway_service_impl.cpp registers it with an empty one), so an address rule can never
    // match it; saying so keeps an operator from reading "no match" as "rule misconfigured".
    html += "<p class=\"hint pad\">Address rules match IPv4 only, and never match an agent that "
            "enrols through a gateway (no address is passed on). Hostnames and cloud providers are "
            "reported by the agent and are not verified. A CA fingerprint rule never matches at "
            "this release.</p>";

    // The Add confirm is this static hx-confirm text and the only copy of the question:
    // yuzu-groups.js appends "This matches every agent." to the confirm event's
    // detail.question when the typed value would match every agent, and adds nothing else.
    html += "<form class=\"form\" hx-post=\"/api/settings/auto-approve\" "
            "hx-target=\"#auto-approve-section\" hx-swap=\"innerHTML\" data-rule-form "
            "hx-confirm=\"Add this rule? Agents matching it join the fleet without approval. "
            "Hostnames and cloud providers are reported by the agent and are not verified.\">"
            "<div class=\"row2\">"
            "<div class=\"fld\"><label for=\"rule-type\">Type</label>"
            "<select id=\"rule-type\" name=\"type\">"
            "<option value=\"hostname_glob\">Hostname glob</option>"
            "<option value=\"ip_subnet\">Address range (IPv4 CIDR)</option>"
            "<option value=\"trusted_ca\">Trusted CA fingerprint</option>"
            "<option value=\"cloud_provider\">Cloud provider</option></select></div>"
            "<div class=\"fld\"><label for=\"rule-value\">Value</label>"
            "<input class=\"in mono\" id=\"rule-value\" type=\"text\" name=\"value\" required "
            "maxlength=\"" + std::to_string(auth::kMaxRuleValueLen) +
            "\" pattern=\"[^:]*\" title=\"A colon is not allowed.\" "
            "placeholder=\"*.prod.example.com\"></div></div>"
            "<div class=\"fld\"><label for=\"rule-label\">Label</label>"
            "<input class=\"in\" id=\"rule-label\" type=\"text\" name=\"label\" maxlength=\"" +
            std::to_string(auth::kMaxRuleLabelLen) +
            "\" pattern=\"[^:]*\" title=\"A colon is not allowed.\" "
            "placeholder=\"Production servers\"></div>"
            "<div><button class=\"btn primary\" type=\"submit\">Add rule</button></div>"
            "</form>";
    return html;
}

} // namespace yuzu::server::enrolment
