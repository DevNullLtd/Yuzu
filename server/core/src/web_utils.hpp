#pragma once

/// @file web_utils.hpp
/// Pure utility functions for the Yuzu web server layer.
/// Extracted here for testability.

#include <algorithm>
#include <cctype>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <ctime>
#include <format>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <vector>

#include <yuzu/log_token.hpp>

namespace yuzu::server {

/// Decode a Base64-encoded string.
inline std::string base64_decode(const std::string& in) {
    static constexpr unsigned char kTable[256] = {
        64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64,
        64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 62,
        64, 64, 64, 63, 52, 53, 54, 55, 56, 57, 58, 59, 60, 61, 64, 64, 64, 64, 64, 64, 64, 0,
        1,  2,  3,  4,  5,  6,  7,  8,  9,  10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22,
        23, 24, 25, 64, 64, 64, 64, 64, 64, 26, 27, 28, 29, 30, 31, 32, 33, 34, 35, 36, 37, 38,
        39, 40, 41, 42, 43, 44, 45, 46, 47, 48, 49, 50, 51, 64, 64, 64, 64, 64, 64, 64, 64, 64,
        64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64,
        64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64,
        64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64,
        64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64,
        64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64,
        64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64};
    std::string out;
    out.reserve(in.size() * 3 / 4);
    unsigned int val = 0;
    int bits = -8;
    for (unsigned char c : in) {
        if (kTable[c] == 64)
            continue;
        val = (val << 6) | kTable[c];
        bits += 6;
        if (bits >= 0) {
            out += static_cast<char>((val >> bits) & 0xFF);
            bits -= 8;
        }
    }
    return out;
}

/// Escape JSON metacharacters in a string so the result is safe to embed
/// inside a JSON string literal. Used in particular for HTMX `hx-vals`
/// attributes — the browser un-HTML-escapes the attribute value *before*
/// HTMX's JSON parser sees it, so a `"` in any value (after `html_escape`
/// becomes `&quot;`, which the browser un-escapes to `"`) would otherwise
/// close the JSON string and inject keys into the form. The correct
/// pattern is JSON-escape FIRST, then HTML-escape the result, so the
/// surrounding html_escape on the JSON-attribute literal is safe.
///
/// Caller is responsible for the final html_escape pass; this function
/// only addresses JSON metacharacters and C0 control bytes per RFC 8259.
/// Multi-byte UTF-8 sequences pass through unchanged — JSON does not
/// require U+2028/U+2029 escaping unless the parser is JS `eval`, which
/// is not the case here.
inline std::string json_escape(std::string_view in) {
    std::string out;
    out.reserve(in.size() + 4);
    for (char c : in) {
        switch (c) {
        case '"':  out += "\\\""; break;
        case '\\': out += "\\\\"; break;
        case '\b': out += "\\b"; break;
        case '\f': out += "\\f"; break;
        case '\n': out += "\\n"; break;
        case '\r': out += "\\r"; break;
        case '\t': out += "\\t"; break;
        default:
            if (static_cast<unsigned char>(c) < 0x20) {
                char buf[8];
                std::snprintf(buf, sizeof(buf), "\\u%04x",
                              static_cast<unsigned char>(c));
                out += buf;
            } else {
                out += c;
            }
        }
    }
    return out;
}

/// Render an agent's `error|...` reply as display text: the FIRST record only,
/// prefix stripped, bounded, and never split mid-codepoint.
///
/// Agent replies are newline-separated records, so a byte-count truncation of
/// the RAW output is wrong in both directions. Too small and it cuts the
/// operator's recovery instruction mid-sentence; too large and it runs past the
/// newline and renders the head of the NEXT record as debris -- `tar status`'s
/// offline reply is `error|...` followed by `storage_state|offline`, and a
/// 300-byte window ends in a trailing `storage_stat`. Bounding the FIRST LINE is
/// the property that holds whatever the message length becomes.
///
/// `max_bytes` is a display bound, so it is walked back off a UTF-8
/// continuation byte rather than splitting the sequence.
inline std::string agent_error_display(const std::string& output, std::size_t max_bytes = 400) {
    static constexpr std::string_view kPrefix = "error|";
    std::string_view v{output};
    if (v.starts_with(kPrefix))
        v.remove_prefix(kPrefix.size());
    // FIRST non-empty record. A leading newline (or a reply whose first record
    // is blank) would otherwise render as an empty message -- a regression
    // against the byte window this replaced, which at least showed the detail.
    while (!v.empty() && (v.front() == '\n' || v.front() == '\r'))
        v.remove_prefix(1);
    v = v.substr(0, v.find('\n')); // npos-safe
    while (!v.empty() && v.back() == '\r') // CRLF replies
        v.remove_suffix(1);

    if (v.size() > max_bytes) {
        std::size_t cut = max_bytes;
        // 10xxxxxx is a UTF-8 continuation byte; step back to its lead byte.
        // Bounded to 3 steps: a longer run means the input was already malformed,
        // and walking to 0 would erase the whole message rather than truncate it.
        std::size_t steps = 0;
        while (cut > 0 && steps < 3 && (static_cast<unsigned char>(v[cut]) & 0xC0) == 0x80) {
            --cut;
            ++steps;
        }
        if (steps == 3 && (static_cast<unsigned char>(v[cut]) & 0xC0) == 0x80)
            cut = max_bytes; // not a real sequence; cut where asked
        v = v.substr(0, cut);
    }
    // Only now materialise, so a multi-megabyte reply is not copied whole.
    return std::string{v};
}

/// Escape HTML special characters for safe rendering.
inline std::string html_escape(const std::string& s) {
    std::string out;
    out.reserve(s.size());
    for (char c : s) {
        switch (c) {
        case '&':
            out += "&amp;";
            break;
        case '<':
            out += "&lt;";
            break;
        case '>':
            out += "&gt;";
            break;
        case '"':
            out += "&quot;";
            break;
        case '\'':
            out += "&#39;";
            break;
        default:
            out += c;
        }
    }
    return out;
}

/// Sanitize an operator-supplied value (definition id, approval id) before it
/// goes into a server log line: control characters — CR/LF especially —
/// would otherwise let a caller forge additional log lines (Gate 8 LOW).
/// Truncates for good measure; callers already substr to bound length.
/// Promoted from `ServerImpl::log_safe` (#2542 PR-7, `instruction_routes.cpp`
/// needs it alongside the pre-existing `/api/approvals/:id/{approve,reject}`
/// call sites, which PR-9 later extracted into `approval_routes.cpp` —
/// reconciled at merge time onto this same promotion rather than PR-9's own
/// independently-promoted `log_safe.hpp`) — mirrors the #2557
/// `json_extract.hpp` precedent: a pure, `this`-free static helper with
/// call sites both inside and outside an about-to-be-extracted route
/// cluster is promoted to a shared free function, never duplicated, so the
/// two calling sites can't silently diverge.
[[nodiscard]] inline std::string log_safe(const std::string& s, std::size_t max = 64) {
    std::string out;
    out.reserve(std::min(s.size(), max));
    for (std::size_t i = 0; i < s.size() && i < max; ++i) {
        unsigned char c = static_cast<unsigned char>(s[i]);
        out += (c < 0x20 || c == 0x7f) ? '?' : s[i];
    }
    return out;
}

/// Neutralise a value for safe interpolation into a STRUCTURED `k=v k=v` audit
/// detail string (#1290 Hermes MEDIUM). Audit details are assembled by string
/// concatenation, so a value carrying a space, `=`, `,`, or a control byte (CRLF)
/// could forge an adjacent field (field confusion) or split the audit line. This
/// replaces every control byte and structural delimiter (space, '=', ',') with
/// '_'; the identity is preserved verbatim in its own audit columns
/// (principal/target_id) and rendered safely elsewhere (DB-parameterised,
/// html-escaped, json-escaped). The mapping itself is yuzu::log_token in
/// common/include/yuzu/log_token.hpp, shared with the agent so the rule can't drift; this
/// name stays as the audit-detail spelling for its call sites (server.cpp CA audits,
/// tar_tree_routes.cpp).
[[nodiscard]] inline std::string audit_token(std::string_view s) {
    return ::yuzu::log_token(s); // shared mapping: common/include/yuzu/log_token.hpp
}

/// Percent-decode a URL-encoded string (also handles + as space).
inline std::string url_decode(const std::string& s) {
    auto hexval = [](char c) -> int {
        if (c >= '0' && c <= '9')
            return c - '0';
        if (c >= 'a' && c <= 'f')
            return c - 'a' + 10;
        if (c >= 'A' && c <= 'F')
            return c - 'A' + 10;
        return -1;
    };
    std::string out;
    out.reserve(s.size());
    for (std::size_t i = 0; i < s.size(); ++i) {
        // #1241 UP-12: a malformed escape (`%zz`, or a truncated `%`/`%a` at the
        // end) must NOT throw — std::stoul on non-hex raised std::invalid_argument
        // and 500'd the request. Decode only a well-formed `%HH`; otherwise emit
        // the bytes literally.
        if (s[i] == '%' && i + 2 < s.size()) {
            const int hi = hexval(s[i + 1]);
            const int lo = hexval(s[i + 2]);
            if (hi >= 0 && lo >= 0) {
                out += static_cast<char>((hi << 4) | lo);
                i += 2;
                continue;
            }
            out += s[i]; // malformed → literal '%'
        } else if (s[i] == '+') {
            out += ' ';
        } else {
            out += s[i];
        }
    }
    return out;
}

/// Strip `hostport`'s trailing port ONLY when it is the default for `scheme`.
///
/// `scheme` is the lowercased `"https://"` / `"http://"` prefix, or empty. An
/// EMPTY scheme strips nothing: without a scheme there is no default to be the
/// default OF, and guessing is what the #2641 review caught. The earlier version
/// treated empty as "collapse both 443 and 80", which meant a bare entry
/// `h:443` silently also trusted `http://h` — the exact defect this function was
/// added to fix, surviving on the axis its tests did not cover. A bare entry
/// carrying an explicit default port is now REFUSED by
/// `normalise_trusted_origins` as ambiguous rather than quietly widened here.
///
/// A leading `:` (`":443"`) is left alone: erasing at index 0 would yield an
/// empty entry, and an empty entry matches a host-less source.
[[nodiscard]] inline std::string strip_scheme_default_port(std::string hostport,
                                                           std::string_view scheme) {
    const auto colon = hostport.rfind(':');
    if (colon == std::string::npos || colon == 0)
        return hostport;
    const auto port = hostport.substr(colon + 1);
    const bool is_default =
        (scheme == "https://" && port == "443") || (scheme == "http://" && port == "80");
    if (is_default)
        hostport.erase(colon);
    return hostport;
}

/// Normalise operator-supplied CSRF trusted origins (`--csrf-trusted-origin`,
/// #2537) into the form `origin_is_same_site` compares against. Call ONCE at
/// boot, not per request.
///
/// Each raw token may itself be comma-separated, mirroring `--cert-san`: CLI11
/// hands the token over whole and this function owns the comma semantics, so
/// do NOT add a CLI11 `->delimiter(',')` (that would split twice and mangle
/// entries — the #1271 lesson on the SAN parser).
///
/// Normalisation runs IN THIS ORDER, and the order is load-bearing — an earlier
/// version documented a different one, and following the documented sequence
/// would have re-admitted `NULL` and `null/x` as entries:
///
///   1. split on commas, trim, drop whitespace-only pieces
///   2. ASCII-lowercase
///   3. split the scheme off (so the path strip cannot eat `//`)
///   4. drop any path/query/fragment tail
///   5. refuse a BARE entry carrying an explicit `:443`/`:80` as ambiguous
///   6. strip the default port OF THE ENTRY'S OWN SCHEME
///   7. drop empties, the bare reserved token `null`, and anything with userinfo
///
/// Steps 6 and 7 are in that order on purpose: every guard must see the CANONICAL
/// value. Running them the other way round is how `null:443` and `:443` reached
/// the allowlist as `null` and `""`.
///
/// A scheme is PRESERVED when supplied, because an entry that carries one is
/// compared on scheme as well as host — that is how a configured deployment also
/// closes the weaker half of #2537, where `http://h` satisfied a request to
/// `https://h`.
///
/// The scheme-awareness of the port strip is load-bearing and was missing in the
/// first version (#2641 review). Stripping `443`/`80` unconditionally collapsed
/// `https://h:80` onto `https://h` — which IS `https://h:443` — so an operator
/// who declared one origin silently got a second one trusted. RFC 6454 makes an
/// origin the triple (scheme, host, port) and omits the port from the canonical
/// form only when it is that scheme's default; that is the rule implemented here
/// and, identically, on the request side of `origin_is_same_site`.
///
/// Wildcards are deliberately NOT supported. An entry like `*.example` is kept
/// verbatim and will simply never match, which fails closed. Silently accepting
/// a wildcard in a CSRF allowlist would be the whole control undone by one
/// character.
[[nodiscard]] inline std::vector<std::string>
normalise_trusted_origins(std::span<const std::string> raw) {
    std::vector<std::string> out;
    for (const auto& token : raw) {
        std::size_t pos = 0;
        while (pos <= token.size()) {
            const auto comma = token.find(',', pos);
            auto piece = token.substr(pos, comma == std::string::npos ? std::string::npos
                                                                     : comma - pos);
            pos = (comma == std::string::npos) ? token.size() + 1 : comma + 1;

            const auto first = piece.find_first_not_of(" \t\r\n");
            if (first == std::string::npos)
                continue; // empty / whitespace-only (e.g. a trailing comma)
            const auto last = piece.find_last_not_of(" \t\r\n");
            piece = piece.substr(first, last - first + 1);

            for (auto& c : piece)
                c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));

            // Split scheme off so the path-strip below cannot eat "//".
            std::string scheme;
            if (const auto sep = piece.find("://"); sep != std::string::npos) {
                scheme = piece.substr(0, sep + 3);
                piece.erase(0, sep + 3);
            }
            for (char delim : {'/', '?', '#'}) {
                if (const auto idx = piece.find(delim); idx != std::string::npos)
                    piece.erase(idx);
            }
            // A BARE entry carrying an explicit default port is AMBIGUOUS and is
            // refused. `h:443` cannot say which scheme it means, and the previous
            // answer — collapse it to `h` and match either scheme — reproduced
            // exactly the defect this whole function exists to prevent: declaring
            // one origin silently trusted a second. Refusing is the only honest
            // option, because both alternatives are wrong (guessing https is a
            // guess; keeping the port makes it unmatchable, since the request side
            // canonicalises `https://h:443` to `h`). The operator writes
            // `https://h` or `http://h` and the ambiguity disappears.
            // `main.cpp` reports supplied-vs-accepted counts at boot so a refusal
            // is visible rather than silent.
            if (scheme.empty()) {
                if (const auto colon = piece.rfind(':');
                    colon != std::string::npos && colon != 0) {
                    const auto port = piece.substr(colon + 1);
                    if (port == "443" || port == "80")
                        continue;
                }
            }

            piece = strip_scheme_default_port(std::move(piece), scheme);

            // Both guards below run on the CANONICAL form, deliberately. Running
            // them earlier is how `null:443` and `:443` slipped past: each guard
            // inspected an intermediate value that the port strip then turned
            // into the very thing being guarded against (#2641 governance).
            // Empty, or host-less (`:443`). A leading colon means the host part
            // is absent, which is not an origin: `strip_scheme_default_port`
            // deliberately will not erase at index 0 (that would manufacture an
            // empty entry), so the check has to name both shapes.
            if (piece.empty() || piece.front() == ':')
                continue;
            // `null` is the RESERVED serialisation of an opaque origin — what a
            // sandboxed iframe, a cross-origin redirected POST and a `file://`
            // document all send. It is not a host, so an entry of `null` would
            // admit every one of them at once. Refuse it rather than hand an
            // operator that foot-gun (#2641 review).
            //
            // Gated on a BARE entry: the opaque serialisation is the token alone,
            // never scheme-qualified. `https://null` is a real (if unfortunate)
            // internal hostname and is kept — refusing it was a false refusal.
            // A host that merely CONTAINS the token (`null.example`) is kept too.
            if (scheme.empty() && piece == "null")
                continue;
            // Userinfo is rejected on the REQUEST side and must be rejected here
            // too, or the boot log advertises an entry that can never match.
            if (piece.find('@') != std::string::npos)
                continue;
            out.push_back(scheme + piece);
        }
    }
    return out;
}

/// CSRF same-site check (shared helper — #1241 H-1). Returns true when the
/// request is safe to act on: a non-browser client (no Origin AND no Referer —
/// curl/automation post without them) OR an Origin/Referer whose host matches
/// Host. Returns false only for a cross-site browser POST. Pure (no I/O) so any
/// cookie-authenticated POST handler, in any TU, can gate a destructive op the
/// same way; the caller emits the 403 + `csrf.denied` audit. Default ports
/// (80/443) are stripped for comparison; userinfo in Origin/Referer (RFC 6454
/// forbids it) fails the check.
///
/// `trusted_origins` (#2537) is an operator-declared allowlist of the external
/// origins the dashboard is served on, normalised by `normalise_trusted_origins`
/// at boot. It exists because a reverse proxy that rewrites `Host` makes the
/// browser's `Origin` and the server's `Host` legitimately differ, which 403'd
/// every gated dashboard action behind nginx/Envoy/ALB.
///
/// NOTE what this deliberately does NOT do: it never reads `X-Forwarded-Host`
/// or any other request header to decide what the external host is. The trust
/// anchor is a boot-time config value, which an attacker cannot set. Trusting a
/// forwarded header instead — even gated on a peer-address CIDR — fails OPEN
/// when the CIDR is too wide or the port is reachable off-proxy: the dashboard
/// keeps working while the CSRF control is silently dead. On the container
/// networks the reference composes use, "inside the CIDR" is usually every
/// sibling container.
///
/// The parameter defaults to empty ON PURPOSE, and the default is safe: a
/// caller that forgets it gets exactly the pre-#2537 behaviour — same-host only,
/// which refuses a proxied browser POST. Forgetting degrades to fail-closed, it
/// never opens a hole.
inline bool origin_is_same_site(std::string_view host, std::string_view origin,
                                std::string_view referer,
                                std::span<const std::string> trusted_origins = {}) {
    auto strip_default_port = [](std::string h) -> std::string {
        auto colon = h.rfind(':');
        if (colon == std::string::npos)
            return h;
        auto port = h.substr(colon + 1);
        if (port == "443" || port == "80")
            h.erase(colon);
        return h;
    };
    // Returns host[:port] with the port INTACT. The two comparisons below need
    // different port rules, so neither can be baked in here: the same-host check
    // keeps the loose pre-#2537 strip, while the allowlist check is scheme-aware
    // per RFC 6454 (#2641 review).
    auto extract_host = [](std::string url) -> std::optional<std::string> {
        auto p = url.find("://");
        if (p != std::string::npos)
            url.erase(0, p + 3);
        for (char delim : {'/', '?', '#'}) {
            auto idx = url.find(delim);
            if (idx != std::string::npos)
                url.erase(idx);
        }
        if (url.find('@') != std::string::npos)
            return std::nullopt; // userinfo → malformed, fail closed
        return url;
    };
    // Scheme of the request origin, lowercased, "" when absent. Only consulted
    // for allowlist entries that themselves carry a scheme.
    auto extract_scheme = [](std::string_view url) -> std::string {
        const auto sep = url.find("://");
        if (sep == std::string_view::npos)
            return {};
        std::string s(url.substr(0, sep + 3));
        for (auto& c : s)
            c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
        return s;
    };
    if (origin.empty() && referer.empty())
        return true; // non-browser client (curl/automation)
    const std::string_view source = origin.empty() ? referer : origin;
    auto extracted = extract_host(std::string(source));
    if (!extracted)
        return false; // userinfo → fail closed, before any allowlist consideration
    // Same-host: the LOOSE strip on both sides, byte-for-byte the pre-#2537
    // behaviour. The Host header carries no scheme, so there is no default to be
    // aware of here, and tightening it would change a path this issue never
    // touched.
    if (strip_default_port(*extracted) == strip_default_port(std::string(host)))
        return true;

    // Allowlist. Compare lowercased, since a config value's case is the
    // operator's typing and a silent no-match there is an opaque 403.
    // The port is canonicalised against the REQUEST's own scheme, matching how
    // `normalise_trusted_origins` canonicalised the entries — so `https://h:80`
    // and `https://h` stay distinct on both sides rather than collapsing into
    // one over-broad entry (#2641 review).
    const std::string want_scheme = extract_scheme(source);
    std::string want = strip_scheme_default_port(std::move(*extracted), want_scheme);
    for (auto& c : want)
        c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
    // Defence in depth, and deliberately not delegated. `normalise_trusted_origins`
    // drops every entry that could match an empty host, but that is a DIFFERENT
    // function — the gate's safety should not rest on an invariant enforced
    // elsewhere, especially now that five call sites supply the span. An empty
    // `want` means a host-less source, which is never a same-site claim.
    if (want.empty() || want.front() == ':')
        return false;
    for (const auto& entry : trusted_origins) {
        if (const auto sep = entry.find("://"); sep != std::string::npos) {
            // Scheme-qualified entry: BOTH must match, so https:// in config
            // refuses an http:// Origin for the same host.
            if (entry.compare(0, sep + 3, want_scheme) == 0 && entry.compare(sep + 3, std::string::npos, want) == 0)
                return true;
        } else if (entry == want) {
            return true; // bare host entry: host-only match
        }
    }
    return false;
}

/// The MCP transport body-cap decision for the server's pre-routing handler
/// (#2437) — extracted from `server.cpp`'s `set_pre_routing_handler` lambda
/// for exactly the reason `is_login_exempt_path` below was: so the decision
/// has direct unit coverage instead of being reachable only by booting a real
/// server. Pure and httplib-free by design; the caller supplies the declared
/// length (`Content-Length`, 0 when the header is absent) and the cap.
///
/// `content_length == 0` returns false ON PURPOSE: this predicate answers
/// *size* only. A chunked or header-less body is not unsized-but-fine — it is
/// refused separately by `mcp_body_unmeasurable` below (411). A caller MUST
/// consult both; consulting only this one reopens the bypass.
///
/// The comparison is strictly greater-than: a request of EXACTLY `cap` bytes
/// is admitted, matching the "<= cap" contract the docs publish.
///
/// Caller contract: consult this AFTER the rate limiter — an oversized-body
/// flood should be throttled like any other traffic, and unlike the
/// on-behalf-of guard there is no misconfiguration it would mask by answering
/// first. It may sit before auth: it discloses only a documented transport
/// limit, nothing argument-shaped.
/// Path scoping for the MCP body cap. `/mcp/v1` (no trailing slash) is
/// included deliberately: the auth chokepoint matches `/mcp/` so that form is
/// authenticated and reaches httplib's body read before 404-ing, and a cap
/// that missed it would be evaded by deleting one character (governance
/// Gate 4 unhappy-path UP-5).
[[nodiscard]] inline bool is_mcp_path(std::string_view path) noexcept {
    // Deliberately `/mcp/` and not `/mcp/v1/`: the auth chokepoint and the
    // engine quota gate both scope on `/mcp/`, so anything under it is
    // authenticated and reaches httplib's body read. Scoping the cap more
    // narrowly than the surface it protects means `/mcp/v1` or `/mcp/v1x` is
    // authenticated-but-uncapped — the same one-character evasion this
    // function exists to prevent (governance Gate 8 security LOW-4), and it
    // would leave a future /mcp/v2/ uncapped by default rather than capped.
    return path.starts_with("/mcp/");
}

[[nodiscard]] inline bool mcp_body_exceeds_cap(std::string_view path,
                                               std::uint64_t content_length,
                                               std::uint64_t cap) noexcept {
    return is_mcp_path(path) && content_length > cap;
}

/// True when `content_encoding` is present and is anything other than
/// `identity` (case-insensitive value match, matching how every library that
/// reads the header compares it, including httplib's own). This build
/// compiles with `CPPHTTPLIB_BROTLI_SUPPORT`, and httplib transparently
/// decompresses and then enforces only its GLOBAL limit on the DECOMPRESSED
/// size — so a sub-cap compressed body can expand to ~100 MB before anything
/// downstream sees it. `Content-Length` measures the compressed bytes and is
/// therefore not a bound on what gets buffered. Split out from
/// `body_unmeasurable` below (#2407-D4) because a non-identity encoding is
/// refused unconditionally on EVERY route class, unlike chunked/undeclared
/// framing, which is refused only for a class that opts into
/// `requires_measurable`.
[[nodiscard]] inline bool
has_non_identity_content_encoding(std::string_view content_encoding) noexcept {
    if (content_encoding.empty())
        return false;
    const bool identity =
        content_encoding.size() == 8 &&
        std::equal(content_encoding.begin(), content_encoding.end(), "identity",
                   [](char a, char b) {
                       return (a | 0x20) == (b | 0x20);
                   });
    return !identity;
}

/// The single Content-Length-for-the-body-cap-gate computation (#2407 R1/R2
/// hardening, 2026-08-07). `Req` is a TEMPLATE PARAMETER, not a concrete
/// `httplib::Request`, specifically so this file stays httplib-free at the
/// header level (see `is_mcp_path`'s doc comment above for why that
/// matters) while still being the literal, single implementation both real
/// callers share — in practice always instantiated with `httplib::Request`,
/// which already exposes the exact public surface this needs
/// (`get_header_value_u64`).
///
/// MUST delegate to httplib's OWN accessor rather than re-implement the
/// parse. A prior round hand-rolled this with `std::from_chars` in
/// server.cpp's pre-routing handler, reasoning (in a since-deleted comment)
/// that a non-numeric value "reads as 0, matching httplib's own
/// get_header_value_u64" — true for a non-numeric value, FALSE for an
/// all-digit value above 2^64-1: `std::from_chars` reports
/// `std::errc::result_out_of_range` for that input and the old code folded
/// that to `content_length = 0` ("no header, don't cap"), while httplib's
/// own `is_numeric()` + `strtoull()` parser (httplib.h:2769-2789) accepts
/// the same digits and returns `SIZE_MAX` — the value it then ALSO uses to
/// decide what it buffers (httplib.h:7057-7061). One unauthenticated
/// `Content-Length: 99999999999999999999999` (or any all-digit value above
/// 2^64-1) defeated every class's cap, including /mcp/'s and the 256 KiB
/// ca_import_chain/scim classes (governance Gate 8 CRITICAL). Calling
/// httplib's accessor from this ONE function — used by both server.cpp's
/// production gate and this file's own test fixtures
/// (`test_body_cap_policy.cpp`'s `UnifiedBodyCapTestServer`,
/// `test_mcp_body_cap.cpp`'s `BodyCapTestServer`) — makes that divergence
/// structurally impossible rather than something to keep re-verifying by
/// hand every time either call site is touched. A genuinely malformed
/// (non-numeric / negative / whitespace-padded) `Content-Length` still
/// reads as 0 here — that is fine, NOT a re-opened gap: httplib's OWN
/// reader (the `is_invalid_value` branch, httplib.h:7057-7063) answers 400
/// and refuses to read the body at all for that case, so no handler is
/// ever reached regardless of what this gate alone decides.
template <typename Req>
[[nodiscard]] inline std::uint64_t content_length_for_body_cap(const Req& req) noexcept {
    return req.get_header_value_u64("Content-Length", 0);
}

/// True when a request body's SIZE cannot be measured before reading it:
/// chunked (or any other non-empty) `Transfer-Encoding`, or a POST/PUT/PATCH
/// with no declared `Content-Length`. `Content-Encoding` is judged separately
/// by `has_non_identity_content_encoding` above — a caller deciding whether
/// to refuse an MCP body historically OR'd the two together (see
/// `mcp_body_unmeasurable` below); #2407-D4 needs to apply the encoding rule
/// to every class unconditionally while keeping this framing rule scoped to
/// classes that opt into `requires_measurable`, so the two are no longer one
/// predicate.
///
/// THE DESIGN RULE, learned the hard way: do NOT re-implement httplib's
/// header parsing and hope the two agree. The first attempt tested
/// `Transfer-Encoding` with a case-SENSITIVE `find("chunked")` while httplib
/// decides with `case_ignore::equal(...)` (httplib.h:6967) — so
/// `Transfer-Encoding: Chunked` passed this check as a measurable body and was
/// then read as chunked, bounded only by the 100 MB global default. One
/// capital letter defeated the whole cap. The substring test was also wrong in
/// the other direction: httplib compares the value for EQUALITY, so
/// `identity, chunked` is not chunked to httplib while `find` matched it. So
/// this refuses ANY non-empty `Transfer-Encoding`, on ANY method — not just
/// chunked and not just POST/PUT/PATCH, since httplib's `expect_content`
/// treats chunking independently of the method, so a chunked
/// GET/DELETE/OPTIONS reaches the same reader.
///
/// DELETE is DELIBERATELY EXCLUDED from the no-`Content-Length` rule, and the
/// reasoning is worth keeping because two reviewers disagreed on it.
/// `expect_content` (httplib.h:8330) is true for DELETE too, so a DELETE
/// carrying an UNDECLARED body is admitted here — today harmlessly, because
/// with `CPPHTTPLIB_SSL_ENABLED` that path returns without reading, which is
/// an accidental dependency on a build flag rather than a bound. Closing it
/// by requiring `Content-Length` on DELETE would break MCP session teardown:
/// `DELETE /mcp/v1/` carries no body and many clients (cpp-httplib's own
/// included) omit `Content-Length: 0` entirely. A live compatibility break on
/// a shipped route is the worse trade against a hazard that is presently
/// unreachable and bounded at 100 MB if it were not. Tracked as a follow-up;
/// a DELETE that carries actual chunked framing IS refused by the rule above,
/// which applies to every method.
///
/// JSON-RPC clients send an identity-encoded body with a Content-Length, so
/// none of this costs a conforming client anything. It is NOT free in general:
/// HTTP permits chunked request bodies, and a proxy or streaming stack that
/// re-frames requests will now be refused. That is a deliberate trade.
[[nodiscard]] inline bool body_unmeasurable(std::string_view method, bool has_content_length,
                                            std::string_view transfer_encoding) noexcept {
    if (!transfer_encoding.empty())
        return true;
    if ((method == "POST" || method == "PUT" || method == "PATCH") && !has_content_length)
        return true;
    return false;
}

/// True when `Content-Length` is the number of body bytes httplib will
/// actually read, so a size check against it is meaningful.
///
/// SEPARATE FROM `body_unmeasurable` ON PURPOSE — do not merge them. They
/// answer different questions and a caller needs both:
///
///   * `body_unmeasurable` = "is this framing something we refuse outright?"
///     Deliberately BROAD (#2437): any non-empty `Transfer-Encoding` counts,
///     because a class with `requires_measurable` refuses anything it is not
///     the sole interpreter of. Narrowing it would LOOSEN `/mcp/`, which
///     today 411s a `Transfer-Encoding: gzip` that this predicate calls
///     perfectly measurable.
///   * this one = "may we compare `Content-Length` against the cap?" Narrow,
///     and it must match httplib exactly.
///
/// Conflating them was a live unauthenticated bypass. The caller computed
/// `oversize = !unmeasurable && content_length > cap`, so the BROAD rule
/// suppressed the size check: `Transfer-Encoding: identity` plus a
/// `Content-Length` of 8 MiB was admitted on every class whose
/// `requires_measurable` is false — 24 of 25, including the rate-limit-exempt
/// health probes — because httplib honours an exact `chunked` and NOTHING
/// else, falling through to `Content-Length` and reading every byte. The gate
/// discarded a length httplib was about to act on. Verified on a raw socket
/// against the real vendored httplib.
///
/// `is_chunked` MUST come from httplib's own `is_chunked_transfer_encoding`,
/// never from a local reading of the header. Third time this change was bitten
/// by that same root cause — `Content-Encoding` and the `Content-Length`
/// overflow parse were the first two — and all three were fixed the same way:
/// ask httplib instead of re-deciding.
[[nodiscard]] inline bool content_length_is_authoritative(bool has_content_length,
                                                          bool is_chunked) noexcept {
    return has_content_length && !is_chunked;
}

/// True when an MCP request carries a body this server cannot size before
/// reading it, and must therefore refuse (411) rather than admit. Composed
/// from `has_non_identity_content_encoding` + `body_unmeasurable` above —
/// MCP opts every one of those reasons into a hard refusal (its `Content-
/// Length` client contract already requires a measurable body, see
/// `body_cap_policy.hpp`'s `requires_measurable` rationale), so the
/// distinction the two split predicates exist for collapses back to one
/// question for this caller specifically.
[[nodiscard]] inline bool mcp_body_unmeasurable(std::string_view path, std::string_view method,
                                                bool has_content_length,
                                                std::string_view transfer_encoding,
                                                std::string_view content_encoding) noexcept {
    if (!is_mcp_path(path))
        return false;
    return has_non_identity_content_encoding(content_encoding) ||
           body_unmeasurable(method, has_content_length, transfer_encoding);
}

/// The unauthenticated-allowlist decision for the server's pre-routing
/// handler (H1, 2026-07-08 SCIM review) — extracted from `server.cpp`'s
/// `set_pre_routing_handler` lambda so the login/SSO/health/PKI/SCIM
/// exemption list has direct unit coverage instead of only being exercised
/// by booting a real server. Every existing exempt path is unchanged; the
/// only addition is the `/scim/v2/` prefix (see below).
///
/// Caller contract: this MUST be consulted AFTER the rate limiter and
/// (once it lands) any on-behalf-of/ADR-1005 rejection in the pre-routing
/// handler, never wired in as an earlier early-return — those controls
/// must stay in effect for every path this allows through unauthenticated.
/// Returns true iff `path` should skip session/bearer resolution entirely.
inline bool is_login_exempt_path(std::string_view path) {
    return path == "/login" || path == "/login/mfa" || path == "/login/mfa/enroll" ||
           path == "/health" || path == "/api/health" || path == "/auth/oidc/start" ||
           path == "/auth/callback" ||
           // #2057: /api/v1/openapi.json used to be listed here as
           // unauthenticated-by-design. It no longer is — the route now
           // gates `Infrastructure:Read` (rest_api_v1.cpp), matching its
           // MCP twin `yuzu://openapi`. Removed so the pre-routing
           // chokepoint resolves a session for it like every other
           // /api/v1/* route; the route's own perm_fn is the authority,
           // not this exemption list.
           path == "/auth/saml/start" || path == "/saml/acs" ||
           // PKI PR4: the CA root cert + CRL are public by design — clients
           // and browsers need them to establish trust / check revocation
           // before they have any session. Exact-match only; /api/v1/ca/issued
           // and /api/v1/ca/revoke remain Security-gated below.
           path == "/api/v1/ca/root" || path == "/api/v1/ca/crl" ||
           path.starts_with("/static/") ||
           // H1 (2026-07-08 SCIM review): /scim/v2/* authenticates itself via
           // a static Bearer token validated against ScimStore
           // (scim_routes.cpp `require_bearer`) — there is no session cookie
           // on this surface at all. Without this exemption every IdP call
           // (even one carrying a valid SCIM bearer token) was 302-redirected
           // to /login before ScimRoutes ever saw the request — 0 SCIM audit
           // rows, the feature never ran. Prefix match: every /scim/v2/*
           // route (Users CRUD + the discovery documents) needs it.
           path.starts_with("/scim/v2/");
}

/// Extract a value from a URL-encoded form body by key name.
inline std::string extract_form_value(const std::string& body, const std::string& key) {
    auto needle = key + "=";
    auto pos = body.find(needle);
    if (pos == std::string::npos)
        return {};
    pos += needle.size();
    auto end = body.find('&', pos);
    auto raw = body.substr(pos, end == std::string::npos ? end : end - pos);
    return url_decode(raw);
}

/// Was `key` PRESENT in the URL-encoded form body at all — even with an empty
/// value?
///
/// `extract_form_value` CANNOT answer this: it returns `""` for an absent key
/// and for a supplied-but-empty `key=` alike. That erasure is precisely the
/// defect `dispatch_target_shape.hpp` names — "an OMITTED targeting argument
/// means the whole fleet; a SUPPLIED one that resolves to nothing is an ERROR.
/// The two are not the same request and must never collapse into each other" —
/// in its form-encoded spelling, the twin of `extract_json_string_array`'s
/// erasure on the JSON routes.
///
/// Matches only at a key boundary (start of body or just after `&`), so a
/// `myscope=` field is never mistaken for `scope=`.
inline bool form_value_supplied(const std::string& body, const std::string& key) {
    const auto needle = key + "=";
    for (std::string::size_type pos = body.find(needle); pos != std::string::npos;
         pos = body.find(needle, pos + 1)) {
        if (pos == 0 || body[pos - 1] == '&')
            return true;
    }
    return false;
}

/// Extract plugin name from a command_id string (format: "plugin-timestamp").
inline std::string extract_plugin(const std::string& command_id) {
    auto dash = command_id.find('-');
    if (dash != std::string::npos) {
        return command_id.substr(0, dash);
    }
    return command_id;
}

// ============================================================================
// Time formatting and now-epoch — used by the executions surface and the TAR
// dashboard. Both surfaces standardise on UTC; relative time goes in the cell
// text, ISO-8601 UTC goes in the title= attribute for forensic copy/paste.
// Mixing local time anywhere is a known failure mode (BST/UTC drift).
// ============================================================================

/// Current epoch seconds (UTC). Equivalent to `std::time(nullptr)` but uses
/// `std::chrono` so it compiles cleanly on every platform.
inline int64_t now_epoch_seconds() {
    return std::chrono::duration_cast<std::chrono::seconds>(
               std::chrono::system_clock::now().time_since_epoch())
        .count();
}

/// Format epoch seconds as RFC 3339 / ISO 8601 in UTC: "YYYY-MM-DDTHH:MM:SSZ".
/// Used in `title=` attributes so operators can copy a precise timestamp.
/// Returns "—" for non-positive input (sentinel "never").
inline std::string format_iso_utc(int64_t epoch_secs) {
    if (epoch_secs <= 0) return "—";
    std::time_t t = static_cast<std::time_t>(epoch_secs);
    std::tm tm_val{};
#ifdef _WIN32
    gmtime_s(&tm_val, &t);
#else
    gmtime_r(&t, &tm_val);
#endif
    return std::format("{:04}-{:02}-{:02}T{:02}:{:02}:{:02}Z",
                        tm_val.tm_year + 1900, tm_val.tm_mon + 1, tm_val.tm_mday,
                        tm_val.tm_hour, tm_val.tm_min, tm_val.tm_sec);
}

/// Format a delta as a coarse "Xs/Xm/Xh/Xd ago" string. Caller passes both
/// epochs so the function is pure and easy to test (no clock read). Argument
/// order is (then, now) to match the existing `format_age` helper in
/// dashboard_routes.cpp — eases a future dedup. `epoch_then <= 0` returns
/// "—" (never-fired sentinel).
inline std::string format_relative_time(int64_t epoch_then, int64_t epoch_now) {
    if (epoch_then <= 0) return "—";
    int64_t delta = epoch_now - epoch_then;
    if (delta < 0) delta = 0;
    if (delta < 60)    return std::format("{}s ago", delta);
    if (delta < 3600)  return std::format("{}m ago", delta / 60);
    if (delta < 86400) return std::format("{}h {}m ago", delta / 3600, (delta % 3600) / 60);
    int64_t days = delta / 86400;
    int64_t hours = (delta % 86400) / 3600;
    if (days < 30) return std::format("{}d {}h ago", days, hours);
    return std::format("{}d ago", days);
}

// ============================================================================
// UTF-8 truncation — first-error preview in the executions list shows up to
// 80 chars. Truncating mid-codepoint produces invalid UTF-8 that breaks the
// browser's title= rendering; this walks back to the previous codepoint
// boundary if needed.
// ============================================================================

/// Truncate `s` to at most `max_chars` *bytes*, walking back to the previous
/// UTF-8 codepoint boundary if the cut would tear a multi-byte sequence.
/// Appends `"…"` (3 bytes UTF-8) when truncation occurred. Returns the input
/// unchanged if `s.size() <= max_chars`.
inline std::string truncate_utf8(std::string_view s, std::size_t max_chars) {
    if (s.size() <= max_chars) return std::string(s);
    std::size_t cut = max_chars;
    while (cut > 0) {
        unsigned char c = static_cast<unsigned char>(s[cut]);
        // 10xxxxxx is a continuation byte — walk back until we land on a
        // codepoint start (0xxxxxxx or 11xxxxxx).
        if ((c & 0xC0) != 0x80) break;
        --cut;
    }
    std::string out(s.substr(0, cut));
    out += "\xE2\x80\xA6"; // U+2026 HORIZONTAL ELLIPSIS, UTF-8
    return out;
}

// ============================================================================
// Status sparkbar — 4-segment stacked bar showing fan-out by agent status.
// Encoding: count → length, status → hue. Renders as inline SVG so the list
// view can ship it without a JS chart library and so screen readers can
// announce a single role="img" with a summary aria-label.
//
// Width is fixed at 120px so all rows align. Heights at 10px so the bar is
// dense but still legible. Buckets with count 0 emit no <rect> (avoids a
// 0-width artifact in some browsers). When `total == 0` (no agents matched
// scope) the bar renders a single hatched/empty cell so the row doesn't look
// like a successful zero-agent run.
//
// Color tokens: Cisco Momentum success/error/stable/text-tertiary. Theme-
// agnostic — light and dark mode both read the same SVG via CSS vars.
// ============================================================================

/// Inline SVG, ~120×10px, rendering a 4-segment stacked status sparkbar.
/// Caller is responsible for any wrapping HTML.
inline std::string render_status_sparkbar(int succeeded, int failed,
                                          int running, int pending) {
    constexpr int kWidth = 120;
    constexpr int kHeight = 10;
    const int total = succeeded + failed + running + pending;

    auto label = total > 0
                     ? std::format("{} succeeded, {} failed, {} running, {} pending of {}",
                                   succeeded, failed, running, pending, total)
                     : std::string{"no agents matched scope"};

    std::string out;
    out.reserve(512);
    out += std::format(
        "<svg class=\"status-sparkbar\" width=\"{}\" height=\"{}\" "
        "viewBox=\"0 0 {} {}\" role=\"img\" aria-label=\"{}\">",
        kWidth, kHeight, kWidth, kHeight, label);

    if (total <= 0) {
        // Hatched empty state — no agents matched scope.
        out += std::format(
            "<defs><pattern id=\"empty-hatch\" patternUnits=\"userSpaceOnUse\" "
            "width=\"4\" height=\"4\" patternTransform=\"rotate(45)\">"
            "<line x1=\"0\" y1=\"0\" x2=\"0\" y2=\"4\" "
            "stroke=\"var(--mds-color-theme-text-tertiary)\" "
            "stroke-width=\"1\" aria-hidden=\"true\" /></pattern></defs>"
            "<rect x=\"0\" y=\"0\" width=\"{}\" height=\"{}\" "
            "fill=\"url(#empty-hatch)\" aria-hidden=\"true\" />",
            kWidth, kHeight);
        out += "</svg>";
        return out;
    }

    // Compute segment widths in fixed-point so the four rounded values sum
    // exactly to kWidth — the last non-zero segment absorbs rounding error.
    // Two-arg `var(...)` fallbacks ensure the sparkbar still renders a
    // legible color when the design-token CSS fails to load (UP-13). The
    // legacy `--green` / `--red` / `--accent` / `--muted` fallbacks are
    // declared in yuzu.css's :root and are unlikely to vanish together.
    struct Seg { int count; const char* fill; };
    Seg segs[4] = {
        {succeeded, "var(--mds-color-bg-success-emphasis,var(--green))"},
        {failed,    "var(--mds-color-theme-indicator-error,var(--red))"},
        {running,   "var(--mds-color-theme-indicator-stable,var(--accent))"},
        {pending,   "var(--mds-color-theme-text-tertiary,var(--muted))"},
    };
    int widths[4] = {0, 0, 0, 0};
    int last_nonzero = -1;
    int allocated = 0;
    for (int i = 0; i < 4; ++i) {
        if (segs[i].count > 0) {
            widths[i] = static_cast<int>(
                static_cast<int64_t>(segs[i].count) * kWidth / total);
            allocated += widths[i];
            last_nonzero = i;
        }
    }
    if (last_nonzero >= 0 && allocated < kWidth) {
        widths[last_nonzero] += (kWidth - allocated);
    }

    int x = 0;
    for (int i = 0; i < 4; ++i) {
        if (segs[i].count <= 0) continue;
        out += std::format(
            "<rect x=\"{}\" y=\"0\" width=\"{}\" height=\"{}\" fill=\"{}\" "
            "aria-hidden=\"true\" />",
            x, widths[i], kHeight, segs[i].fill);
        x += widths[i];
    }
    out += "</svg>";
    return out;
}

// ============================================================================
// Duration bar — single-axis horizontal bar inline in the per-agent table.
// Scaled to the slowest agent in the current execution so the eye picks out
// tail-latency outliers. Server-rendered as a div with a width percentage so
// no JS chart library is needed.
// ============================================================================

/// Render a duration bar as an inline `<div>`. `duration_ms` and
/// `max_duration_ms` are agent timing in this execution; `status_class` is
/// one of "completed" / "failed" / "running" / "pending" and selects the hue.
inline std::string render_duration_bar_html(int64_t duration_ms,
                                            int64_t max_duration_ms,
                                            std::string_view status_class) {
    if (duration_ms < 0) duration_ms = 0;
    int pct = 0;
    if (max_duration_ms > 0) {
        int64_t scaled = duration_ms * 100 / max_duration_ms;
        if (scaled > 100) scaled = 100;
        pct = static_cast<int>(scaled);
    }
    return std::format(
        "<div class=\"duration-bar duration-bar--{}\" "
        "style=\"width:{}%\" role=\"img\" aria-label=\"{} ms\"></div>",
        status_class, pct, duration_ms);
}

} // namespace yuzu::server
