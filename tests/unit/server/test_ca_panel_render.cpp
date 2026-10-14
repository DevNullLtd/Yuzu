/**
 * @file test_ca_panel_render.cpp
 * @brief Pure goldens for the System > Certificates and secrets CA panels
 *        (ca_panel_render.{hpp,cpp}): every state, every escape, the Expired rule, the
 *        purpose-aware revoke wording. No store, no clock, no Postgres.
 */

#include "ca_panel_render.hpp"

#include <catch2/catch_test_macros.hpp>
#include <catch2/matchers/catch_matchers_string.hpp>

#include <string>

using namespace yuzu::server::ca_panel;
using Catch::Matchers::ContainsSubstring;

namespace {

constexpr std::int64_t kNow = 1'800'000'000; // 2027-01-15, fixed: the renderer reads no clock

Model ready() {
    Model m;
    m.availability = Availability::Ready;
    m.now = kNow;
    m.root = {.algo = "EcP384",
              .fingerprint_sha256 = "29:72:BB:04:4D:96:DF:28:71:BA:03:4C:95:DE:27:70",
              .not_after = kNow + 86400 * 365,
              .subordinate = false};
    m.crl = {.present = true,
             .version = 14,
             .published_at = kNow - 3600,
             .next_update = kNow + 86400,
             .revoked_count = 2,
             .state = CrlState::Current};
    return m;
}

IssuedRow row(const std::string& serial, const std::string& purpose,
              std::int64_t not_after = kNow + 86400) {
    return {.serial_hex = serial, .subject = "subj-" + serial, .purpose = purpose,
            .not_after = not_after, .revoked = false};
}

bool has(const std::string& h, const std::string& needle) {
    return h.find(needle) != std::string::npos;
}

} // namespace

TEST_CASE("ca panel: unavailable, store error and no-root are single fixed sentences",
          "[ca_panel][pki][ui]") {
    Model m;
    m.availability = Availability::Unavailable;
    CHECK_THAT(render(m), ContainsSubstring("Certificate authority unavailable."));
    m.availability = Availability::StoreError;
    CHECK_THAT(render(m), ContainsSubstring("Certificate authority store error."));
    m.availability = Availability::NoRoot;
    const auto h = render(m);
    CHECK_THAT(h, ContainsSubstring("No internal CA on this install"));
    // No controls without a root: nothing to import into, nothing to download.
    CHECK_FALSE(has(h, "import-chain"));
    CHECK_FALSE(has(h, "/api/v1/ca/root"));
}

TEST_CASE("ca panel: built-in and subordinate trust mode, algorithm, validity, fingerprint",
          "[ca_panel][pki][ui]") {
    auto m = ready();
    auto h = render(m);
    CHECK_THAT(h, ContainsSubstring("Built-in (self-signed root)"));
    CHECK_THAT(h, ContainsSubstring("EcP384"));
    CHECK_THAT(h, ContainsSubstring(m.root.fingerprint_sha256));
    CHECK_THAT(h, ContainsSubstring("Subordinate this CA to your enterprise root"));
    m.root.subordinate = true;
    h = render(m);
    CHECK_THAT(h, ContainsSubstring("Subordinate (enterprise-rooted)"));
    CHECK_THAT(h, ContainsSubstring("Enterprise subordination"));
}

TEST_CASE("ca panel: the CA download link carries a cache key from the fingerprint",
          "[ca_panel][pki][ui]") {
    // The public root is cached for a day; without the key an import is followed by a
    // download of the pre-import file.
    const auto h = render(ready());
    CHECK_THAT(h, ContainsSubstring("href=\"/api/v1/ca/root?v=2972bb044d96\""));
}

TEST_CASE("ca panel: an expired root is flagged, a valid one is not", "[ca_panel][pki][ui]") {
    auto m = ready();
    CHECK_FALSE(has(render(m), "Expired"));
    m.root.not_after = kNow - 1;
    CHECK_THAT(render(m), ContainsSubstring(">Expired</span>"));
    // not_after == 0 is "unset", never "expired".
    m.root.not_after = 0;
    CHECK_FALSE(has(render(m), "Expired"));
}

TEST_CASE("ca panel: revocation panel states", "[ca_panel][pki][ui]") {
    auto m = ready();
    auto h = render(m);
    CHECK_THAT(h, ContainsSubstring(">Current</span>"));
    CHECK_THAT(h, ContainsSubstring("version 14"));
    CHECK_THAT(h, ContainsSubstring("href=\"/api/v1/ca/crl\""));

    m.crl.state = CrlState::OutOfDate;
    CHECK_THAT(render(m), ContainsSubstring("Out of date: a revocation is not on the published "
                                           "list"));

    // A pre-v3 row has no count: "Not recorded", never 0, and never "Current".
    m.crl.revoked_count.reset();
    m.crl.state = CrlState::Unconfirmed;
    h = render(m);
    CHECK_THAT(h, ContainsSubstring("Not recorded"));
    CHECK_THAT(h, ContainsSubstring("Not confirmed current"));
    CHECK_FALSE(has(h, ">0</b>"));
}

TEST_CASE("ca panel: no CRL published omits the download link", "[ca_panel][pki][ui]") {
    // A link to a CRL that does not exist navigates to a 503 JSON body.
    auto m = ready();
    m.crl = {};
    const auto h = render(m);
    CHECK_THAT(h, ContainsSubstring("None published, or the store could not be read"));
    CHECK_THAT(h, ContainsSubstring("Not yet published"));
    CHECK_FALSE(has(h, "href=\"/api/v1/ca/crl\""));
}

TEST_CASE("ca panel: issued table statuses, Expired rule and revoke availability",
          "[ca_panel][pki][ui]") {
    auto m = ready();
    m.issued.push_back(row("A1", "agent"));
    auto revoked = row("B2", "agent");
    revoked.revoked = true;
    m.issued.push_back(revoked);
    m.issued.push_back(row("C3", "agent", kNow - 1)); // lapsed, not revoked
    m.issued.push_back(row("D4", "code-signing", 0)); // unset not_after is not expired
    const auto h = render(m);
    CHECK_THAT(h, ContainsSubstring(">Active</span>"));
    CHECK_THAT(h, ContainsSubstring(">Revoked</span>"));
    CHECK_THAT(h, ContainsSubstring(">Expired</span>"));
    // Revoke is offered on Active and Expired rows, never on Revoked.
    CHECK(h.find("name=\"serial_hex\" value=\"B2\"") == std::string::npos);
    CHECK_THAT(h, ContainsSubstring("name=\"serial_hex\" value=\"A1\""));
    CHECK_THAT(h, ContainsSubstring("name=\"serial_hex\" value=\"C3\""));
}

TEST_CASE("ca panel: revoke and import post to the wrappers with the pki view field",
          "[ca_panel][pki][ui]") {
    auto m = ready();
    m.issued.push_back(row("A1", "agent"));
    const auto h = render(m);
    CHECK_THAT(h, ContainsSubstring("hx-post=\"/api/settings/ca/revoke\""));
    CHECK_THAT(h, ContainsSubstring("hx-post=\"/api/settings/ca/import-chain\""));
    CHECK_THAT(h, ContainsSubstring("hx-target=\"#ca-section\""));
    // Both wrappers re-render in the shape they were called from.
    std::size_t n = 0;
    for (auto p = h.find("name=\"view\" value=\"pki\""); p != std::string::npos;
         p = h.find("name=\"view\" value=\"pki\"", p + 1))
        ++n;
    CHECK(n == 2);
    // Confirms are the only guard: neither route has server step-up.
    CHECK_THAT(h, ContainsSubstring("hx-confirm=\"Revoke certificate for"));
    CHECK_THAT(h, ContainsSubstring("There is no console action to switch back."));
}

TEST_CASE("ca panel: revoke confirm wording follows the purpose", "[ca_panel][pki][ui]") {
    CHECK_THAT(revoke_confirm_text("agent", "host-1"),
               ContainsSubstring("The agent is refused on its next connection."));
    const auto cs = revoke_confirm_text("code-signing", "release-2026");
    CHECK_THAT(cs, ContainsSubstring("agents do not yet check the list when loading plugins"));
    CHECK_FALSE(has(cs, "refused on its next connection"));
    const auto other = revoke_confirm_text("https", "Yuzu Default https");
    // No runtime effect is promised where none is verified.
    CHECK_FALSE(has(other, "refused"));
    CHECK_THAT(other, ContainsSubstring("recorded as revoked"));
    for (const auto& t : {revoke_confirm_text("agent", "x"), cs, other})
        CHECK_THAT(t, ContainsSubstring("cannot be undone"));
}

TEST_CASE("ca panel: purpose labels", "[ca_panel][pki][ui]") {
    CHECK(purpose_label("agent") == "Agent identity");
    CHECK(purpose_label("code-signing") == "Code signing");
    CHECK(purpose_label("gateway") == "gateway");
    CHECK(purpose_label("relay") == "relay");
}

TEST_CASE("ca panel: every agent- and operator-controlled string is escaped",
          "[ca_panel][pki][ui][security]") {
    auto m = ready();
    m.root.algo = "<img src=x onerror=1>";
    m.root.fingerprint_sha256 = "\"><script>1</script>";
    auto r = row("<b>S</b>", "<i>purpose</i>");
    r.subject = "<script>alert(1)</script>";
    m.issued.push_back(r);
    const auto h = render(m);
    CHECK_FALSE(has(h, "<script>alert(1)</script>"));
    CHECK_FALSE(has(h, "<img src=x"));
    CHECK_FALSE(has(h, "<i>purpose</i>"));
    CHECK_FALSE(has(h, "<b>S</b>"));
    CHECK_THAT(h, ContainsSubstring("&lt;script&gt;alert(1)&lt;/script&gt;"));
    // The confirm attribute carries the subject too: a quote must not break out of it.
    auto q = ready();
    auto e = row("Q1", "agent");
    e.subject = "a\" hx-on:click=\"x";
    q.issued.push_back(e);
    CHECK_FALSE(has(render(q), "hx-on:click=\"x"));
}

TEST_CASE("ca panel: the output carries no inline handler, hx-on or private-key input",
          "[ca_panel][pki][ui][security]") {
    auto m = ready();
    m.issued.push_back(row("A1", "agent"));
    const auto h = render(m);
    CHECK_FALSE(has(h, "hx-on"));
    CHECK_FALSE(has(h, " onclick="));
    CHECK_FALSE(has(h, " onchange="));
    CHECK_FALSE(has(h, "<script"));
    // PEM textareas are not remembered by the browser.
    CHECK_THAT(h, ContainsSubstring("name=\"intermediate_pem\" rows=\"4\" autocomplete=\"off\""));
}

TEST_CASE("ca panel: the cap banner appears only at the row limit", "[ca_panel][pki][ui]") {
    auto m = ready();
    m.panel_limit = 3;
    m.issued = {row("1", "agent"), row("2", "agent")};
    CHECK_FALSE(has(render(m), "Showing the first 3 certificates"));
    m.issued.push_back(row("3", "agent"));
    CHECK_THAT(render(m), ContainsSubstring("Showing the first 3 certificates"));
}

TEST_CASE("ca panel: inventory error and an empty inventory are different sentences",
          "[ca_panel][pki][ui]") {
    auto m = ready();
    CHECK_THAT(render(m), ContainsSubstring("No certificates issued yet"));
    m.inventory_error = true;
    const auto h = render(m);
    CHECK_THAT(h, ContainsSubstring("Certificate inventory unavailable (store error)."));
    CHECK_FALSE(has(h, "No certificates issued yet"));
}

TEST_CASE("ca panel: date formatting is UTC and a zero epoch is a dash", "[ca_panel][pki][ui]") {
    CHECK(format_utc_date(1'800'000'000) == "2027-01-15");
    CHECK(format_utc_minute(1'800'000'000) == "2027-01-15 08:00");
    CHECK(format_utc_date(0) == "\xE2\x80\x94");
    CHECK(is_expired(5, 10));
    CHECK_FALSE(is_expired(0, 10));
    CHECK_FALSE(is_expired(10, 10));
}
