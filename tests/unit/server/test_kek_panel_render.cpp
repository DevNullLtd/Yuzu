/**
 * @file test_kek_panel_render.cpp
 * @brief Pure goldens for the Key-encryption key status panel (kek_panel_render.{hpp,cpp}).
 */

#include "kek_panel_render.hpp"

#include <catch2/catch_test_macros.hpp>
#include <catch2/matchers/catch_matchers_string.hpp>

using namespace yuzu::server::kek_panel;
using Catch::Matchers::ContainsSubstring;

namespace {

Model ready() {
    Model m;
    m.availability = Availability::Ready;
    m.active_version = 7;
    m.oldest_in_use = 7;
    m.rotation_complete = true;
    m.live_versions = 7;
    m.lock_held = false;
    return m;
}

bool has(const std::string& h, const std::string& n) { return h.find(n) != std::string::npos; }

} // namespace

TEST_CASE("kek panel: complete re-wrap, free lock", "[kek_panel][pki][ui]") {
    const auto h = render(ready());
    CHECK_THAT(h, ContainsSubstring("secrets-kek-v7"));
    CHECK_THAT(h, ContainsSubstring("<span>Re-wrap</span><b>Complete</b>"));
    CHECK_THAT(h, ContainsSubstring("<span>Live key versions</span><b>7</b>"));
    CHECK_THAT(h, ContainsSubstring("<span>Operation lock</span><b>Free</b>"));
    CHECK_FALSE(has(h, "Re-wrap incomplete"));
}

TEST_CASE("kek panel: no stored secrets", "[kek_panel][pki][ui]") {
    auto m = ready();
    m.oldest_in_use.reset();
    CHECK_THAT(render(m), ContainsSubstring("No stored secrets"));
}

TEST_CASE("kek panel: incomplete re-wrap leads with a warning and names the versions",
          "[kek_panel][pki][ui]") {
    auto m = ready();
    m.rotation_complete = false;
    m.oldest_in_use = 6;
    const auto h = render(m);
    CHECK_THAT(h, ContainsSubstring("Re-wrap incomplete:"));
    CHECK_THAT(h, ContainsSubstring("oldest key still in use is v6, active is v7"));
    // Status-scoped wording must not claim a half-committed rotation: a running rotation
    // on another request reads the same way.
    CHECK_FALSE(has(h, "Do not rotate again"));
    CHECK_THAT(h, ContainsSubstring("If the operation lock shows Held"));
}

TEST_CASE("kek panel: a secret on a newer key than the active one says re-wrap cannot fix it",
          "[kek_panel][pki][ui]") {
    auto m = ready();
    m.rotation_complete = false;
    m.oldest_in_use = 9;
    CHECK_THAT(render(m), ContainsSubstring("Re-wrap cannot fix this."));
}

TEST_CASE("kek panel: unknown figures are Unknown, never 0 or Free", "[kek_panel][pki][ui]") {
    auto m = ready();
    m.live_versions.reset();
    m.lock_held.reset();
    const auto h = render(m);
    CHECK_THAT(h, ContainsSubstring("<span>Live key versions</span><b>Unknown</b>"));
    CHECK_THAT(h, ContainsSubstring("<span>Operation lock</span><b>Unknown</b>"));
    CHECK_FALSE(has(h, "Free"));
}

TEST_CASE("kek panel: a held lock shows pid and capture time when known", "[kek_panel][pki][ui]") {
    auto m = ready();
    m.lock_held = true;
    m.lock_holder_pid = 18342;
    m.lock_captured_at = "14:41:07 UTC";
    const auto h = render(m);
    CHECK_THAT(h, ContainsSubstring("Held<small>backend pid 18342, read at 14:41:07 UTC</small>"));
    m.lock_holder_pid.reset();
    const auto h2 = render(m);
    CHECK_THAT(h2, ContainsSubstring("<b>Held</b>"));
}

TEST_CASE("kek panel: failure states are fixed sentences with no status rows",
          "[kek_panel][pki][ui][security]") {
    Model m;
    m.availability = Availability::Unavailable;
    auto h = render(m);
    CHECK_THAT(h, ContainsSubstring("Key management is not available (secrets store not ready)."));
    CHECK_FALSE(has(h, "secrets-kek-v"));
    m.availability = Availability::QueryCanceled;
    CHECK_THAT(render(m), ContainsSubstring("the query was cancelled or timed out"));
    m.availability = Availability::Internal;
    CHECK_THAT(render(m), ContainsSubstring("internal error"));
}

TEST_CASE("kek panel: status only, with the API pointers and no write controls",
          "[kek_panel][pki][ui]") {
    const auto h = render(ready());
    CHECK_THAT(h, ContainsSubstring("shows status only"));
    CHECK_THAT(h, ContainsSubstring("POST /api/v1/secrets/kek/rotate"));
    CHECK_FALSE(has(h, "<button"));
    CHECK_FALSE(has(h, "<form"));
}
