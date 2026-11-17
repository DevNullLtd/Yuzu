/**
 * test_plugin_row_neutralisation.cpp -- WP11: endpoint-derived strings in the
 * pipe/newline-delimited result rows must never add columns or forge rows, and
 * the network_config `proxy` row must not carry URL userinfo (credentials).
 *
 * The pure formatters are exercised on every OS; filesystem list_dir/search_dir
 * run the real built plugin through LocalDispatcher on POSIX (a Windows file
 * name cannot hold '|' or LF).
 */
#include <catch2/catch_test_macros.hpp>

#include <installed_apps_parsers.hpp>
#include <network_config_parsers.hpp>
#include <processes_rows.hpp>
#include <procfetch_row.hpp>
#include <update_source_trust_parsers.hpp>
#include <wmi_rows.hpp>

#include <algorithm>
#include <string>

#ifndef _WIN32
#include "filesystem_dispatcher_test_support.hpp"
#include "local_dispatcher.hpp"
#include <yuzu/plugin.h>
#include <vector>
#endif

namespace {

// Count UNESCAPED pipes (a '\|' pair is data), mirroring the server decoder.
std::size_t delimiters(const std::string& row) {
    std::size_t n = 0;
    for (std::size_t i = 0; i < row.size(); ++i) {
        if (row[i] == '\\' && i + 1 < row.size() && row[i + 1] == '|')
            ++i;
        else if (row[i] == '|')
            ++n;
    }
    return n;
}

bool single_line(const std::string& row) {
    return row.find('\n') == std::string::npos && row.find('\r') == std::string::npos;
}

const std::string kHostile = "a|b\nforged|row\r|x";

} // namespace

TEST_CASE("processes.query row neutralises delimiters", "[plugin][row][wp11]") {
    const auto row = yuzu::processes::format_query_row(42, kHostile);
    CHECK(single_line(row));
    CHECK(delimiters(row) == 2);
    CHECK(row.rfind("proc|42|", 0) == 0);
}

TEST_CASE("procfetch row neutralises name and path", "[plugin][row][wp11]") {
    const auto row = yuzu::procfetch::format_row(7, kHostile, kHostile, "abc123");
    CHECK(single_line(row));
    CHECK(delimiters(row) == 3);
    CHECK(row.substr(row.rfind('|') + 1) == "abc123");
}

TEST_CASE("wmi rows neutralise key and value", "[plugin][row][wp11]") {
    const auto r = yuzu::wmi::format_row_line(3, kHostile, kHostile);
    CHECK(single_line(r));
    CHECK(delimiters(r) == 2);
    const auto p = yuzu::wmi::format_property_line(kHostile, kHostile);
    CHECK(single_line(p));
    CHECK(delimiters(p) == 2);
}

TEST_CASE("installed_apps query and list_per_user rows keep their field count",
          "[plugin][row][wp11]") {
    namespace ia = yuzu::installed_apps::parsers;
    const auto q = ia::format_query_row(kHostile, kHostile, kHostile);
    CHECK(single_line(q));
    CHECK(delimiters(q) == 3);
    const auto u = ia::format_user_app_row(kHostile, kHostile, kHostile, kHostile, kHostile);
    CHECK(single_line(u));
    CHECK(delimiters(u) == 5);
    // empty optional fields still render "-"
    CHECK(ia::format_query_row("n", "", "") == "app|n|-|-");
    CHECK(ia::format_user_app_row("u", "n", "", "", "") == "user_app|u|n|-|-|-");
}

TEST_CASE("network_config proxy row redacts userinfo", "[plugin][row][wp11]") {
    using yuzu::network_config::format_proxy_address_row;
    const auto has = [](const std::string& s, const char* needle) {
        return s.find(needle) != std::string::npos;
    };
    CHECK(format_proxy_address_row("http://bob:SEKR3T@proxy.example:3128/") ==
          "proxy_address|http://REDACTED@proxy.example:3128/");
    CHECK(format_proxy_address_row("http://bob:p%2f@ss@proxy:3128") ==
          "proxy_address|http://REDACTED@proxy:3128");
    CHECK(format_proxy_address_row("proxy.example:3128") == "proxy_address|proxy.example:3128");
    for (const char* in : {"bob:SEKR3T@proxy:3128", "bob@proxy:3128", "socks5://bob:SEKR3T@p:1080",
                           "http=bob:SEKR3T@h:80;https=bob:SEKR3T@h2:443"}) {
        const auto row = format_proxy_address_row(in);
        CHECK_FALSE(has(row, "SEKR3T"));
        CHECK_FALSE(has(row, "bob"));
        CHECK(has(row, "REDACTED@"));
    }
    CHECK(format_proxy_address_row("http=bob:SEKR3T@h:80;https=h2:443") ==
          "proxy_address|http=REDACTED@h:80;https=h2:443");
    // a hostile value still yields one row
    const auto row = format_proxy_address_row("http://u:p@h/\nproxy_type|none");
    CHECK(single_line(row));
    CHECK_FALSE(has(row, "u:p"));
}

TEST_CASE("update_source_trust redaction still forwards to the shared logic", "[plugin][wp11]") {
    CHECK(yuzu::update_source_trust::redact_apt_word("http://u:pw@h.example/x") ==
          "http://REDACTED@h.example/x");
}

#ifndef _WIN32
namespace fsd = yuzu::test::filesystem_dispatcher_support;

TEST_CASE("filesystem list_dir/search_dir neutralise hostile file names", "[filesystem][wp11]") {
    auto plugin = fsd::load_or_fail();
    if (!plugin)
        return;
    fsd::Tree t;
    t.write("evil|name\nforged|row|x", "data");

    {
        std::vector<YuzuParam> params{{"path", t.root.c_str()}};
        yuzu::agent::LocalDispatcher d;
        const auto r = d.run(plugin->descriptor, "list_dir", params);
        const auto rows = fsd::captured_rows(r.captured);
        REQUIRE(rows.size() == 1);
        CHECK(delimiters(rows[0]) == 3);
        CHECK(rows[0].rfind("entry|", 0) == 0);
    }
    {
        std::vector<YuzuParam> params{{"root", t.root.c_str()},
                                      {"pattern", "*"},
                                      {"match_type", "files"}};
        yuzu::agent::LocalDispatcher d;
        const auto r = d.run(plugin->descriptor, "search_dir", params);
        const auto rows = fsd::captured_rows(r.captured);
        REQUIRE(rows.size() == 2);
        CHECK(rows[0].rfind("result|", 0) == 0);
        CHECK(rows[1] == "total_matches|1");
    }
}
#endif
