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
#include <vector>

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
          "proxy_address|REDACTED@proxy.example:3128/");
    CHECK(format_proxy_address_row("http://bob:p%2f@ss@proxy:3128") ==
          "proxy_address|REDACTED@proxy:3128");
    CHECK(format_proxy_address_row("proxy.example:3128") == "proxy_address|proxy.example:3128");
    for (const char* in : {"bob:SEKR3T@proxy:3128", "bob@proxy:3128", "socks5://bob:SEKR3T@p:1080"}) {
        const auto row = format_proxy_address_row(in);
        CHECK_FALSE(has(row, "SEKR3T"));
        CHECK_FALSE(has(row, "bob"));
        CHECK(has(row, "REDACTED@"));
    }
    using yuzu::network_config::ProxyShape;
    CHECK(format_proxy_address_row("http=bob:SEKR3T@h:80;https=h2:443", ProxyShape::list) ==
          "proxy_address|REDACTED@h:80;https=h2:443");
    CHECK(format_proxy_address_row("http=h:80;https=h2:443", ProxyShape::list) ==
          "proxy_address|http=h:80;https=h2:443");
    // a hostile value still yields one row
    const auto row = format_proxy_address_row("http://u:p@h/\nproxy_type|none");
    CHECK(single_line(row));
    CHECK_FALSE(has(row, "u:p"));
}

TEST_CASE("proxy redaction: separators and odd characters inside credentials do not leak",
          "[plugin][row][wp11]") {
    using yuzu::network_config::format_proxy_address_row;
    using yuzu::network_config::ProxyShape;
    const auto has = [](const std::string& s, const char* n) {
        return s.find(n) != std::string::npos;
    };
    // {input, every fragment of the credential that must be absent}
    struct Case {
        const char* in;
        std::vector<const char*> secrets;
    };
    const std::vector<Case> cases{
        {"http://user:pa,ss@proxy:3128", {"user", "pa,", ",ss"}},
        {"http://user:p;w@host", {"user", "p;", "w@"}},
        {"http://user:p w@host", {"user", "p ", " w"}},
        {"http://user:p=w@host", {"user", "p=w"}},
        {"http://user:a:b@host", {"user", "a:b"}},
        {"http://user:p/q@host", {"user", "p/q"}},
        {"http://user:p@q@host", {"user", "p@q"}},
        {"user:secret=@host:80", {"user", "secret"}},
        {"user=pw@host:80", {"pw"}},
        {"a:b=c@host", {"a:b", "c@"}},
        {"alice:sekret@host:80/path", {"alice", "sekret"}},
        {"http://x:y@h:1;http://u2:pw2@h2:2", {"pw2", "u2"}},
    };
    for (const auto& c : cases) {
        for (const auto shape : {ProxyShape::single, ProxyShape::list}) {
            const auto row = format_proxy_address_row(c.in, shape);
            for (const char* sec : c.secrets)
                { INFO(c.in << " -> " << row << " leaks " << sec); CHECK_FALSE(has(row, sec)); }
            CHECK(has(row, "REDACTED@"));
        }
    }
    // list values: credentials in the 2nd and 3rd entries, with separators inside
    const auto list = format_proxy_address_row(
        "http=h:80;https=u2:p,w2@h2:443;ftp=u3:p;3 x@h3:21;socks=h4:1080", ProxyShape::list);
    for (const char* sec : {"u2", "p,w2", "u3", "p;3", "x@"})
        CHECK_FALSE(has(list, sec));
    // the 1st entry has no '@' of its own and a later one does, so the split is
    // not trusted: everything up to the last '@' is over-redacted, the tail stays
    CHECK(has(list, "socks=h4:1080"));
    // a list with no '@' anywhere stays fully readable
    CHECK(format_proxy_address_row("http=h:80;https=h:443;socks=h4:1080", ProxyShape::list) ==
          "proxy_address|http=h:80;https=h:443;socks=h4:1080");
    // a credential that itself contains `;scheme://` or `;key=` (looks like an entry boundary)
    for (const char* in :
         {"http=h:80;https=u:pw;x://y@h2:80", "https=user:pw;http://y@h2:80",
          "https=user:pw;key=z@h2:80", "http=h:80;https=user:pw;x://y@h2:80;ftp=a:b@h3",
          "http=u:pw\r\nx://y@h", "a=b@c@d@h;https=x:y@z"}) {
        const auto row = format_proxy_address_row(in, ProxyShape::list);
        INFO(in << " -> " << row);
        for (const char* sec : {"u:pw", "user:pw", "a:b", "x:y", "b@", "d@"})
            CHECK_FALSE(has(row, sec));
        CHECK(has(row, "REDACTED@"));
    }
    // IPv6 literal, percent-encoding and a very long input stay correct and cheap
    CHECK(format_proxy_address_row("http=[::1]:80;https=[::2]:81", ProxyShape::list) ==
          "proxy_address|http=[::1]:80;https=[::2]:81");
    CHECK_FALSE(has(format_proxy_address_row("http=u:p%3Bq@[::1]:80", ProxyShape::list), "p%3Bq"));
    const std::string many = [] {
        std::string m;
        for (int i = 0; i < 100000; ++i)
            m += "a=b;";
        return m + "@";
    }();
    CHECK(has(format_proxy_address_row(many, ProxyShape::list), "REDACTED@"));
    // a hostile (non-plain) key never survives as an unredacted prefix
    CHECK_FALSE(has(format_proxy_address_row("user:secret=@host", ProxyShape::list), "secret"));
    CHECK_FALSE(has(format_proxy_address_row("us er:pw=x@host", ProxyShape::list), "pw"));
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
