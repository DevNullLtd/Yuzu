/**
 * test_result_set_matcher.cpp — unit coverage for the async result-set
 * membership matcher (scope walking PR-D, design §3.3).
 *
 * The matcher is a pure function of (matcher_json, status, output), so it
 * needs no SQLite / dispatch / tracker fixtures — every per-producer rule
 * (SUCCESS default, tar_rows_ge, any_response, column/op/value over both the
 * tar pipe shape and a JSON array-of-objects) is asserted directly here. The
 * server maintenance thread is a thin caller; this is where the rule lives.
 */

#include "result_set_matcher.hpp"

#include <catch2/catch_test_macros.hpp>
#include <nlohmann/json.hpp>

#include <string>
#include <vector>

using namespace yuzu::server::rs_matcher;

namespace {
// A tar.sql response: `__schema__` header, `|`-joined rows, `__total__` trailer.
std::string tar_rows(int n, const std::string& col = "pid") {
    std::string out = "__schema__|" + col;
    for (int i = 0; i < n; ++i)
        out += "\n" + std::to_string(1000 + i);
    out += "\n__total__|" + std::to_string(n);
    return out;
}
constexpr int kOk = kStatusSuccess; // 1
constexpr int kFail = 2;            // any non-SUCCESS
} // namespace

TEST_CASE("matcher: non-success response never qualifies", "[result_set][matcher]") {
    // Even a matcher that would otherwise pass must reject a failed exec —
    // an errored plugin is not evidence of a hit.
    REQUIRE_FALSE(response_matches("", kFail, tar_rows(5)));
    REQUIRE_FALSE(response_matches(R"({"kind":"any_response"})", kFail, tar_rows(5)));
    REQUIRE_FALSE(response_matches(R"({"kind":"tar_rows_ge","n":1})", kFail, tar_rows(5)));
}

TEST_CASE("matcher: empty / blank matcher = SUCCESS default", "[result_set][matcher]") {
    REQUIRE(response_matches("", kOk, "anything"));
    REQUIRE(response_matches("{}", kOk, "anything"));
    // Unparseable JSON falls back to the SUCCESS default rather than emptying.
    REQUIRE(response_matches("not json", kOk, "anything"));
}

TEST_CASE("matcher: any_response includes every SUCCESS responder", "[result_set][matcher]") {
    REQUIRE(response_matches(R"({"kind":"any_response"})", kOk, tar_rows(0)));
    REQUIRE(response_matches(R"({"kind":"any_response"})", kOk, "error|whatever"));
    REQUIRE_FALSE(response_matches(R"({"kind":"any_response"})", kFail, tar_rows(3)));
}

TEST_CASE("matcher: tar_rows_ge thresholds on row count", "[result_set][matcher]") {
    REQUIRE(response_matches(R"({"kind":"tar_rows_ge","n":1})", kOk, tar_rows(1)));
    REQUIRE(response_matches(R"({"kind":"tar_rows_ge","n":1})", kOk, tar_rows(5)));
    REQUIRE_FALSE(response_matches(R"({"kind":"tar_rows_ge","n":1})", kOk, tar_rows(0)));
    REQUIRE(response_matches(R"({"kind":"tar_rows_ge","n":3})", kOk, tar_rows(3)));
    REQUIRE_FALSE(response_matches(R"({"kind":"tar_rows_ge","n":3})", kOk, tar_rows(2)));
    // n defaults to 1 when omitted.
    REQUIRE(response_matches(R"({"kind":"tar_rows_ge"})", kOk, tar_rows(1)));
    REQUIRE_FALSE(response_matches(R"({"kind":"tar_rows_ge"})", kOk, tar_rows(0)));
}

TEST_CASE("matcher: tar error output counts as 0 rows", "[result_set][matcher]") {
    REQUIRE(tar_row_count("error|missing required 'sql' parameter") == 0);
    REQUIRE_FALSE(response_matches(R"({"kind":"tar_rows_ge","n":1})", kOk, "error|nope"));
}

TEST_CASE("matcher: tar_row_count trailer + fallback", "[result_set][matcher]") {
    REQUIRE(tar_row_count(tar_rows(4)) == 4);
    REQUIRE(tar_row_count(tar_rows(0)) == 0);
    // No trailer → fall back to counting data lines (schema excluded).
    REQUIRE(tar_row_count("__schema__|a\nx\ny") == 2);
    REQUIRE(tar_row_count("") == 0);
}

TEST_CASE("matcher: unknown kind excludes conservatively", "[result_set][matcher]") {
    REQUIRE_FALSE(response_matches(R"({"kind":"does_not_exist"})", kOk, tar_rows(9)));
}

TEST_CASE("matcher: column op over tar pipe shape", "[result_set][matcher]") {
    std::string out = "__schema__|pid|sha256\n42|abc\n43|def\n__total__|2";
    REQUIRE(response_matches(R"({"column":"sha256","op":"eq","value":"abc"})", kOk, out));
    REQUIRE(response_matches(R"({"column":"sha256","op":"eq","value":"def"})", kOk, out));
    REQUIRE_FALSE(response_matches(R"({"column":"sha256","op":"eq","value":"zzz"})", kOk, out));
    // in / value_set
    REQUIRE(response_matches(R"({"column":"sha256","op":"in","value_set":["x","def"]})", kOk, out));
    REQUIRE_FALSE(
        response_matches(R"({"column":"sha256","op":"in","value_set":["x","y"]})", kOk, out));
    // contains
    REQUIRE(response_matches(R"({"column":"sha256","op":"contains","value":"e"})", kOk, out));
    // exists (non-empty cell)
    REQUIRE(response_matches(R"({"column":"pid","op":"exists"})", kOk, out));
    // unknown column never matches
    REQUIRE_FALSE(response_matches(R"({"column":"nope","op":"exists"})", kOk, out));
}

TEST_CASE("matcher: column op over JSON array-of-objects fallback", "[result_set][matcher]") {
    std::string out = R"([{"sha256":"bad1","path":"/a"},{"sha256":"good","path":"/b"}])";
    REQUIRE(response_matches(R"({"column":"sha256","op":"in","value_set":["bad1","bad2"]})", kOk,
                             out));
    REQUIRE_FALSE(
        response_matches(R"({"column":"sha256","op":"in","value_set":["nope"]})", kOk, out));
    // {"rows":[...]} envelope is also accepted.
    std::string env = R"({"rows":[{"n":7}]})";
    REQUIRE(response_matches(R"({"column":"n","op":"eq","value":"7"})", kOk, env));
}

TEST_CASE("matcher: malformed column matcher falls back to default", "[result_set][matcher]") {
    // Has neither value nor value_set for eq → row never satisfies, but the
    // matcher SHAPE is recognised, so it's not the "typo → default" path; it
    // simply finds no matching row. A SUCCESS responder with such a matcher
    // and no rows yields no membership.
    std::string out = "__schema__|c\nv\n__total__|1";
    REQUIRE_FALSE(response_matches(R"({"column":"c","op":"eq"})", kOk, out));
    // A matcher object with neither kind nor column is treated as default.
    REQUIRE(response_matches(R"({"foo":"bar"})", kOk, out));
}

// #4644: `m.value("n", 1)` THREW on a wrong-typed n (string/null/array/object), and the
// maintenance tick calls response_matches for every pending set without a try/catch, so one bad
// stored matcher re-threw every 2 s and starved the GC and retention reaps behind it. A numeric n
// outside int range also wrapped (4294967297 read as 1). Now a malformed n fails CLOSED like an
// unknown kind: nobody qualifies, nothing throws.
TEST_CASE("matcher: a malformed tar_rows_ge n never throws and matches nobody (#4644)",
          "[result_set][matcher][numeric_params]") {
    const std::vector<std::string> bad_n = {
        "\"2\"", "\"\"", "null", "true", "[]", "{}", "5.5", "1e3", "4294967297",
        "-4294967295", "9223372036854775808", "18446744073709551615", "2147483648",
        // Below 1 parses as a valid int but is refused at admission; a row stored before that
        // refusal must not read `count >= 0` as "every responder qualifies".
        "0", "-1", "-2147483648"};
    for (const auto& n : bad_n) {
        const std::string m = R"({"kind":"tar_rows_ge","n":)" + n + "}";
        INFO(m);
        bool r = true;
        REQUIRE_NOTHROW(r = response_matches(m, kOk, tar_rows(5)));
        CHECK_FALSE(r);
    }

    // The maintenance tick walks every pending set in one loop: a bad set must not stop the
    // sets after it (the old code threw out of the loop on the first one).
    const std::vector<std::string> pending = {R"({"kind":"tar_rows_ge","n":"x"})",
                                              R"({"kind":"tar_rows_ge","n":2})",
                                              R"({"kind":"any_response"})"};
    std::vector<bool> member;
    REQUIRE_NOTHROW([&] {
        for (const auto& m : pending)
            member.push_back(response_matches(m, kOk, tar_rows(3)));
    }());
    REQUIRE(member.size() == 3);
    CHECK_FALSE(member[0]);
    CHECK(member[1]);
    CHECK(member[2]);

    // A PRESENT `kind` that is not a string is malformed, not absent: it must not fall through to
    // the accept-all default (or to a column matcher) and so admit every responder.
    for (const char* bad_kind :
         {R"({"kind":1})", R"({"kind":null})", R"({"kind":true})", R"({"kind":["tar_rows_ge"]})",
          R"({"kind":{}})", R"({"kind":1,"column":"sha256","op":"exists"})"}) {
        INFO(bad_kind);
        bool r = true;
        REQUIRE_NOTHROW(r = response_matches(bad_kind, kOk, tar_rows(5)));
        CHECK_FALSE(r);
    }

    // Well-formed thresholds keep their meaning, including the INT_MAX boundary and an absent n.
    CHECK(response_matches(R"({"kind":"tar_rows_ge","n":2147483647})", kOk, tar_rows(3)) == false);
    CHECK(response_matches(R"({"kind":"tar_rows_ge","n":3})", kOk, tar_rows(3)));
    CHECK(response_matches(R"({"kind":"tar_rows_ge"})", kOk, tar_rows(1)));
}

TEST_CASE("matcher: validate_matcher accepts only an integer n of at least 1 (#4644)",
          "[result_set][matcher][numeric_params]") {
    for (const char* ok :
         {"", "{}", R"({"kind":"any_response"})", R"({"kind":"tar_rows_ge"})",
          R"({"kind":"tar_rows_ge","n":1})", R"({"kind":"tar_rows_ge","n":2147483647})",
          R"({"column":"sha256","op":"eq","value":"x"})",
          // n only means something for tar_rows_ge, and an unrecognised shape keeps its default.
          R"({"kind":"any_response","n":"x"})", "not json", "[]"}) {
        INFO(ok);
        CHECK_FALSE(validate_matcher(ok).has_value());
    }
    for (const char* bad :
         {R"({"kind":"tar_rows_ge","n":0})", R"({"kind":"tar_rows_ge","n":-1})",
          R"({"kind":"tar_rows_ge","n":4294967297})",
          R"({"kind":"tar_rows_ge","n":9223372036854775808})",
          R"({"kind":"tar_rows_ge","n":18446744073709551615})", R"({"kind":"tar_rows_ge","n":2147483648})",
          R"({"kind":"tar_rows_ge","n":1e3})", R"({"kind":"tar_rows_ge","n":5.5})",
          R"({"kind":"tar_rows_ge","n":"7"})", R"({"kind":"tar_rows_ge","n":""})",
          R"({"kind":"tar_rows_ge","n":null})", R"({"kind":"tar_rows_ge","n":true})",
          R"({"kind":"tar_rows_ge","n":[]})", R"({"kind":"tar_rows_ge","n":{}})",
          // A present kind that is not a string would otherwise fall through to accept-all.
          R"({"kind":1})", R"({"kind":null})", R"({"kind":true})", R"({"kind":[]})",
          R"({"kind":{}})"}) {
        INFO(bad);
        CHECK(validate_matcher(bad).has_value());
    }
}

// The admission check for a parsed caller `matcher`: a value that is not a JSON object is refused
// here (it used to be dropped, i.e. accept-all), so a producer cannot admit accept-all by calling
// only the validator.
TEST_CASE("matcher: validate_matcher_object refuses a non-object and defers to validate_matcher",
          "[result_set][matcher][numeric_params]") {
    using nlohmann::json;
    for (const char* bad : {"null", "[]", "[1]", "5", "5.5", "true", R"("x")", R"("{}")"}) {
        INFO(bad);
        const auto err = validate_matcher_object(json::parse(bad));
        REQUIRE(err.has_value());
        CHECK(err->find("JSON object") != std::string::npos);
    }
    for (const char* ok : {"{}", R"({"kind":"any_response"})", R"({"kind":"tar_rows_ge","n":3})",
                           R"({"column":"c","op":"eq","value":"v"})"}) {
        INFO(ok);
        CHECK_FALSE(validate_matcher_object(json::parse(ok)).has_value());
    }
    for (const char* bad : {R"({"kind":"tar_rows_ge","n":0})", R"({"kind":1})",
                            R"({"column":5,"op":"eq","value":"v"})"}) {
        INFO(bad);
        CHECK(validate_matcher_object(json::parse(bad)).has_value());
    }
}

// A PRESENT but wrong-typed column / op / value / value_set used to fall through the "unrecognised
// shape" default and admit every responder; a MISSING key keeps that documented default.
TEST_CASE("matcher: a present wrong-typed column/op/value matches nobody and is refused at admission",
          "[result_set][matcher][numeric_params]") {
    const std::string out = "__schema__|c\nv\n__total__|1";
    for (const char* bad :
         {R"({"column":5,"op":"eq","value":"v"})", R"({"column":"c","op":5,"value":"v"})",
          R"({"column":null,"op":"exists"})", R"({"column":["c"],"op":"exists"})",
          R"({"column":"c","op":{},"value":"v"})", R"({"column":"c","op":"eq","value":5})",
          R"({"column":"c","op":"exists","value":true})",
          R"({"column":"c","op":"in","value_set":"v"})", R"({"column":"c","op":"in","value_set":{}})",
          R"({"column":5})", R"({"op":5})"}) {
        INFO(bad);
        bool r = true;
        REQUIRE_NOTHROW(r = response_matches(bad, kOk, out));
        CHECK_FALSE(r);
        CHECK(validate_matcher(bad).has_value());
    }

    // A MISSING key is unchanged: the unrecognised-shape default still admits the responder.
    for (const char* missing : {R"({"column":"c"})", R"({"op":"eq"})", R"({"foo":"bar"})"}) {
        INFO(missing);
        CHECK(response_matches(missing, kOk, out));
        CHECK_FALSE(validate_matcher(missing).has_value());
    }
    // Well-formed column matchers are unaffected.
    CHECK(response_matches(R"({"column":"c","op":"eq","value":"v"})", kOk, out));
    CHECK(response_matches(R"({"column":"c","op":"in","value_set":["v"]})", kOk, out));
    CHECK_FALSE(validate_matcher(R"({"column":"c","op":"in","value_set":["v"]})").has_value());
}

// A JSON-array output cell that is an unsigned integer above INT64_MAX renders as itself. The
// signed read first wrapped 18446744073709551615 to "-1", so `eq "-1"` admitted the responder.
TEST_CASE("matcher: a JSON unsigned cell above INT64_MAX is not read as its int64 wrap",
          "[result_set][matcher]") {
    const std::string out = R"([{"c":18446744073709551615}])";
    CHECK(response_matches(R"({"column":"c","op":"eq","value":"18446744073709551615"})", kOk, out));
    CHECK_FALSE(response_matches(R"({"column":"c","op":"eq","value":"-1"})", kOk, out));
}

// ── declared-column matcher over plain pipe rows ─────────────────────────────
// A plugin that is neither tar nor JSON (security.certificates.list) writes a header row
// then pipe rows; the column is resolved from the definition's declared names, which admission
// stores in the matcher (bind_declared_columns).
namespace {
const char* kCertSchema =
    R"([{"name":"subject","type":"string"},{"name":"issuer","type":"string"},)"
    R"({"name":"thumbprint","type":"string"},{"name":"not_before","type":"string"},)"
    R"({"name":"not_after","type":"string"},{"name":"serial","type":"string"},)"
    R"({"name":"store","type":"string"},{"name":"key_usage","type":"string"}])";

const char* kCertHeader = "subject|issuer|thumbprint|not_before|not_after|serial|store|key_usage";

std::string cert_matcher(const std::string& column, const std::string& op,
                         const std::string& value = {}) {
    nlohmann::json m{{"column", column}, {"op", op}};
    if (!value.empty())
        m["value"] = value;
    bind_declared_columns(m, kCertSchema, "certificates");
    return m.dump();
}

std::string cert_output(const std::string& extra = {}) {
    return std::string(kCertHeader) +
           "\nCN=a|CN=DigiCert CA|aa|2020|2030|01|Root|sig"
           "\nCN=b|CN=eMudhra Sub CA|bb|2020|2030|02|Root|sig"
           "\nCN=c|CN=Other CA|cc|2020|2030|03|Root|sig" +
           extra;
}
} // namespace

TEST_CASE("matcher: declared columns resolve a plain pipe-row column", "[result_set][matcher]") {
    const auto m = cert_matcher("issuer", "contains", "eMudhra");
    const auto j = nlohmann::json::parse(m);
    REQUIRE(j["declared_columns"].size() == 8);
    REQUIRE(j["declared_columns"][1] == "issuer");
    REQUIRE(j["plugin"] == "certificates");
    REQUIRE(response_matches(m, kOk, cert_output()));
    REQUIRE_FALSE(response_matches(cert_matcher("issuer", "contains", "Nonexistent"), kOk,
                                   cert_output()));
    REQUIRE(response_matches(cert_matcher("issuer", "eq", "CN=Other CA"), kOk, cert_output()));
    REQUIRE_FALSE(response_matches(m, kFail, cert_output()));
}

TEST_CASE("matcher: declared columns skip the header and short status rows",
          "[result_set][matcher]") {
    // The header's own cells would satisfy exists/contains if it were read as data.
    const auto exists = cert_matcher("issuer", "exists");
    REQUIRE_FALSE(response_matches(exists, kOk, kCertHeader));
    REQUIRE_FALSE(response_matches(exists, kOk, std::string(kCertHeader) + "\nstatus|not_found"));
    REQUIRE_FALSE(response_matches(cert_matcher("issuer", "contains", "issuer"), kOk,
                                   std::string(kCertHeader) + "\n"));
    REQUIRE_FALSE(response_matches(exists, kOk, "not_available|no store reachable"));
    REQUIRE(response_matches(exists, kOk, cert_output()));
    // A short status row after real data does not change the verdict either way.
    REQUIRE(response_matches(cert_matcher("issuer", "contains", "eMudhra"), kOk,
                             cert_output("\nstatus|not_found")));
    REQUIRE_FALSE(response_matches(cert_matcher("issuer", "contains", "not_found"), kOk,
                                   "status|not_found"));
}

TEST_CASE("matcher: declared columns keep row width across an escaped pipe",
          "[result_set][matcher]") {
    const std::string out = std::string(kCertHeader) +
                            "\nCN=a\\|b|CN=eMudhra CA|aa|2020|2030|01|Root|sig";
    REQUIRE(response_matches(cert_matcher("issuer", "contains", "eMudhra"), kOk, out));
    REQUIRE(response_matches(cert_matcher("subject", "eq", "CN=a|b"), kOk, out));
    // An UNescaped extra pipe makes the row 9 wide: dropped, not shifted.
    REQUIRE_FALSE(response_matches(
        cert_matcher("issuer", "contains", "eMudhra"), kOk,
        std::string(kCertHeader) + "\nCN=a|b|CN=eMudhra CA|aa|2020|2030|01|Root|sig"));
}

TEST_CASE("matcher: a column outside the declared list binds nothing", "[result_set][matcher]") {
    nlohmann::json m{{"column", "nope"}, {"op", "exists"}};
    bind_declared_columns(m, kCertSchema, "certificates");
    REQUIRE_FALSE(m.contains("declared_columns"));
    REQUIRE_FALSE(m.contains("plugin"));
    nlohmann::json empty{{"column", "issuer"}, {"op", "exists"}};
    bind_declared_columns(empty, "", "certificates");
    REQUIRE_FALSE(empty.contains("declared_columns"));
    nlohmann::json kind{{"kind", "any_response"}, {"column", "issuer"}};
    bind_declared_columns(kind, kCertSchema, "certificates");
    REQUIRE_FALSE(kind.contains("declared_columns"));
}

TEST_CASE("matcher: wrong-typed declared_columns / plugin match nobody", "[result_set][matcher]") {
    const auto good = nlohmann::json::parse(cert_matcher("issuer", "exists"));
    for (const auto& bad : {nlohmann::json("issuer"), nlohmann::json::array({1, 2}),
                            nlohmann::json::object()}) {
        auto m = good;
        m["declared_columns"] = bad;
        REQUIRE_FALSE(response_matches(m.dump(), kOk, cert_output()));
    }
    auto m = good;
    m["plugin"] = 5;
    REQUIRE_FALSE(response_matches(m.dump(), kOk, cert_output()));
}

TEST_CASE("matcher: admission refuses caller-supplied server-authored keys",
          "[result_set][matcher]") {
    const auto dc = validate_matcher(R"({"column":"issuer","op":"exists","declared_columns":["issuer"]})");
    REQUIRE(dc);
    CHECK(dc->find("declared_columns") != std::string::npos);
    const auto pl = validate_matcher(R"({"column":"issuer","op":"exists","plugin":"x"})");
    REQUIRE(pl);
    CHECK(pl->find("plugin") != std::string::npos);
    REQUIRE_FALSE(validate_matcher(R"({"column":"issuer","op":"exists"})"));
}

TEST_CASE("matcher: declared columns leave tar and json matching unchanged",
          "[result_set][matcher]") {
    nlohmann::json m{{"column", "pid"}, {"op", "eq"}, {"value", "1000"}};
    bind_declared_columns(m, kCertSchema, "certificates"); // pid not declared: unchanged
    REQUIRE(response_matches(m.dump(), kOk, tar_rows(2)));
    REQUIRE(response_matches(R"({"column":"sha256","op":"eq","value":"x"})", kOk,
                             R"([{"sha256":"x"}])"));
}

// ── declared columns wider than a key/value plugin's key + remainder schema (#5624) ──
// find_by_hash declares row_kind/path/size on the key/value `filesystem` plugin. The matcher
// splits each row to the DECLARED width, so a three-column definition can match a row.
namespace {
const char* kFindByHashSchema =
    R"([{"name":"row_kind","type":"string"},{"name":"path","type":"string"},)"
    R"({"name":"size","type":"string"}])";

const char* kFindByHashOutput = "match|/etc/hosts|413\n"
                                "truncated|deadline|visited=5|hashed=9|skipped_unreadable=1\n"
                                "matches_found|1";

bool find_by_hash_matches(const std::string& column, const std::string& op,
                          const std::string& value = {}) {
    nlohmann::json m{{"column", column}, {"op", op}};
    if (!value.empty())
        m["value"] = value;
    bind_declared_columns(m, kFindByHashSchema, "filesystem");
    return response_matches(m.dump(), kOk, kFindByHashOutput);
}
} // namespace

TEST_CASE("matcher: a three-column definition over a key/value plugin matches by declared position",
          "[result_set][matcher]") {
    CHECK(find_by_hash_matches("path", "contains", "/etc/hosts"));
    CHECK(find_by_hash_matches("size", "eq", "413"));
    CHECK(find_by_hash_matches("row_kind", "eq", "truncated"));
    // The truncated row's third cell is the whole remainder.
    CHECK(find_by_hash_matches("size", "contains", "skipped_unreadable=1"));
    // matches_found|N is a two-cell summary, not a data row.
    CHECK_FALSE(find_by_hash_matches("row_kind", "eq", "matches_found"));
    CHECK_FALSE(find_by_hash_matches("path", "contains", "/etc/passwd"));
    CHECK_FALSE(find_by_hash_matches("size", "eq", "414"));
}

TEST_CASE("matcher: a two-column definition over a key/value plugin is unchanged",
          "[result_set][matcher]") {
    nlohmann::json m{{"column", "value"}, {"op", "eq"}, {"value", "ok"}};
    bind_declared_columns(m, R"([{"name":"key","type":"string"},{"name":"value","type":"string"}])",
                          "filesystem");
    CHECK(response_matches(m.dump(), kOk, "status|ok"));
    CHECK_FALSE(response_matches(m.dump(), kOk, "status|no"));
}
