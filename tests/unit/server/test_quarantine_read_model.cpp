/// @file test_quarantine_read_model.cpp
/// Pure tests for quarantine_read_model.hpp: the eight wire keys in wire order, `[]` for an empty
/// list, and escaping that matches the hand-rolled builder the REST route used before it moved
/// to this shared builder. The route-level byte pin (against a real store) is in
/// test_rest_quarantine_routes.cpp; this file needs no Postgres.

#include "quarantine_read_model.hpp"

#include <catch2/catch_test_macros.hpp>

#include <string>
#include <vector>

using namespace yuzu::server;

namespace {

QuarantineRecord make_record(std::string agent_id) {
    QuarantineRecord r;
    r.id = 7; // internal key: must never reach the wire
    r.agent_id = std::move(agent_id);
    r.status = "active";
    r.quarantined_by = "alice";
    r.quarantined_at = 1700000000;
    r.released_at = 1700000500; // not exposed either
    r.whitelist = "10.0.0.1,10.0.0.2";
    r.reason = "malware";
    r.last_applied_at = 1700000100;
    r.last_confirmed_at = 1700000200;
    return r;
}

} // namespace

TEST_CASE("quarantine_record_json: eight keys in wire order, internal fields withheld",
          "[quarantine][read_model]") {
    const auto j = quarantine_record_json(make_record("agent-1"));
    CHECK(quarantine_dump(j) ==
          R"({"agent_id":"agent-1","status":"active","quarantined_by":"alice","quarantined_at":1700000000,)"
          R"("whitelist":"10.0.0.1,10.0.0.2","reason":"malware","last_applied_at":1700000100,)"
          R"("last_confirmed_at":1700000200})");
    std::vector<std::string> keys;
    for (auto it = j.begin(); it != j.end(); ++it)
        keys.push_back(it.key());
    CHECK(keys == std::vector<std::string>{"agent_id", "status", "quarantined_by", "quarantined_at",
                                           "whitelist", "reason", "last_applied_at",
                                           "last_confirmed_at"});
}

TEST_CASE("quarantine_list_data_json: order is preserved and empty is an array",
          "[quarantine][read_model]") {
    CHECK(quarantine_dump(quarantine_list_data_json({})) == "[]");

    const auto j = quarantine_list_data_json({make_record("b"), make_record("a")});
    REQUIRE(j.is_array());
    REQUIRE(j.size() == 2);
    CHECK(j[0]["agent_id"] == "b");
    CHECK(j[1]["agent_id"] == "a");
}

TEST_CASE("quarantine builders escape like the builder they replaced", "[quarantine][read_model]") {
    auto r = make_record("agent-1");
    r.reason = "q\"b\\s\n\r\t\b\f\x01\x1f/\x7f";
    r.whitelist = "a\tb";
    // Short escapes for \b \f \n \r \t, lowercase \u00xx for the other control bytes, and '/'
    // and 0x7f left raw.
    CHECK(quarantine_dump(quarantine_record_json(r)) ==
          std::string(R"({"agent_id":"agent-1","status":"active","quarantined_by":"alice",)"
                      R"("quarantined_at":1700000000,"whitelist":"a\tb",)"
                      R"("reason":"q\"b\\s\n\r\t\b\f\u0001\u001f/)") +
              "\x7f" +
              R"(","last_applied_at":1700000100,"last_confirmed_at":1700000200})");

    // Valid UTF-8 passes through untouched.
    r.reason = "caf\xc3\xa9";
    CHECK(quarantine_record_json(r)["reason"].get<std::string>() == "caf\xc3\xa9");
}

TEST_CASE("quarantine_dump never throws on a non-UTF-8 value", "[quarantine][read_model]") {
    auto r = make_record("agent-1");
    r.reason = "bad\xff" "byte";
    std::string out;
    CHECK_NOTHROW(out = quarantine_dump(quarantine_list_data_json({r})));
    CHECK(out.find("bad") != std::string::npos);
}
