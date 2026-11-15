/**
 * test_model_param_to_params.cpp: `model_detail::to_params`
 * (server/core/src/model_param_helpers.hpp), the copy routes make of `httplib::Request::params`
 * before handing it to the pure parsers.
 *
 * Pins the two things the callers rely on, so a cpp-httplib whose `Params` is not a
 * `std::multimap` (0.59: insertion-ordered) cannot change them: iteration is sorted by
 * key, and a repeated key survives as repeated entries in wire order (what `find_param`'s
 * repeated-key refusal needs).
 */

#include "../../../server/core/src/model_param_helpers.hpp"

#include <httplib.h>

#include <catch2/catch_test_macros.hpp>

#include <iterator>
#include <optional>
#include <string>
#include <utility>
#include <vector>

using yuzu::server::model_detail::find_param;
using yuzu::server::model_detail::Params;
using yuzu::server::model_detail::to_params;

namespace {
std::vector<std::pair<std::string, std::string>> flat(const Params& p) {
    return {p.begin(), p.end()};
}
} // namespace

TEST_CASE("to_params: iteration is sorted by key whatever order the request carried them in",
          "[model_param]") {
    httplib::Params wire;
    wire.emplace("pid", "1");
    wire.emplace("name", "n");
    wire.emplace("alpha", "a");

    const auto got = flat(to_params(wire));
    REQUIRE(got.size() == 3);
    CHECK(got[0].first == "alpha");
    CHECK(got[1].first == "name");
    CHECK(got[2].first == "pid");
}

TEST_CASE("to_params: a repeated key stays repeated, in wire order, and find_param refuses it",
          "[model_param]") {
    httplib::Params wire;
    wire.emplace("k", "first");
    wire.emplace("other", "x");
    wire.emplace("k", "second");

    const auto p = to_params(wire);
    const auto got = flat(p);
    REQUIRE(got.size() == 3);
    CHECK(got[0] == std::make_pair(std::string("k"), std::string("first")));
    CHECK(got[1] == std::make_pair(std::string("k"), std::string("second")));

    std::optional<std::string> err;
    CHECK(find_param(p, "k", err) == nullptr);
    CHECK(err.has_value());

    err.reset();
    const auto* one = find_param(p, "other", err);
    REQUIRE(one != nullptr);
    CHECK(*one == "x");
    CHECK_FALSE(err.has_value());
}

TEST_CASE("to_params: an empty request yields an empty bag", "[model_param]") {
    CHECK(to_params(httplib::Params{}).empty());
}
