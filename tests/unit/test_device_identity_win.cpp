/**
 * test_device_identity_win.cpp -- the pure Windows `domain` decision
 * (device_identity_win.hpp). Runs on every host.
 */

#include "device_identity_win.hpp"

#include <catch2/catch_test_macros.hpp>

#include <cstdint>
#include <string>
#include <vector>

using yuzu::agent::BoundedStatus;
using yuzu::agent::win::JoinInfoRead;
using yuzu::device_identity::win::domain_answer;
using Rows = std::vector<std::string>;

namespace {

JoinInfoRead answered(std::string name, std::uint32_t join_status) {
    return {BoundedStatus::Completed, 0, true, std::move(name), join_status};
}

} // namespace

TEST_CASE("domain_answer: joined is true only for a domain join", "[device_identity][win]") {
    for (std::uint32_t join_status = 0; join_status <= 4; ++join_status) {
        const auto a = domain_answer(answered("corp.example.com", join_status));
        CHECK(a.rc == 0);
        CHECK(a.rows ==
              Rows{"domain|corp.example.com", join_status == 3 ? "joined|true" : "joined|false"});
    }
}

TEST_CASE("domain_answer: an empty name reads N/A", "[device_identity][win]") {
    const auto a = domain_answer(answered("", 3));
    CHECK(a.rc == 0);
    CHECK(a.rows == Rows{"domain|N/A", "joined|true"});
}

TEST_CASE("domain_answer: an answered failure reads N/A and false at rc 0",
          "[device_identity][win]") {
    const JoinInfoRead failed{BoundedStatus::Completed, 5, true, "ignored", 3};
    const JoinInfoRead nameless{BoundedStatus::Completed, 0, false, "ignored", 3};
    for (const auto& read : {failed, nameless}) {
        const auto a = domain_answer(read);
        CHECK(a.rc == 0);
        CHECK(a.rows == Rows{"domain|N/A", "joined|false"});
    }
}

TEST_CASE("domain_answer: an unanswered read gives no rows and rc 1", "[device_identity][win]") {
    for (const auto status : {BoundedStatus::TimedOut, BoundedStatus::Busy,
                              BoundedStatus::Abandoned, BoundedStatus::Rejected}) {
        auto read = answered("corp.example.com", 3);
        read.status = status;
        const auto a = domain_answer(read);
        CHECK(a.rc == 1);
        CHECK(a.rows.empty());
    }
}
