#pragma once

/// @file test_schedule_api_double.hpp
/// FnScheduleApi — a test-only `ScheduleApi` adapter backed by a plain
/// `std::function`, mirroring `FnVerifyApi`/`FnDexPerfApi`. Lets a route/MCP
/// test inject an ARBITRARY `list_schedules` result — including a store
/// FAILURE (`std::unexpected`) — without standing up a real
/// `ScheduleEngine`/Postgres connection. Before the `ScheduleApi` seam
/// existed, no test harness could inject a store failure into the dashboard
/// fragment at all (it called `ScheduleEngine::query_schedules()` directly,
/// which never returns an error), so this double is what makes the
/// degraded-path behaviour delta (see `schedule_types.hpp`'s
/// `ScheduleListResult` doc comment) testable in the first place.
///
/// NOT for production use — the production factory is
/// `make_local_schedule_api` (schedule_api_local.hpp).

#include "schedule_api.hpp"

#include <functional>
#include <utility>

namespace yuzu::server::test {

class FnScheduleApi final : public yuzu::server::ScheduleApi {
public:
    using Fn = std::function<std::expected<yuzu::server::ScheduleListResult, std::string>(
        const yuzu::server::ScheduleQuery&)>;

    explicit FnScheduleApi(Fn fn) : fn_(std::move(fn)) {}

    [[nodiscard]] std::expected<yuzu::server::ScheduleListResult, std::string>
    list_schedules(const yuzu::server::ScheduleQuery& q) const override {
        if (!fn_)
            return std::unexpected(std::string{"FnScheduleApi: unwired"});
        return fn_(q);
    }

private:
    Fn fn_;
};

} // namespace yuzu::server::test
