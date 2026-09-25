#include "schedule_api_local.hpp"

#include "schedule_engine.hpp"

namespace yuzu::server {

/// Store-backed `ScheduleApi` implementation — a thin wrap of
/// `ScheduleEngine::query_schedules_checked` (ADR-0031 WS-A4, seventh
/// family). Behaviour preserved exactly: the honest store-failure-vs-empty
/// distinction and the `truncated` cap flag that `query_schedules_checked`
/// already provided to REST v1/MCP now also reach the dashboard fragment,
/// which previously called the unchecked `query_schedules()` — a deliberate,
/// disclosed behaviour delta (see `schedule_types.hpp`'s
/// `ScheduleListResult` doc comment and the matrix doc's `schedule` family
/// row).
class LocalScheduleApi final : public ScheduleApi {
public:
    explicit LocalScheduleApi(ScheduleEngine& engine) : engine_(engine) {}

    LocalScheduleApi(const LocalScheduleApi&) = delete;
    LocalScheduleApi& operator=(const LocalScheduleApi&) = delete;

    [[nodiscard]] std::expected<ScheduleListResult, std::string>
    list_schedules(const ScheduleQuery& q) const override {
        return engine_.query_schedules_checked(q);
    }

private:
    ScheduleEngine& engine_;
};

std::shared_ptr<ScheduleApi> make_local_schedule_api(ScheduleEngine& engine) {
    return std::make_shared<LocalScheduleApi>(engine);
}

} // namespace yuzu::server
