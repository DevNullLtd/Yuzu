#pragma once

/// @file schedule_api_local.hpp
/// CORE-ONLY. The store-backed factory for the schedule-read seam (ADR-0031
/// WS-A4, seventh family, mirroring `verify_api_local.hpp` /
/// `network_api_local.hpp`). Included by server.cpp (wiring), the impl
/// (schedule_api.cpp) and the tests — NEVER by a presentation/renderer/route
/// TU; the seam-closure lint forbids `*_api_local.hpp` in the family's
/// enforced presentation TUs so the abstract/local boundary is enforced, not
/// conventional.
///
/// Store types stay FORWARD-DECLARED here (zero store `#include`s) — this
/// header is the core side of the seam, not the store layer. That purity is
/// lint-enforced: this header is itself in the family's enforced closure set,
/// so a store `#include` added here fails CI.

#include <memory>

#include "schedule_api.hpp"

namespace yuzu::server {

class ScheduleEngine;

/// Factory for the store-backed implementation (`LocalScheduleApi`,
/// schedule_api.cpp — kept out of the abstract header so that header stays
/// free of store references entirely).
///
/// `engine` is a REFERENCE, not nullable — mirrors the seam's caller
/// convention: every one of the three consumers (dashboard fragment, REST
/// v1, MCP) already guards its own store-unavailable 503/error BEFORE
/// reaching the API (the pre-seam `if (!schedule_engine) {...}` checks,
/// preserved unchanged at each call site), so `make_local_schedule_api` is
/// only ever called once the engine is known live — same posture as
/// `make_local_compliance_api`. A caller wiring this seam unconditionally
/// (server.cpp) is responsible for that same null-guard before calling this
/// factory; see server.cpp's own `schedule_engine_` construction-gate
/// comment.
///
/// LIFETIME CONTRACT (load-bearing, mirrors verify_api_local.hpp/
/// network_api_local.hpp): `engine` is borrowed, NOT owned — it MUST outlive
/// every call to the returned API. `ServerImpl` guarantees this by joining
/// the web thread (`web_server_->stop()`) before destroying
/// `schedule_engine_`, the SAME ordering `ScheduleRunner`'s own borrow of
/// `schedule_engine_` already relies on.
[[nodiscard]] std::shared_ptr<ScheduleApi> make_local_schedule_api(ScheduleEngine& engine);

} // namespace yuzu::server
