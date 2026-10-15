#pragma once

/// @file workflow_api_local.hpp
/// CORE-ONLY. The store-backed factory for the workflow-read seam (ADR-0031
/// WS-A4, eighth family, mirroring `schedule_api_local.hpp` /
/// `verify_api_local.hpp` / `network_api_local.hpp`). Included by server.cpp
/// (wiring), the impl (workflow_api.cpp) and the tests — NEVER by a
/// presentation/renderer/route TU; the seam-closure lint forbids
/// `*_api_local.hpp` in the family's enforced presentation TUs so the
/// abstract/local boundary is enforced, not conventional.
///
/// Store types stay FORWARD-DECLARED here (zero store `#include`s) — this
/// header is the core side of the seam, not the store layer. That purity is
/// lint-enforced: this header is itself in the family's enforced closure set,
/// so a store `#include` added here fails CI.

#include <memory>

#include "workflow_api.hpp"

namespace yuzu::server {

class WorkflowEngine;

/// Factory for the store-backed implementation (`LocalWorkflowApi`,
/// workflow_api.cpp — kept out of the abstract header so that header stays
/// free of store references entirely).
///
/// `engine` is a REFERENCE, not nullable — mirrors the seam's caller
/// convention: every consumer already guards its own store-unavailable
/// 503/error BEFORE reaching the API (the pre-seam `if (!workflow_engine)
/// {...}` checks, replaced at each call site by an equivalent `if
/// (!workflow_api) {...}` check), so `make_local_workflow_api` is only ever
/// called once the engine is known live — same posture as
/// `make_local_schedule_api`. A caller wiring this seam unconditionally
/// (server.cpp) is responsible for that same null-guard before calling this
/// factory; see server.cpp's own `workflow_engine_` construction-gate
/// comment.
///
/// LIFETIME CONTRACT (load-bearing, mirrors schedule_api_local.hpp/
/// verify_api_local.hpp/network_api_local.hpp): `engine` is borrowed, NOT
/// owned — it MUST outlive every call to the returned API. `ServerImpl`
/// guarantees this by joining the web thread (`web_server_->stop()`) before
/// destroying `workflow_engine_`.
[[nodiscard]] std::shared_ptr<WorkflowApi> make_local_workflow_api(WorkflowEngine& engine);

} // namespace yuzu::server
