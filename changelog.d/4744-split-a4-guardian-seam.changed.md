- Internal: added the in-process `GuardianApi` seam for the Guardian / Guaranteed State read
  surface (ADR-0031 WS-A4, the ninth per-family seam) — a store-type-free abstract
  `guardian_api.hpp` covering `GET /api/v1/guaranteed-state/{rules,rules/{id},status,
  status/{agent_id},rules/{id}/status,agents/{id}/rules,device-compliance,events}` (eight of the
  family's nine public REST resources; `GET /guaranteed-state/schemas` is a compiled-in, store-free
  catalog left outside the seam), plus their MCP twins `list_guardian_rules`/`get_guardian_rule`/
  `get_guardian_status`/`get_guardian_agent_status`/`get_guardian_rule_status`/
  `get_guardian_device_guards`/`get_guardian_device_compliance`/`list_guardian_events`, all routed
  through the same seam calls so their JSON shapes cannot drift, a core-only
  `make_local_guardian_api` factory, and a `LocalGuardianApi` implementation wrapping
  `GuaranteedStateStore::list_rules`/`get_rule`/`query_events` and the five shared
  `guardian_model.hpp` functions unmodified. `GuaranteedStateRuleRow`/`GuaranteedStateEventRow`/
  `GuaranteedStateEventQuery`/`GuaranteedStateReadError` relocated out of
  `guaranteed_state_store.hpp`, and the six pre-existing pure result structs (including the nested
  `GuardianDeviceComplianceGuardRow`) relocated out of
  `guardian_model.hpp`, into a pure `guardian_types.hpp`. Both backing stores are nullable at the
  seam (seven of the eight methods need only `GuaranteedStateStore`; only `device_compliance` needs
  `BaselineStore` too), each method degrading individually when its own dependency is absent — the
  rule/baseline mutators (`guardian_routes.cpp`) and the `/fragments/device/guardian` dashboard lens
  (`device_lens_routes.cpp`) keep their existing direct store access, deliberately untouched.
