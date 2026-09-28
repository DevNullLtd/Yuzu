- **Corrected stale source-path references across the docs and agent instructions.** Cited
  paths named files that do not exist: `cert_store.cpp` (the agent "Key Files" lists placed it under
  `server/core/src/`; it is agent-side, and the security review list now names the internal-CA files
  instead), `sdk/src/sdk_utilities.cpp` (now the header plus `agents/core/src/sdk_utilities.cpp`),
  `rbac.cpp` / `session_manager.cpp` / two `metrics.cpp` files (cited under names that never existed;
  the code lives in `rbac_store.cpp`, `auth.cpp` / `session_store.cpp` and the header-only
  `metrics.hpp`), the auth test-pattern references (`tests/unit/test_auth_db.cpp` never existed), the
  gateway Python harness (`scripts/`, not `gateway/`), the Chrome-IR chain fixture
  (`tests/unit/server/`, not `tests/integration/`), `sdk/README.md`'s `include/yuzu/sdk.hpp` row (a
  header the SDK never shipped) and the Codex auth skill's `.codex/agents/` links (now
  `.claude/agents/`). `docs/scope-walking-design.md` no longer claims that result-set audit rows
  carry parent and result ids: that is design intent tracked in #4088, and the document now states
  which walkthrough steps the Chrome-IR fixture actually covers. `sdk/README.md` now states that
  only `plugin.h` is ABI-stable; `plugin.hpp` and the helper headers carry no stability promise.
