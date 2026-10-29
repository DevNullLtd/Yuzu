#pragma once

/// @file fragment_states.hpp
/// The two non-data states a read-only fragment renderer is handed. Store-free by design: a
/// renderer in a TU enrolled in `STORE_DEFINITION_FREE_TUS` (`scripts/ci/check-seam-closure.py`)
/// includes this rather than `access_render.hpp`, which pulls in `rbac_store.hpp`.

namespace yuzu::server::access {

/// The store did not answer. The route logs the cause; the renderer never sees it.
struct Unavailable {};
/// Detail: the store answered and no such record exists.
struct NotFound {};

} // namespace yuzu::server::access
