#pragma once

/**
 * wua_noop_callback.hpp -- agent-core-owned, process-lifetime no-op WUA
 * ISearchCompletedCallback singleton.
 *
 * IUpdateSearcher::BeginSearch() requires a live ISearchCompletedCallback*,
 * but a caller that polls ISearchJob::IsCompleted directly (the shape
 * ADR-3002 requires -- see wmi_bounded.hpp's equivalent WMI bound) never
 * needs the completion notification to actually fire. WUA is documented to
 * hold its own reference to the callback object for as long as the async
 * operation is outstanding -- Microsoft's "Guidelines for Asynchronous WUA
 * Operations": wait for the callback's refcount to return to its starting
 * value before destroying it -- and that reference can outlive a bounded
 * RequestAbort()/timeout on the caller's side. A callback object allocated
 * inside a PLUGIN's own module is therefore unsafe to hand to BeginSearch():
 * if the plugin is dlclose()'d/FreeLibrary()'d while WUA still holds a
 * reference, any later Invoke()/AddRef()/Release() call dispatches through
 * a vtable in unmapped memory.
 *
 * This singleton's vtable lives in the agent's own core library instead --
 * yuzu_agent_core_lib is linked directly into the yuzu-agent executable and
 * is never dlclose()'d (same "lives in agent-core, not a plugin" reasoning
 * as subprocess_runner.hpp's detached reaper) -- so a WUA call into it after
 * ANY plugin unloads remains valid. AddRef()/Release() are permanent no-ops
 * that never destroy the instance: it is meant to live for the whole
 * process, so there is no real refcount to track and nothing to protect
 * against being over/under-released.
 *
 * Windows-only by construction (#ifdef _WIN32); the header is empty
 * elsewhere.
 */

#ifdef _WIN32

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>
#include <wuapi.h> // ISearchCompletedCallback

#include <yuzu/plugin.h> // YUZU_EXPORT

namespace yuzu::agent {

/// Returns a live, process-lifetime ISearchCompletedCallback* whose
/// Invoke() does nothing and whose AddRef()/Release() never destroy the
/// object -- safe to pass to IUpdateSearcher::BeginSearch() from any
/// plugin that polls the search job directly and never needs the
/// completion notification itself. The returned pointer is never null and
/// remains valid for the life of the agent process, even past any
/// individual plugin's own unload. Declared here, DEFINED OUT-OF-LINE in
/// wua_noop_callback.cpp -- same split as subprocess_runner.hpp/.cpp -- so
/// the singleton's vtable compiles only into that pinned image, never into
/// an including plugin.
YUZU_EXPORT ISearchCompletedCallback* wua_noop_search_completed_callback();

} // namespace yuzu::agent

#endif // _WIN32
