/**
 * file_search_legs.hpp -- the seam between the pure slice driver (file_search_driver.hpp) and the OS
 * shells (file_search_posix.cpp). Everything the driver needs from the world is one of these callables, so
 * the driver is proven over fakes and never runs a real process, file, thread or clock in a unit test.
 *
 *   MountReader    the mount table at or under a root and the mounts that contain it.
 *   LegFactory     one filesystem leg per searched unit (the shell builds the POSIX search leg of
 *                  component_legs.hpp with that unit's walk root and prune set).
 *   BoundedRunner  runs the slice's work on a worker thread and waits for it for a bounded time; on a
 *                  timeout the worker is left running and ABANDONED. The production binding is
 *                  shared::bounded_call_ex (bounded_wait.hpp).
 *
 * WORKER LIFETIME. The callable handed to the runner outlives the call that made it when it times out, so
 * it owns every byte it touches (values and shared_ptrs, never a reference to the caller's state) and
 * writes nothing but its own result and its own done flag.
 */
#pragma once

#include <file_search_extents.hpp>
#include <network_fstype.hpp>

#include "component_walk.hpp"
#include "file_search_volumes.hpp"

#include <chrono>
#include <functional>
#include <optional>
#include <string>

namespace yuzu::file_search {

namespace ci = yuzu::component_inventory;

/// What a matched file turned out to be when opened for its facts, and its extents when the shell read
/// them. `facts.opened` false: nothing was read and `extents` says failed.
struct FileFacts {
    ci::MatchFacts facts;
    FileExtents extents;
};

/// One unit's filesystem: the walk's listing seam, the per-match facts and the root check.
struct UnitLeg {
    ci::FsOps ops;
    std::function<FileFacts(const std::string& dir, const std::string& name)> facts;
    std::function<ci::RootState(const std::string& path)> root_state;
};

/// The mount table at or under `root` plus the mounts that contain it (a later entry for a mount point
/// covers an earlier one), or nullopt when it cannot be had in full.
using MountReader = std::function<std::optional<yuzu::shared::MountTable>(const std::string& root)>;

using LegFactory = std::function<UnitLeg(const Unit&)>;

enum class RunStatus { completed, timed_out, rejected };

/// `value` is set exactly when `status` is completed.
template <typename Result>
struct RunOutcome {
    RunStatus status{RunStatus::rejected};
    std::optional<Result> value;
};

template <typename Result>
using BoundedRunner = std::function<RunOutcome<Result>(std::chrono::milliseconds timeout, std::function<Result()> work)>;

} // namespace yuzu::file_search
