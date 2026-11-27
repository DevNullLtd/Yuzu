#pragma once

// dispatch_announcement.hpp -- #2673: how ONE send tells its run about the device list.
//
// Every fan-out that records a run's targets goes through this (`wire_and_dispatch_confined` and
// the software-sync push), so the rules exist once:
//   1. announce BEFORE anything is sent, so an unrecorded send cannot let the run read
//      `succeeded`;
//   2. only a send whose announcement was stored may close an attempt that named nobody: an open
//      attempt it did not announce is somebody else's;
//   3. a list saved by an unannounced send is marked incomplete: it cannot tell whether an
//      earlier list was never saved.
// There is deliberately no destructor action: a send that throws must leave the attempt open.

#include "execution_tracker.hpp"

#include <spdlog/spdlog.h>

#include <string>
#include <string_view>
#include <vector>

namespace yuzu::server {

class DispatchAnnouncement {
public:
    /// Announces at once. Inert when `tracker` is null or `execution_id` is empty (an untracked
    /// dispatch). `caller` names the fan-out in log lines.
    DispatchAnnouncement(ExecutionTracker* tracker, const std::string& execution_id,
                         std::string_view caller)
        : tracker_(execution_id.empty() ? nullptr : tracker), execution_id_(execution_id),
          caller_(caller),
          announced_(tracker_ != nullptr && tracker_->mark_targets_expected(execution_id_)) {
        if (tracked() && !announced_)
            spdlog::warn("{}: could not mark execution_id={} as awaiting its target list",
                         caller_, execution_id_);
    }
    DispatchAnnouncement(const DispatchAnnouncement&) = delete;
    DispatchAnnouncement& operator=(const DispatchAnnouncement&) = delete;

    [[nodiscard]] bool tracked() const noexcept { return tracker_ != nullptr; }

    /// Call once the send has RETURNED. `reached_nobody`: it named no device and sent nothing, so
    /// there is no list to save, and leaving the attempt open would make a later, successful
    /// re-drive read as incomplete.
    void close_if_empty(bool reached_nobody) {
        if (announced_ && reached_nobody && !tracker_->close_empty_attempt(execution_id_))
            spdlog::warn("{}: could not close the empty send of execution_id={}", caller_,
                         execution_id_);
    }

    /// Saves this send's device list. `partial_list`: the devices may not all be listed. False
    /// when nothing was saved for a tracked run; true for an untracked dispatch.
    [[nodiscard]] bool record(const std::vector<DispatchTarget>& targets, bool connected_only,
                              bool partial_list) {
        if (!tracked())
            return true;
        return tracker_->record_dispatch_targets(execution_id_, targets, connected_only,
                                                 /*complete=*/announced_ && !partial_list);
    }

private:
    ExecutionTracker* tracker_;
    std::string execution_id_;
    std::string caller_;
    bool announced_;
};

} // namespace yuzu::server
