// macos_dataless_off.hpp -- switch OFF dataless materialisation for the calling thread, restored on exit.
//
// Dataless (iCloud / File Provider) files and directories must not be materialised by a walk: the
// download runs inside a read the deadline cannot interrupt. The policy is per THREAD and a walk runs on a
// shared or detached worker thread, so it is read, switched OFF for the walk and restored on every exit
// path. With it off a dataless file or directory fails its open with EDEADLK, which a walk already counts
// as unreadable, and a dataless directory is refused by the directory open before the iterator names its
// children.
//
// Shared by every plugin whose walk must stay local to the disk (filesystem find_by_hash, file_search).
// Apple only; header-only, no state beyond the object.
#pragma once

#if defined(__APPLE__)

#include <sys/resource.h> // getiopolicy_np / setiopolicy_np

namespace yuzu::shared {

class DatalessMaterializationOff {
public:
    DatalessMaterializationOff() {
        previous_ = ::getiopolicy_np(IOPOL_TYPE_VFS_MATERIALIZE_DATALESS_FILES, IOPOL_SCOPE_THREAD);
        if (previous_ < 0)
            previous_ = IOPOL_MATERIALIZE_DATALESS_FILES_DEFAULT;
        changed_ = ::setiopolicy_np(IOPOL_TYPE_VFS_MATERIALIZE_DATALESS_FILES, IOPOL_SCOPE_THREAD,
                                    IOPOL_MATERIALIZE_DATALESS_FILES_OFF) == 0;
    }
    ~DatalessMaterializationOff() {
        if (changed_)
            ::setiopolicy_np(IOPOL_TYPE_VFS_MATERIALIZE_DATALESS_FILES, IOPOL_SCOPE_THREAD, previous_);
    }
    DatalessMaterializationOff(const DatalessMaterializationOff&) = delete;
    DatalessMaterializationOff& operator=(const DatalessMaterializationOff&) = delete;

private:
    int previous_ = IOPOL_MATERIALIZE_DATALESS_FILES_DEFAULT;
    bool changed_ = false;
};

} // namespace yuzu::shared

#endif // defined(__APPLE__)
