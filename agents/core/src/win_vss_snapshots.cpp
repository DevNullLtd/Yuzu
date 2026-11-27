// win_vss_snapshots.cpp -- bounded enumeration of VSS shadow copies. See
// yuzu/agent/win_vss_snapshots.hpp for why this lives in agent-core.

#include <yuzu/agent/win_vss_snapshots.hpp>

#include "win_bounded_run.hpp"

#ifdef _WIN32

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>

#include <win_com.hpp> // yuzu::shared::win::ComInit / ComPtr (agents/shared)

#if __has_include(<vsbackup.h>)
#define YUZU_AGENT_HAVE_VSS 1
#include <vss.h>
#include <vswriter.h> // both are prerequisites of vsbackup.h, in this order
#include <vsbackup.h>
#endif

#include <iterator>
#include <optional>

#include "win_str.hpp" // yuzu::win::from_wide (agents/shared)

#endif

namespace yuzu::agent::win {

namespace {

// Process-wide: one read in flight.
SingleFlightSlot& g_vss_slot = detail::new_slot();

#ifdef YUZU_AGENT_HAVE_VSS

/// RAII owner for the heap strings VSS allocates into a VSS_SNAPSHOT_PROP.
/// Next() fills a fresh property block on every iteration, so this must free
/// on every exit from the turn on which it is CONSTRUCTED. It is constructed
/// immediately after a successful fetch and BEFORE every other decision, so
/// the failed-status `break`, the cap `break`, the normal end of the walk, and
/// any check added later are all covered by construction. The one `continue`
/// -- the non-snapshot skip -- runs on a turn where no owner was constructed
/// at all; see the trade-off note at that branch.
///
/// Unwrapped manual cleanup in new C++ is a governance policy floor, not a
/// style preference.
class ScopedSnapshotProp {
public:
    explicit ScopedSnapshotProp(VSS_SNAPSHOT_PROP& p) : p_(&p) {}
    ~ScopedSnapshotProp() {
        if (p_) ::VssFreeSnapshotProperties(p_);
    }
    ScopedSnapshotProp(const ScopedSnapshotProp&) = delete;
    ScopedSnapshotProp& operator=(const ScopedSnapshotProp&) = delete;

private:
    VSS_SNAPSHOT_PROP* p_;
};

std::string guid_to_string(const GUID& g) {
    wchar_t buf[64] = {};
    if (::StringFromGUID2(g, buf, static_cast<int>(std::size(buf))) == 0) return "-";
    return yuzu::win::from_wide(buf);
}

// The walk. The apartment and every interface live and die in this frame, on the
// worker thread: nothing COM crosses the return.
//
// NO CoInitializeSecurity call: it is a process-global, once-only setting that a
// single read must not impose on the agent. Verified as SYSTEM that
// CreateVssBackupComponents/Query both succeed under a bare CoInitializeEx(MTA)
// -- exactly what yuzu::shared::win::ComInit does.
VssSnapshotsRead read_raw() {
    VssSnapshotsRead out;
    const auto failed = [&out](VssStep step, HRESULT hr) {
        out.failed_step = step;
        out.hr = static_cast<std::int32_t>(hr);
    };

    const yuzu::shared::win::ComInit com; // declared first: uninitialised after every Release
    if (!com.ok()) {
        out.failed_step = VssStep::com_init;
        return out;
    }

    yuzu::shared::win::ComPtr<IVssBackupComponents> backup;
    HRESULT hr = ::CreateVssBackupComponents(backup.put());
    if (FAILED(hr) || !backup) {
        failed(VssStep::create, hr);
        return out;
    }

    hr = backup->InitializeForBackup();
    if (FAILED(hr)) {
        failed(VssStep::initialize, hr);
        return out;
    }

    // VSS_CTX_ALL so both persistent backup snapshots and the
    // client-accessible ones behind "Previous Versions" / System Restore are
    // enumerated; the default context reports only a subset. A failure here
    // is NOT fatal -- the query still runs at the default context -- but it
    // narrows what can be seen, so it is recorded rather than swallowed.
    out.context_narrowed = FAILED(backup->SetContext(VSS_CTX_ALL));

    yuzu::shared::win::ComPtr<IVssEnumObject> snapshots;
    hr = backup->Query(GUID_NULL, VSS_OBJECT_NONE, VSS_OBJECT_SNAPSHOT, snapshots.put());
    if (FAILED(hr) || !snapshots) {
        failed(VssStep::query, hr);
        return out;
    }

    // Bound the walk. Next() is driven by a storage provider this process
    // does not control, so the loop carries its own ceiling (kMaxVssSnapshots)
    // for the same reason the filesystem_posture macOS leg caps
    // fs_snapshot_list; the cap matches that leg's so the two platforms'
    // truncation semantics stay comparable.
    //
    // The cap is counted in LOOP TURNS, not collected records. Counting records
    // would let the non-snapshot `continue` below bypass the counter entirely,
    // so a provider that yields non-snapshot objects indefinitely would spin
    // forever AND leak on every turn -- defeating the exact rationale the cap
    // is here for, since Next() is driven by code this process does not
    // control. Governance Gate 2 (security-guardian) caught this; the two
    // decisions were individually fine and wrong in combination.
    std::size_t iterations = 0;

    for (;;) {
        VSS_OBJECT_PROP prop{};
        ULONG fetched = 0;
        const HRESULT next_hr = snapshots->Next(1, &prop, &fetched);

        // `fetched`, NOT the HRESULT, decides whether the provider wrote
        // anything into `prop`. Three cases, and they are NOT interchangeable
        // (Gate 4, unhappy-path UP-2 -- an earlier revision collapsed the
        // second into the first, so an over-fetch reported a healthy EMPTY
        // host on a machine that had snapshots, and leaked the block):
        //
        //   fetched == 0  -> normal end of the walk (S_FALSE). Nothing owned.
        //   fetched  > 1  -> the enumerator ignored our celt of 1. We cannot
        //                    own or free what we cannot address, so this is an
        //                    enumeration FAILURE, never an end-of-walk.
        //   fetched == 1  -> the contract we asked for; fall through and own.
        if (fetched == 0) {
            if (FAILED(next_hr)) failed(VssStep::next, next_hr);
            break;
        }
        if (fetched != 1) {
            failed(VssStep::next, SUCCEEDED(next_hr) ? E_UNEXPECTED : next_hr);
            break;
        }

        // OWNERSHIP IS TAKEN HERE, before ANY other decision, and that
        // ordering is the whole point -- governance Gate 3 (cpp-safety and
        // cpp-expert, independently) found that an earlier revision checked
        // the walk ceiling BEFORE constructing the owner, so the truncation
        // `break` discarded a fully-populated property block that nothing ever
        // freed. Every check below is therefore safe to add: the owner is
        // already alive on every path out of this turn.
        //
        // std::optional is what makes the ownership CONDITIONAL without a
        // second owner type: ScopedSnapshotProp is non-copyable and
        // non-movable, and emplace() constructs it in place.
        const bool is_snapshot = (prop.Type == VSS_OBJECT_SNAPSHOT);
        std::optional<ScopedSnapshotProp> owner;
        if (is_snapshot)
            owner.emplace(prop.Obj.Snap);

        // A populated entry delivered alongside a failed status: own it (above)
        // and then stop.
        if (FAILED(next_hr)) {
            failed(VssStep::next, next_hr);
            break;
        }

        // Bound the WALK, counted in loop turns rather than collected records,
        // so the skip below cannot bypass the ceiling.
        if (++iterations > kMaxVssSnapshots) {
            out.truncated = true;
            break;
        }

        // Only a snapshot-typed property owns snapshot strings, so such an
        // entry is skipped and no owner was constructed for it above.
        //
        // DELIBERATE TRADE-OFF, adjudicated at governance Gate 2 by
        // security-guardian (NOT self-granted -- the policy floor on non-RAII
        // cleanup requires an adjudicator who is not the author):
        //
        // this path frees nothing, so a non-snapshot entry leaks whatever
        // strings its own union arm holds. Accepted because (a) the Query
        // above asks for VSS_OBJECT_SNAPSHOT only, so the branch is
        // unreachable in practice; (b) the alternative -- calling
        // VssFreeSnapshotProperties on a union arm that is not a
        // VSS_SNAPSHOT_PROP -- is undefined behaviour on data this process did
        // not shape; and (c) the leak is BOUNDED by the kMaxVssSnapshots walk
        // ceiling checked above, which is counted in loop turns precisely so
        // this branch cannot spin. The branch is not silent either: it
        // degrades the result (skipped_wrong_type).
        //
        // A strictly better third option exists and is deferred, not rejected:
        // switch on prop.Type and release VSS_PROVIDER_PROP's own strings with
        // CoTaskMemFree (VSS publishes no VssFreeProviderProperties). Left out
        // of this change because it is ~6 lines of untestable code on a branch
        // no query can reach; filed as a follow-up.
        if (!is_snapshot) {
            out.skipped_wrong_type = true;
            continue;
        }

        const VSS_SNAPSHOT_PROP& snap = prop.Obj.Snap;
        out.snapshots.push_back(
            {guid_to_string(snap.m_SnapshotId),
             yuzu::win::from_wide(snap.m_pwszOriginalVolumeName),
             snap.m_pwszSnapshotDeviceObject
                 ? yuzu::win::from_wide(snap.m_pwszSnapshotDeviceObject)
                 : std::string("-")});
    }
    return out;
}

#else

VssSnapshotsRead read_raw() {
    VssSnapshotsRead out;
    out.api_available = false; // not Windows, or an SDK without <vsbackup.h>
    return out;
}

#endif

} // namespace

// The driver is instantiated here so every byte the detached thread runs is agent-core text.

VssSnapshotsRead read_vss_snapshots(std::chrono::milliseconds deadline) {
    return detail::run_bounded_read<VssSnapshotsRead>(g_vss_slot, deadline, "vss_snapshots",
                                                      [] { return read_raw(); });
}

VssSnapshotsRead
read_vss_snapshots_for_test(std::chrono::milliseconds deadline,
                            const std::function<VssSnapshotsRead()>& reader) {
    return detail::run_bounded_read<VssSnapshotsRead>(g_vss_slot, deadline, "vss_snapshots",
                                                      reader);
}

} // namespace yuzu::agent::win
