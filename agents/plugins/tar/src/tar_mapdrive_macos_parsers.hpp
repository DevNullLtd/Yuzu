#pragma once

// tar_mapdrive_macos_parsers.hpp -- pure classifier for the macOS getfsstat
// mapped-drive leg (capability-map §3.8 outbound live). Header-only, no I/O:
// the impure getfsstat(2) wrapper in tar_mapdrive_collector.cpp gathers raw
// mount records and hands them here; this maps them onto the MapDriveEntry
// contract (tar_collectors.hpp) so the mapping is unit-testable off fixture
// data, the same pattern as this collector's other pure parsers
// (parse_proc_mounts / parse_fstab / parse_smbstatus / ...).
//
// remote_host_of (tar_mapdrive_collector.cpp) lives in that translation
// unit's anonymous namespace, unreachable from a header this file's unit test
// also includes directly -- so it is injected as `resolve_host` rather than
// called by name: the collector passes the real remote_host_of, tests pass
// their own fixture-equivalent stand-in. This keeps the header free of any
// dependency on the collector's internals.

#include <functional>
#include <string>
#include <utility> // std::move
#include <vector>

#include "tar_collectors.hpp"

namespace yuzu::tar {

// One raw macOS mount record, as read by getfsstat(2). Field names mirror
// struct statfs (f_fstypename / f_mntfromname / f_mntonname) so the mapping
// in classify_macos_mounts is a direct visual match to the kernel struct the
// impure wrapper reads.
struct MacMountRec {
    std::string fstype; // f_fstypename, e.g. "nfs", "smbfs", "cifs", "afpfs", "webdav", "apfs"
    std::string from;   // f_mntfromname -- the remote spec, e.g. "//user@host/share"
    std::string on;     // f_mntonname -- the local mount point
};

/**
 * Classify raw getfsstat mount records into outbound MapDriveEntry rows.
 * Filters to the network fstypes {nfs, smbfs, cifs, afpfs, webdav}; every
 * other fstype (apfs, devfs, autofs, tmpfs, ...) is dropped. Populates every
 * MapDriveEntry field: direction="outbound" (macOS's getfsstat can only see
 * mounts this host initiated), local_mount=on, remote_path=from,
 * remote_host=resolve_host(from), username="" (unavailable via getfsstat,
 * same as the Linux /proc/mounts leg), provider mapped from fstype
 * (smbfs/cifs -> "SMB", nfs -> "NFS", afpfs -> "AFP", webdav -> "WebDAV").
 * Does NOT apply kMapDriveEntryCap -- the collector applies that (and its
 * warn-once latch) after this call, matching the Linux leg's shape.
 */
inline std::vector<MapDriveEntry>
classify_macos_mounts(const std::vector<MacMountRec>& mounts,
                      const std::function<std::string(const std::string&)>& resolve_host) {
    std::vector<MapDriveEntry> out;
    out.reserve(mounts.size());
    for (const auto& m : mounts) {
        std::string provider;
        if (m.fstype == "smbfs" || m.fstype == "cifs")
            provider = "SMB";
        else if (m.fstype == "nfs")
            provider = "NFS";
        else if (m.fstype == "afpfs")
            provider = "AFP";
        else if (m.fstype == "webdav")
            provider = "WebDAV";
        else
            continue; // not a network fstype we track -- e.g. apfs, devfs, autofs, tmpfs

        MapDriveEntry e;
        e.direction = "outbound";
        e.local_mount = m.on;
        e.remote_path = m.from;
        e.remote_host = resolve_host(m.from);
        e.username = ""; // unavailable via getfsstat, like the Linux leg
        e.provider = provider;
        out.push_back(std::move(e));
    }
    return out;
}

/**
 * Truncate `entries` to at most `cap` rows, returning true iff it truncated.
 * Split out of the collector's enumerate_mapdrive so the cap-and-warn
 * decision (kMapDriveEntryCap parity with the Linux leg at
 * tar_mapdrive_collector.cpp:1019-1026) is pure and unit-testable by feeding
 * constructed records directly, independent of the impure getfsstat call —
 * the collector calls this and only owns the warn-once logging side effect.
 */
inline bool apply_entry_cap(std::vector<MapDriveEntry>& entries, std::size_t cap) {
    if (entries.size() <= cap)
        return false;
    entries.resize(cap);
    return true;
}

/// Outcome of run_getfsstat_with_retry -- `ok=false` means "not a genuinely
/// empty/smaller mount table", the same distinction classify_subprocess_
/// capture's tool_ran/timed_out/output_truncated preserves for the
/// subprocess legs: the caller must throw IncompleteCaptureError, never
/// diff/persist `mounts` as though it were complete.
struct GetfsstatFetchOutcome {
    std::vector<MacMountRec> mounts;
    bool ok{true};
};

/**
 * Bounded size-then-fill retry loop over an injectable getfsstat(2)
 * count/fill pair (BR-002/BR-006).
 *
 * getfsstat(2)'s documented contract is that a bounded call fills the
 * buffer "up to the size specified by bufsize" -- it has no resume handle
 * and no way to report "there were more than fit". So if a mount appears
 * between the size-only count call and the fill call, the fill can end up
 * exactly consuming the buffer for either of two indistinguishable reasons:
 * the count was exact, or the table grew and got truncated. Padding the
 * allocation by one spare slot (`capacity = n + 1`) turns that ambiguity
 * into a detectable signal: a fill that reaches `capacity` can only mean
 * growth-with-truncation (an exact match would leave the spare slot
 * unfilled), so it is treated as churn and retried with a fresh count/size
 * rather than accepted as a complete snapshot -- bounded at `max_attempts`
 * before giving up (`ok=false`) so the caller retains the previous baseline
 * instead of persisting a partial table as though every un-refetched mount
 * had vanished.
 *
 * `cap` bounds the raw kernel-reported count BEFORE any allocation
 * (BR-006): an `n >= cap` short-circuits to `ok=false` rather than
 * allocate/copy/translate a raw table sized by an unbounded kernel-reported
 * count on a host with an abnormally large mount table -- the collector's
 * own post-filter kMapDriveEntryCap check (apply_entry_cap, above) still
 * applies to the classified/filtered result on the ordinary path, but ties
 * the resource bound only to a table that already fit in the raw copy.
 *
 * `count_fn`/`fill_fn` are injected (same seam as classify_macos_mounts'
 * `resolve_host` parameter above) so this exact retry algorithm is
 * unit-testable against synthetic count/fill sequences -- exactly-full,
 * grew-then-stabilized, and give-up-after-max-attempts -- without a live
 * macOS mount table or a stand-in reimplementation of the logic under test.
 * `count_fn` returns getfsstat(nullptr, 0, ...)'s count, or a negative
 * value on an errno failure. `fill_fn` is handed the padded capacity for
 * the next attempt and must either return a negative value on failure, or
 * populate `out_mounts` with exactly the filled records and return that
 * count (which run_getfsstat_with_retry compares against `capacity` to
 * detect the exactly-full case -- `fill_fn` itself does not decide that).
 */
inline GetfsstatFetchOutcome run_getfsstat_with_retry(
    const std::function<int()>& count_fn,
    const std::function<int(std::size_t capacity, std::vector<MacMountRec>& out_mounts)>& fill_fn,
    std::size_t cap, int max_attempts = 4) {
    for (int attempt = 0; attempt < max_attempts; ++attempt) {
        const int n = count_fn();
        if (n < 0)
            return GetfsstatFetchOutcome{.mounts = {}, .ok = false};
        if (n == 0)
            return GetfsstatFetchOutcome{}; // genuinely no mounts -- ok, empty

        if (static_cast<std::size_t>(n) >= cap) {
            // The raw kernel-reported count already meets/exceeds the entry
            // cap -- don't allocate/copy/translate an unbounded raw table;
            // the caller's IncompleteCaptureError path retains the previous
            // baseline exactly as an over-cap classified result would.
            return GetfsstatFetchOutcome{.mounts = {}, .ok = false};
        }

        const std::size_t capacity = static_cast<std::size_t>(n) + 1; // headroom slot
        std::vector<MacMountRec> mounts;
        const int filled = fill_fn(capacity, mounts);
        if (filled < 0)
            return GetfsstatFetchOutcome{.mounts = {}, .ok = false};
        if (filled == 0)
            return GetfsstatFetchOutcome{}; // vanished between calls -- genuinely empty this tick
        if (static_cast<std::size_t>(filled) == capacity)
            continue; // exactly filled the padded buffer -- churn, retry
        return GetfsstatFetchOutcome{.mounts = std::move(mounts), .ok = true};
    }
    // Unstable across every retry -- give up rather than loop forever
    // against a pathologically churning mount table; the caller throws
    // IncompleteCaptureError and retains the previous baseline.
    return GetfsstatFetchOutcome{.mounts = {}, .ok = false};
}

} // namespace yuzu::tar
