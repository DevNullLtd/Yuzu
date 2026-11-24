/**
 * file_search_win.cpp -- the Windows shell of the file_search plugin: the one volume that holds the root, the
 * leg of the searched unit over confined_fs, the facts of a matched file with the two ioctls, the name rule,
 * the cursor key and the worker environment, bound to the neutral shell through file_search_os.hpp. It binds
 * Win32 and NT calls to the pure rules of file_search_win_rules.hpp and DECIDES NOTHING itself: every
 * classification, status reading and mapping is a function there, unit-tested on every OS. Self-gated to
 * Windows (empty elsewhere, where file_search_posix.cpp binds the same names).
 *
 * WALK AND EXTENTS ONLY. No NTFS metadata enumeration. A Windows walk never crosses a volume: a mount point
 * is a reparse entry and is skipped, so the plan holds ONE unit, the volume of the root.
 *
 * THE PLUGIN OPENS NOTHING BY PATH. The volume root is opened by its GUID path with confined_fs::open_root
 * (so a drive letter re-pointed between slices cannot move it) and every directory below it, every hop of the
 * root path included, with confined_fs::open_dir_at: parent-handle-relative, no reparse followed, long paths
 * work. The only file open is confined_fs::open_file_attributes_at. No label is ever handed to the OS.
 *
 * WHAT KEEPS A SEARCH FROM RECALLING A CLOUD PLACEHOLDER (measured; the invariant, stated once). No open flag
 * is relied on: FILE_OPEN_NO_RECALL was measured to protect nothing (a read on such a handle hydrated the
 * file, and enumerating such a directory handle populated it) and is sent on no open. Safety rests on four
 * rules. (i) Every file handle is attribute-only, so it can neither read nor hydrate. (ii) The LISTING
 * attributes decide before any open: nothing marked recall-on-open, recall-on-data-access or offline is
 * opened, enumerated or read (a file reads unsupported:placeholder, a folder is a dataless gap). (iii) A
 * directory's attributes and tag are re-read on the OPENED handle before any enumeration (inside confined_fs
 * for a tagged directory, here for an untagged one), and a handle that fails is closed unread. (iv) Every
 * directory, cloud or ordinary, is opened in the one existing form. An open alone was measured to cause no
 * provider callback of any kind. THE WINDOW THAT IS LEFT: between the recheck and the first enumeration call
 * on one handle, a provider can turn a populated folder back into a not-populated one, and no enumeration
 * mode refuses population. Its worst case is that the provider fills in that ONE folder's entries (names and
 * metadata, never file content: no file handle carries a data right), or, with no provider running, that the
 * listing fails with ERROR_CLOUD_FILE_PROVIDER_NOT_RUNNING, which reads dataless. A provider that never
 * answers the population callback blocks that one enumeration: the slice runs to its bound, the worker is
 * abandoned and the volume reads stalled until the call returns (the driver's abandon path). A recall-on-open
 * folder named on the ROOT PATH is opened (never listed) because no listing precedes a root hop and a handle does
 * not report that bit; opening was measured harmless for a recall-on-data-access folder, a recall-on-open one
 * was not measured.
 *
 * THE TWO IOCTLS, both on the attribute-only handle, once per matched file whose decision says `ioctl`:
 * FSCTL_GET_EXTERNAL_BACKING first (a CompactOS/WOF file lists as a plain file and its retrieval pointers
 * read as ONE hole, so backing is ruled out before any extent is trusted), then
 * FSCTL_GET_RETRIEVAL_POINTERS (one call, no paging). The shell passes GetLastError() verbatim and the pure
 * rules decide the status.
 *
 * NOTHING BEFORE THE WORKER. os_make_leg is allocation only; its handles and the cluster size are opened
 * lazily on first use. The driver builds the leg, and reads the profile roots, on the slice's worker. The
 * bounded volume query below is the only filesystem or registry call made before the worker: it runs on the
 * pool thread after the cursor is authenticated and the slot is taken.
 */
#include "file_search_execute.hpp"

#if defined(_WIN32)

#include "file_search_win_rules.hpp"

#include <bounded_wait.hpp>
#include <user_profile_model.hpp>
#include <win_profiles.hpp>
#include <win_str.hpp>
#include <win_thread_error_mode.hpp>

#include <yuzu/agent/confined_fs.hpp>

#include <winioctl.h> // after <windows.h>: the control codes and the retrieval-pointer structures

#include <bcrypt.h>

#include <algorithm>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <filesystem>
#include <memory>
#include <optional>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

#pragma comment(lib, "bcrypt")

namespace yuzu::file_search {

namespace wr = win_rules;
namespace cfs = yuzu::agent::confined_fs;

// ---- the platform ----

const Os kOs = Os::windows;
// A literal: the catch-all must answer without allocating outside its own guarded calls.
const std::string_view kExceptionProvenance = "windows:file_search:exception";

std::expected<std::string, RequestError> os_normalise_root(std::string_view raw) {
    return wr::normalise_windows_root(raw);
}

// ---- the cursor key ----

bool os_draw_cursor_key(CursorKey& key) noexcept {
    if (::BCryptGenRandom(nullptr, key.data(), static_cast<ULONG>(key.size()), BCRYPT_USE_SYSTEM_PREFERRED_RNG) == 0)
        return true;
    key.fill(0); // never leave a partial draw behind
    return false;
}

// ---- the worker ----

/// Runs inside the worker thread for the whole call of `body`: hard-error dialogs suppressed for this thread
/// (a not-ready volume would otherwise block it), and background priority for the thread's CPU and I/O. Both
/// end when `body` returns (the error mode by its guard, background mode by the END call below), so the
/// environment lasts exactly as long as `body` on any thread, pooled or fresh.
void os_in_worker_environment(const std::function<void()>& body) {
    const yuzu::win::ThreadErrorModeGuard errors(SEM_FAILCRITICALERRORS);
    struct BackgroundMode {
        bool begun;
        BackgroundMode() : begun(::SetThreadPriority(::GetCurrentThread(), THREAD_MODE_BACKGROUND_BEGIN) != 0) {}
        BackgroundMode(const BackgroundMode&) = delete; // a copy would end the mode twice
        BackgroundMode& operator=(const BackgroundMode&) = delete;
        ~BackgroundMode() {
            if (begun)
                (void)::SetThreadPriority(::GetCurrentThread(), THREAD_MODE_BACKGROUND_END);
        }
    } background;
    body();
}

// ---- names ----

namespace {

[[nodiscard]] std::string windows_upcase(std::string_view name) {
    if (std::ranges::all_of(name, [](unsigned char c) { return c < 0x80; })) {
        std::string out(name);
        for (auto& c : out)
            if (c >= 'a' && c <= 'z')
                c = static_cast<char>(c - 'a' + 'A');
        return out;
    }
    // Not ASCII: strict UTF-8 to UTF-16, the invariant locale's upper-casing, back to UTF-8. Any failure
    // leaves the bytes as they are (a name that cannot be converted compares as the bytes it is).
    const int wide_len = ::MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, name.data(), static_cast<int>(name.size()),
                                               nullptr, 0);
    if (wide_len <= 0)
        return std::string(name);
    std::wstring wide(static_cast<std::size_t>(wide_len), L'\0');
    if (::MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, name.data(), static_cast<int>(name.size()), wide.data(),
                              wide_len) != wide_len)
        return std::string(name);
    const int up_len = ::LCMapStringEx(LOCALE_NAME_INVARIANT, LCMAP_UPPERCASE, wide.data(), wide_len, nullptr, 0, nullptr,
                                       nullptr, 0);
    if (up_len <= 0)
        return std::string(name);
    std::wstring upper(static_cast<std::size_t>(up_len), L'\0');
    if (::LCMapStringEx(LOCALE_NAME_INVARIANT, LCMAP_UPPERCASE, wide.data(), wide_len, upper.data(), up_len, nullptr,
                        nullptr, 0) != up_len)
        return std::string(name);
    std::string out = yuzu::win::from_wide(upper.data(), up_len);
    return out.empty() ? std::string(name) : out;
}

} // namespace

fsr::NameSemantics os_name_semantics() {
    return {"windows_upcase_v1", [](std::string_view s) { return windows_upcase(s); }};
}

// ---- the volume ----

namespace {

/// What one bounded query learns about the volume of the root. Strings only: the closure that fills it owns
/// copies and outlives its caller when the bound passes.
struct VolumeFacts {
    bool has_guid{false};
    std::string guid_path; // `\\?\Volume{guid}\`
    UINT drive_type{DRIVE_UNKNOWN};
    std::string fs_name;
    bool info_ok{false};
    DWORD serial{0};
};

/// Asks the OS about `volume` (`C:` or `Volume{guid}`). Never the process-wide error mode: a thread-scoped
/// guard holds for the whole closure.
[[nodiscard]] VolumeFacts query_volume(const std::string& volume) {
    const yuzu::win::ThreadErrorModeGuard errors(SEM_FAILCRITICALERRORS);
    VolumeFacts v;
    const std::string root_utf8 = wr::volume_root_path(volume);
    const std::wstring root = yuzu::win::to_wide(root_utf8);
    if (root.empty())
        return v; // unknown drive type: refused by the plan
    if (volume.starts_with("Volume{")) {
        v.has_guid = true;
        v.guid_path = root_utf8;
    } else {
        wchar_t guid[64] = {};
        if (::GetVolumeNameForVolumeMountPointW(root.c_str(), guid, 64) != 0) {
            v.has_guid = true;
            v.guid_path = yuzu::win::from_wide(guid);
        }
    }
    const std::wstring typed_root = v.has_guid ? yuzu::win::to_wide(v.guid_path) : root;
    v.drive_type = ::GetDriveTypeW(typed_root.c_str());
    if (v.drive_type == DRIVE_FIXED && v.has_guid) {
        wchar_t fs_name[MAX_PATH + 1] = {};
        DWORD serial = 0;
        if (::GetVolumeInformationW(typed_root.c_str(), nullptr, 0, &serial, nullptr, nullptr, fs_name, MAX_PATH) != 0) {
            v.info_ok = true;
            v.serial = serial;
            v.fs_name = yuzu::win::from_wide(fs_name);
        }
    }
    return v;
}

/// The volume queries that timed out and have not returned, one per volume spelling. Touched only by the pool
/// thread that holds the slice slot (the driver reads the mount table at its step 4); a blocked query thread
/// sets only its own done flag.
BlockedQueries g_blocked_queries;

/// The module's bounded call as the driver's runner: the same three outcomes, spelled in the driver's terms.
[[nodiscard]] RunOutcome<VolumeFacts> run_bounded_volume_query(std::chrono::milliseconds timeout,
                                                               std::function<VolumeFacts()> work) {
    auto ran = yuzu::shared::bounded_call_ex(timeout, std::move(work));
    RunOutcome<VolumeFacts> out;
    switch (ran.status) {
    case yuzu::shared::BoundedCallStatus::Completed:
        out.status = RunStatus::completed;
        out.value = std::move(ran.value);
        break;
    case yuzu::shared::BoundedCallStatus::TimedOut:
        out.status = RunStatus::timed_out;
        break;
    case yuzu::shared::BoundedCallStatus::Rejected:
        out.status = RunStatus::rejected;
        break;
    }
    return out;
}

} // namespace

/// The ONE mount entry of a Windows search: the volume that holds the root. The query runs inside a bounded
/// call (a dead network or optical drive must not hold the pool thread); a timeout or a refused worker reads
/// as an unreadable table. A query that timed out is not asked again until it returns: each retry would
/// leave one more thread, and one more of the module's bounded-call slots, behind. Another volume is
/// unaffected. The rule is driver_detail::bounded_blockable_query, pinned by a portable test.
std::optional<yuzu::shared::MountTable> os_read_mounts(const std::string& root) {
    const auto label = wr::split_label(root);
    if (!label)
        return std::nullopt;
    const auto ran = driver_detail::bounded_blockable_query<VolumeFacts>(
        g_blocked_queries, label->volume, std::chrono::seconds{5}, &run_bounded_volume_query,
        [volume = label->volume] { return query_volume(volume); });
    if (!ran)
        return std::nullopt;
    const VolumeFacts& v = *ran;
    yuzu::shared::MountEntry e;
    e.mount_point = "/" + label->volume;
    e.root = v.has_guid ? v.guid_path : "-";
    e.fstype = wr::fstype_token(v.drive_type, v.fs_name, v.has_guid, v.info_ok);
    e.source = e.root;
    e.dev_major = 0;
    e.dev_minor = v.serial;
    yuzu::shared::MountTable table;
    table.entries.push_back(std::move(e));
    return table;
}

// ---- the leg of one unit ----

namespace {

/// Why a hop or a directory could not be had, already read in the walk's two vocabularies.
struct OpenFailure {
    ci::RootState root{ci::RootState::other};
    ci::ListError list{ci::ListError::unreadable};
};

[[nodiscard]] OpenFailure failure_of(cfs::Reason reason, int os_error, std::uint32_t tag) {
    return {wr::root_state_of(reason, static_cast<std::uint32_t>(os_error), tag),
            wr::list_error_of(reason, static_cast<std::uint32_t>(os_error), tag)};
}

/// A directory the handle says is a placeholder (recall or offline bit): closed unread and a dataless gap.
[[nodiscard]] OpenFailure dataless_failure() {
    return {ci::RootState::other, ci::ListError::dataless};
}

[[nodiscard]] std::uint64_t read_u64(const BYTE* p) {
    std::uint64_t v = 0;
    for (int i = 7; i >= 0; --i)
        v = (v << 8) | p[i];
    return v;
}

/// One unit's filesystem. NOT thread-safe: one walk per leg, as the POSIX leg. Everything it opens, it opens
/// lazily, on first use, on the thread that walks.
class WinFs {
public:
    WinFs(std::string walk_root, std::string root_field, std::string fstype)
        : walk_root_(std::move(walk_root)), root_field_(std::move(root_field)),
          stable_(wr::fs_has_stable_ids(fstype)) {}

    [[nodiscard]] ci::RootState root_state() {
        ensure_open();
        return failure_ ? failure_->root : ci::RootState::ok;
    }

    [[nodiscard]] ci::ListResult list(const std::string& dir, std::size_t cap) {
        ci::ListResult out;
        ensure_open();
        if (failure_) {
            out.error = true;
            out.cause = failure_->list;
            return out;
        }
        const Acquired a = acquire(dir);
        if (a.failure) {
            out.error = true;
            out.cause = a.failure->list;
            return out;
        }
        // Identity: the 128-bit FileIdInfo gives the device (the 64-bit volume serial) and, on NTFS, the id.
        // Where it is not answered (the FAT family) the id is UNKNOWN: the 32-bit serial zero-extended and 0.
        FILE_ID_INFO info{};
        if (::GetFileInformationByHandleEx(a.handle, FileIdInfo, &info, sizeof(info)) != 0) {
            out.dev = info.VolumeSerialNumber;
            out.file_id = wr::stable_id(stable_, read_u64(info.FileId.Identifier), read_u64(info.FileId.Identifier + 8));
        } else {
            out.dev = volume_->identity().volume_serial;
        }
        if (out.dev == 0) { // a listing without a device is not one
            out.error = true;
            return out;
        }
        // want_file_ids only on NTFS: off it the default class is used and a FAT-family listing id, which is
        // non-zero and position-derived, is never read, let alone reported.
        cfs::EnumBudget budget{static_cast<std::uint64_t>(cap) + 1, std::chrono::steady_clock::time_point::max(), stable_};
        cfs::EnumerateResult listed = cfs::enumerate_at(a.handle, volume_->identity(), budget);
        if (listed.reason == cfs::Reason::OsError) {
            out.error = true;
            out.cause = wr::list_error_of(cfs::Reason::OsError, static_cast<std::uint32_t>(listed.os_error), 0);
            return out;
        }
        if (listed.reason != cfs::Reason::None && listed.reason != cfs::Reason::EntryCap) {
            out.error = true;
            return out;
        }
        if (listed.reason == cfs::Reason::EntryCap || listed.entries.size() > cap) {
            out.truncated = true;
            listed.entries.resize((std::min)(listed.entries.size(), cap));
        }
        for (cfs::DirEntry& de : listed.entries) {
            // A name that cannot round-trip UTF-8 is a gap (classify): its lossy form may equal a real
            // sibling's, and the walker never merges the two.
            const wr::Listed l = wr::classify(de.meta.attributes, de.meta.reparse_tag, de.name_invalid);
            ci::DirEntry e;
            e.name = std::move(de.name); // moved, not copied: at the caps the names are tens of MB
            e.type = l.type;
            e.gap = l.gap;
            e.file_id = wr::stable_id(stable_, de.meta.file_id, 0);
            e.leg_hint = (static_cast<std::uint64_t>(de.meta.attributes) << 32) | de.meta.reparse_tag;
            out.entries.push_back(std::move(e));
        }
        return out;
    }

    [[nodiscard]] FileFacts facts(const std::string& dir, const ci::DirEntry& entry) {
        FileFacts f;
        f.extents.state = ExtentsState::failed;
        ensure_open();
        if (failure_)
            return f;
        const auto attributes = static_cast<std::uint32_t>(entry.leg_hint >> 32);
        const auto tag = static_cast<std::uint32_t>(entry.leg_hint & 0xFFFFFFFFu);
        // Decided from the listing BEFORE any open: a placeholder is never opened.
        const wr::ExtentsDecision listed = wr::extents_decision(attributes, wr::classify(attributes, tag).family);
        if (!listed.open) {
            f.extents.state = ExtentsState::unsupported;
            f.extents.note = listed.note;
            return f;
        }
        const Acquired a = acquire(dir);
        if (a.failure)
            return f;
        const cfs::OpenFileResult opened = cfs::open_file_attributes_at(a.handle, entry.name, volume_->identity());
        if (!opened.h.valid())
            return f;
        // The same decision again from the HANDLE: an entry that became a link, a directory, an entry the leg
        // cannot search or a placeholder since it was listed is read as failed, with no ioctl.
        const auto now = wr::handle_decision(opened.attributes, opened.reparse_tag);
        if (!now || !now->open)
            return f;
        f.facts = wr::opened_facts(opened);
        if (!now->ioctl) {
            f.extents.state = ExtentsState::unsupported;
            f.extents.note = now->note;
            return f;
        }

        // The FIRST of the two DeviceIoControl calls: is the file externally backed (CompactOS, WOF)?
        BYTE backing[128] = {};
        DWORD bytes = 0;
        const BOOL backing_ok = ::DeviceIoControl(opened.h.get(), FSCTL_GET_EXTERNAL_BACKING, nullptr, 0, backing,
                                                  sizeof(backing), &bytes, nullptr);
        switch (wr::external_backing_of(backing_ok != 0 ? 0 : ::GetLastError())) {
        case wr::Backing::backed:
            f.extents.state = ExtentsState::unsupported;
            f.extents.note = wr::kNoteWofBacking;
            return f;
        case wr::Backing::unknown:
            return f; // backing could not be ruled out: an extent list is never reported
        case wr::Backing::not_backed:
            break;
        }

        // The SECOND: the retrieval pointers, one call, no paging. A buffer under 32 bytes answers
        // ERROR_INSUFFICIENT_BUFFER, not ERROR_MORE_DATA: the static_assert keeps it above that.
        constexpr std::size_t kHeader = offsetof(RETRIEVAL_POINTERS_BUFFER, Extents);
        constexpr std::size_t kRun = sizeof(RETRIEVAL_POINTERS_BUFFER::Extents[0]);
        alignas(8) BYTE buffer[kHeader + kMaxExtents * kRun] = {};
        static_assert(sizeof(buffer) >= 32, "a smaller buffer answers ERROR_INSUFFICIENT_BUFFER");
        STARTING_VCN_INPUT_BUFFER start{};
        start.StartingVcn.QuadPart = 0;
        bytes = 0;
        const BOOL pointers_ok = ::DeviceIoControl(opened.h.get(), FSCTL_GET_RETRIEVAL_POINTERS, &start, sizeof(start),
                                                   buffer, sizeof(buffer), &bytes, nullptr);
        const DWORD error = pointers_ok != 0 ? 0 : ::GetLastError();

        // The shell decides nothing about the status: on success or ERROR_MORE_DATA it takes the runs that lie
        // inside the bytes returned, on any other error none, and hands the code over verbatim.
        std::vector<wr::Run> runs;
        std::uint64_t starting_vcn = 0;
        if ((error == 0 || error == wr::kErrorMoreData) && bytes >= kHeader) {
            // `buffer` is a local alignas(8) BYTE array that the call above filled and that outlives this
            // read. It is read, const, through the system's own structure type, and only the header and the
            // runs that lie inside `bytes` are touched (retrieval_runs_to_read holds the count to that).
            const auto* out = reinterpret_cast<const RETRIEVAL_POINTERS_BUFFER*>(buffer);
            starting_vcn = static_cast<std::uint64_t>(out->StartingVcn.QuadPart);
            const std::size_t n = wr::retrieval_runs_to_read(bytes, kHeader, kRun, out->ExtentCount, kMaxExtents);
            for (std::size_t i = 0; i < n; ++i)
                runs.push_back({static_cast<std::uint64_t>(out->Extents[i].NextVcn.QuadPart), out->Extents[i].Lcn.QuadPart});
        }
        // now->note is a fully local cloud file's `cloud`: the mapper attaches it to an answered list only.
        f.extents = wr::map_retrieval_pointers(
            {error, starting_vcn, runs, cluster_bytes(), opened.size, opened.attributes, now->note});
        return f;
    }

private:
    /// A directory of the current path: its handle, or why it could not be had.
    struct Acquired {
        HANDLE handle{INVALID_HANDLE_VALUE};
        std::optional<OpenFailure> failure;
    };

    /// Opens the volume root, then the walk root hop by hop. Once. A failure is kept and answered by every
    /// caller. Each hop is opened with the cloud policy, its handle's attributes pass the same recall test as
    /// a listed directory before the next hop is opened, and a hop is never enumerated: only the final handle
    /// is kept.
    void ensure_open() {
        if (opened_)
            return;
        opened_ = true;
        auto root = cfs::open_root(std::filesystem::path(yuzu::win::to_wide(root_field_)));
        if (!root.root) {
            failure_ = failure_of(root.reason, root.os_error, 0);
            return;
        }
        volume_ = std::move(*root.root);
        const auto label = wr::split_label(walk_root_);
        if (!label) {
            failure_ = OpenFailure{};
            return;
        }
        HANDLE parent = volume_->h_.get();
        cfs::WinHandle held; // the hop just opened; the previous hop closes when it is replaced
        for (const std::string& hop : label->components) {
            cfs::OpenDirResult r = cfs::open_dir_at(parent, hop, volume_->identity(), cfs::ReparseDirs::allow_populated_cloud);
            if (r.reason != cfs::Reason::None) {
                failure_ = failure_of(r.reason, r.os_error, r.reparse_tag);
                return;
            }
            if (wr::has_recall(r.attributes)) { // a placeholder hop: closed unread
                failure_ = dataless_failure();
                return;
            }
            held = std::move(r.h);
            parent = held.get();
        }
        stack_.push_back({{}, std::move(held)}); // frame 0: the walk root (an empty path gives the volume root)
        if (!stack_.front().handle.valid()) {
            stack_.front().handle = cfs::WinHandle(duplicate_of(volume_->h_.get()));
            if (!stack_.front().handle.valid())
                failure_ = OpenFailure{}; // no handle for the walk root: it cannot be listed
        }
    }

    /// The directory `dir` (a label at or under the walk root): the common prefix of the held frames is kept
    /// by exact name, the rest is closed, and only the missing hops are opened, each from the deepest held
    /// handle. At most kMaxPositionDepth + 1 frames are held (a Position names at most kMaxPositionDepth
    /// directories below the walk root).
    [[nodiscard]] Acquired acquire(const std::string& dir) {
        Acquired out;
        const auto parts = components_below_walk_root(dir);
        if (!parts || stack_.empty() || parts->size() + 1 > fsr::kMaxPositionDepth + 1) {
            out.failure = OpenFailure{};
            return out;
        }
        std::size_t keep = 0; // frames below the walk root that match the path
        while (keep < parts->size() && keep + 1 < stack_.size() && stack_[keep + 1].name == (*parts)[keep])
            ++keep;
        stack_.erase(stack_.begin() + static_cast<std::ptrdiff_t>(keep) + 1, stack_.end());
        for (std::size_t i = keep; i < parts->size(); ++i) {
            cfs::OpenDirResult r = cfs::open_dir_at(stack_.back().handle.get(), (*parts)[i], volume_->identity(),
                                                    cfs::ReparseDirs::allow_populated_cloud);
            if (r.reason != cfs::Reason::None) {
                out.failure = failure_of(r.reason, r.os_error, r.reparse_tag);
                return out;
            }
            // The recheck on the OPENED handle, before anything is enumerated: a placeholder is closed unread.
            // (A tagged directory was already checked inside open_dir_at; an untagged one, the root path, a
            // hop, or one that changed since it was listed, is checked here.)
            if (wr::has_recall(r.attributes)) {
                out.failure = dataless_failure();
                return out;
            }
            stack_.push_back({(*parts)[i], std::move(r.h)});
        }
        out.handle = stack_.back().handle.get();
        return out;
    }

    [[nodiscard]] std::optional<std::vector<std::string>> components_below_walk_root(const std::string& dir) const {
        if (!under(dir, walk_root_))
            return std::nullopt;
        auto d = wr::split_label(dir);
        const auto w = wr::split_label(walk_root_);
        if (!d || !w)
            return std::nullopt;
        // under() put the walk root's components first in the directory's.
        d->components.erase(d->components.begin(), d->components.begin() + static_cast<std::ptrdiff_t>(w->components.size()));
        return std::move(d->components);
    }

    [[nodiscard]] static HANDLE duplicate_of(HANDLE h) {
        HANDLE dup = INVALID_HANDLE_VALUE;
        if (::DuplicateHandle(::GetCurrentProcess(), h, ::GetCurrentProcess(), &dup, 0, FALSE, DUPLICATE_SAME_ACCESS) == 0)
            return INVALID_HANDLE_VALUE;
        return dup;
    }

    /// Bytes per cluster, read once on the first file that reaches the ioctl; 0 when it cannot be read (the
    /// mapper then fails the file rather than guess).
    [[nodiscard]] std::uint64_t cluster_bytes() {
        if (!cluster_read_) {
            cluster_read_ = true;
            const yuzu::win::ThreadErrorModeGuard errors(SEM_FAILCRITICALERRORS);
            DWORD sectors = 0, bytes = 0, free_clusters = 0, total_clusters = 0;
            if (::GetDiskFreeSpaceW(yuzu::win::to_wide(root_field_).c_str(), &sectors, &bytes, &free_clusters,
                                    &total_clusters) != 0)
                cluster_ = static_cast<std::uint64_t>(sectors) * bytes;
        }
        return cluster_;
    }

    struct Frame {
        std::string name; // empty for the walk root
        cfs::WinHandle handle;
    };

    std::string walk_root_;
    std::string root_field_;
    bool stable_{false}; // listing ids are stable on NTFS only
    bool opened_{false};
    std::optional<OpenFailure> failure_;
    std::optional<cfs::ConfinedRoot> volume_;
    std::vector<Frame> stack_; // [0] the walk root, then one frame per directory below it
    bool cluster_read_{false};
    std::uint64_t cluster_{0};
};

} // namespace

/// ALLOCATION ONLY: copies the unit's strings into one shared WinFs and returns the three closures. It makes
/// no system call; the driver already calls it on the worker, and the leg does not lean on that.
UnitLeg os_make_leg(const Unit& unit) {
    const auto fs = std::make_shared<WinFs>(unit.walk_root, unit.root_field, unit.fstype);
    UnitLeg leg;
    leg.ops.list = [fs](const std::string& dir, std::size_t cap) { return fs->list(dir, cap); };
    leg.ops.open_file = [](const std::string&) -> std::optional<ci::FileView> { return std::nullopt; }; // never read
    leg.ops.now = [] { return std::chrono::steady_clock::now(); };
    leg.facts = [fs](const std::string& dir, const ci::DirEntry& entry) { return fs->facts(dir, entry); };
    leg.root_state = [fs](const std::string&) { return fs->root_state(); };
    return leg;
}

// ---- the user directories of a unit ----

/// The ProfileList profiles that live on the unit's volume, as labels in the unit's own namespace, so a
/// profile reads `user` whether its volume was searched by drive letter or by volume GUID path. A profile on
/// another volume is no root of this unit, one that cannot be resolved is skipped, and a failed enumeration
/// returns none (the built-in /Users rule still tags). Called by the driver on the worker.
std::vector<std::string> os_user_roots(const Unit& unit) {
    std::vector<std::string> roots;
    const auto listing = yuzu::win::enumerate_profile_list();
    if (listing.root_rc != ERROR_SUCCESS)
        return roots;
    const yuzu::win::ThreadErrorModeGuard errors(SEM_FAILCRITICALERRORS);
    for (const auto& rec : listing.records) {
        if (yuzu::profiles::is_system_sid(rec.sid) || yuzu::profiles::is_profile_backup_entry(rec.sid) ||
            rec.profile_image_path.empty())
            continue;
        const std::wstring path = yuzu::win::to_wide(rec.profile_image_path);
        if (path.empty())
            continue;
        std::vector<wchar_t> mount_root(path.size() + 8, L'\0');
        if (::GetVolumePathNameW(path.c_str(), mount_root.data(), static_cast<DWORD>(mount_root.size())) == 0)
            continue;
        const std::wstring mount(mount_root.data());
        wchar_t guid[64] = {};
        if (mount.empty() || ::GetVolumeNameForVolumeMountPointW(mount.c_str(), guid, 64) == 0)
            continue;
        if (!ascii_ieq(yuzu::win::from_wide(guid), unit.root_field))
            continue;
        // The mount root must be the path's own prefix (profile_root_label): a path that crosses a junction
        // to another volume is answered with that volume's root and is skipped, tagged by the built-in rule only.
        if (const auto label = wr::profile_root_label(unit.mount_point, yuzu::win::from_wide(mount.c_str()),
                                                      rec.profile_image_path))
            roots.push_back(*label);
    }
    return roots;
}

} // namespace yuzu::file_search

#endif // _WIN32
