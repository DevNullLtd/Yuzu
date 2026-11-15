// echo_db_legacy_rename.hpp -- adopt a pre-rename tar.db as echo.db.
//
// Pre-rename install helper (kept while a pre-rename tar.db can still exist). Before the Echo rename the
// activity-record database lived at <data_dir>/tar.db; it now lives at <data_dir>/echo.db. The
// file keeps its DACL / mode and content, so adoption is a rename, nothing else.
//
// ONE caller: agent core at boot (agents/core/src/agent.cpp), after the KV store opens and
// before any plugin init or dispatch (the plugin scan only registers descriptors; no plugin
// opens a database before init). That placement is the exclusion within the process: no
// process-wide lock exists across plugin dylibs, so no plugin ever adopts, and nothing in this
// process has the database open while it is moved. It does not exclude a predecessor process
// still shutting down during a service restart (the step runs before the Guardian instance
// lock): on Windows its open handle can fail the rename, which is logged and resumed on the
// next start. EchoDatabase::open() refuses to create a fresh echo.db beside an unadopted
// tar.db, so a failed adoption fails closed instead of booting with default config. The caller
// defers adoption entirely while the plugin dir holds only the retired tar plugin (an OTA
// replaces the agent binary alone): the next start after echo.<ext> is installed adopts.
//
// Order is load-bearing: sidecars (-journal, -wal, -shm) move BEFORE the main file. An
// interrupted adoption therefore always looks like "tar.db present, echo.db absent" and resumes
// on the next boot, and echo.db can never be opened while its WAL still carries the old name.
//
// Adoption-intent marker (#6752). A resume must not pair a NEWER tar.db with an OLDER echo.db WAL:
// if an older agent is run against tar.db between an interruption and the next boot, writes, and
// cleanly checkpoints and deletes its WAL, replaying the echo.db WAL over that file would lose or
// corrupt Echo history. So before the FIRST sidecar move the helper durably writes
// <data_dir>/echo.db.adopting holding tar.db's size and mtime at that moment, and removes it after
// the main-file rename. On the next boot:
//   - tar.db present, an echo.db sidecar present, marker present and equal to tar.db's current
//     size and mtime: nothing has touched tar.db since the sidecars moved; resume as normal.
//   - the same with the marker ABSENT or recording a different tar.db: the echo.db sidecar is not
//     provably this adoption's own (the marker is written before every move it guards), so adoption
//     fails closed, naming both files, and moves no legacy file (a foreign echo.db or sidecar that
//     the planted-file heal below already set aside is logged before the refusal);
//     EchoDatabase::open() then refuses until the operator resolves the two files.
// The marker is a plain file written with write_file_atomic (fsync'd on POSIX; on Windows the
// shared writer documents no flush-by-handle, so a power loss right after the write can lose the
// marker there, which fails closed rather than open). A marker left behind once tar.db is gone (the
// removal after the rename failed) is deleted at the next boot. An older agent that never learned
// of the marker still cannot slip through, because the comparison is against tar.db itself.
//
// Open-path ordering (settles the overlap with the v10 schema migration): adoption runs in agent
// core (agents/core/src/agent.cpp) before any plugin initialises, and the v10 migration runs inside
// EchoDatabase::open() from EchoPlugin::init, so the marker is already gone before open() runs and
// a v10 failure never touches it.
//
// If both main files exist they are two independent databases (an agent downgraded after the
// rename, then upgraded again). Nothing is touched: echo.db wins, tar.db and its sidecars are
// left for the operator, and one warning names them. Old tar.db.corrupt-* quarantine files are
// never touched.
//
// ONE exception, Windows only (#6695): the both-present state is also what a PLANTED echo.db looks
// like. A local user who can write the state directory creates echo.db before the first start of
// the upgraded agent; open() refuses it (foreign owner), and the legitimate tar.db could never be
// adopted, so the agent would fail closed on every start with an operator visit as the only exit.
// So when echo.db is owned by an account other than SYSTEM, Administrators or the agent's, it is
// moved aside to `echo.db.planted-<epoch>[-n]` (kept as evidence, never overwritten) and the
// adoption below proceeds. Each file is judged on its own and moved ALONE, never as a group: the
// resume state "tar.db present, echo.db-wal already moved" legitimately leaves an owner-verified
// echo.db-wal beside echo.db, and carrying it away would resume the adoption without its
// committed rows. Only a foreign-owned file moves; an owner-verified sidecar stays and pairs with
// tar.db as in any resume. FAIL CLOSED: when the owner of echo.db or of any existing sidecar
// cannot be resolved nothing is moved, the warning above is the only effect and echo.db wins, so
// an unreadable owner can never be turned into a move.
//
// Recorded limit: the owner probe and the move are two operations on a NAME, so a file swapped
// into that name between them is moved on the earlier verdict. The swap needs rename rights over
// files whose protected DACL withholds them from the planting account, so it reduces to an
// account moving a file it could already move; it is accepted, not closed.
//
// The second shape a planted file takes is a SIDECAR with no echo.db: a planted echo.db-wal
// beside the real tar.db-wal, which the collision refusal below would otherwise stop for good.
// So when echo.db is absent, every echo.db sidecar whose tar.db twin also exists is probed the
// same way; a foreign-owned one is moved aside alone (`echo.db-wal.planted-<epoch>[-n]`), an
// owner-verified one is left where it is and the refusal below stands, and an unresolved one
// cancels every move, as above. A lone echo.db sidecar with no tar.db twin is the resume state
// and is never probed or moved. Adoption
// proceeds only once everything in its way was moved aside: echo.db itself when present, the
// colliding sidecars otherwise. The POSIX arm is unchanged: the state directory is root-owned
// there, so a local user cannot plant a file in it.
//
// A sidecar present at BOTH names while tar.db is being adopted (for example a downgrade wrote a
// fresh tar.db-wal beside an already-moved echo.db-wal) cannot be paired safely: moving tar.db
// anyway would open it with a foreign WAL and strand the legacy WAL's committed rows. Adoption
// fails closed there and moves nothing further; tar.db stays, echo.db stays absent, and
// EchoDatabase::open() refuses until the operator resolves the two files. Without a legacy main
// file there is nothing to adopt, so a stray legacy sidecar is only warned about and left: renamed
// onto a live echo.db, a leftover tar.db-wal would be replayed by SQLite over current data (it
// validates a WAL by its own checksum chain, never against the main file). Every resumable state
// has tar.db present, because sidecars move before the main file.
#pragma once

#include <cstdint>
#include <expected>
#include <filesystem>
#include <format>
#include <fstream>
#include <functional>
#include <memory>
#include <optional>
#include <string>
#include <system_error>
#include <vector>

#include <spdlog/spdlog.h>

#include <sqlite_quarantine.hpp> // claim_quarantine_name: the shared no-overwrite move (#6914)

#ifdef _WIN32
#include <win_echo_db_owner_probe.hpp> // the owner test EchoDatabase::open applies
#endif
#include <atomic_file_write.hpp> // yuzu::shared::write_file_atomic: the fsync'd marker write

namespace yuzu::agent {

/// Whose a database file is, as far as the owner test can tell. `unknown` = it could not be
/// examined (a failed open or owner read, no token user): never treated as either of the others.
enum class EchoFileOwner { ours, foreign, unknown };

/// Judges one existing file. Empty = no judgement (the POSIX default), so the both-present arm
/// leaves everything alone. A parameter so the decision logic is tested without a Windows host.
using EchoOwnerProbe = std::function<EchoFileOwner(const std::filesystem::path&)>;

/// The probe adoption uses by default: the same owner test open() applies, through a handle opened
/// no-follow with READ_CONTROL only. Empty off Windows.
[[nodiscard]] inline EchoOwnerProbe default_echo_owner_probe() {
#ifdef _WIN32
    auto probe = std::make_shared<yuzu::win::EchoDbOwnerProbe>();
    return [probe](const std::filesystem::path& file) {
        if (!probe->ok())
            return EchoFileOwner::unknown;
        constexpr DWORD kShareAll = FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE;
        const HANDLE raw = ::CreateFileW(file.c_str(), READ_CONTROL | FILE_READ_ATTRIBUTES,
                                         kShareAll, nullptr, OPEN_EXISTING,
                                         FILE_ATTRIBUTE_NORMAL | FILE_FLAG_OPEN_REPARSE_POINT,
                                         nullptr);
        if (raw == INVALID_HANDLE_VALUE)
            return EchoFileOwner::unknown;
        const std::unique_ptr<void, decltype(&::CloseHandle)> handle{raw, ::CloseHandle};
        DWORD owner_rc = ERROR_SUCCESS;
        if (probe->foreign_owner(handle.get(), &owner_rc))
            return EchoFileOwner::foreign;
        // nullopt is "ours" only when the owner was actually read (a filesystem without ACLs has
        // no owner to compare: unknown, so nothing is moved on that ground).
        return owner_rc == ERROR_SUCCESS ? EchoFileOwner::ours : EchoFileOwner::unknown;
    };
#else
    return {};
#endif
}


namespace detail {

/// What the marker records about the legacy main file: its size and mtime.
[[nodiscard]] inline std::expected<std::string, std::string>
legacy_echo_fingerprint(const std::filesystem::path& legacy) {
    namespace fs = std::filesystem;
    std::error_code ec;
    const auto size = fs::file_size(legacy, ec);
    if (ec)
        return std::unexpected(std::format("cannot stat {}: {}", legacy.string(), ec.message()));
    const auto mtime = fs::last_write_time(legacy, ec);
    if (ec)
        return std::unexpected(std::format("cannot stat {}: {}", legacy.string(), ec.message()));
    return std::format("{} {}\n", size, mtime.time_since_epoch().count());
}

} // namespace detail

[[nodiscard]] inline std::expected<void, std::string>
adopt_legacy_echo_db(const std::filesystem::path& echo_db,
                     const EchoOwnerProbe& owner_of = default_echo_owner_probe()) {
    namespace fs = std::filesystem;
    constexpr const char* kSidecars[] = {"-journal", "-wal", "-shm"};
    const fs::path legacy = echo_db.parent_path() / "tar.db";

    std::error_code ec;
    bool echo_present = fs::exists(echo_db, ec);
    if (ec)
        return std::unexpected(std::format("cannot stat {}: {}", echo_db.string(), ec.message()));
    const bool legacy_present = fs::exists(legacy, ec);
    if (ec)
        return std::unexpected(std::format("cannot stat {}: {}", legacy.string(), ec.message()));

    if (legacy_present && owner_of) {
        // Planted-file self-heal (#6695, see the header comment). Probe every candidate before
        // moving any.
        std::vector<fs::path> foreign;
        bool echo_foreign = false;
        bool unresolved = false;
        for (const char* suffix : {"", "-journal", "-wal", "-shm"}) {
            fs::path file = echo_db;
            file += suffix;
            const bool present = fs::exists(file, ec);
            if (ec) {
                unresolved = true; // cannot even tell it is there: nothing is moved
                break;
            }
            if (!present)
                continue;
            if (!echo_present) {
                fs::path twin = legacy;
                twin += suffix;
                const bool collides = fs::exists(twin, ec);
                if (ec) {
                    unresolved = true;
                    break;
                }
                if (!collides)
                    continue;
            }
            switch (owner_of(file)) {
            case EchoFileOwner::ours:
                break;
            case EchoFileOwner::foreign:
                foreign.push_back(file);
                echo_foreign = echo_foreign || suffix[0] == '\0';
                break;
            case EchoFileOwner::unknown:
                unresolved = true;
                break;
            }
        }
        const bool heal = !unresolved && (echo_present ? echo_foreign : !foreign.empty());
        if (heal) {
            const auto epoch = yuzu::shared::sqlite_quarantine::now_epoch_seconds();
            // One at a time. The sidecars first, the main file last, so an interruption leaves
            // "echo.db still planted" (re-detected on the next start), never a stranded sidecar.
            for (auto it = foreign.rbegin(); it != foreign.rend(); ++it) {
                std::vector<std::string> notes;
                const auto moved = yuzu::shared::sqlite_quarantine::claim_quarantine_name(
                    *it, epoch, ".planted-", &notes);
                for (const auto& note : notes)
                    spdlog::warn("Legacy adoption: {}", note);
                if (!moved) {
                    return std::unexpected(std::format(
                        "cannot move the foreign-owned {} aside; resolve it by hand",
                        it->string()));
                }
                spdlog::warn("{} is owned by an account other than SYSTEM, Administrators or the "
                             "agent's: moved aside to {} so the legacy {} can be adopted",
                             it->string(), moved->string(), legacy.string());
            }
            if (echo_foreign)
                echo_present = false; // echo.db is gone: carry on to the adoption proper
        }
        if (unresolved) {
            spdlog::warn("Could not resolve the owner of every file at {}: none moved aside",
                         echo_db.string());
        }
    }

    // <data_dir>/echo.db.adopting: the adoption-intent marker (path only; no I/O here).
    fs::path marker = echo_db;
    marker += ".adopting";

    if (echo_present && legacy_present) {
        spdlog::warn("Legacy {} exists beside {}: two independent databases. {} is used; the legacy "
                     "file and its sidecars are left untouched for the operator",
                     legacy.string(), echo_db.string(), echo_db.string());
        return {};
    }

    // No legacy main file: nothing to adopt. A stray legacy sidecar is left where it is, never
    // moved onto echo.db (see the header comment).
    if (!legacy_present) {
        // A marker outliving the main-file rename (its removal failed) is spent: delete it, or a
        // later downgrade that recreates tar.db could be mistaken for this adoption's resume.
        std::error_code mec;
        if (fs::remove(marker, mec); mec)
            spdlog::warn("Cannot remove the spent adoption marker {}: {}", marker.string(),
                         mec.message());
        for (const char* suffix : kSidecars) {
            fs::path stray = legacy;
            stray += suffix;
            const bool stray_present = fs::exists(stray, ec);
            if (ec)
                return std::unexpected(
                    std::format("cannot stat {}: {}", stray.string(), ec.message()));
            if (stray_present)
                spdlog::warn("Legacy {} left in place: there is no {} to adopt, and a stray "
                             "sidecar is never moved onto {}",
                             stray.string(), legacy.string(), echo_db.string());
        }
        return {};
    }

    // Resume safety (#6752): an echo.db sidecar whose legacy twin is absent was either moved by an
    // earlier run of THIS adoption or is stale. It is provably ours only when the marker records
    // tar.db exactly as it is now (see the header comment); otherwise fail closed, moving nothing.
    const auto fingerprint = detail::legacy_echo_fingerprint(legacy);
    if (!fingerprint)
        return std::unexpected(fingerprint.error());
    // An absent or unreadable marker both read as "no marker". The read is capped: a fingerprint is
    // under 64 bytes, so a longer file can only mismatch. The stream is closed before the marker is
    // rewritten or removed below (on Windows an open handle blocks both).
    std::optional<std::string> recorded;
    {
        std::ifstream in(marker, std::ios::binary);
        if (in) {
            std::string buf(256, '\0');
            in.read(buf.data(), static_cast<std::streamsize>(buf.size()));
            buf.resize(static_cast<std::size_t>(in.gcount()));
            recorded = std::move(buf);
        }
    }
    const bool marker_matches = recorded && *recorded == *fingerprint;
    if (!marker_matches) {
        for (const char* suffix : kSidecars) {
            fs::path from = legacy;
            from += suffix;
            fs::path to = echo_db;
            to += suffix;
            const bool from_present = fs::exists(from, ec);
            if (ec)
                return std::unexpected(
                    std::format("cannot stat {}: {}", from.string(), ec.message()));
            const bool to_present = fs::exists(to, ec);
            if (ec)
                return std::unexpected(
                    std::format("cannot stat {}: {}", to.string(), ec.message()));
            if (to_present && !from_present)
                return std::unexpected(std::format(
                    "cannot adopt {}: {} exists but {}, so it cannot be shown to belong to this "
                    "adoption (it could be an older database's log); no legacy files were moved "
                    "(a foreign file moved aside is logged above), resolve {} by hand",
                    legacy.string(), to.string(),
                    recorded ? std::format("{} records a different {}", marker.string(),
                                           legacy.string())
                             : std::format("no adoption marker {} exists", marker.string()),
                    to.string()));
        }
    }

    // Sidecars first. A source that does not exist is already moved (or never was): success.
    bool marker_written = marker_matches;
    for (const char* suffix : kSidecars) {
        // path::operator+= appends in the native character type; string() + suffix would narrow
        // a wide Windows path through the ANSI code page first.
        fs::path from = legacy;
        from += suffix;
        fs::path to = echo_db;
        to += suffix;
        if (!fs::exists(from, ec)) {
            if (ec)
                return std::unexpected(
                    std::format("cannot stat {}: {}", from.string(), ec.message()));
            continue;
        }
        // Never overwrite: an overwritten -wal would lose committed rows. The legacy main file is
        // still to be adopted, so a collision cannot be resolved here (the main file would be
        // paired with the wrong WAL): fail closed and move nothing further.
        const bool to_present = fs::exists(to, ec);
        if (ec)
            return std::unexpected(std::format("cannot stat {}: {}", to.string(), ec.message()));
        if (to_present)
            return std::unexpected(
                std::format("cannot adopt {}: {} and {} both exist; resolve them by hand",
                            legacy.string(), from.string(), to.string()));
        // Record the intent durably BEFORE the first sidecar leaves its name.
        if (!marker_written) {
            if (auto w = yuzu::shared::write_file_atomic(marker, *fingerprint); !w)
                return std::unexpected(std::format("cannot adopt {}: cannot record the adoption "
                                                   "marker {}: {}",
                                                   legacy.string(), marker.string(),
                                                   w.error().message));
            marker_written = true;
        }
        fs::rename(from, to, ec);
        if (ec)
            return std::unexpected(std::format("cannot move {} to {}: {}", from.string(),
                                               to.string(), ec.message()));
        spdlog::info("Adopted legacy {} as {}", from.string(), to.string());
    }

    fs::rename(legacy, echo_db, ec);
    if (ec)
        return std::unexpected(std::format("cannot move {} to {}: {}", legacy.string(),
                                           echo_db.string(), ec.message()));
    // Adoption is complete; the marker is spent. A failed removal is retried at the next boot.
    std::error_code mec;
    if (fs::remove(marker, mec); mec)
        spdlog::warn("Cannot remove the spent adoption marker {}: {}", marker.string(),
                     mec.message());
    spdlog::info("Adopted legacy {} as {}", legacy.string(), echo_db.string());
    return {};
}

} // namespace yuzu::agent
