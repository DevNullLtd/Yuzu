// echo_db_legacy_rename.hpp -- adopt a pre-rename tar.db as echo.db.
//
// Upgrade-window helper (removed with the other legacy-name shims). Before the Echo rename the
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
// Accepted limit of that resume state: when tar.db is present, its own sidecar is absent and the
// echo.db sidecar exists, the helper takes the echo.db sidecar to be tar.db's own, already moved.
// It cannot tell that from a stale one: if an older agent is run against tar.db between the
// interruption and the next boot, writes, and cleanly checkpoints and deletes its WAL, the
// re-upgrade pairs the newer tar.db with the earlier echo.db WAL and replays it over the newer
// file. No cheap check separates the two (a checkpoint writes tar.db after the WAL's last frame,
// so an mtime or header comparison would refuse legitimate resumes), so the residual is accepted.
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
// The second shape a planted file takes is a SIDECAR with no echo.db: a planted echo.db-wal
// beside the real tar.db-wal, which the collision refusal below would otherwise stop for good.
// So when echo.db is absent, every echo.db sidecar whose tar.db twin also exists is probed the
// same way; a foreign-owned one is moved aside alone (`echo.db-wal.planted-<epoch>[-n]`), an
// owner-verified or unresolved one is left where it is and the refusal below stands. A lone
// echo.db sidecar with no tar.db twin is the resume state and is never probed or moved. Adoption
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
#include <functional>
#include <memory>
#include <string>
#include <system_error>
#include <vector>

#include <spdlog/spdlog.h>

#include <sqlite_quarantine.hpp> // claim_quarantine_name: the shared no-overwrite move (#6914)

#ifdef _WIN32
#include <win_echo_db_owner_probe.hpp> // the owner test EchoDatabase::open applies
#endif

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

    if (echo_present && legacy_present) {
        spdlog::warn("Legacy {} exists beside {}: two independent databases. {} is used; the legacy "
                     "file and its sidecars are left untouched for the operator",
                     legacy.string(), echo_db.string(), echo_db.string());
        return {};
    }

    // No legacy main file: nothing to adopt. A stray legacy sidecar is left where it is, never
    // moved onto echo.db (see the header comment).
    if (!legacy_present) {
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

    // Sidecars first. A source that does not exist is already moved (or never was): success.
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
    spdlog::info("Adopted legacy {} as {}", legacy.string(), echo_db.string());
    return {};
}

} // namespace yuzu::agent
