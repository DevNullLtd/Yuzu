#pragma once

/**
 * echo_module_stream.hpp — platform-agnostic module/image-load stream primitives.
 *
 * The image-load peer of echo_proc_stream.hpp. Where the process source answers
 * "what ran", `$Module` answers "what did it LOAD" — DLL / dylib / .so loads plus
 * kernel driver / kext / kmod loads, each with a signing verdict. That is the
 * DLL-search-order-hijack, code-injection, and BYOVD (bring-your-own-vulnerable-
 * driver) surface the process source cannot see.
 *
 * This header defines the shared value type (`ModuleEvent`), the warehouse-token
 * vocabulary, the templated bounded ring (`ModuleEventRing = EventRing<ModuleEvent>`
 * — the SAME backpressure idiom the process ring uses, no fork), and the
 * `ImageStreamCollector` interface the per-platform collectors implement:
 *   - Windows ETW  — Microsoft-Windows-Kernel-Process image-load events on the
 *                    SAME session the process stream already runs (M2/M3);
 *   - macOS ES     — NOTIFY_KEXTLOAD/KEXTUNLOAD + dylib via NOTIFY_MMAP on the
 *                    SAME Endpoint Security client (M4/M5);
 *   - Linux auditd — kernel-module loads via init_module/finit_module (M6).
 *
 * M1 (this header) ships the contract only — NO concrete collector — so the
 * `$Module` warehouse tables register queryable-but-empty. See
 * docs/echo-module-loads.md for the full design and PR ladder.
 *
 * Names-only posture, with ONE deliberate, narrow divergence: `module_dir` (the
 * directory of the loaded image) IS captured, because the forensic signal for a
 * search-order hijack is the path (a `version.dll` in an app dir vs System32),
 * not a command line. No command line is ever captured.
 */

#include "echo_hour_dedup.hpp"  // HourlySeenSet (apply_module_risk_filter)
#include "echo_proc_stream.hpp" // EventRing<T>

#include <cctype>
#include <cstddef>
#include <cstdint>
#include <format>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

namespace yuzu::echo {

/// Lifecycle of a module/image-load observation. Persisted to the warehouse as
/// the lower-case token from `module_action_token()`.
enum class ModuleAction : std::uint8_t {
    kLoaded = 0,   ///< image mapped into a process / driver loaded
    kUnloaded = 1, ///< never stored: apply_module_risk_filter drops it; kept for the ETW mapping
    kSeed = 2,     ///< baseline: already-loaded at agent start (boot-gap seed)
    kBlocked = 3,  ///< load denied by the OS (e.g. CodeIntegrity 3033/3034)
};

/// Signing verdict for the loaded image. Persisted as the token from
/// `module_signed_token()`. `kUnknown` is the honest value where the platform
/// cannot cheaply attest signing (e.g. Linux kernel modules without IMA/EVM) —
/// never fabricated as "signed".
enum class ModuleSignedState : std::uint8_t {
    kUnknown = 0,
    kSigned = 1,
    kUnsigned = 2,
    kInvalid = 3, ///< signature present but fails verification
    kRevoked = 4,
};

/// Stable token for a module event's action. These tokens are the SQL/dashboard
/// vocabulary; they must stay in lockstep with the action tests in `module_delta`
/// (echo_fold.hpp), which counts `loaded` and `blocked` and ignores the rest.
constexpr std::string_view module_action_token(ModuleAction a) noexcept {
    switch (a) {
    case ModuleAction::kLoaded:   return "loaded";
    case ModuleAction::kUnloaded: return "unloaded";
    case ModuleAction::kSeed:     return "seed";
    case ModuleAction::kBlocked:  return "blocked";
    }
    // Unreachable: all four enumerators are handled above and -Wswitch flags any
    // new one. The fallback is a non-matching sentinel ("invalid") so an
    // out-of-range cast can never be silently counted as a real "loaded" event
    // by a rollup `action = '...'` predicate; the trailing return is retained so
    // MSVC does not warn (C4715) on the out-of-range path.
    return "invalid";
}

/// Stable warehouse token for the `module_live.signed_state` column.
constexpr std::string_view module_signed_token(ModuleSignedState s) noexcept {
    switch (s) {
    case ModuleSignedState::kUnknown:  return "unknown";
    case ModuleSignedState::kSigned:   return "signed";
    case ModuleSignedState::kUnsigned: return "unsigned";
    case ModuleSignedState::kInvalid:  return "invalid";
    case ModuleSignedState::kRevoked:  return "revoked";
    }
    return "unknown";
}

/// One module/image-load event decoded from a streaming source. Fields mirror the
/// Echo `module_live` schema. `process_name`/`signer` are resolved at DRAIN (off
/// the kernel-serial ETW/ES callback thread), mirroring the process ring's
/// sid→user-at-drain idiom — signing verification in particular is costly on
/// Windows and must never run on the callback thread.
struct ModuleEvent {
    std::int64_t ts_unix{0};                                     ///< event time, unix seconds
    ModuleAction action{ModuleAction::kLoaded};
    std::uint32_t pid{0};                                        ///< loading process (0 for kernel)
    std::string process_name;                                    ///< loading process basename
    std::string module_name;                                     ///< loaded image basename (names-only)
    std::string module_dir;                                      ///< directory of the loaded image
    ModuleSignedState signed_state{ModuleSignedState::kUnknown};
    std::string signer;                                          ///< publisher (Win) / team id (macOS); "" otherwise
    bool is_kernel{false};                                       ///< driver (Win) / kext (macOS) / kmod (Linux)
};

/// Scrub a user-profile prefix out of a module directory before it is stored —
/// the privacy edge-drop the M1 governance made BLOCKING for the collectors. A
/// loaded image under `C:\Users\<name>`, `C:\Documents and Settings\<name>`,
/// `/home/<name>`, or `/Users/<name>` would otherwise persist a username.
/// Replaces the segment immediately after a case-insensitive `Users` /
/// `Documents and Settings` / `home` / `media` / `Volumes` path segment with
/// `<redacted>`, preserving the original separators (handles `\`, `/`, and the
/// `\Device\HarddiskVolumeN\…` NT form). The `media`/`Volumes` triggers also
/// cover `/media/<user>/...` and `/run/media/<user>/...` (single-segment
/// match on `media` catches both, `run` needing no special case) and
/// `/Volumes/<name>/...` on macOS — the removable-media mount points this
/// helper's other caller, the removable-media exec-from-removable path, needs
/// covered (echo_cursor.hpp rule 4b). Non-profile, non-mount paths (System32,
/// /usr/lib, …) pass through unchanged.
/// Known gaps (documented, deferred): 8.3 short names and redirected/roaming
/// profile roots are not recognised — cross-reference `$Process_Live` for those.
/// Pure + cross-platform: every module collector (ETW/ES/auditd) calls it at
/// drain (the ImageStreamCollector::drain() contract), and it is exercised by
/// the unit tests on every platform. This is the shared post-drain sanitiser
/// that makes redaction structurally hard to forget across future collectors.
inline std::string redact_module_dir(const std::string& dir) {
    auto is_sep = [](char c) { return c == '/' || c == '\\'; };
    // Collect [start,end) spans of each non-separator path segment.
    std::vector<std::pair<std::size_t, std::size_t>> spans;
    for (std::size_t i = 0, n = dir.size(); i < n;) {
        while (i < n && is_sep(dir[i]))
            ++i;
        std::size_t start = i;
        while (i < n && !is_sep(dir[i]))
            ++i;
        if (i > start)
            spans.emplace_back(start, i);
    }
    for (std::size_t k = 0; k + 1 < spans.size(); ++k) {
        std::string seg = dir.substr(spans[k].first, spans[k].second - spans[k].first);
        for (auto& c : seg)
            c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
        if (seg == "users" || seg == "home" || seg == "documents and settings" ||
            seg == "media" || seg == "volumes") {
            // Replace the NEXT segment (the username) with the redaction marker;
            // everything else — including separators — is kept verbatim.
            return dir.substr(0, spans[k + 1].first) + "<redacted>" +
                   dir.substr(spans[k + 1].second);
        }
    }
    return dir;
}

/// A module load that must be kept at FULL fidelity in `module_live` regardless
/// of volume: unsigned / invalid / revoked signatures, kernel driver/kext/kmod
/// loads, and OS-blocked loads. These are the rare, high-signal forensic events.
inline bool module_is_risky(const ModuleEvent& e) {
    return e.is_kernel || e.action == ModuleAction::kBlocked ||
           e.signed_state == ModuleSignedState::kUnsigned ||
           e.signed_state == ModuleSignedState::kInvalid ||
           e.signed_state == ModuleSignedState::kRevoked;
}

/// §5 edge filter (docs/echo-module-loads.md) — bounds `module_live` at the write edge so a
/// module-load storm can't flood it, without losing the rare high-signal rows.
///
///   - `kUnloaded` events are dropped: an unmap is the lowest-value observation and roughly
///     halves the volume.
///   - EVERY risky load (module_is_risky: unsigned / invalid / revoked, kernel, blocked) is
///     kept, one row per event.
///   - Every other event (a signed load, an unknown-signature load on a platform that cannot
///     attest, a boot seed) is kept once per hour per (action, loader process, module name,
///     module directory), through `seen`. module_dir stays in the key so a same-named DLL from
///     two directories (the search-order-hijack signal) is not collapsed; `action` stays in it
///     so a boot seed never consumes the slot of a later `loaded` row, which is the row
///     module_hourly.load_count counts. The hourly load count for ordinary modules is
///     therefore distinct loader/module/folder combinations, not raw loads.
///   - `max_signed` caps the ordinary rows kept per drain. The cap is checked BEFORE `seen`, so
///     only an admitted row is marked and a capped load is admitted by a later drain.
///
/// `seen` is mutated; filter against a COPY and keep it only after the rows are committed so
/// a rolled-back drain is re-filtered identically. Pure and cross-platform, applied
/// plugin-side between drain and insert. The 100k row-count retention on `module_live` is the
/// deterministic backstop behind this.
inline std::vector<ModuleEvent> apply_module_risk_filter(std::vector<ModuleEvent> events,
                                                         HourlySeenSet& seen,
                                                         std::size_t max_signed = 4096) {
    std::vector<ModuleEvent> out;
    out.reserve(events.size());
    std::size_t signed_kept = 0;
    for (auto& e : events) {
        if (e.action == ModuleAction::kUnloaded)
            continue;
        if (module_is_risky(e)) {
            out.push_back(std::move(e));
            continue;
        }
        if (signed_kept >= max_signed)
            continue; // per-drain cap (the hard bound); do NOT mark the key
        auto key = std::format("{}\x1f{}\x1f{}\x1f{}", module_action_token(e.action),
                               e.process_name, e.module_name, e.module_dir);
        if (!seen.first_this_hour(e.ts_unix, std::move(key)))
            continue; // already stored this hour
        ++signed_kept;
        out.push_back(std::move(e));
    }
    return out;
}

/// The module/image-load ring — `EventRing<ModuleEvent>`, the same bounded
/// push→pull backpressure bridge the process ring uses (echo_proc_stream.hpp).
using ModuleEventRing = EventRing<ModuleEvent>;

/// Common interface for a module/image-load stream — the image-load peer of
/// `ProcStreamCollector`. The Echo plugin holds ONE of these per platform and
/// drains it each fast tick, alongside the process stream (they correlate, so
/// they share cadence and snapshot_id). On a platform/SDK without a stream,
/// `start()` returns false and the `$Module` source simply produces nothing —
/// there is never silent partial loss. No concrete collector ships in M1; this
/// is the contract M2/M4/M6 implement.
class ImageStreamCollector {
public:
    virtual ~ImageStreamCollector() = default;

    // Non-copyable / non-movable: a concrete collector owns a live ETW session,
    // ES client, or auditd reader — copying or slicing it would duplicate or
    // sever that ownership. (Sibling invariant: ProcStreamCollector is identical.)
    ImageStreamCollector() = default;
    ImageStreamCollector(const ImageStreamCollector&) = delete;
    ImageStreamCollector& operator=(const ImageStreamCollector&) = delete;
    ImageStreamCollector(ImageStreamCollector&&) = delete;
    ImageStreamCollector& operator=(ImageStreamCollector&&) = delete;

    /// Begin streaming. Returns false if unavailable (wrong platform, missing
    /// entitlement/privilege, session-open failure) — caller captures nothing.
    virtual bool start() = 0;
    /// Stop streaming and release the underlying session/client. Safe if not started.
    virtual void stop() = 0;
    virtual bool running() const noexcept = 0;
    /// Move buffered events out for the batched echo.db write. The concrete
    /// collector MUST apply `redact_module_dir()` to every event's `module_dir`
    /// before the rows are inserted (the privacy edge-drop the M1 governance
    /// made BLOCKING for collectors — docs/echo-module-loads.md §13); a raw
    /// `module_dir` can embed a username. Resolving `process_name`/`signer` and
    /// the signing verdict also happens here, off the kernel-serial callback.
    virtual std::vector<ModuleEvent> drain() = 0;
    /// Events dropped due to ring overflow since construction.
    virtual std::uint64_t dropped() const noexcept = 0;
    /// Events the source's kernel/provider dropped BEFORE they reached userspace
    /// (e.g. an Endpoint Security `seq_num` gap), distinct from dropped() which
    /// counts the userspace ring overflow. Default 0 for sources with no
    /// kernel-side sequence to inspect. (Sibling of ProcStreamCollector — keep
    /// the contract in lockstep so a concrete collector can override either.)
    virtual std::uint64_t kernel_dropped() const noexcept { return 0; }
    /// True when the collector still reports running() but has gone silent long
    /// enough to be presumed dead — for a source with no liveness API (the macOS
    /// Endpoint Security client). The plugin falls back to the poll when this
    /// trips. Default false for sources whose running() already flips on death.
    virtual bool stalled() const noexcept { return false; }
    /// Stable token for the `module_capture_method` status field
    /// ("etw" / "endpoint_security" / "auditd").
    virtual const char* method_name() const noexcept = 0;
};

} // namespace yuzu::echo
