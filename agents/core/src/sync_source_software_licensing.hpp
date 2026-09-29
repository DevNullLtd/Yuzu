#pragma once

/// @file sync_source_software_licensing.hpp
/// The `software_licensing` daily-sync source (ADR-0016; SLE roadmap §5 PR1
/// file-table row 6). Collects detected-licence records by invoking the
/// `license_scan` plugin in-process (`LocalDispatcher`, action `list`) and
/// renders them into a canonical blob the server ingests
/// (server/core/src/software_licensing_ingestion.cpp — the already-committed
/// seam this file is comment-coordinated with; the caps below MUST match it).
///
/// KEY DIFFERENCE from the sibling sources (installed_software / device_ci):
/// per ADR-0024 Decision 3 / roadmap D-2 the server hash-skips on the SHA-256
/// of the RAW received blob bytes — it never re-derives a canonical form from
/// re-parsed rows. So this source needs only STABLE bytes across collects of
/// the same detected state (sort + dedup; the plugin already converts countdowns
/// to absolute dates), NOT a server-byte-identical canonicalisation. §3.3 field
/// hygiene (sync_canonical clamp_field) still applies as defence-in-depth.
///
/// Per-user carve-out (ADR-0024 Decision 11): records may carry
/// `user_scope=user` + a `user_ref`. The `--license-scan-user-ref` knob is
/// applied HERE, before the blob is built: `collect` passes the plugin's local
/// profile name through, `hash` replaces it with a per-agent keyed pseudonym
/// `HMAC-SHA256(k_agent, profile)` truncated to 16 hex, `omit` empties it. An
/// already-empty (unresolvable) profile stays empty in every mode — never a
/// SID, never a hash-of-empty (D-11). `k_agent` is a 256-bit CSPRNG key
/// persisted in the agent KvStore (`license_scan` namespace) and NEVER
/// transmitted or logged (roadmap R16).

#include "sync_scheduler.hpp"

#include <yuzu/plugin.h> // YuzuPluginDescriptor (C ABI) + YUZU_EXPORT

#include <functional>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

namespace yuzu::agent {

/// The `--license-scan-user-ref` knob (ADR-0024 Decision 11). Default `hash`.
enum class UserRefMode { collect, hash, omit };

/// Wire token for the effective mode — emitted verbatim into the `cfg|` record
/// (§3.1) and matched by the server's kUserRefModes whitelist.
YUZU_EXPORT std::string_view user_ref_mode_token(UserRefMode mode);

/// Parse a `collect|hash|omit` token; std::nullopt on anything else (the CLI
/// layer rejects at parse — mirrors main.cpp's other closed-set flags).
YUZU_EXPORT std::optional<UserRefMode> parse_user_ref_mode(std::string_view s);

/// One detected-licence record — the agent-local mirror of the plugin's
/// `lic|` wire line (§3.1). Member order == the 13 positional fields the server
/// seam reads AFTER the `lic` kind prefix
/// (software_licensing_ingestion.cpp:parse_software_licensing_blob):
///   product|vendor|version|license_type|channel|status|expires_at|source|
///   confidence|key_hint|exe_hints|user_scope|user_ref
struct LicRecord {
    std::string product;
    std::string vendor;
    std::string version;
    std::string license_type;
    std::string channel;
    std::string status;
    std::string expires_at; // passed through verbatim (plugin owns the format)
    std::string source;
    std::string confidence;
    std::string key_hint;
    std::string exe_hints;
    std::string user_scope; // "machine" | "user"
    std::string user_ref;   // local profile name or "" — transformed by the knob
};

/// Result of parsing one `license_scan list` capture.
struct LicenseScanParse {
    std::vector<LicRecord> records; ///< `lic|` rows only, fields §3.3-clamped
    /// True iff a CYCLE-BLOCKING surface reported `probe_status|<s>|error`. Two
    /// classes block: a platform *primary* enumeration surface (slp_wmi /
    /// pkg_metadata / mas_receipt — ADR-0024 D3) and an *authoritative* surface
    /// whose records would wrongly read as "licence gone" if full-replaced away on
    /// a transient error (entitlement_certs, flexlm_lic; slp_wmi is both). An
    /// authoritative secondary surface therefore keeps last-good exactly like a
    /// primary failure. Heuristic/probable secondary surfaces — per-user
    /// hives/files (R15), ProbeSpec vendor probes — do NOT set this: their errors
    /// never wipe stored state. When true the collect cycle is skipped (keep last
    /// good state); when false a zero-record parse is a VALID empty state.
    bool blocking_surface_error{false};
};

/// Parse `license_scan` `list` output: keep `lic|` records (fields clamped via
/// sync_canonical clamp_field, §3.3 layer 2), read `probe_status|` lines ONLY
/// for the empty-vs-error guard, and skip every other kind (`ent|`, `cfg|`,
/// blank, unknown) — forward-compat tolerance (ADR-0024 D3).
YUZU_EXPORT LicenseScanParse parse_license_scan_output(const std::string& out);

/// HMAC-SHA256(key, profile) truncated to the first 16 lowercase hex chars
/// (ADR-0024 D11 pseudonym). `key` is the raw 32-byte k_agent. Deterministic:
/// same key + same profile → same 16 hex (pseudonym stability across restarts).
YUZU_EXPORT std::string user_ref_hmac16(std::string_view key, std::string_view profile);

/// Apply the knob to every record's `user_ref`, in place (D-11 semantics):
///   collect → unchanged; hash → user_ref_hmac16(k_agent, user_ref);
///   omit    → "".
/// An already-empty user_ref stays empty in EVERY mode (never a hash-of-empty).
/// `k_agent` (raw bytes) is consulted only in `hash` mode.
YUZU_EXPORT void apply_user_ref_knob(std::vector<LicRecord>& records, UserRefMode mode,
                                     std::string_view k_agent);

/// Build the canonical blob: the single `cfg|user_ref|<mode>` record FIRST
/// (fixed position — D-10, blob-stable), then the `lic|` records sorted +
/// deduped for stability. Fields 0x1F-joined, records 0x1E-terminated (the
/// framing the server seam splits on). Assumes apply_user_ref_knob has already
/// run. Takes records by value (it sorts a copy).
YUZU_EXPORT std::string software_licensing_canonical_blob(std::vector<LicRecord> records,
                                                          UserRefMode mode);

/// Injected configuration for the source. The KvStore accessors are wired to
/// the `license_scan` namespace in agent.cpp; injecting them (rather than a
/// KvStore*) keeps the source unit-testable with a fake key store and lets the
/// tests assert k_agent never leaks (roadmap R16).
struct SoftwareLicensingConfig {
    UserRefMode user_ref_mode{UserRefMode::hash}; ///< default hash (ADR-0024 D11)
    /// Read a persisted value (returns "" when absent). Namespace-scoped upstream.
    std::function<std::string(std::string_view key)> kv_get;
    /// Persist a value. Namespace-scoped upstream.
    // Returns true iff the value was durably persisted. A false return (e.g. a
    // disk-full / SQLite-busy failure to persist the user_ref HMAC key) makes the
    // sync source SKIP the cycle rather than use an unpersisted key that would
    // regenerate next cycle — keeping the per-profile pseudonym stable (Decision 11).
    std::function<bool(std::string_view key, std::string_view value)> kv_set;
};

/// KvStore key (within the `license_scan` namespace) holding the hex-encoded
/// 256-bit k_agent. Public so agent.cpp / tests name the same key.
inline constexpr std::string_view kUserRefHmacKeyName = "user_ref_hmac_key";

/// Build the `software_licensing` SyncSource. `descriptor` is the loaded
/// `license_scan` plugin descriptor; when null (plugin not built/loaded) the
/// source's collect returns std::nullopt and the scheduler no-ops it. 24 h
/// interval.
YUZU_EXPORT SyncSource make_software_licensing_source(const YuzuPluginDescriptor* descriptor,
                                                      SoftwareLicensingConfig config);

} // namespace yuzu::agent
