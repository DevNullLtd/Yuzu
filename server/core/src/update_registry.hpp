#pragma once

/// @file update_registry.hpp
/// OTA agent-update catalog (ADR-0061, Wave 4 ladder blind spot). Persists
/// per-(platform,arch,version) package metadata — sha256, filename, rollout
/// percentage, mandatory flag — that the gRPC OTA path (`CheckForUpdate`/
/// `DownloadUpdate` in `agent_service_impl.cpp`) and the Settings "Updates"
/// admin surface (`settings_routes.cpp`) both read. Package BINARIES stay a
/// node-local filesystem path under `update_dir_` — only the metadata moves
/// to shared Postgres; see the "Binaries stay node-local" note below.
///
/// Substrate contract (ADR-0008): the store holds a `pg::PgPool&` (not a
/// `sqlite3*`), runs its schema migration at construction on a pinned lease,
/// and schema-qualifies every runtime statement (`update_registry.update_packages`)
/// — pooled connections carry no per-store search_path. Mutate-and-return
/// uses `RETURNING` (the #1033-banning idiom), never `sqlite3_changes()`.
///
/// Posture (ADR-0012 §1): CONSTRUCTION is fail-closed — `is_open()` is false
/// (and the server sets `startup_failed_`) if the lease was empty or the
/// migration failed, whenever OTA is enabled (`cfg_.ota_enabled` defaults
/// `true` — opt-out via `--no-ota`, not an opt-in flag). This is a posture
/// upgrade from the SQLite era, which had no `is_open()` check at the
/// `server.cpp` call site at all. RUNTIME reads/writes deliberately keep
/// their pre-migration fail-SOFT shape (bare `bool`/`optional`/`vector`, no
/// `std::expected` widening): a degraded `latest_for`/`list_packages` reads
/// as "no update available this cycle" / "no packages configured", which is
/// the ADR-0036 deny-or-benign carve-out — an agent that misses an update
/// this heartbeat retries on the next one, and an admin who sees an empty
/// Updates list re-checks rather than having anything silently granted,
/// targeted, or enforced on their behalf. See the per-store ADR for the
/// explicit statement this playbook rule requires when a store declines the
/// typed-read widening. A degrade is still counted (never silent to
/// observability, only to the caller) via `set_metrics`' read/write
/// degrade-total families below.
///
/// Backfill: NONE (ADR-0009's 2026-08-25 fresh-start-by-default amendment —
/// no production fleet has ever run a pre-Postgres build of any Yuzu store).
/// The legacy `update_packages.db` is never read for data; construction
/// detects-and-warns via `legacy_sqlite_probe::warn_if_legacy_rows` if it
/// still holds rows, and logs a one-time "fresh start, no legacy backfill"
/// line. No secrets in this store (sha256 is a public content hash, not
/// secret material) — no `SecretCodec` work, no 0600 hardening obligation.
///
/// Binaries stay node-local: `update_dir_` (where uploaded package binaries
/// land, `binary_path()`) is unchanged — a plain filesystem path, same as
/// pre-migration. On today's single-server design
/// (`docs/adr/2002-high-availability-architecture.md`) this is a non-issue;
/// it becomes ADR-2002's concern once/if the server runs multi-replica
/// (fenced-leader/outbox model already scoped there) — not something this
/// migration solves.

#include <cstdint>
#include <cstddef>
#include <filesystem>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

namespace yuzu::server::pg {
class PgPool;
}

namespace yuzu {
class MetricsRegistry;
}

namespace yuzu::server {

struct UpdatePackage {
    std::string platform; // "windows", "linux", "darwin"
    std::string arch;     // "x86_64", "aarch64"
    std::string version;  // "0.2.0+87"
    std::string sha256;   // hex-encoded SHA-256
    std::string filename; // "yuzu-agent-0.2.0-x64-windows.exe"
    bool mandatory{false};
    int rollout_pct{100};    // 0-100
    std::string uploaded_at; // ISO 8601 (kept TEXT — byte-identical round-trip, no caller changes)
    int64_t file_size{0};
};

class UpdateRegistry {
public:
    /// Borrows the shared pool and runs the `update_registry` schema
    /// migration on a pinned lease. `is_open()` is false if the lease was
    /// empty or the migration failed. `update_dir` is unchanged from the
    /// pre-migration constructor — the node-local filesystem path package
    /// binaries live under (see the file header's "Binaries stay
    /// node-local" note).
    explicit UpdateRegistry(pg::PgPool& pool, const std::filesystem::path& update_dir);
    ~UpdateRegistry();

    UpdateRegistry(const UpdateRegistry&) = delete;
    UpdateRegistry& operator=(const UpdateRegistry&) = delete;

    [[nodiscard]] bool is_open() const noexcept { return open_; }

    /// Wire a metrics sink for the read/write degrade-total counters below.
    /// Set-before-traffic contract, same as every other migrated store's
    /// `set_metrics` (e.g. `InstructionStore`, `RuntimeConfigStore`). Optional
    /// — every method degrades silently-to-the-caller (per this class's
    /// documented deny-or-benign posture) whether or not a sink is wired;
    /// wiring one only adds the `yuzu_server_update_registry_{read,write}_
    /// degrade_total{reason}` observability signal (gov sre finding,
    /// adversarial review 2026-08-28).
    void set_metrics(yuzu::MetricsRegistry* m) noexcept { metrics_ = m; }

    /// Outcome of a single-package lookup that distinguishes "not there" from
    /// "the store could not answer".
    ///
    /// The ordinary reads on this store fail SOFT — a degraded `list_packages`
    /// returns an EMPTY VECTOR, which reads as "no packages configured" (see the
    /// posture note at the top of this file, and ADR-0061). That carve-out was
    /// granted on the explicit premise that "no downstream branch treats an empty
    /// list as an authorization or enforcement signal".
    ///
    /// An AUDIT branch does. `ota.package.rollout_changed` records `denied` /
    /// `not_found` when the package is absent, and audit-log.md tells operators
    /// that `result == "denied"` is the filter for enumeration attempts — so a
    /// pool timeout or a PG blip during a legitimate admin rollout would both
    /// manufacture key-enumeration alerts AND assert, in the evidence record,
    /// that a package which exists did not. This lookup exists so that branch can
    /// tell the two apart, without widening the fail-soft reads the rest of the
    /// server depends on. `update_rollout_checked` below is its one consumer.
    enum class PackageLookup { kFound, kAbsent, kUnavailable };

    /// Insert or update a package row. Returns false when the write did NOT
    /// commit — a closed store, a pool-acquire timeout, or a query error.
    ///
    /// It returns a value rather than logging and moving on because a CALLER
    /// AUDITS THIS. `ota.package.rollout_changed` reports a committed transition
    /// ("from=100% to=0%"), and an audit row asserting a change that never
    /// reached the database is worse than no row at all: it is evidence that
    /// disagrees with the state, in the one record an incident responder is
    /// supposed to be able to trust. Callers that do not audit may still ignore
    /// the result; the log line is unchanged.
    [[nodiscard]] bool upsert_package(const UpdatePackage& pkg);

    /// Outcome of an atomic rollout change: what the row held BEFORE the write,
    /// and whether that write committed.
    ///
    /// `status` and `committed` are SEPARATE questions and the caller needs both.
    ///  - `kFound` + `committed`      — applied; the priors are the values this
    ///                                  transaction replaced.
    ///  - `kFound` + `!committed`     — the row was read inside the transaction,
    ///                                  so it exists and the priors are what was
    ///                                  observed, but the write did not land.
    ///  - `kAbsent`                   — the store reported no such row.
    ///  - `kUnavailable`              — nothing is known; priors are unset.
    ///
    /// The middle case is why `committed` is not folded into `status`: collapsing
    /// it onto `kUnavailable` would throw away a prior value that WAS read and an
    /// existence that IS known, and the audit row would then say
    /// `existence_unknown=true` about a package the store had just returned.
    struct RolloutChange {
        PackageLookup status{PackageLookup::kUnavailable};
        bool committed{false};
        int prior_rollout_pct{0};
        bool prior_mandatory{false};
    };

    /// Set one package's rollout percentage, returning the percentage it
    /// replaced — read and written in a SINGLE transaction under a row lock.
    ///
    /// IT MUST STAY ONE TRANSACTION, and that is the whole reason this method
    /// exists rather than a separate lookup + `upsert_package` pair at the call
    /// site. Those are two separate pooled leases in autocommit, so a
    /// concurrent write to the same key can land between them — and
    /// `upsert_package` writes the ENTIRE snapshot back, not just
    /// `rollout_pct`, so the other writer's change is silently discarded. The
    /// audit row is what makes that fatal rather than merely lossy:
    /// audit-log.md states "the `from=` value is the point of this row", and a
    /// `result=success` row whose `from=` names a value the commit did not
    /// actually replace is evidence disagreeing with state, in the one record an
    /// incident responder is meant to be able to trust. It does not need two
    /// colliding admins: one session firing two near-simultaneous requests is
    /// enough, which is exactly the compromised-admin case #3692 exists to catch.
    ///
    /// Same shape as `AuditStore::stamp_complete` (ADR-0040, #2697), where
    /// checking only statement status let a writer that LOST this race report
    /// success while another writer's value sat at the trust anchor. See
    /// docs/postgres-store-playbook.md.
    ///
    /// A degraded store reports `kUnavailable`, never absence — see the
    /// `PackageLookup` comment above for why that distinction is load-bearing
    /// for the audit branch.
    [[nodiscard]] RolloutChange update_rollout_checked(const std::string& platform,
                                                       const std::string& arch,
                                                       const std::string& version, int rollout_pct);

    void remove_package(const std::string& platform, const std::string& arch,
                        const std::string& version);
    std::vector<UpdatePackage> list_packages() const;
    std::optional<UpdatePackage> latest_for(const std::string& platform,
                                            const std::string& arch) const;

    /// Deterministic rollout: hash(agent_id) % 100 < rollout_pct. Pure — no DB.
    static bool is_eligible(const std::string& agent_id, int rollout_pct);

    /// Pure — no DB.
    std::filesystem::path binary_path(const UpdatePackage& pkg) const;

    /// Path to the package's detached CMS signature, if the operator supplied
    /// one at upload (#416/#3807). A SIDECAR beside the binary rather than a
    /// column on the row, mirroring how plugin signatures are stored, so the
    /// signature travels with the artifact and needs no schema migration.
    ///
    /// The server does not verify this and is deliberately not trusted to: the
    /// agent checks it against a trust anchor placed on disk at install time,
    /// out of band of this server entirely. Absent file means unsigned.
    std::filesystem::path signature_path(const UpdatePackage& pkg) const;

private:
    pg::PgPool& pool_;
    bool open_{false};
    std::filesystem::path update_dir_;
    yuzu::MetricsRegistry* metrics_{nullptr};
};

/// Is `name` safe to use as an OTA package filename? (#3863)
///
/// Every OTA artifact path is built as `update_dir_ / filename` — the binary, its
/// `.sig` sidecar, and the `.upload.<n>.tmp` staging file. The filename arrives
/// from an operator-supplied multipart part, so without this check a name of
/// `../../../../etc/cron.d/x` escapes the update directory, and an ABSOLUTE name
/// is worse still: `operator/` discards the left operand entirely when the right
/// is absolute, so `/etc/cron.d/x` ignores `update_dir_` without needing any
/// `..` at all. Either way the uploaded bytes land wherever the server account
/// can write, which is arbitrary file write and, via cron or a unit file, code
/// execution.
///
/// ALLOWLIST, NOT AN ESCAPE-SCAN. This accepts a bare filename and rejects
/// everything else, rather than trying to strip or normalise a hostile one —
/// normalising is where this class of bug comes back, because it invites
/// "just one more" separator or encoding to be handled. Callers reject; nothing
/// rewrites the operator's name behind their back.
///
/// Rejects: empty; `.` and `..`; anything containing `/`, `\\`, or `:`. The
/// backslash and colon are rejected on every platform, not just Windows — the
/// server may run on Windows, where both are path-significant (`:` also selects
/// an NTFS alternate data stream), and a rule that varies by build host is a rule
/// nobody can reason about.
[[nodiscard]] inline bool is_safe_package_filename(std::string_view name) {
    if (name.empty() || name == "." || name == "..")
        return false;
    return name.find_first_of("/\\:") == std::string_view::npos;
}

} // namespace yuzu::server
