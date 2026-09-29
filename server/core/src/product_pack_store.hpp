#pragma once

/// @file product_pack_store.hpp
/// Migrated Postgres store (ADR-0006/0009/0054, schema `product_pack_store`) for operator-
/// installed product packs — multi-document YAML bundles that install into the
/// `InstructionStore`/`PolicyStore`/`WorkflowEngine` catalogs via a caller-supplied
/// `ItemInstallFn`/`ItemUninstallFn`. Two tables, one real internal FK with `ON DELETE CASCADE`
/// (`product_pack_items.pack_id -> product_packs.id`), ported unchanged.
///
/// `migrate_from_sqlite()` retired (chore/retire-migrate-from-sqlite-batch-b, #3623) —
/// see ADR-0054's Update. `server.cpp` now runs a detect-and-warn probe over the
/// legacy file instead; `deleted_pack_ids`/`kErasureCoordLockSql` are kept as-is —
/// their removal is a separate, undecided question.
///
/// Posture (ADR-0012 §1): AUTHORITATIVE / fail-hard, both construction and runtime — packs are
/// operator-installed content (build-time-seeded packs plus operator additions), not a cache.
/// `install`/`uninstall` already returned `std::expected` pre-migration; `list`/`get` are widened
/// to `std::expected` here (ADR-0036 typed-read policy) so a genuine DB error is never collapsed
/// into "no packs installed" / "not found" — matching `LicenseStore`/`ResultSetStore`'s `get`
/// shape (`std::expected<std::optional<T>, std::string>`).
///
/// Substrate contract (ADR-0008): the store holds a `pg::PgPool&` (not a `sqlite3*`), runs its
/// schema migration at construction on a pinned lease, and schema-qualifies every runtime
/// statement (`product_pack_store.product_packs` / `product_pack_store.product_pack_items`) —
/// pooled connections carry no per-store search_path. Mutate-and-return uses `RETURNING` where a
/// caller needs to distinguish "inserted" from "conflicted", never `sqlite3_changes()`.
///
/// **`install()` no longer holds a `pool_` lease across the `ItemInstallFn` callback loop.**
/// The pre-migration SQLite version wrapped the whole install (metadata insert + per-document
/// `install_fn` calls into `InstructionStore`/`PolicyStore`/`WorkflowEngine`) inside one
/// `BEGIN IMMEDIATE` on `db_`. Under the Postgres substrate that shape is forbidden
/// (`docs/postgres-store-playbook.md`: "never call another store while holding a lease" — those
/// sibling stores draw from the SAME shared `PgPool`, so holding our own lease while they try to
/// acquire theirs risks starving a saturated pool). This was never a genuine cross-store
/// transaction even pre-migration: `install_fn`'s callees write to THEIR OWN `db_`/pool, never
/// ours. The new shape preserves that same atomicity boundary explicitly: `install_fn` is called
/// with no lease of ours held; once every document has been resolved, the pack row + its
/// successfully-installed item rows are written in ONE `pool_` transaction (parent-before-child,
/// satisfying the FK). A total-failure install (zero items installed) never WRITES to Postgres —
/// gov Gate 3 (cpp-expert, #3481): a keyed install's F033 idempotency pre-check runs one
/// read-only `SELECT` before `install_fn` is ever reached, so "never touches Postgres at all"
/// stopped being literally true once that pre-check landed.
///
/// **Update (F031/#3481, 2026-08-24): a late failure of that final persist transaction — AFTER
/// `install_fn` already committed one or more documents into sibling stores — is no longer a
/// silent orphan.** `install()` now accepts `compensate_fn` (see its doc comment below) and, on
/// that failure, walks every already-installed item in REVERSE install order, calling
/// `compensate_fn(kind, item_id)` on each as a best-effort undo. Reverse order matters: a bundle
/// can install a `PolicyFragment` followed by a `Policy` that references it (bundle order is
/// dependency order — `PolicyStore::create_policy` validates the fragment exists at creation
/// time), and `PolicyStore::delete_fragment` refuses while any `Policy` still references it —
/// compensating forward would spuriously fail to clean up the fragment. **This safety argument
/// is `PolicyStore`-specific and holds only when the bundle itself respects dependency order**
/// (gov Gate 5 CHAOS-4) — `WorkflowEngine::create_workflow` performs NO existence check on the
/// `InstructionDefinition` ids its steps reference at creation time, so a bundle placing a
/// `Workflow` document BEFORE the `InstructionDefinition` it references produces a brief window,
/// scoped to the remaining length of the SAME compensation loop, where the `Workflow` row (not
/// yet reached by the reverse walk) points at an already-compensated `InstructionDefinition` —
/// self-heals when the loop reaches it moments later, but is a real, undocumented-until-now gap
/// in the "reverse order is always safe" framing. This is best-effort, not
/// a guarantee: a sibling store's own delete can itself fail for a reason unrelated to ordering
/// (a `PolicyFragment` referenced by some OTHER, unrelated policy is the same tolerated exception
/// documented for `uninstall()` below) — a residual orphan from a failed compensation is logged
/// at `spdlog::error` (naming the exact kind/item id) and counted in
/// `yuzu_server_product_pack_install_compensation_total{result}`, for operator follow-up, not
/// automatically retried.
///
/// **Gate 6 review (#3481, sre): the metric/log/audit trail for a compensation attempt is
/// written only after the reverse-order loop completes** — a process crash or forced restart
/// DURING the loop (including immediately after its last, successful iteration but before the
/// trailing emit) leaves that install attempt with NO metric sample, NO summary log line, and
/// NO audit row at all — the request handler never resumes to call `audit_fn`. This is not a
/// regression versus pre-#3481 behavior (every late failure silently orphaned content
/// unconditionally, with the same absent observability) — it degrades to exactly the bug F031
/// exists to close, in the rare window a crash coincides with an already-rare late-install
/// failure. Operator guidance: a restart around the time of a large pack install, with no
/// matching `YuzuProductPackCompensationPartial` alert or `spdlog::error` line for that attempt,
/// is not proof compensation ran cleanly — check the submitted bundle against sibling-store
/// content manually in that specific window. Not closed here; a fast-follow could increment the
/// metric at the FIRST failed item rather than after the loop (never pre-increment — Prometheus
/// counters can't decrement, so a pre-increment-then-correct pattern would false-alarm on every
/// clean compensation), but that changes exactly the emission-point semantics Gate 8 verified
/// with `promtool test rules` and would need its own re-verification, not a casual patch.
///
/// **No `mtx_` (the pre-migration `shared_mutex` is dropped).** Postgres's MVCC + the pool's own
/// connection-level concurrency replace the SQLite single-writer mutex, matching every other
/// migrated store on the ladder. This is a deliberate, accepted trade: two concurrent
/// `uninstall(id, ...)` calls for the SAME id can both pass the `get(id)` existence check and
/// both invoke `uninstall_fn` on the sibling stores before either's delete transaction runs —
/// the sibling-store uninstalls are themselves idempotent-ish (a missing item is just a `false`
/// return, logged, not fatal) and the final Postgres delete is a plain `DELETE ... WHERE id=$1`
/// (harmless if the row is already gone). A small race window, not a security boundary —
/// `ResultSetStore`'s per-owner quota/pin-limit soft-enforcement is the ladder's precedent for
/// recording this class of trade explicitly rather than silently.
///
/// **Update (F032/#3481, 2026-08-24): `uninstall()`'s final metadata-delete transaction can
/// likewise fail AFTER `uninstall_fn` has already removed the real sibling-store content** — the
/// pack stays listed as installed, pointing at content that no longer exists. Unlike F031 above,
/// this gap is accepted as a store-scoped residual risk rather than closed, because there is no
/// symmetric fix: the sibling content is already gone, and re-creating deleted content to satisfy
/// a rollback would itself be a hazard (resurrecting content an operator explicitly asked to
/// remove, from no fresh operator input). Accepted on two grounds: (1) a plain client retry
/// self-heals it — re-issuing the DELETE re-runs `uninstall_fn` against items that are already
/// gone (idempotent no-ops for every sibling store's delete-by-id), then the metadata-delete
/// transaction runs again and, absent a repeat failure, succeeds; (2) the blast radius is the same
/// operator-authored-catalog-metadata classification ADR-0009's `ProductPackStore`/ADR-0054 update
/// note already applies to this store, not personal or regulated subject/device data. **What this
/// does NOT close:** between the failure and a successful retry, `get()`/`list()` show a pack
/// pointing at deleted content, and a lookup that follows one of its item ids into another
/// endpoint 404s — expected during that window, not a new fault, but genuinely visible to a caller
/// that doesn't retry. This reasoning is store-scoped and MUST be re-derived, not copied, by any
/// future store whose own uninstall path can leave metadata dangling over content that cannot be
/// safely restored.
///
/// No secrets (ADR-0010 N/A): `yaml_source` is pack content — verified against
/// `docs/Instruction-Engine.md` / `docs/yaml-dsl-spec.md`, neither of which defines a
/// secret-typed/credential-bearing YAML field; the only crypto-adjacent fields are the public
/// `signature`/`publicKey` pair, which are not secret material. Free-text columns
/// (`name`/`description`/`yaml_source` and the item equivalents) are still `sanitize_pg_text`'d
/// before every write — libpq's text-format binding is C-string-based, so an embedded NUL byte
/// would otherwise silently TRUNCATE the stored value at that point (worse than the
/// pre-migration `sqlite3_bind_text(..., -1, ...)`, which had the identical truncation behavior
/// — U+FFFD replacement is a strict improvement, not a new risk). Sanitization is at-rest
/// storage hygiene only; it does not re-verify the Ed25519 signature over the sanitized bytes —
/// `verify_signature` runs once, before sanitization, over the exact bytes that were signed.

#include "store_errors.hpp"

#include <atomic>
#include <cstdint>
#include <expected>
#include <functional>
#include <optional>
#include <string>
#include <vector>

namespace yuzu::server::pg {
class PgPool;
}

namespace yuzu {
class MetricsRegistry;
}

namespace yuzu::server {

/// Machine-checkable prefix on every `ProductPackStore` `unexpected()` that represents a genuine
/// DB/lease failure rather than caller-input validation, a signature/policy rejection, or a
/// not-found error (mirrors `LicenseStore::kLicenseDbErrorPrefix` / `AccessReviewStore`'s
/// `"not_found: "` idiom, and `InstructionStore::kInstructionStoreDbErrorPrefix` — both alias
/// the single shared `kDbErrorPrefix`, `store_errors.hpp`). Callers classify: `"not_found:"`
/// prefix -> 404, this prefix -> 503, else -> 400 (see `workflow_routes.cpp`'s
/// `product_pack_error_status`).
inline constexpr std::string_view kProductPackDbErrorPrefix = kDbErrorPrefix;

// ── Data types ───────────────────────────────────────────────────────────────

struct ProductPackItem {
    std::string kind;        // "InstructionDefinition", "PolicyFragment", etc.
    std::string item_id;     // ID assigned when the item was installed
    std::string name;        // Display name from the YAML
    std::string yaml_source; // Verbatim YAML for this document
};

struct ProductPack {
    std::string id;
    std::string name;
    std::string version;
    std::string description;
    std::string yaml_source; // The full multi-document YAML bundle
    int64_t installed_at{0};
    bool verified{false}; // Whether the Ed25519 signature was verified

    // Populated by get()
    std::vector<ProductPackItem> items;
};

struct ProductPackQuery {
    std::string name_filter;
    int limit{100};
};

/// #3479: per-document outcome detail from `install()`, optionally requested via its trailing
/// `partial_result` out-param. `install_fn` tolerates a single document failing without failing
/// the whole bundle — this is how a caller learns WHICH documents failed and why, instead of
/// only a bare pack id (success) or the first of potentially several failure reasons (total
/// failure). Populated at every `install()` return point that carries an `install_fn` outcome —
/// a total failure after the document loop ran, or a success (clean or partial). Gov Gate 4
/// finding (consistency-auditor, #3481): NOT populated on a return BEFORE the document loop
/// runs (store-not-open, missing `install_fn`, a malformed bundle, a signature rejection, an
/// idempotency-key conflict/replay) — there is no install_fn outcome to report yet, and
/// structurally can't be: the populating lambda and its captured locals don't exist at that
/// point in `install()`. A caller reading only this comment should not assume "always
/// populated on any `unexpected`" — see `install()`'s own `partial_result` doc for the precise
/// carve-out.
struct InstallPartialResult {
    std::vector<std::string> errors; ///< One entry per document install_fn rejected, in
                                     ///< document order — kind + install_fn's own error string.
    int total_items{0};              ///< Item documents in the bundle (excludes the ProductPack
                                     ///< metadata document itself).
    int installed_count{0};          ///< `total_items - errors.size()`, restated for callers
                                     ///< that only have this struct, not the raw counts.
};

/// Server-authoritative outcome of a post-failure transaction-status re-check (gov Gate 5
/// CHAOS-1/CHAOS-1b, #3481) — see `ProductPackStore::check_transaction_outcome`'s doc comment.
/// Deliberately NOT based on row visibility: a row's absence from a fresh read cannot
/// distinguish "aborted" from "not yet committed" (the client-observed connection failure that
/// triggers this check is not ordered relative to the backend's own commit progress — a
/// middlebox/pooler can sever the client's connection at any point independent of whether the
/// backend has finished, or even started, applying the commit), so `pg_xact_status()` — the
/// question of that xact's true fate, answered by Postgres itself — is the mechanism instead.
enum class TransactionOutcome {
    kCommitted, ///< The backend confirms the transaction committed — the ack was merely lost.
    kAborted,   ///< The backend confirms the transaction genuinely aborted — safe to compensate.
    kUnknown    // Could not determine either way — the ONLY safe read is "do not compensate".
};

/// Gov Gate 4 (unhappy-path UP-2, UP-5), on `kUnknown` specifically: if the underlying
/// transaction had in fact genuinely ABORTED (not merely undetermined), the sibling-store
/// content install_fn already wrote in THIS attempt is now an unlinked orphan — no pack_id was
/// ever persisted to reference it, and — unlike the confirmed-orphan `kAborted` shape — nothing
/// was compensated. A keyed retry's pre-check finds no committed row and re-runs install_fn for
/// the WHOLE bundle: a document with an explicit, retry-stable `id:` collides against attempt
/// 1's already-created row (surfaces as a new errors[] entry); an auto-id document silently
/// creates a full second copy under a NEW pack_id, orphaning attempt 1's content with no
/// pack_id, no audit row, and no metric distinguishing it from an ordinary kUnknown. Also:
/// `check_transaction_outcome` leases from the SAME pool_ as the write step whose failure it's
/// diagnosing — but this reaches `check_transaction_outcome` ONLY when `write_lease_acquired`
/// was true (the write lease WAS obtained, then the txn body failed); under a SUSTAINED full
/// outage the write lease's own `try_acquire_for` fails first for nearly every caller, routing
/// straight to the unambiguous, safe direct-compensate path — NOT through kUnknown at all (gov
/// Gate 6, sre, correcting an earlier overstatement in this same note). The real window is
/// narrower: a BRIEF flap/failover, where a write lease is granted just before the backend
/// drops and collides with pool exhaustion on the immediately-following outcome check. Rare and
/// narrow, not "every in-flight install during an outage" — but each occurrence still carries
/// the retry-collision hazard above. Neither is fixed here — the fail-toward-`kUnknown` design
/// is still the correct, safe choice (never guess `kAborted`); this documents the residual so
/// an operator investigating a kUnknown event during a flap knows what it can compound into.

// ── Callbacks for delegating item install/uninstall to existing stores ────────

/// Called for each YAML document during install.
/// Returns the assigned item ID on success, or an error string.
using ItemInstallFn = std::function<std::expected<std::string, std::string>(
    const std::string& kind, const std::string& yaml_source)>;

/// Called for each item during uninstall to remove it from its origin store. `{}` on success;
/// `unexpected("db_error: ...")` on a genuine store failure — `uninstall()` aborts the whole
/// operation on this (never deletes the pack row while a contained item may still be live);
/// any other `unexpected(...)` (not-found, unsupported kind) is tolerated and logged, matching
/// pre-ADR-0058 behaviour for kinds whose origin store doesn't yet distinguish the two.
using ItemUninstallFn = std::function<std::expected<void, std::string>(const std::string& kind,
                                                                        const std::string& item_id)>;

// ── ProductPackStore ────────────────────────────────────────────────────────

class ProductPackStore {
public:
    /// Borrows the shared pool and runs the `product_pack_store` schema migration on a pinned
    /// lease. `is_open()` is false if the lease was empty or the migration failed.
    explicit ProductPackStore(pg::PgPool& pool);

    ProductPackStore(const ProductPackStore&) = delete;
    ProductPackStore& operator=(const ProductPackStore&) = delete;

    [[nodiscard]] bool is_open() const noexcept { return open_; }

    /// Wire a metrics registry for `list`/`get`'s read-degrade counter
    /// (`yuzu_server_product_pack_read_degrade_total{reason}`), matching
    /// `CustomPropertiesStore`/`DiscoveryStore`'s #1675 convention, and `install`'s F031/#3481
    /// compensation-outcome counter (`yuzu_server_product_pack_install_compensation_total{result}`).
    /// Set ONCE during single-threaded startup, before serving. A null registry (the default,
    /// e.g. in unit tests) disables emission.
    void set_metrics(yuzu::MetricsRegistry* m) noexcept { metrics_ = m; }

    /// When true, packs WITHOUT a `signature` field are rejected at install time. Packs with a
    /// signature are always verified regardless of this flag — failed verification rejects
    /// unconditionally. Defaults to true since #802 / W7.4: unsigned packs are a fleet-wide
    /// arbitrary-code-execution surface. Operators with legacy unsigned packs must explicitly
    /// opt out via the `--allow-unsigned-packs` / `YUZU_ALLOW_UNSIGNED_PACKS` server flag, which
    /// calls `set_require_signed_packs(false)` and emits a `server.unsigned_packs_allowed`
    /// startup audit event.
    ///
    /// gov W7.4 R1 SHOULD-1 (cpp-expert): the field is `std::atomic<bool>` because `install`
    /// reads it OUTSIDE any lease (perf/ordering — the check happens before the DB write phase).
    /// The setter is called at startup, before any concurrent reader exists, but TSAN has no way
    /// to know that — atomic load/store with relaxed memory order silences TSAN AND
    /// future-proofs against any later runtime-toggle endpoint.
    void set_require_signed_packs(bool require) {
        require_signed_packs_.store(require, std::memory_order_relaxed);
    }
    bool require_signed_packs() const {
        return require_signed_packs_.load(std::memory_order_relaxed);
    }

    /// Install a product pack from a multi-document YAML bundle.
    /// Each `---` separated document is parsed for its `kind:` field and
    /// delegated to the appropriate store via install_fn.
    /// The ProductPack metadata is extracted from the document with kind: ProductPack.
    ///
    /// SECURITY INVARIANT (#802 / W7.4): this is the SOLE gate for `require_signed_packs_`. All
    /// code that materialises a `ProductPack` from external (operator-supplied or
    /// network-fetched) input MUST route through this method — direct writes via the underlying
    /// `product_pack_store.product_packs` table, or callbacks that bypass `install`, defeat the
    /// #802 protection and re-introduce the fleet-wide arbitrary-code-execution surface. If a
    /// future bulk-import, hot-reload, sync-from-registry, or content-distribution feature is
    /// added, it MUST either call `install()` (preferred) or implement an equivalent signature
    /// check AND emit a `product_pack.install` audit row with `result=denied` on rejection. The
    /// sole production caller today is `workflow_routes.cpp` `POST /api/product-packs`; any new
    /// caller must update this comment to remain accurate.
    ///
    /// `install_fn` is invoked with NO `pool_` lease of ours held (see the file header) — it is
    /// free to call into its own sibling stores without risking pool starvation.
    ///
    /// `compensate_fn` (F031/#3481): if the final persist transaction fails AFTER one or more
    /// documents were already installed via `install_fn`, this callback is invoked once per
    /// already-installed item, in REVERSE install order, to best-effort undo it — same
    /// `bool(kind, item_id)` shape as `uninstall_fn` (in practice callers pass the identical
    /// per-kind delete dispatch). A single item's compensation failing is logged and does not
    /// abort compensating the rest. Defaults to an empty callback (no compensation attempted) —
    /// existing callers are unaffected until they opt in. See the file header for the full
    /// rationale and the reverse-order requirement.
    ///
    /// `idempotency_key` (F033/#3481): when non-empty, a prior successful install with the SAME
    /// key and an IDENTICAL `yaml_bundle` short-circuits before `install_fn` is invoked at all,
    /// returning the original pack id — this is what stops a client retry from re-running
    /// `install_fn` against every sibling store again (a dedup check only at the final persist
    /// step would not: `install_fn` would still re-run on every attempt). The same key reused
    /// with a DIFFERENT bundle is rejected as a plain validation error (never
    /// `kProductPackDbErrorPrefix` — a 400, not a 503) EXCEPT inside the narrow race window
    /// documented below: the LOSER of two concurrent installs racing the same not-yet-used key
    /// (with genuinely different bodies) never reaches the pre-check's differing-body branch at
    /// all — it hits the persist INSERT's unique-violation instead, which IS
    /// `kProductPackDbErrorPrefix`/503 (retryable), and only converges to the documented 400 on
    /// a subsequent retry once the pre-check can see the winner's committed row (gov Gate 5
    /// CHAOS-3). Defaults to empty (no dedup) — preserves
    /// today's behavior exactly; a caller that never sends a key gets no idempotency protection,
    /// same as before this parameter existed. Namespaced globally (the key alone, not scoped to a
    /// caller/principal) — `POST /api/product-packs` is `ProductPack:Write`-gated, effectively
    /// operator-only against one fleet-wide catalog, unlike e.g. ADR-0032's per-credential
    /// admission-protocol dedupe, which exists for a different, multi-principal threat model. A
    /// narrow race remains (two concurrent installs, same key, both pass the pre-check) — left to
    /// surface as an ordinary unique-violation on the persist INSERT, which the loser's own F031
    /// compensation path already handles; see the CHAOS-3 note above for exactly where a client
    /// retry converges to (the winner's id if the retried body matches the winner's, the
    /// documented 400 if it differs — NOT unconditionally the winner's id). Same class of
    /// accepted race already documented for concurrent `uninstall()` above.
    ///
    /// `partial_result` (#3479): when non-null, populated with per-document failure detail —
    /// on EITHER outcome, a total failure (every document's error, not just the first) or a
    /// partial success (which documents failed and why, alongside the ones that installed).
    /// Defaults to null — preserves existing callers' behavior exactly. NOT populated on ANY
    /// return that happens BEFORE the document loop runs — not just the idempotency pre-check's
    /// short-circuit replay, but also the store-not-open/missing-install_fn/malformed-bundle/
    /// signature-rejection/idempotency-conflict checks: `install_fn` never ran on any of those
    /// calls, so there is no per-document outcome yet to report.
    std::expected<std::string, std::string> install(const std::string& yaml_bundle,
                                                    ItemInstallFn install_fn,
                                                    ItemUninstallFn compensate_fn = {},
                                                    const std::string& idempotency_key = {},
                                                    InstallPartialResult* partial_result = nullptr);

    /// List installed product packs, newest-installed first. `unexpected(msg)` (prefixed
    /// `kProductPackDbErrorPrefix`) is a genuine read failure — never treat it as "no packs
    /// installed".
    std::expected<std::vector<ProductPack>, std::string> list(const ProductPackQuery& q = {});

    /// Get a single product pack with its items. `nullopt` = a successful read finding none;
    /// `unexpected(msg)` (prefixed `kProductPackDbErrorPrefix`) = a genuine read failure — never
    /// treat the latter as "not found".
    std::expected<std::optional<ProductPack>, std::string> get(const std::string& id);

    /// Uninstall a product pack, removing all contained items via uninstall_fn. Stamps `id` into
    /// `deleted_pack_ids` in the SAME transaction as the metadata delete, under
    /// `kErasureCoordLockSql` (ADR-0009 erasure consistency — originally serialized against the
    /// now-retired `migrate_from_sqlite`; see the .cpp for the current status of both).
    /// `unexpected("not_found: ...")` when no pack with this id exists; any other
    /// `unexpected(msg)` (prefixed `kProductPackDbErrorPrefix`) is a genuine failure.
    std::expected<void, std::string> uninstall(const std::string& id, ItemUninstallFn uninstall_fn);

    // Minimal YAML value extraction — public so install callbacks can use it
    static std::string extract_yaml_value(const std::string& yaml, const std::string& key);

    /// Gov Gate 5 CHAOS-1/CHAOS-1b (#3481, verified): a fault landing between Postgres
    /// processing COMMIT and the client reading `PGRES_COMMAND_OK` is indistinguishable, at the
    /// `with_txn_on` call site, from a genuine transaction failure — the client-observed
    /// connection failure is not ordered relative to the backend's own commit progress, so
    /// "check whether the row exists now" (an earlier version of this method) is ALSO not
    /// reliable: absence could mean genuinely aborted, or could mean the backend simply hasn't
    /// finished applying an already-in-flight commit yet. `pg_xact_status()` asks Postgres
    /// itself the true fate of that specific transaction id instead of inferring it from a
    /// side effect — it is documented for exactly this ("commit status of transactions whose
    /// outcome is in doubt due to a lost connection"). Before `install()`'s compensating
    /// rollback runs on a final-persist failure, it uses this to tell "the transaction genuinely
    /// aborted" (safe to compensate — the pre-#3481 behavior) from "it actually committed and
    /// only the ack was lost" (compensating would ACTIVELY DELETE real, already-persisted
    /// content — worse than the orphan #3481 exists to close) from "still in progress, or
    /// unknown" (`kUnknown` — the ONLY safe read when doubt remains; never guess `kAborted`).
    /// Public (not file-local) specifically so this exact decision seam is unit-testable
    /// deterministically (no fault injection needed): open a transaction on one connection,
    /// query its status from a second while still open (`kInProgress`... i.e. `kUnknown`), then
    /// after `COMMIT` (`kCommitted`) and after `ROLLBACK` (`kAborted`) on a fresh transaction —
    /// all three real server-confirmed outcomes are directly producible.
    static TransactionOutcome check_transaction_outcome(pg::PgPool& pool,
                                                        const std::string& xact_id);

    /// Verify an Ed25519 signature over content.
    /// Uses OpenSSL EVP_DigestVerify on every platform (see the .cpp file header for the
    /// BCrypt-was-actually-ECDSA-not-Ed25519 history).
    /// @param content     The data that was signed
    /// @param signature_hex  Hex-encoded Ed25519 signature (128 hex chars = 64 bytes)
    /// @param public_key_hex Hex-encoded Ed25519 public key (64 hex chars = 32 bytes)
    /// @return true if signature is valid, false otherwise
    static bool verify_signature(const std::string& content, const std::string& signature_hex,
                                 const std::string& public_key_hex);

private:
    pg::PgPool& pool_;
    bool open_{false};
    /// Security-by-default since #802 (W7.4): see the setter doc above.
    std::atomic<bool> require_signed_packs_{true};
    yuzu::MetricsRegistry* metrics_{nullptr};

    // Split multi-document YAML on "---" boundaries
    static std::vector<std::string> split_yaml_documents(const std::string& bundle);
};

} // namespace yuzu::server
