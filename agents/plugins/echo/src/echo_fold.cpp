/**
 * echo_fold.cpp -- the fold writer: the only code that touches SQLite on behalf
 * of the roll-up substrate. See echo_fold.hpp for the contract (roll-up is the
 * only storage model; event times are trusted as given; locking; the cooperative
 * GC deadline). Nothing here is wired into open(), the collectors or any config.
 */

#include "echo_fold.hpp"

#include <sqlite3.h>
#include <spdlog/spdlog.h>
#include <yuzu/log_token.hpp>

#include <memory>
#include <type_traits>

namespace yuzu::echo {

namespace {

struct StmtDeleter {
    void operator()(sqlite3_stmt* s) const { sqlite3_finalize(s); }
};
using StmtPtr = std::unique_ptr<sqlite3_stmt, StmtDeleter>;

int64_t now_epoch_seconds() {
    return std::chrono::duration_cast<std::chrono::seconds>(
               std::chrono::system_clock::now().time_since_epoch())
        .count();
}

// A failed step records the SQLite text on the handle (never a bound value: this
// store holds usernames), exactly as TransactionHandle::fail documents.
bool fail_sql(TransactionHandle& h, const char* what) {
    h.fail(std::string(what) + ": " + sqlite3_errmsg(h.raw()));
    return false;
}

bool prep(TransactionHandle& h, StmtPtr& out, const std::string& sql) {
    if (h.poisoned())
        return false;
    sqlite3_stmt* raw = nullptr;
    if (sqlite3_prepare_v2(h.raw(), sql.c_str(), static_cast<int>(sql.size()), &raw, nullptr) !=
        SQLITE_OK)
        return fail_sql(h, "prepare failed");
    out.reset(raw);
    return true;
}

// Step to completion, counting RETURNING rows (never sqlite3_changes(), #1033).
bool run(TransactionHandle& h, sqlite3_stmt* s, std::size_t* rows = nullptr) {
    if (h.poisoned())
        return false;
    int rc = SQLITE_OK;
    std::size_t n = 0;
    while ((rc = sqlite3_step(s)) == SQLITE_ROW)
        ++n;
    if (rc != SQLITE_DONE)
        return fail_sql(h, "step failed");
    if (rows)
        *rows += n;
    return true;
}

void bind_text(sqlite3_stmt* s, int i, std::string_view v) {
    sqlite3_bind_text(s, i, v.data(), static_cast<int>(v.size()), SQLITE_STATIC);
}

void bind_value(sqlite3_stmt* s, int i, const Value& v) {
    std::visit(
        [&](const auto& x) {
            using T = std::decay_t<decltype(x)>;
            if constexpr (std::is_same_v<T, int64_t>)
                sqlite3_bind_int64(s, i, x);
            else if constexpr (std::is_same_v<T, double>)
                sqlite3_bind_double(s, i, x);
            else
                bind_text(s, i, x);
        },
        v);
}

// Interns strings INSIDE a transaction. New ids go to a local staging map; the
// caller publishes them to the shared cache only after COMMIT.
class Interner {
public:
    explicit Interner(const std::unordered_map<std::string, int64_t>& cache) : cache_(cache) {}

    bool intern(TransactionHandle& h, const std::string& text, int64_t& id) {
        if (const auto it = cache_.find(text); it != cache_.end()) {
            id = it->second;
            return true;
        }
        if (const auto it = staged_.find(text); it != staged_.end()) {
            id = it->second;
            return true;
        }
        if (!stmt_) {
            // A no-op DO UPDATE so RETURNING yields the existing row's id on a hit.
            if (!prep(h, stmt_,
                      std::format("INSERT INTO {} (text) VALUES (?) ON CONFLICT(text) DO UPDATE "
                                  "SET text = excluded.text RETURNING id",
                                  kDictTable)))
                return false;
        }
        sqlite3_reset(stmt_.get());
        sqlite3_clear_bindings(stmt_.get());
        bind_text(stmt_.get(), 1, text);
        if (sqlite3_step(stmt_.get()) != SQLITE_ROW)
            return fail_sql(h, "dictionary intern failed");
        id = sqlite3_column_int64(stmt_.get(), 0);
        if (sqlite3_step(stmt_.get()) != SQLITE_DONE)
            return fail_sql(h, "dictionary intern failed");
        staged_.emplace(text, id);
        return true;
    }

    std::unordered_map<std::string, int64_t>& staged() { return staged_; }

private:
    const std::unordered_map<std::string, int64_t>& cache_;
    std::unordered_map<std::string, int64_t> staged_;
    StmtPtr stmt_;
};

// Called after a successful COMMIT, still under op_mu_.
void publish(std::unordered_map<std::string, int64_t>& cache,
             std::unordered_map<std::string, int64_t>& staged) {
    if (staged.empty())
        return;
    // ponytail: clear on overflow; an LRU only if a profile shows the refills matter.
    if (cache.size() + staged.size() > kDictCacheCap)
        cache.clear();
    if (staged.size() > kDictCacheCap)
        return; // one batch bigger than the cache: do not cache it
    for (auto& [text, id] : staged)
        cache.emplace(text, id);
}

// Upsert every tier of the accumulator. Counts RETURNING rows into `touched`.
bool upsert_tiers(TransactionHandle& h, const FoldSourceDef& def, const TierAccumulator& acc,
                  Interner& in, std::size_t& touched) {
    const auto& key_cols = acc.key_columns();
    for (auto tier : def.tiers) {
        const auto rows = acc.rows(tier);
        if (rows.empty())
            continue;
        StmtPtr st;
        if (!prep(h, st, tier_upsert_sql(def, tier)))
            return false;
        for (const auto& row : rows) {
            sqlite3_reset(st.get());
            sqlite3_clear_bindings(st.get());
            int idx = 1;
            sqlite3_bind_int64(st.get(), idx++, row.bucket);
            for (std::size_t k = 0; k < key_cols.size(); ++k) {
                if (key_cols[k].interned) {
                    int64_t id = 0;
                    if (!in.intern(h, std::get<std::string>(row.keys[k]), id))
                        return false;
                    sqlite3_bind_int64(st.get(), idx++, id);
                } else {
                    bind_value(st.get(), idx++, row.keys[k]);
                }
            }
            for (const auto& m : row.measures)
                bind_value(st.get(), idx++, m);
            if (!run(h, st.get(), &touched))
                return false;
        }
    }
    return true;
}

// echo_state UPSERT (same SQL as EchoDatabase::upsert_state_locked, which is private).
bool write_state(TransactionHandle& h, const StateWrite& w) {
    StmtPtr st;
    if (!prep(h, st,
              "INSERT INTO echo_state (collector, state_json, updated_at) VALUES (?, ?, ?) "
              "ON CONFLICT(collector) DO UPDATE SET state_json = excluded.state_json, "
              "updated_at = excluded.updated_at"))
        return false;
    bind_text(st.get(), 1, w.collector);
    bind_text(st.get(), 2, w.json);
    sqlite3_bind_int64(st.get(), 3, now_epoch_seconds());
    return run(h, st.get());
}

// echo_cursor UPSERT (same SQL as the raw-store cursor commit).
bool write_cursor(TransactionHandle& h, std::string_view source, const std::string& json) {
    StmtPtr st;
    if (!prep(h, st,
              "INSERT INTO echo_cursor (source, cursor_json, updated_at) VALUES (?, ?, ?) "
              "ON CONFLICT(source) DO UPDATE SET cursor_json = excluded.cursor_json, "
              "updated_at = excluded.updated_at"))
        return false;
    bind_text(st.get(), 1, source);
    bind_text(st.get(), 2, json);
    sqlite3_bind_int64(st.get(), 3, now_epoch_seconds());
    return run(h, st.get());
}

// Add `n` to the persisted rejected-events counter. An UPSERT-add inside the fold's
// own transaction, so a rollback leaves the counter exactly as it was.
bool bump_rejected(TransactionHandle& h, std::size_t n) {
    StmtPtr st;
    if (!prep(h, st,
              "INSERT INTO echo_config (key, value) VALUES (?, ?) ON CONFLICT(key) DO UPDATE SET "
              "value = CAST(CAST(value AS INTEGER) + CAST(excluded.value AS INTEGER) AS TEXT)"))
        return false;
    bind_text(st.get(), 1, kFoldRejectedCounterKey);
    const std::string add = std::to_string(n);
    bind_text(st.get(), 2, add);
    return run(h, st.get());
}

void warn_rejected(std::string_view source, std::size_t n, std::optional<int64_t> first) {
    if (n == 0)
        return;
    // The first offending stamp only, never the payload.
    spdlog::warn("EchoFold: {} event(s) of source '{}' rejected for an unrepresentable time stamp "
                 "(first: {}); the rest of the batch folded",
                 n, source, first.value_or(0));
}

// Restores the progress handler on every exit path from a GC statement.
struct GcProgress {
    std::function<bool()> expired;
    sqlite3* db;
    GcProgress(sqlite3* d, std::function<bool()> f) : expired(std::move(f)), db(d) {
        // Every 1000 VM instructions; a nonzero return interrupts the statement.
        sqlite3_progress_handler(
            db, 1000,
            [](void* p) noexcept -> int {
                try {
                    return (*static_cast<std::function<bool()>*>(p))() ? 1 : 0;
                } catch (...) {
                    return 1;
                }
            },
            &expired);
    }
    ~GcProgress() { sqlite3_progress_handler(db, 0, nullptr, nullptr); }
    GcProgress(const GcProgress&) = delete;
    GcProgress& operator=(const GcProgress&) = delete;
};

} // namespace

EchoFold::EchoFold(NowFn now) : now_(std::move(now)) {}
EchoFold::~EchoFold() = default;

std::expected<void, std::string> EchoFold::install_fold_schema(EchoDatabase& db) {
    std::lock_guard lock(op_mu_);
    const auto r = db.checked_transaction([](TransactionHandle& h) -> std::expected<void, std::string> {
        // A view cannot take the name of an existing table, and CREATE VIEW IF NOT
        // EXISTS would then silently do nothing: drop the legacy table first.
        // DESTRUCTIVE; no production caller exists in this change.
        for (const auto& name : fold_view_names()) {
            StmtPtr st;
            if (!prep(h, st, "SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = ?"))
                return std::unexpected(h.error());
            bind_text(st.get(), 1, name);
            const int rc = sqlite3_step(st.get());
            if (rc != SQLITE_ROW && rc != SQLITE_DONE) {
                fail_sql(h, "schema probe failed");
                return std::unexpected(h.error());
            }
            st.reset(); // finalize the probe first: DROP TABLE needs the table unlocked
            if (rc == SQLITE_ROW && !h.exec("DROP TABLE " + name))
                return std::unexpected(h.error());
        }
        if (!h.exec(generate_fold_ddl()))
            return std::unexpected(h.error());
        return {};
    });
    // A reinstall may follow a dropped dictionary; never trust cached ids across it.
    cache_.clear();
    return r;
}

std::expected<FoldResult, std::string>
EchoFold::fold_rows(EchoDatabase& db, std::string_view source, const TierAccumulator& acc,
                    const std::optional<StateWrite>& state) {
    std::lock_guard lock(op_mu_);
    const FoldSourceDef* def = fold_source(source);
    if (!def || def->own_tables)
        return std::unexpected(std::format("'{}' is not a fold source", source));
    if (def->cursor_source)
        return std::unexpected(std::format("'{}' is a cursor source: use fold_cursor_rows", source));
    if (acc.def().name != def->name)
        return std::unexpected(std::format("accumulator is for '{}', not '{}'", acc.def().name, source));

    Interner in(cache_);
    std::size_t touched = 0;
    const auto r = db.checked_transaction([&](TransactionHandle& h) -> std::expected<void, std::string> {
        if (!upsert_tiers(h, *def, acc, in, touched))
            return std::unexpected(h.error());
        if (state && !write_state(h, *state))
            return std::unexpected(h.error());
        if (acc.rejected() > 0 && !bump_rejected(h, acc.rejected()))
            return std::unexpected(h.error());
        return {};
    });
    if (!r)
        return std::unexpected(r.error());
    publish(cache_, in.staged());
    warn_rejected(source, acc.rejected(), acc.first_rejected_stamp());
    return FoldResult{touched, acc.rejected()};
}

std::expected<CursorFoldResult, CursorFoldError>
EchoFold::fold_cursor_rows(EchoDatabase& db, std::string_view source,
                           const std::vector<KeyedContribution>& contributions,
                           const std::string& cursor_json,
                           const std::vector<StateWrite>& baseline_writes) {
    using Kind = CursorFoldError::Kind;
    // A blank key is silently catastrophic (the ring's primary key would discard every
    // event after the first and still report success); a NUL binds as zero-length and
    // collapses distinct keys. Refuse the batch before any write.
    for (const auto& c : contributions) {
        if (c.record_key.empty() || c.record_key.find('\0') != std::string::npos) {
            spdlog::error("EchoFold::fold_cursor_rows: refusing a '{}' batch with an empty or "
                          "NUL-bearing record_key",
                          source);
            return std::unexpected(CursorFoldError{Kind::KeyCollision,
                                                   "empty or NUL-bearing record_key"});
        }
    }

    std::lock_guard lock(op_mu_);
    const FoldSourceDef* def = fold_source(source);
    if (!def || def->own_tables || !def->cursor_source)
        return std::unexpected(
            CursorFoldError{Kind::Transient, std::format("'{}' is not a cursor source", source)});

    // An unrepresentable stamp drops only that contribution: it is not folded and not
    // entered in the ring (its batch commit advances the cursor, so it is never
    // re-offered), and it is counted below in the same transaction.
    std::vector<const KeyedContribution*> kept;
    kept.reserve(contributions.size());
    std::size_t rejected = 0;
    std::optional<int64_t> first_rejected;
    for (const auto& c : contributions) {
        if (fold_stamp_representable(c.ts)) {
            kept.push_back(&c);
        } else {
            ++rejected;
            if (!first_rejected)
                first_rejected = c.ts;
        }
    }

    Interner in(cache_);
    CursorFoldResult res;
    res.rejected = rejected;
    bool collided = false;
    const auto r = db.checked_transaction([&](TransactionHandle& h) -> std::expected<void, std::string> {
        res.folded = res.replayed = res.rows_touched = 0;
        StmtPtr max_seq, ins, dup;
        if (!prep(h, max_seq, "SELECT COALESCE(MAX(seq), 0) FROM echo_fold_seen WHERE source = ?") ||
            !prep(h, ins,
                  "INSERT OR IGNORE INTO echo_fold_seen (source, record_key, digest, seq) "
                  "VALUES (?, ?, ?, ?) RETURNING record_key") ||
            !prep(h, dup, "SELECT digest FROM echo_fold_seen WHERE source = ? AND record_key = ?"))
            return std::unexpected(h.error());

        bind_text(max_seq.get(), 1, source);
        if (sqlite3_step(max_seq.get()) != SQLITE_ROW) {
            fail_sql(h, "ring read failed");
            return std::unexpected(h.error());
        }
        int64_t seq = sqlite3_column_int64(max_seq.get(), 0);
        sqlite3_reset(max_seq.get()); // no read cursor left open across the writes below

        TierAccumulator acc(*def);
        for (const KeyedContribution* c : kept) {
            sqlite3_reset(ins.get());
            sqlite3_clear_bindings(ins.get());
            bind_text(ins.get(), 1, source);
            bind_text(ins.get(), 2, c->record_key);
            sqlite3_bind_int64(ins.get(), 3, c->identity_digest);
            sqlite3_bind_int64(ins.get(), 4, seq + 1);
            const int rc = sqlite3_step(ins.get());
            if (rc == SQLITE_ROW) { // inserted: a first sighting, fold it
                sqlite3_reset(ins.get()); // the insert is done; drop the pending RETURNING row
                ++seq;
                // add()'s bool is deliberately ignored: `kept` holds only representable
                // stamps, so it cannot refuse here; a misnamed key or measure makes
                // resolve() throw, which unwinds the lambda and rolls back as Transient.
                // The Interner (and its staged ids) lives OUTSIDE the lambda because
                // checked_transaction runs it exactly once, never retrying.
                acc.add(c->ts, c->keys, c->measures);
                ++res.folded;
                continue;
            }
            if (rc != SQLITE_DONE) {
                fail_sql(h, "ring insert failed");
                return std::unexpected(h.error());
            }
            // Ignored: the key is already in the ring. Same digest is a replay; a
            // different digest is two distinct OS records sharing a key.
            sqlite3_reset(dup.get());
            sqlite3_clear_bindings(dup.get());
            bind_text(dup.get(), 1, source);
            bind_text(dup.get(), 2, c->record_key);
            if (sqlite3_step(dup.get()) != SQLITE_ROW) {
                h.fail("replay ring: a key was ignored but its row could not be read back");
                return std::unexpected(h.error());
            }
            const bool same = sqlite3_column_int64(dup.get(), 0) == c->identity_digest;
            sqlite3_reset(dup.get());
            if (same) {
                ++res.replayed;
                continue;
            }
            spdlog::error("EchoFold::fold_cursor_rows: record_key COLLISION on '{}' (source '{}'): "
                          "the stored record is a DIFFERENT event, so accepting this batch would "
                          "advance the cursor past one that was never folded; failing the "
                          "transaction instead",
                          yuzu::log_key_token(c->record_key), source);
            collided = true;
            h.fail("record_key collision");
            return std::unexpected(h.error());
        }

        if (!upsert_tiers(h, *def, acc, in, res.rows_touched))
            return std::unexpected(h.error());

        // Keep the newest kReplayRingDepth keys of this source.
        if (seq > static_cast<int64_t>(kReplayRingDepth)) {
            StmtPtr prune;
            if (!prep(h, prune, "DELETE FROM echo_fold_seen WHERE source = ? AND seq <= ?"))
                return std::unexpected(h.error());
            bind_text(prune.get(), 1, source);
            sqlite3_bind_int64(prune.get(), 2, seq - static_cast<int64_t>(kReplayRingDepth));
            if (!run(h, prune.get()))
                return std::unexpected(h.error());
        }
        for (const auto& w : baseline_writes)
            if (!write_state(h, w))
                return std::unexpected(h.error());
        if (!write_cursor(h, source, cursor_json))
            return std::unexpected(h.error());
        if (rejected > 0 && !bump_rejected(h, rejected))
            return std::unexpected(h.error());
        return {};
    });
    if (!r)
        return std::unexpected(CursorFoldError{collided ? Kind::KeyCollision : Kind::Transient, r.error()});
    publish(cache_, in.staged());
    warn_rejected(source, rejected, first_rejected);
    return res;
}

std::expected<GcResult, std::string> EchoFold::gc_dictionary(EchoDatabase& db,
                                                             Clock::time_point deadline) {
    std::lock_guard lock(op_mu_);
    const std::string sql = dictionary_gc_sql(kGcBatch);
    GcResult out;
    for (;;) {
        // Cooperative: checked before each batch starts, and by the progress handler
        // while a batch executes. Not mutex acquisition, BEGIN IMMEDIATE's busy wait
        // or COMMIT I/O.
        if (now() >= deadline) {
            out.deadline_hit = true;
            break;
        }
        int64_t deleted = 0;
        bool interrupted = false;
        const auto r = db.checked_transaction([&](TransactionHandle& h) -> std::expected<void, std::string> {
            GcProgress guard(h.raw(), [this, deadline] { return now() >= deadline; });
            StmtPtr st;
            if (!prep(h, st, sql))
                return std::unexpected(h.error());
            int rc = SQLITE_OK;
            while ((rc = sqlite3_step(st.get())) == SQLITE_ROW)
                ++deleted;
            if (rc == SQLITE_INTERRUPT) { // the deadline: the batch rolls back, not an error
                interrupted = true;
                h.fail("dictionary GC interrupted by its deadline");
                return std::unexpected(h.error());
            }
            if (rc != SQLITE_DONE) {
                fail_sql(h, "dictionary GC step failed");
                return std::unexpected(h.error());
            }
            return {};
        });
        if (!r) {
            if (interrupted) {
                out.deadline_hit = true;
                break;
            }
            return std::unexpected(r.error());
        }
        if (deleted > 0) {
            out.deleted += deleted;
            cache_.clear(); // a deleted id must never be served from the cache
        }
        if (deleted < kGcBatch)
            break; // fewer than a full batch: nothing orphaned is left
    }
    return out;
}

} // namespace yuzu::echo
