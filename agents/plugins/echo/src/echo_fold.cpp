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

// The prepared statement, or null with the handle poisoned (the handle carries the text).
StmtPtr prep(TransactionHandle& h, const std::string& sql) {
    if (h.poisoned())
        return nullptr;
    sqlite3_stmt* raw = nullptr;
    if (sqlite3_prepare_v2(h.raw(), sql.c_str(), static_cast<int>(sql.size()), &raw, nullptr) !=
        SQLITE_OK) {
        fail_sql(h, "prepare failed");
        return nullptr;
    }
    return StmtPtr{raw};
}

// Step to completion; the RETURNING row count (never sqlite3_changes(), #1033), or
// nullopt with the handle poisoned.
std::optional<std::size_t> run(TransactionHandle& h, sqlite3_stmt* s) {
    if (h.poisoned())
        return std::nullopt;
    int rc = SQLITE_OK;
    std::size_t n = 0;
    while ((rc = sqlite3_step(s)) == SQLITE_ROW)
        ++n;
    if (rc != SQLITE_DONE) {
        fail_sql(h, "step failed");
        return std::nullopt;
    }
    return n;
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

// Interns strings INSIDE a transaction. New ids go to the caller's staging map; the
// caller publishes them to the shared cache only after COMMIT. Constructed inside the
// transaction callback, so both statements are finalised before COMMIT or ROLLBACK on
// every exit path.
class Interner {
public:
    Interner(const std::unordered_map<std::string, int64_t>& cache,
             std::unordered_map<std::string, int64_t>& staged)
        : cache_(cache), staged_(staged) {}

    // The id of `text`, or nullopt with the handle poisoned.
    std::optional<int64_t> intern(TransactionHandle& h, const std::string& text) {
        if (const auto it = cache_.find(text); it != cache_.end())
            return it->second;
        if (const auto it = staged_.find(text); it != staged_.end())
            return it->second;
        if (!add_) {
            find_ = prep(h, std::format("SELECT id FROM {} WHERE text = ?", kDictTable));
            add_ = prep(h, std::format("INSERT INTO {} (text) VALUES (?) RETURNING id", kDictTable));
            if (!find_ || !add_)
                return std::nullopt;
        }
        // SELECT first: an upsert on a hit still rewrites the index pages holding the string.
        int64_t id = 0;
        bind_one(find_.get(), text);
        const int rc = sqlite3_step(find_.get());
        if (rc == SQLITE_ROW) {
            id = sqlite3_column_int64(find_.get(), 0);
            sqlite3_reset(find_.get());
        } else if (rc == SQLITE_DONE) {
            bind_one(add_.get(), text);
            if (sqlite3_step(add_.get()) != SQLITE_ROW) {
                fail_sql(h, "dictionary intern failed");
                return std::nullopt;
            }
            id = sqlite3_column_int64(add_.get(), 0);
            if (sqlite3_step(add_.get()) != SQLITE_DONE) {
                fail_sql(h, "dictionary intern failed");
                return std::nullopt;
            }
        } else {
            fail_sql(h, "dictionary lookup failed");
            return std::nullopt;
        }
        staged_.emplace(text, id);
        return id;
    }

private:
    static void bind_one(sqlite3_stmt* s, const std::string& text) {
        sqlite3_reset(s);
        sqlite3_clear_bindings(s);
        bind_text(s, 1, text);
    }

    const std::unordered_map<std::string, int64_t>& cache_;
    std::unordered_map<std::string, int64_t>& staged_;
    StmtPtr find_, add_;
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

// Upsert every tier of the accumulator. The RETURNING row count summed over the
// tiers, or nullopt with the handle poisoned.
std::optional<std::size_t> upsert_tiers(TransactionHandle& h, const FoldSourceDef& def,
                                        const TierAccumulator& acc, Interner& in) {
    const auto& key_cols = acc.key_columns();
    std::size_t touched = 0;
    for (auto tier : def.tiers) {
        const auto rows = acc.rows(tier);
        if (rows.empty())
            continue;
        const StmtPtr st = prep(h, tier_upsert_sql(def, tier));
        if (!st)
            return std::nullopt;
        for (const auto& row : rows) {
            sqlite3_reset(st.get());
            sqlite3_clear_bindings(st.get());
            int idx = 1;
            sqlite3_bind_int64(st.get(), idx++, row.bucket);
            for (std::size_t k = 0; k < key_cols.size(); ++k) {
                if (key_cols[k].interned) {
                    const auto id = in.intern(h, std::get<std::string>(row.keys[k]));
                    if (!id)
                        return std::nullopt;
                    sqlite3_bind_int64(st.get(), idx++, *id);
                } else {
                    bind_value(st.get(), idx++, row.keys[k]);
                }
            }
            for (const auto& m : row.measures)
                bind_value(st.get(), idx++, m);
            const auto n = run(h, st.get());
            if (!n)
                return std::nullopt;
            touched += *n;
        }
    }
    return touched;
}

// Prepare `sql`, bind `args` in order, step to completion. Statements with no result rows.
bool exec_bound(TransactionHandle& h, const std::string& sql, std::initializer_list<Value> args) {
    const StmtPtr st = prep(h, sql);
    if (!st)
        return false;
    int i = 1;
    for (const auto& a : args)
        bind_value(st.get(), i++, a);
    return run(h, st.get()).has_value();
}

// echo_cursor UPSERT (same SQL as the raw-store cursor commit).
bool write_cursor(TransactionHandle& h, std::string_view source, const std::string& json) {
    return exec_bound(h,
                      "INSERT INTO echo_cursor (source, cursor_json, updated_at) VALUES (?, ?, ?) "
                      "ON CONFLICT(source) DO UPDATE SET cursor_json = excluded.cursor_json, "
                      "updated_at = excluded.updated_at",
                      {vt(source), vt(json), vi(now_epoch_seconds())});
}

// Add `n` to the persisted rejected-events counter. An UPSERT-add inside the fold's
// own transaction, so a rollback leaves the counter exactly as it was.
bool bump_rejected(TransactionHandle& h, std::size_t n) {
    return exec_bound(h,
                      "INSERT INTO echo_config (key, value) VALUES (?, ?) ON CONFLICT(key) DO UPDATE "
                      "SET value = CAST(CAST(value AS INTEGER) + CAST(excluded.value AS INTEGER) AS TEXT)",
                      {vt(kFoldRejectedCounterKey), vt(std::to_string(n))});
}

void warn_rejected(std::string_view source, std::size_t n, std::optional<int64_t> first) {
    if (n == 0)
        return;
    // The first offending stamp only, never the payload.
    spdlog::warn("EchoFold: {} event(s) of source '{}' rejected for an unrepresentable time stamp "
                 "or a non-finite measure (first stamp: {}); the rest of the batch folded",
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

// echo_state UPSERT through the store's own statement (EchoDatabase befriends EchoFold for it).
// upsert_state_locked only logs and returns false, so the failure is recorded on the handle here.
bool EchoFold::write_state(TransactionHandle& h, const StateWrite& w) {
    if (h.poisoned())
        return false;
    if (EchoDatabase::upsert_state_locked(h.raw(), w.collector, w.json))
        return true;
    h.fail("echo_state write failed");
    return false;
}

std::expected<void, std::string> EchoFold::install_fold_schema(EchoDatabase& db) {
    std::lock_guard lock(op_mu_);
    const auto r = db.checked_transaction([](TransactionHandle& h) -> std::expected<void, std::string> {
        // A view cannot take the name of an existing table, and CREATE VIEW IF NOT
        // EXISTS would then silently do nothing: drop the legacy table first. An empty
        // one is dropped; one that holds rows refuses the install, so it destroys no data.
        for (const auto& name : fold_view_names()) {
            StmtPtr st = prep(h, "SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = ?");
            if (!st)
                return std::unexpected(h.error());
            bind_text(st.get(), 1, name);
            const int rc = sqlite3_step(st.get());
            if (rc != SQLITE_ROW && rc != SQLITE_DONE) {
                fail_sql(h, "schema probe failed");
                return std::unexpected(h.error());
            }
            st.reset(); // finalize the probe first: DROP TABLE needs the table unlocked
            if (rc != SQLITE_ROW)
                continue;
            st = prep(h, "SELECT count(*) FROM " + name);
            if (!st || sqlite3_step(st.get()) != SQLITE_ROW) {
                if (st)
                    fail_sql(h, "legacy table count failed");
                return std::unexpected(h.error());
            }
            const int64_t held = sqlite3_column_int64(st.get(), 0);
            st.reset();
            if (held > 0) {
                h.fail(std::format("{} holds {} rows; move them aside before installing the roll-up schema",
                                   name, held));
                return std::unexpected(h.error());
            }
            if (!h.exec("DROP TABLE " + name))
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

std::expected<std::size_t, std::string>
EchoFold::fold_body(TransactionHandle& h, const FoldSourceDef& def, const TierAccumulator& acc,
                    const std::optional<StateWrite>& state,
                    const std::unordered_map<std::string, int64_t>& cache,
                    std::unordered_map<std::string, int64_t>& staged) {
    Interner in(cache, staged); // its statements are finalised before the caller commits
    const auto n = upsert_tiers(h, def, acc, in);
    if (!n)
        return std::unexpected(h.error());
    if (state && !write_state(h, *state))
        return std::unexpected(h.error());
    return *n;
}

std::expected<FoldResult, std::string>
EchoFold::fold_rows(EchoDatabase& db, std::string_view source, const TierAccumulator& acc,
                    const std::optional<StateWrite>& state, const ExtraFn& extra) {
    std::lock_guard lock(op_mu_);
    const FoldSourceDef* def = fold_source(source);
    if (!def || def->own_tables)
        return std::unexpected(std::format("'{}' is not a fold source", source));
    if (def->cursor_source)
        return std::unexpected(std::format("'{}' is a cursor source: use fold_cursor_rows", source));
    if (acc.def().name != def->name)
        return std::unexpected(std::format("accumulator is for '{}', not '{}'", acc.def().name, source));

    std::unordered_map<std::string, int64_t> staged;
    std::size_t touched = 0;
    const auto r = db.checked_transaction([&](TransactionHandle& h) -> std::expected<void, std::string> {
        const auto n = fold_body(h, *def, acc, state, cache_, staged);
        if (!n)
            return std::unexpected(n.error());
        touched = *n;
        if (acc.rejected() > 0 && !bump_rejected(h, acc.rejected()))
            return std::unexpected(h.error());
        if (extra) {
            if (auto x = extra(h); !x)
                return std::unexpected(std::move(x.error()));
        }
        return {};
    });
    if (!r)
        return std::unexpected(r.error());
    publish(cache_, staged);
    warn_rejected(source, acc.rejected(), acc.first_rejected_stamp());
    return FoldResult{touched, acc.rejected()};
}

std::expected<std::size_t, std::string>
EchoFold::fold_in(TransactionHandle& h, std::string_view source, const TierAccumulator& acc,
                  const std::optional<StateWrite>& state) {
    const FoldSourceDef* def = fold_source(source);
    if (!def || def->own_tables)
        return std::unexpected(std::format("'{}' is not a fold source", source));
    if (acc.def().name != def->name)
        return std::unexpected(std::format("accumulator is for '{}', not '{}'", acc.def().name, source));
    // An empty cache and a throwaway staging map: nothing learnt in the caller's transaction is
    // published, so a rollback cannot leave an id the database does not have.
    static const std::unordered_map<std::string, int64_t> kNoCache;
    std::unordered_map<std::string, int64_t> staged;
    auto n = fold_body(h, *def, acc, state, kNoCache, staged);
    if (n && acc.rejected() > 0 && !bump_rejected(h, acc.rejected()))
        return std::unexpected(h.error());
    return n;
}

std::expected<CursorFoldResult, CursorFoldError>
EchoFold::fold_cursor_rows(EchoDatabase& db, std::string_view source,
                           const std::vector<KeyedContribution>& contributions,
                           const std::string& cursor_json,
                           const std::vector<StateWrite>& baseline_writes) {
    using Kind = CursorFoldError::Kind;
    // A blank key is silently catastrophic (the ring's primary key would discard every
    // event after the first and still report success); a NUL is refused as the raw store
    // refuses it (insert_power_events_and_cursor), and a C-string reader of the key would
    // stop at it. Refuse the batch before any write.
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
            CursorFoldError{Kind::Misuse, std::format("'{}' is not a cursor source", source)});

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

    std::unordered_map<std::string, int64_t> staged;
    CursorFoldResult res;
    res.rejected = rejected;
    Kind kind = Kind::Transient;
    const auto r = db.checked_transaction([&](TransactionHandle& h) -> std::expected<void, std::string> {
        Interner in(cache_, staged);
        res.folded = res.replayed = res.rows_touched = 0;
        // Once one prepare fails the handle is poisoned and the rest return null too.
        const StmtPtr max_seq =
            prep(h, "SELECT COALESCE(MAX(seq), 0) FROM echo_fold_seen WHERE source = ?");
        const StmtPtr ins = prep(h, "INSERT OR IGNORE INTO echo_fold_seen (source, record_key, "
                                    "digest, seq) VALUES (?, ?, ?, ?) RETURNING record_key");
        const StmtPtr dup =
            prep(h, "SELECT digest FROM echo_fold_seen WHERE source = ? AND record_key = ?");
        if (!max_seq || !ins || !dup)
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
                // stamps and a cursor source has no REAL measure, so it cannot refuse. A
                // misnamed key or measure throws; that is a caller error, never a retry.
                try {
                    acc.add(c->ts, c->keys, c->measures);
                } catch (const std::invalid_argument& e) {
                    kind = Kind::Misuse;
                    h.fail(e.what());
                    return std::unexpected(h.error());
                }
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
            kind = Kind::KeyCollision;
            h.fail(std::format("record_key collision at contribution {} of source '{}' ({})",
                               c - contributions.data(), source, yuzu::log_key_token(c->record_key)));
            return std::unexpected(h.error());
        }

        const auto touched = upsert_tiers(h, *def, acc, in);
        if (!touched)
            return std::unexpected(h.error());
        res.rows_touched = *touched;

        // Keep the newest kReplayRingDepth keys of this source.
        if (seq > static_cast<int64_t>(kReplayRingDepth)) {
            const StmtPtr prune =
                prep(h, "DELETE FROM echo_fold_seen WHERE source = ? AND seq <= ?");
            if (!prune)
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
        return std::unexpected(CursorFoldError{kind, r.error()});
    publish(cache_, staged);
    warn_rejected(source, rejected, first_rejected);
    return res;
}

std::expected<GcResult, std::string> EchoFold::gc_dictionary(EchoDatabase& db,
                                                             Clock::time_point deadline) {
    std::lock_guard lock(op_mu_);
    GcResult out;
    // Run `sqls` in ONE transaction under the pass deadline. The RETURNING rows they
    // produced, or nullopt when the deadline fired (that transaction rolled back).
    const auto timed = [&](std::initializer_list<std::string> sqls)
        -> std::expected<std::optional<int64_t>, std::string> {
        int64_t rows = 0;
        bool hit = false;
        const auto r = db.checked_transaction([&](TransactionHandle& h) -> std::expected<void, std::string> {
            GcProgress guard(h.raw(), [this, deadline] { return now() >= deadline; });
            for (const auto& sql : sqls) {
                // A prepare can be interrupted too (it may re-load the schema after a VACUUM).
                const StmtPtr st = prep(h, sql);
                const auto n = st ? run(h, st.get()) : std::nullopt;
                if (!n) {
                    hit = sqlite3_errcode(h.raw()) == SQLITE_INTERRUPT;
                    return std::unexpected(h.error());
                }
                rows += static_cast<int64_t>(*n);
            }
            return {};
        });
        if (r)
            return rows;
        if (hit)
            return std::nullopt;
        return std::unexpected(r.error());
    };

    // Cooperative: checked before each batch starts and by the progress handler inside a statement
    // (the batch rolls back). Not mutex acquisition, BEGIN IMMEDIATE's busy wait or COMMIT I/O.
    if (now() >= deadline) {
        out.deadline_hit = true;
        return out;
    }
    // The live set is derived ONCE per pass (op_mu_ is held, so no fold adds a reference
    // meanwhile, and a retention delete only creates orphans), then orphans go by id. The
    // temp table is dropped on every exit path and before each pass.
    const std::string drop = std::format("DROP TABLE IF EXISTS temp.{}", kGcOrphanTable);
    struct DropOrphans {
        EchoDatabase& db;
        const std::string& sql;
        ~DropOrphans() { db.execute_sql(sql); }
    } const cleanup{db, drop};
    const auto built = timed(
        {drop, std::format("CREATE TEMP TABLE {} (id INTEGER PRIMARY KEY)", kGcOrphanTable),
         dictionary_orphans_sql()});
    if (!built)
        return std::unexpected(built.error());
    if (!*built) { // the scan outran the deadline: nothing was deleted
        out.deadline_hit = true;
        return out;
    }
    out.live_set_built = true;
    const std::string batch =
        std::format("SELECT id FROM temp.{} ORDER BY id LIMIT {}", kGcOrphanTable, kGcBatch);
    const std::string del_dict =
        std::format("DELETE FROM {} WHERE id IN ({}) RETURNING id", kDictTable, batch);
    const std::string del_orphan =
        std::format("DELETE FROM temp.{} WHERE id IN ({})", kGcOrphanTable, batch);
    for (;;) {
        if (now() >= deadline) {
            out.deadline_hit = true;
            break;
        }
        const auto n = timed({del_dict, del_orphan});
        if (!n)
            return std::unexpected(n.error());
        if (!*n) { // the deadline fired mid-statement: the batch rolled back
            out.deadline_hit = true;
            break;
        }
        if (**n > 0) {
            out.deleted += **n;
            cache_.clear(); // a deleted id must never be served from the cache
        }
        if (**n < kGcBatch)
            break; // fewer than a full batch: nothing orphaned is left
    }
    return out;
}

} // namespace yuzu::echo
