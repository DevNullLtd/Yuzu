#pragma once

/**
 * echo_fold.hpp -- roll-up fold: pure bucket math, the tier accumulator, the 17
 * per-source deltas and the transactional fold writer.
 *
 * ROLL-UP IS THE ONLY STORAGE MODEL. Raw capture rows are not kept, and there is
 * no setting, flag, mode switch or environment variable that selects between the
 * two; none may be added. Every collector writes through EchoDatabase's fold_*
 * wrappers, which build a TierAccumulator with the matching *_delta below and hand
 * it to the ONE EchoFold the database owns; the schema is installed by
 * EchoDatabase::open() (a fresh database) or by its v10 migration (an existing one).
 *
 * Two halves:
 *   - PURE CORE (this header, no I/O): bucket_start, Value, TierRow,
 *     TierAccumulator, tier_upsert_sql, identity_digest and the *_delta
 *     functions. Fixture-fed in tests; nothing here opens a database.
 *   - SHELL (echo_fold.cpp): class EchoFold, the only code that touches SQLite.
 *
 * EVENT TIMES ARE TRUSTED AS GIVEN. A bucket comes from the event's own stamp
 * (UTC, floor division; calendar month via std::chrono). There is no clamp
 * against the wall clock and no counter for far-future stamps. Accepted
 * residual: a stamp inside the representable domain but far in the future
 * creates a bucket only age-based eviction removes.
 *
 * The ONE exception is an UNREPRESENTABLE stamp (outside kFoldMinStamp ..
 * kFoldMaxStamp, 0001-01-01..9999-12-31 UTC), which no calendar can bucket, or a
 * NON-FINITE measure (SQLite binds NaN as NULL, which a NOT NULL column refuses).
 * Such an event is rejected INDIVIDUALLY: the rest of its batch folds normally.
 * The rejection is counted in the persisted echo_config counter
 * `fold_rejected_events_total` (kFoldRejectedCounterKey), added inside the same
 * transaction as the fold so a rollback leaves the counter unchanged, and
 * logged once per batch naming the first rejected event's stamp only (never the
 * payload). echo.status does not report the counter.
 *
 * kLast merge: the incoming value replaces the stored one iff its guard column
 * is >= the stored guard, so an older event never overwrites a newer one and two
 * events in the same second resolve to the later arrival.
 */

#include "echo_db.hpp"
#include "echo_fold_schema.hpp"
#include "echo_registry_parsers.hpp"
#include "echo_usage.hpp"

#include <sha256.hpp>

#include <algorithm>
#include <charconv>
#include <chrono>
#include <cmath>
#include <cstddef>
#include <cstdint>
#include <expected>
#include <format>
#include <functional>
#include <initializer_list>
#include <limits>
#include <map>
#include <mutex>
#include <optional>
#include <stdexcept>
#include <string>
#include <string_view>
#include <unordered_map>
#include <utility>
#include <variant>
#include <vector>

namespace yuzu::echo {

// ── Bucket math ─────────────────────────────────────────────────────────────

/// The representable event-time domain: 0001-01-01T00:00:00Z .. 9999-12-31T23:59:59Z.
/// Floor-division arithmetic is overflow-free inside it and std::chrono's calendar
/// is defined over it.
inline constexpr int64_t kFoldMinStamp = -62135596800LL;
inline constexpr int64_t kFoldMaxStamp = 253402300799LL;

/// True iff `ts` can be bucketed by every tier.
[[nodiscard]] inline bool fold_stamp_representable(int64_t ts) noexcept {
    return ts >= kFoldMinStamp && ts <= kFoldMaxStamp;
}

/// Start of the `tier` bucket ("hourly" | "daily" | "monthly") containing `ts`,
/// in UTC epoch seconds. Refuses a stamp outside the representable domain with a
/// message naming it. Every in-domain stamp, past or future, is bucketed exactly.
[[nodiscard]] inline std::expected<int64_t, std::string> bucket_start(int64_t ts,
                                                                       std::string_view tier) {
    if (!fold_stamp_representable(ts))
        return std::unexpected(std::format("event time {} is outside the representable range {}..{}",
                                           ts, kFoldMinStamp, kFoldMaxStamp));
    const auto floor_to = [ts](int64_t n) {
        const int64_t r = ts % n;
        return ts - (r < 0 ? r + n : r);
    };
    if (tier == "hourly")
        return floor_to(3600);
    if (tier == "daily")
        return usage::day_ts_for(ts);
    if (tier == "monthly") {
        using namespace std::chrono;
        const sys_days day = floor<days>(sys_seconds{seconds{ts}});
        const year_month_day ymd{day};
        // days::rep is a 32-bit int: widen BEFORE multiplying.
        return static_cast<int64_t>(sys_days{ymd.year() / ymd.month() / 1}.time_since_epoch().count()) *
               86400;
    }
    return std::unexpected(std::format("unknown tier '{}'", tier));
}

// ── Values and rows ─────────────────────────────────────────────────────────

using Value = std::variant<int64_t, double, std::string>;
/// Column name -> value. Names point at string literals / static column names.
using NamedValues = std::vector<std::pair<std::string_view, Value>>;

[[nodiscard]] inline Value vi(int64_t v) { return v; }
[[nodiscard]] inline Value vr(double v) { return v; }
[[nodiscard]] inline Value vt(std::string_view v) { return std::string{v}; }

/// One roll-up row: the bucket, the key values in FoldSourceDef key order and the
/// merged measures in measure order (generated columns are never carried).
struct TierRow {
    int64_t bucket{0};
    std::vector<Value> keys;
    std::vector<Value> measures;
};

// ── Accumulator ─────────────────────────────────────────────────────────────

/// Pre-aggregates one batch of events into every tier of one source, merging by
/// each measure's MergeOp. Pure: no I/O, no clock.
///
/// A key or measure the caller does not name defaults to 0 / 0.0 / "" -- which is
/// how the enrichment columns (those a delta leaves unnamed) stay at zero. A name that is
/// not a column of the source, or a value whose type is not its column's declared
/// type, throws std::invalid_argument (a declaration typo, caught by the per-delta
/// tests), never a silently dropped or converted value.
class TierAccumulator {
public:
    explicit TierAccumulator(const FoldSourceDef& def) : def_(&def) {
        for (const auto& c : def.columns) {
            if (c.role == ColumnRole::kKey) {
                key_index_.emplace(c.name, key_cols_.size());
                key_cols_.push_back(c);
            } else if (c.role == ColumnRole::kMeasure) {
                measure_index_.emplace(c.name, measure_cols_.size());
                measure_cols_.push_back(c);
            }
        }
        for (const auto& c : measure_cols_) {
            std::size_t guard = 0;
            if (c.merge == MergeOp::kLast) {
                const auto it = measure_index_.find(c.guard);
                if (it == measure_index_.end() || measure_cols_[it->second].sql_type != "INTEGER")
                    throw std::invalid_argument(std::format(
                        "{}.{}: kLast guard '{}' is not an INTEGER measure", def.name, c.name,
                        c.guard));
                guard = it->second;
            }
            guards_.push_back(guard);
        }
        for (auto t : def.tiers)
            tiers_.push_back({t, {}});
    }

    /// Fold one event. Returns false -- folding nothing -- when `ts` is
    /// unrepresentable or a measure is non-finite (counted in rejected()); the
    /// caller keeps folding the rest.
    bool add(int64_t ts, const NamedValues& keys, const NamedValues& measures) {
        const auto reject = [&] {
            ++rejected_;
            if (!first_rejected_)
                first_rejected_ = ts;
            return false;
        };
        std::vector<int64_t> buckets;
        buckets.reserve(tiers_.size());
        for (const auto& t : tiers_) {
            const auto b = bucket_start(ts, t.name);
            if (!b)
                return reject();
            buckets.push_back(*b);
        }
        std::vector<Value> kv = resolve(key_cols_, key_index_, keys, "key");
        std::vector<Value> mv = resolve(measure_cols_, measure_index_, measures, "measure");
        for (const auto& v : mv)
            if (const auto* d = std::get_if<double>(&v); d && !std::isfinite(*d))
                return reject();
        for (std::size_t i = 0; i < tiers_.size(); ++i) {
            const auto [it, fresh] = tiers_[i].slots.try_emplace(SlotKey{buckets[i], kv}, mv);
            if (!fresh)
                merge(it->second, mv);
        }
        return true;
    }

    /// The tier's rows ordered by bucket, then by an unspecified but stable key order;
    /// empty for an unknown tier.
    [[nodiscard]] std::vector<TierRow> rows(std::string_view tier) const {
        std::vector<TierRow> out;
        for (const auto& t : tiers_) {
            if (t.name != tier)
                continue;
            out.reserve(t.slots.size());
            for (const auto& [k, measures] : t.slots)
                out.push_back({k.first, k.second, measures});
        }
        return out;
    }

    [[nodiscard]] const FoldSourceDef& def() const noexcept { return *def_; }
    [[nodiscard]] const std::vector<ColumnDef>& key_columns() const noexcept { return key_cols_; }
    [[nodiscard]] const std::vector<ColumnDef>& measure_columns() const noexcept {
        return measure_cols_;
    }
    /// Events refused for an unrepresentable stamp or a non-finite measure.
    [[nodiscard]] std::size_t rejected() const noexcept { return rejected_; }
    /// The first refused event's stamp -- the only thing the batch warning names.
    [[nodiscard]] std::optional<int64_t> first_rejected_stamp() const noexcept {
        return first_rejected_;
    }

    /// Convenience for tests and callers: the named measure / key of a row, or
    /// nullptr when the source has no such column.
    [[nodiscard]] const Value* measure(const TierRow& r, std::string_view name) const {
        const auto it = measure_index_.find(name);
        return it == measure_index_.end() ? nullptr : &r.measures[it->second];
    }
    [[nodiscard]] const Value* key(const TierRow& r, std::string_view name) const {
        const auto it = key_index_.find(name);
        return it == key_index_.end() ? nullptr : &r.keys[it->second];
    }

private:
    using SlotKey = std::pair<int64_t, std::vector<Value>>; // (bucket, keys)
    // (bucket, keys) -> merged measures. The bucket leads, so rows come out bucket-ordered.
    struct Tier {
        std::string_view name;
        std::map<SlotKey, std::vector<Value>> slots;
    };

    static Value zero_of(const ColumnDef& c) {
        if (c.sql_type == "TEXT")
            return std::string{};
        if (c.sql_type == "REAL")
            return 0.0;
        return int64_t{0};
    }

    // A value must already be of its column's declared type: no int<->real conversion.
    static Value coerce(const ColumnDef& c, const Value& v) {
        const bool ok = c.sql_type == "TEXT"   ? std::holds_alternative<std::string>(v)
                        : c.sql_type == "REAL" ? std::holds_alternative<double>(v)
                                               : std::holds_alternative<int64_t>(v);
        if (!ok)
            throw std::invalid_argument(
                std::format("value type does not fit column '{}' ({})", c.name, c.sql_type));
        return v;
    }

    std::vector<Value> resolve(const std::vector<ColumnDef>& cols,
                               const std::unordered_map<std::string_view, std::size_t>& index,
                               const NamedValues& given, std::string_view what) const {
        std::vector<Value> out;
        out.reserve(cols.size());
        for (const auto& c : cols)
            out.push_back(zero_of(c));
        for (const auto& [name, v] : given) {
            const auto it = index.find(name);
            if (it == index.end())
                throw std::invalid_argument(
                    std::format("{} is not a {} column of source {}", name, what, def_->name));
            out[it->second] = coerce(cols[it->second], v);
        }
        return out;
    }

    // Merge `in` into `cur`. kLast reads the guard values as they were BEFORE this
    // event, exactly as the SQL UPSERT does (every right-hand side sees the old row).
    void merge(std::vector<Value>& cur, const std::vector<Value>& in) const {
        std::vector<char> take(cur.size(), 0);
        for (std::size_t j = 0; j < measure_cols_.size(); ++j)
            if (measure_cols_[j].merge == MergeOp::kLast)
                take[j] = std::get<int64_t>(in[guards_[j]]) >= std::get<int64_t>(cur[guards_[j]]);
        for (std::size_t j = 0; j < measure_cols_.size(); ++j) {
            const bool real = measure_cols_[j].sql_type == "REAL";
            switch (measure_cols_[j].merge) {
            case MergeOp::kSum:
                if (real)
                    std::get<double>(cur[j]) += std::get<double>(in[j]);
                else {
                    // Saturate: signed overflow is undefined, and a wrapped total would be
                    // a plausible wrong number. (The SQL UPSERT promotes to REAL instead;
                    // this sums within one batch only.)
                    auto& a = std::get<int64_t>(cur[j]);
                    const int64_t b = std::get<int64_t>(in[j]);
                    if (b > 0 && a > std::numeric_limits<int64_t>::max() - b)
                        a = std::numeric_limits<int64_t>::max();
                    else if (b < 0 && a < std::numeric_limits<int64_t>::min() - b)
                        a = std::numeric_limits<int64_t>::min();
                    else
                        a += b;
                }
                break;
            case MergeOp::kMax:
                if (real)
                    cur[j] = std::max(std::get<double>(cur[j]), std::get<double>(in[j]));
                else
                    cur[j] = std::max(std::get<int64_t>(cur[j]), std::get<int64_t>(in[j]));
                break;
            case MergeOp::kMin:
                if (real)
                    cur[j] = std::min(std::get<double>(cur[j]), std::get<double>(in[j]));
                else
                    cur[j] = std::min(std::get<int64_t>(cur[j]), std::get<int64_t>(in[j]));
                break;
            case MergeOp::kLast:
                if (take[j])
                    cur[j] = in[j];
                break;
            case MergeOp::kNone:
                break;
            }
        }
    }

    const FoldSourceDef* def_;
    std::vector<ColumnDef> key_cols_;
    std::vector<ColumnDef> measure_cols_;
    std::unordered_map<std::string_view, std::size_t> key_index_;
    std::unordered_map<std::string_view, std::size_t> measure_index_;
    std::vector<std::size_t> guards_; // per measure: index of its kLast guard (unused otherwise)
    std::vector<Tier> tiers_;
    std::size_t rejected_{0};
    std::optional<int64_t> first_rejected_;
};

// ── UPSERT builder ──────────────────────────────────────────────────────────

/// The fold-time UPSERT for one (source, tier): bound as (bucket, keys...,
/// measures...) in exactly TierAccumulator's order (keys then measures, each in
/// declaration order), merged by each measure's MergeOp, and RETURNING id so the
/// caller counts rows touched without sqlite3_changes(). Generated columns are
/// never written. Every right-hand side of the DO UPDATE sees the stored row, so
/// a kLast guard compares against the OLD guard value.
[[nodiscard]] inline std::string tier_upsert_sql(const FoldSourceDef& def, std::string_view tier) {
    std::vector<std::string> keys, measures;
    const auto bucket = std::string{ts_column_for_suffix(tier)};
    for (const auto& c : def.columns) {
        const std::string name = physical_column_name(c);
        if (c.role == ColumnRole::kKey)
            keys.push_back(name);
        else if (c.role == ColumnRole::kMeasure)
            measures.push_back(name);
    }
    const auto join = [](const std::vector<std::string>& v, std::string_view sep) {
        std::string out;
        for (const auto& x : v)
            out += (out.empty() ? "" : std::string{sep}) + x;
        return out;
    };
    std::vector<std::string> insert_cols{bucket};
    insert_cols.insert(insert_cols.end(), keys.begin(), keys.end());
    insert_cols.insert(insert_cols.end(), measures.begin(), measures.end());
    std::vector<std::string> conflict{bucket};
    conflict.insert(conflict.end(), keys.begin(), keys.end());
    return std::format("INSERT INTO {0}({1}) VALUES({2}) ON CONFLICT({3}) DO UPDATE SET {4} "
                       "RETURNING id",
                       physical_table_name(def.name, tier), join(insert_cols, ","),
                       join(std::vector<std::string>(insert_cols.size(), "?"), ","),
                       join(conflict, ","), fold_upsert_assignments(def));
}

// ── Replay identity (cursor sources) ────────────────────────────────────────

/// One cursor-source event as a roll-up contribution. `record_key` is the OS
/// record's replay key; `identity_digest` is what the replay ring compares to tell
/// a legitimate replay (same digest) from a key collision (different digest).
struct KeyedContribution {
    std::string record_key;
    int64_t identity_digest{0};
    int64_t ts{0};
    NamedValues keys;
    NamedValues measures;
};

/// SHA-256 (hex) over the length-prefixed field list. Length prefixes (not a separator) so no
/// field value can forge a boundary.
/// 64 bits distinguish payloads; this is a replay check, not an adversarial boundary.
/// The digest is PERSISTED in echo_fold_seen: changing the field set a delta feeds
/// in, or this encoding, makes every stored digest a false collision, so such a change
/// must clear the ring (DELETE FROM echo_fold_seen) in the same schema step.
[[nodiscard]] inline std::string identity_hex(const std::vector<std::string>& fields) {
    std::string buf;
    for (const auto& f : fields) {
        buf += std::to_string(f.size());
        buf += ':';
        buf += f;
    }
    return yuzu::shared::sha256_hex(buf);
}

/// First 8 bytes of identity_hex, as a signed 64-bit value.
[[nodiscard]] inline int64_t identity_digest(const std::vector<std::string>& fields) {
    const std::string hex = identity_hex(fields);
    uint64_t v = 0;
    std::from_chars(hex.data(), hex.data() + 16, v, 16);
    return static_cast<int64_t>(v);
}

// ── The 13 snapshot-diff deltas ─────────────────────────────────────────────
//
// Each folds one batch of already-derived events into `acc`. Enrichment columns
// (the ones the event structs do not carry) are left unnamed and so stay 0 / ''.
// An unrecognised action token is ignored, never guessed at.

/// The measure `action` maps to in `table`, or nullptr for a token the delta does
/// not know (the caller skips the event).
[[nodiscard]] inline const char*
pick(std::string_view action, std::initializer_list<std::pair<std::string_view, const char*>> table) {
    for (const auto& [token, measure] : table)
        if (action == token)
            return measure;
    return nullptr;
}

inline void process_delta(const std::vector<ProcessEvent>& events, TierAccumulator& acc) {
    for (const auto& e : events) {
        const char* measure = pick(e.action, {{"started", "start_count"}, {"stopped", "stop_count"}});
        if (!measure)
            continue;
        // elevated_count, spoofed_parent_count: zero. An exit with a non-zero status is abnormal;
        // only a stream carries one, so the poll leaves abnormal_exit_count at zero.
        NamedValues measures{{measure, vi(1)}};
        if (e.action == "stopped" && e.exit_code != 0)
            measures.emplace_back("abnormal_exit_count", vi(1));
        acc.add(e.ts, {{"name", vt(e.name)}, {"user", vt(e.user)}, {"parent_name", vt(e.parent_name)}},
                measures);
    }
}

inline void tcp_delta(const std::vector<NetworkEvent>& events, TierAccumulator& acc) {
    for (const auto& e : events) {
        // duration_s_sum: zero.
        if (e.action == "listen_open" || e.action == "listen_close") {
            // A listening socket folds into tcp as remote_addr='*', remote_port=local_port.
            acc.add(e.ts,
                    {{"remote_addr", vt("*")}, {"remote_port", vi(e.local_port)},
                     {"proto", vt(e.proto)}, {"process_name", vt(e.process_name)}},
                    {{e.action == "listen_open" ? "listen_open_count" : "listen_close_count",
                      vi(1)}});
            continue;
        }
        const char* measure = pick(e.action, {{"connected", "connect_count"},
                                              {"disconnected", "disconnect_count"},
                                              {"failed", "failed_count"}});
        if (!measure)
            continue;
        acc.add(e.ts,
                {{"remote_addr", vt(e.remote_addr)}, {"remote_port", vi(e.remote_port)},
                 {"proto", vt(e.proto)}, {"process_name", vt(e.process_name)}},
                {{measure, vi(1)}});
    }
}

inline void module_delta(const std::vector<ModuleRow>& events, TierAccumulator& acc) {
    for (const auto& e : events) {
        // load_count counts `loaded` only (a `seed` row contributes nothing); an unload is
        // not stored; rebased_count: zero.
        const char* measure = pick(e.action, {{"loaded", "load_count"}, {"blocked", "blocked_count"}});
        if (!measure)
            continue;
        acc.add(e.ts,
                {{"module_name", vt(e.module_name)}, {"signer", vt(e.signer)},
                 {"signed_state", vt(e.signed_state)}, {"is_kernel", vi(e.is_kernel ? 1 : 0)},
                 {"module_dir", vt(e.module_dir)}, {"process_name", vt(e.process_name)}},
                {{measure, vi(1)}});
    }
}

// compute_service_events() emits exactly three tokens. status_changes counts
// state_changed only, as the registry's existing service tier does; started and
// stopped feed install_count and remove_count.
inline void service_delta(const std::vector<ServiceEvent>& events, TierAccumulator& acc) {
    for (const auto& e : events) {
        const char* measure = pick(e.action, {{"started", "install_count"},
                                              {"stopped", "remove_count"},
                                              {"state_changed", "status_changes"}});
        if (!measure)
            continue;
        // last_exit_code, last_start_account, last_binary_path, failed_count: zero / ''.
        acc.add(e.ts, {{"name", vt(e.name)}},
                {{measure, vi(1)}, {"last_status", vt(e.status)}, {"last_ts", vi(e.ts)}});
    }
}

inline void user_delta(const std::vector<UserEvent>& events, TierAccumulator& acc) {
    for (const auto& e : events) {
        const char* measure = pick(e.action, {{"login", "login_count"},
                                              {"logout", "logout_count"},
                                              {"disconnect", "disconnect_count"}});
        if (!measure)
            continue;
        // session_s_sum: zero.
        acc.add(e.ts,
                {{"user", vt(e.user)}, {"domain", vt(e.domain)}, {"logon_type", vt(e.logon_type)}},
                {{measure, vi(1)}});
    }
}

inline void software_delta(const std::vector<SoftwareEvent>& events, TierAccumulator& acc) {
    for (const auto& e : events) {
        const char* measure = pick(e.action, {{"installed", "install_count"},
                                              {"removed", "remove_count"},
                                              {"upgraded", "upgrade_count"}});
        if (!measure)
            continue;
        // arch, downgrade_count: zero / ''.
        acc.add(e.ts,
                {{"name", vt(e.name)}, {"version", vt(e.version)}, {"publisher", vt(e.publisher)}},
                {{measure, vi(1)}});
    }
}

inline void arp_delta(const std::vector<ArpEvent>& events, TierAccumulator& acc) {
    for (const auto& e : events) {
        const char* measure = pick(e.action, {{"appeared", "appear_count"}, {"removed", "remove_count"}});
        if (!measure)
            continue;
        // is_router, rebind_count: zero.
        acc.add(e.ts,
                {{"interface", vt(e.iface)}, {"ip_address", vt(e.ip_address)},
                 {"mac_address", vt(e.mac_address)}},
                {{measure, vi(1)}});
    }
}

inline void dns_delta(const std::vector<DnsEvent>& events, TierAccumulator& acc) {
    for (const auto& e : events) {
        const char* measure = pick(e.action, {{"appeared", "appear_count"}, {"removed", "remove_count"}});
        if (!measure)
            continue;
        // negative_count: zero.
        acc.add(e.ts, {{"name", vt(e.name)}, {"record_type", vt(e.record_type)}, {"data", vt(e.data)}},
                {{measure, vi(1)}});
    }
}

inline void netconn_delta(const std::vector<NetConnRow>& events, TierAccumulator& acc) {
    for (const auto& e : events) {
        // phy_type, auth_alg, cipher_alg: ''.
        acc.add(e.ts,
                {{"action", vt(e.action)}, {"channel", vt(e.channel)},
                 {"category", vt(e.category)}, {"capability", vt(e.capability)},
                 {"iface_kind", vt(e.iface_kind)}, {"reason_code", vi(e.reason_code)}},
                {{"event_count", vi(1)}, {"last_ts", vi(e.ts)}});
    }
}

inline void mapdrive_delta(const std::vector<MapDriveEvent>& events, TierAccumulator& acc) {
    for (const auto& e : events) {
        const char* measure = pick(e.action, {{"appeared", "appear_count"},
                                              {"removed", "remove_count"},
                                              {"historical", "historical_count"}});
        if (!measure)
            continue;
        // last_dialect, guest_count: zero / ''.
        acc.add(e.ts,
                {{"direction", vt(e.direction)}, {"local_mount", vt(e.local_mount)},
                 {"remote_path", vt(e.remote_path)}, {"remote_host", vt(e.remote_host)}},
                {{measure, vi(1)}, {"first_ts", vi(e.ts)}, {"last_ts", vi(e.ts)}});
    }
}

inline void perf_delta(const std::vector<PerfRow>& events, TierAccumulator& acc) {
    for (const auto& e : events) {
        // cpu_kernel_sum, rx_bps_max, tx_bps_max, procs_sum, threads_sum, handles_sum: zero.
        acc.add(e.ts, {},
                {{"samples", vi(1)},
                 {"cpu_sum", vr(e.cpu_pct)},
                 {"cpu_max", vr(e.cpu_pct)},
                 {"mem_sum", vr(e.mem_used_pct)},
                 {"mem_max", vr(e.mem_used_pct)},
                 {"commit_sum", vr(e.commit_pct)},
                 {"read_bps_sum", vi(e.disk_read_bps)},
                 {"write_bps_sum", vi(e.disk_write_bps)},
                 {"read_lat_us_sum", vi(e.disk_read_lat_us)},
                 {"write_lat_us_sum", vi(e.disk_write_lat_us)},
                 {"read_lat_us_max", vi(e.disk_read_lat_us)},
                 {"write_lat_us_max", vi(e.disk_write_lat_us)},
                 {"rx_bps_sum", vi(e.net_rx_bps)},
                 {"tx_bps_sum", vi(e.net_tx_bps)}});
    }
}

inline void procperf_delta(const std::vector<ProcPerfRow>& events, TierAccumulator& acc) {
    for (const auto& e : events) {
        // private_bytes_max, handles_max, threads_max, io_read_bytes_sum,
        // io_write_bytes_sum: zero.
        acc.add(e.ts,
                {{"name", vt(e.name)}, {"version", vt(e.version)},
                 {"is_kthread", vi(e.is_kthread ? 1 : 0)}},
                {{"samples", vi(1)},
                 {"instances_max", vi(e.instances)},
                 {"cpu_sum", vr(e.cpu_pct)},
                 {"cpu_max", vr(e.cpu_pct)},
                 {"ws_sum", vi(e.ws_bytes)},
                 {"ws_max_bytes", vi(e.ws_bytes)}});
    }
}

inline void netqual_delta(const std::vector<NetQualRow>& events, TierAccumulator& acc) {
    for (const auto& e : events) {
        // rtt_us_min, bytes_in_sum, bytes_out_sum: zero.
        acc.add(e.ts,
                {{"proto", vt(e.proto)}, {"remote_bucket", vt(e.remote_bucket)},
                 {"process_name", vt(e.process_name)}},
                {{"samples", vi(1)},
                 {"rtt_us_sum", vi(e.rtt_us)},
                 {"rtt_us_max", vi(e.rtt_us)},
                 {"rtt_var_us_sum", vi(e.rtt_var_us)},
                 {"lost_sum", vi(e.lost)},
                 {"lost_max", vi(e.lost)},
                 {"degraded_samples", vi(e.lost > 0 ? 1 : 0)}});
    }
}

// ── The 3 cursor-source deltas ──────────────────────────────────────────────
//
// Each returns one contribution per event. The digest covers exactly the fields
// the raw store compares to recognise a replay: the payload minus snapshot_id,
// minus `ts` where `ts` is not identity (power and removable capture_gap,
// removable present_at_baseline), and for the registry source the action plus,
// unless it is capture_gap, hive, key path, value name, data type / data / size,
// the previous data type / data / size and observed_at -- never `ts` and never
// the attribution fields (actor_pid, actor_image, detail), because the registry
// key does not depend on attribution and a replay may derive a different writer.

inline std::vector<KeyedContribution> power_delta(const std::vector<PowerEvent>& events) {
    std::vector<KeyedContribution> out;
    out.reserve(events.size());
    for (const auto& e : events) {
        std::vector<std::string> id{e.action, e.detail};
        if (e.action != "capture_gap")
            id.push_back(std::to_string(e.ts));
        std::string detail = e.detail;
        registry_detail::clip_utf8(detail, 256);
        // resume_kind, source: ''.
        out.push_back({e.record_key, identity_digest(id), e.ts,
                       {{"action", vt(e.action)}},
                       {{"event_count", vi(1)}, {"last_ts", vi(e.ts)}, {"last_detail", vt(detail)}}});
    }
    return out;
}

inline std::vector<KeyedContribution> removable_delta(const std::vector<RemovableEvent>& events) {
    std::vector<KeyedContribution> out;
    out.reserve(events.size());
    for (const auto& e : events) {
        std::vector<std::string> id{e.action,       e.device_key, e.vendor,
                                    e.product,      e.serial,     e.bus,
                                    e.volume,       std::to_string(e.size_bytes),
                                    e.image_path,   std::to_string(e.pid), e.evidence};
        if (e.action != "capture_gap" && e.action != "present_at_baseline")
            id.push_back(std::to_string(e.ts));
        // disk_id: ''. partition_count is a maximum and not part of the identity digest above.
        out.push_back({e.record_key, identity_digest(id), e.ts,
                       {{"action", vt(e.action)}, {"device_key", vt(e.device_key)},
                        {"vendor", vt(e.vendor)}, {"product", vt(e.product)},
                        {"serial", vt(e.serial)}, {"bus", vt(e.bus)}, {"volume", vt(e.volume)},
                        {"image_path", vt(e.image_path)}},
                       {{"event_count", vi(1)}, {"first_ts", vi(e.ts)}, {"last_ts", vi(e.ts)},
                        {"size_bytes", vi(e.size_bytes)}, {"partition_count", vi(e.partition_count)}}});
    }
    return out;
}

inline std::vector<KeyedContribution> registry_delta(const std::vector<RegistryEvent>& events) {
    std::vector<KeyedContribution> out;
    out.reserve(events.size());
    for (const auto& e : events) {
        std::vector<std::string> id{e.action};
        if (e.action != "capture_gap") {
            id.insert(id.end(),
                      {e.hive, e.key_path, e.value_name, e.data_type, e.data,
                       std::to_string(e.data_size), e.prev_data_type, e.prev_data,
                       std::to_string(e.prev_data_size), std::to_string(e.observed_at)});
        }
        std::string data = e.data;
        registry_detail::clip_utf8(data, 512);
        out.push_back({e.record_key, identity_digest(id), e.ts,
                       {{"hive", vt(e.hive)}, {"key_path", vt(e.key_path)},
                        {"value_name", vt(e.value_name)}, {"action", vt(e.action)}},
                       {{"change_count", vi(1)},
                        {"last_data", vt(data)},
                        {"last_data_type", vt(e.data_type)},
                        {"last_actor_image", vt(e.actor_image)},
                        {"last_ts", vi(e.ts)}}});
    }
    return out;
}

// ── The 17th delta: usage ───────────────────────────────────────────────────

/// A pure adapter over usage::fold_daily (echo_usage.hpp): the day-bucketed run
/// totals map onto the usage daily tier's columns; distinct_users and the
/// enrichment columns are 0 / ''. No second fold is implemented here: usage's own
/// writer (echo_usage.cpp) is unchanged and does not call this.
inline void usage_delta(const std::vector<usage::ClosedRun>& runs, TierAccumulator& acc) {
    for (const auto& d : usage::fold_daily(runs)) {
        acc.add(d.day_ts, {{"exe_key", vt(d.exe_key)}},
                {{"run_count", vi(d.run_count)},
                 {"total_seconds", vi(d.total_seconds)},
                 {"first_seen", vi(d.first_seen)},
                 {"last_seen", vi(d.last_seen)},
                 {"superseded_runs", vi(d.superseded_runs)},
                 {"expired_runs", vi(d.expired_runs)}});
    }
}

// ── The transactional fold writer ───────────────────────────────────────────

/// Persisted counter (echo_config) of events refused for an unrepresentable stamp.
inline constexpr std::string_view kFoldRejectedCounterKey = "fold_rejected_events_total";
/// Replay-ring depth per cursor source.
inline constexpr std::size_t kReplayRingDepth = 4096;
/// Dictionary cache bound; cleared when a fold would overflow it.
inline constexpr std::size_t kDictCacheCap = 50'000;
/// Orphan strings deleted per GC statement.
inline constexpr int kGcBatch = 2000;
/// The temp table holding one GC pass's orphan ids.
inline constexpr std::string_view kGcOrphanTable = "echo_dict_orphan";

/// The live-set scan, run once per GC pass: every dictionary id that no roll-up table
/// references (an EXCEPT chain over every interned key column) into the temp orphan
/// table. Pure text so the compound-select term count can be pinned by a test.
[[nodiscard]] inline std::string dictionary_orphans_sql() {
    std::string sql = std::format("INSERT INTO temp.{1} SELECT id FROM {0}", kDictTable, kGcOrphanTable);
    for (const auto& def : fold_sources()) {
        if (def.own_tables)
            continue;
        for (auto tier : def.tiers)
            for (const auto& c : def.columns)
                if (c.interned)
                    sql += std::format(" EXCEPT SELECT {} FROM {}", physical_column_name(c),
                                       physical_table_name(def.name, tier));
    }
    return sql;
}

struct FoldResult {
    std::size_t rows_touched{0};     ///< RETURNING row count, summed over tiers
    std::size_t rejected_events{0};  ///< events refused for an unrepresentable stamp
};

struct CursorFoldError {
    enum class Kind {
        Transient,    ///< nothing advanced; retrying the same batch is correct
        KeyCollision, ///< PERMANENT: an empty / NUL record_key, or a key already in the
                      ///< ring with a different digest. The same batch is re-derived and
                      ///< re-refused every tick; surface it, never retry indefinitely.
        Misuse,       ///< PERMANENT: not a cursor source, or a contribution naming a column the
                      ///< source lacks / a value of the wrong type; a programming error, never retry.
    };
    Kind kind{Kind::Transient};
    std::string text;
};

struct CursorFoldResult {
    std::size_t folded{0};        ///< contributions folded
    std::size_t replayed{0};      ///< contributions recognised as replays (same digest), not folded
    std::size_t rejected{0};      ///< contributions refused for an unrepresentable stamp
    std::size_t rows_touched{0};
};

struct GcResult {
    int64_t deleted{0};
    bool deadline_hit{false};
    bool live_set_built{false}; ///< the pass's one scan finished (false: it outran the deadline)
};

/**
 * The only code that touches SQLite on behalf of the fold. Owns the dictionary
 * cache and ONE operation mutex.
 *
 * LOCKING. `op_mu_` is held from before the first cache or database access to
 * the method's return: cache reads, the transaction, the post-commit cache
 * publication and cache invalidation. (fold_cursor_rows refuses a blank or NUL
 * record_key before taking it, touching neither.) Lock order is op_mu_ THEN
 * EchoDatabase::mu_ (taken inside
 * checked_transaction); nothing may ever take op_mu_ while holding mu_. There is
 * no second cache lock. ONE EchoFold instance must front a database: a second
 * instance would have its own cache and its own mutex and could race a GC.
 * `echo_dict.id` is AUTOINCREMENT, so an id is never reused: any deleter of
 * `echo_dict` rows goes through EchoFold, which clears its cache; one that does not
 * leaves dangling ids (the view reads NULL), never ids that name a different string.
 *
 * INTERNING. Strings are interned INSIDE the transaction (the intern statements are
 * finalised before COMMIT) into a staging map and published to the cache only after
 * the transaction commits, still under op_mu_. A rollback therefore never leaves the
 * cache holding an id the database does not have. Counts come from RETURNING row
 * counts, never sqlite3_changes().
 *
 * GC DEADLINE IS COOPERATIVE. It is checked before each batch starts (a batch is one
 * transaction; the live-set scan is three statements) and by sqlite3_progress_handler
 * inside a running statement, which rolls the whole batch back. It does NOT cover mutex
 * acquisition, BEGIN IMMEDIATE's busy wait (5 s), or COMMIT I/O.
 *
 * OWNERSHIP. EchoDatabase owns the one instance (built in open(), destroyed with it), so
 * "one EchoFold per database" holds by construction; the collectors, the aggregator and
 * the dictionary GC reach it only through EchoDatabase.
 */
class EchoFold {
public:
    using Clock = std::chrono::steady_clock;
    /// Clock seam for the GC deadline; null means steady_clock::now.
    using NowFn = std::function<Clock::time_point()>;

    explicit EchoFold(NowFn now = nullptr);
    ~EchoFold();
    EchoFold(const EchoFold&) = delete;
    EchoFold& operator=(const EchoFold&) = delete;

    /// Create the dictionary, the replay ring and every roll-up table, index and
    /// view in one transaction. A LEGACY TABLE whose name a view will take is
    /// dropped first (a view cannot be created over an existing table of the same
    /// name, and CREATE VIEW IF NOT EXISTS would then silently do nothing); one that
    /// holds rows refuses the install, naming the table and its row count. Called by
    /// EchoDatabase::open() for a database with no legacy tables; the v10 migration of an
    /// existing one MOVES the rows first (echo_db_v10_migration.cpp) and runs the same DDL in
    /// its own transaction. Clears the dictionary cache.
    [[nodiscard]] std::expected<void, std::string> install_fold_schema(EchoDatabase& db);

    /// Fold a snapshot-diff source's accumulated batch (plus its optional baseline
    /// StateWrite) in ONE transaction. Rejected events (acc.rejected()) are added
    /// to the persisted counter in the same transaction. Additive, not idempotent: a
    /// snapshot source is replay-safe only because its baseline StateWrite commits in
    /// this same transaction.
    ///
    /// `extra`, when set, runs INSIDE that same transaction after the tier upserts and before
    /// the commit: its writes commit or roll back with the fold (the process fold passes the
    /// usage fold here, so a tick's process tiers and usage rows are one unit). It receives the
    /// transaction's handle and must not call any EchoDatabase method that takes the database
    /// mutex; an error it returns rolls the whole fold back.
    using ExtraFn = std::function<std::expected<void, std::string>(TransactionHandle&)>;
    [[nodiscard]] std::expected<FoldResult, std::string>
    fold_rows(EchoDatabase& db, std::string_view source, const TierAccumulator& acc,
              const std::optional<StateWrite>& state = std::nullopt, const ExtraFn& extra = {});

    /// The body of fold_rows' transaction on a handle the CALLER owns: upsert `acc` into every
    /// tier of `source` and write `state`, through a transaction-local interner over an EMPTY
    /// cache, so a rollback of the caller's transaction leaves this instance's cache untouched.
    /// For the v10 migration only, which folds a database's retired raw rows inside its own single
    /// transaction. Takes NEITHER op_mu_ nor the database mutex (the caller holds the latter
    /// inside checked_transaction), so it is valid only while no other thread can reach this
    /// instance, i.e. inside EchoDatabase::open() before the object is returned. Rejected events
    /// are not counted (the caller owns that policy); returns the RETURNING row count.
    [[nodiscard]] std::expected<std::size_t, std::string>
    fold_in(TransactionHandle& h, std::string_view source, const TierAccumulator& acc,
            const std::optional<StateWrite>& state = std::nullopt);

    /// Fold a cursor source's contributions through the digest-checked replay ring,
    /// and commit the cursor and the baseline StateWrites in the SAME transaction.
    /// A replay (same key, same digest) is not folded; the cursor still advances.
    /// The ring is first-sighting FIFO: a record re-offered after kReplayRingDepth
    /// newer keys of its source folds again (kSum double counts; kMax, kMin and kLast
    /// do not). A key collision rolls everything back and is PERMANENT.
    [[nodiscard]] std::expected<CursorFoldResult, CursorFoldError>
    fold_cursor_rows(EchoDatabase& db, std::string_view source,
                     const std::vector<KeyedContribution>& contributions,
                     const std::string& cursor_json,
                     const std::vector<StateWrite>& baseline_writes);

    /// Delete orphaned dictionary strings until none remain or the deadline passes: one
    /// live-set scan per pass into a temp table, then batches by id. A deadline hit is a
    /// result, not an error (GcResult::live_set_built says whether the scan finished; a
    /// pass whose scan outruns the deadline deletes nothing); any OTHER failure is
    /// returned as an error, never as an empty success.
    [[nodiscard]] std::expected<GcResult, std::string> gc_dictionary(EchoDatabase& db,
                                                                      Clock::time_point deadline);

private:
    [[nodiscard]] Clock::time_point now() const { return now_ ? now_() : Clock::now(); }

    /// echo_state UPSERT inside a fold transaction (a member: it needs EchoDatabase's friendship).
    static bool write_state(TransactionHandle& h, const StateWrite& w);

    /// The transaction body fold_rows and fold_in share: upsert every tier of `def`, write `state`.
    /// New dictionary ids go to `staged`; `cache` is only read. The RETURNING row count, or the
    /// handle's error.
    static std::expected<std::size_t, std::string>
    fold_body(TransactionHandle& h, const FoldSourceDef& def, const TierAccumulator& acc,
              const std::optional<StateWrite>& state,
              const std::unordered_map<std::string, int64_t>& cache,
              std::unordered_map<std::string, int64_t>& staged);

    NowFn now_;
    std::mutex op_mu_;
    std::unordered_map<std::string, int64_t> cache_;
};

} // namespace yuzu::echo
