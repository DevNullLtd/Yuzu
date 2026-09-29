#include "guardian_lifecycle_journal.hpp"

#include "guardian_spark_runtime.hpp" // GuardianSparkRuntime::try_page_batch + OutboxEntry

#include <yuzu/agent/kv_store.hpp>
#include <yuzu/agent/plugin_loader.hpp> // kReservedPluginNames - for the pin below

#include <spdlog/spdlog.h>

#include <algorithm>
#include <cassert>
#include <chrono>
#include <expected>
#include <format>
#include <limits>
#include <optional>
#include <random>
#include <set>
#include <unordered_set>
#include <vector>

namespace yuzu::agent {

// #2303 C2. The journal namespace MUST be a reserved plugin name: yuzu_ctx_storage_* keys
// KvStore by the plugin's own declared name on the SAME connection this journal borrows, so a
// plugin able to claim it could read, delete, or forge the audit records replayed over the
// authenticated stream. plugin_loader.hpp (include/) cannot include guardian_journal_format.hpp
// (src/) without inverting the layering, so the literal is duplicated there and pinned here -
// this file is the only translation unit that sees both. Same bind-or-drift pattern as the
// kNetTag* heartbeat-key asserts.
static_assert(std::ranges::find(kReservedPluginNames, kJournalNamespace) !=
                  kReservedPluginNames.end(),
              "kJournalNamespace must appear in kReservedPluginNames (plugin_loader.hpp) - "
              "otherwise a native plugin can claim the journal's kv_store namespace");

namespace {

std::string make_journal_nonce() {
    std::random_device rd;
    const std::uint64_t v = (static_cast<std::uint64_t>(rd()) << 32) ^ static_cast<std::uint64_t>(rd());
    return std::format("{:016x}", v);
}

// Worst-case serialized byte count of a string field once JSON-escaped: a control char
// (< 0x20) can expand to \u00XX (6 bytes), '"' and '\\' to 2 (review M7). Fields are validated
// UTF-8, so multibyte code points pass through 1:1.
std::size_t json_escaped_bytes(std::string_view s) {
    std::size_t n = 0;
    for (unsigned char c : s)
        n += (c < 0x20) ? 6 : ((c == '"' || c == '\\') ? 2 : 1);
    return n;
}

// A byte estimate for one record's JSON entry, used to decide when to start a new batch. It
// must never UNDER-count (a batch estimated below kMaxJournalBatchBytes must actually serialize
// below it), so each field is counted at its worst-case escaped size.
std::size_t est_entry_bytes(const JournalRecord& r) {
    return json_escaped_bytes(r.rule_id) + json_escaped_bytes(r.event_id) +
           json_escaped_bytes(r.kind) + json_escaped_bytes(r.guard_type) +
           json_escaped_bytes(r.rule_name) + 160; // JSON keys/punctuation + worst-case number
                                                   // digits (review round 2 MINOR-2)
}

} // namespace

GuardianLifecycleJournal::GuardianLifecycleJournal(IJournalStore* kv)
    : kv_(kv), boot_nonce_(make_journal_nonce()) {
    // rev-4.1 #9 / review M8: confirm the durability precondition on the BUILT binary. SOFT warn
    // on != FULL (2); NEVER abort, since config drift must not kill an agent.
    if (kv_) {
        const int sync = kv_->pragma_synchronous();
        if (sync != 2)
            spdlog::warn("Guardian journal: kv_store PRAGMA synchronous = {} (expected 2/FULL); "
                         "power-loss durability of the lifecycle journal is not guaranteed",
                         sync);
    }
    seed_size_gauges_();
}

// #2303 C1. The size gauges are what the write-side ceiling in persist() reads, but they were
// only ever RECONSTRUCTED by a successful prune scan - they started at 0 on every construction.
// A journal that survived a restart was therefore invisible to the ceiling until the first
// successful prune, and start_local()'s arm-record flush persists BEFORE any tick or reconnect
// prune runs, so the gauge-at-zero window opened on EVERY restart. A crash-loop over an already
// full journal could then grow the SHARED kv_store.db past the "hard" ceiling, taking unrelated
// plugins' KV with it. Seeding here closes the window: the ceiling is honest from the first
// write of the process.
//
// namespace_size() is the aggregate probe rather than list_entries() on purpose - the hard
// ceiling is 2x the soft caps (2000 batches / 64 MiB), and materializing that to learn two
// numbers would be a multi-tens-of-MiB allocation on an endpoint at startup.
//
// Probe FAILURE is the interesting case, and it fails CLOSED: an un-scannable journal means we
// cannot bound what is already on disk, so we assume-at-ceiling and let persist() reject +
// count write_capacity_rejected_ until a successful prune reconstructs the true size. Records
// already staged are retried, not dropped, as long as a prune EVENTUALLY succeeds; only a
// SUSTAINED double-failure (this probe AND every subsequent prune both failing) past the bounded
// RAM staging (kMaxPendingJournalRecords) drops the oldest - and that drop is counted, not silent
// (journal_stage_dropped). Fail-OPEN here would be the strictly worse trade: it is precisely the
// un-scannable journal (chronic SQLITE_BUSY, a corrupt page) whose size we have least right to
// assume is zero.
void GuardianLifecycleJournal::seed_size_gauges_() {
    // #2303 UP-7: this is the ONLY non-RMW gauge writer (an absolute .store()). It is race-free
    // ONLY because it runs once, in the ctor, before the journal pointer is published to any
    // thread. A future re-seed while persist/prune threads are live would reintroduce the exact
    // lost-update class this fix removes. The call-once assert pins that contract in debug builds.
    assert(!size_seeded_.exchange(true, std::memory_order_relaxed) &&
           "seed_size_gauges_ must run once, at construction, before any thread sees the journal");
    if (!kv_)
        return; // no store to borrow: persist() writes nothing, so the gauges are moot

    auto sz = kv_->namespace_size(kJournalNamespace, kBatchKeyPrefix);
    if (!sz) {
        // Fail CLOSED at the ceiling. This is a CONSERVATIVE seed that a later successful
        // prune scan REBASES back to on-disk reality (rebase-as-delta) - do not treat it as
        // permanent, or an agent that boots once with a busy/corrupt kv_store.db would brick
        // its journal writes forever.
        journal_batch_count_.store(static_cast<std::int64_t>(hard_max_batches_),
                                   std::memory_order_relaxed);
        journal_bytes_.store(static_cast<std::int64_t>(hard_max_bytes_), std::memory_order_relaxed);
        spdlog::warn("Guardian journal: could not size the on-disk journal at startup ({}); "
                     "assuming AT the write ceiling until a successful prune - lifecycle records "
                     "will be staged in RAM and retried, not written",
                     sz.error().message);
        return;
    }
    journal_batch_count_.store(static_cast<std::int64_t>(sz->count), std::memory_order_relaxed);
    journal_bytes_.store(static_cast<std::int64_t>(sz->bytes), std::memory_order_relaxed);
    if (sz->count > 0)
        spdlog::debug("Guardian journal: resuming over {} batch(es) / {} bytes already on disk",
                      sz->count, sz->bytes);
}

std::size_t
GuardianLifecycleJournal::persist(std::span<const std::shared_ptr<const JournalRecord>> pending,
                                  std::vector<PersistedBatch>* out_batches,
                                  std::size_t max_batches, std::size_t max_records) {
    if (!kv_ || pending.empty())
        return 0;
    std::size_t batches_this_call = 0;

    // `written` is the count of leading pending SLOTS durably committed. The caller passes it
    // to erase_persisted_prefix, so it must map 1:1 to the front of `pending`; snapshot never
    // stages a nullptr, so a slot count equals a record count (N5). It advances ONLY after a
    // batch is confirmed Inserted (its terminal COMMIT surfaced by insert_if_absent, B1).
    std::size_t written = 0;
    std::size_t i = 0;
    while (i < pending.size()) {
        // Build + write ONE batch. Every step below allocates (vector copies, JSON dump, key
        // format); a throw must NOT lose the `written` count for batches already committed, so
        // the whole batch is firewalled and treated as a write failure (review B4). The rest
        // stay pending for the maintenance-tick retry.
        try {
            std::vector<JournalRecord> entries;
            std::size_t batch_bytes = 64; // envelope overhead
            std::size_t consumed = 0;     // pending slots this batch spans (incl. any skipped)
            while (i + consumed < pending.size() && entries.size() < kMaxJournalEntriesPerBatch) {
                const auto& rec = pending[i + consumed];
                if (!rec) { // invariant: never nullptr; belt-and-suspenders so a stray slot is
                    ++consumed; // still consumed (erased), never dereferenced
                    continue;
                }
                const std::size_t rb = est_entry_bytes(*rec);
                if (!entries.empty() && batch_bytes + rb > kMaxJournalBatchBytes)
                    break; // this record starts the next batch
                entries.push_back(*rec);
                batch_bytes += rb;
                ++consumed;
            }
            if (entries.empty()) { // only nullptr slots in this span (should never happen)
                i += consumed;
                written = i;
                continue;
            }

            const std::int64_t ts_ms = std::chrono::duration_cast<std::chrono::milliseconds>(
                                           std::chrono::system_clock::now().time_since_epoch())
                                           .count();
            const std::string value = serialize_journal_batch(ts_ms, entries);
            // Same ts into the key and the value: the key is what retention and replay ORDER
            // by (a keys-only scan is the whole point), the value keeps its copy for replay.
            const std::string key = journal_batch_key(ts_ms, boot_nonce_, batch_seq_);

            // Write-side ceiling (review UP-1): retention (prune) is the only shrink path and it
            // can fail indefinitely (chronic SQLITE_BUSY / a corrupt page). Without a write-side
            // cap, a failing prune lets the journal grow without bound and exhaust the SHARED
            // kv_store.db - taking down UNRELATED plugins' KV. This hard ceiling (default 2x the
            // retention caps) sits ABOVE the soft retention caps prune trims to - so normal
            // between-tick overshoot is never rejected - and is deliberately DECOUPLED from the
            // retention caps (a test may shrink retention to force eviction without also blocking
            // the writes that set that up). The cached size (set exactly by each prune scan,
            // incremented below on a durable write) drives it: reject + count + circuit-break,
            // leaving the records in the bounded RAM staging.
            const std::int64_t raw_count = journal_batch_count_.load(std::memory_order_relaxed);
            const std::int64_t raw_bytes = journal_bytes_.load(std::memory_order_relaxed);
            // #2303 UP-2 (Sol review): a NEGATIVE gauge means the cached size is UNTRUSTED (an
            // over-subtraction bug). clamp_nonneg would floor it to 0 and ADMIT the write -
            // fail-OPEN, growing the shared kv_store.db on the strength of a wrong size. Fail
            // CLOSED instead: refuse + count, and let a later prune rebase restore a trusted size
            // (writes then resume). This cannot occur in correct operation - every lc: row is
            // counted - so it never blocks a healthy agent; it is a defense-in-depth tripwire
            // against a future accounting regression, not a live code path.
            if (raw_count < 0 || raw_bytes < 0) {
                gauge_underflow_.fetch_add(1, std::memory_order_relaxed);
                return written; // untrusted size: defer to RAM staging until a prune rebases
            }
            if (clamp_nonneg(raw_count) + 1 > hard_max_batches_ ||
                clamp_nonneg(raw_bytes) + value.size() > hard_max_bytes_) {
                write_capacity_rejected_.fetch_add(1, std::memory_order_relaxed);
                return written; // the rest stay pending; a later prune shrinks, then the tick retries
            }

            KvInsert result;
            if (inject_skip_writes_.load(std::memory_order_relaxed) > 0) {
                inject_skip_writes_.fetch_sub(1, std::memory_order_relaxed); // test-only: let this one write
                result = kv_->insert_if_absent(kJournalNamespace, key, value);
            } else if (inject_fail_writes_.load(std::memory_order_relaxed) > 0) {
                inject_fail_writes_.fetch_sub(1, std::memory_order_relaxed); // test-only fault
                result = KvInsert::Error;
            } else {
                result = kv_->insert_if_absent(kJournalNamespace, key, value);
            }
            switch (result) {
            case KvInsert::Inserted:
                ++batch_seq_;
                batches_written_.fetch_add(1, std::memory_order_relaxed);
                // Track the live-size gauges so the write-side ceiling above and the operator
                // size signal stay honest between prune scans (review UP-1 / sre). fetch_add
                // (not an absolute store) so a concurrent prune rebase never loses this
                // increment (#2303 gauge-race fix).
                //
                // ORDERING IS LOAD-BEARING (#2303 UP-4): this fetch_add MUST stay AFTER the
                // durable insert_if_absent above. That ordering is what makes a prune rebase
                // racing this persist an OVER-count (the row is on disk, seen by the scan, and
                // also fetch_add'd -> ceiling tightens, safe) rather than an UNDER-count (gauge
                // bumped for a row not yet on disk -> ceiling loosens -> fail-open). Do NOT
                // reorder to "reserve then write".
                journal_batch_count_.fetch_add(1, std::memory_order_relaxed);
                journal_bytes_.fetch_add(static_cast<std::int64_t>(value.size()),
                                         std::memory_order_relaxed);
                i += consumed;
                written = i; // count the durably-committed slots BEFORE building the best-effort
                             // provenance record, so a throw there loses only the sent-label
                             // back-fill (best-effort), not by re-persisting a duplicate batch
                             // under a new key next retry (review round 2 MINOR-3).
                if (out_batches) { // provenance back-fill source (review M3)
                    PersistedBatch pb{key, {}};
                    pb.event_ids.reserve(entries.size());
                    for (const auto& e : entries)
                        pb.event_ids.push_back(e.event_id);
                    out_batches->push_back(std::move(pb));
                }
                // PER-CALL BATCH CAP (C0 flip-checklist item 11). Checked HERE, at the very end
                // of the Inserted case, and nowhere earlier: everything above - batch_seq_, the
                // gauges, `i`, `written`, the provenance record - describes a batch that is
                // already durable. Returning before `written` advances would leave a committed
                // batch staged and re-persist it under a new key on the next call (a duplicate
                // durable record); returning before the provenance record would keep durability
                // but silently drop the sent-label evidence for the batch just written.
                //
                // The remainder simply stays staged. That is not a new state: it is exactly what
                // the Exists and Error circuit-breakers below already produce, and the caller
                // handles it the same way - it erases the returned prefix and the next tick
                // re-snapshots the rest.
                // Whichever bound is reached first. `written` is the record count, so the
                // record cap is read straight off it.
                if (max_batches != kJournalPersistUnbounded && ++batches_this_call >= max_batches)
                    return written;
                if (max_records != kJournalPersistUnbounded && written >= max_records)
                    return written;
                break;
            case KvInsert::Exists:
                // ~2^-64 boot-nonce+seq collision: DON'T overwrite. Count it, advance the seq
                // past the occupied key, and circuit-break (the tick retries the rest).
                key_collisions_.fetch_add(1, std::memory_order_relaxed);
                ++batch_seq_;
                write_failures_.fetch_add(1, std::memory_order_relaxed);
                return written;
            case KvInsert::Error:
                // Per-push circuit breaker: stop at the first write failure so one bad write
                // can't stall apply_rules for 500 x the 5 s busy timeout. Keep the seq (nothing
                // was written to this key), leave the rest pending.
                write_failures_.fetch_add(1, std::memory_order_relaxed);
                return written;
            }
        } catch (...) {
            // A build/serialize allocation threw: batches before this one are durably written,
            // so count a write failure and return `written`; the caller erases exactly that
            // prefix and the rest (incl. this batch) stay pending for the tick retry (B4).
            write_failures_.fetch_add(1, std::memory_order_relaxed);
            return written;
        }
    }
    return written;
}

JournalPruneStats GuardianLifecycleJournal::prune(std::int64_t now_ms) {
    // Serialise retention against paging (review round 2 MINOR-1): the maintenance tick calls
    // prune() bare while a concurrent reconnect-hook page_into_window may be renaming/deleting
    // the same keys under paging_mutex_. Without this, the loser of a race falsely counts
    // quarantine_failures / prune_failures on operator-facing integrity counters.
    std::lock_guard<std::mutex> pg{paging_mutex_};
    return prune_locked_(now_ms);
}

JournalPruneStats GuardianLifecycleJournal::prune_locked_(std::int64_t now_ms) {
    JournalPruneStats stats;
    if (!kv_)
        return stats;

    // Shutdown began: a prune pass is a full-journal scan plus one KvStore read per evicted key,
    // each able to block on the 5 s busy timeout. Bail BEFORE starting so the drain-worker join
    // in GuardianEngine::stop() is not held up by retention work nobody will observe (C0 #2298).
    // read_ok stays false, so the page-side boot barrier does NOT latch on a stop-aborted pass.
    if (stopping_.load(std::memory_order_acquire))
        return stats;

    if (inject_fail_reads_.load(std::memory_order_relaxed) > 0) { // test-only injected read fault
        inject_fail_reads_.fetch_sub(1, std::memory_order_relaxed);
        prune_failures_.fetch_add(1, std::memory_order_relaxed);
        return stats; // read_ok stays false, same as a real scan failure
    }
    // #2303 gauge-race fix (rebase-as-delta). Snapshot the gauge count IMMEDIATELY before the
    // scan; after the scan we fetch_add the SIGNED difference (scanned-actual minus this
    // snapshot) rather than storing an absolute. A concurrent persist() fetch_add landing
    // between this load and the rebase is preserved (both are RMW on the same atomic), where
    // an absolute store would silently clobber it and under-count the write ceiling. This is
    // also the sole path that walks a fail-closed boot seed back down to reality.
    const std::int64_t pre_count = journal_batch_count_.load(std::memory_order_relaxed);
    const std::int64_t pre_bytes = journal_bytes_.load(std::memory_order_relaxed);

    // TEST-ONLY interleaving seam (#2303 UP-3): fire a simulated concurrent persist AFTER the
    // pre_count snapshot but BEFORE the scan - the window where the inserted row is BOTH seen by
    // the scan and carries its own fetch_add (the transient double-count). Null in production.
    if (pre_scan_hook_)
        pre_scan_hook_();

    // KEYS ONLY (#2299 perf-P-1). Everything this pass decides - order, age, size, eviction -
    // comes from the key and the value's BYTE LENGTH, so it never pays to materialize a single
    // value. Reading them cost ~670 ms and a +162 MiB transient allocation on a journal at its
    // byte ceiling, of which 97% was parsing rows the 128-candidate cap then discarded.
    auto rows = kv_->list_keys_sized(kJournalNamespace, kBatchKeyPrefix);
    if (!rows) {
        prune_failures_.fetch_add(1, std::memory_order_relaxed); // read error: fail-safe, retry next pass
        return stats; // read_ok stays false: the boot barrier will NOT latch on a failed scan (M5)
    }
    stats.read_ok = true;

    // #2452 Gate 8 (focused re-review UPR-1): a malformed key whose quarantine RENAME fails below
    // leaves a corrupt row STUCK in lc: (re-failing every pass, consuming ceiling budget). Like the
    // page side's any_quarantine_this_pass, that is not a clean, verified-idle retention pass, so it
    // must NOT read the prune stamp fresh - fed into progress_or_verified at the tail. Mirrors the
    // page-side guard the first prune cut missed.
    bool quarantine_stall_this_pass = false;

    // Rebase to what the scan actually observed on disk (all lc: rows, well-keyed or not); the
    // quarantine + eviction below then fetch_sub exactly what they REMOVE, so the gauge lands
    // at the true post-prune size without ever taking an absolute snapshot.
    std::int64_t scanned_bytes = 0;
    for (const auto& row : *rows)
        scanned_bytes += static_cast<std::int64_t>(row.bytes);
    journal_batch_count_.fetch_add(static_cast<std::int64_t>(rows->size()) - pre_count,
                                   std::memory_order_relaxed);
    journal_bytes_.fetch_add(scanned_bytes - pre_bytes, std::memory_order_relaxed);

    // TEST-ONLY interleaving seam: fire a simulated concurrent persist() in the exact window
    // between the rebase and the removal accounting (null in production).
    if (post_scan_hook_)
        post_scan_hook_();

    struct Live {
        std::string key;
        std::int64_t ts_ms;
        std::size_t bytes;
    };
    std::vector<Live> live;
    live.reserve(rows->size());
    for (auto& row : *rows) {
        // Shutdown mid-scan: this loop issues one rename_key per MALFORMED-KEY row, so on a
        // corrupted journal it can be up to hard_max_batches_ KvStore writes, each able to
        // block on the 5 s busy timeout. Bailing here is what makes the post-request_stop()
        // exit bounded (#2298 governance sec-M2): GuardianEngine::stop() holds mtx_ across
        // the drain-worker join, so every second spent here blocks dispatch(), journal_stats()
        // and the heartbeat too. Nothing is lost - the gauges were rebased to the scanned
        // reality above, each completed rename already paired with its own fetch_sub, and the
        // next boot re-scans.
        if (stopping_.load(std::memory_order_acquire))
            return stats;
        // Retention now judges a row by its KEY. A key that fails the strict shape check is
        // corruption - the journal is dormant until the prefer_spark flip, so no key in the
        // pre-ts format can exist on disk - and it has no trustworthy timestamp, so it cannot
        // be aged or ordered: quarantine it exactly as an unparseable value used to be.
        //
        // A corrupt VALUE under a well-formed key is no longer prune's business. It is
        // discovered by the replay pass when that batch is actually considered, which is the
        // only pass that has to read the value at all, and quarantined there (see
        // page_into_window). Until then the row is an ordinary retention candidate - bounded
        // by the same age, count and byte ceilings as any other - so a corrupt journal is
        // still bounded, it is just bounded without paying to parse the whole journal every
        // 120 s. One observable consequence: under mass corruption a row may now be counted
        // as `batches_pruned` rather than `quarantined`, depending on which pass reaches it
        // first.
        // Two size/shape checks, both from the SCAN alone - no value is read here.
        //  - a malformed KEY has no trustworthy timestamp, so it can be neither aged nor
        //    ordered;
        //  - an IMPLAUSIBLY LARGE value cannot have been written by persist(), and if it is
        //    left in the candidate set it counts its full size toward the byte ceiling, whose
        //    eviction is deliberately uncapped - so one such row would evict every older batch
        //    in a single pass. Before #2299 the value parse caught this incidentally; the size
        //    check is how the property survives a keys-only prune (Gate 4 UP-1).
        auto key_ts = parse_journal_batch_key_ts(row.key);
        const bool implausible_size = row.bytes > kMaxPlausibleJournalValueBytes;
        if (!key_ts || implausible_size) {
            // Say WHICH kind of malformed, once per process. The pre-#2299 key shape
            // (`lc:<nonce>:<seq12>`, no timestamp) cannot legitimately exist - the journal was
            // dormant when the format changed - but the one place it plausibly turns up is a
            // dev or UAT box that ran with prefer_spark patched on before the flip, which is
            // exactly the kind of box doing flip work. Quarantining is right either way;
            // reporting it as indistinguishable corruption would send someone hunting a
            // corrupt page instead of recognising a stale journal (governance Gate 3
            // architect). Delete this branch a release after the flip.
            if (!key_ts && !old_format_key_warned_ && looks_like_pre_ts_batch_key(row.key)) {
                old_format_key_warned_ = true;
                // SANITIZED: the key comes off disk, and on a tampered kv_store.db the nonce
                // field is unconstrained apart from ':' - so a raw key could carry newlines or
                // terminal escapes into a forwarded agent log, and be arbitrarily long.
                // ALLOWLIST printable ASCII rather than denying a list of controls: a denylist
                // of <0x20 and 0x7F still passes UTF-8-encoded C1 (0xC2 0x9B is CSI, which
                // xterm and VTE act on), and truncating raw bytes can cut a multi-byte
                // sequence mid-character and produce invalid UTF-8 that a JSON log forwarder
                // drops - losing the diagnostic entirely (Gate 8 security).
                std::string safe;
                safe.reserve(64);
                for (const char c : row.key.substr(0, 64)) {
                    const auto u = static_cast<unsigned char>(c);
                    safe.push_back((u >= 0x20 && u <= 0x7E) ? c : '?');
                }
                if (row.key.size() > 64)
                    safe += "...";
                spdlog::warn("Guardian journal: batch key '{}' is in the PRE-TIMESTAMP format. "
                             "That format was retired while the journal was dormant, so no "
                             "released agent can have written it - the likely cause is a local "
                             "build that enabled the spark backend before the cutover. "
                             "Quarantining it; this is not corrupt-page data loss.",
                             safe);
            }
            // Malformed key → move aside atomically so replay never considers it.
            if (kv_->rename_key(kJournalNamespace, row.key, journal_quarantine_key(row.key)) ==
                KvRename::Renamed) {
                quarantined_.fetch_add(1, std::memory_order_relaxed);
                ++stats.quarantined;
                // Left the lc: namespace: subtract it from the rebased gauge (RMW, #2303).
                journal_batch_count_.fetch_sub(1, std::memory_order_relaxed);
                journal_bytes_.fetch_sub(static_cast<std::int64_t>(row.bytes),
                                         std::memory_order_relaxed);
            } else {
                quarantine_failures_.fetch_add(1, std::memory_order_relaxed);
                quarantine_stall_this_pass = true; // #2452 Gate 8: stuck corrupt row -> not verified idle
            }
            continue;
        }
        live.push_back(Live{row.key, *key_ts, static_cast<std::size_t>(row.bytes)});
    }

    // Oldest-first by (ts_ms, key) - which the ts-leading key format now delivers for free, so
    // `live` arrives in that order from the scan's ORDER BY key - with batches stamped
    // implausibly far in the FUTURE ordered FIRST, so the count and byte ceilings shed them
    // before they shed real evidence.
    //
    // Without that they are immortal: such a batch can never be "too old", and oldest-first
    // count eviction never reaches it either - so once enough exist (a bad RTC, a VM clone, a
    // hand-edited kv_store.db) every genuine record written afterwards is the one evicted in
    // its place, permanently (#2345 Gate 2 security).
    //
    // Deliberately an ORDERING rule, not an expiry rule. Treating "future" as expired would
    // delete on the strength of the local clock being right, and the failure that actually
    // happens in the field is a clock reading in the PAST (a dead CMOS battery reports 1970),
    // which would make every real batch look future-dated and wipe the journal wholesale - the
    // very outcome the anomaly guard above exists to prevent. Reordering cannot delete anything
    // the count and byte ceilings were not already going to delete; if the clock is wrong
    // enough that every row looks future, they all compare equal here and the ceilings simply
    // trim in key order.
    //
    // A stable PARTITION, not a sort: `live` is already in (ts_ms, key) order, and the only
    // reordering this rule asks for is "move the future-dated group to the front, each group
    // keeping its order". A sort would produce the identical sequence at O(n log n) string
    // comparisons; the partition gets there in one linear pass.
    const std::int64_t future_cutoff = now_ms + kJournalFutureSlackMs;
    std::stable_partition(live.begin(), live.end(),
                          [future_cutoff](const Live& l) { return l.ts_ms > future_cutoff; });

    // now_ms is used directly. An earlier round clamped it upward with the previous pass's
    // reading, on the theory that a BACKWARD clock step stops age eviction, lets the journal
    // climb to its hard write ceiling, and makes it start REFUSING new records. Gate 8b showed
    // that premise is wrong: the count and byte ceilings below are computed with no clock at
    // all, so they hold the journal at max_batches_ regardless of what the clock does, and the
    // rejection ceiling is never reached. What the clamp actually bought was one extra pass of
    // eviction against a reading already known to be bad, on the pass AFTER a correction - so
    // it destroyed in-retention evidence to solve a problem that does not exist. Removed.
    //
    // A backward clock therefore just pauses AGE eviction until it is fixed, which is the safe
    // direction for an audit trail, and a correction takes effect on the very next pass.
    const std::int64_t window_ms = static_cast<std::int64_t>(retention_days_) * 86400 * 1000;
    const std::int64_t min_ts = now_ms - window_ms;

    // "Would this pass age out everything?" - counting only batches that are not stamped in the
    // FUTURE. A plain all_of over every row let a single future-dated batch veto the signal
    // permanently (#2345 Gate 8b UP6-1): one row written with a wrong RTC, or carried in by a
    // VM clone, is never itself expired, and because the count ceiling trims oldest-first it is
    // also immortal - so the guard would be silently disarmed for the life of the endpoint by
    // one bad row. Future-dated rows are excluded from the question rather than allowed to
    // answer it.
    std::size_t datable = 0, expired = 0;
    for (const auto& l : live) {
        if (l.ts_ms > now_ms)
            continue; // future-dated: cannot be "too old", and must not veto the signal
        ++datable;
        if (l.ts_ms < min_ts)
            ++expired;
    }
    const bool would_wipe = datable > 0 && expired == datable;
    // KNOWN part-7 nonconformance (routed-concerns.md "Clock-guarded retention", #3208): this
    // threshold is the retention window itself, not a separate ABSOLUTE constant like TAR's
    // kTarMinBigStepSec or audit_store's kAuditMinBigStepSec (#2360/#2361's max(window, floor)
    // class). Inert today only because retention_days_ is fixed at kJournalRetentionDays in
    // production (set_retention_limits_for_test is test-only) - deliberately NOT fixed here,
    // see #3208 for the fix shape and why it's out of scope for #2573's latch->fact-set change.
    const bool big_step = last_prune_now_ms_ != 0 && now_ms - last_prune_now_ms_ > window_ms;

    // Adopt the shared decision core (#2573 GJ half; rung 1 #2549 extracted it, rung 2 PR #3101
    // adopted it in TAR). Field mapping, deliberate:
    //  - prev_unusable = false: the comparison reading (last_prune_now_ms_) is in-process only,
    //    never read back from an untrusted store, so there is nothing to sanitise.
    //  - no_anchor = false: GJ persists no anchor across restarts BY DESIGN (unlike TAR /
    //    audit_store, which both need one because they DO persist) - last_prune_now_ms_ == 0 on
    //    every process start is the ordinary case, not an anomaly. Feeding that in would decline
    //    once per restart, a behavior change this refactor deliberately does not make.
    namespace audit_retention = yuzu::server::audit_retention;
    const audit_retention::Facts facts{.has_expired = expired > 0,
                                        .would_wipe = would_wipe,
                                        .big_step = big_step,
                                        .prev_unusable = false,
                                        .no_anchor = false};
    const audit_retention::Anomaly anomaly = audit_retention::classify(facts);
    // Declined ONCE per anomaly (identity, not just presence - a bool latch cannot tell a
    // repeat from a DIFFERENT anomaly arriving mid-backlog; see the member doc comment).
    // Latching still matters: declining every pass a wipe would occur means a genuinely
    // long-idle agent never ages anything out at all.
    const bool already_reported = last_reported_facts_.has_value() && *last_reported_facts_ == facts;
    const bool skip_age = anomaly != audit_retention::Anomaly::None && !already_reported;
    if (skip_age) {
        clock_jump_skips_.fetch_add(1, std::memory_order_relaxed);
        // The delta is meaningless on the FIRST pass of a process - last_prune_now_ms_ is still
        // zero, so it would print the whole Unix epoch as "the clock moved", in exactly the
        // restarted-VM scenario this detection was redesigned to catch (Gate 8 advisor).
        if (last_prune_now_ms_ == 0)
            spdlog::warn("Guardian journal: the first retention pass after start would age out "
                         "the ENTIRE journal ({} batches); skipping AGE eviction once so a clock "
                         "anomaly cannot delete the audit trail wholesale",
                         live.size());
        else
            spdlog::warn("Guardian journal: this retention pass would age out the ENTIRE journal "
                         "({} batches; clock moved {} ms since the last pass); skipping AGE "
                         "eviction once so a clock anomaly cannot delete the audit trail "
                         "wholesale",
                         live.size(), now_ms - last_prune_now_ms_);
    }
    last_prune_now_ms_ = now_ms;
    std::size_t total_bytes = 0;
    for (const auto& l : live)
        total_bytes += l.bytes;

    std::vector<std::string> evict;
    std::int64_t evicted_bytes = 0; // #2303: bytes to fetch_sub once the delete SUCCEEDS
    std::size_t surviving = live.size();
    // Cap AGE evictions per pass (#2345 Gate 5 CH-5). The count and byte caps are self-limiting
    // - they only ever trim the excess over a fixed ceiling - but age is absolute, so a single
    // clock reading can mark the entire journal expired at once. Bounding the pass turns that
    // into a paced ageing-out. Not applied to the count/byte caps: those must be free to bring
    // an over-ceiling journal back under its ceiling in one pass, which is a hard storage bound.
    std::size_t age_evictions = 0;
    std::size_t age_candidates = 0;
    for (const auto& l : live) { // oldest first: age is absolute, count/bytes trim from this end
        const bool too_many = surviving > max_batches_;
        const bool too_big = total_bytes > max_bytes_;
        if (!skip_age && l.ts_ms < min_ts)
            ++age_candidates;
        const bool too_old =
            !skip_age && l.ts_ms < min_ts && age_evictions < kMaxAgeEvictionsPerPass;
        if (too_old)
            ++age_evictions;
        if (too_old || too_many || too_big) {
            evict.push_back(l.key);
            evicted_bytes += static_cast<std::int64_t>(l.bytes);
            --surviving;
            total_bytes -= l.bytes;
        }
    }

    // The cutoff replay shares (#2345 Gate 5) is INT64_MIN - "nothing is too old to replay" -
    // for as long as this pass is working off a backlog of expired batches, whether because it
    // declined the wipe or because the per-pass cap left some behind. That is what makes the
    // paced deletion buy anything at all: without it, replay skips exactly the batches retention
    // is about to delete and the pacing would only slow the deletion, shipping nothing
    // (#2345 Gate 8 S3/UP5-3). It does not make delivery likely - deletion still outruns replay
    // about five to one at the current cap and refill rate (#2364) - it makes it possible. It
    // costs a bounded burst of redelivery, since sent-but-expired batches become candidates too
    // - bounded by the per-pass batch cap and the paging rate limiter, and the server de-dupes
    // on event_id.
    const bool pacing = skip_age || age_candidates > age_evictions;
    // Publish the CONSERVATIVE cutoff first and tighten it only once the delete below has
    // actually happened (#2345 round 7, Sol). Committing min_ts here and then failing the
    // delete stranded the rows it named: still present on disk, but classified expired by
    // replay, so neither shipped nor removed until some later pass succeeded. Repeated
    // failures alternated stranded and replayable passes while inflating a counter documented
    // to mean the endpoint's clock moved. INT64_MIN means "nothing is too old to replay",
    // which errs toward redelivery - free, since the server de-dupes on event_id.
    last_age_cutoff_ = std::numeric_limits<std::int64_t>::min();
    pruned_cutoff_valid_ = true;
    // Hold the "already declined" latch for as long as this anomaly is still being worked off,
    // not merely for the pass after the decline. Clearing it on the first accepting pass made a
    // large backlog re-trip the guard on alternate passes: it still converged, but at half rate
    // and while incrementing a counter documented to mean "this endpoint's clock moved", which
    // would have an operator chasing a second anomaly that never happened.
    //
    // Hold the recorded fact set only while an anomaly BACKLOG is still being worked off - which
    // is what `pacing` already means. Setting it from `age_candidates > 0` disarmed the guard
    // after any pass that aged out even one batch, and a live agent past its retention horizon
    // has such a pass constantly; a real jump arriving next would then evict unguarded, with no
    // warn line and no clock_jump_skips increment. Four Gate 8b reviewers found this
    // independently, and the correct expression was already computed one line above. Recording
    // THIS pass's facts (not just re-affirming presence) is what lets a DIFFERENT anomaly
    // arriving mid-drain compare unequal to the recorded set and decline on its own merits,
    // rather than being swallowed by a same-shaped-bool latch (#2573 GJ half).
    if (pacing)
        last_reported_facts_ = facts;
    else
        last_reported_facts_.reset();

    // Shutdown immediately before the pass's heaviest write: del_keys is one transaction over
    // the whole evict set and is the single longest KvStore call prune makes (#2298 governance
    // cs-2 - the stopping_ gates must PRECEDE the heavy calls, not merely straddle them).
    // Skipping it retains the batches, which is the safe direction for an audit journal; the
    // gauges already reflect on-disk reality via the rebase, so nothing is left inconsistent.
    if (stopping_.load(std::memory_order_acquire))
        return stats;

    // ONE keys-only scan of the sent-label namespace serves both consumers below - the
    // eviction classifier and the label GC - where the classifier used to issue a separate
    // point read per evicted key and the GC its own value-materializing scan. Labels are
    // presence markers, so their values are never needed. Fetched lazily, though note the
    // label GC below calls it unconditionally - so on a pass that reaches the GC this is one
    // scan, not zero (the saving is the value materialization, not the round trip).
    std::optional<std::expected<std::vector<KvKeySize>, KvStoreError>> sent_scan_cache;
    const auto sent_scan = [&]() -> const std::expected<std::vector<KvKeySize>, KvStoreError>& {
        if (!sent_scan_cache) {
            if (inject_fail_prune_sent_scans_.load(std::memory_order_relaxed) > 0) { // test-only
                inject_fail_prune_sent_scans_.fetch_sub(1, std::memory_order_relaxed);
                sent_scan_cache = std::unexpected(KvStoreError{"injected sent-scan failure"});
            } else {
                sent_scan_cache = kv_->list_keys_sized(kJournalNamespace, kSentKeyPrefix);
            }
        }
        return *sent_scan_cache;
    };

    if (!evict.empty()) {
        // del_keys is one all-or-nothing transaction: a 0 return with a non-empty evict list is
        // a delete FAILURE (review M4). Only AFTER a successful delete do we count the eviction,
        // classify each by its (still-present) sent-label, and let the label-GC run against the
        // now-correct survivor set. On failure the batches + labels are left intact and retried.
        int n;
        if (inject_fail_deletes_.load(std::memory_order_relaxed) > 0) { // test-only injected del fault
            inject_fail_deletes_.fetch_sub(1, std::memory_order_relaxed);
            n = 0;
        } else {
            n = kv_->del_keys(kJournalNamespace, evict);
        }
        if (n <= 0) {
            prune_failures_.fetch_add(1, std::memory_order_relaxed);
            // Nothing was evicted. Under rebase-as-delta the gauge already reflects the scanned
            // on-disk reality and we subtracted only what we actually removed, so a failed
            // delete correctly requires NO gauge change (#2303 - the old absolute store here
            // was itself a lost-update site).
            return stats; // do NOT touch survivors' sent-labels this pass
        }
        batches_pruned_.fetch_add(static_cast<std::uint64_t>(n), std::memory_order_relaxed);
        stats.evicted = static_cast<std::size_t>(n);
        // The delete happened, so the rows this cutoff would exclude from replay are genuinely
        // gone. Only a pass with no expired backlog left may tighten it; while one is being
        // worked off, replay must keep considering everything (see `pacing` above).
        if (!pacing)
            last_age_cutoff_ = min_ts;
        // Evicted keys left the lc: namespace: subtract them from the rebased gauge (RMW).
        // Count uses `n` (RETURNING rows), bytes uses evicted_bytes (the whole evict set): the
        // two bases match ONLY because n == evict.size() here. del_keys rolls back on any
        // failure (n==0), and under paging_mutex_ the sole concurrent writer (persist) only
        // INSERTS - no other path deletes an lc: key - so every evicted key is still present at
        // delete time and n can never be a partial 0<n<size. If a future out-of-lock lc:
        // deleter is added, switch bytes to sum only the actually-deleted keys (a rebase heals
        // the skew next scan regardless).
        journal_batch_count_.fetch_sub(static_cast<std::int64_t>(n), std::memory_order_relaxed);
        journal_bytes_.fetch_sub(evicted_bytes, std::memory_order_relaxed);
        // Classify every evicted key into EXACTLY ONE of three dispositions -
        // evicted_sent_unacked_ / evicted_without_send_evidence_ / evicted_unclassified_ - so
        // that batches_pruned_ (already advanced by `n` above) == the sum of the three, every
        // pass (item 3 / sec-M4, #2298 CC7.2). The third bucket is what makes that invariant
        // exact instead of an undercount: a mid-pass shutdown or an unreadable sent-label must
        // land the affected keys SOMEWHERE, or evicted_without_send_evidence_ - the audit-gap
        // signal an auditor reads - would report a SMALLER gap than actually occurred.
        //
        // The whole classifier is wrapped so a throw (bad_alloc under memory pressure in the
        // set build or the per-key string transform) accounts the not-yet-classified remainder
        // as unclassified before rethrowing to the caller's firewall. Without this the throw
        // would leave batches_pruned_ counting keys that reached no disposition bucket, and the
        // "exact" invariant would hold only on non-throwing passes.
        std::size_t classified = 0;
        try {
            // Fires with 0 here (post-delete, pre-shutdown-gate), then with the running count
            // after each classification. Test-only; null in production.
            if (prune_classify_hook_)
                prune_classify_hook_(classified);
            if (stopping_.load(std::memory_order_acquire)) {
                // Shutdown after the delete, before classification. Skip the sent-label scan
                // entirely (one fewer KvStore round trip on the drain-worker join path, #2298
                // cs-2) and count the WHOLE evict set as unclassified - the gap is reported at
                // its TRUE size, never a smaller one. The orphaned labels are GC'd by the next
                // boot's prune, which is idempotent.
                evicted_unclassified_.fetch_add(evict.size(), std::memory_order_relaxed);
                classified = evict.size();
            } else {
                // Classify from the one keys-only scan rather than a point read per evicted key.
                std::optional<std::set<std::string>> sent_keys;
                if (const auto& s = sent_scan(); s.has_value()) {
                    sent_keys.emplace(); // labels are presence markers; the key set IS the answer
                    for (const auto& r : *s)
                        sent_keys->insert(r.key);
                }
                bool point_read_failed = false;
                for (const auto& key : evict) {
                    // Best-effort classification: a live entry may age out before its batch key
                    // exists, so absence of a sent-label != "never sent".
                    //
                    // SINCE #2299 it also does not mean "was deliverable". A batch with a
                    // corrupt VALUE under a well-formed key is now quarantined by the REPLAY
                    // pass rather than by prune, so one the rotation never reaches within its
                    // retention life is age-evicted here as an ordinary batch - unlabelled, and
                    // therefore counted as evicted_without_send_evidence. That counter is the
                    // audit-loss signal, so on a mass-corruption endpoint it now mixes "never
                    // delivered" with "was never deliverable". Both are genuinely lost evidence,
                    // which is why this is a reporting caveat rather than a bug; an operator
                    // diagnosing a spike should read it alongside `quarantined` rather than alone.
                    const std::string label = journal_sent_key_from_batch_key(key);
                    if (sent_keys) {
                        // Scan-OK path (#2470): classification here is a pure in-memory set
                        // lookup - no I/O, no unbounded per-key cost - so a mid-loop shutdown does
                        // NOT truncate on this path. The remainder is fully determinable from the
                        // already-materialized `sent_keys` at negligible cost, so every key is
                        // classified to its TRUE disposition rather than lumping the tail into
                        // evicted_unclassified_ (which the fleet HELP calls "PERMANENTLY UNKNOWN",
                        // and which would leave evicted_without_send_evidence_ - the audit-gap
                        // floor an auditor reads - looser than the data supports). The earlier
                        // shape kept a per-key stop gate here too (Sol's L3 D1); the empirical
                        // panel reverted it (#2470): shutdown-promptness on an abnormally large
                        // evict set does not justify mislabeling determinable gaps, because these
                        // lookups are cheap. The per-key stop gate lives on the FALLBACK path
                        // ONLY, where each key is a KvStore round trip.
                        if (sent_keys->count(label))
                            evicted_sent_unacked_.fetch_add(1, std::memory_order_relaxed);
                        else
                            evicted_without_send_evidence_.fetch_add(1, std::memory_order_relaxed);
                        ++classified;
                        if (prune_classify_hook_)
                            prune_classify_hook_(classified);
                        continue;
                    }
                    // The scan failed, so each remaining key now costs a KvStore round trip (I/O,
                    // uncapped by the count/byte eviction path). ONLY here must a mid-loop shutdown
                    // truncate promptly - and the remainder is genuinely undeterminable, because
                    // the scan that would classify it already failed, so it is COUNTED as
                    // unclassified, never silently dropped.
                    if (stopping_.load(std::memory_order_acquire)) {
                        evicted_unclassified_.fetch_add(evict.size() - classified,
                                                        std::memory_order_relaxed);
                        classified = evict.size();
                        break;
                    }
                    // Fall back to a per-key read bounded by the evict set - but a FALLIBLE one.
                    // exists() answers false for both "absent" and "the read failed", and the
                    // read here fails for exactly the reason the scan just did, so it would report
                    // a whole evict set as "no send evidence" - the reading an operator is meant to
                    // treat as audit loss. A point error is counted as a read failure AND
                    // classified as UNCLASSIFIED: an unknown disposition is not evidence of
                    // absence, and it still belongs to a bucket so the invariant holds.
                    std::expected<std::optional<std::string>, KvStoreError> one;
                    if (inject_fail_prune_sent_reads_.load(std::memory_order_relaxed) > 0) { // test-only
                        inject_fail_prune_sent_reads_.fetch_sub(1, std::memory_order_relaxed);
                        one = std::unexpected(KvStoreError{"injected sent-label read failure"});
                    } else {
                        one = kv_->get_entry(kJournalNamespace, label);
                    }
                    if (!one) {
                        // Record the pass's read-failure the INSTANT it happens, once (guarded
                        // by point_read_failed), rather than after the loop. A later key's
                        // string-build or the caller's classify-hook can throw, and a
                        // post-loop increment would then be skipped by the catch below - leaving
                        // this unclassified bump WITHOUT its paired prune_failures signal that
                        // the docstring and metrics.md promise for an unreadable label
                        // (Gate 2 sec-INFO / Gate 4 UP-10). Recording it here keeps the pairing
                        // honest even under a throwing pass; still once per pass, never per key.
                        if (!point_read_failed)
                            prune_failures_.fetch_add(1, std::memory_order_relaxed);
                        point_read_failed = true;
                        evicted_unclassified_.fetch_add(1, std::memory_order_relaxed);
                        ++classified;
                        if (prune_classify_hook_)
                            prune_classify_hook_(classified);
                        continue;
                    }
                    if (one->has_value())
                        evicted_sent_unacked_.fetch_add(1, std::memory_order_relaxed);
                    else
                        evicted_without_send_evidence_.fetch_add(1, std::memory_order_relaxed);
                    ++classified;
                    if (prune_classify_hook_)
                        prune_classify_hook_(classified);
                }
            }
        } catch (...) {
            // Account the not-yet-classified remainder before rethrowing to the caller's
            // firewall, so the three-way invariant survives a throwing pass too.
            evicted_unclassified_.fetch_add(evict.size() - classified, std::memory_order_relaxed);
            throw;
        }
    }

    // #2452 Gate 8 - retention ran or was verified idle. This is reached past the eviction block, so
    // a delete FAILURE (returned early above, UP-7), a scan failure (read_ok false), and any stop
    // BEFORE the delete (UP8-3) never get here - all leave the flag false. But reaching here is NOT
    // sufficient on its own (focused re-review): the flag is true iff the pass either APPLIED a
    // delete (evicted > 0 - genuine retention progress) OR the empty evict set genuinely reflects an
    // idle journal - which it does NOT when the pass DECLINED age eviction of rows that WERE expired
    // (`skip_age && expired > 0`, UPR-2: a would_wipe all-expired reading, or a big_step suspend/
    // resume that aged rows out - retention deferred, journal not idle), and NOT when a malformed
    // key's quarantine rename failed and left a corrupt row stuck (quarantine_stall_this_pass, UPR-1,
    // mirroring the page-side guard). `skip_age && expired > 0` is deliberate over plain `!skip_age`:
    // a big_step on a genuinely-idle journal (expired == 0) declined nothing, so it stays
    // verified-idle rather than false-staling. A stop during the trailing label-GC below still leaves
    // this true (retention already ran). A forward-clock-jump WIPE evicts (evicted > 0), so it still
    // reads fresh - the L5 clock-guard (#2360/#2361) owns preventing that wipe, tracked separately.
    stats.progress_or_verified =
        stats.evicted > 0 || (!(skip_age && expired > 0) && !quarantine_stall_this_pass);

    // Surviving batch keys (parseable, not evicted): the reference set for sent-label GC. The
    // size gauges are NOT stored here any more - the rebase above plus the quarantine/eviction
    // fetch_subs already left them at the true on-disk size via RMW only, so a concurrent
    // persist increment is never lost (#2303 gauge-race fix).
    const std::set<std::string> evicted_set(evict.begin(), evict.end());
    std::set<std::string> survivors;
    for (const auto& l : live)
        if (!evicted_set.count(l.key))
            survivors.insert(l.key);

    // Shutdown: skip the two remaining housekeeping scans (label GC + quarantine bounding). Both
    // are best-effort and idempotent - the next boot's prune redoes them - and each is another
    // full scan + del_keys against a possibly-contended KvStore (C0 #2298).
    if (stopping_.load(std::memory_order_acquire))
        return stats;

    // Sent-label GC: drop any sent:<...> whose batch no longer survives - an evicted batch's
    // label, or an orphan from a crash between the pop-after-send label write and eviction.
    // Reuses the pass's single keys-only sent scan (fetched here if the classifier did not).
    if (const auto& sent = sent_scan()) {
        // The gate above covered ENTERING this block; a stop can still land during the list
        // itself, and each remaining step is another KvStore round trip (#2298 Sol review).
        if (stopping_.load(std::memory_order_acquire))
            return stats;
        std::vector<std::string> stale;
        for (const auto& s : *sent)
            if (!survivors.count(journal_batch_key_from_sent_key(s.key)))
                stale.push_back(s.key);
        if (!stale.empty() && !stopping_.load(std::memory_order_acquire))
            stats.sent_labels_gc =
                static_cast<std::size_t>(kv_->del_keys(kJournalNamespace, stale));
    }

    if (stopping_.load(std::memory_order_acquire))
        return stats; // do not START the quarantine scan

    // Bound the quarantine set (drop oldest-by-key; corrupt batches have no trusted ts_ms).
    if (auto q = kv_->list_keys_sized(kJournalNamespace, kQuarantineKeyPrefix)) {
        if (q->size() > max_quarantine_ && !stopping_.load(std::memory_order_acquire)) {
            std::vector<std::string> drop;
            const std::size_t excess = q->size() - max_quarantine_;
            for (std::size_t i = 0; i < excess; ++i)
                drop.push_back((*q)[i].key); // the scan is key-sorted
            // Count + warn the shed (review UP-7 / sre): a fleet quietly discarding over-cap
            // corrupt batches was previously invisible - an operator needs to see quarantine churn.
            if (stopping_.load(std::memory_order_acquire))
                return stats; // last gate before the final delete
            const int dropped = kv_->del_keys(kJournalNamespace, drop);
            if (dropped > 0) {
                quarantine_capacity_evicted_.fetch_add(static_cast<std::uint64_t>(dropped),
                                                       std::memory_order_relaxed);
                spdlog::warn("Guardian journal: shed {} over-cap quarantined batch(es) (cap {})",
                             dropped, max_quarantine_);
            }
        }
    }

    return stats;
}

JournalPageStats GuardianLifecycleJournal::page_into_window(GuardianSparkRuntime& rt,
                                                           std::int64_t now_ms,
                                                           bool replay_sent) {
    JournalPageStats stats;
    if (!kv_)
        return stats;
    // Shutdown began: page nothing at all. The mid-loop gate below already stops the window
    // mutation; checking here (and BEFORE paging_mutex_, so we never queue behind an in-flight
    // prune) also skips the boot-prune barrier's full scan and the candidate-build rename pass,
    // so a stop during maintenance does not delay the drain-worker join (C0 #2298).
    if (stopping_.load(std::memory_order_acquire))
        return stats;
    std::lock_guard<std::mutex> pg{paging_mutex_};

    // N1 / UP-11 (fleet-cost + run-loop stall): a pass with no token can do no net-new work, so
    // short-circuit BEFORE any O(journal) scan - including the boot-prune barrier below. Otherwise
    // a flapping link re-runs the full boot scan on the run-loop thread every reconnect until it
    // latches (up to the 5 s KvStore busy timeout each). The tick's periodic prune + the first
    // token-bearing page both still bound an over-cap journal; nothing is skipped, only deferred.
    // (The process's first page has the startup burst, so the boot prune still runs before the
    // very first replay.) rev-4.1 #6 warned a slow KvStore delays heartbeats; this respects it.
    if (!page_bucket_.ready(now_ms)) {
        stats.deferred_no_token = true;
        return stats;
    }

    // Prune-before-page barrier (rev-4.1 #6): the FIRST paging attempt prunes before it can
    // return any replay candidate, so a stale over-cap journal is bounded before replay. Latch
    // the barrier only on a SUCCESSFUL prune scan (review M5) so a transient read error does not
    // permanently mark the boot prune done and let over-cap data page unpruned.
    //
    // KNOWN LIMIT (#2303 Sol, pre-existing, inert): "bounded before replay" holds for the SCAN
    // (C4 pages nothing on a failed scan). It does NOT hold if the scan succeeds but the
    // retention DELETE fails - prune returns read_ok=true, the barrier latches, and readable
    // over-cap rows page anyway. That is bounded (the page rate-limiter caps the fleet cost) and
    // the rows are valid audit records, just not retention-trimmed first. Gating the barrier on
    // complete retention success (or documenting the intentional replay) is deferred to the
    // cutover resilience work (#2300); it does not gate this inert path.
    if (!boot_pruned_) {
        // Call prune_locked_ directly: we already hold paging_mutex_ (prune() would re-lock it).
        if (!prune_locked_(now_ms).read_ok) {
            // The barrier's own prune scan failed (counted on prune_failures_, NOT
            // page_read_failures_): this pass paged nothing and established nothing, so it must
            // NOT read as replay progress. Flag it so the drain worker's page success stamp does
            // not advance (#2452 - the same "clean return, no work" class as the candidate-scan
            // failures below, reached through the boot barrier before boot_pruned_ latches; in a
            // read-failure-from-boot regime the barrier never latches and every page pass takes
            // this exit).
            stats.read_failed = true;
            return stats; // #2303 C4: the barrier means "prune BEFORE any candidate can page".
                          // Latching only on read_ok (M5) is necessary but not sufficient - on a
                          // failed scan we must also PAGE NOTHING this pass, or we hand the
                          // runtime candidates a successful prune would have evicted, defeating
                          // the barrier on exactly the passes it exists for. Bounded and
                          // self-correcting: the tick's periodic prune and the next token-bearing
                          // pass retry, and expired rows are skipped below regardless.
        }
        boot_pruned_ = true;
    }

    // Re-check after the boot-prune barrier above: that barrier runs a FULL prune pass, so a
    // stop can arrive while it is in flight, and this scan is page's own heaviest read
    // (#2298 governance cs-2).
    if (stopping_.load(std::memory_order_acquire))
        return stats;

    if (inject_fail_page_reads_.load(std::memory_order_relaxed) > 0) { // test-only read fault
        inject_fail_page_reads_.fetch_sub(1, std::memory_order_relaxed);
        page_read_failures_.fetch_add(1, std::memory_order_relaxed);
        stats.read_failed = true;
        return stats; // same observable as a real scan failure below
    }
    // KEYS ONLY (#2299 perf-P-1). Selection - expiry, ordering, sent-label skip, rotation - is
    // entirely a function of the key, so the pass reads the VALUE of a candidate only when it
    // CONSIDERS one: at most kJournalPageMaxBatchesPerPass per pass, against a scan that used
    // to materialize and parse the whole namespace.
    //
    // STANDING INVARIANT, because it is not obvious from here: this pass is now also the ONLY
    // thing that detects a corrupt VALUE (prune reads no values at all). Corrupt-value
    // quarantine is therefore a side-effect of replay SCHEDULING - it happens only for
    // candidates this pass reaches, downstream of the token bucket, the expiry filter and the
    // sent-label skip. Anything that narrows what page considers narrows integrity coverage
    // with it, and no test will go red. If replay is ever gated off, rate-limited much harder,
    // or given a don't-retry set, prune must regain the value check (governance Gate 3
    // architect).
    auto rows = kv_->list_keys_sized(kJournalNamespace, kBatchKeyPrefix);
    if (!rows) {
        // Read error: fail-safe, page nothing this pass. Counted separately from prune's own
        // scan failures - a page-side read that fails every pass stops ALL replay while prune
        // keeps succeeding, so the two are different operator situations (#2345 Gate 6 SRE).
        page_read_failures_.fetch_add(1, std::memory_order_relaxed);
        stats.read_failed = true;
        return stats;
    }

    // Candidates arrive from the scan already in (ts_ms, key) order - that is what the
    // ts-leading key format buys - so there is no sort here any more. Skip expired batches
    // (prune removes them; don't re-send an aged-out event).
    struct Cand {
        std::string key;
        std::int64_t ts_ms;              ///< from the KEY, authoritative for ordering
        std::uint64_t bytes = 0;         ///< on-disk value size, for the gauge on removal
        std::optional<JournalBatch> batch; ///< filled by ensure_batch on first consideration
        bool unusable = false;           ///< quarantined, vanished, or unreadable this pass
        bool read_failed = false;        ///< specifically: the value read FAILED (unknown state)
    };
    std::vector<Cand> cands;
    cands.reserve(rows->size());
    // Use the cutoff RETENTION last decided, not a freshly computed one (#2345 Gate 5 CH-5).
    // Computing it here independently reintroduced the very loss the clock-jump guard exists to
    // prevent, one layer along: prune declined to age-evict on the anomalous reading, so the
    // batches survived on disk - and then page, computing its own cutoff from the same bad
    // clock, classified all of them "expired, prune will remove them" and replayed none. The
    // trail was retained and never sent, which is the worst of both. One decision, one place.
    const std::int64_t min_ts =
        pruned_cutoff_valid_ ? last_age_cutoff_
                             : now_ms - static_cast<std::int64_t>(retention_days_) * 86400 * 1000;
    for (auto& row : *rows) {
        // Shutdown mid-scan: bail rather than finish walking a large journal (C0 #2298).
        // Nothing has been paged yet, so returning here mutates no window and counts no pass;
        // the next boot re-scans.
        if (stopping_.load(std::memory_order_acquire))
            return stats;
        auto key_ts = parse_journal_batch_key_ts(row.key);
        if (!key_ts)
            continue; // malformed key: prune quarantines it (barrier + tick both run prune).
                      // Page deliberately does NOT rename here - it stays write-free for rows
                      // it will not consider, and prune reaches every row on its own cadence.
        if (*key_ts < min_ts)
            continue; // expired: prune evicts it; do not re-send, do not quarantine
        cands.push_back(
            Cand{.key = row.key, .ts_ms = *key_ts, .bytes = row.bytes, .batch = std::nullopt});
    }

    // Lazily read, parse and re-validate ONE candidate's value, at most once per pass. This is
    // where the value-side work that used to run over the entire namespace now happens - only
    // for a candidate the pass actually reaches, and memoized so the headroom re-scan below
    // cannot double it. Returns nullptr when the candidate must not be considered.
    //
    // `value_read_failed` is a PASS-level flag, not merely a per-candidate one: see the episode
    // footer. A failed read leaves that candidate's headroom disposition UNKNOWN, and unknown
    // is not evidence of "not blocked".
    bool value_read_failed = false;
    // Pass-level "this pass hit a CORRUPT candidate" (#2452 Gate 7 / UP-2), set whether the
    // quarantine rename succeeds OR fails. A quarantine is a SUCCESSFUL read of a corrupt batch, so
    // it is not a read failure, but it is not replay progress either: a pass that only quarantines
    // (or fails to quarantine a stuck corrupt batch) placed nothing and did not verify a clean idle
    // backlog, so it must NOT read the page stamp fresh. Feeds progress_or_verified_idle at the
    // tail; on a mass-corruption endpoint that is what makes the age gauge grow instead of lying
    // healthy while zero records reach the server.
    bool any_quarantine_this_pass = false;
    // A throw here would unwind the whole pass BEFORE page_cursor_ advances past this
    // candidate, so the next pass restarts on the same row and throws again - a permanent
    // rotation wedge that starves every batch behind it (Gate 4 unhappy-path UP-2). The
    // realistic source is a bad_alloc on an oversized value. Treat it exactly like a failed
    // read: unknown disposition, counted, rotation advances. The pass-level firewall on the
    // worker stays as the backstop for anything this cannot catch.
    const auto ensure_batch = [&](Cand& c) -> JournalBatch* {
        if (c.batch)
            return &*c.batch;
        if (c.unusable)
            return nullptr;
        try {
            candidate_value_fetches_.fetch_add(1, std::memory_order_relaxed);

            std::expected<std::optional<std::string>, KvStoreError> got;
            if (inject_fail_value_reads_.load(std::memory_order_relaxed) > 0) { // test-only fault
                inject_fail_value_reads_.fetch_sub(1, std::memory_order_relaxed);
                got = std::unexpected(KvStoreError{"injected value-read failure"});
            } else {
                got = kv_->get_entry(kJournalNamespace, c.key);
            }
            if (!got) {
                // The read FAILED. Distinct from absence, and the reason get_entry exists rather
                // than get(): this candidate's disposition is unknown, so it is neither placed nor
                // provably block-free. Counted on the page-side read counter, the same signal a
                // failing candidate scan raises.
                c.unusable = true;
                c.read_failed = true;
                value_read_failed = true;
                stats.read_failed = true; // pass could not establish this candidate (#2452)
                page_read_failures_.fetch_add(1, std::memory_order_relaxed);
                return nullptr;
            }
            if (!*got) {
                // ABSENT: the row was evicted or quarantined between the scan and here. It is
                // definitively gone, which is a known disposition - it waits on no headroom.
                c.unusable = true;
                return nullptr;
            }
            auto b = parse_journal_batch(**got);
            // Re-validate every record before replay (review M6): a corrupt/tampered v4 row on disk
            // (enqueued_ns<=0, an oversized/non-UTF-8 field, or an unrecognized kind) would poison
            // the server compare into a false Conflict every reconnect -- the exact failure the M6
            // MINT gate prevents. QUARANTINE the whole batch (the quarantine unit per section 2/9)
            // so it is never replayed and the removal is COUNTED, not silently skipped.
            //
            // An UNPARSEABLE value is quarantined here too. It used to be prune's job, but prune no
            // longer reads values at all, so the pass that does read a value is the pass that must
            // act on it. Bounded: at most one quarantine per considered candidate per pass, and
            // retention still bounds a corrupt journal by age, count and bytes meanwhile.
            //
            // #2818 (enterprise-readiness Gate 6): "errored" is a real, live-producible kind
            // (GuardianSparkRuntime::on_subscription_lost) as of this PR, not a corruption
            // signature - this allowlist must track guardian_outbox.hpp's documented lifecycle
            // vocabulary ("armed" | "disarmed" | "errored"), not lag one kind behind it. Before
            // this fix, an "errored" record surviving a crash/restart before it drained live would
            // have been silently quarantined here as tampered - destroying the exact audit record
            // #2818 exists to produce, in the exact scenario (durability across a restart) that
            // record is meant to survive.
            bool replayable = b.has_value();
            if (replayable) {
                for (const auto& r : b->entries) {
                    if (validate_record(r) != JournalReject::None ||
                        (r.kind != "armed" && r.kind != "disarmed" && r.kind != "errored")) {
                        replayable = false;
                        break;
                    }
                }
            }
            if (!replayable) {
                // A corrupt candidate this pass - whether the quarantine rename below SUCCEEDS or
                // FAILS (a pre-planted quarantine: twin conflicts, or a write error), the pass
                // placed nothing here and did not verify a clean idle backlog, so it must not read
                // the page stamp fresh (#2452 Gate 7). Set BEFORE the rename so a rename failure -
                // itself a no-work stall on a stuck corrupt batch - cannot slip past the flag.
                any_quarantine_this_pass = true;
                if (kv_->rename_key(kJournalNamespace, c.key, journal_quarantine_key(c.key)) ==
                    KvRename::Renamed) {
                    quarantined_.fetch_add(1, std::memory_order_relaxed);
                    // The row left the lc: namespace here too - keep the running-counter gauges
                    // exact (#2303), matching prune's quarantine fetch_sub. Page does not rebase,
                    // so without this the gauge over-counts the renamed-away row until the next
                    // prune scan (safe direction, but the "RMW exactly what leaves lc:" invariant
                    // must hold on every remover, not just prune).
                    journal_batch_count_.fetch_sub(1, std::memory_order_relaxed);
                    journal_bytes_.fetch_sub(static_cast<std::int64_t>(c.bytes),
                                             std::memory_order_relaxed);
                } else {
                    quarantine_failures_.fetch_add(1, std::memory_order_relaxed);
                }
                c.unusable = true;
                return nullptr;
            }
            c.batch = std::move(*b);
            return &*c.batch;
        } catch (...) {
            c.unusable = true;
            c.read_failed = true; // unknown, NOT provably block-free
            value_read_failed = true;
            stats.read_failed = true; // pass could not establish this candidate (#2452)
            page_read_failures_.fetch_add(1, std::memory_order_relaxed);
            return nullptr;
        }
    };

    // Fair rotation (review B2): resume at the first candidate strictly greater than the
    // last-considered (ts_ms, key) and WRAP, so the never-sent tail is reached instead of the
    // oldest sent-and-popped batches re-charging the bucket every pass and starving it. Bound
    // the pass to min(cands, cap) so a wrap cannot re-page a batch twice in one pass.
    const auto after_cursor = [&](const Cand& c) -> bool {
        if (!page_cursor_)
            return true;
        return c.ts_ms != page_cursor_->first ? c.ts_ms > page_cursor_->first
                                              : c.key > page_cursor_->second;
    };
    std::size_t start = 0;
    while (start < cands.size() && !after_cursor(cands[start]))
        ++start;
    if (start == cands.size())
        start = 0; // cursor at/after the end: wrap to the oldest

    // NOTE ON A REMOVED MECHANISM. Four attempts were made here to stop a LARGE batch being
    // skipped every pass while small ones are placed, and then deleted by retention unsent -
    // a loss channel biased towards the biggest batches, which are mass arm/disarm bursts and
    // so the most audit-significant records. All four scheduled the send window; all four
    // failed, and the reason is structural rather than a bug in any of them: a batch is
    // blocked precisely when the window has less room than it needs, so making it fit means
    // pausing competing replay until the drain creates room. Where the drain cannot create
    // room, such a scheme must either release (restoring the original loss) or hold (stalling
    // every other batch). No amount of counter or branch fixing removes that fork.
    //
    // The channel is therefore DOCUMENTED, not scheduled around: see #2364 and the retention
    // section of docs/guardian-c0-thread-reloc-design.md. It is narrow - a maximum batch is
    // 256 entries against a 4096 window, so it needs sustained occupancy above ~94%, which is
    // itself a delivery failure with its own signals - and the right next step is a signal for
    // that regime (the age of the oldest headroom-blocked batch), not a fifth scheduler.

    // One membership snapshot for the whole pass. Sizing a candidate by its NET-NEW records
    // rather than its raw entry count is what stops a batch that is ALREADY fully windowed
    // from being read as blocked on a phantom shortage - the same accounting error
    // try_page_batch fixes under the lock, which lived on here at the pre-check one layer up
    // (#2345 Gate 8 QE).
    const auto windowed = rt.lifecycle_event_ids();
    // De-duplicated, mirroring try_page_batch's `want` set. Counting per entry let a row that
    // repeats an event_id overstate its requirement by up to a whole batch, so a batch needing
    // one slot could be deferred as though it needed many (#2345 Gate 8b security).
    std::unordered_set<std::string> seen; // reused across candidates to avoid re-allocating
    const auto net_new_of = [&windowed, &seen](const JournalBatch& b) {
        seen.clear();
        for (const auto& r : b.entries)
            if (!windowed.count(r.event_id))
                seen.insert(r.event_id);
        return seen.size();
    };

    // RE-SEND-ALL IS NOT THE STEADY STATE (#2345 round 8). A delivered batch is popped from the
    // in-memory window the instant it ships, and membership in that window was the ONLY test for
    // "already delivered" - so on the next cadence pass the batch looked net-new again and was
    // re-paged and re-sent, for as long as retention kept it. Per agent that is the whole
    // paging budget spent re-delivering records the server already has and de-dupes; across a
    // fleet it is a permanent floor of redundant ingest that scales with endpoint count and
    // does nothing for durability.
    //
    // The durable sent-label already records delivery; it simply was not consulted here (it is
    // read only by prune's eviction classifier). Consult it, and re-offer a labelled batch ONLY
    // on a FORCED pass. Forced is every path that sets the worker's force_page_: boot replay,
    // the reconnect kick, and the headroom-refill re-arm during backlog recovery. The safety net is kept where it can pay and removed
    // where it cannot: a steady stream that returned Sent is not made safer by re-sending the
    // same batch ten seconds later.
    //
    // The trade, stated plainly: a batch whose send was accepted by the stream but never
    // ingested server-side, on an agent that then neither reboots nor reconnects, is no longer
    // re-offered. That is the case the DEFERRED server ack closes properly; until it lands this
    // is the honest boundary of at-least-once here.
    // Shutdown before the label scan. This is a full namespace scan able to block on the 5 s
    // busy timeout, on the thread GuardianEngine::stop() joins while holding mtx_ - the one
    // heavy KvStore call on this path that the candidate-build loop's gate does not cover,
    // because that gate is INSIDE the loop above. Prune states the rule for its identical
    // call: the stopping_ gates must PRECEDE the heavy calls, not merely straddle them
    // (#2298 governance cs-2). Returning here pages nothing, which is the safe direction.
    if (stopping_.load(std::memory_order_acquire))
        return stats;

    std::unordered_set<std::string> sent_labels;
    if (!replay_sent) {
        // Keys only: a label is a presence marker, so its value was never read even before
        // #2299 - and skipping a delivered batch now costs no value I/O at all.
        std::optional<std::vector<KvKeySize>> labels;
        if (inject_fail_sent_scans_.load(std::memory_order_relaxed) > 0) { // test-only fault
            inject_fail_sent_scans_.fetch_sub(1, std::memory_order_relaxed);
        } else if (auto rows_ok = kv_->list_keys_sized(kJournalNamespace, kSentKeyPrefix)) {
            labels = std::move(*rows_ok);
        }
        if (labels) {
            sent_labels.reserve(labels->size());
            for (auto& row : *labels)
                sent_labels.insert(std::move(row.key));
        } else {
            // A read failure leaves the set empty, which skips nothing and re-offers everything
            // - the pre-#2345-round-8 behaviour, and the safe direction, since redelivery is
            // free and a wrongly-skipped batch is lost. COUNTED, because otherwise an agent
            // whose scan fails every pass silently reverts to the old fleet-wide redelivery
            // floor with no signal at all, which is the exact cost this change removed.
            stats.sent_scan_failed = true;
            sent_scan_failures_.fetch_add(1, std::memory_order_relaxed);
        }
    }

    const std::size_t limit = std::min<std::size_t>(cands.size(), kJournalPageMaxBatchesPerPass);
    // Episode-state locals (#2364 telemetry). `note_clean` records a candidate observed
    // block-free this pass into the cross-pass coverage set - only while an episode is
    // active, so the steady no-episode state allocates nothing. A stop-truncated pass
    // proves nothing and must not reach the footer's clear check.
    bool stop_truncated = false;
    const bool episode_active =
        headroom_blocked_since_steady_ms_.load(std::memory_order_relaxed) >= 0;
    const auto note_clean = [&](const std::string& key) {
        if (episode_active)
            clean_keys_since_block_.insert(key);
    };
    for (std::size_t n = 0; n < limit; ++n) {
        if (stopping_.load(std::memory_order_acquire)) {
            stop_truncated = true;
            break; // shutdown began: stop mutating the window (stop-race gate, rev-4.1 #7)
        }
        if (post_classify_hook_)
            post_classify_hook_(); // test-only: land a stop between candidates
        Cand& c = cands[(start + n) % cands.size()];
        if (!sent_labels.empty() &&
            sent_labels.count(journal_sent_key_from_batch_key(c.key)) != 0) {
            ++stats.skipped_already_sent;
            note_clean(c.key); // delivered => waits on no headroom
            page_cursor_ = std::pair{c.ts_ms, c.key}; // advance: never pin the rotation
            continue;
        }
        // Only now is the value worth reading: this candidate is not expired, not already
        // delivered, and inside the pass's cap.
        JournalBatch* batch = ensure_batch(c);
        if (!batch) {
            // Quarantined or vanished: a removed batch waits on no headroom, so it must not
            // pin the episode's coverage set (same rationale as the sent-skip above). But a
            // candidate whose value could not be READ is different - its disposition is
            // unknown, and recording unknown as block-free would let the footer clear an
            // episode while a still-blocking batch went unread. Advance the rotation either
            // way so a bad row cannot pin it.
            if (!c.read_failed)
                note_clean(c.key);
            page_cursor_ = std::pair{c.ts_ms, c.key};
            continue;
        }
        // Check headroom BEFORE building anything. Two reasons (#2298 Gate 4 UP-2 + f-2):
        // try_page_batch's own headroom gate is all-or-nothing per batch, so a full window
        // means every OutboxEntry constructed below - up to 256 per batch, each carrying
        // several strings - is built and immediately discarded; and the caller cannot
        // otherwise distinguish "window full" from "already a member", which are opposite
        // situations. Recording it here makes the distinction explicit and skips the waste.
        // This pre-check is a pure OPTIMISATION - it avoids building up to 256 OutboxEntry
        // objects for a batch that cannot fit. It is deliberately NOT the source of truth: a
        // concurrent arm can consume the room between here and try_page_batch, so the
        // authoritative blocked/member distinction comes back from under outbox_mu_ below
        // (#2345 Gate 3). It is read per candidate rather than hoisted because a single stale
        // read would misclassify every later candidate in the pass.
        const std::size_t headroom = rt.lifecycle_headroom();
        const auto id = std::pair{c.ts_ms, c.key};
        const std::size_t need = net_new_of(*batch);
        if (need == 0) {
            // Already fully windowed: no work, and emphatically NOT a blockage.
            note_clean(c.key);
            page_cursor_ = id;
            continue;
        }
        if (headroom < need) {
            // Paging a newer batch ahead of an older blocked one can invert armed/disarmed
            // wire order across batches. That is tolerated by the server today: dedup compares
            // immutable fields only on an event_id collision, lifecycle events do not update
            // the compliance census, and event queries order by event timestamp rather than
            // arrival. Strict replay order is in any case already best-effort (fair-rotation
            // resume, second-truncated ingest timestamps).
            stats.headroom_blocked = true;
            // Record the SMALLEST blocked requirement so the caller can re-arm only once that
            // much room actually exists - "any headroom > 0" re-armed on every cycle and put
            // UP-2's scan amplification back in the recovery regime.
            if (stats.min_blocked_headroom == 0 || need < stats.min_blocked_headroom)
                stats.min_blocked_headroom = need;
            page_cursor_ = id; // advance: never pin the rotation on a blocked batch
            if (headroom == 0) {
                // Nothing fits at all, so stop scanning - but first record the SMALLEST batch
                // still pending, not this one. Reporting the head's requirement made the
                // worker's re-arm wait for room it never needed (Gate 4 S3). The loop rewrite
                // that later replaced it dropped this scan; restored (#2345 Gate 8b security).
                // Fold in only candidates that actually NEED room. A fully-windowed candidate
                // reports 0 net-new, and taking that into the minimum zeroed it - whereupon the
                // "> 0" guard discarded the whole scan and min_blocked_headroom silently kept
                // the HEAD batch's requirement, which is the exact defect this scan exists to
                // prevent. Not a corner case: live arm/disarm records are both windowed and
                // journal candidates, so a recent batch is routinely fully windowed
                // (#2345 Gate 3 - found independently by three reviewers).
                std::size_t smallest = need; // seeded from a candidate that does need room
                for (std::size_t m = n + 1; m < limit; ++m) {
                    // Shutdown mid-scan. This loop used to be pure in-memory arithmetic; since
                    // the value read became lazy it issues a KvStore point read per candidate
                    // and can issue a quarantine rename, so at the 128 cap it is up to ~127
                    // round trips each able to block on the 5 s busy timeout - on the thread
                    // GuardianEngine::stop() is joining while it holds mtx_. Every other
                    // KvStore-round-trip loop in this file is gated; this one has to be too
                    // (#2298 bounded-shutdown invariant). Breaking early is safe: `smallest` is
                    // seeded from `need`, so the pass reports a CONSERVATIVE (larger)
                    // requirement and the caller merely re-arms later than it might have.
                    if (stopping_.load(std::memory_order_acquire))
                        break;
                    Cand& mc = cands[(start + m) % cands.size()];
                    // Apply the SAME sent-label filter the outer loop applies. Without it this
                    // scan reads and parses already-delivered batches - and it runs exactly when
                    // headroom is 0, the link-down steady state where most candidates carry a
                    // label, so it degenerated "read only what you might place" into "read the
                    // whole cap" in the one regime the lazy read was built for. It also folded
                    // delivered batches into min_blocked_headroom, sizing the caller's re-arm
                    // against a batch that will never be paged.
                    //
                    // NOTE this narrows corrupt-value quarantine a little further (a corrupt
                    // sent-labelled batch is now caught only on a FORCED pass) - see the
                    // standing invariant at the head of this function. No corrupt data is
                    // replayed and nothing is lost; discovery is delayed.
                    if (!sent_labels.empty() &&
                        sent_labels.count(journal_sent_key_from_batch_key(mc.key)) != 0)
                        continue;
                    // Reads each remaining candidate's value, memoized - so a pass pays for a
                    // given candidate once whether it is reached here or by the outer loop, and
                    // the per-pass value-read count stays bounded by the candidate cap.
                    const JournalBatch* mb = ensure_batch(mc);
                    if (!mb)
                        continue; // unreadable/removed: it cannot be the smallest pending need
                    const std::size_t nn = net_new_of(*mb);
                    if (nn > 0)
                        smallest = std::min(smallest, nn);
                    if (smallest == 1)
                        break; // cannot get smaller; stop hashing the rest of the slice
                }
                if (stats.min_blocked_headroom == 0 || smallest < stats.min_blocked_headroom)
                    stats.min_blocked_headroom = smallest;
                break;
            }
            continue;
        }
        const bool have_token = page_bucket_.ready(now_ms); // refills for elapsed time

        std::vector<OutboxEntry> entries;
        entries.reserve(batch->entries.size());
        for (std::size_t i = 0; i < batch->entries.size(); ++i) {
            const auto& r = batch->entries[i];
            OutboxEntry e = OutboxEntry::lifecycle(r.rule_id, r.generation, r.event_id,
                                                   r.enqueued_ns, r.kind, r.guard_type, r.rule_name);
            e.journal_batch_key = c.key; // replay provenance for the sent-label (wire-ignored)
            e.journal_last_in_batch = (i + 1 == batch->entries.size());
            entries.push_back(std::move(e));
        }
        const auto outcome = rt.try_page_batch(std::move(entries));
        // Advance the cursor for EVERY considered batch (paged or a free member / headroom-defer
        // skip), so an already-windowed head cannot pin the rotation.
        page_cursor_ = std::pair{c.ts_ms, c.key};
        if (outcome.blocked_for_headroom) {
            // The window shrank between the pre-check and the locked attempt. Without this the
            // pass would report "nothing to do" and the caller's refill re-arm would never
            // fire, stalling replay for a full cadence interval (#2345 Gate 3).
            stats.headroom_blocked = true;
            if (stats.min_blocked_headroom == 0 || outcome.required < stats.min_blocked_headroom)
                stats.min_blocked_headroom = outcome.required;
        } else {
            note_clean(c.key); // placed, or every entry already a member - not blocked
        }
        if (outcome.added > 0) {
            // Charge BEFORE the break, deliberately. This pass is allowed to place one batch
            // over an empty bucket, and charging for it takes the balance negative, which is
            // simply the debt for work already done: two batches placed cost two tokens, so
            // the next pass waits proportionally longer. Charging only when a token was in
            // hand would hand out one free batch per pass and roughly double the steady-state
            // replay rate the bucket exists to bound (#2345 round 7 - proposed as a fix, and
            // rejected on that arithmetic).
            page_bucket_.take();
            ++stats.batches_paged;
            stats.records_paged += outcome.added;
            if (!have_token)
                break; // paged one net-new over an empty bucket; the rest wait for a refill
        }
        // added == 0 and not blocked: every entry was already a member; keep rotating.
    }

    // Headroom-blocked EPISODE state (#2364 step-1 telemetry): the age of the current
    // replay-congestion episode, surfaced as yuzu.guardian_journal_headroom_blocked_seconds.
    // Pass-level, never per-try_page_batch-call: in the #2364 starvation regime a single pass
    // BOTH places small batches AND leaves the large one blocked, so any per-call
    // set-on-block/clear-on-place state pins the age at ~0 in exactly the regime this gauge
    // exists to expose (Sol + Kimi opine, 2026-07-23).
    //
    // Transition rules (both external reviewers independently, + the Fable review that
    // replaced a coverage COUNT with the distinct-key set):
    //  - A blocked observation is PROOF, however the loop exited: set-if-unset.
    //  - A clean pass is only a SLICE (kJournalPageMaxBatchesPerPass=128 vs up to 1000
    //    batches; the token-debt break above also ends a pass early), so clearing on a clean
    //    pass would zero the gauge whenever the starved batch sits outside the scanned slice
    //    - a sawtooth in the big-journal regime. Clear ONLY once EVERY candidate that
    //    currently exists has itself been observed block-free since the last blocked
    //    observation (the clean_keys_since_block_ membership check below; a single full
    //    clean sweep clears immediately, partial slices accumulate across passes). A COUNT
    //    compared against the current set size is NOT equivalent: prune eviction between
    //    passes removes already-counted candidates, the count survives, the bar drops, and
    //    the episode clears before the rotation re-reaches the still-blocked batch -
    //    re-opening the sawtooth under exactly the shrink-churn the starvation regime
    //    produces. Distinct-key coverage is churn-proof in both directions: an evicted
    //    candidate stops being required, a new one becomes required.
    //  - A stop-truncated pass with no blocked observation proves neither state: touch
    //    nothing. (Every earlier return above - no KV, stopping, no token, boot-prune fail,
    //    scan fail - already touches nothing by construction.)
    //  - Likewise a pass in which any candidate's VALUE READ FAILED. Since #2299 a candidate's
    //    records are read only when it is considered, so a failed point read leaves that
    //    candidate's headroom disposition unknown - and unknown is not evidence of block-free.
    //    Treating it as clean would let a chronically unreadable row complete the coverage set
    //    and clear a live episode while the batch that is actually blocking went unread. Same
    //    rule as the slice and the count-vs-set-size doors before it: clear only on positive
    //    evidence for EVERY current candidate.
    //  - An empty candidate set has nothing to block: clear.
    // Single writer (paging_mutex_ serialises passes); the atomic exists for the lock-free
    // heartbeat read - the heartbeat must never queue behind an in-flight O(journal) pass.
    if (stats.headroom_blocked) {
        clean_keys_since_block_.clear();
        if (headroom_blocked_since_steady_ms_.load(std::memory_order_relaxed) < 0) {
            const auto now_steady = std::chrono::duration_cast<std::chrono::milliseconds>(
                                        std::chrono::steady_clock::now().time_since_epoch())
                                        .count();
            headroom_blocked_since_steady_ms_.store(now_steady, std::memory_order_relaxed);
        }
    } else if (!stop_truncated && !value_read_failed && episode_active) {
        bool covered = true; // empty set: trivially covered -> clear
        for (const Cand& c : cands) {
            if (clean_keys_since_block_.count(c.key) == 0) {
                covered = false;
                break;
            }
        }
        if (covered) {
            headroom_blocked_since_steady_ms_.store(-1, std::memory_order_relaxed);
            clean_keys_since_block_.clear(); // release the epoch's memory
        }
    }
    // Bound the coverage set to keys that still EXIST, whatever the branch above decided.
    // Neither branch runs on a pass that proves nothing (stop-truncated, or one where a value
    // read failed), so an episode held open by a chronically unreadable row would otherwise
    // accumulate every newly-persisted key forever, and never release the keys of batches
    // retention has already deleted - a slow leak reclaimed only by restart. This is exact,
    // not a heuristic: an `lc:` key never returns once it leaves the namespace, so a key
    // absent from this pass's scan can never be required for coverage again. It also cannot
    // change the decision above - that reads only keys that ARE current candidates.
    //
    // Binary-searched over the scan rather than copied into a set: `*rows` is already
    // ORDER BY key, and this runs on every pass with a live episode - i.e. exactly the
    // congestion regime whose peak memory this change exists to reduce, so allocating a full
    // copy of every key here would give some of that back (Gate 8 security).
    if (!clean_keys_since_block_.empty()) {
        std::erase_if(clean_keys_since_block_, [&](const std::string& k) {
            return !std::binary_search(rows->begin(), rows->end(), k,
                                       [](const auto& a, const auto& b) {
                                           if constexpr (std::is_same_v<decltype(a), const KvKeySize&>)
                                               return a.key < b;
                                           else
                                               return a < b.key;
                                       });
        });
    }

    pages_.fetch_add(1, std::memory_order_relaxed);
    records_paged_.fetch_add(stats.records_paged, std::memory_order_relaxed);
    // #2452 Gate 7 - the ONLY site that sets progress_or_verified_idle true. Reached only when the
    // pass finished its consideration loop (no early return, no stopping_ truncation) - which is
    // per-SLICE (capped at kJournalPageMaxBatchesPerPass), not whole-backlog; see the hpp docstring
    // for why per-slice is correct. Healthy iff it PLACED records, or it verified a clean idle slice:
    // nothing left blocked on
    // headroom, nothing quarantined, no candidate value read failed, and the sent-label scan did
    // NOT fall back (sent_scan_failed - a degraded read means the pass could not fully verify what
    // was already delivered, so it is not "verified" idle; parity with the pre-Gate-7 gate).
    // `stop_truncated` guards a mid-loop shutdown; a stopping_ bail before this point never reaches
    // here and leaves the flag false. This positive signal is what closes the negative
    // enumeration's structural gap - a future no-progress exit added above returns early and stays
    // not-fresh by construction.
    stats.progress_or_verified_idle =
        stats.records_paged > 0 ||
        (!stop_truncated && !stats.headroom_blocked && !stats.read_failed &&
         !stats.sent_scan_failed && !any_quarantine_this_pass);
    return stats;
}

void GuardianLifecycleJournal::mark_batch_sent(const std::string& batch_key) {
    if (!kv_ || batch_key.empty())
        return;
    // Best-effort presence marker; the value is unused. set() is an upsert, so a repeated
    // send is idempotent. Never gates re-paging or deletion (design §2/§8).
    if (kv_->set(kJournalNamespace, journal_sent_key_from_batch_key(batch_key), ""))
        sent_labels_written_.fetch_add(1, std::memory_order_relaxed);
}

} // namespace yuzu::agent
