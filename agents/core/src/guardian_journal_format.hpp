#pragma once

/**
 * guardian_journal_format.hpp -- pure on-disk format for the Guardian durable
 * lifecycle-audit journal (item 7, PR-Ag; design rev 4.1:
 * docs/spark-item7-lifecycle-journal-design.md).
 *
 * This TU is the SUBSTRATE ONLY: the record shape, the kv_store key/namespace
 * scheme, the caps, mint-time field validation, and batch (de)serialization.
 * It has NO wiring, NO KvStore access, NO threads - it is deterministic and
 * unit-testable in isolation. Staging, persistence, retention, and replay layer
 * on top of this in later commits.
 *
 * A JournalRecord is FROZEN AT MINT: every field it carries is exactly what was
 * (or will be) sent on the wire, so a replay reconstructs a byte-identical
 * GuaranteedStateEvent and the server's redelivery compare (PR-Sv) sees a match,
 * not a false Conflict. Nothing here is ever re-stamped or re-measured.
 */

#include <yuzu/plugin.h> // YUZU_EXPORT

#include <cstddef>
#include <cstdint>
#include <expected>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <vector>

namespace yuzu::agent {

// ── Namespace, format version, caps (design §3, §6; rev-4.1) ──────────────────

/// Distinct kv_store "plugin" namespace - survives full_sync's rule-record
/// sweep (a scoped delete of "rule:"-prefixed keys under "__guardian__" as of
/// #4021; this namespace was never touched by it either before or after).
inline constexpr std::string_view kJournalNamespace = "__guardian_journal__";

/// Value envelope version. An unknown version on read → quarantine (never trust).
inline constexpr int kJournalFormatVersion = 4;

/// Batch size caps: a push larger than this is chunked into multiple batches.
inline constexpr std::size_t kMaxJournalEntriesPerBatch = 256;
inline constexpr std::size_t kMaxJournalBatchBytes = 256 * 1024; // 256 KiB

/// Bounded staging reserve (RAM). Overflow → drop-oldest + journal_stage_dropped.
inline constexpr std::size_t kMaxPendingJournalRecords = 4096;

/// What ONE heartbeat retry-persist may write (C0 flip-checklist item 11). The heartbeat
/// thread holds the engine mutex across the call, so the cost is a LATENCY budget - but a
/// latency budget expressed only in batches silently becomes a THROUGHPUT floor, and those
/// two are not the same number.
///
/// Why both caps. Each batch is a separate autocommit insert that can approach the KvStore's
/// 5 s busy timeout under contention, so the BATCH cap is what bounds a tick's worst case
/// (~4 x 5 s, inside the 30 s heartbeat) instead of leaving it unbounded. But a batch is
/// capped at kMaxJournalEntriesPerBatch entries AND kMaxJournalBatchBytes, so how many
/// RECORDS four batches carry depends entirely on record size: ~1024 when records are small
/// and batches fill on the entry cap, but as few as ~48 when large fields make the byte cap
/// split them - a 21x swing in sustained drain rate, from ~34 rec/s down to ~1.6 rec/s
/// (governance Gate 3 performance). The heartbeat tick is the only steady-state drain, so at
/// the low end a sustained event rate the pre-cap code absorbed would instead overflow the
/// bounded staging buffer and shed records through the counted journal_stage_dropped path.
/// That would be a NEW loss channel introduced by a latency fix, which is not a trade worth
/// making silently.
///
/// The RECORD cap therefore floors the throughput independently of record size: whichever
/// limit is reached first ends the call, so the tick is bounded in round trips AND the drain
/// rate cannot collapse with record size. 1024 records matches the small-record regime the
/// batch cap already allowed, and stays two orders above any plausible sustained arm/disarm
/// rate. A burst above it drains over the next few ticks.
inline constexpr std::size_t kJournalPersistMaxBatchesPerTick = 4;
inline constexpr std::size_t kJournalPersistMaxRecordsPerTick = 1024;

/// Explicit "no cap" for persist()'s bounds - the one-shot callers (boot re-arm, apply_rules,
/// and both shutdown flushes) each have to drain what they were given. Named rather than a
/// defaulted 0 so that omitting the argument is not the unbounded case: a future cadence
/// caller that forgot it would otherwise get an unbounded write run under the engine mutex,
/// which is exactly the defect the cap exists to prevent (governance Gate 3 architect).
inline constexpr std::size_t kJournalPersistUnbounded = 0;

/// Per-field byte cap. An oversized field keeps the whole record out (counted).
inline constexpr std::size_t kMaxJournalFieldBytes = 4096;

/// The largest stored value `persist()` can produce, with slack. A batch stops at
/// kMaxJournalBatchBytes, and the one case that can exceed it - the first record of a batch is
/// admitted unconditionally - is itself bounded by 7 fields at kMaxJournalFieldBytes, far below
/// this. So a row LARGER than this cannot have been written by this code: it is corruption,
/// detectable from the scan's byte length ALONE with no value read.
///
/// Retention needs that check because it no longer parses values (#2299). Before, an
/// unparseable row was quarantined out of the candidate set and never counted toward the byte
/// ceiling; now a well-keyed row counts for its full size whatever the value contains, so one
/// tampered or bit-rotted 40 MiB row would push the journal over its 32 MiB ceiling and make an
/// UNCAPPED single pass evict every older batch - deleting undelivered evidence and counting it
/// as ordinary retention (governance Gate 4 unhappy-path UP-1). Quarantining by size restores
/// the pre-#2299 property at zero I/O cost.
inline constexpr std::size_t kMaxPlausibleJournalValueBytes = 2 * kMaxJournalBatchBytes;
/// The threshold is a QUARANTINE trigger, and a quarantined row is eventually deleted by the
/// over-cap shed - so it must never be reachable by a legitimate batch. Bind it to the write
/// path's own bound rather than leaving the 2x margin as a comment: narrowing this constant,
/// raising kMaxJournalBatchBytes, or adding a JournalRecord string field that est_entry_bytes
/// does not count would otherwise silently quarantine-then-delete real audit evidence with
/// only a counter to show for it (governance Gate 8 security).
static_assert(kMaxPlausibleJournalValueBytes >= 2 * kMaxJournalBatchBytes,
              "the implausible-value threshold must stay above anything persist() can write");

/// Retention bounds (evict oldest by (ts_ms, key)).
inline constexpr int kJournalRetentionDays = 7;
inline constexpr std::size_t kMaxJournalBatches = 1000;
inline constexpr std::size_t kMaxJournalBytes = 32ull * 1024 * 1024; // 32 MiB

/// Corrupt batches moved aside are ALSO bounded (counted + pruned) so they cannot
/// accumulate outside the caps above.
inline constexpr std::size_t kMaxQuarantineBatches = 100;

/// Replay pacing. This USED to double as the steady-state redelivery rate, because a delivered
/// batch left the send window and window membership was the only "already delivered" test, so
/// every cadence pass re-paged and re-sent it until retention. That is fixed: page_into_window
/// consults the durable sent-label and re-offers a delivered batch only on a FORCED pass (boot
/// replay, reconnect kick) - the events after which an in-flight send may actually have been
/// lost (#2345 round 8). So this now bounds genuinely-new replay plus post-reconnect catch-up,
/// NOT a permanent per-agent redelivery floor. The deferred server ack remains the proper fix
/// for the residual case: a send the stream accepted but the server never ingested, on an agent
/// that neither reboots nor reconnects. Tunable.
inline constexpr double kJournalPageRefillPerSec = 0.1; // 1 batch / 10 s / agent
inline constexpr double kJournalPageBurst = 5.0;        // small startup burst
/// Bound per-pass paging work (reconstruct + membership scan) regardless of journal size.
inline constexpr std::size_t kJournalPageMaxBatchesPerPass = 128;

/// How far in the future a batch's ts_ms may plausibly sit before retention stops trusting it.
///
/// A batch stamped beyond this sorts FIRST for the count and byte ceilings - an ORDERING rule,
/// NOT an expiry rule. The distinction is load-bearing and was arrived at the hard way: making
/// such a batch "immediately expired" hands the whole journal to any clock reading in the past
/// (an RTC that comes up at 1970 makes every real row look future-dated), which is the
/// wholesale wipe the age guard exists to prevent - it failed 21 tests. Do not "simplify" this
/// back to an expiry test. Without the ordering rule such a row is IMMORTAL - it can never be
/// too old, and count eviction is oldest-first so it is never count-evicted either - and worse,
/// it DISPLACES real evidence: once enough of them exist
/// (a bad RTC for a week, a VM clone, a hand-edited kv_store.db), every genuine record written
/// afterwards is the one evicted at the next prune, permanently. Precedent for the shape is
/// server-side in app_perf_daily_store.cpp's kFutureSlackDays (#2345 Gate 2 security).
///
/// One day is generous for clock skew between an endpoint and its own next prune pass, while
/// still bounding the damage a badly-set clock can do to the audit trail.
inline constexpr std::int64_t kJournalFutureSlackMs = 24LL * 3600 * 1000;

/// Batches a single retention pass may evict for AGE. Age is the one retention rule driven by
/// an absolute reading of the wall clock, so one bad reading (a VM restored from snapshot, an
/// NTP overshoot) marks every batch expired simultaneously and would delete the whole durable
/// audit trail in one transaction. Capping the pass converts that into a paced ageing-out that
/// an operator can notice and act on, rather than an instantaneous one.
///
/// It does NOT guarantee the paced batches are shipped first: at 64 per ~120 s pass this sheds
/// roughly 32 batches/minute while replay refills at 0.1 batch/s (~6/minute), so deletion
/// outruns delivery about five to one (#2345 Gate 2 performance). Lowering the cap to match the
/// replay rate, or lifting the paging bucket while pacing, is tracked on #2364; what the cap
/// buys today is time and a signal, not delivery.
///
/// It caps AGE eviction ONLY, and deliberately does not bound how fast a journal shrinks: the
/// count and byte ceilings are uncapped and trim an over-ceiling journal back in a single pass
/// regardless of this constant, so an over-cap journal converges as fast as it ever did. The
/// pacing therefore applies to the case it was built for - a journal that is within its
/// ceilings but suddenly entirely expired - and NOT, as an earlier version of this comment
/// claimed, to "a full 2000-batch journal ageing out in about an hour": at 2000 batches the
/// count ceiling is what evicts, and it evicts ~1000 in one pass (#2345 Gate 8 UP5-2).
inline constexpr std::size_t kMaxAgeEvictionsPerPass = 64;

/// Key prefixes within kJournalNamespace. A batch key is "lc:<ts13>:<nonce>:<seq12>";
/// its sent-label is "sent:<ts13>:<nonce>:<seq12>"; a quarantined batch is
/// "quarantine:" + the original batch key. The three prefixes are disjoint so a
/// prefix scan of one never sees another.
inline constexpr std::string_view kBatchKeyPrefix = "lc:";
inline constexpr std::string_view kSentKeyPrefix = "sent:";
inline constexpr std::string_view kQuarantineKeyPrefix = "quarantine:";

// ── Record (7 fields, frozen at mint; design §3) ─────────────────────────────

struct JournalRecord {
    std::string rule_id;
    std::uint64_t generation{0};
    std::string event_id; // wire idempotency key; boot-nonce'd; PRESERVED verbatim on replay
    std::int64_t enqueued_ns{0}; // wall ns at enqueue; the frozen wire timestamp source
    std::string kind;            // "armed" | "disarmed" | "errored" (#2818) - keep in lockstep
                                 // with guardian_lifecycle_journal.cpp's replay allowlist AND
                                 // guardian_outbox.hpp's documented lifecycle_kind vocabulary
    std::string guard_type;
    std::string rule_name;
};

struct JournalBatch {
    std::int64_t ts_ms{0}; // batch wall-clock ms - the ordering key across batches
    std::vector<JournalRecord> entries;
};

// ── Key helpers ──────────────────────────────────────────────────────────────

/// Widths of the two fixed-width key fields. `ts_ms` is padded to 13 digits, which
/// covers every representable instant up to 9'999'999'999'999 ms (Nov 2286) - a value
/// beyond it, or below zero, is CLAMPED at mint rather than allowed to change the field
/// width or emit a '-' sign, either of which would break the fixed-width ordering the
/// key exists to provide. `seq` keeps its 12 digits (a per-process counter from 0).
inline constexpr int kJournalKeyTsDigits = 13;
inline constexpr int kJournalKeySeqDigits = 12;
inline constexpr std::int64_t kJournalKeyMaxTsMs = 9'999'999'999'999LL;

/// "lc:<ts13>:<boot_nonce>:<seq12>" - the batch's wall-clock ms zero-padded to a FIXED
/// 13 digits, then the boot-nonce, then the per-process sequence.
///
/// The timestamp leads because that makes SQLite's `ORDER BY key` identical to the
/// (ts_ms, key) ordering every consumer wants: equal-ts keys tie-break on
/// "<nonce>:<seq>", exactly as the old comparator did. That is what lets a maintenance
/// pass select and order candidates from KEYS ALONE and read only the values it will
/// actually use (#2299 perf-P-1) - with the nonce leading, key order was random per
/// boot and retention would have evicted arbitrary rather than oldest evidence.
///
/// `ts_ms` is clamped to [0, kJournalKeyMaxTsMs]; see the width note above.
YUZU_EXPORT std::string journal_batch_key(std::int64_t ts_ms, std::string_view boot_nonce,
                                          std::uint64_t seq);

/// The batch timestamp carried by a batch key, or nullopt if `batch_key` is not a
/// well-formed batch key. The check is STRICT ("lc:" + 13 digits + ':' + a non-empty
/// nonce with no ':' + ':' + 12 digits): the journal is dormant until the prefer_spark
/// flip, so no key in the old format can exist on disk and a key that fails this check
/// is corruption, never legacy data. Callers quarantine or skip on nullopt.
YUZU_EXPORT std::optional<std::int64_t> parse_journal_batch_key_ts(std::string_view batch_key);

/// True if `batch_key` has the RETIRED pre-#2299 shape `lc:<nonce>:<seq12>` - no timestamp.
/// Diagnostic only: such a key is malformed and quarantined either way, but distinguishing it
/// lets the log say "stale journal from a pre-cutover local build" rather than leaving an
/// operator to read a quarantine as corrupt-page data loss. Retire this a release after the
/// prefer_spark flip.
YUZU_EXPORT bool looks_like_pre_ts_batch_key(std::string_view batch_key);

/// "quarantine:" + batch_key - where a corrupt/unparseable batch is moved.
YUZU_EXPORT std::string journal_quarantine_key(std::string_view batch_key);

/// Derive the batch key a sent-label refers to: "sent:X:Y" → "lc:X:Y". Used by
/// sent-label GC to find labels whose batch no longer exists. Returns the input
/// unchanged if it is not a sent-label key (it then matches no batch).
YUZU_EXPORT std::string journal_batch_key_from_sent_key(std::string_view sent_key);

/// Derive a batch's sent-label key: "lc:X:Y" → "sent:X:Y". Used when a paged batch's last
/// entry sends, and to classify an eviction. Returns the input unchanged if not a batch key.
YUZU_EXPORT std::string journal_sent_key_from_batch_key(std::string_view batch_key);

// ── Mint-time validation (design §2 loss table; rev-4.1 #2) ───────────────────

/// Why a record was refused entry to the journal. The caller maps each reason to
/// its integrity counter: field faults → journal_field_rejected; a skewed clock →
/// journal_clock_rejected (rev-4.1 #2).
enum class JournalReject {
    None,
    EmbeddedNul,  // a string field contains a NUL - journal values are NUL-free
    Oversized,    // a string field exceeds kMaxJournalFieldBytes
    InvalidUtf8,  // a string field is not valid UTF-8 (JSON cannot carry it byte-exact;
                  // silently replacing bytes would flip the server compare to a false Conflict)
    SkewedClock,  // enqueued_ns floors to epoch seconds <= 0 - the server would stamp
                  // receipt-now instead, making every replay mismatch on timestamp
};

/// Validate a record at mint. Returns the FIRST reason it must be refused, or
/// None if it is journalable. Pure - no I/O.
YUZU_EXPORT JournalReject validate_record(const JournalRecord& r);

// ── Batch (de)serialization ──────────────────────────────────────────────────

/// Serialize a batch to the v:4 JSON envelope. Never throws: entries are assumed
/// already validated (validate_record), and the dump replaces any stray invalid
/// byte rather than throwing (a belt-and-suspenders over validation).
YUZU_EXPORT std::string serialize_journal_batch(std::int64_t ts_ms,
                                                std::span<const JournalRecord> entries);

/// Why a stored batch value could not be parsed back. Either reason → quarantine.
enum class JournalParseError {
    Malformed,      // not JSON, or missing/typewrong required fields
    UnknownVersion, // "v" is present but != kJournalFormatVersion
};

/// Parse a stored batch value. `unexpected` → the caller quarantines the key.
YUZU_EXPORT std::expected<JournalBatch, JournalParseError>
parse_journal_batch(std::string_view json);

} // namespace yuzu::agent
