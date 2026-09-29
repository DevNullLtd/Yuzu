#include "guardian_journal_format.hpp"

#include <nlohmann/json.hpp>

#include <format>

namespace yuzu::agent {

namespace {

constexpr std::int64_t kNsPerSec = 1'000'000'000;

// Strict UTF-8 validation, matching (or exceeding) nlohmann's decoder: rejects
// overlong encodings, surrogates, and code points > U+10FFFF. If a field passes
// this, serialize's dump() cannot throw type_error 316 on it - so we never have
// to fall back to byte-replacement (which would flip a replay to a false
// Conflict against the server's byte-exact compare).
bool is_valid_utf8(std::string_view s) {
    const auto* p = reinterpret_cast<const unsigned char*>(s.data());
    const std::size_t n = s.size();
    std::size_t i = 0;
    while (i < n) {
        const unsigned char c = p[i];
        std::size_t extra;
        unsigned char low = 0x80, high = 0xBF; // valid range for the FIRST continuation byte
        if (c < 0x80) {
            ++i;
            continue;
        } else if ((c & 0xE0) == 0xC0) {
            extra = 1;
            if (c < 0xC2) return false; // C0/C1: overlong 2-byte
        } else if ((c & 0xF0) == 0xE0) {
            extra = 2;
            if (c == 0xE0) low = 0xA0;  // overlong 3-byte
            if (c == 0xED) high = 0x9F; // UTF-16 surrogate half
        } else if ((c & 0xF8) == 0xF0) {
            extra = 3;
            if (c == 0xF0) low = 0x90;  // overlong 4-byte
            if (c == 0xF4) high = 0x8F; // > U+10FFFF
            if (c > 0xF4) return false;
        } else {
            return false; // 0x80-0xBF stray continuation, or 0xF5-0xFF
        }
        if (i + extra >= n) return false; // truncated multibyte
        if (p[i + 1] < low || p[i + 1] > high) return false;
        for (std::size_t k = 2; k <= extra; ++k) {
            const unsigned char cc = p[i + k];
            if (cc < 0x80 || cc > 0xBF) return false;
        }
        i += extra + 1;
    }
    return true;
}

// The maximum JSON nesting a legitimate v4 batch reaches is 3 (root object ->
// entries array -> entry object); this cap is far above that but far below the
// stack-recursion depth nlohmann's recursive-descent parser would blow.
constexpr int kMaxJsonDepth = 100;

// Reject pathologically-nested JSON BEFORE handing the value to nlohmann::parse.
// A tampered kv_store.db value with thousands of nested '['/'{' would recurse the
// parser until the stack overflows, which ABORTS the process - NOT a catchable
// throw, so the try/catch firewalls on the replay/prune paths cannot contain it
// (security review). This O(n) single pass tracks depth while skipping brackets
// inside string literals (honouring '\\' escapes). Over-depth -> Malformed ->
// the caller quarantines the batch.
bool within_json_depth_limit(std::string_view json) {
    int depth = 0;
    bool in_string = false;
    bool escaped = false;
    for (const char ch : json) {
        if (in_string) {
            if (escaped)
                escaped = false;
            else if (ch == '\\')
                escaped = true;
            else if (ch == '"')
                in_string = false;
            continue;
        }
        switch (ch) {
        case '"':
            in_string = true;
            break;
        case '[':
        case '{':
            if (++depth > kMaxJsonDepth)
                return false;
            break;
        case ']':
        case '}':
            if (depth > 0)
                --depth;
            break;
        default:
            break;
        }
    }
    return true;
}

// A field is journalable iff it is NUL-free, within the byte cap, and valid
// UTF-8. Returns the specific fault (order: NUL, size, UTF-8) or None.
JournalReject check_field(std::string_view f) {
    if (f.find('\0') != std::string_view::npos) return JournalReject::EmbeddedNul;
    if (f.size() > kMaxJournalFieldBytes) return JournalReject::Oversized;
    if (!is_valid_utf8(f)) return JournalReject::InvalidUtf8;
    return JournalReject::None;
}

} // namespace

std::string journal_batch_key(std::int64_t ts_ms, std::string_view boot_nonce, std::uint64_t seq) {
    // CLAMP, do not pass through. A negative ts (dead RTC reading pre-1970) would emit a '-'
    // and sort before every well-formed key while reversing order among its own kind; a ts
    // past the 13-digit horizon would WIDEN the field and sort after everything. Either breaks
    // the fixed-width property that makes `ORDER BY key` chronological, which retention and
    // replay both now rely on. Both inputs are clock anomalies the retention layer already
    // distrusts (see the future-slack handling in prune), so pinning them to the ends of the
    // representable range is the honest, order-preserving answer. Do NOT "fix" this into a
    // sign-carrying or variable-width key.
    const std::int64_t clamped = ts_ms < 0 ? 0 : (ts_ms > kJournalKeyMaxTsMs ? kJournalKeyMaxTsMs
                                                                            : ts_ms);
    // std::format needs literal widths, so bind them to the constants the PARSER uses.
    // Editing one without the other desynchronises mint from parse, at which point every
    // key fails the strict check and the whole journal self-quarantines.
    static_assert(kJournalKeyTsDigits == 13 && kJournalKeySeqDigits == 12 &&
                      kJournalKeyMaxTsMs == 9'999'999'999'999LL,
                  "the width literals in this format string are hand-written - update them "
                  "together with the constants");
    return std::format("lc:{:013}:{}:{:012}", clamped, boot_nonce, seq);
}

std::optional<std::int64_t> parse_journal_batch_key_ts(std::string_view batch_key) {
    if (!batch_key.starts_with(kBatchKeyPrefix)) return std::nullopt;
    std::string_view rest = batch_key.substr(kBatchKeyPrefix.size());

    // "<ts13>:<nonce>:<seq12>" - widths are exact, not minimums, so a key that parses here
    // is byte-comparable with every other key that parses here.
    const auto ts_digits = static_cast<std::size_t>(kJournalKeyTsDigits);
    const auto seq_digits = static_cast<std::size_t>(kJournalKeySeqDigits);
    if (rest.size() < ts_digits + 1) return std::nullopt;
    if (rest[ts_digits] != ':') return std::nullopt;

    std::int64_t ts = 0;
    for (std::size_t i = 0; i < ts_digits; ++i) {
        const char c = rest[i];
        if (c < '0' || c > '9') return std::nullopt;
        ts = ts * 10 + (c - '0'); // <= kJournalKeyMaxTsMs by construction: cannot overflow
    }

    std::string_view tail = rest.substr(ts_digits + 1); // "<nonce>:<seq12>"
    const auto sep = tail.rfind(':');
    if (sep == std::string_view::npos || sep == 0) return std::nullopt; // no nonce
    const std::string_view nonce = tail.substr(0, sep);
    if (nonce.find(':') != std::string_view::npos) return std::nullopt; // exactly three fields
    const std::string_view seq = tail.substr(sep + 1);
    if (seq.size() != seq_digits) return std::nullopt;
    for (const char c : seq)
        if (c < '0' || c > '9') return std::nullopt;

    return ts;
}

bool looks_like_pre_ts_batch_key(std::string_view batch_key) {
    // "lc:" + a non-empty nonce with no ':' + ':' + exactly 12 digits. Deliberately checked
    // against the OLD shape rather than "not the new shape": arbitrary corruption must not be
    // reported as a format-migration artefact.
    if (!batch_key.starts_with(kBatchKeyPrefix)) return false;
    const std::string_view rest = batch_key.substr(kBatchKeyPrefix.size());
    const auto sep = rest.rfind(':');
    if (sep == std::string_view::npos || sep == 0) return false;
    const std::string_view nonce = rest.substr(0, sep);
    if (nonce.find(':') != std::string_view::npos) return false;
    const std::string_view seq = rest.substr(sep + 1);
    if (seq.size() != static_cast<std::size_t>(kJournalKeySeqDigits)) return false;
    for (const char c : seq)
        if (c < '0' || c > '9') return false;
    return true;
}

// journal_sent_key(nonce, seq) was deleted with the ts-in-key change: a sent-label is only
// ever DERIVED from the batch key it labels (journal_sent_key_from_batch_key), so a second
// mint path could only ever disagree with it.

std::string journal_quarantine_key(std::string_view batch_key) {
    return std::string(kQuarantineKeyPrefix) + std::string(batch_key);
}

std::string journal_batch_key_from_sent_key(std::string_view sent_key) {
    if (sent_key.starts_with(kSentKeyPrefix))
        return std::string(kBatchKeyPrefix) + std::string(sent_key.substr(kSentKeyPrefix.size()));
    return std::string(sent_key);
}

std::string journal_sent_key_from_batch_key(std::string_view batch_key) {
    if (batch_key.starts_with(kBatchKeyPrefix))
        return std::string(kSentKeyPrefix) + std::string(batch_key.substr(kBatchKeyPrefix.size()));
    return std::string(batch_key);
}

JournalReject validate_record(const JournalRecord& r) {
    // Clock first: a skewed-clock record would replay as server-receipt-now and
    // mismatch on timestamp forever (rev-4.1 #2). Mirror set_common's floored
    // seconds so the threshold is byte-identical to what the wire event carries.
    std::int64_t secs = r.enqueued_ns / kNsPerSec;
    if (r.enqueued_ns % kNsPerSec < 0) --secs; // floor toward -inf, as set_common does
    if (secs <= 0) return JournalReject::SkewedClock;

    for (const std::string_view f : {std::string_view{r.rule_id}, std::string_view{r.event_id},
                                     std::string_view{r.kind}, std::string_view{r.guard_type},
                                     std::string_view{r.rule_name}}) {
        if (auto reason = check_field(f); reason != JournalReject::None) return reason;
    }
    return JournalReject::None;
}

std::string serialize_journal_batch(std::int64_t ts_ms, std::span<const JournalRecord> entries) {
    nlohmann::json j;
    j["v"] = kJournalFormatVersion;
    j["ts_ms"] = ts_ms;
    auto& arr = j["entries"] = nlohmann::json::array();
    for (const auto& r : entries) {
        arr.push_back(nlohmann::json{
            {"rule_id", r.rule_id},
            {"generation", r.generation},
            {"event_id", r.event_id},
            {"enqueued_ns", r.enqueued_ns},
            {"kind", r.kind},
            {"guard_type", r.guard_type},
            {"rule_name", r.rule_name},
        });
    }
    // error_handler_t::replace: a belt-and-suspenders over validate_record so a
    // stray invalid byte can never THROW (which would jam every persist retry).
    return j.dump(-1, ' ', false, nlohmann::json::error_handler_t::replace);
}

std::expected<JournalBatch, JournalParseError> parse_journal_batch(std::string_view json) {
    // Guard the recursive-descent parser against a tampered, deeply-nested value that
    // would stack-overflow (an uncatchable abort) before nlohmann even returns.
    if (!within_json_depth_limit(json))
        return std::unexpected(JournalParseError::Malformed);
    auto j = nlohmann::json::parse(json, nullptr, /*allow_exceptions=*/false);
    if (j.is_discarded() || !j.is_object()) return std::unexpected(JournalParseError::Malformed);

    auto vit = j.find("v");
    if (vit == j.end() || !vit->is_number_integer())
        return std::unexpected(JournalParseError::Malformed);
    if (vit->get<int>() != kJournalFormatVersion)
        return std::unexpected(JournalParseError::UnknownVersion);

    JournalBatch batch;
    auto tsit = j.find("ts_ms");
    if (tsit == j.end() || !tsit->is_number_integer())
        return std::unexpected(JournalParseError::Malformed);
    batch.ts_ms = tsit->get<std::int64_t>();

    auto eit = j.find("entries");
    if (eit == j.end() || !eit->is_array()) return std::unexpected(JournalParseError::Malformed);
    // A row larger than a batch can legally be is Malformed, so it is quarantined and counted
    // rather than replayed (#2345 Gate 8 security/UP5-9). persist() never writes one, but the
    // READ boundary is what has to enforce it: an oversized row - a torn write, a hand-edited
    // kv_store.db, a future writer bug - can never fit the send window, which is floored at
    // exactly kMaxJournalEntriesPerBatch. Left to page, such a row blocks on headroom forever
    // and is retried every pass until retention deletes it, having consumed the journal's
    // count and byte budget the whole time.
    //
    // NOTE: this makes kMaxJournalEntriesPerBatch an ON-DISK FORMAT CONTRACT. It may only ever
    // INCREASE: lowering it in a later release would quarantine, and then capacity-shed,
    // audit batches an earlier release wrote legitimately (#2345 Gate 2 security).
    if (eit->size() > kMaxJournalEntriesPerBatch)
        return std::unexpected(JournalParseError::Malformed);

    const auto req_str = [](const nlohmann::json& o, const char* key,
                            std::string& out) -> bool {
        auto it = o.find(key);
        if (it == o.end() || !it->is_string()) return false;
        out = it->get<std::string>();
        return true;
    };

    for (const auto& e : *eit) {
        if (!e.is_object()) return std::unexpected(JournalParseError::Malformed);
        JournalRecord r;
        auto git = e.find("generation");
        auto nsit = e.find("enqueued_ns");
        if (!req_str(e, "rule_id", r.rule_id) || !req_str(e, "event_id", r.event_id) ||
            !req_str(e, "kind", r.kind) || !req_str(e, "guard_type", r.guard_type) ||
            !req_str(e, "rule_name", r.rule_name) || git == e.end() ||
            !git->is_number_integer() || nsit == e.end() || !nsit->is_number_integer())
            return std::unexpected(JournalParseError::Malformed);
        r.generation = git->get<std::uint64_t>();
        r.enqueued_ns = nsit->get<std::int64_t>();
        batch.entries.push_back(std::move(r));
    }
    return batch;
}

} // namespace yuzu::agent
