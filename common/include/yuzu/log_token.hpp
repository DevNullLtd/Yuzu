#pragma once

/**
 * log_token.hpp - neutralise an untrusted identifier before it is embedded in a
 * space-delimited `key=value` log line (CWE-117 log forging).
 *
 * A raw identifier that contains a newline forges a whole physical log line; one that
 * contains a space or '=' forges extra `key=value` tokens on the SAME line, which a
 * first-match parser then reads. Both are reachable from operator-authored rule ids and
 * agent-supplied event ids.
 *
 * Pure decision code (no I/O, no store or wire types, no trust-boundary authority), so it
 * belongs in this shared root (#2549). It is shared, not duplicated, because the Guardian
 * T_wire (agent) and T_server (server) lines are joined on the id: a mapping or cap that
 * differed between the two sides would silently break the join for exactly the ids that need
 * it.
 *
 * Three functions, the first two sharing one ASCII predicate (detail::is_structural_ascii, so it
 * exists once); log_key_token deliberately does NOT call either -- its mapping is
 * narrower (see below) and folding it through log_token's stricter predicate would defeat the
 * point of having a separate, more permissive function:
 *   - log_token(s): control bytes, DEL, space, '=' and ',' -> '_'. A byte >= 0x80 that is part of
 *     a well-formed UTF-8 sequence (no overlong form, no surrogate, nothing above U+10FFFF, the
 *     exact set PostgreSQL's UTF8 accepts) passes through, EXCEPT the sequences a line splitter
 *     treats as a line break, which fold to ONE '_' per code point: the C1 controls U+0080-U+009F
 *     (`C2 80`..`C2 9F`, NEL U+0085 among them), LINE SEPARATOR U+2028 (`E2 80 A8`) and PARAGRAPH
 *     SEPARATOR U+2029 (`E2 80 A9`) -- the same three log_key_token folds, for the same reason
 *     (Python's str.splitlines(), used by the evidence readers, breaks a line on each). A byte
 *     that is not part of a well-formed sequence (a stray continuation byte, an overlong or
 *     surrogate form, a truncated lead) maps to '_' too, one per byte, so the output is ALWAYS
 *     valid UTF-8. No length cap. This is the structured-audit-detail neutraliser (audit_token in
 *     server/core/src/web_utils.hpp forwards to it). The registry plugin's audit line
 *     (registry_parsers.hpp) folds the same code points with the same single '_' by its own
 *     fold_line_breaks, so its output is unchanged.
 *   - log_id_token(s): for an id written to a Guardian log line. Stricter: it applies
 *     log_token's ASCII mapping and maps EVERY byte >= 0x80 to '_', one per byte (so a multi-byte
 *     character can neither be cut mid-sequence into invalid UTF-8 nor smuggle a Unicode line
 *     separator into a line), and an id longer than kGuardianLogIdMaxBytes is shortened to
 *     exactly that length as <head> '~' <last kGuardianLogIdTailBytes bytes> before mapping.
 *     Keeping the tail matters: a Guardian event id ends in `<wall_ms>-<seq>`, the part that
 *     tells two events of one rule apart, so a plain cut would collapse every event of a long
 *     rule id onto one token.
 *   - log_key_token(s): for a path / service-name / registry-key / free-text field embedded
 *     inside a `'...'`-quoted log fragment (e.g. `SparkEngine: armed '<key>'`). Unlike the two
 *     above, it must NOT mangle spaces or non-ASCII bytes -- a real Windows path like
 *     `C:\Program Files\...` or a legitimate non-ASCII name must survive unchanged wherever
 *     possible, which is exactly why log_token/log_id_token are wrong for this use (both map
 *     space to '_'). It maps only control bytes, DEL, and three UTF-8 byte sequences to '_':
 *     NEL (U+0085, `C2 85`), LINE SEPARATOR (U+2028, `E2 80 A8`) and PARAGRAPH SEPARATOR
 *     (U+2029, `E2 80 A9`) -- folded even though they are otherwise-passable bytes >= 0x80,
 *     because Python's str.splitlines(), used by the driver script that reads agent logs as
 *     evidence, treats those three code points as line breaks exactly like '\n'; leaving them
 *     unmapped would let a raw key value still split one physical log line into two. An
 *     over-length key is shortened to kGuardianLogIdMaxBytes the same head '~' tail shape as
 *     log_id_token, but UTF-8-aware at both cut points (see the function body for why the head
 *     and tail boundary walks go in OPPOSITE directions -- getting that backward silently
 *     produces invalid UTF-8 or blows the byte budget).
 *
 * All three are lossy by design, so two different raw inputs CAN share one token. For
 * log_token/log_id_token: "a b" and "a_b"; two long ids that share both their head and their
 * last kGuardianLogIdTailBytes bytes; and, because '~' is an ordinary character, a raw id of
 * exactly kGuardianLogIdMaxBytes bytes that equals the shortened form of a longer one.
 * log_key_token's own mapping is narrower (space, '=' and ',' survive, so "a b" and "a_b" do
 * NOT collide there), but the same three shapes of collision apply to what IT does fold: "a\nb"
 * and "a_b"; two over-length keys sharing head and tail; and a key of exactly
 * kGuardianLogIdMaxBytes bytes that equals another key's shortened form.
 *
 * This header also owns is_valid_rule_id(s): the single shared validation predicate for an
 * operator-authored GuaranteedState rule id (the REST create handler, the MCP create handler,
 * and the agent's apply_rules ingest all call it, so the three accept exactly the same rule
 * ids). It is unrelated to log rendering -- colocated here only because a valid rule id happens
 * to be exactly the byte shape log_key_token/log_id_token never need to fold -- and uses its own
 * length constant (kRuleIdMaxLength), not kGuardianLogIdMaxBytes: the two limits answer
 * different questions (how long an id may be, versus how much of an id survives a log line) and
 * must stay free to diverge even though they share a value today.
 */

#include <cstddef>
#include <string>
#include <string_view>

namespace yuzu {

/// Length every `Guardian T_*` id token is shortened to, on both sides of the join. A single
/// constant: a per-side length breaks the join.
inline constexpr std::size_t kGuardianLogIdMaxBytes = 256;

/// How many bytes of the END of an over-long id survive shortening (the `<wall_ms>-<seq>`
/// suffix of a Guardian event id fits with room to spare).
inline constexpr std::size_t kGuardianLogIdTailBytes = 24;

static_assert(kGuardianLogIdMaxBytes > kGuardianLogIdTailBytes + 1,
              "an over-long id must keep a non-empty head, the marker and the tail");

/// Length (2..4) of the well-formed UTF-8 sequence that starts at s[i], or 0 when the bytes at i
/// are not one. "Well-formed" is exactly what PostgreSQL's UTF8 encoding accepts, the same rules
/// as server/core/src/utf8_sanitize.hpp (not includable here: this root has no server types).
/// Precondition: s[i] >= 0x80.
[[nodiscard]] inline std::size_t utf8_sequence_length(std::string_view s, std::size_t i) noexcept {
    const std::size_t n = s.size();
    const auto cont = [&](std::size_t j) {
        return j < n && (static_cast<unsigned char>(s[j]) & 0xC0) == 0x80;
    };
    const unsigned char c = static_cast<unsigned char>(s[i]);
    const unsigned char c1 = i + 1 < n ? static_cast<unsigned char>(s[i + 1]) : 0;
    if (c >= 0xC2 && c <= 0xDF)
        return cont(i + 1) ? 2 : 0;
    if (c == 0xE0)
        return (c1 >= 0xA0 && c1 <= 0xBF && cont(i + 2)) ? 3 : 0; // overlong 80..9F refused
    if ((c >= 0xE1 && c <= 0xEC) || c == 0xEE || c == 0xEF)
        return (cont(i + 1) && cont(i + 2)) ? 3 : 0;
    if (c == 0xED)
        return (c1 >= 0x80 && c1 <= 0x9F && cont(i + 2)) ? 3 : 0; // surrogates A0..BF refused
    if (c == 0xF0)
        return (c1 >= 0x90 && c1 <= 0xBF && cont(i + 2) && cont(i + 3)) ? 4 : 0;
    if (c >= 0xF1 && c <= 0xF3)
        return (cont(i + 1) && cont(i + 2) && cont(i + 3)) ? 4 : 0;
    if (c == 0xF4)
        return (c1 >= 0x80 && c1 <= 0x8F && cont(i + 2) && cont(i + 3)) ? 4 : 0; // > U+10FFFF refused
    return 0; // 0x80..0xC1 (stray continuation, overlong lead) and 0xF5..0xFF
}

namespace detail {
/// The ASCII bytes log_token and log_id_token both neutralise: control bytes, DEL, space, '='
/// and ','. ONE predicate, so the two mappings cannot drift apart on the ASCII range.
[[nodiscard]] constexpr bool is_structural_ascii(unsigned char c) noexcept {
    return c < 0x20 || c == 0x7F || c == ' ' || c == '=' || c == ',';
}
} // namespace detail

[[nodiscard]] inline std::string log_token(std::string_view s) {
    std::string out;
    out.reserve(s.size());
    for (std::size_t i = 0; i < s.size();) {
        const unsigned char c = static_cast<unsigned char>(s[i]);
        if (c < 0x80) {
            out.push_back(detail::is_structural_ascii(c) ? '_' : static_cast<char>(c));
            ++i;
            continue;
        }
        const std::size_t len = utf8_sequence_length(s, i);
        if (len == 0) { // not part of a well-formed sequence: one '_' for the one byte
            out.push_back('_');
            ++i;
            continue;
        }
        const unsigned char c1 = static_cast<unsigned char>(s[i + 1]);
        // C1 controls U+0080-U+009F (`C2 80`..`C2 9F`) and U+2028 / U+2029 (`E2 80 A8` / `E2 80 A9`).
        const bool folds = (c == 0xC2 && c1 <= 0x9F) ||
                           (c == 0xE2 && c1 == 0x80 &&
                            (static_cast<unsigned char>(s[i + 2]) == 0xA8 ||
                             static_cast<unsigned char>(s[i + 2]) == 0xA9));
        if (folds)
            out.push_back('_'); // one '_' per folded code point, as log_key_token does
        else
            out.append(s.substr(i, len));
        i += len;
    }
    return out;
}

[[nodiscard]] inline std::string log_id_token(std::string_view s) {
    std::string raw;
    if (s.size() > kGuardianLogIdMaxBytes) {
        raw.reserve(kGuardianLogIdMaxBytes);
        raw.append(s.substr(0, kGuardianLogIdMaxBytes - kGuardianLogIdTailBytes - 1));
        raw.push_back('~');
        raw.append(s.substr(s.size() - kGuardianLogIdTailBytes));
    } else {
        raw.assign(s);
    }
    // Byte-wise, deliberately NOT log_token(): every byte >= 0x80 becomes one '_' here, so the
    // output is pure ASCII and as long as the (already shortened) input, whatever log_token does
    // with a code point. The Guardian T_wire/T_server join depends on this staying identical.
    std::string out;
    out.reserve(raw.size());
    for (const unsigned char c : raw)
        out.push_back((c >= 0x80 || detail::is_structural_ascii(c)) ? '_' : static_cast<char>(c));
    return out;
}

[[nodiscard]] inline std::string log_key_token(std::string_view s) {
    // Step 1: fold control bytes / DEL / the three Unicode line-separator byte sequences to
    // '_'. This runs BEFORE the length cap in step 2 (deliberately, not just "it happens to be
    // first"). Safety does not depend on the order: step 2 is itself UTF-8-aware, so it can
    // never split one of the fold sequences (they are ordinary well-formed UTF-8) whichever side
    // of it the fold runs, and a fold can only SHRINK a string, so truncating first could not
    // push the final length over the cap either. The reason to fold first is fidelity, not
    // safety: kGuardianLogIdMaxBytes is meant to describe the length of the rendered token (see
    // this file's own doc comment), and only measuring the cap against the EMITTED bytes -- after
    // folding, not before -- keeps that true. Truncating raw bytes first and folding the
    // survivors afterwards would instead measure the cap against the pre-fold length, letting a
    // run of multi-byte fold matches near the cut collapse the emitted token to well under
    // kGuardianLogIdMaxBytes bytes of real content.
    std::string folded;
    folded.reserve(s.size());
    for (std::size_t i = 0; i < s.size();) {
        const unsigned char c = static_cast<unsigned char>(s[i]);
        // NEL, U+0085, UTF-8 `C2 85`.
        if (c == 0xC2 && i + 1 < s.size() && static_cast<unsigned char>(s[i + 1]) == 0x85) {
            folded.push_back('_');
            i += 2;
            continue;
        }
        // LINE SEPARATOR U+2028 / PARAGRAPH SEPARATOR U+2029, UTF-8 `E2 80 A8` / `E2 80 A9`.
        // (Python's str.splitlines() also treats \x0b \x0c \x1c \x1d \x1e as line breaks; those
        // are all < 0x20 and already folded by the control-byte case below, so they are not a
        // fourth special sequence here.)
        if (c == 0xE2 && i + 2 < s.size() && static_cast<unsigned char>(s[i + 1]) == 0x80 &&
            (static_cast<unsigned char>(s[i + 2]) == 0xA8 ||
             static_cast<unsigned char>(s[i + 2]) == 0xA9)) {
            folded.push_back('_');
            i += 3;
            continue;
        }
        folded.push_back((c < 0x20 || c == 0x7F) ? '_' : static_cast<char>(c));
        ++i;
    }

    if (folded.size() <= kGuardianLogIdMaxBytes)
        return folded;

    // Step 2: same <head> '~' <tail> shape as log_id_token, but UTF-8-aware at both cut points
    // -- this function keeps bytes >= 0x80 (log_id_token doesn't, which is why it can get away
    // with a byte-offset cut), so a naive cut here can slice a multi-byte sequence in half and
    // emit invalid UTF-8.
    const auto is_continuation = [](unsigned char b) { return (b & 0xC0) == 0x80; };

    std::size_t head_len = kGuardianLogIdMaxBytes - kGuardianLogIdTailBytes - 1;
    // folded[head_len] is the first byte EXCLUDED from the head slice [0, head_len). If it's a
    // UTF-8 continuation byte, the slice ends mid-sequence, so walk head_len BACKWARD (shrinking
    // the head) until it lands on a lead byte. Backward is the only safe direction for the head:
    // forward would grow it past the byte budget.
    while (head_len > 0 && is_continuation(static_cast<unsigned char>(folded[head_len])))
        --head_len;

    std::size_t tail_start = folded.size() - kGuardianLogIdTailBytes;
    // folded[tail_start] is the first byte INCLUDED in the tail slice [tail_start, end). If it's
    // a continuation byte, the slice starts mid-sequence, so walk tail_start FORWARD (shrinking
    // the tail) until it lands on a lead byte or the end. Forward, not backward: unlike the head,
    // walking the tail boundary backward would LENGTHEN it past kGuardianLogIdTailBytes and blow
    // the overall kGuardianLogIdMaxBytes budget this function must stay under.
    while (tail_start < folded.size() &&
           is_continuation(static_cast<unsigned char>(folded[tail_start])))
        ++tail_start;

    std::string out;
    out.reserve(kGuardianLogIdMaxBytes);
    out.append(folded, 0, head_len);
    out.push_back('~');
    out.append(folded, tail_start, std::string::npos);
    return out;
}

/// Maximum length of a `GuaranteedState` rule id, enforced by is_valid_rule_id below. A domain
/// decision -- a rule id is a short identifier, not a payload -- independent of (though
/// numerically equal to) kGuardianLogIdMaxBytes, which caps how much of an id survives log
/// rendering; the two constants answer different questions and must stay free to diverge.
inline constexpr std::size_t kRuleIdMaxLength = 256;

/// The single shared validation predicate for an operator-authored `GuaranteedState` rule id --
/// called by the REST create handler, the MCP create handler, and the agent's apply_rules
/// ingest, so all three accept exactly the same rule ids. True only for a non-empty string of
/// kRuleIdMaxLength bytes or fewer where every byte matches `[A-Za-z0-9._-]` (the documented
/// REST/MCP OpenAPI charset `^[A-Za-z0-9._-]+$`). ASCII-only comparison, no locale dependence.
[[nodiscard]] constexpr bool is_valid_rule_id(std::string_view s) {
    if (s.empty() || s.size() > kRuleIdMaxLength)
        return false;
    for (const char ch : s) {
        const unsigned char c = static_cast<unsigned char>(ch);
        const bool alnum =
            (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9');
        if (!alnum && c != '.' && c != '_' && c != '-')
            return false;
    }
    return true;
}

} // namespace yuzu
