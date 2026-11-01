/**
 * test_log_token.cpp -- the shared log-token neutralisers (common/include/yuzu/log_token.hpp).
 *
 * One mapping core, used on BOTH sides of the Guardian T_wire/T_server id join (log_id_token)
 * and by the server's audit-detail neutraliser (log_token, via audit_token). The tests pin the
 * mapping byte-for-byte because a per-side difference would silently break the join for exactly
 * the ids that need it.
 */

#include "utf8_sanitize.hpp"
#include "web_utils.hpp"

#include <catch2/catch_test_macros.hpp>

#include <yuzu/log_token.hpp>

#include <cstdint>
#include <random>
#include <string>

using yuzu::is_valid_rule_id;
using yuzu::kGuardianLogIdMaxBytes;
using yuzu::kGuardianLogIdTailBytes;
using yuzu::kRuleIdMaxLength;
using yuzu::log_id_token;
using yuzu::log_key_token;
using yuzu::log_token;

namespace {

// Best-effort UTF-8 validity walk over a byte string -- used only to assert log_key_token never
// emits a slice that starts or ends mid multi-byte sequence. Not a general-purpose validator
// (doesn't reject overlong encodings etc.); it only needs to catch what a naive byte-offset cut
// would produce: a lead byte with too few/too many trailing continuation bytes.
bool is_well_formed_utf8(const std::string& s) {
    std::size_t i = 0;
    while (i < s.size()) {
        const unsigned char c = static_cast<unsigned char>(s[i]);
        std::size_t extra = 0;
        if (c < 0x80)
            extra = 0;
        else if ((c & 0xE0) == 0xC0)
            extra = 1;
        else if ((c & 0xF0) == 0xE0)
            extra = 2;
        else if ((c & 0xF8) == 0xF0)
            extra = 3;
        else
            return false; // stray continuation byte or invalid lead byte
        for (std::size_t k = 1; k <= extra; ++k) {
            if (i + k >= s.size())
                return false;
            if ((static_cast<unsigned char>(s[i + k]) & 0xC0) != 0x80)
                return false;
        }
        i += extra + 1;
    }
    return true;
}

} // namespace

TEST_CASE("log_token: ordinary identifiers pass through unchanged", "[log_token]") {
    CHECK(log_token("") == "");
    CHECK(log_token("rule-1") == "rule-1");
    CHECK(log_token("agent-2c82.evt_9:x/y") == "agent-2c82.evt_9:x/y");
    // Bytes >= 0x80 (UTF-8) are not structural for the audit-detail mapping and pass through.
    CHECK(log_token("caf\xC3\xA9") == "caf\xC3\xA9");
}

TEST_CASE("log_token: Unicode line separators and C1 controls fold, one '_' per code point (CH-12)",
          "[log_token]") {
    // U+0085 NEL, U+2028, U+2029: the code points a splitlines()-style reader breaks a line on.
    CHECK(log_token("a\xC2\x85" "b") == "a_b");
    CHECK(log_token("a\xE2\x80\xA8" "b") == "a_b");
    CHECK(log_token("a\xE2\x80\xA9" "b") == "a_b");
    // The whole C1 range U+0080-U+009F folds, both ends included.
    CHECK(log_token("\xC2\x80") == "_");
    CHECK(log_token("\xC2\x9F") == "_");
    // Near misses do NOT fold: U+00A0 (NBSP), U+2027, U+202A, U+00E9, U+20AC.
    CHECK(log_token("\xC2\xA0") == "\xC2\xA0");
    CHECK(log_token("\xE2\x80\xA7") == "\xE2\x80\xA7");
    CHECK(log_token("\xE2\x80\xAA") == "\xE2\x80\xAA");
    CHECK(log_token("caf\xC3\xA9") == "caf\xC3\xA9");
    CHECK(log_token("\xE2\x82\xAC") == "\xE2\x82\xAC");
    CHECK(log_token("\xF0\x9F\x98\x80") == "\xF0\x9F\x98\x80"); // U+1F600, 4 bytes
}

TEST_CASE("log_token: bytes that are not well-formed UTF-8 map to '_' one per byte and the output is "
          "always valid UTF-8 (CH-12)",
          "[log_token]") {
    CHECK(log_token("a\xFF\xFE" "b") == "a__b");           // never valid
    CHECK(log_token("a\x80" "b") == "a_b");                // stray continuation
    CHECK(log_token("a\xC0\xAF" "b") == "a__b");          // overlong '/'
    CHECK(log_token("a\xED\xA0\x80" "b") == "a___b");    // surrogate U+D800
    CHECK(log_token("a\xF5\x80\x80\x80" "b") == "a____b"); // above U+10FFFF
    CHECK(log_token("a\xE2\x82") == "a__");               // truncated 3-byte lead
    CHECK(log_token("a\xE2" "b") == "a_b");                // lead followed by ASCII
    for (const std::string& s : {std::string("a\xFF\xFE" "b\xC0\xAF" "c\xED\xA0\x80" "d\xF5\x80\x80\x80" "e\xE2\x82"),
                                std::string("x\xC2\x85y\xE2\x80\xA8z\xE2\x80\xA9"),
                                std::string("caf\xC3\xA9 \xE2\x82\xAC\xF0\x9F\x98\x80")}) {
        CHECK(is_well_formed_utf8(log_token(s)));
    }
    // log_id_token's pinned output is unchanged: still one '_' per byte >= 0x80.
    CHECK(log_id_token("a\xFF" "b") == "a_b");
    CHECK(log_id_token("a\xE2\x80\xA8" "b") == "a___b");
    CHECK(log_id_token("a\xC2\x85" "b") == "a__b");
    CHECK(log_id_token("caf\xC3\xA9") == "caf__");
}

TEST_CASE("log_token: every structural byte maps to '_'", "[log_token]") {
    CHECK(log_token("a b") == "a_b");
    CHECK(log_token("a=b") == "a_b");
    CHECK(log_token("a,b") == "a_b");
    CHECK(log_token(std::string("a\nb")) == "a_b");
    CHECK(log_token(std::string("a\rb")) == "a_b");
    CHECK(log_token(std::string("a\tb")) == "a_b");
    CHECK(log_token(std::string("a\x7F" "b")) == "a_b");
    CHECK(log_token(std::string("a\0b", 3)) == "a_b"); // embedded NUL
    // The exact forging shape: extra tokens AND a whole second line.
    CHECK(log_token("x agent=victim rule=r\nGuardian T_wire event_id=z") ==
          "x_agent_victim_rule_r_Guardian_T_wire_event_id_z");
    // Boundaries: 0x1F is a control byte, 0x20 is a space, 0x21 is not structural.
    CHECK(log_token(std::string(1, '\x1F')) == "_");
    CHECK(log_token(" ") == "_");
    CHECK(log_token("!") == "!");
}

TEST_CASE("log_id_token: printable ASCII passes, everything else becomes '_'", "[log_token]") {
    CHECK(log_id_token("") == "");
    CHECK(log_id_token("agent-1-r1-1789930557755-5") == "agent-1-r1-1789930557755-5");
    CHECK(log_id_token("rule-1.2:x/y_z~") == "rule-1.2:x/y_z~");
    CHECK(log_id_token("a b=c,d") == "a_b_c_d");
    CHECK(log_id_token(std::string("a\nb\rc\td")) == "a_b_c_d");
    CHECK(log_id_token(std::string("a\0b", 3)) == "a_b");
    CHECK(log_id_token(std::string("a\x7F" "b")) == "a_b");
    // Boundaries: 0x20 (space) maps, 0x21 ('!') and 0x7E ('~') pass, 0x7F maps.
    CHECK(log_id_token(" ") == "_");
    CHECK(log_id_token("!") == "!");
    CHECK(log_id_token("~") == "~");
    // Every byte >= 0x80 maps, so a multi-byte character can neither be cut into invalid UTF-8
    // nor smuggle a Unicode line separator into a line.
    CHECK(log_id_token("caf\xC3\xA9") == "caf__");
    CHECK(log_id_token("a\xE2\x80\xA8" "b") == "a___b"); // U+2028 LINE SEPARATOR
    CHECK(log_id_token("a\xC2\x85" "b") == "a__b");      // U+0085 NEXT LINE
    // The exact forging shape from a hostile rule id.
    CHECK(log_id_token("x agent=victim rule=r\nGuardian T_wire event_id=z") ==
          "x_agent_victim_rule_r_Guardian_T_wire_event_id_z");
}

TEST_CASE("log_id_token: an over-long id keeps its head, a marker and its tail", "[log_token]") {
    constexpr std::size_t kMax = kGuardianLogIdMaxBytes;
    constexpr std::size_t kTail = kGuardianLogIdTailBytes;

    // At or under the cap: untouched.
    const std::string exact(kMax, 'b');
    CHECK(log_id_token(exact) == exact);

    // One byte over: shortened to EXACTLY the cap as head + '~' + the last kTail bytes.
    std::string s;
    for (std::size_t i = 0; i < kMax + 1; ++i)
        s.push_back(static_cast<char>('a' + (i % 26)));
    const std::string t = log_id_token(s);
    REQUIRE(t.size() == kMax);
    CHECK(t.substr(0, kMax - kTail - 1) == s.substr(0, kMax - kTail - 1));
    CHECK(t[kMax - kTail - 1] == '~');
    CHECK(t.substr(kMax - kTail) == s.substr(s.size() - kTail));

    // The tail is what tells two events of one rule apart (`<wall_ms>-<seq>`): two over-long ids
    // that differ only there must NOT collapse onto one token (a plain prefix cut would).
    const std::string head(300, 'r');
    CHECK(log_id_token(head + "-1789930557755-101") != log_id_token(head + "-1789930557755-102"));

    // A multi-byte character straddling the cut cannot leave invalid UTF-8: the result is all ASCII.
    std::string mb(kMax - kTail - 2, 'a');
    mb += "\xC3\xA9"; // straddles the head boundary
    mb.append(200, 'z');
    const std::string m = log_id_token(mb);
    CHECK(m.size() == kMax);
    for (const char c : m)
        CHECK(static_cast<unsigned char>(c) < 0x80);

    // The shared constants themselves (agent and server both use these).
    CHECK(kGuardianLogIdMaxBytes == 256);
    CHECK(kGuardianLogIdTailBytes == 24);
}

TEST_CASE("log_token: audit_token delegates to the same mapping", "[log_token]") {
    // audit_token predates log_token and is the audit-detail neutraliser; it now forwards, so
    // the two cannot drift. Cover every structural class plus a passthrough.
    for (const std::string& s : {std::string("plain"), std::string("a b"), std::string("k=v,k2=v2"),
                                 std::string("x\r\ny"), std::string("\x7F"),
                                 std::string("caf\xC3\xA9")}) {
        CHECK(yuzu::server::audit_token(s) == log_token(s));
    }
}

TEST_CASE("log_key_token: ordinary text, including space/=/,' passes through unchanged",
          "[log_token][log_key_token]") {
    CHECK(log_key_token("") == "");
    CHECK(log_key_token("rule-1") == "rule-1");
    // Unlike log_token/log_id_token, space, '=' and ',' are NOT structural for a '...'-quoted
    // free-text field and must survive -- this is the whole reason the function exists.
    CHECK(log_key_token("C:\\Program Files\\Vendor\\App.exe") ==
          "C:\\Program Files\\Vendor\\App.exe");
    CHECK(log_key_token("HKLM\\SOFTWARE\\Some,Key=Value") == "HKLM\\SOFTWARE\\Some,Key=Value");
    CHECK(log_key_token("a b") == "a b");
    CHECK(log_key_token("a=b") == "a=b");
    CHECK(log_key_token("a,b") == "a,b");
}

TEST_CASE("log_key_token: control bytes and DEL map to '_', bytes >= 0x80 do not",
          "[log_token][log_key_token]") {
    CHECK(log_key_token(std::string("a\nb")) == "a_b");
    CHECK(log_key_token(std::string("a\rb")) == "a_b");
    CHECK(log_key_token(std::string("a\tb")) == "a_b");
    CHECK(log_key_token(std::string(1, '\x1F')) == "_");
    CHECK(log_key_token(std::string("a\0b", 3)) == "a_b"); // embedded NUL
    CHECK(log_key_token(std::string("a\x7F" "b")) == "a_b");
    // An ordinary non-ASCII path/name (no line separators) survives byte-for-byte.
    CHECK(log_key_token("caf\xC3\xA9") == "caf\xC3\xA9");
    CHECK(log_key_token("R\xC3\xA9sum\xC3\xA9.docx") == "R\xC3\xA9sum\xC3\xA9.docx");
}

TEST_CASE("log_key_token: the three Unicode line-separator sequences map to '_'",
          "[log_token][log_key_token]") {
    // U+0085 NEL, UTF-8 `C2 85` -- a Python str.splitlines() break, not covered by log_id_token's
    // blanket >=0x80 mapping being available here (this function keeps >=0x80 bytes otherwise).
    CHECK(log_key_token("a\xC2\x85" "b") == "a_b");
    // U+2028 LINE SEPARATOR, UTF-8 `E2 80 A8`.
    CHECK(log_key_token("a\xE2\x80\xA8" "b") == "a_b");
    // U+2029 PARAGRAPH SEPARATOR, UTF-8 `E2 80 A9`.
    CHECK(log_key_token("a\xE2\x80\xA9" "b") == "a_b");
    // Embedded in a longer, otherwise-ordinary string.
    CHECK(log_key_token("C:\\logs\xC2\x85" "evil.txt") == "C:\\logs_evil.txt");
    CHECK(log_key_token("line1\xE2\x80\xA8" "line2\xE2\x80\xA9" "line3") ==
          "line1_line2_line3");
    // A near-miss must NOT fold: a bare 0x85 continuation byte belonging to a DIFFERENT
    // multi-byte character (not preceded by 0xC2) is not NEL and survives untouched.
    CHECK(log_key_token("\xC3\x85") == "\xC3\x85"); // U+00C5, unrelated to NEL
}

TEST_CASE("log_key_token: over-length input is capped with a UTF-8-aware head~tail cut",
          "[log_token][log_key_token]") {
    constexpr std::size_t kMax = kGuardianLogIdMaxBytes;   // 256
    constexpr std::size_t kTail = kGuardianLogIdTailBytes; // 24
    constexpr std::size_t kHead = kMax - kTail - 1;        // 231, the naive head length

    // At or under the cap: untouched.
    const std::string exact(kMax, 'a');
    CHECK(log_key_token(exact) == exact);

    // Plain over-length ASCII: exactly the cap, head + '~' + tail.
    std::string s;
    for (std::size_t i = 0; i < kMax + 1; ++i)
        s.push_back(static_cast<char>('a' + (i % 26)));
    const std::string t = log_key_token(s);
    REQUIRE(t.size() == kMax);
    CHECK(t.substr(0, kHead) == s.substr(0, kHead));
    CHECK(t[kHead] == '~');
    CHECK(t.substr(kHead + 1) == s.substr(s.size() - kTail));

    // Adversarial case 1: the naive HEAD cut point (byte index kHead == 231) lands on the
    // continuation byte of a 2-byte character whose lead byte is at index kHead - 1. The head
    // boundary must walk BACKWARD off it, shrinking the head by one character (not one byte).
    {
        std::string mb(kHead - 1, 'a'); // indices 0..229
        mb += "\xC3\xA9";               // indices 230 (lead), 231 (continuation) -- the naive cut
        mb.append(100, 'z');            // filler well past the tail window
        REQUIRE(mb.size() > kMax);
        const std::string r = log_key_token(mb);
        CHECK(r.size() <= kMax);
        CHECK(is_well_formed_utf8(r));
        // The whole 2-byte character is excluded from the head (lossy, by design) rather than
        // split: the head ends one byte short of the naive cut.
        CHECK(r.substr(0, kHead - 1) == std::string(kHead - 1, 'a'));
        CHECK(r[kHead - 1] == '~');
        CHECK(r.substr(kHead) == std::string(kTail, 'z'));
    }

    // Adversarial case 2: the naive TAIL start point (byte index size - kTail) lands on the
    // continuation byte of a 2-byte character whose lead byte is the byte just before it. The
    // tail boundary must walk FORWARD off it (never backward -- that would exceed the kTail
    // budget and blow the overall cap).
    {
        constexpr std::size_t kTotal = 300;
        constexpr std::size_t kTailStartNaive = kTotal - kTail; // 276
        std::string mb(kTailStartNaive - 1, 'a');                // indices 0..274
        mb += "\xC3\xA9"; // indices 275 (lead), 276 (continuation) -- the naive tail start
        mb.append(kTotal - mb.size(), 'z');
        REQUIRE(mb.size() == kTotal);
        const std::string r = log_key_token(mb);
        CHECK(r.size() <= kMax);
        CHECK(is_well_formed_utf8(r));
        CHECK(r.substr(0, kHead) == std::string(kHead, 'a'));
        CHECK(r[kHead] == '~');
        // The tail starts one byte later than the naive cut, so it is one byte SHORTER than
        // kTail -- still lossy-by-design, never invalid UTF-8.
        CHECK(r.substr(kHead + 1) == std::string(kTail - 1, 'z'));
    }
}

TEST_CASE("log_key_token: a non-ASCII character clear of both cut points survives truncation "
          "byte-for-byte",
          "[log_token][log_key_token]") {
    // Neither adversarial case above ever leaves a multi-byte character in the output (each one
    // is positioned exactly astride a cut point, so it is always the excluded character). This
    // proves the companion claim the task actually cares about: truncation is UTF-8-*aware*, not
    // UTF-8-*hostile* -- a real accented path component well clear of either boundary comes
    // through untouched in the capped output.
    constexpr std::size_t kMax = kGuardianLogIdMaxBytes;   // 256
    constexpr std::size_t kTail = kGuardianLogIdTailBytes; // 24
    constexpr std::size_t kHead = kMax - kTail - 1;        // 231

    const std::string expected_head = std::string(10, 'a') + "\xC3\xA9" + std::string(219, 'b');
    const std::string expected_tail = std::string(8, 'b') + "\xC3\xA8" + std::string(14, 'z');
    REQUIRE(expected_head.size() == kHead);
    REQUIRE(expected_tail.size() == kTail);

    const std::string mb = std::string(10, 'a') + "\xC3\xA9" /* e-acute, inside the head */ +
                            std::string(272, 'b') +
                            "\xC3\xA8" /* e-grave, inside the tail */ + std::string(14, 'z');
    REQUIRE(mb.size() == 300);

    const std::string r = log_key_token(mb);
    CHECK(r.size() == kMax);
    CHECK(is_well_formed_utf8(r));
    CHECK(r == expected_head + "~" + expected_tail);
}

TEST_CASE("is_valid_rule_id: empty and out-of-charset strings are rejected", "[log_token][rule_id]") {
    CHECK_FALSE(is_valid_rule_id(""));
    CHECK_FALSE(is_valid_rule_id("has space"));
    CHECK_FALSE(is_valid_rule_id("has=equals"));
    CHECK_FALSE(is_valid_rule_id(std::string("has\nnewline")));
    CHECK_FALSE(is_valid_rule_id("caf\xC3\xA9")); // any byte >= 0x80
    CHECK_FALSE(is_valid_rule_id("has,comma"));
    CHECK_FALSE(is_valid_rule_id(std::string("has\0null", 8)));
}

TEST_CASE("is_valid_rule_id: the documented REST/MCP charset is accepted", "[log_token][rule_id]") {
    CHECK(is_valid_rule_id("rule-1"));
    CHECK(is_valid_rule_id("Agent_Rule.42-v2"));
    CHECK(is_valid_rule_id("ABCXYZabcxyz0123456789._-"));
}

TEST_CASE("is_valid_rule_id: length is bounded by kRuleIdMaxLength, boundary inclusive",
          "[log_token][rule_id]") {
    const std::string at_max(kRuleIdMaxLength, 'a');
    CHECK(is_valid_rule_id(at_max));

    const std::string over_max(kRuleIdMaxLength + 1, 'a');
    CHECK_FALSE(is_valid_rule_id(over_max));

    // The constant is its own thing, not a re-export of the log-rendering cap (they happen to
    // share a value today, but a reader must not assume that persists).
    CHECK(kRuleIdMaxLength == 256);
}

namespace {

// Reference model of log_token built ONLY from the server's strict UTF-8 sanitiser
// (server/core/src/utf8_sanitize.hpp, the exact set PostgreSQL accepts) and a code point decode:
// a byte is valid iff it starts a prefix that sanitize_utf8_strict leaves unchanged; the smallest
// such prefix of 2..4 bytes is the one sequence (the lead byte fixes the length).
std::string reference_log_token(const std::string& s) {
    std::string out;
    for (std::size_t i = 0; i < s.size();) {
        const unsigned char c = static_cast<unsigned char>(s[i]);
        if (c < 0x80) {
            const bool structural = c < 0x20 || c == 0x7F || c == ' ' || c == '=' || c == ',';
            out.push_back(structural ? '_' : static_cast<char>(c));
            ++i;
            continue;
        }
        std::size_t len = 0;
        for (std::size_t l = 2; l <= 4 && i + l <= s.size(); ++l) {
            const std::string cand = s.substr(i, l);
            if (yuzu::server::sanitize_utf8_strict(cand) == cand) {
                len = l;
                break;
            }
        }
        if (len == 0) {
            out.push_back('_'); // invalid byte: one '_' per byte
            ++i;
            continue;
        }
        std::uint32_t cp = 0;
        const unsigned char c0 = c;
        if (len == 2)
            cp = ((c0 & 0x1Fu) << 6) | (static_cast<unsigned char>(s[i + 1]) & 0x3Fu);
        else if (len == 3)
            cp = ((c0 & 0x0Fu) << 12) | ((static_cast<unsigned char>(s[i + 1]) & 0x3Fu) << 6) |
                 (static_cast<unsigned char>(s[i + 2]) & 0x3Fu);
        else
            cp = ((c0 & 0x07u) << 18) | ((static_cast<unsigned char>(s[i + 1]) & 0x3Fu) << 12) |
                 ((static_cast<unsigned char>(s[i + 2]) & 0x3Fu) << 6) |
                 (static_cast<unsigned char>(s[i + 3]) & 0x3Fu);
        if ((cp >= 0x80 && cp <= 0x9F) || cp == 0x2028 || cp == 0x2029)
            out.push_back('_');
        else
            out.append(s, i, len);
        i += len;
    }
    return out;
}

} // namespace

TEST_CASE("log_token: classifies UTF-8 validity exactly like sanitize_utf8_strict (differential)",
          "[log_token][differential]") {
    std::size_t mismatches = 0;
    const auto check = [&](const std::string& s) {
        const std::string got = log_token(s);
        if (got != reference_log_token(s) || yuzu::server::sanitize_utf8_strict(got) != got) {
            if (++mismatches <= 5) {
                std::string hex;
                for (const unsigned char ch : s) {
                    static const char* d = "0123456789ABCDEF";
                    hex.push_back(d[ch >> 4]);
                    hex.push_back(d[ch & 15]);
                    hex.push_back(' ');
                }
                FAIL_CHECK("log_token diverges from the reference for bytes: " << hex);
            }
        }
    };

    // Every 1-byte value, every 2-byte sequence.
    for (unsigned a = 0; a < 256; ++a) {
        check(std::string(1, static_cast<char>(a)));
        for (unsigned b = 0; b < 256; ++b)
            check(std::string{static_cast<char>(a), static_cast<char>(b)});
    }
    // Every 3-byte sequence whose lead is 0xE0-0xEF.
    for (unsigned a = 0xE0; a <= 0xEF; ++a)
        for (unsigned b = 0; b < 256; ++b)
            for (unsigned c = 0; c < 256; ++c)
                check(std::string{static_cast<char>(a), static_cast<char>(b), static_cast<char>(c)});

    // A seeded sample of 4-byte sequences, biased to the leads and continuations that matter.
    std::mt19937 rng(0x5EEDC0DEu);
    std::uniform_int_distribution<unsigned> any(0, 255);
    std::uniform_int_distribution<unsigned> lead(0xF0, 0xF7);
    std::uniform_int_distribution<unsigned> cont(0x80, 0xBF);
    for (int n = 0; n < 100000; ++n) {
        const bool plausible = (n % 2) == 0;
        check(std::string{static_cast<char>(lead(rng)),
                          static_cast<char>(plausible ? cont(rng) : any(rng)),
                          static_cast<char>(plausible ? cont(rng) : any(rng)),
                          static_cast<char>(plausible ? cont(rng) : any(rng))});
    }
    // Seeded random short strings mixing ASCII, valid and invalid bytes.
    for (int n = 0; n < 20000; ++n) {
        std::string s;
        const unsigned len = 1 + any(rng) % 12;
        for (unsigned k = 0; k < len; ++k)
            s.push_back(static_cast<char>(any(rng)));
        check(s);
    }
    CHECK(mismatches == 0);
}
