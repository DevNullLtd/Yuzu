/**
 * test_file_search_query.cpp -- unit tests for agents/shared/file_search_query.hpp: the leaf-name
 * pattern compiler/matcher and the query hash of the on-demand file search. Pure and portable:
 * no filesystem, process or clock, so it runs unguarded on every OS.
 */
#include <catch2/catch_test_macros.hpp>

#include <file_search_query.hpp>

#include <array>
#include <cstdint>
#include <random>
#include <string>
#include <string_view>

namespace fs = yuzu::shared::file_search;

namespace {
bool accepts(std::string_view p, const fs::NameSemantics& s = fs::byte_exact()) {
    return fs::Pattern::compile(p, s).has_value();
}
fs::PatternError err(std::string_view p) {
    auto r = fs::Pattern::compile(p, fs::byte_exact());
    REQUIRE(!r.has_value());
    return r.error();
}
bool m(std::string_view p, std::string_view name, const fs::NameSemantics& s = fs::byte_exact()) {
    auto r = fs::Pattern::compile(p, s);
    REQUIRE(r.has_value());
    return r->matches(name);
}
fs::Query q(std::string_view p, fs::Kinds k, std::string root,
            const fs::NameSemantics& s = fs::byte_exact()) {
    return fs::Query{*fs::Pattern::compile(p, s), k, std::move(root)};
}
} // namespace

TEST_CASE("file_search pattern: accepted shapes", "[file_search][query]") {
    CHECK(accepts("*.log"));
    CHECK(accepts("conf?g*"));
    CHECK(accepts(std::string(128, 'a')));
    CHECK(accepts("a*b*c*d*efg")); // exactly 4 stars
    CHECK(accepts("abc"));         // exactly 3 literals
    CHECK(accepts("[a]b"));        // '[' and ']' are literals
}

TEST_CASE("file_search pattern: named refusals", "[file_search][query]") {
    CHECK(err("") == fs::PatternError::empty);
    CHECK(err(std::string(129, 'a')) == fs::PatternError::too_long);
    CHECK(err("a*b*c*d*e*fgh") == fs::PatternError::too_many_stars);
    CHECK(err("*a?b*") == fs::PatternError::too_few_literals);
    CHECK(err("abc/def") == fs::PatternError::forbidden_byte);
    CHECK(err(std::string_view("ab\0cd", 5)) == fs::PatternError::forbidden_byte);
    CHECK(err("a**b") == fs::PatternError::too_few_literals);
}

TEST_CASE("file_search pattern: star runs collapse; brackets are literal", "[file_search][query]") {
    const auto a = fs::Pattern::compile("ab**c", fs::byte_exact());
    const auto b = fs::Pattern::compile("ab*c", fs::byte_exact());
    REQUIRE(a);
    REQUIRE(b);
    CHECK(a->canonical() == b->canonical());
    CHECK(a->canonical() == "ab*c");
    CHECK(m("[ab]c", "[ab]c"));
    CHECK_FALSE(m("[ab]c", "ac"));
}

TEST_CASE("file_search matcher: stars, '?' and length", "[file_search][query]") {
    CHECK(m("*.log", "x.log"));
    CHECK(m("*.log", ".log"));
    CHECK_FALSE(m("*.log", "x.logs"));
    CHECK(m("a*bcd", "aXXbcd"));
    CHECK(m("a*bcd", "abcd"));
    CHECK(m("abc*", "abc"));
    CHECK(m("abc*", "abcdef"));
    CHECK_FALSE(m("abc*", "ab"));
    CHECK(m("a*b*cde", "aXbYbcde")); // backtracks past the first 'b'
    CHECK(m("ab?d", "abcd"));
    CHECK_FALSE(m("ab?d", "abd"));
    CHECK_FALSE(m("ab?d", "abccd"));
}

TEST_CASE("file_search matcher: '?' is one scalar, or one byte of a bad sequence",
          "[file_search][query]") {
    CHECK(m("abc?", "abc\xc3\xa9"));         // U+00E9
    CHECK(m("abc?", "abc\xf0\x9f\x98\x80")); // U+1F600
    CHECK(m("abc?", "abc\xc3"));             // truncated lead byte is one byte
    CHECK(m("abc??", "abc\xc3\xff"));        // two invalid bytes, one '?' each
    CHECK_FALSE(m("abc?", "abc\xc3\xff"));   // two bytes cannot fit one '?'
    CHECK_FALSE(m("abc??", "abc\xc3\xa9"));  // a valid scalar is one '?', not two
}

TEST_CASE("file_search matcher: a star may split a scalar so later '?' fit", "[file_search][query]") {
    // '*' empty makes the first '?' swallow the whole scalar and strand the second; the star must
    // take the lead bytes so each '?' consumes one stray byte.
    CHECK(m("abc*??", "abc\xf0\x9f\x98\x80"));
    CHECK(m("abc*??", "abc\xf0\x9f\x98\x80", fs::ascii_case_fold()));
    CHECK(m("abc*?", "abc\xc3\xa9"));
    CHECK_FALSE(m("abc*???", "abc\xc3\xa9")); // only two bytes after abc
}

TEST_CASE("file_search pattern: limits apply to the raw pattern, then the canonical one",
          "[file_search][query]") {
    // An injected canonicaliser that doubles every byte: 128 raw bytes -> 256 canonical (fine);
    // the 512-byte canonical ceiling is 4 * kMaxPatternBytes.
    const auto dbl = [](std::size_t factor) {
        return fs::NameSemantics{"x", [factor](std::string_view s) {
                                     std::string o;
                                     for (const char c : s)
                                         o.append(factor, c);
                                     return o;
                                 }};
    };
    const std::string raw128(128, 'a');
    CHECK(fs::Pattern::compile(raw128, dbl(4)).has_value()); // exactly 512
    const auto over = fs::Pattern::compile(raw128, dbl(5));  // 640 > 512
    REQUIRE(!over.has_value());
    CHECK(over.error() == fs::PatternError::too_long);
    // Validation is on the RAW pattern: 2 raw literals stay refused even if canon expands them,
    // and a raw '/' is refused before canonicalisation can rewrite it away.
    CHECK(fs::Pattern::compile("ab", dbl(4)).error() == fs::PatternError::too_few_literals);
    const fs::NameSemantics slash_eater{"y", [](std::string_view s) {
                                            std::string o(s);
                                            for (auto& c : o)
                                                if (c == '/')
                                                    c = 'x';
                                            return o;
                                        }};
    CHECK(fs::Pattern::compile("abc/def", slash_eater).error() == fs::PatternError::forbidden_byte);
    CHECK(fs::Pattern::compile(std::string(129, 'a'), dbl(1)).error() ==
          fs::PatternError::too_long);
}

TEST_CASE("file_search semantics: ascii fold vs byte exact", "[file_search][query]") {
    CHECK(m("*.txt", "README.TXT", fs::ascii_case_fold()));
    CHECK_FALSE(m("*.txt", "README.TXT"));
    // Non-ASCII bytes are untouched: U+00C9 does not fold to U+00E9.
    CHECK_FALSE(m("caf\xc3\xa9*", "CAF\xc3\x89", fs::ascii_case_fold()));
    CHECK(m("caf\xc3\xa9*", "CAF\xc3\xa9", fs::ascii_case_fold()));
}

TEST_CASE("file_search matcher: worst-case work is bounded", "[file_search][query]") {
    // 4 stars, 128 bytes, adversarial name of one repeated byte (no match at the end).
    std::string pat = "*a*a*a*a" + std::string(119, 'a') + "b";
    REQUIRE(pat.size() == 128);
    const auto p = fs::Pattern::compile(pat, fs::byte_exact());
    REQUIRE(p);
    const std::string name(255, 'a');
    std::size_t steps = 0;
    CHECK_FALSE(p->matches_counted(name, steps));
    CHECK(steps <= (name.size() + 1) * (p->canonical().size() + 1));
    // A name over the canonical cap never matches and costs nothing.
    steps = 0;
    CHECK_FALSE(p->matches_counted(std::string(fs::kMaxCanonicalNameBytes + 1, 'a'), steps));
    CHECK(steps == 0);
}

TEST_CASE("file_search query_hash: stable, field-sensitive, length-prefixed", "[file_search][query]") {
    const auto base = fs::query_hash(q("*.log", fs::Kinds::files, "/var"));
    CHECK(base == fs::query_hash(q("*.log", fs::Kinds::files, "/var")));
    CHECK(base != fs::query_hash(q("*.txt", fs::Kinds::files, "/var")));
    CHECK(base != fs::query_hash(q("*.log", fs::Kinds::files, "/var", fs::ascii_case_fold())));
    CHECK(base != fs::query_hash(q("*.log", fs::Kinds::directories, "/var")));
    CHECK(base != fs::query_hash(q("*.log", fs::Kinds::both, "/var")));
    CHECK(base != fs::query_hash(q("*.log", fs::Kinds::files, "/vat")));
    // Moving a byte across the pattern/root boundary must not collide.
    CHECK(fs::query_hash(q("abc*", fs::Kinds::files, "d")) !=
          fs::query_hash(q("abc*d", fs::Kinds::files, "")));
    CHECK(fs::query_hash(q("abcd", fs::Kinds::files, "ef")) !=
          fs::query_hash(q("abcde", fs::Kinds::files, "f")));
}

TEST_CASE("file_search query_hash: pinned serialisation vectors", "[file_search][query]") {
    // Digests computed independently (Python hashlib) over
    // "yuzu.file_search.query.v1" | u32le len + pattern | u32le len + semantics id | kinds byte |
    // u32le len + root, truncated to the first 16 bytes. Pins domain, field order, little-endian
    // length prefixes, kinds encoding (files=0, directories=1, both=2) and truncation.
    const auto hex = [](const std::array<std::uint8_t, 16>& h) {
        static constexpr char d[] = "0123456789abcdef";
        std::string s;
        for (const auto b : h) {
            s.push_back(d[b >> 4]);
            s.push_back(d[b & 0xF]);
        }
        return s;
    };
    CHECK(hex(fs::query_hash(q("*.log", fs::Kinds::files, "/var"))) ==
          "3004794b182618fbb2b77104aaa0f15d");
    CHECK(hex(fs::query_hash(q("abc*", fs::Kinds::both, "", fs::ascii_case_fold()))) ==
          "8d705f7e091a232521fbb710036e127d");
}

TEST_CASE("file_search: 20000-input sweep never crashes", "[file_search][query]") {
    std::mt19937 rng(0x5EA2C4u);
    const std::string alpha("ab*?[]./\xc3\xa9\xff\x80\xf0\x9f\x98\x80\0AB", 19);
    const auto rnd = [&](std::size_t maxlen) {
        std::string s(rng() % (maxlen + 1), '\0');
        for (auto& c : s)
            c = alpha[rng() % alpha.size()];
        return s;
    };
    std::size_t compiled = 0;
    for (int i = 0; i < 20000; ++i) {
        const std::string pat = rnd(40), name = rnd(60);
        for (const auto& sem : {fs::byte_exact(), fs::ascii_case_fold()}) {
            if (auto p = fs::Pattern::compile(pat, sem)) {
                (void)p->matches(name);
                ++compiled;
            }
        }
    }
    CHECK(compiled > 0);
}
