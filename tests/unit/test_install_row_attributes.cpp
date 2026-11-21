// The shared install-row attribute field (common/include/yuzu/install_row_attributes.hpp, SAM-46):
// the closed key table, the canonical form and its validators. Pure; the agent writer and the
// server parser both include the header, so these are the rules for both ends of the wire.

#include <catch2/catch_test_macros.hpp>

#include <yuzu/install_row_attributes.hpp>

#include <algorithm>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

using namespace yuzu::install_attrs;

namespace {

constexpr const char* kGuid = "{12345678-90AB-CDEF-1234-567890ABCDEF}";
const std::string kField = std::string("upgrade_code=") + kGuid;

bool refused(std::string_view raw) {
    return !canonical_attributes(raw).has_value();
}

} // namespace

TEST_CASE("kAttributeKeys is sorted and unique", "[install_attrs]") {
    // The compile-time guard (static_assert in the header) and the same check at run time.
    static_assert(keys_sorted_and_unique());
    for (std::size_t i = 1; i < kAttributeKeys.size(); ++i)
        CHECK(kAttributeKeys[i - 1].name < kAttributeKeys[i].name);
    for (const auto& k : kAttributeKeys) {
        CHECK_FALSE(k.name.empty());
        CHECK(k.name.find_first_of(";=") == std::string_view::npos);
    }
}

TEST_CASE("a valid upgrade_code round-trips", "[install_attrs]") {
    const auto c = canonical_attributes(kField);
    REQUIRE(c.has_value());
    CHECK(*c == kField);
    CHECK(attribute_value(*c, "upgrade_code") == kGuid);
    // Every hex digit class and the all-zero / all-F extremes are valid.
    CHECK(canonical_attributes("upgrade_code={00000000-0000-0000-0000-000000000000}"));
    CHECK(canonical_attributes("upgrade_code={FFFFFFFF-FFFF-FFFF-FFFF-FFFFFFFFFFFF}"));
}

TEST_CASE("a malformed upgrade_code is refused", "[install_attrs]") {
    // lower-case hex (the canonical spelling is upper-case)
    CHECK(refused("upgrade_code={12345678-90ab-cdef-1234-567890abcdef}"));
    CHECK(refused("upgrade_code={12345678-90AB-cdef-1234-567890ABCDEF}"));
    // missing or misplaced braces
    CHECK(refused("upgrade_code=12345678-90AB-CDEF-1234-567890ABCDEF"));
    CHECK(refused("upgrade_code={12345678-90AB-CDEF-1234-567890ABCDEF"));
    CHECK(refused("upgrade_code=12345678-90AB-CDEF-1234-567890ABCDEF}"));
    CHECK(refused("upgrade_code=(12345678-90AB-CDEF-1234-567890ABCDEF)"));
    // wrong length, hyphens in the wrong place, a non-hex digit
    CHECK(refused("upgrade_code={12345678-90AB-CDEF-1234-567890ABCDE}"));
    CHECK(refused("upgrade_code={12345678-90AB-CDEF-1234-567890ABCDEF0}"));
    CHECK(refused("upgrade_code={1234567-890AB-CDEF-1234-567890ABCDEF}"));
    CHECK(refused("upgrade_code={12345678-90AB-CDEF-1234-567890ABCDEG}"));
    CHECK(refused("upgrade_code={12345678_90AB-CDEF-1234-567890ABCDEF}"));
}

TEST_CASE("an unknown key, a duplicate key, an out-of-order key and an empty key or value are "
          "refused",
          "[install_attrs]") {
    CHECK(refused("unknown=1"));
    CHECK(refused(std::string("aaa=1;") + kField)); // unknown, and out of order's mirror image
    CHECK(refused(kField + ";aaa=1"));              // unknown, and out of order
    CHECK(refused(kField + ";" + kField));          // duplicate (not strictly ascending)
    CHECK(refused("upgrade_code="));                // empty value
    CHECK(refused("=" + std::string(kGuid)));       // empty key
    CHECK(refused("upgrade_code"));                 // no `=`
    CHECK(refused(";"));
    CHECK(refused(";" + kField)); // leading `;`
    CHECK(refused(kField + ";")); // trailing `;`
    CHECK(refused(kField + ";;"));
    CHECK(refused("UPGRADE_CODE=" + std::string(kGuid))); // keys are case-sensitive
}

TEST_CASE("a value holding a separator or a control byte is refused", "[install_attrs]") {
    const std::string base = "upgrade_code=";
    for (const char bad : {';', '=', '\x1f', '\x1e', '\0', '\x01', '\n', '\t', '\x7f'}) {
        CAPTURE(static_cast<int>(bad));
        std::string v = std::string(kGuid);
        v.insert(v.begin() + 5, bad); // inside the value, so the length rule alone cannot be why
        CHECK(refused(base + v));
        // ...and appended to a field that is otherwise canonical.
        CHECK(refused(kField + std::string(1, bad)));
    }
}

TEST_CASE("empty input is canonical and empty", "[install_attrs]") {
    const auto c = canonical_attributes("");
    REQUIRE(c.has_value());
    CHECK(c->empty());
    CHECK(attribute_value("", "upgrade_code").empty());
    const auto m = make_attributes({});
    REQUIRE(m.has_value());
    CHECK(m->empty());
}

TEST_CASE("canonical_attributes is idempotent", "[install_attrs]") {
    for (const std::string& raw : {std::string{}, kField}) {
        const auto once = canonical_attributes(raw);
        REQUIRE(once.has_value());
        const auto twice = canonical_attributes(*once);
        REQUIRE(twice.has_value());
        CHECK(*twice == *once);
        CHECK(*once == raw); // an already-canonical value is returned byte for byte
    }
}

TEST_CASE("an over-long field is refused, but the 1024 cap itself is not observable yet",
          "[install_attrs]") {
    // With one key the longest canonical field is 51 bytes, so every input near the cap is
    // refused by the key or value rules first, whatever the cap says: no input can tell
    // `size() > kMaxAttributesLen` from `>=`, `+ 1` or its removal. Only the constant is pinned
    // here. The boundary pair (a canonical field of exactly kMaxAttributesLen bytes accepted, one
    // byte more refused) arrives with the second key, when a canonical field can reach the cap.
    static_assert(kMaxAttributesLen == 1024);
    CHECK(refused(kField + std::string(kMaxAttributesLen, 'x')));
    CHECK(refused(std::string(kMaxAttributesLen + 1, 'a')));
}

TEST_CASE("attribute_value returns the value or empty", "[install_attrs]") {
    CHECK(attribute_value(kField, "upgrade_code") == kGuid);
    CHECK(attribute_value(kField, "other").empty());
    CHECK(attribute_value(kField, "").empty());
    CHECK(attribute_value("", "upgrade_code").empty());
    // A key that is only a prefix or suffix of a present one does not match.
    CHECK(attribute_value(kField, "upgrade").empty());
    CHECK(attribute_value(kField, "upgrade_code2").empty());
}

TEST_CASE("make_attributes builds the canonical field and refuses what the validator refuses",
          "[install_attrs]") {
    using Pair = std::pair<std::string_view, std::string_view>;
    const Pair good[] = {{"upgrade_code", kGuid}};
    CHECK(make_attributes(good) == kField);
    const Pair bad_value[] = {{"upgrade_code", "{not-a-guid}"}};
    CHECK_FALSE(make_attributes(bad_value));
    const Pair unknown[] = {{"nope", "1"}};
    CHECK_FALSE(make_attributes(unknown));
    const Pair twice[] = {{"upgrade_code", kGuid}, {"upgrade_code", kGuid}};
    CHECK_FALSE(make_attributes(twice));
    const Pair empty_value[] = {{"upgrade_code", ""}};
    CHECK_FALSE(make_attributes(empty_value));
}
