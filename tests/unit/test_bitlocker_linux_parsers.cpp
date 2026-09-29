/**
 * test_bitlocker_linux_parsers.cpp — bitlocker_linux_parsers.hpp (Wave-3
 * native-acquisition migration: libblkid TYPE enumeration + plain
 * /sys/class/block/dm-N/dm/uuid reads, replacing the `lsblk`+`cryptsetup
 * status` shell-outs).
 *
 * Portable and unguarded — pure string/UUID handling, no filesystem I/O,
 * so this TU carries no platform guard and runs on every leg. Fixtures are
 * SYNTHETIC, built to the documented dm-crypt uuid format
 * ("CRYPT-<SUBSYS>-<uuid-no-dashes>-<mapper-name>") — a privileged Docker
 * loopback-LUKS capture was attempted for this migration but no Docker
 * daemon was reachable in the sandbox this was written in (see the
 * migration's commit message).
 */
#include "bitlocker_linux_parsers.hpp"

#include <catch2/catch_test_macros.hpp>

using namespace yuzu::bitlocker::linux_dm;

TEST_CASE("add_uuid_dashes inserts the canonical 8-4-4-4-12 pattern",
          "[agent][bitlocker_linux_parsers]") {
    CHECK(add_uuid_dashes("a1b2c3d4e5f647a1b2c3d4e5f6a7b8c9") ==
          "a1b2c3d4-e5f6-47a1-b2c3-d4e5f6a7b8c9");
}

TEST_CASE("add_uuid_dashes leaves a malformed value unchanged",
          "[agent][bitlocker_linux_parsers]") {
    CHECK(add_uuid_dashes("too-short") == "too-short");
    CHECK(add_uuid_dashes("") == "");
    CHECK(add_uuid_dashes("zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz") ==
          "zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz"); // 32 chars but not hex — never guessed
}

TEST_CASE("parse_dm_uuid decodes a LUKS2 mapping (synthetic fixture)",
          "[agent][bitlocker_linux_parsers]") {
    // Synthetic, built to the documented CRYPT-<SUBSYS>-<uuid>-<name> shape.
    constexpr std::string_view kUuid =
        "CRYPT-LUKS2-a1b2c3d4e5f647a1b2c3d4e5f6a7b8c9-cryptroot\n";
    auto mapping = parse_dm_uuid("dm-0", kUuid);
    REQUIRE(mapping.has_value());
    CHECK(mapping->dm_name == "dm-0");
    CHECK(mapping->luks_version == "LUKS2");
    CHECK(mapping->uuid_no_dashes == "a1b2c3d4e5f647a1b2c3d4e5f6a7b8c9");
    CHECK(mapping->mapper_name == "cryptroot");
}

TEST_CASE("parse_dm_uuid decodes a LUKS1 mapping (synthetic fixture)",
          "[agent][bitlocker_linux_parsers]") {
    constexpr std::string_view kUuid =
        "CRYPT-LUKS1-deadbeefcafebabe0123456789abcdef-luks-home";
    auto mapping = parse_dm_uuid("dm-3", kUuid);
    REQUIRE(mapping.has_value());
    CHECK(mapping->luks_version == "LUKS1");
    CHECK(mapping->uuid_no_dashes == "deadbeefcafebabe0123456789abcdef");
    // Mapper name itself contains a dash ("luks-home") — taken whole, not
    // split further, since only the first two dashes are structural.
    CHECK(mapping->mapper_name == "luks-home");
}

TEST_CASE("parse_dm_uuid returns nullopt for a non-dm-crypt target",
          "[agent][bitlocker_linux_parsers]") {
    // LVM's own dm uuid convention — must not be misread as a CRYPT target.
    CHECK_FALSE(parse_dm_uuid("dm-1", "LVM-abcdef0123456789abcdef0123456789-lv--root").has_value());
}

TEST_CASE("parse_dm_uuid returns a mapping with empty luks_version for a non-LUKS CRYPT target",
          "[agent][bitlocker_linux_parsers]") {
    // A plain (unauthenticated) dm-crypt volume, no LUKS header at all.
    constexpr std::string_view kUuid =
        "CRYPT-PLAIN-00000000000000000000000000000000-swap";
    auto mapping = parse_dm_uuid("dm-2", kUuid);
    REQUIRE(mapping.has_value());
    CHECK(mapping->luks_version.empty()); // not guessed as LUKS1/LUKS2
}

TEST_CASE("parse_dm_uuid returns nullopt for malformed/short input",
          "[agent][bitlocker_linux_parsers]") {
    CHECK_FALSE(parse_dm_uuid("dm-9", "").has_value());
    CHECK_FALSE(parse_dm_uuid("dm-9", "CRYPT-LUKS2").has_value());
    CHECK_FALSE(parse_dm_uuid("dm-9", "CRYPT-LUKS2-notactuallyhex-name").has_value());
    CHECK_FALSE(parse_dm_uuid("dm-9", "CRYPT-LUKS2-a1b2c3d4e5f647a1b2c3d4e5f6a7b8c9-").has_value());
}

TEST_CASE("has_open_mapping matches a blkid-reported dashed UUID against a dashless dm/uuid",
          "[agent][bitlocker_linux_parsers]") {
    LuksBlockDevice device{"sda2", "a1b2c3d4-e5f6-47a1-b2c3-d4e5f6a7b8c9"};
    std::vector<DmCryptMapping> mappings = {
        {"dm-0", "cryptroot", "LUKS2", "a1b2c3d4e5f647a1b2c3d4e5f6a7b8c9"},
    };
    CHECK(has_open_mapping(device, mappings));
}

TEST_CASE("has_open_mapping matches case-insensitively",
          "[agent][bitlocker_linux_parsers]") {
    LuksBlockDevice device{"sda2", "A1B2C3D4-E5F6-47A1-B2C3-D4E5F6A7B8C9"};
    std::vector<DmCryptMapping> mappings = {
        {"dm-0", "cryptroot", "LUKS2", "a1b2c3d4e5f647a1b2c3d4e5f6a7b8c9"},
    };
    CHECK(has_open_mapping(device, mappings));
}

TEST_CASE("has_open_mapping is false when no mapping matches (closed volume)",
          "[agent][bitlocker_linux_parsers]") {
    LuksBlockDevice device{"sdb1", "11111111-2222-3333-4444-555555555555"};
    std::vector<DmCryptMapping> mappings = {
        {"dm-0", "cryptroot", "LUKS2", "a1b2c3d4e5f647a1b2c3d4e5f6a7b8c9"},
    };
    CHECK_FALSE(has_open_mapping(device, mappings));
}

TEST_CASE("has_open_mapping is false against an empty mapping list",
          "[agent][bitlocker_linux_parsers]") {
    LuksBlockDevice device{"sda2", "a1b2c3d4-e5f6-47a1-b2c3-d4e5f6a7b8c9"};
    CHECK_FALSE(has_open_mapping(device, {}));
}

TEST_CASE("format_volume_row keeps the pre-migration 4-token shape",
          "[agent][bitlocker_linux_parsers]") {
    CHECK(format_volume_row("sda2", true) == "volume|sda2|crypto_LUKS|active");
    CHECK(format_volume_row("sda2", false) == "volume|sda2|crypto_LUKS|inactive");
}
