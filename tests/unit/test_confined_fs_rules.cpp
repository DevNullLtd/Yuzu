// Pure unit tests for confined_fs_rules.hpp's decide_entry. No filesystem,
// no OS headers -- this file includes ONLY confined_fs_rules.hpp.

#include <yuzu/agent/confined_fs_rules.hpp>

#include <catch2/catch_test_macros.hpp>

#include <cstdint>
#include <limits>

using namespace yuzu::agent::confined_fs;

namespace {

constexpr DeleteLimits kOpenLimits{
    /*max_entries=*/1000,
    /*max_bytes=*/1'000'000,
    /*max_wall=*/std::chrono::milliseconds{60'000},
    /*max_depth=*/32,
    /*max_open_dirs=*/64,
};

constexpr EntryMeta regular_file(std::uint64_t size = 100) {
    return EntryMeta{EntryType::RegularFile, size, /*same_device_as_root=*/true};
}

} // namespace

TEST_CASE("decide_entry rejects a symlink", "[confined_fs]") {
    EntryMeta meta{EntryType::Symlink, 0, true};
    Decision d = decide_entry(meta, kOpenLimits, WalkTally{}, false, false, true);
    REQUIRE(d.action == Action::SkipEntry);
    REQUIRE(d.reason == Reason::SymlinkRejected);
}

TEST_CASE("decide_entry rejects a reparse point/junction", "[confined_fs]") {
    EntryMeta meta{EntryType::Reparse, 0, true};
    Decision d = decide_entry(meta, kOpenLimits, WalkTally{}, false, false, true);
    REQUIRE(d.action == Action::SkipEntry);
    REQUIRE(d.reason == Reason::ReparseRejected);
}

TEST_CASE("decide_entry rejects crossing a device boundary", "[confined_fs]") {
    EntryMeta meta{EntryType::RegularFile, 10, /*same_device_as_root=*/false};
    Decision d = decide_entry(meta, kOpenLimits, WalkTally{}, false, false, true);
    REQUIRE(d.action == Action::SkipEntry);
    REQUIRE(d.reason == Reason::DeviceBoundary);
}

TEST_CASE("decide_entry stops the walk at the entry cap", "[confined_fs]") {
    DeleteLimits limits = kOpenLimits;
    limits.max_entries = 5;
    WalkTally tally{5, 0};
    Decision d = decide_entry(regular_file(), limits, tally, false, false, true);
    REQUIRE(d.action == Action::StopWalk);
    REQUIRE(d.reason == Reason::EntryCap);
}

TEST_CASE("decide_entry skips on the byte cap and a following smaller file still deletes",
          "[confined_fs]") {
    DeleteLimits limits = kOpenLimits;
    limits.max_bytes = 100;
    WalkTally tally{0, 0};

    Decision big = decide_entry(regular_file(500), limits, tally, false, false, true);
    REQUIRE(big.action == Action::SkipEntry);
    REQUIRE(big.reason == Reason::ByteCap);

    // Tally is unaffected by a skipped file (the walker only advances
    // bytes_deleted on success) -- a smaller file that fits still deletes.
    Decision small = decide_entry(regular_file(50), limits, tally, false, false, true);
    REQUIRE(small.action == Action::Unlink);
}

TEST_CASE("decide_entry stops the walk on wall-time exhaustion", "[confined_fs]") {
    Decision d = decide_entry(regular_file(), kOpenLimits, WalkTally{}, /*deadline_exceeded=*/true,
                               false, true);
    REQUIRE(d.action == Action::StopWalk);
    REQUIRE(d.reason == Reason::WallTimeCap);
}

TEST_CASE("decide_entry skips a directory past the depth cap", "[confined_fs]") {
    EntryMeta meta{EntryType::Directory, 0, true};
    Decision d = decide_entry(meta, kOpenLimits, WalkTally{}, false, /*depth_exceeded=*/true, true);
    REQUIRE(d.action == Action::SkipEntry);
    REQUIRE(d.reason == Reason::DepthCap);
}

TEST_CASE("decide_entry recurses into a directory under the depth cap", "[confined_fs]") {
    EntryMeta meta{EntryType::Directory, 0, true};
    Decision d = decide_entry(meta, kOpenLimits, WalkTally{}, false, /*depth_exceeded=*/false, true);
    REQUIRE(d.action == Action::RecurseIntoDir);
    REQUIRE(d.reason == Reason::None);
}

TEST_CASE("decide_entry rejects a non-regular-file entry", "[confined_fs]") {
    EntryMeta meta{EntryType::Other, 0, true};
    Decision d = decide_entry(meta, kOpenLimits, WalkTally{}, false, false, true);
    REQUIRE(d.action == Action::SkipEntry);
    REQUIRE(d.reason == Reason::NotRegularFile);
}

TEST_CASE("decide_entry skips a name the caller's match filtered out", "[confined_fs]") {
    Decision d = decide_entry(regular_file(), kOpenLimits, WalkTally{}, false, false,
                               /*name_matched=*/false);
    REQUIRE(d.action == Action::SkipEntry);
    REQUIRE(d.reason == Reason::NameFilteredOut);
}

TEST_CASE("default-constructed DeleteLimits permits no deletion", "[confined_fs]") {
    DeleteLimits zero{}; // fail-closed default: max_entries == 0
    Decision d = decide_entry(regular_file(1), zero, WalkTally{}, false, false, true);
    REQUIRE(d.action != Action::Unlink);
    REQUIRE(d.action == Action::StopWalk);
    REQUIRE(d.reason == Reason::EntryCap);
}

TEST_CASE("rule order: entry cap beats a symlink discovered past it", "[confined_fs]") {
    DeleteLimits limits = kOpenLimits;
    limits.max_entries = 3;
    WalkTally tally{3, 0};
    EntryMeta symlink{EntryType::Symlink, 0, true};
    Decision d = decide_entry(symlink, limits, tally, false, false, true);
    REQUIRE(d.action == Action::StopWalk);
    REQUIRE(d.reason == Reason::EntryCap);
}

TEST_CASE("rule order: a filtered-out reparse entry still reports ReparseRejected",
          "[confined_fs]") {
    EntryMeta reparse{EntryType::Reparse, 0, true};
    Decision d = decide_entry(reparse, kOpenLimits, WalkTally{}, false, false,
                               /*name_matched=*/false);
    REQUIRE(d.action == Action::SkipEntry);
    REQUIRE(d.reason == Reason::ReparseRejected);
}

TEST_CASE("byte-cap overflow boundary: near-UINT64_MAX size never authorizes Unlink",
          "[confined_fs]") {
    DeleteLimits limits = kOpenLimits;
    limits.max_bytes = 100;
    WalkTally tally{0, 90}; // bytes_deleted near max_bytes

    EntryMeta huge{EntryType::RegularFile, std::numeric_limits<std::uint64_t>::max(), true};
    Decision d = decide_entry(huge, limits, tally, false, false, true);
    REQUIRE(d.action == Action::SkipEntry);
    REQUIRE(d.reason == Reason::ByteCap);
}

TEST_CASE("byte-cap overflow boundary: bytes_deleted already at max_bytes rejects any size",
          "[confined_fs]") {
    DeleteLimits limits = kOpenLimits;
    limits.max_bytes = 100;
    WalkTally tally{0, 100}; // exactly at the cap

    EntryMeta any_size{EntryType::RegularFile, 1, true};
    Decision d = decide_entry(any_size, limits, tally, false, false, true);
    REQUIRE(d.action == Action::SkipEntry);
    REQUIRE(d.reason == Reason::ByteCap);
}

TEST_CASE("byte-cap overflow boundary: bytes_deleted somehow past max_bytes still rejects",
          "[confined_fs]") {
    DeleteLimits limits = kOpenLimits;
    limits.max_bytes = 100;
    WalkTally tally{0, 150}; // defense-in-depth clause: bytes_deleted > max_bytes

    EntryMeta any_size{EntryType::RegularFile, 0, true};
    Decision d = decide_entry(any_size, limits, tally, false, false, true);
    REQUIRE(d.action == Action::SkipEntry);
    REQUIRE(d.reason == Reason::ByteCap);
}

TEST_CASE("byte-cap boundary: exact fit deletes", "[confined_fs]") {
    DeleteLimits limits = kOpenLimits;
    limits.max_bytes = 100;
    WalkTally tally{0, 40};

    EntryMeta exact_fit{EntryType::RegularFile, 60, true};
    Decision d = decide_entry(exact_fit, limits, tally, false, false, true);
    REQUIRE(d.action == Action::Unlink);
}

// ── FILETIME -> Unix seconds ────────────────────────────────────────────────
//
// This conversion is the one piece of arithmetic in the mtime change that can
// be silently WRONG rather than obviously broken: a bad epoch offset or tick
// scale still yields plausible, correctly-ORDERED timestamps that are simply
// off by decades. An age filter built on it would appear to work while
// selecting the wrong files — and this filter gates DELETION.
//
// The fixtures below are anchored on values computable by hand from the two
// constants, so a reviewer can check them without running anything.

TEST_CASE("filetime_to_unix_seconds converts the Unix epoch exactly",
          "[confined_fs][mtime]") {
    // 1970-01-01T00:00:00Z expressed in 100ns ticks since 1601-01-01.
    constexpr std::int64_t kUnixEpochInFiletimeTicks = 116'444'736'000'000'000;
    CHECK(filetime_to_unix_seconds(kUnixEpochInFiletimeTicks) == std::optional<std::int64_t>{0});
}

TEST_CASE("filetime_to_unix_seconds converts a known post-epoch instant",
          "[confined_fs][mtime]") {
    // Exactly one day after the Unix epoch: 86400 seconds.
    constexpr std::int64_t kOneDayTicks = 116'444'736'000'000'000 + 86'400LL * 10'000'000LL;
    CHECK(filetime_to_unix_seconds(kOneDayTicks) == std::optional<std::int64_t>{86'400});

    // A whole non-leap year later.
    constexpr std::int64_t kOneYearTicks =
        116'444'736'000'000'000 + 365LL * 86'400LL * 10'000'000LL;
    CHECK(filetime_to_unix_seconds(kOneYearTicks) == std::optional<std::int64_t>{365LL * 86'400LL});
}

TEST_CASE("filetime_to_unix_seconds reports unset timestamps as unknown, not 1601",
          "[confined_fs][mtime]") {
    // Zero is Windows' "not set". Returning its literal conversion would be
    // -11644473600 (the year 1601), which an age filter reads as impossibly
    // old and therefore SAFE TO DELETE. That is the wrong direction for a
    // destructive action, so it must be indistinguishable from "unknown".
    CHECK_FALSE(filetime_to_unix_seconds(0).has_value());
    CHECK_FALSE(filetime_to_unix_seconds(-1).has_value());
}

TEST_CASE("filetime_to_unix_seconds handles pre-epoch timestamps as negative",
          "[confined_fs][mtime]") {
    // 1969: a real value on filesystems carrying restored or backdated files.
    // It must come back NEGATIVE rather than wrapping to something enormous,
    // so an age comparison still sees it as old.
    constexpr std::int64_t kOneDayBeforeEpoch =
        116'444'736'000'000'000 - 86'400LL * 10'000'000LL;
    CHECK(filetime_to_unix_seconds(kOneDayBeforeEpoch) == std::optional<std::int64_t>{-86'400});
}

TEST_CASE("an unpopulated EntryMeta has NO timestamp, never a misleading one",
          "[confined_fs][mtime]") {
    // The default matters: a consumer filtering on age must not be handed a
    // meta that claims 1970 and therefore reads as infinitely old.
    const EntryMeta fresh{};
    CHECK_FALSE(fresh.mtime.has_value());

    // Three-element aggregate initialisation (the pre-change form, still used
    // throughout the existing tests) must also default the timestamp safely
    // rather than to 0.
    const EntryMeta legacy_shape{EntryType::RegularFile, 42, true};
    CHECK_FALSE(legacy_shape.mtime.has_value());
}

TEST_CASE("decide_entry is UNCHANGED by the presence of a timestamp",
          "[confined_fs][mtime]") {
    // Age is CALLER policy, not primitive policy. decide_entry must reach the
    // same verdict regardless of mtime, or the binding first-match order
    // documented on it would silently have gained a new rule.
    const DeleteLimits limits{.max_entries = 10, .max_bytes = 1000, .max_wall = std::chrono::milliseconds{1000},
                              .max_depth = 4, .max_open_dirs = 4};
    const WalkTally tally{};
    EntryMeta ancient{EntryType::RegularFile, 10, true};
    ancient.mtime = 0;
    EntryMeta brand_new{EntryType::RegularFile, 10, true};
    brand_new.mtime = 4'000'000'000;
    EntryMeta unknown_age{EntryType::RegularFile, 10, true};

    const Decision a = decide_entry(ancient, limits, tally, false, false, true);
    const Decision b = decide_entry(brand_new, limits, tally, false, false, true);
    const Decision c = decide_entry(unknown_age, limits, tally, false, false, true);
    CHECK(a.action == Action::Unlink);
    CHECK(b.action == Action::Unlink);
    CHECK(c.action == Action::Unlink);
    CHECK(a.reason == b.reason);
    CHECK(b.reason == c.reason);
}

// ---- the Windows cloud directory rule (pure: runs on every OS) ----

TEST_CASE("is_cloud_reparse_tag is the cloud FAMILY by mask, never one value", "[confined_fs][cloud]") {
    for (const std::uint32_t tag : {0x9000001Au, 0x9000201Au, 0x9000401Au, 0x9000601Au, 0x9000701Au, 0x9000F01Au})
        CHECK(is_cloud_reparse_tag(tag));
    // every state nibble of the family
    for (std::uint32_t nibble = 0; nibble < 16; ++nibble)
        CHECK(is_cloud_reparse_tag(0x9000001Au | (nibble << 12)));
    // link tags, other families, the neighbours of the mask and no tag at all are not
    for (const std::uint32_t tag : {0xA000000Cu, 0xA0000003u, 0xA000001Du, 0x80000017u, 0x80000013u, 0x8000001Bu,
                                    0x9000001Bu, 0x8000001Au, 0x9001001Au, 0u})
        CHECK_FALSE(is_cloud_reparse_tag(tag));
}

TEST_CASE("reparse_dir_open_allowed admits only a populated cloud directory under the opt-in policy",
          "[confined_fs][cloud]") {
    constexpr auto allow = ReparseDirs::allow_populated_cloud;
    constexpr auto refuse = ReparseDirs::refuse;
    // the measured values: a populated folder 0x410 in sync (0x9000601A) and not in sync (0x9000201A), and
    // a sync-root folder 0x430 (0x9000701A)
    CHECK(reparse_dir_open_allowed(allow, 0x410, 0x9000601Au));
    CHECK(reparse_dir_open_allowed(allow, 0x410, 0x9000201Au));
    CHECK(reparse_dir_open_allowed(allow, 0x430, 0x9000701Au));
    // under the default policy nothing is admitted
    CHECK_FALSE(reparse_dir_open_allowed(refuse, 0x410, 0x9000601Au));
    CHECK_FALSE(reparse_dir_open_allowed(refuse, 0x430, 0x9000701Au));
    // the measured not-populated folder (0x401410: offline and recall on data access) is not admitted
    CHECK_FALSE(reparse_dir_open_allowed(allow, 0x401410, 0x9000001Au));
    CHECK_FALSE(reparse_dir_open_allowed(allow, 0x401410, 0x9000401Au));
    // each recall or offline bit alone refuses
    for (const std::uint32_t bit : {0x40000u, 0x400000u, 0x1000u})
        CHECK_FALSE(reparse_dir_open_allowed(allow, 0x410 | bit, 0x9000601Au));
    // a cloud FILE (no directory bit) is refused
    CHECK_FALSE(reparse_dir_open_allowed(allow, 0x420, 0x9000601Au));
    // every link tag and unknown tag refuses whatever its attributes
    for (const std::uint32_t tag : {0xA000000Cu, 0xA0000003u, 0xA000001Du, 0x80000017u, 0x80000013u, 0x8000001Bu, 0u})
        for (const std::uint32_t attrs : {0x410u, 0x430u, 0x10u, 0x400u})
            CHECK_FALSE(reparse_dir_open_allowed(allow, attrs, tag));
}

TEST_CASE("the cloud rule is a constant expression and the recall mask is exact", "[confined_fs][cloud]") {
    static_assert(noexcept(is_cloud_reparse_tag(0)));
    static_assert(noexcept(reparse_dir_open_allowed(ReparseDirs::refuse, 0, 0)));
    static_assert(is_cloud_reparse_tag(0x9000601Au));
    static_assert(reparse_dir_open_allowed(ReparseDirs::allow_populated_cloud, 0x410, 0x9000601Au));
    static_assert(kAttrRecallOrOffline == 0x00441000u);
    static_assert(kAttrDirectory == 0x10u && kAttrReparsePoint == 0x400u);
    // the opt-in columns of EntryMeta and EnumBudget default to nothing, so every existing consumer is unchanged
    const EntryMeta legacy{EntryType::RegularFile, 1, true};
    CHECK(legacy.file_id == 0);
    CHECK(legacy.attributes == 0);
    CHECK(legacy.reparse_tag == 0);
    CHECK_FALSE(EnumBudget{}.want_file_ids);
}
