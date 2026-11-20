/**
 * test_file_search_coverage.cpp -- unit tests for agents/shared/file_search_coverage.hpp: the
 * coverage envelope, its verdict and its row encoding. Pure: no filesystem, process or clock.
 */
#include <catch2/catch_test_macros.hpp>

#include <file_search_coverage.hpp>

#include <set>
#include <string>
#include <utility>
#include <vector>

namespace fs = yuzu::shared::file_search;

namespace {
fs::VolumeCoverage vol(const char* mp, fs::VolumeState st = fs::VolumeState::complete,
                       fs::Reason r = fs::Reason::none) {
    fs::VolumeCoverage v;
    v.mount_point = mp;
    v.fstype = "ext4";
    v.state = st;
    v.reason = r;
    return v;
}
fs::CoverageEnvelope clean() {
    fs::CoverageEnvelope e;
    e.volumes.push_back(vol("/"));
    return e;
}
} // namespace

TEST_CASE("coverage: complete() table", "[file_search][coverage]") {
    CHECK_FALSE(fs::CoverageEnvelope{}.complete()); // zero volumes
    CHECK(clean().complete());

    auto e = clean();
    e.volumes.push_back(vol("/data"));
    CHECK(e.complete());
    e.volumes.push_back(vol("/x", fs::VolumeState::partial, fs::Reason::budget_time));
    CHECK_FALSE(e.complete());

    e = clean();
    e.volumes.push_back(vol("/y", fs::VolumeState::not_searched, fs::Reason::network_mount));
    CHECK_FALSE(e.complete());

    e = clean();
    e.add_gap({"/p", fs::GapCause::depth});
    CHECK_FALSE(e.complete());

    e = clean();
    e.gaps_dropped = 1;
    CHECK_FALSE(e.complete());

    e = clean();
    e.prior_gaps = 1;
    CHECK_FALSE(e.complete());

    e = clean();
    e.has_cursor = true;
    CHECK_FALSE(e.complete());
}

TEST_CASE("coverage: valid() pairs state with reason", "[file_search][coverage]") {
    CHECK(fs::CoverageEnvelope{}.valid());
    CHECK(clean().valid());

    fs::CoverageEnvelope e;
    e.volumes.push_back(vol("/", fs::VolumeState::complete, fs::Reason::budget_time));
    CHECK_FALSE(e.valid());
    e.volumes = {vol("/", fs::VolumeState::partial, fs::Reason::none)};
    CHECK_FALSE(e.valid());
    e.volumes = {vol("/", fs::VolumeState::not_searched, fs::Reason::none)};
    CHECK_FALSE(e.valid());
    e.volumes = {vol("/", fs::VolumeState::partial, fs::Reason::budget_entries),
                 vol("/m", fs::VolumeState::not_searched, fs::Reason::unsupported)};
    CHECK(e.valid());
}

TEST_CASE("coverage: exact rows for two volumes and two gaps", "[file_search][coverage]") {
    fs::CoverageEnvelope e;
    e.volumes.push_back(vol("/"));
    e.volumes.back().entries = 42;
    auto v2 = vol("/mnt/nas", fs::VolumeState::not_searched, fs::Reason::network_mount);
    v2.fstype = "nfs";
    v2.extents = fs::Extents::unsupported;
    e.volumes.push_back(v2);
    e.add_gap({"/a/deep", fs::GapCause::depth});
    e.add_gap({"/b", fs::GapCause::permission_denied});

    const std::vector<std::string> want{
        "volume|/|ext4|complete|none|extents=not_collected|entries=42",
        "volume|/mnt/nas|nfs|not_searched|network_mount|extents=unsupported|entries=0",
        "gap|/a/deep|depth",
        "gap|/b|permission_denied",
        "coverage|partial|slices=1|prior_gaps=0|consistency=single_pass"};
    CHECK(fs::format_coverage_rows(e) == want);
}

TEST_CASE("coverage: hostile names round-trip through decode_name", "[file_search][coverage]") {
    const std::string mp = std::string("/a|b\nc\xff") + "d";
    const std::string path = std::string("/p|q\r\n\xc3(") + "z";
    fs::CoverageEnvelope e;
    e.volumes.push_back(vol(mp.c_str()));
    e.volumes.push_back(vol("/z"));
    e.add_gap({path, fs::GapCause::dir_unreadable});
    const auto rows = fs::format_coverage_rows(e);
    REQUIRE(rows.size() == 4);
    CHECK(rows.back().rfind("coverage|", 0) == 0);

    auto field = [](const std::string& row, std::size_t n) {
        std::size_t b = 0;
        for (; n > 0; --n)
            b = row.find('|', b) + 1;
        return row.substr(b, row.find('|', b) - b);
    };
    for (const auto& r : rows)
        CHECK(r.find('\n') == std::string::npos);
    CHECK(fs::decode_name(field(rows[0], 1)) == mp);
    CHECK(fs::decode_name(field(rows[2], 1)) == path);
}

TEST_CASE("coverage: consistency and cumulative verdict", "[file_search][coverage]") {
    auto e = clean();
    CHECK(fs::format_coverage_rows(e).back() ==
          "coverage|complete|slices=1|prior_gaps=0|consistency=single_pass");
    e.slices = 2;
    CHECK(fs::format_coverage_rows(e).back() ==
          "coverage|complete|slices=2|prior_gaps=0|consistency=not_a_snapshot");
    e = clean();
    e.has_cursor = true; // slice 1 of a search that leaves a cursor is already not a snapshot
    CHECK(fs::format_coverage_rows(e).back() ==
          "coverage|partial|slices=1|prior_gaps=0|consistency=not_a_snapshot");

    e = clean();
    e.prior_gaps = 1; // no gap of its own in this slice
    CHECK(e.gaps.empty());
    CHECK(fs::format_coverage_rows(e).back() ==
          "coverage|partial|slices=1|prior_gaps=1|consistency=single_pass");
}

TEST_CASE("coverage: add_gap caps at kMaxGaps", "[file_search][coverage]") {
    auto e = clean();
    for (std::size_t i = 0; i < fs::kMaxGaps + 5; ++i)
        e.add_gap({"/g" + std::to_string(i), fs::GapCause::dir_truncated});
    CHECK(e.gaps.size() == fs::kMaxGaps);
    CHECK(e.gaps_dropped == 5);
    CHECK_FALSE(e.complete());
    const auto rows = fs::format_coverage_rows(e);
    CHECK(rows[rows.size() - 2] == "gaps_dropped|5");
    CHECK(rows.back().rfind("coverage|partial|", 0) == 0);
}

TEST_CASE("coverage: tokens are distinct and the shared gap tokens are exact",
          "[file_search][coverage]") {
    using fs::GapCause;
    std::set<std::string> s;
    for (auto c : {GapCause::depth, GapCause::dir_unreadable, GapCause::dir_truncated,
                   GapCause::other_device, GapCause::network_mount, GapCause::memory_cap,
                   GapCause::permission_denied, GapCause::dataless, GapCause::private_namespace,
                   GapCause::name_too_long})
        s.insert(fs::to_token(c));
    CHECK(s.size() == 10);
    CHECK(std::string(fs::to_token(GapCause::name_too_long)) == "name_too_long");
    CHECK(std::string(fs::to_token(GapCause::depth)) == "depth");
    CHECK(std::string(fs::to_token(GapCause::dir_unreadable)) == "dir_unreadable");
    CHECK(std::string(fs::to_token(GapCause::dir_truncated)) == "dir_truncated");
    CHECK(std::string(fs::to_token(GapCause::other_device)) == "other_device");
    CHECK(std::string(fs::to_token(GapCause::network_mount)) == "network_mount");
    CHECK(std::string(fs::to_token(GapCause::memory_cap)) == "memory_cap");

    using fs::Reason;
    std::set<std::string> r;
    for (auto x : {Reason::none, Reason::budget_entries, Reason::budget_time, Reason::budget_rows,
                   Reason::cancelled, Reason::fstype_not_allowed, Reason::network_mount,
                   Reason::mount_table_unreadable, Reason::permission_denied,
                   Reason::private_namespace, Reason::other_device, Reason::stalled,
                   Reason::unstable, Reason::unsupported})
        r.insert(fs::to_token(x));
    CHECK(r.size() == 14);

    std::set<std::string> v{fs::to_token(fs::VolumeState::complete),
                            fs::to_token(fs::VolumeState::partial),
                            fs::to_token(fs::VolumeState::not_searched),
                            fs::to_token(fs::Extents::not_collected),
                            fs::to_token(fs::Extents::collected),
                            fs::to_token(fs::Extents::unsupported)};
    CHECK(v.size() == 6);
}

TEST_CASE("coverage: a volume that is complete while naming a reason reads partial", "[file_search][coverage]") {
    fs::CoverageEnvelope e;
    e.volumes.push_back(vol("/", fs::VolumeState::complete, fs::Reason::budget_time)); // contradicts itself
    REQUIRE_FALSE(e.valid());
    CHECK_FALSE(e.complete());
    CHECK(fs::format_coverage_rows(e).back().rfind("coverage|partial|", 0) == 0);
    // the opposite contradiction: a partial volume that names no reason
    e.volumes = {vol("/", fs::VolumeState::partial, fs::Reason::none)};
    CHECK_FALSE(e.complete());
}

TEST_CASE("coverage: volumes the plan dropped make the verdict partial and are counted in a row",
          "[file_search][coverage]") {
    auto e = clean();
    REQUIRE(e.complete());
    e.volumes_dropped = 3;
    CHECK_FALSE(e.complete());
    const auto rows = fs::format_coverage_rows(e);
    REQUIRE(rows.size() == 3);
    CHECK(rows[1] == "volumes_dropped|3");
    CHECK(rows.back().rfind("coverage|partial|", 0) == 0);
    e.volumes_dropped = 0;
    CHECK(fs::format_coverage_rows(e).size() == 2); // no row for none
}

TEST_CASE("coverage: every reason and gap cause is spelled, and the shared tokens are equal",
          "[file_search][coverage]") {
    using fs::GapCause;
    using fs::Reason;
    const std::vector<std::pair<Reason, const char*>> reasons = {
        {Reason::none, "none"},
        {Reason::budget_entries, "budget_entries"},
        {Reason::budget_time, "budget_time"},
        {Reason::budget_rows, "budget_rows"},
        {Reason::cancelled, "cancelled"},
        {Reason::fstype_not_allowed, "fstype_not_allowed"},
        {Reason::network_mount, "network_mount"},
        {Reason::mount_table_unreadable, "mount_table_unreadable"},
        {Reason::permission_denied, "permission_denied"},
        {Reason::private_namespace, "private_namespace"},
        {Reason::other_device, "other_device"},
        {Reason::stalled, "stalled"},
        {Reason::unstable, "unstable"},
        {Reason::unsupported, "unsupported"},
        {Reason::duplicate_mount, "duplicate_mount"},
        {Reason::behind_network_mount, "behind_network_mount"},
        {Reason::max_slices, "max_slices"},
        {Reason::mount_table_changed, "mount_table_changed"},
        {Reason::firmlinks_only, "firmlinks_only"},
    };
    std::set<std::string> seen;
    for (const auto& [r, token] : reasons) {
        CHECK(std::string(fs::to_token(r)) == token);
        seen.insert(token);
    }
    CHECK(seen.size() == reasons.size());

    const std::vector<std::pair<GapCause, const char*>> causes = {
        {GapCause::depth, "depth"},
        {GapCause::dir_unreadable, "dir_unreadable"},
        {GapCause::dir_truncated, "dir_truncated"},
        {GapCause::other_device, "other_device"},
        {GapCause::network_mount, "network_mount"},
        {GapCause::memory_cap, "memory_cap"},
        {GapCause::permission_denied, "permission_denied"},
        {GapCause::dataless, "dataless"},
        {GapCause::private_namespace, "private_namespace"},
        {GapCause::name_too_long, "name_too_long"},
        {GapCause::match_cap, "match_cap"},
    };
    std::set<std::string> gaps;
    for (const auto& [c, token] : causes) {
        CHECK(std::string(fs::to_token(c)) == token);
        gaps.insert(token);
    }
    CHECK(gaps.size() == causes.size());

    // the one vocabulary: where a reason and a gap cause mean the same, they are spelled the same
    CHECK(std::string(fs::to_token(Reason::network_mount)) == fs::to_token(GapCause::network_mount));
    CHECK(std::string(fs::to_token(Reason::permission_denied)) == fs::to_token(GapCause::permission_denied));
    CHECK(std::string(fs::to_token(Reason::private_namespace)) == fs::to_token(GapCause::private_namespace));
    CHECK(std::string(fs::to_token(Reason::other_device)) == fs::to_token(GapCause::other_device));
}
