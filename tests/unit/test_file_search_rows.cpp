/**
 * test_file_search_rows.cpp -- the rows, budgets, extents model and user-directory tag of the on-demand
 * file search plugin (agents/plugins/file_search/src/file_search_rows.hpp, file_search_extents.hpp). Pure:
 * strings and numbers only, no OS, no I/O, portable.
 *
 * MUTATION NOTES (each case FAILS if the named production rule is removed):
 *  - arity: adding, dropping or reordering a column of any row kind fails the column counts and the
 *    spelled examples; the definition of the rows (content/definitions/file_search.yaml) is pinned to
 *    these by a later test.
 *  - fiemap_request: setting the sync flag (a write-back of the file's dirty pages) fails flags == 0.
 *  - flag mapping: a bit mapped to the wrong token, or an unmapped bit leaking into the flags, fails the
 *    table; btrfs_logical set on another filesystem fails the non-btrfs rows.
 *  - 32 extents then a count: keeping more than kMaxExtents fails the size check; not counting the extents
 *    past it fails total; a lower bound printed without ">=" fails the lower-bound row.
 *  - user tag: tagging /home itself, /Users/Shared, /var/root (a link on macOS), or not tagging
 *    /private/var/root, /root or a name that merely starts with a prefix fails the table.
 *  - gap path bound: a bound off by one fails the boundary pair.
 *  - constants: any figure changed without the plan changing fails the pin.
 */
#include <catch2/catch_test_macros.hpp>

#include "file_search_extents.hpp"
#include "file_search_rows.hpp"
#include "file_search_state.hpp"
#include "file_search_volumes.hpp"

#include <file_search_coverage.hpp>
#include <file_search_governor.hpp>
#include <row_byte_budget.hpp>

#include <algorithm>
#include <chrono>
#include <string>
#include <vector>

using namespace yuzu::file_search;
using namespace std::chrono_literals;
namespace fsr = yuzu::shared::file_search;

namespace {

std::size_t columns(const std::string& row) {
    return static_cast<std::size_t>(std::count(row.begin(), row.end(), '|')) + 1;
}

} // namespace

TEST_CASE("file_search rows: the arity and spelling of every row kind is pinned",
          "[file_search][file_search_rows]") {
    MatchInfo m;
    m.path = "/home/a b/yuzu-fs-control-1.bin";  // personal-data-ok: synthetic test path
    m.id = {0x1, 0x2};
    m.size = 4096;
    m.mtime = 1700000000;
    m.scope = Scope::user;
    const std::string match = format_match_row(m);
    CHECK(columns(match) == 7);
    CHECK(match == "match|/home/a b/yuzu-fs-control-1.bin|file|0000000000000001:0000000000000002|4096|1700000000|user");  // personal-data-ok: synthetic test path

    MatchInfo d;
    d.path = "/srv/data";
    d.kind = fsr::EntryKind::directory;
    const std::string dir = format_match_row(d);
    CHECK(columns(dir) == 7);
    CHECK(dir == "match|/srv/data|directory|-|-|-|system"); // a directory is never opened: no size, no time

    FileExtents x;
    x.state = ExtentsState::ok;
    x.add({0, 4096, 8192, kShared});
    const std::string ext = format_extents_row({0x1, 0x2}, x);
    CHECK(columns(ext) == 5);
    CHECK(ext == "extents|0000000000000001:0000000000000002|ok|1|0:4096:8192:shared");

    fsr::CoverageEnvelope env;
    env.volumes.push_back({"/", "ext4", fsr::VolumeState::partial, fsr::Reason::budget_time, fsr::Extents::collected, 7});
    env.add_gap({"/x", fsr::GapCause::dir_unreadable});
    env.gaps_dropped = 2;
    env.volumes_dropped = 3;
    const auto cov = fsr::format_coverage_rows(env);
    REQUIRE(cov.size() == 5);
    CHECK(columns(cov[0]) == 7); // volume
    CHECK(columns(cov[1]) == 3); // gap
    CHECK(columns(cov[2]) == 2); // gaps_dropped
    CHECK(columns(cov[3]) == 2); // volumes_dropped
    CHECK(columns(cov[4]) == 5); // coverage
    CHECK(cov[3] == "volumes_dropped|3");
    CHECK(cov[4] == "coverage|partial|slices=1|prior_gaps=0|consistency=single_pass");
}

TEST_CASE("file_search rows: the cursor row and the search trailer", "[file_search][file_search_rows]") {
    CHECK(format_cursor_row("fsv1.0.x") == "cursor|fsv1.0.x");
    CHECK(columns(format_cursor_row("t")) == 2);

    Trailer t;
    t.status = Status::ok;
    t.reason = "budget_time";
    t.semantics = "bytes";
    t.sequence = 3;
    t.query = "0a1b2c3d";
    t.links_skipped = 5;
    const std::string row = format_search_row(t);
    CHECK(columns(row) == 7);
    CHECK(row == "search|ok|budget_time|bytes|seq=3|q=0a1b2c3d|links_skipped=5");

    // a call refused before a query was compiled still has every column
    Trailer bad;
    bad.status = Status::invalid;
    bad.reason = "missing_root";
    CHECK(format_search_row(bad) == "search|invalid|missing_root|-|seq=0|q=-|links_skipped=0");

    const fsr::QueryHash h{0xde, 0xad, 0xbe, 0xef, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12};
    CHECK(query_prefix(h) == "deadbeef");
}

TEST_CASE("file_search rows: every status and fault has one spelling", "[file_search][file_search_rows]") {
    CHECK(std::string(to_token(Status::ok)) == "ok");
    CHECK(std::string(to_token(Status::invalid)) == "invalid");
    CHECK(std::string(to_token(Status::busy)) == "busy");
    CHECK(std::string(to_token(Status::failed)) == "failed");
    CHECK(std::string(to_token(Fault::busy)) == "busy");
    CHECK(std::string(to_token(Fault::timed_out)) == "timed_out");
    CHECK(std::string(to_token(Fault::rejected)) == "rejected");
    CHECK(std::string(to_token(Fault::no_progress)) == "no_progress");
    CHECK(std::string(to_token(Fault::internal_error)) == "internal_error");
    CHECK(std::string(to_token(Fault::cursor_refused)) == "cursor_refused");
}

TEST_CASE("file_search extents: the request carries flags 0 and never the sync flag",
          "[file_search][file_search_rows]") {
    const FiemapRequest r = fiemap_request();
    CHECK(r.flags == 0);
    CHECK(r.start == 0);
    CHECK(r.length == ~std::uint64_t{0});
    CHECK(r.extent_count == kMaxExtents);
    const FiemapRequest c = fiemap_count_request(); // the second request only counts
    CHECK(c.flags == 0);
    CHECK(c.extent_count == 0);
}

TEST_CASE("file_search extents: the flag mapping for both OS legs", "[file_search][file_search_rows]") {
    namespace fm = fiemap_bits;
    struct Row {
        std::uint32_t flags;
        bool btrfs;
        std::uint32_t want;
    };
    const Row rows[] = {
        {0, false, 0},
        {fm::kFmDataInline, false, kResident},
        {fm::kFmDelalloc, false, kDelalloc},
        {fm::kFmShared, false, kShared},
        {fm::kFmEncoded, false, kCompressed},
        {fm::kFmEncrypted, false, kEncrypted},
        {fm::kFmUnwritten, false, kUnwritten},
        {fm::kFmShared | fm::kFmUnwritten, false, kShared | kUnwritten},
        {0, true, kBtrfsLogical},
        {fm::kFmEncoded | fm::kFmShared, true, kCompressed | kShared | kBtrfsLogical},
        // last extent, location unknown, not aligned, tail-packed and merged say nothing the row reports
        {0x1 | 0x2 | 0x100 | 0x400 | 0x1000, false, 0},
    };
    for (const auto& r : rows)
        CHECK(flags_from_fiemap(r.flags, r.btrfs) == r.want);

    CHECK(flags_from_macos(false, false) == 0);
    CHECK(flags_from_macos(true, false) == kUnallocated);
    CHECK(flags_from_macos(false, true) == kShared);
    CHECK(flags_from_macos(true, true) == (kUnallocated | kShared));

    CHECK(format_extent_flags(0) == "-");
    CHECK(format_extent_flags(kResident | kBtrfsLogical) == "resident+btrfs_logical");
    CHECK(format_extent_flags(0xFF) ==
          "resident+delalloc+shared+compressed+encrypted+unwritten+unallocated+btrfs_logical");
}

TEST_CASE("file_search extents: unallocated and compressed states, and 32 extents then a count",
          "[file_search][file_search_rows]") {
    FileExtents hole;
    hole.state = ExtentsState::ok;
    hole.add({0, ~std::uint64_t{0}, 4096, kUnallocated});
    CHECK(format_extents_row({1, 2}, hole) ==
          "extents|0000000000000001:0000000000000002|ok|1|0:18446744073709551615:4096:unallocated");

    FileExtents comp; // a file the filesystem keeps compressed reports no extents at all
    comp.state = ExtentsState::compressed;
    CHECK(format_extents_row({1, 2}, comp) == "extents|0000000000000001:0000000000000002|compressed|0|-");

    FileExtents none;
    none.state = ExtentsState::unsupported;
    CHECK(format_extents_row({1, 2}, none) == "extents|0000000000000001:0000000000000002|unsupported|0|-");
    FileExtents bad;
    bad.state = ExtentsState::failed;
    CHECK(format_extents_row({}, bad) == "extents|-|failed|0|-");

    FileExtents many;
    many.state = ExtentsState::ok;
    for (std::uint64_t i = 0; i < kMaxExtents + 9; ++i)
        many.add({i * 4096, 1'000'000 + i * 4096, 4096, 0});
    CHECK(many.extents.size() == kMaxExtents);
    CHECK(many.total == kMaxExtents + 9);
    const std::string row = format_extents_row({1, 2}, many);
    CHECK(std::count(row.begin(), row.end(), ',') == static_cast<std::ptrdiff_t>(kMaxExtents) - 1);
    CHECK(row.find("|41|") != std::string::npos);

    many.total_exact = false; // a lower bound where the system cannot count without listing
    CHECK(format_extents_row({1, 2}, many).find("|>=41|") != std::string::npos);
}

TEST_CASE("file_search rows: the user-directory tag per OS", "[file_search][file_search_rows]") {
    struct Row {
        const char* path;
        Os os;
        bool user;
    };
    const Row rows[] = {
        {"/home/alice", Os::linux_os, true},
        {"/home/alice/docs/f.txt", Os::linux_os, true},
        {"/home", Os::linux_os, false},
        {"/home/", Os::linux_os, false},
        {"/homestead/x", Os::linux_os, false},
        {"/root", Os::linux_os, true},
        {"/root/.ssh/id", Os::linux_os, true},
        {"/rootfs/x", Os::linux_os, false},
        {"/usr/share/x", Os::linux_os, false},
        {"/Users/alice", Os::macos, true},
        {"/Users/alice/Documents/f", Os::macos, true},
        {"/Users", Os::macos, false},
        {"/Users/Shared", Os::macos, false},
        {"/Users/Shared/f", Os::macos, false},
        {"/Users/SharedFoo/f", Os::macos, true}, // a user whose name starts with "Shared"  // personal-data-ok: synthetic test path
        {"/var/root/f", Os::macos, false},        // /var is a link there: never reached, never tagged
        {"/private/var/root", Os::macos, true},
        {"/private/var/root/f", Os::macos, true},
        {"/private/var/rooted/f", Os::macos, false},
        {"/home/alice", Os::macos, false}, // another platform's rule is not applied
        {"/Users/alice", Os::linux_os, false},
    };
    for (const auto& r : rows) {
        INFO(r.path);
        CHECK(is_user_profile_path(r.path, r.os) == r.user);
    }
    CHECK(std::string(to_token(Scope::user)) == "user");
    CHECK(std::string(to_token(Scope::system)) == "system");
}

TEST_CASE("file_search rows: a gap path over the bound is counted, never emitted",
          "[file_search][file_search_rows]") {
    CHECK(gap_path_fits(std::string(kMaxGapPathBytes, 'a')));
    CHECK_FALSE(gap_path_fits(std::string(kMaxGapPathBytes + 1, 'a')));
    CHECK(gap_path_fits(""));
}

TEST_CASE("file_search rows: the byte budget leaves a reserve a row can never overflow",
          "[file_search][file_search_rows]") {
    // The driver's test for "one more match with its extents might not fit": the walker's second row cap.
    const auto full_at = [](std::size_t used) {
        const yuzu::shared::RowByteBudget budget{.max_bytes = kMatchRowBudget, .bytes = used};
        return !budget.fits(2 * kMaxMatchRowBytes, 0);
    };
    CHECK_FALSE(full_at(0));
    CHECK_FALSE(full_at(kMatchRowBudget - 2 * kMaxMatchRowBytes));
    CHECK(full_at(kMatchRowBudget - 2 * kMaxMatchRowBytes + 1));
    CHECK(full_at(kMatchRowBudget));
    CHECK(full_at(kMatchRowBudget + 1)); // an overcharged budget reads full, never wraps
    CHECK(kMatchRowBudget + kTailReserveBytes == kSliceRowBytes);
}

TEST_CASE("file_search constants: the named budgets hold the values of the plan",
          "[file_search][file_search_rows]") {
    // Code and tests only: the README names a budget, never its figure.
    CHECK(kMaxSlices == 5'000);
    CHECK(kSliceGrace == 5'000ms);
    CHECK(kMaxVolumes == 64);
    CHECK(kMaxPlanMounts == 16'384);
    CHECK(kSliceRowBytes == 8u * 1024 * 1024);
    CHECK(kMaxGapPathBytes == 1'024);
    CHECK(kMaxMatchesPerDirectory == 500);
    CHECK(kMaxExtents == 32);
    CHECK(kMaxAbandoned == 2);
    CHECK(kMaxLineages == 32);
    CHECK(kMaxRootBytes == 4'096);
    CHECK(kMaxVolumePathBytes == 4'096);
    CHECK(kMaxFstypeBytes == 64);
}
