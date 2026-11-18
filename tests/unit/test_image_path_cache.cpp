// image_path_cache.hpp: the already-hashed lookup runs BEFORE the helper gate, so once the per-action
// cap of stuck helpers trips, a row whose image this action already hashed keeps its hash instead of
// reading `hash_unavailable:skipped`. It is keyed on image IDENTITY (mount namespace + the device and
// inode of the executable mapping in /proc/<pid>/maps), never on path text: a replaced binary reads
// "<path> (deleted)" with the marker stripped, so old and new image share one path text.

#include "image_path_cache.hpp"

#include <catch2/catch_test_macros.hpp>

#include <string>
#if defined(__linux__)
#include <fstream>
#include <sstream>
#include <sys/stat.h>
#include <sys/sysmacros.h>
#include <unistd.h>
#endif

using yuzu::shared::hash_row_cached;
using yuzu::shared::HelperBudget;
using yuzu::shared::ImagePathCache;
using yuzu::shared::kHashUnavailableSkipped;
using yuzu::shared::kHashUnavailableTimeout;

namespace {
// Two real maps lines from a replaced-binary driver: the old image (unlinked, still running) and the
// live replacement share the path text; only the inode differs.
const std::string kOldMaps =
    "6345f4ab7000-6345f4ab8000 r--p 00000000 00:33 22347080                   /tmp/d/prog (deleted)\n"
    "7f0000000000-7f0000001000 r--p 00000000 08:01 99                         /usr/lib/libc.so.6\n";
const std::string kNewMaps =
    "5b1529aeb000-5b1529aec000 r--p 00000000 00:33 22347851                   /tmp/d/prog\n";
} // namespace

TEST_CASE("ImagePathCache::maps_identity: the executable mapping's device and inode",
          "[image_path_cache][processes]") {
    CHECK(ImagePathCache::maps_identity(kOldMaps, "/tmp/d/prog") == "00:33:22347080");
    CHECK(ImagePathCache::maps_identity(kNewMaps, "/tmp/d/prog") == "00:33:22347851");
    // A path with spaces, an anonymous mapping (inode 0), a different path and off-shape text.
    CHECK(ImagePathCache::maps_identity("1-2 r-xp 0 08:02 7   /opt/my app/bin\n", "/opt/my app/bin") == "08:02:7");
    CHECK(ImagePathCache::maps_identity("1-2 rw-p 0 00:00 0\n", "/x").empty());
    CHECK(ImagePathCache::maps_identity(kNewMaps, "/other").empty());
    CHECK(ImagePathCache::maps_identity("garbage", "/x").empty());
    CHECK(ImagePathCache::maps_identity("", "/x").empty());
}

TEST_CASE("ImagePathCache: same path text, different image identity => different keys and hashes",
          "[image_path_cache][processes]") {
    // The spoofing case: the stripped path text of the old (deleted) and the live image is identical.
    const auto old_id = ImagePathCache::maps_identity(kOldMaps, "/tmp/d/prog");
    const auto new_id = ImagePathCache::maps_identity(kNewMaps, "/tmp/d/prog");
    const auto k_old = ImagePathCache::make_key("mnt:[1]", old_id);
    const auto k_new = ImagePathCache::make_key("mnt:[1]", new_id);
    REQUIRE_FALSE(k_old.empty());
    CHECK(k_old != k_new);
    CHECK(ImagePathCache::make_key("mnt:[1]", old_id) != ImagePathCache::make_key("mnt:[2]", old_id));
    CHECK(ImagePathCache::make_key("", old_id).empty());
    CHECK(ImagePathCache::make_key("mnt:[1]", "").empty());

    ImagePathCache cache;
    // The old image is hashed and cached; with no helper allowed the live replacement must NOT get it.
    CHECK(hash_row_cached(cache, k_old, true, [] { return std::string("old-image-hash"); }) == "old-image-hash");
    CHECK(hash_row_cached(cache, k_new, false, [] { return std::string("never"); }) ==
          std::string{kHashUnavailableSkipped});
    CHECK(hash_row_cached(cache, k_new, true, [] { return std::string("new-image-hash"); }) == "new-image-hash");
    // Each identity keeps its own answer afterwards, with the cap tripped.
    CHECK(hash_row_cached(cache, k_old, false, [] { return std::string("never"); }) == "old-image-hash");
    CHECK(hash_row_cached(cache, k_new, false, [] { return std::string("never"); }) == "new-image-hash");
}

TEST_CASE("ImagePathCache: only real hashes are stored", "[image_path_cache][processes]") {
    ImagePathCache c;
    const auto k = ImagePathCache::make_key("mnt:[1]", "00:33:1");
    c.put(k, "");
    c.put(k, kHashUnavailableTimeout);
    c.put(k, kHashUnavailableSkipped);
    CHECK(c.find(k) == nullptr);
    c.put(k, "abc");
    REQUIRE(c.find(k) != nullptr);
    CHECK(*c.find(k) == "abc");
    CHECK(c.find("") == nullptr);
}

TEST_CASE("hash_row_cached: 400 rows, two stalled images, the cache answers before the cap",
          "[image_path_cache][processes]") {
    // 50 distinct images; images 3 and 7 stall (a timeout marker, one stuck helper each); the budget
    // allows 2 stuck helpers. pid 0..7 run helpers (images 0,1,2,4,5,6 hash; 3 and 7 trip the cap).
    // Afterwards no helper starts: the 8 rows of each hashed image keep their hash from the cache.
    ImagePathCache cache;
    HelperBudget budget{2};
    int skipped = 0, hashed = 0, timeout = 0, computes = 0;
    for (int pid = 0; pid < 400; ++pid) {
        const int image = pid % 50;
        const auto key = ImagePathCache::make_key("mnt:[1]", "00:33:" + std::to_string(1000 + image));
        const std::string h = hash_row_cached(cache, key, budget.may_start(), [&]() -> std::string {
            ++computes;
            if (image == 3 || image == 7) {
                budget.note(yuzu::shared::BoundedCallStatus::TimedOut);
                return std::string{kHashUnavailableTimeout};
            }
            return "hash-of-" + std::to_string(image);
        });
        if (h == kHashUnavailableSkipped)
            ++skipped;
        else if (h == kHashUnavailableTimeout)
            ++timeout;
        else {
            ++hashed;
            CHECK(h == "hash-of-" + std::to_string(image));
        }
    }
    CHECK(computes == 8);
    CHECK(hashed == 6 * 8);
    CHECK(timeout == 2);
    CHECK(skipped == 400 - 6 * 8 - 2);
}

#if defined(__linux__)
TEST_CASE("ImagePathCache::maps_identity: matches stat() of this very process's executable",
          "[image_path_cache][processes][linux]") {
    char buf[4096];
    const auto n = ::readlink("/proc/self/exe", buf, sizeof(buf) - 1);
    REQUIRE(n > 0);
    std::string exe(buf, static_cast<std::size_t>(n));
    constexpr std::string_view kDeleted = " (deleted)";
    if (exe.size() > kDeleted.size() && exe.substr(exe.size() - kDeleted.size()) == kDeleted)
        exe.erase(exe.size() - kDeleted.size());
    struct stat st{};
    REQUIRE(::stat("/proc/self/exe", &st) == 0);
    std::ifstream f("/proc/self/maps");
    std::stringstream ss;
    ss << f.rdbuf();
    const auto id = ImagePathCache::maps_identity(ss.str(), exe);
    REQUIRE_FALSE(id.empty());
    char want[96];
    std::snprintf(want, sizeof(want), "%02x:%02x:%llu", ::major(st.st_dev), ::minor(st.st_dev),
                  static_cast<unsigned long long>(st.st_ino));
    // maps prints major:minor in hex with at least two digits.
    CHECK(id == std::string(want));
}
#endif

TEST_CASE("hash_row_cached: a row that may not start a helper and has no cached answer is skipped",
          "[image_path_cache][processes]") {
    ImagePathCache cache;
    bool ran = false;
    const auto k = ImagePathCache::make_key("m", "00:01:2");
    CHECK(hash_row_cached(cache, k, false, [&]() -> std::string { ran = true; return "x"; }) ==
          std::string{kHashUnavailableSkipped});
    CHECK_FALSE(ran);
    cache.put(k, "good");
    CHECK(hash_row_cached(cache, k, false, [&]() -> std::string { ran = true; return "x"; }) == "good");
    CHECK_FALSE(ran);
}
