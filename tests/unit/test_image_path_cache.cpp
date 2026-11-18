// image_path_cache.hpp: the already-hashed lookup runs BEFORE the helper gate, so once the per-action
// cap of stuck helpers trips, a row whose image this action already hashed keeps its hash instead of
// reading `hash_unavailable:skipped`. It is keyed on image IDENTITY (mount namespace + the device and
// inode of the executable mapping in /proc/<pid>/maps), never on path text: a replaced binary reads
// "<path> (deleted)" with the marker stripped, so old and new image share one path text.

#include "image_path_cache.hpp"

#include <catch2/catch_test_macros.hpp>

#include <algorithm>
#include <cstring>
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
using yuzu::shared::RowHash;

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
    CHECK(ImagePathCache::maps_identity(kOldMaps, "/tmp/d/prog", true) == "00:33:22347080");
    CHECK(ImagePathCache::maps_identity(kNewMaps, "/tmp/d/prog", false) == "00:33:22347851");
    // A path with spaces, an anonymous mapping (inode 0), a different path and off-shape text.
    CHECK(ImagePathCache::maps_identity("1-2 r-xp 0 08:02 7   /opt/my app/bin\n", "/opt/my app/bin", false) == "08:02:7");
    CHECK(ImagePathCache::maps_identity("1-2 rw-p 0 00:00 0\n", "/x", false).empty());
    CHECK(ImagePathCache::maps_identity(kNewMaps, "/other", false).empty());
    CHECK(ImagePathCache::maps_identity("garbage", "/x", false).empty());
    CHECK(ImagePathCache::maps_identity("", "/x", false).empty());
    // The deleted state must match the exe link's: a live exe never takes a "(deleted)" line's
    // inode and a deleted exe never takes a live mapping's.
    CHECK(ImagePathCache::maps_identity(kOldMaps, "/tmp/d/prog", false).empty());
    CHECK(ImagePathCache::maps_identity(kNewMaps, "/tmp/d/prog", true).empty());
}

TEST_CASE("ImagePathCache: same path text, different image identity => different keys and hashes",
          "[image_path_cache][processes]") {
    // The spoofing case: the stripped path text of the old (deleted) and the live image is identical.
    const auto old_id = ImagePathCache::maps_identity(kOldMaps, "/tmp/d/prog", true);
    const auto new_id = ImagePathCache::maps_identity(kNewMaps, "/tmp/d/prog", false);
    const auto k_old = ImagePathCache::make_key("mnt:[1]", old_id);
    const auto k_new = ImagePathCache::make_key("mnt:[1]", new_id);
    REQUIRE_FALSE(k_old.empty());
    CHECK(k_old != k_new);
    CHECK(ImagePathCache::make_key("mnt:[1]", old_id) != ImagePathCache::make_key("mnt:[2]", old_id));
    CHECK(ImagePathCache::make_key("", old_id).empty());
    CHECK(ImagePathCache::make_key("mnt:[1]", "").empty());

    ImagePathCache cache;
    // The old image is hashed and cached; with no helper allowed the live replacement must NOT get it.
    CHECK(hash_row_cached(cache, k_old, true, [] { return RowHash{"old-image-hash", true}; }) == "old-image-hash");
    CHECK(hash_row_cached(cache, k_new, false, [] { return RowHash{"never", true}; }) ==
          std::string{kHashUnavailableSkipped});
    CHECK(hash_row_cached(cache, k_new, true, [] { return RowHash{"new-image-hash", true}; }) == "new-image-hash");
    // Each identity keeps its own answer afterwards, with the cap tripped.
    CHECK(hash_row_cached(cache, k_old, false, [] { return RowHash{"never", true}; }) == "old-image-hash");
    CHECK(hash_row_cached(cache, k_new, false, [] { return RowHash{"never", true}; }) == "new-image-hash");
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
        const std::string h = hash_row_cached(cache, key, budget.may_start(), [&]() -> RowHash {
            ++computes;
            if (image == 3 || image == 7) {
                budget.note(yuzu::shared::BoundedCallStatus::TimedOut);
                return {std::string{kHashUnavailableTimeout}, false};
            }
            return {"hash-of-" + std::to_string(image), true};
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

TEST_CASE("ImagePathCache::maps_identity: conflicting mappings of the same path text are ambiguous",
          "[image_path_cache][processes]") {
    // A deleted executable with a replacement ALSO mapped at the same path text, in either address
    // order: with the deleted flag the live mapping is ignored, so the exe's own inode is returned.
    const std::string both =
        "1000-2000 r--p 0 00:33 22347851  /tmp/d/prog\n"
        "5000-6000 r--p 0 00:33 22347080  /tmp/d/prog (deleted)\n";
    CHECK(ImagePathCache::maps_identity(both, "/tmp/d/prog", true) == "00:33:22347080");
    CHECK(ImagePathCache::maps_identity(both, "/tmp/d/prog", false) == "00:33:22347851");
    // Two DIFFERENT deleted files at the same path text, or two live ones: unknown, whichever comes first.
    const std::string two_deleted =
        "1000-2000 r--p 0 00:33 11  /tmp/d/prog (deleted)\n"
        "5000-6000 r--p 0 00:33 12  /tmp/d/prog (deleted)\n";
    CHECK(ImagePathCache::maps_identity(two_deleted, "/tmp/d/prog", true).empty());
    const std::string reversed =
        "1000-2000 r--p 0 00:33 12  /tmp/d/prog (deleted)\n"
        "5000-6000 r--p 0 00:33 11  /tmp/d/prog (deleted)\n";
    CHECK(ImagePathCache::maps_identity(reversed, "/tmp/d/prog", true).empty());
    // Several mappings of ONE image agree.
    const std::string same =
        "1000-2000 r--p 0 00:33 11  /tmp/d/prog\n"
        "2000-3000 r-xp 1000 00:33 11  /tmp/d/prog\n";
    CHECK(ImagePathCache::maps_identity(same, "/tmp/d/prog", false) == "00:33:11");
}

TEST_CASE("ImagePathCache::read_complete: a whole text, never a prefix", "[image_path_cache][processes]") {
    const std::string text(100000, 'x'); // far beyond one chunk and one old 8 KiB read
    auto reader_for = [&](std::size_t& pos) {
        return [&pos, &text](char* b, std::size_t len) -> long {
            const auto n = std::min(len, text.size() - pos);
            std::memcpy(b, text.data() + pos, n);
            pos += n;
            return static_cast<long>(n);
        };
    };
    const auto never = [] { return false; };
    std::size_t pos = 0;
    auto whole = ImagePathCache::read_complete(reader_for(pos), 1 << 20, never);
    REQUIRE(whole.has_value());
    CHECK(whole->size() == text.size());
    // Over the cap: unknown, not a truncated prefix.
    pos = 0;
    CHECK_FALSE(ImagePathCache::read_complete(reader_for(pos), 50000, never).has_value());
    // A read error mid-way, and an expired deadline: unknown.
    int calls = 0;
    CHECK_FALSE(ImagePathCache::read_complete(
                    [&](char*, std::size_t) -> long { return ++calls == 1 ? 10 : -1; }, 1 << 20, never)
                    .has_value());
    pos = 0;
    CHECK_FALSE(ImagePathCache::read_complete(reader_for(pos), 1 << 20, [] { return true; }).has_value());
    // The exe mapping placed AFTER 8 KiB of other mappings is found from the whole text.
    std::string maps;
    for (int i = 0; i < 200; ++i)
        maps += "1000-2000 r--p 0 08:01 5  /usr/lib/lib" + std::to_string(i) + ".so\n";
    maps += "7000-8000 r--p 0 00:33 77  /opt/app\n";
    REQUIRE(maps.size() > 8192);
    CHECK(ImagePathCache::maps_identity(maps, "/opt/app", false) == "00:33:77");
    CHECK(ImagePathCache::maps_identity(maps.substr(0, 8192), "/opt/app", false).empty()); // a prefix finds nothing
}

TEST_CASE("hash_row_cached: a hash that is not verified against the opened image is never remembered; "
          "a row that may start a helper always hashes for real",
          "[image_path_cache][processes]") {
    ImagePathCache cache;
    const auto k = ImagePathCache::make_key("m", "00:01:2");
    int computes = 0;
    // may_start: the compute runs every time, even with a cached entry (the maps key is never trusted
    // while a real hash is possible).
    cache.put(k, "planted");
    CHECK(hash_row_cached(cache, k, true, [&]() -> RowHash { ++computes; return {"real", false}; }) == "real");
    CHECK(computes == 1);
    // An unverified (not cacheable) result is not stored: the planted entry stays what it was.
    ImagePathCache fresh;
    (void)hash_row_cached(fresh, k, true, [&]() -> RowHash { return {"unverified", false}; });
    CHECK(fresh.find(k) == nullptr);
    (void)hash_row_cached(fresh, k, true, [&]() -> RowHash { return {"verified", true}; });
    REQUIRE(fresh.find(k) != nullptr);
    CHECK(*fresh.find(k) == "verified");
}

#if defined(__linux__)
TEST_CASE("ImagePathCache::maps_identity: matches stat() of this very process's executable",
          "[image_path_cache][processes][linux]") {
    char buf[4096];
    const auto n = ::readlink("/proc/self/exe", buf, sizeof(buf) - 1);
    REQUIRE(n > 0);
    std::string exe(buf, static_cast<std::size_t>(n));
    constexpr std::string_view kDeleted = " (deleted)";
    bool deleted = false;
    if (exe.size() > kDeleted.size() && exe.substr(exe.size() - kDeleted.size()) == kDeleted) {
        exe.erase(exe.size() - kDeleted.size());
        deleted = true;
    }
    struct stat st{};
    REQUIRE(::stat("/proc/self/exe", &st) == 0);
    std::ifstream f("/proc/self/maps");
    std::stringstream ss;
    ss << f.rdbuf();
    const auto id = ImagePathCache::maps_identity(ss.str(), exe, deleted);
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
    CHECK(hash_row_cached(cache, k, false, [&]() -> RowHash { ran = true; return {"x", true}; }) ==
          std::string{kHashUnavailableSkipped});
    CHECK_FALSE(ran);
    cache.put(k, "good");
    CHECK(hash_row_cached(cache, k, false, [&]() -> RowHash { ran = true; return {"x", true}; }) == "good");
    CHECK_FALSE(ran);
}
