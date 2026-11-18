// image_path_cache.hpp: the already-hashed lookup runs BEFORE the helper gate, so once the per-action
// cap of stuck helpers trips, a row whose image this action already hashed keeps its hash instead of
// reading `hash_unavailable:skipped` (a local user with two stalled images could otherwise blank the
// hash column for every later row).

#include "image_path_cache.hpp"

#include <catch2/catch_test_macros.hpp>

#include <string>

using yuzu::shared::hash_row_cached;
using yuzu::shared::HelperBudget;
using yuzu::shared::ImagePathCache;
using yuzu::shared::kHashUnavailableSkipped;
using yuzu::shared::kHashUnavailableTimeout;

TEST_CASE("ImagePathCache: key needs a namespace and a path; only real hashes are stored",
          "[image_path_cache][processes]") {
    CHECK(ImagePathCache::make_key("", "/bin/x").empty());
    CHECK(ImagePathCache::make_key("mnt:[1]", "").empty());
    CHECK(ImagePathCache::make_key("mnt:[1]", "/bin/x") != ImagePathCache::make_key("mnt:[2]", "/bin/x"));
    ImagePathCache c;
    const auto k = ImagePathCache::make_key("mnt:[1]", "/bin/x");
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
    // 50 distinct images; images 3 and 7 stall (a timeout marker, one stuck helper each). The
    // budget allows 2 stuck helpers. Rows are visited in pid order, so the cap trips at the second
    // stalled image; every row that shares an image already hashed must still read its hash.
    ImagePathCache cache;
    HelperBudget budget{2};
    int skipped = 0, hashed = 0, timeout = 0, computes = 0;
    for (int pid = 0; pid < 400; ++pid) {
        const int image = pid % 50;
        const std::string path = "/opt/img" + std::to_string(image);
        const auto key = ImagePathCache::make_key("mnt:[1]", path);
        const std::string h = hash_row_cached(cache, key, budget.may_start(), [&]() -> std::string {
            ++computes;
            if (image == 3 || image == 7) {
                budget.note(yuzu::shared::BoundedCallStatus::TimedOut);
                return std::string{kHashUnavailableTimeout};
            }
            return "hash-of-" + path;
        });
        if (h == kHashUnavailableSkipped)
            ++skipped;
        else if (h == kHashUnavailableTimeout)
            ++timeout;
        else {
            ++hashed;
            CHECK(h == "hash-of-" + path);
        }
    }
    // pid 0..7 run helpers (images 0,1,2,4,5,6 hash; images 3 and 7 stall and trip the cap of 2).
    // Afterwards no helper starts: the 8 rows of each of the six hashed images keep their hash from
    // the cache, the two stalled images and every image first seen after the cap read `skipped`.
    CHECK(computes == 8);
    CHECK(hashed == 6 * 8);
    CHECK(timeout == 2);
    CHECK(skipped == 400 - 6 * 8 - 2);
}

TEST_CASE("hash_row_cached: a row that may not start a helper and has no cached answer is skipped",
          "[image_path_cache][processes]") {
    ImagePathCache cache;
    bool ran = false;
    CHECK(hash_row_cached(cache, ImagePathCache::make_key("m", "/p"), false,
                          [&]() -> std::string { ran = true; return "x"; }) ==
          std::string{kHashUnavailableSkipped});
    CHECK_FALSE(ran);
    cache.put(ImagePathCache::make_key("m", "/p"), "good");
    CHECK(hash_row_cached(cache, ImagePathCache::make_key("m", "/p"), false,
                          [&]() -> std::string { ran = true; return "x"; }) == "good");
    CHECK_FALSE(ran);
}
