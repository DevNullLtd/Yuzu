// Pure composition around the bounded bundle-id pass (macOS `list` bundle_id
// column): alignment, the four warning rows, the CONSTRAINED mappings and the
// input-truncation (capped) outcome. No reads, no CoreFoundation -- portable.

#include "installed_apps_bundle_ids.hpp"
#include "installed_apps_parsers.hpp"

#include <catch2/catch_test_macros.hpp>

#include <string>
#include <vector>

namespace bi = yuzu::installed_apps::bundle_ids;
using yuzu::agent::BundleIdPassResult;
using yuzu::agent::BundleIdPassStatus;
using yuzu::installed_apps::parsers::AppRowFields;

namespace {
bi::BundleIdPassOutcome outcome(BundleIdPassStatus s, std::size_t located, std::size_t submitted,
                                std::size_t read = 0) {
    return {s, located, submitted, read, std::chrono::seconds{30}};
}
} // namespace

TEST_CASE("apply_bundle_ids writes ids through the index map; absent stays empty",
          "[installed_apps][bundle_ids]") {
    std::vector<AppRowFields> apps(4);
    apps[1].install_location = "/Applications/A.app";
    apps[3].install_location = "/Applications/B.app";
    BundleIdPassResult r;
    r.ids = {"com.a", ""};
    bi::apply_bundle_ids(apps, r, {1, 3});
    CHECK(apps[0].bundle_id.empty());
    CHECK(apps[1].bundle_id == "com.a");
    CHECK(apps[2].bundle_id.empty());
    CHECK(apps[3].bundle_id.empty());
}

TEST_CASE("apply_bundle_ids with an empty result leaves every bundle_id empty",
          "[installed_apps][bundle_ids]") {
    std::vector<AppRowFields> apps(2);
    apps[0].install_location = "/Applications/A.app";
    apps[1].install_location = "/Applications/B.app";
    // The allocation-failure Rejected shape: no ids, yet a non-empty index map.
    BundleIdPassResult r;
    r.status = BundleIdPassStatus::Rejected;
    bi::apply_bundle_ids(apps, r, {0, 1}); // min() clamp: must not index past r.ids
    CHECK(apps[0].bundle_id.empty());
    CHECK(apps[1].bundle_id.empty());
}

TEST_CASE("bundle-id warning rows and status: one per non-Completed outcome",
          "[installed_apps][bundle_ids]") {
    const auto timeout = outcome(BundleIdPassStatus::TimedOut, 10, 10, 4);
    CHECK(bi::bundle_id_warning_row(timeout).value() ==
          "warning|bundle_id_timeout: 4 of 10 submitted apps read before the 30 s deadline; "
          "remaining rows carry -");
    CHECK(bi::bundle_id_status(timeout).provenance == "installed_apps:bundle_id_timeout");

    const auto busy = outcome(BundleIdPassStatus::Busy, 10, 10);
    CHECK(bi::bundle_id_warning_row(busy).value() ==
          "warning|bundle_id_busy: another bundle-id pass is in flight on this device (a "
          "concurrent list or an earlier abandoned pass); rows carry -");
    CHECK(bi::bundle_id_status(busy).provenance == "installed_apps:bundle_id_busy");

    const auto rejected = outcome(BundleIdPassStatus::Rejected, 10, 10);
    CHECK(bi::bundle_id_warning_row(rejected).value() ==
          "warning|bundle_id_rejected: bounded-call ceiling refused the pass or its admission "
          "allocation failed; rows carry -");
    CHECK(bi::bundle_id_status(rejected).provenance == "installed_apps:bundle_id_rejected");

    const auto capped = outcome(BundleIdPassStatus::Completed, 5001, 5000, 5000);
    CHECK(bi::bundle_id_warning_row(capped).value() ==
          "warning|bundle_id_capped: 5000 of 5001 located apps submitted (cap 5000); remaining "
          "rows carry -");
    CHECK(bi::bundle_id_status(capped).provenance == "installed_apps:bundle_id_capped");

    for (const auto& o : {timeout, busy, rejected, capped}) {
        const auto st = bi::bundle_id_status(o);
        CHECK(st.status == YUZU_RESULT_STATUS_CONSTRAINED);
        CHECK(st.completeness == YUZU_RESULT_COMPLETENESS_PARTIAL);
    }
}

TEST_CASE("bundle-id: Completed untruncated yields no row and OK/FULL; timeout outranks cap",
          "[installed_apps][bundle_ids]") {
    const auto ok = outcome(BundleIdPassStatus::Completed, 7, 7, 7);
    CHECK_FALSE(bi::bundle_id_warning_row(ok).has_value());
    const auto st = bi::bundle_id_status(ok);
    CHECK(st.status == YUZU_RESULT_STATUS_OK);
    CHECK(st.completeness == YUZU_RESULT_COMPLETENESS_FULL);

    const auto both = outcome(BundleIdPassStatus::TimedOut, 5001, 5000, 10);
    CHECK(bi::bundle_id_status(both).provenance == "installed_apps:bundle_id_timeout");
    CHECK(bi::bundle_id_warning_row(both).value().starts_with("warning|bundle_id_timeout:"));
}

TEST_CASE("collect_bundle_id_paths caps a 5001-located input at 5000 and reports capped",
          "[installed_apps][bundle_ids]") {
    std::vector<AppRowFields> apps(5001);
    for (std::size_t i = 0; i < apps.size(); ++i)
        apps[i].install_location = "/Applications/App" + std::to_string(i) + ".app";
    apps.push_back({}); // a row with no location is not "located"
    auto c = bi::collect_bundle_id_paths(apps);
    auto o = c.outcome;
    CHECK(o.located == 5001);
    CHECK(o.submitted == 5000);
    CHECK(c.paths.size() == 5000);
    CHECK(c.index_map.back() == 4999);
    o.status = BundleIdPassStatus::Completed;
    CHECK(bi::bundle_id_status(o).provenance == "installed_apps:bundle_id_capped");
    CHECK(bi::bundle_id_warning_row(o).has_value());
}
