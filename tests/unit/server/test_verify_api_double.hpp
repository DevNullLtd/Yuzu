#pragma once

/// @file test_verify_api_double.hpp
/// FnVerifyApi — a test-only `VerifyApi` adapter wrapping the pre-ADR-0031-
/// WS-A4 `AppPerfCohortFn`-shaped provider (`CohortRead(group_id, app,
/// baseline, candidate, window_days)`), the shape every existing VERIFY-
/// compare test harness already builds. Performs the SAME assembly
/// `LocalVerifyApi::compare` does (verify_api.cpp) — canonicalize both
/// versions, then `build_comparison` — so a test fixture only needs to supply
/// raw `CohortRead` rows, exactly as it did before this seam existed.
///
/// NOT for production use — the production factory is `make_local_verify_api`
/// (verify_api_local.hpp), which takes an `AppPerfCohortReader*` — a DIFFERENT
/// shape from this file's own `CohortRead`/`Fn` below (see `verify_api.cpp`'s
/// own wiring). `CohortRead`/`AppPerfCohortFn` used to live in the production
/// `dex_app_perf_builders.hpp` alongside the (now-retired) `AppPerfProviders`
/// bundle; they were dead in every production build (VerifyApi's real
/// factory never took either shape) and are relocated here — their one
/// genuine consumer, besides this file, is `test_dex_perf_api_double.hpp`'s
/// `FnDexPerfApi::Providers::cohort` field (unused by `DexPerfApi` itself,
/// kept only so a caller building a `Providers` for both seams' test doubles
/// needs no field-level changes) — hence that file `#include`s this one.

#include "app_perf_compare.hpp" // build_comparison, PairedComparison, AppPerfCohortRow
#include "verify_api.hpp"

#include <yuzu/version_string.hpp> // canon_version

#include <cstdint>
#include <functional>
#include <optional>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

namespace yuzu::server {

/// What the `/auto` VERIFY cohort provider returns — the pre-ADR-0031-WS-A4
/// shape every existing VERIFY-compare test harness builds. Left in
/// `yuzu::server` (not `yuzu::server::test`) even though this is a test-only
/// header — every existing test file that names these types spells them
/// `yuzu::server::CohortRead`/`yuzu::server::AppPerfCohortFn` fully qualified,
/// and moving the namespace too would be a needless second churn on top of
/// the file relocation.
struct CohortRead {
    std::int64_t member_count{0};
    std::vector<AppPerfCohortRow> rows;
    bool truncated{false};
};

using AppPerfCohortFn = std::function<std::optional<CohortRead>(
    std::string_view group_id, std::string_view app_name, std::string_view baseline_version,
    std::string_view candidate_version, int window_days)>;

} // namespace yuzu::server

namespace yuzu::server::test {

class FnVerifyApi final : public yuzu::server::VerifyApi {
public:
    using Fn = yuzu::server::AppPerfCohortFn;

    explicit FnVerifyApi(Fn fn) : fn_(std::move(fn)) {}

    [[nodiscard]] std::optional<yuzu::server::VerifyCompareResult>
    compare(const yuzu::server::VerifyCompareQuery& q) const override {
        if (!fn_)
            return std::nullopt;
        auto cohort =
            fn_(q.group_id, q.app, q.baseline_version, q.candidate_version, q.window_days);
        if (!cohort)
            return std::nullopt;
        yuzu::server::VerifyCompareResult out;
        out.member_count = cohort->member_count;
        out.truncated = cohort->truncated;
        const std::string base = yuzu::util::canon_version(q.baseline_version);
        const std::string cand = yuzu::util::canon_version(q.candidate_version);
        out.comparison = yuzu::server::build_comparison(cohort->rows, base, cand, q.window_days);
        return out;
    }

private:
    Fn fn_;
};

} // namespace yuzu::server::test
