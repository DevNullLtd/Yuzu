#include "verify_api_local.hpp"

#include "app_perf_cohort_reader.hpp"
#include "app_perf_daily_store.hpp" // static_assert ONLY — kMaxWindowDays parity
#include "management_group_store.hpp"

#include <yuzu/version_string.hpp> // canon_version — match the stored key

#include <algorithm>
#include <string>
#include <vector>

namespace yuzu::server {

// verify_api.hpp's kMaxWindowDays is named there (not in a store header) so
// the abstract header stays store-free — this assert is what keeps that
// duplicated constant from silently drifting away from the B1 store's own
// retention ceiling.
static_assert(kMaxWindowDays == AppPerfDailyStore::kRetentionDays,
             "verify_api.hpp's kMaxWindowDays must match AppPerfDailyStore::kRetentionDays");

/// Store-backed `VerifyApi` implementation — the `/auto` VERIFY compare
/// resource's store-reaching assembly (previously `server.cpp`'s
/// `app_perf_providers.cohort` lambda, followed by each of the three
/// callers' own `build_comparison` call), moved verbatim behind the seam so
/// it is independently testable (ADR-0031 WS-A4 #4250). Behaviour preserved
/// exactly: two bounded single-store leases (members, then B1 rows) composed
/// never held across each other (ADR-0012 §1), the AUTHORITATIVE-degrade
/// `nullopt` on a missing reader, a DEGRADED member-resolution read (via
/// `ManagementGroupStore::get_members_checked`, not the fail-soft
/// `get_members()` — #1762, fixed: a store-not-open/pool-timeout/query-error
/// member read no longer renders as `member_count == 0`), or a failed row
/// read, an empty/unknown group resolving to `member_count == 0` with an
/// empty (not degraded) comparison, and the SAME two-canonicalize sequence
/// the callers this replaces used — raw versions passed into
/// `get_cohort_rows` (canonicalized internally there to match the stored
/// key), canonicalized again here for `build_comparison`.
class LocalVerifyApi final : public VerifyApi {
public:
    LocalVerifyApi(ManagementGroupStore& groups, AppPerfCohortReader* cohort_reader)
        : groups_(groups), cohort_reader_(cohort_reader) {}

    LocalVerifyApi(const LocalVerifyApi&) = delete;
    LocalVerifyApi& operator=(const LocalVerifyApi&) = delete;

    [[nodiscard]] std::optional<VerifyCompareResult>
    compare(const VerifyCompareQuery& q) const override {
        if (!cohort_reader_)
            return std::nullopt; // AUTHORITATIVE degrade — store not wired yet

        // Resolve members (one bounded read, lease released), THEN read their
        // raw B1 rows (a second bounded read) — never a lease held across the
        // other (ADR-0012 §1). The /auto VERIFY compare engine pairs these
        // per machine. get_members_checked (not the fail-soft get_members())
        // so a member-read degrade fails closed to nullopt rather than
        // rendering as member_count 0 (#1762, fixed).
        auto members = groups_.get_members_checked(q.group_id);
        if (!members)
            return std::nullopt; // AUTHORITATIVE degrade — the member read failed
        std::vector<std::string> agent_ids;
        agent_ids.reserve(members->size());
        for (const auto& m : *members)
            agent_ids.push_back(m.agent_id);

        VerifyCompareResult out;
        out.member_count = static_cast<std::int64_t>(agent_ids.size());
        const std::string base_canon = yuzu::util::canon_version(q.baseline_version);
        const std::string cand_canon = yuzu::util::canon_version(q.candidate_version);
        // Defense-in-depth: every SHIPPED caller (REST/MCP/dashboard) already
        // clamps its own parsed `window` param to this same ceiling before
        // building the query (for display parity with what gets sent here) —
        // this re-clamp changes nothing for them, it only protects a FUTURE
        // caller (e.g. a presentation-side client post-WS-B2) that forgets to.
        const int window_days = std::clamp(q.window_days, 1, kMaxWindowDays);

        if (agent_ids.empty()) {
            // empty/unknown group -> member_count 0, no rows (not a degrade)
            out.comparison = build_comparison({}, base_canon, cand_canon, window_days);
            return out;
        }

        bool truncated = false;
        auto rows = cohort_reader_->get_cohort_rows(agent_ids, q.app, q.baseline_version,
                                                    q.candidate_version, window_days, truncated);
        if (!rows)
            return std::nullopt; // AUTHORITATIVE degrade — the row read failed

        out.truncated = truncated;
        out.comparison = build_comparison(*rows, base_canon, cand_canon, window_days);
        return out;
    }

private:
    ManagementGroupStore& groups_;
    AppPerfCohortReader* cohort_reader_; ///< nullable — degrades every compare() to nullopt
};

std::shared_ptr<VerifyApi> make_local_verify_api(ManagementGroupStore& groups,
                                                 AppPerfCohortReader* cohort_reader) {
    return std::make_shared<LocalVerifyApi>(groups, cohort_reader);
}

} // namespace yuzu::server
