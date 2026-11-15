#pragma once

/// @file cpe_identity_resolver.hpp
/// CpeIdentityResolver (PR 3, ADR-0018) — a PURE, self-contained unit: given
/// ONE installed-software record, decide its lane and, for Lane-1 distro
/// packages, resolve it to a `(cpe_product, confidence)` CPE identity or emit a
/// stable not-assessed reason. NO store, NO NVD, NO engine, NO Postgres. It
/// produces exactly what the future PR-4 engine will feed into
/// `NvdDatabase::assess()`.
///
/// The curated map is security-relevant — a wrong mapping produces wrong
/// findings — which is why it is isolated here and fail-closed (a too-small
/// embed refuses to construct).
///
/// ==========================================================================
/// THE RESOLVED MATCHING MODEL (B1/B2) — READ BEFORE WIRING A DOWNSTREAM QUERY
/// ==========================================================================
/// A curated hit emits an EXACT PRODUCT plus a vendor that is **DISPLAY /
/// provenance ONLY**. `cpe_vendor` MUST NOT gate the downstream match.
///
/// This is deliberate. `NvdDatabase::assess()` (PR 1) matches on product
/// (+ optional vendor). The entire value of the curated map is fixing the
/// PRODUCT token (`libssl3` -> `openssl`), NOT narrowing the vendor. Emitting a
/// vendor into the query would re-introduce the vendor-drift MISS: NVD carries
/// the same product under multiple vendors (e.g. curl as both `haxx:curl` and
/// `curl:curl`). So a downstream `CpeQuery` built from a `ResolvedIdentity`
/// MUST set `vendor=""` and match on `cpe_product` — `cpe_vendor` is carried
/// for provenance/display only.
///
/// Monotonicity: a curated exact-product is a strict improvement over the
/// uncurated name-prefix baseline; it can never regress below it.

#include <cstddef>
#include <string>
#include <string_view>
#include <unordered_map>

namespace yuzu::server {

struct SoftwareEntry; // software_inventory_types.hpp (only referenced by ref)

/// Fail-closed floor: the production constructor refuses to build a resolver
/// whose curated map holds fewer than this many entries (a corrupt/empty embed
/// must not ship a resolver that high-confidence-matches almost nothing). Kept
/// equal to the shipped seed row count. The runtime ctor is the AUTHORITATIVE
/// floor — it counts successfully-parsed, deduplicated keys. The build-time
/// meson probe is a weaker build-time LOWER-BOUND guard: it counts well-formed
/// rows (non-blank / non-`#` / exactly 5 fields / non-empty name+product) but
/// does NOT replicate the key-dedup, so it catches the gross malformed-embed
/// class at configure time without claiming byte-for-byte parity.
inline constexpr std::size_t kMinCuratedRows = 13;

enum class IdentityOutcome { Resolved, NoIdentity, NoVersion, NotAssessed };
enum class Confidence { High, Low };

struct ResolvedIdentity {
    IdentityOutcome outcome = IdentityOutcome::NotAssessed;
    std::string cpe_product; // the ONLY field that gates matching downstream
    std::string cpe_vendor;  // provenance/display ONLY — the PR-4 query never uses it
    bool exact_product = false; // true = curated (-> CpeQuery.exact_product=true); false = normalized prefix
    Confidence confidence = Confidence::Low;
    // Stable reason string for every NON-Resolved outcome (NotAssessed /
    // NoIdentity / NoVersion) — feeds the PR-2 agent_coverage na_* counters.
    // Empty when outcome == Resolved.
    std::string not_assessed_reason;
};

// Stable reason strings (feed PR-2 agent_coverage na_* counters). NOTE:
// "identity-low-confidence" is intentionally ABSENT — the PR-4 ENGINE emits
// that when it demotes a Low-confidence CLEAN result, never the resolver.
inline constexpr std::string_view kReasonOsNative = "os-native-assessment-not-yet-supported";
inline constexpr std::string_view kReasonUnsupportedEcosystem = "unsupported-ecosystem";
inline constexpr std::string_view kReasonNoIdentity = "no-derivable-identity";
inline constexpr std::string_view kReasonNoVersion = "no-version";
// Reason for a name that normalizes below the 3-char prefix floor. Distinct
// from kReasonNoIdentity (empty name) so the na_* counters can tell them apart.
inline constexpr std::string_view kReasonBelowPrefixFloor = "identity-below-prefix-floor";

class CpeIdentityResolver {
public:
    /// Production ctor — parses the build-embedded `kCuratedCpeMap`. Fail-CLOSED
    /// (logs fatal + throws) if the parsed map holds fewer than `kMinCuratedRows`.
    CpeIdentityResolver();

    /// TEST SEAM — parse an explicit CSV literal, no embed / no IO. Same
    /// fail-closed floor as the production ctor.
    explicit CpeIdentityResolver(std::string_view curated_csv);

    CpeIdentityResolver(const CpeIdentityResolver&) = delete;
    CpeIdentityResolver& operator=(const CpeIdentityResolver&) = delete;

    /// Resolve one installed-software record. Decision tree (in order, STOP
    /// early): lane gate -> empty name -> empty version -> curated lookup ->
    /// normalized low-confidence fallback. See the .cpp for the full contract.
    ///
    /// NOTE the resolver EXPOSES `confidence` but does NOT apply the
    /// low-confidence-clean gate: a Low resolve still returns `Resolved`. The
    /// PR-4 engine is what demotes a Low CLEAN result to not-assessed.
    [[nodiscard]] ResolvedIdentity resolve(const SoftwareEntry& e) const;

    [[nodiscard]] std::size_t curated_entry_count() const noexcept { return map_.size(); }

private:
    struct Target {
        std::string vendor;
        std::string product;
    };
    std::unordered_map<std::string, Target> map_; // key = curated_key(eco,distro_id,name)
};

} // namespace yuzu::server
