#pragma once

/**
 * sccm_parsers.hpp — pure, platform-agnostic decision-logic helpers for the
 * sccm plugin's `site` action (agents/plugins/sccm/src/sccm_plugin.cpp).
 *
 * Header-only and OS-free (the windows_updates_parsers.hpp / discovery_parsers.hpp
 * pattern), so this decision logic is unit-tested on every host
 * (test_sccm_parsers.cpp) against the REAL implementation rather than a
 * mirrored copy. Extracted specifically because these two functions have no
 * Windows-type dependency in either their signature or body — unlike
 * classify_service_status (DWORD/SERVICE_* Windows-typed), which stays
 * mirrored in test_sccm_parsers.cpp per the established rdp_control_plugin.cpp
 * precedent (test_new_plugins.cpp's classify_fw_hr).
 */

#include <format>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

namespace yuzu::sccm {

// Picks the "SMS:<sitecode>" subkey to read CurrentManagementPoint from,
// given the subkey names enumerated under
// HKLM\SOFTWARE\Microsoft\CCM\Authority\. This replaces the previously dead
// fallback that matched a LITERAL two-character "{}" substring (never
// substituted -- no std::format wrapped it) and so never found anything.
//
// Prefers an EXACT match against the machine's own AssignedSiteCode: the
// Authority branch can carry stale subkeys left behind by a prior site
// reassignment (SCCM boundary/site migration), and the currently assigned
// site is the correct authority to trust for CurrentManagementPoint. Falls
// back to the first "SMS:"-prefixed subkey when site_code is empty (both
// earlier registry lookups came up empty) or when no subkey matches it
// (stale/mismatched Authority branch) -- first-found is deterministic given
// a stable enumeration order, and there is no second live signal available
// here to break a tie more precisely.
inline std::optional<std::string> select_authority_subkey(const std::vector<std::string>& subkeys,
                                                    std::string_view site_code) {
    if (!site_code.empty()) {
        const std::string exact = std::format("SMS:{}", site_code);
        for (const auto& k : subkeys) {
            if (k == exact)
                return k;
        }
    }
    for (const auto& k : subkeys) {
        if (k.rfind("SMS:", 0) == 0)
            return k;
    }
    return std::nullopt;
}

// Interprets a late-bound IDispatch::Invoke round trip against
// Microsoft.SMS.Client (GetAssignedSite / GetCurrentManagementPoint),
// reduced to the two booleans a caller determines before this function runs:
// `succeeded` (CLSIDFromProgID -> CoCreateInstance -> GetIDsOfNames ->
// Invoke all returned a success HRESULT) and `is_bstr` (the resulting
// VARIANT's vt == VT_BSTR). `bstr_utf8` is the caller's already-converted
// text (BSTR->UTF-8 conversion stays in the impure Windows shell via
// win_str.hpp, so this function itself has no Windows-type dependency).
enum class SmsInvokeOutcome { ok, failed, wrong_type };

struct SmsInvokeResult {
    SmsInvokeOutcome outcome = SmsInvokeOutcome::failed;
    std::string value;
};

inline SmsInvokeResult interpret_sms_invoke(bool succeeded, bool is_bstr, std::string bstr_utf8) {
    if (!succeeded)
        return {SmsInvokeOutcome::failed, {}};
    if (!is_bstr)
        return {SmsInvokeOutcome::wrong_type, {}};
    return {SmsInvokeOutcome::ok, std::move(bstr_utf8)};
}

} // namespace yuzu::sccm
