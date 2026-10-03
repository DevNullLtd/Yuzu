// wmi_error_token.hpp -- stage-aware classification of wmi_bounded.hpp error tokens.
//
// Portable and OS-header-free (no <windows.h>, no <wbemidl.h>): wmi_bounded.hpp is Windows-only,
// but every plugin that consumes its tokens decides what they MEAN in a pure parsers header that
// compiles and is unit-tested on every OS (tests/unit/test_wmi_error_token.cpp). The stage
// prefixes below are spelled as literals for that reason; each Windows TU that includes both
// headers static_asserts them against yuzu::shared::wmi::error_tokens (firmware_posture_win.cpp,
// app_control_win.cpp), so a renamed prefix fails the Windows build instead of silently
// misclassifying a stage.
#pragma once

#include <charconv>
#include <cstddef>
#include <cstdint>
#include <optional>
#include <string_view>
#include <system_error>

namespace yuzu::shared::wmi_token {

enum class WmiReadOutcome { ok, absent, denied, failed };

/// WMI / COM HRESULT bit patterns: WBEM_E_ACCESS_DENIED / E_ACCESSDENIED are refusals; a
/// missing namespace, class or object (0x8004100E, 0x80041010, 0x80041002) is absence. This is
/// the meaning of the bare HRESULT only: whether a given wmi_bounded token may read `absent` also
/// depends on the STAGE that produced it (classify_wmi_error_token).
[[nodiscard]] constexpr WmiReadOutcome classify_hresult(std::uint32_t hr) noexcept {
    if (hr == 0) return WmiReadOutcome::ok;
    if (hr == 0x80041003u || hr == 0x80070005u) return WmiReadOutcome::denied;
    if (hr == 0x8004100Eu || hr == 0x80041010u || hr == 0x80041002u) return WmiReadOutcome::absent;
    return WmiReadOutcome::failed;
}

/// The HRESULT a wmi_bounded error token ends in (`..._0x<8 hex digits>`, e.g.
/// wmi_connect_failed_0x80041003), or nullopt for a token that carries none (com_init_failed,
/// wmi_deadline_exceeded, ...). Extraction only: what the HRESULT means is classify_hresult's job.
[[nodiscard]] inline std::optional<std::uint32_t> hresult_from_token(std::string_view token) noexcept {
    constexpr std::size_t kTail = 10; // "0x" + 8 hex digits
    if (token.size() < kTail) return std::nullopt;
    const char* first = token.data() + token.size() - kTail;
    if (first[0] != '0' || first[1] != 'x') return std::nullopt;
    std::uint32_t hr = 0;
    const char* last = token.data() + token.size();
    const auto [ptr, ec] = std::from_chars(first + 2, last, hr, 16);
    if (ec != std::errc{} || ptr != last) return std::nullopt;
    return hr;
}

/// Classifies a wmi_bounded error token, STAGE-AWARE. A refusal HRESULT is `denied` at every
/// stage; a token with no HRESULT is `failed`. `absent` is exactly the two answers WMI gives when
/// the thing really is missing, and nothing else:
///   - WBEM_E_INVALID_NAMESPACE (0x8004100E) from `wmi_connect_failed_*`: the namespace is not
///     there (a namespace is resolved at ConnectServer);
///   - WBEM_E_INVALID_CLASS (0x80041010) from `wmi_query_failed_*`, or from `wmi_next_failed_*`
///     when NO row had been returned before the failure (`rows_before_error == 0`): the class is
///     not there. The query runs semisynchronously (FORWARD_ONLY | RETURN_IMMEDIATELY), so
///     ExecQuery can succeed without resolving the class and the answer then arrives at the
///     first Next(); tests/unit/test_wmi_bounded.cpp records that WQL validation is deferred to
///     Next(), and a probe on the rig saw a non-existent class fail at Next with InvalidClass
///     (issue #4900 tracks a committed real-WMI test). The same answer after a row WAS returned
///     cannot mean "the class is missing" (the class just answered), so it reads `failed`: the
///     token carries no iteration index, so the caller passes the count wmi_bounded records.
///     `rows_before_error` has no default: a caller that left it out would read a fault after a
///     returned row as an absence.
/// Every other absence-looking HRESULT is a FAULT and reads `failed`: WBEM_E_NOT_FOUND
/// (0x80041002) anywhere (Microsoft lists it at connect as a repository-corruption symptom), and
/// INVALID_NAMESPACE / INVALID_CLASS at a stage that cannot legitimately produce them. The
/// proxy-blanket stage (CoSetProxyBlanket, after connect and before the query) carries no WBEM
/// schema answer, so it never reads `absent`. A damaged repository that presents AS one of the two
/// answers is indistinguishable from a real absence (README caveat 4; decision in #4900).
/// A property-enumeration fault (`wmi_property_enum_failed_*`) is a fault at every HRESULT: it
/// matches no `absent` stage above, so it reads `failed` (or `denied` for a refusal HRESULT).
[[nodiscard]] inline WmiReadOutcome
classify_wmi_error_token(std::string_view token, std::size_t rows_before_error) noexcept {
    const auto hr = hresult_from_token(token);
    const WmiReadOutcome o = hr ? classify_hresult(*hr) : WmiReadOutcome::failed;
    if (o != WmiReadOutcome::absent) return o == WmiReadOutcome::ok ? WmiReadOutcome::failed : o;
    if (token.starts_with("wmi_connect_failed_") && *hr == 0x8004100Eu) return WmiReadOutcome::absent;
    if (*hr == 0x80041010u &&
        (token.starts_with("wmi_query_failed_") ||
         (token.starts_with("wmi_next_failed_") && rows_before_error == 0)))
        return WmiReadOutcome::absent;
    return WmiReadOutcome::failed;
}

} // namespace yuzu::shared::wmi_token
