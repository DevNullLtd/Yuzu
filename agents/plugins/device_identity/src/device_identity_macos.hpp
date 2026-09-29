#pragma once

// device_identity_macos.hpp — pure parser for `dsconfigad -show` plain-text
// output, used by both do_domain() and do_ou() in device_identity_plugin.cpp
// (Wave 3 / #2380 / ADR-3002 promotion: the acquisition call site moved onto
// run_bounded_subprocess, but the shipped floor is rung 2 — an OpenDirectory
// .mm native implementation is explicitly deferred, coordinated with a
// parallel Wave-2 effort doing the same OpenDirectory novelty elsewhere).
//
// VERIFICATION GAP: this build host is not AD-bound, so the fixture below is
// a SYNTHETIC specimen matching Apple's documented `dsconfigad -show` field
// layout (`Active Directory Domain = ...`, `Organizational Unit = ...`), not
// a captured real-world sample — same caveat hardware_disks_macos.hpp's
// SATA path already carries for the identical reason.
//
// Platform-agnostic and header-only so it compiles and its unit tests run on
// every host, matching the hardware_disks_macos.hpp precedent, even though
// it is only ever invoked from the __APPLE__ branch of the plugin.

#include <optional>
#include <string>
#include <string_view>

namespace yuzu::device_identity::macos {

struct DsconfigadInfo {
    bool ad_bound = false; // true iff "Active Directory Domain" was present
    std::string domain;    // "" if not AD-bound
    std::string ou;        // "" if the Organizational Unit line is absent
};

namespace detail {

// Extracts the value after "<label> = " up to end-of-line. Mirrors the
// pre-Wave-3 inline find('=')/find_first_not_of/find_first_of logic exactly.
inline std::optional<std::string> extract_field(std::string_view text, std::string_view label) {
    auto pos = text.find(label);
    if (pos == std::string_view::npos)
        return std::nullopt;
    auto eq = text.find('=', pos);
    if (eq == std::string_view::npos)
        return std::nullopt;
    auto val_start = text.find_first_not_of(" \t", eq + 1);
    if (val_start == std::string_view::npos)
        return std::nullopt;
    auto val_end = text.find_first_of("\r\n", val_start);
    return std::string(
        text.substr(val_start, val_end == std::string_view::npos ? std::string_view::npos
                                                                  : val_end - val_start));
}

} // namespace detail

// Parses `dsconfigad -show` output for the two fields do_domain()/do_ou()
// need. `ad_bound` is set iff the "Active Directory Domain" line is present
// (the do_domain() AD-join signal); `ou` is populated independently so
// do_ou() can use it even in the (never-observed, but not ruled out) case a
// binding carries no domain line surviving this parse.
inline DsconfigadInfo parse_dsconfigad_show(std::string_view text) {
    DsconfigadInfo info;
    if (auto d = detail::extract_field(text, "Active Directory Domain"); d && !d->empty()) {
        info.domain = *d;
        info.ad_bound = true;
    }
    if (auto o = detail::extract_field(text, "Organizational Unit"))
        info.ou = *o;
    return info;
}

} // namespace yuzu::device_identity::macos
