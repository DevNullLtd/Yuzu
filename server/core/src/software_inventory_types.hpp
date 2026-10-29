#pragma once

/// @file software_inventory_types.hpp
/// Plain value type for one installed-software row (`SoftwareEntry`, blob contract v2),
/// split out of `software_inventory_store.hpp` so the hardware read model and the MCP
/// registry lane can name an entry without including a store header (ADR-0031 seam
/// closure, #6558).
/// `software_inventory_store.hpp` re-includes this header, so existing includers are unaffected. No
/// behaviour lives here — the store keeps its class and every query.

#include <string>

namespace yuzu::server {

/// One installed-software entry. **Machine-scope collection only** (see
/// ADR-0016 §8): no per-user rows and no username/SID fields. The wire tail's
/// `install_location` and `uninstall_string` slots (13-14) are reserved: the server
/// neither stores nor hashes them until §8 is re-opened for them (#5186).
///
/// Blob contract v2 + extended tail: member order == the wire/hash field order (append-only —
/// the canonical hash walks this exact sequence, except that wire slots 13-14 have no member
/// and are hashed as empty; the agent's blob builder walks the first 12 today, the tail rule
/// is the agent's to mirror).
/// Fields an ecosystem does not store are EMPTY, never synthesised: NEVRA +
/// signature populate on Linux package managers per their capability (rpm =
/// full; deb = no signature; apk/pacman = name/EVR only); Windows/macOS rows
/// are kind=app with name/version/publisher only; distro_id/distro_version are
/// stamped on every Linux row from /etc/os-release.
struct SoftwareEntry {
    std::string name;
    std::string version; // upstream version, release/revision stripped (v2); for
                         // ecosystem optional_feature, the DISM feature state
    std::string publisher; // rpm PACKAGER / deb Maintainer / Windows Publisher
    std::string install_date;
    std::string kind;      // "package" | "app" | "pkg" | "feat" (agent-side vocabulary)
    std::string ecosystem; // rpm|deb|apk|pacman|snap|flatpak|windows|macos|macos_pkgutil|brew|optional_feature|msi
    std::string epoch;
    std::string release;   // rpm RELEASE / deb revision / apk pkgrel
    std::string arch;
    std::string signature_status; // "signed"|"unsigned" (rpm stored tags only)
    std::string distro_id;        // /etc/os-release ID
    std::string distro_version;   // /etc/os-release VERSION_ID
    // Extended tail (wire slots 15-16; 13-14 are reserved and have no member): enters the
    // canonical hash ONLY when package_id or source is non-empty — a v2 agent's 12-field
    // bytes are unchanged.
    std::string package_id;
    std::string source; // <plugin>.<action> that produced the row
};

} // namespace yuzu::server
