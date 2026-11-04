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
/// `uninstall_string` slot (14) stays reserved: the server neither stores nor hashes it
/// (#5186). Slot 13 (`install_location`) is stored from the blob-v3 `+` record only; the v2
/// path still parses and discards it, so a v2 row's `install_location` is always empty.
///
/// Blob contract v2 + extended tail: member order == the wire/hash field order (append-only —
/// the canonical hash walks this exact sequence, except that wire slot 14 has no member and
/// is hashed as empty, and `install_location` (slot 13) is hashed as empty on the v2 path;
/// the agent's blob builder walks the first 12 today, the tail rule is the agent's to mirror).
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
    std::string ecosystem; // rpm|deb|apk|pacman|snap|flatpak|windows|macos|macos_pkgutil|brew|optional_feature|msi|python|ibm_mq|chocolatey|winget|appx
    std::string epoch;
    std::string release;   // rpm RELEASE / deb revision / apk pkgrel
    std::string arch;
    std::string signature_status; // "signed"|"unsigned" (rpm stored tags only)
    std::string distro_id;        // /etc/os-release ID
    std::string distro_version;   // /etc/os-release VERSION_ID
    // Wire slot 13 (blob v3 only; always empty on the v2 path, which discards it). Sits here so
    // member order == wire order; slot 14 has no member.
    std::string install_location;
    // Extended tail (wire slots 15-16): enters the canonical v2 hash ONLY when package_id or
    // source is non-empty — a v2 agent's 12-field bytes are unchanged.
    std::string package_id;
    std::string source; // <plugin>.<action> that produced the row
    // SERVER-DERIVED, never on the wire and never in either hash. Filled by the store's
    // `derive_install_keys` on every insert path.
    std::string install_type;  // install_type_rules.hpp vocabulary; '' = not derived
    std::string install_scope; // "machine" | "user" (machine-scope collection: always "machine")
    std::string identity_key;  // norm_key(name, publisher) US version US arch US location
    std::string instance_key;  // SHA-256 hex of the row's 16 canonical slots; unique per agent
    // Package URL (purl_compose.hpp), composed server-side from fields already on the wire and
    // set by the blob-v3 apply path ONLY: a row from a v2 report carries '' until its device's
    // first v3 report (the install_location coexistence rule). '' also where the ecosystem has
    // no registered purl type. Never hashed.
    std::string purl;
};

} // namespace yuzu::server
