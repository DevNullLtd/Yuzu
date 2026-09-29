#pragma once

/// @file sync_source_installed_software.hpp
/// The `installed_software` daily-sync source (ADR-0016) — source #1 of the
/// agent sync framework. Collects the machine-wide installed-software inventory
/// by invoking the existing `installed_apps` plugin in-process (`LocalDispatcher`,
/// action `list_inventory` — blob contract v2) and renders it into the canonical
/// wire form the server expects. NO per-user data (machine scope only — no PII).

#include "sync_scheduler.hpp"

#include <yuzu/plugin.h> // YuzuPluginDescriptor (C ABI) — typedef, so include not fwd-decl

#include <string>
#include <vector>

namespace yuzu::agent {

/// One machine-scope installed-software entry (mirror of the server's
/// SoftwareEntry; kept agent-local so this module needs no server headers).
/// Blob contract v2: member order == the wire/hash field order (append-only).
/// Fields an ecosystem does not store stay EMPTY, never synthesised.
struct SwEntry {
    std::string name;
    std::string version; // upstream version, release/revision stripped
    std::string publisher; // rpm PACKAGER / deb Maintainer / Windows Publisher
    std::string install_date;
    std::string kind;      // "package" | "app"
    std::string ecosystem; // rpm|deb|apk|pacman|windows|macos|homebrew
    std::string epoch;
    std::string release;   // rpm RELEASE / deb revision / apk pkgrel
    std::string arch;
    std::string signature_status; // "signed"|"unsigned" (rpm stored tags only)
    std::string distro_id;        // /etc/os-release ID
    std::string distro_version;   // /etc/os-release VERSION_ID
};

/// Parse `installed_apps` `list_inventory` output (pipe-delimited
/// `inv|name|version|publisher|install_date|kind|ecosystem|epoch|release|arch|
/// signature_status|distro_id|distro_version` lines) into machine-scope
/// entries. Rows with any other prefix (`app|`, `user_app|`, `error|`, ...) are
/// ignored; missing trailing tokens read as empty fields (tolerant), tokens
/// beyond the 12th field are dropped (fields never shift).
YUZU_EXPORT std::vector<SwEntry> parse_installed_apps_output(const std::string& out);

/// Canonical wire blob: sorted + deduped; fields unit-separated (0x1F), entries
/// record-separated (0x1E); fields truncated to the server's cap. MUST be
/// byte-identical to the server's reconstruction (ADR-0016 §4 /
/// SoftwareInventoryStore::canonical_hash) so the server-recomputed hash equals
/// this source's. Takes its argument by value (it sorts a copy).
YUZU_EXPORT std::string installed_software_canonical_blob(std::vector<SwEntry> entries);

/// Build the `installed_software` SyncSource. `descriptor` is the loaded
/// `installed_apps` plugin descriptor; when null (plugin not built/loaded — e.g.
/// `build_agent=false`) the source's collect returns std::nullopt and the
/// scheduler no-ops it.
YUZU_EXPORT SyncSource make_installed_software_source(const YuzuPluginDescriptor* descriptor);

} // namespace yuzu::agent
