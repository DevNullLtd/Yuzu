#pragma once

/// @file sync_source_installed_software.hpp
/// The `installed_software` daily-sync source (ADR-0016) — source #1 of the
/// agent sync framework. Collects the machine-wide installed-software inventory
/// by invoking the inventory actions in-process (`LocalDispatcher`) and renders
/// them into the canonical wire form the server expects. The actions (one table
/// in the .cpp; a new inventory action adds one row + one pure adapter):
///   installed_apps.list_inventory           blob contract v2 rows
///   pkg_inventory.packages                  Homebrew formulae/casks (ecosystem `brew`)
///   pkg_inventory.managers                  one `homebrew` presence row
///   windows_optional_features.list          every DISM feature, state in `version`
/// Every row carries `source` = "<plugin>.<action>". NO per-user data (machine
/// scope only — no PII).

#include "sync_scheduler.hpp"

#include <yuzu/plugin.h> // YuzuPluginDescriptor (C ABI) — typedef, so include not fwd-decl

#include <map>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

namespace yuzu::agent {

/// One machine-scope installed-software entry (mirror of the server's
/// SoftwareEntry; kept agent-local so this module needs no server headers).
/// Blob contract v2: member order == the wire/hash field order (append-only).
/// Fields an ecosystem does not store stay EMPTY, never synthesised.
struct SwEntry {
    std::string name;
    std::string version; // upstream version, release/revision stripped; for ecosystem
                         // optional_feature, the DISM feature state (no real version)
    std::string publisher; // rpm PACKAGER / deb Maintainer / Windows Publisher
    std::string install_date;
    std::string kind;      // "package" | "app" | "pkg" | "feat"
    std::string ecosystem; // rpm|deb|apk|pacman|windows|macos|macos_pkgutil|brew|optional_feature
    std::string epoch;
    std::string release;   // rpm RELEASE / deb revision / apk pkgrel
    std::string arch;
    std::string signature_status; // "signed"|"unsigned" (rpm stored tags only)
    std::string distro_id;        // /etc/os-release ID
    std::string distro_version;   // /etc/os-release VERSION_ID
    // Extended tail (mirrors the server's SoftwareEntry). Wire slots 13-14
    // (install_location, uninstall_string) are reserved: no member, always sent
    // empty, never hashed (ADR-0016 §8, #5186).
    std::string package_id;
    std::string source; // "<plugin>.<action>" that produced the row
};

/// Loaded plugins by `descriptor->name`, as the collector consumes them.
using SyncPluginMap = std::map<std::string, const YuzuPluginDescriptor*, std::less<>>;

/// Result of a pure action adapter. `ok` with zero entries is a legitimate
/// answer ("brew present, no formulae"); `unsupported` = the action answered
/// "not on this OS" (skipped silently); `failed` = skip the whole cycle.
/// `ok` with a non-empty `reason` = constrained managers answer whose present
/// row is kept. Collector rules: constrained managers with a present Homebrew row
/// is ok (zero present rows still fails; another OS's managers leg maps its own
/// rows and must decide its own constrained rule); typed PARTIAL completeness
/// skips the cycle unless the action opts in (an in-band `unsupported` answer
/// wins first); an absent plugin is warned.
struct AdaptedRows {
    enum class Status { ok, unsupported, failed };
    Status status{Status::ok};
    std::vector<SwEntry> entries;
    std::string reason; // failed: why (logged); ok: the constraint token of the kept row
};

/// Parse `installed_apps` `list_inventory` output (pipe-delimited
/// `inv|name|version|publisher|install_date|kind|ecosystem|epoch|release|arch|
/// signature_status|distro_id|distro_version` lines) into machine-scope
/// entries. Rows with any other prefix (`app|`, `user_app|`, `error|`, ...) are
/// ignored; missing trailing tokens read as empty fields (tolerant), tokens
/// beyond the 12th field are dropped (fields never shift). Bounded at
/// kMaxEntries + 1 entries: the collector's per-action raw-count check, not this parser,
/// rejects an over-cap host.
YUZU_EXPORT std::vector<SwEntry> parse_installed_apps_output(const std::string& out);

/// Adapt `pkg_inventory` `managers` output (`status|managers|<level>|...` plus
/// `manager|<name>|<present|unavailable>|<version or ->|...` rows). HOMEBREW
/// ONLY today: one presence row {name=homebrew, kind=app, ecosystem=brew} per
/// `present` homebrew row (the collector's dedup collapses a dual-prefix Mac to
/// one); any other manager name is dropped. The Linux/Windows managers legs must
/// add their own mapping deliberately (manager facts belong to facet rows).
YUZU_EXPORT AdaptedRows parse_pkg_inventory_managers_output(const std::string& out);

/// Adapt `pkg_inventory` `packages` output (`status|packages|<level>|...` plus
/// `package|homebrew|<id>|<version>|<formula|cask>`): formula -> kind `pkg`,
/// cask -> kind `app`, ecosystem `brew`.
YUZU_EXPORT AdaptedRows parse_pkg_inventory_packages_output(const std::string& out);

/// Adapt `windows_optional_features` `list` output (`feature|<name>|<state>|<0/1>`):
/// EVERY feature becomes {kind=feat, ecosystem=optional_feature} with the DISM
/// state token verbatim in `version` (a labelled overload — a real state slot is
/// #5186 territory). `feature|unsupported|...` -> unsupported;
/// `feature|unavailable|<token>` or no feature rows at all -> failed.
YUZU_EXPORT AdaptedRows parse_windows_optional_features_output(const std::string& out);

/// The action table's (plugin, action) names in table order, as views into static literals —
/// for the descriptor pin test (tests/unit/test_inventory_sync_action_table.cpp).
YUZU_EXPORT std::vector<std::pair<std::string_view, std::string_view>> installed_software_actions();

/// Canonical wire blob: sorted + deduped; fields unit-separated (0x1F), entries
/// record-separated (0x1E); fields truncated to the server's cap. MUST be
/// byte-identical to the server's reconstruction (ADR-0016 §4 /
/// SoftwareInventoryStore::canonical_hash) so the server-recomputed hash equals
/// this source's. Takes its argument by value (it sorts a copy).
YUZU_EXPORT std::string installed_software_canonical_blob(std::vector<SwEntry> entries);

/// Build the `installed_software` SyncSource. `plugins` maps `descriptor->name`
/// to the loaded descriptor; an absent key = plugin not loaded (it failed init, was
/// refused by the allowlist or signature check, or is not shipped in a trimmed
/// install) -> that action is skipped with a warning, except installed_apps: without
/// it the source stays idle (it anchors the report, UP-IN6). A failing action skips the cycle
/// (nothing is deleted), as does typed PARTIAL completeness unless the action
/// opts in (pkg_inventory managers).
///
/// The source opts into SyncSource::skip_backoff and sets skip_reason to the
/// token of the most recent skip ("<plugin>.<action>:rc=<n>", ":truncated",
/// ":row_cap", ":partial", ":<adapter reason>", "installed_apps:not_loaded",
/// "installed_software:no_rows|entry_cap|blob_cap"), "" after a success. (`no_rows` is
/// defensive: the anchor adapter fails an empty listing first.)
YUZU_EXPORT SyncSource make_installed_software_source(SyncPluginMap plugins);

} // namespace yuzu::agent
