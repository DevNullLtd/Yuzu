#pragma once

/// @file sync_source_installed_software.hpp
/// The `installed_software` daily-sync source (ADR-0016) — source #1 of the
/// agent sync framework. Collects the machine-wide installed-software inventory
/// by invoking the inventory actions in-process (`LocalDispatcher`) and renders
/// them into the canonical wire form the server expects. The actions (one table
/// in the .cpp, whose columns are plugin, action, adapter, `accept_partial` and
/// the `constrained` policy; a new inventory action adds one row + one pure adapter):
///   installed_apps.list_inventory           blob contract v2 rows
///   pkg_inventory.packages                  Homebrew formulae/casks (ecosystem `brew`)
///   pkg_inventory.managers                  one `homebrew` presence row
///   pkg_inventory.store_packages            active snaps/flatpaks (ecosystems `snap`, `flatpak`)
///   windows_optional_features.list          every DISM feature, state in `version`
///   msi_packages.list_inventory             machine-context MSI products (ecosystem `msi`)
///   middleware.ibm_mq   installed IBM MQ (ecosystem ibm_mq; title->name, vendor->publisher from the product table)
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
    std::string ecosystem; // rpm|deb|apk|pacman|windows|macos|macos_pkgutil|brew|snap|flatpak|optional_feature|msi
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

/// What a `constrained` status answer does to its action (the `constrained` column of the
/// collector's action table; the status row itself is parsed by
/// agents/shared/inventory_status_row.hpp). The collector's cycle is all-or-nothing, so a source
/// that cannot answer skips the report -- except `drop_source`, which exists for the middleware
/// rows only.
enum class ConstrainedPolicy {
    /// The action fails the cycle: a partial roster would delete stored rows.
    fail,
    /// The rows are kept (status ok, reason = the status token) iff at least one PRESENT data
    /// row of the action's kind was seen, mapped or not; zero such rows still fails.
    keep_rows_if_present_seen,
    // drop_source: the source contributes zero rows and the cycle continues. The cycle's aggregate
    // replaces the agent's whole stored inventory (server/core/src/software_inventory_store.cpp
    // replace: DELETE agent rows + INSERT), so rows withheld this cycle are
    // REMOVED from the stored inventory until the source recovers: a constrained cycle shows as
    // the source's rows missing plus its warn line, never as stale rows. For the middleware rows
    // only: their steady-state constraint is a permission fact, and failing the whole cycle would
    // freeze every other source for ever.
    drop_source,
};

/// Result of a pure action adapter. `ok` with zero entries is a legitimate
/// answer ("brew present, no formulae"); `unsupported` = the action answered
/// "not on this OS" (skipped silently); `failed` = skip the whole cycle.
/// `ok` with a non-empty `reason` = constrained answer whose rows are kept
/// (ConstrainedPolicy::keep_rows_if_present_seen). Collector rules, per the table's
/// `constrained` column: a constrained managers answer is ok iff at least one PRESENT manager
/// row was seen, whether or not it maps to an entry (Linux dpkg/apt rows map to nothing but are
/// still evidence the read worked; zero present rows still fails); a constrained
/// store_packages, packages or msi list_inventory answer always fails (a partial roster would
/// delete stored rows); typed PARTIAL completeness skips the cycle unless the action opts in
/// (an in-band `unsupported` answer wins first); an absent plugin is warned. `withheld` =
/// a constrained answer under ConstrainedPolicy::drop_source: zero entries, `reason` = the status
/// tokens, the source is skipped and the cycle continues.
struct AdaptedRows {
    enum class Status { ok, unsupported, failed, withheld };
    Status status{Status::ok};
    std::vector<SwEntry> entries;
    std::string reason; // failed/withheld: why (logged); ok: the constraint token of the kept row
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

/// The four status-row adapters below (pkg_inventory managers / packages / store_packages and
/// msi_packages list_inventory) take the action's ConstrainedPolicy from its table row: the
/// collector passes the row's `constrained` column, and a test passes the same value so it
/// exercises what the collector runs.
///
/// Adapt `pkg_inventory` `managers` output (`status|managers|<level>|...` plus
/// `manager|<name>|<present|unavailable>|<version or ->|...` rows). HOMEBREW
/// ONLY today: one presence row {name=homebrew, kind=app, ecosystem=brew} per
/// `present` homebrew row (the collector's dedup collapses a dual-prefix Mac to
/// one); any other manager name is dropped. The Linux/Windows managers legs must
/// add their own mapping deliberately (manager facts belong to facet rows).
YUZU_EXPORT AdaptedRows parse_pkg_inventory_managers_output(const std::string& out,
                                                            ConstrainedPolicy policy);

/// Adapt `pkg_inventory` `packages` output (`status|packages|<level>|...` plus
/// `package|homebrew|<id>|<version>|<formula|cask>`): formula -> kind `pkg`,
/// cask -> kind `app`, ecosystem `brew`.
YUZU_EXPORT AdaptedRows parse_pkg_inventory_packages_output(const std::string& out,
                                                            ConstrainedPolicy policy);

/// Adapt `pkg_inventory` `store_packages` output (`status|store_packages|<level>|...`
/// plus nine-token `package|<snap|flatpak>|<id>|<version or ->|<kind>|<revision or
/// ->|<arch or ->|<branch or ->|<state>`). ACTIVE rows only. snap -> ecosystem
/// `snap`, version from snap.yaml, release = revision; flatpak -> ecosystem
/// `flatpak`, version EMPTY (the branch is a ref, not a version), release =
/// commit, arch. kind `app` iff the row's kind is `app`, else `pkg`.
YUZU_EXPORT AdaptedRows parse_pkg_inventory_store_packages_output(const std::string& out,
                                                                  ConstrainedPolicy policy);

/// Adapt `msi_packages` `list_inventory` output (`status|list_inventory|<level>|...` plus
/// five-token `inv|<product_code>|<name>|<version>|<publisher>`). Each row becomes
/// {kind=pkg, ecosystem=msi} with package_id = the product code exactly as registered
/// (no case normalisation). An empty name is seen-not-mapped. The producer strips `|`,
/// tab, CR, LF and NUL from the fields, so no unescape is needed. The collector's table row
/// fails a `constrained` answer (a partial roster would delete stored msi rows); `unsupported`
/// is skipped.
YUZU_EXPORT AdaptedRows parse_msi_packages_list_inventory_output(const std::string& out,
                                                                 ConstrainedPolicy policy);

/// Adapt `windows_optional_features` `list` output (`feature|<name>|<state>|<0/1>`):
/// EVERY feature becomes {kind=feat, ecosystem=optional_feature} with the DISM
/// state token verbatim in `version` (a labelled overload — a real state slot is
/// #5186 territory). `feature|unsupported|...` -> unsupported;
/// `feature|unavailable|<token>` or no feature rows at all -> failed.
YUZU_EXPORT AdaptedRows parse_windows_optional_features_output(const std::string& out);

/// Adapt `middleware` product output for the product table row `action` names (`status|<id>|<level>|...`
/// plus six-token `<id>|<title>|<name>|<version or ->|<install_path>|<edition or ->`). A row maps
/// to {name=title, publisher=vendor, kind, ecosystem} from agents/shared/middleware_products.hpp
/// ONLY when its title column equals the table title; any other row is dropped and counted, its
/// siblings kept. install_path and edition are not carried. An unknown `action` -> failed.
/// The collector's table row uses ConstrainedPolicy::drop_source: a `constrained` answer
/// contributes no rows (Status::withheld) and the cycle continues; `unsupported` is skipped.
YUZU_EXPORT AdaptedRows parse_middleware_output(const std::string& out, std::string_view action,
                                                ConstrainedPolicy policy);

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
