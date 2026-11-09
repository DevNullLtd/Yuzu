#pragma once

/// @file sync_source_installed_software.hpp
/// The `installed_software` daily-sync source (ADR-0016) — source #1 of the
/// agent sync framework. Collects the machine-wide installed-software inventory
/// by invoking the inventory actions in-process (`LocalDispatcher`) and writes
/// them as a sectioned blob contract v3 (installed_software_v3.hpp): ONE section per
/// plugin action (the table in the .cpp, whose columns are plugin, action, adapter and
/// time limit; a new inventory action adds one row + one pure adapter), rows plus a row-hash
/// delta when the action answered in full, a status-only section when it did not. Each
/// action runs under its own time limit, alone, so one plugin that hangs, fails or is
/// absent costs only its own section.
///   installed_apps.list_inventory           blob rows (the 12 original fields + install_location)
///   pkg_inventory.packages                  Homebrew formulae/casks and Chocolatey packages
///                                           (ecosystems `brew`, `chocolatey`)
///   pkg_inventory.managers                  presence rows: `homebrew` (publisher `Homebrew`),
///                                           `chocolatey` and `winget` (labelled `via:`)
///   pkg_inventory.store_packages            active snaps/flatpaks and Appx packages
///                                           (ecosystems `snap`, `flatpak`, `appx`)
///   windows_optional_features.list          every DISM feature, state in `version`
///                                           (publisher `Microsoft`)
///   msi_packages.list_inventory             machine-context MSI products (ecosystem `msi`)
///   runtimes.python                         installed Python interpreters (ecosystem `python`;
///                                           publisher = the vendor column)
///   middleware.ibm_mq                       installed IBM MQ (ecosystem `ibm_mq`; name and publisher from the product table)
///   hardware.drivers_inventory              Windows PnP signed drivers (ecosystem `windows`) and
///                                           Linux loaded kernel modules (ecosystem `kernel_module`);
///                                           kind `driver`
/// Every row carries `source` = "<plugin>.<action>" and a non-empty publisher: the declared vendor
/// when the source has one, else the origin label `via:<ecosystem>` (pkg_inventory is
/// zero-subprocess, so brew/snap/flatpak rows are `via:brew` etc.). NO per-user data (machine
/// scope only, a per-user install_location is blanked) and no end-user PII; a package maintainer's
/// name in a vendor or Maintainer field is third-party metadata (ADR-0016 "PII scope note").

#include "sync_scheduler.hpp"

#include "local_dispatcher.hpp"

#include <bounded_wait.hpp> // BoundedCallResult: the collector's bounded-call seam
#include <yuzu/plugin.h>    // YuzuPluginDescriptor (C ABI) — typedef, so include not fwd-decl

#include <chrono>
#include <cstddef>
#include <functional>
#include <map>
#include <memory>
#include <mutex>
#include <set>
#include <string>
#include <string_view>
#include <tuple>
#include <utility>
#include <vector>

namespace yuzu::agent {

/// One machine-scope installed-software entry (mirror of the server's
/// SoftwareEntry; kept agent-local so this module needs no server headers).
/// Member order == the wire/hash field order (append-only). Fields an ecosystem does not
/// store stay EMPTY, never synthesised.
struct SwEntry {
    std::string name;
    std::string version; // upstream version, release/revision stripped; for ecosystem
                         // optional_feature, the DISM feature state (no real version)
    std::string publisher; // declared vendor (rpm VENDOR>PACKAGER / deb Maintainer / Windows
                           // Publisher / macOS signer / constant) or the origin label
                           // `via:<ecosystem>`; NEVER empty once the collector has run
                           // (vendor_or_origin)
    std::string install_date;
    std::string kind;      // "package" | "app" | "pkg" | "feat" | "driver"
    std::string ecosystem; // rpm|deb|apk|pacman|windows|macos|macos_pkgutil|brew|snap|flatpak|optional_feature|msi|python|ibm_mq|dotnet|jvm|chocolatey|winget|appx|kernel_module
    std::string epoch;
    std::string release;   // rpm RELEASE / deb revision / apk pkgrel
    std::string arch;
    std::string signature_status; // "signed"|"unsigned" (rpm stored tags, driver signature state)
    std::string distro_id;        // /etc/os-release ID
    std::string distro_version;   // /etc/os-release VERSION_ID
    // Wire slot 13. Machine-scope roots only: the v3 writer blanks a path under an account's
    // home (installed_software_v3.hpp is_per_user_path). Slot 14 (uninstall_string) is
    // reserved and always sent empty (#5186). Inserted here, between distro_version and
    // package_id, so the member order stays the wire order.
    std::string install_location;
    std::string package_id;
    std::string source; // "<plugin>.<action>" that produced the row
};

/// Loaded plugins by `descriptor->name`, as the collector consumes them.
using SyncPluginMap = std::map<std::string, const YuzuPluginDescriptor*, std::less<>>;

/// Result of a pure action adapter. `ok` with zero entries is a legitimate
/// answer ("brew present, no formulae"): the facet is reported in full with no rows.
/// `unsupported` = the action answered "not on this OS" (a `not_collected` section);
/// `constrained` = the action said in-band it could not read everything (its status row), zero
/// entries, `reason` = the status tokens: a status-only `constrained` section, the server keeps
/// the facet's rows; `failed` = the output did not parse (bad status row, no rows from an anchor
/// that always has some), also a `constrained` section with `reason` as its token. There is no
/// partial roster: a degraded read never contributes rows, so it can never delete any.
struct AdaptedRows {
    enum class Status { ok, unsupported, failed, constrained };
    Status status{Status::ok};
    std::vector<SwEntry> entries;
    std::string reason; // failed/constrained: why
};

/// Parse `installed_apps` `list_inventory` output (pipe-delimited
/// `inv|name|version|publisher|install_date|kind|ecosystem|epoch|release|arch|
/// signature_status|distro_id|distro_version|install_location` lines) into machine-scope
/// entries. Rows with any other prefix (`app|`, `user_app|`, `error|`, ...) are
/// ignored; missing trailing tokens read as empty fields (tolerant; a plugin of the previous
/// 13-token layout reads as an empty install_location), tokens beyond the 14th are dropped
/// (fields never shift). Bounded at kV3MaxRows + 1 entries: the collector's per-action
/// raw-count check, not this parser, rejects an over-cap host.
YUZU_EXPORT std::vector<SwEntry> parse_installed_apps_output(const std::string& out);

/// The status-row adapters below (pkg_inventory managers / packages / store_packages,
/// msi_packages list_inventory, runtimes, middleware, hardware drivers_inventory) read the
/// shared status row (agents/shared/inventory_status_row.hpp). Whatever the answer's level, a
/// `constrained` one contributes no rows (Status::constrained, reason = the status tokens): the
/// collector reports it as a status-only section and the server keeps the facet's rows.
///
/// Adapt `pkg_inventory` `managers` output (`status|managers|<level>|...` plus
/// `manager|<name>|<present|unavailable>|<version or ->|...` rows). HOMEBREW
/// plus Windows chocolatey and winget: one presence row {name=homebrew, kind=app,
/// ecosystem=brew} per `present` homebrew row (the writer's dedup collapses a
/// dual-prefix Mac to one), and likewise {name=chocolatey|winget, kind=app,
/// ecosystem=chocolatey|winget}; any other manager name is dropped. The Linux
/// managers leg must add its own mapping deliberately (manager facts belong to
/// facet rows).
YUZU_EXPORT AdaptedRows parse_pkg_inventory_managers_output(const std::string& out);

/// Adapt `pkg_inventory` `packages` output (`status|packages|<level>|...` plus
/// `package|homebrew|<id>|<version>|<formula|cask>`): formula -> kind `pkg`,
/// cask -> kind `app`, ecosystem `brew`. Windows Chocolatey rows
/// (`package|chocolatey|<id>|<version or ->|pkg`) -> kind `pkg`, ecosystem
/// `chocolatey`, version empty when `-`.
YUZU_EXPORT AdaptedRows parse_pkg_inventory_packages_output(const std::string& out);

/// Adapt `pkg_inventory` `store_packages` output (`status|store_packages|<level>|...`
/// plus nine-token `package|<snap|flatpak>|<id>|<version or ->|<kind>|<revision or
/// ->|<arch or ->|<branch or ->|<state>`). ACTIVE rows only. snap -> ecosystem
/// `snap`, version from snap.yaml, release = revision; flatpak -> ecosystem
/// `flatpak`, version EMPTY (the branch is a ref, not a version), release =
/// commit, arch. kind `app` iff the row's kind is `app`, else `pkg`. Windows
/// `appx` -> ecosystem `appx`, kind `app`, name = the package name (the part of
/// the PackageFullName before the first `_`), version and arch from the row,
/// release empty; `deprovisioned` rows are seen but not mapped.
YUZU_EXPORT AdaptedRows parse_pkg_inventory_store_packages_output(const std::string& out);

/// Adapt `msi_packages` `list_inventory` output (`status|list_inventory|<level>|...` plus
/// five-token `inv|<product_code>|<name>|<version>|<publisher>`). Each row becomes
/// {kind=pkg, ecosystem=msi} with package_id = the product code exactly as registered
/// (no case normalisation). An empty name is seen-not-mapped. The producer strips `|`,
/// tab, CR, LF and NUL from the fields, so no unescape is needed.
YUZU_EXPORT AdaptedRows parse_msi_packages_list_inventory_output(const std::string& out);

/// Whether the `runtimes` `python` vendor column is read as a vendor on this host's OS: true on
/// Windows (the PythonCore tag) and on Linux (whose producer always emits `-`, so a Linux row is
/// labelled `via:python`), false on macOS where it is a CFBundleIdentifier id.
#if defined(__APPLE__)
inline constexpr bool kPythonVendorColumnIsVendor = false;
#else
inline constexpr bool kPythonVendorColumnIsVendor = true;
#endif

/// Adapt `runtimes` `python` output (`status|python|<level>|...` plus five-token
/// `python|<flavour>|<version or ->|<install_path or ->|<vendor or ->`). Each row becomes
/// {name=Python, kind=app, ecosystem=python}; `-` version -> empty, publisher = the vendor column
/// (`-` -> empty, labelled `via:python` by the writer), flavour/path dropped. With
/// `vendor_column_is_vendor` false (macOS: the column is a reverse-domain bundle id, an identifier
/// and not a vendor) the column is ignored and publisher is always empty (`via:python`).
/// On Linux the version is major.minor only (the patch level needs the interpreter).
YUZU_EXPORT AdaptedRows parse_runtimes_python_output(const std::string& out,
                                                     bool vendor_column_is_vendor);

/// Adapt `runtimes` `dotnet` output (`status|dotnet|<level>|...` plus five-token
/// `dotnet|<flavour>|<version or ->|<install_path or ->|<vendor or ->`). Each row becomes
/// {kind=app, ecosystem=dotnet, publisher=Microsoft}; name by flavour: `runtime` or `core` ->
/// `.NET Runtime`, `sdk` -> `.NET SDK`, `netfx` -> `.NET Framework`, anything else -> `.NET`.
/// `-` version -> empty; flavour, path and the row's vendor are dropped.
YUZU_EXPORT AdaptedRows parse_runtimes_dotnet_output(const std::string& out);

/// Adapt `runtimes` `jvm` output (same five-token shape, row tag `jvm`). Each row becomes
/// {kind=app, ecosystem=jvm}; name by flavour: `jdk` -> `Java JDK`, `jre` -> `Java JRE`, anything
/// else -> `Java`; publisher = the row's vendor (the build's self-reported IMPLEMENTOR; `-` ->
/// empty); `-` version -> empty; flavour and path dropped.
YUZU_EXPORT AdaptedRows parse_runtimes_jvm_output(const std::string& out);

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
YUZU_EXPORT AdaptedRows parse_middleware_output(const std::string& out, std::string_view action);

/// Adapt `hardware` `drivers_inventory` output (`status|drivers_inventory|<level>|...` plus ten-token
/// `driver_inv|<name>|<version>|<date>|<provider>|<class>|<signer>|<signed>|<inf>|<hwid>`, every
/// absent value `-`). Each row with a name becomes {kind=driver} with `-` -> empty throughout:
/// version, install_date = the date, signature_status = signed|unsigned (anything else empty),
/// publisher = the provider, else the signer (else empty, labelled `via:<ecosystem>` by the
/// writer); class, INF and hardware id have no slot and are dropped. The ecosystem is `windows`
/// on the WMI leg and `kernel_module` on the Linux leg (`kernel_module_leg`, the host OS at
/// compile time in the collector's table): the Linux provider is the fixed literal `kernel`, not a
/// vendor, so it is blanked and a Linux module reads `via:kernel_module`. Drivers get no CPE
/// treatment (cpe_normalize.hpp). macOS answers `unsupported` with no rows.
YUZU_EXPORT AdaptedRows parse_hardware_drivers_inventory_output(const std::string& out,
                                                                bool kernel_module_leg);

/// The action table's (plugin, action, time limit) in table order, the names as views into static
/// literals — for the descriptor pin test (tests/unit/test_inventory_sync_action_table.cpp).
YUZU_EXPORT std::vector<std::tuple<std::string_view, std::string_view, std::chrono::seconds>>
installed_software_actions();

/// Origin-label prefix of a publisher the source does not declare (`via:<ecosystem>`). MUST equal
/// the server's kOriginLabelPrefix (product_normalize.hpp), which treats it as "no vendor"; the
/// test_inventory_sync and test_product_normalize cases pin both to "via:".
inline constexpr std::string_view kOriginLabelPrefix = "via:";

/// The single fallback site: an entry with no declared publisher gets the origin
/// label `via:<ecosystem>` (`via:unknown` when the entry's ecosystem is empty, never the bare
/// `via:`). A declared vendor is left alone. The server's normalize_vendor treats
/// a raw `via:` prefix (case-sensitive, exact) as "no vendor". Applied by the v3 writer
/// (plan_section) to every row it plans, after the field step, so no `+` record has an empty
/// slot 3; the pure hash functions hash the publisher as given.
YUZU_EXPORT void vendor_or_origin(SwEntry& e);

/// The in-flight state of the collector's detached workers: ONE object owned by the agent for
/// its whole life (AgentImpl), never by the SyncSource. The source is rebuilt on every
/// reconnect while a worker abandoned at its time limit may still be inside a plugin, so the
/// single-flight flags and the outstanding count must outlive any one source. A flag is held
/// from the moment a facet's bounded call is admitted until the worker physically returns
/// (not until its caller stops waiting); outstanding() is the number of flags held.
class YUZU_EXPORT CollectorWorkers {
public:
    /// True and the facet marked busy iff no worker of it is in flight.
    [[nodiscard]] bool try_begin(std::string_view facet);
    /// Release a facet (the worker returning, or the caller when the bounded call was rejected
    /// and no worker ever ran).
    void end(std::string_view facet) noexcept;
    /// Workers in flight now (callable from any thread).
    [[nodiscard]] std::size_t outstanding() const;

private:
    mutable std::mutex mu_;
    std::set<std::string, std::less<>> busy_;
};

/// The teardown barrier: wait up to `grace` for `workers` to reach zero. True when drained. When
/// not, `on_stuck(outstanding)` runs (the agent logs and hard-exits there: a plugin must never
/// be shut down or unloaded under a worker still inside it) and false is returned if it
/// returns. Polling, so there is no lock held while waiting.
YUZU_EXPORT bool drain_collector_workers(const CollectorWorkers& workers,
                                         std::chrono::milliseconds grace,
                                         const std::function<void(std::size_t)>& on_stuck);

/// How long a collected facet is reused before its plugin is dispatched again: a second pass
/// inside this window (`__sync__.now`, a first contact split over several calls, the resend after
/// a nack) rebuilds its blob from the rows already collected, against the current acked state.
inline constexpr std::chrono::minutes kPassCooldown{10};

/// Time source for the cooldown; tests inject a fake.
using CollectorClock = std::function<std::chrono::steady_clock::time_point()>;

/// One action's bounded call, as agents/shared/bounded_wait.hpp bounded_call_ex returns it.
/// The collector's only use of a detached worker goes through this seam so a test can drive the
/// Completed / TimedOut / Rejected outcomes without a real thread or a real wait.
using CollectorCallResult = yuzu::shared::BoundedCallResult<std::function<LocalDispatcher::Result()>>;
using CollectorRunner = std::function<CollectorCallResult(
    std::chrono::milliseconds, std::function<LocalDispatcher::Result()>)>;

/// Test seams of the collector; production passes none (every member defaulted).
struct CollectorTuning {
    CollectorClock clock;                    ///< empty = steady_clock::now
    std::chrono::milliseconds time_limit{0}; ///< non-zero replaces every table row's time limit
    CollectorRunner runner;                  ///< empty = yuzu::shared::bounded_call_ex
};

/// Build the `installed_software` SyncSource (blob contract v3). `plugins` maps
/// `descriptor->name` to the loaded descriptor; an absent key = plugin not loaded (it failed init,
/// was refused by the allowlist or signature check, or is not shipped in a trimmed install) ->
/// that facet is reported `not_collected`. Per facet the source writes ONE section:
///   - a plugin that answered in full: `full` (honest-empty included) the first time and after
///     any nack, a row-hash `delta` against the last acknowledged set otherwise, nothing at all
///     when nothing changed;
///   - anything else a status-only section naming why: `constrained` (`rc=<n>`, `truncated`, the
///     plugin's own status tokens, typed PARTIAL completeness, `unknown` for an answer that
///     declared no completeness at all, `no_rows` from installed_apps),
///     `timeout` (`timeout`, `busy` while an earlier worker of that facet is still inside the
///     plugin, `rejected` when no worker could be started), `oversize` (`rows=<n>` / `bytes=<n>`),
///     `not_collected` (`not_loaded`, or the plugin's own `unsupported` answer).
/// A status-only section is sent when its {status, token} differs from the one the server last
/// acknowledged for that facet, and again after a forced send (Sync now), a nack, a reconnect or
/// restart, a send whose response was lost, and once the facet has carried rows; not while it stays
/// the same and acknowledged. The server keeps the rows of a facet it holds through any
/// status-only section.
///
/// Each action runs on a bounded detached worker (agents/shared/bounded_wait.hpp), one at a
/// time, under its table time limit. `workers` is the agent-owned single-flight state above;
/// `kv_get`/`kv_set` are the `__sync__` accessors the per-facet acknowledged sets persist
/// through (`sync.installed_software.<facet>.acked` / `.need_full`). All three are required: a
/// source built without the agent's workers would hold private single-flight state. The source
/// answers the scheduler's hooks: on_force_full (every facet full next), wants_blob (a section
/// was emitted), on_ack (commit the acknowledged sections, mark nacked ones full), has_more (a
/// first contact larger than one call).
YUZU_EXPORT SyncSource make_installed_software_source(SyncPluginMap plugins,
                                                      SyncScheduler::KvGetFn kv_get,
                                                      SyncScheduler::KvSetFn kv_set,
                                                      std::shared_ptr<CollectorWorkers> workers,
                                                      CollectorTuning tuning = {});

} // namespace yuzu::agent
