#include "sync_source_installed_software.hpp"

#include "hard_exit.hpp" // wait_for_workers_to_drain
#include "installed_software_v3.hpp"
#include "local_dispatcher.hpp"
#include "sync_canonical.hpp" // sanitize_utf8_strict / clamp_field / sha256_hex

#include <bounded_wait.hpp>         // bounded_call_ex: the per-action time limit
#include <inventory_status_row.hpp> // the status-row grammar shared with the producing plugins
#include <middleware_products.hpp>  // the middleware product table (title/vendor/ecosystem/kind)
#include <spdlog/spdlog.h>

#include <algorithm>
#include <chrono>
#include <cstdint>
#include <cstdlib>
#include <memory>
#include <optional>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

namespace yuzu::agent {

namespace {

// The raw-row bound and the field clamp are the writer's caps (kV3MaxRows / kV3MaxFieldLen,
// installed_software_v3.hpp, which mirror server/core/src/inventory_blob_v3.hpp), so the
// server's parse neither truncates nor drops differently from what this source hashed. The
// blob and section byte caps live with the writer too.

// ── shared line/token splitters (installed_apps + the pkg/wof adapters) ──

// Calls `fn(line)` for every non-empty line (CRLF-tolerant) until it returns false.
template <class Fn> void for_each_line(const std::string& out, Fn&& fn) {
    std::size_t pos = 0;
    while (pos < out.size()) {
        std::size_t eol = out.find('\n', pos);
        if (eol == std::string::npos)
            eol = out.size();
        std::string_view line(out.data() + pos, eol - pos);
        while (!line.empty() && (line.back() == '\r'))
            line.remove_suffix(1);
        pos = eol + 1;
        if (line.empty())
            continue;
        if (!fn(line))
            return;
    }
}

// Split on '|' into at most `max` tokens; anything past the max-th token is dropped.
// `escaped` additionally treats `\|` as field text, not a separator (the wire form
// yuzu::util::safe_output_field gives a literal pipe; a literal backslash is never emitted, it
// is replaced by '/'). Tokens stay views of the raw line, so an escaped pipe keeps its `\`.
std::vector<std::string_view> split_tokens(std::string_view line, std::size_t max,
                                           bool escaped = false) {
    std::vector<std::string_view> tok;
    std::size_t fp = 0;
    while (tok.size() < max) {
        std::size_t bar = line.find('|', fp);
        while (escaped && bar != std::string_view::npos && bar > fp && line[bar - 1] == '\\')
            bar = line.find('|', bar + 1);
        if (bar == std::string_view::npos) {
            tok.push_back(line.substr(fp));
            break;
        }
        tok.push_back(line.substr(fp, bar - fp));
        fp = bar + 1;
    }
    return tok;
}

// Undo yuzu::util::safe_output_field's pipe escape (`\|` -> `|`) on a free-text token.
std::string unescape_pipes(std::string_view t) {
    std::string out;
    out.reserve(t.size());
    for (std::size_t i = 0; i < t.size(); ++i) {
        if (t[i] == '\\' && i + 1 < t.size() && t[i + 1] == '|')
            continue; // drop the escape, keep the pipe
        out += t[i];
    }
    return out;
}

AdaptedRows failed(std::string reason) {
    AdaptedRows r;
    r.status = AdaptedRows::Status::failed;
    r.reason = std::move(reason);
    return r;
}

// `pkg_inventory` grammar (pkg_inventory_parsers.hpp format_manager_row /
// format_package_row / format_store_row), shared by msi_packages.list_inventory
// (msi_packages_inventory.hpp): exactly one
// `status|<action>|<supported|constrained|unsupported>|<tokens or ->` row, plus
// data rows. The status row is read by yuzu::shared::parse_status_row
// (agents/shared/inventory_status_row.hpp, the helper both plugins format it
// with): it owns the field positions, the level vocabulary and the same-action
// rule, and returns field 4 at every level. Status decides success; malformed
// DATA rows are dropped. A status row answering a different action (or too short) is
// not counted; zero counted rows -> "bad status". A same-action row with an unknown
// level IS counted but carries no level, so it fails validation as "bad status" too
// (alone, or as the second row beside a valid one).
//
// A `constrained` level contributes no rows (Status::constrained, reason = field 4): the answer
// says the read was incomplete, so the collector reports a status-only section and the server
// keeps the facet's rows (they read as unconfirmed). Field 4 surfaces as `reason` under
// constrained only; supported and unsupported leave it empty.
template <class OnRow>
AdaptedRows adapt_pkg_inventory(const std::string& out, std::string_view action, OnRow on_row,
                                bool escaped = false, std::size_t max_tokens = 10) {
    AdaptedRows res;
    int status_rows = 0;
    std::optional<yuzu::shared::StatusLevel> level;
    std::string reason;
    for_each_line(out, [&](std::string_view line) {
        // One more than the widest row (store rows are nine tokens, driver rows ten) so an
        // over-wide row fails the `!= N` width checks instead of being truncated to a valid width.
        const auto tok = split_tokens(line, max_tokens, escaped);
        if (yuzu::shared::is_status_line(tok)) {
            if (auto row = yuzu::shared::parse_status_row(tok, action)) {
                ++status_rows;
                level = row->level;
                reason = std::move(row->tokens);
            }
            return true;
        }
        on_row(tok, res.entries);
        return res.entries.size() <= kV3MaxRows;
    });
    if (status_rows != 1 || !level)
        return failed("bad status");
    if (*level == yuzu::shared::StatusLevel::constrained) {
        // A known-incomplete set is never published as rows.
        res.entries.clear();
        res.status = AdaptedRows::Status::constrained;
        res.reason = std::move(reason);
        return res;
    }
    if (*level == yuzu::shared::StatusLevel::unsupported) {
        res.entries.clear();
        res.status = AdaptedRows::Status::unsupported;
    }
    return res;
}

// Manager token (a `manager|<token>|...` row or a `package|<token>|...` row) -> ecosystem, as
// data. `package_action` names the ONE action whose package rows this manager's token maps in
// (so a snap row inside `packages`, or a homebrew row inside `store_packages`, stays unmapped);
// `presence_row` is whether a present `managers` row for it becomes an installed_software
// entry, and `presence_publisher` the constant vendor of that presence row (empty: the table
// declares none, so `vendor_or_origin` labels it `via:<ecosystem>`). A manager absent from this
// table maps to nothing. The ecosystem values are written as
// `.ecosystem = "..."` so tests/test_software_vocabulary_consistency.py still reads every
// ecosystem this file emits.
//
// The table maps names only: a new manager also needs its own row-shape arm in the adapter
// (store_packages branches on snap vs flatpak for the field layout). A row the table does not
// cover is counted differently per action: an unlisted manager's `packages` row is NOT seen,
// while its `store_packages` and present `managers` rows are seen but not mapped -- each
// adapter's row filter decides that; the `package_action` column only says where a listed
// manager maps.
constexpr std::string_view kActionManagers = "managers";
constexpr std::string_view kActionPackages = "packages";
constexpr std::string_view kActionStorePackages = "store_packages";

struct ManagerEcosystem {
    std::string_view manager;
    std::string_view ecosystem;
    std::string_view package_action;
    bool presence_row{false};
    std::string_view presence_publisher{};
};

constexpr ManagerEcosystem kManagerEcosystems[] = {
    {.manager = "homebrew",
     .ecosystem = "brew",
     .package_action = kActionPackages,
     .presence_row = true,
     .presence_publisher = "Homebrew"},
    {.manager = "snap", .ecosystem = "snap", .package_action = kActionStorePackages},
    {.manager = "flatpak", .ecosystem = "flatpak", .package_action = kActionStorePackages},
    // Windows: Chocolatey packages (`pkg` rows) and its presence row; winget has presence only
    // (its packages are per-user and out of scope); the Appx roster rides store_packages.
    {.manager = "chocolatey",
     .ecosystem = "chocolatey",
     .package_action = kActionPackages,
     .presence_row = true},
    {.manager = "winget", .ecosystem = "winget", .package_action = "", .presence_row = true},
    {.manager = "appx", .ecosystem = "appx", .package_action = kActionStorePackages},
};

constexpr const ManagerEcosystem* find_manager(std::string_view manager) {
    for (const auto& m : kManagerEcosystems) {
        if (m.manager == manager)
            return &m;
    }
    return nullptr;
}

// One table row per inventory action. Adding an action = one row + one pure adapter. The facet
// (and the `source` of every row) is "<plugin>.<action>"; it must be a server kSoftwareSources
// value (tests/test_software_vocabulary_consistency.py reads this table, so the
// `{.plugin = "...", .action = ...}` literal shape is a contract).
struct InventoryAction {
    std::string_view plugin;
    std::string_view action;
    AdaptedRows (*adapt)(const std::string& captured);
    // How long the sync thread waits for this one action before it reports `timeout` and goes on
    // (the worker is abandoned, not killed: single-flight keeps it to one per facet). The agent's
    // shutdown watchdog is 20 s, so a stop that lands inside a wait longer than that ends in the
    // watchdog's hard exit: the same outcome an unbounded in-process dispatch had before.
    std::chrono::seconds time_limit{60};
};

constexpr std::chrono::seconds kSlowActionLimit{120};

// UP-IN6 preserved per plugin: installed_apps always reports >= 1 application on a real
// endpoint, so an empty parse is a plugin hiccup, NOT "everything uninstalled": a `constrained`
// section (token `no_rows`), never a deleting `full`.
AdaptedRows adapt_installed_apps(const std::string& captured) {
    AdaptedRows r;
    r.entries = parse_installed_apps_output(captured);
    if (r.entries.empty())
        return failed("no_rows");
    return r;
}

// runtimes.python is bound through a wrapper that supplies the host's vendor-column rule (the
// collector runs on the agent's own OS), keeping the public adapter testable on any host.
AdaptedRows adapt_runtimes_python(const std::string& captured) {
    return parse_runtimes_python_output(captured, kPythonVendorColumnIsVendor);
}

// drivers_inventory: the ecosystem is the host's (Windows PnP driver, Linux kernel module).
#if defined(_WIN32)
constexpr bool kDriversAreKernelModules = false;
#else
constexpr bool kDriversAreKernelModules = true;
#endif
AdaptedRows adapt_hardware_drivers(const std::string& captured) {
    return parse_hardware_drivers_inventory_output(captured, kDriversAreKernelModules);
}

const InventoryAction kInventoryActions[] = {
    {.plugin = "installed_apps",
     .action = "list_inventory",
     .adapt = adapt_installed_apps,
     .time_limit = kSlowActionLimit},
    {.plugin = "pkg_inventory", .action = kActionManagers, .adapt = parse_pkg_inventory_managers_output},
    {.plugin = "pkg_inventory", .action = kActionPackages, .adapt = parse_pkg_inventory_packages_output},
    {.plugin = "pkg_inventory",
     .action = kActionStorePackages,
     .adapt = parse_pkg_inventory_store_packages_output},
    {.plugin = "windows_optional_features",
     .action = "list",
     .adapt = parse_windows_optional_features_output,
     .time_limit = kSlowActionLimit},
    {.plugin = "msi_packages",
     .action = "list_inventory",
     .adapt = parse_msi_packages_list_inventory_output},
    {.plugin = "runtimes", .action = "python", .adapt = adapt_runtimes_python},
    {.plugin = "middleware",
     .action = "ibm_mq",
     .adapt = [](const std::string& o) { return parse_middleware_output(o, "ibm_mq"); }},
    {.plugin = "runtimes", .action = "dotnet", .adapt = parse_runtimes_dotnet_output},
    {.plugin = "runtimes", .action = "jvm", .adapt = parse_runtimes_jvm_output},
    // LAST: the facet order is the order the sections are planned in, and a driver roster is the
    // one most likely to be large; the server's vocabulary table follows this order.
    {.plugin = "hardware",
     .action = "drivers_inventory",
     .adapt = adapt_hardware_drivers,
     .time_limit = kSlowActionLimit},
};

} // namespace

std::vector<SwEntry> parse_installed_apps_output(const std::string& out) {
    std::vector<SwEntry> entries;
    // Reads ONE PAST kV3MaxRows so the collector's per-action raw-count check can
    // see an over-cap host and report it oversize rather than hash a silently truncated
    // list.
    for_each_line(out, [&entries](std::string_view line) {
        // Split on '|' into up to 14 tokens (the `inv` prefix + 12 blob fields + install_location).
        // Anything past the 14th token is dropped — the same truncation the server's parse
        // applies past its last field, so fields can never shift.
        const auto tok = split_tokens(line, 14);
        if (tok.empty() || tok[0] != "inv")
            return true; // skip app|, user_app|, error|, found|, etc.
        if (tok.size() < 2 || tok[1].empty())
            return true; // malformed / empty name

        // Blob contract field order; missing trailing tokens → empty fields.
        SwEntry e;
        const auto field = [&tok](std::size_t i) -> std::string {
            return tok.size() > i ? clamp_field(tok[i], kV3MaxFieldLen) : std::string{};
        };
        e.name = field(1);
        e.version = field(2);
        e.publisher = field(3);
        e.install_date = field(4);
        e.kind = field(5);
        e.ecosystem = field(6);
        e.epoch = field(7);
        e.release = field(8);
        e.arch = field(9);
        e.signature_status = field(10);
        e.distro_id = field(11);
        e.distro_version = field(12);
        e.install_location = field(13);
        // Drop a name that became empty AFTER clamping (e.g. a separator-only
        // name). The server's parse drops empty-name rows, so the agent must too or
        // the two section hashes diverge → permanent always-full (governance UP-1).
        // Mirrors the server's `!e.name.empty()`.
        if (!e.name.empty())
            entries.push_back(std::move(e));
        return entries.size() <= kV3MaxRows;
    });
    return entries;
}

AdaptedRows parse_pkg_inventory_packages_output(const std::string& out) {
    // package|homebrew|<id>|<version>|<formula|cask>
    // package|chocolatey|<id>|<version or ->|pkg
    // A row whose id carries an escaped `\|` splits wider than five tokens, fails the width
    // check below and is dropped (a gap, never a shifted row); this adapter does not unescape.
    return adapt_pkg_inventory(out, kActionPackages,
                               [](const std::vector<std::string_view>& tok,
                                  std::vector<SwEntry>& entries) {
        if (tok[0] != "package" || tok.size() != 5)
            return false;
        const ManagerEcosystem* m = find_manager(tok[1]);
        if (!m || m->package_action != kActionPackages)
            return false;
        SwEntry e;
        e.name = clamp_field(tok[2], kV3MaxFieldLen);
        if (e.name.empty())
            return true;
        if (tok[4] == "formula")
            e.kind = "pkg";
        else if (tok[4] == "cask")
            e.kind = "app";
        else if (tok[4] == "pkg")
            e.kind = "pkg"; // Chocolatey
        else
            return true;
        // `-` is the row grammar's empty-version sentinel (format_package_row), written for a
        // Chocolatey package whose nuspec was unreadable.
        e.version = tok[3] == "-" ? std::string{} : clamp_field(tok[3], kV3MaxFieldLen);
        e.ecosystem = std::string(m->ecosystem);
        entries.push_back(std::move(e));
        return true;
    });
}

AdaptedRows parse_pkg_inventory_store_packages_output(const std::string& out) {
    // package|<snap|flatpak|appx>|<id>|<version or ->|<kind>|<revision or ->|<arch or ->|<branch or ->|<state>
    // Appx: <id> is the PackageFullName (Name_Version_Arch_ResourceId_PublisherId); the entry's
    // name is the Name part, its version and arch come from tok[3] / tok[6] (`-` = unknown),
    // there is no release, and a `deprovisioned` row is seen but not mapped. A degraded appx
    // row whose registry key carries a '|' (an escaped `\|` on the wire; a parseable
    // PackageFullName never does) splits to ten tokens, fails the `!= 9` check below and is
    // dropped: a gap, never a shifted row. The split is not escape-aware because this adapter
    // is shared with snap/flatpak and never unescapes (it would store `Weird\|Key` as a name).
    // ACTIVE rows only: an inactive or unknown revision is on disk but is not
    // installed software. A degraded active row (version `-`, kind `unknown`) is
    // still collected (honest-empty version), never a reason to constrain the facet.
    // Flatpak `version` is deliberately empty: tok[7] is a branch (a ref such as
    // `stable`/`51`), not a version, and SwEntry has no field for it; the commit
    // rides in `release`.
    return adapt_pkg_inventory(out, kActionStorePackages,
                               [](const std::vector<std::string_view>& tok,
                                  std::vector<SwEntry>& entries) {
        if (tok[0] != "package" || tok.size() != 9)
            return false;
        const ManagerEcosystem* m = find_manager(tok[1]);
        if (tok[8] != "active" || !m || m->package_action != kActionStorePackages)
            return true; // seen, not mapped
        SwEntry e;
        e.name = clamp_field(tok[2], kV3MaxFieldLen);
        if (e.name.empty())
            return true;
        e.kind = tok[4] == "app" ? "app" : "pkg";
        e.ecosystem = std::string(m->ecosystem);
        if (m->manager == "appx") {
            // Name_Version_...: the entry is the package name, never the 5-part identity string.
            e.name = clamp_field(tok[2].substr(0, tok[2].find('_')), kV3MaxFieldLen);
            if (e.name.empty())
                return true;
            e.version = tok[3] == "-" ? std::string{} : clamp_field(tok[3], kV3MaxFieldLen);
            e.arch = tok[6] == "-" ? std::string{} : clamp_field(tok[6], kV3MaxFieldLen);
            entries.push_back(std::move(e));
            return true;
        }
        if (m->manager == "snap")
            e.version = tok[3] == "-" ? std::string{} : clamp_field(tok[3], kV3MaxFieldLen);
        else
            e.arch = tok[6] == "-" ? std::string{} : clamp_field(tok[6], kV3MaxFieldLen);
        e.release = tok[5] == "-" ? std::string{} : clamp_field(tok[5], kV3MaxFieldLen);
        entries.push_back(std::move(e));
        return true;
    });
}

AdaptedRows parse_pkg_inventory_managers_output(const std::string& out) {
    // manager|<name>|<present|unavailable>|<version or ->|<root>|<facts>|<reason>
    // A PRESENCE row only (the row has no field for the prefix, so two Homebrew
    // prefixes collapse to one row after dedup). Only a manager whose kManagerEcosystems row
    // has `presence_row` (homebrew, chocolatey, winget) becomes an entry; any other manager
    // (and any name absent from the table: dpkg/apt/rpm/dnf/pacman/apk) is dropped, so a
    // new managers leg needs a deliberate mapping, and manager facts belong to facet rows.
    return adapt_pkg_inventory(out, kActionManagers,
                               [](const std::vector<std::string_view>& tok,
                                  std::vector<SwEntry>& entries) {
        if (tok[0] != "manager" || tok.size() != 7 || tok[2] != "present")
            return false;
        // A present row that maps to nothing (a Linux dpkg/apt row) is dropped below.
        const ManagerEcosystem* m = find_manager(tok[1]);
        if (!m || !m->presence_row) {
            spdlog::debug("sync: pkg_inventory manager '{}' has no installed_software mapping — "
                          "dropped",
                          tok[1]);
            return true;
        }
        SwEntry e;
        e.name = std::string(m->manager);
        e.version = tok[3] == "-" ? std::string{} : clamp_field(tok[3], kV3MaxFieldLen);
        // The vendor the table declares for this presence row (middleware precedent), else
        // empty, which `vendor_or_origin` labels `via:<ecosystem>`.
        e.publisher = std::string(m->presence_publisher);
        e.kind = "app";
        e.ecosystem = std::string(m->ecosystem);
        entries.push_back(std::move(e));
        return true;
    });
}

AdaptedRows parse_msi_packages_list_inventory_output(const std::string& out) {
    // inv|<product_code>|<name>|<version>|<publisher>, machine-context MSI products.
    // The producer deletes '|', tab, CR, LF and NUL from the fields (msi_packages_inventory.hpp
    // strip_row_breakers), so no unescape is needed here and an over-wide row can only be
    // malformed. A constrained status (an enumeration error or a failed property
    // read) is a status-only `constrained` section: the stored msi rows are kept.
    return adapt_pkg_inventory(out, "list_inventory",
                               [](const std::vector<std::string_view>& tok,
                                  std::vector<SwEntry>& entries) {
        if (tok[0] != "inv" || tok.size() != 5)
            return false;
        SwEntry e;
        e.name = clamp_field(tok[2], kV3MaxFieldLen);
        if (e.name.empty())
            return true; // seen, not mapped: the server drops empty names (also the advertised-only shape)
        e.version = clamp_field(tok[3], kV3MaxFieldLen);
        e.publisher = clamp_field(tok[4], kV3MaxFieldLen);
        e.kind = "pkg";
        e.ecosystem = "msi";
        e.package_id = clamp_field(tok[1], kV3MaxFieldLen);
        entries.push_back(std::move(e));
        return true;
    });
}

AdaptedRows parse_runtimes_python_output(const std::string& out, bool vendor_column_is_vendor) {
    // python|<flavour>|<version or ->|<install_path or ->|<vendor or ->, one row per interpreter the
    // runtimes plugin found at the standard machine roots (agents/plugins/runtimes/src/
    // runtimes_python_parsers.hpp). The status row is the shared inventory grammar. Every row
    // becomes one {name Python, kind app, ecosystem python} entry whose version is the row's
    // (`-` = unknown -> empty; on Linux it is major.minor, the patch level is not available there).
    // The vendor rides in `publisher` (`-` = unknown) wherever the column is read as a vendor
    // (Windows PythonCore; the Linux producer always emits `-`); on macOS it is a
    // CFBundleIdentifier reverse-domain id, an identifier and not a vendor, so it is ignored
    // there (`vendor_column_is_vendor` false) and the collector labels the row `via:python`,
    // the same rule as macos_pkgutil. The flavour and path have no installed_software slot and
    // are dropped.
    // The producer escapes a literal pipe in the free-text fields (runtimes_parsers.hpp
    // field_or_dash -> safe_output_field gives `\|`), so the split is escape-aware: width stays
    // strict (five logical fields); the version is dotted digits by construction on every leg, and
    // the vendor is unescaped (`\|` -> `|`) before it is stored.
    return adapt_pkg_inventory(out, "python",
                               [vendor_column_is_vendor](const std::vector<std::string_view>& tok,
                                            std::vector<SwEntry>& entries) {
        if (tok[0] != "python" || tok.size() != 5)
            return false;
        SwEntry e;
        e.name = "Python";
        e.version = tok[2] == "-" ? std::string{} : clamp_field(tok[2], kV3MaxFieldLen);
        // The vendor column is free text (the producer escapes a literal pipe as `\|`), so it
        // is unescaped here; `-` = unknown, left empty for the collector's via:python label.
        if (vendor_column_is_vendor && tok[4] != "-")
            e.publisher = clamp_field(unescape_pipes(tok[4]), kV3MaxFieldLen);
        e.kind = "app";
        e.ecosystem = "python";
        entries.push_back(std::move(e));
        return true;
    }, /*escaped=*/true);
}

AdaptedRows parse_runtimes_dotnet_output(const std::string& out) {
    // dotnet|<flavour>|<version or ->|<install_path or ->|<vendor or -> (runtimes plugin: runtime
    // /sdk/netfx on Windows, core/sdk/unmodelled on Linux and macOS). Same shape and escape-aware
    // split as the python adapter; the vendor column is dropped, the publisher is always Microsoft.
    return adapt_pkg_inventory(out, "dotnet",
                               [](const std::vector<std::string_view>& tok,
                                  std::vector<SwEntry>& entries) {
        if (tok[0] != "dotnet" || tok.size() != 5)
            return false;
        SwEntry e;
        if (tok[1] == "runtime" || tok[1] == "core")
            e.name = ".NET Runtime";
        else if (tok[1] == "sdk")
            e.name = ".NET SDK";
        else if (tok[1] == "netfx")
            e.name = ".NET Framework";
        else
            e.name = ".NET";
        e.version = tok[2] == "-" ? std::string{} : clamp_field(tok[2], kV3MaxFieldLen);
        e.publisher = "Microsoft";
        e.kind = "app";
        e.ecosystem = "dotnet";
        entries.push_back(std::move(e));
        return true;
    }, /*escaped=*/true);
}

AdaptedRows parse_runtimes_jvm_output(const std::string& out) {
    // jvm|<flavour>|<version or ->|<install_path or ->|<vendor or ->. The vendor is the release
    // file's IMPLEMENTOR, free text the producer escapes, so the split is escape-aware; the vendor
    // is clamped and stored as the publisher.
    return adapt_pkg_inventory(out, "jvm",
                               [](const std::vector<std::string_view>& tok,
                                  std::vector<SwEntry>& entries) {
        if (tok[0] != "jvm" || tok.size() != 5)
            return false;
        SwEntry e;
        if (tok[1] == "jdk")
            e.name = "Java JDK";
        else if (tok[1] == "jre")
            e.name = "Java JRE";
        else
            e.name = "Java";
        e.version = tok[2] == "-" ? std::string{} : clamp_field(tok[2], kV3MaxFieldLen);
        e.publisher = tok[4] == "-" ? std::string{} : clamp_field(tok[4], kV3MaxFieldLen);
        e.kind = "app";
        e.ecosystem = "jvm";
        entries.push_back(std::move(e));
        return true;
    }, /*escaped=*/true);
}

AdaptedRows parse_middleware_output(const std::string& out, std::string_view action) {
    // <id>|<title>|<name>|<version or ->|<install_path>|<edition or ->  (install_path and
    // edition are not carried). Free-text fields arrive escape-aware (a path may hold `\|`), so
    // the split is too. Name, publisher, kind and ecosystem come from the plugin's own product
    // table, never from the row.
    const yuzu::middleware::Product* p = yuzu::middleware::find_product(action);
    if (p == nullptr)
        return failed("unknown middleware product");
    return adapt_pkg_inventory(out, action,
                               [p, action](const std::vector<std::string_view>& tok,
                                           std::vector<SwEntry>& entries) {
        if (tok[0] != action || tok.size() != 6)
            return false;
        // The title column is fixed vocabulary from the table: with no per-product title span a
        // row can only carry p->title, anything else is seen but not mapped (siblings kept). The
        // token keeps its wire escapes, so this raw compare is only exact because
        // products_well_formed() accepts only a title the wire form leaves unchanged: printable ASCII
        // without `|` or `\` (middleware_products.hpp).
        if (tok[1] == p->title) {
            SwEntry e;
            e.name = p->title;
            e.version = tok[3] == "-" ? std::string{} : clamp_field(tok[3], kV3MaxFieldLen);
            e.publisher = p->vendor;
            e.kind = p->kind;
            e.ecosystem = p->ecosystem;
            entries.push_back(std::move(e));
        }
        return true;
    }, /*escaped=*/true);
}

AdaptedRows parse_windows_optional_features_output(const std::string& out) {
    // windows_optional_features_parsers.hpp: `feature|<name>|<state>|<0/1>` per
    // feature (no status row in this grammar); sentinels are 3-token
    // `feature|unsupported|<token>` / `feature|unavailable|<token>`. The restart
    // flag is dropped (transient, no slot); the state token rides in `version`.
    AdaptedRows res;
    AdaptedRows sentinel; // status != ok once an unsupported/unavailable sentinel row is seen
    for_each_line(out, [&](std::string_view line) {
        const auto tok = split_tokens(line, 5);
        if (tok[0] != "feature")
            return true;
        if (tok.size() == 3 && tok[1] == "unsupported") {
            sentinel.status = AdaptedRows::Status::unsupported;
            return false;
        }
        if (tok.size() == 3 && tok[1] == "unavailable") {
            sentinel = failed(std::string(tok[2]));
            return false;
        }
        if (tok.size() != 4)
            return true;
        SwEntry e;
        e.name = clamp_field(tok[1], kV3MaxFieldLen);
        if (e.name.empty())
            return true;
        e.version = clamp_field(tok[2], kV3MaxFieldLen);
        e.publisher = "Microsoft"; // DISM features are Windows components: constant vendor
        e.kind = "feat";
        e.ecosystem = "optional_feature";
        res.entries.push_back(std::move(e));
        return res.entries.size() <= kV3MaxRows;
    });
    if (sentinel.status != AdaptedRows::Status::ok)
        return sentinel;
    if (res.entries.empty())
        return failed("no rows");
    return res;
}

AdaptedRows parse_hardware_drivers_inventory_output(const std::string& out,
                                                    bool kernel_module_leg) {
    // driver_inv|<name>|<version>|<date>|<provider>|<class>|<signer>|<signed>|<inf>|<hwid>
    // (hardware_drivers_inventory.hpp). Every absent value is `-`; free text is escaped by the
    // producer (`\|`), so the split is escape-aware and each text field is unescaped. The class,
    // INF and hardware id have no slot and are dropped. A row with no name is seen, not mapped
    // (the server drops nameless rows).
    const auto text = [](std::string_view t) {
        return t == "-" ? std::string{} : clamp_field(unescape_pipes(t), kV3MaxFieldLen);
    };
    return adapt_pkg_inventory(out, "drivers_inventory",
                               [kernel_module_leg, &text](const std::vector<std::string_view>& tok,
                                                          std::vector<SwEntry>& entries) {
        if (tok[0] != "driver_inv" || tok.size() != 10)
            return false;
        SwEntry e;
        e.name = text(tok[1]);
        if (e.name.empty())
            return true;
        e.version = text(tok[2]);
        e.install_date = text(tok[3]);
        // The Linux provider is the fixed literal `kernel`: a label for the source, not a vendor,
        // so it is not carried and the row reads `via:kernel_module`. Windows carries the
        // driver's provider, else its signer.
        if (!kernel_module_leg) {
            e.publisher = text(tok[4]);
            if (e.publisher.empty())
                e.publisher = text(tok[6]);
        }
        if (tok[7] == "signed" || tok[7] == "unsigned")
            e.signature_status = std::string(tok[7]);
        e.kind = "driver";
        if (kernel_module_leg)
            e.ecosystem = "kernel_module";
        else
            e.ecosystem = "windows";
        entries.push_back(std::move(e));
        return true;
    }, /*escaped=*/true, /*max_tokens=*/11);
}

std::vector<std::tuple<std::string_view, std::string_view, std::chrono::seconds>>
installed_software_actions() {
    std::vector<std::tuple<std::string_view, std::string_view, std::chrono::seconds>> out;
    for (const auto& row : kInventoryActions)
        out.emplace_back(row.plugin, row.action, row.time_limit);
    return out;
}

void vendor_or_origin(SwEntry& e) {
    if (e.publisher.empty())
        e.publisher =
            std::string(kOriginLabelPrefix) + (e.ecosystem.empty() ? "unknown" : e.ecosystem);
}

bool CollectorWorkers::try_begin(std::string_view facet) {
    std::lock_guard<std::mutex> lk(mu_);
    return busy_.emplace(std::string(facet)).second;
}

void CollectorWorkers::end(std::string_view facet) noexcept {
    std::lock_guard<std::mutex> lk(mu_);
    if (const auto it = busy_.find(facet); it != busy_.end())
        busy_.erase(it);
}

std::size_t CollectorWorkers::outstanding() const {
    std::lock_guard<std::mutex> lk(mu_);
    return busy_.size();
}

bool drain_collector_workers(const CollectorWorkers& workers, std::chrono::milliseconds grace,
                             const std::function<void(std::size_t)>& on_stuck) {
    if (wait_for_workers_to_drain([&workers] { return workers.outstanding(); }, grace))
        return true;
    if (on_stuck)
        on_stuck(workers.outstanding());
    return false;
}

namespace {

// Per-call capture cap: the 13-field rows (~200 B each raw) would saturate the shared 2 MiB
// default around ~14k packages, turning a dense host into a permanently oversize facet. 3.5 MiB
// re-aligns the capture ceiling with the 3 MiB blob cap (a ~17k-row facet is ~3 MiB; raw rows
// are larger than their canonical form). The shared default stays 2 MiB. A facet whose rows
// fill this is `truncated`, and one whose FULL section would exceed the blob is `oversize`.
constexpr std::size_t kInventoryCaptureCap = 3'670'016; // 3.5 MiB

// One facet's answer for one pass: either rows (status full) or the reason it has none.
struct Collected {
    V3Status status{V3Status::not_collected};
    std::string token;
    std::vector<SwEntry> rows; // stamped with the source, not yet in normal form
    std::int64_t duration_ms{0};
    std::int64_t bytes_read{0};
};

struct FacetState {
    std::string source;
    std::string acked_key;
    std::string need_full_key;
    std::optional<AckedSet> acked;
    bool need_full{false};
    bool need_full_persisted{false};
    // What the last collect() put in the blob; committed by on_ack, dropped by the next collect.
    bool pending_rows{false};
    AckedSet pending;
    // A status-only section as the server last acknowledged it. While the facet keeps answering
    // the same {status, token} the section is left out (an unchanged section is omitted, so a
    // quiet host sends a hash-only report). Memory only: a restart costs one resend, which the
    // server's upsert makes harmless. Cleared by a nack, by a forced send and by a row-bearing
    // section being acknowledged.
    struct StatusKey {
        V3Status status{V3Status::not_collected};
        std::string token;
        bool operator==(const StatusKey&) const = default;
    };
    std::optional<StatusKey> last_status;
    // The status-only section this collect put in the blob (engaged = one was sent); committed
    // into last_status by on_ack, dropped by the next collect.
    std::optional<StatusKey> pending_status;
    // The cooldown cache (kPassCooldown).
    std::optional<Collected> cache;
    std::chrono::steady_clock::time_point cache_at{};
};

struct CollectorState {
    SyncPluginMap plugins;
    SyncScheduler::KvGetFn kv_get;
    SyncScheduler::KvSetFn kv_set;
    std::shared_ptr<CollectorWorkers> workers;
    CollectorClock clock;
    std::chrono::milliseconds time_limit_override{0};
    CollectorRunner runner;
    std::vector<FacetState> facets; // parallel to kInventoryActions
    // Answers that declared no completeness (UNKNOWN), counted over the agent's life and
    // published as the heartbeat tag yuzu.sync.installed_software.completeness_unknown_total.
    std::string unknown_total_key;
    std::uint64_t unknown_total{0};
    bool loaded{false};
    bool emitted{false}; // the last collect() put at least one section in the blob
    bool more{false};    // ...and left a row-bearing section for the next one

    void ensure_loaded() {
        if (loaded)
            return;
        loaded = true;
        for (auto& f : facets) {
            const std::string v = kv_get(f.acked_key);
            f.acked = acked_decode(v);
            if (!v.empty() && !f.acked)
                spdlog::warn("sync: installed_software '{}' acked state is unreadable — "
                             "that facet is sent in full",
                             f.source);
            f.need_full_persisted = kv_get(f.need_full_key) == "1";
            f.need_full = f.need_full_persisted;
        }
        unknown_total = std::strtoull(kv_get(unknown_total_key).c_str(), nullptr, 10);
    }

    void set_need_full(FacetState& f, bool on) {
        f.need_full = on;
        if (on != f.need_full_persisted) {
            kv_set(f.need_full_key, on ? "1" : "0");
            f.need_full_persisted = on;
        }
    }

    // Dispatch one action under its time limit and turn the answer into a Collected.
    Collected dispatch(std::size_t i) {
        const InventoryAction& row = kInventoryActions[i];
        const std::string& source = facets[i].source;
        Collected c;
        const auto it = plugins.find(row.plugin);
        if (it == plugins.end() || it->second == nullptr) {
            spdlog::warn("sync: {} plugin not loaded — {} is reported not_collected", row.plugin,
                         source);
            c.token = "not_loaded";
            return c;
        }
        // Single-flight: a worker of this facet that outlived its time limit is still inside the
        // plugin. A second dispatch would pile another thread into the same plugin.
        if (!workers->try_begin(source)) {
            spdlog::warn("sync: {} is still running from an earlier pass — reported timeout:busy",
                         source);
            c.status = V3Status::timeout;
            c.token = "busy";
            return c;
        }
        const auto t0 = std::chrono::steady_clock::now();
        // The dispatcher is built INSIDE the worker and the single-flight flag is released by a
        // guard inside it too: whichever of Completed and TimedOut the caller sees, the flag is
        // cleared when the worker physically returns (or throws), never before. A Rejected call
        // never invoked the lambda, so no guard exists and the caller clears the flag below.
        using Result = LocalDispatcher::Result;
        std::function<Result()> fn = [workers = workers, desc = it->second,
                                      action = std::string(row.action), source]() -> Result {
            struct Release {
                CollectorWorkers& w;
                const std::string& k;
                ~Release() { w.end(k); }
            } release{*workers, source};
            try {
                LocalDispatcher d;
                return d.run(desc, action, {}, kInventoryCaptureCap);
            } catch (...) {
                Result failed_run;
                failed_run.rc = -1;
                return failed_run;
            }
        };
        const auto limit = time_limit_override.count() > 0
                               ? time_limit_override
                               : std::chrono::duration_cast<std::chrono::milliseconds>(row.time_limit);
        auto call = runner ? runner(limit, std::move(fn))
                           : yuzu::shared::bounded_call_ex(limit, std::move(fn));
        c.duration_ms = std::chrono::duration_cast<std::chrono::milliseconds>(
                            std::chrono::steady_clock::now() - t0)
                            .count();
        if (call.status == yuzu::shared::BoundedCallStatus::Rejected) {
            workers->end(source);
            spdlog::warn("sync: {} could not start a worker (outstanding-call ceiling or thread "
                         "creation) — reported timeout:rejected",
                         source);
            c.status = V3Status::timeout;
            c.token = "rejected";
            return c;
        }
        if (call.status == yuzu::shared::BoundedCallStatus::TimedOut) {
            spdlog::warn("sync: {} did not return within {} ms — reported timeout; the worker is "
                         "left to finish",
                         source, limit.count());
            c.status = V3Status::timeout;
            c.token = "timeout";
            return c;
        }
        const LocalDispatcher::Result& r = *call.value;
        c.bytes_read = static_cast<std::int64_t>(r.captured.size());
        if (r.rc != 0 || r.truncated) {
            // A truncated capture would be a partial roster and a hash that flip-flops: report it,
            // send no rows.
            spdlog::warn("sync: {} rc={}{} — reported constrained", source, r.rc,
                         r.truncated ? " (output truncated at the capture cap)" : "");
            c.status = V3Status::constrained;
            c.token = r.rc != 0 ? "rc=" + std::to_string(r.rc) : "truncated";
            return c;
        }
        AdaptedRows rows = row.adapt(r.captured);
        if (rows.entries.size() > kV3MaxRows) {
            // Every adapter stops reading at kV3MaxRows + 1 RAW rows, so the post-dedup count
            // cannot see the overflow once exact duplicates pull it back under the cap — a
            // truncated inventory would ship as complete.
            spdlog::warn("sync: {} read more than {} rows — reported oversize", source, kV3MaxRows);
            c.status = V3Status::oversize;
            c.token = "rows=" + std::to_string(rows.entries.size());
            return c;
        }
        const auto reason_or = [&rows](const char* fallback) {
            return (rows.reason.empty() || rows.reason == "-") ? std::string(fallback) : rows.reason;
        };
        switch (rows.status) {
        case AdaptedRows::Status::unsupported:
            spdlog::debug("sync: {} unsupported on this OS — reported not_collected", source);
            c.token = reason_or("unsupported");
            return c;
        case AdaptedRows::Status::failed:
            spdlog::warn("sync: {} failed: {} — reported constrained", source, rows.reason);
            c.status = V3Status::constrained;
            c.token = reason_or("failed");
            return c;
        case AdaptedRows::Status::constrained:
            spdlog::info("sync: {} constrained ({}) — reported constrained; its stored rows are "
                         "kept and read as unconfirmed",
                         source, rows.reason);
            c.status = V3Status::constrained;
            c.token = reason_or("constrained");
            return c;
        case AdaptedRows::Status::ok:
            break;
        }
        if (r.result_completeness != YUZU_RESULT_COMPLETENESS_FULL) {
            // Only a plugin that declares FULL is believed to have read everything. PARTIAL
            // overrides rows the plugin did hand over (a partial roster); an answer that declares
            // nothing (UNKNOWN) is not FULL either and is the one counted and persisted at once
            // (rare).
            const bool partial = r.result_completeness == YUZU_RESULT_COMPLETENESS_PARTIAL;
            if (partial) {
                spdlog::warn("sync: {} typed result completeness PARTIAL — reported constrained",
                             source);
            } else {
                kv_set(unknown_total_key, std::to_string(++unknown_total));
                spdlog::warn("sync: {} declared no result completeness — reported constrained "
                             "(unknown), never read as full",
                             source);
            }
            c.status = V3Status::constrained;
            c.token = !partial                     ? "unknown"
                      : r.result_provenance.empty() ? "partial"
                                                    : r.result_provenance;
            return c;
        }
        for (auto& e : rows.entries)
            e.source = source;
        c.status = V3Status::full;
        c.rows = std::move(rows.entries);
        return c;
    }
};

} // namespace

SyncSource make_installed_software_source(SyncPluginMap plugins, SyncScheduler::KvGetFn kv_get,
                                          SyncScheduler::KvSetFn kv_set,
                                          std::shared_ptr<CollectorWorkers> workers,
                                          CollectorTuning tuning) {
    SyncSource src;
    src.name = "installed_software";
    src.interval = std::chrono::hours{24};
    // No weekly blanket resend: the server's per-section checks (a delta over a base that no
    // longer matches is refused, answered `installed_software:<facet>` and resent in full) heal a
    // diverged facet on their own.
    src.no_full_floor = true;
    // Nightly maintenance window, 01:00-05:00 machine-local time (a compile-time default:
    // no settings channel exists yet). Each agent keeps a stable moment inside it.
    src.window = SyncWindow{60, 300};

    auto st = std::make_shared<CollectorState>();
    st->plugins = std::move(plugins);
    st->kv_get = std::move(kv_get);
    st->kv_set = std::move(kv_set);
    st->workers = std::move(workers);
    st->clock = tuning.clock ? std::move(tuning.clock)
                             : CollectorClock{[] { return std::chrono::steady_clock::now(); }};
    st->time_limit_override = tuning.time_limit;
    st->runner = std::move(tuning.runner);
    st->unknown_total_key =
        SyncScheduler::kv_key("installed_software", kCompletenessUnknownTotalKey);
    for (const auto& row : kInventoryActions) {
        FacetState f;
        f.source = std::string(row.plugin) + '.' + std::string(row.action);
        f.acked_key = SyncScheduler::kv_key("installed_software", (f.source + ".acked").c_str());
        f.need_full_key =
            SyncScheduler::kv_key("installed_software", (f.source + ".need_full").c_str());
        st->facets.push_back(std::move(f));
    }

    src.on_force_full = [st] {
        st->ensure_loaded();
        for (auto& f : st->facets) {
            f.need_full = true;    // this send is full for every facet; nothing to persist
            f.last_status.reset(); // ...and carries every status-only section again, so a forced
                                   // blob is never header-only (the server refuses one)
        }
    };

    src.wants_blob = [st] { return st->emitted; };
    src.has_more = [st] { return st->more; };

    src.on_ack = [st](const std::vector<std::string>& tokens) {
        st->ensure_loaded();
        constexpr std::string_view kName = "installed_software";
        bool whole = false;
        std::set<std::string, std::less<>> nacked;
        for (const auto& t : tokens) {
            // The scheduler passes only this source's tokens: `installed_software` or
            // `installed_software:<facet>`.
            if (t == kName)
                whole = true;
            else
                nacked.insert(t.substr(kName.size() + 1));
        }
        for (auto& f : st->facets) {
            const bool facet_nacked = whole || nacked.contains(f.source);
            if (facet_nacked) {
                // Nothing of this facet is committed: it is resent in full. A whole-source nack
                // commits nothing at all (the blob may not have been attributable).
                st->set_need_full(f, true);
                f.last_status.reset();
            } else if (f.pending_rows) {
                f.acked = f.pending;
                st->kv_set(f.acked_key, acked_encode(*f.acked)); // ONE value: hash and set together
                st->set_need_full(f, false);
                f.last_status.reset();
            } else if (f.pending_status) {
                // The server refuses a delta over any facet whose stored status is not full or
                // delta, so after a status-only section the next row-bearing one must be full.
                f.acked.reset();
                st->kv_set(f.acked_key, std::string{});
                st->set_need_full(f, false);
                f.last_status = f.pending_status;
            }
            f.pending_rows = false;
            f.pending_status.reset();
            f.pending = AckedSet{};
        }
    };

    src.collect = [st]() -> std::optional<std::pair<std::string, std::string>> {
        st->ensure_loaded();
        const auto now = st->clock();
        std::vector<SectionPlan> plans;
        plans.reserve(st->facets.size());
        for (std::size_t i = 0; i < st->facets.size(); ++i) {
            FacetState& f = st->facets[i];
            f.pending_rows = false;
            // A status section sent and never acknowledged (the response was lost) leaves the
            // server's state unknown, so what was last acknowledged proves nothing about it.
            if (f.pending_status)
                f.last_status.reset();
            f.pending_status.reset();
            f.pending = AckedSet{};
            // A pass inside the cooldown rebuilds from the rows already collected. Everything
            // else dispatches; a timeout is never cached (it must see the worker's state afresh).
            std::optional<Collected> local;
            const Collected* c = nullptr;
            if (f.cache && now - f.cache_at < kPassCooldown) {
                c = &*f.cache;
            } else {
                local = st->dispatch(i);
                if (local->status != V3Status::timeout) {
                    f.cache = std::move(local);
                    f.cache_at = now;
                    c = &*f.cache;
                } else {
                    f.cache.reset();
                    c = &*local;
                }
            }
            SectionPlan plan = c->status == V3Status::full
                                   ? plan_section(f.source, c->rows, f.acked, f.need_full)
                                   : status_section(f.source, c->status, c->token);
            // A status-only answer the server already holds is not sent again.
            if (!v3_status_carries_rows(plan.status) && f.last_status &&
                *f.last_status == FacetState::StatusKey{plan.status, plan.token})
                plan.unchanged = true;
            plan.duration_ms = c->duration_ms;
            plan.bytes_read = c->bytes_read;
            plans.push_back(std::move(plan));
        }
        V3Blob out = write_v3_blob(plans);
        st->emitted = !out.sent.empty();
        st->more = !out.deferred.empty();
        std::vector<std::pair<std::string, std::string>> held;
        for (std::size_t i = 0; i < st->facets.size(); ++i) {
            FacetState& f = st->facets[i];
            const SectionPlan& plan = plans[i];
            const bool sent =
                std::find(out.sent.begin(), out.sent.end(), plan.facet) != out.sent.end();
            if (sent && v3_status_carries_rows(plan.status)) {
                f.pending_rows = true;
                f.pending = AckedSet{plan.section_hash, plan.row_hashes};
                held.emplace_back(f.source, plan.section_hash);
            } else if (sent) {
                // held no longer: the server drops it from its report hash
                f.pending_status = FacetState::StatusKey{plan.status, plan.token};
            } else if (f.acked) {
                held.emplace_back(f.source, f.acked->section_hash); // unchanged or deferred
            }
        }
        std::string hash = v3_report_hash(std::move(held));
        return std::make_pair(std::move(out.blob), std::move(hash));
    };
    return src;
}

} // namespace yuzu::agent
