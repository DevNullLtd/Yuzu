#pragma once

#include <yuzu/plugin.h>

#include <array>
#include <cstddef>
#include <cstdint> // SIZE_MAX (sha256_file max_bytes default)
#include <expected>
#include <filesystem>
#include <memory>
#include <optional>
#include <string>
#include <string_view>
#include <unordered_map>
#include <vector>

namespace yuzu::agent {

struct LoadError {
    std::string path;
    std::string reason;
};

/// Plugin names the agent reserves for internal dispatch (Guardian engine,
/// future system/OTA intercepts). Third-party plugins loaded at scan time
/// that declare one of these names are rejected so a compromised or
/// misconfigured plugin author cannot shadow the reserved dispatch paths.
/// See docs/yuzu-guardian-design-v1.1.md §7.2 for `__guard__`.
///
/// The `__guardian*__` / `__sync__` entries are agent-internal kv_store
/// namespaces. They MUST stay reserved because yuzu_ctx_storage_* keys KvStore
/// by the plugin's OWN declared name, on the SAME connection these subsystems
/// use, so a plugin allowed to claim one of those names could read, delete, or
/// forge the state the subsystem loads as authoritative:
///   - `__guardian__`         GuardianEngine rule-state (loaded as live policy
///                            at boot) -> a claimant could forge Guardian rules.
///   - `__guardian_journal__` Guardian lifecycle journal (arm/disarm audit
///                            records replayed over the authenticated stream).
///   - `__sync__`             daily-sync scheduler state (last-hash / need_full)
///                            -> a claimant could force or suppress a sync.
/// Native plugins are trusted (the ABI has no sandbox), so this is a hygiene /
/// audit-integrity control, not isolation. Each namespace constant lives in its
/// owning src/ header, which this include/ header cannot include without
/// inverting the layering, so the literals are duplicated here and pinned to
/// their source constant by a static_assert in the owning translation unit
/// (guardian_lifecycle_journal.cpp, guardian_engine.cpp, agent.cpp) so they
/// cannot drift. See docs/cpp-conventions.md and docs/yuzu-guardian-design-v1.1.md §7.2.
inline constexpr std::array<std::string_view, 6> kReservedPluginNames{
    "__guard__",            // Guardian engine command dispatch (design v1.1 §7.2)
    "__system__",           // reserved for future system-scope commands
    "__update__",           // reserved for OTA update commands
    "__guardian_journal__", // Guardian lifecycle journal kv namespace (#2303 C2)
    "__guardian__",         // GuardianEngine rule-state kv namespace (#2303 sec-M)
    "__sync__",             // daily-sync scheduler-state kv namespace (#2303 sec-L)
};

/// Stable reason prefix recorded in LoadError::reason when a plugin is
/// rejected because its declared name is in kReservedPluginNames. Callers
/// (e.g. agent metrics) can match on this prefix to count rejections by
/// category without re-parsing free-form text.
inline constexpr std::string_view kReservedNameReason = "reserved plugin name";

/// Maximum length of a plugin's self-declared name. Names are operator-visible
/// identifiers used in logs, Prometheus label values, and the command-dispatch
/// match; bounding them keeps log lines and label cardinality sane and stops a
/// plugin from declaring a pathological multi-kilobyte name.
inline constexpr std::size_t kMaxPluginNameLen = 64;

/// Stable, fixed reason string recorded verbatim in LoadError::reason when a
/// plugin is rejected because its declared name is empty, over-length, or
/// contains a byte outside the identifier set [A-Za-z0-9_]. Unlike
/// kReservedNameReason this carries no variable suffix — the offending name is
/// deliberately NOT echoed, because a crafted name may carry newline or control
/// bytes that would forge log lines / corrupt the error channel. See #822.
inline constexpr std::string_view kInvalidNameReason = "invalid plugin name";

/// Stable reason prefixes for code-signing rejections. The metric label
/// derives from the prefix so operators can alert distinctly on
/// "no signature on plugin in require-mode" vs "bad signature" vs
/// "signature does not chain to a trusted CA".
inline constexpr std::string_view kSignatureMissingReason = "plugin signature missing";
inline constexpr std::string_view kSignatureInvalidReason = "plugin signature invalid";
inline constexpr std::string_view kSignatureUntrustedReason = "plugin signature untrusted chain";

/// Plugin code-signing trust anchor. When `trust_bundle_path` is non-empty,
/// PluginLoader::scan() looks for a sibling `<plugin-file>.sig` (PEM CMS
/// detached signature) for every candidate plugin. If a sig is present it
/// must verify against the bundle. If `require_signature` is true an
/// unsigned plugin is rejected; if false an unsigned plugin still loads
/// (allowlist still applies) — a transitional mode for operators rolling
/// out signing.
///
/// The trust bundle is a PEM file containing one or more X.509 root or
/// intermediate certificates. Today it is operator-supplied; once the
/// self-managed CA (auth-and-authz skill, Section 3 #10) ships the same
/// file path can point at the CA-published root.
struct PluginSigningPolicy {
    std::filesystem::path trust_bundle_path;
    bool require_signature{false};

    [[nodiscard]] bool enabled() const noexcept { return !trust_bundle_path.empty(); }
};

/// Verify a CMS detached PEM signature over the bytes of `plugin_path`,
/// chain-validating the embedded signing cert against the certs loaded
/// from `trust_bundle_path`. Returns std::nullopt on success; on failure
/// returns a stable reason prefix from kSignature*Reason that the loader
/// surfaces to the caller and metrics. Treat the return as "is bad" so
/// the call site reads as `if (auto err = verify_plugin_signature(...))`.
///
/// Sig file convention: same path as the plugin with `.sig` appended
/// (e.g. `chargen.so.sig`). PEM-armoured CMS so it inspects with
/// `openssl cms -inform pem -text -noout -in chargen.so.sig`.
[[nodiscard]] YUZU_EXPORT std::optional<std::string>
verify_plugin_signature(const std::filesystem::path& plugin_path,
                        const std::filesystem::path& trust_bundle_path);

/// True if name matches one of kReservedPluginNames exactly (case-sensitive).
[[nodiscard]] constexpr bool is_reserved_plugin_name(std::string_view name) noexcept {
    for (auto reserved : kReservedPluginNames) {
        if (name == reserved) return true;
    }
    return false;
}

/// True if `name` is a well-formed plugin identifier: non-empty, at most
/// kMaxPluginNameLen bytes, and composed solely of ASCII alphanumerics and the
/// underscore. The character test is written out by hand rather than using
/// std::isalnum — that function is locale-sensitive (so the verdict could
/// differ between hosts) and is undefined behaviour for negative `char` values
/// (high-bit bytes). This is constexpr and locale-independent, so the result is
/// identical on every platform.
///
/// The loader enforces this on a plugin's self-declared name BEFORE any
/// reserved-name or dispatch comparison so a crafted name (NUL-truncation,
/// embedded control bytes, path/pipe/newline characters) can never diverge
/// between the std::string_view security check here and a downstream C-string
/// consumer of descriptor->name. Reserved names (e.g. "__guard__") are
/// themselves valid identifiers — they pass this check and are then rejected
/// by is_reserved_plugin_name. See #822.
[[nodiscard]] constexpr bool is_valid_plugin_name(std::string_view name) noexcept {
    if (name.empty() || name.size() > kMaxPluginNameLen) {
        return false;
    }
    for (const char c : name) {
        const bool ok = (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') ||
                        (c >= '0' && c <= '9') || c == '_';
        if (!ok) {
            return false;
        }
    }
    return true;
}

// Compile-time pins for the is_valid_plugin_name contract (#822). Reserved
// names are themselves valid identifiers (they reach the reserved-name check
// and are rejected there, not here); empty, charset-violating, and embedded-NUL
// names are rejected.
static_assert(is_valid_plugin_name("__guard__"));
static_assert(is_valid_plugin_name("example_42"));
static_assert(!is_valid_plugin_name(""));
static_assert(!is_valid_plugin_name("bad name"));
static_assert(!is_valid_plugin_name(std::string_view{"nul\0byte", 8}));

/// SHA-256 hash a file on disk. Returns lowercase hex, or empty on failure OR if
/// the file exceeds `max_bytes` (a bounded read — defends a hashing-DoS / TOCTOU
/// grow on an attacker-controlled path, e.g. Guardian's file-hash-equals guard).
/// Default SIZE_MAX = unbounded (existing trusted-plugin callers are unchanged).
[[nodiscard]] YUZU_EXPORT std::string sha256_file(const std::filesystem::path& path,
                                                  std::size_t max_bytes = SIZE_MAX);

/// Load a plugin allowlist file (one "sha256  filename" per line, like sha256sum output).
/// Returns a map of filename -> expected hash. Empty map on failure or missing file.
[[nodiscard]] std::unordered_map<std::string, std::string>
load_plugin_allowlist(const std::filesystem::path& allowlist_path);

/**
 * PluginHandle owns a loaded plugin shared library and its descriptor.
 * Unloads the library (dlclose / FreeLibrary) on destruction.
 */
class YUZU_EXPORT PluginHandle {
public:
    PluginHandle() = default;
    PluginHandle(const PluginHandle&) = delete;
    PluginHandle& operator=(const PluginHandle&) = delete;
    PluginHandle(PluginHandle&&) noexcept;
    PluginHandle& operator=(PluginHandle&&) noexcept;
    ~PluginHandle();

    [[nodiscard]] const YuzuPluginDescriptor* descriptor() const noexcept { return descriptor_; }
    [[nodiscard]] std::string_view path() const noexcept { return path_; }

    static std::expected<PluginHandle, LoadError> load(const std::filesystem::path& so_path);

private:
    void* handle_{nullptr};
    const YuzuPluginDescriptor* descriptor_{nullptr};
    std::string path_;
};

/**
 * PluginLoader scans a directory for .so/.dll files, loads each one,
 * verifies the ABI version, and returns handles.
 */
class YUZU_EXPORT PluginLoader {
public:
    struct ScanResult {
        std::vector<PluginHandle> loaded;
        std::vector<LoadError> errors;
    };

    /// Scan plugin_dir, optionally verifying each plugin against an allowlist
    /// (sha256 integrity) and/or a code-signing trust anchor (CMS provenance).
    ///
    /// Verification order per file: allowlist (cheap, fail-fast) → signature
    /// (expensive). A plugin must clear *every* enabled check; the two layers
    /// answer different questions — allowlist binds *this filename to this
    /// hash on this host*, signing binds *this file content to a CA-issued
    /// signing identity*. Operators with internal builds typically enable
    /// both.
    [[nodiscard]] static ScanResult scan(
        const std::filesystem::path& plugin_dir,
        const std::unordered_map<std::string, std::string>& allowlist = {},
        const PluginSigningPolicy& signing = {});
};

} // namespace yuzu::agent
