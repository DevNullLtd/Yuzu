#pragma once

/// @file update_signature_mode.hpp
///
/// What the agent tells an operator about its OTA update-signature posture
/// (#5249): one line at startup, and one heartbeat tag.
///
/// WHY THIS EXISTS. With `--update-trust-bundle` unset, update signature
/// checking is OFF entirely, and nothing said so. A dropped flag, a misspelt
/// environment variable (env names are matched exactly, so a typo is silently
/// ignored where an unknown CLI flag would be refused), or an uninstall that
/// deleted the Windows service's `Environment` value all looked exactly like a
/// healthy, enforcing agent — `yuzu_agent_ota_signature_refused_total` stays 0
/// in every one of those states. This header is the agent's half of the fix:
///
///  * `update_signature_mode()` / `update_signature_mode_name()` — the mode the
///    agent ACTUALLY loaded (`off` / `bundle` / `bundle+require`), derived from
///    the same `UpdateConfig` the updater enforces from, never from a re-read of
///    the environment.
///  * `emit_update_signature_mode_tag()` — the heartbeat tag, so the server and
///    fleet views can find agents that are not enforcing.
///  * `unrecognised_update_env_names()` — the startup typo check.
///  * `build_update_signature_startup_lines()` — the startup log lines, built
///    here (testable) and emitted by `main.cpp` (which is in no test target).
///
/// REPORTING ONLY. Nothing here gates, grants or changes enforcement; the
/// updater and `detached_signature.cpp` remain the sole decision points.

#include <yuzu/plugin.h> // YUZU_EXPORT

#include <yuzu/agent/updater.hpp> // UpdateConfig

#include <span>
#include <string>
#include <string_view>
#include <vector>

namespace yuzu::agent {

enum class UpdateSignatureMode {
    /// No trust bundle: update signatures are not checked at all.
    kOff,
    /// Bundle set, unsigned packages still accepted (transitional, stage 1).
    kBundle,
    /// Bundle set and unsigned packages refused (stage 2).
    kBundleRequire,
};

/// The mode the updater will actually enforce for `cfg`.
///
/// `require_signature` without a bundle is `kOff`, not `kBundleRequire`: the
/// updater only consults `require_signature` inside its bundle branch, so that
/// combination enforces nothing (`UpdateConfig::would_fail_open()`, which
/// `main()` refuses to start on). Reporting it as anything but off would be the
/// exact lie this header exists to remove.
[[nodiscard]] inline UpdateSignatureMode update_signature_mode(const UpdateConfig& cfg) noexcept {
    if (!cfg.signature_checking_enabled())
        return UpdateSignatureMode::kOff;
    return cfg.require_signature ? UpdateSignatureMode::kBundleRequire
                                 : UpdateSignatureMode::kBundle;
}

/// The wire/log spelling. A CLOSED set: the heartbeat tag carries exactly one
/// of these three strings, so a consumer can match on them.
[[nodiscard]] constexpr std::string_view
update_signature_mode_name(UpdateSignatureMode m) noexcept {
    switch (m) {
    case UpdateSignatureMode::kOff:
        return "off";
    case UpdateSignatureMode::kBundle:
        return "bundle";
    case UpdateSignatureMode::kBundleRequire:
        return "bundle+require";
    }
    return "off";
}

/// Heartbeat status-tag key carrying `update_signature_mode_name()`.
///
/// It reports the CONFIGURED mode the agent loaded at startup. It does not say
/// whether the bundle file is currently loadable: the verifier re-reads the
/// bundle on every update and fails closed if it cannot, which is reported as
/// `yuzu_agent_ota_signature_refused_total{reason="bundle_unreadable"}` and is
/// summed into `yuzu.ota_signature_refused`.
inline constexpr std::string_view kTagOtaSignatureMode = "yuzu.ota_signature_mode";

/// Write the mode tag into a heartbeat tag map. `TagMap` is any map with a
/// string `operator[]` — the protobuf `status_tags` map in production
/// (agent.cpp), a `std::map` in tests — so the tag the test pins is the tag the
/// heartbeat sends.
template <typename TagMap>
void emit_update_signature_mode_tag(TagMap& tags, const UpdateConfig& cfg) {
    tags[std::string{kTagOtaSignatureMode}] =
        std::string{update_signature_mode_name(update_signature_mode(cfg))};
}

/// Prefix of the environment variables the startup typo check looks at.
inline constexpr std::string_view kUpdateEnvPrefix = "YUZU_UPDATE_";

/// `YUZU_UPDATE_*` names that are NOT typos. Anything else under the prefix is
/// warned about at startup.
///
///  * The first three are read by the agent's own CLI (`main.cpp` envname).
///  * `YUZU_UPDATE_DIR` is the SERVER's update-directory option. It does not
///    configure the agent at all, but it is a real Yuzu name, and warning
///    "unrecognised" on a host whose environment also feeds a server would send
///    the operator chasing a non-problem.
///
/// Add a name here in the same change that adds an agent `YUZU_UPDATE_*` option,
/// or every agent configured with it warns at startup.
inline constexpr std::string_view kRecognisedUpdateEnvNames[] = {
    "YUZU_UPDATE_TRUST_BUNDLE",
    "YUZU_UPDATE_REQUIRE_SIGNATURE",
    "YUZU_UPDATE_CHECK_INTERVAL",
    "YUZU_UPDATE_DIR",
};

/// Environment-variable names compare case-insensitively on Windows (so
/// `yuzu_update_trust_bundle` IS read there) and case-sensitively elsewhere.
#ifdef _WIN32
inline constexpr bool kEnvNamesCaseInsensitive = true;
#else
inline constexpr bool kEnvNamesCaseInsensitive = false;
#endif

/// The names in `env_names` that start with `YUZU_UPDATE_` but are not in
/// `kRecognisedUpdateEnvNames`, in input order.
///
/// The PREFIX test is always case-insensitive, so a lowercase typo such as
/// `yuzu_update_trust_bundle` is caught on every platform. Whether a name is
/// RECOGNISED follows the platform (`names_case_insensitive`): on POSIX that
/// lowercase name is not what the agent reads, so it is reported; on Windows it
/// is, so it is not. Taking the names as input (rather than reading the process
/// environment) is the test seam.
[[nodiscard]] YUZU_EXPORT std::vector<std::string>
unrecognised_update_env_names(std::span<const std::string> env_names, bool names_case_insensitive);

/// The NAMES (never the values) of every variable in this process's
/// environment. POSIX reads `environ` (`_NSGetEnviron()` on macOS, where a
/// shared library cannot rely on the `environ` symbol); Windows reads
/// `GetEnvironmentStringsW()` and converts names to UTF-8, skipping the
/// `=C:`-style per-drive pseudo-entries. Values are deliberately not returned:
/// the environment can hold secrets (`YUZU_ENROLLMENT_TOKEN`), and only names
/// are ever logged.
[[nodiscard]] YUZU_EXPORT std::vector<std::string> process_environment_names();

/// One startup log line. `warning` selects warn over info.
struct UpdateSignatureStartupLine {
    bool warning{false};
    std::string text;
};

/// The startup report for `cfg`:
///
///  * always one info line naming the mode and the bundle path (`off` says in
///    words that update binaries are not signature-checked — info, not warn,
///    because off is the shipped default);
///  * a warning when the bundle is set but `probe_trust_bundle()` cannot load it
///    (every update would then be refused as `bundle_unreadable`);
///  * one warning per unrecognised `YUZU_UPDATE_*` name in `env_names`.
[[nodiscard]] YUZU_EXPORT std::vector<UpdateSignatureStartupLine>
build_update_signature_startup_lines(const UpdateConfig& cfg,
                                     std::span<const std::string> env_names,
                                     bool names_case_insensitive);

} // namespace yuzu::agent
