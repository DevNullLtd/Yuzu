/**
 * platform_security_parsers.hpp -- the PURE layer for platform_security: the
 * efivar / LSM / lockdown / spctl / csrutil decoders, the errno and
 * tool-outcome classifiers, the row formatter, the shared status selector and
 * the collect loops over an INJECTED reader. No OS call, no I/O, no platform
 * header: the leg TUs supply the real reader / runner, the unit suite a fake.
 *
 * ROW: <secure_boot|code_integrity>|<os>|<key>|<raw>|<state>
 * <state> = enabled | disabled | partial | unmodelled | absent | unreadable |
 * unsupported. enabled/disabled/partial describe the PROTECTION, not the raw
 * value (SetupMode=0, a Platform Key enrolled, is `enabled`). `unmodelled` = a
 * value was read that this table cannot interpret (raw keeps it). absent (the
 * OS definitively says it is not there), unreadable (the read failed) and
 * unsupported (no mechanism on this OS) are distinct; a failed read NEVER
 * reads as absent. ABSENCE IS NOT A FAILURE (BIOS/CSM hosts have no efivars,
 * many kernels no Lockdown LSM): an `absent` row adds no token and does not
 * lower the status. <raw> is "-" when nothing was read.
 *
 * REASON TOKENS (one per UNREADABLE row): <key>:eacces (EACCES/EPERM) |
 * <key>:errno_<n> | <key>:efivars:shape (efivar not 4+1 bytes) | macOS tool
 * runs: <key>:timeout | :output_truncated | :spawn_failed | :exit_<n> |
 * :exit_signal. select_status decides for EVERY leg (Windows included):
 * PERMISSION_DENIED/PARTIAL when any read was refused, else CONSTRAINED/
 * PARTIAL when a token exists, else OK/FULL.
 *
 * macOS vocabulary mirrors agents/plugins/vuln_scan/src/config_checks.hpp
 * run_macos_checks (Gatekeeper, SIP; popen-based, rung 3): enabled/disabled
 * agree, but here the match is an exact line and anything else is
 * `unmodelled` (or `partial`, SIP custom configuration). Folding vuln_scan
 * onto this reader is a follow-up, not part of this change.
 */
#pragma once

#include <constraint_accumulator.hpp>

#include <yuzu/plugin.h> // YuzuResultStatus / Completeness (C ABI: no OS types)
#include <yuzu/string_utils.hpp>

#include <array>
#include <cerrno>
#include <cstddef>
#include <cstdint>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <vector>

namespace yuzu::platform_security {

inline constexpr std::string_view kSecureBootAction = "secure_boot";
inline constexpr std::string_view kCodeIntegrityAction = "code_integrity";

enum class PlatformState { enabled, disabled, partial, unmodelled, absent, unreadable, unsupported };

// Indexed by PlatformState: order is part of the contract (pinned by the unit test).
inline constexpr std::array<std::string_view, 7> kStateTokens{
    "enabled", "disabled", "partial", "unmodelled", "absent", "unreadable", "unsupported"};

[[nodiscard]] constexpr std::string_view state_token(PlatformState s) noexcept {
    return kStateTokens[static_cast<std::size_t>(s)];
}

/// First NON-BLANK line of `data`, ASCII-whitespace trimmed. Empty when there is none.
[[nodiscard]] constexpr std::string_view first_line_trimmed(std::string_view data) noexcept {
    const auto ws = [](char c) { return c == ' ' || c == '\t' || c == '\r' || c == '\0'; };
    while (!data.empty()) {
        std::string_view line = data;
        if (const auto nl = data.find('\n'); nl != std::string_view::npos) {
            line = data.substr(0, nl);
            data.remove_prefix(nl + 1);
        } else {
            data = {};
        }
        while (!line.empty() && ws(line.front())) line.remove_prefix(1);
        while (!line.empty() && ws(line.back())) line.remove_suffix(1);
        if (!line.empty()) return line;
    }
    return {};
}

/// efivarfs file = 4-byte attribute word + variable data; SecureBoot/SetupMode
/// are one byte, so exactly 5 bytes. Returns the data byte, nullopt for ANY
/// other size (a shape failure, never guessed at).
[[nodiscard]] constexpr std::optional<std::uint8_t> decode_efivar_bool(std::string_view bytes) noexcept {
    constexpr std::size_t kAttributeBytes = 4;
    if (bytes.size() != kAttributeBytes + 1) return std::nullopt;
    return static_cast<std::uint8_t>(bytes[kAttributeBytes]);
}

/// UEFI 2.x: SecureBoot 1 = enforcing, 0 = off; SetupMode 0 = User Mode (a
/// Platform Key is enrolled), 1 = Setup Mode (no PK: any image may load), so
/// SetupMode maps the opposite way. Any other data byte is `unmodelled`.
[[nodiscard]] constexpr PlatformState efivar_state(bool setup_mode, std::uint8_t v) noexcept {
    if (v > 1) return PlatformState::unmodelled;
    return (v == (setup_mode ? 0 : 1)) ? PlatformState::enabled : PlatformState::disabled;
}

struct EfivarKey {
    std::string_view key;  // row key
    std::string_view path; // full efivarfs path (one table: no request text reaches a path)
    bool setup_mode;
};

// Both variables live under the EFI global-variable GUID 8be4df61-93ca-11d2-aa0d-00e098032b8c.
inline constexpr std::array<EfivarKey, 2> kEfivars{{
    {"secure_boot", "/sys/firmware/efi/efivars/SecureBoot-8be4df61-93ca-11d2-aa0d-00e098032b8c", false},
    {"setup_mode", "/sys/firmware/efi/efivars/SetupMode-8be4df61-93ca-11d2-aa0d-00e098032b8c", true},
}};

// ── LSM list and lockdown (Linux code integrity) ────────────────────────

inline constexpr std::string_view kLsmPath = "/sys/kernel/security/lsm";
inline constexpr std::string_view kLockdownPath = "/sys/kernel/security/lockdown";

/// `lsm` = comma-separated active LSM names (no trailing newline on a real kernel).
/// enabled = a mandatory-access-control LSM (SELinux/AppArmor/Smack/TOMOYO) is
/// active; disabled = list read, none of them (or empty); unmodelled = a token
/// that is not a plain identifier ([a-z0-9_]+).
[[nodiscard]] constexpr PlatformState classify_lsm_list(std::string_view raw) noexcept {
    raw = first_line_trimmed(raw);
    if (raw.empty()) return PlatformState::disabled;
    bool mac = false;
    while (true) {
        const auto comma = raw.find(',');
        const std::string_view tok = raw.substr(0, comma);
        if (tok.empty()) return PlatformState::unmodelled;
        for (const char c : tok)
            if (!((c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '_'))
                return PlatformState::unmodelled;
        mac = mac || tok == "selinux" || tok == "apparmor" || tok == "smack" || tok == "tomoyo";
        if (comma == std::string_view::npos) break;
        raw.remove_prefix(comma + 1);
    }
    return mac ? PlatformState::enabled : PlatformState::disabled;
}

/// `lockdown` lists every mode, the ACTIVE one bracketed: `[none] integrity
/// confidentiality`. none = disabled, integrity = partial, confidentiality =
/// enabled; no bracket, several, or another token = `unmodelled`.
[[nodiscard]] constexpr PlatformState classify_lockdown(std::string_view raw) noexcept {
    raw = first_line_trimmed(raw);
    const auto open = raw.find('[');
    if (open == std::string_view::npos) return PlatformState::unmodelled;
    const auto close = raw.find(']', open);
    if (close == std::string_view::npos) return PlatformState::unmodelled;
    if (raw.find('[', open + 1) != std::string_view::npos) return PlatformState::unmodelled;
    const std::string_view active = raw.substr(open + 1, close - open - 1);
    if (active == "none") return PlatformState::disabled;
    if (active == "integrity") return PlatformState::partial;
    if (active == "confidentiality") return PlatformState::enabled;
    return PlatformState::unmodelled;
}

/// `spctl --status`: `assessments enabled` | `assessments disabled`.
[[nodiscard]] constexpr PlatformState parse_spctl_status(std::string_view text) noexcept {
    const auto line = first_line_trimmed(text);
    if (line == "assessments enabled") return PlatformState::enabled;
    if (line == "assessments disabled") return PlatformState::disabled;
    return PlatformState::unmodelled;
}

/// `csrutil status`: `System Integrity Protection status: enabled.` | `disabled.`;
/// `enabled (Custom Configuration).` = `partial`; anything else (including
/// `unknown (Custom Configuration)`) = `unmodelled`.
[[nodiscard]] constexpr PlatformState parse_csrutil_status(std::string_view text) noexcept {
    constexpr std::string_view kPrefix = "System Integrity Protection status: ";
    auto line = first_line_trimmed(text);
    if (!line.starts_with(kPrefix)) return PlatformState::unmodelled;
    line.remove_prefix(kPrefix.size());
    if (line == "enabled.") return PlatformState::enabled;
    if (line == "disabled.") return PlatformState::disabled;
    if (line == "enabled (Custom Configuration).") return PlatformState::partial;
    return PlatformState::unmodelled;
}

/// Only ENOENT means "not there"; every other errno is a failed read.
[[nodiscard]] constexpr PlatformState classify_read_errno(int err) noexcept {
    return err == ENOENT ? PlatformState::absent : PlatformState::unreadable;
}

/// EACCES/EPERM: the read was refused; select_status turns it into PERMISSION_DENIED.
[[nodiscard]] constexpr bool is_denied_errno(int err) noexcept {
    return err == EACCES || err == EPERM;
}

/// `<key>:eacces` | `<key>:errno_<n>`; nullopt for ENOENT (absence is no failure).
[[nodiscard]] inline std::optional<std::string> failure_token(std::string_view key, int err) {
    if (classify_read_errno(err) == PlatformState::absent) return std::nullopt;
    std::string t{key};
    t += is_denied_errno(err) ? std::string{":eacces"} : ":errno_" + std::to_string(err);
    return t;
}

// ── rows ────────────────────────────────────────────────────────────────

/// `action`/`os` borrow literals; `key` is owned (the Windows CI\Policy value
/// list names rows dynamically). `denied` = the read was refused.
struct PlatformRow {
    std::string_view action;
    std::string_view os;
    std::string key;
    std::string raw; // "-" when nothing was read
    PlatformState state;
    bool denied = false;
};

[[nodiscard]] inline std::string format_row(const PlatformRow& r) {
    // os is a fixed vocabulary; key/raw may carry OS-supplied text.
    std::string out{r.action};
    (out += '|').append(r.os) += '|';
    (out += yuzu::util::safe_output_field(r.key)) += '|';
    (out += yuzu::util::safe_output_field(r.raw)) += '|';
    return out.append(state_token(r.state));
}

/// A read that failed with errno `err`: `absent` and NO token for ENOENT, else
/// `unreadable` with its token recorded in `acc`.
[[nodiscard]] inline PlatformRow failed_row(std::string_view action, std::string_view os,
                                            std::string_view key, int err,
                                            yuzu::shared::ConstraintAccumulator& acc) {
    if (const auto token = failure_token(key, err)) acc.add_failure(*token);
    return {action, os, std::string{key}, "-", classify_read_errno(err), is_denied_errno(err)};
}

/// An unreadable row for a non-errno failure (`cause` = the token suffix).
[[nodiscard]] inline PlatformRow unreadable_row(std::string_view action, std::string_view os,
                                                std::string_view key, std::string_view cause,
                                                yuzu::shared::ConstraintAccumulator& acc) {
    std::string t{key};
    t += ':';
    t += cause;
    acc.add_failure(t);
    return {action, os, std::string{key}, "-", PlatformState::unreadable, false};
}

/// The macOS secure_boot answer: this OS has no public API for it.
[[nodiscard]] inline PlatformRow unsupported_row(std::string_view action, std::string_view os,
                                                 std::string_view key) {
    return {action, os, std::string{key}, "-", PlatformState::unsupported, false};
}

// ── status selection (pure; the one decision every leg shares) ──────────

[[nodiscard]] inline bool any_denied(std::span<const PlatformRow> rows) noexcept {
    for (const auto& r : rows)
        if (r.denied) return true;
    return false;
}

struct PlatformStatus {
    YuzuResultStatus status;
    YuzuResultCompleteness completeness;
    std::string provenance;
};

/// PERMISSION_DENIED/PARTIAL if any read was refused, else CONSTRAINED/PARTIAL
/// if a token exists, else OK/FULL.
[[nodiscard]] inline PlatformStatus select_status(const yuzu::shared::ConstraintAccumulator& acc,
                                                  bool denied) {
    if (denied)
        return {YUZU_RESULT_STATUS_PERMISSION_DENIED, YUZU_RESULT_COMPLETENESS_PARTIAL,
                acc.reason()};
    if (acc.any_failure())
        return {YUZU_RESULT_STATUS_CONSTRAINED, YUZU_RESULT_COMPLETENESS_PARTIAL, acc.reason()};
    return {YUZU_RESULT_STATUS_OK, YUZU_RESULT_COMPLETENESS_FULL, {}};
}

// ── collect loops over an injected reader ───────────────────────────────

/// A file read: err == 0 -> `data` holds the bytes; else the errno of the failure.
struct ReadOutcome {
    int err = 0;
    std::string data;
};

/// `read(path)` -> ReadOutcome. One row per kEfivars entry, in order.
template <typename Reader>
[[nodiscard]] std::vector<PlatformRow> secure_boot_rows_linux(Reader&& read,
                                                                 yuzu::shared::ConstraintAccumulator& acc) {
    std::vector<PlatformRow> rows;
    rows.reserve(kEfivars.size());
    for (const auto& v : kEfivars) {
        const ReadOutcome o = read(v.path);
        if (o.err != 0) {
            rows.push_back(failed_row(kSecureBootAction, "linux", v.key, o.err, acc));
            continue;
        }
        const auto byte = decode_efivar_bool(o.data);
        if (!byte) {
            rows.push_back(unreadable_row(kSecureBootAction, "linux", v.key, "efivars:shape", acc));
            continue;
        }
        rows.push_back({kSecureBootAction, "linux", std::string{v.key}, std::to_string(*byte),
                        efivar_state(v.setup_mode, *byte)});
    }
    return rows;
}

/// `read(path)` -> ReadOutcome. Rows `lsm` then `lockdown`, always both.
template <typename Reader>
[[nodiscard]] std::vector<PlatformRow> code_integrity_rows_linux(Reader&& read,
                                                                    yuzu::shared::ConstraintAccumulator& acc) {
    std::vector<PlatformRow> rows;
    const auto one = [&](std::string_view key, std::string_view path, auto classify) {
        const ReadOutcome o = read(path);
        if (o.err != 0) {
            rows.push_back(failed_row(kCodeIntegrityAction, "linux", key, o.err, acc));
            return;
        }
        std::string raw{first_line_trimmed(o.data)};
        const auto state = classify(raw);
        rows.push_back({kCodeIntegrityAction, "linux", std::string{key}, std::move(raw), state});
    };
    one("lsm", kLsmPath, [](std::string_view s) { return classify_lsm_list(s); });
    one("lockdown", kLockdownPath, [](std::string_view s) { return classify_lockdown(s); });
    return rows;
}

/// One bounded tool run, runner-type-free (the macOS leg fills it from SubprocessResult).
struct ToolOutcome {
    bool tool_ran = false;       // false = exec itself failed
    bool timed_out = false;
    bool output_truncated = false;
    int exit_code = -1;          // -1 = killed by a signal
    int spawn_errno = 0;         // meaningful only when !tool_ran
    std::string output;          // captured stdout
};

/// One row from one tool run. A spawn failure (including ENOENT) is ALWAYS `unreadable`
/// with a token, never `absent` -- both call sites (spctl, csrutil) are sealed-system-volume
/// binaries with no legitimate "not there" case on a real Mac; a missing/renamed binary means
/// a compromised or non-standard host, not a clean answer about Gatekeeper/SIP policy. An
/// incomplete run (deadline, truncation) is also `unreadable`; text that parses is trusted
/// whatever the exit status (spctl may exit non-zero for a disabled state); unparsed text is a
/// failed run on a non-zero exit and `unmodelled` (raw kept) on exit 0.
[[nodiscard]] inline PlatformRow tool_row(std::string_view action, std::string_view os,
                                          std::string_view key, const ToolOutcome& o,
                                          PlatformState (*parse)(std::string_view) noexcept,
                                          yuzu::shared::ConstraintAccumulator& acc) {
    if (!o.tool_ran) {
        if (o.spawn_errno == 0) return unreadable_row(action, os, key, "spawn_failed", acc);
        const bool denied = is_denied_errno(o.spawn_errno);
        const std::string cause =
            denied ? "eacces" : "errno_" + std::to_string(o.spawn_errno);
        std::string token{key};
        (token += ':') += cause;
        acc.add_failure(token);
        return {action, os, std::string{key}, "-", PlatformState::unreadable, denied};
    }
    if (o.timed_out) return unreadable_row(action, os, key, "timeout", acc);
    if (o.output_truncated) return unreadable_row(action, os, key, "output_truncated", acc);
    std::string raw{first_line_trimmed(o.output)};
    const auto state = parse(raw);
    if (state == PlatformState::unmodelled && o.exit_code != 0)
        return unreadable_row(action, os, key,
                              o.exit_code < 0 ? std::string{"exit_signal"}
                                              : "exit_" + std::to_string(o.exit_code),
                              acc);
    return {action, os, std::string{key}, std::move(raw), state, false};
}

/// `run(id)` -> ToolOutcome for id 1 = spctl, 2 = csrutil. Rows `gatekeeper`, `sip`.
template <typename Runner>
[[nodiscard]] std::vector<PlatformRow> code_integrity_rows_macos(Runner&& run,
                                                                    yuzu::shared::ConstraintAccumulator& acc) {
    std::vector<PlatformRow> rows;
    rows.push_back(tool_row(kCodeIntegrityAction, "macos", "gatekeeper", run(1), &parse_spctl_status, acc));
    rows.push_back(tool_row(kCodeIntegrityAction, "macos", "sip", run(2), &parse_csrutil_status, acc));
    return rows;
}

} // namespace yuzu::platform_security
