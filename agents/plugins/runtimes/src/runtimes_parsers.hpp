/**
 * runtimes_parsers.hpp -- the PURE parsing / row-formatting layer for the
 * runtimes plugin (installed .NET and JVM runtimes).
 *
 * Everything here is a free function over plain data: no OS call, no I/O, no
 * logging, no platform header (the repo's pure-core / thin-shell discipline;
 * sibling shape: agents/plugins/peripherals/src/peripherals_parsers.hpp). It
 * compiles and is unit-tested on EVERY OS (tests/unit/test_runtimes_parsers.cpp,
 * unguarded); the OS-reading legs live in runtimes_{linux,macos,win}.cpp.
 *
 * ZERO SUBPROCESS. The plugin never runs `java -version` or `dotnet
 * --list-runtimes`: every fact comes from a directory name or a metadata file
 * the runtime's installer laid down.
 *
 * WIRE GRAMMAR. Every action emits, in this order:
 *
 *   status|<action>|<supported|constrained|unsupported>|<reason tokens, comma-joined, or ->
 *   <action>|<flavour>|<version>|<install_path>|<vendor or ->      (zero or more)
 *
 * The status row ALWAYS comes first, so a consumer never has to infer an empty
 * inventory from silence: `supported` + zero data rows means NONE FOUND AT THE
 * STANDARD ROOTS the leg walks (a runtime installed anywhere else is not looked
 * for); `constrained` means some read failed or was skipped (unreadable
 * directory, oversized/garbled metadata, a network mount, a cap) and the rows
 * that follow may be incomplete -- failure never reads as absent. `unsupported`
 * is the planned-leg placeholder (`macos:planned`, `windows:planned`).
 *
 * FLAVOUR VOCABULARY (fixed, emitted verbatim, never parsed text). Every
 * OS-text -> enum mapper below carries a named `unmodelled` outcome distinct
 * from "no data" (which is an empty optional / no row):
 *   dotnet  core | sdk | unmodelled
 *   jvm     jdk | jre | unmodelled
 * Only the Linux legs ship today, so the vocabulary is the Linux subset; the
 * planned macOS and Windows legs add their own flavours (.NET Framework).
 *
 * Free-text fields (version, path, vendor) are untrusted OS-supplied text and
 * go through yuzu::util::safe_output_field, so a value containing '|' or
 * ending in a backslash can never shift the field count on the server's
 * escape-aware decoder.
 */
#pragma once

#include <constraint_accumulator.hpp> // yuzu::shared::ConstraintAccumulator (agents/shared)

#include <yuzu/string_utils.hpp>

#include <cstddef>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

namespace yuzu::runtimes {

// -- fixed vocabulary: status level ----------------------------------------

enum class StatusLevel { supported, constrained, unsupported };

[[nodiscard]] constexpr std::string_view status_token(StatusLevel l) noexcept {
    switch (l) {
    case StatusLevel::supported:   return "supported";
    case StatusLevel::constrained: return "constrained";
    case StatusLevel::unsupported: return "unsupported";
    }
    return "unsupported";
}

// -- fixed vocabulary: flavours --------------------------------------------

enum class DotnetFlavour { core, sdk, unmodelled };
enum class JvmFlavour { jdk, jre, unmodelled };

[[nodiscard]] constexpr std::string_view flavour_token(DotnetFlavour f) noexcept {
    switch (f) {
    case DotnetFlavour::core:       return "core";
    case DotnetFlavour::sdk:        return "sdk";
    case DotnetFlavour::unmodelled: return "unmodelled";
    }
    return "unmodelled";
}
[[nodiscard]] constexpr std::string_view flavour_token(JvmFlavour f) noexcept {
    switch (f) {
    case JvmFlavour::jdk:        return "jdk";
    case JvmFlavour::jre:        return "jre";
    case JvmFlavour::unmodelled: return "unmodelled";
    }
    return "unmodelled";
}

// -- small text helpers -----------------------------------------------------

namespace detail {

[[nodiscard]] inline bool is_digit(char c) noexcept { return c >= '0' && c <= '9'; }

[[nodiscard]] inline std::string_view trim(std::string_view s) noexcept {
    constexpr std::string_view ws = " \t\r\n";
    const auto b = s.find_first_not_of(ws);
    if (b == std::string_view::npos) return {};
    const auto e = s.find_last_not_of(ws);
    return s.substr(b, e - b + 1);
}

[[nodiscard]] inline bool ieq(std::string_view a, std::string_view b) noexcept {
    if (a.size() != b.size()) return false;
    for (std::size_t i = 0; i < a.size(); ++i) {
        char x = a[i], y = b[i];
        if (x >= 'A' && x <= 'Z') x = static_cast<char>(x - 'A' + 'a');
        if (y >= 'A' && y <= 'Z') y = static_cast<char>(y - 'A' + 'a');
        if (x != y) return false;
    }
    return true;
}

/// A .NET install-tree version directory: `major.minor.patch` (digits), then an
/// optional `-<prerelease>` and an optional `+<build>` (each [0-9A-Za-z.-]+),
/// e.g. "8.0.31", "9.0.100-preview.1.24101.2". A backup or disabled copy
/// ("8.0.31.bak"), a date, a bare integer or a spaced name is not a version (the
/// .NET host would not load it either), so it is not reported as a runtime.
[[nodiscard]] inline bool looks_like_version_dir(std::string_view v) noexcept {
    std::size_t i = 0;
    for (int part = 0; part < 3; ++part) {
        const std::size_t start = i;
        while (i < v.size() && is_digit(v[i])) ++i;
        if (i == start) return false;
        if (part < 2) {
            if (i >= v.size() || v[i] != '.') return false;
            ++i;
        }
    }
    const auto ident = [](char c) {
        return is_digit(c) || (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || c == '.' ||
               c == '-';
    };
    const auto consume_ident = [&]() {
        const std::size_t start = i;
        while (i < v.size() && ident(v[i])) ++i;
        return i > start;
    };
    if (i < v.size() && v[i] == '-') {
        ++i;
        if (!consume_ident()) return false;
    }
    if (i < v.size() && v[i] == '+') {
        ++i;
        if (!consume_ident()) return false;
    }
    return i == v.size();
}

/// True when `s` carries a control character (NUL, C0, DEL). A recognised
/// `release` value with one is malformed and its line is ignored: NUL would
/// truncate the wire row at the C-string boundary write_output crosses.
[[nodiscard]] inline bool has_control_char(std::string_view s) noexcept {
    for (const char ch : s) {
        const auto c = static_cast<unsigned char>(ch);
        if (c < 0x20 || c == 0x7f) return true;
    }
    return false;
}

} // namespace detail

// -- JVM `release` metadata file --------------------------------------------

/// A recognised `release` value longer than this is dropped and flagged: every
/// real value is a short token, and one 64 KiB value would otherwise be copied
/// into the row of every home that carries it.
inline constexpr std::size_t kMaxReleaseValueBytes = 256;

/// The four keys of a JDK/JRE `release` file this plugin reads. Empty string =
/// key absent. Every other key (MODULES, OS_ARCH, SOURCE, ...) is ignored.
/// `oversized` is set when a recognised key's value exceeded
/// kMaxReleaseValueBytes (the value itself is dropped, so the leg can record it).
struct ReleaseFields {
    std::string java_version;
    std::string implementor;
    std::string java_runtime_version;
    std::string image_type;
    bool oversized = false;
};

/// Parses the text of a `release` file (`KEY="value"` lines; the quotes are
/// stripped; unquoted values are accepted; CRLF tolerated; unknown keys, lines
/// without '=', lines with an unbalanced quote and values carrying a control
/// character ignored; a recognised value over kMaxReleaseValueBytes is dropped
/// and sets `oversized`). Never throws on malformed input: garbage yields a
/// ReleaseFields with empty members. The
/// caller bounds the read size (64 KiB for a real `release` file).
[[nodiscard]] inline ReleaseFields parse_release_file(std::string_view text) {
    ReleaseFields out;
    std::size_t pos = 0;
    while (pos <= text.size()) {
        const auto nl = text.find('\n', pos);
        const std::string_view line =
            detail::trim(text.substr(pos, nl == std::string_view::npos ? std::string_view::npos
                                                                       : nl - pos));
        pos = (nl == std::string_view::npos) ? text.size() + 1 : nl + 1;
        const auto eq = line.find('=');
        if (eq == std::string_view::npos || eq == 0) continue;
        const std::string_view key = detail::trim(line.substr(0, eq));
        std::string_view val = detail::trim(line.substr(eq + 1));
        if (!val.empty() && (val.front() == '"' || val.back() == '"')) {
            if (val.size() < 2 || val.front() != '"' || val.back() != '"')
                continue; // unbalanced quote: malformed line, ignored
            val = val.substr(1, val.size() - 2);
        }
        if (detail::has_control_char(val)) continue; // malformed value (NUL would truncate the row)
        const bool recognised = key == "JAVA_VERSION" || key == "IMPLEMENTOR" ||
                                key == "JAVA_RUNTIME_VERSION" || key == "IMAGE_TYPE";
        if (recognised && val.size() > kMaxReleaseValueBytes) {
            out.oversized = true;
            continue;
        }
        if (key == "JAVA_VERSION") out.java_version = std::string{val};
        else if (key == "IMPLEMENTOR") out.implementor = std::string{val};
        else if (key == "JAVA_RUNTIME_VERSION") out.java_runtime_version = std::string{val};
        else if (key == "IMAGE_TYPE") out.image_type = std::string{val};
    }
    return out;
}

/// IMAGE_TYPE "JDK"/"JRE" (case-insensitive) decides. Distributions that omit
/// the key (Debian's OpenJDK `release` file has no IMAGE_TYPE) read
/// `unmodelled` -- deliberately NOT guessed from the module list, which
/// Debian's headless JRE package fills with jdk.* modules, nor from the path.
[[nodiscard]] inline JvmFlavour jvm_flavour_from(std::string_view image_type) noexcept {
    const auto t = detail::trim(image_type);
    if (detail::ieq(t, "jdk")) return JvmFlavour::jdk;
    if (detail::ieq(t, "jre")) return JvmFlavour::jre;
    return JvmFlavour::unmodelled;
}

// -- .NET install-tree directory names ---------------------------------------

struct DotnetEntry {
    DotnetFlavour flavour = DotnetFlavour::unmodelled;
    std::string version;
};

/// Maps one install-tree directory pair to an entry.
///   shared/<framework_dir>/<version_dir>  -- Microsoft.NETCore.App,
///        Microsoft.AspNetCore.App, Microsoft.WindowsDesktop.App -> core;
///        any other framework name -> unmodelled (still reported, never dropped)
///   sdk/<version_dir>                     -- pass framework_dir == "sdk" -> sdk
/// nullopt when `version_dir` is not a plausible version (no data, not
/// `unmodelled`): a stray non-version entry is not a runtime.
[[nodiscard]] inline std::optional<DotnetEntry> dotnet_entry_from_dir(std::string_view framework_dir,
                                                                      std::string_view version_dir) {
    if (!detail::looks_like_version_dir(version_dir)) return std::nullopt;
    DotnetEntry e;
    e.version = std::string{version_dir};
    if (framework_dir == "sdk") e.flavour = DotnetFlavour::sdk;
    else if (framework_dir == "Microsoft.NETCore.App" ||
             framework_dir == "Microsoft.AspNetCore.App" ||
             framework_dir == "Microsoft.WindowsDesktop.App")
        e.flavour = DotnetFlavour::core;
    else e.flavour = DotnetFlavour::unmodelled;
    return e;
}

// -- row formatters -------------------------------------------------------------
//
// Return the row WITHOUT a trailing newline (write_output/append_output insert
// the separator; a formatter-emitted '\n' yields blank rows under
// LocalDispatcher capture).

/// Untrusted OS text becomes one safe field: invalid UTF-8 bytes are replaced first (the
/// output crosses the wire as a proto3 `string`, and one invalid byte fails the parse of
/// the whole chunk; overlong, surrogate and out-of-range sequences still pass, #4864), then the
/// pipe-grammar escaper runs.
[[nodiscard]] inline std::string field_or_dash(std::string_view v) {
    return v.empty() ? std::string{"-"}
                     : yuzu::util::safe_output_field(yuzu::util::sanitize_utf8(std::string{v}));
}

/// <action>|<flavour>|<version>|<install_path>|<vendor or ->
/// `action` and `flavour` are fixed vocabulary (verbatim); the rest is
/// untrusted text.
[[nodiscard]] inline std::string format_runtime_row(std::string_view action,
                                                    std::string_view flavour,
                                                    std::string_view version,
                                                    std::string_view install_path,
                                                    std::string_view vendor) {
    std::string out{action};
    out += '|';
    out.append(flavour);
    out += '|';
    out += field_or_dash(version);
    out += '|';
    out += field_or_dash(install_path);
    out += '|';
    out += field_or_dash(vendor);
    return out;
}

/// status|<action>|<level>|<reason or ->
[[nodiscard]] inline std::string format_status_row(std::string_view action, StatusLevel level,
                                                   std::string_view reason) {
    std::string out = "status|";
    out.append(action);
    out += '|';
    out.append(status_token(level));
    out += '|';
    out += field_or_dash(reason);
    return out;
}

/// The planned-leg placeholder: status|<action>|unsupported|<os_token>, where
/// os_token is a string literal `macos:planned` / `windows:planned`.
[[nodiscard]] inline std::string format_planned_status_row(std::string_view action,
                                                           std::string_view os_token) {
    return format_status_row(action, StatusLevel::unsupported, os_token);
}

/// Status decision from a ConstraintAccumulator: any recorded failure ->
/// constrained + comma-joined tokens; none -> supported, no reason. A later
/// successful sibling read never erases an earlier failure (the accumulator
/// has no removal operation).
struct StatusOutcome {
    StatusLevel level = StatusLevel::supported;
    std::string reason; // empty when supported
};

[[nodiscard]] inline StatusOutcome status_from_accumulator(
    const yuzu::shared::ConstraintAccumulator& acc) {
    if (acc.any_failure()) return {StatusLevel::constrained, acc.reason()};
    return {StatusLevel::supported, {}};
}

/// The full ordered output of one action: the status row first, then every
/// data row. Zero data rows + `supported` means none found at the standard
/// roots. The rows are copied once here; the walk's row budget bounds that copy.
[[nodiscard]] inline std::vector<std::string> compose_output(
    std::string_view action, const std::vector<std::string>& data_rows,
    const yuzu::shared::ConstraintAccumulator& acc) {
    const auto st = status_from_accumulator(acc);
    std::vector<std::string> out;
    out.reserve(data_rows.size() + 1);
    out.push_back(format_status_row(action, st.level, st.reason));
    out.insert(out.end(), data_rows.begin(), data_rows.end());
    return out;
}

// -- per-runtime row builders (parse + format in one pure step) ------------------

/// jvm row from a parsed `release` file. Version = JAVA_VERSION, falling back
/// to JAVA_RUNTIME_VERSION; vendor = IMPLEMENTOR. nullopt when neither version
/// key is present (an unparsable `release` file is not a JVM row; the leg
/// records a constraint token for it).
[[nodiscard]] inline std::optional<std::string> jvm_row(const ReleaseFields& f,
                                                        std::string_view install_path) {
    const std::string_view version =
        !f.java_version.empty() ? std::string_view{f.java_version}
                                : std::string_view{f.java_runtime_version};
    if (version.empty()) return std::nullopt;
    return format_runtime_row("jvm", flavour_token(jvm_flavour_from(f.image_type)), version,
                              install_path, f.implementor);
}

/// jvm row for a home whose installer laid down no `release` file (some distro OpenJDK 8
/// packages): the home is real but its version and vendor are unknown, so both read `-`. The leg
/// records `release_missing` next to it; such a home is never left out.
[[nodiscard]] inline std::string jvm_row_release_missing(std::string_view install_path) {
    return format_runtime_row("jvm", flavour_token(JvmFlavour::unmodelled), "", install_path, "");
}

/// dotnet row for one shared/<fw>/<ver> or sdk/<ver> directory pair.
[[nodiscard]] inline std::optional<std::string> dotnet_row(std::string_view framework_dir,
                                                           std::string_view version_dir,
                                                           std::string_view install_path) {
    const auto e = dotnet_entry_from_dir(framework_dir, version_dir);
    if (!e) return std::nullopt;
    return format_runtime_row("dotnet", flavour_token(e->flavour), e->version, install_path, "");
}

} // namespace yuzu::runtimes
