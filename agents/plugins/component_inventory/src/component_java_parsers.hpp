#pragma once

/**
 * component_java_parsers.hpp — pure parsers for Java archive inventory.
 *
 * Header-only, std-only, no I/O: the zip directory walk is zip_directory.hpp.
 * Every input is untrusted file bytes, so each parser is a bounded linear
 * scan (no regex, no unbounded copies) and returns nullopt / false on
 * anything it cannot positively read.
 *
 * Version precedence is applied by the scan (component_scan.hpp: read_archive
 * and scan), not here: file name, then pom.properties, then manifest, else ''
 * with version_source `unreadable`. The component `name` is the artifact only
 * (no group:artifact).
 */

#include <cstddef>
#include <optional>
#include <string>
#include <string_view>

namespace yuzu::component_inventory {

inline constexpr std::string_view kManifestEntry = "META-INF/MANIFEST.MF";

/// Longest version string any parser will return.
inline constexpr std::size_t kMaxJavaVersionBytes = 128;

/// Longest archive file name parse_jar_filename accepts (the common
/// filesystem name limit); bounds the artifact/version copies.
inline constexpr std::size_t kMaxJarFilenameBytes = 255;

struct JarName {
    std::string artifact;
    std::string version; ///< '' when the file name carries no version
};

namespace java_detail {

constexpr bool is_digit(char c) noexcept { return c >= '0' && c <= '9'; }

constexpr char lower(char c) noexcept { return (c >= 'A' && c <= 'Z') ? static_cast<char>(c + 32) : c; }

constexpr bool is_version_char(char c) noexcept {
    return is_digit(c) || (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || c == '.' || c == '_' ||
           c == '+';
}

constexpr bool iequals(std::string_view a, std::string_view b) noexcept {
    if (a.size() != b.size())
        return false;
    for (std::size_t i = 0; i < a.size(); ++i)
        if (lower(a[i]) != lower(b[i]))
            return false;
    return true;
}

constexpr std::string_view trim(std::string_view s) noexcept {
    while (!s.empty() && (s.front() == ' ' || s.front() == '\t'))
        s.remove_prefix(1);
    while (!s.empty() && (s.back() == ' ' || s.back() == '\t'))
        s.remove_suffix(1);
    return s;
}

constexpr bool is_printable_ascii(std::string_view v) noexcept {
    for (char c : v)
        if (c < 0x20 || c > 0x7E)
            return false;
    return true;
}

/// Non-empty, <= kMaxJavaVersionBytes, printable ASCII (0x20..0x7E) only.
constexpr bool valid_value(std::string_view v) noexcept {
    return !v.empty() && v.size() <= kMaxJavaVersionBytes && is_printable_ascii(v);
}

/// Next line of `text` without its terminator ('\n', optional preceding '\r').
inline std::string_view next_line(std::string_view& text) noexcept {
    const auto nl = text.find('\n');
    std::string_view line = text.substr(0, nl);
    text = (nl == std::string_view::npos) ? std::string_view{} : text.substr(nl + 1);
    if (!line.empty() && line.back() == '\r')
        line.remove_suffix(1);
    return line;
}

} // namespace java_detail

/// A candidate archive file name: at least four bytes, ending in .jar, .war or .ear in any case.
[[nodiscard]] constexpr bool is_java_archive_name(std::string_view name) noexcept {
    using namespace java_detail;
    if (name.size() < 4)
        return false;
    const std::string_view ext = name.substr(name.size() - 4);
    return iequals(ext, ".jar") || iequals(ext, ".war") || iequals(ext, ".ear");
}

/// <artifact>-<version>[-classifier] for .jar/.war/.ear (case-insensitive).
/// The version is the digit-led run after the LAST '-' that starts one and is
/// followed by end or '-' (so log4j-1.2-api-2.17.1.jar -> log4j-1.2-api /
/// 2.17.1); a directly following "-SNAPSHOT" stays in the version.
/// Classifier rule: a candidate with a letter and no '.' (64bit, 32bit) is a
/// classifier, not a version, when an earlier dotted candidate exists
/// (name-1.0-64bit.jar -> name / 1.0). Alone it is still read as the version
/// (foo-64bit.jar), which the pom/manifest fallbacks may then override.
/// Names over kMaxJarFilenameBytes, or with any byte outside printable ASCII
/// (NUL, control, non-ASCII), are rejected before anything is copied.
// ponytail: the parser refuses a non-ASCII file name; the scan still emits a row
// for it (scan_detail::name_of), with each such byte as '?' so the component name
// stays valid UTF-8 downstream. Upgrade to a UTF-8 validator if needed.
inline std::optional<JarName> parse_jar_filename(std::string_view filename) {
    using namespace java_detail;
    if (filename.size() > kMaxJarFilenameBytes || !is_printable_ascii(filename) || !is_java_archive_name(filename))
        return std::nullopt;
    const std::string_view stem = filename.substr(0, filename.size() - 4);
    if (stem.empty())
        return std::nullopt;

    std::size_t best_start = std::string_view::npos;
    std::size_t best_end = 0;
    bool best_dotted = false;
    for (std::size_t i = 1; i + 1 < stem.size(); ++i) {
        if (stem[i] != '-' || !is_digit(stem[i + 1]))
            continue;
        std::size_t e = i + 1;
        bool dotted = false, alpha = false;
        for (; e < stem.size() && is_version_char(stem[e]); ++e) {
            dotted = dotted || stem[e] == '.';
            alpha = alpha || (stem[e] >= 'A' && stem[e] <= 'Z') || (stem[e] >= 'a' && stem[e] <= 'z');
        }
        if (e != stem.size() && stem[e] != '-')
            continue;
        if (!dotted && alpha && best_dotted)
            continue; // classifier such as 64bit after a real version
        best_start = i;
        best_end = e;
        best_dotted = dotted;
    }
    if (best_start == std::string_view::npos)
        return JarName{std::string(stem), std::string{}};

    constexpr std::string_view kSnap = "-SNAPSHOT";
    if (stem.substr(best_end, kSnap.size()) == kSnap) {
        const std::size_t after = best_end + kSnap.size();
        if (after == stem.size() || stem[after] == '-')
            best_end = after;
    }
    return JarName{std::string(stem.substr(0, best_start)),
                   std::string(stem.substr(best_start + 1, best_end - best_start - 1))};
}

/// The `version=` property of a Maven pom.properties (first occurrence).
inline std::optional<std::string> parse_pom_properties_version(std::string_view text) {
    using namespace java_detail;
    while (!text.empty()) {
        std::string_view line = trim(next_line(text));
        if (line.empty() || line.front() == '#' || line.front() == '!')
            continue;
        constexpr std::string_view kKey = "version";
        if (!line.starts_with(kKey))
            continue;
        line.remove_prefix(kKey.size());
        line = trim(line);
        if (line.empty() || (line.front() != '=' && line.front() != ':'))
            continue; // a longer key such as "versionRange"
        const std::string_view value = trim(line.substr(1));
        if (!valid_value(value))
            return std::nullopt;
        return std::string(value);
    }
    return std::nullopt;
}

/// Implementation-Version, else Bundle-Version, from the MANIFEST main section.
inline std::optional<std::string> parse_manifest_version(std::string_view text) {
    using namespace java_detail;
    constexpr std::size_t kRawCap = 2 * kMaxJavaVersionBytes; // bounds the joined copy
    std::string cur;
    bool over = false;
    std::optional<std::string> impl, bundle;

    const auto flush = [&] {
        if (cur.empty()) {
            over = false; // an oversized line leaves cur empty; don't poison the next header
            return;
        }
        const auto colon = cur.find(':');
        if (colon != std::string::npos) {
            const std::string_view name(cur.data(), colon);
            const std::string_view value = trim(std::string_view(cur).substr(colon + 1));
            if (!over && valid_value(value)) {
                if (iequals(name, "Implementation-Version") && !impl)
                    impl = std::string(value);
                else if (iequals(name, "Bundle-Version") && !bundle)
                    bundle = std::string(value);
            }
        }
        cur.clear();
        over = false;
    };

    while (!text.empty()) {
        const std::string_view line = next_line(text);
        if (line.empty())
            break; // end of the main section
        if (line.front() == ' ') {
            if (cur.size() + line.size() - 1 > kRawCap)
                over = true;
            else
                cur.append(line.substr(1));
            continue;
        }
        flush();
        if (line.size() > kRawCap)
            over = true;
        else
            cur.assign(line);
    }
    flush();
    if (impl)
        return impl;
    return bundle;
}

/// BOOT-INF/lib/<x>.jar, WEB-INF/lib/<x>.jar or lib/<x>.jar, no further '/'. The directory prefixes
/// are exact; the extension folds case like is_java_archive_name, so X.JAR is listed, not hidden.
inline bool is_nested_lib_entry(std::string_view entry) noexcept {
    for (const std::string_view prefix : {std::string_view{"BOOT-INF/lib/"}, std::string_view{"WEB-INF/lib/"},
                                          std::string_view{"lib/"}}) {
        if (!entry.starts_with(prefix))
            continue;
        const std::string_view rest = entry.substr(prefix.size());
        return rest.size() > 4 && rest.find('/') == std::string_view::npos &&
               java_detail::iequals(rest.substr(rest.size() - 4), ".jar");
    }
    return false;
}

/// The <a> of META-INF/maven/<g>/<a>/pom.properties; nullopt when `entry` is not that shape.
inline std::optional<std::string_view> pom_properties_artifact(std::string_view entry) noexcept {
    constexpr std::string_view kPrefix = "META-INF/maven/";
    constexpr std::string_view kSuffix = "/pom.properties";
    if (!entry.starts_with(kPrefix) || !entry.ends_with(kSuffix))
        return std::nullopt;
    if (entry.size() < kPrefix.size() + kSuffix.size())
        return std::nullopt;
    const std::string_view mid =
        entry.substr(kPrefix.size(), entry.size() - kPrefix.size() - kSuffix.size());
    const auto slash = mid.find('/');
    if (slash == std::string_view::npos || slash == 0 || slash + 1 >= mid.size() ||
        mid.find('/', slash + 1) != std::string_view::npos)
        return std::nullopt;
    return mid.substr(slash + 1);
}

} // namespace yuzu::component_inventory
