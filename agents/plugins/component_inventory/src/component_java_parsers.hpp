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
 * and scan), not here: the file name, corrected by a pom.properties or manifest
 * version only when the file name anchors it (archive_version_prefix) and the name
 * is not `exact`; with no file-name version, pom.properties, then manifest, else ''
 * with version_source `unreadable`. The component `name` is the artifact only
 * (no group:artifact).
 */

#include <cstddef>
#include <optional>
#include <string>
#include <string_view>

namespace yuzu::component_inventory {

inline constexpr std::string_view kManifestEntry = "META-INF/MANIFEST.MF";

/// Longest version a pom.properties or MANIFEST.MF value may carry. A version read from a file name is
/// bounded by kMaxJarFilenameBytes instead, so it can be longer.
inline constexpr std::size_t kMaxJavaVersionBytes = 128;

/// Longest archive file name parse_jar_filename accepts (the common
/// filesystem name limit); bounds the artifact/version copies.
inline constexpr std::size_t kMaxJarFilenameBytes = 255;

struct JarName {
    std::string artifact;
    std::string version; ///< '' when the file name carries no version
    /// One digit-led candidate and it runs to the end of the stem (my-app-1.0.0-rc1, an OSGi
    /// name_1.2.3.v2023): nothing in the name is ambiguous, so the archive is not asked.
    bool exact{false};
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

/// Non-empty, <= kMaxJavaVersionBytes, printable ASCII (0x20..0x7E) only, and not an unresolved
/// build placeholder (a "${project.version}" is the template, not a version).
constexpr bool valid_value(std::string_view v) noexcept {
    return !v.empty() && v.size() <= kMaxJavaVersionBytes && is_printable_ascii(v) &&
           v.find("${") == std::string_view::npos;
}

/// A pre-release or build qualifier that stays inside a version when it follows one: alpha, beta, rc,
/// cr, m, milestone, ea, preview or snapshot (any case, optional trailing digits), or only digits and
/// dots (a build number or timestamp). Any other word (jre, sources, linux) is a classifier.
constexpr bool is_version_qualifier(std::string_view t) noexcept {
    if (t.empty())
        return false;
    bool numeric = true;
    for (char c : t)
        numeric = numeric && (is_digit(c) || c == '.');
    if (numeric)
        return true;
    while (!t.empty() && is_digit(t.back()))
        t.remove_suffix(1);
    for (const std::string_view q : {"alpha", "beta", "rc", "cr", "m", "milestone", "ea", "preview", "snapshot"})
        if (iequals(t, q))
            return true;
    return false;
}

/// Index of the '-' (or the end) that closes the '-'-separated token starting at `from`.
constexpr std::size_t token_end(std::string_view s, std::size_t from) noexcept {
    const auto d = s.find('-', from);
    return d == std::string_view::npos ? s.size() : d;
}

/// `end` moved past every following "-<qualifier>" token.
constexpr std::size_t extend_qualifiers(std::string_view stem, std::size_t end) noexcept {
    while (end < stem.size() && stem[end] == '-') {
        const std::size_t e = token_end(stem, end + 1);
        if (!is_version_qualifier(stem.substr(end + 1, e - end - 1)))
            break;
        end = e;
    }
    return end;
}

/// Index of the '_' in an OSGi-style name_<major>.<minor>.<micro>[.qualifier][-build], or npos. The
/// three numeric segments must follow the '_', the rest of the stem must be version text, and no later
/// '-' may open a dotted digit-led token (that is a Maven-style version, e.g. a_1.2.3-api-2.0).
constexpr std::size_t osgi_split(std::string_view stem) noexcept {
    for (std::size_t u = stem.find('_', 1); u != std::string_view::npos; u = stem.find('_', u + 1)) {
        std::size_t p = u + 1;
        bool ok = true;
        for (int seg = 0; seg < 3 && ok; ++seg) {
            const std::size_t d0 = p;
            while (p < stem.size() && is_digit(stem[p]))
                ++p;
            ok = p > d0 && (seg == 2 || (p < stem.size() && stem[p] == '.'));
            if (seg < 2 && ok)
                ++p;
        }
        if (!ok || (p < stem.size() && stem[p] != '.' && stem[p] != '-'))
            continue;
        for (std::size_t i = u + 1; ok && i < stem.size(); ++i) {
            if (stem[i] == '-') {
                if (i + 1 < stem.size() && is_digit(stem[i + 1])) {
                    const std::size_t e = token_end(stem, i + 1);
                    ok = stem.substr(i + 1, e - i - 1).find('.') == std::string_view::npos;
                }
            } else {
                ok = is_version_char(stem[i]);
            }
        }
        if (ok)
            return u;
    }
    return std::string_view::npos;
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
/// The version starts at the LAST '-' that opens a digit-led token, then keeps every following
/// pre-release or build qualifier token (is_version_qualifier): my-app-1.0.0-rc1 -> 1.0.0-rc1,
/// foo-1.0-beta-2 -> 1.0-beta-2, foo-1.0-20231101.123456-1 -> the whole tail, my-app-1.0-SNAPSHOT-tests ->
/// 1.0-SNAPSHOT. Any other word after it is a classifier and stays out (guava-31.1-jre -> 31.1,
/// -linux-x86_64, -sources). A later dotted or all-digit candidate after such a word restarts the split
/// (log4j-1.2-api-2.17.1 -> log4j-1.2-api / 2.17.1); a later digit-led candidate with a letter and no '.'
/// (64bit, 32bit) never does once a version is found (name-1.0-64bit.jar -> name / 1.0), but alone it
/// is still the version (foo-64bit.jar). An OSGi name (org.x_3.29.0.v2023-1200) splits at the '_'.
/// This is the only source for a nested library, so it must be right alone; for an outer archive the
/// scan may correct it from the archive (see component_scan.hpp). A qualifier word it does not know
/// reads as a classifier (nested guava 31.1-jre reads 31.1).
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

    if (const std::size_t u = osgi_split(stem); u != std::string_view::npos)
        return JarName{std::string(stem.substr(0, u)), std::string(stem.substr(u + 1)), true};

    std::size_t start = std::string_view::npos, end = 0, seen = 0;
    bool weak = false; // the chosen candidate has a letter and no '.' (64bit): a classifier unless alone
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
        ++seen;
        const bool strong = dotted || !alpha;
        if (start != std::string_view::npos && !strong)
            continue; // classifier such as 64bit after a real version
        start = i;
        weak = !strong;
        end = weak ? e : extend_qualifiers(stem, e);
        i = end - 1; // resume at the '-' that closed the version
    }
    if (start == std::string_view::npos)
        return JarName{std::string(stem), std::string{}};
    if (weak)
        end = extend_qualifiers(stem, end);
    return JarName{std::string(stem.substr(0, start)), std::string(stem.substr(start + 1, end - start - 1)),
                   seen == 1 && end == stem.size()};
}

/// The file-name prefix when `stem` is <prefix><sep><version> or starts <prefix><sep><version>- with a
/// non-empty prefix, else nullopt. Last such separator wins, like the file-name split. This is how the
/// scan decides that an archive's own version describes THIS file name (and not a bundled dependency).
inline std::optional<std::string_view> archive_version_prefix(std::string_view stem, std::string_view version,
                                                              char sep) noexcept {
    if (version.empty())
        return std::nullopt;
    for (std::size_t at = stem.rfind(sep); at != std::string_view::npos && at > 0;
         at = at == 1 ? std::string_view::npos : stem.rfind(sep, at - 1)) {
        const std::string_view rest = stem.substr(at + 1);
        if (rest.starts_with(version) && (rest.size() == version.size() || rest[version.size()] == '-'))
            return stem.substr(0, at);
    }
    return std::nullopt;
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
