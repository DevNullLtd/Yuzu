/**
 * runtimes_fixture_tree.hpp -- the tree.manifest decoder and materializer shared by the runtimes
 * walk tests (test_runtimes_linux_parsers.cpp, test_runtimes_python_parsers.cpp).
 *
 * Line grammar (a blank line or a line starting '#' is ignored):
 *   <relative-path> TAB T:<text with \n \t \\ escapes> | L:<symlink target> | D:
 * A manifest describes a root subtree portably (nothing is tracked as a real directory or symlink, so a
 * Windows checkout is unaffected); `materialize_manifest_file` writes it under a root on disk. The
 * decoder is portable; the materializer uses std::filesystem only.
 */
#pragma once

#include <filesystem>
#include <fstream>
#include <optional>
#include <string>
#include <string_view>
#include <utility>

namespace runtimes_fixture {

namespace fs = std::filesystem;

enum class ManifestKind { text, symlink, directory };

struct ManifestEntry {
    std::string rel;
    ManifestKind kind = ManifestKind::text;
    std::string payload; // decoded text | link target | (unused)
};

enum class LineOutcome { skipped, entry, malformed };

struct ParsedLine {
    LineOutcome outcome = LineOutcome::skipped;
    ManifestEntry entry;
    std::string error;
};

/// Decodes the escapes of a `T:` payload (\n, \t, \\). nullopt on a dangling
/// backslash or an unknown escape.
inline std::optional<std::string> unescape_text(std::string_view s) {
    std::string out;
    for (std::size_t i = 0; i < s.size(); ++i) {
        if (s[i] != '\\') {
            out += s[i];
            continue;
        }
        if (++i >= s.size()) return std::nullopt;
        switch (s[i]) {
        case 'n':  out += '\n'; break;
        case 't':  out += '\t'; break;
        case '\\': out += '\\'; break;
        default:   return std::nullopt;
        }
    }
    return out;
}

inline ParsedLine parse_manifest_line(std::string line) {
    ParsedLine r;
    if (!line.empty() && line.back() == '\r') line.pop_back(); // CRLF checkout tolerance
    if (line.empty() || line.front() == '#') return r;
    const auto bad = [&r](std::string msg) {
        r.outcome = LineOutcome::malformed;
        r.error = std::move(msg);
        return r;
    };
    const auto tab = line.find('\t');
    if (tab == std::string::npos || tab == 0) return bad("no tab separator: " + line);
    r.entry.rel = line.substr(0, tab);
    if (r.entry.rel.front() == '/' || r.entry.rel.find("..") != std::string::npos)
        return bad("path must be relative and inside the tree: " + r.entry.rel);
    const std::string payload = line.substr(tab + 1);
    if (payload.size() < 2 || payload[1] != ':') return bad("payload lacks a kind prefix: " + line);
    const std::string body = payload.substr(2);
    switch (payload[0]) {
    case 'T': {
        auto t = unescape_text(body);
        if (!t) return bad("bad escape in T: payload: " + line);
        r.entry.kind = ManifestKind::text;
        r.entry.payload = std::move(*t);
        break;
    }
    case 'L':
        r.entry.kind = ManifestKind::symlink;
        r.entry.payload = body;
        break;
    case 'D': r.entry.kind = ManifestKind::directory; break;
    default: return bad("unknown payload kind: " + line);
    }
    if (r.entry.kind == ManifestKind::symlink && r.entry.payload.empty())
        return bad("empty L: payload: " + line);
    r.outcome = LineOutcome::entry;
    return r;
}

/// Materializes the manifest file under `root`. Returns false with `error` set on any
/// failure so the caller can REQUIRE with a useful message.
inline bool materialize_manifest_file(const fs::path& root, std::string& error,
                                      const fs::path& manifest_file) {
    std::ifstream in(manifest_file, std::ios::binary);
    if (!in) {
        error = "could not open " + manifest_file.string();
        return false;
    }
    std::string line;
    while (std::getline(in, line)) {
        const auto p = parse_manifest_line(line);
        if (p.outcome == LineOutcome::skipped) continue;
        if (p.outcome == LineOutcome::malformed) {
            error = p.error;
            return false;
        }
        const fs::path target = root / p.entry.rel;
        std::error_code ec;
        fs::create_directories(p.entry.kind == ManifestKind::directory ? target
                                                                        : target.parent_path(),
                               ec);
        if (ec) {
            error = "create_directories failed for " + target.string() + ": " + ec.message();
            return false;
        }
        switch (p.entry.kind) {
        case ManifestKind::directory: break;
        case ManifestKind::symlink:
            fs::create_symlink(p.entry.payload, target, ec);
            if (ec) {
                error = "create_symlink failed for " + target.string() + ": " + ec.message();
                return false;
            }
            break;
        case ManifestKind::text: {
            std::ofstream out(target, std::ios::binary);
            if (!out) {
                error = "could not create " + target.string();
                return false;
            }
            out << p.entry.payload;
            break;
        }
        }
    }
    return true;
}

} // namespace runtimes_fixture
