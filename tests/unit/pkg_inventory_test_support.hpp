/**
 * pkg_inventory_test_support.hpp -- helpers shared by the pkg_inventory unit TUs
 * (macOS and Linux walk suites, local dispatcher). Header-only, inline, no
 * process / network / clock: pure string helpers plus two POSIX-only scope
 * helpers. The per-leg CommandContext harnesses stay TU-local on purpose: each
 * binds a different leg entry point (lnx:: vs mac::) under a different OS guard.
 */
#pragma once

#include <cstddef>
#include <sstream>
#include <string>
#include <vector>

#if !defined(_WIN32)
#include <fcntl.h>
#include <sys/stat.h>

#include <filesystem>
#endif

namespace yuzu::test::pkg_inventory_support {

/// Escape-aware field split. yuzu::util::safe_output_field writes a literal '|'
/// as `\|`, so a naive split('|') overcounts fields on a row whose text holds a pipe.
inline std::vector<std::string> split_fields_escape_aware(const std::string& row) {
    std::vector<std::string> out;
    std::string cur;
    for (std::size_t i = 0; i < row.size(); ++i) {
        if (row[i] == '\\' && i + 1 < row.size() && row[i + 1] == '|') {
            cur += '|';
            ++i;
        } else if (row[i] == '|') {
            out.push_back(cur);
            cur.clear();
        } else {
            cur += row[i];
        }
    }
    out.push_back(cur);
    return out;
}

/// The non-empty lines of a captured command-context output, CR stripped.
inline std::vector<std::string> captured_rows(const std::string& captured) {
    std::vector<std::string> out;
    std::istringstream ss(captured);
    std::string line;
    while (std::getline(ss, line)) {
        if (!line.empty() && line.back() == '\r') line.pop_back();
        if (!line.empty()) out.push_back(line);
    }
    return out;
}

#if !defined(_WIN32)

/// Restores a directory's mode on scope exit so TempDir's remove_all can run even
/// when a REQUIRE unwinds. Declare it AFTER the TempDir so it is destroyed first.
struct ModeGuard {
    std::filesystem::path path;
    mode_t restore;
    ~ModeGuard() { ::chmod(path.string().c_str(), restore); }
};

/// Number of open file descriptors of this process (fd numbers, machine
/// independent: only a before/after difference is ever asserted).
inline std::size_t open_fd_count() {
    std::size_t n = 0;
    for (int fd = 0; fd < 1024; ++fd)
        if (::fcntl(fd, F_GETFD) != -1) ++n;
    return n;
}

#endif

} // namespace yuzu::test::pkg_inventory_support
