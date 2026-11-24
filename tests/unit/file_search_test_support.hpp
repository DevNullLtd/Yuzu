/**
 * file_search_test_support.hpp -- helpers shared by the file_search unit TUs (driver, volumes, local
 * dispatcher, POSIX shell): a mountinfo table built a line at a time, the row splitter and prefix test, and a
 * yuzu_test_ directory under the canonical build root. Header-only and inline.
 */
#pragma once

#include "test_helpers.hpp"

#include <network_fstype.hpp>

#include <cstdlib>
#include <filesystem>
#include <string>
#include <system_error>
#include <vector>

namespace yuzu::file_search_test {

/// A /proc/self/mountinfo table built a line at a time.
struct Mounts {
    std::string text;
    int id{1};
    Mounts& add(const std::string& mp, const std::string& fstype, const std::string& label = "8:1",
                const std::string& root = "/", const std::string& source = "/dev/x") {
        text += std::to_string(id++) + " 1 " + label + " " + root + " " + mp + " rw - " + fstype + " " + source + " rw\n";
        return *this;
    }
    [[nodiscard]] yuzu::shared::MountTable table() const { return yuzu::shared::mount_entries(text); }
};

/// The '|'-separated columns of one row.
inline std::vector<std::string> split(const std::string& row) {
    std::vector<std::string> out;
    std::size_t at = 0;
    for (;;) {
        const auto bar = row.find('|', at);
        out.push_back(row.substr(at, bar == std::string::npos ? std::string::npos : bar - at));
        if (bar == std::string::npos)
            return out;
        at = bar + 1;
    }
}

inline bool starts(const std::string& s, const std::string& p) {
    return s.rfind(p, 0) == 0;
}

/// A directory under the canonical build root (or, with no MESON_BUILD_ROOT, the canonical temp directory),
/// named `prefix` plus the helpers' process salt, removed afterwards. `prefix` starts with "yuzu_test_".
struct Fixture {
    std::filesystem::path root;
    explicit Fixture(const char* prefix) {
        namespace fs = std::filesystem;
        fs::path base;
        if (const char* b = std::getenv("MESON_BUILD_ROOT"); b != nullptr && *b != '\0')
            base = fs::canonical(fs::path{b});
        else
            base = fs::canonical(fs::temp_directory_path());
        root = base / yuzu::test::unique_temp_path(prefix).filename();
        fs::create_directories(root);
        root = fs::canonical(root);
    }
    ~Fixture() {
        std::error_code ec;
        std::filesystem::remove_all(root, ec);
    }
    Fixture(const Fixture&) = delete;
    Fixture& operator=(const Fixture&) = delete;
};

} // namespace yuzu::file_search_test
