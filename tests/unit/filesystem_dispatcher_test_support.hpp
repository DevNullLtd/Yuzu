/**
 * filesystem_dispatcher_test_support.hpp -- helpers shared by the filesystem plugin's unit TUs
 * that load the ACTUAL built plugin through yuzu::agent::LocalDispatcher (get_acl, find_by_hash)
 * and by the find_by_hash walk-core TU. Header-only, inline: a plugin locator / loader, a
 * captured-output splitter, and the canonical-root TempDir fixture. The per-action dispatch
 * wrappers stay TU-local on purpose (each binds a different action and parameter list).
 */
#pragma once

#include <catch2/catch_test_macros.hpp>

#include <yuzu/agent/plugin_loader.hpp>
#include <yuzu/plugin.h>

#include "test_helpers.hpp"

#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <optional>
#include <sstream>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

#ifdef _WIN32
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>
#include <winioctl.h> // FSCTL_SET_REPARSE_POINT (AFTER windows.h)
#else
#include <unistd.h>
#endif

namespace yuzu::test::filesystem_dispatcher_support {

namespace fs = std::filesystem;

#if defined(_WIN32)
inline constexpr const char* kPluginExt = ".dll";
#elif defined(__APPLE__)
inline constexpr const char* kPluginExt = ".dylib";
#else
inline constexpr const char* kPluginExt = ".so";
#endif

/// The non-empty lines of a captured command-context output, CR stripped.
inline std::vector<std::string> captured_rows(const std::string& captured) {
    std::vector<std::string> out;
    std::istringstream ss(captured);
    std::string line;
    while (std::getline(ss, line)) {
        if (!line.empty() && line.back() == '\r')
            line.pop_back();
        if (!line.empty())
            out.push_back(line);
    }
    return out;
}

inline fs::path find_plugin() {
    const std::string lib_name = std::string{"filesystem"} + kPluginExt;
    std::vector<fs::path> candidates;
#if defined(_MSC_VER)
#pragma warning(push)
#pragma warning(disable : 4996)
#endif
    auto* build_root = std::getenv("MESON_BUILD_ROOT");
#if defined(_MSC_VER)
#pragma warning(pop)
#endif
    if (build_root)
        candidates.emplace_back(fs::path{build_root} / "agents" / "plugins" / "filesystem" /
                                lib_name);
    candidates.emplace_back(fs::path{"agents"} / "plugins" / "filesystem" / lib_name);
    candidates.emplace_back(fs::path{".."} / "agents" / "plugins" / "filesystem" / lib_name);
    for (const char* b : {"build-macos", "build-linux", "build-windows"})
        candidates.emplace_back(fs::path{b} / "agents" / "plugins" / "filesystem" / lib_name);
    for (const auto& c : candidates)
        if (std::error_code ec; fs::exists(c, ec))
            return c;
    return {};
}

struct LoadedPlugin {
    yuzu::agent::PluginHandle handle;
    const YuzuPluginDescriptor* descriptor{nullptr};
};

/// Under `meson test` (MESON_BUILD_ROOT always set) a missing plugin is a broken build and
/// must not report "All tests passed".
inline std::optional<LoadedPlugin> load_or_fail() {
    auto path = find_plugin();
    if (!path.empty()) {
        if (auto loaded = yuzu::agent::PluginHandle::load(path)) {
            if (const auto* d = loaded->descriptor())
                return LoadedPlugin{std::move(*loaded), d};
        }
    }
#if defined(_MSC_VER)
#pragma warning(push)
#pragma warning(disable : 4996)
#endif
    const bool under_meson = std::getenv("MESON_BUILD_ROOT") != nullptr;
#if defined(_MSC_VER)
#pragma warning(pop)
#endif
    if (under_meson)
        FAIL("filesystem plugin library not found under meson test -- it did not build, or "
             "link_depends is not forcing it to build before this test runs");
    WARN("filesystem plugin library not found -- skipping the LocalDispatcher round-trip");
    return std::nullopt;
}

/// A TempDir whose root is canonical: the real no-follow hasher (O_NOFOLLOW_ANY refuses the
/// /var -> /private/var link of a macOS temp path) sees a path with no symlink component, and the
/// plugin, which canonicalises its root, reports match rows in the same spelling.
struct Tree {
    yuzu::test::TempDir tmp{"yuzu_test_fbh_"};
    fs::path root;
    Tree() {
        fs::create_directories(tmp.path);
        root = fs::canonical(tmp.path);
    }
    fs::path write(const std::string& rel, std::string_view content = "x") const {
        const fs::path p = root / fs::path(rel).make_preferred();
        fs::create_directories(p.parent_path());
        std::ofstream{p, std::ios::binary} << content;
        return p;
    }
    [[nodiscard]] std::string str() const { return root.string(); }
};

#ifndef _WIN32
inline bool running_as_root() {
    return ::geteuid() == 0;
}
#else
// Privilege-free reparse-point fixtures. create_junction() is copied from
// tests/unit/test_confined_fs_win.cpp (CreateSymbolicLinkW needs a privilege, an NTFS mount point
// built with FSCTL_SET_REPARSE_POINT does not); folding the copies into one is a follow-up.

/// A junction (NTFS mount point) at `link` -> `target`. `link` must not exist yet.
inline bool create_junction(const fs::path& link, const fs::path& target) {
    // Every allocating (throwing) step comes BEFORE the handle is opened: nothing between
    // CreateFileW and CloseHandle can throw, so the raw HANDLE below cannot leak.
    // Hand-built IO_REPARSE_TAG_MOUNT_POINT buffer: REPARSE_DATA_BUFFER is WDK-only. The
    // substitute name is the NT form of the absolute target (the \??\ prefix), the print name the
    // plain absolute path.
    const std::wstring substitute = L"\\??\\" + fs::absolute(target).wstring();
    const std::wstring print_name = fs::absolute(target).wstring();
    const std::size_t sub_bytes = (substitute.size() + 1) * sizeof(wchar_t);
    const std::size_t print_bytes = (print_name.size() + 1) * sizeof(wchar_t);
    constexpr std::size_t kFixedHeaderSize =
        8; // ReparseTag(4) + ReparseDataLength(2) + Reserved(2)
    constexpr std::size_t kMountFieldsSize = 8; // 4 USHORTs: sub/print offset+length
    std::vector<std::byte> buf(kFixedHeaderSize + kMountFieldsSize + sub_bytes + print_bytes);
    const auto put16 = [&](std::size_t off, std::uint16_t v) {
        std::memcpy(buf.data() + off, &v, sizeof(v));
    };
    const auto put32 = [&](std::size_t off, std::uint32_t v) {
        std::memcpy(buf.data() + off, &v, sizeof(v));
    };
    put32(0, IO_REPARSE_TAG_MOUNT_POINT);
    put16(4, static_cast<std::uint16_t>(kMountFieldsSize + sub_bytes + print_bytes));
    put16(6, 0);
    put16(8, 0);
    put16(10, static_cast<std::uint16_t>(sub_bytes - sizeof(wchar_t)));
    put16(12, static_cast<std::uint16_t>(sub_bytes));
    put16(14, static_cast<std::uint16_t>(print_bytes - sizeof(wchar_t)));
    std::memcpy(buf.data() + kFixedHeaderSize + kMountFieldsSize, substitute.c_str(), sub_bytes);
    std::memcpy(buf.data() + kFixedHeaderSize + kMountFieldsSize + sub_bytes, print_name.c_str(),
                print_bytes);

    if (!CreateDirectoryW(link.c_str(), nullptr))
        return false;
    const HANDLE raw =
        CreateFileW(link.c_str(), GENERIC_WRITE, 0, nullptr, OPEN_EXISTING,
                    FILE_FLAG_OPEN_REPARSE_POINT | FILE_FLAG_BACKUP_SEMANTICS, nullptr);
    if (raw == INVALID_HANDLE_VALUE)
        return false;
    DWORD returned = 0;
    const bool ok =
        DeviceIoControl(raw, FSCTL_SET_REPARSE_POINT, buf.data(), static_cast<DWORD>(buf.size()),
                        nullptr, 0, &returned, nullptr) != 0;
    CloseHandle(raw);
    return ok;
}

/// Removes the junction ITSELF on destruction (RemoveDirectory on a reparse-point directory never
/// touches its target). Declare it after the Tree so it runs first.
struct JunctionCleanup {
    fs::path path;
    ~JunctionCleanup() { RemoveDirectoryW(path.c_str()); }
};

/// Turns the existing regular file `file` into a reparse point tagged IO_REPARSE_TAG_AF_UNIX (the
/// tag NTFS stores for an AF_UNIX socket file; no data, no privilege). NTFS rejects an arbitrary
/// non-Microsoft tag here with ERROR_INVALID_REPARSE_DATA, so a Microsoft tag is the portable
/// fixture. std::filesystem does not classify it, so a walk lists it as an ordinary file; only a
/// handle opened with FILE_FLAG_OPEN_REPARSE_POINT sees the attribute. Returns false if the volume
/// refuses the fixture.
inline bool make_file_reparse_point(const fs::path& file) {
    const HANDLE raw = CreateFileW(file.c_str(), GENERIC_WRITE, 0, nullptr, OPEN_EXISTING,
                                   FILE_FLAG_OPEN_REPARSE_POINT, nullptr);
    if (raw == INVALID_HANDLE_VALUE)
        return false;
    // The 8-byte header only: ReparseTag, ReparseDataLength = 0, Reserved.
    std::uint8_t buf[8]{};
    const std::uint32_t tag = 0x80000023; // IO_REPARSE_TAG_AF_UNIX
    std::memcpy(buf, &tag, sizeof(tag));
    DWORD returned = 0;
    const bool ok = DeviceIoControl(raw, FSCTL_SET_REPARSE_POINT, buf, sizeof(buf), nullptr, 0,
                                    &returned, nullptr) != 0;
    CloseHandle(raw);
    return ok;
}
#endif

} // namespace yuzu::test::filesystem_dispatcher_support
