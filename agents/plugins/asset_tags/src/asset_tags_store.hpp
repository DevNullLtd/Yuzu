#pragma once

/**
 * asset_tags_store.hpp — state-file I/O for the asset_tags plugin (#232).
 *
 * Header-only and logger-free: both functions return std::expected, so the
 * persistence lifecycle is unit-testable without loading the plugin. The
 * pure (de)serialisation lives in asset_tags_parsers.hpp. The atomic write
 * itself (exclusive-create temp, fsync, 0600, rename; see its banner for the
 * full contract) lives in agents/shared/atomic_file_write.hpp; this file
 * keeps the plugin-facing names and forwards with owner_only_mode = true.
 */

#include <atomic_file_write.hpp>

#include <expected>
#include <filesystem>
#include <fstream>
#include <iterator>
#include <optional>
#include <string>
#include <string_view>
#include <system_error>

namespace yuzu::asset_tags {

using IoError = yuzu::shared::IoError;
using WriteWarning = yuzu::shared::WriteWarning;

/// Read the state file. A missing file is a normal first run: returns an
/// engaged expected holding nullopt. An unreadable file (or a non-regular
/// path) is an IoError.
[[nodiscard]] inline std::expected<std::optional<std::string>, IoError>
read_state_file(const std::filesystem::path& p) {
    namespace fs = std::filesystem;

    std::error_code ec;
    const auto st = fs::status(p, ec);
    if (st.type() == fs::file_type::not_found)
        return std::nullopt;
    if (ec)
        return std::unexpected(IoError{"cannot stat " + p.string() + ": " + ec.message()});
    if (!fs::is_regular_file(st))
        return std::unexpected(IoError{p.string() + ": not a regular file"});

    std::ifstream f(p, std::ios::binary);
    if (!f)
        return std::unexpected(IoError{"cannot open " + p.string() + " for reading"});
    std::string content{std::istreambuf_iterator<char>(f), std::istreambuf_iterator<char>()};
    if (f.bad())
        return std::unexpected(IoError{"read error on " + p.string()});
    return content;
}

/// Atomically replace `dest` with `bytes`, owner-only (0600 on POSIX).
/// `forced_temp_suffix` and `ops` are TEST SEAMS ONLY (see the shared header).
[[nodiscard]] inline std::expected<std::optional<WriteWarning>, IoError>
write_state_file_atomic(const std::filesystem::path& dest, std::string_view bytes,
                        std::string_view forced_temp_suffix = {},
                        const yuzu::shared::PosixFdOps* ops = nullptr) {
    return yuzu::shared::write_file_atomic(dest, bytes, {true, forced_temp_suffix, ops});
}

} // namespace yuzu::asset_tags
