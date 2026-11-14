#pragma once

/**
 * component_fixture_tree.hpp -- test fixtures for the component_inventory scan.
 *
 *   build_zip   a ZIP archive as bytes (stored or deflated entries, optional prepended bytes such as
 *               an executable jar's launch script), so no fixture is ever captured from a host.
 *   MemTree     an in-memory FsOps with a fake clock that records every listing, open and read, and
 *               can be told to fail an open, fail a read, or report a file as changed.
 *
 * Header-only and portable: it uses no OS header, so every test that includes it builds on all three
 * hosts.
 */

#include "component_walk.hpp"

#include <zlib.h>

#include <algorithm>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <functional>
#include <map>
#include <optional>
#include <set>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

namespace yuzu::component_inventory::fixture {

// ---- ZIP archives ----

struct Entry {
    std::string name;
    std::uint16_t method{0};      // 0 stored, 8 deflate
    std::string bytes;            // as stored in the archive
    std::uint32_t uncomp_size{0}; // as declared in the directory
};

inline void put16(std::string& b, std::uint16_t v) {
    b.push_back(static_cast<char>(v & 0xFF));
    b.push_back(static_cast<char>(v >> 8));
}
inline void put32(std::string& b, std::uint32_t v) {
    put16(b, static_cast<std::uint16_t>(v & 0xFFFF));
    put16(b, static_cast<std::uint16_t>(v >> 16));
}
inline void patch32(std::string& b, std::size_t at, std::uint32_t v) {
    for (int i = 0; i < 4; ++i)
        b[at + static_cast<std::size_t>(i)] = static_cast<char>((v >> (8 * i)) & 0xFF);
}

[[nodiscard]] inline std::string deflate_raw(std::string_view in) {
    z_stream zs{};
    deflateInit2(&zs, Z_DEFAULT_COMPRESSION, Z_DEFLATED, -15, 8, Z_DEFAULT_STRATEGY);
    std::string out(deflateBound(&zs, static_cast<uLong>(in.size())), '\0');
    zs.next_in = const_cast<Bytef*>(reinterpret_cast<const Bytef*>(in.data()));
    zs.avail_in = static_cast<uInt>(in.size());
    zs.next_out = reinterpret_cast<Bytef*>(out.data());
    zs.avail_out = static_cast<uInt>(out.size());
    deflate(&zs, Z_FINISH);
    out.resize(zs.total_out);
    deflateEnd(&zs);
    return out;
}

[[nodiscard]] inline Entry stored(std::string name, std::string data) {
    const auto n = static_cast<std::uint32_t>(data.size());
    return {std::move(name), 0, std::move(data), n};
}

[[nodiscard]] inline Entry deflated(std::string name, std::string_view data) {
    return {std::move(name), 8, deflate_raw(data), static_cast<std::uint32_t>(data.size())};
}

/// A nested library entry: junk bytes (never a real archive, so inflating or reading it would show)
/// with the uncompressed size the directory declares.
[[nodiscard]] inline Entry nested_lib(std::string name, std::uint32_t declared_size) {
    return {std::move(name), 0, "NOT-A-JAR", declared_size};
}

struct Zip {
    std::string bytes;
    std::size_t prefix{0};
    std::size_t cd_off{0}; // relative to the archive start, as the end record records it
    std::size_t cd_size{0};
    [[nodiscard]] std::size_t cd_abs() const { return prefix + cd_off; }
    [[nodiscard]] std::size_t eocd_abs() const { return cd_abs() + cd_size; }
};

/// `prefix` bytes of a launch script go in front; every offset inside stays relative to the archive
/// start, as in a real executable jar.
[[nodiscard]] inline Zip build_zip(const std::vector<Entry>& entries, std::size_t prefix = 0) {
    Zip z;
    z.prefix = prefix;
    std::string body;
    std::string cd;
    for (const auto& e : entries) {
        const auto off = static_cast<std::uint32_t>(body.size());
        put32(body, 0x04034b50U);
        put16(body, 20);
        put16(body, 0);
        put16(body, e.method);
        put32(body, 0);
        put32(body, 0);
        put32(body, static_cast<std::uint32_t>(e.bytes.size()));
        put32(body, e.uncomp_size);
        put16(body, static_cast<std::uint16_t>(e.name.size()));
        put16(body, 0);
        body += e.name;
        body += e.bytes;

        put32(cd, 0x02014b50U);
        put16(cd, 20);
        put16(cd, 20);
        put16(cd, 0);
        put16(cd, e.method);
        put32(cd, 0);
        put32(cd, 0);
        put32(cd, static_cast<std::uint32_t>(e.bytes.size()));
        put32(cd, e.uncomp_size);
        put16(cd, static_cast<std::uint16_t>(e.name.size()));
        put16(cd, 0);
        put16(cd, 0);
        put16(cd, 0);
        put16(cd, 0);
        put32(cd, 0);
        put32(cd, off);
        cd += e.name;
    }
    z.cd_off = body.size();
    z.cd_size = cd.size();
    std::string launcher = "#!/bin/sh\nexec java -jar \"$0\" \"$@\"\n";
    launcher.resize(prefix, '#');
    z.bytes = launcher + body + cd;
    put32(z.bytes, 0x06054b50U);
    put16(z.bytes, 0);
    put16(z.bytes, 0);
    put16(z.bytes, static_cast<std::uint16_t>(entries.size()));
    put16(z.bytes, static_cast<std::uint16_t>(entries.size()));
    put32(z.bytes, static_cast<std::uint32_t>(cd.size()));
    put32(z.bytes, static_cast<std::uint32_t>(z.cd_off));
    put16(z.bytes, 0);
    return z;
}

// ---- in-memory filesystem and fake clock ----

struct MemTree {
    using Type = DirEntry::Type;
    using Clock = std::chrono::steady_clock;

    struct Read {
        std::string path;
        std::uint64_t offset;
        std::size_t len;
    };

    std::map<std::string, std::vector<DirEntry>> dirs;
    std::map<std::string, std::string> files;
    std::map<std::string, std::int64_t> mtimes;

    // What the scan did.
    std::vector<std::string> listed; // every directory list() was called with, in order
    std::map<std::string, int> opens;
    int total_opens{0};
    std::vector<Read> reads;

    // Faults.
    std::set<std::string> unopenable;
    std::set<std::string> changed;
    std::function<bool(const std::string& path, std::uint64_t off, std::size_t len)> fail_read;

    // Fake clock: advances only by these steps.
    Clock::time_point clock{Clock::time_point{} + std::chrono::seconds(1000)};
    std::chrono::milliseconds list_step{0};
    std::chrono::milliseconds open_step{0};

    static constexpr std::int64_t kDefaultMtime = 1700000000;

    /// Lists `path` as an entry of its parent without giving it a listing of its own: a directory
    /// that cannot be listed.
    void dangling_dir(const std::string& path) { link_into_parent(path, Type::dir); }

    void add_dir(const std::string& path) {
        link_into_parent(path, Type::dir);
        dirs.try_emplace(path);
    }

    void add_file(const std::string& path, std::string content) {
        link_into_parent(path, Type::file);
        files[path] = std::move(content);
    }

    [[nodiscard]] FsOps ops() {
        FsOps o;
        o.list = [this](const std::string& d, std::size_t cap) {
            listed.push_back(d);
            clock += list_step;
            ListResult r;
            const auto it = dirs.find(d);
            if (it == dirs.end()) {
                r.error = true;
                return r;
            }
            r.entries = it->second;
            if (r.entries.size() > cap) {
                r.entries.resize(cap);
                r.truncated = true;
            }
            return r;
        };
        o.open_file = [this](const std::string& path) -> std::optional<FileView> {
            ++opens[path];
            ++total_opens;
            clock += open_step;
            const auto it = files.find(path);
            if (it == files.end() || unopenable.count(path))
                return std::nullopt;
            FileView fv;
            fv.size = it->second.size();
            const auto m = mtimes.find(path);
            fv.mtime = m == mtimes.end() ? kDefaultMtime : m->second;
            fv.read_at = [this, path](std::uint64_t off, std::size_t len) -> std::optional<std::string> {
                reads.push_back({path, off, len});
                if (fail_read && fail_read(path, off, len))
                    return std::nullopt;
                const std::string& data = files[path];
                if (off >= data.size())
                    return std::string{};
                return data.substr(static_cast<std::size_t>(off), len);
            };
            fv.unchanged = [this, path] { return changed.count(path) == 0; };
            return fv;
        };
        o.now = [this] { return clock; };
        return o;
    }

private:
    void link_into_parent(const std::string& path, Type type) {
        const auto slash = path.rfind('/');
        if (slash == std::string::npos || slash == 0)
            return;
        const std::string parent = path.substr(0, slash);
        const std::string name = path.substr(slash + 1);
        auto& list = dirs[parent];
        const bool present = std::any_of(list.begin(), list.end(),
                                         [&](const DirEntry& e) { return e.name == name; });
        if (!present)
            list.push_back({name, type});
        link_into_parent(parent, Type::dir);
    }
};

} // namespace yuzu::component_inventory::fixture
