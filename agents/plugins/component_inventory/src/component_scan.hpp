#pragma once

/**
 * component_scan.hpp -- the portable scan of the component_inventory plugin: the walk's candidates
 * become Java component rows, outer archives and the libraries nested in them.
 *
 * Portable: no OS header. Every directory listing, every byte of every archive and every clock read
 * goes through the FsOps seam of component_walk.hpp, so the unit test drives scan() over an
 * in-memory tree and a fake clock. The one non-std dependency is zlib, for raw inflate of at most
 * two small entries per archive.
 *
 * ONE DEADLINE. scan() computes fs.now() + limits.max_wall once, hands it to walk(), and checks the
 * same instant before every archive, so the budget covers the walk, the archive reads, the inflate
 * and the parsing together. Expiry in either phase is Stop::budget_time. The check sits between
 * archives and once more on the final clock read, so the last archive running past the deadline is
 * seen too: one archive's reads are not interrupted (they are bounded by the 16 MiB directory cap and
 * the 64 KiB entry caps, and a hang inside a read is the OS leg's residual, stated in its banner).
 *
 * ONE OPEN PER ARCHIVE. open_file is called once per candidate and every byte (the tail, the
 * directory, a local header, an entry) is read through that FileView, never by path again; the file
 * a name pointed at when it was opened is the file that is read, whatever happens to the name.
 *
 * COMPLETENESS RULE (ADR-0028 Decision 4). Nothing that hides rows may read as complete.
 *   Enumeration failure  an archive that cannot be opened, whose tail or directory cannot be read or
 *                        parsed (any ZipError: ZIP64, an over-size directory, a corrupt record) may
 *                        hold libraries this answer does not list. The outer row is still emitted
 *                        and the scan records Stop::archive_unenumerated.
 *   Changed while read   unchanged() false after the reads records Stop::archive_changed.
 *   Version gap          an outer archive whose version no source gives is a row with version ''
 *                        and version_source `unreadable`. That is an item-level gap: the row exists,
 *                        nothing is hidden, the scan stays complete.
 * The first cause recorded is the reported one, walk causes first.
 *
 * Nested libraries are listed from the central directory alone: name and version from the entry
 * name, size = the entry's uncompressed size, mtime = the outer file's. No nested entry is inflated.
 *
 * Also here, so the plugin TU holds no decision: the wire row, the status verdict (level, tokens,
 * typed result), the six heartbeat cost values, and the whole `scan` answer around them. The
 * answer (the unreadable-mount-table guard included), its emission (rows, typed result, heartbeat
 * KV) and the catch-all's own answer are templates over the OS leg's targets and the host's
 * command/plugin contexts, so a unit test drives each with fakes and never walks the real host.
 */

#include "component_java_parsers.hpp"
#include "component_walk.hpp"
#include "zip_directory.hpp"

#include <inventory_status_row.hpp> // yuzu::shared::StatusLevel (agents/shared)
#include <yuzu/plugin.h>            // YUZU_RESULT_STATUS_* / YUZU_RESULT_COMPLETENESS_*
#include <yuzu/string_utils.hpp>    // yuzu::util::safe_output_field

#include <zlib.h>

#include <algorithm>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <unordered_map>
#include <utility>
#include <vector>

namespace yuzu::component_inventory {

inline constexpr std::string_view kSourceFilename = "filename";
inline constexpr std::string_view kSourcePom = "pom";
inline constexpr std::string_view kSourceManifest = "manifest";
inline constexpr std::string_view kSourceUnreadable = "unreadable";

/// An entry read for its version is at most this many bytes compressed and this many inflated.
inline constexpr std::size_t kMaxEntryBytes = 64 * 1024;

struct Row {
    std::string name;
    std::string version;
    std::string version_source; // filename | pom | manifest | unreadable
    std::string path;           // nested: <outer>!<entry>
    std::uint64_t size{0};
    std::int64_t mtime{0};
    std::string anchor_app;
};

struct ScanResult {
    std::vector<Row> rows;
    Stop stop{Stop::complete};
    WalkStats stats;
    std::size_t version_unreadable{0}; // rows whose version_source is unreadable (informational)
    std::uint64_t elapsed_ms{0};
};

namespace scan_detail {

struct Nested {
    std::string entry;
    std::uint64_t size{0};
};

struct ArchiveRead {
    bool enumerated{false}; // the directory was read and parsed; `nested` is the whole list
    bool changed{false};
    std::uint64_t size{0};
    std::int64_t mtime{0};
    std::optional<std::pair<std::string, std::string_view>> version; // value, source
    std::vector<Nested> nested;
};

[[nodiscard]] inline std::span<const std::byte> as_bytes(const std::string& s) noexcept {
    return {reinterpret_cast<const std::byte*>(s.data()), s.size()};
}

/// Exactly `len` bytes at `offset`, or nullopt (I/O error or a short read): every read here lies
/// inside the size the file had when it was opened, so a short read means it changed or failed.
[[nodiscard]] inline std::optional<std::string> read_exact(const FileView& fv, std::uint64_t offset,
                                                           std::size_t len) {
    auto s = fv.read_at(offset, len);
    if (!s || s->size() != len)
        return std::nullopt;
    return s;
}

/// Raw deflate (no zlib header) of `in` into at most `cap` bytes. Z_FINISH over a buffer of exactly
/// `cap`: anything that would need one more byte is Z_BUF_ERROR, so nothing past the cap is ever
/// produced, and an output of exactly `cap` bytes is accepted. nullopt for any error or an over-cap
/// stream.
[[nodiscard]] inline std::optional<std::string> inflate_raw_capped(std::string_view in, std::size_t cap) {
    // Allocated before inflateInit2: a throw here must not strand zlib state (no inflateEnd runs).
    std::string out(cap, '\0');
    z_stream zs{};
    if (inflateInit2(&zs, -15) != Z_OK)
        return std::nullopt;
    zs.next_in = const_cast<Bytef*>(reinterpret_cast<const Bytef*>(in.data()));
    zs.avail_in = static_cast<uInt>(in.size());
    zs.next_out = reinterpret_cast<Bytef*>(out.data());
    zs.avail_out = static_cast<uInt>(cap);
    const int rc = inflate(&zs, Z_FINISH);
    const auto produced = static_cast<std::size_t>(zs.total_out);
    inflateEnd(&zs);
    if (rc != Z_STREAM_END)
        return std::nullopt;
    out.resize(produced);
    return out;
}

/// The text of a small entry: stored or deflated, at most kMaxEntryBytes compressed and inflated.
/// nullopt = unreadable (an item-level gap for the caller, never an enumeration failure).
[[nodiscard]] inline std::optional<std::string> read_entry_text(const FileView& fv, const ZipTail& tail,
                                                                const ZipEntry& e) {
    if (e.comp_size > kMaxEntryBytes || e.uncomp_size > kMaxEntryBytes)
        return std::nullopt;
    if (e.method != 0 && e.method != 8)
        return std::nullopt;
    const auto at = zip_detail::checked_add(tail.prefix, e.local_header_offset);
    if (!at)
        return std::nullopt;
    const auto header = read_exact(fv, *at, zip_detail::kLocalHeaderLen);
    if (!header)
        return std::nullopt;
    const auto data_off = local_data_offset(as_bytes(*header), e, tail.prefix);
    if (!data_off)
        return std::nullopt;
    const auto data = read_exact(fv, *data_off, static_cast<std::size_t>(e.comp_size));
    if (!data)
        return std::nullopt;
    if (e.method == 0)
        return e.comp_size == e.uncomp_size ? data : std::nullopt;
    return inflate_raw_capped(*data, kMaxEntryBytes);
}

/// Open once; read the tail, the directory and (only when the file name gave no version) the
/// pom.properties and MANIFEST.MF entries, all through the one FileView.
[[nodiscard]] inline ArchiveRead read_archive(const FsOps& fs, const std::string& path, bool want_version) {
    ArchiveRead r;
    const auto fv = fs.open_file(path);
    if (!fv)
        return r;
    r.size = fv->size;
    r.mtime = fv->mtime;
    // Evaluated on every exit below, after the reads.
    const auto finish = [&] {
        r.changed = !fv->unchanged();
        return std::move(r);
    };

    const auto tail_len = static_cast<std::size_t>(std::min<std::uint64_t>(fv->size, kMaxTailBytes));
    const auto tail_bytes = read_exact(*fv, fv->size - tail_len, tail_len);
    if (!tail_bytes)
        return finish();
    const auto tail = find_central_directory(as_bytes(*tail_bytes), fv->size);
    if (!tail)
        return finish();
    const auto cd = read_exact(*fv, tail->cd_offset, static_cast<std::size_t>(tail->cd_size));
    if (!cd)
        return finish();

    std::optional<ZipEntry> pom, manifest;
    const auto walked = for_each_central_entry(as_bytes(*cd), tail->entries, [&](const ZipEntry& e) {
        if (is_nested_lib_entry(e.name))
            r.nested.push_back({std::string(e.name), e.uncomp_size});
        else if (want_version && !pom && is_pom_properties_entry(e.name))
            pom = e;
        else if (want_version && !manifest && e.name == kManifestEntry)
            manifest = e;
        return true;
    });
    if (!walked) {
        r.nested.clear(); // a directory that does not parse lists nothing it can vouch for
        return finish();
    }
    r.enumerated = true;

    if (pom)
        if (const auto text = read_entry_text(*fv, *tail, *pom))
            if (auto v = parse_pom_properties_version(*text))
                r.version.emplace(std::move(*v), kSourcePom);
    if (!r.version && manifest)
        if (const auto text = read_entry_text(*fv, *tail, *manifest))
            if (auto v = parse_manifest_version(*text))
                r.version.emplace(std::move(*v), kSourceManifest);
    return finish();
}

[[nodiscard]] inline std::string_view leaf_of(std::string_view path) noexcept {
    const auto i = path.rfind('/');
    return i == std::string_view::npos ? path : path.substr(i + 1);
}

/// Name and version from a file name. A name parse_jar_filename refuses (non-ASCII, over-long) still
/// gets a row, so the inventory hides nothing: bytes outside printable ASCII become '?', no version.
[[nodiscard]] inline JarName name_of(std::string_view leaf) {
    if (auto n = parse_jar_filename(leaf))
        return std::move(*n);
    if (leaf.size() > 4)
        leaf.remove_suffix(4);
    std::string s(leaf.substr(0, kMaxJarFilenameBytes));
    for (char& c : s)
        if (c < 0x20 || c > 0x7E)
            c = '?';
    return JarName{std::move(s), {}};
}

} // namespace scan_detail

/**
 * Walk `roots`, then read every candidate archive.
 */
[[nodiscard]] inline ScanResult scan(std::span<const std::string> roots, const WalkLimits& limits,
                                     const FsOps& fs) {
    ScanResult out;
    const auto started = fs.now();
    const auto deadline = started + limits.max_wall;

    WalkResult walked = walk(roots, limits, fs, deadline);
    out.stats = walked.stats;
    out.stop = walked.stop;
    const auto record = [&out](Stop s) {
        if (out.stop == Stop::complete)
            out.stop = s;
    };

    std::unordered_map<std::string, std::size_t> per_anchor; // outer + nested rows
    // false = the section is full: stop reading archives.
    const auto add = [&](Row&& r) {
        if (out.rows.size() >= limits.max_rows) {
            record(Stop::section_rows);
            return false;
        }
        std::size_t& n = per_anchor[r.anchor_app];
        if (n >= limits.max_rows_per_anchor) {
            record(Stop::anchor_rows);
            return true;
        }
        ++n;
        if (r.version_source == kSourceUnreadable)
            ++out.version_unreadable;
        out.rows.push_back(std::move(r));
        return true;
    };

    for (const auto& c : walked.candidates) {
        if (fs.now() >= deadline) {
            record(Stop::budget_time);
            break;
        }
        JarName jn = scan_detail::name_of(scan_detail::leaf_of(c.path));
        const auto ar = scan_detail::read_archive(fs, c.path, jn.version.empty());
        if (!ar.enumerated)
            record(Stop::archive_unenumerated);
        if (ar.changed)
            record(Stop::archive_changed);

        Row outer;
        outer.name = std::move(jn.artifact);
        if (!jn.version.empty()) {
            outer.version = std::move(jn.version);
            outer.version_source = std::string(kSourceFilename);
        } else if (ar.version) {
            outer.version = ar.version->first;
            outer.version_source = std::string(ar.version->second);
        } else {
            outer.version_source = std::string(kSourceUnreadable);
        }
        outer.path = c.path;
        outer.size = ar.size;
        outer.mtime = ar.mtime;
        outer.anchor_app = c.anchor_app;
        if (!add(std::move(outer)))
            break;

        bool full = false;
        for (const auto& n : ar.nested) {
            JarName nn = scan_detail::name_of(scan_detail::leaf_of(n.entry));
            Row row;
            row.name = std::move(nn.artifact);
            row.version_source = std::string(nn.version.empty() ? kSourceUnreadable : kSourceFilename);
            row.version = std::move(nn.version);
            row.path = c.path + '!' + n.entry;
            row.size = n.size;
            row.mtime = ar.mtime;
            row.anchor_app = c.anchor_app;
            if (!add(std::move(row))) {
                full = true;
                break;
            }
        }
        if (full)
            break;
    }

    // The last archive (or the walk's last listing) can itself run past the deadline, and no later
    // check would see it: the budget covers the whole scan, so the final clock read is checked too.
    const auto finished = fs.now();
    if (finished >= deadline)
        record(Stop::budget_time);
    const auto elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(finished - started).count();
    out.elapsed_ms = elapsed > 0 ? static_cast<std::uint64_t>(elapsed) : 0;
    return out;
}

// ---- output: the wire row, the status verdict and the cost values (pure) ----

/// comp|java|name|version|version_source|path|size|mtime|anchor_app, every text field escaped.
[[nodiscard]] inline std::string format_component_row(const Row& r) {
    using yuzu::util::safe_output_field;
    std::string s = "comp|java|";
    s += safe_output_field(r.name);
    s += '|';
    s += safe_output_field(r.version);
    s += '|';
    s += safe_output_field(r.version_source);
    s += '|';
    s += safe_output_field(r.path);
    s += '|';
    s += std::to_string(r.size);
    s += '|';
    s += std::to_string(r.mtime);
    s += '|';
    s += safe_output_field(r.anchor_app);
    return s;
}

struct ScanVerdict {
    yuzu::shared::StatusLevel level{yuzu::shared::StatusLevel::constrained};
    std::string tokens; // comma-joined, '' when none (the status row writes '-')
    bool complete{false}; // typed result OK/FULL when true, CONSTRAINED/PARTIAL when false
};

[[nodiscard]] inline std::string component_token(std::string_view os, std::string_view cause) {
    std::string t(os);
    t += ":component_inventory:";
    t += cause;
    return t;
}

/**
 * The status row's level, tokens and typed result as a pure function of how the scan ended.
 * `os` is windows, linux or macos. Anything other than a complete scan (a stop cause, or an
 * unreadable mount table, in which case no walk ran) is constrained and names its cause. Only a
 * complete scan is supported; the informational tokens ride that row and never change the level.
 * `network_skipped` counts network roots dropped plus network mounts the walk passed over.
 */
[[nodiscard]] inline ScanVerdict scan_verdict(std::string_view os, Stop stop, bool mount_table_unreadable,
                                              std::size_t roots_link_skipped, std::size_t network_skipped,
                                              std::size_t version_unreadable) {
    ScanVerdict v;
    if (mount_table_unreadable || stop != Stop::complete) {
        v.level = yuzu::shared::StatusLevel::constrained;
        v.tokens = component_token(os, mount_table_unreadable ? "mount_table_unreadable" : to_token(stop));
        return v;
    }
    v.level = yuzu::shared::StatusLevel::supported;
    v.complete = true;
    const auto info = [&](bool on, std::string_view cause) {
        if (!on)
            return;
        if (!v.tokens.empty())
            v.tokens += ',';
        v.tokens += component_token(os, cause);
    };
    info(roots_link_skipped > 0, "root_link_skipped");
    info(network_skipped > 0, "network_fs_skipped");
    info(version_unreadable > 0, "version_unreadable");
    return v;
}

/// Writes the six cost keys through `kv` (yuzu::PluginContext in the plugin, a recorder in tests); the
/// agent publishes each as yuzu.plugin.component_inventory.<suffix>. `roots_skipped` is the targets'
/// dropped roots (links plus network); the other five come from the scan.
template <class Kv>
inline void write_heartbeat(Kv& kv, const ScanResult& r, std::size_t roots_skipped) {
    kv.storage_set("heartbeat.walk_entries", std::to_string(r.stats.entries));
    kv.storage_set("heartbeat.walk_rows", std::to_string(r.rows.size()));
    kv.storage_set("heartbeat.walk_ms", std::to_string(r.elapsed_ms));
    kv.storage_set("heartbeat.roots_skipped", std::to_string(roots_skipped));
    kv.storage_set("heartbeat.links_skipped", std::to_string(r.stats.links_skipped));
    kv.storage_set("heartbeat.mounts_skipped", std::to_string(r.stats.mounts_skipped));
}

// ---- the `scan` action around the scan: answer, emit, and the catch-all's answer ----

inline constexpr std::string_view kScanAction = "scan";

/// Everything one `scan` says, built in full before the first write, so a failure while building
/// can still answer with its own single status row.
struct Answer {
    ScanResult res;
    ScanVerdict verdict;
    std::vector<std::string> lines; // the status row first, then one comp row per result row
    std::size_t roots_skipped{0};   // the targets' dropped roots (links plus network)
};

/**
 * Scan what the OS leg offers, or nothing. `Targets` is the leg's struct (roots,
 * mount_table_unreadable, roots_link_skipped, roots_network_skipped); `make_fs(t)` builds its FsOps.
 * An unreadable mount table means a network mount cannot be told from a local one: nothing is
 * walked, `make_fs` is not even called, and the answer is constrained with that cause. Pure over
 * its arguments, so a test passes a factory that fails if it is ever reached.
 */
template <class Targets, class MakeFs>
[[nodiscard]] inline Answer answer_scan(std::string_view os, const Targets& t, MakeFs&& make_fs,
                                        const WalkLimits& limits) {
    Answer a;
    if (!t.mount_table_unreadable) {
        const FsOps fs = make_fs(t);
        a.res = scan(t.roots, limits, fs);
    }
    a.roots_skipped = t.roots_link_skipped + t.roots_network_skipped;
    a.verdict = scan_verdict(os, a.res.stop, t.mount_table_unreadable, t.roots_link_skipped,
                             t.roots_network_skipped + a.res.stats.mounts_skipped,
                             a.res.version_unreadable);
    a.lines.reserve(a.res.rows.size() + 1);
    a.lines.push_back(yuzu::shared::format_status_row(kScanAction, a.verdict.level, a.verdict.tokens));
    for (const auto& r : a.res.rows)
        a.lines.push_back(format_component_row(r));
    return a;
}

/**
 * Write the answer: rows, then the typed result, then the cost keys (`kv` null = no plugin
 * context). `wrote` goes true only after a row has really been written, so the caller's catch-all
 * knows whether its own single status row is still owed. Rows found are written at both levels.
 */
template <class Ctx, class Kv>
inline void emit_answer(Ctx& ctx, Kv* kv, const Answer& a, bool& wrote) {
    for (const auto& l : a.lines) {
        ctx.write_output(l);
        wrote = true;
    }
    if (a.verdict.complete)
        ctx.set_result_status(YUZU_RESULT_STATUS_OK, YUZU_RESULT_COMPLETENESS_FULL);
    else
        ctx.set_result_status(YUZU_RESULT_STATUS_CONSTRAINED, YUZU_RESULT_COMPLETENESS_PARTIAL,
                              a.verdict.tokens);
    if (kv != nullptr)
        write_heartbeat(*kv, a.res, a.roots_skipped);
}

/**
 * The catch-all's answer: a constrained status row when no row was written yet, then the typed
 * result, both with `token` (a literal built at compile time, so nothing here allocates outside
 * the guarded calls). Each step is guarded on its own: a second failure while answering is
 * swallowed, never allowed to cross the plugin ABI. The caller returns 1.
 */
template <class Ctx>
inline void answer_internal_error(Ctx& ctx, std::string_view token, bool wrote) noexcept {
    if (!wrote) {
        try {
            ctx.write_output(yuzu::shared::format_status_row(
                kScanAction, yuzu::shared::StatusLevel::constrained, token));
        } catch (...) {
        }
    }
    try {
        ctx.set_result_status(YUZU_RESULT_STATUS_CONSTRAINED, YUZU_RESULT_COMPLETENESS_PARTIAL, token);
    } catch (...) {
    }
}

} // namespace yuzu::component_inventory
