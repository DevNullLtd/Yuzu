#include "installed_software_v3.hpp"

#include "sync_canonical.hpp" // clamp_field / sha256_hex
#include "sync_scheduler.hpp" // sanitize_skip_reason

#include <algorithm>
#include <array>
#include <cctype>
#include <iterator>
#include <tuple>

namespace yuzu::agent {

namespace {

constexpr char kUs = '\x1f';
constexpr char kRs = '\x1e';

// The closed `comp` version_source vocabulary (server inventory_blob_v3.hpp kV3VersionSources).
constexpr std::array<std::string_view, 9> kVersionSources{
    {"filename", "pom", "manifest", "metadata", "package_json", "pe", "elf", "macho",
     "unreadable"}};

std::string clamp(std::string_view s) {
    return clamp_field(s, kV3MaxFieldLen);
}

char ascii_lower(char c) {
    return (c >= 'A' && c <= 'Z') ? static_cast<char>(c - 'A' + 'a') : c;
}

bool starts_with_ci(std::string_view s, std::string_view prefix) {
    if (s.size() < prefix.size())
        return false;
    for (std::size_t i = 0; i < prefix.size(); ++i) {
        if (ascii_lower(s[i]) != ascii_lower(prefix[i]))
            return false;
    }
    return true;
}

bool is_sep(char c) {
    return c == '\\' || c == '/';
}

// Comparator walks the stored fields in wire order, install_location before package_id and
// source: byte for byte the server's entry_less (software_inventory_store.cpp).
bool entry_less(const SwEntry& a, const SwEntry& b) {
    return std::tie(a.name, a.version, a.publisher, a.install_date, a.kind, a.ecosystem, a.epoch,
                    a.release, a.arch, a.signature_status, a.distro_id, a.distro_version,
                    a.install_location, a.package_id, a.source) <
           std::tie(b.name, b.version, b.publisher, b.install_date, b.kind, b.ecosystem, b.epoch,
                    b.release, b.arch, b.signature_status, b.distro_id, b.distro_version,
                    b.install_location, b.package_id, b.source);
}

bool entry_equal(const SwEntry& a, const SwEntry& b) {
    return !entry_less(a, b) && !entry_less(b, a);
}

// The 16 slots of a row already in normal form.
std::string record_of(const SwEntry& e) {
    const std::string_view slots[16] = {e.name,       e.version,          e.publisher,
                                        e.install_date, e.kind,           e.ecosystem,
                                        e.epoch,      e.release,          e.arch,
                                        e.signature_status, e.distro_id,  e.distro_version,
                                        e.install_location, std::string_view{}, e.package_id,
                                        e.source};
    std::string out;
    out.reserve(112);
    for (std::size_t i = 0; i < 16; ++i) {
        if (i)
            out += kUs;
        out += slots[i];
    }
    out += kRs;
    return out;
}

std::string version_source_of(std::string_view raw) {
    for (const auto v : kVersionSources) {
        if (v == raw)
            return std::string(v);
    }
    return "unreadable";
}

SwComponent component_normal_form(const SwComponent& in) {
    SwComponent c;
    c.kind = clamp(in.kind);
    c.name = clamp(in.name);
    c.version = clamp(in.version);
    c.version_source = version_source_of(in.version_source);
    c.path = clamp(in.path);
    c.size = std::max<std::int64_t>(in.size, 0);
    c.mtime = std::max<std::int64_t>(in.mtime, 0);
    c.anchor_app = clamp(in.anchor_app);
    return c;
}

std::string component_record_of(const SwComponent& c) {
    std::string out;
    out += c.kind;
    out += kUs;
    out += c.name;
    out += kUs;
    out += c.version;
    out += kUs;
    out += c.version_source;
    out += kUs;
    out += c.path;
    out += kUs;
    out += std::to_string(c.size);
    out += kUs;
    out += std::to_string(c.mtime);
    out += kUs;
    out += c.anchor_app;
    out += kRs;
    return out;
}

bool component_less(const SwComponent& a, const SwComponent& b) {
    return std::tie(a.kind, a.name, a.version, a.version_source, a.path, a.size, a.mtime,
                    a.anchor_app) < std::tie(b.kind, b.name, b.version, b.version_source, b.path,
                                             b.size, b.mtime, b.anchor_app);
}

std::vector<SwComponent> normalise_components(std::vector<SwComponent> rows) {
    std::vector<SwComponent> out;
    out.reserve(rows.size());
    for (const auto& r : rows) {
        SwComponent c = component_normal_form(r);
        if (!c.kind.empty() && !c.name.empty())
            out.push_back(std::move(c));
    }
    std::sort(out.begin(), out.end(), component_less);
    out.erase(std::unique(out.begin(), out.end(),
                          [](const SwComponent& a, const SwComponent& b) {
                              return !component_less(a, b) && !component_less(b, a);
                          }),
              out.end());
    return out;
}

bool is_hex64_lower(std::string_view s) {
    if (s.size() != 64)
        return false;
    for (const char c : s) {
        if (!((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f')))
            return false;
    }
    return true;
}

// The `S` record of a section.
void append_section_header(std::string& out, const SectionPlan& p) {
    out += 'S';
    out += kUs;
    out += p.facet;
    out += kUs;
    out += v3_status_name(p.status);
    out += kUs;
    out += p.base;
    out += kUs;
    out += sanitize_skip_reason(p.token); // [A-Za-z0-9_.:=,-], at most 64 bytes
    out += kUs;
    out += std::to_string(std::max<std::int64_t>(p.duration_ms, 0));
    out += kUs;
    out += std::to_string(std::max<std::int64_t>(p.bytes_read, 0));
    out += kUs;
    out += p.expect;
    out += kRs;
}

std::string serialise_section(const SectionPlan& p) {
    std::string out;
    append_section_header(out, p);
    if (!v3_status_carries_rows(p.status))
        return out;
    for (const auto& e : p.adds) {
        out += '+';
        out += kUs;
        out += v3_record(e);
    }
    for (const auto& h : p.deletes) {
        out += '-';
        out += kUs;
        out += h;
        out += kRs;
    }
    for (const auto& c : p.components) {
        out += "comp";
        out += kUs;
        out += v3_component_record(c);
    }
    return out;
}

} // namespace

std::string canonical_epoch(std::string_view epoch) {
    return (epoch == "0" || epoch == "(none)") ? std::string{} : std::string(epoch);
}

std::string canonical_release(std::string_view release) {
    return release == "(none)" ? std::string{} : std::string(release);
}

namespace {

// Roots that name an account, compared on the normalised form (lower case, '/' for '\\', any
// drive letter dropped) at a segment boundary.
constexpr std::string_view kPerUserRoots[] = {"/users", "/documents and settings", "/home",
                                               "/root"};

// The macOS firmlink: the Data volume's logical path is the same path without this prefix.
constexpr std::string_view kDataVolume = "/system/volumes/data";

} // namespace

bool is_per_user_path(std::string_view p) {
    if (p.size() >= 2 && is_sep(p[0]) && is_sep(p[1])) {
        // `\\?\` and `\\.\` are the Win32 extended-length and device prefixes: the path after
        // one is the same path as without it, so classify what follows. Anything else that
        // opens with two separators is a UNC path (`\\host\share\...`, `\\?\UNC\...`): the
        // writer cannot tell a home share from an application share, so every UNC path is
        // blanked (fail closed).
        if (p.size() < 4 || !(p[2] == '?' || p[2] == '.') || !is_sep(p[3]))
            return true;
        p.remove_prefix(4);
        if (starts_with_ci(p, "unc") && p.size() > 3 && is_sep(p[3]))
            return true;
    }
    // The same normalisation as mount_entry_is_personal (sync_source_device_ci.cpp), so the two
    // writers classify one spelling alike. They differ on purpose: /volumes is not a root here (an
    // install location on another volume names an application, not a person), a UNC path is
    // blanked above (fail closed) where the mount rule passes it through, and a non-path is kept
    // where the mount rule treats it as personal.
    std::string n(p);
    for (char& c : n)
        c = c == '\\' ? '/' : ascii_lower(c);
    std::string_view v = n;
    if (v.size() >= 2 && v[0] >= 'a' && v[0] <= 'z' && v[1] == ':')
        v.remove_prefix(2);
    if (v.starts_with(kDataVolume) && v.size() > kDataVolume.size() && v[kDataVolume.size()] == '/')
        v.remove_prefix(kDataVolume.size());
    for (const auto root : kPerUserRoots) {
        if (v.starts_with(root) && (v.size() == root.size() || v[root.size()] == '/'))
            return true;
    }
    return false;
}

SwEntry v3_normal_form(const SwEntry& in) {
    SwEntry e;
    e.name = clamp(in.name);
    e.version = clamp(in.version);
    e.publisher = clamp(in.publisher);
    e.install_date = clamp(in.install_date);
    e.kind = clamp(in.kind);
    e.ecosystem = clamp(in.ecosystem);
    e.epoch = canonical_epoch(clamp(in.epoch));
    e.release = canonical_release(clamp(in.release));
    e.arch = clamp(in.arch);
    e.signature_status = clamp(in.signature_status);
    e.distro_id = clamp(in.distro_id);
    e.distro_version = clamp(in.distro_version);
    e.install_location = clamp(in.install_location);
    if (is_per_user_path(e.install_location))
        e.install_location.clear();
    e.package_id = clamp(in.package_id);
    e.source = clamp(in.source);
    return e;
}

namespace {

// `planning`: the planner's rows get the facet as their source and the origin label for an empty
// publisher (every `+` record has a non-empty slot 3 and the source the server demands); the pure
// hash functions hash the fields as given.
std::vector<SwEntry> normalise_rows(const std::vector<SwEntry>& rows, bool planning,
                                    std::string_view facet = {}) {
    std::vector<SwEntry> out;
    out.reserve(rows.size());
    for (const auto& r : rows) {
        SwEntry e = v3_normal_form(r);
        if (e.name.empty())
            continue;
        if (planning) {
            e.source = std::string(facet); // the server refuses a `+` whose source is not its facet
            vendor_or_origin(e);
        }
        out.push_back(std::move(e));
    }
    std::sort(out.begin(), out.end(), entry_less);
    out.erase(std::unique(out.begin(), out.end(), entry_equal), out.end());
    return out;
}

} // namespace

std::vector<SwEntry> v3_normalise_rows(std::vector<SwEntry> rows) {
    return normalise_rows(rows, false);
}

std::string v3_record(const SwEntry& e) {
    return record_of(v3_normal_form(e));
}

std::string v3_row_hash(const SwEntry& e) {
    return sha256_hex(v3_record(e));
}

std::string v3_section_hash(std::vector<SwEntry> rows) {
    const auto norm = v3_normalise_rows(std::move(rows));
    std::string canon;
    canon.reserve(norm.size() * 112);
    for (const auto& e : norm)
        canon += record_of(e);
    return sha256_hex(canon);
}

std::string v3_report_hash(std::vector<std::pair<std::string, std::string>> held) {
    std::sort(held.begin(), held.end(),
              [](const auto& a, const auto& b) { return a.first < b.first; });
    std::string canon;
    for (const auto& [facet, hash] : held) {
        canon += facet;
        canon += kUs;
        canon += hash;
        canon += kRs;
    }
    return "v3:" + sha256_hex(canon);
}

std::string v3_component_record(const SwComponent& c) {
    return component_record_of(component_normal_form(c));
}

std::string v3_component_row_hash(const SwComponent& c) {
    return sha256_hex(v3_component_record(c));
}

std::string v3_component_section_hash(std::vector<SwComponent> rows) {
    const auto norm = normalise_components(std::move(rows));
    std::string canon;
    for (const auto& c : norm)
        canon += component_record_of(c);
    return sha256_hex(canon);
}

SectionPlan status_section(std::string facet, V3Status status, std::string token) {
    SectionPlan p;
    p.facet = std::move(facet);
    p.status = status;
    p.token = std::move(token);
    return p;
}

SectionPlan plan_section(std::string facet, std::vector<SwEntry> rows,
                         const std::optional<AckedSet>& acked, bool need_full) {
    SectionPlan p;
    p.facet = std::move(facet);
    // The cap is on what the server would hold after its own de-duplication.
    const std::vector<SwEntry> cur = normalise_rows(rows, true, p.facet);
    if (cur.size() > kV3MaxRows) {
        p.status = V3Status::oversize;
        p.token = "rows=" + std::to_string(cur.size());
        return p;
    }

    // Records, row hashes and the section hash in one pass over the sorted set.
    std::string canon;
    canon.reserve(cur.size() * 112);
    std::vector<std::string> hashes;
    hashes.reserve(cur.size());
    std::size_t full_bytes = 0;
    for (const auto& e : cur) {
        const std::string rec = record_of(e);
        canon += rec;
        hashes.push_back(sha256_hex(rec));
        full_bytes += 2 + rec.size(); // "+" US then the record
    }
    p.section_hash = sha256_hex(canon);
    p.row_hashes = hashes;
    std::sort(p.row_hashes.begin(), p.row_hashes.end());
    SectionPlan hdr;
    hdr.facet = p.facet;
    hdr.status = V3Status::full;
    std::string probe;
    append_section_header(probe, hdr);
    p.full_bytes = full_bytes + probe.size();
    if (p.full_bytes > kV3SectionByteBudget) {
        p.status = V3Status::oversize;
        p.token = "bytes=" + std::to_string(p.full_bytes);
        return p;
    }

    const auto make_full = [&] {
        p.status = V3Status::full;
        p.base.clear();
        p.expect.clear();
        p.adds = cur;
        p.deletes.clear();
    };
    if (!acked || need_full) {
        make_full();
        return p;
    }

    // A delta against the acked set: both sides are sorted, so the two differences are linear.
    std::vector<std::string> gone;
    std::set_difference(acked->row_hashes.begin(), acked->row_hashes.end(), p.row_hashes.begin(),
                        p.row_hashes.end(), std::back_inserter(gone));
    std::vector<SwEntry> added;
    for (std::size_t i = 0; i < cur.size(); ++i) {
        if (!std::binary_search(acked->row_hashes.begin(), acked->row_hashes.end(), hashes[i]))
            added.push_back(cur[i]);
    }
    if (added.empty() && gone.empty()) {
        if (acked->section_hash == p.section_hash) {
            p.status = V3Status::full; // not sent
            p.unchanged = true;
            return p;
        }
        // The same rows under a different hash: the acked pair is not self-consistent. Resync.
        make_full();
        return p;
    }
    if (added.size() > kV3MaxRows || gone.size() > kV3MaxDeletions) {
        make_full();
        return p;
    }
    p.status = V3Status::delta;
    p.base = acked->section_hash;
    p.expect = p.section_hash;
    p.adds = std::move(added);
    p.deletes = std::move(gone);
    // A delta carries the `-` records too, so a near-total replacement can outgrow the full form;
    // one that no longer fits the blob alone could never ship, so it falls back to the full section.
    if (serialise_section(p).size() > kV3SectionByteBudget)
        make_full();
    return p;
}

V3Blob write_v3_blob(const std::vector<SectionPlan>& plans) {
    V3Blob out;
    out.blob = std::string(kV3Header);
    std::size_t sections = 0;
    // Status-only sections first: they are small, bounded by the reserve the planner left, and
    // they must never be the thing a row-bearing section displaces.
    for (const auto& p : plans) {
        if (p.unchanged || v3_status_carries_rows(p.status) || sections >= kV3MaxSections)
            continue;
        append_section_header(out.blob, p);
        out.sent.push_back(p.facet);
        ++sections;
    }
    std::size_t adds = 0;
    std::size_t deletes = 0;
    std::size_t comps = 0;
    for (const auto& p : plans) {
        if (p.unchanged || !v3_status_carries_rows(p.status))
            continue;
        const std::string sec = serialise_section(p);
        if (sections >= kV3MaxSections || adds + p.adds.size() > kV3MaxRows ||
            deletes + p.deletes.size() > kV3MaxDeletions ||
            comps + p.components.size() > kV3MaxComponents ||
            out.blob.size() + sec.size() > kV3MaxBlobBytes) {
            out.deferred.push_back(p.facet);
            continue;
        }
        out.blob += sec;
        out.sent.push_back(p.facet);
        adds += p.adds.size();
        deletes += p.deletes.size();
        comps += p.components.size();
        ++sections;
    }
    return out;
}

std::string acked_encode(const AckedSet& a) {
    std::string out = a.section_hash;
    out += '\n';
    out.reserve(out.size() + a.row_hashes.size() * 64);
    for (const auto& h : a.row_hashes)
        out += h;
    return out;
}

std::optional<AckedSet> acked_decode(std::string_view v) {
    if (v.size() < 65 || v[64] != '\n' || !is_hex64_lower(v.substr(0, 64)))
        return std::nullopt;
    const std::string_view body = v.substr(65);
    if (body.size() % 64 != 0 || body.size() / 64 > kV3MaxRows)
        return std::nullopt;
    AckedSet a;
    a.section_hash = std::string(v.substr(0, 64));
    a.row_hashes.reserve(body.size() / 64);
    for (std::size_t i = 0; i < body.size(); i += 64) {
        const std::string_view h = body.substr(i, 64);
        if (!is_hex64_lower(h))
            return std::nullopt;
        a.row_hashes.emplace_back(h);
    }
    std::sort(a.row_hashes.begin(), a.row_hashes.end());
    a.row_hashes.erase(std::unique(a.row_hashes.begin(), a.row_hashes.end()), a.row_hashes.end());
    return a;
}

} // namespace yuzu::agent
