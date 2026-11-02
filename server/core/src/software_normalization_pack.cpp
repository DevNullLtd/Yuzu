/// @file software_normalization_pack.cpp
/// Pure CSV parser for the software-title alias pack. See the header.

#include "software_normalization_pack.hpp"

#include "sha256_hex.hpp"
#include "software_catalog_rules.hpp"

#include <algorithm>
#include <set>
#include <tuple>

namespace yuzu::server {

namespace {

constexpr std::string_view kVersionDirective = "#pack_version:";
constexpr std::size_t kFieldCount = 8;

std::string_view trim(std::string_view s) {
    while (!s.empty() && (s.front() == ' ' || s.front() == '\t'))
        s.remove_prefix(1);
    while (!s.empty() && (s.back() == ' ' || s.back() == '\t' || s.back() == '\r'))
        s.remove_suffix(1);
    return s;
}

/// `YYYY.MM.N`: 4 digits, '.', 2 digits, '.', 1+ digits.
bool valid_pack_version(std::string_view v) {
    const auto digits = [](std::string_view s) {
        return !s.empty() && std::all_of(s.begin(), s.end(), [](char c) { return c >= '0' && c <= '9'; });
    };
    if (v.size() < 9 || v[4] != '.' || v[7] != '.')
        return false;
    return digits(v.substr(0, 4)) && digits(v.substr(5, 2)) && digits(v.substr(8));
}

bool valid_cpe_product(std::string_view s) {
    return std::all_of(s.begin(), s.end(), [](char c) {
        return (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '_' || c == '.' ||
               c == '-' || c == '+';
    });
}

bool known_ecosystem(std::string_view e) {
    namespace sc = software_catalog;
    return e.empty() || std::any_of(sc::kEcosystemFamilies.begin(), sc::kEcosystemFamilies.end(),
                                    [&](const sc::EcosystemFamily& f) { return f.ecosystem == e; });
}

std::string line_error(std::size_t line, std::string_view what) {
    return "line " + std::to_string(line) + ": " + std::string{what};
}

} // namespace

std::expected<ParsedPack, std::string> parse_normalization_pack(std::string_view csv) {
    ParsedPack out;
    std::set<std::tuple<std::string, std::string, std::string>> seen;
    bool have_version = false;
    std::size_t line_no = 0;
    std::size_t pos = 0;
    while (pos <= csv.size()) {
        const std::size_t nl = csv.find('\n', pos);
        const std::string_view line =
            trim(csv.substr(pos, nl == std::string_view::npos ? std::string_view::npos : nl - pos));
        pos = nl == std::string_view::npos ? csv.size() + 1 : nl + 1;
        ++line_no;
        if (line.empty())
            continue;
        if (line.starts_with(kVersionDirective)) {
            if (have_version)
                return std::unexpected(line_error(line_no, "duplicate #pack_version directive"));
            const std::string_view v = trim(line.substr(kVersionDirective.size()));
            if (!valid_pack_version(v))
                return std::unexpected(
                    line_error(line_no, "pack_version must have the shape YYYY.MM.N"));
            out.pack_version = std::string{v};
            have_version = true;
            continue;
        }
        if (line.front() == '#')
            continue;
        if (line.find('"') != std::string_view::npos)
            return std::unexpected(line_error(line_no, "double quotes are not allowed"));

        std::vector<std::string_view> f;
        for (std::size_t s = 0;;) {
            const std::size_t c = line.find(',', s);
            f.push_back(trim(line.substr(s, c == std::string_view::npos ? std::string_view::npos : c - s)));
            if (c == std::string_view::npos)
                break;
            s = c + 1;
        }
        if (f.size() != kFieldCount)
            return std::unexpected(line_error(line_no, "expected exactly 8 fields"));

        PackRow row;
        row.ecosystem = std::string{f[0]};
        if (!known_ecosystem(row.ecosystem))
            return std::unexpected(line_error(line_no, "unknown ecosystem"));

        const NormalizedTitle nt = normalize_title(f[1]);
        if (nt.title.empty())
            return std::unexpected(line_error(line_no, "raw_name has no title tokens"));
        row.raw_name = alias_key(nt);
        row.raw_publisher = normalize_vendor(f[2]);

        row.vendor = normalize_vendor(f[3]);
        if (row.vendor.empty())
            return std::unexpected(line_error(line_no, "vendor is empty"));
        const NormalizedTitle prod = normalize_title(f[4]);
        if (prod.title.empty())
            return std::unexpected(line_error(line_no, "product has no title tokens"));
        row.title = prod.title;

        if (!f[5].empty()) {
            const NormalizedTitle col = normalize_title(f[5]);
            if (col.edition.empty() || !col.title.empty())
                return std::unexpected(line_error(line_no, "edition is not a recognised edition token"));
            if (!nt.edition.empty() && nt.edition != col.edition)
                return std::unexpected(line_error(line_no, "edition contradicts raw_name"));
            row.edition = col.edition;
        } else {
            row.edition = nt.edition;
        }

        row.category = f[6].empty() ? std::string{"other"} : std::string{f[6]};
        if (std::find(kCategories.begin(), kCategories.end(), row.category) == kCategories.end())
            return std::unexpected(line_error(line_no, "unknown category"));
        if (!valid_cpe_product(f[7]))
            return std::unexpected(line_error(line_no, "cpe_product has an invalid character"));
        row.cpe_product = std::string{f[7]};
        row.norm_key = product_norm_key(row.vendor, row.title, row.edition);

        if (!seen.emplace(row.ecosystem, row.raw_name, row.raw_publisher).second)
            return std::unexpected(line_error(line_no, "duplicate (ecosystem, raw_name, raw_publisher)"));
        out.rows.push_back(std::move(row));
    }
    if (!have_version)
        return std::unexpected("missing #pack_version directive");
    if (out.rows.size() < kMinSeedRows)
        return std::unexpected("pack has " + std::to_string(out.rows.size()) +
                               " rows, fewer than kMinSeedRows (" + std::to_string(kMinSeedRows) + ")");
    auto digest = sha256_hex(csv);
    if (!digest)
        return std::unexpected("sha256 failed");
    out.sha256 = std::move(*digest);
    out.body = std::string{csv};
    return out;
}

} // namespace yuzu::server
