/**
 * test_middleware_parsers.cpp -- tests for the middleware plugin's pure layer: the product table
 * (agents/shared/middleware_products.hpp), the key=value / file-name parsers and the token and row
 * formatters (middleware_parsers.hpp), and the generic runner (middleware_runner.hpp) driven end to
 * end over an in-memory FakeFs. Builds and runs on every OS, unguarded: nothing here touches a real
 * filesystem beyond reading the committed fixtures.
 *
 * Fixtures: tests/unit/fixtures/middleware/linux/ -- swidtag.listing is a REAL CAPTURE of
 * `ls -ln /opt/mqm/swidtag` from IBM MQ developer images and from a registered 9.4.5.0 install;
 * mqinst.ini is the REAL byte-exact file of that registered install (one stanza, 64 trailing spaces
 * in Description, no Primary key; provenance.txt has the sha256 and cites IBM's documentation).
 * The only synthetic input is kTwoInstallationsInline below, a clearly labelled inline string.
 * Fixtures are read via YUZU_TEST_FIXTURE_DIR and REQUIREd to exist -- a missing fixture fails,
 * never skips.
 *
 * MUTATION NOTES (each assertion below FAILS if the named wiring is removed):
 *  - R1 (component tags): dropping NameForm::exact's "rest starts with '-'" rule fails the
 *    "every component name is rejected" loop and the component-tags-only run_leg case.
 *  - R4 (erroneous listing): matching names before checking `error`/`truncated` fails the
 *    "a listing flagged ... never matches its valid name" cases.
 *  - one budget (R6): constructing a second budget inside run_leg fails the rows=2 / bytes cases.
 *  - per-item reasons never tokenised: routing an ItemReason into the accumulator fails the
 *    `status|ibm_mq|supported|-` assertions of every per-item case.
 *  - one listing per subdirectory: dropping the memo fails the list_calls assertions.
 *  - stanzas never merge: reusing yuzu::shared::parse_ini fails the "not merged" case.
 */
#include <catch2/catch_test_macros.hpp>

#include "middleware_parsers.hpp"
#include "middleware_runner.hpp"

#include <middleware_products.hpp>

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <filesystem>
#include <fstream>
#include <initializer_list>
#include <iterator>
#include <map>
#include <optional>
#include <sstream>
#include <string>
#include <string_view>
#include <type_traits>
#include <utility>
#include <vector>

namespace mw = yuzu::middleware;

namespace {

// -- fixtures -------------------------------------------------------------------------------------

std::filesystem::path fixture_path(const char* name) {
#ifdef YUZU_TEST_FIXTURE_DIR
    return std::filesystem::path(YUZU_TEST_FIXTURE_DIR) / "middleware" / "linux" / name;
#else
    return std::filesystem::path("tests/unit/fixtures/middleware/linux") / name;
#endif
}

std::string read_fixture(const char* name) {
    const auto p = fixture_path(name);
    REQUIRE(std::filesystem::exists(p));
    std::ifstream in(p, std::ios::binary);
    REQUIRE(in.good());
    return std::string(std::istreambuf_iterator<char>(in), std::istreambuf_iterator<char>());
}

std::vector<std::string> lines_of(const std::string& text) {
    std::vector<std::string> out;
    std::istringstream ss(text);
    std::string l;
    while (std::getline(ss, l))
        out.push_back(l);
    return out;
}

std::string last_token(const std::string& line) {
    const auto end = line.find_last_not_of(" \t\r");
    if (end == std::string::npos)
        return {};
    const auto sp = line.find_last_of(" \t", end);
    const std::size_t start = sp == std::string::npos ? 0 : sp + 1;
    return line.substr(start, end - start + 1);
}

/// The file names of the swidtag.listing section whose `# image` header contains `marker`.
std::vector<std::string> listing_section(std::string_view marker) {
    std::vector<std::string> names;
    bool in = false;
    for (const std::string& l : lines_of(read_fixture("swidtag.listing"))) {
        if (!l.empty() && l[0] == '#')
            in = l.find(marker) != std::string::npos;
        else if (in && !l.empty() && l[0] == '-')
            names.push_back(last_token(l));
    }
    return names;
}

constexpr std::string_view kV1001 = "mq:latest";   // 10.0.1.0-r1
constexpr std::string_view kV925 = "mq:9.2.5.0-r3";
constexpr std::string_view kV915 = "mq:9.1.5.0-r2";
constexpr std::string_view kV935 = "mq:9.3.5.1-r2";
constexpr std::string_view kV945 = "9.4.5.0 debs"; // the REGISTERED install (mqinst.ini's source)

/// SYNTHETIC (inline, not a capture): two installations, to prove stanzas are never merged. A real
/// registered install holds one stanza (the mqinst.ini fixture), so no captured file has two.
constexpr const char* kTwoInstallationsInline =
    "Installation:\n"
    "   Name=Installation1\n"
    "   Description=\n"
    "   Identifier=1\n"
    "   FilePath=/opt/mqm\n"
    "   Primary=Yes\n"
    "Installation:\n"
    "   Name=Installation2\n"
    "   Description=second\n"
    "   Identifier=2\n"
    "   FilePath=/opt/mqm2\n"
    "   Primary=No\n";

std::vector<std::string> with_suffix(const std::vector<std::string>& v, std::string_view suffix) {
    std::vector<std::string> out;
    for (const auto& n : v)
        if (n.size() >= suffix.size() && n.compare(n.size() - suffix.size(), suffix.size(), suffix) == 0)
            out.push_back(n);
    return out;
}

// -- wire helpers ---------------------------------------------------------------------------------

/// Escape-aware field split: safe_output_field writes a literal '|' as `\|`, so a naive
/// split('|') overcounts.
std::vector<std::string> split_fields(const std::string& row) {
    std::vector<std::string> f;
    std::string cur;
    for (std::size_t i = 0; i < row.size(); ++i) {
        if (row[i] == '\\' && i + 1 < row.size() && row[i + 1] == '|') {
            cur += '|';
            ++i;
        } else if (row[i] == '|') {
            f.push_back(std::move(cur));
            cur.clear();
        } else {
            cur += row[i];
        }
    }
    f.push_back(std::move(cur));
    return f;
}

std::vector<std::string> split_on(std::string_view s, char sep) {
    std::vector<std::string> out;
    std::size_t pos = 0;
    while (pos <= s.size()) {
        auto at = s.find(sep, pos);
        if (at == std::string_view::npos)
            at = s.size();
        out.emplace_back(s.substr(pos, at - pos));
        pos = at + 1;
    }
    return out;
}

bool all_of_ident(const std::string& s) {
    return !s.empty() && std::all_of(s.begin(), s.end(), [](char c) {
        return (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '_';
    });
}

/// ^(windows|macos|linux):middleware:[a-z0-9_]+:[a-z0-9_]+$
bool is_wire_token(std::string_view t) {
    const auto p = split_on(t, ':');
    return p.size() == 4 && (p[0] == "windows" || p[0] == "macos" || p[0] == "linux") &&
           p[1] == "middleware" && all_of_ident(p[2]) && all_of_ident(p[3]);
}

/// Parses a composed status row and applies the wire rules every status row must hold: the token
/// grammar, a source that is the enumerator probe or `walk`, and no per-item-only spelling.
std::vector<std::string> status_tokens(const std::string& row, std::string_view level) {
    const auto f = split_fields(row);
    REQUIRE(f.size() == 4);
    REQUIRE(f[0] == "status");
    REQUIRE(f[1] == "ibm_mq");
    REQUIRE(f[2] == level);
    std::vector<std::string> tokens;
    if (f[3] != "-")
        tokens = split_on(f[3], ',');
    for (const auto& t : tokens) {
        CAPTURE(t);
        REQUIRE(is_wire_token(t));
        const auto p = split_on(t, ':');
        CHECK((p[2] == "mqinst_ini" || p[2] == "walk"));
        CHECK(p[3] != "missing");
        CHECK(p[3] != "path_refused");
    }
    return tokens;
}

// -- FakeFs ---------------------------------------------------------------------------------------

struct FakeFs {
    std::map<std::string, mw::Read> files;     // abs path -> scripted read
    std::map<std::string, mw::Listing> dirs;   // "<base>|<subdir>" -> scripted listing
    std::size_t exhaust_after = SIZE_MAX;      // exhausted() once this many listings were made
    std::vector<std::pair<std::string, std::size_t>> read_calls; // (path, cap)
    std::vector<std::string> list_calls;                         // "<base>|<subdir>"
    std::vector<std::size_t> list_caps;

    void put_file(const std::string& path, std::string text) {
        files[path] = mw::Read{mw::Read::Outcome::ok, std::move(text)};
    }
    void put_outcome(const std::string& path, mw::Read::Outcome o) {
        files[path] = mw::Read{o, {}};
    }
    void put_dir(const std::string& base, const std::string& subdir, mw::Listing l) {
        dirs[base + "|" + subdir] = std::move(l);
    }
    void put_names(const std::string& base, std::vector<std::string> names) {
        put_dir(base, "swidtag", mw::Listing{std::move(names), false, false, mw::Read::Outcome::ok});
    }

    mw::Read read_abs(std::string_view path, std::size_t cap) {
        read_calls.emplace_back(std::string{path}, cap);
        const auto it = files.find(std::string{path});
        if (it == files.end())
            return mw::Read{mw::Read::Outcome::absent, {}};
        if (it->second.out == mw::Read::Outcome::ok && it->second.text.size() > cap)
            return mw::Read{mw::Read::Outcome::oversized, {}};
        return it->second;
    }
    mw::Listing list_under(std::string_view base, std::string_view subdir, std::size_t cap) {
        const std::string key = std::string{base} + "|" + std::string{subdir};
        list_calls.push_back(key);
        list_caps.push_back(cap);
        const auto it = dirs.find(key);
        if (it == dirs.end())
            return mw::Listing{{}, false, false, mw::Read::Outcome::absent};
        mw::Listing l = it->second;
        if (l.names.size() > cap) {
            l.names.resize(cap);
            l.truncated = true;
        }
        return l;
    }
    bool exhausted() const { return list_calls.size() >= exhaust_after; }
    std::string_view os() const { return "linux"; }
};
static_assert(mw::MiddlewareFs<FakeFs>);

constexpr const char* kIni = "/etc/opt/mqm/mqinst.ini";

struct LogEvent {
    std::string product, probe;
    mw::ItemReason reason;
    std::string candidate;
    bool operator==(const LogEvent&) const = default;
};

struct LegRun {
    std::vector<std::string> rows; ///< composed: the status row first
    std::vector<LogEvent> events;
    std::vector<std::string> data() const { return std::vector<std::string>(rows.begin() + 1, rows.end()); }
    const std::string& status() const { return rows.front(); }
};

/// Runs the ibm_mq Linux leg over `fs` and checks the wire rules of its status row.
LegRun run(FakeFs& fs, yuzu::shared::RowByteBudget budget = mw::make_row_budget()) {
    const mw::Product& p = *mw::find_product("ibm_mq");
    yuzu::shared::ConstraintAccumulator acc;
    LegRun r;
    const auto data = mw::run_leg(
        p, p.linux, fs, acc, budget,
        [&](std::string_view prod, std::string_view probe, mw::ItemReason why, std::string_view cand) {
            r.events.push_back({std::string{prod}, std::string{probe}, why, std::string{cand}});
        });
    r.rows = mw::compose_output(p.id, data, acc);
    REQUIRE_FALSE(r.rows.empty());
    status_tokens(r.status(), acc.any_failure() ? "constrained" : "supported");
    return r;
}

std::string ini_of(std::initializer_list<std::pair<const char*, const char*>> installs) {
    std::string t;
    for (const auto& [name, path] : installs) {
        t += "Installation:\n   Name=";
        t += name;
        t += "\n   FilePath=";
        t += path;
        t += "\n";
    }
    return t;
}

LogEvent ev(const char* probe, mw::ItemReason r, const char* cand) {
    return {"ibm_mq", probe, r, cand};
}

// -- deliberately broken tables (namespace scope: a span needs static storage) ---------------------

using mw::Probe;
using mw::Product;

template <class Fn> constexpr Product mutated(Fn fn) {
    Product p = mw::kProducts[0];
    fn(p);
    return p;
}

constexpr std::array<Probe, 2> kProbesDirFirst{{mw::kIbmMqLinuxProbes[1], mw::kIbmMqLinuxProbes[0]}};
constexpr std::array<Probe, 2> kProbesKvSecond{{mw::kIbmMqLinuxProbes[0], mw::kIbmMqLinuxProbes[0]}};
constexpr std::array<Probe, 2> kProbesSlash = [] {
    std::array<Probe, 2> a{{mw::kIbmMqLinuxProbes[0], mw::kIbmMqLinuxProbes[1]}};
    a[1].path = "a/b";
    return a;
}();
constexpr std::array<Probe, 2> kProbesDotDot = [] {
    std::array<Probe, 2> a{{mw::kIbmMqLinuxProbes[0], mw::kIbmMqLinuxProbes[1]}};
    a[1].path = "..";
    return a;
}();
constexpr std::array<Probe, 2> kProbesEmptySuffix = [] {
    std::array<Probe, 2> a{{mw::kIbmMqLinuxProbes[0], mw::kIbmMqLinuxProbes[1]}};
    a[1].name_suffix = "";
    return a;
}();
constexpr std::array<Probe, 2> kProbesNoKey = [] {
    std::array<Probe, 2> a{{mw::kIbmMqLinuxProbes[0], mw::kIbmMqLinuxProbes[1]}};
    a[0].path_key = nullptr;
    return a;
}();
constexpr std::array<Probe, 2> kProbesRelative = [] {
    std::array<Probe, 2> a{{mw::kIbmMqLinuxProbes[0], mw::kIbmMqLinuxProbes[1]}};
    a[0].path = "etc/mqinst.ini";
    return a;
}();
constexpr std::array<Probe, 2> kProbesDupId = [] {
    std::array<Probe, 2> a{{mw::kIbmMqLinuxProbes[0], mw::kIbmMqLinuxProbes[1]}};
    a[1].id = "mqinst_ini";
    return a;
}();
constexpr std::array<Probe, 2> kProbesBadId = [] {
    std::array<Probe, 2> a{{mw::kIbmMqLinuxProbes[0], mw::kIbmMqLinuxProbes[1]}};
    a[1].id = "Swid-Tag";
    return a;
}();
constexpr std::array<Probe, 2> kProbesBadForm = [] {
    std::array<Probe, 2> a{{mw::kIbmMqLinuxProbes[0], mw::kIbmMqLinuxProbes[1]}};
    a[1].name_form = static_cast<mw::NameForm>(7);
    return a;
}();

constexpr std::array<Product, 1> kGoodControl{
    {mutated([](Product& p) { p.linux.support = YUZU_SUPPORT_CONSTRAINED; })}};
constexpr std::array<Product, 1> kBadSupportedNoProbes{
    {mutated([](Product& p) { p.linux.probes = {}; })}};
constexpr std::array<Product, 1> kBadPlannedWithProbes{
    {mutated([](Product& p) { p.linux.support = YUZU_SUPPORT_PLANNED; })}};
constexpr std::array<Product, 1> kBadSupportLevel{
    {mutated([](Product& p) { p.windows.support = YUZU_SUPPORT_UNSUPPORTED; })}};
constexpr std::array<Product, 1> kBadMechanism{{mutated([](Product& p) { p.linux.mechanism = ""; })}};
constexpr std::array<Product, 1> kBadKind{{mutated([](Product& p) { p.kind = "library"; })}};
constexpr std::array<Product, 1> kBadEcosystem{{mutated([](Product& p) { p.ecosystem = "IBM_MQ"; })}};
constexpr std::array<Product, 1> kBadId{{mutated([](Product& p) { p.id = "9mq"; })}};
constexpr std::array<Product, 1> kBadTitle{{mutated([](Product& p) { p.title = ""; })}};
constexpr std::array<Product, 1> kBadVendor{{mutated([](Product& p) { p.vendor = nullptr; })}};
constexpr std::array<Product, 2> kBadDuplicateId{{mw::kProducts[0], mutated([](Product& p) {
                                                     p.ecosystem = "other";
                                                 })}};
constexpr std::array<Product, 2> kBadDuplicateEcosystem{{mw::kProducts[0], mutated([](Product& p) {
                                                            p.id = "other";
                                                        })}};
constexpr std::array<Product, 1> kBadDirFirst{
    {mutated([](Product& p) { p.linux.probes = kProbesDirFirst; })}};
constexpr std::array<Product, 1> kBadKvSecond{
    {mutated([](Product& p) { p.linux.probes = kProbesKvSecond; })}};
constexpr std::array<Product, 1> kBadSlash{{mutated([](Product& p) { p.linux.probes = kProbesSlash; })}};
constexpr std::array<Product, 1> kBadDotDot{{mutated([](Product& p) { p.linux.probes = kProbesDotDot; })}};
constexpr std::array<Product, 1> kBadEmptySuffix{
    {mutated([](Product& p) { p.linux.probes = kProbesEmptySuffix; })}};
constexpr std::array<Product, 1> kBadNoKey{{mutated([](Product& p) { p.linux.probes = kProbesNoKey; })}};
constexpr std::array<Product, 1> kBadRelative{
    {mutated([](Product& p) { p.linux.probes = kProbesRelative; })}};
constexpr std::array<Product, 1> kBadDupId{{mutated([](Product& p) { p.linux.probes = kProbesDupId; })}};
constexpr std::array<Product, 1> kBadProbeId{{mutated([](Product& p) { p.linux.probes = kProbesBadId; })}};
constexpr std::array<Product, 1> kBadForm{{mutated([](Product& p) { p.linux.probes = kProbesBadForm; })}};

// -- a second, test-only table: kv_file with no stanza header and a version key ---------------------

constexpr std::array<Probe, 2> kKvVersionProbes{{
    {"inst", mw::ProbeKind::kv_file, "/etc/acme.conf", nullptr, "Name", "Path", "Version", nullptr,
     nullptr, mw::NameForm::exact},
    {"tags", mw::ProbeKind::dir_name, "tags", nullptr, nullptr, nullptr, nullptr, "acme", ".tag",
     mw::NameForm::exact},
}};
constexpr std::array<Product, 1> kAcme{{mutated([](Product& p) {
    p.id = "acme";
    p.title = "Acme";
    p.ecosystem = "acme";
    p.linux.probes = kKvVersionProbes;
})}};
static_assert(mw::products_well_formed(std::span<const Product>{kAcme}));

} // namespace

// =================================================================================================
// product table
// =================================================================================================

TEST_CASE("middleware products: the table is well-formed and find_product reads it", "[middleware]") {
    STATIC_REQUIRE(mw::products_well_formed());

    const mw::Product* p = mw::find_product("ibm_mq");
    REQUIRE(p != nullptr);
    CHECK(std::string_view{p->title} == "IBM MQ");
    CHECK(std::string_view{p->vendor} == "IBM");
    CHECK(std::string_view{p->ecosystem} == "ibm_mq");
    CHECK(std::string_view{p->kind} == "app");
    CHECK(p->linux.support == YUZU_SUPPORT_SUPPORTED);
    CHECK(p->linux.probes.size() == 4);
    CHECK(p->windows.support == YUZU_SUPPORT_PLANNED);
    CHECK(p->windows.probes.empty());
    CHECK(p->windows.note != nullptr);
    CHECK(mw::find_product("nope") == nullptr);
    CHECK(mw::find_product("") == nullptr);

    const auto probes = p->linux.probes;
    CHECK(std::string_view{probes[0].id} == "mqinst_ini");
    CHECK(probes[0].kind == mw::ProbeKind::kv_file);
    CHECK(std::string_view{probes[0].stanza} == "Installation:");
    CHECK(std::string_view{probes[1].id} == "swidtag");
    CHECK(std::string_view{probes[2].id} == "swidtag_websphere");
    CHECK(std::string_view{probes[3].id} == "mqtag");
    CHECK(probes[3].name_form == mw::NameForm::exact);
}

TEST_CASE("middleware products: the same consteval check refuses a broken table", "[middleware]") {
    STATIC_REQUIRE(mw::products_well_formed(std::span<const Product>{kGoodControl}));

    SECTION("a SUPPORTED leg with no probes (the spec's deliberately broken copy)") {
        STATIC_REQUIRE_FALSE(mw::products_well_formed(std::span<const Product>{kBadSupportedNoProbes}));
    }
    SECTION("a PLANNED leg that has probes") {
        STATIC_REQUIRE_FALSE(mw::products_well_formed(std::span<const Product>{kBadPlannedWithProbes}));
    }
    SECTION("a support level outside PLANNED / CONSTRAINED / SUPPORTED") {
        STATIC_REQUIRE_FALSE(mw::products_well_formed(std::span<const Product>{kBadSupportLevel}));
    }
    SECTION("empty mechanism, title, nullptr vendor, wrong kind") {
        STATIC_REQUIRE_FALSE(mw::products_well_formed(std::span<const Product>{kBadMechanism}));
        STATIC_REQUIRE_FALSE(mw::products_well_formed(std::span<const Product>{kBadTitle}));
        STATIC_REQUIRE_FALSE(mw::products_well_formed(std::span<const Product>{kBadVendor}));
        STATIC_REQUIRE_FALSE(mw::products_well_formed(std::span<const Product>{kBadKind}));
    }
    SECTION("ids and ecosystems are [a-z][a-z0-9_]* and unique") {
        STATIC_REQUIRE_FALSE(mw::products_well_formed(std::span<const Product>{kBadEcosystem}));
        STATIC_REQUIRE_FALSE(mw::products_well_formed(std::span<const Product>{kBadId}));
        STATIC_REQUIRE_FALSE(mw::products_well_formed(std::span<const Product>{kBadDuplicateId}));
        STATIC_REQUIRE_FALSE(mw::products_well_formed(std::span<const Product>{kBadDuplicateEcosystem}));
    }
    SECTION("probes[0] must be an absolute kv_file with both keys") {
        STATIC_REQUIRE_FALSE(mw::products_well_formed(std::span<const Product>{kBadDirFirst}));
        STATIC_REQUIRE_FALSE(mw::products_well_formed(std::span<const Product>{kBadNoKey}));
        STATIC_REQUIRE_FALSE(mw::products_well_formed(std::span<const Product>{kBadRelative}));
    }
    SECTION("probes[1..] must be dir_name probes with a single-component path and a real grammar") {
        STATIC_REQUIRE_FALSE(mw::products_well_formed(std::span<const Product>{kBadKvSecond}));
        STATIC_REQUIRE_FALSE(mw::products_well_formed(std::span<const Product>{kBadSlash}));
        STATIC_REQUIRE_FALSE(mw::products_well_formed(std::span<const Product>{kBadDotDot}));
        STATIC_REQUIRE_FALSE(mw::products_well_formed(std::span<const Product>{kBadEmptySuffix}));
        STATIC_REQUIRE_FALSE(mw::products_well_formed(std::span<const Product>{kBadForm}));
    }
    SECTION("probe ids are [a-z0-9_]+ and unique within the leg") {
        STATIC_REQUIRE_FALSE(mw::products_well_formed(std::span<const Product>{kBadDupId}));
        STATIC_REQUIRE_FALSE(mw::products_well_formed(std::span<const Product>{kBadProbeId}));
    }
}

// =================================================================================================
// parse_kv_stanzas
// =================================================================================================

TEST_CASE("middleware parsers: parse_kv_stanzas reads the REAL registered-install mqinst.ini",
          "[middleware]") {
    const std::string raw = read_fixture("mqinst.ini");
    // the fixture is byte-exact: 153 bytes, Description's value is 64 trailing spaces (so a stripped
    // fixture, or a parser that keeps the padding, fails here)
    REQUIRE(raw.size() == 153);
    REQUIRE(raw.find("Description=" + std::string(64, ' ') + "\n") != std::string::npos);

    mw::ParseReport rep;
    const auto st = mw::parse_kv_stanzas(raw, "Installation:", rep);
    REQUIRE(st.size() == 1);
    CHECK(rep.seen == 1);
    CHECK(rep.dropped == 0);
    CHECK_FALSE(rep.truncated);
    CHECK_FALSE(rep.malformed);
    CHECK(st[0].kv.size() == 4);
    CHECK(*st[0].get("Name") == "Installation1");
    CHECK(*st[0].get("FilePath") == "/opt/mqm");
    CHECK(*st[0].get("Identifier") == "1");
    REQUIRE(st[0].get("Description") != nullptr);
    CHECK(st[0].get("Description")->empty()); // trimmed: the 64 spaces are padding, not data
    CHECK(st[0].get("Primary") == nullptr);   // a fresh install has no Primary key; never required
}

TEST_CASE("middleware parsers: parse_kv_stanzas reads two installations as two stanzas, never merged",
          "[middleware]") {
    mw::ParseReport rep;
    const auto st = mw::parse_kv_stanzas(kTwoInstallationsInline, "Installation:", rep);
    REQUIRE(st.size() == 2);
    CHECK(rep.seen == 2);
    CHECK(rep.dropped == 0);
    CHECK_FALSE(rep.truncated);
    CHECK_FALSE(rep.malformed);
    CHECK(*st[0].get("Name") == "Installation1");
    CHECK(*st[0].get("FilePath") == "/opt/mqm");
    CHECK(*st[1].get("Name") == "Installation2");
    CHECK(*st[1].get("FilePath") == "/opt/mqm2");
    REQUIRE(st[0].get("Description") != nullptr);
    CHECK(st[0].get("Description")->empty());
    CHECK(*st[1].get("Description") == "second");
    CHECK(st[0].get("Nope") == nullptr);
}

TEST_CASE("middleware parsers: parse_kv_stanzas never merges and reads the first occurrence",
          "[middleware]") {
    SECTION("a re-opened header is a new stanza") {
        mw::ParseReport rep;
        const auto st = mw::parse_kv_stanzas(
            "Installation:\nName=a\nInstallation:\nName=a\nFilePath=/x\n", "Installation:", rep);
        REQUIRE(st.size() == 2);
        CHECK(st[0].get("FilePath") == nullptr);
        CHECK(*st[1].get("FilePath") == "/x");
    }
    SECTION("the FIRST occurrence of a key wins") {
        mw::ParseReport rep;
        const auto st = mw::parse_kv_stanzas("Installation:\nName=first\nName=second\n",
                                              "Installation:", rep);
        REQUIRE(st.size() == 1);
        CHECK(st[0].kv.size() == 2);
        CHECK(*st[0].get("Name") == "first");
    }
}

TEST_CASE("middleware parsers: parse_kv_stanzas stanza and line rules", "[middleware]") {
    mw::ParseReport rep;
    SECTION("the [Installation] form is not a stanza line: zero stanzas, malformed") {
        const auto st = mw::parse_kv_stanzas("[Installation]\nName=a\nFilePath=/x\n", "Installation:", rep);
        CHECK(st.empty());
        CHECK(rep.malformed);
    }
    SECTION("any other Word: line closes the stanza and opens none") {
        const auto st = mw::parse_kv_stanzas(
            "Installation:\n Name=a\n FilePath=/p\nOther:\n Name=zzz\nInstallation:\n Name=b\n",
            "Installation:", rep);
        REQUIRE(st.size() == 2);
        CHECK(*st[0].get("Name") == "a");
        CHECK(st[0].kv.size() == 2);
        CHECK(*st[1].get("Name") == "b");
        CHECK_FALSE(rep.malformed);
    }
    SECTION("key=value lines outside a stanza are ignored") {
        const auto st = mw::parse_kv_stanzas("Name=a\nInstallation:\nName=b\n", "Installation:", rep);
        REQUIRE(st.size() == 1);
        CHECK(*st[0].get("Name") == "b");
        CHECK_FALSE(rep.malformed);
    }
    SECTION("comments, blanks, CRLF and padded keys and values") {
        const auto st = mw::parse_kv_stanzas(
            "# c\r\n; c\r\n\r\nInstallation:\r\n   Name = X Y \r\n   =novalue\r\n", "Installation:", rep);
        REQUIRE(st.size() == 1);
        CHECK(*st[0].get("Name") == "X Y");
        CHECK(st[0].kv.size() == 1);
    }
    SECTION("an empty stanza is kept for the caller to drop") {
        const auto st = mw::parse_kv_stanzas("Installation:\nInstallation:\nName=a\n", "Installation:", rep);
        REQUIRE(st.size() == 2);
        CHECK(st[0].kv.empty());
    }
    SECTION("empty and comment-only text: nothing, and not malformed") {
        CHECK(mw::parse_kv_stanzas("", "Installation:", rep).empty());
        CHECK(mw::parse_kv_stanzas("# only\n; comments\n\n", "Installation:", rep).empty());
        CHECK_FALSE(rep.malformed);
    }
}

TEST_CASE("middleware parsers: parse_kv_stanzas caps rows and bytes", "[middleware]") {
    const auto many = [](std::size_t n) {
        std::string t;
        for (std::size_t i = 0; i < n; ++i)
            t += "Installation:\nName=n" + std::to_string(i) + "\nFilePath=/p\n";
        return t;
    };
    SECTION("exactly kMaxRows stanzas complete") {
        mw::ParseReport rep;
        const auto st = mw::parse_kv_stanzas(many(mw::kMaxRows), "Installation:", rep);
        CHECK(st.size() == mw::kMaxRows);
        CHECK_FALSE(rep.truncated);
    }
    SECTION("one more sets truncated and stops") {
        mw::ParseReport rep;
        const auto st = mw::parse_kv_stanzas(many(mw::kMaxRows + 1), "Installation:", rep);
        CHECK(st.size() == mw::kMaxRows);
        CHECK(rep.truncated);
        CHECK_FALSE(rep.malformed);
    }
    SECTION("text over kMaxKvFileBytes parses nothing") {
        mw::ParseReport rep;
        std::string t = "Installation:\nName=a\nFilePath=/p\n#";
        t.append(mw::kMaxKvFileBytes - t.size() + 1, 'x');
        REQUIRE(t.size() == mw::kMaxKvFileBytes + 1);
        CHECK(mw::parse_kv_stanzas(t, "Installation:", rep).empty());
        CHECK(rep.truncated);
    }
    SECTION("text of exactly kMaxKvFileBytes still parses") {
        mw::ParseReport rep;
        std::string t = "Installation:\nName=a\nFilePath=/p\n#";
        t.append(mw::kMaxKvFileBytes - t.size(), 'x');
        REQUIRE(t.size() == mw::kMaxKvFileBytes);
        CHECK(mw::parse_kv_stanzas(t, "Installation:", rep).size() == 1);
        CHECK_FALSE(rep.truncated);
    }
}

TEST_CASE("middleware parsers: parse_kv_stanzas with no header makes the whole text one stanza",
          "[middleware]") {
    mw::ParseReport rep;
    SECTION("oraInst.loc-shaped text") {
        const auto st = mw::parse_kv_stanzas(
            "inventory_loc=/opt/oracle/oraInventory\ninst_group=oinstall\n", nullptr, rep);
        REQUIRE(st.size() == 1);
        CHECK(*st[0].get("inventory_loc") == "/opt/oracle/oraInventory");
        CHECK(*st[0].get("inst_group") == "oinstall");
        CHECK_FALSE(rep.malformed);
    }
    SECTION("a repeated key stays in the one stanza, first wins") {
        const auto st = mw::parse_kv_stanzas("k=/a\nk=/b\n", nullptr, rep);
        REQUIRE(st.size() == 1);
        CHECK(*st[0].get("k") == "/a");
    }
    SECTION("content without a single key=value is one empty stanza; no content is none") {
        CHECK(mw::parse_kv_stanzas("garbage\n", nullptr, rep).size() == 1);
        CHECK(mw::parse_kv_stanzas("# nothing\n", nullptr, rep).empty());
    }
}

// =================================================================================================
// version_from_file_name
// =================================================================================================

namespace {
const mw::Probe& kSwid = mw::kIbmMqLinuxProbes[1];
const mw::Probe& kWebSphere = mw::kIbmMqLinuxProbes[2];
const mw::Probe& kMqtag = mw::kIbmMqLinuxProbes[3];

std::optional<std::string> ver(const mw::Probe& p, std::string_view name) {
    return mw::version_from_file_name(name, p.name_prefix, p.name_suffix, p.name_form);
}
} // namespace

TEST_CASE("middleware parsers: swidtag file names of the REAL listing yield their versions",
          "[middleware]") {
    const std::array<std::pair<std::string_view, std::string_view>, 5> images{{
        {kV1001, "10.0.1"},
        {kV945, "9.4.5"},
        {kV935, "9.3.5"},
        {kV925, "9.2.5"},
        {kV915, "9.1.5"}}};
    for (const auto& [marker, expected] : images) {
        CAPTURE(marker);
        const auto swid = with_suffix(listing_section(marker), ".swidtag");
        REQUIRE(swid.size() == 1);
        CHECK(swid[0] == "ibm.com_IBM_MQ_Advanced_for_Developers_Non-Warranted-" +
                             std::string{expected} + ".swidtag");
        CHECK(ver(kSwid, swid[0]) == std::string{expected});
        CHECK_FALSE(ver(kWebSphere, swid[0]).has_value());
        CHECK_FALSE(ver(kMqtag, swid[0]).has_value());
    }
}

TEST_CASE("middleware parsers: only IBM_MQ-<v>.mqtag names the product (R1)", "[middleware]") {
    SECTION("the real product tags") {
        CHECK(ver(kMqtag, "IBM_MQ-9.2.5.mqtag") == std::string{"9.2.5"});
        CHECK(ver(kMqtag, "IBM_MQ-9.1.5.mqtag") == std::string{"9.1.5"});
        CHECK(ver(kMqtag, "IBM_MQ-9.4.5.mqtag") == std::string{"9.4.5"});
    }
    SECTION("the registered 9.4.5 install: exactly its product tag yields, its component tags do not") {
        const auto mqtags = with_suffix(listing_section(kV945), ".mqtag");
        REQUIRE(mqtags == std::vector<std::string>{"IBM_MQ-9.4.5.mqtag", "IBM_MQ_GSKit-9.0.0.mqtag",
                                                   "IBM_MQ_Runtime-9.4.5.mqtag"});
        std::vector<std::string> yielding;
        for (const auto& n : mqtags) {
            CAPTURE(n);
            if (ver(kMqtag, n))
                yielding.push_back(n);
        }
        CHECK(yielding == std::vector<std::string>{"IBM_MQ-9.4.5.mqtag"});
        CHECK_FALSE(ver(kMqtag, "IBM_MQ_Runtime-9.4.5.mqtag").has_value());
        CHECK_FALSE(ver(kMqtag, "IBM_MQ_GSKit-9.0.0.mqtag").has_value());
    }
    SECTION("every component name of the listing is rejected; exactly the two product tags yield") {
        std::vector<std::string> mqtags;
        for (const auto marker : {kV925, kV915}) {
            const auto m = with_suffix(listing_section(marker), ".mqtag");
            REQUIRE(m.size() == 21);
            mqtags.insert(mqtags.end(), m.begin(), m.end());
        }
        std::vector<std::string> yielding;
        for (const auto& n : mqtags) {
            CAPTURE(n);
            if (ver(kMqtag, n))
                yielding.push_back(n);
        }
        CHECK(yielding == std::vector<std::string>{"IBM_MQ-9.2.5.mqtag", "IBM_MQ-9.1.5.mqtag"});
        for (const char* component :
             {"IBM_MQ_GSKit-8.0.55.mqtag", "IBM_MQ_JRE-1.8.0.mqtag", "IBM_MQ_Advanced-9.2.5.mqtag",
              "IBM_MQ_Runtime-9.2.5.mqtag", "IBM_MQ_Messages_French-9.2.5.mqtag"}) {
            CAPTURE(component);
            REQUIRE(std::find(mqtags.begin(), mqtags.end(), component) != mqtags.end());
            CHECK_FALSE(ver(kMqtag, component).has_value());
        }
        // the swidtag grammars do not see .mqtag names at all
        for (const auto& n : mqtags) {
            CHECK_FALSE(ver(kSwid, n).has_value());
            CHECK_FALSE(ver(kWebSphere, n).has_value());
        }
    }
}

TEST_CASE("middleware parsers: version_from_file_name accepts and rejects", "[middleware]") {
    SECTION("product_suffix: '-<v>' and '_<anything>-<v>' (the version follows the LAST '-')") {
        CHECK(ver(kSwid, "ibm.com_IBM_MQ-9.2.5.swidtag") == std::string{"9.2.5"});
        CHECK(ver(kSwid, "ibm.com_IBM_MQ-9.3.5.1.swidtag") == std::string{"9.3.5.1"});
        CHECK(ver(kSwid, "ibm.com_IBM_MQ_Advanced-9.2.5.swidtag") == std::string{"9.2.5"});
        CHECK(ver(kWebSphere, "ibm.com_IBM_WebSphere_MQ-8.0.0.swidtag") == std::string{"8.0.0"});
        CHECK_FALSE(ver(kSwid, "ibm.com_IBM_WebSphere_MQ-8.0.0.swidtag").has_value());
    }
    SECTION("not the product: whole-token prefix, other vendor products, empty or odd versions") {
        for (const char* n :
             {"ibm.com_IBM_MQSeries-1.0.swidtag", "ibm.com_IBM_Db2-11.5.swidtag",
              "ibm.com_IBM_MQ_Advanced-.swidtag", "ibm.com_IBM_MQ-.swidtag", "ibm.com_IBM_MQ.swidtag",
              "ibm.com_IBM_MQ-9.swidtag", "ibm.com_IBM_MQ-9.2.x.swidtag",
              "ibm.com_IBM_MQ-9.2.5.1.1.swidtag", "ibm.com_IBM_MQ-.5.swidtag",
              "ibm.com_IBM_MQ-9..5.swidtag", "ibm.com_IBM_MQ-Foo-9.2.5.swidtag",
              "ibm.com_IBM_MQ-9.2.5.swidtag.bak", "xibm.com_IBM_MQ-9.2.5.swidtag", ".swidtag", ""}) {
            CAPTURE(n);
            CHECK_FALSE(ver(kSwid, n).has_value());
        }
        CHECK_FALSE(ver(kMqtag, "IBM_MQ-9.2.mqtag.bak").has_value());
        CHECK_FALSE(ver(kMqtag, "IBM_MQ-abc.mqtag").has_value());
        CHECK_FALSE(ver(kMqtag, "IBM_MQ-.mqtag").has_value());
        CHECK_FALSE(ver(kMqtag, "IBM_MQ.mqtag").has_value());
    }
    SECTION("the two forms differ exactly on '_<anything>'") {
        CHECK_FALSE(mw::version_from_file_name("P_x-1.2.t", "P", ".t", mw::NameForm::exact).has_value());
        CHECK(mw::version_from_file_name("P_x-1.2.t", "P", ".t", mw::NameForm::product_suffix) ==
              std::string{"1.2"});
        CHECK(mw::version_from_file_name("P-1.2.t", "P", ".t", mw::NameForm::exact) == std::string{"1.2"});
        CHECK_FALSE(
            mw::version_from_file_name("P_x.t", "P", ".t", mw::NameForm::product_suffix).has_value());
    }
    SECTION("is_dotted_version is \\d+(\\.\\d+){1,3}") {
        for (const char* v : {"1.2", "10.0.1", "9.3.5.1", "0.0"})
            CHECK(mw::is_dotted_version(v));
        for (const char* v : {"", "1", "1.", ".1", "1..2", "1.2.3.4.5", "1.2a", "v1.2", "1.2 "})
            CHECK_FALSE(mw::is_dotted_version(v));
    }
}

// =================================================================================================
// tokens and rows
// =================================================================================================

TEST_CASE("middleware parsers: tokens carry only enumeration causes", "[middleware]") {
    const std::array<std::pair<mw::Cause, std::string_view>, 8> causes{{
        {mw::Cause::permission_denied, "permission_denied"},
        {mw::Cause::unreadable, "unreadable"},
        {mw::Cause::oversized, "oversized"},
        {mw::Cause::symlink_refused, "symlink_refused"},
        {mw::Cause::malformed, "malformed"},
        {mw::Cause::network_fs_skipped, "network_fs_skipped"},
        {mw::Cause::row_cap, "row_cap"},
        {mw::Cause::internal_error, "internal_error"},
    }};
    for (const auto& [c, name] : causes) {
        CHECK(mw::cause_name(c) == name);
        const std::string t = mw::make_token("linux", "mqinst_ini", c);
        CHECK(t == "linux:middleware:mqinst_ini:" + std::string{name});
        CHECK(is_wire_token(t));
    }
    CHECK(mw::make_token("windows", "walk", mw::Cause::row_cap) == "windows:middleware:walk:row_cap");

    const std::array<std::pair<mw::ItemReason, std::string_view>, 6> reasons{{
        {mw::ItemReason::path_refused, "path_refused"},
        {mw::ItemReason::missing, "missing"},
        {mw::ItemReason::unreadable, "unreadable"},
        {mw::ItemReason::oversized, "oversized"},
        {mw::ItemReason::malformed, "malformed"},
        {mw::ItemReason::network_fs_skipped, "network_fs_skipped"},
    }};
    for (const auto& [r, name] : reasons)
        CHECK(mw::item_reason_name(r) == name);

    // Compile-time proof: no overload of make_token takes an ItemReason, and one never converts to a
    // Cause, so a per-item reason cannot reach the accumulator.
    constexpr bool kTokensTakeCause =
        std::is_invocable_v<decltype(mw::make_token)&, std::string_view, std::string_view, mw::Cause>;
    constexpr bool kTokensTakeReason = std::is_invocable_v<decltype(mw::make_token)&, std::string_view,
                                                           std::string_view, mw::ItemReason>;
    constexpr bool kReasonIsCause = std::is_convertible_v<mw::ItemReason, mw::Cause>;
    STATIC_REQUIRE(kTokensTakeCause);
    STATIC_REQUIRE_FALSE(kTokensTakeReason);
    STATIC_REQUIRE_FALSE(kReasonIsCause);
}

TEST_CASE("middleware parsers: format_row is six escaped fields", "[middleware]") {
    SECTION("a plain row") {
        CHECK(mw::format_row("ibm_mq", "IBM MQ", "Installation1", "9.2.5", "/opt/mqm", "") ==
              "ibm_mq|IBM MQ|Installation1|9.2.5|/opt/mqm|-");
    }
    SECTION("every empty field is '-'") {
        CHECK(mw::format_row("ibm_mq", "", "", "", "", "") == "ibm_mq|-|-|-|-|-");
    }
    SECTION("a pipe is escaped, a backslash folds to '/', newlines fold, and no field shifts") {
        const std::string row =
            mw::format_row("ibm_mq", "T|x", "a|b", "9.2", "C:\\mq\\", "line1\nline2");
        const auto f = split_fields(row);
        REQUIRE(f.size() == 6);
        CHECK(f[1] == "T|x");
        CHECK(f[2] == "a|b");
        CHECK(f[4] == "C:/mq/");
        CHECK(f[5] == "line1 line2");
        CHECK(row.find('\n') == std::string::npos);
    }
    SECTION("invalid UTF-8 is replaced") {
        const std::string row = mw::format_row("ibm_mq", "T", "bad\xff" "name", "9.2", "/p\xc3", "");
        CHECK(row == "ibm_mq|T|bad?name|9.2|/p?|-");
    }
    SECTION("field_or_dash") {
        CHECK(mw::field_or_dash("") == "-");
        CHECK(mw::field_or_dash("a|b") == "a\\|b");
    }
}

TEST_CASE("middleware parsers: compose_output puts the status row first", "[middleware]") {
    yuzu::shared::ConstraintAccumulator acc;
    SECTION("no failure: supported with '-' tokens, rows follow") {
        const auto out = mw::compose_output("ibm_mq", {"ibm_mq|r1", "ibm_mq|r2"}, acc);
        REQUIRE(out.size() == 3);
        CHECK(out[0] == "status|ibm_mq|supported|-");
        CHECK(out[1] == "ibm_mq|r1");
        CHECK(out[2] == "ibm_mq|r2");
    }
    SECTION("failures: constrained, tokens deduplicated in first-seen order") {
        acc.add_failure(mw::make_token("linux", "walk", mw::Cause::row_cap));
        acc.add_failure(mw::make_token("linux", "mqinst_ini", mw::Cause::malformed));
        acc.add_failure(mw::make_token("linux", "walk", mw::Cause::row_cap));
        const auto out = mw::compose_output("ibm_mq", {"ibm_mq|r1"}, acc);
        REQUIRE(out.size() == 2);
        CHECK(out[0] == "status|ibm_mq|constrained|linux:middleware:walk:row_cap,"
                        "linux:middleware:mqinst_ini:malformed");
    }
}

TEST_CASE("middleware runner: make_row_budget clamps to the production ceilings (R6)", "[middleware]") {
    const auto defaults = mw::make_row_budget();
    CHECK(defaults.max_rows == mw::kMaxRows);
    CHECK(defaults.max_bytes == mw::kMaxRowBytes);
    const auto raised = mw::make_row_budget(1'000'000, std::size_t{1} << 30);
    CHECK(raised.max_rows == mw::kMaxRows);
    CHECK(raised.max_bytes == mw::kMaxRowBytes);
    const auto lowered = mw::make_row_budget(2, 10);
    CHECK(lowered.max_rows == 2);
    CHECK(lowered.max_bytes == 10);
}

// =================================================================================================
// run_leg over FakeFs: the enumerator
// =================================================================================================

TEST_CASE("middleware runner: an absent enumerator file is none found, not a failure", "[middleware]") {
    FakeFs fs;
    const auto r = run(fs);
    REQUIRE(r.rows.size() == 1);
    CHECK(r.status() == "status|ibm_mq|supported|-");
    CHECK(r.events.empty());
    REQUIRE(fs.read_calls.size() == 1);
    CHECK(fs.read_calls[0].first == kIni);
    CHECK(fs.read_calls[0].second == mw::kMaxKvFileBytes);
    CHECK(fs.list_calls.empty());
}

TEST_CASE("middleware runner: every enumerator outcome yields exactly its token", "[middleware]") {
    using O = mw::Read::Outcome;
    const std::array<std::pair<O, const char*>, 6> table{{{O::denied, "permission_denied"},
                                                          {O::oversized, "oversized"},
                                                          {O::symlink, "symlink_refused"},
                                                          {O::network, "network_fs_skipped"},
                                                          {O::refused, "unreadable"},
                                                          {O::failed, "unreadable"}}};
    for (const auto& [outcome, cause] : table) {
        CAPTURE(cause);
        FakeFs fs;
        fs.put_outcome(kIni, outcome);
        const auto r = run(fs);
        REQUIRE(r.rows.size() == 1);
        CHECK(r.status() == std::string{"status|ibm_mq|constrained|linux:middleware:mqinst_ini:"} + cause);
        CHECK(r.events.empty());
        CHECK(fs.list_calls.empty());
    }
    SECTION("a file over the cap is oversized (the cap is handed to the Fs)") {
        FakeFs fs;
        fs.put_file(kIni, std::string(mw::kMaxKvFileBytes + 1, '#'));
        const auto r = run(fs);
        CHECK(r.status() == "status|ibm_mq|constrained|linux:middleware:mqinst_ini:oversized");
    }
}

TEST_CASE("middleware runner: malformed enumerator text and dropped stanzas", "[middleware]") {
    FakeFs fs;
    fs.put_names("/opt/mqm", {"ibm.com_IBM_MQ-9.2.5.swidtag"});
    SECTION("content without a stanza line") {
        fs.put_file(kIni, "[Installation]\nName=a\nFilePath=/opt/mqm\n");
        const auto r = run(fs);
        REQUIRE(r.rows.size() == 1);
        CHECK(r.status() == "status|ibm_mq|constrained|linux:middleware:mqinst_ini:malformed");
    }
    SECTION("a stanza lacking a key is dropped once, its siblings are kept") {
        fs.put_file(kIni,
                    "Installation:\n Name=A\nInstallation:\n Name=B\n FilePath=/opt/mqm\n"
                    "Installation:\n FilePath=/x\nInstallation:\n Name=D\n FilePath=\n");
        const auto r = run(fs);
        REQUIRE(r.rows.size() == 2);
        CHECK(r.status() == "status|ibm_mq|constrained|linux:middleware:mqinst_ini:malformed");
        CHECK(r.rows[1] == "ibm_mq|IBM MQ|B|9.2.5|/opt/mqm|-");
    }
    SECTION("more than kMaxRows stanzas: the first kMaxRows are kept and row_cap is the token") {
        std::string t;
        for (std::size_t i = 0; i <= mw::kMaxRows; ++i)
            t += "Installation:\nName=n" + std::to_string(i) + "\nFilePath=/p\n";
        fs.put_file(kIni, t);
        const auto r = run(fs);
        CHECK(r.data().size() == mw::kMaxRows);
        CHECK(r.status() == "status|ibm_mq|constrained|linux:middleware:mqinst_ini:row_cap");
    }
}

// =================================================================================================
// run_leg over FakeFs: the version probes
// =================================================================================================

TEST_CASE("middleware runner: the REAL registered install (mqinst.ini + its swidtag directory)",
          "[middleware]") {
    FakeFs fs;
    fs.put_file(kIni, read_fixture("mqinst.ini"));
    fs.put_names("/opt/mqm", listing_section(kV945)); // swidtag + product mqtag + 2 component tags
    const auto r = run(fs);
    REQUIRE(r.rows.size() == 2);
    CHECK(r.status() == "status|ibm_mq|supported|-");
    CHECK(r.rows[1] == "ibm_mq|IBM MQ|Installation1|9.4.5|/opt/mqm|-");
    CHECK(r.events.empty());
    CHECK(fs.list_calls == std::vector<std::string>{"/opt/mqm|swidtag"});

    SECTION("without the swidtag the product mqtag still names 9.4.5") {
        FakeFs g;
        g.put_file(kIni, read_fixture("mqinst.ini"));
        g.put_names("/opt/mqm", {"IBM_MQ-9.4.5.mqtag", "IBM_MQ_GSKit-9.0.0.mqtag",
                                 "IBM_MQ_Runtime-9.4.5.mqtag"});
        CHECK(run(g).rows[1] == "ibm_mq|IBM MQ|Installation1|9.4.5|/opt/mqm|-");
    }
    SECTION("component tags alone (Runtime-9.4.5, GSKit-9.0.0) name no product (R1)") {
        FakeFs g;
        g.put_file(kIni, read_fixture("mqinst.ini"));
        g.put_names("/opt/mqm", {"IBM_MQ_GSKit-9.0.0.mqtag", "IBM_MQ_Runtime-9.4.5.mqtag"});
        const auto c = run(g);
        CHECK(c.status() == "status|ibm_mq|supported|-");
        CHECK(c.rows[1] == "ibm_mq|IBM MQ|Installation1|-|/opt/mqm|-");
        CHECK(c.events == std::vector<LogEvent>{ev("mqtag", mw::ItemReason::missing, "Installation1")});
    }
}

TEST_CASE("middleware runner: one candidate per stanza, versions from the REAL listing names",
          "[middleware]") {
    FakeFs fs;
    fs.put_file(kIni, kTwoInstallationsInline);         // SYNTHETIC inline: two installations
    fs.put_names("/opt/mqm", listing_section(kV925));   // swidtag + 21 mqtag files
    fs.put_names("/opt/mqm2", listing_section(kV1001)); // the swidtag only
    const auto r = run(fs);
    REQUIRE(r.rows.size() == 3);
    CHECK(r.status() == "status|ibm_mq|supported|-");
    CHECK(r.rows[1] == "ibm_mq|IBM MQ|Installation1|9.2.5|/opt/mqm|-");
    CHECK(r.rows[2] == "ibm_mq|IBM MQ|Installation2|10.0.1|/opt/mqm2|-");
    CHECK(r.events.empty());
    // the three dir probes share one subdirectory: listed ONCE per candidate, with the dir cap
    CHECK(fs.list_calls == std::vector<std::string>{"/opt/mqm|swidtag", "/opt/mqm2|swidtag"});
    CHECK(fs.list_caps == std::vector<std::size_t>{mw::kMaxDirEntries, mw::kMaxDirEntries});
}

TEST_CASE("middleware runner: the probe fallback order is swidtag, websphere swidtag, mqtag",
          "[middleware]") {
    FakeFs fs;
    fs.put_file(kIni, ini_of({{"I1", "/opt/mqm"}}));
    SECTION("swidtag beats everything") {
        fs.put_names("/opt/mqm", {"IBM_MQ-1.1.1.mqtag", "ibm.com_IBM_MQ-9.9.9.swidtag",
                                  "ibm.com_IBM_WebSphere_MQ-7.5.0.swidtag"});
        CHECK(run(fs).rows[1] == "ibm_mq|IBM MQ|I1|9.9.9|/opt/mqm|-");
    }
    SECTION("the WebSphere swidtag beats the mqtag") {
        fs.put_names("/opt/mqm", {"IBM_MQ-1.1.1.mqtag", "ibm.com_IBM_WebSphere_MQ-7.5.0.swidtag"});
        CHECK(run(fs).rows[1] == "ibm_mq|IBM MQ|I1|7.5.0|/opt/mqm|-");
    }
    SECTION("only IBM_MQ-<v>.mqtag present (beside its component tags): the mqtag version") {
        fs.put_names("/opt/mqm", {"IBM_MQ_GSKit-8.0.55.mqtag", "IBM_MQ-9.1.5.mqtag",
                                  "IBM_MQ_JRE-1.8.0.mqtag"});
        const auto r = run(fs);
        CHECK(r.rows[1] == "ibm_mq|IBM MQ|I1|9.1.5|/opt/mqm|-");
        CHECK(r.events.empty());
        CHECK(fs.list_calls.size() == 1);
    }
    SECTION("the 9.2.5 listing (swidtag AND product mqtag): the swidtag is read first") {
        fs.put_names("/opt/mqm", listing_section(kV925));
        CHECK(run(fs).rows[1] == "ibm_mq|IBM MQ|I1|9.2.5|/opt/mqm|-");
    }
}

TEST_CASE("middleware runner: a directory of component tags only names no product (R1)", "[middleware]") {
    auto names = listing_section(kV925);
    names.erase(std::remove_if(names.begin(), names.end(),
                               [](const std::string& n) {
                                   return n == "IBM_MQ-9.2.5.mqtag" ||
                                          n.find(".swidtag") != std::string::npos;
                               }),
                names.end());
    for (const char* component : {"IBM_MQ_GSKit-8.0.55.mqtag", "IBM_MQ_JRE-1.8.0.mqtag",
                                  "IBM_MQ_Runtime-9.2.5.mqtag"})
        REQUIRE(std::find(names.begin(), names.end(), component) != names.end());

    FakeFs fs;
    fs.put_file(kIni, ini_of({{"I1", "/opt/mqm"}}));
    fs.put_names("/opt/mqm", names);
    const auto r = run(fs);
    REQUIRE(r.rows.size() == 2);
    CHECK(r.status() == "status|ibm_mq|supported|-"); // no token
    CHECK(r.rows[1] == "ibm_mq|IBM MQ|I1|-|/opt/mqm|-");
    CHECK(r.events == std::vector<LogEvent>{ev("mqtag", mw::ItemReason::missing, "I1")});
}

TEST_CASE("middleware runner: a flagged listing is never matched, even with a valid name in it (R4)",
          "[middleware]") {
    const std::vector<std::string> valid{"IBM_MQ-9.2.5.mqtag", "ibm.com_IBM_MQ-9.2.5.swidtag"};
    FakeFs fs;
    fs.put_file(kIni, ini_of({{"I1", "/opt/mqm"}}));
    using O = mw::Read::Outcome;

    SECTION("truncated") {
        fs.put_dir("/opt/mqm", "swidtag", mw::Listing{valid, true, false, O::ok});
    }
    SECTION("error") {
        fs.put_dir("/opt/mqm", "swidtag", mw::Listing{valid, false, true, O::ok});
    }
    SECTION("error with a failed outcome") {
        fs.put_dir("/opt/mqm", "swidtag", mw::Listing{valid, false, true, O::failed});
    }
    SECTION("denied or oversized outcome") {
        fs.put_dir("/opt/mqm", "swidtag", mw::Listing{valid, false, false, O::denied});
    }
    SECTION("cut at the dir cap by the Fs") {
        std::vector<std::string> many{"ibm.com_IBM_MQ-9.2.5.swidtag"};
        for (std::size_t i = 0; i < mw::kMaxDirEntries; ++i)
            many.push_back("filler" + std::to_string(i));
        fs.put_names("/opt/mqm", many);
    }
    const auto r = run(fs);
    REQUIRE(r.rows.size() == 2);
    CHECK(r.status() == "status|ibm_mq|supported|-"); // per-item: no token
    CHECK(r.rows[1] == "ibm_mq|IBM MQ|I1|-|/opt/mqm|-");
    // judged once for the shared subdirectory, against the first probe to list it
    CHECK(r.events == std::vector<LogEvent>{ev("swidtag", mw::ItemReason::unreadable, "I1")});
    CHECK(fs.list_calls.size() == 1);
}

TEST_CASE("middleware runner: absent, empty and unrelated listings are 'missing'", "[middleware]") {
    FakeFs fs;
    fs.put_file(kIni, ini_of({{"I1", "/opt/mqm"}}));
    SECTION("the swidtag directory does not exist") {
        const auto r = run(fs);
        CHECK(r.rows[1] == "ibm_mq|IBM MQ|I1|-|/opt/mqm|-");
        CHECK(r.events == std::vector<LogEvent>{ev("swidtag", mw::ItemReason::missing, "I1")});
        CHECK(r.status() == "status|ibm_mq|supported|-");
    }
    SECTION("an empty clean listing") {
        fs.put_names("/opt/mqm", {});
        const auto r = run(fs);
        CHECK(r.rows[1] == "ibm_mq|IBM MQ|I1|-|/opt/mqm|-");
        CHECK(r.events == std::vector<LogEvent>{ev("mqtag", mw::ItemReason::missing, "I1")});
    }
    SECTION("neither file: unrelated names") {
        fs.put_names("/opt/mqm", {"README", "ibm.com_IBM_Db2-11.5.swidtag", "ibm.com_IBM_MQSeries-1.0.swidtag"});
        const auto r = run(fs);
        CHECK(r.rows[1] == "ibm_mq|IBM MQ|I1|-|/opt/mqm|-");
        CHECK(r.events == std::vector<LogEvent>{ev("mqtag", mw::ItemReason::missing, "I1")});
    }
}

TEST_CASE("middleware runner: a refused install path keeps the row and logs path_refused",
          "[middleware]") {
    using O = mw::Read::Outcome;
    for (const O refusal : {O::refused, O::network, O::symlink}) {
        CAPTURE(static_cast<int>(refusal));
        FakeFs fs;
        fs.put_file(kIni, ini_of({{"I1", "/opt/mqm"}}));
        fs.put_dir("/opt/mqm", "swidtag", mw::Listing{{"ibm.com_IBM_MQ-9.2.5.swidtag"}, false, false, refusal});
        const auto r = run(fs);
        REQUIRE(r.rows.size() == 2);
        CHECK(r.status() == "status|ibm_mq|supported|-");
        CHECK(r.rows[1] == "ibm_mq|IBM MQ|I1|-|/opt/mqm|-");
        CHECK(r.events == std::vector<LogEvent>{ev("swidtag", mw::ItemReason::path_refused, "I1")});
    }
}

TEST_CASE("middleware runner: per-item reasons reach only the log", "[middleware]") {
    using O = mw::Read::Outcome;
    FakeFs fs;
    fs.put_file(kIni, ini_of({{"refused", "/p/a"}, {"absent", "/p/b"}, {"cut", "/p/c"}, {"good", "/p/d"}}));
    fs.put_dir("/p/a", "swidtag", mw::Listing{{}, false, false, O::refused});
    fs.put_dir("/p/c", "swidtag", mw::Listing{{"IBM_MQ-9.2.5.mqtag"}, true, false, O::ok});
    fs.put_names("/p/d", {"ibm.com_IBM_MQ-10.0.1.swidtag"});
    const auto r = run(fs);
    CHECK(r.status() == "status|ibm_mq|supported|-");
    CHECK(r.data() == std::vector<std::string>{"ibm_mq|IBM MQ|refused|-|/p/a|-",
                                               "ibm_mq|IBM MQ|absent|-|/p/b|-",
                                               "ibm_mq|IBM MQ|cut|-|/p/c|-",
                                               "ibm_mq|IBM MQ|good|10.0.1|/p/d|-"});
    CHECK(r.events == std::vector<LogEvent>{ev("swidtag", mw::ItemReason::path_refused, "refused"),
                                            ev("swidtag", mw::ItemReason::missing, "absent"),
                                            ev("swidtag", mw::ItemReason::unreadable, "cut")});
}

// =================================================================================================
// run_leg over FakeFs: the budgets
// =================================================================================================

TEST_CASE("middleware runner: the caller-built budget and the Fs budget end in walk:row_cap",
          "[middleware]") {
    FakeFs fs;
    fs.put_file(kIni, ini_of({{"I1", "/a"}, {"I2", "/b"}, {"I3", "/c"}}));
    for (const char* base : {"/a", "/b", "/c"})
        fs.put_names(base, {"ibm.com_IBM_MQ-9.2.5.swidtag"});
    const std::string capped = "status|ibm_mq|constrained|linux:middleware:walk:row_cap";

    SECTION("rows = 2 over 3 stanzas") {
        const auto r = run(fs, mw::make_row_budget(2));
        CHECK(r.status() == capped);
        CHECK(r.data().size() == 2);
    }
    SECTION("rows = 3 over 3 stanzas: an exact fill is admitted") {
        const auto r = run(fs, mw::make_row_budget(3));
        CHECK(r.status() == "status|ibm_mq|supported|-");
        CHECK(r.data().size() == 3);
    }
    SECTION("bytes smaller than one row") {
        const auto r = run(fs, mw::make_row_budget(mw::kMaxRows, 10));
        CHECK(r.status() == capped);
        CHECK(r.data().empty());
    }
    SECTION("an injected limit above the ceiling is clamped, not honoured") {
        auto b = mw::make_row_budget(1'000'000, std::size_t{1} << 30);
        CHECK(b.max_rows == mw::kMaxRows);
        CHECK(run(fs, b).data().size() == 3);
    }
    SECTION("the Fs entries budget runs dry on the second listing: no row past it") {
        fs.exhaust_after = 2;
        const auto r = run(fs);
        CHECK(r.status() == capped);
        CHECK(r.data() == std::vector<std::string>{"ibm_mq|IBM MQ|I1|9.2.5|/a|-"});
        CHECK(fs.list_calls.size() == 2);
    }
}

// =================================================================================================
// run_leg over a second, test-only table (the runner is generic)
// =================================================================================================

TEST_CASE("middleware runner: a whole-file stanza and a version key come from the table", "[middleware]") {
    const mw::Product& acme = kAcme[0];
    yuzu::shared::ConstraintAccumulator acc;
    auto budget = mw::make_row_budget();
    std::vector<LogEvent> events;
    const auto log = [&](std::string_view prod, std::string_view probe, mw::ItemReason why,
                         std::string_view cand) {
        events.push_back({std::string{prod}, std::string{probe}, why, std::string{cand}});
    };
    FakeFs fs;

    SECTION("the version key supplies the version: no directory is listed") {
        fs.put_file("/etc/acme.conf", "Name=Acme One\nPath=/opt/acme\nVersion=3.4.5\n");
        const auto rows = mw::run_leg(acme, acme.linux, fs, acc, budget, log);
        CHECK(rows == std::vector<std::string>{"acme|Acme|Acme One|3.4.5|/opt/acme|-"});
        CHECK(fs.list_calls.empty());
        CHECK_FALSE(acc.any_failure());
    }
    SECTION("no version key value: the dir_name probe supplies it") {
        fs.put_file("/etc/acme.conf", "Name=Acme One\nPath=/opt/acme\n");
        fs.put_dir("/opt/acme", "tags", mw::Listing{{"acme-1.2.3.tag", "acme_x-9.9.tag"}, false, false,
                                                    mw::Read::Outcome::ok});
        const auto rows = mw::run_leg(acme, acme.linux, fs, acc, budget, log);
        CHECK(rows == std::vector<std::string>{"acme|Acme|Acme One|1.2.3|/opt/acme|-"});
        CHECK(fs.list_calls == std::vector<std::string>{"/opt/acme|tags"});
    }
    SECTION("a PLANNED leg reads nothing") {
        const auto rows = mw::run_leg(acme, acme.windows, fs, acc, budget, log);
        CHECK(rows.empty());
        CHECK(fs.read_calls.empty());
        CHECK_FALSE(acc.any_failure());
    }
    SECTION("an unvalidated table whose enumerator is not a kv_file is an internal_error token") {
        const Product bad = mutated([](Product& p) { p.linux.probes = kProbesDirFirst; });
        const auto rows = mw::run_leg(bad, bad.linux, fs, acc, budget, log);
        CHECK(rows.empty());
        CHECK(acc.reason() == "linux:middleware:swidtag:internal_error");
        CHECK(fs.read_calls.empty());
    }
}

// =================================================================================================
// fixtures are only what the tests use
// =================================================================================================

TEST_CASE("middleware fixtures: tree.manifest and provenance say what the tests rely on", "[middleware]") {
    SECTION("tree.manifest holds only the install root the run_leg tests point a candidate at") {
        std::vector<std::string> paths;
        for (const std::string& l : lines_of(read_fixture("tree.manifest")))
            if (!l.empty() && l[0] != '#')
                paths.push_back(last_token(l));
        CHECK(paths == std::vector<std::string>{"/opt/mqm"});
        mw::ParseReport rep;
        const auto st = mw::parse_kv_stanzas(read_fixture("mqinst.ini"), "Installation:", rep);
        REQUIRE_FALSE(st.empty());
        CHECK(*st[0].get("FilePath") == paths[0]);
    }
    SECTION("mqinst.ini is the byte-exact REAL capture and provenance says so, with IBM's caveat") {
        const std::string ini = read_fixture("mqinst.ini");
        CHECK(ini.rfind("Installation:\n", 0) == 0); // no synthetic label or comment line
        CHECK(ini.find("SYNTHETIC") == std::string::npos);
        const std::string prov = read_fixture("provenance.txt");
        CHECK(prov.find("mqinst.ini is a REAL capture") != std::string::npos);
        CHECK(prov.find("1b1c19a3295a5c5fb4c208c116150a99fae38e77e54db006a0252e38ae31ed78") !=
              std::string::npos);
        CHECK(prov.find("Installation configuration file, mqinst.ini") != std::string::npos);
        CHECK(prov.find("NOT fixed") != std::string::npos);
        CHECK(prov.find("MEASURED") != std::string::npos);
    }
}
