// The pure blob-v3 writer (agents/core/src/installed_software_v3.hpp), pinned to the server's
// golden vectors. Every digest below is copied from
// tests/unit/server/test_software_inventory_store.cpp (the recipes are printf | shasum there):
// a one-byte drift between this writer and SoftwareInventoryStore makes a delta refuse
// `mismatch` forever, so these are the cross-side contract.

#include <catch2/catch_test_macros.hpp>

#include "installed_software_v3.hpp"
#include "sync_canonical.hpp"

// The server's parser (header-only): the oracle for the wire. Reached by path, not by putting
// server/core/src on the agent tests' include path, so no server header can shadow an agent one.
#include "../../server/core/src/inventory_blob_v3.hpp"

#include <algorithm>
#include <string>
#include <string_view>
#include <tuple>
#include <vector>

using namespace yuzu::agent;

namespace {

constexpr const char* kApps = "installed_apps.list_inventory";
constexpr const char* kPkgs = "pkg_inventory.packages";
constexpr const char* kPy = "runtimes.python";
constexpr const char* kEmptyHash =
    "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";

SwEntry alpha() {
    SwEntry a;
    a.name = "Alpha";
    a.version = "1.0";
    a.publisher = "Pub";
    a.install_date = "2026-01-01";
    a.kind = "app";
    a.ecosystem = "windows";
    a.arch = "x64";
    a.install_location = "C:\\Program Files\\Alpha";
    a.package_id = "pkg-a";
    a.source = kApps;
    return a;
}

SwEntry beta() {
    SwEntry b;
    b.name = "Beta";
    b.version = "2";
    b.kind = "app";
    b.ecosystem = "windows";
    b.source = kApps;
    return b;
}

SwEntry row(std::string name, std::string version = "1", std::string source = kApps) {
    SwEntry e;
    e.name = std::move(name);
    e.version = std::move(version);
    e.publisher = "Pub";
    e.kind = "pkg";
    e.ecosystem = "deb";
    e.source = std::move(source);
    return e;
}

std::vector<std::string> split(std::string_view s, char sep) {
    std::vector<std::string> out;
    std::size_t pos = 0;
    for (;;) {
        const auto e = s.find(sep, pos);
        if (e == std::string_view::npos) {
            out.emplace_back(s.substr(pos));
            return out;
        }
        out.emplace_back(s.substr(pos, e - pos));
        pos = e + 1;
    }
}

// The server grammar's framing rules (inventory_blob_v3.hpp), restated: the header, then
// 0x1E-terminated records, no NUL anywhere, the last record terminated, an `S` record of eight
// fields, a `+` record of seventeen with a non-empty publisher and a source equal to its
// section's facet, a `-` record naming 64 lowercase hex.
struct Parsed {
    struct Section {
        std::vector<std::string> header; // S fields
        std::vector<std::vector<std::string>> adds;
        std::vector<std::string> deletes;
        std::size_t comps{0};
    };
    std::vector<Section> sections;
};

Parsed parse_like_server(const std::string& blob) {
    REQUIRE(blob.starts_with(kV3Header));
    REQUIRE(blob.find('\0') == std::string::npos);
    REQUIRE(blob.back() == '\x1e');
    Parsed p;
    std::string_view rest = std::string_view(blob).substr(kV3Header.size());
    while (!rest.empty()) {
        const auto e = rest.find('\x1e');
        REQUIRE(e != std::string_view::npos);
        const auto f = split(rest.substr(0, e), '\x1f');
        rest.remove_prefix(e + 1);
        if (f[0] == "S") {
            REQUIRE(f.size() == 8);
            p.sections.push_back({f, {}, {}, 0});
        } else {
            REQUIRE_FALSE(p.sections.empty());
            auto& sec = p.sections.back();
            if (f[0] == "+") {
                REQUIRE(f.size() == 17);
                CHECK_FALSE(f[3].empty());                 // publisher, slot 3
                CHECK(f[14].empty());                      // slot 14 reserved
                CHECK(f[16] == sec.header[1]);             // source == facet
                sec.adds.push_back(f);
            } else if (f[0] == "-") {
                REQUIRE(f.size() == 2);
                REQUIRE(f[1].size() == 64);
                sec.deletes.push_back(f[1]);
            } else {
                REQUIRE(f[0] == "comp");
                ++sec.comps;
            }
        }
    }
    return p;
}

AckedSet acked_of(const SectionPlan& p) {
    return AckedSet{p.section_hash, p.row_hashes};
}

} // namespace

TEST_CASE("v3_record: 16 slots, slot 14 empty, 0x1F-joined, 0x1E-terminated; row hash pinned",
          "[v3][writer][hash]") {
    const std::string rec = v3_record(alpha());
    CHECK(rec.back() == '\x1e');
    const auto slots = split(std::string_view(rec).substr(0, rec.size() - 1), '\x1f');
    REQUIRE(slots.size() == 16);
    CHECK(slots[0] == "Alpha");
    CHECK(slots[12] == "C:\\Program Files\\Alpha");
    CHECK(slots[13].empty()); // slot 14 (1-based), the reserved uninstall_string
    CHECK(slots[14] == "pkg-a");
    CHECK(slots[15] == kApps);
    // The server's instance_key of this row (= the one-row section hash).
    CHECK(v3_row_hash(alpha()) ==
          "c573935d6af97c9deaef2b526cb01a3dabc2d3958b7e69b289968a6e80dbf229");
    // A row with no package_id and no source still writes all 16 slots (no conditional tail).
    SwEntry bare = alpha();
    bare.package_id.clear();
    bare.source.clear();
    CHECK(split(v3_record(bare), '\x1f').size() == 16);
    CHECK(v3_row_hash(bare) != v3_row_hash(alpha()));
}

TEST_CASE("v3_section_hash is order and duplicate independent and matches the server pins",
          "[v3][writer][hash]") {
    CHECK(v3_section_hash({alpha()}) ==
          "c573935d6af97c9deaef2b526cb01a3dabc2d3958b7e69b289968a6e80dbf229");
    // Beta has NO publisher: the pure hash takes the publisher as given (the planner labels it).
    CHECK(v3_section_hash({beta(), alpha(), alpha()}) ==
          "4f5f399d1a8f2cb7e94eee0487cf6dbb86b2bcdbb7b266fbc2869bd92b338fdd");
    CHECK(v3_section_hash({alpha(), beta()}) == v3_section_hash({beta(), alpha(), alpha()}));
    CHECK(v3_section_hash({}) == kEmptyHash);

    // An origin-labelled row (the agent writes `via:<ecosystem>` into slot 3): the server pin.
    SwEntry wget;
    wget.name = "wget";
    wget.version = "1.24";
    wget.publisher = "via:brew";
    wget.kind = "pkg";
    wget.ecosystem = "brew";
    wget.source = kPkgs;
    CHECK(v3_section_hash({wget}) ==
          "906ce129e4448180dcee1d554df55367a898b40e73551cf9dbfaa73d26d0c69f");
    SwEntry bare = wget;
    bare.publisher.clear();
    CHECK(v3_section_hash({bare}) != v3_section_hash({wget}));

    // Every stored field moves the hash, install_location included.
    const auto base = v3_section_hash({alpha()});
    for (auto field : {&SwEntry::install_location, &SwEntry::package_id, &SwEntry::source,
                       &SwEntry::distro_version}) {
        SwEntry other = alpha();
        other.*field = "/opt/zz";
        CHECK(v3_section_hash({other}) != base);
    }
}

TEST_CASE("v3_report_hash sorts by facet in byte order, carries the v3: prefix, pinned",
          "[v3][writer][hash]") {
    const std::string pa(64, 'a');
    const std::string pb(64, 'b');
    const std::string expect = "v3:ca5bfc4023f484d758323b20edec5362f2d927476067c0c6f31eef389bac4878";
    CHECK(v3_report_hash({{kPy, pa}, {kApps, pb}}) == expect);
    CHECK(v3_report_hash({{kApps, pb}, {kPy, pa}}) == expect);
    CHECK(v3_report_hash({{kApps, pb}}) ==
          "v3:2026549037aa0802ef3b58c555d0919e8d0f240a8987c88428bfd45e1f06ff60");
    CHECK(v3_report_hash({{"b", pa}, {"B", pb}}) == v3_report_hash({{"B", pb}, {"b", pa}}));
    CHECK(v3_report_hash({}).starts_with("v3:"));
}

TEST_CASE("component record, row hash and section hash are pinned to the server recipe",
          "[v3][writer][hash][components]") {
    SwComponent log4j{"jar", "log4j-core", "2.14.1", "pom", "/opt/app/log4j-core.jar",
                      1234,  1700000000,  "AcmeApp"};
    SwComponent guava{"jar", "guava", "31.0", "manifest", "/opt/app/guava.jar", 56, 7, ""};
    CHECK(v3_component_row_hash(log4j) ==
          "2a42ddba7479c8a7edbe10b9f64ebe33d35bb294588993515c9313e65bba588f");
    CHECK(v3_component_row_hash(guava) ==
          "ec07687685e447a3fb37bc84a64e94ad9bf5433d20a6b01d2cc6ff3b38a5003a");
    const std::string section = "d9660fb3421ec2ad622c68ad05e58351ece4584d13b29e92cfea9f5c4b8af4cd";
    CHECK(v3_component_section_hash({guava, log4j}) == section);
    CHECK(v3_component_section_hash({log4j, guava, log4j}) == section);
    CHECK(v3_component_section_hash({}) == kEmptyHash);

    // Numeric, not lexical, size ordering: 9 sorts before 10 although "10" < "9" as text.
    SwComponent a = guava;
    a.path = "/same";
    a.size = 9;
    SwComponent b = a;
    b.size = 10;
    CHECK(v3_component_section_hash({b, a}) == v3_component_section_hash({a, b}));
    const std::string ordered = v3_component_record(a) + v3_component_record(b);
    CHECK(v3_component_section_hash({a, b}) == sha256_hex(ordered));

    // A separator in a name or path cannot re-frame the record; a nameless component is dropped;
    // a version_source outside the closed set is written `unreadable`.
    SwComponent evil = log4j;
    evil.name = std::string("lo\x1f" "g\x1e" "4j\0x", 9);
    evil.path = std::string("/opt/\x1f/x\x1e", 9);
    const std::string rec = v3_component_record(evil);
    CHECK(std::count(rec.begin(), rec.end(), '\x1f') == 7);
    CHECK(std::count(rec.begin(), rec.end(), '\x1e') == 1);
    CHECK(rec.find('\0') == std::string::npos);
    SwComponent nameless = log4j;
    nameless.name = "\x1f\x1e";
    CHECK(v3_component_section_hash({nameless}) == kEmptyHash);
    SwComponent odd = log4j;
    odd.version_source = "invented";
    CHECK(split(v3_component_record(odd), '\x1f')[3] == "unreadable");
}

TEST_CASE("a field carrying 0x1E, 0x1F and NUL writes a record with no raw separator",
          "[v3][writer][clamp]") {
    SwEntry e = row("a\x1f" "b\x1e" "c", "1\0" "2");
    e.version = std::string("1\0" "2", 3);
    e.install_location = std::string("/opt/x\x1f/y\x1e", 10);
    const std::string rec = v3_record(e);
    CHECK(std::count(rec.begin(), rec.end(), '\x1f') == 15);
    CHECK(std::count(rec.begin(), rec.end(), '\x1e') == 1);
    CHECK(rec.find('\0') == std::string::npos);
    // clamp_field is the ONE preparation step: the record equals the one built from the
    // clamp_field output (the server's stored form: it hashes the bytes it receives).
    SwEntry clean = e;
    clean.name = "abc";
    clean.version = "12";
    clean.install_location = "/opt/x/y";
    CHECK(rec == v3_record(clean));
    // Invalid UTF-8 is scrubbed to U+FFFD and an over-long field clamped on a codepoint boundary.
    SwEntry bad = row("n");
    bad.version = std::string("v\xE9", 2);
    CHECK(split(v3_record(bad), '\x1f')[1] == "v\xEF\xBF\xBD");
    SwEntry big = row("n");
    big.version = std::string(1024, 'a') + "tail";
    CHECK(split(v3_record(big), '\x1f')[1].size() == 1024);
    // A name that becomes empty after clamping is not a row.
    SwEntry gone = row("\x1f\x1e");
    CHECK(v3_section_hash({gone}) == kEmptyHash);
}

TEST_CASE("machine_install_location and the writer's install_location rule", "[v3][writer][privacy]") {
    for (const char* p : {"C:\\Users\\x", "c:\\users\\x\\AppData", "D:/Users/x", "/Users/x/Applications",
                          "/home/x/.local", "/root", "/root/bin", "C:\\Usersx", "/homework", "",
                          "C:\\", "D:\\Apps\\Tool", "C:\\Tools\\Foo"})
        CHECK(machine_install_location(p).empty());
    CHECK(machine_install_location("C:\\Program Files\\x") == "C:\\Program Files\\x");
    CHECK(machine_install_location("/Applications/x.app") == "/Applications/x.app");
    CHECK(machine_install_location("/opt/x") == "/opt/x");
    CHECK(machine_install_location("/usr/local") == "/usr/local");

    SwEntry e = alpha();
    e.install_location = "C:\\Users\\alex\\AppData\\Local\\Tool";
    CHECK(split(v3_record(e), '\x1f')[12].empty());
    // ...and the ledger-visible key is the blanked row's: the same app under two accounts is one row.
    SwEntry f = alpha();
    f.install_location = "C:\\Users\\sam\\AppData\\Local\\Tool";
    CHECK(v3_row_hash(e) == v3_row_hash(f));
    e.install_location = "/Applications/Tool.app";
    CHECK(split(v3_record(e), '\x1f')[12] == "/Applications/Tool.app");
}

namespace {

// Every spelling the governance probe found leaking under the old blacklist, plus the shapes
// the canonicaliser cannot resolve. None of these may reach the wire.
const std::vector<std::string> kBlankedSpellings = {
        // Quotes, padding, doubled separators, dot segments, trailing dots (installer-authored text).
        "\"C:\\Users\\alice\\AppData\\Local\\Foo\"", " C:\\Users\\alice", "C:\\\\Users\\\\alice\\\\Foo",
        "C:\\.\\Users\\alice", "C:\\Users.\\alice", "C:\\Program Files\\..\\Users\\alice",
        "C:\\Program Files\\..\\..\\Users", "/Applications/../Users/alice/App",
        // `..` resolved BEFORE the allowlist: a machine root climbed out of is not a machine root,
        // and the firmlink is folded only when it survives the climb.
        "/opt/../home/x", "/usr/../root", "/System/Volumes/Data/../../Users/alex",
        // 8.3 names, NT object spellings, drive-relative, unexpanded variables: not resolvable.
        "C:\\DOCUME~1\\alice", "C:\\PROGRA~1\\Tool", "\\??\\C:\\Users\\alice",
        "\\\\?\\GLOBALROOT\\Device\\HarddiskVolume3\\Users\\alice",
        "\\\\?\\Volume{5a2b}\\Users\\alice", "\\\\?\\Volume{5a2b}\\Program Files\\Tool",
        "C:Users\\alice", "%USERPROFILE%\\Tool", "%LOCALAPPDATA%\\Programs\\Foo",
        "%ProgramFiles%\\Vendor", "~/Applications/Tool.app", "Tool",
        // Volumes and relocated profile roots: not under a machine root.
        "/Volumes/Backup/Users/alice/Applications/Foo.app", "/Volumes/Alice's Passport/Foo.app",
        "/Volumes/Data/Apps/Tool", "E:\\Profiles\\alice", "/private/var/root", "/var/home/alice",
        "/mnt/c/Users/alice", "D:\\Apps\\Foo",
        // The Win32 prefixes, every UNC spelling, the macOS firmlink, case and separator variants.
        "\\\\?\\C:\\Users\\Alice\\App",   "\\\\?\\c:\\users\\Alice\\App", "\\\\.\\D:\\Users\\Alice",
        "//?/C:/Users/Alice/App",         "\\\\host\\share\\apps\\Tool",  "\\\\host\\home$\\alice",
        "//host/share/Tool",              "\\\\?\\UNC\\host\\share\\Tool", "\\\\?\\unc\\host\\share",
        "\\\\.\\UNC\\host\\share\\Tool",  "\\\\?\\", "\\\\?\\Cx",
        "/System/Volumes/Data/Users/alice/App", "/System/Volumes/Data/home/alice",
        "/System/Volumes/Data/root/bin", "/System/Volumes/Data",
        "/users/alice/App", "/System/Volumes/Data/users/x", "C:\\Documents and Settings\\alice\\x",
        "c:/documents and settings/x", "\\Users\\alice\\x", "/Documents and Settings/x", "\\x",
        // On the POSIX shape `\` is a filename byte, not a separator: a `\..` inside a segment
        // never pops a real segment, so a per-user path cannot be rewritten into a machine root
        // (`/Users/a/x\..\..\..\opt/Foo.app` is `/Users/a/<name>/Foo.app`, blanked, never
        // `/opt/Foo.app`); and a path that leads with `\` and has no drive letter has no shape.
        "/Users/a/x\\..\\..\\..\\opt/Foo.app", "/home/a/x\\..\\..\\..\\usr/bin", "\\opt\\x",
        "\\opt/Foo.app", "\\Applications\\Tool.app",
        // A control byte is not a path; DEL (0x7F) counts as one.
        std::string("C:\\Program Files\\Tool\x01"), "/Applications/\tTool.app",
        std::string("C:\\Program Files\\Tool\x7f"), std::string("/opt/\x7fTool")};

// Under a machine root the location is kept, in ONE spelling: the shape's separator, an
// upper-case drive letter, no quotes, padding, prefix, doubled separator, dot segment or
// trailing separator, the segments' own case.
const std::vector<std::pair<std::string, std::string>> kKeptSpellings = {
    {"C:\\Program Files\\Tool", "C:\\Program Files\\Tool"},
    {"\"C:\\Program Files\\Tool\"", "C:\\Program Files\\Tool"},
    {" c:/program files (x86)/Tool/ ", "C:\\program files (x86)\\Tool"},
    {"\\\\?\\C:\\Program Files (x86)\\Tool", "C:\\Program Files (x86)\\Tool"},
    {"\\\\.\\C:\\Windows", "C:\\Windows"},
    {"C:\\\\Program Files\\\\.\\Tool\\..\\Tool2.", "C:\\Program Files\\Tool2"},
    {"D:\\ProgramData\\Vendor\\App", "D:\\ProgramData\\Vendor\\App"},
    {"C:\\Program Files\\WindowsApps\\Vendor.App_1.0_x64__8wekyb3d8bbwe",
     "C:\\Program Files\\WindowsApps\\Vendor.App_1.0_x64__8wekyb3d8bbwe"},
    {"C:\\Windows\\System32\\drivers", "C:\\Windows\\System32\\drivers"},
    {"/Applications/Tool.app", "/Applications/Tool.app"},
    {"/Applications/Tool.app/", "/Applications/Tool.app"},
    {"/System/Volumes/Data/Applications/Tool.app", "/Applications/Tool.app"},
    {"/System/Applications/Tool.app", "/System/Applications/Tool.app"},
    {"/Library/Application Support/Vendor", "/Library/Application Support/Vendor"},
    {"/System/Volumes/Data/opt/x", "/opt/x"},
    {"/usr/local/bin", "/usr/local/bin"},
    {"/Developer/Tool", "/Developer/Tool"},
    {"/snap/foo/12", "/snap/foo/12"},
    {"/var/lib/flatpak/app/org.example.Foo", "/var/lib/flatpak/app/org.example.Foo"},
    {"/nix/store/abc-foo", "/nix/store/abc-foo"},
    {"/app/bin", "/app/bin"},
    {"/opt//x/./y/../z", "/opt/x/z"},
    // A backslash under a POSIX root is part of the name (kept as spelled); under a drive letter
    // it is a separator, as `/` is, and the one spelling uses `\`.
    {"/opt/a\\b", "/opt/a\\b"},
    {"C:/Program Files\\Tool/Sub", "C:\\Program Files\\Tool\\Sub"},
    // The rule is lexical (ADR-0016 section 8): under a machine root a segment that merely
    // looks like a profile folder is kept; nothing below the root is inspected.
    {"/opt/users/alice/app", "/opt/users/alice/app"},
    {"/Library/Users", "/Library/Users"},
    {"/opt/homedir", "/opt/homedir"},
    {"C:\\Program Files", "C:\\Program Files"},
    // Junk a single canonicalisation pass does not settle: a quote exposed by a stripped dot
    // segment, trailing dot or padding. The stored form is the fixed point (quote gone), not the
    // one-pass form (`/opt/foo"`): a one-pass writer planned one record and transmitted another.
    {"/opt/foo\"/.", "/opt/foo"},
    {"/opt/foo\"/", "/opt/foo"},
    {"/opt/foo\". ", "/opt/foo\"."}, // POSIX keeps a trailing dot: one pass strips the padding only
    {"C:\\Program Files\\foo\".", "C:\\Program Files\\foo"},
    {"C:\\Program Files\\foo\" .", "C:\\Program Files\\foo"},
    {"C:\\Program Files\\foo\"\\.", "C:\\Program Files\\foo"},
    {"C:\\Program Files\\foo\".\".\".", "C:\\Program Files\\foo"}};

// The same junk shapes under no machine root: blank on both sides, whatever the pass count.
const std::vector<std::string> kJunkBlanked = {"/home/alice/foo\"/.", "C:\\Users\\alice\\foo\".",
                                                "/Users/alice/foo\". ", "/opt/..\"/."};

} // namespace

TEST_CASE("install_location is an allowlist: every spelling outside a machine root is blanked on the wire",
          "[v3][writer][privacy]") {
    for (const auto& path : kBlankedSpellings) {
        CAPTURE(path);
        CHECK(machine_install_location(path).empty());
        SwEntry e = alpha();
        e.install_location = path;
        // v3_record: slot 12 (install_location) is empty, and the row hashes as the blanked row.
        CHECK(split(v3_record(e), '\x1f')[12].empty());
        SwEntry blank = alpha();
        blank.install_location.clear();
        CHECK(v3_record(e) == v3_record(blank));
        // plan_section: the full section carries the blanked row, so its hash is the blanked set's.
        const SectionPlan plan = plan_section(kApps, {e}, std::nullopt, false);
        REQUIRE(plan.status == V3Status::full);
        REQUIRE(plan.adds.size() == 1);
        CHECK(plan.adds[0].install_location.empty());
        CHECK(plan.section_hash == plan_section(kApps, {blank}, std::nullopt, false).section_hash);
    }
    for (const auto& path : kJunkBlanked) {
        CAPTURE(path);
        CHECK(machine_install_location(path).empty());
    }
    // Under a machine root the location is kept, in ONE spelling (kKeptSpellings).
    for (const auto& [path, canonical] : kKeptSpellings) {
        CAPTURE(path);
        CHECK(machine_install_location(path) == canonical);
        SwEntry e = alpha();
        e.install_location = path;
        CHECK(split(v3_record(e), '\x1f')[12] == canonical);
        const SectionPlan plan = plan_section(kApps, {e}, std::nullopt, false);
        REQUIRE(plan.status == V3Status::full);
        REQUIRE(plan.adds.size() == 1);
        CHECK(plan.adds[0].install_location == canonical);
    }
    // The macOS name of the root is kept as spelled; one app under two spellings of its root is
    // one row only when the spellings canonicalise alike (case is kept, separators are not).
    SwEntry a = alpha();
    a.install_location = "C:/Program Files/Tool";
    SwEntry b = alpha();
    b.install_location = "\"C:\\Program Files\\Tool\\\"";
    CHECK(v3_row_hash(a) == v3_row_hash(b));
}

namespace {

// `/opt/foo` under `n` layers of quote-and-dot padding. A pass strips one exposed trailing quote
// (step 1) and drops one dot segment (step 4), so each layer costs one pass and `n` layers settle
// on pass n + 2 (the first pass only drops the outer dot; the last confirms the fixed point).
std::string quote_dot_layers(std::size_t n) {
    std::string s = "/opt/foo";
    for (std::size_t i = 0; i < n; ++i)
        s += "\"/.";
    return s;
}

} // namespace

TEST_CASE("machine_install_location is capped at kV3MaxCanonicalPasses passes and blanks past them",
          "[v3][writer][privacy]") {
    static_assert(kV3MaxCanonicalPasses >= 5,
                  "the kept corpus needs five passes for its deepest installer junk");
    // Pass behaviour, not wall-clock: the deepest value that settles inside the cap is kept, the
    // next layer is blanked (fail closed), whatever the host's speed.
    const std::size_t settles = static_cast<std::size_t>(kV3MaxCanonicalPasses - 2);
    CHECK(machine_install_location(quote_dot_layers(settles)) == "/opt/foo");
    CHECK(machine_install_location(quote_dot_layers(settles + 1)).empty());
    // A hostile registry value of about 20,000 bytes (one layer per three bytes) is blanked at
    // the cap rather than canonicalised once per layer over the whole string.
    const std::string hostile = quote_dot_layers(6666);
    REQUIRE(hostile.size() > 20000);
    CHECK(machine_install_location(hostile).empty());
    // Blank is a fixed point, so the stored form of a blanked value re-normalises to itself.
    CHECK(machine_install_location("").empty());
}

TEST_CASE("canonical epoch and release spelling are stable across two collections",
          "[v3][writer][canonical]") {
    CHECK(canonical_epoch("0").empty());
    CHECK(canonical_epoch("(none)").empty());
    CHECK(canonical_epoch("1") == "1");
    CHECK(canonical_release("(none)").empty());
    CHECK(canonical_release("0") == "0"); // a real release
    CHECK(canonical_release("3.fc40") == "3.fc40");

    SwEntry first = row("bash", "5.2");
    first.ecosystem = "rpm";
    first.epoch = "(none)";
    first.release = "3.fc40";
    SwEntry second = first;
    second.epoch = "0";
    SwEntry third = first;
    third.epoch.clear();
    CHECK(v3_record(first) == v3_record(second));
    CHECK(v3_record(first) == v3_record(third));
    CHECK(v3_row_hash(first) == v3_row_hash(second));
    CHECK(v3_section_hash({first}) == v3_section_hash({second}));
    // A real epoch is kept.
    third.epoch = "2";
    CHECK(v3_record(third) != v3_record(first));
}

TEST_CASE("plan_section: full without an acked set, a one-row delta with expect, unchanged otherwise",
          "[v3][planner]") {
    std::vector<SwEntry> rows = {row("a"), row("b"), row("c")};
    const SectionPlan first = plan_section(kApps, rows, std::nullopt, false);
    REQUIRE(first.status == V3Status::full);
    CHECK(first.adds.size() == 3);
    CHECK(first.deletes.empty());
    CHECK(first.base.empty());
    CHECK(first.section_hash == v3_section_hash([&] {
        auto r = rows;
        for (auto& e : r)
            vendor_or_origin(e);
        return r;
    }()));
    CHECK(first.row_hashes.size() == 3);
    CHECK(std::is_sorted(first.row_hashes.begin(), first.row_hashes.end()));

    const AckedSet acked = acked_of(first);
    // Nothing changed: no section at all.
    const SectionPlan same = plan_section(kApps, rows, acked, false);
    CHECK(same.unchanged);
    // need_full overrides.
    CHECK(plan_section(kApps, rows, acked, true).status == V3Status::full);

    // One row upgraded: exactly one `-` and one `+`, base the acked hash, expect the new hash.
    rows[1].version = "2";
    const SectionPlan delta = plan_section(kApps, rows, acked, false);
    REQUIRE(delta.status == V3Status::delta);
    REQUIRE(delta.adds.size() == 1);
    REQUIRE(delta.deletes.size() == 1);
    CHECK(delta.adds[0].name == "b");
    CHECK(delta.adds[0].version == "2");
    CHECK(delta.base == acked.section_hash);
    CHECK(delta.expect == delta.section_hash);
    CHECK(delta.expect != acked.section_hash);
    CHECK(delta.deletes[0] == v3_row_hash(row("b"))); // the OLD b: version "1"
    // The blob carries expect on the S record of the delta.
    const auto parsed = parse_like_server(write_v3_blob({delta}).blob);
    REQUIRE(parsed.sections.size() == 1);
    CHECK(parsed.sections[0].header[2] == "delta");
    CHECK(parsed.sections[0].header[3] == acked.section_hash);
    CHECK(parsed.sections[0].header[7] == delta.expect);

    // A garbled acked pair (same rows, different hash) is resynced in full, not trusted.
    AckedSet lying = acked;
    lying.section_hash = std::string(64, '0');
    CHECK(plan_section(kApps, std::vector<SwEntry>{row("a"), row("b"), row("c")}, lying, false)
              .status == V3Status::full);
}

TEST_CASE("plan_section: a delta that would outgrow the byte budget falls back to full; 20001 rows is oversize",
          "[v3][planner]") {
    // 2800 rows of ~1 KiB each fit as a FULL section (~3.0 MB < the 3.13 MB budget). Replacing every
    // row makes a delta of the whole new set plus 2800 `-` records, which no longer fits alone.
    const auto fat = [](const char* prefix) {
        std::vector<SwEntry> rows;
        for (int i = 0; i < 2800; ++i) {
            SwEntry e = row(std::string(prefix) + std::to_string(i));
            e.version = std::string(1000, 'v');
            rows.push_back(std::move(e));
        }
        return rows;
    };
    const SectionPlan first = plan_section(kApps, fat("old"), std::nullopt, false);
    REQUIRE(first.status == V3Status::full);
    REQUIRE(first.full_bytes < kV3SectionByteBudget);
    const SectionPlan replaced = plan_section(kApps, fat("new"), acked_of(first), false);
    CHECK(replaced.status == V3Status::full);
    CHECK(replaced.base.empty());

    // 20001 rows is past the per-call cap whatever the acked set says: oversize (rows), status-only.
    std::vector<SwEntry> huge;
    huge.reserve(kV3MaxRows + 1);
    for (std::size_t i = 0; i < kV3MaxRows + 1; ++i)
        huge.push_back(row("n" + std::to_string(i)));
    const SectionPlan over = plan_section(kApps, huge, acked_of(first), false);
    CHECK(over.status == V3Status::oversize);
    CHECK(over.token == "rows=20001");
    CHECK(over.adds.empty());
}

TEST_CASE("plan_section: a section below the row cap whose full form exceeds the byte budget is oversize",
          "[v3][planner]") {
    // ~1 KiB of version per row: 4000 rows is ~4 MiB, over the 3 MiB blob with only 4000 rows.
    std::vector<SwEntry> rows;
    for (int i = 0; i < 4000; ++i) {
        SwEntry e = row("n" + std::to_string(i));
        e.version = std::string(1000, 'v');
        e.distro_version = std::string(24, 'd');
        rows.push_back(std::move(e));
    }
    const SectionPlan p = plan_section(kApps, rows, std::nullopt, false);
    CHECK(p.status == V3Status::oversize);
    CHECK(p.token.starts_with("bytes="));
    CHECK(p.full_bytes > kV3SectionByteBudget);
    // Status-only: never deferred, never carries rows.
    const auto blob = write_v3_blob({p});
    CHECK(blob.deferred.empty());
    const auto parsed = parse_like_server(blob.blob);
    REQUIRE(parsed.sections.size() == 1);
    CHECK(parsed.sections[0].header[2] == "oversize");
    CHECK(parsed.sections[0].adds.empty());
}

TEST_CASE("every + record has a non-empty publisher: the planner applies the origin label",
          "[v3][planner][vendor]") {
    SwEntry e = row("tool");
    e.publisher.clear();
    e.ecosystem = "brew";
    SwEntry blanked_by_clamp = row("other");
    blanked_by_clamp.publisher = "\x1f\x1e"; // empty once the separators are stripped
    blanked_by_clamp.ecosystem.clear();
    const auto parsed = parse_like_server(
        write_v3_blob({plan_section(kPkgs, {e, blanked_by_clamp}, std::nullopt, false)}).blob);
    REQUIRE(parsed.sections.size() == 1);
    REQUIRE(parsed.sections[0].adds.size() == 2);
    std::vector<std::string> pubs;
    for (const auto& a : parsed.sections[0].adds)
        pubs.push_back(a[3]);
    std::sort(pubs.begin(), pubs.end());
    CHECK(pubs == std::vector<std::string>{"via:brew", "via:unknown"});
}

namespace {

namespace srv = yuzu::server;

// The server's side of the contract, over the rows ITS parser produced from the wire: the record
// (software_inventory_store.cpp append_section_record), the comparator (entry_less) and the
// section hash (canonical_section_hash). The planner must land on these bytes exactly.
std::string server_record(const srv::SoftwareEntry& e) {
    const std::string_view slots[16] = {e.name,       e.version,          e.publisher,
                                        e.install_date, e.kind,           e.ecosystem,
                                        e.epoch,      e.release,          e.arch,
                                        e.signature_status, e.distro_id,  e.distro_version,
                                        e.install_location, std::string_view{}, e.package_id,
                                        e.source};
    std::string out;
    for (std::size_t i = 0; i < 16; ++i) {
        if (i)
            out += '\x1f';
        out += slots[i];
    }
    out += '\x1e';
    return out;
}

bool server_less(const srv::SoftwareEntry& a, const srv::SoftwareEntry& b) {
    return std::tie(a.name, a.version, a.publisher, a.install_date, a.kind, a.ecosystem, a.epoch,
                    a.release, a.arch, a.signature_status, a.distro_id, a.distro_version,
                    a.install_location, a.package_id, a.source) <
           std::tie(b.name, b.version, b.publisher, b.install_date, b.kind, b.ecosystem, b.epoch,
                    b.release, b.arch, b.signature_status, b.distro_id, b.distro_version,
                    b.install_location, b.package_id, b.source);
}

std::string server_section_hash(std::vector<srv::SoftwareEntry> rows) {
    std::sort(rows.begin(), rows.end(), server_less);
    rows.erase(std::unique(rows.begin(), rows.end(),
                           [](const auto& a, const auto& b) {
                               return !server_less(a, b) && !server_less(b, a);
                           }),
               rows.end());
    std::string canon;
    for (const auto& e : rows)
        canon += server_record(e);
    return sha256_hex(canon);
}

std::vector<std::string> server_row_hashes(const std::vector<srv::SoftwareEntry>& rows) {
    std::vector<std::string> out;
    for (const auto& e : rows)
        out.push_back(sha256_hex(server_record(e)));
    std::sort(out.begin(), out.end());
    return out;
}

// The one section of a blob as the server parses it, accepted whole.
srv::V3Section server_section(const std::string& blob) {
    const auto parsed = srv::parse_v3_blob(blob);
    REQUIRE(parsed.has_value());
    REQUIRE(parsed->sections.size() == 1);
    REQUIRE(parsed->sections[0].refusal == srv::V3Refusal::kNone);
    return parsed->sections[0];
}

// The 15 stored fields of an agent row, for field-wise equality (SwEntry has no operator==).
std::vector<std::string> fields_of(const SwEntry& e) {
    return {e.name,  e.version, e.publisher, e.install_date, e.kind, e.ecosystem,
            e.epoch, e.release, e.arch, e.signature_status, e.distro_id, e.distro_version,
            e.install_location, e.package_id, e.source};
}

// The shapes that once made the planner hash one record and the writer transmit another: a
// location that settles only after a second canonicalisation pass (with and without a kept
// root), an origin label built from a 1,024-byte ecosystem (1,028 bytes before the clamp), and
// a plain row beside them.
std::vector<SwEntry> trigger_rows() {
    std::vector<SwEntry> rows;
    for (const char* loc : {"/opt/foo\"/.", "/opt/foo\". ", "C:\\Program Files\\foo\".",
                            "C:\\Program Files\\foo\"\\.", "/home/alice/foo\"/.",
                            "C:\\Users\\alice\\foo\"."}) {
        SwEntry e = alpha();
        e.name = std::string("loc-") + loc;
        e.install_location = loc;
        rows.push_back(e);
    }
    SwEntry eco = alpha();
    eco.name = "long-ecosystem";
    eco.publisher.clear();
    eco.ecosystem = std::string(kV3MaxFieldLen, 'x');
    rows.push_back(eco);
    rows.push_back(alpha());
    return rows;
}

} // namespace

TEST_CASE("the planned section hash is the hash over the server-parsed wire records, trigger shapes included",
          "[v3][planner][hash][privacy]") {
    // Each shape alone, then all together: the server hashes what it stored, which is what it
    // parsed, which must be what the planner hashed.
    std::vector<std::vector<SwEntry>> sets;
    for (const auto& r : trigger_rows())
        sets.push_back({r});
    sets.push_back(trigger_rows());
    for (const auto& rows : sets) {
        CAPTURE(rows[0].name, rows.size());
        const SectionPlan p = plan_section(kApps, rows, std::nullopt, false);
        REQUIRE(p.status == V3Status::full);
        const srv::V3Section sec = server_section(write_v3_blob({p}).blob);
        REQUIRE(sec.rows.size() == p.adds.size());
        CHECK(server_section_hash(sec.rows) == p.section_hash);
        CHECK(server_row_hashes(sec.rows) == p.row_hashes);
        // ...and field for field: what the server holds is the planned row.
        for (std::size_t i = 0; i < sec.rows.size(); ++i) {
            CAPTURE(i, p.adds[i].name);
            CHECK(sec.rows[i].publisher == p.adds[i].publisher);
            CHECK(sec.rows[i].install_location == p.adds[i].install_location);
        }
    }
    // The label is clamped on the planner's side, so the server keeps it whole.
    const SectionPlan eco = plan_section(kApps, {trigger_rows()[6]}, std::nullopt, false);
    CHECK(eco.adds[0].publisher.size() == kV3MaxFieldLen);
    CHECK(eco.adds[0].publisher.starts_with("via:xxxx"));
    CHECK(server_section(write_v3_blob({eco}).blob).rows[0].publisher == eco.adds[0].publisher);
}

TEST_CASE("a delta against the acknowledged FULL applies on the server-parsed set: deletions name held rows, expect is the result",
          "[v3][planner][hash][delta]") {
    const std::vector<SwEntry> before = trigger_rows();
    const SectionPlan full = plan_section(kApps, before, std::nullopt, false);
    const srv::V3Section held = server_section(write_v3_blob({full}).blob);
    REQUIRE(server_section_hash(held.rows) == full.section_hash);
    const AckedSet acked = acked_of(full); // what on_ack commits

    // One junk-location row upgraded, one removed, one plain row added.
    std::vector<SwEntry> after;
    for (const auto& r : before) {
        if (r.name == "loc-/opt/foo\". ")
            continue; // gone
        SwEntry e = r;
        if (r.name == "loc-C:\\Program Files\\foo\".")
            e.version = "1.1";
        after.push_back(e);
    }
    after.push_back(row("plain-add"));
    const SectionPlan delta = plan_section(kApps, after, acked, false);
    REQUIRE(delta.status == V3Status::delta);
    CHECK(delta.base == full.section_hash);
    CHECK(delta.deletes.size() == 2);
    CHECK(delta.adds.size() == 2);

    const srv::V3Section wire = server_section(write_v3_blob({delta}).blob);
    REQUIRE(wire.status == srv::V3Status::kDelta);
    CHECK(wire.base == full.section_hash);
    CHECK(wire.expect == delta.expect);
    // Every `-` names a row the server holds, by the hash of the record IT stored.
    const auto held_hashes = server_row_hashes(held.rows);
    for (const auto& d : wire.deletions) {
        CAPTURE(d);
        CHECK(std::binary_search(held_hashes.begin(), held_hashes.end(), d));
    }
    // Apply as the server does: drop the named rows, add the `+` rows, hash the result.
    std::vector<srv::SoftwareEntry> applied;
    for (const auto& e : held.rows) {
        const std::string h = sha256_hex(server_record(e));
        if (std::find(wire.deletions.begin(), wire.deletions.end(), h) == wire.deletions.end())
            applied.push_back(e);
    }
    applied.insert(applied.end(), wire.rows.begin(), wire.rows.end());
    CHECK(server_section_hash(applied) == wire.expect);
    CHECK(server_section_hash(applied) ==
          plan_section(kApps, after, std::nullopt, false).section_hash);
}

TEST_CASE("write_v3_blob writes the planned record byte for byte: the planner is the one normalisation point",
          "[v3][writer]") {
    // A planned row is in normal form. This one is made not to be: epoch `0` is canonically
    // empty. The writer must transmit `0`, because a writer that normalises again hashes one
    // record and transmits another whenever a pass is not a fixed point.
    SectionPlan p = plan_section(kApps, {alpha()}, std::nullopt, false);
    REQUIRE(p.adds.size() == 1);
    p.adds[0].epoch = "0";
    const auto parsed = parse_like_server(write_v3_blob({p}).blob);
    REQUIRE(parsed.sections.size() == 1);
    REQUIRE(parsed.sections[0].adds.size() == 1);
    CHECK(parsed.sections[0].adds[0][7] == "0"); // slot 6 (epoch) is field 7 after the `+`
}

TEST_CASE("v3_normal_form and machine_install_location are fixed points over the privacy corpus and the trigger shapes",
          "[v3][writer][privacy][hash]") {
    std::vector<std::string> corpus = kBlankedSpellings;
    corpus.insert(corpus.end(), kJunkBlanked.begin(), kJunkBlanked.end());
    for (const auto& [path, canonical] : kKeptSpellings) {
        corpus.push_back(path);
        corpus.push_back(canonical);
    }
    for (const auto& path : corpus) {
        CAPTURE(path);
        const std::string once = machine_install_location(path);
        CHECK(machine_install_location(once) == once);
        // ...and the whole row, with every other field at a value its clamp or canonical
        // spelling changes: the normal form of the normal form is the normal form.
        SwEntry e = alpha();
        e.install_location = path;
        e.publisher = std::string(kV3MaxFieldLen + 10, 'p');
        e.ecosystem = std::string(kV3MaxFieldLen, 'x');
        e.epoch = "(none)";
        e.release = "(none)";
        e.version = "1.\x1f" "0";
        const SwEntry nf = v3_normal_form(e);
        CHECK(fields_of(v3_normal_form(nf)) == fields_of(nf));
    }
    // Planned rows (the label applied, the source set) are a fixed point too: the wire form is
    // the normal form, so the server's hash over what it stores is the planner's hash.
    for (const auto& planned : plan_section(kApps, trigger_rows(), std::nullopt, false).adds) {
        CAPTURE(planned.name);
        CHECK(fields_of(v3_normal_form(planned)) == fields_of(planned));
    }
}

TEST_CASE("write_v3_blob: header, S field order, status-only sections first, no rows in them",
          "[v3][writer][blob]") {
    SectionPlan full = plan_section(kApps, {row("a"), row("b")}, std::nullopt, false);
    full.duration_ms = 12;
    full.bytes_read = 3456;
    SectionPlan degraded = status_section(kPy, V3Status::constrained, "rc=2");
    degraded.duration_ms = 7;
    degraded.bytes_read = 99;
    SectionPlan absent = status_section(kPkgs, V3Status::not_collected, "not_loaded");

    const auto out = write_v3_blob({full, degraded, absent});
    CHECK(out.blob.starts_with(std::string(kV3Header)));
    CHECK(out.deferred.empty());
    // Status-only sections come first, in plan order, then the row-bearing one.
    CHECK(out.sent == std::vector<std::string>{kPy, kPkgs, kApps});
    const auto parsed = parse_like_server(out.blob);
    REQUIRE(parsed.sections.size() == 3);
    // S | facet | status | base | token | duration_ms | bytes_read | expect
    CHECK(parsed.sections[0].header ==
          std::vector<std::string>{"S", kPy, "constrained", "", "rc=2", "7", "99", ""});
    CHECK(parsed.sections[0].adds.empty());
    CHECK(parsed.sections[1].header[2] == "not_collected");
    CHECK(parsed.sections[2].header ==
          std::vector<std::string>{"S", kApps, "full", "", "", "12", "3456", ""});
    CHECK(parsed.sections[2].adds.size() == 2);
    // A token is bounded to the safe alphabet: a separator cannot re-frame the S record.
    const auto evil = write_v3_blob(
        {status_section(kPy, V3Status::timeout, "a\x1f" "b\x1e" "c d")});
    CHECK(parse_like_server(evil.blob).sections[0].header[4] == "a_b_c_d");
    // An unchanged plan is not written at all.
    SectionPlan unchanged = plan_section(kApps, {row("a")}, acked_of(plan_section(kApps, {row("a")}, std::nullopt, false)), false);
    REQUIRE(unchanged.unchanged);
    const auto only = write_v3_blob({unchanged, degraded});
    CHECK(only.sent == std::vector<std::string>{kPy});
}

TEST_CASE("write_v3_blob: a row-bearing section that would cross a call cap but fits alone is deferred",
          "[v3][writer][blob]") {
    const auto make = [](const char* facet, std::size_t n, const char* prefix) {
        std::vector<SwEntry> rows;
        rows.reserve(n);
        for (std::size_t i = 0; i < n; ++i)
            rows.push_back(row(std::string(prefix) + std::to_string(i), "1", facet));
        return plan_section(facet, std::move(rows), std::nullopt, false);
    };
    const SectionPlan a = make(kApps, 12000, "a");
    const SectionPlan b = make(kPkgs, 12000, "b"); // 24000 `+` in total: over the call cap
    const SectionPlan c = make(kPy, 10, "c");      // small: still fits after a
    REQUIRE(a.status == V3Status::full);
    REQUIRE(b.status == V3Status::full);
    const auto out = write_v3_blob({a, b, c});
    CHECK(out.sent == std::vector<std::string>{kApps, kPy});
    CHECK(out.deferred == std::vector<std::string>{kPkgs});
    CHECK(out.blob.size() <= kV3MaxBlobBytes);
    const auto parsed = parse_like_server(out.blob);
    REQUIRE(parsed.sections.size() == 2);
    CHECK(parsed.sections[0].adds.size() == 12000);
    CHECK(parsed.sections[1].adds.size() == 10);

    // The byte cap defers too: two sections of ~2 MiB each cannot share a 3 MiB blob.
    const auto fat = [](const char* facet, const char* prefix) {
        std::vector<SwEntry> rows;
        for (int i = 0; i < 2000; ++i) {
            SwEntry e = row(std::string(prefix) + std::to_string(i), "1", facet);
            e.version = std::string(1000, 'v');
            rows.push_back(std::move(e));
        }
        return plan_section(facet, std::move(rows), std::nullopt, false);
    };
    const SectionPlan f1 = fat(kApps, "x");
    const SectionPlan f2 = fat(kPkgs, "y");
    REQUIRE(f1.status == V3Status::full);
    REQUIRE(f2.status == V3Status::full);
    const auto two = write_v3_blob({f1, f2});
    CHECK(two.sent == std::vector<std::string>{kApps});
    CHECK(two.deferred == std::vector<std::string>{kPkgs});
    CHECK(two.blob.size() <= kV3MaxBlobBytes);
}

TEST_CASE("write_v3_blob: the section count is capped at kV3MaxSections; the one past it is deferred",
          "[v3][writer][blob]") {
    // Unreachable from the eleven-row table, pinned so the server's section cap stays mirrored.
    std::vector<SectionPlan> plans;
    std::vector<std::string> facets;
    for (std::size_t i = 0; i <= kV3MaxSections; ++i) {
        facets.push_back("facet." + std::to_string(i));
        plans.push_back(plan_section(facets.back(), {row("r", "1", facets.back())}, std::nullopt, false));
    }
    const auto out = write_v3_blob(plans);
    CHECK(out.sent.size() == kV3MaxSections);
    CHECK(out.deferred == std::vector<std::string>{facets.back()});
    CHECK(parse_like_server(out.blob).sections.size() == kV3MaxSections);

    // A status-only section past the cap is dropped, not deferred: waiting cannot make it fit
    // and a deferral would hold `more` up for a section that carries no rows.
    std::vector<SectionPlan> statuses;
    for (const auto& f : facets)
        statuses.push_back(status_section(f, V3Status::timeout, "t"));
    const auto only_status = write_v3_blob(statuses);
    CHECK(only_status.sent.size() == kV3MaxSections);
    CHECK(only_status.deferred.empty());
    CHECK(parse_like_server(only_status.blob).sections.size() == kV3MaxSections);
}

TEST_CASE("the acked value round-trips and anything torn reads as no acked set", "[v3][kv]") {
    const SectionPlan p = plan_section(kApps, {row("a"), row("b")}, std::nullopt, false);
    const AckedSet in = acked_of(p);
    const std::string v = acked_encode(in);
    CHECK(v.size() == 64 + 1 + 2 * 64);
    const auto out = acked_decode(v);
    REQUIRE(out.has_value());
    CHECK(out->section_hash == in.section_hash);
    CHECK(out->row_hashes == in.row_hashes);

    // Honest-empty: the empty-set hash and no row hashes.
    const auto empty = acked_decode(std::string(kEmptyHash) + "\n");
    REQUIRE(empty.has_value());
    CHECK(empty->row_hashes.empty());

    CHECK_FALSE(acked_decode("").has_value());
    CHECK_FALSE(acked_decode("short\n").has_value());
    CHECK_FALSE(acked_decode(v.substr(0, v.size() - 1)).has_value());                  // torn body
    CHECK_FALSE(acked_decode(in.section_hash + "x" + v.substr(65)).has_value());       // bad separator
    std::string upper = v;
    upper[3] = 'A';
    CHECK_FALSE(acked_decode(upper).has_value());                                       // not lowercase hex
    std::string nonhex = v;
    nonhex[70] = 'g';
    CHECK_FALSE(acked_decode(nonhex).has_value());
    // The row cap on the stored value: a KV row no plan could have written is torn, not trusted.
    std::string over = std::string(kEmptyHash) + "\n";
    for (std::size_t i = 0; i <= kV3MaxRows; ++i)
        over += kEmptyHash;
    CHECK_FALSE(acked_decode(over).has_value());
    CHECK(acked_decode(over.substr(0, over.size() - 64)).has_value()); // exactly kV3MaxRows reads
}
