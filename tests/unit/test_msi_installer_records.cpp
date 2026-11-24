/**
 * test_msi_installer_records.cpp -- the pure core of msi_packages.installer_records (SAM-46).
 *
 * Runs on every OS: msi_installer_records.hpp has no Windows headers and the OS boundary is
 * injected. The registry shapes come from a committed REAL capture
 * (tests/unit/fixtures/software-estate/msi_packages/windows/installer-records-system.txt, see
 * provenance.txt beside it: a read-only SYSTEM registry capture, redacted of user profile
 * paths). The shapes that capture does not hold (a package outside the Installer directory, a
 * product with no cached package, an install location under a profile, a product under two
 * upgrade codes, a missing package, a corrupt one, a timeout, a busy slot, a ceiling
 * rejection, row breakers) are built in the test from its rows.
 *
 * No registry key, package or process is opened: the OS boundary is a fake that records what
 * it was asked, and the handle a package open holds is a counter, so the test can prove the
 * handle is held while the database is read. The only files read are the committed fixture
 * and, in the lexical case, four source files (small, local, read once).
 */
#include <catch2/catch_test_macros.hpp>

#include "msi_installer_records.hpp"

#include <algorithm>
#include <cctype>
#include <chrono>
#include <expected>
#include <filesystem>
#include <format>
#include <fstream>
#include <map>
#include <memory>
#include <optional>
#include <set>
#include <sstream>
#include <string>
#include <string_view>
#include <vector>

#ifndef YUZU_TEST_FIXTURE_DIR
#define YUZU_TEST_FIXTURE_DIR "tests/unit/fixtures"
#endif
#ifndef YUZU_PLUGIN_SRC_DIR
#define YUZU_PLUGIN_SRC_DIR "agents/plugins"
#endif

namespace fs = std::filesystem;
namespace rec = yuzu::msi_packages::records;
namespace msi = yuzu::agent::msi;
using std::chrono::milliseconds;

namespace {

std::vector<std::string> split_raw(std::string_view line, char sep = '|') {
    std::vector<std::string> out;
    std::size_t pos = 0;
    while (true) {
        const auto at = line.find(sep, pos);
        if (at == std::string_view::npos) {
            out.emplace_back(line.substr(pos));
            return out;
        }
        out.emplace_back(line.substr(pos, at - pos));
        pos = at + 1;
    }
}

struct FxProduct {
    std::string packed;
    std::string braced; // the expected unpacked code, computed independently of the C++ codec
    std::optional<rec::InstallProps> props;
};
struct FxUpgrade {
    std::string packed;
    std::string braced;
    std::vector<std::string> products; // packed
};
struct Fixture {
    std::vector<FxProduct> products;
    std::vector<FxUpgrade> upgrades;
};

Fixture load_fixture() {
    const auto path = fs::path{YUZU_TEST_FIXTURE_DIR} / "software-estate" / "msi_packages" /
                      "windows" / "installer-records-system.txt";
    std::ifstream in(path);
    REQUIRE(in.is_open());
    Fixture fx;
    std::string line;
    while (std::getline(in, line)) {
        if (!line.empty() && line.back() == '\r')
            line.pop_back();
        if (line.empty() || line.front() == '#')
            continue;
        const auto f = split_raw(line);
        if (f[0] == "P") {
            REQUIRE(f.size() == 10);
            rec::InstallProps p;
            p.display_name = f[3];
            p.display_version = f[4];
            p.publisher = f[5];
            p.install_date = f[6];
            p.install_location = f[7];
            p.install_source = f[8];
            p.local_package = f[9];
            fx.products.push_back({f[1], f[2], p});
        } else if (f[0] == "N") {
            REQUIRE(f.size() == 3);
            fx.products.push_back({f[1], f[2], std::nullopt});
        } else if (f[0] == "U") {
            REQUIRE(f.size() == 4);
            fx.upgrades.push_back({f[1], f[2], split_raw(f[3], ',')});
        } else {
            FAIL("unknown fixture row kind " << f[0]);
        }
    }
    return fx;
}

constexpr const char* kPythonLauncher = "{0B1B5000-3C0E-41C0-83C4-4C914420AE93}";
constexpr const char* kCMake = "{B7526150-1C45-45B5-932D-A4CF5A23403C}";
constexpr const char* kSevenZip = "{23170F69-40C1-2702-2604-000001000000}";
constexpr const char* kRuntime = "{FED10190-CF54-E72D-7A92-E3F9CA9B7950}";
constexpr const char* kUserProfileProduct = "{80F76A51-EAF7-DA8E-C732-B26C591BCC23}";
constexpr const char* kOutsideInstaller = "{AF4ED0C1-A3D7-450B-A163-62CD3C7BBB27}";
constexpr const char* kNoLocalPackage = "{F9DDDEF1-BCF0-275F-DE29-9332F1149B79}";
constexpr const char* kNoProperties = "{5A6D1C2E-7B3F-4E58-9A10-5A3C0F6D7E21}"; // the one Products key with no InstallProperties

std::string lower(std::string s) {
    for (char& c : s)
        c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
    return s;
}

// What package_open returns: a status and a counted handle (a shared_ptr whose deleter
// decrements the host's live count), so the test can prove the handle outlives the read.
struct FakeOpen {
    rec::OpenStatus status = rec::OpenStatus::refused;
    std::shared_ptr<void> hold;
};

struct Host {
    std::vector<FxProduct> products;
    std::vector<std::string> raw_names; // when non-empty, enumerated instead of `products`
    std::optional<std::string> enum_failure;
    std::map<std::string, std::string> props_failure; // packed -> failure token
    std::set<std::string> absent;                     // lower-case paths the opener reports absent
    std::set<std::string> refused;                    // lower-case paths the opener refuses
    std::map<std::string, msi::ReadResult> answers;   // lower-case path -> the database answer
    milliseconds elapsed{10};                          // per default answer

    int live = 0;
    bool held_during_reads = true;
    std::size_t enumerated = 0;
    std::vector<std::string> opened;
    std::vector<std::string> read;
    std::vector<milliseconds> deadlines;

    // The default answer for a path: a good database whose ProductCode is the product's own
    // and whose UpgradeCode is spelled in lower case (the record must normalise it).
    msi::ReadResult default_answer(const std::string& path) const {
        msi::ReadResult r;
        r.status = msi::ReadStatus::Completed;
        r.elapsed = elapsed;
        r.outcome.kind = msi::Outcome::Kind::Ok;
        for (const auto& p : products) {
            if (p.props && lower(p.props->local_package) == lower(path)) {
                r.outcome.props.product_code = p.braced;
                r.outcome.props.upgrade_code = lower("{7E1A4B20-5C3D-4F68-9A01-2B3C4D5E6F70}");
                r.outcome.props.product_version = p.props->display_version;
                r.outcome.props.manufacturer = p.props->publisher;
                r.outcome.props.product_name = p.props->display_name;
            }
        }
        return r;
    }
};

rec::Context default_context() {
    rec::Context c;
    c.windows_dir = "C:\\WINDOWS";
    c.profile_roots = {"C:\\Users"};
    return c;
}

rec::RecordSet run(Host& h, const rec::Context& ctx = default_context()) {
    return rec::collect_records(
        ctx,
        [&](auto&& on_key) -> std::optional<std::string> {
            if (!h.raw_names.empty()) {
                for (const auto& n : h.raw_names) {
                    ++h.enumerated;
                    if (!on_key(n))
                        break;
                }
            } else {
                for (const auto& p : h.products) {
                    ++h.enumerated;
                    if (!on_key(p.packed))
                        break;
                }
            }
            return h.enum_failure;
        },
        [&](const std::string& packed)
            -> std::expected<std::optional<rec::InstallProps>, std::string> {
            if (const auto f = h.props_failure.find(packed); f != h.props_failure.end())
                return std::unexpected(f->second);
            for (const auto& p : h.products)
                if (p.packed == packed)
                    return p.props;
            return std::optional<rec::InstallProps>{};
        },
        [&](const std::string& path) {
            h.opened.push_back(path);
            FakeOpen o;
            if (h.absent.count(lower(path))) {
                o.status = rec::OpenStatus::absent;
            } else if (h.refused.count(lower(path))) {
                o.status = rec::OpenStatus::refused;
            } else {
                o.status = rec::OpenStatus::ok;
                ++h.live;
                o.hold = std::shared_ptr<void>(&h, [](Host* host) { --host->live; });
            }
            return o;
        },
        [&](const std::string& path, milliseconds deadline) {
            h.read.push_back(path);
            h.deadlines.push_back(deadline);
            if (h.live != 1)
                h.held_during_reads = false;
            if (const auto a = h.answers.find(lower(path)); a != h.answers.end())
                return a->second;
            return h.default_answer(path);
        });
}

const rec::InstallerRecord& record_of(const rec::RecordSet& set, std::string_view braced) {
    for (const auto& r : set.records)
        if (r.product_code == braced)
            return r;
    FAIL("no record for " << braced);
    return set.records.front();
}

Host fixture_host() {
    Host h;
    h.products = load_fixture().products;
    return h;
}

FxProduct& fx_product(Host& h, std::string_view braced) {
    for (auto& p : h.products)
        if (p.braced == braced)
            return p;
    FAIL("no fixture product " << braced);
    return h.products.front();
}

// The lower-case cached-package path the fixture records for a product (the key the fakes use).
std::string package_key(Host& h, std::string_view braced) {
    return lower(fx_product(h, braced).props->local_package);
}

// A distinct, well-formed packed name (as the registry holds it) for the i-th synthetic
// product, with the braced code it unpacks to.
FxProduct synthetic_product(std::size_t i, rec::InstallProps props) {
    std::string packed = std::format("{:032X}", i);
    std::string braced = *rec::unpack_guid(packed);
    return {std::move(packed), std::move(braced), std::move(props)};
}

// A host of `n` products that all have a readable cached package.
Host many_readable(std::size_t n) {
    Host h;
    for (std::size_t i = 0; i < n; ++i) {
        rec::InstallProps p;
        p.display_name = std::format("Product {}", i);
        p.local_package = std::format("C:\\WINDOWS\\Installer\\{:08x}.msi", i + 1);
        h.products.push_back(synthetic_product(i + 1, std::move(p)));
    }
    return h;
}

std::string slurp(const fs::path& p) {
    std::ifstream in(p, std::ios::binary);
    REQUIRE(in.is_open());
    std::ostringstream ss;
    ss << in.rdbuf();
    return ss.str();
}

} // namespace

TEST_CASE("installer records: the packed GUID codec matches an independent implementation",
          "[msi_packages][installer_records]") {
    const auto fx = load_fixture();
    REQUIRE(fx.products.size() == 137); // 136 with InstallProperties, 1 without
    CHECK(fx.upgrades.size() == 136);
    for (const auto& p : fx.products) {
        INFO(p.packed);
        const auto un = rec::unpack_guid(p.packed);
        REQUIRE(un.has_value());
        CHECK(*un == p.braced);
    }
    for (const auto& u : fx.upgrades)
        CHECK(rec::unpack_guid(u.packed) == u.braced);

    // The example Windows Installer's own documentation gives.
    CHECK(rec::unpack_guid("68AB67CA7DA73301B744CAF070E41400") ==
          "{AC76BA86-7AD7-1033-7B44-AC0F074E4100}");
    // Lower-case hex is accepted and the result is upper case.
    CHECK(rec::unpack_guid("68ab67ca7da73301b744caf070e41400") ==
          "{AC76BA86-7AD7-1033-7B44-AC0F074E4100}");
}

TEST_CASE("installer records: a wrong length or a non-hex key name is refused",
          "[msi_packages][installer_records]") {
    CHECK_FALSE(rec::unpack_guid("").has_value());
    CHECK_FALSE(rec::unpack_guid("68AB67CA7DA73301B744CAF070E4140").has_value());   // 31
    CHECK_FALSE(rec::unpack_guid("68AB67CA7DA73301B744CAF070E414000").has_value()); // 33
    CHECK_FALSE(rec::unpack_guid("68AB67CA7DA73301B744CAF070E4140G").has_value());  // 'G'
    CHECK_FALSE(rec::unpack_guid("{AC76BA86-7AD7-1033-7B44-AC0F074E4100}").has_value());
    CHECK_FALSE(rec::unpack_guid(std::string("68AB67CA7DA73301B744CAF070E4140\0", 32)).has_value());
}

TEST_CASE("installer records: the path gate", "[msi_packages][installer_records]") {
    const std::string dir = "C:\\WINDOWS";
    // accepted: the case the registry holds, the case an API spells, and a trailing separator
    CHECK(rec::package_path_allowed("C:\\WINDOWS\\Installer\\1d2e3f40.msi", dir));
    CHECK(rec::package_path_allowed("c:\\windows\\installer\\1a2b3c.MSI", dir));
    CHECK(rec::package_path_allowed("C:\\WINDOWS\\Installer\\1d2e3f40.msi", "C:\\Windows"));
    CHECK(rec::package_path_allowed("C:\\WINDOWS\\Installer\\1d2e3f40.msi", "C:\\WINDOWS\\"));

    // a parent other than <windir>\Installer
    CHECK_FALSE(rec::package_path_allowed("C:\\WINDOWS\\Temp\\x.msi", dir));
    CHECK_FALSE(rec::package_path_allowed("C:\\WINDOWS\\Installer\\Sub\\x.msi", dir));
    CHECK_FALSE(rec::package_path_allowed("C:\\WINDOWS\\Installerx\\x.msi", dir));
    CHECK_FALSE(rec::package_path_allowed("D:\\WINDOWS\\Installer\\x.msi", dir));
    CHECK_FALSE(rec::package_path_allowed("C:\\Temp\\relocated.msi", dir));
    CHECK_FALSE(rec::package_path_allowed("\\\\server\\share\\Installer\\x.msi", dir));
    // a path with `..` (the parent is then not the fixed directory)
    CHECK_FALSE(rec::package_path_allowed("C:\\WINDOWS\\Installer\\..\\Installer\\x.msi", dir));
    CHECK_FALSE(rec::package_path_allowed("C:\\WINDOWS\\Installer\\..\\x.msi", dir));
    // a relative path, an empty one, forward slashes
    CHECK_FALSE(rec::package_path_allowed("Installer\\x.msi", dir));
    CHECK_FALSE(rec::package_path_allowed("x.msi", dir));
    CHECK_FALSE(rec::package_path_allowed("", dir));
    CHECK_FALSE(rec::package_path_allowed("C:/WINDOWS/Installer/x.msi", dir));
    // a leaf that is not one plain name ending .msi
    CHECK_FALSE(rec::package_path_allowed("C:\\WINDOWS\\Installer\\x.exe", dir));
    CHECK_FALSE(rec::package_path_allowed("C:\\WINDOWS\\Installer\\x.msi.exe", dir));
    CHECK_FALSE(rec::package_path_allowed("C:\\WINDOWS\\Installer\\.msi", dir));
    CHECK_FALSE(rec::package_path_allowed("C:\\WINDOWS\\Installer\\x.msi ", dir));
    CHECK_FALSE(rec::package_path_allowed("C:\\WINDOWS\\Installer\\x.msi:stream", dir));
    CHECK_FALSE(rec::package_path_allowed("C:\\WINDOWS\\Installer\\a:b.msi", dir));
    CHECK_FALSE(rec::package_path_allowed("C:\\WINDOWS\\Installer\\*.msi", dir));
    CHECK_FALSE(rec::package_path_allowed(std::string("C:\\WINDOWS\\Installer\\a\0b.msi", 28), dir));
    // the Windows directory itself must be an absolute drive path
    CHECK_FALSE(rec::package_path_allowed("C:\\WINDOWS\\Installer\\x.msi", ""));
    CHECK_FALSE(rec::package_path_allowed("C:\\WINDOWS\\Installer\\x.msi", "WINDOWS"));
    CHECK_FALSE(rec::package_path_allowed("WINDOWS\\Installer\\x.msi", "WINDOWS"));
}

TEST_CASE("installer records: the path gate refuses Windows reserved device names",
          "[msi_packages][installer_records]") {
    const std::string dir = "C:\\WINDOWS";
    const auto in_cache = [](std::string leaf) { return "C:\\WINDOWS\\Installer\\" + leaf; };

    // CON, PRN, AUX, NUL, COM1-9 and LPT1-9, any case, with the .msi extension the gate needs
    for (const char* leaf : {"CON.msi", "con.msi", "Prn.MSI", "AUX.msi", "nul.msi", "NUL.Msi",
                             "COM1.msi", "com9.msi", "Com5.MSI", "LPT1.msi", "lpt9.msi", "Lpt3.msi"}) {
        INFO(leaf);
        CHECK_FALSE(rec::package_path_allowed(in_cache(leaf), dir));
    }
    // the device is what precedes the first dot, and spaces before it are ignored
    CHECK_FALSE(rec::package_path_allowed(in_cache("CON.x.msi"), dir));
    CHECK_FALSE(rec::package_path_allowed(in_cache("com1.backup.msi"), dir));
    CHECK_FALSE(rec::package_path_allowed(in_cache("NUL .msi"), dir));

    // names that only look like one stay allowed: a longer base, a different digit range, a
    // reserved word that is not the whole base name
    for (const char* leaf : {"CONSOLE.msi", "CON1.msi", "COM10.msi", "COMX.msi", "COM.msi",
                             "LPT.msi", "LPT10.msi", "AUXILIARY.msi", "NULL.msi", "PRNT.msi",
                             "a.CON.msi", "1d2e3f40.msi", "1a2b3c.MSI"}) {
        INFO(leaf);
        CHECK(rec::package_path_allowed(in_cache(leaf), dir));
    }
}

TEST_CASE("installer records: the profile-root test is ordinal, boundary-exact and either-separator",
          "[msi_packages][installer_records]") {
    const std::vector<std::string> roots{"C:\\Users", "D:\\Profiles\\"};
    CHECK(rec::path_under_any("C:\\Users\\jsmith\\AppData\\x", roots));
    CHECK(rec::path_under_any("c:/users/jsmith/x", roots));
    CHECK(rec::path_under_any("\\\\?\\C:\\Users\\jsmith\\x", roots));
    CHECK(rec::path_under_any("C:\\Users", roots));
    CHECK(rec::path_under_any("d:\\profiles\\a", roots));
    CHECK_FALSE(rec::path_under_any("C:\\UsersX\\jsmith", roots));
    CHECK_FALSE(rec::path_under_any("C:\\Program Files\\CMake\\", roots));
    CHECK_FALSE(rec::path_under_any("C:\\Use", roots));
    CHECK_FALSE(rec::path_under_any("C:\\Users\\jsmith", {}));
    CHECK_FALSE(rec::path_under_any("C:\\Users\\jsmith", std::vector<std::string>{""}));
}

TEST_CASE("installer records: the fixture products come out as the expected rows",
          "[msi_packages][installer_records]") {
    Host h = fixture_host();
    const auto set = run(h);
    const auto lines = rec::render(set);

    REQUIRE(set.records.size() == 137);
    CHECK_FALSE(set.constraints.any_failure());
    CHECK(set.non_guid_subkeys == 0);
    REQUIRE(lines.size() == 138);
    CHECK(lines[0] == "status|installer_records|supported|-");

    // The first product, in full: registry values, then the database's Property rows (its
    // UpgradeCode was spelled in lower case by the fake and comes out upper case).
    CHECK(lines[1] ==
          "rec|{0B1B5000-3C0E-41C0-83C4-4C914420AE93}|Python Launcher|3.14.6150.0|Python Software "
          "Foundation|20261012||C:\\ProgramData\\Package Cache\\{0B1B5000-3C0E-41C0-83C4-"
          "4C914420AE93}v3.14.6150.0\\|C:\\Windows\\Installer\\db826.msi|{7E1A4B20-5C3D-4F68-9A01-"
          "2B3C4D5E6F70}|{0B1B5000-3C0E-41C0-83C4-4C914420AE93}|3.14.6150.0|Python Software "
          "Foundation|Python Launcher|-");
    for (std::size_t i = 1; i < lines.size(); ++i)
        CHECK(split_raw(lines[i]).size() == 15);

    // the package is opened once per readable product and the handle is held while it is read
    CHECK(h.held_during_reads);
    CHECK(h.live == 0);
    CHECK(h.read.size() == h.opened.size());
}

TEST_CASE("installer records: an orphaned package is a row reason and the status stays supported",
          "[msi_packages][installer_records]") {
    Host h = fixture_host();
    h.absent.insert(package_key(h, kSevenZip)); // 7-Zip's cached package is gone
    const auto set = run(h);

    const auto& r = record_of(set, kSevenZip);
    CHECK(r.reason == "package_missing");
    CHECK(r.db.product_code.empty());
    CHECK(h.read.size() + 1 == h.opened.size()); // the absent package was opened, never read
    CHECK_FALSE(set.constraints.any_failure());
    CHECK(rec::render(set)[0] == "status|installer_records|supported|-");
    CHECK(rec::render(set).size() == 138);
}

TEST_CASE("installer records: a corrupt package keeps its row, names the code and spares its siblings",
          "[msi_packages][installer_records]") {
    Host h = fixture_host();
    msi::ReadResult bad;
    bad.status = msi::ReadStatus::Completed;
    bad.outcome.kind = msi::Outcome::Kind::OpenFailed;
    bad.outcome.rc = 1620; // ERROR_INSTALL_PACKAGE_INVALID
    h.answers[package_key(h, kRuntime)] = bad;
    const auto set = run(h);

    const auto& r = record_of(set, kRuntime);
    CHECK(r.reason == "package_unreadable:1620");
    CHECK(r.db.product_name.empty());
    // siblings are read on both sides of it
    CHECK(record_of(set, kPythonLauncher).reason.empty());
    CHECK(record_of(set, kUserProfileProduct).reason.empty());
    CHECK_FALSE(set.constraints.any_failure());
    CHECK(rec::render(set)[0] == "status|installer_records|supported|-");
}

TEST_CASE("installer records: every non-ok outcome names its reason", "[msi_packages][installer_records]") {
    using K = msi::Outcome::Kind;
    msi::Outcome o;
    o.kind = K::OpenFailed;
    o.rc = 1620;
    CHECK(rec::unreadable_reason(o) == "package_unreadable:1620");
    o.kind = K::ViewFailed;
    o.rc = 1615;
    CHECK(rec::unreadable_reason(o) == "package_unreadable:1615");
    o.kind = K::ReadFailed;
    o.rc = 234;
    CHECK(rec::unreadable_reason(o) == "package_unreadable:234");
    o.kind = K::Exception;
    CHECK(rec::unreadable_reason(o) == "package_unreadable:exception");
    o.kind = K::ApiUnavailable;
    CHECK(rec::unreadable_reason(o) == "package_unreadable:api_unavailable");
}

TEST_CASE("installer records: row-level reasons for a path that is not, or cannot be, opened",
          "[msi_packages][installer_records]") {
    Host h = fixture_host();
    h.refused.insert(package_key(h, kCMake)); // a reparse point, a device, a dead drive
    // shapes the capture does not hold, built from its rows: a package outside <windir>\Installer
    // and a product that records no package
    fx_product(h, kOutsideInstaller).props->local_package = "C:\\Temp\\relocated.msi";
    fx_product(h, kNoLocalPackage).props->local_package.clear();
    const auto set = run(h);

    // refused by the opener
    CHECK(record_of(set, kCMake).reason == "package_path_refused");
    // refused by the path gate before any open: not under <windir>\Installer
    CHECK(record_of(set, kOutsideInstaller).reason == "package_path_refused");
    CHECK(std::find(h.opened.begin(), h.opened.end(), "C:\\Temp\\relocated.msi") == h.opened.end());
    // nothing recorded to open
    CHECK(record_of(set, kNoLocalPackage).reason == "no_local_package");
    CHECK(record_of(set, kNoProperties).reason == "no_install_properties");
    CHECK(record_of(set, kNoProperties).props.display_name.empty());
    // none of those constrains the answer
    CHECK_FALSE(set.constraints.any_failure());
}

TEST_CASE("installer records: a failed registry read constrains the answer and keeps the siblings",
          "[msi_packages][installer_records]") {
    Host h = fixture_host();
    const std::string bad = "0516257B54C15B5439D24AFCA53204C3"; // CMake, as the registry names it
    h.props_failure[bad] = std::string{rec::kTokenAccessDenied};
    const auto set = run(h);

    CHECK(record_of(set, kCMake).reason == "install_properties_unreadable");
    CHECK(record_of(set, kPythonLauncher).reason.empty());
    CHECK(rec::render(set)[0] ==
          "status|installer_records|constrained|windows:installer_records:access_denied");
    CHECK(rec::registry_failure_token(5) == "windows:installer_records:access_denied");
    CHECK(rec::registry_failure_token(1450) == "windows:installer_records:enum:1450");
    CHECK(rec::upgrade_map_failure_token(5) == "windows:msi_upgrade_map:5");
}

TEST_CASE("installer records: an enumeration failure keeps the rows read and says why",
          "[msi_packages][installer_records]") {
    Host h = fixture_host();
    h.enum_failure = rec::enum_token(1450);
    const auto set = run(h);
    CHECK(set.records.size() == 137);
    CHECK(rec::render(set)[0] == "status|installer_records|constrained|windows:installer_records:enum:1450");
}

TEST_CASE("installer records: a subkey that is not a packed GUID is counted, never a row",
          "[msi_packages][installer_records]") {
    Host h;
    h.raw_names = {"Patches", "68AB67CA7DA73301B744CAF070E41400", std::string(31, 'A'), ""};
    const auto set = run(h);
    CHECK(set.non_guid_subkeys == 3);
    REQUIRE(set.records.size() == 1);
    CHECK(set.records[0].product_code == "{AC76BA86-7AD7-1033-7B44-AC0F074E4100}");
    CHECK(set.records[0].reason == "no_install_properties");
    CHECK_FALSE(set.constraints.any_failure());
}

TEST_CASE("installer records: the row cap stops the walk at 5000 rows", "[msi_packages][installer_records]") {
    Host h;
    for (std::size_t i = 0; i < rec::kMaxRecords + 1; ++i)
        h.raw_names.push_back(std::format("{:032X}", i));
    const auto set = run(h);

    CHECK(set.records.size() == 5000);
    CHECK(h.enumerated == 5001); // the 5,001st is asked for, refused, and the walk is told to stop
    const auto lines = rec::render(set);
    CHECK(lines.size() == 5001);
    CHECK(lines[0] == "status|installer_records|constrained|windows:installer_records:row_cap");

    // exactly 5000 products is not over the cap
    Host exact;
    exact.raw_names.assign(h.raw_names.begin(), h.raw_names.begin() + 5000);
    const auto ok = run(exact);
    CHECK(ok.records.size() == 5000);
    CHECK_FALSE(ok.constraints.any_failure());
}

TEST_CASE("installer records: a key stuffed with junk names cannot pin the walk",
          "[msi_packages][installer_records]") {
    Host h;
    h.raw_names.assign(rec::kMaxSubkeysVisited + 5, "junk");
    const auto set = run(h);
    CHECK(h.enumerated == rec::kMaxSubkeysVisited + 1);
    CHECK(set.records.empty());
    CHECK(rec::render(set)[0] == "status|installer_records|constrained|windows:installer_records:row_cap");
}

TEST_CASE("installer records: the records' text is capped in aggregate, not only per field",
          "[msi_packages][installer_records]") {
    // Every product carries six full-length values (the per-field bound allows it): far fewer
    // than kMaxRecords products reach the aggregate cap, so only that cap can stop the walk.
    const std::string full(rec::kMaxValueChars, 'a');
    rec::InstallProps heavy;
    heavy.display_name = heavy.display_version = heavy.publisher = full;
    heavy.install_date = heavy.install_location = heavy.install_source = full;
    // six values, the 38-character product code, and the reason a row with no LocalPackage gets
    const std::size_t per_row = 6 * rec::kMaxValueChars + 38 + std::string_view{"no_local_package"}.size();
    const std::size_t fit = rec::kMaxRecordBytes / per_row;
    REQUIRE(fit + 10 < rec::kMaxRecords);

    {
        Host h;
        for (std::size_t i = 0; i < fit + 10; ++i)
            h.products.push_back(synthetic_product(i + 1, heavy));
        const auto set = run(h);

        CHECK(rec::record_bytes(set.records.front()) == per_row);
        CHECK(set.records.size() == fit); // the row that would pass the cap is dropped
        CHECK(h.enumerated == fit + 1);   // and the walk is told to stop there
        const auto lines = rec::render(set);
        CHECK(lines.size() == fit + 1);
        CHECK(lines[0] == "status|installer_records|constrained|windows:installer_records:row_cap");
    }
    // the cap is on the total: exactly the rows that fit are all kept and the status is supported
    {
        Host h;
        for (std::size_t i = 0; i < fit; ++i)
            h.products.push_back(synthetic_product(i + 1, heavy));
        const auto set = run(h);
        CHECK(set.records.size() == fit);
        CHECK_FALSE(set.constraints.any_failure());
    }
}

TEST_CASE("installer records: the first timeout stops further opens and skips the rest",
          "[msi_packages][installer_records]") {
    Host h = many_readable(5);
    msi::ReadResult timed_out;
    timed_out.status = msi::ReadStatus::TimedOut;
    timed_out.elapsed = milliseconds{5000};
    h.answers["c:\\windows\\installer\\00000002.msi"] = timed_out;
    const auto set = run(h);

    CHECK(set.records[0].reason.empty());
    for (std::size_t i = 1; i < 5; ++i) {
        INFO(i);
        CHECK(set.records[i].reason == "deadline_skipped");
    }
    CHECK(h.read.size() == 2);   // the second timed out; nothing was read after it
    CHECK(h.opened.size() == 2); // and nothing was opened after it
    CHECK(rec::render(set)[0] == "status|installer_records|constrained|windows:installer_records:msi_db:deadline");
    CHECK(h.live == 0);
}

TEST_CASE("installer records: a busy slot on the first read opens nothing more",
          "[msi_packages][installer_records]") {
    for (const auto status : {msi::ReadStatus::Busy, msi::ReadStatus::Rejected}) {
        Host h = many_readable(4);
        msi::ReadResult busy;
        busy.status = status;
        h.answers["c:\\windows\\installer\\00000001.msi"] = busy;
        const auto set = run(h);

        CHECK(h.opened.size() == 1);
        CHECK(h.read.size() == 1);
        for (const auto& r : set.records)
            CHECK(r.reason == "deadline_skipped");
        CHECK(rec::render(set)[0] == "status|installer_records|constrained|windows:installer_records:msi_db:busy");
    }
}

TEST_CASE("installer records: package reads share one 45 second budget",
          "[msi_packages][installer_records]") {
    // nine 5 s reads use it all; the tenth is opened, finds the budget gone and stops the rest
    Host h = many_readable(12);
    h.elapsed = milliseconds{5000};
    const auto set = run(h);
    CHECK(h.read.size() == 9);
    CHECK(h.opened.size() == 10);
    for (const auto d : h.deadlines)
        CHECK(d == milliseconds{5000});
    CHECK(set.records[8].reason.empty());
    for (std::size_t i = 9; i < 12; ++i)
        CHECK(set.records[i].reason == "deadline_skipped");
    CHECK(rec::render(set)[0] == "status|installer_records|constrained|windows:installer_records:msi_db:deadline");

    // each read is asked for min(5 s, what is left): eleven 4 s reads leave 1 s for the twelfth
    Host g = many_readable(13);
    g.elapsed = milliseconds{4000};
    const auto set2 = run(g);
    REQUIRE(g.deadlines.size() == 12);
    CHECK(g.deadlines[10] == milliseconds{5000});
    CHECK(g.deadlines[11] == milliseconds{1000});
    CHECK(set2.records[12].reason == "deadline_skipped");
    CHECK(rec::render(set2)[0] == "status|installer_records|constrained|windows:installer_records:msi_db:deadline");
}

TEST_CASE("installer records: a database ProductCode that differs is flagged and both codes are kept",
          "[msi_packages][installer_records]") {
    Host h = fixture_host();
    msi::ReadResult other;
    other.status = msi::ReadStatus::Completed;
    other.elapsed = milliseconds{1};
    other.outcome.kind = msi::Outcome::Kind::Ok;
    other.outcome.props.product_code = "{FFFFFFFF-0000-4000-8000-000000000000}";
    other.outcome.props.product_name = "Some Other Product";
    h.answers[package_key(h, kPythonLauncher)] = other;
    // a case-only difference is not a mismatch (a machine registers some codes in lower case)
    msi::ReadResult lowered = other;
    lowered.outcome.props.product_code = lower(kCMake);
    h.answers[package_key(h, kCMake)] = lowered;
    const auto set = run(h);

    const auto& r = record_of(set, kPythonLauncher);
    CHECK(r.reason == "product_code_mismatch");
    CHECK(r.product_code == kPythonLauncher);
    CHECK(r.db.product_code == "{FFFFFFFF-0000-4000-8000-000000000000}");
    const auto row = rec::render(set)[1];
    CHECK(row.find(kPythonLauncher) != std::string::npos);
    CHECK(row.find("{FFFFFFFF-0000-4000-8000-000000000000}") != std::string::npos);
    CHECK(row.ends_with("|product_code_mismatch"));
    // a mismatch is a row reason only
    CHECK_FALSE(set.constraints.any_failure());

    const auto& same = record_of(set, kCMake);
    CHECK(same.reason.empty());
    CHECK(same.db.product_code == kCMake); // normalised to upper case
}

TEST_CASE("installer records: an install path under the user profiles is withheld",
          "[msi_packages][installer_records]") {
    Host h = fixture_host();
    // the capture holds profile paths only as install sources (the CMake one); an install
    // location under a profile, spelled in lower case, is built from another row
    fx_product(h, kUserProfileProduct).props->install_location = "c:\\users\\jsmith\\AppData\\Local\\X\\";
    const auto set = run(h);
    const auto& r = record_of(set, kUserProfileProduct);
    CHECK(r.props.install_location == "withheld:user_path");
    CHECK(record_of(set, kCMake).props.install_source == "withheld:user_path");
    // a machine path is left alone
    CHECK(record_of(set, kCMake).props.install_location == "C:\\Program Files\\CMake\\");
    for (const auto& line : rec::render(set))
        CHECK(line.find("jsmith") == std::string::npos);

    // the cached-package path is withheld too when it is under a profile, whatever the gate said,
    // and a sibling directory that merely starts with the same letters is not a profile
    Host g;
    rec::InstallProps p;
    p.local_package = "C:\\Users\\jsmith\\x.msi";
    p.install_location = "C:\\UsersX\\keep";
    p.install_source = "\\\\?\\C:\\Users\\jsmith\\dl";
    g.products.push_back(synthetic_product(1, p));
    const auto set2 = run(g);
    CHECK(set2.records[0].reason == "package_path_refused");
    CHECK(set2.records[0].props.local_package == "withheld:user_path");
    CHECK(set2.records[0].props.install_location == "C:\\UsersX\\keep");
    CHECK(set2.records[0].props.install_source == "withheld:user_path");
}

TEST_CASE("installer records: ProfileList completeness is decided from every failure signal",
          "[msi_packages][installer_records]") {
    rec::ProfileListFacts f; // a clean walk: ended with ERROR_NO_MORE_ITEMS
    CHECK(rec::profile_list_complete(f));
    // exactly the 512-profile cap with nothing behind it (probe finds no more) is complete
    f.last_rc = 0;
    f.probe_rc = rec::kErrorNoMoreItems;
    CHECK(rec::profile_list_complete(f));
    // truncated at the cap: more subkeys exist
    f.probe_rc = 0;
    f.truncated = true;
    CHECK_FALSE(rec::profile_list_complete(f));
    // the cap probe itself failed
    f.truncated = false;
    f.probe_rc = 5;
    CHECK_FALSE(rec::profile_list_complete(f));
    // each other signal alone
    rec::ProfileListFacts g;
    g.root_rc = 5;
    CHECK_FALSE(rec::profile_list_complete(g)); // ProfileList itself could not be opened
    g = {};
    g.last_rc = 5;
    CHECK_FALSE(rec::profile_list_complete(g)); // the walk ended on an error
    g = {};
    g.record_failures = 1;
    CHECK_FALSE(rec::profile_list_complete(g)); // one SID key or path value failed to read
    g = {};
    g.unreadable_paths = 1;
    CHECK_FALSE(rec::profile_list_complete(g)); // ProfileImagePath exists but is unusable
}

TEST_CASE("installer records: an incomplete profile list withholds every path and constrains",
          "[msi_packages][installer_records]") {
    Host g;
    rec::InstallProps p;
    p.install_location = "E:\\Redirected\\jsmith\\App"; // a redirected profile the list missed
    p.install_source = "C:\\Program Files\\Vendor\\";
    p.local_package = "C:\\WINDOWS\\Installer\\1a2b3c.msi";
    g.products.push_back(synthetic_product(1, p));
    auto ctx = default_context();
    ctx.profile_roots_complete = false;
    const auto set = run(g, ctx);
    const auto& r = set.records[0].props;
    CHECK(r.install_location == "withheld:profile_list_incomplete");
    CHECK(r.install_source == "withheld:profile_list_incomplete"); // machine path too: unknowable
    CHECK(r.local_package == "withheld:profile_list_incomplete");
    CHECK(set.constraints.any_failure());
    CHECK(rec::render(set)[0] ==
          "status|installer_records|constrained|windows:installer_records:profile_list_incomplete");
    for (const auto& line : rec::render(set))
        CHECK(line.find("jsmith") == std::string::npos);

    // an empty field has nothing to withhold, and a complete list leaves the redirected path
    // alone only when its folder is a listed root (a redirected profile that IS listed)
    Host h;
    rec::InstallProps q;
    q.install_location = "E:\\Redirected\\jsmith\\App";
    h.products.push_back(synthetic_product(2, q));
    auto done = default_context();
    done.profile_roots.push_back("E:\\Redirected\\jsmith");
    const auto listed = run(h, done);
    CHECK(listed.records[0].props.install_location == "withheld:user_path");
    CHECK(listed.records[0].props.install_source.empty());
    CHECK_FALSE(listed.constraints.any_failure());
}

TEST_CASE("installer records: the profile-root comparison folds ASCII only and keeps UTF-8 exact",
          "[msi_packages][installer_records]") {
    // U+00C9 (E acute) is the two bytes C3 89; its lower-case form U+00E9 is C3 A9. Neither
    // is folded: a non-ASCII profile folder matches only when recorded byte for byte.
    const std::vector<std::string> roots{"C:\\Users\\jsmith\xC3\x89"};
    CHECK(rec::path_under_any("c:\\USERS\\jsmith\xC3\x89\\x", roots));        // ASCII folds
    CHECK(rec::path_under_any("C:\\Users\\jsmith\xC3\x89", roots));            // byte-exact
    CHECK_FALSE(rec::path_under_any("C:\\Users\\jsmith\xC3\xA9\\x", roots));  // case variant
    // high bytes never alias an ASCII letter (no sign-extended std::tolower surprises)
    CHECK(rec::ascii_fold(static_cast<char>(0xC3)) == static_cast<char>(0xC3));
    CHECK(rec::ascii_fold('Z') == 'z');
    CHECK(rec::ascii_fold('[') == '[');
}

TEST_CASE("installer records: a root that is not a literal path makes the list incomplete",
          "[msi_packages][installer_records]") {
    CHECK(rec::count_unresolved_roots({"C:\\Users", "D:\\Profiles\\bob"}) == 0);
    CHECK(rec::count_unresolved_roots({"C:\\Users", "%PROFILE_DRIVE%\\Redirected\\Alice"}) == 1);
    CHECK(rec::count_unresolved_roots({"%HOMESHARE%\\bob", ""}) == 2); // empty: not usable either

    // clean registry facts, every root literal
    CHECK(rec::profile_roots_complete({"C:\\Users", "D:\\p\\bob"}, {}));
    // clean registry facts but an expansion that left a variable in place (the probe)
    CHECK_FALSE(
        rec::profile_roots_complete({"C:\\Users", "%PROFILE_DRIVE%\\Redirected\\Alice"}, {}));
    // ProfilesDirectory unreadable (or ProfileList unopenable) is incomplete on its own
    rec::ProfileListFacts f;
    f.profiles_dir_failed = true;
    CHECK_FALSE(rec::profile_roots_complete({"C:\\Users"}, f));
    // a registry fault is still incomplete with literal roots
    f = {};
    f.root_rc = 5;
    CHECK_FALSE(rec::profile_roots_complete({"C:\\Users"}, f));
}

TEST_CASE("installer records: an unresolved redirected root is withheld and constrained",
          "[msi_packages][installer_records]") {
    Host g;
    rec::InstallProps p;
    p.install_location = "C:\\Program Files\\Vendor\\";
    p.install_source = "E:\\Redirected\\Alice\\setup";
    g.products.push_back(synthetic_product(1, p));
    auto ctx = default_context();
    ctx.profile_roots = {"C:\\Users", "%PROFILE_DRIVE%\\Redirected\\Alice"};
    // the shell's decision, from clean registry facts
    ctx.profile_roots_complete = rec::profile_roots_complete(ctx.profile_roots, {});
    REQUIRE_FALSE(ctx.profile_roots_complete);
    const auto set = run(g, ctx);
    CHECK(set.records[0].props.install_source == "withheld:profile_list_incomplete");
    CHECK(set.records[0].props.install_location == "withheld:profile_list_incomplete");
    CHECK(rec::render(set)[0] ==
          "status|installer_records|constrained|windows:installer_records:profile_list_incomplete");
    for (const auto& line : rec::render(set))
        CHECK(line.find("Alice") == std::string::npos);
}

TEST_CASE("installer records: paths are normalised before the profile-root comparison",
          "[msi_packages][installer_records]") {
    const std::vector<std::string> roots{"C:\\Users", "E:\\Redirected\\alice"};
    // each non-canonical spelling of a profile path is still under the root
    CHECK(rec::path_under_any("C:\\\\Users\\\\x", roots));                  // doubled separators
    CHECK(rec::path_under_any("C:\\Users\\\\\\x\\y\\", roots));             // trailing separator
    CHECK(rec::path_under_any("C:\\Users\\.\\x", roots));                   // dot segment
    CHECK(rec::path_under_any("C:\\Windows\\..\\Users\\x", roots));         // dot-dot segment
    CHECK(rec::path_under_any("C:\\Users.\\x", roots));                     // trailing dot
    CHECK(rec::path_under_any("C:\\Users \\x", roots));                     // trailing space
    CHECK(rec::path_under_any("c:/USERS/x", roots));                        // either separator
    CHECK(rec::path_under_any("\\\\?\\C:\\Users\\x", roots));               // \\?\ prefix
    CHECK(rec::path_under_any("\\??\\C:\\Users\\x", roots));                // NT prefix
    CHECK(rec::path_under_any("\\\\.\\E:\\Redirected\\Alice\\x", roots));   // device prefix
    CHECK(rec::path_under_any("E:\\Redirected\\Alice...\\x", roots));       // trailing dots
    // a UNC profile root, in the long form too
    const std::vector<std::string> unc{"\\\\fs\\profiles$\\bob"};
    CHECK(rec::path_under_any("\\\\fs\\profiles$\\bob\\Documents", unc));
    CHECK(rec::path_under_any("\\\\?\\UNC\\fs\\profiles$\\bob\\Documents", unc));
    CHECK_FALSE(rec::path_under_any("\\\\fs\\profiles$\\bobby", unc));
    // dot-dot never climbs above the root and never leaves a profile by a sibling name
    CHECK_FALSE(rec::path_under_any("C:\\Users\\..\\Program Files", roots));
    CHECK_FALSE(rec::path_under_any("C:\\UsersX\\x", roots));
    // NOT handled, so they stay emitted (documented in the README): 8.3 names, junctions
    CHECK_FALSE(rec::path_under_any("C:\\USERS~1\\x", roots));
    CHECK_FALSE(rec::path_under_any("C:\\Documents and Settings\\x", roots));
    CHECK_FALSE(rec::path_under_any("\\\\localhost\\C$\\Users\\x", roots));
    // a root that normalises to nothing never matches everything
    CHECK_FALSE(rec::path_under_any("C:\\x", std::vector<std::string>{"\\", "\\\\", ".", ""}));
}

TEST_CASE("installer records: row breakers cannot break a row", "[msi_packages][installer_records]") {
    // SYNTHETIC strings: no captured name carries these.
    Host h;
    rec::InstallProps p;
    p.display_name = "A|B\nC\tD\rE";
    p.display_version = std::string("1.0\0|2", 6);
    p.publisher = "Contoso\\Tools|Inc";
    p.install_date = "2026|10";
    p.install_location = "C:\\A|B\\";
    p.install_source = "C:\\\n\\";
    p.local_package = "C:\\WINDOWS\\Installer\\xy.msi";
    h.products.push_back(synthetic_product(1, p));
    msi::ReadResult db;
    db.status = msi::ReadStatus::Completed;
    db.outcome.kind = msi::Outcome::Kind::Ok;
    db.outcome.props.product_name = "N|a\nm\te";
    db.outcome.props.manufacturer = std::string("M\0an", 4);
    h.answers["c:\\windows\\installer\\xy.msi"] = db;
    const auto set = run(h);
    const auto row = rec::render(set)[1];

    CHECK(split_raw(row).size() == 15);
    for (const char c : {'\n', '\r', '\t', '\0'})
        CHECK(row.find(c) == std::string::npos);
    CHECK(row.find("|ABCDE|1.02|Contoso\\ToolsInc|202610|") != std::string::npos);
    CHECK(row.ends_with("|Man|Name|-")); // the database fields are sanitised too
}

TEST_CASE("installer records: status rows", "[msi_packages][installer_records]") {
    rec::RecordSet s;
    CHECK(rec::render(s) == std::vector<std::string>{"status|installer_records|supported|-"});
    s.constraints.add_failure(rec::kTokenRowCap);
    s.constraints.add_failure(rec::kTokenAccessDenied);
    s.constraints.add_failure(rec::kTokenRowCap); // a token is listed once
    CHECK(rec::render(s)[0] ==
          "status|installer_records|constrained|windows:installer_records:row_cap,windows:installer_"
          "records:access_denied");
    CHECK(rec::unsupported_status_row("linux:no_msi") ==
          "status|installer_records|unsupported|linux:no_msi");
    CHECK(rec::unsupported_status_row("macos:no_windows_installer") ==
          "status|installer_records|unsupported|macos:no_windows_installer");
}

namespace {

rec::UpgradeMap build_map(const std::vector<FxUpgrade>& upgrades,
                          std::optional<std::string> failure = std::nullopt,
                          std::size_t* calls = nullptr) {
    return rec::build_upgrade_map([&](auto&& on_upgrade) -> std::optional<std::string> {
        for (const auto& u : upgrades) {
            if (calls)
                ++*calls;
            if (!on_upgrade(u.packed, u.products))
                break;
        }
        return failure;
    });
}

} // namespace

TEST_CASE("installer records: the upgrade map gives every product the code recorded for it",
          "[msi_packages][installer_records]") {
    const auto fx = load_fixture();
    const auto map = build_map(fx.upgrades);

    REQUIRE_FALSE(map.failure.has_value());
    CHECK_FALSE(map.over_cap);
    CHECK(map.bad_names == 0);
    for (const auto& u : fx.upgrades) {
        for (const auto& packed : u.products) {
            const auto product = *rec::unpack_guid(packed);
            const auto got = map.resolve(product);
            REQUIRE(got.has_value());
            CHECK(*got == u.braced);
        }
    }
    // every product of the capture is named under exactly one upgrade code
    CHECK(*map.resolve(kPythonLauncher) == "{1B68A0EC-4DD3-5134-840E-73854B0863F1}");
    CHECK(*map.resolve(kUserProfileProduct) == "{1EF02066-8B0C-AE04-CAD0-93F7E4164DC8}");
    // the Installer registers a code in whichever case; the join is case-insensitive
    CHECK(*map.resolve(lower(kPythonLauncher)) == "{1B68A0EC-4DD3-5134-840E-73854B0863F1}");
}

TEST_CASE("installer records: a product under no upgrade code, or under two, gets an empty token",
          "[msi_packages][installer_records]") {
    auto fx = load_fixture();
    // The capture names every product under one code; a second code naming the same product is
    // built here.
    const auto outside = std::find_if(fx.products.begin(), fx.products.end(),
                                      [](const auto& p) { return p.braced == kOutsideInstaller; });
    REQUIRE(outside != fx.products.end());
    fx.upgrades.push_back({std::format("{:032X}", 1), *rec::unpack_guid(std::format("{:032X}", 1)),
                           {outside->packed}});
    const auto map = build_map(fx.upgrades);

    // under two upgrade codes
    CHECK(*map.resolve(kOutsideInstaller) == "");
    // named under none: the Products key with no InstallProperties, and a code never registered
    for (const auto* none : {kNoProperties, "{FFFFFFFF-0000-4000-8000-000000000000}"})
        CHECK(*map.resolve(none) == "");
    // never an error: an empty token is not a fault
    CHECK(map.resolve(kNoProperties).has_value());
}

TEST_CASE("installer records: a name that is not a packed GUID is skipped and counted",
          "[msi_packages][installer_records]") {
    std::vector<FxUpgrade> up;
    up.push_back({"NotAPackedGuid", "", {"0005B1B0E0C30C14384CC4194402EA39"}});
    up.push_back({"02B4A1E7D3C586F4A910B2C3D4E5F607", "{7E1A4B20-5C3D-4F68-9A01-2B3C4D5E6F70}",
                  {"0005B1B0E0C30C14384CC4194402EA39", "garbage", ""}});
    const auto map = build_map(up);
    CHECK(map.bad_names == 3); // the subkey, and two value names
    CHECK(*map.resolve(kPythonLauncher) == "{7E1A4B20-5C3D-4F68-9A01-2B3C4D5E6F70}");
    CHECK_FALSE(map.over_cap);
}

TEST_CASE("installer records: an over-cap upgrade map is a failure: the roster is constrained",
          "[msi_packages][installer_records]") {
    // 257 value names under one subkey
    {
        FxUpgrade u{"02B4A1E7D3C586F4A910B2C3D4E5F607", "", {}};
        for (std::size_t i = 0; i < rec::kMaxUpgradeValueNames + 1; ++i)
            u.products.push_back(std::format("{:032X}", i));
        std::vector<FxUpgrade> up{load_fixture().upgrades[0], u};
        const auto map = build_map(up);
        CHECK(map.over_cap);
        CHECK(map.failure == std::string{rec::kTokenUpgradeMapOverCap});
        CHECK(map.by_product.empty()); // even the product read before the cap
        CHECK(map.resolve(kPythonLauncher).error() == "windows:msi_upgrade_map:over_cap");
        // exactly 256 is fine
        u.products.pop_back();
        CHECK_FALSE(build_map({u}).over_cap);
    }
    // 20,001 subkeys: the builder tells the walk to stop at the 20,001st
    {
        std::vector<FxUpgrade> up(rec::kMaxSubkeysVisited + 10,
                                  FxUpgrade{"02B4A1E7D3C586F4A910B2C3D4E5F607", "", {}});
        std::size_t calls = 0;
        const auto map = build_map(up, std::nullopt, &calls);
        CHECK(map.over_cap);
        CHECK(calls == rec::kMaxSubkeysVisited + 1);
        CHECK(map.failure == std::string{rec::kTokenUpgradeMapOverCap});
    }
}

TEST_CASE("installer records: the upgrade map caps the value names in all, not only per subkey",
          "[msi_packages][installer_records]") {
    // Each subkey is within its own bound (256 names) and the subkey count is far under its
    // bound, so only the aggregate cap can stop the walk.
    const auto subkey_with = [](std::size_t index, std::size_t names) {
        FxUpgrade u{std::format("{:032X}", 0x1000 + index), "", {}};
        for (std::size_t i = 0; i < names; ++i)
            u.products.push_back(std::format("{:032X}", index * 1000 + i));
        return u;
    };
    const std::size_t per = rec::kMaxUpgradeValueNames;
    const std::size_t full_subkeys = rec::kMaxUpgradeNames / per; // 78 x 256 = 19,968 names
    const std::size_t rest = rec::kMaxUpgradeNames - full_subkeys * per;
    REQUIRE(full_subkeys + 2 < rec::kMaxSubkeysVisited);

    // exactly kMaxUpgradeNames names is not over the cap
    std::vector<FxUpgrade> up;
    for (std::size_t i = 0; i < full_subkeys; ++i)
        up.push_back(subkey_with(i, per));
    up.push_back(subkey_with(full_subkeys, rest));
    std::size_t calls = 0;
    const auto at_cap = build_map(up, std::nullopt, &calls);
    CHECK_FALSE(at_cap.over_cap);
    CHECK(calls == up.size());
    CHECK_FALSE(at_cap.by_product.empty());

    // one name more: every token is empty and the builder tells the walk to stop at that subkey
    up.push_back(subkey_with(full_subkeys + 1, 1));
    // (that subkey is the one past the cap; further subkeys must never be asked for)
    up.push_back(subkey_with(full_subkeys + 2, per));
    calls = 0;
    const auto over = build_map(up, std::nullopt, &calls);
    CHECK(over.over_cap);
    CHECK(calls == full_subkeys + 2);
    CHECK(over.failure == std::string{rec::kTokenUpgradeMapOverCap});
    CHECK(over.by_product.empty()); // even the products read before the cap
    CHECK_FALSE(over.resolve("{00000000-0000-0000-0000-000000000000}").has_value());
}

TEST_CASE("installer records: an absent UpgradeCodes key is an empty map; a read fault is a failure token",
          "[msi_packages][installer_records]") {
    // absent: the walk ends with nothing and no token
    const auto none = build_map({});
    CHECK_FALSE(none.failure.has_value());
    CHECK(*none.resolve(kPythonLauncher) == "");

    // a fault mid-walk: no partial map is served, and every lookup reports the fault so the
    // roster is constrained rather than carrying tokens a fault emptied
    const auto fx = load_fixture();
    const auto map = build_map(fx.upgrades, rec::upgrade_map_failure_token(5));
    REQUIRE(map.failure.has_value());
    CHECK(*map.failure == "windows:msi_upgrade_map:5");
    CHECK(map.by_product.empty());
    const auto got = map.resolve(kPythonLauncher);
    REQUIRE_FALSE(got.has_value());
    CHECK(got.error() == "windows:msi_upgrade_map:5");
}

TEST_CASE("installer records: no Installer API that could repair, install or run code is named",
          "[msi_packages][installer_records]") {
    constexpr std::string_view kForbidden[] = {
        "MsiOpenPackage", "MsiOpenProduct", "MsiConfigure",   "MsiReinstall", "MsiProvide",
        "MsiInstall",     "MsiApplyPatch",  "MsiDoAction",    "MsiSequence",
    };
    const auto hits = [&](std::string_view text) {
        std::vector<std::string> found;
        for (const auto name : kForbidden)
            if (text.find(name) != std::string_view::npos)
                found.emplace_back(name);
        return found;
    };

    // the scanner finds what it is looking for (a check that cannot fail checks nothing)
    CHECK(hits("rc = MsiConfigureProductExW(code, 0, state, cmd);") ==
          std::vector<std::string>{"MsiConfigure"});
    CHECK(hits("MsiOpenPackageW and MsiDoAction").size() == 2);
    CHECK(hits("MsiOpenDatabaseW MsiGetProductInfoExW MsiEnumProductsExW").empty());

    const fs::path plugins{YUZU_PLUGIN_SRC_DIR};
    const fs::path files[] = {
        plugins / "msi_packages" / "src" / "msi_packages_plugin.cpp",
        plugins / "msi_packages" / "src" / "msi_installer_records.hpp",
        plugins / ".." / "core" / "src" / "msi_database_read.cpp",
        plugins / ".." / "core" / "include" / "yuzu" / "agent" / "msi_database_read.hpp",
    };
    for (const auto& f : files) {
        INFO(f.string());
        const auto text = slurp(f);
        REQUIRE_FALSE(text.empty());
        CHECK(hits(text).empty());
    }
}
