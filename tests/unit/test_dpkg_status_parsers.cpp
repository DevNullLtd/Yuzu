/**
 * test_dpkg_status_parsers.cpp -- the dpkg status text parser
 * (agents/shared/dpkg_status_parsers.hpp, SAM-45).
 *
 * The parser is pure: the text goes in, the packages come out, so every case runs on every host.
 *
 * Fixture provenance:
 *   - "real capture": tests/unit/fixtures/software-estate/pkgdb/{debian12,ubuntu2404}/status are
 *     verbatim stanzas of the S-7 captures' /var/lib/dpkg/status (Debian 12, dpkg 1.21.23, and
 *     Ubuntu 24.04, dpkg 1.22.6, run in arm64 containers on 2026-11-19), each with the capture's
 *     own `dpkg-query -W` output (inventory.tsv, list.txt) beside it, bytes unchanged.
 *     tests/unit/fixtures/software-estate/pkgdb/provenance.txt has the commands.
 *   - "edited real stanza": a real stanza with ONE line changed in memory. A fresh container has
 *     no half-installed, unpacked, config-files or held package, so those states are built by
 *     editing the Status line of a real stanza and every such case says "edited" in its name.
 *   - everything else is a hostile string built in memory.
 */

#include <catch2/catch_test_macros.hpp>

#include <dpkg_status_parsers.hpp>

#include <cstddef>
#include <filesystem>
#include <fstream>
#include <iterator>
#include <map>
#include <sstream>
#include <string>
#include <string_view>
#include <vector>

using namespace yuzu::shared;
namespace fs = std::filesystem;

namespace {

std::string read_text(const fs::path& p) {
    REQUIRE(fs::exists(p));
    std::ifstream f(p, std::ios::binary);
    REQUIRE(f.is_open());
    return std::string(std::istreambuf_iterator<char>(f), std::istreambuf_iterator<char>());
}

fs::path pkgdb_fixture(std::string_view capture, std::string_view file) {
    return fs::path{YUZU_TEST_FIXTURE_DIR} / "software-estate" / "pkgdb" / capture / file;
}

PkgDbBudget generous() {
    PkgDbBudget b;
    b.rows_left = 50000;
    b.bytes_left = 1ull << 30;
    return b;
}

std::vector<std::string> split(const std::string& s, char sep) {
    std::vector<std::string> out;
    std::string cur;
    std::istringstream ss(s);
    while (std::getline(ss, cur, sep))
        out.push_back(cur);
    return out;
}

std::vector<std::string> lines_of(const std::string& text) {
    std::vector<std::string> out;
    std::istringstream ss(text);
    std::string line;
    while (std::getline(ss, line))
        if (!line.empty())
            out.push_back(line);
    return out;
}

// The stanza of `name` in `status`, as a string (without its blank-line terminator).
std::string stanza_of(const std::string& status, std::string_view name) {
    const std::string key = "Package: " + std::string{name} + "\n";
    const std::size_t at = status.find(key);
    REQUIRE(at != std::string::npos);
    REQUIRE((at == 0 || status[at - 1] == '\n'));
    const std::size_t end = status.find("\n\n", at);
    return status.substr(at, end == std::string::npos ? std::string::npos : end - at);
}

// `stanza` with its Status line replaced.
std::string with_status(std::string stanza, std::string_view status_value) {
    const std::size_t at = stanza.find("\nStatus: ");
    REQUIRE(at != std::string::npos);
    const std::size_t eol = stanza.find('\n', at + 1);
    stanza.replace(at + 1, (eol == std::string::npos ? stanza.size() : eol) - (at + 1),
                   "Status: " + std::string{status_value});
    return stanza;
}

} // namespace

TEST_CASE("dpkg status: real debian12 and ubuntu2404 captures parse to the capture's own dpkg-query "
          "fields",
          "[dpkg][pkgdb]") {
    for (const char* capture : {"debian12", "ubuntu2404"}) {
        INFO(capture);
        const auto status = read_text(pkgdb_fixture(capture, "status"));
        auto b = generous();
        auto parsed = parse_dpkg_status(status, b);
        REQUIRE(parsed.has_value());

        // inventory.tsv: ${Package} \t ${db:Status-Abbrev} \t ${Version} \t ${Architecture} \t ${Maintainer}
        const auto inv = lines_of(read_text(pkgdb_fixture(capture, "inventory.tsv")));
        // list.txt: ${Package}|${Version}|${Maintainer}|${Status}
        const auto list = lines_of(read_text(pkgdb_fixture(capture, "list.txt")));
        REQUIRE(parsed->size() == inv.size());
        REQUIRE(parsed->size() == list.size());

        std::map<std::string, const DpkgPackage*> by_name;
        for (const auto& p : *parsed)
            by_name[p.name] = &p;
        REQUIRE(by_name.size() == parsed->size());

        for (const auto& line : inv) {
            const auto f = split(line, '\t');
            REQUIRE(f.size() == 5);
            const auto it = by_name.find(f[0]);
            REQUIRE(it != by_name.end());
            const DpkgPackage& p = *it->second;
            CHECK(p.version == f[2]);
            CHECK(p.architecture == f[3]);
            CHECK(p.maintainer == f[4]);
            // Status-Abbrev is <want><state><flag-or-space>; for these installed packages "ii ".
            CHECK(f[1] == "ii ");
            CHECK(p.status == "installed");
        }
        for (const auto& line : list) {
            const auto f = split(line, '|');
            REQUIRE(f.size() == 4);
            const DpkgPackage& p = *by_name.at(f[0]);
            CHECK(p.version == f[1]);
            CHECK(p.maintainer == f[2]);
            CHECK(p.want + " " + p.flag + " " + p.status == f[3]);
        }
    }
}

TEST_CASE("dpkg status: real captures carry epoch, Architecture all, Conffiles and Essential",
          "[dpkg][pkgdb]") {
    // The fixture selection is the coverage claim: assert the stanzas it was chosen for are there.
    const auto status = read_text(pkgdb_fixture("debian12", "status"));
    auto b = generous();
    auto parsed = parse_dpkg_status(status, b);
    REQUIRE(parsed.has_value());
    bool epoch = false, all_arch = false;
    for (const auto& p : *parsed) {
        epoch = epoch || p.version.find(':') != std::string::npos;
        all_arch = all_arch || p.architecture == "all";
    }
    CHECK(epoch);
    CHECK(all_arch);
    CHECK(status.find("\nConffiles:\n /") != std::string::npos);
    CHECK(status.find("\nEssential: yes\n") != std::string::npos);
}

TEST_CASE("dpkg status: continuation lines never leak into a field", "[dpkg][pkgdb]") {
    // debconf carries a multi-line Description and Conffiles. A continuation that LOOKS like a field
    // line (leading space) must neither override the real field nor count as a duplicate.
    const auto status = read_text(pkgdb_fixture("debian12", "status"));
    std::string s = stanza_of(status, "debconf");
    s += "\n Version: 99.99\n Status: purge ok installed\n\tMaintainer: Mallory <m@example.org>\n";
    auto b = generous();
    auto parsed = parse_dpkg_status(s + "\n\n", b);
    REQUIRE(parsed.has_value());
    REQUIRE(parsed->size() == 1);
    const DpkgPackage& p = parsed->front();
    CHECK(p.name == "debconf");
    CHECK(p.version == "1.5.82");
    CHECK(p.status == "installed");
    CHECK(p.maintainer == "Debconf Developers <debconf-devel@lists.alioth.debian.org>");
}

TEST_CASE("dpkg status: a file without a trailing blank line still yields its last stanza",
          "[dpkg][pkgdb]") {
    auto status = read_text(pkgdb_fixture("ubuntu2404", "status"));
    auto b1 = generous();
    const auto full = parse_dpkg_status(status, b1);
    REQUIRE(full.has_value());
    while (!status.empty() && status.back() == '\n')
        status.pop_back();
    auto b2 = generous();
    const auto cut = parse_dpkg_status(status, b2);
    REQUIRE(cut.has_value());
    CHECK(cut->size() == full->size());
    CHECK(cut->back().name == full->back().name);
    CHECK(cut->back().maintainer == full->back().maintainer);
}

TEST_CASE("dpkg status: CRLF line ends and '#' comment lines are tolerated", "[dpkg][pkgdb]") {
    auto b = generous();
    auto parsed = parse_dpkg_status(
        "# a comment between stanzas is skipped\r\nPackage: a\r\nStatus: install ok installed\r\n"
        "Version: 1\r\n# and inside one\r\n\r\nPackage: b\nStatus: install ok installed\n",
        b);
    REQUIRE(parsed.has_value());
    REQUIRE(parsed->size() == 2);
    CHECK((*parsed)[0].name == "a");
    CHECK((*parsed)[0].version == "1");
    CHECK((*parsed)[1].name == "b");
}

TEST_CASE("dpkg status: field names match case-insensitively and values are trimmed", "[dpkg][pkgdb]") {
    auto b = generous();
    auto parsed = parse_dpkg_status("package:   x  \nSTATUS: install ok installed\nMAINTAINER:\t Me <m@x> \t\n", b);
    REQUIRE(parsed.has_value());
    REQUIRE(parsed->size() == 1);
    CHECK(parsed->front().name == "x");
    CHECK(parsed->front().maintainer == "Me <m@x>");
}

TEST_CASE("dpkg status: edited real stanza keeps every state word (half-installed, unpacked, "
          "half-configured, triggers-pending, config-files, hold, reinstreq)",
          "[dpkg][pkgdb]") {
    // EDITED: the Status line of the real debian12 libacl1 stanza is replaced.
    const auto status = read_text(pkgdb_fixture("debian12", "status"));
    const std::string base = stanza_of(status, "libacl1");
    struct Case {
        const char* status;
        const char* want;
        const char* flag;
        const char* state;
    };
    for (const Case& c : {Case{"install ok half-installed", "install", "ok", "half-installed"},
                          Case{"install ok unpacked", "install", "ok", "unpacked"},
                          Case{"install ok half-configured", "install", "ok", "half-configured"},
                          Case{"install ok triggers-pending", "install", "ok", "triggers-pending"},
                          Case{"deinstall ok config-files", "deinstall", "ok", "config-files"},
                          Case{"hold ok installed", "hold", "ok", "installed"},
                          Case{"install reinstreq installed", "install", "reinstreq", "installed"},
                          Case{"deinstall ok installed", "deinstall", "ok", "installed"}}) {
        INFO(c.status);
        auto b = generous();
        auto parsed = parse_dpkg_status(with_status(base, c.status) + "\n\n", b);
        REQUIRE(parsed.has_value());
        REQUIRE(parsed->size() == 1);
        CHECK(parsed->front().name == "libacl1");
        CHECK(parsed->front().want == c.want);
        CHECK(parsed->front().flag == c.flag);
        CHECK(parsed->front().status == c.state);
    }
}

TEST_CASE("dpkg status: edited real stanza with not-installed is skipped", "[dpkg][pkgdb]") {
    const auto status = read_text(pkgdb_fixture("debian12", "status"));
    const std::string removed = with_status(stanza_of(status, "libacl1"), "purge ok not-installed");
    const std::string kept = stanza_of(status, "libattr1");
    auto b = generous();
    auto parsed = parse_dpkg_status(removed + "\n\n" + kept + "\n\n", b);
    REQUIRE(parsed.has_value());
    REQUIRE(parsed->size() == 1);
    CHECK(parsed->front().name == "libattr1");
}

TEST_CASE("dpkg status: hostile text is corrupt, never partial", "[dpkg][pkgdb]") {
    const std::string ok = "Package: a\nStatus: install ok installed\n";
    const auto corrupt = [](std::string_view text, const char* why) {
        INFO(why);
        auto b = generous();
        const auto r = parse_dpkg_status(text, b);
        REQUIRE_FALSE(r.has_value());
        CHECK(r.error() == PkgDbCause::corrupt);
    };
    corrupt(std::string("Package: a\0b\nStatus: install ok installed\n", 42), "a NUL byte");
    corrupt(ok + "this line has no colon\n", "a line without a colon");
    corrupt(ok + ": value with no name\n", "an empty field name");
    corrupt("Status: install ok installed\nVersion: 1\n", "a stanza without Package");
    corrupt("Package: \nStatus: install ok installed\n", "an empty Package");
    corrupt(ok + "Status: install ok installed\n", "a duplicate Status");
    corrupt(ok + "Package: b\n", "a duplicate Package");
    corrupt("Package: a\nStatus: install installed\n", "a two-word Status");
    corrupt("Package: a\nStatus: install ok installed extra\n", "a four-word Status");
    corrupt("Package: a\nStatus: install  ok installed\n", "a double space in Status");
    corrupt("Package: a\nStatus: install\tok installed\n", "a tab inside Status");
    corrupt("Package: a\nVersion: 1\n", "a stanza without Status");
    corrupt(" continuation first\nPackage: a\nStatus: install ok installed\n",
            "a continuation before any field");
    // A good stanza before a bad one does not survive: the whole answer is refused.
    corrupt(ok + "\nVersion: 1\n", "a second stanza without Package");
}

TEST_CASE("dpkg status: row cap, expired clock and empty input", "[dpkg][pkgdb]") {
    const std::string two = "Package: a\nStatus: install ok installed\n\nPackage: b\nStatus: install ok installed\n";
    {
        PkgDbBudget b = generous();
        b.rows_left = 1;
        const auto r = parse_dpkg_status(two, b);
        REQUIRE_FALSE(r.has_value());
        CHECK(r.error() == PkgDbCause::row_cap);
    }
    {
        // Exactly the cap is admitted; the next stanza is refused.
        PkgDbBudget b = generous();
        b.rows_left = 2;
        CHECK(parse_dpkg_status(two, b).has_value());
    }
    {
        // A skipped (not-installed) stanza costs a row too.
        PkgDbBudget b = generous();
        b.rows_left = 1;
        const auto r = parse_dpkg_status("Package: a\nStatus: purge ok not-installed\n\n" + two, b);
        REQUIRE_FALSE(r.has_value());
        CHECK(r.error() == PkgDbCause::row_cap);
    }
    {
        // The clock is read every 256 stanzas: a long text with an expired budget returns timeout.
        std::string many;
        for (int i = 0; i < 300; ++i)
            many += "Package: p" + std::to_string(i) + "\nStatus: install ok installed\n\n";
        PkgDbBudget b = generous();
        b.expired = [] { return true; };
        const auto r = parse_dpkg_status(many, b);
        REQUIRE_FALSE(r.has_value());
        CHECK(r.error() == PkgDbCause::timeout);
    }
    {
        PkgDbBudget b = generous();
        const auto r = parse_dpkg_status("", b);
        REQUIRE(r.has_value());
        CHECK(r->empty());
        const auto blank = parse_dpkg_status("\n\n\n", b);
        REQUIRE(blank.has_value());
        CHECK(blank->empty());
    }
}

TEST_CASE("dpkg status.d merge: the status entry wins; a multi-arch sibling is not a duplicate",
          "[dpkg][pkgdb]") {
    std::vector<DpkgPackage> status{{"libc6", "2.36", "amd64", "M", "install", "ok", "installed"},
                                    {"bash", "5.2", "amd64", "M", "install", "ok", "installed"}};
    std::vector<DpkgPackage> status_d{{"bash", "9.9", "amd64", "Other", "install", "ok", "installed"},
                                      {"libc6", "2.36", "i386", "M", "install", "ok", "installed"},
                                      {"only-here", "1", "all", "M", "install", "ok", "installed"},
                                      {"only-here", "2", "all", "M", "install", "ok", "installed"}};
    merge_dpkg_status_d(status, std::move(status_d));
    REQUIRE(status.size() == 4);
    CHECK(status[1].name == "bash");
    CHECK(status[1].version == "5.2"); // the status entry, not the status.d one
    CHECK(status[2].architecture == "i386");
    CHECK(status[3].name == "only-here");
    CHECK(status[3].version == "1"); // first occurrence within status.d
}
