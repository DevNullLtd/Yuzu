// Pure tests for the software-title alias pack parser (SAM.4): header directive,
// edition-bearing alias keys, validation errors, and the embedded seed contract.
// No database, no I/O.

#include <catch2/catch_test_macros.hpp>

#include "software_normalization_pack.hpp"

#include <algorithm>
#include <iterator>
#include <map>
#include <set>
#include <string>
#include <tuple>

using namespace yuzu::server;

namespace {

// A syntactically valid pack body of `rows` distinct rows (the parser's row floor is
// kMinSeedRows), plus any extra lines appended by the caller.
std::string pack(const std::string& version_line, const std::string& extra = {},
                 std::size_t rows = kMinSeedRows) {
    std::string out = version_line + "\n";
    for (std::size_t i = 0; i < rows; ++i)
        out += "rpm,filler" + std::string(1, static_cast<char>('a' + i / 26)) +
               std::string(1, static_cast<char>('a' + i % 26)) +
               ",,Acme,Filler,,other,\n";
    return out + extra;
}

const std::string kV = "#pack_version: 2026.11.1";

// `n` distinct, mutually consistent rows (one product, many aliases).
std::string many_rows(std::size_t n) {
    std::string out;
    for (std::size_t i = 0; i < n; ++i)
        out += "rpm,filler" + std::to_string(i) + ",,Acme,Filler,,other,\n";
    return out;
}

// The parse error of `csv`, or "" when it parsed.
std::string error_of(const std::string& csv) {
    const auto p = parse_normalization_pack(csv);
    return p ? std::string{} : p.error();
}

bool contains(const std::string& haystack, const char* needle) {
    return haystack.find(needle) != std::string::npos;
}

} // namespace

TEST_CASE("parse accepts the header directive and eight fields and normalises keys",
          "[normalization][pack]") {
    const auto p = parse_normalization_pack(
        pack(kV, "windows,7-Zip 23.01 (x64),Igor Pavlov Inc.,Igor Pavlov,7-Zip,,other,7-zip\n"));
    REQUIRE(p.has_value());
    CHECK(p->pack_version == "2026.11.1");
    CHECK(p->sha256.size() == 64);
    const auto it = std::find_if(p->rows.begin(), p->rows.end(),
                                 [](const PackRow& r) { return r.raw_name == "7-zip"; });
    REQUIRE(it != p->rows.end());
    CHECK(it->ecosystem == "windows");
    CHECK(it->raw_publisher == normalize_vendor("Igor Pavlov Inc."));
    CHECK(it->vendor == "igor pavlov");
    CHECK(it->title == "7-zip");
    CHECK(it->cpe_product == "7-zip");
    CHECK(it->norm_key == "igor pavlov:7-zip");
}

TEST_CASE("parse derives an edition-bearing alias key and alias_key is idempotent",
          "[normalization][pack]") {
    const auto p = parse_normalization_pack(pack(
        kV, "windows,Microsoft SQL Server 2019 Standard (x64),,Microsoft,SQL Server,,database,\n"
            "windows,Microsoft SQL Server 2017 Enterprise,,Microsoft,SQL Server,,database,\n"));
    REQUIRE(p.has_value());
    const auto find = [&](const std::string& key) {
        return std::find_if(p->rows.begin(), p->rows.end(),
                            [&](const PackRow& r) { return r.raw_name == key; });
    };
    const auto std_row = find("microsoft sql server standard");
    const auto ent_row = find("microsoft sql server enterprise");
    REQUIRE(std_row != p->rows.end());
    REQUIRE(ent_row != p->rows.end());
    CHECK(std_row->edition == "standard");
    CHECK(std_row->norm_key == "microsoft:sql server:standard");
    CHECK(ent_row->norm_key == "microsoft:sql server:enterprise"); // distinct SKUs, distinct products

    // Idempotence: re-normalising a key reproduces it.
    for (const auto& r : p->rows) {
        CAPTURE(r.raw_name);
        CHECK(alias_key(normalize_title(r.raw_name)) == r.raw_name);
    }
}

TEST_CASE("parse rejects an edition column that contradicts raw_name and accepts an editionless "
          "raw_name with an edition column",
          "[normalization][pack]") {
    const auto bad = parse_normalization_pack(
        pack(kV, "windows,Microsoft SQL Server 2019 Standard,,Microsoft,SQL Server,enterprise,"
                 "database,\n"));
    REQUIRE_FALSE(bad.has_value());
    CHECK(bad.error().find("edition contradicts raw_name") != std::string::npos);

    const auto ok = parse_normalization_pack(
        pack(kV, "windows,Microsoft Office,,Microsoft,Office,professional,other,\n"));
    REQUIRE(ok.has_value());
    const auto it = std::find_if(ok->rows.begin(), ok->rows.end(),
                                 [](const PackRow& r) { return r.raw_name == "microsoft office"; });
    REQUIRE(it != ok->rows.end());
    CHECK(it->edition == "professional");
    CHECK(it->norm_key == "microsoft:office:professional");

    CHECK(contains(error_of(pack(kV, "windows,Foo,,Acme,Foo,gold,other,\n")),
                   "edition is not a recognised edition token"));
}

TEST_CASE("an edition column is parsed as an edition, and a lone edition word as a raw_name is a "
          "title",
          "[normalization][pack]") {
    // The edition column takes an edition word on its own, though normalize_title would now read
    // a leading edition word as a title word.
    for (const char* edition : {"Pro", "Home", "Standard", "Enterprise x64"}) {
        CAPTURE(edition);
        const auto p = parse_normalization_pack(pack(
            kV, std::string{"windows,Contoso Studio,,Contoso,Studio,"} + edition + ",other,\n"));
        REQUIRE(p.has_value());
        const auto it = std::find_if(p->rows.begin(), p->rows.end(), [](const PackRow& r) {
            return r.raw_name == "contoso studio";
        });
        REQUIRE(it != p->rows.end());
        CHECK(it->edition == normalize_edition(edition));
        CHECK(it->norm_key == "contoso:studio:" + it->edition);
    }
    // A raw_name that is one edition word names a product ("Home"), not an empty title.
    const auto home = parse_normalization_pack(pack(kV, "macos,Home,,Apple,Home,,other,\n"));
    REQUIRE(home.has_value());
    const auto it = std::find_if(home->rows.begin(), home->rows.end(),
                                 [](const PackRow& r) { return r.raw_name == "home"; });
    REQUIRE(it != home->rows.end());
    CHECK(it->edition.empty());
    CHECK(it->norm_key == "apple:home");
    // The column still refuses any word that is no edition.
    CHECK(contains(error_of(pack(kV, "windows,Foo,,Acme,Foo,Pro Display,other,\n")),
                   "edition is not a recognised edition token"));
}

TEST_CASE("parse rejects a missing or malformed pack_version directive", "[normalization][pack]") {
    CHECK(contains(error_of(pack("# no directive")), "missing #pack_version"));
    CHECK(contains(error_of(pack("#pack_version: 2026.1.1")), "YYYY.MM.N"));
    CHECK(contains(error_of(pack("#pack_version: v1")), "YYYY.MM.N"));
    // The month is 01-12.
    CHECK(contains(error_of(pack("#pack_version: 2026.13.1")), "YYYY.MM.N"));
    CHECK(contains(error_of(pack("#pack_version: 2026.00.1")), "YYYY.MM.N"));
    CHECK(parse_normalization_pack(pack("#pack_version: 2026.12.7")).has_value());
    CHECK(parse_normalization_pack(pack("#pack_version: 2026.01.10")).has_value());
    const auto twice = parse_normalization_pack(pack(kV, "#pack_version: 2026.11.2\n"));
    REQUIRE_FALSE(twice.has_value());
    CHECK(twice.error().find("duplicate") != std::string::npos);
}

TEST_CASE("parse rejects a row with the wrong field count", "[normalization][pack]") {
    const auto few = parse_normalization_pack(pack(kV, "windows,Foo,,Acme,Foo,,other\n"));
    REQUIRE_FALSE(few.has_value());
    CHECK(few.error().find("8 fields") != std::string::npos);
    CHECK(contains(error_of(pack(kV, "windows,Foo,,Acme,Foo,,other,x,extra\n")), "8 fields"));
    CHECK(contains(error_of(pack(kV, "windows,\"Foo\",,Acme,Foo,,other,\n")),
                   "double quotes are not allowed"));
}

TEST_CASE("parse rejects an unknown category and an unknown ecosystem", "[normalization][pack]") {
    CHECK(contains(error_of(pack(kV, "windows,Foo,,Acme,Foo,,gadget,\n")), "unknown category"));
    CHECK(contains(error_of(pack(kV, "plan9,Foo,,Acme,Foo,,other,\n")), "unknown ecosystem"));
    CHECK(contains(error_of(pack(kV, "windows,Foo,,Acme,Foo,,other,BAD TOKEN\n")),
                   "cpe_product has an invalid character"));
    // An empty category defaults to other.
    const auto ok = parse_normalization_pack(pack(kV, "windows,Foo,,Acme,Foo,,,\n"));
    REQUIRE(ok.has_value());
    CHECK(ok->rows.back().category == "other");
}

TEST_CASE("parse rejects a duplicate normalised key", "[normalization][pack]") {
    const auto dup = parse_normalization_pack(
        pack(kV, "windows,Foo 1.0,,Acme,Foo,,other,\nwindows,Foo 2.0 (x64),,Acme,Foo,,other,\n"));
    REQUIRE_FALSE(dup.has_value());
    CHECK(dup.error().find("duplicate") != std::string::npos);
    // Same name under another ecosystem or publisher is a different key.
    CHECK(parse_normalization_pack(
              pack(kV, "windows,Foo,,Acme,Foo,,other,\nmacos,Foo,,Acme,Foo,,other,\n"
                       "windows,Foo,Acme,Acme,Foo,,other,\n"))
              .has_value());
}

TEST_CASE("parse rejects fewer than kMinSeedRows rows", "[normalization][pack]") {
    const auto thin = parse_normalization_pack(pack(kV, {}, kMinSeedRows - 1));
    REQUIRE_FALSE(thin.has_value());
    CHECK(thin.error().find("kMinSeedRows") != std::string::npos);
    CHECK(parse_normalization_pack(pack(kV, {}, kMinSeedRows)).has_value());
}

TEST_CASE("parse accepts CRLF line endings and a missing trailing newline",
          "[normalization][pack]") {
    std::string crlf;
    for (const char c : pack(kV))
        crlf += (c == '\n') ? std::string{"\r\n"} : std::string{c};
    CHECK(error_of(crlf).empty());
    std::string no_newline = pack(kV, "windows,Foo,,Acme,Foo,,other,");
    CHECK(error_of(no_newline).empty());
}

TEST_CASE("parse rejects a UTF-8 byte order mark and empty input and a NUL byte",
          "[normalization][pack]") {
    // The BOM hides the directive from the line start, so the first line is a one-field row.
    const std::string bom = error_of("\xEF\xBB\xBF" + pack(kV));
    CHECK(contains(bom, "line 1"));
    CHECK(contains(bom, "8 fields"));
    CHECK(contains(error_of(""), "missing #pack_version"));
    // A NUL anywhere, including inside a comment, rejects the whole pack.
    std::string nul = pack(kV, "# comment");
    nul.push_back('\0');
    CHECK(contains(error_of(nul), "NUL"));
    std::string field_nul = "windows,Fo";
    field_nul.push_back('\0');
    field_nul += "o,,Acme,Foo,,other,\n";
    CHECK(contains(error_of(pack(kV, field_nul)), "NUL"));
}

TEST_CASE("parse enforces the byte and row and field caps and accepts the exact limit",
          "[normalization][pack]") {
    // Rows: exactly kMaxPackRows parses, one more is refused with its line number.
    CHECK(error_of(kV + "\n" + many_rows(kMaxPackRows)).empty());
    const std::string too_many = error_of(kV + "\n" + many_rows(kMaxPackRows + 1));
    CHECK(contains(too_many, "kMaxPackRows"));
    CHECK(contains(too_many, "line "));

    // Field: kMaxFieldBytes bytes parses, one more is refused.
    const auto with_name = [](std::size_t n) {
        return pack(kV, "windows," + std::string(n, 'a') + ",,Acme,Foo,,other,\n");
    };
    CHECK(error_of(with_name(kMaxFieldBytes)).empty());
    CHECK(contains(error_of(with_name(kMaxFieldBytes + 1)), "kMaxFieldBytes"));

    // Bytes: refused before any line is read (comment padding makes the size exceed the cap).
    std::string big = pack(kV);
    big += "#" + std::string(kMaxPackBytes, 'x') + "\n";
    CHECK(contains(error_of(big), "kMaxPackBytes"));
}

TEST_CASE("parse rejects the CPE logical-value placeholders as cpe_product",
          "[normalization][pack]") {
    CHECK(contains(error_of(pack(kV, "windows,Foo,,Acme,Foo,,other,-\n")), "reserved placeholder"));
    CHECK(contains(error_of(pack(kV, "windows,Foo,,Acme,Foo,,other,.\n")), "reserved placeholder"));
    // Ordinary tokens containing those characters stay valid.
    CHECK(error_of(pack(kV, "windows,Foo,,Acme,Foo,,other,a-b.c\n")).empty());
}

TEST_CASE("parse rejects two rows for one product that disagree on category or cpe_product",
          "[normalization][pack]") {
    const std::string cat =
        error_of(pack(kV, "windows,Foo,,Acme,Foo,,database,foo\nmacos,Foo,,Acme,Foo,,other,foo\n"));
    CHECK(contains(cat, "norm_key shared with a different category or cpe_product"));
    CHECK(contains(cat, "line "));
    CHECK(contains(error_of(pack(kV, "windows,Foo,,Acme,Foo,,other,foo\nmacos,Foo,,Acme,Foo,,other,"
                                     "bar\n")),
                   "norm_key shared with a different category or cpe_product"));
    // Agreeing rows (many aliases, one product) and different editions of one title are fine.
    CHECK(error_of(pack(kV, "windows,Foo,,Acme,Foo,,other,foo\nmacos,Foo,,Acme,Foo,,other,foo\n"
                            "windows,Foo Pro,,Acme,Foo,,database,foo\n"))
              .empty());
}

TEST_CASE("purl_type_for maps package ecosystems and leaves app ecosystems empty",
          "[normalization][pack]") {
    CHECK(purl_type_for("rpm") == "rpm");
    CHECK(purl_type_for("deb") == "deb");
    CHECK(purl_type_for("apk") == "apk");
    CHECK(purl_type_for("pacman") == "alpm");
    CHECK(purl_type_for("brew") == "brew");
    for (const char* eco : {"windows", "msi", "macos", "macos_pkgutil", "snap", "flatpak",
                            "optional_feature", ""})
        CHECK(purl_type_for(eco).empty());
}

TEST_CASE("the embedded seed parses with the shipped version and every key in normal form",
          "[normalization][pack]") {
    const auto p = parse_normalization_pack(kSoftwareNormalizationSeed);
    REQUIRE(p.has_value());
    CHECK(p->pack_version == "2026.11.2");
    CHECK(p->rows.size() >= kMinSeedRows);
    // Idempotence only: the parser already stores alias_key(normalize_title(raw_name)), so this
    // shows a stored key survives a second normalisation. It cannot see a re-key; the pinned
    // list in the next test case does.
    for (const auto& r : p->rows) {
        CAPTURE(r.raw_name);
        CHECK(alias_key(normalize_title(r.raw_name)) == r.raw_name);
    }
}

namespace {
// The stored alias key of every seed row, as `ecosystem|alias key|alias publisher|product
// norm_key` (an empty ecosystem or publisher is a wildcard). An added seed row adds one line
// here. A changed line is a re-key: an install that holds a pack never applies a newer seed row,
// so the old alias stops resolving until an operator reloads a pack, and the change needs an
// upgrade note in docs/user-manual/upgrading.md.
const char* const kPinnedSeedKeys[] = {
    "|openssl||openssl:openssl",
    "|openssh-server||openbsd:openssh",
    "|openssh-client||openbsd:openssh",
    "|curl||curl:curl",
    "|libssl3||openssl:openssl",
    "|libssl1.1||openssl:openssl",
    "|libcurl4||curl:curl",
    "|bash||gnu:bash",
    "|glibc||gnu:glibc",
    "|libc6||gnu:glibc",
    "|sudo||sudo_project:sudo",
    "|nginx||nginx:nginx",
    "|wget||gnu:wget",
    "|apache2||apache:http server",
    "|httpd||apache:http server",
    "|tomcat9||apache:tomcat",
    "|tomcat10||apache:tomcat",
    "|postgresql||postgresql:postgresql",
    "|postgresql-server||postgresql:postgresql",
    "|postgresql-18||postgresql:postgresql",
    "|mariadb-server||mariadb:mariadb",
    "|mysql-server||oracle:mysql",
    "|redis-server||redis:redis",
    "|rabbitmq-server||rabbitmq:rabbitmq",
    "|mosquitto||eclipse:mosquitto",
    "|python3||python:python",
    "|python3.14||python:python",
    "|nodejs||openjs:node.js",
    "|git||git-scm:git",
    "windows|7-zip||igor pavlov:7-zip",
    "windows|notepad++||notepad++ team:notepad++",
    "windows|mozilla firefox en-us)||mozilla:firefox",
    "windows|mozilla thunderbird en-us)||mozilla:thunderbird",
    "windows|google chrome||google:chrome",
    "windows|microsoft edge||microsoft:edge",
    "windows|adobe acrobat reader dc||adobe:acrobat reader dc",
    "windows|vlc media player||videolan:vlc media player",
    "windows|git||git-scm:git",
    "windows|python||python:python",
    "windows|java(tm) se development kit||oracle:jdk",
    "windows|java update||oracle:jre",
    "windows|microsoft .net runtime||microsoft:.net runtime",
    "windows|microsoft .net sdk||microsoft:.net sdk",
    "windows|node.js||openjs:node.js",
    "windows|postgresql||postgresql:postgresql",
    "windows|mysql server||oracle:mysql",
    "windows|mariadb||mariadb:mariadb",
    "windows|mongodb||mongodb:mongodb",
    "windows|microsoft sql server standard||microsoft:sql server:standard",
    "windows|microsoft sql server enterprise||microsoft:sql server:enterprise",
    "windows|microsoft sql server express||microsoft:sql server:express",
    "windows|visual studio community||microsoft:visual studio:community",
    "windows|visual studio professional||microsoft:visual studio:professional",
    "windows|visual studio enterprise||microsoft:visual studio:enterprise",
    "windows|microsoft office plus professional||microsoft:office:professional",
    "windows|zoom workplace||zoom:zoom",
    "windows|winrar||win.rar:winrar",
    "windows|wireshark||wireshark:wireshark",
    "windows|putty release||simon tatham:putty",
    "windows|filezilla client||tim kosse:filezilla",
    "windows|docker desktop||docker:docker desktop",
    "windows|oracle vm virtualbox||oracle:virtualbox",
    "windows|vmware workstation||vmware:workstation",
    "windows|libreoffice||libreoffice:libreoffice",
    "macos|firefox||mozilla:firefox",
    "macos|google chrome||google:chrome",
    "macos|safari||apple:safari",
    "macos|visual studio code||microsoft:visual studio code",
    "macos|docker||docker:docker desktop",
    "brew|nginx||nginx:nginx",
    "brew|redis||redis:redis",
    "brew|git||git-scm:git",
    "brew|wget||gnu:wget",
    "brew|curl||curl:curl",
    "brew|node||openjs:node.js",
    "brew|openssl||openssl:openssl",
};
} // namespace

TEST_CASE("the embedded seed's stored alias keys are exactly the pinned ones",
          "[normalization][pack]") {
    const auto p = parse_normalization_pack(kSoftwareNormalizationSeed);
    REQUIRE(p.has_value());
    std::set<std::string> got;
    for (const auto& r : p->rows)
        got.insert(r.ecosystem + '|' + r.raw_name + '|' + r.raw_publisher + '|' + r.norm_key);
    const std::set<std::string> want(std::begin(kPinnedSeedKeys), std::end(kPinnedSeedKeys));
    CHECK(got.size() == p->rows.size()); // no two rows fold into one entry
    CHECK(want.size() == std::size(kPinnedSeedKeys)); // the list holds no duplicate
    for (const auto& k : got) {
        CAPTURE(k);
        CHECK(want.count(k) == 1); // a re-keyed row, or a seed row with no line above
    }
    for (const auto& k : want) {
        CAPTURE(k);
        CHECK(got.count(k) == 1); // a pinned line the seed no longer produces
    }
}

TEST_CASE("the embedded seed gives every product ONE identity", "[normalization][pack]") {
    const auto p = parse_normalization_pack(kSoftwareNormalizationSeed);
    REQUIRE(p.has_value());

    // The same product (title, edition, cpe_product) spelled with two vendors would load as
    // two product rows: one norm_key per such product.
    std::map<std::tuple<std::string, std::string, std::string>, std::set<std::string>> keys_by_product;
    for (const auto& r : p->rows)
        keys_by_product[{r.title, r.edition, r.cpe_product}].insert(r.norm_key);
    for (const auto& [product, keys] : keys_by_product) {
        CAPTURE(std::get<0>(product), std::get<1>(product), std::get<2>(product));
        CHECK(keys.size() == 1);
    }

    // The vendor values the Linux and Windows rows must agree on, pinned by key.
    const auto has_key = [&](const char* k) {
        return std::any_of(p->rows.begin(), p->rows.end(),
                           [&](const PackRow& r) { return r.norm_key == k; });
    };
    CHECK(has_key("postgresql:postgresql"));
    CHECK(has_key("oracle:mysql"));
    CHECK(has_key("libreoffice:libreoffice"));
    CHECK_FALSE(has_key("mysql:mysql"));
    CHECK_FALSE(has_key("the document:libreoffice"));
}

TEST_CASE("the embedded seed keeps its edition rows and maps python3.14 and postgresql-18 onto "
          "their existing products",
          "[normalization][pack]") {
    const auto p = parse_normalization_pack(kSoftwareNormalizationSeed);
    REQUIRE(p.has_value());
    const auto key_of = [&](const char* raw_name) -> std::string {
        const auto it = std::find_if(p->rows.begin(), p->rows.end(),
                                     [&](const PackRow& r) { return r.raw_name == raw_name; });
        return it == p->rows.end() ? std::string{"<no row>"} : it->norm_key;
    };
    // The glued-version names are rows of their own: a version inside a name is not stripped.
    CHECK(key_of("python3.14") == key_of("python3"));
    CHECK(key_of("python3.14") == "python:python");
    CHECK(key_of("postgresql-18") == key_of("postgresql"));
    CHECK(key_of("postgresql-18") == "postgresql:postgresql");

    // Seed rows with an edition column parsed through normalize_edition: one product per edition.
    const std::set<std::string> want{
        "microsoft:sql server:standard",    "microsoft:sql server:enterprise",
        "microsoft:sql server:express",     "microsoft:visual studio:community",
        "microsoft:visual studio:professional", "microsoft:visual studio:enterprise",
    };
    std::set<std::string> got;
    for (const auto& r : p->rows)
        if (want.count(r.norm_key) != 0)
            got.insert(r.norm_key);
    CHECK(got == want);
}

TEST_CASE("a title that resolved through a re-keyed seed alias still resolves to the same product "
          "after the SAM-51 pack bump",
          "[normalization][pack]") {
    // Two seed rows changed their stored alias key: the dangling "-" of ".NET Runtime - 8.0.1"
    // and the "@3" of the Homebrew formula are no longer part of the normalised title. The
    // key a title now forms is the one the NEW seed holds, and it names the product the old key
    // named, so a pack loaded from this seed resolves both exactly as before.
    const auto p = parse_normalization_pack(kSoftwareNormalizationSeed);
    REQUIRE(p.has_value());
    const auto key_of = [&](const char* ecosystem, const std::string& alias) -> std::string {
        const auto it = std::find_if(p->rows.begin(), p->rows.end(), [&](const PackRow& r) {
            return r.ecosystem == ecosystem && r.raw_name == alias;
        });
        return it == p->rows.end() ? std::string{"<no row>"} : it->norm_key;
    };
    const std::string dotnet = alias_key(normalize_title("Microsoft .NET Runtime - 8.0.1 (x64)"));
    CHECK(dotnet == "microsoft .net runtime");
    CHECK(dotnet != "microsoft .net runtime -"); // the key a pre-SAM-51 pack stored
    CHECK(key_of("windows", dotnet) == "microsoft:.net runtime");

    const std::string brew = alias_key(normalize_title("openssl@3"));
    CHECK(brew == "openssl");
    CHECK(brew != "openssl@3"); // the key a pre-SAM-51 pack stored
    CHECK(key_of("brew", brew) == "openssl:openssl");
    // A server that still holds the OLD pack forms the new key `openssl` for `openssl@3`: the
    // generic any-ecosystem `openssl` row (unchanged by SAM-51) names the same product.
    CHECK(key_of("", "openssl") == "openssl:openssl");
}
