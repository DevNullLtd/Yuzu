/**
 * test_component_java_parsers.cpp — pure Java archive parsers
 * (component_java_parsers.hpp). File names are taken from real
 * distributions; no I/O, no archives.
 */

#include "component_java_parsers.hpp"

#include <catch2/catch_test_macros.hpp>

#include <optional>
#include <string>
#include <string_view>

using namespace std::string_view_literals;
using namespace yuzu::component_inventory;

TEST_CASE("jar filename: artifact and version split", "[runtime][component_inventory][java]") {
    struct Row {
        const char* file;
        const char* artifact;
        const char* version;
    };
    const Row rows[] = {
        {"log4j-core-2.17.1.jar", "log4j-core", "2.17.1"},
        {"log4j-1.2-api-2.17.1.jar", "log4j-1.2-api", "2.17.1"},
        {"ojdbc.jar", "ojdbc", ""},
        {"ojdbc8-19.3.0.0.jar", "ojdbc8", "19.3.0.0"},
        {"commons-lang3-3.12.0.jar", "commons-lang3", "3.12.0"},
        {"bcprov-jdk15on-1.70.jar", "bcprov-jdk15on", "1.70"},
        {"guava-31.1-jre.jar", "guava", "31.1"},
        {"netty-transport-native-epoll-4.1.77.Final-linux-x86_64.jar", "netty-transport-native-epoll",
         "4.1.77.Final"},
        {"spring-core-5.3.20-sources.jar", "spring-core", "5.3.20"},
        {"my-app-1.0-SNAPSHOT.jar", "my-app", "1.0-SNAPSHOT"},
        {"my-app-1.0-SNAPSHOT-tests.jar", "my-app", "1.0-SNAPSHOT"},
        {"jackson-databind-2.13.3.JAR", "jackson-databind", "2.13.3"},
        {"app-2.0.0+build5.war", "app", "2.0.0+build5"},
        {"portal-7.4.ear", "portal", "7.4"},
        {"-1.0.jar", "-1.0", ""},
        // Digit-led classifiers after a real version stay classifiers.
        {"name-1.0-64bit.jar", "name", "1.0"},
        {"name-1.0-64bit-sources.jar", "name", "1.0"},
        {"name-1.0-SNAPSHOT-32bit.jar", "name", "1.0-SNAPSHOT"},
        {"log4j-1.2-api-3.jar", "log4j-1.2-api", "3"},
        {"foo-64bit.jar", "foo", "64bit"},
        // Pre-release and build qualifiers stay in the version; other words are classifiers.
        {"my-app-1.0.0-rc1.jar", "my-app", "1.0.0-rc1"},
        {"spring-core-6.0.0-M1.jar", "spring-core", "6.0.0-M1"},
        {"foo-1.0-beta-2.jar", "foo", "1.0-beta-2"},
        {"foo-1.0-20231101.123456-1.jar", "foo", "1.0-20231101.123456-1"},
        {"foo-1.0-RC2-sources.jar", "foo", "1.0-RC2"},
        {"guava-31.1-android.jar", "guava", "31.1"},
        {"guava-31.1-jre.jar", "guava", "31.1"}, // a word it does not know: the archive can say more
        // OSGi: the '_' splits, the version runs to the end of the stem.
        {"org.eclipse.core.runtime_3.29.0.v20230101-1200.jar", "org.eclipse.core.runtime",
         "3.29.0.v20230101-1200"},
        {"bundle_1.2.3.jar", "bundle", "1.2.3"},
        // ... but a later dotted '-' candidate is a Maven-style version.
        {"a_1.2.3-api-2.0.jar", "a_1.2.3-api", "2.0"},
        {"my_app_name.jar", "my_app_name", ""},
        // A weak candidate (64bit) gives way to a later real one, adjacent or not.
        {"foo-64bit-1.0.jar", "foo-64bit", "1.0"},
    };
    for (const auto& r : rows) {
        CAPTURE(r.file);
        const auto n = parse_jar_filename(r.file);
        REQUIRE(n.has_value());
        CHECK(n->artifact == r.artifact);
        CHECK(n->version == r.version);
    }
}

TEST_CASE("jar filename: exact only when nothing in the name is ambiguous", "[runtime][component_inventory][java]") {
    for (const char* f : {"guava-31.1.jar", "my-app-1.0.0-rc1.jar", "foo-1.0-beta-2.jar",
                          "org.eclipse.core.runtime_3.29.0.v20230101-1200.jar", "foo-64bit.jar"})
        CHECK(parse_jar_filename(f)->exact);
    // A classifier after the version, a second candidate, or no version at all: the archive is asked.
    for (const char* f : {"guava-31.1-jre.jar", "log4j-1.2-api-2.17.1.jar", "name-1.0-64bit.jar", "ojdbc.jar",
                          "my-app-1.0-SNAPSHOT-tests.jar"})
        CHECK_FALSE(parse_jar_filename(f)->exact);
}

TEST_CASE("jar filename: an archive version anchors on the stem or not at all", "[runtime][component_inventory][java]") {
    CHECK(archive_version_prefix("guava-31.1-jre", "31.1-jre", '-') == std::optional<std::string_view>{"guava"});
    CHECK(archive_version_prefix("foo-1.0-linux-x86_64", "1.0", '-') == std::optional<std::string_view>{"foo"});
    CHECK(archive_version_prefix("org.x_3.0.0.v1", "3.0.0.v1", '_') == std::optional<std::string_view>{"org.x"});
    // Not anchored: a dependency's version, a longer number, an empty prefix, the wrong separator.
    CHECK_FALSE(archive_version_prefix("myapp-2.0", "1.5", '-').has_value());
    CHECK_FALSE(archive_version_prefix("foo-1.05", "1.0", '-').has_value());
    CHECK_FALSE(archive_version_prefix("-1.0", "1.0", '-').has_value());
    CHECK_FALSE(archive_version_prefix("org.x_3.0.0", "3.0.0", '-').has_value());
    CHECK_FALSE(archive_version_prefix("foo-1.0", "", '-').has_value());
}

TEST_CASE("jar filename: non-archives and empties are rejected", "[runtime][component_inventory][java]") {
    for (const char* f : {"", ".jar", "a.zip", "a.jar.bak", "jar", "readme.txt", "x.jarx"})
        CHECK_FALSE(parse_jar_filename(f).has_value());
    CHECK_FALSE(parse_jar_filename("\0\xff\x01"sv).has_value());
}

TEST_CASE("archive name: .jar, .war and .ear in any case, nothing shorter or longer",
          "[runtime][component_inventory][java]") {
    for (const char* f : {"a.jar", "A.JAR", "x.War", "y.eAr", ".jar", "dir.name.jar"})
        CHECK(is_java_archive_name(f));
    for (const char* f : {"", "jar", "ar", "a.zip", "a.jar.bak", "x.jarx", "x.warx", "a.ja"})
        CHECK_FALSE(is_java_archive_name(f));
}

TEST_CASE("jar filename: binary bytes are rejected on both branches", "[runtime][component_inventory][java]") {
    // Valid archive suffix, so these reach the artifact/version scan.
    for (const std::string_view f : {"a\0.jar"sv, "a\0-1.jar"sv, "a-1\0.jar"sv, "a\x01-1.0.jar"sv,
                                     "a\x7f.jar"sv, "a\xff.jar"sv, "a-1.0\xc3\xa9.war"sv, "a\n-1.jar"sv})
        CHECK_FALSE(parse_jar_filename(f).has_value());
}

TEST_CASE("jar filename: oversized names are rejected before copying", "[runtime][component_inventory][java]") {
    // 255 bytes is the limit: 251 + ".jar".
    CHECK(parse_jar_filename(std::string(kMaxJarFilenameBytes - 4, 'a') + ".jar").has_value());
    CHECK_FALSE(parse_jar_filename(std::string(kMaxJarFilenameBytes - 3, 'a') + ".jar").has_value());
    CHECK_FALSE(parse_jar_filename(std::string(1048576, 'a') + ".jar").has_value());
    CHECK_FALSE(parse_jar_filename(std::string(1048576, 'a') + "-1.0.jar").has_value());
}

TEST_CASE("pom.properties: version property", "[runtime][component_inventory][java]") {
    const std::string pom = "#Generated by Maven\n#Wed Jan 12 10:00:00 UTC 2022\n"
                            "groupId=org.apache.logging.log4j\nartifactId=log4j-core\n"
                            "versionRange=9.9\nversion=2.17.1\n";
    CHECK(parse_pom_properties_version(pom) == std::optional<std::string>{"2.17.1"});
    CHECK(parse_pom_properties_version("\r\n! c\r\n  version : 1.0-SNAPSHOT  \r\n") ==
          std::optional<std::string>{"1.0-SNAPSHOT"});
    CHECK(parse_pom_properties_version("#version=1\n") == std::nullopt);
    CHECK(parse_pom_properties_version("version=\n") == std::nullopt);
    CHECK(parse_pom_properties_version("version=1\x01" "2\n") == std::nullopt);
    // An unresolved build placeholder is not a version.
    CHECK(parse_pom_properties_version("version=${project.version}\n") == std::nullopt);
    CHECK(parse_manifest_version("Implementation-Version: ${version}\n") == std::nullopt);
    CHECK(parse_pom_properties_version("version=" + std::string(128, '1')).has_value());
    CHECK(parse_pom_properties_version("version=" + std::string(129, '1')) == std::nullopt);
}

TEST_CASE("manifest: version precedence and continuation", "[runtime][component_inventory][java]") {
    CHECK(parse_manifest_version("Manifest-Version: 1.0\r\nImplementation-Version: 2.17.1\r\n"
                                 "Bundle-Version: 9.9\r\n\r\n") == std::optional<std::string>{"2.17.1"});
    CHECK(parse_manifest_version("Bundle-Version: 5.3.20\nCreated-By: x\n") ==
          std::optional<std::string>{"5.3.20"});
    CHECK(parse_manifest_version("implementation-version: 1.2\n") == std::optional<std::string>{"1.2"});
    CHECK(parse_manifest_version("Implementation-Version: 1.2.3-very\r\n -long-qualifier\r\nX: y\r\n") ==
          std::optional<std::string>{"1.2.3-very-long-qualifier"});
    // Per-entry section after the first blank line is ignored.
    CHECK(parse_manifest_version("Manifest-Version: 1.0\n\nName: a\nImplementation-Version: 3\n") ==
          std::nullopt);
    CHECK(parse_manifest_version("Implementation-Version:\n") == std::nullopt);
}

TEST_CASE("manifest: bounds and control bytes", "[runtime][component_inventory][java]") {
    CHECK(parse_manifest_version("Implementation-Version: " + std::string(129, '1') + "\n") == std::nullopt);
    // Over-long via continuation lines never builds an unbounded value.
    std::string m = "Implementation-Version: 1\n";
    for (int i = 0; i < 1000; ++i)
        m += " 1111111111111111111111111111111111111111111111111111111111111111111\n";
    CHECK(parse_manifest_version(m) == std::nullopt);
    CHECK(parse_manifest_version("Implementation-Version: 1\x07" "2\n") == std::nullopt);
    // Falls through to Bundle-Version when Implementation-Version is unusable.
    CHECK(parse_manifest_version("Implementation-Version: 1\x07\nBundle-Version: 4.0\n") ==
          std::optional<std::string>{"4.0"});
    // An oversized unrelated line must not poison the next header.
    CHECK(parse_manifest_version("X: " + std::string(254, 'a') + "\nImplementation-Version: 1\n") ==
          std::optional<std::string>{"1"});
    CHECK(parse_manifest_version("X: " + std::string(254, 'a') + "\n " + std::string(10, 'b') +
                                 "\nBundle-Version: 2\n") == std::optional<std::string>{"2"});
}

TEST_CASE("empty and binary input never crash", "[runtime][component_inventory][java]") {
    CHECK(parse_pom_properties_version("") == std::nullopt);
    CHECK(parse_manifest_version("") == std::nullopt);
    std::string bin;
    for (int i = 0; i < 4096; ++i)
        bin.push_back(static_cast<char>(i * 31));
    CHECK(parse_pom_properties_version(bin) == std::nullopt);
    CHECK(parse_manifest_version(bin) == std::nullopt);
    CHECK(parse_manifest_version(std::string(1, '\0') + ":" + std::string(300, '\xff')) == std::nullopt);
    CHECK_FALSE(is_nested_lib_entry(bin));
    CHECK_FALSE(pom_properties_artifact(bin).has_value());
}

TEST_CASE("entry classifiers", "[runtime][component_inventory][java]") {
    CHECK(kManifestEntry == "META-INF/MANIFEST.MF");
    for (const char* e : {"BOOT-INF/lib/spring-core-5.3.20.jar", "WEB-INF/lib/a.jar", "lib/b-1.0.jar"})
        CHECK(is_nested_lib_entry(e));
    // The extension folds case, like is_java_archive_name: X.JAR is listed, not silently absent.
    for (const char* e : {"BOOT-INF/lib/X-1.0.JAR", "WEB-INF/lib/y.Jar", "lib/z-2.jAr", "lib/a.jaR"})
        CHECK(is_nested_lib_entry(e));
    for (const char* e : {"BOOT-INF/lib/a/b.jar", "lib/a/b.jar", "WEB-INF/lib/", "lib/.jar", "lib/.JAR", "lib/a.zip",
                          "lib/a.ZIP", "lib/a.war", "BOOT-INF/classes/a.jar", "xlib/a.jar", "", "lib/a.jar/"})
        CHECK_FALSE(is_nested_lib_entry(e));
    // The directory prefixes stay exact.
    for (const char* e : {"boot-inf/lib/a.jar", "Lib/a.jar", "LIB/a.JAR", "web-inf/lib/a.jar"})
        CHECK_FALSE(is_nested_lib_entry(e));
    CHECK(pom_properties_artifact("META-INF/maven/org.apache/log4j-core/pom.properties").has_value());
    CHECK(pom_properties_artifact("META-INF/maven/org.apache/log4j-core/pom.properties") == "log4j-core");
    CHECK(pom_properties_artifact("META-INF/maven/g/a/b/pom.properties") == std::nullopt);
    CHECK(pom_properties_artifact("META-INF/maven/g//pom.properties") == std::nullopt);
    CHECK(pom_properties_artifact("") == std::nullopt);
    for (const char* e : {"META-INF/maven/org.apache/pom.properties", "META-INF/maven//a/pom.properties",
                          "META-INF/maven/g/a/b/pom.properties", "META-INF/maven/g/a/pom.xml",
                          "META-INF/maven/g/a/", "META-INF/maven/pom.properties", ""})
        CHECK_FALSE(pom_properties_artifact(e).has_value());
}
