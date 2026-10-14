/**
 * test_key_provider.cpp — Unit tests for FileKeyProvider (PR1).
 *
 * Covers: store/load roundtrip, 0600 file mode (POSIX), the path-traversal
 * guard on key_id, the within-base guard on opaque refs (load/has/delete must
 * refuse a ref pointing outside the provider's base dir), and delete.
 */

#include "key_provider.hpp"

#include <catch2/catch_test_macros.hpp>

#include "../test_helpers.hpp"

#include <algorithm>
#include <array>
#include <atomic>
#include <chrono>
#include <cstdint>
#include <filesystem>
#include <fstream>
#include <iterator>
#include <string>
#include <string_view>
#include <system_error>
#include <thread>
#include <vector>

#ifndef _WIN32
#include <sys/stat.h>
#endif

using namespace yuzu::server;

namespace {

constexpr const char* kSampleKey =
    "-----BEGIN PRIVATE KEY-----\nMIGHAgEA...test...\n-----END PRIVATE KEY-----\n";

} // namespace

TEST_CASE("FileKeyProvider: store/load roundtrip", "[key_provider]") {
    yuzu::test::TempDir dir;
    FileKeyProvider provider(dir.path);

    auto ref = provider.store_key("ca-root", kSampleKey);
    REQUIRE(ref);
    REQUIRE(provider.has_key(*ref));

    auto loaded = provider.load_key(*ref);
    REQUIRE(loaded);
    REQUIRE(*loaded == kSampleKey);

    // ref resolves to <base>/ca-root.key
    REQUIRE(*ref == provider.path_for("ca-root").string());
}

#ifndef _WIN32
TEST_CASE("FileKeyProvider: stored key is 0600", "[key_provider][posix]") {
    namespace fs = std::filesystem;
    yuzu::test::TempDir dir;
    FileKeyProvider provider(dir.path);
    auto ref = provider.store_key("k", kSampleKey);
    REQUIRE(ref);

    const auto p = fs::status(*ref).permissions();
    REQUIRE((p & fs::perms::owner_read) != fs::perms::none);
    REQUIRE((p & fs::perms::owner_write) != fs::perms::none);
    REQUIRE((p & fs::perms::group_all) == fs::perms::none);
    REQUIRE((p & fs::perms::others_all) == fs::perms::none);
}
#endif

#ifndef _WIN32
TEST_CASE("FileKeyProvider: store_named_file writes 0600 regardless of umask",
          "[key_provider][posix][security]") {
    namespace fs = std::filesystem;
    yuzu::test::TempDir dir{"yuzu_test_keyprov_"};
    FileKeyProvider provider(dir.path / "fresh"); // created by the call => 0700

    const mode_t old = ::umask(0); // a plain create would now be 0666
    const bool ok = provider.store_named_file("server-key.pem", kSampleKey);
    ::umask(old);
    REQUIRE(ok);

    const auto key = dir.path / "fresh" / "server-key.pem";
    REQUIRE((fs::status(key).permissions() & fs::perms::mask) ==
            (fs::perms::owner_read | fs::perms::owner_write));
    REQUIRE((fs::status(dir.path / "fresh").permissions() & fs::perms::mask) ==
            fs::perms::owner_all);
}

TEST_CASE("FileKeyProvider: store_named_file replaces a planted symlink, never follows it",
          "[key_provider][posix][security]") {
    namespace fs = std::filesystem;
    yuzu::test::TempDir dir{"yuzu_test_keyprov_"};
    const auto victim = dir.path / "victim";
    REQUIRE(fs::create_directories(dir.path / "certs"));
    {
        std::ofstream v(victim);
        v << "untouched";
    }
    fs::create_symlink(victim, dir.path / "certs" / "server-key.pem");

    FileKeyProvider provider(dir.path / "certs");
    REQUIRE(provider.store_named_file("server-key.pem", kSampleKey));

    std::ifstream in(victim);
    std::string got((std::istreambuf_iterator<char>(in)), std::istreambuf_iterator<char>());
    REQUIRE(got == "untouched");
    REQUIRE_FALSE(fs::is_symlink(dir.path / "certs" / "server-key.pem"));
}

TEST_CASE("FileKeyProvider: store_named_file leaves an existing dir's mode alone",
          "[key_provider][posix]") {
    namespace fs = std::filesystem;
    yuzu::test::TempDir dir{"yuzu_test_keyprov_"};
    REQUIRE(fs::create_directories(dir.path));
    fs::permissions(dir.path,
                    fs::perms::owner_all | fs::perms::group_read | fs::perms::group_exec,
                    fs::perm_options::replace); // 0750
    FileKeyProvider provider(dir.path);
    REQUIRE(provider.store_named_file("server-key.pem", kSampleKey));
    REQUIRE((fs::status(dir.path).permissions() & fs::perms::mask) ==
            (fs::perms::owner_all | fs::perms::group_read | fs::perms::group_exec));
}
#endif

TEST_CASE("FileKeyProvider: store_named_file rejects unsafe names and bad sizes",
          "[key_provider][security][negative]") {
    yuzu::test::TempDir dir{"yuzu_test_keyprov_"};
    FileKeyProvider provider(dir.path);
    REQUIRE_FALSE(provider.store_named_file("../evil.pem", kSampleKey));
    REQUIRE_FALSE(provider.store_named_file("a/b.pem", kSampleKey));
    REQUIRE_FALSE(provider.store_named_file("", kSampleKey));
    REQUIRE_FALSE(provider.store_named_file("k.pem", ""));
    REQUIRE_FALSE(provider.store_named_file("k.pem", std::string(1024 * 1024 + 1, 'x')));
}

TEST_CASE("FileKeyProvider: store_named_file writes and replaces a named file (all platforms)",
          "[key_provider]") {
    yuzu::test::TempDir dir{"yuzu_test_keyprov_"};
    FileKeyProvider provider(dir.path);
    const auto dest = dir.path / "server-key.pem";

    REQUIRE(provider.store_named_file("server-key.pem", kSampleKey));
    std::ifstream first(dest, std::ios::binary);
    REQUIRE(std::string((std::istreambuf_iterator<char>(first)),
                        std::istreambuf_iterator<char>()) == kSampleKey);
    first.close();

    // A second store atomically replaces the first (Windows rename-over-existing).
    REQUIRE(provider.store_named_file("server-key.pem", "-----BEGIN PRIVATE KEY-----\nB\n"));
    std::ifstream second(dest, std::ios::binary);
    REQUIRE(std::string((std::istreambuf_iterator<char>(second)),
                        std::istreambuf_iterator<char>()) ==
            "-----BEGIN PRIVATE KEY-----\nB\n");
}

TEST_CASE("FileKeyProvider: rejects unsafe key_id (traversal)", "[key_provider][security]") {
    yuzu::test::TempDir dir;
    FileKeyProvider provider(dir.path);
    REQUIRE_FALSE(provider.store_key("../evil", kSampleKey));
    REQUIRE_FALSE(provider.store_key("a/b", kSampleKey));
    REQUIRE_FALSE(provider.store_key("..", kSampleKey));
    REQUIRE_FALSE(provider.store_key("", kSampleKey));
    REQUIRE_FALSE(provider.store_key("has space", kSampleKey));
    REQUIRE_FALSE(provider.store_key("semi;colon", kSampleKey));
    // A valid id still works.
    REQUIRE(provider.store_key("valid-id_1.key", kSampleKey));
}

TEST_CASE("FileKeyProvider: refuses refs outside base dir", "[key_provider][security]") {
    yuzu::test::TempDir dir;
    FileKeyProvider provider(dir.path);
    REQUIRE(provider.store_key("k", kSampleKey));

    // An opaque ref pointing outside the base must not be readable/deletable.
    REQUIRE_FALSE(provider.load_key("/etc/hostname"));
    REQUIRE_FALSE(provider.has_key("/etc/hostname"));
    REQUIRE_FALSE(provider.delete_key("/etc/passwd"));
    const std::string escape = (dir.path / ".." / "outside.key").string();
    REQUIRE_FALSE(provider.load_key(escape));
}

TEST_CASE("FileKeyProvider: rejects empty and oversized keys", "[key_provider][negative]") {
    yuzu::test::TempDir dir;
    FileKeyProvider provider(dir.path);
    REQUIRE_FALSE(provider.store_key("k", ""));
    const std::string huge(1024 * 1024 + 1, 'x'); // > kMaxKeyPemSize
    REQUIRE_FALSE(provider.store_key("k", huge));
    // A normal key still stores after the rejections.
    REQUIRE(provider.store_key("k", kSampleKey));
}

TEST_CASE("FileKeyProvider: delete removes the key", "[key_provider]") {
    yuzu::test::TempDir dir;
    FileKeyProvider provider(dir.path);
    auto ref = provider.store_key("temp", kSampleKey);
    REQUIRE(ref);
    REQUIRE(provider.has_key(*ref));
    REQUIRE(provider.delete_key(*ref));
    REQUIRE_FALSE(provider.has_key(*ref));
    // Deleting an already-absent key is success (idempotent).
    REQUIRE(provider.delete_key(*ref));
}

// ── KEK wrap/unwrap seam (ADR-0010 §2, #1320 PR 4) ───────────────────────────

namespace {

std::vector<std::uint8_t> bytes_of(std::string_view s) {
    return {reinterpret_cast<const std::uint8_t*>(s.data()),
            reinterpret_cast<const std::uint8_t*>(s.data()) + s.size()};
}

} // namespace

TEST_CASE("FileKeyProvider: generate_kek mints a 32-byte key, resolve finds it",
          "[key_provider][kek]") {
    namespace fs = std::filesystem;
    yuzu::test::TempDir dir;
    FileKeyProvider provider(dir.path);

    REQUIRE_FALSE(provider.resolve_kek("secrets-kek-v1"));
    auto ref = provider.generate_kek("secrets-kek-v1");
    REQUIRE(ref);
    REQUIRE(fs::file_size(fs::path{*ref}) == 32);

    auto resolved = provider.resolve_kek("secrets-kek-v1");
    REQUIRE(resolved);
    REQUIRE(*resolved == *ref);

#ifndef _WIN32
    const auto perms = fs::status(fs::path{*ref}).permissions();
    REQUIRE((perms & (fs::perms::group_all | fs::perms::others_all)) == fs::perms::none);
#endif

    // Re-minting the same id must refuse — overwriting a KEK would orphan
    // every blob wrapped under it.
    REQUIRE_FALSE(provider.generate_kek("secrets-kek-v1"));
    // Unsafe ids are rejected before touching the filesystem.
    REQUIRE_FALSE(provider.generate_kek("../escape"));
}

TEST_CASE("FileKeyProvider: wrap/unwrap round-trip binds the wrap AAD", "[key_provider][kek]") {
    yuzu::test::TempDir dir;
    FileKeyProvider provider(dir.path);
    auto ref = provider.generate_kek("secrets-kek-v1");
    REQUIRE(ref);

    std::array<std::uint8_t, 32> dek{};
    for (std::size_t i = 0; i < dek.size(); ++i)
        dek[i] = static_cast<std::uint8_t>(i * 7 + 1);
    const auto aad = bytes_of("store|table|column|pk|v1");

    auto wrapped = provider.wrap_dek(*ref, dek, aad);
    REQUIRE(wrapped);

    auto unwrapped = provider.unwrap_dek(*ref, *wrapped, aad);
    REQUIRE(unwrapped);
    REQUIRE(unwrapped->size() == 32);
    REQUIRE(std::equal(dek.begin(), dek.end(), unwrapped->data()));

    SECTION("different wrap AAD fails the tag") {
        const auto other = bytes_of("store|table|column|pk|v2");
        auto bad = provider.unwrap_dek(*ref, *wrapped, other);
        REQUIRE_FALSE(bad);
        REQUIRE(bad.error() == yuzu::server::KekError::tag_mismatch);
    }
    SECTION("tampered tag fails") {
        auto t = *wrapped;
        t.tag[0] ^= 0x01;
        auto bad = provider.unwrap_dek(*ref, t, aad);
        REQUIRE_FALSE(bad);
        REQUIRE(bad.error() == yuzu::server::KekError::tag_mismatch);
    }
    SECTION("tampered wrapped DEK fails") {
        auto t = *wrapped;
        t.wrapped[5] ^= 0x80;
        auto bad = provider.unwrap_dek(*ref, t, aad);
        REQUIRE_FALSE(bad);
        REQUIRE(bad.error() == yuzu::server::KekError::tag_mismatch);
    }
    SECTION("fresh nonce per wrap — same DEK+AAD wraps differently") {
        auto again = provider.wrap_dek(*ref, dek, aad);
        REQUIRE(again);
        REQUIRE(again->nonce != wrapped->nonce);
        REQUIRE(again->wrapped != wrapped->wrapped);
    }
}

TEST_CASE("FileKeyProvider: unknown / wrong-size / deleted KEK is unresolvable",
          "[key_provider][kek][negative]") {
    yuzu::test::TempDir dir;
    FileKeyProvider provider(dir.path);
    std::array<std::uint8_t, 32> dek{};
    const auto aad = bytes_of("aad");

    SECTION("unknown ref") {
        auto r = provider.wrap_dek((dir.path / "nope.key").string(), dek, aad);
        REQUIRE_FALSE(r);
        REQUIRE(r.error() == yuzu::server::KekError::unresolvable);
    }
    SECTION("a PEM-sized file is not a 32-byte KEK") {
        auto pem_ref = provider.store_key("not-a-kek", kSampleKey);
        REQUIRE(pem_ref);
        auto r = provider.wrap_dek(*pem_ref, dek, aad);
        REQUIRE_FALSE(r);
        REQUIRE(r.error() == yuzu::server::KekError::unresolvable);
    }
    SECTION("delete_key evicts the resident KEK") {
        auto ref = provider.generate_kek("secrets-kek-v1");
        REQUIRE(ref);
        REQUIRE(provider.wrap_dek(*ref, dek, aad));
        REQUIRE(provider.delete_key(*ref));
        auto r = provider.wrap_dek(*ref, dek, aad);
        REQUIRE_FALSE(r);
        REQUIRE(r.error() == yuzu::server::KekError::unresolvable);
    }
}

TEST_CASE("FileKeyProvider: kek_check_value is deterministic and key-distinct",
          "[key_provider][kek]") {
    yuzu::test::TempDir dir;
    FileKeyProvider provider(dir.path);
    auto r1 = provider.generate_kek("secrets-kek-v1");
    auto r2 = provider.generate_kek("secrets-kek-v2");
    REQUIRE(r1);
    REQUIRE(r2);

    auto k1a = provider.kek_check_value(*r1, "sha256");
    auto k2 = provider.kek_check_value(*r2, "sha256");
    REQUIRE(k1a);
    REQUIRE(k2);
    REQUIRE(*k1a != *k2);

    // Survives a provider restart (fresh cache, re-read from disk).
    FileKeyProvider reopened(dir.path);
    auto k1b = reopened.kek_check_value(*r1, "sha256");
    REQUIRE(k1b);
    REQUIRE(*k1a == *k1b);

    REQUIRE_FALSE(provider.kek_check_value((dir.path / "nope.key").string(), "sha256"));

    // An algorithm this provider cannot compute (e.g. a token-derived KCV from
    // a future HSM/KMS provider) returns nullopt rather than mis-verifying
    // (S2; ADR-0010 Amendment 4).
    REQUIRE_FALSE(provider.kek_check_value(*r1, "hsm-aes-kwp"));
}

TEST_CASE("FileKeyProvider: concurrent wrap vs delete_kek never resurrects a deleted KEK",
          "[key_provider][kek][concurrency]") {
    // Governance safety-S1/TSan coverage: delete_kek removes the file and
    // evicts the resident copy under one lock, so a racing wrap either
    // succeeds (pre-delete) or reports unresolvable — it must never re-cache
    // the deleted key from a stale file read.
    yuzu::test::TempDir dir;
    FileKeyProvider provider(dir.path);
    auto ref = provider.generate_kek("secrets-kek-v1");
    REQUIRE(ref);

    std::array<std::uint8_t, 32> dek{};
    const auto aad = bytes_of("aad");
    std::atomic<bool> stop{false};
    std::atomic<int> wrapped_after_delete{0};
    std::atomic<bool> deleted{false};

    std::thread wrapper([&] {
        while (!stop.load(std::memory_order_relaxed)) {
            const bool was_deleted = deleted.load(std::memory_order_acquire);
            auto r = provider.wrap_dek(*ref, dek, aad);
            if (was_deleted && r.has_value())
                wrapped_after_delete.fetch_add(1, std::memory_order_relaxed);
        }
    });
    std::this_thread::sleep_for(std::chrono::milliseconds(20));
    REQUIRE(provider.delete_kek(*ref));
    deleted.store(true, std::memory_order_release);
    std::this_thread::sleep_for(std::chrono::milliseconds(50));
    stop.store(true, std::memory_order_relaxed);
    wrapper.join();

    REQUIRE(wrapped_after_delete.load() == 0);
    auto r = provider.wrap_dek(*ref, dek, aad);
    REQUIRE_FALSE(r);
    REQUIRE(r.error() == yuzu::server::KekError::unresolvable);
}
