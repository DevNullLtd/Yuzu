/**
 * test_local_path_policy.cpp -- WP10 (security fix package): the shared "may a plugin open this
 * operator- or user-supplied path / connect to this address" predicates.
 *
 *   agents/shared/local_path_policy.hpp      UNC / device / non-fixed-drive / network-mount refusal
 *   agents/shared/outbound_address_policy.hpp resolve-once address vetting (http_client, windows_updates)
 *   agents/shared/bounded_file_hash.hpp      regular-file-only, capped, deadline-bounded hash
 *
 * The decision functions are pure and run on every host; the Windows drive type is injected so the
 * Windows spellings are exercised here on Linux. Nothing here ships an attack: every case asserts a
 * REFUSAL (or that a plain local path still passes).
 */
#include <catch2/catch_test_macros.hpp>

#include "test_helpers.hpp"

#include <bounded_file_hash.hpp>
#include <local_path_policy.hpp>
#include <outbound_address_policy.hpp>
#include <sha256.hpp>

#include <algorithm>
#include <chrono>
#include <cstdlib>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <iterator>
#include <string>
#include <vector>

#ifndef _WIN32
#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>

#include <yuzu/agent/plugin_loader.hpp>
#include <yuzu/plugin.h>

#include "local_dispatcher.hpp"
#endif

namespace fs = std::filesystem;
namespace lp = yuzu::shared::local_path;
namespace ob = yuzu::shared::outbound;

namespace {

// A fake drive table: C: and D: fixed (3), E: removable (2), Z: network (4), anything else absent.
unsigned fake_drive_type(char letter) {
    switch (letter) {
    case 'C': case 'c': case 'D': case 'd': return 3;
    case 'E': case 'e': return 2;
    case 'Z': case 'z': return 4;
    default: return 1; // DRIVE_NO_ROOT_DIR
    }
}

lp::Refusal win(std::string_view p) { return lp::win_refusal(p, fake_drive_type); }

} // namespace

// ── Windows spellings (pure; the drive type is injected) ────────────────────────────────────────

TEST_CASE("local_path: Windows UNC and device spellings are refused", "[shared][local_path]") {
    for (const char* p : {"\\\\host\\share\\f.txt", "//host/share/f.txt", "\\\\host\\share",
                          "\\\\?\\UNC\\host\\share\\f", "\\\\?\\unc\\host\\share\\f",
                          "\\\\.\\PhysicalDrive0", "\\\\.\\pipe\\x", "\\\\?\\GLOBALROOT\\Device\\X",
                          "\\\\?\\Volume{01234567-89ab-cdef-0123-456789abcdef}\\f",
                          "\\??\\C:\\x", "\\??\\UNC\\host\\share", "\\Device\\Mup\\host\\share",
                          "\\device\\LanmanRedirector\\host", "\\SystemRoot\\system32\\x"}) {
        INFO(p);
        CHECK(win(p) == lp::Refusal::network_or_device);
    }
}

TEST_CASE("local_path: a drive letter must be a fixed disk", "[shared][local_path]") {
    CHECK(win("C:\\Windows\\notepad.exe") == lp::Refusal::none);
    CHECK(win("d:/data/file.bin") == lp::Refusal::none);
    CHECK(win("C:\\") == lp::Refusal::none);
    CHECK(win("C:") == lp::Refusal::none);
    CHECK(win("\\\\?\\C:\\Windows\\x") == lp::Refusal::none); // long-path spelling of a fixed drive
    // A mapped network drive, removable media and a drive that does not exist all refuse.
    CHECK(win("Z:\\share\\f") == lp::Refusal::non_fixed_drive);
    CHECK(win("\\\\?\\Z:\\share\\f") == lp::Refusal::non_fixed_drive);
    CHECK(win("E:\\usb\\f") == lp::Refusal::non_fixed_drive);
    CHECK(win("Q:\\nope") == lp::Refusal::non_fixed_drive);
    // Drive-relative spellings reach the drive too: the type check must run for them.
    CHECK(win("Z:file") == lp::Refusal::non_fixed_drive);
    CHECK(win("Z:") == lp::Refusal::non_fixed_drive);
    CHECK(win("Z:/x") == lp::Refusal::non_fixed_drive);
    CHECK(win("E:file.txt") == lp::Refusal::non_fixed_drive);
    CHECK(win("C:file") == lp::Refusal::none);
    CHECK(win("1:file") == lp::Refusal::none); // not a drive letter: an ordinary relative name
}

TEST_CASE("local_path: relative and current-drive-rooted Windows paths pass", "[shared][local_path]") {
    CHECK(win("logs\\app.log") == lp::Refusal::none);
    CHECK(win("..\\up\\f") == lp::Refusal::none);
    CHECK(win("\\Windows\\System32\\drivers\\etc\\hosts") == lp::Refusal::none);
    CHECK(win("") == lp::Refusal::none); // the caller owns the empty-path error
}

TEST_CASE("local_path: reserved DOS device names are refused in any component", "[shared][local_path]") {
    for (const char* p : {"NUL", "con", "C:\\dir\\NUL", "C:\\dir\\nul.txt", "COM1", "lpt9.log",
                          "C:\\x\\AUX", "CONIN$", "CONOUT$", "C:\\a\\prn.", "dir\\COM3\\f"}) {
        INFO(p);
        CHECK(win(p) == lp::Refusal::network_or_device);
    }
    // Names that merely START like a device are ordinary files.
    for (const char* p : {"C:\\x\\console.txt", "C:\\x\\com10", "C:\\x\\lpt0", "C:\\x\\nullable",
                          "C:\\x\\com", "C:\\x\\auxiliary.dll"}) {
        INFO(p);
        CHECK(win(p) == lp::Refusal::none);
    }
}

TEST_CASE("local_path: a leading control character or space is refused rather than guessed at",
          "[shared][local_path]") {
    CHECK(win(" \\\\host\\share") == lp::Refusal::network_or_device);
    CHECK(win("\t C:\\x") == lp::Refusal::network_or_device);
}

TEST_CASE("local_path: win_drive_letter extracts only a real drive designator", "[shared][local_path]") {
    CHECK(lp::win_drive_letter("C:\\x") == 'C');
    CHECK(lp::win_drive_letter("c:") == 'c');
    CHECK(lp::win_drive_letter("\\\\?\\D:\\x") == 'D');
    CHECK(lp::win_drive_letter("\\\\?\\UNC\\h\\s") == 0);
    CHECK(lp::win_drive_letter("\\\\h\\s") == 0);
    CHECK(lp::win_drive_letter("1:\\x") == 0);
    CHECK(lp::win_drive_letter("C:file") == 'C'); // drive-relative still names drive C
    CHECK(lp::win_drive_letter("Z:/x") == 'Z');
    CHECK(lp::win_drive_letter("9:file") == 0);
    CHECK(lp::win_drive_letter(":x") == 0);
    CHECK(lp::win_drive_letter("") == 0);
}

TEST_CASE("local_path: the drive-type callback runs only for a drive-letter spelling",
          "[shared][local_path]") {
    int calls = 0;
    auto counting = [&](char) { ++calls; return 3u; };
    CHECK(lp::win_refusal("rel\\x", counting) == lp::Refusal::none);
    CHECK(calls == 0);
    CHECK(lp::win_refusal("\\\\h\\s", counting) == lp::Refusal::network_or_device);
    CHECK(calls == 0); // a UNC path is refused lexically, never asking the OS
    CHECK(lp::win_refusal("C:\\x", counting) == lp::Refusal::none);
    CHECK(calls == 1);
}

TEST_CASE("local_path: refusal tokens are stable and never carry the path", "[shared][local_path]") {
    CHECK(lp::refusal_token(lp::Refusal::network_or_device) == "path_refused:network_or_device");
    CHECK(lp::refusal_token(lp::Refusal::non_fixed_drive) == "path_refused:non_fixed_drive");
    CHECK(lp::refusal_token(lp::Refusal::mount_table_unreadable) ==
          "path_refused:mount_table_unreadable");
    CHECK_FALSE(lp::refused(lp::Refusal::none));
    CHECK(lp::refused(lp::Refusal::unresolvable));
}

// ── POSIX: network mounts from mountinfo text ───────────────────────────────────────────────────

TEST_CASE("local_path: a path on or under a network mount is refused; siblings are not",
          "[shared][local_path]") {
    const std::string mountinfo =
        "22 1 8:1 / / rw - ext4 /dev/sda1 rw\n"
        "30 22 0:25 / /mnt/nfs rw,relatime - nfs4 srv:/export rw\n"
        "31 22 0:26 / /mnt/space\\040dir rw - cifs //srv/share rw\n"
        "32 22 0:27 / /mnt/auto rw - autofs systemd-1 rw\n";
    const auto mounts = yuzu::shared::network_mount_points(mountinfo);
    REQUIRE(mounts.size() == 3);

    CHECK(lp::posix_refusal("/mnt/nfs", mounts) == lp::Refusal::network_or_device);
    CHECK(lp::posix_refusal("/mnt/nfs/a/b", mounts) == lp::Refusal::network_or_device);
    CHECK(lp::posix_refusal("/mnt/nfs/../nfs/x", mounts) == lp::Refusal::network_or_device);
    CHECK(lp::posix_refusal("/mnt//nfs/./x", mounts) == lp::Refusal::network_or_device);
    CHECK(lp::posix_refusal("/mnt/space dir/f", mounts) == lp::Refusal::network_or_device);
    CHECK(lp::posix_refusal("/mnt/auto/home", mounts) == lp::Refusal::network_or_device);
    // A `..` that climbs OUT of the mount is judged on the normalised path.
    CHECK(lp::posix_refusal("/mnt/nfs/../local", mounts) == lp::Refusal::none);
    // Segment boundary: /mnt/nfs2 is not under /mnt/nfs.
    CHECK(lp::posix_refusal("/mnt/nfs2/f", mounts) == lp::Refusal::none);
    CHECK(lp::posix_refusal("/var/log/syslog", mounts) == lp::Refusal::none);
    CHECK(lp::posix_refusal("/", mounts) == lp::Refusal::none);
    CHECK(lp::posix_refusal("", mounts) == lp::Refusal::none);
}

TEST_CASE("local_path: a network root filesystem refuses everything", "[shared][local_path]") {
    CHECK(lp::posix_under_mount("/anything/at/all", {"/"}));
    CHECK_FALSE(lp::posix_under_mount("/anything", {}));
    CHECK_FALSE(lp::posix_under_mount("/anything", {""}));
}

#ifdef __linux__
TEST_CASE("local_path: the live Linux glue passes an ordinary local temp path", "[shared][local_path]") {
    yuzu::test::TempDir tmp{"yuzu_test_lp_"};
    REQUIRE(fs::create_directory(tmp.path));
    // /proc/self/mountinfo is readable in the test environment; the temp dir is not a network mount.
    CHECK(lp::local_path_refusal(tmp.path.string()) == lp::Refusal::none);
}
#endif

// ── Outbound address classification ─────────────────────────────────────────────────────────────

namespace {
ob::AddressClass v4(unsigned a, unsigned b, unsigned c, unsigned d) {
    return ob::classify_ipv4({static_cast<std::uint8_t>(a), static_cast<std::uint8_t>(b),
                              static_cast<std::uint8_t>(c), static_cast<std::uint8_t>(d)});
}
ob::AddressClass v6(std::initializer_list<unsigned> bytes) {
    ob::Ipv6 b{};
    std::size_t i = 0;
    for (const unsigned x : bytes)
        b[i++] = static_cast<std::uint8_t>(x);
    return ob::classify_ipv6(b);
}
} // namespace

TEST_CASE("outbound: IPv4 classes", "[shared][outbound]") {
    CHECK(v4(8, 8, 8, 8) == ob::AddressClass::Public);
    CHECK(v4(93, 184, 216, 34) == ob::AddressClass::Public);
    CHECK(v4(127, 0, 0, 1) == ob::AddressClass::Loopback);
    CHECK(v4(127, 255, 255, 254) == ob::AddressClass::Loopback);
    CHECK(v4(0, 0, 0, 0) == ob::AddressClass::Unspecified);
    CHECK(v4(0, 1, 2, 3) == ob::AddressClass::Unspecified);
    CHECK(v4(10, 1, 2, 3) == ob::AddressClass::Private);
    CHECK(v4(172, 16, 0, 1) == ob::AddressClass::Private);
    CHECK(v4(172, 31, 255, 255) == ob::AddressClass::Private);
    CHECK(v4(172, 32, 0, 1) == ob::AddressClass::Public);
    CHECK(v4(172, 15, 0, 1) == ob::AddressClass::Public);
    CHECK(v4(192, 168, 1, 1) == ob::AddressClass::Private);
    CHECK(v4(100, 64, 0, 1) == ob::AddressClass::Private); // CGNAT
    CHECK(v4(100, 127, 255, 255) == ob::AddressClass::Private);
    CHECK(v4(100, 128, 0, 1) == ob::AddressClass::Public);
    CHECK(v4(169, 254, 169, 254) == ob::AddressClass::LinkLocal); // cloud metadata
    CHECK(v4(224, 0, 0, 1) == ob::AddressClass::Multicast);
    CHECK(v4(239, 255, 255, 250) == ob::AddressClass::Multicast);
    CHECK(v4(240, 0, 0, 1) == ob::AddressClass::Reserved);
    CHECK(v4(255, 255, 255, 255) == ob::AddressClass::Reserved);
    CHECK(v4(198, 18, 0, 1) == ob::AddressClass::OtherNonGlobal);
    CHECK(v4(198, 19, 255, 255) == ob::AddressClass::OtherNonGlobal);
    CHECK(v4(198, 20, 0, 1) == ob::AddressClass::Public);
    CHECK(v4(192, 0, 2, 5) == ob::AddressClass::OtherNonGlobal);
    CHECK(v4(198, 51, 100, 5) == ob::AddressClass::OtherNonGlobal);
    CHECK(v4(203, 0, 113, 5) == ob::AddressClass::OtherNonGlobal);
}

TEST_CASE("outbound: IPv6 classes including the embedded-IPv4 forms", "[shared][outbound]") {
    CHECK(v6({0x26, 0x06, 0x47, 0x00, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x11, 0x11}) ==
          ob::AddressClass::Public);
    CHECK(v6({0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1}) == ob::AddressClass::Loopback);
    CHECK(v6({0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}) == ob::AddressClass::Unspecified);
    CHECK(v6({0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1}) == ob::AddressClass::LinkLocal);
    CHECK(v6({0xfd, 0x00, 0x0e, 0xc2, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2, 0x54}) ==
          ob::AddressClass::Private); // fd00:ec2::254 (AWS IMDS over IPv6)
    CHECK(v6({0xfc, 0x00, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1}) == ob::AddressClass::Private);
    CHECK(v6({0xff, 0x02, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1}) == ob::AddressClass::Multicast);
    CHECK(v6({0xfe, 0xc0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1}) ==
          ob::AddressClass::OtherNonGlobal); // site-local
    CHECK(v6({0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1}) ==
          ob::AddressClass::OtherNonGlobal); // documentation
    CHECK(v6({0x10, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1}) ==
          ob::AddressClass::OtherNonGlobal); // outside 2000::/3

    // IPv4-mapped (::ffff:a.b.c.d) is judged by the embedded IPv4 address (the #647 bypass).
    CHECK(v6({0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff, 127, 0, 0, 1}) == ob::AddressClass::Loopback);
    CHECK(v6({0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff, 10, 0, 0, 5}) == ob::AddressClass::Private);
    CHECK(v6({0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff, 169, 254, 169, 254}) ==
          ob::AddressClass::LinkLocal);
    CHECK(v6({0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff, 8, 8, 8, 8}) == ob::AddressClass::Public);
    // IPv4-compatible ::a.b.c.d (deprecated) is never public.
    CHECK(v6({0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 8, 8, 8, 8}) == ob::AddressClass::OtherNonGlobal);
    CHECK(v6({0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 127, 0, 0, 1}) == ob::AddressClass::OtherNonGlobal);
    // NAT64 well-known prefix 64:ff9b::/96: embedded IPv4 decides; local-use 64:ff9b:1::/48 refuses.
    CHECK(v6({0x00, 0x64, 0xff, 0x9b, 0, 0, 0, 0, 0, 0, 0, 0, 127, 0, 0, 1}) ==
          ob::AddressClass::Loopback);
    CHECK(v6({0x00, 0x64, 0xff, 0x9b, 0, 0, 0, 0, 0, 0, 0, 0, 169, 254, 169, 254}) ==
          ob::AddressClass::LinkLocal);
    CHECK(v6({0x00, 0x64, 0xff, 0x9b, 0, 0, 0, 0, 0, 0, 0, 0, 8, 8, 8, 8}) ==
          ob::AddressClass::Public);
    CHECK(v6({0x00, 0x64, 0xff, 0x9b, 0, 1, 0, 0, 0, 0, 0, 0, 8, 8, 8, 8}) ==
          ob::AddressClass::OtherNonGlobal);
    // 6to4 2002:AABB:CCDD::/48 embeds the IPv4 address in bytes 2..5.
    CHECK(v6({0x20, 0x02, 127, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1}) == ob::AddressClass::Loopback);
}

TEST_CASE("outbound: the two caller tiers", "[shared][outbound]") {
    // http_client connects only to public addresses.
    CHECK(ob::is_public(ob::AddressClass::Public));
    CHECK_FALSE(ob::is_public(ob::AddressClass::Private));
    CHECK_FALSE(ob::is_public(ob::AddressClass::OtherNonGlobal));
    // windows_updates' patch-source probe still reaches a private WSUS server.
    CHECK_FALSE(ob::never_probeable(ob::AddressClass::Public));
    CHECK_FALSE(ob::never_probeable(ob::AddressClass::Private));
    CHECK_FALSE(ob::never_probeable(ob::AddressClass::OtherNonGlobal));
    for (const auto c : {ob::AddressClass::Loopback, ob::AddressClass::Unspecified,
                         ob::AddressClass::LinkLocal, ob::AddressClass::Multicast,
                         ob::AddressClass::Reserved})
        CHECK(ob::never_probeable(c));
}

namespace {
ob::ResolvedAddress addr4(unsigned a, unsigned b, unsigned c, unsigned d) {
    ob::ResolvedAddress r;
    r.bytes[0] = static_cast<std::uint8_t>(a);
    r.bytes[1] = static_cast<std::uint8_t>(b);
    r.bytes[2] = static_cast<std::uint8_t>(c);
    r.bytes[3] = static_cast<std::uint8_t>(d);
    return r;
}
} // namespace

TEST_CASE("outbound: a resolver answer with ANY non-public address is refused", "[shared][outbound]") {
    using S = ob::VetStatus;
    CHECK(ob::vet_addresses({}).status == S::resolution_failed); // fail closed
    CHECK(ob::vet_addresses({addr4(8, 8, 8, 8)}).status == S::ok);
    CHECK(ob::vet_addresses({addr4(8, 8, 8, 8), addr4(1, 1, 1, 1)}).status == S::ok);
    CHECK(ob::vet_addresses({addr4(127, 0, 0, 1)}).status == S::refused);
    // Mixed: one public and one private answer. Not "use the public one".
    CHECK(ob::vet_addresses({addr4(8, 8, 8, 8), addr4(10, 0, 0, 5)}).status == S::refused);
    CHECK(ob::vet_addresses({addr4(10, 0, 0, 5), addr4(8, 8, 8, 8)}).status == S::refused);
}

TEST_CASE("outbound: a name that resolves public THEN private is judged on ONE lookup",
          "[shared][outbound]") {
    // The DNS-rebinding case (#647 / F17): the first lookup answers a public address, every later
    // lookup a private one. vet_host calls the resolver exactly once, and the answer it vetted is
    // the connect target, so the second (private) answer can never be the one connected to.
    int lookups = 0;
    auto rebinding_resolver = [&]() -> std::vector<ob::ResolvedAddress> {
        return ++lookups == 1 ? std::vector{addr4(93, 184, 216, 34)}
                              : std::vector{addr4(169, 254, 169, 254)};
    };
    std::vector<ob::ResolvedAddress> answers;
    const auto verdict = ob::vet_host(rebinding_resolver, answers);
    CHECK(verdict.status == ob::VetStatus::ok);
    CHECK(lookups == 1);
    REQUIRE(answers.size() == 1);
    CHECK(answers[verdict.index].bytes[0] == 93); // the vetted (public) address is the target

    // And the mirror: a name whose FIRST answer is private is refused outright.
    lookups = 0;
    auto private_first = [&]() -> std::vector<ob::ResolvedAddress> {
        return ++lookups == 1 ? std::vector{addr4(169, 254, 169, 254)}
                              : std::vector{addr4(93, 184, 216, 34)};
    };
    CHECK(ob::vet_host(private_first, answers).status == ob::VetStatus::refused);
    CHECK(lookups == 1);
}

// ── Bounded regular-file hash ───────────────────────────────────────────────────────────────────

TEST_CASE("bounded_file_hash: the stream core caps bytes and honours the deadline", "[shared][bounded_hash]") {
    namespace sh = yuzu::shared;
    const std::string data(200 * 1024, 'x');
    auto reader_for = [&data](std::size_t& off) {
        return [&data, &off](unsigned char* buf, std::size_t len) -> long long {
            const auto n = std::min(len, data.size() - off);
            std::memcpy(buf, data.data() + off, n);
            off += n;
            return static_cast<long long>(n);
        };
    };
    const auto far = sh::HashClock::now() + std::chrono::hours(1);

    std::size_t off = 0;
    auto ok = sh::hash_stream_bounded(reader_for(off), data.size(), far);
    CHECK(ok.status == sh::HashStatus::ok);
    CHECK(ok.hex == sh::sha256_hex(data));

    off = 0;
    CHECK(sh::hash_stream_bounded(reader_for(off), data.size() - 1, far).status ==
          sh::HashStatus::oversize);

    off = 0;
    CHECK(sh::hash_stream_bounded(reader_for(off), data.size(),
                                  sh::HashClock::now() - std::chrono::seconds(1))
              .status == sh::HashStatus::timeout);

    auto failing = [](unsigned char*, std::size_t) -> long long { return -1; };
    CHECK(sh::hash_stream_bounded(failing, 1024, far).status == sh::HashStatus::unreadable);
}

#ifndef _WIN32

namespace {
int open_nonblock(const fs::path& p) {
    return ::open(p.c_str(), O_RDONLY | O_NONBLOCK | O_NOCTTY | O_CLOEXEC);
}
struct Fd {
    int fd;
    ~Fd() {
        if (fd >= 0) ::close(fd);
    }
};
} // namespace

TEST_CASE("bounded_file_hash: a regular file hashes while a FIFO or a directory or an oversize file refuse",
          "[shared][bounded_hash]") {
    namespace sh = yuzu::shared;
    yuzu::test::TempDir tmp{"yuzu_test_bfh_"};
    REQUIRE(fs::create_directory(tmp.path));
    const auto far = sh::HashClock::now() + std::chrono::hours(1);

    const auto file = tmp.path / "f.bin";
    {
        std::ofstream o(file, std::ios::binary);
        o << "hello world";
    }
    {
        Fd f{open_nonblock(file)};
        REQUIRE(f.fd >= 0);
        const auto r = sh::hash_fd_regular(f.fd, 1024, far);
        CHECK(r.status == sh::HashStatus::ok);
        CHECK(r.hex == sh::sha256_hex("hello world"));
    }
    {
        Fd f{open_nonblock(file)};
        REQUIRE(f.fd >= 0);
        CHECK(sh::hash_fd_regular(f.fd, 5, far).status == sh::HashStatus::oversize);
    }
    // A FIFO opens O_NONBLOCK without a writer and must be refused by fstat, never read (a read
    // of the old unbounded ifstream path would block the worker forever).
    const auto fifo = tmp.path / "p.fifo";
    REQUIRE(::mkfifo(fifo.c_str(), 0600) == 0);
    {
        Fd f{open_nonblock(fifo)};
        REQUIRE(f.fd >= 0);
        CHECK(sh::hash_fd_regular(f.fd, 1024, far).status == sh::HashStatus::not_regular);
    }
    {
        Fd f{open_nonblock(tmp.path)};
        REQUIRE(f.fd >= 0);
        CHECK(sh::hash_fd_regular(f.fd, 1024, far).status == sh::HashStatus::not_regular);
    }
}

// ── The real ioc plugin, end to end ─────────────────────────────────────────────────────────────

namespace {

fs::path find_plugin(const std::string& name) {
#if defined(__APPLE__)
    const std::string lib = name + ".dylib";
#else
    const std::string lib = name + ".so";
#endif
    std::vector<fs::path> candidates;
    if (auto* root = std::getenv("MESON_BUILD_ROOT"))
        candidates.emplace_back(fs::path{root} / "agents" / "plugins" / name / lib);
    candidates.emplace_back(fs::path{"agents"} / "plugins" / name / lib);
    candidates.emplace_back(fs::path{".."} / "agents" / "plugins" / name / lib);
    for (const auto& p : candidates) {
        std::error_code ec;
        if (fs::exists(p, ec) && !ec)
            return fs::absolute(p, ec);
    }
    return {};
}

} // namespace

TEST_CASE("ioc plugin: file_hashes over a FIFO returns promptly and reports the path not hashed",
          "[shared][local_path][ioc]") {
    auto path = find_plugin("ioc");
    if (path.empty()) {
        WARN("ioc plugin library not found -- skipping");
        return;
    }
    auto handle = yuzu::agent::PluginHandle::load(path);
    REQUIRE(handle.has_value());
    const auto* descriptor = handle->descriptor();
    REQUIRE(descriptor != nullptr);

    yuzu::test::TempDir tmp{"yuzu_test_iocfifo_"};
    REQUIRE(fs::create_directory(tmp.path));
    const auto fifo = tmp.path / "trap.fifo";
    REQUIRE(::mkfifo(fifo.c_str(), 0600) == 0);
    const auto regular = tmp.path / "real.txt";
    {
        std::ofstream o(regular, std::ios::binary);
        o << "hello world";
    }

    const std::string paths = fifo.string() + "," + regular.string();
    const std::string want = yuzu::shared::sha256_hex("hello world");
    std::vector<YuzuParam> params{{"file_hashes", want.c_str()}, {"file_paths", paths.c_str()}};

    yuzu::agent::LocalDispatcher dispatcher;
    // The old code opened the FIFO with std::ifstream and blocked the worker forever; the new code
    // opens non-blocking, fstat()s the descriptor and moves on. Reaching this line IS the test.
    const auto r = dispatcher.run(descriptor, "check", params);
    CHECK(r.rc == 0);
    // The regular file still matches: hashing each file once did not drop the good path.
    CHECK(r.captured.find("hash|" + want + "|true|") != std::string::npos);

    // With only the FIFO, the row must say a path was not hashed rather than read as a clean miss.
    const std::string only_fifo = fifo.string();
    std::vector<YuzuParam> p2{{"file_hashes", want.c_str()}, {"file_paths", only_fifo.c_str()}};
    const auto r2 = dispatcher.run(descriptor, "check", p2);
    CHECK(r2.rc == 0);
    CHECK(r2.captured.find("hash|" + want + "|false|") != std::string::npos);
    CHECK(r2.captured.find("1 path(s) not hashed") != std::string::npos);
}

TEST_CASE("ioc plugin: more file_paths than the cap is refused and not silently truncated",
          "[shared][local_path][ioc]") {
    auto path = find_plugin("ioc");
    if (path.empty()) {
        WARN("ioc plugin library not found -- skipping");
        return;
    }
    auto handle = yuzu::agent::PluginHandle::load(path);
    REQUIRE(handle.has_value());
    std::string many;
    for (int i = 0; i < 65; ++i)
        many += (i ? ",/nonexistent/yuzu_test_" : "/nonexistent/yuzu_test_") + std::to_string(i);
    std::vector<YuzuParam> params{{"file_paths", many.c_str()}};
    yuzu::agent::LocalDispatcher dispatcher;
    const auto r = dispatcher.run(handle->descriptor(), "check", params);
    CHECK(r.rc == 1);
    CHECK(r.captured.find("Too many file_paths") != std::string::npos);
}

TEST_CASE("http_client plugin: a name that resolves to loopback is blocked and a download writes nothing",
          "[shared][outbound][http_client]") {
    auto path = find_plugin("http_client");
    if (path.empty()) {
        WARN("http_client plugin library not found -- skipping");
        return;
    }
    auto handle = yuzu::agent::PluginHandle::load(path);
    REQUIRE(handle.has_value());
    yuzu::agent::LocalDispatcher dispatcher;

    // `localhost` resolves (from /etc/hosts) to loopback: refused on the ONE lookup, no connect.
    std::vector<YuzuParam> get_params{{"url", "http://localhost:1/"}};
    const auto g = dispatcher.run(handle->descriptor(), "get", get_params);
    CHECK(g.rc == 1);
    CHECK(g.captured.find("SSRF blocked") != std::string::npos);

    // A refused download leaves an existing destination exactly as it was and creates no sibling.
    yuzu::test::TempDir tmp{"yuzu_test_httpdl_"};
    REQUIRE(fs::create_directory(tmp.path));
    const auto dest = tmp.path / "payload.bin";
    {
        std::ofstream o(dest, std::ios::binary);
        o << "original";
    }
    const std::string dest_s = dest.string();
    std::vector<YuzuParam> dl{{"url", "http://localhost:1/x"},
                              {"path", dest_s.c_str()},
                              {"expected_hash", "00"}};
    const auto d = dispatcher.run(handle->descriptor(), "download", dl);
    CHECK(d.rc == 1);
    std::ifstream in(dest, std::ios::binary);
    std::string content((std::istreambuf_iterator<char>(in)), std::istreambuf_iterator<char>());
    CHECK(content == "original");
    std::size_t entries = 0;
    for ([[maybe_unused]] const auto& e : fs::directory_iterator(tmp.path))
        ++entries;
    CHECK(entries == 1);
}

TEST_CASE("disk_space plugin: a local path is still measured",
          "[shared][local_path][disk_space]") {
    auto path = find_plugin("disk_space");
    if (path.empty()) {
        WARN("disk_space plugin library not found -- skipping");
        return;
    }
    auto handle = yuzu::agent::PluginHandle::load(path);
    REQUIRE(handle.has_value());
    yuzu::test::TempDir tmp{"yuzu_test_disk_"};
    REQUIRE(fs::create_directory(tmp.path));
    const std::string where = tmp.path.string();
    std::vector<YuzuParam> params{{"path", where.c_str()}};
    yuzu::agent::LocalDispatcher dispatcher;
    const auto r = dispatcher.run(handle->descriptor(), "free", params);
    CHECK(r.rc == 0);
    CHECK(r.captured.find("disk|") != std::string::npos);
}

TEST_CASE("processes plugin: list_hashed hashes this process's own image through the exe link",
          "[shared][local_path][processes]") {
#ifdef __linux__
    auto path = find_plugin("processes");
    if (path.empty()) {
        WARN("processes plugin library not found -- skipping");
        return;
    }
    auto handle = yuzu::agent::PluginHandle::load(path);
    REQUIRE(handle.has_value());
    yuzu::agent::LocalDispatcher dispatcher;
    const auto r = dispatcher.run(handle->descriptor(), "list_hashed");
    CHECK(r.rc == 0);
    const std::string mine = "proc|" + std::to_string(::getpid()) + "|";
    const auto at = r.captured.find(mine);
    REQUIRE(at != std::string::npos);
    const auto eol = r.captured.find('\n', at);
    const std::string row = r.captured.substr(at, eol == std::string::npos ? std::string::npos : eol - at);
    // proc|pid|name|sha256|path -- the sha256 field is 64 lowercase hex characters.
    std::vector<std::string> f;
    for (std::size_t s = 0;;) {
        const auto bar = row.find('|', s);
        f.push_back(row.substr(s, bar == std::string::npos ? std::string::npos : bar - s));
        if (bar == std::string::npos) break;
        s = bar + 1;
    }
    REQUIRE(f.size() >= 5);
    CHECK(f[3].size() == 64);
    CHECK(f[3].find_first_not_of("0123456789abcdef") == std::string::npos);
#else
    SUCCEED("Linux-only: the exe-link hash path");
#endif
}

#endif // !_WIN32
