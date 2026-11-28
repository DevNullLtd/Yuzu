/**
 * test_file_search_posix_shell.cpp -- the pieces of the file_search plugin that bind the operating system:
 * the thread-capability planner and (Linux, where the capability is permitted) its system calls and the
 * plugin's own worker environment and lookup hook, the macOS name rule and mount-table converter, and the
 * extents of real files. The driver, the volume plan and the rows are pure and are tested beside it
 * (test_file_search_driver.cpp and siblings) over fakes; the whole plugin, loaded, is
 * test_file_search_local_dispatcher.cpp.
 *
 * REAL FILES. The extent cases need a real filesystem: what a file's extents are is a fact of the volume it
 * is on. They live under the canonical build root (MESON_BUILD_ROOT, so not under /tmp, which is often tmpfs
 * on Linux and a link on macOS) in a yuzu_test_ directory that is removed afterwards. Where the volume does
 * not report extents the case says so and checks only that the answer is `unsupported`, never `failed`.
 *
 * MUTATION NOTES (each case FAILS if the named production rule is removed):
 *  - planner: dropping the permitted bit along with the effective one, raising a bit that is not permitted,
 *    or using the wrong word for a capability above 31 fails the planner cases.
 *  - macOS converter: reading a name field past its end, sign-extending the filesystem id, or keeping an
 *    entry with no mount point fails the converter cases; the plan case fails if the data volume stops being
 *    refused as firmlinks_only.
 *  - macOS names: skipping the NFC step, the case fold or the byte fallback for invalid UTF-8 fails the name
 *    cases; the matcher case fails if a pattern and a name no longer canonicalise to the same bytes.
 *  - extents: mapping a hole to an allocated extent, losing the compressed flag's role, or reading a
 *    failure as `unsupported` fails the shell cases; reporting `shared` for a file that is not a clone, or
 *    not reporting it for one, fails the clone case.
 *  - capability scope (Linux, bit permitted): not dropping the bit, or a raise that outlives its scope,
 *    fails the thread case; dropping it on every thread instead of the caller's fails the other-thread
 *    check. The worker case runs the plugin's own runner and hook (run_on_worker, around_lookup_hook): it
 *    fails if the worker environment stops dropping the bit, if the hook stops raising it or leaves it
 *    raised, or if the environment changes the calling thread's set.
 */
#include <catch2/catch_test_macros.hpp>

#include "file_search_execute.hpp"
#include "file_search_legs.hpp"
#include "file_search_test_support.hpp"
#include "file_search_volumes.hpp"
#include "test_helpers.hpp"

#include <file_search_query.hpp>
#include <linux_thread_caps.hpp>
#include <macos_network_mounts.hpp>
#include <network_fstype.hpp>

#include <algorithm>
#include <chrono>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <memory>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

#if !defined(_WIN32)
#include <fcntl.h>
#include <sys/mount.h>
#include <sys/resource.h>
#include <sys/stat.h>
#include <unistd.h>
#endif
#if defined(__linux__)
#include <sys/syscall.h>
#endif
#if defined(__APPLE__)
#include <sys/clonefile.h>
#endif
#if defined(__linux__)
#include <thread>
#endif

namespace fs = std::filesystem;
using namespace yuzu::file_search;
using yuzu::file_search_test::Fixture;
namespace caps = yuzu::shared::thread_caps;

// ---- the thread-capability planner (pure: runs on every host) ----

TEST_CASE("file_search thread caps: dropping clears only the effective bit and keeps it permitted",
          "[file_search][file_search_shell][file_search_caps]") {
    caps::ThreadCaps c;
    c.effective.set(caps::kCapDacReadSearch);
    c.permitted.set(caps::kCapDacReadSearch);
    c.effective.set(1); // another capability, untouched
    c.permitted.set(1);
    c.inheritable.set(caps::kCapDacReadSearch);

    CHECK(caps::plan_drop(c, caps::kCapDacReadSearch));
    CHECK_FALSE(c.effective.has(caps::kCapDacReadSearch));
    CHECK(c.permitted.has(caps::kCapDacReadSearch)); // kept permitted: this is hygiene, not a boundary
    CHECK(c.inheritable.has(caps::kCapDacReadSearch));
    CHECK(c.effective.has(1));
    CHECK(c.permitted.has(1));

    CHECK_FALSE(caps::plan_drop(c, caps::kCapDacReadSearch)); // already clear: nothing changed
}

TEST_CASE("file_search thread caps: a raise needs the bit permitted and changes only the effective set",
          "[file_search][file_search_shell][file_search_caps]") {
    caps::ThreadCaps none; // not permitted
    CHECK_FALSE(caps::plan_raise(none, caps::kCapDacReadSearch));
    CHECK_FALSE(none.effective.has(caps::kCapDacReadSearch));

    caps::ThreadCaps c;
    c.permitted.set(caps::kCapDacReadSearch);
    CHECK(caps::plan_raise(c, caps::kCapDacReadSearch));
    CHECK(c.effective.has(caps::kCapDacReadSearch));
    CHECK(c.permitted.has(caps::kCapDacReadSearch));
    CHECK_FALSE(caps::plan_raise(c, caps::kCapDacReadSearch)); // already effective: not this call's to undo
}

TEST_CASE("file_search thread caps: a capability above 31 lives in the second word, and an unknown one is inert",
          "[file_search][file_search_shell][file_search_caps]") {
    caps::CapBits b;
    b.set(33);
    CHECK(b.has(33));
    CHECK(b.word[0] == 0);
    CHECK(b.word[1] == (std::uint32_t{1} << 1));
    b.clear(33);
    CHECK_FALSE(b.has(33));

    b.set(64); // outside the two words: nothing is written and nothing reads as set
    CHECK_FALSE(b.has(64));
    CHECK(b.word[0] == 0);
    CHECK(b.word[1] == 0);
}

#if defined(__linux__)
TEST_CASE("file_search thread caps: on a thread the bit is dropped outside a raise and the other threads keep it",
          "[file_search][file_search_shell][file_search_caps]") {
    // The system calls act on the calling thread, so the cases run on a thread of their own and report
    // plain booleans back (Catch2 assertions are made on the test's own thread).
    const auto main_before = caps::detail::read_caps();
    REQUIRE(main_before.has_value());
    if (!main_before->permitted.has(caps::kCapDacReadSearch)) {
        WARN("file_search thread caps: CAP_DAC_READ_SEARCH is not permitted here, the capability system calls are not exercised");
        return;
    }

    struct Seen {
        bool dropped{false};
        bool clear_after_drop{false};
        bool permitted_after_drop{false};
        bool raised{false};
        bool set_inside{false};
        bool nested_raised{true};
        bool clear_after_scope{false};
        bool permitted_after_scope{false};
    } seen;
    std::thread worker([&seen] {
        seen.dropped = caps::drop_effective(caps::kCapDacReadSearch);
        if (const auto c = caps::detail::read_caps()) {
            seen.clear_after_drop = !c->effective.has(caps::kCapDacReadSearch);
            seen.permitted_after_drop = c->permitted.has(caps::kCapDacReadSearch);
        }
        {
            const caps::ScopedCapRaise raise;
            seen.raised = raise.raised();
            if (const auto c = caps::detail::read_caps())
                seen.set_inside = c->effective.has(caps::kCapDacReadSearch);
            const caps::ScopedCapRaise nested; // already effective: this one raises nothing and drops nothing
            seen.nested_raised = nested.raised();
        }
        if (const auto c = caps::detail::read_caps()) {
            seen.clear_after_scope = !c->effective.has(caps::kCapDacReadSearch);
            seen.permitted_after_scope = c->permitted.has(caps::kCapDacReadSearch);
        }
    });
    worker.join();

    CHECK(seen.dropped);
    CHECK(seen.clear_after_drop);
    CHECK(seen.permitted_after_drop);
    CHECK(seen.raised);
    CHECK(seen.set_inside);
    CHECK_FALSE(seen.nested_raised);
    CHECK(seen.clear_after_scope);
    CHECK(seen.permitted_after_scope);

    const auto main_after = caps::detail::read_caps();
    REQUIRE(main_after.has_value());
    CHECK(main_after->effective.has(caps::kCapDacReadSearch) == main_before->effective.has(caps::kCapDacReadSearch));
}

TEST_CASE("file_search worker environment: the plugin's own runner drops the bit and its own hook raises it for a lookup only",
          "[file_search][file_search_shell][file_search_caps]") {
    // What the plugin does on its worker, not what the primitives can do: the work function runs through
    // run_on_worker (the environment the driver's BoundedRunner is bound to) and the lookup through
    // around_lookup_hook (the hook the search leg is given). Everything is read from inside the worker and
    // handed back as plain booleans (Catch2 assertions are made on the test's own thread).
    const auto main_before = caps::detail::read_caps();
    REQUIRE(main_before.has_value());
    if (!main_before->permitted.has(caps::kCapDacReadSearch)) {
        WARN("file_search worker environment: CAP_DAC_READ_SEARCH is not permitted here, the capability scope is not exercised");
        return;
    }
    const auto hook = around_lookup_hook();
    REQUIRE(static_cast<bool>(hook));

    struct Seen {
        bool reads_ok{true}; // every capget the worker made answered
        bool clear_before_lookup{false};
        bool permitted_before_lookup{false};
        bool set_inside_lookup{false};
        bool clear_after_lookup{false};
        bool permitted_after_lookup{false};
    };
    const auto seen = std::make_shared<Seen>(); // co-owned: a worker that timed out would outlive this frame
    const auto out = run_on_worker(std::chrono::seconds{60}, [seen, hook]() -> WorkResult {
        const auto read = [&seen] { // a failed capget reads as empty sets and clears reads_ok
            const auto c = caps::detail::read_caps();
            if (!c)
                seen->reads_ok = false;
            return c.value_or(caps::ThreadCaps{});
        };
        const caps::ThreadCaps before = read();
        seen->clear_before_lookup = !before.effective.has(caps::kCapDacReadSearch);
        seen->permitted_before_lookup = before.permitted.has(caps::kCapDacReadSearch);
        hook([&] { seen->set_inside_lookup = read().effective.has(caps::kCapDacReadSearch); });
        const caps::ThreadCaps after = read();
        seen->clear_after_lookup = !after.effective.has(caps::kCapDacReadSearch);
        seen->permitted_after_lookup = after.permitted.has(caps::kCapDacReadSearch);
        return WorkResult{};
    });

    REQUIRE(out.status == RunStatus::completed);
    REQUIRE(out.value.has_value());
    CHECK_FALSE(out.value->threw);
    CHECK(seen->reads_ok);
    CHECK(seen->clear_before_lookup);
    CHECK(seen->permitted_before_lookup);
    CHECK(seen->set_inside_lookup);
    CHECK(seen->clear_after_lookup);
    CHECK(seen->permitted_after_lookup);

    const auto main_after = caps::detail::read_caps();
    REQUIRE(main_after.has_value());
    CHECK(main_after->effective.has(caps::kCapDacReadSearch) == main_before->effective.has(caps::kCapDacReadSearch));
}
#endif

#if !defined(_WIN32)

namespace {

void write_file(const fs::path& p, std::size_t bytes) {
    std::ofstream out(p, std::ios::binary);
    const std::string block(4096, 'x');
    for (std::size_t done = 0; done < bytes; done += block.size())
        out.write(block.data(), static_cast<std::streamsize>(std::min(block.size(), bytes - done)));
}

/// The extents of `p`, read exactly as the match path reads them: opened without following a link and
/// without blocking, never read.
FileExtents extents_of(const fs::path& p) {
    const int fd = ::open(p.c_str(), O_RDONLY | O_NONBLOCK | O_NOFOLLOW);
    REQUIRE(fd >= 0);
    struct stat st {};
    REQUIRE(::fstat(fd, &st) == 0);
    FileExtents x = read_file_extents(fd, st);
    ::close(fd);
    return x;
}

bool on_apfs(const fs::path& p) {
#if defined(__APPLE__)
    struct statfs s {};
    return ::statfs(p.c_str(), &s) == 0 && std::string_view{s.f_fstypename} == "apfs";
#else
    (void)p;
    return false;
#endif
}

std::uint64_t listed_length(const FileExtents& x) {
    std::uint64_t sum = 0;
    for (const auto& e : x.extents)
        sum += e.length;
    return sum;
}

} // namespace

// ---- the worker's I/O class ----

TEST_CASE("file_search worker environment: the work function runs at the background I/O class",
          "[file_search][file_search_shell][file_search_io]") {
    // The class is a per-thread setting made with bare numbers, so a wrong one would run fleet searches at
    // normal priority with nothing to show it. Read it back from inside the work function, and hand it out
    // as a plain int (Catch2 assertions are made on the test's own thread).
    const auto seen = std::make_shared<int>(-1);
    const auto out = run_on_worker(std::chrono::seconds{60}, [seen]() -> WorkResult {
#if defined(__linux__)
        const long v = ::syscall(SYS_ioprio_get, 1 /* IOPRIO_WHO_PROCESS */, 0 /* the calling thread */);
        *seen = v < 0 ? -1 : static_cast<int>(v >> 13); // the class bits of the priority value
#else
        *seen = ::getiopolicy_np(IOPOL_TYPE_DISK, IOPOL_SCOPE_THREAD);
#endif
        return WorkResult{};
    });
    REQUIRE(out.status == RunStatus::completed);
    REQUIRE(out.value.has_value());
    CHECK_FALSE(out.value->threw);
    if (*seen < 0) {
        WARN("file_search worker environment: the I/O class could not be read here, it is not checked");
        return;
    }
#if defined(__linux__)
    CHECK(*seen == 3); // IOPRIO_CLASS_IDLE
#else
    CHECK(*seen == IOPOL_THROTTLE);
#endif
}

// ---- the extents shell over real descriptors ----

TEST_CASE("file_search extents shell: the state follows the errno of the call and, on macOS, the compressed flag",
          "[file_search][file_search_shell][file_search_extents]") {
    // A character device has no extents: the call answers ENOTTY (Linux) or ENOTSUP (macOS), the filesystem
    // not reporting them. A descriptor that is not open answers EBADF, a real failure.
    const int dev_null = ::open("/dev/null", O_RDONLY);
    REQUIRE(dev_null >= 0);
    struct stat st {};
    st.st_size = 10;
    CHECK(read_file_extents(dev_null, st).state == ExtentsState::unsupported);
#if defined(__APPLE__)
    // ENOTSUP on a file the filesystem keeps compressed is `compressed`, not `unsupported`.
    st.st_flags = UF_COMPRESSED;
    CHECK(read_file_extents(dev_null, st).state == ExtentsState::compressed);
    st.st_flags = 0;
#endif
    ::close(dev_null);

    const FileExtents bad = read_file_extents(-1, st);
    CHECK(bad.state == ExtentsState::failed);
    CHECK(bad.extents.empty());
    CHECK(bad.total == 0);
}

TEST_CASE("file_search extents shell: a dense, an empty and a sparse file read as the volume lays them out",
          "[file_search][file_search_shell][file_search_extents]") {
    Fixture fx{"yuzu_test_fs_shell_"};
    const fs::path dense = fx.root / "dense.bin";
    const fs::path empty = fx.root / "empty.bin";
    const fs::path hole = fx.root / "hole.bin";
    const fs::path sparse = fx.root / "sparse.bin";
    constexpr std::size_t kDense = 1024 * 1024;
    constexpr std::uintmax_t kLong = 64u * 1024 * 1024; // long enough that a volume keeps the gap as a hole
    write_file(dense, kDense);
    write_file(empty, 0);
    write_file(hole, 0);
    fs::resize_file(hole, kLong); // all hole: no byte was ever written
    write_file(sparse, 0);
    fs::resize_file(sparse, kLong);
    {
        std::fstream out(sparse, std::ios::in | std::ios::out | std::ios::binary); // 4 KiB written in the middle
        out.seekp(static_cast<std::streamoff>(kLong / 2));
        out << std::string(4096, 'y');
    }

    const FileExtents d = extents_of(dense);
    REQUIRE((d.state == ExtentsState::ok || d.state == ExtentsState::unsupported));
    if (d.state == ExtentsState::unsupported) {
        WARN("file_search extents: this volume does not report extents; the dense, empty and sparse checks are skipped");
        return;
    }
    CHECK(d.total >= 1);
    CHECK(d.total_exact);
    REQUIRE_FALSE(d.extents.empty());
    CHECK(d.extents.front().logical == 0);
    CHECK((d.extents.front().flags & kUnallocated) == 0);
    CHECK(listed_length(d) >= kDense); // allocation rounds up to blocks on some filesystems, never down
#if defined(__APPLE__)
    CHECK(listed_length(d) == kDense); // the macOS answer is the file's own byte range
#endif

    const FileExtents e = extents_of(empty);
    CHECK(e.state == ExtentsState::ok);
    CHECK(e.total == 0);
    CHECK(e.total_exact);
    CHECK(e.extents.empty());

    const FileExtents h = extents_of(hole);
    REQUIRE(h.state == ExtentsState::ok);
    CHECK(h.total_exact);
    const FileExtents s = extents_of(sparse);
    REQUIRE(s.state == ExtentsState::ok);
    CHECK(s.total_exact);
    CHECK(s.total >= 1);
    CHECK(std::ranges::any_of(s.extents, [](const Extent& x) { return (x.flags & kUnallocated) == 0; }));
    if (on_apfs(fx.root)) {
        // APFS reports the holes. A file never written is one unallocated extent over its whole length with
        // no physical offset; the written block splits the sparse file's range around allocated extents,
        // and the extents together cover the whole file.
        REQUIRE(h.extents.size() == 1);
        CHECK(h.total == 1);
        CHECK((h.extents[0].flags & kUnallocated) != 0);
        CHECK(h.extents[0].physical == 0);
        CHECK(h.extents[0].length == kLong);
        CHECK(std::ranges::any_of(s.extents, [](const Extent& x) { return (x.flags & kUnallocated) != 0; }));
        for (const auto& x : s.extents)
            if ((x.flags & kUnallocated) != 0)
                CHECK(x.physical == 0);
        CHECK(listed_length(s) == kLong);
    }
#if defined(__linux__)
    // Linux's interface lists data extents only: a file never written has none.
    CHECK(h.total == 0);
#endif
}

#if defined(__APPLE__)
TEST_CASE("file_search extents shell: a clone shares all its blocks and a plain file shares none",
          "[file_search][file_search_shell][file_search_extents]") {
    Fixture fx{"yuzu_test_fs_shell_"};
    const fs::path original = fx.root / "original.bin";
    const fs::path plain = fx.root / "plain.bin";
    const fs::path clone = fx.root / "clone.bin";
    write_file(original, 256 * 1024);
    write_file(plain, 256 * 1024);

    const FileExtents before = extents_of(original);
    REQUIRE((before.state == ExtentsState::ok || before.state == ExtentsState::unsupported));
    if (before.state != ExtentsState::ok || ::clonefile(original.c_str(), clone.c_str(), 0) != 0) {
        WARN("file_search extents: this volume cannot clone or does not report extents; the shared check is skipped");
        return;
    }
    for (const auto* p : {&original, &clone}) {
        const FileExtents x = extents_of(*p);
        REQUIRE(x.state == ExtentsState::ok);
        REQUIRE_FALSE(x.extents.empty());
        for (const auto& e : x.extents)
            CHECK((e.flags & kShared) != 0);
    }
    const FileExtents p = extents_of(plain);
    REQUIRE(p.state == ExtentsState::ok);
    for (const auto& e : p.extents)
        CHECK((e.flags & kShared) == 0);
}
#endif

// ---- the name rule of each OS ----

TEST_CASE("file_search names: the rule of this OS is named and compiles a pattern",
          "[file_search][file_search_shell][file_search_names]") {
    const fsr::NameSemantics sem = os_name_semantics();
#if defined(__APPLE__)
    CHECK(sem.id == "macos_nfc_casefold_v1");
#else
    CHECK(sem.id == "bytes");
    // Byte for byte: a case difference is a different name.
    const auto p = fsr::Pattern::compile("yuzu-fs-ctl*", sem);
    REQUIRE(p.has_value());
    CHECK(p->evaluate("yuzu-fs-ctl-1") == fsr::Match::yes);
    CHECK(p->evaluate("Yuzu-fs-ctl-1") == fsr::Match::no);
#endif
}

#if defined(__APPLE__)
TEST_CASE("file_search names: macOS folds ASCII inline and normalises and folds everything else",
          "[file_search][file_search_shell][file_search_names]") {
    CHECK(macos_canonical_name("Yuzu-FS-Ctl.BIN") == "yuzu-fs-ctl.bin");
    CHECK(macos_canonical_name("") == "");

    // NFC and NFD spellings of one name, in either case, compare as the same bytes.
    const std::string nfc = "Caf\xC3\xA9";        // e acute, one scalar
    const std::string nfd = "Cafe\xCC\x81";       // e then a combining acute
    const std::string upper = "CAF\xC3\x89";      // E acute, upper case
    CHECK(macos_canonical_name(nfc) == macos_canonical_name(nfd));
    CHECK(macos_canonical_name(nfc) == macos_canonical_name(upper));
    CHECK(macos_canonical_name(nfc) != nfc.substr(0, 3));

    // Not well-formed UTF-8 compares as the bytes it is, in any case.
    const std::string broken = "AB\xFF\xFE" "cd";
    CHECK(macos_canonical_name(broken) == broken);

    // The canonicaliser adds no wildcard: a name with none yields none.
    for (const auto& n : {nfc, nfd, upper, std::string{"a b"}}) {
        const std::string c = macos_canonical_name(n);
        CHECK(c.find('*') == std::string::npos);
        CHECK(c.find('?') == std::string::npos);
    }
}

TEST_CASE("file_search names: a macOS pattern in one spelling and case matches a name in another",
          "[file_search][file_search_shell][file_search_names]") {
    const fsr::NameSemantics sem = os_name_semantics();
    const auto p = fsr::Pattern::compile("CAF\xC3\x89-yuzu-ctl*", sem); // upper case, composed
    REQUIRE(p.has_value());
    CHECK(p->evaluate("cafe\xCC\x81-yuzu-ctl-1.bin") == fsr::Match::yes); // lower case, decomposed
    CHECK(p->evaluate("Caf\xC3\xA9-yuzu-ctl") == fsr::Match::yes);
    CHECK(p->evaluate("cafe-yuzu-ctl-1.bin") == fsr::Match::no); // no accent: a different name
    CHECK(p->semantics_id() == "macos_nfc_casefold_v1");
}

// ---- the mount table of macOS as plan input ----

namespace {

void fill_field(char* field, std::size_t size, const char* text) {
    std::memset(field, 0, size);
    std::strncpy(field, text, size - 1);
}

struct statfs entry(const char* on, const char* type, const char* from, std::int32_t fsid0, std::int32_t fsid1) {
    struct statfs s {};
    fill_field(s.f_mntonname, sizeof s.f_mntonname, on);
    fill_field(s.f_fstypename, sizeof s.f_fstypename, type);
    fill_field(s.f_mntfromname, sizeof s.f_mntfromname, from);
    s.f_fsid.val[0] = fsid0;
    s.f_fsid.val[1] = fsid1;
    return s;
}

} // namespace

TEST_CASE("file_search macOS mounts: statfs entries become mount rows in table order, with the id read unsigned",
          "[file_search][file_search_shell][file_search_mounts]") {
    struct statfs t[3] = {entry("/", "apfs", "/dev/disk3s1s1", 0x1000010, 0x19),
                          entry("/System/Volumes/Data", "apfs", "/dev/disk3s5", -2, 0x19), entry("", "apfs", "x", 1, 1)};
    const yuzu::shared::MountTable m = yuzu::shared::macos_mount_entries(t, 3);
    REQUIRE(m.entries.size() == 2);
    CHECK(m.malformed == 1); // the entry with no mount point yields no row
    CHECK(m.entries[0].mount_point == "/");
    CHECK(m.entries[0].root == "/");
    CHECK(m.entries[0].fstype == "apfs");
    CHECK(m.entries[0].source == "/dev/disk3s1s1");
    CHECK(m.entries[0].dev_major == 0x1000010u);
    CHECK(m.entries[0].dev_minor == 0x19u);
    CHECK(m.entries[1].mount_point == "/System/Volumes/Data");
    CHECK(m.entries[1].dev_major == 0xFFFFFFFEu); // zero-extended, never sign-extended into a 64-bit value
}

TEST_CASE("file_search macOS mounts: a name field with no terminator is read to its end and no further",
          "[file_search][file_search_shell][file_search_mounts]") {
    struct statfs t[1] = {};
    std::memset(t[0].f_mntonname, 'a', sizeof t[0].f_mntonname); // every byte set: no NUL
    t[0].f_mntonname[0] = '/';
    std::strcpy(t[0].f_fstypename, "apfs");
    const yuzu::shared::MountTable m = yuzu::shared::macos_mount_entries(t, 1);
    REQUIRE(m.entries.size() == 1);
    CHECK(m.entries[0].mount_point.size() == sizeof t[0].f_mntonname);
}

TEST_CASE("file_search macOS mounts: a realistic table plans the system volume and refuses the data volume as firmlinks_only",
          "[file_search][file_search_shell][file_search_mounts]") {
    struct statfs t[4] = {entry("/", "apfs", "/dev/disk3s1s1", 0x1000010, 0x19),
                          entry("/System/Volumes/Data", "apfs", "/dev/disk3s5", 0x1000011, 0x19),
                          entry("/System/Volumes/VM", "apfs", "/dev/disk3s6", 0x1000012, 0x19),
                          entry("/dev", "devfs", "devfs", 0x1000013, 0x13)};
    const VolumePlan plan = build_plan(yuzu::shared::macos_mount_entries(t, 4), "/", Os::macos);
    REQUIRE(plan.valid);
    REQUIRE(plan.units.size() == 2);
    CHECK(plan.units[0].mount_point == "/");
    CHECK(plan.units[1].mount_point == "/System/Volumes/VM");
    REQUIRE(plan.refused.size() == 2);
    for (const auto& r : plan.refused) {
        if (r.mount_point == "/System/Volumes/Data")
            CHECK(r.reason == fsr::Reason::firmlinks_only);
        else
            CHECK(r.reason == fsr::Reason::fstype_not_allowed);
    }
}
#endif // __APPLE__

#endif // !_WIN32
