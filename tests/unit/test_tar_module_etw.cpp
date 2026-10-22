// test_tar_module_etw.cpp — M2 pure-logic + no-op coverage for the Windows ETW
// module-load collector. The LIVE ETW session (start/decode/WinVerifyTrust) needs
// a real Windows box (agent UAT) and is NOT unit-testable here — mirroring
// test_tar_proc_etw.cpp. What IS testable, and is pinned below: the ETW-sample →
// ModuleEvent mapping, the module_dir redaction (the M1 governance BLOCKING
// privacy edge-drop), the §5 risk-filter, the signing-verdict cache (with a fake
// verifier), and the off-Windows no-op contract. The Windows-only cases at the end drive
// the REAL no-reparse image open + by-handle WinVerifyTrust against files on the host.

#include "tar_db.hpp"
#include "tar_local_image_path.hpp"
#include "tar_module_etw.hpp"
#include "tar_module_stream.hpp"
#include "test_helpers.hpp"

#include <catch2/catch_test_macros.hpp>

#include <cstdint>
#include <filesystem>
#include <fstream>
#include <optional>
#include <string>
#include <string_view>
#include <type_traits>
#include <utility>
#include <vector>

#ifdef _WIN32
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>

#include <softpub.h>
#include <winioctl.h> // FSCTL_SET_EXTERNAL_BACKING, WOF_EXTERNAL_INFO, FILE_PROVIDER_*
#include <wintrust.h>

#include <win_str.hpp>
#endif

using namespace yuzu::tar;

// The collector owns a live ETW session — copying/moving/slicing it would sever
// that ownership. Pin the non-copyable/non-movable contract at compile time.
static_assert(!std::is_copy_constructible_v<ModuleEtwCollector>);
static_assert(!std::is_move_constructible_v<ModuleEtwCollector>);
static_assert(!std::is_copy_assignable_v<ModuleEtwCollector>);

// ── etw_image_sample_to_module_event ────────────────────────────────────────

TEST_CASE("ETW image sample maps to a ModuleEvent (path split, action, kernel)",
          "[tar][module][etw]") {
    EtwImageSample s;
    s.ts_unix = 1700000000;
    s.is_load = true;
    s.pid = 1234;
    s.image_path = R"(C:\Program Files\App\version.dll)";
    auto e = etw_image_sample_to_module_event(s);
    CHECK(e.ts_unix == 1700000000);
    CHECK(e.action == ModuleAction::kLoaded);
    CHECK(e.pid == 1234u);
    CHECK(e.module_name == "version.dll");
    CHECK(e.module_dir == R"(C:\Program Files\App)");
    CHECK_FALSE(e.is_kernel);
    CHECK(e.signed_state == ModuleSignedState::kUnknown); // resolved at drain
}

TEST_CASE("ETW image sample: unload action + forward-slash path", "[tar][module][etw]") {
    EtwImageSample s;
    s.is_load = false;
    s.pid = 9000;
    s.image_path = "/opt/app/libfoo.so"; // split is separator-agnostic
    auto e = etw_image_sample_to_module_event(s);
    CHECK(e.action == ModuleAction::kUnloaded);
    CHECK(e.module_name == "libfoo.so");
    CHECK(e.module_dir == "/opt/app");
}

TEST_CASE("ETW image sample: System/Idle pid is a kernel/driver load", "[tar][module][etw]") {
    for (std::uint32_t pid : {0u, 4u}) {
        EtwImageSample s;
        s.pid = pid;
        s.image_path = R"(C:\Windows\System32\drivers\bad.sys)";
        auto e = etw_image_sample_to_module_event(s);
        INFO("pid=" << pid);
        CHECK(e.is_kernel);
    }
    // pid 5 is the first non-kernel pid — pin the is_kernel = (pid <= 4) boundary.
    EtwImageSample user;
    user.pid = 5;
    user.image_path = R"(C:\x\y.dll)";
    CHECK_FALSE(etw_image_sample_to_module_event(user).is_kernel);
}

TEST_CASE("ETW image sample: no separator → whole string is basename", "[tar][module][etw]") {
    EtwImageSample s;
    s.image_path = "ntdll.dll";
    auto e = etw_image_sample_to_module_event(s);
    CHECK(e.module_name == "ntdll.dll");
    CHECK(e.module_dir.empty());
}

// ── redact_module_dir ───────────────────────────────────────────────────────
// The `[tar][module][redact]` cases for the shared sanitiser live in
// test_tar_module_stream.cpp (M1), which owns redact_module_dir() — duplicating
// the TEST_CASE names here would collide under Catch2's global registry.

// ── module_is_risky + apply_module_risk_filter ──────────────────────────────

namespace {
ModuleEvent make_signed(const std::string& proc, const std::string& mod, const std::string& signer) {
    ModuleEvent e;
    e.action = ModuleAction::kLoaded;
    e.process_name = proc;
    e.module_name = mod;
    e.signer = signer;
    e.signed_state = ModuleSignedState::kSigned;
    return e;
}
} // namespace

TEST_CASE("module_is_risky flags unsigned/invalid/revoked/kernel/blocked", "[tar][module][filter]") {
    ModuleEvent signed_user = make_signed("app.exe", "ok.dll", "Acme");
    CHECK_FALSE(module_is_risky(signed_user));

    ModuleEvent unsigned_mod = signed_user;
    unsigned_mod.signed_state = ModuleSignedState::kUnsigned;
    CHECK(module_is_risky(unsigned_mod));

    ModuleEvent invalid = signed_user;
    invalid.signed_state = ModuleSignedState::kInvalid;
    CHECK(module_is_risky(invalid));

    ModuleEvent revoked = signed_user;
    revoked.signed_state = ModuleSignedState::kRevoked;
    CHECK(module_is_risky(revoked));

    ModuleEvent kernel = signed_user;
    kernel.is_kernel = true;
    CHECK(module_is_risky(kernel));

    ModuleEvent blocked = signed_user;
    blocked.action = ModuleAction::kBlocked;
    CHECK(module_is_risky(blocked));
}

TEST_CASE("risk-filter keeps every risky load (no dedup for risky)", "[tar][module][filter]") {
    std::vector<ModuleEvent> in;
    for (int i = 0; i < 10; ++i) {
        ModuleEvent e = make_signed("p", "evil.dll", "");
        e.signed_state = ModuleSignedState::kUnsigned; // risky → all kept, even identical
        in.push_back(e);
    }
    auto out = apply_module_risk_filter(std::move(in));
    CHECK(out.size() == 10);
}

TEST_CASE("risk-filter dedups identical signed loads within a batch", "[tar][module][filter]") {
    std::vector<ModuleEvent> in;
    for (int i = 0; i < 50; ++i)
        in.push_back(make_signed("chrome.exe", "kernel32.dll", "Microsoft"));
    auto out = apply_module_risk_filter(std::move(in));
    CHECK(out.size() == 1); // one distinct (proc,module,dir,signer,state) signed tuple
}

TEST_CASE("risk-filter keeps same-named signed DLLs from DIFFERENT dirs distinct",
          "[tar][module][filter]") {
    // The DLL-search-order-hijack signal: version.dll in an app dir vs System32.
    auto app = make_signed("app.exe", "version.dll", "Acme");
    app.module_dir = R"(C:\Program Files\App)";
    auto sys = make_signed("app.exe", "version.dll", "Acme");
    sys.module_dir = R"(C:\Windows\System32)";
    std::vector<ModuleEvent> in{app, sys};
    auto out = apply_module_risk_filter(std::move(in));
    CHECK(out.size() == 2); // module_dir is in the dedup key — NOT collapsed
}

TEST_CASE("risk-filter routes signed kUnloaded through dedup", "[tar][module][filter]") {
    std::vector<ModuleEvent> in;
    for (int i = 0; i < 10; ++i) {
        auto e = make_signed("app.exe", "k.dll", "MS");
        e.action = ModuleAction::kUnloaded; // non-risky → deduped like loaded
        in.push_back(e);
    }
    auto out = apply_module_risk_filter(std::move(in));
    CHECK(out.size() == 1);
}

TEST_CASE("risk-filter keeps a signed load and its unload distinct", "[tar][module][filter]") {
    // The action is in the dedup key: a `loaded` and an `unloaded` of the SAME
    // (proc, module, dir, signer, state) tuple must NOT collapse, or unload
    // visibility in module_live is erased (the M2 review finding).
    auto loaded = make_signed("app.exe", "k.dll", "MS"); // action defaults to kLoaded
    auto unloaded = make_signed("app.exe", "k.dll", "MS");
    unloaded.action = ModuleAction::kUnloaded;
    std::vector<ModuleEvent> in{loaded, unloaded};
    auto out = apply_module_risk_filter(std::move(in));
    CHECK(out.size() == 2); // action in the key keeps load/unload as separate rows
}

TEST_CASE("risk-filter caps distinct signed loads per drain", "[tar][module][filter]") {
    std::vector<ModuleEvent> in;
    for (int i = 0; i < 20; ++i)
        in.push_back(make_signed("app.exe", "mod" + std::to_string(i) + ".dll", "Acme"));
    auto out = apply_module_risk_filter(std::move(in), /*max_signed=*/5);
    CHECK(out.size() == 5);
}

TEST_CASE("risk-filter keeps risky even past the signed cap", "[tar][module][filter]") {
    std::vector<ModuleEvent> in;
    for (int i = 0; i < 5; ++i) // fills the signed cap
        in.push_back(make_signed("app.exe", "s" + std::to_string(i) + ".dll", "Acme"));
    for (int i = 0; i < 3; ++i) { // risky → always kept
        ModuleEvent e = make_signed("app.exe", "u" + std::to_string(i) + ".dll", "");
        e.signed_state = ModuleSignedState::kUnsigned;
        in.push_back(e);
    }
    auto out = apply_module_risk_filter(std::move(in), /*max_signed=*/5);
    CHECK(out.size() == 8); // 5 signed + 3 risky
}

// ── SigningCache (injectable fake verifier) ─────────────────────────────────

TEST_CASE("SigningCache verifies on miss, caches on hit", "[tar][module][signcache]") {
    int calls = 0;
    ModuleVerifier fake = [&](const std::string&) {
        ++calls;
        ModuleSignVerdict v;
        v.state = ModuleSignedState::kSigned;
        v.signer = "Acme";
        return v;
    };
    SigningCache c;
    auto v1 = c.get(R"(C:\a\b.dll)", 100, fake);
    auto v2 = c.get(R"(C:\a\b.dll)", 100, fake); // hit — no second verify
    CHECK(calls == 1);
    CHECK(v1.state == ModuleSignedState::kSigned);
    CHECK(v2.signer == "Acme");
}

TEST_CASE("SigningCache re-verifies when mtime changes", "[tar][module][signcache]") {
    int calls = 0;
    ModuleVerifier fake = [&](const std::string&) {
        ++calls;
        return ModuleSignVerdict{};
    };
    SigningCache c;
    c.get(R"(C:\a\b.dll)", 100, fake);
    c.get(R"(C:\a\b.dll)", 200, fake); // file changed on disk → re-verify
    CHECK(calls == 2);
}

TEST_CASE("SigningCache null verifier yields kUnknown (never fabricates signed)",
          "[tar][module][signcache]") {
    SigningCache c;
    auto v = c.get(R"(C:\a\b.dll)", 1, nullptr);
    CHECK(v.state == ModuleSignedState::kUnknown);
    CHECK(v.signer.empty());
}

TEST_CASE("SigningCache is bounded", "[tar][module][signcache]") {
    ModuleVerifier fake = [](const std::string&) { return ModuleSignVerdict{}; };
    SigningCache c(4);
    for (int i = 0; i < 20; ++i)
        c.get("p" + std::to_string(i), i, fake);
    CHECK(c.size() <= 4);
}

TEST_CASE("SigningCache re-verifies an entry evicted by the bounded flush", "[tar][module][signcache]") {
    int calls = 0;
    ModuleVerifier fake = [&](const std::string&) { ++calls; return ModuleSignVerdict{}; };
    SigningCache c(1);     // cap 1 → a 2nd distinct path flushes the 1st
    c.get("A", 1, fake);   // verify #1, cache {A}
    c.get("B", 1, fake);   // miss → flush {A} → verify #2, cache {B}
    c.get("A", 1, fake);   // A was flushed → must re-verify (#3), not a stale hit
    CHECK(calls == 3);
}

// ── leaf reparse decision (pure; the Windows shell feeds it the handle's tag) ─

TEST_CASE("reparse_leaf_refused refuses name surrogates only", "[tar][module][etw]") {
    constexpr std::uint32_t kReparse = kFileAttributeReparsePoint;
    constexpr std::uint32_t kWof = 0x80000017;        // IO_REPARSE_TAG_WOF (CompactOS)
    constexpr std::uint32_t kDedup = 0x80000013;      // IO_REPARSE_TAG_DEDUP
    constexpr std::uint32_t kCloudFiles = 0x9000001A; // IO_REPARSE_TAG_CLOUD (placeholder)
    constexpr std::uint32_t kSymlink = 0xA000000C;    // IO_REPARSE_TAG_SYMLINK
    CHECK(reparse_leaf_refused(kReparse, kSymlink));
    CHECK(reparse_leaf_refused(kReparse, 0xA0000003)); // IO_REPARSE_TAG_MOUNT_POINT
    CHECK(reparse_leaf_refused(kReparse, 0x20000000)); // any other name-surrogate tag
    CHECK_FALSE(reparse_leaf_refused(kReparse, kWof));
    CHECK_FALSE(reparse_leaf_refused(kReparse, kDedup));
    CHECK_FALSE(reparse_leaf_refused(kReparse, kCloudFiles));
    // No reparse attribute: the tag field is not meaningful and never refuses.
    CHECK_FALSE(reparse_leaf_refused(0x80, kSymlink));
    CHECK_FALSE(reparse_leaf_refused(0, 0));
}

// ── no-op off-Windows contract ──────────────────────────────────────────────

#ifndef _WIN32
TEST_CASE("ModuleEtwCollector is a clean no-op off-Windows", "[tar][module][etw]") {
    ModuleEtwCollector c;
    CHECK_FALSE(c.start());
    CHECK_FALSE(c.running());
    CHECK(c.drain().empty());
    CHECK(c.dropped() == 0);
    CHECK(std::string(c.method_name()) == "etw");
    c.stop(); // safe without start
}
#endif

// ── Windows: no-reparse image open + by-handle verification (real files) ─────
// Needs a Windows host (system binaries, WinVerifyTrust, NTFS); compiled out elsewhere. A case
// SKIPs, naming why, where the account cannot create symbolic links or the volume refuses WOF.
#ifdef _WIN32

namespace {

constexpr DWORD kShareAll = FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE;

std::wstring system_dir() {
    wchar_t buf[MAX_PATH];
    const UINT n = GetSystemDirectoryW(buf, MAX_PATH);
    REQUIRE(n > 0);
    return std::wstring(buf, n);
}

// The NT path (`\Device\HarddiskVolumeN\...`) the IMAGE event would deliver for `win32`.
// FILE_FLAG_OPEN_REPARSE_POINT makes a link report ITS OWN path, not its target's.
std::string nt_path_of(const std::wstring& win32) {
    HANDLE h = CreateFileW(win32.c_str(), 0, kShareAll, nullptr, OPEN_EXISTING,
                           FILE_FLAG_OPEN_REPARSE_POINT | FILE_FLAG_BACKUP_SEMANTICS, nullptr);
    REQUIRE(h != INVALID_HANDLE_VALUE);
    std::wstring buf(1024, L'\0');
    const DWORD n =
        GetFinalPathNameByHandleW(h, buf.data(), static_cast<DWORD>(buf.size()), VOLUME_NAME_NT);
    CloseHandle(h);
    REQUIRE((n > 0 && n < buf.size()));
    buf.resize(n);
    return yuzu::win::from_wide(buf.c_str());
}

// The OLD by-name verdict (WinVerifyTrust on the Win32 path, the production status mapping):
// the oracle the by-handle verdict is compared against.
ModuleSignedState oracle_state(const std::wstring& win32) {
    GUID action = WINTRUST_ACTION_GENERIC_VERIFY_V2;
    WINTRUST_FILE_INFO fi{};
    fi.cbStruct = sizeof(fi);
    fi.pcwszFilePath = win32.c_str();
    WINTRUST_DATA wd{};
    wd.cbStruct = sizeof(wd);
    wd.dwUIChoice = WTD_UI_NONE;
    wd.fdwRevocationChecks = WTD_REVOKE_NONE;
    wd.dwUnionChoice = WTD_CHOICE_FILE;
    wd.pFile = &fi;
    wd.dwStateAction = WTD_STATEACTION_VERIFY;
    const LONG st = WinVerifyTrust(static_cast<HWND>(INVALID_HANDLE_VALUE), &action, &wd);
    wd.dwStateAction = WTD_STATEACTION_CLOSE;
    WinVerifyTrust(static_cast<HWND>(INVALID_HANDLE_VALUE), &action, &wd);
    switch (st) {
    case ERROR_SUCCESS:
        return ModuleSignedState::kSigned;
    case TRUST_E_NOSIGNATURE:
        return ModuleSignedState::kUnsigned;
    case static_cast<LONG>(CERT_E_REVOKED):
        return ModuleSignedState::kRevoked;
    case static_cast<LONG>(TRUST_E_BAD_DIGEST):
    case static_cast<LONG>(CERT_E_EXPIRED):
    case static_cast<LONG>(CERT_E_UNTRUSTEDROOT):
    case static_cast<LONG>(CERT_E_CHAINING):
    case static_cast<LONG>(TRUST_E_EXPLICIT_DISTRUST):
    case static_cast<LONG>(TRUST_E_SUBJECT_NOT_TRUSTED):
        return ModuleSignedState::kInvalid;
    default:
        return ModuleSignedState::kUnknown;
    }
}

// false: this account cannot create symbolic links (the caller SKIPs).
bool make_link(const std::wstring& link, const std::wstring& target, bool directory) {
    const DWORD flags = SYMBOLIC_LINK_FLAG_ALLOW_UNPRIVILEGED_CREATE |
                        (directory ? SYMBOLIC_LINK_FLAG_DIRECTORY : 0);
    if (CreateSymbolicLinkW(link.c_str(), target.c_str(), flags))
        return true;
    const DWORD err = GetLastError();
    if (err == ERROR_PRIVILEGE_NOT_HELD || err == ERROR_INVALID_PARAMETER)
        return false;
    FAIL("CreateSymbolicLinkW failed, error " << err);
    return false;
}

// First boot-critical system binary with an embedded Authenticode signature (kernel32.dll is
// catalog-signed and verifies as unsigned by this path), as {Win32 path, NT path}.
std::optional<std::pair<std::wstring, std::string>> first_signed_candidate() {
    for (const wchar_t* rel : {L"\\ntoskrnl.exe", L"\\ci.dll", L"\\drivers\\ntfs.sys"}) {
        const std::wstring w = system_dir() + rel;
        if (GetFileAttributesW(w.c_str()) != INVALID_FILE_ATTRIBUTES &&
            oracle_state(w) == ModuleSignedState::kSigned)
            return std::make_pair(w, nt_path_of(w));
    }
    return std::nullopt;
}

} // namespace

TEST_CASE("Windows module drain: a system image opens through the no-reparse handle",
          "[tar][module][etw][windows]") {
    const auto image = open_local_image_no_reparse(nt_path_of(system_dir() + L"\\kernel32.dll"));
    REQUIRE(image);
    CHECK(image_mtime_unix(image.get()) > 0);
}

TEST_CASE("Windows module drain: a FILE symlink is refused while the name still opens",
          "[tar][module][etw][windows]") {
    yuzu::test::TempDir dir{"yuzu_test_tar_nolink_"};
    std::filesystem::create_directories(dir.path);
    // Every link below is aimed at an empty DECOY inside the temp root, never at a real system
    // path, so no cleanup bug, however it recurses, can reach outside the temp root.
    const std::filesystem::path target = dir.path / L"decoy.dll";
    REQUIRE(std::ofstream{target}.is_open());
    const std::filesystem::path link = dir.path / L"decoy_link.dll";
    if (!make_link(link.wstring(), target.wstring(), false))
        SKIP("account cannot create symbolic links");
    REQUIRE(std::ifstream{link}.is_open()); // by name the link resolves
    CHECK_FALSE(open_local_image_no_reparse(nt_path_of(link.wstring())));
}

TEST_CASE("Windows module drain: an ancestor DIRECTORY symlink is refused",
          "[tar][module][etw][windows]") {
    yuzu::test::TempDir dir{"yuzu_test_tar_nolink_"};
    const std::filesystem::path decoy_dir = dir.path / L"decoy_dir";
    std::filesystem::create_directories(decoy_dir);
    REQUIRE(std::ofstream{decoy_dir / L"kernel32.dll"}.is_open());
    const std::filesystem::path link_dir = dir.path / L"decoy_dir_link";
    if (!make_link(link_dir.wstring(), decoy_dir.wstring(), true))
        SKIP("account cannot create symbolic links");
    REQUIRE(std::ifstream{link_dir / L"kernel32.dll"}.is_open()); // by name the link resolves
    // The LINK's own NT path plus the leaf, not the decoy's resolved path.
    CHECK_FALSE(open_local_image_no_reparse(nt_path_of(link_dir.wstring()) + "\\kernel32.dll"));
}

TEST_CASE("Windows module drain: the by-handle verdict equals the by-name verdict",
          "[tar][module][etw][windows]") {
    for (const wchar_t* rel :
         {L"\\ntoskrnl.exe", L"\\ci.dll", L"\\drivers\\ntfs.sys", L"\\kernel32.dll"}) {
        const std::wstring w = system_dir() + rel;
        if (GetFileAttributesW(w.c_str()) == INVALID_FILE_ATTRIBUTES)
            continue;
        const std::string nt = nt_path_of(w);
        const auto image = open_local_image_no_reparse(nt);
        REQUIRE(image);
        INFO("file=" << nt);
        CHECK(verify_image_signature_win(image.get(), nt).state == oracle_state(w));
    }
    const auto candidate = first_signed_candidate();
    REQUIRE(candidate.has_value()); // not vacuous: one embedded-signed binary exists
    const auto image = open_local_image_no_reparse(candidate->second);
    REQUIRE(image);
    const ModuleSignVerdict v = verify_image_signature_win(image.get(), candidate->second);
    CHECK(v.state == ModuleSignedState::kSigned);
    CHECK(v.signer == "Microsoft Windows"); // the production signing certificate's display name
}

TEST_CASE("Windows module drain: the verdict comes from the handle, not the name",
          "[tar][module][etw][windows]") {
    const auto candidate = first_signed_candidate();
    REQUIRE(candidate.has_value());
    const auto image = open_local_image_no_reparse(candidate->second);
    REQUIRE(image);
    CHECK(verify_image_signature_win(image.get(),
                                     R"(\Device\HarddiskVolume0\yuzu_test_does_not_exist.dll)")
              .state == ModuleSignedState::kSigned);
}

TEST_CASE("Windows module drain: a WOF-compressed image is not refused and still verifies",
          "[tar][module][etw][windows]") {
    const auto candidate = first_signed_candidate();
    REQUIRE(candidate.has_value());
    yuzu::test::TempDir dir{"yuzu_test_tar_wof_"};
    std::filesystem::create_directories(dir.path);
    const std::wstring copy = (dir.path / L"wof_copy.dll").wstring();
    REQUIRE(CopyFileW(candidate->first.c_str(), copy.c_str(), FALSE));
    SetFileAttributesW(copy.c_str(), FILE_ATTRIBUTE_NORMAL);

    struct WofBacking {
        WOF_EXTERNAL_INFO wof;
        FILE_PROVIDER_EXTERNAL_INFO_V1 file;
    };
    WofBacking in{};
    in.wof.Version = WOF_CURRENT_VERSION;
    in.wof.Provider = WOF_PROVIDER_FILE;
    in.file.Version = FILE_PROVIDER_CURRENT_VERSION;
    in.file.Algorithm = FILE_PROVIDER_COMPRESSION_XPRESS4K;
    HANDLE h = CreateFileW(copy.c_str(), GENERIC_READ | GENERIC_WRITE, kShareAll, nullptr,
                           OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
    REQUIRE(h != INVALID_HANDLE_VALUE);
    DWORD returned = 0;
    const BOOL compressed = DeviceIoControl(h, FSCTL_SET_EXTERNAL_BACKING, &in, sizeof(in),
                                            nullptr, 0, &returned, nullptr);
    // The case proves nothing unless the copy is WOF-backed. A plain attribute query cannot say
    // (the filter hides the reparse bit from a normal open), so ask the filter itself, on the
    // same handle.
    WofBacking backing{};
    const BOOL queried = compressed && DeviceIoControl(h, FSCTL_GET_EXTERNAL_BACKING, nullptr, 0,
                                                       &backing, sizeof(backing), &returned,
                                                       nullptr);
    CloseHandle(h);
    if (!compressed)
        SKIP("WOF unavailable on this volume");
    if (!queried || backing.wof.Provider != WOF_PROVIDER_FILE)
        SKIP("the copy is not WOF-backed on this volume");

    const std::string nt = nt_path_of(copy);
    const auto image = open_local_image_no_reparse(nt);
    REQUIRE(image); // a filter-handled tag is an ordinary image, not a name surrogate
    CHECK(verify_image_signature_win(image.get(), nt).state == ModuleSignedState::kSigned);
    CHECK(oracle_state(copy) == ModuleSignedState::kSigned);
}
#endif // _WIN32

// ── insert_module_events round-trip (the typed DB write path) ───────────────

TEST_CASE("insert_module_events round-trips every column into module_live",
          "[tar][module][store]") {
    yuzu::test::TempDbFile tmp{std::string_view{"tar-module-insert-"}};
    auto opened = TarDatabase::open(tmp.path);
    REQUIRE(opened.has_value());
    TarDatabase db = std::move(*opened);
    REQUIRE(db.create_warehouse_tables());

    std::vector<ModuleRow> rows;
    ModuleRow user_load;
    user_load.ts = 1700000000;
    user_load.snapshot_id = 7;
    user_load.action = "loaded";
    user_load.pid = 4321;
    user_load.process_name = "app.exe";
    user_load.module_name = "version.dll";
    user_load.module_dir = R"(C:\App)"; // already redacted by the collector
    user_load.signed_state = "unsigned";
    user_load.is_kernel = false;
    rows.push_back(user_load);

    ModuleRow driver;
    driver.ts = 1700000001;
    driver.snapshot_id = 7;
    driver.action = "loaded";
    driver.pid = 4;
    driver.process_name = ""; // kernel loads have no owning user process (real collector emits "")
    driver.module_name = "bad.sys";
    driver.module_dir = R"(C:\Windows\System32\drivers)";
    driver.signed_state = "revoked";
    driver.signer = "Sketchy LLC";
    driver.is_kernel = true;
    rows.push_back(driver);

    REQUIRE(db.insert_module_events(rows));

    auto q = db.execute_query(
        "SELECT action, pid, process_name, module_name, module_dir, signed_state, "
        "signer, is_kernel FROM module_live ORDER BY ts");
    REQUIRE(q.has_value());
    REQUIRE(q->rows.size() == 2);

    // Row 0 — the unsigned user-space load.
    CHECK(q->rows[0][0] == "loaded");
    CHECK(q->rows[0][1] == "4321");
    CHECK(q->rows[0][3] == "version.dll");
    CHECK(q->rows[0][5] == "unsigned");
    CHECK(q->rows[0][7] == "0");

    // Row 1 — the revoked kernel driver (the BYOVD signal).
    CHECK(q->rows[1][1] == "4");
    CHECK(q->rows[1][3] == "bad.sys");
    CHECK(q->rows[1][5] == "revoked");
    CHECK(q->rows[1][6] == "Sketchy LLC");
    CHECK(q->rows[1][7] == "1");

    // Empty batch is a successful no-op.
    CHECK(db.insert_module_events({}));
}
