// test_tar_module_etw.cpp — M2 pure-logic + no-op coverage for the Windows ETW
// module-load collector. The LIVE ETW session (start/decode/WinVerifyTrust) needs
// a real Windows box (agent UAT) and is NOT unit-testable here — mirroring
// test_tar_proc_etw.cpp. What IS testable, and is pinned below: the ETW-sample →
// ModuleEvent mapping, the module_dir redaction (the M1 governance BLOCKING
// privacy edge-drop), the §5 risk-filter, the signing-verdict cache (with a fake
// verifier), and the off-Windows no-op contract.

#include "tar_db.hpp"
#include "tar_module_etw.hpp"
#include "tar_module_stream.hpp"
#include "test_helpers.hpp"
#include "test_tar_db_helpers.hpp"

#include <catch2/catch_test_macros.hpp>

#include <cstdint>
#include <string>
#include <string_view>
#include <type_traits>
#include <vector>

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

// ── insert_module_events round-trip (the typed DB write path) ───────────────

TEST_CASE("insert_module_events round-trips every column into module_live",
          "[tar][module][store]") {
    yuzu::test::TempDbFile tmp{std::string_view{"yuzu_test_tar_module_insert_"}};
    auto opened = yuzu::test::open_tar_test_db(tmp.path);
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
