/**
 * test_privacy_permissions_win_walk.cpp -- regression locks for the privacy_permissions Windows
 * leg's two injectable seams, on every host:
 *   - privacy_permissions_win_walk.hpp: the ConsentStore walk over a fake RegistryReader;
 *   - privacy_permissions_hive_guard.hpp: the offline-hive file guard over a fake HiveFileProbe.
 * Both headers are windows.h-free, so nothing here touches a real registry, file, process or
 * clock: the fakes are in-memory trees and scripted tables, and every deadline is injected.
 */
#include <catch2/catch_test_macros.hpp>

#include "privacy_permissions_hive_guard.hpp"
#include "privacy_permissions_win_walk.hpp"

#include <algorithm>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <deque>
#include <map>
#include <memory>
#include <string>
#include <type_traits>
#include <utility>
#include <vector>

using namespace yuzu::privacy_permissions;

namespace {

// ── fake registry ───────────────────────────────────────────────────────

struct FakeValue {
    std::uint32_t type = win::kRegSz;
    std::vector<std::byte> bytes;
    bool more_data_on_read = false; // the size probe succeeds; the real read says ERROR_MORE_DATA
};

struct FakeNode {
    std::vector<std::pair<std::wstring, FakeNode*>> children; // counted names, in enumeration order
    std::map<std::wstring, FakeValue> values;
};

wchar_t fold(wchar_t c) { return (c >= L'A' && c <= L'Z') ? static_cast<wchar_t>(c + 32) : c; }

bool ascii_ieq(std::wstring_view a, std::wstring_view b) {
    return a.size() == b.size() &&
           std::equal(a.begin(), a.end(), b.begin(),
                      [](wchar_t x, wchar_t y) { return fold(x) == fold(y); });
}

std::vector<std::byte> sz16(std::string_view ascii) { // UTF-16LE + NUL, as REG_SZ stores it
    std::vector<std::byte> out;
    for (const char c : ascii) {
        out.push_back(static_cast<std::byte>(c));
        out.push_back(std::byte{0});
    }
    out.push_back(std::byte{0});
    out.push_back(std::byte{0});
    return out;
}

std::vector<std::byte> qword(std::uint64_t v) {
    std::vector<std::byte> out(sizeof v);
    std::memcpy(out.data(), &v, sizeof v);
    return out;
}

struct FakeWatch final : win::ConsentStoreWatch {
    unsigned long wait_rc;
    explicit FakeWatch(unsigned long rc) : wait_rc(rc) {}
    win::StabilityFacts poll() override { return {0, 0, wait_rc, 0}; }
};

struct FakeRegistry final : win::RegistryReader {
    std::deque<FakeNode> nodes;
    FakeNode* root = nullptr;
    std::vector<unsigned long> watch_script; // poll result of the Nth watch; timeout past the end
    std::size_t watches = 0, opens = 0, closes = 0, enum_calls = 0;
    std::uint32_t max_enum_idx = 0;
    std::vector<std::wstring> opened_names;
    mutable std::vector<std::pair<std::wstring, std::wstring>> name_compares;

    FakeRegistry() { root = &nodes.emplace_back(); }

    FakeNode* child(FakeNode* parent, std::wstring_view name) {
        for (auto& [n, c] : parent->children)
            if (ascii_ieq(n, name)) return c;
        return nullptr;
    }
    /// Creates (or finds) `parent\a\b\c`, one level per backslash-separated part.
    FakeNode* path(FakeNode* parent, std::wstring_view p) {
        FakeNode* cur = parent;
        while (!p.empty()) {
            const auto cut = p.find(L'\\');
            const auto part = p.substr(0, cut);
            FakeNode* next = child(cur, part);
            if (!next) {
                next = &nodes.emplace_back();
                cur->children.emplace_back(std::wstring{part}, next);
            }
            cur = next;
            p = cut == std::wstring_view::npos ? std::wstring_view{} : p.substr(cut + 1);
        }
        return cur;
    }
    /// Adds a child with an exact (possibly NUL-bearing or empty) counted name, no path parsing.
    FakeNode* add_raw(FakeNode* parent, std::wstring name) {
        FakeNode* n = &nodes.emplace_back();
        parent->children.emplace_back(std::move(name), n);
        return n;
    }
    static void set(FakeNode* n, const wchar_t* name, FakeValue v) {
        n->values[name] = std::move(v);
    }
    static void set_sz(FakeNode* n, std::string_view v) {
        set(n, L"Value", {win::kRegSz, sz16(v), false});
    }
    FakeNode* store() { return path(root, std::wstring{win::kConsentStorePath}); }

    long open_key(win::RegKeyHandle parent, const wchar_t* name, win::RegKeyHandle& out) override {
        FakeNode* cur = static_cast<FakeNode*>(parent);
        std::wstring_view rest = name;
        while (!rest.empty()) {
            const auto cut = rest.find(L'\\');
            cur = child(cur, rest.substr(0, cut));
            if (!cur) return win::kErrorFileNotFound;
            rest = cut == std::wstring_view::npos ? std::wstring_view{} : rest.substr(cut + 1);
        }
        ++opens;
        opened_names.emplace_back(name);
        out = cur;
        return win::kErrorSuccess;
    }
    void close_key(win::RegKeyHandle) override { ++closes; }
    long enum_key(win::RegKeyHandle parent, std::uint32_t idx, std::wstring& name) override {
        ++enum_calls;
        max_enum_idx = (std::max)(max_enum_idx, idx);
        const auto* n = static_cast<FakeNode*>(parent);
        if (idx >= n->children.size()) return win::kErrorNoMoreItems;
        name = n->children[idx].first;
        return win::kErrorSuccess;
    }
    long query_value(win::RegKeyHandle key, const wchar_t* value_name, std::uint32_t& type,
                     std::span<std::byte> buf, std::uint32_t& size) override {
        auto* n = static_cast<FakeNode*>(key);
        for (auto& [vn, v] : n->values) {
            if (!ascii_ieq(vn, value_name)) continue;
            type = v.type;
            size = static_cast<std::uint32_t>(v.bytes.size());
            if (buf.empty()) return win::kErrorSuccess; // the size probe
            if (v.more_data_on_read || buf.size() < v.bytes.size()) {
                size = static_cast<std::uint32_t>(v.bytes.size() + 8);
                return win::kErrorMoreData;
            }
            std::memcpy(buf.data(), v.bytes.data(), v.bytes.size());
            return win::kErrorSuccess;
        }
        return win::kErrorFileNotFound;
    }
    std::unique_ptr<win::ConsentStoreWatch> watch(win::RegKeyHandle) override {
        const unsigned long rc =
            watches < watch_script.size() ? watch_script[watches] : win::kWaitTimeout;
        ++watches;
        return std::make_unique<FakeWatch>(rc);
    }
    // A documented approximation of CompareStringOrdinal(..., TRUE): ASCII case folding only.
    bool key_name_equals(std::wstring_view a, std::wstring_view b) const override {
        name_compares.emplace_back(std::wstring{a}, std::wstring{b});
        return ascii_ieq(a, b);
    }
    std::string utf8(std::wstring_view s) const override {
        std::string out;
        for (const wchar_t c : s) out.push_back(c < 0x80 ? static_cast<char>(c) : '?');
        return out;
    }
    std::string reg_sz_utf8(std::span<const std::byte> payload) const override {
        std::string out;
        for (std::size_t i = 0; i + 1 < payload.size(); i += 2) {
            const auto lo = static_cast<unsigned>(payload[i]);
            const auto hi = static_cast<unsigned>(payload[i + 1]);
            if (lo == 0 && hi == 0) break;
            out.push_back(hi == 0 && lo < 0x80 ? static_cast<char>(lo) : '?');
        }
        return out;
    }
};

const win::RawGrant* find(const std::vector<win::RawGrant>& v, std::string_view app,
                          std::string_view cat) {
    for (const auto& g : v)
        if (g.app_id == app && g.category == cat) return &g;
    return nullptr;
}

std::size_t count_app(const std::vector<win::RawGrant>& v, std::string_view app,
                      std::string_view cat) {
    return static_cast<std::size_t>(std::count_if(v.begin(), v.end(), [&](const win::RawGrant& g) {
        return g.app_id == app && g.category == cat;
    }));
}

bool has_cause(const std::vector<win::RawGrant>& v, std::string_view cat, std::string_view cause) {
    return std::any_of(v.begin(), v.end(), [&](const win::RawGrant& g) {
        return g.category == cat && g.cause == cause;
    });
}

win::ConsentWalk walk(FakeRegistry& reg, win::RetentionBudget& budget) {
    auto w = win::walk_consent_store(reg, reg.root, budget);
    CHECK(reg.opens == reg.closes); // ScopedKey closes every key it opened, exactly once
    return w;
}

static_assert(!std::is_copy_constructible_v<win::ScopedKey>);
static_assert(!std::is_copy_constructible_v<FakeRegistry>);

} // namespace

TEST_CASE("win walk: a fake fixture ConsentStore is decoded level by level; a missing store is "
          "file-not-found with every category absent",
          "[privacy_permissions][win_walk]") {
    FakeRegistry reg;
    auto* st = reg.store();
    FakeRegistry::set_sz(reg.path(st, L"webcam"), "Allow");
    FakeRegistry::set_sz(reg.path(st, L"webcam\\Pkg.App_1"), "Allow");
    reg.path(st, L"webcam\\NonPackaged"); // the toggle: no Value -> absent
    auto* exe = reg.path(st, L"webcam\\NonPackaged\\C:#app#x.exe");
    FakeRegistry::set_sz(exe, "Deny");
    FakeRegistry::set(exe, L"LastUsedTimeStart",
                      {win::kRegQword, qword(116444736000000000ULL + 10000ULL), false}); // 1 ms
    FakeRegistry::set_sz(reg.path(st, L"microphone"), "Prompt");

    SECTION("decoded level by level; unmodelled and missing keys stay visible") {
        win::RetentionBudget budget;
        const auto w = walk(reg, budget);
        CHECK(w.root_rc == win::kErrorSuccess);
        CHECK(w.refused.empty());
        CHECK(w.structural.empty());
        REQUIRE(find(w.grants, "-", "camera"));
        CHECK(find(w.grants, "-", "camera")->state == PermissionState::allowed);
        REQUIRE(find(w.grants, "Pkg.App_1", "camera"));
        CHECK(find(w.grants, "Pkg.App_1", "camera")->state == PermissionState::allowed);
        REQUIRE(find(w.grants, "NonPackaged", "camera"));
        CHECK(find(w.grants, "NonPackaged", "camera")->state == PermissionState::absent);
        const auto* x = find(w.grants, "C:\\app\\x.exe", "camera");
        REQUIRE(x);
        CHECK(x->state == PermissionState::denied);
        CHECK_FALSE(x->read_denied);
        CHECK(x->last_used_start.value == "1");
        REQUIRE(find(w.grants, "-", "microphone"));
        CHECK(find(w.grants, "-", "microphone")->state == PermissionState::prompt_undetermined);
        REQUIRE(find(w.grants, "-", "location"));
        CHECK(find(w.grants, "-", "location")->state == PermissionState::absent);
    }
    SECTION("a missing store") {
        FakeRegistry empty;
        win::RetentionBudget budget;
        const auto w = walk(empty, budget);
        CHECK(w.root_rc == win::kErrorFileNotFound);
        CHECK(w.grants.size() == win::kCapabilities.size());
        for (const auto& g : w.grants) CHECK(g.state == PermissionState::absent);
    }
}

TEST_CASE("win walk: value shapes -- ERROR_MORE_DATA, oversized, empty and wrong type each name "
          "their cause and are never decoded",
          "[privacy_permissions][win_walk]") {
    FakeRegistry reg;
    auto* st = reg.store();
    reg.path(st, L"webcam");
    auto* more = reg.path(st, L"webcam\\Pkg.More");
    // Value grows between the calls.
    FakeRegistry::set(more, L"Value", {win::kRegSz, sz16("Allow"), true});
    FakeRegistry::set(more, L"LastUsedTimeStart",
                      {win::kRegQword, std::vector<std::byte>(16), false});
    FakeRegistry::set(reg.path(st, L"webcam\\Pkg.Big"), L"Value",
                      {win::kRegSz, std::vector<std::byte>(win::kMaxConsentValueBytes + 2), false});
    FakeRegistry::set(reg.path(st, L"webcam\\Pkg.Empty"), L"Value", {win::kRegSz, {}, false});
    FakeRegistry::set(reg.path(st, L"webcam\\Pkg.Dword"), L"Value",
                      {4, std::vector<std::byte>(4, std::byte{1}), false});
    win::RetentionBudget budget;
    const auto w = walk(reg, budget);

    const auto* m = find(w.grants, "Pkg.More", "camera");
    REQUIRE(m);
    CHECK(m->state == PermissionState::unreadable);
    CHECK(m->cause == "value_win32_234");
    CHECK(m->raw_value == "-");
    CHECK(m->last_used_start.value == "unreadable");
    CHECK(m->last_used_start.cause == "win32_234");
    REQUIRE(find(w.grants, "Pkg.Big", "camera"));
    CHECK(find(w.grants, "Pkg.Big", "camera")->cause == "value_oversized");
    CHECK(find(w.grants, "Pkg.Big", "camera")->raw_value == "-");
    REQUIRE(find(w.grants, "Pkg.Empty", "camera"));
    CHECK(find(w.grants, "Pkg.Empty", "camera")->cause == "value_empty");
    REQUIRE(find(w.grants, "Pkg.Dword", "camera"));
    CHECK(find(w.grants, "Pkg.Dword", "camera")->cause == "value_type_4");
}

TEST_CASE("win walk: a zero-length or NUL-bearing child name is skipped and counted, never "
          "reopened (an empty name would reopen the PARENT)",
          "[privacy_permissions][win_walk]") {
    FakeRegistry reg;
    auto* st = reg.store();
    auto* cam = reg.path(st, L"webcam");
    FakeRegistry::set_sz(reg.add_raw(cam, L"Pkg.Ok"), "Allow");
    reg.add_raw(cam, std::wstring(L"Pk\0g", 4));
    reg.add_raw(cam, L"");

    const auto e = win::enumerate_subkey_names(reg, cam);
    REQUIRE(e.names.size() == 1);
    CHECK(e.names[0] == L"Pkg.Ok");
    CHECK(e.verdict.embedded_nul_names == 2);

    win::RetentionBudget budget;
    const auto w = walk(reg, budget);
    CHECK(count_app(w.grants, "Pkg.Ok", "camera") == 1);
    CHECK(has_cause(w.structural, "camera", "packaged:name_embedded_nul"));
    CHECK(std::count(reg.opened_names.begin(), reg.opened_names.end(), std::wstring{}) == 0);
}

TEST_CASE("win walk: NonPackaged and Executables are matched with the registry's own name compare",
          "[privacy_permissions][win_walk]") {
    FakeRegistry reg;
    auto* st = reg.store();
    FakeRegistry::set_sz(reg.path(st, L"webcam"), "Allow");
    FakeRegistry::set_sz(reg.path(st, L"webcam\\nonpackaged"), "Allow");
    reg.path(st, L"webcam\\nonpackaged\\EXECUTABLES\\foo.exe");
    win::RetentionBudget budget;
    const auto w = walk(reg, budget);

    CHECK(count_app(w.grants, "NonPackaged", "camera") == 1);
    REQUIRE(find(w.grants, "NonPackaged", "camera"));
    CHECK(find(w.grants, "NonPackaged", "camera")->state == PermissionState::allowed);
    CHECK(find(w.grants, "nonpackaged", "camera") == nullptr);
    CHECK(find(w.grants, "EXECUTABLES", "camera") == nullptr);
    CHECK_FALSE(has_cause(w.structural, "camera", "duplicate_app_id"));
    const auto compared = [&](std::wstring_view a, std::wstring_view b) {
        return std::find(reg.name_compares.begin(), reg.name_compares.end(),
                         std::pair<std::wstring, std::wstring>{std::wstring{a}, std::wstring{b}}) !=
               reg.name_compares.end();
    };
    CHECK(compared(L"nonpackaged", win::kNonPackagedKeyName));       // the packaged-skip site
    CHECK(compared(L"EXECUTABLES", win::kExecutablesContainerKeyName)); // the container-skip site
}

TEST_CASE("win walk: a store that changed during the read is walked once more, then refused",
          "[privacy_permissions][win_walk]") {
    FakeRegistry reg;
    auto* st = reg.store();
    FakeRegistry::set_sz(reg.path(st, L"webcam"), "Allow");
    win::RetentionBudget budget;

    SECTION("changed on walk 1, stable on walk 2: the grants are kept once, the counters "
            "restarted") {
        reg.watch_script = {win::kWaitObject0, win::kWaitTimeout};
        const auto w = walk(reg, budget);
        CHECK(reg.watches == 2);
        CHECK(w.refused.empty());
        CHECK(count_app(w.grants, "-", "camera") == 1); // not doubled
        CHECK(budget.source.rows == w.grants.size() + w.structural.size()); // begin_profile() ran
    }
    SECTION("changed again during the re-walk: refused, after exactly two walks") {
        reg.watch_script = {win::kWaitObject0, win::kWaitObject0, win::kWaitObject0};
        const auto w = walk(reg, budget);
        CHECK(reg.watches == 2);
        CHECK(w.refused == win::kChangedDuringRead);
        CHECK(w.grants.empty());
    }
    SECTION("no re-walk once the deadline has passed: one walk, the honest refusal stands") {
        reg.watch_script = {win::kWaitObject0, win::kWaitObject0};
        budget.deadline = std::chrono::steady_clock::now() - std::chrono::seconds{1};
        const auto w = walk(reg, budget);
        CHECK(reg.watches == 1);
        CHECK(w.refused == win::kChangedDuringRead);
    }
}

TEST_CASE("win walk: an expired deadline stops the walk before any key past the store root "
          "is opened",
          "[privacy_permissions][win_walk]") {
    FakeRegistry reg;
    FakeRegistry::set_sz(reg.path(reg.store(), L"webcam"), "Allow");
    win::RetentionBudget budget;
    budget.deadline = std::chrono::steady_clock::now() - std::chrono::seconds{1};
    const auto w = walk(reg, budget);
    CHECK(budget.timed_out);
    CHECK(reg.opens == 1); // the store root alone
    CHECK(w.grants.empty());
}

TEST_CASE("win walk: an enumeration of exactly the cap is complete (one probe); one more child is "
          "truncated",
          "[privacy_permissions][win_walk]") {
    FakeRegistry reg;
    auto* parent = reg.path(reg.root, L"p");
    for (std::uint32_t i = 0; i < win::kMaxEnumeratedSubkeys; ++i)
        reg.add_raw(parent, L"k" + std::to_wstring(i));

    const auto exact = win::enumerate_subkey_names(reg, parent);
    CHECK(exact.names.size() == win::kMaxEnumeratedSubkeys);
    CHECK(exact.verdict.outcome == win::EnumOutcome::complete);
    CHECK_FALSE(win::enum_failure("packaged", exact.verdict).has_value());
    CHECK(reg.enum_calls == win::kMaxEnumeratedSubkeys + 1); // cap reads + the one probe
    CHECK(reg.max_enum_idx == win::kMaxEnumeratedSubkeys);   // the probe, issued once

    reg.add_raw(parent, L"one-more");
    const auto over = win::enumerate_subkey_names(reg, parent);
    CHECK(over.names.size() == win::kMaxEnumeratedSubkeys);
    CHECK(over.verdict.outcome == win::EnumOutcome::truncated);
    REQUIRE(win::enum_failure("packaged", over.verdict).has_value());
    CHECK(win::enum_failure("packaged", over.verdict)->cause == "packaged_enum_truncated");
}

// ── hive-file guard over a fake probe ───────────────────────────────────

namespace {

const std::string kProfileSid = "S-1-5-21-1-2-3-1001";
const std::wstring kHivePath = L"C:\\Users\\alice\\NTUSER.DAT";

struct FakeHiveFileProbe final : win::HiveFileProbe {
    std::uint32_t drive = win::kDriveFixed;
    std::map<std::wstring, std::uint32_t> dir_attrs; // by ancestor path; default: a plain directory
    long dir_rc = 0;
    win::LeafFacts leaf;
    long leaf_rc = 0;
    std::vector<win::SidecarEntry> sidecars;
    long list_rc = 0;
    std::uint32_t sidecar_links = 1, sidecar_attrs = 0;
    long sidecar_rc = 0;
    std::size_t dir_calls = 0, leaf_calls = 0, list_calls = 0, sidecar_calls = 0;

    FakeHiveFileProbe() {
        leaf.owner_sid = kProfileSid;
        leaf.id = {7, {1, 2, 3}};
    }
    std::uint32_t drive_type(const std::wstring&) override { return drive; }
    long path_attributes(const std::wstring& path, std::uint32_t& attrs) override {
        ++opens;
        ++dir_calls;
        const auto it = dir_attrs.find(path);
        attrs = it == dir_attrs.end() ? win::kFileAttributeDirectory : it->second;
        return dir_rc;
    }
    long leaf_facts(const std::wstring&, win::LeafFacts& out) override {
        ++opens;
        ++leaf_calls;
        out = leaf;
        return leaf_rc;
    }
    long list_sidecars(const std::wstring&, const std::wstring&, std::size_t limit,
                       std::vector<win::SidecarEntry>& out) override {
        ++list_calls;
        for (const auto& e : sidecars)
            if (out.size() < limit) out.push_back(e);
        return list_rc;
    }
    long sidecar_facts(const std::wstring&, std::uint32_t& links, std::uint32_t& attrs) override {
        ++opens;
        ++sidecar_calls;
        links = sidecar_links;
        attrs = sidecar_attrs;
        return sidecar_rc;
    }
};

struct GuardRig {
    FakeHiveFileProbe probe;
    bool expired = false;
    win::HiveFileGuard guard{probe, [this] { return expired; }, kProfileSid, std::nullopt};
    std::string before(const std::wstring& path = kHivePath) { return guard.before_load(path); }
};

win::SidecarEntry sidecar(const wchar_t* name, std::uint32_t find_attrs = 0) {
    return {name, find_attrs};
}

} // namespace

TEST_CASE("hive guard: the injected deadline is checked first; UNC, depth and drive refusals "
          "open no handle and list nothing",
          "[privacy_permissions][win_walk]") {
    GuardRig r;
    SECTION("an expired deadline: `timeout`, no probe call at all") {
        r.expired = true;
        CHECK(r.before() == "timeout");
        CHECK(r.probe.opens == 0);
        CHECK(r.probe.list_calls == 0);
    }
    SECTION("a UNC path") {
        CHECK(r.before(L"\\\\server\\share\\NTUSER.DAT") == "hive_path_unc");
        CHECK(r.probe.opens == 0);
        CHECK(r.probe.list_calls == 0);
    }
    SECTION("deeper than kMaxHivePathDepth") {
        std::wstring deep = L"C:\\";
        for (std::size_t i = 0; i < win::kMaxHivePathDepth; ++i) deep += L"d\\";
        deep += L"NTUSER.DAT";
        CHECK(r.before(deep) == "hive_path_too_deep");
        CHECK(r.probe.opens == 0);
        CHECK(r.probe.list_calls == 0);
    }
    SECTION("a drive that is not fixed") {
        r.probe.drive = 4; // DRIVE_REMOTE
        CHECK(r.before() == "hive_path_not_fixed");
        CHECK(r.probe.opens == 0);
        CHECK(r.probe.list_calls == 0);
    }
    SECTION("a stock file is accepted") { CHECK(r.before().empty()); }
}

TEST_CASE("hive guard: attribute bits map to facts -- the not_resident mask, never SPARSE",
          "[privacy_permissions][win_walk]") {
    win::HiveFileFacts f;
    win::apply_attributes(win::kFileAttributeReparsePoint | win::kFileAttributeDirectory, f);
    CHECK(f.is_reparse);
    CHECK(f.is_directory);
    CHECK_FALSE(f.not_resident);

    GuardRig r;
    for (const std::uint32_t bit : {win::kFileAttributeOffline, win::kFileAttributeRecallOnOpen,
                                    win::kFileAttributeRecallOnDataAccess}) {
        r.probe.leaf.attributes = bit;
        CHECK(r.before() == "hive_not_resident");
    }
    r.probe.leaf.attributes = 0x200; // FILE_ATTRIBUTE_SPARSE_FILE: a resident file can be sparse
    CHECK(r.before().empty());
}

TEST_CASE("hive guard: a sidecar is refused from the listing, again from its opened handle, and "
          "when hard-linked -- in listing order",
          "[privacy_permissions][win_walk]") {
    GuardRig r;
    r.probe.sidecars = {sidecar(L"NTUSER.DAT.LOG1")};

    SECTION("the listing says regular, the opened handle says reparse point") {
        r.probe.sidecar_attrs = win::kFileAttributeReparsePoint;
        CHECK(r.before() == "hive_sidecar_reparse");
        CHECK(r.probe.sidecar_calls == 1);
    }
    SECTION("the listing says reparse point: the sidecar is never opened") {
        r.probe.sidecars = {sidecar(L"NTUSER.DAT.LOG1", win::kFileAttributeReparsePoint)};
        CHECK(r.before() == "hive_sidecar_reparse");
        CHECK(r.probe.sidecar_calls == 0);
    }
    SECTION("a hard-linked sidecar") {
        r.probe.sidecar_links = 2;
        CHECK(r.before() == "hive_sidecar_hardlinked");
    }
    SECTION("more than kMaxHiveSidecars: refused, with no probe past the cap") {
        r.probe.sidecars.assign(win::kMaxHiveSidecars + 1, sidecar(L"NTUSER.DAT.LOGx"));
        CHECK(r.before() == "hive_sidecar_count");
        CHECK(r.probe.sidecar_calls == win::kMaxHiveSidecars);
    }
    SECTION("a sidecar that cannot be opened carries its Win32 code") {
        r.probe.sidecar_rc = 5;
        CHECK(r.before() == "hive_stat_failed:win32_5");
    }
    SECTION("a regular, single-link sidecar is fine") { CHECK(r.before().empty()); }
}

TEST_CASE("hive guard: an entry decided before a listing failure outranks it; a failure alone "
          "is reported",
          "[privacy_permissions][win_walk]") {
    GuardRig r;
    r.probe.list_rc = 5;
    SECTION("regular, then a reparse entry, then the listing failed: the reparse decides") {
        r.probe.sidecars = {sidecar(L"NTUSER.DAT.LOG1"),
                            sidecar(L"NTUSER.DAT.LOG2", win::kFileAttributeReparsePoint)};
        CHECK(r.before() == "hive_sidecar_reparse");
    }
    SECTION("one healthy entry, then the listing failed: the failure is reported") {
        r.probe.sidecars = {sidecar(L"NTUSER.DAT.LOG1")};
        CHECK(r.before() == "hive_stat_failed:win32_5");
    }
    SECTION("the listing failed with no entry: the failure is reported") {
        CHECK(r.before() == "hive_stat_failed:win32_5");
    }
    SECTION("no failure and no entries: accepted") {
        r.probe.list_rc = 0;
        CHECK(r.before().empty());
    }
}

TEST_CASE("hive guard: an ancestor reparse point is refused hop by hop, the identity is "
          "re-verified after the load, and stat failures carry their code",
          "[privacy_permissions][win_walk]") {
    GuardRig r;
    SECTION("the second hop is a reparse point: the leaf is never probed") {
        r.probe.dir_attrs[L"C:\\Users\\alice"] = win::kFileAttributeReparsePoint;
        CHECK(r.before() == "hive_path_reparse_ancestor");
        CHECK(r.probe.dir_calls == 2);
        CHECK(r.probe.leaf_calls == 0);
    }
    SECTION("an ancestor that cannot be opened carries its code") {
        r.probe.dir_rc = 3;
        CHECK(r.before() == "hive_stat_failed:win32_3");
    }
    SECTION("the leaf cannot be read") {
        r.probe.leaf_rc = 2;
        CHECK(r.before() == "hive_stat_failed:win32_2");
    }
    SECTION("the same file after the load re-verifies; a different one does not") {
        REQUIRE(r.before().empty());
        CHECK(r.guard.after_load(kHivePath).empty());
        r.probe.leaf.id.file_id[0] = 9;
        CHECK(r.guard.after_load(kHivePath) == "hive_identity_changed");
        r.probe.leaf.id.file_id[0] = 1;
        r.probe.leaf.id.volume_serial = 8;
        CHECK(r.guard.after_load(kHivePath) == "hive_identity_changed");
    }
    SECTION("no snapshot from before_load: refused") {
        CHECK(r.guard.after_load(kHivePath) == "hive_identity_changed");
    }
}
