/**
 * test_registry_write_local_dispatcher.cpp -- the REAL registry.dll's mutating actions driven
 * through yuzu::agent::LocalDispatcher against the live Windows registry (the pure logic is locked on
 * every host by test_registry_parsers.cpp / test_registry_core.cpp; this proves the Win32 binding).
 *
 * Every key lives under a salted `YuzuTest-<yuzu::test::process_random_salt()>` (#1871: a fixed registry
 * key is a cross-JOB shared resource) and an RAII guard removes each scratch object. Cases that need
 * elevation WARN and skip, and a skip is NOT evidence: YUZU_REQUIRE_WINDOWS_REGISTRY_TESTS=1 (the
 * kingsley evidence jobs) turns every skip into a FAIL -- see skip_or_fail(). Off Windows this TU pins
 * the planned-stub contract of the loaded plugin (the #else branch).
 */
#include <catch2/catch_test_macros.hpp>

#include <string>

#ifdef _WIN32

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>

#include <sddl.h>

#include <yuzu/agent/plugin_loader.hpp>
#include <yuzu/plugin.h>

#include <win_hive_file_probe.hpp> // yuzu::win::LocalFreeGuard
#include <win_reg_handle.hpp>

#include "local_dispatcher.hpp"
#include "test_helpers.hpp"

#include <algorithm>
#include <cstdint>
#include <cstdlib>
#include <filesystem>
#include <map>
#include <optional>
#include <iterator>
#include <sstream>
#include <string_view>
#include <vector>

namespace fs = std::filesystem;

namespace {

using Bytes = std::vector<std::uint8_t>;

// ── plugin + dispatch ────────────────────────────────────────────────────

fs::path find_registry_plugin() {
    std::vector<fs::path> candidates;
    if (auto* build_root = std::getenv("MESON_BUILD_ROOT"))
        candidates.emplace_back(fs::path{build_root} / "agents" / "plugins" / "registry" / "registry.dll");
    candidates.emplace_back(fs::path{"agents"} / "plugins" / "registry" / "registry.dll");
    candidates.emplace_back(fs::path{".."} / "agents" / "plugins" / "registry" / "registry.dll");
    candidates.emplace_back(fs::path{"build-windows"} / "agents" / "plugins" / "registry" / "registry.dll");
    for (const auto& p : candidates) {
        std::error_code ec;
        if (fs::exists(p, ec) && !ec) return fs::absolute(p, ec);
    }
    return {};
}

struct Plugin {
    std::optional<yuzu::agent::PluginHandle> handle;
    yuzu::agent::LocalDispatcher dispatcher;

    Plugin() {
        const auto path = find_registry_plugin();
        if (path.empty()) return;
        auto loaded = yuzu::agent::PluginHandle::load(path);
        if (loaded) handle = std::move(*loaded);
    }
    [[nodiscard]] bool ok() const { return handle.has_value() && handle->descriptor() != nullptr; }

    struct Out {
        int rc = -1;
        std::vector<std::string> lines;
        [[nodiscard]] bool has(const std::string& l) const {
            return std::find(lines.begin(), lines.end(), l) != lines.end();
        }
        [[nodiscard]] std::string audit() const {
            for (const auto& l : lines)
                if (l.rfind("audit|", 0) == 0) return l;
            return {};
        }
        [[nodiscard]] std::size_t audit_count() const {
            return static_cast<std::size_t>(std::count_if(lines.begin(), lines.end(), [](const std::string& l) {
                return l.rfind("audit|", 0) == 0;
            }));
        }
    };

    Out run(const std::string& action, const std::map<std::string, std::string>& params) {
        std::vector<YuzuParam> raw;
        for (const auto& [k, v] : params) raw.push_back(YuzuParam{k.c_str(), v.c_str()});
        const auto r = dispatcher.run(handle->descriptor(), action, raw);
        Out out;
        out.rc = r.rc;
        std::istringstream in(r.captured);
        for (std::string l; std::getline(in, l);) out.lines.push_back(l);
        return out;
    }
};

// ── skip or fail ─────────────────────────────────────────────────────────

/// A case that cannot run (registry.dll missing, the process not elevated, a fixture that could not
/// be built) WARNs and returns -- unless YUZU_REQUIRE_WINDOWS_REGISTRY_TESTS is set to a non-empty
/// value other than "0", when it FAILs: a skipped real-registry run proves nothing, so the evidence
/// runs (kingsley, elevated) set the variable and a skip there is red, never silently green.
/// Callers `return` after calling it; FAIL throws, so that return is only reached on a plain skip.
void skip_or_fail(const std::string& why) {
    const char* req = std::getenv("YUZU_REQUIRE_WINDOWS_REGISTRY_TESTS");
    if (req != nullptr && req[0] != '\0' && std::string_view{req} != "0") FAIL(why + " (YUZU_REQUIRE_WINDOWS_REGISTRY_TESTS is set)");
    WARN(why + " -- skipping");
}

// ── names and direct Win32 helpers ───────────────────────────────────────

const std::string& salt() {
    static const std::string s = std::to_string(yuzu::test::process_random_salt());
    return s;
}
std::string scratch_name() { return "YuzuTest-" + salt(); }
std::wstring widen(const std::string& s) { return std::wstring(s.begin(), s.end()); } // ASCII only

bool put(HKEY root, const std::string& key, const std::string& name, DWORD type, const Bytes& data) {
    yuzu::win::RegKey k;
    if (RegCreateKeyExW(root, widen(key).c_str(), 0, nullptr, 0, KEY_SET_VALUE, nullptr, k.put(), nullptr) != ERROR_SUCCESS)
        return false;
    return RegSetValueExW(k.get(), widen(name).c_str(), 0, type, data.empty() ? nullptr : data.data(),
                          static_cast<DWORD>(data.size())) == ERROR_SUCCESS;
}

struct Read {
    bool found = false;
    DWORD type = 0;
    Bytes data;
};
Read read(HKEY root, const std::string& key, const std::string& name) {
    Read r;
    yuzu::win::RegKey k;
    if (RegOpenKeyExW(root, widen(key).c_str(), 0, KEY_QUERY_VALUE, k.put()) != ERROR_SUCCESS) return r;
    DWORD size = 0;
    if (RegQueryValueExW(k.get(), widen(name).c_str(), nullptr, &r.type, nullptr, &size) == ERROR_SUCCESS) {
        r.data.resize(size);
        DWORD got = size;
        r.found = RegQueryValueExW(k.get(), widen(name).c_str(), nullptr, &r.type, size ? r.data.data() : nullptr, &got) ==
                  ERROR_SUCCESS;
        r.data.resize(got);
    }
    return r;
}

bool key_exists(HKEY root, const std::string& key) {
    yuzu::win::RegKey k;
    return RegOpenKeyExW(root, widen(key).c_str(), 0, KEY_READ, k.put()) == ERROR_SUCCESS;
}

Bytes utf16(const std::wstring& w, bool terminator = true) {
    Bytes b;
    for (const wchar_t c : w) {
        b.push_back(static_cast<std::uint8_t>(c & 0xFF));
        b.push_back(static_cast<std::uint8_t>(c >> 8));
    }
    if (terminator) {
        b.push_back(0);
        b.push_back(0);
    }
    return b;
}
Bytes le(std::uint64_t v, int n) {
    Bytes b;
    for (int i = 0; i < n; ++i) b.push_back(static_cast<std::uint8_t>((v >> (8 * i)) & 0xFF));
    return b;
}
std::string to_hex(const Bytes& b) {
    static const char* d = "0123456789abcdef";
    std::string s;
    for (const auto c : b) {
        s += d[c >> 4];
        s += d[c & 15];
    }
    return s;
}

/// Creates a registry link key `link_path` under HKLM whose SymbolicLinkValue (a REG_LINK: the target path
/// WITHOUT a terminating NUL) names HKLM\<target_path>, which need not exist. False when it cannot be made.
bool make_machine_link(const std::string& link_path, const std::string& target_path) {
    yuzu::win::RegKey link;
    if (RegCreateKeyExW(HKEY_LOCAL_MACHINE, widen(link_path).c_str(), 0, nullptr, REG_OPTION_CREATE_LINK,
                        KEY_SET_VALUE | KEY_CREATE_LINK, nullptr, link.put(), nullptr) != ERROR_SUCCESS)
        return false;
    const Bytes target = utf16(L"\\Registry\\Machine\\" + widen(target_path), /*terminator=*/false);
    return RegSetValueExW(link.get(), L"SymbolicLinkValue", 0, REG_LINK, target.data(),
                          static_cast<DWORD>(target.size())) == ERROR_SUCCESS;
}

/// Removes a salted subtree on scope exit (undoing any deny-ACE first). Never throws.
struct ScratchTree {
    HKEY root;
    std::string path;
    ScratchTree(HKEY r, std::string p) : root(r), path(std::move(p)) {}
    ~ScratchTree() {
        yuzu::win::RegKey k;
        if (RegOpenKeyExW(root, widen(path).c_str(), 0, WRITE_DAC | READ_CONTROL, k.put()) == ERROR_SUCCESS) {
            PSECURITY_DESCRIPTOR sd = nullptr;
            if (ConvertStringSecurityDescriptorToSecurityDescriptorW(L"D:(A;;GA;;;WD)", SDDL_REVISION_1, &sd, nullptr)) {
                const yuzu::win::LocalFreeGuard free_sd{sd};
                RegSetKeySecurity(k.get(), DACL_SECURITY_INFORMATION, sd);
            }
        }
        RegDeleteTreeW(root, widen(path).c_str());
    }
    ScratchTree(const ScratchTree&) = delete;
    ScratchTree& operator=(const ScratchTree&) = delete;
};

} // namespace

// ── typed + verified writes (HKCU) ──

TEST_CASE("registry write: set_value round-trips all six types; each preceded by one audit line",
          "[registry][windows][write]") {
    Plugin p;
    if (!p.ok()) { skip_or_fail("registry.dll not found"); return; }
    const std::string base = "Software\\" + scratch_name() + "\\rt";
    ScratchTree cleanup{HKEY_CURRENT_USER, "Software\\" + scratch_name()};

    struct Case {
        const char* what;
        std::map<std::string, std::string> params;
        DWORD type;
        Bytes expect;
    };
    const std::string mib_hex(2 * 1024 * 1024, 'a');
    const std::vector<Case> cases{
        {"REG_SZ", {{"type", "REG_SZ"}, {"value", "hello"}}, REG_SZ, utf16(L"hello")},
        {"empty REG_SZ", {{"type", "REG_SZ"}, {"value", ""}}, REG_SZ, utf16(L"")},
        {"default type is REG_SZ", {{"value", "x"}}, REG_SZ, utf16(L"x")},
        {"REG_EXPAND_SZ", {{"type", "REG_EXPAND_SZ"}, {"value", "%TEMP%\\x"}}, REG_EXPAND_SZ, utf16(L"%TEMP%\\x")},
        {"REG_DWORD", {{"type", "REG_DWORD"}, {"value", "4294967295"}}, REG_DWORD, le(0xFFFFFFFFu, 4)},
        {"REG_QWORD", {{"type", "REG_QWORD"}, {"value", "18446744073709551615"}}, REG_QWORD, le(~0ull, 8)},
        {"REG_MULTI_SZ", {{"type", "REG_MULTI_SZ"}, {"value", "a\nb"}}, REG_MULTI_SZ,
         Bytes{0x61, 0, 0, 0, 0x62, 0, 0, 0, 0, 0}},
        {"empty REG_MULTI_SZ", {{"type", "REG_MULTI_SZ"}, {"value", ""}}, REG_MULTI_SZ, Bytes{0, 0, 0, 0}},
        {"REG_BINARY with embedded NULs", {{"type", "REG_BINARY"}, {"value", "00ff0000aa"}}, REG_BINARY, Bytes{0, 0xff, 0, 0, 0xaa}},
        {"empty REG_BINARY", {{"type", "REG_BINARY"}, {"value", ""}}, REG_BINARY, Bytes{}},
        {"data_hex for a string type", {{"type", "REG_SZ"}, {"data_hex", "61000000"}}, REG_SZ, Bytes{0x61, 0, 0, 0}},
        {"1 MiB REG_BINARY", {{"type", "REG_BINARY"}, {"data_hex", mib_hex}}, REG_BINARY, Bytes(1024 * 1024, 0xaa)},
    };
    int i = 0;
    for (auto c : cases) {
        INFO(c.what);
        c.params["hive"] = "HKCU";
        c.params["key"] = base;
        c.params["name"] = "v" + std::to_string(i++);
        const auto out = p.run("set_value", c.params);
        CHECK(out.rc == 0);
        REQUIRE(out.lines.size() == 2);
        CHECK(out.lines[0].rfind("audit|op=set_value|hive=HKCU|", 0) == 0);
        CHECK(out.lines[0].find("|result=ok|reason=-|verify=ok|") != std::string::npos);
        CHECK(out.lines[1] == "status|ok");
        const auto r = read(HKEY_CURRENT_USER, base, c.params["name"]);
        REQUIRE(r.found);
        CHECK(r.type == c.type);
        CHECK(to_hex(r.data) == to_hex(c.expect));
    }
    SECTION("a refused value writes nothing and says why") {
        const std::string fresh = "Software\\" + scratch_name() + "\\refused";
        for (const auto& [params, token] : std::vector<std::pair<std::map<std::string, std::string>, std::string>>{
                 {{{"type", "REG_BINARY"}, {"value", "abc"}}, "invalid_data"},            // odd-length hex
                 {{{"type", "REG_MULTI_SZ"}, {"data_hex", "61000000"}}, "invalid_data"},  // no double NUL
                 {{{"type", "REG_DWORD"}, {"value", "4294967296"}}, "value_overflow"},
                 {{{"type", "REG_LINK"}, {"value", "x"}}, "invalid_type"},
                 {{{"type", "REG_DWORD"}, {"value", "1"}, {"data_hex", "01000000"}}, "invalid_data"}}) {
            auto q = params;
            q["hive"] = "HKCU";
            q["key"] = fresh;
            q["name"] = "v";
            const auto out = p.run("set_value", q);
            CHECK(out.rc == 1);
            CHECK(out.has("error|" + token));
            CHECK(out.audit().find("|result=refused|reason=" + token + "|") != std::string::npos);
            CHECK_FALSE(key_exists(HKEY_CURRENT_USER, fresh));
        }
    }
}

TEST_CASE("registry write: delete_value; and a value that is not there", "[registry][windows][write]") {
    Plugin p;
    if (!p.ok()) { skip_or_fail("registry.dll not found"); return; }
    const std::string key = "Software\\" + scratch_name() + "\\dv";
    ScratchTree cleanup{HKEY_CURRENT_USER, "Software\\" + scratch_name()};
    REQUIRE(put(HKEY_CURRENT_USER, key, "V", REG_DWORD, le(7, 4)));

    const auto del = p.run("delete_value", {{"hive", "HKCU"}, {"key", key}, {"name", "V"}});
    CHECK(del.rc == 0);
    CHECK(del.has("status|ok"));
    CHECK(del.audit().find("|result=ok|reason=-|verify=ok|") != std::string::npos);
    CHECK(del.audit().find("|old_state=present|old_type=REG_DWORD|old=07000000|") != std::string::npos);
    CHECK_FALSE(read(HKEY_CURRENT_USER, key, "V").found);

    const auto gone = p.run("get_value", {{"hive", "HKCU"}, {"key", key}, {"name", "V"}});
    CHECK(gone.rc == 1);
    CHECK(gone.has("error|value not found"));

    const auto missing = p.run("delete_value", {{"hive", "HKCU"}, {"key", key}, {"name", "V"}});
    CHECK(missing.rc == 1);
    CHECK(missing.has("error|value_not_found"));
    const auto nokey = p.run("delete_value", {{"hive", "HKCU"}, {"key", key + "\\nope"}, {"name", "V"}});
    CHECK(nokey.has("error|key_not_found"));
}

TEST_CASE("registry write: hostile parameters are refused by name and create nothing",
          "[registry][windows][write]") {
    Plugin p;
    if (!p.ok()) { skip_or_fail("registry.dll not found"); return; }
    const std::string root = "Software\\" + scratch_name();
    ScratchTree cleanup{HKEY_CURRENT_USER, root};
    const std::string key300 = root + "\\" + std::string(300, 'k');
    struct Case {
        const char* what;
        std::string key;
        std::string name;
        std::string token;
    };
    const std::vector<Case> cases{
        {"300-character key", key300, "v", "invalid_key_path"},
        {"invalid UTF-8 in the key", root + "\\bad\xC3", "v", "invalid_key_path"},
        {"a hive alias as the first component", "HKLM\\" + root, "v", "invalid_key_path"},
        {"a .. component", root + "\\..\\x", "v", "invalid_key_path"},
        {"a trailing backslash", root + "\\x\\", "v", "invalid_key_path"},
        {"CR in the value name", root + "\\ok", "a\rb", "invalid_value_name"},
        {"LF in the value name", root + "\\ok", "a\nb", "invalid_value_name"},
        {"invalid UTF-8 in the value name", root + "\\ok", "a\xFF", "invalid_value_name"},
    };
    for (const auto& c : cases) {
        INFO(c.what);
        for (const char* action : {"set_value", "delete_value"}) {
            const auto out = p.run(action, {{"hive", "HKCU"}, {"key", c.key}, {"name", c.name}, {"value", "x"}});
            CHECK(out.rc == 1);
            CHECK(out.has("error|" + c.token));
            CHECK(out.audit_count() == 1);
        }
    }
    CHECK_FALSE(key_exists(HKEY_CURRENT_USER, root + "\\ok"));
    CHECK_FALSE(key_exists(HKEY_CURRENT_USER, root + "\\x"));
}

TEST_CASE("registry write: a registry value containing a newline and an audit| line renders as one sanitised row",
          "[registry][windows][write]") {
    Plugin p;
    if (!p.ok()) { skip_or_fail("registry.dll not found"); return; }
    const std::string key = "Software\\" + scratch_name() + "\\inj";
    ScratchTree cleanup{HKEY_CURRENT_USER, "Software\\" + scratch_name()};
    REQUIRE(put(HKEY_CURRENT_USER, key, "V", REG_SZ, utf16(L"x\naudit|op=set_value|result=ok")));
    REQUIRE(put(HKEY_CURRENT_USER, key, "N|\naudit|op=set_value|result=ok", REG_DWORD, le(1, 4))); // a hostile NAME
    REQUIRE(put(HKEY_CURRENT_USER, key + "\\sub|\nname", "n", REG_DWORD, le(1, 4)));
    const auto out = p.run("get_value", {{"hive", "HKCU"}, {"key", key}, {"name", "V"}});
    CHECK(out.rc == 0);
    CHECK(out.audit_count() == 0);
    CHECK(out.has("value|x_audit_op=set_value_result=ok"));
    const auto subs = p.run("enumerate_keys", {{"hive", "HKCU"}, {"key", key}});
    CHECK(subs.audit_count() == 0);
    for (const auto& l : subs.lines) CHECK(l.find('\n') == std::string::npos);
    // enumerate_values lists value NAMES, the registry's other attacker-shaped text: the LF and the `|` in the
    // name become `_`, no line starts with audit|, and the two values are exactly two rows.
    const auto vals = p.run("enumerate_values", {{"hive", "HKCU"}, {"key", key}});
    CHECK(vals.rc == 0);
    CHECK(vals.audit_count() == 0);
    CHECK(vals.has("value|N__audit_op=set_value_result=ok|REG_DWORD"));
    CHECK(vals.lines.size() == 2);
}

// ── delete_key: a leaf by handle, counts, links, ACLs ──

TEST_CASE("registry write: delete_key refuses a key with subkeys and deletes a leaf with its count rows",
          "[registry][windows][write]") {
    Plugin p;
    if (!p.ok()) { skip_or_fail("registry.dll not found"); return; }
    const std::string tree = "Software\\" + scratch_name() + "\\tree";
    ScratchTree cleanup{HKEY_CURRENT_USER, "Software\\" + scratch_name()};
    REQUIRE(put(HKEY_CURRENT_USER, tree, "r1", REG_DWORD, le(1, 4)));
    REQUIRE(put(HKEY_CURRENT_USER, tree + "\\leaf", "a", REG_DWORD, le(2, 4)));
    REQUIRE(put(HKEY_CURRENT_USER, tree + "\\leaf", "b", REG_BINARY, Bytes{1, 2}));

    SECTION("a key with subkeys is refused and nothing is deleted") {
        const auto out = p.run("delete_key", {{"hive", "HKCU"}, {"key", tree}});
        CHECK(out.rc == 1);
        CHECK(out.has("error|key_has_subkeys"));
        CHECK(key_exists(HKEY_CURRENT_USER, tree + "\\leaf"));
    }
    SECTION("a leaf is deleted by handle and reports what it held") {
        const auto out = p.run("delete_key", {{"hive", "HKCU"}, {"key", tree + "\\leaf"}});
        CHECK(out.rc == 0);
        CHECK(out.has("status|ok"));
        CHECK(out.has("counted_keys|1"));
        CHECK(out.has("counted_values|2"));
        CHECK(out.has("dry_run|0"));
        CHECK(out.has("capped|0"));
        CHECK(out.audit().find("|result=ok|reason=-|verify=ok|") != std::string::npos);
        CHECK_FALSE(key_exists(HKEY_CURRENT_USER, tree + "\\leaf"));
        CHECK(key_exists(HKEY_CURRENT_USER, tree));
    }
}

TEST_CASE("registry write: a registry link is refused; never followed; and deleting the link leaves its target",
          "[registry][windows][write]") {
    Plugin p;
    if (!p.ok()) { skip_or_fail("registry.dll not found"); return; }
    // HKLM, not HKCU: the link target path is then the same on every account (a SYSTEM caller's HKCU
    // is HKU\.DEFAULT, not its SID). Needs an elevated token.
    const std::string root = "SOFTWARE\\" + scratch_name();
    ScratchTree cleanup{HKEY_LOCAL_MACHINE, root};
    if (!put(HKEY_LOCAL_MACHINE, root + "\\Target", "keep", REG_DWORD, le(1, 4))) {
        skip_or_fail("not elevated -- HKLM scratch not writable, registry-link case");
        return;
    }
    if (!make_machine_link(root + "\\Link", root + "\\Target")) {
        skip_or_fail("could not create a registry link here");
        return;
    }

    const std::string through = root + "\\Link";
    const auto set = p.run("set_value", {{"hive", "HKLM"}, {"key", through}, {"name", "Evil"}, {"value", "x"}});
    CHECK(set.rc == 1);
    CHECK(set.has("error|key_is_link"));
    const auto setdeep = p.run("set_value", {{"hive", "HKLM"}, {"key", through + "\\Child"}, {"name", "Evil"}, {"value", "x"}});
    CHECK(setdeep.has("error|key_is_link"));
    const auto del = p.run("delete_value", {{"hive", "HKLM"}, {"key", through}, {"name", "keep"}});
    CHECK(del.has("error|key_is_link"));
    CHECK_FALSE(read(HKEY_LOCAL_MACHINE, root + "\\Target", "Evil").found);
    CHECK_FALSE(key_exists(HKEY_LOCAL_MACHINE, root + "\\Target\\Child"));
    const auto deep_delete = p.run("delete_key", {{"hive", "HKLM"}, {"key", through + "\\Child"}});
    CHECK(deep_delete.rc == 1); // a link in the MIDDLE of the path is still refused (or the child is absent)

    // Deleting the key AT the link path removes the link object (by handle), not the target.
    const auto dk = p.run("delete_key", {{"hive", "HKLM"}, {"key", through}});
    CHECK(dk.rc == 0);
    CHECK(dk.has("status|ok"));
    yuzu::win::RegKey gone;
    CHECK(RegOpenKeyExW(HKEY_LOCAL_MACHINE, widen(through).c_str(), REG_OPTION_OPEN_LINK, KEY_READ, gone.put()) ==
          ERROR_FILE_NOT_FOUND);
    const auto kept = read(HKEY_LOCAL_MACHINE, root + "\\Target", "keep");
    REQUIRE(kept.found);
    CHECK(to_hex(kept.data) == "01000000");
}

// A link whose TARGET is absent is the shape that matters for a create: a create that follows it makes the
// target and reports REG_CREATED_NEW_KEY (kingsley probe, 2026-10-18), which the core cannot tell from a
// fresh key. Win32Registry::create_sub therefore passes REG_OPTION_OPEN_LINK. A link planted BEFORE the
// call is caught earlier, by the walk's own link-opening open and SymbolicLinkValue probe (key_is_link), so
// this case pins that a dangling link is refused and nothing is created through it; the create step's own
// flag needs a swap between the walk and the create, which a dispatcher-level case cannot stage, so
// test_registry_win_internals.cpp calls Win32Registry::create_sub on the dangling link directly.
TEST_CASE("registry write: a registry link whose target does not exist is refused and nothing is created through it",
          "[registry][windows][write]") {
    Plugin p;
    if (!p.ok()) { skip_or_fail("registry.dll not found"); return; }
    const std::string root = "SOFTWARE\\" + scratch_name();
    ScratchTree cleanup{HKEY_LOCAL_MACHINE, root};
    if (!put(HKEY_LOCAL_MACHINE, root + "\\Anchor", "keep", REG_DWORD, le(1, 4))) {
        skip_or_fail("not elevated -- HKLM scratch not writable, dangling-link case");
        return;
    }
    if (!make_machine_link(root + "\\Link", root + "\\Target")) { // Target is never created by this case
        skip_or_fail("could not create a registry link here");
        return;
    }

    const std::string through = root + "\\Link";
    const auto set = p.run("set_value", {{"hive", "HKLM"}, {"key", through}, {"name", "Evil"}, {"value", "x"}});
    CHECK(set.rc == 1);
    CHECK(set.has("error|key_is_link"));
    const auto deeper = p.run("set_value", {{"hive", "HKLM"}, {"key", through + "\\Child"}, {"name", "Evil"}, {"value", "x"}});
    CHECK(deeper.rc == 1);
    CHECK(deeper.has("error|key_is_link"));
    CHECK_FALSE(key_exists(HKEY_LOCAL_MACHINE, root + "\\Target"));

    // The link object itself is removable (by handle), so the scratch tree can go.
    const auto dk = p.run("delete_key", {{"hive", "HKLM"}, {"key", through}});
    CHECK(dk.rc == 0);
    CHECK(dk.has("status|ok"));
    CHECK_FALSE(key_exists(HKEY_LOCAL_MACHINE, root + "\\Target"));
}

TEST_CASE("registry write: an ACL-denied key is access_denied; an absent key is key_not_found",
          "[registry][windows][write]") {
    Plugin p;
    if (!p.ok()) { skip_or_fail("registry.dll not found"); return; }
    const std::string root = "Software\\" + scratch_name();
    const std::string key = root + "\\denied";
    ScratchTree cleanup{HKEY_CURRENT_USER, root};
    REQUIRE(put(HKEY_CURRENT_USER, key, "V", REG_DWORD, le(1, 4)));
    {
        yuzu::win::RegKey k;
        REQUIRE(RegOpenKeyExW(HKEY_CURRENT_USER, widen(key).c_str(), 0, WRITE_DAC, k.put()) == ERROR_SUCCESS);
        PSECURITY_DESCRIPTOR sd = nullptr;
        // Deny KEY_SET_VALUE (0x2) to Everyone, allow everything else.
        const BOOL made = ConvertStringSecurityDescriptorToSecurityDescriptorW(L"D:(D;;0x2;;;WD)(A;;GA;;;WD)", SDDL_REVISION_1, &sd, nullptr);
        const yuzu::win::LocalFreeGuard free_sd{sd}; // null-safe: owns it on both exits below
        if (!made || RegSetKeySecurity(k.get(), DACL_SECURITY_INFORMATION, sd) != ERROR_SUCCESS) {
            skip_or_fail("could not install a deny ACE");
            return;
        }
    }

    const auto denied = p.run("set_value", {{"hive", "HKCU"}, {"key", key}, {"name", "V"}, {"type", "REG_DWORD"}, {"value", "2"}});
    CHECK(denied.rc == 1);
    CHECK(denied.has("error|access_denied"));
    CHECK(to_hex(read(HKEY_CURRENT_USER, key, "V").data) == "01000000");
}

// The HKLM verdict table of the fast open, end to end through the plugin (HKLM is where the fast open runs). Every
// shape the reference walk refuses is still refused, wherever the link sits, and nothing is written through it;
// the one shape the walk would refuse but 1.0.0's single RegOpenKeyExW never did -- a decoy value named
// SymbolicLinkValue on a plain ANCESTOR -- writes the real requested key (README "How it works"). Needs an
// elevated token.
TEST_CASE("registry write: HKLM verdicts -- a link is refused wherever it sits and a decoy value on an ancestor "
          "is the documented divergence",
          "[registry][windows][write]") {
    Plugin p;
    if (!p.ok()) { skip_or_fail("registry.dll not found"); return; }
    const std::string root = "SOFTWARE\\" + scratch_name();
    ScratchTree cleanup{HKEY_LOCAL_MACHINE, root};
    if (!put(HKEY_LOCAL_MACHINE, root + "\\Real\\a\\b", "keep", REG_DWORD, le(1, 4)) ||
        !put(HKEY_LOCAL_MACHINE, root + "\\Decoy\\sub", "keep", REG_DWORD, le(1, 4)) ||
        !put(HKEY_LOCAL_MACHINE, root + "\\Decoy", "SymbolicLinkValue", REG_SZ, utf16(L"not a link"))) {
        skip_or_fail("not elevated -- HKLM scratch not writable, verdict-table case");
        return;
    }
    const std::vector<std::string> links{"Lnk", "LeafLnk", "Dangling", "Self"};
    // Deletes each link object through the plugin (by handle) before the scratch tree goes: RegDeleteTreeW follows a link.
    struct LinkSweep {
        Plugin& plugin;
        std::string base;
        std::vector<std::string> names;
        ~LinkSweep() {
            try {
                for (const auto& n : names) plugin.run("delete_key", {{"hive", "HKLM"}, {"key", base + "\\" + n}});
            } catch (...) {
            }
        }
    } sweep{p, root, links};
    if (!make_machine_link(root + "\\Lnk", root + "\\Real") ||
        !make_machine_link(root + "\\LeafLnk", root + "\\Real\\a") ||
        !make_machine_link(root + "\\Dangling", root + "\\Nowhere") ||
        !make_machine_link(root + "\\Self", root + "\\Self")) {
        skip_or_fail("could not create the registry links here");
        return;
    }

    struct Row {
        const char* what;
        std::string rel;
        std::string error; // "" = status|ok
    };
    const std::vector<Row> rows{
        {"an existing key", "Real\\a\\b", ""},
        {"the same key in another case", "real\\A\\B", ""},
        {"a path through a link", "Lnk\\a\\b", "key_is_link"},
        {"a link at the leaf", "LeafLnk", "key_is_link"},
        {"a dangling link at the leaf", "Dangling", "key_is_link"},
        {"a path through a dangling link", "Dangling\\x", "key_is_link"},
        {"a self-referential link", "Self", "key_is_link"},
        {"a decoy value on the LEAF", "Decoy", "key_is_link"},
        {"a missing suffix, created by the walk", "Real\\a\\new\\deeper", ""},
        {"a decoy value on a plain ANCESTOR (the walk refuses this one, the fast open writes it)", "Decoy\\sub", ""},
    };
    for (const auto& row : rows) {
        INFO(row.what);
        const auto out = p.run("set_value", {{"hive", "HKLM"}, {"key", root + "\\" + row.rel}, {"name", "V"},
                                             {"type", "REG_DWORD"}, {"value", "7"}});
        CHECK(out.audit_count() == 1);
        if (row.error.empty()) {
            CHECK(out.rc == 0);
            CHECK(out.has("status|ok"));
        } else {
            CHECK(out.rc == 1);
            CHECK(out.has("error|" + row.error));
        }
    }
    CHECK(to_hex(read(HKEY_LOCAL_MACHINE, root + "\\Real\\a\\b", "V").data) == "07000000");   // both case spellings land here
    CHECK(to_hex(read(HKEY_LOCAL_MACHINE, root + "\\Real\\a\\new\\deeper", "V").data) == "07000000");
    CHECK(to_hex(read(HKEY_LOCAL_MACHINE, root + "\\Decoy\\sub", "V").data) == "07000000");
    CHECK_FALSE(read(HKEY_LOCAL_MACHINE, root + "\\Real", "V").found);        // nothing went through Lnk or LeafLnk
    CHECK_FALSE(read(HKEY_LOCAL_MACHINE, root + "\\Real\\a", "V").found);
    CHECK_FALSE(key_exists(HKEY_LOCAL_MACHINE, root + "\\Nowhere"));           // nothing was created through Dangling
    CHECK_FALSE(read(HKEY_LOCAL_MACHINE, root + "\\Decoy", "V").found);
}

// No KEY_WOW64_* flag is ever passed: the plugin is a 64-bit DLL, so a plain path reaches the 64-bit view and a
// literal Wow6432Node path reaches exactly that key. Observed from outside, the only way to see a flag: a write to
// `SOFTWARE\<name>` must not appear under `SOFTWARE\Wow6432Node\<name>` (KEY_WOW64_32KEY would put it there), and a write
// to the literal Wow6432Node path must be readable at exactly that path in the 64-bit view.
TEST_CASE("registry write: no WOW64 view flag is passed and a literal Wow6432Node path reaches that key",
          "[registry][windows][write]") {
    Plugin p;
    if (!p.ok()) { skip_or_fail("registry.dll not found"); return; }
    const std::string plain = "SOFTWARE\\" + scratch_name() + "-wow-plain";
    const std::string literal = "SOFTWARE\\Wow6432Node\\" + scratch_name() + "-wow-literal";
    ScratchTree cleanup_plain{HKEY_LOCAL_MACHINE, plain};
    ScratchTree cleanup_wow_view{HKEY_LOCAL_MACHINE, "SOFTWARE\\Wow6432Node\\" + scratch_name() + "-wow-plain"};
    ScratchTree cleanup_literal{HKEY_LOCAL_MACHINE, literal};
    if (!put(HKEY_LOCAL_MACHINE, plain, "seed", REG_DWORD, le(1, 4)) ||
        !put(HKEY_LOCAL_MACHINE, literal, "seed", REG_DWORD, le(1, 4))) {
        skip_or_fail("not elevated -- HKLM scratch not writable, WOW64 case");
        return;
    }
    for (const auto& key : {plain, literal}) {
        const auto out = p.run("set_value", {{"hive", "HKLM"}, {"key", key}, {"name", "V"}, {"type", "REG_DWORD"}, {"value", "5"}});
        CHECK(out.rc == 0);
        CHECK(out.has("status|ok"));
        CHECK(to_hex(read(HKEY_LOCAL_MACHINE, key, "V").data) == "05000000");
    }
    CHECK_FALSE(key_exists(HKEY_LOCAL_MACHINE, "SOFTWARE\\Wow6432Node\\" + scratch_name() + "-wow-plain"));
}

#else // !_WIN32

// ═════════════════════════════════════════════════════════════════════════
// off Windows: the planned-stub contract of the loaded plugin
//
// Runs on every non-Windows host, unconditionally (no skip when the plugin was built: under
// `meson test` a missing library is a broken build and FAILS). It pins what the capability matrix and
// the dispatcher rely on: the plugin version, the 9 descriptors with the Windows leg SUPPORTED rung 1
// and the macOS / Linux legs PLANNED (naming the mechanism that will carry them), the read action's
// honest sentinel with rc 0, and every mutator's rc 1 with the same sentinel -- a write that did not
// happen is never a terminal SUCCESS (BR-03).
// ═════════════════════════════════════════════════════════════════════════

#include <yuzu/agent/plugin_loader.hpp>
#include <yuzu/plugin.h>

#include "local_dispatcher.hpp"

#include <algorithm>
#include <cstdlib>
#include <filesystem>
#include <iterator>
#include <optional>
#include <sstream>
#include <string_view>
#include <unordered_set>
#include <vector>

namespace fs = std::filesystem;

namespace {

#if defined(__APPLE__)
constexpr const char* kPluginExt = ".dylib";
constexpr const char* kSentinel = "registry|unsupported|Windows registry has no macOS equivalent; use defaults/plists";
#else
constexpr const char* kPluginExt = ".so";
constexpr const char* kSentinel = "registry|unsupported|Windows registry is not available on this platform";
#endif

constexpr std::string_view kExpectedActions[] = {
    "get_value",      "set_value",      "delete_value",   "delete_key",       "key_exists",
    "enumerate_keys", "enumerate_values", "get_user_value", "list_profiles"};
constexpr std::string_view kMutators[] = {"set_value", "delete_value", "delete_key"};

struct LoadedPlugin {
    yuzu::agent::PluginHandle handle;
    const YuzuPluginDescriptor* descriptor;
};

/// A missing library is a broken build under `meson test` (MESON_BUILD_ROOT set), never a pass.
std::optional<LoadedPlugin> load_registry_plugin() {
    const fs::path rel = fs::path{"agents"} / "plugins" / "registry" / (std::string{"registry"} + kPluginExt);
    std::vector<fs::path> candidates;
    if (auto* root = std::getenv("MESON_BUILD_ROOT")) candidates.push_back(fs::path{root} / rel);
    for (const char* dir : {".", "..", "build-macos", "build-linux"}) candidates.push_back(fs::path{dir} / rel);
    for (const auto& c : candidates) {
        std::error_code ec;
        if (!fs::exists(c, ec) || ec) continue;
        auto handle = yuzu::agent::PluginHandle::load(fs::absolute(c, ec));
        if (!handle.has_value() || !handle->descriptor()) return std::nullopt;
        const auto* descriptor = handle->descriptor();
        return LoadedPlugin{std::move(*handle), descriptor};
    }
    return std::nullopt;
}

void require_plugin_or_skip() {
    if (std::getenv("MESON_BUILD_ROOT") != nullptr)
        FAIL("registry plugin library not found under meson test -- the plugin did not build, or "
             "link_depends is not forcing it to build before this test runs");
    WARN("registry plugin library not found -- skipping (run from the build root, or via `meson test`)");
}

std::vector<std::string> rows_of(const std::string& captured) {
    std::vector<std::string> out;
    std::istringstream ss(captured);
    for (std::string line; std::getline(ss, line);) {
        if (!line.empty() && line.back() == '\r') line.pop_back();
        if (!line.empty()) out.push_back(line);
    }
    return out;
}

} // namespace

TEST_CASE("registry plugin: version 2.0.0 and the 9 descriptors -- Windows supported; macOS and Linux planned",
          "[registry][descriptors]") {
    auto plugin = load_registry_plugin();
    if (!plugin) return require_plugin_or_skip();

    CHECK(std::string_view{plugin->descriptor->name} == "registry");
    CHECK(std::string_view{plugin->descriptor->version} == "2.0.0");
    REQUIRE(plugin->descriptor->action_descriptor_count == std::size(kExpectedActions));
    REQUIRE(plugin->descriptor->action_descriptors != nullptr);
    std::unordered_set<std::string> seen;
    for (std::size_t i = 0; i < plugin->descriptor->action_descriptor_count; ++i) {
        const auto& d = plugin->descriptor->action_descriptors[i];
        REQUIRE(d.action != nullptr);
        INFO("action: " << d.action);
        seen.insert(d.action);
        CHECK(d.linux_leg.support == YUZU_SUPPORT_PLANNED);
        CHECK(d.linux_leg.rung == 2);
        CHECK(std::string_view{d.linux_leg.mechanism} == "dconf/gsettings");
        CHECK(d.macos_leg.support == YUZU_SUPPORT_PLANNED);
        CHECK(d.macos_leg.rung == 1);
        CHECK(std::string_view{d.macos_leg.mechanism} == "defaults/CFPreferences (per-domain plist)");
        CHECK(d.windows_leg.support == YUZU_SUPPORT_SUPPORTED);
        CHECK(d.windows_leg.rung == 1);
    }
    CHECK(seen == std::unordered_set<std::string>(std::begin(kExpectedActions), std::end(kExpectedActions)));
}

TEST_CASE("registry plugin: off Windows a read answers the sentinel with rc 0 and every mutator with rc 1",
          "[registry][actions]") {
    auto plugin = load_registry_plugin();
    if (!plugin) return require_plugin_or_skip();

    SECTION("get_value: the honest sentinel, a successful read of an unavailable store") {
        yuzu::agent::LocalDispatcher dispatcher;
        const auto result = dispatcher.run(plugin->descriptor, "get_value");
        CHECK(result.rc == 0);
        const auto rows = rows_of(result.captured);
        REQUIRE(rows.size() == 1);
        CHECK(rows[0] == kSentinel);
    }
    for (const auto action : kMutators) {
        SECTION(std::string{"mutator "} + std::string{action}) {
            yuzu::agent::LocalDispatcher dispatcher;
            const auto result = dispatcher.run(plugin->descriptor, action);
            CHECK(result.rc == 1); // a write that did not happen is never a terminal SUCCESS
            const auto rows = rows_of(result.captured);
            REQUIRE(rows.size() == 1);
            CHECK(rows[0] == kSentinel);
        }
    }
    SECTION("an unknown action is an error, not a silent success") {
        yuzu::agent::LocalDispatcher dispatcher;
        const auto result = dispatcher.run(plugin->descriptor, "get_vaule");
        CHECK(result.rc == 1);
        const auto rows = rows_of(result.captured);
        REQUIRE(rows.size() == 1);
        CHECK(rows[0] == "error|unknown action: get_vaule");
    }
}

#endif // _WIN32
