/**
 * test_registry_write_local_dispatcher.cpp -- the REAL registry.dll's mutating actions driven
 * through yuzu::agent::LocalDispatcher against the live Windows registry (the pure logic is locked on
 * every host by test_registry_parsers.cpp / test_registry_core.cpp; this proves the Win32 binding).
 *
 * Registry 2.1.0 adds the recursive delete_key, the per-user hive writes (the caller's LIVE hive and an OFFLINE NTUSER.DAT
 * fixture, both through the real with_user_hive ladder) and `apply` (dry run, real run, reversed manifest, a create
 * denied by ACL, a 256-item reply under the dispatcher's capture cap).
 *
 * Every key lives under a salted `YuzuTest-[<scope>-]<yuzu::test::process_random_salt()>` (#1871: a fixed
 * registry key is a cross-JOB shared resource; the optional scope is YUZU_TEST_REGISTRY_SCOPE, which CI sets per
 * job so its leftover-key check is per job) and an RAII guard removes each scratch object. Cases that need
 * elevation WARN and skip, and a skip is NOT evidence: YUZU_REQUIRE_WINDOWS_REGISTRY_TESTS=1 (CI's Windows leg,
 * #6488, and the evidence runs) turns every skip into a FAIL -- see skip_or_fail(). Off Windows this TU pins
 * the planned-stub contract of the loaded plugin and the ABI-containment catch of its execute() (the #else
 * branch). The last case, on every host, pins the scratch-key prefix helper the per-job leftover check relies on.
 */
#include <catch2/catch_test_macros.hpp>

#include <string>
#include <string_view>

#include "scoped_env.hpp"
#include "test_helpers.hpp"

#ifdef _WIN32

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>

#include <aclapi.h>
#include <sddl.h>

#include <yuzu/agent/plugin_loader.hpp>
#include <yuzu/plugin.h>

#include <win_hive_file_probe.hpp> // yuzu::win::LocalFreeGuard
#include <win_profiles.hpp>        // PrivilegeScope, ScopedUserHive
#include <win_reg_handle.hpp>

#include "local_dispatcher.hpp"

#include <algorithm>
#include <cstdint>
#include <cstdlib>
#include <filesystem>
#include <future>
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
        bool truncated = false; ///< the dispatcher's capture cap was hit (its sentinel is appended to the capture)
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

    Out run(const std::string& action, const std::map<std::string, std::string>& params,
            std::size_t capture_cap = yuzu::agent::LocalDispatcher::kCaptureMaxBytes) {
        std::vector<YuzuParam> raw;
        for (const auto& [k, v] : params) raw.push_back(YuzuParam{k.c_str(), v.c_str()});
        const auto r = dispatcher.run(handle->descriptor(), action, raw, capture_cap);
        Out out;
        out.rc = r.rc;
        out.truncated = r.truncated;
        std::istringstream in(r.captured);
        for (std::string l; std::getline(in, l);) out.lines.push_back(l);
        return out;
    }
};

// ── skip or fail ─────────────────────────────────────────────────────────

/// A case that cannot run (registry.dll missing, the process not elevated, a fixture that could not
/// be built) WARNs and returns -- unless YUZU_REQUIRE_WINDOWS_REGISTRY_TESTS is set to a non-empty
/// value other than "0", when it FAILs: a skipped real-registry run proves nothing, so CI's Windows leg and the
/// evidence runs (elevated) set the variable and a skip there is red, never silently green.
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
std::string scratch_name() { return yuzu::test::registry_scratch_prefix() + salt(); }
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

/// Removes registry link objects (HKLM-relative `paths`) BY HANDLE on scope exit: a link-opening open with DELETE,
/// then NtDeleteKey on that handle, which removes the link object and never its target (the shape of
/// test_registry_win_internals.cpp's LinkSweep, which this TU cannot reuse because it does not include
/// registry_win.cpp). Independent of the plugin under test, so a failed plugin call cannot leave a link behind
/// for the ScratchTree's RegDeleteTreeW, which FOLLOWS links. Declare it AFTER the ScratchTree it protects, so it
/// runs first. A path that is absent (the plugin already removed it) is skipped; never throws.
struct LinkSweep {
    std::vector<std::string> paths;
    ~LinkSweep() {
        try {
            using NtDeleteKeyFn = LONG(NTAPI*)(HANDLE);
            static const NtDeleteKeyFn nt_delete_key = [] {
                const HMODULE ntdll = GetModuleHandleW(L"ntdll.dll");
                return ntdll == nullptr ? nullptr
                                        : reinterpret_cast<NtDeleteKeyFn>(
                                              reinterpret_cast<void*>(GetProcAddress(ntdll, "NtDeleteKey")));
            }();
            if (nt_delete_key == nullptr) return; // leave the link; a by-name delete would follow it
            for (const auto& path : paths) {
                yuzu::win::RegKey k;
                if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, widen(path).c_str(), REG_OPTION_OPEN_LINK, DELETE, k.put()) ==
                    ERROR_SUCCESS)
                    nt_delete_key(k.get());
            }
        } catch (...) {
        }
    }
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
        std::string new_field; ///< when set: what new= carries (raw hex of the bytes, capped at 256 with ~<total>)
    };
    const std::string mib_hex(2 * 1024 * 1024, 'a');
    const std::vector<Case> cases{
        {"REG_SZ", {{"type", "REG_SZ"}, {"value", "hello"}}, REG_SZ, utf16(L"hello"),
         "680065006c006c006f000000"},
        {"empty REG_SZ", {{"type", "REG_SZ"}, {"value", ""}}, REG_SZ, utf16(L"")},
        {"default type is REG_SZ", {{"value", "x"}}, REG_SZ, utf16(L"x")},
        {"REG_EXPAND_SZ", {{"type", "REG_EXPAND_SZ"}, {"value", "%TEMP%\\x"}}, REG_EXPAND_SZ, utf16(L"%TEMP%\\x")},
        {"REG_DWORD", {{"type", "REG_DWORD"}, {"value", "4294967295"}}, REG_DWORD, le(0xFFFFFFFFu, 4), "ffffffff"},
        {"REG_QWORD", {{"type", "REG_QWORD"}, {"value", "18446744073709551615"}}, REG_QWORD, le(~0ull, 8),
         "ffffffffffffffff"},
        {"REG_MULTI_SZ", {{"type", "REG_MULTI_SZ"}, {"value", "a\nb"}}, REG_MULTI_SZ,
         Bytes{0x61, 0, 0, 0, 0x62, 0, 0, 0, 0, 0}},
        {"empty REG_MULTI_SZ", {{"type", "REG_MULTI_SZ"}, {"value", ""}}, REG_MULTI_SZ, Bytes{0, 0, 0, 0}},
        {"REG_BINARY with embedded NULs", {{"type", "REG_BINARY"}, {"value", "00ff0000aa"}}, REG_BINARY, Bytes{0, 0xff, 0, 0, 0xaa}},
        {"empty REG_BINARY", {{"type", "REG_BINARY"}, {"value", ""}}, REG_BINARY, Bytes{}},
        {"data_hex for a string type", {{"type", "REG_SZ"}, {"data_hex", "61000000"}}, REG_SZ, Bytes{0x61, 0, 0, 0}},
        // 256 raw bytes as hex, then the total length.
        {"1 MiB REG_BINARY", {{"type", "REG_BINARY"}, {"data_hex", mib_hex}}, REG_BINARY, Bytes(1024 * 1024, 0xaa),
         std::string(512, 'a') + "~1048576"},
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
        if (!c.new_field.empty()) CHECK(out.lines[0].ends_with("|new=" + c.new_field)); // raw hex, never masked
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

// enumerate_values read value names into a 256-wchar buffer and ended the list at the first name that did not fit
// (ERROR_MORE_DATA), answering rc 0 with the list cut short; set_value accepts names up to 16,383 characters.
TEST_CASE("registry write: enumerate_values lists value names longer than 255 characters up to the 16383 maximum and the values after them",
          "[registry][windows][write]") {
    Plugin p;
    if (!p.ok()) { skip_or_fail("registry.dll not found"); return; }
    const std::string key = "Software\\" + scratch_name() + "\\longname";
    ScratchTree cleanup{HKEY_CURRENT_USER, "Software\\" + scratch_name()};
    const std::string name(300, 'n');
    const std::string longest(16383, 'm'); // the registry maximum: the enumeration buffer must hold all of it
    for (const auto& n : {name, longest}) {
        const auto set = p.run("set_value", {{"hive", "HKCU"}, {"key", key}, {"name", n}, {"type", "REG_DWORD"}, {"value", "1"}});
        REQUIRE(set.rc == 0);
    }
    REQUIRE(put(HKEY_CURRENT_USER, key, "after", REG_DWORD, le(2, 4))); // a truncated list ends before this one
    const auto vals = p.run("enumerate_values", {{"hive", "HKCU"}, {"key", key}});
    CHECK(vals.rc == 0);
    CHECK(vals.has("value|" + name + "|REG_DWORD"));
    CHECK(vals.has("value|" + longest + "|REG_DWORD"));
    CHECK(vals.has("value|after|REG_DWORD"));
    CHECK(vals.lines.size() == 3);
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
    REQUIRE(put(HKEY_CURRENT_USER, key, "U", REG_SZ, utf16(L"a\u2028b\x85" L"c\u2029d"))); // the Unicode line breaks
    const auto out = p.run("get_value", {{"hive", "HKCU"}, {"key", key}, {"name", "V"}});
    CHECK(out.rc == 0);
    CHECK(out.audit_count() == 0);
    CHECK(out.has("value|x_audit_op=set_value_result=ok"));
    const auto unicode = p.run("get_value", {{"hive", "HKCU"}, {"key", key}, {"name", "U"}});
    CHECK(unicode.rc == 0);
    CHECK(unicode.has("value|a_b_c_d")); // U+2028, U+0085 and U+2029 fold to '_' like LF: one row, never split
    const auto subs = p.run("enumerate_keys", {{"hive", "HKCU"}, {"key", key}});
    CHECK(subs.audit_count() == 0);
    for (const auto& l : subs.lines) CHECK(l.find('\n') == std::string::npos);
    // enumerate_values lists value NAMES, the registry's other attacker-shaped text: the LF and the `|` in the
    // name become `_`, no line starts with audit|, and the two values are exactly two rows.
    const auto vals = p.run("enumerate_values", {{"hive", "HKCU"}, {"key", key}});
    CHECK(vals.rc == 0);
    CHECK(vals.audit_count() == 0);
    CHECK(vals.has("value|N__audit_op=set_value_result=ok|REG_DWORD"));
    CHECK(vals.has("value|U|REG_SZ"));
    CHECK(vals.lines.size() == 3);
}

// #6490: get_value reads at most kMaxWriteBytes (1 MiB, the bound get_user_value and the write path already use) and
// answers get_user_value's oversized line for a larger value instead of holding the bytes three times (the read, the
// hex string, the sanitised copy). The boundary is inclusive, as query_value_bounded's own case pins.
// Mutation: put the bound back to UINT32_MAX -> the 1 MiB + 1 section answers the value.
TEST_CASE("registry read: get_value answers a value of exactly 1 MiB and refuses one byte more",
          "[registry][windows][write]") {
    Plugin p;
    if (!p.ok()) { skip_or_fail("registry.dll not found"); return; }
    const std::string key = "Software\\" + scratch_name() + "\\big";
    ScratchTree cleanup{HKEY_CURRENT_USER, "Software\\" + scratch_name()};
    constexpr std::size_t kMiB = 1024 * 1024;
    // The hex of 1 MiB is 2 MiB: past LocalDispatcher's default capture cap, so this case raises it.
    constexpr std::size_t kCap = 4 * kMiB;

    SECTION("exactly 1 MiB: the value and its type, no audit line") {
        REQUIRE(put(HKEY_CURRENT_USER, key, "V", REG_BINARY, Bytes(kMiB, 0xaa)));
        const auto out = p.run("get_value", {{"hive", "HKCU"}, {"key", key}, {"name", "V"}}, kCap);
        CHECK(out.rc == 0);
        CHECK(out.has("type|REG_BINARY"));
        CHECK(out.has("value|" + std::string(2 * kMiB, 'a')));
        CHECK(out.audit_count() == 0);
    }
    SECTION("1 MiB + 1: refused with the shared oversized line, no value, no audit line") {
        REQUIRE(put(HKEY_CURRENT_USER, key, "V", REG_BINARY, Bytes(kMiB + 1, 0xaa)));
        const auto out = p.run("get_value", {{"hive", "HKCU"}, {"key", key}, {"name", "V"}}, kCap);
        CHECK(out.rc == 1);
        REQUIRE(out.lines.size() == 1);
        CHECK(out.lines[0] == "error|value exceeds 1 MiB limit");
        CHECK(out.audit_count() == 0);
    }
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
    LinkSweep sweep{{root + "\\Link"}};
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
// target and reports REG_CREATED_NEW_KEY (measured 2026-10-18), which the core cannot tell from a
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
    LinkSweep sweep{{root + "\\Link"}};
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
    // Removes each link object by handle before the scratch tree goes: RegDeleteTreeW follows a link.
    LinkSweep sweep;
    for (const char* name : {"Lnk", "LeafLnk", "Dangling", "Self"}) sweep.paths.push_back(root + "\\" + name);
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

TEST_CASE("registry write: a non-ASCII key and value name reach the registry as UTF-16 text",
          "[registry][windows][write]") {
    // The plugin converts ASCII names through a stack buffer and every other name through the full UTF-8 to
    // UTF-16 conversion. A name with a two-byte UTF-8 character must land as ONE UTF-16 code unit, not as two
    // widened bytes.
    Plugin p;
    if (!p.ok()) { skip_or_fail("registry.dll not found"); return; }
    ScratchTree cleanup{HKEY_CURRENT_USER, "Software\\" + scratch_name()};
    const std::string key = "Software\\" + scratch_name() + "\\caf\xC3\xA9";
    const auto out = p.run("set_value", {{"hive", "HKCU"}, {"key", key}, {"name", "n\xC3\xA9"}, {"type", "REG_DWORD"}, {"value", "7"}});
    CHECK(out.rc == 0);
    CHECK(out.has("status|ok"));
    yuzu::win::RegKey k;
    const std::wstring wkey = L"Software\\" + widen(scratch_name()) + L"\\caf\u00e9";
    REQUIRE(RegOpenKeyExW(HKEY_CURRENT_USER, wkey.c_str(), 0, KEY_QUERY_VALUE, k.put()) == ERROR_SUCCESS);
    DWORD type = 0, got = 4;
    std::uint8_t data[4] = {};
    REQUIRE(RegQueryValueExW(k.get(), L"n\u00e9", nullptr, &type, data, &got) == ERROR_SUCCESS);
    CHECK(type == REG_DWORD);
    CHECK(got == 4);
    CHECK(data[0] == 7);
}

// ═════════════════════════════════════════════════════════════════════════
// registry 2.1.0: recursive delete_key, per-user hive writes, apply
// ═════════════════════════════════════════════════════════════════════════

namespace {

/// The caller's own user SID as a string ("S-1-5-21-..."), nullopt when it cannot be read.
std::optional<std::string> current_user_sid() {
    HANDLE token{};
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &token)) return std::nullopt;
    struct Closer {
        HANDLE h;
        ~Closer() { CloseHandle(h); }
    } guard{token};
    DWORD needed = 0;
    GetTokenInformation(token, TokenUser, nullptr, 0, &needed);
    if (needed == 0) return std::nullopt;
    std::vector<BYTE> buf(needed);
    if (!GetTokenInformation(token, TokenUser, buf.data(), needed, &needed)) return std::nullopt;
    LPWSTR s = nullptr;
    const BOOL converted = ConvertSidToStringSidW(reinterpret_cast<TOKEN_USER*>(buf.data())->User.Sid, &s);
    const yuzu::win::LocalFreeGuard free_s{s}; // owns the string before the resize below can throw
    if (!converted || !s) return std::nullopt;
    // n counts the terminating NUL: the buffer holds all n bytes, then the NUL is dropped.
    const int n = WideCharToMultiByte(CP_UTF8, 0, s, -1, nullptr, 0, nullptr, nullptr);
    if (n <= 1) return std::nullopt;
    std::string out(static_cast<std::size_t>(n), '\0');
    if (WideCharToMultiByte(CP_UTF8, 0, s, -1, out.data(), n, nullptr, nullptr) != n) return std::nullopt;
    out.pop_back();
    return out;
}

/// The cells of one `item|...` / `undo|...` row `idx` of an apply reply (empty when the row is absent).
std::vector<std::string> row_cells(const Plugin::Out& o, const std::string& kind, int idx) {
    std::vector<std::string> f;
    const std::string prefix = kind + "|" + std::to_string(idx) + "|";
    for (const auto& l : o.lines)
        if (l.rfind(prefix, 0) == 0) {
            std::istringstream in(l);
            for (std::string c; std::getline(in, c, '|');) f.push_back(c);
            break;
        }
    return f;
}

/// `\` doubled, for a key path embedded in a JSON string.
std::string json_path(const std::string& path) {
    std::string e;
    for (const char c : path) e += (c == '\\') ? "\\\\" : std::string{c};
    return e;
}

/// Gives `key` (a handle opened with WRITE_DAC) a DACL, from SDDL text. False when it could not.
bool set_key_sddl(HKEY key, const wchar_t* sddl) {
    PSECURITY_DESCRIPTOR sd = nullptr;
    if (!ConvertStringSecurityDescriptorToSecurityDescriptorW(sddl, SDDL_REVISION_1, &sd, nullptr)) return false;
    const yuzu::win::LocalFreeGuard free_sd{sd};
    return RegSetKeySecurity(key, DACL_SECURITY_INFORMATION, sd) == ERROR_SUCCESS;
}

/// Reopens `path` (HKLM) onto a permissive DACL on scope exit, so a deny ACE the case installed never blocks the
/// scratch tree's removal. Never throws.
struct AclRestore {
    std::string path;
    ~AclRestore() {
        yuzu::win::RegKey k;
        if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, widen(path).c_str(), 0, WRITE_DAC | READ_CONTROL, k.put()) == ERROR_SUCCESS)
            set_key_sddl(k.get(), L"D:(A;;GA;;;WD)");
    }
};

} // namespace

TEST_CASE("registry write: delete_key recursive -- dry-run counts equal the real counts and change nothing",
          "[registry][windows][write][recursive]") {
    Plugin p;
    if (!p.ok()) { skip_or_fail("registry.dll not found"); return; }
    const std::string tree = "Software\\" + scratch_name() + "\\tree";
    ScratchTree cleanup{HKEY_CURRENT_USER, "Software\\" + scratch_name()};
    // 4 keys (tree, c1, c1\g1, c2) and 5 values.
    REQUIRE(put(HKEY_CURRENT_USER, tree, "r1", REG_DWORD, le(1, 4)));
    REQUIRE(put(HKEY_CURRENT_USER, tree, "r2", REG_SZ, utf16(L"x")));
    REQUIRE(put(HKEY_CURRENT_USER, tree + "\\c1", "c", REG_DWORD, le(2, 4)));
    REQUIRE(put(HKEY_CURRENT_USER, tree + "\\c1\\g1", "g1", REG_DWORD, le(3, 4)));
    REQUIRE(put(HKEY_CURRENT_USER, tree + "\\c1\\g1", "g2", REG_BINARY, Bytes{1, 2}));
    {
        yuzu::win::RegKey k;
        REQUIRE(RegCreateKeyExW(HKEY_CURRENT_USER, widen(tree + "\\c2").c_str(), 0, nullptr, 0, KEY_READ, nullptr, k.put(),
                                nullptr) == ERROR_SUCCESS);
    }

    SECTION("a non-recursive delete of a key with subkeys is refused") {
        const auto out = p.run("delete_key", {{"hive", "HKCU"}, {"key", tree}});
        CHECK(out.rc == 1);
        CHECK(out.has("error|key_has_subkeys"));
        CHECK(key_exists(HKEY_CURRENT_USER, tree));
    }
    SECTION("a flag that is not a boolean is invalid_data, audited as a refusal, and nothing is deleted") {
        for (const auto& [flag, value] : std::vector<std::pair<std::string, std::string>>{
                 {"recursive", "maybe"}, {"recursive", "2"}, {"dry_run", "yes"}}) {
            const auto out = p.run("delete_key", {{"hive", "HKCU"}, {"key", tree}, {flag, value}});
            INFO(flag << "=" << value);
            CHECK(out.rc == 1);
            CHECK(out.has("error|invalid_data"));
            CHECK(out.audit().find("|result=refused|reason=invalid_data|") != std::string::npos);
            CHECK(key_exists(HKEY_CURRENT_USER, tree + "\\c1\\g1"));
        }
    }
    SECTION("dry run then real") {
        const auto dry = p.run("delete_key", {{"hive", "HKCU"}, {"key", tree}, {"recursive", "true"}, {"dry_run", "true"}});
        CHECK(dry.rc == 0);
        CHECK(dry.has("status|ok"));
        CHECK(dry.has("counted_keys|4"));
        CHECK(dry.has("counted_values|5"));
        CHECK(dry.has("dry_run|1"));
        CHECK(dry.has("capped|0"));
        CHECK(dry.audit().find("|dry_run=1|") != std::string::npos);
        CHECK(key_exists(HKEY_CURRENT_USER, tree + "\\c1\\g1")); // nothing removed

        const auto real = p.run("delete_key", {{"hive", "HKCU"}, {"key", tree}, {"recursive", "true"}});
        CHECK(real.rc == 0);
        CHECK(real.has("counted_keys|4"));
        CHECK(real.has("counted_values|5"));
        CHECK(real.has("dry_run|0"));
        CHECK(real.has("capped|0"));
        CHECK(real.audit().find("|result=ok|reason=-|verify=ok|") != std::string::npos);
        CHECK(real.audit().find("|dry_run=0|counted_keys=4|counted_values=5|capped=0|") != std::string::npos);
        CHECK_FALSE(key_exists(HKEY_CURRENT_USER, tree));
    }
    SECTION("a non-recursive dry run counts a leaf and deletes nothing") {
        const auto dry = p.run("delete_key", {{"hive", "HKCU"}, {"key", tree + "\\c1\\g1"}, {"dry_run", "true"}});
        CHECK(dry.rc == 0);
        CHECK(dry.has("counted_keys|1"));
        CHECK(dry.has("counted_values|2"));
        CHECK(dry.has("dry_run|1"));
        CHECK(key_exists(HKEY_CURRENT_USER, tree + "\\c1\\g1"));
    }
}

TEST_CASE("registry write: a recursive delete refuses a registry link inside the tree and deletes nothing, "
          "and a link leaf is removed alone",
          "[registry][windows][write][recursive]") {
    Plugin p;
    if (!p.ok()) { skip_or_fail("registry.dll not found"); return; }
    // HKLM, as the single-key link case does: the link target path is the same on every account.
    const std::string root = "SOFTWARE\\" + scratch_name();
    ScratchTree cleanup{HKEY_LOCAL_MACHINE, root};
    if (!put(HKEY_LOCAL_MACHINE, root + "\\Target", "keep", REG_DWORD, le(1, 4))) {
        skip_or_fail("not elevated -- HKLM scratch not writable, recursive link case");
        return;
    }
    REQUIRE(put(HKEY_LOCAL_MACHINE, root + "\\Target\\Y", "keep", REG_DWORD, le(2, 4)));
    REQUIRE(put(HKEY_LOCAL_MACHINE, root + "\\Tree\\A", "a", REG_DWORD, le(3, 4)));
    LinkSweep sweep{{root + "\\Tree\\Link"}};
    if (!make_machine_link(root + "\\Tree\\Link", root + "\\Target")) {
        skip_or_fail("could not create a registry link here");
        return;
    }

    for (const char* dry : {"true", "false"}) {
        INFO("dry_run=" << dry);
        const auto out = p.run("delete_key", {{"hive", "HKLM"}, {"key", root + "\\Tree"}, {"recursive", "true"}, {"dry_run", dry}});
        CHECK(out.rc == 1);
        CHECK(out.has("error|key_is_link"));
        CHECK(key_exists(HKEY_LOCAL_MACHINE, root + "\\Tree\\A"));  // the vet refused before anything was removed
        CHECK(key_exists(HKEY_LOCAL_MACHINE, root + "\\Target\\Y")); // the link's target and its subtree are intact
        CHECK(read(HKEY_LOCAL_MACHINE, root + "\\Target", "keep").found);
    }
    // The key AT the link path is the link object: a recursive delete removes it and never enters the target.
    const auto leaf = p.run("delete_key", {{"hive", "HKLM"}, {"key", root + "\\Tree\\Link"}, {"recursive", "true"}});
    CHECK(leaf.rc == 0);
    CHECK(key_exists(HKEY_LOCAL_MACHINE, root + "\\Target\\Y"));
    CHECK(read(HKEY_LOCAL_MACHINE, root + "\\Target", "keep").found);
    // ... and with the link gone the same tree deletes cleanly
    const auto rest = p.run("delete_key", {{"hive", "HKLM"}, {"key", root + "\\Tree"}, {"recursive", "true"}});
    CHECK(rest.rc == 0);
    CHECK_FALSE(key_exists(HKEY_LOCAL_MACHINE, root + "\\Tree"));
}

TEST_CASE("registry write: set_user_value / delete_user_value on the caller's own LIVE hive round-trip, "
          "with no unload warning",
          "[registry][windows][write][user]") {
    Plugin p;
    if (!p.ok()) { skip_or_fail("registry.dll not found"); return; }
    const auto sid = current_user_sid();
    if (!sid) { skip_or_fail("no SID"); return; }
    const std::string root = "Software\\" + scratch_name();
    ScratchTree cleanup{HKEY_CURRENT_USER, root};
    // set_user_value resolves the profile through ProfileList like get_user_value; a system account
    // (S-1-5-18/19/20) is deliberately not in that list.
    const auto probe = p.run("get_user_value", {{"sid", *sid}, {"key", root}, {"name", "x"}});
    if (probe.has("error|sid '" + *sid + "' not found in enumerated profiles")) {
        skip_or_fail("own SID is not an enumerated, non-system profile (running as a system account?)");
        return;
    }
    struct Case {
        const char* what;
        std::map<std::string, std::string> params;
        DWORD type;
        Bytes expect;
        const char* type_name;
    };
    const std::vector<Case> cases{
        {"REG_SZ", {{"type", "REG_SZ"}, {"value", "hello"}}, REG_SZ, utf16(L"hello"), "REG_SZ"},
        {"REG_EXPAND_SZ", {{"type", "REG_EXPAND_SZ"}, {"value", "%TEMP%\\x"}}, REG_EXPAND_SZ, utf16(L"%TEMP%\\x"), "REG_EXPAND_SZ"},
        {"REG_DWORD", {{"type", "REG_DWORD"}, {"value", "42"}}, REG_DWORD, le(42, 4), "REG_DWORD"},
        {"REG_QWORD", {{"type", "REG_QWORD"}, {"value", "18446744073709551615"}}, REG_QWORD, le(~0ull, 8), "REG_QWORD"},
        {"REG_MULTI_SZ", {{"type", "REG_MULTI_SZ"}, {"value", "a\nb"}}, REG_MULTI_SZ, Bytes{0x61, 0, 0, 0, 0x62, 0, 0, 0, 0, 0},
         "REG_MULTI_SZ"},
        {"REG_BINARY", {{"type", "REG_BINARY"}, {"value", "00ff0000aa"}}, REG_BINARY, Bytes{0, 0xff, 0, 0, 0xaa}, "REG_BINARY"},
    };
    int i = 0;
    for (auto c : cases) {
        INFO(c.what);
        c.params["sid"] = *sid;
        c.params["key"] = root + "\\u";
        c.params["name"] = "V" + std::to_string(i++);
        const auto set = p.run("set_user_value", c.params);
        CHECK(set.rc == 0);
        CHECK(set.has("status|ok"));
        CHECK(set.audit().find("|op=set_user_value|hive=HKU|") != std::string::npos);
        CHECK(set.audit().find("|sid=" + *sid + "|") != std::string::npos);
        CHECK(set.audit().find("|result=ok|reason=-|verify=ok|") != std::string::npos);
        for (const auto& l : set.lines) CHECK(l.find("hive_unload_failed") == std::string::npos);
        const auto r = read(HKEY_CURRENT_USER, root + "\\u", c.params["name"]);
        REQUIRE(r.found);
        CHECK(r.type == c.type);
        CHECK(to_hex(r.data) == to_hex(c.expect));
        // and the read action sees the same value, through the same ladder
        const auto got = p.run("get_user_value", {{"sid", *sid}, {"key", root + "\\u"}, {"name", c.params["name"]}});
        CHECK(got.rc == 0);
        CHECK(got.has(std::string{"type|"} + c.type_name));
    }

    const auto del = p.run("delete_user_value", {{"sid", *sid}, {"key", root + "\\u"}, {"name", "V2"}});
    CHECK(del.rc == 0);
    CHECK(del.audit().find("|op=delete_user_value|hive=HKU|") != std::string::npos);
    CHECK_FALSE(read(HKEY_CURRENT_USER, root + "\\u", "V2").found);
    const auto again = p.run("delete_user_value", {{"sid", *sid}, {"key", root + "\\u"}, {"name", "V2"}});
    CHECK(again.rc == 1);
    CHECK(again.has("error|value_not_found"));
    const auto nosuch = p.run("set_user_value", {{"sid", "S-1-5-21-0-0-0-999999999"}, {"key", root}, {"name", "V"}, {"value", "x"}});
    CHECK(nosuch.rc == 1);
    const auto bad = p.run("set_user_value", {{"sid", *sid}, {"key", root + "\\u"}, {"name", "V"}, {"type", "REG_DWORD"}, {"value", "x"}});
    CHECK(bad.rc == 1);
    CHECK(bad.audit().find("|result=refused|reason=invalid_data|") != std::string::npos);
}

namespace {

/// An elevated-only offline-hive fixture: a salted temp "profile" directory holding an NTUSER.DAT saved with
/// RegSaveKeyExW from a scratch HKCU key, plus a salted fake SID under ProfileList pointing at it. Removed on scope
/// exit. The scratch names carry registry_scratch_prefix(), so a leftover is visible to the per-job leftover check.
struct OfflineProfile {
    bool ok = false;
    std::string sid;
    yuzu::test::TempDir tmp{"yuzu_test_profile_"}; // salted, removed on destruction; matches the Defender wildcard
    fs::path dir;                                  // tmp.path in its long-path form, once created
    std::string profile_key;
    HKEY hklm = HKEY_LOCAL_MACHINE;

    OfflineProfile() {
        yuzu::win::PrivilegeScope backup(L"SeBackupPrivilege");
        yuzu::win::PrivilegeScope restore(L"SeRestorePrivilege");
        if (!backup.ok() || !restore.ok()) return;
        sid = "S-1-5-21-1-2-3-" + std::to_string(90000 + (yuzu::test::process_random_salt() % 9000));
        dir = tmp.path;
        std::error_code ec;
        fs::create_directories(dir, ec);
        {   // The hive-file guard compares the requested path with the kernel's final (long) path, so hand it the
            // long form (a user's %TEMP% is often an 8.3 short path).
            wchar_t longp[MAX_PATH * 2]{};
            if (GetLongPathNameW(dir.c_str(), longp, static_cast<DWORD>(std::size(longp))) > 0) dir = longp;
        }
        const std::string src = "Software\\" + scratch_name() + "\\fixture";
        if (!put(HKEY_CURRENT_USER, src, "seed", REG_DWORD, le(1, 4))) return;
        const fs::path hive = dir / "NTUSER.DAT";
        LSTATUS rc = ERROR_GEN_FAILURE;
        {
            yuzu::win::RegKey k;
            if (RegOpenKeyExW(HKEY_CURRENT_USER, widen("Software\\" + scratch_name()).c_str(), 0, KEY_READ, k.put()) != ERROR_SUCCESS)
                return;
            rc = RegSaveKeyExW(k.get(), hive.wstring().c_str(), nullptr, REG_STANDARD_FORMAT);
        }
        RegDeleteTreeW(HKEY_CURRENT_USER, widen("Software\\" + scratch_name()).c_str());
        if (rc != ERROR_SUCCESS) return;
        {   // RegSaveKeyExW leaves the file owned by the calling user's SID, which the hive-file guard refuses (allowed
            // owners: the profile's SID, SYSTEM, Administrators). A real NTUSER.DAT is owned by its profile SID; this
            // fake profile uses a made-up SID, so give the file to Administrators.
            PSID admins = nullptr;
            if (!ConvertStringSidToSidW(L"S-1-5-32-544", &admins)) return;
            const yuzu::win::LocalFreeGuard free_admins{admins};
            const DWORD orc = SetNamedSecurityInfoW(const_cast<LPWSTR>(hive.wstring().c_str()), SE_FILE_OBJECT,
                                                    OWNER_SECURITY_INFORMATION, admins, nullptr, nullptr, nullptr);
            if (orc != ERROR_SUCCESS) return;
        }
        profile_key = "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\ProfileList\\" + sid;
        yuzu::win::RegKey pk;
        if (RegCreateKeyExW(hklm, widen(profile_key).c_str(), 0, nullptr, 0, KEY_SET_VALUE, nullptr, pk.put(), nullptr) !=
            ERROR_SUCCESS)
            return;
        const std::wstring path = dir.wstring();
        ok = RegSetValueExW(pk.get(), L"ProfileImagePath", 0, REG_EXPAND_SZ, reinterpret_cast<const BYTE*>(path.c_str()),
                            static_cast<DWORD>((path.size() + 1) * sizeof(wchar_t))) == ERROR_SUCCESS;
    }
    ~OfflineProfile() {
        if (!profile_key.empty()) RegDeleteTreeW(hklm, widen(profile_key).c_str());
        // the profile directory itself is removed by `tmp`, after this body
    }
    OfflineProfile(const OfflineProfile&) = delete;
    OfflineProfile& operator=(const OfflineProfile&) = delete;

    /// Loads the saved hive for the test, runs fn(root) and unloads it.
    template <typename Fn>
    bool with_loaded(Fn&& fn) {
        yuzu::win::PrivilegeScope backup(L"SeBackupPrivilege");
        yuzu::win::PrivilegeScope restore(L"SeRestorePrivilege");
        if (!backup.ok() || !restore.ok()) return false;
        // ScopedUserHive unloads on destruction, so a REQUIRE that throws inside fn cannot leave the salted mount behind
        // on the shared box. The scopes above outlive it (the unload needs SeRestore).
        bool unload_failed = false;
        {
            yuzu::win::ScopedUserHive hive{widen(scratch_name() + "-verify"), (dir / "NTUSER.DAT").wstring(), &unload_failed};
            if (!hive.ok()) return false;
            hive.with_root(fn);
        }
        return !unload_failed;
    }
};

} // namespace

TEST_CASE("registry write: set_user_value on an OFFLINE NTUSER.DAT is carried to the file and refused when "
          "the file cannot be mounted or trusted",
          "[registry][windows][write][user][offline]") {
    Plugin p;
    if (!p.ok()) { skip_or_fail("registry.dll not found"); return; }
    OfflineProfile prof;
    if (!prof.ok) {
        skip_or_fail("not elevated (or no SeBackup/SeRestore), or the offline fixture could not be built -- offline-hive write cases");
        return;
    }

    SECTION("the write reaches the file: a fresh RegLoadKeyW by the test reads it back byte-identical") {
        const auto out = p.run("set_user_value", {{"sid", prof.sid}, {"key", "fixture\\sub"}, {"name", "V"}, {"type", "REG_SZ"}, {"value", "offline"}});
        CHECK(out.rc == 0);
        CHECK(out.has("status|ok"));
        CHECK(out.audit().find("|op=set_user_value|hive=HKU|") != std::string::npos);
        CHECK(out.audit().find("|sid=" + prof.sid + "|") != std::string::npos);
        for (const auto& l : out.lines) {
            CHECK(l.find("hive_unload_failed") == std::string::npos);
            CHECK(l.find("hive_loaded_after_offline_write") == std::string::npos); // the post-unload probe found no hive
        }
        Bytes got;
        bool found = false;
        REQUIRE(prof.with_loaded([&](HKEY r) {
            yuzu::win::RegKey k;
            if (RegOpenKeyExW(r, L"fixture\\sub", 0, KEY_QUERY_VALUE, k.put()) != ERROR_SUCCESS) return;
            DWORD type = 0, size = 0;
            if (RegQueryValueExW(k.get(), L"V", nullptr, &type, nullptr, &size) == ERROR_SUCCESS) {
                got.resize(size);
                found = RegQueryValueExW(k.get(), L"V", nullptr, &type, got.data(), &size) == ERROR_SUCCESS && type == REG_SZ;
            }
        }));
        REQUIRE(found);
        CHECK(to_hex(got) == to_hex(utf16(L"offline")));

        const auto del = p.run("delete_user_value", {{"sid", prof.sid}, {"key", "fixture\\sub"}, {"name", "V"}});
        CHECK(del.rc == 0);
        bool gone = false;
        REQUIRE(prof.with_loaded([&](HKEY r) {
            yuzu::win::RegKey k;
            if (RegOpenKeyExW(r, L"fixture\\sub", 0, KEY_QUERY_VALUE, k.put()) != ERROR_SUCCESS) return;
            gone = RegQueryValueExW(k.get(), L"V", nullptr, nullptr, nullptr, nullptr) == ERROR_FILE_NOT_FOUND;
        }));
        CHECK(gone);
    }
    SECTION("a mount the plugin cannot make (the file is already loaded) is refused and writes nothing") {
        yuzu::win::PrivilegeScope backup(L"SeBackupPrivilege");
        yuzu::win::PrivilegeScope restore(L"SeRestorePrivilege");
        Plugin::Out out;
        {   // the mount is held by a guard that unloads it however this case exits
            yuzu::win::ScopedUserHive hold{widen(scratch_name() + "-hold"), (prof.dir / "NTUSER.DAT").wstring()};
            REQUIRE(hold.ok());
            out = p.run("set_user_value", {{"sid", prof.sid}, {"key", "fixture"}, {"name", "V"}, {"value", "x"}});
        }
        CHECK(out.rc == 1);
        CHECK(out.audit().find("|result=refused|") != std::string::npos);
        // hive_mount_failed (RegLoadKeyW refused the shared file) or the guard's own token when its probe could not
        // open the exclusively held file: either way nothing was written and the reason is named
        WARN("held-mount reason: " << out.lines.back());
        CHECK(out.lines.back().rfind("error|", 0) == 0);
    }
    SECTION("a profile directory reached through a reparse point (a directory symlink, like a junction) is refused "
            "by the hive-file guard") {
        const fs::path real = prof.dir.parent_path() / ("yuzu_test_junction_real_" + salt());
        const fs::path link = prof.dir.parent_path() / ("yuzu_test_junction_link_" + salt());
        std::error_code ec;
        fs::create_directories(real, ec);
        fs::copy_file(prof.dir / "NTUSER.DAT", real / "NTUSER.DAT", ec);
        // A directory symlink is a reparse point exactly as a junction is; it needs no process spawn.
        const bool made = CreateSymbolicLinkW(link.wstring().c_str(), real.wstring().c_str(),
                                              SYMBOLIC_LINK_FLAG_DIRECTORY | SYMBOLIC_LINK_FLAG_ALLOW_UNPRIVILEGED_CREATE) != 0;
        if (made) {
            yuzu::win::RegKey pk;
            if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, widen(prof.profile_key).c_str(), 0, KEY_SET_VALUE, pk.put()) == ERROR_SUCCESS) {
                const std::wstring path = link.wstring();
                RegSetValueExW(pk.get(), L"ProfileImagePath", 0, REG_EXPAND_SZ, reinterpret_cast<const BYTE*>(path.c_str()),
                               static_cast<DWORD>((path.size() + 1) * sizeof(wchar_t)));
            }
            const auto out = p.run("set_user_value", {{"sid", prof.sid}, {"key", "fixture"}, {"name", "V"}, {"value", "x"}});
            CHECK(out.rc == 1);
            CHECK(out.has("error|hive_path_reparse_ancestor"));
            CHECK(out.audit().find("|result=refused|reason=hive_path_reparse_ancestor|") != std::string::npos);
            RemoveDirectoryW(link.wstring().c_str());
        } else {
            fs::remove_all(real, ec); // before skip_or_fail, whose FAIL throws
            skip_or_fail("could not create a directory symlink");
        }
        fs::remove_all(real, ec);
    }
}

TEST_CASE("registry write: concurrent set_user_value and get_user_value on one offline profile all complete, "
          "none hive_mount_failed",
          "[registry][windows][write][user][offline]") {
    Plugin p;
    if (!p.ok()) { skip_or_fail("registry.dll not found"); return; }
    OfflineProfile prof;
    if (!prof.ok) { skip_or_fail("not elevated, or the offline fixture could not be built"); return; }
    constexpr int kWriters = 6;
    std::vector<std::future<Plugin::Out>> futures;
    for (int i = 0; i < kWriters; ++i) {
        futures.push_back(std::async(std::launch::async, [&p, &prof, i] {
            return p.run("set_user_value", {{"sid", prof.sid}, {"key", "fixture\\conc"}, {"name", "n" + std::to_string(i)}, {"value", "v"}});
        }));
        futures.push_back(std::async(std::launch::async, [&p, &prof] {
            return p.run("get_user_value", {{"sid", prof.sid}, {"key", "fixture"}, {"name", "seed"}});
        }));
    }
    for (auto& f : futures) {
        const auto out = f.get();
        for (const auto& l : out.lines) {
            CHECK(l.find("hive_mount_failed") == std::string::npos);
            CHECK(l.find("failed to load hive") == std::string::npos);
        }
    }
    int present = 0;
    REQUIRE(prof.with_loaded([&](HKEY r) {
        yuzu::win::RegKey k;
        if (RegOpenKeyExW(r, L"fixture\\conc", 0, KEY_QUERY_VALUE, k.put()) != ERROR_SUCCESS) return;
        for (int i = 0; i < kWriters; ++i) {
            DWORD size = 0;
            if (RegQueryValueExW(k.get(), widen("n" + std::to_string(i)).c_str(), nullptr, nullptr, nullptr, &size) == ERROR_SUCCESS)
                ++present;
        }
    }));
    CHECK(present == kWriters);
}

TEST_CASE("registry write: apply on the real machine hive -- dry run, real run, then the reversed manifest "
          "restores the original bytes",
          "[registry][windows][write][apply]") {
    Plugin p;
    if (!p.ok()) { skip_or_fail("registry.dll not found"); return; }
    const std::string root = "SOFTWARE\\" + scratch_name();
    ScratchTree cleanup{HKEY_LOCAL_MACHINE, root};
    if (!put(HKEY_LOCAL_MACHINE, root + "\\Acme", "Mode", REG_SZ, utf16(L"old"))) {
        skip_or_fail("not elevated -- HKLM scratch not writable, apply case");
        return;
    }
    REQUIRE(put(HKEY_LOCAL_MACHINE, root + "\\Acme", "Count", REG_DWORD, le(7, 4)));
    REQUIRE(put(HKEY_LOCAL_MACHINE, root + "\\Acme", "", REG_SZ, utf16(L"dflt")));
    REQUIRE(put(HKEY_LOCAL_MACHINE, root + "\\Leaf", "a", REG_DWORD, le(1, 4)));
    REQUIRE(put(HKEY_LOCAL_MACHINE, root + "\\Leaf", "b", REG_BINARY, Bytes{9, 8, 7}));

    const std::string r = json_path(root);
    const std::string plan =
        "[{\"op\":\"set_value\",\"key\":\"" + r + "\\\\Acme\",\"name\":\"Mode\",\"type\":\"REG_SZ\",\"value\":\"new\"},"
        "{\"op\":\"set_value\",\"key\":\"" + r + "\\\\Made\\\\Deep\",\"name\":\"V\",\"type\":\"REG_DWORD\",\"value\":\"5\"},"
        "{\"op\":\"delete_value\",\"key\":\"" + r + "\\\\Acme\",\"name\":\"Count\"},"
        "{\"op\":\"set_value\",\"key\":\"" + r + "\\\\Acme\",\"type\":\"REG_SZ\",\"value\":\"new-default\"},"
        "{\"op\":\"delete_key\",\"key\":\"" + r + "\\\\Leaf\"}]";

    const auto dry = p.run("apply", {{"plan", plan}}); // dry_run defaults to true
    CHECK(dry.rc == 0);
    CHECK(read(HKEY_LOCAL_MACHINE, root + "\\Acme", "Mode").found);
    CHECK_FALSE(key_exists(HKEY_LOCAL_MACHINE, root + "\\Made"));
    CHECK(dry.has("summary|5|5|0|0|0|1|1"));
    CHECK(dry.audit_count() == 5);
    CHECK(dry.audit().find("|dry_run=1|") != std::string::npos);
    CHECK(row_cells(dry, "item", 1).at(9) == "2"); // Made and Deep: the dry run predicts what the real run creates

    const auto real = p.run("apply", {{"plan", plan}, {"dry_run", "false"}});
    CHECK(real.rc == 0);
    CHECK(real.has("summary|5|5|0|0|0|0|1"));
    CHECK(to_hex(read(HKEY_LOCAL_MACHINE, root + "\\Acme", "Mode").data) == to_hex(utf16(L"new")));
    CHECK(key_exists(HKEY_LOCAL_MACHINE, root + "\\Made\\Deep"));
    CHECK_FALSE(read(HKEY_LOCAL_MACHINE, root + "\\Acme", "Count").found);
    CHECK(to_hex(read(HKEY_LOCAL_MACHINE, root + "\\Acme", "").data) == to_hex(utf16(L"new-default")));
    CHECK_FALSE(key_exists(HKEY_LOCAL_MACHINE, root + "\\Leaf"));
    CHECK(real.audit_count() == 5);
    CHECK(row_cells(real, "item", 1).at(9) == "2");
    // the deleted key's values come back as undo rows, names exact ("a", "b"), hex complete (the registry's value
    // enumeration order is its own, so the row is looked up by name)
    CHECK(real.has("undo|4|a|REG_DWORD|01000000|0"));
    CHECK(real.has("undo|4|b|REG_BINARY|090807|0"));

    // The reverse, written from the manifest rows: values first (the default value is spelt "-" in a row and ""
    // in a plan), then the created keys deepest first.
    const std::string back_values =
        "[{\"op\":\"set_value\",\"key\":\"" + r + "\\\\Acme\",\"name\":\"Mode\",\"type\":\"REG_SZ\",\"data_hex\":\"" + to_hex(utf16(L"old")) + "\"},"
        "{\"op\":\"set_value\",\"key\":\"" + r + "\\\\Acme\",\"name\":\"Count\",\"type\":\"REG_DWORD\",\"data_hex\":\"07000000\"},"
        "{\"op\":\"set_value\",\"key\":\"" + r + "\\\\Acme\",\"type\":\"REG_SZ\",\"data_hex\":\"" + to_hex(utf16(L"dflt")) + "\"},"
        "{\"op\":\"delete_value\",\"key\":\"" + r + "\\\\Made\\\\Deep\",\"name\":\"V\"},"
        "{\"op\":\"set_value\",\"key\":\"" + r + "\\\\Leaf\",\"name\":\"a\",\"type\":\"REG_DWORD\",\"data_hex\":\"01000000\"},"
        "{\"op\":\"set_value\",\"key\":\"" + r + "\\\\Leaf\",\"name\":\"b\",\"type\":\"REG_BINARY\",\"data_hex\":\"090807\"}]";
    CHECK(p.run("apply", {{"plan", back_values}, {"dry_run", "false"}}).rc == 0);
    CHECK(p.run("apply", {{"plan", "[{\"op\":\"delete_key\",\"key\":\"" + r + "\\\\Made\\\\Deep\"}]"}, {"dry_run", "false"}}).rc == 0);
    CHECK(p.run("apply", {{"plan", "[{\"op\":\"delete_key\",\"key\":\"" + r + "\\\\Made\"}]"}, {"dry_run", "false"}}).rc == 0);

    CHECK(to_hex(read(HKEY_LOCAL_MACHINE, root + "\\Acme", "Mode").data) == to_hex(utf16(L"old")));
    CHECK(to_hex(read(HKEY_LOCAL_MACHINE, root + "\\Acme", "Count").data) == "07000000");
    CHECK(to_hex(read(HKEY_LOCAL_MACHINE, root + "\\Acme", "").data) == to_hex(utf16(L"dflt")));
    CHECK(to_hex(read(HKEY_LOCAL_MACHINE, root + "\\Leaf", "a").data) == "01000000");
    CHECK(to_hex(read(HKEY_LOCAL_MACHINE, root + "\\Leaf", "b").data) == "090807");
    CHECK_FALSE(key_exists(HKEY_LOCAL_MACHINE, root + "\\Made"));
}

TEST_CASE("registry write: apply refuses a create beneath a key that denies KEY_CREATE_SUB_KEY as access_denied "
          "in a dry run and a real run alike, and creates nothing",
          "[registry][windows][write][apply]") {
    // The dry run cannot create to find out: it re-opens the deepest existing key onto itself with KEY_CREATE_SUB_KEY
    // (an empty-subkey RegOpenKeyExW) and relies on the access check happening at open. This case proves that premise
    // against the real API, which the in-memory fake cannot.
    Plugin p;
    if (!p.ok()) { skip_or_fail("registry.dll not found"); return; }
    const std::string root = "SOFTWARE\\" + scratch_name();
    const std::string locked = root + "\\Locked";
    const std::string open_key = root + "\\Open";
    ScratchTree cleanup{HKEY_LOCAL_MACHINE, root};
    AclRestore unlock{locked}; // destroyed first: removes the deny ACE, then the subtree goes
    if (!put(HKEY_LOCAL_MACHINE, locked, "V", REG_DWORD, le(1, 4))) {
        skip_or_fail("not elevated -- HKLM scratch not writable, apply deny-ACE case");
        return;
    }
    REQUIRE(put(HKEY_LOCAL_MACHINE, open_key, "V", REG_DWORD, le(1, 4)));
    {
        yuzu::win::RegKey k;
        REQUIRE(RegOpenKeyExW(HKEY_LOCAL_MACHINE, widen(locked).c_str(), 0, WRITE_DAC, k.put()) == ERROR_SUCCESS);
        // Deny KEY_CREATE_SUB_KEY (0x4) to Everyone, allow everything else.
        if (!set_key_sddl(k.get(), L"D:(D;;0x4;;;WD)(A;;GA;;;WD)")) {
            skip_or_fail("could not install a deny ACE");
            return;
        }
    }

    const std::string r = json_path(root);
    // Items 0 and 1 sit under the missing Locked\New; item 2 is the control that creates beneath the writable Open key.
    // Sibling keys, so the plan has no dependent_items refusal.
    const std::string plan =
        "[{\"op\":\"set_value\",\"key\":\"" + r + "\\\\Locked\\\\New\\\\A\",\"name\":\"V\",\"type\":\"REG_DWORD\",\"value\":\"1\"},"
        "{\"op\":\"create_key\",\"key\":\"" + r + "\\\\Locked\\\\New\\\\B\"},"
        "{\"op\":\"create_key\",\"key\":\"" + r + "\\\\Open\\\\Made\"}]";

    const auto dry = p.run("apply", {{"plan", plan}, {"continue_on_error", "true"}}); // dry_run defaults to true
    const auto real = p.run("apply", {{"plan", plan}, {"dry_run", "false"}, {"continue_on_error", "true"}});
    for (const auto* run : {&dry, &real}) {
        INFO((run == &dry ? "dry run" : "real run"));
        CHECK(run->rc == 1);
        for (const int i : {0, 1}) {
            const auto f = row_cells(*run, "item", i);
            REQUIRE(f.size() > 7);
            CHECK(f[6] == "refused");
            CHECK(f[7] == "access_denied");
        }
    }
    CHECK(row_cells(dry, "item", 2).at(6) == "would_apply");
    CHECK(row_cells(real, "item", 2).at(6) == "applied");
    CHECK_FALSE(key_exists(HKEY_LOCAL_MACHINE, locked + "\\New"));
    CHECK(key_exists(HKEY_LOCAL_MACHINE, open_key + "\\Made"));
}

TEST_CASE("registry write: apply refuses a flag that is not a boolean and a malformed plan before any item, unaudited",
          "[registry][windows][write][apply]") {
    // Both refusals come before the registry is touched, so this case needs the plugin but not elevation.
    Plugin p;
    if (!p.ok()) { skip_or_fail("registry.dll not found"); return; }
    const std::string root = "SOFTWARE\\" + scratch_name();
    ScratchTree cleanup{HKEY_LOCAL_MACHINE, root};
    const std::string plan = "[{\"op\":\"create_key\",\"key\":\"" + json_path(root) + "\\\\Made\"}]";
    SECTION("a flag that is not a boolean is invalid_data") {
        // the last case would be a REAL run (dry_run=false) but for its continue_on_error
        for (const auto& flags : std::vector<std::map<std::string, std::string>>{
                 {{"dry_run", "maybe"}}, {{"continue_on_error", "maybe"}}, {{"dry_run", "false"}, {"continue_on_error", "2"}}}) {
            auto params = flags;
            params["plan"] = plan;
            INFO("dry_run=" << (flags.contains("dry_run") ? flags.at("dry_run") : "(default)"));
            const auto out = p.run("apply", params);
            CHECK(out.rc == 1);
            CHECK(out.lines == std::vector<std::string>{"error|invalid_data"});
            CHECK(out.audit_count() == 0);
            CHECK_FALSE(key_exists(HKEY_LOCAL_MACHINE, root));
        }
    }
    SECTION("a whole-plan shape error names the defect and its index") {
        const auto out = p.run("apply", {{"plan", "[{\"op\":\"nope\"}]"}});
        CHECK(out.rc == 1);
        CHECK(out.lines == std::vector<std::string>{"error|invalid_plan:invalid_op:0"});
        CHECK(out.audit_count() == 0);
    }
}

TEST_CASE("registry write: a 256-item apply reply stays under the dispatcher's capture cap and is not truncated",
          "[registry][windows][write][apply]") {
    // 256 overwrites of 4,096-byte values: every item row would carry its previous value, so the one capture budget
    // (512 KiB) is what keeps the reply under the 2 MiB cap -- the undo manifest says it is incomplete rather than
    // overflowing.
    Plugin p;
    if (!p.ok()) { skip_or_fail("registry.dll not found"); return; }
    const std::string root = "SOFTWARE\\" + scratch_name();
    ScratchTree cleanup{HKEY_LOCAL_MACHINE, root};
    std::string plan = "[";
    const std::string r = json_path(root);
    for (int k = 0; k < 8; ++k) {
        for (int n = 0; n < 32; ++n) {
            const std::string key = root + "\\K" + std::to_string(k);
            const std::string name = "n" + std::to_string(n);
            if (!put(HKEY_LOCAL_MACHINE, key, name, REG_BINARY, Bytes(4096, static_cast<std::uint8_t>(n)))) {
                skip_or_fail("not elevated -- HKLM scratch not writable, 256-item apply case");
                return;
            }
            if (plan.size() > 1) plan += ",";
            plan += "{\"op\":\"set_value\",\"key\":\"" + r + "\\\\K" + std::to_string(k) + "\",\"name\":\"" + name +
                    "\",\"type\":\"REG_DWORD\",\"value\":\"1\"}";
        }
    }
    plan += "]";
    REQUIRE(plan.size() <= 65536);
    for (const char* dry : {"true", "false"}) {
        INFO("dry_run=" << dry);
        const auto out = p.run("apply", {{"plan", plan}, {"dry_run", dry}});
        CHECK(out.rc == 0);
        CHECK_FALSE(out.truncated);
        CHECK(out.audit_count() == 256);
        CHECK(out.has(std::string{"summary|256|256|0|0|0|"} + (std::string{dry} == "true" ? "1" : "0") + "|0")); // undo_complete=0
        std::size_t bytes = 0;
        for (const auto& l : out.lines) bytes += l.size() + 1;
        WARN("a 256-item apply over 4,096-byte previous values: " << bytes << " reply bytes of "
                                                                  << yuzu::agent::LocalDispatcher::kCaptureMaxBytes);
        CHECK(bytes < yuzu::agent::LocalDispatcher::kCaptureMaxBytes);
    }
}

#else // !_WIN32

// ═════════════════════════════════════════════════════════════════════════
// off Windows: the planned-stub contract of the loaded plugin
//
// Runs on every non-Windows host, unconditionally (no skip when the plugin was built: under
// `meson test` a missing library is a broken build and FAILS). It pins what the capability matrix and
// the dispatcher rely on: the plugin version, the 12 descriptors with the Windows leg SUPPORTED rung 1
// and the macOS / Linux legs PLANNED (naming the mechanism that will carry them), the read action's
// honest sentinel with rc 0, and every mutator's rc 1 with the same sentinel -- a write that did not
// happen is never a terminal SUCCESS (BR-03). The last case includes registry_plugin.cpp (the guard macro
// below drops its C plugin entry point and makes any action throw when its `name` parameter says so) to prove
// nothing thrown inside execute() crosses the plugin boundary, and that a mutator leaves its fixed exception audit
// line: the Windows leg's twin is execute_guarded in test_registry_win_internals.cpp.
// ═════════════════════════════════════════════════════════════════════════

#include <yuzu/agent/plugin_loader.hpp>
#include <yuzu/plugin.h>

#include "local_dispatcher.hpp"

#include <algorithm>
#include <cstdlib>
#include <filesystem>
#include <functional>
#include <iterator>
#include <optional>
#include <span>
#include <sstream>
#include <string_view>
#include <unordered_set>
#include <vector>

#define YUZU_REGISTRY_UNIT_TEST_INTERNALS_ONLY 1
#include "../../agents/plugins/registry/src/registry_plugin.cpp"
#undef YUZU_REGISTRY_UNIT_TEST_INTERNALS_ONLY

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
    "enumerate_keys", "enumerate_values", "get_user_value", "list_profiles",    "set_user_value",
    "delete_user_value", "apply"};
constexpr std::string_view kMutators[] = {"set_value", "delete_value", "delete_key", "set_user_value",
                                          "delete_user_value", "apply"};

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

// A fake descriptor whose execute runs an injected body against a REAL yuzu::CommandContext (the
// test_registry_win_internals.cpp shape), so RegistryPlugin::execute writes to the same capture LocalDispatcher
// reads for the loaded plugin.
std::function<int(yuzu::CommandContext&)> g_body;

int fake_seam_execute(YuzuCommandContext* raw_ctx, const char* /*action*/, const YuzuParam* /*params*/,
                      std::size_t /*param_count*/) {
    yuzu::CommandContext ctx(raw_ctx);
    return g_body(ctx);
}

const char* const kFakeActions[] = {"seam", nullptr};

const YuzuPluginDescriptor kFakeDescriptor = {
    /*abi_version=*/YUZU_PLUGIN_ABI_VERSION,
    /*name=*/"registry_seam",
    /*version=*/"1.0.0",
    /*description=*/"test-only registry execute fixture",
    /*actions=*/kFakeActions,
    /*init=*/nullptr,
    /*shutdown=*/nullptr,
    /*execute=*/fake_seam_execute,
    /*sdk_version=*/nullptr,
};

struct Executed {
    int rc = 0;
    std::vector<std::string> rows;
};

/// Runs RegistryPlugin::execute(`action`) inside the fake context, with the one parameter `name`=`name_param`
/// (nullptr: no params).
Executed run_execute(std::string_view action, const char* name_param = nullptr) {
    g_body = [action, name_param](yuzu::CommandContext& ctx) -> int {
        RegistryPlugin plugin;
        const YuzuParam params[] = {{"name", name_param != nullptr ? name_param : ""}};
        return plugin.execute(
            ctx, action, yuzu::Params{std::span<const YuzuParam>{params, name_param != nullptr ? 1u : 0u}});
    };
    const auto result = yuzu::agent::LocalDispatcher{}.run(&kFakeDescriptor, "seam");
    g_body = nullptr;
    return {result.rc, rows_of(result.captured)};
}

} // namespace

TEST_CASE("registry plugin: version 2.1.0 and the 12 descriptors -- Windows supported; macOS and Linux planned",
          "[registry][descriptors]") {
    auto plugin = load_registry_plugin();
    if (!plugin) return require_plugin_or_skip();

    CHECK(std::string_view{plugin->descriptor->name} == "registry");
    CHECK(std::string_view{plugin->descriptor->version} == "2.1.0");
    CHECK(std::size(kExpectedActions) == 12);
    CHECK(std::size(kMutators) == 6);
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

TEST_CASE("registry plugin: an exception inside an off-Windows dispatch is contained as error|exception",
          "[registry][actions]") {
    SECTION("a read that throws answers rc 1 and one error|exception line; nothing escapes") {
        // mutant: the catch (...) in RegistryPlugin::execute deleted -- the exception reaches the host
        const auto r = run_execute("get_value", "__throw_std");
        CHECK(r.rc == 1);
        REQUIRE(r.rows.size() == 1);
        CHECK(r.rows[0] == "error|exception");
    }
    SECTION("a value that is not a std::exception is contained too") {
        // mutant: the catch narrowed to const std::exception&
        const auto r = run_execute("enumerate_keys", "__throw_other");
        CHECK(r.rc == 1);
        REQUIRE(r.rows.size() == 1);
        CHECK(r.rows[0] == "error|exception");
    }
    for (const std::string_view mutator : kMutators) {
        for (const char* how : {"__throw_std", "__throw_other"}) {
            SECTION(std::string{mutator} + " throwing " + how + " leaves its fixed audit line, then error|exception") {
                // mutant: the catch writes error|exception alone (the server then mints no failed registry.write row)
                const auto r = run_execute(mutator, how);
                CHECK(r.rc == 1);
                REQUIRE(r.rows.size() == 2);
                CHECK(r.rows[0] == yuzu::registry::exception_audit_line(mutator));
                CHECK(r.rows[0].rfind(std::string{"audit|op="} + std::string{mutator} +
                                          "|hive=-|result=failed|reason=exception|verify=-|",
                                      0) == 0);
                CHECK(r.rows[1] == "error|exception");
            }
        }
    }
    SECTION("an ordinary unknown action still passes through unchanged") {
        const auto r = run_execute("get_vaule");
        CHECK(r.rc == 1);
        REQUIRE(r.rows.size() == 1);
        CHECK(r.rows[0] == "error|unknown action: get_vaule");
    }
}

#endif // _WIN32

// ═════════════════════════════════════════════════════════════════════════
// every host: the scratch-key namespace CI's per-job leftover check keys on (#6488)
// ═════════════════════════════════════════════════════════════════════════

// scripts/ci/check-registry-test-leftovers.ps1 fails a job on a key named `YuzuTest-<scope>-*`, so a fixture whose
// name does not carry the scope in exactly that form is invisible to it. The fixtures take their prefix from
// registry_scratch_prefix(), and tests/test_registry_definition.py pins that no fixture spells the stem itself.
TEST_CASE("registry_scratch_prefix puts the CI scope between the fixed stem and the salt", "[registry][scratch]") {
    const std::string stem{"YuzuTest"};
    const std::string bare = yuzu::test::registry_scratch_prefix(nullptr);
    CHECK(bare == stem + "-");
    CHECK(yuzu::test::registry_scratch_prefix("") == bare); // an empty scope is no scope
    // the shape CI sets: <run id>-<attempt>-<build type>
    CHECK(yuzu::test::registry_scratch_prefix("123-2-debug") == stem + "-123-2-debug-");
}

// The zero-argument call is what every fixture makes: the CI job scope reaches the key names only through the
// environment variable, so a rename of either end must turn this red.
TEST_CASE("registry_scratch_prefix reads the scope from YUZU_TEST_REGISTRY_SCOPE", "[registry][scratch]") {
    const std::string stem{"YuzuTest"};
    {
        yuzu::test::ScopedEnv scope{"YUZU_TEST_REGISTRY_SCOPE", "123-2-debug"};
        CHECK(yuzu::test::registry_scratch_prefix() == stem + "-123-2-debug-");
    }
    {
        yuzu::test::ScopedEnv scope{"YUZU_TEST_REGISTRY_SCOPE", yuzu::test::unset_tag{}};
        CHECK(yuzu::test::registry_scratch_prefix() == stem + "-");
    }
}
