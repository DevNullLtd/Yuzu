/**
 * test_registry_core.cpp -- registry_core.hpp over an in-memory FakeRegistry (per-node fault flags, link
 * keys, a call log, rc injection and call-boundary hooks), on every host: the checked-handle walk (incl.
 * the check-to-use swap), verified writes and delete_key. The fake's destructor checks that no handle
 * is left open (the Owned wrapper's job).
 */
#include <catch2/catch_test_macros.hpp>
#include <catch2/generators/catch_generators.hpp>

#include <algorithm>
#include <cstdint>
#include <functional>
#include <iterator>
#include <map>
#include <memory>
#include <optional>
#include <set>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

#include "registry_core.hpp"

using namespace yuzu::registry;
using yuzu::profiles::kRegBinary;
using yuzu::profiles::kRegDword;
using yuzu::profiles::kRegMultiSz;
using yuzu::profiles::kRegQword;
using yuzu::profiles::kRegSz;
using Bytes = std::vector<std::uint8_t>;

namespace {

// ── the fake ─────────────────────────────────────────────────────────────

struct ILess {
    bool operator()(const std::string& a, const std::string& b) const {
        return fold_ascii(a) < fold_ascii(b);
    }
    static std::string fold_ascii(std::string s) {
        for (char& c : s)
            if (c >= 'A' && c <= 'Z') c = static_cast<char>(c + 32);
        return s;
    }
};

struct Node;
using NodeP = std::shared_ptr<Node>;
struct Val {
    std::uint32_t type = 0;
    Bytes data;
};
struct Node {
    std::map<std::string, NodeP, ILess> subkeys;
    std::map<std::string, Val, ILess> values;
    bool is_link = false;
    /// is_link: the canonical path (from the fake root) the kernel follows to; "" is a dangling link.
    std::string link_target;
    bool deleted = false;
    // fault flags
    /// The walk cannot open this key (ACL). open_path fails for it only as the LEAF: the kernel needs just
    /// traverse access to pass THROUGH an ancestor, which is the first documented divergence.
    bool deny_open = false, deny_query = false, deny_set = false;
    bool deny_create = false; ///< creating a child fails (create_sub)
    bool deny_delete_value = false, deny_delete_key = false;
    std::set<std::string> unreadable_values;
};

std::string hex(const Bytes& b) { return yuzu::profiles::hex_encode(b); }

/// The registry as the kernel presents it: `open_sub` opens ONE component of the current handle as it is
/// (the walk always passes REG_OPTION_OPEN_LINK), while `open_path` resolves a whole path the way
/// RegOpenKeyExW does -- an intermediate link is FOLLOWED to its target, a link at the leaf is opened as the
/// link object -- and `final_name` is the canonical name of the object the handle is bound to. A plain key may
/// carry a VALUE named SymbolicLinkValue; the probe cannot tell that from a link.
class FakeRegistry final : public RegistryWriter {
public:
    static constexpr Handle kRoot = 1;
    static constexpr Handle kRootNoName = 2; ///< the same root, with no kernel name (HKCU / HKCR)
    static constexpr const char* kRootName = "\\REGISTRY\\MACHINE";
    ~FakeRegistry() override { CHECK(open.empty()); } // a leaked handle, whichever test made it
    NodeP root = std::make_shared<Node>();
    std::map<Handle, NodeP> open;
    Handle next = 0x100;
    std::vector<std::string> log;
    /// Every call across the seam, and per method: the deterministic stand-in for latency.
    std::size_t seam_calls = 0;
    std::map<std::string, std::size_t> by_method;
    /// Fired BEFORE create_sub and AFTER query_value / delete_value, named "<op>:<name>" (e.g.
    /// "create_sub:B"), so a test can change the tree at a call boundary.
    std::function<void(const std::string&)> before, after;
    std::function<void(Node&, const std::string&)> tamper_after_set;
    /// Fired at the start of every enum_value call: a value set that grows while it is being enumerated.
    std::function<void(Node&)> grow_on_enum;
    /// "<op>:<name>" -> rc, consumed on use. open_path/final_name/root_name also take the bare method name.
    std::map<std::string, long> inject;

    NodeP node(Handle h) const {
        if (h == kRoot || h == kRootNoName) return root;
        const auto it = open.find(h);
        return it == open.end() ? nullptr : it->second;
    }
    NodeP key(const std::string& path, bool create = true) {
        NodeP cur = root;
        for (const auto part : split_key(path)) {
            const auto it = cur->subkeys.find(std::string{part});
            if (it != cur->subkeys.end()) {
                cur = it->second;
            } else if (create) {
                auto n = std::make_shared<Node>();
                cur->subkeys[std::string{part}] = n;
                cur = n;
            } else {
                return nullptr;
            }
        }
        return cur;
    }
    /// Makes `path` a link to `target` (created if needed).
    void link(const std::string& path, const std::string& target) {
        const auto n = key(path);
        n->is_link = true;
        n->link_target = target;
    }
    void put(const std::string& path, const std::string& name, std::uint32_t type, const Bytes& data) {
        key(path)->values[name] = Val{type, data};
    }
    const Val* get(const std::string& path, const std::string& name) {
        const auto k = key(path, false);
        if (!k) return nullptr;
        const auto it = k->values.find(name);
        return it == k->values.end() ? nullptr : &it->second;
    }
    [[nodiscard]] bool exists(const std::string& path) { return key(path, false) != nullptr; }
    [[nodiscard]] std::size_t calls(const std::string& prefix) const {
        return static_cast<std::size_t>(std::count_if(log.begin(), log.end(), [&](const std::string& l) {
            return l.rfind(prefix, 0) == 0;
        }));
    }
    [[nodiscard]] std::size_t method_calls(const std::string& method) const {
        const auto it = by_method.find(method);
        return it == by_method.end() ? 0 : it->second;
    }
    /// Canonical dump of the whole tree: byte-identical comparison of two registry states.
    std::string dump() { return dump_node(*root, ""); }
    /// The canonical path (stored names) of `target` in the tree; false when it is not in it.
    [[nodiscard]] bool canonical_path(const Node* target, std::string& out) const {
        if (target == root.get()) {
            out.clear();
            return true;
        }
        return path_of(*root, target, "", out);
    }

    // RegistryWriter
    long open_sub(Handle parent, std::string_view name, std::uint32_t, Handle& out) override {
        tally("open_sub");
        const std::string ev = "open_sub:" + std::string{name};
        log.push_back(ev);
        long rc = 0;
        if (const auto inj = take(ev)) rc = *inj;
        const auto p = node(parent);
        NodeP child;
        if (rc == 0) {
            if (!p || p->deleted) rc = 1018;
            else if (const auto it = p->subkeys.find(std::string{name}); it == p->subkeys.end()) rc = 2;
            else if (it->second->deny_open) rc = 5;
            else child = it->second;
        }
        if (rc == 0) {
            out = next++;
            open[out] = child;
        }
        return rc;
    }
    long open_path(Handle root_h, std::string_view key_path, std::uint32_t, Handle& out) override {
        tally("open_path");
        const std::string ev = "open_path:" + std::string{key_path};
        log.push_back(ev);
        if (const auto inj = take(ev, "open_path")) return *inj;
        const auto start = node(root_h);
        if (!start) return 1018;
        const auto r = resolve(start, key_path, /*leaf_open_link=*/true, 0);
        if (r.rc != 0) return r.rc;
        if (!key_path.empty() && r.node->deny_open) return 5; // the leaf needs real access; an ancestor only traverse
        out = next++;
        open[out] = r.node;
        return 0;
    }
    long final_name(Handle key_h, std::string& out) override {
        tally("final_name");
        log.push_back("final_name");
        if (const auto inj = take("final_name", "final_name")) return *inj;
        const auto n = node(key_h);
        std::string path;
        if (!n || n->deleted || !canonical_path(n.get(), path)) return 1018;
        out = std::string{kRootName} + (path.empty() ? "" : "\\" + path);
        return 0;
    }
    long root_name(Handle root_h, std::string& out) override {
        tally("root_name");
        log.push_back("root_name");
        if (const auto inj = take("root_name", "root_name")) return *inj;
        if (root_h != kRoot) return kErrorNotSupported;
        out = kRootName;
        return 0;
    }
    long create_sub(Handle parent, std::string_view name, std::uint32_t, Handle& out, bool& created_new) override {
        tally("create_sub");
        const std::string ev = "create_sub:" + std::string{name};
        log.push_back(ev);
        if (before) before(ev);
        long rc = 0;
        if (const auto inj = take(ev)) rc = *inj;
        const auto p = node(parent);
        if (rc == 0 && (!p || p->deleted)) rc = 1018;
        if (rc == 0 && p->deny_create) rc = 5;
        if (rc == 0) {
            const auto it = p->subkeys.find(std::string{name});
            if (it == p->subkeys.end()) {
                auto n = std::make_shared<Node>();
                p->subkeys[std::string{name}] = n;
                out = next++;
                open[out] = n;
                created_new = true;
            } else {
                out = next++;
                open[out] = it->second;
                created_new = false; // REG_OPENED_EXISTING_KEY
            }
        }
        return rc;
    }
    void close(Handle key_h) override {
        tally("close");
        open.erase(key_h);
    }
    long query_value(Handle key_h, std::string_view name, std::size_t cap, QueryResult& out) override {
        tally("query_value");
        const std::string ev = "query_value:" + std::string{name};
        log.push_back(ev);
        long rc = 0;
        if (const auto inj = take(ev)) rc = *inj;
        else rc = do_query(key_h, name, cap, out);
        if (after) after(ev);
        return rc;
    }
    long set_value(Handle key_h, std::string_view name, std::uint32_t type, std::span<const std::uint8_t> data) override {
        tally("set_value");
        const std::string ev = "set_value:" + std::string{name};
        log.push_back(ev);
        if (const auto inj = take(ev)) return *inj;
        const auto n = node(key_h);
        if (!n || n->deleted) return 1018;
        if (n->deny_set) return 5;
        n->values[std::string{name}] = Val{type, Bytes(data.begin(), data.end())};
        if (tamper_after_set) tamper_after_set(*n, std::string{name});
        return 0;
    }
    long delete_value(Handle key_h, std::string_view name) override {
        tally("delete_value");
        const std::string ev = "delete_value:" + std::string{name};
        log.push_back(ev);
        long rc = 0;
        const auto n = node(key_h);
        if (const auto inj = take(ev)) rc = *inj;
        else if (!n || n->deleted) rc = 1018;
        else if (n->deny_delete_value) rc = 5;
        else rc = n->values.erase(std::string{name}) ? 0 : 2;
        if (after) after(ev);
        return rc;
    }
    long enum_value(Handle key_h, std::uint32_t index, std::string& name) override {
        tally("enum_value");
        const auto n = node(key_h);
        if (!n || n->deleted) return 1018;
        if (grow_on_enum) grow_on_enum(*n);
        if (index >= n->values.size()) return 259;
        name = std::next(n->values.begin(), index)->first;
        return 0;
    }
    long enum_subkey(Handle key_h, std::uint32_t index, std::string& name) override {
        tally("enum_subkey");
        const auto n = node(key_h);
        if (!n || n->deleted) return 1018;
        if (index >= n->subkeys.size()) return 259;
        name = std::next(n->subkeys.begin(), index)->first;
        return 0;
    }
    long delete_key_by_handle(Handle key_h) override {
        tally("delete_key_by_handle");
        log.push_back("delete_key_by_handle");
        const auto n = node(key_h);
        if (!n || n->deleted) return 1018;
        if (n->deny_delete_key || !n->subkeys.empty()) return 5; // STATUS_CANNOT_DELETE maps to access denied
        n->deleted = true;
        detach(root, n.get());
        return 0;
    }

private:
    void tally(const char* method) {
        ++seam_calls;
        ++by_method[method];
    }
    struct Resolved {
        long rc = 0;
        NodeP node;
    };
    /// RegOpenKeyExW's resolution of `path` from `start`: an intermediate link is followed (to a target that
    /// is itself resolved with every link followed), a link at the leaf only when the open is not OPEN_LINK.
    /// A dangling target is not-found; more than 16 hops (a self-link or a cycle) fails.
    Resolved resolve(const NodeP& start, std::string_view path, bool leaf_open_link, int hops) const {
        NodeP cur = start;
        const auto parts = path.empty() ? std::vector<std::string_view>{} : split_key(path);
        for (std::size_t i = 0; i < parts.size(); ++i) {
            const bool last = i + 1 == parts.size();
            if (cur->deleted) return {1018, nullptr};
            const auto it = cur->subkeys.find(std::string{parts[i]});
            if (it == cur->subkeys.end()) return {2, nullptr};
            NodeP child = it->second;
            if (child->is_link && (!last || !leaf_open_link)) {
                if (hops >= 16) return {1921, nullptr}; // ERROR_CANT_RESOLVE_FILENAME
                if (child->link_target.empty()) return {2, nullptr};
                const auto target = resolve(root, child->link_target, false, hops + 1);
                if (target.rc != 0) return target;
                child = target.node;
            }
            cur = child;
        }
        return {0, cur};
    }
    long do_query(Handle key_h, std::string_view name, std::size_t cap, QueryResult& out) {
        const auto n = node(key_h);
        if (!n || n->deleted) return 1018;
        if (name == "SymbolicLinkValue") {
            if (n->deny_query) return 5;
            if (n->is_link) {
                out.type = 6;
                out.size = 8;
                return 0;
            }
            // not a link: a plain key may still hold an ordinary value of this name, answered like any other
        }
        if (n->unreadable_values.contains(std::string{name})) return 5;
        const auto it = n->values.find(std::string{name});
        if (it == n->values.end()) return 2;
        out.type = it->second.type;
        out.size = it->second.data.size();
        out.bytes.clear();
        if (cap > 0 && out.size <= kMaxWriteBytes)
            out.bytes.assign(it->second.data.begin(),
                             it->second.data.begin() + static_cast<std::ptrdiff_t>(std::min(cap, out.size)));
        return 0;
    }
    std::optional<long> take(const std::string& ev, const char* method = nullptr) {
        for (const std::string& k : {ev, std::string{method != nullptr ? method : ""}}) {
            if (k.empty()) continue;
            const auto it = inject.find(k);
            if (it == inject.end()) continue;
            const long rc = it->second;
            inject.erase(it);
            return rc;
        }
        return std::nullopt;
    }
    static bool detach(const NodeP& from, Node* target) {
        for (auto it = from->subkeys.begin(); it != from->subkeys.end(); ++it) {
            if (it->second.get() == target) {
                from->subkeys.erase(it);
                return true;
            }
            if (detach(it->second, target)) return true;
        }
        return false;
    }
    static bool path_of(const Node& from, const Node* target, const std::string& prefix, std::string& out) {
        for (const auto& [name, k] : from.subkeys) {
            const std::string p = prefix.empty() ? name : prefix + "\\" + name;
            if (k.get() == target) {
                out = p;
                return true;
            }
            if (path_of(*k, target, p, out)) return true;
        }
        return false;
    }
    static std::string dump_node(const Node& n, const std::string& path) {
        std::string out;
        for (const auto& [name, v] : n.values)
            out += path + "|" + name + "|" + std::to_string(v.type) + "|" + hex(v.data) + "\n";
        for (const auto& [name, k] : n.subkeys) {
            const std::string p = path.empty() ? ILess::fold_ascii(name) : path + "\\" + ILess::fold_ascii(name);
            out += "[" + p + "]" + (k->is_link ? " link" : "") + "\n";
            out += dump_node(*k, p);
        }
        return out;
    }
};

Bytes B(std::initializer_list<int> v) {
    Bytes out;
    for (const int x : v) out.push_back(static_cast<std::uint8_t>(x));
    return out;
}
Bytes dword(std::uint32_t v) { return B({int(v & 255), int((v >> 8) & 255), int((v >> 16) & 255), int((v >> 24) & 255)}); }
Bytes sz(const std::string& s) {
    Bytes out;
    for (const char c : s) {
        out.push_back(static_cast<std::uint8_t>(c));
        out.push_back(0);
    }
    out.push_back(0);
    out.push_back(0);
    return out;
}

} // namespace

// ── set_value_verified ───────────────────────────────────────────────────

TEST_CASE("registry core: set_value_verified round-trips every type and reads it back",
          "[registry][core]") {
    const bool fast = GENERATE(false, true); // the walk and the fast open
    FakeRegistry reg;
    reg.key("Software"); // a creating write needs an existing top-level key (root_level_create otherwise)
    struct Case {
        std::uint32_t type;
        Bytes data;
        const char* what;
    };
    Bytes mib(kMaxWriteBytes, 0x5a);
    const std::vector<Case> cases{
        {kRegSz, sz("hello"), "REG_SZ"}, // the core is type-agnostic: one string, the byte edge cases
        {kRegBinary, {}, "empty REG_BINARY"},
        {kRegBinary, B({0, 1, 0, 2, 0, 0}), "binary with embedded NULs"},
        {kRegBinary, mib, "1 MiB REG_BINARY"},
    };
    for (const auto& c : cases) {
        INFO(c.what);
        const auto o = set_value_verified(reg, FakeRegistry::kRoot, "Software\\Acme", "V", c.type, c.data, fast);
        CHECK(o.result == "ok");
        CHECK(o.verify == "ok");
        CHECK(o.reason.empty());
        CHECK(o.mutated);
        const auto* stored = reg.get("Software\\Acme", "V");
        REQUIRE(stored != nullptr);
        CHECK(stored->type == c.type);
        CHECK(stored->data == c.data);
    }
}

TEST_CASE("registry core: the previous value is captured before the write", "[registry][core]") {
    const bool fast = GENERATE(false, true);
    FakeRegistry reg;
    reg.key("A"); // the key exists; only the value is absent in the first section
    SECTION("absent") {
        const auto o = set_value_verified(reg, FakeRegistry::kRoot, "A", "V", kRegDword, dword(1), fast);
        CHECK(o.has_old);
        CHECK(o.old.state == OldState::absent);
    }
    SECTION("unreadable: the write still proceeds and the audit records why") {
        reg.put("A", "V", kRegDword, dword(7));
        reg.key("A")->unreadable_values.insert("V");
        const auto o = set_value_verified(reg, FakeRegistry::kRoot, "A", "V", kRegDword, dword(1), fast);
        CHECK(o.old.state == OldState::unreadable);
        CHECK(o.old.error == "access_denied");
        // the verifying read-back is denied too, so the write cannot be confirmed
        CHECK(o.result == "failed");
        CHECK(o.verify == "mismatch");
    }
}

TEST_CASE("registry core: verify_mismatch when the stored value is not what was written",
          "[registry][core]") {
    const bool fast = GENERATE(false, true);
    FakeRegistry reg;
    reg.key("A");
    reg.tamper_after_set = [](Node& n, const std::string& name) { n.values[name].data[0] ^= 0xff; };
    const auto o = set_value_verified(reg, FakeRegistry::kRoot, "A", "V", kRegDword, dword(5), fast);
    CHECK(o.result == "failed");
    CHECK(o.reason == "verify_mismatch");
    CHECK(o.verify == "mismatch");
    CHECK(o.mutated);
    SECTION("a type change between set and read-back is a mismatch too") {
        FakeRegistry r2;
        r2.key("A");
        r2.tamper_after_set = [](Node& n, const std::string& name) { n.values[name].type = kRegBinary; };
        CHECK(set_value_verified(r2, FakeRegistry::kRoot, "A", "V", kRegDword, dword(5), fast).reason ==
              "verify_mismatch");
    }
}

TEST_CASE("registry core: a refused or failed set_value reports the right token", "[registry][core]") {
    const bool fast = GENERATE(false, true);
    FakeRegistry reg;
    SECTION("the SetValue call itself is denied") {
        reg.key("A")->deny_set = true;
        const auto o = set_value_verified(reg, FakeRegistry::kRoot, "A", "V", kRegDword, dword(1), fast);
        CHECK(o.result == "failed");
        CHECK(o.reason == "access_denied");
        CHECK_FALSE(o.mutated);
        CHECK(o.verify.empty());
    }
    SECTION("an unexpected Win32 code keeps its number") {
        reg.key("A");
        reg.inject["set_value:V"] = 1450;
        CHECK(set_value_verified(reg, FakeRegistry::kRoot, "A", "V", kRegDword, dword(1), fast).reason ==
              "win32:1450");
    }
    SECTION("the create itself is denied: access_denied and nothing is written") {
        reg.key("Locked")->deny_create = true;
        const auto o = set_value_verified(reg, FakeRegistry::kRoot, "Locked\\New", "V", kRegDword, dword(1), fast);
        CHECK(o.result == "refused");
        CHECK(o.reason == "access_denied");
        CHECK(o.created == 0);
        CHECK(reg.calls("set_value") == 0);
        CHECK_FALSE(reg.exists("Locked\\New"));
    }
}

// ── open_checked ─────────────────────────────────────────────────────────

TEST_CASE("registry core: a registry link is refused at every position, and nothing is written",
          "[registry][core]") {
    const bool fast = GENERATE(false, true);
    FakeRegistry reg;
    SECTION("an intermediate component") {
        reg.key("L\\Child");
        reg.key("Elsewhere\\Child"); // the link resolves here: a handle on THIS key is what a fast open must not accept
        reg.link("L", "Elsewhere");
        const auto o = set_value_verified(reg, FakeRegistry::kRoot, "L\\Child", "V", kRegDword, dword(9), fast);
        CHECK(o.result == "refused");
        CHECK(o.reason == "key_is_link");
        CHECK(reg.get("L\\Child", "V") == nullptr);
        CHECK(reg.get("Elsewhere\\Child", "V") == nullptr);
        CHECK(reg.calls("set_value") == 0);
    }
    SECTION("the leaf") {
        reg.key("Real");
        reg.link("Software\\L", "Real");
        const auto o = set_value_verified(reg, FakeRegistry::kRoot, "Software\\L", "V", kRegDword, dword(9), fast);
        CHECK(o.reason == "key_is_link");
        CHECK(reg.calls("set_value") == 0);
        CHECK(reg.get("Real", "V") == nullptr);
    }
    SECTION("delete_value refuses a link leaf") {
        reg.key("Real");
        reg.link("Software\\L", "Real");
        reg.put("Software\\L", "V", kRegDword, dword(1));
        CHECK(delete_value_verified(reg, FakeRegistry::kRoot, "Software\\L", "V", fast).reason == "key_is_link");
        CHECK(reg.calls("delete_") == 0);
    }
    SECTION("delete_key on a link leaf removes the LINK, never its target") {
        reg.put("Real\\Target", "keep", kRegDword, dword(1));
        reg.link("Software\\L", "Real\\Target");
        const auto o = delete_key_tree(reg, FakeRegistry::kRoot, "Software\\L", fast);
        CHECK(o.result == "ok");
        CHECK_FALSE(reg.exists("Software\\L"));
        REQUIRE(reg.get("Real\\Target", "keep") != nullptr);
        CHECK(reg.get("Real\\Target", "keep")->data == dword(1));
        CHECK(reg.calls("delete_key_by_handle") == 1);
        CHECK((reg.method_calls("open_sub") == 0) == fast); // the fast open accepted the link as the leaf
    }
    SECTION("a link in the middle of a delete_key path is still refused") {
        reg.key("L\\Child");
        reg.key("Elsewhere\\Child");
        reg.link("L", "Elsewhere");
        CHECK(delete_key_tree(reg, FakeRegistry::kRoot, "L\\Child", fast).reason == "key_is_link");
        CHECK(reg.calls("delete_") == 0);
        CHECK(reg.exists("Elsewhere\\Child"));
    }
    SECTION("a link whose probe is denied is not assumed plain") {
        reg.key("Software\\P")->deny_query = true;
        const auto o = set_value_verified(reg, FakeRegistry::kRoot, "Software\\P", "V", kRegDword, dword(9), fast);
        CHECK(o.reason == "access_denied");
        CHECK(reg.calls("set_value") == 0);
    }
}

TEST_CASE("registry core: check-to-use -- a component swapped for a link after the open cannot redirect "
          "the write",
          "[registry][core]") {
    const bool fast = GENERATE(false, true);
    FakeRegistry reg;
    const NodeP original_b = reg.key("A\\B");
    reg.key("Elsewhere\\Target");
    int probes = 0;
    // The walk probes A then B; the fast open probes only the leaf B. The instant B has been probed plain --
    // the check is finished, the use has not started -- B's tree entry becomes a link, exactly the swap a
    // path-based mutation would follow.
    const int leaf_probe = fast ? 1 : 2;
    reg.after = [&](const std::string& ev) {
        if (ev == "query_value:SymbolicLinkValue" && ++probes == leaf_probe) {
            auto link = std::make_shared<Node>();
            link->is_link = true;
            link->link_target = "Elsewhere\\Target";
            reg.key("A", false)->subkeys["B"] = link;
        }
    };
    const auto o = set_value_verified(reg, FakeRegistry::kRoot, "A\\B", "V", kRegDword, dword(42), fast);
    CHECK(o.result == "ok");
    CHECK((reg.method_calls("open_path") == 1) == fast);
    // The write landed on the node that was checked, not on whatever now sits at the path.
    REQUIRE(original_b->values.contains("V"));
    CHECK(original_b->values["V"].data == dword(42));
    CHECK(reg.key("A", false)->subkeys["B"]->values.empty());
    CHECK(reg.key("A", false)->subkeys["B"]->is_link);
    // And once the mutation began nothing opened or created anything by name again.
    const auto set_pos = std::find(reg.log.begin(), reg.log.end(), "set_value:V");
    REQUIRE(set_pos != reg.log.end());
    CHECK(std::none_of(set_pos, reg.log.end(), [](const std::string& l) {
        return l.rfind("open_sub", 0) == 0 || l.rfind("open_path", 0) == 0 || l.rfind("create_sub", 0) == 0;
    }));
}

TEST_CASE("registry core: a missing suffix is created component-wise from the checked handle",
          "[registry][core]") {
    const bool fast = GENERATE(false, true); // a fast open that finds the key missing falls to the walk, which creates
    FakeRegistry reg;
    reg.key("Software");
    const auto o = set_value_verified(reg, FakeRegistry::kRoot, "Software\\New\\Deeper", "V", kRegDword, dword(3), fast);
    CHECK(o.result == "ok");
    CHECK(o.created == 2);
    REQUIRE(reg.get("Software\\New\\Deeper", "V") != nullptr);
    // Walked Software, found New missing, then created New and Deeper (no by-name path anywhere).
    CHECK(reg.calls("create_sub:New") == 1);
    CHECK(reg.calls("create_sub:Deeper") == 1);
    CHECK(reg.calls("create_sub:Software") == 0);
    CHECK((reg.method_calls("open_path") == 1) == fast);

    SECTION("a missing top-level key is not created at all") {
        FakeRegistry r2;
        const auto p = set_value_verified(r2, FakeRegistry::kRoot, "X\\Y\\Z", "V", kRegDword, dword(3), fast);
        CHECK(p.result == "refused");
        CHECK(p.reason == "root_level_create");
        CHECK(p.created == 0);
        CHECK(r2.calls("create_sub") == 0);
        CHECK_FALSE(r2.exists("X"));
    }
}

TEST_CASE("registry core: a create that finds the key already there refuses concurrent_change",
          "[registry][core]") {
    const bool fast = GENERATE(false, true);
    SECTION("the very first created component") {
        FakeRegistry reg;
        reg.key("Top");
        // The walk saw A absent; before the create lands, someone else makes it.
        reg.before = [&](const std::string& ev) {
            if (ev == "create_sub:A") reg.key("Top\\A");
        };
        const auto o = set_value_verified(reg, FakeRegistry::kRoot, "Top\\A\\B", "V", kRegDword, dword(3), fast);
        CHECK(o.result == "refused");
        CHECK(o.reason == "concurrent_change");
        CHECK(o.created == 0);
        CHECK(reg.calls("set_value") == 0);
        CHECK(reg.get("Top\\A\\B", "V") == nullptr);
    }
    SECTION("a later component: what this call created stays reported") {
        FakeRegistry reg;
        reg.key("Top");
        reg.before = [&](const std::string& ev) {
            if (ev == "create_sub:B") reg.key("Top\\A\\B");
        };
        const auto o = set_value_verified(reg, FakeRegistry::kRoot, "Top\\A\\B", "V", kRegDword, dword(3), fast);
        CHECK(o.result == "failed"); // A was created before the conflict: a mutation happened
        CHECK(o.reason == "concurrent_change");
        CHECK(o.created == 1);
        CHECK(reg.calls("set_value") == 0);
    }
}

TEST_CASE("registry core: open_checked reports a missing key distinct from a denied one",
          "[registry][core]") {
    const bool fast = GENERATE(false, true);
    FakeRegistry reg;
    reg.key("Denied")->deny_open = true;
    SECTION("absent: key_not_found and how many components were missing") {
        Opened o = open_checked(reg, FakeRegistry::kRoot, "No\\Such\\Key", kKeySetValue, false, false, fast);
        CHECK(o.error == "key_not_found");
        CHECK(o.missing == 3);
        CHECK(o.created == 0);
    }
    SECTION("ACL-denied: access_denied, not key_not_found") {
        Opened o = open_checked(reg, FakeRegistry::kRoot, "Denied", kKeySetValue, false, false, fast);
        CHECK(o.error == "access_denied");
    }
    SECTION("an empty component is refused before any call") {
        Opened o = open_checked(reg, FakeRegistry::kRoot, "A\\\\B", kKeySetValue, false, false, fast);
        CHECK(o.error == "invalid_key_path");
        CHECK(reg.log.empty());
    }
}

// ── delete_value_verified ────────────────────────────────────────────────

TEST_CASE("registry core: delete_value_verified splits not-found from denied and re-queries",
          "[registry][core]") {
    const bool fast = GENERATE(false, true);
    FakeRegistry reg;
    reg.put("A", "V", kRegDword, dword(1));
    SECTION("success: the value is gone and was read back as gone") {
        const auto o = delete_value_verified(reg, FakeRegistry::kRoot, "A", "V", fast);
        CHECK(o.result == "ok");
        CHECK(o.verify == "ok");
        CHECK(o.old.state == OldState::present);
        CHECK(reg.get("A", "V") == nullptr);
    }
    SECTION("missing key") {
        const auto o = delete_value_verified(reg, FakeRegistry::kRoot, "Nope", "V", fast);
        CHECK(o.result == "refused");
        CHECK(o.reason == "key_not_found");
    }
    SECTION("missing value: refused without calling delete") {
        const auto o = delete_value_verified(reg, FakeRegistry::kRoot, "A", "Other", fast);
        CHECK(o.result == "refused");
        CHECK(o.reason == "value_not_found");
        CHECK(reg.calls("delete_value") == 0);
    }
    SECTION("the delete itself is denied") {
        reg.key("A")->deny_delete_value = true;
        const auto o = delete_value_verified(reg, FakeRegistry::kRoot, "A", "V", fast);
        CHECK(o.result == "failed");
        CHECK(o.reason == "access_denied");
        CHECK(reg.get("A", "V") != nullptr);
    }
    SECTION("a value that is back after a successful delete is a mismatch") {
        reg.after = [&](const std::string& ev) {
            if (ev == "delete_value:V") reg.put("A", "V", kRegDword, dword(1)); // somebody writes it straight back
        };
        const auto o = delete_value_verified(reg, FakeRegistry::kRoot, "A", "V", fast);
        CHECK(o.result == "failed");
        CHECK(o.reason == "verify_mismatch");
        CHECK(o.verify == "mismatch");
    }
}

// ── delete_key ───────────────────────────────────────────────────────────

namespace {

/// A 3-level tree: Root(2 values) -> {C1 (1 value) -> {G1 (2 values)}, C2}. 4 keys, 5 values.
void build_tree(FakeRegistry& reg) {
    reg.put("T", "r1", kRegDword, dword(1));
    reg.put("T", "r2", kRegSz, sz("x"));
    reg.put("T\\C1", "c1", kRegDword, dword(2));
    reg.put("T\\C1\\G1", "g1", kRegDword, dword(3));
    reg.put("T\\C1\\G1", "g2", kRegBinary, B({1, 2}));
    reg.key("T\\C2");
    reg.put("Keep", "k", kRegDword, dword(9));
}

} // namespace

TEST_CASE("registry core: delete_key non-recursive refuses a key with subkeys and deletes a leaf by handle",
          "[registry][core]") {
    const bool fast = GENERATE(false, true);
    FakeRegistry reg;
    build_tree(reg);
    SECTION("with subkeys: key_has_subkeys, nothing deleted") {
        const auto o = delete_key_tree(reg, FakeRegistry::kRoot, "T", fast);
        CHECK(o.result == "refused");
        CHECK(o.reason == "key_has_subkeys");
        CHECK(reg.exists("T"));
        CHECK(reg.calls("delete_key_by_handle") == 0);
    }
    SECTION("a leaf: counted, deleted by handle, verified through the deleted handle") {
        const auto o = delete_key_tree(reg, FakeRegistry::kRoot, "T\\C1\\G1", fast);
        CHECK(o.result == "ok");
        CHECK(o.verify == "ok");
        CHECK(o.counted_keys == 1);
        CHECK(o.counted_values == 2);
        CHECK_FALSE(o.capped);
        CHECK_FALSE(reg.exists("T\\C1\\G1"));
        CHECK(reg.exists("T\\C1"));
        CHECK(reg.calls("delete_key_by_handle") == 1);
    }
    SECTION("a missing key") {
        CHECK(delete_key_tree(reg, FakeRegistry::kRoot, "T\\Nope", fast).reason == "key_not_found");
    }
}

// ── the guarded two-call value read ──────────────────────────────────────

namespace {

/// RegQueryValueExW over one value, for query_value_bounded: a null `data` answers the SIZE only (whatever
/// `*size` holds), a too-small buffer answers ERROR_MORE_DATA with the real size, `after(n)` lets a test
/// change the value once call n has returned, and `script` overrides a call outright.
struct QueryModel {
    std::uint32_t type = kRegBinary;
    Bytes value;
    bool absent = false;
    std::function<void(std::size_t)> after;
    std::function<std::optional<long>(std::size_t, std::uint32_t*, std::uint8_t*, std::uint32_t*)> script;
    std::vector<std::pair<bool, std::uint32_t>> calls; ///< (data != nullptr, *size on entry)

    long operator()(std::uint32_t* t, std::uint8_t* data, std::uint32_t* size) {
        const std::size_t n = calls.size();
        calls.emplace_back(data != nullptr, *size);
        long rc = 0;
        if (const auto scripted = script ? script(n, t, data, size) : std::nullopt) {
            rc = *scripted;
        } else if (absent) {
            rc = 2;
        } else {
            *t = type;
            if (data == nullptr) {
                *size = static_cast<std::uint32_t>(value.size());
            } else if (*size < value.size()) {
                *size = static_cast<std::uint32_t>(value.size());
                rc = 234;
            } else {
                std::copy(value.begin(), value.end(), data);
                *size = static_cast<std::uint32_t>(value.size());
            }
        }
        if (after) after(n);
        return rc;
    }
};

} // namespace

TEST_CASE("registry core: query_value_bounded reads a value that grows from nothing between the two calls",
          "[registry][core][query]") {
    QueryModel m;
    m.type = kRegDword;
    m.after = [&](std::size_t n) {
        if (n == 0) m.value = B({1, 2, 3, 4}); // empty at the size query, 4 bytes by the data call
    };
    QueryResult q;
    CHECK(query_value_bounded(4096, std::ref(m), q) == 0);
    CHECK(q.type == kRegDword);
    CHECK(q.size == 4);
    CHECK(q.bytes == B({1, 2, 3, 4}));
    REQUIRE(m.calls.size() == 3); // size query, data call (MORE_DATA), data call
    CHECK(m.calls[1].first); // the data call gets real storage, never a null lpData ...
    CHECK(m.calls[1].second >= 1); // ... of at least one byte
    CHECK(m.calls[2].second == 4);
}

TEST_CASE("registry core: query_value_bounded grows its buffer once and honours the cap and the size bound",
          "[registry][core][query]") {
    SECTION("N bytes growing to more: one MORE_DATA retry") {
        QueryModel m;
        m.value = B({1, 2, 3, 4});
        m.after = [&](std::size_t n) {
            if (n == 0) m.value = B({1, 2, 3, 4, 5, 6, 7, 8});
        };
        QueryResult q;
        CHECK(query_value_bounded(4096, std::ref(m), q) == 0);
        CHECK(q.size == 8);
        CHECK(q.bytes == B({1, 2, 3, 4, 5, 6, 7, 8}));
        CHECK(m.calls.size() == 3);
    }
    SECTION("a cap cuts the bytes, the size stays full") {
        QueryModel m;
        m.value = B({1, 2, 3, 4, 5, 6});
        QueryResult q;
        CHECK(query_value_bounded(4, std::ref(m), q) == 0);
        CHECK(q.size == 6);
        CHECK(q.bytes == B({1, 2, 3, 4}));
    }
    SECTION("cap 0 asks for the size only: one call, no bytes") {
        QueryModel m;
        m.value = B({1, 2, 3});
        QueryResult q;
        CHECK(query_value_bounded(0, std::ref(m), q) == 0);
        CHECK(q.size == 3);
        CHECK(q.bytes.empty());
        CHECK(m.calls.size() == 1);
    }
    SECTION("a value above kMaxWriteBytes is answered size-only without reading it") {
        QueryModel m;
        m.script = [](std::size_t, std::uint32_t* t, std::uint8_t* data, std::uint32_t* size) -> std::optional<long> {
            if (data != nullptr) return std::nullopt;
            *t = kRegBinary;
            *size = static_cast<std::uint32_t>(kMaxWriteBytes + 1);
            return 0;
        };
        QueryResult q;
        CHECK(query_value_bounded(4096, std::ref(m), q) == 0);
        CHECK(q.size == kMaxWriteBytes + 1);
        CHECK(q.bytes.empty());
        CHECK(m.calls.size() == 1);
    }
    SECTION("a value that grows past the bound mid-read is answered size-only") {
        QueryModel m;
        m.value = B({1, 2});
        m.after = [&](std::size_t n) {
            if (n == 0) m.value = B({1, 2, 3, 4, 5, 6, 7, 8});
        };
        QueryResult q;
        CHECK(query_value_bounded(4096, std::ref(m), q, /*max_read=*/4) == 0);
        CHECK(q.size == 8);
        CHECK(q.bytes.empty());
    }
}

TEST_CASE("registry core: query_value_bounded gives up on a value that keeps growing and passes failures through",
          "[registry][core][query]") {
    SECTION("three retries, then ERROR_MORE_DATA") {
        QueryModel m;
        m.value = B({1, 2, 3, 4});
        m.after = [&](std::size_t) { m.value.push_back(0); }; // grows after every call
        QueryResult q;
        CHECK(query_value_bounded(4096, std::ref(m), q) == 234);
        CHECK(m.calls.size() == 4); // the size query and three data calls
    }
    SECTION("an absent value, and a failing data call, return their code") {
        QueryModel absent;
        absent.absent = true;
        QueryResult q;
        CHECK(query_value_bounded(4096, std::ref(absent), q) == 2);
        CHECK(absent.calls.size() == 1);

        QueryModel denied;
        denied.value = B({1});
        denied.script = [](std::size_t n, std::uint32_t*, std::uint8_t*, std::uint32_t*) -> std::optional<long> {
            return n == 1 ? std::optional<long>{5} : std::nullopt;
        };
        CHECK(query_value_bounded(4096, std::ref(denied), q) == 5);
    }
}

TEST_CASE("registry core: query_value_bounded answers a value that stays zero-length without looping",
          "[registry][core][query]") {
    QueryModel m;
    m.type = kRegSz;
    QueryResult q;
    CHECK(query_value_bounded(4096, std::ref(m), q) == 0);
    CHECK(q.type == kRegSz);
    CHECK(q.size == 0);
    CHECK(q.bytes.empty());
    CHECK(m.calls.size() == 2); // the size query and one data call
}

TEST_CASE("registry core: query_value_bounded never forms a copy range from a count the buffer cannot hold",
          "[registry][core][query]") {
    SECTION("a SUCCESS that reports more bytes than the buffer holds is retried with room") {
        QueryModel m;
        m.value = B({1, 2, 3, 4});
        m.script = [&](std::size_t n, std::uint32_t* t, std::uint8_t* data, std::uint32_t* size) -> std::optional<long> {
            if (n != 1) return std::nullopt;
            *t = kRegBinary;
            *size = 8; // the first data call claims 8 bytes although it was given room for 4
            data[0] = 0xEE;
            return 0;
        };
        m.after = [&](std::size_t n) {
            if (n == 1) m.value = B({1, 2, 3, 4, 5, 6, 7, 8});
        };
        QueryResult q;
        CHECK(query_value_bounded(4096, std::ref(m), q) == 0);
        CHECK(q.size == 8);
        CHECK(q.bytes == B({1, 2, 3, 4, 5, 6, 7, 8}));
        CHECK(m.calls.size() == 3);
    }
}

// ── single-action output ─────────────────────────────────────────────────

TEST_CASE("registry core: render_single_action shapes the wire output", "[registry][core]") {
    AuditRecord au;
    au.op = "delete_key";
    au.hive = "HKLM";
    au.key = "A";
    SECTION("delete_key success appends the four count rows; dry_run is always 0 and capped is 0 or 1") {
        for (const bool capped : {false, true}) {
            WriteOutcome o;
            o.result = "ok";
            o.verify = "ok";
            o.counted_keys = 1;
            o.counted_values = 5;
            o.capped = capped;
            const std::string c = capped ? "1" : "0";
            const auto out = render_single_action(au, o, true);
            REQUIRE(out.lines.size() == 6);
            CHECK(out.lines[0].find("|result=ok|") != std::string::npos);
            CHECK(out.lines[0].find("|dry_run=0|counted_keys=1|counted_values=5|capped=" + c + "|") !=
                  std::string::npos);
            CHECK(out.lines[1] == "status|ok");
            CHECK(out.lines[2] == "counted_keys|1");
            CHECK(out.lines[3] == "counted_values|5");
            CHECK(out.lines[4] == "dry_run|0");
            CHECK(out.lines[5] == "capped|" + c);
            CHECK(out.rc == 0);
        }
    }
    SECTION("set_value success is exactly the audit line then status|ok") {
        AuditRecord s;
        s.op = "set_value";
        WriteOutcome o;
        o.result = "ok";
        const auto out = render_single_action(s, o, false);
        REQUIRE(out.lines.size() == 2);
        CHECK(out.lines[1] == "status|ok");
    }
    SECTION("a failure is the audit line then error|<token>, rc 1; a refusal's counts are what was counted") {
        WriteOutcome o;
        o.result = "refused";
        o.reason = "key_has_subkeys";
        o.counted_keys = 2;
        const auto out = render_single_action(au, o, true);
        REQUIRE(out.lines.size() == 2);
        CHECK(out.lines[0].find("|result=refused|reason=key_has_subkeys|") != std::string::npos);
        CHECK(out.lines[1] == "error|key_has_subkeys");
        CHECK(out.rc == 1);
    }
}

TEST_CASE("registry core: a delete_key whose handle does not report ERROR_KEY_DELETED is a verify mismatch",
          "[registry][core]") {
    const bool fast = GENERATE(false, true);
    FakeRegistry reg;
    reg.key("K");
    reg.inject["query_value:"] = 0; // the verify query answers SUCCESS: the key still reads as present
    const auto o = delete_key_tree(reg, FakeRegistry::kRoot, "K", fast);
    CHECK(o.result == "failed");
    CHECK(o.verify == "mismatch");
    CHECK(o.reason == "verify_mismatch");
}

// ── the value-count cap ──────────────────────────────────────────────────

TEST_CASE("registry core: delete_key on a leaf with more values than the cap stops counting at the cap and "
          "still deletes the key",
          "[registry][core]") {
    const bool fast = GENERATE(false, true);
    FakeRegistry reg;
    reg.key("Top");
    for (std::size_t i = 0; i < kMaxTreeNodes + 5; ++i) reg.put("Top\\Big", "v" + std::to_string(i), kRegDword, dword(1));
    const auto o = delete_key_tree(reg, FakeRegistry::kRoot, "Top\\Big", fast);
    CHECK(o.result == "ok");
    CHECK(o.capped);
    CHECK(o.counted_keys == 1);
    CHECK(o.counted_values == kMaxTreeNodes - 1); // the key itself is node 1
    CHECK_FALSE(reg.exists("Top\\Big"));
    CHECK(reg.method_calls("enum_value") == kMaxTreeNodes); // 9,999 values counted, the 10,000th call hit the cap
    const auto out = render_single_action(AuditRecord{}, o, true);
    REQUIRE(out.lines.size() == 6);
    CHECK(out.lines[5] == "capped|1");
}

TEST_CASE("registry core: a leaf whose value set grows on every enumeration call ends capped instead of "
          "spinning",
          "[registry][core]") {
    FakeRegistry reg;
    reg.key("Top\\Grows");
    std::size_t added = 0;
    reg.grow_on_enum = [&added](Node& n) { n.values["g" + std::to_string(added++)] = Val{kRegDword, dword(1)}; };
    const auto o = delete_key_tree(reg, FakeRegistry::kRoot, "Top\\Grows");
    CHECK(o.capped);
    CHECK(o.counted_values == kMaxTreeNodes - 1);
    CHECK(reg.method_calls("enum_value") == kMaxTreeNodes);
    CHECK(o.result == "ok"); // NtDeleteKey of a leaf removes its values whatever their count
}

// ── the fast open ────────────────────────────────────────────────────────

TEST_CASE("registry core: names_equal_ascii_ci folds A-Z only", "[registry][core]") {
    CHECK(names_equal_ascii_ci("\\REGISTRY\\MACHINE\\Soft", "\\registry\\machine\\SOFT"));
    CHECK_FALSE(names_equal_ascii_ci("a", "ab"));
    CHECK_FALSE(names_equal_ascii_ci("a\\b", "a/b"));
    CHECK(names_equal_ascii_ci("", ""));
    // a name that differs in NON-ASCII case is a different name to this compare: the caller walks
    CHECK_FALSE(names_equal_ascii_ci("Caf\xC3\xA9", "Caf\xC3\x89"));
    CHECK(names_equal_ascii_ci("Caf\xC3\xA9", "CAF\xC3\xA9"));
    // the characters between 'Z' and 'a' are not letters
    CHECK_FALSE(names_equal_ascii_ci("[", "{"));
    CHECK_FALSE(names_equal_ascii_ci("@", "`"));
}

TEST_CASE("registry fast_open_hive: HKLM and HKU only", "[registry][core]") {
    CHECK(fast_open_hive(Hive::hklm));
    CHECK(fast_open_hive(Hive::hku));
    CHECK_FALSE(fast_open_hive(Hive::hkcu)); // resolves per calling user
    CHECK_FALSE(fast_open_hive(Hive::hkcr)); // a merged view of two trees
}

namespace {

constexpr std::uint32_t kFastAccess = kKeySetValue | kKeyQueryValue;

/// splitmix64. std::uniform_int_distribution is not portable across standard libraries and the corpus has to
/// be the same trees on every host.
struct Rng {
    std::uint64_t state;
    std::uint64_t next() {
        std::uint64_t z = (state += 0x9E3779B97F4A7C15ull);
        z = (z ^ (z >> 30)) * 0xBF58476D1CE4E5B9ull;
        z = (z ^ (z >> 27)) * 0x94D049BB133111EBull;
        return z ^ (z >> 31);
    }
    std::uint32_t below(std::uint32_t n) { return static_cast<std::uint32_t>(next() % n); }
    bool chance(std::uint32_t percent) { return below(100) < percent; }
};

std::string join(const std::vector<std::string>& v, std::size_t from, std::size_t to) {
    std::string out;
    for (std::size_t i = from; i < to; ++i) out += (out.empty() ? "" : "\\") + v[i];
    return out;
}

/// What is true of a requested path in the TREE, worked out from the nodes and their flags alone (never through
/// the fake's kernel emulation, which is what the code under test is checked against).
struct Truth {
    bool found = false;          ///< every component exists
    NodeP leaf;
    bool link_before_leaf = false;
    bool leaf_is_link = false;
    bool leaf_decoy = false;     ///< a plain leaf holding a value named SymbolicLinkValue
    bool leaf_denied = false;
    /// What the reference walk must answer, stopping at the first problem in path order: "" accepts.
    std::string walk_error;
    /// The first problem at an ANCESTOR (not the leaf), when the walk would have refused there.
    std::string ancestor_problem;
};

Truth truth_of(FakeRegistry& reg, std::string_view path, bool leaf_may_be_link) {
    Truth t;
    const auto parts = split_key(path);
    NodeP cur = reg.root;
    bool walk_stopped = false;
    bool all_found = true;
    for (std::size_t i = 0; i < parts.size(); ++i) {
        const bool last = i + 1 == parts.size();
        const auto it = cur->subkeys.find(std::string{parts[i]});
        if (it == cur->subkeys.end()) {
            if (!walk_stopped) t.walk_error = "key_not_found";
            all_found = false;
            break;
        }
        const NodeP child = it->second;
        const bool link = child->is_link;
        const bool decoy = !link && child->values.contains("SymbolicLinkValue");
        if (last) {
            t.leaf_is_link = link;
            t.leaf_decoy = decoy;
            t.leaf_denied = child->deny_open;
        } else if (link) {
            t.link_before_leaf = true;
        }
        if (!walk_stopped) {
            if (child->deny_open) {
                t.walk_error = "access_denied";
                walk_stopped = true;
            } else if ((link || decoy) && !(last && leaf_may_be_link)) {
                t.walk_error = "key_is_link";
                walk_stopped = true;
            }
            if (walk_stopped && !last) t.ancestor_problem = t.walk_error;
        }
        cur = child;
    }
    t.found = all_found;
    if (all_found) t.leaf = cur;
    return t;
}

/// One corpus tree: a main path of 1..10 components with a random mix of links (intermediate and leaf, dangling,
/// real, chained and self-referential), decoy SymbolicLinkValue values, traverse-only ancestors, a sibling tree
/// with the same suffix and a missing leaf. Returns the path as stored.
std::string build_trial(FakeRegistry& reg, Rng& rng) {
    static constexpr const char* kBase[] = {"Soft", "SOFT", "Acme", "aCmE", "Run", "k"};
    const std::size_t depth = 1 + rng.below(10);
    std::vector<std::string> names;
    for (std::size_t i = 0; i < depth; ++i) names.push_back(std::string{kBase[rng.below(6)]} + std::to_string(i));
    const std::string path = join(names, 0, depth);
    reg.key(path);
    reg.put(path, "V", kRegDword, dword(1));

    // How a link at position `at` (0-based) resolves: 0 dangling, 1 a real alternative tree, 2 via a second link,
    // 3 back to itself.
    const auto make_link = [&](std::size_t at, bool leaf) {
        const std::string link_path = join(names, 0, at + 1);
        const NodeP node = reg.key(link_path);
        node->is_link = true;
        switch (rng.below(4)) {
        case 0: node->link_target.clear(); break;
        case 1:
            reg.key("Alt\\" + (leaf ? std::string{"Leaf"} : join(names, at + 1, depth)));
            node->link_target = "Alt";
            break;
        case 2:
            reg.key("Alt\\" + (leaf ? std::string{"Leaf"} : join(names, at + 1, depth)));
            reg.link("Chain", "Alt");
            node->link_target = "Chain";
            break;
        default: node->link_target = link_path; break;
        }
    };
    if (depth >= 2 && rng.chance(25)) make_link(rng.below(static_cast<std::uint32_t>(depth - 1)), false);
    if (rng.chance(15)) make_link(depth - 1, true);
    if (depth >= 2 && rng.chance(20)) {
        const auto j = rng.below(static_cast<std::uint32_t>(depth - 1));
        reg.put(join(names, 0, j + 1), "SymbolicLinkValue", kRegSz, sz("decoy"));
    }
    if (rng.chance(10)) reg.put(path, "SymbolicLinkValue", kRegSz, sz("decoy"));
    if (depth >= 2 && rng.chance(15)) reg.key(join(names, 0, 1 + rng.below(static_cast<std::uint32_t>(depth - 1))))->deny_open = true;
    if (rng.chance(8)) reg.key(path)->deny_open = true;
    if (depth >= 2 && rng.chance(15)) reg.key("Alt2\\" + join(names, 1, depth));
    if (rng.chance(10)) { // the leaf is missing
        const NodeP parent = depth == 1 ? reg.root : reg.key(join(names, 0, depth - 1));
        parent->subkeys.erase(names.back());
    }
    return path;
}

/// `path` with each ASCII letter flipped to the other case on a coin toss.
std::string flip_case(std::string path, Rng& rng) {
    for (char& c : path) {
        if (c >= 'a' && c <= 'z' && rng.chance(50)) c = static_cast<char>(c - 32);
        else if (c >= 'A' && c <= 'Z' && rng.chance(50)) c = static_cast<char>(c + 32);
    }
    return path;
}

} // namespace

TEST_CASE("registry core: fast open corpus -- ACCEPT only ever lands on the canonical object with no real link on "
          "the path",
          "[registry][core]") {
    constexpr int kTrials = 2000;
    Rng rng{0x59757A75ull}; // "Yuzu"
    int requests = 0, accepted = 0, clean = 0, clean_hits = 0;
    int acl_divergences = 0, decoy_divergences = 0, leaf_decoy_refusals = 0, link_refusals = 0;
    for (int trial = 0; trial < kTrials; ++trial) {
        FakeRegistry reg;
        const std::string stored = build_trial(reg, rng);
        for (const std::string& request : {stored, flip_case(stored, rng)}) {
            for (const bool lml : {false, true}) {
                INFO("trial " << trial << " path " << request << " leaf_may_be_link " << lml);
                const Truth t = truth_of(reg, request, lml);
                // The reference walk answers what the tree says, whatever the fast open does.
                const Opened walk = open_checked(reg, FakeRegistry::kRoot, request, kFastAccess, false, lml, false);
                CHECK(walk.error == t.walk_error);
                if (walk.error.empty()) {
                    REQUIRE(t.found);
                    CHECK(reg.node(walk.leaf.get()) == t.leaf);
                }
                const Opened fast = open_fast(reg, FakeRegistry::kRoot, request, kFastAccess, lml);
                CHECK(fast.error.empty()); // open_fast never produces a verdict
                ++requests;
                if (t.walk_error.empty()) {
                    ++clean;
                    clean_hits += fast.fast ? 1 : 0;
                }
                if (!fast.fast) {
                    CHECK(fast.leaf.get() == 0); // a declined open holds nothing
                    if (t.link_before_leaf || (t.leaf_is_link && !lml)) ++link_refusals;
                    if (t.leaf_decoy && !lml && !t.leaf_is_link) ++leaf_decoy_refusals;
                    continue;
                }
                ++accepted;
                // SOUNDNESS: the handle is bound to the canonical object and no real link was traversed.
                REQUIRE(t.found);
                CHECK_FALSE(t.link_before_leaf);
                CHECK_FALSE(t.leaf_denied);
                if (!lml) {
                    CHECK_FALSE(t.leaf_is_link);
                    CHECK_FALSE(t.leaf_decoy);
                }
                CHECK(reg.node(fast.leaf.get()) == t.leaf);
                // The walk's ACCEPT follows, except for the two ancestor-only divergences, each named.
                if (!walk.error.empty()) {
                    REQUIRE(t.ancestor_problem == walk.error);
                    if (walk.error == "access_denied") ++acl_divergences;
                    if (walk.error == "key_is_link") ++decoy_divergences;
                }
            }
        }
    }
    // Liveness: a request the walk accepts is a fast hit, case variants included (an ASCII-only fold).
    CHECK(clean == clean_hits);
    // The corpus exercises every class it claims to.
    CHECK(acl_divergences > 0);
    CHECK(decoy_divergences > 0);
    CHECK(leaf_decoy_refusals > 0);
    CHECK(link_refusals > 0);
    WARN("fast open corpus: " << accepted << " of " << requests << " requests accepted fast; " << clean_hits << " of "
         << clean << " walk-accepted ones; ancestor divergences: " << acl_divergences << " traverse-only, "
         << decoy_divergences << " decoy value");
}

TEST_CASE("registry core: fast open and the two documented ancestor divergences", "[registry][core]") {
    SECTION("a traverse-only ancestor: the walk says access_denied and the fast open accepts the real key") {
        FakeRegistry reg;
        reg.key("A\\B\\C");
        reg.key("A\\B")->deny_open = true;
        const auto walk = set_value_verified(reg, FakeRegistry::kRoot, "A\\B\\C", "V", kRegDword, dword(1), false);
        CHECK(walk.reason == "access_denied");
        CHECK(reg.get("A\\B\\C", "V") == nullptr);
        const auto fast = set_value_verified(reg, FakeRegistry::kRoot, "A\\B\\C", "V", kRegDword, dword(1), true);
        CHECK(fast.result == "ok");
        REQUIRE(reg.get("A\\B\\C", "V") != nullptr); // the write landed on the real requested key
        CHECK(reg.method_calls("open_path") == 1);
    }
    SECTION("a decoy value on a non-link ancestor: the walk says key_is_link and the fast open accepts the real key") {
        FakeRegistry reg;
        reg.key("A\\B\\C");
        reg.put("A\\B", "SymbolicLinkValue", kRegSz, sz("not a link"));
        const auto walk = set_value_verified(reg, FakeRegistry::kRoot, "A\\B\\C", "V", kRegDword, dword(1), false);
        CHECK(walk.reason == "key_is_link");
        CHECK(reg.get("A\\B\\C", "V") == nullptr);
        const auto fast = set_value_verified(reg, FakeRegistry::kRoot, "A\\B\\C", "V", kRegDword, dword(1), true);
        CHECK(fast.result == "ok");
        REQUIRE(reg.get("A\\B\\C", "V") != nullptr);
    }
    SECTION("the same decoy on the LEAF is refused on both paths and nothing is written") {
        for (const bool fast : {false, true}) {
            FakeRegistry reg;
            reg.key("A\\B\\C");
            reg.put("A\\B\\C", "SymbolicLinkValue", kRegSz, sz("not a link"));
            const auto o = set_value_verified(reg, FakeRegistry::kRoot, "A\\B\\C", "V", kRegDword, dword(1), fast);
            CHECK(o.result == "refused");
            CHECK(o.reason == "key_is_link");
            CHECK(reg.calls("set_value") == 0);
        }
    }
}

TEST_CASE("registry core: fast set_value issues a fixed number of seam calls at every depth", "[registry][core]") {
    // Seam calls, not Win32 calls: capture and read-back are each a size call and a data call underneath
    // (query_value_bounded), so a fast set_value is about nine Win32 calls. Counted across the whole seam, the
    // fast path is root_name + open_path + final_name + probe + capture + set + read-back + close, whatever
    // the depth; the walk it replaces grows with every component.
    constexpr std::size_t kBudget = 8;
    std::vector<std::size_t> fast_counts, walk_counts;
    for (const std::size_t depth : {3u, 6u, 10u}) {
        std::vector<std::string> names;
        for (std::size_t i = 0; i < depth; ++i) names.push_back("K" + std::to_string(i));
        const std::string path = join(names, 0, depth);
        for (const bool fast : {true, false}) {
            FakeRegistry reg;
            reg.put(path, "V", kRegDword, dword(1)); // an existing key, so no create
            const auto o = set_value_verified(reg, FakeRegistry::kRoot, path, "V", kRegDword, dword(2), fast);
            REQUIRE(o.ok());
            (fast ? fast_counts : walk_counts).push_back(reg.seam_calls);
            if (fast) {
                CHECK(reg.method_calls("open_sub") == 0);
                CHECK(reg.method_calls("create_sub") == 0);
                CHECK(reg.method_calls("open_path") == 1);
                CHECK(reg.method_calls("final_name") == 1);
            }
        }
    }
    REQUIRE(fast_counts.size() == 3);
    for (const std::size_t n : fast_counts) {
        CHECK(n <= kBudget);
        CHECK(n == fast_counts.front()); // equal at depth 3, 6 and 10
    }
    CHECK(walk_counts[0] < walk_counts[1]); // the walk is what grows
    CHECK(walk_counts[1] < walk_counts[2]);
    WARN("seam calls for set_value at depth 3/6/10: fast " << fast_counts[0] << "/" << fast_counts[1] << "/"
         << fast_counts[2] << ", walk " << walk_counts[0] << "/" << walk_counts[1] << "/" << walk_counts[2]);
}

TEST_CASE("registry core: the walk is taken only for a missing key a name mismatch and an ineligible hive",
          "[registry][core]") {
    SECTION("an existing key never walks") {
        FakeRegistry reg;
        reg.put("Software\\Acme", "V", kRegDword, dword(1));
        const auto o = set_value_verified(reg, FakeRegistry::kRoot, "Software\\Acme", "V", kRegDword, dword(2), true);
        REQUIRE(o.ok());
        CHECK(reg.method_calls("open_sub") == 0);
        CHECK(reg.method_calls("open_path") == 1);
    }
    SECTION("a missing key is created by the walk") {
        FakeRegistry reg;
        reg.key("Software");
        const auto o = set_value_verified(reg, FakeRegistry::kRoot, "Software\\New", "V", kRegDword, dword(2), true);
        REQUIRE(o.ok());
        CHECK(o.created == 1);
        CHECK(reg.method_calls("open_path") == 1); // tried first, found the key missing
        CHECK(reg.method_calls("open_sub") >= 1);
        CHECK(reg.method_calls("create_sub") == 1);
    }
    SECTION("a name that is not the canonical path walks") {
        FakeRegistry reg;
        reg.put("Elsewhere\\Child", "V", kRegDword, dword(1));
        reg.link("Alias", "Elsewhere");
        const auto o = set_value_verified(reg, FakeRegistry::kRoot, "Alias\\Child", "V", kRegDword, dword(2), true);
        CHECK(o.reason == "key_is_link");
        CHECK(reg.method_calls("open_path") == 1);
        CHECK(reg.method_calls("open_sub") >= 1);
        CHECK(reg.get("Elsewhere\\Child", "V")->data == dword(1)); // the target was never written
    }
    SECTION("an ineligible hive (HKCU and HKCR) never tries the fast open") {
        FakeRegistry reg;
        reg.put("Software\\Acme", "V", kRegDword, dword(1));
        const auto o = set_value_verified(reg, FakeRegistry::kRoot, "Software\\Acme", "V", kRegDword, dword(2), false);
        REQUIRE(o.ok());
        CHECK(reg.method_calls("open_path") == 0);
        CHECK(reg.method_calls("final_name") == 0);
        CHECK(reg.method_calls("root_name") == 0);
        CHECK(reg.method_calls("open_sub") == 2); // Software, then Acme
    }
    SECTION("a root with no kernel name walks even when asked to be fast") {
        FakeRegistry reg;
        reg.put("Software\\Acme", "V", kRegDword, dword(1));
        const auto o = set_value_verified(reg, FakeRegistry::kRootNoName, "Software\\Acme", "V", kRegDword, dword(2), true);
        REQUIRE(o.ok());
        CHECK(reg.method_calls("root_name") == 1);
        CHECK(reg.method_calls("open_path") == 0);
        CHECK(reg.method_calls("open_sub") == 2);
    }
    SECTION("an empty component is refused by the walk before any call") {
        FakeRegistry reg;
        const auto o = set_value_verified(reg, FakeRegistry::kRoot, "A\\\\B", "V", kRegDword, dword(2), true);
        CHECK(o.reason == "invalid_key_path");
        CHECK(reg.seam_calls == 0);
    }
}

TEST_CASE("registry core: a case variant of an existing key is a fast hit", "[registry][core]") {
    FakeRegistry reg;
    reg.put("Software\\Acme", "V", kRegDword, dword(1));
    const auto o = set_value_verified(reg, FakeRegistry::kRoot, "SOFTWARE\\ACME", "V", kRegDword, dword(2), true);
    REQUIRE(o.ok());
    CHECK(reg.method_calls("open_sub") == 0); // an ASCII-only case difference does not cost the fast path
    CHECK(reg.get("Software\\Acme", "V")->data == dword(2));
}

TEST_CASE("registry core: a non-ASCII case variant takes the walk and reaches the same verdict",
          "[registry][core]") {
    FakeRegistry reg;
    reg.put("Software\\Caf\xC3\xA9", "V", kRegDword, dword(1));
    const auto o = set_value_verified(reg, FakeRegistry::kRoot, "Software\\Caf\xC3\x89", "V", kRegDword, dword(2), true);
    // the fake compares names ASCII-case-insensitively only, so the walk does not find this key either
    CHECK(o.reason != "key_is_link");
    CHECK(reg.method_calls("open_path") == 1);
    CHECK(reg.method_calls("open_sub") >= 1); // the fast open declined: an ASCII fold never equates the two names
}

TEST_CASE("registry core: a failed final_name or root_name falls back to the walk and never accepts",
          "[registry][core]") {
    SECTION("final_name fails on a path that goes through a link: the walk refuses and nothing is written") {
        FakeRegistry reg;
        reg.put("Elsewhere\\Child", "V", kRegDword, dword(1));
        reg.link("Alias", "Elsewhere");
        reg.inject["final_name"] = 5;
        const auto o = set_value_verified(reg, FakeRegistry::kRoot, "Alias\\Child", "V", kRegDword, dword(2), true);
        CHECK(o.reason == "key_is_link");
        CHECK(reg.get("Elsewhere\\Child", "V")->data == dword(1));
        CHECK(reg.calls("set_value") == 0);
    }
    SECTION("final_name fails on a clean path: the walk takes over and the write still lands") {
        FakeRegistry reg;
        reg.put("Software\\Acme", "V", kRegDword, dword(1));
        reg.inject["final_name"] = 234; // a name that does not fit the buffer
        const auto o = set_value_verified(reg, FakeRegistry::kRoot, "Software\\Acme", "V", kRegDword, dword(2), true);
        REQUIRE(o.ok());
        CHECK(reg.method_calls("open_sub") >= 1);
        CHECK(reg.get("Software\\Acme", "V")->data == dword(2));
    }
    SECTION("root_name fails: the walk takes over") {
        FakeRegistry reg;
        reg.put("Software\\Acme", "V", kRegDword, dword(1));
        reg.inject["root_name"] = 5;
        REQUIRE(set_value_verified(reg, FakeRegistry::kRoot, "Software\\Acme", "V", kRegDword, dword(2), true).ok());
        CHECK(reg.method_calls("open_path") == 0);
    }
    SECTION("open_path fails for a reason other than a missing key: the walk reports it") {
        FakeRegistry reg;
        reg.key("Software\\Acme");
        reg.inject["open_path"] = 1450;
        const auto o = set_value_verified(reg, FakeRegistry::kRoot, "Software\\Acme", "V", kRegDword, dword(2), true);
        REQUIRE(o.ok()); // the walk, not the fast open, produced this verdict
        CHECK(reg.method_calls("open_sub") >= 1);
    }
}

TEST_CASE("registry core: a leaf link is accepted by the fast open only to be deleted as the link",
          "[registry][core]") {
    SECTION("delete_key takes the link object fast and leaves its target") {
        FakeRegistry reg;
        reg.put("Real\\Target", "keep", kRegDword, dword(1));
        reg.link("Software\\L", "Real\\Target");
        const auto o = delete_key_tree(reg, FakeRegistry::kRoot, "Software\\L", true);
        REQUIRE(o.ok());
        CHECK(reg.method_calls("open_sub") == 0); // the leaf probe is skipped, the name compare still ran
        CHECK(reg.method_calls("final_name") == 1);
        CHECK_FALSE(reg.exists("Software\\L"));
        CHECK(reg.get("Real\\Target", "keep")->data == dword(1));
    }
    SECTION("set_value and delete_value refuse the same leaf link") {
        FakeRegistry reg;
        reg.put("Real\\Target", "V", kRegDword, dword(1));
        reg.link("Software\\L", "Real\\Target");
        CHECK(set_value_verified(reg, FakeRegistry::kRoot, "Software\\L", "V", kRegDword, dword(2), true).reason ==
              "key_is_link");
        CHECK(delete_value_verified(reg, FakeRegistry::kRoot, "Software\\L", "V", true).reason == "key_is_link");
        CHECK(reg.get("Real\\Target", "V")->data == dword(1));
    }
}

TEST_CASE("registry core: an intermediate link that resolves is never accepted by the fast open",
          "[registry][core]") {
    // The shape the name compare exists for: the kernel opens the TARGET key successfully and the probe on it
    // is clean, so only the canonical-name check separates this from a plain key.
    FakeRegistry reg;
    reg.put("Target\\Child", "V", kRegDword, dword(1));
    reg.link("A\\Link", "Target");
    reg.key("A\\Link\\Child"); // the tree below a link: irrelevant to the kernel, which follows the link
    const Opened fast = open_fast(reg, FakeRegistry::kRoot, "A\\Link\\Child", kFastAccess, false);
    CHECK_FALSE(fast.fast);
    CHECK(reg.method_calls("open_path") == 1);
    CHECK(reg.method_calls("final_name") == 1);
    CHECK(reg.method_calls("query_value") == 0); // declined at the name compare, before any probe
    const auto o = set_value_verified(reg, FakeRegistry::kRoot, "A\\Link\\Child", "V", kRegDword, dword(2), true);
    CHECK(o.reason == "key_is_link");
    CHECK(reg.get("Target\\Child", "V")->data == dword(1));
}
