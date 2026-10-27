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
#include <format>
#include <functional>
#include <iterator>
#include <map>
#include <memory>
#include <new>
#include <optional>
#include <set>
#include <stdexcept>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

#include "local_dispatcher.hpp"
#include "registry_core.hpp"

using namespace yuzu::registry;
using yuzu::profiles::kRegBinary;
using yuzu::profiles::kRegDword;
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
    /// Non-empty: the value's RAW UTF-16 name is not well-formed (its stored key stands for it, e.g. the WTF-8 bytes of a
    /// lone surrogate, which no UTF-8 name can address) and an enumeration presents it lossily as this (U+FFFD); an exact
    /// enumeration answers kErrorInvalidData.
    std::string enum_as;
};
struct Node {
    std::map<std::string, NodeP, ILess> subkeys;
    std::map<std::string, Val, ILess> values;
    bool is_link = false;
    std::string enum_as; ///< as Val::enum_as, for this key's own name as its parent's enum_subkey presents it
    /// is_link: the canonical path (from the fake root) the kernel follows to; "" is a dangling link.
    std::string link_target;
    bool deleted = false;
    // fault flags
    /// The walk cannot open this key (ACL). open_path fails for it only as the LEAF: the kernel needs just
    /// traverse access to pass THROUGH an ancestor, which is the first documented divergence.
    bool deny_open = false, deny_query = false, deny_set = false;
    bool deny_create = false; ///< creating a child fails (create_sub)
    bool deny_delete_value = false, deny_delete_key = false;
    bool deny_delete_access = false; ///< the ACL denies DELETE: an open_sub asking for it fails (5)
    std::set<std::string> unreadable_values;
};

/// The registry as the kernel presents it: `open_sub` opens ONE component of the current handle as it is
/// (the walk always passes REG_OPTION_OPEN_LINK), while `open_path` resolves a whole path the way
/// RegOpenKeyExW does -- an intermediate link is FOLLOWED to its target, a link at the leaf is opened as the
/// link object -- and `final_name` is the canonical name of the object the handle is bound to. A plain key may
/// carry a VALUE named SymbolicLinkValue; the probe cannot tell that from a link. A relative open or create from
/// a handle whose key has BECOME a link (a test hook completes it) is followed to the link's target, so the
/// walk's check-to-use race is expressible.
///
/// Access masks are ENFORCED per handle: a handle answers 5 (ERROR_ACCESS_DENIED) to a call whose right it was not
/// opened with (set_value / delete_value: KEY_SET_VALUE; query_value / enum_value: KEY_QUERY_VALUE; enum_subkey:
/// KEY_ENUMERATE_SUB_KEYS; delete_key_by_handle: DELETE), after the deleted-key (1018) answer and before the
/// per-node fault flags. The two root handles grant everything. create_sub is DELIBERATELY not checked against the
/// parent handle's mask: RegCreateKeyExW checks key creation against the parent's security descriptor, not the
/// samDesired the parent was opened with (observed on Windows 11, kingsley: a KEY_READ handle can create when the
/// descriptor allows), so a refusal here would prove nothing about production; the KEY_CREATE_SUB_KEY the core
/// asks for on an intermediate create is pinned by the masks case instead. final_name needs no right
/// (KeyNameInformation).
class FakeRegistry final : public RegistryWriter {
public:
    static constexpr Handle kRoot = 1;
    static constexpr Handle kRootNoName = 2; ///< the same root, with no kernel name (HKCU / HKCR)
    static constexpr const char* kRootName = "\\REGISTRY\\MACHINE";
    ~FakeRegistry() override { CHECK(open.empty()); } // a leaked handle, whichever test made it
    NodeP root = std::make_shared<Node>();
    struct Granted {
        NodeP node;
        std::uint32_t access = 0;
    };
    std::map<Handle, Granted> open;
    Handle next = 0x100;
    std::vector<std::string> log;
    /// "<call>:<name>:<access mask in hex>" of every open_sub / open_path / create_sub, in call order.
    std::vector<std::string> masks;
    /// Every call across the seam, and per method: the deterministic stand-in for latency.
    std::size_t seam_calls = 0;
    std::map<std::string, std::size_t> by_method;
    /// Fired BEFORE open_sub, create_sub, set_value, delete_value and final_name ("final_name") and AFTER query_value /
    /// delete_value (a value erased by the call is gone when `after` runs), named
    /// "<op>:<name>" (e.g. "create_sub:B"), so a test can change the tree at a call boundary (or throw there). A
    /// test completes a link or adds a key from a hook with `link()` / `key()`; `masks.back()` is the call's own mask.
    std::function<void(const std::string&)> before, after;
    std::function<void(Node&, const std::string&)> tamper_after_set;
    /// Fired at the start of every enum_value call: a value set that grows while it is being enumerated.
    std::function<void(Node&)> grow_on_enum;
    /// "<op>:<name>" -> rc, consumed on use. open_path/final_name/root_name/enum_value/enum_subkey also take the bare
    /// method name.
    std::map<std::string, long> inject;
    /// RegFlushKey calls that answered success.
    std::size_t flushed = 0;

    NodeP node(Handle h) const {
        if (h == kRoot || h == kRootNoName) return root;
        const auto it = open.find(h);
        return it == open.end() ? nullptr : it->second.node;
    }
    /// Whether the handle was opened with `right` (the roots grant everything).
    [[nodiscard]] bool has(Handle h, std::uint32_t right) const {
        if (h == kRoot || h == kRootNoName) return true;
        const auto it = open.find(h);
        return it != open.end() && (it->second.access & right) == right;
    }
    NodeP key(const std::string& path, bool create = true) {
        forget_cursors();
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
        const auto n = key(path); // (key() forgets the cursors)
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
    /// The canonical path (stored names) of `target` in the tree; false when it is not in it.
    [[nodiscard]] bool canonical_path(const Node* target, std::string& out) const {
        if (target == root.get()) {
            out.clear();
            return true;
        }
        return path_of(*root, target, "", out);
    }

    // RegistryWriter
    long open_sub(Handle parent, std::string_view name, std::uint32_t access, Handle& out) override {
        tally("open_sub");
        const std::string ev = "open_sub:" + std::string{name};
        log.push_back(ev);
        masks.push_back(std::format("{}:{:#x}", ev, access));
        if (before) before(ev);
        long rc = 0;
        if (const auto inj = take(ev)) rc = *inj;
        NodeP child;
        if (rc == 0) {
            const auto base = children_of(node(parent));
            if (base.rc != 0) rc = base.rc;
            else if (name.empty()) {
                // RegOpenKeyExW(h, L""): a NEW handle to the same key, access-checked against ITS descriptor (not the
                // mask `h` was opened with), which is how a dry run asks "could I create here?" without creating.
                if ((access & kKeyCreateSubKey) != 0 && base.node->deny_create) rc = 5;
                else child = base.node;
            }
            else if (const auto it = base.node->subkeys.find(std::string{name}); it == base.node->subkeys.end()) rc = 2;
            else if (it->second->deny_open || ((access & kAccessDelete) != 0 && it->second->deny_delete_access)) rc = 5;
            else child = it->second;
        }
        if (rc == 0) {
            out = next++;
            open[out] = {child, access};
        }
        return rc;
    }
    long open_path(Handle root_h, std::string_view key_path, std::uint32_t access, Handle& out) override {
        tally("open_path");
        const std::string ev = "open_path:" + std::string{key_path};
        log.push_back(ev);
        masks.push_back(std::format("{}:{:#x}", ev, access));
        if (const auto inj = take(ev, "open_path")) return *inj;
        const auto start = node(root_h);
        if (!start) return 1018;
        const auto r = resolve(start, key_path, /*leaf_open_link=*/true, 0);
        if (r.rc != 0) return r.rc;
        if (!key_path.empty() && r.node->deny_open) return 5; // the leaf needs real access; an ancestor only traverse
        out = next++;
        open[out] = {r.node, access};
        return 0;
    }
    long final_name(Handle key_h, std::string& out) override {
        tally("final_name");
        log.push_back("final_name");
        if (before) before("final_name");
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
    long create_sub(Handle parent, std::string_view name, std::uint32_t access, Handle& out,
                    bool& created_new) override {
        tally("create_sub");
        const std::string ev = "create_sub:" + std::string{name};
        log.push_back(ev);
        masks.push_back(std::format("{}:{:#x}", ev, access));
        if (before) before(ev);
        forget_cursors();
        long rc = 0;
        if (const auto inj = take(ev)) rc = *inj;
        Resolved base;
        if (rc == 0) {
            base = children_of(node(parent));
            rc = base.rc;
        }
        if (rc == 0 && base.node->deny_create) rc = 5;
        if (rc == 0) {
            const auto p = base.node;
            const auto it = p->subkeys.find(std::string{name});
            if (it == p->subkeys.end()) {
                auto n = std::make_shared<Node>();
                p->subkeys[std::string{name}] = n;
                out = next++;
                open[out] = {n, access};
                created_new = true;
            } else {
                out = next++;
                open[out] = {it->second, access};
                created_new = false; // REG_OPENED_EXISTING_KEY
            }
        }
        return rc;
    }
    void close(Handle key_h) noexcept override {
        tally("close");
        log.push_back("close");
        open.erase(key_h);
        value_cursor.erase(key_h);
        subkey_cursor.erase(key_h);
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
        if (before) before(ev);
        if (const auto inj = take(ev)) return *inj;
        const auto n = node(key_h);
        if (!n || n->deleted) return 1018;
        if (!has(key_h, kKeySetValue) || n->deny_set) return 5;
        forget_cursors();
        n->values[std::string{name}] = Val{type, Bytes(data.begin(), data.end())};
        if (tamper_after_set) tamper_after_set(*n, std::string{name});
        return 0;
    }
    long delete_value(Handle key_h, std::string_view name) override {
        tally("delete_value");
        const std::string ev = "delete_value:" + std::string{name};
        log.push_back(ev);
        if (before) before(ev);
        long rc = 0;
        const auto n = node(key_h);
        if (const auto inj = take(ev)) rc = *inj;
        else if (!n || n->deleted) rc = 1018;
        else if (!has(key_h, kKeySetValue) || n->deny_delete_value) rc = 5;
        else {
            forget_cursors();
            rc = n->values.erase(std::string{name}) ? 0 : 2;
        }
        if (after) after(ev);
        return rc;
    }
    long enum_value(Handle key_h, std::uint32_t index, std::string& name, bool require_exact = false) override {
        tally("enum_value");
        if (const auto inj = take("enum_value", "enum_value")) return *inj;
        const auto n = node(key_h);
        if (!n || n->deleted) return 1018;
        if (!has(key_h, kKeyQueryValue)) return 5;
        if (grow_on_enum) grow_on_enum(*n);
        if (index >= n->values.size()) return 259;
        const auto& [stored, v] = *nth(n->values, key_h, index, value_cursor);
        return enumerated(stored, v.enum_as, require_exact, name);
    }
    long enum_subkey(Handle key_h, std::uint32_t index, std::string& name, bool require_exact = false) override {
        tally("enum_subkey");
        if (const auto inj = take("enum_subkey", "enum_subkey")) return *inj;
        const auto n = node(key_h);
        if (!n || n->deleted) return 1018;
        if (!has(key_h, kKeyEnumerateSubKeys)) return 5;
        if (index >= n->subkeys.size()) return 259;
        const auto& [stored, child] = *nth(n->subkeys, key_h, index, subkey_cursor);
        return enumerated(stored, child->enum_as, require_exact, name);
    }
    long flush_key(Handle key_h) override {
        tally("flush_key");
        log.push_back("flush_key");
        if (const auto inj = take("flush_key", "flush_key")) return *inj;
        const auto n = node(key_h);
        if (!n || n->deleted) return 1018;
        ++flushed;
        return 0;
    }
    long delete_key_by_handle(Handle key_h) noexcept override {
        tally("delete_key_by_handle");
        log.push_back("delete_key_by_handle");
        if (const auto inj = take("delete_key_by_handle")) return *inj;
        const auto n = node(key_h);
        if (!n || n->deleted) return 1018;
        if (!has(key_h, kAccessDelete) || n->deny_delete_key || !n->subkeys.empty()) return 5; // STATUS_CANNOT_DELETE maps to access denied
        forget_cursors();
        n->deleted = true;
        detach(root, n.get());
        return 0;
    }

private:
    /// enum_value / enum_subkey's position per handle. std::next from begin() is O(n) per call, so a walk over the
    /// 10,000-entry cap fixtures was O(n^2); a call for index+1 on the same handle advances the kept iterator instead.
    /// Every mutating call forgets the cursors, a cursor whose map changed size is not used, and with a test hook set
    /// (it can change the tree from outside) none is kept.
    template <class M>
    struct Cursor {
        std::uint32_t index = 0;
        std::size_t size = 0;
        typename M::const_iterator it;
    };
    std::map<Handle, Cursor<decltype(Node::values)>> value_cursor;
    std::map<Handle, Cursor<decltype(Node::subkeys)>> subkey_cursor;
    void forget_cursors() noexcept {
        value_cursor.clear();
        subkey_cursor.clear();
    }
    template <class M>
    typename M::const_iterator nth(const M& m, Handle h, std::uint32_t index, std::map<Handle, Cursor<M>>& cursors) {
        if (before || after || grow_on_enum || tamper_after_set) return std::next(m.begin(), index);
        if (const auto c = cursors.find(h);
            c != cursors.end() && c->second.index + 1 == index && c->second.size == m.size()) {
            c->second.index = index;
            return c->second.it = std::next(c->second.it);
        }
        const auto it = std::next(m.begin(), index);
        cursors[h] = Cursor<M>{index, m.size(), it};
        return it;
    }
    /// Win32Registry's enumerated_name: a malformed raw name (`lossy` set) is kErrorInvalidData when exact, else shown lossily.
    static long enumerated(const std::string& stored, const std::string& lossy, bool require_exact, std::string& out) {
        if (lossy.empty()) out = stored;
        else if (require_exact) return kErrorInvalidData;
        else out = lossy;
        return 0;
    }
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
    /// The node whose children a relative open or create from the handle bound to `p` sees. A key that has
    /// become a link (completed after the handle was opened) is FOLLOWED to its target, the way the kernel
    /// parses a name below a link object; a dangling link is not-found. Any other node is its own.
    Resolved children_of(const NodeP& p) const {
        if (!p || p->deleted) return {1018, nullptr};
        if (!p->is_link) return {0, p};
        if (p->link_target.empty()) return {2, nullptr};
        return resolve(root, p->link_target, false, 1);
    }
    long do_query(Handle key_h, std::string_view name, std::size_t cap, QueryResult& out) {
        const auto n = node(key_h);
        if (!n || n->deleted) return 1018;
        if (!has(key_h, kKeyQueryValue)) return 5;
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

TEST_CASE("registry core: a registry link is refused at every position; nothing is written",
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
    int captures = 0;
    // Both opens finish their checks before the previous-value capture (the walk's probes and kernel-name test,
    // the fast open's name compare and leaf probe). The instant the capture has been read -- the check is
    // finished, the use has not started -- B's tree entry becomes a link, exactly the swap a path-based
    // mutation would follow.
    reg.after = [&](const std::string& ev) {
        if (ev == "query_value:V" && ++captures == 1) {
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

// The walk's last test (open_checked / leaf_name_check): the leaf handle's kernel name must be the first
// component's name plus the remaining requested components. These run the WALK (fast_eligible false) because the
// probes it makes cannot see a link completed, or a component moved, AFTER the probe. Every REFUSAL assertion
// below is a mutant sentinel: with the check dropped (or a failed name read accepted) the write lands on the
// object the handle follows -- the decoy, or the parked key -- and the case turns red.
TEST_CASE("registry core: the walk refuses a leaf whose kernel name is not the requested path",
          "[registry][core][walk_identity]") {
    SECTION("a component completed into a link after its probe: the next relative open follows it to the decoy") {
        for (const int which : {1, 2}) { // 1: the first component A, 2: the intermediate component B
            INFO("component " << which);
            FakeRegistry reg;
            const NodeP a = reg.key("A");
            const NodeP b = reg.key("A\\B");
            reg.key("A\\B\\C");
            reg.put("Decoy\\B\\C", "Marker", kRegDword, dword(0xDEC0));
            int probes = 0;
            // The walk probes A, B, C in turn. A link is made in two steps (the key, then its SymbolicLinkValue),
            // so the probe of component `which` saw a plain key and the value lands right after it.
            reg.after = [&](const std::string& ev) {
                if (ev == "query_value:SymbolicLinkValue" && ++probes == which) {
                    const NodeP n = which == 1 ? a : b;
                    n->is_link = true;
                    n->link_target = which == 1 ? "Decoy" : "Decoy\\B";
                }
            };
            const auto o = set_value_verified(reg, FakeRegistry::kRoot, "A\\B\\C", "V", kRegDword, dword(7), false);
            CHECK(o.result == "refused");
            CHECK(o.reason == "key_is_link");
            CHECK_FALSE(o.mutated);
            CHECK(reg.calls("set_value") == 0); // nothing was written anywhere
            CHECK(reg.get("Decoy\\B\\C", "V") == nullptr);
            REQUIRE(reg.get("Decoy\\B\\C", "Marker") != nullptr);
            CHECK(reg.get("Decoy\\B\\C", "Marker")->data == dword(0xDEC0));
            CHECK(reg.get("A\\B\\C", "V") == nullptr);
            CHECK(reg.method_calls("final_name") == 2); // the first component's name and the leaf's
        }
    }
    SECTION("a component moved by a rename after its probe: the handle follows the object, not the path") {
        // NtRenameKey moves the object a handle is bound to without touching the handle. The real B goes to
        // A\Parked and a prepared link to the decoy takes its name; the walk's handle still opens C beneath the
        // moved object, and only its kernel name (A\Parked\C, not A\B\C) shows it.
        FakeRegistry reg;
        const NodeP a = reg.key("A");
        reg.put("A\\B\\C", "Marker", kRegDword, dword(0xD0));
        reg.put("Decoy", "Marker", kRegDword, dword(0xDEC0));
        int probes = 0;
        reg.after = [&](const std::string& ev) {
            if (ev == "query_value:SymbolicLinkValue" && ++probes == 2) {
                a->subkeys["Parked"] = a->subkeys["B"];
                auto link = std::make_shared<Node>();
                link->is_link = true;
                link->link_target = "Decoy";
                a->subkeys["B"] = link;
            }
        };
        const auto o = set_value_verified(reg, FakeRegistry::kRoot, "A\\B\\C", "V", kRegDword, dword(7), false);
        CHECK(o.result == "refused");
        CHECK(o.reason == "key_is_link");
        CHECK(reg.calls("set_value") == 0);
        CHECK(reg.get("A\\Parked\\C", "V") == nullptr);
        CHECK(reg.get("A\\Parked\\C", "Marker")->data == dword(0xD0));
        CHECK(reg.get("Decoy", "V") == nullptr);
    }
    SECTION("the create path: the parent completed into a link just before create_sub; what was made is deleted") {
        FakeRegistry reg;
        const NodeP top = reg.key("Top");
        reg.put("Decoy", "Marker", kRegDword, dword(0xDEC0));
        reg.before = [&](const std::string& ev) {
            if (ev == "create_sub:A") {
                top->is_link = true;
                top->link_target = "Decoy";
            }
        };
        const auto o = set_value_verified(reg, FakeRegistry::kRoot, "Top\\A\\B", "V", kRegDword, dword(7), false);
        CHECK(o.reason == "key_is_link");
        // A and B were created beneath the decoy before the name could be read, then deleted by their own
        // handles, leaf first (the fake refuses to delete a key that still has a subkey): nothing is left.
        CHECK(o.result == "refused");
        CHECK(o.created == 0);
        CHECK_FALSE(o.mutated);
        REQUIRE(reg.method_calls("delete_key_by_handle") == 2);
        const auto first_delete = std::find(reg.log.begin(), reg.log.end(), "delete_key_by_handle");
        const auto second_delete = std::find(std::next(first_delete), reg.log.end(), "delete_key_by_handle");
        CHECK(std::find(first_delete, second_delete, "close") != second_delete); // the leaf's handle is closed first
        CHECK_FALSE(reg.exists("Decoy\\A"));
        CHECK(reg.calls("set_value") == 0);
        CHECK(reg.get("Decoy", "Marker")->data == dword(0xDEC0));
        CHECK(render_single_action(AuditRecord{}, o, false).lines[0].find("|created=0|") != std::string::npos);
    }
    SECTION("a legitimate walk is accepted, case variants and a leaf link for delete_key included") {
        FakeRegistry reg;
        reg.put("Software\\Acme\\Deep", "V", kRegDword, dword(1));
        reg.link("Software\\L", "Software\\Acme");
        for (const std::string request : {"Software\\Acme\\Deep", "SOFTWARE\\acme\\DEEP", "software\\ACME\\deep"}) {
            INFO(request);
            const Opened o = open_checked(reg, FakeRegistry::kRoot, request, kKeySetValue, false);
            CHECK(o.error.empty());
            CHECK_FALSE(o.fast);
            CHECK(o.leaf.get() != 0);
        }
        const Opened link = open_checked(reg, FakeRegistry::kRoot, "software\\l", kKeySetValue, false, true);
        CHECK(link.error.empty()); // the link object itself: its own name is the requested one
    }
}

TEST_CASE("registry core: leaf_name_check compares the kernel names with an ASCII-only fold",
          "[registry][core][walk_identity]") {
    FakeRegistry reg;
    reg.key("Soft\\Caf\xC3\xA9");
    Handle h = 0;
    REQUIRE(reg.open_path(FakeRegistry::kRoot, "Soft\\Caf\xC3\xA9", kKeyQueryValue, h) == 0);
    const Owned leaf{reg, h};
    const std::string first = "\\REGISTRY\\MACHINE\\Soft";
    CHECK(leaf_name_check(reg, h, first, split_key("Soft\\Caf\xC3\xA9")).empty());
    CHECK(leaf_name_check(reg, h, first, split_key("SOFT\\CAF\xC3\xA9")).empty()); // A-Z fold; the first part is the kernel's
    // A difference outside ASCII is a different name to this compare: refused (README caveat 1), never accepted.
    CHECK(leaf_name_check(reg, h, first, split_key("Soft\\Caf\xC3\x89")) == "key_is_link");
    CHECK(leaf_name_check(reg, h, first, split_key("Soft\\Other")) == "key_is_link");
    CHECK(leaf_name_check(reg, h, first, split_key("Soft")) == "key_is_link"); // a shorter requested path
    reg.inject["final_name"] = 5;
    CHECK(leaf_name_check(reg, h, first, split_key("Soft\\Caf\xC3\xA9")) == "access_denied");
}

TEST_CASE("registry core: a walk whose handle cannot be named refuses and holds nothing", "[registry][core][walk_identity]") {
    SECTION("the first component's name cannot be read: refused before any probe") {
        FakeRegistry reg;
        reg.key("A\\B");
        reg.inject["final_name"] = 5;
        const auto o = set_value_verified(reg, FakeRegistry::kRoot, "A\\B", "V", kRegDword, dword(1), false);
        CHECK(o.result == "refused");
        CHECK(o.reason == "access_denied");
        CHECK(reg.method_calls("query_value") == 0);
        CHECK(reg.calls("set_value") == 0);
    }
    SECTION("the leaf's name cannot be read: refused, the unexpected code keeps its number") {
        FakeRegistry reg;
        reg.key("A\\B");
        reg.after = [&](const std::string& ev) { // the first probe is after the first name read
            if (ev == "query_value:SymbolicLinkValue" && reg.inject.empty()) reg.inject["final_name"] = 1450;
        };
        const auto o = set_value_verified(reg, FakeRegistry::kRoot, "A\\B", "V", kRegDword, dword(1), false);
        CHECK(o.result == "refused");
        CHECK(o.reason == "win32:1450");
        CHECK(reg.calls("set_value") == 0);
        CHECK(reg.get("A\\B", "V") == nullptr);
    }
}

TEST_CASE("registry core: a first component renamed between its open and its name read is refused",
          "[registry][core][walk_identity]") {
    struct Case {
        const char* request;
        const char* parked_leaf; ///< where the requested leaf sits once A has been renamed to Parked
    };
    for (const Case c : {Case{"A", "Parked"}, Case{"A\\B", "Parked\\B"}}) {
        INFO(c.request);
        FakeRegistry reg;
        reg.put("A\\B", "Marker", kRegDword, dword(0xD0));
        int names = 0;
        // The first name read follows the open of A immediately: the rename lands between the two, so the handle is
        // bound to an object that is no longer called A and the leaf's name (Parked\B) would match a walk anchored
        // at the renamed object.
        reg.before = [&](const std::string& ev) {
            if (ev == "final_name" && ++names == 1) {
                reg.root->subkeys["Parked"] = reg.root->subkeys["A"];
                reg.root->subkeys.erase("A");
            }
        };
        const auto o = set_value_verified(reg, FakeRegistry::kRoot, c.request, "V", kRegDword, dword(7), false);
        CHECK(o.result == "refused");
        CHECK(o.reason == "key_is_link");
        CHECK(reg.calls("set_value") == 0);
        CHECK(reg.get(c.parked_leaf, "V") == nullptr);
    }
}

TEST_CASE("registry core: every open and create asks for the access it needs", "[registry][core]") {
    FakeRegistry reg;
    reg.key("Software");
    // One denied open of the intermediate component: the walk retries it with the read access alone.
    reg.inject["open_sub:Software"] = 5;
    const auto o = set_value_verified(reg, FakeRegistry::kRoot, "Software\\New\\Deeper", "V", kRegDword, dword(3),
                                      false);
    REQUIRE(o.result == "ok");
    // KEY_QUERY_VALUE 0x1, KEY_SET_VALUE 0x2, KEY_CREATE_SUB_KEY 0x4, DELETE 0x10000. A created key carries DELETE
    // so a walk that stops can remove it by handle; the leaf also carries what the write and the probe need.
    const std::vector<std::string> expected{
        "open_sub:Software:0x5",         // denied
        "open_sub:Software:0x1",         // the retry
        "open_sub:New:0x5",              // not there
        "create_sub:New:0x10005",
        "create_sub:Deeper:0x10003",
    };
    CHECK(reg.masks == expected);

    FakeRegistry fast;
    fast.key("Software\\Acme");
    REQUIRE(set_value_verified(fast, FakeRegistry::kRoot, "Software\\Acme", "V", kRegDword, dword(3), true).ok());
    const std::vector<std::string> expected_fast{"open_path:Software\\Acme:0x3"};
    CHECK(fast.masks == expected_fast);

    // delete_value needs KEY_SET_VALUE (RegDeleteValueW) and the capture / verify queries KEY_QUERY_VALUE: 0x3.
    for (const bool is_fast : {false, true}) {
        FakeRegistry dv;
        dv.put("A", "V", kRegDword, dword(1));
        REQUIRE(delete_value_verified(dv, FakeRegistry::kRoot, "A", "V", is_fast).ok());
        const std::vector<std::string> want{is_fast ? "open_path:A:0x3" : "open_sub:A:0x3"};
        CHECK(dv.masks == want);
    }
    // delete_key: DELETE | KEY_ENUMERATE_SUB_KEYS | KEY_QUERY_VALUE (0x10009), no KEY_SET_VALUE.
    for (const bool is_fast : {false, true}) {
        FakeRegistry dk;
        dk.key("T");
        REQUIRE(delete_key_tree(dk, FakeRegistry::kRoot, "T", is_fast).ok());
        const std::vector<std::string> want{is_fast ? "open_path:T:0x10009" : "open_sub:T:0x10009"};
        CHECK(dk.masks == want);
    }
}

// The fake grants a handle exactly the rights it was opened with, so dropping a right from the mask the core asks
// for (the line above) turns a green case red instead of passing on a fake that never looked.
TEST_CASE("registry core: the fake enforces the access a handle was opened with", "[registry][core]") {
    FakeRegistry reg;
    reg.put("A", "V", kRegDword, dword(1));
    reg.key("A\\S");
    QueryResult q;
    std::string name;
    const auto open_a = [&](std::uint32_t access) {
        Handle h = 0;
        REQUIRE(reg.open_sub(FakeRegistry::kRoot, "A", access, h) == 0);
        return Owned{reg, h};
    };
    SECTION("each call needs its own right and answers access denied without it") {
        const auto query_only = open_a(kKeyQueryValue);
        CHECK(reg.query_value(query_only.get(), "V", 0, q) == 0);
        CHECK(reg.enum_value(query_only.get(), 0, name) == 0);
        CHECK(reg.set_value(query_only.get(), "W", kRegDword, dword(2)) == 5);
        CHECK(reg.delete_value(query_only.get(), "V") == 5);
        CHECK(reg.enum_subkey(query_only.get(), 0, name) == 5);
        CHECK(reg.get("A", "V") != nullptr);
        CHECK(reg.get("A", "W") == nullptr);

        const auto set_only = open_a(kKeySetValue);
        CHECK(reg.query_value(set_only.get(), "V", 0, q) == 5);
        CHECK(reg.enum_value(set_only.get(), 0, name) == 5);
        CHECK(reg.set_value(set_only.get(), "W", kRegDword, dword(2)) == 0);
        CHECK(reg.delete_value(set_only.get(), "W") == 0);

        const auto enum_only = open_a(kKeyEnumerateSubKeys);
        CHECK(reg.enum_subkey(enum_only.get(), 0, name) == 0);
        CHECK(reg.query_value(enum_only.get(), "V", 0, q) == 5);
        CHECK(reg.set_value(enum_only.get(), "W", kRegDword, dword(2)) == 5);
    }
    SECTION("delete_key_by_handle needs DELETE") {
        // A\S through two handles: one without DELETE, one with.
        Handle no_delete = 0, deletable = 0;
        REQUIRE(reg.open_path(FakeRegistry::kRoot, "A\\S", kKeyQueryValue | kKeyEnumerateSubKeys, no_delete) == 0);
        Owned no_delete_owner{reg, no_delete};
        REQUIRE(reg.open_path(FakeRegistry::kRoot, "A\\S", kAccessDelete, deletable) == 0);
        Owned deletable_owner{reg, deletable};
        CHECK(reg.delete_key_by_handle(no_delete_owner.get()) == 5);
        CHECK(reg.exists("A\\S"));
        CHECK(reg.delete_key_by_handle(deletable_owner.get()) == 0);
        CHECK_FALSE(reg.exists("A\\S"));
        // A deleted key answers 1018 before any access check: a handle lacking the right still sees the deletion.
        CHECK(reg.set_value(no_delete_owner.get(), "W", kRegDword, dword(2)) == 1018);
        CHECK(reg.query_value(no_delete_owner.get(), "V", 0, q) == 1018);
    }
    SECTION("create_sub is not gated by the parent handle's mask (RegCreateKeyExW checks the security descriptor)") {
        const auto query_only = open_a(kKeyQueryValue);
        Handle made = 0;
        bool created_new = false;
        REQUIRE(reg.create_sub(query_only.get(), "New", kKeyQueryValue, made, created_new) == 0);
        Owned made_owner{reg, made};
        CHECK(created_new);
        CHECK(reg.exists("A\\New"));
    }
    SECTION("the root handles grant everything") {
        CHECK(reg.set_value(FakeRegistry::kRoot, "R", kRegDword, dword(1)) == 0);
        CHECK(reg.enum_subkey(FakeRegistry::kRootNoName, 0, name) == 0);
    }
}

TEST_CASE("registry core: a missing suffix is created component-wise from the checked handle",
          "[registry][core]") {
    const bool fast = GENERATE(false, true); // a fast open that finds the key missing falls to the walk, which creates
    FakeRegistry reg;
    reg.key("Software");
    const auto o = set_value_verified(reg, FakeRegistry::kRoot, "Software\\New\\Deeper", "V", kRegDword, dword(3), fast);
    CHECK(o.result == "ok");
    CHECK(o.created == 2);
    // The count is on the wire too, where the server's audit row carries it.
    CHECK(render_single_action(AuditRecord{}, o, false).lines[0].find("|created=2|") != std::string::npos);
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
        // A was created before the conflict and cannot be removed (the other party's B is inside it): reported.
        CHECK(o.result == "failed");
        CHECK(o.reason == "concurrent_change");
        CHECK(o.created == 1);
        CHECK(reg.calls("set_value") == 0);
    }
}

// A walk that creates keys and then does not hand its leaf over deletes every key it created, on EVERY such exit
// (a later create fails, a later create finds its key already there, the name test refuses -- that last one is
// covered above), and only keys create_sub reported as new. Where a section says so, Top is completed into a link
// to Decoy just before the first create, which lands that create beneath Decoy: the stranded key the rollback
// exists for. The mutant each section turns red is named on its first line.
TEST_CASE("registry core: a walk that does not hand its leaf over deletes the keys it created",
          "[registry][core][walk_identity]") {
    FakeRegistry reg;
    const NodeP top = reg.key("Top");
    reg.put("Decoy", "Marker", kRegDword, dword(0xDEC0));
    const auto complete_link = [&](const std::string& ev) {
        if (ev == "create_sub:A") {
            top->is_link = true;
            top->link_target = "Decoy";
        }
    };
    const auto write = [&](const char* key) {
        return set_value_verified(reg, FakeRegistry::kRoot, key, "V", kRegDword, dword(7), false);
    };

    SECTION("a later create fails: the key beneath the link target is removed, the failure keeps its token") {
        // mutant: no roll_back() after the failed create_sub
        reg.before = complete_link;
        reg.inject["create_sub:B"] = 1450;
        const auto o = write("Top\\A\\B");
        CHECK(o.result == "refused");
        CHECK(o.reason == "win32:1450");
        CHECK(o.created == 0);
        CHECK_FALSE(reg.exists("Decoy\\A"));
        CHECK(reg.get("Decoy", "Marker")->data == dword(0xDEC0));
        CHECK(reg.calls("set_value") == 0);
    }
    SECTION("a later create finds its key elsewhere: ours is removed, the one it found is closed and untouched") {
        // mutants: no roll_back() on the !created_new exit; the opened-existing key pushed into made_keys
        reg.put("Other\\B", "Marker", kRegDword, dword(0xB0));
        reg.before = [&](const std::string& ev) {
            complete_link(ev);
            if (ev == "create_sub:B") { // the fake follows a create below a key that became a link: B is found in Other
                const NodeP a = reg.key("Decoy\\A", false);
                a->is_link = true;
                a->link_target = "Other";
            }
        };
        const auto o = write("Top\\A\\B");
        CHECK(o.result == "refused");
        CHECK(o.reason == "concurrent_change");
        CHECK(o.created == 0);
        CHECK_FALSE(reg.exists("Decoy\\A"));
        REQUIRE(reg.get("Other\\B", "Marker") != nullptr);
        CHECK(reg.get("Other\\B", "Marker")->data == dword(0xB0));
        CHECK(reg.method_calls("delete_key_by_handle") == 1); // only the key this call created was ever deleted
    }
    SECTION("a later create finds its key inside ours: that key survives, ours is the reported residual") {
        // mutants: no roll_back() on the !created_new exit (no delete is tried); the opened-existing key pushed
        // into made_keys (its delete is tried first and succeeds)
        reg.before = [&](const std::string& ev) {
            complete_link(ev);
            if (ev == "create_sub:B") reg.put("Decoy\\A\\B", "Marker", kRegDword, dword(0xB0));
        };
        const auto o = write("Top\\A\\B");
        CHECK(o.result == "failed");
        CHECK(o.reason == "concurrent_change");
        CHECK(o.created == 1);
        CHECK(reg.exists("Decoy\\A"));
        REQUIRE(reg.get("Decoy\\A\\B", "Marker") != nullptr);
        CHECK(reg.get("Decoy\\A\\B", "Marker")->data == dword(0xB0));
        CHECK(reg.method_calls("delete_key_by_handle") == 1); // A was tried; B never was
    }
    SECTION("a legitimate partial failure under a plain parent is all-or-nothing too") {
        // mutant: no roll_back() after the failed create_sub
        reg.inject["create_sub:B"] = 5;
        const auto o = write("Top\\A\\B");
        CHECK(o.result == "refused");
        CHECK(o.reason == "access_denied");
        CHECK(o.created == 0);
        CHECK_FALSE(reg.exists("Top\\A"));
        CHECK(reg.exists("Top")); // the parent the walk found is not ours to delete
    }
    SECTION("a rollback delete that fails is reported: failed, with the residual count") {
        // mutant: --created taken whether or not the delete succeeded
        reg.before = complete_link;
        reg.inject["create_sub:B"] = 1450;
        reg.inject["delete_key_by_handle"] = 5;
        const auto o = write("Top\\A\\B");
        CHECK(o.result == "failed");
        CHECK(o.reason == "win32:1450");
        CHECK(o.created == 1);
        CHECK(reg.exists("Decoy\\A"));
        CHECK(reg.calls("set_value") == 0);
        // The residual is on the wire, where the server's audit row carries it.
        const auto line = render_single_action(AuditRecord{}, o, false).lines[0];
        CHECK(line.find("|result=failed|reason=win32:1450|") != std::string::npos);
        CHECK(line.find("|created=1|") != std::string::npos);
    }
    SECTION("the first create finds its key already there: nothing was created, nothing is deleted") {
        // mutant: the opened-existing key pushed into made_keys before the !created_new test
        reg.before = [&](const std::string& ev) {
            if (ev == "create_sub:A") reg.put("Top\\A", "Marker", kRegDword, dword(0xB0));
        };
        const auto o = write("Top\\A\\B");
        CHECK(o.result == "refused");
        CHECK(o.reason == "concurrent_change");
        CHECK(o.created == 0);
        REQUIRE(reg.get("Top\\A", "Marker") != nullptr);
        CHECK(reg.method_calls("delete_key_by_handle") == 0);
    }
    SECTION("an exception after a create rolls back and goes on: the stranded key is removed") {
        // mutant: no catch (...) { roll_back(); throw; } around the create loop and the hand-over
        reg.before = [&](const std::string& ev) {
            complete_link(ev);
            if (ev == "create_sub:B") throw std::bad_alloc{};
        };
        CHECK_THROWS_AS(write("Top\\A\\B"), std::bad_alloc);
        CHECK_FALSE(reg.exists("Decoy\\A"));
        CHECK(reg.get("Decoy", "Marker")->data == dword(0xDEC0));
        CHECK(reg.calls("set_value") == 0);
    }
    SECTION("an exception while the leaf's name is being tested also rolls back") {
        // mutant: the try block ends before hand_over()
        int names = 0;
        reg.before = [&](const std::string& ev) {
            if (ev == "final_name" && ++names == 2) throw std::bad_alloc{}; // the first is Top's, the second the leaf's
        };
        CHECK_THROWS_AS(write("Top\\A\\B"), std::bad_alloc);
        CHECK_FALSE(reg.exists("Top\\A"));
        CHECK(reg.exists("Top"));
        CHECK(reg.calls("set_value") == 0);
    }
}

// The keys a creating write makes stay owned by its Opened (the leaf included) until the verified write is over. An
// exception at any seam call from the first create to the read-back therefore deletes them again, by handle, leaf
// first, after the value the write set. The mutant each section turns red is named on its first line.
TEST_CASE("registry core: an exception after hand-over rolls back the keys and the value a creating write made",
          "[registry][core][rollback]") {
    FakeRegistry reg;
    reg.key("Software");
    const auto write = [&] {
        return set_value_verified(reg, FakeRegistry::kRoot, "Software\\New\\Deeper", "V", kRegDword, dword(3), false);
    };
    const auto nothing_left = [&] {
        CHECK_FALSE(reg.exists("Software\\New"));
        CHECK(reg.exists("Software"));
    };

    SECTION("the previous-value capture throws: both created keys are removed") {
        // mutant: the keys are released to the caller at hand-over, so only a returning exit removes them
        reg.after = [&](const std::string& ev) {
            if (ev == "query_value:V") throw std::bad_alloc{}; // the first read of V is the capture
        };
        CHECK_THROWS_AS(write(), std::bad_alloc);
        nothing_left();
        CHECK(reg.calls("set_value") == 0);
    }
    SECTION("the write throws before it lands") {
        // mutant: as above
        reg.before = [&](const std::string& ev) {
            if (ev == "set_value:V") throw std::bad_alloc{};
        };
        CHECK_THROWS_AS(write(), std::bad_alloc);
        nothing_left();
        CHECK(reg.calls("delete_value") == 0); // nothing landed, so there is no value to remove
    }
    SECTION("the read-back throws after the value landed: the value goes first, then the keys") {
        // mutant: the written value is not removed first (the leaf is then kept as holding a value)
        int reads = 0;
        reg.after = [&](const std::string& ev) {
            if (ev == "query_value:V" && ++reads == 2) throw std::bad_alloc{};
        };
        CHECK_THROWS_AS(write(), std::bad_alloc);
        nothing_left();
        CHECK(reg.calls("delete_value:V") == 1);
        CHECK(reg.method_calls("delete_key_by_handle") == 2); // the leaf, then New
    }
    SECTION("a seam call inside the rollback throws too: nothing escapes the destructor, the key stays") {
        // mutant: no try/catch around a rollback step (a throw while unwinding ends the process)
        int reads = 0;
        reg.after = [&](const std::string& ev) {
            if (ev == "query_value:V" && ++reads == 2) throw std::bad_alloc{};
        };
        reg.grow_on_enum = [](Node&) { throw std::bad_alloc{}; }; // the rollback's enum_value
        CHECK_THROWS_AS(write(), std::bad_alloc);
        CHECK(reg.exists("Software\\New\\Deeper")); // a key whose rollback step threw is kept
    }
    SECTION("the rollback's own value delete throws before it erases: nothing escapes, the value and its keys stay") {
        // mutant: no try/catch around the value delete (a throw while unwinding ends the process)
        int reads = 0;
        reg.after = [&](const std::string& ev) {
            if (ev == "query_value:V" && ++reads == 2) throw std::bad_alloc{};
        };
        reg.before = [&](const std::string& ev) {
            if (ev == "delete_value:V") throw std::bad_alloc{};
        };
        CHECK_THROWS_AS(write(), std::bad_alloc); // the read-back's, not a second one from the rollback
        CHECK(reg.calls("delete_value:V") == 1);
        REQUIRE(reg.get("Software\\New\\Deeper", "V") != nullptr); // the delete never ran
        CHECK(reg.exists("Software\\New\\Deeper")); // a key that holds a value is kept
        CHECK(reg.exists("Software\\New"));
    }
    SECTION("the rollback's own value delete throws after it erased: nothing escapes, the keys are removed") {
        // mutant: as above; and a value delete that throws must not skip the key loop
        int reads = 0;
        reg.after = [&](const std::string& ev) {
            if (ev == "query_value:V" && ++reads == 2) throw std::bad_alloc{};
            if (ev == "delete_value:V") throw std::bad_alloc{}; // V is already gone when this fires
        };
        CHECK_THROWS_AS(write(), std::bad_alloc);
        CHECK(reg.calls("delete_value:V") == 1);
        // The catch around the value delete swallows it and the loop goes on: the value is gone, so both keys are empty.
        nothing_left();
        CHECK(reg.method_calls("delete_key_by_handle") == 2);
    }
    SECTION("a write that creates nothing keeps its value when the read-back throws") {
        // mutant: the rollback owner also removes the value of a write that made no key
        reg.key("Software\\New\\Deeper");
        int reads = 0;
        reg.after = [&](const std::string& ev) {
            if (ev == "query_value:V" && ++reads == 2) throw std::bad_alloc{};
        };
        CHECK_THROWS_AS(write(), std::bad_alloc);
        REQUIRE(reg.get("Software\\New\\Deeper", "V") != nullptr);
        CHECK(reg.get("Software\\New\\Deeper", "V")->data == dword(3));
        CHECK(reg.calls("delete_") == 0);
    }
    SECTION("an ok write commits: the keys stay and the rollback never runs") {
        // mutant: commit() missing (the destructor removes what the write just made)
        const auto o = write();
        CHECK(o.result == "ok");
        CHECK(o.created == 2);
        CHECK(reg.get("Software\\New\\Deeper", "V") != nullptr);
        CHECK(reg.method_calls("delete_key_by_handle") == 0);
        CHECK(reg.method_calls("enum_value") == 0);
    }
    SECTION("a creating write that ends verify_mismatch commits too: the keys and the value stay and are reported") {
        // mutant: commit() only on an ok result (the destructor then removes what the write made)
        reg.tamper_after_set = [](Node& n, const std::string& name) { n.values[name].data[0] ^= 0xff; };
        const auto o = write();
        CHECK(o.reason == "verify_mismatch");
        CHECK(o.created == 2);
        CHECK(reg.get("Software\\New\\Deeper", "V") != nullptr);
        CHECK(reg.method_calls("delete_key_by_handle") == 0);
        CHECK(render_single_action(AuditRecord{}, o, false).lines[0].find("|created=2|") != std::string::npos);
    }
}

// roll_back kept NtDeleteKey unconditional, and NtDeleteKey removes a key that holds VALUES (only a subkey blocks
// it): a value another party wrote into a key the walk had just made was destroyed with it. The rollback now asks
// enum_value first and keeps (and counts) a key that holds anything it did not put there.
TEST_CASE("registry core: the rollback keeps a key that holds another party's value or key",
          "[registry][core][rollback]") {
    FakeRegistry reg;
    reg.key("Software");

    SECTION("a foreign value in a key the walk made: kept and reported, the failure keeps its token") {
        // mutant: NtDeleteKey is tried without the enum_value check
        reg.before = [&](const std::string& ev) {
            if (ev == "create_sub:Deeper") reg.put("Software\\New", "Foreign", kRegDword, dword(0xF0));
        };
        reg.inject["create_sub:Deeper"] = 1450;
        const auto o = set_value_verified(reg, FakeRegistry::kRoot, "Software\\New\\Deeper", "V", kRegDword, dword(3), false);
        CHECK(o.result == "failed");
        CHECK(o.reason == "win32:1450");
        CHECK(o.created == 1);
        REQUIRE(reg.get("Software\\New", "Foreign") != nullptr);
        CHECK(reg.get("Software\\New", "Foreign")->data == dword(0xF0));
        CHECK(reg.method_calls("delete_key_by_handle") == 0);
    }
    SECTION("a foreign value in the MIDDLE key after three creates: only the empty leaf goes, the rest is kept") {
        // mutant: the rollback deletes without the enum_value check (Mid would lose Foreign); or only the last key made
        // is considered. All three keys are CREATED (nothing pre-exists, so none is "opened-existing" and none is skipped
        // as somebody else's); the walk then ends on its leaf-name read, after the creates.
        reg.before = [&](const std::string& ev) {
            if (ev != "create_sub:Deeper") return;
            reg.put("Software\\New\\Mid", "Foreign", kRegDword, dword(0xF0)); // lands after New and Mid are made
            reg.inject["final_name"] = 5;                                      // the leaf-name read then fails
        };
        const auto o = set_value_verified(reg, FakeRegistry::kRoot, "Software\\New\\Mid\\Deeper", "V", kRegDword,
                                          dword(3), false);
        CHECK(o.result == "failed");
        CHECK(o.reason == "access_denied");
        CHECK(o.created == 2); // New and Mid remain; Deeper was deleted by its own handle
        CHECK_FALSE(reg.exists("Software\\New\\Mid\\Deeper"));
        REQUIRE(reg.get("Software\\New\\Mid", "Foreign") != nullptr);
        CHECK(reg.get("Software\\New\\Mid", "Foreign")->data == dword(0xF0));
        CHECK(reg.exists("Software\\New"));
        // Deeper (empty) is deleted; Mid is kept at the enum_value check without a delete call; New has no value, so a
        // delete is attempted and the key refuses it for its subkey Mid.
        CHECK(reg.method_calls("delete_key_by_handle") == 2);
        CHECK(reg.calls("set_value") == 0); // the write never ran
    }
    SECTION("a foreign value planted at the write: our value goes, theirs stays, the key is counted") {
        // mutant: as above, or the owner's own value left in place (the key is then kept as holding it)
        Opened op = open_checked(reg, FakeRegistry::kRoot, "Software\\New", kKeySetValue, true);
        REQUIRE(op.error.empty());
        REQUIRE(op.created == 1);
        op.value_name = "V";
        reg.before = [&](const std::string& ev) {
            if (ev == "set_value:V") reg.put("Software\\New", "Foreign", kRegDword, dword(0xF0));
        };
        REQUIRE(reg.set_value(op.handle(), "V", kRegDword, dword(1)) == 0);
        op.value_landed = true;
        op.rollback();
        CHECK(op.created == 1);
        CHECK(reg.get("Software\\New", "V") == nullptr);
        REQUIRE(reg.get("Software\\New", "Foreign") != nullptr);
        CHECK(reg.method_calls("delete_key_by_handle") == 0);
        op.rollback(); // idempotent
        CHECK(op.created == 1);
    }
    SECTION("a key whose values cannot be listed is kept: absence of a value is never assumed") {
        // mutant: any enum_value result but "a value exists" lets the delete go ahead
        Opened op = open_checked(reg, FakeRegistry::kRoot, "Software\\New", kKeySetValue, true);
        REQUIRE(op.created == 1);
        reg.inject["enum_value"] = 5;
        op.rollback();
        CHECK(op.created == 1);
        CHECK(reg.exists("Software\\New"));
        CHECK(reg.method_calls("delete_key_by_handle") == 0);
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
        CHECK(o.has_old); // the audit line carries what was deleted
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
        CHECK(o.has_old); // refused, but the audit line still says the value was absent
        CHECK(o.old.state == OldState::absent);
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
        // DELETE | KEY_ENUMERATE_SUB_KEYS | KEY_QUERY_VALUE: nothing on this path sets a value, so no KEY_SET_VALUE.
        REQUIRE_FALSE(reg.masks.empty());
        CHECK(reg.masks.back().ends_with(":0x10009"));
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
    SECTION("a subkey enumeration that fails is a refusal with its token; nothing is deleted") {
        // mutant: the enum_subkey result other than "found one" / "none" is ignored (the counts are then wrong)
        reg.inject["enum_subkey"] = 5;
        const auto o = delete_key_tree(reg, FakeRegistry::kRoot, "T\\C2", fast);
        CHECK(o.result == "refused");
        CHECK(o.reason == "access_denied");
        CHECK(reg.exists("T\\C2"));
        CHECK(reg.calls("delete_key_by_handle") == 0);
        // refused before any value was counted: nothing to report (README audit grammar, counted_values)
        CHECK(o.counted_keys == 0);
        CHECK(o.counted_values == 0);
        CHECK_FALSE(o.capped);
        CHECK(render_single_action(AuditRecord{}, o, true).lines[0].find("|counted_keys=0|counted_values=0|capped=0|") !=
              std::string::npos);
    }
    SECTION("a value enumeration that fails is a refusal with its token; nothing is deleted") {
        // mutant: a failed enum_value ends the count as if the values were all listed (capped=0, counts under-reported)
        reg.inject["enum_value"] = 1450;
        const auto o = delete_key_tree(reg, FakeRegistry::kRoot, "T\\C1\\G1", fast);
        CHECK(o.result == "refused");
        CHECK(o.reason == "win32:1450");
        CHECK_FALSE(o.capped);
        CHECK(reg.exists("T\\C1\\G1"));
        CHECK(reg.calls("delete_key_by_handle") == 0);
        CHECK(o.counted_keys == 1); // the failure came on the first enumeration call: the key only
        CHECK(o.counted_values == 0);
    }
    SECTION("a value enumeration that fails after two values reports the partial count") {
        // mutant: the counts are zeroed (or not recorded) on a failed enumeration
        // G1 holds g1 and g2; the third enum_value call (the one that would answer "no more") fails.
        int calls = 0;
        reg.grow_on_enum = [&](Node&) {
            if (++calls == 2) reg.inject["enum_value"] = 1450; // consumed by the next call
        };
        const auto o = delete_key_tree(reg, FakeRegistry::kRoot, "T\\C1\\G1", fast);
        CHECK(o.result == "refused");
        CHECK(o.reason == "win32:1450");
        CHECK(o.counted_keys == 1);
        CHECK(o.counted_values == 2);
        CHECK_FALSE(o.capped);
        CHECK(reg.exists("T\\C1\\G1"));
        CHECK(reg.calls("delete_key_by_handle") == 0);
        CHECK(render_single_action(AuditRecord{}, o, true).lines[0].find("|counted_keys=1|counted_values=2|capped=0|") !=
              std::string::npos);
    }
    SECTION("NtDeleteKey denied: the delete fails access_denied and the key stays") {
        reg.key("T\\C2")->deny_delete_key = true;
        const auto o = delete_key_tree(reg, FakeRegistry::kRoot, "T\\C2", fast);
        CHECK(o.result == "failed");
        CHECK(o.reason == "access_denied");
        CHECK(reg.exists("T\\C2"));
    }
}

// ── the guarded value read ───────────────────────────────────────────────

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
    /// Every call carried real storage of at least one byte (never a null lpData, #2771 P2-N5).
    [[nodiscard]] bool every_call_had_storage() const {
        return std::all_of(calls.begin(), calls.end(), [](const auto& c) { return c.first && c.second >= 1; });
    }
};

/// n bytes, 1, 2, 3 ... (wrapping), so a short copy or a stale buffer shows.
[[nodiscard]] Bytes ramp(std::size_t n) {
    Bytes b(n);
    for (std::size_t i = 0; i < n; ++i) b[i] = static_cast<std::uint8_t>(i + 1);
    return b;
}

} // namespace

TEST_CASE("registry core: query_value_bounded reads a value that fits the first buffer in one data call",
          "[registry][core][query]") {
    // The first data call has 256 bytes of stack storage: the usual value costs ONE Win32 call, not a size
    // query and a read. A value over 256 bytes answers ERROR_MORE_DATA with its size and is read once more.
    SECTION("a small value: one call, with storage") {
        QueryModel m;
        m.type = kRegDword;
        m.value = B({1, 2, 3, 4});
        QueryResult q;
        CHECK(query_value_bounded(4096, std::ref(m), q) == 0);
        CHECK(q.type == kRegDword);
        CHECK(q.size == 4);
        CHECK(q.bytes == B({1, 2, 3, 4}));
        REQUIRE(m.calls.size() == 1);
        CHECK(m.every_call_had_storage());
        CHECK(m.calls[0].second == 256);
    }
    SECTION("exactly 256 bytes still fits: one call") {
        QueryModel m;
        m.value = ramp(256);
        QueryResult q;
        CHECK(query_value_bounded(4096, std::ref(m), q) == 0);
        CHECK(q.size == 256);
        CHECK(q.bytes == ramp(256));
        CHECK(m.calls.size() == 1);
    }
    SECTION("257 bytes does not: MORE_DATA, then one read with exactly the room it reported") {
        QueryModel m;
        m.value = ramp(257);
        QueryResult q;
        CHECK(query_value_bounded(4096, std::ref(m), q) == 0);
        CHECK(q.type == kRegBinary);
        CHECK(q.size == 257);
        CHECK(q.bytes == ramp(257));
        REQUIRE(m.calls.size() == 2);
        CHECK(m.every_call_had_storage());
        CHECK(m.calls[1].second == 257); // no separate size query in between
    }
    SECTION("a zero-length value: one call, the type and size survive, no bytes, no loop") {
        QueryModel m;
        m.type = kRegSz;
        QueryResult q;
        CHECK(query_value_bounded(4096, std::ref(m), q) == 0);
        CHECK(q.type == kRegSz);
        CHECK(q.size == 0);
        CHECK(q.bytes.empty());
        CHECK(m.calls.size() == 1);
        CHECK(m.every_call_had_storage());
    }
}

TEST_CASE("registry core: query_value_bounded honours the cap and the size bound", "[registry][core][query]") {
    SECTION("a cap smaller than a value that fits the first buffer cuts the bytes, the size stays full") {
        QueryModel m;
        m.value = B({1, 2, 3, 4, 5, 6});
        QueryResult q;
        CHECK(query_value_bounded(4, std::ref(m), q) == 0);
        CHECK(q.size == 6);
        CHECK(q.bytes == B({1, 2, 3, 4}));
        CHECK(m.calls.size() == 1);
    }
    SECTION("a cap smaller than a value past the first buffer does the same") {
        QueryModel m;
        m.value = ramp(300);
        QueryResult q;
        CHECK(query_value_bounded(4, std::ref(m), q) == 0);
        CHECK(q.size == 300);
        CHECK(q.bytes == B({1, 2, 3, 4}));
        CHECK(m.calls.size() == 2);
    }
    SECTION("cap 0 asks for the size only: one null-data call, no bytes") {
        for (const std::size_t n : {std::size_t{3}, std::size_t{300}}) {
            QueryModel m;
            m.value = ramp(n);
            QueryResult q;
            CHECK(query_value_bounded(0, std::ref(m), q) == 0);
            CHECK(q.size == n);
            CHECK(q.bytes.empty());
            REQUIRE(m.calls.size() == 1);
            CHECK_FALSE(m.calls[0].first);
        }
    }
    SECTION("max_read below a value that fits the first buffer: size only, no bytes") {
        QueryModel m;
        m.value = ramp(8);
        QueryResult q;
        CHECK(query_value_bounded(4096, std::ref(m), q, /*max_read=*/4) == 0);
        CHECK(q.size == 8);
        CHECK(q.bytes.empty());
        CHECK(m.calls.size() == 1);
    }
    SECTION("max_read is inclusive: a value of exactly max_read is read, one byte more is size-only") {
        // mutant: `size > max_read` becomes `size >= max_read` (or the reverse) on either path
        for (const std::size_t limit : {std::size_t{8}, std::size_t{300}}) { // the first-buffer path, then past it
            QueryModel at;
            at.value = ramp(limit);
            QueryResult q;
            CHECK(query_value_bounded(4096, std::ref(at), q, limit) == 0);
            CHECK(q.size == limit);
            CHECK(q.bytes == ramp(limit));
            QueryModel over;
            over.value = ramp(limit + 1);
            QueryResult r;
            CHECK(query_value_bounded(4096, std::ref(over), r, limit) == 0);
            CHECK(r.size == limit + 1);
            CHECK(r.bytes.empty());
        }
    }
    SECTION("a value above kMaxWriteBytes is answered size-only without ever reading it") {
        QueryModel m;
        m.script = [](std::size_t, std::uint32_t* t, std::uint8_t* data, std::uint32_t* size) -> std::optional<long> {
            *t = kRegBinary;
            *size = static_cast<std::uint32_t>(kMaxWriteBytes + 1);
            return data != nullptr ? 234 : 0; // too big for any buffer it was given; the null-data call says the size
        };
        QueryResult q;
        CHECK(query_value_bounded(4096, std::ref(m), q) == 0);
        CHECK(q.type == kRegBinary);
        CHECK(q.size == kMaxWriteBytes + 1);
        CHECK(q.bytes.empty());
        REQUIRE(m.calls.size() == 2); // the data call, then the size-only question that also yields the type
        CHECK(m.calls[0].second == 256);
        CHECK_FALSE(m.calls[1].first);
    }
}

TEST_CASE("registry core: query_value_bounded reads a value that grows between its calls",
          "[registry][core][query]") {
    SECTION("past the first buffer, then bigger again: one MORE_DATA retry") {
        QueryModel m;
        m.value = ramp(300);
        m.after = [&](std::size_t n) {
            if (n == 0) m.value = ramp(500);
        };
        QueryResult q;
        CHECK(query_value_bounded(4096, std::ref(m), q) == 0);
        CHECK(q.size == 500);
        CHECK(q.bytes == ramp(500));
        CHECK(m.calls.size() == 3); // 256 -> MORE_DATA(300); 300 -> MORE_DATA(500); 500 -> ok
        CHECK(m.every_call_had_storage());
    }
    SECTION("past the bound mid-read is answered size-only") {
        QueryModel m;
        m.value = ramp(300);
        m.after = [&](std::size_t n) {
            if (n == 0) m.value = ramp(400);
        };
        QueryResult q;
        CHECK(query_value_bounded(4096, std::ref(m), q, /*max_read=*/350) == 0);
        CHECK(q.size == 400);
        CHECK(q.bytes.empty());
        CHECK(m.calls.size() == 2);
    }
    SECTION("a value that keeps growing: three retries, then ERROR_MORE_DATA") {
        QueryModel m;
        m.value = ramp(300);
        m.after = [&](std::size_t) { m.value.push_back(0); }; // grows after every call
        QueryResult q;
        CHECK(query_value_bounded(4096, std::ref(m), q) == 234);
        CHECK(m.calls.size() == 4); // the first data call and three sized reads
    }
}

TEST_CASE("registry core: query_value_bounded passes failures through", "[registry][core][query]") {
    QueryResult q;
    SECTION("an absent value") {
        QueryModel absent;
        absent.absent = true;
        CHECK(query_value_bounded(4096, std::ref(absent), q) == 2);
        CHECK(absent.calls.size() == 1);
    }
    SECTION("a failing first data call") {
        QueryModel denied;
        denied.value = B({1});
        denied.script = [](std::size_t, std::uint32_t*, std::uint8_t*, std::uint32_t*) -> std::optional<long> { return 5; };
        CHECK(query_value_bounded(4096, std::ref(denied), q) == 5);
        CHECK(denied.calls.size() == 1);
    }
    SECTION("a failing sized read") {
        QueryModel denied;
        denied.value = ramp(300);
        denied.script = [](std::size_t n, std::uint32_t*, std::uint8_t*, std::uint32_t*) -> std::optional<long> {
            return n == 1 ? std::optional<long>{5} : std::nullopt;
        };
        CHECK(query_value_bounded(4096, std::ref(denied), q) == 5);
        CHECK(denied.calls.size() == 2);
    }
    SECTION("a failing size-only question") {
        QueryModel gone;
        gone.script = [](std::size_t n, std::uint32_t* t, std::uint8_t*, std::uint32_t* size) -> std::optional<long> {
            *t = kRegBinary;
            *size = static_cast<std::uint32_t>(kMaxWriteBytes + 1);
            return n == 0 ? 234 : 2; // too big, then gone before the size could be read
        };
        CHECK(query_value_bounded(4096, std::ref(gone), q) == 2);
        CHECK(gone.calls.size() == 2);
    }
}

TEST_CASE("registry core: query_value_bounded never forms a copy range from a count the buffer cannot hold",
          "[registry][core][query]") {
    SECTION("a SUCCESS on the first call that reports more bytes than the 256-byte buffer is read again with room") {
        QueryModel m;
        m.value = ramp(300);
        m.script = [&](std::size_t n, std::uint32_t* t, std::uint8_t* data, std::uint32_t* size) -> std::optional<long> {
            if (n != 0) return std::nullopt;
            *t = kRegBinary;
            *size = 300; // claims 300 although it was given room for 256
            data[0] = 0xEE;
            return 0;
        };
        QueryResult q;
        CHECK(query_value_bounded(4096, std::ref(m), q) == 0);
        CHECK(q.size == 300);
        CHECK(q.bytes == ramp(300)); // none of it is the 0xEE the lying call left behind
        CHECK(m.calls.size() == 2);
        CHECK(m.calls[1].second == 300);
    }
    SECTION("a SUCCESS count past max_read is answered size-only, as MORE_DATA is: the ceiling holds on both arms") {
        QueryModel m;
        m.value = ramp(300);
        m.script = [&](std::size_t n, std::uint32_t* t, std::uint8_t* data, std::uint32_t* size) -> std::optional<long> {
            if (n != 1) return std::nullopt;
            *t = kRegBinary;
            *size = 500; // the sized read was given room for 300; the ceiling is 350
            data[0] = 0xEE;
            return 0;
        };
        QueryResult q;
        CHECK(query_value_bounded(4096, std::ref(m), q, /*max_read=*/350) == 0);
        CHECK(q.size == 500);
        CHECK(q.bytes.empty());
        CHECK(m.calls.size() == 2); // no retry with a buffer sized by the lie
    }
    SECTION("a SUCCESS on a sized read that reports more bytes than it was given room for is retried with room") {
        QueryModel m;
        m.value = ramp(300);
        m.script = [&](std::size_t n, std::uint32_t* t, std::uint8_t* data, std::uint32_t* size) -> std::optional<long> {
            if (n != 1) return std::nullopt;
            *t = kRegBinary;
            *size = 400; // the sized read was given room for 300
            data[0] = 0xEE;
            return 0;
        };
        m.after = [&](std::size_t n) {
            if (n == 1) m.value = ramp(400);
        };
        QueryResult q;
        CHECK(query_value_bounded(4096, std::ref(m), q) == 0);
        CHECK(q.size == 400);
        CHECK(q.bytes == ramp(400));
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

// ── the ABI-seam catch ───────────────────────────────────────────────────

namespace {

/// A CommandContext stand-in for report_exception: records every line, and throws on the ones `fails` names.
struct RecordingCtx {
    std::vector<std::string> lines;
    std::function<bool(std::string_view)> fails;
    void write_output(std::string_view text) {
        if (fails && fails(text)) throw std::bad_alloc{};
        lines.emplace_back(text);
    }
};

} // namespace

TEST_CASE("registry core: report_exception leaves a mutator's fixed audit line, then error|exception",
          "[registry][core][exception]") {
    SECTION("each mutating action: its literal first, so the server mints a failed registry.write row") {
        // mutant: the audit line is not written, or is written after error|exception
        for (const std::string_view action : {"set_value", "delete_value", "delete_key"}) {
            INFO(action);
            RecordingCtx ctx;
            report_exception(ctx, action);
            REQUIRE(ctx.lines.size() == 2);
            CHECK(ctx.lines[0] == exception_audit_line(action));
            CHECK(ctx.lines[0].rfind("audit|op=", 0) == 0);
            CHECK(ctx.lines[0].find("|result=failed|reason=exception|") != std::string::npos);
            CHECK(ctx.lines[1] == "error|exception");
        }
    }
    SECTION("a read action and an unknown one: only error|exception, no audit row") {
        for (const std::string_view action : {"get_value", "list_profiles", "__nope", ""}) {
            INFO(action);
            RecordingCtx ctx;
            report_exception(ctx, action);
            REQUIRE(ctx.lines.size() == 1);
            CHECK(ctx.lines[0] == "error|exception");
        }
    }
    SECTION("an allocation failure on the error line leaves the audit literal alone, and nothing escapes") {
        // mutant: no try/catch around the second write (the failure escapes the ABI seam)
        RecordingCtx ctx;
        ctx.fails = [](std::string_view t) { return t == "error|exception"; };
        CHECK_NOTHROW(report_exception(ctx, "set_value"));
        REQUIRE(ctx.lines.size() == 1);
        CHECK(ctx.lines[0] == exception_audit_line("set_value"));
    }
    SECTION("an allocation failure on the audit line cannot suppress error|exception, and nothing escapes") {
        RecordingCtx ctx;
        ctx.fails = [](std::string_view t) { return t.rfind("audit|", 0) == 0; };
        CHECK_NOTHROW(report_exception(ctx, "set_value"));
        REQUIRE(ctx.lines.size() == 1);
        CHECK(ctx.lines[0] == "error|exception");
    }
}

namespace {

/// The ABI seam's shape (registry_win.cpp execute_guarded): emit the action's lines; whatever escapes goes to
/// report_exception.
int seam_emit(RecordingCtx& ctx, std::string_view action, const ActionOutput& out) {
    try {
        return emit_lines(ctx, out);
    } catch (...) {
        report_exception(ctx, action);
        return 1;
    }
}

std::size_t audit_line_count(const RecordingCtx& ctx) {
    return static_cast<std::size_t>(std::ranges::count_if(
        ctx.lines, [](const std::string& l) { return l.rfind("audit|", 0) == 0; }));
}

} // namespace

TEST_CASE("registry core: a sink failure after the real audit line adds no second audit line",
          "[registry][core][exception]") {
    FakeRegistry reg;
    reg.key("K");
    const auto ok = render_single_action(AuditRecord{}, delete_key_tree(reg, FakeRegistry::kRoot, "K"), true);
    REQUIRE(ok.lines.size() == 6);
    REQUIRE(ok.lines[0].rfind("audit|", 0) == 0);
    const auto missing = render_single_action(AuditRecord{}, delete_key_tree(reg, FakeRegistry::kRoot, "Gone"), true);
    REQUIRE(missing.lines.size() == 2);
    REQUIRE(missing.rc == 1);

    SECTION("no failure: the lines go out as rendered") {
        RecordingCtx ctx;
        CHECK(seam_emit(ctx, "delete_key", ok) == ok.rc);
        CHECK(ctx.lines == ok.lines);
    }
    SECTION("the sink fails on any line after the audit line: exactly one audit line, the real one") {
        // mutant: emit_lines rethrows after the audit line went out, so report_exception adds the fixed line
        const auto bad = GENERATE(1, 2, 3, 4, 5);
        INFO("failing line index " << bad);
        RecordingCtx ctx;
        ctx.fails = [&ok, bad](std::string_view t) { return t == ok.lines[static_cast<std::size_t>(bad)]; };
        CHECK(seam_emit(ctx, "delete_key", ok) == 1);
        CHECK(audit_line_count(ctx) == 1);
        REQUIRE_FALSE(ctx.lines.empty());
        CHECK(ctx.lines[0] == ok.lines[0]);
        CHECK(ctx.lines.back() == "error|exception");
        CHECK(std::ranges::find(ctx.lines, std::string{exception_audit_line("delete_key")}) == ctx.lines.end());
    }
    SECTION("a refused action whose error line fails: still one audit line") {
        RecordingCtx ctx;
        ctx.fails = [&missing](std::string_view t) { return t == missing.lines[1]; };
        CHECK(seam_emit(ctx, "delete_key", missing) == 1);
        CHECK(audit_line_count(ctx) == 1);
        CHECK(ctx.lines[0] == missing.lines[0]);
        CHECK(ctx.lines.back() == "error|exception");
    }
    SECTION("the sink fails before any audit line went out: the fixed failed line is left, once") {
        RecordingCtx ctx;
        ctx.fails = [n = 0](std::string_view) mutable { return n++ == 0; };
        CHECK(seam_emit(ctx, "delete_key", ok) == 1);
        REQUIRE(ctx.lines.size() == 2);
        CHECK(ctx.lines[0] == exception_audit_line("delete_key"));
        CHECK(ctx.lines[1] == "error|exception");
        CHECK(audit_line_count(ctx) == 1);
    }
}

// ── previous-value capture ───────────────────────────────────────────────

TEST_CASE("registry core: capture_old keeps kCaptureValueCap bytes of a bigger value and the full size on the audit "
          "line",
          "[registry][core]") {
    FakeRegistry reg;
    Bytes big(5000);
    for (std::size_t i = 0; i < big.size(); ++i) big[i] = static_cast<std::uint8_t>(i % 251);
    reg.put("A", "Big", kRegBinary, big);
    Handle h = 0;
    REQUIRE(reg.open_sub(FakeRegistry::kRoot, "A", kKeyQueryValue, h) == 0);
    const Owned owner{reg, h};

    const OldValue old = capture_old(reg, owner.get(), "Big");
    CHECK(old.state == OldState::present);
    CHECK(old.type == kRegBinary);
    CHECK(old.bytes.size() == kCaptureValueCap);
    CHECK(old.total == 5000);
    CHECK(std::equal(old.bytes.begin(), old.bytes.end(), big.begin()));

    // Through the real capture, not a hand-built record: fill_old copies it, and the line shows the first
    // kAuditHexCapBytes (256) of it, then ~<the full size>.
    AuditRecord au;
    au.op = "set_value";
    fill_old(au, old);
    CHECK(au.old_total == 5000);
    const std::string want =
        "|old=" + yuzu::profiles::hex_encode(std::span<const std::uint8_t>{big}.first(kAuditHexCapBytes)) + "~5000|new=-";
    CHECK(render_audit_line(au).ends_with(want));
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
    // a name is never equated with itself plus a NUL, in either order (the kernel name carries the NUL, the
    // requested one does not, and the reverse)
    CHECK_FALSE(names_equal_ascii_ci("L", std::string_view{"L\0", 2}));
    CHECK_FALSE(names_equal_ascii_ci(std::string_view{"L\0", 2}, "L"));
    // U+FFFD on the requested side: equal only to the same bytes, never to the plain name
    CHECK(names_equal_ascii_ci("L\xEF\xBF\xBD", "L\xEF\xBF\xBD"));
    CHECK_FALSE(names_equal_ascii_ci("L\xEF\xBF\xBD", "L"));
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
    // Seam calls, not Win32 calls: the probe, the capture and the read-back are each ONE RegQueryValueExW for a
    // value that fits query_value_bounded's first buffer, so a fast set_value is about seven Win32 calls. Counted
    // across the whole seam, the fast path is root_name + open_path + final_name + probe + capture + set +
    // read-back + close, whatever the depth; the walk it replaces grows with every component.
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
            } else {
                // The walk's name test costs two final_name calls whatever the depth: the first component's and the
                // leaf's (a depth-1 path reads the same handle twice).
                CHECK(reg.method_calls("open_path") == 0);
                CHECK(reg.method_calls("final_name") == 2);
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
        CHECK(reg.method_calls("final_name") == 2); // the walk's own name test, none from the fast open
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
        CHECK(reg.method_calls("final_name") == 2); // the walk names its own handles; the root needs no name
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

// ═════════════════════════════════════════════════════════════════════════
// registry 2.1.0: recursive delete_key, flush, per-user write output, apply
// ═════════════════════════════════════════════════════════════════════════

namespace {

/// Every key and value of the fake as one string: the registry's state, for "changed nothing" and "restored exactly".
void dump_node(const Node& n, const std::string& path, std::string& out) {
    for (const auto& [name, v] : n.values)
        out += path + "|" + name + "|" + std::to_string(v.type) + "|" + yuzu::profiles::hex_encode(v.data) + "\n";
    for (const auto& [name, k] : n.subkeys) {
        const std::string p = path.empty() ? name : path + "\\" + name;
        out += p + "/\n"; // the key itself, so an empty key is part of the state
        dump_node(*k, p, out);
    }
}
std::string dump(const FakeRegistry& reg) {
    std::string out;
    dump_node(*reg.root, "", out);
    return out;
}

std::vector<std::string> cells(const std::string& line) {
    std::vector<std::string> out;
    std::size_t pos = 0;
    for (;;) {
        const auto bar = line.find('|', pos);
        out.push_back(line.substr(pos, bar == std::string::npos ? std::string::npos : bar - pos));
        if (bar == std::string::npos) return out;
        pos = bar + 1;
    }
}

/// A chain D\k\k\k... with `below` keys under D.
void make_chain(FakeRegistry& reg, unsigned below) {
    NodeP cur = reg.key("D");
    for (unsigned i = 0; i < below; ++i) {
        auto n = std::make_shared<Node>();
        cur->subkeys["k"] = n;
        cur = n;
    }
}

constexpr const char* kDeleteMask = ":0x10009"; // DELETE | KEY_ENUMERATE_SUB_KEYS | KEY_QUERY_VALUE

/// The DELETE-phase open of a child. The vet and the delete walk ask for the same mask (so a child that denies DELETE
/// refuses at the vet), so within one delete_key_tree call the delete walk's open of a child is its SECOND open_sub.
struct SecondOpen {
    std::map<std::string, int> seen;
    bool operator()(const std::string& ev) { return ev.starts_with("open_sub:") && ++seen[ev] == 2; }
};

} // namespace

TEST_CASE("registry core: recursive delete_key dry run counts what a real run removes and deletes nothing",
          "[registry][core][recursive]") {
    const bool fast = GENERATE(false, true);
    FakeRegistry reg;
    build_tree(reg); // T (2 values), C1 (1), G1 (2), C2: 4 keys, 5 values
    const std::string before = dump(reg);
    const auto dry = delete_key_tree(reg, FakeRegistry::kRoot, "T", fast, /*recursive=*/true, /*dry_run=*/true);
    CHECK(dry.result == "ok");
    CHECK(dry.dry_run);
    CHECK(dry.counted_keys == 4);
    CHECK(dry.counted_values == 5);
    CHECK_FALSE(dry.capped);
    CHECK(dump(reg) == before);
    CHECK(reg.calls("delete_key_by_handle") == 0);
    // the vet asks for the delete walk's DELETE | QUERY | ENUM on every child (the target's own open, by the walk, is
    // open_checked's), and the audit line and rows say it was a dry run
    std::size_t vet_opens = 0;
    for (const auto& m : reg.masks)
        if (m.starts_with("open_sub:") && !m.starts_with("open_sub:T:")) {
            CHECK(m.ends_with(kDeleteMask));
            ++vet_opens;
        }
    CHECK(vet_opens == 3); // C1, G1, C2
    const auto rendered = render_single_action(AuditRecord{}, dry, true);
    REQUIRE(rendered.lines.size() == 6);
    CHECK(rendered.lines[0].find("|dry_run=1|counted_keys=4|counted_values=5|capped=0|") != std::string::npos);
    CHECK(rendered.lines[1] == "status|ok");
    CHECK(rendered.lines[4] == "dry_run|1");

    reg.masks.clear();
    const auto real = delete_key_tree(reg, FakeRegistry::kRoot, "T", fast, true, false);
    CHECK(real.result == "ok");
    CHECK(real.verify == "ok");
    CHECK_FALSE(real.dry_run);
    CHECK(real.counted_keys == dry.counted_keys);
    CHECK(real.counted_values == dry.counted_values);
    CHECK_FALSE(reg.exists("T"));
    CHECK(reg.exists("Keep"));
    CHECK(reg.calls("delete_key_by_handle") == 4);
    // every child the delete walk opened asked for DELETE | QUERY | ENUM (the fake enforces the masks)
    std::size_t delete_opens = 0;
    for (const auto& m : reg.masks)
        if (m.starts_with("open_sub:") && !m.starts_with("open_sub:T:") && m.ends_with(kDeleteMask)) ++delete_opens;
    CHECK(delete_opens == 6); // C1, G1, C2, by the vet and again by the delete walk: the target is open_checked's
    CHECK(render_single_action(AuditRecord{}, real, true).lines[4] == "dry_run|0");
}

TEST_CASE("registry core: a non-recursive dry run counts a leaf and refuses a key with subkeys deleting nothing",
          "[registry][core][recursive]") {
    FakeRegistry reg;
    build_tree(reg);
    const auto leaf = delete_key_tree(reg, FakeRegistry::kRoot, "T\\C1\\G1", false, /*recursive=*/false, /*dry_run=*/true);
    CHECK(leaf.result == "ok");
    CHECK(leaf.dry_run);
    CHECK(leaf.counted_keys == 1);
    CHECK(leaf.counted_values == 2);
    CHECK(reg.exists("T\\C1\\G1"));
    const auto top = delete_key_tree(reg, FakeRegistry::kRoot, "T", false, false, true);
    CHECK(top.result == "refused");
    CHECK(top.reason == "key_has_subkeys");
    CHECK(top.dry_run);
    // the default arguments are the 2.0.x behaviour: no recursion, a real delete
    const auto plain = delete_key_tree(reg, FakeRegistry::kRoot, "T\\C1\\G1");
    CHECK(plain.result == "ok");
    CHECK_FALSE(plain.dry_run);
    CHECK_FALSE(reg.exists("T\\C1\\G1"));
}

TEST_CASE("registry core: a link inside the tree is refused by the vet and nothing is deleted",
          "[registry][core][recursive]") {
    const bool fast = GENERATE(false, true);
    const bool dry = GENERATE(false, true);
    FakeRegistry reg;
    build_tree(reg);
    reg.put("Real", "keep", kRegDword, dword(7));
    reg.link("T\\C1\\L", "Real");
    const std::string before = dump(reg);
    const auto o = delete_key_tree(reg, FakeRegistry::kRoot, "T", fast, true, dry);
    CHECK(o.result == "refused");
    CHECK(o.reason == "key_is_link");
    CHECK(reg.calls("delete_key_by_handle") == 0);
    CHECK(dump(reg) == before); // the link, its target and every sibling are untouched
    CHECK(reg.get("Real", "keep")->data == dword(7));
}

// A child key whose RAW name is a lone surrogate (L"K\xD800") enumerates lossily as "K<U+FFFD>", which opens its
// well-formed sibling L"K\xFFFD" instead: the vet would count that sibling twice, and the delete would remove it and
// then stop on a child it cannot open. The exact enumeration refuses the whole call before anything is deleted.
TEST_CASE("registry core: a child whose raw key name is not well-formed UTF-16 refuses the recursive delete",
          "[registry][core][recursive]") {
    const bool fast = GENERATE(false, true);
    FakeRegistry reg;
    const auto lone_child = [&reg] { reg.key("T\\K\xED\xA0\x80")->enum_as = "K\xEF\xBF\xBD"; };
    SECTION("found by the vet: refused unrepresentable_name, in a dry run and a real run, nothing deleted") {
        // mutant: count_tree enumerates its children lossily
        const bool dry = GENERATE(false, true);
        reg.put("T\\K\xED\xA0\x80", "a", kRegDword, dword(1));
        reg.put("T\\K\xEF\xBF\xBD", "b", kRegDword, dword(2));
        lone_child();
        const std::string before = dump(reg);
        const auto o = delete_key_tree(reg, FakeRegistry::kRoot, "T", fast, true, dry);
        CHECK(o.result == "refused");
        CHECK(o.reason == "unrepresentable_name");
        CHECK(reg.calls("delete_key_by_handle") == 0);
        CHECK(dump(reg) == before);
    }
    SECTION("appearing after the vet: the delete walk stops on it with the same token, the key stays") {
        // mutant: delete_subtree enumerates its children lossily (it then answers key_not_found)
        reg.put("T\\A", "a", kRegDword, dword(1));
        reg.before = [&lone_child, second = SecondOpen{}](const std::string& ev) mutable {
            if (ev == "open_sub:A" && second(ev)) lone_child();
        };
        const auto o = delete_key_tree(reg, FakeRegistry::kRoot, "T", fast, true, false);
        CHECK(o.result == "failed");
        CHECK(o.reason == "unrepresentable_name");
        CHECK_FALSE(reg.exists("T\\A"));
        CHECK(reg.exists("T\\K\xED\xA0\x80"));
        CHECK(reg.exists("T"));
    }
}

TEST_CASE("registry core: a link planted after the vet stops the delete and is never followed",
          "[registry][core][recursive]") {
    FakeRegistry reg;
    reg.put("T\\A", "a", kRegDword, dword(1));
    reg.put("T\\Z", "z", kRegDword, dword(2));
    reg.put("Real", "keep", kRegDword, dword(7));
    const auto plant_at = [&](const std::string& name) {
        // the DELETE-phase open of `name`
        reg.before = [&reg, name, second = SecondOpen{}](const std::string& ev) mutable {
            if (ev == "open_sub:" + name && second(ev)) reg.link("T\\" + name, "Real");
        };
    };
    SECTION("after one key was removed: failed, the partial truth is counted") {
        // mutant: delete_subtree does not re-probe a child it finds at delete time
        plant_at("Z");
        const auto o = delete_key_tree(reg, FakeRegistry::kRoot, "T", false, true, false);
        CHECK(o.result == "failed");
        CHECK(o.reason == "key_is_link");
        CHECK(o.mutated);
        CHECK(o.counted_keys == 1);
        CHECK(o.counted_values == 1);
        CHECK_FALSE(reg.exists("T\\A"));
        CHECK(reg.exists("T\\Z"));
        CHECK(reg.exists("T"));
        CHECK(reg.calls("delete_key_by_handle") == 1);
        CHECK(reg.get("Real", "keep")->data == dword(7));
    }
    SECTION("before anything was removed: refused, nothing counted") {
        plant_at("A");
        const auto o = delete_key_tree(reg, FakeRegistry::kRoot, "T", false, true, false);
        CHECK(o.result == "refused");
        CHECK(o.reason == "key_is_link");
        CHECK_FALSE(o.mutated);
        CHECK(o.counted_keys == 0);
        CHECK(reg.calls("delete_key_by_handle") == 0);
        CHECK(reg.exists("T\\A"));
    }
}

TEST_CASE("registry core: a key added after the vet is deleted and counted like any other",
          "[registry][core][recursive]") {
    // The vet is a size bound and a link sweep, not a membership list: the operator named the tree, and a child that
    // appeared under it since is under it still.
    FakeRegistry reg;
    reg.put("T\\A", "a", kRegDword, dword(1));
    reg.put("T\\Z", "z", kRegDword, dword(2));
    const auto dry = delete_key_tree(reg, FakeRegistry::kRoot, "T", false, true, true);
    REQUIRE(dry.ok());
    CHECK(dry.counted_keys == 3);
    bool planted = false;
    SecondOpen second;
    reg.before = [&](const std::string& ev) {
        if (!planted && ev != "open_sub:T" && second(ev)) {
            planted = true;
            reg.put("T\\New", "n1", kRegDword, dword(3));
            reg.put("T\\New\\Deep", "n2", kRegDword, dword(4));
        }
    };
    const auto o = delete_key_tree(reg, FakeRegistry::kRoot, "T", false, true, false);
    CHECK(planted);
    CHECK(o.result == "ok");
    CHECK(o.verify == "ok");
    CHECK(o.counted_keys == 5);   // T, A, Z, New, Deep: what was REMOVED, more than the dry run saw
    CHECK(o.counted_values == 4);
    CHECK(o.counted_keys > dry.counted_keys);
    CHECK_FALSE(reg.exists("T"));
}

TEST_CASE("registry core: a tree past the node or depth bound is capped and a real delete of it is refused",
          "[registry][core][recursive]") {
    const bool fast = GENERATE(false, true);
    SECTION("more nodes than kMaxTreeNodes") {
        FakeRegistry reg;
        reg.key("Top");
        for (std::size_t i = 0; i < kMaxTreeNodes + 5; ++i) reg.put("Top\\Big", "v" + std::to_string(i), kRegDword, dword(1));
        const auto dry = delete_key_tree(reg, FakeRegistry::kRoot, "Top\\Big", fast, true, true);
        CHECK(dry.result == "ok");
        CHECK(dry.capped);
        CHECK(dry.counted_values == kMaxTreeNodes - 1); // a lower bound
        const auto real = delete_key_tree(reg, FakeRegistry::kRoot, "Top\\Big", fast, true, false);
        // mutant: the tree_too_large refusal is dropped and the capped tree is deleted
        CHECK(real.result == "refused");
        CHECK(real.reason == "tree_too_large");
        CHECK(real.capped);
        CHECK(reg.calls("delete_key_by_handle") == 0);
        CHECK(reg.exists("Top\\Big"));
        const auto rendered = render_single_action(AuditRecord{}, dry, true);
        CHECK(rendered.lines[5] == "capped|1");
    }
    SECTION("keys that outnumber the bound") {
        FakeRegistry reg;
        reg.key("Wide");
        for (std::size_t i = 0; i < kMaxTreeNodes + 5; ++i) reg.key("Wide\\k" + std::to_string(i));
        const auto dry = delete_key_tree(reg, FakeRegistry::kRoot, "Wide", fast, true, true);
        CHECK(dry.capped);
        CHECK(dry.counted_keys == kMaxTreeNodes);
        CHECK(delete_key_tree(reg, FakeRegistry::kRoot, "Wide", fast, true, false).reason == "tree_too_large");
        CHECK(reg.exists("Wide"));
    }
    SECTION("exactly kMaxTreeDepth levels below the target is within the bound; one more is capped") {
        FakeRegistry ok_tree, deep_tree;
        make_chain(ok_tree, kMaxTreeDepth);
        make_chain(deep_tree, kMaxTreeDepth + 1);
        const auto fits = delete_key_tree(ok_tree, FakeRegistry::kRoot, "D", fast, true, false);
        CHECK(fits.result == "ok");
        CHECK(fits.counted_keys == kMaxTreeDepth + 1);
        CHECK_FALSE(ok_tree.exists("D"));
        const auto dry = delete_key_tree(deep_tree, FakeRegistry::kRoot, "D", fast, true, true);
        CHECK(dry.capped);
        const auto real = delete_key_tree(deep_tree, FakeRegistry::kRoot, "D", fast, true, false);
        CHECK(real.reason == "tree_too_large");
        CHECK(deep_tree.calls("delete_key_by_handle") == 0);
        CHECK(deep_tree.exists("D"));
    }
}

TEST_CASE("registry core: a tree that outgrows the bound between the vet and the delete stops concurrent_change",
          "[registry][core][recursive]") {
    FakeRegistry reg;
    reg.put("T\\A", "a", kRegDword, dword(1));
    reg.put("T\\Z", "z", kRegDword, dword(2));
    std::size_t added = 0;
    SecondOpen second;
    reg.before = [&](const std::string& ev) {
        // from the delete-phase open of Z on, every value enumeration of a key adds a value
        if (ev == "open_sub:Z" && second(ev))
            reg.grow_on_enum = [&added](Node& n) { n.values["g" + std::to_string(added++)] = Val{kRegDword, dword(1)}; };
    };
    const auto o = delete_key_tree(reg, FakeRegistry::kRoot, "T", false, true, false);
    CHECK(o.result == "failed"); // A's NtDeleteKey was issued before the stop
    CHECK(o.reason == "concurrent_change");
    CHECK(o.counted_keys == 1);
    CHECK(o.counted_values == 1);
    CHECK(reg.exists("T\\Z"));
    CHECK(reg.exists("T"));
}

TEST_CASE("registry core: values added to an ancestor after the vet count toward the tree's running total",
          "[registry][core][recursive]") {
    // At T's own delete the walk has removed A and Z (a key and a value each: 4 nodes) and T itself is node 5, so T
    // may hold kMaxTreeNodes - 5 values. The values are planted on T once the delete phase opens Z.
    const bool over = GENERATE(false, true);
    const std::size_t planted = kMaxTreeNodes - 5 + (over ? 1 : 0);
    FakeRegistry reg;
    reg.put("T\\A", "a", kRegDword, dword(1));
    reg.put("T\\Z", "z", kRegDword, dword(2));
    bool done = false;
    SecondOpen second;
    reg.before = [&](const std::string& ev) {
        if (done || ev != "open_sub:Z" || !second(ev)) return;
        done = true;
        for (std::size_t i = 0; i < planted; ++i) reg.put("T", "g" + std::to_string(i), kRegDword, dword(1));
    };
    const auto o = delete_key_tree(reg, FakeRegistry::kRoot, "T", false, true, false);
    REQUIRE(done);
    if (over) {
        // mutant: T's values counted from a fresh total (the per-key cap) and T is deleted past the bound
        CHECK(o.result == "failed");
        CHECK(o.reason == "concurrent_change");
        CHECK(o.counted_keys == 2);
        CHECK(o.counted_values == 2);
        CHECK(reg.exists("T"));
    } else {
        CHECK(o.result == "ok");
        CHECK(o.counted_keys == 3);
        CHECK(o.counted_values == 2 + planted);
        CHECK_FALSE(reg.exists("T"));
    }
}

TEST_CASE("registry core: a tree that grows by one node after the vet and reaches the bound stops before its root",
          "[registry][core][recursive]") {
    // The vet sees T, Big and kMaxTreeNodes - 2 values: kMaxTreeNodes nodes, within the bound. One more value lands on Big
    // once the delete phase opens it, so Big's removal brings the walk's total to exactly kMaxTreeNodes and T (no values of
    // its own) would be node 10,001: the walk stops there, T stays.
    FakeRegistry reg;
    reg.key("T\\Big");
    for (std::size_t i = 0; i < kMaxTreeNodes - 2; ++i) reg.put("T\\Big", "v" + std::to_string(i), kRegDword, dword(1));
    bool grown = false;
    SecondOpen second;
    reg.before = [&](const std::string& ev) {
        if (grown || ev != "open_sub:Big" || !second(ev)) return;
        grown = true;
        reg.put("T\\Big", "extra", kRegDword, dword(1));
    };
    const auto o = delete_key_tree(reg, FakeRegistry::kRoot, "T", false, true, false);
    REQUIRE(grown);
    // mutant: the running-total check at a key's own delete is `>`, so T is removed as the 10,001st node
    CHECK(o.result == "failed"); // Big's NtDeleteKey was issued before the stop
    CHECK(o.reason == "concurrent_change");
    CHECK(o.counted_keys == 1);
    CHECK(o.counted_values == kMaxTreeNodes - 1);
    CHECK_FALSE(reg.exists("T\\Big"));
    CHECK(reg.exists("T"));
}

TEST_CASE("registry core: a recursive delete of a link leaf removes the link object only",
          "[registry][core][recursive]") {
    const bool fast = GENERATE(false, true);
    FakeRegistry reg;
    reg.put("Real\\Target", "keep", kRegDword, dword(1));
    reg.link("Software\\L", "Real\\Target");
    const auto o = delete_key_tree(reg, FakeRegistry::kRoot, "Software\\L", fast, true, false);
    CHECK(o.result == "ok");
    CHECK(o.counted_keys == 1);
    CHECK_FALSE(reg.exists("Software\\L"));
    CHECK(reg.get("Real\\Target", "keep")->data == dword(1));
}

// ── flush ────────────────────────────────────────────────────────────────

TEST_CASE("registry core: flush is called once after a verified write and never after a refusal",
          "[registry][core][flush]") {
    FakeRegistry reg;
    reg.put("A", "V", kRegDword, dword(1));
    SECTION("set_value, flush on") {
        const auto o = set_value_verified(reg, FakeRegistry::kRoot, "A", "V", kRegDword, dword(2), false, true);
        CHECK(o.ok());
        CHECK(reg.flushed == 1);
    }
    SECTION("set_value, flush off (the default)") {
        CHECK(set_value_verified(reg, FakeRegistry::kRoot, "A", "V", kRegDword, dword(2)).ok());
        CHECK(reg.flushed == 0);
    }
    SECTION("delete_value, flush on") {
        CHECK(delete_value_verified(reg, FakeRegistry::kRoot, "A", "V", false, true).ok());
        CHECK(reg.flushed == 1);
    }
    SECTION("a refusal flushes nothing") {
        CHECK(delete_value_verified(reg, FakeRegistry::kRoot, "A", "Nope", false, true).reason == "value_not_found");
        CHECK(delete_value_verified(reg, FakeRegistry::kRoot, "Nope", "V", false, true).reason == "key_not_found");
        reg.key("A")->deny_set = true;
        CHECK(set_value_verified(reg, FakeRegistry::kRoot, "A", "V", kRegDword, dword(2), false, true).reason ==
              "access_denied");
        CHECK(reg.flushed == 0);
        CHECK(reg.calls("flush_key") == 0);
    }
    SECTION("a verify mismatch is not flushed either") {
        reg.tamper_after_set = [](Node& n, const std::string& name) { n.values[name].data[0] ^= 0xff; };
        CHECK(set_value_verified(reg, FakeRegistry::kRoot, "A", "V", kRegDword, dword(2), false, true).reason ==
              "verify_mismatch");
        CHECK(reg.calls("flush_key") == 0);
    }
}

TEST_CASE("registry core: a flush failure fails the write; a creating write's keys are rolled back",
          "[registry][core][flush]") {
    FakeRegistry reg;
    reg.key("Software");
    SECTION("an overwrite: failed with the flush token, the verified value stays (durability unknown)") {
        reg.put("Software\\Acme", "V", kRegDword, dword(1));
        reg.inject["flush_key"] = 5;
        const auto o = set_value_verified(reg, FakeRegistry::kRoot, "Software\\Acme", "V", kRegDword, dword(2), false, true);
        CHECK(o.result == "failed");
        CHECK(o.reason == "flush_failed:access_denied");
        CHECK(o.verify == "ok");
        CHECK(o.mutated);
        CHECK(reg.get("Software\\Acme", "V")->data == dword(2));
    }
    SECTION("a creating write: the value and the keys it made are removed again") {
        // mutant: flush_on runs after op.commit(), so the rollback has nothing to do
        reg.inject["flush_key"] = 1450;
        const auto o = set_value_verified(reg, FakeRegistry::kRoot, "Software\\New\\Deeper", "V", kRegDword, dword(3), false, true);
        CHECK(o.result == "failed");
        CHECK(o.reason == "flush_failed:win32:1450");
        CHECK(o.created == 0);
        CHECK_FALSE(reg.exists("Software\\New"));
        CHECK(reg.method_calls("delete_key_by_handle") == 2);
    }
    SECTION("delete_value") {
        reg.put("Software\\Acme", "V", kRegDword, dword(1));
        reg.inject["flush_key"] = 5;
        const auto o = delete_value_verified(reg, FakeRegistry::kRoot, "Software\\Acme", "V", false, true);
        CHECK(o.result == "failed");
        CHECK(o.reason == "flush_failed:access_denied");
        CHECK(reg.get("Software\\Acme", "V") == nullptr);
    }
}

TEST_CASE("registry core: commit keeps the leaf open until the Opened is destroyed", "[registry][core][flush]") {
    FakeRegistry reg;
    reg.key("Software");
    {
        Opened op = open_checked(reg, FakeRegistry::kRoot, "Software\\New\\Deeper", kKeySetValue, true);
        REQUIRE(op.error.empty());
        REQUIRE(op.created == 2);
        op.commit();
        CHECK(reg.open.size() == 1); // the intermediate handle closed, the leaf did not
        const Handle h = op.handle();
        CHECK(reg.set_value(h, "V", kRegDword, dword(5)) == 0); // still usable
        op.rollback();                                          // committed: nothing to roll back
        CHECK(reg.exists("Software\\New\\Deeper"));
    }
    CHECK(reg.open.empty());
    CHECK(reg.get("Software\\New\\Deeper", "V")->data == dword(5));
}

// ── open_checked probe_create ────────────────────────────────────────────

TEST_CASE("registry core: probe_create asks for create access on the deepest existing key and creates nothing",
          "[registry][core][probe]") {
    FakeRegistry reg;
    reg.key("Software\\Acme");
    SECTION("allowed: key_not_found with the missing count, nothing created") {
        const Opened o = open_checked(reg, FakeRegistry::kRoot, "Software\\Acme\\New\\Deeper", kKeySetValue, false,
                                      false, false, /*probe_create=*/true);
        CHECK(o.error == "key_not_found");
        CHECK(o.missing == 2);
        CHECK(o.created == 0);
        CHECK(reg.method_calls("create_sub") == 0);
        CHECK_FALSE(reg.exists("Software\\Acme\\New"));
        CHECK(std::ranges::find(reg.masks, "open_sub::0x4") != reg.masks.end()); // the self re-open for KEY_CREATE_SUB_KEY
    }
    SECTION("denied: access_denied, exactly what the real create would answer") {
        reg.key("Software\\Acme")->deny_create = true;
        const Opened probe = open_checked(reg, FakeRegistry::kRoot, "Software\\Acme\\New", kKeySetValue, false, false,
                                          false, true);
        CHECK(probe.error == "access_denied");
        const Opened real = open_checked(reg, FakeRegistry::kRoot, "Software\\Acme\\New", kKeySetValue, true);
        CHECK(real.error == "access_denied");
    }
    SECTION("a first component missing under the root is root_level_create in both modes") {
        CHECK(open_checked(reg, FakeRegistry::kRoot, "Nowhere\\K", kKeySetValue, false, false, false, true).error ==
              "root_level_create");
        CHECK(open_checked(reg, FakeRegistry::kRoot, "Nowhere\\K", kKeySetValue, true).error == "root_level_create");
    }
    SECTION("without the flag a missing key stays plain key_not_found and no probe is made") {
        const Opened o = open_checked(reg, FakeRegistry::kRoot, "Software\\Acme\\New", kKeySetValue, false);
        CHECK(o.error == "key_not_found");
        CHECK(std::ranges::find(reg.masks, "open_sub::0x4") == reg.masks.end());
    }
    SECTION("an existing key is opened as usual") {
        const Opened o = open_checked(reg, FakeRegistry::kRoot, "Software\\Acme", kKeySetValue, false, false, false, true);
        CHECK(o.error.empty());
        CHECK(std::ranges::find(reg.masks, "open_sub::0x4") == reg.masks.end());
    }
}

// ── per-user write output ────────────────────────────────────────────────

namespace {

using yuzu::profiles::HiveAccessStatus;

constexpr const char* kSid = "S-1-5-21-111-222-333-1001";

AuditRecord user_record(const char* op = "set_user_value") {
    AuditRecord au;
    au.op = op;
    au.hive = "HKU";
    au.key = "Software\\Acme";
    au.name = "V";
    au.type_name = "REG_DWORD";
    au.len = 4;
    return au;
}

WriteOutcome ok_write() {
    WriteOutcome wo;
    wo.result = "ok";
    wo.verify = "ok";
    wo.mutated = true;
    return wo;
}

bool starts(const std::string& s, const char* p) { return s.rfind(p, 0) == 0; }

} // namespace

TEST_CASE("registry core: render_user_write orders the hive lines the race warning the audit line and the status",
          "[registry][core][user]") {
    SECTION("a clean write: the audit line (hive=HKU, sid=) then status|ok") {
        const auto out = render_user_write(user_record(), ok_write(), HiveFacts{}, kSid);
        REQUIRE(out.lines.size() == 2);
        CHECK(starts(out.lines[0], "audit|op=set_user_value|hive=HKU|result=ok|reason=-|verify=ok|"));
        CHECK(out.lines[0].find(std::string{"|sid="} + kSid + "|") != std::string::npos);
        CHECK(out.lines[1] == "status|ok");
        CHECK(out.rc == 0);
    }
    SECTION("an unload that failed after a durable write keeps result=ok and says so in the reason, warning first") {
        HiveFacts hf;
        hf.unload_failed = true;
        hf.mount_name = "YUZU_HIVE_x";
        const auto out = render_user_write(user_record(), ok_write(), hf, kSid);
        REQUIRE(out.lines.size() == 3);
        CHECK(starts(out.lines[0], "warning|hive_unload_failed:"));
        CHECK(starts(out.lines[1], "audit|op=set_user_value|hive=HKU|result=ok|reason=hive_unload_failed|"));
        CHECK(out.lines[2] == "status|ok");
        CHECK(out.rc == 0);
    }
    SECTION("a mount that failed AND failed to unload: the unload warning precedes the terminal error") {
        HiveFacts hf;
        hf.status = HiveAccessStatus::mount_failed;
        hf.unload_failed = true;
        const auto out = render_user_write(user_record(), WriteOutcome{}, hf, kSid);
        REQUIRE(out.lines.size() == 4);
        CHECK(starts(out.lines[0], "warning|hive_unload_failed:"));
        CHECK(starts(out.lines[1], "error|failed to load hive for sid"));
        CHECK(starts(out.lines[2], "audit|op=set_user_value|hive=HKU|result=refused|reason=hive_mount_failed|"));
        CHECK(out.lines[3] == "error|hive_mount_failed");
        CHECK(out.rc == 1);
    }
    SECTION("each unreachable status is a refusal with its own reason, whatever the outcome claimed") {
        // mutant: a non-ok hive status keeps the caller's WriteOutcome (here a stale "ok")
        const struct {
            HiveAccessStatus st;
            const char* reason;
        } cases[] = {{HiveAccessStatus::not_found, "hive_not_found"},
                     {HiveAccessStatus::privilege_missing, "privilege_missing"},
                     {HiveAccessStatus::mount_failed, "hive_mount_failed"}};
        for (const auto& c : cases) {
            HiveFacts hf;
            hf.status = c.st;
            const auto out = render_user_write(user_record(), ok_write(), hf, kSid);
            INFO(c.reason);
            REQUIRE_FALSE(out.lines.empty());
            CHECK(out.rc == 1);
            CHECK(out.lines.back() == std::string{"error|"} + c.reason);
            CHECK(out.lines[out.lines.size() - 2].find(std::string{"|result=refused|reason="} + c.reason + "|") !=
                  std::string::npos);
        }
    }
    SECTION("a refused hive file names the guard's token on the error line and as the reason") {
        HiveFacts hf;
        hf.status = HiveAccessStatus::file_refused;
        hf.refusal = "hive_file_reparse_point";
        const auto out = render_user_write(user_record(), WriteOutcome{}, hf, kSid);
        REQUIRE(out.lines.size() == 3);
        CHECK(out.lines[0] == std::string{"error|hive file refused for sid '"} + kSid + "': hive_file_reparse_point");
        CHECK(starts(out.lines[1], "audit|op=set_user_value|hive=HKU|result=refused|reason=hive_file_reparse_point|"));
        CHECK(out.lines[2] == "error|hive_file_reparse_point");
        CHECK(out.rc == 1);
        hf.refusal.clear();
        CHECK(render_user_write(user_record(), WriteOutcome{}, hf, kSid).lines.back() == "error|hive_file_refused");
    }
    SECTION("the race warning follows the hive lines and precedes the audit line; the write stays ok") {
        HiveFacts hf;
        hf.race_warning = "hive_loaded_after_offline_write";
        const auto out = render_user_write(user_record("delete_user_value"), ok_write(), hf, kSid);
        REQUIRE(out.lines.size() == 3);
        CHECK(out.lines[0] == "warning|hive_loaded_after_offline_write");
        CHECK(starts(out.lines[1], "audit|op=delete_user_value|hive=HKU|result=ok|"));
        CHECK(out.rc == 0);
    }
    SECTION("a failed write keeps its own reason and rc 1") {
        WriteOutcome wo = ok_write();
        wo.fail("flush_failed:access_denied", true);
        const auto out = render_user_write(user_record(), wo, HiveFacts{}, kSid);
        REQUIRE(out.lines.size() == 2);
        CHECK(starts(out.lines[0], "audit|op=set_user_value|hive=HKU|result=failed|reason=flush_failed:access_denied|"));
        CHECK(out.lines[1] == "error|flush_failed:access_denied");
        CHECK(out.rc == 1);
    }
    SECTION("a failed write whose hive then failed to unload keeps its own reason; only a write that succeeded is relabelled") {
        // mutant: hive_unload_failed overwrites the reason of any write, so a failed write loses its token
        HiveFacts hf;
        hf.unload_failed = true;
        hf.mount_name = "YUZU_HIVE_x";
        WriteOutcome wo = ok_write();
        wo.fail("flush_failed:access_denied", true);
        const auto out = render_user_write(user_record(), wo, hf, kSid);
        REQUIRE(out.lines.size() == 3);
        CHECK(starts(out.lines[0], "warning|hive_unload_failed:"));
        CHECK(starts(out.lines[1], "audit|op=set_user_value|hive=HKU|result=failed|reason=flush_failed:access_denied|"));
        CHECK(out.lines[2] == "error|flush_failed:access_denied");
        CHECK(out.rc == 1);
    }
}

// ── apply ────────────────────────────────────────────────────────────────

namespace {

using json = nlohmann::json;

json set_item(const std::string& key, const std::string& name, const std::string& value,
              const std::string& type = "REG_SZ") {
    return {{"op", "set_value"}, {"key", key}, {"name", name}, {"type", type}, {"value", value}};
}
json hex_item(const std::string& key, const std::string& name, const std::string& type, const std::string& hex) {
    return {{"op", "set_value"}, {"key", key}, {"name", name}, {"type", type}, {"data_hex", hex}};
}
json del_value_item(const std::string& key, const std::string& name) {
    return {{"op", "delete_value"}, {"key", key}, {"name", name}};
}
json make_key_item(const std::string& key) { return {{"op", "create_key"}, {"key", key}}; }
json del_key_item(const std::string& key) { return {{"op", "delete_key"}, {"key", key}}; }

std::vector<PlanItem> plan_of(const json& plan) {
    auto parsed = parse_plan(plan.dump());
    REQUIRE(parsed.error.empty());
    return std::move(parsed.items);
}

/// run_apply's output (as its sink recorded it) split into its row kinds (item/undo/summary as cells).
struct ApplyRun {
    ActionOutput out;
    std::vector<std::vector<std::string>> items, undo;
    std::vector<std::string> audits;
    std::vector<std::string> summary;
    [[nodiscard]] const std::string& verdict(std::size_t i) const { return items.at(i).at(6); }
    [[nodiscard]] const std::string& reason(std::size_t i) const { return items.at(i).at(7); }
    [[nodiscard]] std::vector<std::string> verdicts() const {
        std::vector<std::string> v;
        for (const auto& row : items) v.push_back(row.at(6));
        return v;
    }
    [[nodiscard]] bool undo_complete() const { return summary.at(7) == "1"; }
    [[nodiscard]] std::size_t bytes() const {
        std::size_t n = 0;
        for (const auto& l : out.lines) n += l.size() + 1;
        return n;
    }
};

ApplyRun split_output(ActionOutput out) {
    ApplyRun r;
    for (const auto& line : out.lines) {
        if (starts(line, "item|")) r.items.push_back(cells(line));
        else if (starts(line, "undo|")) r.undo.push_back(cells(line));
        else if (starts(line, "audit|")) r.audits.push_back(line);
        else if (starts(line, "summary|")) r.summary = cells(line);
    }
    r.out = std::move(out);
    return r;
}

/// Runs a plan through run_apply into a recording sink (`ctx`, when given, is that sink: a test can make it fail).
ApplyRun run_plan(FakeRegistry& reg, const json& plan, bool dry, bool cont = false, bool fast = true,
                  RecordingCtx* ctx = nullptr) {
    RecordingCtx own;
    RecordingCtx& sink = ctx != nullptr ? *ctx : own;
    ActionOutput out;
    out.rc = run_apply(sink, reg, FakeRegistry::kRoot, plan_of(plan), ApplyOptions{dry, cont}, fast);
    out.lines = sink.lines;
    return split_output(std::move(out));
}

std::string long_name(char fill, std::size_t index) {
    std::string n(kMaxValueNameBytes - 3, fill);
    n += std::to_string(1000 + index).substr(1);
    return n;
}

} // namespace

// The safe default: an ApplyOptions nobody filled in is a dry run (every test below passes both flags explicitly).
static_assert(ApplyOptions{}.dry_run, "ApplyOptions defaults to a dry run");

TEST_CASE("registry apply: a dry run gives the real run's verdicts item for item and changes nothing",
          "[registry][core][apply]") {
    const auto build = [](FakeRegistry& r) {
        r.put("Software\\Acme", "Keep", kRegDword, dword(1));
        r.put("Software\\Acme", "Gone", kRegSz, sz("bye"));
        r.put("Software\\Old", "a", kRegDword, dword(2));
        r.put("Software\\Old", "b", kRegBinary, B({1, 2, 3}));
        r.key("Software\\Parent\\Child");
    };
    const json plan = json::array({
        set_item("Software\\Acme", "Keep", "5", "REG_DWORD"),   // 0 overwrite
        del_value_item("Software\\Acme", "Gone"),               // 1
        set_item("Software\\Fresh\\Deep", "v", "x"),            // 2 creates two keys
        make_key_item("Software\\Made"),                        // 3
        del_key_item("Software\\Old"),                          // 4 a leaf with two values
        del_value_item("Software\\Acme", "Missing"),            // 5 refused: value_not_found
        del_key_item("Software\\Nope"),                         // 6 refused: key_not_found
        del_key_item("Software\\Parent"),                       // 7 refused: key_has_subkeys
    });
    FakeRegistry dry_reg, real_reg;
    build(dry_reg);
    build(real_reg);
    const std::string before = dump(dry_reg);

    const auto dry = run_plan(dry_reg, plan, /*dry=*/true, /*cont=*/true);
    CHECK(dump(dry_reg) == before); // a dry run mutates nothing
    CHECK(dry_reg.method_calls("set_value") == 0);
    CHECK(dry_reg.method_calls("delete_value") == 0);
    CHECK(dry_reg.method_calls("create_sub") == 0);
    CHECK(dry_reg.method_calls("delete_key_by_handle") == 0);
    const auto real = run_plan(real_reg, plan, /*dry=*/false, /*cont=*/true);

    CHECK(dry.verdicts() == std::vector<std::string>{"would_apply", "would_apply", "would_apply", "would_apply",
                                                      "would_apply", "refused", "refused", "refused"});
    CHECK(real.verdicts() == std::vector<std::string>{"applied", "applied", "applied", "applied", "applied", "refused",
                                                       "refused", "refused"});
    REQUIRE(dry.items.size() == real.items.size());
    for (std::size_t i = 0; i < dry.items.size(); ++i) {
        INFO("item " << i);
        CHECK(dry.items[i].size() == 14);
        CHECK(dry.reason(i) == real.reason(i));               // the same facts, the same verdict function
        CHECK(dry.items[i][9] == real.items[i][9]);           // created: predicted == actual
        for (const std::size_t c : {10u, 11u, 12u, 13u}) CHECK(dry.items[i][c] == real.items[i][c]); // old_* and new_len
    }
    CHECK(dry.reason(5) == "value_not_found");
    CHECK(dry.reason(6) == "key_not_found");
    CHECK(dry.reason(7) == "key_has_subkeys");
    CHECK(dry.items[2][9] == "2"); // Fresh and Deep
    CHECK(dry.items[0][10] == "present");
    CHECK(dry.items[0][11] == "REG_DWORD");
    CHECK(dry.items[0][12] == "01000000");
    CHECK(dry.items[0][13] == "4");
    CHECK(dry.out.rc == 1);
    CHECK(real.out.rc == 1);
    CHECK(dry.out.lines.back() == "error|partial_failure");
    CHECK(dry.summary == std::vector<std::string>{"summary", "8", "5", "3", "0", "0", "1", "1"});
    CHECK(real.summary == std::vector<std::string>{"summary", "8", "5", "3", "0", "0", "0", "1"});

    CHECK(real_reg.get("Software\\Acme", "Keep")->data == dword(5));
    CHECK(real_reg.get("Software\\Acme", "Gone") == nullptr);
    CHECK(real_reg.get("Software\\Fresh\\Deep", "v") != nullptr);
    CHECK(real_reg.exists("Software\\Made"));
    CHECK_FALSE(real_reg.exists("Software\\Old"));
    // the deleted key's values come back as undo rows
    REQUIRE(real.undo.size() == 2);
    CHECK(real.undo[0] == std::vector<std::string>{"undo", "4", "a", "REG_DWORD", "02000000", "0"});
    CHECK(real.undo[1] == std::vector<std::string>{"undo", "4", "b", "REG_BINARY", "010203", "0"});
    // one audit line per item, op=apply.<op>, dry_run reported, the old and new values on the value ops
    REQUIRE(dry.audits.size() == 8);
    CHECK(starts(dry.audits[0], "audit|op=apply.set_value|hive=HKLM|result=ok|reason=-|verify=-|key=Software\\Acme|name=Keep|"
                                "type=REG_DWORD|len=4|dry_run=1|"));
    CHECK(dry.audits[0].ends_with("|old_state=present|old_type=REG_DWORD|old=01000000|new=05000000"));
    CHECK(starts(real.audits[0], "audit|op=apply.set_value|hive=HKLM|result=ok|reason=-|verify=ok|"));
    CHECK(real.audits[0].find("|dry_run=0|") != std::string::npos);
    CHECK(real.audits[4].find("|op=apply.delete_key|") != std::string::npos);
    CHECK(real.audits[4].find("|counted_keys=1|counted_values=2|capped=0|") != std::string::npos);
    CHECK(starts(real.audits[5], "audit|op=apply.delete_value|hive=HKLM|result=refused|reason=value_not_found|"));
}

TEST_CASE("registry apply: a dry run opens with the mutation's own mask and probes create access without creating",
          "[registry][core][apply]") {
    FakeRegistry reg;
    reg.key("Software\\Locked")->deny_create = true;
    reg.put("Software\\Acme", "V", kRegDword, dword(1));
    const json plan = json::array({
        set_item("Software\\Locked\\New", "V", "1", "REG_DWORD"),
        set_item("Software\\Acme", "V", "2", "REG_DWORD"),
    });
    SECTION("dry run") {
        const auto run = run_plan(reg, plan, true, true);
        CHECK(run.verdicts() == std::vector<std::string>{"refused", "would_apply"});
        CHECK(run.reason(0) == "access_denied");
        CHECK(reg.method_calls("create_sub") == 0);
        CHECK_FALSE(reg.exists("Software\\Locked\\New"));
        CHECK(std::ranges::find(reg.masks, "open_path:Software\\Acme:0x3") != reg.masks.end()); // QUERY | SET, like a write
        CHECK(std::ranges::find(reg.masks, "open_sub::0x4") != reg.masks.end());                 // the create probe
    }
    SECTION("real run: the same verdict") {
        const auto run = run_plan(reg, plan, false, true);
        CHECK(run.verdicts() == std::vector<std::string>{"refused", "applied"});
        CHECK(run.reason(0) == "access_denied");
        CHECK_FALSE(reg.exists("Software\\Locked\\New"));
    }
    SECTION("a first component missing under the root is root_level_create in both modes") {
        const json top = json::array({set_item("NewTop\\K", "V", "x")});
        FakeRegistry a, b;
        const auto dry = run_plan(a, top, true, true);
        const auto real = run_plan(b, top, false, true);
        CHECK(dry.reason(0) == "root_level_create");
        CHECK(real.reason(0) == "root_level_create");
        CHECK(dry.verdict(0) == "refused");
        CHECK(real.verdict(0) == "refused");
    }
}

TEST_CASE("registry apply: a failed open is never cached so a later item on the key still creates it",
          "[registry][core][apply]") {
    SECTION("delete_value on a missing key, then set_value on it") {
        // mutant: the open's outcome is cached per key even when it failed
        const json plan = json::array({del_value_item("Software\\K", "a"), set_item("Software\\K", "b", "1", "REG_DWORD")});
        FakeRegistry dry_reg, real_reg;
        dry_reg.key("Software");
        real_reg.key("Software");
        const auto dry = run_plan(dry_reg, plan, true, true);
        const auto real = run_plan(real_reg, plan, false, true);
        CHECK(dry.verdicts() == std::vector<std::string>{"refused", "would_apply"});
        CHECK(real.verdicts() == std::vector<std::string>{"refused", "applied"});
        CHECK(dry.reason(0) == "key_not_found");
        CHECK(real.reason(0) == "key_not_found");
        CHECK(dry.items[1][9] == "1");
        CHECK(real.items[1][9] == "1");
        CHECK(real_reg.get("Software\\K", "b") != nullptr); // the second item CREATED the key
        CHECK_FALSE(dry_reg.exists("Software\\K"));
    }
    SECTION("the reverse order: the delete finds the key the first item created, in both modes") {
        const json plan = json::array({set_item("Software\\K", "b", "1", "REG_DWORD"), del_value_item("Software\\K", "a")});
        FakeRegistry dry_reg, real_reg;
        dry_reg.key("Software");
        real_reg.key("Software");
        const auto dry = run_plan(dry_reg, plan, true, true);
        const auto real = run_plan(real_reg, plan, false, true);
        CHECK(dry.verdicts() == std::vector<std::string>{"would_apply", "refused"});
        CHECK(real.verdicts() == std::vector<std::string>{"applied", "refused"});
        CHECK(dry.reason(1) == "value_not_found");
        CHECK(real.reason(1) == "value_not_found");
        CHECK(dry.items[0][9] == real.items[0][9]);
        // and the key the second item reached was the first item's handle, not a second open
        CHECK(real_reg.method_calls("create_sub") == 1);
    }
}

TEST_CASE("registry apply: previous values are captured and the one budget flags an incomplete manifest",
          "[registry][core][apply]") {
    SECTION("the previous value is in the item row; a value over 4 KiB keeps its first 4 KiB and flags the manifest") {
        FakeRegistry reg;
        Bytes big(5000);
        for (std::size_t i = 0; i < big.size(); ++i) big[i] = static_cast<std::uint8_t>(i % 251);
        reg.put("Software\\A", "Big", kRegBinary, big);
        reg.put("Software\\A", "Small", kRegSz, sz("old"));
        const auto run = run_plan(reg, json::array({set_item("Software\\A", "Small", "new"),
                                                    hex_item("Software\\A", "Big", "REG_BINARY", "00")}), true);
        CHECK(run.items[0][12] == yuzu::profiles::hex_encode(sz("old")));
        CHECK(run.items[1][12] == yuzu::profiles::hex_encode(std::span<const std::uint8_t>{big}.first(kCaptureValueCap)) + "~5000");
        CHECK_FALSE(run.undo_complete());
    }
    SECTION("128 values of 4,000 bytes fit the 512 KiB budget; the 129th and later keep their metadata but no bytes") {
        FakeRegistry reg;
        json plan = json::array();
        for (std::size_t i = 0; i < 140; ++i) {
            const std::string name = "v" + std::to_string(1000 + i).substr(1);
            reg.put("Software\\Big", name, kRegBinary, Bytes(4000, static_cast<std::uint8_t>(i)));
            plan.push_back(del_value_item("Software\\Big", name));
        }
        const auto dry = run_plan(reg, plan, true, true);
        const auto real = run_plan(reg, plan, false, true);
        for (const auto* run : {&dry, &real}) {
            REQUIRE(run->items.size() == 140);
            std::size_t retained = 0, kept_rows = 0;
            for (const auto& row : run->items) {
                CHECK(row[6] == (run == &dry ? "would_apply" : "applied"));
                if (row[12].find('~') == std::string::npos) { // the whole 4,000 bytes
                    ++kept_rows;
                    retained += row[5].size() + row[12].size() / 2 + kUndoRowOverhead;
                } else {
                    CHECK(row[12] == "~4000"); // metadata and the size, no bytes
                }
            }
            CHECK(kept_rows == 128);
            CHECK(retained <= kCaptureTotalCap);
            CHECK_FALSE(run->undo_complete());
        }
        CHECK(reg.key("Software\\Big")->values.empty()); // the real run deleted them all
    }
}

TEST_CASE("registry apply: a value NAME is charged to the budget too and the vet still sees every value",
          "[registry][core][apply]") {
    FakeRegistry reg;
    for (std::size_t i = 0; i < 256; ++i) reg.put("Software\\Names", long_name('n', i), kRegBinary, Bytes{});
    const json plan = json::array({del_key_item("Software\\Names")});
    const auto dry = run_plan(reg, plan, true);
    REQUIRE(dry.verdict(0) == "would_apply");
    CHECK(dry.audits[0].find("|counted_keys=1|counted_values=256|capped=0|") != std::string::npos); // all 256 vetted
    CHECK(reg.exists("Software\\Names"));
    const auto real = run_plan(reg, plan, false);
    CHECK(real.verdict(0) == "applied");
    CHECK_FALSE(reg.exists("Software\\Names")); // the delete proceeds although the manifest cannot hold every row
    CHECK_FALSE(real.undo_complete());
    CHECK_FALSE(dry.undo_complete()); // the dry run charges identically, so the operator sees it before mutating
    // one row costs name + data + kUndoRowOverhead: 16,383 + 0 + 64 -> 31 rows in 512 KiB, never more
    constexpr std::size_t kRow = kMaxValueNameBytes + kUndoRowOverhead;
    REQUIRE(real.undo.size() == kCaptureTotalCap / kRow);
    std::size_t retained = 0;
    for (const auto& row : real.undo) retained += row[2].size() + row[4].size() / 2 + kUndoRowOverhead;
    CHECK(retained <= kCaptureTotalCap);
    CHECK(retained + kRow > kCaptureTotalCap); // and it stopped because the next row would not fit
    WARN("long-name budget: " << real.undo.size() << " of 256 rows retained, " << retained << " of " << kCaptureTotalCap
                              << " bytes charged");
}

TEST_CASE("registry apply: a refused or capped delete_key charges the budget nothing and each leaf is enumerated once",
          "[registry][core][apply]") {
    const bool dry = GENERATE(true, false);
    const bool capped = GENERATE(true, false);
    INFO((dry ? "dry run" : "real run") << (capped ? ", capped leaf" : ", leaf with a defect"));
    FakeRegistry reg;
    for (std::size_t i = 0; i < 100; ++i) {
        const std::string name = "v" + std::to_string(1000 + i).substr(1);
        reg.put("Software\\Good", name, kRegBinary, Bytes(4000, 1));
        if (!capped) reg.put("Software\\Bad", name, kRegBinary, Bytes(4000, 2));
    }
    if (capped)
        for (std::size_t i = 0; i < kMaxTreeNodes + 5; ++i) reg.put("Software\\Bad", "w" + std::to_string(i), kRegDword, dword(1));
    else
        reg.put("Software\\Bad", "v999", 0 /*REG_NONE*/, Bytes{});
    const auto run = run_plan(reg, json::array({del_key_item("Software\\Bad"), del_key_item("Software\\Good")}), dry, true);
    CHECK(run.verdicts() == std::vector<std::string>{"refused", dry ? "would_apply" : "applied"});
    CHECK(run.reason(0) == (capped ? "tree_too_large" : "unsupported_old_type"));
    CHECK(run.undo_complete());
    CHECK(run.undo.size() == (dry ? 0u : 100u));
    CHECK(reg.method_calls("enum_value") == (capped ? kMaxTreeNodes : 100 + 1) + (100 + 1));
}

TEST_CASE("registry apply: delete_key vets EVERY value of the leaf before it deletes anything",
          "[registry][core][apply]") {
    const bool dry = GENERATE(true, false);
    FakeRegistry reg;
    for (std::size_t i = 0; i < 299; ++i)
        reg.put("Software\\Leaf", "v" + std::to_string(1000 + i).substr(1), kRegDword, dword(1));
    const json plan = json::array({del_key_item("Software\\Leaf")});
    SECTION("the 300th value has a type this plugin cannot write back") {
        // mutant: only the values the budget retained (or the first 256) are checked
        reg.put("Software\\Leaf", "v299", 0 /*REG_NONE*/, Bytes{});
        const auto run = run_plan(reg, plan, dry);
        CHECK(run.verdict(0) == "refused");
        CHECK(run.reason(0) == "unsupported_old_type");
    }
    SECTION("the 300th value has a name the manifest cannot spell") {
        reg.put("Software\\Leaf", "v299|x", kRegDword, dword(1));
        const auto run = run_plan(reg, plan, dry);
        CHECK(run.reason(0) == "unrepresentable_name");
    }
    SECTION("an enumerated name that is not valid UTF-8, holds a tab, a C1 control or ends in a backslash") {
        const std::string bad = GENERATE(std::string{"ab\xFF"}, std::string{"a\tb"}, std::string{"a\xC2\x85z"},
                                         std::string{"a\\"}, std::string{"-"});
        INFO("name bytes " << yuzu::profiles::hex_encode(std::span<const std::uint8_t>{
                                  reinterpret_cast<const std::uint8_t*>(bad.data()), bad.size()}));
        reg.put("Software\\Leaf", bad, kRegDword, dword(1));
        const auto run = run_plan(reg, plan, dry);
        CHECK(run.reason(0) == "unrepresentable_name");
    }
    SECTION("an unreadable value") {
        reg.put("Software\\Leaf", "v299", kRegDword, dword(1));
        reg.key("Software\\Leaf")->unreadable_values.insert("v299");
        CHECK(run_plan(reg, plan, dry).reason(0) == "access_denied");
    }
    SECTION("a shape this plugin could not write (a REG_DWORD that is not four bytes)") {
        reg.put("Software\\Leaf", "v299", kRegDword, B({1, 2}));
        CHECK(run_plan(reg, plan, dry).reason(0) == "unsupported_old_type");
    }
    SECTION("more values than the bound: tree_too_large, nothing deleted") {
        for (std::size_t i = 0; i < kMaxTreeNodes + 5; ++i) reg.put("Software\\Leaf", "w" + std::to_string(i), kRegDword, dword(1));
        const auto run = run_plan(reg, plan, dry);
        CHECK(run.reason(0) == "tree_too_large");
        CHECK(run.audits[0].find("|capped=1|") != std::string::npos);
    }
    CHECK(reg.exists("Software\\Leaf"));
    CHECK(reg.calls("delete_key_by_handle") == 0);
}

TEST_CASE("registry apply: delete_key refuses a value that was enumerated and then vanished in both modes",
          "[registry][core][apply]") {
    // The enumeration is exact, so the name itself round-trips: a query that cannot find it means the value was removed
    // under us. That is concurrent_change, never "nothing to restore" -- the undo manifest would silently lack the row.
    const bool dry = GENERATE(true, false);
    FakeRegistry reg;
    reg.put("Software\\Leaf", "a", kRegDword, dword(1));
    reg.put("Software\\Leaf", "gone", kRegDword, dword(2));
    reg.put("Software\\Leaf", "z", kRegDword, dword(3));
    reg.inject["query_value:gone"] = kErrorFileNotFound;
    // mutant: the vanished value is accepted and the key is deleted (or would be) without a row for it
    const auto run = run_plan(reg, json::array({del_key_item("Software\\Leaf")}), dry);
    CHECK(run.verdict(0) == "refused");
    CHECK(run.reason(0) == "concurrent_change");
    CHECK(run.undo.empty());
    CHECK(reg.exists("Software\\Leaf"));
    CHECK(reg.get("Software\\Leaf", "gone") != nullptr);
    CHECK(reg.calls("delete_key_by_handle") == 0);
}

TEST_CASE("registry apply: a row that exactly fits the remaining budget is kept and the manifest stays complete",
          "[registry][core][apply]") {
    // 128 rows of a 32-byte name, 4,000 data bytes and kUndoRowOverhead cost 4,096 each: the 128th takes exactly what is
    // left of kCaptureTotalCap, and a row that fits to the byte is retained.
    constexpr std::size_t kRows = 128, kNameBytes = 32, kDataBytes = 4000;
    static_assert(kRows * (kNameBytes + kDataBytes + kUndoRowOverhead) == kCaptureTotalCap);
    const bool dry = GENERATE(true, false);
    FakeRegistry reg;
    for (std::size_t i = 0; i < kRows; ++i)
        reg.put("Software\\Fit", std::string(kNameBytes - 3, 'n') + std::to_string(1000 + i).substr(1), kRegBinary,
                Bytes(kDataBytes, 7));
    // mutant: the budget refuses a row whose cost equals what remains (>= for >), dropping the 128th
    const auto run = run_plan(reg, json::array({del_key_item("Software\\Fit")}), dry);
    REQUIRE(run.verdict(0) == (dry ? "would_apply" : "applied"));
    CHECK(run.undo_complete());
    CHECK(run.undo.size() == (dry ? 0u : kRows));
    if (!dry) CHECK(run.undo.back()[4].find('~') == std::string::npos); // the last row kept its bytes
}

TEST_CASE("registry apply: a key op opens its key without the right to set values; a value op asks for it",
          "[registry][core][apply]") {
    // mutant: every item opens its key with KEY_SET_VALUE, whatever the op
    const bool fast = GENERATE(true, false);
    const bool dry = GENERATE(true, false);
    INFO((fast ? "fast open" : "walk") << (dry ? ", dry run" : ", real run"));
    const auto leaf_masks = [](const FakeRegistry& r) { // the mask of every open, as a number
        std::vector<std::uint32_t> out;
        for (const auto& m : r.masks) out.push_back(static_cast<std::uint32_t>(std::stoul(m.substr(m.rfind(':') + 1), nullptr, 16)));
        return out;
    };
    SECTION("create_key and delete_key") {
        FakeRegistry reg;
        reg.key("Software\\Made");
        reg.put("Software\\Gone", "g", kRegDword, dword(1));
        const auto run = run_plan(reg, json::array({make_key_item("Software\\Made"), del_key_item("Software\\Gone")}), dry, true, fast);
        REQUIRE(run.verdicts() == std::vector<std::string>{dry ? "would_apply" : "applied", dry ? "would_apply" : "applied"});
        REQUIRE_FALSE(reg.masks.empty());
        for (const auto mask : leaf_masks(reg)) CHECK((mask & kKeySetValue) == 0);
        if (fast) {
            CHECK(std::ranges::find(reg.masks, "open_path:Software\\Made:0x1") != reg.masks.end());
            CHECK(std::ranges::find(reg.masks, "open_path:Software\\Gone:0x10009") != reg.masks.end());
        }
    }
    SECTION("set_value and delete_value") {
        FakeRegistry reg;
        reg.put("Software\\Acme", "a", kRegDword, dword(1));
        reg.put("Software\\Other", "b", kRegDword, dword(1));
        const auto run = run_plan(reg, json::array({set_item("Software\\Acme", "a", "2", "REG_DWORD"),
                                                    del_value_item("Software\\Other", "b")}), dry, true, fast);
        REQUIRE(run.out.rc == 0);
        if (fast) {
            CHECK(std::ranges::find(reg.masks, "open_path:Software\\Acme:0x3") != reg.masks.end());
            CHECK(std::ranges::find(reg.masks, "open_path:Software\\Other:0x3") != reg.masks.end());
        }
    }
}

// A value whose RAW UTF-16 name is a lone surrogate (L"V\xD800") enumerates lossily as "V<U+FFFD>", the same bytes as
// its well-formed sibling L"V\xFFFD". A lossy vet captures the sibling twice, NtDeleteKey takes both, and the manifest
// holds two identical rows under undo_complete=1. The vet's enumeration is exact, so the item is refused first.
TEST_CASE("registry apply: delete_key refuses a value whose raw name is not well-formed UTF-16 in both modes",
          "[registry][core][apply]") {
    const std::string lone = "V\xED\xA0\x80"; // the fake's stand-in for the raw L"V\xD800"
    const std::string fffd = "V\xEF\xBF\xBD"; // a real, well-formed U+FFFD name
    const auto build = [&](FakeRegistry& r, bool with_lone) {
        r.put("Software\\Leaf", fffd, kRegDword, dword(2));
        if (with_lone) {
            r.put("Software\\Leaf", lone, kRegDword, dword(1));
            r.key("Software\\Leaf")->values[lone].enum_as = fffd;
        }
        r.put("Software\\Other", "o", kRegDword, dword(3));
    };
    SECTION("a lone-surrogate name next to its U+FFFD lookalike: refused, nothing deleted, the next item unaffected") {
        // mutant: vet_leaf_values enumerates lossily (the item applies and the manifest repeats one row)
        const json plan = json::array({del_key_item("Software\\Leaf"), del_key_item("Software\\Other")});
        FakeRegistry dry_reg, real_reg;
        build(dry_reg, true);
        build(real_reg, true);
        const auto dry = run_plan(dry_reg, plan, true, true);
        const auto real = run_plan(real_reg, plan, false, true);
        CHECK(dry.verdicts() == std::vector<std::string>{"refused", "would_apply"});
        CHECK(real.verdicts() == std::vector<std::string>{"refused", "applied"});
        CHECK(dry.reason(0) == "unrepresentable_name");
        CHECK(real.reason(0) == dry.reason(0));
        REQUIRE(real_reg.exists("Software\\Leaf"));
        CHECK(real_reg.get("Software\\Leaf", lone)->data == dword(1));
        CHECK(real_reg.get("Software\\Leaf", fffd)->data == dword(2));
        CHECK_FALSE(real_reg.exists("Software\\Other"));
        CHECK(real_reg.calls("delete_key_by_handle") == 1); // Other only
        REQUIRE(real.undo.size() == 1);                      // Other's value; nothing from the refused item
        CHECK(real.undo[0] == std::vector<std::string>{"undo", "1", "o", "REG_DWORD", "03000000", "0"});
        CHECK(real.undo_complete());
        CHECK(dry.undo_complete());
    }
    SECTION("a plain U+FFFD name alone is well-formed: applied, and the manifest spells it") {
        const bool dry = GENERATE(true, false);
        FakeRegistry reg;
        build(reg, false);
        const auto run = run_plan(reg, json::array({del_key_item("Software\\Leaf")}), dry);
        CHECK(run.verdict(0) == (dry ? "would_apply" : "applied"));
        if (!dry) {
            REQUIRE(run.undo.size() == 1);
            CHECK(run.undo[0] == std::vector<std::string>{"undo", "0", fffd, "REG_DWORD", "02000000", "0"});
            CHECK_FALSE(reg.exists("Software\\Leaf"));
        }
    }
    SECTION("a lone-surrogate name on a key no item deletes does not matter") {
        const bool dry = GENERATE(true, false);
        FakeRegistry reg;
        build(reg, false);
        reg.put("Software\\Other", lone, kRegDword, dword(1));
        reg.key("Software\\Other")->values[lone].enum_as = fffd;
        const auto run = run_plan(reg, json::array({set_item("Software\\Other", "o", "4", "REG_DWORD"),
                                                    del_key_item("Software\\Leaf")}), dry);
        CHECK(run.verdicts() == (dry ? std::vector<std::string>{"would_apply", "would_apply"}
                                     : std::vector<std::string>{"applied", "applied"}));
        CHECK(reg.get("Software\\Other", lone)->data == dword(1));
    }
}

TEST_CASE("registry apply: a name the manifest cannot spell refuses before anything is opened in both modes",
          "[registry][core][apply]") {
    const bool dry = GENERATE(true, false);
    struct Case {
        json item;
        const char* what;
    };
    const Case cases[] = {
        {set_item("Software\\A", "-", "x"), "a value named \"-\" (the row spelling of the default name)"},
        {set_item("Software\\A", "a|b", "x"), "a pipe in the value name"},
        {set_item("Software\\A|B", "v", "x"), "a pipe in the key"},
        {set_item("Software\\A", "a\xE2\x80\xA8z", "x"), "U+2028"},
        {set_item("Software\\A", "a\xE2\x80\xA9z", "x"), "U+2029"},
        {set_item("Software\\A", "a\xC2\x85z", "x"), "a C1 control (NEL)"},
        {del_value_item("Software\\A", "a\\"), "a trailing backslash"},
    };
    for (const auto& c : cases) {
        INFO(c.what);
        FakeRegistry reg;
        reg.put("Software\\A", "v", kRegDword, dword(1));
        const auto run = run_plan(reg, json::array({c.item}), dry, true);
        CHECK(run.verdict(0) == "refused");
        CHECK(run.reason(0) == "unrepresentable_name");
        CHECK(reg.seam_calls == 0); // refused by the parser's verdict, nothing opened, probed or written
    }
}

TEST_CASE("registry apply: an unreadable previous value refuses before any mutation in both modes",
          "[registry][core][apply]") {
    const bool dry = GENERATE(true, false);
    FakeRegistry reg;
    reg.put("Software\\K", "v", kRegDword, dword(1));
    reg.put("Software\\K", "w", kRegDword, dword(1));
    reg.key("Software\\K")->unreadable_values.insert("v");
    reg.key("Software\\K")->unreadable_values.insert("w");
    const auto run = run_plan(reg, json::array({set_item("Software\\K", "v", "2", "REG_DWORD"), del_value_item("Software\\K", "w")}),
                              dry, true);
    CHECK(run.verdicts() == std::vector<std::string>{"refused", "refused"});
    CHECK(run.reason(0) == "access_denied");
    CHECK(run.reason(1) == "access_denied");
    CHECK(reg.calls("set_value") == 0);
    CHECK(reg.calls("delete_value") == 0);
    CHECK(run.items[0][10] == "unreadable");
}

TEST_CASE("registry apply: a delete_key that mutated but failed its verify still hands back its undo rows",
          "[registry][core][apply]") {
    FakeRegistry reg;
    reg.put("Software\\Del", "a", kRegDword, dword(1));
    reg.put("Software\\Del", "b", kRegSz, sz("x"));
    // the verify reads the deleted handle with the default value name: answer "present" for it
    reg.inject["query_value:"] = 0;
    const auto run = run_plan(reg, json::array({del_key_item("Software\\Del")}), false);
    CHECK(run.verdict(0) == "failed");
    CHECK(run.reason(0) == "verify_mismatch");
    CHECK(run.items[0][8] == "mismatch");
    CHECK_FALSE(reg.exists("Software\\Del")); // it was deleted all the same
    REQUIRE(run.undo.size() == 2);            // mutant: undo rows only when the verify held
    CHECK(run.undo[0][2] == "a");
    CHECK(run.undo[1][2] == "b");
    CHECK(run.out.rc == 1);
}

TEST_CASE("registry apply: stop at the first refused item or carry on and always say partial_failure",
          "[registry][core][apply]") {
    const json plan = json::array({set_item("Software\\A", "one", "1"), del_value_item("Software\\A", "missing"),
                                   set_item("Software\\A", "three", "3")});
    SECTION("continue_on_error=false: the rest are skipped, with no audit line of their own") {
        FakeRegistry reg;
        reg.key("Software\\A");
        const auto run = run_plan(reg, plan, false, false);
        CHECK(run.verdicts() == std::vector<std::string>{"applied", "refused", "skipped"});
        CHECK(run.audits.size() == 2);
        CHECK(reg.get("Software\\A", "three") == nullptr);
        CHECK(run.summary == std::vector<std::string>{"summary", "3", "1", "1", "0", "1", "0", "1"});
        CHECK(run.out.rc == 1);
        CHECK(run.out.lines.back() == "error|partial_failure");
    }
    SECTION("continue_on_error=true: every item is tried") {
        FakeRegistry reg;
        reg.key("Software\\A");
        const auto run = run_plan(reg, plan, false, true);
        CHECK(run.verdicts() == std::vector<std::string>{"applied", "refused", "applied"});
        CHECK(reg.get("Software\\A", "three") != nullptr);
        CHECK(run.out.rc == 1);
    }
    SECTION("nothing refused: rc 0 and no error line") {
        FakeRegistry reg;
        reg.key("Software\\A");
        const auto run = run_plan(reg, json::array({set_item("Software\\A", "one", "1")}), false);
        CHECK(run.out.rc == 0);
        CHECK(run.out.lines.back().rfind("summary|", 0) == 0);
    }
}

TEST_CASE("registry apply: a creating item that fails part-way flags the manifest incomplete and reports what stayed",
          "[registry][core][apply]") {
    FakeRegistry reg;
    reg.key("Software");
    // a stranger puts a value in Mid just before Deeper is created, so the rollback must keep Mid (and New above it)
    reg.before = [&](const std::string& ev) {
        if (ev == "create_sub:Deeper") reg.put("Software\\New\\Mid", "Foreign", kRegDword, dword(1));
    };
    reg.inject["create_sub:Deeper"] = 1450;
    const auto run = run_plan(reg, json::array({set_item("Software\\New\\Mid\\Deeper", "v", "1")}), false);
    CHECK(run.verdict(0) == "failed");
    CHECK(run.reason(0) == "win32:1450");
    CHECK(run.items[0][9] == "2"); // New and Mid are still there
    CHECK_FALSE(run.undo_complete()); // created (2) < missing (3): `created=2` cannot name what to remove
    CHECK(reg.exists("Software\\New\\Mid"));
    CHECK(run.out.rc == 1);
}

TEST_CASE("registry apply: the reverse plan built from the manifest restores the registry byte for byte",
          "[registry][core][apply]") {
    const std::string cafe = "caf\xC3\xA9";
    const std::string longn = long_name('x', 0);
    FakeRegistry reg;
    reg.put("Software\\Acme", "Keep", kRegDword, dword(1));
    reg.put("Software\\Acme", "Gone", kRegSz, sz("bye"));
    reg.put("Software\\Acme", "", kRegSz, sz("dflt"));
    reg.put("Software\\Uni", cafe, kRegDword, dword(7)); // a non-ASCII name: the only value item on its key
    reg.put("Software\\Acme", longn, kRegBinary, B({9, 8}));
    reg.put("Software\\Old", "a", kRegDword, dword(2));
    reg.put("Software\\Old", "b", kRegBinary, B({1, 2, 3}));
    reg.put("Software\\Old", cafe, kRegSz, sz("u"));
    reg.put("Software\\Old", "", kRegDword, dword(4));
    reg.put("Software\\Old", long_name('y', 1), kRegBinary, Bytes{});
    reg.put("Software\\Untouched", "u", kRegDword, dword(0));
    const std::string before = dump(reg);

    const auto fwd = run_plan(reg, json::array({
        set_item("Software\\Acme", "Keep", "99", "REG_DWORD"),
        del_value_item("Software\\Acme", "Gone"),
        set_item("Software\\Acme", "", "new-default"),
        del_value_item("Software\\Uni", cafe),
        set_item("Software\\Acme", "newval", "5", "REG_DWORD"),
        set_item("Software\\Fresh", "v", "1", "REG_DWORD"),
        del_key_item("Software\\Old"),
        hex_item("Software\\Acme", longn, "REG_BINARY", "ff"),
        make_key_item("Software\\Made"),
        set_item("Software\\Caf\xC3\xA9", "v", "1", "REG_DWORD"),
    }), false);
    REQUIRE(fwd.out.rc == 0);
    REQUIRE(fwd.undo_complete());
    REQUIRE(dump(reg) != before);

    // the reverse, read from the rows alone ("-" is the empty default name, a ~ suffix would mean a cut value)
    const auto name_of = [](const std::string& cell) { return cell == "-" ? std::string{} : cell; };
    // A non-ASCII value name is dependent on every other value item on its key (parse_plan), so it is restored in a
    // plan of its own.
    json first = json::array(), second = json::array(), third = json::array();
    const auto non_ascii = [](const std::string& n) {
        return std::ranges::any_of(n, [](char c) { return static_cast<unsigned char>(c) >= 0x80; });
    };
    for (const auto& r : fwd.items) {
        const std::string &op = r[2], &key = r[4], name = name_of(r[5]);
        const std::string &old_state = r[10], &old_type = r[11], &old_hex = r[12];
        const bool made_key = r[9] != "0";
        REQUIRE(old_hex.find('~') == std::string::npos);
        if (op == "set_value" || op == "delete_value") {
            if (old_state == "present") first.push_back(hex_item(key, name, old_type, old_hex));
            else if (made_key) first.push_back(del_key_item(key)); // the write created this key (a single component)
            else first.push_back(del_value_item(key, name));
        } else if (op == "create_key" && made_key) {
            first.push_back(del_key_item(key));
        }
    }
    std::set<std::string> recreated;
    for (const auto& u : fwd.undo) {
        const std::string key = fwd.items.at(std::stoul(u[1]))[4]; // the undo row names its item; the item names the key
        if (recreated.insert(key).second) first.push_back(make_key_item(key));
        (non_ascii(u[2]) ? third : second).push_back(hex_item(key, name_of(u[2]), u[3], u[4]));
    }
    const auto back1 = run_plan(reg, first, false);
    REQUIRE(back1.out.rc == 0);
    const auto back2 = run_plan(reg, second, false);
    REQUIRE(back2.out.rc == 0);
    REQUIRE(third.size() == 1);
    const auto back3 = run_plan(reg, third, false);
    REQUIRE(back3.out.rc == 0);
    CHECK(dump(reg) == before);

    // A TAB name passes `representable` but set_value cannot write it back, so a delete_key over a key holding one is
    // refused unrepresentable_name rather than handing back a manifest that could not restore it.
    reg.put("Software\\Tabbed", "a\tb", kRegDword, dword(1));
    const std::string with_tab = dump(reg);
    const auto tab = run_plan(reg, json::array({del_key_item("Software\\Tabbed")}), false);
    CHECK(tab.verdict(0) == "refused");
    CHECK(tab.reason(0) == "unrepresentable_name");
    CHECK(dump(reg) == with_tab);
}

TEST_CASE("registry apply: each distinct key is opened once and its handle reused whatever the spelling of its case",
          "[registry][core][apply]") {
    FakeRegistry reg;
    reg.put("Software\\Acme", "a", kRegDword, dword(1));
    reg.put("Software\\Acme", "b", kRegDword, dword(1));
    const auto run = run_plan(reg, json::array({set_item("Software\\Acme", "a", "2", "REG_DWORD"),
                                                set_item("SOFTWARE\\ACME", "b", "3", "REG_DWORD")}), false);
    CHECK(run.out.rc == 0);
    CHECK(reg.method_calls("open_path") == 1); // mutant: one open per item
    CHECK(reg.method_calls("root_name") == 1);
    CHECK(reg.method_calls("final_name") == 1);
    CHECK(reg.get("Software\\Acme", "b")->data == dword(3));
    // a key op is never given a value op's handle: the parser refuses them on one key (dependent_items), and two key
    // ops are different keys here, so each opens its own
    FakeRegistry reg2;
    reg2.key("Software\\X");
    reg2.key("Software\\Y");
    const auto keys = run_plan(reg2, json::array({make_key_item("Software\\X"), make_key_item("Software\\Y")}), false);
    CHECK(keys.out.rc == 0);
    CHECK(reg2.method_calls("open_path") == 2);
}

TEST_CASE("registry apply: a 256-item plan over 8 keys issues a fixed number of seam calls at every depth",
          "[registry][core][apply]") {
    // The cost of an apply is one checked open per DISTINCT key plus three seam calls per item
    // (capture, set, read-back), whatever the depth. Per key: root_name + open_path + final_name + the leaf probe + close.
    constexpr std::size_t kKeys = 8, kNames = 32;
    std::vector<std::size_t> real_counts, dry_counts;
    for (const std::size_t depth : {3u, 6u, 10u}) {
        std::string base;
        for (std::size_t i = 0; i + 1 < depth; ++i) base += "K" + std::to_string(i) + "\\";
        for (const bool dry : {false, true}) {
            FakeRegistry reg;
            json plan = json::array();
            for (std::size_t k = 0; k < kKeys; ++k) {
                const std::string key = base + "S" + std::to_string(k);
                for (std::size_t n = 0; n < kNames; ++n) {
                    const std::string name = "n" + std::to_string(n);
                    reg.put(key, name, kRegDword, dword(1));
                    plan.push_back(set_item(key, name, "2", "REG_DWORD"));
                }
            }
            REQUIRE(plan.size() == 256);
            const auto run = run_plan(reg, plan, dry);
            REQUIRE(run.out.rc == 0);
            (dry ? dry_counts : real_counts).push_back(reg.seam_calls);
            INFO("depth " << depth << (dry ? " dry" : " real"));
            CHECK(reg.method_calls("open_path") == kKeys);
            CHECK(reg.method_calls("root_name") == kKeys);
            CHECK(reg.method_calls("final_name") == kKeys);
            CHECK(reg.method_calls("close") == kKeys);
            CHECK(reg.method_calls("open_sub") == 0);
            CHECK(reg.method_calls("create_sub") == 0);
            CHECK(reg.method_calls("set_value") == (dry ? 0u : kKeys * kNames));
            CHECK(reg.seam_calls == kKeys * 5 + kKeys * kNames * (dry ? 1 : 3));
        }
    }
    for (const auto* counts : {&real_counts, &dry_counts}) {
        REQUIRE(counts->size() == 3);
        CHECK((*counts)[0] == (*counts)[1]);
        CHECK((*counts)[1] == (*counts)[2]); // equal at depth 3, 6 and 10
    }
    WARN("seam calls for a 256-item apply over 8 keys: real " << real_counts[0] << ", dry run " << dry_counts[0]
                                                                << " (8*5 + 256*3 and 8*5 + 256*1)");
}

TEST_CASE("registry apply: a plan's reply stays under the dispatcher's 2 MiB capture cap", "[registry][core][apply]") {
    // 100 overwrites of 4,000-byte values and 100 leaf deletes of three 4,000-byte values each: the budget, not the
    // data, decides how much of the previous state is carried, so the whole reply is bounded.
    FakeRegistry reg;
    json plan = json::array();
    for (std::size_t i = 0; i < 100; ++i) {
        const std::string name = "v" + std::to_string(1000 + i).substr(1);
        reg.put("Software\\Big", name, kRegBinary, Bytes(4000, 0xAB));
        plan.push_back(hex_item("Software\\Big", name, "REG_BINARY", "00"));
        const std::string leaf = "Software\\Leaf" + std::to_string(1000 + i).substr(1);
        for (const char* v : {"x", "y", "z"}) reg.put(leaf, v, kRegBinary, Bytes(4000, 0xCD));
        plan.push_back(del_key_item(leaf));
    }
    const auto run = run_plan(reg, plan, false);
    REQUIRE(run.out.rc == 0);
    CHECK_FALSE(run.undo_complete());
    constexpr std::size_t kDispatcherCap = yuzu::agent::LocalDispatcher::kCaptureMaxBytes;
    CHECK(run.bytes() < kDispatcherCap);
    // every row that kept its bytes was charged name + bytes + kUndoRowOverhead against the one budget (all values here
    // are under the 4 KiB capture cap, so a `~` means the budget dropped the bytes and the row was not charged)
    std::size_t retained = 0;
    for (const auto& row : run.items)
        if (row[10] == "present" && row[12].find('~') == std::string::npos)
            retained += row[5].size() + row[12].size() / 2 + kUndoRowOverhead;
    for (const auto& row : run.undo)
        if (row[4].find('~') == std::string::npos) retained += row[2].size() + row[4].size() / 2 + kUndoRowOverhead;
    CHECK(retained <= kCaptureTotalCap);
    WARN("a 200-item plan with 4,000-byte values: reply " << run.bytes() << " bytes of " << kDispatcherCap
                                                          << ", retained " << retained << " of " << kCaptureTotalCap);
}

TEST_CASE("registry apply: each item's rows go out as it concludes and a sink failure stops the plan",
          "[registry][core][apply]") {
    const auto build = [](FakeRegistry& r) {
        r.put("Software\\Del", "a", kRegDword, dword(1));
        r.put("Software\\Del", "b", kRegSz, sz("x"));
        r.put("Software\\B", "v", kRegDword, dword(1));
        r.put("Software\\C", "v", kRegDword, dword(1));
    };
    const json plan = json::array({del_key_item("Software\\Del"), set_item("Software\\B", "v", "2", "REG_DWORD"),
                                   set_item("Software\\C", "v", "3", "REG_DWORD")});
    const auto untouched = [](FakeRegistry& r, const char* key) { return r.get(key, "v")->data == dword(1); };

    SECTION("item N's rows and its undo rows are out before item N+1 opens anything") {
        // mutant: run_apply renders every row and writes them after the loop
        FakeRegistry reg;
        build(reg);
        RecordingCtx ctx;
        std::vector<std::string> seen; // "<row kind>:<B untouched><C untouched>" at the moment each line is written
        ctx.fails = [&](std::string_view t) {
            seen.push_back(std::string{t.substr(0, t.find('|'))} + ":" + (untouched(reg, "Software\\B") ? "1" : "0") +
                           (untouched(reg, "Software\\C") ? "1" : "0"));
            return false;
        };
        const auto run = run_plan(reg, plan, false, false, true, &ctx);
        REQUIRE(run.out.rc == 0);
        CHECK(seen == std::vector<std::string>{"audit:11", "item:11", "undo:11", "undo:11", "audit:01", "item:01",
                                               "audit:00", "item:00", "summary:00"});
    }
    SECTION("a sink failure after item 1's audit line stops the plan: nothing after it is opened or changed") {
        // mutant: the plan carries on after the sink failed (or every row is written after the loop)
        FakeRegistry reg;
        build(reg);
        RecordingCtx ctx;
        ctx.fails = [](std::string_view t) { return t.rfind("item|1|", 0) == 0; };
        const auto run = run_plan(reg, plan, false, false, true, &ctx);
        CHECK(run.out.rc == 1);
        CHECK(run.audits.size() == 2); // items 0 and 1: item 1 mutated and its audit line is out
        CHECK(run.undo.size() == 2);   // item 0's manifest was delivered
        CHECK(run.summary.empty());
        CHECK(run.out.lines.back() == "error|exception");
        CHECK(std::ranges::find(run.out.lines, std::string{exception_audit_line("apply")}) == run.out.lines.end());
        CHECK_FALSE(untouched(reg, "Software\\B"));
        CHECK(untouched(reg, "Software\\C"));
        CHECK(reg.calls("open_path:Software\\C") == 0);
    }
    SECTION("a sink failure on item 1's AUDIT line, with item 0 complete, reaches the seam: the fixed failed row stands for it") {
        // mutant: the audit-coverage flag is per plan, so item 1 (already mutated) loses its audit line AND the fixed row
        FakeRegistry reg;
        build(reg);
        RecordingCtx ctx;
        ctx.fails = [n = 0](std::string_view t) mutable { return t.rfind("audit|", 0) == 0 && n++ == 1; };
        try {
            (void)run_apply(ctx, reg, FakeRegistry::kRoot, plan_of(plan), ApplyOptions{false, false}, true);
            FAIL("the sink failure did not propagate");
        } catch (const std::bad_alloc&) {
            report_exception(ctx, "apply"); // the seam (execute_guarded)
        }
        REQUIRE(ctx.lines.size() == 6);
        CHECK(starts(ctx.lines[0], "audit|op=apply.delete_key|"));
        CHECK(starts(ctx.lines[1], "item|0|"));
        CHECK(starts(ctx.lines[2], "undo|0|a|"));
        CHECK(starts(ctx.lines[3], "undo|0|b|"));
        CHECK(ctx.lines[4] == exception_audit_line("apply")); // item 1 changed the registry: this row is its record
        CHECK(ctx.lines[5] == "error|exception");
        CHECK_FALSE(untouched(reg, "Software\\B"));              // item 1 mutated before its audit line failed
        CHECK(untouched(reg, "Software\\C"));                    // nothing after it was opened
        CHECK(reg.calls("open_path:Software\\C") == 0);
    }
    SECTION("a sink failure on an undo row stops the plan: no later item is opened or changed and no summary goes out") {
        // mutant: an undo-row sink failure only sets the answer to 1 and the plan carries on
        FakeRegistry reg;
        build(reg);
        RecordingCtx ctx;
        ctx.fails = [n = 0](std::string_view t) mutable { return t.rfind("undo|", 0) == 0 && n++ == 0; };
        const auto run = run_plan(reg, plan, false, false, true, &ctx);
        CHECK(run.out.rc == 1);
        CHECK(run.audits.size() == 1); // item 0 only: its audit line is out
        CHECK(run.items.size() == 1);
        CHECK(run.undo.empty());       // the first undo row failed and the second was never offered
        CHECK(run.summary.empty());
        CHECK(run.out.lines.back() == "error|exception");
        CHECK_FALSE(reg.exists("Software\\Del")); // item 0 ran before its rows went out
        CHECK(untouched(reg, "Software\\B"));
        CHECK(untouched(reg, "Software\\C"));
        CHECK(reg.calls("open_path:Software\\B") == 0);
        CHECK(reg.calls("open_path:Software\\C") == 0);
    }
    SECTION("a sink that fails on the first audit line: the failure propagates and nothing after item 0 runs") {
        FakeRegistry reg;
        build(reg);
        RecordingCtx ctx;
        ctx.fails = [n = 0](std::string_view t) mutable { return t.rfind("audit|", 0) == 0 && n++ == 0; };
        try {
            (void)run_apply(ctx, reg, FakeRegistry::kRoot, plan_of(plan), ApplyOptions{false, false}, true);
            FAIL("the sink failure did not propagate");
        } catch (const std::bad_alloc&) {
            report_exception(ctx, "apply"); // the seam (execute_guarded)
        }
        CHECK(ctx.lines == std::vector<std::string>{std::string{exception_audit_line("apply")}, "error|exception"});
        CHECK_FALSE(reg.exists("Software\\Del")); // item 0 ran before its line went out: the fixed line stands for it
        CHECK(untouched(reg, "Software\\B"));
        CHECK(untouched(reg, "Software\\C"));
    }
    SECTION("an exception at item 2 leaves items 0 and 1 and the undo manifest delivered ahead of the fixed line") {
        // mutant: the rows are held until the end of the plan (the exception discards them)
        FakeRegistry reg;
        build(reg);
        int sets = 0;
        reg.before = [&sets](const std::string& ev) {
            if (ev == "set_value:v" && ++sets == 2) throw std::runtime_error("injected");
        };
        RecordingCtx ctx;
        try {
            (void)run_apply(ctx, reg, FakeRegistry::kRoot, plan_of(plan), ApplyOptions{false, false}, true);
            FAIL("no exception");
        } catch (const std::runtime_error&) {
            report_exception(ctx, "apply");
        }
        REQUIRE(ctx.lines.size() == 8);
        CHECK(starts(ctx.lines[0], "audit|op=apply.delete_key|"));
        CHECK(starts(ctx.lines[1], "item|0|"));
        CHECK(starts(ctx.lines[2], "undo|0|a|"));
        CHECK(starts(ctx.lines[3], "undo|0|b|"));
        CHECK(starts(ctx.lines[4], "audit|op=apply.set_value|"));
        CHECK(starts(ctx.lines[5], "item|1|"));
        CHECK(ctx.lines[6] == exception_audit_line("apply"));
        CHECK(ctx.lines[7] == "error|exception");
    }
    SECTION("an exception at item 1 leaves item 0's rows ahead of the fixed line and no handle open") {
        // mutant: the rows are held until the end of the plan, or until the next item concludes
        FakeRegistry reg;
        build(reg);
        reg.before = [](const std::string& ev) {
            if (ev == "set_value:v") throw std::runtime_error("injected");
        };
        RecordingCtx ctx;
        try {
            (void)run_apply(ctx, reg, FakeRegistry::kRoot, plan_of(plan), ApplyOptions{false, false}, true);
            FAIL("no exception");
        } catch (const std::runtime_error&) {
            report_exception(ctx, "apply");
        }
        CHECK(reg.open.empty());
        REQUIRE(ctx.lines.size() == 6);
        CHECK(starts(ctx.lines[0], "audit|op=apply.delete_key|"));
        CHECK(starts(ctx.lines[1], "item|0|"));
        CHECK(starts(ctx.lines[2], "undo|0|a|"));
        CHECK(starts(ctx.lines[3], "undo|0|b|"));
        CHECK(ctx.lines[4] == exception_audit_line("apply"));
        CHECK(ctx.lines[5] == "error|exception");
        CHECK(untouched(reg, "Software\\B"));
    }
}

TEST_CASE("registry apply: an item refused before its capture shows old_state - and never absent",
          "[registry][core][apply]") {
    // mutant: the previous value (default `absent`) and the delete_key counts are rendered for every item
    const bool dry = GENERATE(true, false);
    FakeRegistry reg;
    reg.put("Software\\Acme", "v", kRegDword, dword(1));
    reg.put("Software\\Locked", "w", kRegDword, dword(1));
    reg.put("Software\\Shut", "x", kRegDword, dword(1));
    reg.key("Software\\Locked")->deny_open = true;
    reg.key("Software\\Shut")->deny_open = true;
    reg.put("Software\\Parent", "p", kRegDword, dword(1));
    reg.key("Software\\Parent\\Child");
    reg.put("Software\\Odd", "a", kRegDword, dword(1));
    reg.put("Software\\Odd", "n", 0 /*REG_NONE*/, B({1}));
    const auto run = run_plan(reg,
                              json::array({
                                  set_item("Software\\Acme", "v", "x", "REG_NOPE"), // invalid_type: refused by the parser
                                  del_value_item("Software\\Locked", "w"),           // its open is refused
                                  del_key_item("Software\\Shut"),                    // its open is refused
                                  del_value_item("Software\\Acme", "gone"),          // read: absent is a fact
                                  del_key_item("Software\\Parent"),                  // a subkey: its values never counted
                                  del_key_item("Software\\Odd"),                     // the vet refused part-way
                              }),
                              dry, true);
    REQUIRE(run.verdicts() ==
            std::vector<std::string>{"refused", "refused", "refused", "refused", "refused", "refused"});
    CHECK(run.reason(0) == "invalid_type");
    CHECK(run.reason(1) == "access_denied");
    CHECK(run.reason(2) == "access_denied");
    CHECK(run.reason(3) == "value_not_found");
    CHECK(run.reason(4) == "key_has_subkeys");
    CHECK(run.reason(5) == "unsupported_old_type");
    CHECK(run.items[0][10] == "-");
    CHECK(run.items[1][10] == "-");
    CHECK(run.items[3][10] == "absent");
    REQUIRE(run.audits.size() == 6);
    CHECK(run.audits[0].find("|old_state=-|") != std::string::npos);
    CHECK(run.audits[1].find("|old_state=-|") != std::string::npos);
    CHECK(run.audits[2].find("|counted_keys=-|counted_values=-|capped=-|") != std::string::npos);
    CHECK(run.audits[3].find("|old_state=absent|") != std::string::npos);
    // mutant: counted_values/capped rendered whenever the key was opened (0, or a partial count, for values never read)
    CHECK(run.audits[4].find("|counted_keys=1|counted_values=-|capped=-|") != std::string::npos);
    CHECK(run.audits[5].find("|counted_keys=1|counted_values=-|capped=-|") != std::string::npos);
    CHECK(reg.get("Software\\Acme", "v") != nullptr);
}

TEST_CASE("registry apply: a refused creating item rolls back the keys it made before its row goes out",
          "[registry][core][apply]") {
    // mutant: the rollback is left to the end of run_apply (the row says failed created=1 for a key then removed)
    FakeRegistry reg;
    reg.key("Software");
    reg.inject["query_value:v"] = 5; // the capture on the NEW key is refused (a stand-in for a value planted there)
    RecordingCtx ctx;
    bool existed_at_row = true;
    ctx.fails = [&](std::string_view t) {
        if (t.rfind("item|0|", 0) == 0) existed_at_row = reg.exists("Software\\New");
        return false;
    };
    const auto run = run_plan(reg, json::array({set_item("Software\\New", "v", "1")}), false, false, true, &ctx);
    CHECK(run.verdict(0) == "refused");
    CHECK(run.reason(0) == "access_denied");
    CHECK(run.items[0][9] == "0");
    CHECK_FALSE(existed_at_row);
    CHECK_FALSE(reg.exists("Software\\New"));
    CHECK(run.undo_complete());
    CHECK(run.out.rc == 1);
}

TEST_CASE("registry apply: a refused creating item whose rollback keeps a key reports failed with the residue",
          "[registry][core][apply]") {
    // mutant: the refusal-time rollback's residue is ignored (verdict refused, created 0, or undo_complete left 1)
    FakeRegistry reg;
    reg.key("Software");
    reg.inject["query_value:v"] = 5; // the capture on the NEW leaf is refused
    reg.before = [&reg](const std::string& ev) { // another party writes into the key the walk just made
        if (ev == "create_sub:Deep") reg.put("Software\\New", "stranger", kRegDword, dword(7));
    };
    const auto run = run_plan(reg, json::array({set_item("Software\\New\\Deep", "v", "1")}), false, false, true);
    CHECK(run.verdict(0) == "failed");
    CHECK(run.reason(0) == "access_denied");
    CHECK(run.items[0][9] == "1"); // New stayed (it holds the stranger's value); Deep was removed
    CHECK(reg.exists("Software\\New"));
    CHECK_FALSE(reg.exists("Software\\New\\Deep"));
    CHECK_FALSE(run.undo_complete()); // created < missing: the row cannot name which key stayed
    CHECK(run.out.rc == 1);
}

TEST_CASE("registry apply: a dry run predicts created for items sharing a missing key or ancestor as the real run does",
          "[registry][core][apply]") {
    // mutant: the dry run's sim_created dedupe always counts (insert(...).second replaced by true)
    const json plan = json::array({set_item("Software\\New\\Deep", "b", "1"), set_item("Software\\New\\Deep", "c", "1"),
                                   set_item("Software\\New\\Side", "d", "1")});
    std::vector<std::string> dry_created, real_created;
    for (const bool dry : {true, false}) {
        FakeRegistry reg;
        reg.key("Software");
        const auto run = run_plan(reg, plan, dry);
        REQUIRE(run.out.rc == 0);
        for (const auto& row : run.items) (dry ? dry_created : real_created).push_back(row[9]);
    }
    CHECK(real_created == std::vector<std::string>{"2", "0", "1"});
    CHECK(dry_created == real_created);
}

TEST_CASE("registry apply: set_value and delete_value over a value the manifest cannot restore are refused in both modes",
          "[registry][core][apply]") {
    // mutant: either unsupported_old_type arm of refusal_reason is dropped (the value is overwritten or deleted while
    // the manifest says undo_complete=1)
    const bool dry = GENERATE(true, false);
    FakeRegistry reg;
    reg.put("Software\\K", "n", 0 /*REG_NONE*/, B({1, 2}));
    reg.put("Software\\K", "m", 0 /*REG_NONE*/, B({3}));
    const auto run = run_plan(reg, json::array({set_item("Software\\K", "n", "x"), del_value_item("Software\\K", "m")}),
                              dry, true);
    CHECK(run.verdicts() == std::vector<std::string>{"refused", "refused"});
    CHECK(run.reason(0) == "unsupported_old_type");
    CHECK(run.reason(1) == "unsupported_old_type");
    CHECK(reg.calls("set_value") == 0);
    CHECK(reg.calls("delete_value") == 0);
}

TEST_CASE("registry apply: refused items neither spend the undo budget nor flag a later manifest incomplete",
          "[registry][core][apply]") {
    // mutant: budgeted_old charges every value op that read a previous value, refused ones included. 140 refused rows of
    // 4096 bytes exceed the 512 KiB budget, so the one item that does change loses its bytes and undo_complete drops to 0.
    const bool dry = GENERATE(true, false);
    FakeRegistry reg;
    json plan = json::array();
    for (int i = 0; i < 140; ++i) {
        const std::string name = "n" + std::to_string(i);
        reg.put("Software\\K", name, 0 /*REG_NONE*/, Bytes(kCaptureValueCap, 7)); // present, and not a type apply can write back
        plan.push_back(set_item("Software\\K", name, "x"));
    }
    reg.put("Software\\K", "last", kRegDword, dword(1));
    plan.push_back(set_item("Software\\K", "last", "2", "REG_DWORD"));
    const auto run = run_plan(reg, plan, dry, true);
    REQUIRE(run.items.size() == 141);
    CHECK(run.reason(0) == "unsupported_old_type");
    CHECK(run.reason(139) == "unsupported_old_type");
    CHECK(run.verdict(140) == (dry ? "would_apply" : "applied"));
    CHECK(run.items[0][12] == "~4096");       // a refused row keeps its metadata, not the bytes
    CHECK(run.items[140][12] == "01000000");  // the changed item's previous value is retained whole
    CHECK(run.undo_complete());
}

TEST_CASE("registry core: a child whose ACL denies DELETE refuses a recursive delete at the vet before anything goes",
          "[registry][core][delete_key]") {
    // mutant: count_tree opens children without DELETE (the dry run says ok; the real run deletes A and stops at B)
    const bool dry = GENERATE(true, false);
    FakeRegistry reg;
    reg.key("Software\\T\\A");
    reg.key("Software\\T\\B")->deny_delete_access = true;
    reg.key("Software\\T\\C");
    const auto o = delete_key_tree(reg, FakeRegistry::kRoot, "Software\\T", false, /*recursive=*/true, dry);
    CHECK(o.result == "refused");
    CHECK(o.reason == "access_denied");
    CHECK_FALSE(o.mutated);
    CHECK(reg.exists("Software\\T\\A"));
    CHECK(reg.calls("delete_key_by_handle") == 0);
}

TEST_CASE("registry core: the delete walk stops concurrent_change at a tree one level past the depth bound",
          "[registry][core][delete_key]") {
    // Driven past the vet (delete_key_on directly), as a tree that grew a level between the vet and the delete.
    // mutant: delete_subtree's `depth > kMaxTreeDepth` guard is dropped (the whole chain is deleted)
    const unsigned levels = GENERATE(kMaxTreeDepth, kMaxTreeDepth + 1); // levels below the key
    FakeRegistry reg;
    std::string path = "Software\\Deep";
    for (unsigned i = 0; i < levels; ++i) path += "\\k";
    reg.key(path);
    Opened op = open_checked(reg, FakeRegistry::kRoot, "Software\\Deep",
                             kAccessDelete | kKeyQueryValue | kKeyEnumerateSubKeys, false, /*leaf_may_be_link=*/true);
    REQUIRE(op.error.empty());
    const auto o = delete_key_on(reg, op.handle(), /*recursive=*/true);
    if (levels == kMaxTreeDepth) {
        CHECK(o.ok());
        CHECK_FALSE(reg.exists("Software\\Deep"));
    } else {
        CHECK(o.reason == "concurrent_change");
        CHECK(reg.exists(path)); // post-order: the walk stopped before it deleted anything
    }
}

TEST_CASE("registry apply: an exception mid-write closes every handle and rolls back the keys the item made",
          "[registry][core][apply]") {
    FakeRegistry reg;
    reg.key("Software");
    reg.before = [](const std::string& ev) {
        if (ev == "set_value:v") throw std::runtime_error("injected");
    };
    CHECK_THROWS_AS(run_plan(reg, json::array({set_item("Software\\New\\Deeper", "v", "1")}), false), std::runtime_error);
    CHECK_FALSE(reg.exists("Software\\New")); // ~Opened rolled back what the walk made
    CHECK(reg.method_calls("delete_key_by_handle") == 2);
    // the fake's destructor then checks that no handle was left open
}

TEST_CASE("registry apply: create_key and delete_key refuse a link and a missing key; creating an existing key is a no-op",
          "[registry][core][apply]") {
    FakeRegistry reg;
    reg.put("Real\\Target", "keep", kRegDword, dword(1));
    reg.link("Software\\L", "Real\\Target");
    reg.key("Software\\Plain");
    const auto run = run_plan(reg, json::array({make_key_item("Software\\L"), del_key_item("Software\\L2"),
                                                make_key_item("Software\\Plain")}), true, true);
    // create_key over a link is refused (no op recreates a link), over a plain key it is a no-op that would apply
    CHECK(run.verdict(0) == "refused");
    CHECK(run.reason(0) == "key_is_link");
    CHECK(run.verdict(1) == "refused");
    CHECK(run.reason(1) == "key_not_found");
    CHECK(run.verdict(2) == "would_apply");
    CHECK(run.items[2][9] == "0");
    CHECK(run.audits[2].find("|op=apply.create_key|") != std::string::npos);
    FakeRegistry link_delete;
    link_delete.put("Real\\Target", "keep", kRegDword, dword(1));
    link_delete.link("Software\\L", "Real\\Target");
    const auto del = run_plan(link_delete, json::array({del_key_item("Software\\L")}), false);
    CHECK(del.reason(0) == "key_is_link"); // apply's delete_key is not allowed to remove a link
    CHECK(link_delete.exists("Software\\L"));
    CHECK(link_delete.get("Real\\Target", "keep")->data == dword(1));
}
