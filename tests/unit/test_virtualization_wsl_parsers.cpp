/**
 * test_virtualization_wsl_parsers.cpp -- the pure core of the virtualization `wsl` action:
 * the Ops-templated Lxss walk, the injected per-profile hive-access seam (live and offline
 * outcomes), the shared WalkBudget, decide_wsl and the row formatters. A fake registry and a
 * fake HiveAccessFn stand in for Reg*W and with_user_hive, so every branch runs on every host
 * with no real registry, file, process or clock.
 */
#include <catch2/catch_test_macros.hpp>

#include "virtualization_wsl_parsers.hpp"

#include <algorithm>
#include <array>
#include <cstdio>
#include <deque>
#include <functional>
#include <map>
#include <memory>
#include <optional>
#include <regex>
#include <set>
#include <stdexcept>
#include <string>
#include <string_view>
#include <tuple>
#include <utility>
#include <vector>

namespace wsl = yuzu::virtualization::wsl;
using yuzu::profiles::HiveAccessStatus;
using yuzu::profiles::ProfileInfo;
using yuzu::virtualization::Posture;
using yuzu::virtualization::StatusState;

namespace {

constexpr const char* kSidA = "S-1-5-21-1111111111-2222222222-3333333333-1001";
constexpr const char* kSidB = "S-1-5-21-1111111111-2222222222-3333333333-1002";
constexpr const char* kSidC = "S-1-5-21-1111111111-2222222222-3333333333-1003";

constexpr const char* kGuid1 = "{11111111-2222-3333-4444-555555555555}";
constexpr const char* kGuid2 = "{AAAAAAAA-bbbb-CCCC-dddd-EEEEEEEEEEEE}";

/// The profile-row `outcome` vocabulary (closed): the oracle the production literals are held to.
constexpr std::array<std::string_view, 8> kProfileOutcomes = {
    "not_found",    "privilege_missing", "mount_failed",   "access_denied",
    "file_refused", "unload_failed",     "backup_skipped", "sid_invalid",
};

/// REG_SZ values the README names as never emitted, each seeded with a distinct sentinel so a
/// read-and-emit shows up as that sentinel on the wire (BasePath, VhdFileName and DefaultUid are
/// seeded separately by make_hive). Distribution-key values, then Lxss-key values.
struct Excluded {
    const wchar_t* value;
    const char* sentinel;
};
constexpr Excluded kExcludedDistroValues[] = {
    {L"ShortcutPath", "SECRETSHORTCUT"},
    {L"TerminalProfilePath", "SECRETTERMINAL"},
    {L"PackageFamilyName", "SECRETPKGFAMILY"},
    {L"KernelCommandLine", "SECRETKERNELCMD"},
};
constexpr Excluded kExcludedLxssValues[] = {
    {L"NatIpAddress", "SECRETNATIP"},
    {L"NatNetwork", "SECRETNATNET"},
};

std::wstring w(const std::string& s) { return std::wstring(s.begin(), s.end()); }

// -- fake registry ---------------------------------------------------------------------------

struct Val {
    std::uint32_t type = wsl::kRegSz;
    std::vector<std::byte> data;
    long fail_rc = 0;      // returned for any query when non-zero
    long fill_rc = 0;      // returned by the FILL call only
    std::optional<std::uint32_t> fill_size_override; // a hostile FILL: SUCCESS, but this size
};

struct Node {
    std::vector<std::pair<std::wstring, Node*>> children;
    std::map<std::wstring, Val> values;
    long open_rc = 0;
    long enum_fail_rc = 0; // returned at enum_fail_idx
    std::size_t enum_fail_idx = static_cast<std::size_t>(-1);
    /// Called at the top of every enum_key on this node (before the index is resolved), so a test
    /// can change the children between two enumeration calls the way a concurrent writer would.
    std::function<void(std::uint32_t idx)> on_enum;
};

struct FakeOps {
    std::deque<Node> arena;
    int opens = 0, closes = 0, enums = 0, queries = 0, probes = 0, fills = 0;
    bool throw_on_enum = false;
    std::vector<std::size_t> payload_sizes; // what the REG_SZ decoder was handed, per call
    /// Every (key, value name) the walk asked for, in call order (probe and fill both record).
    std::vector<std::pair<const Node*, std::wstring>> queried;

    /// Every enum_key/query_value call the walk made (each one is preceded by a budget visit).
    std::size_t calls() const { return static_cast<std::size_t>(enums + queries); }

    Node& node() { return arena.emplace_back(); }
    Node& child(Node& parent, const std::wstring& name) {
        Node& c = node();
        parent.children.emplace_back(name, &c);
        return c;
    }

    static void set_sz(Node& n, const wchar_t* name, const std::string& v,
                       std::uint32_t type = wsl::kRegSz) {
        Val val;
        val.type = type;
        for (char c : v)
            val.data.push_back(static_cast<std::byte>(c));
        val.data.push_back(std::byte{0});
        n.values[name] = std::move(val);
    }
    static void set_dword(Node& n, const wchar_t* name, std::uint32_t v) {
        Val val;
        val.type = wsl::kRegDword;
        for (int i = 0; i < 4; ++i)
            val.data.push_back(static_cast<std::byte>((v >> (8 * i)) & 0xff));
        n.values[name] = std::move(val);
    }

    /// The marker a registry link object carries: a `SymbolicLinkValue` value (REG_LINK = 6 on a
    /// real link; the walk accepts any type, so a REG_SZ decoy of that name reads the same way).
    static void set_link(Node& n, std::uint32_t type = 6) {
        set_sz(n, L"SymbolicLinkValue", "\\Registry\\Machine\\SOFTWARE\\Decoy", type);
    }

    long open_key(void* parent, const wchar_t* name, void*& out) {
        auto* p = static_cast<Node*>(parent);
        for (auto& [n, c] : p->children) {
            if (n == name) {
                if (c->open_rc != 0)
                    return c->open_rc;
                out = c;
                ++opens;
                return wsl::kErrorSuccess;
            }
        }
        return wsl::kErrorFileNotFound;
    }
    void close_key(void*) { ++closes; }
    long enum_key(void* parent, std::uint32_t idx, std::wstring& name) {
        if (throw_on_enum)
            throw std::runtime_error("probe: enum threw");
        ++enums;
        auto* p = static_cast<Node*>(parent);
        if (p->on_enum)
            p->on_enum(idx);
        if (idx == p->enum_fail_idx)
            return p->enum_fail_rc;
        if (idx >= p->children.size())
            return wsl::kErrorNoMoreItems;
        name = p->children[idx].first;
        return wsl::kErrorSuccess;
    }
    long query_value(void* key, const wchar_t* name, std::uint32_t& type, std::span<std::byte> buf,
                     std::uint32_t& size) {
        ++queries;
        auto* n = static_cast<Node*>(key);
        queried.emplace_back(n, name);
        auto it = n->values.find(name);
        if (it == n->values.end())
            return wsl::kErrorFileNotFound;
        const Val& v = it->second;
        if (v.fail_rc != 0)
            return v.fail_rc;
        type = v.type;
        const auto need = static_cast<std::uint32_t>(v.data.size());
        if (buf.empty()) {
            ++probes;
            size = need;
            return wsl::kErrorSuccess;
        }
        ++fills;
        if (v.fill_rc != 0)
            return v.fill_rc;
        if (buf.size() < v.data.size()) {
            size = need;
            return wsl::kErrorMoreData;
        }
        std::copy(v.data.begin(), v.data.end(), buf.begin());
        size = v.fill_size_override ? *v.fill_size_override : need;
        return wsl::kErrorSuccess;
    }
    std::string utf8(std::wstring_view s) const { return std::string(s.begin(), s.end()); }
    std::string reg_sz_utf8(std::span<const std::byte> p) {
        payload_sizes.push_back(p.size());
        std::string out;
        for (auto b : p) {
            if (b == std::byte{0})
                break;
            out += static_cast<char>(b);
        }
        return out;
    }
};

struct Distro {
    std::string guid, name;
    std::uint32_t version = 2, state = 1;
    std::string flavor = "ubuntu";
};

/// A hive root holding Lxss with the given distributions; `default_guid` empty = none set.
Node& make_hive(FakeOps& ops, const std::vector<Distro>& distros,
                const std::string& default_guid = {}) {
    Node& root = ops.node();
    Node& lx = ops.child(root, wsl::detail::kLxssPath);
    if (!default_guid.empty())
        FakeOps::set_sz(lx, L"DefaultDistribution", default_guid);
    for (const auto& e : kExcludedLxssValues)
        FakeOps::set_sz(lx, e.value, e.sentinel);
    for (const auto& d : distros) {
        Node& dk = ops.child(lx, w(d.guid));
        FakeOps::set_sz(dk, L"DistributionName", d.name);
        FakeOps::set_dword(dk, L"Version", d.version);
        FakeOps::set_dword(dk, L"State", d.state);
        FakeOps::set_sz(dk, L"Flavor", d.flavor);
        // Values that must never be read or emitted.
        FakeOps::set_sz(dk, L"BasePath", "D:\\wsl-store\\SECRETPATH\\Packages");
        FakeOps::set_sz(dk, L"VhdFileName", "ext4.SECRETVHD");
        FakeOps::set_dword(dk, L"DefaultUid", 424242);
        for (const auto& e : kExcludedDistroValues)
            FakeOps::set_sz(dk, e.value, e.sentinel);
    }
    return root;
}

Node& lxss_of(Node& root) { return *root.children.front().second; }

/// `n` distributions with distinct GUIDs (`tag` keeps them distinct across hives).
std::vector<Distro> many(unsigned tag, int n, const std::string& label) {
    std::vector<Distro> ds;
    for (int k = 0; k < n; ++k) {
        char g[64];
        std::snprintf(g, sizeof g, "{%08x-0000-0000-0000-%012x}", tag, static_cast<unsigned>(k));
        ds.push_back({g, label + "-" + std::to_string(k), 2, 1, "x"});
    }
    return ds;
}

// -- fake access seam ------------------------------------------------------------------------

struct Cfg {
    HiveAccessStatus status = HiveAccessStatus::ok;
    Node* root = nullptr; // walked when status == ok
    std::string refusal;
    bool unload_failed = false;
    long live_rc = wsl::kErrorSuccess;
};

struct FakeAccess {
    std::map<std::string, Cfg> cfg;
    std::map<std::string, int> calls;

    wsl::HiveAccessFn fn() {
        return [this](const ProfileInfo& p, const std::function<void(void*)>& walk) {
            ++calls[p.sid];
            const Cfg& c = cfg.at(p.sid);
            if (c.status == HiveAccessStatus::ok && c.root)
                walk(c.root);
            wsl::HiveAccess a;
            a.status = c.status;
            a.refusal = c.refusal;
            a.unload_failed = c.unload_failed;
            a.live_open_rc = c.live_rc;
            return a;
        };
    }
    int total_calls() const {
        int n = 0;
        for (auto& [k, v] : calls)
            n += v;
        return n;
    }
};

ProfileInfo profile(const std::string& sid, const std::string& name) {
    ProfileInfo p;
    p.sid = sid;
    p.profile_name = name;
    p.profile_path = "C:\\Users\\" + name;
    return p;
}

struct Run {
    wsl::WslReads reads;
    Posture posture;
};

/// Every token in a status reason is `windows:virtualization:wsl:<suffix>` where the suffix is in
/// the closed table or is one of the two cause-bearing families. Run on EVERY dispatch the tests
/// make, so a token that is emitted but missing from kFixedTokenSuffixes (and so from
/// kHeaderReserveBytes) fails whichever case first produces it.
void check_tokens_are_in_the_table(const Posture& p) {
    const std::string prefix{wsl::kTokenPrefix};
    std::size_t at = 0;
    while (at < p.reason.size()) {
        const auto end = p.reason.find(',', at);
        const std::string tok = p.reason.substr(at, end == std::string::npos ? end : end - at);
        INFO("token: " << tok);
        REQUIRE(tok.starts_with(prefix));
        const std::string suffix = tok.substr(prefix.size());
        const bool in_table = std::find(wsl::kFixedTokenSuffixes.begin(),
                                        wsl::kFixedTokenSuffixes.end(),
                                        std::string_view{suffix}) != wsl::kFixedTokenSuffixes.end();
        CHECK((in_table || suffix.starts_with("package_") || suffix.starts_with("profile_list_")));
        if (end == std::string::npos)
            break;
        at = end + 1;
    }
}

Run run(std::vector<ProfileInfo> profiles, FakeAccess& acc, FakeOps& ops, wsl::WalkBudget& budget) {
    Run r;
    wsl::collect_wsl(std::span<const ProfileInfo>{profiles}, acc.fn(), ops, budget, r.reads);
    r.posture = wsl::decide_wsl(r.reads);
    check_tokens_are_in_the_table(r.posture);
    return r;
}

Run run(std::vector<ProfileInfo> profiles, FakeAccess& acc, FakeOps& ops) {
    wsl::WalkBudget budget;
    return run(std::move(profiles), acc, ops, budget);
}

bool has_row(const Posture& p, const std::string& row) {
    return std::find(p.rows.begin(), p.rows.end(), row) != p.rows.end();
}

std::string joined(const Posture& p) {
    std::string s = p.reason;
    for (const auto& r : p.rows)
        s += "\n" + r;
    return s;
}

bool has_token(const Posture& p, const std::string& suffix) {
    return p.reason.find(std::string{wsl::kTokenPrefix} + suffix) != std::string::npos;
}

std::size_t fields(const std::string& row) {
    std::size_t n = 1;
    for (std::size_t i = 0; i < row.size(); ++i) {
        if (row[i] == '\\' && i + 1 < row.size())
            ++i;
        else if (row[i] == '|')
            ++n;
    }
    return n;
}

} // namespace

// ---------------------------------------------------------------------------------------------

TEST_CASE("wsl: a loaded hive lists its distributions with default, version and state",
          "[virtualization][wsl]") {
    FakeOps ops;
    Node& hive = make_hive(ops, {{kGuid1, "Ubuntu-26.04", 2, 1, "ubuntu"},
                                 {kGuid2, "Legacy", 1, 3, "-"}},
                           kGuid1);
    FakeAccess acc;
    acc.cfg[kSidA] = {HiveAccessStatus::ok, &hive};
    const auto r = run({profile(kSidA, "alice")}, acc, ops);

    CHECK(r.posture.status == StatusState::supported);
    CHECK(r.posture.reason.empty());
    REQUIRE(r.posture.rows.size() == 3);
    CHECK(r.posture.rows[0] == "summary|2|1|1|0|-");
    CHECK(r.posture.rows[1] == "distribution|alice|Legacy|1|installing|no|-");
    CHECK(r.posture.rows[2] == "distribution|alice|Ubuntu-26.04|2|installed|yes|ubuntu");
    CHECK(ops.opens == ops.closes);
}

TEST_CASE("wsl: the offline arm is indistinguishable on the wire; ok ignores a refused live root",
          "[virtualization][wsl]") {
    FakeOps ops;
    Node& hive = make_hive(ops, {{kGuid1, "Debian", 2, 1, "debian"}});
    FakeAccess live, offline;
    live.cfg[kSidA] = {HiveAccessStatus::ok, &hive};
    offline.cfg[kSidA] = {HiveAccessStatus::ok, &hive, "", false, wsl::kErrorAccessDenied};
    const auto a = run({profile(kSidA, "alice")}, live, ops);
    const auto b = run({profile(kSidA, "alice")}, offline, ops);
    CHECK(a.posture.rows == b.posture.rows);
    CHECK(b.posture.status == StatusState::supported);
    CHECK_FALSE(has_token(b.posture, "hive_access_denied"));
}

TEST_CASE("wsl: a guard refusal skips the walk, is carried verbatim and spares other profiles",
          "[virtualization][wsl]") {
    for (const char* lit : {"hive_path_unc", "hive_stat_failed:win32_5"}) {
        FakeOps ops;
        Node& hive = make_hive(ops, {{kGuid1, "Ubuntu", 2, 1, "ubuntu"}});
        FakeAccess acc;
        acc.cfg[kSidA] = {HiveAccessStatus::ok, &hive};
        acc.cfg[kSidB] = {HiveAccessStatus::file_refused, nullptr, lit};
        const auto r = run({profile(kSidA, "alice"), profile(kSidB, "bob")}, acc, ops);
        CHECK(r.posture.status == StatusState::constrained);
        CHECK(has_token(r.posture, "hive_file_refused"));
        const std::string row = std::string{"profile|bob|file_refused|"} + lit;
        CHECK(has_row(r.posture, row));
        CHECK(fields(row) == 4);
        CHECK(r.posture.rows[0] == "summary|1|1|1|1|-");
        CHECK(has_row(r.posture, "distribution|alice|Ubuntu|2|installed|no|ubuntu"));
    }
}

TEST_CASE("wsl: every failed status x live-root code maps to one outcome, access_denied first",
          "[virtualization][wsl]") {
    struct Case {
        HiveAccessStatus st;
        const char* outcome;
        const char* token;
    };
    const Case cases[] = {
        {HiveAccessStatus::not_found, "not_found", "hive_not_found"},
        {HiveAccessStatus::privilege_missing, "privilege_missing", "hive_privilege_missing"},
        {HiveAccessStatus::mount_failed, "mount_failed", "hive_mount_failed"},
        {HiveAccessStatus::file_refused, "file_refused", "hive_file_refused"},
    };
    for (const auto& c : cases) {
        for (const long live : {wsl::kErrorFileNotFound, wsl::kErrorAccessDenied}) {
            FakeOps ops;
            Node& hive = make_hive(ops, {{kGuid1, "Ubuntu", 2, 1, "ubuntu"}});
            FakeAccess acc;
            const char* const refusal =
                c.st == HiveAccessStatus::file_refused ? "hive_hardlinked" : "";
            acc.cfg[kSidA] = {c.st, nullptr, refusal, false, live};
            acc.cfg[kSidB] = {HiveAccessStatus::ok, &hive};
            const auto r = run({profile(kSidA, "alice"), profile(kSidB, "bob")}, acc, ops);
            INFO(c.outcome << " live=" << live);
            const bool denied = (live == wsl::kErrorAccessDenied);
            const std::string outcome = denied ? "access_denied" : c.outcome;
            const std::string token = denied ? "hive_access_denied" : c.token;
            const std::string detail =
                c.st == HiveAccessStatus::file_refused ? "hive_hardlinked" : "-";
            CHECK(has_row(r.posture, "profile|alice|" + outcome + "|" + detail));
            CHECK(has_token(r.posture, token));
            CHECK(acc.calls[kSidB] == 1); // the next profile is still accessed and listed
            CHECK(r.posture.rows[0] == "summary|1|1|1|1|-");
        }
    }
}

// The salted mount name embeds the SID and never leaves the Windows shell: HiveAccess has no field
// to carry it, so this case cannot observe a mount-name leak (feeding the name to a fake that has
// nowhere to put it proves nothing). That half of the contract is pinned lexically, with a
// mutation, in tests/test_virtualization_wsl_pin_lexical.py ("mount_name copied into the
// result"). What this case does prove: unload_failed is processed independently of the access
// status, and no SID or mount-name prefix reaches any emitted row.
TEST_CASE("wsl: unload_failed is independent of the access status; no SID reaches a row",
          "[virtualization][wsl]") {
    struct Case {
        HiveAccessStatus st;
        std::string refusal;
        bool expect_failure_row;
        std::string failure_row;
    };
    const Case cases[] = {
        {HiveAccessStatus::ok, "", false, ""},
        {HiveAccessStatus::file_refused, "hive_identity_changed", true,
         "profile|alice|file_refused|hive_identity_changed"},
        {HiveAccessStatus::mount_failed, "", true, "profile|alice|mount_failed|-"},
    };
    for (const auto& c : cases) {
        FakeOps ops;
        Node& hive = make_hive(ops, {{kGuid1, "Ubuntu", 2, 1, "ubuntu"}});
        FakeAccess acc;
        acc.cfg[kSidA] = {c.st, &hive, c.refusal, true};
        const auto r = run({profile(kSidA, "alice")}, acc, ops);
        CHECK(has_row(r.posture, "profile|alice|unload_failed|-"));
        CHECK(has_token(r.posture, "hive_unload_failed"));
        CHECK(r.posture.status == StatusState::constrained);
        if (c.expect_failure_row) {
            CHECK(has_row(r.posture, c.failure_row));
            CHECK(r.posture.rows[0].starts_with("summary|0|0|0|1|"));
        } else {
            // The hive was read: the distribution stays, profiles_read counts it, not_loaded
            // does not.
            CHECK(r.posture.rows[0] == "summary|1|1|1|0|-");
            CHECK(has_row(r.posture, "distribution|alice|Ubuntu|2|installed|no|ubuntu"));
        }
        const std::string all = joined(r.posture);
        CHECK(all.find("S-1-5-") == std::string::npos);
        CHECK(all.find("YUZU_HIVE") == std::string::npos);
    }
}

TEST_CASE("wsl: a .bak entry and an invalid SID are named and never accessed",
          "[virtualization][wsl]") {
    FakeOps ops;
    FakeAccess acc;
    acc.cfg[kSidA] = {HiveAccessStatus::not_found};
    const std::string bak = std::string{kSidA} + ".bak";
    const auto r = run({profile(bak, "oldalice"), profile("not-a-sid", "mallory"),
                        profile("S-1-5-21-1-2-", "trailing"), profile(kSidA, "alice")},
                       acc, ops);
    CHECK(acc.calls[bak] == 0);
    CHECK(acc.calls["not-a-sid"] == 0);
    CHECK(acc.calls["S-1-5-21-1-2-"] == 0);
    CHECK(acc.calls[kSidA] == 1);
    CHECK(has_row(r.posture, "profile|oldalice|backup_skipped|-"));
    CHECK(has_row(r.posture, "profile|mallory|sid_invalid|-"));
    CHECK(has_row(r.posture, "profile|trailing|sid_invalid|-"));
    CHECK(has_token(r.posture, "profile_backup_skipped"));
    CHECK(has_token(r.posture, "profile_sid_invalid"));
    CHECK(r.posture.rows[0] == "summary|0|0|0|4|-");
}

TEST_CASE("wsl: an unreadable ProfileImagePath is reported whatever the hive access does",
          "[virtualization][wsl]") {
    // The producer sets only the flag (no record failure) for a zero-length, over-cap or
    // wrong-typed value, so this is the one place the token can come from for such a profile.
    const auto unreadable = [](const std::string& sid) {
        ProfileInfo p;
        p.sid = sid;
        p.profile_path_unreadable = true; // no folder name, no path
        return p;
    };

    SECTION("a reachable live hive keeps its rows under account `-` and is still constrained") {
        FakeOps ops;
        Node& hive = make_hive(ops, {{kGuid1, "Ubuntu", 2, 1, "ubuntu"}});
        FakeAccess acc;
        acc.cfg[kSidA] = {HiveAccessStatus::ok, &hive};
        const auto r = run({unreadable(kSidA)}, acc, ops);
        CHECK(acc.calls[kSidA] == 1); // still accessed
        CHECK(has_row(r.posture, "distribution|-|Ubuntu|2|installed|no|ubuntu"));
        CHECK(has_token(r.posture, "profile_unreadable"));
        CHECK_FALSE(has_token(r.posture, "hive_not_found"));
        CHECK(r.posture.status == StatusState::constrained);
        CHECK(r.posture.rows[0] == "summary|1|1|1|0|-");
    }
    SECTION("an unreachable hive carries both tokens") {
        FakeOps ops;
        FakeAccess acc;
        acc.cfg[kSidA] = {HiveAccessStatus::not_found};
        const auto r = run({unreadable(kSidA)}, acc, ops);
        CHECK(has_token(r.posture, "hive_not_found"));
        CHECK(has_token(r.posture, "profile_unreadable"));
        CHECK(has_row(r.posture, "profile|-|not_found|-"));
        CHECK(r.posture.status == StatusState::constrained);
    }
    SECTION("several such profiles are one token") {
        FakeOps ops;
        Node& hive = make_hive(ops, {{kGuid1, "Ubuntu", 2, 1, "ubuntu"}});
        FakeAccess acc;
        acc.cfg[kSidA] = {HiveAccessStatus::ok, &hive};
        acc.cfg[kSidB] = {HiveAccessStatus::not_found};
        const auto r = run({unreadable(kSidA), unreadable(kSidB)}, acc, ops);
        const std::string needle = std::string{wsl::kTokenPrefix} + "profile_unreadable";
        std::size_t hits = 0;
        for (auto at = r.posture.reason.find(needle); at != std::string::npos;
             at = r.posture.reason.find(needle, at + needle.size()))
            ++hits;
        CHECK(hits == 1);
        CHECK(std::count(r.reads.tokens.begin(), r.reads.tokens.end(), "profile_unreadable") == 1);
    }
    SECTION("a readable profile record adds no token") {
        FakeOps ops;
        Node& hive = make_hive(ops, {{kGuid1, "Ubuntu", 2, 1, "ubuntu"}});
        FakeAccess acc;
        acc.cfg[kSidA] = {HiveAccessStatus::ok, &hive};
        const auto r = run({profile(kSidA, "alice")}, acc, ops);
        CHECK_FALSE(has_token(r.posture, "profile_unreadable"));
        CHECK(r.posture.status == StatusState::supported);
    }
}

TEST_CASE("wsl: the SID validator accepts only S-1-<n>(-<n>)*", "[virtualization][wsl]") {
    CHECK(wsl::is_valid_sid_string(kSidA));
    CHECK(wsl::is_valid_sid_string("S-1-5-18"));
    CHECK_FALSE(wsl::is_valid_sid_string(""));
    CHECK_FALSE(wsl::is_valid_sid_string("S-1-"));
    CHECK_FALSE(wsl::is_valid_sid_string("S-1-5--1"));
    CHECK_FALSE(wsl::is_valid_sid_string("S-1-5-1a"));
    CHECK_FALSE(wsl::is_valid_sid_string(std::string{"S-1-"} + std::string(300, '1')));
}

// -- budget ----------------------------------------------------------------------------------

namespace {

struct Fleet {
    FakeOps ops;
    FakeAccess acc;
    std::vector<ProfileInfo> profiles;

    explicit Fleet(int per_hive = 2) {
        const char* sids[] = {kSidA, kSidB, kSidC};
        const char* names[] = {"alice", "bob", "carol"};
        for (int i = 0; i < 3; ++i) {
            std::vector<Distro> ds;
            for (int k = 0; k < per_hive; ++k) {
                char g[64];
                std::snprintf(g, sizeof g, "{0000000%d-0000-0000-0000-00000000000%d}", i + 1, k);
                ds.push_back({g, std::string{names[i]} + "-d" + std::to_string(k), 2, 1, "x"});
            }
            Node& hive = make_hive(ops, ds);
            // A and C are loaded hives, B arrives through the offline arm.
            acc.cfg[sids[i]] = {HiveAccessStatus::ok, &hive, "", false,
                                i == 1 ? wsl::kErrorAccessDenied : wsl::kErrorSuccess};
            profiles.push_back(profile(sids[i], names[i]));
        }
    }
};

} // namespace

TEST_CASE("wsl: the row bound trips alone, inside the second hive, and the third is never accessed",
          "[virtualization][wsl][budget]") {
    Fleet f(8);
    wsl::WalkBudget big;
    const auto full = run(f.profiles, f.acc, f.ops, big);
    REQUIRE(full.posture.rows.size() == 1 + 24);
    CHECK(full.posture.status == StatusState::supported);

    Fleet g(8);
    wsl::WalkBudget capped(/*max_rows=*/12, wsl::kDefaultMaxBytes, wsl::kDefaultMaxVisited);
    const auto r = run(g.profiles, g.acc, g.ops, capped);
    CHECK(has_token(r.posture, "row_cap"));
    CHECK_FALSE(has_token(r.posture, "entry_cap"));
    CHECK(g.acc.calls[kSidB] == 1); // the cap tripped inside B ...
    CHECK(g.acc.calls[kSidC] == 0); // ... and C was never reached
    // 12 rows - 2 reserved = 10 retained distributions; the summary counts exactly those.
    CHECK(r.posture.rows.size() == 1 + 10);
    // C was never reached: it is counted as not loaded, with no row (the budget is spent).
    CHECK(r.posture.rows[0] == "summary|10|10|2|1|-");
    CHECK(g.ops.opens == g.ops.closes);
}

TEST_CASE("wsl: the byte bound trips alone, at the exact byte", "[virtualization][wsl][budget]") {
    Fleet f(3);
    wsl::WalkBudget big;
    (void)run(f.profiles, f.acc, f.ops, big);
    const std::size_t exact = big.rows.bytes;

    Fleet fit(3);
    wsl::WalkBudget at(wsl::kDefaultMaxRows, exact, wsl::kDefaultMaxVisited);
    const auto ok = run(fit.profiles, fit.acc, fit.ops, at);
    CHECK_FALSE(has_token(ok.posture, "row_cap"));

    Fleet tight(3);
    wsl::WalkBudget under(wsl::kDefaultMaxRows, exact - 1, wsl::kDefaultMaxVisited);
    const auto r = run(tight.profiles, tight.acc, tight.ops, under);
    CHECK(has_token(r.posture, "row_cap"));
    CHECK(under.rows.bytes <= exact - 1);
    CHECK(r.posture.rows.size() == 1 + 8);
    CHECK(tight.ops.opens == tight.ops.closes); // the mid-walk stop closed every key
}

TEST_CASE("wsl: the visited-entry bound trips alone and stops the loop",
          "[virtualization][wsl][budget]") {
    Fleet f(2);
    wsl::WalkBudget big;
    (void)run(f.profiles, f.acc, f.ops, big);
    const std::size_t exact = big.visited;
    REQUIRE(exact > 10);

    Fleet fit(2);
    wsl::WalkBudget at(wsl::kDefaultMaxRows, wsl::kDefaultMaxBytes, exact);
    CHECK_FALSE(has_token(run(fit.profiles, fit.acc, fit.ops, at).posture, "entry_cap"));
    CHECK(fit.ops.calls() <= at.max_visited); // every registry call was preceded by a visit
    CHECK(fit.ops.calls() == at.visited);

    Fleet cut(2);
    wsl::WalkBudget under(wsl::kDefaultMaxRows, wsl::kDefaultMaxBytes, exact - 1);
    const auto r = run(cut.profiles, cut.acc, cut.ops, under);
    CHECK(has_token(r.posture, "entry_cap"));
    CHECK_FALSE(has_token(r.posture, "row_cap"));
    CHECK_FALSE(has_token(r.posture, "hive_entry_cap"));
    CHECK(cut.acc.calls[kSidC] == 1); // the last call of the last hive was the one refused
    CHECK(cut.ops.opens == cut.ops.closes);
    CHECK(cut.ops.calls() <= under.max_visited);
    CHECK(cut.ops.calls() == exact - 1); // the refused call was never made

    Fleet early(2);
    wsl::WalkBudget tiny(wsl::kDefaultMaxRows, wsl::kDefaultMaxBytes, 3);
    const auto e = run(early.profiles, early.acc, early.ops, tiny);
    CHECK(has_token(e.posture, "entry_cap"));
    CHECK(early.acc.calls[kSidB] == 0); // stopped in A: later profiles never accessed
    CHECK(early.acc.calls[kSidC] == 0);
    CHECK(early.ops.calls() <= tiny.max_visited);
    CHECK(early.ops.opens == early.ops.closes);
    // B and C were never reached: counted (A was reached, its hive read).
    CHECK(e.reads.profiles_not_loaded == 2);

    // Production limits are the documented ones.
    wsl::WalkBudget prod;
    CHECK(prod.rows.max_rows == 1024);
    CHECK(prod.rows.max_bytes == 262144);
    CHECK(prod.max_visited == 4096);
    CHECK(prod.max_visited_per_hive == 512);
    CHECK(prod.max_rows_per_hive == 128);
    CHECK(prod.max_bytes_per_hive == 32768);
}

TEST_CASE("wsl: the per-hive call bound ends that hive alone; later hives are still walked",
          "[virtualization][wsl][budget]") {
    FakeOps ops;
    Node& ha = make_hive(ops, many(1, 8, "hostile"));
    Node& hb = make_hive(ops, many(2, 2, "bob"));
    Node& hc = make_hive(ops, many(3, 2, "carol"));
    FakeAccess acc;
    acc.cfg[kSidA] = {HiveAccessStatus::ok, &ha};
    acc.cfg[kSidB] = {HiveAccessStatus::ok, &hb, "", false, wsl::kErrorAccessDenied};
    acc.cfg[kSidC] = {HiveAccessStatus::ok, &hc};
    // 20 calls per hive: A (2 + 8 per distribution: the link probe, DefaultDistribution, then per
    // distribution the enum, its link probe and six value calls) is cut inside its third
    // distribution; B and C (2 + 2 x 8 + 1 = 19) fit. The dispatch-wide caps are the production
    // ones.
    wsl::WalkBudget b(wsl::kDefaultMaxRows, wsl::kDefaultMaxBytes, wsl::kDefaultMaxVisited,
                      /*max_visited_per_hive=*/20, wsl::kDefaultMaxRowsPerHive);
    const auto r = run({profile(kSidA, "alice"), profile(kSidB, "bob"), profile(kSidC, "carol")},
                       acc, ops, b);

    CHECK(has_token(r.posture, "hive_entry_cap"));
    CHECK_FALSE(has_token(r.posture, "entry_cap"));
    CHECK_FALSE(has_token(r.posture, "row_cap"));
    CHECK(r.posture.status == StatusState::constrained);
    CHECK(acc.calls[kSidB] == 1); // the trip was NOT a dispatch stop
    CHECK(acc.calls[kSidC] == 1);
    // alice keeps the two distributions read whole; the half-read third is discarded.
    CHECK(r.posture.rows[0] == "summary|6|6|3|0|-");
    CHECK(has_row(r.posture, "distribution|alice|hostile-1|2|installed|no|x"));
    CHECK_FALSE(has_row(r.posture, "distribution|alice|hostile-2|2|installed|no|x"));
    CHECK(has_row(r.posture, "distribution|carol|carol-1|2|installed|no|x"));
    CHECK(ops.calls() == b.visited);
    CHECK(ops.opens == ops.closes);
    // The counters are per hive, not cumulative: the dispatch total is the sum of three hives.
    CHECK(b.visited == 20 + 19 + 19);
}

TEST_CASE("wsl: the per-hive row bound ends that hive alone; later hives are still walked",
          "[virtualization][wsl][budget]") {
    FakeOps ops;
    Node& ha = make_hive(ops, many(1, 8, "hostile"));
    Node& hb = make_hive(ops, many(2, 2, "bob"));
    Node& hc = make_hive(ops, many(3, 2, "carol"));
    FakeAccess acc;
    acc.cfg[kSidA] = {HiveAccessStatus::ok, &ha};
    acc.cfg[kSidB] = {HiveAccessStatus::ok, &hb, "", false, wsl::kErrorAccessDenied};
    acc.cfg[kSidC] = {HiveAccessStatus::ok, &hc};
    wsl::WalkBudget b(wsl::kDefaultMaxRows, wsl::kDefaultMaxBytes, wsl::kDefaultMaxVisited,
                      wsl::kDefaultMaxVisitedPerHive, /*max_rows_per_hive=*/3);
    const auto r = run({profile(kSidA, "alice"), profile(kSidB, "bob"), profile(kSidC, "carol")},
                       acc, ops, b);

    CHECK(has_token(r.posture, "hive_row_cap"));
    CHECK_FALSE(has_token(r.posture, "row_cap"));
    CHECK_FALSE(has_token(r.posture, "entry_cap"));
    CHECK_FALSE(has_token(r.posture, "hive_entry_cap"));
    CHECK(acc.calls[kSidB] == 1);
    CHECK(acc.calls[kSidC] == 1);
    CHECK(r.posture.rows[0] == "summary|7|7|3|0|-"); // 3 + 2 + 2
    CHECK(has_row(r.posture, "distribution|alice|hostile-2|2|installed|no|x"));
    CHECK_FALSE(has_row(r.posture, "distribution|alice|hostile-3|2|installed|no|x"));
    // The refused fourth distribution is detected before its values are read:
    // A = 2 + 3 x 8 + the enum that listed the fourth; B and C = 19 each.
    CHECK(b.visited == 27 + 19 + 19);
    CHECK(ops.opens == ops.closes);
}

TEST_CASE("wsl: the per-hive byte bound ends that hive alone; later hives are still walked",
          "[virtualization][wsl][budget]") {
    FakeOps ops;
    Node& ha = make_hive(ops, many(1, 8, "hostile"));
    Node& hb = make_hive(ops, many(2, 2, "bob"));
    Node& hc = make_hive(ops, many(3, 2, "carol"));
    FakeAccess acc;
    acc.cfg[kSidA] = {HiveAccessStatus::ok, &ha};
    acc.cfg[kSidB] = {HiveAccessStatus::ok, &hb, "", false, wsl::kErrorAccessDenied};
    acc.cfg[kSidC] = {HiveAccessStatus::ok, &hc};
    // Room for exactly three of alice's rows (every one is the same length, + the newline); bob's
    // and carol's two rows each are shorter, so only alice's hive reaches the allowance.
    const std::size_t alice_row =
        std::string{"distribution|alice|hostile-0|2|installed|no|x"}.size() + 1;
    wsl::WalkBudget b(wsl::kDefaultMaxRows, wsl::kDefaultMaxBytes, wsl::kDefaultMaxVisited,
                      wsl::kDefaultMaxVisitedPerHive, wsl::kDefaultMaxRowsPerHive,
                      /*max_bytes_per_hive=*/3 * alice_row);
    const auto r = run({profile(kSidA, "alice"), profile(kSidB, "bob"), profile(kSidC, "carol")},
                       acc, ops, b);

    CHECK(has_token(r.posture, "hive_row_cap"));
    CHECK_FALSE(has_token(r.posture, "row_cap"));
    CHECK_FALSE(has_token(r.posture, "entry_cap"));
    CHECK_FALSE(has_token(r.posture, "hive_entry_cap"));
    CHECK(r.posture.status == StatusState::constrained);
    CHECK(acc.calls[kSidB] == 1); // the trip was NOT a dispatch stop
    CHECK(acc.calls[kSidC] == 1);
    CHECK(r.posture.rows[0] == "summary|7|7|3|0|-"); // 3 + 2 + 2
    CHECK(has_row(r.posture, "distribution|alice|hostile-2|2|installed|no|x"));
    CHECK_FALSE(has_row(r.posture, "distribution|alice|hostile-3|2|installed|no|x"));
    CHECK(has_row(r.posture, "distribution|carol|carol-1|2|installed|no|x"));
    // The byte counter is per hive: A = 2 + 4 x 8 (the fourth is read whole, then refused), B and
    // C = 19 each; the refused row was never charged to the dispatch budget.
    CHECK(b.visited == 34 + 19 + 19);
    CHECK(b.rows.bytes == wsl::kHeaderReserveBytes + 3 * alice_row + 2 * 40 + 2 * 44);
    CHECK(ops.opens == ops.closes);
}

TEST_CASE("wsl: with production limits one hive of worst-case rows cannot starve the next profile",
          "[virtualization][wsl][budget]") {
    // Names and flavours at the largest escaped size a 4 KiB REG_SZ can produce: 2047 pipes, each
    // emitted as two bytes. Before the per-hive byte allowance, ~31 such rows spent the whole
    // 256 KiB dispatch budget and the second profile was never accessed.
    const std::string pipes(2047, '|');
    FakeOps ops;
    std::vector<Distro> hostile = many(1, 40, "x");
    for (auto& d : hostile) {
        d.name = pipes;
        d.flavor = pipes;
    }
    Node& ha = make_hive(ops, hostile);
    Node& hb = make_hive(ops, many(2, 2, "bob"));
    FakeAccess acc;
    acc.cfg[kSidA] = {HiveAccessStatus::ok, &ha};
    acc.cfg[kSidB] = {HiveAccessStatus::ok, &hb};
    wsl::WalkBudget b; // production limits, nothing overridden
    const auto r = run({profile(kSidA, "alice"), profile(kSidB, "bob")}, acc, ops, b);

    CHECK(acc.calls[kSidB] == 1);
    CHECK(has_token(r.posture, "hive_row_cap"));
    CHECK_FALSE(has_token(r.posture, "row_cap"));
    CHECK_FALSE(has_token(r.posture, "entry_cap"));
    CHECK(r.posture.status == StatusState::constrained);
    CHECK(has_row(r.posture, "distribution|bob|bob-0|2|installed|no|x"));
    CHECK(has_row(r.posture, "distribution|bob|bob-1|2|installed|no|x"));

    REQUIRE(r.reads.hives.size() == 2);
    const auto& alice = r.reads.hives[0];
    REQUIRE_FALSE(alice.distros.empty());
    CHECK(alice.distros.size() < 40);
    std::size_t alice_bytes = 0;
    for (const auto& d : alice.distros)
        alice_bytes += wsl::format_distribution_row(alice.account, d).size() + 1;
    CHECK(alice_bytes <= b.max_bytes_per_hive);
    // One more such row would have crossed it: the cap fired on the byte allowance, not by chance.
    CHECK(alice_bytes + wsl::format_distribution_row(alice.account, alice.distros.front()).size() +
              1 >
          b.max_bytes_per_hive);

    // The summary counts are the rows that exist.
    const auto n_rows = static_cast<std::size_t>(
        std::count_if(r.posture.rows.begin(), r.posture.rows.end(),
                      [](const std::string& row) { return row.rfind("distribution|", 0) == 0; }));
    CHECK(n_rows == alice.distros.size() + 2);
    CHECK(r.posture.rows[0].rfind("summary|" + std::to_string(n_rows) + "|", 0) == 0);
    CHECK(ops.opens == ops.closes);
}

namespace {

/// SIDs `S-1-5-21-9-9-9-<n>`, the profile folder name `u<n>` (two characters for n < 10).
std::string numbered_sid(int n) { return "S-1-5-21-9-9-9-" + std::to_string(n); }
std::string numbered_name(int n) { return "u" + std::to_string(n); }

/// `n` distributions (tag keeps GUIDs distinct) each of whose wire row, for a two-character
/// account, is exactly `row_bytes` including the newline: the arithmetic below is then exact.
std::vector<Distro> sized_rows(unsigned tag, int n, std::size_t row_bytes) {
    const std::string fixed = "distribution|u0||2|installed|no|x"; // a row with an empty name
    REQUIRE(row_bytes > fixed.size() + 1);
    const std::string name(row_bytes - (fixed.size() + 1), 'n');
    std::vector<Distro> ds;
    for (int k = 0; k < n; ++k) {
        char g[64];
        std::snprintf(g, sizeof g, "{%08x-0000-0000-0000-%012x}", tag, static_cast<unsigned>(k));
        ds.push_back({g, name, 2, 1, "x"});
    }
    return ds;
}

} // namespace

TEST_CASE("wsl: with production limits the profiles after a dispatch stop are counted, never "
          "accessed, and the same run repeats byte for byte",
          "[virtualization][wsl][budget]") {
    // Eight hives each spend their whole 512-call allowance (7 end on the per-hive cap, the 8th
    // meets the dispatch-wide 4096 at the same call); the other two profiles are the blind tail.
    // The run is deterministic, so a re-run is blind to the same two profiles: the status token
    // and the not-loaded count are all an operator gets (the skipped profiles have no row).
    const auto once = [] {
        auto ops = std::make_unique<FakeOps>();
        Node& heavy = make_hive(*ops, many(1, 80, "x")); // 2 + 80 x 8 calls > 512
        auto acc = std::make_unique<FakeAccess>();
        std::vector<ProfileInfo> ps;
        for (int i = 1; i <= 10; ++i) {
            acc->cfg[numbered_sid(i)] = {HiveAccessStatus::ok, &heavy};
            ps.push_back(profile(numbered_sid(i), i <= 8 ? numbered_name(i) : "skipped" + numbered_name(i)));
        }
        wsl::WalkBudget production; // nothing overridden
        auto r = run(ps, *acc, *ops, production);
        struct Out {
            Run result;
            std::map<std::string, int> calls;
            bool balanced;
            std::size_t visited;
        };
        return Out{std::move(r), acc->calls, ops->opens == ops->closes, production.visited};
    };
    const auto a = once();

    CHECK(a.visited == wsl::kDefaultMaxVisited);
    CHECK(has_token(a.result.posture, "hive_entry_cap")); // hives 1-7: their own allowance
    CHECK(has_token(a.result.posture, "entry_cap"));      // hive 8: the dispatch-wide cap
    CHECK_FALSE(has_token(a.result.posture, "row_cap"));
    CHECK(a.result.posture.status == StatusState::constrained);
    for (int i = 1; i <= 8; ++i)
        CHECK(a.calls.at(numbered_sid(i)) == 1);
    CHECK(a.calls.count(numbered_sid(9)) == 0); // never accessed: no mount, no read
    CHECK(a.calls.count(numbered_sid(10)) == 0);
    CHECK(a.result.reads.profiles_not_loaded == 2);
    // summary: 8 hives read, 2 not loaded; the skipped profiles have no row and no identity.
    const std::string& summary = a.result.posture.rows[0];
    CHECK(summary.ends_with("|8|2|-"));
    CHECK(joined(a.result.posture).find("skipped") == std::string::npos);
    CHECK(a.balanced);

    const auto b = once();
    CHECK(b.result.posture.rows == a.result.posture.rows);
    CHECK(b.result.posture.reason == a.result.posture.reason);
}

TEST_CASE("wsl: eight byte-heavy profiles spend the dispatch byte budget; seven leave room",
          "[virtualization][wsl][budget]") {
    // The 256 KiB dispatch budget is eight 32 KiB per-hive allowances (less the reserved header):
    // pin the arithmetic so a change to either constant is a visible decision.
    static_assert(8 * wsl::kDefaultMaxBytesPerHive == wsl::kDefaultMaxBytes);
    // Seven full hives and the reserved header leave room for a small eighth; eight do not fit.
    static_assert(7 * wsl::kDefaultMaxBytesPerHive + wsl::kHeaderReserveBytes + 4096 <=
                  wsl::kDefaultMaxBytes);
    static_assert(8 * wsl::kDefaultMaxBytesPerHive + wsl::kHeaderReserveBytes >
                  wsl::kDefaultMaxBytes);

    // Each heavy hive's rows are exactly 2 KiB, so it retains exactly sixteen (32768 bytes) and
    // ends on `hive_row_cap`.
    constexpr std::size_t kRow = 2048;
    const auto fleet = [&](int heavy) {
        auto ops = std::make_unique<FakeOps>();
        auto acc = std::make_unique<FakeAccess>();
        std::vector<ProfileInfo> ps;
        for (int i = 0; i < heavy; ++i) {
            Node& h = make_hive(*ops, sized_rows(static_cast<unsigned>(i + 1), 24, kRow));
            acc->cfg[numbered_sid(i)] = {HiveAccessStatus::ok, &h};
            ps.push_back(profile(numbered_sid(i), numbered_name(i)));
        }
        Node& last = make_hive(*ops, many(99, 1, "last"));
        acc->cfg[numbered_sid(heavy)] = {HiveAccessStatus::ok, &last};
        ps.push_back(profile(numbered_sid(heavy), numbered_name(heavy)));
        wsl::WalkBudget production;
        auto r = run(ps, *acc, *ops, production);
        CHECK(ops->opens == ops->closes);
        return std::make_tuple(std::move(r), std::move(acc), production.rows.bytes);
    };

    SECTION("seven heavy hives and a ninth-slot profile: the last one is still read") {
        auto [r, acc, bytes] = fleet(7);
        CHECK(acc->calls[numbered_sid(7)] == 1);
        CHECK(has_row(r.posture, "distribution|u7|last-0|2|installed|no|x"));
        CHECK(has_token(r.posture, "hive_row_cap"));
        CHECK_FALSE(has_token(r.posture, "row_cap"));
        CHECK(r.posture.status == StatusState::constrained);
        CHECK(r.reads.profiles_not_loaded == 0);
        CHECK(bytes <= wsl::kDefaultMaxBytes);
        for (int i = 0; i < 7; ++i)
            CHECK(r.reads.hives[static_cast<std::size_t>(i)].distros.size() == 16);
    }
    SECTION("eight heavy hives: the dispatch budget is spent and the next profile is never read") {
        auto [r, acc, bytes] = fleet(8);
        CHECK(has_token(r.posture, "row_cap")); // the eighth hive crosses the dispatch cap
        CHECK(acc->calls.count(numbered_sid(8)) == 0);
        CHECK(r.reads.profiles_not_loaded == 1);
        CHECK_FALSE(has_row(r.posture, "distribution|u8|last-0|2|installed|no|x"));
        // Flagged, never a clean `supported` that reads like "the last profile has no WSL".
        CHECK(r.posture.status == StatusState::constrained);
        CHECK(bytes <= wsl::kDefaultMaxBytes);
    }
}

TEST_CASE("wsl: the header reserve is a proven maximum", "[virtualization][wsl][budget]") {
    std::string reason;
    for (const auto s : wsl::kFixedTokenSuffixes) {
        if (!reason.empty())
            reason += ',';
        reason += std::string{wsl::kTokenPrefix} + std::string{s};
    }
    reason += std::string{","} + std::string{wsl::kTokenPrefix} + "package_win32_-2147483648";
    reason += std::string{","} + std::string{wsl::kTokenPrefix} + "profile_list_win32_-2147483648";
    const std::string status =
        yuzu::virtualization::format_status_row("wsl", StatusState::constrained, reason);

    // Worst-case escaping: every version byte is a pipe, doubled by safe_output_field.
    wsl::WslReads reads;
    reads.package_version = yuzu::virtualization::wire_field(std::string(64, '|'));
    reads.profiles_not_loaded = 18446744073709551615ULL;
    const auto p = wsl::decide_wsl(reads);
    std::string summary = p.rows.at(0);
    // decide_wsl's counts are small here; widen the numeric fields to the 20-digit worst case.
    summary = "summary|18446744073709551615|18446744073709551615|18446744073709551615|"
              "18446744073709551615|" + *reads.package_version;
    CHECK(status.size() + 1 + summary.size() + 1 <= wsl::kHeaderReserveBytes);
    CHECK(reads.package_version->size() == 128);
}

TEST_CASE("wsl: a profile row that would cross the row budget is itself row_cap",
          "[virtualization][wsl][budget]") {
    FakeOps ops;
    FakeAccess acc;
    acc.cfg[kSidA] = {HiveAccessStatus::not_found};
    acc.cfg[kSidB] = {HiveAccessStatus::not_found};
    wsl::WalkBudget b(/*max_rows=*/3, wsl::kDefaultMaxBytes, wsl::kDefaultMaxVisited);
    const auto r = run({profile(kSidA, "alice"), profile(kSidB, "bob")}, acc, ops, b);
    CHECK(has_row(r.posture, "profile|alice|not_found|-"));
    CHECK_FALSE(has_row(r.posture, "profile|bob|not_found|-"));
    CHECK(has_token(r.posture, "row_cap"));
    CHECK(r.posture.rows[0] == "summary|0|0|0|2|-"); // counts stay truthful
}

TEST_CASE("wsl: retained values are the sanitized, charged ones; e-mail shapes are redacted",
          "[virtualization][wsl]") {
    FakeOps ops;
    const std::string big_email = std::string(3000, 'a') + "@example.com";
    Node& hive = make_hive(ops, {{kGuid1, big_email, 2, 1, "me@example.org"}});
    FakeAccess acc;
    acc.cfg[kSidA] = {HiveAccessStatus::ok, &hive};
    wsl::WalkBudget b;
    const auto r = run({profile(kSidA, "alice")}, acc, ops, b);
    REQUIRE(r.reads.hives.size() == 1);
    REQUIRE(r.reads.hives[0].distros.size() == 1);
    const auto& d = r.reads.hives[0].distros[0];
    CHECK(*d.name == "[redacted-email]");
    CHECK(*d.flavor == "[redacted-email]");
    CHECK(has_row(r.posture,
                  "distribution|alice|[redacted-email]|2|installed|no|[redacted-email]"));
    // charged == formatted row + newline, on top of the reserved header
    const std::string row = wsl::format_distribution_row("alice", d);
    CHECK(b.rows.bytes == wsl::kHeaderReserveBytes + row.size() + 1);
}

// -- walk branches ---------------------------------------------------------------------------

TEST_CASE("wsl: an exception inside a mounted hive propagates and every key is closed",
          "[virtualization][wsl]") {
    FakeOps ops;
    Node& hive = make_hive(ops, {{kGuid1, "Ubuntu", 2, 1, "ubuntu"}});
    ops.throw_on_enum = true;
    FakeAccess acc;
    acc.cfg[kSidA] = {HiveAccessStatus::ok, &hive};
    wsl::WslReads reads;
    wsl::WalkBudget b;
    std::vector<ProfileInfo> ps{profile(kSidA, "alice")};
    CHECK_THROWS(wsl::collect_wsl(std::span<const ProfileInfo>{ps}, acc.fn(), ops, b, reads));
    CHECK(ops.opens == ops.closes);
}

TEST_CASE("wsl: DefaultDistribution matches case-insensitively; absent means every row no",
          "[virtualization][wsl]") {
    {
        FakeOps ops;
        Node& hive = make_hive(ops, {{kGuid2, "Ubuntu", 2, 1, "ubuntu"}},
                               "{aaaaaaaa-BBBB-cccc-DDDD-eeeeeeeeeeee}");
        FakeAccess acc;
        acc.cfg[kSidA] = {HiveAccessStatus::ok, &hive};
        CHECK(has_row(run({profile(kSidA, "alice")}, acc, ops).posture,
                      "distribution|alice|Ubuntu|2|installed|yes|ubuntu"));
    }
    {
        FakeOps ops;
        Node& hive = make_hive(ops, {{kGuid2, "Ubuntu", 2, 1, "ubuntu"}});
        FakeAccess acc;
        acc.cfg[kSidA] = {HiveAccessStatus::ok, &hive};
        CHECK(has_row(run({profile(kSidA, "alice")}, acc, ops).posture,
                      "distribution|alice|Ubuntu|2|installed|no|ubuntu"));
    }
}

TEST_CASE("wsl: the Lxss key open maps NOT_FOUND to read-ok, denial and failure to tokens",
          "[virtualization][wsl]") {
    FakeOps ops;
    Node& none = ops.node(); // a hive with no Lxss key
    Node& denied = make_hive(ops, {});
    lxss_of(denied).open_rc = wsl::kErrorAccessDenied;
    Node& broken = make_hive(ops, {});
    lxss_of(broken).open_rc = 1450;
    FakeAccess acc;
    acc.cfg[kSidA] = {HiveAccessStatus::ok, &none};
    acc.cfg[kSidB] = {HiveAccessStatus::ok, &denied};
    acc.cfg[kSidC] = {HiveAccessStatus::ok, &broken};
    const auto r =
        run({profile(kSidA, "alice"), profile(kSidB, "bob"), profile(kSidC, "carol")}, acc, ops);
    CHECK(has_token(r.posture, "hive_access_denied"));
    CHECK(has_token(r.posture, "hive_open_failed"));
    CHECK(r.posture.rows[0] == "summary|0|0|1|0|-"); // only the NOT_FOUND hive counts as read
    CHECK(r.posture.rows.size() == 1);
    CHECK(ops.opens == ops.closes);
}

TEST_CASE("wsl: only GUID-shaped children are opened; others are skipped silently",
          "[virtualization][wsl]") {
    FakeOps ops;
    Node& hive = make_hive(ops, {{kGuid1, "Ubuntu", 2, 1, "ubuntu"}});
    Node& lx = lxss_of(hive);
    for (const wchar_t* junk : {L"InstallStatus", L"AppxInstallerCache", L"{not-a-guid}",
                                L"{11111111-22223333-4444-555555555555}", L""})
        ops.child(lx, junk);
    ops.child(lx, std::wstring(L"{11111111-2222-3333-4444-55555555555") + std::wstring(1, L'\0') +
                      L"}");
    FakeAccess acc;
    acc.cfg[kSidA] = {HiveAccessStatus::ok, &hive};
    const auto r = run({profile(kSidA, "alice")}, acc, ops);
    CHECK(r.posture.status == StatusState::supported);
    CHECK(r.posture.rows.size() == 2);
    CHECK(ops.opens == 2); // the Lxss key and the one distribution
    CHECK(wsl::is_guid_shaped(L"{AAAAAAAA-bbbb-CCCC-dddd-EEEEEEEEEEEE}"));
    CHECK_FALSE(wsl::is_guid_shaped(L"{AAAAAAAA-bbbb-CCCC-dddd-EEEEEEEEEEEG}"));
}

TEST_CASE("wsl: an enumeration failure mid-walk keeps the rows so far and is a token",
          "[virtualization][wsl]") {
    FakeOps ops;
    Node& hive =
        make_hive(ops, {{kGuid1, "Ubuntu", 2, 1, "ubuntu"}, {kGuid2, "Debian", 2, 1, "debian"}});
    lxss_of(hive).enum_fail_idx = 1;
    lxss_of(hive).enum_fail_rc = wsl::kErrorAccessDenied;
    FakeAccess acc;
    acc.cfg[kSidA] = {HiveAccessStatus::ok, &hive};
    const auto r = run({profile(kSidA, "alice")}, acc, ops);
    CHECK(has_token(r.posture, "hive_enum_failed"));
    CHECK(r.posture.status == StatusState::constrained);
    CHECK(r.posture.rows.size() == 2);
    CHECK(ops.opens == ops.closes);
}

TEST_CASE("wsl: an enumeration MORE_DATA skips that index and the walk goes on",
          "[virtualization][wsl]") {
    FakeOps ops;
    Node& hive =
        make_hive(ops, {{kGuid1, "Ubuntu", 2, 1, "ubuntu"}, {kGuid2, "Debian", 2, 1, "debian"}});
    lxss_of(hive).enum_fail_idx = 0;
    lxss_of(hive).enum_fail_rc = wsl::kErrorMoreData;
    FakeAccess acc;
    acc.cfg[kSidA] = {HiveAccessStatus::ok, &hive};
    wsl::WalkBudget b;
    const auto r = run({profile(kSidA, "alice")}, acc, ops, b);
    CHECK_FALSE(has_token(r.posture, "hive_enum_failed"));
    CHECK(r.posture.status == StatusState::supported);
    CHECK(r.posture.rows.size() == 2);
    CHECK(r.posture.rows[0] == "summary|1|1|1|0|-");
    CHECK(has_row(r.posture, "distribution|alice|Debian|2|installed|no|debian"));
    // The skipped index was charged: the Lxss link probe + DefaultDistribution + 3 enums (skipped,
    // listed, end) + the listed distribution's link probe + 6 values.
    CHECK(ops.enums == 3);
    CHECK(b.visited == 2 + 3 + 1 + 6);
    CHECK(ops.calls() == b.visited);
    CHECK(ops.opens == ops.closes);
}

TEST_CASE("wsl: a child deleted or added between two enumeration calls never aborts the walk",
          "[virtualization][wsl]") {
    // The walk enumerates by index with no snapshot, so a concurrent writer can shift the list
    // under it. This is a CHARACTERISATION of that disclosed residual (the window is milliseconds
    // and the next run is whole): the walk neither throws nor leaks a key, every counted row
    // exists, and neither shift raises a token.
    const auto build = [](FakeOps& ops) -> Node& {
        return make_hive(ops, {{"{00000001-0000-0000-0000-000000000001}", "Alpha", 2, 1, "a"},
                               {"{00000002-0000-0000-0000-000000000002}", "Beta", 2, 1, "b"},
                               {"{00000003-0000-0000-0000-000000000003}", "Gamma", 2, 1, "c"}});
    };
    const auto distribution_rows = [](const Posture& p) {
        std::vector<std::string> out;
        for (const auto& r : p.rows)
            if (r.starts_with("distribution|"))
                out.push_back(r);
        return out;
    };

    SECTION("a child removed after it was listed: the next one slides into its index") {
        FakeOps ops;
        Node& hive = build(ops);
        Node& lx = lxss_of(hive);
        lx.on_enum = [&lx](std::uint32_t idx) {
            if (idx == 1) // Alpha was just listed; remove it before index 1 is resolved
                lx.children.erase(lx.children.begin());
        };
        FakeAccess acc;
        acc.cfg[kSidA] = {HiveAccessStatus::ok, &hive};
        wsl::WalkBudget b;
        Run r;
        REQUIRE_NOTHROW(r = run({profile(kSidA, "alice")}, acc, ops, b));
        // Beta slid into index 0 and was never listed: one distribution silently skipped.
        CHECK(distribution_rows(r.posture) ==
              std::vector<std::string>{"distribution|alice|Alpha|2|installed|no|a",
                                       "distribution|alice|Gamma|2|installed|no|c"});
        CHECK(r.posture.status == StatusState::supported);
        CHECK(r.posture.rows[0] == "summary|2|2|1|0|-");
        CHECK(ops.opens == ops.closes);
        CHECK(ops.calls() == b.visited);
    }
    SECTION("a child added in front: the one already read is listed again") {
        FakeOps ops;
        Node& hive = build(ops);
        Node& lx = lxss_of(hive);
        Node* alpha = lx.children.front().second;
        const std::wstring alpha_name = lx.children.front().first;
        bool done = false;
        lx.on_enum = [&](std::uint32_t idx) {
            if (idx == 1 && !done) {
                done = true;
                lx.children.insert(lx.children.begin(), {alpha_name, alpha}); // a second Alpha
            }
        };
        FakeAccess acc;
        acc.cfg[kSidA] = {HiveAccessStatus::ok, &hive};
        wsl::WalkBudget b;
        Run r;
        REQUIRE_NOTHROW(r = run({profile(kSidA, "alice")}, acc, ops, b));
        const auto rows = distribution_rows(r.posture);
        CHECK(std::count(rows.begin(), rows.end(), "distribution|alice|Alpha|2|installed|no|a") ==
              2);
        CHECK(rows.size() == 4); // Alpha, Alpha, Beta, Gamma
        CHECK(r.posture.status == StatusState::supported);
        CHECK(r.posture.rows[0] == "summary|4|4|1|0|-"); // the counts are exactly the rows
        CHECK(ops.opens == ops.closes);
    }
}

TEST_CASE("wsl: one defect repeated across many children is one token", "[virtualization][wsl]") {
    FakeOps ops;
    Node& hive = make_hive(ops, many(1, 50, "bad"));
    Node& lx = lxss_of(hive);
    for (auto& [name, dk] : lx.children)
        FakeOps::set_dword(*dk, L"DistributionName", 7); // wrong type on every child
    FakeAccess acc;
    acc.cfg[kSidA] = {HiveAccessStatus::ok, &hive};
    const auto r = run({profile(kSidA, "alice")}, acc, ops);
    REQUIRE(r.reads.hives.size() == 1);
    CHECK(r.reads.hives[0].tokens == std::vector<std::string>{"value_malformed"});
    CHECK(r.reads.hives[0].distros.size() == 50);
    CHECK(has_token(r.posture, "value_malformed"));
    CHECK(ops.opens == ops.closes);
}

TEST_CASE("wsl: a distribution key that fails to open is a typed row", "[virtualization][wsl]") {
    // ACCESS_DENIED is a refused key; FILE_NOT_FOUND is a child enumerated and then deleted before
    // the open (the vanished-child race). Both are the same typed row, counted, never an abort.
    for (const long rc : {wsl::kErrorAccessDenied, wsl::kErrorFileNotFound}) {
        INFO("open rc " << rc);
        FakeOps ops;
        Node& hive = make_hive(ops, {{kGuid1, "Ubuntu", 2, 1, "ubuntu"}, {kGuid2, "Debian", 1, 1, "d"}},
                               kGuid1);
        lxss_of(hive).children.front().second->open_rc = rc;
        FakeAccess acc;
        acc.cfg[kSidA] = {HiveAccessStatus::ok, &hive};
        const auto r = run({profile(kSidA, "alice")}, acc, ops);
        CHECK(has_token(r.posture, "distro_open_failed"));
        CHECK(r.posture.status == StatusState::constrained);
        CHECK(has_row(r.posture, "distribution|alice|-|unknown|unknown|yes|-"));
        CHECK(has_row(r.posture, "distribution|alice|Debian|1|installed|no|d")); // the sibling is read
        // The unknown row is a distribution row: the summary counts it, and the hive was read.
        CHECK(r.posture.rows[0] == "summary|2|0|1|0|-");
        CHECK(ops.opens == ops.closes);
    }
}

// -- planted registry links -------------------------------------------------------------------
//
// The shell opens every key with REG_OPTION_OPEN_LINK, so a link planted at the Lxss key or at a
// distribution key opens as the link object: no values, no children. Without a probe that reads
// as a clean "no WSL" profile. is_link_key detects it; a link is reported and never read through.
// (The fake cannot prove the real OPEN_LINK semantics; the capture on a disposable account does.)

TEST_CASE("wsl: a link planted at the Lxss key is reported, never read, and the profile is not "
          "counted as read",
          "[virtualization][wsl][link]") {
    // REG_LINK is what a real link carries; a plain key holding a REG_SZ of that name is a decoy
    // and reads the same way (constrained, never fail-open).
    for (const std::uint32_t type : {std::uint32_t{6}, wsl::kRegSz}) {
        INFO("SymbolicLinkValue type " << type);
        FakeOps ops;
        // The hive still has Lxss children and a default, so any read past the probe would show.
        Node& hive = make_hive(ops, {{kGuid1, "Ubuntu", 2, 1, "ubuntu"}}, kGuid1);
        FakeOps::set_link(lxss_of(hive), type);
        FakeAccess acc;
        acc.cfg[kSidA] = {HiveAccessStatus::ok, &hive};
        acc.cfg[kSidB] = {HiveAccessStatus::ok, &make_hive(ops, {{kGuid2, "Debian", 1, 1, "d"}})};
        wsl::WalkBudget b;
        const auto r = run({profile(kSidA, "alice"), profile(kSidB, "bob")}, acc, ops, b);

        CHECK(has_token(r.posture, "lxss_link"));
        CHECK(r.posture.status == StatusState::constrained);
        // alice: not read, in neither count (like a denied Lxss open); bob: read and listed.
        CHECK(r.posture.rows[0] == "summary|1|0|1|0|-");
        CHECK(has_row(r.posture, "distribution|bob|Debian|1|installed|no|d"));
        CHECK_FALSE(has_row(r.posture, "distribution|alice|Ubuntu|2|installed|yes|ubuntu"));
        CHECK(joined(r.posture).find("alice") == std::string::npos); // no row names the profile
        // Past the probe nothing was asked of the link: no DefaultDistribution, no enumeration.
        const Node& lxss_a = lxss_of(hive);
        for (const auto& [key, name] : ops.queried)
            if (key == &lxss_a)
                CHECK(name == L"SymbolicLinkValue");
        CHECK(ops.opens == ops.closes);
        CHECK(ops.calls() == b.visited); // the probe was charged like any other call
    }
}

TEST_CASE("wsl: a link planted at a distribution key is a typed unknown row; its values are not read",
          "[virtualization][wsl][link]") {
    for (const std::uint32_t type : {std::uint32_t{6}, wsl::kRegSz}) {
        INFO("SymbolicLinkValue type " << type);
        FakeOps ops;
        Node& hive = make_hive(ops, {{kGuid1, "Ubuntu", 2, 1, "ubuntu"}, {kGuid2, "Debian", 1, 1, "d"}},
                               kGuid2);
        Node& linked = *lxss_of(hive).children[1].second; // kGuid2, the default
        FakeOps::set_link(linked, type);
        FakeAccess acc;
        acc.cfg[kSidA] = {HiveAccessStatus::ok, &hive};
        const auto r = run({profile(kSidA, "alice")}, acc, ops);

        CHECK(has_token(r.posture, "lxss_link"));
        CHECK_FALSE(has_token(r.posture, "distro_open_failed"));
        CHECK(r.posture.status == StatusState::constrained);
        // The same row an open failure gives (the default flag survives); the sibling is intact.
        CHECK(has_row(r.posture, "distribution|alice|-|unknown|unknown|yes|-"));
        CHECK(has_row(r.posture, "distribution|alice|Ubuntu|2|installed|no|ubuntu"));
        CHECK_FALSE(has_row(r.posture, "distribution|alice|Debian|1|installed|yes|d"));
        CHECK(r.posture.rows[0] == "summary|2|1|1|0|-"); // the unknown row counts; the hive was read
        // Only the marker was asked of the linked key.
        std::set<std::wstring> asked;
        for (const auto& [key, name] : ops.queried)
            if (key == &linked)
                asked.insert(name);
        CHECK(asked == std::set<std::wstring>{L"SymbolicLinkValue"});
        CHECK(ops.opens == ops.closes);
    }
}

TEST_CASE("wsl: a link probe that fails is a token, and the key is then read as a plain one",
          "[virtualization][wsl][link]") {
    FakeOps ops;
    Node& hive = make_hive(ops, {{kGuid1, "Ubuntu", 2, 1, "ubuntu"}});
    FakeOps::set_link(lxss_of(hive));
    lxss_of(hive).values[L"SymbolicLinkValue"].fail_rc = wsl::kErrorAccessDenied; // unreadable
    Node& child = *lxss_of(hive).children.front().second;
    FakeOps::set_link(child);
    child.values[L"SymbolicLinkValue"].fail_rc = 1450;
    FakeAccess acc;
    acc.cfg[kSidA] = {HiveAccessStatus::ok, &hive};
    const auto r = run({profile(kSidA, "alice")}, acc, ops);
    CHECK(has_token(r.posture, "value_unreadable"));
    CHECK_FALSE(has_token(r.posture, "lxss_link"));
    CHECK(r.posture.status == StatusState::constrained); // never a clean `supported`
    CHECK(has_row(r.posture, "distribution|alice|Ubuntu|2|installed|no|ubuntu"));
    CHECK(r.posture.rows[0] == "summary|1|1|1|0|-");
    CHECK(ops.opens == ops.closes);
}

TEST_CASE("wsl: a refused link probe ends the right scope and examines nothing past it",
          "[virtualization][wsl][link]") {
    SECTION("the dispatch-wide cap refuses the Lxss probe: entry_cap and the loop stops") {
        FakeOps ops;
        Node& hive = make_hive(ops, {{kGuid1, "Ubuntu", 2, 1, "ubuntu"}});
        FakeAccess acc;
        acc.cfg[kSidA] = {HiveAccessStatus::ok, &hive};
        acc.cfg[kSidB] = {HiveAccessStatus::ok, &hive};
        wsl::WalkBudget b(wsl::kDefaultMaxRows, wsl::kDefaultMaxBytes, /*max_visited=*/0);
        const auto r = run({profile(kSidA, "alice"), profile(kSidB, "bob")}, acc, ops, b);
        CHECK(has_token(r.posture, "entry_cap"));
        CHECK(acc.calls[kSidB] == 0);
        CHECK(ops.calls() == 0); // the refused probe was never made
        CHECK(r.reads.profiles_not_loaded == 1);
        CHECK(r.posture.rows[0] == "summary|0|0|1|1|-"); // opened but not examined: counted read
        CHECK(ops.opens == ops.closes);
    }
    SECTION("the per-hive cap refuses a distribution's probe: that hive ends, the next is walked") {
        FakeOps ops;
        Node& ha = make_hive(ops, {{kGuid1, "Ubuntu", 2, 1, "ubuntu"}});
        Node& hb = make_hive(ops, {});
        FakeAccess acc;
        acc.cfg[kSidA] = {HiveAccessStatus::ok, &ha};
        acc.cfg[kSidB] = {HiveAccessStatus::ok, &hb};
        // Lxss probe (1), DefaultDistribution (2), enum (3); the child's probe would be the 4th.
        wsl::WalkBudget b(wsl::kDefaultMaxRows, wsl::kDefaultMaxBytes, wsl::kDefaultMaxVisited,
                          /*max_visited_per_hive=*/3);
        const auto r = run({profile(kSidA, "alice"), profile(kSidB, "bob")}, acc, ops, b);
        CHECK(has_token(r.posture, "hive_entry_cap"));
        CHECK_FALSE(has_token(r.posture, "entry_cap"));
        CHECK(acc.calls[kSidB] == 1);
        CHECK(r.posture.rows.size() == 1); // the unexamined distribution is discarded, not emitted
        CHECK(ops.opens == ops.closes);
    }
}

TEST_CASE("wsl: RAW value branches classify type, size and race", "[virtualization][wsl]") {
    struct Mutate {
        const char* what;
        std::function<void(Node&)> apply;
        const char* token; // nullptr = none
        std::string row;
        int fills; // FILL calls across the four reads (a size probe is not a fill)
    };
    const std::string at_cap(wsl::kMaxValueBytes - 1, 'x'); // + the NUL = exactly kMaxValueBytes
    const std::string over_cap(wsl::kMaxValueBytes, 'x');   // + the NUL = kMaxValueBytes + 1
    const std::vector<Mutate> cases = {
        {"name typed DWORD", [](Node& d) { FakeOps::set_dword(d, L"DistributionName", 7); },
         "value_malformed", "distribution|alice|-|2|installed|no|ubuntu", 3},
        {"name typed REG_EXPAND_SZ",
         [](Node& d) { FakeOps::set_sz(d, L"DistributionName", "Ubuntu", 2); }, "value_malformed",
         "distribution|alice|-|2|installed|no|ubuntu", 3},
        {"name typed REG_MULTI_SZ",
         [](Node& d) { FakeOps::set_sz(d, L"DistributionName", "Ubuntu", 7); }, "value_malformed",
         "distribution|alice|-|2|installed|no|ubuntu", 3},
        {"name oversized (no fill)",
         [](Node& d) {
             FakeOps::set_sz(d, L"DistributionName", std::string(5000, 'x'));
         },
         "value_oversized", "distribution|alice|-|2|installed|no|ubuntu", 3},
        {"name at the 4096-byte bound (filled)",
         [&](Node& d) { FakeOps::set_sz(d, L"DistributionName", at_cap); }, nullptr,
         "distribution|alice|" + at_cap + "|2|installed|no|ubuntu", 4},
        {"name one byte past the bound (no fill)",
         [&](Node& d) { FakeOps::set_sz(d, L"DistributionName", over_cap); }, "value_oversized",
         "distribution|alice|-|2|installed|no|ubuntu", 3},
        {"name fill MORE_DATA",
         [](Node& d) { d.values[L"DistributionName"].fill_rc = wsl::kErrorMoreData; },
         "value_unreadable", "distribution|alice|-|2|installed|no|ubuntu", 4},
        {"name query denied",
         [](Node& d) { d.values[L"DistributionName"].fail_rc = wsl::kErrorAccessDenied; },
         "value_unreadable", "distribution|alice|-|2|installed|no|ubuntu", 3},
        {"version size 8",
         [](Node& d) {
             Val v;
             v.type = wsl::kRegDword;
             v.data.assign(8, std::byte{1});
             d.values[L"Version"] = v;
         },
         "value_malformed", "distribution|alice|Ubuntu|unknown|installed|no|ubuntu", 4},
        {"version absent", [](Node& d) { d.values.erase(L"Version"); }, nullptr,
         "distribution|alice|Ubuntu|unknown|installed|no|ubuntu", 3},
        // The DWORD branch (`type != REG_DWORD || size != 4`): a REG_SZ and a short DWORD are both
        // malformed, never read as a number.
        {"version typed REG_SZ", [](Node& d) { FakeOps::set_sz(d, L"Version", "2"); },
         "value_malformed", "distribution|alice|Ubuntu|unknown|installed|no|ubuntu", 4},
        {"state a 2-byte DWORD",
         [](Node& d) {
             Val v;
             v.type = wsl::kRegDword;
             v.data.assign(2, std::byte{1});
             d.values[L"State"] = v;
         },
         "value_malformed", "distribution|alice|Ubuntu|2|unknown|no|ubuntu", 4},
        {"state 7 (compacting)", [](Node& d) { FakeOps::set_dword(d, L"State", 7); }, nullptr,
         "distribution|alice|Ubuntu|2|compacting|no|ubuntu", 4},
        {"state 8 (past the enum)", [](Node& d) { FakeOps::set_dword(d, L"State", 8); }, nullptr,
         "distribution|alice|Ubuntu|2|state_8|no|ubuntu", 4},
        {"flavor absent", [](Node& d) { d.values.erase(L"Flavor"); }, nullptr,
         "distribution|alice|Ubuntu|2|installed|no|-", 3},
    };
    for (const auto& c : cases) {
        INFO(c.what);
        FakeOps ops;
        Node& hive = make_hive(ops, {{kGuid1, "Ubuntu", 2, 1, "ubuntu"}});
        c.apply(*lxss_of(hive).children.front().second);
        FakeAccess acc;
        acc.cfg[kSidA] = {HiveAccessStatus::ok, &hive};
        const auto r = run({profile(kSidA, "alice")}, acc, ops);
        CHECK(has_row(r.posture, c.row));
        if (c.token)
            CHECK(has_token(r.posture, c.token));
        else
            CHECK(r.posture.status == StatusState::supported);
        // A wrong-typed or oversized value never reaches the FILL call, so it never allocates.
        CHECK(ops.fills == c.fills);
        CHECK(ops.opens == ops.closes);
    }
}

TEST_CASE("wsl: a FILL that reports more bytes than the buffer is clamped to the buffer",
          "[virtualization][wsl]") {
    FakeOps ops;
    Node& hive = make_hive(ops, {{kGuid1, "Ubuntu", 2, 1, "ubuntu"}});
    // The probe said 7 bytes ("Ubuntu" + NUL); the fill then claims 9999 and succeeds.
    lxss_of(hive).children.front().second->values[L"DistributionName"].fill_size_override = 9999;
    FakeAccess acc;
    acc.cfg[kSidA] = {HiveAccessStatus::ok, &hive};
    const auto r = run({profile(kSidA, "alice")}, acc, ops);
    // The decoder was handed the buffer (7 bytes) for the name and the flavor, never 9999.
    CHECK(ops.payload_sizes == std::vector<std::size_t>{7, 7});
    CHECK(r.posture.status == StatusState::supported);
    CHECK(has_row(r.posture, "distribution|alice|Ubuntu|2|installed|no|ubuntu"));
    CHECK(ops.opens == ops.closes);
}

TEST_CASE("wsl: a value-sized redaction worst case is bounded and emitted as is",
          "[virtualization][wsl]") {
    // The densest `@(` run a REG_SZ of kMaxValueBytes can hold: every `@` opens a comment that is
    // never closed, which is the e-mail scan's quadratic input. The input is bounded BEFORE
    // redaction, so the test pins the bound (the value is read whole and is not an address), not a
    // time.
    std::string hostile = "a";
    while (hostile.size() + 2 <= wsl::kMaxValueBytes - 1)
        hostile += "@(";
    REQUIRE(hostile.size() + 1 == wsl::kMaxValueBytes);
    CHECK_FALSE(yuzu::shared::looks_like_email_address(hostile));

    FakeOps ops;
    Node& hive = make_hive(ops, {{kGuid1, hostile, 2, 1, "ubuntu"}});
    FakeAccess acc;
    acc.cfg[kSidA] = {HiveAccessStatus::ok, &hive};
    const auto r = run({profile(kSidA, "alice")}, acc, ops);
    REQUIRE(r.reads.hives.size() == 1);
    REQUIRE(r.reads.hives[0].distros.size() == 1);
    CHECK(r.reads.hives[0].tokens.empty());
    CHECK(r.reads.hives[0].distros[0].name == hostile);
    CHECK(r.posture.status == StatusState::supported);
    CHECK(has_row(r.posture, "distribution|alice|" + hostile + "|2|installed|no|ubuntu"));
}

TEST_CASE("wsl: an e-mail-shaped profile folder name is redacted on every row that carries it",
          "[virtualization][wsl]") {
    FakeOps ops;
    Node& hive = make_hive(ops, {{kGuid1, "Ubuntu", 2, 1, "ubuntu"}});
    FakeAccess acc;
    acc.cfg[kSidA] = {HiveAccessStatus::ok, &hive};
    acc.cfg[kSidB] = {HiveAccessStatus::not_found};
    const auto r = run(
        {profile(kSidA, "jsmith@corp.example"), profile(kSidB, "kjones@corp.example")}, acc, ops);
    CHECK(has_row(r.posture, "distribution|[redacted-email]|Ubuntu|2|installed|no|ubuntu"));
    CHECK(has_row(r.posture, "profile|[redacted-email]|not_found|-"));
    const std::string all = joined(r.posture);
    CHECK(all.find("corp.example") == std::string::npos);
    CHECK(all.find("jsmith") == std::string::npos);
    CHECK(all.find("kjones") == std::string::npos);
}

TEST_CASE("wsl: nothing on the never-emit list is read or reaches a row", "[virtualization][wsl]") {
    FakeOps ops;
    Node& hive = make_hive(ops, {{kGuid1, "Ubuntu", 2, 1, "ubuntu"}}, kGuid1);
    FakeAccess acc;
    acc.cfg[kSidA] = {HiveAccessStatus::ok, &hive, "", true};
    acc.cfg[kSidB] = {HiveAccessStatus::not_found};
    const auto r = run({profile(kSidA, ""), profile(kSidB, "bob")}, acc, ops);
    const std::string all = joined(r.posture);
    for (const char* secret :
         {"SECRETPATH", "SECRETVHD", "424242", "S-1-5-", "YUZU_HIVE", kGuid1})
        CHECK(all.find(secret) == std::string::npos);
    for (const auto& e : kExcludedDistroValues)
        CHECK(all.find(e.sentinel) == std::string::npos);
    for (const auto& e : kExcludedLxssValues)
        CHECK(all.find(e.sentinel) == std::string::npos);
    // An empty folder name reads "-".
    CHECK(has_row(r.posture, "distribution|-|Ubuntu|2|installed|yes|ubuntu"));

    // The exclusion is also a read-side contract: only the intended values are ever asked for,
    // each on its own key (a value read on the wrong key would pass a whole-run name check).
    std::map<const Node*, std::set<std::wstring>> by_key;
    for (const auto& [key, name] : ops.queried)
        by_key[key].insert(name);
    const Node& lxss = lxss_of(hive);
    const Node& distro = *lxss.children.front().second;
    CHECK(by_key.size() == 2);
    CHECK(by_key[&lxss] ==
          std::set<std::wstring>{L"SymbolicLinkValue", L"DefaultDistribution"});
    CHECK(by_key[&distro] == std::set<std::wstring>{L"SymbolicLinkValue", L"DistributionName",
                                                    L"Version", L"State", L"Flavor"});

    // The package key: only Version, even with another value present beside it.
    FakeOps pkg_ops;
    Node& hklm = pkg_ops.node();
    Node& msi = pkg_ops.child(hklm, wsl::detail::kMsiPath);
    FakeOps::set_sz(msi, L"Version", "3.0.3.0");
    FakeOps::set_sz(msi, L"InstallLocation", "SECRETMSIPATH");
    wsl::WalkBudget b;
    wsl::WslReads pkg_reads;
    wsl::read_package_version(pkg_ops, &hklm, b, pkg_reads);
    REQUIRE(pkg_ops.queried.size() >= 1);
    for (const auto& [key, name] : pkg_ops.queried) {
        CHECK(key == &msi);
        CHECK(name == L"Version");
    }
    CHECK(pkg_reads.package_version == "3.0.3.0");
}

TEST_CASE("wsl: hostile names stay seven fields", "[virtualization][wsl]") {
    FakeOps ops;
    Node& hive = make_hive(ops, {{kGuid1, std::string("a|b\\c\nd\xff") + "e", 2, 1, "x|y"}});
    FakeAccess acc;
    acc.cfg[kSidA] = {HiveAccessStatus::ok, &hive};
    const auto r = run({profile(kSidA, "ali|ce")}, acc, ops);
    for (const auto& row : r.posture.rows)
        if (row.starts_with("distribution|")) {
            CHECK(fields(row) == 7);
            CHECK(row.find('\n') == std::string::npos);
        }
}

// -- package version and ProfileList ---------------------------------------------------------

TEST_CASE("wsl: the package version is read, bounded and tokenised", "[virtualization][wsl]") {
    const auto read = [](const std::function<void(FakeOps&, Node&)>& setup) {
        FakeOps ops;
        Node& hklm = ops.node();
        setup(ops, hklm);
        wsl::WalkBudget b;
        wsl::WslReads reads;
        wsl::read_package_version(ops, &hklm, b, reads);
        CHECK(ops.opens == ops.closes);
        return reads;
    };
    auto ok = read([](FakeOps& o, Node& h) {
        FakeOps::set_sz(o.child(h, wsl::detail::kMsiPath), L"Version", "3.0.3.0");
    });
    CHECK(ok.package_version == "3.0.3.0");
    CHECK(ok.tokens.empty());
    // ... and it is the sixth summary field (an inverted `? :` there would swap the two).
    CHECK(wsl::decide_wsl(ok).rows.at(0) == "summary|0|0|0|0|3.0.3.0");
    CHECK(wsl::decide_wsl(wsl::WslReads{}).rows.at(0) == "summary|0|0|0|0|-");

    CHECK_FALSE(read([](FakeOps&, Node&) {}).package_version); // no key: no token
    CHECK(read([](FakeOps&, Node&) {}).tokens.empty());

    auto longv = read([](FakeOps& o, Node& h) {
        FakeOps::set_sz(o.child(h, wsl::detail::kMsiPath), L"Version", std::string(65, '1'));
    });
    CHECK_FALSE(longv.package_version);
    CHECK(longv.tokens == std::vector<std::string>{"package_malformed"});

    auto keyfail = read([](FakeOps& o, Node& h) {
        o.child(h, wsl::detail::kMsiPath).open_rc = wsl::kErrorAccessDenied;
    });
    CHECK(keyfail.tokens == std::vector<std::string>{"package_access_denied"});

    auto valfail = read([](FakeOps& o, Node& h) {
        Node& k = o.child(h, wsl::detail::kMsiPath);
        FakeOps::set_sz(k, L"Version", "3.0");
        k.values[L"Version"].fail_rc = 1450;
    });
    CHECK(valfail.tokens == std::vector<std::string>{"package_win32_1450"});

    auto wrongtype = read([](FakeOps& o, Node& h) {
        FakeOps::set_dword(o.child(h, wsl::detail::kMsiPath), L"Version", 3);
    });
    CHECK(wrongtype.tokens == std::vector<std::string>{"package_malformed"});
}

TEST_CASE("wsl: ProfileList discovery is classified, never a prefix read as complete",
          "[virtualization][wsl]") {
    using E = wsl::ProfileListEnd;
    using wsl::classify_profile_list_end;
    CHECK(classify_profile_list_end(wsl::kErrorNoMoreItems, wsl::kErrorSuccess) == E::complete);
    CHECK(classify_profile_list_end(wsl::kErrorAccessDenied, wsl::kErrorNoMoreItems) ==
          E::enum_failed);
    CHECK(classify_profile_list_end(wsl::kErrorSuccess, wsl::kErrorNoMoreItems) == E::complete);
    CHECK(classify_profile_list_end(wsl::kErrorSuccess, wsl::kErrorSuccess) == E::cap);
    CHECK(classify_profile_list_end(wsl::kErrorSuccess, wsl::kErrorAccessDenied) ==
          E::enum_failed);

    CHECK_FALSE(wsl::profile_list_token(0, wsl::kErrorNoMoreItems, 0));
    CHECK(wsl::profile_list_token(wsl::kErrorAccessDenied, 0, 0) == "profile_list_access_denied");
    CHECK(wsl::profile_list_token(2, 0, 0) == "profile_list_win32_2");
    CHECK(wsl::profile_list_token(0, wsl::kErrorSuccess, wsl::kErrorSuccess) == "profile_cap");
    CHECK(wsl::profile_list_token(0, wsl::kErrorSuccess, wsl::kErrorAccessDenied) ==
          "profile_list_enum_failed");
}

// -- formatters, decide, grammar -------------------------------------------------------------

TEST_CASE("wsl: state and version tokens", "[virtualization][wsl]") {
    CHECK(wsl::state_token(1) == "installed");
    CHECK(wsl::state_token(3) == "installing");
    CHECK(wsl::state_token(4) == "uninstalling");
    CHECK(wsl::state_token(5) == "converting");
    CHECK(wsl::state_token(6) == "exporting");
    CHECK(wsl::state_token(7) == "compacting");
    // Invalid (0) and Running (2) are deliberately not labelled; nor is anything past the enum.
    CHECK(wsl::state_token(0) == "state_0");
    CHECK(wsl::state_token(2) == "state_2");
    CHECK(wsl::state_token(8) == "state_8");
    CHECK(wsl::state_token(std::nullopt) == "unknown");
    CHECK(wsl::version_token(1) == "1");
    CHECK(wsl::version_token(2) == "2");
    CHECK(wsl::version_token(3) == "unknown");
    CHECK(wsl::version_token(std::nullopt) == "unknown");
}

TEST_CASE("wsl: rows sort by account then name; profile rows by account then outcome",
          "[virtualization][wsl]") {
    FakeOps ops;
    Node& ha = make_hive(ops, {{kGuid2, "Zeta", 2, 1, "z"}, {kGuid1, "Alpha", 2, 1, "a"}});
    Node& hb = make_hive(ops, {{kGuid1, "Mid", 1, 1, "m"}});
    FakeAccess acc;
    acc.cfg[kSidA] = {HiveAccessStatus::ok, &hb};
    acc.cfg[kSidB] = {HiveAccessStatus::ok, &ha, "", true};
    const auto r = run({profile(kSidA, "zed"), profile(kSidB, "amy")}, acc, ops);
    std::vector<std::string> d;
    for (const auto& row : r.posture.rows)
        d.push_back(row.substr(0, row.find('|', row.find('|') + 1)));
    CHECK(d == std::vector<std::string>{"summary|3", "profile|amy", "distribution|amy",
                                        "distribution|amy", "distribution|zed"});
    CHECK(r.posture.rows[2].find("Alpha") != std::string::npos);
}

TEST_CASE("wsl: profile rows sort by account then outcome", "[virtualization][wsl]") {
    // Inserted in the reverse of the expected order. A profile always emits its access outcome
    // before `unload_failed`, so the outcome key is only observable across two profiles that
    // share a folder name: the first leaves a mount behind, the second is refused by the guard.
    FakeOps ops;
    FakeAccess acc;
    acc.cfg[kSidC] = {HiveAccessStatus::not_found};
    acc.cfg[kSidA] = {HiveAccessStatus::ok, nullptr, "", true};
    acc.cfg[kSidB] = {HiveAccessStatus::file_refused, nullptr, "hive_path_unc"};
    const auto r =
        run({profile(kSidC, "zed"), profile(kSidA, "amy"), profile(kSidB, "amy")}, acc, ops);
    std::vector<std::string> profile_rows;
    for (const auto& row : r.posture.rows)
        if (row.starts_with("profile|"))
            profile_rows.push_back(row);
    CHECK(profile_rows == std::vector<std::string>{"profile|amy|file_refused|hive_path_unc",
                                                   "profile|amy|unload_failed|-",
                                                   "profile|zed|not_found|-"});
}

TEST_CASE("wsl: a defect repeated across profiles stays one token in the reads",
          "[virtualization][wsl]") {
    // Deduped at push (not only by the ConstraintAccumulator in decide_wsl), so 512 refused
    // profiles never become a 512-entry token vector.
    FakeOps ops;
    FakeAccess acc;
    std::vector<ProfileInfo> ps;
    for (int i = 0; i < 40; ++i) {
        const std::string sid = "S-1-5-21-9-9-9-" + std::to_string(2000 + i);
        acc.cfg[sid] = {HiveAccessStatus::not_found};
        ps.push_back(profile(sid, "u" + std::to_string(i)));
    }
    const auto r = run(ps, acc, ops);
    CHECK(r.reads.profile_rows.size() == 40);
    CHECK(r.reads.tokens == std::vector<std::string>{"hive_not_found"});
}

TEST_CASE("wsl: every emitted token matches the class (a) grammar", "[virtualization][wsl]") {
    const std::regex re{"^windows:virtualization:wsl:[a-z0-9_]+$"};
    for (const auto s : wsl::kFixedTokenSuffixes)
        CHECK(std::regex_match(std::string{wsl::kTokenPrefix} + std::string{s}, re));
    CHECK(std::regex_match(std::string{wsl::kTokenPrefix} + "package_" + wsl::win32_cause(1450),
                           re));
    CHECK(std::regex_match(std::string{wsl::kTokenPrefix} + "profile_list_" + wsl::win32_cause(5),
                           re));
    CHECK(kProfileOutcomes.size() == 8);

    // Every profile-row outcome decide can produce is one of the eight literals.
    FakeOps ops;
    FakeAccess acc;
    const HiveAccessStatus all[] = {
        HiveAccessStatus::not_found, HiveAccessStatus::privilege_missing,
        HiveAccessStatus::mount_failed, HiveAccessStatus::file_refused};
    const char* sids[] = {kSidA, kSidB, kSidC, "S-1-5-21-9-9-9-1004"};
    std::vector<ProfileInfo> ps;
    for (int i = 0; i < 4; ++i) {
        acc.cfg[sids[i]] = {all[i], nullptr, "hive_path_unc", i == 0, 0};
        ps.push_back(profile(sids[i], "u" + std::to_string(i)));
    }
    acc.cfg["S-1-5-21-9-9-9-1005"] = {HiveAccessStatus::not_found, nullptr, "", false,
                                      wsl::kErrorAccessDenied};
    ps.push_back(profile("S-1-5-21-9-9-9-1005", "denied"));
    ps.push_back(profile("bad", "b"));
    ps.push_back(profile(std::string{kSidA} + ".bak", "k"));
    const auto r = run(ps, acc, ops);
    std::set<std::string> outcomes;
    for (const auto& row : r.posture.rows)
        if (row.starts_with("profile|")) {
            const auto a = row.find('|', 8);
            outcomes.insert(row.substr(a + 1, row.find('|', a + 1) - a - 1));
        }
    for (const auto& o : outcomes)
        CHECK(std::find(kProfileOutcomes.begin(), kProfileOutcomes.end(), o) !=
              kProfileOutcomes.end());
    CHECK(outcomes.size() == 8);
    for (const char* tok : {"windows:virtualization:wsl:hive_not_found",
                            "windows:virtualization:wsl:hive_access_denied"})
        CHECK(r.posture.reason.find(tok) != std::string::npos);
    const std::string& reason = r.posture.reason;
    for (std::size_t pos = 0; (pos = reason.find("windows:", pos)) != std::string::npos; ++pos) {
        const auto end = reason.find(',', pos);
        CHECK(std::regex_match(reason.substr(pos, end == std::string::npos ? end : end - pos), re));
    }
}
