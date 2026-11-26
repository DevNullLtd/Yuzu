/**
 * test_win_join_registry.cpp -- yuzu::agent::win::read_join_info and read_hklm_values
 * (agent-core), and the registry decode and walk rules (win_registry_walk.hpp) over a fake Ops.
 *
 * The decode, walk and injected-reader cases run on every OS. The injected-reader ones share the
 * production process-wide slots, so each one that blocks a reader opens its gate with a ScopeExit
 * and waits for the slot to recover. Ordering comes from promises; anything an abandonable reader
 * touches is captured BY VALUE. The caps are written here as literals, so moving one in the code
 * fails a case.
 *
 * TEST-EFFICIENCY JUSTIFICATION (runtime depends on a clock, thread creation and, in the real
 * cases, the OS): the deadline on a detached worker is the property under test (one 200 ms wait
 * per function). The real cases are bounded reads of local join state and fixed registry keys; on
 * Windows they are the only check that the shipped Win32 calls answer correctly.
 */

#include <catch2/catch_test_macros.hpp>

#include <yuzu/agent/win_join_info.hpp>
#include <yuzu/agent/win_registry_read.hpp>

#include "test_helpers.hpp"
#include "win_registry_walk.hpp"

#include <algorithm>
#include <atomic>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <functional>
#include <future>
#include <map>
#include <memory>
#include <string>
#include <vector>

using namespace std::chrono_literals;
using yuzu::agent::BoundedStatus;
using yuzu::agent::win::JoinInfoRead;
using yuzu::agent::win::read_hklm_values;
using yuzu::agent::win::read_hklm_values_for_test;
using yuzu::agent::win::read_join_info;
using yuzu::agent::win::read_join_info_for_test;
using yuzu::agent::win::RegRead;
using yuzu::agent::win::RegRequest;
using yuzu::agent::win::RegValue;
using yuzu::agent::win::detail::decode_reg_value;
using yuzu::agent::win::detail::walk_registry;
using Bytes = std::vector<std::uint8_t>;

namespace {

/// A never-returning reader: TimedOut, then Abandoned without a second call, then recovery.
/// `read(deadline, reader)` is one of the _for_test seams.
template <typename R, typename Read> void check_stall_and_recovery(Read read) {
    std::promise<void> gate;
    bool gate_open = false;
    const auto release = [&] {
        if (!gate_open) {
            gate_open = true;
            gate.set_value();
        }
    };
    // A failing REQUIRE must not leave a worker wedged: it holds the process-wide slot.
    yuzu::test::ScopeExit opener{release};
    auto entered = std::make_shared<std::promise<void>>();
    auto entered_f = entered->get_future();
    auto calls = std::make_shared<std::atomic<int>>(0);
    const std::function<R()> stalled = [opened = gate.get_future().share(), entered, calls] {
        if (++*calls == 1)
            entered->set_value();
        opened.wait();
        return R{};
    };

    CHECK(read(200ms, stalled).status == BoundedStatus::TimedOut);
    REQUIRE(entered_f.wait_for(5s) == std::future_status::ready);

    CHECK(read(5000ms, stalled).status == BoundedStatus::Abandoned);
    CHECK(calls->load() == 1);

    release();
    CHECK(yuzu::test::spin_until(
        [&] { return read(5000ms, [] { return R{}; }).status == BoundedStatus::Completed; }));
}

/// The bytes of a UTF-16LE payload, exactly as given (no terminator is added).
Bytes utf16le(std::u16string_view text) {
    Bytes out;
    for (const char16_t unit : text) {
        out.push_back(static_cast<std::uint8_t>(unit & 0xFF));
        out.push_back(static_cast<std::uint8_t>(unit >> 8));
    }
    return out;
}

RegValue decode(std::uint32_t type, const Bytes& data) {
    return decode_reg_value("name-a", type, data);
}

struct FakeValue {
    std::uint32_t type = 3; // REG_BINARY
    Bytes data;
    std::uint32_t rc = 0; ///< a non-zero answer to both queries
    int grows = 0;        ///< data queries answered "more data" before one succeeds
};

/// Every key holds the same values; an unlisted name is absent.
struct FakeOps {
    std::uint32_t base_rc = 0;
    std::vector<std::u16string> children;
    std::size_t enum_fails_at = static_cast<std::size_t>(-1);
    std::map<std::u16string, std::uint32_t> refused; ///< child name -> open error
    std::map<std::string, FakeValue> values;

    int calls = 0;
    std::vector<std::uint32_t> access; ///< of every open, the base first
    std::vector<std::u16string> opened;
    std::map<std::string, int> size_queries;
    std::map<std::string, int> data_queries;

    std::uint32_t open_base(const std::string&, std::uint32_t mask) {
        ++calls;
        access.push_back(mask);
        return base_rc;
    }
    std::uint32_t child_name(std::uint32_t index, std::u16string& name) {
        ++calls;
        if (index == enum_fails_at)
            return 5;
        if (index >= children.size())
            return 259;
        name = children[index];
        return 0;
    }
    std::uint32_t open_child(const std::u16string& name, std::uint32_t mask) {
        ++calls;
        access.push_back(mask);
        opened.push_back(name);
        const auto it = refused.find(name);
        return it == refused.end() ? 0 : it->second;
    }
    std::uint32_t query_value(const std::string& name, std::uint32_t& type, std::uint8_t* data,
                              std::uint32_t& size) {
        ++calls;
        ++(data ? data_queries : size_queries)[name];
        const auto it = values.find(name);
        if (it == values.end())
            return 2;
        FakeValue& value = it->second;
        if (value.rc != 0)
            return value.rc;
        type = value.type;
        const auto length = static_cast<std::uint32_t>(value.data.size());
        if (data) {
            if (value.grows > 0) {
                --value.grows;
                return 234;
            }
            if (size < length)
                return 234;
            std::copy(value.data.begin(), value.data.end(), data);
        }
        size = length;
        return 0;
    }
};

} // namespace

TEST_CASE("read_join_info_for_test returns the injected answer", "[bounded_os_call][agent]") {
    const auto r = read_join_info_for_test(5000ms, [] {
        JoinInfoRead out;
        out.nerr = 5;
        out.has_name = true;
        out.name = "name-a";
        out.join_status = 3;
        return out;
    });
    REQUIRE(r.status == BoundedStatus::Completed);
    CHECK(r.nerr == 5);
    CHECK(r.has_name);
    CHECK(r.name == "name-a");
    CHECK(r.join_status == 3);
}

TEST_CASE("read_hklm_values_for_test returns the injected answer", "[bounded_os_call][agent]") {
    const auto r = read_hklm_values_for_test(5000ms, [] {
        RegRead out;
        out.win_error = 5;
        out.truncated = true;
        out.keys.push_back({"child-a", 6, {{"name-a", true, 0, 1, "text-a", 7, {1, 2}}}});
        return out;
    });
    REQUIRE(r.status == BoundedStatus::Completed);
    CHECK(r.win_error == 5);
    CHECK(r.truncated);
    REQUIRE(r.keys.size() == 1);
    CHECK(r.keys.front().child == "child-a");
    CHECK(r.keys.front().win_error == 6);
    REQUIRE(r.keys.front().values.size() == 1);
    const auto& v = r.keys.front().values.front();
    CHECK(v.name == "name-a");
    CHECK(v.present);
    CHECK(v.type == 1);
    CHECK(v.text == "text-a");
    CHECK(v.number == 7);
    CHECK(v.bytes == Bytes{1, 2});
}

TEST_CASE("a never-returning join reader times out, then Abandoned, then recovers",
          "[bounded_os_call][agent]") {
    check_stall_and_recovery<JoinInfoRead>(
        [](std::chrono::milliseconds deadline, const std::function<JoinInfoRead()>& reader) {
            return read_join_info_for_test(deadline, reader);
        });
}

TEST_CASE("a never-returning registry reader times out, then Abandoned, then recovers",
          "[bounded_os_call][agent]") {
    check_stall_and_recovery<RegRead>(
        [](std::chrono::milliseconds deadline, const std::function<RegRead()>& reader) {
            return read_hklm_values_for_test(deadline, reader);
        });
}

TEST_CASE("decode_reg_value: REG_SZ and REG_EXPAND_SZ", "[bounded_os_call][agent]") {
    const auto terminated = decode(1, utf16le({u"aé\0", 3}));
    CHECK(terminated.name == "name-a");
    CHECK(terminated.present);
    CHECK(terminated.win_error == 0);
    CHECK(terminated.type == 1);
    CHECK(terminated.text == "a\xc3\xa9");
    CHECK(terminated.bytes.empty());

    CHECK(decode(1, utf16le(u"ab")).text == "ab");
    CHECK(decode(1, {'a', 0, 'b'}).text == "a"); // the odd trailing byte is dropped
    CHECK(decode(1, utf16le({u"a\0b\0", 4})).text == "a");
    CHECK(decode(2, utf16le(u"%windir%\\x")).text == "%windir%\\x");

    const auto empty = decode(1, {});
    CHECK(empty.present);
    CHECK(empty.win_error == 0);
    CHECK(empty.text.empty());
}

TEST_CASE("decode_reg_value: REG_MULTI_SZ", "[bounded_os_call][agent]") {
    CHECK(decode(7, utf16le({u"ab\0cd\0\0", 7})).text == "ab\ncd");
    CHECK(decode(7, utf16le({u"ab\0cd", 5})).text == "ab\ncd"); // no terminator at all
    CHECK(decode(7, utf16le({u"ab\0\0cd\0", 7})).text == "ab"); // the empty string ends the list
    CHECK(decode(7, {}).text.empty());
}

TEST_CASE("decode_reg_value: numbers and other types", "[bounded_os_call][agent]") {
    CHECK(decode(4, {0x04, 0x03, 0x02, 0x01}).number == 0x01020304u);
    CHECK(decode(11, {0x08, 0x07, 0x06, 0x05, 0x04, 0x03, 0x02, 0x01}).number ==
          0x0102030405060708ull);

    for (const auto& value : {decode(4, Bytes(3, 0xFF)), decode(11, Bytes(7, 0xFF))}) {
        CHECK(value.present);
        CHECK(value.win_error == 13);
        CHECK(value.number == 0);
        CHECK(value.bytes.empty());
    }

    for (const std::uint32_t type : {3u, 5u, 99u}) { // binary, big-endian DWORD, unknown
        const auto value = decode(type, {1, 2, 3, 4});
        CHECK(value.present);
        CHECK(value.win_error == 0);
        CHECK(value.type == type);
        CHECK(value.number == 0);
        CHECK(value.text.empty());
        CHECK(value.bytes == Bytes{1, 2, 3, 4});
    }
}

TEST_CASE("walk_registry refuses a request over the caps without an Ops call",
          "[bounded_os_call][agent]") {
    for (const RegRequest& request :
         {RegRequest{"SOFTWARE", std::vector<std::string>(65, "name-a")},
          RegRequest{"", {"name-a"}}}) {
        FakeOps ops;
        const auto r = walk_registry(request, ops);
        CHECK(r.win_error == 87);
        CHECK(r.keys.empty());
        CHECK(ops.calls == 0);
    }

    FakeOps ops;
    const auto r = walk_registry({"SOFTWARE", std::vector<std::string>(64, "name-a")}, ops);
    CHECK(r.win_error == 0);
    REQUIRE(r.keys.size() == 1);
    CHECK(r.keys.front().values.size() == 64);
}

TEST_CASE("walk_registry opens every key read-only in the requested view",
          "[bounded_os_call][agent]") {
    // KEY_READ (0x20019) plus KEY_WOW64_64KEY (0x100) or KEY_WOW64_32KEY (0x200), nothing else.
    for (const bool wow64_32 : {false, true}) {
        FakeOps ops;
        ops.children = {u"a"};
        walk_registry({"SOFTWARE", {"name-a"}, true, wow64_32}, ops);
        const std::uint32_t expected = wow64_32 ? 0x20219u : 0x20119u;
        CHECK(ops.access == std::vector<std::uint32_t>{expected, expected});
    }
}

TEST_CASE("walk_registry reports a failed base open and reads nothing",
          "[bounded_os_call][agent]") {
    FakeOps ops;
    ops.base_rc = 5;
    const auto r = walk_registry({"SOFTWARE", {"name-a"}, true}, ops);
    CHECK(r.win_error == 5);
    CHECK(r.keys.empty());
    CHECK(ops.calls == 1);
}

TEST_CASE("walk_registry reads the key itself, present and absent values",
          "[bounded_os_call][agent]") {
    FakeOps ops;
    ops.values["dword"] = {4, {7, 0, 0, 0}};
    ops.values["empty"] = {1, {}};
    ops.values["denied"] = {1, {}, 5};
    const auto r = walk_registry({"SOFTWARE", {"absent", "dword", "empty", "denied"}}, ops);
    CHECK(r.win_error == 0);
    CHECK_FALSE(r.truncated);
    CHECK(ops.opened.empty());
    REQUIRE(r.keys.size() == 1);
    CHECK(r.keys.front().child.empty());
    const auto& v = r.keys.front().values;
    REQUIRE(v.size() == 4);
    CHECK(v[0].name == "absent");
    CHECK_FALSE(v[0].present);
    CHECK(v[0].win_error == 2);
    CHECK(v[1].present);
    CHECK(v[1].number == 7);
    // An empty value still gets a data query, which needs a buffer to point at.
    CHECK(v[2].present);
    CHECK(v[2].win_error == 0);
    CHECK(ops.data_queries["empty"] == 1);
    CHECK_FALSE(v[3].present);
    CHECK(v[3].win_error == 5);
}

TEST_CASE("walk_registry goes on past a child that cannot be opened", "[bounded_os_call][agent]") {
    FakeOps ops;
    ops.children = {u"a", u"b", u"c"};
    ops.refused[u"b"] = 5;
    ops.values["name-a"] = {3, {1}};
    const auto r = walk_registry({"SOFTWARE", {"name-a"}, true}, ops);
    CHECK(r.win_error == 0);
    CHECK_FALSE(r.truncated);
    CHECK(ops.opened == ops.children);
    REQUIRE(r.keys.size() == 3);
    CHECK(r.keys[0].child == "a");
    CHECK(r.keys[1].child == "b");
    CHECK(r.keys[1].win_error == 5);
    CHECK(r.keys[1].values.empty());
    CHECK(r.keys[2].child == "c");
    CHECK(r.keys[2].win_error == 0);
    REQUIRE(r.keys[2].values.size() == 1);
    CHECK(r.keys[2].values.front().present);
}

TEST_CASE("walk_registry keeps what it read when enumeration fails", "[bounded_os_call][agent]") {
    FakeOps ops;
    ops.children = {u"a", u"b", u"c"};
    ops.enum_fails_at = 1;
    const auto r = walk_registry({"SOFTWARE", {"name-a"}, true}, ops);
    CHECK(r.win_error == 5);
    CHECK(r.truncated);
    REQUIRE(r.keys.size() == 1);
    CHECK(r.keys.front().child == "a");
}

TEST_CASE("walk_registry reads at most 256 children", "[bounded_os_call][agent]") {
    for (const std::size_t count : {std::size_t{256}, std::size_t{257}}) {
        FakeOps ops;
        ops.children.assign(count, u"a");
        const auto r = walk_registry({"SOFTWARE", {"name-a"}, true}, ops);
        CHECK(r.win_error == 0);
        CHECK(r.truncated == (count == 257));
        CHECK(r.keys.size() == 256);
        CHECK(ops.opened.size() == 256);
    }
}

TEST_CASE("walk_registry returns no payload for a value over 64 KiB and reads on",
          "[bounded_os_call][agent]") {
    FakeOps ops;
    ops.values["at-cap"] = {3, Bytes(65536, 1)};
    ops.values["over"] = {3, Bytes(65537, 1)};
    ops.values["next"] = {3, {2}};
    const auto r = walk_registry({"SOFTWARE", {"at-cap", "over", "next"}}, ops);
    CHECK(r.truncated);
    REQUIRE(r.keys.size() == 1);
    const auto& v = r.keys.front().values;
    REQUIRE(v.size() == 3);
    CHECK(v[0].win_error == 0);
    CHECK(v[0].bytes.size() == 65536);
    CHECK(v[1].present);
    CHECK(v[1].win_error == 234);
    CHECK(v[1].type == 3);
    CHECK(v[1].bytes.empty());
    CHECK(ops.data_queries["over"] == 0); // refused on the queried size, before any buffer
    CHECK(v[2].bytes == Bytes{2});
}

TEST_CASE("walk_registry re-reads a growing value at most three times",
          "[bounded_os_call][agent]") {
    FakeOps ops;
    ops.values["settles"] = {3, {1}, 0, 3};
    ops.values["keeps-growing"] = {3, {1}, 0, 4};
    ops.values["next"] = {3, {2}};
    const auto r = walk_registry({"SOFTWARE", {"settles", "keeps-growing", "next"}}, ops);
    CHECK(r.truncated);
    REQUIRE(r.keys.size() == 1);
    const auto& v = r.keys.front().values;
    REQUIRE(v.size() == 3);
    CHECK(v[0].win_error == 0);
    CHECK(v[0].bytes == Bytes{1});
    CHECK(v[1].present);
    CHECK(v[1].win_error == 234);
    CHECK(v[1].bytes.empty());
    CHECK(ops.size_queries["keeps-growing"] == 4); // sized again before each re-read
    CHECK(ops.data_queries["keeps-growing"] == 4);
    CHECK(v[2].bytes == Bytes{2});
}

TEST_CASE("walk_registry stops at 1 MiB of value data", "[bounded_os_call][agent]") {
    // Eight names of 64 KiB are 512 KiB a key: two children fit exactly.
    RegRequest request{"SOFTWARE", {}, true};
    FakeOps ops;
    for (int i = 0; i < 8; ++i) {
        const auto name = "name-" + std::to_string(i);
        request.value_names.push_back(name);
        ops.values[name] = {3, Bytes(65536, 1)};
    }

    ops.children = {u"a", u"b"};
    const auto fits = walk_registry(request, ops);
    CHECK_FALSE(fits.truncated);
    REQUIRE(fits.keys.size() == 2);
    CHECK(fits.keys.back().values.size() == 8);

    ops.children = {u"a", u"b", u"c", u"d"};
    ops.opened.clear();
    ops.size_queries.clear();
    const auto over = walk_registry(request, ops);
    CHECK(over.truncated);
    CHECK(over.win_error == 0);
    REQUIRE(over.keys.size() == 3);
    CHECK(over.keys[1].values.size() == 8);
    CHECK(over.keys[2].values.empty());
    CHECK(ops.opened.size() == 3); // the fourth child is never opened
    CHECK(ops.size_queries["name-0"] == 3);
    CHECK(ops.size_queries["name-1"] == 2); // nothing after the value that passed the cap
}

#ifdef _WIN32

TEST_CASE("read_join_info answers on this host", "[bounded_os_call][agent]") {
    const auto r = read_join_info(yuzu::agent::win::kJoinInfoDeadline);
    REQUIRE(r.status == BoundedStatus::Completed);
    CHECK(r.nerr == 0);
}

TEST_CASE("read_hklm_values reads present and absent values", "[bounded_os_call][agent]") {
    const auto r = read_hklm_values({"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion",
                                     {"CurrentBuildNumber", "ProductName", "YuzuNoSuchValue"}},
                                    yuzu::agent::win::kRegistryReadDeadline);
    REQUIRE(r.status == BoundedStatus::Completed);
    CHECK(r.win_error == 0);
    CHECK_FALSE(r.truncated);
    REQUIRE(r.keys.size() == 1);
    CHECK(r.keys.front().child.empty());
    const auto& values = r.keys.front().values;
    REQUIRE(values.size() == 3);
    for (std::size_t i = 0; i < 2; ++i) {
        CHECK(values[i].present);
        CHECK_FALSE(values[i].text.empty());
    }
    CHECK_FALSE(values[2].present);
    CHECK(values[2].win_error == 2);
}

TEST_CASE("read_hklm_values walks immediate children", "[bounded_os_call][agent]") {
    const auto r = read_hklm_values({"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\ProfileList",
                                     {"ProfileImagePath"},
                                     true},
                                    yuzu::agent::win::kRegistryReadDeadline);
    REQUIRE(r.status == BoundedStatus::Completed);
    CHECK(r.win_error == 0);
    REQUIRE_FALSE(r.keys.empty());
    CHECK_FALSE(r.keys.front().child.empty());
    CHECK(std::any_of(r.keys.begin(), r.keys.end(), [](const auto& key) {
        return key.values.size() == 1 && key.values.front().present;
    }));
}

#else

TEST_CASE("the join and registry reads answer unimplemented off Windows",
          "[bounded_os_call][agent]") {
    const auto join = read_join_info(yuzu::agent::win::kJoinInfoDeadline);
    REQUIRE(join.status == BoundedStatus::Completed);
    CHECK(join.nerr == 120);
    CHECK_FALSE(join.has_name);

    const auto reg =
        read_hklm_values({"SOFTWARE", {"name-a"}}, yuzu::agent::win::kRegistryReadDeadline);
    REQUIRE(reg.status == BoundedStatus::Completed);
    CHECK(reg.win_error == 120);
    CHECK(reg.keys.empty());
}

#endif
