/**
 * test_hw_ci_detail_wiring_lexical.cpp -- #7163 (part 3): a LEXICAL pin of the `hw_ci_detail_fn`
 * closure in server.cpp.
 *
 * WHAT THIS IS, AND IS NOT. This is a source-text scan (the test_store_wiring_order.cpp style), NOT
 * a behavioural test. ServerImpl is not unit-constructible, so nothing here executes the closure,
 * reaches a store, or proves that a request through the running server returns the right record;
 * the route and MCP tests use a fake `ci_detail_fn`, and the real mapping
 * (`apply_ci_with_sections_read`, `record_section_integrity`) is covered by its own unit tests.
 * It also pins the guard and arguments of the count call and the boot registration of the metric.
 * What this pins is the wiring those tests cannot see, by reading the stripped server.cpp text at
 * test run time (YUZU_SERVER_SRC_DIR):
 *   1. the closure is defined once and is the very one assigned to BOTH the REST routes' deps
 *      (`.ci_detail_fn = hw_ci_detail_fn`) and the MCP tools (`tool_deps.ci_detail_fn =
 *      hw_ci_detail_fn`), and no third `ci_detail_fn` composition exists in the file;
 *   2. inside its body, `CiRead::WithSections` selects `get_device_ci_with_sections` (and the
 *      integrity count after it), and every other read mode selects `get_device_ci`;
 *   3. an unwired `device_inventory_store_` degrades `ci` before either store method is named.
 * It matches identifiers with whitespace removed, so a reformat does not turn it red; a rename of
 * `hw_ci_detail_fn` or a restructuring that keeps the behaviour does, and the fix is to update the
 * names here. Comments are stripped first, so commented-out code cannot satisfy it. Limits: it
 * cannot tell that the branch is reachable or that the arguments are right.
 */

#include "source_scan.hpp"

#include <catch2/catch_test_macros.hpp>

#include <cstddef>
#include <string>
#include <string_view>

namespace {

using yuzu::test::source_scan::comment_free_source;
using yuzu::test::source_scan::count_occurrences;

/// `text` with every whitespace byte removed, so a needle matches whatever the line breaks are.
std::string squeeze(std::string_view text) {
    std::string out;
    out.reserve(text.size());
    for (const char c : text)
        if (c != ' ' && c != '\t' && c != '\n' && c != '\r')
            out.push_back(c);
    return out;
}

/// The squeezed body of the lambda `auto hw_ci_detail_fn = [...](...) -> HardwareCiDetail { ... };`
/// (everything between its outermost braces). Empty when it cannot be found or the braces do not
/// balance. The body holds no brace inside a string literal, so a plain depth count is enough.
std::string closure_body(const std::string& src) {
    const std::size_t def = src.find("auto hw_ci_detail_fn");
    if (def == std::string::npos)
        return {};
    const std::size_t ret = src.find("-> HardwareCiDetail", def);
    if (ret == std::string::npos)
        return {};
    const std::size_t open = src.find('{', ret);
    if (open == std::string::npos)
        return {};
    int depth = 0;
    for (std::size_t i = open; i < src.size(); ++i) {
        if (src[i] == '{')
            ++depth;
        else if (src[i] == '}' && --depth == 0)
            return squeeze(std::string_view(src).substr(open + 1, i - open - 1));
    }
    return {};
}

} // namespace

TEST_CASE("hw_ci_detail_fn wiring (LEXICAL pin, not behaviour): one closure feeds REST and MCP",
          "[hardware][wiring][lexical]") {
    const std::string& src = comment_free_source("server.cpp");
    const std::string flat = squeeze(src);

    // The closure is defined exactly once, with the named read mode as its second parameter.
    REQUIRE(count_occurrences(flat, "autohw_ci_detail_fn=[") == 1);
    CHECK(count_occurrences(flat, "conststd::string&agent_id,CiReadci_read)->HardwareCiDetail{") ==
          1);

    // It is the one handed to BOTH consumers, and to nothing else: a second `ci_detail_fn =`
    // composition (or a consumer wired to a different closure) would let the transports diverge.
    CHECK(count_occurrences(flat, ".ci_detail_fn=hw_ci_detail_fn,") == 1);
    CHECK(count_occurrences(flat, "tool_deps.ci_detail_fn=hw_ci_detail_fn;") == 1);
    // The member is only ever assigned in those two places (`.ci_detail_fn=` is the member access;
    // the closure's own definition `hw_ci_detail_fn=` has no leading dot).
    CHECK(count_occurrences(flat, ".ci_detail_fn=") == 2);
}

TEST_CASE(
    "hw_ci_detail_fn wiring (LEXICAL pin, not behaviour): the read mode selects the store method",
    "[hardware][wiring][lexical]") {
    const std::string body = closure_body(comment_free_source("server.cpp"));
    REQUIRE_FALSE(body.empty());

    const auto pos = [&](std::string_view needle) {
        return body.find(needle);
    };
    const auto npos = std::string::npos;

    // An unwired store degrades `ci` first, before either store method is named.
    const auto unwired =
        pos("if(!device_inventory_store_){detail.ci=std::unexpected(CiReadError::kDegraded);}");
    REQUIRE(unwired != npos);

    // The WithSections arm reads the record and sections together (one snapshot), then counts.
    const auto with_arm = pos("elseif(ci_read==CiRead::WithSections){");
    REQUIRE(with_arm != npos);
    CHECK(with_arm > unwired);
    const auto with_read = pos("apply_ci_with_sections_read(detail,device_inventory_store_->get_"
                               "device_ci_with_sections(agent_id));");
    REQUIRE(with_read != npos);
    CHECK(with_read > with_arm);
    // The count: guarded by the sections actually being present, passing the registry (not
    // nullptr), and directly after the sections read - not in a dead branch.
    const std::string guarded_call =
        "if(detail.ci_sections&&*detail.ci_sections)"
        "record_section_integrity(**detail.ci_sections,agent_id,&metrics_);";
    const auto counted = pos(guarded_call);
    REQUIRE(counted != npos);
    CHECK(counted > with_read);
    CHECK(counted == with_read + std::string_view("apply_ci_with_sections_read(detail,device_"
                                                  "inventory_store_->get_device_ci_with_sections("
                                                  "agent_id));")
                                     .size()); // adjacent: nothing wedged between read and count
    CHECK(count_occurrences(body, "&metrics_") == 1); // the registry is passed, once
    CHECK(count_occurrences(body, "nullptr") == 0);
    for (const std::string_view dead : {"if(false)", "if(0)", "if(!true)", "#if0", "#ifdef"})
        CHECK(body.find(dead) == npos);

    // Every other read mode (the dashboard and the actions lens: RecordOnly) takes the record-only
    // read, after the WithSections arm closes; the sections method is named exactly once.
    const auto else_arm = pos("}else{detail.ci=device_inventory_store_->get_device_ci(agent_id);}");
    REQUIRE(else_arm != npos);
    CHECK(else_arm > counted);
    CHECK(count_occurrences(body, "get_device_ci_with_sections(") == 1);
    CHECK(count_occurrences(body, "get_device_ci(") == 1);
    CHECK(count_occurrences(body, "record_section_integrity(") == 1);
}

TEST_CASE("hw_ci_detail_fn wiring (LEXICAL pin, not behaviour): the integrity metric is registered "
          "at boot",
          "[hardware][wiring][lexical]") {
    // The describe + the three pre-seeded series live in register_section_integrity_metrics; if
    // ServerImpl stops calling it the series appear only after a first fault.
    const std::string flat = squeeze(comment_free_source("server.cpp"));
    CHECK(count_occurrences(flat, "register_section_integrity_metrics(metrics_);") == 1);
    CHECK(count_occurrences(flat, "yuzu_hardware_section_integrity_total") ==
          0); // one home for the name
}
