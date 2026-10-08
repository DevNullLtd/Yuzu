/**
 * test_instruction_param_golden.cpp - golden accept/reject table for the strict parameter
 * validation of POST /api/instructions/{id}/execute.
 *
 * PG-free and route-free. Each row is (definition id, params, expected verdict) and is run
 * through the SHIPPED definition's stored schema (kBundledDefinitions, generated from
 * content/) with instr::prepare_param_validator + ParamValidator::check, the pair the route
 * calls. A content or validator change that flips a row fails here, and the strictness note
 * in docs/user-manual/upgrading.md has to be revisited with it.
 *
 * A row whose definition id starts with '@' is not a shipped definition: the rest of the id
 * is the RAW stored schema text (the `{}`, empty and whitespace "no schema" forms).
 */

#include "bundled_content.hpp"
#include "instruction_param_schema.hpp"

#include <catch2/catch_test_macros.hpp>
#include <nlohmann/json.hpp>

#include <map>
#include <string>
#include <vector>

using nlohmann::json;
using yuzu::server::instr::prepare_param_validator;

namespace {

struct Row {
    std::string def;  // shipped definition id, or "@<raw stored schema text>"
    json params;      // what the caller sent as `params` (null = omitted)
    bool accept;      // expected verdict
    const char* note;  // shown on failure
};

// definition id -> the stored `parameter_schema` text ("" when none is stored)
std::map<std::string, std::string> shipped_schemas() {
    std::map<std::string, std::string> out;
    for (const auto& raw : yuzu::server::kBundledDefinitions) {
        const json env = json::parse(raw, nullptr, false);
        REQUIRE_FALSE(env.is_discarded());
        const std::string id = env.value("id", std::string{});
        REQUIRE_FALSE(id.empty());
        out[id] = (env.contains("parameter_schema") && env["parameter_schema"].is_string())
                      ? env["parameter_schema"].get<std::string>()
                      : std::string{};
    }
    return out;
}

const std::string kHash64(64, 'a');
const std::string kNul = std::string("info") + std::string(1, '\0') + "x";

std::vector<Row> golden_rows() {
    std::vector<Row> r;
    auto acc = [&r](const char* def, json p, const char* note) {
        r.push_back({def, std::move(p), true, note});
    };
    auto rej = [&r](const char* def, json p, const char* note) {
        r.push_back({def, std::move(p), false, note});
    };

    // The six corrected definitions. Every accept row names a parameter that is accepted only
    // while the shipped schema declares it, so un-declaring it fails here.
    acc("agent.content_dist.cleanup", {{"hours", 24}}, "cleanup hours");
    acc("agent.content_dist.cleanup", {{"hours", "168"}}, "cleanup hours as a GUI string");
    acc("agent.content_dist.cleanup", {{"filename", "x.msi"}}, "the dead filename stays declared");
    rej("agent.content_dist.cleanup", {{"hours", "soon"}}, "unparsable hours");
    // 0 and below are documented as "remove everything". Above the maximum the server refuses
    // on execute-by-id; the plugin clamps independently (parse_cleanup_hours saturates at
    // 876000), so the cutoff arithmetic can no longer wrap into the future.
    acc("agent.content_dist.cleanup", {{"hours", 0}}, "hours 0 removes everything, as documented");
    acc("agent.content_dist.cleanup", {{"hours", -1}}, "negative hours, as documented");
    acc("agent.content_dist.cleanup", {{"hours", 876000}}, "hours at its maximum");
    rej("agent.content_dist.cleanup", {{"hours", 876001}}, "hours one over its maximum");
    rej("agent.content_dist.cleanup", {{"hours", 1500000}}, "hours far above its maximum");
    // The dashboard sends digit strings; coercion runs before the bound check.
    acc("agent.content_dist.cleanup", {{"hours", "876000"}}, "hours digit string at its maximum");
    rej("agent.content_dist.cleanup", {{"hours", "876001"}},
        "hours digit string one over its maximum");
    rej("agent.content_dist.cleanup", {{"hours", "1500000"}},
        "hours digit string past the overflow point");
    acc("agent.content_dist.execute_staged", {{"filename", "a.msi"}, {"expected_hash", kHash64}},
        "execute_staged expected_hash");
    rej("agent.content_dist.execute_staged", {{"filename", "a.msi"}, {"expected_hash", "ABC"}},
        "expected_hash is 64 lowercase hex");
    for (const char* lvl : {"INFO", "Debug", "warn", "WARNING", "Err", "critical", "off"})
        acc("device.agent_actions.set_log_level", {{"level", lvl}}, "set_log_level, any case/alias");
    rej("device.agent_actions.set_log_level", {{"level", "verbose"}}, "not a level");
    rej("device.agent_actions.set_log_level", {{"level", "info "}}, "trailing space: anchored");
    rej("device.agent_actions.set_log_level", {{"level", "info\n"}}, "trailing newline: $ is end of text");
    rej("device.agent_actions.set_log_level", {{"level", ""}}, "empty level");
    rej("device.agent_actions.set_log_level", {{"level", kNul}}, "embedded NUL");
    acc("device.wol.check", {{"host", "10.0.0.1"}, {"timeout_ms", 1000}}, "wol.check timeout_ms");
    acc("device.wol.check", {{"host", "10.0.0.1"}, {"count", "5"}}, "wol.check count");
    acc("device.wol.check", {{"host", "10.0.0.1"}, {"timeout_ms", 100}}, "timeout_ms at minimum");
    acc("device.wol.check", {{"host", "10.0.0.1"}, {"timeout_ms", 5000}}, "timeout_ms at maximum");
    rej("device.wol.check", {{"host", "10.0.0.1"}, {"timeout_ms", 99}}, "timeout_ms below minimum");
    rej("device.wol.check", {{"host", "10.0.0.1"}, {"timeout_ms", 5001}}, "timeout_ms above maximum");
    acc("workflow.config_search_and_replace",
        {{"path", "/etc/a.ini"}, {"search", "a"}, {"replacement", "b"}, {"dry_run", "true"}},
        "dry_run, read by filesystem.replace");
    acc("workflow.config_search_and_replace",
        {{"path", "/etc/a.ini"}, {"search", "a"}, {"replacement", "b"},
         {"case_sensitive", "false"}, {"max_replacements", 3}},
        "case_sensitive and max_replacements");
    rej("workflow.config_search_and_replace",
        {{"path", "/etc/a.ini"}, {"search", "a"}, {"replacement", "b"}, {"dry_run", "True"}},
        "dry_run enum is case-sensitive");
    rej("workflow.config_search_and_replace",
        {{"config_path", "/etc/a.ini"}, {"old_value", "a"}, {"new_value", "b"}},
        "the old names the plugin never read");
    acc("workflow.version_compliance_check", {{"path", "/usr/bin/app"}}, "path, read by get_version_info");
    rej("workflow.version_compliance_check", {{"executable_path", "/usr/bin/app"}},
        "the old name the plugin never read");

    // Enums the plugin never enforced.
    acc("device.filesystem.search_dir", {{"root", "/tmp"}, {"pattern", "*"}, {"match_type", "both"}},
        "a declared match_type");
    rej("device.filesystem.search_dir", {{"root", "/tmp"}, {"pattern", "*"}, {"match_type", "all"}},
        "the plugin matched every entry for an unknown match_type");
    acc("device.asset_tags.sync", {{"environment", "Production"}}, "a member of the enum");
    rej("device.asset_tags.sync", {{"environment", "staging"}}, "not a member");
    acc("windows.features.list", {{"state", "pending"}}, "a declared state");
    rej("windows.features.list", {{"state", "all"}}, "the plugin ignored an unknown state");
    acc("crossplatform.tar.query", {{"type", "dns"}}, "a declared type");
    rej("crossplatform.tar.query", {{"type", "bogus"}}, "an unknown type");

    // Over-maximum values the plugin used to clamp.
    acc("device.agent_logging.get_log", {{"lines", 1}}, "get_log at its minimum");
    acc("device.agent_logging.get_log", {{"lines", 500}}, "get_log at its maximum");
    rej("device.agent_logging.get_log", {{"lines", 501}}, "get_log one over");
    rej("device.agent_logging.get_log", {{"lines", 0}}, "get_log below its minimum");
    acc("device.script_exec.exec", {{"command", "/bin/true"}, {"timeout", 3600}}, "timeout at maximum");
    rej("device.script_exec.exec", {{"command", "/bin/true"}, {"timeout", 3601}}, "timeout one over");
    rej("device.script_exec.exec", {{"command", "/bin/true"}, {"timeout", 0}}, "timeout below minimum");
    acc("device.event_logs.errors", {{"hours", 720}}, "errors hours at maximum");
    rej("device.event_logs.errors", {{"hours", 721}}, "errors hours one over");
    acc("device.windows_updates.patch_connectivity", {{"timeout_seconds", 30}}, "in range");
    rej("device.windows_updates.patch_connectivity", {{"timeout_seconds", 61}}, "one over");

    // String forms, empty and null, floats.
    acc("device.interaction.set_dnd", {{"enabled", "true"}, {"duration_minutes", "30"}},
        "integer sent as a digit string");
    acc("device.interaction.set_dnd", {{"enabled", true}}, "JSON true is stringified to the enum member");
    rej("device.interaction.set_dnd", {{"enabled", "True"}}, "enum is case-sensitive");
    rej("device.interaction.set_dnd", {{"enabled", "1"}}, "the plugin read 1 as true");
    rej("device.interaction.set_dnd", {{"enabled", "true"}, {"duration_minutes", "+5"}}, "leading plus");
    rej("device.interaction.set_dnd", {{"enabled", "true"}, {"duration_minutes", " 5"}}, "leading space");
    rej("device.interaction.set_dnd", {{"enabled", "true"}, {"duration_minutes", ""}},
        "empty string for an optional integer");
    rej("device.interaction.set_dnd", {{"enabled", "true"}, {"duration_minutes", nullptr}},
        "null for an optional integer");
    rej("device.interaction.set_dnd", {{"enabled", ""}}, "empty string for an enum");
    rej("device.wol.check", {{"host", "h"}, {"count", ""}}, "empty string for a patterned string");
    rej("device.wol.check", {{"host", "h"}, {"count", nullptr}}, "null for a patterned string");
    rej("device.event_logs.errors", {{"hours", 5.0}}, "5.0 is not an integer");
    rej("device.event_logs.errors", {{"hours", nullptr}}, "null for an integer");

    // No-properties, required, defaults, undeclared, value limits.
    rej("device.os_info.os_name", {{"x", "y"}}, "a param to a no-param definition");
    acc("device.os_info.os_name", json::object(), "empty object");
    acc("device.os_info.os_name", nullptr, "params omitted");
    rej("device.os_info.os_name", json::array(), "a non-object params when a schema is stored");
    rej("device.wol.check", json::object(), "host omitted");
    rej("crossplatform.tar.sql", json::object(), "no default for sql");
    acc("device.wol.check", {{"host", "h"}}, "only the required name supplied");
    acc("crossplatform.tar.recent_processes", json::object(), "required sql has a default");
    rej("device.wol.check", {{"host", "h"}, {"legacy_param", 1}}, "undeclared name");
    rej("device.wol.check", {{"host", std::string("a") + '\0' + "b"}}, "embedded NUL");
    rej("device.wol.check", {{"host", "h"}, {"count", std::string(70 * 1024, '7')}}, "70 KiB patterned value");
    rej("device.script_exec.exec", {{"command", std::string(4097, 'a')}}, "one over maxLength");

    // No schema stored: anything passes (the YAML-saved forms).
    acc("@{}", {{"anything", 1}}, "literal {}");
    acc("@{}", json::array({1, 2}), "{} ignores a non-object params");
    acc("@", {{"anything", "x"}}, "empty stored schema");
    acc("@   ", {{"anything", "x"}}, "whitespace stored schema");
    return r;
}

}  // namespace

TEST_CASE("param-golden: every shipped definition's stored schema prepares",
          "[instr][param-schema][param-golden]") {
    std::size_t declared = 0;
    for (const auto& [id, schema] : shipped_schemas()) {
        INFO("definition " << id);
        auto v = prepare_param_validator(schema);
        REQUIRE(v.has_value());
        declared += v->absent() ? 0 : 1;
    }
    CHECK(declared > 100);  // the corpus is mostly declared schemas, not the 7 with none stored
}

TEST_CASE("param-golden: every definition id in the table is a shipped definition that stores a schema",
          "[instr][param-schema][param-golden]") {
    const auto shipped = shipped_schemas();
    for (const auto& row : golden_rows()) {
        if (row.def[0] == '@')
            continue;
        INFO("definition id '" << row.def << "' (renamed or removed?)");
        REQUIRE(shipped.count(row.def) == 1);
        // Otherwise its rows would all vacuously accept.
        CHECK_FALSE(shipped.at(row.def).empty());
    }
}

TEST_CASE("param-golden: each row is accepted or rejected exactly as recorded",
          "[instr][param-schema][param-golden]") {
    const auto shipped = shipped_schemas();
    for (const auto& row : golden_rows()) {
        const std::string stored = row.def[0] == '@' ? row.def.substr(1) : shipped.at(row.def);
        INFO("def=" << row.def << " note=" << row.note
                    << " params(prefix)=" << row.params.dump().substr(0, 120));
        auto v = prepare_param_validator(stored);
        REQUIRE(v.has_value());
        const auto violation = v->check(row.params);
        INFO("violation: " << (violation ? violation->path + ": " + violation->reason
                                         : std::string("(none)")));
        CHECK(violation.has_value() == !row.accept);
    }
}
