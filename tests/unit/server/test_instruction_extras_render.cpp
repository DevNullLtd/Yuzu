/**
 * test_instruction_extras_render.cpp -- pure helpers behind the Instructions
 * extras: the YAML-save merge (B-1) and the library fragment's limit clamp,
 * approval label, truncation foot and sets panel (B-2). No store, no route.
 */

#include "instruction_extras_render.hpp"

#include <catch2/catch_test_macros.hpp>

#include <string>

using namespace yuzu::server;
namespace ex = yuzu::server::instruction_extras;

namespace {

InstructionDefinition stored_row() {
    InstructionDefinition d;
    d.id = "def.keep";
    d.name = "Old name";
    d.version = "2.3.4";
    d.type = "action";
    d.plugin = "os_info";
    d.action = "os_name";
    d.description = "old description";
    d.enabled = false;
    d.instruction_set_id = "set-123";
    d.gather_ttl_seconds = 77;
    d.response_ttl_days = 12;
    d.created_by = "original-author";
    d.parameter_schema = R"({"type":"object"})";
    d.result_schema = R"({"cols":["a"]})";
    d.approval_mode = "always";
    d.concurrency_mode = "per-definition";
    d.platforms = "windows,linux";
    d.min_agent_version = "1.2.3";
    d.required_plugins = "os_info";
    d.readable_payload = "Inspect ${x}";
    d.visualization_spec = R"({"kind":"bar"})";
    d.response_templates_spec = R"([{"name":"t"}])";
    return d;
}

instruction_yaml::DefinitionFields yaml_fields() {
    instruction_yaml::DefinitionFields f;
    f.name = "New name";
    f.plugin = "os_info";
    f.action = "os_version";
    f.description = "new description";
    f.has_description = true;
    return f; // version/type/concurrency/approval omitted
}

} // namespace

TEST_CASE("instruction_extras: a YAML that omits description keeps the stored one; an explicit "
          "empty one clears it",
          "[instruction_extras][merge]") {
    auto stored = stored_row();
    stored.description = "kept description";

    auto f = yaml_fields();
    f.description.clear();
    f.has_description = false; // the YAML does not mention a description
    CHECK(ex::merge_yaml_into_stored(stored, f, "y", "editor").description == "kept description");

    f.has_description = true; // `description: ""`
    CHECK(ex::merge_yaml_into_stored(stored, f, "y", "editor").description.empty());

    f.description = "edited";
    CHECK(ex::merge_yaml_into_stored(stored, f, "y", "editor").description == "edited");
}

TEST_CASE("instruction_extras: merge carries forward every column the YAML cannot express",
          "[instruction_extras][merge]") {
    const auto stored = stored_row();
    auto d = ex::merge_yaml_into_stored(stored, yaml_fields(), "yaml: text", "editor");

    // YAML-carried fields are the edit.
    CHECK(d.name == "New name");
    CHECK(d.action == "os_version");
    CHECK(d.description == "new description");
    CHECK(d.yaml_source == "yaml: text");
    // Everything else survives.
    CHECK(d.instruction_set_id == "set-123");
    CHECK_FALSE(d.enabled);
    CHECK(d.gather_ttl_seconds == 77);
    CHECK(d.response_ttl_days == 12);
    CHECK(d.result_schema == stored.result_schema);
    CHECK(d.visualization_spec == stored.visualization_spec);
    CHECK(d.response_templates_spec == stored.response_templates_spec);
    CHECK(d.platforms == "windows,linux");
    CHECK(d.min_agent_version == "1.2.3");
    CHECK(d.required_plugins == "os_info");
    CHECK(d.readable_payload == "Inspect ${x}");
    CHECK(d.created_by == "original-author");
    // parameter_schema empty means KEEP in update_definition.
    CHECK(d.parameter_schema.empty());
}

TEST_CASE("instruction_extras: a YAML that omits approval/type/version/concurrency keeps the "
          "stored values, never the create defaults",
          "[instruction_extras][merge]") {
    auto d = ex::merge_yaml_into_stored(stored_row(), yaml_fields(), "y", "editor");
    CHECK(d.approval_mode == "always");
    CHECK(d.type == "action");
    CHECK(d.version == "2.3.4");
    CHECK(d.concurrency_mode == "per-definition");
}

TEST_CASE("instruction_extras: a YAML value that differs from the stored one is an intentional "
          "edit and is written",
          "[instruction_extras][merge]") {
    auto f = yaml_fields();
    f.approval = "auto";
    f.type = "question";
    f.version = "3.0.0";
    f.concurrency = "per-device";
    auto d = ex::merge_yaml_into_stored(stored_row(), f, "y", "editor");
    CHECK(d.approval_mode == "auto");
    CHECK(d.type == "question");
    CHECK(d.version == "3.0.0");
    CHECK(d.concurrency_mode == "per-device");
}

TEST_CASE("instruction_extras: a stored row with empty scalars falls back to the create "
          "defaults",
          "[instruction_extras][merge]") {
    InstructionDefinition blank;
    blank.id = "d";
    auto d = ex::merge_yaml_into_stored(blank, yaml_fields(), "y", "editor");
    CHECK(d.approval_mode == "auto");
    CHECK(d.type == "question");
    CHECK(d.version == "1.0.0");
    CHECK(d.concurrency_mode == "per-device");
    CHECK(d.created_by == "editor"); // no stored author: the saver is recorded
}

TEST_CASE("instruction_extras: clamp_library_limit defaults, clamps and rejects junk",
          "[instruction_extras][limit]") {
    CHECK(ex::clamp_library_limit("") == 100);
    CHECK(ex::clamp_library_limit("abc") == 100);
    CHECK(ex::clamp_library_limit("-5") == 100);
    CHECK(ex::clamp_library_limit("0") == 100);
    CHECK(ex::clamp_library_limit("12x") == 100);
    CHECK(ex::clamp_library_limit("25") == 25);
    CHECK(ex::clamp_library_limit("500") == 500);
    CHECK(ex::clamp_library_limit("501") == 500);
    CHECK(ex::clamp_library_limit("99999999999999999999") == 100); // overflow is junk, not max
}

TEST_CASE("instruction_extras: approval label is fail-closed for unknown modes",
          "[instruction_extras][label]") {
    CHECK(std::string(ex::approval_label("auto")) == "No");
    CHECK(std::string(ex::approval_label("always")) == "Yes");
    CHECK(std::string(ex::approval_label("role-gated")) == "Unless administrator");
    CHECK(std::string(ex::approval_label("")) == "Unknown");
    CHECK(std::string(ex::approval_label("whatever")) == "Unknown");
}

TEST_CASE("instruction_extras: truncation foot names the real limit and only shows when "
          "truncated",
          "[instruction_extras][foot]") {
    CHECK(ex::render_library_foot(100, false).empty());
    auto foot = ex::render_library_foot(250, true);
    CHECK(foot.find("Showing the first 250. Narrow the filter.") != std::string::npos);
    CHECK(foot.find("data-truncated=\"1\"") != std::string::npos);
}

TEST_CASE("instruction_extras: sets panel escapes every user string and shows counts",
          "[instruction_extras][sets]") {
    InstructionSet s;
    s.id = "abcdefgh<ij>";
    s.name = "<img src=x onerror=1>";
    s.description = "a & b";
    auto html = ex::render_instruction_sets_panel({{s, 3}}, false);
    CHECK(html.find("<img") == std::string::npos);
    CHECK(html.find("&lt;img") != std::string::npos);
    CHECK(html.find("a &amp; b") != std::string::npos);
    CHECK(html.find("<td>3</td>") != std::string::npos);
    CHECK(ex::render_instruction_sets_panel({{s, 3}}, true).find("<td>3+</td>") !=
          std::string::npos);
    CHECK(ex::render_instruction_sets_panel({}, false).find("No instruction sets yet.") !=
          std::string::npos);
}
