/**
 * test_instruction_yaml.cpp — schema-aware InstructionDefinition YAML field
 * extraction (instruction_yaml.{hpp,cpp}), the shared contract behind
 * POST /api/instructions/yaml (Save) and POST /api/instructions/validate-yaml.
 *
 * Regression net for #1993: the Save path used raw whole-document substring
 * scanning against a flat schema (metadata.name / spec.plugin / spec.action),
 * so canonical nested YAML (metadata.id / spec.execution.plugin — the shape
 * used by the docs, validate-yaml, and every bundled definition) passed
 * validation but failed Save with "Missing required fields: name, plugin,
 * action". These cases pin both schemas plus the resolution/fallback order
 * mirrored from the build-time importer (embed_content.py::def_envelope).
 */

#include "instruction_yaml.hpp"
#include "reserved_definition_id.hpp"

#include <catch2/catch_test_macros.hpp>

#include <string>

using namespace yuzu::server::instruction_yaml;

namespace {

// The getting-started tutorial's first definition, verbatim (docs/
// getting-started.md "Define it in YAML") — the exact input #1993 reported
// as un-saveable.
const std::string kTutorialYaml = R"(apiVersion: yuzu.io/v1alpha1
kind: InstructionDefinition
metadata:
  id: hello.system.info
  displayName: Get System Info
  version: 1.0.0
  description: Returns basic OS information from all targeted endpoints.
spec:
  type: question
  platforms: [windows, linux, darwin]
  execution:
    plugin: os_info
    action: os_name
)";

// The flat schema the New Definition panel's structured form generates
// (instruction_ui.cpp formToYaml) — must keep working unchanged.
const std::string kFlatPanelYaml = R"(apiVersion: yuzu.io/v1alpha1
kind: InstructionDefinition
metadata:
  name: "tutorial.service.inspect"
  version: "1.0.0"
spec:
  plugin: "services"
  action: "list"
  type: question
  description: "Returns the current state of a named service."
  concurrency: unlimited
  approval: auto
  platforms: [windows, linux, darwin]
  parameters:
    type: object
    additionalProperties:
      type: string
  results:
    - name: output
      type: string
)";

// Shipped-definition shape: nested execution block with concurrency, an
// approval mapping, a parameters block whose `type: object` / properties'
// `name:`s must NOT shadow the definition's own type/name, and a folded
// description.
const std::string kShippedYaml = R"(apiVersion: yuzu.io/v1alpha1
kind: InstructionDefinition
metadata:
  id: device.agent_actions.set_log_level
  displayName: Set Agent Log Level
  version: 1.0.0
  description: >
    Changes the agent's spdlog log level at runtime.
  tags: [agent, logging, management]

spec:
  type: action
  platforms: [windows, linux, darwin]

  execution:
    plugin: agent_actions
    action: Set_Log_Level
    concurrency: per-device

  parameters:
    type: object
    required: [level]
    properties:
      level:
        type: string
        displayName: Log Level

  result:
    columns:
      - name: status
        type: string

  approval:
    mode: role-gated
)";

} // namespace

TEST_CASE("instruction_yaml: canonical nested schema (tutorial YAML) parses",
          "[instruction_yaml]") {
    auto f = parse_definition_yaml(kTutorialYaml);
    CHECK(f.id == "hello.system.info");
    CHECK(f.name == "Get System Info"); // displayName wins over id
    CHECK(f.version == "1.0.0");
    CHECK(f.type == "question");
    CHECK(f.plugin == "os_info");
    CHECK(f.action == "os_name");
    CHECK(f.description == "Returns basic OS information from all targeted endpoints.");
    CHECK(f.has_api_version);
    CHECK(f.has_kind);
}

TEST_CASE("instruction_yaml: flat panel schema keeps working", "[instruction_yaml]") {
    auto f = parse_definition_yaml(kFlatPanelYaml);
    CHECK(f.id.empty()); // flat form has no metadata.id — store generates one
    CHECK(f.name == "tutorial.service.inspect");
    CHECK(f.version == "1.0.0");
    CHECK(f.type == "question");
    CHECK(f.plugin == "services");
    CHECK(f.action == "list");
    CHECK(f.description == "Returns the current state of a named service.");
    CHECK(f.concurrency == "unlimited");
    CHECK(f.approval == "auto");
}

TEST_CASE("instruction_yaml: shipped-definition shape — nested keys don't shadow",
          "[instruction_yaml]") {
    auto f = parse_definition_yaml(kShippedYaml);
    CHECK(f.id == "device.agent_actions.set_log_level");
    CHECK(f.name == "Set Agent Log Level");
    // parameters.type: object / result columns' type: string must not leak
    // into the definition's own type.
    CHECK(f.type == "action");
    CHECK(f.plugin == "agent_actions");
    CHECK(f.action == "set_log_level"); // lowercased for case-sensitive plugin match
    CHECK(f.concurrency == "per-device");
    CHECK(f.approval == "role-gated"); // spec.approval.mode form
    // Folded description isn't a plain scalar — extraction yields empty; the
    // verbatim yaml_source remains the source of truth for it.
    CHECK(f.description.empty());
}

TEST_CASE("instruction_yaml: metadata.name fallback when no displayName/id", "[instruction_yaml]") {
    auto f = parse_definition_yaml("apiVersion: yuzu.io/v1alpha1\n"
                                   "kind: InstructionDefinition\n"
                                   "metadata:\n"
                                   "  name: bare.name\n"
                                   "spec:\n"
                                   "  plugin: p\n"
                                   "  action: a\n");
    CHECK(f.name == "bare.name");
    CHECK(f.id.empty());
}

TEST_CASE("instruction_yaml: quoted values and inline comments", "[instruction_yaml]") {
    auto f = parse_definition_yaml("apiVersion: yuzu.io/v1alpha1\n"
                                   "kind: InstructionDefinition\n"
                                   "metadata:\n"
                                   "  id: \"quoted.id\" # trailing comment\n"
                                   "  description: \"tracks issue #5\"\n"
                                   "spec:\n"
                                   "  execution:\n"
                                   "    plugin: os_info # inline comment\n"
                                   "    action: os_name\n");
    CHECK(f.id == "quoted.id");
    // '#' inside a quoted scalar is content, not a comment.
    CHECK(f.description == "tracks issue #5");
    CHECK(f.plugin == "os_info");
}

TEST_CASE("instruction_yaml: validate accepts what save needs — both schemas",
          "[instruction_yaml]") {
    CHECK(validate_definition_yaml(kTutorialYaml).empty());
    CHECK(validate_definition_yaml(kFlatPanelYaml).empty());
    CHECK(validate_definition_yaml(kShippedYaml).empty());
}

TEST_CASE("instruction_yaml: validate names the specific missing field", "[instruction_yaml]") {
    SECTION("empty source") {
        auto errors = validate_definition_yaml("");
        REQUIRE(errors.size() == 1);
        CHECK(errors[0] == "YAML source is empty");
    }
    SECTION("no identifier") {
        auto errors = validate_definition_yaml("apiVersion: yuzu.io/v1alpha1\n"
                                               "kind: InstructionDefinition\n"
                                               "spec:\n"
                                               "  plugin: p\n"
                                               "  action: a\n");
        REQUIRE(errors.size() == 1);
        CHECK(errors[0] == "Missing metadata.id (or metadata.name) field");
    }
    SECTION("no plugin/action") {
        auto errors = validate_definition_yaml("apiVersion: yuzu.io/v1alpha1\n"
                                               "kind: InstructionDefinition\n"
                                               "metadata:\n"
                                               "  id: x\n");
        REQUIRE(errors.size() == 2);
        CHECK(errors[0] == "Missing spec.execution.plugin (or spec.plugin) field");
        CHECK(errors[1] == "Missing spec.execution.action (or spec.action) field");
    }
    SECTION("missing apiVersion and kind") {
        auto errors = validate_definition_yaml("metadata:\n"
                                               "  id: x\n"
                                               "spec:\n"
                                               "  plugin: p\n"
                                               "  action: a\n");
        REQUIRE(errors.size() == 2);
        CHECK(errors[0] == "Missing apiVersion field");
        CHECK(errors[1] == "Missing kind field");
    }
    SECTION("invalid approval mode is caught at validate time") {
        auto errors = validate_definition_yaml("apiVersion: yuzu.io/v1alpha1\n"
                                               "kind: InstructionDefinition\n"
                                               "metadata:\n"
                                               "  id: x\n"
                                               "spec:\n"
                                               "  plugin: p\n"
                                               "  action: a\n"
                                               "  approval: sometimes\n");
        REQUIRE(errors.size() == 1);
        // Byte-identical to the JSON-create/PUT routes' denial — one denial,
        // one string shape everywhere (governance cons-S3).
        CHECK(errors[0] == "invalid approval_mode: sometimes (must be auto, role-gated, or "
                           "always)");
    }
    SECTION("invalid type enum is caught at validate time") {
        auto errors = validate_definition_yaml("apiVersion: yuzu.io/v1alpha1\n"
                                               "kind: InstructionDefinition\n"
                                               "metadata:\n"
                                               "  id: x\n"
                                               "spec:\n"
                                               "  type: gather\n"
                                               "  plugin: p\n"
                                               "  action: a\n");
        REQUIRE(errors.size() == 1);
        // Byte-identical to InstructionStore::create_definition_impl's
        // rejection so validate-pass always implies save-pass.
        CHECK(errors[0] == "type must be 'question' or 'action'");
    }
}

TEST_CASE("instruction_yaml: explicit metadata.id charset/length gate matches Save",
          "[instruction_yaml]") {
    // The store's create_definition_impl rejects an explicit id that is >128
    // bytes or contains anything outside [A-Za-z0-9._-]. validate-yaml must
    // reject the same ids byte-for-byte, or a document that validates green
    // 400s on Save (Doomgoose blocker on #2010 — the id gate re-broke #1993's
    // "YAML that validates always saves" contract).
    auto with_id = [](const std::string& id) {
        return "apiVersion: yuzu.io/v1alpha1\n"
               "kind: InstructionDefinition\n"
               "metadata:\n"
               "  id: " +
               id +
               "\n"
               "spec:\n"
               "  execution:\n"
               "    plugin: os_info\n"
               "    action: os_name\n";
    };
    SECTION("id with a space is rejected") {
        auto errors = validate_definition_yaml(with_id("hello system info"));
        REQUIRE(errors.size() == 1);
        CHECK(errors[0] == "definition id may only contain letters, digits, '.', '_', and '-'");
    }
    SECTION("id longer than 128 bytes is rejected") {
        auto errors = validate_definition_yaml(with_id(std::string(129, 'a')));
        REQUIRE(errors.size() == 1);
        CHECK(errors[0] == "definition id too long (max 128 characters)");
    }
    SECTION("a 128-byte id and canonical dotted ids validate") {
        CHECK(validate_definition_yaml(with_id(std::string(128, 'a'))).empty());
        CHECK(validate_definition_yaml(with_id("system.os.info-1_beta")).empty());
    }
    SECTION("the reserved mcp. namespace is rejected here too") {
        // #2442 added a THIRD rule the store applies to an explicit id. The
        // first cut of it landed only in the store, which broke the same
        // validate-implies-save contract for the third time (#1993, #2010,
        // then this) — hence the shared predicate both sides now call.
        auto errors = validate_definition_yaml(with_id("mcp.quarantine_device"));
        REQUIRE(errors.size() == 1);
        CHECK(errors[0] == std::string(yuzu::server::kReservedDefinitionIdError));
    }
    SECTION("only the exact prefix is reserved") {
        CHECK(validate_definition_yaml(with_id("mcpx.thing")).empty());
        CHECK(validate_definition_yaml(with_id("a.mcp.thing")).empty());
    }
}

TEST_CASE("instruction_yaml: byte-level malformations are rejected outright",
          "[instruction_yaml]") {
    SECTION("NUL byte") {
        std::string doc = "apiVersion: yuzu.io/v1alpha1\n"
                          "kind: InstructionDefinition\n";
        doc.push_back('\0');
        doc += "metadata:\n  id: x\nspec:\n  plugin: p\n  action: a\n";
        auto errors = validate_definition_yaml(doc);
        REQUIRE(errors.size() == 1);
        CHECK(errors[0] == "YAML source contains a NUL byte");
    }
    SECTION("oversize source mirrors the store cap") {
        std::string doc = "apiVersion: yuzu.io/v1alpha1\nkind: InstructionDefinition\n";
        doc.append(1048577, '#');
        auto errors = validate_definition_yaml(doc);
        REQUIRE(errors.size() == 1);
        CHECK(errors[0] == "yaml_source too large (max 1MB)");
    }
}

TEST_CASE("instruction_yaml: multi-document paste is rejected, lead-ins are not",
          "[instruction_yaml]") {
    const std::string doc_body = "apiVersion: yuzu.io/v1alpha1\n"
                                 "kind: InstructionDefinition\n"
                                 "metadata:\n"
                                 "  id: solo.def\n"
                                 "spec:\n"
                                 "  plugin: p\n"
                                 "  action: a\n";
    SECTION("comment header + leading separator is a single document") {
        CHECK(validate_definition_yaml("## Shipped definition header\n---\n" + doc_body).empty());
    }
    SECTION("a second document separator is rejected") {
        auto errors = validate_definition_yaml(doc_body + "---\n" + doc_body);
        REQUIRE(errors.size() == 1);
        CHECK(errors[0] == "YAML source contains multiple documents (--- separator) — save one "
                           "definition at a time");
    }
}

TEST_CASE("instruction_yaml: duplicate sibling keys — first one wins", "[instruction_yaml]") {
    auto f = parse_definition_yaml("apiVersion: yuzu.io/v1alpha1\n"
                                   "kind: InstructionDefinition\n"
                                   "metadata:\n"
                                   "  id: first.id\n"
                                   "  id: second.id\n"
                                   "spec:\n"
                                   "  plugin: p\n"
                                   "  action: a\n");
    // Top-down first-match, consistent with how an operator reads yaml_source.
    CHECK(f.id == "first.id");
}

TEST_CASE("instruction_yaml: mixed tab/space sibling indentation drops the off-level key",
          "[instruction_yaml]") {
    // A tab counts as ONE column, so a tab-indented line sits at a different
    // indent level than its 2-space siblings; only minimum-indent keys are
    // consulted. The dropped key must degrade to a fallback or a validation
    // error — never to an invented value (governance qe-S2). Here the tab
    // line (indent 1) is the child level: id resolves, the 2-space
    // displayName is out of scope, and name falls back to the id.
    auto f = parse_definition_yaml("apiVersion: yuzu.io/v1alpha1\n"
                                   "kind: InstructionDefinition\n"
                                   "metadata:\n"
                                   "\tid: tab.id\n"
                                   "  displayName: Two Space Name\n"
                                   "spec:\n"
                                   "  plugin: p\n"
                                   "  action: a\n");
    CHECK(f.id == "tab.id");
    CHECK(f.name == "tab.id");
}

TEST_CASE("instruction_yaml: sibling key-prefix does not shadow", "[instruction_yaml]") {
    // The `line[key.size()] == ':'` guard is the PR's namesake anti-shadowing
    // mechanism — pin it directly (governance qe-S3).
    auto f = parse_definition_yaml("apiVersion: yuzu.io/v1alpha1\n"
                                   "kind: InstructionDefinition\n"
                                   "metadata:\n"
                                   "  id: x\n"
                                   "spec:\n"
                                   "  action_type: custom\n"
                                   "  action: real_action\n"
                                   "  plugin_home: /opt\n"
                                   "  plugin: real_plugin\n");
    CHECK(f.action == "real_action");
    CHECK(f.plugin == "real_plugin");
}

TEST_CASE("instruction_yaml: line-ending and EOF edges", "[instruction_yaml]") {
    SECTION("no trailing newline — key on the final line") {
        auto f = parse_definition_yaml("metadata:\n  id: eof.id\nspec:\n  execution:\n"
                                       "    plugin: p\n    action: a"); // no trailing \n
        CHECK(f.id == "eof.id");
        CHECK(f.action == "a");
    }
    SECTION("CRLF line endings") {
        auto f = parse_definition_yaml("apiVersion: yuzu.io/v1alpha1\r\n"
                                       "kind: InstructionDefinition\r\n"
                                       "metadata:\r\n"
                                       "  id: crlf.id\r\n"
                                       "spec:\r\n"
                                       "  plugin: p\r\n"
                                       "  action: a\r\n");
        CHECK(f.id == "crlf.id");
        CHECK(f.plugin == "p");
    }
}

TEST_CASE("instruction_yaml: block-scalar indicators and comment-only openers are absent",
          "[instruction_yaml]") {
    // `>-` / `|+` / `|2` are block-scalar indicators, not values; a
    // comment-only value is a mapping opener with an annotation. Both must
    // extract as absent, never as literal text (governance dsl-S3).
    auto f = parse_definition_yaml("metadata:\n"
                                   "  id: blocks.id\n"
                                   "  description: >-\n"
                                   "    folded and chomped text\n"
                                   "spec:\n"
                                   "  approval:  # role gate configured below\n"
                                   "    mode: role-gated\n"
                                   "  execution:\n"
                                   "    plugin: p\n"
                                   "    action: a\n"
                                   "  notes: |+\n"
                                   "    keep\n");
    CHECK(f.description.empty());
    CHECK(f.approval == "role-gated"); // comment-only opener fell through to mode
    CHECK(f.plugin == "p");
}
