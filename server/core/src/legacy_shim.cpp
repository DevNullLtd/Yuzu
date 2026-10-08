#include "legacy_shim.hpp"

#include <nlohmann/json.hpp>
#include <spdlog/spdlog.h>

#include <format>
#include <string>
#include <vector>

namespace yuzu::server {

namespace {

// Build a minimal YAML source string that conforms to the
// apiVersion: yuzu.io/v1alpha1 InstructionDefinition format.
std::string build_yaml_source(const std::string& plugin_name, const std::string& action,
                              const std::string& def_id) {
    return std::format("apiVersion: yuzu.io/v1alpha1\n"
                       "kind: InstructionDefinition\n"
                       "metadata:\n"
                       "  name: \"{}:{}\"\n"
                       "  id: \"{}\"\n"
                       "spec:\n"
                       "  plugin: \"{}\"\n"
                       "  action: \"{}\"\n"
                       "  type: question\n"
                       "  version: \"1.0.0\"\n"
                       "  description: \"Auto-generated from {} plugin descriptor\"\n"
                       "  concurrency: per-device\n"
                       "  approval: auto\n"
                       "  parameters:\n"
                       "    type: object\n"
                       "    additionalProperties:\n"
                       "      type: string\n"
                       "  results:\n"
                       "    - name: output\n"
                       "      type: string\n",
                       plugin_name, action, def_id, plugin_name, action, plugin_name);
}

} // namespace

std::vector<InstructionDefinition>
generate_legacy_definitions(const std::vector<PluginCapability>& capabilities) {

    // The literal "{}" ("none stored") keeps these definitions accepting arbitrary string
    // params: the store refuses an `additionalProperties` schema at write time, and the
    // execute route does not validate a definition that stores none.
    constexpr const char* kNoStoredParameterSchema = "{}";

    const nlohmann::json result_schema =
        nlohmann::json::array({{{"name", "output"}, {"type", "string"}}});

    std::vector<InstructionDefinition> definitions;

    for (const auto& cap : capabilities) {
        for (const auto& action : cap.actions) {
            InstructionDefinition def;
            def.id = std::format("legacy.{}.{}", cap.plugin_name, action);
            def.name = std::format("{}:{}", cap.plugin_name, action);
            def.version = "1.0.0";
            def.type = "question";
            def.plugin = cap.plugin_name;
            def.action = action;
            def.description =
                std::format("Auto-generated from {} plugin descriptor", cap.plugin_name);
            def.parameter_schema = kNoStoredParameterSchema;
            def.result_schema = result_schema.dump();
            def.concurrency_mode = "per-device";
            def.approval_mode = "auto";
            def.enabled = true;
            def.yaml_source = build_yaml_source(cap.plugin_name, action, def.id);

            definitions.push_back(std::move(def));
        }
    }

    return definitions;
}

int sync_legacy_definitions(InstructionStore& store,
                            const std::vector<PluginCapability>& capabilities,
                            const std::string& created_by) {

    auto definitions = generate_legacy_definitions(capabilities);
    int created_count = 0;
    int skipped_count = 0;

    for (auto& def : definitions) {
        def.created_by = created_by;

        auto result = store.create_definition(def);
        if (result.has_value()) {
            ++created_count;
            spdlog::info("Legacy shim: created definition '{}'", def.id);
        } else {
            ++skipped_count;
            spdlog::debug("Legacy shim: skipped '{}' (already exists or error: {})", def.id,
                          result.error());
        }
    }

    spdlog::info("Legacy shim sync complete: {} created, {} skipped, {} total", created_count,
                 skipped_count, created_count + skipped_count);

    return created_count;
}

} // namespace yuzu::server
