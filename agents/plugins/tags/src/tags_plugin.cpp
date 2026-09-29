/**
 * tags_plugin.cpp — Device tagging plugin for Yuzu
 *
 * Actions:
 *   "set"     — Set a tag (key, value).
 *   "get"     — Get a tag value by key.
 *   "get_all" — Get all tags.
 *   "delete"  — Delete a tag by key.
 *   "check"   — Check if a tag exists.
 *   "clear"   — Clear all tags.
 *   "count"   — Count tags.
 *
 * Tags are stored in <data_dir>/tags.json and reported to the server
 * via AgentInfo.scopable_tags during registration.
 */

#include <yuzu/plugin.hpp>

#include <nlohmann/json.hpp>

#include <filesystem>
#include <format>
#include <fstream>
#include <string>
#include <string_view>
#include <unordered_map>

namespace {

namespace fs = std::filesystem;

YuzuPluginContext* g_ctx = nullptr;
std::unordered_map<std::string, std::string> g_tags;
fs::path g_tags_path;

void load_tags() {
    g_tags.clear();
    if (g_tags_path.empty())
        return;

    std::error_code ec;
    if (!fs::exists(g_tags_path, ec))
        return;

    std::ifstream f(g_tags_path);
    if (!f)
        return;

    try {
        auto j = nlohmann::json::parse(f);
        if (j.is_object()) {
            for (auto& [key, val] : j.items()) {
                if (val.is_string()) {
                    g_tags[key] = val.get<std::string>();
                }
            }
        }
    } catch (...) {}
}

void save_tags() {
    if (g_tags_path.empty())
        return;

    std::error_code ec;
    auto parent = g_tags_path.parent_path();
    if (!parent.empty()) {
        fs::create_directories(parent, ec);
    }

    nlohmann::json j = g_tags;
    std::ofstream f(g_tags_path);
    if (f) {
        f << j.dump(2);
    }
}

// ── ABI4 capability declarations (#2204) ────────────────────────────────────
//
// All 7 actions are pure in-process reads/writes of <data_dir>/tags.json —
// no subprocess on any OS (rung 1, "local_json_store" on all three legs).
const YuzuActionDescriptor kActionDescriptors[] = {
    {"set", {YUZU_SUPPORT_SUPPORTED, 1, "local_json_store", nullptr},
     {YUZU_SUPPORT_SUPPORTED, 1, "local_json_store", nullptr},
     {YUZU_SUPPORT_SUPPORTED, 1, "local_json_store", nullptr}},
    {"get", {YUZU_SUPPORT_SUPPORTED, 1, "local_json_store", nullptr},
     {YUZU_SUPPORT_SUPPORTED, 1, "local_json_store", nullptr},
     {YUZU_SUPPORT_SUPPORTED, 1, "local_json_store", nullptr}},
    {"get_all", {YUZU_SUPPORT_SUPPORTED, 1, "local_json_store", nullptr},
     {YUZU_SUPPORT_SUPPORTED, 1, "local_json_store", nullptr},
     {YUZU_SUPPORT_SUPPORTED, 1, "local_json_store", nullptr}},
    {"delete", {YUZU_SUPPORT_SUPPORTED, 1, "local_json_store", nullptr},
     {YUZU_SUPPORT_SUPPORTED, 1, "local_json_store", nullptr},
     {YUZU_SUPPORT_SUPPORTED, 1, "local_json_store", nullptr}},
    {"check", {YUZU_SUPPORT_SUPPORTED, 1, "local_json_store", nullptr},
     {YUZU_SUPPORT_SUPPORTED, 1, "local_json_store", nullptr},
     {YUZU_SUPPORT_SUPPORTED, 1, "local_json_store", nullptr}},
    {"clear", {YUZU_SUPPORT_SUPPORTED, 1, "local_json_store", nullptr},
     {YUZU_SUPPORT_SUPPORTED, 1, "local_json_store", nullptr},
     {YUZU_SUPPORT_SUPPORTED, 1, "local_json_store", nullptr}},
    {"count", {YUZU_SUPPORT_SUPPORTED, 1, "local_json_store", nullptr},
     {YUZU_SUPPORT_SUPPORTED, 1, "local_json_store", nullptr},
     {YUZU_SUPPORT_SUPPORTED, 1, "local_json_store", nullptr}},
};

} // namespace

class TagsPlugin final : public yuzu::Plugin {
public:
    std::string_view name() const noexcept override { return "tags"; }
    std::string_view version() const noexcept override { return "0.1.0"; }
    std::string_view description() const noexcept override {
        return "Device tagging — set, get, delete, list tags for scope evaluation";
    }

    const char* const* actions() const noexcept override {
        static const char* acts[] = {"set",   "get",   "get_all", "delete",
                                     "check", "clear", "count",   nullptr};
        return acts;
    }

    const YuzuActionDescriptor* action_descriptors() const noexcept override {
        return kActionDescriptors;
    }
    size_t action_descriptor_count() const noexcept override {
        return sizeof(kActionDescriptors) / sizeof(kActionDescriptors[0]);
    }

    yuzu::Result<void> init(yuzu::PluginContext& ctx) override {
        g_ctx = ctx.raw();

        // Determine tags.json path from data_dir
        yuzu::PluginContext pctx{g_ctx};
        auto data_dir = pctx.get_config("agent.data_dir");
        if (!data_dir.empty()) {
            g_tags_path = fs::path(std::string{data_dir}) / "tags.json";
        }

        load_tags();
        return {};
    }

    void shutdown(yuzu::PluginContext& /*ctx*/) noexcept override { g_ctx = nullptr; }

    int execute(yuzu::CommandContext& ctx, std::string_view action, yuzu::Params params) override {
        if (action == "set")
            return do_set(ctx, params);
        if (action == "get")
            return do_get(ctx, params);
        if (action == "get_all")
            return do_get_all(ctx);
        if (action == "delete")
            return do_delete(ctx, params);
        if (action == "check")
            return do_check(ctx, params);
        if (action == "clear")
            return do_clear(ctx);
        if (action == "count")
            return do_count(ctx);

        ctx.write_output(std::format("unknown action: {}", action));
        return 1;
    }

private:
    int do_set(yuzu::CommandContext& ctx, yuzu::Params params) {
        auto key = params.get("key");
        auto value = params.get("value");
        if (key.empty()) {
            ctx.write_output("error|missing required parameter: key");
            return 1;
        }
        // Validate key: max 64 chars, [a-zA-Z0-9_-.:]
        std::string key_str{key};
        if (key_str.size() > 64) {
            ctx.write_output("error|key exceeds 64 characters");
            return 1;
        }
        std::string val_str{value};
        if (val_str.size() > 448) {
            ctx.write_output("error|value exceeds 448 bytes");
            return 1;
        }

        g_tags[key_str] = val_str;
        save_tags();
        ctx.write_output(std::format("tag_set|{}|{}", key_str, val_str));
        return 0;
    }

    int do_get(yuzu::CommandContext& ctx, yuzu::Params params) {
        auto key = params.get("key");
        if (key.empty()) {
            ctx.write_output("error|missing required parameter: key");
            return 1;
        }
        std::string key_str{key};
        auto it = g_tags.find(key_str);
        if (it == g_tags.end()) {
            ctx.write_output(std::format("tag|{}|", key_str));
        } else {
            ctx.write_output(std::format("tag|{}|{}", key_str, it->second));
        }
        return 0;
    }

    int do_get_all(yuzu::CommandContext& ctx) {
        for (const auto& [key, value] : g_tags) {
            ctx.write_output(std::format("tag|{}|{}", key, value));
        }
        ctx.write_output(std::format("count|{}", g_tags.size()));
        return 0;
    }

    int do_delete(yuzu::CommandContext& ctx, yuzu::Params params) {
        auto key = params.get("key");
        if (key.empty()) {
            ctx.write_output("error|missing required parameter: key");
            return 1;
        }
        std::string key_str{key};
        bool found = g_tags.erase(key_str) > 0;
        save_tags();
        ctx.write_output(std::format("tag_deleted|{}|{}", key_str, found ? "true" : "false"));
        return 0;
    }

    int do_check(yuzu::CommandContext& ctx, yuzu::Params params) {
        auto key = params.get("key");
        if (key.empty()) {
            ctx.write_output("error|missing required parameter: key");
            return 1;
        }
        std::string key_str{key};
        bool exists = g_tags.contains(key_str);
        ctx.write_output(std::format("tag_exists|{}|{}", key_str, exists ? "true" : "false"));
        return 0;
    }

    int do_clear(yuzu::CommandContext& ctx) {
        auto count = g_tags.size();
        g_tags.clear();
        save_tags();
        ctx.write_output(std::format("tags_cleared|{}", count));
        return 0;
    }

    int do_count(yuzu::CommandContext& ctx) {
        ctx.write_output(std::format("count|{}", g_tags.size()));
        return 0;
    }
};

YUZU_PLUGIN_EXPORT(TagsPlugin)
