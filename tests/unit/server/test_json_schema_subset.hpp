// A subset JSON-Schema checker for the MCP output-schema conformance tests (shared by the
// hardware and containment twin tests so a served body is validated against the schema
// tools/list publishes, not against a copy). Not a general validator.
#pragma once

#include <nlohmann/json.hpp>

#include <cstddef>
#include <string>
#include <vector>

namespace yuzu::test {

// A subset JSON-Schema check sufficient for the output schemas these tools publish: type
// (string or array of strings), properties (no extra keys), required, items, enum. Returns
// the first violation, or "" when `v` conforms.
inline std::string schema_violation(const nlohmann::json& schema, const nlohmann::json& v, const std::string& path = "") {
    if (schema.contains("type")) {
        std::vector<std::string> types;
        if (schema["type"].is_array())
            for (const auto& t : schema["type"])
                types.push_back(t.get<std::string>());
        else
            types.push_back(schema["type"].get<std::string>());
        bool ok = false;
        for (const auto& t : types) {
            if ((t == "object" && v.is_object()) || (t == "array" && v.is_array()) ||
                (t == "string" && v.is_string()) || (t == "integer" && v.is_number_integer()) ||
                (t == "number" && v.is_number()) || (t == "boolean" && v.is_boolean()) ||
                (t == "null" && v.is_null()))
                ok = true;
        }
        if (!ok)
            return path + ": type mismatch, value " + v.dump();
    }
    if (schema.contains("enum")) {
        bool ok = false;
        for (const auto& e : schema["enum"])
            ok = ok || e == v;
        if (!ok)
            return path + ": not in enum, value " + v.dump();
    }
    if (v.is_object() && schema.contains("properties")) {
        for (const auto& [k, sub] : v.items()) {
            if (!schema["properties"].contains(k))
                return path + "/" + k + ": key not declared in the schema";
            if (auto r = schema_violation(schema["properties"][k], sub, path + "/" + k); !r.empty())
                return r;
        }
        if (schema.contains("required"))
            for (const auto& req : schema["required"])
                if (!v.contains(req.get<std::string>()))
                    return path + ": required key " + req.get<std::string>() + " is missing";
    }
    if (v.is_array() && schema.contains("items"))
        for (std::size_t i = 0; i < v.size(); ++i)
            if (auto r = schema_violation(schema["items"], v[i], path + "/" + std::to_string(i));
                !r.empty())
                return r;
    return "";
}

} // namespace yuzu::test
