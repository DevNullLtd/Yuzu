#include "instruction_yaml.hpp"

#include "reserved_definition_id.hpp" // the ONE reserved-namespace rule (#2442)
#include "yaml_scan.hpp"

#include <cctype>
#include <cstddef>
#include <string>
#include <string_view>

namespace yuzu::server::instruction_yaml {

namespace {

// Extract `key: value` only when `key` is an immediate child of `block`
// (a section body as returned by yaml_scan::extract_yaml_section, or the
// whole document for top-level keys). yaml_scan::extract_yaml_value matches
// the key at ANY depth inside the block, which is exactly the substring
// laxness #1993 grew out of — a shipped definition declares
// `spec.parameters.type: object` before `spec.type` reaches the scanner, and
// whichever the find() hits first wins. Here the child level is the minimum
// indentation across the block's lines, and only keys at that level match.
std::string child_value(const std::string& block, std::string_view key) {
    // Pass 1: find the block's own (minimum) indentation.
    std::size_t child_indent = std::string::npos;
    for (std::size_t line_start = 0; line_start < block.size();) {
        auto eol = block.find('\n', line_start);
        if (eol == std::string::npos)
            eol = block.size();
        auto first = block.find_first_not_of(" \t", line_start);
        if (first != std::string::npos && first < eol && block[first] != '#' &&
            block[first] != '-') {
            auto indent = first - line_start;
            if (indent < child_indent)
                child_indent = indent;
        }
        line_start = eol + 1;
    }
    if (child_indent == std::string::npos)
        return {};

    // Pass 2: scan only lines at that indentation for `key:`.
    for (std::size_t line_start = 0; line_start < block.size();) {
        auto eol = block.find('\n', line_start);
        if (eol == std::string::npos)
            eol = block.size();
        auto first = block.find_first_not_of(" \t", line_start);
        if (first != std::string::npos && first < eol && first - line_start == child_indent) {
            std::string_view line{block.data() + first, eol - first};
            if (line.size() > key.size() + 1 && line.substr(0, key.size()) == key &&
                line[key.size()] == ':') {
                auto val = line.substr(key.size() + 1);
                // Trim surrounding whitespace (incl. CR) and matching quotes.
                while (!val.empty() && (val.front() == ' ' || val.front() == '\t'))
                    val.remove_prefix(1);
                while (!val.empty() &&
                       (val.back() == ' ' || val.back() == '\t' || val.back() == '\r'))
                    val.remove_suffix(1);
                if (!val.empty() && (val.front() == '"' || val.front() == '\'')) {
                    // Quoted scalar: take the quoted span verbatim (a '#'
                    // inside the quotes is content, not a comment).
                    auto close = val.find(val.front(), 1);
                    if (close != std::string_view::npos)
                        val = val.substr(1, close - 1);
                } else {
                    // A comment-only value (`key:  # note`) is a mapping
                    // opener with an annotation, not a scalar — treat as
                    // absent so callers fall through to the nested form.
                    if (!val.empty() && val.front() == '#')
                        return {};
                    // Strip an inline comment (YAML requires whitespace
                    // before '#').
                    for (std::size_t i = 0; i < val.size(); ++i) {
                        if (val[i] == '#' && i > 0 && (val[i - 1] == ' ' || val[i - 1] == '\t')) {
                            val = val.substr(0, i);
                            while (!val.empty() && (val.back() == ' ' || val.back() == '\t'))
                                val.remove_suffix(1);
                            break;
                        }
                    }
                    // A block-scalar indicator — bare `>`/`|` or with
                    // chomping/indent modifiers (`>-`, `|+`, `|2-`) — means
                    // "not a plain scalar"; treat as absent rather than
                    // storing the indicator text as the value.
                    if (!val.empty() && (val.front() == '>' || val.front() == '|')) {
                        bool indicator = true;
                        for (std::size_t i = 1; i < val.size(); ++i) {
                            if (val[i] != '+' && val[i] != '-' &&
                                !std::isdigit(static_cast<unsigned char>(val[i]))) {
                                indicator = false;
                                break;
                            }
                        }
                        if (indicator)
                            return {};
                    }
                }
                return std::string{val};
            }
        }
        line_start = eol + 1;
    }
    return {};
}

std::string first_non_empty(const std::string& a, const std::string& b) {
    return a.empty() ? b : a;
}

} // namespace

DefinitionFields parse_definition_yaml(const std::string& yaml_source) {
    using yaml_scan::extract_yaml_section;
    using yaml_scan::yaml_has_key;

    DefinitionFields f;
    if (yaml_source.empty())
        return f;

    f.has_api_version = yaml_has_key(yaml_source, "apiVersion");
    f.has_kind = yaml_has_key(yaml_source, "kind");

    const auto metadata = extract_yaml_section(yaml_source, "metadata");
    const auto spec = extract_yaml_section(yaml_source, "spec");
    const auto execution = extract_yaml_section(yaml_source, "spec.execution");

    f.id = child_value(metadata, "id");
    f.name = first_non_empty(child_value(metadata, "displayName"),
                             first_non_empty(child_value(metadata, "name"), f.id));
    f.version = first_non_empty(child_value(metadata, "version"), child_value(spec, "version"));
    f.type = child_value(spec, "type");
    f.plugin = first_non_empty(child_value(execution, "plugin"), child_value(spec, "plugin"));
    f.action = first_non_empty(child_value(execution, "action"), child_value(spec, "action"));
    for (auto& c : f.action)
        c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
    f.description =
        first_non_empty(child_value(metadata, "description"), child_value(spec, "description"));
    f.concurrency =
        first_non_empty(child_value(execution, "concurrency"), child_value(spec, "concurrency"));
    // Flat form: `approval: auto` scalar. Canonical form: an `approval:`
    // mapping whose `mode:` child carries the value.
    f.approval = child_value(spec, "approval");
    if (f.approval.empty())
        f.approval = child_value(extract_yaml_section(yaml_source, "spec.approval"), "mode");

    return f;
}

std::vector<std::string> validate_definition_yaml(const std::string& yaml_source) {
    std::vector<std::string> errors;
    if (yaml_source.empty()) {
        errors.push_back("YAML source is empty");
        return errors;
    }
    // Byte-level malformations first — these make text extraction and the
    // stored blob diverge, so nothing else is worth reporting alongside them.
    // NUL: sqlite3_bind_text(-1) would truncate the stored yaml_source at the
    // first NUL while the scanner reads past it (governance UP-2).
    if (yaml_source.find('\0') != std::string::npos) {
        errors.push_back("YAML source contains a NUL byte");
        return errors;
    }
    // Size: mirror the store's create/update cap so validate can never pass
    // a document Save then rejects (governance UP-3).
    if (yaml_source.size() > 1048576) {
        errors.push_back("yaml_source too large (max 1MB)");
        return errors;
    }
    // Multiple documents: the Save path persists ONE definition; a pasted
    // multi-doc file (every shipped content/definitions/*.yaml) would save
    // doc 1 and silently drop the rest (governance dsl-S2). A separator on
    // the first content line is a lead-in, not a second document.
    {
        bool seen_content = false;
        for (std::size_t pos = 0; pos < yaml_source.size();) {
            auto eol = yaml_source.find('\n', pos);
            if (eol == std::string::npos)
                eol = yaml_source.size();
            std::string_view line{yaml_source.data() + pos, eol - pos};
            while (!line.empty() &&
                   (line.back() == ' ' || line.back() == '\t' || line.back() == '\r'))
                line.remove_suffix(1);
            if (line == "---") {
                if (seen_content) {
                    errors.push_back("YAML source contains multiple documents (--- separator) "
                                     "— save one definition at a time");
                    return errors;
                }
            } else if (!line.empty()) {
                // Comment-only lines don't count: a comment header followed
                // by a `---` lead-in is still a single document.
                auto first = line.find_first_not_of(" \t");
                if (first != std::string_view::npos && line[first] != '#')
                    seen_content = true;
            }
            pos = eol + 1;
        }
    }
    const auto f = parse_definition_yaml(yaml_source);
    if (!f.has_api_version)
        errors.push_back("Missing apiVersion field");
    if (!f.has_kind)
        errors.push_back("Missing kind field");
    if (f.name.empty())
        errors.push_back("Missing metadata.id (or metadata.name) field");
    if (f.plugin.empty())
        errors.push_back("Missing spec.execution.plugin (or spec.plugin) field");
    if (f.action.empty())
        errors.push_back("Missing spec.execution.action (or spec.action) field");
    // Explicit-id charset/length gate, byte-identical to the store's
    // create_definition_impl (instruction_store.cpp) so validate-pass ⇒
    // save-pass holds for the id too: an operator-supplied metadata.id with a
    // space or >128 bytes is rejected on Save, so validate must reject it
    // here (Doomgoose blocker on #2010 — the id gate re-broke the #1993
    // "YAML that validates always saves" contract). Store-generated ids are
    // hex and never reach this path.
    if (!f.id.empty()) {
        if (f.id.size() > 128) {
            errors.push_back("definition id too long (max 128 characters)");
        } else {
            for (char c : f.id) {
                const bool ok = (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') ||
                                (c >= '0' && c <= '9') || c == '.' || c == '_' || c == '-';
                if (!ok) {
                    errors.push_back(
                        "definition id may only contain letters, digits, '.', '_', and '-'");
                    break;
                }
            }
        }
        // Same contract, second rule on the id (#2442): the store refuses the
        // reserved MCP namespace on Save, so validate must refuse it here.
        // Both sides call the ONE predicate rather than copying it — the
        // charset gate above was copied, and copying is how this contract broke
        // on #2010 and again when the reservation first landed.
        if (is_reserved_definition_id(f.id))
            errors.push_back(std::string(kReservedDefinitionIdError));
    }
    // Enum checks match the store/JSON-route error strings byte-for-byte so
    // one denial has one shape everywhere (governance cons-S3).
    if (!f.type.empty() && f.type != "question" && f.type != "action")
        errors.push_back("type must be 'question' or 'action'");
    if (!f.approval.empty() && f.approval != "auto" && f.approval != "role-gated" &&
        f.approval != "always") {
        errors.push_back("invalid approval_mode: " + f.approval +
                         " (must be auto, role-gated, or always)");
    }
    return errors;
}

} // namespace yuzu::server::instruction_yaml
