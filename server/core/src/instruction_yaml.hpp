#pragma once

#include <string>
#include <vector>

namespace yuzu::server::instruction_yaml {

// Denormalized scalar fields extracted from an InstructionDefinition YAML
// document. `yaml_source` stays the authoritative blob (stored verbatim);
// these are only the queryable columns the store needs — the same contract
// the build-time bundled importer (embed_content.py::def_envelope) uses.
//
// Field resolution mirrors def_envelope so the authoring surfaces
// (POST /api/instructions/yaml, validate-yaml) accept the canonical nested
// schema every shipped definition and the docs use, while still accepting
// the flat spec.plugin/spec.action shape the New Definition panel's
// structured form generates (#1993):
//
//   id          metadata.id
//   name        metadata.displayName || metadata.name || metadata.id
//   version     metadata.version     || spec.version
//   type        spec.type
//   plugin      spec.execution.plugin || spec.plugin
//   action      spec.execution.action || spec.action   (lowercased)
//   description metadata.description || spec.description
//   concurrency spec.execution.concurrency || spec.concurrency
//   approval    spec.approval (scalar) || spec.approval.mode
struct DefinitionFields {
    std::string id;
    std::string name;
    std::string version;
    std::string type;
    std::string plugin;
    std::string action;
    std::string description;
    std::string concurrency;
    std::string approval;
    bool has_api_version{false};
    bool has_kind{false};
};

/// Parse the denormalized fields out of an InstructionDefinition YAML doc.
/// Pure text extraction via yaml_scan (no YAML library at runtime); only
/// immediate children of the metadata/spec/spec.execution/spec.approval
/// blocks are consulted, so nested schema keys (e.g. parameters.type,
/// result.columns[].name) can never shadow the definition's own fields.
DefinitionFields parse_definition_yaml(const std::string& yaml_source);

/// Validation shared by POST /api/instructions/validate-yaml and the
/// POST /api/instructions/yaml save path — one contract, so YAML that
/// passes validation can always be saved (#1993). Returns human-readable
/// errors; empty means valid.
std::vector<std::string> validate_definition_yaml(const std::string& yaml_source);

} // namespace yuzu::server::instruction_yaml
