#pragma once

#include <string>
#include <utility>
#include <vector>

namespace yuzu::server::yaml_scan {

// Minimal YAML scanners for the subset of YAML structures used in Yuzu's DSL
// (PolicyFragment, Policy, and — via scope_yaml — the scope-walking `scope:`
// block). These avoid pulling a YAML library into the runtime: PyYAML is a
// build-time-only dependency, and the runtime treats `yaml_source` as the
// authoritative blob, only ever needing a handful of fields out of it.
//
// Supported patterns:
//   key: value                  (scalar)
//   key: "quoted value"         (quoted scalar)
//   key: >                      (folded block — first indented line only)
//   key:                        (start of mapping/sequence — returned empty)
//   - item                      (sequence items, via extract_yaml_list)
//   nested.key via extract_yaml_section
//
// NOT a general-purpose YAML parser. Sufficient for yuzu.io/v1alpha1 DSL.
//
// Line breaks (#2123): CRLF, a lone CR and LF are all line breaks (YAML 1.2
// §5.4), so a CRLF or lone-CR document reads exactly like its LF twin. Blank
// and comment-only lines never end a block. Every key lookup goes through one
// anchored helper: a key matches only as the first token on its line.
// extract_yaml_section returns its block joined with '\n' whatever the
// source used.
//
// SECURITY CONTRACT (#1215 review / #1221 MEDIUM-2): these scanners are now
// load-bearing for authorization decisions (scope_yaml lowers a `scope:` block
// that gates which devices a command targets). Every scanner takes the FIRST
// line in its input whose first token is `key:` (any depth), so the same key
// under a sibling section can be matched if you scan the WHOLE document. Any
// new security-relevant lookup
// MUST first isolate the owning block with `extract_yaml_section(<dotted.path>)`
// and scan within that, the way `scope_yaml::parse_scope_block` does. Raw
// whole-document `extract_yaml_value` is for non-authorization fields only.
//
// History: these four functions lived in policy_store.cpp's anonymous namespace
// until PR-E (scope-walking YAML DSL) needed them in a second translation unit.
// `yaml_has_key` is new; `extract_yaml_value` gained comment-awareness in the
// #1215 follow-up (it now skips keys inside `#` comments, matching yaml_has_key).
// #2123 put all five on one anchored lookup and one CRLF/CR/LF line walker;
// before that, extract_yaml_list and extract_yaml_mapping used a bare find().

/// Extract a scalar value for `key`. Returns empty when the key is absent or
/// opens a mapping/sequence (so callers can use emptiness to mean "not a
/// scalar" and fall back to section/list extraction).
std::string extract_yaml_value(const std::string& yaml, const std::string& key);

/// Extract a YAML list under `key` — either inline (`key: [a, b]`) or block
/// (`key:` followed by `- a` / `- b` lines). An inline list must close on the
/// key's own line; if it does not, the raw value (e.g. `[a,`) is returned as a
/// single item, never as an empty list, so a caller that validates items
/// rejects it rather than silently losing them. A block list ends at the first
/// line outside it (shallower than its items, or a sibling key), so an outer
/// list's items are never absorbed (#2123).
std::vector<std::string> extract_yaml_list(const std::string& yaml, const std::string& key);

/// Extract a YAML mapping under `key`: all `subkey: value` pairs in the block
/// indented under the key.
std::vector<std::pair<std::string, std::string>>
extract_yaml_mapping(const std::string& yaml, const std::string& key);

/// Find a nested YAML section and return its indented content block. The dotted
/// path is walked segment by segment, e.g. extract_yaml_section(yaml,
/// "spec.scope") returns the block under "scope:" within "spec:".
std::string extract_yaml_section(const std::string& yaml, const std::string& dotted_path);

/// True iff `key:` appears at the start of a line (ignoring leading whitespace)
/// within `block`. Unlike extract_yaml_value this answers presence even when
/// the key opens a mapping (where extract_yaml_value returns empty), and it is
/// anchored to line starts so a key appearing inside a quoted scalar or a `#`
/// comment does not register. Intended to be called on an already-isolated
/// block (e.g. the output of extract_yaml_section) so the scan stays local.
bool yaml_has_key(const std::string& block, const std::string& key);

} // namespace yuzu::server::yaml_scan
