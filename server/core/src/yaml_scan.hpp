#pragma once

#include <string>
#include <string_view>
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
//   key: > / key: |             (block scalar — returned empty, not read)
//   key:                        (start of mapping/sequence — returned empty)
//   - item                      (sequence items, via extract_yaml_list)
//   nested.key via extract_yaml_section
//
// NOT a general-purpose YAML parser. Sufficient for yuzu.io/v1alpha1 DSL.
//
// Line breaks (#2123): CRLF, a lone CR and LF are all line breaks (YAML 1.2
// §5.4), so a CRLF or lone-CR document reads exactly like its LF twin. Blank
// and comment-only lines never end a block. Every key lookup goes through one
// anchored helper: a key matches only as the first token on its line
// (extract_yaml_value alone also accepts it after `- ` sequence indicators, so
// list items like `- type: interval` are read). extract_yaml_section returns its
// block joined with '\n' whatever the source used. A list line extract_yaml_list
// cannot place is returned as a raw item, never dropped (see its doc comment).
//
// SECURITY CONTRACT (#1215 review / #1221 MEDIUM-2): these scanners are now
// load-bearing for authorization decisions (scope_yaml lowers a `scope:` block
// that gates which devices a command targets). Every scanner takes the FIRST
// line in its input whose first token is `key:` at any depth (extract_yaml_value:
// or after `- `), so the same key under a sibling section can be matched if you
// scan the WHOLE document. Any new security-relevant lookup MUST first isolate
// the owning block with `extract_yaml_section(<dotted.path>)` and scan within
// that, the way `scope_yaml::parse_scope_block` does. Raw whole-document
// `extract_yaml_value` is for non-authorization fields only.
//
// History: these four functions lived in policy_store.cpp's anonymous namespace
// until PR-E (scope-walking YAML DSL) needed them in a second translation unit.
// `yaml_has_key` is new; `extract_yaml_value` gained comment-awareness in the
// #1215 follow-up (it now skips keys inside `#` comments, matching yaml_has_key).
// #2123 put all five on one anchored lookup and one CRLF/CR/LF line walker;
// before that, extract_yaml_list and extract_yaml_mapping used a bare find().

/// Split `text` into lines exactly as every scanner here does: CRLF, a lone CR
/// and LF are all line breaks, and the break is not part of the line. Any other
/// code that walks a `yaml_source` line by line (e.g. instruction_yaml's
/// multi-document guard) must use this, or it disagrees with the scanners on
/// where lines start (#2123 governance G2-SEC-F2). The views borrow `text`.
std::vector<std::string_view> split_lines(std::string_view text);

/// Extract a scalar value for `key`. Returns empty when the key is absent or
/// opens a mapping/sequence (so callers can use emptiness to mean "not a
/// scalar" and fall back to section/list extraction).
std::string extract_yaml_value(const std::string& yaml, const std::string& key);

/// Extract a YAML list under `key`: inline (`key: [a, b]`) or block (`key:`
/// followed by `- a` / `- b` lines). Within the lines it scans — from the key to
/// the next key at or shallower than it — no line that belongs to the list is
/// dropped, and no line from outside it is returned as a plain item (#2123). A
/// line that already sits outside `yaml` (because the caller isolated a section
/// that ended before it) is not seen at all:
///   - a scalar where a list is expected (`key: a`) is ONE raw item (` a`); a
///     YAML null (`null`, `~`) is an empty list; a quoted empty string is kept;
///   - an inline list must close on the key's own line; otherwise the raw value
///     (e.g. `[a,`) comes back as one item;
///   - a block list ends at a `key:` line at or shallower than `key`, or at a
///     `---`/`...` marker (a first non-dash line at or shallower than `key`
///     belongs to the parent and ends an empty list); a deeper non-`-` line is
///     folded into the current item with a space (after an empty `- ` it IS the
///     item);
///   - any other line it cannot place (a `-` line off the item column, a line
///     with no dash, a `key:` line deeper than `key`) comes back as ONE raw item
///     that always contains a space (`- prod`, ` pci`).
/// CALLER OBLIGATION: every consumer MUST either validate each item against the
/// scope-token charset — non-empty, letters, digits and `_ . : * -` only, so no
/// space, `[`, `,`, quote or `#` (validate_scope_block and
/// validate_management_group_ids do) — or use the list only for emptiness. A
/// consumer that trusts the items as-is would act on a raw item (` a`, `[a,`,
/// `- b`) or an empty string.
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
