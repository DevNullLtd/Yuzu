#include "yaml_scan.hpp"

#include <cstddef>
#include <optional>
#include <string_view>

namespace yuzu::server::yaml_scan {

namespace {

constexpr auto kNpos = std::string::npos;

// One physical line of a document. YAML 1.2 §5.4: a line break is CRLF, a
// lone CR, or LF, and the break is not part of the line's content. Every
// scanner walks lines through line_at() so a CRLF or lone-CR document is
// read exactly like its LF twin (#2123: splitting on '\n' alone left a "\r"
// on each line, so a CRLF blank line read as a non-blank line at column 0
// and ended the enclosing block early, dropping later scope predicates).
struct Line {
    std::size_t begin; // first content byte
    std::size_t end;   // one past the last content byte (break excluded)
    std::size_t next;  // first byte of the following line; == size() at EOF
};

Line line_at(std::string_view s, std::size_t begin) {
    const auto brk = s.find_first_of("\r\n", begin);
    if (brk == kNpos)
        return {begin, s.size(), s.size()};
    auto next = brk + 1;
    if (s[brk] == '\r' && next < s.size() && s[next] == '\n')
        ++next;
    return {begin, brk, next};
}

bool is_ws(char c) {
    return c == ' ' || c == '\t';
}

std::size_t first_non_ws(const std::string& s, const Line& l) {
    for (auto i = l.begin; i < l.end; ++i)
        if (!is_ws(s[i]))
            return i;
    return kNpos;
}

// A line with no content, or whose first token is '#'. YAML comment lines
// take no part in indentation, so neither kind can end a block (#2123).
bool is_blank_or_comment(const std::string& s, const Line& l) {
    const auto fc = first_non_ws(s, l);
    return fc == kNpos || s[fc] == '#';
}

struct KeyLine {
    Line line;
    std::size_t key_pos;   // offset of the key's first byte
    std::size_t value_pos; // offset just past "key:"
};

// The first line whose first token is `key:` — the single key lookup every
// scanner uses (yaml_scan.hpp SECURITY CONTRACT). A key inside a value, after
// an inline '#', on a comment line, or as the tail of a longer key
// (`extratags:` for `tags`) never matches. `allow_seq_entry` also accepts the
// key as the first token after one or more `- ` sequence indicators, which
// extract_yaml_value callers rely on for list items (`- type: interval`).
std::optional<KeyLine> find_key_line(const std::string& s, const std::string& key,
                                     bool allow_seq_entry) {
    const std::string needle = key + ":";
    for (std::size_t b = 0; b < s.size();) {
        const auto l = line_at(s, b);
        auto p = first_non_ws(s, l);
        while (allow_seq_entry && p != kNpos && s[p] == '-' && p + 1 < l.end && is_ws(s[p + 1])) {
            p += 2;
            while (p < l.end && is_ws(s[p]))
                ++p;
            if (p == l.end)
                p = kNpos;
        }
        if (p != kNpos && l.end - p >= needle.size() && s.compare(p, needle.size(), needle) == 0)
            return KeyLine{l, p, p + needle.size()};
        b = l.next;
    }
    return std::nullopt;
}

void trim(std::string& v) {
    std::size_t b = 0;
    while (b < v.size() && is_ws(v[b]))
        ++b;
    auto e = v.size();
    while (e > b && (is_ws(v[e - 1]) || v[e - 1] == '\r' || v[e - 1] == '\n'))
        --e;
    v = v.substr(b, e - b);
}

void strip_quotes(std::string& v) {
    if (v.size() >= 2 &&
        ((v.front() == '"' && v.back() == '"') || (v.front() == '\'' && v.back() == '\'')))
        v = v.substr(1, v.size() - 2);
}

// `key:` / `key: value` — the first token ends in ':' followed by a space or
// the end of the line. Used to tell the next key from a stray list line.
bool looks_like_key_line(std::string_view text) {
    for (std::size_t i = 0; i < text.size(); ++i) {
        const char ch = text[i];
        if (ch == ':')
            return i > 0 && (i + 1 == text.size() || is_ws(text[i + 1]));
        if (is_ws(ch) || ch == '#' || ch == '[' || ch == '{' || ch == '"' || ch == '\'')
            return false;
    }
    return false;
}

// A list line extract_yaml_list cannot place. It is kept, never dropped, in a
// form that always contains a space: `- <rest>` for a dash line (so `-prod` and
// a bare `-` are `- prod` and `- `), ` <text>` for a line with no dash.
void push_raw(std::vector<std::string>& out, std::size_t& cur, std::string_view text, bool dash) {
    std::string rest{dash ? text.substr(1) : text};
    trim(rest);
    cur = out.size();
    out.push_back((dash ? "- " : " ") + rest);
}

// The block-list lines under `kl`, by the rules below. extract_yaml_list runs
// this whatever is on the key line, so a value there can never hide the
// lines that follow it (governance Gate 8 round 4 dsl-engineer F1/F2).
std::vector<std::string> scan_block_list(const std::string& yaml, const KeyLine& kl) {
    std::vector<std::string> result;
    // Block list (#2123). The first `-` sets the item column; it may sit at the
    // key's own column (compact form, `tags:\n- a`) or deeper. After it:
    //   - a `-` line at the item column is the next item;
    //   - a `key:` line at or shallower than the list's own key (a sibling or a
    //     parent key), or a `---`/`...` document marker, ends the list; a `key:`
    //     line deeper than the list's key cannot be its sibling: at the item
    //     column it is a raw item, deeper it is folded into the current item;
    //   - a deeper non-`-` line continues the current item and is folded into it
    //     with a space, as YAML folds a multi-line plain scalar;
    //   - every other line is a RAW item: a `-` line at any other column
    //     (including a first `-` line shallower than the key, by any amount) is
    //     kept as `- <rest>`, and a line with no dash that is not a `key:` line
    //     is kept as ` <text>` — except a first line at or shallower than the
    //     key, which belongs to the parent and ends the (empty) list.
    // The rule behind all of it: a line belonging to the list must never vanish,
    // because a vanished tag widens a scope, and must never be absorbed as a
    // plain item, because an absorbed management group widens targeting. Raw
    // and folded items ALWAYS contain a space, whatever the input (`-prod` and a
    // bare `-` become `- prod` and `- `), and the scope-token charset that
    // callers validate tags and group ids with has no space, so the document is
    // refused rather than stored with a different meaning (governance G2-SEC-F1,
    // G3-DSL-F1, G4-CON-F3, Gate 8 C8-1 / F8). The valid YAML this refuses is a
    // list (or an empty `key:`) followed directly by an OUTER list's next item;
    // end the list with another key first (`key: []` there is refused too). Blank and
    // comment lines are skipped. A quirk kept deliberately: `-b` AT the item
    // column is read as the item `b` (at any other column it is the raw `- b`).
    const auto key_col = kl.key_pos - kl.line.begin;
    auto item_col = kNpos;
    auto cur = kNpos; // index in `result` of the item a continuation line extends
    for (auto b = kl.line.next; b < yaml.size();) {
        const auto l = line_at(yaml, b);
        b = l.next;
        if (is_blank_or_comment(yaml, l))
            continue;
        const auto len = l.end - l.begin;
        const bool doc_marker =
            len >= 3 &&
            (yaml.compare(l.begin, 3, "---") == 0 || yaml.compare(l.begin, 3, "...") == 0) &&
            (len == 3 || is_ws(yaml[l.begin + 3]));
        if (doc_marker)
            break;
        const auto fc = first_non_ws(yaml, l);
        const auto col = fc - l.begin;
        const bool dash = yaml[fc] == '-';
        const auto text = std::string_view{yaml}.substr(fc, l.end - fc);
        if (!dash && looks_like_key_line(text) && col <= key_col)
            break; // a sibling or parent key: the list (or the empty `key:`) is over
        if (item_col == kNpos) {
            if (!dash) {
                if (col <= key_col)
                    break; // not ours: shallower or level text belongs to the parent
                push_raw(result, cur, text, /*dash=*/false);
                continue;
            }
            if (col < key_col) {
                push_raw(result, cur, text, /*dash=*/true);
                return result;
            }
            item_col = col;
        } else if (col > item_col && !dash) {
            auto more = std::string{text};
            trim(more);
            if (cur == kNpos) {
                // `- ` with its value on the next line: that line IS the item —
                // unless it is key-shaped (a mapping entry), which stays raw.
                if (looks_like_key_line(more)) {
                    push_raw(result, cur, text, /*dash=*/false);
                    continue;
                }
                strip_quotes(more);
                cur = result.size();
                result.push_back(std::move(more));
            } else {
                result[cur] += " " + more;
            }
            continue;
        } else if (col != item_col || !dash) {
            push_raw(result, cur, text, dash);
            continue;
        }
        auto item = yaml.substr(fc + 1, l.end - fc - 1);
        trim(item);
        // A key-shaped item (`- pci:`) is a mapping entry in YAML, not a plain
        // scalar; `:` passes the scope-token charset, so keep it raw (governance
        // Gate 8 round 4 cpp-expert F1).
        if (looks_like_key_line(item)) {
            push_raw(result, cur, text, /*dash=*/true);
            continue;
        }
        // A bare `- ` is an item whose value is null. It is still DROPPED here,
        // so it is not refused and an all-null `tags:` list reads as no tags
        // (pre-existing, not yet refused; tracked on #2123, ledger
        // G8R5-NULL-ITEM). A quoted `- ""` is an empty string and is kept so
        // the caller refuses it (governance Gate 8 N3).
        const bool present = !item.empty();
        strip_quotes(item);
        cur = kNpos;
        if (present) {
            cur = result.size();
            result.push_back(std::move(item));
        }
    }
    return result;
}

// Block items found after a value on the key line (`tags: null`,
// `tags: prod`, `tags: [a]`) cannot be placed: keep each one raw.
void append_as_raw(std::vector<std::string>& out, const std::vector<std::string>& block) {
    for (const auto& item : block)
        out.push_back("- " + item);
}

} // namespace

std::vector<std::string_view> split_lines(std::string_view text) {
    std::vector<std::string_view> out;
    for (std::size_t b = 0; b < text.size();) {
        const auto l = line_at(text, b);
        out.push_back(text.substr(l.begin, l.end - l.begin));
        b = l.next;
    }
    return out;
}

std::string extract_yaml_value(const std::string& yaml, const std::string& key) {
    const auto kl = find_key_line(yaml, key, /*allow_seq_entry=*/true);
    if (!kl)
        return {};
    auto v = kl->value_pos;
    while (v < kl->line.end && is_ws(yaml[v]))
        ++v;
    // Nothing after the colon: the key opens a mapping, sequence or block.
    if (v >= kl->line.end)
        return {};
    auto val = yaml.substr(v, kl->line.end - v);
    trim(val);
    strip_quotes(val);
    // YAML folded/literal block indicator: not a scalar.
    if (val == ">" || val == "|")
        return {};
    return val;
}

std::vector<std::string> extract_yaml_list(const std::string& yaml, const std::string& key) {
    std::vector<std::string> result;
    const auto kl = find_key_line(yaml, key, /*allow_seq_entry=*/false);
    if (!kl)
        return result;

    // Inline list: key: [item1, item2]. The closing ']' is looked for on the
    // key's own line only, before any inline comment: a multi-line flow list
    // or an unterminated one must never pull ids out of a comment or a later
    // key's list (#2123). With no ']' there the raw value is returned as ONE
    // item, never as an empty list: a tag containing '[' fails
    // validate_scope_block's charset (the policy is rejected) and a group id
    // containing '[' matches no group, whereas an empty list would silently
    // drop every tag predicate and widen the scope.
    auto c = kl->value_pos;
    while (c < kl->line.end && is_ws(yaml[c]))
        ++c;
    if (c < kl->line.end && yaml[c] == '[') {
        auto limit = kl->line.end;
        for (auto i = c + 1; i < kl->line.end; ++i) {
            if (yaml[i] == '#' && is_ws(yaml[i - 1])) {
                limit = i;
                break;
            }
        }
        const auto close = yaml.find(']', c);
        if (close == kNpos || close >= limit) {
            auto raw = yaml.substr(c, limit - c);
            trim(raw);
            result.push_back(std::move(raw));
            append_as_raw(result, scan_block_list(yaml, *kl));
            return result;
        }
        const auto inner = yaml.substr(c + 1, close - c - 1);
        std::size_t start = 0;
        while (start < inner.size()) {
            auto comma = inner.find(',', start);
            if (comma == kNpos)
                comma = inner.size();
            auto item = inner.substr(start, comma - start);
            trim(item);
            // A quoted empty string (`""`) is kept so the caller refuses it
            // (governance Gate 8 N3). A missing entry between commas (`[,]`,
            // `[a,,b]`) is still DROPPED, not refused (pre-existing, not yet
            // refused; tracked on #2123, ledger G8R5-NULL-ITEM).
            const bool present = !item.empty();
            strip_quotes(item);
            if (present)
                result.push_back(std::move(item));
            start = comma + 1;
        }
        append_as_raw(result, scan_block_list(yaml, *kl));
        return result;
    }

    // A scalar where a list is expected (`tags: prod`) is neither read nor
    // dropped: dropping it read as "no tags" and widened a scope (governance
    // Gate 8 R2-2), and reading it as one item made a scalar `managementGroups:
    // <id>` anywhere in the document a group that replaces the selector, and
    // `managementGroups: null` the group `null` (Gate 8 A1, UP-A, UP-B). It is kept
    // as ONE raw item with a leading space, which every caller's charset refuses.
    // A YAML null (`null`, `Null`, `NULL`, `~`, optionally followed by a comment)
    // with nothing after it is an empty list, as YAML means; followed by list
    // lines it is refused like any other scalar, so the null cannot hide them
    // (Gate 8 round 4 dsl-engineer F1). A comment-only remainder (`tags:  #
    // note`) is the usual opener of a block list and falls through to it.
    if (c < kl->line.end && yaml[c] != '#') {
        auto scalar = yaml.substr(c, kl->line.end - c);
        trim(scalar);
        auto bare = scalar;
        for (std::size_t i = 1; i < bare.size(); ++i) {
            if (bare[i] == '#' && is_ws(bare[i - 1])) {
                bare.resize(i);
                trim(bare);
                break;
            }
        }
        auto block = scan_block_list(yaml, *kl);
        if ((bare == "null" || bare == "Null" || bare == "NULL" || bare == "~") && block.empty())
            return result;
        result.push_back(" " + scalar);
        append_as_raw(result, block);
        return result;
    }

    return scan_block_list(yaml, *kl);
}

std::vector<std::pair<std::string, std::string>>
extract_yaml_mapping(const std::string& yaml, const std::string& key) {
    std::vector<std::pair<std::string, std::string>> result;
    const auto kl = find_key_line(yaml, key, /*allow_seq_entry=*/false);
    if (!kl)
        return result;
    const auto key_indent = kl->key_pos - kl->line.begin;

    for (auto b = kl->line.next; b < yaml.size();) {
        const auto l = line_at(yaml, b);
        b = l.next;
        if (is_blank_or_comment(yaml, l))
            continue;
        const auto fc = first_non_ws(yaml, l);
        // Back to the key's own level or an outer one: end of the mapping.
        if (fc - l.begin <= key_indent)
            break;

        // Parse "subkey: value"
        const auto line = yaml.substr(fc, l.end - fc);
        const auto colon = line.find(':');
        if (colon == kNpos)
            continue;
        auto k = line.substr(0, colon);
        trim(k);
        auto v = line.substr(colon + 1);
        trim(v);
        strip_quotes(v);
        if (!k.empty())
            result.emplace_back(std::move(k), std::move(v));
    }
    return result;
}

std::string extract_yaml_section(const std::string& yaml, const std::string& dotted_path) {
    std::string current = yaml;
    std::string remaining = dotted_path;

    while (!remaining.empty()) {
        const auto dot = remaining.find('.');
        const auto segment = (dot == kNpos) ? remaining : remaining.substr(0, dot);
        remaining = (dot == kNpos) ? "" : remaining.substr(dot + 1);

        // Anchor to a real key: the match must be the first token on its
        // line, not a `segment:` substring inside a value, a description, or
        // a comment. An unanchored find() previously mis-anchored on such a
        // substring, mis-computed key_indent, and returned an empty block —
        // silently dropping the whole section (for a policy that means the
        // scope predicate vanishes). (#1221 MEDIUM-2 / #1215 adversarial H-2.)
        const auto kl = find_key_line(current, segment, /*allow_seq_entry=*/false);
        if (!kl)
            return {};
        const auto key_indent = kl->key_pos - kl->line.begin;

        // Collect every line more indented than the key. Blank and comment
        // lines never end the block (#2123); they are kept so the block reads
        // like the source. The block is re-joined with '\n' whatever the
        // source's line breaks were, so callers only ever see LF.
        std::string block;
        for (auto b = kl->line.next; b < current.size();) {
            const auto l = line_at(current, b);
            b = l.next;
            if (!is_blank_or_comment(current, l) &&
                first_non_ws(current, l) - l.begin <= key_indent)
                break;
            block.append(current, l.begin, l.end - l.begin);
            block += '\n';
        }
        current = std::move(block);
    }
    return current;
}

bool yaml_has_key(const std::string& block, const std::string& key) {
    return find_key_line(block, key, /*allow_seq_entry=*/false).has_value();
}

} // namespace yuzu::server::yaml_scan
