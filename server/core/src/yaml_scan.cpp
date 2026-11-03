#include "yaml_scan.hpp"

#include <cstddef>
#include <optional>

namespace yuzu::server::yaml_scan {

namespace {

constexpr auto npos = std::string::npos;

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

Line line_at(const std::string& s, std::size_t begin) {
    const auto brk = s.find_first_of("\r\n", begin);
    if (brk == npos)
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
    return npos;
}

// A line with no content, or whose first token is '#'. YAML comment lines
// take no part in indentation, so neither kind can end a block (#2123).
bool is_blank_or_comment(const std::string& s, const Line& l) {
    const auto fc = first_non_ws(s, l);
    return fc == npos || s[fc] == '#';
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
        while (allow_seq_entry && p != npos && s[p] == '-' && p + 1 < l.end && is_ws(s[p + 1])) {
            p += 2;
            while (p < l.end && is_ws(s[p]))
                ++p;
            if (p == l.end)
                p = npos;
        }
        if (p != npos && l.end - p >= needle.size() && s.compare(p, needle.size(), needle) == 0)
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

} // namespace

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
        if (close == npos || close >= limit) {
            auto raw = yaml.substr(c, limit - c);
            trim(raw);
            result.push_back(std::move(raw));
            return result;
        }
        const auto inner = yaml.substr(c + 1, close - c - 1);
        std::size_t start = 0;
        while (start < inner.size()) {
            auto comma = inner.find(',', start);
            if (comma == npos)
                comma = inner.size();
            auto item = inner.substr(start, comma - start);
            trim(item);
            strip_quotes(item);
            if (!item.empty())
                result.push_back(std::move(item));
            start = comma + 1;
        }
        return result;
    }

    // Block list (#2123). The first `-` sets the item column; it may sit at
    // the key's own column (compact form, `tags:\n- a`) or deeper, never
    // shallower. After it:
    //   - a `-` line at the item column is the next item;
    //   - a deeper line continues the current item and is skipped, NOT a
    //     terminator: ending there would drop later items, and a dropped tag
    //     widens a scope;
    //   - a line at any shallower column, or a non-`-` line at the item
    //     column, ends the list, so an outer or sibling list's items are
    //     never absorbed (an absorbed management group widens targeting);
    //   - a `---`/`...` document marker ends it.
    // Blank and comment lines are skipped. An item written `-b` (no space) is
    // still read as `b`; rejecting it is left to the fail-closed work.
    const auto key_col = kl->key_pos - kl->line.begin;
    auto item_col = npos;
    for (auto b = kl->line.next; b < yaml.size();) {
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
        if (item_col == npos) {
            if (yaml[fc] != '-' || col < key_col)
                break;
            item_col = col;
        } else if (col > item_col) {
            continue;
        } else if (col < item_col || yaml[fc] != '-') {
            break;
        }
        auto item = yaml.substr(fc + 1, l.end - fc - 1);
        trim(item);
        strip_quotes(item);
        if (!item.empty())
            result.push_back(std::move(item));
    }
    return result;
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
        if (colon == npos)
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
        const auto segment = (dot == npos) ? remaining : remaining.substr(0, dot);
        remaining = (dot == npos) ? "" : remaining.substr(dot + 1);

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
