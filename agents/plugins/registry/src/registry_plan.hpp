#pragma once

/**
 * registry_plan.hpp -- the registry plugin's PURE `apply` layer that needs a JSON parser: the plan parser, the
 * exact-name predicate the undo manifest depends on, and the item / undo / summary row renderers. Kept out of
 * registry_parsers.hpp so the server's audit test (which includes that header) does not pull nlohmann. No windows.h,
 * no I/O, no clock; unit-tested on every host (tests/unit/test_registry_plan.cpp). The logic that RUNS a plan over an
 * injected registry is registry_core.hpp's run_apply.
 *
 * THE EXACT-NAME RULE. An `apply` reply carries an undo manifest, so every key path and value name a row spells has
 * to read back as the very name that was in the registry. A row cell is sanitised display text (row_field folds '|',
 * CR, LF, the other controls, C1, U+2028 / U+2029 and a trailing NUL, and replaces invalid UTF-8): lossy by design.
 * So a name that row_field would change is REFUSED before anything is mutated (`unrepresentable_name`), never
 * encoded: `representable()` is that one predicate, used for the names a plan carries and for the names enumerated
 * from a key that is about to be deleted.
 */

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

#include <nlohmann/json.hpp>

#include "registry_parsers.hpp"

namespace yuzu::registry {

// ── the exact-name rule ──────────────────────────────────────────────────

/// One cell of a row: the text scrubbed of NUL and invalid UTF-8 (wire_utf8.hpp), then folded by sanitize_field ('|',
/// the controls, C1, U+2028 / U+2029 and trailing NULs become '_' or are dropped), and a trailing backslash becomes '_'
/// (the server's column splitter, result_parsing.hpp find_unescaped_pipe, reads `\|` as an escaped pipe and would merge
/// the cell with the next, as log_token guards it); "-" when nothing is left. Lossy by design; `representable` is the
/// guard that keeps a name from ever being damaged by it.
[[nodiscard]] inline std::string row_field(std::string_view s) {
    std::string t{s};
    yuzu::shared::scrub_wire_bytes(t);
    t = yuzu::profiles::sanitize_field(t);
    if (t.empty()) return "-";
    if (t.back() == '\\') t.back() = '_';
    return t;
}

/// Whether `s` survives a row cell byte for byte, so the manifest names exactly what was in the registry:
/// `row_field(s) == s` (no '|', no C0 / DEL / C1 control, no U+2028 / U+2029, no invalid UTF-8, no NUL, no trailing
/// backslash), and additionally not the literal "-" (a row spells the empty default name that way, so a value really
/// named "-" could not be told from it). The empty name is the key's default value and is representable. A TAB is kept
/// by sanitize_field and so passes here; the callers that need a name this plugin can also WRITE BACK add
/// validate_value_name (which refuses a control byte).
[[nodiscard]] inline bool representable(std::string_view s) {
    if (s.empty()) return true;
    if (s == "-") return false;
    return row_field(s) == s;
}

// ── the plan ─────────────────────────────────────────────────────────────

/// `count_` is not an op: it counts the enumerators, so a new op without its name fails the static_assert below.
enum class PlanOp { set_value, delete_value, create_key, delete_key, count_ };

inline constexpr std::array<std::string_view, 4> kPlanOpNames{"set_value", "delete_value", "create_key", "delete_key"};
static_assert(kPlanOpNames.size() == static_cast<std::size_t>(PlanOp::count_)); // one name per op
static_assert(kPlanOpNames[static_cast<std::size_t>(PlanOp::delete_key)] == "delete_key"); // indexed by enum value
[[nodiscard]] constexpr std::string_view plan_op_name(PlanOp o) noexcept {
    return kPlanOpNames[static_cast<std::size_t>(o)];
}

struct PlanItem {
    PlanOp op = PlanOp::set_value;
    std::string hive = "HKLM";
    std::string key, name, type_name;
    std::uint32_t type = 0;
    std::vector<std::uint8_t> bytes; ///< encoded new data (set_value)
    std::string invalid;             ///< a per-item kTok* token: the item is refused with it
};

struct PlanParse {
    std::vector<PlanItem> items;
    /// Whole-plan refusal, "" = accepted: `invalid_plan:<why>[:<item index>]` or `dependent_items:<i>:<j>`; already the
    /// text that follows `error|`.
    std::string error;
};

namespace detail {

[[nodiscard]] inline bool is_key_op(PlanOp o) noexcept { return o == PlanOp::create_key || o == PlanOp::delete_key; }

/// a == b or a is an ancestor of b (by path components).
[[nodiscard]] inline bool key_covers(std::string_view a, std::string_view b) noexcept {
    return b == a || (b.size() > a.size() && b.starts_with(a) && b[a.size()] == '\\');
}

/// The ASCII fold with every maximal run of non-ASCII bytes collapsed to one 0x80: the most two keys the ASCII fold
/// cannot tell apart might still be (the kernel folds all of Unicode, this plugin only ASCII). Two keys that agree
/// here but not under fold_ascii alone MAY be one key under different spellings.
[[nodiscard]] inline std::string fold_skeleton(std::string_view s) {
    std::string out;
    out.reserve(s.size());
    bool in_run = false;
    for (const char c : fold_ascii(s)) {
        const bool high = static_cast<unsigned char>(c) >= 0x80;
        if (!high || !in_run) out += high ? '\x80' : c;
        in_run = high;
    }
    return out;
}

/// True when, at some depth the two keys share under the skeleton fold, the components are one key to the kernel but
/// spelled differently under the ASCII fold (all arguments already folded; `ka`/`sa` and `kb`/`sb` are the same key
/// under fold_ascii / fold_skeleton). A shared PARENT counts, not only the whole path: the item that creates `Ä` makes
/// a later `ä\Y` fail the canonical-name check even though the leaf keys differ.
[[nodiscard]] inline bool ambiguous_shared_prefix(std::string_view ka, std::string_view kb, std::string_view sa,
                                                  std::string_view sb) {
    const auto ca = split_key(ka), cb = split_key(kb), xa = split_key(sa), xb = split_key(sb);
    for (std::size_t d = 0; d < std::min(ca.size(), cb.size()); ++d) {
        if (xa[d] != xb[d]) return false; // the keys part company under every spelling: nothing deeper is shared
        if (ca[d] != cb[d]) return true;
    }
    return false;
}

/// Nesting depth of '[' / '{' outside string literals; > 2 is not a flat array of flat objects. Checked BEFORE the
/// parse so a deeply nested document never reaches the parser (or its destructor).
[[nodiscard]] inline bool nested_deeper_than_two(std::string_view s) noexcept {
    int depth = 0;
    bool in_str = false;
    for (std::size_t i = 0; i < s.size(); ++i) {
        const char c = s[i];
        if (in_str) {
            if (c == '\\')
                ++i;
            else if (c == '"')
                in_str = false;
        } else if (c == '"') {
            in_str = true;
        } else if (c == '[' || c == '{') {
            if (++depth > 2) return true;
        } else if (c == ']' || c == '}') {
            --depth;
        }
    }
    return false;
}

} // namespace detail

/// Parses an apply plan: a JSON array of flat objects with the string fields `op`, `hive`, `key`, `name`, `type`,
/// `value`, `data_hex`. WHOLE-PLAN refusals (`error`): more than 64 KiB / nested / not JSON / not an array / empty /
/// more than 256 items / an item that is not an object, has an unknown key, a non-string field or an unknown `op` /
/// `dependent_items`. Everything else is a PER-ITEM refusal in PlanItem::invalid (hive other than HKLM, a key path or
/// value name that fails validation or is not `representable`, a key op that carries data, a value that does not
/// encode), so a dry run and a real run give the same verdict item for item.
///
/// DEPENDENT ITEMS (two value ops on one key and name; a key op over another item's equal, ancestor or descendant key)
/// are refused as a whole, so no verdict depends on an earlier item and dry run == real run; items that are already
/// refused cannot change anything and are left out of the comparison. ponytail: O(n^2) over <= 256 items; keys compare
/// ASCII-case-insensitively, so keys that differ only in non-ASCII case are not recognised as one (README caveat).
/// Value names are CONSERVATIVE instead: Windows folds a value name's case with the full Unicode table, which this
/// parser cannot reproduce, so two value items on one key are dependent whenever either name holds a non-ASCII byte.
[[nodiscard]] inline PlanParse parse_plan(std::string_view text) {
    PlanParse out;
    const auto fail = [&](std::string e) {
        out.items.clear();
        out.error = std::move(e);
        return out;
    };
    const auto at = [](std::string_view why, std::size_t idx) {
        return "invalid_plan:" + std::string{why} + ":" + std::to_string(idx);
    };
    if (text.size() > kMaxPlanBytes) return fail("invalid_plan:plan_too_large");
    if (detail::nested_deeper_than_two(text)) return fail("invalid_plan:not_flat");
    const auto doc = nlohmann::json::parse(text.begin(), text.end(), nullptr, /*allow_exceptions=*/false);
    if (doc.is_discarded()) return fail("invalid_plan:not_json");
    if (!doc.is_array()) return fail("invalid_plan:not_array");
    if (doc.empty()) return fail("invalid_plan:empty");
    if (doc.size() > kMaxPlanItems) return fail("invalid_plan:too_many_items");

    constexpr std::array<std::string_view, 7> kFields{"op", "hive", "key", "name", "type", "value", "data_hex"};
    for (std::size_t idx = 0; idx < doc.size(); ++idx) {
        const auto& obj = doc[idx];
        if (!obj.is_object()) return fail(at("item_not_object", idx));
        std::array<std::string, 7> f{};
        bool hex_present = false;
        for (const auto& [k, v] : obj.items()) {
            const auto it = std::find(kFields.begin(), kFields.end(), std::string_view{k});
            if (it == kFields.end()) return fail(at("unknown_key", idx));
            if (!v.is_string()) return fail(at("field_type", idx));
            f[static_cast<std::size_t>(it - kFields.begin())] = v.get<std::string>();
            if (k == "data_hex") hex_present = true;
        }
        PlanItem item;
        const auto op_it = std::find(kPlanOpNames.begin(), kPlanOpNames.end(), f[0]);
        if (op_it == kPlanOpNames.end()) return fail(at("invalid_op", idx));
        item.op = static_cast<PlanOp>(op_it - kPlanOpNames.begin());
        item.hive = f[1].empty() ? "HKLM" : f[1];
        item.key = f[2];
        item.name = f[3];
        const bool value_op = !detail::is_key_op(item.op);
        // apply targets the machine hive only: HKCU / HKU are per-user (set_user_value) and HKCR is a merged view
        // whose writes land in either hive.
        if (item.hive != "HKLM") {
            item.invalid = std::string{kTokInvalidHive};
        } else if (const auto e = validate_key_path(item.key); !e.empty()) {
            item.invalid = std::string{e};
        } else if (!representable(item.key)) {
            item.invalid = std::string{kTokUnrepresentableName};
        } else if (!value_op) {
            if (!item.name.empty()) item.invalid = std::string{kTokInvalidValueName};
        } else if (const auto name_err = validate_value_name(item.name); !name_err.empty()) {
            item.invalid = std::string{name_err};
        } else if (!representable(item.name)) {
            item.invalid = std::string{kTokUnrepresentableName};
        }
        if (item.invalid.empty()) {
            if (item.op == PlanOp::set_value) {
                item.type_name = f[4].empty() ? "REG_SZ" : f[4];
                if (const auto t = parse_reg_type(item.type_name)) {
                    item.type = *t;
                    auto enc = encode_value(*t, f[5], f[6], hex_present);
                    if (!enc.error.empty())
                        item.invalid = std::string{enc.error};
                    else
                        item.bytes = std::move(enc.bytes);
                } else {
                    item.invalid = std::string{kTokInvalidType};
                }
            } else if (!f[4].empty() || !f[5].empty() || hex_present) {
                item.invalid = std::string{kTokInvalidData}; // only set_value carries data
            }
        }
        out.items.push_back(std::move(item));
    }

    std::vector<std::string> keys, skeletons, names;
    std::vector<bool> non_ascii;
    keys.reserve(out.items.size());
    skeletons.reserve(out.items.size());
    names.reserve(out.items.size());
    for (const auto& it : out.items) {
        keys.push_back(detail::fold_ascii(it.key));
        skeletons.push_back(detail::fold_skeleton(it.key));
        names.push_back(detail::fold_ascii(it.name));
        non_ascii.push_back(std::ranges::any_of(it.name, [](char c) { return static_cast<unsigned char>(c) >= 0x80; }));
    }
    for (std::size_t j = 1; j < out.items.size(); ++j) {
        if (!out.items[j].invalid.empty()) continue;
        for (std::size_t i = 0; i < j; ++i) {
            if (!out.items[i].invalid.empty()) continue;
            const bool key_involved = detail::is_key_op(out.items[i].op) || detail::is_key_op(out.items[j].op);
            // Related under the ASCII fold: a key op over an equal/ancestor/descendant key of any item, else the same key.
            const bool ascii_related = key_involved ? (detail::key_covers(keys[i], keys[j]) || detail::key_covers(keys[j], keys[i]))
                                                    : keys[i] == keys[j];
            // Keys that differ only in the case of a non-ASCII character are one kernel key that apply's ASCII-only
            // handle map treats as two: the real run would refuse the second spelling (key_is_link) where the dry run
            // predicted it. The ASCII fold can neither prove them one nor apart, so such a plan is refused whole, as
            // the value-name rule below does for non-ASCII names. Any shared path prefix counts, not only the whole key.
            const bool spelling_clash = detail::ambiguous_shared_prefix(keys[i], keys[j], skeletons[i], skeletons[j]);
            const bool clash = spelling_clash || (ascii_related && (key_involved || names[i] == names[j] || non_ascii[i] || non_ascii[j]));
            if (clash)
                return fail(std::string{kTokDependentItems} + ":" + std::to_string(i) + ":" + std::to_string(j));
        }
    }
    return out;
}

// ── apply rows ───────────────────────────────────────────────────────────

struct ItemRow {
    std::size_t index = 0;
    std::string op, hive, key, name;
    std::string verdict;   ///< would_apply | applied | refused | failed | skipped
    std::string reason;    ///< token, "" = "-"
    std::string verify;    ///< ok | mismatch, "" = "-"
    long long created = -1;
    bool value_op = false; ///< set_value / delete_value whose previous value was read: the old_* columns apply ("-" else)
    OldValue old;          ///< the previous value (value ops)
    long long new_len = -1;
};

/// `item|<idx>|<op>|<hive>|<key>|<name>|<verdict>|<reason>|<verify>|<created>|<old_state>|<old_type>|<old_hex>|<new_len>`
/// (14 cells). <old_hex> is the retained part of the previous value (<= kCaptureValueCap bytes), `~<total>` appended when
/// the value was larger or the capture budget could not keep it. The key and name cells are row_field text: for an
/// item that proceeds they are exact (representable), for a refused one they may be the folded display form.
[[nodiscard]] inline std::string render_item_row(const ItemRow& r) {
    using detail::dash;
    using detail::num;
    const bool has_old = r.value_op && r.old.state == OldState::present;
    return "item|" + std::to_string(r.index) + "|" + row_field(r.op) + "|" + row_field(r.hive) + "|" +
           row_field(r.key) + "|" + row_field(r.name) + "|" + r.verdict + "|" + row_field(r.reason) + "|" +
           dash(r.verify) + "|" + num(r.created) + "|" +
           (r.value_op ? std::string{old_state_name(r.old.state)} : std::string{"-"}) + "|" +
           (has_old ? std::string{yuzu::profiles::reg_type_name(r.old.type)} : std::string{"-"}) + "|" +
           (has_old ? render_hex(r.old.bytes, kCaptureValueCap, r.old.total) : std::string{"-"}) + "|" +
           num(r.new_len);
}

/// `undo|<idx>|<name>|<type>|<hex>|<truncated>` (6 cells): one value captured from a key an item deleted. <hex> is the
/// retained part (`~<total>` appended when cut), <truncated> is 1 then. The name is exact (the caller retained it only
/// when it is `representable`).
[[nodiscard]] inline std::string render_undo_row(std::size_t index, std::string_view name, const OldValue& v) {
    const bool truncated = v.bytes.size() < v.total;
    return "undo|" + std::to_string(index) + "|" + row_field(name) + "|" +
           std::string{yuzu::profiles::reg_type_name(v.type)} + "|" + render_hex(v.bytes, kCaptureValueCap, v.total) +
           "|" + (truncated ? "1" : "0");
}

struct ApplySummary {
    std::size_t total = 0, applied = 0, refused = 0, failed = 0, skipped = 0;
    bool dry_run = false;
    bool undo_complete = true;
};

/// `summary|<total>|<applied>|<refused>|<failed>|<skipped>|<dry_run>|<undo_complete>` (8 cells).
[[nodiscard]] inline std::string render_summary_row(const ApplySummary& s) {
    return "summary|" + std::to_string(s.total) + "|" + std::to_string(s.applied) + "|" + std::to_string(s.refused) +
           "|" + std::to_string(s.failed) + "|" + std::to_string(s.skipped) + "|" + (s.dry_run ? "1" : "0") + "|" +
           (s.undo_complete ? "1" : "0");
}

} // namespace yuzu::registry
