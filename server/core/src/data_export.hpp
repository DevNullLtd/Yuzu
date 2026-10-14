#pragma once

#include <string>
#include <vector>

namespace yuzu::server::data_export {

// CWE-1236 (CSV/formula injection): a field whose FIRST byte is one of these
// is executed as a formula by Excel/Sheets when the exported CSV is opened
// there -- `=`/`+`/`-`/`@` trigger a formula, and a leading tab (0x09) or CR
// (0x0d) can smuggle one past a naive "starts with =" filter. Promoted from
// access_review_model.cpp (the original, tested precedent for this fix) to
// this shared chokepoint so every CSV export -- not just the access-review
// one -- gets the same protection, rather than each new export forking its
// own copy.
inline bool is_formula_trigger(char c) {
    return c == '=' || c == '+' || c == '-' || c == '@' || c == '\t' || c == '\r';
}

// Neutralize a formula-injection-triggering leading byte by prefixing a
// literal `'` -- Excel/Sheets render a leading apostrophe as a text-cell
// marker (not part of the value) rather than executing what follows. Applied
// BEFORE the RFC-4180 quoting pass below. A field that legitimately starts
// with `-`/`+` (a negative number, an echoed CLI flag) is altered by this --
// an accepted, documented trade-off (matches the access-review precedent),
// since the alternative is a live formula-injection vector on every export
// of agent-influenceable content.
inline std::string neutralize_formula(const std::string& field) {
    if (!field.empty() && is_formula_trigger(field.front()))
        return "'" + field;
    return field;
}

// RFC 4180 quote-only: wrap in double quotes (doubling any internal quote)
// when the field contains a comma, quote, CR or LF. No formula neutralisation,
// so it is the right call for cells that are not free text -- a JSON number
// `-5` must stay `-5`, and a serialised nested object must keep its commas
// inside one cell (neutralisation of those would be wrong or a no-op).
inline std::string csv_quote(const std::string& field) {
    bool needs_quoting = false;
    for (char c : field) {
        if (c == ',' || c == '"' || c == '\n' || c == '\r') {
            needs_quoting = true;
            break;
        }
    }
    if (!needs_quoting)
        return field;

    std::string result;
    result.reserve(field.size() + 8);
    result += '"';
    for (char c : field) {
        if (c == '"')
            result += '"';
        result += c;
    }
    result += '"';
    return result;
}

// RFC 4180 CSV field escaping for free-text fields: formula-injection
// neutralization (above) runs first, then csv_quote, so every caller of this
// chokepoint is protected without having to know CWE-1236 exists.
inline std::string csv_escape(const std::string& field) {
    return csv_quote(neutralize_formula(field));
}

// Convert a JSON array string to CSV.  Expects a JSON array of objects
// with uniform keys.  Returns CSV with header row.
std::string json_array_to_csv(const std::string& json_str);

} // namespace yuzu::server::data_export
