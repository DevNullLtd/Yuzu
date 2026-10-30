/**
 * echo_sql_executor.cpp -- Safe SQL validation and $-name translation
 *
 * Three-layer defense:
 *  1. SELECT-only keyword check
 *  2. $-name whitelist translation
 *  3. Single-statement enforcement (reject trailing SQL)
 */

#include "echo_sql_executor.hpp"
#include "echo_schema_registry.hpp"

#include <algorithm>
#include <cctype>
#include <format>
#include <optional>
#include <regex>
#include <string>
#include <string_view>

namespace yuzu::echo {

namespace {

/// Trim leading and trailing whitespace.
std::string_view trim(std::string_view s) {
    while (!s.empty() && std::isspace(static_cast<unsigned char>(s.front())))
        s.remove_prefix(1);
    while (!s.empty() && std::isspace(static_cast<unsigned char>(s.back())))
        s.remove_suffix(1);
    return s;
}

/// Case-insensitive check if the string starts with a keyword.
bool starts_with_ci(std::string_view s, std::string_view prefix) {
    if (s.size() < prefix.size())
        return false;
    for (size_t i = 0; i < prefix.size(); ++i) {
        if (std::tolower(static_cast<unsigned char>(s[i])) !=
            std::tolower(static_cast<unsigned char>(prefix[i])))
            return false;
    }
    // Must be followed by whitespace or '(' to be a keyword boundary
    if (s.size() > prefix.size()) {
        char next = s[prefix.size()];
        if (std::isalnum(static_cast<unsigned char>(next)) || next == '_')
            return false;
    }
    return true;
}

/// Scan `sql` left to right, invoking `on_code(begin, end)` for each maximal
/// run of ordinary SQL and `on_skip(begin, end)` for each single-quoted string
/// literal or comment (block or line). Both the keyword stripper and the $-name
/// translator are built on this one scanner so they always agree on what is
/// code vs. data — the root-cause fix for the validate-vs-execute divergence
/// (#631). [begin, end) are byte offsets into `sql`.
template <class CodeFn, class SkipFn>
void scan_sql(const std::string& sql, CodeFn on_code, SkipFn on_skip) {
    size_t i = 0;
    size_t code_start = 0;
    auto flush_code = [&](size_t end) {
        if (end > code_start)
            on_code(code_start, end);
    };
    while (i < sql.size()) {
        // Single-quoted string literal
        if (sql[i] == '\'') {
            flush_code(i);
            size_t start = i;
            ++i;
            while (i < sql.size()) {
                if (sql[i] == '\'' && i + 1 < sql.size() && sql[i + 1] == '\'')
                    i += 2; // escaped ''
                else if (sql[i] == '\'') {
                    ++i;
                    break;
                } else
                    ++i;
            }
            on_skip(start, i);
            code_start = i;
        }
        // Block comment
        else if (sql[i] == '/' && i + 1 < sql.size() && sql[i + 1] == '*') {
            flush_code(i);
            size_t start = i;
            i += 2;
            while (i + 1 < sql.size() && !(sql[i] == '*' && sql[i + 1] == '/'))
                ++i;
            i = (i + 1 < sql.size()) ? i + 2 : sql.size();
            on_skip(start, i);
            code_start = i;
        }
        // Line comment
        else if (sql[i] == '-' && i + 1 < sql.size() && sql[i + 1] == '-') {
            flush_code(i);
            size_t start = i;
            i += 2;
            while (i < sql.size() && sql[i] != '\n')
                ++i;
            on_skip(start, i);
            code_start = i;
        } else {
            ++i;
        }
    }
    flush_code(sql.size());
}

/// Replace string literals and comments with a single space so keyword matching
/// doesn't produce false positives on data values. (H7)
std::string strip_literals_and_comments(const std::string& sql) {
    std::string out;
    out.reserve(sql.size());
    scan_sql(
        sql, [&](size_t b, size_t e) { out.append(sql, b, e - b); },
        [&](size_t, size_t) { out += ' '; });
    return out;
}

/// Translate $Word_Word table placeholders to their real table names, but ONLY
/// in code regions — never inside a string literal or comment. A $name that is
/// data (e.g. '$tar_events' as a string value) is left untouched, so the
/// executed query is the same one the validator checked (#631). Returns an
/// error if a placeholder is not in the registry whitelist.
std::expected<std::string, std::string> translate_dollar_names(const std::string& sql) {
    // This regex must stay anchor-free (no ^, $, \b, lookbehind): it is run per
    // code span via regex_search over fresh [p, end) ranges, which don't preserve
    // match_prev_avail across spans, so anchors would misbehave (#631).
    static const std::regex dollar_re(R"(\$([A-Za-z]+_[A-Za-z]+))");
    std::string out;
    out.reserve(sql.size());
    std::optional<std::string> error;
    scan_sql(
        sql,
        [&](size_t b, size_t e) {
            if (error)
                return;
            const char* p = sql.data() + b;
            const char* end = sql.data() + e;
            std::cmatch m;
            while (std::regex_search(p, end, m, dollar_re)) {
                out.append(p, p + m.position(0));
                std::string dollar_name = "$" + m.str(1);
                auto real = translate_dollar_name(dollar_name);
                if (!real) {
                    error = std::format("unknown table: {}", dollar_name);
                    return;
                }
                out += *real;
                p += m.position(0) + m.length(0);
            }
            out.append(p, end);
        },
        [&](size_t b, size_t e) { out.append(sql, b, e - b); });
    if (error)
        return std::unexpected(*error);
    return out;
}

/// Check if the SQL contains a dangerous keyword (case-insensitive word match).
/// Operates on stripped input (no string literals or comments).
bool contains_dangerous_keyword(const std::string& stripped_sql) {
    std::string upper;
    upper.reserve(stripped_sql.size());
    for (char c : stripped_sql)
        upper += static_cast<char>(std::toupper(static_cast<unsigned char>(c)));

    static const std::string_view dangerous[] = {
        "INSERT",    "UPDATE",  "DELETE",   "DROP",           "ALTER",   "CREATE",
        "ATTACH",    "DETACH",  "PRAGMA",   "REPLACE",        "REINDEX", "VACUUM",
        "SAVEPOINT", "RELEASE", "ROLLBACK", "LOAD_EXTENSION",
    };

    for (auto kw : dangerous) {
        auto pos = upper.find(kw);
        while (pos != std::string::npos) {
            bool left_ok =
                (pos == 0) ||
                !std::isalnum(static_cast<unsigned char>(upper[pos - 1])) && upper[pos - 1] != '_';
            bool right_ok = (pos + kw.size() >= upper.size()) ||
                            !std::isalnum(static_cast<unsigned char>(upper[pos + kw.size()])) &&
                                upper[pos + kw.size()] != '_';
            if (left_ok && right_ok)
                return true;
            pos = upper.find(kw, pos + 1);
        }
    }
    return false;
}

/// Check for multiple statements (semicolons followed by non-whitespace).
bool has_multiple_statements(std::string_view sql) {
    auto semi = sql.find(';');
    if (semi == std::string_view::npos)
        return false;
    // Check if there's meaningful content after the semicolon
    auto rest = trim(sql.substr(semi + 1));
    return !rest.empty();
}

} // namespace

std::expected<std::string, std::string> validate_and_translate_sql(const std::string& raw_sql) {
    // H12: Reject oversized input to prevent regex DoS
    if (raw_sql.size() > 4096)
        return std::unexpected("SQL query exceeds 4KB limit");

    auto trimmed = trim(raw_sql);
    if (trimmed.empty())
        return std::unexpected("empty SQL query");

    // Layer 1: Must start with SELECT
    if (!starts_with_ci(trimmed, "SELECT"))
        return std::unexpected("only SELECT queries are allowed");

    // Layer 1b: Must not contain dangerous keywords
    // H7: Strip string literals and comments first to avoid false positives
    std::string sql_str(trimmed);
    auto stripped = strip_literals_and_comments(sql_str);
    if (contains_dangerous_keyword(stripped))
        return std::unexpected("query contains forbidden keyword");

    // Layer 3: single statement only. Checked on the stripped form so a ';'
    // inside a string literal or comment doesn't trip it; execute_user_query's
    // prepare-tail check is the engine-level backstop.
    if (has_multiple_statements(stripped))
        return std::unexpected("only single-statement queries are allowed");

    // Layer 2: translate $-prefixed table names — only outside string literals
    // and comments, so the executed query is the one that was validated (#631).
    auto translated = translate_dollar_names(sql_str);
    if (!translated)
        return std::unexpected(translated.error());
    std::string result = std::move(*translated);

    // Strip trailing semicolons
    while (!result.empty() &&
           (result.back() == ';' || std::isspace(static_cast<unsigned char>(result.back()))))
        result.pop_back();

    return result;
}

} // namespace yuzu::echo
