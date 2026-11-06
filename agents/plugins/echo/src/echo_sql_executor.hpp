#pragma once

/**
 * echo_sql_executor.hpp -- Safe SQL query execution for the Echo warehouse
 *
 * Validates operator-submitted SQL queries for safety:
 *  1. SELECT-only (rejects INSERT/UPDATE/DELETE/DROP/ALTER/CREATE/ATTACH/PRAGMA)
 *  2. $-name whitelist translation ($Process_Live -> process_live)
 *  3. Single-statement enforcement
 *
 * Used by the echo.sql plugin action.
 */

#include <expected>
#include <string>

namespace yuzu::echo {

/**
 * Validate and translate a SQL query containing $-prefixed table names.
 * Returns the translated SQL on success, or an error message on failure.
 *
 * Validation rules:
 *  - Must start with SELECT (case-insensitive, after whitespace trimming)
 *  - Must not contain dangerous keywords (INSERT, UPDATE, DELETE, DROP, etc.)
 *  - All $Name_Suffix references must be in the schema registry whitelist
 *  - Must be a single statement (no trailing SQL after the first semicolon)
 */
std::expected<std::string, std::string> validate_and_translate_sql(const std::string& raw_sql);

} // namespace yuzu::echo
