/// @file test_instruction_store_faults.hpp
/// Fault injections against the instruction store's REAL relations in a throwaway database. Built
/// on `yuzu::test::SqlFault` (arm / repair, repaired by the destructor). `ExistsProbeFault` is used
/// by the v1 REST authoring tests and the MCP tests; `WriteFault` by the MCP tests only.
#pragma once

#include "test_principal_lock_gate.hpp"

namespace yuzu::test {

/// Moves `instruction_definitions` behind a view that behaves identically EXCEPT that the
/// existence probe `update_definition` runs after a zero-row compare-and-set
/// (`SELECT 1 FROM instruction_store.instruction_definitions ...`) raises. The reads and the
/// UPDATE itself are unaffected, so the only failing statement is the probe.
class ExistsProbeFault : public SqlFault {
public:
    explicit ExistsProbeFault(yuzu::server::pg::PgPool& pool)
        : SqlFault(
              pool,
              "DO $do$ BEGIN "
              "EXECUTE $f$CREATE FUNCTION public.yuzu_test_probe_gate() RETURNS boolean "
              "LANGUAGE plpgsql VOLATILE AS $b$ BEGIN "
              "IF current_query() LIKE 'SELECT 1 FROM instruction_store.instruction_definitions%' "
              "THEN RAISE EXCEPTION 'yuzu_test: existence probe fault'; END IF; "
              "RETURN true; END $b$$f$; "
              "EXECUTE 'ALTER TABLE instruction_store.instruction_definitions RENAME TO "
              "instruction_definitions_real'; "
              "EXECUTE 'CREATE VIEW instruction_store.instruction_definitions AS SELECT * FROM "
              "instruction_store.instruction_definitions_real WHERE public.yuzu_test_probe_gate()'; "
              "END $do$",
              "DO $do$ BEGIN "
              "EXECUTE 'DROP VIEW instruction_store.instruction_definitions'; "
              "EXECUTE 'ALTER TABLE instruction_store.instruction_definitions_real RENAME TO "
              "instruction_definitions'; "
              "EXECUTE 'DROP FUNCTION public.yuzu_test_probe_gate()'; "
              "END $do$") {}
};

/// A BEFORE INSERT / UPDATE / DELETE statement trigger on `table` (schema-qualified, a literal from
/// the caller's test) that raises, so every write to that table fails while every read, and every
/// other table, keeps working. `tag` names the trigger and its function (distinct tags let two
/// faults coexist in one database).
class WriteFault : public SqlFault {
public:
    WriteFault(yuzu::server::pg::PgPool& pool, const std::string& table, const std::string& tag)
        : SqlFault(
              pool,
              "DO $do$ BEGIN "
              "EXECUTE $f$CREATE FUNCTION public.yuzu_test_wf_" + tag +
                  "() RETURNS trigger LANGUAGE plpgsql AS $b$ BEGIN "
                  "RAISE EXCEPTION 'yuzu_test: write fault'; END $b$$f$; "
                  "EXECUTE 'CREATE TRIGGER yuzu_test_wf_" + tag +
                  " BEFORE INSERT OR UPDATE OR DELETE ON " + table +
                  " FOR EACH STATEMENT EXECUTE FUNCTION public.yuzu_test_wf_" + tag + "()'; "
                  "END $do$",
              "DO $do$ BEGIN "
              "EXECUTE 'DROP TRIGGER yuzu_test_wf_" + tag + " ON " + table + "'; "
              "EXECUTE 'DROP FUNCTION public.yuzu_test_wf_" + tag + "()'; "
              "END $do$") {}
};

} // namespace yuzu::test
