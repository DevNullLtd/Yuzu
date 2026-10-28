/**
 * test_echo_rename_migration_pg.cpp -- the Echo rename's Postgres data migrations (upgrade window).
 *
 * Ten stores each carry one new migration that rewrites stored references from the pre-rename
 * plugin name `tar` to `echo` (definition ids, plugin names, policy/workflow/response references,
 * enablement units, kill switches, result-set vocabulary). Each case seeds LEGACY rows by raw SQL,
 * rolls the store's schema_meta version back one step, constructs the store again so the migration
 * runs against those rows, and reads the result back. The legacy spellings below are the input the
 * migrations exist to rewrite, so they stay verbatim.
 *
 * Tagged [pg][echo][migration]: the shard filter that claims [pg][echo] places this file.
 */

#include "approval_manager.hpp"
#include "device_token_store.hpp"
#include "execution_tracker.hpp"
#include "instruction_store.hpp"
#include "key_provider.hpp"
#include "pg/pg_pool.hpp"
#include "pg/pg_raii.hpp"
#include "pg/secret_codec.hpp"
#include "plugin_config_store.hpp"
#include "policy_store.hpp"
#include "response_store.hpp"
#include "result_set_store.hpp"
#include "schedule_engine.hpp"
#include "workflow_engine.hpp"

#include "../test_helpers.hpp"

#include <catch2/catch_test_macros.hpp>

#include <libpq-fe.h>

#include <string>

using yuzu::server::pg::PgConn;
using yuzu::server::pg::PgPool;
using yuzu::server::pg::PgResult;

namespace {

// Run one or more statements on a fresh connection.
void exec_sql(const std::string& dsn, const std::string& sql) {
    PgConn conn{PQconnectdb(dsn.c_str())};
    REQUIRE(PQstatus(conn.get()) == CONNECTION_OK);
    PgResult r{PQexec(conn.get(), sql.c_str())};
    INFO(sql);
    INFO(PQresultErrorMessage(r.get()));
    REQUIRE(r.ok());
}

// First column of the first row ("<none>" when there is no row).
std::string one(const std::string& dsn, const std::string& sql) {
    PgConn conn{PQconnectdb(dsn.c_str())};
    REQUIRE(PQstatus(conn.get()) == CONNECTION_OK);
    PgResult r{PQexec(conn.get(), sql.c_str())};
    INFO(sql);
    INFO(PQresultErrorMessage(r.get()));
    REQUIRE(PQresultStatus(r.get()) == PGRES_TUPLES_OK);
    if (PQntuples(r.get()) == 0)
        return "<none>";
    if (PQgetisnull(r.get(), 0, 0))
        return "<null>";
    return PQgetvalue(r.get(), 0, 0);
}

// Roll one store's recorded schema version back so its newest migration runs again.
void roll_back(const std::string& dsn, const char* store, int to_version) {
    exec_sql(dsn, "UPDATE public.schema_meta SET version = " + std::to_string(to_version) +
                      " WHERE store = '" + store + "'");
}

std::string version_of(const std::string& dsn, const char* store) {
    return one(dsn, std::string("SELECT version FROM public.schema_meta WHERE store = '") + store +
                        "'");
}

} // namespace

TEST_CASE("Echo rename: instruction_store v3 rewrites ids, plugin, requiredPlugins and every "
          "YAML form; controls are untouched",
          "[pg][echo][migration][instruction_store]") {
    YUZU_REQUIRE_PG_MIGRATION_DB(db);
    {
        PgPool pool{{.conninfo = db.dsn(), .size = 2}};
        yuzu::server::InstructionStore store{pool};
        REQUIRE(store.is_open());
    }
    const std::string& dsn = db.dsn();

    // A builtin-shaped Echo definition: every free-text column carries the old vocabulary.
    exec_sql(dsn,
             "INSERT INTO instruction_store.instruction_definitions "
             "(id, name, type, plugin, description, required_plugins, yaml_source, "
             " parameter_schema, result_schema) VALUES "
             "('crossplatform.tar.query', 'TAR: SQL Query', 'question', 'tar', "
             " 'Reads the Timeline Activity Record (TAR) via tar.sql; see tar_state and TAR.', "
             " 'tar,other', "
             " E'apiVersion: yuzu.io/v1alpha1\\nspec:\\n  plugin: tar\\n  requiredPlugins: [tar]\\n"
             "  tags: [tar, warehouse]\\n  note: reads tar.db, response line tar|snapshot|complete', "
             " '{\"properties\":{\"q\":{\"description\":\"a tar.sql query\"}}}', "
             " '{\"columns\":[{\"name\":\"x\",\"description\":\"from tar_state\"}]}')");
    // An operator-authored definition of another plugin that still names the renamed plugin in
    // the three YAML forms (quoted scalar, flow list with quotes, block list) AND runs the
    // archive tool in a shell step, which must survive.
    exec_sql(dsn,
             "INSERT INTO instruction_store.instruction_definitions "
             "(id, name, type, plugin, required_plugins, yaml_source) VALUES "
             "('custom.quoted', 'Custom', 'question', 'other', 'other, tar', "
             " E'spec:\\n  plugin: \"tar\"\\n  requiredPlugins: [\"tar\", \"other\"]\\n"
             "  needs:\\n    - tar\\n    - other\\n  run: tar -czf out.tar.gz dir\\n"
             "  ref: crossplatform.tar.status')");
    // A control that never mentions the renamed plugin except as the archive tool.
    exec_sql(dsn,
             "INSERT INTO instruction_store.instruction_definitions "
             "(id, name, type, plugin, required_plugins, yaml_source) VALUES "
             "('control.archive', 'Archive', 'action', 'other', 'other', "
             " E'spec:\\n  plugin: other\\n  run: tar -xzf bundle.tar.gz\\n')");
    exec_sql(dsn, "INSERT INTO instruction_store.deleted_seed_content (kind, id, deleted_at) VALUES "
                  "('definition', 'crossplatform.tar.export', 1), ('definition', 'other.keep', 1)");

    roll_back(dsn, "instruction_store", 2);
    {
        PgPool pool{{.conninfo = db.dsn(), .size = 2}};
        yuzu::server::InstructionStore store{pool};
        REQUIRE(store.is_open());
    }
    CHECK(version_of(dsn, "instruction_store") == "3");

    const auto col = [&](const char* id, const char* column) {
        return one(dsn, std::string("SELECT ") + column +
                            " FROM instruction_store.instruction_definitions WHERE id = '" + id +
                            "'");
    };
    CHECK(one(dsn, "SELECT count(*) FROM instruction_store.instruction_definitions WHERE id = "
                   "'crossplatform.tar.query'") == "0");
    CHECK(col("crossplatform.echo.query", "plugin") == "echo");
    CHECK(col("crossplatform.echo.query", "name") == "Echo: SQL Query");
    CHECK(col("crossplatform.echo.query", "required_plugins") == "echo,other");
    CHECK(col("crossplatform.echo.query", "description") ==
          "Reads the Echo via echo.sql; see echo_state and Echo.");
    const auto yaml = col("crossplatform.echo.query", "yaml_source");
    CHECK(yaml.find("plugin: echo") != std::string::npos);
    CHECK(yaml.find("requiredPlugins: [echo]") != std::string::npos);
    CHECK(yaml.find("tags: [echo, warehouse]") != std::string::npos);
    CHECK(yaml.find("reads echo.db, response line echo|snapshot|complete") != std::string::npos);
    CHECK(yaml.find("tar") == std::string::npos);
    CHECK(col("crossplatform.echo.query", "parameter_schema").find("a echo.sql query") !=
          std::string::npos);
    CHECK(col("crossplatform.echo.query", "result_schema").find("from echo_state") !=
          std::string::npos);

    const auto custom = col("custom.quoted", "yaml_source");
    CHECK(custom.find("plugin: \"echo\"") != std::string::npos);
    CHECK(custom.find("requiredPlugins: [\"echo\", \"other\"]") != std::string::npos);
    CHECK(custom.find("    - echo\n    - other") != std::string::npos);
    CHECK(custom.find("ref: crossplatform.echo.status") != std::string::npos);
    CHECK(custom.find("run: tar -czf out.tar.gz dir") != std::string::npos); // archive tool kept
    CHECK(col("custom.quoted", "required_plugins") == "other,echo");

    CHECK(col("control.archive", "yaml_source") ==
          "spec:\n  plugin: other\n  run: tar -xzf bundle.tar.gz\n");
    CHECK(col("control.archive", "required_plugins") == "other");

    CHECK(one(dsn, "SELECT id FROM instruction_store.deleted_seed_content WHERE id LIKE "
                   "'crossplatform.%'") == "crossplatform.echo.export");
    CHECK(one(dsn, "SELECT count(*) FROM instruction_store.deleted_seed_content WHERE id = "
                   "'other.keep'") == "1");

    // Idempotent: constructing again (already at v3) changes nothing.
    const auto snapshot = [&] {
        return one(dsn, "SELECT string_agg(id || '|' || plugin || '|' || required_plugins || '|' || "
                        "md5(yaml_source), ',' ORDER BY id) FROM "
                        "instruction_store.instruction_definitions");
    };
    const auto before = snapshot();
    {
        PgPool pool{{.conninfo = db.dsn(), .size = 2}};
        yuzu::server::InstructionStore store{pool};
        REQUIRE(store.is_open());
    }
    CHECK(snapshot() == before);
}

TEST_CASE("Echo rename: definition-id references follow in schedules, executions, approvals, "
          "device tokens, workflows, policies and responses",
          "[pg][echo][migration][references]") {
    YUZU_REQUIRE_PG_MIGRATION_DB(db);
    const std::string& dsn = db.dsn();
    {
        PgPool pool{{.conninfo = dsn, .size = 4}};
        yuzu::server::ScheduleEngine schedules{pool};
        yuzu::server::ExecutionTracker tracker{pool};
        yuzu::server::ApprovalManager approvals{pool};
        yuzu::server::DeviceTokenStore tokens{pool};
        yuzu::server::PolicyStore policies{pool};
        yuzu::server::WorkflowEngine workflows{pool};
        yuzu::server::ResponseStore responses{pool};
        REQUIRE(schedules.is_open());
        REQUIRE(tracker.is_open());
        REQUIRE(approvals.is_open());
        REQUIRE(tokens.is_open());
        REQUIRE(policies.is_open());
        REQUIRE(workflows.is_open());
        REQUIRE(responses.is_open());
    }

    // One legacy row and one control per table.
    exec_sql(dsn, "INSERT INTO schedule_engine.schedules (id, name, definition_id) VALUES "
                  "('s1', 's', 'crossplatform.tar.query'), ('s2', 's', 'crossplatform.other.query')");
    exec_sql(dsn, "INSERT INTO execution_tracker.executions (id, definition_id) VALUES "
                  "('e1', 'crossplatform.tar.export'), ('e2', 'crossplatform.other.export')");
    exec_sql(dsn, "INSERT INTO execution_tracker.concurrency_claims (definition_id, agent_id, "
                  "execution_id, command_id, claimed_at, expires_at) VALUES "
                  "('crossplatform.tar.query', 'a1', 'e1', 'c1', 1, 2)");
    exec_sql(dsn, "INSERT INTO execution_tracker.command_execution (command_id, execution_id, "
                  "created_at, plugin) VALUES ('c1', 'e1', 1, 'tar'), ('c2', 'e2', 1, 'other')");
    exec_sql(dsn, "INSERT INTO approval_manager.approvals (id, definition_id, target_plugin) VALUES "
                  "('ap1', 'crossplatform.tar.query', 'tar'), ('ap2', 'crossplatform.x.q', 'other')");
    exec_sql(dsn, "INSERT INTO device_token_store.device_auth_tokens (token_id, token_hash, "
                  "principal_id, definition_id) VALUES "
                  "('t1', 'h1', 'p', 'crossplatform.tar.query'), ('t2', 'h2', 'p', 'crossplatform.o.q')");
    exec_sql(dsn, "INSERT INTO policy_store.policy_fragments (id, name, yaml_source, "
                  "check_instruction, fix_instruction, post_check_instruction) VALUES "
                  "('f1', 'f', 'check: crossplatform.tar.query', 'crossplatform.tar.query', "
                  " 'crossplatform.tar.export', 'crossplatform.tar.query'), "
                  "('f2', 'f', 'check: crossplatform.o.q', 'crossplatform.o.q', NULL, NULL)");
    exec_sql(dsn, "INSERT INTO workflow_engine.workflows (id, name, yaml_source) VALUES "
                  "('w1', 'w', 'step: crossplatform.tar.query'), ('w2', 'w', 'step: crossplatform.o.q')");
    exec_sql(dsn, "INSERT INTO workflow_engine.workflow_steps (workflow_id, step_index, "
                  "instruction_id) VALUES ('w1', 0, 'crossplatform.tar.query'), "
                  "('w2', 0, 'crossplatform.o.q')");
    exec_sql(dsn, "INSERT INTO workflow_engine.workflow_executions (id, workflow_id) VALUES "
                  "('we1', 'w1')");
    exec_sql(dsn, "INSERT INTO workflow_engine.workflow_step_results (execution_id, step_index, "
                  "instruction_id) VALUES ('we1', 0, 'crossplatform.tar.query')");
    const auto resp_id = one(dsn, "INSERT INTO response_store.responses (instruction_id, agent_id, "
                                  "timestamp, status, output) VALUES "
                                  "('crossplatform.tar.query', 'a1', 1, 0, 'x') RETURNING id");
    exec_sql(dsn, "INSERT INTO response_store.responses (instruction_id, agent_id, timestamp, "
                  "status, output) VALUES ('crossplatform.o.q', 'a1', 1, 0, 'x')");
    exec_sql(dsn, "INSERT INTO response_store.response_facets (response_id, instruction_id, "
                  "agent_id, col_idx, value) VALUES (" + resp_id +
                      ", 'crossplatform.tar.query', 'a1', 0, 'v')");

    roll_back(dsn, "schedule_engine", 1);
    roll_back(dsn, "execution_tracker", 7);
    roll_back(dsn, "approval_manager", 3);
    roll_back(dsn, "device_token_store", 1);
    roll_back(dsn, "policy_store", 4);
    roll_back(dsn, "workflow_engine", 1);
    roll_back(dsn, "response_store", 2);
    {
        PgPool pool{{.conninfo = dsn, .size = 4}};
        yuzu::server::ScheduleEngine schedules{pool};
        yuzu::server::ExecutionTracker tracker{pool};
        yuzu::server::ApprovalManager approvals{pool};
        yuzu::server::DeviceTokenStore tokens{pool};
        yuzu::server::PolicyStore policies{pool};
        yuzu::server::WorkflowEngine workflows{pool};
        yuzu::server::ResponseStore responses{pool};
        REQUIRE(schedules.is_open());
        REQUIRE(tracker.is_open());
        REQUIRE(approvals.is_open());
        REQUIRE(tokens.is_open());
        REQUIRE(policies.is_open());
        REQUIRE(workflows.is_open());
        REQUIRE(responses.is_open());
    }
    CHECK(version_of(dsn, "schedule_engine") == "2");
    CHECK(version_of(dsn, "execution_tracker") == "8");
    CHECK(version_of(dsn, "approval_manager") == "4");
    CHECK(version_of(dsn, "device_token_store") == "2");
    CHECK(version_of(dsn, "policy_store") == "5");
    CHECK(version_of(dsn, "workflow_engine") == "2");
    CHECK(version_of(dsn, "response_store") == "3");

    CHECK(one(dsn, "SELECT definition_id FROM schedule_engine.schedules WHERE id = 's1'") ==
          "crossplatform.echo.query");
    CHECK(one(dsn, "SELECT definition_id FROM schedule_engine.schedules WHERE id = 's2'") ==
          "crossplatform.other.query");
    CHECK(one(dsn, "SELECT definition_id FROM execution_tracker.executions WHERE id = 'e1'") ==
          "crossplatform.echo.export");
    CHECK(one(dsn, "SELECT definition_id FROM execution_tracker.executions WHERE id = 'e2'") ==
          "crossplatform.other.export");
    CHECK(one(dsn, "SELECT definition_id FROM execution_tracker.concurrency_claims") ==
          "crossplatform.echo.query");
    CHECK(one(dsn, "SELECT plugin FROM execution_tracker.command_execution WHERE command_id = "
                   "'c1'") == "echo");
    CHECK(one(dsn, "SELECT plugin FROM execution_tracker.command_execution WHERE command_id = "
                   "'c2'") == "other");
    CHECK(one(dsn, "SELECT definition_id || '/' || target_plugin FROM approval_manager.approvals "
                   "WHERE id = 'ap1'") == "crossplatform.echo.query/echo");
    CHECK(one(dsn, "SELECT definition_id || '/' || target_plugin FROM approval_manager.approvals "
                   "WHERE id = 'ap2'") == "crossplatform.x.q/other");
    CHECK(one(dsn, "SELECT definition_id FROM device_token_store.device_auth_tokens WHERE "
                   "token_id = 't1'") == "crossplatform.echo.query");
    CHECK(one(dsn, "SELECT definition_id FROM device_token_store.device_auth_tokens WHERE "
                   "token_id = 't2'") == "crossplatform.o.q");

    // Policy: all three instruction columns and the fragment source follow, so the evaluator's
    // get_definition lookup resolves the renamed ids.
    CHECK(one(dsn, "SELECT check_instruction || '|' || fix_instruction || '|' || "
                   "post_check_instruction || '|' || yaml_source FROM "
                   "policy_store.policy_fragments WHERE id = 'f1'") ==
          "crossplatform.echo.query|crossplatform.echo.export|crossplatform.echo.query|"
          "check: crossplatform.echo.query");
    CHECK(one(dsn, "SELECT check_instruction FROM policy_store.policy_fragments WHERE id = 'f2'") ==
          "crossplatform.o.q");
    CHECK(one(dsn, "SELECT coalesce(fix_instruction, 'NULL') FROM policy_store.policy_fragments "
                   "WHERE id = 'f2'") == "NULL");

    CHECK(one(dsn, "SELECT yaml_source FROM workflow_engine.workflows WHERE id = 'w1'") ==
          "step: crossplatform.echo.query");
    CHECK(one(dsn, "SELECT instruction_id FROM workflow_engine.workflow_steps WHERE workflow_id = "
                   "'w1'") == "crossplatform.echo.query");
    CHECK(one(dsn, "SELECT instruction_id FROM workflow_engine.workflow_steps WHERE workflow_id = "
                   "'w2'") == "crossplatform.o.q");
    CHECK(one(dsn, "SELECT instruction_id FROM workflow_engine.workflow_step_results") ==
          "crossplatform.echo.query");

    CHECK(one(dsn, "SELECT count(*) FROM response_store.responses WHERE instruction_id = "
                   "'crossplatform.echo.query'") == "1");
    CHECK(one(dsn, "SELECT count(*) FROM response_store.responses WHERE instruction_id LIKE "
                   "'crossplatform.tar.%'") == "0");
    CHECK(one(dsn, "SELECT count(*) FROM response_store.responses WHERE instruction_id = "
                   "'crossplatform.o.q'") == "1");
    CHECK(one(dsn, "SELECT instruction_id FROM response_store.response_facets") ==
          "crossplatform.echo.query");

    // Idempotent: a second construction (all stores already at the new version) changes nothing.
    const auto snap = [&] {
        return one(dsn, "SELECT (SELECT string_agg(definition_id, ',' ORDER BY id) FROM "
                        "schedule_engine.schedules) || '#' || (SELECT string_agg(instruction_id, "
                        "',' ORDER BY id) FROM response_store.responses)");
    };
    const auto before = snap();
    {
        PgPool pool{{.conninfo = dsn, .size = 4}};
        yuzu::server::ScheduleEngine schedules{pool};
        yuzu::server::ResponseStore responses{pool};
        REQUIRE(schedules.is_open());
        REQUIRE(responses.is_open());
    }
    CHECK(snap() == before);
}

TEST_CASE("Echo rename: plugin_config_store v4 moves configs, every kill-switch scope form and "
          "enablement units; secrets are left alone",
          "[pg][echo][migration][plugin_config_store]") {
    YUZU_REQUIRE_PG_MIGRATION_DB(db);
    const std::string& dsn = db.dsn();
    yuzu::test::TempDir keys{"yuzu_test_keys_"};
    yuzu::server::FileKeyProvider provider(keys.path);
    // A SecretCodec registers the store's secret column once, so each construction gets its own.
    {
        yuzu::server::pg::SecretCodec codec(provider);
        PgPool pool{{.conninfo = dsn, .size = 2}};
        yuzu::server::PluginConfigStore store{pool, codec};
        REQUIRE(store.is_open());
    }

    exec_sql(dsn, "INSERT INTO plugin_config_store.configs (plugin, key, value) VALUES "
                  "('tar', 'retention_days', '30'), ('other', 'retention_days', '5')");
    // The four scope forms kill_switch_scope_key builds, plus a control.
    exec_sql(dsn, "INSERT INTO plugin_config_store.kill_switches (scope_key, plugin, action, "
                  "enabled, os) VALUES "
                  "('tar', 'tar', '', false, ''), "
                  "('tar.query', 'tar', 'query', false, ''), "
                  "('tar@windows', 'tar', '', false, 'windows'), "
                  "('tar.query@linux', 'tar', 'query', false, 'linux'), "
                  "('other', 'other', '', false, '')");
    exec_sql(dsn, "INSERT INTO plugin_config_store.enablement_rules (id, units, selector, "
                  "provenance) VALUES "
                  "('r1', ARRAY['tar', 'tar.query', 'other.x'], 'all', 'operator'), "
                  "('r2', ARRAY['other.x'], 'all', 'operator')");
    exec_sql(dsn, "INSERT INTO plugin_config_store.secrets (scope_key, plugin, key, sealed_value) "
                  "VALUES ('tar.token', 'tar', 'token', '\\x0102'::bytea)");

    roll_back(dsn, "plugin_config_store", 3);
    {
        yuzu::server::pg::SecretCodec codec(provider);
        PgPool pool{{.conninfo = dsn, .size = 2}};
        yuzu::server::PluginConfigStore store{pool, codec};
        REQUIRE(store.is_open());

        CHECK(version_of(dsn, "plugin_config_store") == "4");
        CHECK(one(dsn, "SELECT string_agg(plugin || ':' || key, ',' ORDER BY plugin) FROM "
                       "plugin_config_store.configs") == "echo:retention_days,other:retention_days");
        CHECK(one(dsn, "SELECT string_agg(scope_key || '=' || plugin, ',' ORDER BY scope_key) "
                       "FROM plugin_config_store.kill_switches") ==
              "echo=echo,echo.query=echo,echo.query@linux=echo,echo@windows=echo,other=other");
        CHECK(one(dsn, "SELECT array_to_string(units, ',') FROM "
                       "plugin_config_store.enablement_rules WHERE id = 'r1'") ==
              "echo,echo.query,other.x");
        CHECK(one(dsn, "SELECT array_to_string(units, ',') FROM "
                       "plugin_config_store.enablement_rules WHERE id = 'r2'") == "other.x");
        // secrets: scope_key is the sealing AAD, so the row is exactly as it was.
        CHECK(one(dsn, "SELECT scope_key || '|' || plugin || '|' || encode(sealed_value, 'hex') "
                       "FROM plugin_config_store.secrets") == "tar.token|tar|0102");

        // The migrated per-OS row is the row a later write finds: set_kill_switch UPDATES it
        // rather than adding a twin.
        const auto set = store.set_kill_switch("echo", "", true, "re-enabled", "test", "windows");
        REQUIRE(set.has_value());
        CHECK(set->enabled);
        CHECK(one(dsn, "SELECT count(*) FROM plugin_config_store.kill_switches WHERE "
                       "plugin = 'echo' AND action = '' AND os = 'windows'") == "1");
        const auto off = store.set_kill_switch("echo", "", false, "again", "test", "windows");
        REQUIRE(off.has_value());
        CHECK_FALSE(off->enabled);
        CHECK(one(dsn, "SELECT count(*) FROM plugin_config_store.kill_switches WHERE "
                       "plugin = 'echo' AND os = 'windows'") == "1");
        const auto got = store.get_kill_switch("echo", "", "windows");
        REQUIRE(got.has_value());
        CHECK_FALSE(got->enabled);
    }

    // Idempotent: a further construction changes nothing.
    {
        yuzu::server::pg::SecretCodec codec(provider);
        PgPool pool{{.conninfo = dsn, .size = 2}};
        yuzu::server::PluginConfigStore store{pool, codec};
        REQUIRE(store.is_open());
        CHECK(one(dsn, "SELECT count(*) FROM plugin_config_store.kill_switches WHERE plugin = "
                       "'tar'") == "0");
    }
}

TEST_CASE("Echo rename: result_set_store v3 rewrites the source kind and matcher",
          "[pg][echo][migration][result_set]") {
    YUZU_REQUIRE_PG_MIGRATION_DB(db);
    const std::string& dsn = db.dsn();
    {
        PgPool pool{{.conninfo = dsn, .size = 2}};
        yuzu::server::ResultSetStore store{pool};
        REQUIRE(store.is_open());
    }
    exec_sql(dsn, "INSERT INTO result_set_store.result_sets (id, owner_principal, created_at, "
                  "ttl_at, last_used_at, source_kind, source_payload, matcher) VALUES "
                  "('rs_legacy1', 'p', 1, 2, 1, 'tar_query', '{}', "
                  " '{\"kind\":\"tar_rows_ge\",\"n\":1}'), "
                  "('rs_control1', 'p', 1, 2, 1, 'plugin_query', '{}', '{\"kind\":\"rows_ge\"}')");
    roll_back(dsn, "result_set_store", 2);
    {
        PgPool pool{{.conninfo = dsn, .size = 2}};
        yuzu::server::ResultSetStore store{pool};
        REQUIRE(store.is_open());
    }
    CHECK(version_of(dsn, "result_set_store") == "3");
    CHECK(one(dsn, "SELECT source_kind || '|' || matcher FROM result_set_store.result_sets WHERE "
                   "id = 'rs_legacy1'") == "echo_query|{\"kind\":\"echo_rows_ge\",\"n\":1}");
    CHECK(one(dsn, "SELECT source_kind || '|' || matcher FROM result_set_store.result_sets WHERE "
                   "id = 'rs_control1'") == "plugin_query|{\"kind\":\"rows_ge\"}");
}
