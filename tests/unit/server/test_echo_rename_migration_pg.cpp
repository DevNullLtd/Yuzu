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
 * Two cases hold the migrations to the contract rather than to the migration author's own list:
 * an instruction_store oracle (the migrated row equals the freshly seeded renamed row on every
 * column) and an enablement round trip (migrated units load clean and resolve through
 * EnablementStore, not just read back as text).
 *
 * Tagged [pg][echo][migration]: the shard filter that claims [pg][echo] places this file.
 */

#include "agent_registry.hpp" // detail::scope_kind_catalog
#include "approval_manager.hpp"
#include "bundled_content.hpp"
#include "capability_fragments.hpp"
#include "device_token_store.hpp"
#include "enablement_resolver.hpp"
#include "enablement_store.hpp"
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
#include <nlohmann/json.hpp>

#include <algorithm>
#include <stdexcept>
#include <string>
#include <string_view>
#include <vector>

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

// The PRE-rename `crossplatform.tar.query` envelope: what a pre-rename server's build embedded
// from content/definitions/tar.yaml at 78b82fcc5, produced by embed_content.py's def_envelope
// (re-indented for readability; JSON whitespace is not content). It is the INPUT the
// instruction_store v3 migration exists to rewrite, so the old spellings stay verbatim, and it is
// deliberately not derived from the renamed content: reversing the token chain on the new
// envelope would make the oracle below circular.
const std::string kPreRenameQueryEnvelope = R"OLD_ENVELOPE({
 "id": "crossplatform.tar.query",
 "name": "Query TAR Events",
 "version": "1.0.0",
 "type": "question",
 "plugin": "tar",
 "action": "query",
 "description": "Queries the TAR event database for system activity records within a time range. Events include process starts/stops, network connections opened/closed, service state changes, and user logins/logouts. Results are pipe-delimited: timestamp|event_type|event_action|snapshot_id|detail_json. The detail_json field contains a JSON object with type-specific fields:\nProcess events: {\"pid\":N, \"ppid\":N, \"name\":\"...\", \"cmdline\":\"...\", \"user\":\"...\"} Network events: {\"proto\":\"tcp\", \"local_addr\":\"...\", \"local_port\":N, \"remote_addr\":\"...\", \"remote_host\":\"...\", \"remote_port\":N, \"state\":\"...\", \"pid\":N} Service events: {\"name\":\"...\", \"display_name\":\"...\", \"status\":\"...\", \"startup_type\":\"...\"} User events: {\"user\":\"...\", \"domain\":\"...\", \"logon_type\":\"...\", \"session_id\":\"...\"}\n",
 "enabled": true,
 "platforms": "windows,linux,darwin",
 "approval_mode": "auto",
 "concurrency_mode": "per-device",
 "gather_ttl_seconds": 30,
 "yaml_source": "\napiVersion: yuzu.io/v1alpha1\nkind: InstructionDefinition\nmetadata:\n  id: crossplatform.tar.query\n  displayName: Query TAR Events\n  version: 1.0.0\n  description: >\n    Queries the TAR event database for system activity records within a\n    time range. Events include process starts/stops, network connections\n    opened/closed, service state changes, and user logins/logouts. Results\n    are pipe-delimited: timestamp|event_type|event_action|snapshot_id|detail_json.\n    The detail_json field contains a JSON object with type-specific fields:\n\n    Process events: {\"pid\":N, \"ppid\":N, \"name\":\"...\", \"cmdline\":\"...\", \"user\":\"...\"}\n    Network events: {\"proto\":\"tcp\", \"local_addr\":\"...\", \"local_port\":N, \"remote_addr\":\"...\", \"remote_host\":\"...\", \"remote_port\":N, \"state\":\"...\", \"pid\":N}\n    Service events: {\"name\":\"...\", \"display_name\":\"...\", \"status\":\"...\", \"startup_type\":\"...\"}\n    User events: {\"user\":\"...\", \"domain\":\"...\", \"logon_type\":\"...\", \"session_id\":\"...\"}\n  tags: [tar, timeline, query, forensics, compliance]\n\nspec:\n  type: question\n  platforms: [windows, linux, darwin]\n\n  execution:\n    plugin: tar\n    action: query\n    concurrency: per-device\n\n  parameters:\n    type: object\n    properties:\n      from:\n        type: string\n        displayName: Start Time\n        description: >\n          Start of the query time range as Unix epoch seconds.\n          Defaults to 0 (beginning of time).\n      to:\n        type: string\n        displayName: End Time\n        description: >\n          End of the query time range as Unix epoch seconds.\n          Defaults to the current time.\n      type:\n        type: string\n        displayName: Event Type Filter\n        description: >\n          Filter results by event type. Valid values: process, network,\n          service, user, software, arp, dns, mapdrive. software is part of the\n          default feed (see software_enabled); arp/dns/mapdrive are device-state\n          sources reached only by an explicit filter \u2014 they are excluded from the default\n          (empty-filter) feed. mapdrive (\u00a73.8) returns network-share mappings in\n          both directions, including historical (action='historical') rows. Leave\n          empty to return the core process/network/service/user/software types.\n        validation:\n          enum: [process, network, service, user, software, arp, dns, mapdrive, \"\"]\n      limit:\n        type: string\n        displayName: Result Limit\n        description: >\n          Maximum number of events to return. Default 1000, max 10000.\n        validation:\n          pattern: \"^[0-9]+$\"\n\n  result:\n    columns:\n      - name: timestamp\n        type: int64\n        description: Unix epoch seconds the event was recorded.\n        example: \"-\"\n        platforms: [windows, linux, darwin]\n      - name: event_type\n        type: string\n        description: 'Which capture source the row came from. Values: process, network, service, user, software, arp, dns, mapdrive.'\n        example: \"-\"\n        platforms: [windows, linux, darwin]\n      - name: event_action\n        type: string\n        description: 'The lifecycle verb for this event (e.g. started/stopped, appeared/removed, opened/closed); the vocabulary is source-specific. Values: free text, source-dependent verb.'\n        example: \"-\"\n        platforms: [windows, linux, darwin]\n      - name: snapshot_id\n        type: int64\n        description: 'Internal id of the collection cycle that produced this row, used to correlate rows from the same tick. Values: integer.'\n        example: \"-\"\n        platforms: [windows, linux, darwin]\n      - name: detail_json\n        type: clob\n        description: >-\n          JSON object with type-specific fields (see metadata.description for the per-type shape); empty string on the default (no type filter) union branches, which project only ts/event_type/action/snapshot_id. Values: JSON object, or empty string.\n        example: \"-\"\n        platforms: [windows, linux, darwin]\n\n  readablePayload: \"Query TAR events from ${from} to ${to} type=${type}\"\n\n  gather:\n    ttlSeconds: 30\n\n  approval:\n    mode: auto\n\n  permissions:\n    executeRoles: [endpoint-admin, endpoint-operator]\n    authorRoles: [content-author]\n\n  compatibility:\n    minAgentVersion: 0.1.0\n    requiredPlugins: [tar]\n\nstatus:\n  phase: active\n\n",
 "created_by": "system",
 "parameter_schema": "{\"type\": \"object\", \"properties\": {\"from\": {\"type\": \"string\", \"displayName\": \"Start Time\", \"description\": \"Start of the query time range as Unix epoch seconds. Defaults to 0 (beginning of time).\\n\"}, \"to\": {\"type\": \"string\", \"displayName\": \"End Time\", \"description\": \"End of the query time range as Unix epoch seconds. Defaults to the current time.\\n\"}, \"type\": {\"type\": \"string\", \"displayName\": \"Event Type Filter\", \"description\": \"Filter results by event type. Valid values: process, network, service, user, software, arp, dns, mapdrive. software is part of the default feed (see software_enabled); arp/dns/mapdrive are device-state sources reached only by an explicit filter \\u2014 they are excluded from the default (empty-filter) feed. mapdrive (\\u00a73.8) returns network-share mappings in both directions, including historical (action='historical') rows. Leave empty to return the core process/network/service/user/software types.\\n\", \"validation\": {\"enum\": [\"process\", \"network\", \"service\", \"user\", \"software\", \"arp\", \"dns\", \"mapdrive\", \"\"]}}, \"limit\": {\"type\": \"string\", \"displayName\": \"Result Limit\", \"description\": \"Maximum number of events to return. Default 1000, max 10000.\\n\", \"validation\": {\"pattern\": \"^[0-9]+$\"}}}}",
 "result_schema": "{\"columns\": [{\"name\": \"timestamp\", \"type\": \"int64\", \"description\": \"Unix epoch seconds the event was recorded.\", \"example\": \"-\", \"platforms\": [\"windows\", \"linux\", \"darwin\"]}, {\"name\": \"event_type\", \"type\": \"string\", \"description\": \"Which capture source the row came from. Values: process, network, service, user, software, arp, dns, mapdrive.\", \"example\": \"-\", \"platforms\": [\"windows\", \"linux\", \"darwin\"]}, {\"name\": \"event_action\", \"type\": \"string\", \"description\": \"The lifecycle verb for this event (e.g. started/stopped, appeared/removed, opened/closed); the vocabulary is source-specific. Values: free text, source-dependent verb.\", \"example\": \"-\", \"platforms\": [\"windows\", \"linux\", \"darwin\"]}, {\"name\": \"snapshot_id\", \"type\": \"int64\", \"description\": \"Internal id of the collection cycle that produced this row, used to correlate rows from the same tick. Values: integer.\", \"example\": \"-\", \"platforms\": [\"windows\", \"linux\", \"darwin\"]}, {\"name\": \"detail_json\", \"type\": \"clob\", \"description\": \"JSON object with type-specific fields (see metadata.description for the per-type shape); empty string on the default (no type filter) union branches, which project only ts/event_type/action/snapshot_id. Values: JSON object, or empty string.\", \"example\": \"-\", \"platforms\": [\"windows\", \"linux\", \"darwin\"]}]}",
 "readable_payload": "Query TAR events from ${from} to ${to} type=${type}"
})OLD_ENVELOPE";

// The shipped (post-rename) envelope for one definition id, exactly as the build embedded it.
std::string shipped_envelope(std::string_view id) {
    for (const auto& raw : yuzu::server::kBundledDefinitions) {
        const auto env = nlohmann::json::parse(raw, nullptr, false);
        if (!env.is_discarded() && env.value("id", std::string{}) == id)
            return raw;
    }
    return {};
}

std::vector<std::string> split_csv(const std::string& csv) {
    std::vector<std::string> out;
    for (std::size_t from = 0; from <= csv.size();) {
        const auto to = csv.find(',', from);
        out.push_back(csv.substr(from, to == std::string::npos ? std::string::npos : to - from));
        if (to == std::string::npos)
            break;
        from = to + 1;
    }
    return out;
}

// The overlay and selector kinds production builds (server.cpp), so a migrated rule is judged by
// the same loader and resolver a deployment runs.
yuzu::server::enablement::UnitOverlay make_overlay() {
    auto r = yuzu::server::enablement::build_unit_overlay({YUZU_ALL_CAPABILITY_FRAGMENTS},
                                                          yuzu::server::enablement::kProtectivePredicate);
    if (!r)
        throw std::runtime_error("overlay build failed: " + r.error());
    return std::move(*r);
}

const std::vector<std::string_view>& selector_kinds() {
    static const auto k = yuzu::server::enablement::durable_attribute_kinds(
        yuzu::server::detail::scope_kind_catalog());
    return k;
}

} // namespace

TEST_CASE("Echo rename: instruction_store v3 rewrites ids and plugin and requiredPlugins and "
          "every YAML form; controls are untouched",
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
    // A bare list item under an unrelated key is left as written (the block-list rule is scoped
    // to `requiredPlugins:` / `tags:`; see the dedicated case below).
    CHECK(custom.find("  needs:\n    - tar\n    - other") != std::string::npos);
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

TEST_CASE("Echo rename: instruction_store v3 scopes the block-list rule and tolerates CRLF "
          "and trailing comments",
          "[pg][echo][migration][instruction_store]") {
    YUZU_REQUIRE_PG_MIGRATION_DB(db);
    {
        PgPool pool{{.conninfo = db.dsn(), .size = 2}};
        yuzu::server::InstructionStore store{pool};
        REQUIRE(store.is_open());
    }
    const std::string& dsn = db.dsn();

    // CH-10: a bare `- tar` list item that is NOT a plugin reference (an archive-format enum, a
    // package list, a list under a key that merely follows requiredPlugins) must stay as written.
    exec_sql(dsn,
             "INSERT INTO instruction_store.instruction_definitions "
             "(id, name, type, plugin, required_plugins, yaml_source) VALUES "
             "('ops.enum', 'Enum', 'action', 'shell', 'shell', "
             " E'spec:\\n  plugin: shell\\n  parameters:\\n    format:\\n      validation:\\n"
             "        enum:\\n          - zip\\n          - tar\\n          - gz\\n"
             "  packages:\\n    - tar\\n'), "
             "('ops.after', 'After', 'action', 'shell', 'shell', "
             " E'spec:\\n  requiredPlugins:\\n    - shell\\n  steps:\\n    - tar\\n')");
    // The same shapes that ARE plugin references: block lists under requiredPlugins: and tags:,
    // with a blank line, a comment line and a trailing comment between and after the items.
    exec_sql(dsn,
             "INSERT INTO instruction_store.instruction_definitions "
             "(id, name, type, plugin, required_plugins, yaml_source) VALUES "
             "('ops.block', 'Block', 'question', 'other', 'other', "
             " E'spec:\\n  compatibility:\\n    requiredPlugins:\\n      - other\\n\\n"
             "      # the activity plugin\\n      - tar # first\\n  tags:\\n    - \"tar\"\\n    - ops\\n')");
    // CH-8: CRLF line endings (the ordinary dashboard-textarea case) and a trailing comment on a
    // `plugin:` line. The CR and the comment are preserved byte for byte.
    exec_sql(dsn,
             "INSERT INTO instruction_store.instruction_definitions "
             "(id, name, type, plugin, required_plugins, yaml_source) VALUES "
             "('ops.crlf', 'Crlf', 'question', 'other', 'other', "
             " E'spec:\\r\\n  plugin: tar   # activity plugin\\r\\n  requiredPlugins:\\r\\n"
             "    - tar # first\\r\\n    - other\\r\\n')");

    roll_back(dsn, "instruction_store", 2);
    {
        PgPool pool{{.conninfo = dsn, .size = 2}};
        yuzu::server::InstructionStore store{pool};
        REQUIRE(store.is_open());
    }
    CHECK(version_of(dsn, "instruction_store") == "3");

    const auto yaml = [&](const char* id) {
        return one(dsn, std::string("SELECT yaml_source FROM "
                                    "instruction_store.instruction_definitions WHERE id = '") +
                            id + "'");
    };
    // CH-10 controls: byte-identical.
    CHECK(yaml("ops.enum") == "spec:\n  plugin: shell\n  parameters:\n    format:\n      validation:\n"
                              "        enum:\n          - zip\n          - tar\n          - gz\n"
                              "  packages:\n    - tar\n");
    CHECK(yaml("ops.after") == "spec:\n  requiredPlugins:\n    - shell\n  steps:\n    - tar\n");
    // The scoped block lists are rewritten, comments and blank lines intact.
    CHECK(yaml("ops.block") ==
          "spec:\n  compatibility:\n    requiredPlugins:\n      - other\n\n"
          "      # the activity plugin\n      - echo # first\n  tags:\n    - \"echo\"\n    - ops\n");
    // CH-8: CRLF and trailing comments no longer defeat the line anchors.
    CHECK(yaml("ops.crlf") ==
          "spec:\r\n  plugin: echo   # activity plugin\r\n  requiredPlugins:\r\n"
          "    - echo # first\r\n    - other\r\n");
}

TEST_CASE("Echo rename: instruction_store v3 moves an operator Echo definition's plugin and "
          "YAML identity but leaves its prose and SQL literals alone",
          "[pg][echo][migration][instruction_store]") {
    YUZU_REQUIRE_PG_MIGRATION_DB(db);
    {
        PgPool pool{{.conninfo = db.dsn(), .size = 2}};
        yuzu::server::InstructionStore store{pool};
        REQUIRE(store.is_open());
    }
    const std::string& dsn = db.dsn();

    // Not a builtin (its id lacks the crossplatform.tar. prefix), but it runs the renamed plugin
    // and its prose and SQL name the archive tool `tar` as a process, which must stay as written.
    exec_sql(dsn, R"SQL(INSERT INTO instruction_store.instruction_definitions
        (id, name, type, plugin, description, required_plugins, yaml_source) VALUES
        ('ops.tar-hunt', 'Hunt', 'question', 'tar', 'Find tar processes', 'tar',
         E'spec:\n  plugin: tar\n  sql: SELECT pid FROM procs WHERE name = ''tar''\n'))SQL");

    roll_back(dsn, "instruction_store", 2);
    {
        PgPool pool{{.conninfo = dsn, .size = 2}};
        yuzu::server::InstructionStore store{pool};
        REQUIRE(store.is_open());
    }
    CHECK(version_of(dsn, "instruction_store") == "3");

    const auto col = [&](const char* column) {
        return one(dsn, std::string("SELECT ") + column +
                            " FROM instruction_store.instruction_definitions WHERE id = "
                            "'ops.tar-hunt'");
    };
    CHECK(col("plugin") == "echo");
    CHECK(col("required_plugins") == "echo");
    CHECK(col("yaml_source") ==
          "spec:\n  plugin: echo\n  sql: SELECT pid FROM procs WHERE name = 'tar'\n");
    CHECK(col("description") == "Find tar processes");
    CHECK(col("name") == "Hunt");
}

TEST_CASE("Echo rename: the migrated crossplatform.tar.query row equals the freshly seeded "
          "crossplatform.echo.query row on every column",
          "[pg][echo][migration][instruction_store]") {
    YUZU_REQUIRE_PG_MIGRATION_DB(db);
    const std::string& dsn = db.dsn();
    const std::string fresh = shipped_envelope("crossplatform.echo.query");
    REQUIRE_FALSE(fresh.empty());

    // Seed the pre-rename row through the real import path, then run v3 over it.
    {
        PgPool pool{{.conninfo = dsn, .size = 2}};
        yuzu::server::InstructionStore store{pool};
        REQUIRE(store.is_open());
        const auto old_id = store.import_definition_json_trusted(kPreRenameQueryEnvelope);
        REQUIRE(old_id.has_value());
        CHECK(*old_id == "crossplatform.tar.query");
    }
    roll_back(dsn, "instruction_store", 2);
    {
        PgPool pool{{.conninfo = dsn, .size = 2}};
        yuzu::server::InstructionStore store{pool};
        REQUIRE(store.is_open());
    }
    CHECK(version_of(dsn, "instruction_store") == "3");
    CHECK(one(dsn, "SELECT count(*) FROM instruction_store.instruction_definitions WHERE id = "
                   "'crossplatform.tar.query'") == "0");

    // Park the migrated row, then reseed the renamed content under the same id. A raw DELETE, not
    // delete_definition: that would stamp deleted_seed_content and the reseed would skip.
    exec_sql(dsn, "CREATE TABLE instruction_store.migrated_oracle AS SELECT * FROM "
                  "instruction_store.instruction_definitions WHERE id = 'crossplatform.echo.query'");
    REQUIRE(one(dsn, "SELECT count(*) FROM instruction_store.migrated_oracle") == "1");
    exec_sql(dsn, "DELETE FROM instruction_store.instruction_definitions WHERE id = "
                  "'crossplatform.echo.query'");
    {
        PgPool pool{{.conninfo = dsn, .size = 2}};
        yuzu::server::InstructionStore store{pool};
        REQUIRE(store.is_open());
        const auto new_id = store.import_definition_json_trusted(fresh);
        REQUIRE(new_id.has_value());
        CHECK(*new_id == "crossplatform.echo.query");
    }

    // Every column of the table, read from the catalogue so a column added later is compared
    // too. Only the three write-time stamps are exempt: they record when and by whom the row was
    // written, which is the migration's moment on one side and the reseed's on the other.
    const auto columns = split_csv(
        one(dsn, "SELECT string_agg(column_name, ',' ORDER BY ordinal_position) FROM "
                 "information_schema.columns WHERE table_schema = 'instruction_store' AND "
                 "table_name = 'instruction_definitions'"));
    const std::vector<std::string> stamps{"created_at", "updated_at", "created_by"};
    const auto differs = [&](const std::string& col) {
        return one(dsn, "SELECT count(*) FROM instruction_store.migrated_oracle m JOIN "
                        "instruction_store.instruction_definitions d USING (id) WHERE m." +
                            col + " IS DISTINCT FROM d." + col);
    };
    CHECK(one(dsn, "SELECT count(*) FROM instruction_store.migrated_oracle m JOIN "
                   "instruction_store.instruction_definitions d USING (id)") == "1");
    REQUIRE(columns.size() > stamps.size());
    std::size_t compared = 0;
    for (const auto& col : columns) {
        if (std::find(stamps.begin(), stamps.end(), col) != stamps.end())
            continue;
        ++compared;
        if (differs(col) != "0") {
            FAIL_CHECK("column " << col << " differs: migrated=["
                                 << one(dsn, "SELECT " + col + " FROM instruction_store.migrated_oracle")
                                 << "] reseeded=["
                                 << one(dsn, "SELECT " + col + " FROM instruction_store.instruction_definitions "
                                                "WHERE id = 'crossplatform.echo.query'")
                                 << "]");
        }
    }
    CHECK(compared == columns.size() - stamps.size()); // the stamps exist; nothing else was skipped

    // Positive control: the comparison does see a difference when one exists.
    exec_sql(dsn, "UPDATE instruction_store.migrated_oracle SET yaml_source = yaml_source || 'x'");
    CHECK(differs("yaml_source") == "1");
}

TEST_CASE("Echo rename: definition-id references follow in schedules and executions and "
          "approvals and device tokens and workflows and policies and responses",
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

TEST_CASE("Echo rename: plugin_config_store v4 moves configs and every kill-switch scope form "
          "and enablement units; secrets are left alone",
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
                  "('r1', ARRAY['tar', 'tar.query', 'other.x'], '__all__', 'operator'), "
                  "('r2', ARRAY['other.x'], '__all__', 'operator')");
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

        // The migrated units are judged by the consumer that classifies them, not only read back
        // as text: they load unquarantined, name nothing this release does not know except the
        // control unit, and switch the echo plugin and its query action off.
        yuzu::server::EnablementStore enablement{pool, make_overlay(), selector_kinds()};
        REQUIRE(enablement.is_open());
        auto loaded = enablement.load_rules();
        REQUIRE(loaded.has_value());
        CHECK(loaded->quarantined.empty());
        CHECK(loaded->rules.size() == 2);
        CHECK(loaded->unresolved_units == std::vector<std::string>{"other.x"});
        const auto resolved = yuzu::server::enablement::resolve(
            loaded->rules, enablement.overlay(), "windows",
            [](std::string_view) { return std::string{}; });
        REQUIRE(resolved.has_value());
        const auto is_off = [&](std::string_view unit) {
            return std::any_of(resolved->off.begin(), resolved->off.end(),
                               [&](const auto& o) { return o.unit == unit; });
        };
        CHECK(is_off("echo"));
        CHECK(is_off("echo.query"));
        CHECK(is_off("echo.fleet_snapshot")); // contained in the plugin unit r1 names

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
                  "('rs_legacy1', 'p', 1, 2, 1, 'tar_query', "
                  " '{\"instruction_id\":\"crossplatform.tar.query\"}', "
                  " '{\"kind\":\"tar_rows_ge\",\"n\":1}'), "
                  "('rs_control1', 'p', 1, 2, 1, 'plugin_query', "
                  " '{\"instruction_id\":\"crossplatform.o.q\"}', '{\"kind\":\"rows_ge\"}')");
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
    // CH-11: the payload carries the producing instruction id; a re-evaluation of a pre-rename
    // set resolves it only if the id follows the rename.
    CHECK(one(dsn, "SELECT source_payload FROM result_set_store.result_sets WHERE id = "
                   "'rs_legacy1'") == "{\"instruction_id\":\"crossplatform.echo.query\"}");
    CHECK(one(dsn, "SELECT source_payload FROM result_set_store.result_sets WHERE id = "
                   "'rs_control1'") == "{\"instruction_id\":\"crossplatform.o.q\"}");
}

// CH-5: the two steps that scan all-time history (response_store v3 and execution_tracker v8) lift
// the pool's per-lease statement_timeout for their own transaction. Without that, a multi-million
// row store runs past the 30 s cap, the step is cancelled (SQLSTATE 57014), the version rolls back
// and the store logs "disabled" and carries on: the server boots with response persistence and the
// execution tracker off. A BEFORE UPDATE trigger that sleeps per matching row makes each step
// outlast the 200 ms pool timeout deterministically, whatever the machine speed or data volume.
TEST_CASE("Echo rename: the history scans of response_store v3 and execution_tracker v8 outlast a "
          "200 ms statement timeout",
          "[pg][echo][migration][chaos][statement_timeout]") {
    YUZU_REQUIRE_PG_MIGRATION_DB(db);
    const std::string& dsn = db.dsn();
    {
        PgPool pool{{.conninfo = dsn, .size = 2}};
        yuzu::server::ResponseStore responses{pool};
        yuzu::server::ExecutionTracker tracker{pool};
        REQUIRE(responses.is_open());
        REQUIRE(tracker.is_open());
    }
    exec_sql(dsn, "INSERT INTO response_store.responses (instruction_id, agent_id, timestamp, status, "
                  "output, plugin) VALUES ('crossplatform.tar.query', 'a1', 1, 0, 'x', 'tar')");
    exec_sql(dsn, "INSERT INTO execution_tracker.executions (id, definition_id) VALUES "
                  "('e1', 'crossplatform.tar.export')");
    exec_sql(dsn, R"SQL(
        CREATE FUNCTION public.yuzu_test_slow_row() RETURNS trigger LANGUAGE plpgsql AS
            $$ BEGIN PERFORM pg_sleep(0.5); RETURN NEW; END $$;
        CREATE TRIGGER yuzu_test_slow BEFORE UPDATE ON response_store.responses
            FOR EACH ROW WHEN (OLD.instruction_id LIKE 'crossplatform.tar.%')
            EXECUTE FUNCTION public.yuzu_test_slow_row();
        CREATE TRIGGER yuzu_test_slow BEFORE UPDATE ON execution_tracker.executions
            FOR EACH ROW WHEN (OLD.definition_id LIKE 'crossplatform.tar.%')
            EXECUTE FUNCTION public.yuzu_test_slow_row();)SQL");

    PgPool pool{{.conninfo = dsn, .size = 2, .statement_timeout_ms = 200}};

    // Positive control: under this pool an UPDATE of the same shape IS cancelled with 57014, so a
    // green run below means the migrations lifted the timeout, not that nothing was slow.
    {
        auto lease = pool.acquire();
        REQUIRE(lease);
        PgResult r{PQexec(lease.get(), "UPDATE response_store.responses SET plugin = plugin WHERE "
                                       "instruction_id LIKE 'crossplatform.tar.%'")};
        REQUIRE(PQresultStatus(r.get()) == PGRES_FATAL_ERROR);
        const char* state = PQresultErrorField(r.get(), PG_DIAG_SQLSTATE);
        REQUIRE(state != nullptr);
        CHECK(std::string_view{state} == "57014");
    }

    roll_back(dsn, "response_store", 2);
    roll_back(dsn, "execution_tracker", 7);
    yuzu::server::ResponseStore responses{pool};
    yuzu::server::ExecutionTracker tracker{pool};
    REQUIRE(responses.is_open());
    REQUIRE(tracker.is_open());
    CHECK(version_of(dsn, "response_store") == "3");
    CHECK(version_of(dsn, "execution_tracker") == "8");
    CHECK(one(dsn, "SELECT instruction_id || '/' || plugin FROM response_store.responses") ==
          "crossplatform.echo.query/echo");
    CHECK(one(dsn, "SELECT definition_id FROM execution_tracker.executions WHERE id = 'e1'") ==
          "crossplatform.echo.export");
}
