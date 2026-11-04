// test_rest_software_curation.cpp - HTTP-level tests for the software normalisation curation
// routes (SoftwareCurationRoutes) and the pure key/cursor codecs.
//
// The unit cases run over a CLOSED ProductRegistryStore (a pool on a garbage conninfo never
// opens the store), which proves everything that happens before or around the store: the gates,
// request validation, audit-before-write and fail-closed, and the 503 mapping of a store that
// cannot answer. The [pg] cases at the bottom drive the same routes over a live store.

#include "list_keyset.hpp"
#include "openapi_spec_access.hpp"
#include "pg/pg_exec.hpp"
#include "pg/pg_pool.hpp"
#include "pg/pg_raii.hpp"
#include "product_registry_store.hpp"
#include "software_curation_routes.hpp"
#include "software_normalization_pack.hpp"
#include "test_route_sink.hpp"

#include <yuzu/server/auth.hpp>

#include <catch2/catch_test_macros.hpp>

#include <httplib.h>
#include <libpq-fe.h>
#include <nlohmann/json.hpp>

#include "../test_helpers.hpp"

#include <memory>
#include <optional>
#include <stdexcept>
#include <string>
#include <vector>

using namespace yuzu::server;
using yuzu::server::pg::PgPool;
using nlohmann::json;
namespace pg = yuzu::server::pg;

namespace {

const std::string kBase = "/api/v1/inventory/software/normalization";

struct AuditRow {
    std::string action, result, target_id, detail;
};

struct Harness {
    bool authed{true};
    bool service_scoped{false};
    bool perm_ok{true};
    bool audit_ok{true};
    std::vector<AuditRow> audits;
    std::vector<std::string> perms; ///< "Type:Op" asked of perm_fn
    SoftwareCurationRoutes routes;
    yuzu::server::test::TestRouteSink sink;

    explicit Harness(ProductRegistryStore* registry) {
        SoftwareCurationRoutes::Deps d;
        d.auth_fn = [this](const httplib::Request&,
                           httplib::Response& res) -> std::optional<auth::Session> {
            if (!authed) {
                res.status = 401;
                res.set_content(R"({"error":"unauthenticated"})", "application/json");
                return std::nullopt;
            }
            auth::Session s;
            s.username = "operator";
            if (service_scoped)
                s.token_scope_service = "svc";
            return s;
        };
        d.perm_fn = [this](const httplib::Request&, httplib::Response& res, const std::string& t,
                           const std::string& op) {
            perms.push_back(t + ":" + op);
            if (perm_ok)
                return true;
            res.status = 403;
            res.set_content(R"({"error":"forbidden"})", "application/json");
            return false;
        };
        d.audit_fn = [this](const httplib::Request&, const std::string& action,
                            const std::string& result, const std::string&,
                            const std::string& target_id, const std::string& detail) {
            audits.push_back({action, result, target_id, detail});
            return audit_ok;
        };
        d.registry = registry;
        routes.register_routes(sink, std::move(d));
    }
};

// A pool on an unusable conninfo: the store constructs closed and every call degrades.
struct ClosedStore {
    PgPool pool{{.conninfo = "=quohth4eeQu5 garbage =", .size = 1}};
    ProductRegistryStore store{pool};
    ClosedStore() { REQUIRE_FALSE(store.is_open()); }
};

std::string alias_body(const json& over = json::object()) {
    json b = {{"ecosystem", "windows"},
              {"raw_name", "Contoso Studio Standard"},
              {"raw_publisher", "Contoso Ltd"},
              {"vendor", "Contoso"},
              {"product", "Studio"},
              {"category", "other"}};
    b.update(over);
    return b.dump();
}

std::string key_for(const std::string& n, const std::string& p, const std::string& e) {
    return *curation_keys::encode_key({n, p, e});
}

} // namespace

// ── codecs ────────────────────────────────────────────────────────────────────────────────

TEST_CASE("curation key round-trips and refuses anything encode_key could not produce",
          "[software_curation][rest]") {
    const auto k = curation_keys::encode_key({"Name With Space", "Pub", "windows"});
    REQUIRE(k.has_value());
    const auto back = curation_keys::decode_key(*k);
    REQUIRE(back.has_value());
    CHECK(back->raw_name == "Name With Space");
    CHECK(back->raw_publisher == "Pub");
    CHECK(back->ecosystem == "windows");

    CHECK(curation_keys::decode_key(key_for("a", "", "rpm")).has_value()); // empty publisher ok
    CHECK_FALSE(curation_keys::encode_key({"a\x1F" "b", "", "rpm"}).has_value());
    CHECK_FALSE(curation_keys::decode_key("").has_value());
    CHECK_FALSE(curation_keys::decode_key("not base64!").has_value());
    CHECK_FALSE(curation_keys::decode_key("YQ==").has_value());      // padding is not canonical
    CHECK_FALSE(curation_keys::decode_key(key_for("", "p", "rpm")).has_value()); // empty name
    CHECK_FALSE(curation_keys::decode_key(key_for("a", "p", "")).has_value());   // empty ecosystem
    // Two fields only, and four fields.
    CHECK_FALSE(curation_keys::decode_key(keyset::b64url_encode("a\x1F" "b")).has_value());
    CHECK_FALSE(
        curation_keys::decode_key(keyset::b64url_encode("a\x1F" "b\x1F" "c\x1F" "d")).has_value());
    // Over the decoded bound.
    CHECK_FALSE(curation_keys::decode_key(
                    key_for(std::string(curation_keys::kMaxKeyBytes, 'x'), "p", "rpm"))
                    .has_value());
}

TEST_CASE("a maximal listed queue key (2400-byte triple) still decodes", "[software_curation][rest]") {
    // The queue admits triples whose fields sum to 2400 bytes; the key adds two separators.
    const std::string name(1000, 'n'), pub(1000, 'p'), eco(400, 'e');
    const auto k = curation_keys::encode_key({name, pub, eco});
    REQUIRE(k.has_value());
    const auto back = curation_keys::decode_key(*k);
    REQUIRE(back.has_value());
    CHECK(back->raw_name == name);
    CHECK(back->ecosystem == eco);
    // One byte more is refused.
    CHECK_FALSE(curation_keys::decode_key(key_for(name + "x", pub, eco)).has_value());

    ClosedStore cs;
    Harness h{&cs.store};
    const auto res = h.sink.Post(kBase + "/queue/" + *k + "/reject", "");
    CHECK(res->status == 503); // past the codec, to the (closed) store; not a 400
    CHECK(h.audits.size() == 1);
}

TEST_CASE("keys and cursors carrying a NUL byte or invalid UTF-8 are refused",
          "[software_curation][rest]") {
    using keyset::b64url_encode;
    const std::string nul("a\0b", 3);
    CHECK_FALSE(curation_keys::decode_key(b64url_encode(nul + "\x1F" "p\x1F" "rpm")).has_value());
    CHECK_FALSE(curation_keys::decode_key(b64url_encode("n\x1F" + nul + "\x1F" "rpm")).has_value());
    CHECK_FALSE(curation_keys::decode_key(b64url_encode("\xC3\x28\x1F" "p\x1F" "rpm")).has_value());
    CHECK_FALSE(curation_keys::decode_key(b64url_encode("\xED\xA0\x80\x1F" "p\x1F" "rpm")).has_value());
    CHECK_FALSE(curation_keys::decode_cursor(b64url_encode("3\x1F" + nul + "\x1F\x1F" "rpm")).has_value());
    CHECK_FALSE(curation_keys::decode_cursor(b64url_encode("3\x1F\xFF\x1F\x1F" "rpm")).has_value());
    CHECK(curation_keys::decode_key(b64url_encode("caf\xC3\xA9\x1F" "p\x1F" "rpm")).has_value());

    CHECK(valid_utf8("plain \xE2\x82\xAC \xF0\x9F\x98\x80"));
    CHECK_FALSE(valid_utf8("\xC0\x80"));     // overlong
    CHECK_FALSE(valid_utf8("\xE2\x82"));     // truncated
    CHECK_FALSE(valid_utf8("\xF4\x90\x80\x80")); // above U+10FFFF

    ClosedStore cs;
    Harness h{&cs.store};
    const auto bad = h.sink.Post(
        kBase + "/queue/" + b64url_encode(nul + "\x1F" "p\x1F" "rpm") + "/reject", "");
    CHECK(bad->status == 400);
    CHECK(h.sink.Post(kBase + "/pack", "#pack_version: 2026.11.1\n\xFF\n", "text/csv")->status == 400);
}

TEST_CASE("curation cursor round-trips and refuses a forged token", "[software_curation][rest]") {
    const CurationCursor c{true, 42, "name", "pub", "deb"};
    const auto tok = curation_keys::encode_cursor(c);
    REQUIRE(tok.has_value());
    const auto back = curation_keys::decode_cursor(*tok);
    REQUIRE(back.has_value());
    CHECK(back->device_count == 42);
    CHECK(back->raw_name == "name");
    CHECK(back->raw_publisher == "pub");
    CHECK(back->ecosystem == "deb");
    CHECK_FALSE(curation_keys::decode_cursor("").has_value());
    CHECK_FALSE(curation_keys::decode_cursor("AAAA").has_value());
    CHECK_FALSE(curation_keys::decode_cursor(keyset::b64url_encode("-1\x1F" "a\x1F\x1F" "rpm"))
                    .has_value()); // negative count
    CHECK_FALSE(curation_keys::decode_cursor(keyset::b64url_encode("x\x1F" "a\x1F\x1F" "rpm"))
                    .has_value()); // non-numeric count
}

// ── gates ─────────────────────────────────────────────────────────────────────────────────

TEST_CASE("every curation route refuses an unauthenticated caller, a service-scoped token and a "
          "denied permission, and writes nothing",
          "[software_curation][rest]") {
    ClosedStore cs;
    Harness h{&cs.store};
    const std::string key = key_for("a", "", "rpm");
    const std::vector<std::pair<std::string, std::string>> routes = {
        {"GET", kBase + "/status"},
        {"GET", kBase + "/queue"},
        {"POST", kBase + "/aliases"},
        {"POST", kBase + "/queue/" + key + "/reject"},
        {"POST", kBase + "/pack"}};
    auto call = [&](const std::pair<std::string, std::string>& r) {
        return r.first == "GET" ? h.sink.Get(r.second)
                                : h.sink.Post(r.second, alias_body(), "text/csv");
    };
    SECTION("401") {
        h.authed = false;
        for (const auto& r : routes) {
            INFO(r.second);
            REQUIRE(call(r)->status == 401);
        }
        CHECK(h.audits.empty());
    }
    SECTION("service-scoped token: 403 before the permission is even asked, audited denied") {
        h.service_scoped = true;
        for (const auto& r : routes) {
            INFO(r.second);
            const auto res = call(r);
            REQUIRE(res->status == 403);
            CHECK(json::parse(res->body)["error"]["permission"].is_null());
        }
        CHECK(h.perms.empty());
        // One `denied` row per refusal, under the route's own verb (the reads' verbs appear
        // only here), on the fleet target, and never a `requested` row.
        const std::vector<std::string> verbs = {
            "inventory.software.curation.status", "inventory.software.curation.queue",
            "inventory.software.curation.alias", "inventory.software.curation.reject",
            "inventory.software.curation.pack"};
        REQUIRE(h.audits.size() == verbs.size());
        for (std::size_t i = 0; i < verbs.size(); ++i) {
            INFO(verbs[i]);
            CHECK(h.audits[i].action == verbs[i]);
            CHECK(h.audits[i].result == "denied");
            CHECK(h.audits[i].target_id == "fleet");
        }
    }
    SECTION("permission denied (a confined caller fails the global gate)") {
        h.perm_ok = false;
        for (const auto& r : routes) {
            INFO(r.second);
            REQUIRE(call(r)->status == 403);
        }
        // The permission gate audits its own refusals (auth.permission_required); this
        // handler does not double-write.
        CHECK(h.audits.empty());
    }
}

TEST_CASE("reads ask Inventory:Read and writes ask Inventory:Write, globally",
          "[software_curation][rest]") {
    ClosedStore cs;
    Harness h{&cs.store};
    (void)h.sink.Get(kBase + "/status");
    (void)h.sink.Post(kBase + "/aliases", alias_body());
    REQUIRE(h.perms.size() == 2);
    CHECK(h.perms[0] == "Inventory:Read");
    CHECK(h.perms[1] == "Inventory:Write");
}

TEST_CASE("a null registry is a 503 with the A4 envelope", "[software_curation][rest]") {
    Harness h{nullptr};
    const auto res = h.sink.Get(kBase + "/status");
    REQUIRE(res->status == 503);
    const auto b = json::parse(res->body)["error"];
    CHECK(b["code"] == 503);
    CHECK(b.contains("correlation_id"));
    CHECK(res->has_header("X-Correlation-Id"));
}

// ── reads ─────────────────────────────────────────────────────────────────────────────────

TEST_CASE("a store that cannot answer is a 503 with retry_after_ms, never an empty 200",
          "[software_curation][rest]") {
    ClosedStore cs;
    Harness h{&cs.store};
    for (const auto& path : {kBase + "/status", kBase + "/queue"}) {
        INFO(path);
        const auto res = h.sink.Get(path);
        REQUIRE(res->status == 503);
        CHECK(json::parse(res->body)["error"]["retry_after_ms"] == 5000);
    }
    CHECK(h.audits.empty()); // an admitted read is never audited
}

TEST_CASE("queue query parameters: bad status, limit, cursor and repeats are 400",
          "[software_curation][rest]") {
    ClosedStore cs;
    Harness h{&cs.store};
    for (const auto& q : {"?status=bogus", "?limit=0", "?limit=501", "?limit=abc", "?limit=-1",
                          "?cursor=!!!", "?status=open&status=rejected", "?limit=1&limit=2"}) {
        INFO(q);
        REQUIRE(h.sink.Get(kBase + "/queue" + q)->status == 400);
    }
    // Valid parameters get past validation (and meet the closed store).
    for (const auto& q : {"?status=all", "?status=rejected&limit=500", ""}) {
        INFO(q);
        REQUIRE(h.sink.Get(kBase + "/queue" + q)->status == 503);
    }
    const auto tok = *curation_keys::encode_cursor({true, 3, "n", "", "rpm"});
    CHECK(h.sink.Get(kBase + "/queue?cursor=" + tok)->status == 503);
}

// ── aliases ───────────────────────────────────────────────────────────────────────────────

TEST_CASE("POST aliases validates every field before auditing or writing",
          "[software_curation][rest]") {
    ClosedStore cs;
    Harness h{&cs.store};
    const std::string big(257, 'x');
    const std::vector<std::string> bad = {
        "not json",
        "[]",
        alias_body({{"ecosystem", "plan9"}}),
        alias_body({{"ecosystem", 5}}),
        alias_body({{"ecosystem", nullptr}}),
        alias_body({{"raw_name", ""}}),
        alias_body({{"raw_name", big}}),
        alias_body({{"vendor", big}}),
        alias_body({{"product", std::string("a\0b", 3)}}),
        alias_body({{"category", "gadget"}}),
        alias_body({{"cpe_product", "Has Space"}}),
        alias_body({{"cpe_product", "-"}}),
        alias_body({{"edition", "notanedition"}}),
        alias_body({{"raw_name", "Contoso Studio Standard"}, {"edition", "enterprise"}}),
        alias_body({{"vendor", "inc"}}), // normalises to nothing
    };
    for (const auto& b : bad) {
        INFO(b.substr(0, 60));
        const auto res = h.sink.Post(kBase + "/aliases", b);
        REQUIRE(res->status == 400);
        CHECK(json::parse(res->body)["error"]["code"] == 400);
    }
    // Refusals are audited as denied, never as requested.
    REQUIRE_FALSE(h.audits.empty());
    for (const auto& a : h.audits) {
        CHECK(a.action == "inventory.software.curation.alias");
        CHECK(a.result == "denied");
    }
}

TEST_CASE("POST aliases audits BEFORE the write and fails closed when the audit cannot be stored",
          "[software_curation][rest]") {
    ClosedStore cs;
    Harness h{&cs.store};
    SECTION("audit stored, then the store (closed here) fails the write: 503") {
        const auto res = h.sink.Post(kBase + "/aliases", alias_body());
        REQUIRE(res->status == 503);
        REQUIRE(h.audits.size() == 1);
        CHECK(h.audits[0].action == "inventory.software.curation.alias");
        CHECK(h.audits[0].result == "requested");
        CHECK(h.audits[0].target_id == "contoso:studio:standard");
        CHECK_FALSE(res->has_header("Sec-Audit-Failed"));
    }
    SECTION("audit persist failure: 503 + Sec-Audit-Failed, and the write is not attempted") {
        h.audit_ok = false;
        const auto res = h.sink.Post(kBase + "/aliases", alias_body());
        REQUIRE(res->status == 503);
        CHECK(res->get_header_value("Sec-Audit-Failed") == "true");
        const auto msg = json::parse(res->body)["error"]["message"].get<std::string>();
        CHECK(msg.find("audit") != std::string::npos);
        // The store's own failure message never appears: its write was not attempted.
        CHECK(msg.find("curation write failed") == std::string::npos);
    }
}

TEST_CASE("POST aliases accepts an omitted category and neutralises the audit detail",
          "[software_curation][rest]") {
    ClosedStore cs;
    Harness h{&cs.store};
    json b = json::parse(alias_body());
    b.erase("category");
    // No category is valid: it reaches the audit row and the (closed) store, never a 400.
    const auto ok = h.sink.Post(kBase + "/aliases", b.dump());
    CHECK(ok->status == 503);
    REQUIRE(h.audits.size() == 1);
    CHECK(h.audits[0].result == "requested");

    h.audits.clear();
    json evil = json::parse(alias_body());
    evil["raw_publisher"] = "Contoso\nresult=success cid=FORGED";
    evil["raw_name"] = "Contoso Studio\ncid=FORGED Standard";
    h.sink.Post(kBase + "/aliases", evil.dump());
    REQUIRE(h.audits.size() == 1);
    const auto& d = h.audits[0].detail;
    CHECK(d.find('\n') == std::string::npos);
    CHECK(d.find("cid=FORGED") == std::string::npos);
    CHECK(d.find("cid=") == d.rfind("cid=")); // only the server's own cid=
}

// ── reject ────────────────────────────────────────────────────────────────────────────────

TEST_CASE("POST reject: a malformed key is a 400; a valid key audits then meets the store",
          "[software_curation][rest]") {
    ClosedStore cs;
    Harness h{&cs.store};
    for (const std::string k : {std::string{"AAAA"}, std::string{"YQ"},
                                keyset::b64url_encode("a\x1F" "b"), key_for("", "p", "rpm")}) {
        INFO(k);
        REQUIRE(h.sink.Post(kBase + "/queue/" + k + "/reject", "")->status == 400);
    }
    h.audits.clear();
    const auto res = h.sink.Post(kBase + "/queue/" + key_for("n", "", "rpm") + "/reject", "");
    REQUIRE(res->status == 503); // closed store: a store error, not a 404
    REQUIRE(h.audits.size() == 1);
    CHECK(h.audits[0].action == "inventory.software.curation.reject");
    CHECK(h.audits[0].result == "requested");

    h.audit_ok = false;
    const auto failed = h.sink.Post(kBase + "/queue/" + key_for("n", "", "rpm") + "/reject", "");
    CHECK(failed->status == 503);
    CHECK(failed->get_header_value("Sec-Audit-Failed") == "true");
}

TEST_CASE("POST reject neutralises caller-controlled key fields in the audit row",
          "[software_curation][rest]") {
    ClosedStore cs;
    Harness h{&cs.store};
    const auto k = key_for("evil\nname cid=FORGED", "pub\r\nresult=success", "rpm\ncid=FORGED2");
    h.sink.Post(kBase + "/queue/" + k + "/reject", "");
    REQUIRE(h.audits.size() == 1);
    for (const auto& s : {h.audits[0].detail, h.audits[0].target_id}) {
        CHECK(s.find('\n') == std::string::npos);
        CHECK(s.find('\r') == std::string::npos);
    }
    CHECK(h.audits[0].detail.find("cid=") == h.audits[0].detail.rfind("cid="));
    CHECK(h.audits[0].detail.find("cid=FORGED") == std::string::npos);
}

// ── pack ──────────────────────────────────────────────────────────────────────────────────

TEST_CASE("POST pack: content type, parser refusal reason, and fail-closed audit",
          "[software_curation][rest]") {
    ClosedStore cs;
    Harness h{&cs.store};
    CHECK(h.sink.Post(kBase + "/pack", "x", "application/json")->status == 415);
    // The media type is matched whole, case-insensitively, parameters ignored.
    CHECK(h.sink.Post(kBase + "/pack", "x", "text/csvx")->status == 415);
    CHECK(h.sink.Post(kBase + "/pack", "x", "text/csv-evil; charset=utf-8")->status == 415);
    CHECK(h.sink.Post(kBase + "/pack", "x", "xtext/plain")->status == 415);
    // Past the type gate, the parser refuses the body.
    CHECK(h.sink.Post(kBase + "/pack", "x", "Text/CSV")->status == 400);
    CHECK(h.sink.Post(kBase + "/pack", "x", "TEXT/PLAIN ; charset=utf-8")->status == 400);

    const auto refused = h.sink.Post(kBase + "/pack", "#pack_version: 2026.11.1\n", "text/csv");
    REQUIRE(refused->status == 400);
    CHECK(json::parse(refused->body)["error"]["message"].get<std::string>().find("kMinSeedRows") !=
          std::string::npos);
    CHECK(h.sink.Post(kBase + "/pack", std::string("a\0b", 3), "text/plain")->status == 400);
    CHECK(h.sink.Post(kBase + "/pack", std::string(kMaxPackBytes + 1, 'x'), "text/csv")->status ==
          400);

    // A valid pack reaches the audit row, then the (closed) store: 503, one 'requested' row.
    h.audits.clear();
    const std::string csv{kSoftwareNormalizationSeed};
    const auto res = h.sink.Post(kBase + "/pack", csv, "text/csv; charset=utf-8");
    REQUIRE(res->status == 503);
    REQUIRE(h.audits.size() == 1);
    CHECK(h.audits[0].action == "inventory.software.curation.pack");
    CHECK(h.audits[0].result == "requested");
    CHECK(h.audits[0].detail.find("rows=") != std::string::npos);

    h.audit_ok = false;
    const auto failed = h.sink.Post(kBase + "/pack", csv, "text/csv");
    CHECK(failed->status == 503);
    CHECK(failed->get_header_value("Sec-Audit-Failed") == "true");
}

// ── OpenAPI ───────────────────────────────────────────────────────────────────────────────

TEST_CASE("every curation route is documented in openapi.json with its pinned operationId",
          "[software_curation][rest][openapi]") {
    const auto spec = json::parse(openapi_spec_json());
    const auto& paths = spec.at("paths");
    struct Pin {
        const char* path;
        const char* method;
        const char* id;
    };
    const Pin pins[] = {
        {"/inventory/software/normalization/status", "get",
         "getInventorySoftwareNormalizationStatus"},
        {"/inventory/software/normalization/queue", "get",
         "getInventorySoftwareNormalizationQueue"},
        {"/inventory/software/normalization/aliases", "post",
         "postInventorySoftwareNormalizationAliases"},
        {"/inventory/software/normalization/queue/{key}/reject", "post",
         "postInventorySoftwareNormalizationQueueByKeyReject"},
        {"/inventory/software/normalization/pack", "post",
         "postInventorySoftwareNormalizationPack"},
    };
    for (const auto& p : pins) {
        INFO(p.path);
        REQUIRE(paths.contains(p.path));
        CHECK(paths.at(p.path).at(p.method).at("operationId") == p.id);
    }
    // The ecosystem enum is the generated one, never the raw token.
    const auto body = paths.at("/inventory/software/normalization/aliases")
                          .at("post")
                          .at("requestBody")
                          .dump();
    CHECK(body.find("@@ECOSYSTEM_ENUM@@") == std::string::npos);
    CHECK(body.find("\"windows\"") != std::string::npos);
}

// ── live store ────────────────────────────────────────────────────────────────────────────

namespace {
yuzu::test::PgTestTemplate curation_tpl{"prodreg", [](const std::string& dsn) {
    PgPool pool{{.conninfo = dsn, .size = 1}};
    ProductRegistryStore store{pool};
    if (!store.is_open())
        throw std::runtime_error("prodreg template: store failed to migrate");
}};
} // namespace

TEST_CASE("curation routes end to end over a live store", "[pg][software_curation][rest]") {
    YUZU_REQUIRE_PG_DB_TPL(db, curation_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    REQUIRE(pool.valid());
    ProductRegistryStore store{pool};
    REQUIRE(store.is_open());
    Harness h{&store};

    // Empty queue / status: all seven keys, with their JSON types.
    auto st = json::parse(h.sink.Get(kBase + "/status")->body)["data"];
    CHECK(st.size() == 7);
    CHECK(st.at("pack_version").is_string());
    CHECK(st.at("loaded_at").is_number_integer());
    CHECK(st.at("loaded_by").is_string());
    for (const char* k :
         {"titles_normalized", "titles_unnormalized", "queue_open", "queue_rejected"})
        CHECK(st.at(k).is_number_integer());
    CHECK(st["queue_open"] == 0);
    CHECK(json::parse(h.sink.Get(kBase + "/queue")->body)["data"]["count"] == 0);
    CHECK(h.audits.empty()); // admitted reads are never audited

    // Curate -> 201, the alias resolves.
    const auto cur = h.sink.Post(kBase + "/aliases", alias_body());
    REQUIRE(cur->status == 201);
    const auto data = json::parse(cur->body)["data"];
    CHECK(data["alias_source"] == "curated:windows");
    CHECK(data["alias_key"] == "contoso studio standard");

    // Replace the pack: 200, then the same version is a 409.
    const std::string csv{kSoftwareNormalizationSeed};
    const auto first = h.sink.Post(kBase + "/pack", csv, "text/csv");
    REQUIRE(first->status == 200);
    CHECK(json::parse(first->body)["data"]["pack_version"].is_string());
    const auto second = h.sink.Post(kBase + "/pack", csv, "text/csv");
    CHECK(second->status == 409);

    // Queue a row directly, list it, page it, reject it through its key.
    {
        auto lease = pool.acquire();
        REQUIRE(lease);
        for (const char* n : {"alpha", "beta"}) {
            auto r = pg::exec_params(
                lease.get(),
                "INSERT INTO product_registry_store.curation_queue VALUES ($1, '', 'rpm', 4, "
                "'open', 1, 2)",
                std::vector<std::string>{n});
            REQUIRE(r.status() == PGRES_COMMAND_OK);
        }
    }
    const auto page1 = json::parse(h.sink.Get(kBase + "/queue?limit=1")->body)["data"];
    REQUIRE(page1["items"].size() == 1);
    CHECK(page1["items"][0]["raw_name"] == "alpha");
    REQUIRE(page1["next_cursor"].is_string());
    const auto page2 = json::parse(
        h.sink.Get(kBase + "/queue?limit=1&cursor=" + page1["next_cursor"].get<std::string>())
            ->body)["data"];
    REQUIRE(page2["items"].size() == 1);
    CHECK(page2["items"][0]["raw_name"] == "beta");
    CHECK(page2["next_cursor"].is_null());

    const auto key = page1["items"][0]["key"].get<std::string>();
    CHECK(h.sink.Post(kBase + "/queue/" + key + "/reject", "")->status == 200);
    CHECK(h.sink.Post(kBase + "/queue/" + key + "/reject", "")->status == 404); // already rejected
    const auto open = json::parse(h.sink.Get(kBase + "/queue")->body)["data"];
    CHECK(open["count"] == 1);
    const auto rej = json::parse(h.sink.Get(kBase + "/queue?status=rejected")->body)["data"];
    CHECK(rej["count"] == 1);
}

TEST_CASE("an audit failure leaves a live store untouched, and an omitted category keeps the "
          "product's category", "[pg][software_curation][rest]") {
    YUZU_REQUIRE_PG_DB_TPL(db, curation_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    REQUIRE(pool.valid());
    ProductRegistryStore store{pool};
    REQUIRE(store.is_open());
    Harness h{&store};
    const auto count = [&](const char* sql) {
        auto lease = pool.acquire();
        REQUIRE(lease);
        auto r = pg::exec_params(lease.get(), sql, std::vector<std::string>{});
        REQUIRE(r.status() == PGRES_TUPLES_OK);
        return std::string{PQgetvalue(r.get(), 0, 0)};
    };

    h.audit_ok = false;
    CHECK(h.sink.Post(kBase + "/aliases", alias_body({{"category", "database"}}))->status == 503);
    CHECK(h.sink.Post(kBase + "/pack", std::string{kSoftwareNormalizationSeed}, "text/csv")->status ==
          503);
    CHECK(count("SELECT count(*) FROM product_registry_store.products") == "0");
    CHECK(count("SELECT count(*) FROM product_registry_store.product_aliases") == "0");

    h.audit_ok = true;
    REQUIRE(h.sink.Post(kBase + "/aliases", alias_body({{"category", "database"}}))->status == 201);
    // A second raw name onto the same product, category omitted: the category is kept.
    json second = json::parse(alias_body({{"raw_name", "Contoso Studio 2 Standard"},
                                          {"edition", "standard"}}));
    second.erase("category");
    REQUIRE(h.sink.Post(kBase + "/aliases", second.dump())->status == 201);
    CHECK(count("SELECT category FROM product_registry_store.products WHERE "
                "norm_key = 'contoso:studio:standard'") == "database");
}
