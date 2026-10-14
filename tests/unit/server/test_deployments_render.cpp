// Pure vocabulary, builders and fragment renderers for the read-only deployment list and
// detail. Always runs (no PG): deployment_state's table, the shared JSON builders' secret
// exclusion, and the HTML renderers' escaping and degraded copy.

#include <catch2/catch_test_macros.hpp>

#include "deployment_routes.hpp" // deployment_row_json / deployment_device_json / detail json
#include "deployments_render.hpp"

#include <string>
#include <vector>

using namespace yuzu::server;

namespace {

DeploymentRow row(const std::string& status = "complete") {
    DeploymentRow d;
    d.deployment_id = "00112233aabbccdd";
    d.source_run_id = "run-1";
    d.created_by = "alice";
    d.name = "Chrome 132";
    d.artifact_url = "https://repo.example/pkg.msi?sig=SECRETTOKEN";
    d.artifact_filename = "pkg.msi";
    d.artifact_sha256 = std::string(64, 'a');
    d.exec_args = "/qn LICENSE=SECRETKEY";
    d.status = status;
    d.created_at_ms = 1'700'000'000'000;
    d.total = 10;
    d.succeeded = 7;
    d.failed = 2;
    d.skipped = 1;
    return d;
}

} // namespace

TEST_CASE("deployment_state: the live model's vocabulary and nothing else",
          "[deployment][state][render]") {
    struct Case {
        const char* status;
        int failed, skipped;
        const char* code;
        const char* label;
        const char* tone;
    };
    const Case cases[] = {
        {"running", 0, 0, "running", "Running", "info"},
        {"running", 3, 1, "running", "Running", "info"}, // counts never leak into a live row
        {"complete", 0, 0, "complete", "Complete", "ok"},
        {"complete", 2, 0, "complete_failed", "Complete, 2 failed", "warn"},
        {"complete", 0, 4, "complete_skipped", "Complete, 4 skipped", "warn"},
        {"complete", 1, 4, "complete_failed", "Complete, 1 failed", "warn"}, // failures win
        {"staged", 0, 0, "unknown", "Unknown", "idle"},      // never invented
        {"cancelled", 0, 0, "unknown", "Unknown", "idle"},
        {"rolled_back", 0, 0, "unknown", "Unknown", "idle"},
        {"", 0, 0, "unknown", "Unknown", "idle"},
    };
    for (const auto& c : cases) {
        INFO(c.status << " failed=" << c.failed << " skipped=" << c.skipped);
        const auto s = deployment_state(c.status, c.failed, c.skipped);
        CHECK(s.code == c.code);
        CHECK(s.label == c.label);
        CHECK(s.tone == c.tone);
    }
}

TEST_CASE("deployment JSON builders never carry the installer URL or arguments",
          "[deployment][builder][security]") {
    const auto j = deployment_row_json(row());
    const std::string dump = j.dump();
    CHECK(dump.find("SECRETTOKEN") == std::string::npos);
    CHECK(dump.find("SECRETKEY") == std::string::npos);
    CHECK_FALSE(j.contains("artifact_url"));
    CHECK_FALSE(j.contains("exec_args"));
    CHECK_FALSE(j.contains("created_by")); // the owner-scope key is not a payload field
    CHECK(j["has_args"] == true);
    CHECK(j["state"]["label"] == "Complete, 2 failed");
    CHECK(j["total"] == 10);

    auto none = row();
    none.exec_args.clear();
    CHECK(deployment_row_json(none)["has_args"] == false);
}

TEST_CASE("deployment_detail_json: truncated reflects the exact run total",
          "[deployment][builder]") {
    DeploymentDeviceRow a;
    a.agent_id = "a1";
    a.hostname = "h1";
    a.step = "succeeded";
    DeploymentDeviceRow b = a;
    b.agent_id = "a2";
    b.step = "no-such-step"; // an unknown token never reaches the wire as-is

    auto full = row();
    full.total = 2;
    auto j = deployment_detail_json(full, {a, b}, 500);
    CHECK(j["truncated"] == false);
    CHECK(j["device_limit"] == 500);
    REQUIRE(j["devices"].size() == 2);
    CHECK(j["devices"][1]["step"] == "skipped"); // the parser's fail-safe: never claimed to have run

    auto part = row(); // total 10, only two device rows returned
    j = deployment_detail_json(part, {a, b}, 2);
    CHECK(j["truncated"] == true);
}

TEST_CASE("render_deployments_list: empty copy, escaping, aged-out target",
          "[deployment][render]") {
    const std::string empty = render_deployments_list({}, {});
    CHECK(empty.find("No deployments in the last 14 days. A deployment starts from a "
                     "pre-flight run.") != std::string::npos);
    CHECK(empty.find("failbox") == std::string::npos); // empty is not an error

    auto d = row("running");
    d.name = "<script>alert(1)</script>";
    d.artifact_filename = "a\"b.msi";
    const std::string h = render_deployments_list({d, row()}, {"Finance <laptops>", ""});
    CHECK(h.find("<script>") == std::string::npos);
    CHECK(h.find("&lt;script&gt;") != std::string::npos);
    CHECK(h.find("Finance &lt;laptops&gt;") != std::string::npos);
    CHECK(h.find("Run no longer kept") != std::string::npos);
    CHECK(h.find("Running") != std::string::npos);
    CHECK(h.find("Complete, 2 failed") != std::string::npos);
    CHECK(h.find("SECRET") == std::string::npos);
}

TEST_CASE("render_deployment_detail: exact counts, no secrets, truncation note",
          "[deployment][render]") {
    DeploymentDeviceRow dev;
    dev.agent_id = "agent-1";
    dev.hostname = "<b>host</b>";
    dev.os = "windows";
    dev.step = "failed";
    dev.exit_code = 1603;
    dev.error = std::string(500, 'x') + "<img src=x>";
    const std::string h = render_deployment_detail(row("running"), {dev});
    CHECK(h.find("SECRET") == std::string::npos);
    CHECK(h.find("Set (not shown)") != std::string::npos);
    CHECK(h.find("&lt;b&gt;host&lt;/b&gt;") != std::string::npos);
    CHECK(h.find("<img") == std::string::npos);
    CHECK(h.find("1603") != std::string::npos);
    CHECK(h.find("data-truncated") != std::string::npos);
    CHECK(h.find("only while a Deployments page is open") != std::string::npos);
    // The error text is bounded: 500 'x' must not appear in full.
    CHECK(h.find(std::string(300, 'x')) == std::string::npos);

    auto full_row = row();
    full_row.total = 0;
    const std::string done = render_deployment_detail(full_row, {});
    CHECK(done.find("only while a Deployments page is open") == std::string::npos);
    CHECK(done.find("data-truncated") == std::string::npos);
}

TEST_CASE("render_deployments_failbox escapes its text and is never a table",
          "[deployment][render]") {
    const std::string h = render_deployments_failbox("could not <read>");
    CHECK(h.find("failbox") != std::string::npos);
    CHECK(h.find("&lt;read&gt;") != std::string::npos);
    CHECK(h.find("<table") == std::string::npos);
}
