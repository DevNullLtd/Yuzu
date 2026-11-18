// #8159: the session id (a bearer credential) must never be rendered into a log line; only a
// short non-reversible fingerprint may be.

#include "session_log_fingerprint.hpp"

#include <catch2/catch_test_macros.hpp>
#include <spdlog/sinks/ostream_sink.h>
#include <spdlog/spdlog.h>

#include <memory>
#include <regex>
#include <sstream>
#include <string>

TEST_CASE("session_log_fingerprint never contains the session id", "[agent][log_injection][session_fp]") {
    const std::string sid = "0123456789abcdef0123456789abcdef-session-credential";
    const std::string fp = yuzu::agent::session_log_fingerprint(sid);
    CHECK(fp.size() == 8);
    CHECK(sid.find(fp) == std::string::npos);
    CHECK(fp.find("session") == std::string::npos);
    CHECK(fp == yuzu::agent::session_log_fingerprint(sid)); // stable, so lines correlate
    CHECK(fp != yuzu::agent::session_log_fingerprint(sid + "x"));
    CHECK(yuzu::agent::session_log_fingerprint("") == "none");

    // Cross-component pin: the shell joins (scripts/lib/agent-session-fp.sh, the HA scripts, the
    // UAT scripts) hash the server-side id with sha256sum and compare the first 8 lowercase hex.
    // SHA-256("abc") is the FIPS 180-2 vector ba7816bf8f01cfea...; a different digest, a constant,
    // an upper-case or longer render all break every join silently.
    CHECK(yuzu::agent::session_log_fingerprint("abc") == "ba7816bf");
    CHECK(yuzu::agent::session_log_fingerprint("abd") != "ba7816bf");
    CHECK(std::regex_match(fp, std::regex("[0-9a-f]{8}")));
    CHECK(std::regex_match(yuzu::agent::session_log_fingerprint("gw-session-0123"), std::regex("[0-9a-f]{8}")));

    std::ostringstream os;
    spdlog::logger lg("yuzu_test_fp", std::make_shared<spdlog::sinks::ostream_sink_mt>(os));
    lg.info("Registered with server (session_fp={})", fp);
    lg.flush();
    CHECK(os.str().find(sid) == std::string::npos);
    CHECK(os.str().find(fp) != std::string::npos);
}
