// F50: the session id (a bearer credential) must never be rendered into a log line; only a
// short non-reversible fingerprint may be.

#include "session_log_fingerprint.hpp"

#include <catch2/catch_test_macros.hpp>
#include <spdlog/sinks/ostream_sink.h>
#include <spdlog/spdlog.h>

#include <memory>
#include <sstream>

#include <string>

TEST_CASE("session_log_fingerprint never contains the session id", "[agent][log_injection][F50]") {
    const std::string sid = "0123456789abcdef0123456789abcdef-session-credential";
    const std::string fp = yuzu::agent::session_log_fingerprint(sid);
    CHECK(fp.size() == 8);
    CHECK(sid.find(fp) == std::string::npos);
    CHECK(fp.find("session") == std::string::npos);
    CHECK(fp == yuzu::agent::session_log_fingerprint(sid)); // stable, so lines correlate
    CHECK(fp != yuzu::agent::session_log_fingerprint(sid + "x"));
    CHECK(yuzu::agent::session_log_fingerprint("") == "none");

    std::ostringstream os;
    spdlog::logger lg("yuzu_test_fp", std::make_shared<spdlog::sinks::ostream_sink_mt>(os));
    lg.info("Registered with server (session_fp={})", fp);
    lg.flush();
    CHECK(os.str().find(sid) == std::string::npos);
    CHECK(os.str().find(fp) != std::string::npos);
}
