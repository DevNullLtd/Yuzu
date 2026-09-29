// Drogon build canary (WS-B1 / ADR-0031 Gate G10).
//
// Designed to prove that Drogon — the async framework the future *presentation*
// binary will run on (ADR-0031 Decision 5) — LINKS (and, run as a meson test,
// LOADS) across the Meson/vcpkg matrix WITHOUT disturbing the load-bearing
// grpc/protobuf/abseil static-linkage config (#375). Linux is proven locally;
// the Windows MSVC leg is exercised in CI (it runs there via server-checks).
// This is a
// gate, not an assumption: the #375 history (LNK2038 / LNK2005 on Windows
// MSVC) is exactly why linking a new C++ framework alongside that stack has to
// be demonstrated in CI rather than presumed.
//
// It must FORCE the linker to resolve a real out-of-line Drogon symbol — a
// header-only include does not prove linkage. `drogon::app()` is itself an
// inline forwarder, so the symbol that actually lives in libdrogon (and thus
// proves linkage) is `HttpAppFramework::instance()`, which app() calls;
// invoking app() makes the link fail if Drogon is not resolvable. We
// deliberately do NOT start the event loop or bind a listener; the canary is a
// link/build/load assertion, not a runtime server.
//
// Scope guard: Drogon is pulled with DEFAULT FEATURES ONLY (no orm / postgres
// / sqlite3 / mysql / redis / yaml), matching ADR-0031 Decision 5 — the
// presentation layer uses Drogon for transport, framing and rendering only,
// never its ORM. Do not link this into the real server/agent binaries; it is
// a canary target (yuzu_drogon_canary) only.
//
// Exit code 0 = the process linked and ran; there is no runtime contract
// beyond "it started". The value of this target is at BUILD/LINK time.

#include <cstdio>
#include <format>

#include <drogon/drogon.h>

int main() {
    // Out-of-line symbol from libdrogon (HttpAppFramework::instance() via the
    // inline drogon::app() forwarder): forces link resolution.
    drogon::HttpAppFramework& app = drogon::app();
    (void)app;
    std::fputs(std::format("drogon canary: Drogon linked; "
                           "HttpAppFramework::instance resolved\n")
                   .c_str(),
               stdout);
    return 0;
}
