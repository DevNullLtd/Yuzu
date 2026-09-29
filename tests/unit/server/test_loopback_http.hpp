#pragma once
// Loopback httplib helpers for tests that prove a PRE-ROUTING rejection
// (403/413/415 returned from a pre-routing handler before the request body
// is read). Pinned httplib version: 0.37.1 (vcpkg.json).
//
// MECHANISM (#2757): httplib's routing() invokes the pre-routing handler
// before read_content runs, and write_response_core sets `Connection: close`
// for any status >= 400. So a pre-routing rejection can close the socket
// while the client is still writing (or about to write) a request body the
// server never read. A request whose body crosses
// CPPHTTPLIB_EXPECT_100_THRESHOLD (1024 bytes) additionally triggers an
// `Expect: 100-continue` round trip first, so the body WRITE itself can fail
// after the server's early rejection, not only the response READ.
//
// Windows discards an already-buffered response on the resulting reset
// (WSAECONNRESET); the CI evidence for #2757 is that the exact same request
// against the exact same rejection logic reads the 4xx response cleanly on
// Linux/macOS. This header does not itself prove which httplib::Error a
// given Windows run reports for a given case — each call site is expected to
// have been run on Windows at least once to confirm which of the accepted
// classes actually fires there before relying on this helper.
//
// Draining an already-small, already-sent body is not expressible inside the
// current pre-routing callback without an httplib API change or a patch:
// `set_pre_routing_handler` receives `(const Request&, Response&)`, not a
// `Stream`, so it cannot read a pending body itself. httplib does expose an
// Expect-100 handler seam that could reject BEFORE sending `100 Continue`
// for the Expect-100 case specifically - that would not help the two D4/H1
// cases below, whose bodies are well under the threshold. The real
// constraint is ADR-1005's reject-before-read pre-routing ordering
// (server.cpp's pre-routing chokepoint); moving the small-body case to a
// post-read stage would change that ordering for production traffic, not
// just for this fixture. Follow-up: file an issue tracking that a real
// Windows client of the shipped Windows server can see the same reset for a
// small rejected body, and cite it here once filed.
#include <httplib.h>

#include <catch2/catch_test_macros.hpp>

#include <atomic>

namespace yuzu::test {

/// Sends a request expected to be rejected in PRE-ROUTING with
/// `expected_status`, tolerating a Windows-only connection reset IF AND ONLY
/// IF the fixture's own rejection counter (`witness`, incremented by the
/// fixture's pre-routing handler at the exact point it sets the rejection
/// status) can be shown to have advanced across this specific call - proving
/// the pre-routing handler actually ran and rejected THIS request, not
/// merely that some earlier request was rejected or that the server happens
/// to still answer something. `send` performs the request and returns an
/// httplib::Result (e.g. `[&]{ return cli.Post(...); }`).
///
/// - A response WAS read: the witness MUST have advanced (proves THIS
///   response came from the fixture's own pre-routing rejection, not some
///   other 4xx path returning the same status - the increment happens on
///   the server thread strictly before that thread writes the response, and
///   `send()` only returns after the client has read it, so there is no
///   race to check for) and its status MUST equal `expected_status`, on
///   every platform. This is the normal, common path and the only one
///   exercised on POSIX in practice.
/// - No response was read, POSIX: fails via REQUIRE, unchanged from before
///   this helper existed - POSIX delivers a buffered response before the
///   reset in every observed case.
/// - No response was read, Windows: accepted ONLY when the httplib error is
///   RST-class (`Read`, `Write`, or `ConnectionClosed` - never `Connection`
///   or `Timeout`, which mean the request never reached a live server, a
///   real failure on every platform) AND the witness counter advanced.
template <class Send>
void expect_pre_routing_rejection(Send&& send, int expected_status,
                                   const std::atomic<int>& witness) {
    const int witness_before = witness.load();
    auto r = send();
    if (r) {
        CHECK(witness.load() > witness_before);
        CHECK(r->status == expected_status);
        return;
    }
    const auto err = r.error();
    INFO("no response read; httplib error = " << httplib::to_string(err));
#ifdef _WIN32
    const bool rst_class = err == httplib::Error::Read || err == httplib::Error::Write ||
                            err == httplib::Error::ConnectionClosed;
    REQUIRE(rst_class);
    REQUIRE(witness.load() > witness_before);
    WARN("Windows: the " << expected_status
                          << " response was lost to a connection reset after the server's "
                             "pre-routing handler rejected the request (documented mechanism, "
                             "see test_loopback_http.hpp; witness counter confirms the "
                             "rejection happened) - issue #2757");
#else
    (void)witness_before;
    REQUIRE(r); // POSIX delivers the buffered response before the reset.
#endif
}

} // namespace yuzu::test
