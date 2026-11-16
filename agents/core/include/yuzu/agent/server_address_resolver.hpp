#pragma once

/**
 * server_address_resolver.hpp -- resolves the agent's configured server
 * target ("host:port", possibly a hostname) to concrete IP literal(s) ONCE
 * at agent startup, before any plugin (including quarantine) ever runs.
 *
 * WHY THIS LIVES HERE, RESOLVED AT STARTUP, AND CACHED -- not re-resolved
 * on demand by a plugin at the moment it's needed: quarantine's whitelist
 * derivation used to call getaddrinfo() directly, at quarantine-DISPATCH
 * time, on the host BEING quarantined -- letting that host's own live
 * resolver state (a poisoned /etc/hosts, a compromised local resolver, a
 * hostile DHCP-served nameserver) decide which address survives its own
 * containment. Quarantine is normally dispatched IN RESPONSE to a
 * suspected compromise, so resolving at that exact moment is close to the
 * worst possible timing for trusting the local resolver. Resolving once
 * here, at boot, narrows the window to "compromised before or at agent
 * startup" instead. It also means quarantine-time performs NO DNS I/O at
 * all: resolve_server_address_literals() below is bounded, so a wedged
 * resolver delays agent startup once rather than blocking every future
 * quarantine/unquarantine/whitelist dispatch (which all share one
 * mutation gate in the quarantine plugin).
 *
 * Threaded into every plugin's config as "agent.server_address_resolved"
 * by Agent::Run() (agent.cpp), read by the quarantine plugin's
 * do_quarantine instead of resolving anything itself.
 *
 * Its companion, "agent.server_peer" (UP-8): the literal address of the peer
 * the LATEST successful Register actually answered on (`host:port` or
 * `[v6]:port`, grpc_peer_literal() in server_address_parsers.hpp), published
 * by AgentImpl::publish_server_peer at every Register and answered by
 * yuzu_ctx_get_config from an atomic, not from the config map (empty/unset
 * until the first Register, and whenever the peer is not a usable literal).
 * The start-resolved set above can name a server that has since moved; the
 * live peer is the address the control channel uses NOW. It carries the same
 * trust rule: produced by agents/core from the stream the server answered on
 * (certificate-authenticated when tls_enabled), never resolved by a plugin or
 * by the host being contained -- a plugin admits only the literal published
 * here. The firewall plugin's containment allows it first and proves it in
 * its verification; a server re-addressed AFTER a containment still strands
 * the host (the new address is blocked before the agent can learn it).
 *
 * Bounding note (#3429 round 4): the deadline is enforced by
 * yuzu::shared::bounded_call() (agents/shared/bounded_wait.hpp), which runs
 * the resolve on a detached thread and waits on a condition variable --
 * NOT by a plain std::async(std::launch::async, ...)-obtained future's
 * wait_for(), whose destructor blocks the CALLING thread until the task
 * finishes even past a timed-out wait_for() ([futures.async]). That shape
 * was this file's round-3 bug: the caller looked bounded but still hung on
 * a wedged resolver until getaddrinfo() itself returned.
 */

#include <yuzu/plugin.h> // YUZU_EXPORT

#include <chrono>
#include <functional>
#include <string>
#include <string_view>
#include <vector>

namespace yuzu::agent {

/// Returns a comma-joined list of IP literal(s) that `target`'s host
/// portion resolves to. `target` is a gRPC-style "host:port" string (the
/// agent's own --server config) -- an already-IP-literal host is returned
/// as-is (no DNS round-trip); a hostname is resolved via a BOUNDED
/// getaddrinfo() call on a detached thread, discarded on timeout. Empty on
/// failure, timeout, or an unparseable target -- never blocks the caller
/// past the bound.
YUZU_EXPORT std::string resolve_server_address_literals(std::string_view target);

namespace detail {

/// Core of resolve_server_address_literals(), with the resolve step
/// injected so a unit test can exercise the bounding behavior with a
/// deterministic synthetic callable instead of a real DNS round-trip (this
/// repo's "no network in unit tests" discipline). Production code always
/// goes through resolve_server_address_literals(), which supplies the real
/// getaddrinfo()-backed resolver and the live deadline.
YUZU_EXPORT std::string
resolve_bounded(std::string_view target, std::chrono::milliseconds deadline,
                 const std::function<std::vector<std::string>(const std::string&)>& resolve);

} // namespace detail

} // namespace yuzu::agent
