#pragma once

/// @file post_read_stage.hpp
/// The per-server registry of the POST-READ STAGE, and the contract `HttplibRouteSink` honours
/// when it consults it.
///
/// WHAT the stage is: one function, run for every matched route after the request body has been
/// read and before the route's own handler. In production it is `detail::run_post_read_stage`
/// (`step_up_wiring.hpp`): the #2407 post-read body cap, then the MFA step-up chokepoint, in that
/// order. `Handled` means the stage already wrote the response and the handler must not run.
///
/// WHY it is a handler wrapper and not `httplib::Server::set_pre_request_handler`: from
/// cpp-httplib v0.47.0 `Server::dispatch_request` runs the pre-request handler BEFORE
/// `read_content`, so a stage hung there sees an empty `req.body` and its body-size check never
/// fires. (Up to v0.46.x the pre-request handler ran after the body had been read, which is the
/// ordering this stage was written against.) httplib offers no hook between reading the body and
/// calling the handler, so the stage runs inside the handler: `HttplibRouteSink` wraps each
/// handler it registers with `if (stage(req, res) == Handled) return; handler(req, res);`. That is
/// the same point in the request on every httplib version, so a dependency bump cannot move it.
///
/// KEYED BY SERVER, like `RouteInventory`, because the process holds more than one
/// `httplib::Server` (the plaintext redirect listener, in-process test servers). The key is an
/// opaque address used for identity only, never dereferenced. A server with no stage installed is
/// REFUSED by `HttplibRouteSink` (it throws at registration) unless the sink was built with the
/// explicit `StageRequirement::ExemptNoStage`: the plaintext redirect listener (it only answers
/// 301) is the one production exemption, and tests opt out the same way. The in-process
/// `TestRouteSink` never consults this registry.
///
/// ORDERING GUARD: the stage is looked up when a route is REGISTERED, so a stage installed after
/// the first route would silently leave that route unwrapped. `install()` therefore throws
/// `std::logic_error` when `RouteInventory` already holds a route for the server (and on a
/// second install), turning that mistake into a boot failure instead of an uncapped route.
/// The inventory records every route registered through `HttplibRouteSink`; a route registered on
/// the server by a path that does not go through the sink is neither recorded nor wrapped, which
/// is why the L3 source scan (`route_inventory_scan.hpp`) exists.
///
/// COVERAGE, unchanged from the pre-request-handler wiring it replaces: the stage runs for a
/// MATCHED route only (an unmatched path never reaches a handler), and for a multipart request
/// `req.body` stays empty so the cap cannot see it. See `body_cap_policy.hpp`.

#include <httplib.h>

#include <functional>
#include <memory>
#include <mutex>
#include <type_traits>
#include <unordered_map>
#include <utility>

namespace yuzu::server {

class PostReadStageRegistry {
public:
    using Stage = std::function<httplib::Server::HandlerResponse(const httplib::Request&,
                                                                 httplib::Response&)>;

    /// The single process-wide instance.
    static PostReadStageRegistry& instance();

    /// Install `stage` for `server`. Throws `std::logic_error` when `stage` is empty, when one is
    /// already installed for `server`, or when `RouteInventory` already holds a route for it
    /// (see ORDERING GUARD). Thread-safe.
    void install(const void* server, Stage stage);

    /// The stage installed for `server`, or null. The returned pointer keeps the stage alive for
    /// the handlers that captured it, so it stays valid after `forget`.
    [[nodiscard]] std::shared_ptr<const Stage> stage_for(const void* server) const;

    /// Drop `server`'s stage. A new server may reuse a destroyed one's address, so the owner of a
    /// server calls this (next to `RouteInventory::forget`) before it registers.
    void forget(const void* server);

private:
    mutable std::mutex mu_;
    std::unordered_map<const void*, std::shared_ptr<const Stage>> by_server_;
};


/// RAII owner of ONE server's post-read stage registration (and its `RouteInventory` record).
///
/// It ADOPTS a registration the caller has just made with `PostReadStageRegistry::install`
/// (the install call stays at the owner, visible to the source-text pins that check it precedes
/// the first route); the constructor takes nothing but the server's address. The destructor and
/// `reset()` drop the stage and the inventory record, so a later server that reuses the address
/// starts clean: a stale stage under a reused address would wrap an `ExemptNoStage` sink with a
/// dead stage. Make it a MEMBER declared AFTER the `httplib::Server` it names (destroyed first),
/// and call `reset()` once the server's listener thread is joined. It replaces the hand-paired
/// install/forget each owner would otherwise keep (cpp-safety CS-1). Move-only; the default state
/// is empty and `reset()` on it is a no-op.
class ScopedPostReadStage {
public:
    ScopedPostReadStage() noexcept = default;
    explicit ScopedPostReadStage(const httplib::Server& adopted) noexcept : server_(&adopted) {}
    ~ScopedPostReadStage() { reset(); }

    ScopedPostReadStage(const ScopedPostReadStage&) = delete;
    ScopedPostReadStage& operator=(const ScopedPostReadStage&) = delete;
    ScopedPostReadStage(ScopedPostReadStage&& other) noexcept
        : server_(std::exchange(other.server_, nullptr)) {}
    /// Move-assigning over a non-empty guard resets the OLD registration first. If that old
    /// address were reused by the new server, the reset would erase the fresh registration, so
    /// assign only over an empty guard (ServerImpl does: stop() resets it first).
    ScopedPostReadStage& operator=(ScopedPostReadStage&& other) noexcept {
        if (this != &other) {
            reset();
            server_ = std::exchange(other.server_, nullptr);
        }
        return *this;
    }

    /// Drop the stage and the inventory record now. Safe to call twice; a no-op when empty.
    /// `noexcept` could in theory terminate if a registry mutex lock throws; accepted, teardown
    /// cannot recover from that anyway.
    void reset() noexcept;

    [[nodiscard]] explicit operator bool() const noexcept { return server_ != nullptr; }

private:
    const void* server_ = nullptr;
};

static_assert(!std::is_copy_constructible_v<ScopedPostReadStage> &&
                  !std::is_copy_assignable_v<ScopedPostReadStage>,
              "ScopedPostReadStage owns one registration: copying it would double-forget");
static_assert(std::is_nothrow_move_constructible_v<ScopedPostReadStage> &&
                  std::is_nothrow_move_assignable_v<ScopedPostReadStage>,
              "ScopedPostReadStage is moved into a ServerImpl member");

} // namespace yuzu::server
