#pragma once

/// @file groups_routes.hpp
/// The Groups and enrolment page (Phase 2 UI).
///
/// Routes (all GET):
///   /groups                  page; 302 /login without a session
///   /static/yuzu-groups.js   the page's client glue
///
/// The page's three panels re-use the enrolment fragments that already exist under
/// `/fragments/settings/{tokens,pending,auto-approve}` (same routes, same `admin_fn_` gate,
/// same mutation routes and audit rows). No fragment, mutating route or gate is added here.

#include <yuzu/server/auth.hpp>

#include <httplib.h>

#include <functional>
#include <optional>

namespace yuzu::server {

class HttpRouteSink;

namespace groups {

struct Deps {
    using AuthFn =
        std::function<std::optional<auth::Session>(const httplib::Request&, httplib::Response&)>;
    AuthFn auth_fn;
};

/// Throws `std::invalid_argument` when any `Deps` member is unbound.
void register_groups_routes(HttpRouteSink& sink, Deps deps);

} // namespace groups
} // namespace yuzu::server
