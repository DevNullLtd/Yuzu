#pragma once

/// @file pki_routes.hpp
///
/// `GET /settings/pki`: the System > Certificates and secrets page. Page only. The
/// panels are fragments owned where their data lives (`/fragments/settings/ca` in
/// ca_routes.cpp, `/fragments/settings/kek` in kek_routes.cpp), and the CA / KEK
/// mutations keep their existing routes.

#include "http_route_sink.hpp"

#include <httplib.h>

#include <functional>

namespace yuzu::server::pki {

struct Deps {
    /// Legacy-admin gate (`require_admin`), the same one `GET /settings` uses. A refusal has
    /// already written its response; the handler then redirects to `/`.
    std::function<bool(const httplib::Request&, httplib::Response&)> admin_fn;
};

void register_pki_routes(HttpRouteSink& sink, Deps deps);

} // namespace yuzu::server::pki
