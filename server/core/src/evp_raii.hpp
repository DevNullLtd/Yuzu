#pragma once

// Shared RAII wrapper for OpenSSL's EVP_MD_CTX, used by any server-side code
// that streams or hashes a short buffer via the EVP digest API. Extracted
// from file_retrieval_routes.cpp / upload_grant_store.cpp, which each
// carried a byte-identical copy — a chokepoint of one rather than a fork.
//
// Deliberately scoped to server/core: agents/*, plugins, and the older
// server sites (plugin_signing_helpers.cpp, auth.cpp, oidc_provider.cpp,
// saml_provider.cpp, product_pack_store.cpp) each carry their own
// pre-existing copy and are untouched here — consolidating those is a
// separate, wider change, not part of this fix.

#include <openssl/evp.h>

#include <memory>

namespace yuzu::server {

struct EvpMdCtxDeleter {
    void operator()(EVP_MD_CTX* ctx) const noexcept { EVP_MD_CTX_free(ctx); }
};
using EvpMdCtxPtr = std::unique_ptr<EVP_MD_CTX, EvpMdCtxDeleter>;

}  // namespace yuzu::server
