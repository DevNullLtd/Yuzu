#pragma once

/// @file product_pack_model.hpp
///
/// #4029 (api-parity Batch A, content/catalog half): the shared pure builder
/// family for `ProductPack` JSON (docs/api-twin-recipe.md §1), plus the
/// error-status/client-message classifiers `workflow_routes.cpp`'s legacy
/// `/api/product-packs*` routes already used privately (`static` functions,
/// now hoisted here so `GET /api/v1/product-packs*` and MCP
/// `list_product_packs`/`get_product_pack` can share them too instead of
/// growing their own copies). No `httplib.h`, no MCP-specific includes.
///
/// Unlike the InstructionDefinition family, there was no pre-existing MCP
/// twin to reconcile against here (the issue's evidence: zero
/// `product_pack`/`ProductPack` hits anywhere in `mcp_server.cpp` before this
/// change) — `product_pack_row_json`/`product_pack_detail_json` are a
/// verbatim factoring-out of the legacy REST fragment's existing shapes, not
/// a superset reconciliation. The legacy `/api/product-packs` and
/// `/api/product-packs/{id}` routes are refactored to call these too (a
/// zero-shape-change extraction — see workflow_routes.cpp), closing the
/// duplication before the new v1 + MCP callers make it a three-way copy.

#include "product_pack_store.hpp"

#include <nlohmann/json.hpp>

#include <string>

namespace yuzu::server {

/// List-row shape — id/name/version/description/item_count/items[{kind,
/// item_id,name}]/installed_at/verified. NO per-item `yaml_source` (matches
/// the legacy `/api/product-packs` list route — the full bundle source is a
/// detail-only field, `product_pack_detail_json` below). Used by
/// `GET /api/product-packs` (legacy), `GET /api/v1/product-packs`, and MCP
/// `list_product_packs`.
nlohmann::json product_pack_row_json(const ProductPack& p);

/// Single-pack detail shape — `product_pack_row_json`'s fields plus the pack's
/// own `yaml_source` (the full multi-document bundle) and each item's
/// `yaml_source` too. Used by `GET /api/product-packs/{id}` (legacy),
/// `GET /api/v1/product-packs/{id}`, and MCP `get_product_pack`.
nlohmann::json product_pack_detail_json(const ProductPack& p);

/// HTTP status classifier for a `ProductPackStore` `std::expected` failure —
/// `"not_found:"` prefix -> 404, `kProductPackDbErrorPrefix` -> 503 (genuine
/// DB/lease failure), anything else (signature rejection, validation,
/// business-rule error) -> 400. Hoisted from workflow_routes.cpp's
/// file-local `product_pack_error_status` (same shape, same rationale — see
/// the `.cpp` for the full comment) so `rest_api_v1.cpp`'s new
/// `/api/v1/product-packs*` routes don't grow a second copy.
int product_pack_error_status(const std::string& err);

/// Caller-facing message for a `ProductPackStore` `std::expected` failure —
/// a `kProductPackDbErrorPrefix` error is logged server-side and replaced
/// with a generic "service unavailable" (it carries raw PQ driver detail,
/// not caller-actionable feedback); anything else (never carries the prefix)
/// is operator-authored request feedback and safe to echo verbatim. Hoisted
/// from workflow_routes.cpp's file-local `product_pack_client_message`.
std::string product_pack_client_message(const char* op, const std::string& err);

} // namespace yuzu::server
