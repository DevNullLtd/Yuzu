#pragma once

/// @file quarantine_read_model.hpp
/// PURE JSON builders for the active-quarantine list, shared by REST `GET /api/v1/quarantine`
/// and its MCP twin (the "one builder" rule, docs/api-twin-recipe.md §1). Header-only: no I/O,
/// no httplib, no store access -- the caller hands in already-fetched, already-scoped
/// `QuarantineRecord`s (see quarantine_visible.hpp for the admit-then-filter read).
///
/// Wire contract: exactly the eight keys below, in this order. A record ended by force whose
/// device still owes a release (listed only on request, `include=release_owed`, #7624) reads
/// status `release_owed` and carries two more keys after the eight, `released_at` and
/// `release_owed_since`; an active or releasing record never does, so its bytes are unchanged. `nlohmann::ordered_json` keeps
/// insertion order; plain `nlohmann::json` would alphabetise the keys and change the bytes the
/// REST route has always served (pinned by `test_rest_quarantine_routes.cpp`,
/// "body bytes are pinned"). `QuarantineRecord::id` is deliberately NOT exposed (see the field
/// comment in quarantine_types.hpp), and `released_at` only on an owed row.
///
/// Serialising: the REST route used a hand-rolled builder whose escaping matches nlohmann's
/// (short escapes for \b \f \n \r \t, lowercase `\u00xx` for the other control bytes, `/` and
/// 0x7f left raw, valid UTF-8 passed through). Its only divergence is input that is not valid
/// UTF-8: the old builder copied the bytes through, nlohmann's default `dump()` throws. Dump
/// with `error_handler_t::replace` (see `quarantine_dump`) so such a value degrades to U+FFFD
/// instead of throwing out of a request handler. The store's text columns cannot hold invalid
/// UTF-8, so this is defence in depth.

#include "quarantine_types.hpp"

#include <nlohmann/json.hpp>

#include <string>
#include <vector>

namespace yuzu::server {

/// One active-quarantine record as the wire object (the eight documented keys, in order).
[[nodiscard]] inline nlohmann::ordered_json quarantine_record_json(const QuarantineRecord& r) {
    nlohmann::ordered_json o = nlohmann::ordered_json::object();
    o["agent_id"] = r.agent_id;
    o["status"] = r.status;
    o["quarantined_by"] = r.quarantined_by;
    o["quarantined_at"] = r.quarantined_at;
    o["whitelist"] = r.whitelist;
    o["reason"] = r.reason;
    // #3425: endpoint-containment confirmation state (schema v2), 0 = never, matching
    // quarantined_at's own never-happened shape. last_applied_at: a system re-dispatch of the
    // stored whitelist was accepted (agents_reached > 0), NOT proof of containment.
    // last_confirmed_at: a follow-up firewall.quarantine_status read reported the device's rules in force.
    o["last_applied_at"] = r.last_applied_at;
    o["last_confirmed_at"] = r.last_confirmed_at;
    if (r.status == "released" && r.device_release_owed_at != 0) {
        o["status"] = "release_owed";
        o["released_at"] = r.released_at;
        o["release_owed_since"] = r.device_release_owed_at;
    }
    return o;
}

/// The `data` array of the list: one `quarantine_record_json` per record, in the order given
/// (the store's newest-first). An empty list is `[]`, never null.
[[nodiscard]] inline nlohmann::ordered_json quarantine_list_data_json(const std::vector<QuarantineRecord>& records) {
    nlohmann::ordered_json arr = nlohmann::ordered_json::array();
    for (const auto& r : records)
        arr.push_back(quarantine_record_json(r));
    return arr;
}

/// Compact dump that cannot throw on non-UTF-8 text (see the file comment).
[[nodiscard]] inline std::string quarantine_dump(const nlohmann::ordered_json& j) {
    return j.dump(-1, ' ', false, nlohmann::ordered_json::error_handler_t::replace);
}

} // namespace yuzu::server
