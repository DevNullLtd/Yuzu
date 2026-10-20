#include "approval_model.hpp"

namespace yuzu::server {

nlohmann::json approval_row_json(const Approval& a) {
    nlohmann::json row{
        {"id", a.id},
        {"definition_id", a.definition_id},
        {"status", a.status},
        {"submitted_by", a.submitted_by},
        {"submitted_at", a.submitted_at},
        {"reviewed_by", a.reviewed_by},
        {"reviewed_at", a.reviewed_at},
        {"review_comment", a.review_comment},
        {"scope_expression", a.scope_expression},
    };

    // A BOUND ticket (#6062) adds three fields; an unbound row is byte-identical to the
    // shape every caller has always seen. "Bound" is read from the stored state, not from
    // the origin: a row carrying ANY of the three columns shows all of them, so an
    // inconsistent row (a digest with no request, an unreadable roots list) is visible
    // rather than silently dropped.
    const bool bound = !a.request_json.empty() || !a.request_digest.empty() ||
                       !a.excluded_roots.empty() || a.excluded_roots_unreadable;
    if (!bound)
        return row;

    // `request` is the stored document PARSED, not the stored string: the digest below is
    // of the exact stored bytes, which a re-serialisation (sorted keys, no whitespace) may
    // not reproduce, so it identifies the ticket's request and is not a recipe for
    // recomputing it from this object. A request that cannot be shown is `null` with
    // `request_unreadable: true`; it is parsed only after the shared size/depth bound, so a
    // hostile row cannot reach the recursive serializer.
    if (a.request_json.empty()) {
        row["request"] = nullptr;
    } else if (bound_request_is_readable(a.request_json)) {
        row["request"] = nlohmann::json::parse(a.request_json, nullptr, /*allow_exceptions=*/false);
    } else {
        row["request"] = nullptr;
        row["request_unreadable"] = true;
    }
    row["request_digest"] = a.request_digest;
    row["excluded_roots"] = a.excluded_roots;
    if (a.excluded_roots_unreadable)
        row["excluded_roots_unreadable"] = true;
    return row;
}

} // namespace yuzu::server
