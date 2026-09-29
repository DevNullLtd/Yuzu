#include "approval_model.hpp"

namespace yuzu::server {

nlohmann::json approval_row_json(const Approval& a) {
    return nlohmann::json{
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
}

} // namespace yuzu::server
