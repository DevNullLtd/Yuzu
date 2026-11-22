#include "compliance_eval.hpp"

#include "cel_eval.hpp"

namespace yuzu::server {

ComplianceResult evaluate_compliance(std::string_view expression,
                                     const std::map<std::string, std::string>& result_fields) {
    if (expression.empty())
        return ComplianceResult::compliant; // empty = always compliant

    auto result = cel::evaluate_tri(expression, result_fields);
    if (!result.has_value())
        return ComplianceResult::eval_error; // timeout, parse error, over-long or undefined expression
    return *result ? ComplianceResult::compliant : ComplianceResult::non_compliant;
}

bool evaluate_compliance_bool(std::string_view expression,
                              const std::map<std::string, std::string>& result_fields) {
    return evaluate_compliance(expression, result_fields) == ComplianceResult::compliant;
}

std::string validate_compliance_expression(std::string_view expression) {
    if (expression.empty())
        return {};

    return cel::validate(expression);
}

} // namespace yuzu::server
