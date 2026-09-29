#include "license_model.hpp"

namespace yuzu::server {

nlohmann::json platform_license_json(const License& lic, int64_t days_remaining) {
    return nlohmann::json{
        {"id", lic.id},
        {"organization", lic.organization},
        {"seat_count", lic.seat_count},
        {"seats_used", lic.seats_used},
        {"issued_at", lic.issued_at},
        {"expires_at", lic.expires_at},
        {"edition", lic.edition},
        {"status", lic.status},
        {"days_remaining", days_remaining},
    };
}

nlohmann::json license_alert_json(const LicenseAlert& a) {
    return nlohmann::json{
        {"id", a.id},
        {"license_id", a.license_id},
        {"alert_type", a.alert_type},
        {"message", a.message},
        {"triggered_at", a.triggered_at},
        {"acknowledged", a.acknowledged},
    };
}

} // namespace yuzu::server
