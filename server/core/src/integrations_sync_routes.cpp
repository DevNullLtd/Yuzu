#include "integrations_sync_routes.hpp"

#include "rbac_store.hpp"
#include "rest_audit.hpp" // detail::emit_behavioral_audit

#include <memory>
#include <stdexcept>

namespace yuzu::server {
extern const std::string kYuzuIntegrationsSyncJs; // yuzu_integrations_sync_js_bundle.cpp
} // namespace yuzu::server

namespace yuzu::server::integrations {

namespace {

/// `std::stoll` throws out_of_range on a 20-digit id even though the route
/// regex only admits digits; an unparseable id is "not found", never a throw.
[[nodiscard]] std::optional<std::int64_t> parse_id_segment(const std::string& s) {
    try {
        return std::stoll(s);
    } catch (const std::exception&) {
        return std::nullopt;
    }
}

void send_html(httplib::Response& res, const std::string& body) {
    // Fragments answer 200 with an honest body for every state (htmx does not
    // swap 4xx/5xx), and are never cached: lists, history and PII.
    res.set_header("Cache-Control", "no-store");
    res.set_content(body, "text/html; charset=utf-8");
}

template <class D> LastDelivery last_of(const std::optional<std::vector<D>>& d) {
    LastDelivery out;
    if (!d) {
        out.kind = LastDelivery::Kind::unknown;
    } else if (!d->empty()) {
        out.kind = LastDelivery::Kind::known;
        out.status_code = d->front().status_code;
        out.at = d->front().delivered_at;
        out.error = d->front().error;
    }
    return out;
}

/// admin gate first, then (when bound) the JSON twin's securable, so a fragment
/// is never wider than the route it mirrors.
[[nodiscard]] bool gate(const SyncDeps& d, const httplib::Request& req, httplib::Response& res,
                        const char* securable) {
    if (!d.admin_fn(req, res))
        return false;
    return d.perm_fn(req, res, securable, "Read");
}

template <class T> std::expected<T, ReadError> unavailable() {
    return std::unexpected(ReadError::unavailable);
}

} // namespace

SyncDeps bind_stores(WebhookStore* wh, OffloadTargetStore* off, DirectorySync* dir,
                 const RbacStore* rbac) {
    SyncDeps d;
    auto map_dir = [](DirectoryReadError e) {
        return e == DirectoryReadError::store_unavailable ? ReadError::unavailable
                                                          : ReadError::failed;
    };

    d.webhooks_list = [wh](int limit) -> std::expected<std::vector<Webhook>, ReadError> {
        if (!wh || !wh->is_open())
            return unavailable<std::vector<Webhook>>();
        auto r = wh->list(limit);
        if (!r)
            return std::unexpected(ReadError::failed);
        return *std::move(r);
    };
    d.webhook_get =
        [wh](std::int64_t id) -> std::expected<std::optional<Webhook>, ReadError> {
        if (!wh || !wh->is_open())
            return unavailable<std::optional<Webhook>>();
        bool ok = true;
        auto w = wh->get(id, &ok);
        if (!ok)
            return std::unexpected(ReadError::failed);
        return w;
    };
    d.webhook_deliveries = [wh](std::int64_t id, int limit) {
        return wh ? wh->get_deliveries_checked(id, limit)
                  : std::optional<std::vector<WebhookDelivery>>{};
    };

    d.offload_list = [off](int limit) -> std::expected<std::vector<OffloadTarget>, ReadError> {
        if (!off || !off->is_open())
            return unavailable<std::vector<OffloadTarget>>();
        auto r = off->list(limit);
        if (!r)
            return std::unexpected(ReadError::failed);
        return *std::move(r);
    };
    d.offload_get =
        [off](std::int64_t id) -> std::expected<std::optional<OffloadTarget>, ReadError> {
        if (!off || !off->is_open())
            return unavailable<std::optional<OffloadTarget>>();
        bool ok = true;
        auto t = off->get(id, &ok);
        if (!ok)
            return std::unexpected(ReadError::failed);
        return t;
    };
    d.offload_deliveries = [off](std::int64_t id, int limit) {
        return off ? off->get_deliveries_checked(id, limit)
                   : std::optional<std::vector<OffloadDelivery>>{};
    };

    d.directory_status = [dir, map_dir]() -> std::expected<SyncStatus, ReadError> {
        if (!dir)
            return unavailable<SyncStatus>();
        auto r = dir->get_status_checked();
        if (!r)
            return std::unexpected(map_dir(r.error()));
        return *std::move(r);
    };
    d.directory_user_count = [dir, map_dir]() -> std::expected<std::int64_t, ReadError> {
        if (!dir)
            return unavailable<std::int64_t>();
        auto r = dir->get_synced_user_count_checked();
        if (!r)
            return std::unexpected(map_dir(r.error()));
        return *r;
    };
    d.directory_groups =
        [dir, map_dir]() -> std::expected<std::vector<DirectoryGroup>, ReadError> {
        if (!dir)
            return unavailable<std::vector<DirectoryGroup>>();
        auto r = dir->get_synced_groups_checked();
        if (!r)
            return std::unexpected(map_dir(r.error()));
        return *std::move(r);
    };
    d.directory_users = [dir, map_dir](int limit) -> std::expected<std::vector<DirectoryUser>, ReadError> {
        if (!dir)
            return unavailable<std::vector<DirectoryUser>>();
        auto r = dir->get_synced_users_checked({}, limit);
        if (!r)
            return std::unexpected(map_dir(r.error()));
        return *std::move(r);
    };
    d.role_names = [rbac]() -> std::expected<std::vector<std::string>, ReadError> {
        if (!rbac)
            return unavailable<std::vector<std::string>>();
        std::vector<std::string> names;
        for (const auto& r : rbac->list_roles())
            names.push_back(r.name);
        // list_roles() is a plain container: an empty answer cannot be told
        // from a failed read, so the renderer treats empty as "cannot edit".
        return names;
    };
    return d;
}

void register_integrations_sync_routes(HttpRouteSink& sink, SyncDeps deps) {
    // A fragment without its admin gate, securable gate or users-view audit sink
    // would be a silent hole: refuse to register rather than serve one.
    if (!deps.admin_fn || !deps.perm_fn || !deps.audit_read)
        throw std::invalid_argument(
            "register_integrations_sync_routes: admin_fn, perm_fn and audit_read are required");
    // The SyncDeps are shared by every handler; one heap copy keeps lambdas small.
    auto d = std::make_shared<const SyncDeps>(std::move(deps));

    sink.Get("/fragments/settings/webhooks", [d](const httplib::Request& req, httplib::Response& res) {
        if (!gate(*d, req, res, "Infrastructure"))
            return;
        std::expected<std::vector<WebhookRow>, ReadError> rows;
        auto list = d->webhooks_list(static_cast<int>(kListShown) + 1);
        if (!list) {
            rows = std::unexpected(list.error());
        } else {
            std::vector<WebhookRow> v;
            std::size_t n = 0;
            bool history_lost = false;
            for (auto& w : *list) {
                WebhookRow r;
                r.webhook = std::move(w);
                // Rows past the shown cap are only the "more exist" sentinel.
                if (++n <= kListShown) {
                    // One failed history read (lease timeout) means the rest would
                    // wait out the same timeout: mark them unknown instead of
                    // holding the worker for up to 100 timeouts.
                    if (history_lost) {
                        r.last.kind = LastDelivery::Kind::unknown;
                    } else {
                        r.last = last_of(d->webhook_deliveries(r.webhook.id, 1));
                        history_lost = r.last.kind == LastDelivery::Kind::unknown;
                    }
                }
                v.push_back(std::move(r));
            }
            rows = std::move(v);
        }
        send_html(res, render_webhooks(rows));
    });

    sink.Get(R"(/fragments/settings/webhooks/(\d+)/deliveries)",
             [d](const httplib::Request& req, httplib::Response& res) {
                 if (!gate(*d, req, res, "Infrastructure"))
                     return;
                 const auto id = parse_id_segment(req.matches[1].str());
                 if (!id) {
                     send_html(res, render_not_found_note("The webhook"));
                     return;
                 }
                 auto rows = d->webhook_deliveries(*id, static_cast<int>(kDeliveriesShown));
                 if (!rows) {
                     send_html(res, render_webhook_deliveries(std::unexpected(ReadError::failed)));
                     return;
                 }
                 if (rows->empty()) {
                     // A second read that fails is "could not be read", never "not found".
                     auto w = d->webhook_get(*id);
                     if (!w) {
                         send_html(res,
                                   render_webhook_deliveries(std::unexpected(w.error())));
                         return;
                     }
                     if (!*w) {
                         send_html(res, render_not_found_note("The webhook"));
                         return;
                     }
                 }
                 send_html(res, render_webhook_deliveries(std::move(*rows)));
             });

    sink.Get("/fragments/settings/offload-targets",
             [d](const httplib::Request& req, httplib::Response& res) {
                 if (!gate(*d, req, res, "Infrastructure"))
                     return;
                 std::expected<std::vector<OffloadRow>, ReadError> rows;
                 auto list = d->offload_list(static_cast<int>(kListShown) + 1);
                 if (!list) {
                     rows = std::unexpected(list.error());
                 } else {
                     std::vector<OffloadRow> v;
                     std::size_t n = 0;
                     bool history_lost = false; // see the webhooks list: stop after one failure
                     for (auto& t : *list) {
                         OffloadRow r;
                         r.target = std::move(t);
                         if (++n <= kListShown) {
                             if (history_lost) {
                                 r.last.kind = LastDelivery::Kind::unknown;
                             } else {
                                 r.last = last_of(d->offload_deliveries(r.target.id, 1));
                                 history_lost = r.last.kind == LastDelivery::Kind::unknown;
                             }
                         }
                         v.push_back(std::move(r));
                     }
                     rows = std::move(v);
                 }
                 send_html(res, render_offload_targets(rows));
             });

    sink.Get(R"(/fragments/settings/offload-targets/(\d+)/deliveries)",
             [d](const httplib::Request& req, httplib::Response& res) {
                 if (!gate(*d, req, res, "Infrastructure"))
                     return;
                 const auto id = parse_id_segment(req.matches[1].str());
                 if (!id) {
                     send_html(res, render_not_found_note("The offload target"));
                     return;
                 }
                 // get() first: a degraded read is "could not be read", never
                 // "not found", and a missing target is not an empty history.
                 auto t = d->offload_get(*id);
                 if (!t) {
                     send_html(res,
                               render_offload_deliveries(std::unexpected(t.error())));
                     return;
                 }
                 if (!*t) {
                     send_html(res, render_not_found_note("The offload target"));
                     return;
                 }
                 auto rows = d->offload_deliveries(*id, static_cast<int>(kDeliveriesShown));
                 if (!rows) {
                     send_html(res,
                               render_offload_deliveries(std::unexpected(ReadError::failed)));
                     return;
                 }
                 send_html(res, render_offload_deliveries(std::move(*rows)));
             });

    sink.Get("/fragments/settings/directory-sync",
             [d](const httplib::Request& req, httplib::Response& res) {
                 if (!gate(*d, req, res, "Directory"))
                     return;
                 DirectoryView v{d->directory_status(), d->directory_user_count(),
                                 d->directory_groups(), d->role_names()};
                 send_html(res, render_directory_panel(v));
             });

    sink.Get("/fragments/settings/directory-sync/users",
             [d](const httplib::Request& req, httplib::Response& res) {
                 if (!gate(*d, req, res, "Directory"))
                     return;
                 // PII: refuse to render without a persisted audit row (the
                 // REST v1 twin's fail-closed posture).
                 // The shared behavioural-audit funnel: it catches a throwing audit sink
                 // (withheld, not a 500) and sets Sec-Audit-Failed on a failed persist.
                 // An unset sink must not read as "audit off" here: the list is PII,
                 // so the route fails closed (production always binds one).
                 if (!d->audit_read ||
                     !detail::emit_behavioral_audit(d->audit_read, req, res,
                                                    "directory.users.view", "success", "Directory",
                                                    "", "integrations page directory users read")) {
                     send_html(res, render_audit_withheld_note());
                     return;
                 }
                 // The shown cap + 1: enough to tell "more exist" without reading a
                 // whole directory (the count above is a separate COUNT).
                 auto users = d->directory_users(static_cast<int>(kUsersShown) + 1);
                 auto total = d->directory_user_count();
                 send_html(res, render_directory_users(users, total ? std::optional<std::int64_t>(*total)
                                                              : std::nullopt));
             });

    sink.Get("/static/yuzu-integrations-sync.js", [](const httplib::Request&, httplib::Response& res) {
        res.set_header("Cache-Control", "no-cache, no-store, must-revalidate");
        res.set_content(yuzu::server::kYuzuIntegrationsSyncJs, "application/javascript; charset=utf-8");
    });
}

} // namespace yuzu::server::integrations
