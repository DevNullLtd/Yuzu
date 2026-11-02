/// @file software_title_dimension.cpp
/// Pure title resolution + the cross-store normalisation pass. See the header.

#include "software_title_dimension.hpp"

#include "pg/pg_array.hpp"
#include "pg/pg_exec.hpp"
#include "pg/pg_pool.hpp"
#include "pg/pg_raii.hpp"
#include "software_normalization_pack.hpp"

#include <yuzu/metrics.hpp>

#include <libpq-fe.h>
#include <spdlog/spdlog.h>

#include <algorithm>
#include <array>
#include <cstdlib>
#include <exception>
#include <set>
#include <unordered_map>
#include <utility>

namespace yuzu::server {

// Minting a product for an unmatched title is not implemented in this owner. Flipping
// the constant without adding it would label births 'normalized' with a NULL product.
static_assert(!kAutoBirthEnabled, "auto-birth needs a product-minting path in SoftwareTitleDimension");

namespace {

constexpr std::chrono::milliseconds kAcquireTimeout{3000};
constexpr std::size_t kCancelCheckEvery = 256;

std::int64_t now_secs() {
    return std::chrono::duration_cast<std::chrono::seconds>(
               std::chrono::system_clock::now().time_since_epoch())
        .count();
}

std::int64_t cell_i64(const pg::PgResult& res, int row, int col) {
    return std::strtoll(PQgetvalue(res.get(), row, col), nullptr, 10);
}

std::size_t token_count(std::string_view s) {
    std::size_t n = 0;
    bool in = false;
    for (char c : s) {
        const bool sp = c == ' ';
        if (!sp && !in)
            ++n;
        in = !sp;
    }
    return n;
}

/// Statement failure -> one structured log line carrying the SQLSTATE.
bool log_failed(std::string_view label, const pg::PgResult& r) {
    const char* state = PQresultErrorField(r.get(), PG_DIAG_SQLSTATE);
    const std::string_view err = PQresultErrorMessage(r.get());
    spdlog::warn("SoftwareTitleDimension: '{}' failed (sqlstate {}): {}", label,
                 state ? state : "-", err.empty() ? "unexpected result shape" : err);
    return false;
}

/// `pg::exec_params`, with a failed statement logged (label + SQLSTATE).
pg::PgResult exec_logged(PGconn* c, const char* label, const char* sql,
                         const std::vector<std::string>& params) {
    pg::PgResult r = pg::exec_params(c, sql, params);
    if (r.status() != PGRES_COMMAND_OK && r.status() != PGRES_TUPLES_OK)
        log_failed(label, r);
    return r;
}

/// `SET LOCAL statement_timeout` from `kPassBudget` (the pass budget IS the statement
/// timeout - one number). Deliberately the constant, never `run_pass`'s `budget` argument:
/// a test passes 0 s and `statement_timeout = 0` DISABLES the timeout in Postgres.
bool set_statement_timeout(PGconn* c) {
    static const std::string sql =
        "SET LOCAL statement_timeout = '" + std::to_string(kPassBudget.count()) + "s'";
    return exec_logged(c, "statement_timeout", sql.c_str(), {}).status() == PGRES_COMMAND_OK;
}

/// The cluster-wide single-writer lock, taken as the first statement of a pass and of the
/// queue reconcile. `nullopt` = the statement failed; `false` = a peer holds it (skip).
std::optional<bool> try_norm_lock(PGconn* c) {
    pg::PgResult lk = exec_logged(
        c, "advisory lock",
        "SELECT pg_try_advisory_xact_lock(hashtextextended('software_normalization', 0))", {});
    if (lk.status() != PGRES_TUPLES_OK)
        return std::nullopt;
    return !(PQntuples(lk.get()) == 1 && std::string_view(PQgetvalue(lk.get(), 0, 0)) == "f");
}

/// Distinct values as views (the keyed reads take a de-duplicated array).
std::vector<std::string_view> distinct_views(const std::vector<std::string>& v) {
    const std::set<std::string_view> u(v.begin(), v.end());
    return {u.begin(), u.end()};
}

std::string text_array(const std::vector<std::string>& v) {
    std::vector<std::string_view> views(v.begin(), v.end());
    return pg::to_text_array(views);
}

struct Candidate {
    TitleKey key;
    std::int64_t device_count{0};
};

} // namespace

// ── pure core ────────────────────────────────────────────────────────────────

TitleResolution resolve_title(const TitleKey& key,
                              const std::vector<NormalizationAliasRow>& aliases_for_key,
                              const ProductRow* exact_product, bool auto_birth) {
    const NormalizedTitle nt = normalize_title(key.raw_name);
    const std::string ak = alias_key(nt);
    const std::string nv = normalize_vendor(key.raw_publisher);

    TitleResolution out;
    out.norm_status = "unnormalized";
    out.vendor = nv;
    out.product = nt.title;
    out.edition = nt.edition;
    out.title_version = nt.version;
    out.purl_type = std::string{purl_type_for(key.ecosystem)};

    const auto adopt = [&](const ProductRow& p, std::string method) {
        out.norm_status = "normalized";
        out.method = std::move(method);
        out.product_id = p.product_id;
        out.vendor = p.vendor;
        out.product = p.title;
        out.edition = p.edition;
        out.category = p.category.empty() ? "other" : p.category;
        out.cpe_product = p.cpe_product; // the product row's own column, never a resolver
    };

    // Tier (curated > pack), then specificity (eco,pub) > (eco,'') > ('',pub) > ('','').
    const std::array<std::pair<std::string_view, std::string_view>, 4> specificity{{
        {key.ecosystem, nv},
        {key.ecosystem, ""},
        {"", nv},
        {"", ""},
    }};
    for (const std::string_view tier : {std::string_view{"curated"}, std::string_view{"pack"}}) {
        for (const auto& [eco, pub] : specificity) {
            const std::string source = std::string{tier} + ':' + std::string{eco};
            for (const auto& a : aliases_for_key) {
                if (a.raw_name == ak && a.source == source && a.raw_publisher == pub) {
                    adopt(a.product, a.method.empty() ? std::string{tier} : a.method);
                    return out;
                }
            }
        }
    }

    // The product whose norm_key is exactly norm_key(raw_name, raw_publisher). The key embeds
    // the edition, so a title can never land on another edition's product. The matcher's
    // title_vendor/token_set tiers are guesses and are not used here (see the header).
    if (exact_product != nullptr) {
        adopt(*exact_product, "exact_norm");
        return out;
    }

    if (auto_birth && !nv.empty() && token_count(nt.title) >= kAutoBirthMinTokens) {
        out.norm_status = "normalized";
        out.method = "birth";
        return out;
    }
    return out; // labelled unnormalized, never guessed
}

// ── owner ────────────────────────────────────────────────────────────────────

SoftwareTitleDimension::SoftwareTitleDimension(pg::PgPool& pool, ProductRegistryStore&,
                                               SoftwareInventoryStore&,
                                               yuzu::MetricsRegistry* metrics)
    : pool_(pool), metrics_(metrics) {}

PassResult SoftwareTitleDimension::run_pass(const std::function<bool()>& cancelled,
                                            std::chrono::seconds budget) {
    PassResult out;
    PassOutcome inner = PassOutcome::failed;
    int processed = 0;
    int normalized = 0;
    int unnormalized = 0;

    const auto started = std::chrono::steady_clock::now();
    const auto deadline = started + budget;
    // Polled every 256 titles and before each write. A trip records WHY and rolls back.
    const auto abort_requested = [&]() -> bool {
        if (cancelled && cancelled()) {
            inner = PassOutcome::cancelled;
            return true;
        }
        if (std::chrono::steady_clock::now() >= deadline) {
            inner = PassOutcome::timed_out;
            return true;
        }
        return false;
    };

    bool ok = false;
    try {
        ok = pool_.with_txn_for(kAcquireTimeout, [&](PGconn* c) -> bool {
            if (!set_statement_timeout(c))
                return false;

            // Cluster-wide single writer: a peer holding the lock is already normalising.
            const auto locked = try_norm_lock(c);
            if (!locked)
                return false;
            if (!*locked) {
                inner = PassOutcome::skipped_peer;
                return true;
            }

            pg::PgResult pk =
                exec_logged(c, "pack version",
                            "SELECT pack_version FROM product_registry_store.normalization_pack "
                            "WHERE id = 1",
                            {});
            if (pk.status() != PGRES_TUPLES_OK)
                return false;
            if (PQntuples(pk.get()) == 0) {
                inner = PassOutcome::no_pack;
                return true;
            }
            const std::string pack_version = PQgetvalue(pk.get(), 0, 0);

            // The `<>` arm also catches the '' stale sentinel (D14); the third arm is a
            // product deleted under a normalized row (ON DELETE SET NULL).
            pg::PgResult cand = exec_logged(
                c, "candidates",
                "SELECT t.name, t.publisher, t.ecosystem, t.device_count "
                "FROM software_inventory_store.title_triples t "
                "LEFT JOIN product_registry_store.title_dimension d "
                "  ON (d.raw_name, d.raw_publisher, d.ecosystem) = (t.name, t.publisher, t.ecosystem) "
                "WHERE d.raw_name IS NULL OR d.pack_version <> $1 "
                "   OR (d.norm_status = 'normalized' AND d.product_id IS NULL) "
                "ORDER BY t.device_count DESC, t.name, t.publisher, t.ecosystem LIMIT $2::bigint",
                {pack_version, std::to_string(kPassLimit)});
            if (cand.status() != PGRES_TUPLES_OK)
                return false;
            std::vector<Candidate> titles;
            titles.reserve(static_cast<std::size_t>(PQntuples(cand.get())));
            for (int i = 0; i < PQntuples(cand.get()); ++i)
                titles.push_back({{PQgetvalue(cand.get(), i, 0), PQgetvalue(cand.get(), i, 1),
                                   PQgetvalue(cand.get(), i, 2)},
                                  cell_i64(cand, i, 3)});
            processed = static_cast<int>(titles.size());
            if (titles.empty()) {
                inner = PassOutcome::ok;
                return true;
            }

            // Each title's alias key and exact product key, then the aliases and the products
            // for exactly those keys on THIS connection (one transaction, no nested lease).
            // Both reads are keyed, so the work holding the lease is O(batch): normalise each
            // title once, two indexed reads, hash lookups - no scan of the product registry.
            std::vector<std::string> alias_keys;
            std::vector<std::string> product_keys;
            alias_keys.reserve(titles.size());
            product_keys.reserve(titles.size());
            for (const auto& t : titles) {
                alias_keys.push_back(alias_key(normalize_title(t.key.raw_name)));
                product_keys.push_back(norm_key(t.key.raw_name, t.key.raw_publisher));
            }
            auto aliases =
                ProductRegistryStore::read_normalization_aliases(c, distinct_views(alias_keys));
            if (!aliases)
                return false;
            std::unordered_map<std::string, std::vector<NormalizationAliasRow>> aliases_by_key;
            for (auto& a : *aliases)
                aliases_by_key[a.raw_name].push_back(std::move(a));
            auto products =
                ProductRegistryStore::read_products_by_norm_key(c, distinct_views(product_keys));
            if (!products)
                return false;
            std::unordered_map<std::string, ProductRow> products_by_key;
            for (auto& pr_row : *products) {
                std::string k = pr_row.norm_key;
                products_by_key.emplace(std::move(k), std::move(pr_row));
            }

            static const std::vector<NormalizationAliasRow> kNoAliases;
            std::vector<TitleResolution> resolved;
            resolved.reserve(titles.size());
            for (std::size_t i = 0; i < titles.size(); ++i) {
                if (i % kCancelCheckEvery == 0 && abort_requested())
                    return false;
                const auto al = aliases_by_key.find(alias_keys[i]);
                const auto pr_it = products_by_key.find(product_keys[i]);
                resolved.push_back(resolve_title(
                    titles[i].key, al == aliases_by_key.end() ? kNoAliases : al->second,
                    pr_it == products_by_key.end() ? nullptr : &pr_it->second, kAutoBirthEnabled));
            }

            // Parallel arrays for the set-based writes.
            std::vector<std::string> n, p, e, st, m, pid, v, pr, ed, tv, cat, pt, cp;
            std::vector<std::string> qn, qp, qe, qdc; // unnormalized -> queue upsert
            std::vector<std::string> dn, dp, de;      // normalized -> queue delete
            for (std::size_t i = 0; i < titles.size(); ++i) {
                const auto& k = titles[i].key;
                const auto& r = resolved[i];
                n.push_back(k.raw_name);
                p.push_back(k.raw_publisher);
                e.push_back(k.ecosystem);
                st.push_back(r.norm_status);
                m.push_back(r.method);
                pid.push_back(r.product_id ? std::to_string(*r.product_id) : std::string{});
                v.push_back(r.vendor);
                pr.push_back(r.product);
                ed.push_back(r.edition);
                tv.push_back(r.title_version);
                cat.push_back(r.category);
                pt.push_back(r.purl_type);
                cp.push_back(r.cpe_product);
                if (r.norm_status == "normalized") {
                    ++normalized;
                    dn.push_back(k.raw_name);
                    dp.push_back(k.raw_publisher);
                    de.push_back(k.ecosystem);
                } else {
                    ++unnormalized;
                    qn.push_back(k.raw_name);
                    qp.push_back(k.raw_publisher);
                    qe.push_back(k.ecosystem);
                    qdc.push_back(std::to_string(titles[i].device_count));
                }
            }

            const std::string now = std::to_string(now_secs());
            if (abort_requested())
                return false;
            if (exec_logged(c, "dimension upsert",
                    "INSERT INTO product_registry_store.title_dimension "
                    "(raw_name, raw_publisher, ecosystem, norm_status, method, product_id, vendor, "
                    " product, edition, title_version, category, purl_type, cpe_product, "
                    " pack_version, first_seen_at, updated_at) "
                    "SELECT a, b, c, d, e, NULLIF(f, '')::bigint, g, h, i, j, k, l, m, "
                    "       $14::text, $15::bigint, $15::bigint "
                    "FROM unnest($1::text[], $2::text[], $3::text[], $4::text[], $5::text[], "
                    "            $6::text[], $7::text[], $8::text[], $9::text[], $10::text[], "
                    "            $11::text[], $12::text[], $13::text[]) "
                    "  AS t(a, b, c, d, e, f, g, h, i, j, k, l, m) "
                    "ON CONFLICT (raw_name, raw_publisher, ecosystem) DO UPDATE SET "
                    "  norm_status = EXCLUDED.norm_status, method = EXCLUDED.method, "
                    "  product_id = EXCLUDED.product_id, vendor = EXCLUDED.vendor, "
                    "  product = EXCLUDED.product, edition = EXCLUDED.edition, "
                    "  title_version = EXCLUDED.title_version, category = EXCLUDED.category, "
                    "  purl_type = EXCLUDED.purl_type, cpe_product = EXCLUDED.cpe_product, "
                    "  pack_version = EXCLUDED.pack_version, updated_at = EXCLUDED.updated_at",
                    {text_array(n), text_array(p), text_array(e), text_array(st), text_array(m),
                     text_array(pid), text_array(v), text_array(pr), text_array(ed), text_array(tv),
                     text_array(cat), text_array(pt), text_array(cp), pack_version, now})
                    .status() != PGRES_COMMAND_OK)
                return false;

            if (!qn.empty()) {
                if (abort_requested())
                    return false;
                // status is not in the SET list: a 'rejected' row stays rejected.
                if (exec_logged(c, "queue upsert",
                        "INSERT INTO product_registry_store.curation_queue "
                        "(raw_name, raw_publisher, ecosystem, device_count, status, first_queued_at, "
                        " last_seen_at) "
                        "SELECT a, b, c, d::bigint, 'open', $5::bigint, $5::bigint "
                        "FROM unnest($1::text[], $2::text[], $3::text[], $4::text[]) "
                        "  AS t(a, b, c, d) "
                        "ON CONFLICT (raw_name, raw_publisher, ecosystem) DO UPDATE SET "
                        "  device_count = EXCLUDED.device_count, last_seen_at = EXCLUDED.last_seen_at",
                        {text_array(qn), text_array(qp), text_array(qe), text_array(qdc), now})
                        .status() != PGRES_COMMAND_OK)
                    return false;
            }
            if (!dn.empty()) {
                if (abort_requested())
                    return false;
                if (exec_logged(c, "queue delete",
                        "DELETE FROM product_registry_store.curation_queue "
                        "WHERE (raw_name, raw_publisher, ecosystem) IN "
                        "  (SELECT a, b, c FROM unnest($1::text[], $2::text[], $3::text[]) "
                        "     AS t(a, b, c))",
                        {text_array(dn), text_array(dp), text_array(de)})
                        .status() != PGRES_COMMAND_OK)
                    return false;
            }
            inner = PassOutcome::ok;
            return true;
        });
    } catch (const std::exception& ex) {
        spdlog::error("SoftwareTitleDimension: pass threw ({})", ex.what());
        return out; // failed
    } catch (...) {
        spdlog::error("SoftwareTitleDimension: pass threw an unknown exception");
        return out;
    }

    if (!ok) {
        out.outcome = (inner == PassOutcome::cancelled || inner == PassOutcome::timed_out)
                          ? inner
                          : PassOutcome::failed;
        if (out.outcome == PassOutcome::timed_out)
            spdlog::warn("SoftwareTitleDimension: pass exceeded its {} s budget (elapsed {} s) - "
                         "rolled back",
                         budget.count(),
                         std::chrono::duration_cast<std::chrono::seconds>(
                             std::chrono::steady_clock::now() - started)
                             .count());
        return out;
    }
    out.outcome = inner;
    if (inner == PassOutcome::ok) {
        out.processed = processed;
        out.normalized = normalized;
        out.unnormalized = unnormalized;
    }
    return out;
}

bool SoftwareTitleDimension::reconcile_queue(const std::function<bool()>& cancelled) {
    try {
        return pool_.with_txn_for(kAcquireTimeout, [&](PGconn* c) -> bool {
            if (!set_statement_timeout(c))
                return false;
            const auto locked = try_norm_lock(c);
            if (!locked)
                return false;
            if (!*locked)
                return true; // a peer is normalising; it reconciles
            if (cancelled && cancelled())
                return false;
            // ponytail: one set-based UPDATE over the whole queue; partition it if the
            // queue ever exceeds ~10^5 rows.
            const std::string now = std::to_string(now_secs());
            if (exec_logged(c, "queue refresh",
                            "UPDATE product_registry_store.curation_queue q "
                            "SET device_count = t.device_count, last_seen_at = $1::bigint "
                            "FROM software_inventory_store.title_triples t "
                            "WHERE q.raw_name = t.name AND q.raw_publisher = t.publisher "
                            "  AND q.ecosystem = t.ecosystem",
                            {now})
                    .status() != PGRES_COMMAND_OK)
                return false;
            if (cancelled && cancelled())
                return false;
            // Re-queue: a title that was pruned while absent and has returned. Its dimension
            // row is permanent and current-pack 'unnormalized', so no pass candidate selects it
            // again; this is the only path that restores its open row. A stale-pack row is left
            // to the pass (it re-resolves and queues or deletes itself). DO NOTHING keeps a
            // 'rejected' row rejected and an existing open row as the UPDATE above left it.
            if (exec_logged(c, "queue requeue",
                            "INSERT INTO product_registry_store.curation_queue "
                            "(raw_name, raw_publisher, ecosystem, device_count, status, "
                            " first_queued_at, last_seen_at) "
                            "SELECT t.name, t.publisher, t.ecosystem, t.device_count, 'open', "
                            "       $1::bigint, $1::bigint "
                            "FROM software_inventory_store.title_triples t "
                            "JOIN product_registry_store.title_dimension d "
                            "  ON (d.raw_name, d.raw_publisher, d.ecosystem) = "
                            "     (t.name, t.publisher, t.ecosystem) "
                            "WHERE d.norm_status = 'unnormalized' "
                            "  AND d.pack_version = (SELECT pack_version FROM "
                            "       product_registry_store.normalization_pack WHERE id = 1) "
                            "ON CONFLICT (raw_name, raw_publisher, ecosystem) DO NOTHING",
                            {now})
                    .status() != PGRES_COMMAND_OK)
                return false;
            if (cancelled && cancelled())
                return false;
            return exec_logged(c, "queue prune",
                               "DELETE FROM product_registry_store.curation_queue q "
                               "WHERE q.status = 'open' AND NOT EXISTS ("
                               "  SELECT 1 FROM software_inventory_store.title_triples t "
                               "  WHERE t.name = q.raw_name AND t.publisher = q.raw_publisher "
                               "    AND t.ecosystem = q.ecosystem)",
                               {})
                       .status() == PGRES_COMMAND_OK;
        });
    } catch (const std::exception& ex) {
        spdlog::error("SoftwareTitleDimension: queue reconcile threw ({})", ex.what());
        return false;
    } catch (...) {
        return false;
    }
}

void SoftwareTitleDimension::refresh_gauges() {
    if (metrics_ == nullptr)
        return;
    std::array<std::int64_t, 3> titles{0, 0, 0}; // normalized, unnormalized, pending
    std::array<std::int64_t, 3> devices{0, 0, 0};
    std::int64_t queue_open = 0;
    std::string pack_version;
    bool ok = false;
    try {
        ok = pool_.with_txn_for(kAcquireTimeout, [&](PGconn* c) -> bool {
            if (pg::PgResult iso{PQexec(c, "SET TRANSACTION ISOLATION LEVEL REPEATABLE READ")};
                iso.status() != PGRES_COMMAND_OK)
                return log_failed("isolation", iso);
            pg::PgResult g = pg::exec_params(
                c,
                "SELECT COALESCE(d.norm_status, 'pending'), count(*), "
                "       COALESCE(sum(t.device_count), 0) "
                "FROM software_inventory_store.title_triples t "
                "LEFT JOIN product_registry_store.title_dimension d "
                "  ON (d.raw_name, d.raw_publisher, d.ecosystem) = (t.name, t.publisher, t.ecosystem) "
                "GROUP BY 1",
                std::vector<std::string>{});
            if (g.status() != PGRES_TUPLES_OK)
                return log_failed("gauge titles", g);
            for (int i = 0; i < PQntuples(g.get()); ++i) {
                const std::string_view s = PQgetvalue(g.get(), i, 0);
                const std::size_t slot = s == "normalized" ? 0 : s == "unnormalized" ? 1 : 2;
                titles[slot] += cell_i64(g, i, 1);
                devices[slot] += cell_i64(g, i, 2);
            }
            pg::PgResult q = pg::exec_params(
                c,
                "SELECT (SELECT count(*) FROM product_registry_store.curation_queue "
                "        WHERE status = 'open'), "
                "       COALESCE((SELECT pack_version FROM product_registry_store.normalization_pack "
                "                 WHERE id = 1), '')",
                std::vector<std::string>{});
            if (q.status() != PGRES_TUPLES_OK || PQntuples(q.get()) != 1)
                return log_failed("gauge queue", q);
            queue_open = cell_i64(q, 0, 0);
            pack_version = PQgetvalue(q.get(), 0, 1);
            return true;
        });
    } catch (const std::exception& ex) {
        spdlog::warn("SoftwareTitleDimension: gauge refresh threw ({}) - previous values kept",
                     ex.what());
        return;
    } catch (...) {
        spdlog::warn("SoftwareTitleDimension: gauge refresh threw an unknown exception - "
                     "previous values kept");
        return;
    }
    if (!ok) {
        // A failed statement already logged itself; an unavailable lease did not.
        spdlog::warn("SoftwareTitleDimension: gauge refresh failed (lease or statement, see any "
                     "preceding line) - previous values kept");
        return; // keep the previous values - never a false zero
    }

    static constexpr std::array<const char*, 3> kStatus{"normalized", "unnormalized", "pending"};
    for (std::size_t i = 0; i < kStatus.size(); ++i)
        metrics_->gauge("yuzu_software_titles", {{"norm_status", kStatus[i]}})
            .set(static_cast<double>(titles[i]));
    const std::int64_t total_devices = devices[0] + devices[1] + devices[2];
    metrics_->gauge("yuzu_software_unnormalized_ratio")
        .set(total_devices == 0 ? 0.0
                                : static_cast<double>(devices[1] + devices[2]) /
                                      static_cast<double>(total_devices));
    metrics_->gauge("yuzu_software_normalization_curation_queue_size")
        .set(static_cast<double>(queue_open));
    if (!last_pack_version_label_.empty() && last_pack_version_label_ != pack_version)
        metrics_->gauge("yuzu_software_normalization_pack_info",
                        {{"pack_version", last_pack_version_label_}})
            .set(0);
    if (!pack_version.empty())
        metrics_->gauge("yuzu_software_normalization_pack_info", {{"pack_version", pack_version}})
            .set(1);
    last_pack_version_label_ = pack_version;
}

TickResult SoftwareTitleDimension::run_tick(const std::function<bool()>& cancelled,
                                            int max_passes) {
    TickResult tick;
    const auto stop = [&] { return cancelled && cancelled(); };
    for (int pass = 0; pass < max_passes; ++pass) {
        if (stop()) {
            tick.cancelled = true;
            break;
        }
        const PassResult r = run_pass(cancelled);
        ++tick.passes;
        tick.processed += r.processed;
        if (r.outcome == PassOutcome::cancelled) {
            tick.cancelled = true;
            break;
        }
        if (r.outcome == PassOutcome::failed || r.outcome == PassOutcome::timed_out ||
            r.outcome == PassOutcome::no_pack) {
            tick.errored = true;
            break;
        }
        if (r.outcome == PassOutcome::skipped_peer || r.processed < kPassLimit)
            break; // a peer is normalising, or a short page: nothing left to do
        if (pass + 1 == max_passes)
            tick.capped = true; // a full page on the last allowed pass: a backlog remains
    }
    if (!tick.cancelled && !stop()) {
        if (!reconcile_queue(cancelled) && !stop())
            tick.errored = true;
    }
    if (stop())
        tick.cancelled = !tick.errored;
    tick.capped = tick.capped && !tick.errored && !tick.cancelled;
    // A shutdown cancel skips the gauges: they keep their last values (the same posture as a
    // degraded read) and the stop path avoids a lease plus the title_triples join.
    if (!tick.cancelled)
        refresh_gauges();
    return tick;
}

} // namespace yuzu::server
