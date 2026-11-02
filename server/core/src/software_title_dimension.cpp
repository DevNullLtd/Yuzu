/// @file software_title_dimension.cpp
/// Pure title resolution + the cross-store normalisation pass. See the header.

#include "software_title_dimension.hpp"

#include "pg/pg_array.hpp"
#include "pg/pg_exec.hpp"
#include "pg/pg_pool.hpp"
#include "pg/pg_raii.hpp"
#include "software_inventory_store.hpp"
#include "software_normalization_pack.hpp"

#include <yuzu/metrics.hpp>

#include <libpq-fe.h>
#include <spdlog/spdlog.h>

#include <algorithm>
#include <array>
#include <cstdlib>
#include <exception>
#include <set>
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

const char* tier_name(MatchTier t) {
    switch (t) {
    case MatchTier::exact_norm:
        return "exact_norm";
    case MatchTier::title_vendor:
        return "title_vendor";
    case MatchTier::token_set:
        return "token_set";
    case MatchTier::birth:
        break;
    }
    return "birth";
}

/// Statement failure -> one structured log line carrying the SQLSTATE.
bool log_failed(std::string_view label, const pg::PgResult& r) {
    const char* state = PQresultErrorField(r.get(), PG_DIAG_SQLSTATE);
    const std::string_view err = PQresultErrorMessage(r.get());
    spdlog::warn("SoftwareTitleDimension: '{}' failed (sqlstate {}): {}", label,
                 state ? state : "-", err.empty() ? "unexpected result shape" : err);
    return false;
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

ProductIndex::ProductIndex(std::vector<ProductRow> products) : products_(std::move(products)) {
    candidates_.reserve(products_.size());
    for (std::size_t i = 0; i < products_.size(); ++i) {
        candidates_.push_back({products_[i].norm_key, products_[i].title, products_[i].vendor});
        by_key_.emplace(products_[i].norm_key, i);
    }
}

const ProductRow* ProductIndex::find(std::string_view norm_key) const {
    const auto it = by_key_.find(std::string{norm_key});
    return it == by_key_.end() ? nullptr : &products_[it->second];
}

TitleResolution resolve_title(const TitleKey& key,
                              const std::vector<NormalizationAliasRow>& aliases_for_key,
                              const ProductIndex& products, bool auto_birth) {
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

    // Matcher fallback. EDITION GUARD: title_vendor/token_set relate editions across
    // SKUs by design (right for the SLE matcher, wrong for an identity dimension), so a
    // hit on a product of a different edition is treated as no match.
    const MatchResult m = match_product(key.raw_name, key.raw_publisher, products.candidates());
    if (m.tier != MatchTier::birth) {
        if (const ProductRow* p = products.find(m.norm_key); p != nullptr && p->edition == nt.edition) {
            adopt(*p, tier_name(m.tier));
            return out;
        }
    }

    if (auto_birth && !nv.empty() && token_count(nt.title) >= kAutoBirthMinTokens) {
        out.norm_status = "normalized";
        out.method = "birth";
        return out;
    }
    return out; // labelled unnormalized, never guessed
}

// ── owner ────────────────────────────────────────────────────────────────────

SoftwareTitleDimension::SoftwareTitleDimension(pg::PgPool& pool, ProductRegistryStore& registry,
                                               SoftwareInventoryStore& inventory,
                                               yuzu::MetricsRegistry* metrics)
    : pool_(pool), registry_(registry), inventory_(inventory), metrics_(metrics) {}

PassResult SoftwareTitleDimension::run_pass(const std::function<bool()>& cancelled) {
    PassResult out;
    PassOutcome inner = PassOutcome::failed;
    int processed = 0;
    int normalized = 0;
    int unnormalized = 0;

    const auto started = std::chrono::steady_clock::now();
    const auto deadline = started + kPassBudget;
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
            const auto run = [&](const char* label, const char* sql,
                                 const std::vector<std::string>& params) -> pg::PgResult {
                pg::PgResult r = pg::exec_params(c, sql, params);
                if (r.status() != PGRES_COMMAND_OK && r.status() != PGRES_TUPLES_OK)
                    log_failed(label, r);
                return r;
            };
            if (run("statement_timeout", "SET LOCAL statement_timeout = '60s'", {}).status() !=
                PGRES_COMMAND_OK)
                return false;

            // Cluster-wide single writer: a peer holding the lock is already normalising.
            pg::PgResult lk = run("advisory lock",
                                  "SELECT pg_try_advisory_xact_lock(hashtextextended("
                                  "'software_normalization', 0))",
                                  {});
            if (lk.status() != PGRES_TUPLES_OK)
                return false;
            if (PQntuples(lk.get()) == 1 && std::string_view(PQgetvalue(lk.get(), 0, 0)) == "f") {
                inner = PassOutcome::skipped_peer;
                return true;
            }

            pg::PgResult pk =
                run("pack version",
                    "SELECT pack_version FROM product_registry_store.normalization_pack WHERE id = 1",
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
            pg::PgResult cand = run(
                "candidates",
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

            // Alias keys of the batch, then the aliases and the matcher's products on
            // THIS connection (one snapshot-ish transaction, no nested lease).
            std::set<std::string> key_set;
            for (const auto& t : titles)
                key_set.insert(alias_key(normalize_title(t.key.raw_name)));
            const std::vector<std::string> keys(key_set.begin(), key_set.end());
            const std::vector<std::string_view> key_views(keys.begin(), keys.end());
            auto aliases = ProductRegistryStore::read_normalization_aliases(c, key_views);
            if (!aliases)
                return false;
            std::unordered_map<std::string, std::vector<NormalizationAliasRow>> by_key;
            for (auto& a : *aliases)
                by_key[a.raw_name].push_back(std::move(a));
            auto products = ProductRegistryStore::read_products(c, kMatcherCandidateCap);
            if (!products)
                return false;
            if (products->size() >= static_cast<std::size_t>(kMatcherCandidateCap))
                spdlog::warn("SoftwareTitleDimension: product list hit the {}-row matcher cap; "
                             "resolution may miss products",
                             kMatcherCandidateCap);
            const ProductIndex index{std::move(*products)};

            static const std::vector<NormalizationAliasRow> kNoAliases;
            std::vector<TitleResolution> resolved;
            resolved.reserve(titles.size());
            for (std::size_t i = 0; i < titles.size(); ++i) {
                if (i % kCancelCheckEvery == 0 && abort_requested())
                    return false;
                const auto it = by_key.find(alias_key(normalize_title(titles[i].key.raw_name)));
                resolved.push_back(resolve_title(titles[i].key,
                                                 it == by_key.end() ? kNoAliases : it->second,
                                                 index, kAutoBirthEnabled));
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
            if (run("dimension upsert",
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
                    "  pack_version = EXCLUDED.pack_version, updated_at = EXCLUDED.updated_at "
                    "WHERE (title_dimension.norm_status, title_dimension.method, "
                    "       title_dimension.product_id, title_dimension.vendor, "
                    "       title_dimension.product, title_dimension.edition, "
                    "       title_dimension.title_version, title_dimension.category, "
                    "       title_dimension.purl_type, title_dimension.cpe_product, "
                    "       title_dimension.pack_version) "
                    "  IS DISTINCT FROM (EXCLUDED.norm_status, EXCLUDED.method, EXCLUDED.product_id, "
                    "       EXCLUDED.vendor, EXCLUDED.product, EXCLUDED.edition, "
                    "       EXCLUDED.title_version, EXCLUDED.category, EXCLUDED.purl_type, "
                    "       EXCLUDED.cpe_product, EXCLUDED.pack_version)",
                    {text_array(n), text_array(p), text_array(e), text_array(st), text_array(m),
                     text_array(pid), text_array(v), text_array(pr), text_array(ed), text_array(tv),
                     text_array(cat), text_array(pt), text_array(cp), pack_version, now})
                    .status() != PGRES_COMMAND_OK)
                return false;

            if (!qn.empty()) {
                if (abort_requested())
                    return false;
                // status is not in the SET list: a 'rejected' row stays rejected.
                if (run("queue upsert",
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
                if (run("queue delete",
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
                         kPassBudget.count(),
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
            const auto run = [&](const char* label, const char* sql,
                                 const std::vector<std::string>& params) -> pg::PgResult {
                pg::PgResult r = pg::exec_params(c, sql, params);
                if (r.status() != PGRES_COMMAND_OK && r.status() != PGRES_TUPLES_OK)
                    log_failed(label, r);
                return r;
            };
            if (run("statement_timeout", "SET LOCAL statement_timeout = '60s'", {}).status() !=
                PGRES_COMMAND_OK)
                return false;
            pg::PgResult lk = run("reconcile lock",
                                  "SELECT pg_try_advisory_xact_lock(hashtextextended("
                                  "'software_normalization', 0))",
                                  {});
            if (lk.status() != PGRES_TUPLES_OK)
                return false;
            if (PQntuples(lk.get()) == 1 && std::string_view(PQgetvalue(lk.get(), 0, 0)) == "f")
                return true; // a peer is normalising; it reconciles
            if (cancelled && cancelled())
                return false;
            // ponytail: one set-based UPDATE over the whole queue; partition it if the
            // queue ever exceeds ~10^5 rows.
            if (run("queue refresh",
                    "UPDATE product_registry_store.curation_queue q "
                    "SET device_count = t.device_count, last_seen_at = $1::bigint "
                    "FROM software_inventory_store.title_triples t "
                    "WHERE q.raw_name = t.name AND q.raw_publisher = t.publisher "
                    "  AND q.ecosystem = t.ecosystem",
                    {std::to_string(now_secs())})
                    .status() != PGRES_COMMAND_OK)
                return false;
            if (cancelled && cancelled())
                return false;
            return run("queue prune",
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
    } catch (...) {
        ok = false;
    }
    if (!ok)
        return; // keep the previous values - never a false zero

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

TickResult SoftwareTitleDimension::run_tick(const std::function<bool()>& cancelled) {
    TickResult tick;
    const auto stop = [&] { return cancelled && cancelled(); };
    for (int pass = 0; pass < kMaxPassesPerTick; ++pass) {
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
    }
    if (!tick.cancelled && !stop()) {
        if (!reconcile_queue(cancelled) && !stop())
            tick.errored = true;
    }
    if (stop())
        tick.cancelled = !tick.errored;
    refresh_gauges();
    return tick;
}

} // namespace yuzu::server
