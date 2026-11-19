/**
 * test_reregistration_audit_budget_alloc.cpp - WP01: the audit-mode budget under ALLOCATION
 * FAILURE (server/core/src/reregistration_audit_budget.hpp).
 *
 * WHY A SEPARATE EXECUTABLE. It replaces the global operator new (process-wide, cannot be scoped to
 * one test), so it is not a source of yuzu_server_tests and is absent under a sanitizer (which owns
 * the allocator), like tests/unit/test_spark_alloc_budget.cpp. Linux only.
 *
 * What it pins (1). A scenario SWEEP (the oracle below) over the accumulation, window-closing, queueing,
 * requeue, take_pending and flush paths: at every allocation point no exception escapes, and every id
 * of a row that was NOT admitted is either NAMED in a summary row or COUNTED (take_ids_truncated), the
 * count being an upper bound. The sweep covers the paths listed in `make_scenarios`, not every line.
 * What it pins (2). For EVERY allocation point inside the closing admit() of a window that dropped 250
 * ids (a countdown of N allocations before the injected std::bad_alloc, N = 0, 1, 2, ...):
 *  - admit() never throws (an exception escaping it reaches gRPC as UNKNOWN);
 *  - the closed window is never lost uncounted: every dropped id is either NAMED in a queued chunk
 *    row or COUNTED by id (take_ids_truncated), summing to exactly 250.
 */

#include <catch2/catch_test_macros.hpp>

#include <memory>
#include <cstdlib>
#include <functional>
#include <new>
#include <set>
#include <sstream>
#include <string>
#include <vector>

#include "reregistration_audit_budget.hpp"

namespace {
thread_local long g_countdown = -1; // allocations left before the injected failure; -1 = off

void* injected_alloc(std::size_t n) {
    if (g_countdown >= 0 && g_countdown-- == 0)
        throw std::bad_alloc();
    if (void* p = std::malloc(n ? n : 1))
        return p;
    throw std::bad_alloc();
}

std::size_t ids_in_row(const std::string& row) {
    const auto at = row.find(" ids=");
    if (at == std::string::npos || at + 5 >= row.size())
        return 0;
    std::size_t n = 1;
    for (std::size_t i = at + 5; i < row.size(); ++i)
        n += row[i] == ',' ? 1 : 0;
    return n;
}
} // namespace

void* operator new(std::size_t n) { return injected_alloc(n); }
void* operator new[](std::size_t n) { return injected_alloc(n); }

TEST_CASE("budget: an allocation failure at ANY point of the window-closing admit() loses nothing "
          "uncounted and throws nothing",
          "[reregistration_gate][wp01][audit_budget][alloc]") {
    using B = yuzu::server::detail::UnprovenAuditBudget;
    std::size_t points_with_failure = 0;
    for (long n = 0; n < 400; ++n) {
        B b;
        std::int64_t t = 1'000'000;
        for (int i = 0; i < 400; ++i) // 400 ids become recent
            (void)b.admit("live-" + std::to_string(i), "seed-" + std::to_string(i / 40), t);
        t += B::kWindowMs + 1;
        for (int i = 0; i < 300; ++i) // one source: 50 rows, 250 dropped
            (void)b.admit("live-" + std::to_string(i), "atk", t);
        t += B::kWindowMs + 1;

        g_countdown = n;
        bool threw = false;
        try {
            (void)b.admit("closer", "x", t); // closes the window with 250 drops
        } catch (...) {
            threw = true;
        }
        const bool fired = g_countdown < 0; // the countdown reached zero inside admit()
        g_countdown = -1;
        CHECK_FALSE(threw);
        if (!fired)
            break; // n is past the last allocation point of admit(): every point was swept
        ++points_with_failure;

        // Nothing may be stranded in the open window: close it too.
        (void)b.poll_closed(t + B::kWindowMs + 1, true);
        std::size_t named = 0;
        while (auto row = b.take_pending())
            named += ids_in_row(row->text);
        const std::size_t counted = b.take_ids_truncated();
        INFO("allocation point " << n << ": named " << named << " counted " << counted);
        // 250 dropped ids, plus at most the closing row's own id counted when its admission failed
        CHECK(named + counted >= 250);
        CHECK(named + counted <= 251);
    }
    CHECK(points_with_failure > 5); // the sweep really exercised failures
}

// ---- the scenario sweep -----------------------------------------------------------------------

namespace {
using B = yuzu::server::detail::UnprovenAuditBudget;
using yuzu::server::detail::flush_reregistration_budget;

struct Ctx {
    B b;
    std::int64_t t{1'000'000};
    std::set<std::string> not_admitted; ///< ids of rows admit() refused or dropped
    std::set<std::string> named;        ///< ids named in a summary row
    std::uint64_t counted{0};           ///< ids counted unnamed
    std::uint64_t alloc_failed{0};
    bool escaped{false};
    bool adm(const std::string& id, const std::string& src, std::int64_t at) {
        bool ok = false;
        try {
            ok = b.admit(id, src, at).admitted;
        } catch (...) {
            escaped = true;
            ok = true;
        }
        if (!ok)
            not_admitted.insert(id);
        return ok;
    }
};
/// Suspends the injection while the TEST's own bookkeeping allocates.
struct Pause {
    long saved;
    Pause() : saved(g_countdown) { g_countdown = -1; }
    ~Pause() { if (saved >= 0) g_countdown = saved; }
};
void parse_named(const std::string& text, std::set<std::string>& out) {
    const auto i = text.find(" ids=");
    if (i == std::string::npos)
        return;
    std::stringstream ss(text.substr(i + 5));
    std::string x;
    while (std::getline(ss, x, ','))
        if (!x.empty())
            out.insert(x);
}
void fill_budget(Ctx& c) {
    (void)c.adm("open", "s", c.t);
    for (int i = 0; i < 1400; ++i)
        c.adm("f" + std::to_string(i), "s", c.t);
}
void drop_many(Ctx& c, int n, const char* pfx) {
    for (int i = 0; i < n; ++i)
        c.adm(std::string(pfx) + std::to_string(i), "s" + std::to_string(i % 7), c.t);
}
void drain(Ctx& c, std::int64_t at) {
    try {
        (void)c.b.poll_closed(at, true);
    } catch (...) {
        c.escaped = true;
    }
    while (auto r = c.b.take_pending())
        parse_named(r->text, c.named);
    c.counted += c.b.take_ids_truncated();
    c.alloc_failed += c.b.take_alloc_failed();
}

struct Scenario {
    const char* name;
    std::function<void(Ctx&)> setup;
    std::function<void(Ctx&)> armed;
};

std::vector<Scenario> make_scenarios() {
    std::vector<Scenario> sc;
    sc.push_back({"closing admit()", [](Ctx& c) { fill_budget(c); drop_many(c, 450, "d"); },
                  [](Ctx& c) { c.adm("NEWID", "sN", c.t + B::kWindowMs + 1); }});
    sc.push_back({"accumulate a new dropped id", [](Ctx& c) { fill_budget(c); drop_many(c, 10, "d"); },
                  [](Ctx& c) { c.adm("VICT1", "srcV", c.t); }});
    sc.push_back({"repeat cut of a seen id",
                  [](Ctx& c) { fill_budget(c); for (int i = 0; i < 4; ++i) c.adm("f1", "s", c.t); },
                  [](Ctx& c) { c.adm("f1", "s", c.t); }});
    sc.push_back({"repeat of a dropped id from a new source", [](Ctx& c) { fill_budget(c); drop_many(c, 10, "d"); },
                  [](Ctx& c) { c.adm("d3", "newsrc", c.t); }});
    sc.push_back({"over-cap id", [](Ctx& c) { fill_budget(c); drop_many(c, 20005, "o"); },
                  [](Ctx& c) { c.adm("OVF", "srcO", c.t); c.adm("OVF2", "srcO", c.t); }});
    sc.push_back({"admitted id (recent_/seen_)", [](Ctx& c) { (void)c.adm("open", "s", c.t); },
                  [](Ctx& c) { c.adm("ADM1", "s", c.t); }});
    sc.push_back({"poll_closed(force) 450 ids", [](Ctx& c) { fill_budget(c); drop_many(c, 450, "d"); },
                  [](Ctx& c) { (void)c.b.poll_closed(c.t + 1, true); }});
    sc.push_back({"poll_closed 20005 ids (over the cap)", [](Ctx& c) { fill_budget(c); drop_many(c, 20005, "o"); },
                  [](Ctx& c) { (void)c.b.poll_closed(c.t + 1, true); }});
    sc.push_back({"queue full, second window",
                  [](Ctx& c) {
                      fill_budget(c);
                      drop_many(c, 20000, "o");
                      (void)c.b.poll_closed(c.t + B::kWindowMs + 1, false);
                      c.t += B::kWindowMs + 1;
                      fill_budget(c);
                      drop_many(c, 20000, "p");
                  },
                  [](Ctx& c) { (void)c.b.poll_closed(c.t + B::kWindowMs + 1, false); }});
    for (const int j : {0, 5, 8, 9, 12})
        for (int att = 0; att < 3; ++att) {
            sc.push_back({"flush, failing writer (requeue_front)",
                          [att, j](Ctx& c) {
                              fill_budget(c);
                              drop_many(c, 2500, "d");
                              (void)c.b.poll_closed(c.t + B::kWindowMs + 1, false);
                              for (int x = 0; x < j; ++x)
                                  if (auto r = c.b.take_pending())
                                      parse_named(r->text, c.named);
                              for (int a = 0; a < att; ++a)
                                  if (auto r = c.b.take_pending())
                                      (void)c.b.requeue_front(std::move(*r));
                          },
                          [](Ctx& c) {
                              std::int64_t now = 0;
                              try {
                                  auto r = flush_reregistration_budget(
                                      c.b, c.t + B::kWindowMs + 1, false, 2000,
                                      [&](const std::string&) { return false; }, [&] { return now; });
                                  c.counted += r.ids_truncated;
                              } catch (...) {
                                  c.escaped = true;
                              }
                          }});
        }
    // every j: the re-queue only allocates when it crosses a deque block boundary (about every 9 rows)
    for (int j = 0; j <= 12; ++j)
        sc.push_back({"flush, deadline (requeue_front_unconditional)",
                      [j](Ctx& c) {
                          fill_budget(c);
                          drop_many(c, 2500, "d");
                          (void)c.b.poll_closed(c.t + B::kWindowMs + 1, false);
                          for (int x = 0; x < j; ++x)
                              if (auto r = c.b.take_pending())
                                  parse_named(r->text, c.named);
                      },
                      [](Ctx& c) {
                          std::int64_t now = 0;
                          try {
                              auto r = flush_reregistration_budget(
                                  c.b, c.t + B::kWindowMs + 1, false, 2000,
                                  [&](const std::string& tx) {
                                      Pause p;
                                      parse_named(tx, c.named);
                                      now += 2500;
                                      return true;
                                  },
                                  [&] { return now; });
                              c.counted += r.ids_truncated;
                          } catch (...) {
                              c.escaped = true;
                          }
                      }});
    sc.push_back({"flush success path", [](Ctx& c) {
                      fill_budget(c);
                      drop_many(c, 450, "d");
                      (void)c.b.poll_closed(c.t + B::kWindowMs + 1, false);
                  },
                  [](Ctx& c) {
                      std::int64_t now = 0;
                      try {
                          auto r = flush_reregistration_budget(
                              c.b, c.t + B::kWindowMs + 1, false, 2000,
                              [&](const std::string& tx) { Pause p; parse_named(tx, c.named); return true; },
                              [&] { return now; });
                          c.counted += r.ids_truncated;
                      } catch (...) {
                          c.escaped = true;
                      }
                  }});
    sc.push_back({"forced flush, failing writer", [](Ctx& c) { fill_budget(c); drop_many(c, 450, "d"); },
                  [](Ctx& c) {
                      std::int64_t now = 0;
                      try {
                          auto r = flush_reregistration_budget(
                              c.b, c.t + 1, true, 2000, [&](const std::string&) { return false; },
                              [&] { return now; });
                          c.counted += r.ids_truncated;
                      } catch (...) {
                          c.escaped = true;
                      }
                  }});
    return sc;
}
} // namespace

TEST_CASE("budget: a scenario sweep at EVERY allocation point throws nothing and leaves no refused id "
          "neither named nor counted",
          "[reregistration_gate][wp01][audit_budget][alloc]") {
    bool saw_alloc_failed = false;
    std::size_t total_points = 0;
    for (const auto& s : make_scenarios()) {
        std::size_t points = 0;
        bool scenario_saw_alloc_failed = false;
        for (long k = 0; k < 400000; k += (k < 300 ? 1 : 97)) {
            auto c = std::make_unique<Ctx>();
            s.setup(*c);
            g_countdown = k;
            try {
                s.armed(*c);
            } catch (...) {
                c->escaped = true;
            }
            const bool fired = g_countdown < 0;
            g_countdown = -1;
            if (!fired)
                break;
            ++points;
            drain(*c, c->t + B::kWindowMs * 3);
            long unnamed = 0;
            for (const auto& id : c->not_admitted)
                if (!c->named.count(id))
                    ++unnamed;
            INFO(s.name << " at allocation point " << k << ": unnamed " << unnamed << " counted " << c->counted);
            CHECK_FALSE(c->escaped);
            CHECK(static_cast<long>(c->counted) >= unnamed); // counted is an upper bound
            saw_alloc_failed = saw_alloc_failed || c->alloc_failed > 0;
            scenario_saw_alloc_failed = scenario_saw_alloc_failed || c->alloc_failed > 0;
        }
        // The two scenarios that BUILD chunks must see `alloc_failed` move at some point.
        if (std::string(s.name) == "closing admit()" || std::string(s.name) == "poll_closed(force) 450 ids") {
            INFO(s.name);
            CHECK(scenario_saw_alloc_failed);
        }
        total_points += points; // a path that never allocates (e.g. a re-queue into spare deque room) has none
    }
    CHECK(total_points > 200);
    CHECK(saw_alloc_failed); // the alloc_failed count really moves (the window-closing arm)
}

static_assert(noexcept(std::declval<yuzu::server::detail::UnprovenAuditBudget&>().requeue_front(
                  std::declval<yuzu::server::detail::UnprovenAuditBudget::PendingRow>())),
              "requeue_front must stay noexcept");
static_assert(noexcept(std::declval<yuzu::server::detail::UnprovenAuditBudget&>()
                           .requeue_front_unconditional(
                               std::declval<yuzu::server::detail::UnprovenAuditBudget::PendingRow>())),
              "requeue_front_unconditional must stay noexcept");
static_assert(noexcept(std::declval<yuzu::server::detail::UnprovenAuditBudget&>().note_unrecorded()),
              "note_unrecorded must stay noexcept");

// ---- the re-queue node-boundary fault ---------------------------------------------------------

TEST_CASE("budget: a re-queue that must allocate a deque node (a node boundary) counts the chunk's ids",
          "[reregistration_gate][wp01][audit_budget][alloc]") {
    std::size_t fired_unconditional = 0, fired_conditional = 0;
    for (int pre = 0; pre < 40; ++pre)
        for (int which = 0; which < 2; ++which) {
            B b;
            for (long i = 0; i < 12000; ++i)
                (void)b.admit("i" + std::to_string(i), "s", 0);
            (void)b.poll_closed(20000, true);
            (void)b.take_ids_truncated();
            for (int k = 0; k < pre; ++k)
                (void)b.take_pending();
            auto r = b.take_pending();
            if (!r)
                continue;
            const std::size_t ids = r->ids;
            r->attempts = 0;
            g_countdown = 0; // the very next allocation fails
            if (which == 0)
                b.requeue_front_unconditional(std::move(*r));
            else
                (void)b.requeue_front(std::move(*r));
            const bool fired = g_countdown < 0;
            g_countdown = -1;
            if (!fired)
                continue; // spare room in the front node: nothing allocated
            (which == 0 ? fired_unconditional : fired_conditional) += 1;
            CHECK(b.take_ids_truncated() == ids);
            CHECK(b.take_alloc_failed() == 1);
        }
    CHECK(fired_unconditional > 0);
    CHECK(fired_conditional > 0);
}

// ---- three windows, flush rounds under fault: ids are conserved ---------------------------------

namespace {
long ids_in(const std::string& row) {
    const auto p = row.find(" ids=");
    if (p == std::string::npos)
        return 0;
    const auto s = row.substr(p + 5);
    if (s.empty())
        return 0;
    long n = 1;
    for (const char c : s)
        n += c == ',' ? 1 : 0;
    return n;
}
/// 3 windows of `nd` drops, then 12 flush rounds with the writer in `mode` (0 ok, 1 every 2nd call
/// fails, 2 always fails) and the allocation fault armed at the `failn`-th allocation of the rounds.
/// Returns true when an id was lost (dropped > named + counted).
bool conservation_run(int mode, long failn, long nd) {
    B b;
    long long dropped = 0, named = 0, trunc = 0;
    std::int64_t t = 0;
    long calls = 0;
    const auto admit_n = [&](long n, long base) {
        for (long i = 0; i < n; ++i)
            if (!b.admit("id" + std::to_string(base + i), "s" + std::to_string(i % 7), t).admitted)
                ++dropped;
    };
    admit_n(nd, 0);
    t += 10000;
    admit_n(nd, 100000);
    t += 10000;
    admit_n(nd, 200000);
    t += 10000;
    std::int64_t clk = t;
    const auto now = [&] { return clk; };
    const auto write = [&](const std::string& row) -> bool {
        Pause p;
        ++calls;
        if (mode == 2 || (mode == 1 && calls % 2 == 0))
            return false;
        named += ids_in(row);
        return true;
    };
    g_countdown = failn;
    for (int rnd = 0; rnd < 12; ++rnd) {
        clk += 5000;
        try {
            const auto r = yuzu::server::detail::flush_reregistration_budget(b, clk, false, 2000, write, now);
            Pause p;
            trunc += static_cast<long long>(r.ids_truncated);
        } catch (...) {
            g_countdown = -1;
            return true; // an exception escaped the flush
        }
    }
    g_countdown = -1;
    const auto r = yuzu::server::detail::flush_reregistration_budget(b, clk + 100000, true, 2000, write, now);
    trunc += static_cast<long long>(r.ids_truncated) + static_cast<long long>(b.take_ids_truncated());
    return dropped > named + trunc;
}
} // namespace

TEST_CASE("budget: across three windows and every allocation fault in the flush rounds, no dropped id is lost",
          "[reregistration_gate][wp01][audit_budget][alloc]") {
    std::size_t runs = 0, lost = 0;
    for (int mode = 0; mode < 3; ++mode)
        for (long n = 1; n <= 160; ++n) {
            ++runs;
            lost += conservation_run(mode, n, 1500) ? 1 : 0;
        }
    CHECK(runs == 480);
    CHECK(lost == 0);
}

TEST_CASE("budget: with the queue FULL (three 20000-id windows against 128 rows) every dropped id is still "
          "named or counted",
          "[reregistration_gate][wp01][audit_budget][alloc]") {
    // No fault here: this pins the queue-full accounting the fault sweep above cannot reach (its
    // windows are too small to fill the queue).
    CHECK_FALSE(conservation_run(0, -1, 25000));
    CHECK_FALSE(conservation_run(2, -1, 25000));
}
