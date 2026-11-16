/**
 * test_census_pair_harness.cpp : UP-14 server PR B, commit B4: the randomised schedule-exploration
 * harness for the census ORDER decision on the agent's (boot_epoch, emit_seq) pair (#5690).
 *
 * Needs a Postgres database (YUZU_TEST_POSTGRES_DSN); without one the Postgres case SKIPS, so a
 * run with no DSN proves nothing.
 *
 * WHAT IT DOES. For each seed the harness generates a delivery schedule (first deliveries, lost
 * events replayed as 0/0, failed census writes, redeliveries), runs it through a C++ port of the
 * executable model of the regime machine, then replays the SAME schedule through the real
 * GuaranteedStateStore one delivery at a time. After EVERY delivery it compares the model's
 * census rows, pending set and agent order row (epoch, sequence mark, retired epoch, all seven
 * counters) with the database's, and the decision label the delivery counted. The model is the
 * oracle: a mismatch is a disagreement between the model and the SQL for the reader to
 * adjudicate, and no expectation here is loosened to make a seed pass. Because equality is
 * checked after every delivery, the model's per-arrival invariants (no apply reversal, a clean
 * paired row holds the greatest pair, truth != row implies flagged) hold of the SQL exactly where
 * they hold of the model.
 *
 * WHAT THIS IS, PLAINLY. A differential against a ported model; invariants are not asserted here.
 * The model is the oracle for every expected value, so a bug the model shares with the SQL is not
 * found by this file, and an invariant (no apply reversal, a clean paired row holds the greatest
 * pair, truth != row implies flagged) is checked only through "the SQL equals the model".
 *
 * NOT COVERED. No second stamping sender and no fresh-pair gap repair (the generator never makes
 * either), no `delete_rule`, no `delete_agent`, and no commit-visibility schedule (the F6-A case:
 * a pending event that commits after a newer verdict; it is a fixed case in
 * test_census_pair_order.cpp). Stored clocks are never in the database's future, so the
 * future-slack arm of the freshness test is not reached. The simulated clock is only accurate to
 * about 60 s (the real clock runs while the model's does not). The threaded pairs prove same-agent
 * serialisation only, not an interleaving of different agents. Keys are never capped or zero.
 *
 * WHERE THE EXPECTED VALUES COME FROM. The model of record is the C++ in this file. It is a port
 * of the original Python model, `pend.Store("plan", REC2)` with the generator `pend.gen_actions`
 * over `ext.gen2`, and of CPython's Mersenne Twister, so that `random.Random(seed)` and this file
 * draw the same numbers. The Python sources are NOT in the tree (nothing ran them): they are at
 * commit d96b0e54a3 of PR #8011 under tests/unit/server/pair_model/ (`git show
 * d96b0e54a3:tests/unit/server/pair_model/README.md`), where `harness_digests.py` produced the table.
 * The port is held to that original by the case "census pair harness: the C++ port agrees with the
 * Python model": it needs no database, and compares an FNV-style digest (see `fnv1a`) of the first
 * 64 seeds' schedules and model traces with the table `kPythonDigests` (from the canonical forms
 * `schedule_text` and `snap_text` below). What the table pins from here on is THIS FILE: a change
 * to the generator or the model changes a digest and fails that case. An intended change is made
 * on purpose, by updating the digests from the values the failing CHECKs print, in the same change
 * as the model edit and with the reason stated; the independent Python cross-check is no longer
 * run, so such a change is reviewed on the model's merits.
 *
 * SEEDS AND REPLAY. A seed is the Python seed, so seed 17 here is `random.Random(17)` there.
 *   YUZU_TEST_PAIR_HARNESS_SEEDS=N  runs seeds 0..N-1 (default 64; a campaign of
 *                                   thousands of seeds, or a mutation hunt, widens it)
 *   YUZU_TEST_PAIR_HARNESS_ONLY=S   runs seed S alone, with the full schedule printed
 * To replay a failure: YUZU_TEST_POSTGRES_DSN=... YUZU_TEST_PAIR_HARNESS_ONLY=<seed> \
 *   yuzu_server_tests "census pair harness: seeds replayed through the store*"
 * On a mismatch the output names the seed, the campaign, the schedule (steps in readable form),
 * the first step whose state differs, and the expected and actual state side by side. The seed
 * stops at its first differing STATE (a later step would only repeat it); a decision-label
 * mismatch is reported once per seed and does not stop it.
 * YUZU_TEST_PAIR_HARNESS_DECISIONS=0 leaves the decision-label comparison out (the metric family
 * `yuzu_server_guardian_census_pair_decisions_total` arrives with the census SQL; before it, every
 * label would read as a mismatch and hide the verdict comparison).
 *
 * THE SCHEDULE. Five campaigns (seed % 5): all faults, failures 10 %, pending-heavy with clock
 * steps, equal-epoch restarts (KV wipe; the axis the duplicate-counting mutant needs), and late
 * old-boot deliveries. Two or three rules per agent (seed / 5 % 2). Time is simulated: a stored
 * database-clock column is shifted back by the elapsed seconds before each delivery, which is
 * exactly what the clock reads as later; there is no sleep. Where a clock comparison would sit
 * within 15 s of the one-hour window (the real clock keeps running while the model's does not),
 * every later receipt is moved 31 s later, in the model and the replay alike: a harness
 * adaptation, applied after the digests above are taken.
 *
 * FAILURES. A failing census write is a trigger on the census table (a delivery always writes its
 * row, so it always fails); a failing Repair holds the agent's order row so the Repair's clock read
 * times out (its decision may write no census row, so a trigger would not make it fail).
 *
 * CONCURRENCY. About one seed in seven (seed % 7 == 3) runs some adjacent delivery pairs on two
 * threads: the first delivery is parked at the census lock barrier, the second must park behind it
 * on the agent's order row, and the pair must end as the serial schedule does (the same agent's
 * deliveries serialise on that row). The second delivery then carries the first's receipt time,
 * because the clock cannot be shifted while a row is held.
 */

#include "guaranteed_state_store.hpp"
#include "pg/pg_exec.hpp"
#include "pg/pg_pool.hpp"
#include "pg/pg_raii.hpp"
#include "../test_helpers.hpp"
#include "../test_log_capture.hpp"

#include <yuzu/metrics.hpp>

#include <catch2/catch_test_macros.hpp>
#include <catch2/generators/catch_generators.hpp>
#include <catch2/generators/catch_generators_range.hpp>

#include <libpq-fe.h>

#include <algorithm>
#include <array>
#include <atomic>
#include <cerrno>
#include <chrono>
#include <cstdint>
#include <cstdlib>
#include <future>
#include <limits>
#include <map>
#include <memory>
#include <optional>
#include <sstream>
#include <stdexcept>
#include <string>
#include <thread>
#include <utility>
#include <vector>

using namespace yuzu::server;
using yuzu::server::pg::PgPool;
namespace pg = yuzu::server::pg;

namespace {

using i64 = std::int64_t;
using Pair = std::pair<i64, i64>;

// ── CPython's random.Random, for the integer seeds used here ─────────────────────────────────

class PyRandom {
public:
    explicit PyRandom(std::uint32_t seed) {
        init_genrand(19650218U);
        const std::uint32_t key[1] = {seed};
        std::size_t i = 1, j = 0;
        for (std::size_t k = 624; k > 0; --k) {
            mt_[i] = (mt_[i] ^ ((mt_[i - 1] ^ (mt_[i - 1] >> 30)) * 1664525U)) + key[j] +
                     static_cast<std::uint32_t>(j);
            ++i;
            ++j;
            if (i >= 624) {
                mt_[0] = mt_[623];
                i = 1;
            }
            if (j >= 1)
                j = 0;
        }
        for (std::size_t k = 623; k > 0; --k) {
            mt_[i] = (mt_[i] ^ ((mt_[i - 1] ^ (mt_[i - 1] >> 30)) * 1566083941U)) -
                     static_cast<std::uint32_t>(i);
            ++i;
            if (i >= 624) {
                mt_[0] = mt_[623];
                i = 1;
            }
        }
        mt_[0] = 0x80000000U;
        idx_ = 624;
    }
    double random() {
        const std::uint32_t a = next() >> 5, b = next() >> 6;
        return (a * 67108864.0 + b) * (1.0 / 9007199254740992.0);
    }
    // random.randint(lo, hi) == lo + _randbelow(hi - lo + 1)
    i64 randint(i64 lo, i64 hi) { return lo + below(hi - lo + 1); }
    i64 randrange(i64 n) { return below(n); }
    template <class T> T choice(const std::vector<T>& v) {
        return v[static_cast<std::size_t>(below(static_cast<i64>(v.size())))];
    }

private:
    void init_genrand(std::uint32_t s) {
        mt_[0] = s;
        for (std::uint32_t i = 1; i < 624; ++i)
            mt_[i] = 1812433253U * (mt_[i - 1] ^ (mt_[i - 1] >> 30)) + i;
    }
    std::uint32_t next() {
        if (idx_ >= 624) {
            for (int k = 0; k < 624; ++k) {
                const std::uint32_t y =
                    (mt_[k] & 0x80000000U) | (mt_[(k + 1) % 624] & 0x7fffffffU);
                mt_[k] = mt_[(k + 397) % 624] ^ (y >> 1) ^ ((y & 1U) ? 0x9908b0dfU : 0U);
            }
            idx_ = 0;
        }
        std::uint32_t y = mt_[idx_++];
        y ^= y >> 11;
        y ^= (y << 7) & 0x9d2c5680U;
        y ^= (y << 15) & 0xefc60000U;
        y ^= y >> 18;
        return y;
    }
    // _randbelow_with_getrandbits: k = n.bit_length(), draw k bits until below n.
    i64 below(i64 n) {
        int k = 0;
        for (i64 t = n; t > 0; t >>= 1)
            ++k;
        i64 r = next() >> (32 - k);
        while (r >= n)
            r = next() >> (32 - k);
        return r;
    }
    std::array<std::uint32_t, 624> mt_{};
    int idx_{624};
};

// ── The schedule generator (ext.gen2 and pend.gen_actions) ─────────────────────────────────────

constexpr i64 kStale = 3600, kSlack = 300, kCap = 300;

struct Ev {
    int id{0};
    int rule{0};
    char state{'C'};
    i64 ts{0};
    std::optional<Pair> pair;
};
enum class Kind { First, Repair };
struct Action {
    Kind kind{Kind::First};
    i64 at{0};
    Ev ev;      // First
    int ref{0}; // Repair: the id of the event redelivered
    bool fail{false};
};

struct Campaign {
    const char* name;
    double p_fail, p_lost, p_step, p_claim_fail, p_lower_epoch, p_eqwipe, p_late;
};
constexpr std::array<Campaign, 5> kCampaigns = {{
    {"all faults", 0.2, 0.03, 0.05, 0.05, 0.1, 0.1, 0.05}, {"failures 10%", 0.1, 0.03, 0.05, 0.0, 0.0, 0.0, 0.0}, {"pending-heavy, clock steps", 0.4, 0.0, 0.2, 0.0, 0.0, 0.0, 0.0}, {"equal-epoch restarts", 0.2, 0.03, 0.05, 0.0, 0.0, 0.4, 0.0}, {"late old-boot deliveries", 0.2, 0.0, 0.05, 0.05, 0.15, 0.1, 0.2},
}};

std::vector<Action> gen_actions(PyRandom& rng, const Campaign& c, int nrules) {
    const std::vector<i64> lags = {10, 46, 600};
    const double p_reorder = 0.1, p_quiet_gap = 0.15, p_redeliver = 0.7;
    i64 t = 1'000'000, off = 0;
    const i64 boots = rng.randint(1, 4);
    i64 epoch = rng.randint(1000, 5000);
    int eid = 0;
    std::vector<std::pair<i64, Ev>> arrivals;
    for (i64 b = 0; b < boots; ++b) {
        if (b > 0) {
            t += rng.choice(std::vector<i64>{60, 600, 4000, 12000});
            const double r = rng.random();
            if (r < c.p_lower_epoch)
                epoch = std::max<i64>(1, epoch - rng.randint(1, 3000));
            else if (r < c.p_lower_epoch + c.p_eqwipe) {
            } else
                epoch += rng.randint(1, 5000);
        }
        const bool claim_fail = rng.random() < c.p_claim_fail;
        i64 seq = 0;
        const i64 n = rng.randint(2, 10);
        for (i64 k = 0; k < n; ++k) {
            if (rng.random() < p_quiet_gap)
                t += rng.choice(std::vector<i64>{4000, 8000});
            else
                t += rng.randint(1, 60);
            if (rng.random() < c.p_step)
                off -= rng.randint(1, 20);
            else if (rng.random() < 0.03)
                off += rng.randint(1, 20);
            ++seq;
            ++eid;
            Ev ev;
            ev.id = eid;
            ev.rule = static_cast<int>(rng.randrange(nrules));
            ev.state = rng.choice(std::vector<char>{'C', 'E'});
            ev.ts = t + off;
            if (!claim_fail)
                ev.pair = Pair{epoch, seq};
            if (rng.random() < c.p_lost) {
                Ev rep = ev;
                rep.pair.reset();
                arrivals.push_back({t + rng.choice(lags), rep});
            } else {
                i64 d = rng.randint(0, 3);
                d += (rng.random() < p_reorder) ? rng.randint(0, 2) : 0;
                if (rng.random() < c.p_late)
                    d += rng.choice(std::vector<i64>{4000, 8000});
                arrivals.push_back({t + d, ev});
            }
        }
    }
    std::stable_sort(arrivals.begin(), arrivals.end(),
                     [](const auto& a, const auto& b) { return a.first < b.first; });
    std::vector<Action> acts;
    for (const auto& [at, ev] : arrivals) {
        Action a;
        a.at = at;
        a.ev = ev;
        a.fail = rng.random() < c.p_fail;
        acts.push_back(a);
        if (a.fail && rng.random() < p_redeliver) {
            i64 tt = at;
            for (int k = 0; k < 2; ++k) {
                tt += rng.choice(std::vector<i64>{30, 600, 4000, 8000});
                Action r;
                r.kind = Kind::Repair;
                r.at = tt;
                r.ref = ev.id;
                r.fail = rng.random() < c.p_fail;
                acts.push_back(r);
                if (!r.fail)
                    break;
            }
        }
    }
    std::stable_sort(acts.begin(), acts.end(),
                     [](const Action& a, const Action& b) { return a.at < b.at; });
    return acts;
}

// ── The model (pend.Store("plan", REC2) over model.py's rows) ────────────────────────────────────

struct Row {
    char state{0};
    i64 key{0}, iseq{0};
    std::optional<i64> ts_hwm, seq_hwm, hwm_recv;
    bool flag{false};
    std::optional<Pair> pair;
    int upd{0};
};
struct Ev2 {
    int id{0}, rule{0};
    char state{'C'};
    i64 key{0};
    bool capped{false};
    i64 iseq{0};
    std::optional<Pair> pair;
    bool pending{false};
};
struct Counters {
    i64 unpaired_events{0}, unpaired_held{0}, pair_regressions{0}, pair_stragglers{0},
        pair_recoveries{0}, pair_duplicates{0}, retired_events{0};
};

std::optional<i64> or_none(i64 v) { return v == 0 ? std::nullopt : std::optional<i64>(v); }

class Model {
public:
    std::map<int, Row> rows;
    std::map<int, Ev2> events;
    std::optional<i64> a_epoch, a_hwm, a_recv, a_retired;
    Counters cnt;
    std::string last;
    // The first action index at which a clock comparison sat within kNear seconds of a window.
    std::optional<std::size_t> near_at;
    std::size_t cur{0};
    static constexpr i64 kNear = 15;

    void first(const Ev& ev, i64 now, bool fail) {
        ++iseq_;
        Ev2 e;
        e.id = ev.id;
        e.rule = ev.rule;
        e.state = ev.state;
        e.iseq = iseq_;
        e.pair = ev.pair;
        if (ev.ts > 0) {
            const i64 b = now + kCap;
            e.key = ev.ts > b ? b : ev.ts;
            e.capped = ev.ts > b;
        }
        events[e.id] = e;
        Ev2& ref = events[e.id];
        if (fail) {
            ref.pending = true;
            last = sql_mode(agent_step(ref.pair, now)) + ":pending";
            return;
        }
        project(ref, false, now);
    }
    void repair(int id, i64 now, bool fail) {
        last = "noop";
        Ev2& e = events.at(id);
        if (!e.pending)
            return;
        if (fail) {
            last = sql_mode(mode_readonly(e.pair, now)) + ":pending";
            return;
        }
        project(e, true, now);
    }
    std::vector<int> pending_ids() const {
        std::vector<const Ev2*> v;
        for (const auto& [id, e] : events)
            if (e.pending)
                v.push_back(&e);
        std::sort(v.begin(), v.end(), [](auto* a, auto* b) { return a->iseq < b->iseq; });
        std::vector<int> out;
        for (auto* e : v)
            out.push_back(e->id);
        return out;
    }

private:
    i64 iseq_{0};

    static std::string sql_mode(const std::string& m) {
        return m == "straggler" ? "current_straggler" : m == "rebase" ? "current_rebase" : m;
    }
    void note_clock(i64 recv, i64 now) {
        const auto close = [](i64 a, i64 b) { return a - b <= kNear && b - a <= kNear; };
        if (close(now - recv, kStale) || close(recv - now, kSlack))
            if (!near_at)
                near_at = cur;
    }
    bool fresh(i64 now) {
        if (!a_recv)
            return false;
        note_clock(*a_recv, now);
        return !(now - *a_recv > kStale || *a_recv > now + kSlack);
    }
    std::string agent_step(const std::optional<Pair>& pair, i64 now) {
        if (!pair) {
            ++cnt.unpaired_events;
            if (a_epoch && fresh(now)) {
                ++cnt.unpaired_held;
                return "unpaired_held";
            }
            return "unpaired";
        }
        const auto [e, sq] = *pair;
        if (a_retired && e == *a_retired) {
            ++cnt.retired_events;
            return "refused_retired";
        }
        if (!a_epoch || e > *a_epoch) {
            a_epoch = e, a_hwm = sq, a_recv = now;
            return "current";
        }
        if (e == *a_epoch && sq > *a_hwm) {
            a_hwm = sq, a_recv = now;
            return "current";
        }
        if (e == *a_epoch) {
            if (fresh(now)) {
                ++cnt.pair_stragglers;
                return "straggler";
            }
            a_hwm = sq, a_recv = now;
            ++cnt.pair_recoveries;
            return "rebase";
        }
        if (fresh(now)) {
            ++cnt.pair_regressions;
            return "refused_regression";
        }
        a_retired = a_epoch;
        a_epoch = e, a_hwm = sq, a_recv = now;
        ++cnt.pair_recoveries;
        return "rebase";
    }
    std::string mode_readonly(const std::optional<Pair>& pair, i64 now) {
        if (!pair)
            return (a_epoch && fresh(now)) ? "unpaired_held" : "unpaired";
        const auto [e, sq] = *pair;
        if (a_retired && e == *a_retired)
            return "refused_retired";
        if (!a_epoch || e > *a_epoch || (e == *a_epoch && sq > *a_hwm))
            return "current";
        if (e == *a_epoch)
            return "straggler";
        return "refused_regression";
    }

    // D(p, row), Dinc(p, e): both unpaired, both paired, or mixed (REC2: seen_arrival, seen_epoch).
    bool disagrees(const Ev2& p, const std::optional<Pair>& other_pair, i64 other_key,
                   i64 other_iseq) const {
        const bool pp = p.pair.has_value(), op = other_pair.has_value();
        if (pp && op)
            return *p.pair >= *other_pair || (a_retired && p.pair->first == *a_retired) ||
                   p.iseq > other_iseq || p.pair->first != other_pair->first;
        if (pp != op)
            return true;
        return std::pair(p.key, p.iseq) > std::pair(other_key, other_iseq) || p.iseq > other_iseq ||
               (p.key != 0 && p.key == other_key && p.iseq != other_iseq);
    }
    bool dominated(const Ev2& p, const Row& row) const {
        const bool pp = p.pair.has_value(), rp = row.pair.has_value();
        if (pp && a_retired && p.pair->first == *a_retired)
            return true;
        if (pp && rp)
            return *p.pair <= *row.pair;
        if (!pp && rp)
            return true;
        if (pp && !rp)
            return false;
        return std::pair(p.key, p.iseq) <= std::pair(row.key, row.iseq);
    }
    void fold(int rule, const std::vector<Ev2*>& seen, i64 now) {
        auto it = rows.find(rule);
        if (it == rows.end())
            return;
        Row& row = it->second;
        i64 mk = 0;
        bool any = false;
        for (const Ev2* p : seen)
            if (disagrees(*p, row.pair, row.key, row.iseq)) {
                any = true;
                mk = std::max(mk, p->key);
            }
        if (!any)
            return;
        row.flag = true;
        if (mk > row.ts_hwm.value_or(0)) {
            row.hwm_recv = now;
            row.ts_hwm = or_none(std::max(row.ts_hwm.value_or(0), mk));
        }
    }

    // v4_apply_s: the key regime's apply, with the seen events.
    void v4_apply(Row& row, i64 key, bool capped, i64 iseq, i64 now, char state, i64 seen_max,
                  const std::vector<Ev2*>& seen, int upd) {
        const bool P = key > row.key || (key == row.key && iseq > row.iseq);
        bool R = false;
        if (row.hwm_recv)
            note_clock(*row.hwm_recv, now);
        if (key > 0 && key < row.ts_hwm.value_or(0) && iseq > row.iseq && row.hwm_recv)
            R = *row.hwm_recv > now + kSlack || now - *row.hwm_recv > kStale;
        const bool APPLY = P || R;
        const bool TIE = key != 0 && key == row.key && state != row.state;
        const i64 base_seq = row.seq_hwm ? *row.seq_hwm : row.iseq;
        const bool where = APPLY || iseq > row.iseq || TIE || key > row.ts_hwm.value_or(0) ||
                           seen_max > base_seq;
        if (!where)
            return;
        const i64 old_hwm = row.ts_hwm.value_or(0);
        bool flag;
        if (APPLY) {
            bool seen_bad = false;
            for (const Ev2* p : seen)
                seen_bad = seen_bad || p->iseq > iseq ||
                           (p->key != 0 && p->key == key && p->iseq != iseq);
            flag = key == 0 || capped || row.key == 0 || key < old_hwm ||
                   (row.flag && key <= old_hwm) || iseq < base_seq || TIE || seen_bad;
            row.state = state, row.key = key, row.iseq = iseq, row.upd = upd;
        } else {
            flag = row.flag || iseq > row.iseq || TIE;
        }
        if (key > old_hwm)
            row.hwm_recv = now;
        row.ts_hwm = or_none(std::max(old_hwm, key));
        row.seq_hwm = std::max({base_seq, iseq, seen_max});
        row.flag = flag;
    }

    static std::string label(const std::string& mode, const std::optional<std::pair<bool, std::optional<Pair>>>& old,
                             bool applied, const std::optional<Pair>& pair) {
        if (mode == "refused_regression" || mode == "refused_retired")
            return mode;
        if (mode == "unpaired" || mode == "unpaired_held") {
            if (old && old->first)
                return (mode == "unpaired" && applied) ? "transition_to_key" : "held_unpaired";
            return applied ? "applied_key" : "";
        }
        if (!old)
            return mode == "rebase" ? "rebase" : "applied_pair";
        if (!old->first)
            return mode == "rebase" ? "rebase" : "transition_to_pair";
        if (old->second == pair)
            return "refused_duplicate";
        if (applied)
            return mode == "rebase" ? "rebase" : "applied_pair";
        return "refused_straggler";
    }

    void upsert(const Ev2& e, const std::string& mode, const std::vector<Ev2*>& seen, i64 now) {
        const int rule = e.rule;
        const i64 key = e.key, iseq = e.iseq;
        const bool capped = e.capped;
        const char state = e.state;
        const std::optional<Pair> pair = e.pair;
        i64 seen_max = 0;
        for (const Ev2* p : seen)
            seen_max = std::max(seen_max, p->iseq);
        auto it = rows.find(rule);
        Row* r = it == rows.end() ? nullptr : &it->second;
        const i64 prev_key = r ? r->key : 0;
        const i64 base_seq = r ? (r->seq_hwm ? *r->seq_hwm : r->iseq) : 0;
        const auto fold_row = [&](Row& rr) {
            if (rr.flag) {
                const i64 v = std::max(key, prev_key);
                if (v > rr.ts_hwm.value_or(0)) {
                    rr.ts_hwm = v;
                    rr.hwm_recv = now;
                }
            }
        };
        const auto bump = [&] {
            if (r)
                r->seq_hwm = std::max({base_seq, iseq, seen_max});
        };
        std::optional<i64> mk;
        for (const Ev2* p : seen)
            if (disagrees(*p, pair, key, iseq))
                mk = mk ? std::max(*mk, p->key) : p->key;
        const auto ins_row = [&](bool flag_force) {
            Row nr;
            nr.state = state, nr.upd = e.id, nr.key = key, nr.iseq = iseq;
            nr.seq_hwm = std::max(iseq, seen_max);
            const bool keymode = mode == "unpaired" || mode == "unpaired_held";
            if (keymode) {
                nr.ts_hwm = or_none(std::max(key, mk.value_or(0)));
                if (key > 0 || mk)
                    nr.hwm_recv = now;
                nr.flag = mode == "unpaired_held" || key == 0 || capped || mk.has_value();
            } else {
                nr.pair = pair;
                nr.flag = flag_force || mk.has_value();
                if (nr.flag)
                    nr.ts_hwm = or_none(std::max(key, mk.value_or(0)));
                if (nr.flag && nr.ts_hwm)
                    nr.hwm_recv = now;
            }
            rows[rule] = nr;
        };
        if (mode == "refused_retired" || mode == "refused_regression") {
            if (!r)
                ins_row(true);
            else {
                r->flag = true;
                fold_row(*r);
                bump();
            }
            return;
        }
        if (mode == "unpaired_held") {
            if (!r)
                ins_row(true);
            else if (r->pair) {
                r->flag = true;
                const i64 old = r->ts_hwm.value_or(0);
                if (key > old)
                    r->hwm_recv = now;
                r->ts_hwm = or_none(std::max(old, key));
                fold_row(*r);
                bump();
            } else
                v4_apply(*r, key, capped, iseq, now, state, seen_max, seen, e.id);
            return;
        }
        if (mode == "unpaired") {
            if (!r)
                ins_row(false);
            else if (r->pair && !(iseq > r->iseq)) {
                r->flag = true; // an unpaired event older by arrival than the paired verdict
                fold_row(*r);
                bump();
            } else if (r->pair) {
                const i64 old = r->ts_hwm.value_or(0);
                r->state = state, r->upd = e.id, r->key = key, r->iseq = iseq, r->flag = true;
                r->pair.reset();
                const i64 nk = std::max(key, prev_key);
                if (nk > old)
                    r->hwm_recv = now;
                r->ts_hwm = or_none(std::max(old, nk));
                bump();
            } else
                v4_apply(*r, key, capped, iseq, now, state, seen_max, seen, e.id);
            return;
        }
        // current / straggler / rebase: a paired event.
        const auto [ev_e, ev_s] = *pair;
        if (!r) {
            ins_row(mode == "rebase");
            return;
        }
        bool any_dis = false;
        for (const Ev2* p : seen)
            any_dis = any_dis || disagrees(*p, pair, key, iseq);
        const bool clean = key > r->ts_hwm.value_or(0) && !any_dis;
        const auto do_apply = [&](bool flag) {
            r->state = state, r->upd = e.id, r->key = key, r->iseq = iseq, r->pair = pair;
            r->flag = flag;
        };
        if (!r->pair)
            do_apply(true);
        else {
            const auto [ce, cs] = *r->pair;
            if (ce != ev_e) {
                if (mode == "rebase" || ce > ev_e)
                    do_apply(true);
                else
                    do_apply(!clean);
            } else if (ev_s > cs)
                do_apply(mode == "rebase" ? true : !clean);
            else if (ev_s == cs)
                r->flag = true;
            else if (mode == "straggler")
                r->flag = true;
            else
                do_apply(true);
        }
        fold_row(*r);
        bump();
    }

    void project(Ev2& e, bool is_repair, i64 now) {
        std::vector<Ev2*> seen;
        for (auto& [id, p] : events)
            if (p.pending && p.rule == e.rule && p.id != e.id)
                seen.push_back(&p);
        std::sort(seen.begin(), seen.end(), [](auto* a, auto* b) { return a->iseq < b->iseq; });
        const std::string mode = is_repair ? mode_readonly(e.pair, now) : agent_step(e.pair, now);
        fold(e.rule, seen, now);
        std::optional<std::pair<bool, std::optional<Pair>>> old;
        if (auto it = rows.find(e.rule); it != rows.end())
            old = std::pair(it->second.pair.has_value(), it->second.pair);
        upsert(e, mode, seen, now);
        auto it = rows.find(e.rule);
        const bool applied = it != rows.end() && it->second.iseq == e.iseq;
        const std::string lab = label(mode, old, applied, e.pair);
        if (lab == "refused_duplicate" && !is_repair)
            ++cnt.pair_duplicates;
        last = sql_mode(mode) + "|" + lab;
        fold(e.rule, seen, now);
        if (it = rows.find(e.rule); it != rows.end()) {
            std::vector<Ev2*> cand;
            if (is_repair)
                cand.push_back(&e);
            cand.insert(cand.end(), seen.begin(), seen.end());
            for (Ev2* p : cand)
                if (p->pending && dominated(*p, it->second))
                    p->pending = false;
        }
    }
};

// ── Canonical text of a state (the model's, and the database's rendered the same way) ──────────

std::string opt(const std::optional<i64>& v) { return v ? std::to_string(*v) : ""; }

// "<label>" of a step: the part of Model::last after '|' ("" when there is none).
std::string label_of(const std::string& last) {
    const auto bar = last.find('|');
    return bar == std::string::npos ? "" : last.substr(bar + 1);
}

struct Snap {
    std::vector<std::string> rows; // one per rule, rule order
    std::string pending;
    std::string agent;
    std::vector<std::string> times; // per row: hwm_recv and the applying event
    std::string agent_time;         // the agent's pair clock, "" when unset
};

// with_times adds the two clocks and the applying event: the digest includes them, the
// comparison against the database does not (it checks the clocks within a tolerance instead).
std::string snap_text(const Snap& s, bool with_times, std::size_t seed, std::size_t i,
                      const std::string& last) {
    std::ostringstream o;
    const std::string tag = std::to_string(seed) + "|" + std::to_string(i) + "|";
    if (with_times)
        o << "D|" << tag << last << "\n";
    for (std::size_t k = 0; k < s.rows.size(); ++k)
        o << "R|" << tag << s.rows[k] << (with_times ? "|" + s.times[k] : "") << "\n";
    o << "P|" << tag << s.pending << "\n";
    o << "A|" << tag << s.agent << (with_times ? "|" + s.agent_time : "") << "\n";
    return o.str();
}

Snap model_snap(const Model& m, std::size_t nrules) {
    Snap s;
    for (std::size_t rule = 0; rule < nrules; ++rule) {
        const auto it = m.rows.find(static_cast<int>(rule));
        if (it == m.rows.end())
            continue;
        const Row& r = it->second;
        std::ostringstream o;
        o << "r" << rule << "|" << r.state << "|" << (r.flag ? "t" : "f") << "|"
          << (r.pair ? std::to_string(r.pair->first) : "") << "|"
          << (r.pair ? std::to_string(r.pair->second) : "") << "|" << r.key << "|" << opt(r.ts_hwm)
          << "|" << opt(r.seq_hwm) << "|" << r.iseq;
        s.rows.push_back(o.str());
        s.times.push_back(opt(r.hwm_recv) + "|t" + std::to_string(r.upd));
    }
    std::string ids;
    for (int id : m.pending_ids())
        ids += (ids.empty() ? "" : ",") + std::to_string(id);
    s.pending = ids;
    const Counters& c = m.cnt;
    s.agent = opt(m.a_epoch) + "|" + opt(m.a_hwm) + "|" + opt(m.a_retired) + "|" +
              std::to_string(c.unpaired_events) + "|" + std::to_string(c.unpaired_held) + "|" +
              std::to_string(c.pair_regressions) + "|" + std::to_string(c.pair_stragglers) + "|" +
              std::to_string(c.pair_recoveries) + "|" + std::to_string(c.pair_duplicates) + "|" +
              std::to_string(c.retired_events);
    s.agent_time = opt(m.a_recv);
    return s;
}

// ── One seed: the schedule, its model trace, and the harness adaptations ────────────────────────

struct Seed {
    std::size_t seed{0};
    const Campaign* campaign{nullptr};
    int nrules{2};
    std::vector<Action> acts;
    std::vector<bool> with_next; // acts[i] and acts[i + 1] run on two threads
    std::vector<Snap> expect;    // model state after each action
    std::vector<std::string> last;
};

void run_model(Seed& s, Model& m) {
    s.expect.clear();
    s.last.clear();
    for (std::size_t i = 0; i < s.acts.size(); ++i) {
        const Action& a = s.acts[i];
        m.cur = i;
        if (a.kind == Kind::First)
            m.first(a.ev, a.at, a.fail);
        else
            m.repair(a.ref, a.at, a.fail);
        s.expect.push_back(model_snap(m, static_cast<std::size_t>(s.nrules)));
        s.last.push_back(m.last);
    }
}

Seed generate(std::size_t seed) {
    Seed s;
    s.seed = seed;
    s.campaign = &kCampaigns[seed % kCampaigns.size()];
    s.nrules = 2 + static_cast<int>((seed / 5) % 2);
    PyRandom rng(static_cast<std::uint32_t>(seed));
    s.acts = gen_actions(rng, *s.campaign, s.nrules);
    s.with_next.assign(s.acts.size(), false);
    return s;
}

std::string schedule_text(const Seed& s) {
    std::ostringstream o;
    for (std::size_t i = 0; i < s.acts.size(); ++i) {
        const Action& a = s.acts[i];
        o << (a.kind == Kind::First ? "F," : "R,") << a.at << ",";
        if (a.kind == Kind::First)
            o << a.ev.id << "," << a.ev.rule << "," << a.ev.state << "," << a.ev.ts << ","
              << (a.ev.pair ? a.ev.pair->first : 0) << "," << (a.ev.pair ? a.ev.pair->second : 0);
        else
            o << a.ref;
        o << "," << (a.fail ? 1 : 0) << "\n";
    }
    return o.str();
}

std::string trace_text(const Seed& s) {
    std::string out;
    for (std::size_t i = 0; i < s.expect.size(); ++i)
        out += snap_text(s.expect[i], true, s.seed, i, s.last[i]);
    return out;
}

// An FNV-style 64-bit hash, NOT standard FNV-1a: the offset basis below is 1469598103934665603, not
// the real FNV-1a basis 14695981039346656037 (a digit was lost when it was first typed). The
// same constant was in harness_digests.py (see the header), so the two agreed; changing it, or
// "fixing" it, changes every digest in `kPythonDigests`.
std::uint64_t fnv1a(const std::string& s) {
    std::uint64_t h = 1469598103934665603ULL;
    for (unsigned char c : s) {
        h ^= c;
        h *= 1099511628211ULL;
    }
    return h;
}

// Which adjacent pairs run on two threads (seed % 7 == 3), then the receipt-time adaptations,
// then the model run that the replay compares with.
void adapt(Seed& s) {
    if (s.seed % 7 == 3)
        for (std::size_t i = 0; i + 1 < s.acts.size(); ++i)
            if (s.acts[i].kind == Kind::First && !s.acts[i].fail && !s.acts[i + 1].fail &&
                (s.seed + i) % 3 == 0 && !(i > 0 && s.with_next[i - 1])) {
                s.with_next[i] = true;
                s.acts[i + 1].at = s.acts[i].at; // the clock cannot move while a row is held
            }
    for (int round = 0; round < 64; ++round) {
        Model m;
        run_model(s, m);
        if (!m.near_at)
            return;
        std::size_t from = *m.near_at;
        if (from > 0 && s.with_next[from - 1])
            --from;
        for (std::size_t j = from; j < s.acts.size(); ++j)
            s.acts[j].at += 31;
    }
    throw std::runtime_error("harness: no receipt shift clears the clock window");
}

// ── Digests from the original Python model (see the header), seeds 0..63: {schedule, trace} ──────

constexpr std::array<std::array<std::uint64_t, 2>, 64> kPythonDigests = {{
    {0x4555c08ed599ea31, 0x6c6ad8e4486c58f7}, {0x72d5b61832a66f30, 0xe152bf6ef0e88631},
    {0xee870de2f4ea0c62, 0xd20917a1424aadf6}, {0x01f1867cfa3c1c12, 0x76ee23bf9c317b8c},
    {0x3e186d91f01134f5, 0xeb624e3d29703414}, {0xd54a28389ccc9950, 0x98e4b7bc2edf7cf7},
    {0xc493dfc27dc49b6e, 0xa15aef41f9f6081d}, {0x6cf8f8c71c8f1628, 0x5d4c0748f266e8ab},
    {0xec5d63a38fc09b03, 0xa96be86c563a3d26}, {0x364cb3b9ad330e60, 0xcb5cb21827272fd4},
    {0x2b818c5068688c68, 0x18726685db70fa7b}, {0x1b7a27b62da92423, 0xeee504fdd01c7e8b},
    {0xa8293fe6fe7bf903, 0x54bc647be7904797}, {0x9484d0d4da5b86e0, 0xa6793b5f4bff1829},
    {0xc9de98d33b251754, 0x35c3fe3b5aeae35f}, {0x4b7bb586fd6334f1, 0x743d87fa6fd93325},
    {0x585494c96a8ea219, 0x0ec956bce1280ec6}, {0xff0bbbb58b0f1082, 0x987b41e2d2fd89ce},
    {0xe096fb1bbcbad3d6, 0xe2ede9be0e344794}, {0x5a53cddf0515ccfc, 0xb27683ae3603b439},
    {0xd3efabeddabc10d3, 0x425213a350d14df3}, {0x573d80aac793373a, 0x9b52cef514d3c0b7},
    {0x85f81333fa315a93, 0xdc4de7c6273028c4}, {0x53a74080f452d02f, 0xdd001ae298927eb9},
    {0xb3e96fc7f6d4b002, 0x80ce8c0529a40e2a}, {0x2a54fc71b811e5af, 0x812f7336da4d687f},
    {0x89b38d843bf72d6a, 0x1fdd1e0efeff704e}, {0x88e13a4f6dab81e1, 0x6c783913629b208c},
    {0x36111887f9d1b631, 0x5a9becf736b4863b}, {0x7aaec4f7fca1fa1d, 0x30c28a989b771b84},
    {0xc6dd263c834c96d9, 0x7090841c88c50dc9}, {0x4e00c62a94a3fac7, 0x0b2cfd6b2e520799},
    {0xf89fb1d809cd2446, 0x2db72818c84753dd}, {0x1b440ac4f84ad037, 0xaf968e9d7d466fe0},
    {0x5f0976da2112edab, 0x92caf69d0cca6aff}, {0x287a6e2efcbd7f10, 0x7f8aa82f8345bd4b},
    {0xc8f2fa24c3f5adc7, 0x91ba7f809ebdefa1}, {0xb9a6bd2f29a7b9b0, 0x35f940fb5493a706},
    {0x604d26f305a1f511, 0x4e40d0a8364daedd}, {0xd4f286714912186b, 0x2784d3103476b87a},
    {0xb92ae3b7b30997f7, 0x57d44d7da33222bf}, {0xd11269923a4f8cff, 0x9a8ae131027b79e3},
    {0x09b26c9fb09f75a9, 0x46c9495bfd017665}, {0x452ed6a31a180468, 0xa92b03bacb06f514},
    {0x5a7d3fad0a9418ff, 0xeca84b0dd139731f}, {0xcd1e52ba348dee4a, 0xca1d957ec527421f},
    {0x778d778f3f4ced39, 0xf9dfe95e62a14525}, {0x6bd222ae87e79fd3, 0x2288d1049213cff7},
    {0x711417cc7a9c54bb, 0x658160efad45adbd}, {0x030d12274da41694, 0xb6387a00772b4149},
    {0x1059a4fcb2bcc7a4, 0x450d312c3bbbabc3}, {0x02bc4fb0dd4cb365, 0xbf8ee22381298a72},
    {0x64a9eb61868b0ff0, 0x3ff0da26139de77c}, {0x2c6aea7841c6947f, 0x160faf9a5e49a5ec},
    {0xaaffa37b829dc4f1, 0x765bd32343305de5}, {0xc741165372b5a191, 0xcfc1c757d680a7fd},
    {0xfe2f03a85fa0d408, 0x143d40ce014d2004}, {0xab8090e1a68e5ff7, 0x1509e1718df511f7},
    {0x49bca3ea03e0ee09, 0x74e543ea686d1446}, {0x0028ee7cae1dd6c5, 0x77444863ff47a3cd},
    {0x6683717a92f87903, 0xc81431d5f3e916bc}, {0xa63fc19d10273f0a, 0x3ab6ad2946000a0a},
    {0x85fab7bd55a55bf5, 0xb68757eaea67fbdd}, {0x1386fdb2198612c5, 0x5dea5bcfa36870cf},
}};

// ── The store replay ──────────────────────────────────────────────────────────────────────────

constexpr const char* kSchema = "guaranteed_state_store";
constexpr i64 kBase = 1'700'000'000'000'000'000LL; // a plausible receipt instant, ns
constexpr i64 kSec = 1'000'000'000LL;
constexpr i64 kClockTolS = 60; // a stored clock may differ from the model's by the real run time

yuzu::test::PgTestTemplate harness_tpl{"guardianstate", [](const std::string& dsn) {
                                           PgPool pool{{.conninfo = dsn, .size = 1}};
                                           GuaranteedStateStore store{pool};
                                           if (!store.is_open())
                                               throw std::runtime_error(
                                                   "guardianstate template: store failed to migrate");
                                       }};

GuaranteedStateRuleRow make_rule(std::string rule_id) {
    GuaranteedStateRuleRow r;
    r.name = "guard-" + rule_id;
    r.rule_id = std::move(rule_id);
    r.yaml_source = "apiVersion: yuzu.io/v1alpha1\nkind: GuaranteedStateRule\n";
    r.version = 1;
    r.enabled = true;
    r.enforcement_mode = "enforce";
    r.severity = "high";
    r.os_target = "windows";
    r.scope_expr = "tag:workstations";
    r.created_at = r.updated_at = "2026-04-19T12:00:00Z";
    r.created_by = r.updated_by = "alice";
    return r;
}

// One connection kept open for the whole seed: a case issues about six statements per delivery.
// Main thread only (a Catch2 assertion is not thread-safe).
class Probe {
public:
    explicit Probe(const std::string& dsn) : conn_{PQconnectdb(dsn.c_str())} {
        REQUIRE(PQstatus(conn_.get()) == CONNECTION_OK);
    }
    std::string one(const std::string& sql) {
        pg::PgResult r{PQexec(conn_.get(), sql.c_str())};
        INFO(PQresultErrorMessage(r.get()));
        REQUIRE(r.ok());
        return PQntuples(r.get()) == 0 || PQgetisnull(r.get(), 0, 0) ? "" : PQgetvalue(r.get(), 0, 0);
    }

private:
    pg::PgConn conn_;
};

// A switch that makes any row WRITTEN to the census table fail while it is on (a first delivery's
// census statement always writes its row, so it always fails: the event is stored pending, the
// agent step having already run).
class FailSwitch {
public:
    explicit FailSwitch(Probe& p) : p_(p) {
        p_.one(std::string("CREATE TABLE ") + kSchema + ".yuzu_test_fail_on (x int)");
        p_.one(std::string("CREATE FUNCTION ") + kSchema +
               ".yuzu_test_pair_fail() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN IF EXISTS "
               "(SELECT 1 FROM " + kSchema + ".yuzu_test_fail_on) THEN RAISE EXCEPTION 'forced "
               "census failure' USING ERRCODE = 'XX000'; END IF; RETURN NEW; END $$");
        p_.one(std::string("CREATE TRIGGER yuzu_test_pair_fail BEFORE INSERT OR UPDATE ON ") +
               kSchema + ".guardian_agent_rule_status FOR EACH ROW EXECUTE FUNCTION " + kSchema +
               ".yuzu_test_pair_fail()");
    }
    void on() { p_.one(std::string("INSERT INTO ") + kSchema + ".yuzu_test_fail_on VALUES (1)"); }
    void off() { p_.one(std::string("DELETE FROM ") + kSchema + ".yuzu_test_fail_on"); }

private:
    Probe& p_;
};

// Holds the census lock barrier at its first hit so a test can park one writer.
struct BarrierHold {
    std::promise<void> reached_p, release_p;
    std::future<void> reached_f = reached_p.get_future();
    std::shared_future<void> release_f = release_p.get_future().share();
    std::atomic<int> calls{0};
    std::atomic<bool> released{false};
    void hit() {
        if (calls.fetch_add(1) == 0) {
            reached_p.set_value();
            release_f.wait();
        }
    }
    void release() {
        if (!released.exchange(true))
            release_p.set_value();
    }
};

// Owns the writer threads. RULE: every local a thread touches is declared BEFORE the owner, so it
// outlives the join; on scope exit (a failed REQUIRE included) it releases the barrier, joins, and
// only then clears the store's barrier.
class WriterThreads {
public:
    WriterThreads(GuaranteedStateStore& store, BarrierHold* hold) : store_(store), hold_(hold) {}
    WriterThreads(const WriterThreads&) = delete;
    WriterThreads& operator=(const WriterThreads&) = delete;
    ~WriterThreads() { join_all(); }
    template <class F> void start(F&& f) { threads_.emplace_back(std::forward<F>(f)); }
    void join_all() {
        if (hold_ != nullptr)
            hold_->release();
        for (auto& t : threads_)
            if (t.joinable())
                t.join();
        threads_.clear();
        store_.set_census_lock_barrier_for_test({});
    }

private:
    GuaranteedStateStore& store_;
    BarrierHold* hold_;
    std::vector<std::thread> threads_;
};

// The agent step's own lock bound for one store, restored to the production default on scope exit.
struct AgentStepLockWait {
    explicit AgentStepLockWait(GuaranteedStateStore& s, int ms) : store(s) {
        store.set_agent_step_lock_timeout_ms_for_test(ms);
    }
    AgentStepLockWait(const AgentStepLockWait&) = delete;
    AgentStepLockWait& operator=(const AgentStepLockWait&) = delete;
    ~AgentStepLockWait() {
        store.set_agent_step_lock_timeout_ms_for_test(
            GuaranteedStateStore::kAgentStepLockTimeoutMs);
    }
    GuaranteedStateStore& store;
};

constexpr const char* kCompliant = "guard.compliant";
constexpr const char* kErrored = "guard.unhealthy";

// The census pair decision metric: a closed set of ten labels, from the census SQL.
constexpr const char* kDecisionCounter = "yuzu_server_guardian_census_pair_decisions_total";
constexpr std::array<const char*, 10> kDecisionLabels = {
    "applied_pair",       "applied_key",     "transition_to_pair", "transition_to_key",
    "rebase",             "held_unpaired",   "refused_regression", "refused_retired",
    "refused_duplicate",  "refused_straggler"};
using DecisionCounts = std::array<double, kDecisionLabels.size()>;

DecisionCounts decision_counts(yuzu::MetricsRegistry& metrics) {
    DecisionCounts out{};
    for (std::size_t i = 0; i < kDecisionLabels.size(); ++i)
        out[i] = metrics.counter(kDecisionCounter, {{"decision", kDecisionLabels[i]}}).value();
    return out;
}
// "label+n" per label that moved, comma-joined in label order; "-" for none.
std::string decision_delta(const DecisionCounts& before, const DecisionCounts& after) {
    std::string out;
    for (std::size_t i = 0; i < kDecisionLabels.size(); ++i)
        if (const auto d = static_cast<long long>(after[i] - before[i]); d != 0)
            out += (out.empty() ? "" : ",") + std::string(kDecisionLabels[i]) + "+" +
                   std::to_string(d);
    return out.empty() ? "-" : out;
}
std::string expected_delta(const std::vector<std::string>& labels) {
    DecisionCounts c{};
    for (const auto& l : labels)
        for (std::size_t i = 0; i < kDecisionLabels.size(); ++i)
            if (l == kDecisionLabels[i])
                c[i] += 1;
    return decision_delta(DecisionCounts{}, c);
}

// Runs one seed's schedule against the store and compares the state after every delivery.
class Replay {
public:
    Replay(GuaranteedStateStore& store, const std::string& dsn, yuzu::MetricsRegistry& metrics,
           const Seed& s, bool labels)
        : store_(store), dsn_(dsn), metrics_(metrics), s_(s), labels_(labels), probe_(dsn),
          agent_("h" + std::to_string(s.seed)) {}

    // False once a delivery's state differed (the report names it); the seed stops there.
    bool run() {
        for (std::size_t i = 0; i < s_.acts.size() && !failed_; ++i) {
            const Action& a = s_.acts[i];
            INFO("step " << i << ": " << describe(a));
            if (last_at_ >= 0 && a.at > last_at_)
                shift(a.at - last_at_);
            last_at_ = a.at;
            const DecisionCounts before = decision_counts(metrics_);
            std::vector<std::string> expect_labels{label_of(s_.last[i])};
            if (s_.with_next[i]) {
                pair_run(i);
                ++i;
                expect_labels.push_back(label_of(s_.last[i]));
            } else {
                serial_run(i);
            }
            compare(i, before, expect_labels);
        }
        return !failed_;
    }

private:
    static std::string describe(const Action& a) {
        std::ostringstream o;
        o << (a.fail ? "failing " : "") << (a.kind == Kind::First ? "first delivery " : "repair of ");
        if (a.kind == Kind::First)
            o << "e" << a.ev.id << " rule r" << a.ev.rule << " " << a.ev.state << " ts=" << a.ev.ts
              << " pair=" << (a.ev.pair ? std::to_string(a.ev.pair->first) + "/" +
                                              std::to_string(a.ev.pair->second)
                                        : std::string("0/0"));
        else
            o << "e" << a.ref;
        o << " at=" << a.at;
        return o.str();
    }

    GuaranteedStateEventRow event_row(const Action& a) const {
        GuaranteedStateEventRow e;
        e.event_id = "e" + std::to_string(a.ev.id);
        e.rule_id = "r" + std::to_string(a.ev.rule);
        e.agent_id = agent_;
        e.event_type = a.ev.state == 'C' ? kCompliant : kErrored;
        e.severity = "high";
        e.guard_type = "registry";
        e.guard_category = "event";
        e.detected_value = "0";
        e.expected_value = "1";
        e.remediation_action = "registry-write";
        e.remediation_success = true;
        e.timestamp = "2026-04-19T12:00:00Z";
        e.agent_ns = kBase + a.ev.ts * kSec;
        e.received_ns = kBase + a.at * kSec;
        if (a.ev.pair) {
            e.boot_epoch = a.ev.pair->first;
            e.emit_seq = a.ev.pair->second;
        }
        return e;
    }
    // The row an action sends (a first delivery's is remembered for its later redeliveries).
    const GuaranteedStateEventRow& row_for(const Action& a) {
        if (a.kind == Kind::Repair)
            return rows_.at(a.ref);
        return rows_[a.ev.id] = event_row(a);
    }
    void note_ingest_seq(const Action& a) {
        if (a.kind != Kind::First)
            return;
        const std::string v = probe_.one(
            std::string("SELECT ingest_seq FROM ") + kSchema +
            ".guaranteed_state_events WHERE event_id = 'e" + std::to_string(a.ev.id) + "'");
        ingest_.push_back(std::stoll(v));
    }

    // Let `delta_s` of database time pass: this agent's stored database-clock columns read older.
    void shift(i64 delta_s) {
        const std::string d = std::to_string(delta_s * kSec);
        probe_.one(std::string("UPDATE ") + kSchema +
                   ".guardian_agent_order SET epoch_recv_ns = epoch_recv_ns - " + d +
                   ", unpaired_recv_ns = unpaired_recv_ns - " + d + " WHERE agent_id = '" +
                   agent_ + "'");
        probe_.one(std::string("UPDATE ") + kSchema +
                   ".guardian_agent_rule_status SET hwm_recv_ns = hwm_recv_ns - " + d +
                   " WHERE agent_id = '" + agent_ + "'");
    }

    void serial_run(std::size_t i) {
        const Action& a = s_.acts[i];
        const GuaranteedStateEventRow& row = row_for(a);
        EventInsertResult r;
        yuzu::test::LogCapture cap(spdlog::level::err); // a failing write logs; that is expected
        if (a.fail && a.kind == Kind::First) {
            if (!fail_)
                fail_.emplace(probe_);
            fail_->on();
            r = store_.insert_event_classified(row);
            fail_->off();
        } else if (a.fail) {
            // A Repair decides its mode by a share lock on the agent's order row: holding that row
            // makes the read time out, so the Repair fails whatever its decision would have written.
            Probe holder(dsn_);
            holder.one("BEGIN");
            holder.one(std::string("SELECT 1 FROM ") + kSchema +
                       ".guardian_agent_order WHERE agent_id = '" + agent_ + "' FOR UPDATE");
            {
                AgentStepLockWait quick(store_, 100);
                r = store_.insert_event_classified(row);
            }
            holder.one("ROLLBACK");
        } else {
            r = store_.insert_event_classified(row);
        }
        cap.stop();
        REQUIRE(r.outcome == (a.kind == Kind::First ? EventInsertOutcome::Inserted
                                                    : EventInsertOutcome::Redelivered));
        note_ingest_seq(a);
        if (a.fail) {
            // The injection must have taken effect, or the replay would differ from the model for
            // a harness reason: a failed first delivery, and a failed Repair of an event the
            // model still holds pending, leave that event pending.
            const int id = a.kind == Kind::First ? a.ev.id : a.ref;
            const auto& pend = s_.expect[i].pending;
            if (a.kind == Kind::First || (","+pend+",").find("," + std::to_string(id) + ",") != std::string::npos)
                REQUIRE(probe_.one(std::string("SELECT projection_pending FROM ") + kSchema +
                                   ".guaranteed_state_events WHERE event_id = 'e" +
                                   std::to_string(id) + "'") == "t");
        }
    }

    // Number of backends in this database that wait on a lock.
    int lock_waiters() {
        return std::stoi(probe_.one("SELECT count(*) FROM pg_stat_activity WHERE datname = "
                                    "current_database() AND wait_event_type = 'Lock'"));
    }
    // Poll until a writer parks on a lock, or `done` says it finished. Observes a real park.
    bool wait_parked_or_done(const std::atomic<bool>& done) {
        const auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(10);
        while (std::chrono::steady_clock::now() < deadline) {
            if (done.load())
                return false;
            if (lock_waiters() >= 1)
                return true;
            std::this_thread::sleep_for(std::chrono::milliseconds(5));
        }
        return false;
    }

    // Deliveries i and i + 1 on two threads: the first parks at the census lock barrier, holding
    // the agent's order row; the second must park behind it, and runs when the first is released.
    void pair_run(std::size_t i) {
        const Action& a1 = s_.acts[i];
        const Action& a2 = s_.acts[i + 1];
        const GuaranteedStateEventRow row1 = row_for(a1);
        const GuaranteedStateEventRow row2 = row_for(a2);
        AgentStepLockWait patient(store_, 10000);
        BarrierHold hold;
        std::atomic<bool> d1{false}, d2{false};
        EventInsertResult r1, r2;
        WriterThreads writers(store_, &hold);
        store_.set_census_lock_barrier_for_test([&hold] { hold.hit(); });
        writers.start([&] {
            r1 = store_.insert_event_classified(row1);
            d1 = true;
        });
        bool reached = false;
        for (auto end = std::chrono::steady_clock::now() + std::chrono::seconds(10);
             !reached && !d1 && std::chrono::steady_clock::now() < end;)
            reached = hold.reached_f.wait_for(std::chrono::milliseconds(5)) ==
                      std::future_status::ready;
        bool parked = false;
        if (reached) {
            writers.start([&] {
                r2 = store_.insert_event_classified(row2);
                d2 = true;
            });
            parked = wait_parked_or_done(d2);
        }
        writers.join_all();
        if (!reached)
            r2 = store_.insert_event_classified(row2); // the first never parked: run it serially
        REQUIRE(r1.outcome == EventInsertOutcome::Inserted);
        REQUIRE(r2.outcome == (a2.kind == Kind::First ? EventInsertOutcome::Inserted
                                                     : EventInsertOutcome::Redelivered));
        if (reached && !parked && a2.kind == Kind::First) {
            FAIL_CHECK("the second delivery of the same agent did not wait behind the first "
                       "(first deliveries of one agent serialise on its order row)");
            failed_ = true;
        }
        note_ingest_seq(a1);
        note_ingest_seq(a2);
    }

    // ── The database rendered as the model is ──

    std::string model_s(const std::string& ns) const {
        if (ns.empty())
            return "";
        const i64 v = std::stoll(ns);
        return (v - kBase) % kSec == 0 ? std::to_string((v - kBase) / kSec) : "?" + ns;
    }
    std::string ordinal(const std::string& ingest) const {
        if (ingest.empty())
            return "";
        for (std::size_t k = 0; k < ingest_.size(); ++k)
            if (std::to_string(ingest_[k]) == ingest)
                return std::to_string(k + 1);
        return "?" + ingest;
    }
    static std::vector<std::string> split(const std::string& s, char c) {
        std::vector<std::string> out;
        std::size_t from = 0;
        while (from <= s.size() && !s.empty()) {
            const auto to = s.find(c, from);
            out.push_back(s.substr(from, to == std::string::npos ? std::string::npos : to - from));
            if (to == std::string::npos)
                break;
            from = to + 1;
        }
        return out;
    }
    // A stored clock, shifted into the model's frame, must sit within the tolerance of the model's.
    void clock_check(const char* what, const std::string& real_ns, const std::string& model_s,
                     i64 db_now_ns, i64 at, std::string& notes) const {
        if (real_ns.empty() != model_s.empty()) {
            notes += std::string(what) + ": " + (real_ns.empty() ? "unset" : "set") + " but model " +
                     (model_s.empty() ? "unset" : "set") + "\n";
            return;
        }
        if (real_ns.empty())
            return;
        const i64 mine = at + (std::stoll(real_ns) - db_now_ns) / kSec;
        if (std::abs(mine - std::stoll(model_s)) > kClockTolS)
            notes += std::string(what) + ": database clock reads " + std::to_string(mine) +
                     ", model " + model_s + "\n";
    }

    Snap actual(i64 at, std::string& clock_notes) {
        Snap s;
        const i64 now_ns = std::stoll(
            probe_.one("SELECT (extract(epoch from clock_timestamp()) * 1000000000)::bigint"));
        const std::string rows = probe_.one(
            std::string("SELECT COALESCE(string_agg(concat_ws(',', rule_id, "
                        "upper(left(state, 1)), CASE WHEN order_uncertain THEN 't' ELSE 'f' END, "
                        "COALESCE(boot_epoch::text, ''), COALESCE(emit_seq::text, ''), "
                        "COALESCE(key_ns::text, ''), COALESCE(ts_hwm::text, ''), "
                        "COALESCE(seq_hwm::text, ''), COALESCE(ingest_seq::text, ''), "
                        "COALESCE(hwm_recv_ns::text, '')), ';' ORDER BY rule_id), '') FROM ") +
            kSchema + ".guardian_agent_rule_status WHERE agent_id = '" + agent_ + "'");
        for (const std::string& rec : split(rows, ';')) {
            // concat_ws drops nothing here (every field is COALESCEd), so the split is exact.
            std::vector<std::string> f = split(rec, ',');
            while (f.size() < 10)
                f.push_back("");
            s.rows.push_back(f[0] + "|" + f[1] + "|" + f[2] + "|" + f[3] + "|" + f[4] + "|" +
                             model_s(f[5]) + "|" + model_s(f[6]) + "|" + ordinal(f[7]) + "|" +
                             ordinal(f[8]));
            clock_check(f[0].c_str(), f[9], model_hwm_recv(i_now_, f[0]), now_ns, at, clock_notes);
        }
        s.pending = probe_.one(std::string("SELECT COALESCE(string_agg(substr(event_id, 2), ',' "
                                           "ORDER BY ingest_seq), '') FROM ") +
                               kSchema + ".guaranteed_state_events WHERE agent_id = '" + agent_ +
                               "' AND projection_pending");
        const std::string ord = probe_.one(
            std::string("SELECT concat_ws('|', COALESCE(epoch::text, ''), "
                        "COALESCE(emit_seq_hwm::text, ''), COALESCE(retired_epoch::text, ''), "
                        "unpaired_events, unpaired_held, pair_regressions, pair_stragglers, "
                        "pair_recoveries, pair_duplicates, retired_events, "
                        "COALESCE(epoch_recv_ns::text, '')) FROM ") +
            kSchema + ".guardian_agent_order WHERE agent_id = '" + agent_ + "'");
        std::vector<std::string> f = split(ord, '|');
        if (f.empty())
            f = {"", "", "", "0", "0", "0", "0", "0", "0", "0", ""};
        f.resize(11);
        s.agent = f[0] + "|" + f[1] + "|" + f[2];
        for (int k = 3; k < 10; ++k)
            s.agent += "|" + f[static_cast<std::size_t>(k)];
        clock_check("agent clock", f[10], s_.expect[i_now_].agent_time, now_ns, at, clock_notes);
        return s;
    }
    // The model's hwm_recv of the census row of rule `r<n>` after the step under comparison.
    std::string model_hwm_recv(std::size_t i, const std::string& rule_id) const {
        const Snap& m = s_.expect[i];
        for (std::size_t k = 0; k < m.rows.size(); ++k)
            if (m.rows[k].compare(0, rule_id.size() + 1, rule_id + "|") == 0)
                return m.times[k].substr(0, m.times[k].find('|'));
        return "";
    }

    void compare(std::size_t i, const DecisionCounts& before, const std::vector<std::string>& labels) {
        i_now_ = i;
        std::string clock_notes;
        const Snap got = actual(s_.acts[i].at, clock_notes);
        const std::string want_text = snap_text(s_.expect[i], false, s_.seed, i, "");
        const std::string got_text = snap_text(got, false, s_.seed, i, "");
        if (labels_ && !label_reported_) {
            const std::string want = expected_delta(labels);
            const std::string have = decision_delta(before, decision_counts(metrics_));
            if (want != have) {
                label_reported_ = true; // once per seed; the state comparison goes on
                FAIL_CHECK("seed " << s_.seed << ": after step " << i
                                       << " the decision labels counted were " << have
                                       << ", the model's " << want);
            }
        }
        if (got_text != want_text || !clock_notes.empty()) {
            failed_ = true;
            FAIL_CHECK("seed " << s_.seed << " (" << s_.campaign->name << ") first differs after step "
                               << i << "\n--- model (expected) ---\n" << want_text
                               << "--- store (actual) ---\n" << got_text
                               << (got_text == want_text ? "(census rows, pending set and order row agree)\n" : "")
                               << clock_notes);
        }
    }

    GuaranteedStateStore& store_;
    std::string dsn_;
    yuzu::MetricsRegistry& metrics_;
    const Seed& s_;
    bool labels_;
    Probe probe_;
    std::string agent_;
    std::optional<FailSwitch> fail_;
    std::map<int, GuaranteedStateEventRow> rows_;
    std::vector<i64> ingest_; // ingest_seq of the k-th first delivery: the model's iseq k + 1
    i64 last_at_{-1};
    std::size_t i_now_{0};
    bool failed_{false};
    bool label_reported_{false};
};

// A checked non-negative integer from an environment variable: the whole text must be a decimal
// number that fits an int. A malformed value throws (the running test case fails with the message)
// instead of silently running seed 0 or the default range, which would pass for the wrong reason.
int checked_env_int(const char* name, const char* text) {
    errno = 0;
    char* end = nullptr;
    const unsigned long long v = std::strtoull(text, &end, 10);
    if (end == text || *end != '\0' || errno != 0 || text[0] == '-' || text[0] == '+' ||
        v > static_cast<unsigned long long>(std::numeric_limits<int>::max()))
        throw std::runtime_error(std::string(name) + "='" + text +
                                 "' is not a non-negative decimal integer that fits an int");
    return static_cast<int>(v);
}

std::pair<int, int> seed_range() {
    if (const char* only = std::getenv("YUZU_TEST_PAIR_HARNESS_ONLY"); only && *only) {
        const int seed = checked_env_int("YUZU_TEST_PAIR_HARNESS_ONLY", only);
        return {seed, seed + 1};
    }
    if (const char* n = std::getenv("YUZU_TEST_PAIR_HARNESS_SEEDS"); n && *n) {
        const int count = checked_env_int("YUZU_TEST_PAIR_HARNESS_SEEDS", n);
        if (count == 0)
            throw std::runtime_error("YUZU_TEST_PAIR_HARNESS_SEEDS=0 would run no seeds");
        return {0, count};
    }
    return {0, 64};
}

bool labels_enabled() {
    const char* v = std::getenv("YUZU_TEST_PAIR_HARNESS_DECISIONS");
    return v == nullptr || std::string(v) != "0";
}

} // namespace

TEST_CASE("census pair harness: the C++ port agrees with the Python model",
          "[census][ordering][pair][harness][digest]") {
    // No database: the generator and the model are ported, and this pins the port to the Python
    // model's schedules and per-step traces for the first 64 seeds (digests in kPythonDigests).
    for (std::size_t seed = 0; seed < kPythonDigests.size(); ++seed) {
        Seed s = generate(seed);
        Model m;
        run_model(s, m);
        INFO("seed " << seed << " (a mismatch means the port, or the Python model, changed)");
        CHECK(fnv1a(schedule_text(s)) == kPythonDigests[seed][0]);
        CHECK(fnv1a(trace_text(s)) == kPythonDigests[seed][1]);
    }
}

TEST_CASE("census pair harness: seeds replayed through the store against the model",
          "[pg][guaranteed_state_store][db][census][ordering][pair][harness]") {
    const auto seeds = seed_range();
    const int seed = GENERATE_COPY(range(seeds.first, seeds.second));
    YUZU_REQUIRE_PG_DB_TPL(db, harness_tpl);
    Seed s = generate(static_cast<std::size_t>(seed));
    adapt(s);
    INFO("seed " << seed << ": campaign '" << s.campaign->name << "', " << s.nrules
                 << " rules; replay with YUZU_TEST_PAIR_HARNESS_ONLY=" << seed
                 << "\nschedule (F,at,id,rule,state,ts,epoch,seq,fail | R,at,id,fail):\n"
                 << schedule_text(s));
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    GuaranteedStateStore store(pool);
    REQUIRE(store.is_open());
    yuzu::MetricsRegistry metrics;
    store.set_metrics(&metrics);
    for (int r = 0; r < s.nrules; ++r)
        REQUIRE(store.create_rule(make_rule("r" + std::to_string(r))));
    Replay replay(store, db.dsn(), metrics, s, labels_enabled());
    CHECK(replay.run());
}
