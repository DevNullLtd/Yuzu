#include "sync_scheduler.hpp"

#include <spdlog/spdlog.h>

#include <algorithm>
#include <cstdint>
#include <cstdlib>
#include <limits>
#include <mutex>
#include <optional>
#include <string>

namespace yuzu::agent {

namespace {

// FNV-1a 64-bit over a string — deterministic across platforms and process
// runs (unlike std::hash), so the per-(agent,source) phase offset is stable
// across reboots (ADR-0016 §3): the fleet keeps a uniform, reproducible spread.
std::uint64_t fnv1a(const std::string& s) {
    std::uint64_t h = 1469598103934665603ULL;
    for (unsigned char c : s) {
        h ^= c;
        h *= 1099511628211ULL;
    }
    return h;
}

// Smallest T > now with (T mod interval) == offset (the next phase-aligned slot).
std::int64_t next_slot(std::int64_t now, std::int64_t interval, std::int64_t offset) {
    if (interval <= 0)
        return now + 1;
    std::int64_t base = now - (now % interval) + offset;
    if (base <= now)
        base += interval;
    return base;
}

// A persisted next_fire further ahead than this is not a schedule this agent wrote: the
// longest legitimate lead is a skip-ladder or window placement of 24 h plus a window, so
// 2 days is a bound, not a tunable. A clock stepped back (NTP, a VM restore) or a corrupt
// KV value would otherwise stall the source until the wall clock caught up.
constexpr std::int64_t kFarFutureSlack = 2 * 24 * 60 * 60;

} // namespace

SyncScheduler::SyncScheduler(std::string agent_id, KvGetFn kv_get, KvSetFn kv_set, SenderFn sender,
                             LocalClock clock)
    : agent_id_(std::move(agent_id)), kv_get_(std::move(kv_get)), kv_set_(std::move(kv_set)),
      sender_(std::move(sender)), clock_(std::move(clock)) {}

void SyncScheduler::add_source(SyncSource src) {
    sources_.push_back(std::move(src));
    states_.emplace_back();
}

std::string sanitize_skip_reason(std::string_view reason) {
    std::string out;
    out.reserve(std::min(reason.size(), kPluginHeartbeatMaxValueBytes));
    for (unsigned char c : reason.substr(0, kPluginHeartbeatMaxValueBytes)) {
        const bool ok = (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') ||
                        (c >= '0' && c <= '9') || c == '_' || c == '.' || c == ':' || c == '=' ||
                        c == ',' || c == '-';
        out.push_back(ok ? static_cast<char>(c) : '_');
    }
    return out;
}

std::string SyncScheduler::kv_key(const std::string& source, const char* field) {
    return "sync." + source + "." + field;
}

std::int64_t SyncScheduler::phase_offset(const std::string& source, std::int64_t interval) const {
    if (interval <= 0)
        return 0;
    return static_cast<std::int64_t>(fnv1a(agent_id_ + ":" + source) %
                                     static_cast<std::uint64_t>(interval));
}

std::int64_t SyncScheduler::next_due(std::size_t idx, std::int64_t now_secs) const {
    const SyncSource& src = sources_[idx];
    if (src.window)
        return next_window_fire(now_secs, *src.window,
                                fnv1a(agent_id_ + ":window:" + src.name), clock_);
    return next_slot(now_secs, src.interval.count(),
                     phase_offset(src.name, src.interval.count()));
}

void SyncScheduler::catch_up_if_overdue(std::size_t idx, std::int64_t now_secs) {
    State& st = states_[idx];
    // Two comparisons, no `now - next_fire`: next_fire comes from strtoll, which saturates a
    // corrupt value to LLONG_MIN/LLONG_MAX, and that subtraction would overflow.
    if (st.next_fire >= now_secs - kMaxTickSeconds.count() &&
        st.next_fire <= now_secs + kFarFutureSlack)
        return;
    const SyncSource& src = sources_[idx];
    const bool overdue = st.next_fire < now_secs;
    st.next_fire = now_secs + static_cast<std::int64_t>(
                                  fnv1a(agent_id_ + ":catchup:" + src.name) %
                                  static_cast<std::uint64_t>(kCatchUpWindow.count()));
    spdlog::info("sync: source '{}' had {} next fire — catching up at +{}s", src.name,
                 overdue ? "an overdue" : "an implausibly distant", st.next_fire - now_secs);
    save_state(src, st);
}

SyncScheduler::State& SyncScheduler::load_state(std::size_t idx, std::int64_t now_secs) {
    // Index in, not pointer-arithmetic out: deriving the index from `&src -
    // sources_.data()` was only well-defined because the caller always passed
    // sources_[i] (gov cpp-expert/cpp-safety) — take the index directly instead.
    const SyncSource& src = sources_[idx];
    State& st = states_[idx];
    if (st.loaded)
        return st;

    const std::string nf = kv_get_(kv_key(src.name, "next_fire"));
    if (nf.empty()) {
        // First run: catch up soon, jittered by a stable per-(agent,source)
        // offset in [0, kStartupJitterWindow) so a mass-enroll does not herd.
        const std::int64_t jitter = static_cast<std::int64_t>(
            fnv1a(agent_id_ + ":startup:" + src.name) %
            static_cast<std::uint64_t>(kStartupJitterWindow.count()));
        st.next_fire = now_secs + jitter;
        st.last_full = 0;
        st.last_hash.clear();
        st.force_full = false;
        save_state(src, st);
    } else {
        st.next_fire = std::strtoll(nf.c_str(), nullptr, 10);
        st.last_full = std::strtoll(kv_get_(kv_key(src.name, "last_full")).c_str(), nullptr, 10);
        st.last_hash = kv_get_(kv_key(src.name, "last_hash"));
        st.force_full = kv_get_(kv_key(src.name, "force_full")) == "1";
        st.needfull_streak =
            static_cast<int>(std::strtoll(kv_get_(kv_key(src.name, "nf_streak")).c_str(), nullptr, 10));
        // Clamp: a corrupt KV value must never reach the backoff shift as a negative.
        const long long ss =
            std::strtoll(kv_get_(kv_key(src.name, "skip_streak")).c_str(), nullptr, 10);
        st.skip_streak =
            static_cast<int>(std::clamp<long long>(ss, 0, std::numeric_limits<int>::max()));
        st.last_skip = kv_get_(kv_key(src.name, "last_skip"));
    }
    st.loaded = true;
    return st;
}

void SyncScheduler::save_state(const SyncSource& src, const State& st) {
    // KvStore has no multi-set transaction; the writes are ordered so a process
    // kill between them leaves the skip visible with a stale (past) next_fire —
    // the next tick simply retries — rather than an advanced next_fire with no
    // recorded reason, which would hide the skip until the next collection.
    kv_set_(kv_key(src.name, "skip_streak"), std::to_string(st.skip_streak));
    kv_set_(kv_key(src.name, "last_skip"), st.last_skip);
    kv_set_(kv_key(src.name, "next_fire"), std::to_string(st.next_fire));
    kv_set_(kv_key(src.name, "last_full"), std::to_string(st.last_full));
    kv_set_(kv_key(src.name, "last_hash"), st.last_hash);
    kv_set_(kv_key(src.name, "force_full"), st.force_full ? "1" : "0");
    kv_set_(kv_key(src.name, "nf_streak"), std::to_string(st.needfull_streak));
}

void SyncScheduler::note_skip(std::size_t idx, std::int64_t now_secs) {
    const SyncSource& src = sources_[idx];
    State& st = states_[idx];
    st.last_skip = src.skip_reason ? sanitize_skip_reason(src.skip_reason()) : std::string{};
    if (st.skip_streak < std::numeric_limits<int>::max()) // overflow guard, not a cap
        ++st.skip_streak;
    const std::int64_t interval = src.interval.count();
    if (!src.skip_backoff) {
        st.next_fire = now_secs + interval;
    } else {
        const std::int64_t slot = next_due(idx, now_secs);
        if (st.skip_streak <= kSkipRetryBudget)
            st.next_fire =
                std::min(slot, now_secs + (static_cast<std::int64_t>(kSkipRetryBase.count())
                                           << (st.skip_streak - 1)));
        else
            st.next_fire = slot; // budget spent: exactly one attempt per slot
    }
    save_state(src, st);
}

void SyncScheduler::note_collected(std::size_t idx) {
    State& st = states_[idx];
    // A reason left behind a zero streak (save_state writes skip_streak before last_skip, so an
    // interrupted clear can leave one) is cleared here too.
    if (st.skip_streak == 0 && st.last_skip.empty())
        return;
    st.skip_streak = 0;
    st.last_skip.clear();
    save_state(sources_[idx], st);
}

std::vector<std::string> SyncScheduler::request_now(std::string_view sources_csv_or_all,
                                                    std::chrono::seconds delay_max) {
    // All-or-nothing: resolve every token first, arm only if all are known.
    std::vector<std::size_t> idx;
    if (sources_csv_or_all == kAllSources) {
        for (std::size_t i = 0; i < sources_.size(); ++i)
            idx.push_back(i);
    } else {
        std::string_view rest = sources_csv_or_all;
        for (;;) {
            const auto comma = rest.find(',');
            const std::string_view tok = rest.substr(0, comma);
            const auto it = std::find_if(sources_.begin(), sources_.end(),
                                         [&](const SyncSource& s) { return s.name == tok; });
            if (it == sources_.end())
                return {};
            idx.push_back(static_cast<std::size_t>(it - sources_.begin()));
            if (comma == std::string_view::npos)
                break;
            rest.remove_prefix(comma + 1);
        }
        // Registration order, so the slow installed_software still goes last.
        std::sort(idx.begin(), idx.end());
        idx.erase(std::unique(idx.begin(), idx.end()), idx.end());
    }
    std::vector<std::string> names;
    if (idx.empty())
        return names;
    const std::int64_t delay = std::max<std::int64_t>(delay_max.count(), 0);
    std::lock_guard<std::mutex> lk(pending_mu_);
    for (std::size_t i : idx) {
        auto it = std::find_if(pending_.begin(), pending_.end(),
                               [i](const auto& p) { return p.first == i; });
        if (it == pending_.end())
            pending_.emplace_back(i, delay);
        else
            it->second = std::min(it->second, delay);
        names.push_back(sources_[i].name);
    }
    return names;
}

std::vector<std::string> SyncScheduler::source_names() const {
    std::vector<std::string> out;
    out.reserve(sources_.size());
    for (const auto& s : sources_)
        out.push_back(s.name);
    return out;
}

std::vector<std::size_t> SyncScheduler::drain_pending(std::int64_t now_secs) {
    std::vector<std::pair<std::size_t, std::int64_t>> armed;
    {
        std::lock_guard<std::mutex> lk(pending_mu_);
        armed.swap(pending_);
    }
    std::vector<std::size_t> valid;
    valid.reserve(armed.size());
    for (const auto& [i, delay] : armed) {
        if (i >= sources_.size())
            continue;
        State& st = load_state(i, now_secs); // must run first so a never-loaded source is real
        // delay 0: fire in THIS tick's forced pass. delay > 0: a stable per-(agent,source)
        // offset in [0, delay) and NOT in the forced list — the batch pass fires it when due.
        // A request only ever pulls a fire earlier: a FUTURE next_fire already sooner than the
        // offset (a skip-ladder retry, an earlier delayed click) is kept; a PAST one is replaced,
        // or catch-up would re-spread it over 30 min instead of the requested window.
        if (delay > 0) {
            const std::int64_t fire_at = now_secs + phase_offset("now:" + sources_[i].name, delay);
            st.next_fire = st.next_fire > now_secs ? std::min(st.next_fire, fire_at) : fire_at;
        } else {
            st.next_fire = now_secs;
        }
        st.force_full = true;
        // An operator click deliberately beats the need_full backoff ladder (UP-5):
        // the ladder exists to stop a FLEET stampeding a cold server, not to
        // hold one device an operator is looking at.
        st.needfull_streak = 0;
        save_state(sources_[i], st); // persisted BEFORE the send: a failed RPC retries full
        spdlog::info("sync: source '{}' forced by request_now (delay_max={}s)", sources_[i].name,
                     delay);
        if (delay == 0)
            valid.push_back(i);
    }
    return valid;
}

bool SyncScheduler::forced_full_due(std::size_t idx, const State& st, std::int64_t now_secs) const {
    // A source that heals divergence per section (SyncSource::no_full_floor) is exempt from the
    // weekly floor only; a force and a whole-source nack still send full. A never-acknowledged
    // hash is deliberately NOT in this blanket: decide_full still sends the blob for it, but a
    // sectioned source sends a facet with no acknowledged set in full by its own rule, and
    // blanketing it would re-force the facets already acknowledged after a per-facet nack.
    const bool floor_due =
        !sources_[idx].no_full_floor &&
        (now_secs - st.last_full) >= static_cast<std::int64_t>(kFullFloor.count());
    return st.force_full || floor_due;
}

bool SyncScheduler::decide_full(std::size_t idx, const State& st, const std::string& hash,
                                std::int64_t now_secs) const {
    const SyncSource& src = sources_[idx];
    return forced_full_due(idx, st, now_secs) || st.last_hash.empty() || hash != st.last_hash ||
           (src.wants_blob && src.wants_blob());
}

void SyncScheduler::apply_ack(std::size_t idx, const std::string& hash, bool sent_full,
                              const std::vector<std::string>& need_full, std::int64_t now_secs) {
    const SyncSource& src = sources_[idx];
    State& st = states_[idx];
    // The whole-source nack (the source name) and the per-section nack of a sectioned source
    // (`<name>:<detail>`) both mean the server could not take this source's report as sent.
    std::vector<std::string> named;
    for (const auto& tok : need_full) {
        if (tok == src.name ||
            (tok.size() > src.name.size() && tok.compare(0, src.name.size(), src.name) == 0 &&
             tok[src.name.size()] == ':'))
            named.push_back(tok);
    }
    const bool nacked = !named.empty();
    const bool whole_source =
        std::find(named.begin(), named.end(), src.name) != named.end();
    // The source commits (or discards) its own per-section state first, so a crash after this
    // call and before save_state() below costs at most one extra section on the next send.
    if (src.on_ack)
        src.on_ack(named);
    if (nacked) {
        // Server could not materialise from a hash-only report (cold cache /
        // drift) OR hit a transient store error — either way it nacked. Resend
        // full, but with EXPONENTIAL BACKOFF on consecutive nacks so a
        // sustained fleet-wide cold cache or a store outage does not resend at
        // a flat 30s cadence forever (governance UP-5). Each nack doubles the
        // delay from kMinTickSeconds, capped so backoff + the per-(agent,source)
        // jitter stays within kMaxTickSeconds; reset on the next clean sync
        // (the else branch). The jitter still de-stampedes a synchronized
        // fleet-wide nack (e.g. a server DB restore).
        // A per-section nack (`<name>:<detail>`) is the source's to resend, one section in full
        // (on_ack above); only the whole-source nack forces every section full again. A
        // per-section nack also CONSUMES an owed force: the forced blob was delivered and every
        // section of it attributed (the acknowledged ones are committed, the nacked one is
        // flagged by the source), so keeping the force would re-send the acknowledged sections.
        // last_hash stays as it was: this is not a complete acknowledgement.
        st.force_full = whole_source;
        st.needfull_streak += 1;
        const std::int64_t jitter_cap = kNeedFullJitterWindow.count();
        const std::int64_t max_backoff = kMaxTickSeconds.count() - jitter_cap;
        std::int64_t backoff = kMinTickSeconds.count();
        for (int s = 1; s < st.needfull_streak && backoff < max_backoff; ++s)
            backoff *= 2;
        backoff = std::min(backoff, max_backoff);
        const std::int64_t nf_jitter = static_cast<std::int64_t>(
            fnv1a(agent_id_ + ":needfull:" + src.name) % static_cast<std::uint64_t>(jitter_cap));
        st.next_fire = now_secs + backoff + nf_jitter;
    } else {
        st.last_hash = hash;
        st.force_full = false;
        st.needfull_streak = 0; // clean sync → reset the backoff ladder
        if (sent_full)
            st.last_full = now_secs;
        // A source that left part of its payload for the next collection comes straight back.
        st.next_fire = (src.has_more && src.has_more()) ? now_secs + kMinTickSeconds.count()
                                                        : next_due(idx, now_secs);
        // Once per successful sync per source (about daily): where the next one is placed.
        spdlog::info("sync: source '{}' synced — next sync at epoch {} (in {}s)", src.name,
                     st.next_fire, st.next_fire - now_secs);
    }
    save_state(src, st);
}

std::chrono::seconds SyncScheduler::tick(std::int64_t now_secs) {
    // Operator-forced sources first, so they are due in THIS pass.
    const std::vector<std::size_t> forced = drain_pending(now_secs);

    // Round-3 item 4: each forced source gets its OWN immediate ReportInventory
    // RPC (one source's {name: hash} + optional blob, not the whole due set),
    // fired as soon as THAT source's own collect() finishes — instead of
    // folding it into the one shared batch RPC below, which previously made a
    // fast forced source (device_ci/app_perf/licensing) wait behind a slow
    // one's collect() (installed_software's macOS system_profiler scan can run
    // several seconds) whenever more than one source was forced at once (the
    // header "Sync now" forces every source via kAllSources). `handled` excludes
    // these indices from the batch pass below regardless of outcome — a
    // forced source that fails here retries on the NEXT tick (its next_fire/
    // force_full were already persisted by drain_pending), never a second
    // attempt in the SAME tick via the batch path. Registration order in
    // agent.cpp decides processing order here (forced indices come out of
    // drain_pending in ascending source-index order) — installed_software
    // registers LAST so a "sync all" reports the four fast sources back to
    // the server before starting the slow one.
    std::vector<bool> handled(sources_.size(), false);
    for (std::size_t i : forced) {
        handled[i] = true;
        const SyncSource& src = sources_[i];
        State& st = load_state(i, now_secs);
        if (src.on_force_full && forced_full_due(i, st, now_secs))
            src.on_force_full();
        auto collected = src.collect ? src.collect() : std::nullopt;
        if (!collected) {
            spdlog::debug(
                "sync: forced source '{}' collect returned nothing — will retry next tick",
                src.name);
            continue;
        }
        note_collected(i);
        const std::string& blob = collected->first;
        const std::string& hash = collected->second;
        const bool full = decide_full(i, st, hash, now_secs);
        const std::vector<std::pair<std::string, std::string>> one_hash{{src.name, hash}};
        std::vector<std::pair<std::string, std::string>> one_blob;
        if (full)
            one_blob.emplace_back(src.name, blob);
        auto need_full = sender_ ? sender_(one_hash, one_blob) : std::nullopt;
        if (!need_full) {
            spdlog::debug(
                "sync: forced source '{}' ReportInventory RPC failed — will retry next tick",
                src.name);
            continue;
        }
        apply_ack(i, hash, full, *need_full, now_secs);
    }

    // Gather every REMAINING due (cadence-based, non-forced-this-tick) source's
    // hash (always) + blob (only when sending full) into ONE batch RPC —
    // unchanged from before the pass split above.
    std::vector<std::pair<std::string, std::string>> hashes;
    std::vector<std::pair<std::string, std::string>> blobs;
    std::vector<std::size_t> due_idx;
    std::vector<std::string> due_hash; // current hash per due source (index-aligned)
    std::vector<bool> sent_full;

    for (std::size_t i = 0; i < sources_.size(); ++i) {
        if (handled[i])
            continue;
        const SyncSource& src = sources_[i];
        State& st = load_state(i, now_secs);
        // Restart after being off, or resume from sleep: spread the catch-up, don't stampede.
        catch_up_if_overdue(i, now_secs);
        if (now_secs < st.next_fire)
            continue;

        if (src.on_force_full && forced_full_due(i, st, now_secs))
            src.on_force_full();
        auto collected = src.collect ? src.collect() : std::nullopt;
        if (!collected) {
            // Source unavailable this cycle (e.g. backing plugin not loaded).
            // Skip; leave last_hash untouched. note_skip picks the retry time.
            note_skip(i, now_secs);
            spdlog::debug("sync: source '{}' collect returned nothing — skipping (reason='{}', "
                          "streak={}, next_fire={})",
                          src.name, st.last_skip, st.skip_streak, st.next_fire);
            continue;
        }
        note_collected(i);
        const std::string& blob = collected->first;
        const std::string& hash = collected->second;
        const bool full = decide_full(i, st, hash, now_secs);

        hashes.emplace_back(src.name, hash);
        if (full)
            blobs.emplace_back(src.name, blob);

        due_idx.push_back(i);
        due_hash.push_back(hash);
        sent_full.push_back(full);
    }

    if (!due_idx.empty()) {
        auto need_full = sender_ ? sender_(hashes, blobs) : std::nullopt;
        if (!need_full) {
            // RPC failed — do NOT advance state; the next pass retries. The
            // clamped sleep below throttles a persistent-failure loop.
            spdlog::debug("sync: ReportInventory RPC failed — {} source(s) will retry",
                          due_idx.size());
        } else {
            for (std::size_t k = 0; k < due_idx.size(); ++k)
                apply_ack(due_idx[k], due_hash[k], sent_full[k], *need_full, now_secs);
        }
    }

    // Sleep until the soonest next_fire, clamped.
    std::int64_t soonest = now_secs + kMaxTickSeconds.count();
    for (std::size_t i = 0; i < sources_.size(); ++i) {
        if (states_[i].loaded)
            soonest = std::min(soonest, states_[i].next_fire);
    }
    std::int64_t sleep_for = soonest - now_secs;
    sleep_for = std::clamp<std::int64_t>(sleep_for, kMinTickSeconds.count(), kMaxTickSeconds.count());
    return std::chrono::seconds{sleep_for};
}

} // namespace yuzu::agent
