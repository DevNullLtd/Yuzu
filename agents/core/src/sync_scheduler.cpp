#include "sync_scheduler.hpp"

#include <spdlog/spdlog.h>

#include <algorithm>
#include <cstdint>
#include <cstdlib>
#include <mutex>
#include <optional>

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

} // namespace

SyncScheduler::SyncScheduler(std::string agent_id, KvGetFn kv_get, KvSetFn kv_set, SenderFn sender)
    : agent_id_(std::move(agent_id)), kv_get_(std::move(kv_get)), kv_set_(std::move(kv_set)),
      sender_(std::move(sender)) {}

void SyncScheduler::add_source(SyncSource src) {
    sources_.push_back(std::move(src));
    states_.emplace_back();
}

std::string SyncScheduler::kv_key(const std::string& source, const char* field) const {
    return "sync." + source + "." + field;
}

std::int64_t SyncScheduler::phase_offset(const std::string& source, std::int64_t interval) const {
    if (interval <= 0)
        return 0;
    return static_cast<std::int64_t>(fnv1a(agent_id_ + ":" + source) %
                                     static_cast<std::uint64_t>(interval));
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
    }
    st.loaded = true;
    return st;
}

void SyncScheduler::save_state(const SyncSource& src, const State& st) {
    kv_set_(kv_key(src.name, "next_fire"), std::to_string(st.next_fire));
    kv_set_(kv_key(src.name, "last_full"), std::to_string(st.last_full));
    kv_set_(kv_key(src.name, "last_hash"), st.last_hash);
    kv_set_(kv_key(src.name, "force_full"), st.force_full ? "1" : "0");
    kv_set_(kv_key(src.name, "nf_streak"), std::to_string(st.needfull_streak));
}

std::vector<std::string> SyncScheduler::request_now(std::string_view source_or_all) {
    std::vector<std::size_t> idx;
    for (std::size_t i = 0; i < sources_.size(); ++i)
        if (source_or_all == kAllSources || sources_[i].name == source_or_all)
            idx.push_back(i);
    std::vector<std::string> names;
    if (idx.empty())
        return names;
    std::lock_guard<std::mutex> lk(pending_mu_);
    for (std::size_t i : idx) {
        if (std::find(pending_.begin(), pending_.end(), i) == pending_.end())
            pending_.push_back(i);
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
    std::vector<std::size_t> armed;
    {
        std::lock_guard<std::mutex> lk(pending_mu_);
        armed.swap(pending_);
    }
    std::vector<std::size_t> valid;
    valid.reserve(armed.size());
    for (std::size_t i : armed) {
        if (i >= sources_.size())
            continue;
        State& st = load_state(i, now_secs); // must run first so a never-loaded source is real
        st.next_fire = now_secs;
        st.force_full = true;
        // An operator click deliberately beats the need_full backoff ladder (UP-5):
        // the ladder exists to stop a FLEET stampeding a cold server, not to
        // hold one device an operator is looking at.
        st.needfull_streak = 0;
        save_state(sources_[i], st); // persisted BEFORE the send: a failed RPC retries full
        spdlog::info("sync: source '{}' forced by request_now", sources_[i].name);
        valid.push_back(i);
    }
    return valid;
}

bool SyncScheduler::decide_full(const State& st, const std::string& hash,
                                std::int64_t now_secs) const {
    const bool floor_due =
        (now_secs - st.last_full) >= static_cast<std::int64_t>(kFullFloor.count());
    return st.force_full || st.last_hash.empty() || floor_due || hash != st.last_hash;
}

void SyncScheduler::apply_ack(std::size_t idx, const std::string& hash, bool sent_full,
                              const std::vector<std::string>& need_full, std::int64_t now_secs) {
    const SyncSource& src = sources_[idx];
    State& st = states_[idx];
    const bool nacked = std::find(need_full.begin(), need_full.end(), src.name) != need_full.end();
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
        st.force_full = true;
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
        st.next_fire =
            next_slot(now_secs, src.interval.count(), phase_offset(src.name, src.interval.count()));
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
        auto collected = src.collect ? src.collect() : std::nullopt;
        if (!collected) {
            spdlog::debug(
                "sync: forced source '{}' collect returned nothing — will retry next tick",
                src.name);
            continue;
        }
        const std::string& blob = collected->first;
        const std::string& hash = collected->second;
        const bool full = decide_full(st, hash, now_secs);
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
        if (now_secs < st.next_fire)
            continue;

        auto collected = src.collect ? src.collect() : std::nullopt;
        if (!collected) {
            // Source unavailable this cycle (e.g. backing plugin not loaded).
            // Skip + retry next interval; leave last_hash untouched.
            spdlog::debug("sync: source '{}' collect returned nothing — skipping", src.name);
            st.next_fire = now_secs + src.interval.count();
            save_state(src, st);
            continue;
        }
        const std::string& blob = collected->first;
        const std::string& hash = collected->second;
        const bool full = decide_full(st, hash, now_secs);

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
