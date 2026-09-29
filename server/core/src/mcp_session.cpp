#include "mcp_session.hpp"

#include "mcp_stream.hpp"

#include <yuzu/metrics.hpp>
#include <yuzu/server/auth.hpp>

#include <spdlog/spdlog.h>

#include <utility>

namespace yuzu::server::mcp {

namespace {
constexpr const char* kMetricSessionsActive = "yuzu_mcp_sessions_active";
constexpr const char* kMetricSessionsOpened = "yuzu_mcp_sessions_opened_total";
}  // namespace

McpSessionRegistry::McpSessionRegistry() : McpSessionRegistry(Config{}, {}, nullptr) {}

McpSessionRegistry::McpSessionRegistry(Config cfg, ClockFn clock, yuzu::MetricsRegistry* metrics)
    : cfg_(cfg), clock_(std::move(clock)), metrics_(metrics) {}

// Out-of-line: Entry holds a shared_ptr<McpStreamState>, an incomplete type at
// the header's point of definition.
McpSessionRegistry::~McpSessionRegistry() = default;

std::chrono::steady_clock::time_point McpSessionRegistry::now() const {
    return clock_ ? clock_() : std::chrono::steady_clock::now();
}

std::size_t McpSessionRegistry::principal_count_locked(const std::string& p) const {
    std::size_t n = 0;
    for (const auto& [id, e] : sessions_) {
        if (e.principal == p) {
            ++n;
        }
    }
    return n;
}

void McpSessionRegistry::publish_active_gauge(std::size_t active) const {
    // Called AFTER releasing mu_, never under it. MetricsRegistry::gauge() takes the
    // process-global metrics mutex, which /metrics also holds for the whole exposition
    // build — taking it under the registry mutex would make every Prometheus scrape
    // serialise against every MCP POST and every stream tick (both call
    // validate_and_touch). Cheap to avoid; nasty to diagnose.
    if (metrics_ != nullptr) {
        metrics_->gauge(kMetricSessionsActive).set(static_cast<double>(active));
    }
}

std::vector<std::shared_ptr<McpStreamState>> McpSessionRegistry::gc_locked() {
    std::vector<std::shared_ptr<McpStreamState>> reaped;
    const auto cutoff = now();
    for (auto it = sessions_.begin(); it != sessions_.end();) {
        if (cutoff - it->second.last_seen > cfg_.idle_ttl) {
            // Collect, don't close: closing takes the stream's mutex, and a
            // publisher takes that mutex before touching a sink — so calling into a
            // stream while we hold mu_ would nest the two locks in the forbidden
            // order. The caller closes these after releasing mu_.
            reaped.push_back(std::move(it->second.stream));
            it = sessions_.erase(it);
        } else {
            ++it;
        }
    }
    return reaped;
}

void McpSessionRegistry::gc() {
    std::vector<std::shared_ptr<McpStreamState>> reaped;
    std::size_t active = 0;
    {
        std::lock_guard<std::mutex> lk(mu_);
        reaped = gc_locked();
        active = sessions_.size();
    }
    publish_active_gauge(active);
    for (const auto& s : reaped) {
        if (s) {
            s->close(McpStreamClose::kSessionTerminated);
        }
    }
}

std::size_t McpSessionRegistry::shutdown() noexcept {
    std::unordered_map<std::string, Entry> grabbed;
    {
        std::lock_guard<std::mutex> lk(mu_);
        if (closing_) {
            return 0;  // idempotent — a second call finds an already-empty map anyway
        }
        closing_ = true;
        grabbed.swap(sessions_);  // O(1), non-throwing — keeps the critical section trivial
    }
    // Best-effort tail, outside mu_ (lock order, as in gc_locked): closing a stream
    // takes its own mutex, and this function is noexcept (called from
    // ServerImpl::stop(), itself noexcept), so nothing below may escape.
    // McpStreamState::close() is not itself declared noexcept — a lock_guard ctor
    // can theoretically throw — so each close is individually contained: one bad
    // stream must not stop the rest from being signalled (mirrors #3043's still-open
    // request to give gc()/mint()/validate_and_touch()'s close_sink() calls the same
    // containment poison_terminal() already has; this call site is native-contained
    // from the start rather than added retroactively).
    for (auto& [id, entry] : grabbed) {
        if (entry.stream) {
            try {
                entry.stream->close(McpStreamClose::kSessionTerminated);
            } catch (...) {
                // Mirror poison_close_contained's posture (mcp_stream.cpp): a swallowed
                // close failure must not also be a swallowed diagnostic, or an operator
                // sees a lower "close-signalled" count than sessions actually existed
                // with no explanation. The log call itself is the one thing here that
                // could still throw (spdlog's formatter allocates), so it gets its own
                // net — nothing left to safely do if even that fails.
                try {
                    spdlog::warn("MCP sessions: close of session [{}] failed and was "
                                 "contained during shutdown; the client may see a bare "
                                 "connection drop instead of a close frame",
                                 id.substr(0, 8));
                } catch (...) {  // NOLINT(bugprone-empty-catch)
                }
            }
        }
    }
    try {
        publish_active_gauge(0);
    } catch (...) {  // NOLINT(bugprone-empty-catch) — nothing left we could safely do
    }
    return grabbed.size();
}

McpSessionRegistry::MintResult McpSessionRegistry::mint(const std::string& principal) {
    std::vector<std::shared_ptr<McpStreamState>> reaped;
    MintResult result;
    std::size_t active = 0;
    bool opened = false;
    // Built BEFORE the lock. Constructing it resolves its metric gauges, which takes the
    // process-global metrics mutex — and /metrics holds that one for a whole exposition
    // build, so doing it under the registry lock would make every scrape stall every MCP
    // session operation. The cost of building one we then discard on a cap reject is a
    // single small allocation on a path that is already rejecting.
    auto stream = std::make_shared<McpStreamState>(cfg_.ring_cap, metrics_, cfg_.ring_bytes_cap);
    {
        std::lock_guard<std::mutex> lk(mu_);
        reaped = gc_locked();  // reclaim idle sessions before enforcing caps

        if (closing_) {
            result = {false, {}, "shutdown"};
        } else if (sessions_.size() >= cfg_.global_cap) {
            result = {false, {}, "global_cap"};
        } else if (principal_count_locked(principal) >= cfg_.per_principal_cap) {
            result = {false, {}, "per_principal_cap"};
        } else {
            // 16 CSPRNG bytes → 32 lowercase hex chars = 128-bit id. Regenerate on the
            // (astronomically unlikely) collision rather than overwrite a live session.
            std::string id;
            bool free_slot = false;
            for (int attempt = 0; attempt < 4; ++attempt) {
                id = auth::AuthManager::bytes_to_hex(auth::AuthManager::random_bytes(16));
                if (sessions_.find(id) == sessions_.end()) {
                    free_slot = true;
                    break;
                }
            }
            if (!free_slot) {
                // Four consecutive 128-bit CSPRNG collisions is impossible with a healthy
                // RNG; a degenerate/constant RNG is the only way here. Reject rather than
                // emplace onto an existing key (which would no-op yet report success,
                // binding the caller to a foreign entry) — keeps mint total (governance
                // CPP-I1 / UP-7).
                result = {false, {}, "id_generation"};
            } else {
                const auto t = now();
                // Attribute this stream's rare publish() WARN lines to the session. Set
                // WHILE the stream is still exclusively owned by this local (before the
                // emplace hands it to the map under mu_) - that is the write-once-before-
                // shared contract set_log_context relies on. An 8-char prefix is enough to
                // correlate against the audit log without putting the full session id in
                // application logs.
                stream->set_log_context("sid=" + id.substr(0, 8));
                sessions_.emplace(id, Entry{principal, t, t, std::move(stream)});
                opened = true;
                result = {true, id, {}};
            }
        }
        active = sessions_.size();
    }
    if (opened && metrics_ != nullptr) {
        metrics_->counter(kMetricSessionsOpened).increment();
    }
    publish_active_gauge(active);
    for (const auto& s : reaped) {
        if (s) {
            s->close(McpStreamClose::kSessionTerminated);
        }
    }
    return result;
}

McpSessionRegistry::ValidateResult
McpSessionRegistry::validate_and_touch(const std::string& id, const std::string& principal) {
    std::vector<std::shared_ptr<McpStreamState>> reaped;
    ValidateResult result = ValidateResult::kUnknown;
    std::size_t active = 0;
    {
        std::lock_guard<std::mutex> lk(mu_);
        reaped = gc_locked();
        auto it = sessions_.find(id);
        // Wrong principal is indistinguishable from unknown (no existence oracle,
        // CH-8). The extra string compare vs. a straight miss is negligible against
        // network latency — "no gross timing divergence" per Decision 15(a).
        if (it != sessions_.end() && it->second.principal == principal) {
            it->second.last_seen = now();
            result = ValidateResult::kValid;
        }
        active = sessions_.size();
    }
    publish_active_gauge(active);
    for (const auto& s : reaped) {
        if (s) {
            s->close(McpStreamClose::kSessionTerminated);
        }
    }
    return result;
}

std::shared_ptr<McpStreamState> McpSessionRegistry::stream_for(const std::string& id,
                                                               const std::string& principal) {
    std::lock_guard<std::mutex> lk(mu_);
    auto it = sessions_.find(id);
    if (it == sessions_.end() || it->second.principal != principal) {
        return nullptr;  // same no-oracle answer as validate_and_touch
    }
    it->second.last_seen = now();
    return it->second.stream;
}

bool McpSessionRegistry::terminate(const std::string& id, const std::string& principal) {
    std::shared_ptr<McpStreamState> stream;
    std::size_t active = 0;
    {
        std::lock_guard<std::mutex> lk(mu_);
        auto it = sessions_.find(id);
        if (it == sessions_.end() || it->second.principal != principal) {
            return false;
        }
        stream = std::move(it->second.stream);
        sessions_.erase(it);
        active = sessions_.size();
    }
    publish_active_gauge(active);
    // Outside mu_ (lock order, as in gc_locked). The stream state itself survives
    // until the live provider's release callback drops the last reference — the
    // erase above only removes the registry's.
    if (stream) {
        stream->close(McpStreamClose::kSessionTerminated);
    }
    return true;
}

std::size_t McpSessionRegistry::active_count() const {
    std::lock_guard<std::mutex> lk(mu_);
    return sessions_.size();
}

bool McpSessionRegistry::exists(const std::string& id, const std::string& principal) const {
    std::lock_guard<std::mutex> lk(mu_);
    auto it = sessions_.find(id);
    if (it == sessions_.end() || it->second.principal != principal) {
        return false;
    }
    return now() - it->second.last_seen <= cfg_.idle_ttl;  // gc_locked's predicate, negated
}

}  // namespace yuzu::server::mcp
