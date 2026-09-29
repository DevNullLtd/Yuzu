#pragma once

/**
 * fake_journal_store.hpp -- an in-memory, serialised test double for IJournalStore
 * (#4153).
 *
 * WHY. GuardianLifecycleJournal's two heaviest concurrency checkpoints ("concurrent
 * pagers + a drainer" and QE-1 "concurrent persist + page + prune + drain") used to
 * run several worker threads in UNBOUNDED loops against a REAL on-disk KvStore
 * (SQLite, WAL, a 5s busy timeout). Termination depended on the main thread winning
 * lock races against those workers, which starves under contention and caused real
 * CI stalls (#2373, #2345, #4018). This fake removes the SQLite dependency from
 * those two tests' correctness/termination story while preserving the exact
 * per-call contract IJournalStore requires (kv_store.hpp), so the same TSan
 * checkpoints still exercise the journal's own locking (paging_mutex_, the atomic
 * gauges, outbox_mu_ via the runtime) - just not real disk I/O.
 *
 * CONTRACT (mirrors IJournalStore's doc comment exactly - see kv_store.hpp):
 *   - every method serialises itself under ONE mutex, for the whole call;
 *   - every method returns an OWNING snapshot (a copy) and releases its lock
 *     before returning;
 *   - no method ever invokes a callback, blocks on another participant, or calls
 *     back into a journal while holding its lock.
 *
 * SEMANTICS mirror kv_store.cpp's SQLite behaviour, with one documented divergence:
 * SQLite's LIKE prefix match is ASCII-case-insensitive; this fake's prefix match is
 * plain case-sensitive std::string::starts_with. The journal's own key prefixes
 * ("lc:", "sent:", "quarantine:") are fixed lowercase literals, so this never
 * matters for the journal's own call sites - but a future consumer scanning a
 * mixed-case prefix would see a different result than the same prefix against a
 * real KvStore. Documented here rather than silently matched.
 *
 * Diagnostic counters (ops/contended) are memory_order_relaxed ONLY - a stronger
 * ordering would add a synchronises-with edge the real KvStore does not have, and
 * that mismatch could mask a genuine race the checkpoints exist to find. They are
 * reported as Catch2 INFO, never CHECKed: zero contention is a legitimate outcome
 * (e.g. the pagers/pruner/persister serialise through the journal's own
 * paging_mutex_, so the fake's own mutex may see little or no contention even
 * under a real concurrent run).
 */

#include <yuzu/agent/kv_store.hpp>

#include <atomic>
#include <cstdint>
#include <expected>
#include <map>
#include <mutex>
#include <optional>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

namespace yuzu::test {

class FakeJournalStore final : public yuzu::agent::IJournalStore {
public:
    FakeJournalStore() = default;
    ~FakeJournalStore() override = default;

    FakeJournalStore(const FakeJournalStore&) = delete;
    FakeJournalStore& operator=(const FakeJournalStore&) = delete;
    FakeJournalStore(FakeJournalStore&&) = delete;
    FakeJournalStore& operator=(FakeJournalStore&&) = delete;

    [[nodiscard]] int pragma_synchronous() override {
        auto lock = acquire();
        return 2; // always "FULL" - the fake never warns
    }

    [[nodiscard]] std::expected<yuzu::agent::KvNamespaceSize, yuzu::agent::KvStoreError>
    namespace_size(std::string_view plugin, std::string_view prefix) override {
        auto lock = acquire();
        yuzu::agent::KvNamespaceSize sz;
        const auto it = plugins_.find(std::string(plugin));
        if (it == plugins_.end())
            return sz;
        for (const auto& [key, value] : it->second) {
            if (!key.starts_with(prefix))
                continue;
            ++sz.count;
            sz.bytes += value.size();
        }
        return sz;
    }

    [[nodiscard]] std::expected<std::vector<yuzu::agent::KvKeySize>, yuzu::agent::KvStoreError>
    list_keys_sized(std::string_view plugin, std::string_view prefix) override {
        auto lock = acquire();
        std::vector<yuzu::agent::KvKeySize> out;
        const auto it = plugins_.find(std::string(plugin));
        if (it == plugins_.end())
            return out;
        // std::map<std::string, ...> iterates in ascending key order under the default
        // std::less<std::string>, which compares bytes the same way SQLite's default
        // BINARY collation does for ASCII text - matching KvStore's `ORDER BY key`.
        for (const auto& [key, value] : it->second) {
            if (!key.starts_with(prefix))
                continue;
            out.push_back(yuzu::agent::KvKeySize{key, value.size()});
        }
        return out;
    }

    [[nodiscard]] std::expected<std::optional<std::string>, yuzu::agent::KvStoreError>
    get_entry(std::string_view plugin, std::string_view key) override {
        auto lock = acquire();
        const auto it = plugins_.find(std::string(plugin));
        if (it == plugins_.end())
            return std::optional<std::string>{};
        const auto kit = it->second.find(std::string(key));
        if (kit == it->second.end())
            return std::optional<std::string>{};
        return std::optional<std::string>{kit->second};
    }

    [[nodiscard]] yuzu::agent::KvInsert insert_if_absent(std::string_view plugin,
                                                         std::string_view key,
                                                         std::string_view value) override {
        auto lock = acquire();
        auto& ns = plugins_[std::string(plugin)];
        const auto [it, inserted] = ns.try_emplace(std::string(key), std::string(value));
        (void)it;
        return inserted ? yuzu::agent::KvInsert::Inserted : yuzu::agent::KvInsert::Exists;
    }

    // Ordering matches kv_store.cpp's single UPDATE exactly (advisor-reviewed): SQLite's
    // `UPDATE ... WHERE key = from_key` matches ZERO rows when from_key is absent, so it
    // returns NotFound before any PK conflict is even evaluated - a to_key that already
    // exists is irrelevant if from_key does not. Self-rename (from_key == to_key) is a
    // single UPDATE of a row onto itself, which SQLite allows without a PK conflict.
    [[nodiscard]] yuzu::agent::KvRename rename_key(std::string_view plugin,
                                                   std::string_view from_key,
                                                   std::string_view to_key) override {
        auto lock = acquire();
        auto& ns = plugins_[std::string(plugin)];
        const std::string from(from_key);
        const std::string to(to_key);
        const auto from_it = ns.find(from);
        if (from_it == ns.end())
            return yuzu::agent::KvRename::NotFound;
        if (from == to)
            return yuzu::agent::KvRename::Renamed; // self-update, no PK conflict
        if (ns.contains(to))
            return yuzu::agent::KvRename::Conflict;
        ns.emplace(to, std::move(from_it->second));
        ns.erase(from_it);
        return yuzu::agent::KvRename::Renamed;
    }

    [[nodiscard]] int del_keys(std::string_view plugin,
                               const std::vector<std::string>& keys) override {
        auto lock = acquire();
        const auto it = plugins_.find(std::string(plugin));
        if (it == plugins_.end())
            return 0;
        int deleted = 0;
        for (const auto& k : keys)
            deleted += static_cast<int>(it->second.erase(k));
        return deleted;
    }

    bool set(std::string_view plugin, std::string_view key, std::string_view value) override {
        auto lock = acquire();
        plugins_[std::string(plugin)][std::string(key)] = std::string(value);
        return true;
    }

    // ---- diagnostics (INFO only - see file header; never CHECKed) ----
    [[nodiscard]] std::uint64_t ops() const noexcept {
        return ops_.load(std::memory_order_relaxed);
    }
    [[nodiscard]] std::uint64_t contended() const noexcept {
        return contended_.load(std::memory_order_relaxed);
    }

private:
    void note_call() noexcept { ops_.fetch_add(1, std::memory_order_relaxed); }

    // Acquire mu_ for the duration of one call, counting a miss as contention. try_lock
    // first so a successful uncontended acquisition never pays for the diagnostic.
    [[nodiscard]] std::unique_lock<std::mutex> acquire() {
        note_call();
        std::unique_lock<std::mutex> lock(mu_, std::try_to_lock);
        if (!lock.owns_lock()) {
            contended_.fetch_add(1, std::memory_order_relaxed);
            lock.lock();
        }
        return lock;
    }

    std::mutex mu_;
    std::map<std::string, std::map<std::string, std::string>> plugins_; // plugin -> key -> value
    std::atomic<std::uint64_t> ops_{0};
    std::atomic<std::uint64_t> contended_{0};
};

} // namespace yuzu::test
