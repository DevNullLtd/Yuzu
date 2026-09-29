#pragma once

#include <atomic>
#include <chrono>
#include <cmath>
#include <format>
#include <mutex>
#include <string>
#include <tuple>
#include <unordered_map>
#include <utility>
#include <vector>

namespace yuzu {

// ── Label set (key-value pairs for metric dimensions) ────────────────────────

using Labels = std::vector<std::pair<std::string, std::string>>;

// Escape label values for Prometheus exposition format (per OpenMetrics spec):
// backslash → \\, double-quote → \", newline → \n
inline std::string escape_label_value(const std::string& v) {
    std::string out;
    out.reserve(v.size());
    for (char c : v) {
        switch (c) {
            case '\\': out += "\\\\"; break;
            case '"':  out += "\\\""; break;
            case '\n': out += "\\n";  break;
            default:   out += c;      break;
        }
    }
    return out;
}

inline std::string labels_key(const Labels& labels) {
    std::string key;
    for (const auto& [k, v] : labels) {
        if (!key.empty())
            key += ',';
        key += k + "=\"" + escape_label_value(v) + "\"";
    }
    return key;
}

inline std::string labels_prometheus(const Labels& labels) {
    if (labels.empty())
        return {};
    std::string out = "{";
    for (size_t i = 0; i < labels.size(); ++i) {
        if (i > 0)
            out += ',';
        out += labels[i].first + "=\"" + escape_label_value(labels[i].second) + "\"";
    }
    out += '}';
    return out;
}

// ── Counter ─────────────────────────────────────────────────────────────────

class Counter {
public:
    void increment(double v = 1.0) {
        std::lock_guard lock(mu_);
        value_ += v;
    }
    double value() const {
        std::lock_guard lock(mu_);
        return value_;
    }

private:
    mutable std::mutex mu_;
    double value_ = 0.0;
};

// ── Gauge ───────────────────────────────────────────────────────────────────

class Gauge {
public:
    void set(double v) {
        std::lock_guard lock(mu_);
        value_ = v;
    }
    void increment(double v = 1.0) {
        std::lock_guard lock(mu_);
        value_ += v;
    }
    void decrement(double v = 1.0) {
        std::lock_guard lock(mu_);
        value_ -= v;
    }
    double value() const {
        std::lock_guard lock(mu_);
        return value_;
    }

private:
    mutable std::mutex mu_;
    double value_ = 0.0;
};

// ── Histogram ───────────────────────────────────────────────────────────────

class Histogram {
public:
    explicit Histogram(std::vector<double> buckets = default_buckets())
        : boundaries_(std::move(buckets)), bucket_counts_(boundaries_.size() + 1, 0) {}

    void observe(double value) {
        std::lock_guard lock(mu_);
        sum_ += value;
        count_++;
        // Increment only the first matching bucket (non-cumulative storage).
        // snapshot() cumulates on export for Prometheus format.
        bool placed = false;
        for (size_t i = 0; i < boundaries_.size(); ++i) {
            if (!placed && value <= boundaries_[i]) {
                bucket_counts_[i]++;
                placed = true;
                break;
            }
        }
        if (!placed) {
            bucket_counts_.back()++; // +Inf bucket (value exceeds all boundaries)
        }
    }

    struct Snapshot {
        double sum;
        uint64_t count;
        std::vector<double> boundaries;
        std::vector<uint64_t> cumulative_counts;
    };

    Snapshot snapshot() const {
        std::lock_guard lock(mu_);
        Snapshot s;
        s.sum = sum_;
        s.count = count_;
        s.boundaries = boundaries_;
        // Make cumulative
        s.cumulative_counts.resize(boundaries_.size() + 1);
        uint64_t cumulative = 0;
        for (size_t i = 0; i < boundaries_.size(); ++i) {
            cumulative += bucket_counts_[i];
            s.cumulative_counts[i] = cumulative;
        }
        s.cumulative_counts.back() = count_;
        return s;
    }

    static std::vector<double> default_buckets() {
        return {0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0};
    }

    // Latency buckets extended into the 10-60s saturation tail, for histograms
    // whose p99 can sit past the default 10s ceiling under load (inventory
    // full-replace ingest, Postgres pool acquire under contention). Without these
    // the tail collapses into +Inf and an alert must reconstruct it from the
    // +Inf-minus-le=10 complement. #1686.
    static std::vector<double> seconds_buckets_60s() {
        return {0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0,
                15.0, 20.0, 30.0, 45.0, 60.0};
    }

private:
    mutable std::mutex mu_;
    std::vector<double> boundaries_;
    std::vector<uint64_t> bucket_counts_;
    double sum_ = 0.0;
    uint64_t count_ = 0;
};

// ── Labeled metric families ─────────────────────────────────────────────────

template <typename T> class MetricFamily {
public:
    T& labels(const Labels& l) {
        auto key = labels_key(l);
        std::lock_guard lock(mu_);
        return instances_[key].metric;
    }

    // Get-or-create a series whose metric is constructed with `buckets` on first
    // insertion. std::piecewise_construct builds the metric IN PLACE in the map
    // node — Histogram holds a std::mutex and is therefore non-movable, so it can
    // never be constructed-then-moved/copied in. On an existing series `buckets`
    // is ignored (boundaries are fixed at first creation, per Prometheus). Only
    // instantiated for metric types whose ctor accepts buckets (Histogram). #1686.
    T& labels_with_buckets(const Labels& l, std::vector<double> buckets) {
        auto key = labels_key(l);
        std::lock_guard lock(mu_);
        auto it = instances_.find(key);
        if (it == instances_.end())
            it = instances_
                     .emplace(std::piecewise_construct, std::forward_as_tuple(std::move(key)),
                              std::forward_as_tuple(std::move(buckets)))
                     .first;
        return it->second.metric;
    }

    T& no_labels() { return labels({}); }

    struct Entry {
        Labels label_set;
        T metric;
    };

    void clear() {
        std::lock_guard lock(mu_);
        instances_.clear();
    }

    // For serialization
    std::vector<std::pair<std::string, T*>> all() {
        std::lock_guard lock(mu_);
        std::vector<std::pair<std::string, T*>> result;
        for (auto& [key, entry] : instances_) {
            result.emplace_back(key, &entry.metric);
        }
        return result;
    }

private:
    struct LabeledInstance {
        T metric;
        LabeledInstance() = default;
        // Construct the wrapped metric in place from a Histogram's custom bucket
        // boundaries. Only instantiated when labels_with_buckets() is used — i.e.
        // for MetricFamily<Histogram>; never for Counter/Gauge families. #1686.
        explicit LabeledInstance(std::vector<double> buckets) : metric(std::move(buckets)) {}
    };
    std::mutex mu_;
    std::unordered_map<std::string, LabeledInstance> instances_;
};

// ── Registry — collects all metrics and serializes to Prometheus format ─────

class MetricsRegistry {
public:
    struct MetricInfo {
        std::string name;
        std::string help;
        std::string type; // "counter", "gauge", "histogram"
    };

    Counter& counter(const std::string& name) {
        std::lock_guard lock(mu_);
        return counters_[name].no_labels();
    }

    Counter& counter(const std::string& name, const Labels& l) {
        std::lock_guard lock(mu_);
        return counters_[name].labels(l);
    }

    Gauge& gauge(const std::string& name) {
        std::lock_guard lock(mu_);
        return gauges_[name].no_labels();
    }

    Gauge& gauge(const std::string& name, const Labels& l) {
        std::lock_guard lock(mu_);
        return gauges_[name].labels(l);
    }

    Histogram& histogram(const std::string& name) {
        std::lock_guard lock(mu_);
        return histograms_[name].no_labels();
    }

    Histogram& histogram(const std::string& name, const Labels& l) {
        std::lock_guard lock(mu_);
        return histograms_[name].labels(l);
    }

    // Buckets-on-first-creation overloads (#1686). Pass the bucket boundaries the
    // series should own; ignored once the series exists (boundaries are fixed at
    // creation). `buckets` is a vector<double>, unambiguous against the Labels
    // (vector<pair<string,string>>) overloads above.
    Histogram& histogram(const std::string& name, const Labels& l, std::vector<double> buckets) {
        std::lock_guard lock(mu_);
        return histograms_[name].labels_with_buckets(l, std::move(buckets));
    }

    Histogram& histogram(const std::string& name, std::vector<double> buckets) {
        std::lock_guard lock(mu_);
        return histograms_[name].labels_with_buckets({}, std::move(buckets));
    }

    /// DESTROYS every series in the family — which INVALIDATES any `Gauge&`/`Gauge*` a
    /// caller cached from it (see `McpStreamState`, which caches two for the life of a
    /// stream to keep allocation off a locked path). Only call this on families whose
    /// gauges nobody holds a reference to.
    void clear_gauge_family(const std::string& name) {
        std::lock_guard lock(mu_);
        if (auto it = gauges_.find(name); it != gauges_.end()) {
            it->second.clear();
        }
    }

    void describe(const std::string& name, const std::string& help, const std::string& type) {
        std::lock_guard lock(mu_);
        descriptions_[name] = {name, help, type};
    }

    std::string serialize() {
        std::lock_guard lock(mu_);
        std::string out;

        // Counters
        for (auto& [name, family] : counters_) {
            write_type_help(out, name, "counter");
            for (auto& [key, metric] : family.all()) {
                auto lbl = key.empty() ? "" : ("{" + key + "}");
                out += std::format("{}{} {}\n", name, lbl, metric->value());
            }
        }

        // Gauges
        for (auto& [name, family] : gauges_) {
            write_type_help(out, name, "gauge");
            for (auto& [key, metric] : family.all()) {
                auto lbl = key.empty() ? "" : ("{" + key + "}");
                out += std::format("{}{} {}\n", name, lbl, metric->value());
            }
        }

        // Histograms
        for (auto& [name, family] : histograms_) {
            write_type_help(out, name, "histogram");
            for (auto& [key, metric] : family.all()) {
                auto snap = metric->snapshot();
                auto base_labels = key.empty() ? "" : key;

                for (size_t i = 0; i < snap.boundaries.size(); ++i) {
                    auto le = format_double(snap.boundaries[i]);
                    auto lbl = base_labels.empty() ? std::format("le=\"{}\"", le)
                                                   : std::format("{},le=\"{}\"", base_labels, le);
                    out +=
                        std::format("{}_bucket{{{}}} {}\n", name, lbl, snap.cumulative_counts[i]);
                }
                // +Inf bucket
                auto inf_lbl = base_labels.empty() ? "le=\"+Inf\""
                                                   : std::format("{},le=\"+Inf\"", base_labels);
                out += std::format("{}_bucket{{{}}} {}\n", name, inf_lbl, snap.count);

                auto sum_lbl = base_labels.empty() ? "" : ("{" + base_labels + "}");
                out += std::format("{}_sum{} {}\n", name, sum_lbl, snap.sum);
                out += std::format("{}_count{} {}\n", name, sum_lbl, snap.count);
            }
        }

        return out;
    }

private:
    void write_type_help(std::string& out, const std::string& name,
                         const std::string& default_type) {
        auto it = descriptions_.find(name);
        if (it != descriptions_.end()) {
            out += std::format("# HELP {} {}\n", name, it->second.help);
            out += std::format("# TYPE {} {}\n", name, it->second.type);
        } else {
            out += std::format("# TYPE {} {}\n", name, default_type);
        }
    }

    static std::string format_double(double v) {
        if (v == std::floor(v) && v < 1e6) {
            return std::format("{}", static_cast<long long>(v));
        }
        return std::format("{}", v);
    }

    std::mutex mu_;
    std::unordered_map<std::string, MetricFamily<Counter>> counters_;
    std::unordered_map<std::string, MetricFamily<Gauge>> gauges_;
    std::unordered_map<std::string, MetricFamily<Histogram>> histograms_;
    std::unordered_map<std::string, MetricInfo> descriptions_;
};

} // namespace yuzu
