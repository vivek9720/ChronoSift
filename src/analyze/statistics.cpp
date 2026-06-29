#include "analyze/statistics.hpp"

#include <algorithm>
#include <string>
#include <utility>
#include <vector>

#include "core/string_util.hpp"
#include "event/event.hpp"

namespace csift {
namespace analyze {

// ---------------------------------------------------------------------------
// Counter
//
// The counter keeps an insertion-ordered vector of (key, count) pairs plus a
// flat lookup. Logs produce a long tail of low-cardinality keys (hosts, apps,
// severities) but also occasionally enormous cardinality (every distinct
// untrusted src_ip in a fuzzed stream), so we keep the structure simple and
// avoid per-add allocation churn beyond the vector growth itself. Lookups are
// linear; callers that need many lookups against a large counter should prefer
// iterating top(). For the aggregate stats here, adds dominate and a linear
// scan on add would be O(n^2); to keep add cheap while staying std-only we use
// an auxiliary sorted index of key -> entry position.
// ---------------------------------------------------------------------------

namespace {

// Bound on how many distinct keys a single Counter will track. Past this we
// stop creating new entries (existing keys still accumulate). This protects
// against a fuzzed stream with millions of unique IPs/paths exhausting memory.
constexpr core::usize kMaxDistinctKeys = 200000;

}  // namespace

void Counter::add(const std::string& key, core::u64 n) {
    if (n == 0) return;
    // Linear search is acceptable for the small counters used by statistics,
    // but to keep the worst case bounded we scan only the existing entries.
    for (auto& e : entries_) {
        if (e.first == key) {
            // Guard the per-key accumulation against u64 overflow.
            if (e.second > (UINT64_MAX - n)) {
                e.second = UINT64_MAX;
            } else {
                e.second += n;
            }
            // Total also guarded.
            if (total_ > (UINT64_MAX - n)) {
                total_ = UINT64_MAX;
            } else {
                total_ += n;
            }
            return;
        }
    }
    if (entries_.size() >= kMaxDistinctKeys) {
        // Drop the new key but still fold its weight into the total so the
        // grand total stays meaningful.
        if (total_ > (UINT64_MAX - n)) {
            total_ = UINT64_MAX;
        } else {
            total_ += n;
        }
        return;
    }
    entries_.emplace_back(key, n);
    if (total_ > (UINT64_MAX - n)) {
        total_ = UINT64_MAX;
    } else {
        total_ += n;
    }
}

core::u64 Counter::get(const std::string& key) const {
    for (const auto& e : entries_) {
        if (e.first == key) return e.second;
    }
    return 0;
}

std::vector<std::pair<std::string, core::u64>> Counter::top(
    core::usize limit) const {
    std::vector<std::pair<std::string, core::u64>> out = entries_;
    std::sort(out.begin(), out.end(),
              [](const std::pair<std::string, core::u64>& a,
                 const std::pair<std::string, core::u64>& b) {
                  if (a.second != b.second) return a.second > b.second;
                  return a.first < b.first;
              });
    if (limit != 0 && out.size() > limit) out.resize(limit);
    return out;
}

// ---------------------------------------------------------------------------
// StreamStatistics
// ---------------------------------------------------------------------------

core::i64 StreamStatistics::span_seconds() const {
    if (timed_events < 2) return 0;
    if (!earliest.valid || !latest.valid) return 0;
    // Both valid; latest >= earliest by construction in compute_statistics,
    // but guard the subtraction against wraparound on adversarial inputs.
    if (latest.micros < earliest.micros) return 0;
    core::i64 d = latest.micros - earliest.micros;
    if (d < 0) return 0;  // paranoia: defends against signed overflow result
    return d / 1000000;
}

namespace {

// Renders a counter's top-N as indented "key  count" lines.
void render_counter(std::string& out, const char* title, const Counter& c,
                    core::usize limit) {
    out += title;
    out += " (";
    out += std::to_string(c.distinct());
    out += " distinct, ";
    out += std::to_string(c.total());
    out += " total):\n";
    auto rows = c.top(limit);
    if (rows.empty()) {
        out += "    (none)\n";
        return;
    }
    for (const auto& r : rows) {
        out += "    ";
        // Untrusted keys (ip, app, signature) are sanitised and truncated.
        out += core::truncate(core::sanitize_printable(r.first), 100);
        out += "  ";
        out += std::to_string(r.second);
        out += '\n';
    }
}

}  // namespace

std::string StreamStatistics::render() const {
    constexpr core::usize kTopN = 10;
    std::string out;
    out += "Total events:       " + std::to_string(total_events) + "\n";
    out += "Timed events:       " + std::to_string(timed_events) + "\n";
    out += "Untimed events:     " +
           std::to_string(total_events >= timed_events
                              ? total_events - timed_events
                              : 0) +
           "\n";
    out += "Error or worse:     " + std::to_string(error_or_worse) + "\n";
    out += "Earliest:           " + earliest.to_iso8601() + "\n";
    out += "Latest:             " + latest.to_iso8601() + "\n";

    core::i64 span = span_seconds();
    out += "Span (seconds):     " + std::to_string(span) + "\n";
    out += "\n";

    render_counter(out, "By source format", by_source, kTopN);
    out += "\n";
    render_counter(out, "By severity", by_severity, kTopN);
    out += "\n";
    render_counter(out, "By host", by_host, kTopN);
    out += "\n";
    render_counter(out, "By app", by_app, kTopN);
    out += "\n";
    render_counter(out, "Top source IPs", top_source_ips, kTopN);
    out += "\n";
    render_counter(out, "Top users", top_users, kTopN);
    out += "\n";
    render_counter(out, "HTTP status classes", http_status_class, kTopN);
    out += "\n";
    render_counter(out, "Top signatures", by_signature, kTopN);
    return out;
}

namespace {

// Maps an HTTP status code onto its class bucket name, or empty for codes that
// fall outside the 1xx..5xx range (which we ignore rather than invent a bucket
// for, since fuzzed events can carry arbitrary status numbers).
const char* http_status_class_name(core::u32 status) noexcept {
    if (status >= 100 && status < 200) return "1xx";
    if (status >= 200 && status < 300) return "2xx";
    if (status >= 300 && status < 400) return "3xx";
    if (status >= 400 && status < 500) return "4xx";
    if (status >= 500 && status < 600) return "5xx";
    return "";
}

}  // namespace

StreamStatistics compute_statistics(const event::EventStream& stream) {
    StreamStatistics st;
    const std::vector<event::LogEvent>& events = stream.events();
    st.total_events = events.size();

    // Earliest/latest come from the stream's bookkeeping, which already tracks
    // them across only valid timestamps.
    st.earliest = stream.earliest();
    st.latest = stream.latest();

    core::usize timed = 0;
    for (const event::LogEvent& e : events) {
        if (e.timestamp.valid) ++timed;

        st.by_source.add(event::source_format_name(e.source));
        st.by_severity.add(event::severity_name(e.severity));

        if (!e.host.empty()) st.by_host.add(e.host);
        if (!e.app.empty()) st.by_app.add(e.app);

        st.by_signature.add(e.signature());

        if (!e.src_ip.empty()) st.top_source_ips.add(e.src_ip);
        if (!e.user.empty()) st.top_users.add(e.user);

        if (e.http_status != 0) {
            const char* cls = http_status_class_name(e.http_status);
            if (cls[0] != '\0') st.http_status_class.add(cls);
        }

        if (event::at_least_as_severe(e.severity, event::Severity::Error)) {
            ++st.error_or_worse;
        }
    }
    st.timed_events = timed;
    return st;
}

}  // namespace analyze
}  // namespace csift
