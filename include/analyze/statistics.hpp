#ifndef CSIFT_ANALYZE_STATISTICS_HPP
#define CSIFT_ANALYZE_STATISTICS_HPP

#include <string>
#include <utility>
#include <vector>

#include "core/types.hpp"
#include "event/severity.hpp"
#include "event/stream.hpp"

namespace csift {
namespace analyze {

// An insertion-stable frequency counter over string keys. Avoids std::map so
// iteration/order is deterministic and the top-N extraction is explicit.
class Counter {
public:
    void add(const std::string& key, core::u64 n = 1);
    core::u64 get(const std::string& key) const;
    core::u64 total() const noexcept { return total_; }
    core::usize distinct() const noexcept { return entries_.size(); }

    // Keys/counts sorted by count descending, then key ascending. `limit` of 0
    // returns all.
    std::vector<std::pair<std::string, core::u64>> top(core::usize limit = 0) const;

private:
    std::vector<std::pair<std::string, core::u64>> entries_;
    core::u64 total_ = 0;
};

// Aggregate statistics over an event stream.
struct StreamStatistics {
    core::usize total_events = 0;
    core::usize timed_events = 0;
    core::Timestamp earliest;
    core::Timestamp latest;

    Counter by_source;       // syslog/json/web-access/win-event
    Counter by_severity;     // severity name
    Counter by_host;
    Counter by_app;
    Counter by_signature;    // event signature (type)
    Counter top_source_ips;
    Counter top_users;
    Counter http_status_class;  // "2xx", "4xx", ...

    core::usize error_or_worse = 0;  // events at Error severity or above

    // Span of the capture in seconds (0 when fewer than two timed events).
    core::i64 span_seconds() const;

    std::string render() const;
};

StreamStatistics compute_statistics(const event::EventStream& stream);

}  // namespace analyze
}  // namespace csift

#endif  // CSIFT_ANALYZE_STATISTICS_HPP
