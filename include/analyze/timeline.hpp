#ifndef CSIFT_ANALYZE_TIMELINE_HPP
#define CSIFT_ANALYZE_TIMELINE_HPP

#include <string>
#include <vector>

#include "core/time_util.hpp"
#include "core/types.hpp"
#include "event/severity.hpp"
#include "event/stream.hpp"

namespace csift {
namespace analyze {

// Counts within one fixed-width time window.
struct TimelineBucket {
    core::Timestamp start;
    core::usize count = 0;
    core::usize error_or_worse = 0;
};

// A gap in coverage: an interval longer than the gap threshold with no events,
// which on a host timeline can indicate log tampering or an outage.
struct TimelineGap {
    core::Timestamp before;  // last event before the gap
    core::Timestamp after;   // first event after the gap
    core::i64 seconds = 0;
};

struct Timeline {
    core::i64 bucket_width_seconds = 0;
    std::vector<TimelineBucket> buckets;
    std::vector<TimelineGap> gaps;
    core::usize untimed_events = 0;

    // Index of the busiest bucket, or buckets.size() when empty.
    core::usize peak_bucket() const;

    std::string render() const;
};

// Builds a histogram of the (time-sorted) stream into `bucket_width_seconds`
// windows and records gaps longer than `gap_threshold_seconds`. The input does
// not need to be pre-sorted; the function copies timestamps and sorts them.
Timeline build_timeline(const event::EventStream& stream,
                        core::i64 bucket_width_seconds,
                        core::i64 gap_threshold_seconds);

}  // namespace analyze
}  // namespace csift

#endif  // CSIFT_ANALYZE_TIMELINE_HPP
