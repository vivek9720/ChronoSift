#ifndef CSIFT_EVENT_STREAM_HPP
#define CSIFT_EVENT_STREAM_HPP

#include <string>
#include <vector>

#include "core/time_util.hpp"
#include "core/types.hpp"
#include "event/event.hpp"

namespace csift {
namespace event {

// An ordered collection of parsed events plus aggregate bookkeeping. Parsers
// append to a stream; analysis consumes it. The stream owns its events.
class EventStream {
public:
    void add(LogEvent event);
    void reserve(core::usize n) { events_.reserve(n); }

    const std::vector<LogEvent>& events() const noexcept { return events_; }
    std::vector<LogEvent>& events() noexcept { return events_; }
    core::usize size() const noexcept { return events_.size(); }
    bool empty() const noexcept { return events_.empty(); }

    // Number of events that carried a valid timestamp.
    core::usize timed_count() const noexcept;

    // Earliest / latest valid timestamps seen (invalid if none).
    core::Timestamp earliest() const noexcept { return earliest_; }
    core::Timestamp latest() const noexcept { return latest_; }

    // Sorts events by timestamp (stable). Events without a timestamp keep their
    // relative order and sort to the front.
    void sort_by_time();

    // Count of events at or above a severity level.
    core::usize count_at_least(Severity level) const noexcept;

private:
    std::vector<LogEvent> events_;
    core::Timestamp earliest_;
    core::Timestamp latest_;
};

}  // namespace event
}  // namespace csift

#endif  // CSIFT_EVENT_STREAM_HPP
