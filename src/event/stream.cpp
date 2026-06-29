#include "event/stream.hpp"

#include <algorithm>

namespace csift {
namespace event {

void EventStream::add(LogEvent event) {
    if (event.timestamp.valid) {
        if (!earliest_.valid || event.timestamp.micros < earliest_.micros) {
            earliest_ = event.timestamp;
        }
        if (!latest_.valid || event.timestamp.micros > latest_.micros) {
            latest_ = event.timestamp;
        }
    }
    events_.push_back(std::move(event));
}

core::usize EventStream::timed_count() const noexcept {
    core::usize n = 0;
    for (const LogEvent& e : events_) {
        if (e.timestamp.valid) ++n;
    }
    return n;
}

void EventStream::sort_by_time() {
    std::stable_sort(events_.begin(), events_.end(),
                     [](const LogEvent& a, const LogEvent& b) {
                         return a.timestamp < b.timestamp;
                     });
}

core::usize EventStream::count_at_least(Severity level) const noexcept {
    core::usize n = 0;
    for (const LogEvent& e : events_) {
        if (at_least_as_severe(e.severity, level)) ++n;
    }
    return n;
}

}  // namespace event
}  // namespace csift
