#ifndef CSIFT_ANALYZE_CORRELATE_HPP
#define CSIFT_ANALYZE_CORRELATE_HPP

#include <string>
#include <vector>

#include "core/time_util.hpp"
#include "core/types.hpp"
#include "event/stream.hpp"

namespace csift {
namespace analyze {

// Which event attribute sessions are keyed on.
enum class SessionKey {
    SourceIp,
    User,
    Host,
};

// A run of events sharing a key with no idle gap larger than the threshold.
struct Session {
    std::string key;
    core::Timestamp start;
    core::Timestamp end;
    std::vector<core::usize> events;  // indices into the stream

    core::i64 duration_seconds() const;
};

// Groups timed events by the chosen key, then splits each group wherever the
// inter-event gap exceeds `idle_gap_seconds`, yielding sessions. Events without
// a timestamp or without the chosen key are ignored. Output is ordered by
// session start time.
std::vector<Session> build_sessions(const event::EventStream& stream,
                                    SessionKey key, core::i64 idle_gap_seconds);

// Renders a compact session listing for tool output.
std::string render_sessions(const std::vector<Session>& sessions,
                            const event::EventStream& stream, core::usize limit);

}  // namespace analyze
}  // namespace csift

#endif  // CSIFT_ANALYZE_CORRELATE_HPP
