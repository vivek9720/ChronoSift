#ifndef CSIFT_EVENT_SEVERITY_HPP
#define CSIFT_EVENT_SEVERITY_HPP

#include <string>

#include "core/types.hpp"

namespace csift {
namespace event {

// A single normalized severity scale that every source format maps onto. The
// numeric values mirror the syslog severity ordering (0 = most severe) so they
// can be compared directly and so a syslog priority maps without translation.
enum class Severity {
    Emergency = 0,
    Alert = 1,
    Critical = 2,
    Error = 3,
    Warning = 4,
    Notice = 5,
    Informational = 6,
    Debug = 7,
    Unknown = 8,
};

const char* severity_name(Severity s) noexcept;

// Maps a raw 0-7 syslog severity number onto the enum, clamping out-of-range.
Severity severity_from_syslog(core::u32 value) noexcept;

// Maps a free-text level word ("err", "WARNING", "crit", "informational", ...)
// onto the scale. Returns Unknown when unrecognised.
Severity severity_from_word(const std::string& word);

// Maps a Windows event "Level" field (1=Critical .. 5=Verbose) onto the scale.
Severity severity_from_winlevel(core::u32 level) noexcept;

// True if `a` is at least as severe as `b` (i.e. a numerically <= b, excluding
// Unknown which is never "more severe").
bool at_least_as_severe(Severity a, Severity b) noexcept;

}  // namespace event
}  // namespace csift

#endif  // CSIFT_EVENT_SEVERITY_HPP
