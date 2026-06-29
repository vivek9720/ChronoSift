#ifndef CSIFT_CORE_TIME_UTIL_HPP
#define CSIFT_CORE_TIME_UTIL_HPP

#include <string>

#include "core/status.hpp"
#include "core/types.hpp"

// Timestamp handling for log forensics. Logs carry timestamps in a dozen
// incompatible shapes; this module parses the common ones into a single
// canonical representation (UTC microseconds since the Unix epoch) so events
// from different sources can be merged onto one timeline.
namespace csift {
namespace core {

// A point in time as microseconds since 1970-01-01T00:00:00Z. `valid` is false
// for the sentinel "unknown time" used when a record carried no parseable
// timestamp.
struct Timestamp {
    i64 micros = 0;
    bool valid = false;

    static Timestamp invalid() { return Timestamp{}; }
    static Timestamp from_micros(i64 us) { return Timestamp{us, true}; }
    static Timestamp from_unix_seconds(i64 s) { return Timestamp{s * 1000000, true}; }

    bool operator<(const Timestamp& o) const noexcept {
        if (valid != o.valid) return o.valid;  // invalid sorts first
        return micros < o.micros;
    }
    bool operator==(const Timestamp& o) const noexcept {
        return valid == o.valid && micros == o.micros;
    }

    // Difference in microseconds (this - other); meaningful only when both valid.
    i64 diff_micros(const Timestamp& o) const noexcept { return micros - o.micros; }

    // ISO-8601 UTC rendering, e.g. "2024-03-09T11:22:33.456789Z". Returns
    // "unknown" when not valid.
    std::string to_iso8601() const;
};

// Broken-down civil time in UTC. Exposed so callers can do calendar reasoning
// without pulling in <ctime>, whose gmtime is not reentrant on all platforms.
struct CivilTime {
    i32 year = 1970;
    u8 month = 1;   // 1-12
    u8 day = 1;     // 1-31
    u8 hour = 0;
    u8 minute = 0;
    u8 second = 0;
    u32 micro = 0;
};

// Converts epoch micros to civil UTC and back. The conversions are pure
// arithmetic (no libc), valid across the full proleptic Gregorian range used by
// realistic logs.
CivilTime civil_from_micros(i64 micros);
i64 micros_from_civil(const CivilTime& t);

// Number of days in a given month/year accounting for leap years.
int days_in_month(i32 year, u8 month) noexcept;
bool is_leap_year(i32 year) noexcept;

// Format dispatchers. Each returns an invalid Timestamp on failure so callers
// can try several formats in turn.

// ISO-8601 / RFC3339, e.g. "2024-03-09T11:22:33.456Z" or with "+02:00" offset.
Timestamp parse_iso8601(const std::string& s);

// RFC3164 BSD syslog time "Mmm dd hh:mm:ss" with no year; the year is supplied
// (typically the capture year) because the format omits it.
Timestamp parse_syslog_bsd_time(const std::string& s, i32 assume_year);

// Apache/CLF time "[10/Oct/2000:13:55:36 -0700]" (brackets optional).
Timestamp parse_clf_time(const std::string& s);

// Windows FILETIME: 100-nanosecond intervals since 1601-01-01.
Timestamp parse_filetime(u64 filetime);

// A best-effort dispatcher that tries the known formats and returns the first
// that parses. `assume_year` is used only by the year-less BSD format.
Timestamp parse_any_time(const std::string& s, i32 assume_year);

}  // namespace core
}  // namespace csift

#endif  // CSIFT_CORE_TIME_UTIL_HPP
