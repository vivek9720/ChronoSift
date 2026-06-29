#include "core/time_util.hpp"

#include <cstdio>

#include "core/string_util.hpp"

namespace csift {
namespace core {

bool is_leap_year(i32 year) noexcept {
    return (year % 4 == 0 && year % 100 != 0) || (year % 400 == 0);
}

int days_in_month(i32 year, u8 month) noexcept {
    static const int kDays[] = {31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31};
    if (month < 1 || month > 12) return 0;
    if (month == 2 && is_leap_year(year)) return 29;
    return kDays[month - 1];
}

// Days from 1970-01-01 to the start of `year` (can be negative for < 1970).
static i64 days_before_year(i32 year) {
    i64 y = year - 1;
    i64 leaps = y / 4 - y / 100 + y / 400;
    i64 base_y = 1969;
    i64 base_leaps = base_y / 4 - base_y / 100 + base_y / 400;
    return (static_cast<i64>(year) - 1970) * 365 + (leaps - base_leaps);
}

static i64 days_before_month(i32 year, u8 month) {
    i64 days = 0;
    for (u8 m = 1; m < month; ++m) days += days_in_month(year, m);
    return days;
}

i64 micros_from_civil(const CivilTime& t) {
    i64 days = days_before_year(t.year) + days_before_month(t.year, t.month) +
               (static_cast<i64>(t.day) - 1);
    i64 secs = days * 86400 + static_cast<i64>(t.hour) * 3600 +
               static_cast<i64>(t.minute) * 60 + static_cast<i64>(t.second);
    return secs * 1000000 + static_cast<i64>(t.micro);
}

CivilTime civil_from_micros(i64 micros) {
    CivilTime t;
    i64 secs = micros / 1000000;
    i64 rem_us = micros % 1000000;
    if (rem_us < 0) {
        rem_us += 1000000;
        secs -= 1;
    }
    t.micro = static_cast<u32>(rem_us);

    i64 days = secs / 86400;
    i64 secs_of_day = secs % 86400;
    if (secs_of_day < 0) {
        secs_of_day += 86400;
        days -= 1;
    }
    t.hour = static_cast<u8>(secs_of_day / 3600);
    t.minute = static_cast<u8>((secs_of_day % 3600) / 60);
    t.second = static_cast<u8>(secs_of_day % 60);

    // Walk from the epoch to the right year. Bounded by the magnitude of `days`.
    i32 year = 1970;
    while (true) {
        i64 year_days = is_leap_year(year) ? 366 : 365;
        if (days >= year_days) {
            days -= year_days;
            ++year;
        } else if (days < 0) {
            --year;
            days += is_leap_year(year) ? 366 : 365;
        } else {
            break;
        }
    }
    t.year = year;
    u8 month = 1;
    while (month <= 12) {
        int dim = days_in_month(year, month);
        if (days < dim) break;
        days -= dim;
        ++month;
    }
    t.month = month > 12 ? 12 : month;
    t.day = static_cast<u8>(days + 1);
    return t;
}

std::string Timestamp::to_iso8601() const {
    if (!valid) return "unknown";
    CivilTime t = civil_from_micros(micros);
    char buf[40];
    // Manual formatting keeps this free of locale/<ctime> dependencies.
    std::snprintf(buf, sizeof(buf),
                  "%04d-%02u-%02uT%02u:%02u:%02u.%06uZ", t.year,
                  static_cast<unsigned>(t.month), static_cast<unsigned>(t.day),
                  static_cast<unsigned>(t.hour), static_cast<unsigned>(t.minute),
                  static_cast<unsigned>(t.second), t.micro);
    return std::string(buf);
}

static int month_from_abbrev(const std::string& s) {
    static const char* kMon[] = {"Jan", "Feb", "Mar", "Apr", "May", "Jun",
                                 "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"};
    for (int i = 0; i < 12; ++i) {
        if (ascii_iequals(s, kMon[i])) return i + 1;
    }
    return 0;
}

// Reads exactly `n` digits starting at `pos`; on success advances `pos` and
// returns true. Used by the strict timestamp parsers.
static bool read_digits(const std::string& s, usize& pos, int n, i64& out) {
    if (pos + static_cast<usize>(n) > s.size()) return false;
    i64 value = 0;
    for (int i = 0; i < n; ++i) {
        char c = s[pos + i];
        if (!is_digit(c)) return false;
        value = value * 10 + (c - '0');
    }
    pos += n;
    out = value;
    return true;
}

Timestamp parse_iso8601(const std::string& raw) {
    std::string s = trim(raw);
    if (s.size() < 10) return Timestamp::invalid();
    usize pos = 0;
    i64 year, month, day;
    if (!read_digits(s, pos, 4, year)) return Timestamp::invalid();
    if (pos >= s.size() || s[pos] != '-') return Timestamp::invalid();
    ++pos;
    if (!read_digits(s, pos, 2, month)) return Timestamp::invalid();
    if (pos >= s.size() || s[pos] != '-') return Timestamp::invalid();
    ++pos;
    if (!read_digits(s, pos, 2, day)) return Timestamp::invalid();
    if (month < 1 || month > 12 || day < 1 || day > 31) return Timestamp::invalid();

    CivilTime t;
    t.year = static_cast<i32>(year);
    t.month = static_cast<u8>(month);
    t.day = static_cast<u8>(day);

    if (pos < s.size() && (s[pos] == 'T' || s[pos] == ' ' || s[pos] == 't')) {
        ++pos;
        i64 hh, mm, ss;
        if (!read_digits(s, pos, 2, hh)) return Timestamp::invalid();
        if (pos >= s.size() || s[pos] != ':') return Timestamp::invalid();
        ++pos;
        if (!read_digits(s, pos, 2, mm)) return Timestamp::invalid();
        if (pos >= s.size() || s[pos] != ':') return Timestamp::invalid();
        ++pos;
        if (!read_digits(s, pos, 2, ss)) return Timestamp::invalid();
        if (hh > 23 || mm > 59 || ss > 60) return Timestamp::invalid();
        t.hour = static_cast<u8>(hh);
        t.minute = static_cast<u8>(mm);
        t.second = static_cast<u8>(ss == 60 ? 59 : ss);

        u32 frac_us = 0;
        if (pos < s.size() && s[pos] == '.') {
            ++pos;
            int digits = 0;
            i64 frac = 0;
            while (pos < s.size() && is_digit(s[pos]) && digits < 6) {
                frac = frac * 10 + (s[pos] - '0');
                ++digits;
                ++pos;
            }
            while (pos < s.size() && is_digit(s[pos])) ++pos;  // drop extra precision
            for (int i = digits; i < 6; ++i) frac *= 10;
            frac_us = static_cast<u32>(frac);
        }
        t.micro = frac_us;

        i64 base = micros_from_civil(t);
        // Timezone offset.
        if (pos < s.size()) {
            char z = s[pos];
            if (z == 'Z' || z == 'z') {
                ++pos;
            } else if (z == '+' || z == '-') {
                ++pos;
                i64 oh, om;
                if (!read_digits(s, pos, 2, oh)) return Timestamp::invalid();
                if (pos < s.size() && s[pos] == ':') ++pos;
                if (!read_digits(s, pos, 2, om)) return Timestamp::invalid();
                i64 offset = (oh * 3600 + om * 60) * 1000000;
                base += (z == '+') ? -offset : offset;  // convert to UTC
            }
        }
        return Timestamp::from_micros(base);
    }
    return Timestamp::from_micros(micros_from_civil(t));
}

Timestamp parse_syslog_bsd_time(const std::string& raw, i32 assume_year) {
    // "Mmm dd hh:mm:ss" — day may be space-padded.
    std::vector<std::string> parts = split_whitespace(raw);
    if (parts.size() < 3) return Timestamp::invalid();
    int month = month_from_abbrev(parts[0]);
    if (month == 0) return Timestamp::invalid();
    u64 day = 0;
    if (!parse_u64(parts[1], day) || day < 1 || day > 31) return Timestamp::invalid();
    std::vector<std::string> hms = split(parts[2], ':');
    if (hms.size() != 3) return Timestamp::invalid();
    u64 hh = 0, mm = 0, ss = 0;
    if (!parse_u64(hms[0], hh) || !parse_u64(hms[1], mm) || !parse_u64(hms[2], ss))
        return Timestamp::invalid();
    if (hh > 23 || mm > 59 || ss > 60) return Timestamp::invalid();
    CivilTime t;
    t.year = assume_year;
    t.month = static_cast<u8>(month);
    t.day = static_cast<u8>(day);
    t.hour = static_cast<u8>(hh);
    t.minute = static_cast<u8>(mm);
    t.second = static_cast<u8>(ss == 60 ? 59 : ss);
    return Timestamp::from_micros(micros_from_civil(t));
}

Timestamp parse_clf_time(const std::string& raw) {
    // "[10/Oct/2000:13:55:36 -0700]" or without brackets.
    std::string s = trim(raw);
    if (!s.empty() && s.front() == '[') s = s.substr(1);
    if (!s.empty() && s.back() == ']') s.pop_back();
    // Split date part and offset.
    std::vector<std::string> sp = split_whitespace(s);
    if (sp.empty()) return Timestamp::invalid();
    std::vector<std::string> dt = split(sp[0], ':');
    if (dt.size() != 4) return Timestamp::invalid();
    std::vector<std::string> dmy = split(dt[0], '/');
    if (dmy.size() != 3) return Timestamp::invalid();
    u64 day = 0, year = 0, hh = 0, mm = 0, ss = 0;
    if (!parse_u64(dmy[0], day)) return Timestamp::invalid();
    int month = month_from_abbrev(dmy[1]);
    if (month == 0) return Timestamp::invalid();
    if (!parse_u64(dmy[2], year)) return Timestamp::invalid();
    if (!parse_u64(dt[1], hh) || !parse_u64(dt[2], mm) || !parse_u64(dt[3], ss))
        return Timestamp::invalid();
    if (day < 1 || day > 31 || hh > 23 || mm > 59 || ss > 60)
        return Timestamp::invalid();
    CivilTime t;
    t.year = static_cast<i32>(year);
    t.month = static_cast<u8>(month);
    t.day = static_cast<u8>(day);
    t.hour = static_cast<u8>(hh);
    t.minute = static_cast<u8>(mm);
    t.second = static_cast<u8>(ss == 60 ? 59 : ss);
    i64 base = micros_from_civil(t);
    if (sp.size() >= 2 && sp[1].size() == 5 && (sp[1][0] == '+' || sp[1][0] == '-')) {
        const std::string& off = sp[1];
        if (is_digit(off[1]) && is_digit(off[2]) && is_digit(off[3]) && is_digit(off[4])) {
            i64 oh = (off[1] - '0') * 10 + (off[2] - '0');
            i64 om = (off[3] - '0') * 10 + (off[4] - '0');
            i64 offset = (oh * 3600 + om * 60) * 1000000;
            base += (off[0] == '+') ? -offset : offset;
        }
    }
    return Timestamp::from_micros(base);
}

Timestamp parse_filetime(u64 filetime) {
    // FILETIME counts 100ns ticks since 1601-01-01. Convert to Unix micros.
    // Ticks between 1601 and 1970 = 11644473600 seconds.
    const u64 kTicksPerMicro = 10;
    const i64 kEpochDiffSeconds = 11644473600LL;
    i64 micros = static_cast<i64>(filetime / kTicksPerMicro);
    micros -= kEpochDiffSeconds * 1000000;
    return Timestamp::from_micros(micros);
}

Timestamp parse_any_time(const std::string& s, i32 assume_year) {
    Timestamp t = parse_iso8601(s);
    if (t.valid) return t;
    t = parse_clf_time(s);
    if (t.valid) return t;
    t = parse_syslog_bsd_time(s, assume_year);
    if (t.valid) return t;
    // Bare epoch seconds?
    u64 secs = 0;
    std::string trimmed = trim(s);
    if (parse_u64(trimmed, secs) && trimmed.size() >= 9 && trimmed.size() <= 11) {
        return Timestamp::from_unix_seconds(static_cast<i64>(secs));
    }
    return Timestamp::invalid();
}

}  // namespace core
}  // namespace csift
