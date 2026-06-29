#include "cef/cef_record.hpp"

#include "core/string_util.hpp"

// CefRecord accessors and the CEF severity normalisation.
//
// CEF (ArcSight Common Event Format) carries a severity that is either a
// numeric value in the range 0-10 or one of a small set of severity words
// ("Low", "Medium", "High", "Very-High"/"Critical"). The event model speaks a
// 0-7 syslog-style scale (0 = most severe). normalized_severity() projects the
// CEF severity onto that scale, returning 8 (the "unknown" sentinel the event
// layer recognises) when the field is missing or unparseable.
//
// Like the rest of the CEF module this code is exercised under ASan/UBSan, so
// every access is bounds-conscious and tolerant of empty / binary input.

namespace csift {
namespace cef {

// Linear scan over the parsed extensions. CEF records carry only a handful of
// extension pairs in practice, so a vector scan is cheaper than a map and keeps
// insertion order available to callers. Returns the first match (CEF does not
// define duplicate-key semantics; first-wins is the conventional choice).
std::string CefRecord::ext(const std::string& key) const {
    for (const CefExtension& e : extensions) {
        if (e.key == key) return e.value;
    }
    return std::string();
}

bool CefRecord::has_ext(const std::string& key) const {
    for (const CefExtension& e : extensions) {
        if (e.key == key) return true;
    }
    return false;
}

core::u32 CefRecord::normalized_severity() const {
    // An absent severity is "unknown".
    std::string s = core::trim(severity);
    if (s.empty()) return 8;

    // Numeric severity (0-10). We accept a pure run of decimal digits; anything
    // else (including a negative sign or trailing junk) falls through to the
    // word mapping below. parse_u64 already guards against overflow.
    bool all_digits = true;
    for (char c : s) {
        if (!core::is_digit(c)) {
            all_digits = false;
            break;
        }
    }
    if (all_digits) {
        core::u64 n = 0;
        if (core::parse_u64(s, n)) {
            // Map the 0-10 CEF band onto the syslog-style scale. Values above
            // 10 are out of spec; clamp them into the most-severe band rather
            // than rejecting, since an appliance emitting e.g. "11" still means
            // "very bad".
            if (n <= 3) return 6;   // 0-3  -> Informational
            if (n <= 6) return 4;   // 4-6  -> Warning
            if (n <= 8) return 3;   // 7-8  -> Error
            return 2;               // 9-10 (and above) -> Critical
        }
        // parse_u64 only fails here on overflow of a huge digit string; treat
        // such an absurd value as the most severe band rather than unknown.
        return 2;
    }

    // Word severity. CEF severities are case-insensitive in practice; fold to
    // lower case for comparison.
    std::string w = core::to_lower(s);
    if (w == "low") return 6;
    if (w == "medium") return 4;
    if (w == "high") return 3;
    if (w == "very-high" || w == "critical") return 2;

    // Unrecognised word.
    return 8;
}

}  // namespace cef
}  // namespace csift
