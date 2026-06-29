#include "event/severity.hpp"

#include "core/string_util.hpp"

namespace csift {
namespace event {

const char* severity_name(Severity s) noexcept {
    switch (s) {
        case Severity::Emergency: return "emergency";
        case Severity::Alert: return "alert";
        case Severity::Critical: return "critical";
        case Severity::Error: return "error";
        case Severity::Warning: return "warning";
        case Severity::Notice: return "notice";
        case Severity::Informational: return "informational";
        case Severity::Debug: return "debug";
        case Severity::Unknown: return "unknown";
    }
    return "unknown";
}

Severity severity_from_syslog(core::u32 value) noexcept {
    if (value > 7) return Severity::Unknown;
    return static_cast<Severity>(value);
}

Severity severity_from_word(const std::string& word) {
    std::string w = core::to_lower(core::trim(word));
    if (w == "emerg" || w == "emergency" || w == "panic") return Severity::Emergency;
    if (w == "alert") return Severity::Alert;
    if (w == "crit" || w == "critical") return Severity::Critical;
    if (w == "err" || w == "error") return Severity::Error;
    if (w == "warn" || w == "warning") return Severity::Warning;
    if (w == "notice") return Severity::Notice;
    if (w == "info" || w == "information" || w == "informational")
        return Severity::Informational;
    if (w == "debug" || w == "trace" || w == "verbose") return Severity::Debug;
    return Severity::Unknown;
}

Severity severity_from_winlevel(core::u32 level) noexcept {
    // Windows event Level: 1=Critical, 2=Error, 3=Warning, 4=Information,
    // 5=Verbose. 0 means "always log" / undefined.
    switch (level) {
        case 1: return Severity::Critical;
        case 2: return Severity::Error;
        case 3: return Severity::Warning;
        case 4: return Severity::Informational;
        case 5: return Severity::Debug;
        default: return Severity::Unknown;
    }
}

bool at_least_as_severe(Severity a, Severity b) noexcept {
    if (a == Severity::Unknown) return false;
    if (b == Severity::Unknown) return true;
    return static_cast<int>(a) <= static_cast<int>(b);
}

}  // namespace event
}  // namespace csift
