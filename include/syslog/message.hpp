#ifndef CSIFT_SYSLOG_MESSAGE_HPP
#define CSIFT_SYSLOG_MESSAGE_HPP

#include <string>
#include <vector>

#include "core/time_util.hpp"
#include "core/types.hpp"

namespace csift {
namespace syslog {

// One element of RFC5424 structured data: an SD-ID plus its name="value" pairs,
// e.g. [exampleSDID@32473 iut="3" eventSource="App"].
struct SdParam {
    std::string name;
    std::string value;
};

struct SdElement {
    std::string id;
    std::vector<SdParam> params;
};

// Which syslog dialect a line was recognised as.
enum class SyslogFlavor {
    Unknown = 0,
    Rfc3164,  // classic BSD: "<PRI>Mmm dd hh:mm:ss host tag[pid]: msg"
    Rfc5424,  // modern IETF: "<PRI>VER TIMESTAMP HOST APP PROCID MSGID SD MSG"
};

// A decoded syslog line. The PRI is split into facility/severity; fields absent
// in a given flavor stay empty / default.
struct SyslogMessage {
    SyslogFlavor flavor = SyslogFlavor::Unknown;

    bool has_pri = false;
    core::u32 priority = 0;   // raw PRI value (facility*8 + severity)
    core::u32 facility = 0;   // 0-23
    core::u32 severity = 0;   // 0-7

    core::u32 version = 0;            // RFC5424 version (1)
    core::Timestamp timestamp;

    std::string hostname;
    std::string app_name;     // tag (3164) / APP-NAME (5424)
    std::string proc_id;      // pid (3164) / PROCID (5424)
    std::string msg_id;       // RFC5424 only
    std::vector<SdElement> structured_data;
    std::string message;      // free-text MSG

    // Facility/severity names for display.
    std::string facility_name() const;
    std::string severity_name() const;
};

// The standard syslog facility keywords (index == facility number).
const char* syslog_facility_name(core::u32 facility) noexcept;

}  // namespace syslog
}  // namespace csift

#endif  // CSIFT_SYSLOG_MESSAGE_HPP
