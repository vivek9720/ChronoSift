#include "syslog/message.hpp"

#include "event/severity.hpp"

namespace csift {
namespace syslog {

// The canonical syslog facility keywords as defined by RFC5424 §6.2.1 and the
// long-standing BSD assignments. Index == facility number; entries 0-23 are the
// only ones defined. Anything outside that range is "unknown" so an adversarial
// PRI value can never index past the table.
namespace {

const char* const kFacilityNames[] = {
    "kern",      //  0  kernel messages
    "user",      //  1  user-level messages
    "mail",      //  2  mail system
    "daemon",    //  3  system daemons
    "auth",      //  4  security/authorization messages
    "syslog",    //  5  messages generated internally by syslogd
    "lpr",       //  6  line printer subsystem
    "news",      //  7  network news subsystem
    "uucp",      //  8  UUCP subsystem
    "cron",      //  9  clock daemon
    "authpriv",  // 10  security/authorization messages (private)
    "ftp",       // 11  FTP daemon
    "ntp",       // 12  NTP subsystem
    "audit",     // 13  log audit
    "alert",     // 14  log alert
    "clock",     // 15  clock daemon (note 2)
    "local0",    // 16  local use 0
    "local1",    // 17  local use 1
    "local2",    // 18  local use 2
    "local3",    // 19  local use 3
    "local4",    // 20  local use 4
    "local5",    // 21  local use 5
    "local6",    // 22  local use 6
    "local7",    // 23  local use 7
};

// Number of defined facility keywords above.
constexpr core::u32 kFacilityCount =
    static_cast<core::u32>(sizeof(kFacilityNames) / sizeof(kFacilityNames[0]));

}  // namespace

const char* syslog_facility_name(core::u32 facility) noexcept {
    if (facility < kFacilityCount) return kFacilityNames[facility];
    return "unknown";
}

std::string SyslogMessage::facility_name() const {
    return std::string(syslog_facility_name(facility));
}

std::string SyslogMessage::severity_name() const {
    // Reuse the shared event severity scale, whose numeric values mirror the
    // syslog 0-7 ordering exactly. severity_from_syslog clamps out-of-range
    // values to Unknown, so a corrupt severity number stays safe.
    return std::string(
        event::severity_name(event::severity_from_syslog(severity)));
}

}  // namespace syslog
}  // namespace csift
