#ifndef CSIFT_CEF_CEF_RECORD_HPP
#define CSIFT_CEF_CEF_RECORD_HPP

#include <string>
#include <vector>

#include "core/types.hpp"

namespace csift {
namespace cef {

// One extension key/value pair from a CEF message (e.g. src=10.0.0.1).
struct CefExtension {
    std::string key;
    std::string value;
};

// A decoded ArcSight Common Event Format record. The prefix is seven
// pipe-delimited header fields; the extension is a space-separated set of
// key=value pairs that follows. CEF is widely used by firewalls, IDS/IPS and
// other security appliances to ship events into a SIEM, so it is a natural
// artifact for offline triage.
struct CefRecord {
    bool valid = false;
    core::u32 version = 0;
    std::string device_vendor;
    std::string device_product;
    std::string device_version;
    std::string signature_id;
    std::string name;
    std::string severity;  // CEF severity is 0-10 or a word (Low/High/...)
    std::vector<CefExtension> extensions;

    // Returns the value of an extension by key, or empty when absent.
    std::string ext(const std::string& key) const;
    bool has_ext(const std::string& key) const;

    // Maps the CEF severity (numeric 0-10 or a word) onto a 0-7 syslog-style
    // scale value for the event model. Returns 8 (unknown) when unparseable.
    core::u32 normalized_severity() const;
};

}  // namespace cef
}  // namespace csift

#endif  // CSIFT_CEF_CEF_RECORD_HPP
