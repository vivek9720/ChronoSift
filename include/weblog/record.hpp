#ifndef CSIFT_WEBLOG_RECORD_HPP
#define CSIFT_WEBLOG_RECORD_HPP

#include <string>

#include "core/time_util.hpp"
#include "core/types.hpp"

namespace csift {
namespace weblog {

// The HTTP request-line broken into its three parts, e.g.
// "GET /index.html?q=1 HTTP/1.1".
struct RequestLine {
    std::string method;
    std::string target;    // path + query, percent-encoded as-logged
    std::string version;   // "HTTP/1.1"
    bool valid = false;
};

// Which access-log layout a line matched.
enum class WebLogFormat {
    Unknown = 0,
    Common,    // NCSA Common Log Format
    Combined,  // Common + referer + user-agent
};

// A decoded web-server access log entry. Missing optional fields stay empty;
// a "-" placeholder in the log is normalised to an empty field.
struct AccessRecord {
    WebLogFormat format = WebLogFormat::Unknown;

    std::string client_ip;
    std::string ident;      // RFC1413 identity (rarely present)
    std::string user;       // authenticated user
    core::Timestamp time;

    RequestLine request;
    core::u32 status = 0;
    core::u64 bytes = 0;    // response size; "-" means 0/unknown
    bool bytes_known = false;

    std::string referer;    // Combined only
    std::string user_agent; // Combined only

    // The decoded path component of the request target (query stripped,
    // percent-decoding applied), useful for matching/grouping.
    std::string decoded_path() const;
};

}  // namespace weblog
}  // namespace csift

#endif  // CSIFT_WEBLOG_RECORD_HPP
