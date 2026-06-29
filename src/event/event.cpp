#include "event/event.hpp"

#include "core/string_util.hpp"

namespace csift {
namespace event {

const char* source_format_name(SourceFormat f) noexcept {
    switch (f) {
        case SourceFormat::Unknown: return "unknown";
        case SourceFormat::Syslog: return "syslog";
        case SourceFormat::Json: return "json";
        case SourceFormat::WebAccess: return "web-access";
        case SourceFormat::WinEvent: return "win-event";
    }
    return "unknown";
}

std::string LogEvent::summary() const {
    std::string out;
    out += timestamp.to_iso8601();
    out += "  ";
    out += severity_name(severity);
    out += "  ";
    out += source_format_name(source);
    if (!host.empty()) {
        out += "  host=";
        out += host;
    }
    if (!app.empty()) {
        out += "  app=";
        out += app;
    }
    if (event_id != 0) {
        out += "  id=";
        out += std::to_string(event_id);
    }
    if (!src_ip.empty()) {
        out += "  src=";
        out += src_ip;
    }
    if (http_status != 0) {
        out += "  ";
        out += http_method;
        out += " ";
        out += core::truncate(http_path, 80);
        out += " ";
        out += std::to_string(http_status);
    }
    if (!message.empty()) {
        out += "  ";
        out += core::truncate(core::sanitize_printable(message), 160);
    }
    return out;
}

// Collapses a message down to its structural shape by replacing digit runs with
// '#' and long hex/token runs with '*'. Events that differ only in identifiers
// then share a signature, which is what frequency analysis wants.
static std::string message_shape(const std::string& msg) {
    std::string out;
    out.reserve(msg.size());
    core::usize i = 0;
    const core::usize n = msg.size();
    while (i < n) {
        char c = msg[i];
        if (core::is_digit(c)) {
            while (i < n && core::is_digit(msg[i])) ++i;
            out.push_back('#');
        } else {
            out.push_back(c);
            ++i;
        }
        if (out.size() >= 120) break;  // bound signature length
    }
    return out;
}

std::string LogEvent::signature() const {
    std::string sig = source_format_name(source);
    sig += '|';
    if (!provider.empty()) {
        sig += provider;
    } else if (!app.empty()) {
        sig += app;
    }
    sig += '|';
    if (event_id != 0) {
        sig += std::to_string(event_id);
    } else if (http_status != 0) {
        sig += http_method;
        sig += ' ';
        sig += std::to_string(http_status);
    } else {
        sig += message_shape(message);
    }
    return sig;
}

}  // namespace event
}  // namespace csift
