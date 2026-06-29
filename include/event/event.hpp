#ifndef CSIFT_EVENT_EVENT_HPP
#define CSIFT_EVENT_EVENT_HPP

#include <string>

#include "core/time_util.hpp"
#include "core/types.hpp"
#include "event/field.hpp"
#include "event/severity.hpp"

namespace csift {
namespace event {

// Which parser produced an event. Kept on the event so cross-source analysis
// can weight or filter by origin.
enum class SourceFormat {
    Unknown = 0,
    Syslog,
    Json,
    WebAccess,
    WinEvent,
};

const char* source_format_name(SourceFormat f) noexcept;

// The canonical, source-agnostic representation of one log record. Every parser
// fills in as much of this as its format provides; absent fields keep their
// defaults. Analysis code reads only this structure, never the raw formats.
struct LogEvent {
    core::Timestamp timestamp;
    Severity severity = Severity::Unknown;
    SourceFormat source = SourceFormat::Unknown;

    // Origin identity.
    std::string host;        // hostname / source machine
    std::string app;         // program / service / facility name
    core::i64 pid = -1;      // process id, -1 when unknown

    // Human-readable message / summary.
    std::string message;

    // Actor / subject commonly used by correlation.
    std::string user;        // account or username, when present

    // Network 5-tuple-ish fields (string IPs to stay format-neutral).
    std::string src_ip;
    std::string dst_ip;
    core::u32 src_port = 0;
    core::u32 dst_port = 0;

    // Web/HTTP specifics.
    std::string http_method;
    std::string http_path;
    core::u32 http_status = 0;
    core::u64 bytes = 0;

    // Windows event specifics.
    core::u32 event_id = 0;
    std::string channel;     // e.g. "Security", "System"
    std::string provider;    // event provider/source name

    // The position of this record in its source stream (1-based), for locating
    // it again in the original artifact.
    core::usize record_index = 0;

    // All other extracted fields the structured formats carried.
    FieldMap fields;

    // True when a parseable timestamp was recovered.
    bool has_time() const noexcept { return timestamp.valid; }

    // A stable one-line summary for timelines and tool output.
    std::string summary() const;

    // A composite key used to group "the same kind of event" for frequency
    // analysis: source + app/provider + event_id (or a hash of the message
    // shape). Two events with the same signature are treated as the same type.
    std::string signature() const;
};

}  // namespace event
}  // namespace csift

#endif  // CSIFT_EVENT_EVENT_HPP
