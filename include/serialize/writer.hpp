#ifndef CSIFT_SERIALIZE_WRITER_HPP
#define CSIFT_SERIALIZE_WRITER_HPP

#include <string>
#include <vector>

#include "core/types.hpp"
#include "event/event.hpp"
#include "event/stream.hpp"

// Serializers that turn the normalized event stream back into portable text so
// triage results can be handed to other tools: newline-delimited JSON for
// piping into jq or a SIEM, and CSV for spreadsheets and quick review.
namespace csift {
namespace serialize {

// Escapes a string as a JSON string body (without surrounding quotes), emitting
// \uXXXX for control characters and \" \\ for the specials.
std::string json_escape(const std::string& s);

// Quotes a CSV field per RFC 4180: wraps in double quotes and doubles any
// embedded quote when the field contains a comma, quote, or newline.
std::string csv_quote(const std::string& s);

// Renders a single event as a one-line JSON object (canonical key order).
std::string event_to_json(const event::LogEvent& e);

// Renders the whole stream as newline-delimited JSON (one object per line).
std::string to_ndjson(const event::EventStream& stream);

// Renders the stream as CSV with a fixed header row of the common columns.
// Extended fields are not expanded into columns (they vary per record); the
// canonical columns give a stable, diffable table.
std::string to_csv(const event::EventStream& stream);

// The CSV header row used by to_csv, exposed for tests.
std::string csv_header();

}  // namespace serialize
}  // namespace csift

#endif  // CSIFT_SERIALIZE_WRITER_HPP
