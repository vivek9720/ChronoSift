#ifndef CSIFT_WEBLOG_PARSER_HPP
#define CSIFT_WEBLOG_PARSER_HPP

#include <string>

#include "core/byte_span.hpp"
#include "core/diagnostics.hpp"
#include "core/status.hpp"
#include "event/event.hpp"
#include "event/stream.hpp"
#include "weblog/record.hpp"

namespace csift {
namespace weblog {

struct ParseOptions {
    core::usize max_field_bytes = 1u << 16;  // bound any single quoted field
    core::usize max_line_bytes = 1u << 20;
};

// Splits a CLF/Combined line into its top-level fields, honouring the three
// quoting styles the format uses: bare tokens, "double-quoted" strings, and
// [bracketed] timestamps. Returns the field list. Exposed for testing the
// tokenizer independently of field interpretation.
std::vector<std::string> tokenize_fields(const std::string& line,
                                          const ParseOptions& opts);

// Parses an HTTP request line ("METHOD TARGET VERSION").
RequestLine parse_request_line(const std::string& text);

// Parses one access-log line into an AccessRecord, auto-detecting Common vs
// Combined by field count.
core::Result<AccessRecord> parse_line(const std::string& line,
                                      const ParseOptions& opts);

event::LogEvent to_event(const AccessRecord& rec);

// Parses a whole access-log file into an event stream.
event::EventStream parse_stream(core::ByteSpan bytes, core::DiagnosticSink& diags,
                                const ParseOptions& opts = ParseOptions());

// Fuzz entry point exercising tokenization + request-line + timestamp + field
// interpretation + event conversion.
void fuzz_one(core::ByteSpan bytes);

}  // namespace weblog
}  // namespace csift

#endif  // CSIFT_WEBLOG_PARSER_HPP
