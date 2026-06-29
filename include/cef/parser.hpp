#ifndef CSIFT_CEF_PARSER_HPP
#define CSIFT_CEF_PARSER_HPP

#include <string>
#include <vector>

#include "cef/cef_record.hpp"
#include "core/byte_span.hpp"
#include "core/diagnostics.hpp"
#include "core/status.hpp"
#include "event/event.hpp"
#include "event/stream.hpp"

namespace csift {
namespace cef {

struct ParseOptions {
    core::i32 assume_year = 1970;
    core::usize max_extensions = 1024;
    core::usize max_field_bytes = 1u << 16;
};

// Splits the seven pipe-delimited CEF header fields, honouring the `\|` and
// `\\` escapes the format defines. A leading "CEF:" marker (optionally preceded
// by a syslog prefix that the caller has already stripped) is required.
core::Result<std::vector<std::string>> split_header(const std::string& line,
                                                    const ParseOptions& opts);

// Parses the extension section ("key=value key2=value2 ...") starting at
// `text[pos]`, honouring `\=`, `\\` and `\n` escapes inside values and the rule
// that a value runs until the next " key=" boundary. Appends to `out`.
core::Status parse_extensions(const std::string& text, core::usize pos,
                              std::vector<CefExtension>& out,
                              const ParseOptions& opts);

// Parses one CEF line into a record.
core::Result<CefRecord> parse_line(const std::string& line, const ParseOptions& opts);

event::LogEvent to_event(const CefRecord& rec, const ParseOptions& opts);

// Parses a whole CEF artifact (one record per line) into an event stream.
event::EventStream parse_stream(core::ByteSpan bytes, core::DiagnosticSink& diags,
                                const ParseOptions& opts = ParseOptions());

// Fuzz entry point exercising header splitting, escape handling, extension
// parsing and event conversion.
void fuzz_one(core::ByteSpan bytes);

}  // namespace cef
}  // namespace csift

#endif  // CSIFT_CEF_PARSER_HPP
