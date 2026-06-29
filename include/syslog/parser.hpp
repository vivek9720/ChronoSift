#ifndef CSIFT_SYSLOG_PARSER_HPP
#define CSIFT_SYSLOG_PARSER_HPP

#include <string>

#include "core/byte_span.hpp"
#include "core/diagnostics.hpp"
#include "core/status.hpp"
#include "event/event.hpp"
#include "event/stream.hpp"
#include "syslog/message.hpp"

namespace csift {
namespace syslog {

// Tunable safety limits applied while parsing. Defaults are generous for real
// logs but bound the work an adversarial artifact can induce.
struct ParseOptions {
    core::i32 assume_year = 1970;  // year for year-less RFC3164 timestamps
    core::usize max_sd_elements = 256;
    core::usize max_sd_params = 256;
    core::usize max_message_bytes = 1u << 20;  // 1 MiB per line
};

// Parses one syslog line (no trailing newline) into a SyslogMessage. Recognises
// the leading "<PRI>" and then dispatches on whether an RFC5424 version digit
// follows. Returns Malformed/Truncated on structurally broken input.
core::Result<SyslogMessage> parse_line(const std::string& line,
                                       const ParseOptions& opts);

// Parses the RFC5424 STRUCTURED-DATA section starting at `text[pos]`. Advances
// `pos` past the section. Exposed for targeted testing of the SD grammar.
core::Status parse_structured_data(const std::string& text, core::usize& pos,
                                   std::vector<SdElement>& out,
                                   const ParseOptions& opts);

// Converts a decoded message into the unified event model.
event::LogEvent to_event(const SyslogMessage& msg);

// Parses a whole multi-line syslog artifact into an event stream. Each line is
// parsed independently; a malformed line yields a diagnostic and a best-effort
// event rather than aborting the run.
event::EventStream parse_stream(core::ByteSpan bytes, core::DiagnosticSink& diags,
                                const ParseOptions& opts = ParseOptions());

// Fuzz entry point: parse arbitrary bytes as a syslog artifact and exercise the
// full line-split + PRI + timestamp + structured-data + event-conversion path.
void fuzz_one(core::ByteSpan bytes);

}  // namespace syslog
}  // namespace csift

#endif  // CSIFT_SYSLOG_PARSER_HPP
