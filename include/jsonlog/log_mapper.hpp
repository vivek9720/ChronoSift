#ifndef CSIFT_JSONLOG_LOG_MAPPER_HPP
#define CSIFT_JSONLOG_LOG_MAPPER_HPP

#include "core/byte_span.hpp"
#include "core/diagnostics.hpp"
#include "event/event.hpp"
#include "event/stream.hpp"
#include "jsonlog/json_parser.hpp"
#include "jsonlog/json_value.hpp"

namespace csift {
namespace jsonlog {

// Maps a parsed JSON object onto the unified event model. It probes a list of
// well-known field aliases for each canonical field (e.g. timestamp may be
// "timestamp", "time", "@timestamp", "ts", "eventTime"), flattening nested
// objects into dotted keys in the event's field map. Non-object top-level
// values (arrays, scalars) produce an event carrying the rendered value as the
// message.
event::LogEvent map_to_event(const JsonValue& value, core::i32 assume_year);

// Parses a JSON-lines artifact (one JSON document per line) into an event
// stream. Blank lines are skipped; a line that fails to parse becomes a
// diagnostic plus a raw fallback event so no data is silently dropped.
event::EventStream parse_stream(core::ByteSpan bytes, core::DiagnosticSink& diags,
                                const JsonLimits& limits = JsonLimits(),
                                core::i32 assume_year = 1970);

// Fuzz entry point: parse arbitrary bytes as JSON lines, run the limit-checked
// parser, and map each document to an event.
void fuzz_one(core::ByteSpan bytes);

}  // namespace jsonlog
}  // namespace csift

#endif  // CSIFT_JSONLOG_LOG_MAPPER_HPP
