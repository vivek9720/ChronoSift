#ifndef CSIFT_PIPELINE_INGEST_HPP
#define CSIFT_PIPELINE_INGEST_HPP

#include <string>

#include "core/byte_span.hpp"
#include "core/diagnostics.hpp"
#include "event/event.hpp"
#include "event/stream.hpp"

namespace csift {
namespace pipeline {

// The artifact format ingest detected (or was told to use).
enum class Format {
    Auto = 0,
    Syslog,
    Json,
    WebAccess,
    WinEvtx,
    Cef,
};

const char* format_name(Format f) noexcept;

// Parses a format name as accepted on the command line ("syslog", "json",
// "web", "evtx", "auto"). Returns false on an unknown name.
bool parse_format_name(const std::string& name, Format& out);

// Sniffs the leading bytes to guess the format: the EVTX magic, a leading '{'
// for JSON lines, a leading '<' PRI for syslog, or the CLF shape otherwise.
Format detect_format(core::ByteSpan bytes);

// Options threaded through to the underlying parsers.
struct IngestOptions {
    Format format = Format::Auto;
    core::i32 assume_year = 1970;
};

// Parses `bytes` with the selected (or detected) parser and returns the unified
// event stream. Diagnostics from the underlying parser are collected in `diags`.
event::EventStream ingest(core::ByteSpan bytes, core::DiagnosticSink& diags,
                          const IngestOptions& opts = IngestOptions());

}  // namespace pipeline
}  // namespace csift

#endif  // CSIFT_PIPELINE_INGEST_HPP
