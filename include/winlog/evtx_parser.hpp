#ifndef CSIFT_WINLOG_EVTX_PARSER_HPP
#define CSIFT_WINLOG_EVTX_PARSER_HPP

#include <string>
#include <vector>

#include "core/byte_span.hpp"
#include "core/diagnostics.hpp"
#include "core/status.hpp"
#include "core/types.hpp"
#include "event/event.hpp"
#include "event/stream.hpp"
#include "winlog/binxml.hpp"
#include "winlog/evtx_header.hpp"

namespace csift {
namespace winlog {

// One event record's framing plus its decoded XML fields.
struct EvtxRecord {
    core::u64 record_id = 0;
    core::u64 written_filetime = 0;
    core::usize file_offset = 0;   // offset of the record within the file
    RenderedXml xml;
};

struct ParseOptions {
    core::usize max_chunks = 4096;
    core::usize max_records = 1u << 20;
    BinXmlLimits binxml;
};

// Iterates the records inside a single chunk (given as a chunk-origin span),
// decoding each record's BinXML. Appends decoded records to `out`. Stops at the
// chunk's free-space boundary or on the first framing error.
core::Status parse_chunk_records(core::ByteSpan chunk, std::vector<EvtxRecord>& out,
                                 core::DiagnosticSink& diags,
                                 const ParseOptions& opts);

// Maps a decoded record onto the unified event model, pulling EventID, Level,
// Provider, Channel, TimeCreated and EventData/UserData leaf fields out of the
// rendered XML.
event::LogEvent to_event(const EvtxRecord& rec);

// Parses a whole EVTX file: file header, then each chunk and its records.
event::EventStream parse_stream(core::ByteSpan bytes, core::DiagnosticSink& diags,
                                const ParseOptions& opts = ParseOptions());

// Fuzz entry point: drive arbitrary bytes through the full EVTX file -> chunk
// -> record -> BinXML -> event pipeline.
void fuzz_one(core::ByteSpan bytes);

}  // namespace winlog
}  // namespace csift

#endif  // CSIFT_WINLOG_EVTX_PARSER_HPP
