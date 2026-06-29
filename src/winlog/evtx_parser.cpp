#include "winlog/evtx_parser.hpp"

#include <string>
#include <vector>

#include "core/byte_reader.hpp"
#include "core/string_util.hpp"
#include "core/time_util.hpp"
#include "event/severity.hpp"

// Top-level EVTX driver: file header -> chunks -> event records -> BinXML ->
// unified events. All sizes and offsets come from untrusted input and are
// validated against the available bytes; every record/chunk loop makes strict
// forward progress so a malformed container can never spin.
namespace csift {
namespace winlog {

namespace {

constexpr core::u32 kRecordSig32 = 0x00002a2a;  // low u16 == "**"
constexpr core::usize kRecordHeaderTrailer = 24 + 4;  // 24-byte header + u32 trailer
constexpr core::usize kRecordMinSize = 24;            // header alone, no payload

// Case-insensitive "does `name` end with `leaf`?" used to pull well-known EVTX
// fields out of arbitrarily nested dotted field names.
bool ends_with_ci(const std::string& name, const std::string& leaf) {
    if (leaf.size() > name.size()) return false;
    core::usize off = name.size() - leaf.size();
    for (core::usize i = 0; i < leaf.size(); ++i) {
        if (core::ascii_to_lower(name[off + i]) != core::ascii_to_lower(leaf[i]))
            return false;
    }
    return true;
}

// Returns the value of the first field whose dotted name ends with `leaf`
// (case-insensitive), or empty when none matches.
std::string find_by_leaf(const RenderedXml& xml, const std::string& leaf) {
    for (const XmlField& f : xml.fields) {
        if (ends_with_ci(f.name, leaf)) return f.value;
    }
    return std::string();
}

bool has_leaf(const RenderedXml& xml, const std::string& leaf, std::string& out) {
    for (const XmlField& f : xml.fields) {
        if (ends_with_ci(f.name, leaf)) {
            out = f.value;
            return true;
        }
    }
    return false;
}

}  // namespace

core::Status parse_chunk_records(core::ByteSpan chunk, std::vector<EvtxRecord>& out,
                                 core::DiagnosticSink& diags,
                                 const ParseOptions& opts) {
    // Records begin after the 512-byte chunk header and run until the chunk's
    // free-space boundary. Clamp that boundary to [512, chunk size, 65536].
    core::Result<ChunkHeader> hr = parse_chunk_header(chunk);
    if (!hr.ok()) {
        return hr.status();
    }
    const ChunkHeader& ch = hr.value();

    core::usize chunk_limit = chunk.size();
    if (chunk_limit > kChunkSize) chunk_limit = kChunkSize;

    core::usize free_off = ch.free_space_offset;
    if (free_off < kChunkHeaderSize) free_off = kChunkHeaderSize;
    if (free_off > chunk_limit) free_off = chunk_limit;

    core::usize pos = kChunkHeaderSize;
    while (pos + kRecordMinSize <= free_off) {
        if (out.size() >= opts.max_records) {
            diags.warn("winlog.chunk", "max_records reached in chunk");
            break;
        }

        core::ByteReader r(chunk.subspan(pos, free_off - pos));
        core::u32 sig = r.read_u32_le();
        if (r.error()) break;
        if ((sig & 0xffff) != kRecordSignature) {
            // Not a record signature: the record area has ended (or is padded).
            break;
        }

        core::u32 size = r.read_u32_le();
        if (r.error()) break;

        // size is the TOTAL record length incl header + trailing size copy.
        if (size == 0) {
            // Zero size would not advance: stop to prevent an infinite loop.
            diags.warn("winlog.chunk", "zero-length record; stopping");
            break;
        }
        if (size < kRecordHeaderTrailer) {
            diags.warn("winlog.chunk", "record size smaller than framing");
            break;
        }
        // The record must fit within the remaining record area.
        if (size > free_off - pos) {
            diags.warn("winlog.chunk", "record size exceeds remaining chunk");
            break;
        }

        EvtxRecord rec;
        rec.record_id = r.read_u64_le();          // @8
        rec.written_filetime = r.read_u64_le();   // @16
        rec.file_offset = pos;
        if (r.error()) break;

        // BinXML occupies [record+24, record+size-4). Carve it from the chunk
        // span (not the local reader) so chunk-relative name/template offsets
        // resolve against the true chunk origin.
        core::usize bx_start = pos + 24;
        core::usize bx_end = pos + size - 4;
        if (bx_end > bx_start && bx_end <= chunk.size()) {
            core::ByteSpan bx = chunk.subspan(bx_start, bx_end - bx_start);
            rec.xml = decode_binxml(bx, chunk, diags, opts.binxml);
        }

        out.push_back(std::move(rec));

        // Advance by the full record size. We already proved size >= 28 > 0, so
        // this strictly increases pos and the loop terminates.
        pos += size;
    }

    return core::Status();  // Ok
}

event::LogEvent to_event(const EvtxRecord& rec) {
    event::LogEvent ev;
    ev.source = event::SourceFormat::WinEvent;
    ev.timestamp = core::parse_filetime(rec.written_filetime);
    ev.record_index = static_cast<core::usize>(rec.record_id);

    const RenderedXml& xml = rec.xml;

    // EventID -> event_id.
    std::string event_id;
    if (has_leaf(xml, "EventID", event_id)) {
        core::u64 n = 0;
        if (core::parse_u64(core::trim(event_id), n)) {
            ev.event_id = static_cast<core::u32>(n);
        }
    }

    // Level -> severity.
    std::string level;
    if (has_leaf(xml, "Level", level)) {
        core::u64 n = 0;
        if (core::parse_u64(core::trim(level), n)) {
            ev.severity = event::severity_from_winlevel(static_cast<core::u32>(n));
        } else {
            ev.severity = event::severity_from_word(level);
        }
    }

    // Computer -> host.
    std::string computer = find_by_leaf(xml, "Computer");
    if (!computer.empty()) ev.host = computer;

    // Channel -> channel.
    std::string channel = find_by_leaf(xml, "Channel");
    if (!channel.empty()) ev.channel = channel;

    // Provider name: prefer the "Provider@Name" attribute, else a "Name" leaf.
    std::string provider = find_by_leaf(xml, "Provider@Name");
    if (provider.empty()) provider = find_by_leaf(xml, "@Name");
    if (provider.empty()) provider = find_by_leaf(xml, "Name");
    if (!provider.empty()) {
        ev.provider = provider;
        ev.app = provider;
    }

    // TimeCreated@SystemTime overrides the record's written filetime when it is
    // present and parses as ISO-8601 (the BinXML renderer emits SysTime values
    // in that shape).
    std::string systime = find_by_leaf(xml, "TimeCreated@SystemTime");
    if (systime.empty()) systime = find_by_leaf(xml, "@SystemTime");
    if (!systime.empty()) {
        core::Timestamp t = core::parse_iso8601(core::trim(systime));
        if (t.valid) ev.timestamp = t;
    }

    // Copy every leaf field into the event's field map. Use the dotted name as
    // the key so callers can disambiguate (the map preserves insertion order).
    for (const XmlField& f : xml.fields) {
        ev.fields.set_string(f.name, f.value);
    }

    // Synthesize a one-line message from the salient fields plus a couple of
    // EventData values for context.
    std::string msg;
    if (!ev.provider.empty()) msg += ev.provider;
    if (!ev.channel.empty()) {
        if (!msg.empty()) msg += "/";
        msg += ev.channel;
    }
    if (ev.event_id != 0) {
        if (!msg.empty()) msg += " ";
        msg += "EventID=" + std::to_string(ev.event_id);
    }

    // Append up to two EventData/UserData values for a glimpse of the payload.
    int extras = 0;
    for (const XmlField& f : xml.fields) {
        if (extras >= 2) break;
        if (f.value.empty()) continue;
        if (ends_with_ci(f.name, "EventID") || ends_with_ci(f.name, "Level") ||
            ends_with_ci(f.name, "Channel") || ends_with_ci(f.name, "Computer")) {
            continue;
        }
        bool is_data = core::contains(f.name, "EventData") ||
                       core::contains(f.name, "UserData") ||
                       core::contains(f.name, "Data");
        if (!is_data) continue;
        if (!msg.empty()) msg += " ";
        // Keep each extra short so the message stays one line.
        msg += core::truncate(core::sanitize_printable(f.value), 48);
        ++extras;
    }

    ev.message = msg;
    return ev;
}

event::EventStream parse_stream(core::ByteSpan bytes, core::DiagnosticSink& diags,
                                const ParseOptions& opts) {
    event::EventStream stream;

    core::Result<FileHeader> fhr = parse_file_header(bytes);
    if (!fhr.ok()) {
        diags.error("winlog.file", "invalid EVTX file header: " +
                                       fhr.status().to_string());
        return stream;
    }

    // Iterate chunks at file offset 4096 + i*65536, bounded by max_chunks and by
    // the bytes available. We do not trust chunk_count; we walk until we run out
    // of well-formed chunks or hit the cap.
    core::usize chunk_index = 0;
    core::usize total_records = 0;

    for (; chunk_index < opts.max_chunks; ++chunk_index) {
        // Guard the offset arithmetic against overflow before trusting it.
        core::u64 off64 = static_cast<core::u64>(kFileHeaderSize) +
                          static_cast<core::u64>(chunk_index) * kChunkSize;
        if (core::add_overflows_u64(static_cast<core::u64>(kFileHeaderSize),
                                    static_cast<core::u64>(chunk_index) * kChunkSize)) {
            break;
        }
        if (off64 >= bytes.size()) break;  // no more chunk bytes

        core::usize off = static_cast<core::usize>(off64);
        // A chunk header alone is 512 bytes; require at least that much.
        core::usize avail = bytes.size() - off;
        if (avail < kChunkHeaderSize) {
            diags.warn("winlog.chunk", "trailing bytes too short for a chunk",
                       chunk_index);
            break;
        }

        core::usize chunk_len = avail < kChunkSize ? avail : kChunkSize;
        core::ByteSpan chunk = bytes.subspan(off, chunk_len);

        core::Result<ChunkHeader> chr = parse_chunk_header(chunk);
        if (!chr.ok()) {
            // A bad chunk magic means we've likely passed the last chunk; warn
            // and stop rather than scanning forever.
            diags.warn("winlog.chunk", "skipping chunk with bad header: " +
                                          chr.status().to_string(),
                       chunk_index);
            // If it was merely truncated/malformed at this offset, stop; later
            // offsets cannot become valid chunks of a different stride.
            break;
        }

        std::vector<EvtxRecord> records;
        core::Status rs = parse_chunk_records(chunk, records, diags, opts);
        if (!rs.ok()) {
            diags.warn("winlog.chunk", "record parse stopped: " + rs.to_string(),
                       chunk_index);
        }

        for (EvtxRecord& rec : records) {
            if (total_records >= opts.max_records) {
                diags.warn("winlog.stream", "max_records reached; stopping");
                return stream;
            }
            // Use a 1-based stream index when the record carried no id.
            if (rec.record_id == 0) {
                rec.record_id = static_cast<core::u64>(total_records + 1);
            }
            stream.add(to_event(rec));
            ++total_records;
        }
    }

    return stream;
}

void fuzz_one(core::ByteSpan bytes) {
    // Drive the full pipeline. Cap the limits so a hostile input cannot make the
    // fuzzer itself run unboundedly, while still exercising every code path.
    core::DiagnosticSink diags(256);
    ParseOptions opts;
    opts.max_chunks = 64;
    opts.max_records = 4096;

    event::EventStream stream = parse_stream(bytes, diags, opts);

    // Touch the derived accessors on every event so any UB in summary/signature
    // synthesis is caught too. Results are intentionally discarded.
    volatile core::usize sink = 0;
    for (const event::LogEvent& ev : stream.events()) {
        std::string s = ev.summary();
        std::string g = ev.signature();
        sink += s.size() + g.size();
    }
    (void)sink;
    (void)diags.render();
}

}  // namespace winlog
}  // namespace csift
