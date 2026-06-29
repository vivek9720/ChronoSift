#ifndef CSIFT_WINLOG_EVTX_HEADER_HPP
#define CSIFT_WINLOG_EVTX_HEADER_HPP

#include "core/byte_span.hpp"
#include "core/status.hpp"
#include "core/types.hpp"

namespace csift {
namespace winlog {

// Layout constants of the Windows EVTX container format.
constexpr core::usize kFileHeaderSize = 4096;
constexpr core::usize kChunkSize = 65536;
constexpr core::usize kChunkHeaderSize = 512;
constexpr core::u16 kRecordSignature = 0x2a2a;  // "**"

// The 4096-byte file header at offset 0. Magic is "ElfFile\0".
struct FileHeader {
    bool valid = false;
    core::u64 first_chunk_number = 0;
    core::u64 last_chunk_number = 0;
    core::u64 next_record_id = 0;
    core::u32 header_size = 0;
    core::u16 minor_version = 0;
    core::u16 major_version = 0;
    core::u16 header_block_size = 0;
    core::u16 chunk_count = 0;
    core::u32 file_flags = 0;
    core::u32 checksum = 0;
};

// The 512-byte chunk header. Magic is "ElfChnk\0". The record numbers/ids bound
// what the chunk claims to contain; the parser treats them as hints, not trust.
struct ChunkHeader {
    bool valid = false;
    core::u64 first_event_record_number = 0;
    core::u64 last_event_record_number = 0;
    core::u64 first_event_record_id = 0;
    core::u64 last_event_record_id = 0;
    core::u32 header_size = 0;
    core::u32 last_event_record_data_offset = 0;
    core::u32 free_space_offset = 0;
    core::u32 event_records_checksum = 0;
    core::u32 header_checksum = 0;
};

// Parses the file header from the first kFileHeaderSize bytes. Verifies the
// magic and that sizes are self-consistent; otherwise returns Malformed.
core::Result<FileHeader> parse_file_header(core::ByteSpan bytes);

// Parses a chunk header from a span whose origin is the start of the chunk.
core::Result<ChunkHeader> parse_chunk_header(core::ByteSpan chunk);

}  // namespace winlog
}  // namespace csift

#endif  // CSIFT_WINLOG_EVTX_HEADER_HPP
