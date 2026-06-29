#include "winlog/evtx_header.hpp"

#include "core/byte_reader.hpp"

namespace csift {
namespace winlog {

// Layout offsets inside the 4096-byte file header. Only the prefix up to the
// flags/checksum at the tail of the 128-byte logical header carries data; the
// rest of the 4096-byte block is reserved padding.
namespace {

constexpr const char* kFileMagic = "ElfFile\0";   // 8 bytes incl. trailing NUL
constexpr const char* kChunkMagic = "ElfChnk\0";  // 8 bytes incl. trailing NUL
constexpr core::usize kMagicLen = 8;

}  // namespace

core::Result<FileHeader> parse_file_header(core::ByteSpan bytes) {
    FileHeader hdr;

    // A header needs at least its magic; the full logical header is 128 bytes
    // but we read individual fields defensively so a short-but-valid prefix is
    // still rejected only when a required field cannot be read.
    if (bytes.size() < kMagicLen) {
        return core::Result<FileHeader>::failure(core::StatusCode::Truncated,
                                                 "file header shorter than magic");
    }

    // Verify the "ElfFile\0" magic byte-for-byte (the trailing NUL matters; a
    // bare "ElfFile" without the NUL is treated as malformed).
    for (core::usize i = 0; i < kMagicLen; ++i) {
        if (bytes.at(i) != static_cast<core::byte>(kFileMagic[i])) {
            return core::Result<FileHeader>::failure(core::StatusCode::Malformed,
                                                     "bad EVTX file magic");
        }
    }

    core::ByteReader r(bytes);
    r.skip(kMagicLen);  // past the magic

    hdr.first_chunk_number = r.read_u64_le();   // @8
    hdr.last_chunk_number = r.read_u64_le();    // @16
    hdr.next_record_id = r.read_u64_le();       // @24
    hdr.header_size = r.read_u32_le();          // @32
    hdr.minor_version = r.read_u16_le();        // @36
    hdr.major_version = r.read_u16_le();        // @38
    hdr.header_block_size = r.read_u16_le();    // @40
    hdr.chunk_count = r.read_u16_le();          // @42

    // file_flags @120 and checksum @124 live near the end of the logical header.
    // These are optional for our purposes: read them only if the bytes exist.
    if (bytes.size() >= 124) {
        r.seek(120);
        hdr.file_flags = r.read_u32_le();
    }
    if (bytes.size() >= 128) {
        r.seek(124);
        hdr.checksum = r.read_u32_le();
    }

    // If we could not even read the fixed prefix the input is truncated. The
    // ByteReader latches a sticky error on the first underflow.
    if (r.error() && bytes.size() < 44) {
        return core::Result<FileHeader>::failure(core::StatusCode::Truncated,
                                                 "truncated EVTX file header");
    }

    hdr.valid = true;
    return core::Result<FileHeader>(hdr);
}

core::Result<ChunkHeader> parse_chunk_header(core::ByteSpan chunk) {
    ChunkHeader hdr;

    if (chunk.size() < kMagicLen) {
        return core::Result<ChunkHeader>::failure(core::StatusCode::Truncated,
                                                  "chunk header shorter than magic");
    }

    for (core::usize i = 0; i < kMagicLen; ++i) {
        if (chunk.at(i) != static_cast<core::byte>(kChunkMagic[i])) {
            return core::Result<ChunkHeader>::failure(core::StatusCode::Malformed,
                                                      "bad EVTX chunk magic");
        }
    }

    core::ByteReader r(chunk);
    r.skip(kMagicLen);  // past the magic

    hdr.first_event_record_number = r.read_u64_le();  // @8
    hdr.last_event_record_number = r.read_u64_le();   // @16
    hdr.first_event_record_id = r.read_u64_le();      // @24
    hdr.last_event_record_id = r.read_u64_le();       // @32
    hdr.header_size = r.read_u32_le();                // @40
    hdr.last_event_record_data_offset = r.read_u32_le();  // @44
    hdr.free_space_offset = r.read_u32_le();          // @48
    hdr.event_records_checksum = r.read_u32_le();     // @52

    if (chunk.size() >= 128) {
        r.seek(124);
        hdr.header_checksum = r.read_u32_le();        // @124
    }

    if (r.error() && chunk.size() < 56) {
        return core::Result<ChunkHeader>::failure(core::StatusCode::Truncated,
                                                  "truncated EVTX chunk header");
    }

    hdr.valid = true;
    return core::Result<ChunkHeader>(hdr);
}

}  // namespace winlog
}  // namespace csift
