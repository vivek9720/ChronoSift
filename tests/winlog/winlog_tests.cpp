#include <cstring>
#include <string>
#include <vector>

#include "core/byte_span.hpp"
#include "core/diagnostics.hpp"
#include "test_util.hpp"
#include "winlog/evtx_header.hpp"
#include "winlog/evtx_parser.hpp"

using namespace csift::winlog;
using csift::core::ByteSpan;
using csift::core::DiagnosticSink;

static void put_u16(std::vector<uint8_t>& b, size_t off, uint16_t v) {
    b[off] = v & 0xff;
    b[off + 1] = (v >> 8) & 0xff;
}
static void put_u32(std::vector<uint8_t>& b, size_t off, uint32_t v) {
    for (int i = 0; i < 4; ++i) b[off + i] = (v >> (8 * i)) & 0xff;
}
static void put_u64(std::vector<uint8_t>& b, size_t off, uint64_t v) {
    for (int i = 0; i < 8; ++i) b[off + i] = (v >> (8 * i)) & 0xff;
}

static void test_file_header_valid() {
    std::vector<uint8_t> b(kFileHeaderSize, 0);
    std::memcpy(b.data(), "ElfFile\0", 8);
    put_u64(b, 8, 0);     // first chunk
    put_u64(b, 16, 0);    // last chunk
    put_u64(b, 24, 1);    // next record id
    put_u32(b, 32, 128);  // header size
    put_u16(b, 36, 1);    // minor
    put_u16(b, 38, 3);    // major
    put_u16(b, 40, 4096); // header block size
    put_u16(b, 42, 1);    // chunk count
    auto r = parse_file_header(ByteSpan(b.data(), b.size()));
    CHECK(r.ok());
    CHECK(r.value().valid);
    CHECK_EQ(r.value().major_version, static_cast<csift::core::u16>(3));
    CHECK_EQ(r.value().chunk_count, static_cast<csift::core::u16>(1));
}

static void test_file_header_bad_magic() {
    std::vector<uint8_t> b(kFileHeaderSize, 0);
    std::memcpy(b.data(), "NOTaFILE", 8);
    auto r = parse_file_header(ByteSpan(b.data(), b.size()));
    CHECK(!r.ok());
}

static void test_robustness() {
    DiagnosticSink d1;
    // Empty input.
    auto s0 = parse_stream(ByteSpan(), d1, ParseOptions());
    CHECK_EQ(s0.size(), static_cast<csift::core::usize>(0));

    // Lone magic, nothing else.
    std::string lone = "ElfFile";
    DiagnosticSink d2;
    auto s1 = parse_stream(ByteSpan::from_string(lone), d2, ParseOptions());
    (void)s1;

    // Valid header, truncated chunk region (no crash, no records).
    std::vector<uint8_t> b(kFileHeaderSize, 0);
    std::memcpy(b.data(), "ElfFile\0", 8);
    put_u16(b, 42, 4);  // claims 4 chunks but no data follows
    DiagnosticSink d3;
    auto s2 = parse_stream(ByteSpan(b.data(), b.size()), d3, ParseOptions());
    (void)s2;

    // Pure junk of varied sizes must not crash.
    for (size_t n : {1u, 7u, 8u, 64u, 513u, 4097u}) {
        std::vector<uint8_t> junk(n, 0xAB);
        DiagnosticSink d;
        auto s = parse_stream(ByteSpan(junk.data(), junk.size()), d, ParseOptions());
        (void)s;
    }
    CHECK(true);  // survived everything
}

int main() {
    std::printf("winlog_tests\n");
    RUN_TEST(test_file_header_valid);
    RUN_TEST(test_file_header_bad_magic);
    RUN_TEST(test_robustness);
    return TEST_MAIN_RESULT();
}
