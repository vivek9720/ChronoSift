#include <cstddef>
#include <cstdint>

#include "core/byte_span.hpp"
#include "syslog/parser.hpp"

// libFuzzer entry point. Each invocation drives an arbitrary byte buffer through
// the full syslog pipeline: line framing, PRI decoding, RFC3164/RFC5424
// dispatch, timestamp and structured-data parsing, and conversion to the
// unified event model. The parser is built to absorb any malformed or truncated
// input without crashing or reading out of bounds.
extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
    csift::syslog::fuzz_one(csift::core::ByteSpan(data, size));
    return 0;
}
