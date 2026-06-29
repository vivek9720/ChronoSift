#include <cstddef>
#include <cstdint>

#include "cef/parser.hpp"
#include "core/byte_span.hpp"

// libFuzzer entry point. Drives arbitrary bytes through the CEF pipeline: the
// "CEF:" marker scan, the seven escaped pipe-delimited header fields, the
// key=value extension grammar with its own escape rules, and conversion to the
// unified event model. Tolerates any malformed or truncated input.
extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
    csift::cef::fuzz_one(csift::core::ByteSpan(data, size));
    return 0;
}
