#include <cstddef>
#include <cstdint>

#include "core/byte_span.hpp"
#include "jsonlog/log_mapper.hpp"

// libFuzzer entry point. Drives arbitrary bytes through the JSON-lines pipeline:
// the depth- and size-limited recursive-descent JSON parser, then the field
// alias mapping that projects each document onto the unified event model. The
// parser's explicit limits keep deeply nested or oversized input bounded.
extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
    csift::jsonlog::fuzz_one(csift::core::ByteSpan(data, size));
    return 0;
}
