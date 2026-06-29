#include <cstddef>
#include <cstdint>

#include "core/byte_span.hpp"
#include "weblog/parser.hpp"

// libFuzzer entry point. Drives arbitrary bytes through the web access-log
// pipeline: field tokenization (with quote and bracket handling), request-line
// parsing, CLF timestamp parsing, Common/Combined field interpretation, and
// event conversion. Tolerates any malformed or truncated input.
extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
    csift::weblog::fuzz_one(csift::core::ByteSpan(data, size));
    return 0;
}
