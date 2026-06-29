#include <cstddef>
#include <cstdint>

#include "core/byte_span.hpp"
#include "winlog/evtx_parser.hpp"

// libFuzzer entry point. Drives arbitrary bytes through the Windows EVTX
// pipeline: file-header validation, chunk iteration, event-record framing, the
// recursive Binary XML token walker (including template instances and
// substitution arrays), and conversion to the unified event model. Every offset
// and length read from the input is treated as untrusted and bounds-clamped, so
// no input can cause an out-of-bounds access or a non-terminating loop.
extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
    csift::winlog::fuzz_one(csift::core::ByteSpan(data, size));
    return 0;
}
