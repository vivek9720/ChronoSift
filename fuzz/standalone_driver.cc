// Minimal libFuzzer-compatible driver for local robustness testing.
//
// ClusterFuzzLite (and OSS-Fuzz) supply their own fuzzing engine through the
// $LIB_FUZZING_ENGINE link flag, so this file is NOT compiled in that
// environment. It exists only so developers can build the harnesses with an
// ordinary compiler (no libFuzzer) and replay a corpus or a single input:
//
//     ./syslog_fuzzer corpus/syslog_fuzzer/*
//     ./syslog_fuzzer some_input.bin
//
// Each argument is read as a file and fed once to LLVMFuzzerTestOneInput. With
// no arguments it reads standard input.

#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <vector>

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size);

namespace {

std::vector<uint8_t> read_stream(std::FILE* f) {
    std::vector<uint8_t> buf;
    uint8_t chunk[4096];
    size_t n;
    while ((n = std::fread(chunk, 1, sizeof(chunk), f)) > 0) {
        buf.insert(buf.end(), chunk, chunk + n);
    }
    return buf;
}

}  // namespace

int main(int argc, char** argv) {
    if (argc < 2) {
        std::vector<uint8_t> bytes = read_stream(stdin);
        return LLVMFuzzerTestOneInput(bytes.data(), bytes.size());
    }
    int rc = 0;
    for (int i = 1; i < argc; ++i) {
        std::FILE* f = std::fopen(argv[i], "rb");
        if (!f) {
            std::fprintf(stderr, "warning: cannot open %s\n", argv[i]);
            continue;
        }
        std::vector<uint8_t> bytes = read_stream(f);
        std::fclose(f);
        int r = LLVMFuzzerTestOneInput(bytes.data(), bytes.size());
        if (r != 0) rc = r;
    }
    return rc;
}
