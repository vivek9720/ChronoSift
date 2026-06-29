#include <string>

#include "core/byte_span.hpp"
#include "core/diagnostics.hpp"
#include "pipeline/ingest.hpp"
#include "test_util.hpp"

using namespace csift::pipeline;
using csift::core::ByteSpan;
using csift::core::DiagnosticSink;

static void test_format_detection() {
    CHECK_EQ(detect_format(ByteSpan::from_string("<34>Oct 11 22:14:15 h x: y")),
             Format::Syslog);
    CHECK_EQ(detect_format(ByteSpan::from_string("{\"a\":1}")), Format::Json);
    CHECK_EQ(detect_format(ByteSpan::from_string(
                 "1.2.3.4 - - [01/Jan/2024:00:00:00 +0000] \"GET / HTTP/1.1\" 200 1")),
             Format::WebAccess);
    CHECK_EQ(detect_format(ByteSpan::from_string("ElfFile\x00 rest")), Format::WinEvtx);
    Format f;
    CHECK(parse_format_name("json", f) && f == Format::Json);
    CHECK(!parse_format_name("nonsense", f));
}

static void test_ingest_dispatch() {
    DiagnosticSink diags;
    IngestOptions opts;
    opts.format = Format::Auto;
    auto stream = ingest(ByteSpan::from_string("{\"message\":\"hi\",\"level\":\"warn\"}"),
                         diags, opts);
    CHECK_EQ(stream.size(), static_cast<csift::core::usize>(1));
    CHECK_EQ(stream.events()[0].source, csift::event::SourceFormat::Json);
}

static void test_ingest_empty() {
    DiagnosticSink diags;
    auto stream = ingest(ByteSpan(), diags, IngestOptions());
    CHECK_EQ(stream.size(), static_cast<csift::core::usize>(0));
}

int main() {
    std::printf("pipeline_tests\n");
    RUN_TEST(test_format_detection);
    RUN_TEST(test_ingest_dispatch);
    RUN_TEST(test_ingest_empty);
    return TEST_MAIN_RESULT();
}
