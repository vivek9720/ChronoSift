#include <string>

#include "core/byte_span.hpp"
#include "core/diagnostics.hpp"
#include "syslog/parser.hpp"
#include "test_util.hpp"

using namespace csift::syslog;
using csift::core::ByteSpan;
using csift::core::DiagnosticSink;

static void test_rfc3164() {
    ParseOptions opts;
    opts.assume_year = 2024;
    auto r = parse_line("<34>Oct 11 22:14:15 mymachine su[1234]: 'su root' failed",
                        opts);
    CHECK(r.ok());
    const SyslogMessage& m = r.value();
    CHECK_EQ(m.flavor, SyslogFlavor::Rfc3164);
    CHECK(m.has_pri);
    CHECK_EQ(m.facility, static_cast<csift::core::u32>(4));
    CHECK_EQ(m.severity, static_cast<csift::core::u32>(2));
    CHECK_EQ(m.hostname, std::string("mymachine"));
    CHECK_EQ(m.app_name, std::string("su"));
    CHECK_EQ(m.proc_id, std::string("1234"));
    CHECK(m.timestamp.valid);
}

static void test_rfc5424_with_sd() {
    ParseOptions opts;
    auto r = parse_line(
        "<165>1 2003-10-11T22:14:15.003Z host.example.com evntslog 1024 ID47 "
        "[exampleSDID@32473 iut=\"3\" eventID=\"1011\"] An application event",
        opts);
    CHECK(r.ok());
    const SyslogMessage& m = r.value();
    CHECK_EQ(m.flavor, SyslogFlavor::Rfc5424);
    CHECK_EQ(m.version, static_cast<csift::core::u32>(1));
    CHECK_EQ(m.hostname, std::string("host.example.com"));
    CHECK_EQ(m.app_name, std::string("evntslog"));
    CHECK_EQ(m.msg_id, std::string("ID47"));
    CHECK(m.timestamp.valid);
    CHECK_EQ(m.structured_data.size(), static_cast<csift::core::usize>(1));
    CHECK_EQ(m.structured_data[0].id, std::string("exampleSDID@32473"));
    CHECK_EQ(m.structured_data[0].params.size(), static_cast<csift::core::usize>(2));
}

static void test_invalid_and_edge() {
    ParseOptions opts;
    // No PRI: still best-effort, must not crash.
    auto r1 = parse_line("plain text line with no priority", opts);
    (void)r1;
    // Degenerate PRI forms.
    (void)parse_line("<", opts);
    (void)parse_line("<>", opts);
    (void)parse_line("<999>", opts);  // out-of-range priority
    (void)parse_line("", opts);
    CHECK(true);  // reaching here means no crash/UB
}

static void test_stream() {
    const char* text =
        "<34>Oct 11 22:14:15 host su[1]: a\n"
        "<165>1 2024-01-01T00:00:00Z h app 2 id - msg\n"
        "garbage line\n";
    DiagnosticSink diags;
    ParseOptions opts;
    opts.assume_year = 2024;
    auto stream = parse_stream(ByteSpan::from_string(text), diags, opts);
    CHECK_EQ(stream.size(), static_cast<csift::core::usize>(3));
    // The two well-formed lines carry timestamps.
    CHECK(stream.timed_count() >= 2);
}

int main() {
    std::printf("syslog_tests\n");
    RUN_TEST(test_rfc3164);
    RUN_TEST(test_rfc5424_with_sd);
    RUN_TEST(test_invalid_and_edge);
    RUN_TEST(test_stream);
    return TEST_MAIN_RESULT();
}
