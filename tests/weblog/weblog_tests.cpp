#include <string>

#include "core/byte_span.hpp"
#include "core/diagnostics.hpp"
#include "test_util.hpp"
#include "weblog/parser.hpp"

using namespace csift::weblog;
using csift::core::ByteSpan;
using csift::core::DiagnosticSink;

static void test_combined() {
    ParseOptions opts;
    auto r = parse_line(
        "127.0.0.1 - frank [10/Oct/2000:13:55:36 -0700] "
        "\"GET /apache_pb.gif?x=1 HTTP/1.0\" 200 2326 "
        "\"http://example.com/start.html\" \"Mozilla/4.08\"",
        opts);
    CHECK(r.ok());
    const AccessRecord& a = r.value();
    CHECK_EQ(a.format, WebLogFormat::Combined);
    CHECK_EQ(a.client_ip, std::string("127.0.0.1"));
    CHECK_EQ(a.user, std::string("frank"));
    CHECK_EQ(a.request.method, std::string("GET"));
    CHECK_EQ(a.request.version, std::string("HTTP/1.0"));
    CHECK_EQ(a.status, static_cast<csift::core::u32>(200));
    CHECK_EQ(a.bytes, static_cast<csift::core::u64>(2326));
    CHECK(a.bytes_known);
    CHECK_EQ(a.user_agent, std::string("Mozilla/4.08"));
    CHECK(a.time.valid);
    CHECK_EQ(a.decoded_path(), std::string("/apache_pb.gif"));
}

static void test_common_and_dash() {
    ParseOptions opts;
    auto r = parse_line(
        "10.0.0.5 - - [01/Jan/2024:00:00:00 +0000] \"POST /login HTTP/1.1\" 302 -",
        opts);
    CHECK(r.ok());
    const AccessRecord& a = r.value();
    CHECK_EQ(a.format, WebLogFormat::Common);
    CHECK_EQ(a.status, static_cast<csift::core::u32>(302));
    CHECK(!a.bytes_known);  // "-" bytes
    CHECK(a.user.empty());  // "-" user normalized to empty
}

static void test_invalid() {
    ParseOptions opts;
    auto r = parse_line("just three fields here", opts);
    CHECK(!r.ok());  // too few fields
    // Tokenizer must survive imbalanced quotes/brackets.
    (void)tokenize_fields("\"unterminated", opts);
    (void)tokenize_fields("[unterminated", opts);
    (void)parse_request_line("GET");
    CHECK(true);
}

static void test_stream() {
    const char* text =
        "1.2.3.4 - - [01/Jan/2024:00:00:00 +0000] \"GET / HTTP/1.1\" 200 10\n"
        "1.2.3.4 - - [01/Jan/2024:00:00:01 +0000] \"GET /x HTTP/1.1\" 404 0\n";
    DiagnosticSink diags;
    ParseOptions opts;
    auto stream = parse_stream(ByteSpan::from_string(text), diags, opts);
    CHECK_EQ(stream.size(), static_cast<csift::core::usize>(2));
}

int main() {
    std::printf("weblog_tests\n");
    RUN_TEST(test_combined);
    RUN_TEST(test_common_and_dash);
    RUN_TEST(test_invalid);
    RUN_TEST(test_stream);
    return TEST_MAIN_RESULT();
}
