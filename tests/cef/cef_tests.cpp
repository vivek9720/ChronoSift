#include <string>

#include "cef/parser.hpp"
#include "core/byte_span.hpp"
#include "core/diagnostics.hpp"
#include "test_util.hpp"

using namespace csift::cef;
using csift::core::ByteSpan;
using csift::core::DiagnosticSink;

static void test_basic() {
    ParseOptions opts;
    auto r = parse_line(
        "CEF:0|Security|threatmanager|1.0|100|worm stopped|10|"
        "src=10.0.0.1 dst=2.1.2.2 spt=1232 dpt=443 act=blocked",
        opts);
    CHECK(r.ok());
    const CefRecord& c = r.value();
    CHECK(c.valid);
    CHECK_EQ(c.version, static_cast<csift::core::u32>(0));
    CHECK_EQ(c.device_vendor, std::string("Security"));
    CHECK_EQ(c.device_product, std::string("threatmanager"));
    CHECK_EQ(c.signature_id, std::string("100"));
    CHECK_EQ(c.name, std::string("worm stopped"));
    CHECK_EQ(c.ext("src"), std::string("10.0.0.1"));
    CHECK_EQ(c.ext("dpt"), std::string("443"));
    CHECK(c.has_ext("act"));
    CHECK(!c.has_ext("missing"));
}

static void test_syslog_prefixed_and_escapes() {
    ParseOptions opts;
    auto r = parse_line(
        "<134>Jan 18 11:07:53 host CEF:0|Vendor\\|Inc|Pro\\\\duct|2.0|1|"
        "Name with \\| pipe|3|msg=hi reason=bad\\=value",
        opts);
    CHECK(r.ok());
    const CefRecord& c = r.value();
    CHECK_EQ(c.device_vendor, std::string("Vendor|Inc"));
    CHECK_EQ(c.device_product, std::string("Pro\\duct"));
    CHECK_EQ(c.name, std::string("Name with | pipe"));
    CHECK_EQ(c.ext("reason"), std::string("bad=value"));
}

static void test_to_event() {
    ParseOptions opts;
    auto r = parse_line(
        "CEF:0|McAfee|ePO|5.10|18000|Failed login|7|"
        "suser=admin src=203.0.113.7",
        opts);
    CHECK(r.ok());
    auto e = to_event(r.value(), opts);
    CHECK_EQ(e.src_ip, std::string("203.0.113.7"));
    CHECK_EQ(e.user, std::string("admin"));
    // CEF severity 7 maps to Error (3) on the normalized scale.
    CHECK_EQ(e.severity, csift::event::Severity::Error);
}

static void test_invalid_and_stream() {
    ParseOptions opts;
    CHECK(!parse_line("no marker here", opts).ok());
    CHECK(!parse_line("CEF:0|only|three|pipes", opts).ok());
    (void)parse_line("CEF:", opts);
    (void)parse_line("CEF:0|v|p|ver|sig|name|5|key= =value broken=", opts);

    const char* text =
        "CEF:0|A|B|1|1|n|5|src=1.1.1.1\n"
        "CEF:0|A|B|1|2|m|9|src=2.2.2.2 dpt=22\n";
    DiagnosticSink diags;
    auto stream = parse_stream(ByteSpan::from_string(text), diags, opts);
    CHECK_EQ(stream.size(), static_cast<csift::core::usize>(2));
}

int main() {
    std::printf("cef_tests\n");
    RUN_TEST(test_basic);
    RUN_TEST(test_syslog_prefixed_and_escapes);
    RUN_TEST(test_to_event);
    RUN_TEST(test_invalid_and_stream);
    return TEST_MAIN_RESULT();
}
