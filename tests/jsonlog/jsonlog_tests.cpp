#include <string>

#include "core/byte_span.hpp"
#include "core/diagnostics.hpp"
#include "jsonlog/json_parser.hpp"
#include "jsonlog/json_value.hpp"
#include "jsonlog/log_mapper.hpp"
#include "test_util.hpp"

using namespace csift::jsonlog;
using csift::core::ByteSpan;
using csift::core::DiagnosticSink;

static void test_parse_scalars() {
    JsonParser p;
    auto r = p.parse("{\"a\":1,\"b\":true,\"c\":\"x\",\"d\":null,\"e\":1.5}");
    CHECK(r.ok());
    const JsonValue& v = r.value();
    CHECK(v.is_object());
    const JsonValue* a = v.find("a");
    CHECK(a && a->is_number());
    CHECK_EQ(a->as_int(), static_cast<csift::core::i64>(1));
    const JsonValue* b = v.find("b");
    CHECK(b && b->is_bool() && b->as_bool());
    const JsonValue* c = v.find("c");
    CHECK(c && c->is_string());
    CHECK_EQ(c->as_string(), std::string("x"));
}

static void test_escapes_and_unicode() {
    JsonParser p;
    auto r = p.parse("\"a\\tb\\u0041\\u00e9\"");
    CHECK(r.ok());
    // a, \t, b, 'A' (A), é (é -> UTF-8 0xC3 0xA9)
    CHECK_EQ(r.value().as_string(), std::string("a\tbA\xc3\xa9"));
    // surrogate pair for U+1F600
    auto r2 = p.parse("\"\\ud83d\\ude00\"");
    CHECK(r2.ok());
    CHECK_EQ(r2.value().as_string().size(), static_cast<csift::core::usize>(4));
}

static void test_limits_and_invalid() {
    JsonLimits limits;
    limits.max_depth = 8;
    JsonParser p(limits);
    // Deep nesting beyond the limit must be rejected, not crash.
    std::string deep;
    for (int i = 0; i < 100; ++i) deep += '[';
    auto r = p.parse(deep);
    CHECK(!r.ok());
    CHECK_EQ(r.code(), csift::core::StatusCode::LimitExceeded);
    // Trailing garbage rejected.
    CHECK(!p.parse("{} junk").ok());
    // Unterminated string rejected.
    CHECK(!p.parse("\"abc").ok());
    // Control char in string rejected.
    CHECK(!p.parse(std::string("\"a\x01\"")).ok());
}

static void test_mapping_and_stream() {
    const char* text =
        "{\"@timestamp\":\"2024-03-09T11:22:33Z\",\"level\":\"error\","
        "\"message\":\"boom\",\"host\":\"web1\",\"user\":\"root\"}\n"
        "\n"
        "not json\n";
    DiagnosticSink diags;
    auto stream = parse_stream(ByteSpan::from_string(text), diags, JsonLimits(), 2024);
    CHECK(stream.size() >= 1);
    const auto& e = stream.events()[0];
    CHECK_EQ(e.source, csift::event::SourceFormat::Json);
    CHECK_EQ(e.severity, csift::event::Severity::Error);
    CHECK_EQ(e.host, std::string("web1"));
    CHECK(e.timestamp.valid);
}

int main() {
    std::printf("jsonlog_tests\n");
    RUN_TEST(test_parse_scalars);
    RUN_TEST(test_escapes_and_unicode);
    RUN_TEST(test_limits_and_invalid);
    RUN_TEST(test_mapping_and_stream);
    return TEST_MAIN_RESULT();
}
