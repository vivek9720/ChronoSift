#include <string>

#include "event/stream.hpp"
#include "serialize/writer.hpp"
#include "test_util.hpp"

using namespace csift::serialize;
using csift::core::Timestamp;
using csift::event::LogEvent;
using csift::event::Severity;
using csift::event::SourceFormat;
using csift::event::EventStream;

static void test_json_escape() {
    CHECK_EQ(json_escape("plain"), std::string("plain"));
    CHECK_EQ(json_escape("a\"b"), std::string("a\\\"b"));
    CHECK_EQ(json_escape("a\\b"), std::string("a\\\\b"));
    CHECK_EQ(json_escape(std::string("a\x01""b")), std::string("a\\u0001b"));
    CHECK_EQ(json_escape("tab\there"), std::string("tab\\there"));
}

static void test_csv_quote() {
    CHECK_EQ(csv_quote("plain"), std::string("plain"));
    CHECK_EQ(csv_quote("a,b"), std::string("\"a,b\""));
    CHECK_EQ(csv_quote("a\"b"), std::string("\"a\"\"b\""));
    CHECK_EQ(csv_quote("line\nbreak"), std::string("\"line\nbreak\""));
}

static LogEvent sample() {
    LogEvent e;
    e.timestamp = Timestamp::from_unix_seconds(1709983353);
    e.severity = Severity::Error;
    e.source = SourceFormat::WebAccess;
    e.record_index = 1;
    e.src_ip = "10.0.0.1";
    e.http_method = "GET";
    e.http_path = "/a,b";  // contains a comma to test CSV quoting
    e.http_status = 500;
    e.message = "boom \"quoted\"";
    e.fields.set_string("extra", "v1");
    return e;
}

static void test_ndjson_and_csv() {
    EventStream s;
    s.add(sample());
    std::string nd = to_ndjson(s);
    CHECK(nd.find("\"severity\":\"error\"") != std::string::npos);
    CHECK(nd.find("\"http_status\":500") != std::string::npos);
    CHECK(nd.find("\"src_ip\":\"10.0.0.1\"") != std::string::npos);
    CHECK(nd.find("\"extra\"") != std::string::npos);
    CHECK(!nd.empty() && nd.back() == '\n');

    std::string csv = to_csv(s);
    CHECK(csv.find(csv_header()) == 0);          // header first
    CHECK(csv.find("\"/a,b\"") != std::string::npos);  // comma field quoted
    CHECK(csv.find("500") != std::string::npos);
}

static void test_empty() {
    EventStream s;
    CHECK(to_ndjson(s).empty());
    std::string csv = to_csv(s);
    CHECK(csv.find(csv_header()) == 0);  // header even when no rows
}

int main() {
    std::printf("serialize_tests\n");
    RUN_TEST(test_json_escape);
    RUN_TEST(test_csv_quote);
    RUN_TEST(test_ndjson_and_csv);
    RUN_TEST(test_empty);
    return TEST_MAIN_RESULT();
}
