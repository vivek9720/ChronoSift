#include <string>

#include "event/event.hpp"
#include "query/filter.hpp"
#include "test_util.hpp"

using namespace csift::query;
using csift::event::LogEvent;
using csift::event::Severity;

static LogEvent make_event() {
    LogEvent e;
    e.severity = Severity::Error;
    e.host = "web1";
    e.src_ip = "10.0.0.5";
    e.http_status = 404;
    e.message = "Failed password for root";
    e.fields.set_string("zone", "dmz");
    return e;
}

static void test_simple_match() {
    LogEvent e = make_event();
    auto f = parse_filter("host=web1");
    CHECK(f.ok());
    CHECK(f.value().matches(e));
    auto f2 = parse_filter("host=other");
    CHECK(f2.ok());
    CHECK(!f2.value().matches(e));
}

static void test_operators() {
    LogEvent e = make_event();
    CHECK(parse_filter("message~password").value().matches(e));
    CHECK(!parse_filter("message!~password").value().matches(e));
    CHECK(parse_filter("status>=400").value().matches(e));
    CHECK(!parse_filter("status<400").value().matches(e));
    // severity ordering: Error is more severe than warning, so severity<=error
    // (error or worse) holds.
    CHECK(parse_filter("severity<=error").value().matches(e));
    CHECK(parse_filter("severity>=warning").value().matches(e));
    // dynamic field from the FieldMap
    CHECK(parse_filter("zone=dmz").value().matches(e));
}

static void test_conjunctions() {
    LogEvent e = make_event();
    CHECK(parse_filter("host=web1 AND status=404").value().matches(e));
    CHECK(!parse_filter("host=web1 AND status=200").value().matches(e));
    CHECK(parse_filter("host=nope OR src_ip=10.0.0.5").value().matches(e));
}

static void test_empty_and_invalid() {
    LogEvent e = make_event();
    auto empty = parse_filter("   ");
    CHECK(empty.ok());
    CHECK(empty.value().matches(e));  // empty matches everything
    CHECK(!parse_filter("host").ok());          // missing operator
    CHECK(!parse_filter("host=").ok());         // missing value (bare)
    CHECK(!parse_filter("host=web1 AND").ok()); // dangling conjunction
    CHECK(!parse_filter("=value").ok());        // missing field
    // quoted value with spaces
    auto q = parse_filter("message~\"Failed password\"");
    CHECK(q.ok());
    CHECK(q.value().matches(e));
}

int main() {
    std::printf("query_tests\n");
    RUN_TEST(test_simple_match);
    RUN_TEST(test_operators);
    RUN_TEST(test_conjunctions);
    RUN_TEST(test_empty_and_invalid);
    return TEST_MAIN_RESULT();
}
