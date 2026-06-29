#include "event/event.hpp"
#include "event/field.hpp"
#include "event/severity.hpp"
#include "event/stream.hpp"
#include "test_util.hpp"

using namespace csift::event;
using csift::core::Timestamp;

static void test_severity_mapping() {
    CHECK_EQ(severity_from_syslog(3), Severity::Error);
    CHECK_EQ(severity_from_syslog(99), Severity::Unknown);
    CHECK_EQ(severity_from_word("ERR"), Severity::Error);
    CHECK_EQ(severity_from_word("warning"), Severity::Warning);
    CHECK_EQ(severity_from_word("bogus"), Severity::Unknown);
    CHECK_EQ(severity_from_winlevel(2), Severity::Error);
    CHECK(at_least_as_severe(Severity::Critical, Severity::Error));
    CHECK(!at_least_as_severe(Severity::Notice, Severity::Error));
    CHECK(!at_least_as_severe(Severity::Unknown, Severity::Debug));
}

static void test_field_map() {
    FieldMap m;
    m.set_string("user", "alice");
    m.set_int("port", 22);
    CHECK(m.has("user"));
    CHECK(!m.has("missing"));
    CHECK_EQ(m.get_string("user"), std::string("alice"));
    CHECK_EQ(m.get_string("port"), std::string("22"));
    m.set_string("user", "bob");  // replace, not duplicate
    CHECK_EQ(m.size(), static_cast<csift::core::usize>(2));
    CHECK_EQ(m.get_string("user"), std::string("bob"));
}

static void test_signature_and_summary() {
    LogEvent e;
    e.source = SourceFormat::Syslog;
    e.app = "sshd";
    e.message = "Failed password for user from 10.0.0.1 port 22";
    std::string s1 = e.signature();
    LogEvent e2 = e;
    e2.message = "Failed password for user from 10.0.0.9 port 44";
    // Digit runs collapse, so the two share a signature.
    CHECK_EQ(e.signature(), e2.signature());
    CHECK(!e.summary().empty());
}

static void test_stream_sort_and_bounds() {
    EventStream s;
    LogEvent a;
    a.timestamp = Timestamp::from_unix_seconds(300);
    a.severity = Severity::Error;
    LogEvent b;
    b.timestamp = Timestamp::from_unix_seconds(100);
    b.severity = Severity::Informational;
    LogEvent c;  // untimed
    s.add(a);
    s.add(b);
    s.add(c);
    CHECK_EQ(s.size(), static_cast<csift::core::usize>(3));
    CHECK_EQ(s.timed_count(), static_cast<csift::core::usize>(2));
    CHECK_EQ(s.earliest().micros, static_cast<csift::core::i64>(100) * 1000000);
    CHECK_EQ(s.count_at_least(Severity::Error), static_cast<csift::core::usize>(1));
    s.sort_by_time();
    // Untimed sorts first, then by time ascending.
    CHECK(!s.events()[0].timestamp.valid);
    CHECK_EQ(s.events()[1].timestamp.micros, static_cast<csift::core::i64>(100) * 1000000);
}

int main() {
    std::printf("event_tests\n");
    RUN_TEST(test_severity_mapping);
    RUN_TEST(test_field_map);
    RUN_TEST(test_signature_and_summary);
    RUN_TEST(test_stream_sort_and_bounds);
    return TEST_MAIN_RESULT();
}
