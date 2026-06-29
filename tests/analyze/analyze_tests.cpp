#include <string>

#include "analyze/correlate.hpp"
#include "analyze/detections.hpp"
#include "analyze/statistics.hpp"
#include "analyze/timeline.hpp"
#include "event/stream.hpp"
#include "test_util.hpp"

using namespace csift::analyze;
using csift::core::Timestamp;
using csift::event::LogEvent;
using csift::event::Severity;
using csift::event::SourceFormat;
using csift::event::EventStream;

static LogEvent failed_auth(const char* ip, csift::core::i64 t) {
    LogEvent e;
    e.source = SourceFormat::Syslog;
    e.app = "sshd";
    e.src_ip = ip;
    e.severity = Severity::Notice;
    e.timestamp = Timestamp::from_unix_seconds(t);
    e.message = "Failed password for invalid user admin from ";
    e.message += ip;
    return e;
}

static void test_statistics() {
    EventStream s;
    for (int i = 0; i < 5; ++i) s.add(failed_auth("10.0.0.1", 1000 + i));
    LogEvent ok;
    ok.source = SourceFormat::WebAccess;
    ok.http_status = 200;
    ok.timestamp = Timestamp::from_unix_seconds(1010);
    s.add(ok);
    StreamStatistics stats = compute_statistics(s);
    CHECK_EQ(stats.total_events, static_cast<csift::core::usize>(6));
    CHECK_EQ(stats.by_source.get("syslog"), static_cast<csift::core::u64>(5));
    CHECK_EQ(stats.top_source_ips.get("10.0.0.1"), static_cast<csift::core::u64>(5));
    CHECK(stats.http_status_class.get("2xx") >= 1);
    CHECK(!stats.render().empty());
}

static void test_bruteforce_detection() {
    EventStream s;
    for (int i = 0; i < 8; ++i) s.add(failed_auth("203.0.113.7", 1000 + i * 5));
    DetectionConfig cfg;
    cfg.bruteforce_min_failures = 5;
    cfg.bruteforce_window_seconds = 120;
    auto findings = run_detections(s, cfg);
    bool found_bf = false;
    for (const Finding& f : findings) {
        if (f.kind == FindingKind::AuthBruteForce) {
            found_bf = true;
            CHECK_EQ(f.entity, std::string("203.0.113.7"));
            CHECK(f.count >= 5);
        }
    }
    CHECK(found_bf);
}

static void test_timeline_and_sessions() {
    EventStream s;
    s.add(failed_auth("10.0.0.2", 1000));
    s.add(failed_auth("10.0.0.2", 1005));
    s.add(failed_auth("10.0.0.2", 100000));  // big gap -> new session
    Timeline tl = build_timeline(s, 3600, 3600);
    CHECK(!tl.buckets.empty());
    CHECK(!tl.gaps.empty());
    auto sessions = build_sessions(s, SessionKey::SourceIp, 900);
    CHECK_EQ(sessions.size(), static_cast<csift::core::usize>(2));
}

static void test_empty_stream() {
    EventStream s;
    auto findings = run_detections(s, DetectionConfig());
    CHECK(findings.empty());
    StreamStatistics stats = compute_statistics(s);
    CHECK_EQ(stats.total_events, static_cast<csift::core::usize>(0));
    Timeline tl = build_timeline(s, 60, 60);
    CHECK(tl.buckets.empty());  // no crash on empty
}

int main() {
    std::printf("analyze_tests\n");
    RUN_TEST(test_statistics);
    RUN_TEST(test_bruteforce_detection);
    RUN_TEST(test_timeline_and_sessions);
    RUN_TEST(test_empty_stream);
    return TEST_MAIN_RESULT();
}
