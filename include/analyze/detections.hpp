#ifndef CSIFT_ANALYZE_DETECTIONS_HPP
#define CSIFT_ANALYZE_DETECTIONS_HPP

#include <string>
#include <vector>

#include "core/types.hpp"
#include "event/event.hpp"
#include "event/severity.hpp"
#include "event/stream.hpp"

namespace csift {
namespace analyze {

// The category of a heuristic finding.
enum class FindingKind {
    AuthBruteForce,     // many failed auths from one source in a window
    AuthSprayThenHit,   // failures followed by a success from same source
    HttpErrorBurst,     // spike of 4xx/5xx from one client
    PortOrPathScan,     // one source touching many distinct paths/targets
    SeveritySpike,      // burst of high-severity events in a window
    RareSignature,      // an event type that occurs only a handful of times
    LogGap,             // a suspicious absence of events
};

const char* finding_kind_name(FindingKind k) noexcept;

// One detection result. `evidence` holds indices into the stream's event vector
// so a tool can print the supporting records.
struct Finding {
    FindingKind kind;
    event::Severity severity = event::Severity::Warning;
    std::string title;
    std::string description;
    std::string entity;        // the implicated host/ip/user/signature
    core::usize count = 0;
    core::Timestamp first_seen;
    core::Timestamp last_seen;
    std::vector<core::usize> evidence;

    std::string render() const;
};

// Thresholds for the detectors. Defaults are tuned for typical host logs but
// are all overridable so an analyst can tighten or loosen them.
struct DetectionConfig {
    core::usize bruteforce_min_failures = 5;
    core::i64 bruteforce_window_seconds = 120;
    core::usize http_error_min = 20;
    core::i64 http_error_window_seconds = 60;
    core::usize scan_distinct_min = 25;
    core::i64 scan_window_seconds = 60;
    core::usize severity_spike_min = 10;
    core::i64 severity_spike_window_seconds = 30;
    core::usize rare_signature_max = 3;
    core::usize evidence_cap = 32;  // max evidence indices kept per finding
};

// Classification helpers shared by detectors. They look at the normalized event
// (message text, event_id, fields) to decide intent.
bool is_failed_auth(const event::LogEvent& e);
bool is_successful_auth(const event::LogEvent& e);

// Extracts the "actor" key a detector groups by for a given event (source IP if
// present, else user, else host). Empty when none is available.
std::string actor_key(const event::LogEvent& e);

// Individual detectors. Each returns its findings; the orchestrator below runs
// them all. They assume the stream is sorted by time and sort it if not.
std::vector<Finding> detect_auth_bruteforce(const event::EventStream& s,
                                            const DetectionConfig& cfg);
std::vector<Finding> detect_http_error_bursts(const event::EventStream& s,
                                              const DetectionConfig& cfg);
std::vector<Finding> detect_scans(const event::EventStream& s,
                                  const DetectionConfig& cfg);
std::vector<Finding> detect_severity_spikes(const event::EventStream& s,
                                            const DetectionConfig& cfg);
std::vector<Finding> detect_rare_signatures(const event::EventStream& s,
                                            const DetectionConfig& cfg);

// Runs every detector and returns the merged, time-ordered findings.
std::vector<Finding> run_detections(event::EventStream& stream,
                                    const DetectionConfig& cfg = DetectionConfig());

}  // namespace analyze
}  // namespace csift

#endif  // CSIFT_ANALYZE_DETECTIONS_HPP
