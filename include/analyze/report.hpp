#ifndef CSIFT_ANALYZE_REPORT_HPP
#define CSIFT_ANALYZE_REPORT_HPP

#include <string>

#include "analyze/detections.hpp"
#include "analyze/statistics.hpp"
#include "analyze/timeline.hpp"
#include "event/stream.hpp"

namespace csift {
namespace analyze {

// Options controlling what a full report includes.
struct ReportOptions {
    bool include_statistics = true;
    bool include_timeline = true;
    bool include_findings = true;
    core::i64 bucket_width_seconds = 3600;
    core::i64 gap_threshold_seconds = 3600;
    core::usize top_n = 10;
};

// Computes statistics, timeline and detections for `stream` and renders a single
// textual report. The stream is sorted by time as a side effect.
std::string render_full_report(event::EventStream& stream,
                               const ReportOptions& opts = ReportOptions(),
                               const DetectionConfig& detect = DetectionConfig());

}  // namespace analyze
}  // namespace csift

#endif  // CSIFT_ANALYZE_REPORT_HPP
