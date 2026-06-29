#include "analyze/report.hpp"

#include <string>
#include <vector>

#include "analyze/detections.hpp"
#include "analyze/statistics.hpp"
#include "analyze/timeline.hpp"
#include "event/severity.hpp"

namespace csift {
namespace analyze {

// ---------------------------------------------------------------------------
// Full report rendering.
//
// Each requested section is computed and rendered, then concatenated under a
// banner header. The stream is sorted by time as a side effect of running the
// detectors (run_detections sorts it); we run detections last so the statistics
// and timeline see the same (now sorted) data without an extra sort pass when
// findings are disabled.
// ---------------------------------------------------------------------------

namespace {

// Emits a boxed section header to visually separate report sections.
void section_header(std::string& out, const char* title) {
    out += "========================================================\n";
    out += "  ";
    out += title;
    out += "\n";
    out += "========================================================\n";
}

}  // namespace

std::string render_full_report(event::EventStream& stream,
                               const ReportOptions& opts,
                               const DetectionConfig& detect) {
    std::string out;

    section_header(out, "ChronoSift Report");
    out += "Events in stream: " + std::to_string(stream.size()) + "\n";
    out += "Timed events:     " + std::to_string(stream.timed_count()) + "\n";
    out += "\n";

    if (opts.include_statistics) {
        section_header(out, "Statistics");
        StreamStatistics stats = compute_statistics(stream);
        out += stats.render();
        out += "\n";
    }

    if (opts.include_timeline) {
        section_header(out, "Timeline");
        Timeline tl = build_timeline(stream, opts.bucket_width_seconds,
                                     opts.gap_threshold_seconds);
        out += tl.render();
        out += "\n";
    }

    if (opts.include_findings) {
        section_header(out, "Findings");
        // run_detections sorts the stream by time as a documented side effect.
        std::vector<Finding> findings = run_detections(stream, detect);
        out += "Total findings: " + std::to_string(findings.size()) + "\n\n";
        if (findings.empty()) {
            out += "(no findings)\n";
        } else {
            // Cap the number of rendered findings to keep output bounded; the
            // count above still reflects the true total.
            const core::usize cap = opts.top_n != 0 ? (opts.top_n * 10)
                                                    : findings.size();
            core::usize shown = 0;
            for (const Finding& f : findings) {
                if (shown >= cap) {
                    out += "... (" + std::to_string(findings.size() - shown) +
                           " more findings)\n";
                    break;
                }
                out += f.render();
                out += "\n";
                ++shown;
            }
        }
        out += "\n";
    }

    return out;
}

}  // namespace analyze
}  // namespace csift
