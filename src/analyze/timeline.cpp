#include "analyze/timeline.hpp"

#include <algorithm>
#include <string>
#include <vector>

#include "core/string_util.hpp"
#include "event/event.hpp"

namespace csift {
namespace analyze {

// ---------------------------------------------------------------------------
// Timeline construction.
//
// We collect the valid timestamps (in micros) of every event together with a
// flag of whether the event was at Error-or-worse severity, sort by time, then
// walk them into fixed-width buckets aligned to the earliest timestamp. Gaps
// longer than the threshold are recorded between consecutive events.
//
// All of the time arithmetic is on i64 micros from untrusted sources, so every
// subtraction/addition is guarded against overflow. Bucket counts are bounded
// so a pathological (huge span, tiny width) configuration cannot allocate an
// unbounded vector.
// ---------------------------------------------------------------------------

namespace {

// Hard cap on the number of histogram buckets we will allocate regardless of
// span/width, to defend against (enormous span / 1s width) blowups.
constexpr core::usize kMaxBuckets = 100000;
// Hard cap on recorded gaps so a stream that alternates huge jumps cannot grow
// the gap list without bound.
constexpr core::usize kMaxGaps = 4096;

struct TimedSample {
    core::i64 micros;
    bool error;
};

// Saturating signed addition for i64; clamps instead of overflowing.
core::i64 sat_add(core::i64 a, core::i64 b) noexcept {
    if (b > 0 && a > (INT64_MAX - b)) return INT64_MAX;
    if (b < 0 && a < (INT64_MIN - b)) return INT64_MIN;
    return a + b;
}

}  // namespace

core::usize Timeline::peak_bucket() const {
    if (buckets.empty()) return buckets.size();
    core::usize best = 0;
    for (core::usize i = 1; i < buckets.size(); ++i) {
        if (buckets[i].count > buckets[best].count) best = i;
    }
    return best;
}

std::string Timeline::render() const {
    constexpr core::usize kMaxRenderedBuckets = 200;
    std::string out;
    out += "Bucket width (seconds): " + std::to_string(bucket_width_seconds) +
           "\n";
    out += "Buckets:                " + std::to_string(buckets.size()) + "\n";
    out += "Untimed events:         " + std::to_string(untimed_events) + "\n";
    out += "Gaps recorded:          " + std::to_string(gaps.size()) + "\n";

    core::usize peak = peak_bucket();
    if (peak < buckets.size()) {
        out += "Peak bucket:            " + buckets[peak].start.to_iso8601() +
               "  (" + std::to_string(buckets[peak].count) + " events)\n";
    }
    out += "\n";

    if (buckets.empty()) {
        out += "(no timed events)\n";
    } else {
        out += "Histogram:\n";
        core::usize shown = 0;
        for (const TimelineBucket& b : buckets) {
            if (shown >= kMaxRenderedBuckets) {
                out += "    ... (" +
                       std::to_string(buckets.size() - shown) +
                       " more buckets)\n";
                break;
            }
            out += "    ";
            out += b.start.to_iso8601();
            out += "  count=";
            out += std::to_string(b.count);
            out += "  err=";
            out += std::to_string(b.error_or_worse);
            out += '\n';
            ++shown;
        }
    }

    if (!gaps.empty()) {
        out += "\nGaps (> threshold):\n";
        core::usize shown = 0;
        for (const TimelineGap& g : gaps) {
            if (shown >= kMaxRenderedBuckets) {
                out += "    ... (" + std::to_string(gaps.size() - shown) +
                       " more gaps)\n";
                break;
            }
            out += "    ";
            out += g.before.to_iso8601();
            out += "  ->  ";
            out += g.after.to_iso8601();
            out += "   (";
            out += std::to_string(g.seconds);
            out += "s)\n";
            ++shown;
        }
    }
    return out;
}

Timeline build_timeline(const event::EventStream& stream,
                        core::i64 bucket_width_seconds,
                        core::i64 gap_threshold_seconds) {
    Timeline tl;
    // Clamp the bucket width to a sane minimum of 1 second; a non-positive
    // width would make the bucketing math meaningless / divide-by-zero.
    if (bucket_width_seconds < 1) bucket_width_seconds = 1;
    tl.bucket_width_seconds = bucket_width_seconds;

    const std::vector<event::LogEvent>& events = stream.events();

    // Collect timed samples and count untimed events.
    std::vector<TimedSample> samples;
    samples.reserve(events.size());
    for (const event::LogEvent& e : events) {
        if (!e.timestamp.valid) {
            ++tl.untimed_events;
            continue;
        }
        TimedSample s;
        s.micros = e.timestamp.micros;
        s.error = event::at_least_as_severe(e.severity, event::Severity::Error);
        samples.push_back(s);
    }

    if (samples.empty()) return tl;

    std::sort(samples.begin(), samples.end(),
              [](const TimedSample& a, const TimedSample& b) {
                  return a.micros < b.micros;
              });

    const core::i64 earliest_us = samples.front().micros;
    // Width in micros, guarded: bucket_width_seconds is >= 1 here.
    core::i64 width_us;
    if (bucket_width_seconds > (INT64_MAX / 1000000)) {
        width_us = INT64_MAX;
    } else {
        width_us = bucket_width_seconds * 1000000;
    }
    if (width_us < 1) width_us = 1;

    // Gap threshold in micros (guarded). A non-positive threshold disables
    // gap detection (every interval would qualify otherwise, which is noise).
    bool gaps_enabled = gap_threshold_seconds > 0;
    core::i64 gap_us = 0;
    if (gaps_enabled) {
        if (gap_threshold_seconds > (INT64_MAX / 1000000)) {
            gap_us = INT64_MAX;
        } else {
            gap_us = gap_threshold_seconds * 1000000;
        }
    }

    // Build buckets in a single pass. Because samples are sorted, each sample's
    // bucket index is monotonically non-decreasing, so we can append.
    for (core::usize i = 0; i < samples.size(); ++i) {
        const TimedSample& s = samples[i];

        // bucket index = (micros - earliest) / width_us, guarded.
        core::i64 delta = s.micros - earliest_us;  // >= 0 since sorted
        if (delta < 0) delta = 0;  // paranoia against overflow in subtraction
        core::usize bucket_index =
            static_cast<core::usize>(delta / width_us);
        if (bucket_index > kMaxBuckets) bucket_index = kMaxBuckets;

        // Grow the bucket vector up to (and including) bucket_index, capping at
        // kMaxBuckets total entries. Each newly created bucket gets its aligned
        // start time. Overshooting past the cap folds extra samples into the
        // last bucket so totals stay accurate even if resolution is lost.
        while (tl.buckets.size() <= bucket_index &&
               tl.buckets.size() < kMaxBuckets) {
            TimelineBucket b;
            core::i64 offset =
                static_cast<core::i64>(tl.buckets.size());
            // start = earliest_us + offset * width_us, all guarded.
            core::i64 step = (offset > (INT64_MAX / width_us))
                                 ? INT64_MAX
                                 : offset * width_us;
            b.start = core::Timestamp::from_micros(sat_add(earliest_us, step));
            tl.buckets.push_back(b);
        }
        core::usize target =
            tl.buckets.empty() ? 0
                               : (bucket_index < tl.buckets.size()
                                      ? bucket_index
                                      : tl.buckets.size() - 1);
        TimelineBucket& b = tl.buckets[target];
        ++b.count;
        if (s.error) ++b.error_or_worse;

        // Gap detection between consecutive (sorted) samples.
        if (gaps_enabled && i > 0 && tl.gaps.size() < kMaxGaps) {
            core::i64 prev = samples[i - 1].micros;
            // interval = s.micros - prev, both valid; sorted so >= 0.
            core::i64 interval = s.micros - prev;
            if (interval >= 0 && interval > gap_us) {
                TimelineGap g;
                g.before = core::Timestamp::from_micros(prev);
                g.after = core::Timestamp::from_micros(s.micros);
                g.seconds = interval / 1000000;
                tl.gaps.push_back(g);
            }
        }
    }

    return tl;
}

}  // namespace analyze
}  // namespace csift
