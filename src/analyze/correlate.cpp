#include "analyze/correlate.hpp"

#include <algorithm>
#include <string>
#include <unordered_map>
#include <vector>

#include "core/string_util.hpp"
#include "event/event.hpp"

namespace csift {
namespace analyze {

// ---------------------------------------------------------------------------
// Sessionization.
//
// Events are grouped by the chosen key (source IP, user, or host). Within each
// group, the time-ordered events are split into sessions wherever the gap
// between consecutive events exceeds `idle_gap_seconds`. Only timed events with
// a non-empty key participate.
// ---------------------------------------------------------------------------

namespace {

// Caps to keep memory bounded on adversarial inputs: a maximum number of
// distinct session keys we will track, and a maximum number of sessions we will
// emit overall.
constexpr core::usize kMaxKeys = 100000;
constexpr core::usize kMaxSessions = 200000;

const std::string& key_for(const event::LogEvent& e, SessionKey key) {
    switch (key) {
        case SessionKey::SourceIp: return e.src_ip;
        case SessionKey::User: return e.user;
        case SessionKey::Host: return e.host;
    }
    return e.host;
}

}  // namespace

core::i64 Session::duration_seconds() const {
    if (!start.valid || !end.valid) return 0;
    if (end.micros < start.micros) return 0;  // guard against bad ordering
    core::i64 d = end.micros - start.micros;
    if (d < 0) return 0;
    return d / 1000000;
}

std::vector<Session> build_sessions(const event::EventStream& stream,
                                    SessionKey key, core::i64 idle_gap_seconds) {
    std::vector<Session> sessions;
    const std::vector<event::LogEvent>& events = stream.events();

    // Idle gap in micros, saturating; a non-positive gap means "never split"
    // is wrong (it would merge everything) — instead treat <=0 as 0 so any
    // positive inter-event gap starts a new session only when strictly greater.
    core::i64 gap_us;
    if (idle_gap_seconds < 0) idle_gap_seconds = 0;
    if (idle_gap_seconds > (INT64_MAX / 1000000)) {
        gap_us = INT64_MAX;
    } else {
        gap_us = idle_gap_seconds * 1000000;
    }

    // Collect, per key, the indices of its timed events in time order. We sort
    // each key's events by timestamp explicitly rather than assuming the stream
    // is pre-sorted (the header says it need not be).
    struct Sample {
        core::i64 micros;
        core::usize index;
    };
    std::unordered_map<std::string, std::vector<Sample>> groups;

    for (core::usize i = 0; i < events.size(); ++i) {
        const event::LogEvent& e = events[i];
        if (!e.timestamp.valid) continue;
        const std::string& k = key_for(e, key);
        if (k.empty()) continue;
        auto it = groups.find(k);
        if (it == groups.end()) {
            if (groups.size() >= kMaxKeys) continue;  // bound key cardinality
            it = groups.emplace(k, std::vector<Sample>()).first;
        }
        it->second.push_back(Sample{e.timestamp.micros, i});
    }

    for (auto& kv : groups) {
        const std::string& k = kv.first;
        std::vector<Sample>& samples = kv.second;
        if (samples.empty()) continue;
        std::stable_sort(samples.begin(), samples.end(),
                         [](const Sample& a, const Sample& b) {
                             return a.micros < b.micros;
                         });

        Session cur;
        cur.key = k;
        bool open = false;
        core::i64 prev_us = 0;
        for (const Sample& sm : samples) {
            if (!open) {
                cur = Session();
                cur.key = k;
                cur.start = core::Timestamp::from_micros(sm.micros);
                cur.end = cur.start;
                cur.events.push_back(sm.index);
                open = true;
                prev_us = sm.micros;
                continue;
            }
            // Gap from previous event in this group (samples sorted => >= 0).
            core::i64 delta = sm.micros - prev_us;
            if (delta < 0) delta = 0;
            if (delta > gap_us) {
                // Close current session and start a new one.
                if (sessions.size() < kMaxSessions) {
                    sessions.push_back(std::move(cur));
                }
                cur = Session();
                cur.key = k;
                cur.start = core::Timestamp::from_micros(sm.micros);
                cur.end = cur.start;
                cur.events.push_back(sm.index);
            } else {
                cur.end = core::Timestamp::from_micros(sm.micros);
                cur.events.push_back(sm.index);
            }
            prev_us = sm.micros;
        }
        if (open && sessions.size() < kMaxSessions) {
            sessions.push_back(std::move(cur));
        }
    }

    // Order sessions by start time (then key for stability).
    std::sort(sessions.begin(), sessions.end(),
              [](const Session& a, const Session& b) {
                  if (!(a.start == b.start)) return a.start < b.start;
                  return a.key < b.key;
              });

    return sessions;
}

std::string render_sessions(const std::vector<Session>& sessions,
                            const event::EventStream& stream,
                            core::usize limit) {
    (void)stream;  // events are referenced by index; not needed for the summary
    std::string out;
    out += "Sessions: " + std::to_string(sessions.size()) + "\n";
    if (sessions.empty()) {
        out += "(none)\n";
        return out;
    }
    out += "\n";
    core::usize shown = 0;
    for (const Session& s : sessions) {
        if (limit != 0 && shown >= limit) {
            out += "... (" + std::to_string(sessions.size() - shown) +
                   " more sessions)\n";
            break;
        }
        out += "  key=" + core::truncate(core::sanitize_printable(s.key), 80) +
               "\n";
        out += "    start:    " + s.start.to_iso8601() + "\n";
        out += "    end:      " + s.end.to_iso8601() + "\n";
        out += "    duration: " + std::to_string(s.duration_seconds()) + "s\n";
        out += "    events:   " + std::to_string(s.events.size()) + "\n";
        ++shown;
    }
    return out;
}

}  // namespace analyze
}  // namespace csift
