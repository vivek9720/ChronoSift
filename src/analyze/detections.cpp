#include "analyze/detections.hpp"

#include <algorithm>
#include <string>
#include <unordered_map>
#include <vector>

#include "core/string_util.hpp"
#include "event/field.hpp"

namespace csift {
namespace analyze {

// ===========================================================================
// Finding kinds & rendering
// ===========================================================================

const char* finding_kind_name(FindingKind k) noexcept {
    switch (k) {
        case FindingKind::AuthBruteForce: return "auth-brute-force";
        case FindingKind::AuthSprayThenHit: return "auth-spray-then-hit";
        case FindingKind::HttpErrorBurst: return "http-error-burst";
        case FindingKind::PortOrPathScan: return "port-or-path-scan";
        case FindingKind::SeveritySpike: return "severity-spike";
        case FindingKind::RareSignature: return "rare-signature";
        case FindingKind::LogGap: return "log-gap";
    }
    return "unknown";
}

std::string Finding::render() const {
    constexpr core::usize kMaxEvidenceShown = 16;
    std::string out;
    out += "[";
    out += event::severity_name(severity);
    out += "] ";
    out += finding_kind_name(kind);
    out += ": ";
    out += core::truncate(core::sanitize_printable(title), 120);
    out += '\n';
    out += "    entity:   " +
           core::truncate(core::sanitize_printable(entity), 100) + "\n";
    out += "    count:    " + std::to_string(count) + "\n";
    out += "    window:   " + first_seen.to_iso8601() + "  ->  " +
           last_seen.to_iso8601() + "\n";
    if (!description.empty()) {
        out += "    detail:   " +
               core::truncate(core::sanitize_printable(description), 200) +
               "\n";
    }
    if (!evidence.empty()) {
        out += "    evidence: ";
        core::usize shown = 0;
        for (core::usize idx : evidence) {
            if (shown >= kMaxEvidenceShown) {
                out += "... (+" +
                       std::to_string(evidence.size() - shown) + " more)";
                break;
            }
            if (shown != 0) out += ", ";
            out += "#" + std::to_string(idx);
            ++shown;
        }
        out += '\n';
    }
    return out;
}

// ===========================================================================
// Classification helpers
// ===========================================================================

namespace {

// Case-insensitive substring search using the project string helpers. We lower
// both sides once; needles are already lowercase literals at the call site.
bool icontains(const std::string& haystack_lower, const char* needle) {
    return core::contains(haystack_lower, std::string(needle));
}

// Reads one of the common outcome-ish fields and lowercases its string form.
// Returns empty when none of the candidate keys is present.
std::string outcome_field_lower(const event::LogEvent& e) {
    static const char* kKeys[] = {"outcome", "result", "status"};
    for (const char* key : kKeys) {
        const event::FieldValue* v = e.fields.find(key);
        if (v != nullptr && !v->is_null()) {
            return core::to_lower(core::trim(v->to_string()));
        }
    }
    return std::string();
}

}  // namespace

bool is_failed_auth(const event::LogEvent& e) {
    std::string msg = core::to_lower(e.message);
    if (icontains(msg, "failed password") ||
        icontains(msg, "authentication failure") ||
        icontains(msg, "failed login") || icontains(msg, "invalid user")) {
        return true;
    }
    if (e.source == event::SourceFormat::WinEvent && e.event_id == 4625) {
        return true;
    }
    std::string outcome = outcome_field_lower(e);
    if (outcome == "failure" || outcome == "failed" || outcome == "denied") {
        return true;
    }
    return false;
}

bool is_successful_auth(const event::LogEvent& e) {
    std::string msg = core::to_lower(e.message);
    if (icontains(msg, "accepted password") ||
        icontains(msg, "session opened") ||
        icontains(msg, "login successful")) {
        return true;
    }
    if (e.source == event::SourceFormat::WinEvent && e.event_id == 4624) {
        return true;
    }
    std::string outcome = outcome_field_lower(e);
    if (outcome == "success") {
        return true;
    }
    return false;
}

std::string actor_key(const event::LogEvent& e) {
    if (!e.src_ip.empty()) return e.src_ip;
    if (!e.user.empty()) return e.user;
    return e.host;  // may be empty; callers skip empty actors
}

// ===========================================================================
// Shared sliding-window utilities
//
// Detectors operate on the already-time-sorted stream. To group by actor we
// build, per actor, a list of (micros, index) pairs in time order (the stream
// order, which is time order). A monotonic two-pointer window then finds the
// densest run. All time math is guarded against overflow.
// ===========================================================================

namespace {

// One observation for a sliding window: when it happened and where it lives.
struct Obs {
    core::i64 micros;
    core::usize index;
};

// Difference helper that never overflows (operands are real timestamps).
core::i64 micros_diff(core::i64 a, core::i64 b) noexcept {
    // a >= b expected; compute carefully to avoid signed overflow.
    if (a >= b) {
        core::u64 ua = static_cast<core::u64>(a);
        core::u64 ub = static_cast<core::u64>(b);
        core::u64 d = ua - ub;
        if (d > static_cast<core::u64>(INT64_MAX)) return INT64_MAX;
        return static_cast<core::i64>(d);
    }
    return 0;
}

// Converts a window in seconds to micros, saturating.
core::i64 window_micros(core::i64 seconds) noexcept {
    if (seconds < 0) return 0;
    if (seconds > (INT64_MAX / 1000000)) return INT64_MAX;
    return seconds * 1000000;
}

}  // namespace

// ===========================================================================
// detect_auth_bruteforce
// ===========================================================================

std::vector<Finding> detect_auth_bruteforce(const event::EventStream& s,
                                            const DetectionConfig& cfg) {
    std::vector<Finding> findings;
    const std::vector<event::LogEvent>& events = s.events();
    const core::i64 win = window_micros(cfg.bruteforce_window_seconds);

    // Per-actor record of failed-auth observations and of successful auths,
    // both in time order. We only consider events that carry a usable actor
    // key and a timestamp.
    struct ActorState {
        std::vector<Obs> failures;
        std::vector<Obs> successes;
    };
    std::unordered_map<std::string, ActorState> by_actor;

    for (core::usize i = 0; i < events.size(); ++i) {
        const event::LogEvent& e = events[i];
        if (!e.timestamp.valid) continue;
        std::string actor = actor_key(e);
        if (actor.empty()) continue;
        bool failed = is_failed_auth(e);
        bool ok = !failed && is_successful_auth(e);
        if (!failed && !ok) continue;
        ActorState& st = by_actor[actor];
        if (failed) {
            st.failures.push_back(Obs{e.timestamp.micros, i});
        } else {
            st.successes.push_back(Obs{e.timestamp.micros, i});
        }
    }

    for (auto& kv : by_actor) {
        const std::string& actor = kv.first;
        ActorState& st = kv.second;
        const std::vector<Obs>& fails = st.failures;
        if (fails.empty()) continue;

        // Sliding window over the failure timeline: for each right edge, find
        // the densest window ending there. Track the maximum count and the
        // window [first, last] that achieved/began the brute-force condition.
        core::usize left = 0;
        core::usize best_count = 0;
        core::usize best_left = 0;
        core::usize best_right = 0;
        for (core::usize right = 0; right < fails.size(); ++right) {
            while (left < right &&
                   micros_diff(fails[right].micros, fails[left].micros) > win) {
                ++left;
            }
            core::usize count = right - left + 1;
            if (count > best_count) {
                best_count = count;
                best_left = left;
                best_right = right;
            }
        }

        if (best_count >= cfg.bruteforce_min_failures &&
            cfg.bruteforce_min_failures > 0) {
            Finding f;
            f.kind = FindingKind::AuthBruteForce;
            f.severity = event::Severity::Alert;
            f.entity = actor;
            f.count = best_count;
            f.first_seen = core::Timestamp::from_micros(fails[best_left].micros);
            f.last_seen = core::Timestamp::from_micros(fails[best_right].micros);
            f.title = std::to_string(best_count) +
                      " failed authentications from " +
                      core::truncate(actor, 64) + " within " +
                      std::to_string(cfg.bruteforce_window_seconds) + "s";
            f.description =
                "repeated authentication failures concentrated in a short "
                "window, consistent with a brute-force attempt";
            // Evidence: the failure indices inside the best window, capped.
            for (core::usize j = best_left;
                 j <= best_right && f.evidence.size() < cfg.evidence_cap; ++j) {
                f.evidence.push_back(fails[j].index);
            }
            findings.push_back(std::move(f));

            // Spray-then-hit: a successful auth from the same actor occurring
            // after at least `min_failures` failures have accumulated. We find
            // the earliest success whose time is at or after the time of the
            // (min_failures)-th failure.
            if (!st.successes.empty()) {
                std::sort(st.successes.begin(), st.successes.end(),
                          [](const Obs& a, const Obs& b) {
                              return a.micros < b.micros;
                          });
                // Time of the Nth failure (1-based N = min_failures). fails is
                // already in time order (stream order).
                core::usize n = cfg.bruteforce_min_failures;
                if (n >= 1 && n <= fails.size()) {
                    core::i64 threshold_time = fails[n - 1].micros;
                    for (const Obs& succ : st.successes) {
                        if (succ.micros >= threshold_time) {
                            Finding sf;
                            sf.kind = FindingKind::AuthSprayThenHit;
                            sf.severity = event::Severity::Critical;
                            sf.entity = actor;
                            sf.count = best_count;
                            sf.first_seen = core::Timestamp::from_micros(
                                fails.front().micros);
                            sf.last_seen =
                                core::Timestamp::from_micros(succ.micros);
                            sf.title =
                                "successful authentication from " +
                                core::truncate(actor, 64) +
                                " after " + std::to_string(best_count) +
                                " failures";
                            sf.description =
                                "a login succeeded from an actor that had "
                                "already produced a brute-force burst of "
                                "failures, suggesting a compromised credential";
                            // Evidence: a few failures then the success.
                            for (core::usize j = 0;
                                 j < fails.size() &&
                                 sf.evidence.size() + 1 < cfg.evidence_cap;
                                 ++j) {
                                sf.evidence.push_back(fails[j].index);
                            }
                            sf.evidence.push_back(succ.index);
                            findings.push_back(std::move(sf));
                            break;
                        }
                    }
                }
            }
        }
    }

    return findings;
}

// ===========================================================================
// detect_http_error_bursts
// ===========================================================================

std::vector<Finding> detect_http_error_bursts(const event::EventStream& s,
                                              const DetectionConfig& cfg) {
    std::vector<Finding> findings;
    const std::vector<event::LogEvent>& events = s.events();
    const core::i64 win = window_micros(cfg.http_error_window_seconds);

    std::unordered_map<std::string, std::vector<Obs>> by_actor;
    for (core::usize i = 0; i < events.size(); ++i) {
        const event::LogEvent& e = events[i];
        if (!e.timestamp.valid) continue;
        if (e.http_status < 400 || e.http_status >= 600) continue;  // 4xx/5xx
        std::string actor = actor_key(e);
        if (actor.empty()) continue;
        by_actor[actor].push_back(Obs{e.timestamp.micros, i});
    }

    for (auto& kv : by_actor) {
        const std::string& actor = kv.first;
        const std::vector<Obs>& obs = kv.second;
        if (obs.empty()) continue;

        core::usize left = 0;
        core::usize best_count = 0;
        core::usize best_left = 0;
        core::usize best_right = 0;
        for (core::usize right = 0; right < obs.size(); ++right) {
            while (left < right &&
                   micros_diff(obs[right].micros, obs[left].micros) > win) {
                ++left;
            }
            core::usize count = right - left + 1;
            if (count > best_count) {
                best_count = count;
                best_left = left;
                best_right = right;
            }
        }

        if (cfg.http_error_min > 0 && best_count >= cfg.http_error_min) {
            Finding f;
            f.kind = FindingKind::HttpErrorBurst;
            f.severity = event::Severity::Warning;
            f.entity = actor;
            f.count = best_count;
            f.first_seen = core::Timestamp::from_micros(obs[best_left].micros);
            f.last_seen = core::Timestamp::from_micros(obs[best_right].micros);
            f.title = std::to_string(best_count) +
                      " HTTP 4xx/5xx responses to " +
                      core::truncate(actor, 64) + " within " +
                      std::to_string(cfg.http_error_window_seconds) + "s";
            f.description =
                "a burst of client/server error responses to one client, which "
                "can indicate scanning, fuzzing, or a failing integration";
            for (core::usize j = best_left;
                 j <= best_right && f.evidence.size() < cfg.evidence_cap; ++j) {
                f.evidence.push_back(obs[j].index);
            }
            findings.push_back(std::move(f));
        }
    }
    return findings;
}

// ===========================================================================
// detect_scans
// ===========================================================================

std::vector<Finding> detect_scans(const event::EventStream& s,
                                  const DetectionConfig& cfg) {
    std::vector<Finding> findings;
    const std::vector<event::LogEvent>& events = s.events();
    const core::i64 win = window_micros(cfg.scan_window_seconds);

    // For scans we group by actor and, within a time window, count the number
    // of DISTINCT targets touched. The target is the http_path when present,
    // otherwise the destination port. Each observation carries its target.
    struct ScanObs {
        core::i64 micros;
        core::usize index;
        std::string target;
    };
    std::unordered_map<std::string, std::vector<ScanObs>> by_actor;

    for (core::usize i = 0; i < events.size(); ++i) {
        const event::LogEvent& e = events[i];
        if (!e.timestamp.valid) continue;
        std::string actor = actor_key(e);
        if (actor.empty()) continue;
        std::string target;
        if (!e.http_path.empty()) {
            target = "path:" + e.http_path;
        } else if (e.dst_port != 0) {
            target = "port:" + std::to_string(e.dst_port);
        } else {
            continue;  // nothing scan-relevant on this event
        }
        by_actor[actor].push_back(ScanObs{e.timestamp.micros, i, std::move(target)});
    }

    for (auto& kv : by_actor) {
        const std::string& actor = kv.first;
        const std::vector<ScanObs>& obs = kv.second;
        if (obs.empty()) continue;

        // Sliding window with a distinct-target count maintained incrementally
        // via a frequency map keyed on the target string.
        std::unordered_map<std::string, core::usize> freq;
        core::usize left = 0;
        core::usize best_distinct = 0;
        core::usize best_left = 0;
        core::usize best_right = 0;
        for (core::usize right = 0; right < obs.size(); ++right) {
            ++freq[obs[right].target];
            while (left < right &&
                   micros_diff(obs[right].micros, obs[left].micros) > win) {
                auto it = freq.find(obs[left].target);
                if (it != freq.end()) {
                    if (it->second <= 1) {
                        freq.erase(it);
                    } else {
                        --it->second;
                    }
                }
                ++left;
            }
            core::usize distinct = freq.size();
            if (distinct > best_distinct) {
                best_distinct = distinct;
                best_left = left;
                best_right = right;
            }
        }

        if (cfg.scan_distinct_min > 0 && best_distinct >= cfg.scan_distinct_min) {
            Finding f;
            f.kind = FindingKind::PortOrPathScan;
            f.severity = event::Severity::Warning;
            f.entity = actor;
            f.count = best_distinct;
            f.first_seen = core::Timestamp::from_micros(obs[best_left].micros);
            f.last_seen = core::Timestamp::from_micros(obs[best_right].micros);
            f.title = core::truncate(actor, 64) + " touched " +
                      std::to_string(best_distinct) +
                      " distinct targets within " +
                      std::to_string(cfg.scan_window_seconds) + "s";
            f.description =
                "one source reached many distinct paths/ports in a short "
                "window, consistent with enumeration or scanning";
            // Evidence: indices spanning the densest window, capped.
            for (core::usize j = best_left;
                 j <= best_right && f.evidence.size() < cfg.evidence_cap; ++j) {
                f.evidence.push_back(obs[j].index);
            }
            findings.push_back(std::move(f));
        }
    }
    return findings;
}

// ===========================================================================
// detect_severity_spikes
// ===========================================================================

std::vector<Finding> detect_severity_spikes(const event::EventStream& s,
                                            const DetectionConfig& cfg) {
    std::vector<Finding> findings;
    const std::vector<event::LogEvent>& events = s.events();
    const core::i64 win = window_micros(cfg.severity_spike_window_seconds);

    // Global (not per-actor) sliding window over Error-or-worse events.
    std::vector<Obs> obs;
    obs.reserve(events.size());
    for (core::usize i = 0; i < events.size(); ++i) {
        const event::LogEvent& e = events[i];
        if (!e.timestamp.valid) continue;
        if (!event::at_least_as_severe(e.severity, event::Severity::Error)) {
            continue;
        }
        obs.push_back(Obs{e.timestamp.micros, i});
    }
    if (obs.empty()) return findings;

    core::usize left = 0;
    core::usize best_count = 0;
    core::usize best_left = 0;
    core::usize best_right = 0;
    for (core::usize right = 0; right < obs.size(); ++right) {
        while (left < right &&
               micros_diff(obs[right].micros, obs[left].micros) > win) {
            ++left;
        }
        core::usize count = right - left + 1;
        if (count > best_count) {
            best_count = count;
            best_left = left;
            best_right = right;
        }
    }

    if (cfg.severity_spike_min > 0 && best_count >= cfg.severity_spike_min) {
        Finding f;
        f.kind = FindingKind::SeveritySpike;
        f.severity = event::Severity::Error;
        f.entity = "(global)";
        f.count = best_count;
        f.first_seen = core::Timestamp::from_micros(obs[best_left].micros);
        f.last_seen = core::Timestamp::from_micros(obs[best_right].micros);
        f.title = std::to_string(best_count) +
                  " error-or-worse events within " +
                  std::to_string(cfg.severity_spike_window_seconds) + "s";
        f.description =
            "a concentrated burst of high-severity events, which may signal an "
            "incident, outage, or active attack";
        for (core::usize j = best_left;
             j <= best_right && f.evidence.size() < cfg.evidence_cap; ++j) {
            f.evidence.push_back(obs[j].index);
        }
        findings.push_back(std::move(f));
    }
    return findings;
}

// ===========================================================================
// detect_rare_signatures
// ===========================================================================

std::vector<Finding> detect_rare_signatures(const event::EventStream& s,
                                            const DetectionConfig& cfg) {
    std::vector<Finding> findings;
    const std::vector<event::LogEvent>& events = s.events();

    // Count occurrences per signature and remember the indices (capped) and the
    // first/last time each was seen. We keep insertion order so output is
    // deterministic regardless of hash ordering.
    struct SigInfo {
        core::usize order;            // first-seen ordinal, for stable output
        core::usize count = 0;
        std::vector<core::usize> indices;
        core::Timestamp first;
        core::Timestamp last;
    };
    std::unordered_map<std::string, SigInfo> by_sig;
    core::usize next_order = 0;

    for (core::usize i = 0; i < events.size(); ++i) {
        const event::LogEvent& e = events[i];
        std::string sig = e.signature();
        auto it = by_sig.find(sig);
        if (it == by_sig.end()) {
            SigInfo info;
            info.order = next_order++;
            it = by_sig.emplace(std::move(sig), std::move(info)).first;
        }
        SigInfo& info = it->second;
        if (info.count < (core::usize)-1) ++info.count;
        if (info.indices.size() < cfg.evidence_cap) {
            info.indices.push_back(i);
        }
        if (e.timestamp.valid) {
            if (!info.first.valid || e.timestamp.micros < info.first.micros) {
                info.first = e.timestamp;
            }
            if (!info.last.valid || e.timestamp.micros > info.last.micros) {
                info.last = e.timestamp;
            }
        }
    }

    // Collect rare signatures (count in 1..rare_signature_max) and emit one
    // finding each, ordered by first-seen ordinal for determinism.
    std::vector<std::pair<core::usize, const std::string*>> rare;  // (order, key)
    for (const auto& kv : by_sig) {
        const SigInfo& info = kv.second;
        if (info.count >= 1 && info.count <= cfg.rare_signature_max) {
            rare.emplace_back(info.order, &kv.first);
        }
    }
    std::sort(rare.begin(), rare.end(),
              [](const std::pair<core::usize, const std::string*>& a,
                 const std::pair<core::usize, const std::string*>& b) {
                  return a.first < b.first;
              });

    for (const auto& r : rare) {
        const std::string& sig = *r.second;
        const SigInfo& info = by_sig.at(sig);
        Finding f;
        f.kind = FindingKind::RareSignature;
        f.severity = event::Severity::Notice;
        f.entity = sig;
        f.count = info.count;
        f.first_seen = info.first;
        f.last_seen = info.last;
        f.title = "rare event signature seen " + std::to_string(info.count) +
                  " time(s): " + core::truncate(sig, 80);
        f.description =
            "an event type that occurs only a handful of times across the "
            "whole stream, which is worth a human glance";
        f.evidence = info.indices;  // already capped during accumulation
        findings.push_back(std::move(f));
    }
    return findings;
}

// ===========================================================================
// run_detections
// ===========================================================================

std::vector<Finding> run_detections(event::EventStream& stream,
                                    const DetectionConfig& cfg) {
    // Detectors assume time order; enforce it once up front.
    stream.sort_by_time();

    std::vector<Finding> all;
    auto append = [&all](std::vector<Finding> v) {
        for (auto& f : v) all.push_back(std::move(f));
    };

    append(detect_auth_bruteforce(stream, cfg));
    append(detect_http_error_bursts(stream, cfg));
    append(detect_scans(stream, cfg));
    append(detect_severity_spikes(stream, cfg));
    append(detect_rare_signatures(stream, cfg));

    // Order findings by first_seen (invalid timestamps sort first per the
    // Timestamp comparator), then by kind name and entity for stability.
    std::stable_sort(all.begin(), all.end(),
                     [](const Finding& a, const Finding& b) {
                         if (!(a.first_seen == b.first_seen)) {
                             return a.first_seen < b.first_seen;
                         }
                         int kc = std::string(finding_kind_name(a.kind))
                                      .compare(finding_kind_name(b.kind));
                         if (kc != 0) return kc < 0;
                         return a.entity < b.entity;
                     });
    return all;
}

}  // namespace analyze
}  // namespace csift
