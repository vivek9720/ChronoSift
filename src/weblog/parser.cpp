#include "weblog/parser.hpp"

#include <string>
#include <vector>

#include "core/string_util.hpp"
#include "core/time_util.hpp"
#include "event/field.hpp"
#include "event/severity.hpp"

// Parser for NCSA Common Log Format and the Apache "Combined" extension.
//
//   Common:   host ident authuser [date] "request" status bytes
//   Combined: host ident authuser [date] "request" status bytes "referer" "ua"
//
// The interesting part is tokenization: a single line mixes three quoting
// conventions (bare tokens, "double-quoted" strings, and [bracketed] dates),
// and real-world logs are routinely malformed (unbalanced quotes, missing
// fields, binary noise injected via the user-agent or request line). Every
// routine here is written to be total over arbitrary byte input: it bounds
// every index, never reads past the end of a string, and degrades to a
// best-effort partial parse rather than crashing. The fuzz harness at the
// bottom is run under ASan/UBSan and must never report a fault.
namespace csift {
namespace weblog {

namespace {

// A log field of '-' is the conventional CLF placeholder for "absent". For the
// fields where that applies (ident, authuser, referer, user-agent, bytes) we
// normalise it to an empty string so downstream code does not special-case the
// dash.
bool is_dash_placeholder(const std::string& s) {
    return s.size() == 1 && s[0] == '-';
}

// Appends a byte to `field`, but only while the field is under the configured
// byte cap. Once the cap is reached further bytes are dropped. This keeps a
// single hostile field (e.g. a megabyte user-agent) from ballooning memory
// while still letting tokenization advance to the field's natural terminator.
// `truncated` records whether anything was dropped, for diagnostics.
void push_bounded(std::string& field, char c, core::usize max_bytes,
                  bool& truncated) {
    if (max_bytes == 0) {
        // A zero cap means "no content allowed"; treat everything as dropped.
        truncated = true;
        return;
    }
    if (field.size() < max_bytes) {
        field.push_back(c);
    } else {
        truncated = true;
    }
}

// HTTP status -> normalized event severity. 5xx server errors are Error, 4xx
// client errors are Warning, and everything else (1xx/2xx/3xx, or an
// unrecognised code) is Informational. An out-of-range / zero status falls
// through to Informational, which is the safe default for "we could not tell".
event::Severity severity_from_status(core::u32 status) {
    if (status >= 500 && status <= 599) return event::Severity::Error;
    if (status >= 400 && status <= 499) return event::Severity::Warning;
    return event::Severity::Informational;
}

}  // namespace

// ---------------------------------------------------------------------------
// Tokenization
// ---------------------------------------------------------------------------

std::vector<std::string> tokenize_fields(const std::string& line,
                                         const ParseOptions& opts) {
    std::vector<std::string> fields;

    // Bound the work up front: never inspect more than max_line_bytes of the
    // input even if the caller handed us something larger. A zero limit means
    // "no parsing".
    const core::usize limit =
        line.size() < opts.max_line_bytes ? line.size() : opts.max_line_bytes;
    const core::usize max_field = opts.max_field_bytes;

    core::usize i = 0;
    while (i < limit) {
        // Skip any run of whitespace separating top-level fields.
        while (i < limit && core::is_space(line[i])) {
            ++i;
        }
        if (i >= limit) {
            break;
        }

        char open = line[i];
        std::string field;
        bool truncated = false;

        if (open == '"') {
            // Double-quoted string. The opening quote is consumed and not kept.
            // A backslash escapes the next byte (canonically '\"' and '\\', but
            // we pass any escaped byte through literally so binary noise inside
            // the quotes is preserved rather than mis-parsed). The closing quote
            // terminates the field. If the closing quote is never found (an
            // unbalanced quote, common in truncated logs) we consume to end of
            // line and still emit what we captured.
            ++i;  // consume opening quote
            while (i < limit) {
                char c = line[i];
                if (c == '\\') {
                    // Escape: take the next byte verbatim if one exists. A
                    // trailing backslash at end-of-input has nothing to escape,
                    // so we keep the backslash itself.
                    if (i + 1 < limit) {
                        push_bounded(field, line[i + 1], max_field, truncated);
                        i += 2;
                    } else {
                        push_bounded(field, c, max_field, truncated);
                        i += 1;
                    }
                    continue;
                }
                if (c == '"') {
                    ++i;  // consume closing quote
                    break;
                }
                push_bounded(field, c, max_field, truncated);
                ++i;
            }
            fields.push_back(std::move(field));
        } else if (open == '[') {
            // Bracketed timestamp. The brackets are consumed and not kept. CLF
            // dates contain a space ("10/Oct/2000:13:55:36 -0700"), which is the
            // whole reason they are bracketed, so we read until the matching
            // ']'. If there is no closing bracket we consume to end of line.
            ++i;  // consume '['
            while (i < limit) {
                char c = line[i];
                if (c == ']') {
                    ++i;  // consume ']'
                    break;
                }
                push_bounded(field, c, max_field, truncated);
                ++i;
            }
            fields.push_back(std::move(field));
        } else {
            // Bare token: everything up to the next whitespace. Quotes and
            // brackets appearing mid-token are kept literally (they only have
            // special meaning at a field boundary).
            while (i < limit && !core::is_space(line[i])) {
                push_bounded(field, line[i], max_field, truncated);
                ++i;
            }
            fields.push_back(std::move(field));
        }
    }

    return fields;
}

// ---------------------------------------------------------------------------
// Request line
// ---------------------------------------------------------------------------

RequestLine parse_request_line(const std::string& text) {
    RequestLine out;

    // The canonical form is exactly three space-separated parts:
    //   METHOD SP target SP HTTP-version
    // We split on runs of whitespace. If we get exactly three parts the line is
    // well-formed; otherwise it is marked invalid but we still salvage whatever
    // parts we found (e.g. a bare method, or a method+target with no version)
    // so the event still carries useful context.
    std::vector<std::string> parts = core::split_whitespace(text);

    if (parts.size() == 3) {
        out.method = std::move(parts[0]);
        out.target = std::move(parts[1]);
        out.version = std::move(parts[2]);
        out.valid = true;
        return out;
    }

    // Best-effort salvage for the malformed cases.
    out.valid = false;
    if (parts.size() >= 1) {
        out.method = std::move(parts[0]);
    }
    if (parts.size() == 2) {
        // Two parts: almost certainly "METHOD target" with the version dropped.
        out.target = std::move(parts[1]);
    } else if (parts.size() > 3) {
        // More than three parts: a target containing unencoded spaces is the
        // usual culprit. Treat the last part as the version (if it looks like
        // one) and everything between method and version as the target so we
        // don't lose the path.
        out.target = core::join(
            std::vector<std::string>(parts.begin() + 1, parts.end() - 1), " ");
        out.version = parts.back();
    }
    // parts.size() == 0 leaves everything empty, which is correct for an empty
    // request line.
    return out;
}

// ---------------------------------------------------------------------------
// Single line -> AccessRecord
// ---------------------------------------------------------------------------

core::Result<AccessRecord> parse_line(const std::string& line,
                                      const ParseOptions& opts) {
    std::vector<std::string> fields = tokenize_fields(line, opts);

    // The smallest structure we will accept is the five fields that make a
    // recognisable request record: host, (ident/user collapsed away in broken
    // logs), date, request, status. Fewer than five fields means there is no
    // plausible CLF structure to map, so we report Malformed and let the caller
    // emit a best-effort raw event instead.
    if (fields.size() < 5) {
        return core::Result<AccessRecord>::failure(
            core::StatusCode::Malformed,
            "too few fields for an access-log record");
    }

    AccessRecord rec;

    // Field layout (0-based) for the two canonical shapes:
    //   Common (7):   0 host  1 ident  2 user  3 time  4 request  5 status  6 bytes
    //   Combined (9): ... + 7 referer  8 user-agent
    //
    // Real logs drift from these counts. We pick a layout by field count,
    // tolerating extras/missing entries: 9+ fields read as Combined, otherwise
    // we read the Common positions and leave the Combined-only fields empty.
    // Indices are only ever read after an explicit size check, so a short field
    // vector can never cause an out-of-bounds access.
    const core::usize n = fields.size();
    const bool combined = (n >= 9);
    rec.format = combined ? WebLogFormat::Combined : WebLogFormat::Common;

    // host / client IP (field 0 always exists since n >= 5).
    rec.client_ip = fields[0];

    // ident (field 1): '-' placeholder normalises to empty.
    if (n >= 2 && !is_dash_placeholder(fields[1])) {
        rec.ident = fields[1];
    }

    // authenticated user (field 2): '-' placeholder normalises to empty.
    if (n >= 3 && !is_dash_placeholder(fields[2])) {
        rec.user = fields[2];
    }

    // timestamp (field 3). parse_clf_time returns an invalid Timestamp on
    // failure, which we keep as-is (the record is still useful without a time).
    if (n >= 4) {
        rec.time = core::parse_clf_time(fields[3]);
    }

    // request line (field 4).
    if (n >= 5) {
        rec.request = parse_request_line(fields[4]);
    }

    // status code (field 5): parse as u32 with overflow protection. A value
    // that does not parse or overflows u32 leaves status at 0.
    if (n >= 6) {
        core::u64 status64 = 0;
        if (core::parse_u64(fields[5], status64) && status64 <= 0xFFFFFFFFull) {
            rec.status = static_cast<core::u32>(status64);
        }
    }

    // response byte count (field 6): a '-' placeholder means "size unknown".
    // Any other non-numeric value also leaves bytes_known false.
    if (n >= 7) {
        const std::string& bytes_field = fields[6];
        if (!is_dash_placeholder(bytes_field)) {
            core::u64 parsed = 0;
            if (core::parse_u64(bytes_field, parsed)) {
                rec.bytes = parsed;
                rec.bytes_known = true;
            }
        }
    }

    // Combined-only fields: referer (7) and user-agent (8), each with the dash
    // placeholder normalised to empty.
    if (combined) {
        if (n >= 8 && !is_dash_placeholder(fields[7])) {
            rec.referer = fields[7];
        }
        if (n >= 9 && !is_dash_placeholder(fields[8])) {
            rec.user_agent = fields[8];
        }
    }

    return core::Result<AccessRecord>(std::move(rec));
}

// ---------------------------------------------------------------------------
// AccessRecord -> LogEvent
// ---------------------------------------------------------------------------

event::LogEvent to_event(const AccessRecord& rec) {
    event::LogEvent ev;

    ev.source = event::SourceFormat::WebAccess;
    ev.severity = severity_from_status(rec.status);
    ev.timestamp = rec.time;

    // Prefer leaving `host` empty and carrying the client identity in src_ip;
    // for web access logs the "host" field of the record is the connecting
    // client, which is semantically the source address, not the server name.
    ev.src_ip = rec.client_ip;
    ev.user = rec.user;

    ev.http_method = rec.request.method;
    ev.http_path = rec.request.target;
    ev.http_status = rec.status;
    if (rec.bytes_known) {
        ev.bytes = rec.bytes;
    }

    // Synthesized one-line summary: "METHOD target -> status". Each component is
    // optional so a partial record still produces something readable. The target
    // is bounded so a pathological path cannot blow up the message length.
    std::string message;
    if (!rec.request.method.empty()) {
        message += rec.request.method;
    } else {
        message += "-";
    }
    message += ' ';
    if (!rec.request.target.empty()) {
        message += core::truncate(rec.request.target, 512);
    } else {
        message += "-";
    }
    message += " -> ";
    message += std::to_string(rec.status);
    ev.message = std::move(message);

    // Carry the Combined-only metadata as extra fields when present so analysis
    // that cares about referer/user-agent can find them without re-parsing.
    if (!rec.referer.empty()) {
        ev.fields.set_string("referer", rec.referer);
    }
    if (!rec.user_agent.empty()) {
        ev.fields.set_string("user_agent", rec.user_agent);
    }
    // Preserve the RFC1413 ident when a server happened to log one; it is rare
    // but occasionally load-bearing for correlation.
    if (!rec.ident.empty()) {
        ev.fields.set_string("ident", rec.ident);
    }

    return ev;
}

// ---------------------------------------------------------------------------
// Whole stream
// ---------------------------------------------------------------------------

namespace {

// Builds a minimal "we couldn't structure this line" event so a malformed line
// is not silently lost. The raw line is sanitised and bounded before being used
// as the message so binary/over-long content cannot corrupt downstream output.
event::LogEvent make_raw_event(const std::string& raw, core::usize index) {
    event::LogEvent ev;
    ev.source = event::SourceFormat::WebAccess;
    ev.severity = event::Severity::Unknown;
    ev.record_index = index;
    ev.message =
        "unparsed: " + core::truncate(core::sanitize_printable(raw), 256);
    return ev;
}

}  // namespace

event::EventStream parse_stream(core::ByteSpan bytes, core::DiagnosticSink& diags,
                                const ParseOptions& opts) {
    event::EventStream stream;

    // Materialise the span into a string once; ByteSpan::to_string is bounds-safe
    // and yields an empty string for an empty/null span.
    const std::string text = bytes.to_string();
    if (text.empty()) {
        diags.info("weblog.parse_stream", "empty input");
        return stream;
    }

    // split_lines handles both LF and CRLF terminators and strips them.
    std::vector<std::string> lines = core::split_lines(text);
    stream.reserve(lines.size());

    core::usize index = 0;
    for (const std::string& raw : lines) {
        ++index;  // 1-based record index

        // Skip wholly blank lines (all whitespace or empty) silently; they carry
        // no record and are not an error condition.
        bool blank = true;
        for (char c : raw) {
            if (!core::is_space(c)) {
                blank = false;
                break;
            }
        }
        if (blank) {
            continue;
        }

        core::Result<AccessRecord> parsed = parse_line(raw, opts);
        if (parsed.ok()) {
            event::LogEvent ev = to_event(parsed.value());
            ev.record_index = index;
            if (!ev.has_time()) {
                diags.debug("weblog.parse_stream",
                            "record has no parseable timestamp", index);
            }
            stream.add(std::move(ev));
        } else {
            // Malformed line: record a warning and still emit a best-effort raw
            // event so the line is visible on the timeline rather than dropped.
            diags.warn("weblog.parse_stream", parsed.status().message(), index);
            stream.add(make_raw_event(raw, index));
        }
    }

    return stream;
}

// ---------------------------------------------------------------------------
// Fuzz entry point
// ---------------------------------------------------------------------------

void fuzz_one(core::ByteSpan bytes) {
    // Exercise the full pipeline on arbitrary bytes. A local sink with a small
    // cap keeps a hostile, diagnostic-spamming input from exhausting memory. We
    // must never crash, read out of bounds, overflow, or invoke UB regardless of
    // what `bytes` contains (empty, binary, truncated, quote-imbalanced, etc.).
    core::DiagnosticSink diags(64);
    ParseOptions opts;

    event::EventStream stream = parse_stream(bytes, diags, opts);

    // Touch the derived views of every event so their code paths are fuzzed too.
    // We accumulate into volatile-ish sinks (via a running size sum) so the calls
    // cannot be optimised away.
    core::usize sink = 0;
    for (const event::LogEvent& ev : stream.events()) {
        sink += ev.summary().size();
        sink += ev.signature().size();
    }

    // Independently fuzz the lower-level building blocks on the raw bytes so the
    // tokenizer, request-line splitter, and record mapper are exercised even on
    // inputs that produce no stream events.
    const std::string text = bytes.to_string();
    std::vector<std::string> fields = tokenize_fields(text, opts);
    for (const std::string& f : fields) {
        RequestLine rl = parse_request_line(f);
        sink += rl.method.size() + rl.target.size() + rl.version.size();
    }

    core::Result<AccessRecord> rec = parse_line(text, opts);
    if (rec.ok()) {
        sink += rec.value().decoded_path().size();
        event::LogEvent ev = to_event(rec.value());
        sink += ev.summary().size();
        sink += ev.signature().size();
    }

    // Defeat dead-code elimination without performing any I/O.
    (void)sink;
}

}  // namespace weblog
}  // namespace csift
