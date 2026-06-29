#include "syslog/parser.hpp"

#include "core/string_util.hpp"
#include "core/time_util.hpp"
#include "event/field.hpp"
#include "event/severity.hpp"

// Syslog line parser for ChronoSift.
//
// Supports the two dialects encountered in real captures:
//   * RFC3164 (classic BSD): "<PRI>Mmm dd hh:mm:ss host tag[pid]: message"
//   * RFC5424 (IETF):        "<PRI>VER TIMESTAMP HOST APP PROCID MSGID SD MSG"
//
// The whole module is exercised by a fuzz harness under ASan/UBSan, so the
// implementation is written defensively: every index into a std::string is
// bounds-checked, no arithmetic relies on unchecked attacker input, there is no
// recursion, and every helper tolerates empty / truncated / binary input. A
// malformed line never throws or aborts; it degrades to a best-effort result.

namespace csift {
namespace syslog {

namespace {

// RFC5424 NILVALUE: a lone '-' standing in for an absent field.
const std::string kNil = "-";

// Returns true when the field text is the RFC5424 NILVALUE.
bool is_nil(const std::string& s) noexcept { return s == kNil; }

// Maps a NILVALUE to the empty string, otherwise returns the field unchanged.
std::string denil(const std::string& s) { return is_nil(s) ? std::string() : s; }

// Skips ASCII spaces (only the SP character, per the RFC field separator) at
// `pos` within `text`. Never reads past the end.
void skip_spaces(const std::string& text, core::usize& pos) {
    while (pos < text.size() && text[pos] == ' ') ++pos;
}

// Reads a run of non-space characters starting at `pos`, advancing `pos` past
// it. Returns the token (possibly empty if `pos` already sits on a space/end).
std::string read_token(const std::string& text, core::usize& pos) {
    core::usize start = pos;
    while (pos < text.size() && text[pos] != ' ') ++pos;
    return text.substr(start, pos - start);
}

// Parses the leading "<PRI>" header if present.
//
// On success sets has_pri/priority/facility/severity and advances `pos` past
// the closing '>'. Recognises 1-3 decimal digits with value <= 191 (the maximum
// valid PRI = facility 23 * 8 + severity 7). Anything else (no '<', empty body,
// non-digit, overflow, value > 191, missing '>') leaves `pos` untouched and
// reports has_pri=false so the caller can still attempt a best-effort parse.
void parse_pri(const std::string& line, core::usize& pos, SyslogMessage& msg) {
    msg.has_pri = false;
    if (pos >= line.size() || line[pos] != '<') return;

    core::usize i = pos + 1;        // first digit candidate
    core::usize digits = 0;
    core::u32 value = 0;
    while (i < line.size() && core::is_digit(line[i]) && digits < 3) {
        value = value * 10 + static_cast<core::u32>(line[i] - '0');
        ++i;
        ++digits;
    }
    // Require at least one digit, a closing '>', and a legal PRI value.
    if (digits == 0) return;
    if (i >= line.size() || line[i] != '>') return;
    if (value > 191) return;

    msg.has_pri = true;
    msg.priority = value;
    msg.facility = value / 8;
    msg.severity = value % 8;
    pos = i + 1;  // step past '>'
}

// Decides whether the text at `pos` looks like the RFC5424 VERSION field: 1-2
// decimal digits immediately followed by a single SP. Does not consume input.
bool looks_like_rfc5424_version(const std::string& line, core::usize pos) {
    core::usize i = pos;
    core::usize digits = 0;
    while (i < line.size() && core::is_digit(line[i]) && digits < 2) {
        ++i;
        ++digits;
    }
    if (digits == 0) return false;
    return i < line.size() && line[i] == ' ';
}

// ---------------------------------------------------------------------------
// RFC3164 (BSD) parsing.
// ---------------------------------------------------------------------------

// The classic format has a fixed-width 15-char timestamp "Mmm dd hh:mm:ss"
// (single-digit days are space-padded). We extract exactly those 15 bytes when
// they are present and well-shaped, hand them to core::parse_syslog_bsd_time,
// and then continue from the byte after them.
//
// Some emitters omit the timestamp entirely; in that case we leave the
// timestamp invalid and treat what follows as host/tag/message.

// True when `text` from `pos` matches the rough BSD timestamp shape:
// "Aaa d? dd hh:mm:ss" -> 3 alpha, space, day digits, space, time with colons.
// We validate cheaply here; core::parse_syslog_bsd_time does the real parse.
bool looks_like_bsd_timestamp(const std::string& text, core::usize pos) {
    // Need at least "Mmm dd hh:mm:ss" = 15 chars.
    if (pos + 15 > text.size()) return false;
    // Three alphabetic month characters.
    if (!core::is_alpha(text[pos]) || !core::is_alpha(text[pos + 1]) ||
        !core::is_alpha(text[pos + 2])) {
        return false;
    }
    if (text[pos + 3] != ' ') return false;
    // Day: position 4 is space or digit, position 5 is a digit.
    char d0 = text[pos + 4];
    char d1 = text[pos + 5];
    if (!(d0 == ' ' || core::is_digit(d0))) return false;
    if (!core::is_digit(d1)) return false;
    if (text[pos + 6] != ' ') return false;
    // Time hh:mm:ss at offsets 7..14.
    if (!core::is_digit(text[pos + 7]) || !core::is_digit(text[pos + 8])) return false;
    if (text[pos + 9] != ':') return false;
    if (!core::is_digit(text[pos + 10]) || !core::is_digit(text[pos + 11])) return false;
    if (text[pos + 12] != ':') return false;
    if (!core::is_digit(text[pos + 13]) || !core::is_digit(text[pos + 14])) return false;
    return true;
}

// Splits an RFC3164 "tag[pid]:" token into app_name and proc_id. The pid and
// the trailing colon are both optional. `token` is a single whitespace-free run
// (the colon, if present, is the last char). Examples:
//   "sshd[1234]:" -> app="sshd" pid="1234"
//   "sshd:"       -> app="sshd" pid=""
//   "kernel"      -> app="kernel" pid=""
void split_tag(const std::string& token, std::string& app, std::string& pid) {
    app.clear();
    pid.clear();
    std::string t = token;
    // Drop a single trailing ':' if present.
    if (!t.empty() && t.back() == ':') t.pop_back();
    if (t.empty()) return;

    // Look for a "[pid]" suffix.
    if (t.back() == ']') {
        core::usize open = t.rfind('[');
        if (open != std::string::npos && open + 1 < t.size()) {
            // pid is the content strictly between '[' and the final ']'.
            pid = t.substr(open + 1, t.size() - 1 - (open + 1));
            app = t.substr(0, open);
            return;
        }
    }
    app = t;
}

// Parses the body of an RFC3164 line (text after the optional PRI). Fills the
// timestamp (when present), hostname, tag/pid, and message. Always succeeds in
// the best-effort sense: whatever cannot be recognised lands in the message.
void parse_rfc3164_body(const std::string& line, core::usize pos,
                        SyslogMessage& msg, const ParseOptions& opts) {
    msg.flavor = SyslogFlavor::Rfc3164;

    skip_spaces(line, pos);

    // Timestamp (fixed 15 bytes) when it matches the BSD shape.
    if (looks_like_bsd_timestamp(line, pos)) {
        std::string ts = line.substr(pos, 15);
        msg.timestamp = core::parse_syslog_bsd_time(ts, opts.assume_year);
        pos += 15;
        skip_spaces(line, pos);
    } else {
        msg.timestamp = core::Timestamp::invalid();
    }

    // Hostname: the next whitespace-delimited token. If there is nothing left,
    // we simply have no host.
    if (pos < line.size()) {
        std::string host = read_token(line, pos);
        msg.hostname = host;
        skip_spaces(line, pos);
    }

    // Tag[pid]: token. If the next token contains a ':' or '[' we treat it as a
    // tag; otherwise we still take it as the app name and leave the rest as the
    // message (some daemons omit the colon).
    if (pos < line.size()) {
        core::usize tag_start = pos;
        std::string token = read_token(line, pos);
        bool looks_tagged =
            (!token.empty() && (token.back() == ':' ||
                                token.find('[') != std::string::npos));
        if (looks_tagged) {
            split_tag(token, msg.app_name, msg.proc_id);
            skip_spaces(line, pos);
            if (pos < line.size()) msg.message = line.substr(pos);
        } else {
            // No clear tag delimiter: everything from here is the message, but
            // record the first token as the app name as a best-effort guess.
            msg.app_name = token;
            // Restore to just after the token for the message, trimming one run
            // of spaces.
            skip_spaces(line, pos);
            if (pos < line.size()) {
                msg.message = line.substr(pos);
            }
            // If the host token absorbed what was really the message (no tag at
            // all), keep behaviour predictable: nothing more to do.
            (void)tag_start;
        }
    }
}

// ---------------------------------------------------------------------------
// RFC5424 (IETF) parsing.
// ---------------------------------------------------------------------------

// Parses the header fields VERSION TIMESTAMP HOSTNAME APP-NAME PROCID MSGID,
// each a single SP-delimited token, starting at `pos` (positioned just after
// the PRI). Advances `pos` to the start of the STRUCTURED-DATA section. Returns
// false only when the version token is missing/invalid (which the caller has
// already screened for, so this is belt-and-braces).
bool parse_rfc5424_header(const std::string& line, core::usize& pos,
                          SyslogMessage& msg) {
    skip_spaces(line, pos);

    // VERSION (1-2 digits).
    std::string ver = read_token(line, pos);
    if (ver.empty()) return false;
    core::u64 vnum = 0;
    if (!core::parse_u64(ver, vnum)) return false;
    // Clamp to the u32 field; realistic versions are tiny.
    msg.version = static_cast<core::u32>(
        core::clamp_value<core::u64>(vnum, 0, 0xffffffffu));

    skip_spaces(line, pos);
    std::string ts = read_token(line, pos);
    if (!is_nil(ts) && !ts.empty()) {
        msg.timestamp = core::parse_iso8601(ts);
    } else {
        msg.timestamp = core::Timestamp::invalid();
    }

    skip_spaces(line, pos);
    msg.hostname = denil(read_token(line, pos));

    skip_spaces(line, pos);
    msg.app_name = denil(read_token(line, pos));

    skip_spaces(line, pos);
    msg.proc_id = denil(read_token(line, pos));

    skip_spaces(line, pos);
    msg.msg_id = denil(read_token(line, pos));

    skip_spaces(line, pos);
    return true;
}

}  // namespace

// ---------------------------------------------------------------------------
// STRUCTURED-DATA grammar (public for targeted testing).
// ---------------------------------------------------------------------------
//
// SD = NILVALUE / 1*SD-ELEMENT
// SD-ELEMENT = "[" SD-ID *(SP SD-PARAM) "]"
// SD-PARAM   = PARAM-NAME "=" %d34 PARAM-VALUE %d34   (double-quoted)
//
// Inside a quoted PARAM-VALUE the characters '"', '\' and ']' must be escaped as
// \" \\ \] respectively. We honour those three escapes and pass any other
// backslash sequence through verbatim (keeping the backslash), which matches how
// lenient real-world consumers behave.
//
// The function is bounded by opts.max_sd_elements and opts.max_sd_params and
// returns StatusCode::LimitExceeded when either is exceeded. It never reads past
// the end of `text`; malformed structure yields StatusCode::Malformed with `pos`
// left at the offending byte so the caller can decide how much to salvage.
core::Status parse_structured_data(const std::string& text, core::usize& pos,
                                   std::vector<SdElement>& out,
                                   const ParseOptions& opts) {
    out.clear();

    if (pos >= text.size()) {
        return core::Status(core::StatusCode::Truncated,
                            "structured-data: no input");
    }

    // NILVALUE: a lone '-' (optionally followed by SP/EOL meaning "absent").
    if (text[pos] == '-') {
        // Only treat as NILVALUE when '-' is not the start of a '[' element.
        ++pos;
        return core::Status();  // Ok, empty SD.
    }

    // Must begin with '[' for real structured data.
    if (text[pos] != '[') {
        return core::Status(core::StatusCode::Malformed,
                            "structured-data: expected '[' or '-'");
    }

    while (pos < text.size() && text[pos] == '[') {
        if (out.size() >= opts.max_sd_elements) {
            return core::Status(core::StatusCode::LimitExceeded,
                                "structured-data: too many SD elements");
        }
        ++pos;  // consume '['

        SdElement elem;

        // SD-ID: characters up to the first SP or ']'. SD-NAME forbids SP, '=',
        // ']' and '"', but we are lenient: we stop at SP or ']' and keep the
        // rest, which is enough to be safe and useful.
        core::usize id_start = pos;
        while (pos < text.size() && text[pos] != ' ' && text[pos] != ']') {
            ++pos;
        }
        elem.id = text.substr(id_start, pos - id_start);
        if (elem.id.empty()) {
            return core::Status(core::StatusCode::Malformed,
                                "structured-data: empty SD-ID");
        }

        // Zero or more SP-separated params until the closing ']'.
        while (true) {
            // Skip the separating spaces.
            skip_spaces(text, pos);
            if (pos >= text.size()) {
                return core::Status(core::StatusCode::Truncated,
                                    "structured-data: unterminated element");
            }
            if (text[pos] == ']') {
                ++pos;  // consume ']'
                break;
            }

            if (elem.params.size() >= opts.max_sd_params) {
                return core::Status(core::StatusCode::LimitExceeded,
                                    "structured-data: too many SD params");
            }

            // PARAM-NAME up to '='.
            core::usize name_start = pos;
            while (pos < text.size() && text[pos] != '=' && text[pos] != ' ' &&
                   text[pos] != ']') {
                ++pos;
            }
            if (pos >= text.size() || text[pos] != '=') {
                return core::Status(core::StatusCode::Malformed,
                                    "structured-data: param missing '='");
            }
            std::string name = text.substr(name_start, pos - name_start);
            ++pos;  // consume '='

            // Opening quote.
            if (pos >= text.size() || text[pos] != '"') {
                return core::Status(core::StatusCode::Malformed,
                                    "structured-data: param value not quoted");
            }
            ++pos;  // consume opening '"'

            // PARAM-VALUE up to the closing unescaped '"'.
            std::string value;
            bool closed = false;
            while (pos < text.size()) {
                char c = text[pos];
                if (c == '\\') {
                    // Escape sequence: look at the next char if available.
                    if (pos + 1 < text.size()) {
                        char n = text[pos + 1];
                        if (n == '"' || n == '\\' || n == ']') {
                            value.push_back(n);
                            pos += 2;
                            continue;
                        }
                    }
                    // Lone or unknown escape: keep the backslash verbatim.
                    value.push_back('\\');
                    ++pos;
                    continue;
                }
                if (c == '"') {
                    ++pos;  // consume closing quote
                    closed = true;
                    break;
                }
                value.push_back(c);
                ++pos;
            }
            if (!closed) {
                return core::Status(core::StatusCode::Truncated,
                                    "structured-data: unterminated param value");
            }

            SdParam param;
            param.name = std::move(name);
            param.value = std::move(value);
            elem.params.push_back(std::move(param));
        }

        out.push_back(std::move(elem));
        // Loop continues if another '[' immediately follows; per the grammar
        // elements are concatenated with no separator, but we also tolerate an
        // incidental space between them.
        skip_spaces(text, pos);
    }

    return core::Status();
}

core::Result<SyslogMessage> parse_line(const std::string& line,
                                       const ParseOptions& opts) {
    SyslogMessage msg;

    if (line.empty()) {
        return core::Result<SyslogMessage>(
            core::Status(core::StatusCode::Empty, "empty syslog line"));
    }

    core::usize pos = 0;
    parse_pri(line, pos, msg);  // sets msg.has_pri, advances pos past "<PRI>"

    // Decide the flavor. After the PRI (or at the start when there was none) we
    // look for an RFC5424 version digit + space; otherwise fall back to BSD.
    skip_spaces(line, pos);

    if (looks_like_rfc5424_version(line, pos)) {
        msg.flavor = SyslogFlavor::Rfc5424;
        core::usize hpos = pos;
        if (!parse_rfc5424_header(line, hpos, msg)) {
            // Header screening already passed, so this is unexpected; treat the
            // whole remainder as the message rather than failing hard.
            msg.message = line.substr(pos);
            return core::Result<SyslogMessage>(std::move(msg));
        }
        pos = hpos;

        // STRUCTURED-DATA.
        if (pos < line.size()) {
            std::vector<SdElement> sd;
            core::usize sd_pos = pos;
            core::Status st = parse_structured_data(line, sd_pos, sd, opts);
            if (st.ok()) {
                msg.structured_data = std::move(sd);
                pos = sd_pos;
            } else if (st.code() == core::StatusCode::LimitExceeded) {
                // Keep whatever we gathered and surface the limit to the caller.
                msg.structured_data = std::move(sd);
                pos = sd_pos;
                // Remaining text (if any) becomes the message after one space.
                skip_spaces(line, pos);
                if (pos < line.size()) msg.message = line.substr(pos);
                return core::Result<SyslogMessage>(st);
            } else {
                // Malformed/Truncated SD: do not advance; the rest is message.
                // This keeps a single bad SD section from discarding the line.
            }
        }

        // MSG: a single SP then the free text to end-of-line. Per RFC5424 the
        // MSG may begin with a UTF-8 BOM, which we keep verbatim.
        skip_spaces(line, pos);
        if (pos < line.size()) {
            msg.message = line.substr(pos);
        }
        return core::Result<SyslogMessage>(std::move(msg));
    }

    // RFC3164 / best-effort BSD path.
    parse_rfc3164_body(line, pos, msg, opts);
    return core::Result<SyslogMessage>(std::move(msg));
}

event::LogEvent to_event(const SyslogMessage& msg) {
    event::LogEvent ev;
    ev.source = event::SourceFormat::Syslog;
    ev.timestamp = msg.timestamp;
    ev.severity = msg.has_pri ? event::severity_from_syslog(msg.severity)
                              : event::Severity::Unknown;
    ev.host = msg.hostname;
    ev.app = msg.app_name;
    ev.provider = msg.app_name;
    ev.message = msg.message;

    // PROCID -> pid: only when it is a plain decimal integer that fits i64.
    ev.pid = -1;
    if (!msg.proc_id.empty()) {
        core::i64 pid = 0;
        if (core::parse_i64(msg.proc_id, pid)) ev.pid = pid;
    }

    // Copy structured-data params into the field map as "SD-ID.param" = value.
    for (const SdElement& elem : msg.structured_data) {
        for (const SdParam& p : elem.params) {
            std::string key = elem.id;
            key.push_back('.');
            key += p.name;
            ev.fields.set_string(key, p.value);
        }
    }

    return ev;
}

event::EventStream parse_stream(core::ByteSpan bytes, core::DiagnosticSink& diags,
                                const ParseOptions& opts) {
    event::EventStream stream;

    // Materialise as a string so we can use the shared line splitter, then walk
    // the lines. ByteSpan::to_string is safe on empty/null spans.
    std::string text = bytes.to_string();
    if (text.empty()) {
        return stream;
    }

    std::vector<std::string> lines = core::split_lines(text);
    stream.reserve(lines.size());

    for (core::usize idx = 0; idx < lines.size(); ++idx) {
        const std::string& raw = lines[idx];
        core::usize record_index = idx + 1;  // 1-based

        core::Result<SyslogMessage> res = parse_line(raw, opts);

        if (res.ok()) {
            event::LogEvent ev = to_event(res.value());
            ev.record_index = record_index;
            // Bound the message length defensively.
            ev.message = core::truncate(ev.message, opts.max_message_bytes);
            stream.add(std::move(ev));
        } else {
            // Empty lines are not an error worth a diagnostic flood; skip them
            // but still record a placeholder so indices line up with the source.
            if (res.code() == core::StatusCode::Empty) {
                event::LogEvent ev;
                ev.source = event::SourceFormat::Syslog;
                ev.record_index = record_index;
                stream.add(std::move(ev));
                continue;
            }

            // A real parse failure (e.g. LimitExceeded): warn and still add a
            // best-effort event carrying the raw line as the message so nothing
            // silently disappears from the timeline.
            diags.warn("syslog.line", res.status().to_string(), record_index);

            event::LogEvent ev;
            // If the partial parse produced useful header fields, keep them.
            ev = to_event(res.value());
            ev.source = event::SourceFormat::Syslog;
            ev.record_index = record_index;
            if (ev.message.empty()) {
                ev.message = raw;
            }
            ev.message = core::truncate(ev.message, opts.max_message_bytes);
            stream.add(std::move(ev));
        }
    }

    return stream;
}

void fuzz_one(core::ByteSpan bytes) {
    // Use a small diagnostic cap so a hostile artifact cannot make the sink grow
    // without bound, then run the full parse path.
    core::DiagnosticSink diags(256);
    ParseOptions opts;  // defaults are already bounded.

    event::EventStream stream = parse_stream(bytes, diags, opts);

    // Touch the derived views so the optimiser cannot elide the work, and so the
    // summary()/signature() code paths are themselves fuzzed.
    volatile core::usize sink = 0;
    for (const event::LogEvent& ev : stream.events()) {
        std::string s = ev.summary();
        std::string g = ev.signature();
        sink += s.size();
        sink += g.size();
    }
    sink += diags.size();
    sink += diags.dropped();
    (void)sink;
}

}  // namespace syslog
}  // namespace csift
