#include "cef/parser.hpp"

#include "core/string_util.hpp"
#include "core/time_util.hpp"
#include "event/field.hpp"
#include "event/severity.hpp"

// ArcSight Common Event Format (CEF) parser for ChronoSift.
//
// Grammar:
//   CEF:Version|DeviceVendor|DeviceProduct|DeviceVersion|SignatureID|Name|Severity|Extension
//
// The line consists of the literal marker "CEF:" followed by exactly seven
// pipe-delimited header fields; the eighth section (Extension) is a free-form
// run of "key=value" pairs separated by spaces. A real CEF line is frequently
// embedded in a syslog frame, e.g.
//   <134>Jan  1 00:00:00 host CEF:0|Vendor|Product|1.0|100|Login failed|5|src=10.0.0.1
// so parse_line first locates the "CEF:" marker and parses from there.
//
// Escaping:
//   * Header fields: "\|" is a literal pipe, "\\" is a literal backslash.
//   * Extension values: "\=" is a literal '=', "\\" a literal backslash, and
//     "\n"/"\r" are newlines. A value runs until the next " key=" boundary
//     (a space followed by a key token immediately followed by '=').
//
// The whole module is fuzzed under ASan/UBSan, so it is written defensively:
// every index into a std::string is bounds-checked, no arithmetic trusts an
// attacker-supplied length, there is no recursion, the configured limits on
// extension count and field size are honoured, and every helper tolerates
// empty / truncated / binary input without throwing or aborting.

namespace csift {
namespace cef {

namespace {

// The marker that introduces a CEF record. Version follows immediately.
const char kMarker[] = "CEF:";
const core::usize kMarkerLen = 4;

// CEF defines seven pipe-delimited header fields: Version, DeviceVendor,
// DeviceProduct, DeviceVersion, SignatureID, Name, Severity. The Version is
// read separately (it sits right after the "CEF:" marker), so after the version
// there are six more pipe-delimited fields before the Extension section.
const core::usize kPostVersionFieldCount = 6;

// Appends `c` to `out` unless that would push it past `limit`. Returns false
// when the limit was hit so callers can stop accumulating. A limit of 0 means
// "no limit" is treated as effectively unbounded by callers that pass a real
// cap; here we always respect the cap that is given.
bool push_bounded(std::string& out, char c, core::usize limit) {
    if (out.size() >= limit) return false;
    out.push_back(c);
    return true;
}

// Locates the "CEF:" marker within `line`. Returns the offset of the 'C', or
// std::string::npos when absent. We scan rather than assume a fixed syslog
// prefix length because the prefix shape varies wildly between appliances.
core::usize find_marker(const std::string& line) {
    return line.find(kMarker);
}

// Reads the integer CEF version sitting immediately after the marker. `pos`
// must point at the first character after "CEF:". On success advances `pos` to
// the first '|' (or end) and returns true. Tolerates a missing version (treats
// it as 0) but requires the digits to be a contiguous prefix.
bool read_version(const std::string& body, core::usize& pos, core::u32& out) {
    core::usize start = pos;
    core::u64 v = 0;
    bool overflow = false;
    while (pos < body.size() && core::is_digit(body[pos])) {
        core::u64 next = v * 10 + static_cast<core::u64>(body[pos] - '0');
        if (next < v) overflow = true;  // wrapped; clamp below
        v = next;
        ++pos;
    }
    // No digits at all -> still acceptable as version 0, but we report whether
    // anything was consumed so the caller can leave pos where it found it.
    if (pos == start) {
        out = 0;
        return true;
    }
    out = overflow ? 0xffffffffu
                   : static_cast<core::u32>(
                         core::clamp_value<core::u64>(v, 0, 0xffffffffu));
    return true;
}

}  // namespace

// ---------------------------------------------------------------------------
// Header splitting.
// ---------------------------------------------------------------------------
//
// `line` is expected to begin at (or contain) the "CEF:" marker. We locate the
// marker, read the version, then split the following text into the six
// post-version header fields on unescaped '|'. Within a field "\|" yields a
// literal pipe and "\\" yields a literal backslash; any other backslash
// sequence is kept verbatim (backslash retained), matching lenient real-world
// consumers. A trailing lone backslash at end-of-input is kept as a literal
// backslash.
//
// To keep split_header self-contained for testing, the returned vector is
// self-describing with exactly eight entries on success:
//   [version, vendor, product, deviceVersion, signatureId, name, severity, extension]
// The first element is the version rendered as text; the last is the (possibly
// empty) Extension section. (See parse_line for how this is consumed.)
core::Result<std::vector<std::string>> split_header(const std::string& line,
                                                    const ParseOptions& opts) {
    using R = core::Result<std::vector<std::string>>;

    core::usize marker = find_marker(line);
    if (marker == std::string::npos) {
        return R::failure(core::StatusCode::Malformed,
                          "cef: missing 'CEF:' marker");
    }

    core::usize pos = marker + kMarkerLen;

    // Version digits.
    core::u32 version = 0;
    read_version(line, pos, version);

    // After the version we require a '|' separator before the first header
    // field. A bare "CEF:0" with no pipe is malformed.
    if (pos >= line.size() || line[pos] != '|') {
        return R::failure(core::StatusCode::Malformed,
                          "cef: missing field separator after version");
    }
    ++pos;  // consume the '|' that ends the version section.

    std::vector<std::string> fields;
    fields.reserve(kPostVersionFieldCount + 2);
    // Element 0 carries the version as text so the vector is self-describing.
    fields.push_back(std::to_string(version));

    // Parse the six post-version fields (Vendor, Product, DeviceVersion,
    // SignatureID, Name, Severity). Each stops at an unescaped '|'; the last
    // (Severity) also stops at '|' so the remainder (the Extension section) can
    // be returned as a final element. We accumulate field characters with the
    // header escape rules applied.
    const core::usize cap = opts.max_field_bytes;
    core::usize parsed = 0;
    std::string field;
    field.reserve(32);

    while (parsed < kPostVersionFieldCount) {
        field.clear();
        bool truncated_field = false;

        while (pos < line.size()) {
            char c = line[pos];
            if (c == '\\') {
                // Escape sequence inside a header field.
                if (pos + 1 < line.size()) {
                    char n = line[pos + 1];
                    if (n == '|') {
                        if (!push_bounded(field, '|', cap)) truncated_field = true;
                        pos += 2;
                        continue;
                    }
                    if (n == '\\') {
                        if (!push_bounded(field, '\\', cap)) truncated_field = true;
                        pos += 2;
                        continue;
                    }
                    // Unknown escape: keep the backslash verbatim and let the
                    // next iteration handle the following character.
                    if (!push_bounded(field, '\\', cap)) truncated_field = true;
                    ++pos;
                    continue;
                }
                // Trailing lone backslash at end-of-input: keep it literally.
                if (!push_bounded(field, '\\', cap)) truncated_field = true;
                ++pos;
                continue;
            }
            if (c == '|') {
                break;  // unescaped field separator
            }
            if (!push_bounded(field, c, cap)) {
                truncated_field = true;
                // Keep scanning to find the field boundary, but stop appending.
            }
            ++pos;
        }

        (void)truncated_field;  // truncation is silent and bounded; not fatal.
        fields.push_back(field);
        ++parsed;

        if (parsed < kPostVersionFieldCount) {
            // We must be sitting on a '|' to start the next field.
            if (pos >= line.size()) {
                return R::failure(core::StatusCode::Truncated,
                                  "cef: fewer than seven header fields");
            }
            // Consume the separator.
            ++pos;
        }
    }

    // Whatever remains after the header fields is the Extension section. The
    // Severity field's scan stopped at the '|' that precedes it (if any).
    std::string extension;
    if (pos < line.size() && line[pos] == '|') {
        ++pos;  // consume the '|' before the extension
        extension = line.substr(pos);
    } else if (pos >= line.size()) {
        // Exactly seven header fields and no extension section: valid CEF.
        extension.clear();
    } else {
        // Should not happen (loop only breaks on '|' or end), but stay safe.
        extension = line.substr(pos);
    }
    // Bound the extension section length defensively before it is reparsed.
    if (extension.size() > cap) extension.resize(cap);
    fields.push_back(std::move(extension));

    return R(std::move(fields));
}

// ---------------------------------------------------------------------------
// Extension parsing.
// ---------------------------------------------------------------------------
//
// The extension section is "key=value key2=value2 ...". A value can itself
// contain spaces, so we cannot naively split on whitespace. Instead a value
// runs until the next " key=" boundary: a space followed by a key token (a run
// of key characters) immediately followed by '='. Keys are typically
// alphanumeric (plus a few punctuation chars some vendors use), so we accept a
// conservative key-character set when probing for a boundary.
//
// Value escapes: "\=" -> '=', "\\" -> '\\', "\n" -> '\n', "\r" -> '\r'. Any
// other backslash sequence keeps the backslash verbatim. A trailing lone
// backslash is kept literally.

namespace {

// True when `c` may appear in a CEF extension key. ArcSight keys are dotted
// alphanumerics (e.g. "deviceCustomString1", "cs1Label"); we accept letters,
// digits, '.', '_' and '-' which covers vendor extensions without swallowing
// the '=' or space that delimit a pair.
bool is_key_char(char c) noexcept {
    return core::is_alnum(c) || c == '.' || c == '_' || c == '-';
}

// Looks ahead from `i` (which must index a space) to decide whether a new
// "key=" pair begins right after the space. Returns true and sets
// `key_start`/`key_end`/`eq` (positions of the key span and the '=') when a
// boundary is found; returns false otherwise (the space is part of the value).
bool is_pair_boundary(const std::string& text, core::usize space_pos,
                      core::usize& key_start, core::usize& key_end,
                      core::usize& eq) {
    core::usize i = space_pos + 1;
    // A key must be at least one key-char.
    core::usize ks = i;
    while (i < text.size() && is_key_char(text[i])) ++i;
    if (i == ks) return false;          // no key characters after the space
    if (i >= text.size()) return false;  // ran out before any '='
    if (text[i] != '=') return false;    // not a "key=" shape
    key_start = ks;
    key_end = i;
    eq = i;
    return true;
}

// Reads a key starting at `pos` (a run of key chars) up to the '='. Advances
// `pos` to the '=' on success. Returns the key (possibly empty).
std::string read_key(const std::string& text, core::usize& pos) {
    core::usize start = pos;
    while (pos < text.size() && is_key_char(text[pos])) ++pos;
    return text.substr(start, pos - start);
}

}  // namespace

core::Status parse_extensions(const std::string& text, core::usize pos,
                              std::vector<CefExtension>& out,
                              const ParseOptions& opts) {
    // Skip any leading spaces before the first key.
    while (pos < text.size() && text[pos] == ' ') ++pos;

    const core::usize cap = opts.max_field_bytes;

    while (pos < text.size()) {
        if (out.size() >= opts.max_extensions) {
            return core::Status(core::StatusCode::LimitExceeded,
                                "cef: too many extension pairs");
        }

        // A pair starts with a key (run of key chars) then '='. If the current
        // character is not a key char we cannot form a pair; skip it so binary
        // noise or stray punctuation does not stall the scan.
        if (!is_key_char(text[pos])) {
            ++pos;
            continue;
        }

        core::usize key_start = pos;
        std::string key = read_key(text, pos);

        // Require the '=' delimiter. If it is missing the token was not a real
        // key (e.g. trailing word); drop it and continue past it.
        if (pos >= text.size() || text[pos] != '=') {
            // Skip to the next space so we resynchronise at a likely boundary.
            while (pos < text.size() && text[pos] != ' ') ++pos;
            while (pos < text.size() && text[pos] == ' ') ++pos;
            (void)key_start;
            continue;
        }
        ++pos;  // consume '='

        if (key.empty()) {
            // "=value" with no key: not a valid pair. Skip the value run.
            while (pos < text.size() && text[pos] != ' ') ++pos;
            while (pos < text.size() && text[pos] == ' ') ++pos;
            continue;
        }
        if (key.size() > cap) key.resize(cap);

        // Accumulate the value until the next " key=" boundary or end-of-input,
        // applying the value escape rules.
        std::string value;
        value.reserve(16);
        bool truncated_value = false;

        while (pos < text.size()) {
            char c = text[pos];

            if (c == '\\') {
                if (pos + 1 < text.size()) {
                    char n = text[pos + 1];
                    char decoded = 0;
                    bool known = true;
                    switch (n) {
                        case '=': decoded = '='; break;
                        case '\\': decoded = '\\'; break;
                        case 'n': decoded = '\n'; break;
                        case 'r': decoded = '\r'; break;
                        default: known = false; break;
                    }
                    if (known) {
                        if (!push_bounded(value, decoded, cap)) truncated_value = true;
                        pos += 2;
                        continue;
                    }
                    // Unknown escape: keep the backslash and let the next loop
                    // iteration process the following character normally.
                    if (!push_bounded(value, '\\', cap)) truncated_value = true;
                    ++pos;
                    continue;
                }
                // Trailing lone backslash: keep it literally and finish.
                if (!push_bounded(value, '\\', cap)) truncated_value = true;
                ++pos;
                continue;
            }

            if (c == ' ') {
                // Possible start of the next pair. Probe for a " key=" boundary.
                core::usize ks = 0, ke = 0, eq = 0;
                if (is_pair_boundary(text, pos, ks, ke, eq)) {
                    // The space is the separator; stop the value here without
                    // consuming the space (the outer loop will skip it).
                    break;
                }
                // The space belongs to the value.
                if (!push_bounded(value, ' ', cap)) truncated_value = true;
                ++pos;
                continue;
            }

            if (!push_bounded(value, c, cap)) {
                truncated_value = true;
                // Keep scanning for the boundary but stop appending. We still
                // need to find where the value ends so the next pair parses.
            }
            ++pos;
        }

        (void)truncated_value;  // truncation is bounded and non-fatal.

        CefExtension pair;
        pair.key = std::move(key);
        pair.value = std::move(value);
        out.push_back(std::move(pair));

        // Skip the separating spaces before the next pair.
        while (pos < text.size() && text[pos] == ' ') ++pos;
    }

    return core::Status();
}

// ---------------------------------------------------------------------------
// Line parsing.
// ---------------------------------------------------------------------------

core::Result<CefRecord> parse_line(const std::string& line,
                                   const ParseOptions& opts) {
    using R = core::Result<CefRecord>;

    if (line.empty()) {
        return R(core::Status(core::StatusCode::Empty, "empty cef line"));
    }

    core::Result<std::vector<std::string>> hdr = split_header(line, opts);
    if (!hdr.ok()) {
        return R(hdr.status());
    }

    const std::vector<std::string>& f = hdr.value();
    // split_header returns: [version, vendor, product, ver, sig, name, sev, ext]
    // i.e. exactly kPostVersionFieldCount + 2 entries on success. Guard the size
    // in case of any future change so indexing below is always in range.
    if (f.size() < kPostVersionFieldCount + 2) {
        return R(core::Status(core::StatusCode::Malformed,
                              "cef: incomplete header"));
    }

    CefRecord rec;
    // Element 0 is the version text.
    core::u64 vnum = 0;
    if (core::parse_u64(f[0], vnum)) {
        rec.version = static_cast<core::u32>(
            core::clamp_value<core::u64>(vnum, 0, 0xffffffffu));
    } else {
        rec.version = 0;
    }
    rec.device_vendor = f[1];
    rec.device_product = f[2];
    rec.device_version = f[3];
    rec.signature_id = f[4];
    rec.name = f[5];
    rec.severity = f[6];

    // Parse the extension section (element 7).
    core::Status ext_st = parse_extensions(f[7], 0, rec.extensions, opts);
    // A LimitExceeded from the extension parser is non-fatal: we keep whatever
    // pairs we gathered and still consider the record valid. The caller can
    // observe the limit via the returned status if it cares, but most consumers
    // just want the best-effort record.
    (void)ext_st;

    rec.valid = true;
    return R(std::move(rec));
}

// ---------------------------------------------------------------------------
// Event conversion.
// ---------------------------------------------------------------------------

namespace {

// Builds the provider string "vendor product", trimmed, collapsing the case
// where one half is empty so we never emit a stray leading/trailing space.
std::string make_provider(const CefRecord& rec) {
    std::string v = core::trim(rec.device_vendor);
    std::string p = core::trim(rec.device_product);
    if (v.empty()) return p;
    if (p.empty()) return v;
    return v + " " + p;
}

// Attempts to interpret a CEF "rt" (receipt time) value as a timestamp. CEF
// receipt times are conventionally epoch milliseconds, but some emitters send a
// human-readable string. We try the numeric-milliseconds interpretation first
// (a pure digit run), then fall back to the generic time parser.
core::Timestamp parse_rt(const std::string& rt, const ParseOptions& opts) {
    std::string s = core::trim(rt);
    if (s.empty()) return core::Timestamp::invalid();

    bool all_digits = !s.empty();
    for (char c : s) {
        if (!core::is_digit(c)) {
            all_digits = false;
            break;
        }
    }
    if (all_digits) {
        core::u64 ms = 0;
        if (core::parse_u64(s, ms)) {
            // Convert milliseconds to microseconds with overflow protection.
            // i64 micros holds ~292k years from the epoch, so realistic ms
            // values never overflow; guard the multiply regardless.
            const core::u64 kMaxMs =
                static_cast<core::u64>(0x7fffffffffffffffLL) / 1000u;
            if (ms <= kMaxMs) {
                return core::Timestamp::from_micros(
                    static_cast<core::i64>(ms) * 1000);
            }
            // Absurd value: do not pretend to know the time.
            return core::Timestamp::invalid();
        }
        return core::Timestamp::invalid();
    }

    // Non-numeric: try the generic dispatcher (ISO-8601, syslog, CLF, ...).
    return core::parse_any_time(s, opts.assume_year);
}

// Parses an unsigned port-ish value into a u32, clamping to the field width.
// Returns 0 (the "unknown port" sentinel used by the event model) on failure.
core::u32 parse_port(const std::string& s) {
    core::u64 n = 0;
    if (!core::parse_u64(core::trim(s), n)) return 0;
    return static_cast<core::u32>(core::clamp_value<core::u64>(n, 0, 0xffffffffu));
}

}  // namespace

event::LogEvent to_event(const CefRecord& rec, const ParseOptions& opts) {
    event::LogEvent ev;

    // There is no dedicated CEF value in the SourceFormat enum. Per the module
    // contract we leave the source as Unknown rather than mislabel it, and
    // surface the appliance identity through provider/app/channel instead.
    ev.source = event::SourceFormat::Unknown;

    // Severity comes from the normalised CEF severity mapped onto the syslog
    // scale that severity_from_syslog understands.
    ev.severity = event::severity_from_syslog(rec.normalized_severity());

    // Appliance identity.
    ev.provider = make_provider(rec);
    ev.app = core::trim(rec.device_product);
    ev.channel = core::trim(rec.device_product);

    // Default message is the CEF Name; an explicit "msg" extension overrides it.
    ev.message = rec.name;

    // event_id: when the SignatureID is a plain decimal integer, expose it as
    // the numeric event id (clamped to the u32 field). Non-numeric signatures
    // (some vendors use textual IDs) are kept only in the field map.
    {
        core::u64 sig = 0;
        std::string sid = core::trim(rec.signature_id);
        if (!sid.empty() && core::parse_u64(sid, sig)) {
            ev.event_id = static_cast<core::u32>(
                core::clamp_value<core::u64>(sig, 0, 0xffffffffu));
        }
    }

    // Map the well-known CEF extension keys onto first-class event fields, and
    // record every extension (including the mapped ones, for fidelity) into the
    // field map. Order of the map follows the source order of the extensions.
    bool have_rt = false;
    for (const CefExtension& e : rec.extensions) {
        const std::string& k = e.key;
        const std::string& v = e.value;

        if (k == "src" || k == "dvc") {
            if (ev.src_ip.empty()) ev.src_ip = v;
        } else if (k == "dst") {
            if (ev.dst_ip.empty()) ev.dst_ip = v;
        } else if (k == "spt") {
            if (ev.src_port == 0) ev.src_port = parse_port(v);
        } else if (k == "dpt") {
            if (ev.dst_port == 0) ev.dst_port = parse_port(v);
        } else if (k == "suser" || k == "duser") {
            if (ev.user.empty()) ev.user = v;
        } else if (k == "rt") {
            core::Timestamp ts = parse_rt(v, opts);
            if (ts.valid) {
                ev.timestamp = ts;
                have_rt = true;
            }
        } else if (k == "msg") {
            ev.message = v;
        }

        // Always preserve the raw pair in the field map.
        ev.fields.set_string(k, v);
    }
    (void)have_rt;

    // Preserve the structural header fields in the map as well so nothing is
    // lost in translation (analysis code can group on these).
    if (!rec.signature_id.empty()) {
        ev.fields.set_string("cef.signatureId", rec.signature_id);
    }
    if (!rec.name.empty()) {
        ev.fields.set_string("cef.name", rec.name);
    }
    if (!rec.device_version.empty()) {
        ev.fields.set_string("cef.deviceVersion", rec.device_version);
    }
    ev.fields.set_int("cef.version", static_cast<core::i64>(rec.version));

    return ev;
}

// ---------------------------------------------------------------------------
// Stream parsing.
// ---------------------------------------------------------------------------

event::EventStream parse_stream(core::ByteSpan bytes, core::DiagnosticSink& diags,
                                const ParseOptions& opts) {
    event::EventStream stream;

    std::string text = bytes.to_string();
    if (text.empty()) {
        return stream;
    }

    std::vector<std::string> lines = core::split_lines(text);
    stream.reserve(lines.size());

    const core::usize msg_cap = opts.max_field_bytes;

    for (core::usize idx = 0; idx < lines.size(); ++idx) {
        const std::string& raw = lines[idx];
        core::usize record_index = idx + 1;  // 1-based

        core::Result<CefRecord> res = parse_line(raw, opts);

        if (res.ok()) {
            event::LogEvent ev = to_event(res.value(), opts);
            ev.record_index = record_index;
            ev.message = core::truncate(ev.message, msg_cap);
            stream.add(std::move(ev));
            continue;
        }

        // Empty lines are common filler between records; record a placeholder so
        // indices line up with the source artifact but emit no diagnostic flood.
        if (res.code() == core::StatusCode::Empty) {
            event::LogEvent ev;
            ev.source = event::SourceFormat::Unknown;
            ev.record_index = record_index;
            stream.add(std::move(ev));
            continue;
        }

        // A real failure (no "CEF:" marker, truncated header, ...): warn and
        // still emit a best-effort event carrying the raw line as the message so
        // nothing silently vanishes from the timeline.
        diags.warn("cef.line", res.status().to_string(), record_index);

        event::LogEvent ev;
        ev.source = event::SourceFormat::Unknown;
        ev.record_index = record_index;
        ev.message = core::truncate(raw, msg_cap);
        stream.add(std::move(ev));
    }

    return stream;
}

// ---------------------------------------------------------------------------
// Fuzz entry point.
// ---------------------------------------------------------------------------

void fuzz_one(core::ByteSpan bytes) {
    // A small diagnostic cap bounds the sink so a hostile artifact that would
    // otherwise generate millions of warnings cannot exhaust memory.
    core::DiagnosticSink diags(256);
    ParseOptions opts;  // defaults are already bounded.

    event::EventStream stream = parse_stream(bytes, diags, opts);

    // Touch the derived views so the optimiser cannot elide the work and so the
    // summary()/signature() code paths are themselves exercised by the fuzzer.
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

}  // namespace cef
}  // namespace csift
