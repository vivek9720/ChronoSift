#include "serialize/writer.hpp"

#include <string>
#include <vector>

#include "core/types.hpp"
#include "event/event.hpp"
#include "event/field.hpp"
#include "event/severity.hpp"
#include "event/stream.hpp"

// Implementation of the export serializers. The events fed in here originate
// from parsers that run over untrusted (and during testing, fuzzed) input, so
// every string we touch may be arbitrarily long and may contain arbitrary
// bytes including embedded NULs, control characters and invalid UTF-8. The code
// below is written to be strictly linear in the input size, to never index out
// of bounds, and to avoid recursion entirely: the only nesting we emit is the
// single "fields" object, which is built with a flat loop.
namespace csift {
namespace serialize {

namespace {

// Lowercase hex digit for a 4-bit nibble. Used only for \uXXXX escapes, which
// always cover values < 0x20, so a 16-entry table is plenty.
inline char hex_digit(core::u8 nibble) noexcept {
    static const char kHex[] = "0123456789abcdef";
    return kHex[nibble & 0x0F];
}

// Appends the six-character JSON escape \u00XX for a control byte. Control
// bytes are always <= 0x1F here, so the two high hex digits are always "00",
// but we compute all four nibbles for clarity and safety.
void append_u_escape(std::string& out, core::u8 byte) {
    out += "\\u";
    out.push_back(hex_digit(static_cast<core::u8>((byte >> 12) & 0x0F)));
    out.push_back(hex_digit(static_cast<core::u8>((byte >> 8) & 0x0F)));
    out.push_back(hex_digit(static_cast<core::u8>((byte >> 4) & 0x0F)));
    out.push_back(hex_digit(static_cast<core::u8>(byte & 0x0F)));
}

// Appends a JSON string literal, including the surrounding double quotes, with
// the body escaped. Kept separate from json_escape so the object builder can
// emit a quoted value without an extra temporary allocation.
void append_json_string(std::string& out, const std::string& s) {
    out.push_back('"');
    out += json_escape(s);
    out.push_back('"');
}

// Appends `"key":` for an object member. The key is a fixed, known-safe ASCII
// literal in every call site, but we still route it through the escaper so the
// output stays valid even if a key ever changes.
void append_json_key(std::string& out, const char* key) {
    out.push_back('"');
    out += json_escape(std::string(key));
    out += "\":";
}

// Emits a string-valued member: `"key":"escaped value"`. The caller is
// responsible for any leading comma separator.
void append_string_member(std::string& out, const char* key,
                          const std::string& value) {
    append_json_key(out, key);
    append_json_string(out, value);
}

// Emits a numeric member: `"key":number`. The value is rendered with
// std::to_string, which produces a bare decimal integer with no locale
// grouping, so it is always valid JSON.
template <typename Int>
void append_number_member(std::string& out, const char* key, Int value) {
    append_json_key(out, key);
    out += std::to_string(value);
}

}  // namespace

std::string json_escape(const std::string& s) {
    std::string out;
    // The escaped form is at least as long as the input; reserve up front so a
    // worst-case all-control-byte string (6x growth) still amortizes to linear.
    out.reserve(s.size() + s.size() / 8 + 8);
    for (core::usize i = 0; i < s.size(); ++i) {
        // Treat the byte as unsigned so values >= 0x80 are not seen as
        // negative chars; we pass those through verbatim per the contract.
        const core::u8 c = static_cast<core::u8>(s[i]);
        switch (c) {
            case '"':
                out += "\\\"";
                break;
            case '\\':
                out += "\\\\";
                break;
            case '\b':
                out += "\\b";
                break;
            case '\f':
                out += "\\f";
                break;
            case '\n':
                out += "\\n";
                break;
            case '\r':
                out += "\\r";
                break;
            case '\t':
                out += "\\t";
                break;
            default:
                if (c < 0x20) {
                    // Any other C0 control: emit the full \uXXXX form.
                    append_u_escape(out, c);
                } else {
                    // Printable ASCII and all high bytes (UTF-8 / latin1) pass
                    // through unchanged: we do not re-encode.
                    out.push_back(static_cast<char>(c));
                }
                break;
        }
    }
    return out;
}

std::string csv_quote(const std::string& s) {
    // Determine whether the field needs quoting at all: only when it contains a
    // separator, a quote, or a line break (RFC 4180 section 2.6).
    bool needs_quote = false;
    for (core::usize i = 0; i < s.size(); ++i) {
        const char c = s[i];
        if (c == ',' || c == '"' || c == '\r' || c == '\n') {
            needs_quote = true;
            break;
        }
    }
    if (!needs_quote) {
        return s;
    }

    std::string out;
    // Reserve for the two surrounding quotes plus a little slack for doubled
    // quotes; if the field is mostly quotes this still stays linear.
    out.reserve(s.size() + s.size() / 8 + 2);
    out.push_back('"');
    for (core::usize i = 0; i < s.size(); ++i) {
        const char c = s[i];
        if (c == '"') {
            // Embedded double-quote is escaped by doubling it.
            out += "\"\"";
        } else {
            out.push_back(c);
        }
    }
    out.push_back('"');
    return out;
}

// The canonical column order, shared by csv_header and to_csv so the two can
// never drift apart. Defined once here as the single source of truth.
namespace {
const char* const kCsvColumns[] = {
    "timestamp", "severity",    "source",      "record_index", "host",
    "app",       "pid",         "user",        "src_ip",       "dst_ip",
    "src_port",  "dst_port",    "http_method", "http_path",    "http_status",
    "bytes",     "event_id",    "channel",     "provider",     "message",
};
const core::usize kCsvColumnCount = sizeof(kCsvColumns) / sizeof(kCsvColumns[0]);
}  // namespace

std::string csv_header() {
    std::string out;
    for (core::usize i = 0; i < kCsvColumnCount; ++i) {
        if (i != 0) out.push_back(',');
        // Header names are fixed ASCII identifiers with no specials, but quote
        // them defensively so the header obeys the same rules as the rows.
        out += csv_quote(std::string(kCsvColumns[i]));
    }
    return out;
}

std::string event_to_json(const event::LogEvent& e) {
    std::string out;
    // A modest reservation; the object grows linearly with the event's strings.
    out.reserve(256);
    out.push_back('{');

    // Tracks whether a comma separator is needed before the next member. Using
    // a flag (rather than trimming a trailing comma) keeps the output exactly
    // right even when every optional field is omitted.
    bool first = true;
    auto sep = [&out, &first]() {
        if (!first) out.push_back(',');
        first = false;
    };

    // --- Always-present-ish leading keys, in canonical order. ---

    // timestamp: only when a parseable time was recovered.
    if (e.timestamp.valid) {
        sep();
        append_string_member(out, "timestamp", e.timestamp.to_iso8601());
    }

    // severity and source are always emitted; they are enumerations that always
    // have a defined name (including "unknown"), and they anchor every record.
    sep();
    append_string_member(out, "severity", event::severity_name(e.severity));

    sep();
    append_string_member(out, "source", event::source_format_name(e.source));

    // record_index is the locator back into the source artifact; always useful.
    sep();
    append_number_member(out, "record_index", e.record_index);

    // --- Optional fields, omitted when empty / default, in canonical order. ---

    if (!e.host.empty()) {
        sep();
        append_string_member(out, "host", e.host);
    }
    if (!e.app.empty()) {
        sep();
        append_string_member(out, "app", e.app);
    }
    if (e.pid >= 0) {
        // pid == -1 is the "unknown" sentinel; only emit a real pid.
        sep();
        append_number_member(out, "pid", e.pid);
    }
    if (!e.user.empty()) {
        sep();
        append_string_member(out, "user", e.user);
    }
    if (!e.src_ip.empty()) {
        sep();
        append_string_member(out, "src_ip", e.src_ip);
    }
    if (!e.dst_ip.empty()) {
        sep();
        append_string_member(out, "dst_ip", e.dst_ip);
    }
    if (e.src_port != 0) {
        sep();
        append_number_member(out, "src_port", e.src_port);
    }
    if (e.dst_port != 0) {
        sep();
        append_number_member(out, "dst_port", e.dst_port);
    }
    if (!e.http_method.empty()) {
        sep();
        append_string_member(out, "http_method", e.http_method);
    }
    if (!e.http_path.empty()) {
        sep();
        append_string_member(out, "http_path", e.http_path);
    }
    if (e.http_status != 0) {
        sep();
        append_number_member(out, "http_status", e.http_status);
    }
    if (e.bytes != 0) {
        sep();
        append_number_member(out, "bytes", e.bytes);
    }
    if (e.event_id != 0) {
        sep();
        append_number_member(out, "event_id", e.event_id);
    }
    if (!e.channel.empty()) {
        sep();
        append_string_member(out, "channel", e.channel);
    }
    if (!e.provider.empty()) {
        sep();
        append_string_member(out, "provider", e.provider);
    }
    if (!e.message.empty()) {
        sep();
        append_string_member(out, "message", e.message);
    }

    // --- Nested "fields" object, only when there is at least one entry. ---
    const std::vector<event::FieldMap::Entry>& entries = e.fields.entries();
    if (!entries.empty()) {
        sep();
        append_json_key(out, "fields");
        out.push_back('{');
        // Flat (non-recursive) iteration. Every value is rendered to its
        // display string and emitted as a JSON string, even numeric kinds, so
        // the nested object is uniformly typed and round-trips losslessly as
        // text. Insertion order is preserved by FieldMap, so we keep it.
        bool first_field = true;
        for (core::usize i = 0; i < entries.size(); ++i) {
            const event::FieldMap::Entry& entry = entries[i];
            if (!first_field) out.push_back(',');
            first_field = false;
            append_json_string(out, entry.key);
            out.push_back(':');
            append_json_string(out, entry.value.to_string());
        }
        out.push_back('}');
    }

    out.push_back('}');
    return out;
}

std::string to_ndjson(const event::EventStream& stream) {
    const std::vector<event::LogEvent>& events = stream.events();
    std::string out;
    if (events.empty()) {
        // An empty stream produces an empty document (no stray newline).
        return out;
    }
    // Rough reservation to cut reallocations on large streams; the real size is
    // dominated by per-event string content, which we cannot predict here.
    out.reserve(events.size() * 96);
    for (core::usize i = 0; i < events.size(); ++i) {
        if (i != 0) out.push_back('\n');
        out += event_to_json(events[i]);
    }
    // Trailing newline so the file is a clean sequence of complete lines, which
    // is what line-oriented consumers (jq -c, grep, SIEM ingest) expect.
    out.push_back('\n');
    return out;
}

namespace {

// Builds one CSV row in the canonical column order. Each cell is csv_quote'd.
// Numeric zeros are rendered as empty cells (our consistent choice), and the
// unknown-pid sentinel and invalid timestamp likewise produce empty cells, so
// "no value" reads the same across every column.
void append_csv_row(std::string& out, const event::LogEvent& e) {
    // Small helpers so the column list below reads as a flat, ordered sequence
    // that visibly matches kCsvColumns / csv_header.
    bool first = true;
    auto cell_str = [&out, &first](const std::string& v) {
        if (!first) out.push_back(',');
        first = false;
        out += csv_quote(v);
    };
    auto cell_raw = [&cell_str](const char* v) { cell_str(std::string(v)); };
    // A number cell: empty when the value is zero, else its decimal form.
    auto cell_num = [&cell_str](core::u64 v) {
        cell_str(v == 0 ? std::string() : std::to_string(v));
    };

    // 1. timestamp -- ISO-8601 when valid, empty otherwise.
    cell_str(e.timestamp.valid ? e.timestamp.to_iso8601() : std::string());
    // 2. severity, 3. source -- always-defined enum names.
    cell_raw(event::severity_name(e.severity));
    cell_raw(event::source_format_name(e.source));
    // 4. record_index -- a position; emit literally even when zero so the
    //    locator column is never silently blank for the first record.
    cell_str(std::to_string(e.record_index));
    // 5. host, 6. app.
    cell_str(e.host);
    cell_str(e.app);
    // 7. pid -- empty for the -1 unknown sentinel, else the decimal value.
    cell_str(e.pid < 0 ? std::string() : std::to_string(e.pid));
    // 8. user, 9. src_ip, 10. dst_ip.
    cell_str(e.user);
    cell_str(e.src_ip);
    cell_str(e.dst_ip);
    // 11. src_port, 12. dst_port -- zero means "not set".
    cell_num(e.src_port);
    cell_num(e.dst_port);
    // 13. http_method, 14. http_path.
    cell_str(e.http_method);
    cell_str(e.http_path);
    // 15. http_status, 16. bytes.
    cell_num(e.http_status);
    cell_num(e.bytes);
    // 17. event_id.
    cell_num(e.event_id);
    // 18. channel, 19. provider, 20. message.
    cell_str(e.channel);
    cell_str(e.provider);
    cell_str(e.message);
}

}  // namespace

std::string to_csv(const event::EventStream& stream) {
    const std::vector<event::LogEvent>& events = stream.events();
    std::string out = csv_header();
    out.push_back('\n');
    out.reserve(out.size() + events.size() * 96);
    for (core::usize i = 0; i < events.size(); ++i) {
        append_csv_row(out, events[i]);
        // Every row, including the last, is newline-terminated so the table is
        // a clean set of complete records even when concatenated or appended.
        out.push_back('\n');
    }
    return out;
}

}  // namespace serialize
}  // namespace csift
