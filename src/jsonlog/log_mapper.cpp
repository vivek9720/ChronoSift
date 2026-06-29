#include "jsonlog/log_mapper.hpp"

#include <cstdio>

#include "core/string_util.hpp"
#include "core/time_util.hpp"
#include "event/severity.hpp"

namespace csift {
namespace jsonlog {

namespace {

// Canonical-field alias tables. The first alias that is present on the object
// wins, mirroring how heterogeneous JSON logs label the same concept.
const char* const kTimestampAliases[] = {
    "timestamp", "time", "@timestamp", "ts", "eventTime", "date"};
const char* const kSeverityAliases[] = {"level", "severity", "syslog_level",
                                         "loglevel"};
const char* const kMessageAliases[] = {"message", "msg", "log", "event",
                                       "text"};
const char* const kHostAliases[] = {"host", "hostname", "source_host",
                                    "computer"};
const char* const kAppAliases[] = {"app",     "application", "program",
                                   "service", "logger",      "tag"};
const char* const kUserAliases[] = {"user", "username", "account", "user_name",
                                    "subject"};
const char* const kSrcIpAliases[] = {"src_ip",      "source_ip", "client_ip",
                                     "remote_addr", "ip"};

template <core::usize N>
const JsonValue* probe(const JsonValue& obj, const char* const (&aliases)[N]) {
    for (core::usize i = 0; i < N; ++i) {
        if (const JsonValue* v = obj.find(aliases[i])) return v;
    }
    return nullptr;
}

// Converts a JSON scalar to a FieldValue, preserving its kind. Containers are
// not expected here (they are flattened) but are rendered as a string defensively.
event::FieldValue to_field_value(const JsonValue& v) {
    switch (v.type()) {
        case JsonValue::Type::Bool:
            return event::FieldValue::make_bool(v.as_bool());
        case JsonValue::Type::Int:
            return event::FieldValue::make_int(v.as_int());
        case JsonValue::Type::Double:
            return event::FieldValue::make_double(v.as_double());
        case JsonValue::Type::String:
            return event::FieldValue::make_string(v.as_string());
        case JsonValue::Type::Null:
            return event::FieldValue();
        default:
            return event::FieldValue::make_string(v.to_display_string());
    }
}

std::string index_to_string(core::usize i) {
    char buf[32];
    int n = std::snprintf(buf, sizeof(buf), "%llu",
                          static_cast<unsigned long long>(i));
    if (n <= 0) return std::string("0");
    return std::string(buf, static_cast<core::usize>(n));
}

// Recursively flattens a JSON value into the field map using dotted/indexed
// keys. The tree was built by the depth-limited parser, so recursion is bounded.
void flatten(const JsonValue& v, const std::string& prefix,
             event::FieldMap& fields) {
    switch (v.type()) {
        case JsonValue::Type::Object: {
            const auto& members = v.members();
            if (members.empty()) {
                // Preserve the presence of an empty object as a marker field.
                fields.set(prefix, event::FieldValue::make_string("{}"));
                return;
            }
            for (const auto& m : members) {
                std::string key =
                    prefix.empty() ? m.key : (prefix + "." + m.key);
                flatten(m.value, key, fields);
            }
            return;
        }
        case JsonValue::Type::Array: {
            const auto& items = v.array_items();
            if (items.empty()) {
                fields.set(prefix, event::FieldValue::make_string("[]"));
                return;
            }
            for (core::usize i = 0; i < items.size(); ++i) {
                std::string key = prefix.empty()
                                      ? index_to_string(i)
                                      : (prefix + "." + index_to_string(i));
                flatten(items[i], key, fields);
            }
            return;
        }
        default:
            fields.set(prefix, to_field_value(v));
            return;
    }
}

// Resolves a timestamp from an aliased value: numbers are treated as epoch
// seconds; strings go through the format dispatcher.
core::Timestamp resolve_time(const JsonValue& v, core::i32 assume_year) {
    if (v.is_number()) {
        if (v.type() == JsonValue::Type::Int) {
            return core::Timestamp::from_unix_seconds(v.as_int());
        }
        // Fractional epoch seconds -> microseconds.
        double secs = v.as_double();
        double micros = secs * 1000000.0;
        if (micros >= 9223372036854775807.0) micros = 9223372036854775807.0;
        if (micros <= -9223372036854775808.0) micros = -9223372036854775808.0;
        return core::Timestamp::from_micros(static_cast<core::i64>(micros));
    }
    if (v.is_string()) {
        return core::parse_any_time(v.as_string(), assume_year);
    }
    return core::Timestamp::invalid();
}

// Resolves severity from an aliased value: numeric 0-7 -> syslog severity,
// otherwise the textual word mapper.
event::Severity resolve_severity(const JsonValue& v) {
    if (v.type() == JsonValue::Type::Int) {
        core::i64 n = v.as_int();
        if (n >= 0 && n <= 7) {
            return event::severity_from_syslog(static_cast<core::u32>(n));
        }
        return event::severity_from_word(v.to_display_string());
    }
    if (v.is_string()) {
        // A numeric string severity ("3") is also treated as a syslog level.
        const std::string& s = v.as_string();
        core::i64 n = 0;
        if (core::parse_i64(s, n) && n >= 0 && n <= 7) {
            return event::severity_from_syslog(static_cast<core::u32>(n));
        }
        return event::severity_from_word(s);
    }
    return event::Severity::Unknown;
}

// Extracts the string form of an aliased scalar; containers render compactly.
std::string scalar_text(const JsonValue& v) { return v.to_display_string(); }

}  // namespace

event::LogEvent map_to_event(const JsonValue& value, core::i32 assume_year) {
    event::LogEvent ev;
    ev.source = event::SourceFormat::Json;

    if (!value.is_object()) {
        // Arrays and scalars carry their rendered form as the message.
        ev.message = value.to_display_string();
        return ev;
    }

    if (const JsonValue* v = probe(value, kTimestampAliases)) {
        ev.timestamp = resolve_time(*v, assume_year);
    }
    if (const JsonValue* v = probe(value, kSeverityAliases)) {
        ev.severity = resolve_severity(*v);
    }
    if (const JsonValue* v = probe(value, kMessageAliases)) {
        ev.message = scalar_text(*v);
    }
    if (const JsonValue* v = probe(value, kHostAliases)) {
        ev.host = scalar_text(*v);
    }
    if (const JsonValue* v = probe(value, kAppAliases)) {
        ev.app = scalar_text(*v);
    }
    if (const JsonValue* v = probe(value, kUserAliases)) {
        ev.user = scalar_text(*v);
    }
    if (const JsonValue* v = probe(value, kSrcIpAliases)) {
        ev.src_ip = scalar_text(*v);
    }

    // Flatten every member into the field map for completeness, regardless of
    // whether it was also promoted to a canonical field.
    flatten(value, std::string(), ev.fields);

    return ev;
}

event::EventStream parse_stream(core::ByteSpan bytes, core::DiagnosticSink& diags,
                                const JsonLimits& limits, core::i32 assume_year) {
    event::EventStream stream;
    std::string text = bytes.to_string();
    std::vector<std::string> lines = core::split_lines(text);

    core::usize record_index = 0;
    for (core::usize li = 0; li < lines.size(); ++li) {
        const std::string& raw = lines[li];
        // Skip blank / whitespace-only lines.
        if (core::trim(raw).empty()) continue;

        ++record_index;
        JsonParser parser(limits);
        core::Result<JsonValue> parsed = parser.parse(raw);
        if (parsed.ok()) {
            event::LogEvent ev = map_to_event(parsed.value(), assume_year);
            ev.record_index = record_index;
            stream.add(std::move(ev));
        } else {
            diags.warn("jsonlog.parse",
                       "line failed to parse as JSON: " +
                           parsed.status().message(),
                       li + 1);
            // Raw fallback event so no input line is silently dropped.
            event::LogEvent ev;
            ev.source = event::SourceFormat::Json;
            ev.severity = event::Severity::Unknown;
            ev.message = raw;
            ev.record_index = record_index;
            stream.add(std::move(ev));
        }
    }

    return stream;
}

void fuzz_one(core::ByteSpan bytes) {
    core::DiagnosticSink diags;
    JsonLimits limits;  // defaults bound depth/size/count
    event::EventStream stream = parse_stream(bytes, diags, limits, 1970);
    // Touch derived views to exercise the full pipeline. Volatile sinks keep the
    // compiler from optimising the calls away while never affecting behaviour.
    for (const auto& ev : stream.events()) {
        volatile core::usize a = ev.summary().size();
        volatile core::usize b = ev.signature().size();
        (void)a;
        (void)b;
    }
    (void)diags.size();
}

}  // namespace jsonlog
}  // namespace csift
