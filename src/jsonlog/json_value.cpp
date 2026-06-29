#include "jsonlog/json_value.hpp"

#include <cstdio>

namespace csift {
namespace jsonlog {

// ---------------------------------------------------------------------------
// Factories
// ---------------------------------------------------------------------------

JsonValue JsonValue::make_bool(bool b) {
    JsonValue v;
    v.type_ = Type::Bool;
    v.bool_ = b;
    return v;
}

JsonValue JsonValue::make_int(core::i64 value) {
    JsonValue v;
    v.type_ = Type::Int;
    v.int_ = value;
    // Keep the double mirror in sync so as_double() is exact for in-range ints.
    v.dbl_ = static_cast<double>(value);
    return v;
}

JsonValue JsonValue::make_double(double value) {
    JsonValue v;
    v.type_ = Type::Double;
    v.dbl_ = value;
    return v;
}

JsonValue JsonValue::make_string(std::string s) {
    JsonValue v;
    v.type_ = Type::String;
    v.str_ = std::move(s);
    return v;
}

JsonValue JsonValue::make_array() {
    JsonValue v;
    v.type_ = Type::Array;
    return v;
}

JsonValue JsonValue::make_object() {
    JsonValue v;
    v.type_ = Type::Object;
    return v;
}

// ---------------------------------------------------------------------------
// Numeric accessors
// ---------------------------------------------------------------------------

core::i64 JsonValue::as_int() const noexcept {
    switch (type_) {
        case Type::Int:
            return int_;
        case Type::Double: {
            // Truncate towards zero, but guard against values outside the i64
            // range so the cast is well-defined (no UB on overflow).
            double d = dbl_;
            if (d >= 9223372036854775807.0) return INT64_MAX;
            if (d <= -9223372036854775808.0) return INT64_MIN;
            return static_cast<core::i64>(d);
        }
        case Type::Bool:
            return bool_ ? 1 : 0;
        default:
            return 0;
    }
}

double JsonValue::as_double() const noexcept {
    switch (type_) {
        case Type::Double:
            return dbl_;
        case Type::Int:
            return static_cast<double>(int_);
        case Type::Bool:
            return bool_ ? 1.0 : 0.0;
        default:
            return 0.0;
    }
}

// ---------------------------------------------------------------------------
// Mutators
// ---------------------------------------------------------------------------

void JsonValue::push_back(JsonValue v) {
    // Pushing into a non-array promotes the node to an array so the parser and
    // callers never silently drop data.
    if (type_ != Type::Array) {
        type_ = Type::Array;
        array_.clear();
    }
    array_.push_back(std::move(v));
}

void JsonValue::set_member(std::string key, JsonValue v) {
    if (type_ != Type::Object) {
        type_ = Type::Object;
        members_.clear();
    }
    for (auto& m : members_) {
        if (m.key == key) {
            m.value = std::move(v);
            return;
        }
    }
    Member m;
    m.key = std::move(key);
    m.value = std::move(v);
    members_.push_back(std::move(m));
}

const JsonValue* JsonValue::find(const std::string& key) const noexcept {
    if (type_ != Type::Object) return nullptr;
    for (const auto& m : members_) {
        if (m.key == key) return &m.value;
    }
    return nullptr;
}

// ---------------------------------------------------------------------------
// Rendering
// ---------------------------------------------------------------------------

namespace {

// Renders a double compactly. JSON numbers are decimal; we use %g but fall back
// to a representation that round-trips integral doubles without a decimal point
// surprising the reader.
std::string render_double(double d) {
    char buf[64];
    // 17 significant digits round-trips any IEEE-754 double.
    int n = std::snprintf(buf, sizeof(buf), "%.17g", d);
    if (n <= 0) return std::string("0");
    if (static_cast<core::usize>(n) >= sizeof(buf)) n = sizeof(buf) - 1;
    return std::string(buf, static_cast<core::usize>(n));
}

std::string render_int(core::i64 v) {
    char buf[32];
    int n = std::snprintf(buf, sizeof(buf), "%lld", static_cast<long long>(v));
    if (n <= 0) return std::string("0");
    if (static_cast<core::usize>(n) >= sizeof(buf)) n = sizeof(buf) - 1;
    return std::string(buf, static_cast<core::usize>(n));
}

// Appends `s` as a JSON string literal (with surrounding quotes) to `out`,
// escaping the characters the grammar requires.
void append_json_quoted(std::string& out, const std::string& s) {
    out.push_back('"');
    for (unsigned char c : s) {
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
                    static const char* hexd = "0123456789abcdef";
                    out += "\\u00";
                    out.push_back(hexd[(c >> 4) & 0xf]);
                    out.push_back(hexd[c & 0xf]);
                } else {
                    out.push_back(static_cast<char>(c));
                }
                break;
        }
    }
    out.push_back('"');
}

void render_compact(const JsonValue& v, std::string& out);

void render_array(const JsonValue& v, std::string& out) {
    out.push_back('[');
    const auto& items = v.array_items();
    for (core::usize i = 0; i < items.size(); ++i) {
        if (i) out.push_back(',');
        render_compact(items[i], out);
    }
    out.push_back(']');
}

void render_object(const JsonValue& v, std::string& out) {
    out.push_back('{');
    const auto& members = v.members();
    for (core::usize i = 0; i < members.size(); ++i) {
        if (i) out.push_back(',');
        append_json_quoted(out, members[i].key);
        out.push_back(':');
        render_compact(members[i].value, out);
    }
    out.push_back('}');
}

void render_compact(const JsonValue& v, std::string& out) {
    switch (v.type()) {
        case JsonValue::Type::Null:
            out += "null";
            break;
        case JsonValue::Type::Bool:
            out += v.as_bool() ? "true" : "false";
            break;
        case JsonValue::Type::Int:
            out += render_int(v.as_int());
            break;
        case JsonValue::Type::Double:
            out += render_double(v.as_double());
            break;
        case JsonValue::Type::String:
            append_json_quoted(out, v.as_string());
            break;
        case JsonValue::Type::Array:
            render_array(v, out);
            break;
        case JsonValue::Type::Object:
            render_object(v, out);
            break;
    }
}

}  // namespace

std::string JsonValue::to_display_string() const {
    switch (type_) {
        case Type::Null:
            return "null";
        case Type::Bool:
            return bool_ ? "true" : "false";
        case Type::Int:
            return render_int(int_);
        case Type::Double:
            return render_double(dbl_);
        case Type::String:
            // Scalars render to their plain text, not a quoted literal.
            return str_;
        case Type::Array:
        case Type::Object: {
            std::string out;
            render_compact(*this, out);
            return out;
        }
    }
    return std::string();
}

// ---------------------------------------------------------------------------
// Depth
// ---------------------------------------------------------------------------

core::usize JsonValue::depth() const {
    // Scalars (and empty containers) have depth 1; a container is one deeper
    // than its deepest child. The tree was built by a depth-limited parser, so
    // this recursion is bounded and cannot overflow the stack.
    switch (type_) {
        case Type::Array: {
            core::usize deepest = 0;
            for (const auto& item : array_) {
                core::usize d = item.depth();
                if (d > deepest) deepest = d;
            }
            return deepest + 1;
        }
        case Type::Object: {
            core::usize deepest = 0;
            for (const auto& m : members_) {
                core::usize d = m.value.depth();
                if (d > deepest) deepest = d;
            }
            return deepest + 1;
        }
        default:
            return 1;
    }
}

}  // namespace jsonlog
}  // namespace csift
