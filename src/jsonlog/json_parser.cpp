#include "jsonlog/json_parser.hpp"

#include <cstdlib>

#include "core/encoding.hpp"
#include "core/string_util.hpp"

namespace csift {
namespace jsonlog {

namespace {

using core::StatusCode;

// Appends the UTF-8 encoding of a code point. Mirrors core::encoding's private
// helper; kept local so the parser owns its surrogate-pair logic end to end.
void append_utf8(std::string& out, core::u32 cp) {
    if (cp < 0x80) {
        out.push_back(static_cast<char>(cp));
    } else if (cp < 0x800) {
        out.push_back(static_cast<char>(0xc0 | (cp >> 6)));
        out.push_back(static_cast<char>(0x80 | (cp & 0x3f)));
    } else if (cp < 0x10000) {
        out.push_back(static_cast<char>(0xe0 | (cp >> 12)));
        out.push_back(static_cast<char>(0x80 | ((cp >> 6) & 0x3f)));
        out.push_back(static_cast<char>(0x80 | (cp & 0x3f)));
    } else {
        out.push_back(static_cast<char>(0xf0 | (cp >> 18)));
        out.push_back(static_cast<char>(0x80 | ((cp >> 12) & 0x3f)));
        out.push_back(static_cast<char>(0x80 | ((cp >> 6) & 0x3f)));
        out.push_back(static_cast<char>(0x80 | (cp & 0x3f)));
    }
}

// Reads exactly four hex digits at s[pos..pos+4) into `out`. Advances `pos` past
// them on success. Returns false (without advancing) when fewer than four hex
// digits are available.
bool read_hex4(const std::string& s, core::usize& pos, core::u32& out) {
    if (pos + 4 > s.size()) return false;
    core::u32 value = 0;
    for (core::usize k = 0; k < 4; ++k) {
        int nib = core::hex_nibble(s[pos + k]);
        if (nib < 0) return false;
        value = (value << 4) | static_cast<core::u32>(nib);
    }
    pos += 4;
    out = value;
    return true;
}

}  // namespace

core::Result<JsonValue> JsonParser::parse(const std::string& text) {
    total_values_ = 0;
    core::usize pos = 0;
    skip_ws(text, pos);
    if (pos >= text.size()) {
        return core::Result<JsonValue>::failure(StatusCode::Empty,
                                                "no JSON value present");
    }
    core::Result<JsonValue> value = parse_value(text, pos, 0);
    if (!value.ok()) return value;
    skip_ws(text, pos);
    if (pos != text.size()) {
        return core::Result<JsonValue>::failure(
            StatusCode::Malformed, "trailing data after JSON value");
    }
    return value;
}

void JsonParser::skip_ws(const std::string& s, core::usize& pos) {
    // RFC 8259 whitespace: space, tab, LF, CR only.
    while (pos < s.size()) {
        char c = s[pos];
        if (c == ' ' || c == '\t' || c == '\n' || c == '\r') {
            ++pos;
        } else {
            break;
        }
    }
}

core::Result<JsonValue> JsonParser::parse_value(const std::string& s,
                                                core::usize& pos,
                                                core::usize depth) {
    // Enforce the depth limit before descending so deeply nested input can
    // never grow the C++ call stack without bound.
    if (depth > limits_.max_depth) {
        return core::Result<JsonValue>::failure(StatusCode::LimitExceeded,
                                                "maximum nesting depth exceeded");
    }
    // Every value (scalar or container) counts towards the total-values budget.
    if (++total_values_ > limits_.max_total_values) {
        return core::Result<JsonValue>::failure(StatusCode::LimitExceeded,
                                                "maximum total values exceeded");
    }

    skip_ws(s, pos);
    if (pos >= s.size()) {
        return core::Result<JsonValue>::failure(StatusCode::Truncated,
                                                "expected a value, found end");
    }

    char c = s[pos];
    switch (c) {
        case '{':
            return parse_object(s, pos, depth);
        case '[':
            return parse_array(s, pos, depth);
        case '"':
            return parse_string(s, pos);
        case 't':
            if (pos + 4 <= s.size() && s.compare(pos, 4, "true") == 0) {
                pos += 4;
                return core::Result<JsonValue>(JsonValue::make_bool(true));
            }
            return core::Result<JsonValue>::failure(StatusCode::Malformed,
                                                    "invalid literal");
        case 'f':
            if (pos + 5 <= s.size() && s.compare(pos, 5, "false") == 0) {
                pos += 5;
                return core::Result<JsonValue>(JsonValue::make_bool(false));
            }
            return core::Result<JsonValue>::failure(StatusCode::Malformed,
                                                    "invalid literal");
        case 'n':
            if (pos + 4 <= s.size() && s.compare(pos, 4, "null") == 0) {
                pos += 4;
                return core::Result<JsonValue>(JsonValue::make_null());
            }
            return core::Result<JsonValue>::failure(StatusCode::Malformed,
                                                    "invalid literal");
        default:
            if (c == '-' || (c >= '0' && c <= '9')) {
                return parse_number(s, pos);
            }
            return core::Result<JsonValue>::failure(StatusCode::Malformed,
                                                    "unexpected character");
    }
}

core::Result<JsonValue> JsonParser::parse_string(const std::string& s,
                                                 core::usize& pos) {
    // Caller guarantees s[pos] == '"'.
    ++pos;  // consume opening quote
    std::string out;
    while (pos < s.size()) {
        unsigned char c = static_cast<unsigned char>(s[pos]);
        if (c == '"') {
            ++pos;  // consume closing quote
            if (out.size() > limits_.max_string_bytes) {
                return core::Result<JsonValue>::failure(
                    StatusCode::LimitExceeded, "string exceeds byte limit");
            }
            return core::Result<JsonValue>(JsonValue::make_string(std::move(out)));
        }
        if (c == '\\') {
            ++pos;  // consume backslash
            if (pos >= s.size()) {
                return core::Result<JsonValue>::failure(
                    StatusCode::Truncated, "unterminated escape in string");
            }
            char esc = s[pos];
            switch (esc) {
                case '"':
                    out.push_back('"');
                    ++pos;
                    break;
                case '\\':
                    out.push_back('\\');
                    ++pos;
                    break;
                case '/':
                    out.push_back('/');
                    ++pos;
                    break;
                case 'b':
                    out.push_back('\b');
                    ++pos;
                    break;
                case 'f':
                    out.push_back('\f');
                    ++pos;
                    break;
                case 'n':
                    out.push_back('\n');
                    ++pos;
                    break;
                case 'r':
                    out.push_back('\r');
                    ++pos;
                    break;
                case 't':
                    out.push_back('\t');
                    ++pos;
                    break;
                case 'u': {
                    ++pos;  // consume 'u'
                    core::u32 cp = 0;
                    if (!read_hex4(s, pos, cp)) {
                        return core::Result<JsonValue>::failure(
                            StatusCode::Malformed,
                            "invalid \\u escape in string");
                    }
                    if (cp >= 0xd800 && cp <= 0xdbff) {
                        // High surrogate: must be followed by \uXXXX low
                        // surrogate to form a valid pair.
                        if (pos + 2 <= s.size() && s[pos] == '\\' &&
                            s[pos + 1] == 'u') {
                            core::usize after = pos + 2;
                            core::u32 lo = 0;
                            if (read_hex4(s, after, lo) && lo >= 0xdc00 &&
                                lo <= 0xdfff) {
                                core::u32 combined =
                                    0x10000 + ((cp - 0xd800) << 10) +
                                    (lo - 0xdc00);
                                append_utf8(out, combined);
                                pos = after;
                                break;
                            }
                        }
                        // Lone high surrogate -> replacement character.
                        append_utf8(out, 0xfffd);
                    } else if (cp >= 0xdc00 && cp <= 0xdfff) {
                        // Lone low surrogate -> replacement character.
                        append_utf8(out, 0xfffd);
                    } else {
                        append_utf8(out, cp);
                    }
                    break;
                }
                default:
                    return core::Result<JsonValue>::failure(
                        StatusCode::Malformed, "invalid escape in string");
            }
        } else if (c < 0x20) {
            // Raw control characters are not allowed inside JSON strings.
            return core::Result<JsonValue>::failure(
                StatusCode::Malformed, "control character in string");
        } else {
            out.push_back(static_cast<char>(c));
            ++pos;
        }
        // Bound the working buffer eagerly so a huge string is rejected before
        // it is fully materialised.
        if (out.size() > limits_.max_string_bytes) {
            return core::Result<JsonValue>::failure(
                StatusCode::LimitExceeded, "string exceeds byte limit");
        }
    }
    return core::Result<JsonValue>::failure(StatusCode::Truncated,
                                            "unterminated string");
}

core::Result<JsonValue> JsonParser::parse_number(const std::string& s,
                                                 core::usize& pos) {
    core::usize start = pos;
    bool is_double = false;

    // Optional minus.
    if (pos < s.size() && s[pos] == '-') ++pos;

    // Integer part: a single 0, or [1-9] followed by digits.
    if (pos >= s.size()) {
        return core::Result<JsonValue>::failure(StatusCode::Malformed,
                                                "invalid number");
    }
    if (s[pos] == '0') {
        ++pos;
    } else if (s[pos] >= '1' && s[pos] <= '9') {
        while (pos < s.size() && s[pos] >= '0' && s[pos] <= '9') ++pos;
    } else {
        return core::Result<JsonValue>::failure(StatusCode::Malformed,
                                                "invalid number");
    }

    // Fractional part.
    if (pos < s.size() && s[pos] == '.') {
        is_double = true;
        ++pos;
        if (pos >= s.size() || !(s[pos] >= '0' && s[pos] <= '9')) {
            return core::Result<JsonValue>::failure(
                StatusCode::Malformed, "missing fraction digits");
        }
        while (pos < s.size() && s[pos] >= '0' && s[pos] <= '9') ++pos;
    }

    // Exponent part.
    if (pos < s.size() && (s[pos] == 'e' || s[pos] == 'E')) {
        is_double = true;
        ++pos;
        if (pos < s.size() && (s[pos] == '+' || s[pos] == '-')) ++pos;
        if (pos >= s.size() || !(s[pos] >= '0' && s[pos] <= '9')) {
            return core::Result<JsonValue>::failure(
                StatusCode::Malformed, "missing exponent digits");
        }
        while (pos < s.size() && s[pos] >= '0' && s[pos] <= '9') ++pos;
    }

    std::string token = s.substr(start, pos - start);

    if (!is_double) {
        core::i64 iv = 0;
        if (core::parse_i64(token, iv)) {
            return core::Result<JsonValue>(JsonValue::make_int(iv));
        }
        // Integer that does not fit i64 (e.g. very long digit run) falls back to
        // a double so the value is preserved approximately rather than lost.
        is_double = true;
    }

    // strtod over the validated token. The token is a syntactically valid JSON
    // number, so strtod consumes all of it; we still pass a null-terminated copy.
    const char* cstr = token.c_str();
    char* endp = nullptr;
    double dv = std::strtod(cstr, &endp);
    if (endp == cstr) {
        return core::Result<JsonValue>::failure(StatusCode::Malformed,
                                                "unparseable number");
    }
    return core::Result<JsonValue>(JsonValue::make_double(dv));
}

core::Result<JsonValue> JsonParser::parse_array(const std::string& s,
                                                core::usize& pos,
                                                core::usize depth) {
    // Caller guarantees s[pos] == '['.
    ++pos;  // consume '['
    JsonValue arr = JsonValue::make_array();

    skip_ws(s, pos);
    if (pos < s.size() && s[pos] == ']') {
        ++pos;
        return core::Result<JsonValue>(std::move(arr));
    }

    core::usize count = 0;
    while (true) {
        if (count >= limits_.max_array_items) {
            return core::Result<JsonValue>::failure(
                StatusCode::LimitExceeded, "array exceeds item limit");
        }
        core::Result<JsonValue> elem = parse_value(s, pos, depth + 1);
        if (!elem.ok()) return elem;
        arr.push_back(std::move(elem.value()));
        ++count;

        skip_ws(s, pos);
        if (pos >= s.size()) {
            return core::Result<JsonValue>::failure(
                StatusCode::Truncated, "unterminated array");
        }
        if (s[pos] == ',') {
            ++pos;
            skip_ws(s, pos);
            // A trailing comma before ']' is malformed JSON.
            if (pos < s.size() && s[pos] == ']') {
                return core::Result<JsonValue>::failure(
                    StatusCode::Malformed, "trailing comma in array");
            }
            continue;
        }
        if (s[pos] == ']') {
            ++pos;
            return core::Result<JsonValue>(std::move(arr));
        }
        return core::Result<JsonValue>::failure(
            StatusCode::Malformed, "expected ',' or ']' in array");
    }
}

core::Result<JsonValue> JsonParser::parse_object(const std::string& s,
                                                 core::usize& pos,
                                                 core::usize depth) {
    // Caller guarantees s[pos] == '{'.
    ++pos;  // consume '{'
    JsonValue obj = JsonValue::make_object();

    skip_ws(s, pos);
    if (pos < s.size() && s[pos] == '}') {
        ++pos;
        return core::Result<JsonValue>(std::move(obj));
    }

    core::usize count = 0;
    while (true) {
        if (count >= limits_.max_object_members) {
            return core::Result<JsonValue>::failure(
                StatusCode::LimitExceeded, "object exceeds member limit");
        }
        skip_ws(s, pos);
        if (pos >= s.size() || s[pos] != '"') {
            return core::Result<JsonValue>::failure(
                StatusCode::Malformed, "expected string key in object");
        }
        core::Result<JsonValue> key = parse_string(s, pos);
        if (!key.ok()) return key;

        skip_ws(s, pos);
        if (pos >= s.size() || s[pos] != ':') {
            return core::Result<JsonValue>::failure(
                StatusCode::Malformed, "expected ':' after object key");
        }
        ++pos;  // consume ':'

        core::Result<JsonValue> val = parse_value(s, pos, depth + 1);
        if (!val.ok()) return val;
        obj.set_member(key.value().as_string(), std::move(val.value()));
        ++count;

        skip_ws(s, pos);
        if (pos >= s.size()) {
            return core::Result<JsonValue>::failure(
                StatusCode::Truncated, "unterminated object");
        }
        if (s[pos] == ',') {
            ++pos;
            skip_ws(s, pos);
            if (pos < s.size() && s[pos] == '}') {
                return core::Result<JsonValue>::failure(
                    StatusCode::Malformed, "trailing comma in object");
            }
            continue;
        }
        if (s[pos] == '}') {
            ++pos;
            return core::Result<JsonValue>(std::move(obj));
        }
        return core::Result<JsonValue>::failure(
            StatusCode::Malformed, "expected ',' or '}' in object");
    }
}

}  // namespace jsonlog
}  // namespace csift
