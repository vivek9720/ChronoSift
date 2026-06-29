#ifndef CSIFT_JSONLOG_JSON_PARSER_HPP
#define CSIFT_JSONLOG_JSON_PARSER_HPP

#include <string>

#include "core/status.hpp"
#include "core/types.hpp"
#include "jsonlog/json_value.hpp"

namespace csift {
namespace jsonlog {

// Limits enforced by the parser to keep adversarial input bounded. Exceeding
// any of them yields StatusCode::LimitExceeded rather than unbounded recursion
// or allocation.
struct JsonLimits {
    core::usize max_depth = 64;
    core::usize max_array_items = 1u << 16;
    core::usize max_object_members = 1u << 16;
    core::usize max_string_bytes = 1u << 20;
    core::usize max_total_values = 1u << 20;
};

// A recursive-descent JSON parser with explicit depth/size limits. It accepts
// the standard JSON grammar (RFC 8259) including escaped strings, exponents,
// and unicode escapes with surrogate pairs. The depth limit is enforced before
// each descent so deeply nested input cannot overflow the stack.
class JsonParser {
public:
    explicit JsonParser(const JsonLimits& limits = JsonLimits())
        : limits_(limits) {}

    // Parses a single JSON document from `text`. Trailing non-whitespace after
    // the value is reported as Malformed.
    core::Result<JsonValue> parse(const std::string& text);

private:
    core::Result<JsonValue> parse_value(const std::string& s, core::usize& pos,
                                         core::usize depth);
    core::Result<JsonValue> parse_string(const std::string& s, core::usize& pos);
    core::Result<JsonValue> parse_number(const std::string& s, core::usize& pos);
    core::Result<JsonValue> parse_array(const std::string& s, core::usize& pos,
                                        core::usize depth);
    core::Result<JsonValue> parse_object(const std::string& s, core::usize& pos,
                                          core::usize depth);
    void skip_ws(const std::string& s, core::usize& pos);

    JsonLimits limits_;
    core::usize total_values_ = 0;
};

}  // namespace jsonlog
}  // namespace csift

#endif  // CSIFT_JSONLOG_JSON_PARSER_HPP
