#ifndef CSIFT_JSONLOG_JSON_VALUE_HPP
#define CSIFT_JSONLOG_JSON_VALUE_HPP

#include <memory>
#include <string>
#include <vector>

#include "core/types.hpp"

namespace csift {
namespace jsonlog {

// A parsed JSON value. Objects and arrays own their children via the node's own
// storage, so a JsonValue is a self-contained tree. Numbers are kept both as a
// double and, when integral, as an i64 so log fields like ports and ids do not
// lose precision.
class JsonValue {
public:
    enum class Type { Null, Bool, Int, Double, String, Array, Object };

    // Defined after the class, once JsonValue is a complete type.
    struct Member;

    JsonValue() : type_(Type::Null) {}

    static JsonValue make_null() { return JsonValue(); }
    static JsonValue make_bool(bool b);
    static JsonValue make_int(core::i64 v);
    static JsonValue make_double(double v);
    static JsonValue make_string(std::string s);
    static JsonValue make_array();
    static JsonValue make_object();

    Type type() const noexcept { return type_; }
    bool is_object() const noexcept { return type_ == Type::Object; }
    bool is_array() const noexcept { return type_ == Type::Array; }
    bool is_string() const noexcept { return type_ == Type::String; }
    bool is_number() const noexcept {
        return type_ == Type::Int || type_ == Type::Double;
    }
    bool is_bool() const noexcept { return type_ == Type::Bool; }
    bool is_null() const noexcept { return type_ == Type::Null; }

    bool as_bool() const noexcept { return bool_; }
    core::i64 as_int() const noexcept;
    double as_double() const noexcept;
    const std::string& as_string() const noexcept { return str_; }

    // Mutators used by the parser while building the tree.
    void push_back(JsonValue v);
    void set_member(std::string key, JsonValue v);

    const std::vector<JsonValue>& array_items() const noexcept { return array_; }
    const std::vector<Member>& members() const noexcept { return members_; }

    // Object lookup by key; returns nullptr when absent or not an object.
    const JsonValue* find(const std::string& key) const noexcept;

    // Renders any scalar to a string; objects/arrays render to a compact form.
    std::string to_display_string() const;

    // Maximum nesting depth of this subtree (1 for a scalar).
    core::usize depth() const;

private:
    Type type_;
    bool bool_ = false;
    core::i64 int_ = 0;
    double dbl_ = 0.0;
    std::string str_;
    std::vector<JsonValue> array_;
    std::vector<Member> members_;
};

// Now that JsonValue is complete, the object member can hold one by value.
struct JsonValue::Member {
    std::string key;
    JsonValue value;
};

}  // namespace jsonlog
}  // namespace csift

#endif  // CSIFT_JSONLOG_JSON_VALUE_HPP
