#ifndef CSIFT_EVENT_FIELD_HPP
#define CSIFT_EVENT_FIELD_HPP

#include <string>
#include <vector>

#include "core/types.hpp"

namespace csift {
namespace event {

// The dynamic value type carried by extracted fields. Logs are schemaless, so a
// field can be a string, an integer, a floating value, or a boolean. The variant
// is hand-rolled (rather than std::variant) to keep a stable, copyable layout
// and a small, explicit API the analysis code can rely on.
class FieldValue {
public:
    enum class Kind { Null, String, Int, Double, Bool };

    FieldValue() : kind_(Kind::Null), int_(0), dbl_(0), bool_(false) {}

    static FieldValue make_string(std::string s) {
        FieldValue v;
        v.kind_ = Kind::String;
        v.str_ = std::move(s);
        return v;
    }
    static FieldValue make_int(core::i64 i) {
        FieldValue v;
        v.kind_ = Kind::Int;
        v.int_ = i;
        return v;
    }
    static FieldValue make_double(double d) {
        FieldValue v;
        v.kind_ = Kind::Double;
        v.dbl_ = d;
        return v;
    }
    static FieldValue make_bool(bool b) {
        FieldValue v;
        v.kind_ = Kind::Bool;
        v.bool_ = b;
        return v;
    }

    Kind kind() const noexcept { return kind_; }
    bool is_null() const noexcept { return kind_ == Kind::Null; }
    bool is_string() const noexcept { return kind_ == Kind::String; }
    bool is_int() const noexcept { return kind_ == Kind::Int; }

    const std::string& as_string_ref() const noexcept { return str_; }
    core::i64 as_int() const noexcept { return int_; }
    double as_double() const noexcept { return dbl_; }
    bool as_bool() const noexcept { return bool_; }

    // Renders any kind to a display string.
    std::string to_string() const;

private:
    Kind kind_;
    std::string str_;
    core::i64 int_;
    double dbl_;
    bool bool_;
};

// An ordered key/value collection. Order is preserved (insertion order) so a
// round-tripped record keeps its field order, which matters for diffing logs.
// Lookups are case-sensitive on the key as stored.
class FieldMap {
public:
    struct Entry {
        std::string key;
        FieldValue value;
    };

    void set(const std::string& key, FieldValue value);
    void set_string(const std::string& key, std::string value) {
        set(key, FieldValue::make_string(std::move(value)));
    }
    void set_int(const std::string& key, core::i64 value) {
        set(key, FieldValue::make_int(value));
    }

    bool has(const std::string& key) const noexcept;
    const FieldValue* find(const std::string& key) const noexcept;

    // Returns the string form of a field, or `fallback` when absent.
    std::string get_string(const std::string& key,
                           const std::string& fallback = std::string()) const;

    const std::vector<Entry>& entries() const noexcept { return entries_; }
    core::usize size() const noexcept { return entries_.size(); }
    bool empty() const noexcept { return entries_.empty(); }

    void clear() { entries_.clear(); }

private:
    std::vector<Entry> entries_;
};

}  // namespace event
}  // namespace csift

#endif  // CSIFT_EVENT_FIELD_HPP
