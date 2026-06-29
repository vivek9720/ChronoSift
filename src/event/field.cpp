#include "event/field.hpp"

#include <cstdio>

namespace csift {
namespace event {

std::string FieldValue::to_string() const {
    switch (kind_) {
        case Kind::Null:
            return std::string();
        case Kind::String:
            return str_;
        case Kind::Int:
            return std::to_string(int_);
        case Kind::Double: {
            char buf[32];
            std::snprintf(buf, sizeof(buf), "%g", dbl_);
            return std::string(buf);
        }
        case Kind::Bool:
            return bool_ ? "true" : "false";
    }
    return std::string();
}

void FieldMap::set(const std::string& key, FieldValue value) {
    for (Entry& e : entries_) {
        if (e.key == key) {
            e.value = std::move(value);
            return;
        }
    }
    entries_.push_back(Entry{key, std::move(value)});
}

bool FieldMap::has(const std::string& key) const noexcept {
    return find(key) != nullptr;
}

const FieldValue* FieldMap::find(const std::string& key) const noexcept {
    for (const Entry& e : entries_) {
        if (e.key == key) return &e.value;
    }
    return nullptr;
}

std::string FieldMap::get_string(const std::string& key,
                                 const std::string& fallback) const {
    const FieldValue* v = find(key);
    if (!v) return fallback;
    return v->to_string();
}

}  // namespace event
}  // namespace csift
