#include "core/string_util.hpp"

namespace csift {
namespace core {

char ascii_to_lower(char c) noexcept {
    return (c >= 'A' && c <= 'Z') ? static_cast<char>(c - 'A' + 'a') : c;
}

char ascii_to_upper(char c) noexcept {
    return (c >= 'a' && c <= 'z') ? static_cast<char>(c - 'a' + 'A') : c;
}

std::string to_lower(const std::string& s) {
    std::string out;
    out.reserve(s.size());
    for (char c : s) out.push_back(ascii_to_lower(c));
    return out;
}

std::string to_upper(const std::string& s) {
    std::string out;
    out.reserve(s.size());
    for (char c : s) out.push_back(ascii_to_upper(c));
    return out;
}

bool ascii_iequals(const std::string& a, const std::string& b) noexcept {
    if (a.size() != b.size()) return false;
    for (usize i = 0; i < a.size(); ++i) {
        if (ascii_to_lower(a[i]) != ascii_to_lower(b[i])) return false;
    }
    return true;
}

bool is_space(char c) noexcept {
    return c == ' ' || c == '\t' || c == '\r' || c == '\n' || c == '\v' || c == '\f';
}

bool is_digit(char c) noexcept { return c >= '0' && c <= '9'; }

bool is_hex_digit(char c) noexcept {
    return is_digit(c) || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F');
}

bool is_alpha(char c) noexcept {
    return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z');
}

bool is_alnum(char c) noexcept { return is_alpha(c) || is_digit(c); }

std::string trim_left(const std::string& s) {
    usize i = 0;
    while (i < s.size() && is_space(s[i])) ++i;
    return s.substr(i);
}

std::string trim_right(const std::string& s) {
    usize n = s.size();
    while (n > 0 && is_space(s[n - 1])) --n;
    return s.substr(0, n);
}

std::string trim(const std::string& s) {
    usize i = 0;
    usize n = s.size();
    while (i < n && is_space(s[i])) ++i;
    while (n > i && is_space(s[n - 1])) --n;
    return s.substr(i, n - i);
}

bool starts_with(const std::string& s, const std::string& prefix) noexcept {
    return s.size() >= prefix.size() &&
           s.compare(0, prefix.size(), prefix) == 0;
}

bool ends_with(const std::string& s, const std::string& suffix) noexcept {
    return s.size() >= suffix.size() &&
           s.compare(s.size() - suffix.size(), suffix.size(), suffix) == 0;
}

bool contains(const std::string& s, const std::string& needle) noexcept {
    return s.find(needle) != std::string::npos;
}

std::vector<std::string> split(const std::string& s, char delim, bool skip_empty,
                               usize max_splits) {
    std::vector<std::string> out;
    usize start = 0;
    usize splits = 0;
    for (usize i = 0; i < s.size(); ++i) {
        if (s[i] == delim && (max_splits == 0 || splits < max_splits)) {
            std::string field = s.substr(start, i - start);
            if (!skip_empty || !field.empty()) out.push_back(std::move(field));
            start = i + 1;
            ++splits;
        }
    }
    std::string last = s.substr(start);
    if (!skip_empty || !last.empty()) out.push_back(std::move(last));
    return out;
}

std::vector<std::string> split_whitespace(const std::string& s) {
    std::vector<std::string> out;
    usize i = 0;
    while (i < s.size()) {
        while (i < s.size() && is_space(s[i])) ++i;
        if (i >= s.size()) break;
        usize start = i;
        while (i < s.size() && !is_space(s[i])) ++i;
        out.push_back(s.substr(start, i - start));
    }
    return out;
}

std::vector<std::string> split_lines(const std::string& s) {
    std::vector<std::string> out;
    usize start = 0;
    for (usize i = 0; i < s.size(); ++i) {
        if (s[i] == '\n') {
            usize end = i;
            if (end > start && s[end - 1] == '\r') --end;
            out.push_back(s.substr(start, end - start));
            start = i + 1;
        }
    }
    if (start < s.size()) {
        usize end = s.size();
        if (end > start && s[end - 1] == '\r') --end;
        out.push_back(s.substr(start, end - start));
    }
    return out;
}

std::string join(const std::vector<std::string>& parts, const std::string& sep) {
    std::string out;
    for (usize i = 0; i < parts.size(); ++i) {
        if (i) out += sep;
        out += parts[i];
    }
    return out;
}

std::string replace_all(const std::string& s, const std::string& from,
                        const std::string& to) {
    if (from.empty()) return s;
    std::string out;
    usize pos = 0;
    while (true) {
        usize found = s.find(from, pos);
        if (found == std::string::npos) {
            out.append(s, pos, std::string::npos);
            break;
        }
        out.append(s, pos, found - pos);
        out += to;
        pos = found + from.size();
    }
    return out;
}

bool parse_u64(const std::string& s, u64& out) noexcept {
    if (s.empty()) return false;
    u64 value = 0;
    for (char c : s) {
        if (!is_digit(c)) return false;
        u64 digit = static_cast<u64>(c - '0');
        if (value > (UINT64_MAX - digit) / 10) return false;  // overflow
        value = value * 10 + digit;
    }
    out = value;
    return true;
}

bool parse_i64(const std::string& s, i64& out) noexcept {
    if (s.empty()) return false;
    bool neg = false;
    usize i = 0;
    if (s[0] == '+' || s[0] == '-') {
        neg = (s[0] == '-');
        i = 1;
    }
    if (i >= s.size()) return false;
    u64 mag = 0;
    for (; i < s.size(); ++i) {
        if (!is_digit(s[i])) return false;
        u64 digit = static_cast<u64>(s[i] - '0');
        if (mag > (UINT64_MAX - digit) / 10) return false;
        mag = mag * 10 + digit;
    }
    // Bound magnitude to the signed range.
    if (neg) {
        if (mag > static_cast<u64>(INT64_MAX) + 1) return false;
        out = (mag == static_cast<u64>(INT64_MAX) + 1)
                  ? INT64_MIN
                  : -static_cast<i64>(mag);
    } else {
        if (mag > static_cast<u64>(INT64_MAX)) return false;
        out = static_cast<i64>(mag);
    }
    return true;
}

std::string sanitize_printable(const std::string& s) {
    std::string out;
    out.reserve(s.size());
    for (unsigned char c : s) {
        if (c == '\t') {
            out += "\\t";
        } else if (c == '\n') {
            out += "\\n";
        } else if (c == '\r') {
            out += "\\r";
        } else if (c >= 0x20 && c < 0x7f) {
            out.push_back(static_cast<char>(c));
        } else {
            static const char* hexd = "0123456789abcdef";
            out += "\\x";
            out.push_back(hexd[(c >> 4) & 0xf]);
            out.push_back(hexd[c & 0xf]);
        }
    }
    return out;
}

std::string truncate(const std::string& s, usize max) {
    if (s.size() <= max) return s;
    if (max <= 3) return s.substr(0, max);
    return s.substr(0, max - 3) + "...";
}

}  // namespace core
}  // namespace csift
