#ifndef CSIFT_CORE_STRING_UTIL_HPP
#define CSIFT_CORE_STRING_UTIL_HPP

#include <string>
#include <vector>

#include "core/types.hpp"

// Small, allocation-conscious string helpers shared by the text parsers. They
// are written against std::string only (no locale dependence) so behaviour is
// deterministic across platforms.
namespace csift {
namespace core {

// ASCII case folding; bytes outside a-z/A-Z are passed through unchanged.
char ascii_to_lower(char c) noexcept;
char ascii_to_upper(char c) noexcept;
std::string to_lower(const std::string& s);
std::string to_upper(const std::string& s);

bool ascii_iequals(const std::string& a, const std::string& b) noexcept;

// Whitespace = space, tab, CR, LF, vertical tab, form feed.
bool is_space(char c) noexcept;
bool is_digit(char c) noexcept;
bool is_hex_digit(char c) noexcept;
bool is_alpha(char c) noexcept;
bool is_alnum(char c) noexcept;

std::string trim_left(const std::string& s);
std::string trim_right(const std::string& s);
std::string trim(const std::string& s);

bool starts_with(const std::string& s, const std::string& prefix) noexcept;
bool ends_with(const std::string& s, const std::string& suffix) noexcept;
bool contains(const std::string& s, const std::string& needle) noexcept;

// Splits on a single delimiter. Empty fields are preserved unless
// `skip_empty` is set. `max_splits` of 0 means unlimited.
std::vector<std::string> split(const std::string& s, char delim,
                               bool skip_empty = false, usize max_splits = 0);

// Splits on runs of whitespace, never producing empty fields. Useful for the
// space-delimited classic log formats.
std::vector<std::string> split_whitespace(const std::string& s);

// Splits text into lines, handling LF and CRLF. The terminators are stripped.
std::vector<std::string> split_lines(const std::string& s);

std::string join(const std::vector<std::string>& parts, const std::string& sep);

std::string replace_all(const std::string& s, const std::string& from,
                        const std::string& to);

// Parses an unsigned decimal integer with overflow protection. Returns false
// if the whole string is not a valid number or it overflows u64.
bool parse_u64(const std::string& s, u64& out) noexcept;

// Parses a signed decimal integer with overflow protection.
bool parse_i64(const std::string& s, i64& out) noexcept;

// Replaces non-printable bytes with a visible escape so untrusted log text can
// be displayed without corrupting a terminal.
std::string sanitize_printable(const std::string& s);

// Truncates `s` to at most `max` characters, appending an ellipsis marker when
// it had to cut. Used to keep report fields bounded.
std::string truncate(const std::string& s, usize max);

}  // namespace core
}  // namespace csift

#endif  // CSIFT_CORE_STRING_UTIL_HPP
