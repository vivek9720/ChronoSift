#ifndef CSIFT_CORE_ENCODING_HPP
#define CSIFT_CORE_ENCODING_HPP

#include <string>

#include "core/byte_span.hpp"
#include "core/status.hpp"
#include "core/types.hpp"

// Decoders for the transfer encodings that appear inside log artifacts:
// percent-encoding in URLs, hex blobs, base64 structured-data, and UTF-16LE
// strings inside the binary event log. All are bounds-safe and reject invalid
// input rather than guessing.
namespace csift {
namespace core {

// Decodes a single hex nibble; returns -1 for non-hex input.
int hex_nibble(char c) noexcept;

// Lowercase hex string of the bytes (e.g. for hashes/identifiers).
std::string to_hex(ByteSpan bytes);
std::string to_hex(const std::string& bytes);

// Decodes a hex string to raw bytes. Fails on odd length or non-hex chars.
Result<std::string> from_hex(const std::string& text);

// Percent-decoding (URL decoding). Invalid `%` sequences are passed through
// literally rather than dropped, matching how lenient log tooling behaves.
std::string percent_decode(const std::string& text);

// Standard base64 decode. Tolerates missing padding and embedded whitespace;
// fails on invalid alphabet characters.
Result<std::string> base64_decode(const std::string& text);

// Validates that a byte range is well-formed UTF-8. Returns the number of
// decoded code points via `out_codepoints` when non-null.
bool is_valid_utf8(ByteSpan bytes, usize* out_codepoints = nullptr);

// Converts a UTF-16LE byte range (as found in the binary event log) to UTF-8.
// `units` is the number of 16-bit code units to consume. Lone surrogates are
// emitted as U+FFFD rather than rejected, so it never throws on bad input.
std::string utf16le_to_utf8(ByteSpan bytes, usize units);

}  // namespace core
}  // namespace csift

#endif  // CSIFT_CORE_ENCODING_HPP
