#include "core/encoding.hpp"

#include "core/string_util.hpp"

namespace csift {
namespace core {

int hex_nibble(char c) noexcept {
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}

static const char* kHexLower = "0123456789abcdef";

std::string to_hex(ByteSpan bytes) {
    std::string out;
    out.reserve(bytes.size() * 2);
    for (usize i = 0; i < bytes.size(); ++i) {
        byte b = bytes[i];
        out.push_back(kHexLower[(b >> 4) & 0xf]);
        out.push_back(kHexLower[b & 0xf]);
    }
    return out;
}

std::string to_hex(const std::string& bytes) {
    return to_hex(ByteSpan::from_string(bytes));
}

Result<std::string> from_hex(const std::string& text) {
    if (text.size() % 2 != 0) {
        return Result<std::string>::failure(StatusCode::InvalidField,
                                            "hex string has odd length");
    }
    std::string out;
    out.reserve(text.size() / 2);
    for (usize i = 0; i + 1 < text.size(); i += 2) {
        int hi = hex_nibble(text[i]);
        int lo = hex_nibble(text[i + 1]);
        if (hi < 0 || lo < 0) {
            return Result<std::string>::failure(StatusCode::InvalidField,
                                                "non-hex character");
        }
        out.push_back(static_cast<char>((hi << 4) | lo));
    }
    return Result<std::string>(std::move(out));
}

std::string percent_decode(const std::string& text) {
    std::string out;
    out.reserve(text.size());
    for (usize i = 0; i < text.size(); ++i) {
        char c = text[i];
        if (c == '%' && i + 2 < text.size()) {
            int hi = hex_nibble(text[i + 1]);
            int lo = hex_nibble(text[i + 2]);
            if (hi >= 0 && lo >= 0) {
                out.push_back(static_cast<char>((hi << 4) | lo));
                i += 2;
                continue;
            }
        } else if (c == '+') {
            out.push_back(' ');
            continue;
        }
        out.push_back(c);
    }
    return out;
}

static int base64_value(char c) noexcept {
    if (c >= 'A' && c <= 'Z') return c - 'A';
    if (c >= 'a' && c <= 'z') return c - 'a' + 26;
    if (c >= '0' && c <= '9') return c - '0' + 52;
    if (c == '+') return 62;
    if (c == '/') return 63;
    return -1;
}

Result<std::string> base64_decode(const std::string& text) {
    std::string out;
    out.reserve(text.size() / 4 * 3 + 3);
    u32 acc = 0;
    int bits = 0;
    usize seen = 0;
    for (char c : text) {
        if (is_space(c)) continue;
        if (c == '=') break;  // padding: stop accumulating
        int v = base64_value(c);
        if (v < 0) {
            return Result<std::string>::failure(StatusCode::InvalidField,
                                                "invalid base64 character");
        }
        acc = (acc << 6) | static_cast<u32>(v);
        bits += 6;
        ++seen;
        if (bits >= 8) {
            bits -= 8;
            out.push_back(static_cast<char>((acc >> bits) & 0xff));
        }
    }
    // A single leftover sextet cannot form a byte and indicates corruption.
    if (seen % 4 == 1) {
        return Result<std::string>::failure(StatusCode::InvalidField,
                                            "truncated base64 group");
    }
    return Result<std::string>(std::move(out));
}

bool is_valid_utf8(ByteSpan bytes, usize* out_codepoints) {
    usize i = 0;
    usize cps = 0;
    const usize n = bytes.size();
    while (i < n) {
        byte b = bytes[i];
        usize extra;
        u32 cp;
        u32 min_cp;
        if (b < 0x80) {
            ++i;
            ++cps;
            continue;
        } else if ((b & 0xe0) == 0xc0) {
            extra = 1;
            cp = b & 0x1f;
            min_cp = 0x80;
        } else if ((b & 0xf0) == 0xe0) {
            extra = 2;
            cp = b & 0x0f;
            min_cp = 0x800;
        } else if ((b & 0xf8) == 0xf0) {
            extra = 3;
            cp = b & 0x07;
            min_cp = 0x10000;
        } else {
            return false;  // invalid lead byte
        }
        if (i + extra >= n) return false;  // truncated sequence
        for (usize k = 1; k <= extra; ++k) {
            byte cb = bytes[i + k];
            if ((cb & 0xc0) != 0x80) return false;  // bad continuation
            cp = (cp << 6) | (cb & 0x3f);
        }
        if (cp < min_cp) return false;             // overlong encoding
        if (cp > 0x10ffff) return false;           // out of range
        if (cp >= 0xd800 && cp <= 0xdfff) return false;  // surrogate
        i += extra + 1;
        ++cps;
    }
    if (out_codepoints) *out_codepoints = cps;
    return true;
}

static void append_utf8(std::string& out, u32 cp) {
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

std::string utf16le_to_utf8(ByteSpan bytes, usize units) {
    std::string out;
    // Each unit needs 2 bytes; clip to what is actually present.
    usize avail_units = bytes.size() / 2;
    if (units > avail_units) units = avail_units;
    usize i = 0;
    while (i < units) {
        u32 w = static_cast<u32>(bytes[i * 2]) |
                (static_cast<u32>(bytes[i * 2 + 1]) << 8);
        if (w >= 0xd800 && w <= 0xdbff) {
            // High surrogate: needs a following low surrogate.
            if (i + 1 < units) {
                u32 w2 = static_cast<u32>(bytes[(i + 1) * 2]) |
                         (static_cast<u32>(bytes[(i + 1) * 2 + 1]) << 8);
                if (w2 >= 0xdc00 && w2 <= 0xdfff) {
                    u32 cp = 0x10000 + ((w - 0xd800) << 10) + (w2 - 0xdc00);
                    append_utf8(out, cp);
                    i += 2;
                    continue;
                }
            }
            append_utf8(out, 0xfffd);  // lone high surrogate
            ++i;
        } else if (w >= 0xdc00 && w <= 0xdfff) {
            append_utf8(out, 0xfffd);  // lone low surrogate
            ++i;
        } else {
            append_utf8(out, w);
            ++i;
        }
    }
    return out;
}

}  // namespace core
}  // namespace csift
