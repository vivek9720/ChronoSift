#ifndef CSIFT_CORE_ENDIAN_HPP
#define CSIFT_CORE_ENDIAN_HPP

#include "core/types.hpp"

// Endian load helpers that read from a raw pointer the caller has already
// bounds-checked. They assemble values byte-by-byte rather than reinterpreting
// memory, so they are alignment-safe and independent of host endianness.
namespace csift {
namespace core {

inline u16 load_u16_le(const byte* p) noexcept {
    return static_cast<u16>(p[0]) | (static_cast<u16>(p[1]) << 8);
}

inline u16 load_u16_be(const byte* p) noexcept {
    return static_cast<u16>(p[1]) | (static_cast<u16>(p[0]) << 8);
}

inline u32 load_u32_le(const byte* p) noexcept {
    return static_cast<u32>(p[0]) | (static_cast<u32>(p[1]) << 8) |
           (static_cast<u32>(p[2]) << 16) | (static_cast<u32>(p[3]) << 24);
}

inline u32 load_u32_be(const byte* p) noexcept {
    return static_cast<u32>(p[3]) | (static_cast<u32>(p[2]) << 8) |
           (static_cast<u32>(p[1]) << 16) | (static_cast<u32>(p[0]) << 24);
}

inline u64 load_u64_le(const byte* p) noexcept {
    u64 lo = load_u32_le(p);
    u64 hi = load_u32_le(p + 4);
    return lo | (hi << 32);
}

inline u64 load_u64_be(const byte* p) noexcept {
    u64 hi = load_u32_be(p);
    u64 lo = load_u32_be(p + 4);
    return (hi << 32) | lo;
}

}  // namespace core
}  // namespace csift

#endif  // CSIFT_CORE_ENDIAN_HPP
