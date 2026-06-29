#ifndef CSIFT_CORE_TYPES_HPP
#define CSIFT_CORE_TYPES_HPP

#include <cstddef>
#include <cstdint>

// Fundamental fixed-width aliases used throughout ChronoSift. Keeping them in a
// single header avoids the inconsistent mix of <cstdint> names and bare `int`
// that tends to creep into parsing code and hide truncation bugs.
namespace csift {
namespace core {

using u8 = std::uint8_t;
using u16 = std::uint16_t;
using u32 = std::uint32_t;
using u64 = std::uint64_t;

using i8 = std::int8_t;
using i16 = std::int16_t;
using i32 = std::int32_t;
using i64 = std::int64_t;

using usize = std::size_t;
using byte = std::uint8_t;

// Clamp helper used by the parsers when projecting an untrusted wide value onto
// a narrower field width. Returns `value` bounded to [lo, hi].
template <typename T>
constexpr T clamp_value(T value, T lo, T hi) {
    return value < lo ? lo : (value > hi ? hi : value);
}

// True when adding `a + b` would overflow the unsigned 64-bit range. The binary
// parsers use this before trusting attacker-supplied offset/length pairs.
constexpr bool add_overflows_u64(u64 a, u64 b) {
    return a > (UINT64_MAX - b);
}

}  // namespace core
}  // namespace csift

#endif  // CSIFT_CORE_TYPES_HPP
