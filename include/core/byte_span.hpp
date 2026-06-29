#ifndef CSIFT_CORE_BYTE_SPAN_HPP
#define CSIFT_CORE_BYTE_SPAN_HPP

#include <string>

#include "core/types.hpp"

namespace csift {
namespace core {

// A non-owning view over a contiguous run of bytes. Every accessor is
// bounds-checked or returns a safe default; the class never reads past the
// window it was given, which is the property the fuzz harnesses lean on.
class ByteSpan {
public:
    ByteSpan() noexcept : data_(nullptr), size_(0) {}
    ByteSpan(const byte* data, usize size) noexcept
        : data_(size ? data : nullptr), size_(data ? size : 0) {}

    static ByteSpan from_string(const std::string& s) noexcept {
        return ByteSpan(reinterpret_cast<const byte*>(s.data()), s.size());
    }

    const byte* data() const noexcept { return data_; }
    usize size() const noexcept { return size_; }
    bool empty() const noexcept { return size_ == 0; }

    // Unchecked element access; callers must have validated the index. Used on
    // hot paths after an explicit bounds check.
    byte operator[](usize i) const noexcept { return data_[i]; }

    // Bounds-checked element access. Returns 0 when out of range so a missing
    // byte never turns into an out-of-bounds read.
    byte at(usize i) const noexcept { return i < size_ ? data_[i] : 0; }

    // Returns the sub-range [offset, offset+len). Any portion outside the span
    // is silently clipped, so the result is always a valid view.
    ByteSpan subspan(usize offset, usize len) const noexcept {
        if (offset >= size_) return ByteSpan();
        usize avail = size_ - offset;
        if (len > avail) len = avail;
        return ByteSpan(data_ + offset, len);
    }

    // Everything from `offset` to the end (clipped).
    ByteSpan from(usize offset) const noexcept {
        if (offset >= size_) return ByteSpan();
        return ByteSpan(data_ + offset, size_ - offset);
    }

    // The first `len` bytes (clipped to the available size).
    ByteSpan first(usize len) const noexcept {
        return ByteSpan(data_, len < size_ ? len : size_);
    }

    std::string to_string() const {
        if (!data_ || size_ == 0) return std::string();
        return std::string(reinterpret_cast<const char*>(data_), size_);
    }

    const byte* begin() const noexcept { return data_; }
    const byte* end() const noexcept { return data_ + size_; }

    // Lexicographic comparison against a NUL-terminated literal, used by the
    // binary parsers to test fixed magic markers without constructing strings.
    bool starts_with(const char* literal) const noexcept {
        usize i = 0;
        for (; literal[i] != '\0'; ++i) {
            if (i >= size_) return false;
            if (data_[i] != static_cast<byte>(literal[i])) return false;
        }
        return true;
    }

private:
    const byte* data_;
    usize size_;
};

}  // namespace core
}  // namespace csift

#endif  // CSIFT_CORE_BYTE_SPAN_HPP
