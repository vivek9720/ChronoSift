#include "core/byte_reader.hpp"

#include "core/endian.hpp"

namespace csift {
namespace core {

void ByteReader::fail(StatusCode code, const char* what) noexcept {
    if (status_.ok()) {
        status_ = Status(code, what);
    }
}

bool ByteReader::seek(usize offset) noexcept {
    if (offset > span_.size()) {
        pos_ = span_.size();
        fail(StatusCode::Truncated, "seek past end");
        return false;
    }
    pos_ = offset;
    return true;
}

bool ByteReader::skip(usize n) noexcept {
    if (error()) return false;
    if (n > remaining()) {
        pos_ = span_.size();
        fail(StatusCode::Truncated, "skip past end");
        return false;
    }
    pos_ += n;
    return true;
}

u8 ByteReader::read_u8() noexcept {
    if (!can_read(1)) {
        fail(StatusCode::Truncated, "read_u8");
        return 0;
    }
    return span_[pos_++];
}

u16 ByteReader::read_u16_le() noexcept {
    if (!can_read(2)) {
        fail(StatusCode::Truncated, "read_u16_le");
        return 0;
    }
    u16 v = load_u16_le(span_.data() + pos_);
    pos_ += 2;
    return v;
}

u16 ByteReader::read_u16_be() noexcept {
    if (!can_read(2)) {
        fail(StatusCode::Truncated, "read_u16_be");
        return 0;
    }
    u16 v = load_u16_be(span_.data() + pos_);
    pos_ += 2;
    return v;
}

u32 ByteReader::read_u32_le() noexcept {
    if (!can_read(4)) {
        fail(StatusCode::Truncated, "read_u32_le");
        return 0;
    }
    u32 v = load_u32_le(span_.data() + pos_);
    pos_ += 4;
    return v;
}

u32 ByteReader::read_u32_be() noexcept {
    if (!can_read(4)) {
        fail(StatusCode::Truncated, "read_u32_be");
        return 0;
    }
    u32 v = load_u32_be(span_.data() + pos_);
    pos_ += 4;
    return v;
}

u64 ByteReader::read_u64_le() noexcept {
    if (!can_read(8)) {
        fail(StatusCode::Truncated, "read_u64_le");
        return 0;
    }
    u64 v = load_u64_le(span_.data() + pos_);
    pos_ += 8;
    return v;
}

u64 ByteReader::read_u64_be() noexcept {
    if (!can_read(8)) {
        fail(StatusCode::Truncated, "read_u64_be");
        return 0;
    }
    u64 v = load_u64_be(span_.data() + pos_);
    pos_ += 8;
    return v;
}

ByteSpan ByteReader::read_bytes(usize len) noexcept {
    if (len == 0) return ByteSpan();
    if (!can_read(len)) {
        fail(StatusCode::Truncated, "read_bytes");
        return ByteSpan();
    }
    ByteSpan out = span_.subspan(pos_, len);
    pos_ += len;
    return out;
}

std::string ByteReader::read_string(usize len) {
    ByteSpan s = read_bytes(len);
    return s.to_string();
}

u8 ByteReader::peek_u8() const noexcept {
    if (error() || remaining() < 1) return 0;
    return span_[pos_];
}

}  // namespace core
}  // namespace csift
