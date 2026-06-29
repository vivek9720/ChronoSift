#ifndef CSIFT_CORE_BYTE_READER_HPP
#define CSIFT_CORE_BYTE_READER_HPP

#include <string>

#include "core/byte_span.hpp"
#include "core/status.hpp"
#include "core/types.hpp"

namespace csift {
namespace core {

// A forward cursor over a ByteSpan for the binary parsers (winlog). Every read
// checks the remaining length first; on underflow the reader latches a sticky
// error status and subsequent reads return zero/empty without advancing. This
// lets a decode routine issue a batch of reads and check `error()` once at the
// end instead of branching after every field.
class ByteReader {
public:
    explicit ByteReader(ByteSpan span) noexcept : span_(span), pos_(0) {}

    usize position() const noexcept { return pos_; }
    usize remaining() const noexcept { return pos_ <= span_.size() ? span_.size() - pos_ : 0; }
    bool error() const noexcept { return !status_.ok(); }
    const Status& last_status() const noexcept { return status_; }
    ByteSpan span() const noexcept { return span_; }

    // True if at least `n` more bytes are available from the current position.
    bool can_read(usize n) const noexcept { return !error() && remaining() >= n; }

    // Move the cursor to an absolute offset. Seeking past the end latches an
    // error and clamps the position to the end.
    bool seek(usize offset) noexcept;

    // Advance by `n` bytes. Latches an error on overflow.
    bool skip(usize n) noexcept;

    u8 read_u8() noexcept;
    u16 read_u16_le() noexcept;
    u16 read_u16_be() noexcept;
    u32 read_u32_le() noexcept;
    u32 read_u32_be() noexcept;
    u64 read_u64_le() noexcept;
    u64 read_u64_be() noexcept;

    // Reads `len` raw bytes as a sub-span without copying. On underflow latches
    // an error and returns an empty span.
    ByteSpan read_bytes(usize len) noexcept;

    // Reads a fixed-length field and returns it as a string (e.g. UTF-16LE is
    // handled by callers; this returns the raw bytes interpreted as latin1).
    std::string read_string(usize len);

    // Peeks the next byte without advancing; returns 0 at end of input.
    u8 peek_u8() const noexcept;

private:
    void fail(StatusCode code, const char* what) noexcept;

    ByteSpan span_;
    usize pos_;
    Status status_;
};

}  // namespace core
}  // namespace csift

#endif  // CSIFT_CORE_BYTE_READER_HPP
