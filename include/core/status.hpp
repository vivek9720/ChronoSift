#ifndef CSIFT_CORE_STATUS_HPP
#define CSIFT_CORE_STATUS_HPP

#include <string>
#include <utility>

#include "core/types.hpp"

namespace csift {
namespace core {

// Coarse outcome classes shared by every parser. They map cleanly onto the
// kinds of failure an analyst cares about: structurally broken input, input
// that ran out before a record completed, or a field that violated a format
// invariant.
enum class StatusCode {
    Ok = 0,
    Truncated,        // ran out of bytes before a record/field completed
    Malformed,        // structurally invalid (bad magic, framing, syntax)
    InvalidField,     // a field was present but failed validation
    Unsupported,      // a recognised but unimplemented variant/version
    LimitExceeded,    // a safety limit (depth, count, size) was hit
    Empty,            // nothing to parse
};

const char* status_code_name(StatusCode code) noexcept;

// A status carries a code plus a short human-readable context string. It is
// deliberately cheap to copy and construct so it can be returned by value from
// the deep call chains in the parsers.
class Status {
public:
    Status() : code_(StatusCode::Ok) {}
    Status(StatusCode code, std::string message)
        : code_(code), message_(std::move(message)) {}
    explicit Status(StatusCode code) : code_(code) {}

    StatusCode code() const noexcept { return code_; }
    bool ok() const noexcept { return code_ == StatusCode::Ok; }
    const std::string& message() const noexcept { return message_; }

    std::string to_string() const;

private:
    StatusCode code_;
    std::string message_;
};

// A value-or-status result. Avoids exceptions on the parsing hot paths while
// still letting callers distinguish the failure mode. `T` must be default
// constructible; the contained value is meaningful only when ok().
template <typename T>
class Result {
public:
    Result(T value) : status_(), value_(std::move(value)) {}
    Result(Status status) : status_(std::move(status)), value_() {}
    Result(StatusCode code, std::string message)
        : status_(code, std::move(message)), value_() {}

    static Result success(T value) { return Result(std::move(value)); }
    static Result failure(StatusCode code, std::string message) {
        return Result(Status(code, std::move(message)));
    }

    bool ok() const noexcept { return status_.ok(); }
    const Status& status() const noexcept { return status_; }
    StatusCode code() const noexcept { return status_.code(); }

    // Valid only when ok(); callers check ok() first.
    T& value() noexcept { return value_; }
    const T& value() const noexcept { return value_; }

    // Returns the value if present, otherwise the supplied fallback.
    T value_or(T fallback) const { return ok() ? value_ : std::move(fallback); }

private:
    Status status_;
    T value_;
};

}  // namespace core
}  // namespace csift

#endif  // CSIFT_CORE_STATUS_HPP
