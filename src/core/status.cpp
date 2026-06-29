#include "core/status.hpp"

namespace csift {
namespace core {

const char* status_code_name(StatusCode code) noexcept {
    switch (code) {
        case StatusCode::Ok: return "ok";
        case StatusCode::Truncated: return "truncated";
        case StatusCode::Malformed: return "malformed";
        case StatusCode::InvalidField: return "invalid-field";
        case StatusCode::Unsupported: return "unsupported";
        case StatusCode::LimitExceeded: return "limit-exceeded";
        case StatusCode::Empty: return "empty";
    }
    return "unknown";
}

std::string Status::to_string() const {
    std::string out = status_code_name(code_);
    if (!message_.empty()) {
        out += ": ";
        out += message_;
    }
    return out;
}

}  // namespace core
}  // namespace csift
