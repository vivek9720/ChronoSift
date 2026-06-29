#include "core/diagnostics.hpp"

namespace csift {
namespace core {

const char* diag_level_name(DiagLevel level) noexcept {
    switch (level) {
        case DiagLevel::Debug: return "debug";
        case DiagLevel::Info: return "info";
        case DiagLevel::Warning: return "warning";
        case DiagLevel::Error: return "error";
    }
    return "?";
}

std::string Diagnostic::to_string() const {
    std::string out = "[";
    out += diag_level_name(level);
    out += "] ";
    out += where;
    if (line != 0) {
        out += " (line ";
        out += std::to_string(line);
        if (offset != 0) {
            out += ", offset ";
            out += std::to_string(offset);
        }
        out += ")";
    } else if (offset != 0) {
        out += " (offset ";
        out += std::to_string(offset);
        out += ")";
    }
    out += ": ";
    out += detail;
    return out;
}

void DiagnosticSink::emit(DiagLevel level, std::string where, std::string detail,
                          usize line, usize offset) {
    if (entries_.size() >= max_entries_) {
        ++dropped_;
        return;
    }
    Diagnostic d;
    d.level = level;
    d.where = std::move(where);
    d.detail = std::move(detail);
    d.line = line;
    d.offset = offset;
    entries_.push_back(std::move(d));
}

usize DiagnosticSink::count_at_least(DiagLevel level) const noexcept {
    usize n = 0;
    for (const Diagnostic& d : entries_) {
        if (static_cast<int>(d.level) >= static_cast<int>(level)) ++n;
    }
    return n;
}

std::string DiagnosticSink::render() const {
    std::string out;
    for (const Diagnostic& d : entries_) {
        out += d.to_string();
        out += '\n';
    }
    if (dropped_ != 0) {
        out += "... ";
        out += std::to_string(dropped_);
        out += " further diagnostic(s) suppressed\n";
    }
    return out;
}

}  // namespace core
}  // namespace csift
