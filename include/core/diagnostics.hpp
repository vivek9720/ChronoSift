#ifndef CSIFT_CORE_DIAGNOSTICS_HPP
#define CSIFT_CORE_DIAGNOSTICS_HPP

#include <string>
#include <vector>

#include "core/types.hpp"

namespace csift {
namespace core {

// Severity of a diagnostic emitted while parsing. These describe the parser's
// confidence in the artifact, not the security severity of an event (that
// lives on the event model).
enum class DiagLevel {
    Debug = 0,
    Info,
    Warning,
    Error,
};

const char* diag_level_name(DiagLevel level) noexcept;

// A single diagnostic. `where` names the component (e.g. "syslog.header"),
// `detail` is the human message, and `line`/`offset` locate the problem in the
// source artifact when known (0 = unknown).
struct Diagnostic {
    DiagLevel level = DiagLevel::Info;
    std::string where;
    std::string detail;
    usize line = 0;
    usize offset = 0;

    std::string to_string() const;
};

// Collects diagnostics during a parse run. Sinks have an optional cap so a
// hostile artifact that would otherwise generate millions of warnings cannot
// exhaust memory; once the cap is hit further messages are counted but dropped.
class DiagnosticSink {
public:
    DiagnosticSink() = default;
    explicit DiagnosticSink(usize max_entries) : max_entries_(max_entries) {}

    void emit(DiagLevel level, std::string where, std::string detail,
              usize line = 0, usize offset = 0);

    void debug(std::string where, std::string detail, usize line = 0) {
        emit(DiagLevel::Debug, std::move(where), std::move(detail), line);
    }
    void info(std::string where, std::string detail, usize line = 0) {
        emit(DiagLevel::Info, std::move(where), std::move(detail), line);
    }
    void warn(std::string where, std::string detail, usize line = 0) {
        emit(DiagLevel::Warning, std::move(where), std::move(detail), line);
    }
    void error(std::string where, std::string detail, usize line = 0) {
        emit(DiagLevel::Error, std::move(where), std::move(detail), line);
    }

    const std::vector<Diagnostic>& entries() const noexcept { return entries_; }
    usize size() const noexcept { return entries_.size(); }
    usize dropped() const noexcept { return dropped_; }
    bool empty() const noexcept { return entries_.empty(); }

    // Counts of entries at or above a given level, for summary reporting.
    usize count_at_least(DiagLevel level) const noexcept;
    bool has_errors() const noexcept { return count_at_least(DiagLevel::Error) > 0; }

    std::string render() const;

private:
    std::vector<Diagnostic> entries_;
    usize max_entries_ = 4096;
    usize dropped_ = 0;
};

}  // namespace core
}  // namespace csift

#endif  // CSIFT_CORE_DIAGNOSTICS_HPP
