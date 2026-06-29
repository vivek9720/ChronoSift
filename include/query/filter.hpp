#ifndef CSIFT_QUERY_FILTER_HPP
#define CSIFT_QUERY_FILTER_HPP

#include <string>
#include <vector>

#include "core/status.hpp"
#include "core/types.hpp"
#include "event/event.hpp"

// A small filter-expression language for selecting events during triage, e.g.
//   severity>=error AND host=web1 AND message~password
// It supports a fixed set of fields, the operators = != ~ (contains) !~ < <= >
// >=, and AND/OR combination with left-to-right evaluation. The language is
// deliberately tiny and total: any parse error is reported, never thrown.
namespace csift {
namespace query {

enum class Op {
    Eq,        // =
    Ne,        // !=
    Contains,  // ~
    NotContains,  // !~
    Lt,        // <
    Le,        // <=
    Gt,        // >
    Ge,        // >=
};

enum class Conj { And, Or };

// One field-operator-value comparison.
struct Predicate {
    std::string field;  // e.g. "severity", "host", "src_ip", "status", "message", "app", or a fields[] key
    Op op = Op::Eq;
    std::string value;

    // Evaluates this predicate against an event.
    bool matches(const event::LogEvent& e) const;
};

// A conjunction/disjunction of predicates evaluated left to right. Empty filter
// matches everything.
class Filter {
public:
    bool empty() const noexcept { return predicates_.empty(); }
    core::usize size() const noexcept { return predicates_.size(); }

    void add(Predicate p, Conj conj_with_previous);

    // True if `e` satisfies the whole expression.
    bool matches(const event::LogEvent& e) const;

    const std::vector<Predicate>& predicates() const noexcept { return predicates_; }

private:
    std::vector<Predicate> predicates_;
    std::vector<Conj> conjunctions_;  // size == predicates_.size()-1
};

// Compiles a filter expression string. Returns Malformed/InvalidField with a
// helpful message on a bad expression.
core::Result<Filter> parse_filter(const std::string& expr);

// Parses a single operator token at text[pos], advancing pos. Returns false if
// no operator is present. Exposed for testing.
bool parse_op(const std::string& text, core::usize& pos, Op& out);

}  // namespace query
}  // namespace csift

#endif  // CSIFT_QUERY_FILTER_HPP
