#include "query/filter.hpp"

#include "core/string_util.hpp"
#include "event/field.hpp"
#include "event/severity.hpp"

// Implementation of ChronoSift's tiny filter-expression language. The grammar
// is:
//
//   filter    := <empty> | predicate ( (AND|OR) predicate )*
//   predicate := field SP* op SP* value
//   field     := [A-Za-z0-9_.\[\]]+
//   op        := "!=" | "!~" | "<=" | ">=" | "=" | "~" | "<" | ">"
//   value     := quoted | bare
//   quoted    := '"' ( '\\' any | not('"') )* '"'
//   bare      := not(SP)+
//
// The parser and every evaluator are total: malformed input is reported as a
// core::Result failure and matches() never throws, even on hostile field names,
// huge values, or unterminated quotes. All indexing is explicitly bounds
// checked because the expression and the event strings can be attacker
// controlled (the language is used in interactive tools and is fuzz tested).
namespace csift {
namespace query {

namespace {

// AND/OR keywords are matched case-insensitively as whole whitespace-delimited
// tokens. The literals are short so a direct compare is cheaper than building a
// lowered copy of every token.
const char kKwAnd[] = "AND";
const char kKwOr[] = "OR";

// Upper bound on the number of predicates a single expression may contain. A
// generous limit that still prevents a pathological expression from forcing an
// unbounded amount of work or allocation.
constexpr core::usize kMaxPredicates = 256;

// Upper bound on a single field or value token. Untrusted input should not be
// able to make us materialise an arbitrarily large token; real field names and
// filter values are tiny.
constexpr core::usize kMaxTokenLen = 4096;

bool is_field_char(char c) noexcept {
    // Field names accept identifier characters plus '.', '[' and ']' so dotted
    // and bracketed FieldMap keys (e.g. "winlog.event_data[0]") are addressable.
    return core::is_alnum(c) || c == '_' || c == '.' || c == '[' || c == ']';
}

// Compares a substring of `text` starting at `pos` of length `len` against the
// keyword `kw` (a NUL-terminated literal) case-insensitively. Used so AND/OR
// recognition never copies.
bool token_iequals(const std::string& text, core::usize pos, core::usize len,
                   const char* kw) noexcept {
    core::usize i = 0;
    for (; i < len; ++i) {
        char k = kw[i];
        if (k == '\0') return false;  // token longer than keyword
        if (core::ascii_to_lower(text[pos + i]) != core::ascii_to_lower(k)) {
            return false;
        }
    }
    return kw[i] == '\0';  // keyword fully consumed
}

// Advances `pos` past any run of whitespace. Bounds checked against `n`.
void skip_spaces(const std::string& text, core::usize& pos, core::usize n) noexcept {
    while (pos < n && core::is_space(text[pos])) ++pos;
}

// Resolves the canonical (lower-cased) field name to a string view of the
// event. Returns true and fills `out` when the field is a known built-in or a
// present FieldMap key; returns false when the value is absent so callers can
// treat a missing field as the empty string for equality and never-match for
// ordering.
//
// `lname` must already be lower-cased.
bool resolve_string(const std::string& lname, const event::LogEvent& e,
                    std::string& out) {
    if (lname == "severity") {
        out = event::severity_name(e.severity);
        return true;
    }
    if (lname == "source") {
        out = event::source_format_name(e.source);
        return true;
    }
    if (lname == "host") {
        out = e.host;
        return !out.empty();
    }
    if (lname == "app") {
        out = e.app;
        return !out.empty();
    }
    if (lname == "user") {
        out = e.user;
        return !out.empty();
    }
    if (lname == "src_ip") {
        out = e.src_ip;
        return !out.empty();
    }
    if (lname == "dst_ip") {
        out = e.dst_ip;
        return !out.empty();
    }
    if (lname == "src_port") {
        out = std::to_string(e.src_port);
        return true;
    }
    if (lname == "dst_port") {
        out = std::to_string(e.dst_port);
        return true;
    }
    if (lname == "status") {
        out = std::to_string(e.http_status);
        return true;
    }
    if (lname == "method") {
        out = e.http_method;
        return !out.empty();
    }
    if (lname == "path") {
        out = e.http_path;
        return !out.empty();
    }
    if (lname == "event_id") {
        out = std::to_string(e.event_id);
        return true;
    }
    if (lname == "channel") {
        out = e.channel;
        return !out.empty();
    }
    if (lname == "provider") {
        out = e.provider;
        return !out.empty();
    }
    if (lname == "message") {
        out = e.message;
        return !out.empty();
    }

    // Not a built-in: look the original-cased key up in the dynamic FieldMap.
    // FieldMap keys are case-sensitive, so use the predicate's stored field
    // verbatim rather than the lowered copy. The caller passes `lname` only;
    // it also stores the raw name on the predicate, so dynamic lookups are
    // handled in matches() with the raw key. Here we report "not built-in" by
    // returning false with an empty out, and matches() falls back.
    out.clear();
    return false;
}

// Numeric built-in fields whose ordering comparisons should be done on integer
// values rather than lexicographically.
bool is_numeric_field(const std::string& lname) noexcept {
    return lname == "src_port" || lname == "dst_port" || lname == "status" ||
           lname == "event_id";
}

// Maps a Severity enum to its numeric rank for ordering. Mirrors the syslog
// scale where 0 is most severe; Unknown is forced to sort last so it never
// compares as "more severe" than a real level.
int severity_rank(event::Severity s) noexcept {
    int v = static_cast<int>(s);
    if (s == event::Severity::Unknown) return 1000;
    return v;
}

// Parses the right-hand side of a severity comparison: it may be a level word
// ("error", "warn", "crit") or a raw numeric rank (0..7). Returns the rank, or
// the Unknown rank when unrecognised.
int severity_value_rank(const std::string& value) {
    core::i64 num = 0;
    if (core::parse_i64(value, num)) {
        // Treat as a raw scale number. Clamp into the representable range so an
        // out-of-range number still orders sensibly rather than wrapping.
        if (num < 0) return 0;
        if (num > 8) return 1000;  // >= Unknown sorts last
        return severity_rank(static_cast<event::Severity>(num));
    }
    event::Severity s = event::severity_from_word(value);
    return severity_rank(s);
}

}  // namespace

bool parse_op(const std::string& text, core::usize& pos, Op& out) {
    const core::usize n = text.size();
    if (pos >= n) return false;

    char c0 = text[pos];
    char c1 = (pos + 1 < n) ? text[pos + 1] : '\0';

    // Try the two-character operators first so "!=", "!~", "<=" and ">=" are not
    // mis-read as their one-character prefixes.
    if (c0 == '!' && c1 == '=') {
        out = Op::Ne;
        pos += 2;
        return true;
    }
    if (c0 == '!' && c1 == '~') {
        out = Op::NotContains;
        pos += 2;
        return true;
    }
    if (c0 == '<' && c1 == '=') {
        out = Op::Le;
        pos += 2;
        return true;
    }
    if (c0 == '>' && c1 == '=') {
        out = Op::Ge;
        pos += 2;
        return true;
    }

    // One-character operators.
    switch (c0) {
        case '=':
            out = Op::Eq;
            pos += 1;
            return true;
        case '~':
            out = Op::Contains;
            pos += 1;
            return true;
        case '<':
            out = Op::Lt;
            pos += 1;
            return true;
        case '>':
            out = Op::Gt;
            pos += 1;
            return true;
        default:
            return false;
    }
}

namespace {

// Reads a value token starting at `pos`. A value is either a double-quoted
// string (with \" and \\ escapes) that may contain spaces, or a bare run of
// non-whitespace. On success advances `pos` past the value and fills `out`.
// Returns a failing Status on an unterminated quote or an over-long token.
core::Status read_value(const std::string& text, core::usize& pos,
                        core::usize n, std::string& out) {
    out.clear();
    if (pos >= n) {
        return core::Status(core::StatusCode::Malformed,
                            "missing value after operator");
    }

    if (text[pos] == '"') {
        ++pos;  // consume opening quote
        bool closed = false;
        while (pos < n) {
            char c = text[pos];
            if (c == '\\') {
                // Escape sequence: the next byte is taken literally. Only \" and
                // \\ are meaningful; any other escaped byte is passed through so
                // the language stays total and predictable.
                if (pos + 1 < n) {
                    out.push_back(text[pos + 1]);
                    pos += 2;
                } else {
                    // Trailing backslash before EOF: treat the backslash as a
                    // literal and let the unterminated-quote check below fire.
                    out.push_back('\\');
                    pos += 1;
                }
            } else if (c == '"') {
                ++pos;  // consume closing quote
                closed = true;
                break;
            } else {
                out.push_back(c);
                ++pos;
            }
            if (out.size() > kMaxTokenLen) {
                return core::Status(core::StatusCode::LimitExceeded,
                                    "quoted value too long");
            }
        }
        if (!closed) {
            return core::Status(core::StatusCode::Malformed,
                                "unterminated quoted value");
        }
        return core::Status();
    }

    // Bare token: everything up to the next whitespace.
    while (pos < n && !core::is_space(text[pos])) {
        out.push_back(text[pos]);
        ++pos;
        if (out.size() > kMaxTokenLen) {
            return core::Status(core::StatusCode::LimitExceeded,
                                "value token too long");
        }
    }
    if (out.empty()) {
        return core::Status(core::StatusCode::Malformed, "empty value");
    }
    return core::Status();
}

// Parses one predicate beginning at `pos`. On success the predicate is filled
// and `pos` advances past the value. Returns a failing Status describing the
// first problem encountered.
core::Status parse_predicate(const std::string& text, core::usize& pos,
                             core::usize n, Predicate& out) {
    skip_spaces(text, pos, n);

    // --- field name ---
    core::usize start = pos;
    while (pos < n && is_field_char(text[pos])) {
        ++pos;
        if (pos - start > kMaxTokenLen) {
            return core::Status(core::StatusCode::LimitExceeded,
                                "field name too long");
        }
    }
    if (pos == start) {
        // No field characters: either an operator/value with no field, or junk.
        return core::Status(core::StatusCode::InvalidField,
                            "expected a field name");
    }
    out.field = text.substr(start, pos - start);

    skip_spaces(text, pos, n);

    // --- operator ---
    if (pos >= n) {
        return core::Status(core::StatusCode::Malformed,
                            "missing operator after field '" + out.field + "'");
    }
    Op op = Op::Eq;
    if (!parse_op(text, pos, op)) {
        return core::Status(core::StatusCode::Malformed,
                            "expected an operator after field '" + out.field +
                                "'");
    }
    out.op = op;

    skip_spaces(text, pos, n);

    // --- value ---
    core::Status vs = read_value(text, pos, n, out.value);
    if (!vs.ok()) return vs;

    return core::Status();
}

}  // namespace

core::Result<Filter> parse_filter(const std::string& expr) {
    Filter filter;

    const core::usize n = expr.size();
    core::usize pos = 0;

    // An empty or whitespace-only expression is the universal filter.
    skip_spaces(expr, pos, n);
    if (pos >= n) {
        return core::Result<Filter>::success(std::move(filter));
    }

    // The first predicate is added with an arbitrary conjunction (it is never
    // consulted because matches() seeds with predicate 0).
    bool expecting_predicate = true;
    Conj pending_conj = Conj::And;
    bool have_predicate = false;
    core::usize count = 0;

    while (pos < n) {
        skip_spaces(expr, pos, n);
        if (pos >= n) break;

        if (expecting_predicate) {
            if (count >= kMaxPredicates) {
                return core::Result<Filter>::failure(
                    core::StatusCode::LimitExceeded,
                    "filter has too many predicates (max " +
                        std::to_string(kMaxPredicates) + ")");
            }
            Predicate p;
            core::Status st = parse_predicate(expr, pos, n, p);
            if (!st.ok()) {
                return core::Result<Filter>(st);
            }
            filter.add(std::move(p), have_predicate ? pending_conj : Conj::And);
            have_predicate = true;
            ++count;
            expecting_predicate = false;
            continue;
        }

        // Expecting an AND/OR keyword. Read the next whitespace-delimited token
        // and classify it. Anything else is a syntax error.
        core::usize kw_start = pos;
        while (pos < n && !core::is_space(expr[pos])) ++pos;
        core::usize kw_len = pos - kw_start;

        if (token_iequals(expr, kw_start, kw_len, kKwAnd)) {
            pending_conj = Conj::And;
        } else if (token_iequals(expr, kw_start, kw_len, kKwOr)) {
            pending_conj = Conj::Or;
        } else {
            return core::Result<Filter>::failure(
                core::StatusCode::Malformed,
                "expected AND or OR but found '" +
                    expr.substr(kw_start, kw_len) + "'");
        }
        expecting_predicate = true;
    }

    // A trailing AND/OR with no following predicate is malformed.
    if (expecting_predicate && have_predicate) {
        return core::Result<Filter>::failure(
            core::StatusCode::Malformed,
            "expression ends with a dangling AND/OR");
    }

    return core::Result<Filter>::success(std::move(filter));
}

void Filter::add(Predicate p, Conj conj_with_previous) {
    // The first predicate has no preceding conjunction. Every subsequent one
    // records how it combines with the running result, keeping the invariant
    // conjunctions_.size() == predicates_.size() - 1.
    if (!predicates_.empty()) {
        conjunctions_.push_back(conj_with_previous);
    }
    predicates_.push_back(std::move(p));
}

bool Filter::matches(const event::LogEvent& e) const {
    if (predicates_.empty()) return true;  // universal filter

    bool acc = predicates_[0].matches(e);
    for (core::usize i = 1; i < predicates_.size(); ++i) {
        // conjunctions_[i-1] joins predicate i to the running accumulator. Guard
        // the index defensively in case the invariant was ever violated.
        Conj conj = (i - 1 < conjunctions_.size()) ? conjunctions_[i - 1]
                                                    : Conj::And;
        bool rhs = predicates_[i].matches(e);
        if (conj == Conj::And) {
            acc = acc && rhs;
        } else {
            acc = acc || rhs;
        }
    }
    return acc;
}

bool Predicate::matches(const event::LogEvent& e) const {
    // Resolve the field to a concrete string. Built-ins resolve directly; an
    // unknown name falls back to the dynamic FieldMap using the raw key.
    const std::string lname = core::to_lower(field);

    std::string lhs;
    bool present = resolve_string(lname, e, lhs);
    bool is_dynamic = false;

    if (!present) {
        // Distinguish "known built-in that is empty" from "unknown field". The
        // resolve_string helper returns false for both an empty built-in and an
        // unknown field, so re-check whether this name is a built-in at all by
        // probing the FieldMap when it is not.
        const event::FieldValue* fv = e.fields.find(field);
        if (fv != nullptr) {
            lhs = fv->to_string();
            present = true;
            is_dynamic = true;
        } else {
            // Either an empty built-in or a genuinely absent field. lhs is "".
            present = false;
        }
    }

    switch (op) {
        case Op::Eq:
            // Full-string, case-insensitive equality. A missing field equals
            // only the empty string.
            return core::ascii_iequals(lhs, value);
        case Op::Ne:
            return !core::ascii_iequals(lhs, value);
        case Op::Contains:
            // Case-insensitive substring. An empty needle is contained in any
            // string (including a missing field), matching intuitive "~"" use.
            return core::contains(core::to_lower(lhs), core::to_lower(value));
        case Op::NotContains:
            return !core::contains(core::to_lower(lhs), core::to_lower(value));
        case Op::Lt:
        case Op::Le:
        case Op::Gt:
        case Op::Ge:
            break;  // handled below
    }

    // --- ordering comparisons ---
    // A field with no value never satisfies an ordering comparison; this keeps
    // ">"/"<" from accidentally matching absent data.
    if (!present) return false;

    // Compute a three-way comparison `cmp` (<0, 0, >0) of lhs against value
    // under the appropriate ordering, then map it through the operator.
    int cmp = 0;
    bool comparable = true;

    if (lname == "severity") {
        // Severity comparisons rank by how *severe* the level is, so the
        // operators read intuitively: "severity>=error" matches Error and
        // anything more severe (Critical, Alert, Emergency). Internally the
        // syslog rank is 0=most severe, so we invert it into a magnitude where
        // a more severe level is the larger value before comparing.
        int lhs_mag = -severity_rank(e.severity);
        int rhs_mag = -severity_value_rank(value);
        if (lhs_mag < rhs_mag) {
            cmp = -1;
        } else if (lhs_mag > rhs_mag) {
            cmp = 1;
        } else {
            cmp = 0;
        }
    } else if (!is_dynamic && is_numeric_field(lname)) {
        // Built-in numeric fields: compare as signed integers when both sides
        // parse. If the value side is not numeric, fall back to lexicographic so
        // the comparison stays total.
        core::i64 a = 0, b = 0;
        if (core::parse_i64(lhs, a) && core::parse_i64(value, b)) {
            if (a < b) {
                cmp = -1;
            } else if (a > b) {
                cmp = 1;
            } else {
                cmp = 0;
            }
        } else {
            comparable = false;
        }
    } else {
        // Dynamic integer fields compare numerically when both sides are ints.
        core::i64 a = 0, b = 0;
        if (is_dynamic && core::parse_i64(lhs, a) &&
            core::parse_i64(value, b)) {
            if (a < b) {
                cmp = -1;
            } else if (a > b) {
                cmp = 1;
            } else {
                cmp = 0;
            }
        } else {
            comparable = false;
        }
    }

    if (!comparable) {
        // Lexicographic byte comparison of the raw strings as a total fallback.
        int c = lhs.compare(value);
        cmp = (c < 0) ? -1 : (c > 0 ? 1 : 0);
    }

    switch (op) {
        case Op::Lt:
            return cmp < 0;
        case Op::Le:
            return cmp <= 0;
        case Op::Gt:
            return cmp > 0;
        case Op::Ge:
            return cmp >= 0;
        default:
            return false;  // unreachable; keeps the compiler happy
    }
}

}  // namespace query
}  // namespace csift
