#include "weblog/record.hpp"

#include <string>

#include "core/encoding.hpp"

namespace csift {
namespace weblog {

// The decoded path is the request target with any query string and fragment
// stripped, then percent-decoded. The target is stored exactly as it appeared
// in the log (percent-encoded, possibly with a query), so this is what callers
// want when they group or match by "the resource that was requested" without
// caring about per-request query parameters.
//
// Both '?' (query) and '#' (fragment) terminate the path component. A target
// that is missing or empty yields an empty path. Decoding is delegated to
// core::percent_decode, which is lenient: malformed '%' escapes are passed
// through literally rather than dropped, matching how forgiving log tooling
// behaves and keeping the function total on any input.
std::string AccessRecord::decoded_path() const {
    const std::string& target = request.target;
    if (target.empty()) {
        return std::string();
    }

    // Locate the first query ('?') or fragment ('#') delimiter; whichever comes
    // first ends the path component. find() on an empty/short string is safe and
    // simply returns npos.
    std::string::size_type cut = target.size();
    for (std::string::size_type i = 0; i < target.size(); ++i) {
        char c = target[i];
        if (c == '?' || c == '#') {
            cut = i;
            break;
        }
    }

    // substr(0, cut) is bounds-safe: cut is always <= size().
    std::string path = target.substr(0, cut);
    if (path.empty()) {
        return std::string();
    }

    return core::percent_decode(path);
}

}  // namespace weblog
}  // namespace csift
