#ifndef CSIFT_TOOLS_CLI_COMMON_HPP
#define CSIFT_TOOLS_CLI_COMMON_HPP

#include <cstdio>
#include <string>
#include <vector>

#include "core/byte_span.hpp"

// Shared helpers for the ChronoSift command-line tools. The tools are strictly
// offline: they read a single local file (or standard input) given on the
// command line and write a textual report to stdout. There is no network code,
// no configuration file, and no environment dependence beyond argv.
namespace csift {
namespace cli {

// Reads the entire contents of a local file into `out`. Returns false on error.
// A path of "-" reads standard input.
inline bool read_file(const std::string& path, std::string& out) {
    if (path == "-") {
        std::string data;
        char buf[65536];
        size_t n;
        while ((n = std::fread(buf, 1, sizeof(buf), stdin)) > 0) {
            data.append(buf, n);
        }
        out = std::move(data);
        return true;
    }
    std::FILE* f = std::fopen(path.c_str(), "rb");
    if (!f) return false;
    std::string data;
    char buf[65536];
    size_t n;
    while ((n = std::fread(buf, 1, sizeof(buf), f)) > 0) {
        data.append(buf, n);
    }
    std::fclose(f);
    out = std::move(data);
    return true;
}

// A minimal options reader over argv. Recognises "--name value", "--name=value"
// and bare positional arguments. It does no validation beyond presence; callers
// interpret the string values.
class Args {
public:
    // `boolean_flags` names the options that never take a value (e.g. "fields",
    // "help"). Without this, a flag like `--fields` immediately before a
    // positional file argument would wrongly swallow the filename as its value.
    Args(int argc, char** argv, std::vector<std::string> boolean_flags = {})
        : boolean_flags_(std::move(boolean_flags)) {
        for (int i = 1; i < argc; ++i) {
            std::string a = argv[i];
            if (a.size() >= 2 && a[0] == '-' && a[1] == '-') {
                std::string key = a.substr(2);
                std::string val;
                bool has_val = false;
                size_t eq = key.find('=');
                if (eq != std::string::npos) {
                    val = key.substr(eq + 1);
                    key = key.substr(0, eq);
                    has_val = true;
                } else if (!is_boolean_flag(key) && i + 1 < argc &&
                           argv[i + 1][0] != '-') {
                    val = argv[++i];
                    has_val = true;
                }
                options_.push_back({key, val, has_val});
            } else {
                positional_.push_back(a);
            }
        }
    }

    bool has(const std::string& key) const {
        for (const Option& o : options_) {
            if (o.key == key) return true;
        }
        return false;
    }

    std::string get(const std::string& key, const std::string& fallback) const {
        for (const Option& o : options_) {
            if (o.key == key && o.has_value) return o.value;
        }
        return fallback;
    }

    long get_long(const std::string& key, long fallback) const {
        std::string v = get(key, std::string());
        if (v.empty()) return fallback;
        char* end = nullptr;
        long n = std::strtol(v.c_str(), &end, 10);
        if (end == v.c_str()) return fallback;
        return n;
    }

    const std::vector<std::string>& positional() const { return positional_; }

private:
    bool is_boolean_flag(const std::string& key) const {
        for (const std::string& f : boolean_flags_) {
            if (f == key) return true;
        }
        return false;
    }

    struct Option {
        std::string key;
        std::string value;
        bool has_value;
    };
    std::vector<Option> options_;
    std::vector<std::string> positional_;
    std::vector<std::string> boolean_flags_;
};

}  // namespace cli
}  // namespace csift

#endif  // CSIFT_TOOLS_CLI_COMMON_HPP
