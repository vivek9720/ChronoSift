// logparse — parse a local log/event artifact and print the normalized events.
//
// Reads one file (PCAP-style EVTX, syslog, JSON-lines, or web access log),
// auto-detecting the format unless told otherwise, and prints one normalized
// event per line. Useful as the first triage step: it turns a heterogeneous log
// into a uniform, greppable view and surfaces parser diagnostics.

#include <cstdio>
#include <string>

#include "cli_common.hpp"
#include "core/byte_span.hpp"
#include "core/diagnostics.hpp"
#include "event/stream.hpp"
#include "pipeline/ingest.hpp"

namespace {

void print_usage(const char* prog) {
    std::printf(
        "Usage: %s [options] <file>\n"
        "\n"
        "Parse a log/event artifact into normalized events.\n"
        "\n"
        "Options:\n"
        "  -f, --format NAME   Force a format: auto|syslog|json|web|evtx (default auto)\n"
        "      --year N        Year to assume for year-less syslog timestamps\n"
        "      --limit N       Print at most N events (0 = all)\n"
        "      --fields        Also print each event's extracted key/value fields\n"
        "      --diagnostics   Print parser diagnostics to stderr\n"
        "  -h, --help          Show this help and exit\n"
        "\n"
        "A path of \"-\" reads standard input.\n",
        prog);
}

}  // namespace

int main(int argc, char** argv) {
    csift::cli::Args args(argc, argv, {"fields", "diagnostics", "help", "h"});
    if (args.has("help") || args.has("h") || args.positional().empty()) {
        print_usage(argv[0]);
        return args.positional().empty() ? 2 : 0;
    }

    const std::string path = args.positional().front();
    std::string data;
    if (!csift::cli::read_file(path, data)) {
        std::fprintf(stderr, "error: cannot read %s\n", path.c_str());
        return 1;
    }

    csift::pipeline::IngestOptions opts;
    std::string fmt_name = args.get("format", args.get("f", "auto"));
    if (!csift::pipeline::parse_format_name(fmt_name, opts.format)) {
        std::fprintf(stderr, "error: unknown format '%s'\n", fmt_name.c_str());
        return 2;
    }
    opts.assume_year = static_cast<csift::core::i32>(args.get_long("year", 1970));

    csift::core::DiagnosticSink diags;
    csift::event::EventStream stream =
        csift::pipeline::ingest(csift::core::ByteSpan::from_string(data), diags, opts);

    const long limit = args.get_long("limit", 0);
    const bool show_fields = args.has("fields");

    std::printf("# %zu event(s) parsed from %s\n", stream.size(), path.c_str());
    long printed = 0;
    for (const csift::event::LogEvent& e : stream.events()) {
        if (limit > 0 && printed >= limit) break;
        std::printf("%s\n", e.summary().c_str());
        if (show_fields) {
            for (const auto& f : e.fields.entries()) {
                std::printf("    %s = %s\n", f.key.c_str(), f.value.to_string().c_str());
            }
        }
        ++printed;
    }

    if (args.has("diagnostics")) {
        std::fprintf(stderr, "%s", diags.render().c_str());
    }
    if (diags.has_errors()) {
        std::fprintf(stderr, "# %zu diagnostic error(s)\n",
                     diags.count_at_least(csift::core::DiagLevel::Error));
    }
    return 0;
}
