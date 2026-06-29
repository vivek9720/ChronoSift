// logstats — aggregate statistics over a local log/event artifact.
//
// Parses the artifact and prints frequency breakdowns: events by source format,
// severity, host, application, top source IPs, top users, HTTP status classes,
// and the most common event signatures. Gives an analyst a quick quantitative
// picture of what a log contains before drilling in.

#include <cstdio>
#include <string>

#include "analyze/statistics.hpp"
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
        "Print aggregate statistics over a log/event artifact.\n"
        "\n"
        "Options:\n"
        "  -f, --format NAME   Force a format: auto|syslog|json|web|evtx (default auto)\n"
        "      --year N        Year to assume for year-less syslog timestamps\n"
        "      --diagnostics   Print parser diagnostics to stderr\n"
        "  -h, --help          Show this help and exit\n",
        prog);
}

}  // namespace

int main(int argc, char** argv) {
    csift::cli::Args args(argc, argv, {"diagnostics", "help", "h"});
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

    csift::analyze::StreamStatistics stats =
        csift::analyze::compute_statistics(stream);
    std::printf("%s", stats.render().c_str());

    if (args.has("diagnostics")) {
        std::fprintf(stderr, "%s", diags.render().c_str());
    }
    return 0;
}
