// logdetect — run heuristic detections over a local log/event artifact.
//
// Parses the artifact and applies ChronoSift's detectors: authentication
// brute-force, password-spray-then-success, HTTP error bursts, path/port scans,
// high-severity spikes, and rare event signatures. Prints each finding with its
// supporting evidence so an analyst can confirm or dismiss it.

#include <cstdio>
#include <string>
#include <vector>

#include "analyze/detections.hpp"
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
        "Run heuristic security detections over a log/event artifact.\n"
        "\n"
        "Options:\n"
        "  -f, --format NAME      Force format: auto|syslog|json|web|evtx (default auto)\n"
        "      --year N           Year to assume for year-less syslog timestamps\n"
        "      --bf-failures N    Min failed auths for a brute-force finding (default 5)\n"
        "      --bf-window N      Brute-force window in seconds (default 120)\n"
        "      --http-errors N    Min 4xx/5xx for an error-burst finding (default 20)\n"
        "      --scan-distinct N  Min distinct targets for a scan finding (default 25)\n"
        "      --evidence         Print supporting event summaries for each finding\n"
        "  -h, --help             Show this help and exit\n",
        prog);
}

}  // namespace

int main(int argc, char** argv) {
    csift::cli::Args args(argc, argv, {"evidence", "diagnostics", "help", "h"});
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

    csift::analyze::DetectionConfig cfg;
    cfg.bruteforce_min_failures =
        static_cast<csift::core::usize>(args.get_long("bf-failures",
            static_cast<long>(cfg.bruteforce_min_failures)));
    cfg.bruteforce_window_seconds =
        args.get_long("bf-window", static_cast<long>(cfg.bruteforce_window_seconds));
    cfg.http_error_min =
        static_cast<csift::core::usize>(args.get_long("http-errors",
            static_cast<long>(cfg.http_error_min)));
    cfg.scan_distinct_min =
        static_cast<csift::core::usize>(args.get_long("scan-distinct",
            static_cast<long>(cfg.scan_distinct_min)));

    std::vector<csift::analyze::Finding> findings =
        csift::analyze::run_detections(stream, cfg);

    std::printf("# %zu finding(s) across %zu event(s)\n", findings.size(),
                stream.size());
    const bool show_evidence = args.has("evidence");
    for (const csift::analyze::Finding& f : findings) {
        std::printf("\n%s\n", f.render().c_str());
        if (show_evidence) {
            for (csift::core::usize idx : f.evidence) {
                if (idx < stream.size()) {
                    std::printf("    | %s\n", stream.events()[idx].summary().c_str());
                }
            }
        }
    }

    if (args.has("diagnostics")) {
        std::fprintf(stderr, "%s", diags.render().c_str());
    }
    return findings.empty() ? 0 : 0;
}
