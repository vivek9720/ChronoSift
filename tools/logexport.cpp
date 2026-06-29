// logexport — normalize a local log/event artifact and export it as NDJSON or
// CSV, optionally filtering with a query expression.
//
// This is the bridge step: it turns any supported artifact into a uniform,
// machine-readable table that downstream tooling (jq, spreadsheets, a SIEM
// importer) can consume, after optionally narrowing to the events of interest.

#include <cstdio>
#include <string>

#include "cli_common.hpp"
#include "core/byte_span.hpp"
#include "core/diagnostics.hpp"
#include "event/stream.hpp"
#include "pipeline/ingest.hpp"
#include "query/filter.hpp"
#include "serialize/writer.hpp"

namespace {

void print_usage(const char* prog) {
    std::printf(
        "Usage: %s [options] <file>\n"
        "\n"
        "Export normalized events as NDJSON or CSV.\n"
        "\n"
        "Options:\n"
        "  -f, --format NAME   Force input format: auto|syslog|json|web|evtx|cef\n"
        "      --year N        Year to assume for year-less syslog timestamps\n"
        "  -o, --out KIND      Output format: ndjson (default) or csv\n"
        "      --filter EXPR   Only export events matching the filter expression,\n"
        "                      e.g. \"severity>=error AND host=web1\"\n"
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
        std::fprintf(stderr, "error: unknown input format '%s'\n", fmt_name.c_str());
        return 2;
    }
    opts.assume_year = static_cast<csift::core::i32>(args.get_long("year", 1970));

    csift::core::DiagnosticSink diags;
    csift::event::EventStream stream =
        csift::pipeline::ingest(csift::core::ByteSpan::from_string(data), diags, opts);

    // Optional filtering.
    if (args.has("filter")) {
        std::string expr = args.get("filter", "");
        auto compiled = csift::query::parse_filter(expr);
        if (!compiled.ok()) {
            std::fprintf(stderr, "error: bad filter: %s\n",
                         compiled.status().to_string().c_str());
            return 2;
        }
        const csift::query::Filter& filter = compiled.value();
        csift::event::EventStream filtered;
        for (const csift::event::LogEvent& e : stream.events()) {
            if (filter.matches(e)) filtered.add(e);
        }
        stream = std::move(filtered);
    }

    const std::string out_kind = args.get("out", args.get("o", "ndjson"));
    if (out_kind == "csv") {
        std::printf("%s", csift::serialize::to_csv(stream).c_str());
    } else if (out_kind == "ndjson" || out_kind == "json") {
        std::printf("%s", csift::serialize::to_ndjson(stream).c_str());
    } else {
        std::fprintf(stderr, "error: unknown output format '%s'\n", out_kind.c_str());
        return 2;
    }

    if (args.has("diagnostics")) {
        std::fprintf(stderr, "%s", diags.render().c_str());
    }
    return 0;
}
