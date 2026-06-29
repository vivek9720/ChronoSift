// logtimeline — build a temporal view of a local log/event artifact.
//
// Parses the artifact, sorts events by time, and prints a bucketed activity
// histogram, the coverage gaps (which can indicate log tampering or outages),
// and optionally a sessionized view grouping activity by source IP, user, or
// host. This is the "what happened, and when" step of an investigation.

#include <cstdio>
#include <string>
#include <vector>

#include "analyze/correlate.hpp"
#include "analyze/timeline.hpp"
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
        "Build a timeline and session view of a log/event artifact.\n"
        "\n"
        "Options:\n"
        "  -f, --format NAME    Force format: auto|syslog|json|web|evtx (default auto)\n"
        "      --year N         Year to assume for year-less syslog timestamps\n"
        "      --bucket N       Histogram bucket width in seconds (default 3600)\n"
        "      --gap N          Report coverage gaps longer than N seconds (default 3600)\n"
        "      --sessions KEY   Also print sessions grouped by: ip|user|host\n"
        "      --idle N         Session idle-gap threshold in seconds (default 900)\n"
        "      --limit N        Max sessions to print (default 25)\n"
        "  -h, --help           Show this help and exit\n",
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

    const long bucket = args.get_long("bucket", 3600);
    const long gap = args.get_long("gap", 3600);
    csift::analyze::Timeline timeline =
        csift::analyze::build_timeline(stream, bucket > 0 ? bucket : 3600, gap);
    std::printf("%s", timeline.render().c_str());

    if (args.has("sessions")) {
        std::string key_name = args.get("sessions", "ip");
        csift::analyze::SessionKey key = csift::analyze::SessionKey::SourceIp;
        if (key_name == "user") {
            key = csift::analyze::SessionKey::User;
        } else if (key_name == "host") {
            key = csift::analyze::SessionKey::Host;
        }
        const long idle = args.get_long("idle", 900);
        std::vector<csift::analyze::Session> sessions =
            csift::analyze::build_sessions(stream, key, idle > 0 ? idle : 900);
        const long limit = args.get_long("limit", 25);
        std::printf("\n%s", csift::analyze::render_sessions(
                                sessions, stream,
                                static_cast<csift::core::usize>(limit > 0 ? limit : 25))
                                .c_str());
    }

    if (args.has("diagnostics")) {
        std::fprintf(stderr, "%s", diags.render().c_str());
    }
    return 0;
}
