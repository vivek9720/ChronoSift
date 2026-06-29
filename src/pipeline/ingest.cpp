#include "pipeline/ingest.hpp"

#include "cef/parser.hpp"
#include "core/string_util.hpp"
#include "jsonlog/log_mapper.hpp"
#include "syslog/parser.hpp"
#include "weblog/parser.hpp"
#include "winlog/evtx_parser.hpp"

namespace csift {
namespace pipeline {

const char* format_name(Format f) noexcept {
    switch (f) {
        case Format::Auto: return "auto";
        case Format::Syslog: return "syslog";
        case Format::Json: return "json";
        case Format::WebAccess: return "web-access";
        case Format::WinEvtx: return "evtx";
        case Format::Cef: return "cef";
    }
    return "auto";
}

bool parse_format_name(const std::string& name, Format& out) {
    std::string n = core::to_lower(core::trim(name));
    if (n == "auto") {
        out = Format::Auto;
    } else if (n == "syslog" || n == "sys") {
        out = Format::Syslog;
    } else if (n == "json" || n == "jsonl" || n == "ndjson") {
        out = Format::Json;
    } else if (n == "web" || n == "web-access" || n == "access" || n == "clf" ||
               n == "httpd") {
        out = Format::WebAccess;
    } else if (n == "evtx" || n == "winevtx" || n == "win" || n == "winlog") {
        out = Format::WinEvtx;
    } else if (n == "cef") {
        out = Format::Cef;
    } else {
        return false;
    }
    return true;
}

// Finds the first byte that is not ASCII whitespace.
static core::byte first_non_space(core::ByteSpan bytes, core::usize& idx) {
    for (core::usize i = 0; i < bytes.size(); ++i) {
        core::byte b = bytes[i];
        if (b != ' ' && b != '\t' && b != '\r' && b != '\n') {
            idx = i;
            return b;
        }
    }
    idx = bytes.size();
    return 0;
}

Format detect_format(core::ByteSpan bytes) {
    if (bytes.empty()) return Format::Syslog;

    // EVTX binary container: the file header magic is "ElfFile\0".
    if (bytes.starts_with("ElfFile")) return Format::WinEvtx;

    core::usize idx = 0;
    core::byte b = first_non_space(bytes, idx);

    // CEF appliance logs contain a "CEF:" marker near the start of the first
    // line, either at column 0 or just after a syslog prefix.
    {
        std::string head = bytes.first(256).to_string();
        core::usize nl = head.find('\n');
        std::string first_line = (nl == std::string::npos) ? head : head.substr(0, nl);
        if (first_line.find("CEF:") != std::string::npos) return Format::Cef;
    }

    // JSON lines start with an object or array.
    if (b == '{' || b == '[') return Format::Json;

    // Classic syslog lines begin with the PRI marker "<NNN>".
    if (b == '<') {
        core::usize j = idx + 1;
        core::usize digits = 0;
        while (j < bytes.size() && bytes[j] >= '0' && bytes[j] <= '9') {
            ++j;
            ++digits;
        }
        if (digits >= 1 && digits <= 3 && j < bytes.size() && bytes[j] == '>') {
            return Format::Syslog;
        }
    }

    // Web access logs: the first field is an IP/host, and a bracketed time plus
    // a quoted request appear on the line. Sniff for the '[' ... ']' "..." shape
    // within the first line.
    std::string head = bytes.first(512).to_string();
    core::usize nl = head.find('\n');
    std::string line = (nl == std::string::npos) ? head : head.substr(0, nl);
    if (line.find('[') != std::string::npos && line.find('"') != std::string::npos) {
        return Format::WebAccess;
    }

    // Default: treat as syslog/plain text, which the syslog parser degrades to
    // gracefully (an unparseable line becomes a raw message event).
    return Format::Syslog;
}

event::EventStream ingest(core::ByteSpan bytes, core::DiagnosticSink& diags,
                          const IngestOptions& opts) {
    Format fmt = opts.format;
    if (fmt == Format::Auto) {
        fmt = detect_format(bytes);
        diags.info("ingest", std::string("auto-detected format: ") + format_name(fmt));
    }

    switch (fmt) {
        case Format::Json: {
            jsonlog::JsonLimits limits;
            return jsonlog::parse_stream(bytes, diags, limits, opts.assume_year);
        }
        case Format::WebAccess: {
            weblog::ParseOptions wopts;
            return weblog::parse_stream(bytes, diags, wopts);
        }
        case Format::WinEvtx: {
            winlog::ParseOptions eopts;
            return winlog::parse_stream(bytes, diags, eopts);
        }
        case Format::Cef: {
            cef::ParseOptions copts;
            copts.assume_year = opts.assume_year;
            return cef::parse_stream(bytes, diags, copts);
        }
        case Format::Syslog:
        case Format::Auto:
        default: {
            syslog::ParseOptions sopts;
            sopts.assume_year = opts.assume_year;
            return syslog::parse_stream(bytes, diags, sopts);
        }
    }
}

}  // namespace pipeline
}  // namespace csift
