# ChronoSift

ChronoSift is an offline toolkit and C++17 library for **log and event
forensics**. It ingests the heterogeneous log formats that pile up on a host or
land on an analyst's desk during an incident — Linux/BSD syslog, JSON-lines
application logs, web-server access logs, Windows EVTX event records, and CEF
security-appliance feeds — normalizes them into a single event model, and runs
timeline, correlation, and detection analysis over the result.

Everything ChronoSift does happens locally. It opens files supplied on the
command line, parses them defensively, and writes structured reports to stdout.
There is no network code, no telemetry, no daemon, and no configuration server —
by design, so it can run on an isolated analysis workstation or an air-gapped
responder laptop without exfiltrating the very evidence it is examining.

## Why it exists

When you are triaging an incident or reviewing a host you usually end up with a
pile of mismatched evidence:

- a `/var/log` tree full of `syslog`, `auth.log`, and `cron` entries,
- a JSON-lines stream exported from an application or a log shipper,
- an `access.log` from a web server you suspect was probed,
- an exported Windows `.evtx` event log,
- a batch of CEF events a firewall or IDS forwarded to a collector.

Each format has its own framing, its own timestamp dialect, and its own quirks.
ChronoSift turns all of them into one uniform stream of events with a common
schema, so you can ask cross-source questions — *"show me everything from this
source IP, in time order, across the web log and the auth log"* — and get a
single answer. Because the files under analysis are frequently
attacker-influenced, every parser is written to be **robust against hostile
input**: a malformed record produces a diagnostic, never a crash.

## Real-world use cases

- **Incident triage.** Point `logparse` at a log and get a uniform, greppable
  view of every record, regardless of source format.
- **Timeline reconstruction.** `logtimeline` buckets activity into time windows,
  highlights the busiest periods, and flags coverage gaps that can indicate log
  tampering or an outage.
- **Threat detection.** `logdetect` applies heuristics for authentication
  brute-force, password-spray-then-success, HTTP error bursts, path/port
  scanning, high-severity spikes, and rare event signatures.
- **Quantitative overview.** `logstats` summarizes a log by source, severity,
  host, application, top source IPs, top users, and HTTP status classes.
- **Evidence export.** `logexport` emits normalized events as NDJSON or CSV, with
  an optional filter expression, for handoff to `jq`, a spreadsheet, or a SIEM.
- **Library reuse.** Embed the parsers and the event model in your own offline
  tooling; they have no dependencies beyond the C++17 standard library.

## Supported artifact formats

| Format | Module | Notes |
|--------|--------|-------|
| Syslog | `syslog` | RFC 3164 (BSD) and RFC 5424 (IETF), PRI/facility/severity, structured data |
| JSON lines | `jsonlog` | RFC 8259 parser with depth/size limits; field-alias mapping |
| Web access logs | `weblog` | NCSA Common and Combined Log Format |
| Windows events | `winlog` | EVTX container + Binary XML (chunks, records, templates, substitutions) |
| CEF | `cef` | ArcSight Common Event Format header + escaped key/value extensions |

The `pipeline` module auto-detects the format from the leading bytes, or you can
force one with `--format`.

## Architecture

```
core/       byte spans & readers, endian helpers, status/result types,
            diagnostics, string/encoding utilities, timestamp parsing
event/      the unified event model: LogEvent, FieldMap, Severity, EventStream
syslog/     RFC 3164 + RFC 5424 parser
weblog/     Common / Combined access-log parser
jsonlog/    JSON value model + recursive-descent parser + log field mapper
winlog/     EVTX file/chunk/record framing + Binary XML decoder
cef/        Common Event Format parser
pipeline/   format auto-detection and dispatch (ingest)
analyze/    statistics, timeline, sessionization, detections, reporting
query/      a small filter-expression language for selecting events
serialize/  NDJSON and CSV writers
tools/      command-line front-ends
```

Data flows one way: a format parser turns raw bytes into `LogEvent`s appended to
an `EventStream`; the `analyze`, `query`, and `serialize` modules consume only
the normalized stream and never touch the raw formats. New formats plug in by
producing events; new analyses plug in by consuming them.

## Command-line tools

```
logparse     parse an artifact and print one normalized event per line
logstats     print aggregate statistics over an artifact
logtimeline  build a bucketed timeline, coverage gaps, and sessions
logdetect    run the heuristic security detectors and print findings
logexport    export normalized events as NDJSON or CSV, with optional filtering
```

Examples:

```sh
# Auto-detect and summarize a syslog file.
logparse /var/log/auth.log

# Force CEF and show extracted fields.
logparse --format cef --fields firewall.cef

# Look for brute-force activity in an access log.
logdetect --http-errors 30 access.log --evidence

# Hourly timeline plus per-source-IP sessions.
logtimeline --bucket 3600 --sessions ip auth.log

# Export only the errors from a JSON log as CSV.
logexport --out csv --filter "severity>=error" app.jsonl

# Frequency breakdown of an EVTX export.
logstats --format evtx Security.evtx
```

All tools read a single local file (or `-` for standard input) and write to
stdout; none take network input or require configuration.

### Filter expressions

`logexport --filter` accepts a small expression language:

```
severity>=error AND host=web1 AND message~password
```

Supported fields include `severity`, `source`, `host`, `app`, `user`,
`src_ip`, `dst_ip`, `src_port`, `dst_port`, `status`, `method`, `path`,
`event_id`, `channel`, `provider`, `message`, and any extracted field key.
Operators are `=`, `!=`, `~` (contains), `!~`, `<`, `<=`, `>`, `>=`, combined
with `AND` / `OR`.

## Building

ChronoSift uses CMake and depends only on a C++17 compiler and the standard
library.

```sh
cmake -S . -B build -DCMAKE_BUILD_TYPE=RelWithDebInfo
cmake --build build -j
```

This builds the static library `libchronosift.a`, the five command-line tools,
and the test suite. Useful options:

- `-DCHRONOSIFT_BUILD_TOOLS=OFF` — library and tests only.
- `-DCHRONOSIFT_BUILD_TESTS=OFF` — skip the test suite.
- `-DCHRONOSIFT_SANITIZE=ON` — build with AddressSanitizer + UndefinedBehaviorSanitizer.

## Testing

```sh
ctest --test-dir build --output-on-failure
```

Each module has a deterministic test executable covering both valid inputs
(correct field extraction, timestamps, severities) and invalid ones (truncated
records, malformed framing, oversized and adversarial input) to confirm the
parsers fail cleanly rather than crash.

## Developer QA / robustness testing

Because ChronoSift parses untrusted files, the parsers are continuously
exercised with coverage-guided fuzzing during development. The harnesses live in
`fuzz/` and each drives one parser's full path from raw bytes:

```
fuzz/syslog_fuzzer.cc    fuzz/weblog_fuzzer.cc    fuzz/jsonlog_fuzzer.cc
fuzz/winlog_fuzzer.cc    fuzz/cef_fuzzer.cc
```

Build and run a harness locally with an ordinary compiler (no fuzzing engine
required) using the in-tree standalone driver:

```sh
cmake -S . -B build -DCHRONOSIFT_BUILD_FUZZERS=ON -DCHRONOSIFT_SANITIZE=ON
cmake --build build -j
./build/winlog_fuzzer fuzz/corpus/winlog_fuzzer/*     # replay the seed corpus
./build/syslog_fuzzer < some_input.bin                # replay one input
```

For a coverage-guided run with a compiler that ships libFuzzer (e.g. Clang), the
`.clusterfuzzlite/build.sh` script compiles every harness against the project's
configured sanitizer/fuzzing-engine flags and writes the binaries to `$OUT`:

```sh
CXX=clang++ CXXFLAGS="-O1 -g -fsanitize=address,fuzzer-no-link" \
LIB_FUZZING_ENGINE="-fsanitize=fuzzer" OUT=./out \
  bash .clusterfuzzlite/build.sh
./out/syslog_fuzzer -max_total_time=60 fuzz/corpus/syslog_fuzzer
```

### Seed corpus

`fuzz/corpus/<harness>/` holds realistic seed inputs for each parser so a
coverage-guided run starts from well-formed, structure-bearing examples and
mutates outward to reach the deep parsing logic quickly:

- `syslog_fuzzer/` — RFC 3164 and RFC 5424 lines, structured data, a multi-line
  mix, and a near-valid malformed sample.
- `weblog_fuzzer/` — Common and Combined log lines, a scan burst, and a
  malformed sample.
- `jsonlog_fuzzer/` — flat and nested objects, arrays/scalars with unicode
  escapes, and a malformed sample.
- `winlog_fuzzer/` — a single-record and a multi-record EVTX file, a
  header-only file, and a malformed container.
- `cef_fuzzer/` — firewall/auth/IDS events, escaped header and extension fields,
  and a malformed sample.

`fuzz/dictionary.txt` lists the format magics, token bytes, and keywords that
help a fuzzer cross the structural gates.

## Manual review checklist

For reviewers auditing the code for quality and originality:

- [ ] Every parser entry point treats its input as untrusted and bounds-checks
      every read; the binary `winlog` decoder uses `core::ByteReader`, which
      latches a sticky error on underflow.
- [ ] Recursion in the JSON parser and the Binary XML decoder is depth-limited
      by explicit, configurable limits checked before each descent.
- [ ] All loops over attacker-controlled counts/offsets make forward progress or
      break (no infinite loops on zero-length or self-referential structures).
- [ ] The unified event model (`event/`) is the only contract between parsers and
      analysis; modules do not reach across each other.
- [ ] No use of anything beyond the C++17 standard library; no network, file
      globbing, environment, or absolute-path dependencies in the library.
- [ ] Tests cover both valid and invalid inputs for each module.
- [ ] Timestamp math is pure arithmetic (no `<ctime>` reentrancy hazards) and is
      round-trip tested.

## License

MIT. See [LICENSE](LICENSE).
