# Proof-of-concept inputs

This directory holds crashing inputs discovered by robustness testing, if any.

Status: **no crash found.** All parser harnesses (syslog, weblog, jsonlog,
winlog, cef) were exercised under AddressSanitizer + UndefinedBehaviorSanitizer
over their seed corpora and a large volume of mutated inputs with no
memory-safety error, out-of-bounds access, or undefined behavior. No
proof-of-concept input has been recorded.

The directory is kept so that a future finding can be saved here as the exact
raw bytes the relevant harness reads.
