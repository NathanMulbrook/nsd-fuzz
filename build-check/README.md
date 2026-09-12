# Build artifact checker

This checker inspects the 36 NSD build trees and linked `nsd` fuzzing
executables with GNU `readelf`; it never executes an artifact. It verifies
static ELF evidence for ASan, UBSan, shared trace-pc-guard coverage,
CoverBridge's libFuzzer counters, LLVM profiles, and source coverage.

Run it from the repository root:

```sh
nice -n 19 ionice -c 3 ./checkObjects.sh
```

The checker writes `logs/symbolReport.md`. A zero exit status means every
configured expectation passed. Status 1 means instrumentation policy failures;
status 2 means inspection or configuration errors. File details distinguish
`FOUND`, `SYMBOL-ONLY`, `NOT-SEEN`, and `UNKNOWN` evidence.

The linked sanitizer runtimes define UBSan and comparison-tracing symbols, so
those definition-only results are intentionally not used as proof. Their use is
verified in the independently scanned object files. Translation units compiled
out by a selected NSD feature configuration have narrow policy overrides in the
config; ASan and any source mapping they retain are still checked.

Paths and expectations are configured in `check-build.ini`. Paths are relative
to that file. `object_dirs` are scanned recursively for ELF relocatable objects
and archives. `binary_paths` may name individual binaries or directories.
Checks use `present`, `absent`, or `ignore`, and `[checks:PATH_GLOB]` sections
override expectations for matching artifacts.
