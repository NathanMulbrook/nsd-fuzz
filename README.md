# nsd-fuzz

NSD is built from an untouched release archive. Every build extracts a fresh
copy under `build/src_N`, applies the public patches, then the private patches,
and installs the result under `run/run_N`.

The target release is kept in `source-version.sh`. Change the version, URL and
SHA-256 there to move the fuzzer to another NSD release.

On a fresh checkout, clone the public and private patch repositories and
download the verified NSD archive with:

```console
./build.sh --init
```

The private repository is optional for people who do not have access. Clone
`nsd-patches` by hand in that case. A patched build stops with a clear error
when the public patch stack is missing. `./build.sh --download` only downloads
and verifies the source, and `./build.sh --no-patch` builds the clean release.

The fuzzer uses its own LLVM 23.1.1 install. The checked-out toolchain is not
tracked. Build it when it is missing:

```console
./build.sh --bootstrap-toolchain
```

Builds use a repository-local ccache under `toolchain/ccache` when ccache is
installed. It defaults to 20G. Set `NSD_FUZZ_CCACHE=0` to disable it or
`NSD_FUZZ_CCACHE_MAXSIZE=SIZE` to change the limit.

Like the 389 fuzzer, no argument means all configurations. This builds all 30
in batches of eight with one make job per build, then runs all 30 fuzzers:

```console
./build.sh
./run.sh
```

The 389-style short options work too. Use `-c=N` for one configuration, `-j`
for four make jobs, and `-f` to run the server without its embedded fuzzer:

```console
./build.sh -c=1 -j
./run.sh -c=1
./run.sh -c=1 -f
./run.sh -c=1 --single-process
./run.sh -c=1 --no-restart
```

Use `--parallel-builds=N` or `NSD_FUZZ_PARALLEL_BUILDS=N` to change the outer
build limit. `-j=N` still controls make jobs inside each build.

Builds, starts and corpus resets coordinate through lock files under
`run/locks`. A build waits for startup of the same configuration to finish,
and refuses to replace a configuration owned by a running campaign. Corpus
reset refuses to run until every campaign has stopped.

The builds are installed under `run/run_1` through `run/run_30` and listen on
ports 5301 through 5330. They vary the receive path, allocators, lookup tree,
runtime checks, statistics, DNS features, TCP defaults and SIMD parsers. UDP
and TCP are selected by the corpus input, so a second set of builds is not
needed just for TCP.
Configurations 1, 2, 4, 9, 12 and 30 enable NSD's internal runtime checks so
failed invariants are reported as fuzzing findings. The other configurations
use the production-style `NDEBUG` setting so one checked-build assertion does
not keep most of the fuzzing capacity in a restart loop. Configuration 29 is
the optimized `-O2` build; the others use `-O1`.

Use `./run.sh --server-only --config=1` to run NSD without starting libFuzzer.
This is useful for replaying a testcase:

```console
./send-test-case.py corpus/udp-a-example --port 5301
```

## Corpus format

The first byte controls the harness:

- bit 0: TCP instead of UDP
- bit 1: multipacket input
- bit 2: drain one response between packets
- bit 3: send TCP bytes without adding a DNS length prefix

A normal input is the control byte followed by one raw DNS packet. A
multipacket input repeats a two-byte big-endian packet length followed by that
raw DNS packet. With bits 1 and 3 set, those lengths describe separate TCP
write chunks, which lets the corpus split the DNS length and body across
writes. The harness processes at most 64 packets and gives normal multipacket
inputs three seconds of work before it moves on. `generate-corpus.py` creates
a small structured corpus with
ordinary, EDNS, malformed, TCP and multipacket requests. `run.sh` refreshes
the named seeds so the DNS Cookie verification timestamp is current.

The live corpus grows as libFuzzer finds new paths. Stop `run.sh`, then use
`./reset-corpus.sh` when startup is spending too long reducing old inputs. It
archives the current corpus under `logs/old/` before creating a fresh named
seed corpus.

Each `run.sh` invocation writes LLVM profiles into a new directory under
`logs/profiles`. After stopping it, make a report with:

```console
./genreport.sh logs/profiles/SESSION_DIRECTORY 1
```

Generate the report before rebuilding that configuration. New profile
sessions record the NSD binary hash and reject a report from a different
build.

By default, libFuzzer runs in NSD's parent process and the normal NSD query
worker runs in a child process. CoverBridge uses a shared `trace-pc-guard` map
to bring the worker's site coverage and hit counts back to stock libFuzzer
before each input returns. The bridge source used by the build is under
`coverbridge/`. Its comparison operands and value profiles do not cross the
process boundary, so this build uses worker site and hit-count guidance. Use
`--single-process` when comparing against the older harness layout.

The parent starts libFuzzer only after the query worker has been forked. If a
query worker dies, the parent also stops so `run.sh` can preserve libFuzzer's
current input and restart the complete instance without forking from a
multithreaded process. LLVM source coverage is collected separately with
continuous atomic counters, so coverage survives crashes and normal stops.
The text report is `coverage.txt`; open `html/index.html` for the browsable
map. `coverage-core.txt` reports the DNS request, answer and IXFR code
separately.
`coverage-network.txt` adds the server, transfer, rate-limit and TSIG paths.
The whole-program number also includes NSD control, reload, transfer-client,
TLS and zone-maintenance code that network query inputs cannot normally reach.

Check every compiled object and all 30 installed NSD fuzzers for ASan, UBSan,
shared guard coverage, CoverBridge/libFuzzer guidance and source coverage with:

```console
nice -n 19 ionice -c 3 ./checkObjects.sh
```

The result is written to `logs/symbolReport.md`. ASan and UBSan do not produce
runtime logs during a clean fuzzing run; a log appears only when a sanitizer
finds a problem.

Build output is written to `logs/buildN.log`, server output to `logs/errorN.log`
and sanitizer output to `logs/asanN.log.PID`. ASan and UBSan use the same Clang
runtime, so both report types go to that file. Findings write the triggering
input under `logs/artifacts/`, then `run.sh` restarts the affected configuration
after two seconds. Use `--no-restart` when a configuration should stay stopped
for debugging. Leak detection remains disabled.
`asanProcess.sh` writes normalized unique reports to `asanfiltered.log`. The
normalized reports are kept under `logs/sanitizer-unique/`, and the original
reports are compressed under `logs/old/asan/` and `logs/old/ubsan/`. LLVM
profiles stay under `logs/profiles/`.

The build logs are produced by the normal all-configuration build. A single
`./build.sh -c=N` build writes directly to the terminal, matching the 389
fuzzer's command behavior. Watch a running libFuzzer with:

```console
tail -f logs/error1.log
```

Use `./run.sh --stdout -c=1` when the output should stay in the terminal. Stop
an all-configuration run with Ctrl-C in its terminal. From another shell, the
campaign owner can be stopped with:

```console
kill -TERM "$(cat run/run_1/run/fuzzer.owner)"
```

Coverage reports are written under
`logs/coverage/SESSION_DIRECTORY/run_N/`. Run `./asanProcess.sh` manually to
normalize and archive any sanitizer logs without waiting for the next run.

The reason for the parent/worker layout, the iteration boundary and the
failure/restart behavior are documented in `ARCHITECTURE.md`.
