# Fuzzer architecture

NSD normally forks its network workers. libFuzzer and SanitizerCoverage keep
their live guidance in process memory, so a libFuzzer loop in the NSD parent
cannot see coverage written only by a query worker. LLVM source profiles are
file-backed and are useful for reports, but they do not guide the current
libFuzzer input.

The fuzzer therefore keeps libFuzzer in NSD's server-main parent and runs
exactly one normal query worker. CoverBridge allocates a shared
`trace-pc-guard` counter map before the fork. Only the query worker records into
that map. After each input, the parent snapshots the map into libFuzzer's extra
counters. This gives stock libFuzzer worker edge-site and hit-count feedback
while preserving NSD's normal query process boundary. Comparison operands and
value profiles remain process-local and are not imported.

`server-count: 1` is required and enforced because one input must have one
worker and one coverage snapshot. xfrd forks before the bridge producer is
enabled and remains outside input coverage. Reload is ignored during a fuzzing
campaign because replacing the worker would invalidate the shared state and
the input boundary.

The worker parks before every input. The parent clears the shared counters,
releases the worker, sends the input, waits for the worker to finish, and then
imports the snapshot. A UDP iteration covers one receive-handler batch. A TCP
iteration covers one connection, including every packet or write chunk in a
multipacket input. These boundaries keep coverage from adjacent inputs out of
the snapshot.

If the query worker exits, the parent exits too. `run.sh` retains libFuzzer's
artifact and restarts the complete NSD tree after two seconds. Forking a new
worker from a running multithreaded libFuzzer parent would be unsafe and would
also make the coverage boundary ambiguous. `--no-restart` leaves the instance
stopped for debugging.

`--single-process` keeps the same park/release boundary while running the DNS
handler in the libFuzzer process. It is useful as a coverage comparison and
diagnostic mode; the default parent/worker mode exercises the production
process layout.

Every NSD target object is built with ASan, UBSan, source coverage, and
`trace-pc-guard`. The fuzzer controller and CoverBridge objects are deliberately
outside the shared guard map. `checkObjects.sh` verifies that split in all
object files and all 36 installed NSD binaries. A clean run produces no ASan or
UBSan report. libFuzzer status always goes to `logs/errorN.log` unless
`--stdout` is used; sanitizer findings go to `logs/asanN.log.PID`.
