# CoverBridge subset

These files come from the supplied CoverBridge 0.1 source archive. NSD uses
the guard collector, snapshot storage and libFuzzer extra-counter adapter.
The wire protocol is unnecessary because the NSD parent and query worker share
the collector through `fork`.

`cb_producer_enable()` is the only local addition. The query worker calls it
after the fork so parent supervision and xfrd activity cannot be attributed to
fuzzer inputs.
