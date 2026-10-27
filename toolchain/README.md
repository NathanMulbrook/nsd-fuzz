# LLVM toolchain

The NSD fuzzer uses a local LLVM 23.1.1 toolchain so Clang, ASan, UBSan,
libFuzzer and the coverage tools always match.

Build it once with `./build.sh --bootstrap-toolchain`. The build needs about 80
GB free while compiling and installs under `toolchain/llvm-23.1.1`. Sources and
intermediate files are left in `toolchain/work` and can be removed afterward.

`LLVM_ROOT`, `LLVM_TOOLCHAIN_WORK_DIR`, `LLVM_TOOLCHAIN_JOBS` and
`LLVM_MIN_FREE_GB` can override the defaults.

`build.sh` uses a repository-local ccache at `toolchain/ccache` when ccache is
installed. Set `NSD_FUZZ_CCACHE=0` to disable it or
`NSD_FUZZ_CCACHE_MAXSIZE=SIZE` to change the 20G default.
