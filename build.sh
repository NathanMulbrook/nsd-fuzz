#!/usr/bin/env bash
set -euo pipefail

directory="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
source "$directory/source-version.sh"

CONFIG="all"
CONFIG_COUNT=36
PATCH=1
DOWNLOAD_ONLY=0
BUILD_INIT=0
JOBS="${NSD_FUZZ_JOBS:-1}"

help() {
    echo "Usage: ./build.sh [options]"
    echo "  --config=N, -c=N       Build one configuration"
    echo "  --all                  Build all 36 configurations (default)"
    echo "  --jobs, -j             Build with four jobs"
    echo "  --jobs=N, -j=N         Parallel make jobs"
    echo "  --no-patch, -p"
    echo "                          Build clean NSD without the fuzzer patches"
    echo "  --init, -i             Clone the patch repositories and download NSD"
    echo "  --download             Download and verify the source, then exit"
    echo "  --bootstrap-toolchain  Build the pinned LLVM toolchain, then exit"
    echo "  --help, -h             Show this help"
}

for arg in "$@"; do
    case "$arg" in
    --help | -h)
        help
        exit
        ;;
    --bootstrap-toolchain)
        "$directory/toolchain/build-llvm.sh"
        exit
        ;;
    --init | -i)
        BUILD_INIT=1
        DOWNLOAD_ONLY=1
        ;;
    --download)
        DOWNLOAD_ONLY=1
        ;;
    --all)
        CONFIG="all"
        ;;
    --no-patch | -p)
        PATCH=0
        ;;
    --jobs | -j)
        JOBS=4
        ;;
    --config=* | -c=*)
        CONFIG="${arg#*=}"
        ;;
    --jobs=* | -j=*)
        JOBS="${arg#*=}"
        ;;
    *)
        echo "Unknown option: $arg"
        help
        exit 1
        ;;
    esac
done

if [ "$BUILD_INIT" -eq 1 ]; then
    if [ ! -d "$directory/nsd-patches/.git" ]; then
        git clone https://github.com/NathanMulbrook/nsd-patches.git \
            "$directory/nsd-patches"
    fi
    if [ ! -d "$directory/nsd-patches-private/.git" ]; then
        if ! git clone git@github.com:NathanMulbrook/nsd-patches-private.git \
                "$directory/nsd-patches-private"; then
            echo "Private patches were not cloned; continuing with public patches."
        fi
    fi
fi

case "$JOBS" in
    "" | 0 | *[!0-9]*)
        echo "Job count must be a positive number."
        exit 1
        ;;
esac

lock_dir="$directory/run/locks"
mkdir -p "$lock_dir"
archive="$directory/downloads/nsd-$NSD_VERSION.tar.gz"

download_source() {
    local source_lock_fd

    exec {source_lock_fd}>"$lock_dir/source.lock"
    flock "$source_lock_fd"
    mkdir -p "$directory/downloads"
    if [ ! -f "$archive" ]; then
        echo "Downloading NSD $NSD_VERSION"
        curl --fail --location --retry 3 --output "$archive.part" "$NSD_SOURCE_URL"
        mv "$archive.part" "$archive"
    fi
    printf '%s  %s\n' "$NSD_SOURCE_SHA256" "$archive" | sha256sum --check
    flock -u "$source_lock_fd"
    exec {source_lock_fd}>&-
}

download_source
if [ "$DOWNLOAD_ONLY" -eq 1 ]; then
    exit
fi

source "$directory/toolchain/use-llvm.sh" || exit

profile_continuous_flag="-fprofile-continuous"
if [ "${NSD_FUZZ_CCACHE:-1}" != "0" ]; then
    if command -v ccache >/dev/null; then
        ccache_command="$(command -v ccache)"
        export CCACHE_DIR="$directory/toolchain/ccache"
        export CCACHE_TEMPDIR="$CCACHE_DIR/tmp"
        export CCACHE_MAXSIZE="${NSD_FUZZ_CCACHE_MAXSIZE:-20G}"
        mkdir -p "$CCACHE_TEMPDIR"
        "$ccache_command" --max-size "$CCACHE_MAXSIZE" >/dev/null
        "$ccache_command" --set-config "temporary_dir=$CCACHE_TEMPDIR" >/dev/null
        export CC="$ccache_command $CC"
        export CXX="$ccache_command $CXX"
        profile_continuous_flag="--ccache-skip -fprofile-continuous"
        echo "Using ccache at $CCACHE_DIR"
    else
        echo "ccache was not found; building without it"
    fi
fi

export CFLAGS="-g \
    -O1 \
    -fno-omit-frame-pointer \
    -fno-optimize-sibling-calls \
    -fno-common \
    -fsanitize=address,undefined \
    -fsanitize-recover=all \
    -fprofile-instr-generate \
    $profile_continuous_flag \
    -fprofile-update=atomic \
    -fcoverage-mapping \
    -fsanitize-coverage=trace-pc-guard \
    -fsanitize-address-use-after-scope \
    -U_FORTIFY_SOURCE \
    -D_FORTIFY_SOURCE=0 \
    -pthread"
export CXXFLAGS="$CFLAGS"
export LSAN_OPTIONS=detect_leaks=0

config_build() {
    case "$BUILD_CONFIG" in
    1)
        config_flags=(--enable-checking)
        ;;
    2)
        config_flags=(--enable-checking --enable-recvmmsg)
        ;;
    3)
        config_flags=(--disable-minimal-responses)
        ;;
    4)
        config_flags=(--enable-checking --disable-radix-tree)
        ;;
    5)
        config_flags=(--disable-ipv6)
        ;;
    6)
        config_flags=(--disable-bind8-stats --disable-zone-stats)
        ;;
    7)
        config_flags=(--disable-ratelimit)
        ;;
    8)
        config_flags=(--disable-nsec3)
        ;;
    9)
        config_flags=(--enable-checking --enable-memclean)
        ;;
    10)
        config_flags=(--enable-mmap)
        ;;
    11)
        config_flags=(--enable-tcp-fastopen)
        ;;
    12)
        config_flags=(--enable-checking --disable-westmere)
        ;;
    13)
        config_flags=(--disable-haswell)
        ;;
    14)
        config_flags=(--disable-westmere --disable-haswell)
        ;;
    15)
        config_flags=(--enable-log-role)
        ;;
    16)
        config_flags=(--enable-multiple-catalog-zones)
        ;;
    17)
        config_flags=(--disable-ratelimit-default-is-off)
        ;;
    18)
        config_flags=(--with-max-cname-chain=1)
        ;;
    19)
        config_flags=(--with-max-cname-chain=64)
        ;;
    20)
        config_flags=(--with-tcp-timeout=1)
        ;;
    21)
        config_flags=(--with-tcp-timeout=3600)
        ;;
    22)
        config_flags=(--enable-recvmmsg)
        ;;
    23)
        config_flags=(--enable-recvmmsg --disable-minimal-responses)
        ;;
    24)
        config_flags=(--disable-minimal-responses --disable-radix-tree)
        ;;
    25)
        config_flags=(--enable-mmap --enable-memclean)
        ;;
    26)
        config_flags=(--disable-nsec3 --disable-ratelimit)
        ;;
    27)
        config_flags=(--disable-bind8-stats --disable-zone-stats --disable-nsec3 --disable-ratelimit)
        ;;
    28)
        config_flags=()
        ;;
    29)
        config_flags=()
        ;;
    30)
        config_flags=(--enable-checking --enable-memclean --disable-ipv6 --disable-nsec3 --disable-ratelimit --disable-zone-stats --disable-bind8-stats --disable-westmere --disable-haswell)
        ;;
    31)
        config_flags=(--enable-packed)
        ;;
    32)
        config_flags=(--enable-packed --disable-radix-tree)
        ;;
    33)
        config_flags=(--enable-packed --enable-mmap)
        ;;
    34)
        config_flags=(--enable-packed --enable-recvmmsg)
        ;;
    35)
        config_flags=(--enable-packed --disable-minimal-responses)
        ;;
    36)
        config_flags=(--enable-packed --disable-westmere --disable-haswell)
        ;;
    *)
        echo "Build configuration must be between 1 and $CONFIG_COUNT."
        exit 1
        ;;
    esac
}

apply_patches() {
    local patch_dir
    local patch_file
    local patch_files
    local patch_dirs=(
        "$directory/nsd-patches/patches"
        "$directory/nsd-patches-private/patches"
    )

    if [ ! -d "${patch_dirs[0]}" ] || \
        ! compgen -G "${patch_dirs[0]}/*.patch" >/dev/null; then
        echo "Missing public patches under nsd-patches/patches."
        echo "Run ./build.sh --init first."
        exit 1
    fi

    shopt -s nullglob
    for patch_dir in "${patch_dirs[@]}"; do
        patch_files=("$patch_dir"/*.patch)
        for patch_file in "${patch_files[@]}"; do
            GIT_CEILING_DIRECTORIES="$directory" git apply --check "$patch_file"
            GIT_CEILING_DIRECTORIES="$directory" git apply --whitespace=nowarn "$patch_file"
            echo "Applied ${patch_file#"$directory/"}"
        done
    done
    shopt -u nullglob
}

build_software() {
    local build_dir="$directory/build/build_$BUILD_CONFIG"
    local source_dir="$directory/build/src_$BUILD_CONFIG"
    local run_dir="$directory/run/run_$BUILD_CONFIG"
    local port=$((5300 + BUILD_CONFIG))
    local user
    local owner
    local common_flags
    local build_cflags="$CFLAGS"
    local build_cxxflags="$CXXFLAGS"
    local config_lock_fd

    user="$(id -un)"
    config_build

    if [[ " ${config_flags[*]} " == *" --enable-packed "* ]]; then
        build_cflags="$build_cflags -fno-sanitize=alignment"
        build_cxxflags="$build_cxxflags -fno-sanitize=alignment"
    fi

    exec {config_lock_fd}>"$lock_dir/config_$BUILD_CONFIG.lock"
    flock "$config_lock_fd"

    if [ "$BUILD_CONFIG" -eq 29 ]; then
        build_cflags="${build_cflags/ -O1 / -O2 }"
        build_cxxflags="${build_cxxflags/ -O1 / -O2 }"
    fi

    echo "Building NSD $NSD_VERSION configuration $BUILD_CONFIG on port $port"
    if [ -s "$run_dir/run/fuzzer.owner" ]; then
        owner="$(cat "$run_dir/run/fuzzer.owner")"
        if kill -0 "$owner" 2>/dev/null; then
            echo "Configuration $BUILD_CONFIG is owned by run.sh PID $owner."
            echo "Stop it before rebuilding."
            exit 1
        fi
        rm -f "$run_dir/run/fuzzer.owner"
    fi
    rm -rf "$build_dir" "$source_dir" "$run_dir"
    mkdir -p "$build_dir" "$source_dir" "$run_dir/log" \
        "$run_dir/run" "$run_dir/var/db/nsd" "$run_dir/etc/nsd"
    tar -xzf "$archive" --strip-components=1 -C "$source_dir"

    cd "$source_dir"
    if [ "$PATCH" -eq 1 ]; then
        apply_patches
        cp "$directory/fuzzer.c" "$directory/fuzzer.h" "$source_dir/"
        cp -R "$directory/coverbridge" "$source_dir/"
        sed -i \
            -e "s/FUZZ_PORT/$port/g" \
            -e "s#FuzzingCorpusDirectory#$directory/corpus#g" \
            -e "s#FuzzingDictionary#$directory/dict.txt#g" \
            -e "s#FuzzingArtifactDirectory#$directory/logs/artifacts#g" \
            "$source_dir/fuzzer.c"
    fi

    common_flags=(
        --prefix="$run_dir"
        --with-configdir="$run_dir/etc/nsd"
        --with-nsd_conf_file="$run_dir/etc/nsd/nsd.conf"
        --with-zonesdir="$run_dir/etc/nsd"
        --with-dbfile="$run_dir/var/db/nsd/nsd.db"
        --with-xfrdfile="$run_dir/var/db/nsd/xfrd.state"
        --with-zonelistfile="$run_dir/var/db/nsd/zone.list"
        --with-xfrdir="$run_dir/var/db/nsd"
        --with-pidfile="$run_dir/run/nsd.pid"
        --with-logfile="$run_dir/log/nsd.log"
        --with-user="$user"
        --with-libevent=no
        --disable-dnstap
    )

    cd "$build_dir"
    CFLAGS="$build_cflags" CXXFLAGS="$build_cxxflags" \
        "$source_dir/configure" "${common_flags[@]}" "${config_flags[@]}"
    make -j "$JOBS" install

    sed \
        -e "s#RUN_DIRECTORY#$run_dir#g" \
        -e "s/RUN_USER/$user/g" \
        -e "s/FUZZ_PORT/$port/g" \
        "$directory/nsd.conf" >"$run_dir/etc/nsd/nsd.conf"
    if [ "$BUILD_CONFIG" -eq 17 ]; then
        sed -i '/    verbosity: 2/a\
    rrl-ratelimit: 1\
    rrl-whitelist-ratelimit: 1\
    rrl-slip: 2' "$run_dir/etc/nsd/nsd.conf"
    fi
    if [ "$BUILD_CONFIG" -eq 22 ]; then
        sed -i \
            -e 's/ip-address: 127.0.0.1/ip-address: ::1/' \
            -e 's/do-ip4: yes/do-ip4: no/' \
            -e 's/do-ip6: no/do-ip6: yes/' \
            "$run_dir/etc/nsd/nsd.conf"
    fi
    if [ "$BUILD_CONFIG" -eq 28 ]; then
        sed -i \
            -e "/    verbosity: 2/a\\
    proxy-protocol-port: $port\\
    allow-proxy: 127.0.0.1" \
            -e '/    name: example.com/a\
    allow-query: 192.0.2.1 NOKEY\
    allow-query: 198.51.100.1 BLOCKED' \
            -e '/    name: example.org/a\
    allow-query: 0.0.0.0/0 NOKEY\
    allow-query: 127.0.0.1 BLOCKED' \
            "$run_dir/etc/nsd/nsd.conf"
    fi
    if [[ " ${config_flags[*]} " == *" --disable-ipv6 "* ]]; then
        sed -i '/provide-xfr: ::/d' "$run_dir/etc/nsd/nsd.conf"
    fi
    cp "$directory"/*.zone "$run_dir/etc/nsd/"
    "$run_dir/sbin/nsd-checkconf" "$run_dir/etc/nsd/nsd.conf"
    "$run_dir/sbin/nsd-checkzone" example.com "$run_dir/etc/nsd/example.com.zone"
    "$run_dir/sbin/nsd-checkzone" example.org "$run_dir/etc/nsd/example.org.zone"
    "$run_dir/sbin/nsd-checkzone" example "$run_dir/etc/nsd/nsec3.example.zone"
    echo "Installed $run_dir/sbin/nsd"
}

mkdir -p "$directory/logs/artifacts"
exec {corpus_lock_fd}>"$lock_dir/corpus.lock"
flock "$corpus_lock_fd"
if [ ! -d "$directory/corpus" ] || [ -z "$(find "$directory/corpus" -maxdepth 1 -type f -print -quit)" ]; then
    NSD_FUZZ_CORPUS_LOCKED=1 \
        "$directory/generate-corpus.py" "$directory/corpus"
fi
flock -u "$corpus_lock_fd"
exec {corpus_lock_fd}>&-

if [ "$CONFIG" = "all" ]; then
    mkdir -p "$directory/logs/old/asan" "$directory/logs/old/ubsan" \
        "$directory/logs/old/error" "$directory/logs/old/build" \
        "$directory/run"
    sed "s#@ROOT@#$directory#g" "$directory/logrotate.conf" \
        >"$directory/run/logrotate.conf"
    if command -v logrotate >/dev/null; then
        logrotate --force "$directory/run/logrotate.conf" \
            -s "$directory/logs/old/logrotate.status" || true
    fi
    build_pids=()
    child_args=()
    if [ "$PATCH" -eq 0 ]; then
        child_args+=(--no-patch)
    fi
    failed=0
    for ((BUILD_CONFIG = 1; BUILD_CONFIG <= CONFIG_COUNT; BUILD_CONFIG++)); do
        echo "Starting build $BUILD_CONFIG of $CONFIG_COUNT"
        "$directory/build.sh" --config="$BUILD_CONFIG" --jobs="$JOBS" \
            "${child_args[@]}" 2>&1 | \
            tee "$directory/logs/build$BUILD_CONFIG.log" &
        build_pids[$BUILD_CONFIG]="$!"
    done
    for ((BUILD_CONFIG = 1; BUILD_CONFIG <= CONFIG_COUNT; BUILD_CONFIG++)); do
        if wait "${build_pids[$BUILD_CONFIG]}"; then
            echo "Finished build $BUILD_CONFIG"
        else
            echo "Build $BUILD_CONFIG failed. See logs/build$BUILD_CONFIG.log"
            failed=1
        fi
    done
    exit "$failed"
else
    BUILD_CONFIG="$CONFIG"
    build_software
fi
