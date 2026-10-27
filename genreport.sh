#!/usr/bin/env bash
set -euo pipefail

directory="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
source "$directory/toolchain/use-llvm.sh"

if [ "$#" -ne 2 ]; then
    echo "Usage: ./genreport.sh PROFILE_SESSION BUILD_CONFIG"
    echo "Example: ./genreport.sh logs/profiles/20260911T120000Z-1234 1"
    exit 1
fi

profile_session="$(realpath "$1")"
build_config="$2"
profile_dir="$profile_session/run_$build_config"
binary="$directory/run/run_$build_config/sbin/nsd"
report_dir="$directory/logs/coverage/$(basename "$profile_session")/run_$build_config"
source_dir="$directory/build/src_$build_config"
binary_hash_file="$profile_dir/nsd.sha256"

if [ ! -x "$binary" ]; then
    echo "Missing NSD binary: $binary"
    exit 1
fi

if [ -f "$binary_hash_file" ]; then
    expected_hash="$(tr -cd '0-9a-f' <"$binary_hash_file")"
    current_hash="$(sha256sum "$binary" | cut -d ' ' -f 1)"
    if [ "$expected_hash" != "$current_hash" ]; then
        echo "Build $build_config changed after this profile was recorded."
        echo "Generate coverage before rebuilding that configuration."
        exit 1
    fi
fi

mapfile -t profiles < <(find "$profile_dir" -type f -name '*.profraw' -size +0c | sort)
if [ "${#profiles[@]}" -eq 0 ]; then
    echo "No profiles found in $profile_dir"
    exit 1
fi

mkdir -p "$report_dir"
llvm-profdata merge -sparse "${profiles[@]}" -o "$report_dir/coverage.profdata"
llvm-cov report "$binary" \
    -instr-profile="$report_dir/coverage.profdata" >"$report_dir/coverage.txt"
llvm-cov report "$binary" \
    -instr-profile="$report_dir/coverage.profdata" \
    "$source_dir/answer.c" \
    "$source_dir/axfr.c" \
    "$source_dir/dname.c" \
    "$source_dir/edns.c" \
    "$source_dir/ixfr.c" \
    "$source_dir/nsec3.c" \
    "$source_dir/packet.c" \
    "$source_dir/query.c" >"$report_dir/coverage-core.txt"
llvm-cov report "$binary" \
    -instr-profile="$report_dir/coverage.profdata" \
    "$source_dir/answer.c" \
    "$source_dir/axfr.c" \
    "$source_dir/dname.c" \
    "$source_dir/edns.c" \
    "$source_dir/ixfr.c" \
    "$source_dir/nsec3.c" \
    "$source_dir/packet.c" \
    "$source_dir/query.c" \
    "$source_dir/rrl.c" \
    "$source_dir/server.c" \
    "$source_dir/tsig.c" \
    "$source_dir/difffile.c" \
    "$source_dir/ipc.c" \
    "$source_dir/xfrd.c" \
    "$source_dir/xfrd-catalog-zones.c" \
    "$source_dir/xfrd-disk.c" \
    "$source_dir/xfrd-notify.c" \
    "$source_dir/xfrd-tcp.c" \
    "$source_dir/util/proxy_protocol.c" >"$report_dir/coverage-network.txt"
llvm-cov show "$binary" -format=html \
    -output-dir="$report_dir/html" \
    -instr-profile="$report_dir/coverage.profdata"

echo "Coverage report: $report_dir/coverage.txt"
echo "DNS query coverage: $report_dir/coverage-core.txt"
echo "DNS network coverage: $report_dir/coverage-network.txt"
echo "HTML report: $report_dir/html/index.html"
