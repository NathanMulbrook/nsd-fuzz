#!/usr/bin/env bash
set -euo pipefail

directory="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
source "$directory/source-version.sh"

jobs="${NSD_STATIC_JOBS:-1}"
compiler="${NSD_STATIC_CC:-/usr/bin/gcc}"
archive="$directory/downloads/nsd-$NSD_VERSION.tar.gz"
full_log="$directory/logs/static-analysis-full.log"
summary_log="$directory/logs/static-analysis.log"

case "$jobs" in
"" | 0 | *[!0-9]*)
    echo "NSD_STATIC_JOBS must be a positive number."
    exit 1
    ;;
esac

if [ ! -x "$compiler" ]; then
    echo "GCC was not found at $compiler. Set NSD_STATIC_CC to its path."
    exit 1
fi
if ! "$compiler" --help=common 2>/dev/null | grep -q -- '-fanalyzer'; then
    echo "$compiler does not support -fanalyzer."
    exit 1
fi

if [ ! -f "$archive" ]; then
    "$directory/build.sh" --download
fi
printf '%s  %s\n' "$NSD_SOURCE_SHA256" "$archive" | sha256sum --check

mkdir -p "$directory/logs"
work_dir="$(mktemp -d "${TMPDIR:-/tmp}/nsd-static.XXXXXX")"
trap 'rm -rf -- "$work_dir"' EXIT
source_dir="$work_dir/source"
build_dir="$work_dir/build"
mkdir -p "$source_dir" "$build_dir"
tar -xzf "$archive" --strip-components=1 -C "$source_dir"

compiler_version="$("$compiler" --version | sed -n '1p')"
run_date="$(date --iso-8601=seconds)"

set +e
(
    cd "$build_dir"
    CC="$compiler" \
        CFLAGS="-O1 -g -fanalyzer -Wall -Wextra -Wformat=2" \
        "$source_dir/configure" \
        --with-user="$(id -un)" \
        --with-libevent=no \
        --disable-dnstap &&
        make -j "$jobs"
) >"$full_log" 2>&1
analysis_status=$?
set -e

warning_count="$(grep -c -E 'warning: .*\[-Wanalyzer-' "$full_log" || true)"
{
    echo "NSD static-analysis summary"
    echo "Date: $run_date"
    echo "Target: unmodified NSD $NSD_VERSION"
    echo "Compiler: $compiler_version"
    echo "Profile: release build; libevent and dnstap disabled; other optional features auto-detected"
    echo "CFLAGS: -O1 -g -fanalyzer -Wall -Wextra -Wformat=2"
    echo "Build exit status: $analysis_status"
    echo "Analyzer diagnostics: $warning_count"
    echo
    echo "These are unconfirmed leads, not findings. Reproduce a warning through"
    echo "the real server path before adding it to findings/."
    echo
    if [ "$warning_count" -eq 0 ]; then
        echo "No GCC analyzer diagnostics."
    else
        grep -E 'warning: .*\[-Wanalyzer-' "$full_log" | \
            sed -E "s#$work_dir/(source|build)#nsd-$NSD_VERSION#g" | \
            sort | uniq -c | sed -E 's/^ +1 /  /; s/^ +([0-9]+) /  \1x /' || true
    fi
    echo
    echo "Full compiler diagnostics: logs/static-analysis-full.log"
} >"$summary_log"

cat "$summary_log"
exit "$analysis_status"
