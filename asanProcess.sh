#!/usr/bin/env bash

set -euo pipefail

directory="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
cd "$directory" || exit

mkdir -p logs/old/asan logs/old/ubsan logs/sanitizer-unique run

caller_has_lock=0
if [ -d "/proc/$PPID/fd" ]; then
    for fd in /proc/"$PPID"/fd/*; do
        if [ -e "$fd" ] && [ "run/maintenance.lock" -ef "$fd" ]; then
            caller_has_lock=1
            break
        fi
    done
fi
if [ "$caller_has_lock" -eq 0 ]; then
    exec 8>run/maintenance.lock
    flock 8
fi

sanitizer_logs=()
while IFS= read -r -d '' log; do
    pid="${log##*.}"
    if [[ "$pid" =~ ^[0-9]+$ ]] && [ -d "/proc/$pid/fd" ]; then
        for fd in /proc/"$pid"/fd/*; do
            if [ -e "$fd" ] && [ "$log" -ef "$fd" ]; then
                continue 2
            fi
        done
    fi
    sanitizer_logs+=("$log")
done < <(
    find logs -maxdepth 1 -type f ! -name '*.gz' \
        \( -name 'asan*.log.*' -o -name 'ubsan*.log.*' \) \
        -mmin +0 -print0
)
if [ "${#sanitizer_logs[@]}" -eq 0 ]; then
    echo "No new sanitizer logs found."
    exit
fi

tmpdir="$(mktemp -d "$directory/run/asan-process.XXXXXX")"
trap 'rm -rf -- "$tmpdir"' EXIT

for log in "${sanitizer_logs[@]}"; do
    normalized="$tmpdir/normalized.log"
    sed -E \
        -e '/SUMMARY: UndefinedBehaviorSanitizer: undefined-behavior /d' \
        -e '/note: pointer points here/d' \
        -e '/note: nonnull attribute specified here/d' \
        -e '/(.{1,2}[0-9a-f]{2}){32}/d' \
        -e 's/(==)[0-9]{3,}(==)/==????==/g' \
        -e 's/(0x)[0-9a-fA-F]{3,}/????/g' \
        -e 's/([Tt]hread T)[0-9]{1,3}/thread T???/g' \
        -e 's/(src_)[0-9]{1,2}/src_?/g' \
        -e 's/(run_)[0-9]{1,2}/run_?/g' \
        "$log" >"$normalized"

    if [ -s "$normalized" ]; then
        signature="$(sha256sum "$normalized")"
        signature="${signature%% *}"
        if [ ! -e "logs/sanitizer-unique/$signature.log" ]; then
            cp "$normalized" "$tmpdir/$signature.log"
            mv "$tmpdir/$signature.log" "logs/sanitizer-unique/$signature.log"
        fi
    fi
done

report="$tmpdir/asanfiltered.log"
: >"$report"
shopt -s nullglob
unique_reports=(logs/sanitizer-unique/*.log)
for unique_report in "${unique_reports[@]}"; do
    cat "$unique_report" >>"$report"
    printf '\n' >>"$report"
done
mv "$report" asanfiltered.log

for log in "${sanitizer_logs[@]}"; do
    case "$log" in
        logs/asan*) archive=logs/old/asan ;;
        logs/ubsan*) archive=logs/old/ubsan ;;
    esac

    archived="$archive/$(basename "$log").gz"
    if [ -e "$archived" ]; then
        archived="$(mktemp "$archive/$(basename "$log").XXXXXX.gz")"
        rm -f -- "$archived"
    fi
    gzip -c -- "$log" >"$tmpdir/archive.gz"
    mv "$tmpdir/archive.gz" "$archived"
    rm -f -- "$log"
done

printf 'Unique sanitizer reports: %s\n' "${#unique_reports[@]}"
