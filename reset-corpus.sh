#!/usr/bin/env bash
set -euo pipefail

directory="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
timestamp="$(date -u +%Y%m%dT%H%M%SZ)"

mkdir -p "$directory/run/locks"
exec 7>"$directory/run/locks/campaign.lock"
if ! flock -n 7; then
    echo "A fuzzing campaign is running."
    echo "Stop it before resetting the corpus."
    exit 1
fi
exec 6>"$directory/run/locks/corpus.lock"
flock 6

# The exclusive campaign lock proves no supported run.sh instance is active.
# Still reject orphaned NSD processes before removing stale ownership records.
for proc in /proc/[0-9]*/exe; do
    running_binary="$(readlink "$proc" 2>/dev/null)" || continue
    running_binary="${running_binary% (deleted)}"
    case "$running_binary" in
    "$directory"/run/run_[0-9]*/sbin/nsd)
        echo "An NSD fuzzing process is still running: $running_binary"
        echo "Stop it before resetting the corpus."
        exit 1
        ;;
    esac
done

for owner_file in "$directory"/run/run_*/run/fuzzer.owner; do
    [ -e "$owner_file" ] || continue
    rm -f -- "$owner_file"
done

mkdir -p "$directory/logs/old"
if [ -d "$directory/corpus" ]; then
    archive="$directory/logs/old/corpus-$timestamp.tar.gz"
    tar -C "$directory" -czf "$archive" corpus
    echo "Archived the old corpus to $archive"
fi

NSD_FUZZ_CORPUS_LOCKED=1 \
    "$directory/generate-corpus.py" --clean "$directory/corpus"
