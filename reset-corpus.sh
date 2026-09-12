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

for owner_file in "$directory"/run/run_*/run/fuzzer.owner; do
    [ -s "$owner_file" ] || continue
    owner="$(cat "$owner_file")"
    echo "A fuzzing campaign owns a configuration under run.sh PID $owner."
    echo "Stop it before resetting the corpus."
    exit 1
done

mkdir -p "$directory/logs/old"
if [ -d "$directory/corpus" ]; then
    archive="$directory/logs/old/corpus-$timestamp.tar.gz"
    tar -C "$directory" -czf "$archive" corpus
    echo "Archived the old corpus to $archive"
fi

NSD_FUZZ_CORPUS_LOCKED=1 \
    "$directory/generate-corpus.py" --clean "$directory/corpus"
