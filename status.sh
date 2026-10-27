#!/usr/bin/env bash
set -u

directory="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
CONFIG="all"
CONFIG_COUNT="$(sed -n 's/^CONFIG_COUNT=//p' "$directory/run.sh" | head -n 1)"

help() {
    echo "Usage: ./status.sh [options]"
    echo "  --config=N, -c=N  Show one configuration"
    echo "  --all             Show all configurations (default)"
    echo "  --help, -h        Show this help"
}

for arg in "$@"; do
    case "$arg" in
    --all)
        CONFIG="all"
        ;;
    --config=* | -c=*)
        CONFIG="${arg#*=}"
        ;;
    --help | -h)
        help
        exit
        ;;
    *)
        echo "Unknown option: $arg" >&2
        help >&2
        exit 1
        ;;
    esac
done

case "$CONFIG_COUNT" in
'' | *[!0-9]*)
    echo "Could not read CONFIG_COUNT from run.sh." >&2
    exit 1
    ;;
esac

if [ "$CONFIG" != "all" ]; then
    case "$CONFIG" in
    '' | *[!0-9]*)
        echo "Configuration must be between 1 and $CONFIG_COUNT." >&2
        exit 1
        ;;
    esac
    if [ "$CONFIG" -lt 1 ] || [ "$CONFIG" -gt "$CONFIG_COUNT" ]; then
        echo "Configuration must be between 1 and $CONFIG_COUNT." >&2
        exit 1
    fi
    first_config="$CONFIG"
    last_config="$CONFIG"
else
    first_config=1
    last_config="$CONFIG_COUNT"
fi

read -r corpus_files corpus_latest < <(
    find "$directory/corpus" -maxdepth 1 -type f -printf '%T@\n' 2>/dev/null |
        awk '{ count++; if ($1 > latest) latest=$1 }
             END { printf "%d %.0f\n", count, latest }'
)
corpus_size="$(du -sh "$directory/corpus" 2>/dev/null | awk '{print $1}')"
corpus_size="${corpus_size:-0}"
now="$(date +%s)"
if [ "$corpus_latest" -gt 0 ]; then
    corpus_age="$((now - corpus_latest))"
else
    corpus_age=0
fi

fuzzing=0
server_only=0
starting=0
stopped=0
missing=0
lines=()
declare -A config_processes=()

for proc in /proc/[0-9]*/exe; do
    actual_exe="$(readlink "$proc" 2>/dev/null)" || continue
    actual_exe="${actual_exe% (deleted)}"
    case "$actual_exe" in
    "$directory"/run/run_[0-9]*/sbin/nsd)
        process_config="${actual_exe#"$directory/run/run_"}"
        process_config="${process_config%%/*}"
        pid="${proc#/proc/}"
        pid="${pid%/exe}"
        config_processes["$process_config"]+=" $pid"
        ;;
    esac
done

for ((config_id = first_config; config_id <= last_config; config_id++)); do
    run_dir="$directory/run/run_$config_id"
    binary="$run_dir/sbin/nsd"
    owner_file="$run_dir/run/fuzzer.owner"
    error_file="$directory/logs/error$config_id.log"
    old_error_file="$directory/logs/old/error/error$config_id.log.1"
    state="stopped"
    detail=""

    if [ ! -x "$binary" ]; then
        state="missing"
        missing="$((missing + 1))"
    else
        process_list="${config_processes[$config_id]-}"
        if [ -n "$process_list" ]; then
            read -ra pids <<<"$process_list"
            mapfile -t pids < <(printf '%s\n' "${pids[@]}" | sort -n)
            root_pid="${pids[0]}"
            state="server-only"
            if tr '\0' '\n' <"/proc/$root_pid/environ" 2>/dev/null |
                    grep -qE '^NSD_FUZZ_(COVERBRIDGE|SINGLE_PROCESS)=1$'; then
                state="fuzzing"
            fi
            pid_list="$(IFS=,; echo "${pids[*]}")"
            read -r cpu rss < <(
                ps -p "$pid_list" -o %cpu=,rss= 2>/dev/null |
                    awk '{ cpu += $1; rss += $2 }
                         END { printf "%.1f %.0f\n", cpu, rss / 1024 }'
            )
            detail="pid=$root_pid procs=${#pids[@]} cpu=${cpu:-0.0}% rss=${rss:-0}MiB"
            if [ "$state" = "fuzzing" ]; then
                fuzzing="$((fuzzing + 1))"
            else
                server_only="$((server_only + 1))"
            fi
        elif [ -s "$owner_file" ]; then
            owner="$(cat "$owner_file" 2>/dev/null)" || true
            case "$owner" in
            '' | *[!0-9]*) owner="" ;;
            esac
            if [ -n "$owner" ] && kill -0 "$owner" 2>/dev/null; then
                state="starting"
                detail="runner=$owner"
                starting="$((starting + 1))"
            else
                stopped="$((stopped + 1))"
            fi
        else
            stopped="$((stopped + 1))"
        fi
    fi

    if [ "$state" = "fuzzing" ]; then
        progress="$(
            cat "$old_error_file" "$error_file" 2>/dev/null |
                grep -aE '^#[0-9]+.*(pulse|INITED|NEW|REDUCE|RELOAD|DONE)' |
                tail -n 1 || true
        )"
        if [ -n "$progress" ]; then
            detail+=" ${progress:0:180}"
        else
            detail+=" starting"
        fi
    fi
    lines+=("$(printf 'config %2d  %-11s %s' "$config_id" "$state" "$detail")")
done

echo "Profiles: $fuzzing fuzzing, $server_only server-only, $starting starting, $stopped stopped, $missing missing"
echo "Corpus: $corpus_files files, $corpus_size, newest file ${corpus_age}s ago"
printf '%s\n' "${lines[@]}"
