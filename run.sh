#!/usr/bin/env bash
set -uo pipefail

directory="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
source "$directory/toolchain/use-llvm.sh" || exit
CONFIG="all"
CONFIG_COUNT=36
SERVER_ONLY=0
SINGLE_PROCESS=0
PACKET_CAPTURE=0
LOG_OUTPUT=1
RESTART=1
pids=()
server_pids=()
declare -A pid_configs=()
declare -A owned_configs=()

help() {
    echo "Usage: ./run.sh [options]"
    echo "  --config=N, -c=N  Run one configuration"
    echo "  --all             Run all 36 configurations (default)"
    echo "  --server-only, --fuzz, -f"
    echo "                    Disable the embedded libFuzzer thread"
    echo "  --single-process  Run libFuzzer and the DNS loop in one process"
    echo "  --no-restart      Leave a configuration stopped after it exits"
    echo "  --packet, -p      Capture loopback DNS traffic with tcpdump"
    echo "  --stdout, -s      Send NSD output to the terminal"
    echo "  --help, -h        Show this help"
}

for arg in "$@"; do
    case "$arg" in
    --help | -h)
        help
        exit
        ;;
    --all)
        CONFIG="all"
        ;;
    --server-only | --fuzz | -f)
        SERVER_ONLY=1
        ;;
    --single-process)
        SINGLE_PROCESS=1
        ;;
    --no-restart)
        RESTART=0
        ;;
    --packet | -p)
        PACKET_CAPTURE=1
        ;;
    --stdout | -s | --LOG_OUPTUT)
        LOG_OUTPUT=0
        ;;
    --config=* | -c=*)
        CONFIG="${arg#*=}"
        ;;
    *)
        echo "Unknown option: $arg"
        help
        exit 1
        ;;
    esac
done

if [ "$CONFIG" != "a" ] && [ "$CONFIG" != "all" ]; then
    case "$CONFIG" in
    [1-9] | 1[0-9] | 2[0-9] | 3[0-6]) ;;
    *)
        echo "Configuration must be between 1 and $CONFIG_COUNT."
        exit 1
        ;;
    esac
fi

mkdir -p "$directory/logs/old/asan" "$directory/logs/old/ubsan" \
    "$directory/logs/old/error" "$directory/logs/old/build" \
    "$directory/logs/old/testCases" "$directory/logs/oldasan" \
    "$directory/run/locks"

exec 7>"$directory/run/locks/campaign.lock"
flock -s 7
exec 6>"$directory/run/locks/corpus.lock"
flock 6
NSD_FUZZ_CORPUS_LOCKED=1 \
    "$directory/generate-corpus.py" "$directory/corpus" || exit
flock -u 6
exec 6>&-

sed "s#tacos#$directory#g" "$directory/logrotate.conf" \
    >"$directory/run/logrotate.conf"
session="$(date -u +%Y%m%dT%H%M%SZ)-$$"
profile_dir="$directory/logs/profiles/$session"
mkdir -p "$profile_dir"

cleanup() {
    local build_config
    local owner
    local owner_file
    local pid
    local parent
    trap - INT TERM EXIT
    for pid in "${pids[@]}"; do
        parent="$(ps -o ppid= -p "$pid" 2>/dev/null)"
        parent="${parent//[[:space:]]/}"
        [ "$parent" = "$$" ] && kill -TERM "$pid" 2>/dev/null || true
    done
    for pid in "${pids[@]}"; do
        wait "$pid" 2>/dev/null || true
    done
    for build_config in "${!owned_configs[@]}"; do
        owner_file="$directory/run/run_$build_config/run/fuzzer.owner"
        owner="$(cat "$owner_file" 2>/dev/null)" || true
        [ "$owner" = "$$" ] && rm -f "$owner_file"
    done
}

trap cleanup EXIT
trap 'exit 130' INT TERM

find_old_instance() {
    local run_dir="$1"
    local binary="$run_dir/sbin/nsd"
    local proc
    local running_binary

    for proc in /proc/[0-9]*/exe; do
        running_binary="$(readlink "$proc" 2>/dev/null)" || continue
        running_binary="${running_binary% (deleted)}"
        [ "$running_binary" = "$binary" ] || continue
        old_pids+=("${proc#/proc/}")
        old_pids[-1]="${old_pids[-1]%/exe}"
        old_binaries["${old_pids[-1]}"]="$binary"
    done
}

old_instance_running() {
    local old_pid="$1"
    local running_binary

    running_binary="$(readlink "/proc/$old_pid/exe" 2>/dev/null)" || return 1
    running_binary="${running_binary% (deleted)}"
    [ "$running_binary" = "${old_binaries[$old_pid]}" ]
}

stop_old_instances() {
    local old_pid
    local attempt
    local alive

    for old_pid in "${old_pids[@]}"; do
        old_instance_running "$old_pid" && \
            kill -TERM "$old_pid" 2>/dev/null || true
    done
    for ((attempt = 0; attempt < 50; attempt++)); do
        alive=0
        for old_pid in "${old_pids[@]}"; do
            old_instance_running "$old_pid" && alive=1
        done
        [ "$alive" -eq 0 ] && return
        sleep 0.1
    done
    for old_pid in "${old_pids[@]}"; do
        if old_instance_running "$old_pid"; then
            kill -KILL "$old_pid" 2>/dev/null || true
        fi
    done
    for ((attempt = 0; attempt < 50; attempt++)); do
        alive=0
        for old_pid in "${old_pids[@]}"; do
            old_instance_running "$old_pid" && alive=1
        done
        [ "$alive" -eq 0 ] && return
        sleep 0.1
    done
    echo "Unable to stop an old NSD instance."
    return 1
}

old_pids=()
declare -A old_binaries=()
exec 9>"$directory/run/locks/start.lock"
flock 9

"$directory/asanProcess.sh" || true
exec 8>"$directory/run/maintenance.lock"
flock 8
if command -v logrotate >/dev/null; then
    logrotate --force "$directory/run/logrotate.conf" \
        -s "$directory/logs/old/logrotate.status" || true
fi
flock -u 8
exec 8>&-

run_instance() {
    local build_config="$1"
    local config_lock_fd="$2"
    local run_dir="$directory/run/run_$build_config"
    local binary="$run_dir/sbin/nsd"
    local config_file="$run_dir/etc/nsd/nsd.conf"
    local instance_profiles="$profile_dir/run_$build_config"
    local output_file="$directory/logs/error$build_config.log"
    local owner_file="$run_dir/run/fuzzer.owner"
    local profile_file="$instance_profiles/nsd-%m-%c.profraw"
    local asan_options
    local ubsan_options
    local env_args
    local pid
    local running_binary
    local attempt

    if [ ! -x "$binary" ]; then
        echo "Missing $binary. Run ./build.sh --config=$build_config first."
        return 1
    fi

    mkdir -p "$instance_profiles"
    printf '%s\n' "$$" >"$owner_file"
    owned_configs["$build_config"]=1
    sha256sum "$binary" | cut -d ' ' -f 1 >"$instance_profiles/nsd.sha256"
    asan_options="strict_string_checks=1:detect_stack_use_after_return=1:check_initialization_order=1:strict_init_order=1:log_path=$directory/logs/asan$build_config.log:halt_on_error=0"
    ubsan_options="halt_on_error=0:print_stacktrace=1"
    env_args=(
        "LLVM_PROFILE_FILE=$profile_file"
        "ASAN_SYMBOLIZER_PATH=$LLVM_ROOT/bin/llvm-symbolizer"
        "ASAN_OPTIONS=$asan_options"
        "UBSAN_OPTIONS=$ubsan_options"
        "LSAN_OPTIONS=detect_leaks=0"
    )
    if [ "$SERVER_ONLY" -eq 0 ]; then
        env_args+=("NSD_FUZZ_COVERBRIDGE=1")
    fi
    if [ "$SINGLE_PROCESS" -eq 1 ]; then
        env_args+=("NSD_FUZZ_SINGLE_PROCESS=1")
    fi
    if [ "$SERVER_ONLY" -eq 1 ]; then
        env_args+=("NSD_FUZZ_DISABLE=1")
    fi

    echo "Starting configuration $build_config"
    if [ "$LOG_OUTPUT" -eq 1 ]; then
        (
            exec {config_lock_fd}>&-
            exec 7>&-
            exec 9>&-
            exec env "${env_args[@]}" "$binary" -d -c "$config_file"
        ) >>"$output_file" 2>&1 &
    else
        (
            exec {config_lock_fd}>&-
            exec 7>&-
            exec 9>&-
            exec env "${env_args[@]}" "$binary" -d -c "$config_file"
        ) &
    fi
    pid="$!"
    pids+=("$pid")
    server_pids+=("$pid")
    pid_configs["$pid"]="$build_config"
    for ((attempt = 0; attempt < 50; attempt++)); do
        running_binary="$(readlink "/proc/$pid/exe" 2>/dev/null)" || true
        running_binary="${running_binary% (deleted)}"
        [ "$running_binary" = "$binary" ] && return
        kill -0 "$pid" 2>/dev/null || break
        sleep 0.1
    done
    echo "Configuration $build_config failed to start. Check $output_file."
    return 1
}

start_instance() {
    local build_config="$1"
    local config_lock_fd
    local status=0

    exec {config_lock_fd}>"$directory/run/locks/config_$build_config.lock"
    flock "$config_lock_fd"
    old_pids=()
    old_binaries=()
    find_old_instance "$directory/run/run_$build_config"
    if ! stop_old_instances; then
        status=1
    elif ! run_instance "$build_config" "$config_lock_fd"; then
        status=1
    fi
    flock -u "$config_lock_fd"
    exec {config_lock_fd}>&-
    return "$status"
}

maintain_logs() {
    while :; do
        sleep 60
        "$directory/asanProcess.sh" || true
        exec 8>"$directory/run/maintenance.lock"
        flock 8
        if command -v logrotate >/dev/null; then
            logrotate "$directory/run/logrotate.conf" \
                -s "$directory/logs/old/logrotate.status" || true
        fi
        flock -u 8
        exec 8>&-
    done
}

remove_pid() {
    local dead_pid="$1"
    local pid
    local remaining=()

    for pid in "${pids[@]}"; do
        [ "$pid" = "$dead_pid" ] || remaining+=("$pid")
    done
    pids=("${remaining[@]}")
    remaining=()
    for pid in "${server_pids[@]}"; do
        [ "$pid" = "$dead_pid" ] || remaining+=("$pid")
    done
    server_pids=("${remaining[@]}")
}

owns_config() {
    local build_config="$1"
    local owner_file="$directory/run/run_$build_config/run/fuzzer.owner"

    [ "$(cat "$owner_file" 2>/dev/null)" = "$$" ]
}

if [ "$PACKET_CAPTURE" -eq 1 ]; then
    tcpdump -i lo -w "$directory/logs/dump-$session.pcap" \
        'udp or tcp' 7>&- 9>&- &
    pids+=("$!")
fi

if [ "$CONFIG" = "a" ] || [ "$CONFIG" = "all" ]; then
    for ((build_config = 1; build_config <= CONFIG_COUNT; build_config++)); do
        start_instance "$build_config" || exit 1
    done
else
    start_instance "$CONFIG" || exit 1
fi

flock -u 9
exec 9>&-
maintain_logs 7>&- 9>&- &
maintenance_pid="$!"
pids+=("$maintenance_pid")
echo "Coverage profiles: $profile_dir"
while [ "${#server_pids[@]}" -gt 0 ]; do
    finished_pid=""
    wait -n -p finished_pid "${server_pids[@]}"
    status="$?"
    [ -n "$finished_pid" ] || continue
    build_config="${pid_configs[$finished_pid]}"
    unset 'pid_configs[$finished_pid]'
    remove_pid "$finished_pid"
    if [ "$RESTART" -eq 0 ] || ! owns_config "$build_config"; then
        continue
    fi
    echo "Configuration $build_config exited with status $status; restarting in 2 seconds"
    printf '[%s] runner: exited with status %s; restarting\n' \
        "$(date --iso-8601=seconds)" "$status" >>"$directory/logs/error$build_config.log"
    sleep 2
    exec 9>"$directory/run/locks/start.lock"
    flock 9
    if owns_config "$build_config"; then
        start_instance "$build_config" || true
    fi
    flock -u 9
    exec 9>&-
done
kill -TERM "$maintenance_pid" 2>/dev/null || true
wait "$maintenance_pid" 2>/dev/null || true
