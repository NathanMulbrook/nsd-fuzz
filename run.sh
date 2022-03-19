

FUZZ="--fuzz"
directory="$(pwd)"
mkdir -p logs
CONFIG="all"
LOG_OUPTUT=1
PACKET_CAPTURE=0

pkill nsd


mkdir logs/old
cp logrotate.conf logs/logrotate.conf
sed -i s#tacos#$directory#g logs/logrotate.conf

_term() {
    for fuzzerpid in $puzzerpids; do
        kill -INT "$fuzzerpid" 2>/dev/null
    done
    exit
}

trap _term SIGTERM
trap _term SIGINT

pids=()


config_build()
{
    case "${BUILD_CONFIG}" in

      1)
        config_flags="-d"
      ;;
      2)
        config_flags="-d"
       ;;
             3)
        config_flags="-d"
       ;;
             4)
        config_flags=""
       ;;
             5)
        config_flags=""
       ;;
             6)
        config_flags=""
       ;;
             7)
        config_flags=""
       ;;
             8)
        config_flags=""
       ;;
             9)
        config_flags=""
       ;;
             10)
        config_flags=""
       ;;
                    11)
        config_flags=""
       ;;
             12)
        config_flags=""
       ;;
                    13)
        config_flags=""
       ;;
             14)
        config_flags=""
       ;;
                    15)
        config_flags=""
       ;;
                           16)
        config_flags=""
       ;;
                           17)
        config_flags=""
       ;;
                           18)
        config_flags=""
       ;;
                           19)
        config_flags=""
       ;;
                           20)
        config_flags=""
       ;;
                                  21)
        config_flags=""
       ;;                           22)
        config_flags=""
       ;;                           23)
        config_flags=""
       ;;                           24)
        config_flags=""
       ;;                           25)
        config_flags=""
       ;;                           26)
        config_flags=""
       ;;


      *) echo "Bad case. Try again.";
        echo "Argument should be number 1-10"
        exit 1;;
    esac
}

run_fuzzer()
{
      config_build

    if [ $LOG_OUPTUT = 1 ]; then
    echo "ASAN_OPTIONS=strict_string_checks=1:detect_stack_use_after_return=1:check_initialization_order=1:strict_init_order=1:log_path=$directory/logs/asan$BUILD_CONFIG.log:halt_on_error=0 UBSAN_OPTIONS=halt_on_error=0 LSAN_OPTIONS=detect_leaks=0 $directory/run/run_$BUILD_CONFIG/sbin/nsd $config_flags   >> $directory/logs/error$BUILD_CONFIG 2>>$directory/logs/error$BUILD_CONFIG &"
    ASAN_OPTIONS=strict_string_checks=1:detect_stack_use_after_return=1:check_initialization_order=1:strict_init_order=1:log_path=$directory/logs/asan$BUILD_CONFIG.log:halt_on_error=0  LSAN_OPTIONS=detect_leaks=0 UBSAN_OPTIONS=halt_on_error=0 $directory/run/run_$BUILD_CONFIG/sbin/nsd $config_flags  >> $directory/logs/error$BUILD_CONFIG 2>>$directory/logs/error$BUILD_CONFIG &

      
    else
    echo "ASAN_OPTIONS=strict_string_checks=1:detect_stack_use_after_return=1:check_initialization_order=1:strict_init_order=1:log_path=$directory/logs/asan$BUILD_CONFIG.log:halt_on_error=0 UBSAN_OPTIONS=halt_on_error=0 LSAN_OPTIONS=detect_leaks=0 $directory/run/run_$BUILD_CONFIG/sbin/nsd  $config_flags  &"
    ASAN_OPTIONS=strict_string_checks=1:detect_stack_use_after_return=1:check_initialization_order=1:strict_init_order=1:log_path=$directory/logs/asan$BUILD_CONFIG.log:halt_on_error=0 UBSAN_OPTIONS=halt_on_error=0  LSAN_OPTIONS=detect_leaks=0 $directory/run/run_$BUILD_CONFIG/sbin/nsd $config_flags  &
    fi
    
    fuzzerpids+=($!)
}


for arg in "$@"
do
  case "$arg" in
    --fuzz|-f)
      FUZZ=" "
      ;;

    --packet|-p)
      PACKET_CAPTURE=1
      ;;

    --config=*|-c=*) CONFIG="${arg#*=}" ;;

    --LOG_OUPTUT|-s)
      LOG_OUPTUT=0
      ;;

  esac
done

if [ ${PACKET_CAPTURE} = 1 ]; then
  # if [ "$EUID" -ne 0 ]
  #   then echo "Please run with sudo"
  #   exit
  # fi
  tcpdump -G 43200 -i lo ip6 -w logs/dump$$.pcap -z gzip &
  fuzzerpids+=($!)
      sleep 5  
fi

if [ "$CONFIG" = "a" ] || [ "$CONFIG" = "all" ]; then
    for BUILD_CONFIG in {1..26}
    do
        sleep 0.1
        run_fuzzer
    done
else
    BUILD_CONFIG=$CONFIG
    run_fuzzer
fi


while :
do
    sleep 5
    logrotate ./logs/logrotate.conf   -s logs/old/logrotate.status
done

