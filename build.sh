#!/usr/bin/env bash
PATCH=1
CONFIG="a"
BUILD_INIT=0

directory="$(pwd)"
source_dir="$directory/nsd"
build_dir_default="build"

export CC=clang
export CXX=clang++
export LSAN_OPTIONS=detect_leaks=0
export CFLAGS='-g -O2 -fsanitize=fuzzer-no-link,address,undefined,leak -fno-omit-frame-pointer -fno-optimize-sibling-calls -fprofile-instr-generate -fcoverage-mapping -fsanitize-coverage=trace-cmp -fno-common -fsanitize-address-use-after-scope -fsanitize-address-use-after-return=runtime -U_FORTIFY_SOURCE -D_FORTIFY_SOURCE=0  -fsanitize-recover=all'
export CXXFLAGS='-g -O2 -fsanitize=fuzzer-no-link,address,undefined,leak -fno-omit-frame-pointer -fno-optimize-sibling-calls -fprofile-instr-generate -fcoverage-mapping -fsanitize-coverage=trace-cmp -fno-common -fsanitize-address-use-after-scope -fsanitize-address-use-after-return=runtime -U_FORTIFY_SOURCE -D_FORTIFY_SOURCE=0  -fsanitize-recover=all'
export config_flags_default="--disable-flto --enable-root-server"

list_descendants () {
  local children=$(ps -o pid= --ppid "$1")
  for pid in $children
  do
    list_descendants "$pid"
  done
  echo "$children"
}

_term() {
    echo "Killing Children"
    kill $(list_descendants $$)
    kill -9 $(list_descendants $$)
    exit
}

trap _term SIGINT
trap _term INT

cleanup() {
    cd "$temp_source_dir" || exit
    git apply -R ../patches/*.patch
    cd "$directory" || exit
}

help() {
    echo "Is a useful program"
    echo "Read the source."
    exit
}

config_build() {
    TEMP_CONFIG=$(($BUILD_CONFIG % 26+1))
    echo "############# Buiding Config: $BUILD_CONFIG ##################"
    case "${TEMP_CONFIG}" in
    1)
        config_flags="${config_flags_default}  --with-ssl=yes --enable-recvmmsg"
        ;;
    2)
        config_flags="${config_flags_default}  --with-ssl=yes --enable-bind8-stats"
        ;;
    3)
        config_flags="${config_flags_default}  --with-ssl=yes "
        ;;
    4)
        config_flags="${config_flags_default}  --with-ssl=yes --enable-ratelimit"
        ;;
    5)
        config_flags="${config_flags_default}  --with-ssl=yes --enable-memclean"
        ;;
    6)
        config_flags="${config_flags_default}  --with-ssl=yes --disable-nsec3 "
        ;;
    7)
        config_flags="${config_flags_default}  --with-ssl=yes --disable-minimal-responses"
        ;;
    8)
        config_flags="${config_flags_default}  --with-ssl=yes --enable-mmap"
        ;;
    9)
        config_flags="${config_flags_default}  --with-ssl=yes --disable-radix-tree"
        ;;
    10)
        config_flags="${config_flags_default}  --with-ssl=yes --enable-packed "
        ;;
    11)
        config_flags="${config_flags_default}  --with-ssl=yes --enable-dnstap"
        ;;
    12)
        config_flags="${config_flags_default}  --with-ssl=yes --enable-tcp-fastopen"
        ;;
    13)
        config_flags="${config_flags_default}  --with-ssl=yes --enable-bind8-stats --enable-zone-stats --enable-ratelimit  --disable-radix-tree --enable-packed --enable-dnstap  --enable-tcp-fastopen"
        ;;
    14)
        config_flags="${config_flags_default}  --with-ssl=yes --enable-bind8-stats --enable-zone-stats --enable-packed --enable-dnstap  --enable-tcp-fastopen"
        ;;
    15)
        config_flags="${config_flags_default}  --with-ssl=yes  --enable-bind8-stats --enable-zone-stats --enable-ratelimit --enable-memclean --enable-mmap --enable-packed --enable-dnstap  --enable-tcp-fastopen"
        ;;
    16)
        config_flags="${config_flags_default}  --with-ssl=yes --enable-recvmmsg --enable-bind8-stats --enable-zone-stats --enable-ratelimit --enable-mmap --enable-packed --enable-dnstap  --enable-tcp-fastopen"
        ;;
    17)
        config_flags="${config_flags_default}  --with-ssl=yes --enable-recvmmsg --enable-bind8-stats --enable-zone-stats --enable-ratelimit --enable-memclean --enable-mmap --disable-radix-tree --enable-packed --enable-dnstap "
        ;;
    18)
        config_flags="${config_flags_default}  --enable-recvmmsg --enable-bind8-stats --enable-zone-stats --enable-ratelimit --enable-memclean --enable-mmap --disable-radix-tree --enable-packed --enable-dnstap  --enable-tcp-fastopen"
        ;;
    19)
        config_flags="${config_flags_default} "
        ;;
    20)
        config_flags="${config_flags_default} --with-ssl=yes --enable-recvmmsg --enable-bind8-stats --enable-zone-stats --enable-ratelimit --enable-memclean --enable-mmap  --enable-packed --enable-dnstap  --enable-tcp-fastopen"
        ;;
    21)
        config_flags="${config_flags_default} --with-ssl=yes --enable-recvmmsg --enable-bind8-stats --enable-zone-stats --enable-ratelimit --enable-memclean --disable-radix-tree --enable-packed --enable-dnstap  "
        ;;
    22)
        config_flags="${config_flags_default} --with-ssl=yes --enable-recvmmsg --enable-bind8-stats --enable-zone-stats  --enable-mmap --disable-radix-tree --enable-packed --enable-dnstap  --enable-tcp-fastopen"
        ;;
    23)
        config_flags="${config_flags_default} --with-ssl=yes --enable-zone-stats --enable-ratelimit --enable-memclean --enable-mmap --disable-radix-tree  --enable-dnstap  --enable-tcp-fastopen"
        ;;
    24)
        config_flags="${config_flags_default} --with-ssl=yes --enable-recvmmsg  --enable-memclean --enable-mmap --disable-radix-tree --enable-packed --enable-dnstap  --enable-tcp-fastopen"
        ;;
    25)
        config_flags="${config_flags_default} --with-ssl=yes --enable-recvmmsg --enable-bind8-stats --enable-zone-stats  --enable-mmap --disable-radix-tree --enable-packed --enable-dnstap  --enable-tcp-fastopen"
        ;;
    26)
        config_flags="${config_flags_default} --with-ssl=yes --enable-recvmmsg --enable-bind8-stats --enable-zone-stats --enable-ratelimit --enable-memclean --enable-mmap --disable-radix-tree   --enable-tcp-fastopen"
        ;;

    \
        *)
        echo "Bad case. Try again."
        echo "Argument should be number 1-10"
        exit 1
        ;;
    esac
}

build_software() {
    run_dir="$directory/run/run_${BUILD_CONFIG}"
    build_dir="$directory/$build_dir_default/build_${BUILD_CONFIG}"
    temp_source_dir="$directory/build/src_${BUILD_CONFIG}"
    port=$(($BUILD_CONFIG + 3500))
    portsec=$(($BUILD_CONFIG + 3600))
    portconf=$(($BUILD_CONFIG + 8900))

    #Settup directories
    pkill -9 -f "run_$BUILD_CONFIG/sbin/nsd"
    rm "$run_dir/sbin/nsd"
    rm -rf "$run_dir"
    rm -rf "$build_dir"
    rm -rf "$temp_source_dir"

    mkdir -p "$temp_source_dir"
    mkdir -p "$build_dir"
    mkdir -p "$directory/run"
    mkdir -p "$run_dir/sbin"
    mkdir -p "$run_dir/sbin/corpus"
    mkdir -p "$directory/corpus"

    #Copy patch and configure source code
    cp -r "$source_dir"/* "$temp_source_dir"
    cd "$temp_source_dir" || cleanup
    if [ $PATCH = 1 ]; then
        git apply --reject --ignore-space-change --ignore-whitespace ../patches/*.patch
    fi
    aclocal && autoconf && autoheader
    sleep 2
    config_build

    cd "$build_dir" || cleanup
    "$temp_source_dir"/configure --prefix="$run_dir/" --exec-prefix="$run_dir/" $config_flags
    sleep 2
    make clean

    #Copy fuzzer code
    cp "$directory"/fuzzer.c ./
    cp "$directory"/fuzzer.h ./
    rm -p fuzzer.o
    sed -i s/3535/$port/g fuzzer.c
    sed -i "s!FuzzingCorpusDirectory!$directory/corpus!g" fuzzer.c

    #Use TCP for half of the fuzzers
    if [ ${BUILD_CONFIG} -gt 26 ]; then
        fuzzerFlags="-D FUZZTCP"
        sed -i s/6000/65000/g fuzzer.c
    else
        fuzzerFlags=""
    fi

    #Build fuzzer
    clang "$fuzzerFlags" -c fuzzer.c -pthread -fsanitize=fuzzer-no-link -Ofast -march=native -o fuzzer.o

    #Build NSD
    make install -j$(($(nproc) + 1))
    if [ $? -ne 0 ]; then
        echo "########### Make Failed, Retrying ###########"
        cd "$directory" || cleanup
        ./build.sh $@
        exit
    fi

    #Copy NSD configs and settup NSD
    cd "$directory" || cleanup
    cp nsd.conf "$run_dir"/etc/nsd/nsd.conf
    cp *.zone "$run_dir"/etc/nsd/
    sed -i s/3535/$port/g "$run_dir"/etc/nsd/nsd.conf
    sed -i s/8952/$portconf/g "$run_dir"/etc/nsd/nsd.conf
    sed -i s/admin/$(whoami)/g "$run_dir"/etc/nsd/nsd.conf
    "$run_dir"/sbin/nsd-control-setup
    cp dict.txt "$run_dir"/etc/nsd/

    #Create corpus dir and cleanup build
    mkdir -p corpus
    rm -rf "$build_dir"
    rm -rf "$temp_source_dir"
    pkill -9 -f "run_$BUILD_CONFIG/sbin/nsd"
}

for arg in "$@"; do
    case "$arg" in
    --help | -h)
        help
        ;;

    --init | -i)
        BUILD_INIT=1
        ;;

    --no_patch | -p)
        export PATCH=0
        ;;

    --config=* | -c=*)
        CONFIG="${arg#*=}"
        ;;
    esac
done

#Clone repo and checkout fuzz branch
if [ ${BUILD_INIT} = 1 ]; then
    git clone git@github.com:NathanMulbrook/nsd.git
    cd "$directory/nsd" || cleanup
    git checkout tags/fuzz2
    cd "$directory" || cleanup
fi

#Launch the build jobs
if [ "$CONFIG" = "a" ] || [ "$CONFIG" = "all" ]; then
    for BUILD_CONFIG in {1..52}; do
        ./build.sh -c=$BUILD_CONFIG $@ &
        fuzzerpids+=($!)
        sleep 5
    done
else
    BUILD_CONFIG="$CONFIG"
    build_software
fi
sleep 2
cleanup

# `configure' configures NSD 4.3.10 to adapt to many kinds of systems.

# Usage: ./configure [OPTION]... [VAR=VALUE]...

# To assign environment variables (e.g., CC, CFLAGS...), specify them as
# VAR=VALUE.  See below for descriptions of some of the useful variables.

# Defaults for the options are specified in brackets.

# Configuration:
# -h, --help              display this help and exit
# --help=short        display options specific to this package
# --help=recursive    display the short help of all the included packages
# -V, --version           display version information and exit
# -q, --quiet, --silent   do not print `checking ...' messages
# --cache-file=FILE   cache test results in FILE [disabled]
# -C, --config-cache      alias for `--cache-file=config.cache'
# -n, --no-create         do not create output files
# --srcdir=DIR        find the sources in DIR [configure dir or `..']

# Installation directories:
# --prefix=PREFIX         install architecture-independent files in PREFIX
# [/usr/local]
# --exec-prefix=EPREFIX   install architecture-dependent files in EPREFIX
# [PREFIX]

# By default, `make install' will install all the files in
# `/usr/local/bin', `/usr/local/lib' etc.  You can specify
# an installation prefix other than `/usr/local' using `--prefix',
# for instance `--prefix=$HOME'.

# For better control, use the options below.

# Fine tuning of the installation directories:
# --bindir=DIR            user executables [EPREFIX/bin]
# --sbindir=DIR           system admin executables [EPREFIX/sbin]
# --libexecdir=DIR        program executables [EPREFIX/libexec]
# --sysconfdir=DIR        read-only single-machine data [PREFIX/etc]
# --sharedstatedir=DIR    modifiable architecture-independent data [PREFIX/com]
# --localstatedir=DIR     modifiable single-machine data [PREFIX/var]
# --runstatedir=DIR       modifiable per-process data [LOCALSTATEDIR/run]
# --libdir=DIR            object code libraries [EPREFIX/lib]
# --includedir=DIR        C header files [PREFIX/include]
# --oldincludedir=DIR     C header files for non-gcc [/usr/include]
# --datarootdir=DIR       read-only arch.-independent data root [PREFIX/share]
# --datadir=DIR           read-only architecture-independent data [DATAROOTDIR]
# --infodir=DIR           info documentation [DATAROOTDIR/info]
# --localedir=DIR         locale-dependent data [DATAROOTDIR/locale]
# --mandir=DIR            man documentation [DATAROOTDIR/man]
# --docdir=DIR            documentation root [DATAROOTDIR/doc/nsd]
# --htmldir=DIR           html documentation [DOCDIR]
# --dvidir=DIR            dvi documentation [DOCDIR]
# --pdfdir=DIR            pdf documentation [DOCDIR]
# --psdir=DIR             ps documentation [DOCDIR]

# Optional Features:
# --disable-option-checking  ignore unrecognized --enable/--with options
# --disable-FEATURE       do not include FEATURE (same as --enable-FEATURE=no)
# --enable-FEATURE[=ARG]  include FEATURE [ARG=yes]
# --disable-flto          Disable link-time optimization (gcc specific option)
# --enable-pie            Enable Position-Independent Executable (eg. to fully
# benefit from ASLR, small performance penalty)
# --enable-relro-now      Enable full relocation binding at load-time (RELRO
# NOW, to protect GOT and .dtor areas)
# --disable-largefile     omit support for large files
# --enable-recvmmsg       Enable recvmmsg and sendmmsg compilation, faster but
# some kernel versions may have implementation
# problems for IPv6
# --enable-root-server    Configure NSD as a root server
# --disable-ipv6          Disables IPv6 support
# --enable-bind8-stats    Enables BIND8 like NSTATS & XSTATS and statistics in
# nsd-control
# --enable-zone-stats     Enable per-zone statistics gathering (needs
# --enable-bind8-stats)
# --enable-checking       Enable internal runtime checks
# --enable-memclean       Cleanup memory (at exit) for eg. valgrind, memcheck
# --enable-ratelimit      Enable rate limiting
# --enable-ratelimit-default-is-off
# Enable this to set default of ratelimit to off
# (enable in nsd.conf), otherwise ratelimit is enabled
# by default if --enable-ratelimit is enabled
# --disable-nsec3         Disable NSEC3 support
# --disable-minimal-responses
# Disable response minimization. More truncation.
# --enable-mmap           Use mmap instead of malloc. Experimental.
# --disable-radix-tree    You can disable the radix tree and use the red-black
# tree for the main lookups, the red-black tree uses
# less memory, but uses some more CPU.
# --enable-packed         Enable packed structure alignment, uses less memory,
# but unaligned reads.
# --enable-dnstap         Enable dnstap support (requires fstrm, protobuf-c)
# --enable-systemd        compile with systemd support
# --enable-tcp-fastopen   Enable TCP Fast Open

# Optional Packages:
# --with-PACKAGE[=ARG]    use PACKAGE [ARG=yes]
# --without-PACKAGE       do not use PACKAGE (same as --with-PACKAGE=no)
# --with-configdir=dir    NSD configuration directory
# --with-nsd_conf_file=path
# Pathname to the NSD configuration file
# --with-logfile=path     Pathname to the default log file
# --with-pidfile=path     Pathname to the NSD pidfile
# --with-dbfile=path      Pathname to the NSD database
# --with-zonesdir=dir     NSD default location for zone files
# --with-xfrdfile=path    Pathname to the NSD xfrd zone timer state file
# --with-zonelistfile=path
# Pathname to the NSD zone list file
# --with-xfrdir=path      Pathname to where the NSD transfer dir is created
# --with-chroot=dir       NSD default chroot directory
# --with-user=username    User name or ID to answer the queries with
# --with-libevent=pathname
# use libevent (will check /usr/local /opt/local
# /usr/lib /usr/pkg /usr/sfw /usr
# /usr/local/opt/libevent or you can specify an
# explicit path), useful when the zone count is high.
# --with-facility=name    Syslog default facility (LOG_DAEMON)
# --with-tcp-timeout=number
# Limit the default tcp timeout
# --with-ssl=pathname     enable SSL (will check /usr/local/ssl /usr/lib/ssl
# /usr/ssl /usr/pkg /usr/sfw /usr/local /usr
# /usr/local/opt/openssl)
# --with-dnstap-socket-path=pathname
# set default dnstap socket path
# --with-protobuf-c=path  Path where protobuf-c is installed, for dnstap
# --with-libfstrm=path    Path where libfstrm is installed, for dnstap

# Some influential environment variables:
# SED         location of the sed program
# AWK         location of the awk program
# GREP        location of the grep program
# EGREP       location of the egrep program
# LEX         location of the lex program with GNU extensions (flex)
# YACC        location of the yacc program with GNU extensions (bison)
# CC          C compiler command
# CFLAGS      C compiler flags
# LDFLAGS     linker flags, e.g. -L<lib dir> if you have libraries in a
# nonstandard directory <lib dir>
# LIBS        libraries to pass to the linker, e.g. -l<library>
# CPPFLAGS    (Objective) C/C++ preprocessor flags, e.g. -I<include dir> if
# you have headers in a nonstandard directory <include dir>
# CPP         C preprocessor
# YFLAGS      The list of arguments that will be passed by default to $YACC.
# This script will default YFLAGS to the empty string to avoid a
# default value of `-d' given by some make applications.
# PKG_CONFIG  path to pkg-config utility
# PKG_CONFIG_PATH
# directories to add to pkg-config's search path
# PKG_CONFIG_LIBDIR
# path overriding pkg-config's built-in search path
# SYSTEMD_CFLAGS
# C compiler flags for SYSTEMD, overriding pkg-config
# SYSTEMD_LIBS
# linker flags for SYSTEMD, overriding pkg-config
# SYSTEMD_DAEMON_CFLAGS
# C compiler flags for SYSTEMD_DAEMON, overriding pkg-config
# SYSTEMD_DAEMON_LIBS
# linker flags for SYSTEMD_DAEMON, overriding pkg-config

# Use these variables to override the choices made by `configure' or to help
# it to find libraries and programs with nonstandard names/locations.
