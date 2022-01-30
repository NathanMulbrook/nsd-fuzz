directory="$(pwd)"
mkdir -p build
mkdir -p build/run
mkdir -p build/run/etc
mkdir -p build/run/etc/nsd


# git clone git@github.com:NathanMulbrook/nsd.git
cd nsd
# git checkout tags/fuzz2
aclocal && autoconf && autoheader

cd ../build

CC=clang   ../nsd/configure --prefix=$directory/build/run/ --disable-flto
make clean
cp ../nsd/fuzzer.c ./
cp ../nsd/fuzzer.h ./
rm -p fuzzer.o
clang -c fuzzer.c -pthread -fsanitize=fuzzer-no-link -O2 -o fuzzer.o 

make nsd -j 34
cp ../nsd.conf run/etc/nsd/nsd.conf
cp ../example.com.zone run/etc/nsd/example.com.zone
