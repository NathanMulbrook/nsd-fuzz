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

CC=clang CXX=clang++ CFLAGS='-g -O2 -fsanitize=fuzzer-no-link,address,undefined,leak -fno-omit-frame-pointer -fno-optimize-sibling-calls -fprofile-instr-generate -fcoverage-mapping -fsanitize-coverage=trace-cmp -fno-common -fsanitize-address-use-after-scope -fsanitize-address-use-after-return=runtime -U_FORTIFY_SOURCE -D_FORTIFY_SOURCE=0' CXXFLAGS='-g -O2 -fsanitize=fuzzer-no-link,address,undefined,leak -fno-omit-frame-pointer -fno-optimize-sibling-calls -fprofile-instr-generate -fcoverage-mapping -fsanitize-coverage=trace-cmp -fno-common -fsanitize-address-use-after-scope -fsanitize-address-use-after-return=runtime -U_FORTIFY_SOURCE -D_FORTIFY_SOURCE=0'  ../nsd/configure --prefix=$directory/build/run/ --disable-flto --enable-root-server --with-ssl=yes --with-libevent=yes --enable-dnstap 
make clean
cp ../nsd/fuzzer.c ./
cp ../nsd/fuzzer.h ./
rm -p fuzzer.o
clang -c fuzzer.c -pthread -fsanitize=fuzzer-no-link -Ofast -march=native -o fuzzer.o 

make install  -j 34
cp ../nsd.conf run/etc/nsd/nsd.conf
cp ../*.zone run/etc/nsd/
./run/sbin/nsd-control-setup
mkdir -p run/sbin/corpus
cp ../dict.txt run/etc/nsd/dict.txt
