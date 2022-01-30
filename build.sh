directory="$(pwd)"
mkdir -p build
mkdir -p build/run
mkdir -p build/run/etc
mkdir -p build/run/etc/nsd


# git clone https://github.com/NLnetLabs/nsd.git
#git clone git@github.com:NathanMulbrook/nsd.git
cd nsd
# git checkout tags/NSD_4_3_9_REL
aclocal && autoconf && autoheader
cd ../build

CC=clang   ../nsd/configure --prefix=$directory/build/run/ --disable-flto
make clean
#clang++ -c ../DataFlow.cpp -fsanitize=dataflow -O2 -o DataFlow.o
#clang++ -c ../DataFlowCallbacks.cpp -O2 -fPIC -o DataFlowCallbacks.o
make nsd -j 34
cp ../nsd.conf run/etc/nsd/nsd.conf
cp ../example.com.zone run/etc/nsd/example.com.zone
