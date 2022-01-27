directory="$(pwd)"
mkdir build
mkdir build/run
mkdir build/run/etc
mkdir build/run/etc/nsd


# git clone https://github.com/NLnetLabs/nsd.git
#git clone git@github.com:NathanMulbrook/nsd.git
cd nsd
# git checkout tags/NSD_4_3_9_REL
aclocal && autoconf && autoheader
cd ../build

CC=clang   ../nsd/configure --prefix=$directory/build/run/
make clean
make -j 30
cp ../nsd.conf run/etc/nsd/nsd.conf
cp ../example.com.zone run/etc/nsd/example.com.zone
