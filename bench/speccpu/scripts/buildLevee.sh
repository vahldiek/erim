#!/bin/bash

leveesrc=../../src/levee

buildLeveeInstance () {
    leveeloc=$1
    
    cmake -DCMAKE_BUILD_TYPE=Release -DLLVM_ENABLE_ASSERTIONS=ON -DLLVM_BINUTILS_INCDIR=/usr/include $leveeloc
    if [ $? -ne 0 ]; then
	exit $?
    fi
    
    make -j40
    if [ $? -ne 0 ]; then
	exit $?
    fi
}

setERIMIsolation () {
    from=$1
    to=$2
    for f in lib/CodeGen/CPI.cpp projects/compiler-rt/lib/cpi/cpi.h;
    do
	sed -i "s/^$from/$to/g" $leveesrc/$f
    done
}

#CPI without erim
setERIMIsolation "\#define ERIM" "\/\/\#define ERIM" #disable erim
mkdir -p levee
cd levee
buildLeveeInstance ../$leveesrc
cd -

#cpi with erim
setERIMIsolation "\/\/\#define ERIM" "\#define ERIM" #endbale erim
mkdir -p leveeERIM
cd leveeERIM
buildLeveeInstance ../$leveesrc
cd -

#cpi with erim, but simulating
setERIMIsolation "\/\/\#define SIMULATE_PKRU" "\#define SIMULATE_PKRU" #endbale erim
mkdir -p leveeERIMSIM
cd leveeERIMSIM
buildLeveeInstance ../$leveesrc
cd -

# set to initial state (no erim)
setERIMIsolation "\#define ERIM" "\/\/\#define ERIM" #disable erim
setERIMIsolation "\#define SIMULATE_PKRU" "\/\/\#define SIMULATE_PKRU" #disable erim
