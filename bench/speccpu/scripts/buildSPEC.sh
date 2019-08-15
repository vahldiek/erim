#!/bin/bash

buildSPECInstance () {
    LLVM_BIN=`realpath $1` #levee/bin
    FLAGS=$2 #CPI/CPS
    OUTDIR=$3
    
    TESTSUITE_BUILD_DIR=$OUTDIR
    rm -rf $TESTSUITE_BUILD_DIR
    
    mkdir -p $TESTSUITE_BUILD_DIR && cd $TESTSUITE_BUILD_DIR
    
    CFLAGS="-flto $FLAGS" CXXFLAGS="-flto $FLAGS" cmake ../test-suite -DCMAKE_C_COMPILER=$LLVM_BIN/clang -DCMAKE_CXX_COMPILER=$LLVM_BIN/clang++ 
    
    make -j 40 -C External/SPEC/CINT2006/
    make -j 40 -C External/SPEC/CFP2006/
    
    cd -
}

if [ -z "$1" ]
then
    #native
    buildSPECInstance levee/bin " " specnative
    
    #cpi
    buildSPECInstance levee/bin " -fcpi" speccpi
    
    #cps
    buildSPECInstance levee/bin " -fcps" speccps
    
    #cpierim
    buildSPECInstance leveeERIM/bin " -fcpi" speccpierim
    
    #cpserim
    buildSPECInstance leveeERIM/bin " -fcps" speccpserim
    
    #cpierimsim
    buildSPECInstance leveeERIMSIM/bin " -fcpi" speccpierimsim
    
    #cpserimsim
    buildSPECInstance leveeERIMSIM/bin " -fcps" speccpserimsim
else
    # build specific spec
    buildSPECInstance levee$1/bin "$2" "spec$3"
fi
