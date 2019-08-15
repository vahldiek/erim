#!/bin/bash

out=$1
if [ $# -eq 0 ]
then
    out="."
fi

mkdir -p $out

declare -a configs=("cpierim")
declare -a testsfp=("433.milc" "444.namd" "447.dealII" "450.soplex" "470.lbm" "482.sphinx3") # "453.provray
declare -a testsint=("403.gcc" "445.gobmk" "458.sjeng" "464.h264ref" "473.astar" "401.bzip2" "429.mcf" "456.hmmer" "462.libquantum" "471.omnetpp" "483.xalancbmk") #"400.perlbench"

for config in "${configs[@]}"
do
    for t in "${testsint[@]}"
    do
	cp spec$config/External/SPEC/CINT2006/$t/$t $out
    done
    
    for t in "${testsfp[@]}"
    do
	cp spec$config/External/SPEC/CFP2006/$t/$t $out
    done
done
