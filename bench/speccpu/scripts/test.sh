#!/bin/bash

declare -a configs=("native cpi cpierim cps cpserim")
declare -a testsfp=("433.milc" "444.namd" "447.dealII" "450.soplex" "470.lbm" "482.sphinx3") # "453.provray
declare -a testsint=("403.gcc" "445.gobmk" "458.sjeng" "464.h264ref" "473.astar" "401.bzip2" "429.mcf" "456.hmmer" "462.libquantum" "471.omnetpp" "483.xalancbmk") #"400.perlbench"

rm -f test.out

for config in ${configs[@]}
do
    for fp in ${testsfp[@]}
    do
	./scripts/lit.py -j 1 spec$config/External/SPEC/CFP2006/$fp >> test.out 2>&1 &
    done

    for int in ${testsint[@]}
    do
	./scripts/lit.py -j 1 spec$config/External/SPEC/CINT2006/$int >> test.out 2>&1 &	
    done
done

for job in `jobs -p`
do
    echo $job
    wait $job || let "FAIL+=1"
done
