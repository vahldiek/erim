#!/bin/bash

out=$1
if [ $# -eq 0 ]
then
    out="."
fi

safeplace=/DS/erim/work/results

num_repititions=3
parallelism=1
declare -a configs=("cpierim" "cpi" "native")
declare -a testsfp=("433.milc" "444.namd" "447.dealII" "450.soplex" "470.lbm" "482.sphinx3") # "453.provray
declare -a testsint=("403.gcc" "445.gobmk" "458.sjeng" "464.h264ref" "473.astar" "401.bzip2" "429.mcf" "456.hmmer" "462.libquantum" "471.omnetpp" "483.xalancbmk") #"400.perlbench"

date=`date +%Y-%m-%d_%H%M`
res_dir="$out/specbench-$date"
mkdir $res_dir

echo "Results in $res_dir"
echo "tail -f $res_dir/run.out"

{
    #write config
    mkdir $res_dir/conf
    touch $res_dir/conf/`uname -n`
    uname -a >>$res_dir/conf/machine
    lscpu >>$res_dir/conf/machine
    cat /proc/meminfo >>$res_dir/conf/machine
    lspci | egrep 'network|ethernet|Network|Ethernet' >>$res_dir/conf/machine
    cp scripts/runSPECLevee.sh $res_dir/conf
    cp scripts/parseSPEC.py $res_dir/conf
    cp scripts/runLit.sh $res_dir/conf
    cp scripts/runCmdsFile.py $res_dir/conf
    mkdir $res_dir/json
    
    cmdfilename=$res_dir/conf/cmdfile
    
    for config in "${configs[@]}"
    do
	echo "#$date " > $res_dir/spec.aggsum.$config.txt
	for t in "${testsint[@]}"
	do
	    echo "scripts/runLit.sh $res_dir $num_repititions $config $t CINT2006" >> $cmdfilename
	done
	
	for t in "${testsfp[@]}"
	do
	    echo "scripts/runLit.sh $res_dir $num_repititions $config $t CFP2006" >> $cmdfilename
	done
    done
    
    python scripts/runCmdsFile.py $cmdfilename $parallelism

    for config in "${configs[@]}"
    do
	echo "$config$"
	cat $res_dir/spec.aggsum.$config.txt | wc -l
	sort $res_dir/spec.aggsum.$config.txt -k 2,2 > $res_dir/spec.aggsum.$config.txt.sorted
    done
    
    cp -ra $res_dir $safeplace

} > $res_dir/run.out 2>&1
