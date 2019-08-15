#!/bin/bash

res_dir=$1
num_repititions=$2
config=$3
test=$4
wl=$5

echo "Testing $config $test $wl in $res_dir for $num_repititions"

for rep in $(seq 1 $num_repititions)
do
    scripts/lit.py -v -j 1 spec$config/External/SPEC/$wl/$test/ -o $res_dir/json/spec.$config.$rep.$wl.$test.json
    
    python scripts/parseSPEC.py $res_dir/json/spec.$config.$rep.$wl.$test.json | sed -e "s/^/$config /" >> $res_dir/sum.txt
    
    echo "finished $rep"
done

grep "^$config $test" $res_dir/sum.txt | awk '{for(i=4;i<=NF;i++) {sum[i] += $i; sumsq[i] += ($i)^2}}  END {for (i=4;i<=NF;i++) {
          printf "%d %f %f %f \n", NR, sum[i]/NR, sqrt((sumsq[i]-sum[i]^2/NR)/NR), sqrt((sumsq[i]-sum[i]^2/NR)/NR)/(sum[i]/NR)*100} }' | sed -e "s/^/$config $test /" >> $res_dir/spec.aggsum.$config.txt

echo "finished $config $test $wl"
