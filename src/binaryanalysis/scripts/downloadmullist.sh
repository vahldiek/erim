#!/bin/bash
date=`date "+%Y-%m-%d-%H-%M-%S"`
count=0
mkdir $date
cd $date
mkdir download-output
mkdir pkgs
for list in $@
do
    nohup ../scripts/downloadpkglist.sh $list >download-output/downloadpkglist-$count.txt 2>&1 &
    count=$((count+1))
done
